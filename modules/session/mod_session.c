/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_session.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#define SESSION_EXPIRY "expiry"
#define HTTP_SESSION "HTTP_SESSION"

APR_HOOK_STRUCT(
                APR_HOOK_LINK(session_load)
                APR_HOOK_LINK(session_save)
                APR_HOOK_LINK(session_encode)
                APR_HOOK_LINK(session_decode)
)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, SESSION, int, session_load,
                      (request_rec * r, session_rec ** z), (r, z), DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, SESSION, int, session_save,
                       (request_rec * r, session_rec * z), (r, z), DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, SESSION, int, session_encode,
                   (request_rec * r, session_rec * z), (r, z), OK, DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, SESSION, int, session_decode,
                   (request_rec * r, session_rec * z), (r, z), OK, DECLINED)

static int session_identity_encode(request_rec * r, session_rec * z);
static int session_identity_decode(request_rec * r, session_rec * z);
static int session_fixups(request_rec * r);

/**
 * Should the session be included within this URL.
 *
 * This function tests whether a session is valid for this URL. It uses the
 * include and exclude arrays to determine whether they should be included.
 */
static int session_included(request_rec * r, session_dir_conf * conf)
{

    const char **includes = (const char **) conf->includes->elts;
    const char **excludes = (const char **) conf->excludes->elts;
    int included = 1;                /* defaults to included */
    int i;

    if (conf->includes->nelts) {
        included = 0;
        for (i = 0; !included && i < conf->includes->nelts; i++) {
            const char *include = includes[i];
            if (strncmp(r->uri, include, strlen(include)) == 0) {
                included = 1;
            }
        }
    }

    if (conf->excludes->nelts) {
        for (i = 0; included && i < conf->excludes->nelts; i++) {
            const char *exclude = excludes[i];
            if (strncmp(r->uri, exclude, strlen(exclude)) == 0) {
                included = 0;
            }
        }
    }

    return included;
}

/**
 * Load the session.
 *
 * If the session doesn't exist, a blank one will be created.
 *
 * @param r The request
 * @param z A pointer to where the session will be written.
 */
static apr_status_t ap_session_load(request_rec * r, session_rec ** z)
{

    session_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                   &session_module);
    apr_time_t now;
    session_rec *zz = NULL;
    int rv = 0;

    /* is the session enabled? */
    if (!dconf || !dconf->enabled) {
        return APR_SUCCESS;
    }

    /* should the session be loaded at all? */
    if (!session_included(r, dconf)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01814)
                      "excluded by configuration for: %s", r->uri);
        return APR_SUCCESS;
    }

    /* load the session from the session hook */
    rv = ap_run_session_load(r, &zz);
    if (DECLINED == rv) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01815)
                      "session is enabled but no session modules have been configured, "
                      "session not loaded: %s", r->uri);
        return APR_EGENERAL;
    }
    else if (OK != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01816)
                      "error while loading the session, "
                      "session not loaded: %s", r->uri);
        return rv;
    }

    /* found a session that hasn't expired? */
    now = apr_time_now();
    if (zz) {
        if (zz->expiry && zz->expiry < now) {
            zz = NULL;
        }
        else {
            /* having a session we cannot decode is just as good as having
               none at all */
            rv = ap_run_session_decode(r, zz);
            if (OK != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01817)
                              "error while decoding the session, "
                              "session not loaded: %s", r->uri);
                zz = NULL;
            }
        }
    }

    /* no luck, create a blank session */
    if (!zz) {
        zz = (session_rec *) apr_pcalloc(r->pool, sizeof(session_rec));
        zz->pool = r->pool;
        zz->entries = apr_table_make(zz->pool, 10);
    }

    /* make sure the expiry and maxage are set, if present */
    if (dconf->maxage) {
        if (!zz->expiry) {
            zz->expiry = now + dconf->maxage * APR_USEC_PER_SEC;
        }
        zz->maxage = dconf->maxage;
    }

    *z = zz;

    return APR_SUCCESS;

}

/**
 * Save the session.
 *
 * In most implementations the session is only saved if the dirty flag is
 * true. This prevents the session being saved unnecessarily.
 *
 * @param r The request
 * @param z A pointer to where the session will be written.
 */
static apr_status_t ap_session_save(request_rec * r, session_rec * z)
{
    if (z) {
        apr_time_t now = apr_time_now();
        int rv = 0;

        session_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                       &session_module);

        /* sanity checks, should we try save at all? */
        if (z->written) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01818)
                          "attempt made to save the session twice, "
                          "session not saved: %s", r->uri);
            return APR_EGENERAL;
        }
        if (z->expiry && z->expiry < now) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01819)
                          "attempt made to save a session when the session had already expired, "
                          "session not saved: %s", r->uri);
            return APR_EGENERAL;
        }

        /* reset the expiry back to maxage, if the expiry is present */
        if (dconf->maxage) {
            z->expiry = now + dconf->maxage * APR_USEC_PER_SEC;
            z->maxage = dconf->maxage;
        }

        /* reset the expiry before saving if present */
        if (z->dirty && z->maxage) {
            z->expiry = now + z->maxage * APR_USEC_PER_SEC;
        } 

        /* encode the session */
        rv = ap_run_session_encode(r, z);
        if (OK != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01820)
                          "error while encoding the session, "
                          "session not saved: %s", r->uri);
            return rv;
        }

        /* try the save */
        rv = ap_run_session_save(r, z);
        if (DECLINED == rv) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01821)
                          "session is enabled but no session modules have been configured, "
                          "session not saved: %s", r->uri);
            return APR_EGENERAL;
        }
        else if (OK != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01822)
                          "error while saving the session, "
                          "session not saved: %s", r->uri);
            return rv;
        }
        else {
            z->written = 1;
        }
    }

    return APR_SUCCESS;

}

/**
 * Get a particular value from the session.
 * @param r The current request.
 * @param z The current session. If this value is NULL, the session will be
 * looked up in the request, created if necessary, and saved to the request
 * notes.
 * @param key The key to get.
 * @param value The buffer to write the value to.
 */
static apr_status_t ap_session_get(request_rec * r, session_rec * z,
        const char *key, const char **value)
{
    if (!z) {
        apr_status_t rv;
        rv = ap_session_load(r, &z);
        if (APR_SUCCESS != rv) {
            return rv;
        }
    }
    if (z && z->entries) {
        *value = apr_table_get(z->entries, key);
    }

    return OK;
}

/**
 * Set a particular value to the session.
 *
 * Using this method ensures that the dirty flag is set correctly, so that
 * the session can be saved efficiently.
 * @param r The current request.
 * @param z The current session. If this value is NULL, the session will be
 * looked up in the request, created if necessary, and saved to the request
 * notes.
 * @param key The key to set. The existing key value will be replaced.
 * @param value The value to set.
 */
static apr_status_t ap_session_set(request_rec * r, session_rec * z,
        const char *key, const char *value)
{
    if (!z) {
        apr_status_t rv;
        rv = ap_session_load(r, &z);
        if (APR_SUCCESS != rv) {
            return rv;
        }
    }
    if (z) {
        if (value) {
            apr_table_set(z->entries, key, value);
        }
        else {
            apr_table_unset(z->entries, key);
        }
        z->dirty = 1;
    }
    return APR_SUCCESS;
}

static int identity_count(void *v, const char *key, const char *val)
{
    int *count = v;
    *count += strlen(key) * 3 + strlen(val) * 3 + 1;
    return 1;
}

static int identity_concat(void *v, const char *key, const char *val)
{
    char *slider = v;
    int length = strlen(slider);
    slider += length;
    if (length) {
        *slider = '&';
        slider++;
    }
    ap_escape_urlencoded_buffer(slider, key);
    slider += strlen(slider);
    *slider = '=';
    slider++;
    ap_escape_urlencoded_buffer(slider, val);
    return 1;
}

/**
 * Default identity encoding for the session.
 *
 * By default, the name value pairs in the session are URLEncoded, separated
 * by equals, and then in turn separated by ampersand, in the format of an
 * html form.
 *
 * This was chosen to make it easy for external code to unpack a session,
 * should there be a need to do so.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
static apr_status_t session_identity_encode(request_rec * r, session_rec * z)
{

    char *buffer = NULL;
    int length = 0;
    if (z->expiry) {
        char *expiry = apr_psprintf(z->pool, "%" APR_INT64_T_FMT, z->expiry);
        apr_table_setn(z->entries, SESSION_EXPIRY, expiry);
    }
    apr_table_do(identity_count, &length, z->entries, NULL);
    buffer = apr_pcalloc(r->pool, length + 1);
    apr_table_do(identity_concat, buffer, z->entries, NULL);
    z->encoded = buffer;
    return OK;

}

/**
 * Default identity decoding for the session.
 *
 * By default, the name value pairs in the session are URLEncoded, separated
 * by equals, and then in turn separated by ampersand, in the format of an
 * html form.
 *
 * This was chosen to make it easy for external code to unpack a session,
 * should there be a need to do so.
 *
 * This function reverses that process, and populates the session table.
 *
 * Name / value pairs that are not encoded properly are ignored.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
static apr_status_t session_identity_decode(request_rec * r, session_rec * z)
{

    char *last = NULL;
    char *encoded, *pair;
    const char *sep = "&";

    /* sanity check - anything to decode? */
    if (!z->encoded) {
        return OK;
    }

    /* decode what we have */
    encoded = apr_pstrdup(r->pool, z->encoded);
    pair = apr_strtok(encoded, sep, &last);
    while (pair && pair[0]) {
        char *plast = NULL;
        const char *psep = "=";
        char *key = apr_strtok(pair, psep, &plast);
        char *val = apr_strtok(NULL, psep, &plast);
        if (key && *key) {
            if (!val || !*val) {
                apr_table_unset(z->entries, key);
            }
            else if (!ap_unescape_urlencoded(key) && !ap_unescape_urlencoded(val)) {
                if (!strcmp(SESSION_EXPIRY, key)) {
                    z->expiry = (apr_time_t) apr_atoi64(val);
                }
                else {
                    apr_table_set(z->entries, key, val);
                }
            }
        }
        pair = apr_strtok(NULL, sep, &last);
    }
    z->encoded = NULL;
    return OK;

}

/**
 * Ensure any changes to the session are committed.
 *
 * This is done in an output filter so that our options for where to
 * store the session can include storing the session within a cookie:
 * As an HTTP header, the cookie must be set before the output is
 * written, but after the handler is run.
 *
 * NOTE: It is possible for internal redirects to cause more than one
 * request to be present, and each request might have a session
 * defined. We need to go through each session in turn, and save each
 * one.
 *
 * The same session might appear in more than one request. The first
 * attempt to save the session will be called
 */
static apr_status_t session_output_filter(ap_filter_t * f,
        apr_bucket_brigade * in)
{

    /* save all the sessions in all the requests */
    request_rec *r = f->r->main;
    if (!r) {
        r = f->r;
    }
    while (r) {
        session_rec *z = NULL;
        session_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                      &session_module);

        /* load the session, or create one if necessary */
        /* when unset or on error, z will be NULL */
        ap_session_load(r, &z);
        if (!z || z->written) {
            r = r->next;
            continue;
        }

        /* if a header was specified, insert the new values from the header */
        if (conf->header_set) {
            const char *override = apr_table_get(r->err_headers_out, conf->header);
            if (!override) {
                override = apr_table_get(r->headers_out, conf->header);
            }
            if (override) {
                apr_table_unset(r->err_headers_out, conf->header);
                apr_table_unset(r->headers_out, conf->header);
                z->encoded = override;
                z->dirty = 1;
                session_identity_decode(r, z);
            }
        }

        /* save away the session, and we're done */
        /* when unset or on error, we've complained to the log */
        ap_session_save(r, z);

        r = r->next;
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next, in);

}

/**
 * Insert the output filter.
 */
static void session_insert_output_filter(request_rec * r)
{
    ap_add_output_filter("MOD_SESSION_OUT", NULL, r, r->connection);
}

/**
 * Fixups hook.
 *
 * Load the session within a fixup - this ensures that the session is
 * properly loaded prior to the handler being called.
 *
 * The fixup is also responsible for injecting the session into the CGI
 * environment, should the admin have configured it so.
 *
 * @param r The request
 */
static int session_fixups(request_rec * r)
{
    session_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                  &session_module);

    session_rec *z = NULL;

    /* if an error occurs or no session has been configured, we ignore
     * the broken session and allow it to be recreated from scratch on save
     * if necessary.
     */
    ap_session_load(r, &z);

    if (conf->env) {
        if (z) {
            session_identity_encode(r, z);
            if (z->encoded) {
                apr_table_set(r->subprocess_env, HTTP_SESSION, z->encoded);
                z->encoded = NULL;
            }
        }
        apr_table_unset(r->headers_in, "Session");
    }

    return OK;

}


static void *create_session_dir_config(apr_pool_t * p, char *dummy)
{
    session_dir_conf *new =
    (session_dir_conf *) apr_pcalloc(p, sizeof(session_dir_conf));

    new->includes = apr_array_make(p, 10, sizeof(const char **));
    new->excludes = apr_array_make(p, 10, sizeof(const char **));

    return (void *) new;
}

static void *merge_session_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_dir_conf *new = (session_dir_conf *) apr_pcalloc(p, sizeof(session_dir_conf));
    session_dir_conf *add = (session_dir_conf *) addv;
    session_dir_conf *base = (session_dir_conf *) basev;

    new->enabled = (add->enabled_set == 0) ? base->enabled : add->enabled;
    new->enabled_set = add->enabled_set || base->enabled_set;
    new->maxage = (add->maxage_set == 0) ? base->maxage : add->maxage;
    new->maxage_set = add->maxage_set || base->maxage_set;
    new->header = (add->header_set == 0) ? base->header : add->header;
    new->header_set = add->header_set || base->header_set;
    new->env = (add->env_set == 0) ? base->env : add->env;
    new->env_set = add->env_set || base->env_set;
    new->includes = apr_array_append(p, base->includes, add->includes);
    new->excludes = apr_array_append(p, base->excludes, add->excludes);

    return new;
}


static const char *
     set_session_enable(cmd_parms * parms, void *dconf, int flag)
{
    session_dir_conf *conf = dconf;

    conf->enabled = flag;
    conf->enabled_set = 1;

    return NULL;
}

static const char *
     set_session_maxage(cmd_parms * parms, void *dconf, const char *arg)
{
    session_dir_conf *conf = dconf;

    conf->maxage = atol(arg);
    conf->maxage_set = 1;

    return NULL;
}

static const char *
     set_session_header(cmd_parms * parms, void *dconf, const char *arg)
{
    session_dir_conf *conf = dconf;

    conf->header = arg;
    conf->header_set = 1;

    return NULL;
}

static const char *
     set_session_env(cmd_parms * parms, void *dconf, int flag)
{
    session_dir_conf *conf = dconf;

    conf->env = flag;
    conf->env_set = 1;

    return NULL;
}

static const char *add_session_include(cmd_parms * cmd, void *dconf, const char *f)
{
    session_dir_conf *conf = dconf;

    const char **new = apr_array_push(conf->includes);
    *new = f;

    return NULL;
}

static const char *add_session_exclude(cmd_parms * cmd, void *dconf, const char *f)
{
    session_dir_conf *conf = dconf;

    const char **new = apr_array_push(conf->excludes);
    *new = f;

    return NULL;
}


static const command_rec session_cmds[] =
{
    AP_INIT_FLAG("Session", set_session_enable, NULL, RSRC_CONF|OR_AUTHCFG,
                 "on if a session should be maintained for these URLs"),
    AP_INIT_TAKE1("SessionMaxAge", set_session_maxage, NULL, RSRC_CONF|OR_AUTHCFG,
                  "length of time for which a session should be valid. Zero to disable"),
    AP_INIT_TAKE1("SessionHeader", set_session_header, NULL, RSRC_CONF|OR_AUTHCFG,
                  "output header, if present, whose contents will be injected into the session."),
    AP_INIT_FLAG("SessionEnv", set_session_env, NULL, RSRC_CONF|OR_AUTHCFG,
                 "on if a session should be written to the CGI environment. Defaults to off"),
    AP_INIT_TAKE1("SessionInclude", add_session_include, NULL, RSRC_CONF|OR_AUTHCFG,
                  "URL prefixes to include in the session. Defaults to all URLs"),
    AP_INIT_TAKE1("SessionExclude", add_session_exclude, NULL, RSRC_CONF|OR_AUTHCFG,
                  "URL prefixes to exclude from the session. Defaults to no URLs"),
    {NULL}
};

static void register_hooks(apr_pool_t * p)
{
    ap_register_output_filter("MOD_SESSION_OUT", session_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_filter(session_insert_output_filter, NULL, NULL,
                          APR_HOOK_MIDDLE);
    ap_hook_insert_error_filter(session_insert_output_filter,
                                NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(session_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_session_encode(session_identity_encode, NULL, NULL,
                           APR_HOOK_REALLY_FIRST);
    ap_hook_session_decode(session_identity_decode, NULL, NULL,
                           APR_HOOK_REALLY_LAST);
    APR_REGISTER_OPTIONAL_FN(ap_session_get);
    APR_REGISTER_OPTIONAL_FN(ap_session_set);
    APR_REGISTER_OPTIONAL_FN(ap_session_load);
    APR_REGISTER_OPTIONAL_FN(ap_session_save);
}

AP_DECLARE_MODULE(session) =
{
    STANDARD20_MODULE_STUFF,
    create_session_dir_config,   /* dir config creater */
    merge_session_dir_config,    /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server config */
    session_cmds,                /* command apr_table_t */
    register_hooks               /* register hooks */
};
