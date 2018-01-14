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
#include "http_log.h"
#include "util_cookies.h"

#define MOD_SESSION_COOKIE "mod_session_cookie"

module AP_MODULE_DECLARE_DATA session_cookie_module;

/**
 * Structure to carry the per-dir session config.
 */
typedef struct {
    const char *name;
    int name_set;
    const char *name_attrs;
    const char *name2;
    int name2_set;
    const char *name2_attrs;
    int remove;
    int remove_set;
} session_cookie_dir_conf;

/**
 * Set the cookie and embed the session within it.
 *
 * This function adds an RFC2109 compliant Set-Cookie header for
 * the cookie specified in SessionCookieName, and an RFC2965 compliant
 * Set-Cookie2 header for the cookie specified in SessionCookieName2.
 *
 * If specified, the optional cookie attributes will be added to
 * each cookie. If defaults are not specified, DEFAULT_ATTRS
 * will be used.
 *
 * On success, this method will return APR_SUCCESS.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
static apr_status_t session_cookie_save(request_rec * r, session_rec * z)
{

    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_cookie_module);

    /* don't cache auth protected pages */
    apr_table_addn(r->headers_out, "Cache-Control", "no-cache");

    /* create RFC2109 compliant cookie */
    if (conf->name_set) {
        if (z->encoded && z->encoded[0]) {
            ap_cookie_write(r, conf->name, z->encoded, conf->name_attrs,
                            z->maxage, r->headers_out, r->err_headers_out,
                            NULL);
        }
        else {
            ap_cookie_remove(r, conf->name, conf->name_attrs, r->headers_out,
                             r->err_headers_out, NULL);
        }
    }

    /* create RFC2965 compliant cookie */
    if (conf->name2_set) {
        if (z->encoded && z->encoded[0]) {
            ap_cookie_write2(r, conf->name2, z->encoded, conf->name2_attrs,
                             z->maxage, r->headers_out, r->err_headers_out,
                             NULL);
        }
        else {
            ap_cookie_remove2(r, conf->name2, conf->name2_attrs,
                              r->headers_out, r->err_headers_out, NULL);
        }
    }

    if (conf->name_set || conf->name2_set) {
        return OK;
    }
    return DECLINED;

}

/**
 * Isolate the cookie with the name "name", and if present, extract
 * the payload from the cookie.
 *
 * If the cookie is found, the cookie and any other cookies with the
 * same name are removed from the cookies passed in the request, so
 * that credentials are not leaked to a backend server or process.
 *
 * A missing or malformed cookie will cause this function to return
 * APR_EGENERAL.
 *
 * On success, this returns APR_SUCCESS.
 */
static apr_status_t session_cookie_load(request_rec * r, session_rec ** z)
{

    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_cookie_module);

    session_rec *zz = NULL;
    const char *val = NULL;
    const char *note = NULL;
    const char *name = NULL;
    request_rec *m = r;

    /* find the first redirect */
    while (m->prev) {
        m = m->prev;
    }
    /* find the main request */
    while (m->main) {
        m = m->main;
    }

    /* is our session in a cookie? */
    if (conf->name2_set) {
        name = conf->name2;
    }
    else if (conf->name_set) {
        name = conf->name;
    }
    else {
        return DECLINED;
    }

    /* first look in the notes */
    note = apr_pstrcat(m->pool, MOD_SESSION_COOKIE, name, NULL);
    zz = (session_rec *)apr_table_get(m->notes, note);
    if (zz) {
        *z = zz;
        return OK;
    }

    /* otherwise, try parse the cookie */
    ap_cookie_read(r, name, &val, conf->remove);

    /* create a new session and return it */
    zz = (session_rec *) apr_pcalloc(m->pool, sizeof(session_rec));
    zz->pool = m->pool;
    zz->entries = apr_table_make(m->pool, 10);
    zz->encoded = val;
    *z = zz;

    /* put the session in the notes so we don't have to parse it again */
    apr_table_setn(m->notes, note, (char *)zz);

    return OK;

}



static void *create_session_cookie_dir_config(apr_pool_t * p, char *dummy)
{
    session_cookie_dir_conf *new =
    (session_cookie_dir_conf *) apr_pcalloc(p, sizeof(session_cookie_dir_conf));

    return (void *) new;
}

static void *merge_session_cookie_dir_config(apr_pool_t * p, void *basev,
                                             void *addv)
{
    session_cookie_dir_conf *new = (session_cookie_dir_conf *)
                                apr_pcalloc(p, sizeof(session_cookie_dir_conf));
    session_cookie_dir_conf *add = (session_cookie_dir_conf *) addv;
    session_cookie_dir_conf *base = (session_cookie_dir_conf *) basev;

    new->name = (add->name_set == 0) ? base->name : add->name;
    new->name_attrs = (add->name_set == 0) ? base->name_attrs : add->name_attrs;
    new->name_set = add->name_set || base->name_set;
    new->name2 = (add->name2_set == 0) ? base->name2 : add->name2;
    new->name2_attrs = (add->name2_set == 0) ? base->name2_attrs : add->name2_attrs;
    new->name2_set = add->name2_set || base->name2_set;
    new->remove = (add->remove_set == 0) ? base->remove : add->remove;
    new->remove_set = add->remove_set || base->remove_set;

    return new;
}

/**
 * Sanity check a given string that it exists, is not empty,
 * and does not contain special characters.
 */
static const char *check_string(cmd_parms * cmd, const char *string)
{
    if (!string || !*string || ap_strchr_c(string, '=') || ap_strchr_c(string, '&')) {
        return apr_pstrcat(cmd->pool, cmd->directive->directive,
                           " cannot be empty, or contain '=' or '&'.",
                           NULL);
    }
    return NULL;
}

static const char *set_cookie_name(cmd_parms * cmd, void *config,
                                   const char *args)
{
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    session_cookie_dir_conf *conf = (session_cookie_dir_conf *) config;
    char *cookie = apr_strtok(line, " \t", &last);
    conf->name = cookie;
    conf->name_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    conf->name_attrs = last;
    return check_string(cmd, cookie);
}

static const char *set_cookie_name2(cmd_parms * cmd, void *config,
                                    const char *args)
{
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    session_cookie_dir_conf *conf = (session_cookie_dir_conf *) config;
    char *cookie = apr_strtok(line, " \t", &last);
    conf->name2 = cookie;
    conf->name2_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    conf->name2_attrs = last;
    return check_string(cmd, cookie);
}

static const char *
     set_remove(cmd_parms * parms, void *dconf, int flag)
{
    session_cookie_dir_conf *conf = dconf;

    conf->remove = flag;
    conf->remove_set = 1;

    return NULL;
}

static const command_rec session_cookie_cmds[] =
{
    AP_INIT_RAW_ARGS("SessionCookieName", set_cookie_name, NULL, RSRC_CONF|OR_AUTHCFG,
                     "The name of the RFC2109 cookie carrying the session"),
    AP_INIT_RAW_ARGS("SessionCookieName2", set_cookie_name2, NULL, RSRC_CONF|OR_AUTHCFG,
                     "The name of the RFC2965 cookie carrying the session"),
    AP_INIT_FLAG("SessionCookieRemove", set_remove, NULL, RSRC_CONF|OR_AUTHCFG,
                 "Set to 'On' to remove the session cookie from the headers "
                 "and hide the cookie from a backend server or process"),
    {NULL}
};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_session_load(session_cookie_load, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_session_save(session_cookie_save, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(session_cookie) =
{
    STANDARD20_MODULE_STUFF,
    create_session_cookie_dir_config, /* dir config creater */
    merge_session_cookie_dir_config,  /* dir merger --- default is to
                                       * override */
    NULL,                             /* server config */
    NULL,                             /* merge server config */
    session_cookie_cmds,              /* command apr_table_t */
    register_hooks                    /* register hooks */
};
