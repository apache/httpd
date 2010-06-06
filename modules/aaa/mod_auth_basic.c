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

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "apr_lib.h"            /* for apr_isspace */
#include "apr_base64.h"         /* for apr_base64_decode et al */
#define APR_WANT_STRFUNC        /* for strcasecmp */
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_provider.h"

#include "mod_auth.h"

typedef struct {
    authn_provider_list *providers;
    char *dir;
    int authoritative;
} auth_basic_config_rec;

static void *create_auth_basic_dir_config(apr_pool_t *p, char *d)
{
    auth_basic_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    conf->dir = d;
    /* Any failures are fatal. */
    conf->authoritative = 1;

    return conf;
}

static const char *add_authn_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    auth_basic_config_rec *conf = (auth_basic_config_rec*)config;
    authn_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = apr_pstrdup(cmd->pool, arg);

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                        newp->provider_name,
                                        AUTHN_PROVIDER_VERSION);

    if (newp->provider == NULL) {
        /* by the time they use it, the provider should be loaded and
           registered with us. */
        return apr_psprintf(cmd->pool,
                            "Unknown Authn provider: %s",
                            newp->provider_name);
    }

    if (!newp->provider->check_password) {
        /* if it doesn't provide the appropriate function, reject it */
        return apr_psprintf(cmd->pool,
                            "The '%s' Authn provider doesn't support "
                            "Basic Authentication", newp->provider_name);
    }

    /* Add it to the list now. */
    if (!conf->providers) {
        conf->providers = newp;
    }
    else {
        authn_provider_list *last = conf->providers;

        while (last->next) {
            last = last->next;
        }
        last->next = newp;
    }

    return NULL;
}

static const command_rec auth_basic_cmds[] =
{
    AP_INIT_ITERATE("AuthBasicProvider", add_authn_provider, NULL, OR_AUTHCFG,
                    "specify the auth providers for a directory or location"),
    AP_INIT_FLAG("AuthBasicAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(auth_basic_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the UserID is not known to this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_basic_module;

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * HTTP_INTERNAL_SERVER_ERROR, if things are so totally confused that we
 * couldn't figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

static void note_basic_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
                   (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
                                                   : "WWW-Authenticate",
                   apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r),
                               "\"", NULL));
}

static int get_basic_auth(request_rec *r, const char **user,
                          const char **pw)
{
    const char *auth_line;
    char *decoded_line;
    int length;

    /* Get the appropriate header */
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");

    if (!auth_line) {
        note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "client used wrong authentication scheme: %s", r->uri);
        note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    /* Skip leading spaces. */
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }

    decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
    length = apr_base64_decode(decoded_line, auth_line);
    /* Null-terminate the string. */
    decoded_line[length] = '\0';

    *user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');
    *pw = decoded_line;

    /* set the user, even though the user is unauthenticated at this point */
    r->user = (char *) *user;

    return OK;
}

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */
static int authenticate_basic_user(request_rec *r)
{
    auth_basic_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_basic_module);
    const char *sent_user, *sent_pw, *current_auth;
    int res;
    authn_status auth_result;
    authn_provider_list *current_provider;

    /* Are we configured to be Basic auth? */
    current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "Basic")) {
        return DECLINED;
    }

    /* We need an authentication realm. */
    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR,
                      0, r, "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->ap_auth_type = (char*)current_auth;

    res = get_basic_auth(r, &sent_user, &sent_pw);
    if (res) {
        return res;
    }

    current_provider = conf->providers;
    do {
        const authn_provider *provider;

        /* For now, if a provider isn't set, we'll be nice and use the file
         * provider.
         */
        if (!current_provider) {
            provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                          AUTHN_DEFAULT_PROVIDER,
                                          AUTHN_PROVIDER_VERSION);

            if (!provider || !provider->check_password) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "No Authn provider configured");
                auth_result = AUTH_GENERAL_ERROR;
                break;
            }
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, AUTHN_DEFAULT_PROVIDER);
        }
        else {
            provider = current_provider->provider;
            apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, current_provider->provider_name);
        }


        auth_result = provider->check_password(r, sent_user, sent_pw);

        apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

        /* Something occured. Stop checking. */
        if (auth_result != AUTH_USER_NOT_FOUND) {
            break;
        }

        /* If we're not really configured for providers, stop now. */
        if (!conf->providers) {
            break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (auth_result != AUTH_GRANTED) {
        int return_code;

        /* If we're not authoritative, then any error is ignored. */
        if (!(conf->authoritative) && auth_result != AUTH_DENIED) {
            return DECLINED;
        }

        switch (auth_result) {
        case AUTH_DENIED:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user %s: authentication failure for \"%s\": "
                      "Password Mismatch",
                      sent_user, r->uri);
            return_code = HTTP_UNAUTHORIZED;
            break;
        case AUTH_USER_NOT_FOUND:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user %s not found: %s", sent_user, r->uri);
            return_code = HTTP_UNAUTHORIZED;
            break;
        case AUTH_GENERAL_ERROR:
        default:
            /* We'll assume that the module has already said what its error
             * was in the logs.
             */
            return_code = HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        /* If we're returning 403, tell them to try again. */
        if (return_code == HTTP_UNAUTHORIZED) {
            note_basic_auth_failure(r);
        }
        return return_code;
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authn(authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(auth_basic) =
{
    STANDARD20_MODULE_STUFF,
    create_auth_basic_dir_config,  /* dir config creater */
    NULL,                          /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    auth_basic_cmds,               /* command apr_table_t */
    register_hooks                 /* register hooks */
};
