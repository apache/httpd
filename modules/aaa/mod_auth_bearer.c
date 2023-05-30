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

/**
 * This module adds support for https://tools.ietf.org/html/rfc6750 Bearer
 * tokens, both as a generator of bearer tokens, and as an acceptor of
 * Bearer tokens for authentication.
 */

#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_lib.h"            /* for apr_isspace */
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
#include "ap_expr.h"

#include "mod_auth.h"

module AP_MODULE_DECLARE_DATA auth_bearer_module;

typedef struct {
    autht_provider_list *providers;
    int authoritative;
    ap_expr_info_t *proxy;
    int authoritative_set:1;
    int proxy_set:1;
} auth_bearer_config_rec;

static void *create_auth_bearer_dir_config(apr_pool_t *p, char *d)
{
    auth_bearer_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    /* Any failures are fatal. */
    conf->authoritative = 1;

    return conf;
}

static void *merge_auth_bearer_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    auth_bearer_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    auth_bearer_config_rec *base = basev;
    auth_bearer_config_rec *overrides = overridesv;

    newconf->authoritative =
            overrides->authoritative_set ? overrides->authoritative :
                    base->authoritative;
    newconf->authoritative_set = overrides->authoritative_set
            || base->authoritative_set;

    newconf->providers = overrides->providers ? overrides->providers : base->providers;

    newconf->proxy =
            overrides->proxy_set ? overrides->proxy : base->proxy;
    newconf->proxy_set = overrides->proxy_set || base->proxy_set;

    return newconf;
}

static const char *add_autht_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    auth_bearer_config_rec *conf = (auth_bearer_config_rec*)config;
    autht_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(autht_provider_list));
    newp->provider_name = arg;

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHT_PROVIDER_GROUP,
                                        newp->provider_name,
                                        AUTHT_PROVIDER_VERSION);

    if (newp->provider == NULL) {
        /* by the time they use it, the provider should be loaded and
           registered with us. */
        return apr_psprintf(cmd->pool,
                            "Unknown Autht provider: %s",
                            newp->provider_name);
    }

    if (!newp->provider->check_token) {
        /* if it doesn't provide the appropriate function, reject it */
        return apr_psprintf(cmd->pool,
                            "The '%s' Autht provider doesn't support "
                            "Bearer Authentication", newp->provider_name);
    }

    /* Add it to the list now. */
    if (!conf->providers) {
        conf->providers = newp;
    }
    else {
        autht_provider_list *last = conf->providers;

        while (last->next) {
            last = last->next;
        }
        last->next = newp;
    }

    return NULL;
}

static const char *set_authoritative(cmd_parms * cmd, void *config, int flag)
{
    auth_bearer_config_rec *conf = (auth_bearer_config_rec *) config;

    conf->authoritative = flag;
    conf->authoritative_set = 1;

    return NULL;
}

static const char *set_bearer_proxy(cmd_parms * cmd, void *config,
        const char *user)
{
    auth_bearer_config_rec *conf = (auth_bearer_config_rec *) config;
    const char *err;

    if (!strcasecmp(user, "off")) {
        conf->proxy = NULL;
        conf->proxy_set = 1;
    }
    else {

        conf->proxy =
                ap_expr_parse_cmd(cmd, user, AP_EXPR_FLAG_STRING_RESULT,
                        &err, NULL);
        if (err) {
            return apr_psprintf(cmd->pool,
                    "Could not parse proxy expression '%s': %s", user,
                    err);
        }
        conf->proxy_set = 1;
    }

    return NULL;
}

static const command_rec auth_bearer_cmds[] =
{
    AP_INIT_ITERATE("AuthBearerProvider", add_autht_provider, NULL, OR_AUTHCFG,
                    "specify the auth providers for a directory or location"),
    AP_INIT_FLAG("AuthBearerAuthoritative", set_authoritative, NULL, OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the token is not known to this module"),
    AP_INIT_TAKE1("AuthBearerProxy", set_bearer_proxy, NULL, OR_AUTHCFG,
                  "Pass a bearer authentication token over a proxy connection "
                  "generated using the given expression, 'off' to disable."),
    {NULL}
};

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * HTTP_INTERNAL_SERVER_ERROR, if things are so totally confused that we
 * couldn't figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

static void note_bearer_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
                   (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
                                                   : "WWW-Authenticate",
                   apr_pstrcat(r->pool, "Bearer realm=\"", ap_auth_name(r),
                               "\"", NULL));
}

static int hook_note_bearer_auth_failure(request_rec *r, const char *auth_type)
{
    if (strcasecmp(auth_type, "Bearer"))
        return DECLINED;

    note_bearer_auth_failure(r);
    return OK;
}

static int get_bearer_auth(request_rec *r, const char **token)
{
    const char *auth_line;

    /* Get the appropriate header */
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");

    if (!auth_line) {
        note_bearer_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Bearer")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10448)
                      "client used wrong authentication scheme: %s", r->uri);
        note_bearer_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    /* Skip leading spaces. */
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }

    *token = auth_line;

    return OK;
}

/* Determine the token, and check if we can process the token, for HTTP
 * bearer authentication...
 */
static int authenticate_bearer_token(request_rec *r)
{
    auth_bearer_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_bearer_module);
    const char *sent_token, *current_auth;
    int res;
    autht_status auth_result;
    autht_provider_list *current_provider;

    /* Are we configured to be Bearer auth? */
    current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "Bearer")) {
        return DECLINED;
    }

    /* We need an authentication realm. */
    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10449)
                      "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->ap_auth_type = (char*)current_auth;

    res = get_bearer_auth(r, &sent_token);
    if (res) {
        return res;
    }

    current_provider = conf->providers;
    do {
        const autht_provider *provider;

        /* For now, if a provider isn't set, we'll be nice and use the jwt
         * provider.
         */
        if (!current_provider) {
            provider = ap_lookup_provider(AUTHT_PROVIDER_GROUP,
                                          AUTHT_DEFAULT_PROVIDER,
                                          AUTHT_PROVIDER_VERSION);

            if (!provider || !provider->check_token) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10424)
                              "No Autht provider configured");
                auth_result = AUTHT_GENERAL_ERROR;
                break;
            }
            apr_table_setn(r->notes, AUTHT_PROVIDER_NAME_NOTE, AUTHT_DEFAULT_PROVIDER);
        }
        else {
            provider = current_provider->provider;
            apr_table_setn(r->notes, AUTHT_PROVIDER_NAME_NOTE, current_provider->provider_name);
        }

        auth_result = provider->check_token(r, "bearer", sent_token);

        apr_table_unset(r->notes, AUTHT_PROVIDER_NAME_NOTE);

        /* Something occurred. Stop checking. */
        if (auth_result != AUTHT_MISMATCH) {
            break;
        }

        /* If we're not really configured for providers, stop now. */
        if (!conf->providers) {
            break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (auth_result != AUTHT_GRANTED) {
        int return_code;

        /* If we're not authoritative, then any error is ignored. */
        if (!(conf->authoritative) && auth_result != AUTHT_DENIED) {
            return DECLINED;
        }

        switch (auth_result) {
        case AUTHT_DENIED:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10425)
                      "bearer token %s: authentication failure for \"%s\": "
                      "Token Rejected",
                      sent_token, r->uri);
            return_code = HTTP_UNAUTHORIZED;
            break;
        case AUTHT_EXPIRED:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10426)
                      "bearer token %s: authentication failure for \"%s\": "
                      "Token has expired",
                      sent_token, r->uri);
            return_code = HTTP_UNAUTHORIZED;
            break;
        case AUTHT_INVALID:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10427)
                      "bearer token %s: authentication failure for \"%s\": "
                      "Token is not yet valid",
                      sent_token, r->uri);
            return_code = HTTP_UNAUTHORIZED;
            break;
        case AUTHT_MISMATCH:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10428)
                      "bearer token %s: did not match '%s': %s", sent_token,
					  ap_auth_name(r), r->uri);
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

        /* If we're returning 401, tell them to try again. */
        if (return_code == HTTP_UNAUTHORIZED) {
            note_bearer_auth_failure(r);
        }
        return return_code;
    }

    return OK;
}

/* If we have set claims to be made, create a bearer authentication header
 * for the benefit of a proxy or application running behind this server.
 */
static int authenticate_bearer_fixup(request_rec *r)
{
    const char *auth_line, *token, *err;
    auth_bearer_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_bearer_module);

    if (!conf->proxy) {
        return DECLINED;
    }

    token = ap_expr_str_exec(r, conf->proxy, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10429)
                      "AuthBearerProxy: could not evaluate token expression for URI '%s': %s", r->uri, err);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!token || !*token) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(10430)
                      "AuthBearerProxy: empty token expression for URI '%s', ignoring", r->uri);

        apr_table_unset(r->headers_in, "Authorization");

        return DECLINED;
    }

    auth_line = apr_pstrcat(r->pool, "Bearer ", token,
                            NULL);
    apr_table_setn(r->headers_in, "Authorization", auth_line);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(10431)
                  "AuthBearerProxy: \"Authorization: %s\"",
                  auth_line);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_autht(authenticate_bearer_token, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_fixups(authenticate_bearer_fixup, NULL, NULL, APR_HOOK_LAST);
    ap_hook_note_auth_failure(hook_note_bearer_auth_failure, NULL, NULL,
                              APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(auth_bearer) =
{
    STANDARD20_MODULE_STUFF,
    create_auth_bearer_dir_config,  /* dir config creater */
    merge_auth_bearer_dir_config,   /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    auth_bearer_cmds,               /* command apr_table_t */
    register_hooks                  /* register hooks */
};
