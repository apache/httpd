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
#include "util_md5.h"
#include "ap_provider.h"
#include "ap_expr.h"

#include "mod_auth.h"

typedef struct {
    authn_provider_list *providers;
    char *dir; /* unused variable */
    int authoritative;
    ap_expr_info_t *fakeuser;
    ap_expr_info_t *fakepass;
    const char *use_digest_algorithm;
    int fake_set:1;
    int use_digest_algorithm_set:1;
    int authoritative_set:1;
} auth_basic_config_rec;

static void *create_auth_basic_dir_config(apr_pool_t *p, char *d)
{
    auth_basic_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    /* Any failures are fatal. */
    conf->authoritative = 1;

    return conf;
}

static void *merge_auth_basic_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    auth_basic_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    auth_basic_config_rec *base = basev;
    auth_basic_config_rec *overrides = overridesv;

    newconf->authoritative =
            overrides->authoritative_set ? overrides->authoritative :
                    base->authoritative;
    newconf->authoritative_set = overrides->authoritative_set
            || base->authoritative_set;

    newconf->fakeuser =
            overrides->fake_set ? overrides->fakeuser : base->fakeuser;
    newconf->fakepass =
            overrides->fake_set ? overrides->fakepass : base->fakepass;
    newconf->fake_set = overrides->fake_set || base->fake_set;

    newconf->use_digest_algorithm =
        overrides->use_digest_algorithm_set ? overrides->use_digest_algorithm
                                            : base->use_digest_algorithm;
    newconf->use_digest_algorithm_set =
        overrides->use_digest_algorithm_set || base->use_digest_algorithm_set;

    newconf->providers = overrides->providers ? overrides->providers : base->providers;

    return newconf;
}

static const char *add_authn_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    auth_basic_config_rec *conf = (auth_basic_config_rec*)config;
    authn_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = arg;

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

static const char *set_authoritative(cmd_parms * cmd, void *config, int flag)
{
    auth_basic_config_rec *conf = (auth_basic_config_rec *) config;

    conf->authoritative = flag;
    conf->authoritative_set = 1;

    return NULL;
}

static const char *add_basic_fake(cmd_parms * cmd, void *config,
        const char *user, const char *pass)
{
    auth_basic_config_rec *conf = (auth_basic_config_rec *) config;
    const char *err;

    if (!strcasecmp(user, "off")) {
        conf->fakeuser = NULL;
        conf->fakepass = NULL;
        conf->fake_set = 1;
    }
    else {
        /* if password is unspecified, set it to the fixed string "password" to
         * be compatible with the behaviour of mod_ssl.
         */
        if (!pass) {
            pass = "password";
        }

        conf->fakeuser =
                ap_expr_parse_cmd(cmd, user, AP_EXPR_FLAG_STRING_RESULT,
                        &err, NULL);
        if (err) {
            return apr_psprintf(cmd->pool,
                    "Could not parse fake username expression '%s': %s", user,
                    err);
        }
        conf->fakepass =
                ap_expr_parse_cmd(cmd, pass, AP_EXPR_FLAG_STRING_RESULT,
                        &err, NULL);
        if (err) {
            return apr_psprintf(cmd->pool,
                    "Could not parse fake password expression associated to user '%s': %s",
                    user, err);
        }
        conf->fake_set = 1;
    }

    return NULL;
}

static const char *set_use_digest_algorithm(cmd_parms *cmd, void *config,
                                            const char *alg)
{
    auth_basic_config_rec *conf = (auth_basic_config_rec *)config;

    if (strcasecmp(alg, "Off") && strcasecmp(alg, "MD5")) {
        return apr_pstrcat(cmd->pool,
                           "Invalid algorithm in "
                           "AuthBasicUseDigestAlgorithm: ", alg, NULL);
    }

    conf->use_digest_algorithm = alg;
    conf->use_digest_algorithm_set = 1;

    return NULL;
}

static const command_rec auth_basic_cmds[] =
{
    AP_INIT_ITERATE("AuthBasicProvider", add_authn_provider, NULL, OR_AUTHCFG,
                    "specify the auth providers for a directory or location"),
    AP_INIT_FLAG("AuthBasicAuthoritative", set_authoritative, NULL, OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the UserID is not known to this module"),
    AP_INIT_TAKE12("AuthBasicFake", add_basic_fake, NULL, OR_AUTHCFG,
                  "Fake basic authentication using the given expressions for "
                  "username and password, 'off' to disable. Password defaults "
                  "to 'password' if missing."),
    AP_INIT_TAKE1("AuthBasicUseDigestAlgorithm", set_use_digest_algorithm,
                  NULL, OR_AUTHCFG,
                  "Set to 'MD5' to use the auth provider's authentication "
                  "check for digest auth, using a hash of 'user:realm:pass'"),
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

static int hook_note_basic_auth_failure(request_rec *r, const char *auth_type)
{
    if (ap_cstr_casecmp(auth_type, "Basic"))
        return DECLINED;

    note_basic_auth_failure(r);
    return OK;
}

static int get_basic_auth(request_rec *r, const char **user,
                          const char **pw)
{
    const char *auth_line;
    char *decoded_line;

    /* Get the appropriate header */
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");

    if (!auth_line) {
        note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (ap_cstr_casecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01614)
                      "client used wrong authentication scheme: %s", r->uri);
        note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    /* Skip leading spaces. */
    while (*auth_line == ' ' || *auth_line == '\t') {
        auth_line++;
    }

    decoded_line = ap_pbase64decode(r->pool, auth_line);

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
    const char *realm = NULL;
    const char *digest = NULL;
    int res;
    authn_status auth_result;
    authn_provider_list *current_provider;

    /* Are we configured to be Basic auth? */
    current_auth = ap_auth_type(r);
    if (!current_auth || ap_cstr_casecmp(current_auth, "Basic")) {
        return DECLINED;
    }

    /* We need an authentication realm. */
    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01615)
                      "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->ap_auth_type = (char*)current_auth;

    res = get_basic_auth(r, &sent_user, &sent_pw);
    if (res) {
        return res;
    }

    if (conf->use_digest_algorithm
        && !ap_cstr_casecmp(conf->use_digest_algorithm, "MD5")) {
        realm = ap_auth_name(r);
        digest = ap_md5(r->pool,
                        (unsigned char *)apr_pstrcat(r->pool, sent_user, ":",
                                                     realm, ":",
                                                     sent_pw, NULL));
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01616)
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

        if (digest) {
            char *password;

            if (!provider->get_realm_hash) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02493)
                              "Authn provider does not support "
                              "AuthBasicUseDigestAlgorithm");
                auth_result = AUTH_GENERAL_ERROR;
                break;
            }
            /* We expect the password to be hash of user:realm:password */
            auth_result = provider->get_realm_hash(r, sent_user, realm,
                                                   &password);
            if (auth_result == AUTH_USER_FOUND) {
                auth_result = strcmp(digest, password) ? AUTH_DENIED
                                                       : AUTH_GRANTED;
            }
        }
        else {
            auth_result = provider->check_password(r, sent_user, sent_pw);
        }

        apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

        /* Something occurred. Stop checking. */
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01617)
                      "user %s: authentication failure for \"%s\": "
                      "Password Mismatch",
                      sent_user, r->uri);
            return_code = HTTP_UNAUTHORIZED;
            break;
        case AUTH_USER_NOT_FOUND:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01618)
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

        /* If we're returning 401, tell them to try again. */
        if (return_code == HTTP_UNAUTHORIZED) {
            note_basic_auth_failure(r);
        }
        return return_code;
    }

    return OK;
}

/* If requested, create a fake basic authentication header for the benefit
 * of a proxy or application running behind this server.
 */
static int authenticate_basic_fake(request_rec *r)
{
    const char *auth_line, *user, *pass, *err;
    auth_basic_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &auth_basic_module);

    if (!conf->fakeuser) {
        return DECLINED;
    }

    user = ap_expr_str_exec(r, conf->fakeuser, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02455)
                      "AuthBasicFake: could not evaluate user expression for URI '%s': %s", r->uri, err);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!user || !*user) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02458)
                      "AuthBasicFake: empty username expression for URI '%s', ignoring", r->uri);

        apr_table_unset(r->headers_in, "Authorization");

        return DECLINED;
    }

    pass = ap_expr_str_exec(r, conf->fakepass, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02456)
                      "AuthBasicFake: could not evaluate password expression for URI '%s': %s", r->uri, err);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!pass || !*pass) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02459)
                      "AuthBasicFake: empty password expression for URI '%s', ignoring", r->uri);

        apr_table_unset(r->headers_in, "Authorization");

        return DECLINED;
    }

    auth_line = apr_pstrcat(r->pool, "Basic ",
                            ap_pbase64encode(r->pool,
                                             apr_pstrcat(r->pool, user,
                                                         ":", pass, NULL)),
                            NULL);
    apr_table_setn(r->headers_in, "Authorization", auth_line);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02457)
                  "AuthBasicFake: \"Authorization: %s\"",
                  auth_line);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authn(authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_fixups(authenticate_basic_fake, NULL, NULL, APR_HOOK_LAST);
    ap_hook_note_auth_failure(hook_note_basic_auth_failure, NULL, NULL,
                              APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(auth_basic) =
{
    STANDARD20_MODULE_STUFF,
    create_auth_basic_dir_config,  /* dir config creater */
    merge_auth_basic_dir_config,   /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    auth_basic_cmds,               /* command apr_table_t */
    register_hooks                 /* register hooks */
};
