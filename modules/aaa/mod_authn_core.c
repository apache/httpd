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

/*
 * Security options etc.
 *
 * Module derived from code originally written by Rob McCool
 *
 */

#include "apr_strings.h"
#include "apr_network_io.h"
#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_expr.h"
#include "ap_provider.h"

#include "mod_auth.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* TODO List

- Track down all of the references to r->ap_auth_type
   and change them to ap_auth_type()
- Remove ap_auth_type and ap_auth_name from the
   request_rec

*/

typedef struct {
    ap_expr_info_t *ap_auth_type;
    int auth_type_set;
    ap_expr_info_t *ap_auth_name;
} authn_core_dir_conf;

typedef struct provider_alias_rec {
    char *provider_name;
    char *provider_alias;
    ap_conf_vector_t *sec_auth;
    const authn_provider *provider;
} provider_alias_rec;

typedef struct authn_alias_srv_conf {
    apr_hash_t *alias_rec;
} authn_alias_srv_conf;


module AP_MODULE_DECLARE_DATA authn_core_module;

static void *create_authn_core_dir_config(apr_pool_t *p, char *dummy)
{
    authn_core_dir_conf *conf =
            (authn_core_dir_conf *)apr_pcalloc(p, sizeof(authn_core_dir_conf));

    return (void *)conf;
}

static void *merge_authn_core_dir_config(apr_pool_t *a, void *basev, void *newv)
{
    authn_core_dir_conf *base = (authn_core_dir_conf *)basev;
    authn_core_dir_conf *new = (authn_core_dir_conf *)newv;
    authn_core_dir_conf *conf =
        (authn_core_dir_conf *)apr_pcalloc(a, sizeof(authn_core_dir_conf));

    if (new->auth_type_set) {
        conf->ap_auth_type = new->ap_auth_type;
        conf->auth_type_set = 1;
    }
    else {
        conf->ap_auth_type = base->ap_auth_type;
        conf->auth_type_set = base->auth_type_set;
    }

    if (new->ap_auth_name) {
        conf->ap_auth_name = new->ap_auth_name;
    } else {
        conf->ap_auth_name = base->ap_auth_name;
    }

    return (void*)conf;
}

static authn_status authn_alias_check_password(request_rec *r, const char *user,
                                              const char *password)
{
    /* Look up the provider alias in the alias list */
    /* Get the dir_config and call ap_Merge_per_dir_configs() */
    /* Call the real provider->check_password() function */
    /* return the result of the above function call */

    const char *provider_name = apr_table_get(r->notes, AUTHN_PROVIDER_NAME_NOTE);
    authn_status ret = AUTH_USER_NOT_FOUND;
    authn_alias_srv_conf *authcfg =
        (authn_alias_srv_conf *)ap_get_module_config(r->server->module_config,
                                                     &authn_core_module);

    if (provider_name) {
        provider_alias_rec *prvdraliasrec = apr_hash_get(authcfg->alias_rec,
                                                         provider_name, APR_HASH_KEY_STRING);
        ap_conf_vector_t *orig_dir_config = r->per_dir_config;

        /* If we found the alias provider in the list, then merge the directory
           configurations and call the real provider */
        if (prvdraliasrec) {
            r->per_dir_config = ap_merge_per_dir_configs(r->pool, orig_dir_config,
                                                         prvdraliasrec->sec_auth);
            ret = prvdraliasrec->provider->check_password(r,user,password);
            r->per_dir_config = orig_dir_config;
        }
    }

    return ret;
}

static authn_status authn_alias_get_realm_hash(request_rec *r, const char *user,
                                               const char *realm, char **rethash)
{
    /* Look up the provider alias in the alias list */
    /* Get the dir_config and call ap_Merge_per_dir_configs() */
    /* Call the real provider->get_realm_hash() function */
    /* return the result of the above function call */

    const char *provider_name = apr_table_get(r->notes, AUTHN_PROVIDER_NAME_NOTE);
    authn_status ret = AUTH_USER_NOT_FOUND;
    authn_alias_srv_conf *authcfg =
        (authn_alias_srv_conf *)ap_get_module_config(r->server->module_config,
                                                     &authn_core_module);

    if (provider_name) {
        provider_alias_rec *prvdraliasrec = apr_hash_get(authcfg->alias_rec,
                                                         provider_name, APR_HASH_KEY_STRING);
        ap_conf_vector_t *orig_dir_config = r->per_dir_config;

        /* If we found the alias provider in the list, then merge the directory
           configurations and call the real provider */
        if (prvdraliasrec) {
            r->per_dir_config = ap_merge_per_dir_configs(r->pool, orig_dir_config,
                                                         prvdraliasrec->sec_auth);
            ret = prvdraliasrec->provider->get_realm_hash(r,user,realm,rethash);
            r->per_dir_config = orig_dir_config;
        }
    }

    return ret;
}

static void *create_authn_alias_svr_config(apr_pool_t *p, server_rec *s)
{

    authn_alias_srv_conf *authcfg;

    authcfg = (authn_alias_srv_conf *) apr_pcalloc(p, sizeof(authn_alias_srv_conf));
    authcfg->alias_rec = apr_hash_make(p);

    return (void *) authcfg;
}

/* Only per-server directive we have is GLOBAL_ONLY */
static void *merge_authn_alias_svr_config(apr_pool_t *p, void *basev, void *overridesv)
{
    return basev;
}

static const authn_provider authn_alias_provider =
{
    &authn_alias_check_password,
    &authn_alias_get_realm_hash,
};

static const authn_provider authn_alias_provider_nodigest =
{
    &authn_alias_check_password,
    NULL,
};

static const char *authaliassection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *endp = ap_strrchr_c(arg, '>');
    const char *args;
    char *provider_alias;
    char *provider_name;
    int old_overrides = cmd->override;
    const char *errmsg;
    const authn_provider *provider = NULL;
    ap_conf_vector_t *new_auth_config = ap_create_per_dir_config(cmd->pool);
    authn_alias_srv_conf *authcfg =
        (authn_alias_srv_conf *)ap_get_module_config(cmd->server->module_config,
                                                     &authn_core_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    args = apr_pstrndup(cmd->temp_pool, arg, endp - arg);

    if (!args[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive requires additional arguments", NULL);
    }

    /* Pull the real provider name and the alias name from the block header */
    provider_name = ap_getword_conf(cmd->pool, &args);
    provider_alias = ap_getword_conf(cmd->pool, &args);

    if (!provider_name[0] || !provider_alias[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive requires additional arguments", NULL);
    }

    if (strcasecmp(provider_name, provider_alias) == 0) {
        return apr_pstrcat(cmd->pool,
                           "The alias provider name must be different from the base provider name.", NULL);
    }

    /* Look up the alias provider to make sure that it hasn't already been registered. */
    provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, provider_alias,
                                  AUTHN_PROVIDER_VERSION);
    if (provider) {
        return apr_pstrcat(cmd->pool, "The alias provider ", provider_alias,
                           " has already be registered previously as either a base provider or an alias provider.",
                           NULL);
    }

    /* walk the subsection configuration to get the per_dir config that we will
       merge just before the real provider is called. */
    cmd->override = OR_AUTHCFG | ACCESS_CONF;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_auth_config);
    cmd->override = old_overrides;

    if (!errmsg) {
        provider_alias_rec *prvdraliasrec = apr_pcalloc(cmd->pool, sizeof(provider_alias_rec));
        provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, provider_name,
                                      AUTHN_PROVIDER_VERSION);

        if (!provider) {
            /* by the time they use it, the provider should be loaded and
               registered with us. */
            return apr_psprintf(cmd->pool,
                                "Unknown Authn provider: %s",
                                provider_name);
        }

        /* Save off the new directory config along with the original provider name
           and function pointer data */
        prvdraliasrec->sec_auth = new_auth_config;
        prvdraliasrec->provider_name = provider_name;
        prvdraliasrec->provider_alias = provider_alias;
        prvdraliasrec->provider = provider;
        apr_hash_set(authcfg->alias_rec, provider_alias, APR_HASH_KEY_STRING, prvdraliasrec);

        /* Register the fake provider so that we get called first */
        ap_register_auth_provider(cmd->pool, AUTHN_PROVIDER_GROUP,
                                  provider_alias, AUTHN_PROVIDER_VERSION,
                                  provider->get_realm_hash ?
                                      &authn_alias_provider :
                                      &authn_alias_provider_nodigest,
                                  AP_AUTH_INTERNAL_PER_CONF);
    }

    return errmsg;
}

/*
 * Load an authorisation realm into our location configuration, applying the
 * usual rules that apply to realms.
 */
static const char *set_authname(cmd_parms *cmd, void *mconfig,
                                const char *word1)
{
    authn_core_dir_conf *aconfig = (authn_core_dir_conf *)mconfig;
    const char *expr_err = NULL;

    aconfig->ap_auth_name = ap_expr_parse_cmd(cmd, word1, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);
    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", word1, "' in AuthName: ",
                      expr_err, NULL);
    }

    return NULL;
}

static const char *set_authtype(cmd_parms *cmd, void *mconfig,
                                const char *word1)
{
    authn_core_dir_conf *aconfig = (authn_core_dir_conf *)mconfig;
    const char *expr_err = NULL;

    aconfig->ap_auth_type = ap_expr_parse_cmd(cmd, word1, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);
    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", word1, "' in AuthType: ",
                      expr_err, NULL);
    }

    aconfig->auth_type_set = 1;

    return NULL;
}

static const char *authn_ap_auth_type(request_rec *r)
{
    authn_core_dir_conf *conf;

    conf = (authn_core_dir_conf *) ap_get_module_config(r->per_dir_config,
            &authn_core_module);

    if (conf->ap_auth_type) {
        const char *err = NULL, *type;
        type = ap_expr_str_exec(r, conf->ap_auth_type, &err);
        if (err) {
            ap_log_rerror(
                    APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(02834) "AuthType expression could not be evaluated: %s", err);
            return NULL;
        }

        return strcasecmp(type, "None") ? type : NULL;
    }

    return NULL;
}

static const char *authn_ap_auth_name(request_rec *r)
{
    authn_core_dir_conf *conf;
    const char *err = NULL, *name;

    conf = (authn_core_dir_conf *) ap_get_module_config(r->per_dir_config,
            &authn_core_module);

    if (conf->ap_auth_name) {
        name = ap_expr_str_exec(r, conf->ap_auth_name, &err);
        if (err) {
            ap_log_rerror(
                    APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(02835) "AuthName expression could not be evaluated: %s", err);
            return NULL;
        }

        return ap_escape_quotes(r->pool, name);
    }

    return NULL;
}

static const command_rec authn_cmds[] =
{
    AP_INIT_TAKE1("AuthType", set_authtype, NULL, OR_AUTHCFG,
                  "an HTTP authorization type (e.g., \"Basic\")"),
    AP_INIT_TAKE1("AuthName", set_authname, NULL, OR_AUTHCFG,
                  "the authentication realm (e.g. \"Members Only\")"),
    AP_INIT_RAW_ARGS("<AuthnProviderAlias", authaliassection, NULL, RSRC_CONF,
                     "container for grouping an authentication provider's "
                     "directives under a provider alias"),
    {NULL}
};

static int authenticate_no_user(request_rec *r)
{
    /* if there isn't an AuthType, then assume that no authentication
        is required so return OK */
    if (!ap_auth_type(r)) {
        return OK;
    }

    /* there's an AuthType configured, but no authentication module
     * loaded to support it
     */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(01796)
                  "AuthType %s configured without corresponding module",
                  ap_auth_type(r));

    return HTTP_INTERNAL_SERVER_ERROR;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authn_ap_auth_type);
    APR_REGISTER_OPTIONAL_FN(authn_ap_auth_name);

    ap_hook_check_authn(authenticate_no_user, NULL, NULL, APR_HOOK_LAST,
                        AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authn_core) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_core_dir_config,   /* dir config creater */
    merge_authn_core_dir_config,    /* dir merger --- default is to override */
    create_authn_alias_svr_config,  /* server config */
    merge_authn_alias_svr_config,   /* merge server config */
    authn_cmds,
    register_hooks                  /* register hooks */
};

