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
#define APR_WANT_STRFUNC        /* for strcasecmp */
#include "apr_want.h"

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "ap_provider.h"

#include "mod_auth.h"

typedef struct provider_alias_rec {
    char *provider_name;
    char *provider_alias;
    ap_conf_vector_t *sec_auth;
    const authn_provider *provider;
} provider_alias_rec;

typedef struct authn_alias_srv_conf {
    apr_hash_t *alias_rec;
} authn_alias_srv_conf;

module AP_MODULE_DECLARE_DATA authn_alias_module;

static authn_status authn_alias_check_password(request_rec *r, const char *user,
                                              const char *password)
{
    /* Look up the provider alias in the alias list */
    /* Get the the dir_config and call ap_Merge_per_dir_configs() */
    /* Call the real provider->check_password() function */
    /* return the result of the above function call */

    const char *provider_name = apr_table_get(r->notes, AUTHN_PROVIDER_NAME_NOTE);
    authn_status ret = AUTH_USER_NOT_FOUND;
    authn_alias_srv_conf *authcfg =
        (authn_alias_srv_conf *)ap_get_module_config(r->server->module_config,
                                                     &authn_alias_module);

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
    /* Get the the dir_config and call ap_Merge_per_dir_configs() */
    /* Call the real provider->get_realm_hash() function */
    /* return the result of the above function call */

    const char *provider_name = apr_table_get(r->notes, AUTHN_PROVIDER_NAME_NOTE);
    authn_status ret = AUTH_USER_NOT_FOUND;
    authn_alias_srv_conf *authcfg =
        (authn_alias_srv_conf *)ap_get_module_config(r->server->module_config,
                                                     &authn_alias_module);

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

static const authn_provider authn_alias_provider =
{
    &authn_alias_check_password,
    &authn_alias_get_realm_hash,
};

static const char *authaliassection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    int old_overrides = cmd->override;
    const char *endp = ap_strrchr_c(arg, '>');
    const char *args;
    char *provider_alias;
    char *provider_name;
    const char *errmsg;
    const authn_provider *provider = NULL;
    ap_conf_vector_t *new_auth_config = ap_create_per_dir_config(cmd->pool);
    authn_alias_srv_conf *authcfg =
        (authn_alias_srv_conf *)ap_get_module_config(cmd->server->module_config,
                                                     &authn_alias_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    args = apr_pstrndup(cmd->pool, arg, endp - arg);

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
    provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, provider_alias, "0");
    if (provider) {
        return apr_pstrcat(cmd->pool, "The alias provider ", provider_alias,
                           " has already be registered previously as either a base provider or an alias provider.",
                           NULL);
    }

    /* walk the subsection configuration to get the per_dir config that we will
       merge just before the real provider is called. */
    cmd->override = OR_ALL|ACCESS_CONF;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_auth_config);

    if (!errmsg) {
        provider_alias_rec *prvdraliasrec = apr_pcalloc(cmd->pool, sizeof(provider_alias_rec));
        provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, provider_name, "0");

        /* Save off the new directory config along with the original provider name
           and function pointer data */
        prvdraliasrec->sec_auth = new_auth_config;
        prvdraliasrec->provider_name = provider_name;
        prvdraliasrec->provider_alias = provider_alias;
        prvdraliasrec->provider = provider;
        apr_hash_set(authcfg->alias_rec, provider_alias, APR_HASH_KEY_STRING, prvdraliasrec);

        /* Register the fake provider so that we get called first */
        ap_register_provider(cmd->pool, AUTHN_PROVIDER_GROUP, provider_alias, "0",
                             &authn_alias_provider);
    }

    cmd->override = old_overrides;

    return errmsg;
}

static const command_rec authn_alias_cmds[] =
{
    AP_INIT_RAW_ARGS("<AuthnProviderAlias", authaliassection, NULL, RSRC_CONF,
                     "Container for authentication directives grouped under "
                     "a provider alias"),
    {NULL}
};


module AP_MODULE_DECLARE_DATA authn_alias_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                          /* dir config creater */
    NULL,                          /* dir merger --- default is to override */
    create_authn_alias_svr_config, /* server config */
    NULL,                          /* merge server config */
    authn_alias_cmds,               /* command apr_table_t */
    NULL                           /* register hooks */
};
