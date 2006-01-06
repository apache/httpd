/* Copyright 2002-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
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
    char *ap_auth_type;
    char *ap_auth_name;
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
    authn_core_dir_conf *conf;

    /* Create this conf by duplicating the base, replacing elements
    * (or creating copies for merging) where new-> values exist.
    */
    conf = (authn_core_dir_conf *)apr_palloc(a, sizeof(authn_core_dir_conf));
    memcpy(conf, base, sizeof(authn_core_dir_conf));

    if (new->ap_auth_type) {
        conf->ap_auth_type = new->ap_auth_type;
    }

    if (new->ap_auth_name) {
        conf->ap_auth_name = new->ap_auth_name;
    }

    return (void*)conf;
}

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

    /* walk the subsection configuration to get the per_dir config that we will
       merge just before the real provider is called. */
    cmd->override = OR_ALL|ACCESS_CONF;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_auth_config);

    if (!errmsg) {
        provider_alias_rec *prvdraliasrec = apr_pcalloc(cmd->pool, sizeof(provider_alias_rec));
        const authn_provider *provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, provider_name,"0");

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

/*
 * Load an authorisation realm into our location configuration, applying the
 * usual rules that apply to realms.
 */
static const char *set_authname(cmd_parms *cmd, void *mconfig,
                                const char *word1)
{
    authn_core_dir_conf *aconfig = (authn_core_dir_conf *)mconfig;

    aconfig->ap_auth_name = ap_escape_quotes(cmd->pool, word1);
    return NULL;
}


static const char *authn_ap_auth_type(request_rec *r)
{
    authn_core_dir_conf *conf;

    conf = (authn_core_dir_conf *)ap_get_module_config(r->per_dir_config,
        &authn_core_module);

    return apr_pstrdup(r->pool, conf->ap_auth_type);
}

static const char *authn_ap_auth_name(request_rec *r)
{
    authn_core_dir_conf *conf;

    conf = (authn_core_dir_conf *)ap_get_module_config(r->per_dir_config,
        &authn_core_module);

    return apr_pstrdup(r->pool, conf->ap_auth_name);
}

static const command_rec authn_cmds[] =
{
    AP_INIT_TAKE1("AuthType", ap_set_string_slot,
                  (void*)APR_OFFSETOF(authn_core_dir_conf, ap_auth_type), OR_AUTHCFG,
                  "An HTTP authorization type (e.g., \"Basic\")"),
    AP_INIT_TAKE1("AuthName", set_authname, NULL, OR_AUTHCFG,
                  "The authentication realm (e.g. \"Members Only\")"),
    AP_INIT_RAW_ARGS("<AuthnProviderAlias", authaliassection, NULL, RSRC_CONF,
                     "Container for authentication directives grouped under "
                     "a provider alias"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authn_ap_auth_type);
    APR_REGISTER_OPTIONAL_FN(authn_ap_auth_name);
}

module AP_MODULE_DECLARE_DATA authn_core_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_core_dir_config,   /* dir config creater */
    merge_authn_core_dir_config,    /* dir merger --- default is to override */
    create_authn_alias_svr_config,  /* server config */
    NULL,                           /* merge server config */
    authn_cmds,
    register_hooks                  /* register hooks */
};
