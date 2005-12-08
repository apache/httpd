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
#include "apr_md5.h"

#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

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

- Convert all of the authz modules to providers
- Remove the ap_requires field from the request_rec
- Remove the ap_requires field from authz_dir_conf   
- Remove the function ap_requires() and authz_ap_requires()
   since their functionality is no longer supported 
   or necessary in the refactoring
- Remove the calls to ap_some_auth_required() in the
   core request handling to allow the hooks to be called
   in all cases.  Is this function even necessary
   anymore?
- Determine of merge_authz_dir_config is even 
   necessary and remove if not
X- Split the authz type from the arguments when the
   authz provider is registered and store the type
   in ->provider_name and the arguments in ->requirement
X- Move the check for METHOD_MASK out of the authz 
   providers and into the provider vector
X- Change the status code to AUTHZ_DENIED, AUTHZ_GRANTED
   and AUTHZ_GENERAL_ERROR   
- Determine if setting the AUTHZ_PROVIDER_NAME_NOTE note
   is even necessary.  This was used in authn to support
   authn_alias.  Is there a need for an authz_alias?
- Move the Satisfy directive out of mod_core and into
   mod_authz_core.
- Expand the Satisfy directive to handle 'and' and 'or'
   logic for determining which authorization must succeed
   vs. may succeed
- Remove the AuthzXXXAuthoritative directives from all of
   the authz providers
      
*/

typedef struct {
    apr_array_header_t *ap_requires;
    authz_provider_list *providers;
} authz_core_dir_conf;

module AP_MODULE_DECLARE_DATA authz_core_module;

static void *create_authz_core_dir_config(apr_pool_t *p, char *dummy)
{
    authz_core_dir_conf *conf =
            (authz_core_dir_conf *)apr_pcalloc(p, sizeof(authz_core_dir_conf));

    return (void *)conf;
}

static void *merge_authz_core_dir_config(apr_pool_t *a, void *basev, void *newv)
{
    authz_core_dir_conf *base = (authz_core_dir_conf *)basev;
    authz_core_dir_conf *new = (authz_core_dir_conf *)newv;
    authz_core_dir_conf *conf;

    /* Create this conf by duplicating the base, replacing elements
    * (or creating copies for merging) where new-> values exist.
    */
    conf = (authz_core_dir_conf *)apr_palloc(a, sizeof(authz_core_dir_conf));
    memcpy(conf, base, sizeof(authz_core_dir_conf));

    if (new->ap_requires) {
        conf->ap_requires = new->ap_requires;
    }

    return (void*)conf;
}

static const char *add_authz_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    authz_core_dir_conf *conf = (authz_core_dir_conf*)config;
    authz_provider_list *newp;
    const char *t, *w;

    newp = apr_pcalloc(cmd->pool, sizeof(authz_provider_list));
    /* XXX: Split this out to the name and then the rest of the directive. */

    t = arg;
    w = ap_getword_white(cmd->pool, &t);

    if (w)
        newp->provider_name = apr_pstrdup(cmd->pool, w);
    if (t)
        newp->requirement = apr_pstrdup(cmd->pool, t);
    newp->method_mask = cmd->limited;

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHZ_PROVIDER_GROUP,
                                        newp->provider_name, "0");

    /* by the time the config file is used, the provider should be loaded
     * and registered with us.
     */
    if (newp->provider == NULL) {
        return apr_psprintf(cmd->pool,
                            "Unknown Authz provider: %s",
                            newp->provider_name);
    }

    /* if the provider doesn't provide the appropriate function, reject it */
    if (!newp->provider->check_authorization) {
        return apr_psprintf(cmd->pool,
                            "The '%s' Authz provider is not supported by any "
                            "of the loaded authorization modules ",
                            newp->provider_name);
    }

    /* Add it to the list now. */
    if (!conf->providers) {
        conf->providers = newp;
    }
    else {
        authz_provider_list *last = conf->providers;

        while (last->next) {
            last = last->next;
        }
        last->next = newp;
    }

    return NULL;
}

static const command_rec authz_cmds[] =
{
    AP_INIT_RAW_ARGS("Require", add_authz_provider, NULL, OR_AUTHCFG,
                     "Selects which authenticated users or groups may access "
                     "a protected space"),
    {NULL}
};

static int authorize_user(request_rec *r)
{
    authz_core_dir_conf *conf = ap_get_module_config(r->per_dir_config,
            &authz_core_module);
    authz_status auth_result;
    authz_provider_list *current_provider;

    current_provider = conf->providers;
    do {
        const authz_provider *provider;

        /* For now, if a provider isn't set, we'll be nice and use the file
         * provider.
         */
        if (!current_provider) {
            provider = ap_lookup_provider(AUTHZ_PROVIDER_GROUP,
                                          AUTHZ_DEFAULT_PROVIDER, "0");

            if (!provider || !provider->check_authorization) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "No default authz provider configured");
                auth_result = AUTHZ_GENERAL_ERROR;
                break;
            }
            apr_table_setn(r->notes, AUTHZ_PROVIDER_NAME_NOTE,
                           AUTHZ_DEFAULT_PROVIDER);
        }
        else {
            provider = current_provider->provider;
            apr_table_setn(r->notes, AUTHZ_PROVIDER_NAME_NOTE,
                           current_provider->provider_name);
        }

        /* check to make sure that the request method requires
        authorization before calling the provider */
        if (!(current_provider->method_mask & 
            (AP_METHOD_BIT << r->method_number))) {
            continue;
        }

        auth_result = provider->check_authorization(r,
                        current_provider->requirement);

        apr_table_unset(r->notes, AUTHZ_PROVIDER_NAME_NOTE);

        /* Something occured. Stop checking. */
        /* XXX: We need to figure out what the implications of multiple
         * require directives are.  Must all satisfy?  Can we leverage
         * satisfy here then?
         */
        if (auth_result != AUTHZ_DENIED) {
            break;
        }

        /* If we're not really configured for providers, stop now. */
        if (!conf->providers) {
            break;
        }

        current_provider = current_provider->next;
    } while (current_provider);

    if (auth_result != AUTHZ_GRANTED) {
        int return_code;

        switch (auth_result) {
            case AUTHZ_DENIED:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "user %s: authorization failure for \"%s\": ",
                              r->user, r->uri);
                return_code = HTTP_UNAUTHORIZED;
                break;
            case AUTHZ_GENERAL_ERROR:
            default:
                /* We'll assume that the module has already said what its
                 * error was in the logs.
                 */
                return_code = HTTP_INTERNAL_SERVER_ERROR;
                break;
        }

        /* If we're returning 403, tell them to try again. */
        if (return_code == HTTP_UNAUTHORIZED) {
            ap_note_auth_failure (r);
        }
        return return_code;
    }

    return OK;
}

static const apr_array_header_t *authz_ap_requires(request_rec *r)
{
    authz_core_dir_conf *conf;

    conf = (authz_core_dir_conf *)ap_get_module_config(r->per_dir_config,
        &authz_core_module);

    return conf->ap_requires;
}

static int authz_some_auth_required(request_rec *r)
{
    authz_core_dir_conf *conf = ap_get_module_config(r->per_dir_config,
            &authz_core_module);
    authz_provider_list *current_provider;
    int req_authz = 0;

    current_provider = conf->providers;
    while (current_provider) {

        /* Does this provider config apply for this method */
        if (current_provider->method_mask &
                (AP_METHOD_BIT << r->method_number)) {
            req_authz = 1;
            break;
        }

        current_provider = current_provider->next;
    }

    return req_authz;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authz_ap_requires);
    APR_REGISTER_OPTIONAL_FN(authz_some_auth_required);
   
    ap_hook_auth_checker(authorize_user, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_core_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_core_dir_config,   /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    authz_cmds,
    register_hooks                  /* register hooks */
};
