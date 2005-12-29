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

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_provider.h"

#include "mod_auth.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* TODO List

X- Convert all of the authz modules to providers
- Remove the ap_requires field from the request_rec
X- Remove the ap_requires field from authz_dir_conf   
X- Remove the function ap_requires() and authz_ap_requires()
   since their functionality is no longer supported 
   or necessary in the refactoring
X- Remove the calls to ap_some_auth_required() in the
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
- Remove the Satisfy directive and replace it with the
   <RequireAll>, <RequireOne> directives
X- Implement the <RequireAll> <RequireOne> block directives
   to handle the 'and' and 'or' logic for authorization.
X- Remove the AuthzXXXAuthoritative directives from all of
   the authz providers
X- Implement the Reject directive that will deny authorization
   if the argument is true
X- Fold the Reject directive into the <RequireAll> <RequireOne>
   logic
- Reimplement the host based authorization 'allow', 'deny'
   and 'order' as authz providers   
      
*/

typedef struct provider_alias_rec {
    char *provider_name;
    char *provider_alias;
    char *provider_args;
    ap_conf_vector_t *sec_auth;
    const authz_provider *provider;
} provider_alias_rec;

typedef struct {
    authz_provider_list *providers;
    authz_request_state req_state;
    int req_state_level;
} authz_core_dir_conf;

typedef struct authz_core_srv_conf {
    apr_hash_t *alias_rec;
} authz_core_srv_conf;


module AP_MODULE_DECLARE_DATA authz_core_module;

static void *create_authz_core_dir_config(apr_pool_t *p, char *dummy)
{
    authz_core_dir_conf *conf =
            (authz_core_dir_conf *)apr_pcalloc(p, sizeof(authz_core_dir_conf));

    conf->req_state = AUTHZ_REQSTATE_ONE;
    conf->req_state_level = 0;
    return (void *)conf;
}

#if 0
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

    return (void*)conf;
}
#endif

static void *create_authz_core_svr_config(apr_pool_t *p, server_rec *s)
{

    authz_core_srv_conf *authcfg;

    authcfg = (authz_core_srv_conf *) apr_pcalloc(p, sizeof(authz_core_srv_conf));
    authcfg->alias_rec = apr_hash_make(p);

    return (void *) authcfg;
}

static const char *add_authz_provider(cmd_parms *cmd, void *config,
                                      const char *arg)
{
    authz_core_dir_conf *conf = (authz_core_dir_conf*)config;
    authz_provider_list *newp;
    const char *t, *w;

    newp = apr_pcalloc(cmd->pool, sizeof(authz_provider_list));

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
    newp->req_state = conf->req_state;
    newp->req_state_level = conf->req_state_level;
    newp->is_reject = (int)cmd->info;

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
        int level = conf->req_state_level;

        /* if the level is 0 then take care of the implicit 'or'
           operation at this level. */
        if (level == 0) {
            /* Just run through the Require_one list and add the
                node */
            while (last->one_next) {
                last = last->one_next;
            }
            last->one_next = newp;
        } 
        else {
            /* Traverse the list to find the last entry.Each level 
               indicates a transition in the logic. */
            for (;level;level--) {
                /* if we are in a Require_all block then run through
                    all of the Require_all nodes to the end of the list */
                if (last->req_state == AUTHZ_REQSTATE_ALL) {
                    while (last->all_next) {
                        last = last->all_next;
                    }
                    /* If the end of the list contains a node state
                        change then run through all of the Require_one
                        nodes to the end of that list */
                    if (level >= last->req_state_level) {
                        while (last->one_next) {
                            last = last->one_next;
                        }
                    }
                    continue;
                }
                /* if we are in a Require_one block then run through
                    all of the Require_one nodes to the end of the list */
                if (last->req_state == AUTHZ_REQSTATE_ONE) {
                    while (last->one_next) {
                        last = last->one_next;
                    }
                    /* If the end of the list contains a node state
                        change then run through all of the Require_all
                        nodes to the end of that list */
                    if (level >= last->req_state_level) {
                        while (last->all_next) {
                            last = last->all_next;
                        }
                    }
                    continue;
                }
            }

            /* The current state flag indicates which way the transition should
               go.  If ALL then take the all_next path, otherwise one_next */
            if (last->req_state == AUTHZ_REQSTATE_ALL) {
                /* If we already have an all_next node, then
                   we must have dropped back a level so assign
                   the node to one_next */
                if (!last->all_next) {
                    last->all_next = newp;
                }
                else
                    last->one_next = newp;
            }
            else {
                /* If we already have a one_next node, then
                   we must have dropped back a level so assign
                   the node to all_next */
                if (!last->one_next) {
                    last->one_next = newp;
                }
                else
                    last->all_next = newp;
            }
        }
    }

    return NULL;
}

/* This is a fake authz provider that really merges various authz alias
   configurations and then envokes them. */
static authz_status authz_alias_check_authorization(request_rec *r,
                                              const char *require_args)
{
    /* Look up the provider alias in the alias list */
    /* Get the the dir_config and call ap_Merge_per_dir_configs() */
    /* Call the real provider->check_authorization() function */
    /* return the result of the above function call */

    const char *provider_name = apr_table_get(r->notes, AUTHZ_PROVIDER_NAME_NOTE);
    authz_status ret = AUTHZ_DENIED;
    authz_core_srv_conf *authcfg =
        (authz_core_srv_conf *)ap_get_module_config(r->server->module_config,
                                                     &authz_core_module);

    if (provider_name) {
        provider_alias_rec *prvdraliasrec = apr_hash_get(authcfg->alias_rec,
                                                         provider_name, APR_HASH_KEY_STRING);
        ap_conf_vector_t *orig_dir_config = r->per_dir_config;

        /* If we found the alias provider in the list, then merge the directory
           configurations and call the real provider */
        if (prvdraliasrec) {
            r->per_dir_config = ap_merge_per_dir_configs(r->pool, orig_dir_config,
                                                         prvdraliasrec->sec_auth);
            ret = prvdraliasrec->provider->check_authorization(r, prvdraliasrec->provider_args);
            r->per_dir_config = orig_dir_config;
        }
    }

    return ret;
}

static const authz_provider authz_alias_provider =
{
    &authz_alias_check_authorization,
};

static const char *authz_require_alias_section(cmd_parms *cmd, void *mconfig, const char *arg)
{
    int old_overrides = cmd->override;
    const char *endp = ap_strrchr_c(arg, '>');
    const char *args;
    char *provider_alias;
    char *provider_name;
    char *provider_args;
    const char *errmsg;
    ap_conf_vector_t *new_authz_config = ap_create_per_dir_config(cmd->pool);
    authz_core_srv_conf *authcfg = 
        (authz_core_srv_conf *)ap_get_module_config(cmd->server->module_config,
                                                     &authz_core_module);

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
    provider_args = ap_getword_conf(cmd->pool, &args);

    if (!provider_name[0] || !provider_alias[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive requires additional arguments", NULL);
    }

    /* walk the subsection configuration to get the per_dir config that we will
       merge just before the real provider is called. */
    cmd->override = OR_ALL|ACCESS_CONF;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_authz_config);

    if (!errmsg) {
        provider_alias_rec *prvdraliasrec = apr_pcalloc(cmd->pool, sizeof(provider_alias_rec));
        const authz_provider *provider = ap_lookup_provider(AUTHZ_PROVIDER_GROUP, provider_name,"0");

        /* Save off the new directory config along with the original provider name
           and function pointer data */
        prvdraliasrec->sec_auth = new_authz_config;
        prvdraliasrec->provider_name = provider_name;
        prvdraliasrec->provider_alias = provider_alias;
        prvdraliasrec->provider_args = provider_args;
        prvdraliasrec->provider = provider;         
        
        apr_hash_set(authcfg->alias_rec, provider_alias, APR_HASH_KEY_STRING, prvdraliasrec);

        /* Register the fake provider so that we get called first */
        ap_register_provider(cmd->pool, AUTHZ_PROVIDER_GROUP, provider_alias, "0",
                             &authz_alias_provider);
    }

    cmd->override = old_overrides;

    return errmsg;
}

static const char *authz_require_section(cmd_parms *cmd, void *mconfig, const char *arg)
{
    int old_overrides = cmd->override;
    const char *endp = ap_strrchr_c(arg, '>');
    const char *args;
    const char *errmsg;
    authz_request_state old_reqstate;
    authz_core_dir_conf *conf = (authz_core_dir_conf*)mconfig;
//  authz_core_srv_conf *authcfg = 
//      (authz_core_srv_conf *)ap_get_module_config(cmd->server->module_config,
//                                                   &authz_core_module);

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    args = apr_pstrndup(cmd->pool, arg, endp - arg);

    if (args[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive doesn't take additional arguments", NULL);
    }

    /* Save off the current request state so that we can go back to it after walking
       the subsection.  Indicate a transition in the logic incrementing the level.
       After the subsection walk the level will be decremented to indicate the
       path to follow. As the require directives are read by the configuration
       the req_state and the level will allow it to traverse the list to find
       the last element in the provider calling list. */
    old_reqstate = conf->req_state;
    if (strcasecmp (cmd->directive->directive, "<RequireAll") == 0) {
        conf->req_state = AUTHZ_REQSTATE_ALL;
    }
    else {
        conf->req_state = AUTHZ_REQSTATE_ONE;
    }
    conf->req_state_level++;
    cmd->override = OR_ALL|ACCESS_CONF;

    /* walk the subsection configuration to get the per_dir config that we will
       merge just before the real provider is called. */
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, cmd->context);

    conf->req_state_level--;
    conf->req_state = old_reqstate;
    cmd->override = old_overrides;

    return errmsg;
}

static const command_rec authz_cmds[] =
{
    AP_INIT_RAW_ARGS("Require", add_authz_provider, NULL, OR_AUTHCFG,
                     "Selects which authenticated users or groups may access "
                     "a protected space"),
    AP_INIT_RAW_ARGS("Reject", add_authz_provider, (void*)1, OR_AUTHCFG,
                     "Rejects the specified authenticated users or groups from accessing "
                     "a protected space"),
    AP_INIT_RAW_ARGS("<RequireAlias", authz_require_alias_section, NULL, RSRC_CONF,
                     "Container for authorization directives grouped under "
                     "an authz provider alias"),
    AP_INIT_RAW_ARGS("<RequireAll", authz_require_section, NULL, OR_AUTHCFG,
                     "Container for grouping require statements that must all " 
                     "succeed for authorization to be granted"),
    AP_INIT_RAW_ARGS("<RequireOne", authz_require_section, NULL, OR_AUTHCFG,
                     "Container for grouping require statements of which one " 
                     "must succeed for authorization to be granted"),
    {NULL}
};

static authz_status check_provider_list (request_rec *r, authz_provider_list *current_provider, int prev_level)
{
    authz_status auth_result = AUTHZ_DENIED;

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
            return auth_result;
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
        return AUTHZ_DENIED;
    }

    auth_result = provider->check_authorization(r,
                    current_provider->requirement);

    if (auth_result == AUTHZ_GENERAL_ERROR) {
        return auth_result;
    }

    if (current_provider->is_reject) {
        auth_result = auth_result == AUTHZ_DENIED ? AUTHZ_GRANTED : AUTHZ_DENIED;
    }

    apr_table_unset(r->notes, AUTHZ_PROVIDER_NAME_NOTE);

    /* If the current node is a Require_One type */
    if (current_provider->req_state == AUTHZ_REQSTATE_ONE) {
        /* if the auth_result of *this* node was GRANTED and we are embedded in a Require_all block
            then look to see if there is another Require_all node that needs to be satisfied */
        if (auth_result == AUTHZ_GRANTED) {
            if ((current_provider->all_next) && 
                (current_provider->all_next->req_state_level < current_provider->req_state_level)) {
                auth_result = check_provider_list (r, current_provider->all_next,
                                                   current_provider->req_state_level);
            }
            return auth_result;
        }
        one_next:

        /* Traverse forward to the next Require_one node it one exists 
            otherwise just return the auth_result */
        if (current_provider->one_next) {
            auth_result = check_provider_list (r, current_provider->one_next, 
                                               current_provider->req_state_level);
        }
        else
            return auth_result;

        /* if the *last* auth_result was GRANTED and we are embedded in a Require_all block
            then look to see if there is another Require_all node that needs to be satisfied */
        if ((auth_result == AUTHZ_GRANTED) && (current_provider->all_next) &&
            (current_provider->all_next->req_state_level < current_provider->req_state_level)) {
            auth_result = check_provider_list (r, current_provider->all_next,
                                               current_provider->req_state_level);
        }
             /* If the *last* auth_result was DENIED and we are inside of a Require_one block
                 then look to see if there is another Require_one node that can be satisfied */
        else if ((auth_result == AUTHZ_DENIED) && (current_provider->one_next) &&
                 (current_provider->one_next->req_state_level < current_provider->req_state_level)) {
            goto one_next;
        }

        return auth_result;
    }

    /* If the current node is a Require_All type */
    if (current_provider->req_state == AUTHZ_REQSTATE_ALL) {
        /* if the auth_result of *this* node was DENIED and we are embedded in a Require_one block
            then look to see if there is another Require_one node that can be satisfied */
        if (auth_result == AUTHZ_DENIED) {
            if ((current_provider->one_next) && 
                (current_provider->one_next->req_state_level < current_provider->req_state_level)) {
                auth_result = check_provider_list (r, current_provider->one_next,
                                                   current_provider->req_state_level);
            }
            return auth_result;
        }
        all_next:

        /* Traverse forward to the next Require_all node it one exists 
            otherwise just return the auth_result */
        if (current_provider->all_next) {
            auth_result = check_provider_list (r, current_provider->all_next,
                                               current_provider->req_state_level);
        }
        else
            return auth_result;

        /* if the *last* auth_result was DENIED and we are embedded in a Require_one block
            then look to see if there is another Require_one node that can be satisfied */
        if ((auth_result == AUTHZ_DENIED) && (current_provider->one_next) &&
            (current_provider->one_next->req_state_level < current_provider->req_state_level)) {
            auth_result = check_provider_list (r, current_provider->one_next,
                                               current_provider->req_state_level);
        }
             /* If the *last* auth_result was GRANTED and we are inside of a Require_all block
                 then look to see if there is another Require_all node that needs to be satisfied */
        else if ((auth_result == AUTHZ_GRANTED) && (current_provider->all_next) &&
                 (current_provider->all_next->req_state_level < current_provider->req_state_level)) {
            goto all_next;
        }
    }

    return auth_result;
}

static int authorize_user(request_rec *r)
{
    authz_core_dir_conf *conf = ap_get_module_config(r->per_dir_config,
            &authz_core_module);
    authz_status auth_result;
    authz_provider_list *current_provider;

    /* If we're not really configured for providers, stop now. */
    if (!conf->providers) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "no authorization providers configured");
        return HTTP_UNAUTHORIZED;
    }

    current_provider = conf->providers;

    auth_result = check_provider_list (r, current_provider, 0);

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

        current_provider = current_provider->one_next;
    }

    return req_authz;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authz_some_auth_required);

    ap_hook_auth_checker(authorize_user, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_core_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_core_dir_config,   /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    create_authz_core_svr_config,   /* server config */
    NULL,                           /* merge server config */
    authz_cmds,
    register_hooks                  /* register hooks */
};
