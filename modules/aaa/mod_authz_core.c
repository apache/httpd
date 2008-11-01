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
#include "apr_md5.h"

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
#include "ap_provider.h"

#include "mod_auth.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* TODO List

X- Convert all of the authz modules to providers
X- Remove the ap_requires field from the core_dir_config structure
X- Remove the ap_requires field from authz_dir_conf
X- Remove the function ap_requires() and authz_ap_requires()
   since their functionality is no longer supported
   or necessary in the refactoring
X- Remove the calls to ap_some_auth_required() in the
   core request handling to allow the hooks to be called
   in all cases.  Is this function even necessary
   anymore?
X- Determine of merge_authz_dir_config is even
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
X- Remove the Satisfy directive functionality and replace it with the
   <SatisfyAll>, <SatisfyOne> directives
X- Remove the Satisfy directive
X- Implement the <SatisfyAll> <SatisfyOne> block directives
   to handle the 'and' and 'or' logic for authorization.
X- Remove the AuthzXXXAuthoritative directives from all of
   the authz providers
X- Implement the Reject directive that will deny authorization
   if the argument is true
X- Fold the Reject directive into the <SatisfyAll> <SatisfyOne>
   logic
X- Reimplement the host based authorization 'allow', 'deny'
   and 'order' as authz providers
X- Remove the 'allow', 'deny' and 'order' directives
- Merge mod_authn_alias into mod_authn_core
X- Remove all of the references to the authzxxxAuthoritative
   directives from the documentation
X- Remove the Satisfy directive from the documentation
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
    int merge_rules;
} authz_core_dir_conf;

typedef struct authz_core_srv_conf {
    apr_hash_t *alias_rec;
} authz_core_srv_conf;

module AP_MODULE_DECLARE_DATA authz_core_module;
static const char *merge_authz_provider(authz_core_dir_conf *conf, authz_provider_list *newp);
static void walk_merge_provider_list(apr_pool_t *a, authz_core_dir_conf *conf, authz_provider_list *providers);

#define BASE_REQ_STATE AUTHZ_REQSTATE_ALL
#define BASE_REQ_LEVEL 0

static void *create_authz_core_dir_config(apr_pool_t *p, char *dummy)
{
    authz_core_dir_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->req_state = BASE_REQ_STATE;
    conf->req_state_level = BASE_REQ_LEVEL;
    conf->merge_rules = 1;
    return (void *)conf;
}

static void *merge_authz_core_dir_config(apr_pool_t *p,
                                         void *basev, void *newv)
{
    authz_core_dir_conf *base = (authz_core_dir_conf *)basev;
    authz_core_dir_conf *new = (authz_core_dir_conf *)newv;
    authz_core_dir_conf *conf;

    /* Create this conf by duplicating the base, replacing elements
    * (or creating copies for merging) where new-> values exist.
    */
    conf = (authz_core_dir_conf *)apr_pmemdup(p, base, sizeof(authz_core_dir_conf));

    /* Wipe out the providers and rejects lists so that
        they can be recreated by the merge process. */
    conf->providers = NULL;

    /* Only merge the base providers in if the merge_rules
        directive has been set. */
    if (base->providers && new->merge_rules) {
        walk_merge_provider_list (p, conf, base->providers);
    }
    if (new->providers) {
        walk_merge_provider_list (p, conf, new->providers);
    }

    return (void*)conf;
}

static void *create_authz_core_svr_config(apr_pool_t *p, server_rec *s)
{

    authz_core_srv_conf *authcfg;

    authcfg = apr_pcalloc(p, sizeof(*authcfg));
    authcfg->alias_rec = apr_hash_make(p);

    return (void *)authcfg;
}

/* This is a fake authz provider that really merges various authz alias
 * configurations and then invokes them.
 */
static authz_status authz_alias_check_authorization(request_rec *r,
                                                    const char *require_args)
{
    const char *provider_name;
    authz_status ret = AUTHZ_DENIED;

    /* Look up the provider alias in the alias list.
     * Get the the dir_config and call ap_Merge_per_dir_configs()
     * Call the real provider->check_authorization() function
     * return the result of the above function call
     */

    provider_name = apr_table_get(r->notes, AUTHZ_PROVIDER_NAME_NOTE);

    if (provider_name) {
        authz_core_srv_conf *authcfg;
        provider_alias_rec *prvdraliasrec;

        authcfg = ap_get_module_config(r->server->module_config,
                                       &authz_core_module);

        prvdraliasrec = apr_hash_get(authcfg->alias_rec, provider_name,
                                     APR_HASH_KEY_STRING);

        /* If we found the alias provider in the list, then merge the directory
           configurations and call the real provider */
        if (prvdraliasrec) {
            ap_conf_vector_t *orig_dir_config = r->per_dir_config;

            r->per_dir_config =
                ap_merge_per_dir_configs(r->pool, orig_dir_config,
                                         prvdraliasrec->sec_auth);

            ret = prvdraliasrec->provider->
                check_authorization(r, prvdraliasrec->provider_args);

            r->per_dir_config = orig_dir_config;
        }
    }

    return ret;
}

static const authz_provider authz_alias_provider =
{
    &authz_alias_check_authorization
};

static const char *authz_require_alias_section(cmd_parms *cmd, void *mconfig,
                                               const char *args)
{
    const char *endp = ap_strrchr_c(args, '>');
    char *provider_name;
    char *provider_alias;
    char *provider_args;
    ap_conf_vector_t *new_authz_config;
    int old_overrides = cmd->override;
    const char *errmsg;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    args = apr_pstrndup(cmd->pool, args, endp - args);

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

    new_authz_config = ap_create_per_dir_config(cmd->pool);

    /* Walk the subsection configuration to get the per_dir config that we will
     * merge just before the real provider is called.
     */
    cmd->override = OR_ALL|ACCESS_CONF;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_authz_config);
    cmd->override = old_overrides;

    if (!errmsg) {
        provider_alias_rec *prvdraliasrec;
        authz_core_srv_conf *authcfg;

        prvdraliasrec = apr_pcalloc(cmd->pool, sizeof(*prvdraliasrec));

        /* Save off the new directory config along with the original
         * provider name and function pointer data
         */
        prvdraliasrec->provider_name = provider_name;
        prvdraliasrec->provider_alias = provider_alias;
        prvdraliasrec->provider_args = provider_args;
        prvdraliasrec->sec_auth = new_authz_config;
        prvdraliasrec->provider =
            ap_lookup_provider(AUTHZ_PROVIDER_GROUP, provider_name,
                               AUTHZ_PROVIDER_VERSION);

        /* by the time the config file is used, the provider should be loaded
         * and registered with us.
         */
        if (!prvdraliasrec->provider) {
            return apr_psprintf(cmd->pool,
                                "Unknown Authz provider: %s",
                                provider_name);
        }

        authcfg = ap_get_module_config(cmd->server->module_config,
                                       &authz_core_module);

        apr_hash_set(authcfg->alias_rec, provider_alias,
                     APR_HASH_KEY_STRING, prvdraliasrec);

        /* Register the fake provider so that we get called first */
        ap_register_auth_provider(cmd->pool, AUTHZ_PROVIDER_GROUP,
                                  provider_alias, AUTHZ_PROVIDER_VERSION,
                                  &authz_alias_provider,
                                  AP_AUTH_INTERNAL_PER_CONF);
    }

    return errmsg;
}

static void walk_merge_provider_list(apr_pool_t *a, authz_core_dir_conf *conf, authz_provider_list *providers)
{
    authz_provider_list *newp = (authz_provider_list *)apr_palloc(a, sizeof(authz_provider_list));
    memcpy(newp, providers, sizeof(authz_provider_list));

    /* Since the merge is being done at a later time rather than
        at configuration time, we need to fake the current
        state of the list so that the new element get merged
        into the correct location. The current state is
        derived from the state of the object to be merged. */
    conf->req_state = newp->req_state;
    conf->req_state_level = newp->req_state_level;
    newp->one_next = NULL;
    newp->all_next = NULL;

    /* Merge it into the existing provider logic. */
    merge_authz_provider(conf, newp);

    /* Walk all of the elements recursively to allow each existing
        element to be copied and merged into the final configuration.*/
    if (BASE_REQ_STATE == AUTHZ_REQSTATE_ONE) {
        if (providers->one_next) {
            walk_merge_provider_list (a, conf, providers->one_next);
        }
        if (providers->all_next) {
            walk_merge_provider_list (a, conf, providers->all_next);
        }
    }
    else {
        if (providers->all_next) {
            walk_merge_provider_list (a, conf, providers->all_next);
        }
        if (providers->one_next) {
            walk_merge_provider_list (a, conf, providers->one_next);
        }
    }

    return;
}

static const char *merge_authz_provider(authz_core_dir_conf *conf, authz_provider_list *newp)
{
    /* Add it to the list now. */
    if (!conf->providers) {
        conf->providers = newp;
    }
    else {
        authz_provider_list *last = conf->providers;
        int level = conf->req_state_level;

        /* if the level is the base level then take care of the implicit
         * operation at this level.
         */
        if (level == BASE_REQ_LEVEL) {
            if (conf->req_state == AUTHZ_REQSTATE_ONE) {
                /* Just run through the Require_one list and add the
                 * node
                 */
                while (last->one_next) {
                    last = last->one_next;
                }
                last->one_next = newp;
            }
            else {
                /* Just run through the Require_all list and add the
                 * node
                 */
                while (last->all_next) {
                    last = last->all_next;
                }
                last->all_next = newp;
            }
        }

        /* if the last nodes level is greater than the new nodes
         *  level, then we need to insert the new node at this
         *  point.  The req_state of the new node determine
         *  how it is inserted into the list.
         */
        else if (last->req_state_level > newp->req_state_level) {
            if (newp->req_state == AUTHZ_REQSTATE_ONE)
                newp->one_next = last;
            else
                newp->all_next = last;
            conf->providers = newp;
        }
        else {
            /* Traverse the list to find the last entry.Each level
             * indicates a transition in the logic.
             */
            for (;level;level--) {
                /* if we are in a Require_all block then run through
                 * all of the Require_all nodes to the end of the list.
                 * Stop if we run into a node whose level is greater than
                 * the level of the node that is being inserted.
                 */
                if (last->req_state == AUTHZ_REQSTATE_ALL) {
                    while ((last->all_next) && (last->all_next->req_state_level <= conf->req_state_level)) {
                        last = last->all_next;
                    }
                    /* If the end of the list contains a node state
                     * change then run through all of the Require_one
                     * nodes to the end of that list
                     */
                    if (level >= last->req_state_level) {
                        while (last->one_next) {
                            last = last->one_next;
                        }
                    }
                    continue;
                }
                /* if we are in a Require_one block then run through
                 * all of the Require_one nodes to the end of the list
                 */
                if (last->req_state == AUTHZ_REQSTATE_ONE) {
                    while (last->one_next) {
                        last = last->one_next;
                    }
                    /* If the end of the list contains a node state
                     * change then run through all of the Require_all
                     * nodes to the end of that list
                     */
                    if (level >= last->req_state_level) {
                        while (last->all_next) {
                            last = last->all_next;
                        }
                    }
                    continue;
                }
            }

            /* The current state flag indicates which way the transition should
             * go.  If ALL then take the all_next path, otherwise one_next
             */
            if (last->req_state == AUTHZ_REQSTATE_ALL) {
                /* If we already have an all_next node, then
                 * we must have dropped back a level so assign
                 * the node to one_next
                 */
                if (!last->all_next) {
                    last->all_next = newp;
                }
                /* If the level of the new node is greater than the
                 *  last node, then insert the new node at this point.
                 *  The req_state of the new node will determine
                 *  how the node is added to the list.
                 */
                else if (last->req_state_level <= newp->req_state_level) {
                    if (newp->req_state == AUTHZ_REQSTATE_ONE)
                        newp->one_next = last->all_next;
                    else
                        newp->all_next = last->all_next;
                    last->all_next = newp;
                }
                else {
                    last->one_next = newp;
                }
            }
            else {
                /* If we already have a one_next node, then
                 * we must have dropped back a level so assign
                 * the node to all_next
                 */
                if (!last->one_next) {
                    last->one_next = newp;
                }
                /* If the level of the new node is greater than the
                 *  last node, then insert the new node at this point.
                 *  The req_state of the new node will determine
                 *  how the node is added to the list.
                 */
                else if (last->req_state_level <= newp->req_state_level) {
                    if (newp->req_state == AUTHZ_REQSTATE_ONE)
                        newp->one_next = last->one_next;
                    else
                        newp->all_next = last->one_next;
                    last->one_next = newp;
                }
                else {
                    last->all_next = newp;
                }
            }
        }
    }

    return NULL;
}

static const char *add_authz_provider(cmd_parms *cmd, void *config,
                                      const char *args)
{
    authz_core_dir_conf *conf = (authz_core_dir_conf*)config;
    authz_provider_list *newp;
    const char *t, *w;

    newp = apr_pcalloc(cmd->pool, sizeof(authz_provider_list));

    t = args;
    w = ap_getword_white(cmd->pool, &t);

    if (w)
        newp->provider_name = apr_pstrdup(cmd->pool, w);
    if (t)
        newp->requirement = apr_pstrdup(cmd->pool, t);
    newp->method_mask = cmd->limited;

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHZ_PROVIDER_GROUP,
                                        newp->provider_name,
                                        AUTHZ_PROVIDER_VERSION);
    newp->req_state = conf->req_state;
    newp->req_state_level = conf->req_state_level;
    newp->is_reject = (cmd->info != NULL);

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

    /* Add the element to the list. */
    return merge_authz_provider(conf, newp);
}

static const char *add_authz_section(cmd_parms *cmd, void *mconfig,
                                     const char *args)
{
    authz_core_dir_conf *conf = mconfig;
    const char *endp = ap_strrchr_c(args, '>');
    authz_request_state old_reqstate;
    int old_overrides = cmd->override;
    const char *errmsg;

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    args = apr_pstrndup(cmd->pool, args, endp - args);

    if (args[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive doesn't take additional arguments", NULL);
    }

    /* Save off the current request state so that we can go back to it after walking
     *  the subsection.  Indicate a transition in the logic incrementing the level.
     *  After the subsection walk the level will be decremented to indicate the
     *  path to follow. As the require directives are read by the configuration
     *  the req_state and the level will allow it to traverse the list to find
     *  the last element in the provider calling list.
     */
    old_reqstate = conf->req_state;
    if (strcasecmp (cmd->directive->directive, "<SatisfyAll") == 0) {
        conf->req_state = AUTHZ_REQSTATE_ALL;
    }
    else {
        conf->req_state = AUTHZ_REQSTATE_ONE;
    }
    conf->req_state_level++;
    cmd->override = OR_ALL|ACCESS_CONF;

    /* Walk the subsection configuration to get the per_dir config that we will
     * merge just before the real provider is called.
     */
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
                     "Rejects the specified authenticated users groups or "
                     "host based requests from accessing a protected space"),
    AP_INIT_RAW_ARGS("<RequireAlias", authz_require_alias_section, NULL, RSRC_CONF,
                     "Container for authorization directives grouped under "
                     "an authz provider alias"),
    AP_INIT_RAW_ARGS("<SatisfyAll", add_authz_section, NULL, OR_AUTHCFG,
                     "Container for grouping require statements that must all "
                     "succeed for authorization to be granted"),
    AP_INIT_RAW_ARGS("<SatisfyOne", add_authz_section, NULL, OR_AUTHCFG,
                     "Container for grouping require statements of which one "
                     "must succeed for authorization to be granted"),
    AP_INIT_FLAG("AuthzMergeRules", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_core_dir_conf, merge_rules), OR_AUTHCFG,
                 "Set to 'on' to allow the parent's <Directory> or <Location> authz rules "
                 "to be merged into the current <Directory> or <Location>.  Set to 'off' "
                 "to disable merging. If set to 'off', only the authz rules defined in "
                 "the current <Directory> or <Location> block will apply. The default is 'on'."),
    {NULL}
};

#define RESOLVE_NEUTRAL(orig,new)  (new == AUTHZ_NEUTRAL) ? orig : new;

static authz_status check_provider_list (request_rec *r, authz_provider_list *current_provider, int prev_level)
{
    authz_status auth_result = AUTHZ_DENIED;

    const authz_provider *provider;

    provider = current_provider->provider;
    apr_table_setn(r->notes, AUTHZ_PROVIDER_NAME_NOTE,
                   current_provider->provider_name);

    /* check to make sure that the request method requires
     * authorization before calling the provider
     */
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
        /* If the provider was called through a reject directive, then
            alter the result accordingly.  If the original result was
            Denied then the new result is Neutral since we can not grant
            access simply because authorization was not rejected. */
        auth_result = auth_result == AUTHZ_DENIED ? AUTHZ_NEUTRAL : AUTHZ_DENIED;
    }

    apr_table_unset(r->notes, AUTHZ_PROVIDER_NAME_NOTE);

    /* If the current node is a Require_One type */
    if (current_provider->req_state == AUTHZ_REQSTATE_ONE) {
        /* If the auth_result of *this* node was GRANTED and we are
         * embedded in a Require_all block then look to see if there
         * is another Require_all node that needs to be satisfied
         */
        if ((auth_result == AUTHZ_GRANTED) || (auth_result == AUTHZ_NEUTRAL)) {
            if ((current_provider->all_next) &&
                (current_provider->all_next->req_state_level < current_provider->req_state_level)) {
                authz_status temp_result = check_provider_list (r, current_provider->all_next,
                                                                current_provider->req_state_level);
                auth_result = RESOLVE_NEUTRAL(auth_result, temp_result);
            }
            return auth_result;
        }
        one_next:

        /* Traverse forward to the next Require_one node it one exists
         * otherwise just return the auth_result
         */
        if (current_provider->one_next) {
            authz_status temp_result = check_provider_list (r, current_provider->one_next,
                                                            current_provider->req_state_level);
            auth_result = RESOLVE_NEUTRAL(auth_result, temp_result);
        }
        else
            return auth_result;

        /* If the *last* auth_result was GRANTED and we are embedded in
         * a Require_all block then look to see if there is another
         * Require_all node that needs to be satisfied
         */
        if (((auth_result == AUTHZ_GRANTED) || (auth_result == AUTHZ_NEUTRAL))
            && (current_provider->all_next)
            && (current_provider->all_next->req_state_level < current_provider->req_state_level)) {
            authz_status temp_result = check_provider_list (r, current_provider->all_next,
                                                            current_provider->req_state_level);
            auth_result = RESOLVE_NEUTRAL(auth_result, temp_result);
        }
        /* If the *last* auth_result was DENIED and we are inside of a
         * Require_one block then look to see if there is another
         * Require_one node that can be satisfied
         */
        else if ((auth_result == AUTHZ_DENIED)
                 && (current_provider->one_next)
                 && (current_provider->one_next->req_state_level < current_provider->req_state_level)) {
            goto one_next;
        }

        return auth_result;
    }

    /* If the current node is a Require_All type */
    if (current_provider->req_state == AUTHZ_REQSTATE_ALL) {
        /* if the auth_result of *this* node was DENIED and we are
         * embedded in a Require_one block then look to see if there
         * is another Require_one node that can be satisfied
         */
        if (auth_result == AUTHZ_DENIED) {
            if ((current_provider->one_next) &&
                (current_provider->one_next->req_state_level < current_provider->req_state_level)) {
                authz_status temp_result = check_provider_list (r, current_provider->one_next,
                                                                current_provider->req_state_level);
                auth_result = RESOLVE_NEUTRAL(auth_result, temp_result);
            }
            return auth_result;
        }
        all_next:

        /* Traverse forward to the next Require_all node it one exists
         * otherwise just return the auth_result
         */
        if (current_provider->all_next) {
            authz_status temp_result = check_provider_list (r, current_provider->all_next,
                                                            current_provider->req_state_level);
            auth_result = RESOLVE_NEUTRAL(auth_result, temp_result);
        }
        else
            return auth_result;

        /* if the *last* auth_result was DENIED and we are embedded
         * in a Require_one block then look to see if there is another
         * Require_one node that can be satisfied
         */
        if ((auth_result == AUTHZ_DENIED)
            && (current_provider->one_next)
            && (current_provider->one_next->req_state_level < current_provider->req_state_level)) {
            authz_status temp_result = check_provider_list (r, current_provider->one_next,
                                                            current_provider->req_state_level);
            auth_result = RESOLVE_NEUTRAL(auth_result, temp_result);
        }
        /* If the *last* auth_result was GRANTED and we are inside of a
         * Require_all block then look to see if there is another
         * Require_all node that needs to be satisfied
         */
        else if (((auth_result == AUTHZ_GRANTED) || (auth_result == AUTHZ_NEUTRAL))
                 && (current_provider->all_next)
                 && (current_provider->all_next->req_state_level < current_provider->req_state_level)) {
            goto all_next;
        }
    }

    return auth_result;
}

static int authorize_user(request_rec *r)
{
    authz_core_dir_conf *conf;
    authz_status auth_result;
    authz_provider_list *current_provider;
    const char *note = apr_table_get(r->notes, AUTHZ_ACCESS_PASSED_NOTE);

    conf = ap_get_module_config(r->per_dir_config, &authz_core_module);

    /* If we're not really configured for providers, stop now. */
    if (!conf->providers) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "no authorization providers configured");
        return DECLINED;
    }

    /* run through the require logic. */
    current_provider = conf->providers;
    auth_result = check_provider_list (r, current_provider, 0);

    if (auth_result != AUTHZ_GRANTED) {
        int return_code;

        switch (auth_result) {
            case AUTHZ_DENIED:
            case AUTHZ_NEUTRAL:
                /* XXX If the deprecated Satisfy directive is set to anything
                   but ANY a failure in access control or authz will cause
                   an HTTP_UNAUTHORIZED.  Just the if statement
                   should be removed in 3.0 when the Satisfy directive
                   goes away. */
                if (!note || (ap_satisfies(r) != SATISFY_ANY) || (note[0] == 'N')) {
                    if (r->ap_auth_type == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "client denied by server configuration: %s%s",
                                      r->filename ? "" : "uri ",
                                      r->filename ? r->filename : r->uri);
                        return_code = HTTP_FORBIDDEN;
                    }
                    else {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "user %s: authorization failure for \"%s\": ",
                                      r->user, r->uri);
                        return_code = HTTP_UNAUTHORIZED;
                    }
                }
                else {
                    return_code = DECLINED;
                }
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
    authz_core_dir_conf *conf;
    authz_provider_list *current_provider;

    conf = ap_get_module_config(r->per_dir_config, &authz_core_module);

    current_provider = conf->providers;

    while (current_provider) {

        /* Does this provider config apply for this method */
        if (current_provider->method_mask &
                (AP_METHOD_BIT << r->method_number)) {
            return 1;
        }

        current_provider = current_provider->one_next;
    }

    return 0;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authz_some_auth_required);

    ap_hook_check_authz(authorize_user, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA authz_core_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_core_dir_config,   /* dir config creater */
    merge_authz_core_dir_config,    /* dir merger */
    create_authz_core_svr_config,   /* server config */
    NULL,                           /* merge server config */
    authz_cmds,
    register_hooks                  /* register hooks */
};

