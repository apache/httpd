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

#undef AUTHZ_EXTRA_CONFIGS

typedef struct provider_alias_rec {
    char *provider_name;
    char *provider_alias;
    char *provider_args;
    ap_conf_vector_t *sec_auth;
    const authz_provider *provider;
} provider_alias_rec;

typedef enum {
    AUTHZ_LOGIC_AND,
    AUTHZ_LOGIC_OR,
    AUTHZ_LOGIC_OFF
} authz_logic_op;

typedef struct authz_section_conf authz_section_conf;

struct authz_section_conf {
    const char *provider_name;
    const char *provider_args;
    const authz_provider *provider;
    apr_int64_t limited;
    authz_logic_op op;
    int negate;
    authz_section_conf *first;
    authz_section_conf *next;
};

typedef struct authz_core_dir_conf authz_core_dir_conf;

struct authz_core_dir_conf {
    authz_section_conf *section;
    authz_logic_op op;
    authz_core_dir_conf *next;
};

typedef struct authz_core_srv_conf {
    apr_hash_t *alias_rec;
} authz_core_srv_conf;

module AP_MODULE_DECLARE_DATA authz_core_module;

static authz_core_dir_conf *authz_core_first_dir_conf;

static void *create_authz_core_dir_config(apr_pool_t *p, char *dummy)
{
    authz_core_dir_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->op = AUTHZ_LOGIC_OFF;

    conf->next = authz_core_first_dir_conf;
    authz_core_first_dir_conf = conf;

    return (void *)conf;
}

static void *merge_authz_core_dir_config(apr_pool_t *p,
                                         void *basev, void *newv)
{
    authz_core_dir_conf *base = (authz_core_dir_conf *)basev;
    authz_core_dir_conf *new = (authz_core_dir_conf *)newv;
    authz_core_dir_conf *conf;

    if (new->op == AUTHZ_LOGIC_OFF || !(base->section || new->section)) {
        conf = apr_pmemdup(p, new, sizeof(*new));
    }
    else {
        authz_section_conf *section;

        if (base->section) {
            if (new->section) {
                section = apr_pcalloc(p, sizeof(*section));

                section->limited =
                    base->section->limited | new->section->limited;

                section->op = new->op;

                section->first = apr_pmemdup(p, base->section,
                                             sizeof(*base->section));
                section->first->next = apr_pmemdup(p, new->section,
                                                   sizeof(*new->section));
            } else {
                section = apr_pmemdup(p, base->section,
                                      sizeof(*base->section));
            }
        }
        else {
            section = apr_pmemdup(p, new->section, sizeof(*new->section));
        }

        conf = apr_pcalloc(p, sizeof(*conf));

        conf->section = section;
        conf->op = new->op;
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
    cmd->override = OR_AUTHCFG | ACCESS_CONF;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd,
                            new_authz_config);
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

static const char* format_authz_result(authz_status result)
{
    return ((result == AUTHZ_DENIED)
            ? "denied"
            : ((result == AUTHZ_GRANTED)
               ? "granted"
               : "neutral"));
}

static const char* format_authz_command(apr_pool_t *p,
                                        authz_section_conf *section)
{
    return (section->provider
            ? apr_pstrcat(p, "Require ", (section->negate ? "not " : ""),
                          section->provider_name, " ",
                          section->provider_args, NULL)
            : apr_pstrcat(p, "<Require",
                          ((section->op == AUTHZ_LOGIC_AND)
                           ? (section->negate ? "NotAll" : "All")
                           : (section->negate ? "None" : "Any")),
                          ">", NULL));
}

static authz_section_conf* create_default_section(apr_pool_t *p)
{
    authz_section_conf *section = apr_pcalloc(p, sizeof(*section));

    section->op = AUTHZ_LOGIC_OR;

    return section;
}

static const char *add_authz_provider(cmd_parms *cmd, void *config,
                                      const char *args)
{
    authz_core_dir_conf *conf = (authz_core_dir_conf*)config;
    authz_section_conf *section = apr_pcalloc(cmd->pool, sizeof(*section));
    authz_section_conf *child;

    section->provider_name = ap_getword_conf(cmd->pool, &args);

    if (!strcasecmp(section->provider_name, "not")) {
        section->provider_name = ap_getword_conf(cmd->pool, &args);
        section->negate = 1;
    }

    section->provider_args = args;

    /* lookup and cache the actual provider now */
    section->provider = ap_lookup_provider(AUTHZ_PROVIDER_GROUP,
                                           section->provider_name,
                                           AUTHZ_PROVIDER_VERSION);

    /* by the time the config file is used, the provider should be loaded
     * and registered with us.
     */
    if (!section->provider) {
        return apr_psprintf(cmd->pool,
                            "Unknown Authz provider: %s",
                            section->provider_name);
    }

    /* if the provider doesn't provide the appropriate function, reject it */
    if (!section->provider->check_authorization) {
        return apr_psprintf(cmd->pool,
                            "The '%s' Authz provider is not supported by any "
                            "of the loaded authorization modules",
                            section->provider_name);
    }

    section->limited = cmd->limited;

    if (!conf->section) {
        conf->section = create_default_section(cmd->pool);
    }

    if (section->negate && conf->section->op == AUTHZ_LOGIC_OR) {
        return apr_psprintf(cmd->pool, "negative %s directive has no effect "
                            "in %s directive",
                            cmd->cmd->name,
                            format_authz_command(cmd->pool, conf->section));
    }

    conf->section->limited |= section->limited;

    child = conf->section->first;

    if (child) {
        while (child->next) {
            child = child->next;
        }

        child->next = section;
    }
    else {
        conf->section->first = section;
    }

    return NULL;
}

static const char *add_authz_section(cmd_parms *cmd, void *mconfig,
                                     const char *args)
{
    authz_core_dir_conf *conf = mconfig;
    const char *endp = ap_strrchr_c(args, '>');
    authz_section_conf *old_section = conf->section;
    authz_section_conf *section;
    int old_overrides = cmd->override;
    apr_int64_t old_limited = cmd->limited;
    const char *errmsg;

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    args = apr_pstrndup(cmd->pool, args, endp - args);

    if (args[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive doesn't take additional arguments",
                           NULL);
    }

    section = apr_pcalloc(cmd->pool, sizeof(*section));

    if (!strcasecmp(cmd->cmd->name, "<RequireAll")) {
        section->op = AUTHZ_LOGIC_AND;
    }
    else if (!strcasecmp(cmd->cmd->name, "<RequireAny")) {
        section->op = AUTHZ_LOGIC_OR;
    }
    else if (!strcasecmp(cmd->cmd->name, "<RequireNotAll")) {
        section->op = AUTHZ_LOGIC_AND;
        section->negate = 1;
    }
    else {
        section->op = AUTHZ_LOGIC_OR;
        section->negate = 1;
    }

    conf->section = section;

    /* trigger NOT_IN_LIMIT errors as if this were a <Limit> directive */
    cmd->limited &= ~(AP_METHOD_BIT << (METHODS - 1));

    cmd->override = OR_AUTHCFG;
    errmsg = ap_walk_config(cmd->directive->first_child, cmd, cmd->context);
    cmd->override = old_overrides;

    cmd->limited = old_limited;

    conf->section = old_section;

    if (errmsg) {
        return errmsg;
    }

    if (section->first) {
        authz_section_conf *child;

        if (!old_section) {
            old_section = conf->section = create_default_section(cmd->pool);
        }

        if (section->negate && old_section->op == AUTHZ_LOGIC_OR) {
            return apr_psprintf(cmd->pool, "%s directive has "
                                "no effect in %s directive",
                                format_authz_command(cmd->pool, section),
                                format_authz_command(cmd->pool, old_section));
        }

        old_section->limited |= section->limited;

        if (!section->negate && section->op == old_section->op) {
            /* be associative */
            section = section->first;
        }

        child = old_section->first;

        if (child) {
            while (child->next) {
                child = child->next;
            }

            child->next = section;
        }
        else {
            old_section->first = section;
        }
    }
    else {
        return apr_pstrcat(cmd->pool,
                           format_authz_command(cmd->pool, section),
                           " directive contains no authorization directives",
                           NULL);
    }

    return NULL;
}

static const char *authz_merge_sections(cmd_parms *cmd, void *mconfig,
                                        const char *arg)
{
    authz_core_dir_conf *conf = mconfig;

    if (!strcasecmp(arg, "Off")) {
        conf->op = AUTHZ_LOGIC_OFF;
    }
    else if (!strcasecmp(arg, "And")) {
        conf->op = AUTHZ_LOGIC_AND;
    }
    else if (!strcasecmp(arg, "Or")) {
        conf->op = AUTHZ_LOGIC_OR;
    }
    else {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " must be one of: "
                           "Off | And | Or", NULL);
    }

    return NULL;
}

static int authz_core_check_section(apr_pool_t *p, server_rec *s,
                                    authz_section_conf *section, int is_conf)
{
    authz_section_conf *prev = NULL;
    authz_section_conf *child = section->first;
    int ret = !OK;

    while (child) {
        if (child->first) {
            if (authz_core_check_section(p, s, child, 0) != OK) {
                return !OK;
            }

            if (child->negate && child->op != section->op) {
                authz_section_conf *next = child->next;

                /* avoid one level of recursion when De Morgan permits */
                child = child->first;

                if (prev) {
                    prev->next = child;
                }
                else {
                    section->first = child;
                }

                do {
                    child->negate = !child->negate;
                } while (child->next && (child = child->next));

                child->next = next;
            }
        }

        prev = child;
        child = child->next;
    }

    child = section->first;

    while (child) {
        if (!child->negate) {
            ret = OK;
            break;
        }

        child = child->next;
    }

    if (ret != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, APR_SUCCESS, s,
                     "%s",
                     apr_pstrcat(p, (is_conf
                                     ? "<Directory>, <Location>, or similar"
                                     : format_authz_command(p, section)),
                                 " directive contains only negative "
                                 "authorization directives", NULL));
    }

    return ret;
}

static int authz_core_pre_config(apr_pool_t *p, apr_pool_t *plog,
                                 apr_pool_t *ptemp)
{
    authz_core_first_dir_conf = NULL;

    return OK;
}

static int authz_core_check_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    authz_core_dir_conf *conf = authz_core_first_dir_conf;

    while (conf) {
        if (conf->section) {
            if (authz_core_check_section(p, s, conf->section, 1) != OK) {
                return !OK;
            }
        }

        conf = conf->next;
    }

    return OK;
}

static const command_rec authz_cmds[] =
{
    AP_INIT_RAW_ARGS("<AuthzProviderAlias", authz_require_alias_section,
                     NULL, RSRC_CONF,
                     "container for grouping an authorization provider's "
                     "directives under a provider alias"),
    AP_INIT_RAW_ARGS("Require", add_authz_provider, NULL, OR_AUTHCFG,
                     "specifies authorization directives "
                     "which one must pass (or not) for a request to suceeed"),
    AP_INIT_RAW_ARGS("<RequireAll", add_authz_section, NULL, OR_AUTHCFG,
                     "container for grouping authorization directives "
                     "of which none must fail and at least one must pass "
                     "for a request to succeed"),
    AP_INIT_RAW_ARGS("<RequireAny", add_authz_section, NULL, OR_AUTHCFG,
                     "container for grouping authorization directives "
                     "of which one must pass "
                     "for a request to succeed"),
#ifdef AUTHZ_EXTRA_CONFIGS
    AP_INIT_RAW_ARGS("<RequireNotAll", add_authz_section, NULL, OR_AUTHCFG,
                     "container for grouping authorization directives "
                     "of which some must fail or none must pass "
                     "for a request to succeed"),
#endif
    AP_INIT_RAW_ARGS("<RequireNone", add_authz_section, NULL, OR_AUTHCFG,
                     "container for grouping authorization directives "
                     "of which none must pass "
                     "for a request to succeed"),
    AP_INIT_TAKE1("AuthMerging", authz_merge_sections, NULL, OR_AUTHCFG,
                  "controls how a <Directory>, <Location>, or similar "
                  "directive's authorization directives are combined with "
                  "those of its predecessor"),
    {NULL}
};

static authz_status apply_authz_sections(request_rec *r,
                                         authz_section_conf *section,
                                         authz_logic_op parent_op)
{
    authz_status auth_result;

    /* check to make sure that the request method requires authorization */
    if (!(section->limited & (AP_METHOD_BIT << r->method_number))) {
        auth_result =
            (parent_op == AUTHZ_LOGIC_AND) ? AUTHZ_GRANTED : AUTHZ_NEUTRAL;

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "authorization result of %s: %s "
                      "(directive limited to other methods)",
                      format_authz_command(r->pool, section),
                      format_authz_result(auth_result));

        return auth_result;
    }

    if (section->provider) {
        apr_table_setn(r->notes, AUTHZ_PROVIDER_NAME_NOTE,
                       section->provider_name);

        auth_result =
            section->provider->check_authorization(r, section->provider_args);

        apr_table_unset(r->notes, AUTHZ_PROVIDER_NAME_NOTE);
    }
    else {
        authz_section_conf *child = section->first;

        auth_result = AUTHZ_NEUTRAL;

        while (child) {
            authz_status child_result;

            child_result = apply_authz_sections(r, child, section->op);

            if (child_result == AUTHZ_GENERAL_ERROR) {
                return AUTHZ_GENERAL_ERROR;
            }

            if (child_result != AUTHZ_NEUTRAL) {
                auth_result = child_result;

                if ((section->op == AUTHZ_LOGIC_AND
                     && child_result == AUTHZ_DENIED)
                    || (section->op == AUTHZ_LOGIC_OR
                        && child_result == AUTHZ_GRANTED)) {
                    break;
                }
            }

            child = child->next;
        }
    }

    if (section->negate) {
        if (auth_result == AUTHZ_GRANTED) {
            auth_result = AUTHZ_DENIED;
        }
        else if (auth_result == AUTHZ_DENIED) {
            /* For negated directives, if the original result was denied
             * then the new result is neutral since we can not grant
             * access simply because authorization was not rejected.
             */
            auth_result = AUTHZ_NEUTRAL;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                  "authorization result of %s: %s",
                  format_authz_command(r->pool, section),
                  format_authz_result(auth_result));

    return auth_result;
}

static int authorize_user(request_rec *r)
{
    authz_core_dir_conf *conf;
    authz_status auth_result;

    conf = ap_get_module_config(r->per_dir_config, &authz_core_module);

    if (!conf->section) {
        if (ap_auth_type(r)) {
            /* there's an AuthType configured, but no authorization
             * directives applied to support it
             */

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "AuthType configured with no corresponding "
                          "authorization directives");

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
                      "authorization result: granted (no directives)");

        return OK;
    }

    auth_result = apply_authz_sections(r, conf->section, AUTHZ_LOGIC_AND);

    if (auth_result == AUTHZ_GRANTED) {
        return OK;
    }
    else if (auth_result == AUTHZ_DENIED || auth_result == AUTHZ_NEUTRAL) {
        if (ap_auth_type(r) == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "client denied by server configuration: %s%s",
                          r->filename ? "" : "uri ",
                          r->filename ? r->filename : r->uri);

            return HTTP_FORBIDDEN;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "user %s: authorization failure for \"%s\": ",
                          r->user, r->uri);

            /* If we're returning 403, tell them to try again. */
            /* XXX: ap_note_auth_failure is currently broken */
            /*ap_note_auth_failure(r);*/

            return HTTP_UNAUTHORIZED;
        }
    }
    else {
        /* We'll assume that the module has already said what its
         * error was in the logs.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}

static int authz_some_auth_required(request_rec *r)
{
    authz_core_dir_conf *conf;

    conf = ap_get_module_config(r->per_dir_config, &authz_core_module);

    if (conf->section
        && (conf->section->limited & (AP_METHOD_BIT << r->method_number))) {
        return 1;
    }

    return 0;
}

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authz_some_auth_required);

    ap_hook_pre_config(authz_core_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(authz_core_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_authz(authorize_user, NULL, NULL, APR_HOOK_LAST,
                        AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_core) =
{
    STANDARD20_MODULE_STUFF,
    create_authz_core_dir_config,   /* dir config creater */
    merge_authz_core_dir_config,    /* dir merger */
    create_authz_core_svr_config,   /* server config */
    NULL,                           /* merge server config */
    authz_cmds,
    register_hooks                  /* register hooks */
};

