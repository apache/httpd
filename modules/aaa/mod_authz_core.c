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
#include "ap_expr.h"

#include "mod_auth.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#undef AUTHZ_EXTRA_CONFIGS

typedef struct provider_alias_rec {
    char *provider_name;
    char *provider_alias;
    char *provider_args;
    const void *provider_parsed_args;
    ap_conf_vector_t *sec_auth;
    const authz_provider *provider;
} provider_alias_rec;

typedef enum {
    AUTHZ_LOGIC_AND,
    AUTHZ_LOGIC_OR,
    AUTHZ_LOGIC_OFF,
    AUTHZ_LOGIC_UNSET
} authz_logic_op;

typedef struct authz_section_conf authz_section_conf;

struct authz_section_conf {
    const char *provider_name;
    const char *provider_args;
    const void *provider_parsed_args;
    const authz_provider *provider;
    apr_int64_t limited;
    authz_logic_op op;
    int negate;
    /** true if this is not a real container but produced by AuthMerging;
     *  only used for logging */
    int is_merged;
    authz_section_conf *first;
    authz_section_conf *next;
};

typedef struct authz_core_dir_conf authz_core_dir_conf;

struct authz_core_dir_conf {
    authz_section_conf *section;
    authz_core_dir_conf *next;
    authz_logic_op op;
    signed char authz_forbidden_on_fail;
};

#define UNSET -1

typedef struct authz_core_srv_conf {
    apr_hash_t *alias_rec;
} authz_core_srv_conf;

module AP_MODULE_DECLARE_DATA authz_core_module;

static authz_core_dir_conf *authz_core_first_dir_conf;

static void *create_authz_core_dir_config(apr_pool_t *p, char *dummy)
{
    authz_core_dir_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->op = AUTHZ_LOGIC_UNSET;
    conf->authz_forbidden_on_fail = UNSET;

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

    if (new->op == AUTHZ_LOGIC_UNSET && !new->section && base->section ) {
        /* Only authz_forbidden_on_fail has been set in new. Don't treat
         * it as a new auth config w.r.t. AuthMerging */
        conf = apr_pmemdup(p, base, sizeof(*base));
    }
    else if (new->op == AUTHZ_LOGIC_OFF || new->op == AUTHZ_LOGIC_UNSET ||
             !(base->section || new->section)) {
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
                section->is_merged = 1;

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

    if (new->authz_forbidden_on_fail == UNSET)
        conf->authz_forbidden_on_fail = base->authz_forbidden_on_fail;
    else
        conf->authz_forbidden_on_fail = new->authz_forbidden_on_fail;

    return (void*)conf;
}

/* Only per-server directive we have is GLOBAL_ONLY */
static void *merge_authz_core_svr_config(apr_pool_t *p,
                                         void *basev, void *newv)
{
    return basev;
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
                                                    const char *require_args,
                                                    const void *parsed_require_args)
{
    const char *provider_name;

    /* Look up the provider alias in the alias list.
     * Get the dir_config and call ap_merge_per_dir_configs()
     * Call the real provider->check_authorization() function
     * Return the result of the above function call
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
            authz_status ret;

            r->per_dir_config =
                ap_merge_per_dir_configs(r->pool, orig_dir_config,
                                         prvdraliasrec->sec_auth);

            ret = prvdraliasrec->provider->
                check_authorization(r, prvdraliasrec->provider_args,
                                    prvdraliasrec->provider_parsed_args);

            r->per_dir_config = orig_dir_config;

            return ret;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02305)
                  "no alias provider found for '%s' (BUG?)",
                  provider_name ? provider_name : "n/a");

    return AUTHZ_DENIED;
}

static const authz_provider authz_alias_provider =
{
    &authz_alias_check_authorization,
    NULL,
};

static const char *authz_require_alias_section(cmd_parms *cmd, void *mconfig,
                                               const char *args)
{
    const char *endp = ap_strrchr_c(args, '>');
    char *provider_name;
    char *provider_alias;
    char *provider_args, *extra_args;
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

    args = apr_pstrndup(cmd->temp_pool, args, endp - args);

    if (!args[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive requires additional arguments", NULL);
    }

    /* Pull the real provider name and the alias name from the block header */
    provider_name = ap_getword_conf(cmd->pool, &args);
    provider_alias = ap_getword_conf(cmd->pool, &args);
    provider_args = ap_getword_conf(cmd->pool, &args);
    extra_args = ap_getword_conf(cmd->pool, &args);

    if (!provider_name[0] || !provider_alias[0]) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive requires additional arguments", NULL);
    }
    
    /* We only handle one "Require-Parameters" parameter.  If several parameters
       are needed, they must be enclosed between quotes */
    if (extra_args && *extra_args) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, APLOGNO(10142)
                     "When several arguments (%s %s...) are passed to a %s directive, "
                     "they must be enclosed in quotation marks.  Otherwise, only the "
                     "first one is taken into account",
                     provider_args, extra_args, cmd->cmd->name);
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
        if (prvdraliasrec->provider->parse_require_line) {
            err = prvdraliasrec->provider->parse_require_line(cmd,
                         provider_args, &prvdraliasrec->provider_parsed_args);
            if (err)
                return apr_psprintf(cmd->pool,
                                    "Can't parse 'Require %s %s': %s",
                                    provider_name, provider_args, err);
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
               : ((result == AUTHZ_DENIED_NO_USER)
                  ? "denied (no authenticated user yet)"
                  : "neutral")));
}

static const char* format_authz_command(apr_pool_t *p,
                                        authz_section_conf *section)
{
    return (section->provider
            ? apr_pstrcat(p, "Require ", (section->negate ? "not " : ""),
                          section->provider_name, " ",
                          section->provider_args, NULL)
            : apr_pstrcat(p, section->is_merged ? "AuthMerging " : "<Require",
                          ((section->op == AUTHZ_LOGIC_AND)
                           ? (section->negate ? "NotAll" : "All")
                           : (section->negate ? "None" : "Any")),
                          section->is_merged ? "" : ">", NULL));
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

    if (section->provider->parse_require_line) {
        const char *err;
        apr_pool_userdata_setn(section->provider_name,
                               AUTHZ_PROVIDER_NAME_NOTE,
                               apr_pool_cleanup_null,
                               cmd->temp_pool);
        err = section->provider->parse_require_line(cmd, args,
                                              &section->provider_parsed_args);

        if (err)
            return err;
    }

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

    args = apr_pstrndup(cmd->temp_pool, args, endp - args);

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
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, APR_SUCCESS, s, APLOGNO(01624)
                     "%s directive contains only negative authorization directives",
                     is_conf ? "<Directory>, <Location>, or similar"
                             : format_authz_command(p, section));
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
    AP_INIT_FLAG("AuthzSendForbiddenOnFailure", ap_set_flag_slot_char,
                 (void *)APR_OFFSETOF(authz_core_dir_conf, authz_forbidden_on_fail),
                 OR_AUTHCFG,
                 "Controls if an authorization failure should result in a "
                 "'403 FORBIDDEN' response instead of the HTTP-conforming "
                 "'401 UNAUTHORIZED'"),
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

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(01625)
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
            section->provider->check_authorization(r, section->provider_args,
                                                   section->provider_parsed_args);

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
                /*
                 * Handling of AUTHZ_DENIED/AUTHZ_DENIED_NO_USER: Return
                 * AUTHZ_DENIED_NO_USER if providing a user may change the
                 * result, AUTHZ_DENIED otherwise.
                 */
                if (section->op == AUTHZ_LOGIC_AND) {
                    if (child_result == AUTHZ_DENIED) {
                        auth_result = child_result;
                        break;
                    }
                    if ((child_result == AUTHZ_DENIED_NO_USER
                         && auth_result != AUTHZ_DENIED)
                        || (auth_result == AUTHZ_NEUTRAL)) {
                        auth_result = child_result;
                    }
                }
                else {
                    /* AUTHZ_LOGIC_OR */
                    if (child_result == AUTHZ_GRANTED) {
                        auth_result = child_result;
                        break;
                    }
                    if ((child_result == AUTHZ_DENIED_NO_USER
                         && auth_result == AUTHZ_DENIED)
                        || (auth_result == AUTHZ_NEUTRAL)) {
                        auth_result = child_result;
                    }
                }
            }

            child = child->next;
        }
    }

    if (section->negate) {
        if (auth_result == AUTHZ_GRANTED) {
            auth_result = AUTHZ_DENIED;
        }
        else if (auth_result == AUTHZ_DENIED ||
                 auth_result == AUTHZ_DENIED_NO_USER) {
            /* For negated directives, if the original result was denied
             * then the new result is neutral since we can not grant
             * access simply because authorization was not rejected.
             */
            auth_result = AUTHZ_NEUTRAL;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(01626)
                  "authorization result of %s: %s",
                  format_authz_command(r->pool, section),
                  format_authz_result(auth_result));

    return auth_result;
}

static int authorize_user_core(request_rec *r, int after_authn)
{
    authz_core_dir_conf *conf;
    authz_status auth_result;

    conf = ap_get_module_config(r->per_dir_config, &authz_core_module);

    if (!conf->section) {
        if (ap_auth_type(r)) {
            /* there's an AuthType configured, but no authorization
             * directives applied to support it
             */

            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(01627)
                          "AuthType configured with no corresponding "
                          "authorization directives");

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(01628)
                      "authorization result: granted (no directives)");

        return OK;
    }

    auth_result = apply_authz_sections(r, conf->section, AUTHZ_LOGIC_AND);

    if (auth_result == AUTHZ_GRANTED) {
        return OK;
    }
    else if (auth_result == AUTHZ_DENIED_NO_USER) {
        if (after_authn) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(01629)
                          "authorization failure (no authenticated user): %s",
                          r->uri);
            /*
             * If we're returning 401 to an authenticated user, tell them to
             * try again. If unauthenticated, note_auth_failure has already
             * been called during auth.
             */
            if (r->user)
                ap_note_auth_failure(r);

            return HTTP_UNAUTHORIZED;
        }
        else {
            /*
             * We need a user before we can decide what to do.
             * Get out of the way and proceed with authentication.
             */
            return DECLINED;
        }
    }
    else if (auth_result == AUTHZ_DENIED || auth_result == AUTHZ_NEUTRAL) {
        if (!after_authn || ap_auth_type(r) == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(01630)
                          "client denied by server configuration: %s%s",
                          r->filename ? "" : "uri ",
                          r->filename ? r->filename : r->uri);

            return HTTP_FORBIDDEN;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, APLOGNO(01631)
                          "user %s: authorization failure for \"%s\": ",
                          r->user, r->uri);

            if (conf->authz_forbidden_on_fail > 0) {
                return HTTP_FORBIDDEN;
            }
            else {
                /*
                 * If we're returning 401 to an authenticated user, tell them to
                 * try again. If unauthenticated, note_auth_failure has already
                 * been called during auth.
                 */
                if (r->user)
                    ap_note_auth_failure(r);
                return HTTP_UNAUTHORIZED;
            }
        }
    }
    else {
        /* We'll assume that the module has already said what its
         * error was in the logs.
         */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
}

static int authorize_userless(request_rec *r)
{
    return authorize_user_core(r, 0);
}

static int authorize_user(request_rec *r)
{
    return authorize_user_core(r, 1);
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

/*
 * env authz provider
 */

static authz_status env_check_authorization(request_rec *r,
                                            const char *require_line,
                                            const void *parsed_require_line)
{
    const char *t, *w;

    /* The 'env' provider will allow the configuration to specify a list of
        env variables to check rather than a single variable.  This is different
        from the previous host based syntax. */
    t = require_line;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (apr_table_get(r->subprocess_env, w)) {
            return AUTHZ_GRANTED;
        }
    }

    return AUTHZ_DENIED;
}

static const authz_provider authz_env_provider =
{
    &env_check_authorization,
    NULL,
};


/*
 * all authz provider
 */

static authz_status all_check_authorization(request_rec *r,
                                            const char *require_line,
                                            const void *parsed_require_line)
{
    if (parsed_require_line) {
        return AUTHZ_GRANTED;
    }
    return AUTHZ_DENIED;
}

static const char *all_parse_config(cmd_parms *cmd, const char *require_line,
                                    const void **parsed_require_line)
{
    /*
     * If the argument to the 'all' provider is 'granted' then just let
     * everybody in. This would be equivalent to the previous syntax of
     * 'allow from all'. If the argument is 'denied' we reject everybody,
     * which is equivalent to 'deny from all'.
     */
    if (strcasecmp(require_line, "granted") == 0) {
        *parsed_require_line = (void *)1;
        return NULL;
    }
    else if (strcasecmp(require_line, "denied") == 0) {
        /* *parsed_require_line is already NULL */
        return NULL;
    }
    else {
        return "Argument for 'Require all' must be 'granted' or 'denied'";
    }
}

static const authz_provider authz_all_provider =
{
    &all_check_authorization,
    &all_parse_config,
};


/*
 * method authz provider
 */

static authz_status method_check_authorization(request_rec *r,
                                               const char *require_line,
                                               const void *parsed_require_line)
{
    const apr_int64_t *allowed = parsed_require_line;
    if (*allowed & (AP_METHOD_BIT << r->method_number))
        return AUTHZ_GRANTED;
    else
        return AUTHZ_DENIED;
}

static const char *method_parse_config(cmd_parms *cmd, const char *require_line,
                                       const void **parsed_require_line)
{
    const char *w, *t;
    apr_int64_t *allowed = apr_pcalloc(cmd->pool, sizeof(apr_int64_t));

    t = require_line;

    while ((w = ap_getword_conf(cmd->temp_pool, &t)) && w[0]) {
        int m = ap_method_number_of(w);
        if (m == M_INVALID) {
            return apr_pstrcat(cmd->pool, "Invalid Method '", w, "'", NULL);
        }

        *allowed |= (AP_METHOD_BIT << m);
    }

    *parsed_require_line = allowed;
    return NULL;
}

static const authz_provider authz_method_provider =
{
    &method_check_authorization,
    &method_parse_config,
};

/*
 * expr authz provider
 */

#define REQUIRE_EXPR_NOTE "Require_expr_info"
struct require_expr_info {
    ap_expr_info_t *expr;
    int want_user;
};

static int expr_lookup_fn(ap_expr_lookup_parms *parms)
{
    if (parms->type == AP_EXPR_FUNC_VAR
        && strcasecmp(parms->name, "REMOTE_USER") == 0) {
        struct require_expr_info *info;
        apr_pool_userdata_get((void**)&info, REQUIRE_EXPR_NOTE, parms->ptemp);
        AP_DEBUG_ASSERT(info != NULL);
        info->want_user = 1;
    }
    return ap_expr_lookup_default(parms);
}

static const char *expr_parse_config(cmd_parms *cmd, const char *require_line,
                                     const void **parsed_require_line)
{
    const char *expr_err = NULL;
    struct require_expr_info *info = apr_pcalloc(cmd->pool, sizeof(*info));

    /* if the expression happens to be surrounded by quotes, skip them */
    if (require_line[0] == '"') {
        apr_size_t len = strlen(require_line);

        if (require_line[len-1] == '"')
            require_line = apr_pstrndup(cmd->temp_pool,
                                        require_line + 1,
                                        len - 2);
    }

    apr_pool_userdata_setn(info, REQUIRE_EXPR_NOTE, apr_pool_cleanup_null,
                          cmd->temp_pool);
    info->expr = ap_expr_parse_cmd(cmd, require_line, 0, &expr_err,
                                   expr_lookup_fn);

    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = info;

    return NULL;
}

static authz_status expr_check_authorization(request_rec *r,
                                             const char *require_line,
                                             const void *parsed_require_line)
{
    const char *err = NULL;
    const struct require_expr_info *info = parsed_require_line;
    int rc = ap_expr_exec(r, info->expr, &err);

    if (rc < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02320)
                      "Error evaluating expression in 'Require expr': %s",
                      err);
        return AUTHZ_GENERAL_ERROR;
    }
    else if (rc == 0) {
        if (info->want_user)
            return AUTHZ_DENIED_NO_USER;
        else
            return AUTHZ_DENIED;
    }
    else {
        return AUTHZ_GRANTED;
    }
}

static const authz_provider authz_expr_provider =
{
    &expr_check_authorization,
    &expr_parse_config,
};


static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authz_some_auth_required);

    ap_hook_pre_config(authz_core_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(authz_core_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_authz(authorize_user, NULL, NULL, APR_HOOK_LAST,
                        AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_check_access_ex(authorize_userless, NULL, NULL, APR_HOOK_LAST,
                            AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "env",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_env_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "all",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_all_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "method",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_method_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "expr",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_expr_provider, AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_core) =
{
    STANDARD20_MODULE_STUFF,
    create_authz_core_dir_config,   /* dir config creater */
    merge_authz_core_dir_config,    /* dir merger */
    create_authz_core_svr_config,   /* server config */
    merge_authz_core_svr_config ,   /* merge server config */
    authz_cmds,
    register_hooks                  /* register hooks */
};

