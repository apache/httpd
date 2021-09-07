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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_expr.h"

extern module AP_MODULE_DECLARE_DATA log_debug_module;

typedef struct {
    ap_expr_info_t *msg_expr;
    ap_expr_info_t *condition;
    const char *hook;
} msg_entry;

typedef struct {
    apr_array_header_t *entries;
} log_debug_dirconf;

static const char *allhooks = "all";
static const char * const hooks[] = {
    "log_transaction",      /*  0 */
    "quick_handler",        /*  1 */
    "handler",              /*  2 */
    "translate_name",       /*  3 */
    "map_to_storage",       /*  4 */
    "fixups",               /*  5 */
    "type_checker",         /*  6 */
    "check_access",         /*  7 */
    "check_access_ex",      /*  8 */
    "check_authn",          /*  9 */
    "check_authz",          /* 10 */
    "insert_filter",        /* 11 */
    "pre_translate_name",   /* 12 */
    NULL
};

static void do_debug_log(request_rec *r, const char *hookname)
{
    log_debug_dirconf *dconf = ap_get_module_config(r->per_dir_config, &log_debug_module);
    int i;
    if (dconf->entries == NULL)
        return;

    for (i = 0; i < dconf->entries->nelts; i++) {
        const char *msg, *err;
        msg_entry *entry = APR_ARRAY_IDX(dconf->entries, i, msg_entry *);
        if (entry->hook != allhooks && entry->hook != hookname)
            continue;
        if (entry->condition) {
            int ret = ap_expr_exec(r, entry->condition, &err);
            if (err) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00640)
                              "Can't evaluate condition: %s", err);
                continue;
            }
            if (!ret)
                continue;
        }
        msg = ap_expr_str_exec(r, entry->msg_expr, &err);
        if (err)
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00641)
                          "Can't evaluate message expression: %s", err);
        if (APLOGrdebug(r))
            /* Intentional no APLOGNO */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                           "%s (%s hook, %s:%d)",
                           msg, hookname, entry->msg_expr->filename,
                           entry->msg_expr->line_number);
        else
            /* Intentional no APLOGNO */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "%s", msg);
    }
}

static int log_debug_log_transaction(request_rec *r)
{
    do_debug_log(r, hooks[0]);
    return DECLINED;
}

static int log_debug_quick_handler(request_rec *r, int lookup_uri)
{
    do_debug_log(r, hooks[1]);
    return DECLINED;
}

static int log_debug_handler(request_rec *r)
{
    do_debug_log(r, hooks[2]);
    return DECLINED;
}

static int log_debug_pre_translate_name(request_rec *r)
{
    do_debug_log(r, hooks[12]);
    return DECLINED;
}

static int log_debug_translate_name(request_rec *r)
{
    do_debug_log(r, hooks[3]);
    return DECLINED;
}

static int log_debug_map_to_storage(request_rec *r)
{
    do_debug_log(r, hooks[4]);
    return DECLINED;
}

static int log_debug_fixups(request_rec *r)
{
    do_debug_log(r, hooks[5]);
    return DECLINED;
}

static int log_debug_type_checker(request_rec *r)
{
    do_debug_log(r, hooks[6]);
    return DECLINED;
}

static int log_debug_check_access(request_rec *r)
{
    do_debug_log(r, hooks[7]);
    return DECLINED;
}

static int log_debug_check_access_ex(request_rec *r)
{
    do_debug_log(r, hooks[8]);
    return DECLINED;
}

static int log_debug_check_authn(request_rec *r)
{
    do_debug_log(r, hooks[9]);
    return DECLINED;
}

static int log_debug_check_authz(request_rec *r)
{
    do_debug_log(r, hooks[10]);
    return DECLINED;
}

static void log_debug_insert_filter(request_rec *r)
{
    do_debug_log(r, hooks[11]);
}

static void *log_debug_create_dconf(apr_pool_t *p, char *dirspec)
{
    log_debug_dirconf *dconf = apr_pcalloc(p, sizeof(log_debug_dirconf));
    return dconf;
}

static void *log_debug_merge_dconf(apr_pool_t *p, void *parent_conf, void *new_conf)
{
    log_debug_dirconf *merged = apr_pcalloc(p, sizeof(log_debug_dirconf));
    const log_debug_dirconf *parent = parent_conf;
    const log_debug_dirconf *new = new_conf;

    if (parent->entries == NULL)
        merged->entries = new->entries;
    else if (new->entries == NULL)
        merged->entries = parent->entries;
    else
        /* apr_array_append actually creates a new array */
        merged->entries = apr_array_append(p, parent->entries, new->entries);

    return merged;
}

static const char *cmd_log_message(cmd_parms *cmd, void *dconf_, const char *arg1,
                                   const char *arg2, const char *arg3)
{
    msg_entry *entry = apr_pcalloc(cmd->pool, sizeof(msg_entry));
    log_debug_dirconf *dconf = dconf_;
    int i, j;
    const char *err;
    const char *args[2];
    args[0] = arg2;
    args[1] = arg3;

    entry->msg_expr = ap_expr_parse_cmd(cmd, arg1, AP_EXPR_FLAG_STRING_RESULT|
                                                   AP_EXPR_FLAG_DONT_VARY,
                                        &err, NULL);
    if (err)
        return apr_psprintf(cmd->pool,
                            "Could not parse message expression '%s': %s",
                            arg1, err);

    for (i = 0; i < 2; i++) {
        if (args[i] == NULL)
            break;

        if (strncasecmp(args[i], "hook=", 5) == 0) {
            const char *name = args[i] + 5;
            j = 0;
            while (hooks[j]) {
                if (strcasecmp(hooks[j], name) == 0) {
                    entry->hook = hooks[j];
                    break;
                }
                j++;
            }
            if (entry->hook == NULL) {
                if (strcmp(name, "*") == 0 || strcasecmp(name, allhooks) == 0)
                    entry->hook = allhooks;
                else
                    return apr_psprintf(cmd->pool, "Invalid hook name: %s", name);
            }
        }
        else if (strncasecmp(args[i], "expr=", 5) == 0) {
            const char *expr = args[i] + 5;
            entry->condition = ap_expr_parse_cmd(cmd, expr,
                                                 AP_EXPR_FLAG_DONT_VARY,
                                                 &err, NULL);
            if (err)
                return apr_psprintf(cmd->pool,
                                    "Could not parse expression '%s': %s",
                                    expr, err);
        }
        else {
            return apr_psprintf(cmd->pool, "Invalid argument %s", args[i]);
        }
    }
    if (entry->hook == NULL)
        entry->hook = hooks[0];

    if (!dconf->entries)
        dconf->entries = apr_array_make(cmd->pool, 4, sizeof(msg_entry *));

    APR_ARRAY_PUSH(dconf->entries, msg_entry *) = entry;

    return NULL;
}

static const command_rec log_debug_cmds[] =
{
    AP_INIT_TAKE123("LogMessage", cmd_log_message, NULL, RSRC_CONF|ACCESS_CONF,
        "Log a debug message to the error log if this config block is used for "
        " a request"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_log_transaction(log_debug_log_transaction, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_quick_handler(log_debug_quick_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_handler(log_debug_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_pre_translate_name(log_debug_pre_translate_name, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_translate_name(log_debug_translate_name, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_map_to_storage(log_debug_map_to_storage, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(log_debug_fixups, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_type_checker(log_debug_type_checker, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_check_access(log_debug_check_access, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
    ap_hook_check_access_ex(log_debug_check_access_ex, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
    ap_hook_check_authn(log_debug_check_authn, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
    ap_hook_check_authz(log_debug_check_authz, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
    ap_hook_insert_filter(log_debug_insert_filter, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(log_debug) =
{
    STANDARD20_MODULE_STUFF,
    log_debug_create_dconf,     /* create per-dir config */
    log_debug_merge_dconf,      /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    log_debug_cmds,             /* command apr_table_t */
    register_hooks              /* register hooks */
};

