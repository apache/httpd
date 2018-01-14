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

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "ap_provider.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_strings.h"
#include "mod_authz_dbd.h"

#include "mod_auth.h"


module AP_MODULE_DECLARE_DATA authz_dbd_module;

/* Export a hook for modules that manage clientside sessions
 * (e.g. mod_auth_cookie)
 * to deal with those when we successfully login/logout at the server
 *
 * XXX: WHY would this be specific to dbd_authz?  Why wouldn't we track
 * this across all authz user providers in a lower level mod, such as
 * mod_auth_basic/digest?
 */
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(authz_dbd, AUTHZ_DBD, int, client_login,
                            (request_rec *r, int code, const char *action),
                            (r, code, action), OK, DECLINED)


typedef struct {
    const char *query;
    const char *redir_query;
    int redirect;
} authz_dbd_cfg ;

static ap_dbd_t *(*dbd_handle)(request_rec*) = NULL;
static void (*dbd_prepare)(server_rec*, const char*, const char*) = NULL;

static const char *const noerror = "???";

static void *authz_dbd_cr_cfg(apr_pool_t *pool, char *dummy)
{
    authz_dbd_cfg *ret = apr_pcalloc(pool, sizeof(authz_dbd_cfg));
    ret->redirect = -1;
    return ret;
}

static void *authz_dbd_merge_cfg(apr_pool_t *pool, void *BASE, void *ADD)
{
    authz_dbd_cfg *base = BASE;
    authz_dbd_cfg *add = ADD;
    authz_dbd_cfg *ret = apr_palloc(pool, sizeof(authz_dbd_cfg));

    ret->query = (add->query == NULL) ? base->query : add->query;
    ret->redir_query = (add->redir_query == NULL)
                            ? base->redir_query : add->redir_query;
    ret->redirect = (add->redirect == -1) ? base->redirect : add->redirect;
    return ret;
}

static const char *authz_dbd_prepare(cmd_parms *cmd, void *cfg,
                                     const char *query)
{
    static unsigned int label_num = 0;
    char *label;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    if (dbd_prepare == NULL) {
        dbd_prepare = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (dbd_prepare == NULL) {
            return "You must load mod_dbd to enable AuthzDBD functions";
        }
        dbd_handle = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }
    label = apr_psprintf(cmd->pool, "authz_dbd_%d", ++label_num);

    dbd_prepare(cmd->server, query, label);

    /* save the label here for our own use */
    return ap_set_string_slot(cmd, cfg, label);
}

static const command_rec authz_dbd_cmds[] = {
    AP_INIT_FLAG("AuthzDBDLoginToReferer", ap_set_flag_slot,
                 (void*)APR_OFFSETOF(authz_dbd_cfg, redirect), ACCESS_CONF,
                 "Whether to redirect to referer on successful login"),
    AP_INIT_TAKE1("AuthzDBDQuery", authz_dbd_prepare,
                  (void*)APR_OFFSETOF(authz_dbd_cfg, query), ACCESS_CONF,
                  "SQL query for DBD Authz or login"),
    AP_INIT_TAKE1("AuthzDBDRedirectQuery", authz_dbd_prepare,
                  (void*)APR_OFFSETOF(authz_dbd_cfg, redir_query), ACCESS_CONF,
                  "SQL query to get per-user redirect URL after login"),
    {NULL}
};

static int authz_dbd_login(request_rec *r, authz_dbd_cfg *cfg,
                           const char *action)
{
    int rv;
    const char *newuri = NULL;
    int nrows;
    const char *message;
    ap_dbd_t *dbd;
    apr_dbd_prepared_t *query;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;

    if (cfg->query == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01642)
                      "No query configured for %s!", action);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    dbd = dbd_handle(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02902)
                      "No db handle available for %s! "
                      "Check your database access",
                      action);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    query = apr_hash_get(dbd->prepared, cfg->query, APR_HASH_KEY_STRING);
    if (query == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01643)
                      "Error retrieving Query for %s!", action);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_dbd_pvquery(dbd->driver, r->pool, dbd->handle, &nrows,
                         query, r->user, NULL);
    if (rv == 0) {
        if (nrows != 1) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01644)
                          "authz_dbd: %s of user %s updated %d rows",
                          action, r->user, nrows);
        }
    }
    else {
        message = apr_dbd_error(dbd->driver, dbd->handle, rv);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01645)
                      "authz_dbd: query for %s failed; user %s [%s]",
                      action, r->user, message?message:noerror);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cfg->redirect == 1) {
        newuri = apr_table_get(r->headers_in, "Referer");
    }

    if (!newuri && cfg->redir_query) {
        query = apr_hash_get(dbd->prepared, cfg->redir_query,
                             APR_HASH_KEY_STRING);
        if (query == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01646)
                          "authz_dbd: no redirect query!");
            /* OK, this is non-critical; we can just not-redirect */
        }
        else if ((rv = apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle,
                                        &res, query, 0, r->user, NULL)) == 0) {
            for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
                 rv != -1;
                 rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
                if (rv != 0) {
                    message = apr_dbd_error(dbd->driver, dbd->handle, rv);
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01647)
                          "authz_dbd in get_row; action=%s user=%s [%s]",
                          action, r->user, message?message:noerror);
                }
                else if (newuri == NULL) {
                    newuri =
                        apr_pstrdup(r->pool,
                                    apr_dbd_get_entry(dbd->driver, row, 0));
                }
                /* we can't break out here or row won't get cleaned up */
            }
        }
        else {
            message = apr_dbd_error(dbd->driver, dbd->handle, rv);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01648)
                          "authz_dbd/redirect for %s of %s [%s]",
                          action, r->user, message?message:noerror);
        }
    }
    if (newuri != NULL) {
        r->status = HTTP_MOVED_TEMPORARILY;
        apr_table_set(r->err_headers_out, "Location", newuri);
    }
    authz_dbd_run_client_login(r, OK, action);
    return OK;
}

static int authz_dbd_group_query(request_rec *r, authz_dbd_cfg *cfg,
                                 apr_array_header_t *groups)
{
    /* SELECT group FROM authz WHERE user = %s */
    int rv;
    const char *message;
    ap_dbd_t *dbd;
    apr_dbd_prepared_t *query;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;

    if (cfg->query == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01649)
                      "No query configured for dbd-group!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    dbd = dbd_handle(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02903)
                      "No db handle available for dbd-query! "
                      "Check your database access");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    query = apr_hash_get(dbd->prepared, cfg->query, APR_HASH_KEY_STRING);
    if (query == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01650)
                      "Error retrieving query for dbd-group!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    rv = apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res,
                          query, 0, r->user, NULL);
    if (rv == 0) {
        for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
             rv != -1;
             rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
            if (rv == 0) {
                APR_ARRAY_PUSH(groups, const char *) =
                    apr_pstrdup(r->pool,
                                apr_dbd_get_entry(dbd->driver, row, 0));
            }
            else {
                message = apr_dbd_error(dbd->driver, dbd->handle, rv);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01651)
                        "authz_dbd in get_row; group query for user=%s [%s]",
                        r->user, message?message:noerror);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    else {
        message = apr_dbd_error(dbd->driver, dbd->handle, rv);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01652)
                      "authz_dbd, in groups query for %s [%s]",
                      r->user, message?message:noerror);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}

static authz_status dbdgroup_check_authorization(request_rec *r,
                                                 const char *require_args,
                                                 const void *parsed_require_args)
{
    int rv;
    const char *w;
    apr_array_header_t *groups;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;
    authz_dbd_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                              &authz_dbd_module);

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    groups = apr_array_make(r->pool, 4, sizeof(const char*));
    rv = authz_dbd_group_query(r, cfg, groups);
    if (rv != OK) {
        return AUTHZ_GENERAL_ERROR;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02590)
                      "authz_dbd authorize: require dbd-group: Can't "
                      "evaluate require expression: %s", err);
        return AUTHZ_DENIED;
    }

    t = require;
    while (t[0]) {
        w = ap_getword_white(r->pool, &t);
        if (ap_array_str_contains(groups, w)) {
            return AUTHZ_GRANTED;
        }
    }

    return AUTHZ_DENIED;
}

static authz_status dbdlogin_check_authorization(request_rec *r,
                                                 const char *require_args,
                                                 const void *parsed_require_args)
{
    authz_dbd_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                              &authz_dbd_module);

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    return (authz_dbd_login(r, cfg, "login") == OK ? AUTHZ_GRANTED : AUTHZ_DENIED);
}

static authz_status dbdlogout_check_authorization(request_rec *r,
                                                  const char *require_args,
                                                  const void *parsed_require_args)
{
    authz_dbd_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                              &authz_dbd_module);

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    return (authz_dbd_login(r, cfg, "logout") == OK ? AUTHZ_GRANTED : AUTHZ_DENIED);
}

static const char *dbd_parse_config(cmd_parms *cmd, const char *require_line,
                                    const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
                             &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);
    }

    *parsed_require_line = expr;

    return NULL;
}

static const authz_provider authz_dbdgroup_provider =
{
    &dbdgroup_check_authorization,
    &dbd_parse_config,
};

static const authz_provider authz_dbdlogin_provider =
{
    &dbdlogin_check_authorization,
    NULL,
};

static const authz_provider authz_dbdlogout_provider =
{
    &dbdlogout_check_authorization,
    NULL,
};

static void authz_dbd_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "dbd-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_dbdgroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "dbd-login",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_dbdlogin_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "dbd-logout",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_dbdlogout_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_dbd) =
{
    STANDARD20_MODULE_STUFF,
    authz_dbd_cr_cfg,
    authz_dbd_merge_cfg,
    NULL,
    NULL,
    authz_dbd_cmds,
    authz_dbd_hooks
};
