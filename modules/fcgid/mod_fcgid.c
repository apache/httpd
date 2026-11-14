/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
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
#include "http_request.h"
#include "http_protocol.h"
#include "ap_mmn.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "mod_cgi.h"
#include "mod_status.h"
#include "util_script.h"
#include "fcgid_global.h"
#include "fcgid_pm.h"
#include "fcgid_proctbl.h"
#include "fcgid_conf.h"
#include "fcgid_spawn_ctl.h"
#include "fcgid_bridge.h"
#include "fcgid_filter.h"
#include "fcgid_protocol.h"
#include "fcgid_proc.h"

static APR_OPTIONAL_FN_TYPE(ap_cgi_build_command) * cgi_build_command;
static ap_filter_rec_t *fcgid_filter_handle;
static int g_php_fix_pathinfo_enable = 0;

enum fcgid_procnode_type {
    FCGID_PROCNODE_TYPE_IDLE,
    FCGID_PROCNODE_TYPE_BUSY,
    FCGID_PROCNODE_TYPE_ERROR,
};

enum fcgid_auth_check_mode {
    FCGID_AUTH_CHECK_AUTHN,
    FCGID_AUTH_CHECK_AUTHZ,
    FCGID_AUTH_CHECK_ACCESS
};

/* Stolen from mod_cgi.c */
/* KLUDGE --- for back-compatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

static int is_scriptaliased(request_rec * r)
{
    const char *t = apr_table_get(r->notes, "alias-forced-type");

    return t && (!strcasecmp(t, "cgi-script"));
}

static apr_status_t
default_build_command(const char **cmd, const char ***argv,
                      request_rec * r, apr_pool_t * p,
                      cgi_exec_info_t * e_info)
{
    int numwords, x, idx;
    char *w;
    const char *args = NULL;

    if (e_info->process_cgi) {
        *cmd = r->filename;
        /* Do not process r->args if they contain an '=' assignment
         */
        if (r->args && r->args[0] && !ap_strchr_c(r->args, '=')) {
            args = r->args;
        }
    }

    if (!args) {
        numwords = 1;
    } else {
        /* count the number of keywords */
        for (x = 0, numwords = 2; args[x]; x++) {
            if (args[x] == '+') {
                ++numwords;
            }
        }
    }
    /* Everything is - 1 to account for the first parameter
     * which is the program name.
     */
    if (numwords > APACHE_ARG_MAX - 1) {
        numwords = APACHE_ARG_MAX - 1;  /* Truncate args to prevent overrun */
    }
    *argv = apr_palloc(p, (numwords + 2) * sizeof(char *));
    (*argv)[0] = *cmd;
    for (x = 1, idx = 1; x < numwords; x++) {
        w = ap_getword_nulls(p, &args, '+');
        ap_unescape_url(w);
        (*argv)[idx++] = ap_escape_shell_cmd(p, w);
    }
    (*argv)[idx] = NULL;

    return APR_SUCCESS;
}

/* http2env stolen from util_script.c */
static char *http2env(apr_pool_t *a, const char *w)
{
    char *res = (char *)apr_palloc(a, sizeof("HTTP_") + strlen(w));
    char *cp = res;
    char c;

    *cp++ = 'H';
    *cp++ = 'T';
    *cp++ = 'T';
    *cp++ = 'P';
    *cp++ = '_';

    while ((c = *w++) != 0) {
        if (!apr_isalnum(c)) {
            *cp++ = '_';
        }
        else {
            *cp++ = apr_toupper(c);
        }
    }
    *cp = 0;

    return res;
}

static void fcgid_add_cgi_vars(request_rec * r)
{
    apr_array_header_t *passheaders = get_pass_headers(r);

    if (passheaders != NULL) {
        const char **hdr = (const char **) passheaders->elts;
        int hdrcnt = passheaders->nelts;
        int i;

        for (i = 0; i < hdrcnt; i++, ++hdr) {
            const char *val = apr_table_get(r->headers_in, *hdr);

            if (val) {
                /* no munging of header name to create envvar name;
                 * consistent with legacy mod_fcgid behavior and mod_fastcgi
                 * prior to 2.4.7
                 */
                apr_table_setn(r->subprocess_env, *hdr, val);
                /* standard munging of header name (upcase, HTTP_, etc.) */
                apr_table_setn(r->subprocess_env, http2env(r->pool, *hdr), val);
            }
        }
    }

    /* Work around cgi.fix_pathinfo = 1 in php.ini */
    if (g_php_fix_pathinfo_enable) {
        char *merge_path;
        apr_table_t *e = r->subprocess_env;

        /* "DOCUMENT_ROOT"/"SCRIPT_NAME" -> "SCRIPT_NAME" */
        const char *doc_root = apr_table_get(e, "DOCUMENT_ROOT");
        const char *script_name = apr_table_get(e, "SCRIPT_NAME");

        if (doc_root && script_name
            && apr_filepath_merge(&merge_path, doc_root, script_name, 0,
                                  r->pool) == APR_SUCCESS) {
            apr_table_setn(e, "SCRIPT_NAME", merge_path);
        }
    }
}

static int fcgid_handler(request_rec * r)
{
    cgi_exec_info_t e_info;
    const char *command;
    const char **argv;
    apr_status_t rv;
    int http_retcode;
    fcgid_cmd_conf *wrapper_conf;

    if (strcmp(r->handler, "fcgid-script"))
        return DECLINED;

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r))
        return HTTP_FORBIDDEN;

    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info)
        return HTTP_NOT_FOUND;

    e_info.process_cgi = 1;
    e_info.cmd_type = APR_PROGRAM;
    e_info.detached = 0;
    e_info.in_pipe = APR_CHILD_BLOCK;
    e_info.out_pipe = APR_CHILD_BLOCK;
    e_info.err_pipe = APR_CHILD_BLOCK;
    e_info.prog_type = RUN_AS_CGI;
    e_info.bb = NULL;
    e_info.ctx = NULL;
    e_info.next = NULL;

    wrapper_conf = get_wrapper_info(r->filename, r);

    /* Check for existence of requested file, unless we use a virtual wrapper. */
    if (wrapper_conf == NULL || !wrapper_conf->virtual) {
        if (r->finfo.filetype == 0)
            return HTTP_NOT_FOUND;

        if (r->finfo.filetype == APR_DIR)
            return HTTP_FORBIDDEN;
    }

    /* Build the command line */
    if (wrapper_conf) {
        if ((rv =
             default_build_command(&command, &argv, r, r->pool,
                                   &e_info)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "mod_fcgid: don't know how to spawn wrapper child process: %s",
                          r->filename);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        if ((rv = cgi_build_command(&command, &argv, r, r->pool,
                                    &e_info)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "mod_fcgid: don't know how to spawn child process: %s",
                          r->filename);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Check request like "http://localhost/cgi-bin/a.exe/defghi" */
        if (r->finfo.inode == 0 && r->finfo.device == 0) {
            if ((rv =
                 apr_stat(&r->finfo, command, APR_FINFO_IDENT,
                          r->pool)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                              "mod_fcgid: can't get %s file info", command);
                return HTTP_NOT_FOUND;
            }
        }

        /* Dummy up a wrapper configuration, using the requested file as
         * both the executable path and command-line.
         */
        wrapper_conf = apr_pcalloc(r->pool, sizeof(*wrapper_conf));

        if (strlen(command) >= fcgid_min(FCGID_PATH_MAX, FCGID_CMDLINE_MAX)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_fcgid: Executable path length exceeds compiled-in limit: %s",
                          command);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        wrapper_conf->cgipath = apr_pstrdup(r->pool, command);
        wrapper_conf->cmdline = wrapper_conf->cgipath;
        wrapper_conf->inode = r->finfo.inode;
        wrapper_conf->deviceid = r->finfo.device;
    }

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    fcgid_add_cgi_vars(r);

    /* Remove hop-by-hop headers handled by http
     */
    apr_table_unset(r->subprocess_env, "HTTP_KEEP_ALIVE");
    apr_table_unset(r->subprocess_env, "HTTP_TE");
    apr_table_unset(r->subprocess_env, "HTTP_TRAILER");
    apr_table_unset(r->subprocess_env, "HTTP_TRANSFER_ENCODING");
    apr_table_unset(r->subprocess_env, "HTTP_UPGRADE");

    /* Connection hop-by-hop header to prevent the CGI from hanging */
    apr_table_set(r->subprocess_env, "HTTP_CONNECTION", "close");

    /* Insert output filter */
    ap_add_output_filter_handle(fcgid_filter_handle, NULL, r,
                                r->connection);

    http_retcode = bridge_request(r, FCGI_RESPONDER, wrapper_conf);
    return (http_retcode == HTTP_OK ? OK : http_retcode);
}

static int fcgidsort(fcgid_procnode **e1, fcgid_procnode **e2)
{
    int cmp = strcmp((*e1)->executable_path, (*e2)->executable_path);

    if (cmp != 0)
        return cmp;
    if ((*e1)->gid != (*e2)->gid)
        return (*e1)->gid > (*e2)->gid ? 1 : -1;
    if ((*e1)->uid != (*e2)->uid)
        return (*e1)->uid > (*e2)->uid ? 1 : -1;
    cmp = strcmp((*e1)->cmdline, (*e2)->cmdline);
    if (cmp != 0)
        return cmp;
    if ((*e1)->vhost_id != (*e2)->vhost_id)
        return (*e1)->vhost_id > (*e2)->vhost_id ? 1 : -1;
    if ((*e1)->diewhy != (*e2)->diewhy)
        return (*e1)->diewhy > (*e2)->diewhy ? 1 : -1;
    if ((*e1)->node_type != (*e2)->node_type)
        return (*e1)->node_type > (*e2)->node_type ? 1 : -1;
    return 0;
}

static char *get_state_desc(fcgid_procnode *node)
{
    if (node->node_type == FCGID_PROCNODE_TYPE_IDLE)
        return "Ready";
    else if (node->node_type == FCGID_PROCNODE_TYPE_BUSY)
        return "Working";
    else {
        switch (node->diewhy) {
        case FCGID_DIE_KILLSELF:
            return "Exiting(normal exit)";
        case FCGID_DIE_IDLE_TIMEOUT:
            return "Exiting(idle timeout)";
        case FCGID_DIE_LIFETIME_EXPIRED:
            return "Exiting(lifetime expired)";
        case FCGID_DIE_BUSY_TIMEOUT:
            return "Exiting(busy timeout)";
        case FCGID_DIE_CONNECT_ERROR:
            return "Exiting(connect error)";
        case FCGID_DIE_COMM_ERROR:
            return "Exiting(communication error)";
        case FCGID_DIE_SHUTDOWN:
            return "Exiting(shutting down)";
        default:
            return "Exiting";
        }
    }
}

/* fcgid Extension to mod_status */
static int fcgid_status_hook(request_rec *r, int flags)
{
    fcgid_procnode **ar = NULL, *current_node;
    int num_ent, index;
    apr_ino_t last_inode = 0;
    apr_dev_t last_deviceid = 0;
    gid_t last_gid = 0;
    uid_t last_uid = 0;
    const char *last_cmdline = "";
    apr_time_t now;
    int last_vhost_id = -1;
    const char *basename, *tmpbasename;
    fcgid_procnode *proc_table = proctable_get_table_array();
    fcgid_procnode *error_list_header = proctable_get_error_list();
    fcgid_procnode *idle_list_header = proctable_get_idle_list();
    fcgid_procnode *busy_list_header = proctable_get_busy_list();

    if ((flags & AP_STATUS_SHORT) || (proc_table == NULL))
        return OK;

    proctable_lock(r);

    /* Get element count */
    num_ent = 0;
    current_node = &proc_table[busy_list_header->next_index];
    while (current_node != proc_table) {
        num_ent++;
        current_node = &proc_table[current_node->next_index];
    }
    current_node = &proc_table[idle_list_header->next_index];
    while (current_node != proc_table) {
        num_ent++;
        current_node = &proc_table[current_node->next_index];
    }
    current_node = &proc_table[error_list_header->next_index];
    while (current_node != proc_table) {
        num_ent++;
        current_node = &proc_table[current_node->next_index];
    }

    /* Create an array for qsort() */
    if (num_ent != 0) {
        ar = (fcgid_procnode **)apr_palloc(r->pool, num_ent * sizeof(fcgid_procnode*));
        index = 0;
        current_node = &proc_table[busy_list_header->next_index];
        while (current_node != proc_table) {
            ar[index] = apr_palloc(r->pool, sizeof(fcgid_procnode));
            *ar[index] = *current_node;
            ar[index++]->node_type = FCGID_PROCNODE_TYPE_BUSY;
            current_node = &proc_table[current_node->next_index];
        }
        current_node = &proc_table[idle_list_header->next_index];
        while (current_node != proc_table) {
            ar[index] = apr_palloc(r->pool, sizeof(fcgid_procnode));
            *ar[index] = *current_node;
            ar[index++]->node_type = FCGID_PROCNODE_TYPE_IDLE;
            current_node = &proc_table[current_node->next_index];
        }
        current_node = &proc_table[error_list_header->next_index];
        while (current_node != proc_table) {
            ar[index] = apr_palloc(r->pool, sizeof(fcgid_procnode));
            *ar[index] = *current_node;
            ar[index++]->node_type = FCGID_PROCNODE_TYPE_ERROR;
            current_node = &proc_table[current_node->next_index];
        }
    }
    proctable_unlock(r);

    now = apr_time_now();

    /* Sort the array */
    if (num_ent != 0)
        qsort((void *)ar, num_ent, sizeof(fcgid_procnode *),
              (int (*)(const void *, const void *))fcgidsort);

    /* Output */
    ap_rputs("<hr />\n<h1>mod_fcgid status:</h1>\n", r);
    ap_rprintf(r, "Total FastCGI processes: %d\n", num_ent);
    for (index = 0; index < num_ent; index++) {
    	current_node = ar[index];
        if (current_node->inode != last_inode || current_node->deviceid != last_deviceid
            || current_node->gid != last_gid || current_node->uid != last_uid
            || strcmp(current_node->cmdline, last_cmdline)
            || current_node->vhost_id != last_vhost_id) {
            if (index != 0)
                 ap_rputs("</table>\n\n", r);

            /* Print executable path basename */
	    tmpbasename = ap_strrchr_c(current_node->executable_path, '/');
	    if (tmpbasename != NULL)
                tmpbasename++;
            basename = ap_strrchr_c(tmpbasename, '\\');
            if (basename != NULL)
                basename++;
	    else
                basename = tmpbasename;
            ap_rprintf(r, "<hr />\n<b>Process: %s</b>&nbsp;&nbsp;(%s)<br />\n",
                       basename, current_node->cmdline);

            /* Create a new table for this process info */
            ap_rputs("\n\n<table border=\"0\"><tr>"
                     "<th>Pid</th><th>Active</th><th>Idle</th>"
                     "<th>Accesses</th><th>State</th>"
                     "</tr>\n", r);

            last_inode = current_node->inode;
            last_deviceid = current_node->deviceid;
            last_gid = current_node->gid;
            last_uid = current_node->uid;
            last_cmdline = current_node->cmdline;
            last_vhost_id = current_node->vhost_id;
        }

        ap_rprintf(r, "<tr><td>%" APR_PID_T_FMT "</td><td>%" APR_TIME_T_FMT "</td><td>%" APR_TIME_T_FMT "</td><td>%d</td><td>%s</td></tr>",
                   current_node->proc_id.pid,
                   apr_time_sec(now - current_node->start_time),
                   apr_time_sec(now - current_node->last_active_time),
                   current_node->requests_handled,
                   get_state_desc(current_node));
    }
    if (num_ent != 0) {
        ap_rputs("</table>\n\n", r);
        ap_rputs("<hr>\n"
                 "<b>Active</b> and <b>Idle</b> are time active and time since\n"
                 "last request, in seconds.\n", r);
    }

    return OK;
}

static int mod_fcgid_modify_auth_header(void *subprocess_env,
                                        const char *key, const char *val)
{
    /* When the application gives a 200 response, the server ignores response
       headers whose names aren't prefixed with Variable- prefix, and ignores
       any response content */
    if (strncasecmp(key, "Variable-", 9) == 0)
        apr_table_setn(subprocess_env, key + 9, val);
    return 1;
}

static int mod_fcgid_check_auth(request_rec *r,
                                enum fcgid_auth_check_mode auth_check_mode)
{
    int res = 0;
    const char *password = NULL;
    apr_table_t *saved_subprocess_env = NULL;
    fcgid_cmd_conf *auth_cmd_info = NULL;
    int authoritative;
    const char *auth_role = NULL;
    const char *role_log_msg = NULL;
    const char *user_log_msg = "";

    /* Because we don't function as authn/z providers, integration with
     * the standard httpd authn/z modules is somewhat problematic.
     *
     * With httpd 2.4 in particular, our hook functions may be
     * circumvented by mod_authz_core's check_access_ex hook, unless
     * Require directives specify that user-based authn/z is needed.
     *
     * Even then, APR_HOOK_MIDDLE may cause our authentication hook to be
     * ordered after mod_auth_basic's check_authn hook, in which case it
     * will be skipped unless AuthBasicAuthoritative is Off and no authn
     * provider recognizes the user or outright denies the request.
     *
     * Also, when acting as an authenticator, we don't have a mechanism to
     * set r->user based on the script response, so scripts can't implement
     * a private authentication scheme; instead we use ap_get_basic_auth_pw()
     * and only support Basic HTTP authentication.
     *
     * It is possible to act reliably as both authenticator and authorizer
     * if mod_authn_core is loaded to support AuthType and AuthName, but
     * mod_authz_core and mod_auth_basic are not loaded.  However, in this
     * case the Require directive is not available, which defeats many
     * common configuration tropes.
     */

    switch (auth_check_mode) {
    case FCGID_AUTH_CHECK_AUTHN:
        auth_cmd_info = get_authenticator_info(r, &authoritative);
        auth_role = "AUTHENTICATOR";
        role_log_msg = "Authentication";
        break;

    case FCGID_AUTH_CHECK_AUTHZ:
        auth_cmd_info = get_authorizer_info(r, &authoritative);
        auth_role = "AUTHORIZER";
        role_log_msg = "Authorization";
        break;

    case FCGID_AUTH_CHECK_ACCESS:
        auth_cmd_info = get_access_info(r, &authoritative);
        auth_role = "ACCESS_CHECKER";
        role_log_msg = "Access check";
        break;
    }

    /* Is this auth check command enabled? */
    if (auth_cmd_info == NULL)
        return DECLINED;

    /* Get the user password */
    if (auth_check_mode == FCGID_AUTH_CHECK_AUTHN
        && (res = ap_get_basic_auth_pw(r, &password)) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_fcgid: authenticator requires "
                      "basic HTTP auth credentials");
        return res;
    }

    if (auth_check_mode != FCGID_AUTH_CHECK_ACCESS) {
        user_log_msg = apr_psprintf(r->pool, " of user %s", r->user);
    }

    /* Save old process environment */
    saved_subprocess_env = apr_table_copy(r->pool, r->subprocess_env);

    /* Add some environment variables */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    fcgid_add_cgi_vars(r);
    if (auth_check_mode == FCGID_AUTH_CHECK_AUTHN) {
        apr_table_setn(r->subprocess_env, "REMOTE_PASSWD", password);
    }
    apr_table_setn(r->subprocess_env, "FCGI_APACHE_ROLE", auth_role);

    /* Drop the variables CONTENT_LENGTH, PATH_INFO, PATH_TRANSLATED,
     * SCRIPT_NAME and most Hop-By-Hop headers - EXCEPT we will pass
     * PROXY_AUTH to allow CGI to perform proxy auth for httpd
     */
    apr_table_unset(r->subprocess_env, "CONTENT_LENGTH");
    apr_table_unset(r->subprocess_env, "PATH_INFO");
    apr_table_unset(r->subprocess_env, "PATH_TRANSLATED");
    apr_table_unset(r->subprocess_env, "SCRIPT_NAME");
    apr_table_unset(r->subprocess_env, "HTTP_KEEP_ALIVE");
    apr_table_unset(r->subprocess_env, "HTTP_TE");
    apr_table_unset(r->subprocess_env, "HTTP_TRAILER");
    apr_table_unset(r->subprocess_env, "HTTP_TRANSFER_ENCODING");
    apr_table_unset(r->subprocess_env, "HTTP_UPGRADE");

    /* Connection hop-by-hop header to prevent the CGI from hanging */
    apr_table_set(r->subprocess_env, "HTTP_CONNECTION", "close");

    /* Handle the request */
    res = bridge_request(r, FCGI_AUTHORIZER, auth_cmd_info);

    /* Restore r->subprocess_env */
    r->subprocess_env = saved_subprocess_env;

    if (res == OK && r->status == HTTP_OK
        && apr_table_get(r->headers_out, "Location") == NULL) {
        /* Pass */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_fcgid: %s%s to access %s succeeded",
                      role_log_msg, user_log_msg, r->uri);

        /* Modify headers: An Authorizer application's 200 response may include headers
           whose names are prefixed with Variable-.  */
        apr_table_do(mod_fcgid_modify_auth_header, r->subprocess_env,
                     r->err_headers_out, NULL);

        return OK;
    }
    else {
        const char *add_err_msg = "";

        /* Print error info first */
        if (res != OK) {
            add_err_msg =
                apr_psprintf(r->pool, "; error or unexpected condition "
                                      "while parsing response (%d)", res);
        }
        else if (r->status == HTTP_OK) {
            add_err_msg = "; internal redirection not allowed";
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_fcgid: %s%s to access %s failed, reason: "
                      "script returned status %d%s",
                      role_log_msg, user_log_msg, r->uri, r->status,
                      add_err_msg);

        /* Handle error */
        if (!authoritative) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_fcgid: not authoritative");
            return DECLINED;
        }
        else {
            if (auth_check_mode != FCGID_AUTH_CHECK_ACCESS) {
                ap_note_basic_auth_failure(r);
            }
            return (res == OK) ? HTTP_UNAUTHORIZED : res;
        }
    }
}

static int mod_fcgid_authenticator(request_rec *r)
{
    return mod_fcgid_check_auth(r, FCGID_AUTH_CHECK_AUTHN);
}

static int mod_fcgid_authorizer(request_rec *r)
{
    return mod_fcgid_check_auth(r, FCGID_AUTH_CHECK_AUTHZ);
}

static int mod_fcgid_check_access(request_rec *r)
{
    return mod_fcgid_check_auth(r, FCGID_AUTH_CHECK_ACCESS);
}

static void initialize_child(apr_pool_t * pchild, server_rec * main_server)
{
    apr_status_t rv;

    if ((rv = proctable_child_init(main_server, pchild)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: Can't initialize shared memory or mutex in child");
        return;
    }

    if ((rv = procmgr_child_init(main_server, pchild)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: Can't initialize process manager");
        return;
    }

    return;
}

static int
fcgid_init(apr_pool_t * config_pool, apr_pool_t * plog, apr_pool_t * ptemp,
           server_rec * main_server)
{
    const char *userdata_key = "fcgid_init";
    apr_status_t rv;
    void *dummy = NULL;
    fcgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                    &fcgid_module);

    ap_add_version_component(config_pool, MODFCGID_PRODUCT);

    g_php_fix_pathinfo_enable = sconf->php_fix_pathinfo_enable;

    /* Initialize process manager only once */
    apr_pool_userdata_get(&dummy, userdata_key,
                          main_server->process->pool);
    if (!dummy) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null,
                              main_server->process->pool);
        return OK;
    }

    /* Initialize share memory and share lock */
    if ((rv =
         proctable_post_config(main_server, config_pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: Can't initialize shared memory or mutex");
        return rv;
    }

    /* Initialize process manager */
    if ((rv =
         procmgr_post_config(main_server, config_pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, main_server,
                     "mod_fcgid: Can't initialize process manager");
        return rv;
    }

    /* This is the means by which unusual (non-unix) os's may find alternate
     * means to run a given command (e.g. shebang/registry parsing on Win32)
     */
    cgi_build_command = APR_RETRIEVE_OPTIONAL_FN(ap_cgi_build_command);
    if (!cgi_build_command) {
        cgi_build_command = default_build_command;
    }

    return APR_SUCCESS;
}

static const command_rec fcgid_cmds[] = {
    AP_INIT_TAKE1("FcgidAccessChecker", set_access_info, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "a absolute access checker file path"),
    AP_INIT_FLAG("FcgidAccessCheckerAuthoritative",
                 set_access_authoritative, NULL, ACCESS_CONF | OR_FILEINFO,
                 "Set to 'off' to allow access control to be passed along to lower modules upon failure"),
    AP_INIT_TAKE1("FcgidAuthenticator", set_authenticator_info, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "a absolute authenticator file path"),
    AP_INIT_FLAG("FcgidAuthenticatorAuthoritative",
                 set_authenticator_authoritative, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "Set to 'off' to allow authentication to be passed along to lower modules upon failure"),
    AP_INIT_TAKE1("FcgidAuthorizer", set_authorizer_info, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "a absolute authorizer file path"),
    AP_INIT_FLAG("FcgidAuthorizerAuthoritative",
                 set_authorizer_authoritative, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "Set to 'off' to allow authorization to be passed along to lower modules upon failure"),
    AP_INIT_TAKE1("FcgidBusyScanInterval", set_busy_scan_interval, NULL,
                  RSRC_CONF,
                  "scan interval for busy timeout process"),
    AP_INIT_TAKE1("FcgidBusyTimeout", set_busy_timeout, NULL, RSRC_CONF,
                  "a fastcgi application will be killed after handling a request for BusyTimeout"),
    AP_INIT_RAW_ARGS("FcgidCmdOptions", set_cmd_options, NULL, RSRC_CONF,
                     "set processing options for a FastCGI command"),
    AP_INIT_TAKE12("FcgidInitialEnv", add_default_env_vars, NULL, RSRC_CONF,
                   "an environment variable name and optional value to pass to FastCGI."),
    AP_INIT_TAKE1("FcgidMaxProcessesPerClass",
                  set_max_class_process,
                  NULL, RSRC_CONF,
                  "Max process count of one class of fastcgi application"),
    AP_INIT_TAKE1("FcgidMinProcessesPerClass",
                  set_min_class_process,
                  NULL, RSRC_CONF,
                  "Min process count of one class of fastcgi application"),
    AP_INIT_TAKE1("FcgidErrorScanInterval", set_error_scan_interval, NULL,
                  RSRC_CONF,
                  "scan interval for exited process"),
    AP_INIT_TAKE1("FcgidIdleScanInterval", set_idle_scan_interval, NULL,
                  RSRC_CONF,
                  "scan interval for idle timeout process"),
    AP_INIT_TAKE1("FcgidIdleTimeout", set_idle_timeout, NULL, RSRC_CONF,
                  "an idle fastcgi application will be killed after IdleTimeout"),
    AP_INIT_TAKE1("FcgidIOTimeout", set_ipc_comm_timeout, NULL, RSRC_CONF,
                  "Communication timeout to fastcgi server"),
    AP_INIT_TAKE1("FcgidConnectTimeout", set_ipc_connect_timeout, NULL,
                  RSRC_CONF,
                  "Connect timeout to fastcgi server"),
    AP_INIT_TAKE1("FcgidMaxProcesses", set_max_process, NULL, RSRC_CONF,
                  "Max total process count"),
    AP_INIT_TAKE1("FcgidMaxRequestInMem", set_max_mem_request_len, NULL,
                  RSRC_CONF,
                  "The part of HTTP request which greater than this limit will swap to disk"),
    AP_INIT_TAKE1("FcgidMaxRequestLen", set_max_request_len, NULL, RSRC_CONF,
                  "Max HTTP request length in byte"),
    AP_INIT_TAKE1("FcgidMaxRequestsPerProcess", set_max_requests_per_process,
                  NULL, RSRC_CONF,
                  "Max requests handled by each fastcgi application"),
    AP_INIT_TAKE1("FcgidOutputBufferSize", set_output_buffersize, NULL,
                  RSRC_CONF,
                  "CGI output buffer size"),
    AP_INIT_TAKE1("FcgidPassHeader", add_pass_headers, NULL, RSRC_CONF,
                  "Header name which will be passed to FastCGI as environment variable."),
    AP_INIT_TAKE1("FcgidFixPathinfo",
                  set_php_fix_pathinfo_enable,
                  NULL, RSRC_CONF,
                  "Set 1, if cgi.fix_pathinfo=1 in php.ini"),
    AP_INIT_TAKE1("FcgidProcessLifeTime", set_proc_lifetime, NULL, RSRC_CONF,
                  "fastcgi application lifetime"),
    AP_INIT_TAKE1("FcgidProcessTableFile", set_shmpath, NULL, RSRC_CONF,
                  "fastcgi shared memory file path"),
    AP_INIT_TAKE1("FcgidIPCDir", set_socketpath, NULL, RSRC_CONF,
                  "fastcgi socket file path"),
    AP_INIT_TAKE1("FcgidSpawnScore", set_spawn_score, NULL, RSRC_CONF,
                  "Score of spawn"),
    AP_INIT_TAKE1("FcgidSpawnScoreUpLimit", set_spawnscore_uplimit, NULL,
                  RSRC_CONF,
                  "Spawn score up limit"),
    AP_INIT_TAKE1("FcgidTerminationScore", set_termination_score, NULL,
                  RSRC_CONF,
                  "Score of termination"),
    AP_INIT_TAKE1("FcgidTimeScore", set_time_score, NULL,
                  RSRC_CONF,
                  "Score of passage of time (in seconds)"),
    AP_INIT_TAKE123("FcgidWrapper", set_wrapper_config, NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "The CGI wrapper file an optional URL suffix and an optional flag"),
    AP_INIT_TAKE1("FcgidZombieScanInterval", set_zombie_scan_interval, NULL,
                  RSRC_CONF,
                  "scan interval for zombie process"),
#ifdef WIN32
    AP_INIT_FLAG("FcgidWin32PreventOrphans",
                 set_win32_prevent_process_orphans, NULL, RSRC_CONF,
                 "Prevented fcgi process orphaning during Apache worker "
                 "abrupt shutdowns [see documentation]"),
#endif

    /* The following directives are all deprecated in favor
     * of a consistent use of the Fcgid prefix.
     * Add all new command above this line.
     */
    AP_INIT_TAKE1("BusyScanInterval", set_busy_scan_interval, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidBusyScanInterval' instead"),
    AP_INIT_TAKE1("BusyTimeout", set_busy_timeout, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidBusyTimeout' instead"),
    AP_INIT_TAKE12("DefaultInitEnv", add_default_env_vars, NULL, RSRC_CONF,
                   "Deprecated - Use 'FcgidInitialEnv' instead"),
    AP_INIT_TAKE1("DefaultMaxClassProcessCount",
                  set_max_class_process,
                  NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidMaxProcessesPerClass' instead"),
    AP_INIT_TAKE1("DefaultMinClassProcessCount",
                  set_min_class_process,
                  NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidMinProcessesPerClass' instead"),
    AP_INIT_TAKE1("ErrorScanInterval", set_error_scan_interval, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidErrorScanInterval' instead"),
    AP_INIT_TAKE1("FastCgiAccessChecker", set_access_info, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "Deprecated - Use 'FcgidAccessChecker' instead"),
    AP_INIT_FLAG("FastCgiAccessCheckerAuthoritative",
                 set_access_authoritative, NULL, ACCESS_CONF | OR_FILEINFO,
                 "Deprecated - Use 'FcgidAccessCheckerAuthoritative' instead"),
    AP_INIT_TAKE1("FastCgiAuthenticator", set_authenticator_info, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "Deprecated - Use 'FcgidAuthenticator' instead"),
    AP_INIT_FLAG("FastCgiAuthenticatorAuthoritative",
                 set_authenticator_authoritative, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "Deprecated - Use 'FcgidAuthenticatorAuthoritative' instead"),
    AP_INIT_TAKE1("FastCgiAuthorizer", set_authorizer_info, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "Deprecated - Use 'FcgidAuthorizer' instead"),
    AP_INIT_FLAG("FastCgiAuthorizerAuthoritative",
                 set_authorizer_authoritative, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "Deprecated - Use 'FcgidAuthorizerAuthoritative' instead"),
    AP_INIT_TAKE123("FCGIWrapper", set_wrapper_config, NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "Deprecated - Use 'FcgidWrapper' instead"),
    AP_INIT_TAKE1("IdleScanInterval", set_idle_scan_interval, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidIdleScanInterval' instead"),
    AP_INIT_TAKE1("IdleTimeout", set_idle_timeout, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidIdleTimeout' instead"),
    AP_INIT_TAKE1("IPCCommTimeout", set_ipc_comm_timeout, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidIOTimeout' instead"),
    AP_INIT_TAKE1("IPCConnectTimeout", set_ipc_connect_timeout, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidConnectTimeout' instead"),
    AP_INIT_TAKE1("MaxProcessCount", set_max_process, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidMaxProcesses' instead"),
    AP_INIT_TAKE1("MaxRequestInMem", set_max_mem_request_len, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidMaxRequestInMem' instead"),
    AP_INIT_TAKE1("MaxRequestLen", set_max_request_len, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidMaxRequestLen' instead"),
    AP_INIT_TAKE1("MaxRequestsPerProcess", set_max_requests_per_process,
                  NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidMaxRequestsPerProcess' instead"),
    AP_INIT_TAKE1("OutputBufferSize", set_output_buffersize, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidOutputBufferSize' instead"),
    AP_INIT_TAKE1("PassHeader", add_pass_headers, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidPassHeader' instead"),
    AP_INIT_TAKE1("PHP_Fix_Pathinfo_Enable",
                  set_php_fix_pathinfo_enable,
                  NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidFixPathinfo' instead"),
    AP_INIT_TAKE1("ProcessLifeTime", set_proc_lifetime, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidProcessLifeTime' instead"),
    AP_INIT_TAKE1("SharememPath", set_shmpath, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidProcessTableFile' instead"),
    AP_INIT_TAKE1("SocketPath", set_socketpath, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidIPCDir' instead"),
    AP_INIT_TAKE1("SpawnScore", set_spawn_score, NULL, RSRC_CONF,
                  "Deprecated - Use 'FcgidSpawnScore' instead"),
    AP_INIT_TAKE1("SpawnScoreUpLimit", set_spawnscore_uplimit, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidSpawnScoreUpLimit' instead"),
    AP_INIT_TAKE1("TerminationScore", set_termination_score, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidTerminationScore' instead"),
    AP_INIT_TAKE1("TimeScore", set_time_score, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidTimeScore' instead"),
    AP_INIT_TAKE1("ZombieScanInterval", set_zombie_scan_interval, NULL,
                  RSRC_CONF,
                  "Deprecated - Use 'FcgidZombieScanInterval' instead"),
    {NULL}
};

static int fcgid_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp)
{
    apr_status_t rv;

    APR_OPTIONAL_HOOK(ap, status_hook, fcgid_status_hook, NULL, NULL,
                      APR_HOOK_MIDDLE);

    rv = procmgr_pre_config(pconf, plog, ptemp);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = proctable_pre_config(pconf, plog, ptemp);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return OK;
}

static void register_hooks(apr_pool_t * p)
{
    ap_hook_pre_config(fcgid_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(fcgid_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(fcgid_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(mod_fcgid_authenticator, NULL, NULL,
                          APR_HOOK_MIDDLE);
    ap_hook_auth_checker(mod_fcgid_authorizer, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_access_checker(mod_fcgid_check_access, NULL, NULL,
                           APR_HOOK_MIDDLE);

    /* Insert fcgid output filter */
    fcgid_filter_handle =
        ap_register_output_filter("FCGID_OUT",
                                  fcgid_filter,
                                  NULL, AP_FTYPE_RESOURCE - 10);
}

module AP_MODULE_DECLARE_DATA fcgid_module = {
    STANDARD20_MODULE_STUFF,
    create_fcgid_dir_config,    /* create per-directory config structure */
    merge_fcgid_dir_config,     /* merge per-directory config structures */
    create_fcgid_server_config, /* create per-server config structure */
    merge_fcgid_server_config,  /* merge per-server config structures */
    fcgid_cmds,                 /* command apr_table_t */
    register_hooks              /* register hooks */
};
