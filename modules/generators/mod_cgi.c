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
 * http_script: keeps all script-related ramblings together.
 *
 * Compliant to CGI/1.1 spec
 *
 * Adapted by rst from original NCSA code by Rob McCool
 *
 * This modules uses a httpd core function (ap_add_common_vars) to add some new env vars, 
 * like REDIRECT_URL and REDIRECT_QUERY_STRING for custom error responses and DOCUMENT_ROOT.
 * It also adds SERVER_ADMIN - useful for scripts to know who to mail when they fail.
 * 
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */
#include "apr_optional.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_poll.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "mod_core.h"
#include "mod_cgi.h"

#if APR_HAVE_STRUCT_RLIMIT
#if defined (RLIMIT_CPU) || defined (RLIMIT_NPROC) || defined (RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
#define AP_CGI_USE_RLIMIT
#endif
#endif

module AP_MODULE_DECLARE_DATA cgi_module;

static APR_OPTIONAL_FN_TYPE(ap_cgi_build_command) *cgi_build_command;

/* Read and discard the data in the brigade produced by a CGI script */
static void discard_script_output(apr_bucket_brigade *bb);

/* KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

static int is_scriptaliased(request_rec *r)
{
    const char *t = apr_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}

/* Configuration stuff */

#define DEFAULT_LOGBYTES 10385760
#define DEFAULT_BUFBYTES 1024

typedef struct {
    const char *logname;
    long        logbytes;
    apr_size_t  bufbytes;
} cgi_server_conf;

typedef struct {
    apr_interval_time_t timeout;
} cgi_dirconf;

#if APR_FILES_AS_SOCKETS
#define WANT_CGI_BUCKET
#endif
#include "cgi_common.h"

static void *create_cgi_config(apr_pool_t *p, server_rec *s)
{
    cgi_server_conf *c =
    (cgi_server_conf *) apr_pcalloc(p, sizeof(cgi_server_conf));

    c->logname = NULL;
    c->logbytes = DEFAULT_LOGBYTES;
    c->bufbytes = DEFAULT_BUFBYTES;

    return c;
}

static void *merge_cgi_config(apr_pool_t *p, void *basev, void *overridesv)
{
    cgi_server_conf *base = (cgi_server_conf *) basev,
                    *overrides = (cgi_server_conf *) overridesv;

    return overrides->logname ? overrides : base;
}

static void *create_cgi_dirconf(apr_pool_t *p, char *dummy)
{
    cgi_dirconf *c = (cgi_dirconf *) apr_pcalloc(p, sizeof(cgi_dirconf));
    return c;
}

static const char *set_scriptlog(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    cgi_server_conf *conf = ap_get_module_config(s->module_config,
                                                 &cgi_module);

    conf->logname = ap_server_root_relative(cmd->pool, arg);

    if (!conf->logname) {
        return apr_pstrcat(cmd->pool, "Invalid ScriptLog path ",
                           arg, NULL);
    }

    return NULL;
}

static const char *set_scriptlog_length(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    server_rec *s = cmd->server;
    cgi_server_conf *conf = ap_get_module_config(s->module_config,
                                                 &cgi_module);

    conf->logbytes = atol(arg);
    return NULL;
}

static const char *set_scriptlog_buffer(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    server_rec *s = cmd->server;
    cgi_server_conf *conf = ap_get_module_config(s->module_config,
                                                 &cgi_module);

    conf->bufbytes = atoi(arg);
    return NULL;
}

static const char *set_script_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    cgi_dirconf *dc = dummy;

    if (ap_timeout_parameter_parse(arg, &dc->timeout, "s") != APR_SUCCESS) {
        return "CGIScriptTimeout has wrong format";
    }

    return NULL;
}

static const command_rec cgi_cmds[] =
{
AP_INIT_TAKE1("ScriptLog", set_scriptlog, NULL, RSRC_CONF,
     "the name of a log for script debugging info"),
AP_INIT_TAKE1("ScriptLogLength", set_scriptlog_length, NULL, RSRC_CONF,
     "the maximum length (in bytes) of the script debug log"),
AP_INIT_TAKE1("ScriptLogBuffer", set_scriptlog_buffer, NULL, RSRC_CONF,
     "the maximum size (in bytes) to record of a POST request"),
AP_INIT_TAKE1("CGIScriptTimeout", set_script_timeout, NULL, RSRC_CONF | ACCESS_CONF,
     "The amount of time to wait between successful reads from "
     "the CGI script, in seconds."),
    {NULL}
};

static int log_script(request_rec *r, cgi_server_conf * conf, int ret,
                      char *dbuf, const char *sbuf, apr_bucket_brigade *bb,
                      apr_file_t *script_err)
{
    const apr_array_header_t *hdrs_arr = apr_table_elts(r->headers_in);
    const apr_table_entry_t *hdrs = (const apr_table_entry_t *) hdrs_arr->elts;
    char argsbuffer[HUGE_STRING_LEN];
    apr_file_t *f = NULL;
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;
    int first;
    int i;
    apr_finfo_t finfo;
    char time_str[APR_CTIME_LEN];

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!conf->logname ||
        ((apr_stat(&finfo, conf->logname,
                   APR_FINFO_SIZE, r->pool) == APR_SUCCESS) &&
         (finfo.size > conf->logbytes)) ||
        (apr_file_open(&f, conf->logname,
                       APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT,
                       r->pool) != APR_SUCCESS)) {
        /* Soak up script output */
        discard_script_output(bb);
        log_script_err(r, script_err);
        return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri,
                    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin" */
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename);

    apr_file_puts("%request\n", f);
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key)
            continue;
        apr_file_printf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }
    if ((r->method_number == M_POST || r->method_number == M_PUT) &&
        *dbuf) {
        apr_file_printf(f, "\n%s\n", dbuf);
    }

    apr_file_puts("%response\n", f);
    hdrs_arr = apr_table_elts(r->err_headers_out);
    hdrs = (const apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key)
            continue;
        apr_file_printf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }

    if (sbuf && *sbuf)
        apr_file_printf(f, "%s\n", sbuf);

    first = 1;
    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS || (len == 0)) {
            break;
        }
        if (first) {
            apr_file_puts("%stdout\n", f);
            first = 0;
        }
        apr_file_write(f, buf, &len);
        apr_file_puts("\n", f);
    }

    if (apr_file_gets(argsbuffer, HUGE_STRING_LEN, script_err) == APR_SUCCESS) {
        apr_file_puts("%stderr\n", f);
        apr_file_puts(argsbuffer, f);
        while (apr_file_gets(argsbuffer, HUGE_STRING_LEN,
                             script_err) == APR_SUCCESS) {
            apr_file_puts(argsbuffer, f);
        }
        apr_file_puts("\n", f);
    }

    apr_brigade_destroy(bb);
    apr_file_close(script_err);

    apr_file_close(f);
    return ret;
}


/* This is the special environment used for running the "exec cmd="
 *   variety of SSI directives.
 */
static void add_ssi_vars(request_rec *r)
{
    apr_table_t *e = r->subprocess_env;

    if (r->path_info && r->path_info[0] != '\0') {
        request_rec *pa_req;

        apr_table_setn(e, "PATH_INFO", ap_escape_shell_cmd(r->pool,
                                                           r->path_info));

        pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info),
                                       r, NULL);
        if (pa_req->filename) {
            apr_table_setn(e, "PATH_TRANSLATED",
                           apr_pstrcat(r->pool, pa_req->filename,
                                       pa_req->path_info, NULL));
        }
        ap_destroy_sub_req(pa_req);
    }

    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        apr_table_setn(e, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        apr_table_setn(e, "QUERY_STRING_UNESCAPED",
                       ap_escape_shell_cmd(r->pool, arg_copy));
    }
}

static void cgi_child_errfn(apr_pool_t *pool, apr_status_t err,
                            const char *description)
{
    apr_file_t *stderr_log;

    apr_file_open_stderr(&stderr_log, pool);
    /* Escape the logged string because it may be something that
     * came in over the network.
     */
    apr_file_printf(stderr_log,
                    "(%d)%pm: %s\n",
                    err,
                    &err,
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
                    ap_escape_logitem(pool,
#endif
                    description
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
                    )
#endif
                    );
}

static apr_status_t run_cgi_child(apr_file_t **script_out,
                                  apr_file_t **script_in,
                                  apr_file_t **script_err,
                                  const char *command,
                                  const char * const argv[],
                                  request_rec *r,
                                  apr_pool_t *p,
                                  cgi_exec_info_t *e_info)
{
    const char * const *env;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;
    apr_status_t rc = APR_SUCCESS;

#ifdef AP_CGI_USE_RLIMIT
    core_dir_config *conf = ap_get_core_module_config(r->per_dir_config);
#endif

#ifdef DEBUG_CGI
#ifdef OS2
    /* Under OS/2 need to use device con. */
    FILE *dbg = fopen("con", "w");
#else
    FILE *dbg = fopen("/dev/tty", "w");
#endif
    int i;
#endif

    RAISE_SIGSTOP(CGI_CHILD);
#ifdef DEBUG_CGI
    fprintf(dbg, "Attempting to exec %s as CGI child (argv0 = %s)\n",
            r->filename, argv[0]);
#endif

    env = (const char * const *)ap_create_environment(p, r->subprocess_env);

#ifdef DEBUG_CGI
    fprintf(dbg, "Environment: \n");
    for (i = 0; env[i]; ++i)
        fprintf(dbg, "'%s'\n", env[i]);
    fclose(dbg);
#endif

    /* Transmute ourselves into the script.
     * NB only ISINDEX scripts get decoded arguments.
     */
    if (((rc = apr_procattr_create(&procattr, p)) != APR_SUCCESS) ||
        ((rc = apr_procattr_io_set(procattr,
                                   e_info->in_pipe,
                                   e_info->out_pipe,
                                   e_info->err_pipe)) != APR_SUCCESS) ||
        ((rc = apr_procattr_dir_set(procattr,
                        ap_make_dirstr_parent(r->pool,
                                              r->filename))) != APR_SUCCESS) ||
#if defined(RLIMIT_CPU) && defined(AP_CGI_USE_RLIMIT)
        ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_CPU,
                                      conf->limit_cpu)) != APR_SUCCESS) ||
#endif
#if defined(AP_CGI_USE_RLIMIT) && (defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS))
        ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_MEM,
                                      conf->limit_mem)) != APR_SUCCESS) ||
#endif
#if defined(RLIMIT_NPROC) && defined(AP_CGI_USE_RLIMIT)
        ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_NPROC,
                                      conf->limit_nproc)) != APR_SUCCESS) ||
#endif
        ((rc = apr_procattr_cmdtype_set(procattr,
                                        e_info->cmd_type)) != APR_SUCCESS) ||

        ((rc = apr_procattr_detach_set(procattr,
                                        e_info->detached)) != APR_SUCCESS) ||
        ((rc = apr_procattr_addrspace_set(procattr,
                                        e_info->addrspace)) != APR_SUCCESS) ||
        ((rc = apr_procattr_child_errfn_set(procattr, cgi_child_errfn)) != APR_SUCCESS)) {
        /* Something bad happened, tell the world. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01216)
                      "couldn't set child process attributes: %s", r->filename);
    }
    else {
        procnew = apr_pcalloc(p, sizeof(*procnew));
        rc = ap_os_create_privileged_process(r, procnew, command, argv, env,
                                             procattr, p);

        if (rc != APR_SUCCESS) {
            /* Bad things happened. Everyone should have cleaned up. */
            /* Intentional no APLOGNO */
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, rc, r,
                          "couldn't create child process: %d: %s", rc,
                          apr_filepath_name_get(r->filename));
        }
        else {
            cgi_dirconf *dc = ap_get_module_config(r->per_dir_config, &cgi_module);
            apr_interval_time_t timeout = dc->timeout > 0 ? dc->timeout : r->server->timeout;

            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);

            *script_in = procnew->out;
            if (!*script_in)
                return APR_EBADF;
            apr_file_pipe_timeout_set(*script_in, timeout);

            if (e_info->prog_type == RUN_AS_CGI) {
                *script_out = procnew->in;
                if (!*script_out)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_out, timeout);

                *script_err = procnew->err;
                if (!*script_err)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_err, timeout);
            }
        }
    }
    return (rc);
}


static apr_status_t default_build_command(const char **cmd, const char ***argv,
                                          request_rec *r, apr_pool_t *p,
                                          cgi_exec_info_t *e_info)
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
    }
    else {
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
        numwords = APACHE_ARG_MAX - 1;    /* Truncate args to prevent overrun */
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

static int cgi_handler(request_rec *r)
{
    int nph;
    apr_size_t dbufsize;
    const char *argv0;
    const char *command;
    const char **argv;
    char *dbuf = NULL;
    apr_file_t *script_out = NULL, *script_in = NULL, *script_err = NULL;
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
    apr_bucket *b;
    int is_included;
    apr_pool_t *p;
    cgi_server_conf *conf;
    apr_status_t rv;
    cgi_exec_info_t e_info;
    cgi_dirconf *dc = ap_get_module_config(r->per_dir_config, &cgi_module);
    apr_interval_time_t timeout = dc->timeout > 0 ? dc->timeout : r->server->timeout;

    if (strcmp(r->handler, CGI_MAGIC_TYPE) && strcmp(r->handler, "cgi-script")) {
        return DECLINED;
    }

    is_included = !strcmp(r->protocol, "INCLUDED");

    p = r->main ? r->main->pool : r->pool;

    argv0 = apr_filepath_name_get(r->filename);
    nph = !(strncmp(argv0, "nph-", 4));
    conf = ap_get_module_config(r->server->module_config, &cgi_module);

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r))
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(02809),
                               "Options ExecCGI is off in this directory");
    if (nph && is_included)
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(02810),
                               "attempt to include NPH CGI script");

    if (r->finfo.filetype == APR_NOFILE)
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, APLOGNO(02811),
                               "script not found or unable to stat");
    if (r->finfo.filetype == APR_DIR)
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(02812),
                               "attempt to invoke directory as script");

    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info)
    {
        /* default to accept */
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, APLOGNO(02813),
                               "AcceptPathInfo off disallows user's path");
    }
/*
    if (!ap_suexec_enabled) {
        if (!ap_can_exec(&r->finfo))
            return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(03194)
                                   "file permissions deny server execution");
    }

*/
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    e_info.process_cgi = 1;
    e_info.cmd_type    = APR_PROGRAM;
    e_info.detached    = 0;
    e_info.in_pipe     = APR_CHILD_BLOCK;
    e_info.out_pipe    = APR_CHILD_BLOCK;
    e_info.err_pipe    = APR_CHILD_BLOCK;
    e_info.prog_type   = RUN_AS_CGI;
    e_info.bb          = NULL;
    e_info.ctx         = NULL;
    e_info.next        = NULL;
    e_info.addrspace   = 0;

    /* build the command line */
    if ((rv = cgi_build_command(&command, &argv, r, p, &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01222)
                      "don't know how to spawn child process: %s",
                      r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* run the script in its own process */
    if ((rv = run_cgi_child(&script_out, &script_in, &script_err,
                            command, argv, r, p, &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01223)
                      "couldn't spawn child process: %s", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Buffer for logging script stdout. */
    if (conf->logname) {
        dbufsize = conf->bufbytes;
        dbuf = apr_palloc(r->pool, dbufsize + 1);
    }
    else {
        dbufsize = 0;
        dbuf = NULL;
    }

    /* Read the request body. */
    rv = cgi_handle_request(r, script_out, bb, dbuf, dbufsize);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01225)
                      "Error reading request entity data");
        return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
    }

    /* Is this flush really needed? */
    apr_file_flush(script_out);
    apr_file_close(script_out);

    AP_DEBUG_ASSERT(script_in != NULL);

#if APR_FILES_AS_SOCKETS
    b = cgi_bucket_create(r, dc->timeout, script_in, script_err, c->bucket_alloc);
    if (b == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;
#else
    b = apr_bucket_pipe_create(script_in, c->bucket_alloc);
#endif
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return cgi_handle_response(r, nph, bb, timeout, conf, dbuf, script_err);
}

/*============================================================================
 *============================================================================
 * This is the beginning of the cgi filter code moved from mod_include. This
 *   is the code required to handle the "exec" SSI directive.
 *============================================================================
 *============================================================================*/
static apr_status_t include_cgi(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb, char *s)
{
    request_rec *r = f->r;
    request_rec *rr = ap_sub_req_lookup_uri(s, r, f->next);
    int rr_status;

    if (rr->status != HTTP_OK) {
        ap_destroy_sub_req(rr);
        return APR_EGENERAL;
    }

    /* No hardwired path info or query allowed */
    if ((rr->path_info && rr->path_info[0]) || rr->args) {
        ap_destroy_sub_req(rr);
        return APR_EGENERAL;
    }
    if (rr->finfo.filetype != APR_REG) {
        ap_destroy_sub_req(rr);
        return APR_EGENERAL;
    }

    /* Script gets parameters of the *document*, for back compatibility */
    rr->path_info = r->path_info;       /* hard to get right; see mod_cgi.c */
    rr->args = r->args;

    /* Force sub_req to be treated as a CGI request, even if ordinary
     * typing rules would have called it something else.
     */
    ap_set_content_type_ex(rr, CGI_MAGIC_TYPE, 1);

    /* Run it. */
    rr_status = ap_run_sub_req(rr);
    if (ap_is_HTTP_REDIRECT(rr_status)) {
        const char *location = apr_table_get(rr->headers_out, "Location");

        if (location) {
            char *buffer;

            location = ap_escape_html(rr->pool, location);
            buffer = apr_pstrcat(ctx->pool, "<a href=\"", location, "\">",
                                 location, "</a>", NULL);

            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(buffer,
                                    strlen(buffer), ctx->pool,
                                    f->c->bucket_alloc));
        }
    }

    ap_destroy_sub_req(rr);

    return APR_SUCCESS;
}

static apr_status_t include_cmd(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb, const char *command)
{
    cgi_exec_info_t  e_info;
    const char **argv;
    apr_file_t *script_out = NULL, *script_in = NULL, *script_err = NULL;
    apr_status_t rv;
    request_rec *r = f->r;

    add_ssi_vars(r);

    e_info.process_cgi = 0;
    e_info.cmd_type    = APR_SHELLCMD;
    e_info.detached    = 0;
    e_info.in_pipe     = APR_NO_PIPE;
    e_info.out_pipe    = APR_FULL_BLOCK;
    e_info.err_pipe    = APR_NO_PIPE;
    e_info.prog_type   = RUN_AS_SSI;
    e_info.bb          = &bb;
    e_info.ctx         = ctx;
    e_info.next        = f->next;
    e_info.addrspace   = 0;

    if ((rv = cgi_build_command(&command, &argv, r, r->pool,
                                &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01226)
                      "don't know how to spawn cmd child process: %s",
                      r->filename);
        return rv;
    }

    /* run the script in its own process */
    if ((rv = run_cgi_child(&script_out, &script_in, &script_err,
                            command, argv, r, r->pool,
                            &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01227)
                      "couldn't spawn child process: %s", r->filename);
        return rv;
    }

    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pipe_create(script_in,
                            f->c->bucket_alloc));
    ctx->flush_now = 1;

    /* We can't close the pipe here, because we may return before the
     * full CGI has been sent to the network.  That's okay though,
     * because we can rely on the pool to close the pipe for us.
     */
    return APR_SUCCESS;
}

static int cgi_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    /* This is the means by which unusual (non-unix) os's may find alternate
     * means to run a given command (e.g. shebang/registry parsing on Win32)
     */
    cgi_build_command    = APR_RETRIEVE_OPTIONAL_FN(ap_cgi_build_command);
    if (!cgi_build_command) {
        cgi_build_command = default_build_command;
    }
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[] = { "mod_include.c", NULL };
    ap_hook_handler(cgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(cgi_post_config, aszPre, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_optional_fn_retrieve(cgi_optfns_retrieve, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(cgi) =
{
    STANDARD20_MODULE_STUFF,
    create_cgi_dirconf,          /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    create_cgi_config,           /* server config */
    merge_cgi_config,            /* merge server config */
    cgi_cmds,                    /* command apr_table_t */
    register_hooks               /* register hooks */
};
