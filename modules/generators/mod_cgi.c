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
 * Apache adds some new env vars; REDIRECT_URL and REDIRECT_QUERY_STRING for
 * custom error responses, and DOCUMENT_ROOT because we found it useful.
 * It also adds SERVER_ADMIN - useful for scripts to know who to mail when
 * they fail.
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
#include "util_script.h"
#include "ap_mpm.h"
#include "mod_core.h"
#include "mod_cgi.h"

#if APR_HAVE_STRUCT_RLIMIT
#if defined (RLIMIT_CPU) || defined (RLIMIT_NPROC) || defined (RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
#define AP_CGI_USE_RLIMIT
#endif
#endif

module AP_MODULE_DECLARE_DATA cgi_module;

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *cgi_pfn_reg_with_ssi;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *cgi_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *cgi_pfn_ps;
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

static const command_rec cgi_cmds[] =
{
AP_INIT_TAKE1("ScriptLog", set_scriptlog, NULL, RSRC_CONF,
     "the name of a log for script debugging info"),
AP_INIT_TAKE1("ScriptLogLength", set_scriptlog_length, NULL, RSRC_CONF,
     "the maximum length (in bytes) of the script debug log"),
AP_INIT_TAKE1("ScriptLogBuffer", set_scriptlog_buffer, NULL, RSRC_CONF,
     "the maximum size (in bytes) to record of a POST request"),
    {NULL}
};

static int log_scripterror(request_rec *r, cgi_server_conf * conf, int ret,
                           apr_status_t rv, char *error)
{
    apr_file_t *f = NULL;
    apr_finfo_t finfo;
    char time_str[APR_CTIME_LEN];
    int log_flags = rv ? APLOG_ERR : APLOG_ERR;

    ap_log_rerror(APLOG_MARK, log_flags, rv, r,
                  "%s: %s", error, r->filename);

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!conf->logname ||
        ((apr_stat(&finfo, conf->logname,
                   APR_FINFO_SIZE, r->pool) == APR_SUCCESS) &&
         (finfo.size > conf->logbytes)) ||
        (apr_file_open(&f, conf->logname,
                       APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT,
                       r->pool) != APR_SUCCESS)) {
        return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri,
                    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin */
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename);

    apr_file_printf(f, "%%error\n%s\n", error);

    apr_file_close(f);
    return ret;
}

/* Soak up stderr from a script and redirect it to the error log.
 */
static apr_status_t log_script_err(request_rec *r, apr_file_t *script_err)
{
    char argsbuffer[HUGE_STRING_LEN];
    char *newline;
    apr_status_t rv;

    while ((rv = apr_file_gets(argsbuffer, HUGE_STRING_LEN,
                               script_err)) == APR_SUCCESS) {
        newline = strchr(argsbuffer, '\n');
        if (newline) {
            *newline = '\0';
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01215)
                      "%s", argsbuffer);
    }

    return rv;
}

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
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, rc, r,
                          "couldn't create child process: %d: %s", rc,
                          apr_filepath_name_get(r->filename));
        }
        else {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);

            *script_in = procnew->out;
            if (!*script_in)
                return APR_EBADF;
            apr_file_pipe_timeout_set(*script_in, r->server->timeout);

            if (e_info->prog_type == RUN_AS_CGI) {
                *script_out = procnew->in;
                if (!*script_out)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_out, r->server->timeout);

                *script_err = procnew->err;
                if (!*script_err)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_err, r->server->timeout);
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

static void discard_script_output(apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
}

#if APR_FILES_AS_SOCKETS

/* A CGI bucket type is needed to catch any output to stderr from the
 * script; see PR 22030. */
static const apr_bucket_type_t bucket_type_cgi;

struct cgi_bucket_data {
    apr_pollset_t *pollset;
    request_rec *r;
};

/* Create a CGI bucket using pipes from script stdout 'out'
 * and stderr 'err', for request 'r'. */
static apr_bucket *cgi_bucket_create(request_rec *r,
                                     apr_file_t *out, apr_file_t *err,
                                     apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    apr_status_t rv;
    apr_pollfd_t fd;
    struct cgi_bucket_data *data = apr_palloc(r->pool, sizeof *data);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;

    /* Create the pollset */
    rv = apr_pollset_create(&data->pollset, 2, r->pool, 0);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01217)
                     "apr_pollset_create(); check system or user limits");
        return NULL;
    }

    fd.desc_type = APR_POLL_FILE;
    fd.reqevents = APR_POLLIN;
    fd.p = r->pool;
    fd.desc.f = out; /* script's stdout */
    fd.client_data = (void *)1;
    rv = apr_pollset_add(data->pollset, &fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01218)
                     "apr_pollset_add(); check system or user limits");
        return NULL;
    }

    fd.desc.f = err; /* script's stderr */
    fd.client_data = (void *)2;
    rv = apr_pollset_add(data->pollset, &fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01219)
                     "apr_pollset_add(); check system or user limits");
        return NULL;
    }

    data->r = r;
    b->data = data;
    return b;
}

/* Create a duplicate CGI bucket using given bucket data */
static apr_bucket *cgi_bucket_dup(struct cgi_bucket_data *data,
                                  apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    b->data = data;
    return b;
}

/* Handle stdout from CGI child.  Duplicate of logic from the _read
 * method of the real APR pipe bucket implementation. */
static apr_status_t cgi_read_stdout(apr_bucket *a, apr_file_t *out,
                                    const char **str, apr_size_t *len)
{
    char *buf;
    apr_status_t rv;

    *str = NULL;
    *len = APR_BUCKET_BUFF_SIZE;
    buf = apr_bucket_alloc(*len, a->list); /* XXX: check for failure? */

    rv = apr_file_read(out, buf, len);

    if (rv != APR_SUCCESS && rv != APR_EOF) {
        apr_bucket_free(buf);
        return rv;
    }

    if (*len > 0) {
        struct cgi_bucket_data *data = a->data;
        apr_bucket_heap *h;

        /* Change the current bucket to refer to what we read */
        a = apr_bucket_heap_make(a, buf, *len, apr_bucket_free);
        h = a->data;
        h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */
        *str = buf;
        APR_BUCKET_INSERT_AFTER(a, cgi_bucket_dup(data, a->list));
    }
    else {
        apr_bucket_free(buf);
        a = apr_bucket_immortal_make(a, "", 0);
        *str = a->data;
    }
    return rv;
}

/* Read method of CGI bucket: polls on stderr and stdout of the child,
 * sending any stderr output immediately away to the error log. */
static apr_status_t cgi_bucket_read(apr_bucket *b, const char **str,
                                    apr_size_t *len, apr_read_type_e block)
{
    struct cgi_bucket_data *data = b->data;
    apr_interval_time_t timeout;
    apr_status_t rv;
    int gotdata = 0;

    timeout = block == APR_NONBLOCK_READ ? 0 : data->r->server->timeout;

    do {
        const apr_pollfd_t *results;
        apr_int32_t num;

        rv = apr_pollset_poll(data->pollset, timeout, &num, &results);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            if (timeout) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, data->r, APLOGNO(01220)
                              "Timeout waiting for output from CGI script %s",
                              data->r->filename);
                return rv;
            }
            else {
                return APR_EAGAIN;
            }
        }
        else if (APR_STATUS_IS_EINTR(rv)) {
            continue;
        }
        else if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, data->r, APLOGNO(01221)
                          "poll failed waiting for CGI child");
            return rv;
        }

        for (; num; num--, results++) {
            if (results[0].client_data == (void *)1) {
                /* stdout */
                rv = cgi_read_stdout(b, results[0].desc.f, str, len);
                if (APR_STATUS_IS_EOF(rv)) {
                    rv = APR_SUCCESS;
                }
                gotdata = 1;
            } else {
                /* stderr */
                apr_status_t rv2 = log_script_err(data->r, results[0].desc.f);
                if (APR_STATUS_IS_EOF(rv2)) {
                    apr_pollset_remove(data->pollset, &results[0]);
                }
            }
        }

    } while (!gotdata);

    return rv;
}

static const apr_bucket_type_t bucket_type_cgi = {
    "CGI", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    cgi_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};

#endif

static int cgi_handler(request_rec *r)
{
    int nph;
    apr_size_t dbpos = 0;
    const char *argv0;
    const char *command;
    const char **argv;
    char *dbuf = NULL;
    apr_file_t *script_out = NULL, *script_in = NULL, *script_err = NULL;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    int is_included;
    int seen_eos, child_stopped_reading;
    apr_pool_t *p;
    cgi_server_conf *conf;
    apr_status_t rv;
    cgi_exec_info_t e_info;
    conn_rec *c;

    if (strcmp(r->handler, CGI_MAGIC_TYPE) && strcmp(r->handler, "cgi-script")) {
        return DECLINED;
    }

    c = r->connection;

    is_included = !strcmp(r->protocol, "INCLUDED");

    p = r->main ? r->main->pool : r->pool;

    argv0 = apr_filepath_name_get(r->filename);
    nph = !(strncmp(argv0, "nph-", 4));
    conf = ap_get_module_config(r->server->module_config, &cgi_module);

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r))
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0,
                               "Options ExecCGI is off in this directory");
    if (nph && is_included)
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0,
                               "attempt to include NPH CGI script");

    if (r->finfo.filetype == APR_NOFILE)
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0,
                               "script not found or unable to stat");
    if (r->finfo.filetype == APR_DIR)
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0,
                               "attempt to invoke directory as script");

    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info)
    {
        /* default to accept */
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0,
                               "AcceptPathInfo off disallows user's path");
    }
/*
    if (!ap_suexec_enabled) {
        if (!ap_can_exec(&r->finfo))
            return log_scripterror(r, conf, HTTP_FORBIDDEN, 0,
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

    /* Transfer any put/post args, CERN style...
     * Note that we already ignore SIGPIPE in the core server.
     */
    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    seen_eos = 0;
    child_stopped_reading = 0;
    if (conf->logname) {
        dbuf = apr_palloc(r->pool, conf->bufbytes + 1);
        dbpos = 0;
    }
    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01224)
                              "Timeout during reading request entity data");
                return HTTP_REQUEST_TIME_OUT;
            }
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01225)
                          "Error reading request entity data");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */
            if (APR_BUCKET_IS_FLUSH(bucket)) {
                continue;
            }

            /* If the child stopped, we still must read to EOS. */
            if (child_stopped_reading) {
                continue;
            }

            /* read */
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

            if (conf->logname && dbpos < conf->bufbytes) {
                int cursize;

                if ((dbpos + len) > conf->bufbytes) {
                    cursize = conf->bufbytes - dbpos;
                }
                else {
                    cursize = len;
                }
                memcpy(dbuf + dbpos, data, cursize);
                dbpos += cursize;
            }

            /* Keep writing data to the child until done or too much time
             * elapses with no progress or an error occurs.
             */
            rv = apr_file_write_full(script_out, data, len, NULL);

            if (rv != APR_SUCCESS) {
                /* silly script stopped reading, soak up remaining message */
                child_stopped_reading = 1;
            }
        }
        apr_brigade_cleanup(bb);
    }
    while (!seen_eos);

    if (conf->logname) {
        dbuf[dbpos] = '\0';
    }
    /* Is this flush really needed? */
    apr_file_flush(script_out);
    apr_file_close(script_out);

    AP_DEBUG_ASSERT(script_in != NULL);

    apr_brigade_cleanup(bb);

#if APR_FILES_AS_SOCKETS
    apr_file_pipe_timeout_set(script_in, 0);
    apr_file_pipe_timeout_set(script_err, 0);

    b = cgi_bucket_create(r, script_in, script_err, c->bucket_alloc);
    if (b == NULL)
        return HTTP_INTERNAL_SERVER_ERROR;
#else
    b = apr_bucket_pipe_create(script_in, c->bucket_alloc);
#endif
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* Handle script return... */
    if (!nph) {
        const char *location;
        char sbuf[MAX_STRING_LEN];
        int ret;

        if ((ret = ap_scan_script_header_err_brigade_ex(r, bb, sbuf,
                                                        APLOG_MODULE_INDEX)))
        {
            ret = log_script(r, conf, ret, dbuf, sbuf, bb, script_err);

            /*
             * ret could be HTTP_NOT_MODIFIED in the case that the CGI script
             * does not set an explicit status and ap_meets_conditions, which
             * is called by ap_scan_script_header_err_brigade, detects that
             * the conditions of the requests are met and the response is
             * not modified.
             * In this case set r->status and return OK in order to prevent
             * running through the error processing stack as this would
             * break with mod_cache, if the conditions had been set by
             * mod_cache itself to validate a stale entity.
             * BTW: We circumvent the error processing stack anyway if the
             * CGI script set an explicit status code (whatever it is) and
             * the only possible values for ret here are:
             *
             * HTTP_NOT_MODIFIED          (set by ap_meets_conditions)
             * HTTP_PRECONDITION_FAILED   (set by ap_meets_conditions)
             * HTTP_INTERNAL_SERVER_ERROR (if something went wrong during the
             * processing of the response of the CGI script, e.g broken headers
             * or a crashed CGI process).
             */
            if (ret == HTTP_NOT_MODIFIED) {
                r->status = ret;
                return OK;
            }

            return ret;
        }

        location = apr_table_get(r->headers_out, "Location");

        if (location && r->status == 200) {
            /* For a redirect whether internal or not, discard any
             * remaining stdout from the script, and log any remaining
             * stderr output, as normal. */
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            apr_file_pipe_timeout_set(script_err, r->server->timeout);
            log_script_err(r, script_err);
        }

        if (location && location[0] == '/' && r->status == 200) {
            /* This redirect needs to be a GET no matter what the original
             * method was.
             */
            r->method = "GET";
            r->method_number = M_GET;

            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            apr_table_unset(r->headers_in, "Content-Length");

            ap_internal_redirect_handler(location, r);
            return OK;
        }
        else if (location && r->status == 200) {
            /* XXX: Note that if a script wants to produce its own Redirect
             * body, it now has to explicitly *say* "Status: 302"
             */
            return HTTP_MOVED_TEMPORARILY;
        }

        rv = ap_pass_brigade(r->output_filters, bb);
    }
    else /* nph */ {
        struct ap_filter_t *cur;

        /* get rid of all filters up through protocol...  since we
         * haven't parsed off the headers, there is no way they can
         * work
         */

        cur = r->proto_output_filters;
        while (cur && cur->frec->ftype < AP_FTYPE_CONNECTION) {
            cur = cur->next;
        }
        r->output_filters = r->proto_output_filters = cur;

        rv = ap_pass_brigade(r->output_filters, bb);
    }

    /* don't soak up script output if errors occurred writing it
     * out...  otherwise, we prolong the life of the script when the
     * connection drops or we stopped sending output for some other
     * reason */
    if (rv == APR_SUCCESS && !r->connection->aborted) {
        apr_file_pipe_timeout_set(script_err, r->server->timeout);
        log_script_err(r, script_err);
    }

    apr_file_close(script_err);

    return OK;                      /* NOT r->status, even if it has changed. */
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
    ap_set_content_type(rr, CGI_MAGIC_TYPE);

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

static apr_status_t handle_exec(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb)
{
    char *tag = NULL;
    char *tag_val = NULL;
    request_rec *r = f->r;
    char *file = r->filename;
    char parsed_string[MAX_STRING_LEN];

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK,
                      (ctx->flags & SSI_FLAG_PRINTING)
                          ? APLOG_ERR : APLOG_WARNING,
                      0, r, "missing argument for exec element in %s",
                      r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    if (ctx->flags & SSI_FLAG_NO_EXEC) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01228) "exec used but not allowed "
                      "in %s", r->filename);
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    while (1) {
        cgi_pfn_gtv(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        if (!strcmp(tag, "cmd")) {
            apr_status_t rv;

            cgi_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string),
                       SSI_EXPAND_LEAVE_NAME);

            rv = include_cmd(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01229) "execution failure "
                              "for parameter \"%s\" to tag exec in file %s",
                              tag, r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else if (!strcmp(tag, "cgi")) {
            apr_status_t rv;

            cgi_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string),
                       SSI_EXPAND_DROP_NAME);

            rv = include_cgi(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01230) "invalid CGI ref "
                              "\"%s\" in %s", tag_val, file);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01231) "unknown parameter "
                          "\"%s\" to tag exec in %s", tag, file);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            break;
        }
    }

    return APR_SUCCESS;
}


/*============================================================================
 *============================================================================
 * This is the end of the cgi filter code moved from mod_include.
 *============================================================================
 *============================================================================*/


static int cgi_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    cgi_pfn_reg_with_ssi = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
    cgi_pfn_gtv          = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    cgi_pfn_ps           = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);

    if ((cgi_pfn_reg_with_ssi) && (cgi_pfn_gtv) && (cgi_pfn_ps)) {
        /* Required by mod_include filter. This is how mod_cgi registers
         *   with mod_include to provide processing of the exec directive.
         */
        cgi_pfn_reg_with_ssi("exec", handle_exec);
    }

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
}

AP_DECLARE_MODULE(cgi) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                        /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    create_cgi_config,           /* server config */
    merge_cgi_config,            /* merge server config */
    cgi_cmds,                    /* command apr_table_t */
    register_hooks               /* register hooks */
};
