/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/* 
 * http_script: keeps all script-related ramblings together. 
 * 
 * Compliant to cgi/1.1 spec 
 * 
 * Adapted by rst from original NCSA code by Rob McCool 
 * 
 * Apache adds some new env vars; REDIRECT_URL and REDIRECT_QUERY_STRING for 
 * custom error responses, and DOCUMENT_ROOT because we found it useful. 
 * It also adds SERVER_ADMIN - useful for scripts to know who to mail when 
 * they fail. 
 */ 

#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "apr_file_io.h"
#include "apr_portable.h"
#include "apr_buckets.h"
#include "apr_optional.h"
#include "apr_signal.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define CORE_PRIVATE 

#include "util_filter.h"
#include "httpd.h" 
#include "http_config.h" 
#include "http_request.h" 
#include "http_core.h" 
#include "http_protocol.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "util_script.h" 
#include "ap_mpm.h"
#include "unixd.h"
#include "mod_suexec.h"
#include "../filters/mod_include.h"

#include "mod_core.h"


/* ### should be tossed in favor of APR */
#include <sys/stat.h>
#include <sys/un.h> /* for sockaddr_un */


module AP_MODULE_DECLARE_DATA cgid_module; 

static int cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server); 
static int handle_exec(include_ctx_t *ctx, apr_bucket_brigade **bb, request_rec *r,
                       ap_filter_t *f, apr_bucket *head_ptr, apr_bucket **inserted_head);

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *cgid_pfn_reg_with_ssi;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *cgid_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *cgid_pfn_ps;

static apr_pool_t *pcgi; 
static int total_modules = 0;
static pid_t daemon_pid;
static int daemon_should_exit = 0;

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
#define DEFAULT_SOCKET  DEFAULT_REL_RUNTIMEDIR "/cgisock"

#define CGI_REQ    1
#define SSI_REQ    2
#define GETPID_REQ 3 /* get the pid of script created for prior request */

#define ERRFN_USERDATA_KEY         "CGIDCHILDERRFN"

/* DEFAULT_CGID_LISTENBACKLOG controls the max depth on the unix socket's
 * pending connection queue.  If a bunch of cgi requests arrive at about
 * the same time, connections from httpd threads/processes will back up
 * in the queue while the cgid process slowly forks off a child to process
 * each connection on the unix socket.  If the queue is too short, the
 * httpd process will get ECONNREFUSED when trying to connect.
 */
#ifndef DEFAULT_CGID_LISTENBACKLOG
#define DEFAULT_CGID_LISTENBACKLOG 100
#endif

/* DEFAULT_CONNECT_ATTEMPTS controls how many times we'll try to connect
 * to the cgi daemon from the thread/process handling the cgi request.
 * Generally we want to retry when we get ECONNREFUSED since it is
 * probably because the listen queue is full.  We need to try harder so
 * the client doesn't see it as a 503 error.
 *
 * Set this to 0 to continually retry until the connect works or Apache
 * terminates.
 */
#ifndef DEFAULT_CONNECT_ATTEMPTS
#define DEFAULT_CONNECT_ATTEMPTS  15
#endif

typedef struct { 
    const char *sockname;
    const char *logname; 
    long logbytes; 
    int bufbytes; 
} cgid_server_conf; 

typedef struct {
    int req_type; /* request type (CGI_REQ, SSI_REQ, etc.) */
    unsigned long conn_id; /* connection id; daemon uses this as a hash value
                            * to find the script pid when it is time for that
                            * process to be cleaned up
                            */
    int core_module_index;
    int have_suexec;
    int suexec_module_index;
    suexec_config_t suexec_cfg;
    int env_count;
    apr_size_t filename_len;
    apr_size_t argv0_len;
    apr_size_t uri_len;
    apr_size_t args_len;
    apr_size_t mod_userdir_user_len;
    int loglevel; /* to stuff in server_rec */
} cgid_req_t;

/* This routine is called to create the argument list to be passed
 * to the CGI script.  When suexec is enabled, the suexec path, user, and
 * group are the first three arguments to be passed; if not, all three
 * must be NULL.  The query info is split into separate arguments, where
 * "+" is the separator between keyword arguments.
 *
 * Do not process the args if they containing an '=' assignment.
 */
static char **create_argv(apr_pool_t *p, char *path, char *user, char *group,
                          char *av0, const char *args)
{
    int x, numwords;
    char **av;
    char *w;
    int idx = 0;

    if (ap_strchr_c(args, '=')) {
        numwords = 0;
    }
    else {
        /* count the number of keywords */
        
        for (x = 0, numwords = 1; args[x]; x++) {
            if (args[x] == '+') {
                ++numwords;
            }
        }
    }

    if (numwords > APACHE_ARG_MAX - 5) {
        numwords = APACHE_ARG_MAX - 5;  /* Truncate args to prevent overrun */
    }
    av = (char **) apr_pcalloc(p, (numwords + 5) * sizeof(char *));

    if (path) {
        av[idx++] = path;
    }
    if (user) {
        av[idx++] = user;
    }
    if (group) {
        av[idx++] = group;
    }

    av[idx++] = apr_pstrdup(p, av0);

    for (x = 1; x <= numwords; x++) {
        w = ap_getword_nulls(p, &args, '+');
        if (strcmp(w, "")) {
            ap_unescape_url(w);
            av[idx++] = ap_escape_shell_cmd(p, w);
        }
    }
    av[idx] = NULL;
    return av;
}

#if APR_HAS_OTHER_CHILD
static void cgid_maint(int reason, void *data, apr_wait_t status)
{
    pid_t *sd = data;

    switch (reason) {
        case APR_OC_REASON_DEATH:
        case APR_OC_REASON_RESTART:
            /* don't do anything; server is stopping or restarting */
            apr_proc_other_child_unregister(data);
            break;
        case APR_OC_REASON_LOST:
            /* it would be better to restart just the cgid child
             * process but for now we'll gracefully restart the entire 
             * server by sending AP_SIG_GRACEFUL to ourself, the httpd 
             * parent process
             */
            kill(getpid(), AP_SIG_GRACEFUL);
            break;
        case APR_OC_REASON_UNREGISTER:
            /* we get here when pcgi is cleaned up; pcgi gets cleaned
             * up when pconf gets cleaned up
             */
            kill(*sd, SIGHUP); /* send signal to daemon telling it to die */
            break;
    }
}
#endif

/* deal with incomplete reads and signals
 * assume you really have to read buf_size bytes
 */
static apr_status_t sock_read(int fd, void *vbuf, size_t buf_size)
{
    char *buf = vbuf;
    int rc;
    size_t bytes_read = 0;

    do {
        do {
            rc = read(fd, buf + bytes_read, buf_size - bytes_read);
        } while (rc < 0 && errno == EINTR);
        switch(rc) {
        case -1:
            return errno;
        case 0: /* unexpected */
            return ECONNRESET;
        default:
            bytes_read += rc;
        }
    } while (bytes_read < buf_size);

    return APR_SUCCESS;
}

/* deal with signals
 */
static apr_status_t sock_write(int fd, const void *buf, size_t buf_size)
{
    int rc;

    do {
        rc = write(fd, buf, buf_size);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }

    return APR_SUCCESS;
}

static apr_status_t get_req(int fd, request_rec *r, char **argv0, char ***env, 
                            cgid_req_t *req)
{ 
    int i; 
    char *user;
    char **environ; 
    core_dir_config *temp_core; 
    void **dconf;
    apr_status_t stat;

    r->server = apr_pcalloc(r->pool, sizeof(server_rec)); 

    /* read the request header */
    stat = sock_read(fd, req, sizeof(*req));
    if (stat != APR_SUCCESS) {
        return stat;
    }
    r->server->loglevel = req->loglevel;
    if (req->req_type == GETPID_REQ) {
        /* no more data sent for this request */
        return APR_SUCCESS;
    }

    /* handle module indexes and such */
    dconf = (void **) apr_pcalloc(r->pool, sizeof(void *) * (total_modules + DYNAMIC_MODULE_LIMIT));

    temp_core = (core_dir_config *)apr_palloc(r->pool, sizeof(core_module)); 
    dconf[req->core_module_index] = (void *)temp_core;

    if (req->have_suexec) {
        dconf[req->suexec_module_index] = &req->suexec_cfg;
    }

    r->per_dir_config = (ap_conf_vector_t *)dconf; 

    /* Read the filename, argv0, uri, and args */
    r->filename = apr_pcalloc(r->pool, req->filename_len + 1);
    *argv0 = apr_pcalloc(r->pool, req->argv0_len + 1);
    r->uri = apr_pcalloc(r->pool, req->uri_len + 1);
    if ((stat = sock_read(fd, r->filename, req->filename_len)) != APR_SUCCESS ||
        (stat = sock_read(fd, *argv0, req->argv0_len)) != APR_SUCCESS ||
        (stat = sock_read(fd, r->uri, req->uri_len)) != APR_SUCCESS) {
        return stat;
    }

    r->args = apr_pcalloc(r->pool, req->args_len + 1); /* empty string if no args */
    if (req->args_len) {
        if ((stat = sock_read(fd, r->args, req->args_len)) != APR_SUCCESS) {
            return stat;
        }
    }

    /* read the environment variables */
    environ = apr_pcalloc(r->pool, (req->env_count + 2) *sizeof(char *));
    for (i = 0; i < req->env_count; i++) {
        apr_size_t curlen;

        if ((stat = sock_read(fd, &curlen, sizeof(curlen))) != APR_SUCCESS) {
            return stat;
        }
        environ[i] = apr_pcalloc(r->pool, curlen + 1);
        if ((stat = sock_read(fd, environ[i], curlen)) != APR_SUCCESS) {
            return stat;
        }
    }
    *env = environ;

    /* basic notes table to avoid segfaults */
    r->notes = apr_table_make(r->pool, 1);

    /* mod_userdir requires the mod_userdir_user note */
    if (req->mod_userdir_user_len) {
        user = apr_pcalloc(r->pool, req->mod_userdir_user_len + 1); /* last byte is '\0' */
        stat = sock_read(fd, user, req->mod_userdir_user_len);
        if (stat != APR_SUCCESS) {
            return stat;
        }
        apr_table_set(r->notes, "mod_userdir_user", (const char *)user);
    }

#if 0
#ifdef RLIMIT_CPU 
    sock_read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_cpu = (struct rlimit *)apr_palloc (sizeof(struct rlimit)); 
        sock_read(fd, temp_core->limit_cpu, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_cpu = NULL; 
    } 
#endif 

#if defined (RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS) 
    sock_read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_mem = (struct rlimit *)apr_palloc(r->pool, sizeof(struct rlimit)); 
        sock_read(fd, temp_core->limit_mem, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_mem = NULL; 
    } 
#endif 

#ifdef RLIMIT_NPROC 
    sock_read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_nproc = (struct rlimit *)apr_palloc(r->pool, sizeof(struct rlimit)); 
        sock_read(fd, temp_core->limit_nproc, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_nproc = NULL; 
    } 
#endif 
#endif

    return APR_SUCCESS;
} 

static apr_status_t send_req(int fd, request_rec *r, char *argv0, char **env, 
                             int req_type) 
{ 
    int i;
    const char *user;
    module *suexec_mod = ap_find_linked_module("mod_suexec.c");
    cgid_req_t req = {0};
    suexec_config_t *suexec_cfg;
    apr_status_t stat;

    req.req_type = req_type;
    req.conn_id = r->connection->id;
    req.core_module_index = core_module.module_index;
    if (suexec_mod) {
        req.have_suexec = 1;
        req.suexec_module_index = suexec_mod->module_index;
        suexec_cfg = ap_get_module_config(r->per_dir_config,
                                          suexec_mod);
        req.suexec_cfg = *suexec_cfg;
    }
    for (req.env_count = 0; env[req.env_count]; req.env_count++) {
        continue; 
    }
    req.filename_len = strlen(r->filename);
    req.argv0_len = strlen(argv0);
    req.uri_len = strlen(r->uri);
    req.args_len = r->args ? strlen(r->args) : 0;
    user = (const char *)apr_table_get(r->notes, "mod_userdir_user");
    if (user != NULL) {
        req.mod_userdir_user_len = strlen(user);
    }
    req.loglevel = r->server->loglevel;

    /* Write the request header */
    if ((stat = sock_write(fd, &req, sizeof(req))) != APR_SUCCESS) {
        return stat;
    }

    /* Write filename, argv0, uri, and args */
    if ((stat = sock_write(fd, r->filename, req.filename_len)) != APR_SUCCESS ||
        (stat = sock_write(fd, argv0, req.argv0_len)) != APR_SUCCESS ||
        (stat = sock_write(fd, r->uri, req.uri_len)) != APR_SUCCESS) {
        return stat;
    }
    if (req.args_len) {
        if ((stat = sock_write(fd, r->args, req.args_len)) != APR_SUCCESS) {
            return stat;
        }
    }

    /* write the environment variables */
    for (i = 0; i < req.env_count; i++) {
        apr_size_t curlen = strlen(env[i]);

        if ((stat = sock_write(fd, &curlen, sizeof(curlen))) != APR_SUCCESS) {
            return stat;
        }
            
        if ((stat = sock_write(fd, env[i], curlen)) != APR_SUCCESS) {
            return stat;
        }
    }

    /* send a minimal notes table */
    if (user) {
        if ((stat = sock_write(fd, user, req.mod_userdir_user_len)) != APR_SUCCESS) {
            return stat;
        }
    }

#if 0
#ifdef RLIMIT_CPU 
    if (conf->limit_cpu) { 
        len = 1; 
        stat = sock_write(fd, &len, sizeof(int)); 
        stat = sock_write(fd, conf->limit_cpu, sizeof(struct rlimit)); 
    } 
    else { 
        len = 0; 
        stat = sock_write(fd, &len, sizeof(int)); 
    } 
#endif 

#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS) 
    if (conf->limit_mem) { 
        len = 1; 
        stat = sock_write(fd, &len, sizeof(int)); 
        stat = sock_write(fd, conf->limit_mem, sizeof(struct rlimit)); 
    } 
    else { 
        len = 0; 
        stat = sock_write(fd, &len, sizeof(int)); 
    } 
#endif 
  
#ifdef RLIMIT_NPROC 
    if (conf->limit_nproc) { 
        len = 1; 
        stat = sock_write(fd, &len, sizeof(int)); 
        stat = sock_write(fd, conf->limit_nproc, sizeof(struct rlimit)); 
    } 
    else { 
        len = 0; 
        stat = sock_write(fd, &len, sizeof(int)); 
    } 
#endif
#endif
    return APR_SUCCESS;
} 

static void daemon_signal_handler(int sig)
{
    if (sig == SIGHUP) {
        ++daemon_should_exit;
    }
}

static void cgid_child_errfn(apr_pool_t *pool, apr_status_t err,
                             const char *description)
{
    request_rec *r;
    void *vr;

    apr_pool_userdata_get(&vr, ERRFN_USERDATA_KEY, pool);
    r = vr;

    /* sure we got r, but don't call ap_log_rerror() because we don't
     * have r->headers_in and possibly other storage referenced by
     * ap_log_rerror()
     */
    ap_log_error(APLOG_MARK, APLOG_ERR, err, r->server, "%s", description);
}

static int cgid_server(void *data) 
{ 
    struct sockaddr_un unix_addr;
    int sd, sd2, rc;
    mode_t omask;
    apr_socklen_t len;
    apr_pool_t *ptrans;
    server_rec *main_server = data;
    cgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                   &cgid_module); 
    apr_hash_t *script_hash = apr_hash_make(pcgi);

    apr_pool_create(&ptrans, pcgi); 

    apr_signal(SIGCHLD, SIG_IGN); 
    apr_signal(SIGHUP, daemon_signal_handler);

    if (unlink(sconf->sockname) < 0 && errno != ENOENT) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
                     "Couldn't unlink unix domain socket %s",
                     sconf->sockname);
        /* just a warning; don't bail out */
    }

    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                     "Couldn't create unix domain socket");
        return errno;
    } 

    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, sconf->sockname);

    omask = umask(0077); /* so that only Apache can use socket */
    rc = bind(sd, (struct sockaddr *)&unix_addr, sizeof(unix_addr));
    umask(omask); /* can't fail, so can't clobber errno */
    if (rc < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                     "Couldn't bind unix domain socket %s",
                     sconf->sockname); 
        return errno;
    } 

    if (listen(sd, DEFAULT_CGID_LISTENBACKLOG) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                     "Couldn't listen on unix domain socket"); 
        return errno;
    } 

    if (!geteuid()) {
        if (chown(sconf->sockname, unixd_config.user_id, -1) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                         "Couldn't change owner of unix domain socket %s",
                         sconf->sockname); 
            return errno;
        }
    }
    
    unixd_setup_child(); /* if running as root, switch to configured user/group */

    while (!daemon_should_exit) {
        int errfileno = STDERR_FILENO;
        char *argv0; 
        char **env; 
        const char * const *argv; 
        apr_int32_t in_pipe;
        apr_int32_t out_pipe;
        apr_int32_t err_pipe;
        apr_cmdtype_e cmd_type;
        request_rec *r;
        apr_procattr_t *procattr = NULL;
        apr_proc_t *procnew = NULL;
        apr_file_t *inout;
        cgid_req_t cgid_req;
        apr_status_t stat;

        apr_pool_clear(ptrans);

        len = sizeof(unix_addr);
        sd2 = accept(sd, (struct sockaddr *)&unix_addr, &len);
        if (sd2 < 0) {
            if (errno != EINTR) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, 
                             (server_rec *)data,
                             "Error accepting on cgid socket");
            }
            continue;
        }
       
        r = apr_pcalloc(ptrans, sizeof(request_rec)); 
        procnew = apr_pcalloc(ptrans, sizeof(*procnew));
        r->pool = ptrans; 
        stat = get_req(sd2, r, &argv0, &env, &cgid_req); 
        if (stat != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, stat,
                         main_server,
                         "Error reading request on cgid socket");
            close(sd2);
            continue;
        }

        if (cgid_req.req_type == GETPID_REQ) {
            pid_t pid;

            pid = (pid_t)apr_hash_get(script_hash, &cgid_req.conn_id, sizeof(cgid_req.conn_id));
            if (write(sd2, &pid, sizeof(pid)) != sizeof(pid)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                             main_server,
                             "Error writing pid %" APR_PID_T_FMT " to handler", pid);
            }
            close(sd2);
            continue;
        }

        apr_os_file_put(&r->server->error_log, &errfileno, 0, r->pool);
        apr_os_file_put(&inout, &sd2, 0, r->pool);

        if (cgid_req.req_type == SSI_REQ) {
            in_pipe  = APR_NO_PIPE;
            out_pipe = APR_FULL_BLOCK;
            err_pipe = APR_NO_PIPE;
            cmd_type = APR_SHELLCMD;
        }
        else {
            in_pipe  = APR_CHILD_BLOCK;
            out_pipe = APR_CHILD_BLOCK;
            err_pipe = APR_CHILD_BLOCK;
            cmd_type = APR_PROGRAM;
        }

        if (((rc = apr_procattr_create(&procattr, ptrans)) != APR_SUCCESS) ||
            ((cgid_req.req_type == CGI_REQ) && 
             (((rc = apr_procattr_io_set(procattr,
                                        in_pipe,
                                        out_pipe,
                                        err_pipe)) != APR_SUCCESS) ||
              /* XXX apr_procattr_child_*_set() is creating an unnecessary 
               * pipe between this process and the child being created...
               * It is cleaned up with the temporary pool for this request.
               */
              ((rc = apr_procattr_child_err_set(procattr, r->server->error_log, NULL)) != APR_SUCCESS) ||
              ((rc = apr_procattr_child_in_set(procattr, inout, NULL)) != APR_SUCCESS))) ||
            ((rc = apr_procattr_child_out_set(procattr, inout, NULL)) != APR_SUCCESS) ||
            ((rc = apr_procattr_dir_set(procattr,
                                  ap_make_dirstr_parent(r->pool, r->filename))) != APR_SUCCESS) ||
            ((rc = apr_procattr_cmdtype_set(procattr, cmd_type)) != APR_SUCCESS) ||
            ((rc = apr_procattr_child_errfn_set(procattr, cgid_child_errfn)) != APR_SUCCESS)) {
            /* Something bad happened, tell the world. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "couldn't set child process attributes: %s", r->filename);
        }
        else {
            apr_pool_userdata_set(r, ERRFN_USERDATA_KEY, apr_pool_cleanup_null, ptrans);

            argv = (const char * const *)create_argv(r->pool, NULL, NULL, NULL, argv0, r->args);

           /* We want to close sd2 for the new CGI process too.
            * If it is left open it'll make ap_pass_brigade() block
            * waiting for EOF if CGI forked something running long.
            * close(sd2) here should be okay, as CGI channel
            * is already dup()ed by apr_procattr_child_{in,out}_set()
            * above.
            */
            close(sd2);

            rc = ap_os_create_privileged_process(r, procnew, argv0, argv, 
                                                 (const char * const *)env, 
                                                 procattr, ptrans);

            if (rc != APR_SUCCESS) {
                /* Bad things happened. Everyone should have cleaned up. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, rc, r,
                              "couldn't create child process: %d: %s", rc, 
                              apr_filename_of_pathname(r->filename));
            }
            else {
                apr_hash_set(script_hash, &cgid_req.conn_id, sizeof(cgid_req.conn_id), 
                             (void *)procnew->pid);
            }
        }
    } 
    return -1; 
} 

static int cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, 
                      server_rec *main_server) 
{ 
    apr_proc_t *procnew;
    void *data;
    int first_time = 0;
    const char *userdata_key = "cgid_init";
    module **m;

    apr_pool_userdata_get(&data, userdata_key, main_server->process->pool);
    if (!data) {
        first_time = 1;
        apr_pool_userdata_set((const void *)1, userdata_key,
                         apr_pool_cleanup_null, main_server->process->pool);
    }

    if (!first_time) {
        total_modules = 0;
        for (m = ap_preloaded_modules; *m != NULL; m++)
            total_modules++;

        daemon_should_exit = 0; /* clear setting from previous generation */
        if ((daemon_pid = fork()) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                         "mod_cgid: Couldn't spawn cgid daemon process"); 
            return DECLINED;
        }
        else if (daemon_pid == 0) {
            apr_pool_create(&pcgi, p); 
            cgid_server(main_server);
            exit(-1);
        } 
        procnew = apr_pcalloc(p, sizeof(*procnew));
        procnew->pid = daemon_pid;
        procnew->err = procnew->in = procnew->out = NULL;
        apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
#if APR_HAS_OTHER_CHILD
        apr_proc_other_child_register(procnew, cgid_maint, &procnew->pid, NULL, p);
#endif

        cgid_pfn_reg_with_ssi = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
        cgid_pfn_gtv          = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
        cgid_pfn_ps           = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);

        if ((cgid_pfn_reg_with_ssi) && (cgid_pfn_gtv) && (cgid_pfn_ps)) {
            /* Required by mod_include filter. This is how mod_cgid registers
             *   with mod_include to provide processing of the exec directive.
             */
            cgid_pfn_reg_with_ssi("exec", handle_exec);
        }
    }
    return OK;
} 

static void *create_cgid_config(apr_pool_t *p, server_rec *s) 
{ 
    cgid_server_conf *c = 
    (cgid_server_conf *) apr_pcalloc(p, sizeof(cgid_server_conf)); 

    c->logname = NULL; 
    c->logbytes = DEFAULT_LOGBYTES; 
    c->bufbytes = DEFAULT_BUFBYTES; 
    c->sockname = ap_server_root_relative(p, DEFAULT_SOCKET); 
    return c; 
} 

static void *merge_cgid_config(apr_pool_t *p, void *basev, void *overridesv) 
{ 
    cgid_server_conf *base = (cgid_server_conf *) basev, *overrides = (cgid_server_conf *) overridesv; 

    return overrides->logname ? overrides : base; 
} 

static const char *set_scriptlog(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = ap_get_module_config(s->module_config,
                                                  &cgid_module); 

    conf->logname = ap_server_root_relative(cmd->pool, arg);

    if (!conf->logname) {
        return apr_pstrcat(cmd->pool, "Invalid ScriptLog path ",
                           arg, NULL);
    }
    return NULL; 
} 

static const char *set_scriptlog_length(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = ap_get_module_config(s->module_config,
                                                  &cgid_module); 

    conf->logbytes = atol(arg); 
    return NULL; 
} 

static const char *set_scriptlog_buffer(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = ap_get_module_config(s->module_config,
                                                  &cgid_module); 

    conf->bufbytes = atoi(arg); 
    return NULL; 
} 

static const char *set_script_socket(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = ap_get_module_config(s->module_config,
                                                  &cgid_module); 

    conf->sockname = ap_server_root_relative(cmd->pool, arg); 

    if (!conf->sockname) {
        return apr_pstrcat(cmd->pool, "Invalid Scriptsock path ",
                           arg, NULL);
    }

    return NULL; 
} 

static const command_rec cgid_cmds[] = 
{ 
    AP_INIT_TAKE1("ScriptLog", set_scriptlog, NULL, RSRC_CONF,
                  "the name of a log for script debugging info"), 
    AP_INIT_TAKE1("ScriptLogLength", set_scriptlog_length, NULL, RSRC_CONF,
                  "the maximum length (in bytes) of the script debug log"), 
    AP_INIT_TAKE1("ScriptLogBuffer", set_scriptlog_buffer, NULL, RSRC_CONF,
                  "the maximum size (in bytes) to record of a POST request"), 
    AP_INIT_TAKE1("Scriptsock", set_script_socket, NULL, RSRC_CONF,
                  "the name of the socket to use for communication with "
                  "the cgi daemon."), 
    {NULL} 
}; 

static int log_scripterror(request_rec *r, cgid_server_conf * conf, int ret, 
                           apr_status_t rv, char *error) 
{ 
    apr_file_t *f = NULL; 
    struct stat finfo; 
    char time_str[APR_CTIME_LEN];
    int log_flags = rv ? APLOG_ERR : APLOG_ERR;

    ap_log_rerror(APLOG_MARK, log_flags, rv, r, 
                "%s: %s", error, r->filename); 

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!conf->logname || 
        ((stat(conf->logname, &finfo) == 0) 
         && (finfo.st_size > conf->logbytes)) || 
         (apr_file_open(&f, conf->logname,
                  APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)) { 
        return ret; 
    } 

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgid-bin/printenv HTTP/1.0" */ 
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri, 
            r->args ? "?" : "", r->args ? r->args : "", r->protocol); 
    /* "%% 500 /usr/local/apache/cgid-bin */ 
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename); 

    apr_file_printf(f, "%%error\n%s\n", error); 

    apr_file_close(f); 
    return ret; 
} 

static int log_script(request_rec *r, cgid_server_conf * conf, int ret, 
                      char *dbuf, const char *sbuf, apr_bucket_brigade *bb,
                      apr_file_t *script_err) 
{ 
    const apr_array_header_t *hdrs_arr = apr_table_elts(r->headers_in); 
    const apr_table_entry_t *hdrs = (apr_table_entry_t *) hdrs_arr->elts; 
    char argsbuffer[HUGE_STRING_LEN]; 
    apr_file_t *f = NULL; 
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;
    int first;
    int i; 
    struct stat finfo; 
    char time_str[APR_CTIME_LEN];

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!conf->logname || 
        ((stat(conf->logname, &finfo) == 0) 
         && (finfo.st_size > conf->logbytes)) || 
         (apr_file_open(&f, conf->logname, 
                  APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)) { 
        /* Soak up script output */ 
        discard_script_output(bb);
        if (script_err) {
            while (apr_file_gets(argsbuffer, HUGE_STRING_LEN, 
                                 script_err) == APR_SUCCESS) 
                continue; 
        }
        return ret; 
    } 

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgid-bin/printenv HTTP/1.0" */ 
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri, 
            r->args ? "?" : "", r->args ? r->args : "", r->protocol); 
    /* "%% 500 /usr/local/apache/cgid-bin" */ 
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename); 

    apr_file_puts("%request\n", f); 
    for (i = 0; i < hdrs_arr->nelts; ++i) { 
        if (!hdrs[i].key) 
            continue; 
        apr_file_printf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val); 
    } 
    if ((r->method_number == M_POST || r->method_number == M_PUT) 
        && *dbuf) { 
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
    APR_BRIGADE_FOREACH(e, bb) {
        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (!APR_STATUS_IS_SUCCESS(rv) || (len == 0)) {
            break;
        }
        if (first) {
            apr_file_puts("%stdout\n", f);
            first = 0;
        }
        apr_file_write(f, buf, &len);
        apr_file_puts("\n", f);
    }

    if (script_err) {
        if (apr_file_gets(argsbuffer, HUGE_STRING_LEN, 
                          script_err) == APR_SUCCESS) { 
            apr_file_puts("%stderr\n", f); 
            apr_file_puts(argsbuffer, f); 
            while (apr_file_gets(argsbuffer, HUGE_STRING_LEN, 
                                 script_err) == APR_SUCCESS) 
                apr_file_puts(argsbuffer, f); 
            apr_file_puts("\n", f); 
        } 
    }

    if (script_err) {
        apr_file_close(script_err); 
    }

    apr_file_close(f); 
    return ret; 
} 

static apr_status_t close_unix_socket(void *thefd)
{
    int fd = (int)thefd;
    
    return close(fd);
}

static int connect_to_daemon(int *sdptr, request_rec *r,
                             cgid_server_conf *conf)
{
    struct sockaddr_un unix_addr;
    int sd;
    int connect_tries;
    apr_interval_time_t sliding_timer;

    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, conf->sockname);

    connect_tries = 0;
    sliding_timer = 100000; /* 100 milliseconds */
    while (1) {
        ++connect_tries;
        if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return log_scripterror(r, conf, HTTP_INTERNAL_SERVER_ERROR, errno, 
                                   "unable to create socket to cgi daemon");
        }
        if (connect(sd, (struct sockaddr *)&unix_addr, sizeof(unix_addr)) < 0) {
            if (errno == ECONNREFUSED && connect_tries < DEFAULT_CONNECT_ATTEMPTS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, errno, r,
                              "connect #%d to cgi daemon failed, sleeping before retry",
                              connect_tries);
                close(sd);
                apr_sleep(sliding_timer);
                if (sliding_timer < apr_time_from_sec(2)) {
                    sliding_timer *= 2;
                }
            }
            else {
                close(sd);
                return log_scripterror(r, conf, HTTP_SERVICE_UNAVAILABLE, errno, 
                                       "unable to connect to cgi daemon after multiple tries");
            }
        }
        else {
            apr_pool_cleanup_register(r->pool, (void *)sd, close_unix_socket,
                                      apr_pool_cleanup_null);
            break; /* we got connected! */
        }
        /* gotta try again, but make sure the cgid daemon is still around */
        if (kill(daemon_pid, 0) != 0) {
            return log_scripterror(r, conf, HTTP_SERVICE_UNAVAILABLE, errno,
                                   "cgid daemon is gone; is Apache terminating?");
        }
    }
    *sdptr = sd;
    return OK;
}

static void discard_script_output(apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;
    APR_BRIGADE_FOREACH(e, bb) {
        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (!APR_STATUS_IS_SUCCESS(rv)) {
            break;
        }
    }
}

/**************************************************************** 
 * 
 * Actual cgid handling... 
 */ 

struct cleanup_script_info {
    request_rec *r;
    unsigned long conn_id;
    cgid_server_conf *conf;
};

static apr_status_t dead_yet(pid_t pid, apr_interval_time_t max_wait)
{
    apr_interval_time_t interval = 10000; /* 10 ms */
    apr_interval_time_t total = 0;

    do {
        if (kill(pid, 0) < 0) {
            return APR_SUCCESS;
        }
        apr_sleep(interval);
        total = total + interval;
        if (interval < 500000) {
            interval *= 2;
        }
    } while (total < max_wait);
    return APR_EGENERAL;
}

static apr_status_t cleanup_nonchild_process(request_rec *r, pid_t pid)
{
    kill(pid, SIGTERM); /* in case it isn't dead yet */
    if (dead_yet(pid, apr_time_from_sec(3)) == APR_SUCCESS) {
        return APR_SUCCESS;
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "CGI process %" APR_PID_T_FMT " didn't exit, sending SIGKILL",
                  pid);
    kill(pid, SIGKILL);
    if (dead_yet(pid, apr_time_from_sec(3)) == APR_SUCCESS) {
        return APR_SUCCESS;
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "CGI process %" APR_PID_T_FMT " didn't exit, sending SIGKILL again",
                  pid);
    kill(pid, SIGKILL);

    return APR_EGENERAL;
}

static apr_status_t cleanup_script(void *vptr)
{
    struct cleanup_script_info *info = vptr;
    int sd;
    int rc;
    cgid_req_t req = {0};
    pid_t pid;
    apr_status_t stat;

    rc = connect_to_daemon(&sd, info->r, info->conf);
    if (rc != OK) {
        return APR_EGENERAL;
    }

    req.req_type = GETPID_REQ;
    req.conn_id = info->r->connection->id;

    stat = sock_write(sd, &req, sizeof(req));
    if (stat != APR_SUCCESS) {
        close(sd);
        return stat;
    }

    /* wait for pid of script */
    stat = sock_read(sd, &pid, sizeof(pid));
    if (stat != APR_SUCCESS) {
        close(sd);
        return stat;
    }
    close(sd);

    if (pid == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, info->r,
                      "daemon couldn't find CGI process for connection %lu",
                      info->conn_id);
        return APR_EGENERAL;
    }
    return cleanup_nonchild_process(info->r, pid);
}

static int cgid_handler(request_rec *r) 
{ 
    conn_rec *c = r->connection;
    int retval, nph, dbpos = 0; 
    char *argv0, *dbuf = NULL; 
    apr_bucket_brigade *bb;
    apr_bucket *b;
    cgid_server_conf *conf;
    int is_included;
    int seen_eos, child_stopped_reading;
    int sd;
    char **env; 
    apr_file_t *tempsock;
    struct cleanup_script_info *info;
    apr_status_t rv;

    if (strcmp(r->handler,CGI_MAGIC_TYPE) && strcmp(r->handler,"cgi-script"))
        return DECLINED;

    if (r->method_number == M_OPTIONS) { 
        /* 99 out of 100 cgid scripts, this is all they support */ 
        r->allowed |= (AP_METHOD_BIT << M_GET); 
        r->allowed |= (AP_METHOD_BIT << M_POST); 
        return DECLINED; 
    } 

    conf = ap_get_module_config(r->server->module_config, &cgid_module); 
    is_included = !strcmp(r->protocol, "INCLUDED"); 

    if ((argv0 = strrchr(r->filename, '/')) != NULL)
        argv0++;
    else
        argv0 = r->filename;
 
    nph = !(strncmp(argv0, "nph-", 4)); 

    if ((argv0 = strrchr(r->filename, '/')) != NULL) 
        argv0++; 
    else 
        argv0 = r->filename; 

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r)) 
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, 
                               "Options ExecCGI is off in this directory"); 
    if (nph && is_included) 
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, 
                               "attempt to include NPH CGI script"); 

#if defined(OS2) || defined(WIN32)
#error mod_cgid does not work on this platform.  If you teach it to, look 
#error at mod_cgi.c for required code in this path.
#else 
    if (r->finfo.filetype == 0) 
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, 
                               "script not found or unable to stat"); 
#endif 
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
    env = ap_create_environment(r->pool, r->subprocess_env); 

    if ((retval = connect_to_daemon(&sd, r, conf)) != OK) {
        return retval;
    }

    rv = send_req(sd, r, argv0, env, CGI_REQ); 
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "write to cgi daemon process");
    }

    info = apr_palloc(r->pool, sizeof(struct cleanup_script_info));
    info->r = r;
    info->conn_id = r->connection->id;
    info->conf = conf;
    apr_pool_cleanup_register(r->pool, info,
                              cleanup_script,
                              apr_pool_cleanup_null);
    /* We are putting the socket discriptor into an apr_file_t so that we can
     * use a pipe bucket to send the data to the client.
     * Note that this does not register a cleanup for the socket.  We did
     * that explicitly right after we created the socket.
     */
    apr_os_pipe_put(&tempsock, &sd, r->pool);

    if ((argv0 = strrchr(r->filename, '/')) != NULL) 
        argv0++; 
    else 
        argv0 = r->filename; 

    /* Transfer any put/post args, CERN style... 
     * Note that we already ignore SIGPIPE in the core server. 
     */ 
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
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
            return rv;
        }
 
        APR_BRIGADE_FOREACH(bucket, bb) {
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
            rv = apr_file_write_full(tempsock, data, len, NULL);

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

    /* we're done writing, or maybe we didn't write at all;
     * force EOF on child's stdin so that the cgi detects end (or
     * absence) of data
     */
    shutdown(sd, 1);

    /* Handle script return... */ 
    if (!nph) { 
        const char *location; 
        char sbuf[MAX_STRING_LEN]; 
        int ret; 

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        b = apr_bucket_pipe_create(tempsock, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        if ((ret = ap_scan_script_header_err_brigade(r, bb, sbuf))) { 
            return log_script(r, conf, ret, dbuf, sbuf, bb, NULL); 
        } 

        location = apr_table_get(r->headers_out, "Location"); 

        if (location && location[0] == '/' && r->status == 200) { 

            /* Soak up all the script output */
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            /* This redirect needs to be a GET no matter what the original 
             * method was. 
             */ 
            r->method = apr_pstrdup(r->pool, "GET"); 
            r->method_number = M_GET; 

            /* We already read the message body (if any), so don't allow 
             * the redirected request to think it has one. We can ignore 
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR. 
             */ 
            apr_table_unset(r->headers_in, "Content-Length"); 

            ap_internal_redirect_handler(location, r); 
            return OK; 
        } 
        else if (location && r->status == 200) { 
            /* XX Note that if a script wants to produce its own Redirect 
             * body, it now has to explicitly *say* "Status: 302" 
             */ 
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            return HTTP_MOVED_TEMPORARILY; 
        } 

        /* Passing our socket down the filter chain in a pipe bucket
         * gives up the responsibility of closing the socket, so
         * get rid of the cleanup.
         */
        apr_pool_cleanup_kill(r->pool, (void *)sd, close_unix_socket);

        ap_pass_brigade(r->output_filters, bb);
    } 

    if (nph) {
        struct ap_filter_t *cur;
        
        /* Passing our socket down the filter chain in a pipe bucket
         * gives up the responsibility of closing the socket, so
         * get rid of the cleanup.
         */
        apr_pool_cleanup_kill(r->pool, (void *)sd, close_unix_socket);

        /* get rid of all filters up through protocol...  since we
         * haven't parsed off the headers, there is no way they can
         * work
         */

        cur = r->proto_output_filters;
        while (cur && cur->frec->ftype < AP_FTYPE_CONNECTION) {
            cur = cur->next;
        }
        r->output_filters = r->proto_output_filters = cur;

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        b = apr_bucket_pipe_create(tempsock, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        ap_pass_brigade(r->output_filters, bb);
    } 

    return OK; /* NOT r->status, even if it has changed. */ 
} 




/*============================================================================
 *============================================================================
 * This is the beginning of the cgi filter code moved from mod_include. This
 *   is the code required to handle the "exec" SSI directive.
 *============================================================================
 *============================================================================*/
static int include_cgi(char *s, request_rec *r, ap_filter_t *next,
                       apr_bucket *head_ptr, apr_bucket **inserted_head)
{
    request_rec *rr = ap_sub_req_lookup_uri(s, r, next);
    int rr_status;
    apr_bucket  *tmp_buck, *tmp2_buck;

    if (rr->status != HTTP_OK) {
        ap_destroy_sub_req(rr);
        return -1;
    }

    /* No hardwired path info or query allowed */

    if ((rr->path_info && rr->path_info[0]) || rr->args) {
        ap_destroy_sub_req(rr);
        return -1;
    }
    if (rr->finfo.filetype != APR_REG) {
        ap_destroy_sub_req(rr);
        return -1;
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
        apr_size_t len_loc;
        const char *location = apr_table_get(rr->headers_out, "Location");
        conn_rec *c = r->connection;

        location = ap_escape_html(rr->pool, location);
        len_loc = strlen(location);

        /* XXX: if most of this stuff is going to get copied anyway,
         * it'd be more efficient to pstrcat it into a single pool buffer
         * and a single pool bucket */

        tmp_buck = apr_bucket_immortal_create("<A HREF=\"",
                                              sizeof("<A HREF=\"") - 1,
                                              c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
        tmp2_buck = apr_bucket_heap_create(location, len_loc, NULL,
                                           c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
        tmp2_buck = apr_bucket_immortal_create("\">", sizeof("\">") - 1,
                                               c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
        tmp2_buck = apr_bucket_heap_create(location, len_loc, NULL,
                                           c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
        tmp2_buck = apr_bucket_immortal_create("</A>", sizeof("</A>") - 1,
                                               c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);

        if (*inserted_head == NULL) {
            *inserted_head = tmp_buck;
        }
    }

    ap_destroy_sub_req(rr);

    return 0;
}


/* This is the special environment used for running the "exec cmd="
 *   variety of SSI directives.
 */
static void add_ssi_vars(request_rec *r, ap_filter_t *next)
{
    apr_table_t *e = r->subprocess_env;

    if (r->path_info && r->path_info[0] != '\0') {
        request_rec *pa_req;

        apr_table_setn(e, "PATH_INFO", ap_escape_shell_cmd(r->pool, r->path_info));

        pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info), r, NULL);
        if (pa_req->filename) {
            apr_table_setn(e, "PATH_TRANSLATED",
                           apr_pstrcat(r->pool, pa_req->filename, pa_req->path_info, NULL));
        }
        ap_destroy_sub_req(pa_req);
    }

    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        apr_table_setn(e, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        apr_table_setn(e, "QUERY_STRING_UNESCAPED", ap_escape_shell_cmd(r->pool, arg_copy));
    }
}

static int include_cmd(include_ctx_t *ctx, apr_bucket_brigade **bb, char *command,
                       request_rec *r, ap_filter_t *f)
{
    char **env; 
    const char *location; 
    int sd;
    apr_status_t rc = APR_SUCCESS; 
    int retval;
    apr_bucket_brigade *bcgi;
    apr_bucket *b;
    apr_file_t *tempsock = NULL;
    cgid_server_conf *conf = ap_get_module_config(r->server->module_config,
                                                  &cgid_module); 
    struct cleanup_script_info *info;

    add_ssi_vars(r, f->next);
    env = ap_create_environment(r->pool, r->subprocess_env);

    if ((retval = connect_to_daemon(&sd, r, conf)) != OK) {
        return retval;
    }

    SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, rc);
    if (rc != APR_SUCCESS) {
        return rc;
    }

    send_req(sd, r, command, env, SSI_REQ); 

    info = apr_palloc(r->pool, sizeof(struct cleanup_script_info));
    info->r = r;
    info->conn_id = r->connection->id;
    info->conf = conf;
    /* for this type of request, the script is invoked through an
     * intermediate shell process...  cleanup_script is only able 
     * to knock out the shell process, not the actual script
     */
    apr_pool_cleanup_register(r->pool, info,
                              cleanup_script,
                              apr_pool_cleanup_null);
    /* We are putting the socket discriptor into an apr_file_t so that we can
     * use a pipe bucket to send the data to the client.
     * Note that this does not register a cleanup for the socket.  We did
     * that explicitly right after we created the socket.
     */
    apr_os_pipe_put(&tempsock, &sd, r->pool);

    if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) 
        return retval; 
    
    location = apr_table_get(r->headers_out, "Location"); 

    if (location && location[0] == '/' && r->status == 200) { 
        char argsbuffer[HUGE_STRING_LEN]; 

        /* Soak up all the script output */ 
        while (apr_file_gets(argsbuffer, HUGE_STRING_LEN, 
                             tempsock) == APR_SUCCESS) { 
            continue; 
        } 
        /* This redirect needs to be a GET no matter what the original 
         * method was. 
         */ 
        r->method = apr_pstrdup(r->pool, "GET"); 
        r->method_number = M_GET; 

        /* We already read the message body (if any), so don't allow 
         * the redirected request to think it has one. We can ignore 
         * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR. 
         */ 
        apr_table_unset(r->headers_in, "Content-Length"); 

        ap_internal_redirect_handler(location, r); 
        return OK; 
    } 
    else if (location && r->status == 200) { 
        /* XX Note that if a script wants to produce its own Redirect 
         * body, it now has to explicitly *say* "Status: 302" 
         */ 
        return HTTP_MOVED_TEMPORARILY; 
    } 

    if (!r->header_only) { 
        /* Passing our socket down the filter chain in a pipe bucket
         * gives up the responsibility of closing the socket, so
         * get rid of the cleanup.
         */
        apr_pool_cleanup_kill(r->pool, (void *)sd, close_unix_socket);

        bcgi = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        b    = apr_bucket_pipe_create(tempsock, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bcgi, b);
        ap_pass_brigade(f->next, bcgi);
    } 

    return 0;
}

static int handle_exec(include_ctx_t *ctx, apr_bucket_brigade **bb, request_rec *r,
                       ap_filter_t *f, apr_bucket *head_ptr, apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *file = r->filename;
    apr_bucket  *tmp_buck;
    char parsed_string[MAX_STRING_LEN];

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        if (ctx->flags & FLAG_NO_EXEC) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "exec used but not allowed in %s", r->filename);
            CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
        }
        else {
            while (1) {
                cgid_pfn_gtv(ctx, &tag, &tag_val, 1);
                if (tag_val == NULL) {
                    if (tag == NULL) {
                        return (0);
                    }
                    else {
                        return 1;
                    }
                }
                if (!strcmp(tag, "cmd")) {
                    cgid_pfn_ps(r, ctx, tag_val, parsed_string, sizeof(parsed_string), 1);
                    if (include_cmd(ctx, bb, parsed_string, r, f) == -1) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                    "execution failure for parameter \"%s\" "
                                    "to tag exec in file %s", tag, r->filename);
                        CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                    }
                    /* just in case some stooge changed directories */
                }
                else if (!strcmp(tag, "cgi")) {
                    apr_status_t retval = APR_SUCCESS;

                    cgid_pfn_ps(r, ctx, tag_val, parsed_string, sizeof(parsed_string), 0);
                    SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, retval);
                    if (retval != APR_SUCCESS) {
                        return retval;
                    }

                    if (include_cgi(parsed_string, r, f->next, head_ptr, inserted_head) == -1) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                    "invalid CGI ref \"%s\" in %s", tag_val, file);
                        CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                    }
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "unknown parameter \"%s\" to tag exec in %s", tag, file);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                }
            }
        }
    }
    return 0;
}
/*============================================================================
 *============================================================================
 * This is the end of the cgi filter code moved from mod_include.
 *============================================================================
 *============================================================================*/


static void register_hook(apr_pool_t *p)
{
    static const char * const aszPre[] = { "mod_include.c", NULL };

    ap_hook_post_config(cgid_init, aszPre, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(cgid_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA cgid_module = { 
    STANDARD20_MODULE_STUFF, 
    NULL, /* dir config creater */ 
    NULL, /* dir merger --- default is to override */ 
    create_cgid_config, /* server config */ 
    merge_cgid_config, /* merge server config */ 
    cgid_cmds, /* command table */ 
    register_hook /* register_handlers */ 
}; 

