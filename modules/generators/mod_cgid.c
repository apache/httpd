/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

static void cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server); 
static int handle_exec(include_ctx_t *ctx, apr_bucket_brigade **bb, request_rec *r,
                       ap_filter_t *f, apr_bucket *head_ptr, apr_bucket **inserted_head);

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *cgid_pfn_reg_with_ssi;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *cgid_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *cgid_pfn_ps;

static apr_pool_t *pcgi; 
static int total_modules = 0;

/* KLUDGE --- for back-combatibility, we don't have to check Execcgid 
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
#define DEFAULT_SOCKET "logs/cgisock"

#define CGI_REQ 1
#define SSI_REQ 2

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

typedef struct { 
    const char *sockname;
    const char *logname; 
    long logbytes; 
    int bufbytes; 
} cgid_server_conf; 

/* If a request includes query info in the URL (stuff after "?"), and
 * the query info does not contain "=" (indicative of a FORM submission),
 * then this routine is called to create the argument list to be passed
 * to the CGI script.  When suexec is enabled, the suexec path, user, and
 * group are the first three arguments to be passed; if not, all three
 * must be NULL.  The query info is split into separate arguments, where
 * "+" is the separator between keyword arguments.
 *
 * XXXX: note that the WIN32 code uses one of the suexec strings
 * to pass an interpreter name.  Remember this if changing the way they
 * are handled in create_argv.
 *
 */
static char **create_argv(apr_pool_t *p, char *path, char *user, char *group,
                          char *av0, const char *args)
{
    int x, numwords;
    char **av;
    char *w;
    int idx = 0;

    /* count the number of keywords */

    for (x = 0, numwords = 1; args[x]; x++) {
        if (args[x] == '+') {
            ++numwords;
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
            /* don't do anything; server is stopping or restarting */
            break;
        case APR_OC_REASON_LOST:
            /* it would be better to restart just the cgid child
             * process but for now we'll gracefully restart the entire 
             * server by sending AP_SIG_GRACEFUL to ourself, the httpd 
             * parent process
             */
            kill(getpid(), AP_SIG_GRACEFUL);
            break;
        case APR_OC_REASON_RESTART:
            apr_proc_other_child_unregister(data);
            break;
        case APR_OC_REASON_UNREGISTER:
            /* we get here when pcgi is cleaned up; pcgi gets cleaned
             * up when pconf gets cleaned up
             */
            kill(*sd, SIGHUP);
            break;
    }
}
#endif

static void get_req(int fd, request_rec *r, char **argv0, char ***env, int *req_type) 
{ 
    int i, len, j; 
    unsigned char *data; 
    char **environ; 
    core_dir_config *temp_core; 
    void **dconf; 
    module *suexec_mod = ap_find_linked_module("mod_suexec.c");

    r->server = apr_pcalloc(r->pool, sizeof(server_rec)); 

    read(fd, req_type, sizeof(int));
    read(fd, &j, sizeof(int)); 
    read(fd, &len, sizeof(int)); 
    data = apr_pcalloc(r->pool, len + 1); /* get a cleared byte for final '\0' */
    i = read(fd, data, len); 

    r->filename = ap_getword(r->pool, (const char **)&data, '\n'); 
    *argv0 = ap_getword(r->pool, (const char **)&data, '\n'); 

    r->uri = ap_getword(r->pool, (const char **)&data, '\n'); 
    
    environ = apr_pcalloc(r->pool, (j + 2) *sizeof(char *)); 
    i = 0; 
    for (i = 0; i < j; i++) { 
        environ[i] = ap_getword(r->pool, (const char **)&data, '\n'); 
    } 
    *env = environ; 
    r->args = ap_getword(r->pool, (const char **)&data, '\n'); 
  
    read(fd, &i, sizeof(int)); 
     
    /* add 1, so that if i == 0, we still malloc something. */ 

    dconf = (void **) apr_pcalloc(r->pool, sizeof(void *) * (total_modules + DYNAMIC_MODULE_LIMIT));

    temp_core = (core_dir_config *)apr_palloc(r->pool, sizeof(core_module)); 

    dconf[i] = (void *)temp_core; 

    if (suexec_mod) {
        suexec_config_t *suexec_cfg = apr_pcalloc(r->pool, sizeof(*suexec_cfg));

        read(fd, &i, sizeof(int));
        read(fd, &suexec_cfg->ugid.uid, sizeof(uid_t));
        read(fd, &suexec_cfg->ugid.gid, sizeof(gid_t));
        read(fd, &suexec_cfg->active, sizeof(int));
        dconf[i] = (void *)suexec_cfg;
    }

    r->per_dir_config = (ap_conf_vector_t *)dconf; 
#if 0
#ifdef RLIMIT_CPU 
    read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_cpu = (struct rlimit *)apr_palloc (sizeof(struct rlimit)); 
        read(fd, temp_core->limit_cpu, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_cpu = NULL; 
    } 
#endif 

#if defined (RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS) 
    read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_mem = (struct rlimit *)apr_palloc(r->pool, sizeof(struct rlimit)); 
        read(fd, temp_core->limit_mem, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_mem = NULL; 
    } 
#endif 

#ifdef RLIMIT_NPROC 
    read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_nproc = (struct rlimit *)apr_palloc(r->pool, sizeof(struct rlimit)); 
        read(fd, temp_core->limit_nproc, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_nproc = NULL; 
    } 
#endif 
#endif
    /* For right now, just make the notes table.  At some point we will need
     * to actually fill this out, but for now we just don't want suexec to
     * seg fault.
     */
    r->notes = apr_table_make(r->pool, 1);
} 



static void send_req(int fd, request_rec *r, char *argv0, char **env, int req_type) 
{ 
    int len, r_type = req_type; 
    int i = 0; 
    char *data; 
    module *suexec_mod = ap_find_linked_module("mod_suexec.c");

    data = apr_pstrcat(r->pool, r->filename, "\n", argv0, "\n", r->uri, "\n", 
                     NULL); 

    for (i =0; env[i]; i++) { 
        continue; 
    } 

    /* Write the request type (SSI "exec cmd" or cgi). */
    if (write(fd, &r_type, sizeof(int)) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                     "write to cgi daemon process");
    }

    /* Write the number of entries in the environment. */
    if (write(fd, &i, sizeof(int)) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
        }     

    for (i = 0; env[i]; i++) { 
        data = apr_pstrcat(r->pool, data, env[i], "\n", NULL); 
    } 
    data = apr_pstrcat(r->pool, data, r->args, NULL); 
    len = strlen(data); 
    /* Write the length of the concatenated env string. */
    if (write(fd, &len, sizeof(int)) < 0) { 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
    }
    /* Write the concatted env string. */     
    if (write(fd, data, len) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
    }
    /* Write module_index id value. */     
    if (write(fd, &core_module.module_index, sizeof(int)) < 0) { 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
    }     
    if (suexec_mod) {
        suexec_config_t *suexec_cfg = ap_get_module_config(r->per_dir_config,
                                                           suexec_mod);

        write(fd, &suexec_mod->module_index, sizeof(int));
        write(fd, &suexec_cfg->ugid.uid, sizeof(uid_t));
        write(fd, &suexec_cfg->ugid.gid, sizeof(gid_t));
        write(fd, &suexec_cfg->active, sizeof(int));
    }

#if 0
#ifdef RLIMIT_CPU 
    if (conf->limit_cpu) { 
        len = 1; 
        write(fd, &len, sizeof(int)); 
        write(fd, conf->limit_cpu, sizeof(struct rlimit)); 
    } 
    else { 
        len = 0; 
        write(fd, &len, sizeof(int)); 
    } 
#endif 

#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS) 
    if (conf->limit_mem) { 
        len = 1; 
        write(fd, &len, sizeof(int)); 
        write(fd, conf->limit_mem, sizeof(struct rlimit)); 
    } 
    else { 
        len = 0; 
        write(fd, &len, sizeof(int)); 
    } 
#endif 
  
#ifdef RLIMIT_NPROC 
    if (conf->limit_nproc) { 
        len = 1; 
        write(fd, &len, sizeof(int)); 
        write(fd, conf->limit_nproc, sizeof(struct rlimit)); 
    } 
    else { 
        len = 0; 
        write(fd, &len, sizeof(int)); 
    } 
#endif
#endif 
} 

static int cgid_server(void *data) 
{ 
    struct sockaddr_un unix_addr;
    int sd, sd2, rc, req_type;
    mode_t omask;
    apr_socklen_t len;
    apr_pool_t *ptrans;
    server_rec *main_server = data;
    cgid_server_conf *sconf = ap_get_module_config(main_server->module_config,
                                                   &cgid_module); 

    apr_pool_create(&ptrans, pcgi); 

    apr_signal(SIGCHLD, SIG_IGN); 
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
    while (1) {
        int errfileno = STDERR_FILENO;
        char *argv0; 
        char **env; 
        const char * const *argv; 
        apr_int32_t   in_pipe  = APR_CHILD_BLOCK;
        apr_int32_t   out_pipe = APR_CHILD_BLOCK;
        apr_int32_t   err_pipe = APR_CHILD_BLOCK;
        apr_cmdtype_e cmd_type = APR_PROGRAM;
        request_rec *r; 
        apr_procattr_t *procattr = NULL;
        apr_proc_t *procnew = NULL;
        apr_file_t *inout;

        apr_pool_clear(ptrans);

        len = sizeof(unix_addr);
        sd2 = accept(sd, (struct sockaddr *)&unix_addr, &len);
        if (sd2 < 0) {
            if (errno != EINTR) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, 
                             (server_rec *)data,
                             "Error accepting on cgid socket.");
            }
            continue;
        }
       
        r = apr_pcalloc(ptrans, sizeof(request_rec)); 
        procnew = apr_pcalloc(ptrans, sizeof(*procnew));
        r->pool = ptrans; 
        get_req(sd2, r, &argv0, &env, &req_type); 
        apr_os_file_put(&r->server->error_log, &errfileno, r->pool);
        apr_os_file_put(&inout, &sd2, r->pool);

        if (req_type == SSI_REQ) {
            in_pipe  = APR_NO_PIPE;
            out_pipe = APR_FULL_BLOCK;
            err_pipe = APR_NO_PIPE;
            cmd_type = APR_SHELLCMD;
        }

        if (((rc = apr_procattr_create(&procattr, ptrans)) != APR_SUCCESS) ||
            ((req_type == CGI_REQ) && 
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
            ((rc = apr_procattr_cmdtype_set(procattr, cmd_type)) != APR_SUCCESS)) {
            /* Something bad happened, tell the world. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                      "couldn't set child process attributes: %s", r->filename);
        }
        else {
            argv = (const char * const *)create_argv(r->pool, NULL, NULL, NULL, argv0, r->args);

           /* We want to sd2 close for new CGI process too.
            * If it's remained open it'll make ap_pass_brigade() block
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                        "couldn't create child process: %d: %s", rc, r->filename);
            }
        }
    } 
    return -1; 
} 

static int cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, 
                      server_rec *main_server) 
{ 
    pid_t pid; 
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


        if ((pid = fork()) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                         "Couldn't spawn cgid daemon process"); 
            /* XXX should we return a failure here ? */
        }
        else if (pid == 0) {
            apr_pool_create(&pcgi, p); 
            cgid_server(main_server);
            exit(-1);
        } 
        procnew = apr_pcalloc(p, sizeof(*procnew));
        procnew->pid = pid;
        procnew->err = procnew->in = procnew->out = NULL;
        apr_pool_note_subprocess(p, procnew, kill_after_timeout);
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
    int log_flags = rv ? APLOG_ERR : APLOG_NOERRNO | APLOG_ERR;

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
                  char *dbuf, const char *sbuf, apr_file_t *script_in, apr_file_t *script_err) 
{ 
    const apr_array_header_t *hdrs_arr = apr_table_elts(r->headers_in); 
    const apr_table_entry_t *hdrs = (apr_table_entry_t *) hdrs_arr->elts; 
    char argsbuffer[HUGE_STRING_LEN]; 
    apr_file_t *f = NULL; 
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
        while (apr_file_gets(argsbuffer, HUGE_STRING_LEN, 
                             script_in) == APR_SUCCESS) 
            continue; 
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

    if (apr_file_gets(argsbuffer, HUGE_STRING_LEN, script_in) == APR_SUCCESS) { 
        apr_file_puts("%stdout\n", f); 
        apr_file_puts(argsbuffer, f); 
        while (apr_file_gets(argsbuffer, HUGE_STRING_LEN, 
                             script_in) == APR_SUCCESS) 
            apr_file_puts(argsbuffer, f); 
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

    apr_file_close(script_in); 
    if (script_err) {
        apr_file_close(script_err); 
    }

    apr_file_close(f); 
    return ret; 
} 



/**************************************************************** 
 * 
 * Actual cgid handling... 
 */ 
static int cgid_handler(request_rec *r) 
{ 
    int retval, nph, dbpos = 0; 
    char *argv0, *dbuf = NULL; 
    apr_bucket_brigade *bb;
    apr_bucket *b;
    char argsbuffer[HUGE_STRING_LEN]; 
    cgid_server_conf *conf;
    int is_included;
    int sd;
    char **env; 
    struct sockaddr_un unix_addr;
    apr_file_t *tempsock;
    apr_size_t nbytes;

    if(strcmp(r->handler,CGI_MAGIC_TYPE) && strcmp(r->handler,"cgi-script"))
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

    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return log_scripterror(r, conf, HTTP_INTERNAL_SERVER_ERROR, errno, 
                                   "unable to create socket to cgi daemon");
    } 
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, conf->sockname);

    if (connect(sd, (struct sockaddr *)&unix_addr, sizeof(unix_addr)) < 0) {
            return log_scripterror(r, conf, HTTP_INTERNAL_SERVER_ERROR, errno, 
                                   "unable to connect to cgi daemon");
    } 

    send_req(sd, r, argv0, env, CGI_REQ); 

    /* We are putting the tempsock variable into a file so that we can use
     * a pipe bucket to send the data to the client.
     */
    apr_os_file_put(&tempsock, &sd, r->pool);

    if ((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) 
        return retval; 
     
    if ((argv0 = strrchr(r->filename, '/')) != NULL) 
        argv0++; 
    else 
        argv0 = r->filename; 

    /* Transfer any put/post args, CERN style... 
     * Note that we already ignore SIGPIPE in the core server. 
     */ 

    if (ap_should_client_block(r)) { 
        int dbsize, len_read; 

        if (conf->logname) { 
            dbuf = apr_pcalloc(r->pool, conf->bufbytes + 1); 
            dbpos = 0; 
        } 

        while ((len_read = 
                ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN)) > 0) { 
            if (conf->logname) { 
                if ((dbpos + len_read) > conf->bufbytes) { 
                    dbsize = conf->bufbytes - dbpos; 
                } 
                else { 
                    dbsize = len_read; 
                } 
                memcpy(dbuf + dbpos, argsbuffer, dbsize); 
                dbpos += dbsize; 
            } 
            nbytes = len_read;
            apr_file_write(tempsock, argsbuffer, &nbytes);
            if (nbytes < len_read) { 
                /* silly script stopped reading, soak up remaining message */ 
                while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0) { 
                    /* dump it */ 
                } 
                break; 
            } 
        } 
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

        if ((ret = ap_scan_script_header_err(r, tempsock, sbuf))) { 
            return log_script(r, conf, ret, dbuf, sbuf, tempsock, NULL); 
        } 

        location = apr_table_get(r->headers_out, "Location"); 

        if (location && location[0] == '/' && r->status == 200) { 

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
            bb = apr_brigade_create(r->pool);
            b = apr_bucket_pipe_create(tempsock);
            APR_BRIGADE_INSERT_TAIL(bb, b);
            b = apr_bucket_eos_create();
            APR_BRIGADE_INSERT_TAIL(bb, b);
            ap_pass_brigade(r->output_filters, bb);
        } 
    } 

    if (nph) {
        bb = apr_brigade_create(r->pool);
        b = apr_bucket_pipe_create(tempsock);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        b = apr_bucket_eos_create();
        APR_BRIGADE_INSERT_TAIL(bb, b);
        ap_pass_brigade(r->output_filters, bb);
    } 

    apr_file_close(tempsock);

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

    rr->content_type = CGI_MAGIC_TYPE;

    /* Run it. */

    rr_status = ap_run_sub_req(rr);
    if (ap_is_HTTP_REDIRECT(rr_status)) {
        apr_size_t len_loc;
        const char *location = apr_table_get(rr->headers_out, "Location");

        location = ap_escape_html(rr->pool, location);
        len_loc = strlen(location);

        /* XXX: if most of this stuff is going to get copied anyway,
         * it'd be more efficient to pstrcat it into a single pool buffer
         * and a single pool bucket */

        tmp_buck = apr_bucket_immortal_create("<A HREF=\"", sizeof("<A HREF=\""));
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
        tmp2_buck = apr_bucket_heap_create(location, len_loc, 1);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
        /* XXX: this looks like a bug: should be sizeof - 1 */
        tmp2_buck = apr_bucket_immortal_create("\">", sizeof("\">"));
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
        tmp2_buck = apr_bucket_heap_create(location, len_loc, 1);
        APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
        /* XXX: this looks like a bug: should be sizeof - 1 */
        tmp2_buck = apr_bucket_immortal_create("</A>", sizeof("</A>"));
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

        pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info), r, next);
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
    struct sockaddr_un unix_addr;
    apr_file_t *tempsock = NULL;
    cgid_server_conf *conf = ap_get_module_config(r->server->module_config,
                                                  &cgid_module); 

    add_ssi_vars(r, f->next);
    env = ap_create_environment(r->pool, r->subprocess_env);

    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return log_scripterror(r, conf, HTTP_INTERNAL_SERVER_ERROR, 0, 
                                   "unable to create socket to cgi daemon");
    }

    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, conf->sockname);

    if (connect(sd, (struct sockaddr *)&unix_addr, sizeof(unix_addr)) < 0) {
            return log_scripterror(r, conf, HTTP_INTERNAL_SERVER_ERROR, 0, 
                                   "unable to connect to cgi daemon");
    } 

    SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, rc);
    if (rc != APR_SUCCESS) {
        return rc;
    }

    send_req(sd, r, command, env, SSI_REQ); 

    /* We are putting the tempsock variable into a file so that we can use
     * a pipe bucket to send the data to the client.
     */
    apr_os_file_put(&tempsock, &sd, r->pool);

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
        bcgi = apr_brigade_create(r->pool);
        b    = apr_bucket_pipe_create(tempsock);
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
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
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
                    cgid_pfn_ps(r, tag_val, parsed_string, sizeof(parsed_string), 1);
                    if (include_cmd(ctx, bb, parsed_string, r, f) == -1) {
                        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                                    "execution failure for parameter \"%s\" "
                                    "to tag exec in file %s", tag, r->filename);
                        CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                    }
                    /* just in case some stooge changed directories */
                }
                else if (!strcmp(tag, "cgi")) {
                    apr_status_t retval = APR_SUCCESS;

                    cgid_pfn_ps(r, tag_val, parsed_string, sizeof(parsed_string), 0);
                    SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, retval);
                    if (retval != APR_SUCCESS) {
                        return retval;
                    }

                    if (include_cgi(parsed_string, r, f->next, head_ptr, inserted_head) == -1) {
                        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                                    "invalid CGI ref \"%s\" in %s", tag_val, file);
                        CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                    }
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
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

