/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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



#define CORE_PRIVATE 

#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "apr_file_io.h"
#include "apr_portable.h"
#include "httpd.h" 
#include "http_config.h" 
#include "http_request.h" 
#include "http_core.h" 
#include "http_protocol.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "util_script.h" 
#include "http_conf_globals.h" 
#include "buff.h" 
#include "ap_mpm.h"
#include "ap_iol.h"
#include "unixd.h"
#include <sys/stat.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <sys/un.h> /* for sockaddr_un */
#include <sys/types.h>

module MODULE_VAR_EXPORT cgid_module; 

static void cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server); 
static int once_through = 0; 

static apr_pool_t *pcgi; 

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

#define SHELL_PATH "/bin/sh"

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
    BUFF *bin; 
    BUFF *bout; 
    BUFF *berror; 
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
    av = (char **) apr_palloc(p, (numwords + 5) * sizeof(char *));

    if (path) {
        av[idx++] = path;
    }
    if (user) {
        av[idx++] = user;
    }
    if (group) {
        av[idx++] = group;
     }

    av[idx++] = av0;

    for (x = 1; x <= numwords; x++) {
        w = ap_getword_nulls(p, &args, '+');
        ap_unescape_url(w);
        av[idx++] = ap_escape_shell_cmd(p, w);
    }
    av[idx] = NULL;
    return av;
}

static int call_exec(request_rec *r, char *argv0, char **env, int shellcmd)
{
    int pid = 0;
    int errfileno = STDERR_FILENO;
    /* the fd on r->server->error_log is closed, but we need somewhere to            
     * put the error messages from the log_* functions. So, we use stderr,
     * since that is better than allowing errors to go unnoticed. 
     */
    apr_put_os_file(&r->server->error_log, &errfileno, r->pool);
    /* TODO: reimplement suexec */
#if 0
    if (ap_suexec_enabled
        && ((r->server->server_uid != ap_user_id)
            || (r->server->server_gid != ap_group_id)
            || (!strncmp("/~", r->uri, 2)))) {

        char *execuser, *grpname;
        struct passwd *pw;
        struct group *gr;

        if (!strncmp("/~", r->uri, 2)) {
            gid_t user_gid;
            char *username = apr_pstrdup(r->pool, r->uri + 2);
            char *pos = strchr(username, '/');

            if (pos) {
                *pos = '\0';
            }

            if ((pw = getpwnam(username)) == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                             "getpwnam: invalid username %s", username);
                return (pid);
            }
            execuser = apr_pstrcat(r->pool, "~", pw->pw_name, NULL);
            user_gid = pw->pw_gid;

            if ((gr = getgrgid(user_gid)) == NULL) {
                if ((grpname = apr_palloc(r->pool, 16)) == NULL) {
                    return (pid);
                }
                else {
                    apr_snprintf(grpname, 16, "%ld", (long) user_gid);
                }
            }
            else {
                grpname = gr->gr_name;
            }
        }
        else {
            if ((pw = getpwuid(r->server->server_uid)) == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                             "getpwuid: invalid userid %ld",
                             (long) r->server->server_uid);
                return (pid);
            }
            execuser = apr_pstrdup(r->pool, pw->pw_name);

            if ((gr = getgrgid(r->server->server_gid)) == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                             "getgrgid: invalid groupid %ld",
                             (long) r->server->server_gid);
                return (pid);
            }
            grpname = gr->gr_name;
        }

        if (shellcmd) {
            execle(SUEXEC_BIN, SUEXEC_BIN, execuser, grpname, argv0,
                   NULL, env);
        }

        else if ((!r->args) || (!r->args[0]) || strchr(r->args, '=')) {
            execle(SUEXEC_BIN, SUEXEC_BIN, execuser, grpname, argv0,
                   NULL, env);
        }

        else {
            execve(SUEXEC_BIN,
                   create_argv(r->pool, SUEXEC_BIN, execuser, grpname,
                               argv0, r->args),
                   env);
        }
    }
    else {
#endif
        if (shellcmd) {
            execle(SHELL_PATH, SHELL_PATH, "-c", argv0, NULL, env);
        }

        else if ((!r->args) || (!r->args[0]) || strchr(r->args, '=')) {
            execle(r->filename, argv0, NULL, env);
        }

        else {
            execve(r->filename,
                   create_argv(r->pool, NULL, NULL, NULL, argv0, r->args),
                   env);
        }
#if 0
    }
#endif
    return (pid);
}

static void cgid_maint(int reason, void *data, ap_wait_t status)
{
#if APR_HAS_OTHER_CHILD
    int *sd = data;
    switch (reason) {
        case APR_OC_REASON_DEATH:
        case APR_OC_REASON_LOST:
            /* stop gap to make sure everything else works.  In the end,
             * we'll just restart the cgid server. */
            apr_destroy_pool(pcgi);
            kill(getppid(), SIGWINCH);
            break;
        case APR_OC_REASON_RESTART:
        case APR_OC_REASON_UNREGISTER:
            apr_destroy_pool(pcgi);
            kill(*sd, SIGHUP);
            break;
    }
#endif
}

static void get_req(int fd, request_rec *r, char **filename, char **argv0, char ***env) 
{ 
    int i, len, j; 
    unsigned char *data; 
    char **environ; 
    core_dir_config *temp_core; 
    void **dconf; 

    r->server = apr_pcalloc(r->pool, sizeof(server_rec)); 

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
  
    read(fd, &r->server->server_uid, sizeof(uid_t)); 
    read(fd, &r->server->server_gid, sizeof(gid_t)); 

    read(fd, &i, sizeof(int)); 
     
    /* add 1, so that if i == 0, we still malloc something. */ 
    dconf = (void **)malloc(sizeof(void *) * i + 1); 

    temp_core = (core_dir_config *)malloc(sizeof(core_module)); 
#if 0
#ifdef RLIMIT_CPU 
    read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_cpu = (struct rlimit *)malloc (sizeof(struct rlimit)); 
        read(fd, temp_core->limit_cpu, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_cpu = NULL; 
    } 
#endif 

#if defined (RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS) 
    read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_mem = (struct rlimit *)malloc (sizeof(struct rlimit)); 
        read(fd, temp_core->limit_mem, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_mem = NULL; 
    } 
#endif 

#ifdef RLIMIT_NPROC 
    read(fd, &j, sizeof(int)); 
    if (j) { 
        temp_core->limit_nproc = (struct rlimit *)malloc (sizeof(struct rlimit)); 
        read(fd, temp_core->limit_nproc, sizeof(struct rlimit)); 
    } 
    else { 
        temp_core->limit_nproc = NULL; 
    } 
#endif 
#endif
    dconf[i] = (void *)temp_core; 
    r->per_dir_config = dconf; 
} 



static void send_req(int fd, request_rec *r, char *argv0, char **env) 
{ 
    int len; 
    int i = 0; 
    char *data; 

    data = apr_pstrcat(r->pool, r->filename, "\n", argv0, "\n", r->uri, "\n", 
                     NULL); 

    for (i =0; env[i]; i++) { 
        continue; 
    } 

    if (write(fd, &i, sizeof(int)) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
        }     

    for (i = 0; env[i]; i++) { 
        data = apr_pstrcat(r->pool, data, env[i], "\n", NULL); 
    } 
    data = apr_pstrcat(r->pool, data, r->args, NULL); 
    len = strlen(data); 
    if (write(fd, &len, sizeof(int)) < 0) { 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
        }     
    if (write(fd, data, len) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
        }     
    if (write(fd, &r->server->server_uid, sizeof(uid_t)) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
        }     
    if (write(fd, &r->server->server_gid, sizeof(gid_t)) < 0) { 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
        }     
    if (write(fd, &core_module.module_index, sizeof(int)) < 0) { 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, 
                     "write to cgi daemon process"); 
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

static int cgid_server_child(int sd) 
{ 
    char *argv0; 
    char *filename; 
    char **env; 
    apr_pool_t *p; 
    request_rec *r; 

    apr_create_pool(&p, pcgi); 
    r = apr_pcalloc(p, sizeof(request_rec)); 
    r->pool = p; 
    dup2(sd, STDIN_FILENO); 
    dup2(sd, STDOUT_FILENO); 
    get_req(sd, r, &filename, &argv0, &env); 
    call_exec(r, argv0, env, 0); 
    exit(-1);   /* We should NEVER get here */
} 

static int cgid_server(void *data) 
{ 
    struct sockaddr_un unix_addr;
    int pid; 
    int sd, sd2, len, rc;
    int errfile;
    mode_t omask;
    server_rec *main_server = data;
    cgid_server_conf *sconf = (cgid_server_conf *)ap_get_module_config( 
                       main_server->module_config, &cgid_module); 

    apr_signal(SIGCHLD, SIG_IGN); 
    if (unlink(sconf->sockname) < 0 &&
        errno != ENOENT) {
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
        len = sizeof(unix_addr);
        sd2 = accept(sd, (struct sockaddr *)&unix_addr, &len);
        if (sd2 < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, (server_rec *)data,
                         "Error accepting on cgid socket.");
            continue;
        }
       
        if ((pid = fork()) > 0) {
            close(sd2);
        } 
        else if (pid == 0) { 
            /* setup the STDERR here, because I have all the info
             * for it.  I'll do the STDIN and STDOUT later, but I can't
             * do STDERR as easily.
             */
            if (sconf->logname) {
                dup2(open(sconf->logname, O_WRONLY), STDERR_FILENO);
            }
            else {
                apr_get_os_file(&errfile, main_server->error_log);
                dup2(errfile, STDERR_FILENO);
            }
            cgid_server_child(sd2); 
        } 
        else { 
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, (server_rec *)data, 
                         "Couldn't fork cgi script"); 
        } 
    } 
    return -1; 
} 

static void cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server) 
{ 
    pid_t pid; 
    apr_proc_t *procnew;

    if (once_through > 0) { 
        apr_create_pool(&pcgi, p); 

        if ((pid = fork()) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, 
                         "Couldn't spawn cgid daemon process"); 
        }
        else if (pid == 0) {
            cgid_server(main_server);
            exit(-1);
        } 
        procnew = apr_pcalloc(p, sizeof(*procnew));        
        procnew->pid = pid;
        procnew->err = procnew->in = procnew->out = NULL;
        apr_note_subprocess(p, procnew, kill_after_timeout);
#if APR_HAS_OTHER_CHILD
        apr_register_other_child(procnew, cgid_maint, NULL, NULL, p);
#endif
    } 
    else once_through++; 
} 

static void *create_cgid_config(apr_pool_t *p, server_rec *s) 
{ 
    cgid_server_conf *c = 
    (cgid_server_conf *) apr_pcalloc(p, sizeof(cgid_server_conf)); 

    c->logname = NULL; 
    c->logbytes = DEFAULT_LOGBYTES; 
    c->bufbytes = DEFAULT_BUFBYTES; 
    c->sockname = ap_server_root_relative(p, DEFAULT_SOCKET); 
    c->bin = c->bout = c->berror = NULL; 
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
    cgid_server_conf *conf = 
    (cgid_server_conf *) ap_get_module_config(s->module_config, &cgid_module); 

    conf->logname = arg; 
    return NULL; 
} 

static const char *set_scriptlog_length(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = 
    (cgid_server_conf *) ap_get_module_config(s->module_config, &cgid_module); 

    conf->logbytes = atol(arg); 
    return NULL; 
} 

static const char *set_scriptlog_buffer(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = 
    (cgid_server_conf *) ap_get_module_config(s->module_config, &cgid_module); 

    conf->bufbytes = atoi(arg); 
    return NULL; 
} 

static const char *set_script_socket(cmd_parms *cmd, void *dummy, const char *arg) 
{ 
    server_rec *s = cmd->server; 
    cgid_server_conf *conf = 
    (cgid_server_conf *) ap_get_module_config(s->module_config, &cgid_module); 

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
                           int show_errno, char *error) 
{ 
    apr_file_t *f = NULL; 
    struct stat finfo; 
    char time_str[AP_CTIME_LEN];

    ap_log_rerror(APLOG_MARK, show_errno|APLOG_ERR, errno, r, 
                "%s: %s", error, r->filename); 

    if (!conf->logname || 
        ((stat(ap_server_root_relative(r->pool, conf->logname), &finfo) == 0) 
         && (finfo.st_size > conf->logbytes)) || 
         (apr_open(&f, ap_server_root_relative(r->pool, conf->logname),
                  APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)) { 
        return ret; 
    } 

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgid-bin/printenv HTTP/1.0" */ 
    apr_ctime(time_str, apr_now());
    apr_fprintf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri, 
            r->args ? "?" : "", r->args ? r->args : "", r->protocol); 
    /* "%% 500 /usr/local/apache/cgid-bin */ 
    apr_fprintf(f, "%%%% %d %s\n", ret, r->filename); 

    apr_fprintf(f, "%%error\n%s\n", error); 

    apr_close(f); 
    return ret; 
} 

static int log_script(request_rec *r, cgid_server_conf * conf, int ret, 
                  char *dbuf, const char *sbuf, BUFF *script_in, BUFF *script_err) 
{ 
    apr_array_header_t *hdrs_arr = ap_table_elts(r->headers_in); 
    apr_table_entry_t *hdrs = (apr_table_entry_t *) hdrs_arr->elts; 
    char argsbuffer[HUGE_STRING_LEN]; 
    apr_file_t *f = NULL; 
    int i; 
    struct stat finfo; 
    char time_str[AP_CTIME_LEN];

    if (!conf->logname || 
        ((stat(ap_server_root_relative(r->pool, conf->logname), &finfo) == 0) 
         && (finfo.st_size > conf->logbytes)) || 
         (apr_open(&f, ap_server_root_relative(r->pool, conf->logname), 
                  APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)) { 
        /* Soak up script output */ 
        while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0) 
            continue; 
        if (script_err) {
            while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) 
                continue; 
        }
        return ret; 
    } 

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgid-bin/printenv HTTP/1.0" */ 
    apr_ctime(time_str, apr_now());
    apr_fprintf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri, 
            r->args ? "?" : "", r->args ? r->args : "", r->protocol); 
    /* "%% 500 /usr/local/apache/cgid-bin" */ 
    apr_fprintf(f, "%%%% %d %s\n", ret, r->filename); 

    apr_puts("%request\n", f); 
    for (i = 0; i < hdrs_arr->nelts; ++i) { 
        if (!hdrs[i].key) 
            continue; 
        apr_fprintf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val); 
    } 
    if ((r->method_number == M_POST || r->method_number == M_PUT) 
        && *dbuf) { 
        apr_fprintf(f, "\n%s\n", dbuf); 
    } 

    apr_puts("%response\n", f); 
    hdrs_arr = ap_table_elts(r->err_headers_out); 
    hdrs = (apr_table_entry_t *) hdrs_arr->elts; 

    for (i = 0; i < hdrs_arr->nelts; ++i) { 
        if (!hdrs[i].key) 
            continue; 
        apr_fprintf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val); 
    } 

    if (sbuf && *sbuf) 
        apr_fprintf(f, "%s\n", sbuf); 

    if (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0) { 
        apr_puts("%stdout\n", f); 
        apr_puts(argsbuffer, f); 
        while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_in) > 0) 
            apr_puts(argsbuffer, f); 
        apr_puts("\n", f); 
    } 

    if (script_err) {
        if (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) { 
            apr_puts("%stderr\n", f); 
            apr_puts(argsbuffer, f); 
            while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script_err) > 0) 
                apr_puts(argsbuffer, f); 
            apr_puts("\n", f); 
        } 
    }

    ap_bclose(script_in); 
    if (script_err) {
        ap_bclose(script_err); 
    }

    apr_close(f); 
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
    BUFF *script = NULL; 
    char argsbuffer[HUGE_STRING_LEN]; 
    void *sconf = r->server->module_config; 
    cgid_server_conf *conf = (cgid_server_conf *) ap_get_module_config(sconf, &cgid_module); 
    int is_included = !strcmp(r->protocol, "INCLUDED"); 
    int sd;
    char **env; 
    struct sockaddr_un unix_addr;
    apr_socket_t *tempsock = NULL;
    int nbytes;
    ap_iol *iol;
    script = ap_bcreate(r->pool, B_RDWR); 

    if (r->method_number == M_OPTIONS) { 
        /* 99 out of 100 cgid scripts, this is all they support */ 
        r->allowed |= (1 << M_GET); 
        r->allowed |= (1 << M_POST); 
        return DECLINED; 
    } 

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
        return log_scripterror(r, conf, HTTP_FORBIDDEN, APLOG_NOERRNO, 
                               "Options ExecCGI is off in this directory"); 
    if (nph && is_included) 
        return log_scripterror(r, conf, HTTP_FORBIDDEN, APLOG_NOERRNO, 
                               "attempt to include NPH CGI script"); 

#if defined(OS2) || defined(WIN32) 
    /* Allow for cgid files without the .EXE extension on them under OS/2 */ 
    if (r->finfo.st_mode == 0) { 
        struct stat statbuf; 
        char *newfile; 

        newfile = apr_pstrcat(r->pool, r->filename, ".EXE", NULL); 

        if ((stat(newfile, &statbuf) != 0) || (!S_ISREG(statbuf.st_mode))) { 
            return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, 
                                   "script not found or unable to stat"); 
        } else { 
            r->filename = newfile; 
        } 
    } 
#else 
    if (r->finfo.protection == 0) 
        return log_scripterror(r, conf, HTTP_NOT_FOUND, APLOG_NOERRNO, 
                               "script not found or unable to stat"); 
#endif 
    if (r->finfo.filetype == APR_DIR) 
        return log_scripterror(r, conf, HTTP_FORBIDDEN, APLOG_NOERRNO, 
                               "attempt to invoke directory as script"); 
/*
    if (!ap_suexec_enabled) { 
        if (!ap_can_exec(&r->finfo)) 
            return log_scripterror(r, conf, HTTP_FORBIDDEN, APLOG_NOERRNO, 
                                   "file permissions deny server execution"); 
    } 
*/
    ap_add_common_vars(r); 
    ap_add_cgi_vars(r); 
    env = ap_create_environment(r->pool, r->subprocess_env); 

    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, 
                                   "unable to create socket to cgi daemon");
    } 
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, conf->sockname);

    if (connect(sd, (struct sockaddr *)&unix_addr, sizeof(unix_addr)) < 0) {
            return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, 
                                   "unable to connect to cgi daemon");
    } 

    send_req(sd, r, argv0, env); 

    apr_put_os_sock(&tempsock, &sd, pcgi);

    iol = ap_iol_attach_socket(pcgi, tempsock);

    ap_bpush_iol(script, iol); 

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
            ap_bwrite(script, argsbuffer, len_read, &nbytes);
            if (nbytes < len_read) { 
                /* silly script stopped reading, soak up remaining message */ 
                while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN) > 0) { 
                    /* dump it */ 
                } 
                break; 
            } 
        } 

        ap_bflush(script); 

    } 

    /* Handle script return... */ 
    if (script && !nph) { 
        const char *location; 
        char sbuf[MAX_STRING_LEN]; 
        int ret; 

        if ((ret = ap_scan_script_header_err_buff(r, script, sbuf))) { 
            return log_script(r, conf, ret, dbuf, sbuf, script, NULL); 
        } 

        location = apr_table_get(r->headers_out, "Location"); 

        if (location && location[0] == '/' && r->status == 200) { 

            /* Soak up all the script output */ 
            while (ap_bgets(argsbuffer, HUGE_STRING_LEN, script) > 0) { 
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

        ap_send_http_header(r); 
        if (!r->header_only) { 
            ap_send_fb(script, r); 
        } 
        ap_bclose(script); 
    } 

    if (script && nph) { 
        ap_send_fb(script, r); 
    } 

    return OK; /* NOT r->status, even if it has changed. */ 
} 

static const handler_rec cgid_handlers[] = 
{ 
    {CGI_MAGIC_TYPE, cgid_handler}, 
    {"cgi-script", cgid_handler}, 
    {NULL} 
};

static void register_hook(void)
{
    ap_hook_post_config(cgid_init, NULL, NULL, AP_HOOK_MIDDLE);
}

module MODULE_VAR_EXPORT cgid_module = { 
    STANDARD20_MODULE_STUFF, 
    NULL, /* dir config creater */ 
    NULL, /* dir merger --- default is to override */ 
    create_cgid_config, /* server config */ 
    merge_cgid_config, /* merge server config */ 
    cgid_cmds, /* command table */ 
    cgid_handlers, /* handlers */ 
    register_hook /* register_handlers */ 
}; 

