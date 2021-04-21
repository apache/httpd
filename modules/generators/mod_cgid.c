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
 * Compliant to cgi/1.1 spec
 *
 * Adapted by rst from original NCSA code by Rob McCool
 *
 * This modules uses a httpd core function (ap_add_common_vars) to add some new env vars, 
 * like REDIRECT_URL and REDIRECT_QUERY_STRING for custom error responses and DOCUMENT_ROOT.
 * It also adds SERVER_ADMIN - useful for scripts to know who to mail when they fail.
 * 
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
#include "mpm_common.h"
#include "mod_suexec.h"
#include "../filters/mod_include.h"

#include "mod_core.h"


/* ### should be tossed in favor of APR */
#include <sys/stat.h>
#include <sys/un.h> /* for sockaddr_un */

#if APR_HAVE_STRUCT_RLIMIT
#if defined (RLIMIT_CPU) || defined (RLIMIT_NPROC) || defined (RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
#define AP_CGID_USE_RLIMIT
#endif
#endif

module AP_MODULE_DECLARE_DATA cgid_module;

static int cgid_start(apr_pool_t *p, server_rec *main_server, apr_proc_t *procnew);
static int cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *main_server);
static int handle_exec(include_ctx_t *ctx, ap_filter_t *f, apr_bucket_brigade *bb);

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *cgid_pfn_reg_with_ssi;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *cgid_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *cgid_pfn_ps;

static apr_pool_t *pcgi = NULL;
static pid_t daemon_pid;
static int daemon_should_exit = 0;
static server_rec *root_server = NULL;
static apr_pool_t *root_pool = NULL;
static const char *sockname;
static struct sockaddr_un *server_addr;
static apr_socklen_t server_addr_len;
static pid_t parent_pid;
static ap_unix_identity_t empty_ugid = { (uid_t)-1, (gid_t)-1, -1 };

typedef struct { 
    apr_interval_time_t timeout;
} cgid_dirconf;

/* The APR other-child API doesn't tell us how the daemon exited
 * (SIGSEGV vs. exit(1)).  The other-child maintenance function
 * needs to decide whether to restart the daemon after a failure
 * based on whether or not it exited due to a fatal startup error
 * or something that happened at steady-state.  This exit status
 * is unlikely to collide with exit signals.
 */
#define DAEMON_STARTUP_ERROR 254

/* Read and discard the data in the brigade produced by a CGI script */
static void discard_script_output(apr_bucket_brigade *bb);

/* This doer will only ever be called when we are sure that we have
 * a valid ugid.
 */
static ap_unix_identity_t *cgid_suexec_id_doer(const request_rec *r)
{
    return (ap_unix_identity_t *)
                        ap_get_module_config(r->request_config, &cgid_module);
}

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
#define DEFAULT_SOCKET "cgisock"

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

#ifndef DEFAULT_CONNECT_STARTUP_DELAY
#define DEFAULT_CONNECT_STARTUP_DELAY 60
#endif

typedef struct {
    const char *logname;
    long logbytes;
    int bufbytes;
} cgid_server_conf;

#ifdef AP_CGID_USE_RLIMIT
typedef struct {
#ifdef RLIMIT_CPU
    int    limit_cpu_set;
    struct rlimit limit_cpu;
#endif
#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)
    int    limit_mem_set;
    struct rlimit limit_mem;
#endif
#ifdef RLIMIT_NPROC
    int    limit_nproc_set;
    struct rlimit limit_nproc;
#endif

} cgid_rlimit_t;
#endif

typedef struct {
    int req_type; /* request type (CGI_REQ, SSI_REQ, etc.) */
    unsigned long conn_id; /* connection id; daemon uses this as a hash value
                            * to find the script pid when it is time for that
                            * process to be cleaned up
                            */
    pid_t ppid;            /* sanity check for config problems leading to
                            * wrong cgid socket use
                            */
    int env_count;
    ap_unix_identity_t ugid;
    apr_size_t filename_len;
    apr_size_t argv0_len;
    apr_size_t uri_len;
    apr_size_t args_len;
    int loglevel; /* to stuff in server_rec */

#ifdef AP_CGID_USE_RLIMIT
    cgid_rlimit_t limits;
#endif
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

    if (!(*args) || ap_strchr_c(args, '=')) {
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
        ap_unescape_url(w);
        av[idx++] = ap_escape_shell_cmd(p, w);
    }
    av[idx] = NULL;
    return av;
}

#if APR_HAS_OTHER_CHILD
static void cgid_maint(int reason, void *data, apr_wait_t status)
{
    apr_proc_t *proc = data;
    int mpm_state;
    int stopping;

    switch (reason) {
        case APR_OC_REASON_DEATH:
            apr_proc_other_child_unregister(data);
            /* If apache is not terminating or restarting,
             * restart the cgid daemon
             */
            stopping = 1; /* if MPM doesn't support query,
                           * assume we shouldn't restart daemon
                           */
            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS &&
                mpm_state != AP_MPMQ_STOPPING) {
                stopping = 0;
            }
            if (!stopping) {
                if (status == DAEMON_STARTUP_ERROR) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, APLOGNO(01238)
                                 "cgid daemon failed to initialize");
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(01239)
                                 "cgid daemon process died, restarting");
                    cgid_start(root_pool, root_server, proc);
                }
            }
            break;
        case APR_OC_REASON_RESTART:
            /* don't do anything; server is stopping or restarting */
            apr_proc_other_child_unregister(data);
            break;
        case APR_OC_REASON_LOST:
            /* Restart the child cgid daemon process */
            apr_proc_other_child_unregister(data);
            cgid_start(root_pool, root_server, proc);
            break;
        case APR_OC_REASON_UNREGISTER:
            /* we get here when pcgi is cleaned up; pcgi gets cleaned
             * up when pconf gets cleaned up
             */
            kill(proc->pid, SIGHUP); /* send signal to daemon telling it to die */

            /* Remove the cgi socket, we must do it here in order to try and
             * guarantee the same permissions as when the socket was created.
             */
            if (unlink(sockname) < 0 && errno != ENOENT) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, ap_server_conf, APLOGNO(01240)
                             "Couldn't unlink unix domain socket %s",
                             sockname);
            }
            break;
    }
}
#endif

static apr_status_t close_unix_socket(void *thefd)
{
    int fd = (int)((long)thefd);

    return close(fd);
}

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

static apr_status_t sock_writev(int fd, request_rec *r, int count, ...)
{
    va_list ap;
    int rc;
    struct iovec *vec;
    int i;

    vec = (struct iovec *)apr_palloc(r->pool, count * sizeof(struct iovec));
    va_start(ap, count);
    for (i = 0; i < count; i++) {
        vec[i].iov_base = va_arg(ap, caddr_t);
        vec[i].iov_len  = va_arg(ap, apr_size_t);
    }
    va_end(ap);

    do {
        rc = writev(fd, vec, count);
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
    char **environ;
    core_request_config *temp_core;
    void **rconf;
    apr_status_t stat;

    r->server = apr_pcalloc(r->pool, sizeof(server_rec));

    /* read the request header */
    stat = sock_read(fd, req, sizeof(*req));
    if (stat != APR_SUCCESS) {
        return stat;
    }
    r->server->log.level = req->loglevel;
    if (req->req_type == GETPID_REQ) {
        /* no more data sent for this request */
        return APR_SUCCESS;
    }

    /* handle module indexes and such */
    rconf = (void **)ap_create_request_config(r->pool);

    temp_core = (core_request_config *)apr_palloc(r->pool, sizeof(core_module));
    rconf[AP_CORE_MODULE_INDEX] = (void *)temp_core;
    r->request_config = (ap_conf_vector_t *)rconf;
    ap_set_module_config(r->request_config, &cgid_module, (void *)&req->ugid);

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

#ifdef AP_CGID_USE_RLIMIT
    if ((stat = sock_read(fd, &(req->limits), sizeof(cgid_rlimit_t))) != APR_SUCCESS)
         return stat;
#endif

    return APR_SUCCESS;
}

static apr_status_t send_req(int fd, request_rec *r, char *argv0, char **env,
                             int req_type)
{
    int i;
    cgid_req_t req = {0};
    apr_status_t stat;
    ap_unix_identity_t * ugid = ap_run_get_suexec_identity(r);
    core_dir_config *core_conf = ap_get_core_module_config(r->per_dir_config);


    if (ugid == NULL) {
        req.ugid = empty_ugid;
    } else {
        memcpy(&req.ugid, ugid, sizeof(ap_unix_identity_t));
    }

    req.req_type = req_type;
    req.ppid = parent_pid;
    req.conn_id = r->connection->id;
    for (req.env_count = 0; env[req.env_count]; req.env_count++) {
        continue;
    }
    req.filename_len = strlen(r->filename);
    req.argv0_len = strlen(argv0);
    req.uri_len = strlen(r->uri);
    req.args_len = r->args ? strlen(r->args) : 0;
    req.loglevel = r->server->log.level;

    /* Write the request header */
    if (req.args_len) {
        stat = sock_writev(fd, r, 5,
                           &req, sizeof(req),
                           r->filename, req.filename_len,
                           argv0, req.argv0_len,
                           r->uri, req.uri_len,
                           r->args, req.args_len);
    } else {
        stat = sock_writev(fd, r, 4,
                           &req, sizeof(req),
                           r->filename, req.filename_len,
                           argv0, req.argv0_len,
                           r->uri, req.uri_len);
    }

    if (stat != APR_SUCCESS) {
        return stat;
    }

    /* write the environment variables */
    for (i = 0; i < req.env_count; i++) {
        apr_size_t curlen = strlen(env[i]);

        if ((stat = sock_writev(fd, r, 2, &curlen, sizeof(curlen),
                                env[i], curlen)) != APR_SUCCESS) {
            return stat;
        }
    }
#if defined(RLIMIT_CPU) && defined(AP_CGID_USE_RLIMIT)
    if (core_conf->limit_cpu) {
        req.limits.limit_cpu = *(core_conf->limit_cpu);
        req.limits.limit_cpu_set = 1;
    }
    else {
        req.limits.limit_cpu_set = 0;
    }
#endif

#if defined(AP_CGID_USE_RLIMIT) && (defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS))
    if (core_conf->limit_mem) {
        req.limits.limit_mem = *(core_conf->limit_mem);
        req.limits.limit_mem_set = 1;
    }
    else {
        req.limits.limit_mem_set = 0;
    }

#endif

#if defined(RLIMIT_NPROC) && defined(AP_CGID_USE_RLIMIT)
    if (core_conf->limit_nproc) {
        req.limits.limit_nproc = *(core_conf->limit_nproc);
        req.limits.limit_nproc_set = 1;
    }
    else {
        req.limits.limit_nproc_set = 0;
    }
#endif

#ifdef AP_CGID_USE_RLIMIT
    if ( (stat = sock_write(fd, &(req.limits), sizeof(cgid_rlimit_t))) != APR_SUCCESS)
        return stat;
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
    ap_log_error(APLOG_MARK, APLOG_ERR, err, r->server, APLOGNO(01241) "%s", description);
}

static int cgid_server(void *data)
{
    int sd, sd2, rc;
    mode_t omask;
    apr_pool_t *ptrans;
    server_rec *main_server = data;
    apr_hash_t *script_hash = apr_hash_make(pcgi);
    apr_status_t rv;

    apr_pool_create(&ptrans, pcgi);
    apr_pool_tag(ptrans, "cgid_ptrans");

    apr_signal(SIGCHLD, SIG_IGN);
    apr_signal(SIGHUP, daemon_signal_handler);

    /* Close our copy of the listening sockets */
    ap_close_listeners();

    /* cgid should use its own suexec doer */
    ap_hook_get_suexec_identity(cgid_suexec_id_doer, NULL, NULL,
                                APR_HOOK_REALLY_FIRST);
    apr_hook_sort_all();

    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, APLOGNO(01242)
                     "Couldn't create unix domain socket");
        return errno;
    }

    apr_pool_cleanup_register(pcgi, (void *)((long)sd),
                              close_unix_socket, close_unix_socket);

    omask = umask(0077); /* so that only Apache can use socket */
    rc = bind(sd, (struct sockaddr *)server_addr, server_addr_len);
    umask(omask); /* can't fail, so can't clobber errno */
    if (rc < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, APLOGNO(01243)
                     "Couldn't bind unix domain socket %s",
                     sockname);
        return errno;
    }

    /* Not all flavors of unix use the current umask for AF_UNIX perms */
    rv = apr_file_perms_set(sockname, APR_FPROT_UREAD|APR_FPROT_UWRITE|APR_FPROT_UEXECUTE);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, main_server, APLOGNO(01244)
                     "Couldn't set permissions on unix domain socket %s",
                     sockname);
        return rv;
    }

    if (listen(sd, DEFAULT_CGID_LISTENBACKLOG) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, APLOGNO(01245)
                     "Couldn't listen on unix domain socket");
        return errno;
    }

    if (!geteuid()) {
        if (chown(sockname, ap_unixd_config.user_id, -1) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, APLOGNO(01246)
                         "Couldn't change owner of unix domain socket %s",
                         sockname);
            return errno;
        }
    }

    /* if running as root, switch to configured user/group */
    if ((rc = ap_run_drop_privileges(pcgi, ap_server_conf)) != 0) {
        return rc;
    }

    while (!daemon_should_exit) {
        int errfileno = STDERR_FILENO;
        char *argv0 = NULL;
        char **env = NULL;
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
        void *key;
        apr_socklen_t len;
        struct sockaddr_un unix_addr;

        apr_pool_clear(ptrans);

        len = sizeof(unix_addr);
        sd2 = accept(sd, (struct sockaddr *)&unix_addr, &len);
        if (sd2 < 0) {
#if defined(ENETDOWN)
            if (errno == ENETDOWN) {
                /* The network has been shut down, no need to continue. Die gracefully */
                ++daemon_should_exit;
            }
#endif
            if (errno != EINTR) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno,
                             (server_rec *)data, APLOGNO(01247)
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
                         main_server, APLOGNO(01248)
                         "Error reading request on cgid socket");
            close(sd2);
            continue;
        }

        if (cgid_req.ppid != parent_pid) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, main_server, APLOGNO(01249)
                         "CGI request received from wrong server instance; "
                         "see ScriptSock directive");
            close(sd2);
            continue;
        }

        if (cgid_req.req_type == GETPID_REQ) {
            pid_t pid;
            apr_status_t rv;

            pid = (pid_t)((long)apr_hash_get(script_hash, &cgid_req.conn_id, sizeof(cgid_req.conn_id)));
            rv = sock_write(sd2, &pid, sizeof(pid));
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                             main_server, APLOGNO(01250)
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
#ifdef AP_CGID_USE_RLIMIT
#ifdef RLIMIT_CPU
        (  (cgid_req.limits.limit_cpu_set) && ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_CPU,
                                      &cgid_req.limits.limit_cpu)) != APR_SUCCESS)) ||
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
        ( (cgid_req.limits.limit_mem_set) && ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_MEM,
                                      &cgid_req.limits.limit_mem)) != APR_SUCCESS)) ||
#endif
#ifdef RLIMIT_NPROC
        ( (cgid_req.limits.limit_nproc_set) && ((rc = apr_procattr_limit_set(procattr, APR_LIMIT_NPROC,
                                      &cgid_req.limits.limit_nproc)) != APR_SUCCESS)) ||
#endif
#endif

            ((rc = apr_procattr_child_errfn_set(procattr, cgid_child_errfn)) != APR_SUCCESS)) {
            /* Something bad happened, tell the world.
             * ap_log_rerror() won't work because the header table used by
             * ap_log_rerror() hasn't been replicated in the phony r
             */
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, r->server, APLOGNO(01251)
                         "couldn't set child process attributes: %s", r->filename);

            procnew->pid = 0; /* no process to clean up */
            close(sd2);
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

            if (memcmp(&empty_ugid, &cgid_req.ugid, sizeof(empty_ugid))) {
                /* We have a valid identity, and can be sure that
                 * cgid_suexec_id_doer will return a valid ugid
                 */
                rc = ap_os_create_privileged_process(r, procnew, argv0, argv,
                                                     (const char * const *)env,
                                                     procattr, ptrans);
            } else {
                rc = apr_proc_create(procnew, argv0, argv,
                                     (const char * const *)env,
                                     procattr, ptrans);
            }

            if (rc != APR_SUCCESS) {
                /* Bad things happened. Everyone should have cleaned up.
                 * ap_log_rerror() won't work because the header table used by
                 * ap_log_rerror() hasn't been replicated in the phony r
                 */
                ap_log_error(APLOG_MARK, APLOG_ERR, rc, r->server, APLOGNO(01252)
                             "couldn't create child process: %d: %s", rc,
                             apr_filepath_name_get(r->filename));

                procnew->pid = 0; /* no process to clean up */
            }
        }

        /* If the script process was created, remember the pid for
         * later cleanup.  If the script process wasn't created, clear
         * out any prior pid with the same key.
         *
         * We don't want to leak storage for the key, so only allocate
         * a key if the key doesn't exist yet in the hash; there are
         * only a limited number of possible keys (one for each
         * possible thread in the server), so we can allocate a copy
         * of the key the first time a thread has a cgid request.
         * Note that apr_hash_set() only uses the storage passed in
         * for the key if it is adding the key to the hash for the
         * first time; new key storage isn't needed for replacing the
         * existing value of a key.
         */

        if (apr_hash_get(script_hash, &cgid_req.conn_id, sizeof(cgid_req.conn_id))) {
            key = &cgid_req.conn_id;
        }
        else {
            key = apr_pmemdup(pcgi, &cgid_req.conn_id, sizeof(cgid_req.conn_id));
        }
        apr_hash_set(script_hash, key, sizeof(cgid_req.conn_id),
                     (void *)((long)procnew->pid));
    }
    return -1; /* should be <= 0 to distinguish from startup errors */
}

static int cgid_start(apr_pool_t *p, server_rec *main_server,
                      apr_proc_t *procnew)
{

    daemon_should_exit = 0; /* clear setting from previous generation */
    if ((daemon_pid = fork()) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server, APLOGNO(01253)
                     "mod_cgid: Couldn't spawn cgid daemon process");
        return DECLINED;
    }
    else if (daemon_pid == 0) {
        if (pcgi == NULL) {
            apr_pool_create(&pcgi, p);
            apr_pool_tag(pcgi, "cgid_pcgi");
        }
        exit(cgid_server(main_server) > 0 ? DAEMON_STARTUP_ERROR : -1);
    }
    procnew->pid = daemon_pid;
    procnew->err = procnew->in = procnew->out = NULL;
    apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
#if APR_HAS_OTHER_CHILD
    apr_proc_other_child_register(procnew, cgid_maint, procnew, NULL, p);
#endif
    return OK;
}

static int cgid_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp)
{
    sockname = ap_append_pid(pconf, DEFAULT_SOCKET, ".");
    return OK;
}

static int cgid_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                     server_rec *main_server)
{
    apr_proc_t *procnew = NULL;
    const char *userdata_key = "cgid_init";
    int ret = OK;
    void *data;

    root_server = main_server;
    root_pool = p;

    apr_pool_userdata_get(&data, userdata_key, main_server->process->pool);
    if (!data) {
        procnew = apr_pcalloc(main_server->process->pool, sizeof(*procnew));
        procnew->pid = -1;
        procnew->err = procnew->in = procnew->out = NULL;
        apr_pool_userdata_set((const void *)procnew, userdata_key,
                     apr_pool_cleanup_null, main_server->process->pool);
        return ret;
    }
    else {
        procnew = data;
    }

    if (ap_state_query(AP_SQ_MAIN_STATE) != AP_SQ_MS_CREATE_PRE_CONFIG) {
        char *tmp_sockname;

        parent_pid = getpid();
        tmp_sockname = ap_runtime_dir_relative(p, sockname);
        if (strlen(tmp_sockname) > sizeof(server_addr->sun_path) - 1) {
            tmp_sockname[sizeof(server_addr->sun_path)] = '\0';
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, main_server, APLOGNO(01254)
                        "The length of the ScriptSock path exceeds maximum, "
                        "truncating to %s", tmp_sockname);
        }
        sockname = tmp_sockname;

        server_addr_len = APR_OFFSETOF(struct sockaddr_un, sun_path) + strlen(sockname);
        server_addr = (struct sockaddr_un *)apr_palloc(p, server_addr_len + 1);
        server_addr->sun_family = AF_UNIX;
        strcpy(server_addr->sun_path, sockname);

        ret = cgid_start(p, main_server, procnew);
        if (ret != OK ) {
            return ret;
        }
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
    return ret;
}

static void *create_cgid_config(apr_pool_t *p, server_rec *s)
{
    cgid_server_conf *c =
    (cgid_server_conf *) apr_pcalloc(p, sizeof(cgid_server_conf));

    c->logname = NULL;
    c->logbytes = DEFAULT_LOGBYTES;
    c->bufbytes = DEFAULT_BUFBYTES;
    return c;
}

static void *merge_cgid_config(apr_pool_t *p, void *basev, void *overridesv)
{
    cgid_server_conf *base = (cgid_server_conf *) basev, *overrides = (cgid_server_conf *) overridesv;

    return overrides->logname ? overrides : base;
}

static void *create_cgid_dirconf(apr_pool_t *p, char *dummy)
{
    cgid_dirconf *c = (cgid_dirconf *) apr_pcalloc(p, sizeof(cgid_dirconf));
    return c;
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
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    /* Make sure the pid is appended to the sockname */
    sockname = ap_append_pid(cmd->pool, arg, ".");
    sockname = ap_runtime_dir_relative(cmd->pool, sockname);

    if (!sockname) {
        return apr_pstrcat(cmd->pool, "Invalid ScriptSock path",
                           arg, NULL);
    }

    return NULL;
}
static const char *set_script_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    cgid_dirconf *dc = dummy;

    if (ap_timeout_parameter_parse(arg, &dc->timeout, "s") != APR_SUCCESS) { 
        return "CGIDScriptTimeout has wrong format";
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
    AP_INIT_TAKE1("ScriptSock", set_script_socket, NULL, RSRC_CONF,
                  "the name of the socket to use for communication with "
                  "the cgi daemon."),
    AP_INIT_TAKE1("CGIDScriptTimeout", set_script_timeout, NULL, RSRC_CONF | ACCESS_CONF,
                  "The amount of time to wait between successful reads from "
                  "the CGI script, in seconds."),
                  
    {NULL}
};

static int log_scripterror(request_rec *r, cgid_server_conf * conf, int ret,
                           apr_status_t rv, char *error)
{
    apr_file_t *f = NULL;
    struct stat finfo;
    char time_str[APR_CTIME_LEN];
    int log_flags = rv ? APLOG_ERR : APLOG_ERR;

    /* Intentional no APLOGNO */
    /* Callee provides APLOGNO in error text */
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
        apr_file_write_full(f, buf, len, NULL);
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

static int connect_to_daemon(int *sdptr, request_rec *r,
                             cgid_server_conf *conf)
{
    int sd;
    int connect_tries;
    int connect_errno;
    apr_interval_time_t sliding_timer;

    connect_tries = 0;
    sliding_timer = 100000; /* 100 milliseconds */
    while (1) {
        connect_errno = 0;
        ++connect_tries;
        if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return log_scripterror(r, conf, HTTP_INTERNAL_SERVER_ERROR, errno,
                                   APLOGNO(01255) "unable to create socket to cgi daemon");
        }
        if (connect(sd, (struct sockaddr *)server_addr, server_addr_len) < 0) {
            /* Save errno for later */
            connect_errno = errno;
            /* ECONNREFUSED means the listen queue is full; ENOENT means that
             * the cgid server either hasn't started up yet, or we're pointing
             * at the wrong socket file */
            if ((errno == ECONNREFUSED || errno == ENOENT) && 
                 connect_tries < DEFAULT_CONNECT_ATTEMPTS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, errno, r, APLOGNO(01256)
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
                return log_scripterror(r, conf, HTTP_SERVICE_UNAVAILABLE, errno, APLOGNO(01257)
                                       "unable to connect to cgi daemon after multiple tries");
            }
        }
        else {
            apr_pool_cleanup_register(r->pool, (void *)((long)sd),
                                      close_unix_socket, apr_pool_cleanup_null);
            break; /* we got connected! */
        }

        /* If we didn't find the socket but the server was not recently restarted,
         * chances are there's something wrong with the cgid daemon
         */
        if (connect_errno == ENOENT &&
            apr_time_sec(apr_time_now() - ap_scoreboard_image->global->restart_time) > 
                DEFAULT_CONNECT_STARTUP_DELAY) {
            return log_scripterror(r, conf, HTTP_SERVICE_UNAVAILABLE, connect_errno, 
                                   apr_pstrcat(r->pool, APLOGNO(02833) "ScriptSock ", sockname, " does not exist", NULL));
        }

        /* gotta try again, but make sure the cgid daemon is still around */
        if (connect_errno != ENOENT && kill(daemon_pid, 0) != 0) {
            return log_scripterror(r, conf, HTTP_SERVICE_UNAVAILABLE, connect_errno, APLOGNO(01258)
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

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(e);
         e = APR_BRIGADE_FIRST(bb))
    {
        if (apr_bucket_read(e, &buf, &len, APR_BLOCK_READ)) {
            break;
        }
        apr_bucket_delete(e);
    }
}

/****************************************************************
 *
 * Actual cgid handling...
 */

struct cleanup_script_info {
    request_rec *r;
    cgid_server_conf *conf;
    pid_t pid;
};

static apr_status_t dead_yet(pid_t pid, apr_interval_time_t max_wait)
{
    apr_interval_time_t interval = 10000; /* 10 ms */
    apr_interval_time_t total = 0;

    do {
#ifdef _AIX
        /* On AIX, for processes like mod_cgid's script children where
         * SIGCHLD is ignored, kill(pid,0) returns success for up to
         * one second after the script child exits, based on when a
         * daemon runs to clean up unnecessary process table entries.
         * getpgid() can report the proper info (-1/ESRCH) immediately.
         */
        if (getpgid(pid) < 0) {
#else
        if (kill(pid, 0) < 0) {
#endif
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
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01259)
                  "CGI process %" APR_PID_T_FMT " didn't exit, sending SIGKILL",
                  pid);
    kill(pid, SIGKILL);
    if (dead_yet(pid, apr_time_from_sec(3)) == APR_SUCCESS) {
        return APR_SUCCESS;
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01260)
                  "CGI process %" APR_PID_T_FMT " didn't exit, sending SIGKILL again",
                  pid);
    kill(pid, SIGKILL);

    return APR_EGENERAL;
}

static apr_status_t get_cgi_pid(request_rec *r,  cgid_server_conf *conf, pid_t *pid) { 
    cgid_req_t req = {0};
    apr_status_t stat;
    int rc, sd;

    rc = connect_to_daemon(&sd, r, conf);
    if (rc != OK) {
        return APR_EGENERAL;
    }

    req.req_type = GETPID_REQ;
    req.ppid = parent_pid;
    req.conn_id = r->connection->id;

    stat = sock_write(sd, &req, sizeof(req));
    if (stat != APR_SUCCESS) {
        return stat;
    }

    /* wait for pid of script */
    stat = sock_read(sd, pid, sizeof(*pid));
    if (stat != APR_SUCCESS) {
        return stat;
    }

    if (pid == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01261)
                      "daemon couldn't find CGI process for connection %lu",
                      r->connection->id);
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}


static apr_status_t cleanup_script(void *vptr)
{
    struct cleanup_script_info *info = vptr;
    return cleanup_nonchild_process(info->r, info->pid);
}

static int cgid_handler(request_rec *r)
{
    int retval, nph, dbpos;
    char *argv0, *dbuf;
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
    cgid_dirconf *dc;

    if (strcmp(r->handler, CGI_MAGIC_TYPE) && strcmp(r->handler, "cgi-script")) {
        return DECLINED;
    }

    conf = ap_get_module_config(r->server->module_config, &cgid_module);
    dc = ap_get_module_config(r->per_dir_config, &cgid_module);

    
    is_included = !strcmp(r->protocol, "INCLUDED");

    if ((argv0 = strrchr(r->filename, '/')) != NULL) {
        argv0++;
    }
    else {
        argv0 = r->filename;
    }

    nph = !(strncmp(argv0, "nph-", 4));

    argv0 = r->filename;

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r)) {
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(01262)
                "Options ExecCGI is off in this directory");
    }

    if (nph && is_included) {
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(01263)
                "attempt to include NPH CGI script");
    }

#if defined(OS2) || defined(WIN32)
#error mod_cgid does not work on this platform.  If you teach it to, look
#error at mod_cgi.c for required code in this path.
#else
    if (r->finfo.filetype == APR_NOFILE) {
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, APLOGNO(01264)
                "script not found or unable to stat");
    }
#endif
    if (r->finfo.filetype == APR_DIR) {
        return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(01265)
                "attempt to invoke directory as script");
    }

    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info)
    {
        /* default to accept */
        return log_scripterror(r, conf, HTTP_NOT_FOUND, 0, APLOGNO(01266)
                               "AcceptPathInfo off disallows user's path");
    }
    /*
    if (!ap_suexec_enabled) {
        if (!ap_can_exec(&r->finfo))
            return log_scripterror(r, conf, HTTP_FORBIDDEN, 0, APLOGNO(01267)
                                   "file permissions deny server execution");
    }
    */

    /*
     * httpd core function used to add common environment variables like
     * DOCUMENT_ROOT. 
     */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    env = ap_create_environment(r->pool, r->subprocess_env);

    if ((retval = connect_to_daemon(&sd, r, conf)) != OK) {
        return retval;
    }

    rv = send_req(sd, r, argv0, env, CGI_REQ);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01268)
                     "write to cgi daemon process");
    }

    info = apr_palloc(r->pool, sizeof(struct cleanup_script_info));
    info->conf = conf;
    info->r = r;
    rv = get_cgi_pid(r, conf, &(info->pid));

    if (APR_SUCCESS == rv){  
        apr_pool_cleanup_register(r->pool, info,
                              cleanup_script,
                              apr_pool_cleanup_null);
    }
    else { 
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, "error determining cgi PID");
    }

    /* We are putting the socket discriptor into an apr_file_t so that we can
     * use a pipe bucket to send the data to the client.  APR will create
     * a cleanup for the apr_file_t which will close the socket, so we'll
     * get rid of the cleanup we registered when we created the socket.
     */

    apr_os_pipe_put_ex(&tempsock, &sd, 1, r->pool);
    if (dc->timeout > 0) { 
        apr_file_pipe_timeout_set(tempsock, dc->timeout);
    }
    else { 
        apr_file_pipe_timeout_set(tempsock, r->server->timeout);
    }
    apr_pool_cleanup_kill(r->pool, (void *)((long)sd), close_unix_socket);

    /* Transfer any put/post args, CERN style...
     * Note that we already ignore SIGPIPE in the core server.
     */
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    seen_eos = 0;
    child_stopped_reading = 0;
    dbuf = NULL;
    dbpos = 0;
    if (conf->logname) {
        dbuf = apr_palloc(r->pool, conf->bufbytes + 1);
    }
    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01270)
                          "Error reading request entity data");
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
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
            rv = apr_file_write_full(tempsock, data, len, NULL);

            if (rv != APR_SUCCESS) {
                /* silly script stopped reading, soak up remaining message */
                child_stopped_reading = 1;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,  APLOGNO(02651)
                              "Error writing request body to script %s", 
                              r->filename);

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
        conn_rec *c = r->connection;
        const char *location;
        char sbuf[MAX_STRING_LEN];
        int ret;

        bb = apr_brigade_create(r->pool, c->bucket_alloc);
        b = apr_bucket_pipe_create(tempsock, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        b = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        if ((ret = ap_scan_script_header_err_brigade_ex(r, bb, sbuf,
                                                        APLOG_MODULE_INDEX)))
        {
            ret = log_script(r, conf, ret, dbuf, sbuf, bb, NULL);

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

        if (location && location[0] == '/' && r->status == 200) {

            /* Soak up all the script output */
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            /* This redirect needs to be a GET no matter what the original
             * method was.
             */
            r->method = "GET";
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
            /* XXX: Note that if a script wants to produce its own Redirect
             * body, it now has to explicitly *say* "Status: 302"
             */
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            return HTTP_MOVED_TEMPORARILY;
        }

        rv = ap_pass_brigade(r->output_filters, bb);
        if (rv != APR_SUCCESS) { 
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                          "Failed to flush CGI output to client");
        }
    }

    if (nph) {
        conn_rec *c = r->connection;
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

/* This is the special environment used for running the "exec cmd="
 *   variety of SSI directives.
 */
static void add_ssi_vars(request_rec *r)
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

static int include_cmd(include_ctx_t *ctx, ap_filter_t *f,
                       apr_bucket_brigade *bb, char *command)
{
    char **env;
    int sd;
    int retval;
    apr_file_t *tempsock = NULL;
    request_rec *r = f->r;
    cgid_server_conf *conf = ap_get_module_config(r->server->module_config,
                                                  &cgid_module);
    cgid_dirconf *dc = ap_get_module_config(r->per_dir_config, &cgid_module);

    struct cleanup_script_info *info;
    apr_status_t rv;

    add_ssi_vars(r);
    env = ap_create_environment(r->pool, r->subprocess_env);

    if ((retval = connect_to_daemon(&sd, r, conf)) != OK) {
        return retval;
    }

    send_req(sd, r, command, env, SSI_REQ);

    info = apr_palloc(r->pool, sizeof(struct cleanup_script_info));
    info->conf = conf;
    info->r = r;
    rv = get_cgi_pid(r, conf, &(info->pid));
    if (APR_SUCCESS == rv) {             
        /* for this type of request, the script is invoked through an
         * intermediate shell process...  cleanup_script is only able
         * to knock out the shell process, not the actual script
         */
        apr_pool_cleanup_register(r->pool, info,
                                  cleanup_script,
                                  apr_pool_cleanup_null);
    }
    else { 
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, "error determining cgi PID (for SSI)");
    }

    apr_pool_cleanup_register(r->pool, info,
                              cleanup_script,
                              apr_pool_cleanup_null);

    /* We are putting the socket discriptor into an apr_file_t so that we can
     * use a pipe bucket to send the data to the client.  APR will create
     * a cleanup for the apr_file_t which will close the socket, so we'll
     * get rid of the cleanup we registered when we created the socket.
     */
    apr_os_pipe_put_ex(&tempsock, &sd, 1, r->pool);
    if (dc->timeout > 0) {
        apr_file_pipe_timeout_set(tempsock, dc->timeout);
    }
    else {
        apr_file_pipe_timeout_set(tempsock, r->server->timeout);
    }

    apr_pool_cleanup_kill(r->pool, (void *)((long)sd), close_unix_socket);

    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pipe_create(tempsock,
                            f->c->bucket_alloc));
    ctx->flush_now = 1;

    return APR_SUCCESS;
}

static apr_status_t handle_exec(include_ctx_t *ctx, ap_filter_t *f,
                                apr_bucket_brigade *bb)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    request_rec *r = f->r;
    char *file = r->filename;
    char parsed_string[MAX_STRING_LEN];

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK,
                      (ctx->flags & SSI_FLAG_PRINTING)
                          ? APLOG_ERR : APLOG_WARNING,
                      0, r, APLOGNO(03196)
                      "missing argument for exec element in %s", r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    if (ctx->flags & SSI_FLAG_NO_EXEC) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01271) "exec used but not allowed "
                      "in %s", r->filename);
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    while (1) {
        cgid_pfn_gtv(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        if (!strcmp(tag, "cmd")) {
            apr_status_t rv;

            cgid_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string),
                        SSI_EXPAND_LEAVE_NAME);

            rv = include_cmd(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01272)
                              "execution failure for parameter \"%s\" "
                              "to tag exec in file %s", tag, r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else if (!strcmp(tag, "cgi")) {
            apr_status_t rv;

            cgid_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string),
                        SSI_EXPAND_DROP_NAME);

            rv = include_cgi(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01273) "invalid CGI ref "
                              "\"%s\" in %s", tag_val, file);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01274) "unknown parameter "
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


static void register_hook(apr_pool_t *p)
{
    static const char * const aszPre[] = { "mod_include.c", NULL };

    ap_hook_pre_config(cgid_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(cgid_init, aszPre, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(cgid_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(cgid) = {
    STANDARD20_MODULE_STUFF,
    create_cgid_dirconf, /* dir config creater */
    NULL, /* dir merger --- default is to override */
    create_cgid_config, /* server config */
    merge_cgid_config, /* merge server config */
    cgid_cmds, /* command table */
    register_hook /* register_handlers */
};

