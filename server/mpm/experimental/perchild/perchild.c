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

#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_portable.h"
#include "apr_file_io.h"
#include "apr_signal.h"

#define APR_WANT_IOVEC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if !APR_HAS_THREADS
#error The perchild MPM requires APR threads, but they are unavailable.
#endif  

#define CORE_PRIVATE 
 
#include "ap_config.h"
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"    /* for read_config */ 
#include "http_core.h"      /* for get_remote_host */ 
#include "http_protocol.h"
#include "http_connection.h"
#include "ap_mpm.h"
#include "unixd.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "mpm_default.h"
#include "mpm.h"
#include "scoreboard.h"
#include "util_filter.h"
#include "apr_poll.h"

#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

/* ### should be APR-ized */
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <setjmp.h>
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h> /* for bindprocessor() */
#endif

/*
 * Define some magic numbers that we use for the state of the incomming
 * request. These must be < 0 so they don't collide with a file descriptor.
 */
#define AP_PERCHILD_THISCHILD -1
#define AP_PERCHILD_OTHERCHILD -2

/* Limit on the threads per process.  Clients will be locked out if more than
 * this * server_limit are needed.
 *
 * We keep this for one reason it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef DEFAULT_THREAD_LIMIT
#define DEFAULT_THREAD_LIMIT 64 
#endif

/* Admin can't tune ThreadLimit beyond MAX_THREAD_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_THREAD_LIMIT
#define MAX_THREAD_LIMIT 20000
#endif 

/* Limit on the total --- clients will be locked out if more servers than
 * this are needed.  It is intended solely to keep the server from crashing
 * when things get out of hand.
 *
 * We keep a hard maximum number of servers, for two reasons --- first off,
 * in case something goes seriously wrong, we want to stop the fork bomb
 * short of actually crashing the machine we're running on by filling some
 * kernel table.  Secondly, it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef DEFAULT_SERVER_LIMIT
#define DEFAULT_SERVER_LIMIT 8 
#endif

/* Admin can't tune ServerLimit beyond MAX_SERVER_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_SERVER_LIMIT
#define MAX_SERVER_LIMIT 20000
#endif

/*
 * Actual definitions of config globals
 */

static int threads_to_start = 0;         /* Worker threads per child */
static int min_spare_threads = 0;
static int max_spare_threads = 0;
static int max_threads = 0;
static int server_limit = DEFAULT_SERVER_LIMIT;
static int first_server_limit;
static int thread_limit = DEFAULT_THREAD_LIMIT;
static int first_thread_limit;
static int changed_limit_at_restart;
static int num_daemons = 0;
static int curr_child_num = 0;
static int workers_may_exit = 0;
static int requests_this_child;
static int num_listensocks = 0;
static ap_pod_t *pod;
static jmp_buf jmpbuffer;

struct child_info_t {
    uid_t uid;
    gid_t gid;
    int input;       /* The socket descriptor */
    int output;      /* The socket descriptor */
};

typedef struct {
    const char *sockname;       /* The base name for the socket */
    const char *fullsockname;   /* socket base name + extension */
    int        input;           /* The socket descriptor */
    int        output;          /* The socket descriptor */
} perchild_server_conf;

typedef struct child_info_t child_info_t;

/* Tables used to determine the user and group each child process should
 * run as.  The hash table is used to correlate a server name with a child
 * process.
 */
static child_info_t *child_info_table;
static int          *thread_socket_table;
struct ap_ctable    *ap_child_table;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with NumServers changes across AP_SIG_GRACEFUL restarts.  We 
 * use this value to optimize routines that have to scan the entire child 
 * table.
 *
 * XXX - It might not be worth keeping this code in. There aren't very
 * many child processes in this MPM.
 */
int ap_max_daemons_limit = -1;
int ap_threads_per_child; /* XXX not part of API!  axe it! */

module AP_MODULE_DECLARE_DATA mpm_perchild_module;

static apr_file_t *pipe_of_death_in = NULL;
static apr_file_t *pipe_of_death_out = NULL;
static apr_thread_mutex_t *pipe_of_death_mutex;

/* *Non*-shared http_main globals... */

server_rec *ap_server_conf;

/* one_process --- debugging mode variable; can be set from the command line
 * with the -X flag.  If set, this gets you the child_main loop running
 * in the process which originally started up (no detach, no make_child),
 * which is a pretty nice debugging environment.  (You'll get a SIGHUP
 * early in standalone_main; just continue through.  This is the server
 * trying to kill off any child processes which it might have lying
 * around --- Apache doesn't keep track of their pids, it just sends
 * SIGHUP to the process group, ignoring it in the root process.
 * Continue through and you'll be fine.).
 */

static int one_process = 0;

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

static apr_pool_t *pconf;              /* Pool for config stuff */
static apr_pool_t *pchild;             /* Pool for httpd child stuff */
static apr_pool_t *thread_pool_parent; /* Parent of per-thread pools */
static apr_thread_mutex_t *thread_pool_parent_mutex;

static int child_num;
static unsigned int my_pid; /* Linux getpid() doesn't work except in 
                      main thread. Use this instead */
/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static apr_thread_mutex_t *worker_thread_count_mutex;
static int *worker_thread_free_ids;
static apr_threadattr_t *worker_thread_attr;

/* Keep track of the number of idle worker threads */
static int idle_thread_count;
static apr_thread_mutex_t *idle_thread_count_mutex;

/* Locks for accept serialization */
#ifdef NO_SERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) APR_SUCCESS
#else
#define SAFE_ACCEPT(stmt) (stmt)
static apr_proc_mutex_t *process_accept_mutex;
#endif /* NO_SERIALIZED_ACCEPT */
static apr_thread_mutex_t *thread_accept_mutex;

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_max_daemons_limit;
            return APR_SUCCESS;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_DYNAMIC;
            return APR_SUCCESS;
        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_STATIC;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = server_limit;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = thread_limit;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_THREADS:
            *result = max_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:    
            *result = min_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = max_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS; 
        case AP_MPMQ_MAX_DAEMONS:
            *result = num_daemons;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code)
{
    if (pchild) {
        apr_pool_destroy(pchild);
    }
    exit(code);
}

static void just_die(int sig)
{
    clean_child_exit(0);
}

/*****************************************************************
 * Connection structures and accounting...
 */

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
static int volatile child_fatal;
/* we don't currently track ap_my_generation, but mod_status 
 * references it so it must be defined */
ap_generation_t volatile ap_my_generation=0;

/*
 * ap_start_shutdown() and ap_start_restart(), below, are a first stab at
 * functions to initiate shutdown or restart without relying on signals. 
 * Previously this was initiated in sig_term() and restart() signal handlers, 
 * but we want to be able to start a shutdown/restart from other sources --
 * e.g. on Win32, from the service manager. Now the service manager can
 * call ap_start_shutdown() or ap_start_restart() as appropiate.  Note that
 * these functions can also be called by the child processes, since global
 * variables are no longer used to pass on the required action to the parent.
 *
 * These should only be called from the parent process itself, since the
 * parent process will use the shutdown_pending and restart_pending variables
 * to determine whether to shutdown or restart. The child process should
 * call signal_parent() directly to tell the parent to die -- this will
 * cause neither of those variable to be set, which the parent will
 * assume means something serious is wrong (which it will be, for the
 * child to force an exit) and so do an exit anyway.
 */

static void ap_start_shutdown(void)
{
    if (shutdown_pending == 1) {
        /* Um, is this _probably_ not an error, if the user has
         * tried to do a shutdown twice quickly, so we won't
         * worry about reporting it.
         */
        return;
    }
    shutdown_pending = 1;
}

/* do a graceful restart if graceful == 1 */
static void ap_start_restart(int graceful)
{

    if (restart_pending == 1) {
        /* Probably not an error - don't bother reporting it */
        return;
    }
    restart_pending = 1;
    is_graceful = graceful;
}

static void sig_term(int sig)
{
    ap_start_shutdown();
}

static void restart(int sig)
{
#ifndef WIN32
    ap_start_restart(sig == AP_SIG_GRACEFUL);
#else
    ap_start_restart(1);
#endif
}

static void set_signals(void)
{
#ifndef NO_USE_SIGACTION
    struct sigaction sa;
#endif

    if (!one_process) {
        ap_fatal_signal_setup(ap_server_conf, pconf);
    }

#ifndef NO_USE_SIGACTION
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(SIGTERM)");
#ifdef SIGINT
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(SIGINT)");
#endif
#ifdef SIGXCPU
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXCPU, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(SIGXCPU)");
#endif
#ifdef SIGXFSZ
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXFSZ, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(SIGXFSZ)");
#endif
#ifdef SIGPIPE
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(SIGPIPE)");
#endif

    /* we want to ignore HUPs and AP_SIG_GRACEFUL while we're busy 
     * processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, AP_SIG_GRACEFUL);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(SIGHUP)");
    if (sigaction(AP_SIG_GRACEFUL, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                     "sigaction(" AP_SIG_GRACEFUL_STRING ")");
#else
    if (!one_process) {
#ifdef SIGXCPU
        apr_signal(SIGXCPU, SIG_DFL);
#endif /* SIGXCPU */
#ifdef SIGXFSZ
        apr_signal(SIGXFSZ, SIG_DFL);
#endif /* SIGXFSZ */
    }

    apr_signal(SIGTERM, sig_term);
#ifdef SIGHUP
    apr_signal(SIGHUP, restart);
#endif /* SIGHUP */
#ifdef AP_SIG_GRACEFUL
    apr_signal(AP_SIG_GRACEFUL, restart);
#endif /* AP_SIG_GRACEFUL */
#ifdef SIGPIPE
    apr_signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
}

/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

int ap_graceful_stop_signalled(void)
{
    /* XXX - Does this really work? - Manoj */
    return is_graceful;
}

/*****************************************************************
 * Child process main loop.
 */

static void process_socket(apr_pool_t *p, apr_socket_t *sock, long conn_id,
                           apr_bucket_alloc_t *bucket_alloc)
{
    conn_rec *current_conn;
    int csd;
    apr_status_t rv;
    int thread_num = conn_id % thread_limit;
    ap_sb_handle_t *sbh;

    if ((rv = apr_os_sock_get(&csd, sock)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, "apr_os_sock_get");
    }

    if (csd >= FD_SETSIZE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                     "new file descriptor %d is too large; you probably need "
                     "to rebuild Apache with a larger FD_SETSIZE "
                     "(currently %d)", 
                     csd, FD_SETSIZE);
        apr_socket_close(sock);
        return;
    }

    if (thread_socket_table[thread_num] < 0) {
        ap_sock_disable_nagle(sock);
    }

    ap_create_sb_handle(&sbh, p, conn_id / thread_limit, thread_num);
    current_conn = ap_run_create_connection(p, ap_server_conf, sock, conn_id, 
                                            sbh, bucket_alloc);
    if (current_conn) {
        ap_process_connection(current_conn, sock);
        ap_lingering_close(current_conn);
    }
}

static int perchild_process_connection(conn_rec *c)
{
    ap_filter_t *f;
    apr_bucket_brigade *bb;
    core_net_rec *net;

    apr_pool_userdata_get((void **)&bb, "PERCHILD_SOCKETS", c->pool);
    if (bb != NULL) {
        for (f = c->output_filters; f != NULL; f = f->next) {
            if (!strcmp(f->frec->name, "core")) {
                break;
            }
        }
        if (f != NULL) {
            net = f->ctx;
            net->in_ctx = apr_palloc(c->pool, sizeof(*net->in_ctx));
            net->in_ctx->b = bb;
        }
    }
    return DECLINED;
}
    

static void *worker_thread(apr_thread_t *, void *);

/* Starts a thread as long as we're below max_threads */
static int start_thread(void)
{
    apr_thread_t *thread;
    int rc;

    apr_thread_mutex_lock(worker_thread_count_mutex);
    if (worker_thread_count < max_threads - 1) {
        rc = apr_thread_create(&thread, worker_thread_attr, worker_thread,
                 &worker_thread_free_ids[worker_thread_count], pchild);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, rc, ap_server_conf,
                         "apr_thread_create: unable to create worker thread");
            /* In case system resources are maxxed out, we don't want
               Apache running away with the CPU trying to fork over and
               over and over again if we exit. */
            sleep(10);
            workers_may_exit = 1;
            apr_thread_mutex_unlock(worker_thread_count_mutex);
            return 0;
        }
        else {
            worker_thread_count++;
        }
    }
    else {
        static int reported = 0;
        
        if (!reported) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                         ap_server_conf,
                         "server reached MaxThreadsPerChild setting, "
                         "consider raising the MaxThreadsPerChild or "
                         "NumServers settings");
            reported = 1;
        }
        apr_thread_mutex_unlock(worker_thread_count_mutex);
        return 0;
    }
    apr_thread_mutex_unlock(worker_thread_count_mutex);
    return 1;

}

/* Sets workers_may_exit if we received a character on the pipe_of_death */
static apr_status_t check_pipe_of_death(void **csd, ap_listen_rec *lr,
                                        apr_pool_t *ptrans)
{
    apr_thread_mutex_lock(pipe_of_death_mutex);
    if (!workers_may_exit) {
        int ret;
        char pipe_read_char;
        apr_size_t n = 1;

        ret = apr_socket_recv(lr->sd, &pipe_read_char, &n);
        if (APR_STATUS_IS_EAGAIN(ret)) {
            /* It lost the lottery. It must continue to suffer
             * through a life of servitude. */
        }
        else {
            /* It won the lottery (or something else is very
             * wrong). Embrace death with open arms. */
            workers_may_exit = 1;
        }
    }
    apr_thread_mutex_unlock(pipe_of_death_mutex);
    return APR_SUCCESS;
}

static apr_status_t receive_from_other_child(void **csd, ap_listen_rec *lr,
                                             apr_pool_t *ptrans)
{
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buffer[HUGE_STRING_LEN * 2], *headers, *body;
    int headerslen, bodylen;
    struct iovec iov;
    int ret, dp;
    apr_os_sock_t sd;
    apr_bucket_alloc_t *alloc = apr_bucket_alloc_create(ptrans);
    apr_bucket_brigade *bb = apr_brigade_create(ptrans, alloc);
    apr_bucket *bucket;

    apr_os_sock_get(&sd, lr->sd);

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    cmsg = apr_palloc(ptrans, sizeof(*cmsg) + sizeof(sd));
    cmsg->cmsg_len = sizeof(*cmsg) + sizeof(sd);
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;

    ret = recvmsg(sd, &msg, 0);

    memcpy(&dp, CMSG_DATA(cmsg), sizeof(dp));

    *csd = NULL; /* tell apr_os_sock_put() to allocate new apr_socket_t */
    apr_os_sock_put((apr_socket_t **)csd, &dp, ptrans);

    bucket = apr_bucket_eos_create(alloc);
    APR_BRIGADE_INSERT_HEAD(bb, bucket);
    bucket = apr_bucket_socket_create(*csd, alloc);
    APR_BRIGADE_INSERT_HEAD(bb, bucket);

    body = strchr(iov.iov_base, 0);
    if (!body) {
        return 1;
    }

    body++;
    bodylen = strlen(body);

    headers = iov.iov_base;
    headerslen = body - headers;

    bucket = apr_bucket_heap_create(body, bodylen, NULL, alloc);
    APR_BRIGADE_INSERT_HEAD(bb, bucket);
    bucket = apr_bucket_heap_create(headers, headerslen, NULL, alloc);
    APR_BRIGADE_INSERT_HEAD(bb, bucket);

    apr_pool_userdata_set(bb, "PERCHILD_SOCKETS", NULL, ptrans);

    return 0;
}

/* idle_thread_count should be incremented before starting a worker_thread */

static void *worker_thread(apr_thread_t *thd, void *arg)
{
    void *csd;
    apr_pool_t *tpool;      /* Pool for this thread           */
    apr_pool_t *ptrans;     /* Pool for per-transaction stuff */
    volatile int thread_just_started = 1;
    int srv;
    int thread_num = *((int *) arg);
    long conn_id = child_num * thread_limit + thread_num;
    apr_pollfd_t *pollset;
    apr_status_t rv;
    ap_listen_rec *lr, *last_lr = ap_listeners;
    int n;
    apr_bucket_alloc_t *bucket_alloc;

    apr_thread_mutex_lock(thread_pool_parent_mutex);
    apr_pool_create(&tpool, thread_pool_parent);
    apr_thread_mutex_unlock(thread_pool_parent_mutex);
    apr_pool_create(&ptrans, tpool);

    (void) ap_update_child_status_from_indexes(child_num, thread_num, 
                                               SERVER_STARTING,
                                               (request_rec *) NULL);

    bucket_alloc = apr_bucket_alloc_create(apr_thread_pool_get(thd));

    apr_poll_setup(&pollset, num_listensocks, tpool);
    for(lr = ap_listeners; lr != NULL; lr = lr->next) {
        int fd;
        apr_poll_socket_add(pollset, lr->sd, APR_POLLIN);

        apr_os_sock_get(&fd, lr->sd);
    }

    while (!workers_may_exit) {
        workers_may_exit |= ((ap_max_requests_per_child != 0)
                            && (requests_this_child <= 0));
        if (workers_may_exit) break;
        if (!thread_just_started) {
            apr_thread_mutex_lock(idle_thread_count_mutex);
            if (idle_thread_count < max_spare_threads) {
                idle_thread_count++;
                apr_thread_mutex_unlock(idle_thread_count_mutex);
            }
            else {
                apr_thread_mutex_unlock(idle_thread_count_mutex);
                break;
            }
        }
        else {
            thread_just_started = 0;
        }

        (void) ap_update_child_status_from_indexes(child_num, thread_num, 
                                                   SERVER_READY,
                                                   (request_rec *) NULL);

        apr_thread_mutex_lock(thread_accept_mutex);
        if (workers_may_exit) {
            apr_thread_mutex_unlock(thread_accept_mutex);
            break;
        }
        if ((rv = SAFE_ACCEPT(apr_proc_mutex_lock(process_accept_mutex)))
            != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                         "apr_proc_mutex_lock failed. Attempting to shutdown "
                         "process gracefully.");
            workers_may_exit = 1;
        }

        while (!workers_may_exit) {
            apr_int16_t event;
            srv = apr_poll(pollset, num_listensocks, &n, -1);

            if (srv != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(srv)) {
                    continue;
                }

                /* apr_poll() will only return errors in catastrophic
                 * circumstances. Let's try exiting gracefully, for now. */
                ap_log_error(APLOG_MARK, APLOG_ERR, srv, (const server_rec *)
                             ap_server_conf, "apr_poll: (listen)");
                workers_may_exit = 1;
            }
            if (workers_may_exit) break;

            /* find a listener */
            lr = last_lr;
            do {
                lr = lr->next;
                if (lr == NULL) {
                    lr = ap_listeners;
                }
                /* XXX: Should we check for POLLERR? */
                apr_poll_revents_get(&event, lr->sd, pollset);
                if (event & (APR_POLLIN)) {
                    last_lr = lr;
                    goto got_fd;
                }
            } while (lr != last_lr);
        }
    got_fd:
        if (!workers_may_exit) {
            rv = lr->accept_func(&csd, lr, ptrans);
            if (rv == APR_EGENERAL) {
                /* E[NM]FILE, ENOMEM, etc */
                workers_may_exit = 1;
            }
            if ((rv = SAFE_ACCEPT(apr_proc_mutex_unlock(process_accept_mutex)))
                != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "apr_proc_mutex_unlock failed. Attempting to shutdown "
                             "process gracefully.");
                workers_may_exit = 1;
            }
            apr_thread_mutex_unlock(thread_accept_mutex);
            apr_thread_mutex_lock(idle_thread_count_mutex);
            if (idle_thread_count > min_spare_threads) {
                idle_thread_count--;
            }
            else {
                if (!start_thread()) {
                    idle_thread_count--;
                }
            }
            apr_thread_mutex_unlock(idle_thread_count_mutex);
            if (setjmp(jmpbuffer) != 1) {
                process_socket(ptrans, csd, conn_id, bucket_alloc);
            }
            else {
                thread_socket_table[thread_num] = AP_PERCHILD_THISCHILD;
            }  
            requests_this_child--;
        }
        else {
            if ((rv = SAFE_ACCEPT(apr_proc_mutex_unlock(process_accept_mutex)))
                != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "apr_proc_mutex_unlock failed. Attempting to shutdown "
                             "process gracefully.");
                workers_may_exit = 1;
            }
            apr_thread_mutex_unlock(thread_accept_mutex);
            apr_thread_mutex_lock(idle_thread_count_mutex);
            idle_thread_count--;
            apr_thread_mutex_unlock(idle_thread_count_mutex);
        break;
        }
        apr_pool_clear(ptrans);
    }

    apr_thread_mutex_lock(thread_pool_parent_mutex);
    ap_update_child_status_from_indexes(child_num, thread_num, SERVER_DEAD,
                                        (request_rec *) NULL);
    apr_pool_destroy(tpool);
    apr_thread_mutex_unlock(thread_pool_parent_mutex);
    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count--;
    worker_thread_free_ids[worker_thread_count] = thread_num;
    if (worker_thread_count == 0) {
        /* All the threads have exited, now finish the shutdown process
         * by signalling the sigwait thread */
        kill(my_pid, SIGTERM);
    }
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    apr_bucket_alloc_destroy(bucket_alloc);

    return NULL;
}



/* Set group privileges.
 *
 * Note that we use the username as set in the config files, rather than
 * the lookup of to uid --- the same uid may have multiple passwd entries,
 * with different sets of groups for each.
 */

static int set_group_privs(uid_t uid, gid_t gid)
{
    if (!geteuid()) {
        const char *name;

        /* Get username if passed as a uid */

        struct passwd *ent;

        if ((ent = getpwuid(uid)) == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "getpwuid: couldn't determine user name from uid %u, "
                         "you probably need to modify the User directive",
                         (unsigned)uid);
            return -1;
        }

        name = ent->pw_name;

        /*
         * Set the GID before initgroups(), since on some platforms
         * setgid() is known to zap the group list.
         */
        if (setgid(gid) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "setgid: unable to set group id to Group %u",
                         (unsigned)gid);
            return -1;
        }

        /* Reset `groups' attributes. */

        if (initgroups(name, gid) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                         "initgroups: unable to set groups for User %s "
                         "and Group %u", name, (unsigned)gid);
            return -1;
        }
    }
    return 0;
}


static int perchild_setup_child(int childnum)
{
    child_info_t *ug = &child_info_table[childnum];

    if (ug->uid == -1 && ug->gid == -1) {
        return unixd_setup_child();
    }
    if (set_group_privs(ug->uid, ug->gid)) {
        return -1;
    }
    /* Only try to switch if we're running as root */
    if (!geteuid()
        && (
#ifdef _OSD_POSIX
            os_init_job_environment(server_conf, unixd_config.user_name,
                                    one_process) != 0 ||
#endif
            setuid(ug->uid) == -1)) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                     "setuid: unable to change to uid: %ld",
                     (long) ug->uid);
        return -1;
    }
    return 0;
}

static int check_signal(int signum)
{
    switch (signum) {
    case SIGTERM:
    case SIGINT:
        just_die(signum);
        return 1;
    }
    return 0;
}                                                                               

typedef struct perchild_header {
    char *headers;
    apr_pool_t *p;
} perchild_header;

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to table_do(), so their interfaces are co-dependent.
 * In other words, don't change this one without checking table_do in alloc.c.
 * It returns true unless there was a write error of some kind.
 */
static int perchild_header_field(perchild_header *h,
                             const char *fieldname, const char *fieldval)
{
    apr_pstrcat(h->p, h->headers, fieldname, ": ", fieldval, CRLF, NULL); 
    return 1;
}


static void child_main(int child_num_arg)
{
    int i;
    apr_status_t rv;
    apr_socket_t *sock = NULL;
    ap_listen_rec *lr;
    
    my_pid = getpid();
    ap_fatal_signal_child_setup(ap_server_conf);
    child_num = child_num_arg;
    apr_pool_create(&pchild, pconf);

    for (lr = ap_listeners ; lr->next != NULL; lr = lr->next) {
        continue;
    }

    apr_os_sock_put(&sock, &child_info_table[child_num].input, pconf);
    lr->next = apr_palloc(pconf, sizeof(*lr));
    lr->next->sd = sock;
    lr->next->active = 1;
    lr->next->accept_func = receive_from_other_child;
    lr->next->next = NULL;
    lr = lr->next;
    num_listensocks++;

    /*stuff to do before we switch id's, so we have permissions.*/

    rv = SAFE_ACCEPT(apr_proc_mutex_child_init(&process_accept_mutex, 
                                               ap_lock_fname, pchild));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                     "Couldn't initialize cross-process lock in child");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (perchild_setup_child(child_num)) {
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_run_child_init(pchild, ap_server_conf);

    /*done with init critical section */

    apr_setup_signal_thread();

    requests_this_child = ap_max_requests_per_child;
    

    /* Setup worker threads */

    if (threads_to_start > max_threads) {
        threads_to_start = max_threads;
    }
    idle_thread_count = threads_to_start;
    worker_thread_count = 0;
    worker_thread_free_ids = (int *)apr_pcalloc(pchild, thread_limit * sizeof(int));
    for (i = 0; i < max_threads; i++) {
        worker_thread_free_ids[i] = i;
    }
    apr_pool_create(&thread_pool_parent, pchild);
    apr_thread_mutex_create(&thread_pool_parent_mutex, 
                    APR_THREAD_MUTEX_DEFAULT, pchild);
    apr_thread_mutex_create(&idle_thread_count_mutex, 
                    APR_THREAD_MUTEX_DEFAULT, pchild);
    apr_thread_mutex_create(&worker_thread_count_mutex,
                    APR_THREAD_MUTEX_DEFAULT, pchild);
    apr_thread_mutex_create(&pipe_of_death_mutex,
                    APR_THREAD_MUTEX_DEFAULT, pchild);
    apr_thread_mutex_create(&thread_accept_mutex,
                    APR_THREAD_MUTEX_DEFAULT, pchild);

    apr_threadattr_create(&worker_thread_attr, pchild);
    apr_threadattr_detach_set(worker_thread_attr, 1);                                     

    /* We are creating worker threads right now */
    for (i=0; i < threads_to_start; i++) {
        /* start_thread shouldn't fail here */
        if (!start_thread()) {
            break;
        }
    }

    apr_signal_thread(check_signal);
}

static int make_child(server_rec *s, int slot)
{
    int pid;

    if (slot + 1 > ap_max_daemons_limit) {
        ap_max_daemons_limit = slot + 1;
    }

    if (one_process) {
        set_signals();
        ap_child_table[slot].pid = getpid();
        ap_child_table[slot].status = SERVER_ALIVE;
        child_main(slot);
    }
    (void) ap_update_child_status_from_indexes(slot, 0, SERVER_STARTING,
                                               (request_rec *) NULL);

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "fork: Unable to fork new process");
        /* In case system resources are maxxed out, we don't want
         * Apache running away with the CPU trying to fork over and
         * over and over again. */
        sleep(10);

        return -1;
    }

    if (!pid) {
#ifdef HAVE_BINDPROCESSOR
        /* By default, AIX binds to a single processor.  This bit unbinds
         * children which will then bind to another CPU.
         */
        int status = bindprocessor(BINDPROCESS, (int)getpid(),
                                   PROCESSOR_CLASS_ANY);
        if (status != OK) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, 
                         ap_server_conf, "processor unbind failed %d", status);
        }
#endif

        RAISE_SIGSTOP(MAKE_CHILD);

        /* XXX - For an unthreaded server, a signal handler will be necessary
         * apr_signal(SIGTERM, just_die);
         */
        child_main(slot);
        clean_child_exit(0);
    }
    /* else */
    ap_child_table[slot].pid = pid;
    ap_child_table[slot].status = SERVER_ALIVE;

    return 0;
}

/* start up a bunch of children */
static int startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < num_daemons; ++i) {
        if (ap_child_table[i].pid) {
            continue;
        }
        if (make_child(ap_server_conf, i) < 0) {
            break;
        }
        --number_to_start;
    }
    return number_to_start;
}


/*
 * spawn_rate is the number of children that will be spawned on the
 * next maintenance cycle if there aren't enough servers.  It is
 * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
 * without the need to spawn.
 */
static int spawn_rate = 1;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE  (32)
#endif
static int hold_off_on_exponential_spawning;

static void perform_child_maintenance(void)
{
    int i;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead = -1;

    /* initialize the free_list */
    free_length = 0;
    
    for (i = 0; i < num_daemons; ++i) {
        if (ap_child_table[i].pid == 0) {
            if (free_length < spawn_rate) {
                free_slots[free_length] = i;
                ++free_length;
            }
        }
        else {
            last_non_dead = i;
        }

        if (i >= ap_max_daemons_limit && free_length >= spawn_rate) {
            break;
        }
    }
    ap_max_daemons_limit = last_non_dead + 1;

    if (free_length > 0) {
        for (i = 0; i < free_length; ++i) {
            make_child(ap_server_conf, free_slots[i]);
        }
        /* the next time around we want to spawn twice as many if this
         * wasn't good enough, but not if we've just done a graceful
         */
        if (hold_off_on_exponential_spawning) {
            --hold_off_on_exponential_spawning;
        }
        else if (spawn_rate < MAX_SPAWN_RATE) {
            spawn_rate *= 2;
        }
    }
    else {
        spawn_rate = 1;
    }
}

static void server_main_loop(int remaining_children_to_start)
{
    int child_slot;
    apr_exit_why_e exitwhy;
    int status;
    apr_proc_t pid;
    int i;

    while (!restart_pending && !shutdown_pending) {
        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf);
        
        if (pid.pid != -1) {
            if (ap_process_child_status(&pid, exitwhy, status)
                == APEXIT_CHILDFATAL) {
                shutdown_pending = 1;
                child_fatal = 1;
                return;
            }
            /* non-fatal death... note that it's gone in the child table and
             * clean out the status table. */
            child_slot = -1;
            for (i = 0; i < ap_max_daemons_limit; ++i) {
                if (ap_child_table[i].pid == pid.pid) {
                    child_slot = i;
                    break;
                }
            }
            if (child_slot >= 0) {
                ap_child_table[child_slot].pid = 0;
                ap_update_child_status_from_indexes(child_slot, i, SERVER_DEAD,
                                                    (request_rec *) NULL);

                
                if (remaining_children_to_start
                    && child_slot < num_daemons) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_child(ap_server_conf, child_slot);
                    --remaining_children_to_start;
                }
#if APR_HAS_OTHER_CHILD
            }
            else if (apr_proc_other_child_read(&pid, status) == 0) {
            /* handled */
#endif
            }
            else if (is_graceful) {
                /* Great, we've probably just lost a slot in the
                * child table.  Somehow we don't know about this
                * child.
                */
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, 
                             ap_server_conf,
                             "long lost child came home! (pid %ld)", 
                             (long)pid.pid);
            }
            /* Don't perform idle maintenance when a child dies,
             * only do it when there's a timeout.  Remember only a
             * finite number of children can die, and it's pretty
             * pathological for a lot to die suddenly.
             */
            continue;
        }
        else if (remaining_children_to_start) {
            /* we hit a 1 second timeout in which none of the previous
             * generation of children needed to be reaped... so assume
             * they're all done, and pick up the slack if any is left.
             */
            remaining_children_to_start = \
                startup_children(remaining_children_to_start);
            /* In any event we really shouldn't do the code below because
             * few of the servers we just started are in the IDLE state
             * yet, so we'd mistakenly create an extra server.
             */
            continue;
        }

        perform_child_maintenance();
    }
}

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int remaining_children_to_start;
    int i;
    apr_status_t rv;
    apr_size_t one = 1;
    ap_listen_rec *lr;
    apr_socket_t *sock = NULL;
    int fd;

    ap_log_pid(pconf, ap_pid_fname);

    first_server_limit = server_limit;
    first_thread_limit = thread_limit;
    if (changed_limit_at_restart) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "WARNING: Attempt to change ServerLimit or ThreadLimit "
                     "ignored during restart");
        changed_limit_at_restart = 0;
    }

    ap_server_conf = s;

    if ((ap_accept_lock_mech == APR_LOCK_SYSVSEM) || 
        (ap_accept_lock_mech == APR_LOCK_POSIXSEM)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "Server configured for an accept lock mechanism that "
                     "cannot be used with perchild.  Falling back to FCNTL.");
        ap_accept_lock_mech = APR_LOCK_FCNTL;
    }

    /* Initialize cross-process accept lock */
    ap_lock_fname = apr_psprintf(_pconf, "%s.%u",
                                 ap_server_root_relative(_pconf, ap_lock_fname),
                                 my_pid);
    rv = SAFE_ACCEPT(apr_proc_mutex_create(&process_accept_mutex,
                                     ap_lock_fname, ap_accept_lock_mech,
                                     _pconf));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Couldn't create cross-process lock");
        return 1;
    }

    if (!is_graceful) {
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            return 1;
        }
    }
    /* Initialize the child table */
    if (!is_graceful) {
        for (i = 0; i < server_limit; i++) {
            ap_child_table[i].pid = 0;
        }
    }

    /* We need to put the new listeners at the end of the ap_listeners
     * list.  If we don't, then the pool will be cleared before the
     * open_logs phase is called for the second time, and ap_listeners
     * will have only invalid data.  If that happens, then the sockets
     * that we opened using make_sock() will be lost, and the server
     * won't start.
     */
    for (lr = ap_listeners ; lr->next != NULL; lr = lr->next) {
        continue;
    }

    apr_os_file_get(&fd, pipe_of_death_in);
    apr_os_sock_put(&sock, &fd, pconf);
    lr->next = apr_palloc(pconf, sizeof(*lr));
    lr->next->sd = sock;
    lr->next->active = 1;
    lr->next->accept_func = check_pipe_of_death;
    lr->next->next = NULL;
    lr = lr->next;
    num_listensocks++;

    set_signals();

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens 
     * pretty rapidly... and for each one that exits we'll start a new one 
     * until we reach at least daemons_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = num_daemons;
    if (!is_graceful) {
        remaining_children_to_start = \
            startup_children(remaining_children_to_start);
    }
    else {
        /* give the system some time to recover before kicking into
         * exponential mode */
        hold_off_on_exponential_spawning = 10;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                 "%s configured -- resuming normal operations",
                 ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
                 "Server built: %s", ap_get_server_built());
#ifdef AP_MPM_WANT_SET_ACCEPT_LOCK_MECH
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
		"AcceptMutex: %s (default: %s)",
		apr_proc_mutex_name(process_accept_mutex),
		apr_proc_mutex_defname());
#endif
    restart_pending = shutdown_pending = 0;

    server_main_loop(remaining_children_to_start);

    if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (unixd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                         "killpg SIGTERM");
        }
        ap_reclaim_child_processes(1);      /* Start with SIGTERM */

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            const char *pidfile = NULL;
            pidfile = ap_server_root_relative (pconf, ap_pid_fname);
            if (pidfile != NULL && unlink(pidfile) == 0) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                             ap_server_conf,
                             "removed PID file %s (pid=%ld)",
                             pidfile, (long)getpid());
            }
    
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
                         ap_server_conf, "caught SIGTERM, shutting down");
        }
        return 1;
    }

    /* we've been told to restart */
    apr_signal(SIGHUP, SIG_IGN);

    if (one_process) {
        /* not worth thinking about */
        return 1;
    }

    if (is_graceful) {
        char char_of_death = '!';

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
                     ap_server_conf, AP_SIG_GRACEFUL_STRING " received.  "
                     "Doing graceful restart");

        /* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.
         */
    
        for (i = 0; i < num_daemons; ++i) {
            if (ap_child_table[i].pid) {
                ap_child_table[i].status = SERVER_DYING;
            } 
        }
        /* give the children the signal to die */
        for (i = 0; i < num_daemons;) {
            if ((rv = apr_file_write(pipe_of_death_out, &char_of_death,
                                     &one)) != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(rv)) continue;
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                             "write pipe_of_death");
            }
            i++;
        }
    }
    else {
        /* Kill 'em all.  Since the child acts the same on the parents SIGTERM 
         * and a SIGHUP, we may as well use the same signal, because some user
         * pthreads are stealing signals from us left and right.
         */
        if (unixd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                         "killpg SIGTERM");
        }
        ap_reclaim_child_processes(1);      /* Start with SIGTERM */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
                     ap_server_conf, "SIGHUP received.  Attempting to restart");
    }
    return 0;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 */
static int perchild_open_logs(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;

    pconf = p;
    ap_server_conf = s;

    if ((num_listensocks = ap_setup_listeners(ap_server_conf)) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_STARTUP, 0,
                     NULL, "no listening sockets available, shutting down");
        return DONE;
    }

    ap_log_pid(pconf, ap_pid_fname);

    if ((rv = ap_mpm_pod_open(pconf, &pod))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_STARTUP, rv, NULL,
                "Could not open pipe-of-death.");
        return DONE;
    }

    if ((rv = apr_file_pipe_create(&pipe_of_death_in, &pipe_of_death_out,
                                   pconf)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                     (const server_rec*) ap_server_conf,
                     "apr_file_pipe_create (pipe_of_death)");
        exit(1);
    }
    if ((rv = apr_file_pipe_timeout_set(pipe_of_death_in, 0)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                     (const server_rec*) ap_server_conf,
                     "apr_file_pipe_timeout_set (pipe_of_death)");
        exit(1);
    }

    return OK;
}

static int perchild_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach, debug, foreground;
    ap_directive_t *pdir;
    int i;
    int tmp_server_limit = DEFAULT_SERVER_LIMIT;
    int tmp_thread_limit = DEFAULT_THREAD_LIMIT;
    apr_status_t rv;

    debug = ap_exists_config_define("DEBUG");

    if (debug) {
        foreground = one_process = 1;
        no_detach = 0;
    }
    else {
        one_process = ap_exists_config_define("ONE_PROCESS");
        no_detach = ap_exists_config_define("NO_DETACH");
        foreground = ap_exists_config_define("FOREGROUND");
    }

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
        is_graceful = 0;

        if (!one_process && !foreground) {
            rv = apr_proc_detach(no_detach ? APR_PROC_DETACH_FOREGROUND
                                           : APR_PROC_DETACH_DAEMONIZE);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                             "apr_proc_detach failed");
                return HTTP_INTERNAL_SERVER_ERROR;
            }                  
        }

        my_pid = getpid();
    }

    unixd_pre_config(ptemp);
    ap_listen_pre_config();
    num_daemons = DEFAULT_NUM_DAEMON;
    threads_to_start = DEFAULT_START_THREAD;
    min_spare_threads = DEFAULT_MIN_SPARE_THREAD;
    max_spare_threads = DEFAULT_MAX_SPARE_THREAD;
    max_threads = thread_limit;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    curr_child_num = 0;
#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
	ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;
#endif

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));

    /* we need to know ServerLimit and ThreadLimit before we start processing
     * the tree because we need to already have allocated child_info_table
     */
    for (pdir = ap_conftree; pdir != NULL; pdir = pdir->next) {
        if (!strcasecmp(pdir->directive, "ServerLimit")) {
            if (atoi(pdir->args) > tmp_server_limit) {
                tmp_server_limit = atoi(pdir->args);
                if (tmp_server_limit > MAX_SERVER_LIMIT) {
                    tmp_server_limit = MAX_SERVER_LIMIT;
                }
            }
        }
        else if (!strcasecmp(pdir->directive, "ThreadLimit")) {
            if (atoi(pdir->args) > tmp_thread_limit) {
                tmp_thread_limit = atoi(pdir->args);
                if (tmp_thread_limit > MAX_THREAD_LIMIT) {
                    tmp_thread_limit = MAX_THREAD_LIMIT;
                }
            }
        }
    }

    child_info_table = (child_info_t *)apr_pcalloc(p, tmp_server_limit * sizeof(child_info_t));
    for (i = 0; i < tmp_server_limit; i++) {
        child_info_table[i].uid = -1;
        child_info_table[i].gid = -1;
        child_info_table[i].input = -1;
        child_info_table[i].output = -1;
    }

    return OK;
}

static int pass_request(request_rec *r)
{
    int rv;
    apr_socket_t *thesock = ap_get_module_config(r->connection->conn_config, &core_module);
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int sfd;
    struct iovec iov[2];
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
    apr_bucket_brigade *sockbb;
    char request_body[HUGE_STRING_LEN] = "\0";
    apr_size_t l = sizeof(request_body);
    perchild_header h;
    apr_bucket *sockbuck;
    perchild_server_conf *sconf = (perchild_server_conf *)
                            ap_get_module_config(r->server->module_config, 
                                                 &mpm_perchild_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                 "passing request to another child.  Vhost: %s, child %d %d",
                 apr_table_get(r->headers_in, "Host"), child_num, sconf->output);
    ap_get_brigade(r->connection->input_filters, bb, AP_MODE_EXHAUSTIVE, APR_NONBLOCK_READ,
                   0);

    for (sockbuck = APR_BRIGADE_FIRST(bb); sockbuck != APR_BRIGADE_SENTINEL(bb);
         sockbuck = APR_BUCKET_NEXT(sockbuck)) {
        if (APR_BUCKET_IS_SOCKET(sockbuck)) {
            break;
        }
    }
    
    if (!sockbuck) {
    }
    sockbb = apr_brigade_split(bb, sockbuck); 

    if (apr_brigade_flatten(bb, request_body, &l) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                     "Unable to flatten brigade, declining request");
        return DECLINED;
    }

    apr_os_sock_get(&sfd, thesock);

    h.p = r->pool;
    h.headers = apr_pstrcat(h.p, r->the_request, CRLF, "Host: ", r->hostname, 
                            CRLF, NULL);
    apr_table_do((int (*) (void *, const char *, const char *))
                 perchild_header_field, (void *) &h, r->headers_in, NULL); 
    h.headers = apr_pstrcat(h.p, h.headers, CRLF, NULL);

    iov[0].iov_base = h.headers;
    iov[0].iov_len = strlen(h.headers) + 1;
    iov[1].iov_base = request_body;
    iov[1].iov_len = l + 1;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    cmsg = apr_palloc(r->pool, sizeof(*cmsg) + sizeof(sfd));
    cmsg->cmsg_len = sizeof(*cmsg) + sizeof(sfd);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    memcpy(CMSG_DATA(cmsg), &sfd, sizeof(sfd));

    msg.msg_control = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                 "Writing message to %d, passing sd:  %d", sconf->output, sfd);

    if ((rv = sendmsg(sconf->output, &msg, 0)) == -1) {
        apr_pool_destroy(r->pool);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                 "Writing message failed %d %d", rv, errno);
        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                 "Writing message succeeded %d", rv);

    apr_pool_destroy(r->pool);
    return 1;
}

static char *make_perchild_socket(const char *fullsockname, int sd[2])
{
    socketpair(PF_UNIX, SOCK_STREAM, 0, sd);
    return NULL;
}

static int perchild_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    int i;
    server_rec *sr;
    perchild_server_conf *sconf;
    int def_sd[2];

    def_sd[0] = -1;
    def_sd[1] = -1;

    for (sr = s; sr; sr = sr->next) {
        sconf = (perchild_server_conf *)ap_get_module_config(sr->module_config,
                                                      &mpm_perchild_module);

        if (sconf->input == -1) {
            sconf->fullsockname = apr_pstrcat(sr->process->pool, 
                                             sconf->sockname, ".DEFAULT", NULL);
            if (def_sd[0] == -1) {
                if (!make_perchild_socket(sconf->fullsockname, def_sd)) {
                    /* log error */
                }
            }
            sconf->input = def_sd[0];
            sconf->output = def_sd[1];
        }
    }

    for (i = 0; i < num_daemons; i++) {
        if (child_info_table[i].uid == -1) {
            child_info_table[i].input = def_sd[0];
            child_info_table[i].output = def_sd[1];
        }
    }

    thread_socket_table = (int *)apr_pcalloc(p, thread_limit * sizeof(int));
    for (i = 0; i < thread_limit; i++) {
        thread_socket_table[i] = AP_PERCHILD_THISCHILD;
    }
    ap_child_table = (ap_ctable *)apr_pcalloc(p, server_limit * sizeof(ap_ctable));

    return OK;
}

static int perchild_post_read(request_rec *r)
{
    int thread_num = r->connection->id % thread_limit;
    perchild_server_conf *sconf = (perchild_server_conf *)
                            ap_get_module_config(r->server->module_config, 
                                                 &mpm_perchild_module);

    if (thread_socket_table[thread_num] != AP_PERCHILD_THISCHILD) {
        apr_socket_t *csd = NULL;

        apr_os_sock_put(&csd, &thread_socket_table[thread_num], 
                        r->connection->pool);
        ap_sock_disable_nagle(csd);
        ap_set_module_config(r->connection->conn_config, &core_module, csd);
        return OK;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                     "Determining if request should be passed. "
                     "Child Num: %d, SD: %d, sd from table: %d, hostname from server: %s", child_num, 
                     sconf->input, child_info_table[child_num].input, 
                     r->server->server_hostname);
        /* sconf is the server config for this vhost, so if our socket
         * is not the same that was set in the config, then the request
         * needs to be passed to another child. */
        if (sconf->input != child_info_table[child_num].input) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, 
                         "Passing request.");
            if (pass_request(r) == -1) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                             ap_server_conf, "Could not pass request to proper "
                             "child, request will not be honored.");
            }
            longjmp(jmpbuffer, 1); 
        }
        return OK;
    }
    return OK;
}

static void perchild_hooks(apr_pool_t *p)
{
    /* The perchild open_logs phase must run before the core's, or stderr
     * will be redirected to a file, and the messages won't print to the
     * console.
     */
    static const char *const aszSucc[] = {"core.c", NULL};
    one_process = 0;

    ap_hook_open_logs(perchild_open_logs, NULL, aszSucc, APR_HOOK_MIDDLE);
    ap_hook_pre_config(perchild_pre_config, NULL, NULL, APR_HOOK_MIDDLE); 
    ap_hook_post_config(perchild_post_config, NULL, NULL, APR_HOOK_MIDDLE); 

    /* Both of these must be run absolutely first.  If this request isn't for 
     * this server then we need to forward it to the proper child.  No sense
     * tying up this server running more post_read request hooks if it is
     * just going to be forwarded along.  The process_connection hook allows
     * perchild to receive the passed request correctly, by automatically
     * filling in the core_input_filter's ctx pointer.
     */
    ap_hook_post_read_request(perchild_post_read, NULL, NULL,
                              APR_HOOK_REALLY_FIRST);
    ap_hook_process_connection(perchild_process_connection, NULL, NULL, 
                               APR_HOOK_REALLY_FIRST);
}

static const char *set_num_daemons(cmd_parms *cmd, void *dummy,
                                   const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    num_daemons = atoi(arg);
    if (num_daemons > server_limit) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: NumServers of %d exceeds ServerLimit value "
                    "of %d servers,", num_daemons, server_limit);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " lowering NumServers to %d.  To increase, please "
                    "see the", server_limit);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " ServerLimit directive.");
       num_daemons = server_limit;
    } 
    else if (num_daemons < 1) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require NumServers > 0, setting to 1");
        num_daemons = 1;
    }
    return NULL;
}

static const char *set_threads_to_start(cmd_parms *cmd, void *dummy,
                                        const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    threads_to_start = atoi(arg);
    if (threads_to_start > thread_limit) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: StartThreads of %d exceeds ThreadLimit value"
                     " of %d threads,", threads_to_start,
                     thread_limit);
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     " lowering StartThreads to %d. To increase, please"
                     " see the", thread_limit);
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     " ThreadLimit directive.");
    }
    else if (threads_to_start < 1) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require StartThreads > 0, setting to 1");
        threads_to_start = 1;
    }
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    if (min_spare_threads <= 0) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: detected MinSpareThreads set to non-positive.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "Resetting to 1 to avoid almost certain Apache failure.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "Please read the documentation.");
       min_spare_threads = 1;
    }
       
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    if (max_spare_threads >= thread_limit) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: detected MinSpareThreads set higher than");
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "ThreadLimit. Resetting to %d", thread_limit);
       max_spare_threads = thread_limit;
    }
    return NULL;
}

static const char *set_max_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_threads = atoi(arg);
    if (max_threads > thread_limit) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: detected MaxThreadsPerChild set higher than");
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "ThreadLimit. Resetting to %d", thread_limit);
       max_threads = thread_limit;
    }
    return NULL;
}

static const char *set_child_per_uid(cmd_parms *cmd, void *dummy, const char *u,
                                     const char *g, const char *num)
{
    int i;
    int max_this_time = atoi(num) + curr_child_num;
    

    for (i = curr_child_num; i < max_this_time; i++, curr_child_num++) {
        if (i > num_daemons) {
            return "Trying to use more child ID's than NumServers.  Increase "
                   "NumServers in your config file.";
        }
    
        child_info_table[i].uid = ap_uname2id(u);
        child_info_table[i].gid = ap_gname2id(g); 

#ifndef BIG_SECURITY_HOLE
        if (child_info_table[i].uid == 0 || child_info_table[i].gid == 0) {
            return "Assigning root user/group to a child.";
        }
#endif
    }
    return NULL;
}

static const char *assign_childuid(cmd_parms *cmd, void *dummy, const char *uid,
                                   const char *gid)
{
    int i;
    int matching = 0;
    int u = ap_uname2id(uid);
    int g = ap_gname2id(gid);
    const char *errstr;
    int socks[2];
    perchild_server_conf *sconf = (perchild_server_conf *)
                            ap_get_module_config(cmd->server->module_config, 
                                                 &mpm_perchild_module);

    sconf->fullsockname = apr_pstrcat(cmd->pool, sconf->sockname, ".", uid,
                                      ":", gid, NULL);

    if ((errstr = make_perchild_socket(sconf->fullsockname, socks))) {
        return errstr;
    }

    sconf->input = socks[0]; 
    sconf->output = socks[1];

    for (i = 0; i < num_daemons; i++) {
        if (u == child_info_table[i].uid && g == child_info_table[i].gid) {
            child_info_table[i].input = sconf->input;
            child_info_table[i].output = sconf->output;
            matching++;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, 
                         "filling out child_info_table; UID: %d, GID: %d, "
                         "SD: %d %d, OUTPUT: %d %d, Child Num: %d", 
                         child_info_table[i].uid, child_info_table[i].gid, 
                         sconf->input, child_info_table[i].input, sconf->output,
                         child_info_table[i].output, i);
        }
    }

    if (!matching) {
        return "Unable to find process with matching uid/gid.";
    }
    return NULL;
}

static const char *set_server_limit (cmd_parms *cmd, void *dummy, const char *arg) 
{
    int tmp_server_limit;
    
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    tmp_server_limit = atoi(arg);
    /* you cannot change ServerLimit across a restart; ignore
     * any such attempts
     */
    if (first_server_limit &&
        tmp_server_limit != server_limit) {
        /* how do we log a message?  the error log is a bit bucket at this
         * point; we'll just have to set a flag so that ap_mpm_run()
         * logs a warning later
         */
        changed_limit_at_restart = 1;
        return NULL;
    }
    server_limit = tmp_server_limit;
    
    if (server_limit > MAX_SERVER_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: ServerLimit of %d exceeds compile time limit "
                    "of %d servers,", server_limit, MAX_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " lowering ServerLimit to %d.", MAX_SERVER_LIMIT);
       server_limit = MAX_SERVER_LIMIT;
    } 
    else if (server_limit < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require ServerLimit > 0, setting to 1");
	server_limit = 1;
    }
    return NULL;
}

static const char *set_thread_limit (cmd_parms *cmd, void *dummy, const char *arg) 
{
    int tmp_thread_limit;
    
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    tmp_thread_limit = atoi(arg);
    /* you cannot change ThreadLimit across a restart; ignore
     * any such attempts
     */
    if (first_thread_limit &&
        tmp_thread_limit != thread_limit) {
        /* how do we log a message?  the error log is a bit bucket at this
         * point; we'll just have to set a flag so that ap_mpm_run()
         * logs a warning later
         */
        changed_limit_at_restart = 1;
        return NULL;
    }
    thread_limit = tmp_thread_limit;
    
    if (thread_limit > MAX_THREAD_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: ThreadLimit of %d exceeds compile time limit "
                    "of %d servers,", thread_limit, MAX_THREAD_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " lowering ThreadLimit to %d.", MAX_THREAD_LIMIT);
       thread_limit = MAX_THREAD_LIMIT;
    } 
    else if (thread_limit < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require ThreadLimit > 0, setting to 1");
	thread_limit = 1;
    }
    return NULL;
}

static const command_rec perchild_cmds[] = {
UNIX_DAEMON_COMMANDS,
LISTEN_COMMANDS,
AP_INIT_TAKE1("NumServers", set_num_daemons, NULL, RSRC_CONF,
              "Number of children alive at the same time"),
AP_INIT_TAKE1("StartThreads", set_threads_to_start, NULL, RSRC_CONF,
              "Number of threads each child creates"),
AP_INIT_TAKE1("MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
              "Minimum number of idle threads per child, to handle "
              "request spikes"),
AP_INIT_TAKE1("MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
              "Maximum number of idle threads per child"),
AP_INIT_TAKE1("MaxThreadsPerChild", set_max_threads, NULL, RSRC_CONF,
              "Maximum number of threads per child"),
AP_INIT_TAKE3("ChildperUserID", set_child_per_uid, NULL, RSRC_CONF,
              "Specify a User and Group for a specific child process."),
AP_INIT_TAKE2("AssignUserID", assign_childuid, NULL, RSRC_CONF,
              "Tie a virtual host to a specific child process."),
AP_INIT_TAKE1("ServerLimit", set_server_limit, NULL, RSRC_CONF,
              "Maximum value of NumServers for this run of Apache"),
AP_INIT_TAKE1("ThreadLimit", set_thread_limit, NULL, RSRC_CONF,
              "Maximum worker threads in a server for this run of Apache"),
{ NULL }
};

static void *perchild_create_config(apr_pool_t *p, server_rec *s)
{
    perchild_server_conf *c = (perchild_server_conf *)
                                  apr_pcalloc(p, sizeof(perchild_server_conf));

    c->input = -1;
    c->output = -1;
    return c;
}

module AP_MODULE_DECLARE_DATA mpm_perchild_module = {
    MPM20_MODULE_STUFF,
    ap_mpm_rewrite_args,        /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    perchild_create_config,     /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    perchild_cmds,              /* command apr_table_t */
    perchild_hooks              /* register_hooks */
};

