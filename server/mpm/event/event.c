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

/**
 * This MPM tries to fix the 'keep alive problem' in HTTP.
 *
 * After a client completes the first request, the client can keep the
 * connection open to send more requests with the same socket.  This can save
 * significant overhead in creating TCP connections.  However, the major
 * disadvantage is that Apache traditionally keeps an entire child
 * process/thread waiting for data from the client.  To solve this problem,
 * this MPM has a dedicated thread for handling both the Listening sockets,
 * and all sockets that are in a Keep Alive status.
 *
 * The MPM assumes the underlying apr_pollset implementation is somewhat
 * threadsafe.  This currently is only compatible with KQueue and EPoll.  This
 * enables the MPM to avoid extra high level locking or having to wake up the
 * listener thread when a keep-alive socket needs to be sent to it.
 *
 * This MPM does not perform well on older platforms that do not have very good
 * threading, like Linux with a 2.4 kernel, but this does not matter, since we
 * require EPoll or KQueue.
 *
 * For FreeBSD, use 5.3.  It is possible to run this MPM on FreeBSD 5.2.1, if
 * you use libkse (see `man libmap.conf`).
 *
 * For NetBSD, use at least 2.0.
 *
 * For Linux, you should use a 2.6 kernel, and make sure your glibc has epoll
 * support compiled in.
 *
 */

#include "apr.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_thread_mutex.h"
#include "apr_poll.h"
#include "apr_ring.h"
#include "apr_queue.h"
#include "apr_atomic.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_version.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h>      /* for bindprocessor() */
#endif

#if !APR_HAS_THREADS
#error The Event MPM requires APR threads, but they are unavailable.
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"        /* for read_config */
#include "http_core.h"          /* for get_remote_host */
#include "http_connection.h"
#include "http_protocol.h"
#include "ap_mpm.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "scoreboard.h"
#include "fdqueue.h"
#include "mpm_default.h"
#include "http_vhost.h"
#include "unixd.h"
#include "apr_skiplist.h"

#include <signal.h>
#include <limits.h>             /* for INT_MAX */


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
#define DEFAULT_SERVER_LIMIT 16
#endif

/* Admin can't tune ServerLimit beyond MAX_SERVER_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_SERVER_LIMIT
#define MAX_SERVER_LIMIT 20000
#endif

/* Limit on the threads per process.  Clients will be locked out if more than
 * this are needed.
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
#define MAX_THREAD_LIMIT 100000
#endif

#define MPM_CHILD_PID(i) (ap_scoreboard_image->parent[i].pid)

#if !APR_VERSION_AT_LEAST(1,4,0)
#define apr_time_from_msec(x) (x * 1000)
#endif

#ifndef MAX_SECS_TO_LINGER
#define MAX_SECS_TO_LINGER 30
#endif
#define SECONDS_TO_LINGER  2

/*
 * Actual definitions of config globals
 */

#ifndef DEFAULT_WORKER_FACTOR
#define DEFAULT_WORKER_FACTOR 2
#endif
#define WORKER_FACTOR_SCALE   16  /* scale factor to allow fractional values */
static unsigned int worker_factor = DEFAULT_WORKER_FACTOR * WORKER_FACTOR_SCALE;

static int threads_per_child = 0;   /* Worker threads per child */
static int ap_daemons_to_start = 0;
static int min_spare_threads = 0;
static int max_spare_threads = 0;
static int ap_daemons_limit = 0;
static int max_workers = 0;
static int server_limit = 0;
static int thread_limit = 0;
static int had_healthy_child = 0;
static int dying = 0;
static int workers_may_exit = 0;
static int start_thread_may_exit = 0;
static int listener_may_exit = 0;
static int num_listensocks = 0;
static apr_int32_t conns_this_child;        /* MaxConnectionsPerChild, only access
                                               in listener thread */
static apr_uint32_t connection_count = 0;   /* Number of open connections */
static apr_uint32_t lingering_count = 0;    /* Number of connections in lingering close */
static apr_uint32_t suspended_count = 0;    /* Number of suspended connections */
static apr_uint32_t clogged_count = 0;      /* Number of threads processing ssl conns */
static int resource_shortage = 0;
static fd_queue_t *worker_queue;
static fd_queue_info_t *worker_queue_info;
static int mpm_state = AP_MPMQ_STARTING;

static apr_thread_mutex_t *timeout_mutex;

module AP_MODULE_DECLARE_DATA mpm_event_module;

struct event_conn_state_t {
    /** APR_RING of expiration timeouts */
    APR_RING_ENTRY(event_conn_state_t) timeout_list;
    /** the expiration time of the next keepalive timeout */
    apr_time_t expiration_time;
    /** connection record this struct refers to */
    conn_rec *c;
    /** request record (if any) this struct refers to */
    request_rec *r;
    /** is the current conn_rec suspended?  (disassociated with
     * a particular MPM thread; for suspend_/resume_connection
     * hooks)
     */
    int suspended;
    /** memory pool to allocate from */
    apr_pool_t *p;
    /** bucket allocator */
    apr_bucket_alloc_t *bucket_alloc;
    /** poll file descriptor information */
    apr_pollfd_t pfd;
    /** public parts of the connection state */
    conn_state_t pub;
};
APR_RING_HEAD(timeout_head_t, event_conn_state_t);

struct timeout_queue {
    struct timeout_head_t head;
    int count;
    const char *tag;
};
/*
 * Several timeout queues that use different timeouts, so that we always can
 * simply append to the end.
 *   write_completion_q uses TimeOut
 *   keepalive_q        uses KeepAliveTimeOut
 *   linger_q           uses MAX_SECS_TO_LINGER
 *   short_linger_q     uses SECONDS_TO_LINGER
 */
static struct timeout_queue write_completion_q, keepalive_q, linger_q,
                            short_linger_q;
static apr_pollfd_t *listener_pollfd;

/*
 * Macros for accessing struct timeout_queue.
 * For TO_QUEUE_APPEND and TO_QUEUE_REMOVE, timeout_mutex must be held.
 */
#define TO_QUEUE_APPEND(q, el)                                                  \
    do {                                                                        \
        APR_RING_INSERT_TAIL(&(q).head, el, event_conn_state_t, timeout_list);  \
        (q).count++;                                                            \
    } while (0)

#define TO_QUEUE_REMOVE(q, el)             \
    do {                                   \
        APR_RING_REMOVE(el, timeout_list); \
        (q).count--;                       \
    } while (0)

#define TO_QUEUE_INIT(q)                                                  \
    do {                                                                  \
            APR_RING_INIT(&(q).head, event_conn_state_t, timeout_list);   \
            (q).tag = #q;                                                 \
    } while (0)

#define TO_QUEUE_ELEM_INIT(el) APR_RING_ELEM_INIT(el, timeout_list)

/*
 * The pollset for sockets that are in any of the timeout queues. Currently
 * we use the timeout_mutex to make sure that connections are added/removed
 * atomically to/from both event_pollset and a timeout queue. Otherwise
 * some confusion can happen under high load if timeout queues and pollset
 * get out of sync.
 * XXX: It should be possible to make the lock unnecessary in many or even all
 * XXX: cases.
 */
static apr_pollset_t *event_pollset;

/* The structure used to pass unique initialization info to each thread */
typedef struct
{
    int pid;
    int tid;
    int sd;
} proc_info;

/* Structure used to pass information to the thread responsible for
 * creating the rest of the threads.
 */
typedef struct
{
    apr_thread_t **threads;
    apr_thread_t *listener;
    int child_num_arg;
    apr_threadattr_t *threadattr;
} thread_starter;

typedef enum
{
    PT_CSD,
    PT_ACCEPT
} poll_type_e;

typedef struct
{
    poll_type_e type;
    void *baton;
} listener_poll_type;

/* data retained by event across load/unload of the module
 * allocated on first call to pre-config hook; located on
 * subsequent calls to pre-config hook
 */
typedef struct event_retained_data {
    int first_server_limit;
    int first_thread_limit;
    int module_loads;
    int sick_child_detected;
    ap_generation_t my_generation;
    int volatile is_graceful; /* set from signal handler */
    int maxclients_reported;
    /*
     * The max child slot ever assigned, preserved across restarts.  Necessary
     * to deal with MaxRequestWorkers changes across AP_SIG_GRACEFUL restarts.
     * We use this value to optimize routines that have to scan the entire
     * scoreboard.
     */
    int max_daemons_limit;
    /*
     * idle_spawn_rate is the number of children that will be spawned on the
     * next maintenance cycle if there aren't enough idle servers.  It is
     * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
     * without the need to spawn.
     */
    int idle_spawn_rate;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE        (32)
#endif
    int hold_off_on_exponential_spawning;
} event_retained_data;
static event_retained_data *retained;

#define ID_FROM_CHILD_THREAD(c, t)    ((c * thread_limit) + t)

static ap_pod_t *pod;

/* The event MPM respects a couple of runtime flags that can aid
 * in debugging. Setting the -DNO_DETACH flag will prevent the root process
 * from detaching from its controlling terminal. Additionally, setting
 * the -DONE_PROCESS flag (which implies -DNO_DETACH) will get you the
 * child_main loop running in the process which originally started up.
 * This gives you a pretty nice debugging environment.  (You'll get a SIGHUP
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

static apr_pool_t *pconf;       /* Pool for config stuff */
static apr_pool_t *pchild;      /* Pool for httpd child stuff */

static pid_t ap_my_pid;         /* Linux getpid() doesn't work except in main
                                   thread. Use this instead */
static pid_t parent_pid;
static apr_os_thread_t *listener_os_thread;

/* The LISTENER_SIGNAL signal will be sent from the main thread to the
 * listener thread to wake it up for graceful termination (what a child
 * process from an old generation does when the admin does "apachectl
 * graceful").  This signal will be blocked in all threads of a child
 * process except for the listener thread.
 */
#define LISTENER_SIGNAL     SIGHUP

/* An array of socket descriptors in use by each thread used to
 * perform a non-graceful (forced) shutdown of the server.
 */
static apr_socket_t **worker_sockets;

static void disable_listensocks(int process_slot)
{
    int i;
    for (i = 0; i < num_listensocks; i++) {
        apr_pollset_remove(event_pollset, &listener_pollfd[i]);
    }
    ap_scoreboard_image->parent[process_slot].not_accepting = 1;
}

static void enable_listensocks(int process_slot)
{
    int i;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(00457)
                 "Accepting new connections again: "
                 "%u active conns (%u lingering/%u clogged/%u suspended), "
                 "%u idle workers",
                 apr_atomic_read32(&connection_count),
                 apr_atomic_read32(&lingering_count),
                 apr_atomic_read32(&clogged_count),
                 apr_atomic_read32(&suspended_count),
                 ap_queue_info_get_idlers(worker_queue_info));
    for (i = 0; i < num_listensocks; i++)
        apr_pollset_add(event_pollset, &listener_pollfd[i]);
    /*
     * XXX: This is not yet optimal. If many workers suddenly become available,
     * XXX: the parent may kill some processes off too soon.
     */
    ap_scoreboard_image->parent[process_slot].not_accepting = 0;
}

static void close_worker_sockets(void)
{
    int i;
    for (i = 0; i < threads_per_child; i++) {
        if (worker_sockets[i]) {
            apr_socket_close(worker_sockets[i]);
            worker_sockets[i] = NULL;
        }
    }
}

static void wakeup_listener(void)
{
    listener_may_exit = 1;
    if (!listener_os_thread) {
        /* XXX there is an obscure path that this doesn't handle perfectly:
         *     right after listener thread is created but before
         *     listener_os_thread is set, the first worker thread hits an
         *     error and starts graceful termination
         */
        return;
    }

    /* unblock the listener if it's waiting for a worker */
    ap_queue_info_term(worker_queue_info);

    /*
     * we should just be able to "kill(ap_my_pid, LISTENER_SIGNAL)" on all
     * platforms and wake up the listener thread since it is the only thread
     * with SIGHUP unblocked, but that doesn't work on Linux
     */
#ifdef HAVE_PTHREAD_KILL
    pthread_kill(*listener_os_thread, LISTENER_SIGNAL);
#else
    kill(ap_my_pid, LISTENER_SIGNAL);
#endif
}

#define ST_INIT              0
#define ST_GRACEFUL          1
#define ST_UNGRACEFUL        2

static int terminate_mode = ST_INIT;

static void signal_threads(int mode)
{
    if (terminate_mode == mode) {
        return;
    }
    terminate_mode = mode;
    mpm_state = AP_MPMQ_STOPPING;

    /* in case we weren't called from the listener thread, wake up the
     * listener thread
     */
    wakeup_listener();

    /* for ungraceful termination, let the workers exit now;
     * for graceful termination, the listener thread will notify the
     * workers to exit once it has stopped accepting new connections
     */
    if (mode == ST_UNGRACEFUL) {
        workers_may_exit = 1;
        ap_queue_interrupt_all(worker_queue);
        close_worker_sockets(); /* forcefully kill all current connections */
    }
}

static int event_query(int query_code, int *result, apr_status_t *rv)
{
    *rv = APR_SUCCESS;
    switch (query_code) {
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = retained->max_daemons_limit;
        break;
    case AP_MPMQ_IS_THREADED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_IS_FORKED:
        *result = AP_MPMQ_DYNAMIC;
        break;
    case AP_MPMQ_IS_ASYNC:
        *result = 1;
        break;
    case AP_MPMQ_HARD_LIMIT_DAEMONS:
        *result = server_limit;
        break;
    case AP_MPMQ_HARD_LIMIT_THREADS:
        *result = thread_limit;
        break;
    case AP_MPMQ_MAX_THREADS:
        *result = threads_per_child;
        break;
    case AP_MPMQ_MIN_SPARE_DAEMONS:
        *result = 0;
        break;
    case AP_MPMQ_MIN_SPARE_THREADS:
        *result = min_spare_threads;
        break;
    case AP_MPMQ_MAX_SPARE_DAEMONS:
        *result = 0;
        break;
    case AP_MPMQ_MAX_SPARE_THREADS:
        *result = max_spare_threads;
        break;
    case AP_MPMQ_MAX_REQUESTS_DAEMON:
        *result = ap_max_requests_per_child;
        break;
    case AP_MPMQ_MAX_DAEMONS:
        *result = ap_daemons_limit;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = mpm_state;
        break;
    case AP_MPMQ_GENERATION:
        *result = retained->my_generation;
        break;
    default:
        *rv = APR_ENOTIMPL;
        break;
    }
    return OK;
}

static void event_note_child_killed(int childnum, pid_t pid, ap_generation_t gen)
{
    if (childnum != -1) { /* child had a scoreboard slot? */
        ap_run_child_status(ap_server_conf,
                            ap_scoreboard_image->parent[childnum].pid,
                            ap_scoreboard_image->parent[childnum].generation,
                            childnum, MPM_CHILD_EXITED);
        ap_scoreboard_image->parent[childnum].pid = 0;
    }
    else {
        ap_run_child_status(ap_server_conf, pid, gen, -1, MPM_CHILD_EXITED);
    }
}

static void event_note_child_started(int slot, pid_t pid)
{
    ap_scoreboard_image->parent[slot].pid = pid;
    ap_run_child_status(ap_server_conf,
                        ap_scoreboard_image->parent[slot].pid,
                        retained->my_generation, slot, MPM_CHILD_STARTED);
}

static void event_note_child_lost_slot(int slot, pid_t newpid)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(00458)
                 "pid %" APR_PID_T_FMT " taking over scoreboard slot from "
                 "%" APR_PID_T_FMT "%s",
                 newpid,
                 ap_scoreboard_image->parent[slot].pid,
                 ap_scoreboard_image->parent[slot].quiescing ?
                 " (quiescing)" : "");
    ap_run_child_status(ap_server_conf,
                        ap_scoreboard_image->parent[slot].pid,
                        ap_scoreboard_image->parent[slot].generation,
                        slot, MPM_CHILD_LOST_SLOT);
    /* Don't forget about this exiting child process, or we
     * won't be able to kill it if it doesn't exit by the
     * time the server is shut down.
     */
    ap_register_extra_mpm_process(ap_scoreboard_image->parent[slot].pid,
                                  ap_scoreboard_image->parent[slot].generation);
}

static const char *event_get_name(void)
{
    return "event";
}

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    mpm_state = AP_MPMQ_STOPPING;
    if (pchild) {
        apr_pool_destroy(pchild);
    }

    if (one_process) {
        event_note_child_killed(/* slot */ 0, 0, 0);
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

static int child_fatal;

/* volatile because they're updated from a signal handler */
static int volatile shutdown_pending;
static int volatile restart_pending;

static apr_status_t decrement_connection_count(void *cs_)
{
    event_conn_state_t *cs = cs_;
    switch (cs->pub.state) {
        case CONN_STATE_LINGER_NORMAL:
        case CONN_STATE_LINGER_SHORT:
            apr_atomic_dec32(&lingering_count);
            break;
        case CONN_STATE_SUSPENDED:
            apr_atomic_dec32(&suspended_count);
            break;
        default:
            break;
    }
    apr_atomic_dec32(&connection_count);
    return APR_SUCCESS;
}

/*
 * ap_start_shutdown() and ap_start_restart(), below, are a first stab at
 * functions to initiate shutdown or restart without relying on signals.
 * Previously this was initiated in sig_term() and restart() signal handlers,
 * but we want to be able to start a shutdown/restart from other sources --
 * e.g. on Win32, from the service manager. Now the service manager can
 * call ap_start_shutdown() or ap_start_restart() as appropriate.  Note that
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

static void ap_start_shutdown(int graceful)
{
    mpm_state = AP_MPMQ_STOPPING;
    if (shutdown_pending == 1) {
        /* Um, is this _probably_ not an error, if the user has
         * tried to do a shutdown twice quickly, so we won't
         * worry about reporting it.
         */
        return;
    }
    shutdown_pending = 1;
    retained->is_graceful = graceful;
}

/* do a graceful restart if graceful == 1 */
static void ap_start_restart(int graceful)
{
    mpm_state = AP_MPMQ_STOPPING;
    if (restart_pending == 1) {
        /* Probably not an error - don't bother reporting it */
        return;
    }
    restart_pending = 1;
    retained->is_graceful = graceful;
}

static void sig_term(int sig)
{
    ap_start_shutdown(sig == AP_SIG_GRACEFUL_STOP);
}

static void restart(int sig)
{
    ap_start_restart(sig == AP_SIG_GRACEFUL);
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
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00459)
                     "sigaction(SIGTERM)");
#ifdef AP_SIG_GRACEFUL_STOP
    if (sigaction(AP_SIG_GRACEFUL_STOP, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00460)
                     "sigaction(" AP_SIG_GRACEFUL_STOP_STRING ")");
#endif
#ifdef SIGINT
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00461)
                     "sigaction(SIGINT)");
#endif
#ifdef SIGXCPU
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXCPU, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00462)
                     "sigaction(SIGXCPU)");
#endif
#ifdef SIGXFSZ
    /* For systems following the LFS standard, ignoring SIGXFSZ allows
     * a write() beyond the 2GB limit to fail gracefully with E2BIG
     * rather than terminate the process. */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGXFSZ, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00463)
                     "sigaction(SIGXFSZ)");
#endif
#ifdef SIGPIPE
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00464)
                     "sigaction(SIGPIPE)");
#endif

    /* we want to ignore HUPs and AP_SIG_GRACEFUL while we're busy
     * processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, AP_SIG_GRACEFUL);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00465)
                     "sigaction(SIGHUP)");
    if (sigaction(AP_SIG_GRACEFUL, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(00466)
                     "sigaction(" AP_SIG_GRACEFUL_STRING ")");
#else
    if (!one_process) {
#ifdef SIGXCPU
        apr_signal(SIGXCPU, SIG_DFL);
#endif /* SIGXCPU */
#ifdef SIGXFSZ
        apr_signal(SIGXFSZ, SIG_IGN);
#endif /* SIGXFSZ */
    }

    apr_signal(SIGTERM, sig_term);
#ifdef SIGHUP
    apr_signal(SIGHUP, restart);
#endif /* SIGHUP */
#ifdef AP_SIG_GRACEFUL
    apr_signal(AP_SIG_GRACEFUL, restart);
#endif /* AP_SIG_GRACEFUL */
#ifdef AP_SIG_GRACEFUL_STOP
     apr_signal(AP_SIG_GRACEFUL_STOP, sig_term);
#endif /* AP_SIG_GRACEFUL_STOP */
#ifdef SIGPIPE
    apr_signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
}

static int start_lingering_close_common(event_conn_state_t *cs)
{
    apr_status_t rv;
    struct timeout_queue *q;
    apr_socket_t *csd = cs->pfd.desc.s;
#ifdef AP_DEBUG
    {
        rv = apr_socket_timeout_set(csd, 0);
        AP_DEBUG_ASSERT(rv == APR_SUCCESS);
    }
#else
    apr_socket_timeout_set(csd, 0);
#endif
    /*
     * If some module requested a shortened waiting period, only wait for
     * 2s (SECONDS_TO_LINGER). This is useful for mitigating certain
     * DoS attacks.
     */
    if (apr_table_get(cs->c->notes, "short-lingering-close")) {
        cs->expiration_time =
            apr_time_now() + apr_time_from_sec(SECONDS_TO_LINGER);
        q = &short_linger_q;
        cs->pub.state = CONN_STATE_LINGER_SHORT;
    }
    else {
        cs->expiration_time =
            apr_time_now() + apr_time_from_sec(MAX_SECS_TO_LINGER);
        q = &linger_q;
        cs->pub.state = CONN_STATE_LINGER_NORMAL;
    }
    apr_atomic_inc32(&lingering_count);
    apr_thread_mutex_lock(timeout_mutex);
    cs->c->sbh = NULL;
    TO_QUEUE_APPEND(*q, cs);
    cs->pfd.reqevents = (
            cs->pub.sense == CONN_SENSE_WANT_WRITE ? APR_POLLOUT :
                    APR_POLLIN) | APR_POLLHUP | APR_POLLERR;
    cs->pub.sense = CONN_SENSE_DEFAULT;
    rv = apr_pollset_add(event_pollset, &cs->pfd);
    apr_thread_mutex_unlock(timeout_mutex);
    if (rv != APR_SUCCESS && !APR_STATUS_IS_EEXIST(rv)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                     "start_lingering_close: apr_pollset_add failure");
        apr_thread_mutex_lock(timeout_mutex);
        TO_QUEUE_REMOVE(*q, cs);
        apr_thread_mutex_unlock(timeout_mutex);
        apr_socket_close(cs->pfd.desc.s);
        apr_pool_clear(cs->p);
        ap_push_pool(worker_queue_info, cs->p);
        return 0;
    }
    return 1;
}

/*
 * Close our side of the connection, flushing data to the client first.
 * Pre-condition: cs is not in any timeout queue and not in the pollset,
 *                timeout_mutex is not locked
 * return: 0 if connection is fully closed,
 *         1 if connection is lingering
 * May only be called by worker thread.
 */
static int start_lingering_close_blocking(event_conn_state_t *cs)
{
    if (ap_start_lingering_close(cs->c)) {
        apr_pool_clear(cs->p);
        ap_push_pool(worker_queue_info, cs->p);
        return 0;
    }
    return start_lingering_close_common(cs);
}

/*
 * Close our side of the connection, NOT flushing data to the client.
 * This should only be called if there has been an error or if we know
 * that our send buffers are empty.
 * Pre-condition: cs is not in any timeout queue and not in the pollset,
 *                timeout_mutex is not locked
 * return: 0 if connection is fully closed,
 *         1 if connection is lingering
 * may be called by listener thread
 */
static int start_lingering_close_nonblocking(event_conn_state_t *cs)
{
    conn_rec *c = cs->c;
    apr_socket_t *csd = cs->pfd.desc.s;

    if (c->aborted
        || apr_socket_shutdown(csd, APR_SHUTDOWN_WRITE) != APR_SUCCESS) {
        apr_socket_close(csd);
        apr_pool_clear(cs->p);
        ap_push_pool(worker_queue_info, cs->p);
        return 0;
    }
    return start_lingering_close_common(cs);
}

/*
 * forcibly close a lingering connection after the lingering period has
 * expired
 * Pre-condition: cs is not in any timeout queue and not in the pollset
 * return: irrelevant (need same prototype as start_lingering_close)
 */
static int stop_lingering_close(event_conn_state_t *cs)
{
    apr_status_t rv;
    apr_socket_t *csd = ap_get_conn_socket(cs->c);
    ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, ap_server_conf,
                 "socket reached timeout in lingering-close state");
    rv = apr_socket_close(csd);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(00468) "error closing socket");
        AP_DEBUG_ASSERT(0);
    }
    apr_pool_clear(cs->p);
    ap_push_pool(worker_queue_info, cs->p);
    return 0;
}

static void notify_suspend(event_conn_state_t *cs)
{
    ap_run_suspend_connection(cs->c, cs->r);
    cs->suspended = 1;
}

static void notify_resume(event_conn_state_t *cs)
{
    cs->suspended = 0;
    ap_run_resume_connection(cs->c, cs->r);
}

/*
 * This runs before any non-MPM cleanup code on the connection;
 * if the connection is currently suspended as far as modules
 * know, provide notification of resumption.
 */
static apr_status_t ptrans_pre_cleanup(void *dummy)
{
    event_conn_state_t *cs = dummy;

    if (cs->suspended) {
        notify_resume(cs);
    }
    return APR_SUCCESS;
}

/*
 * event_pre_read_request() and event_request_cleanup() track the
 * current r for a given connection.
 */
static apr_status_t event_request_cleanup(void *dummy)
{
    conn_rec *c = dummy;
    event_conn_state_t *cs = ap_get_module_config(c->conn_config,
                                                  &mpm_event_module);

    cs->r = NULL;
    return APR_SUCCESS;
}

static void event_pre_read_request(request_rec *r, conn_rec *c)
{
    event_conn_state_t *cs = ap_get_module_config(c->conn_config,
                                                  &mpm_event_module);

    cs->r = r;
    apr_pool_cleanup_register(r->pool, c, event_request_cleanup,
                              apr_pool_cleanup_null);
}

/*
 * process one connection in the worker
 */
static void process_socket(apr_thread_t *thd, apr_pool_t * p, apr_socket_t * sock,
                          event_conn_state_t * cs, int my_child_num,
                          int my_thread_num)
{
    conn_rec *c;
    long conn_id = ID_FROM_CHILD_THREAD(my_child_num, my_thread_num);
    int rc;
    ap_sb_handle_t *sbh;

    /* XXX: This will cause unbounded mem usage for long lasting connections */
    ap_create_sb_handle(&sbh, p, my_child_num, my_thread_num);

    if (cs == NULL) {           /* This is a new connection */
        listener_poll_type *pt = apr_pcalloc(p, sizeof(*pt));
        cs = apr_pcalloc(p, sizeof(event_conn_state_t));
        cs->bucket_alloc = apr_bucket_alloc_create(p);
        c = ap_run_create_connection(p, ap_server_conf, sock,
                                     conn_id, sbh, cs->bucket_alloc);
        if (!c) {
            apr_bucket_alloc_destroy(cs->bucket_alloc);
            apr_pool_clear(p);
            ap_push_pool(worker_queue_info, p);
            return;
        }
        apr_atomic_inc32(&connection_count);
        apr_pool_cleanup_register(c->pool, cs, decrement_connection_count,
                                  apr_pool_cleanup_null);
        ap_set_module_config(c->conn_config, &mpm_event_module, cs);
        c->current_thread = thd;
        cs->c = c;
        c->cs = &(cs->pub);
        cs->p = p;
        cs->pfd.desc_type = APR_POLL_SOCKET;
        cs->pfd.reqevents = APR_POLLIN;
        cs->pfd.desc.s = sock;
        pt->type = PT_CSD;
        pt->baton = cs;
        cs->pfd.client_data = pt;
        apr_pool_pre_cleanup_register(p, cs, ptrans_pre_cleanup);
        TO_QUEUE_ELEM_INIT(cs);

        ap_update_vhost_given_ip(c);

        rc = ap_run_pre_connection(c, sock);
        if (rc != OK && rc != DONE) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(00469)
                          "process_socket: connection aborted");
            c->aborted = 1;
        }

        /**
         * XXX If the platform does not have a usable way of bundling
         * accept() with a socket readability check, like Win32,
         * and there are measurable delays before the
         * socket is readable due to the first data packet arriving,
         * it might be better to create the cs on the listener thread
         * with the state set to CONN_STATE_CHECK_REQUEST_LINE_READABLE
         *
         * FreeBSD users will want to enable the HTTP accept filter
         * module in their kernel for the highest performance
         * When the accept filter is active, sockets are kept in the
         * kernel until a HTTP request is received.
         */
        cs->pub.state = CONN_STATE_READ_REQUEST_LINE;

        cs->pub.sense = CONN_SENSE_DEFAULT;
    }
    else {
        c = cs->c;
        c->sbh = sbh;
        notify_resume(cs);
        c->current_thread = thd;
    }

    if (c->clogging_input_filters && !c->aborted) {
        /* Since we have an input filter which 'clogs' the input stream,
         * like mod_ssl used to, lets just do the normal read from input
         * filters, like the Worker MPM does. Filters that need to write
         * where they would otherwise read, or read where they would
         * otherwise write, should set the sense appropriately.
         */
        apr_atomic_inc32(&clogged_count);
        ap_run_process_connection(c);
        if (cs->pub.state != CONN_STATE_SUSPENDED) {
            cs->pub.state = CONN_STATE_LINGER;
        }
        apr_atomic_dec32(&clogged_count);
    }

read_request:
    if (cs->pub.state == CONN_STATE_READ_REQUEST_LINE) {
        if (!c->aborted) {
            ap_run_process_connection(c);

            /* state will be updated upon return
             * fall thru to either wait for readability/timeout or
             * do lingering close
             */
        }
        else {
            cs->pub.state = CONN_STATE_LINGER;
        }
    }

    if (cs->pub.state == CONN_STATE_WRITE_COMPLETION) {
        ap_filter_t *output_filter = c->output_filters;
        apr_status_t rv;
        ap_update_child_status_from_conn(sbh, SERVER_BUSY_WRITE, c);
        while (output_filter->next != NULL) {
            output_filter = output_filter->next;
        }
        rv = output_filter->frec->filter_func.out_func(output_filter, NULL);
        if (rv != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO(00470)
                          "network write failure in core output filter");
            cs->pub.state = CONN_STATE_LINGER;
        }
        else if (c->data_in_output_filters) {
            /* Still in WRITE_COMPLETION_STATE:
             * Set a write timeout for this connection, and let the
             * event thread poll for writeability.
             */
            cs->expiration_time = ap_server_conf->timeout + apr_time_now();
            notify_suspend(cs);
            apr_thread_mutex_lock(timeout_mutex);
            TO_QUEUE_APPEND(write_completion_q, cs);
            cs->pfd.reqevents = (
                    cs->pub.sense == CONN_SENSE_WANT_READ ? APR_POLLIN :
                            APR_POLLOUT) | APR_POLLHUP | APR_POLLERR;
            cs->pub.sense = CONN_SENSE_DEFAULT;
            rc = apr_pollset_add(event_pollset, &cs->pfd);
            apr_thread_mutex_unlock(timeout_mutex);
            return;
        }
        else if (c->keepalive != AP_CONN_KEEPALIVE || c->aborted ||
            listener_may_exit) {
            cs->pub.state = CONN_STATE_LINGER;
        }
        else if (c->data_in_input_filters) {
            cs->pub.state = CONN_STATE_READ_REQUEST_LINE;
            goto read_request;
        }
        else {
            cs->pub.state = CONN_STATE_CHECK_REQUEST_LINE_READABLE;
        }
    }

    if (cs->pub.state == CONN_STATE_LINGER) {
        start_lingering_close_blocking(cs);
        notify_suspend(cs);
    }
    else if (cs->pub.state == CONN_STATE_CHECK_REQUEST_LINE_READABLE) {
        /* It greatly simplifies the logic to use a single timeout value here
         * because the new element can just be added to the end of the list and
         * it will stay sorted in expiration time sequence.  If brand new
         * sockets are sent to the event thread for a readability check, this
         * will be a slight behavior change - they use the non-keepalive
         * timeout today.  With a normal client, the socket will be readable in
         * a few milliseconds anyway.
         */
        cs->expiration_time = ap_server_conf->keep_alive_timeout +
                              apr_time_now();
        c->sbh = NULL;
        notify_suspend(cs);
        apr_thread_mutex_lock(timeout_mutex);
        TO_QUEUE_APPEND(keepalive_q, cs);

        /* Add work to pollset. */
        cs->pfd.reqevents = APR_POLLIN;
        rc = apr_pollset_add(event_pollset, &cs->pfd);
        apr_thread_mutex_unlock(timeout_mutex);

        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, ap_server_conf,
                         "process_socket: apr_pollset_add failure");
            AP_DEBUG_ASSERT(rc == APR_SUCCESS);
        }
    }
    else if (cs->pub.state == CONN_STATE_SUSPENDED) {
        apr_atomic_inc32(&suspended_count);
        c->sbh = NULL;
        notify_suspend(cs);
    }
}

/* conns_this_child has gone to zero or below.  See if the admin coded
   "MaxConnectionsPerChild 0", and keep going in that case.  Doing it this way
   simplifies the hot path in worker_thread */
static void check_infinite_requests(void)
{
    if (ap_max_requests_per_child) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "Stopping process due to MaxConnectionsPerChild");
        signal_threads(ST_GRACEFUL);
    }
    else {
        /* keep going */
        conns_this_child = APR_INT32_MAX;
    }
}

static void close_listeners(int process_slot, int *closed) {
    if (!*closed) {
        int i;
        disable_listensocks(process_slot);
        ap_close_listeners();
        *closed = 1;
        dying = 1;
        ap_scoreboard_image->parent[process_slot].quiescing = 1;
        for (i = 0; i < threads_per_child; ++i) {
            ap_update_child_status_from_indexes(process_slot, i,
                                                SERVER_GRACEFUL, NULL);
        }
        /* wake up the main thread */
        kill(ap_my_pid, SIGTERM);
    }
}

static void unblock_signal(int sig)
{
    sigset_t sig_mask;

    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, sig);
#if defined(SIGPROCMASK_SETS_THREAD_MASK)
    sigprocmask(SIG_UNBLOCK, &sig_mask, NULL);
#else
    pthread_sigmask(SIG_UNBLOCK, &sig_mask, NULL);
#endif
}

static void dummy_signal_handler(int sig)
{
    /* XXX If specifying SIG_IGN is guaranteed to unblock a syscall,
     *     then we don't need this goofy function.
     */
}


static apr_status_t init_pollset(apr_pool_t *p)
{
    ap_listen_rec *lr;
    listener_poll_type *pt;
    int i = 0;

    TO_QUEUE_INIT(write_completion_q);
    TO_QUEUE_INIT(keepalive_q);
    TO_QUEUE_INIT(linger_q);
    TO_QUEUE_INIT(short_linger_q);

    listener_pollfd = apr_palloc(p, sizeof(apr_pollfd_t) * num_listensocks);
    for (lr = ap_listeners; lr != NULL; lr = lr->next, i++) {
        apr_pollfd_t *pfd;
        AP_DEBUG_ASSERT(i < num_listensocks);
        pfd = &listener_pollfd[i];
        pt = apr_pcalloc(p, sizeof(*pt));
        pfd->desc_type = APR_POLL_SOCKET;
        pfd->desc.s = lr->sd;
        pfd->reqevents = APR_POLLIN;

        pt->type = PT_ACCEPT;
        pt->baton = lr;

        pfd->client_data = pt;

        apr_socket_opt_set(pfd->desc.s, APR_SO_NONBLOCK, 1);
        apr_pollset_add(event_pollset, pfd);

        lr->accept_func = ap_unixd_accept;
    }

    return APR_SUCCESS;
}

static apr_status_t push_timer2worker(timer_event_t* te)
{
    return ap_queue_push_timer(worker_queue, te);
}

/*
 * Pre-condition: pfd->cs is neither in pollset nor timeout queue
 * this function may only be called by the listener
 */
static apr_status_t push2worker(const apr_pollfd_t * pfd,
                                apr_pollset_t * pollset)
{
    listener_poll_type *pt = (listener_poll_type *) pfd->client_data;
    event_conn_state_t *cs = (event_conn_state_t *) pt->baton;
    apr_status_t rc;

    rc = ap_queue_push(worker_queue, cs->pfd.desc.s, cs, cs->p);
    if (rc != APR_SUCCESS) {
        /* trash the connection; we couldn't queue the connected
         * socket to a worker
         */
        apr_bucket_alloc_destroy(cs->bucket_alloc);
        apr_socket_close(cs->pfd.desc.s);
        ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                     ap_server_conf, APLOGNO(00471) "push2worker: ap_queue_push failed");
        apr_pool_clear(cs->p);
        ap_push_pool(worker_queue_info, cs->p);
    }

    return rc;
}

/* get_worker:
 *     If *have_idle_worker_p == 0, reserve a worker thread, and set
 *     *have_idle_worker_p = 1.
 *     If *have_idle_worker_p is already 1, will do nothing.
 *     If blocking == 1, block if all workers are currently busy.
 *     If no worker was available immediately, will set *all_busy to 1.
 *     XXX: If there are no workers, we should not block immediately but
 *     XXX: close all keep-alive connections first.
 */
static void get_worker(int *have_idle_worker_p, int blocking, int *all_busy)
{
    apr_status_t rc;

    if (*have_idle_worker_p) {
        /* already reserved a worker thread - must have hit a
         * transient error on a previous pass
         */
        return;
    }

    if (blocking)
        rc = ap_queue_info_wait_for_idler(worker_queue_info, all_busy);
    else
        rc = ap_queue_info_try_get_idler(worker_queue_info);

    if (rc == APR_SUCCESS) {
        *have_idle_worker_p = 1;
    }
    else if (!blocking && rc == APR_EAGAIN) {
        *all_busy = 1;
    }
    else if (!APR_STATUS_IS_EOF(rc)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ap_server_conf, APLOGNO(00472)
                     "ap_queue_info_wait_for_idler failed.  "
                     "Attempting to shutdown process gracefully");
        signal_threads(ST_GRACEFUL);
    }
}

/* Structures to reuse */
static APR_RING_HEAD(timer_free_ring_t, timer_event_t) timer_free_ring;

static apr_skiplist *timer_skiplist;

static int indexing_comp(void *a, void *b)
{
    apr_time_t t1 = (apr_time_t) (((timer_event_t *) a)->when);
    apr_time_t t2 = (apr_time_t) (((timer_event_t *) b)->when);
    AP_DEBUG_ASSERT(t1);
    AP_DEBUG_ASSERT(t2);
    return ((t1 < t2) ? -1 : ((t1 > t2) ? 1 : 0));
}

static int indexing_compk(void *ac, void *b)
{
    apr_time_t *t1 = (apr_time_t *) ac;
    apr_time_t t2 = (apr_time_t) (((timer_event_t *) b)->when);
    AP_DEBUG_ASSERT(t2);
    return ((*t1 < t2) ? -1 : ((*t1 > t2) ? 1 : 0));
}

static apr_thread_mutex_t *g_timer_skiplist_mtx;

static apr_status_t event_register_timed_callback(apr_time_t t,
                                                  ap_mpm_callback_fn_t *cbfn,
                                                  void *baton)
{
    timer_event_t *te;
    /* oh yeah, and make locking smarter/fine grained. */
    apr_thread_mutex_lock(g_timer_skiplist_mtx);

    if (!APR_RING_EMPTY(&timer_free_ring, timer_event_t, link)) {
        te = APR_RING_FIRST(&timer_free_ring);
        APR_RING_REMOVE(te, link);
    }
    else {
        te = apr_skiplist_alloc(timer_skiplist, sizeof(timer_event_t));
        APR_RING_ELEM_INIT(te, link);
    }

    te->cbfunc = cbfn;
    te->baton = baton;
    /* XXXXX: optimize */
    te->when = t + apr_time_now();

    /* Okay, insert sorted by when.. */
    apr_skiplist_insert(timer_skiplist, (void *)te);

    apr_thread_mutex_unlock(g_timer_skiplist_mtx);

    return APR_SUCCESS;
}


/*
 * Close socket and clean up if remote closed its end while we were in
 * lingering close.
 * Only to be called in the listener thread;
 * Pre-condition: cs is in one of the linger queues and in the pollset
 */
static void process_lingering_close(event_conn_state_t *cs, const apr_pollfd_t *pfd)
{
    apr_socket_t *csd = ap_get_conn_socket(cs->c);
    char dummybuf[2048];
    apr_size_t nbytes;
    apr_status_t rv;
    struct timeout_queue *q;
    q = (cs->pub.state == CONN_STATE_LINGER_SHORT) ?  &short_linger_q : &linger_q;

    /* socket is already in non-blocking state */
    do {
        nbytes = sizeof(dummybuf);
        rv = apr_socket_recv(csd, dummybuf, &nbytes);
    } while (rv == APR_SUCCESS);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        return;
    }

    apr_thread_mutex_lock(timeout_mutex);
    rv = apr_pollset_remove(event_pollset, pfd);
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    rv = apr_socket_close(csd);
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    TO_QUEUE_REMOVE(*q, cs);
    apr_thread_mutex_unlock(timeout_mutex);
    TO_QUEUE_ELEM_INIT(cs);

    apr_pool_clear(cs->p);
    ap_push_pool(worker_queue_info, cs->p);
}

/* call 'func' for all elements of 'q' with timeout less than 'timeout_time'.
 * Pre-condition: timeout_mutex must already be locked
 * Post-condition: timeout_mutex will be locked again
 */
static void process_timeout_queue(struct timeout_queue *q,
                                  apr_time_t timeout_time,
                                  int (*func)(event_conn_state_t *))
{
    int count = 0;
    event_conn_state_t *first, *cs, *last;
    apr_status_t rv;
    if (!q->count) {
        return;
    }
    AP_DEBUG_ASSERT(!APR_RING_EMPTY(&q->head, event_conn_state_t, timeout_list));

    cs = first = APR_RING_FIRST(&q->head);
    while (cs != APR_RING_SENTINEL(&q->head, event_conn_state_t, timeout_list)
           && cs->expiration_time < timeout_time) {
        last = cs;
        rv = apr_pollset_remove(event_pollset, &cs->pfd);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rv)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, cs->c, APLOGNO(00473)
                          "apr_pollset_remove failed");
        }
        cs = APR_RING_NEXT(cs, timeout_list);
        count++;
    }
    if (!count)
        return;

    APR_RING_UNSPLICE(first, last, timeout_list);
    AP_DEBUG_ASSERT(q->count >= count);
    q->count -= count;
    apr_thread_mutex_unlock(timeout_mutex);
    while (count) {
        cs = APR_RING_NEXT(first, timeout_list);
        TO_QUEUE_ELEM_INIT(first);
        func(first);
        first = cs;
        count--;
    }
    apr_thread_mutex_lock(timeout_mutex);
}

static void * APR_THREAD_FUNC listener_thread(apr_thread_t * thd, void *dummy)
{
    timer_event_t *ep;
    timer_event_t *te;
    apr_status_t rc;
    proc_info *ti = dummy;
    int process_slot = ti->pid;
    apr_pool_t *tpool = apr_thread_pool_get(thd);
    void *csd = NULL;
    apr_pool_t *ptrans;         /* Pool for per-transaction stuff */
    ap_listen_rec *lr;
    int have_idle_worker = 0;
    event_conn_state_t *cs;
    const apr_pollfd_t *out_pfd;
    apr_int32_t num = 0;
    apr_interval_time_t timeout_interval;
    apr_time_t timeout_time = 0, now, last_log;
    listener_poll_type *pt;
    int closed = 0, listeners_disabled = 0;

    last_log = apr_time_now();
    free(ti);

    /* the following times out events that are really close in the future
     *   to prevent extra poll calls
     *
     * current value is .1 second
     */
#define TIMEOUT_FUDGE_FACTOR 100000
#define EVENT_FUDGE_FACTOR 10000

    rc = init_pollset(tpool);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ap_server_conf,
                     "failed to initialize pollset, "
                     "attempting to shutdown process gracefully");
        signal_threads(ST_GRACEFUL);
        return NULL;
    }

    /* Unblock the signal used to wake this thread up, and set a handler for
     * it.
     */
    unblock_signal(LISTENER_SIGNAL);
    apr_signal(LISTENER_SIGNAL, dummy_signal_handler);

    for (;;) {
        int workers_were_busy = 0;
        if (listener_may_exit) {
            close_listeners(process_slot, &closed);
            if (terminate_mode == ST_UNGRACEFUL
                || apr_atomic_read32(&connection_count) == 0)
                break;
        }

        if (conns_this_child <= 0)
            check_infinite_requests();

        now = apr_time_now();
        if (APLOGtrace6(ap_server_conf)) {
            /* trace log status every second */
            if (now - last_log > apr_time_from_msec(1000)) {
                last_log = now;
                apr_thread_mutex_lock(timeout_mutex);
                ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                             "connections: %u (clogged: %u write-completion: %d "
                             "keep-alive: %d lingering: %d suspended: %u)",
                             apr_atomic_read32(&connection_count),
                             apr_atomic_read32(&clogged_count),
                             write_completion_q.count,
                             keepalive_q.count,
                             apr_atomic_read32(&lingering_count),
                             apr_atomic_read32(&suspended_count));
                apr_thread_mutex_unlock(timeout_mutex);
            }
        }

        apr_thread_mutex_lock(g_timer_skiplist_mtx);
        te = apr_skiplist_peek(timer_skiplist);
        if (te) {
            if (te->when > now) {
                timeout_interval = te->when - now;
            }
            else {
                timeout_interval = 1;
            }
        }
        else {
            timeout_interval = apr_time_from_msec(100);
        }
        apr_thread_mutex_unlock(g_timer_skiplist_mtx);

        rc = apr_pollset_poll(event_pollset, timeout_interval, &num, &out_pfd);
        if (rc != APR_SUCCESS) {
            if (APR_STATUS_IS_EINTR(rc)) {
                continue;
            }
            if (!APR_STATUS_IS_TIMEUP(rc)) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rc, ap_server_conf,
                             "apr_pollset_poll failed.  Attempting to "
                             "shutdown process gracefully");
                signal_threads(ST_GRACEFUL);
            }
        }

        if (listener_may_exit) {
            close_listeners(process_slot, &closed);
            if (terminate_mode == ST_UNGRACEFUL
                || apr_atomic_read32(&connection_count) == 0)
                break;
        }

        now = apr_time_now();
        apr_thread_mutex_lock(g_timer_skiplist_mtx);
        ep = apr_skiplist_peek(timer_skiplist);
        while (ep) {
            if (ep->when < now + EVENT_FUDGE_FACTOR) {
                apr_skiplist_pop(timer_skiplist, NULL);
                push_timer2worker(ep);
            }
            else {
                break;
            }
            ep = apr_skiplist_peek(timer_skiplist);
        }
        apr_thread_mutex_unlock(g_timer_skiplist_mtx);

        while (num) {
            pt = (listener_poll_type *) out_pfd->client_data;
            if (pt->type == PT_CSD) {
                /* one of the sockets is readable */
                struct timeout_queue *remove_from_q = &write_completion_q;
                int blocking = 1;
                cs = (event_conn_state_t *) pt->baton;
                switch (cs->pub.state) {
                case CONN_STATE_CHECK_REQUEST_LINE_READABLE:
                    cs->pub.state = CONN_STATE_READ_REQUEST_LINE;
                    remove_from_q = &keepalive_q;
                    /* don't wait for a worker for a keepalive request */
                    blocking = 0;
                    /* FALL THROUGH */
                case CONN_STATE_WRITE_COMPLETION:
                    get_worker(&have_idle_worker, blocking,
                               &workers_were_busy);
                    apr_thread_mutex_lock(timeout_mutex);
                    TO_QUEUE_REMOVE(*remove_from_q, cs);
                    rc = apr_pollset_remove(event_pollset, &cs->pfd);

                    /*
                     * Some of the pollset backends, like KQueue or Epoll
                     * automagically remove the FD if the socket is closed,
                     * therefore, we can accept _SUCCESS or _NOTFOUND,
                     * and we still want to keep going
                     */
                    if (rc != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rc)) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, rc, ap_server_conf,
                                     "pollset remove failed");
                        apr_thread_mutex_unlock(timeout_mutex);
                        start_lingering_close_nonblocking(cs);
                        break;
                    }

                    apr_thread_mutex_unlock(timeout_mutex);
                    TO_QUEUE_ELEM_INIT(cs);
                    /* If we didn't get a worker immediately for a keep-alive
                     * request, we close the connection, so that the client can
                     * re-connect to a different process.
                     */
                    if (!have_idle_worker) {
                        start_lingering_close_nonblocking(cs);
                        break;
                    }
                    rc = push2worker(out_pfd, event_pollset);
                    if (rc != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                     ap_server_conf, "push2worker failed");
                    }
                    else {
                        have_idle_worker = 0;
                    }
                    break;
                case CONN_STATE_LINGER_NORMAL:
                case CONN_STATE_LINGER_SHORT:
                    process_lingering_close(cs, out_pfd);
                    break;
                default:
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                 ap_server_conf,
                                 "event_loop: unexpected state %d",
                                 cs->pub.state);
                    ap_assert(0);
                }
            }
            else if (pt->type == PT_ACCEPT) {
                /* A Listener Socket is ready for an accept() */
                if (workers_were_busy) {
                    if (!listeners_disabled)
                        disable_listensocks(process_slot);
                    listeners_disabled = 1;
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                                 "All workers busy, not accepting new conns "
                                 "in this process");
                }
                else if (  (int)apr_atomic_read32(&connection_count)
                           - (int)apr_atomic_read32(&lingering_count)
                         > threads_per_child
                           + ap_queue_info_get_idlers(worker_queue_info) *
                             worker_factor / WORKER_FACTOR_SCALE)
                {
                    if (!listeners_disabled)
                        disable_listensocks(process_slot);
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                                 "Too many open connections (%u), "
                                 "not accepting new conns in this process",
                                 apr_atomic_read32(&connection_count));
                    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                                 "Idle workers: %u",
                                 ap_queue_info_get_idlers(worker_queue_info));
                    listeners_disabled = 1;
                }
                else if (listeners_disabled) {
                    listeners_disabled = 0;
                    enable_listensocks(process_slot);
                }
                if (!listeners_disabled) {
                    lr = (ap_listen_rec *) pt->baton;
                    ap_pop_pool(&ptrans, worker_queue_info);

                    if (ptrans == NULL) {
                        /* create a new transaction pool for each accepted socket */
                        apr_allocator_t *allocator;

                        apr_allocator_create(&allocator);
                        apr_allocator_max_free_set(allocator,
                                                   ap_max_mem_free);
                        apr_pool_create_ex(&ptrans, pconf, NULL, allocator);
                        apr_allocator_owner_set(allocator, ptrans);
                        if (ptrans == NULL) {
                            ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                         ap_server_conf,
                                         "Failed to create transaction pool");
                            signal_threads(ST_GRACEFUL);
                            return NULL;
                        }
                    }
                    apr_pool_tag(ptrans, "transaction");

                    get_worker(&have_idle_worker, 1, &workers_were_busy);
                    rc = lr->accept_func(&csd, lr, ptrans);

                    /* later we trash rv and rely on csd to indicate
                     * success/failure
                     */
                    AP_DEBUG_ASSERT(rc == APR_SUCCESS || !csd);

                    if (rc == APR_EGENERAL) {
                        /* E[NM]FILE, ENOMEM, etc */
                        resource_shortage = 1;
                        signal_threads(ST_GRACEFUL);
                    }

                    if (csd != NULL) {
                        conns_this_child--;
                        rc = ap_queue_push(worker_queue, csd, NULL, ptrans);
                        if (rc != APR_SUCCESS) {
                            /* trash the connection; we couldn't queue the connected
                             * socket to a worker
                             */
                            apr_socket_close(csd);
                            ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                         ap_server_conf,
                                         "ap_queue_push failed");
                            apr_pool_clear(ptrans);
                            ap_push_pool(worker_queue_info, ptrans);
                        }
                        else {
                            have_idle_worker = 0;
                        }
                    }
                    else {
                        apr_pool_clear(ptrans);
                        ap_push_pool(worker_queue_info, ptrans);
                    }
                }
            }               /* if:else on pt->type */
            out_pfd++;
            num--;
        }                   /* while for processing poll */

        /* XXX possible optimization: stash the current time for use as
         * r->request_time for new requests
         */
        now = apr_time_now();
        /* we only do this once per 0.1s (TIMEOUT_FUDGE_FACTOR) */
        if (now > timeout_time) {
            struct process_score *ps;
            timeout_time = now + TIMEOUT_FUDGE_FACTOR;

            /* handle timed out sockets */
            apr_thread_mutex_lock(timeout_mutex);

            /* Step 1: keepalive timeouts */
            /* If all workers are busy, we kill older keep-alive connections so that they
             * may connect to another process.
             */
            if (workers_were_busy && keepalive_q.count) {
                ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                             "All workers are busy, will close %d keep-alive "
                             "connections",
                             keepalive_q.count);
                process_timeout_queue(&keepalive_q,
                                      timeout_time + ap_server_conf->keep_alive_timeout,
                                      start_lingering_close_nonblocking);
            }
            else {
                process_timeout_queue(&keepalive_q, timeout_time,
                                      start_lingering_close_nonblocking);
            }
            /* Step 2: write completion timeouts */
            process_timeout_queue(&write_completion_q, timeout_time,
                                  start_lingering_close_nonblocking);
            /* Step 3: (normal) lingering close completion timeouts */
            process_timeout_queue(&linger_q, timeout_time, stop_lingering_close);
            /* Step 4: (short) lingering close completion timeouts */
            process_timeout_queue(&short_linger_q, timeout_time, stop_lingering_close);

            ps = ap_get_scoreboard_process(process_slot);
            ps->write_completion = write_completion_q.count;
            ps->keep_alive = keepalive_q.count;
            apr_thread_mutex_unlock(timeout_mutex);

            ps->connections = apr_atomic_read32(&connection_count);
            ps->suspended = apr_atomic_read32(&suspended_count);
            ps->lingering_close = apr_atomic_read32(&lingering_count);
        }
        if (listeners_disabled && !workers_were_busy
            && (int)apr_atomic_read32(&connection_count)
               - (int)apr_atomic_read32(&lingering_count)
               < ((int)ap_queue_info_get_idlers(worker_queue_info) - 1)
                 * worker_factor / WORKER_FACTOR_SCALE + threads_per_child)
        {
            listeners_disabled = 0;
            enable_listensocks(process_slot);
        }
        /*
         * XXX: do we need to set some timeout that re-enables the listensocks
         * XXX: in case no other event occurs?
         */
    }     /* listener main loop */

    close_listeners(process_slot, &closed);
    ap_queue_term(worker_queue);

    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

/* XXX For ungraceful termination/restart, we definitely don't want to
 *     wait for active connections to finish but we may want to wait
 *     for idle workers to get out of the queue code and release mutexes,
 *     since those mutexes are cleaned up pretty soon and some systems
 *     may not react favorably (i.e., segfault) if operations are attempted
 *     on cleaned-up mutexes.
 */
static void *APR_THREAD_FUNC worker_thread(apr_thread_t * thd, void *dummy)
{
    proc_info *ti = dummy;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    apr_socket_t *csd = NULL;
    event_conn_state_t *cs;
    apr_pool_t *ptrans;         /* Pool for per-transaction stuff */
    apr_status_t rv;
    int is_idle = 0;
    timer_event_t *te = NULL;

    free(ti);

    ap_scoreboard_image->servers[process_slot][thread_slot].pid = ap_my_pid;
    ap_scoreboard_image->servers[process_slot][thread_slot].tid = apr_os_thread_current();
    ap_scoreboard_image->servers[process_slot][thread_slot].generation = retained->my_generation;
    ap_update_child_status_from_indexes(process_slot, thread_slot,
                                        SERVER_STARTING, NULL);

    while (!workers_may_exit) {
        if (!is_idle) {
            rv = ap_queue_info_set_idle(worker_queue_info, NULL);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "ap_queue_info_set_idle failed. Attempting to "
                             "shutdown process gracefully.");
                signal_threads(ST_GRACEFUL);
                break;
            }
            is_idle = 1;
        }

        ap_update_child_status_from_indexes(process_slot, thread_slot,
                                            dying ? SERVER_GRACEFUL : SERVER_READY, NULL);
      worker_pop:
        if (workers_may_exit) {
            break;
        }

        te = NULL;
        rv = ap_queue_pop_something(worker_queue, &csd, &cs, &ptrans, &te);

        if (rv != APR_SUCCESS) {
            /* We get APR_EOF during a graceful shutdown once all the
             * connections accepted by this server process have been handled.
             */
            if (APR_STATUS_IS_EOF(rv)) {
                break;
            }
            /* We get APR_EINTR whenever ap_queue_pop() has been interrupted
             * from an explicit call to ap_queue_interrupt_all(). This allows
             * us to unblock threads stuck in ap_queue_pop() when a shutdown
             * is pending.
             *
             * If workers_may_exit is set and this is ungraceful termination/
             * restart, we are bound to get an error on some systems (e.g.,
             * AIX, which sanity-checks mutex operations) since the queue
             * may have already been cleaned up.  Don't log the "error" if
             * workers_may_exit is set.
             */
            else if (APR_STATUS_IS_EINTR(rv)) {
                goto worker_pop;
            }
            /* We got some other error. */
            else if (!workers_may_exit) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                             "ap_queue_pop failed");
            }
            continue;
        }
        if (te != NULL) {
            te->cbfunc(te->baton);

            {
                apr_thread_mutex_lock(g_timer_skiplist_mtx);
                APR_RING_INSERT_TAIL(&timer_free_ring, te, timer_event_t, link);
                apr_thread_mutex_unlock(g_timer_skiplist_mtx);
            }
        }
        else {
            is_idle = 0;
            worker_sockets[thread_slot] = csd;
            process_socket(thd, ptrans, csd, cs, process_slot, thread_slot);
            worker_sockets[thread_slot] = NULL;
        }
    }

    ap_update_child_status_from_indexes(process_slot, thread_slot,
                                        dying ? SERVER_DEAD :
                                        SERVER_GRACEFUL,
                                        (request_rec *) NULL);

    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static int check_signal(int signum)
{
    switch (signum) {
    case SIGTERM:
    case SIGINT:
        return 1;
    }
    return 0;
}



static void create_listener_thread(thread_starter * ts)
{
    int my_child_num = ts->child_num_arg;
    apr_threadattr_t *thread_attr = ts->threadattr;
    proc_info *my_info;
    apr_status_t rv;

    my_info = (proc_info *) ap_malloc(sizeof(proc_info));
    my_info->pid = my_child_num;
    my_info->tid = -1;          /* listener thread doesn't have a thread slot */
    my_info->sd = 0;
    rv = apr_thread_create(&ts->listener, thread_attr, listener_thread,
                           my_info, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(00474)
                     "apr_thread_create: unable to create listener thread");
        /* let the parent decide how bad this really is */
        clean_child_exit(APEXIT_CHILDSICK);
    }
    apr_os_thread_get(&listener_os_thread, ts->listener);
}

/* XXX under some circumstances not understood, children can get stuck
 *     in start_threads forever trying to take over slots which will
 *     never be cleaned up; for now there is an APLOG_DEBUG message issued
 *     every so often when this condition occurs
 */
static void *APR_THREAD_FUNC start_threads(apr_thread_t * thd, void *dummy)
{
    thread_starter *ts = dummy;
    apr_thread_t **threads = ts->threads;
    apr_threadattr_t *thread_attr = ts->threadattr;
    int child_num_arg = ts->child_num_arg;
    int my_child_num = child_num_arg;
    proc_info *my_info;
    apr_status_t rv;
    int i;
    int threads_created = 0;
    int listener_started = 0;
    int loops;
    int prev_threads_created;
    int max_recycled_pools = -1;
    int good_methods[] = {APR_POLLSET_KQUEUE, APR_POLLSET_PORT, APR_POLLSET_EPOLL};

    /* We must create the fd queues before we start up the listener
     * and worker threads. */
    worker_queue = apr_pcalloc(pchild, sizeof(*worker_queue));
    rv = ap_queue_init(worker_queue, threads_per_child, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
                     "ap_queue_init() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (ap_max_mem_free != APR_ALLOCATOR_MAX_FREE_UNLIMITED) {
        /* If we want to conserve memory, let's not keep an unlimited number of
         * pools & allocators.
         * XXX: This should probably be a separate config directive
         */
        max_recycled_pools = threads_per_child * 3 / 4 ;
    }
    rv = ap_queue_info_create(&worker_queue_info, pchild,
                              threads_per_child, max_recycled_pools);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
                     "ap_queue_info_create() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Create the timeout mutex and main pollset before the listener
     * thread starts.
     */
    rv = apr_thread_mutex_create(&timeout_mutex, APR_THREAD_MUTEX_DEFAULT,
                                 pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                     "creation of the timeout mutex failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Create the main pollset */
    for (i = 0; i < sizeof(good_methods) / sizeof(void*); i++) {
        rv = apr_pollset_create_ex(&event_pollset,
                            threads_per_child*2, /* XXX don't we need more, to handle
                                                * connections in K-A or lingering
                                                * close?
                                                */
                            pchild, APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY | APR_POLLSET_NODEFAULT,
                            good_methods[i]);
        if (rv == APR_SUCCESS) {
            break;
        }
    }
    if (rv != APR_SUCCESS) {
        rv = apr_pollset_create(&event_pollset,
                               threads_per_child*2, /* XXX don't we need more, to handle
                                                     * connections in K-A or lingering
                                                     * close?
                                                     */
                               pchild, APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY);
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                     "apr_pollset_create with Thread Safety failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02471)
                 "start_threads: Using %s", apr_pollset_method_name(event_pollset));
    worker_sockets = apr_pcalloc(pchild, threads_per_child
                                 * sizeof(apr_socket_t *));

    loops = prev_threads_created = 0;
    while (1) {
        /* threads_per_child does not include the listener thread */
        for (i = 0; i < threads_per_child; i++) {
            int status =
                ap_scoreboard_image->servers[child_num_arg][i].status;

            if (status != SERVER_GRACEFUL && status != SERVER_DEAD) {
                continue;
            }

            my_info = (proc_info *) ap_malloc(sizeof(proc_info));
            my_info->pid = my_child_num;
            my_info->tid = i;
            my_info->sd = 0;

            /* We are creating threads right now */
            ap_update_child_status_from_indexes(my_child_num, i,
                                                SERVER_STARTING, NULL);
            /* We let each thread update its own scoreboard entry.  This is
             * done because it lets us deal with tid better.
             */
            rv = apr_thread_create(&threads[i], thread_attr,
                                   worker_thread, my_info, pchild);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
                             "apr_thread_create: unable to create worker thread");
                /* let the parent decide how bad this really is */
                clean_child_exit(APEXIT_CHILDSICK);
            }
            threads_created++;
        }

        /* Start the listener only when there are workers available */
        if (!listener_started && threads_created) {
            create_listener_thread(ts);
            listener_started = 1;
        }


        if (start_thread_may_exit || threads_created == threads_per_child) {
            break;
        }
        /* wait for previous generation to clean up an entry */
        apr_sleep(apr_time_from_sec(1));
        ++loops;
        if (loops % 120 == 0) { /* every couple of minutes */
            if (prev_threads_created == threads_created) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                             "child %" APR_PID_T_FMT " isn't taking over "
                             "slots very quickly (%d of %d)",
                             ap_my_pid, threads_created,
                             threads_per_child);
            }
            prev_threads_created = threads_created;
        }
    }

    /* What state should this child_main process be listed as in the
     * scoreboard...?
     *  ap_update_child_status_from_indexes(my_child_num, i, SERVER_STARTING,
     *                                      (request_rec *) NULL);
     *
     *  This state should be listed separately in the scoreboard, in some kind
     *  of process_status, not mixed in with the worker threads' status.
     *  "life_status" is almost right, but it's in the worker's structure, and
     *  the name could be clearer.   gla
     */
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static void join_workers(apr_thread_t * listener, apr_thread_t ** threads)
{
    int i;
    apr_status_t rv, thread_rv;

    if (listener) {
        int iter;

        /* deal with a rare timing window which affects waking up the
         * listener thread...  if the signal sent to the listener thread
         * is delivered between the time it verifies that the
         * listener_may_exit flag is clear and the time it enters a
         * blocking syscall, the signal didn't do any good...  work around
         * that by sleeping briefly and sending it again
         */

        iter = 0;
        while (iter < 10 && !dying) {
            /* listener has not stopped accepting yet */
            apr_sleep(apr_time_make(0, 500000));
            wakeup_listener();
            ++iter;
        }
        if (iter >= 10) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(00475)
                         "the listener thread didn't stop accepting");
        }
        else {
            rv = apr_thread_join(&thread_rv, listener);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00476)
                             "apr_thread_join: unable to join listener thread");
            }
        }
    }

    for (i = 0; i < threads_per_child; i++) {
        if (threads[i]) {       /* if we ever created this thread */
            rv = apr_thread_join(&thread_rv, threads[i]);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00477)
                             "apr_thread_join: unable to join worker "
                             "thread %d", i);
            }
        }
    }
}

static void join_start_thread(apr_thread_t * start_thread_id)
{
    apr_status_t rv, thread_rv;

    start_thread_may_exit = 1;  /* tell it to give up in case it is still
                                 * trying to take over slots from a
                                 * previous generation
                                 */
    rv = apr_thread_join(&thread_rv, start_thread_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00478)
                     "apr_thread_join: unable to join the start " "thread");
    }
}

static void child_main(int child_num_arg)
{
    apr_thread_t **threads;
    apr_status_t rv;
    thread_starter *ts;
    apr_threadattr_t *thread_attr;
    apr_thread_t *start_thread_id;

    mpm_state = AP_MPMQ_STARTING;       /* for benefit of any hooks that run as this
                                         * child initializes
                                         */
    ap_my_pid = getpid();
    ap_fatal_signal_child_setup(ap_server_conf);
    apr_pool_create(&pchild, pconf);

    /*stuff to do before we switch id's, so we have permissions. */
    ap_reopen_scoreboard(pchild, NULL, 0);

    if (ap_run_drop_privileges(pchild, ap_server_conf)) {
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    apr_thread_mutex_create(&g_timer_skiplist_mtx, APR_THREAD_MUTEX_DEFAULT, pchild);
    APR_RING_INIT(&timer_free_ring, timer_event_t, link);
    apr_skiplist_init(&timer_skiplist, pchild);
    apr_skiplist_set_compare(timer_skiplist, indexing_comp, indexing_compk);
    ap_run_child_init(pchild, ap_server_conf);

    /* done with init critical section */

    /* Just use the standard apr_setup_signal_thread to block all signals
     * from being received.  The child processes no longer use signals for
     * any communication with the parent process.
     */
    rv = apr_setup_signal_thread();
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(00479)
                     "Couldn't initialize signal thread");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (ap_max_requests_per_child) {
        conns_this_child = ap_max_requests_per_child;
    }
    else {
        /* coding a value of zero means infinity */
        conns_this_child = APR_INT32_MAX;
    }

    /* Setup worker threads */

    /* clear the storage; we may not create all our threads immediately,
     * and we want a 0 entry to indicate a thread which was not created
     */
    threads = ap_calloc(threads_per_child, sizeof(apr_thread_t *));
    ts = apr_palloc(pchild, sizeof(*ts));

    apr_threadattr_create(&thread_attr, pchild);
    /* 0 means PTHREAD_CREATE_JOINABLE */
    apr_threadattr_detach_set(thread_attr, 0);

    if (ap_thread_stacksize != 0) {
        rv = apr_threadattr_stacksize_set(thread_attr, ap_thread_stacksize);
        if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, APLOGNO(02436)
                         "WARNING: ThreadStackSize of %" APR_SIZE_T_FMT " is "
                         "inappropriate, using default", 
                         ap_thread_stacksize);
        }
    }

    ts->threads = threads;
    ts->listener = NULL;
    ts->child_num_arg = child_num_arg;
    ts->threadattr = thread_attr;

    rv = apr_thread_create(&start_thread_id, thread_attr, start_threads,
                           ts, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(00480)
                     "apr_thread_create: unable to create worker thread");
        /* let the parent decide how bad this really is */
        clean_child_exit(APEXIT_CHILDSICK);
    }

    mpm_state = AP_MPMQ_RUNNING;

    /* If we are only running in one_process mode, we will want to
     * still handle signals. */
    if (one_process) {
        /* Block until we get a terminating signal. */
        apr_signal_thread(check_signal);
        /* make sure the start thread has finished; signal_threads()
         * and join_workers() depend on that
         */
        /* XXX join_start_thread() won't be awakened if one of our
         *     threads encounters a critical error and attempts to
         *     shutdown this child
         */
        join_start_thread(start_thread_id);

        /* helps us terminate a little more quickly than the dispatch of the
         * signal thread; beats the Pipe of Death and the browsers
         */
        signal_threads(ST_UNGRACEFUL);

        /* A terminating signal was received. Now join each of the
         * workers to clean them up.
         *   If the worker already exited, then the join frees
         *   their resources and returns.
         *   If the worker hasn't exited, then this blocks until
         *   they have (then cleans up).
         */
        join_workers(ts->listener, threads);
    }
    else {                      /* !one_process */
        /* remove SIGTERM from the set of blocked signals...  if one of
         * the other threads in the process needs to take us down
         * (e.g., for MaxConnectionsPerChild) it will send us SIGTERM
         */
        unblock_signal(SIGTERM);
        apr_signal(SIGTERM, dummy_signal_handler);
        /* Watch for any messages from the parent over the POD */
        while (1) {
            rv = ap_mpm_podx_check(pod);
            if (rv == AP_MPM_PODX_NORESTART) {
                /* see if termination was triggered while we slept */
                switch (terminate_mode) {
                case ST_GRACEFUL:
                    rv = AP_MPM_PODX_GRACEFUL;
                    break;
                case ST_UNGRACEFUL:
                    rv = AP_MPM_PODX_RESTART;
                    break;
                }
            }
            if (rv == AP_MPM_PODX_GRACEFUL || rv == AP_MPM_PODX_RESTART) {
                /* make sure the start thread has finished;
                 * signal_threads() and join_workers depend on that
                 */
                join_start_thread(start_thread_id);
                signal_threads(rv ==
                               AP_MPM_PODX_GRACEFUL ? ST_GRACEFUL : ST_UNGRACEFUL);
                break;
            }
        }

        /* A terminating signal was received. Now join each of the
         * workers to clean them up.
         *   If the worker already exited, then the join frees
         *   their resources and returns.
         *   If the worker hasn't exited, then this blocks until
         *   they have (then cleans up).
         */
        join_workers(ts->listener, threads);
    }

    free(threads);

    clean_child_exit(resource_shortage ? APEXIT_CHILDSICK : 0);
}

static int make_child(server_rec * s, int slot)
{
    int pid;

    if (slot + 1 > retained->max_daemons_limit) {
        retained->max_daemons_limit = slot + 1;
    }

    if (one_process) {
        set_signals();
        event_note_child_started(slot, getpid());
        child_main(slot);
        /* NOTREACHED */
    }

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, APLOGNO(00481)
                     "fork: Unable to fork new process");

        /* fork didn't succeed.  There's no need to touch the scoreboard;
         * if we were trying to replace a failed child process, then
         * server_main_loop() marked its workers SERVER_DEAD, and if
         * we were trying to replace a child process that exited normally,
         * its worker_thread()s left SERVER_DEAD or SERVER_GRACEFUL behind.
         */

        /* In case system resources are maxxed out, we don't want
           Apache running away with the CPU trying to fork over and
           over and over again. */
        apr_sleep(apr_time_from_sec(10));

        return -1;
    }

    if (!pid) {
#ifdef HAVE_BINDPROCESSOR
        /* By default, AIX binds to a single processor.  This bit unbinds
         * children which will then bind to another CPU.
         */
        int status = bindprocessor(BINDPROCESS, (int) getpid(),
                                   PROCESSOR_CLASS_ANY);
        if (status != OK)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, errno,
                         ap_server_conf, APLOGNO(00482)
                         "processor unbind failed");
#endif
        RAISE_SIGSTOP(MAKE_CHILD);

        apr_signal(SIGTERM, just_die);
        child_main(slot);
        /* NOTREACHED */
    }
    /* else */
    if (ap_scoreboard_image->parent[slot].pid != 0) {
        /* This new child process is squatting on the scoreboard
         * entry owned by an exiting child process, which cannot
         * exit until all active requests complete.
         */
        event_note_child_lost_slot(slot, pid);
    }
    ap_scoreboard_image->parent[slot].quiescing = 0;
    ap_scoreboard_image->parent[slot].not_accepting = 0;
    event_note_child_started(slot, pid);
    return 0;
}

/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
        if (ap_scoreboard_image->parent[i].pid != 0) {
            continue;
        }
        if (make_child(ap_server_conf, i) < 0) {
            break;
        }
        --number_to_start;
    }
}

static void perform_idle_server_maintenance(void)
{
    int i, j;
    int idle_thread_count;
    worker_score *ws;
    process_score *ps;
    int free_length;
    int totally_free_length = 0;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;
    int active_thread_count = 0;

    /* initialize the free_list */
    free_length = 0;

    idle_thread_count = 0;
    last_non_dead = -1;
    total_non_dead = 0;

    for (i = 0; i < ap_daemons_limit; ++i) {
        /* Initialization to satisfy the compiler. It doesn't know
         * that threads_per_child is always > 0 */
        int status = SERVER_DEAD;
        int any_dying_threads = 0;
        int any_dead_threads = 0;
        int all_dead_threads = 1;
        int child_threads_active = 0;

        if (i >= retained->max_daemons_limit
            && totally_free_length == retained->idle_spawn_rate)
            /* short cut if all active processes have been examined and
             * enough empty scoreboard slots have been found
             */

            break;
        ps = &ap_scoreboard_image->parent[i];
        for (j = 0; j < threads_per_child; j++) {
            ws = &ap_scoreboard_image->servers[i][j];
            status = ws->status;

            /* XXX any_dying_threads is probably no longer needed    GLA */
            any_dying_threads = any_dying_threads ||
                (status == SERVER_GRACEFUL);
            any_dead_threads = any_dead_threads || (status == SERVER_DEAD);
            all_dead_threads = all_dead_threads &&
                (status == SERVER_DEAD || status == SERVER_GRACEFUL);

            /* We consider a starting server as idle because we started it
             * at least a cycle ago, and if it still hasn't finished starting
             * then we're just going to swamp things worse by forking more.
             * So we hopefully won't need to fork more if we count it.
             * This depends on the ordering of SERVER_READY and SERVER_STARTING.
             */
            if (ps->pid != 0) { /* XXX just set all_dead_threads in outer
                                   for loop if no pid?  not much else matters */
                if (status <= SERVER_READY && !ps->quiescing && !ps->not_accepting
                    && ps->generation == retained->my_generation)
                {
                    ++idle_thread_count;
                }
                if (status >= SERVER_READY && status < SERVER_GRACEFUL) {
                    ++child_threads_active;
                }
            }
        }
        active_thread_count += child_threads_active;
        if (any_dead_threads
            && totally_free_length < retained->idle_spawn_rate
            && free_length < MAX_SPAWN_RATE
            && (!ps->pid      /* no process in the slot */
                  || ps->quiescing)) {  /* or at least one is going away */
            if (all_dead_threads) {
                /* great! we prefer these, because the new process can
                 * start more threads sooner.  So prioritize this slot
                 * by putting it ahead of any slots with active threads.
                 *
                 * first, make room by moving a slot that's potentially still
                 * in use to the end of the array
                 */
                free_slots[free_length] = free_slots[totally_free_length];
                free_slots[totally_free_length++] = i;
            }
            else {
                /* slot is still in use - back of the bus
                 */
                free_slots[free_length] = i;
            }
            ++free_length;
        }
        else if (child_threads_active == threads_per_child) {
            had_healthy_child = 1;
        }
        /* XXX if (!ps->quiescing)     is probably more reliable  GLA */
        if (!any_dying_threads) {
            last_non_dead = i;
            ++total_non_dead;
        }
    }

    if (retained->sick_child_detected) {
        if (had_healthy_child) {
            /* Assume this is a transient error, even though it may not be.  Leave
             * the server up in case it is able to serve some requests or the
             * problem will be resolved.
             */
            retained->sick_child_detected = 0;
        }
        else {
            /* looks like a basket case, as no child ever fully initialized; give up.
             */
            shutdown_pending = 1;
            child_fatal = 1;
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0,
                         ap_server_conf, APLOGNO(02324)
                         "A resource shortage or other unrecoverable failure "
                         "was encountered before any child process initialized "
                         "successfully... httpd is exiting!");
            /* the child already logged the failure details */
            return;
        }
    }

    retained->max_daemons_limit = last_non_dead + 1;

    if (idle_thread_count > max_spare_threads) {
        /* Kill off one child */
        ap_mpm_podx_signal(pod, AP_MPM_PODX_GRACEFUL);
        retained->idle_spawn_rate = 1;
    }
    else if (idle_thread_count < min_spare_threads) {
        /* terminate the free list */
        if (free_length == 0) { /* scoreboard is full, can't fork */

            if (active_thread_count >= ap_daemons_limit * threads_per_child) {
                if (!retained->maxclients_reported) {
                    /* only report this condition once */
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(00484)
                                 "server reached MaxRequestWorkers setting, "
                                 "consider raising the MaxRequestWorkers "
                                 "setting");
                    retained->maxclients_reported = 1;
                }
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(00485)
                             "scoreboard is full, not at MaxRequestWorkers");
            }
            retained->idle_spawn_rate = 1;
        }
        else {
            if (free_length > retained->idle_spawn_rate) {
                free_length = retained->idle_spawn_rate;
            }
            if (retained->idle_spawn_rate >= 8) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00486)
                             "server seems busy, (you may need "
                             "to increase StartServers, ThreadsPerChild "
                             "or Min/MaxSpareThreads), "
                             "spawning %d children, there are around %d idle "
                             "threads, and %d total children", free_length,
                             idle_thread_count, total_non_dead);
            }
            for (i = 0; i < free_length; ++i) {
                make_child(ap_server_conf, free_slots[i]);
            }
            /* the next time around we want to spawn twice as many if this
             * wasn't good enough, but not if we've just done a graceful
             */
            if (retained->hold_off_on_exponential_spawning) {
                --retained->hold_off_on_exponential_spawning;
            }
            else if (retained->idle_spawn_rate < MAX_SPAWN_RATE) {
                retained->idle_spawn_rate *= 2;
            }
        }
    }
    else {
        retained->idle_spawn_rate = 1;
    }
}

static void server_main_loop(int remaining_children_to_start)
{
    ap_generation_t old_gen;
    int child_slot;
    apr_exit_why_e exitwhy;
    int status, processed_status;
    apr_proc_t pid;
    int i;

    while (!restart_pending && !shutdown_pending) {
        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf, ap_server_conf);

        if (pid.pid != -1) {
            processed_status = ap_process_child_status(&pid, exitwhy, status);
            child_slot = ap_find_child_by_pid(&pid);
            if (processed_status == APEXIT_CHILDFATAL) {
                /* fix race condition found in PR 39311
                 * A child created at the same time as a graceful happens 
                 * can find the lock missing and create a fatal error.
                 * It is not fatal for the last generation to be in this state.
                 */
                if (child_slot < 0
                    || ap_get_scoreboard_process(child_slot)->generation
                       == retained->my_generation) {
                    shutdown_pending = 1;
                    child_fatal = 1;
                    return;
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(00487)
                                 "Ignoring fatal error in child of previous "
                                 "generation (pid %ld).",
                                 (long)pid.pid);
                    retained->sick_child_detected = 1;
                }
            }
            else if (processed_status == APEXIT_CHILDSICK) {
                /* tell perform_idle_server_maintenance to check into this
                 * on the next timer pop
                 */
                retained->sick_child_detected = 1;
            }
            /* non-fatal death... note that it's gone in the scoreboard. */
            if (child_slot >= 0) {
                for (i = 0; i < threads_per_child; i++)
                    ap_update_child_status_from_indexes(child_slot, i,
                                                        SERVER_DEAD,
                                                        (request_rec *) NULL);

                event_note_child_killed(child_slot, 0, 0);
                ap_scoreboard_image->parent[child_slot].quiescing = 0;
                if (processed_status == APEXIT_CHILDSICK) {
                    /* resource shortage, minimize the fork rate */
                    retained->idle_spawn_rate = 1;
                }
                else if (remaining_children_to_start
                         && child_slot < ap_daemons_limit) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_child(ap_server_conf, child_slot);
                    --remaining_children_to_start;
                }
            }
            else if (ap_unregister_extra_mpm_process(pid.pid, &old_gen) == 1) {

                event_note_child_killed(-1, /* already out of the scoreboard */
                                        pid.pid, old_gen);
                if (processed_status == APEXIT_CHILDSICK
                    && old_gen == retained->my_generation) {
                    /* resource shortage, minimize the fork rate */
                    retained->idle_spawn_rate = 1;
                }
#if APR_HAS_OTHER_CHILD
            }
            else if (apr_proc_other_child_alert(&pid, APR_OC_REASON_DEATH,
                                                status) == 0) {
                /* handled */
#endif
            }
            else if (retained->is_graceful) {
                /* Great, we've probably just lost a slot in the
                 * scoreboard.  Somehow we don't know about this child.
                 */
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                             ap_server_conf, APLOGNO(00488)
                             "long lost child came home! (pid %ld)",
                             (long) pid.pid);
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
            startup_children(remaining_children_to_start);
            remaining_children_to_start = 0;
            /* In any event we really shouldn't do the code below because
             * few of the servers we just started are in the IDLE state
             * yet, so we'd mistakenly create an extra server.
             */
            continue;
        }

        perform_idle_server_maintenance();
    }
}

static int event_run(apr_pool_t * _pconf, apr_pool_t * plog, server_rec * s)
{
    int remaining_children_to_start;

    ap_log_pid(pconf, ap_pid_fname);

    if (!retained->is_graceful) {
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            mpm_state = AP_MPMQ_STOPPING;
            return DONE;
        }
        /* fix the generation number in the global score; we just got a new,
         * cleared scoreboard
         */
        ap_scoreboard_image->global->running_generation = retained->my_generation;
    }

    restart_pending = shutdown_pending = 0;
    set_signals();
    /* Don't thrash... */
    if (max_spare_threads < min_spare_threads + threads_per_child)
        max_spare_threads = min_spare_threads + threads_per_child;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens pretty
     * rapidly... and for each one that exits we may start a new one, until
     * there are at least min_spare_threads idle threads, counting across
     * all children.  But we may be permitted to start more children than
     * that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = ap_daemons_to_start;
    if (remaining_children_to_start > ap_daemons_limit) {
        remaining_children_to_start = ap_daemons_limit;
    }
    if (!retained->is_graceful) {
        startup_children(remaining_children_to_start);
        remaining_children_to_start = 0;
    }
    else {
        /* give the system some time to recover before kicking into
         * exponential mode */
        retained->hold_off_on_exponential_spawning = 10;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00489)
                 "%s configured -- resuming normal operations",
                 ap_get_server_description());
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00490)
                 "Server built: %s", ap_get_server_built());
    ap_log_command_line(plog, s);

    mpm_state = AP_MPMQ_RUNNING;

    server_main_loop(remaining_children_to_start);
    mpm_state = AP_MPMQ_STOPPING;

    if (shutdown_pending && !retained->is_graceful) {
        /* Time to shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        ap_mpm_podx_killpg(pod, ap_daemons_limit, AP_MPM_PODX_RESTART);
        ap_reclaim_child_processes(1, /* Start with SIGTERM */
                                   event_note_child_killed);

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            ap_remove_pid(pconf, ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
                         ap_server_conf, APLOGNO(00491) "caught SIGTERM, shutting down");
        }
        return DONE;
    } else if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        int active_children;
        int index;
        apr_time_t cutoff = 0;

        /* Close our listeners, and then ask our children to do same */
        ap_close_listeners();
        ap_mpm_podx_killpg(pod, ap_daemons_limit, AP_MPM_PODX_GRACEFUL);
        ap_relieve_child_processes(event_note_child_killed);

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            ap_remove_pid(pconf, ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00492)
                         "caught " AP_SIG_GRACEFUL_STOP_STRING
                         ", shutting down gracefully");
        }

        if (ap_graceful_shutdown_timeout) {
            cutoff = apr_time_now() +
                     apr_time_from_sec(ap_graceful_shutdown_timeout);
        }

        /* Don't really exit until each child has finished */
        shutdown_pending = 0;
        do {
            /* Pause for a second */
            apr_sleep(apr_time_from_sec(1));

            /* Relieve any children which have now exited */
            ap_relieve_child_processes(event_note_child_killed);

            active_children = 0;
            for (index = 0; index < ap_daemons_limit; ++index) {
                if (ap_mpm_safe_kill(MPM_CHILD_PID(index), 0) == APR_SUCCESS) {
                    active_children = 1;
                    /* Having just one child is enough to stay around */
                    break;
                }
            }
        } while (!shutdown_pending && active_children &&
                 (!ap_graceful_shutdown_timeout || apr_time_now() < cutoff));

        /* We might be here because we received SIGTERM, either
         * way, try and make sure that all of our processes are
         * really dead.
         */
        ap_mpm_podx_killpg(pod, ap_daemons_limit, AP_MPM_PODX_RESTART);
        ap_reclaim_child_processes(1, event_note_child_killed);

        return DONE;
    }

    /* we've been told to restart */
    apr_signal(SIGHUP, SIG_IGN);

    if (one_process) {
        /* not worth thinking about */
        return DONE;
    }

    /* advance to the next generation */
    /* XXX: we really need to make sure this new generation number isn't in
     * use by any of the children.
     */
    ++retained->my_generation;
    ap_scoreboard_image->global->running_generation = retained->my_generation;

    if (retained->is_graceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00493)
                     AP_SIG_GRACEFUL_STRING
                     " received.  Doing graceful restart");
        /* wake up the children...time to die.  But we'll have more soon */
        ap_mpm_podx_killpg(pod, ap_daemons_limit, AP_MPM_PODX_GRACEFUL);


        /* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.
         */

    }
    else {
        /* Kill 'em all.  Since the child acts the same on the parents SIGTERM
         * and a SIGHUP, we may as well use the same signal, because some user
         * pthreads are stealing signals from us left and right.
         */
        ap_mpm_podx_killpg(pod, ap_daemons_limit, AP_MPM_PODX_RESTART);

        ap_reclaim_child_processes(1,  /* Start with SIGTERM */
                                   event_note_child_killed);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00494)
                     "SIGHUP received.  Attempting to restart");
    }

    return OK;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 */
static int event_open_logs(apr_pool_t * p, apr_pool_t * plog,
                           apr_pool_t * ptemp, server_rec * s)
{
    int startup = 0;
    int level_flags = 0;
    apr_status_t rv;

    pconf = p;

    /* the reverse of pre_config, we want this only the first time around */
    if (retained->module_loads == 1) {
        startup = 1;
        level_flags |= APLOG_STARTUP;
    }

    if ((num_listensocks = ap_setup_listeners(ap_server_conf)) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, 0,
                     (startup ? NULL : s),
                     "no listening sockets available, shutting down");
        return DONE;
    }

    if (!one_process) {
        if ((rv = ap_mpm_podx_open(pconf, &pod))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                         (startup ? NULL : s),
                         "could not open pipe-of-death");
            return DONE;
        }
    }
    /* for skiplist */
    srand((unsigned int)apr_time_now());
    return OK;
}

static int event_pre_config(apr_pool_t * pconf, apr_pool_t * plog,
                            apr_pool_t * ptemp)
{
    int no_detach, debug, foreground;
    apr_status_t rv;
    const char *userdata_key = "mpm_event_module";

    mpm_state = AP_MPMQ_STARTING;

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
    retained = ap_retained_data_get(userdata_key);
    if (!retained) {
        retained = ap_retained_data_create(userdata_key, sizeof(*retained));
        retained->max_daemons_limit = -1;
        retained->idle_spawn_rate = 1;
    }
    ++retained->module_loads;
    if (retained->module_loads == 2) {
        /* test for correct operation of fdqueue */
        static apr_uint32_t foo1, foo2;

        apr_atomic_set32(&foo1, 100);
        foo2 = apr_atomic_add32(&foo1, -10);
        if (foo2 != 100 || foo1 != 90) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, APLOGNO(02405)
                         "atomics not working as expected - add32 of negative number");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        rv = apr_pollset_create(&event_pollset, 1, plog,
                                APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(00495)
                         "Couldn't create a Thread Safe Pollset. "
                         "Is it supported on your platform?"
                         "Also check system or user limits!");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_pollset_destroy(event_pollset);

        if (!one_process && !foreground) {
            /* before we detach, setup crash handlers to log to errorlog */
            ap_fatal_signal_setup(ap_server_conf, pconf);
            rv = apr_proc_detach(no_detach ? APR_PROC_DETACH_FOREGROUND
                                 : APR_PROC_DETACH_DAEMONIZE);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(00496)
                             "apr_proc_detach failed");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    parent_pid = ap_my_pid = getpid();

    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    min_spare_threads = DEFAULT_MIN_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    max_spare_threads = DEFAULT_MAX_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    server_limit = DEFAULT_SERVER_LIMIT;
    thread_limit = DEFAULT_THREAD_LIMIT;
    ap_daemons_limit = server_limit;
    threads_per_child = DEFAULT_THREADS_PER_CHILD;
    max_workers = ap_daemons_limit * threads_per_child;
    had_healthy_child = 0;
    ap_extended_status = 0;

    return OK;
}

static int event_check_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;

    /* the reverse of pre_config, we want this only the first time around */
    if (retained->module_loads == 1) {
        startup = 1;
    }

    if (server_limit > MAX_SERVER_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00497)
                         "WARNING: ServerLimit of %d exceeds compile-time "
                         "limit of", server_limit);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " %d servers, decreasing to %d.",
                         MAX_SERVER_LIMIT, MAX_SERVER_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00498)
                         "ServerLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         server_limit, MAX_SERVER_LIMIT);
        }
        server_limit = MAX_SERVER_LIMIT;
    }
    else if (server_limit < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00499)
                         "WARNING: ServerLimit of %d not allowed, "
                         "increasing to 1.", server_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00500)
                         "ServerLimit of %d not allowed, increasing to 1",
                         server_limit);
        }
        server_limit = 1;
    }

    /* you cannot change ServerLimit across a restart; ignore
     * any such attempts
     */
    if (!retained->first_server_limit) {
        retained->first_server_limit = server_limit;
    }
    else if (server_limit != retained->first_server_limit) {
        /* don't need a startup console version here */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00501)
                     "changing ServerLimit to %d from original value of %d "
                     "not allowed during restart",
                     server_limit, retained->first_server_limit);
        server_limit = retained->first_server_limit;
    }

    if (thread_limit > MAX_THREAD_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00502)
                         "WARNING: ThreadLimit of %d exceeds compile-time "
                         "limit of", thread_limit);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " %d threads, decreasing to %d.",
                         MAX_THREAD_LIMIT, MAX_THREAD_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00503)
                         "ThreadLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         thread_limit, MAX_THREAD_LIMIT);
        }
        thread_limit = MAX_THREAD_LIMIT;
    }
    else if (thread_limit < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00504)
                         "WARNING: ThreadLimit of %d not allowed, "
                         "increasing to 1.", thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00505)
                         "ThreadLimit of %d not allowed, increasing to 1",
                         thread_limit);
        }
        thread_limit = 1;
    }

    /* you cannot change ThreadLimit across a restart; ignore
     * any such attempts
     */
    if (!retained->first_thread_limit) {
        retained->first_thread_limit = thread_limit;
    }
    else if (thread_limit != retained->first_thread_limit) {
        /* don't need a startup console version here */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00506)
                     "changing ThreadLimit to %d from original value of %d "
                     "not allowed during restart",
                     thread_limit, retained->first_thread_limit);
        thread_limit = retained->first_thread_limit;
    }

    if (threads_per_child > thread_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00507)
                         "WARNING: ThreadsPerChild of %d exceeds ThreadLimit "
                         "of", threads_per_child);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " %d threads, decreasing to %d.",
                         thread_limit, thread_limit);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " To increase, please see the ThreadLimit "
                         "directive.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00508)
                         "ThreadsPerChild of %d exceeds ThreadLimit "
                         "of %d, decreasing to match",
                         threads_per_child, thread_limit);
        }
        threads_per_child = thread_limit;
    }
    else if (threads_per_child < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00509)
                         "WARNING: ThreadsPerChild of %d not allowed, "
                         "increasing to 1.", threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00510)
                         "ThreadsPerChild of %d not allowed, increasing to 1",
                         threads_per_child);
        }
        threads_per_child = 1;
    }

    if (max_workers < threads_per_child) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00511)
                         "WARNING: MaxRequestWorkers of %d is less than "
                         "ThreadsPerChild of", max_workers);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " %d, increasing to %d.  MaxRequestWorkers must be at "
                         "least as large",
                         threads_per_child, threads_per_child);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " as the number of threads in a single server.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00512)
                         "MaxRequestWorkers of %d is less than ThreadsPerChild "
                         "of %d, increasing to match",
                         max_workers, threads_per_child);
        }
        max_workers = threads_per_child;
    }

    ap_daemons_limit = max_workers / threads_per_child;

    if (max_workers % threads_per_child) {
        int tmp_max_workers = ap_daemons_limit * threads_per_child;

        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00513)
                         "WARNING: MaxRequestWorkers of %d is not an integer "
                         "multiple of", max_workers);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " ThreadsPerChild of %d, decreasing to nearest "
                         "multiple %d,", threads_per_child,
                         tmp_max_workers);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " for a maximum of %d servers.",
                         ap_daemons_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00514)
                         "MaxRequestWorkers of %d is not an integer multiple "
                         "of ThreadsPerChild of %d, decreasing to nearest "
                         "multiple %d", max_workers, threads_per_child,
                         tmp_max_workers);
        }
        max_workers = tmp_max_workers;
    }

    if (ap_daemons_limit > server_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00515)
                         "WARNING: MaxRequestWorkers of %d would require %d "
                         "servers and ", max_workers, ap_daemons_limit);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " would exceed ServerLimit of %d, decreasing to %d.",
                         server_limit, server_limit * threads_per_child);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " To increase, please see the ServerLimit "
                         "directive.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00516)
                         "MaxRequestWorkers of %d would require %d servers and "
                         "exceed ServerLimit of %d, decreasing to %d",
                         max_workers, ap_daemons_limit, server_limit,
                         server_limit * threads_per_child);
        }
        ap_daemons_limit = server_limit;
    }

    /* ap_daemons_to_start > ap_daemons_limit checked in ap_mpm_run() */
    if (ap_daemons_to_start < 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00517)
                         "WARNING: StartServers of %d not allowed, "
                         "increasing to 1.", ap_daemons_to_start);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00518)
                         "StartServers of %d not allowed, increasing to 1",
                         ap_daemons_to_start);
        }
        ap_daemons_to_start = 1;
    }

    if (min_spare_threads < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00519)
                         "WARNING: MinSpareThreads of %d not allowed, "
                         "increasing to 1", min_spare_threads);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " to avoid almost certain server failure.");
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " Please read the documentation.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00520)
                         "MinSpareThreads of %d not allowed, increasing to 1",
                         min_spare_threads);
        }
        min_spare_threads = 1;
    }

    /* max_spare_threads < min_spare_threads + threads_per_child
     * checked in ap_mpm_run()
     */

    return OK;
}

static void event_hooks(apr_pool_t * p)
{
    /* Our open_logs hook function must run before the core's, or stderr
     * will be redirected to a file, and the messages won't print to the
     * console.
     */
    static const char *const aszSucc[] = { "core.c", NULL };
    one_process = 0;

    ap_hook_open_logs(event_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);
    /* we need to set the MPM state before other pre-config hooks use MPM query
     * to retrieve it, so register as REALLY_FIRST
     */
    ap_hook_pre_config(event_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_check_config(event_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm(event_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(event_query, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_register_timed_callback(event_register_timed_callback, NULL, NULL,
                                        APR_HOOK_MIDDLE);
    ap_hook_pre_read_request(event_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_get_name(event_get_name, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_max_workers(cmd_parms * cmd, void *dummy,
                                   const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    if (!strcasecmp(cmd->cmd->name, "MaxClients")) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL, APLOGNO(00521)
                     "MaxClients is deprecated, use MaxRequestWorkers "
                     "instead.");
    }
    max_workers = atoi(arg);
    return NULL;
}

static const char *set_threads_per_child(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    threads_per_child = atoi(arg);
    return NULL;
}
static const char *set_server_limit (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    server_limit = atoi(arg);
    return NULL;
}

static const char *set_thread_limit(cmd_parms * cmd, void *dummy,
                                    const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    thread_limit = atoi(arg);
    return NULL;
}

static const char *set_worker_factor(cmd_parms * cmd, void *dummy,
                                     const char *arg)
{
    double val;
    char *endptr;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    val = strtod(arg, &endptr);
    if (*endptr)
        return "error parsing value";

    if (val <= 0)
        return "AsyncRequestWorkerFactor argument must be a positive number";

    worker_factor = val * WORKER_FACTOR_SCALE;
    if (worker_factor == 0)
        worker_factor = 1;
    return NULL;
}


static const command_rec event_cmds[] = {
    LISTEN_COMMANDS,
    AP_INIT_TAKE1("StartServers", set_daemons_to_start, NULL, RSRC_CONF,
                  "Number of child processes launched at server startup"),
    AP_INIT_TAKE1("ServerLimit", set_server_limit, NULL, RSRC_CONF,
                  "Maximum number of child processes for this run of Apache"),
    AP_INIT_TAKE1("MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
                  "Minimum number of idle threads, to handle request spikes"),
    AP_INIT_TAKE1("MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
                  "Maximum number of idle threads"),
    AP_INIT_TAKE1("MaxClients", set_max_workers, NULL, RSRC_CONF,
                  "Deprecated name of MaxRequestWorkers"),
    AP_INIT_TAKE1("MaxRequestWorkers", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time"),
    AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
                  "Number of threads each child creates"),
    AP_INIT_TAKE1("ThreadLimit", set_thread_limit, NULL, RSRC_CONF,
                  "Maximum number of worker threads per child process for this "
                  "run of Apache - Upper limit for ThreadsPerChild"),
    AP_INIT_TAKE1("AsyncRequestWorkerFactor", set_worker_factor, NULL, RSRC_CONF,
                  "How many additional connects will be accepted per idle "
                  "worker thread"),
    AP_GRACEFUL_SHUTDOWN_TIMEOUT_COMMAND,
    {NULL}
};

AP_DECLARE_MODULE(mpm_event) = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    event_cmds,                 /* command apr_table_t */
    event_hooks                 /* register_hooks */
};
