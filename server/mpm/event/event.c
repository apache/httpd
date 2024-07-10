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

#include <stdlib.h>

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
#ifdef HAVE_TIME_H
#include <time.h>               /* for clock_gettime() */
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
#include "mpm_fdqueue.h"
#include "mpm_default.h"
#include "http_vhost.h"
#include "unixd.h"
#include "apr_skiplist.h"
#include "util_time.h"

#include <signal.h>
#include <limits.h>             /* for INT_MAX */


#if HAVE_SERF
#include "mod_serf.h"
#include "serf.h"
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

#ifndef DEFAULT_ASYNC_FACTOR
#define DEFAULT_ASYNC_FACTOR 2.0
#endif

#ifndef MAX_SPARE_THREADS_RATIO
#define MAX_SPARE_THREADS_RATIO 0.75 /* of MaxRequestWorkers */
#endif
#ifndef MAX_DAEMONS_THREADS_RATIO
#define MAX_DAEMONS_THREADS_RATIO 32
#endif

#ifndef SCOREBOARD_DAEMONS_FACTOR
#define SCOREBOARD_DAEMONS_FACTOR 4
#endif

#define MPM_CHILD_PID(i) (ap_scoreboard_image->parent[i].pid)

#if !APR_VERSION_AT_LEAST(1,4,0)
#define apr_time_from_msec(x) ((x) * 1000)
#endif

/* Lingering close (read) timeout */
#define LINGER_READ_TIMEOUT     apr_time_from_sec(2)

/* Shrink linger_q at this period (min) when busy */
#define QUEUES_SHRINK_TIMEOUT   apr_time_from_msec(500)

/* Update scoreboard stats at this period */
#define STATS_UPDATE_TIMEOUT    apr_time_from_msec(1000)

/* Don't wait more time in poll() if APR_POLLSET_WAKEABLE is not implemented */
#define NON_WAKEABLE_TIMEOUT    apr_time_from_msec(100)

/* Prevent extra poll/wakeup calls for timeouts close in the future (queues
 * have the granularity of a second anyway).
 * XXX: Wouldn't 0.5s (instead of 0.1s) be "enough"?
 */
#define QUEUES_FUDGE_TIMEOUT    apr_time_from_msec(100)

/* Same goal as for QUEUES_FUDGE_TIMEOUT, but applied to timers.
 * XXX: Since their timeouts are custom (user defined), we can't be too
 * approximative here (using 5ms).
 */
#define TIMERS_FUDGE_TIMEOUT    apr_time_from_msec(5)

/*
 * Actual definitions of config globals
 */

static int threads_per_child = 0;           /* ThreadsPerChild */
static int ap_daemons_to_start = 0;         /* StartServers */
static int min_spare_threads = 0;           /* MinSpareThreads */
static int max_spare_threads = 0;           /* MaxSpareThreads */
static int active_daemons_limit = 0;        /* MaxRequestWorkers / ThreadsPerChild */
static int max_workers = 0;                 /* MaxRequestWorkers */
static int server_limit = 0;                /* ServerLimit */
static int thread_limit = 0;                /* ThreadLimit */
static int conns_this_child = 0;            /* MaxConnectionsPerChild, only accessed
                                               in listener thread */
static double async_factor = DEFAULT_ASYNC_FACTOR; /* AsyncRequestWorkerFactor */

static int auto_settings = 0;               /* Auto settings based on max_workers
                                               and num_online_cpus */
static int num_online_cpus = 0;             /* Number of CPUs detected */

static int workers_backlog_limit = 0;       /* Max number of events in the workers' backlog
                                               (above which not accepting new connections) */

static /*atomic*/ apr_uint32_t dying = 0;
static /*atomic*/ apr_uint32_t workers_may_exit = 0;
static /*atomic*/ apr_uint32_t start_thread_may_exit = 0;
static /*atomic*/ apr_uint32_t listener_may_exit = 0;
static /*atomic*/ apr_uint32_t connection_count = 0; /* Number of open connections */
static /*atomic*/ apr_uint32_t timers_count = 0;     /* Number of queued timers */
static /*atomic*/ apr_uint32_t suspended_count = 0;  /* Number of suspended connections */
static /*atomic*/ apr_uint32_t threads_shutdown = 0; /* Number of threads that have shutdown
                                                        early during graceful termination */

static int had_healthy_child = 0;
static int resource_shortage = 0;

static fd_queue_t *worker_queue;
static fd_queue_info_t *worker_queue_info;

static int num_listensocks = 0;
static int listener_is_wakeable = 0; /* Pollset supports APR_POLLSET_WAKEABLE */
static apr_pollfd_t *listener_pollfd;

module AP_MODULE_DECLARE_DATA mpm_event_module;

/* forward declare */
struct event_srv_cfg_s;
typedef struct event_srv_cfg_s event_srv_cfg;

struct timeout_queue;
static apr_thread_mutex_t *timeout_mutex;

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
#define POLLSET_RESERVE_SIZE 10000

struct backlog_timer_event {
    timer_event_t te;
    ap_queue_event_t qe;
};
#define te_qe(te) (&((struct backlog_timer_event *)(te))->qe)
#define te_in_backlog(te) (te_qe(te)->cb != NULL)

typedef struct event_conn_state_t event_conn_state_t;
struct event_conn_state_t {
    /** APR_RING of expiration timeouts */
    APR_RING_ENTRY(event_conn_state_t) timeout_list;
    /** public parts of the connection state */
    conn_state_t pub;
    /** memory pool allocated on and to allocate from (ptrans) */
    apr_pool_t *p;
    /** connection record this struct refers to */
    conn_rec *c;
    /** request record (if any) this struct refers to */
    request_rec *r;
    /** server config this struct refers to */
    event_srv_cfg *sc;
    /** server config this struct refers to during keepalive */
    event_srv_cfg *ka_sc;
    /** scoreboard handle for the conn_rec */
    ap_sb_handle_t *sbh;
    /** bucket allocator */
    apr_bucket_alloc_t *bucket_alloc;

    /*
     * when queued to the listener
     */
    /** poll file descriptor information */
    apr_pollfd_t pfd;
    /** the time when the entry was queued */
    apr_time_t queue_timestamp;
    /** the timeout queue for this entry */
    struct timeout_queue *q;
    /** the timer event for this entry */
    timer_event_t *te;

    /*
     * when queued to workers
     */
    /** the backlog event for this entry */
    struct backlog_socket_event {
        sock_event_t se;
        ap_queue_event_t qe;
        struct timeout_queue *q;
    } bse;

    /*
     * bools as bits
     */
    unsigned int
        /** Is the current conn_rec suspended?  (disassociated with
         *  a particular MPM thread; for suspend_/resume_connection
         *  hooks)
         */
        suspended       :1,
        /** Is lingering close from defer_lingering_close()? */
        deferred_linger :1,
        /** Has ap_start_lingering_close() been called? */
        linger_started  :1,
        /** Is lingering connection flushed and shutdown? */
        linger_shutdown :1;
};
#define cs_se(cs) (&(cs)->bse.se)
#define cs_qe(cs) (&(cs)->bse.qe)
#define cs_in_backlog(cs) (cs_qe(cs)->cb != NULL)

static APR_INLINE apr_socket_t *cs_sd(event_conn_state_t *cs)
{
    ap_assert(cs != NULL);
    return cs->pfd.desc.s;
}
static APR_INLINE int cs_fd(event_conn_state_t *cs)
{
    apr_os_sock_t fd = -1;
    apr_os_sock_get(&fd, cs_sd(cs));
    return fd;
}
static APR_INLINE apr_sockaddr_t *cs_raddr(event_conn_state_t *cs)
{
    apr_sockaddr_t *addr = NULL;
    apr_socket_addr_get(&addr, APR_REMOTE, cs_sd(cs));
    return addr;
}
static APR_INLINE const char *cs_state_str(event_conn_state_t *cs)
{
    switch (cs->pub.state) {
    case CONN_STATE_PROCESSING:
        return "STATE_PROCESSING";
    case CONN_STATE_HANDLER:
        return "STATE_HANDLER";
    case CONN_STATE_ASYNC_WAITIO:
        return "STATE_ASYNC_WAITIO";
    case CONN_STATE_WRITE_COMPLETION:
        return "STATE_WRITE_COMPLETION";
    case CONN_STATE_KEEPALIVE:
        return "STATE_KEEPALIVE";
    case CONN_STATE_LINGER:
    case CONN_STATE_LINGER_NORMAL:
    case CONN_STATE_LINGER_SHORT:
        return "STATE_LINGER";
    case CONN_STATE_SUSPENDED:
        return "STATE_SUSPENDED";
    default:
        return "STATE_UNKNOWN";
    }
}
#define CS_FMT          "pp:%s:%i"
#define CS_ARG(cs)      (cs), cs_state_str(cs), cs_fd(cs)
#define CS_FMT_TO       CS_FMT " to [%pI]"
#define CS_ARG_TO(cs)   CS_ARG(cs), cs_raddr(cs)

#define USE_CLOCK_COARSE 0  /* not for now */
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)            /* POSIX */
static clockid_t event_clockid;
#elif HAVE_CLOCK_GETTIME_NSEC_NP && defined(CLOCK_UPTIME_RAW) /* Newer OSX */
/* All #include'd by <time.h> already */
#elif HAVE_MACH_MACH_TIME_H                                   /* Older OSX */
#include <mach/mach_time.h>
#endif

static void event_time_init(void)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
    event_clockid = (clockid_t)-1;

#if HAVE_CLOCK_GETRES && defined(CLOCK_MONOTONIC_COARSE) && USE_CLOCK_COARSE
    if (event_clockid == (clockid_t)-1) {
        struct timespec ts;
        if (clock_getres(CLOCK_MONOTONIC_COARSE, &ts) == 0) {
            apr_time_t res = apr_time_from_sec(ts.tv_sec) + ts.tv_nsec / 1000;
            if (res <= TIMERS_FUDGE_TIMEOUT) {
                event_clockid = CLOCK_MONOTONIC_COARSE;
            }
        }
    }
#endif /* CLOCK_MONOTONIC_COARSE */

#if HAVE_CLOCK_GETRES && defined(CLOCK_MONOTONIC_FAST) && USE_CLOCK_COARSE
    if (event_clockid == (clockid_t)-1) {
        struct timespec ts;
        if (clock_getres(CLOCK_MONOTONIC_FAST, &ts) == 0) {
            apr_time_t res = apr_time_from_sec(ts.tv_sec) + ts.tv_nsec / 1000;
            if (res <= TIMERS_FUDGE_TIMEOUT) {
                event_clockid = CLOCK_MONOTONIC_FAST;
            }
        }
    }
#endif /* CLOCK_MONOTONIC_FAST */

#if HAVE_CLOCK_GETRES && defined(CLOCK_MONOTONIC_RAW_APPROX) && USE_CLOCK_COARSE
    if (event_clockid == (clockid_t)-1) {
        struct timespec ts;
        if (clock_getres(CLOCK_MONOTONIC_RAW_APPROX, &ts) == 0) {
            apr_time_t res = apr_time_from_sec(ts.tv_sec) + ts.tv_nsec / 1000;
            if (res <= TIMERS_FUDGE_TIMEOUT) {
                event_clockid = CLOCK_MONOTONIC_RAW_APPROX;
            }
        }
    }
#endif /* CLOCK_MONOTONIC_RAW_APPROX */

    if (event_clockid == (clockid_t)-1) {
#if defined(CLOCK_MONOTONIC_RAW)
        event_clockid = CLOCK_MONOTONIC_RAW;
#else
        event_clockid = CLOCK_MONOTONIC;
#endif
    }

#endif /* HAVE_CLOCK_GETTIME */
}

static apr_time_t event_time_now(void)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)

    struct timespec ts;
    clock_gettime(event_clockid, &ts);
    return apr_time_from_sec(ts.tv_sec) + ts.tv_nsec / 1000;

#elif HAVE_CLOCK_GETTIME_NSEC_NP && defined(CLOCK_UPTIME_RAW)

    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000;

#elif HAVE_MACH_MACH_TIME_H

    mach_timebase_info_data_t ti;
    mach_timebase_info(&ti);
    return mach_continuous_time() * ti.numer / ti.denom / 1000;

#else

    /* XXX: not monotonic, still some platform to care about? */
    return apr_time_now();

#endif
}

APR_RING_HEAD(timeout_head_t, event_conn_state_t);
struct timeout_queue {
    struct timeout_head_t head;
    apr_interval_time_t timeout;
    apr_uint32_t count;         /* for this queue */
    apr_uint32_t *total;        /* for all chained/related queues */
    const char *name;           /* for logging */
    struct timeout_queue *next; /* chaining */
};

/*
 * Several timeout queues that use different timeouts, so that we always can
 * simply append to the end.
 *   waitio_q           uses vhost's TimeOut
 *   write_completion_q uses vhost's TimeOut
 *   keepalive_q        uses vhost's KeepAliveTimeOut
 *   shutdown_q         uses vhost's TimeOut
 *   linger_q           uses LINGER_READ_TIMEOUT
 *   backlog_q          uses vhost's TimeOut
 */
static struct timeout_queue *waitio_q,           /* wait for I/O to happen */
                            *write_completion_q, /* completion or user async poll */
                            *keepalive_q,        /* in between requests */
                            *shutdown_q,         /* shutting down (write) before close */
                            *linger_q,           /* lingering (read) before close */
                            *backlog_q;          /* waiting for a worker */
static volatile apr_time_t queues_next_expiry; /* next expiry time accross all queues */

/*
 * Macros for accessing struct timeout_queue.
 * For TO_QUEUE_APPEND and TO_QUEUE_REMOVE, timeout_mutex must be held.
 */
static void TO_QUEUE_APPEND(struct timeout_queue *q, event_conn_state_t *cs)
{
    apr_time_t elem_expiry;
    apr_time_t next_expiry;

    ap_assert(q && !cs->q);

    cs->q = q;
    cs->queue_timestamp = event_time_now();
    APR_RING_INSERT_TAIL(&q->head, cs, event_conn_state_t, timeout_list);
    ++q->count;

    /* Use atomic_set to be ordered/consistent with potential atomic reads
     * outside the critical section, but writes are protected so a more
     * expensive atomic_inc is not needed.
     */
    apr_atomic_set32(q->total, *q->total + 1);

    /* Cheaply update the global queues_next_expiry with the one of the
     * first entry of this queue (oldest) if it expires before.
     */
    cs = APR_RING_FIRST(&q->head);
    elem_expiry = cs->queue_timestamp + q->timeout;
    next_expiry = queues_next_expiry;
    if (!next_expiry || next_expiry > elem_expiry + QUEUES_FUDGE_TIMEOUT) {
        queues_next_expiry = elem_expiry;
        /* Unblock the poll()ing listener for it to update its timeout. */
        if (listener_is_wakeable) {
            apr_pollset_wakeup(event_pollset);
        }
    }
}

static void TO_QUEUE_REMOVE(struct timeout_queue *q, event_conn_state_t *cs)
{
    ap_assert(q && cs->q == q);
    cs->q = NULL;

    APR_RING_REMOVE(cs, timeout_list);
    APR_RING_ELEM_INIT(cs, timeout_list);
    --q->count;

    /* Use atomic_set to be ordered/consistent with potential atomic reads
     * outside the critical section, but writes are protected so a more
     * expensive atomic_dec is not needed.
     */
    apr_atomic_set32(q->total, *q->total - 1);
}

static struct timeout_queue *TO_QUEUE_MAKE(apr_pool_t *p,
                                           const char *name,
                                           apr_interval_time_t t,
                                           struct timeout_queue *ref)
{
    struct timeout_queue *q;

    q = apr_pcalloc(p, sizeof *q);
    APR_RING_INIT(&q->head, event_conn_state_t, timeout_list);
    q->total = (ref) ? ref->total : apr_pcalloc(p, sizeof *q->total);
    q->timeout = t;
    q->name = name;

    return q;
}

static struct timeout_queue *TO_QUEUE_CHAIN(apr_pool_t *p,
                                            const char *name,
                                            apr_interval_time_t t,
                                            struct timeout_queue **ref,
                                            apr_hash_t *ht, apr_pool_t *hp)
{
    struct timeout_queue *q = apr_hash_get(ht, &t, sizeof t);

    if (!q) {
        q = TO_QUEUE_MAKE(p, name, t, *ref);
        q->next = *ref;
        *ref = q;

        apr_hash_set(ht, apr_pmemdup(hp, &t, sizeof t), sizeof t, q);
    }

    return q;
}

#if HAVE_SERF
typedef struct {
    apr_pollset_t *pollset;
    apr_pool_t *pool;
} s_baton_t;

static serf_context_t *g_serf;
#endif

/* The structure used to pass unique initialization info to each thread */
typedef struct
{
    int pslot;  /* process slot */
    int tslot;  /* worker slot of the thread */
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
#if HAVE_SERF
    , PT_SERF
#endif
    , PT_USER
} poll_type_e;

typedef struct
{
    poll_type_e type;
    void *baton;
} listener_poll_type;

typedef struct socket_callback_baton
{
    ap_mpm_callback_fn_t *cbfunc;
    void *user_baton;
    apr_array_header_t *pfds;
    timer_event_t *cancel_event; /* If a timeout was requested, a pointer to the timer event */
    struct socket_callback_baton *next;
} socket_callback_baton_t;

typedef struct event_child_bucket {
    ap_pod_t *pod;
    ap_listen_rec *listeners;
} event_child_bucket;
static event_child_bucket *my_bucket;  /* Current child bucket */

/* data retained by event across load/unload of the module
 * allocated on first call to pre-config hook; located on
 * subsequent calls to pre-config hook
 */
typedef struct event_retained_data {
    ap_unixd_mpm_retained_data *mpm;

    apr_pool_t *gen_pool; /* generation pool (children start->stop lifetime) */
    event_child_bucket *buckets; /* children buckets (reset per generation) */

    ap_listen_rec **listen_buckets;
    int num_listen_buckets;

    int first_server_limit;
    int first_thread_limit;
    int first_server_sb_limit;
    int sick_child_detected;
    int maxclients_reported;
    int near_maxclients_reported;

    /*
     * The max child slot ever assigned, preserved across restarts.  Necessary
     * to deal with MaxRequestWorkers changes across AP_SIG_GRACEFUL restarts.
     * We use this value to optimize routines that have to scan the entire
     * scoreboard.
     */
    int max_daemon_used;

    /*
     * All running workers, active and shutting down, including those that
     * may be left from before a graceful restart.
     * Not kept up-to-date when shutdown is pending.
     */
    int total_daemons;
    /*
     * Workers that still active, i.e. are not shutting down gracefully.
     */
    int active_daemons;

    /*
     * idle_spawn_rate is the number of children that will be spawned on the
     * next maintenance cycle if there aren't enough idle servers.  It is
     * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
     * without the need to spawn.
     */
    int idle_spawn_rate;
    int max_spawn_rate, *free_slots;
    int hold_off_on_exponential_spawning;
} event_retained_data;
static event_retained_data *retained;

#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE 32
#endif

struct event_srv_cfg_s {
    /* Per server timeout queues */
    struct timeout_queue *io_q,
                         *wc_q,
                         *ka_q,
                         *sh_q,
                         *bl_q;
    server_rec *s; /* backref */
};

#define ID_FROM_CHILD_THREAD(c, t)    ((c * thread_limit) + t)

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
static apr_pool_t *pruntime;    /* Pool for MPM threads stuff */

static pid_t ap_my_pid;         /* Linux getpid() doesn't work except in main
                                   thread. Use this instead */
static pid_t parent_pid;
static apr_os_thread_t *listener_os_thread;

static int ap_child_slot;       /* Current child process slot in scoreboard */

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

/* Disabling / enabling listening sockets can only happen in the listener
 * thread, which is the only one to set 'dying' to 1 too, so it's all thread
 * safe. 'listensocks_off' is changed atomically still because it's read
 * concurrently in listensocks_disabled().
 */
static /*atomic*/ apr_uint32_t listensocks_off = 0;

static int disable_listensocks(void)
{
    volatile process_score *ps;
    int i;

    if (apr_atomic_cas32(&listensocks_off, 1, 0) != 0) {
        return 0;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf, APLOGNO(10381)
                 "Suspend listening sockets: idlers:%i conns:%u backlog:%u "
                 "waitio:%u write:%u keepalive:%u shutdown:%u "
                 "linger:%u timers:%u suspended:%u",
                 ap_queue_info_idlers_count(worker_queue_info),
                 apr_atomic_read32(&connection_count),
                 apr_atomic_read32(backlog_q->total),
                 apr_atomic_read32(waitio_q->total),
                 apr_atomic_read32(write_completion_q->total),
                 apr_atomic_read32(keepalive_q->total),
                 apr_atomic_read32(shutdown_q->total),
                 apr_atomic_read32(linger_q->total),
                 apr_atomic_read32(&timers_count),
                 apr_atomic_read32(&suspended_count));

    ps = &ap_scoreboard_image->parent[ap_child_slot];
    ps->not_accepting = 1;

    for (i = 0; i < num_listensocks; i++) {
        apr_pollset_remove(event_pollset, &listener_pollfd[i]);
    }
    return 1;
}

static int enable_listensocks(void)
{
    volatile process_score *ps;
    int i;

    if (apr_atomic_read32(&dying)
        || apr_atomic_cas32(&listensocks_off, 0, 1) != 1) {
        return 0;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf, APLOGNO(00457)
                 "Resume listening sockets: idlers:%i conns:%u backlog:%u "
                 "waitio:%u write:%u keepalive:%u shutdown:%u "
                 "linger:%u timers:%u suspended:%u",
                 ap_queue_info_idlers_count(worker_queue_info),
                 apr_atomic_read32(&connection_count),
                 apr_atomic_read32(backlog_q->total),
                 apr_atomic_read32(waitio_q->total),
                 apr_atomic_read32(write_completion_q->total),
                 apr_atomic_read32(keepalive_q->total),
                 apr_atomic_read32(shutdown_q->total),
                 apr_atomic_read32(linger_q->total),
                 apr_atomic_read32(&timers_count),
                 apr_atomic_read32(&suspended_count));

    /*
     * XXX: This is not yet optimal. If many workers suddenly become available,
     * XXX: the parent may kill some processes off too soon.
     */
    ps = &ap_scoreboard_image->parent[ap_child_slot];
    ps->not_accepting = 0;

    for (i = 0; i < num_listensocks; i++) {
        apr_pollset_add(event_pollset, &listener_pollfd[i]);
    }
    return 1;
}

static APR_INLINE int listensocks_disabled(void)
{
    return apr_atomic_read32(&listensocks_off) != 0;
}

/* Choose one of these */
#define LIMIT_BY_CONNS_TOTAL_VS_IDLERS                           0
#define LIMIT_BY_BACKLOG_MAYBLOCK_VS_IDLERS                      0
#define LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_VS_IDLERS            1 /* the winner? */
#define LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_AND_QUEUES_VS_IDLERS 0

#if LIMIT_BY_BACKLOG_MAYBLOCK_VS_IDLERS \
    || LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_VS_IDLERS \
    || LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_AND_QUEUES_VS_IDLERS
/* The rationale for backlog_nonblock_count is that only connections about
 * to be processed outside the MPM can make a worker thread block, since we
 * have no guarantee that modules won't block processing them. The core will
 * not block processing TLS handshakes or reading the HTTP header for instance,
 * but once the connections are passed to modules they may block in a handler
 * reading the body or whatever. Those connections are in CONN_STATE_PROCESSING
 * state in the backlog, which includes newly accepted connections and the ones
 * waking up from CONN_STATE_KEEPALIVE and CONN_STATE_ASYNC_WAITIO.
 * But the processing by/inside MPM event will never block, so fast enough
 * eventually to consider the connections fully handled by the MPM differently
 * in connnections_above_limit(), where backlog_nonblock_count can help.
 */
static /*atomic*/ apr_uint32_t backlog_nonblock_count;
#endif

static APR_INLINE int connections_above_limit(void)
{
    /* Note that idlers >= 0 gives the number of idle workers, idlers < 0 gives
     * the number of connections in the backlog waiting for an idle worker.
     */
    int idlers = ap_queue_info_idlers_count(worker_queue_info);

#if LIMIT_BY_CONNS_TOTAL_VS_IDLERS

    /* Limit reached when the number of connections (excluding the ones in
     * lingering close) is above the number of idle workers.
     */
    if (idlers >= 0) {
        int conns = (apr_atomic_read32(&connection_count) -
                     apr_atomic_read32(linger_q->total));
        AP_DEBUG_ASSERT(conns >= 0);
        if (idlers >= conns) {
            return 0;
        }
    }

#elif LIMIT_BY_BACKLOG_MAYBLOCK_VS_IDLERS

    /* Limit reached when the number of potentially blocking connections in
     * the backlog is above the number of idle workers.
     *
     * Ignore connections in the backlog with "nonblocking" states by adding
     * them back.
     */
    idlers += apr_atomic_read32(&backlog_nonblock_count);
    if (idlers >= 0) {
        return 0;
    }

#elif LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_VS_IDLERS

    /* Limit reached when the number of potentially blocking connections in
     * the backlog is above the number of idle workers, or the total number
     * of connections waiting for a worker in the backlog is above some hard
     * workers_backlog_limit.
     */
    if (idlers >= -workers_backlog_limit) {
        /* Ignore connections in the backlog with "nonblocking" states by
         * adding them back.
         */
        idlers += apr_atomic_read32(&backlog_nonblock_count);
        if (idlers >= 0) {
            return 0;
        }
    }

#elif LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_AND_QUEUES_VS_IDLERS

    /* Limit reached when the number of potentially blocking connections in
     * the backlog *and* the queues is above the number of idle workers, or
     * the total number of connections waiting for a worker in the backlog
     * is above some hard workers_backlog_limit.
     */
    if (idlers >= -workers_backlog_limit) {
        /* Ignore connections in the backlog with "nonblocking" states by
         * adding them back.
         */
        idlers += apr_atomic_read32(&backlog_nonblock_count);
        if (idlers >= (apr_atomic_read32(keepalive_q->total) +
                       apr_atomic_read32(waitio_q->total))) {
            return 0;
        }
    }

#else

    /* Legacy but w/o ignoring the keepalive_q (not shrinked anymore).
     * Limit reached when the number of conns (besides lingering close ones)
     * is above some unclear limit (the total number of workers plus the
     * number of idle workers times the async factor..).
     */
    int off = listensocks_disabled(); /* off by disabled() to limit flip flop */
    if (idlers >= off) {
        int avail = (threads_per_child + (int)((idlers - off) * async_factor));
        int conns = (apr_atomic_read32(&connection_count) -
                     apr_atomic_read32(linger_q->total));
        AP_DEBUG_ASSERT(conns >= 0);
        if (avail >= conns) {
            return 0;
        }
    }

#endif

    return 1;
}

static APR_INLINE int should_enable_listensocks(void)
{
    return (listensocks_disabled()
            && !apr_atomic_read32(&dying)
            && !connections_above_limit());
}

static void close_socket_at(apr_socket_t *csd,
                            const char *at, int line)
{
    apr_os_sock_t fd = -1;
    apr_status_t rv = apr_os_sock_get(&fd, csd);

    /* close_worker_sockets() may have closed it already */
    if (rv == APR_SUCCESS && fd == -1) {
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "dead socket %pp at %s:%i", csd, at, line);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE7, rv, ap_server_conf,
                "closing socket %pp:%i at %s:%i", csd, (int)fd, at, line);

    apr_socket_opt_set(csd, APR_SO_NONBLOCK, 1);
    rv = apr_socket_close(csd);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(00468)
                     "error closing socket");
        AP_DEBUG_ASSERT(0);
    }
}
#define close_socket(csd) \
    close_socket_at(csd, __FUNCTION__, __LINE__)

static void close_worker_sockets(void)
{
    int i;
    for (i = 0; i < threads_per_child; i++) {
        apr_socket_t *csd = worker_sockets[i];
        if (csd) {
            worker_sockets[i] = NULL;
            close_socket(csd);
        }
    }
}

static void shutdown_listener(void)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "shutting down listener%s",
                 apr_atomic_read32(&listener_may_exit) ? " again" : "");

    apr_atomic_set32(&listener_may_exit, 1);

    /* Unblock the listener if it's poll()ing */
    if (event_pollset && listener_is_wakeable) {
        apr_pollset_wakeup(event_pollset);
    }

    /* unblock the listener if it's waiting for a worker */
    if (worker_queue_info) {
        ap_queue_info_term(worker_queue_info);
    }

    if (!listener_os_thread) {
        /* XXX there is an obscure path that this doesn't handle perfectly:
         *     right after listener thread is created but before
         *     listener_os_thread is set, the first worker thread hits an
         *     error and starts graceful termination
         */
        return;
    }
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
    if (terminate_mode >= mode) {
        return;
    }
    terminate_mode = mode;
    retained->mpm->mpm_state = AP_MPMQ_STOPPING;

    /* in case we weren't called from the listener thread, wake up the
     * listener thread
     */
    shutdown_listener();

    /* for ungraceful termination, let the workers exit now;
     * for graceful termination, the listener thread will notify the
     * workers to exit once it has stopped accepting new connections
     */
    if (mode == ST_UNGRACEFUL) {
        apr_atomic_set32(&workers_may_exit, 1);
        ap_queue_interrupt_all(worker_queue);
        close_worker_sockets(); /* forcefully kill all current connections */
    }

    ap_run_child_stopping(pchild, mode == ST_GRACEFUL);
}

static int event_query(int query_code, int *result, apr_status_t *rv)
{
    *rv = APR_SUCCESS;
    switch (query_code) {
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = retained->max_daemon_used;
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
    case AP_MPMQ_HAS_SERF:
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
        *result = active_daemons_limit;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = retained->mpm->mpm_state;
        break;
    case AP_MPMQ_GENERATION:
        *result = retained->mpm->my_generation;
        break;
    case AP_MPMQ_CAN_SUSPEND:
        *result = 1;
        break;
    case AP_MPMQ_CAN_POLL:
        *result = 1;
        break;
    case AP_MPMQ_CAN_WAITIO:
        *result = 1;
        break;
    default:
        *rv = APR_ENOTIMPL;
        break;
    }
    return OK;
}

static void event_note_child_stopped(int slot, pid_t pid, ap_generation_t gen)
{
    if (slot != -1) { /* child had a scoreboard slot? */
        volatile process_score *ps = &ap_scoreboard_image->parent[slot];
        int i;

        pid = ps->pid;
        gen = ps->generation;
        for (i = 0; i < threads_per_child; i++) {
            ap_update_child_status_from_indexes(slot, i, SERVER_DEAD, NULL);
        }
        ap_run_child_status(ap_server_conf, pid, gen, slot, MPM_CHILD_EXITED);
        if (ps->quiescing != 2) { /* vs perform_idle_server_maintenance() */
            retained->active_daemons--;
        }
        retained->total_daemons--;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "Child %d stopped: pid %d, gen %d, "
                     "active %d/%d, total %d/%d/%d, quiescing %d",
                     slot, (int)pid, (int)gen,
                     retained->active_daemons, active_daemons_limit,
                     retained->total_daemons, retained->max_daemon_used,
                     server_limit, ps->quiescing);
        ps->not_accepting = 0;
        ps->quiescing = 0;
        ps->pid = 0;
    }
    else {
        ap_run_child_status(ap_server_conf, pid, gen, -1, MPM_CHILD_EXITED);
    }
}

static void event_note_child_started(int slot, pid_t pid)
{
    ap_generation_t gen = retained->mpm->my_generation;

    retained->total_daemons++;
    retained->active_daemons++;
    ap_scoreboard_image->parent[slot].pid = pid;
    ap_scoreboard_image->parent[slot].generation = gen;
    ap_run_child_status(ap_server_conf, pid, gen, slot, MPM_CHILD_STARTED);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "Child %d started: pid %d, gen %d, "
                 "active %d/%d, total %d/%d/%d",
                 slot, (int)pid, (int)gen,
                 retained->active_daemons, active_daemons_limit,
                 retained->total_daemons, retained->max_daemon_used,
                 server_limit);
}

static const char *event_get_name(void)
{
    return "event";
}

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    retained->mpm->mpm_state = AP_MPMQ_STOPPING;
    if (terminate_mode == ST_INIT) {
        ap_run_child_stopping(pchild, 0);
    }

    if (pchild) {
        ap_run_child_stopped(pchild, terminate_mode == ST_GRACEFUL);
        apr_pool_destroy(pchild);
    }

    if (one_process) {
        event_note_child_stopped(/* slot */ 0, 0, 0);
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

static apr_status_t decrement_connection_count(void *cs_)
{
    event_conn_state_t *cs = cs_;
    int is_last_connection, is_dying;

    ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                 "connection %" CS_FMT_TO " cleaned up",
                 CS_ARG_TO(cs));

    switch (cs->pub.state) {
    case CONN_STATE_SUSPENDED:
        apr_atomic_dec32(&suspended_count);
    default:
        break;
    }

    /* Unblock the listener if it's waiting for connection_count = 0,
     * or if the listening sockets were disabled due to limits and can
     * now accept new connections.
     */
    is_last_connection = !apr_atomic_dec32(&connection_count);
    is_dying = apr_atomic_read32(&dying);
    if (listener_is_wakeable
        && ((is_last_connection && is_dying)
            || should_enable_listensocks())) {
        apr_pollset_wakeup(event_pollset);
    }
    if (is_dying) {
        /* Help worker_thread_should_exit_early() */
        ap_queue_interrupt_one(worker_queue);
    }
    return APR_SUCCESS;
}

static void notify_suspend(event_conn_state_t *cs)
{
    ap_run_suspend_connection(cs->c, cs->r);
    cs->c->sbh = NULL;
    cs->suspended = 1;
}

static void notify_resume(event_conn_state_t *cs, int cleanup)
{
    cs->suspended = 0;
    cs->c->sbh = cleanup ? NULL : cs->sbh;
    ap_run_resume_connection(cs->c, cs->r);
}

/* Close the connection and release its resources (ptrans), either because an
 * unrecoverable error occured (queues or pollset add/remove) or more usually
 * if lingering close timed out.
 * Pre-condition: nonblocking, can be called from anywhere provided cs is not
 *                in any timeout queue or in the pollset.
 */
static void close_connection_at(event_conn_state_t *cs,
                                const char *at, int line)
{
    if (cs->c) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                      "closing connection %" CS_FMT " at %s:%i",
                      CS_ARG(cs), at, line);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                      "closing connection %" CS_FMT_TO " at %s:%i",
                      CS_ARG_TO(cs), at, line);
    }

    close_socket_at(cs_sd(cs), at, line);
    ap_queue_info_push_pool(worker_queue_info, cs->p);
}
#define close_connection(cs) \
    close_connection_at((cs), __FUNCTION__, __LINE__)

static void kill_connection_at(event_conn_state_t *cs, apr_status_t status,
                               const char *at, int line)
{
    if (cs->c) {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, status, cs->c, APLOGNO(10382)
                      "killing connection in %s at %s:%i",
                      cs_state_str(cs), at, line);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, status, ap_server_conf, APLOGNO(10383)
                     "killing unprocessed connection from %pI in %s at %s:%i",
                     cs_raddr(cs), cs_state_str(cs), at, line);
    }

    close_connection_at(cs, at, line);
}
#define kill_connection(cs, status) \
    kill_connection_at((cs), (status), __FUNCTION__, __LINE__)

/* forward declare */
static void set_conn_state_sense(event_conn_state_t *cs, int sense);
static void push2worker(event_conn_state_t *cs, timer_event_t *te,
                        apr_time_t now, int *busy);

/* Shutdown the connection in case of timeout, error or resources shortage.
 * This starts lingering close if not already there, or directly closes
 * the connection otherwise.
 * Pre-condition: nonblocking, can be called from anywhere provided cs is not
 *                in the pollset nor any non-backlog timeout queue.
 */
static void shutdown_connection(event_conn_state_t *cs, apr_time_t now,
                                int in_backlog)
{
    ap_assert(!cs->q && !cs->te);

    if (cs->c) {
        int log_level = APLOG_INFO;
        switch (cs->pub.state) {
        case CONN_STATE_LINGER:
        case CONN_STATE_KEEPALIVE:
            log_level = APLOG_TRACE2;
        default:
            break;
        }
        ap_log_cerror(APLOG_MARK, log_level, 0, cs->c, APLOGNO(10380)
                      "shutting down %s connection in %s",
                      in_backlog ? "backlog" : "timed out",
                      cs_state_str(cs));

        /* Don't re-schedule connections in lingering close, they had
         * their chance already so just close them now.
         */
        if (cs->pub.state != CONN_STATE_LINGER) {
            cs->pub.state = CONN_STATE_LINGER;
            push2worker(cs, NULL, now, NULL);
        }
        else {
            close_connection(cs);
        }
    }
    else {
        /* Never been scheduled/processed, kill it. */
        ap_assert(in_backlog);
        kill_connection(cs, APR_EBUSY);
    }
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
        notify_resume(cs, 1);
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
    cs->sc = ap_get_module_config(ap_server_conf->module_config,
                                  &mpm_event_module);
    apr_pool_cleanup_register(r->pool, c, event_request_cleanup,
                              apr_pool_cleanup_null);
}

/*
 * event_post_read_request() tracks the current server config for a
 * given request.
 */
static int event_post_read_request(request_rec *r)
{
    conn_rec *c = r->connection;
    event_conn_state_t *cs = ap_get_module_config(c->conn_config,
                                                  &mpm_event_module);

    /* Use Timeout from the request's server. */
    cs->sc = ap_get_module_config(r->server->module_config,
                                  &mpm_event_module);

    /* To preserve legacy behaviour (consistent with other MPMs), use
     * KeepaliveTimeout from the base server (first on this IP:port)
     * when none is explicitly configured on this server. Otherwise
     * use the one from the request's server.
     */
    if (!r->server->keep_alive_timeout_set) {
        cs->ka_sc = ap_get_module_config(c->base_server->module_config,
                                         &mpm_event_module);
    }
    else {
        cs->ka_sc = cs->sc;
    }

    return OK;
}

static int pollset_add_at(event_conn_state_t *cs, int sense,
                          struct timeout_queue *q, timer_event_t *te,
                          const char *at, int line)
{
    apr_status_t rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "pollset: add %s=%" APR_TIME_T_FMT " events=%x"
                  " for connection %" CS_FMT " at %s:%i",
                  (q) ? "q" : "t",
                  (q) ? q->timeout : (te) ? te->timeout : -1,
                  (int)cs->pfd.reqevents,
                  CS_ARG(cs), at, line);

    ap_assert(cs->q == NULL && cs->te == NULL && ((q != NULL) ^ (te != NULL)));

    set_conn_state_sense(cs, sense);

    if (q) {
        apr_thread_mutex_lock(timeout_mutex);
        TO_QUEUE_APPEND(q, cs);
    }
    else {
        cs->te = te;
    }

    rv = apr_pollset_add(event_pollset, &cs->pfd);
    if (rv != APR_SUCCESS) {
        if (q) {
            TO_QUEUE_REMOVE(q, cs);
            apr_thread_mutex_unlock(timeout_mutex);
        }
        else {
            te->canceled = 1;
            cs->te = NULL;
        }

        /* close_worker_sockets() may have closed it already */
        if (apr_atomic_read32(&workers_may_exit)) {
            AP_DEBUG_ASSERT(APR_STATUS_IS_EBADF(rv));
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, cs->c, APLOGNO(03093)
                          "pollset add failed for connection %" CS_FMT " at %s:%i",
                          CS_ARG(cs), at, line);
            AP_DEBUG_ASSERT(0);
            signal_threads(ST_GRACEFUL);
        }
        return 0;
    }
    if (q) {
        apr_thread_mutex_unlock(timeout_mutex);
    }
    return 1;
}
#define pollset_add(cs, sense, q, te) \
    pollset_add_at((cs), (sense), (q), (te), __FUNCTION__, __LINE__)

static int pollset_del_at(event_conn_state_t *cs, int locked,
                          const char *at, int line)
{
    apr_status_t rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "pollset: del %s=%" APR_TIME_T_FMT " events=%x"
                  " for connection %" CS_FMT " at %s:%i",
                  (cs->q) ? "q" : "t",
                  (cs->q) ? cs->q->timeout : (cs->te ? cs->te->timeout : -1),
                  (int)cs->pfd.reqevents,
                  CS_ARG(cs), at, line);

    ap_assert((cs->q != NULL) ^ (cs->te != NULL));

    if (cs->q) {
        if (!locked) {
            apr_thread_mutex_lock(timeout_mutex);
        }
        TO_QUEUE_REMOVE(cs->q, cs);
        if (!locked) {
            apr_thread_mutex_unlock(timeout_mutex);
        }
    }
    else {
        cs->te->canceled = 1;
        cs->te = NULL;
    }

    /*
     * Some of the pollset backends, like KQueue or Epoll
     * automagically remove the FD if the socket is closed,
     * therefore, we can accept _SUCCESS or _NOTFOUND,
     * and we still want to keep going
     */
    rv = apr_pollset_remove(event_pollset, &cs->pfd);
    if (rv != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rv)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, cs->c, APLOGNO(03094)
                      "pollset remove failed for connection %" CS_FMT " at %s:%i",
                      CS_ARG(cs), at, line);
        AP_DEBUG_ASSERT(0);
        signal_threads(ST_GRACEFUL);
        return 0;
    }

    return 1;
}
#define pollset_del(cs, locked) \
    pollset_del_at((cs), (locked), __FUNCTION__, __LINE__)

/* Forward declare */
static timer_event_t *get_timer_event(apr_time_t timeout,
                                      ap_mpm_callback_fn_t *cbfn, void *baton,
                                      int insert,
                                      apr_array_header_t *pfds);
static void process_lingering_close(event_conn_state_t *cs);

static event_conn_state_t *make_conn_state(apr_pool_t *p, apr_socket_t *csd)
{
    event_conn_state_t *cs = apr_pcalloc(p, sizeof(*cs));
    listener_poll_type *pt;

    cs->pfd.desc_type = APR_POLL_SOCKET;
    cs->pfd.desc.s = cs_se(cs)->sd = csd;
    cs->pfd.client_data = pt = apr_pcalloc(p, sizeof(*pt));
    cs_qe(cs)->cb_baton = cs_se(cs)->baton = cs;
    cs_qe(cs)->type = AP_QUEUE_EVENT_SOCK;
    cs_qe(cs)->data.se = cs_se(cs);
    cs->p = cs_se(cs)->p = p;
    pt->type = PT_CSD;
    pt->baton = cs;

    APR_RING_ELEM_INIT(cs, timeout_list);

    cs->sc = cs->ka_sc = ap_get_module_config(ap_server_conf->module_config,
                                              &mpm_event_module);

    /**
     * XXX If the platform does not have a usable way of bundling
     * accept() with a socket readability check, like Win32,
     * and there are measurable delays before the
     * socket is readable due to the first data packet arriving,
     * it might be better to create the cs on the listener thread
     * with the state set to CONN_STATE_KEEPALIVE
     *
     * FreeBSD users will want to enable the HTTP accept filter
     * module in their kernel for the highest performance
     * When the accept filter is active, sockets are kept in the
     * kernel until a HTTP request is received.
     */
    cs->pub.state = CONN_STATE_PROCESSING;
    cs->pub.sense = CONN_SENSE_DEFAULT;

    apr_atomic_inc32(&connection_count);
    apr_pool_cleanup_register(p, cs, decrement_connection_count,
                              apr_pool_cleanup_null);
    return cs;
}

static void set_conn_state_sense(event_conn_state_t *cs, int default_sense)
{
    int sense = default_sense;

    if (cs->pub.sense != CONN_SENSE_DEFAULT) {
        sense = cs->pub.sense;

        /* Reset to default for the next round */
        cs->pub.sense = CONN_SENSE_DEFAULT;
    }

    if (sense == CONN_SENSE_WANT_READ) {
        cs->pfd.reqevents = APR_POLLIN | APR_POLLHUP;
    }
    else {
        cs->pfd.reqevents = APR_POLLOUT;
    }
    /* POLLERR is usually returned event only, but some pollset
     * backends may require it in reqevents to do the right thing,
     * so it shouldn't hurt (ignored otherwise).
     */
    cs->pfd.reqevents |= APR_POLLERR;
}

/*
 * process one connection in the worker
 */
static void process_socket(apr_thread_t *thd, apr_pool_t *p,
                           apr_socket_t *sock, event_conn_state_t *cs,
                           int my_child_num, int my_thread_num)
{
    conn_rec *c = cs->c;
    long conn_id = ID_FROM_CHILD_THREAD(my_child_num, my_thread_num);
    int rc = OK, processed = 0;

    if (!c) { /* This is a new connection */
        cs->bucket_alloc = apr_bucket_alloc_create(p);
        ap_create_sb_handle(&cs->sbh, p, my_child_num, my_thread_num);
        cs->c = c = ap_run_create_connection(p, ap_server_conf, sock, conn_id,
                                             cs->sbh, cs->bucket_alloc);
        if (!c) {
            ap_queue_info_push_pool(worker_queue_info, p);
            return;
        }
        apr_pool_pre_cleanup_register(p, cs, ptrans_pre_cleanup);
        ap_set_module_config(c->conn_config, &mpm_event_module, cs);
        c->current_thread = thd;
        c->cs = &cs->pub;

        ap_update_vhost_given_ip(c);
        rc = ap_pre_connection(c, sock);
        if (rc != OK && rc != DONE) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(00469)
                          "process_socket: connection aborted (%d)", rc);
            close_connection(cs);
            return;
        }

        cs->pub.sense = CONN_SENSE_DEFAULT;
    }
    else { /* The connection is scheduled back */
        c = cs->c;
        c->current_thread = thd;
        c->id = conn_id; /* thread number is part of ID */
        ap_update_sb_handle(cs->sbh, my_child_num, my_thread_num);
        notify_resume(cs, 0);
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                  "processing connection %" CS_FMT " (aborted %d, clogging %d)",
                  CS_ARG(cs), c->aborted, c->clogging_input_filters);

    if (cs->pub.state == CONN_STATE_LINGER) {
        goto lingering_close;
    }

    if (cs->pub.state == CONN_STATE_PROCESSING
        /* If we have an input filter which 'clogs' the input stream,
         * like mod_ssl used to, lets just do the normal read from input
         * filters, like the Worker MPM does. Filters that need to write
         * where they would otherwise read, or read where they would
         * otherwise write, should set the sense appropriately.
         */
         || c->clogging_input_filters) {
 process_connection:
        processed = 1;
        cs->pub.state = CONN_STATE_PROCESSING;
        rc = ap_run_process_connection(c);
        /*
         * The process_connection hooks should set the appropriate connection
         * state upon return, for event MPM to either:
         * - CONN_STATE_LINGER: do lingering close;
         * - CONN_STATE_WRITE_COMPLETION: flush pending outputs using Timeout
         *   and wait for next incoming data using KeepAliveTimeout, then come
         *   back to process_connection() hooks;
         * - CONN_STATE_SUSPENDED: suspend the connection such that it now
         *   interacts with the MPM through suspend/resume_connection() hooks,
         *   and/or registered poll callbacks (PT_USER), and/or registered
         *   timed callbacks triggered by timer events;
         * - CONN_STATE_ASYNC_WAITIO: wait for read/write-ability of the underlying
         *   socket using Timeout and come back to process_connection() hooks when
         *   ready;
         * - CONN_STATE_KEEPALIVE: now handled by CONN_STATE_WRITE_COMPLETION
         *   to flush before waiting for next data (that might depend on it).
         * If a process_connection hook returns an error or no hook sets the state
         * to one of the above expected value, forcibly close the connection w/
         * CONN_STATE_LINGER.  This covers the cases where no process_connection
         * hook executes (DECLINED), or one returns OK w/o touching the state (i.e.
         * CONN_STATE_PROCESSING remains after the call) which can happen with
         * third-party modules not updated to work specifically with event MPM
         * while this was expected to do lingering close unconditionally with
         * worker or prefork MPMs for instance.
         */
        switch (rc) {
        case DONE:
            rc = OK; /* same as OK, fall through */
        case OK:
            if (cs->pub.state == CONN_STATE_PROCESSING) {
                cs->pub.state = CONN_STATE_LINGER;
            }
            else if (cs->pub.state == CONN_STATE_KEEPALIVE) {
                cs->pub.state = CONN_STATE_WRITE_COMPLETION;
            }
            break;
        }
        if (rc != OK || (cs->pub.state != CONN_STATE_LINGER
                         && cs->pub.state != CONN_STATE_ASYNC_WAITIO
                         && cs->pub.state != CONN_STATE_WRITE_COMPLETION
                         && cs->pub.state != CONN_STATE_SUSPENDED)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(10111)
                          "process_socket: connection processing returned %i "
                          "(%sstate %i): closing",
                          rc, rc ? "" : "unexpected ", (int)cs->pub.state);
            cs->pub.state = CONN_STATE_LINGER;
        }
        else if (c->aborted) {
            cs->pub.state = CONN_STATE_LINGER;
        }
        if (cs->pub.state == CONN_STATE_LINGER) {
            goto lingering_close;
        }
    }

    if (cs->pub.state == CONN_STATE_ASYNC_WAITIO) {
        apr_interval_time_t timeout;
        struct timeout_queue *q = NULL;
        timer_event_t *te = NULL;

        /* Set a read/write timeout for this connection, and let the
         * event thread poll for read/writeability.
         */
        ap_update_child_status(cs->sbh, SERVER_BUSY_READ, NULL);
        notify_suspend(cs);

        /* If the connection timeout is actually different than the waitio_q's,
         * use a timer event to honor it (e.g. mod_reqtimeout may enforce its
         * own timeouts per request stage).
         */
        timeout = ap_get_connection_timeout(c, cs->sc->s);
        if (timeout >= 0 && timeout != cs->sc->io_q->timeout) {
            /* Prevent the timer from firing before the pollset is updated */
            if (timeout < TIMERS_FUDGE_TIMEOUT) {
                timeout = TIMERS_FUDGE_TIMEOUT;
            }
            te = get_timer_event(timeout, NULL, cs, 1, NULL);
        }
        else {
            q = cs->sc->io_q;
        }
        if (!pollset_add(cs, CONN_SENSE_WANT_READ, q, te)) {
            cs->pub.state = CONN_STATE_LINGER;
            goto lingering_close;
        }

        return; /* queued */
    }

    if (cs->pub.state == CONN_STATE_WRITE_COMPLETION) {
        int pending = OK;

        /* Flush all pending outputs before going to CONN_STATE_KEEPALIVE or
         * straight to CONN_STATE_PROCESSING if inputs are pending already.
         */
        ap_update_child_status(cs->sbh, SERVER_BUSY_WRITE, NULL);

        if (!processed) {
            pending = ap_check_output_pending(c);
        }
        else if (ap_filter_should_yield(c->output_filters)) {
            pending = AGAIN;
        }
        if (pending == AGAIN) {
            /* Let the event thread poll for write */
            notify_suspend(cs);
            cs->pub.sense = CONN_SENSE_DEFAULT;
            if (pollset_add(cs, CONN_SENSE_WANT_WRITE, cs->sc->wc_q, NULL)) {
                return; /* queued */
            }
            /* Fall through lingering close */
        }
        else if (pending == OK) {
            /* Some data to process immediately? */
            pending = (c->keepalive == AP_CONN_KEEPALIVE
                       ? ap_check_input_pending(c)
                       : DONE);
            if (pending == AGAIN) {
                goto process_connection;
            }
        }
        if (pending != OK) {
            cs->pub.state = CONN_STATE_LINGER;
            goto lingering_close;
        }

        /* Fall through */
        cs->pub.state = CONN_STATE_KEEPALIVE;
    }

    if (cs->pub.state == CONN_STATE_KEEPALIVE) {
        ap_update_child_status(cs->sbh, SERVER_BUSY_KEEPALIVE, NULL);

        /* It greatly simplifies the logic to use a single timeout value per q
         * because the new element can just be added to the end of the list and
         * it will stay sorted in expiration time sequence.  If brand new
         * sockets are sent to the event thread for a readability check, this
         * will be a slight behavior change - they use the non-keepalive
         * timeout today.  With a normal client, the socket will be readable in
         * a few milliseconds anyway.
         */
        notify_suspend(cs);

        if (!pollset_add(cs, CONN_SENSE_WANT_READ, cs->ka_sc->ka_q, NULL)) {
            cs->pub.state = CONN_STATE_LINGER;
            goto lingering_close;
        }

        return; /* queued */
    }

    if (cs->pub.state == CONN_STATE_SUSPENDED) {
        cs->c->suspended_baton = cs;
        apr_atomic_inc32(&suspended_count);
        notify_suspend(cs);
        return; /* done */
    }

 lingering_close:
    process_lingering_close(cs);
}

/* Put a SUSPENDED connection back into a queue. */
static apr_status_t event_resume_suspended (conn_rec *c)
{
    event_conn_state_t* cs = (event_conn_state_t*) c->suspended_baton;
    if (cs == NULL) {
        ap_log_cerror (APLOG_MARK, LOG_WARNING, 0, c, APLOGNO(02615)
                "event_resume_suspended: suspended_baton is NULL");
        return APR_EGENERAL;
    }
    if (!cs->suspended) {
        ap_log_cerror (APLOG_MARK, LOG_WARNING, 0, c, APLOGNO(02616)
                "event_resume_suspended: Thread isn't suspended");
        return APR_EGENERAL;
    }

    apr_atomic_dec32(&suspended_count);
    c->suspended_baton = NULL;

    cs->pub.sense = CONN_SENSE_DEFAULT;
    if (cs->pub.state != CONN_STATE_LINGER) {
        cs->pub.state = CONN_STATE_WRITE_COMPLETION;
        if (pollset_add(cs, CONN_SENSE_WANT_WRITE, cs->sc->wc_q, NULL)) {
            return APR_SUCCESS; /* queued */
        }

        /* fall through lingering close on error */
        cs->pub.state = CONN_STATE_LINGER;
    }
    process_lingering_close(cs);
    return APR_SUCCESS;
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
    /* keep going */
    conns_this_child = APR_INT32_MAX;
}

static void set_child_dying(void)
{
    volatile process_score *ps;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, "quiescing");
    ps = &ap_scoreboard_image->parent[ap_child_slot];
    ps->quiescing = 1;

    apr_atomic_set32(&dying, 1);
    disable_listensocks(); /* definitively with dying = 1 */
    ap_close_listeners_ex(my_bucket->listeners);

#if 0
    {
        int i;
        for (i = 0; i < threads_per_child; ++i) {
            ap_update_child_status_from_indexes(ap_child_slot, i,
                                                SERVER_GRACEFUL, NULL);
        }
    }
#endif

    /* wake up idle worker threads */
    ap_queue_interrupt_all(worker_queue);
    /* wake up the main thread */
    kill(ap_my_pid, SIGTERM);

    /* No new connections will use the idle pools */
    ap_queue_info_free_idle_pools(worker_queue_info);
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


#if HAVE_SERF
static apr_status_t s_socket_add(void *user_baton,
                                 apr_pollfd_t *pfd,
                                 void *serf_baton)
{
    s_baton_t *s = (s_baton_t*)user_baton;
    /* XXXXX: recycle listener_poll_types */
    listener_poll_type *pt = ap_malloc(sizeof(*pt));
    pt->type = PT_SERF;
    pt->baton = serf_baton;
    pfd->client_data = pt;
    return apr_pollset_add(s->pollset, pfd);
}

static apr_status_t s_socket_remove(void *user_baton,
                                    apr_pollfd_t *pfd,
                                    void *serf_baton)
{
    s_baton_t *s = (s_baton_t*)user_baton;
    listener_poll_type *pt = pfd->client_data;
    free(pt);
    return apr_pollset_remove(s->pollset, pfd);
}
#endif

#if HAVE_SERF
static void init_serf(apr_pool_t *p)
{
    s_baton_t *baton = NULL;

    baton = apr_pcalloc(p, sizeof(*baton));
    baton->pollset = event_pollset;
    /* TODO: subpools, threads, reuse, etc.  -- currently use malloc() inside :( */
    baton->pool = p;

    g_serf = serf_context_create_ex(baton,
                                    s_socket_add,
                                    s_socket_remove, p);

    ap_register_provider(p, "mpm_serf",
                         "instance", "0", g_serf);
}
#endif

/* A backlog connection is both in the worker_queue (for a worker to pull
 * it ASAP) and in the backlog_q (for the listener to enforce a timeout).
 * The worker_queue can do the queuing on both queues for us, that is
 * consistently and safely push/pop to/from both queues under its lock,
 * thanks to a callback called when an event is pushed and popped.
 */
static void conn_state_backlog_cb(void *baton, int pushed)
{
    event_conn_state_t *cs = baton;

    if (pushed) {
        TO_QUEUE_APPEND(cs->sc->bl_q, cs);
#if LIMIT_BY_BACKLOG_MAYBLOCK_VS_IDLERS \
    || LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_VS_IDLERS \
    || LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_AND_QUEUES_VS_IDLERS
        if (cs->pub.state != CONN_STATE_PROCESSING) {
            /* These connections won't block when processed.
             *
             * Increment *after* TO_QUEUE_APPEND() to make sure that:
             *   cs->sc->bl_q->total >= backlog_nonblock_count
             * always holds.
             */
            apr_atomic_inc32(&backlog_nonblock_count);
        }
#endif
    }
    else { /* popped */
#if LIMIT_BY_BACKLOG_MAYBLOCK_VS_IDLERS \
    || LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_VS_IDLERS \
    || LIMIT_BY_BACKLOG_TOTAL_AND_MAYBLOCK_AND_QUEUES_VS_IDLERS
        if (cs->pub.state != CONN_STATE_PROCESSING) {
            /* These connections won't block when processed.
             *
             * Decrement *before* TO_QUEUE_REMOVE() to make sure that:
             *   cs->sc->bl_q->total >= backlog_nonblock_count
             * always holds.
             */
            apr_atomic_dec32(&backlog_nonblock_count);
        }
#endif
        TO_QUEUE_REMOVE(cs->sc->bl_q, cs);

        /* not in backlog anymore */
        cs_qe(cs)->cb = NULL;
    }
}

static void timer_event_backlog_cb(void *baton, int pushed)
{
    timer_event_t *te = baton;
    ap_assert(te && te_qe(te));

    if (pushed) {
        apr_atomic_inc32(&timers_count);
    }
    else { /* popped */
        apr_atomic_dec32(&timers_count);

        /* not in backlog anymore */
        te_qe(te)->cb = NULL;
    }
}

/*
 * Pre-condition: cs is neither in event_pollset nor a queue
 * this function may only be called by the listener
 */
static void push2worker(event_conn_state_t *cs, timer_event_t *te,
                        apr_time_t now, int *above_limit)
{
    ap_queue_event_t *qe;
    apr_status_t rc;
    int busy;

    ap_assert((cs != NULL) ^ (te != NULL));

    busy = (ap_queue_info_idlers_dec(worker_queue_info) < 0);
    if (busy) {
        /* Might need to kindle the fire by not accepting new connections until
         * the situation settles down. The listener and new idling workers will
         * test for should_enable_listensocks() to recover (when suitable).
         */
        if (connections_above_limit()) {
            disable_listensocks();
            if (above_limit) {
                *above_limit = 1;
            }
        }
    }

    if (te) {
        ap_assert(!te_in_backlog(te));

        qe = te_qe(te);
        qe->cb = timer_event_backlog_cb;
    }
    else {
        ap_assert(!cs_in_backlog(cs));
        ap_assert(!cs->q);

        if (busy && cs->pub.state == CONN_STATE_LINGER && cs->linger_shutdown) {
            /* Not worth lingering more on this connection if we are short of
             * workers and everything is flushed+shutdown already, back out
             * and close.
             */
            ap_queue_info_idlers_inc(worker_queue_info);
            close_connection(cs);
            return;
        }

        if (cs->c) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                          "pushing connection %" CS_FMT,
                          CS_ARG(cs));
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                          "pushing connection %" CS_FMT_TO,
                          CS_ARG_TO(cs));
        }

        qe = cs_qe(cs);
        qe->cb = conn_state_backlog_cb;
    }

    rc = ap_queue_push_event(worker_queue, qe);
    if (rc != APR_SUCCESS) {
        int mode = ST_GRACEFUL;

        ap_queue_info_idlers_inc(worker_queue_info);

        ap_log_error(APLOG_MARK, APLOG_CRIT, rc, ap_server_conf, APLOGNO(00471)
                     "push2worker: queuing %s failed", cs ? "socket" : "timer");

        if (cs) {
            /* Can't go anywhere, kill (and log). */
            kill_connection(cs, rc);
        }
        else {
            /* Can't call te->cbfunc() and potentially block there, someone is
             * going to miss this event thus never release their connection(s),
             * graceful stop could never complete.
             */
            mode = ST_UNGRACEFUL;
        }

        AP_DEBUG_ASSERT(0);
        signal_threads(mode);
    }
}

/* Structures to reuse */
static timer_event_t timer_free_ring;

static apr_skiplist *timer_skiplist;
static volatile apr_time_t timers_next_expiry;

/* The timer_comp() function is used by apr_skiplist_insert() to keep the
 * elements/timers sorted, but it should never return 0 because inserting
 * duplicates is not possible (apr_skiplist_add() would allow this but it's
 * not available before APR 1.6). Thus duplicates are sorted by order of
 * insertion and timers are never equal for the skiplist (not an issue
 * because MPM event does not use apr_skiplist_{find,remove}() but
 * apr_skiplist_pop() only).
 */
static int timer_comp(void *a, void *b)
{
    const timer_event_t *ta = a, *tb = b;
    return (ta->when < tb->when) ? -1 : 1;
}

static apr_thread_mutex_t *g_timer_skiplist_mtx;

static timer_event_t *get_timer_event(apr_time_t timeout,
                                      ap_mpm_callback_fn_t *cbfn, void *baton,
                                      int insert,
                                      apr_array_header_t *pfds)
{
    timer_event_t *te;
    apr_time_t now = (timeout < 0) ? 0 : event_time_now();

    /* oh yeah, and make locking smarter/fine grained. */

    apr_thread_mutex_lock(g_timer_skiplist_mtx);

    if (!APR_RING_EMPTY(&timer_free_ring.link, timer_event_t, link)) {
        te = APR_RING_FIRST(&timer_free_ring.link);
        APR_RING_REMOVE(te, link);
    }
    else {
        struct backlog_timer_event *bte;
        /* invariant: (te == &bte->te) => (te_qe(te) == &bte->qe) */
        bte = apr_skiplist_alloc(timer_skiplist, sizeof(*bte));
        memset(bte, 0, sizeof(*bte));
        bte->qe.type = AP_QUEUE_EVENT_TIMER;
        bte->qe.data.te = bte->qe.cb_baton = &bte->te;
        te = &bte->te;
    }

    APR_RING_ELEM_INIT(te, link);
    te->cbfunc = cbfn;
    te->baton = baton;
    te->when = now + timeout;
    te->timeout = timeout;
    te->pfds = pfds;

    if (insert) {
        apr_time_t next_expiry;

        /* Okay, add sorted by when.. */
        apr_skiplist_insert(timer_skiplist, te);

        /* Cheaply update the global timers_next_expiry with this event's
         * if it expires before.
         */
        next_expiry = timers_next_expiry;
        if (!next_expiry || next_expiry > te->when + TIMERS_FUDGE_TIMEOUT) {
            timers_next_expiry = te->when;
            /* Wake up the listener to eventually update its poll()ing timeout. */
            if (listener_is_wakeable) {
                apr_pollset_wakeup(event_pollset);
            }
        }
    }

    apr_thread_mutex_unlock(g_timer_skiplist_mtx);

    return te;
}

static void put_timer_event(timer_event_t *te, int locked)
{
    if (!locked) {
        apr_thread_mutex_lock(g_timer_skiplist_mtx);
    }

    memset(te, 0, sizeof(*te));
    APR_RING_INSERT_TAIL(&timer_free_ring.link, te, timer_event_t, link);

    if (!locked) {
        apr_thread_mutex_unlock(g_timer_skiplist_mtx);
    }
}

static apr_status_t event_register_timed_callback_ex(apr_time_t timeout,
                                                  ap_mpm_callback_fn_t *cbfn,
                                                  void *baton,
                                                  apr_array_header_t *pfds)
{
    if (!cbfn) {
        return APR_EINVAL;
    }
    get_timer_event(timeout, cbfn, baton, 1, pfds);
    return APR_SUCCESS;
}

static apr_status_t event_register_timed_callback(apr_time_t timeout,
                                                  ap_mpm_callback_fn_t *cbfn,
                                                  void *baton)
{
    event_register_timed_callback_ex(timeout, cbfn, baton, NULL);
    return APR_SUCCESS;
}

static apr_status_t event_cleanup_poll_callback(void *data)
{
    apr_status_t final_rc = APR_SUCCESS;
    apr_array_header_t *pfds = data;
    int i;

    for (i = 0; i < pfds->nelts; i++) {
        apr_pollfd_t *pfd = (apr_pollfd_t *)pfds->elts + i;
        if (pfd->client_data) {
            apr_status_t rc;
            rc = apr_pollset_remove(event_pollset, pfd);
            if (rc != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rc)) {
                final_rc = rc;
            }
            pfd->client_data = NULL;
        }
    }

    if (final_rc) {
        AP_DEBUG_ASSERT(0);
        signal_threads(ST_GRACEFUL);
    }
    return final_rc;
}

static apr_status_t event_register_poll_callback_ex(apr_pool_t *p,
                                                const apr_array_header_t *pfds,
                                                ap_mpm_callback_fn_t *cbfn,
                                                ap_mpm_callback_fn_t *tofn,
                                                void *baton,
                                                apr_time_t timeout)
{
    listener_poll_type *pt;
    socket_callback_baton_t *scb;
    apr_status_t rc, final_rc = APR_SUCCESS;
    int i;

    if (!cbfn || !tofn) {
        return APR_EINVAL;
    }

    scb = apr_pcalloc(p, sizeof(*scb));
    scb->cbfunc = cbfn;
    scb->user_baton = baton;
    scb->pfds = apr_array_copy(p, pfds);

    pt = apr_palloc(p, sizeof(*pt));
    pt->type = PT_USER;
    pt->baton = scb;

    apr_pool_pre_cleanup_register(p, scb->pfds, event_cleanup_poll_callback);

    for (i = 0; i < scb->pfds->nelts; i++) {
        apr_pollfd_t *pfd = (apr_pollfd_t *)scb->pfds->elts + i;
        if (pfd->reqevents) {
            if (pfd->reqevents & APR_POLLIN) {
                pfd->reqevents |= APR_POLLHUP;
            }
            pfd->reqevents |= APR_POLLERR;
            pfd->client_data = pt;
        }
        else {
            pfd->client_data = NULL;
        }
    }

    if (timeout > 0) {
        /* Prevent the timer from firing before the pollset is updated */
        if (timeout < TIMERS_FUDGE_TIMEOUT) {
            timeout = TIMERS_FUDGE_TIMEOUT;
        }
        scb->cancel_event = get_timer_event(timeout, tofn, baton, 1, scb->pfds);
    }
    for (i = 0; i < scb->pfds->nelts; i++) {
        apr_pollfd_t *pfd = (apr_pollfd_t *)scb->pfds->elts + i;
        if (pfd->client_data) {
            rc = apr_pollset_add(event_pollset, pfd);
            if (rc != APR_SUCCESS) {
                final_rc = rc;
            }
        }
    }
    return final_rc;
}

static apr_status_t event_register_poll_callback(apr_pool_t *p,
                                                 const apr_array_header_t *pfds,
                                                 ap_mpm_callback_fn_t *cbfn,
                                                 void *baton)
{
    return event_register_poll_callback_ex(p,
                                           pfds,
                                           cbfn,
                                           NULL, /* no timeout function */
                                           baton,
                                           0     /* no timeout */);
}

/*
 * Flush data and close our side of the connection, then drain incoming data.
 * If the latter would block put the connection in one of the linger timeout
 * queues to be called back when ready, and repeat until it's closed by peer.
 * Only to be called in the worker thread, and since it's in immediate call
 * stack, we can afford a comfortable buffer size to consume data quickly.
 * Pre-condition: cs is not in any timeout queue and not in the pollset,
 *                timeout_mutex is not locked
 */
#define LINGERING_BUF_SIZE (32 * 1024)
static void process_lingering_close(event_conn_state_t *cs)
{
    char dummybuf[LINGERING_BUF_SIZE];
    apr_socket_t *csd = cs_sd(cs);
    apr_status_t rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                  "lingering close for connection %" CS_FMT,
                  CS_ARG(cs));
    AP_DEBUG_ASSERT(cs->pub.state == CONN_STATE_LINGER);

    /* Flush and shutdown first */
    if (!cs->linger_shutdown) {
        conn_rec *c = cs->c;
        int rc = OK;

        cs->pub.state = CONN_STATE_LINGER;

        if (!cs->linger_started) {
            cs->linger_started = 1; /* once! */
            notify_suspend(cs);

            /* Shutdown the connection, i.e. pre_connection_close hooks,
             * SSL/TLS close notify, WC bucket, etc..
             */
            rc = ap_prep_lingering_close(c);
            if (rc == OK) {
                rc = ap_shutdown_conn(c, AP_SHUTDOWN_CONN_WC);
                if (rc == OK) {
                    if (c->aborted) {
                        rc = DONE;
                    }
                    else if (ap_filter_should_yield(c->output_filters)) {
                        rc = AGAIN;
                    }
                }
            }
        }
        else {
            rc = ap_check_output_pending(c);
        }

        cs->pub.state = CONN_STATE_LINGER;
        cs->pub.sense = CONN_SENSE_DEFAULT;
        if (rc == AGAIN) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                          "queuing lingering close for connection %" CS_FMT,
                          CS_ARG(cs));
            if (pollset_add(cs, CONN_SENSE_WANT_WRITE, cs->sc->sh_q, NULL)) {
                return; /* queued */
            }
        }
        if (rc != OK || apr_socket_shutdown(csd, APR_SHUTDOWN_WRITE)) {
            close_connection(cs);
            return;
        }
        
        cs->linger_shutdown = 1; /* once! */

        /* All nonblocking from now, no need for APR_INCOMPLETE_READ either */
        apr_socket_timeout_set(csd, 0);
        apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 0);
    }

    /* Drain until EAGAIN or EOF/error, in the former case requeue and
     * come back when readable again, otherwise the connection is over.
     */
    do {
        apr_size_t nbytes = sizeof(dummybuf);
        rv = apr_socket_recv(csd, dummybuf, &nbytes);
    } while (rv == APR_SUCCESS);

    if (!APR_STATUS_IS_EAGAIN(rv)
        || listensocks_disabled() /* busy enough */
        || !pollset_add(cs, CONN_SENSE_WANT_READ, linger_q, NULL)) {
        close_connection(cs);
    }
}

/* Call shutdown_connection() for the elements of 'q' that timed out, or
 * for all if 'shrink' is set.
 * Pre-condition: timeout_mutex must already be locked
 */
static unsigned int process_timeout_queue_ex(struct timeout_queue *queue,
                                             apr_time_t now,
                                             int shrink)
{
    unsigned int count = 0;
    struct timeout_queue *q;

    if (!*queue->total) {
        return 0;
    }

    for (q = queue; q; q = q->next) {
        while (!APR_RING_EMPTY(&q->head, event_conn_state_t, timeout_list)) {
            event_conn_state_t *cs = APR_RING_FIRST(&q->head);

            ap_assert(cs->q == q);

            if (!shrink) {
                /* Stop if this entry did not expire, no following one will
                 * thanks to the single timeout per queue (latest entries are
                 * added to the tail).
                 */
                apr_time_t elem_expiry = cs->queue_timestamp + q->timeout;
                if (elem_expiry > now) {
                    /* This is the next expiring entry of this queue, update
                     * the global queues_next_expiry if it expires after
                     * this one.
                     */
                    apr_time_t next_expiry = queues_next_expiry;
                    if (!next_expiry
                        || next_expiry > elem_expiry + QUEUES_FUDGE_TIMEOUT) {
                        queues_next_expiry = elem_expiry;
                    }
                    break;
                }
            }

            if (cs_in_backlog(cs)) {
                /* Remove the backlog connection from worker_queue (note that
                 * the lock is held by the listener already when maintaining
                 * the backlog_q), and unreserve/set a worker/idler since
                 * none could handle the event.
                 */
                ap_assert(cs_qe(cs)->cb_baton == cs);
                ap_assert(cs->q == cs->sc->bl_q);
                ap_queue_info_idlers_inc(worker_queue_info);
                ap_queue_kill_event_locked(worker_queue, cs_qe(cs));
                shutdown_connection(cs, now, 1);
            }
            else if (pollset_del(cs, 1)) {
                /* Removed from the pollset and timeout queue. */
                shutdown_connection(cs, now, 0);
            }
            else {
                /* Can't go anywhere, kill (and log). */
                kill_connection(cs, APR_EGENERAL);
            }

            count++;
        }
    }

    return count;
}

static APR_INLINE void process_timeout_queue(struct timeout_queue *queue,
                                             apr_time_t now)
{
    (void)process_timeout_queue_ex(queue, now, 0);
}

/* When all workers are busy or dying, kill'em all \m/ */
static APR_INLINE void shrink_timeout_queue(struct timeout_queue *queue,
                                            apr_time_t now)
{
    unsigned int count = process_timeout_queue_ex(queue, now, 1);
    if (count) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "All workers are %s, %s queue shrinked (%u done, %u left)",
                     apr_atomic_read32(&dying) ? "dying" : "busy", queue->name,
                     count, apr_atomic_read32(queue->total));
    }
}

static void update_stats(process_score *ps, apr_time_t now,
                         apr_time_t *when, int force)
{
    int expired = (*when <= now);

    if (expired || force) {
        apr_atomic_set32(&ps->wait_io, apr_atomic_read32(waitio_q->total));
        apr_atomic_set32(&ps->write_completion, apr_atomic_read32(write_completion_q->total));
        apr_atomic_set32(&ps->keep_alive, apr_atomic_read32(keepalive_q->total));
        apr_atomic_set32(&ps->shutdown, apr_atomic_read32(shutdown_q->total));
        apr_atomic_set32(&ps->lingering_close, apr_atomic_read32(linger_q->total));
        apr_atomic_set32(&ps->backlog, apr_atomic_read32(backlog_q->total));
        apr_atomic_set32(&ps->suspended, apr_atomic_read32(&suspended_count));
        apr_atomic_set32(&ps->connections, apr_atomic_read32(&connection_count));
    }

    if (expired) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "child: idlers:%i conns:%u backlog:%u "
                     "waitio:%u write:%u keepalive:%u shutdown:%u linger:%u "
                     "timers:%u suspended:%u (%u/%u workers shutdown)",
                     ap_queue_info_idlers_count(worker_queue_info),
                     apr_atomic_read32(&connection_count),
                     apr_atomic_read32(backlog_q->total),
                     apr_atomic_read32(waitio_q->total),
                     apr_atomic_read32(write_completion_q->total),
                     apr_atomic_read32(keepalive_q->total),
                     apr_atomic_read32(shutdown_q->total),
                     apr_atomic_read32(linger_q->total),
                     apr_atomic_read32(&timers_count),
                     apr_atomic_read32(&suspended_count),
                     apr_atomic_read32(&threads_shutdown),
                     threads_per_child);

        *when = now + STATS_UPDATE_TIMEOUT;
    }
}

static void * APR_THREAD_FUNC listener_thread(apr_thread_t * thd, void *dummy)
{
    apr_status_t rc;
    proc_info *ti = dummy;
    int process_slot = ti->pslot;
    process_score *ps = ap_get_scoreboard_process(process_slot);
    apr_time_t next_stats_time = 0, next_shrink_time = 0;
    apr_interval_time_t min_poll_timeout = -1;

    free(ti);

#if HAVE_SERF
    init_serf(apr_thread_pool_get(thd));
#endif

    /* Unblock the signal used to wake this thread up, and set a handler for
     * it.
     */
    apr_signal(LISTENER_SIGNAL, dummy_signal_handler);
    unblock_signal(LISTENER_SIGNAL);

    /* Don't wait in poll() for more than NON_WAKEABLE_TIMEOUT if the pollset
     * is not wakeable, and not more then the stats update period either.
     */
    if (!listener_is_wakeable) {
        min_poll_timeout = NON_WAKEABLE_TIMEOUT;
    }
    if (min_poll_timeout < 0 || min_poll_timeout > STATS_UPDATE_TIMEOUT) {
        min_poll_timeout = STATS_UPDATE_TIMEOUT;
    }

    for (;;) {
        apr_int32_t num = 0;
        apr_time_t next_expiry = -1;
        apr_interval_time_t timeout = -1;
        int workers_were_busy = 0, force_stats = 0;
        socket_callback_baton_t *user_chain;
        const apr_pollfd_t *out_pfd;
        apr_time_t now, poll_time;
        event_conn_state_t *cs;
        timer_event_t *te;

        if (conns_this_child <= 0) {
            /* Gracefuly stop (eventually) and keep going */
            check_infinite_requests();
        }

        now = poll_time = event_time_now();

        if (apr_atomic_read32(&listener_may_exit)) {
            int once = !apr_atomic_read32(&dying);
            if (once) {
                set_child_dying();
            }

            if (terminate_mode == ST_UNGRACEFUL
                || (apr_atomic_read32(&connection_count) == 0
                    && apr_atomic_read32(&timers_count) == 0))
                break;

            if (once) {
                /* Don't wait in poll() the first time (i.e. dying now), we
                 * want to maintain the queues ASAP to shutdown the workers
                 * and exit the child faster.
                 */
                goto do_maintenance; /* with next_expiry == -1 */
            }
        }

#if HAVE_SERF
        rc = serf_context_prerun(g_serf);
        if (rc != APR_SUCCESS) {
            /* TODO: what should we do here? ugh. */
        }
#endif

        /* Start with an infinite poll() timeout and update it according to
         * the next expiring timer or queue entry. If there are none, either
         * the listener is wakeable and it can poll() indefinitely until a wake
         * up occurs, otherwise periodic checks (maintenance, shutdown, ...)
         * must be performed.
         */
        timeout = -1;

        /* Push expired timers to a worker, the first remaining one (if any)
         * determines the maximum time to poll() below.
         */
        next_expiry = timers_next_expiry;
        if (next_expiry && next_expiry <= now) {
            apr_thread_mutex_lock(g_timer_skiplist_mtx);
            while ((te = apr_skiplist_peek(timer_skiplist))) {
                if (te->when > now) {
                    break;
                }
                apr_skiplist_pop(timer_skiplist, NULL);

                if (te->canceled) {
                    put_timer_event(te, 1);
                    continue;
                }

                if (!te->cbfunc) {
                    cs = te->baton;
                    put_timer_event(te, 1);
                    ap_assert(cs && cs->te == te);
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                                  "timed out connection %" CS_FMT,
                                  CS_ARG(cs));
                    (void)pollset_del(cs, 0);
                    kill_connection(cs, APR_TIMEUP);
                    continue;
                }

                if (te->pfds) {
                    /* remove all sockets from the pollset */
                    apr_pool_cleanup_run(te->pfds->pool, te->pfds,
                                         event_cleanup_poll_callback);
                }
                push2worker(NULL, te, now, &workers_were_busy);
            }
            if (te) {
                next_expiry = te->when;
            }
            else {
                next_expiry = 0;
            }
            timers_next_expiry = next_expiry;
            apr_thread_mutex_unlock(g_timer_skiplist_mtx);
        }
        if (next_expiry) {
            timeout = next_expiry > now ? next_expiry - now : 0;
        }

        /* Same for queues, use their next expiry, if any. */
        next_expiry = queues_next_expiry;
        if (next_expiry && (timeout < 0 || next_expiry - now < timeout)) {
            timeout = next_expiry > now ? next_expiry - now : 0;
        }

        /* So long as there are connections, wake up at most every
         * min_poll_timeout to refresh the scoreboard stats.
         */
        if (timeout < 0 || timeout > min_poll_timeout) {
            if (timeout > 0
                || !listener_is_wakeable
                || apr_atomic_read32(&connection_count)) {
                timeout = next_stats_time - now;
                if (timeout <= 0 || timeout > min_poll_timeout) {
                    timeout = min_poll_timeout;
                }
            }
            else {
                /* No connections and entering infinite poll(),
                 * clear the stats first.
                 */
                force_stats = 1;
            }
        }
        update_stats(ps, now, &next_stats_time, force_stats);

        /* apr_pollset_poll() might round down the timeout to
         * milliseconds, let's forcibly round up here to never
         * return before the timeout.
         */
        if (timeout > 0) {
            timeout = apr_time_from_msec(
                apr_time_as_msec(timeout + apr_time_from_msec(1) - 1)
            );
        }

        /* Unpause listening sockets before poll()ing if possible */
        if (should_enable_listensocks()) {
            enable_listensocks();
        }

        ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                     "pollset: wait timeout=%" APR_TIME_T_FMT
                     " queues_timeout=%" APR_TIME_T_FMT
                     " timers_timeout=%" APR_TIME_T_FMT
                     " listen=%s conns=%d exit=%d/%d",
                     timeout,
                     queues_next_expiry ? queues_next_expiry - now : 0,
                     timers_next_expiry ? timers_next_expiry - now : 0,
                     listensocks_disabled() ? "no" : "yes",
                     apr_atomic_read32(&connection_count),
                     apr_atomic_read32(&listener_may_exit),
                     apr_atomic_read32(&dying));

        rc = apr_pollset_poll(event_pollset, timeout, &num, &out_pfd);
        if (rc != APR_SUCCESS) {
            if (!APR_STATUS_IS_EINTR(rc) && !APR_STATUS_IS_TIMEUP(rc)) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rc, ap_server_conf,
                             APLOGNO(03267)
                             "apr_pollset_poll failed.  Attempting to "
                             "shutdown process gracefully");
                AP_DEBUG_ASSERT(0);
                signal_threads(ST_GRACEFUL);
            }
            num = 0;
        }

        /* Update "now" after polling and use it for everything below (all
         * non-(indefinitely-)blocking code). "now - poll_time" is then the
         * time passed in poll().
         *
         * XXX possible optimization: stash this time for use as
         * r->request_time for new requests.
         */
        now = event_time_now();

        ap_log_error(APLOG_MARK, APLOG_TRACE7, rc, ap_server_conf,
                     "pollset: have num=%i"
                     " elapsed=%" APR_TIME_T_FMT "/%" APR_TIME_T_FMT
                     " queues_timeout=%" APR_TIME_T_FMT
                     " timers_timeout=%" APR_TIME_T_FMT
                     " listen=%s conns=%d exit=%d/%d",
                     (int)num, now - poll_time, timeout,
                     queues_next_expiry ? queues_next_expiry - now : 0,
                     timers_next_expiry ? timers_next_expiry - now : 0,
                     listensocks_disabled() ? "no" : "yes",
                     apr_atomic_read32(&connection_count),
                     apr_atomic_read32(&listener_may_exit),
                     apr_atomic_read32(&dying));

        for (user_chain = NULL; num > 0; --num, ++out_pfd) {
            listener_poll_type *pt = out_pfd->client_data;
            socket_callback_baton_t *baton;

            switch (pt->type) {
            case PT_CSD:
                /* one of the sockets is ready */
                cs = (event_conn_state_t *)pt->baton;
                ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                              "polled connection %" CS_FMT,
                              CS_ARG(cs));

                switch (cs->pub.state) {
                case CONN_STATE_KEEPALIVE:
                case CONN_STATE_ASYNC_WAITIO:
                    cs->pub.state = CONN_STATE_PROCESSING;
                case CONN_STATE_WRITE_COMPLETION:
                case CONN_STATE_LINGER:
                    break;

                default:
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                 ap_server_conf, APLOGNO(03096)
                                 "event_loop: unexpected state %d",
                                 cs->pub.state);
                    ap_assert(0);
                }

                if (pollset_del(cs, 0)) {
                    push2worker(cs, NULL, now, &workers_were_busy);
                }
                else {
                    /* Can't go anywhere, kill (and log) and next. */
                    kill_connection(cs, APR_EGENERAL);
                }
                break;

            case PT_ACCEPT:
                /* A Listener Socket is ready for an accept() */
                if (workers_were_busy) {
                    /* Listeners disabled for now, keep the new connection in
                     * the socket backlog until listening again.
                     */
                    continue;
                }
                if (!apr_atomic_read32(&dying)) {
                    void *csd = NULL;
                    ap_listen_rec *lr = (ap_listen_rec *) pt->baton;
                    apr_pool_t *ptrans;         /* Pool for per-transaction stuff */

                    ptrans = ap_queue_info_pop_pool(worker_queue_info);
                    if (ptrans == NULL) {
                        /* create a new transaction pool for each accepted socket */
                        apr_allocator_t *allocator = NULL;

                        rc = apr_allocator_create(&allocator);
                        if (rc == APR_SUCCESS) {
                            apr_allocator_max_free_set(allocator,
                                                       ap_max_mem_free);
                            rc = apr_pool_create_ex(&ptrans, pconf, NULL,
                                                    allocator);
                            if (rc == APR_SUCCESS) {
                                apr_pool_tag(ptrans, "transaction");
                                apr_allocator_owner_set(allocator, ptrans);
                            }
                        }
                        if (rc != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                         ap_server_conf, APLOGNO(03097)
                                         "Failed to create transaction pool");
                            if (allocator) {
                                apr_allocator_destroy(allocator);
                            }
                            resource_shortage = 1;
                            signal_threads(ST_GRACEFUL);
                            continue;
                        }
                    }

                    rc = lr->accept_func(&csd, lr, ptrans);
                    if (rc == APR_SUCCESS) {
                        conns_this_child--;

                        /* Create and account for the connection from here, or
                         * a graceful shutdown happening before it's processed
                         * would consider it does not exist and could exit the
                         * child too early.
                         */
                        ap_assert(csd != NULL);
                        cs = make_conn_state(ptrans, csd);
                        push2worker(cs, NULL, now, &workers_were_busy);
                    }
                    else {
                        if (rc == APR_EGENERAL) {
                            /* E[NM]FILE, ENOMEM, etc */
                            resource_shortage = 1;
                            signal_threads(ST_GRACEFUL);
                        }
                        else if (ap_accept_error_is_nonfatal(rc)) {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                                         "accept() on client socket failed");
                        }
                        ap_queue_info_push_pool(worker_queue_info, ptrans);
                    }
                }
                break;

#if HAVE_SERF
            case PT_SERF:
                /* send socket to serf. */
                /* XXXX: this doesn't require a worker thread */
                serf_event_trigger(g_serf, pt->baton, out_pfd);
                break;
#endif

            case PT_USER:
                /* Multiple pfds of the same baton might trigger in this pass
                 * so chain once here and run the cleanup only after this loop
                 * to avoid lifetime issues (i.e. pfds->pool cleared while some
                 * of its pfd->client_data are still to be dereferenced here).
                 */
                baton = pt->baton;
                if (baton != user_chain && !baton->next) {
                    baton->next = user_chain;
                    user_chain = baton;
                }
                break;
            }
        } /* for processing poll */

        /* Time to queue user callbacks chained above */
        while (user_chain) {
            socket_callback_baton_t *baton = user_chain;
            user_chain = user_chain->next;
            baton->next = NULL;

            /* Not expirable anymore */
            if (baton->cancel_event) {
                baton->cancel_event->canceled = 1;
                baton->cancel_event = NULL;
            }

            /* remove all sockets from the pollset */
            apr_pool_cleanup_run(baton->pfds->pool, baton->pfds,
                                 event_cleanup_poll_callback);

            /* masquerade as a timer event that is firing */
            te = get_timer_event(-1 /* fake timer */,
                                 baton->cbfunc,
                                 baton->user_baton,
                                 0, /* don't insert it */
                                 NULL /* no associated socket callback */);
            push2worker(NULL, te, now, &workers_were_busy);
        }

        /* We process the timeout queues here only when the global
         * queues_next_expiry has passed. This happens accurately since
         * adding to the queues (in workers) can only decrease this expiry,
         * while latest ones are only taken into account here (in listener)
         * during queues' processing, with the lock held. This works both
         * with and without wake-ability.
         * Even if "now" drifted a bit since it was fetched and the real
         * "now" went below "expiry" in the meantime, the next poll() will
         * return immediately so the maintenance will happen then.
         */
        next_expiry = queues_next_expiry;
        if (next_expiry && next_expiry <= now) {
do_maintenance:
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         "queues maintenance: expired=%" APR_TIME_T_FMT,
                         next_expiry > 0 ? now - next_expiry : -1);

            apr_thread_mutex_lock(timeout_mutex);

            /* Recompute this by walking the timeout queues (under the lock) */
            queues_next_expiry = 0;

            /* Process shutdown_q first because the expired entries from the
             * other queues will go there and don't need to be checked twice
             * (nor do we want to potentially kill them before the shutdown).
             */
            process_timeout_queue(shutdown_q, now);

            process_timeout_queue(waitio_q, now);
            process_timeout_queue(write_completion_q, now);
            process_timeout_queue(keepalive_q, now);

            /* The linger queue can be shrinked any time under pressure */
            if (workers_were_busy || apr_atomic_read32(&dying)) {
                shrink_timeout_queue(linger_q, now);
                next_shrink_time = now + QUEUES_SHRINK_TIMEOUT;
            }
            else {
                process_timeout_queue(linger_q, now);
            }

            /* Connections in backlog race with the workers (dequeuing) under
             * the worker_queue mutex.
             */
            if (apr_atomic_read32(backlog_q->total)) {
                ap_queue_lock(worker_queue);
                process_timeout_queue(backlog_q, now);
                ap_queue_unlock(worker_queue);
            }

            next_expiry = queues_next_expiry;
            apr_thread_mutex_unlock(timeout_mutex);

            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         "queues maintained: next timeout=%" APR_TIME_T_FMT,
                         next_expiry ? next_expiry - now : -1);
        }
        else if (next_shrink_time <= now
                 && (workers_were_busy || apr_atomic_read32(&dying))
                 && apr_atomic_read32(linger_q->total)) {
            apr_thread_mutex_lock(timeout_mutex);
            shrink_timeout_queue(linger_q, now);
            apr_thread_mutex_unlock(timeout_mutex);
            next_shrink_time = now + QUEUES_SHRINK_TIMEOUT;
        }
    } /* listener main loop */

    ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                 "listener thread exiting");

    ap_queue_term(worker_queue);

    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

/*
 * During graceful shutdown, if there are more running worker threads than
 * open connections, exit one worker thread.
 *
 * return 1 if thread should exit, 0 if it should continue running.
 */
static int worker_thread_should_exit_early(int slot)
{
    const apr_uint32_t max = threads_per_child;
    for (;;) {
        apr_uint32_t conns = apr_atomic_read32(&connection_count);
        apr_uint32_t deads = apr_atomic_read32(&threads_shutdown);

        AP_DEBUG_ASSERT(deads < max);
        if (conns >= max - deads)
            return 0;

        if (apr_atomic_cas32(&threads_shutdown, deads + 1, deads) == deads) {
            /*
             * No other thread has exited in the mean time, safe to exit
             * this one.
             */
            ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                         "worker thread %i/%i-%i should exit (%i conns)",
                         slot, threads_per_child, deads + 1, conns);
            return 1;
        }
    }
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
    int process_slot = ti->pslot;
    int thread_slot = ti->tslot;
    worker_score *ws = &ap_scoreboard_image->servers[process_slot][thread_slot];
    int is_idler = 0;
    apr_status_t rv;

    free(ti);

    ws->pid = ap_my_pid;
    ws->tid = apr_os_thread_current();
    ws->generation = retained->mpm->my_generation;
    ap_update_child_status_from_indexes(process_slot, thread_slot,
                                        SERVER_STARTING, NULL);

    for (;;) {
        ap_queue_event_t *qe;

        if (!is_idler) {
            int idlers = ap_queue_info_idlers_inc(worker_queue_info);
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         "worker thread %i/%i idle (idlers %i)",
                         thread_slot, threads_per_child, idlers);
            is_idler = 1;

            /* If the listening sockets are paused and this new idler switches
             * connections_above_limit() back, let the listener know and poll
             * them again.
             */
            if (listener_is_wakeable && should_enable_listensocks()) {
                apr_pollset_wakeup(event_pollset);
            }
        }

        ap_update_child_status_from_indexes(process_slot, thread_slot,
                                            (apr_atomic_read32(&dying)
                                             ? SERVER_GRACEFUL : SERVER_READY),
                                            NULL);

        if (apr_atomic_read32(&workers_may_exit)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                         "worker thread %i/%i may exit",
                         thread_slot, threads_per_child);
            break;
        }
        if (apr_atomic_read32(&dying)
            && worker_thread_should_exit_early(thread_slot)) {
            break;
        }

        rv = ap_queue_pop_event(worker_queue, &qe);
        if (rv != APR_SUCCESS) {
            /* We get APR_EOF during a graceful shutdown once all the
             * connections accepted by this server process have been handled.
             */
            if (APR_STATUS_IS_EOF(rv)) {
                ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                             "worker thread %i/%i queue terminated",
                             thread_slot, threads_per_child);
                break;
            }

            /* We get APR_EINTR whenever ap_queue_pop_event() has been
             * interrupted from an explicit call to ap_queue_interrupt_*().
             * This allows us to unblock threads stuck in ap_queue_pop_event()
             * when a shutdown is pending.
             *
             * If workers_may_exit is set and this is ungraceful stop or
             * restart, we are bound to get an error on some systems (e.g.,
             * AIX, which sanity-checks mutex operations) since the queue
             * may have already been cleaned up.  Don't log the "error" if
             * workers_may_exit is set.
             */
            if (!APR_STATUS_IS_EINTR(rv) && !apr_atomic_read32(&workers_may_exit)) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                             APLOGNO(03099) "ap_queue_pop_event failed");
                AP_DEBUG_ASSERT(0);
                signal_threads(ST_GRACEFUL);
            }
            continue;
        }

        is_idler = 0; /* event consumed */
        ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                     "worker thread %i/%i busy (idlers %i)",
                     thread_slot, threads_per_child,
                     ap_queue_info_idlers_count(worker_queue_info));

        if (qe->type == AP_QUEUE_EVENT_SOCK) {
            apr_pool_t *p;
            apr_socket_t *csd;
            event_conn_state_t *cs;

            ap_assert(qe->data.se);
            p = qe->data.se->p;
            csd = qe->data.se->sd;
            cs = qe->data.se->baton;
            ap_assert(p && csd && cs && qe == cs_qe(cs));

            worker_sockets[thread_slot] = csd;
            process_socket(thd, p, csd, cs, process_slot, thread_slot);
            worker_sockets[thread_slot] = NULL;
        }
        else if (qe->type == AP_QUEUE_EVENT_TIMER) {
            timer_event_t *te;
            ap_mpm_callback_fn_t *cbfunc;
            void *baton;

            te = qe->data.te;
            ap_assert(te && qe == te_qe(te));

            cbfunc = te->cbfunc;
            baton = te->baton;

            /* first recycle the timer event */
            put_timer_event(te, 0);

            ap_update_child_status_from_indexes(process_slot, thread_slot,
                                                SERVER_BUSY_WRITE, NULL);
            ap_assert(cbfunc != NULL);
            cbfunc(baton);
        }
        else {
            ap_assert(0);
        }
    }
    if (is_idler) {
        /* Not idling anymore */
        ap_queue_info_idlers_dec(worker_queue_info);
    }

    ap_update_child_status_from_indexes(process_slot, thread_slot,
                                        (apr_atomic_read32(&dying)
                                         ? SERVER_DEAD : SERVER_GRACEFUL),
                                        NULL);

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
    my_info->pslot = my_child_num;
    my_info->tslot = -1;      /* listener thread doesn't have a thread slot */
    rv = ap_thread_create(&ts->listener, thread_attr, listener_thread,
                          my_info, pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(00474)
                     "ap_thread_create: unable to create listener thread");
        /* let the parent decide how bad this really is */
        clean_child_exit(APEXIT_CHILDSICK);
    }
    apr_os_thread_get(&listener_os_thread, ts->listener);
}

static void setup_threads_runtime(void)
{
    apr_status_t rv;
    ap_listen_rec *lr;
    apr_pool_t *pskip = NULL;
    int max_recycled_pools = -1, i;
    const int good_methods[] = { APR_POLLSET_PORT,
                                 APR_POLLSET_KQUEUE,
                                 APR_POLLSET_EPOLL };
    const double threads_factor = (async_factor < DEFAULT_ASYNC_FACTOR
                                   ? DEFAULT_ASYNC_FACTOR
                                   : async_factor);
    const apr_size_t pollset_size = ((unsigned int)(threads_per_child * threads_factor) +
                                     (unsigned int)num_listensocks +
                                     POLLSET_RESERVE_SIZE);
    int pollset_flags;

    /* Event's skiplist operations will happen concurrently with other modules'
     * runtime so they need their own pool for allocations, and its lifetime
     * should be at least the one of the connections (ptrans). Thus pskip is
     * created as a subpool of pconf like/before ptrans (before so that it's
     * destroyed after). In forked mode pconf is never destroyed so we are good
     * anyway, but in ONE_PROCESS mode this ensures that the skiplist works
     * from connection/ptrans cleanups (even after pchild is destroyed).
     */
    apr_pool_create(&pskip, pconf);
    apr_pool_tag(pskip, "mpm_skiplist");
    apr_thread_mutex_create(&g_timer_skiplist_mtx, APR_THREAD_MUTEX_DEFAULT, pskip);
    APR_RING_INIT(&timer_free_ring.link, timer_event_t, link);
    apr_skiplist_init(&timer_skiplist, pskip);
    apr_skiplist_set_compare(timer_skiplist, timer_comp, timer_comp);

    /* All threads (listener, workers) and synchronization objects (queues,
     * pollset, mutexes...) created here should have at least the lifetime of
     * the connections they handle (i.e. ptrans). We can't use this thread's
     * self pool because all these objects survive it, nor use pchild or pconf
     * directly because this starter thread races with other modules' runtime,
     * nor finally pchild (or subpool thereof) because it is killed explicitly
     * before pconf (thus connections/ptrans can live longer, which matters in
     * ONE_PROCESS mode). So this leaves us with a subpool of pconf, created
     * before any ptrans hence destroyed after.
     */
    apr_pool_create(&pruntime, pconf);
    apr_pool_tag(pruntime, "mpm_runtime");

    /* We must create the fd queues before we start up the listener
     * and worker threads, it's bounded by connections_above_limit(). */
    rv = ap_queue_create(&worker_queue, -1, pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(03100)
                     "ap_queue_create() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (ap_max_mem_free != APR_ALLOCATOR_MAX_FREE_UNLIMITED) {
        /* If we want to conserve memory, let's not keep an unlimited number of
         * pools & allocators.
         * XXX: This should probably be a separate config directive
         */
        max_recycled_pools = threads_per_child * 3 / 4 ;
    }
    rv = ap_queue_info_create(&worker_queue_info, pruntime, max_recycled_pools);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(03101)
                     "ap_queue_info_create() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Create the timeout mutex and main pollset before the listener
     * thread starts.
     */
    rv = apr_thread_mutex_create(&timeout_mutex, APR_THREAD_MUTEX_DEFAULT,
                                 pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(03102)
                     "creation of the timeout mutex failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Create the main pollset. When APR_POLLSET_WAKEABLE is asked we account
     * for the wakeup pipe explicitely with pollset_size+1 because some pollset
     * implementations don't do it implicitely in APR.
     */
    pollset_flags = APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY |
                    APR_POLLSET_WAKEABLE | APR_POLLSET_NODEFAULT;
    for (i = 0; i < sizeof(good_methods) / sizeof(good_methods[0]); i++) {
        rv = apr_pollset_create_ex(&event_pollset, pollset_size + 1, pruntime,
                                   pollset_flags, good_methods[i]);
        if (rv == APR_SUCCESS) {
            listener_is_wakeable = 1;
            break;
        }
    }
    if (rv != APR_SUCCESS) {
        pollset_flags &= ~APR_POLLSET_NODEFAULT;
        rv = apr_pollset_create(&event_pollset, pollset_size + 1, pruntime,
                                pollset_flags);
        if (rv == APR_SUCCESS) {
            listener_is_wakeable = 1;
        }
        else {
            pollset_flags &= ~APR_POLLSET_WAKEABLE;
            rv = apr_pollset_create(&event_pollset, pollset_size, pruntime,
                                    pollset_flags);
        }
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(03103)
                     "apr_pollset_create with Thread Safety failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Add listeners to the main pollset */
    listener_pollfd = apr_pcalloc(pruntime,
                                  num_listensocks * sizeof(apr_pollfd_t));
    for (i = 0, lr = my_bucket->listeners; lr; lr = lr->next, i++) {
        apr_pollfd_t *pfd;
        listener_poll_type *pt;

        ap_assert(i < num_listensocks);
        pfd = &listener_pollfd[i];

        pfd->reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;
#ifdef APR_POLLEXCL
        /* If APR_POLLEXCL is available, use it to prevent the thundering
         * herd issue. The listening sockets are potentially polled by all
         * the children at the same time, when new connections arrive this
         * avoids all of them to be woken up while most would get EAGAIN
         * on accept().
         */
        pfd->reqevents |= APR_POLLEXCL;
#endif
        pfd->desc_type = APR_POLL_SOCKET;
        pfd->desc.s = lr->sd;

        pt = apr_pcalloc(pruntime, sizeof(*pt));
        pfd->client_data = pt;
        pt->type = PT_ACCEPT;
        pt->baton = lr;

        apr_socket_opt_set(pfd->desc.s, APR_SO_NONBLOCK, 1);
        rv = apr_pollset_add(event_pollset, pfd);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(10473)
                         "apr_pollset_add for listener failed.");
            clean_child_exit(APEXIT_CHILDFATAL);
        }

        lr->accept_func = ap_unixd_accept;
    }

    worker_sockets = apr_pcalloc(pruntime, threads_per_child *
                                           sizeof(apr_socket_t *));
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
    int my_child_num = ts->child_num_arg;
    proc_info *my_info;
    apr_status_t rv;
    int threads_created = 0;
    int listener_started = 0;
    int prev_threads_created;
    int loops, i;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02471)
                 "start_threads: Using %s (%swakeable)",
                 apr_pollset_method_name(event_pollset),
                 listener_is_wakeable ? "" : "not ");

    loops = prev_threads_created = 0;
    while (1) {
        /* threads_per_child does not include the listener thread */
        for (i = 0; i < threads_per_child; i++) {
            int status =
                ap_scoreboard_image->servers[my_child_num][i].status;

            if (status != SERVER_DEAD) {
                continue;
            }

            my_info = (proc_info *) ap_malloc(sizeof(proc_info));
            my_info->pslot = my_child_num;
            my_info->tslot = i;

            /* We are creating threads right now */
            ap_update_child_status_from_indexes(my_child_num, i,
                                                SERVER_STARTING, NULL);
            /* We let each thread update its own scoreboard entry.  This is
             * done because it lets us deal with tid better.
             */
            rv = ap_thread_create(&threads[i], thread_attr,
                                  worker_thread, my_info, pruntime);
            if (rv != APR_SUCCESS) {
                ap_update_child_status_from_indexes(my_child_num, i, SERVER_DEAD, NULL);
                ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
                             APLOGNO(03104)
                             "ap_thread_create: unable to create worker thread");
                /* Let the parent decide how bad this really is by returning
                 * APEXIT_CHILDSICK. If threads were created already let them
                 * stop cleanly first to avoid deadlocks in clean_child_exit(),
                 * just stop creating new ones here (but set resource_shortage
                 * to return APEXIT_CHILDSICK still when the child exists).
                 */
                if (threads_created) {
                    resource_shortage = 1;
                    signal_threads(ST_GRACEFUL);
                    if (!listener_started) {
                        workers_may_exit = 1;
                        ap_queue_term(worker_queue);
                        /* wake up main POD thread too */
                        kill(ap_my_pid, SIGTERM);
                    }
                    apr_thread_exit(thd, APR_SUCCESS);
                    return NULL;
                }
                clean_child_exit(APEXIT_CHILDSICK);
            }
            threads_created++;
        }

        /* Start the listener only when there are workers available */
        if (!listener_started && threads_created) {
            create_listener_thread(ts);
            listener_started = 1;
        }


        if (apr_atomic_read32(&start_thread_may_exit)
            || threads_created == threads_per_child) {
            break;
        }
        /* wait for previous generation to clean up an entry */
        apr_sleep(apr_time_from_sec(1));
        ++loops;
        if (loops % 120 == 0) { /* every couple of minutes */
            if (prev_threads_created == threads_created) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                             APLOGNO(03271)
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
        while (!apr_atomic_read32(&dying)) {
            apr_sleep(apr_time_from_msec(500));
            if (apr_atomic_read32(&dying) || ++iter > 10) {
                break;
            }
            /* listener has not stopped accepting yet */
            ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                         "listener has not stopped accepting yet (%d iter)", iter);
            shutdown_listener();
        }
        if (iter > 10) {
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
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "apr_thread_join: joining thread %pp (%i/%i)",
                     threads[i], i, threads_per_child);
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

    /* tell it to give up in case it is still trying to take over slots
     * from a previous generation
     */
    apr_atomic_set32(&start_thread_may_exit, 1);

    rv = apr_thread_join(&thread_rv, start_thread_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00478)
                     "apr_thread_join: unable to join the start " "thread");
    }
}

static void child_main(int child_num_arg, int child_bucket)
{
    apr_thread_t **threads;
    apr_status_t rv;
    thread_starter *ts;
    apr_threadattr_t *thread_attr;
    apr_thread_t *start_thread_id;
    int i;

    /* for benefit of any hooks that run as this child initializes */
    retained->mpm->mpm_state = AP_MPMQ_STARTING;

    ap_my_pid = getpid();
    ap_child_slot = child_num_arg;
    ap_fatal_signal_child_setup(ap_server_conf);

    /* Get a sub context for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    apr_pool_create(&pchild, pconf);
    apr_pool_tag(pchild, "pchild");

#if AP_HAS_THREAD_LOCAL
    if (!one_process) {
        apr_thread_t *thd = NULL;
        if ((rv = ap_thread_main_create(&thd, pchild))) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(10377)
                         "Couldn't initialize child main thread");
            clean_child_exit(APEXIT_CHILDFATAL);
        }
    }
#endif

    /* close unused listeners and pods */
    for (i = 0; i < retained->mpm->num_buckets; i++) {
        if (i != child_bucket) {
            ap_close_listeners_ex(retained->buckets[i].listeners);
            ap_mpm_podx_close(retained->buckets[i].pod);
        }
    }

    /*stuff to do before we switch id's, so we have permissions. */
    ap_reopen_scoreboard(pchild, NULL, 0);

    /* done with init critical section */
    if (ap_run_drop_privileges(pchild, ap_server_conf)) {
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Just use the standard apr_setup_signal_thread to block all signals
     * from being received.  The child processes no longer use signals for
     * any communication with the parent process. Let's also do this before
     * child_init() hooks are called and possibly create threads that
     * otherwise could "steal" (implicitly) MPM's signals.
     */
    rv = apr_setup_signal_thread();
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(00479)
                     "Couldn't initialize signal thread");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* For rand() users (e.g. skiplist). */
    srand((unsigned int)event_time_now());

    ap_run_child_init(pchild, ap_server_conf);

    if (ap_max_requests_per_child) {
        conns_this_child = ap_max_requests_per_child;
    }
    else {
        /* coding a value of zero means infinity */
        conns_this_child = APR_INT32_MAX;
    }

    /* Setup threads */

    /* Globals used by signal_threads() so to be initialized before */
    setup_threads_runtime();

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

    rv = ap_thread_create(&start_thread_id, thread_attr, start_threads,
                          ts, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(00480)
                     "ap_thread_create: unable to create worker thread");
        /* let the parent decide how bad this really is */
        clean_child_exit(APEXIT_CHILDSICK);
    }

    retained->mpm->mpm_state = AP_MPMQ_RUNNING;

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
        apr_signal(SIGTERM, dummy_signal_handler);
        unblock_signal(SIGTERM);
        /* Watch for any messages from the parent over the POD */
        while (1) {
            rv = ap_mpm_podx_check(my_bucket->pod);
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
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "%s termination received, joining workers",
                     rv == AP_MPM_PODX_GRACEFUL ? "graceful" : "ungraceful");
        join_workers(ts->listener, threads);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "%s termination, workers joined, exiting",
                     rv == AP_MPM_PODX_GRACEFUL ? "graceful" : "ungraceful");
    }

    free(threads);

    clean_child_exit(resource_shortage ? APEXIT_CHILDSICK : 0);
}

static int make_child(server_rec *s, int slot)
{
    int pid, bucket = slot % retained->mpm->num_buckets;

    if (slot + 1 > retained->max_daemon_used) {
        retained->max_daemon_used = slot + 1;
    }

    if (ap_scoreboard_image->parent[slot].pid != 0) {
        /* XXX replace with assert or remove ? */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(03455)
                 "BUG: Scoreboard slot %d should be empty but is "
                 "in use by pid %" APR_PID_T_FMT,
                 slot, ap_scoreboard_image->parent[slot].pid);
        return -1;
    }

    if (one_process) {
        my_bucket = &retained->buckets[0];

        event_note_child_started(slot, getpid());
        child_main(slot, 0);
        /* NOTREACHED */
        ap_assert(0);
        return -1;
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
#if AP_HAS_THREAD_LOCAL
        ap_thread_current_after_fork();
#endif

        my_bucket = &retained->buckets[bucket];

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
        child_main(slot, bucket);
        /* NOTREACHED */
        ap_assert(0);
        return -1;
    }

    event_note_child_started(slot, pid);
    return 0;
}

/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < server_limit; ++i) {
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
    volatile process_score *ps;
    const int num_buckets = retained->mpm->num_buckets;
    int last_non_dead = -1;
    int free_length = 0, free_bucket = 0;
    int max_daemon_used = 0;
    int idle_thread_count = 0;
    int active_thread_count = 0;
    int backlog_count = 0;
    int i, j;

    for (i = 0; i < server_limit; ++i) {
        if (i >= retained->max_daemon_used &&
            free_length == retained->idle_spawn_rate) {
            /* short cut if all active processes have been examined and
             * enough empty scoreboard slots have been found
             */
            break;
        }

        ps = &ap_scoreboard_image->parent[i];
        if (ps->pid != 0) {
            int child_threads_active = 0;
            if (ps->quiescing == 1) {
                ps->quiescing = 2;
                retained->active_daemons--;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                             "Child %d quiescing: pid %d, gen %d, "
                             "active %d/%d, total %d/%d/%d",
                             i, (int)ps->pid, (int)ps->generation,
                             retained->active_daemons, active_daemons_limit,
                             retained->total_daemons, retained->max_daemon_used,
                             server_limit);
            }
            for (j = 0; j < threads_per_child; j++) {
                int status = ap_scoreboard_image->servers[i][j].status;

                /* We consider a starting server as idle because we started it
                 * at least a cycle ago, and if it still hasn't finished starting
                 * then we're just going to swamp things worse by forking more.
                 * So we hopefully won't need to fork more if we count it.
                 * This depends on the ordering of SERVER_READY and SERVER_STARTING.
                 */
                if (status <= SERVER_READY && !ps->quiescing && !ps->not_accepting
                    && ps->generation == retained->mpm->my_generation) {
                    ++idle_thread_count;
                }
                if (status >= SERVER_READY && status < SERVER_GRACEFUL) {
                    ++child_threads_active;
                }
            }
            active_thread_count += child_threads_active;
            backlog_count += apr_atomic_read32(&ps->backlog);
            if (child_threads_active == threads_per_child) {
                had_healthy_child = 1;
            }
            last_non_dead = i;
        }
        else if (free_length < retained->idle_spawn_rate
                 && (i % num_buckets) == free_bucket) {
            retained->free_slots[free_length++] = i;
            if (++free_bucket == num_buckets) {
                free_bucket = 0;
            }
        }
    }
    if (max_daemon_used < last_non_dead + 1) {
        max_daemon_used = last_non_dead + 1;
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
            retained->mpm->shutdown_pending = 1;
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

    AP_DEBUG_ASSERT(retained->active_daemons <= retained->total_daemons
                    && retained->total_daemons <= retained->max_daemon_used
                    && retained->max_daemon_used <= server_limit);

    if (idle_thread_count > max_spare_threads) {
        /*
         * Child processes that we ask to shut down won't die immediately
         * but may stay around for a long time when they finish their
         * requests. If the server load changes many times, many such
         * gracefully finishing processes may accumulate, filling up the
         * scoreboard. To avoid running out of scoreboard entries, we
         * don't shut down more processes if there are stopping ones
         * already (i.e. active_daemons != total_daemons) and not enough
         * slack space in the scoreboard for a graceful restart.
         *
         * XXX It would be nice if we could
         * XXX - kill processes without keepalive connections first
         * XXX - tell children to stop accepting new connections, and
         * XXX   depending on server load, later be able to resurrect them
         *       or kill them
         */
        int do_kill = (retained->active_daemons == retained->total_daemons
                       || (server_limit - retained->total_daemons >
                           active_daemons_limit));
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "%shutting down one child: "
                     "active %d/%d, total %d/%d/%d, "
                     "idle threads %d, max workers %d",
                     (do_kill) ? "S" : "Not s",
                     retained->active_daemons, active_daemons_limit,
                     retained->total_daemons, retained->max_daemon_used,
                     server_limit, idle_thread_count, max_workers);
        if (do_kill) {
            for (i = 0; i < num_buckets; ++i) {
                ap_mpm_podx_signal(retained->buckets[i].pod,
                                   AP_MPM_PODX_GRACEFUL);
            }
        }
        else {
            /* Wait for dying daemon(s) to exit */
        }
        retained->idle_spawn_rate = num_buckets;
    }
    else if (idle_thread_count < min_spare_threads) {
        if (active_thread_count >= max_workers) {
            if (0 == idle_thread_count) {
                if (!retained->maxclients_reported) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(00484)
                                 "server reached MaxRequestWorkers setting, "
                                 "consider raising the MaxRequestWorkers "
                                 "setting");
                    retained->maxclients_reported = 1;
                }
             }
             else {
                if (!retained->near_maxclients_reported) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(10159)
                            "server is within MinSpareThreads of "
                            "MaxRequestWorkers, consider raising the "
                            "MaxRequestWorkers setting");
                    retained->near_maxclients_reported = 1;
                }
            }
            retained->idle_spawn_rate = num_buckets;
        }
        else if (free_length == 0) { /* scoreboard is full, can't fork */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(03490)
                         "scoreboard is full, not at MaxRequestWorkers."
                         "Increase ServerLimit.");
            retained->idle_spawn_rate = num_buckets;
        }
        else {
            if (free_length + retained->active_daemons > active_daemons_limit) {
                if (retained->active_daemons < active_daemons_limit) {
                    free_length = active_daemons_limit - retained->active_daemons;
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                                 "server is at active daemons limit, spawning "
                                 "of %d children cancelled: active %d/%d, "
                                 "total %d/%d/%d, rate %d", free_length,
                                 retained->active_daemons, active_daemons_limit,
                                 retained->total_daemons, retained->max_daemon_used,
                                 server_limit, retained->idle_spawn_rate);
                    /* reset the spawning rate and prevent its growth below */
                    retained->idle_spawn_rate = num_buckets;
                    free_length = 0;
                }
            }
            if (retained->idle_spawn_rate >= retained->max_spawn_rate / 4) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00486)
                             "server seems busy, (you may need "
                             "to increase StartServers, ThreadsPerChild "
                             "or Min/MaxSpareThreads), "
                             "spawning %d children, there are around %d idle "
                             "threads, %d active children, and %d children "
                             "that are shutting down", free_length,
                             idle_thread_count, retained->active_daemons,
                             retained->total_daemons);
            }
            free_length = (free_length / num_buckets) * num_buckets;
            for (i = 0; i < free_length; ++i) {
                int slot = retained->free_slots[i];
                if (make_child(ap_server_conf, slot) < 0) {
                    continue;
                }
                if (max_daemon_used < slot + 1) {
                    max_daemon_used = slot + 1;
                }
            }
            /* the next time around we want to spawn twice as many if this
             * wasn't good enough, but not if we've just done a graceful
             */
            if (retained->hold_off_on_exponential_spawning) {
                --retained->hold_off_on_exponential_spawning;
            }
            else if (free_length && retained->idle_spawn_rate < retained->max_spawn_rate) {
                int new_rate = retained->idle_spawn_rate * 2;
                new_rate = ((new_rate + num_buckets - 1) / num_buckets) * num_buckets;
                if (new_rate > retained->max_spawn_rate) {
                    new_rate = retained->max_spawn_rate;
                }
                retained->idle_spawn_rate = new_rate;
            }
        }
    }
    else {
        retained->idle_spawn_rate = num_buckets;
    }

    retained->max_daemon_used = max_daemon_used;
    if (APLOGdebug(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "score: idlers:%d backlog:%d, "
                     "threads active:%d/%d max:%d, "
                     "daemons active:%d/%d max:%d used:%d/%d/%d",
                     idle_thread_count, backlog_count,
                     active_thread_count, retained->active_daemons * threads_per_child,
                     max_workers, retained->active_daemons, retained->total_daemons,
                     active_daemons_limit, max_daemon_used, retained->max_daemon_used,
                     server_limit);
    }
}

static void server_main_loop(int remaining_children_to_start)
{
    int successive_kills = 0;
    int child_slot;
    apr_exit_why_e exitwhy;
    int status, processed_status;
    apr_proc_t pid;

    while (!retained->mpm->restart_pending && !retained->mpm->shutdown_pending) {
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
                       == retained->mpm->my_generation) {
                    retained->mpm->shutdown_pending = 1;
                    child_fatal = 1;
                    /*
                     * total_daemons counting will be off now, but as we
                     * are shutting down, that is not an issue anymore.
                     */
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
                event_note_child_stopped(child_slot, 0, 0);

                if (processed_status == APEXIT_CHILDSICK) {
                    /* resource shortage, minimize the fork rate */
                    retained->idle_spawn_rate = retained->mpm->num_buckets;
                }
                else if (remaining_children_to_start) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_child(ap_server_conf, child_slot);
                    --remaining_children_to_start;
                }
            }
#if APR_HAS_OTHER_CHILD
            else if (apr_proc_other_child_alert(&pid, APR_OC_REASON_DEATH,
                                                status) == 0) {
                /* handled */
            }
#endif
            else if (retained->mpm->was_graceful) {
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
             * pathological for a lot to die suddenly.  If a child is
             * killed by a signal (faulting) we want to restart it ASAP
             * though, up to 3 successive faults or we stop this until
             * a timeout happens again (to avoid the flood of fork()ed
             * processes that keep being killed early).
             */
            if (child_slot < 0 || !APR_PROC_CHECK_SIGNALED(exitwhy)) {
                continue;
            }
            if (++successive_kills >= 3) {
                if (successive_kills % 10 == 3) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                                 ap_server_conf, APLOGNO(10392)
                                 "children are killed successively!");
                }
                continue;
            }
            ++remaining_children_to_start;
        }
        else {
            successive_kills = 0;
        }

        if (remaining_children_to_start) {
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
    int num_buckets, i;
    apr_status_t rv;

    ap_log_pid(pconf, ap_pid_fname);

    /* Preserve the scoreboard on graceful restart, reset when ungraceful */
    if (!retained->mpm->was_graceful
        && ap_run_pre_mpm(s->process->pool, SB_SHARED)) {
        retained->mpm->mpm_state = AP_MPMQ_STOPPING;
        return !OK;
    }

    /* Now on for the new generation. */
    ap_scoreboard_image->global->running_generation = retained->mpm->my_generation;
    ap_unixd_mpm_set_signals(pconf, one_process);

    /* Set the buckets listeners from the listen_buckets initialized
     * in event_open_logs().
     */
    num_buckets = retained->num_listen_buckets;
    retained->buckets = apr_pcalloc(retained->gen_pool,
                                    num_buckets * sizeof(event_child_bucket));
    for (i = 0; i < num_buckets; i++) {
        if (!one_process /* no POD in one_process mode */
                && (rv = ap_mpm_podx_open(retained->gen_pool,
                                          &retained->buckets[i].pod))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                         ap_server_conf, APLOGNO(03274)
                         "could not open pipe-of-death");
            return !OK;
        }
        retained->buckets[i].listeners = retained->listen_buckets[i];
    }
    /* Reset for the next generation/restart */
    retained->listen_buckets = NULL;
    retained->num_listen_buckets = 0;

    /* If num_buckets changed, adjust max_spawn_rate and the free_slots buffer */
    if (retained->mpm->num_buckets != num_buckets) {
        if (retained->mpm->max_buckets < num_buckets) {
            int new_max, new_slots;
            new_max = retained->mpm->max_buckets * 2;
            if (new_max < num_buckets) {
                new_max = num_buckets;
            }
            else {
                new_max = ((new_max + num_buckets - 1) / num_buckets) * num_buckets;
            }
            new_slots = ((MAX_SPAWN_RATE + new_max - 1) / new_max) * new_max;
            retained->free_slots = apr_palloc(ap_pglobal, new_slots * sizeof(int));
            retained->mpm->max_buckets = new_max;
        }
        /* We always spawn/kill children in a multiple of num_buckets (as needed),
         * so align (round up) max_spawn_rate and idle_spawn_rate to num_buckets.
         */
        retained->max_spawn_rate = (((MAX_SPAWN_RATE + num_buckets - 1)
                                     / num_buckets) * num_buckets);
        retained->idle_spawn_rate = (((retained->idle_spawn_rate + num_buckets - 1)
                                      / num_buckets) * num_buckets);
        if (retained->idle_spawn_rate < num_buckets) {
            retained->idle_spawn_rate = num_buckets;
        }
        else if (retained->idle_spawn_rate > retained->max_spawn_rate) {
            retained->idle_spawn_rate = retained->max_spawn_rate;
        }
        retained->mpm->num_buckets = num_buckets;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(10464)
                 "MPM event settings%s: MaxRequestWorkers=%d AsyncRequestWorkerFactor=%.1lf "
                 "ThreadsPerChild=%d ThreadLimit=%d MinSpareThreads=%d MaxSpareThreads=%d "
                 "ServerLimit=%d/%d StartServers=%d Buckets=%d CPUs=%d",
                 auto_settings ? " (auto)" : "", max_workers, async_factor,
                 threads_per_child, thread_limit, min_spare_threads, max_spare_threads,
                 active_daemons_limit, server_limit, ap_daemons_to_start,
                 num_buckets, num_online_cpus);

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
    if (remaining_children_to_start > active_daemons_limit) {
        remaining_children_to_start = active_daemons_limit;
    }
    if (!retained->mpm->was_graceful) {
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
    ap_log_mpm_common(s);

    retained->mpm->mpm_state = AP_MPMQ_RUNNING;

    server_main_loop(remaining_children_to_start);
    retained->mpm->mpm_state = AP_MPMQ_STOPPING;

    if (retained->mpm->shutdown_pending && retained->mpm->is_ungraceful) {
        /* Time to shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        for (i = 0; i < num_buckets; i++) {
            ap_mpm_podx_killpg(retained->buckets[i].pod,
                               active_daemons_limit, AP_MPM_PODX_RESTART);
        }
        ap_reclaim_child_processes(1, /* Start with SIGTERM */
                                   event_note_child_stopped);

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            ap_remove_pid(pconf, ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
                         ap_server_conf, APLOGNO(00491) "caught SIGTERM, shutting down");
        }

        return DONE;
    }

    if (retained->mpm->shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        int active_children;
        int index;
        apr_time_t cutoff = 0;

        /* Close our listeners, and then ask our children to do same */
        ap_close_listeners();
        for (i = 0; i < num_buckets; i++) {
            ap_mpm_podx_killpg(retained->buckets[i].pod,
                               active_daemons_limit, AP_MPM_PODX_GRACEFUL);
        }
        ap_relieve_child_processes(event_note_child_stopped);

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            ap_remove_pid(pconf, ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00492)
                         "caught " AP_SIG_GRACEFUL_STOP_STRING
                         ", shutting down gracefully");
        }

        if (ap_graceful_shutdown_timeout) {
            cutoff = event_time_now() +
                     apr_time_from_sec(ap_graceful_shutdown_timeout);
        }

        /* Don't really exit until each child has finished */
        retained->mpm->shutdown_pending = 0;
        do {
            /* Pause for a second */
            apr_sleep(apr_time_from_sec(1));

            /* Relieve any children which have now exited */
            ap_relieve_child_processes(event_note_child_stopped);

            active_children = 0;
            for (index = 0; index < retained->max_daemon_used; ++index) {
                if (ap_mpm_safe_kill(MPM_CHILD_PID(index), 0) == APR_SUCCESS) {
                    active_children = 1;
                    /* Having just one child is enough to stay around */
                    break;
                }
            }
        } while (!retained->mpm->shutdown_pending && active_children &&
                 (!ap_graceful_shutdown_timeout || event_time_now() < cutoff));

        /* We might be here because we received SIGTERM, either
         * way, try and make sure that all of our processes are
         * really dead.
         */
        for (i = 0; i < num_buckets; i++) {
            ap_mpm_podx_killpg(retained->buckets[i].pod,
                               active_daemons_limit, AP_MPM_PODX_RESTART);
        }
        ap_reclaim_child_processes(1, event_note_child_stopped);

        return DONE;
    }

    /* we've been told to restart */
    if (one_process) {
        /* not worth thinking about */
        return DONE;
    }

    if (!retained->mpm->is_ungraceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00493)
                     "%s received.  Doing graceful restart",
                     AP_SIG_GRACEFUL_STRING);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00494)
                     "SIGHUP received.  Attempting to restart");
    }
    return OK;
}

static void setup_slave_conn(conn_rec *c, void *csd)
{
    event_conn_state_t *mcs;
    event_conn_state_t *cs;

    mcs = ap_get_module_config(c->master->conn_config, &mpm_event_module);

    cs = make_conn_state(c->pool, csd);
    cs->c = c;
    cs->sc = mcs->sc;
    cs->suspended = 0;
    cs->bucket_alloc = c->bucket_alloc;
    cs->pfd = mcs->pfd;
    cs->pub = mcs->pub;
    cs->pub.state = CONN_STATE_PROCESSING;
    cs->pub.sense = CONN_SENSE_DEFAULT;

    c->cs = &(cs->pub);
    ap_set_module_config(c->conn_config, &mpm_event_module, cs);
}

static int event_pre_connection(conn_rec *c, void *csd)
{
    if (c->master && (!c->cs || c->cs == c->master->cs)) {
        setup_slave_conn(c, csd);
    }
    return OK;
}

static int event_protocol_switch(conn_rec *c, request_rec *r, server_rec *s,
                                 const char *protocol)
{
    if (!r && s) {
        /* connection based switching of protocol, set the correct server
         * configuration, so that timeouts, keepalives and such are used
         * for the server that the connection was switched on.
         * Normally, we set this on post_read_request, but on a protocol
         * other than http/1.1, this might never happen.
         */
        event_conn_state_t *cs;

        cs = ap_get_module_config(c->conn_config, &mpm_event_module);
        cs->sc = ap_get_module_config(s->module_config, &mpm_event_module);
    }
    return DECLINED;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 * We compute num_buckets here too, thus the definitive AP_MPMQ_* settings
 * which need it and which may be needed by the post_config hooks of other
 * modules.
 */
static int event_open_logs(apr_pool_t * p, apr_pool_t * plog,
                           apr_pool_t * ptemp, server_rec * s)
{
    int startup = 0;
    int level_flags = 0;
    int num_buckets = 0, i;
    int min_threads;
    apr_status_t rv;

    pconf = p;

    /* the reverse of pre_config, we want this only the first time around */
    if (retained->mpm->module_loads == 1) {
        startup = 1;
        level_flags |= APLOG_STARTUP;
    }

    /* This sets up new listeners or reuses existing ones, as well as cleaning
     * up unused ones from the previous generation.
     */
    num_listensocks = ap_setup_listeners(ap_server_conf);
    if (num_listensocks < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, 0,
                     (startup ? NULL : s), APLOGNO(03272)
                     "no listening sockets available, shutting down");
        return !OK;
    }

    /* On first startup create gen_pool to satisfy the lifetime of the
     * parent's PODs and listeners; on restart stop the children from the
     * previous generation and clear gen_pool for the next one.
     */
    if (!retained->gen_pool) {
        apr_pool_create(&retained->gen_pool, ap_pglobal);
    }
    else {
        num_buckets = retained->mpm->num_buckets;
        if (retained->mpm->was_graceful) {
            /* wake up the children...time to die.  But we'll have more soon */
            for (i = 0; i < num_buckets; i++) {
                ap_mpm_podx_killpg(retained->buckets[i].pod,
                                   active_daemons_limit, AP_MPM_PODX_GRACEFUL);
            }
        }
        else {
            /* Kill 'em all.  Since the child acts the same on the parents SIGTERM
             * and a SIGHUP, we may as well use the same signal, because some user
             * pthreads are stealing signals from us left and right.
             */
            for (i = 0; i < num_buckets; i++) {
                ap_mpm_podx_killpg(retained->buckets[i].pod,
                                   active_daemons_limit, AP_MPM_PODX_RESTART);
            }
            ap_reclaim_child_processes(1,  /* Start with SIGTERM */
                                       event_note_child_stopped);
        }
        apr_pool_clear(retained->gen_pool);
        retained->buckets = NULL;

        /* advance to the next generation */
        /* XXX: we really need to make sure this new generation number isn't in
         * use by any of the previous children.
         */
        ++retained->mpm->my_generation;
    }

    /* On graceful restart, preserve the listeners buckets. When ungraceful,
     * set num_buckets to zero to let ap_duplicate_listeners() below determine
     * how many are needed/configured.
     */
    if (!retained->mpm->was_graceful) {
        num_buckets = (one_process) ? 1 : 0; /* one_process => one bucket */
        retained->mpm->num_buckets = 0; /* old gen's until event_run() */
    }
    if ((rv = ap_duplicate_listeners(retained->gen_pool, ap_server_conf,
                                     &retained->listen_buckets,
                                     &num_buckets))) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, rv,
                     (startup ? NULL : s), APLOGNO(03273)
                     "could not duplicate listeners, shutting down");
        return !OK;
    }
    retained->num_listen_buckets = num_buckets;

    /* Don't thrash since num_buckets depends on the system and the
     * number of CPU cores, so make the settings consistent.
     */
    if (retained->first_thread_limit) {
        if (threads_per_child > retained->first_thread_limit) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10465)
                         "ThreadsPerChild (%d) exceeds initial ThreadLimit, "
                         "forcing ThreadsPerChild to %d",
                         threads_per_child, retained->first_thread_limit);
            threads_per_child = retained->first_thread_limit;
        }
    }
    else {
        if (thread_limit < threads_per_child) {
            thread_limit = threads_per_child;
        }
        retained->first_thread_limit = thread_limit;
    }
    min_threads = threads_per_child * num_buckets;
    if (max_workers < min_threads) {
        max_workers = min_threads;
    }
    else {
        max_workers = (max_workers / min_threads) * min_threads;
    }
    active_daemons_limit = max_workers / threads_per_child;
    if (retained->first_server_limit) {
        if (active_daemons_limit > retained->first_server_sb_limit) {
            int new_max_workers = retained->first_server_sb_limit * threads_per_child;
            if (new_max_workers < min_threads) {
                new_max_workers = min_threads;
            }
            else {
                new_max_workers = (new_max_workers / min_threads) * min_threads;
            }
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10466)
                         "MaxRequestWorkers (%d) / ThreadsPerChild (%d) would "
                         "exceed initial scoreboard limit (%d), forcing "
                         "MaxRequestWorkers to %d",
                         max_workers, threads_per_child,
                         retained->first_server_sb_limit,
                         new_max_workers);
            max_workers = new_max_workers;
            active_daemons_limit = retained->first_server_sb_limit;
        }
        server_limit = retained->first_server_sb_limit;
    }
    else {
        /* Save the initial ServerLimit which cannot be changed on restart, but
         * leave some spare room in the actual server_[sb_]limit (used to size
         * the scoreboard) to allow for children restarting while the old gen
         * is gracefully exiting.
         */
        retained->first_server_limit = server_limit;
        if (server_limit < active_daemons_limit * SCOREBOARD_DAEMONS_FACTOR) {
            server_limit = active_daemons_limit * SCOREBOARD_DAEMONS_FACTOR;
        }
        retained->first_server_sb_limit = server_limit;
    }
    if (ap_daemons_to_start < num_buckets) {
        ap_daemons_to_start = num_buckets;
    }
    else if (ap_daemons_to_start < active_daemons_limit) {
        ap_daemons_to_start = (ap_daemons_to_start / num_buckets) * num_buckets;
    }
    else {
        ap_daemons_to_start = active_daemons_limit;
    }
    if (min_spare_threads < ap_daemons_to_start * threads_per_child) {
        min_spare_threads = ap_daemons_to_start * threads_per_child;
    }
    else if (min_spare_threads < max_workers) {
        min_spare_threads = (min_spare_threads / min_threads) * min_threads;
    }
    else {
        min_spare_threads = max_workers;
    }
    if (max_spare_threads < 0) { /* auto settings */
        max_spare_threads = max_workers * MAX_SPARE_THREADS_RATIO;
    }
    if (max_spare_threads < min_spare_threads + min_threads) {
        max_spare_threads = min_spare_threads + min_threads;
    }
    else if (max_spare_threads < max_workers) {
        max_spare_threads = (max_spare_threads / min_threads) * min_threads;
    }
    else {
        max_spare_threads = max_workers;
    }

    workers_backlog_limit = threads_per_child * async_factor;

    return OK;
}

static int event_pre_config(apr_pool_t * pconf, apr_pool_t * plog,
                            apr_pool_t * ptemp)
{
    int no_detach, debug, foreground;
    apr_status_t rv;
    const char *userdata_key = "mpm_event_module";
    int test_atomics = 0;

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

    event_time_init();

    retained = ap_retained_data_get(userdata_key);
    if (!retained) {
        retained = ap_retained_data_create(userdata_key, sizeof(*retained));
        retained->mpm = ap_unixd_mpm_get_retained_data();
        retained->mpm->baton = retained;
        if (retained->mpm->module_loads) {
            test_atomics = 1;
        }
    }
    else if (retained->mpm->baton != retained) {
        /* If the MPM changes on restart, be ungraceful */
        retained->mpm->baton = retained;
        retained->mpm->was_graceful = 0;
    }
    retained->mpm->mpm_state = AP_MPMQ_STARTING;
    ++retained->mpm->module_loads;

    /* test once for correct operation of fdqueue */
    if (test_atomics || retained->mpm->module_loads == 2) {
        static apr_uint32_t foo1, foo2;

        apr_atomic_set32(&foo1, 100);
        foo2 = apr_atomic_add32(&foo1, -10);
        if (foo2 != 100 || foo1 != 90) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, APLOGNO(02405)
                         "atomics not working as expected - add32 of negative number");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* sigh, want this only the second time around */
    if (retained->mpm->module_loads == 2) {
        apr_pollset_t *tmp = NULL;
        rv = apr_pollset_create(&tmp, 1, plog,
                                APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(00495)
                         "Couldn't create a Thread Safe Pollset. "
                         "Is it supported on your platform?"
                         "Also check system or user limits!");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_pollset_destroy(tmp);

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
    had_healthy_child = 0;
    ap_extended_status = 0;

    max_workers = -1;
    threads_per_child = -1;
    min_spare_threads = max_spare_threads = -1;
    server_limit = thread_limit = -1;
    ap_daemons_to_start = -1;
    auto_settings = 0;

#ifndef _SC_NPROCESSORS_ONLN
    num_online_cpus = 1;
#else
    num_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_online_cpus < 1) {
        num_online_cpus = 1;
    }
#endif
    async_factor = DEFAULT_ASYNC_FACTOR;

    return OK;
}

static int event_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    apr_hash_t *io_h, *wc_h, *ka_h, *sh_h, *bl_h;

    /* Not needed in pre_config stage */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    io_h = apr_hash_make(ptemp);
    wc_h = apr_hash_make(ptemp);
    ka_h = apr_hash_make(ptemp);
    sh_h = apr_hash_make(ptemp);
    bl_h = apr_hash_make(ptemp);

    linger_q = TO_QUEUE_MAKE(pconf, "linger", LINGER_READ_TIMEOUT, NULL);

    for (; s; s = s->next) {
        event_srv_cfg *sc = apr_pcalloc(pconf, sizeof *sc);
        ap_set_module_config(s->module_config, &mpm_event_module, sc);
        sc->s = s; /* backref */

        sc->io_q = TO_QUEUE_CHAIN(pconf, "waitio", s->timeout,
                                  &waitio_q, io_h, ptemp);

        sc->wc_q = TO_QUEUE_CHAIN(pconf, "write_completion", s->timeout,
                                  &write_completion_q, wc_h, ptemp);

        sc->ka_q = TO_QUEUE_CHAIN(pconf, "keepalive", s->keep_alive_timeout,
                                  &keepalive_q, ka_h, ptemp);

        sc->sh_q = TO_QUEUE_CHAIN(pconf, "shutdown", s->timeout,
                                  &shutdown_q, sh_h, ptemp);

        sc->bl_q = TO_QUEUE_CHAIN(pconf, "backlog", s->timeout,
                                  &backlog_q, bl_h, ptemp);
    }

    return OK;
}

static int event_check_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;

    /* the reverse of pre_config, we want this only the first time around */
    if (retained->mpm->module_loads == 1) {
        startup = 1;
    }

    if (server_limit < 0) {
        server_limit = DEFAULT_SERVER_LIMIT;
    }
    else if (server_limit > MAX_SERVER_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00497)
                         "WARNING: ServerLimit of %d exceeds compile-time "
                         "limit of %d servers, decreasing to %d.",
                         server_limit, MAX_SERVER_LIMIT, MAX_SERVER_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00498)
                         "ServerLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         server_limit, MAX_SERVER_LIMIT);
        }
        server_limit = MAX_SERVER_LIMIT;
    }
    else if (server_limit == 0) {
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
    if (retained->first_server_limit && server_limit != retained->first_server_limit) {
        /* don't need a startup console version here */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00501)
                     "changing ServerLimit to %d from original value of %d "
                     "not allowed during restart",
                     server_limit, retained->first_server_limit);
        server_limit = retained->first_server_limit;
    }

    if (thread_limit < 0) {
        thread_limit = DEFAULT_THREAD_LIMIT;
    }
    else if (thread_limit > MAX_THREAD_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00502)
                         "WARNING: ThreadLimit of %d exceeds compile-time "
                         "limit of %d threads, decreasing to %d.",
                         thread_limit, MAX_THREAD_LIMIT, MAX_THREAD_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00503)
                         "ThreadLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         thread_limit, MAX_THREAD_LIMIT);
        }
        thread_limit = MAX_THREAD_LIMIT;
    }
    else if (thread_limit == 0) {
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
    if (retained->first_thread_limit && thread_limit != retained->first_thread_limit) {
        /* don't need a startup console version here */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00506)
                     "changing ThreadLimit to %d from original value of %d "
                     "not allowed during restart",
                     thread_limit, retained->first_thread_limit);
        thread_limit = retained->first_thread_limit;
    }

    /* Auto settings depend on max_workers and num_buckets, the latter being
     * known in event_open_logs() only. So defer to there (with no warnings
     * since it's somewhat auto..).
     */
    if (auto_settings) {
        if (max_workers <= 0) {
            /* This used to warn before auto settings, just take the
             * default value still but silently.
             */
            max_workers = DEFAULT_SERVER_LIMIT * DEFAULT_THREADS_PER_CHILD;
        }
        if (threads_per_child <= 0) {
            /* Default threads_per_child is the number of CPUs  */
            threads_per_child = num_online_cpus;

            /* With a lot of workers and not so much CPUs to handle them,
             * spawn more threads to get a reasonable active_daemons_limit
             * i.e. processes / threads ratio.
             */
            while (max_workers / threads_per_child >
                   threads_per_child * MAX_DAEMONS_THREADS_RATIO) {
                threads_per_child *= 2;
            }
        }
        return OK; /* => event_open_logs() */
    }

    /* No auto settings; use the default for anything not set (or set to
     * some negative value), warn about nonsense values and adjust otherwise.
     */

    if (threads_per_child < 0) {
        threads_per_child = DEFAULT_THREADS_PER_CHILD;
    }
    else if (threads_per_child > thread_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00507)
                         "WARNING: ThreadsPerChild of %d exceeds ThreadLimit "
                         "of %d threads, decreasing to %d. "
                         "To increase, please see the ThreadLimit directive.",
                         threads_per_child, thread_limit, thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00508)
                         "ThreadsPerChild of %d exceeds ThreadLimit "
                         "of %d, decreasing to match",
                         threads_per_child, thread_limit);
        }
        threads_per_child = thread_limit;
    }
    else if (threads_per_child == 0) {
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

    if (max_workers < 0) {
        max_workers = DEFAULT_SERVER_LIMIT * DEFAULT_THREADS_PER_CHILD;
    }
    else if (max_workers < threads_per_child) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00511)
                         "WARNING: MaxRequestWorkers of %d is less than "
                         "ThreadsPerChild of %d, increasing to %d. "
                         "MaxRequestWorkers must be at least as large "
                         "as the number of threads in a single server.",
                         max_workers, threads_per_child, threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00512)
                         "MaxRequestWorkers of %d is less than ThreadsPerChild "
                         "of %d, increasing to match",
                         max_workers, threads_per_child);
        }
        max_workers = threads_per_child;
    }

    active_daemons_limit = max_workers / threads_per_child;
    if (active_daemons_limit > server_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00515)
                         "WARNING: MaxRequestWorkers of %d would require %d servers "
                         "and would exceed ServerLimit of %d, decreasing to %d. "
                         "To increase, please see the ServerLimit directive.",
                         max_workers, active_daemons_limit, server_limit,
                         server_limit * threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00516)
                         "MaxRequestWorkers of %d would require %d servers and "
                         "exceed ServerLimit of %d, decreasing to %d",
                         max_workers, active_daemons_limit, server_limit,
                         server_limit * threads_per_child);
        }
        active_daemons_limit = server_limit;
        max_workers = active_daemons_limit * threads_per_child;
    }
    else if (max_workers % threads_per_child) {
        int new_max_workers = active_daemons_limit * threads_per_child;
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00513)
                         "WARNING: MaxRequestWorkers of %d is not an integer "
                         "multiple of ThreadsPerChild of %d, decreasing to nearest "
                         "multiple %d, for a maximum of %d servers.",
                         max_workers, threads_per_child, new_max_workers,
                         active_daemons_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00514)
                         "MaxRequestWorkers of %d is not an integer multiple "
                         "of ThreadsPerChild of %d, decreasing to nearest "
                         "multiple %d", max_workers, threads_per_child,
                         new_max_workers);
        }
        max_workers = new_max_workers;
    }

    if (ap_daemons_to_start < 0) {
        ap_daemons_to_start = DEFAULT_START_DAEMON;
    }
    else if (ap_daemons_to_start > active_daemons_limit) {
        ap_daemons_to_start = active_daemons_limit;
    }
    else if (ap_daemons_to_start == 0) {
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

    if (min_spare_threads < 0) {
        min_spare_threads = DEFAULT_MIN_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    }
    else if (min_spare_threads == 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00519)
                         "WARNING: MinSpareThreads of %d not allowed, "
                         "increasing to 1 to avoid almost certain server "
                         "failure. Please read the documentation.",
                         min_spare_threads);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00520)
                         "MinSpareThreads of %d not allowed, increasing to 1",
                         min_spare_threads);
        }
        min_spare_threads = threads_per_child;
    }

    if (max_spare_threads < 0) {
        max_spare_threads = DEFAULT_MAX_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    }
    else {
        /* max_spare_threads value has never been checked, it's silently
         * adjusted in event_open_logs() such that max_spare_threads >=
         * min_spare_threads + threads_per_child.
         */
    }

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
    ap_force_set_tz(p);

    ap_hook_open_logs(event_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);
    /* we need to set the MPM state before other pre-config hooks use MPM query
     * to retrieve it, so register as REALLY_FIRST
     */
    ap_hook_pre_config(event_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_post_config(event_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(event_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm(event_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(event_query, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_register_timed_callback(event_register_timed_callback, NULL, NULL,
                                        APR_HOOK_MIDDLE);
    ap_hook_mpm_register_poll_callback(event_register_poll_callback,
                                       NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_register_poll_callback_timeout(event_register_poll_callback_ex,
                                               NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_read_request(event_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(event_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_get_name(event_get_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_resume_suspended(event_resume_suspended, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_pre_connection(event_pre_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_protocol_switch(event_protocol_switch, NULL, NULL, APR_HOOK_REALLY_FIRST);
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
                                   const char *arg, const char *arg2)
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
    auto_settings = (arg2 && !strcasecmp(arg2, "auto"));

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
static const char *set_server_limit(cmd_parms *cmd, void *dummy, const char *arg)
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
    char *endptr;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    async_factor = strtod(arg, &endptr);
    if (*endptr || async_factor < 1.0) {
        return "AsyncRequestWorkerFactor must be a rational number greater or equal to 1";
    }
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
    AP_INIT_TAKE12("MaxClients", set_max_workers, NULL, RSRC_CONF,
                   "Deprecated name of MaxRequestWorkers"),
    AP_INIT_TAKE12("MaxRequestWorkers", set_max_workers, NULL, RSRC_CONF,
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
