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

/* The BeOS MPM!
 *
 * This is a single process, with multiple worker threads.
 *
 * Under testing I found that given the inability of BeOS to handle threads
 * and forks it didn't make sense to try and have a set of "children" threads
 * that spawned the "worker" threads, so just missed out the middle mand and
 * somehow arrived here.
 *
 * For 2.1 this has been rewritten to have simpler logic, though there is still
 * some simplification that can be done. It's still a work in progress!
 *
 * TODO Items
 *
 * - on exit most worker threads segfault trying to access a kernel page.
 */

#include <kernel/OS.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>

#include "apr_strings.h"
#include "apr_portable.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"        /* for read_config */
#include "http_core.h"          /* for get_remote_host */
#include "http_connection.h"
#include "ap_mpm.h"
#include "beosd.h"
#include "ap_listen.h"
#include "scoreboard.h"
#include "mpm_common.h"
#include "mpm.h"
#include "mpm_default.h"
#include "apr_thread_mutex.h"
#include "apr_poll.h"

#define MPM_HARD_LIMITS_FILE APACHE_MPM_DIR "/mpm_default.h"

extern int _kset_fd_limit_(int num);

/* Limit on the total --- clients will be locked out if more servers than
 * this are needed.  It is intended solely to keep the server from crashing
 * when things get out of hand.
 *
 * We keep a hard maximum number of servers, for two reasons:
 * 1) in case something goes seriously wrong, we want to stop the server starting
 *    threads ad infinitum and crashing the server (remember that BeOS has a 192
 *    thread per team limit).
 * 2) it keeps the size of the scoreboard file small
 *    enough that we can read the whole thing without worrying too much about
 *    the overhead.
 */

/* we only ever have 1 main process running... */
#define HARD_SERVER_LIMIT 1

/* Limit on the threads per process.  Clients will be locked out if more than
 * this  * HARD_SERVER_LIMIT are needed.
 *
 * We keep this for one reason it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifdef NO_THREADS
#define HARD_THREAD_LIMIT 1
#endif
#ifndef HARD_THREAD_LIMIT
#define HARD_THREAD_LIMIT 50
#endif

/*
 * Actual definitions of config globals
 */

static int ap_threads_to_start=0;
static int ap_max_requests_per_thread = 0;
static int min_spare_threads=0;
static int max_spare_threads=0;
static int ap_thread_limit=0;
static int num_listening_sockets = 0;
static int mpm_state = AP_MPMQ_STARTING;
apr_thread_mutex_t *accept_mutex = NULL;

static apr_pool_t *pconf;    /* Pool for config stuff */
static apr_pool_t *pmain;    /* Pool for httpd child stuff */

static int server_pid;


/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across AP_SIG_GRACEFUL restarts.  We use
 * this value to optimize routines that have to scan the entire scoreboard.
 */
int ap_max_child_assigned = -1;
int ap_max_threads_limit = -1;

static apr_socket_t *udp_sock;
static apr_sockaddr_t *udp_sa;

server_rec *ap_server_conf;

/* one_process */
static int one_process = 0;

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

static void check_restart(void *data);

/* When a worker thread gets to the end of it's life it dies with an
 * exit value of the code supplied to this function. The thread has
 * already had check_restart() registered to be called when dying, so
 * we don't concern ourselves with restarting at all here. We do however
 * mark the scoreboard slot as belonging to a dead server and zero out
 * it's thread_id.
 *
 * TODO - use the status we set to determine if we need to restart the
 *        thread.
 */
static void clean_child_exit(int code, int slot)
{
    (void) ap_update_child_status_from_indexes(0, slot, SERVER_DEAD,
                                               (request_rec*)NULL);
    ap_scoreboard_image->servers[0][slot].tid = 0;
    exit_thread(code);
}

/* proper cleanup when returning from ap_mpm_run() */
static void mpm_main_cleanup(void)
{
    if (pmain) {
        apr_pool_destroy(pmain);
    }
}


/*****************************************************************
 * Connection structures and accounting...
 */

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
static int volatile child_fatal;
ap_generation_t volatile ap_my_generation = 0;

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
    /* If the user tries to shut us down twice in quick succession then we
     * may well get triggered while we are working through previous attempt
     * to shutdown. We won't worry about even reporting it as it seems a little
     * pointless.
     */
    if (shutdown_pending == 1)
        return;

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

/* sig_coredump attempts to handle all the potential signals we
 * may get that should result in a core dump. This is called from
 * the signal handler routine, so when we enter we are essentially blocked
 * on the signal. Once we exit we will allow the signal to be processed by
 * system, which may or may not produce a .core file. All this function does
 * is try and respect the users wishes about where that file should be
 * located (chdir) and then signal the parent with the signal.
 *
 * If we called abort() the parent would only see SIGABRT which doesn't provide
 * as much information.
 */
static void sig_coredump(int sig)
{
    chdir(ap_coredump_dir);
    signal(sig, SIG_DFL);
    kill(server_pid, sig);
}

static void sig_term(int sig)
{
    ap_start_shutdown();
}

static void restart(int sig)
{
    ap_start_restart(sig == AP_SIG_GRACEFUL);
}

/* Handle queries about our inner workings... */
AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_max_child_assigned;
            return APR_SUCCESS;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_DYNAMIC;
            return APR_SUCCESS;
        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_NOT_SUPPORTED;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = HARD_THREAD_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_THREADS:
            *result = HARD_THREAD_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:
            *result = max_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = min_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_thread;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MPM_STATE:
            *result = mpm_state;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}

/* This accepts a connection and allows us to handle the error codes better than
 * the previous code, while also making it more obvious.
 */
static apr_status_t beos_accept(void **accepted, ap_listen_rec *lr, apr_pool_t *ptrans)
{
    apr_socket_t *csd;
    apr_status_t status;
    int sockdes;

    *accepted = NULL;
    status = apr_socket_accept(&csd, lr->sd, ptrans);
    if (status == APR_SUCCESS) {
        *accepted = csd;
        apr_os_sock_get(&sockdes, csd);
        return status;
    }

    if (APR_STATUS_IS_EINTR(status)) {
        return status;
    }
        /* This switch statement provides us with better error details. */
    switch (status) {
#ifdef ECONNABORTED
        case ECONNABORTED:
#endif
#ifdef ETIMEDOUT
        case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
        case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
        case ENETUNREACH:
#endif
            break;
#ifdef ENETDOWN
        case ENETDOWN:
            /*
             * When the network layer has been shut down, there
             * is not much use in simply exiting: the parent
             * would simply re-create us (and we'd fail again).
             * Use the CHILDFATAL code to tear the server down.
             * @@@ Martin's idea for possible improvement:
             * A different approach would be to define
             * a new APEXIT_NETDOWN exit code, the reception
             * of which would make the parent shutdown all
             * children, then idle-loop until it detected that
             * the network is up again, and restart the children.
             * Ben Hyde noted that temporary ENETDOWN situations
             * occur in mobile IP.
             */
            ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf,
                         "apr_socket_accept: giving up.");
            return APR_EGENERAL;
#endif /*ENETDOWN*/

        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, status, ap_server_conf,
                         "apr_socket_accept: (client socket)");
            return APR_EGENERAL;
    }
    return status;
}

static void tell_workers_to_exit(void)
{
    apr_size_t len;
    int i = 0;
    for (i = 0 ; i < ap_max_child_assigned; i++){
        len = 4;
        if (apr_socket_sendto(udp_sock, udp_sa, 0, "die!", &len) != APR_SUCCESS)
            break;
    }
}

static void set_signals(void)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    /* The first batch get handled by sig_coredump */
    if (!one_process) {
        sa.sa_handler = sig_coredump;

        if (sigaction(SIGSEGV, &sa, NULL) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGSEGV)");
        if (sigaction(SIGBUS, &sa, NULL) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGBUS)");
        if (sigaction(SIGABRT, &sa, NULL) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGABRT)");
        if (sigaction(SIGILL, &sa, NULL) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGILL)");
        sa.sa_flags = 0;
    }

    /* These next two are handled by sig_term */
    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGTERM)");
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGINT)");

    /* We ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGPIPE)");

    /* we want to ignore HUPs and AP_SIG_GRACEFUL while we're busy
     * processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, AP_SIG_GRACEFUL);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
    if (sigaction(AP_SIG_GRACEFUL, &sa, NULL) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(" AP_SIG_GRACEFUL_STRING ")");
}

/* This is the thread that actually does all the work. */
static int32 worker_thread(void *dummy)
{
    int worker_slot = (int)dummy;
    apr_allocator_t *allocator;
    apr_bucket_alloc_t *bucket_alloc;
    apr_status_t rv = APR_EINIT;
    int last_poll_idx = 0;
    sigset_t sig_mask;
    int requests_this_child = 0;
    apr_pollset_t *pollset = NULL;
    ap_listen_rec *lr = NULL;
    ap_sb_handle_t *sbh = NULL;
    int i;
    /* each worker thread is in control of its own destiny...*/
    int this_worker_should_exit = 0;
    /* We have 2 pools that we create/use throughout the lifetime of this
     * worker. The first and longest lived is the pworker pool. From
     * this we create the ptrans pool, the lifetime of which is the same
     * as each connection and is reset prior to each attempt to
     * process a connection.
     */
    apr_pool_t *ptrans = NULL;
    apr_pool_t *pworker = NULL;

    mpm_state = AP_MPMQ_STARTING; /* for benefit of any hooks that run as this
                                  * child initializes
                                  */

    on_exit_thread(check_restart, (void*)worker_slot);

    /* block the signals for this thread only if we're not running as a
     * single process.
     */
    if (!one_process) {
        sigfillset(&sig_mask);
        sigprocmask(SIG_BLOCK, &sig_mask, NULL);
    }

    /* Each worker thread is fully in control of it's destinay and so
     * to allow each thread to handle the lifetime of it's own resources
     * we create and use a subcontext for every thread.
     * The subcontext is a child of the pconf pool.
     */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    apr_pool_create_ex(&pworker, pconf, NULL, allocator);
    apr_allocator_owner_set(allocator, pworker);

    apr_pool_create(&ptrans, pworker);
    apr_pool_tag(ptrans, "transaction");

    ap_create_sb_handle(&sbh, pworker, 0, worker_slot);
    (void) ap_update_child_status(sbh, SERVER_READY, (request_rec *) NULL);

    /* We add an extra socket here as we add the udp_sock we use for signalling
     * death. This gets added after the others.
     */
    apr_pollset_create(&pollset, num_listening_sockets + 1, pworker, 0);

    for (lr = ap_listeners, i = num_listening_sockets; i--; lr = lr->next) {
        apr_pollfd_t pfd = {0};

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = lr->sd;
        pfd.reqevents = APR_POLLIN;
        pfd.client_data = lr;

        apr_pollset_add(pollset, &pfd);
    }
    {
        apr_pollfd_t pfd = {0};

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = udp_sock;
        pfd.reqevents = APR_POLLIN;

        apr_pollset_add(pollset, &pfd);
    }

    bucket_alloc = apr_bucket_alloc_create(pworker);

    mpm_state = AP_MPMQ_RUNNING;

        while (!this_worker_should_exit) {
        conn_rec *current_conn;
        void *csd;

        /* (Re)initialize this child to a pre-connection state. */
        apr_pool_clear(ptrans);

        if ((ap_max_requests_per_thread > 0
             && requests_this_child++ >= ap_max_requests_per_thread))
            clean_child_exit(0, worker_slot);

        (void) ap_update_child_status(sbh, SERVER_READY, (request_rec *) NULL);

        apr_thread_mutex_lock(accept_mutex);

        /* We always (presently) have at least 2 sockets we listen on, so
         * we don't have the ability for a fast path for a single socket
         * as some MPM's allow :(
         */
        for (;;) {
            apr_int32_t numdesc = 0;
            const apr_pollfd_t *pdesc = NULL;

            rv = apr_pollset_poll(pollset, -1, &numdesc, &pdesc);
            if (rv != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(rv)) {
                    if (one_process && shutdown_pending)
                        return;
                    continue;
                }
                ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                             ap_server_conf, "apr_pollset_poll: (listen)");
                clean_child_exit(1, worker_slot);
            }
            /* We can always use pdesc[0], but sockets at position N
             * could end up completely starved of attention in a very
             * busy server. Therefore, we round-robin across the
             * returned set of descriptors. While it is possible that
             * the returned set of descriptors might flip around and
             * continue to starve some sockets, we happen to know the
             * internal pollset implementation retains ordering
             * stability of the sockets. Thus, the round-robin should
             * ensure that a socket will eventually be serviced.
             */
            if (last_poll_idx >= numdesc)
                last_poll_idx = 0;

            /* Grab a listener record from the client_data of the poll
             * descriptor, and advance our saved index to round-robin
             * the next fetch.
             *
             * ### hmm... this descriptor might have POLLERR rather
             * ### than POLLIN
             */

            lr = pdesc[last_poll_idx++].client_data;

            /* The only socket we add without client_data is the first, the UDP socket
             * we listen on for restart signals. If we've therefore gotten a hit on that
             * listener lr will be NULL here and we know we've been told to die.
             * Before we jump to the end of the while loop with this_worker_should_exit
             * set to 1 (causing us to exit normally we hope) we release the accept_mutex
             * as we want every thread to go through this same routine :)
             * Bit of a hack, but compared to what I had before...
             */
            if (lr == NULL) {
                this_worker_should_exit = 1;
                apr_thread_mutex_unlock(accept_mutex);
                goto got_a_black_spot;
            }
            goto got_fd;
        }
got_fd:
        /* Run beos_accept to accept the connection and set things up to
         * allow us to process it. We always release the accept_lock here,
         * even if we failt o accept as otherwise we'll starve other workers
         * which would be bad.
         */
        rv = beos_accept(&csd, lr, ptrans);
        apr_thread_mutex_unlock(accept_mutex);

        if (rv == APR_EGENERAL) {
            /* resource shortage or should-not-occur occured */
            clean_child_exit(1, worker_slot);
        } else if (rv != APR_SUCCESS)
            continue;

        current_conn = ap_run_create_connection(ptrans, ap_server_conf, csd, worker_slot, sbh, bucket_alloc);
        if (current_conn) {
            ap_process_connection(current_conn, csd);
            ap_lingering_close(current_conn);
        }

        if (ap_my_generation !=
                 ap_scoreboard_image->global->running_generation) { /* restart? */
            /* yeah, this could be non-graceful restart, in which case the
             * parent will kill us soon enough, but why bother checking?
             */
            this_worker_should_exit = 1;
        }
got_a_black_spot:
    }

    apr_pool_destroy(ptrans);
    apr_pool_destroy(pworker);

    clean_child_exit(0, worker_slot);
}

static int make_worker(int slot)
{
    thread_id tid;

    if (slot + 1 > ap_max_child_assigned)
            ap_max_child_assigned = slot + 1;

    (void) ap_update_child_status_from_indexes(0, slot, SERVER_STARTING, (request_rec*)NULL);

    if (one_process) {
        set_signals();
        ap_scoreboard_image->parent[0].pid = getpid();
        ap_scoreboard_image->servers[0][slot].tid = find_thread(NULL);
        return 0;
    }

    tid = spawn_thread(worker_thread, "apache_worker", B_NORMAL_PRIORITY,
                       (void *)slot);
    if (tid < B_NO_ERROR) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, NULL,
            "spawn_thread: Unable to start a new thread");
        /* In case system resources are maxed out, we don't want
         * Apache running away with the CPU trying to fork over and
         * over and over again.
         */
        (void) ap_update_child_status_from_indexes(0, slot, SERVER_DEAD,
                                                   (request_rec*)NULL);

        sleep(10);
        return -1;
    }
    resume_thread(tid);

    ap_scoreboard_image->servers[0][slot].tid = tid;
    return 0;
}

/* When a worker thread exits, this function is called. If we are not in
 * a shutdown situation then we restart the worker in the slot that was
 * just vacated.
 */
static void check_restart(void *data)
{
    if (!restart_pending && !shutdown_pending) {
        int slot = (int)data;
        make_worker(slot);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL,
                     "spawning a new worker thread in slot %d", slot);
    }
}

/* Start number_to_start children. This is used to start both the
 * initial 'pool' of workers but also to replace existing workers who
 * have reached the end of their time. It walks through the scoreboard to find
 * an empty slot and starts the worker thread in that slot.
 */
static void startup_threads(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_thread_limit; ++i) {
        if (ap_scoreboard_image->servers[0][i].tid)
            continue;

        if (make_worker(i) < 0)
                break;

        --number_to_start;
    }
}


/*
 * spawn_rate is the number of children that will be spawned on the
 * next maintenance cycle if there aren't enough idle servers.  It is
 * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
 * without the need to spawn.
 */
static int spawn_rate = 1;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE  (32)
#endif
static int hold_off_on_exponential_spawning;

static void perform_idle_server_maintenance(void)
{
    int i;
    int free_length;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead  = -1;

    /* initialize the free_list */
    free_length = 0;

    for (i = 0; i < ap_thread_limit; ++i) {
        if (ap_scoreboard_image->servers[0][i].tid == 0) {
            if (free_length < spawn_rate) {
                free_slots[free_length] = i;
                ++free_length;
            }
        }
        else {
            last_non_dead = i;
        }

        if (i >= ap_max_child_assigned && free_length >= spawn_rate) {
                 break;
        }
    }
    ap_max_child_assigned = last_non_dead + 1;

    if (free_length > 0) {
        for (i = 0; i < free_length; ++i) {
                make_worker(free_slots[i]);
        }
        /* the next time around we want to spawn twice as many if this
         * wasn't good enough, but not if we've just done a graceful
         */
        if (hold_off_on_exponential_spawning) {
            --hold_off_on_exponential_spawning;
        } else if (spawn_rate < MAX_SPAWN_RATE) {
            spawn_rate *= 2;
        }
    } else {
        spawn_rate = 1;
    }
}

static void server_main_loop(int remaining_threads_to_start)
{
    int child_slot;
    apr_exit_why_e exitwhy;
    int status;
    apr_proc_t pid;
    int i;

    while (!restart_pending && !shutdown_pending) {

        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf);

        if (pid.pid >= 0) {
            if (ap_process_child_status(&pid, exitwhy, status) == APEXIT_CHILDFATAL) {
                shutdown_pending = 1;
                child_fatal = 1;
                return;
            }
            /* non-fatal death... note that it's gone in the scoreboard. */
            child_slot = -1;
            for (i = 0; i < ap_max_child_assigned; ++i) {
                if (ap_scoreboard_image->servers[0][i].tid == pid.pid) {
                    child_slot = i;
                    break;
                }
            }
            if (child_slot >= 0) {
                ap_scoreboard_image->servers[0][child_slot].tid = 0;
                (void) ap_update_child_status_from_indexes(0, child_slot,
                                                           SERVER_DEAD,
                                                           (request_rec*)NULL);

                if (remaining_threads_to_start
                            && child_slot < ap_thread_limit) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_worker(child_slot);
                    --remaining_threads_to_start;
                        }
/* TODO
#if APR_HAS_OTHER_CHILD
            }
            else if (apr_proc_other_child_refresh(&pid, status) == 0) {
#endif
*/
            }
            else if (is_graceful) {
                /* Great, we've probably just lost a slot in the
                 * scoreboard.  Somehow we don't know about this
                 * child.
                 */
                 ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                                          "long lost child came home! (pid %ld)", pid.pid);
            }

            /* Don't perform idle maintenance when a child dies,
             * only do it when there's a timeout.  Remember only a
             * finite number of children can die, and it's pretty
             * pathological for a lot to die suddenly.
             */
             continue;
         }
             else if (remaining_threads_to_start) {
             /* we hit a 1 second timeout in which none of the previous
              * generation of children needed to be reaped... so assume
              * they're all done, and pick up the slack if any is left.
              */
              startup_threads(remaining_threads_to_start);
              remaining_threads_to_start = 0;
              /* In any event we really shouldn't do the code below because
               * few of the servers we just started are in the IDLE state
               * yet, so we'd mistakenly create an extra server.
               */
              continue;
         }
         perform_idle_server_maintenance();
    }
}

/* This is called to not only setup and run for the initial time, but also
 * when we've asked for a restart. This means it must be able to handle both
 * situations. It also means that when we exit here we should have tidied
 * up after ourselves fully.
 */
int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int remaining_threads_to_start, i,j;
    apr_status_t rv;
    ap_listen_rec *lr;
    pconf = _pconf;
    ap_server_conf = s;

    /* Increase the available pool of fd's.  This code from
     * Joe Kloss <joek@be.com>
     */
    if( FD_SETSIZE > 128 && (i = _kset_fd_limit_( 128 )) < 0 ){
        ap_log_error(APLOG_MARK, APLOG_ERR, i, s,
            "could not set FD_SETSIZE (_kset_fd_limit_ failed)");
    }

    /* BeOS R5 doesn't support pipes on select() calls, so we use a
     * UDP socket as these are supported in both R5 and BONE.  If we only cared
     * about BONE we'd use a pipe, but there it is.
     * As we have UDP support in APR, now use the APR functions and check all the
     * return values...
     */
    if (apr_sockaddr_info_get(&udp_sa, "127.0.0.1", APR_UNSPEC, 7772, 0, _pconf)
        != APR_SUCCESS){
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, s,
            "couldn't create control socket information, shutting down");
        return 1;
    }
    if (apr_socket_create(&udp_sock, udp_sa->family, SOCK_DGRAM, 0,
                      _pconf) != APR_SUCCESS){
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, s,
            "couldn't create control socket, shutting down");
        return 1;
    }
    if (apr_socket_bind(udp_sock, udp_sa) != APR_SUCCESS){
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, s,
            "couldn't bind UDP socket!");
        return 1;
    }

    if ((num_listening_sockets = ap_setup_listeners(ap_server_conf)) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s,
            "no listening sockets available, shutting down");
        return 1;
    }

    ap_log_pid(pconf, ap_pid_fname);

    /*
     * Create our locks...
     */

    /* accept_mutex
     * used to lock around select so we only have one thread
     * in select at a time
     */
    rv = apr_thread_mutex_create(&accept_mutex, 0, pconf);
    if (rv != APR_SUCCESS) {
        /* tsch tsch, can't have more than one thread in the accept loop
           at a time so we need to fall on our sword... */
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Couldn't create accept lock");
        return 1;
    }

    /*
     * Startup/shutdown...
     */

    if (!is_graceful) {
        /* setup the scoreboard shared memory */
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            return 1;
        }

        for (i = 0; i < HARD_SERVER_LIMIT; i++) {
            ap_scoreboard_image->parent[i].pid = 0;
            for (j = 0;j < HARD_THREAD_LIMIT; j++)
                ap_scoreboard_image->servers[i][j].tid = 0;
        }
    }

    if (HARD_SERVER_LIMIT == 1)
        ap_scoreboard_image->parent[0].pid = getpid();

    set_signals();

    apr_pool_create(&pmain, pconf);
    ap_run_child_init(pmain, ap_server_conf);

    /* Sanity checks to avoid thrashing... */
    if (max_spare_threads < min_spare_threads )
        max_spare_threads = min_spare_threads;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of threads exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens
     * pretty rapidly... and for each one that exits we'll start a new one
     * until we reach at least threads_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_threads_to_start = ap_threads_to_start;
    /* sanity check on the number to start... */
    if (remaining_threads_to_start > ap_thread_limit) {
            remaining_threads_to_start = ap_thread_limit;
    }

    /* If we're doing the single process thing or we're in a graceful_restart
     * then we don't start threads here.
     * if we're in one_process mode we don't want to start threads
     * do we??
     */
    if (!is_graceful && !one_process) {
            startup_threads(remaining_threads_to_start);
            remaining_threads_to_start = 0;
    } else {
            /* give the system some time to recover before kicking into
             * exponential mode */
        hold_off_on_exponential_spawning = 10;
    }

    /*
     * record that we've entered the world !
     */
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                "%s configured -- resuming normal operations",
                ap_get_server_description());

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
                "Server built: %s", ap_get_server_built());

    restart_pending = shutdown_pending = 0;

    mpm_state = AP_MPMQ_RUNNING;

    /* We sit in the server_main_loop() until we somehow manage to exit. When
     * we do, we need to kill the workers we have, so we start by using the
     * tell_workers_to_exit() function, but as it sometimes takes a short while
     * to accomplish this we have a pause builtin to allow them the chance to
     * gracefully exit.
     */
    if (!one_process) {
        server_main_loop(remaining_threads_to_start);
        tell_workers_to_exit();
        snooze(1000000);
    } else {
        worker_thread((void*)0);
    }
    mpm_state = AP_MPMQ_STOPPING;

    /* close the UDP socket we've been using... */
    apr_socket_close(udp_sock);

    if ((one_process || shutdown_pending) && !child_fatal) {
        const char *pidfile = NULL;
        pidfile = ap_server_root_relative (pconf, ap_pid_fname);
        if ( pidfile != NULL && unlink(pidfile) == 0)
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
                         "removed PID file %s (pid=%ld)", pidfile,
                         (long)getpid());
    }

    if (one_process) {
        mpm_main_cleanup();
        return 1;
    }

    /*
     * If we get here we're shutting down...
     */
    if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (beosd_killpg(getpgrp(), SIGTERM) < 0)
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
             "killpg SIGTERM");

        /* use ap_reclaim_child_processes starting with SIGTERM */
        ap_reclaim_child_processes(1);

        if (!child_fatal) {         /* already recorded */
            /* record the shutdown in the log */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                         "caught SIGTERM, shutting down");
        }

        mpm_main_cleanup();
        return 1;
    }

    /* we've been told to restart */
    signal(SIGHUP, SIG_IGN);

    if (is_graceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                    AP_SIG_GRACEFUL_STRING " received.  Doing graceful restart");
    } else {
        /* Kill 'em all.  Since the child acts the same on the parents SIGTERM
         * and a SIGHUP, we may as well use the same signal, because some user
         * pthreads are stealing signals from us left and right.
         */

        ap_reclaim_child_processes(1);   /* Start with SIGTERM */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                    "SIGHUP received.  Attempting to restart");
    }

    /* just before we go, tidy up the lock we created to prevent a
     * potential leak of semaphores...
     */
    apr_thread_mutex_destroy(accept_mutex);

    mpm_main_cleanup();
    return 0;
}

static int beos_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach, debug, foreground;
    apr_status_t rv;

    mpm_state = AP_MPMQ_STARTING;

    debug = ap_exists_config_define("DEBUG");

    if (debug) {
        foreground = one_process = 1;
        no_detach = 0;
    }
    else
    {
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

        server_pid = getpid();
    }

    beosd_pre_config();
    ap_listen_pre_config();
    ap_threads_to_start = DEFAULT_START_THREADS;
    min_spare_threads = DEFAULT_MIN_FREE_THREADS;
    max_spare_threads = DEFAULT_MAX_FREE_THREADS;
    ap_thread_limit = HARD_THREAD_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_thread = DEFAULT_MAX_REQUESTS_PER_THREAD;
#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
        ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;
#endif

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));

    return OK;
}

static int beos_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    static int restart_num = 0;
    int startup = 0;

    /* the reverse of pre_config, we want this only the first time around */
    if (restart_num++ == 0) {
        startup = 1;
    }

    if (ap_thread_limit > HARD_THREAD_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: MaxClients of %d exceeds compile-time "
                         "limit of", ap_thread_limit);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " %d servers, decreasing to %d.",
                         HARD_THREAD_LIMIT, HARD_THREAD_LIMIT);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " To increase, please see the HARD_THREAD_LIMIT"
                         "define in");
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " server/mpm/beos%s.", MPM_HARD_LIMITS_FILE);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "MaxClients of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         ap_thread_limit, HARD_THREAD_LIMIT);
        }
        ap_thread_limit = HARD_THREAD_LIMIT;
    }
    else if (ap_thread_limit < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: MaxClients of %d not allowed, "
                         "increasing to 1.", ap_thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "MaxClients of %d not allowed, increasing to 1",
                         ap_thread_limit);
        }
        ap_thread_limit = 1;
    }

    /* ap_threads_to_start > ap_thread_limit checked in ap_mpm_run() */
    if (ap_threads_to_start < 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: StartThreads of %d not allowed, "
                         "increasing to 1.", ap_threads_to_start);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "StartThreads of %d not allowed, increasing to 1",
                         ap_threads_to_start);
        }
        ap_threads_to_start = 1;
    }

    if (min_spare_threads < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: MinSpareThreads of %d not allowed, "
                         "increasing to 1", min_spare_threads);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " to avoid almost certain server failure.");
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " Please read the documentation.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "MinSpareThreads of %d not allowed, increasing to 1",
                         min_spare_threads);
        }
        min_spare_threads = 1;
    }

    /* max_spare_threads < min_spare_threads checked in ap_mpm_run() */

    if (ap_max_requests_per_thread < 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: MaxRequestsPerThread of %d not allowed, "
                         "increasing to 0,", ap_max_requests_per_thread);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " but this may not be what you want.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "MaxRequestsPerThread of %d not allowed, "
                         "increasing to 0", ap_max_requests_per_thread);
        }
        ap_max_requests_per_thread = 0;
    }

    return OK;
}

static void beos_hooks(apr_pool_t *p)
{
    one_process = 0;

    ap_hook_pre_config(beos_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(beos_check_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_threads_to_start(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_threads_limit (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_thread_limit = atoi(arg);
    return NULL;
}

static const char *set_max_requests_per_thread (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_thread = atoi(arg);
    return NULL;
}

static const command_rec beos_cmds[] = {
BEOS_DAEMON_COMMANDS,
LISTEN_COMMANDS,
AP_INIT_TAKE1( "StartThreads", set_threads_to_start, NULL, RSRC_CONF,
  "Number of threads to launch at server startup"),
AP_INIT_TAKE1( "MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
  "Minimum number of idle children, to handle request spikes"),
AP_INIT_TAKE1( "MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
  "Maximum number of idle children" ),
AP_INIT_TAKE1( "MaxClients", set_threads_limit, NULL, RSRC_CONF,
  "Maximum number of children alive at the same time (max threads)" ),
AP_INIT_TAKE1( "MaxRequestsPerThread", set_max_requests_per_thread, NULL, RSRC_CONF,
  "Maximum number of requests served by a thread" ),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_beos_module = {
    MPM20_MODULE_STUFF,
    NULL,          /* hook to run before apache parses args */
    NULL,          /* create per-directory config structure */
    NULL,          /* merge per-directory config structures */
    NULL,          /* create per-server config structure */
    NULL,          /* merge per-server config structures */
    beos_cmds,     /* command apr_table_t */
    beos_hooks     /* register_hooks */
};

