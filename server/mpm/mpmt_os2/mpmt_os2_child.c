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

#define INCL_NOPMAPI
#define INCL_DOS
#define INCL_DOSERRORS

#include "ap_config.h"
#include "httpd.h"
#include "mpm_default.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"  /* for get_remote_host */
#include "http_connection.h"
#include "mpm.h"
#include "ap_mpm.h"
#include "ap_listen.h"
#include "apr_portable.h"
#include "apr_poll.h"
#include "mpm_common.h"
#include "apr_strings.h"
#include <os2.h>
#include <process.h>

/* XXXXXX move these to header file private to this MPM */

/* We don't need many processes,
 * they're only for redundancy in the event of a crash
 */
#define HARD_SERVER_LIMIT 10

/* Limit on the total number of threads per process
 */
#ifndef HARD_THREAD_LIMIT
#define HARD_THREAD_LIMIT 256
#endif

#define ID_FROM_CHILD_THREAD(c, t)    ((c * HARD_THREAD_LIMIT) + t)

typedef struct {
    apr_pool_t *pconn;
    apr_socket_t *conn_sd;
} worker_args_t;

#define WORKTYPE_CONN 0
#define WORKTYPE_EXIT 1

static apr_pool_t *pchild = NULL;
static int child_slot;
static int shutdown_pending = 0;
extern int ap_my_generation;
static int volatile is_graceful = 1;
HEV shutdown_event; /* signaled when this child is shutting down */

/* grab some MPM globals */
extern int ap_min_spare_threads;
extern int ap_max_spare_threads;
extern HMTX ap_mpm_accept_mutex;

static void worker_main(void *vpArg);
static void clean_child_exit(int code);
static void set_signals();
static void server_maintenance(void *vpArg);


static void clean_child_exit(int code)
{
    if (pchild) {
        apr_pool_destroy(pchild);
    }

    exit(code);
}



void ap_mpm_child_main(apr_pool_t *pconf)
{
    ap_listen_rec *lr = NULL;
    int requests_this_child = 0;
    int rv = 0;
    unsigned long ulTimes;
    int my_pid = getpid();
    ULONG rc, c;
    HQUEUE workq;
    apr_pollset_t *pollset;
    int num_listeners;
    TID server_maint_tid;
    void *sb_mem;

    /* Stop Ctrl-C/Ctrl-Break signals going to child processes */
    DosSetSignalExceptionFocus(0, &ulTimes);
    set_signals();

    /* Create pool for child */
    apr_pool_create(&pchild, pconf);

    ap_run_child_init(pchild, ap_server_conf);

    /* Create an event semaphore used to trigger other threads to shutdown */
    rc = DosCreateEventSem(NULL, &shutdown_event, 0, FALSE);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "unable to create shutdown semaphore, exiting");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Gain access to the scoreboard. */
    rc = DosGetNamedSharedMem(&sb_mem, ap_scoreboard_fname,
                              PAG_READ|PAG_WRITE);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "scoreboard not readable in child, exiting");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_calc_scoreboard_size();
    ap_init_scoreboard(sb_mem);

    /* Gain access to the accpet mutex */
    rc = DosOpenMutexSem(NULL, &ap_mpm_accept_mutex);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "accept mutex couldn't be accessed in child, exiting");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Find our pid in the scoreboard so we know what slot our parent allocated us */
    for (child_slot = 0; ap_scoreboard_image->parent[child_slot].pid != my_pid && child_slot < HARD_SERVER_LIMIT; child_slot++);

    if (child_slot == HARD_SERVER_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "child pid not found in scoreboard, exiting");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_my_generation = ap_scoreboard_image->parent[child_slot].generation;
    memset(ap_scoreboard_image->servers[child_slot], 0, sizeof(worker_score) * HARD_THREAD_LIMIT);

    /* Set up an OS/2 queue for passing connections & termination requests
     * to worker threads
     */
    rc = DosCreateQueue(&workq, QUE_FIFO, apr_psprintf(pchild, "/queues/httpd/work.%d", my_pid));

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "unable to create work queue, exiting");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Create initial pool of worker threads */
    for (c = 0; c < ap_min_spare_threads; c++) {
//        ap_scoreboard_image->servers[child_slot][c].tid = _beginthread(worker_main, NULL, 128*1024, (void *)c);
    }

    /* Start maintenance thread */
    server_maint_tid = _beginthread(server_maintenance, NULL, 32768, NULL);

    /* Set up poll */
    for (num_listeners = 0, lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }

    apr_pollset_create(&pollset, num_listeners, pchild, 0);

    for (lr = ap_listeners; lr != NULL; lr = lr->next) {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = lr->sd;
        pfd.reqevents = APR_POLLIN;
        pfd.client_data = lr;
        apr_pollset_add(pollset, &pfd);
    }

    /* Main connection accept loop */
    do {
        apr_pool_t *pconn;
        worker_args_t *worker_args;
        int last_poll_idx = 0;

        apr_pool_create(&pconn, pchild);
        worker_args = apr_palloc(pconn, sizeof(worker_args_t));
        worker_args->pconn = pconn;

        if (num_listeners == 1) {
            rv = apr_socket_accept(&worker_args->conn_sd, ap_listeners->sd, pconn);
        } else {
            const apr_pollfd_t *poll_results;
            apr_int32_t num_poll_results;

            rc = DosRequestMutexSem(ap_mpm_accept_mutex, SEM_INDEFINITE_WAIT);

            if (shutdown_pending) {
                DosReleaseMutexSem(ap_mpm_accept_mutex);
                break;
            }

            rv = APR_FROM_OS_ERROR(rc);

            if (rv == APR_SUCCESS) {
                rv = apr_pollset_poll(pollset, -1, &num_poll_results, &poll_results);
                DosReleaseMutexSem(ap_mpm_accept_mutex);
            }

            if (rv == APR_SUCCESS) {
                if (last_poll_idx >= num_listeners) {
                    last_poll_idx = 0;
                }

                lr = poll_results[last_poll_idx++].client_data;
                rv = apr_socket_accept(&worker_args->conn_sd, lr->sd, pconn);
                last_poll_idx++;
            }
        }

        if (rv != APR_SUCCESS) {
            if (!APR_STATUS_IS_EINTR(rv)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                             "apr_socket_accept");
                clean_child_exit(APEXIT_CHILDFATAL);
            }
        } else {
            DosWriteQueue(workq, WORKTYPE_CONN, sizeof(worker_args_t), worker_args, 0);
            requests_this_child++;
        }

        if (ap_max_requests_per_child != 0 && requests_this_child >= ap_max_requests_per_child)
            break;
    } while (!shutdown_pending && ap_my_generation == ap_scoreboard_image->global->running_generation);

    ap_scoreboard_image->parent[child_slot].quiescing = 1;
    DosPostEventSem(shutdown_event);
    DosWaitThread(&server_maint_tid, DCWW_WAIT);

    if (is_graceful) {
        char someleft;

        /* tell our worker threads to exit */
        for (c=0; c<HARD_THREAD_LIMIT; c++) {
            if (ap_scoreboard_image->servers[child_slot][c].status != SERVER_DEAD) {
                DosWriteQueue(workq, WORKTYPE_EXIT, 0, NULL, 0);
            }
        }

        do {
            someleft = 0;

            for (c=0; c<HARD_THREAD_LIMIT; c++) {
                if (ap_scoreboard_image->servers[child_slot][c].status != SERVER_DEAD) {
                    someleft = 1;
                    DosSleep(1000);
                    break;
                }
            }
        } while (someleft);
    } else {
        DosPurgeQueue(workq);

        for (c=0; c<HARD_THREAD_LIMIT; c++) {
            if (ap_scoreboard_image->servers[child_slot][c].status != SERVER_DEAD) {
                DosKillThread(ap_scoreboard_image->servers[child_slot][c].tid);
            }
        }
    }

    apr_pool_destroy(pchild);
}



void add_worker()
{
    int thread_slot;

    /* Find a free thread slot */
    for (thread_slot=0; thread_slot < HARD_THREAD_LIMIT; thread_slot++) {
        if (ap_scoreboard_image->servers[child_slot][thread_slot].status == SERVER_DEAD) {
            ap_scoreboard_image->servers[child_slot][thread_slot].status = SERVER_STARTING;
            ap_scoreboard_image->servers[child_slot][thread_slot].tid =
                _beginthread(worker_main, NULL, 128*1024, (void *)thread_slot);
            break;
        }
    }
}



ULONG APIENTRY thread_exception_handler(EXCEPTIONREPORTRECORD *pReportRec,
                                        EXCEPTIONREGISTRATIONRECORD *pRegRec,
                                        CONTEXTRECORD *pContext,
                                        PVOID p)
{
    int c;

    if (pReportRec->fHandlerFlags & EH_NESTED_CALL) {
        return XCPT_CONTINUE_SEARCH;
    }

    if (pReportRec->ExceptionNum == XCPT_ACCESS_VIOLATION ||
        pReportRec->ExceptionNum == XCPT_INTEGER_DIVIDE_BY_ZERO) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "caught exception in worker thread, initiating child shutdown pid=%d", getpid());
        for (c=0; c<HARD_THREAD_LIMIT; c++) {
            if (ap_scoreboard_image->servers[child_slot][c].tid == _gettid()) {
                ap_scoreboard_image->servers[child_slot][c].status = SERVER_DEAD;
                break;
            }
        }

        /* Shut down process ASAP, it could be quite unhealthy & leaking resources */
        shutdown_pending = 1;
        ap_scoreboard_image->parent[child_slot].quiescing = 1;
        kill(getpid(), SIGHUP);
        DosUnwindException(UNWIND_ALL, 0, 0);
    }

    return XCPT_CONTINUE_SEARCH;
}



static void worker_main(void *vpArg)
{
    long conn_id;
    conn_rec *current_conn;
    apr_pool_t *pconn;
    apr_allocator_t *allocator;
    apr_bucket_alloc_t *bucket_alloc;
    worker_args_t *worker_args;
    HQUEUE workq;
    PID owner;
    int rc;
    REQUESTDATA rd;
    ULONG len;
    BYTE priority;
    int thread_slot = (int)vpArg;
    EXCEPTIONREGISTRATIONRECORD reg_rec = { NULL, thread_exception_handler };
    ap_sb_handle_t *sbh;

    /* Trap exceptions in this thread so we don't take down the whole process */
    DosSetExceptionHandler( &reg_rec );

    rc = DosOpenQueue(&owner, &workq,
                      apr_psprintf(pchild, "/queues/httpd/work.%d", getpid()));

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "unable to open work queue, exiting");
        ap_scoreboard_image->servers[child_slot][thread_slot].tid = 0;
    }

    conn_id = ID_FROM_CHILD_THREAD(child_slot, thread_slot);
    ap_update_child_status_from_indexes(child_slot, thread_slot, SERVER_READY,
                                        NULL);

    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    bucket_alloc = apr_bucket_alloc_create_ex(allocator);

    while (rc = DosReadQueue(workq, &rd, &len, (PPVOID)&worker_args, 0, DCWW_WAIT, &priority, NULLHANDLE),
           rc == 0 && rd.ulData != WORKTYPE_EXIT) {
        pconn = worker_args->pconn;
        ap_create_sb_handle(&sbh, pconn, child_slot, thread_slot);
        current_conn = ap_run_create_connection(pconn, ap_server_conf,
                                                worker_args->conn_sd, conn_id,
                                                sbh, bucket_alloc);

        if (current_conn) {
            ap_process_connection(current_conn, worker_args->conn_sd);
            ap_lingering_close(current_conn);
        }

        apr_pool_destroy(pconn);
        ap_update_child_status_from_indexes(child_slot, thread_slot,
                                            SERVER_READY, NULL);
    }

    ap_update_child_status_from_indexes(child_slot, thread_slot, SERVER_DEAD,
                                        NULL);

    apr_bucket_alloc_destroy(bucket_alloc);
    apr_allocator_destroy(allocator);
}



static void server_maintenance(void *vpArg)
{
    int num_idle, num_needed;
    ULONG num_pending = 0;
    int threadnum;
    HQUEUE workq;
    ULONG rc;
    PID owner;

    rc = DosOpenQueue(&owner, &workq,
                      apr_psprintf(pchild, "/queues/httpd/work.%d", getpid()));

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "unable to open work queue in maintenance thread");
        return;
    }

    do {
        for (num_idle=0, threadnum=0; threadnum < HARD_THREAD_LIMIT; threadnum++) {
            num_idle += ap_scoreboard_image->servers[child_slot][threadnum].status == SERVER_READY;
        }

        DosQueryQueue(workq, &num_pending);
        num_needed = ap_min_spare_threads - num_idle + num_pending;

        if (num_needed > 0) {
            for (threadnum=0; threadnum < num_needed; threadnum++) {
                add_worker();
            }
        }

        if (num_idle - num_pending > ap_max_spare_threads) {
            DosWriteQueue(workq, WORKTYPE_EXIT, 0, NULL, 0);
        }
    } while (DosWaitEventSem(shutdown_event, 500) == ERROR_TIMEOUT);
}



/* Signal handling routines */

static void sig_term(int sig)
{
    shutdown_pending = 1;
    is_graceful = 0;
    signal(SIGTERM, SIG_DFL);
}



static void sig_hup(int sig)
{
    shutdown_pending = 1;
    is_graceful = 1;
}



static void set_signals()
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sig_term;

    if (sigaction(SIGTERM, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGTERM)");

    sa.sa_handler = sig_hup;

    if (sigaction(SIGHUP, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
}
