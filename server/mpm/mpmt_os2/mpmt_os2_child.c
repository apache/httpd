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
 
#define CORE_PRIVATE
#define INCL_NOPMAPI
#define INCL_DOS
#define INCL_DOSERRORS

#include "ap_config.h"
#include "httpd.h"
#include "mpm_default.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"		/* for get_remote_host */
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
    ap_listen_rec *first_lr = NULL;
    int requests_this_child = 0;
    apr_socket_t *sd = ap_listeners->sd;
    int nsds, rv = 0;
    unsigned long ulTimes;
    int my_pid = getpid();
    ULONG rc, c;
    HQUEUE workq;
    apr_pollfd_t *pollset;
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

    apr_poll_setup(&pollset, num_listeners, pchild);

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_poll_socket_add(pollset, lr->sd, APR_POLLIN);
    }

    /* Main connection accept loop */
    do {
        apr_pool_t *pconn;
        worker_args_t *worker_args;

        apr_pool_create(&pconn, pchild);
        worker_args = apr_palloc(pconn, sizeof(worker_args_t));
        worker_args->pconn = pconn;

        if (num_listeners == 1) {
            rv = apr_accept(&worker_args->conn_sd, ap_listeners->sd, pconn);
        } else {
            rc = DosRequestMutexSem(ap_mpm_accept_mutex, SEM_INDEFINITE_WAIT);

            if (shutdown_pending) {
                DosReleaseMutexSem(ap_mpm_accept_mutex);
                break;
            }

            rv = APR_FROM_OS_ERROR(rc);

            if (rv == APR_SUCCESS) {
                rv = apr_poll(pollset, num_listeners, &nsds, -1);
                DosReleaseMutexSem(ap_mpm_accept_mutex);
            }

            if (rv == APR_SUCCESS) {
                if (first_lr == NULL) {
                    first_lr = ap_listeners;
                }

                lr = first_lr;

                do {
                    apr_int16_t event;

                    apr_poll_revents_get(&event, lr->sd, pollset);

                    if (event == APR_POLLIN) {
                        apr_sockaddr_t *sa;
                        apr_port_t port;
                        apr_socket_addr_get(&sa, APR_LOCAL, lr->sd);
                        apr_sockaddr_port_get(&port, sa);
                        first_lr = lr->next;
                        break;
                    }
                    lr = lr->next;

                    if (!lr) {
                        lr = ap_listeners;
                    }
                } while (lr != first_lr);

                if (lr == first_lr) {
                    continue;
                }

                sd = lr->sd;
                rv = apr_accept(&worker_args->conn_sd, sd, pconn);
            }
        }

        if (rv != APR_SUCCESS) {
            if (!APR_STATUS_IS_EINTR(rv)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                             "apr_accept");
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

    while (rc = DosReadQueue(workq, &rd, &len, (PPVOID)&worker_args, 0, DCWW_WAIT, &priority, NULLHANDLE),
           rc == 0 && rd.ulData != WORKTYPE_EXIT) {
        pconn = worker_args->pconn;
        bucket_alloc = apr_bucket_alloc_create(pconn);
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
