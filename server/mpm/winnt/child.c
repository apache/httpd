/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

#ifdef WIN32

#define CORE_PRIVATE 
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "apr_portable.h"
#include "apr_thread_proc.h"
#include "apr_getopt.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_shm.h"
#include "apr_thread_mutex.h"
#include "ap_mpm.h"
#include "ap_config.h"
#include "ap_listen.h"
#include "mpm_default.h"
#include "mpm_winnt.h"
#include "mpm_common.h"
#include <malloc.h>
#include "apr_atomic.h"

/* shared with mpm_winnt.c */
extern DWORD my_pid;

/* used by parent to signal the child to start and exit */
/* shared with mpm_winnt.c, but should be private to child.c */
apr_proc_mutex_t *start_mutex;
HANDLE exit_event;

/* child_main() should never need to modify is_graceful!?! */
extern int volatile is_graceful;

/* Queue for managing the passing of COMP_CONTEXTs between
 * the accept and worker threads.
 */
static apr_pool_t *pchild;
static int shutdown_in_progress = 0;
static int workers_may_exit = 0;
static unsigned int g_blocked_threads = 0;
static HANDLE max_requests_per_child_event;


static apr_thread_mutex_t  *qlock;
static PCOMP_CONTEXT qhead = NULL;
static PCOMP_CONTEXT qtail = NULL;
static int num_completion_contexts = 0;
static HANDLE ThreadDispatchIOCP = NULL;
static HANDLE qwait_event = NULL;


AP_DECLARE(void) mpm_recycle_completion_context(PCOMP_CONTEXT context)
{
    /* Recycle the completion context.
     * - clear the ptrans pool
     * - put the context on the queue to be consumed by the accept thread
     * Note: 
     * context->accept_socket may be in a disconnected but reusable 
     * state so -don't- close it.
     */
    if (context) {
        apr_pool_clear(context->ptrans);
        context->next = NULL;
        ResetEvent(context->Overlapped.hEvent);
        apr_thread_mutex_lock(qlock);
        if (qtail) {
            qtail->next = context;
        } else {
            qhead = context;
            SetEvent(qwait_event);
        }
        qtail = context;
        apr_thread_mutex_unlock(qlock);
    }
}

AP_DECLARE(PCOMP_CONTEXT) mpm_get_completion_context(void)
{
    apr_status_t rv;
    PCOMP_CONTEXT context = NULL;

    while (1) {
        /* Grab a context off the queue */
        apr_thread_mutex_lock(qlock);
        if (qhead) {
            context = qhead;
            qhead = qhead->next;
            if (!qhead)
                qtail = NULL;
        } else {
            ResetEvent(qwait_event);
        }
        apr_thread_mutex_unlock(qlock);
  
        if (!context) {
            /* We failed to grab a context off the queue, consider allocating a
             * new one out of the child pool. There may be up to ap_threads_per_child
             * contexts in the system at once.
             */
            if (num_completion_contexts >= ap_threads_per_child) {
                /* All workers are busy, need to wait for one */
                static int reported = 0;
                if (!reported) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                                 "Server ran out of threads to serve requests. Consider "
                                 "raising the ThreadsPerChild setting");
                    reported = 1;
                }

                /* Wait for a worker to free a context. Once per second, give
                 * the caller a chance to check for shutdown. If the wait
                 * succeeds, get the context off the queue. It must be available,
                 * since there's only one consumer.
                 */
                rv = WaitForSingleObject(qwait_event, 1000);
                if (rv == WAIT_OBJECT_0)
                    continue;
                else /* Hopefully, WAIT_TIMEOUT */
                    return NULL;
            } else {
                /* Allocate another context.
                 * Note:
                 * Multiple failures in the next two steps will cause the pchild pool
                 * to 'leak' storage. I don't think this is worth fixing...
                 */
                apr_allocator_t *allocator;

                context = (PCOMP_CONTEXT) apr_pcalloc(pchild, sizeof(COMP_CONTEXT));
  
                context->Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                if (context->Overlapped.hEvent == NULL) {
                    /* Hopefully this is a temporary condition ... */
                    ap_log_error(APLOG_MARK,APLOG_WARNING, apr_get_os_error(), ap_server_conf,
                                 "mpm_get_completion_context: CreateEvent failed.");
                    return NULL;
                }
 
                /* Create the tranaction pool */
                apr_allocator_create(&allocator);
                apr_allocator_max_free_set(allocator, ap_max_mem_free);
                rv = apr_pool_create_ex(&context->ptrans, pchild, NULL, allocator);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK,APLOG_WARNING, rv, ap_server_conf,
                                 "mpm_get_completion_context: Failed to create the transaction pool.");
                    CloseHandle(context->Overlapped.hEvent);
                    return NULL;
                }
                apr_allocator_owner_set(allocator, context->ptrans);
                apr_pool_tag(context->ptrans, "transaction");
 
                context->accept_socket = INVALID_SOCKET;
                context->ba = apr_bucket_alloc_create(pchild);
                apr_atomic_inc32(&num_completion_contexts); 
                break;
            }
        } else {
            /* Got a context from the queue */
            break;
        }
    }

    return context;
}

AP_DECLARE(apr_status_t) mpm_post_completion_context(PCOMP_CONTEXT context, 
                                                     io_state_e state)
{
    LPOVERLAPPED pOverlapped;
    if (context)
        pOverlapped = &context->Overlapped;
    else
        pOverlapped = NULL;

    PostQueuedCompletionStatus(ThreadDispatchIOCP, 0, state, pOverlapped);
    return APR_SUCCESS;
}


/*
 * find_ready_listener()
 * Only used by Win9* and should go away when the win9*_accept() function is 
 * reimplemented using apr_poll().
 */
static ap_listen_rec *head_listener;

static APR_INLINE ap_listen_rec *find_ready_listener(fd_set * main_fds)
{
    ap_listen_rec *lr;
    SOCKET nsd;

    for (lr = head_listener; lr ; lr = lr->next) {
        apr_os_sock_get(&nsd, lr->sd);
	if (FD_ISSET(nsd, main_fds)) {
	    head_listener = lr->next;
            if (head_listener == NULL)
                head_listener = ap_listeners;

	    return (lr);
	}
    }
    return NULL;
}


/* Windows 9x specific code...
 * Accept processing for on Windows 95/98 uses a producer/consumer queue 
 * model. A single thread accepts connections and queues the accepted socket 
 * to the accept queue for consumption by a pool of worker threads.
 *
 * win9x_accept()
 *    The accept threads runs this function, which accepts connections off 
 *    the network and calls add_job() to queue jobs to the accept_queue.
 * add_job()/remove_job()
 *    Add or remove an accepted socket from the list of sockets 
 *    connected to clients. allowed_globals.jobmutex protects
 *    against multiple concurrent access to the linked list of jobs.
 * win9x_get_connection()
 *    Calls remove_job() to pull a job from the accept queue. All the worker 
 *    threads block on remove_job.
 */

typedef struct joblist_s {
    struct joblist_s *next;
    int sock;
} joblist;

typedef struct globals_s {
    HANDLE jobsemaphore;
    joblist *jobhead;
    joblist *jobtail;
    apr_thread_mutex_t *jobmutex;
    int jobcount;
} globals;

globals allowed_globals = {NULL, NULL, NULL, NULL, 0};

#define MAX_SELECT_ERRORS 100


static void add_job(int sock)
{
    joblist *new_job;

    new_job = (joblist *) malloc(sizeof(joblist));
    if (new_job == NULL) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "Ouch!  Out of memory in add_job()!");
        return;
    }
    new_job->next = NULL;
    new_job->sock = sock;

    apr_thread_mutex_lock(allowed_globals.jobmutex);

    if (allowed_globals.jobtail != NULL)
	allowed_globals.jobtail->next = new_job;
    allowed_globals.jobtail = new_job;
    if (!allowed_globals.jobhead)
	allowed_globals.jobhead = new_job;
    allowed_globals.jobcount++;
    ReleaseSemaphore(allowed_globals.jobsemaphore, 1, NULL);

    apr_thread_mutex_unlock(allowed_globals.jobmutex);
}


static int remove_job(void)
{
    joblist *job;
    int sock;

    WaitForSingleObject(allowed_globals.jobsemaphore, INFINITE);
    apr_thread_mutex_lock(allowed_globals.jobmutex);

    if (shutdown_in_progress && !allowed_globals.jobhead) {
        apr_thread_mutex_unlock(allowed_globals.jobmutex);
	return (INVALID_SOCKET);
    }
    job = allowed_globals.jobhead;
    ap_assert(job);
    allowed_globals.jobhead = job->next;
    if (allowed_globals.jobhead == NULL)
	allowed_globals.jobtail = NULL;
    apr_thread_mutex_unlock(allowed_globals.jobmutex);
    sock = job->sock;
    free(job);

    return (sock);
}


static void win9x_accept(void * dummy)
{
    struct timeval tv;
    fd_set main_fds;
    int wait_time = 1;
    int csd;
    SOCKET nsd = INVALID_SOCKET;
    struct sockaddr_in sa_client;
    int count_select_errors = 0;
    int rc;
    int clen;
    ap_listen_rec *lr;
    struct fd_set listenfds;
    SOCKET listenmaxfd = INVALID_SOCKET;

    /* Setup the listeners 
     * ToDo: Use apr_poll()
     */
    FD_ZERO(&listenfds);
    for (lr = ap_listeners; lr; lr = lr->next) {
        if (lr->sd != NULL) {
            apr_os_sock_get(&nsd, lr->sd);
            FD_SET(nsd, &listenfds);
            if (listenmaxfd == INVALID_SOCKET || nsd > listenmaxfd) {
                listenmaxfd = nsd;
            }
        }
    }

    head_listener = ap_listeners;

    while (!shutdown_in_progress) {
	tv.tv_sec = wait_time;
	tv.tv_usec = 0;
	memcpy(&main_fds, &listenfds, sizeof(fd_set));

	rc = select(listenmaxfd + 1, &main_fds, NULL, NULL, &tv);

        if (rc == 0 || (rc == SOCKET_ERROR && APR_STATUS_IS_EINTR(apr_get_netos_error()))) {
            count_select_errors = 0;    /* reset count of errors */            
            continue;
        }
        else if (rc == SOCKET_ERROR) {
            /* A "real" error occurred, log it and increment the count of
             * select errors. This count is used to ensure we don't go into
             * a busy loop of continuous errors.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, apr_get_netos_error(), ap_server_conf, 
                         "select failed with error %d", apr_get_netos_error());
            count_select_errors++;
            if (count_select_errors > MAX_SELECT_ERRORS) {
                shutdown_in_progress = 1;
                ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_netos_error(), ap_server_conf,
                             "Too many errors in select loop. Child process exiting.");
                break;
            }
	} else {
	    ap_listen_rec *lr;

	    lr = find_ready_listener(&main_fds);
	    if (lr != NULL) {
                /* fetch the native socket descriptor */
                apr_os_sock_get(&nsd, lr->sd);
	    }
	}

	do {
            clen = sizeof(sa_client);
            csd = accept(nsd, (struct sockaddr *) &sa_client, &clen);
        } while (csd < 0 && APR_STATUS_IS_EINTR(apr_get_netos_error()));

	if (csd < 0) {
            if (APR_STATUS_IS_ECONNABORTED(apr_get_netos_error())) {
		ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_netos_error(), ap_server_conf,
			    "accept: (client socket)");
            }
	}
	else {
	    add_job(csd);
	}
    }
    SetEvent(exit_event);
}


static PCOMP_CONTEXT win9x_get_connection(PCOMP_CONTEXT context)
{
    apr_os_sock_info_t sockinfo;
    int len;

    if (context == NULL) {
        /* allocate the completion context and the transaction pool */
        apr_allocator_t *allocator;
        context = apr_pcalloc(pchild, sizeof(COMP_CONTEXT));
        apr_allocator_create(&allocator);
        apr_allocator_max_free_set(allocator, ap_max_mem_free);
        apr_pool_create_ex(&context->ptrans, pchild, NULL, allocator);
        apr_allocator_owner_set(allocator, context->ptrans);
        apr_pool_tag(context->ptrans, "transaction");
        context->ba = apr_bucket_alloc_create(pchild);
    }
    
    while (1) {
        apr_pool_clear(context->ptrans);        
        context->accept_socket = remove_job();
        if (context->accept_socket == INVALID_SOCKET) {
            return NULL;
        }
	len = sizeof(struct sockaddr);
        context->sa_server = apr_palloc(context->ptrans, len);
        if (getsockname(context->accept_socket, 
                        context->sa_server, &len)== SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_netos_error(), ap_server_conf, 
                         "getsockname failed");
            continue;
        }
        len = sizeof(struct sockaddr);
        context->sa_client = apr_palloc(context->ptrans, len);
        if ((getpeername(context->accept_socket,
                         context->sa_client, &len)) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_netos_error(), ap_server_conf, 
                         "getpeername failed");
            memset(&context->sa_client, '\0', sizeof(context->sa_client));
        }
        sockinfo.os_sock = &context->accept_socket;
        sockinfo.local   = context->sa_server;
        sockinfo.remote  = context->sa_client;
        sockinfo.family  = APR_INET;
        sockinfo.type    = SOCK_STREAM;
        apr_os_sock_make(&context->sock, &sockinfo, context->ptrans);

        return context;
    }
}


/* Windows NT/2000 specific code...
 * Accept processing for on Windows NT uses a producer/consumer queue 
 * model. An accept thread accepts connections off the network then issues
 * PostQueuedCompletionStatus() to awake a thread blocked on the ThreadDispatch 
 * IOCompletionPort.
 *
 * winnt_accept()
 *    One or more accept threads run in this function, each of which accepts 
 *    connections off the network and calls PostQueuedCompletionStatus() to
 *    queue an io completion packet to the ThreadDispatch IOCompletionPort.
 * winnt_get_connection()
 *    Worker threads block on the ThreadDispatch IOCompletionPort awaiting 
 *    connections to service.
 */
static void winnt_accept(void *lr_) 
{
    ap_listen_rec *lr = (ap_listen_rec *)lr_;
    apr_os_sock_info_t sockinfo;
    PCOMP_CONTEXT context = NULL;
    DWORD BytesRead;
    SOCKET nlsd;
    int rv, err_count = 0;

    apr_os_sock_get(&nlsd, lr->sd);

    while (!shutdown_in_progress) {
        if (!context) {
            context = mpm_get_completion_context();
            if (!context) {
                /* Temporary resource constraint? */
                Sleep(0);
                continue;
            }
        }

        /* Create and initialize the accept socket */
        if (context->accept_socket == INVALID_SOCKET) {
            context->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (context->accept_socket == INVALID_SOCKET) {
                /* Another temporary condition? */
                ap_log_error(APLOG_MARK,APLOG_WARNING, apr_get_netos_error(), ap_server_conf,
                             "winnt_accept: Failed to allocate an accept socket. "
                             "Temporary resource constraint? Try again.");
                Sleep(100);
                continue;
            }
        }

        /* AcceptEx on the completion context. The completion context will be 
         * signaled when a connection is accepted. 
         */
        if (!AcceptEx(nlsd, context->accept_socket,
                      context->buff,
                      0,
                      PADDED_ADDR_SIZE, 
                      PADDED_ADDR_SIZE,
                      &BytesRead,
                      &context->Overlapped)) {
            rv = apr_get_netos_error();
            if ((rv == APR_FROM_OS_ERROR(WSAEINVAL)) ||
                (rv == APR_FROM_OS_ERROR(WSAENOTSOCK))) {
                /* Hack alert, we can get here because: 
                 * 1) Occasionally, TransmitFile will not recycle the accept socket 
                 *    (usually when the client disconnects early). 
                 * 2) There is VPN or Firewall software installed with buggy AcceptEx implementation
                 * 3) The webserver is using a dynamic address and it has changed
                 */
                Sleep(0);
                if (++err_count > 1000) { 
                    apr_int32_t disconnected;

                    /* abitrary socket call to test if the Listening socket is still valid */
                    apr_status_t listen_rv =  apr_socket_opt_get(lr->sd, APR_SO_DISCONNECTED, &disconnected);

                    if (listen_rv == APR_SUCCESS) {
                        ap_log_error(APLOG_MARK,APLOG_ERR, listen_rv, ap_server_conf,
                                     "AcceptEx error: If this occurs constantly and NO requests are being served "
                                     "try using the WindowsSocketsWorkaround directive set to 'on'.");
                        err_count = 0;
                    }
                    else {
                        ap_log_error(APLOG_MARK,APLOG_ERR, listen_rv, ap_server_conf,
                                     "The Listening socket is no longer valid. Dynamic address changed?");
                        break;
                    }
                }

                closesocket(context->accept_socket);
                context->accept_socket = INVALID_SOCKET;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf,
                       "winnt_accept: AcceptEx failed, either early client disconnect, "
                       "dynamic address renewal, or incompatible VPN or Firewall software.");
          
                continue;
            }
            else if ((rv != APR_FROM_OS_ERROR(ERROR_IO_PENDING)) &&
                     (rv != APR_FROM_OS_ERROR(WSA_IO_PENDING))) {
                ap_log_error(APLOG_MARK,APLOG_ERR, rv, ap_server_conf,
                             "winnt_accept: AcceptEx failed. Attempting to recover.");
                closesocket(context->accept_socket);
                context->accept_socket = INVALID_SOCKET;
                Sleep(100);
                continue;
            }
            err_count = 0;  

            /* Wait for pending i/o. 
             * Wake up once per second to check for shutdown .
             * XXX: We should be waiting on exit_event instead of polling
             */
            while (1) {
                rv = WaitForSingleObject(context->Overlapped.hEvent, 1000);
                if (rv == WAIT_OBJECT_0) {
                    if (context->accept_socket == INVALID_SOCKET) {
                        /* socket already closed */
                        break;
                    }
                    if (!GetOverlappedResult((HANDLE)context->accept_socket, 
                                             &context->Overlapped, 
                                             &BytesRead, FALSE)) {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 
                                     apr_get_os_error(), ap_server_conf,
                             "winnt_accept: Asynchronous AcceptEx failed.");
                        closesocket(context->accept_socket);
                        context->accept_socket = INVALID_SOCKET;
                    }
                    break;
                }
                /* WAIT_TIMEOUT */
                if (shutdown_in_progress) {
                    closesocket(context->accept_socket);
                    context->accept_socket = INVALID_SOCKET;
                    break;
                }
            }
            if (context->accept_socket == INVALID_SOCKET) {
                continue;
            }
        }

        /* Inherit the listen socket settings. Required for 
         * shutdown() to work 
         */
        if (setsockopt(context->accept_socket, SOL_SOCKET,
                       SO_UPDATE_ACCEPT_CONTEXT, (char *)&nlsd,
                       sizeof(nlsd))) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_netos_error(), ap_server_conf,
                         "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed.");
            /* Not a failure condition. Keep running. */
        }

        /* Get the local & remote address */
        GetAcceptExSockaddrs(context->buff,
                             0,
                             PADDED_ADDR_SIZE,
                             PADDED_ADDR_SIZE,
                             &context->sa_server,
                             &context->sa_server_len,
                             &context->sa_client,
                             &context->sa_client_len);

        sockinfo.os_sock = &context->accept_socket;
        sockinfo.local   = context->sa_server;
        sockinfo.remote  = context->sa_client;
        sockinfo.family  = APR_INET;
        sockinfo.type    = SOCK_STREAM;
        apr_os_sock_make(&context->sock, &sockinfo, context->ptrans);

        /* When a connection is received, send an io completion notification to
         * the ThreadDispatchIOCP. This function could be replaced by
         * mpm_post_completion_context(), but why do an extra function call...
         */
        PostQueuedCompletionStatus(ThreadDispatchIOCP, 0, IOCP_CONNECTION_ACCEPTED,
                                   &context->Overlapped);
        context = NULL;
    }
    if (!shutdown_in_progress) {
        /* Yow, hit an irrecoverable error! Tell the child to die. */
        SetEvent(exit_event);
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, ap_server_conf,
                 "Child %d: Accept thread exiting.", my_pid);
}


static PCOMP_CONTEXT winnt_get_connection(PCOMP_CONTEXT context)
{
    int rc;
    DWORD BytesRead;
    DWORD CompKey;
    LPOVERLAPPED pol;

    mpm_recycle_completion_context(context);

    apr_atomic_inc32(&g_blocked_threads);
    while (1) {
        if (workers_may_exit) {
            apr_atomic_dec32(&g_blocked_threads);
            return NULL;
        }
        rc = GetQueuedCompletionStatus(ThreadDispatchIOCP, &BytesRead, &CompKey,
                                       &pol, INFINITE);
        if (!rc) {
            rc = apr_get_os_error();
            ap_log_error(APLOG_MARK,APLOG_DEBUG, rc, ap_server_conf,
                             "Child %d: GetQueuedComplationStatus returned %d", my_pid, rc);
            continue;
        }

        switch (CompKey) {
        case IOCP_CONNECTION_ACCEPTED:
            context = CONTAINING_RECORD(pol, COMP_CONTEXT, Overlapped);
            break;
        case IOCP_SHUTDOWN:
            apr_atomic_dec32(&g_blocked_threads);
            return NULL;
        default:
            apr_atomic_dec32(&g_blocked_threads);
            return NULL;
        }
        break;
    }
    apr_atomic_dec32(&g_blocked_threads);

    return context;
}


/*
 * worker_main()
 * Main entry point for the worker threads. Worker threads block in 
 * win*_get_connection() awaiting a connection to service.
 */
static void worker_main(long thread_num)
{
    static int requests_this_child = 0;
    PCOMP_CONTEXT context = NULL;
    ap_sb_handle_t *sbh;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ap_server_conf,
                 "Child %d: Worker thread %d starting.", my_pid, thread_num);
    while (1) {
        conn_rec *c;
        apr_int32_t disconnected;

        ap_update_child_status_from_indexes(0, thread_num, SERVER_READY, NULL);

        /* Grab a connection off the network */
        if (use_acceptex) {
            context = winnt_get_connection(context);
        }
        else {
            context = win9x_get_connection(context);
        }
        
        if (!context) {
            /* Time for the thread to exit */
            break;
        }

        /* Have we hit MaxRequestPerChild connections? */
        if (ap_max_requests_per_child) {
            requests_this_child++;
            if (requests_this_child > ap_max_requests_per_child) {
                SetEvent(max_requests_per_child_event);
            }
        }

        ap_create_sb_handle(&sbh, context->ptrans, 0, thread_num);
        c = ap_run_create_connection(context->ptrans, ap_server_conf,
                                     context->sock, thread_num, sbh,
                                     context->ba);

        if (c) {
            ap_process_connection(c, context->sock);
            apr_socket_opt_get(context->sock, APR_SO_DISCONNECTED, 
                               &disconnected);
            if (!disconnected) {
                context->accept_socket = INVALID_SOCKET;
                ap_lingering_close(c);
            }
            else if (!use_acceptex) {
                /* If the socket is disconnected but we are not using acceptex, 
                 * we cannot reuse the socket. Disconnected sockets are removed
                 * from the apr_socket_t struct by apr_sendfile() to prevent the
                 * socket descriptor from being inadvertently closed by a call 
                 * to apr_socket_close(), so close it directly.
                 */
                closesocket(context->accept_socket);
                context->accept_socket = INVALID_SOCKET;
            }
        }
        else {
            /* ap_run_create_connection closes the socket on failure */
            context->accept_socket = INVALID_SOCKET;
        }
    }

    ap_update_child_status_from_indexes(0, thread_num, SERVER_DEAD, 
                                        (request_rec *) NULL);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ap_server_conf,
                 "Child %d: Worker thread %d exiting.", my_pid, thread_num);
}


static void cleanup_thread(HANDLE *handles, int *thread_cnt, int thread_to_clean)
{
    int i;

    CloseHandle(handles[thread_to_clean]);
    for (i = thread_to_clean; i < ((*thread_cnt) - 1); i++)
	handles[i] = handles[i + 1];
    (*thread_cnt)--;
}


/*
 * child_main() 
 * Entry point for the main control thread for the child process. 
 * This thread creates the accept thread, worker threads and
 * monitors the child process for maintenance and shutdown
 * events.
 */
static void create_listener_thread()
{
    int tid;
    if (!use_acceptex) {
        _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE) win9x_accept,
                       NULL, 0, &tid);
    } else {
        /* Start an accept thread per listener 
         * XXX: Why would we have a NULL sd in our listeners?
         */
        ap_listen_rec *lr;
        for (lr = ap_listeners; lr; lr = lr->next) {
            if (lr->sd != NULL) {
                _beginthreadex(NULL, 1000, (LPTHREAD_START_ROUTINE) winnt_accept,
                               (void *) lr, 0, &tid);
            }
        }
    }
}


void child_main(apr_pool_t *pconf)
{
    apr_status_t status;
    apr_hash_t *ht;
    ap_listen_rec *lr;
    HANDLE child_events[2];
    int threads_created = 0;
    int listener_started = 0;
    int tid;
    HANDLE *child_handles;
    int rv;
    time_t end_time;
    int i;
    int cld;

    apr_pool_create(&pchild, pconf);
    apr_pool_tag(pchild, "pchild");

    ap_run_child_init(pchild, ap_server_conf);
    ht = apr_hash_make(pchild);

    /* Initialize the child_events */
    max_requests_per_child_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!max_requests_per_child_event) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Child %d: Failed to create a max_requests event.", my_pid);
        exit(APEXIT_CHILDINIT);
    }
    child_events[0] = exit_event;
    child_events[1] = max_requests_per_child_event;

    allowed_globals.jobsemaphore = CreateSemaphore(NULL, 0, 1000000, NULL);
    apr_thread_mutex_create(&allowed_globals.jobmutex, 
                            APR_THREAD_MUTEX_DEFAULT, pchild);

    /*
     * Wait until we have permission to start accepting connections.
     * start_mutex is used to ensure that only one child ever
     * goes into the listen/accept loop at once.
     */
    status = apr_proc_mutex_lock(start_mutex);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK,APLOG_ERR, status, ap_server_conf,
                     "Child %d: Failed to acquire the start_mutex. Process will exit.", my_pid);
        exit(APEXIT_CHILDINIT);
    }
    ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf, 
                 "Child %d: Acquired the start mutex.", my_pid);

    /*
     * Create the worker thread dispatch IOCompletionPort
     * on Windows NT/2000
     */
    if (use_acceptex) {
        /* Create the worker thread dispatch IOCP */
        ThreadDispatchIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                                    NULL,
                                                    0,
                                                    0); /* CONCURRENT ACTIVE THREADS */
        apr_thread_mutex_create(&qlock, APR_THREAD_MUTEX_DEFAULT, pchild);
        qwait_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!qwait_event) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                         "Child %d: Failed to create a qwait event.", my_pid);
            exit(APEXIT_CHILDINIT);
        }
    }

    /* 
     * Create the pool of worker threads
     */
    ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf, 
                 "Child %d: Starting %d worker threads.", my_pid, ap_threads_per_child);
    child_handles = (HANDLE) apr_pcalloc(pchild, ap_threads_per_child * sizeof(int));
    while (1) {
        for (i = 0; i < ap_threads_per_child; i++) {
            int *score_idx;
            int status = ap_scoreboard_image->servers[0][i].status;
            if (status != SERVER_GRACEFUL && status != SERVER_DEAD) {
                continue;
            }
            ap_update_child_status_from_indexes(0, i, SERVER_STARTING, NULL);
            child_handles[i] = (HANDLE) _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE) worker_main,
                                                       (void *) i, 0, &tid);
            if (child_handles[i] == 0) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                             "Child %d: _beginthreadex failed. Unable to create all worker threads. "
                             "Created %d of the %d threads requested with the ThreadsPerChild configuration directive.", 
                             my_pid, threads_created, ap_threads_per_child);
                ap_signal_parent(SIGNAL_PARENT_SHUTDOWN);
                goto shutdown;
            }
            threads_created++;
            /* Save the score board index in ht keyed to the thread handle. We need this 
             * when cleaning up threads down below...
             */
            score_idx = apr_pcalloc(pchild, sizeof(int));
            *score_idx = i;
            apr_hash_set(ht, &child_handles[i], sizeof(HANDLE), score_idx);
        }
        /* Start the listener only when workers are available */
        if (!listener_started && threads_created) {
            create_listener_thread();
            listener_started = 1;
            winnt_mpm_state = AP_MPMQ_RUNNING;
        }
        if (threads_created == ap_threads_per_child) {
            break;
        }
        /* Check to see if the child has been told to exit */
        if (WaitForSingleObject(exit_event, 0) != WAIT_TIMEOUT) {
            break;
        }
        /* wait for previous generation to clean up an entry in the scoreboard */
        apr_sleep(1 * APR_USEC_PER_SEC);
    }

    /* Wait for one of three events:
     * exit_event: 
     *    The exit_event is signaled by the parent process to notify 
     *    the child that it is time to exit.
     *
     * max_requests_per_child_event: 
     *    This event is signaled by the worker threads to indicate that
     *    the process has handled MaxRequestsPerChild connections.
     *
     * TIMEOUT:
     *    To do periodic maintenance on the server (check for thread exits,
     *    number of completion contexts, etc.)
     *
     * XXX: thread exits *aren't* being checked.
     *
     * XXX: other_child - we need the process handles to the other children
     *      in order to map them to apr_proc_other_child_read (which is not
     *      named well, it's more like a_p_o_c_died.)
     *
     * XXX: however - if we get a_p_o_c handle inheritance working, and
     *      the parent process creates other children and passes the pipes 
     *      to our worker processes, then we have no business doing such 
     *      things in the child_main loop, but should happen in master_main.
     */
    while (1) {
#if !APR_HAS_OTHER_CHILD
        rv = WaitForMultipleObjects(2, (HANDLE *) child_events, FALSE, INFINITE);
        cld = rv - WAIT_OBJECT_0;
#else
        rv = WaitForMultipleObjects(2, (HANDLE *) child_events, FALSE, 1000);
        cld = rv - WAIT_OBJECT_0;
        if (rv == WAIT_TIMEOUT) {
            apr_proc_other_child_refresh_all(APR_OC_REASON_RUNNING);
        }
        else 
#endif
            if (rv == WAIT_FAILED) {
            /* Something serious is wrong */
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                         "Child %d: WAIT_FAILED -- shutting down server", my_pid);
            break;
        }
        else if (cld == 0) {
            /* Exit event was signaled */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                         "Child %d: Exit event signaled. Child process is ending.", my_pid);
            break;
        }
        else {
            /* MaxRequestsPerChild event set by the worker threads.
             * Signal the parent to restart
             */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                         "Child %d: Process exiting because it reached "
                         "MaxRequestsPerChild. Signaling the parent to "
                         "restart a new child process.", my_pid);
            ap_signal_parent(SIGNAL_PARENT_RESTART);
            break;
        }
    }

    /* 
     * Time to shutdown the child process 
     */

 shutdown:

    winnt_mpm_state = AP_MPMQ_STOPPING;
    /* Setting is_graceful will cause threads handling keep-alive connections 
     * to close the connection after handling the current request.
     */
    is_graceful = 1;

    /* Close the listening sockets. Note, we must close the listeners
     * before closing any accept sockets pending in AcceptEx to prevent
     * memory leaks in the kernel.
     */
    for (lr = ap_listeners; lr ; lr = lr->next) {
        apr_socket_close(lr->sd);
    }

    /* Shutdown listener threads and pending AcceptEx socksts 
     * but allow the worker threads to continue consuming from
     * the queue of accepted connections.
     */
    shutdown_in_progress = 1;

    Sleep(1000);

    /* Tell the worker threads to exit */
    workers_may_exit = 1;

    /* Release the start_mutex to let the new process (in the restart
     * scenario) a chance to begin accepting and servicing requests 
     */
    rv = apr_proc_mutex_unlock(start_mutex);
    if (rv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK,APLOG_NOTICE, rv, ap_server_conf, 
                     "Child %d: Released the start mutex", my_pid);
    }
    else {
        ap_log_error(APLOG_MARK,APLOG_ERR, rv, ap_server_conf, 
                     "Child %d: Failure releasing the start mutex", my_pid);
    }

    /* Shutdown the worker threads */
    if (!use_acceptex) {
        for (i = 0; i < threads_created; i++) {
            add_job(INVALID_SOCKET);
        }
    }
    else { /* Windows NT/2000 */
        /* Post worker threads blocked on the ThreadDispatch IOCompletion port */
        while (g_blocked_threads > 0) {
            ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, ap_server_conf, 
                         "Child %d: %d threads blocked on the completion port", my_pid, g_blocked_threads);
            for (i=g_blocked_threads; i > 0; i--) {
                PostQueuedCompletionStatus(ThreadDispatchIOCP, 0, IOCP_SHUTDOWN, NULL);
            }
            Sleep(1000);
        }
        /* Empty the accept queue of completion contexts */
        apr_thread_mutex_lock(qlock);
        while (qhead) {
            CloseHandle(qhead->Overlapped.hEvent);
            closesocket(qhead->accept_socket);
            qhead = qhead->next;
        }
        apr_thread_mutex_unlock(qlock);
    }

    /* Give busy worker threads a chance to service their connections */
    ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf, 
                 "Child %d: Waiting for %d worker threads to exit.", my_pid, threads_created);
    end_time = time(NULL) + 180;
    while (threads_created) {
        rv = wait_for_many_objects(threads_created, child_handles, end_time - time(NULL));
        if (rv != WAIT_TIMEOUT) {
            rv = rv - WAIT_OBJECT_0;
            ap_assert((rv >= 0) && (rv < threads_created));
            cleanup_thread(child_handles, &threads_created, rv);
            continue;
        }
        break;
    }

    /* Kill remaining threads off the hard way */
    if (threads_created) {
        ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf, 
                     "Child %d: Terminating %d threads that failed to exit.", my_pid);
    }
    for (i = 0; i < threads_created; i++) {
        int *score_idx;
        TerminateThread(child_handles[i], 1);
        CloseHandle(child_handles[i]);
        /* Reset the scoreboard entry for the thread we just whacked */
        score_idx = apr_hash_get(ht, &child_handles[i], sizeof(HANDLE));
        ap_update_child_status_from_indexes(0, *score_idx, SERVER_DEAD, NULL);        
    }
    ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf, 
                 "Child %d: All worker threads have exited.", my_pid);

    CloseHandle(allowed_globals.jobsemaphore);
    apr_thread_mutex_destroy(allowed_globals.jobmutex);
    if (use_acceptex) {
    	apr_thread_mutex_destroy(qlock);
        CloseHandle(qwait_event);
    }

    apr_pool_destroy(pchild);
    CloseHandle(exit_event);
}

#endif /* def WIN32 */
