/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this 
 *    software must display the following acknowledgment: 
 *    "This product includes software developed by the Apache Group 
 *    for use in the Apache HTTP server project (http://www.apache.org/)." 
 * 
 * 4. The names "Apache Server" and "Apache Group" must not be used to 
 *    endorse or promote products derived from this software without 
 *    prior written permission. For written permission, please contact 
 *    apache@apache.org. 
 * 
 * 5. Products derived from this software may not be called "Apache" 
 *    nor may "Apache" appear in their names without prior written 
 *    permission of the Apache Group. 
 * 
 * 6. Redistributions of any form whatsoever must retain the following 
 *    acknowledgment: 
 *    "This product includes software developed by the Apache Group 
 *    for use in the Apache HTTP server project (http://www.apache.org/)." 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY 
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR 
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
 * OF THE POSSIBILITY OF SUCH DAMAGE. 
 * ==================================================================== 
 * 
 * This software consists of voluntary contributions made by many 
 * individuals on behalf of the Apache Group and was originally based 
 * on public domain software written at the National Center for 
 * Supercomputing Applications, University of Illinois, Urbana-Champaign. 
 * For more information on the Apache Group and the Apache HTTP server 
 * project, please see <http://www.apache.org/>. 
 * 
 */ 
 
#define CORE_PRIVATE 
 
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "ap_config.h"
#include "ap_listen.h"
#include "multithread.h"
#include "../os/win32/getopt.h"
#include "mpm_default.h"
#include "../os/win32/iol_socket.h"
#include "winnt.h"

/*
 * Definitions of WINNT MPM specific config globals
 */
int ap_max_requests_per_child=0;
int ap_daemons_to_start=0;
static char *mpm_pid_fname=NULL;
static int ap_threads_per_child = 0;
static int workers_may_exit = 0;
static int max_requests_per_child = 0;

static struct pollfd *listenfds;
static int num_listenfds = 0;
int listenmaxfd = -1;

static pool *pconf;		/* Pool for config stuff */

static char ap_coredump_dir[MAX_STRING_LEN];


static server_rec *server_conf;

static int one_process = 0;
event *exit_event;
mutex *start_mutex;
int my_pid;
int parent_pid;


/*
 * Signalling Apache on NT.
 *
 * Under Unix, Apache can be told to shutdown or restart by sending various
 * signals (HUP, USR, TERM). On NT we don't have easy access to signals, so
 * we use "events" instead. The parent apache process goes into a loop
 * where it waits forever for a set of events. Two of those events are
 * called
 *
 *    apPID_shutdown
 *    apPID_restart
 *
 * (where PID is the PID of the apache parent process). When one of these
 * is signalled, the Apache parent performs the appropriate action. The events
 * can become signalled through internal Apache methods (e.g. if the child
 * finds a fatal error and needs to kill its parent), via the service
 * control manager (the control thread will signal the shutdown event when
 * requested to stop the Apache service), from the -k Apache command line,
 * or from any external program which finds the Apache PID from the
 * httpd.pid file.
 *
 * The signal_parent() function, below, is used to signal one of these events.
 * It can be called by any child or parent process, since it does not
 * rely on global variables.
 *
 * On entry, type gives the event to signal. 0 means shutdown, 1 means 
 * graceful restart.
 */

static void signal_parent(int type)
{
    HANDLE e;
    char *signal_name;
    extern char signal_shutdown_name[];
    extern char signal_restart_name[];

    /* after updating the shutdown_pending or restart flags, we need
     * to wake up the parent process so it can see the changes. The
     * parent will normally be waiting for either a child process
     * to die, or for a signal on the "spache-signal" event. So set the
     * "apache-signal" event here.
     */
    if (one_process) {
	return;
    }

    switch(type) {
    case 0: signal_name = signal_shutdown_name; break;
    case 1: signal_name = signal_restart_name; break;
    default: return;
    }

    e = OpenEvent(EVENT_ALL_ACCESS, FALSE, signal_name);
    if (!e) {
	/* Um, problem, can't signal the parent, which means we can't
	 * signal ourselves to die. Ignore for now...
	 */
	ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_WIN32ERROR, server_conf,
	    "OpenEvent on %s event", signal_name);
	return;
    }
    if (SetEvent(e) == 0) {
	/* Same problem as above */
	ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_WIN32ERROR, server_conf,
	    "SetEvent on %s event", signal_name);
	CloseHandle(e);
	return;
    }
    CloseHandle(e);
}
void ap_start_shutdown(void)
{
    signal_parent(0);
}
void ap_start_restart(int graceful)
{
    signal_parent(1);
}

static int volatile is_graceful = 0;
API_EXPORT(int) ap_graceful_stop_signalled(void)
{
    return is_graceful;
}

/*
 * Routines that deal with sockets, some are WIN32 specific...
 */
static int s_iInitCount = 0;
static int AMCSocketInitialize(void)
{
    int iVersionRequested;
    WSADATA wsaData;
    int err;

    if (s_iInitCount > 0) {
	s_iInitCount++;
	return (0);
    }
    else if (s_iInitCount < 0)
	return (s_iInitCount);

    /* s_iInitCount == 0. Do the initailization */
    iVersionRequested = MAKEWORD(1, 1);
    err = WSAStartup((WORD) iVersionRequested, &wsaData);
    if (err) {
	s_iInitCount = -1;
	return (s_iInitCount);
    }
    if (LOBYTE(wsaData.wVersion) != 1 ||
	HIBYTE(wsaData.wVersion) != 1) {
	s_iInitCount = -2;
	WSACleanup();
	return (s_iInitCount);
    }

    s_iInitCount++;
    return (s_iInitCount);

}
static void AMCSocketCleanup(void)
{
    if (--s_iInitCount == 0)
	WSACleanup();
    return;
}

static void sock_disable_nagle(int s) /* ZZZ abstract */
{
    /* The Nagle algorithm says that we should delay sending partial
     * packets in hopes of getting more data.  We don't want to do
     * this; we are not telnet.  There are bad interactions between
     * persistent connections and Nagle's algorithm that have very severe
     * performance penalties.  (Failing to disable Nagle is not much of a
     * problem with simple HTTP.)
     *
     * In spite of these problems, failure here is not a shooting offense.
     */
    int just_say_no = 1;

    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &just_say_no,
		   sizeof(int)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf,
		    "setsockopt: (TCP_NODELAY)");
    }
}

/*
 * Routines to deal with managing the list of listening sockets.
 */
static ap_listen_rec *head_listener;
static ap_inline ap_listen_rec *find_ready_listener(fd_set * main_fds)
{
    ap_listen_rec *lr;

    for (lr = head_listener; lr ; lr = lr->next) {
	if (FD_ISSET(lr->fd, main_fds)) {
	    head_listener = lr->next;
            if (head_listener == NULL)
                head_listener = ap_listeners;

	    return (lr);
	}
    }
    return NULL;
}
static int setup_listeners(pool *pconf, server_rec *s)
{
    ap_listen_rec *lr;
    int num_listeners = 0;

    /* Setup the listeners */
    listenmaxfd = -1;
    FD_ZERO(&listenfds);

    if (ap_listen_open(pconf, s->port)) {
       return 0;
    }
    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
        if (lr->fd >= 0) {
            FD_SET(lr->fd, &listenfds);
            if (lr->fd > listenmaxfd)
                listenmaxfd = lr->fd;
        }
    }

    head_listener = ap_listeners;

    return num_listeners;
}

static int setup_inherited_listeners(pool *p, server_rec *s)
{
    WSAPROTOCOL_INFO WSAProtocolInfo;
    HANDLE pipe;
    ap_listen_rec *lr;
    DWORD BytesRead;
    int num_listeners = 0;
    int fd;

    /* Setup the listeners */
    listenmaxfd = -1;
    FD_ZERO(&listenfds);

    /* Set up a default listener if necessary */
    if (ap_listeners == NULL) {
        struct sockaddr_in local_addr;
        ap_listen_rec *new;
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(s->port ? s->port : DEFAULT_HTTP_PORT);
        new = malloc(sizeof(ap_listen_rec));
        new->local_addr = local_addr;
        new->fd = -1;
        new->next = ap_listeners;
        ap_listeners = new;
    }

    /* Open the pipe to the parent process to receive the inherited socket
     * data. The sockets have been set to listening in the parent process.
     */
    pipe = GetStdHandle(STD_INPUT_HANDLE);
    for (lr = ap_listeners; lr; lr = lr->next) {
        if (!ReadFile(pipe, &WSAProtocolInfo, sizeof(WSAPROTOCOL_INFO), 
                      &BytesRead, (LPOVERLAPPED) NULL)) {
            ap_log_error(APLOG_MARK, APLOG_WIN32ERROR|APLOG_CRIT, server_conf,
                         "setup_inherited_listeners: Unable to read socket data from parent");
            signal_parent(0);	/* tell parent to die */
            exit(1);
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf,
                         "BytesRead = %d WSAProtocolInfo = %x20", BytesRead, WSAProtocolInfo);
        fd = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                       &WSAProtocolInfo, 0, 0);
        if (fd == INVALID_SOCKET) {
            ap_log_error(APLOG_MARK, APLOG_WIN32ERROR|APLOG_CRIT, server_conf,
                         "setup_inherited_listeners: WSASocket failed to open the inherited socket.");
            signal_parent(0);	/* tell parent to die */
            exit(1);
        }
        if (fd >= 0) {
            FD_SET(fd, &listenfds);
            if (fd > listenmaxfd)
                listenmaxfd = fd;
        }
        ap_note_cleanups_for_socket(p, fd);

        lr->fd = fd;
    }
    CloseHandle(pipe);


    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }

    head_listener = ap_listeners;

    return num_listeners;
}


/**********************************************************************
 * Multithreaded implementation
 *
 * This code is fairly specific to Win32.
 *
 * The model used to handle requests is a set of threads. One "main"
 * thread listens for new requests. When something becomes
 * available, it does a select and places the newly available socket
 * onto a list of "jobs" (add_job()). Then any one of a fixed number
 * of "worker" threads takes the top job off the job list with
 * remove_job() and handles that connection to completion. After
 * the connection has finished the thread is free to take another
 * job from the job list.
 *
 * In the code, the "main" thread is running within the worker_main()
 * function. The first thing this function does is create the
 * worker threads, which operate in the child_sub_main() function. The
 * main thread then goes into a loop within worker_main() where they
 * do a select() on the listening sockets. The select times out once
 * per second so that the thread can check for an "exit" signal
 * from the parent process (see below). If this signal is set, the 
 * thread can exit, but only after it has accepted all incoming
 * connections already in the listen queue (since Win32 appears
 * to through away listened but unaccepted connections when a 
 * process dies).
 *
 * Because the main and worker threads exist within a single process
 * they are vulnerable to crashes or memory leaks (crashes can also
 * be caused within modules, of course). There also needs to be a 
 * mechanism to perform restarts and shutdowns. This is done by
 * creating the main & worker threads within a subprocess. A
 * main process (the "parent process") creates one (or more) 
 * processes to do the work, then the parent sits around waiting
 * for the working process to die, in which case it starts a new
 * one. The parent process also handles restarts (by creating
 * a new working process then signalling the previous working process 
 * exit ) and shutdowns (by signalling the working process to exit).
 * The parent process operates within the master_main() function. This
 * process also handles requests from the service manager (NT only).
 *
 * Signalling between the parent and working process uses a Win32
 * event. Each child has a unique name for the event, which is
 * passed to it with the -Z argument when the child is spawned. The
 * parent sets (signals) this event to tell the child to die.
 * At present all children do a graceful die - they finish all
 * current jobs _and_ empty the listen queue before they exit.
 * A non-graceful die would need a second event. The -Z argument in
 * the child is also used to create the shutdown and restart events,
 * since the prefix (apPID) contains the parent process PID.
 *
 * The code below starts with functions at the lowest level -
 * worker threads, and works up to the top level - the main()
 * function of the parent process.
 *
 * The scoreboard (in process memory) contains details of the worker
 * threads (within the active working process). There is no shared
 * "scoreboard" between processes, since only one is ever active
 * at once (or at most, two, when one has been told to shutdown but
 * is processes outstanding requests, and a new one has been started).
 * This is controlled by a "start_mutex" which ensures only one working
 * process is active at once.
 **********************************************************************/

int service_init()
{
/*
    common_init();
 
    ap_cpystrn(ap_server_root, HTTPD_ROOT, sizeof(ap_server_root));
    if (ap_registry_get_service_conf(pconf, ap_server_confname, sizeof(ap_server_confname),
                                     ap_server_argv0))
        return FALSE;

    ap_setup_prelinked_modules();
    server_conf = ap_read_config(pconf, ptrans, ap_server_confname);
    ap_log_pid(pconf, ap_pid_fname);
    post_parse_init();
*/
    return TRUE;
}

/*
 * Definition of jobs, shared by main and worker threads.
 */

typedef struct joblist_s {
    struct joblist_s *next;
    int sock;
} joblist;

/*
 * Globals common to main and worker threads. This structure is not
 * used by the parent process.
 */

typedef struct globals_s {
    semaphore *jobsemaphore;
    joblist *jobhead;
    joblist *jobtail;
    CRITICAL_SECTION jobmutex;
    int jobcount;
} globals;

globals allowed_globals =
{NULL, NULL, NULL, NULL, 0};

/*
 * add_job()/remove_job() - add or remove an accepted socket from the
 * list of sockets connected to clients. allowed_globals.jobmutex protects
 * against multiple concurrent access to the linked list of jobs.
 */

static void add_job(int sock)
{
    joblist *new_job;

    new_job = (joblist *) malloc(sizeof(joblist));
    if (new_job == NULL) {
	fprintf(stderr, "Ouch!  Out of memory in add_job()!\n");
        return;
    }
    new_job->next = NULL;
    new_job->sock = sock;

    EnterCriticalSection(&allowed_globals.jobmutex);
    if (allowed_globals.jobtail != NULL)
	allowed_globals.jobtail->next = new_job;
    allowed_globals.jobtail = new_job;
    if (!allowed_globals.jobhead)
	allowed_globals.jobhead = new_job;
    allowed_globals.jobcount++;
    release_semaphore(allowed_globals.jobsemaphore);
    LeaveCriticalSection(&allowed_globals.jobmutex);
}

static int remove_job(void)
{
    joblist *job;
    int sock;

    acquire_semaphore(allowed_globals.jobsemaphore);
    EnterCriticalSection(&allowed_globals.jobmutex);

    if (workers_may_exit && !allowed_globals.jobhead) {
        LeaveCriticalSection(&allowed_globals.jobmutex);
	return (-1);
    }
    job = allowed_globals.jobhead;
    ap_assert(job);
    allowed_globals.jobhead = job->next;
    if (allowed_globals.jobhead == NULL)
	allowed_globals.jobtail = NULL;
    LeaveCriticalSection(&allowed_globals.jobmutex);
    sock = job->sock;
    free(job);

    return (sock);
}
#define MAX_SELECT_ERRORS 100
#define PADDED_ADDR_SIZE sizeof(SOCKADDR_IN)+16
static void accept_and_queue_connections(void * dummy)
{
    int requests_this_child = 0;
    struct timeval tv;
    fd_set main_fds;
    int wait_time = 1;
    int csd;
    int sd = -1;
    struct sockaddr_in sa_client;
    int count_select_errors = 0;
    int rc;
    int clen;

    while (!workers_may_exit) {
        if (ap_max_requests_per_child && (requests_this_child > ap_max_requests_per_child)) {
            break;
	}

	tv.tv_sec = wait_time;
	tv.tv_usec = 0;
	memcpy(&main_fds, &listenfds, sizeof(fd_set));

	rc = ap_select(listenmaxfd + 1, &main_fds, NULL, NULL, &tv);

        if (rc == 0 || (rc == SOCKET_ERROR && h_errno == WSAEINTR)) {
            count_select_errors = 0;    /* reset count of errors */            
            continue;
        }
        else if (rc == SOCKET_ERROR) {
            /* A "real" error occurred, log it and increment the count of
             * select errors. This count is used to ensure we don't go into
             * a busy loop of continuous errors.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_WIN32ERROR, server_conf, "select failed with errno %d", h_errno);
            count_select_errors++;
            if (count_select_errors > MAX_SELECT_ERRORS) {
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                             "Too many errors in select loop. Child process exiting.");
                break;
            }
	} else {
	    ap_listen_rec *lr;

	    lr = find_ready_listener(&main_fds);
	    if (lr != NULL) {
		sd = lr->fd;
	    }
	}

	do {
	    clen = sizeof(sa_client);
	    csd = accept(sd, (struct sockaddr *) &sa_client, &clen);
	    if (csd == INVALID_SOCKET) {
		csd = -1;
	    }
	} while (csd < 0 && h_errno == WSAEINTR);

	if (csd < 0) {
            if (h_errno != WSAECONNABORTED) {
		ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, server_conf,
			    "accept: (client socket)");
            }
	}
	else {
	    add_job(csd);
	    requests_this_child++;
	}
    }
    SetEvent(exit_event);
}
static PCOMP_CONTEXT win9x_get_connection(PCOMP_CONTEXT context)
{
    int len;
    while (1) {
        context->accept_socket = remove_job();
        if (context->accept_socket == -1) {
            CloseHandle(context->Overlapped.hEvent); /* TODO: Clean up in the caller not here */
            return NULL;
        }

        len = sizeof(struct sockaddr);
        if (getsockname(context->accept_socket, 
                        &context->sa_server, &len)== SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, 
                         "getsockname failed with error %d\n", WSAGetLastError());
            continue;
        }
        
        len = sizeof(struct sockaddr);
        if ((getpeername(context->accept_socket,
                         &context->sa_client, &len)) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, 
                         "getpeername failed with error %d\n", WSAGetLastError());
            memset(&context->sa_client, '\0', sizeof(context->sa_client));
        }

        return context;
    }
}
static PCOMP_CONTEXT winnt_get_connection(PCOMP_CONTEXT context)
{
    int requests_this_child = 0;
    int count_select_errors = 0;
    struct timeval tv;
    fd_set main_fds;
    int wait_time = 1;
    int sd = -1;
    int rc;

    /* AcceptEx needs a pre-allocated accept socket */
    context->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    EnterCriticalSection(&allowed_globals.jobmutex);    

    while (!workers_may_exit) {
        workers_may_exit |= ((ap_max_requests_per_child != 0) && (requests_this_child > ap_max_requests_per_child));
        if (workers_may_exit)
            break;

        tv.tv_sec = wait_time;
        tv.tv_usec = 0;
        memcpy(&main_fds, &listenfds, sizeof(fd_set));

        rc = ap_select(listenmaxfd + 1, &main_fds, NULL, NULL, &tv);

        if (rc == 0 || (rc == SOCKET_ERROR && h_errno == WSAEINTR)) {
            count_select_errors = 0;    /* reset count of errors */            
            continue;
        }
        else if (rc == SOCKET_ERROR) {
            /* A "real" error occurred, log it and increment the count of
             * select errors. This count is used to ensure we don't go into
             * a busy loop of continuous errors.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_WIN32ERROR, server_conf, "select failed with errno %d", h_errno);
            count_select_errors++;
            if (count_select_errors > MAX_SELECT_ERRORS) {
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                             "Too many errors in select loop. Child process exiting.");
                break;
            }
        }
        else {
            DWORD BytesRead;
            ap_listen_rec *lr;
            
            lr = find_ready_listener(&main_fds);
            if (lr != NULL) {
                sd = lr->fd;
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                             "select returned but there are no ready listeners! Exiting.");
                break;
            }

            rc = AcceptEx(sd, context->accept_socket,
                          context->conn_io->inbase,
                          context->conn_io->bufsiz - 2*PADDED_ADDR_SIZE,
                          PADDED_ADDR_SIZE,
                          PADDED_ADDR_SIZE,
                          &BytesRead,
                          &context->Overlapped);
            
            if (!rc && (h_errno == WSA_IO_PENDING)) {
                rc = GetOverlappedResult(context->Overlapped.hEvent,
                                         &context->Overlapped,
                                         &BytesRead,
                                         INFINITE); /* TODO: get timeout from the config file */
            }
            if (!rc) {
                if (h_errno != WSAECONNABORTED) {
                    ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                                 "AcceptEx failed.");
                }
                continue;  /* go back to select */
            }
            requests_this_child++;   
            context->conn_io->incnt = BytesRead;
            GetAcceptExSockaddrs(context->conn_io->inbase, 
                                 context->conn_io->bufsiz - 2*PADDED_ADDR_SIZE,
                                 PADDED_ADDR_SIZE,
                                 PADDED_ADDR_SIZE,
                                 &context->sa_server,
                                 &context->sa_server_len,
                                 &context->sa_client,
                                 &context->sa_client_len);


            LeaveCriticalSection(&allowed_globals.jobmutex);
            return context;
        }
    }
    CloseHandle(context->Overlapped.hEvent);
    LeaveCriticalSection(&allowed_globals.jobmutex);
    SetEvent(exit_event);
    return NULL;
}

/*
 * child_main() - this is the main loop for the worker threads
 *
 * Each thread runs within this function. They wait within remove_job()
 * for a job to become available, then handle all the requests on that
 * connection until it is closed, then return to remove_job().
 *
 * The worker thread will exit when it removes a job which contains
 * socket number -1. This provides a graceful thread exit, since
 * it will never exit during a connection.
 *
 * This code in this function is basically equivalent to the child_main()
 * from the multi-process (Unix) environment, except that we
 *
 *  - do not call child_init_modules (child init API phase)
 *  - block in remove_job, and when unblocked we have an already
 *    accepted socket, instead of blocking on a mutex or select().
 */
//#define QUEUED_ACCEPT  for Windows 95 TODO: Make this a run time check
static void child_main(int child_num)
{
    PCOMP_CONTEXT lpCompContext;
    ap_iol *iol;

    /* Create and initialize the static (unchangeing) portion of the 
     * completion context 
     */
    lpCompContext = ap_pcalloc(pconf, sizeof(COMP_CONTEXT));
    lpCompContext->Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); 
    lpCompContext->ptrans = ap_make_sub_pool(pconf);

#if 0
    (void) ap_update_child_status(child_num, SERVER_READY, (request_rec *) NULL);
#endif

    while (1) {
        BUFF *conn_io;
        pool *ptrans;
        int csd = -1;
        conn_rec *current_conn;

        /* Initialize the dynamic portion of the completion context */
	ap_clear_pool(lpCompContext->ptrans);
        lpCompContext->conn_io =  ap_bcreate(lpCompContext->ptrans, B_RDWR);


#ifdef QUEUED_ACCEPT
        lpCompContext = win9x_get_connection(lpCompContext);
#else
        lpCompContext = winnt_get_connection(lpCompContext);
#endif

        if (!lpCompContext)
            break;

        conn_io = lpCompContext->conn_io;
        ptrans = lpCompContext->ptrans;
        csd = lpCompContext->accept_socket;

	ap_note_cleanups_for_socket(ptrans, csd);

#if 0
	(void) ap_update_child_status(child_num, SERVER_BUSY_READ,
                                      (request_rec *) NULL);
#endif
	sock_disable_nagle(csd);

        iol = win32_attach_socket(csd);
        if (iol == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
                         "error attaching to socket");
            close(csd);
            continue;
        }

        ap_bpush_iol(conn_io, iol);

	current_conn = ap_new_connection(ptrans, server_conf, conn_io,
                                         (struct sockaddr_in *) &lpCompContext->sa_client,
                                         (struct sockaddr_in *) &lpCompContext->sa_server,
                                         child_num);

        ap_process_connection(current_conn);
    }
    /* TODO: Add code to clean-up completion contexts here */
}

static void cleanup_thread(thread **handles, int *thread_cnt, int thread_to_clean)
{
    int i;

    free_thread(handles[thread_to_clean]);
    for (i = thread_to_clean; i < ((*thread_cnt) - 1); i++)
	handles[i] = handles[i + 1];
    (*thread_cnt)--;
}

/*
 * The Win32 call WaitForMultipleObjects will only allow you to wait for 
 * a maximum of MAXIMUM_WAIT_OBJECTS (current 64).  Since the threading 
 * model in the multithreaded version of apache wants to use this call, 
 * we are restricted to a maximum of 64 threads.  This is a simplistic 
 * routine that will increase this size.
 */
static DWORD wait_for_many_objects(DWORD nCount, CONST HANDLE *lpHandles, 
                            DWORD dwSeconds)
{
    time_t tStopTime;
    DWORD dwRet = WAIT_TIMEOUT;
    DWORD dwIndex=0;
    BOOL bFirst = TRUE;
  
    tStopTime = time(NULL) + dwSeconds;
  
    do {
        if (!bFirst)
            Sleep(1000);
        else
            bFirst = FALSE;
          
        for (dwIndex = 0; dwIndex * MAXIMUM_WAIT_OBJECTS < nCount; dwIndex++) {
            dwRet = WaitForMultipleObjects(
                        min(MAXIMUM_WAIT_OBJECTS, 
                            nCount - (dwIndex * MAXIMUM_WAIT_OBJECTS)),
                        lpHandles + (dwIndex * MAXIMUM_WAIT_OBJECTS), 
                        0, 0);
                                           
            if (dwRet != WAIT_TIMEOUT) {                                          
              break;
            }
        }
    } while((time(NULL) < tStopTime) && (dwRet == WAIT_TIMEOUT));
    
    return dwRet;
}


/*
 * Initialise the signal names, in the global variables signal_name_prefix, 
 * signal_restart_name and signal_shutdown_name.
 */

#define MAX_SIGNAL_NAME 30  /* Long enough for apPID_shutdown, where PID is an int */
char signal_name_prefix[MAX_SIGNAL_NAME];
char signal_restart_name[MAX_SIGNAL_NAME]; 
char signal_shutdown_name[MAX_SIGNAL_NAME];
static void setup_signal_names(char *prefix)
{
    ap_snprintf(signal_name_prefix, sizeof(signal_name_prefix), prefix);    
    ap_snprintf(signal_shutdown_name, sizeof(signal_shutdown_name), 
	"%s_shutdown", signal_name_prefix);    
    ap_snprintf(signal_restart_name, sizeof(signal_restart_name), 
	"%s_restart", signal_name_prefix);    
}

/*
 * worker_main() is main loop for the child process. The loop in
 * this function becomes the controlling thread for the actually working
 * threads (which run in a loop in child_sub_main()).
 * Globals Used:
 *  exit_event, start_mutex, ap_threads_per_child, server_conf,
 *  h_errno defined to WSAGetLastError in winsock2.h,
 */
static void worker_main()
{
    int nthreads = ap_threads_per_child;


    thread **child_handles;
    int rv;
    time_t end_time;
    int i;
    pool *pchild;

    pchild = ap_make_sub_pool(pconf);

//    ap_restart_time = time(NULL);

#if 0
    reinit_scoreboard(pconf);
#endif

    /*
     * Wait until we have permission to start accepting connections.
     * start_mutex is used to ensure that only one child ever
     * goes into the listen/accept loop at once. Also wait on exit_event,
     * in case we (this child) is told to die before we get a chance to
     * serve any requests.
     */
    rv = WaitForSingleObject(start_mutex,0);
    if (rv == WAIT_FAILED) {
	ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                     "Waiting for start_mutex or exit_event -- process will exit");

	ap_destroy_pool(pchild);
#if 0
	cleanup_scoreboard();
#endif
	exit(0);
    }

    /* start_mutex obtained, continue into the select() loop */
    if (one_process) {
        setup_listeners(pconf, server_conf);
    } else {
        /* Get listeners from the parent process */
        setup_inherited_listeners(pconf, server_conf);
    }

    if (listenmaxfd == -1) {
	/* Help, no sockets were made, better log something and exit */
	ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, NULL,
		    "No sockets were created for listening");

	signal_parent(0);	/* tell parent to die */

	ap_destroy_pool(pchild);
#if 0
	cleanup_scoreboard();
#endif
	exit(0);
    }

    allowed_globals.jobsemaphore = create_semaphore(0);
    InitializeCriticalSection(&allowed_globals.jobmutex);

    /* spawn off the worker threads */
    child_handles = (thread *) alloca(nthreads * sizeof(int));
    for (i = 0; i < nthreads; i++) {
	child_handles[i] = create_thread((void (*)(void *)) child_main, (void *) i);
    }

#ifdef QUEUED_ACCEPT
    /* spawn off accept thread */
    create_thread((void (*)(void *)) accept_and_queue_connections, (void *) NULL);
#endif

    rv = WaitForSingleObject(exit_event, INFINITE);
    printf("exit event signalled \n");
    workers_may_exit = 1;      

    /* Get ready to shutdown and exit */
    ap_release_mutex(start_mutex);
#ifdef QUEUED_ACCEPT
    for (i = 0; i < nthreads; i++) {
	add_job(-1);
    }
#endif
    /* Wait for all your children */
    end_time = time(NULL) + 180;
    while (nthreads) {
        rv = wait_for_many_objects(nthreads, child_handles, 
                                   end_time - time(NULL));
	if (rv != WAIT_TIMEOUT) {
	    rv = rv - WAIT_OBJECT_0;
	    ap_assert((rv >= 0) && (rv < nthreads));
	    cleanup_thread(child_handles, &nthreads, rv);
	    continue;
	}
	break;
    }

    for (i = 0; i < nthreads; i++) {
	kill_thread(child_handles[i]);
	free_thread(child_handles[i]);
    }

    destroy_semaphore(allowed_globals.jobsemaphore);
    DeleteCriticalSection(&allowed_globals.jobmutex);

    ap_destroy_pool(pchild);

#if 0
    cleanup_scoreboard();
#endif
}
static HANDLE create_exit_event(const char* event_name)
{
    return CreateEvent(NULL, TRUE, FALSE, event_name);
}
/*
 * Spawn a child Apache process. The child process has the command line arguments from
 * argc and argv[], plus a -Z argument giving the name of an event. The child should
 * open and poll or wait on this event. When it is signalled, the child should die.
 * prefix is a prefix string for the event name.
 * 
 * The child_num argument on entry contains a serial number for this child (used to create
 * a unique event name). On exit, this number will have been incremented by one, ready
 * for the next call. 
 *
 * On exit, the value pointed to be *ev will contain the event created
 * to signal the new child process.
 *
 * The return value is the handle to the child process if successful, else -1. If -1 is
 * returned the error will already have been logged by ap_log_error().
 */

/**********************************************************************
 * master_main - this is the parent (main) process. We create a
 * child process to do the work, then sit around waiting for either
 * the child to exit, or a restart or exit signal. If the child dies,
 * we just respawn a new one. If we have a shutdown or graceful restart,
 * tell the child to die when it is ready. If it is a non-graceful
 * restart, force the child to die immediately.
 **********************************************************************/

#define MAX_PROCESSES 50 /* must be < MAX_WAIT_OBJECTS-1 */

static void cleanup_process(HANDLE *handles, HANDLE *events, int position, int *processes)
{
    int i;
    int handle = 0;

    CloseHandle(handles[position]);
    CloseHandle(events[position]);

    handle = (int)handles[position];

    for (i = position; i < (*processes)-1; i++) {
	handles[i] = handles[i + 1];
	events[i] = events[i + 1];
    }
    (*processes)--;
}

static int create_process(pool *p, HANDLE *handles, HANDLE *events, int *processes)
{
    int rv;
    char buf[1024];
    char *pCommand;

    STARTUPINFO si;           /* Filled in prior to call to CreateProcess */
    PROCESS_INFORMATION pi;   /* filled in on call to CreateProces */

    ap_listen_rec *lr;
    DWORD BytesWritten;
    HANDLE hPipeRead = NULL;
    HANDLE hPipeWrite = NULL;
    SECURITY_ATTRIBUTES sa = {0};  

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Build the command line. Should look something like this:
     * C:/apache/bin/apache.exe -f ap_server_confname 
     * First, get the path to the executable...
     */
    rv = GetModuleFileName(NULL, buf, sizeof(buf));
    if (rv == sizeof(buf)) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                     "Parent: Path to Apache process too long");
        return -1;
    } else if (rv == 0) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                     "Parent: GetModuleFileName() returned NULL for current process.");
        return -1;
    }

    //    pCommand = ap_psprintf(p, "\"%s\" -f \"%s\"", buf, ap_server_confname);  
    pCommand = ap_psprintf(p, "\"%s\" -f \"%s\"", buf, SERVER_CONFIG_FILE);  

    /* Create a pipe to send socket info to the child */
    if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                     "Parent: Unable to create pipe to child process.\n");
        return -1;
    }

    SetEnvironmentVariable("AP_PARENT_PID",ap_psprintf(p,"%d",parent_pid));

    /* Give the read in of the pipe (hPipeRead) to the child as stdin. The 
     * parent will write the socket data to the child on this pipe.
     */
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = hPipeRead;

    if (!CreateProcess(NULL, pCommand, NULL, NULL, 
                       TRUE,               /* Inherit handles */
                       CREATE_SUSPENDED,   /* Creation flags */
                       NULL,               /* Environment block */
                       NULL,
                       &si, &pi)) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                     "Parent: Not able to create the child process.");
        /*
         * We must close the handles to the new process and its main thread
         * to prevent handle and memory leaks.
         */ 
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }
    else {
        HANDLE kill_event;
        LPWSAPROTOCOL_INFO  lpWSAProtocolInfo;

        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, server_conf,
                     "Parent: Created child process %d", pi.dwProcessId);

        SetEnvironmentVariable("AP_PARENT_PID",NULL);

        /* Create the exit_event, apCHILD_PID */
        kill_event = create_exit_event(ap_psprintf(pconf,"apC%d", pi.dwProcessId));
//CreateEvent(NULL, TRUE, TRUE, ap_psprintf(pconf,"apC%d", pi.dwProcessId)); // exit_event_name...
        if (!kill_event) {
            ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                         "Parent: Could not create exit event for child process");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return -1;
        }
        
        /* Assume the child process lives. Update the process and event tables */
        handles[*processes] = pi.hProcess;
        events[*processes] = kill_event;
        (*processes)++;

        /* We never store the thread's handle, so close it now. */
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        /* Run the chain of open sockets. For each socket, duplicate it 
         * for the target process then send the WSAPROTOCOL_INFO 
         * (returned by dup socket) to the child */
        for (lr = ap_listeners; lr; lr = lr->next) {
            lpWSAProtocolInfo = ap_pcalloc(p, sizeof(WSAPROTOCOL_INFO));
            ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, server_conf,
                         "Parent: Duplicating socket %d and sending it to child process %d", lr->fd, pi.dwProcessId);
            if (WSADuplicateSocket(lr->fd, 
                                   pi.dwProcessId,
                                   lpWSAProtocolInfo) == SOCKET_ERROR) {
                ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                             "Parent: WSADuplicateSocket failed for socket %d.", lr->fd );
                return -1;
            }

            if (!WriteFile(hPipeWrite, lpWSAProtocolInfo, (DWORD) sizeof(WSAPROTOCOL_INFO),
                           &BytesWritten,
                           (LPOVERLAPPED) NULL)) {
                ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                             "Parent: Unable to write duplicated socket %d to the child.", lr->fd );
                return -1;
            }
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf,
                         "BytesWritten = %d WSAProtocolInfo = %x20", BytesWritten, *lpWSAProtocolInfo);
        }
    }
    CloseHandle(hPipeRead);
    CloseHandle(hPipeWrite);        

    return 0;
}

/* To share the semaphores with other processes, we need a NULL ACL
 * Code from MS KB Q106387
 */
static PSECURITY_ATTRIBUTES GetNullACL()
{
    PSECURITY_DESCRIPTOR pSD;
    PSECURITY_ATTRIBUTES sa;

    sa  = (PSECURITY_ATTRIBUTES) LocalAlloc(LPTR, sizeof(SECURITY_ATTRIBUTES));
    pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR,
					    SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (pSD == NULL || sa == NULL) {
        return NULL;
    }
    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)
	|| GetLastError()) {
        LocalFree( pSD );
        LocalFree( sa );
        return NULL;
    }
    if (!SetSecurityDescriptorDacl(pSD, TRUE, (PACL) NULL, FALSE)
	|| GetLastError()) {
        LocalFree( pSD );
        LocalFree( sa );
        return NULL;
    }
    sa->nLength = sizeof(sa);
    sa->lpSecurityDescriptor = pSD;
    sa->bInheritHandle = TRUE;
    return sa;
}


static void CleanNullACL( void *sa ) {
    if( sa ) {
        LocalFree( ((PSECURITY_ATTRIBUTES)sa)->lpSecurityDescriptor);
        LocalFree( sa );
    }
}

static int master_main(server_rec *s, HANDLE shutdown_event, HANDLE restart_event)
{
    int remaining_children_to_start = ap_daemons_to_start;
    int i;
    int rv, cld;
    int child_num = 0;
    int restart_pending = 0;
    int shutdown_pending = 0;
    int current_live_processes = 0; /* number of child process we know about */

    HANDLE process_handles[MAX_PROCESSES];
    HANDLE process_kill_events[MAX_PROCESSES];

    setup_listeners(pconf, s);

    /* Create child process 
     * Should only be one in this version of Apache for WIN32 
     */
    while (remaining_children_to_start--) {
        if (create_process(pconf, process_handles, process_kill_events, 
                           &current_live_processes) < 0) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO, server_conf,
                         "master_main: create child process failed. Exiting.");
            shutdown_pending = 1;
            goto die_now;
        }
    }

    /* service_set_status(SERVICE_RUNNING);*/
    restart_pending = shutdown_pending = 0;
    
    /* Wait for shutdown or restart events or for child death */
    process_handles[current_live_processes] = shutdown_event;
    process_handles[current_live_processes+1] = restart_event;
    rv = WaitForMultipleObjects(current_live_processes+2, (HANDLE *)process_handles, 
                                FALSE, INFINITE);
    cld = rv - WAIT_OBJECT_0;
    if (rv == WAIT_FAILED) {
        /* Something serious is wrong */
        ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_WIN32ERROR, server_conf,
                     "master_main: : WaitForMultipeObjects on process handles and apache-signal -- doing shutdown");
        shutdown_pending = 1;
    }
    else if (rv == WAIT_TIMEOUT) {
        /* Hey, this cannot happen */
        ap_log_error(APLOG_MARK, APLOG_ERR, s,
                     "master_main: WaitForMultipeObjects with INFINITE wait exited with WAIT_TIMEOUT");
        shutdown_pending = 1;
    }
    else if (cld == current_live_processes) {
        /* shutdown_event signalled */
        shutdown_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, s, 
                     "master_main: Shutdown event signaled. Shutting the server down.");
        if (ResetEvent(shutdown_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, s,
                         "ResetEvent(shutdown_event)");
        }

    }
    else if (cld == current_live_processes+1) {
        /* restart_event signalled */
        int children_to_kill = current_live_processes;
        restart_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, s, 
                     "master_main: Restart event signaled. Doing a graceful restart.");
        if (ResetEvent(restart_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, s,
                         "master_main: ResetEvent(restart_event) failed.");
        }
        /* Signal each child process to die 
         * We are making a big assumption here that the child process, once signaled,
         * will REALLY go away. Since this is a restart, we do not want to hold the 
         * new child process up waiting for the old child to die. Remove the old 
         * child out of the process_handles table and hope for the best...
         */
        for (i = 0; i < children_to_kill; i++) {
            /* APD3("master_main: signalling child #%d handle %d to die", i, process_handles[i]); */
            if (SetEvent(process_kill_events[i]) == 0)
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, s,
                             "master_main: SetEvent for child process in slot #%d failed", i);
            cleanup_process(process_handles, process_kill_events, i, &current_live_processes);
        }
    } 
    else {
        /* A child process must have exited because of MaxRequestPerChild being hit
         * or a fatal error condition (seg fault, etc.). Remove the dead process 
         * from the process_handles and process_kill_events table and create a new
         * child process.
         * TODO: Consider restarting the child immediately without looping through http_main
         * and without rereading the configuration. Will need this if we ever support multiple 
         * children. One option, create a parent thread which waits on child death and restarts it.
         */
        restart_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, server_conf, 
                     "master_main: Child processed exited (due to MaxRequestsPerChild?). Restarting the child process.");
        ap_assert(cld < current_live_processes);
        cleanup_process(process_handles, process_kill_events, cld, &current_live_processes);
        /* APD2("main_process: child in slot %d died", rv); */
        /* restart_child(process_hancles, process_kill_events, cld, &current_live_processes); */
    }

die_now:
    if (shutdown_pending) {
        int tmstart = time(NULL);
        /* Signal each child processes to die */
        for (i = 0; i < current_live_processes; i++) {
            if (SetEvent(process_kill_events[i]) == 0)
                ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                             "master_main: SetEvent for child process in slot #%d failed", i);
        }

        while (current_live_processes && ((tmstart+60) > time(NULL))) {
            rv = WaitForMultipleObjects(current_live_processes, (HANDLE *)process_handles, FALSE, 2000);
            if (rv == WAIT_TIMEOUT)
                continue;
            ap_assert(rv != WAIT_FAILED);
            cld = rv - WAIT_OBJECT_0;
            ap_assert(rv < current_live_processes);
            cleanup_process(process_handles, process_kill_events, cld, &current_live_processes);
        }
        for (i = 0; i < current_live_processes; i++) {
            ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, server_conf,
                         "forcing termination of child #%d (handle %d)", i, process_handles[i]);
            TerminateProcess((HANDLE) process_handles[i], 1);
        }
        return (0); /* Tell the caller we are shutting down */
    }

    return (1); /* Tell the caller we want a restart */
}

/* 
 * winnt_pre_config()
 */
static void winnt_pre_config(pool *pconf, pool *plog, pool *ptemp) 
{
    char *pid;
    one_process=1;//!!getenv("ONE_PROCESS");

    /* AP_PARENT_PID is only valid in the child */
    pid = getenv("AP_PARENT_PID");
    if (pid) {
        /* This is the child */
        parent_pid = atoi(pid);
        my_pid = getpid();
    }
    else {
        /* This is the parent */
        parent_pid = my_pid = getpid();
        ap_log_pid(pconf, mpm_pid_fname);
    }

    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_NUM_DAEMON;
    ap_threads_per_child = DEFAULT_START_THREAD;
    mpm_pid_fname = DEFAULT_PIDLOG;
    max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;

    ap_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));

}

static void winnt_post_config(pool *pconf, pool *plog, pool *ptemp, server_rec* server_conf)
{
    server_conf = server_conf;
}

API_EXPORT(int) ap_mpm_run(pool *_pconf, pool *plog, server_rec *s )
{

    char* exit_event_name;

//    time_t tmstart;
    HANDLE shutdown_event;	/* used to signal shutdown to parent */
    HANDLE restart_event;	/* used to signal a restart to parent */

    pconf = _pconf;
    server_conf = s;

    if ((parent_pid != my_pid) || one_process) {
        /* Child process */
        AMCSocketInitialize();
        exit_event_name = ap_psprintf(pconf, "apC%d", my_pid);
        setup_signal_names(ap_psprintf(pconf,"ap%d", parent_pid));
        if (one_process) {
            start_mutex = ap_create_mutex(signal_name_prefix);        
            exit_event = create_exit_event(exit_event_name);

        }
        else {
            start_mutex = ap_open_mutex(signal_name_prefix);
            exit_event = open_event(exit_event_name);
        }
        ap_assert(start_mutex);
        ap_assert(exit_event);

        worker_main();

        destroy_event(exit_event);
        AMCSocketCleanup();
    }
    else {
        /* Parent process */
        static int restart = 0;
        PSECURITY_ATTRIBUTES sa = GetNullACL();  /* returns NULL if invalid (Win95?) */

        ap_clear_pool(plog);
        ap_open_logs(server_conf, plog);

        if (!restart) {
            /* service_set_status(SERVICE_START_PENDING);*/
            AMCSocketInitialize();
            setup_signal_names(ap_psprintf(pconf,"ap%d", parent_pid));
        
            /* Create shutdown event, apPID_shutdown, where PID is the parent 
             * Apache process ID. Shutdown is signaled by 'apache -k shutdown'.
             */
            shutdown_event = CreateEvent(sa, TRUE, FALSE, signal_shutdown_name);
            if (!shutdown_event) {
                ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_WIN32ERROR, s,
                             "master_main: Cannot create shutdown event %s", signal_shutdown_name);
                CleanNullACL((void *)sa);
                exit(1);
            }

            /* Create restart event, apPID_restart, where PID is the parent 
             * Apache process ID. Restart is signaled by 'apache -k restart'.
             */
            restart_event = CreateEvent(sa, TRUE, FALSE, signal_restart_name);
            if (!restart_event) {
                CloseHandle(shutdown_event);
                ap_log_error(APLOG_MARK, APLOG_EMERG|APLOG_WIN32ERROR, s,
                             "master_main: Cannot create restart event %s", signal_restart_name);
                CleanNullACL((void *)sa);
                exit(1);
            }
            CleanNullACL((void *)sa);
            
            /* Create the start mutex, apPID, where PID is the parent Apache process ID.
             * Ths start mutex is used during a restart to prevent more than one 
             * child process from entering the accept loop at once.
             */
            start_mutex = ap_create_mutex(signal_name_prefix);        
            /* TODO: Add some code to detect failure */
        }

        /* Go to work... */
        restart = master_main(server_conf, shutdown_event, restart_event);

        if (!restart) {
            const char *pidfile = NULL;
            /* Shutting down. Clean up... */
            pidfile = ap_server_root_relative (pconf, mpm_pid_fname);
            if ( pidfile != NULL && unlink(pidfile) == 0)
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO,
                             server_conf,
                             "removed PID file %s (pid=%ld)",
                             pidfile, (long)getpid());
            ap_destroy_mutex(start_mutex);

            CloseHandle(restart_event);
            CloseHandle(shutdown_event);
            AMCSocketCleanup();
            /* service_set_status(SERVICE_STOPPED); */
        }
        return !restart;
    }
    return (0);
}

static void winnt_hooks(void)
{
//    INIT_SIGLIST()
    one_process = 0;
    /* Configuration hooks implemented by http_config.c ... */
    ap_hook_pre_config(winnt_pre_config, NULL, NULL, HOOK_MIDDLE);
}

/* 
 * Command processors 
 */
static const char *set_pidfile(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (cmd->server->is_virtual) {
	return "PidFile directive not allowed in <VirtualHost>";
    }
    mpm_pid_fname = arg;
    return NULL;
}

static const char *set_threads_per_child (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_per_child = atoi(arg);
    if (ap_threads_per_child > HARD_THREAD_LIMIT) {
        fprintf(stderr, "WARNING: ThreadsPerChild of %d exceeds compile time"
                " limit of %d threads,\n", ap_threads_per_child,
                HARD_THREAD_LIMIT);
        fprintf(stderr, " lowering ThreadsPerChild to %d. To increase, please"
                " see the\n", HARD_THREAD_LIMIT);
        fprintf(stderr, " HARD_THREAD_LIMIT define in src/include/httpd.h.\n");
    }
    else if (ap_threads_per_child < 1) {
	fprintf(stderr, "WARNING: Require ThreadsPerChild > 0, setting to 1\n");
	ap_threads_per_child = 1;
    }
    return NULL;
}


static const char *set_max_requests(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_requests_per_child = atoi(arg);

    return NULL;
}

static const char *set_coredumpdir (cmd_parms *cmd, void *dummy, char *arg) 
{
    struct stat finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    /* ZZZ change this to the AP func FileInfo*/
    if ((stat(fname, &finfo) == -1) || !S_ISDIR(finfo.st_mode)) {
	return ap_pstrcat(cmd->pool, "CoreDumpDirectory ", fname, 
			  " does not exist or is not a directory", NULL);
    }
    ap_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
}
/*
static int
map_rv(int rv)
{
    switch(rv)
    {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return(MULTI_OK);
    case WAIT_TIMEOUT:
        return(MULTI_TIMEOUT);
    case WAIT_FAILED:
        return(MULTI_ERR);
    default:
        assert(0);
    }

    assert(0);
    return(0);
}
*/

/*
API_EXPORT(mutex *) ap_open_mutex(char *name)
{
    return(OpenMutex(MUTEX_ALL_ACCESS, FALSE, name));
}
*/

struct ap_thread_mutex {
    CRITICAL_SECTION _mutex;
};


API_EXPORT(ap_thread_mutex *) ap_thread_mutex_new(void)
{
    ap_thread_mutex *mtx;

    mtx = malloc(sizeof(ap_thread_mutex));
    InitializeCriticalSection(&(mtx->_mutex));
    return mtx;
}


API_EXPORT(void) ap_thread_mutex_lock(ap_thread_mutex *mtx)
{
    EnterCriticalSection(&(mtx->_mutex));
}


API_EXPORT(void) ap_thread_mutex_unlock(ap_thread_mutex *mtx)
{
    LeaveCriticalSection(&(mtx->_mutex));
}

API_EXPORT(void) ap_thread_mutex_destroy(ap_thread_mutex *mtx)
{
    DeleteCriticalSection(&(mtx->_mutex));
    free(mtx);
}

static const command_rec winnt_cmds[] = {
LISTEN_COMMANDS
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
//{ "ScoreBoardFile", set_scoreboard, NULL, RSRC_CONF, TAKE1,
//    "A file for Apache to maintain runtime process management information"},
{ "ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF, TAKE1,
  "Number of threads each child creates" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ NULL }
};

module MODULE_VAR_EXPORT mpm_winnt_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    winnt_cmds,		        /* command table */
    NULL,			/* handlers */
    winnt_hooks 		/* register_hooks */
};
