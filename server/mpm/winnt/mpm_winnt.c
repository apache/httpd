/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "apr_portable.h"
#include "apr_getopt.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "ap_mpm.h"
#include "ap_config.h"
#include "ap_listen.h"
#include "mpm_default.h"
#include "mpm_winnt.h"
#include "mpm_common.h"

typedef HANDLE thread;
#ifdef CONTAINING_RECORD
#undef CONTAINING_RECORD
#endif
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (PCHAR)(&((type *)0)->field)))
#define PADDED_ADDR_SIZE sizeof(SOCKADDR_IN)+16

typedef struct CompContext {
    struct CompContext *next;
    OVERLAPPED Overlapped;
    apr_socket_t *sock;
    SOCKET accept_socket;
    char buff[2*PADDED_ADDR_SIZE];
    struct sockaddr *sa_server;
    int sa_server_len;
    struct sockaddr *sa_client;
    int sa_client_len;
    apr_pool_t *ptrans;
} COMP_CONTEXT, *PCOMP_CONTEXT;

typedef enum {
    IOCP_CONNECTION_ACCEPTED = 1,
    IOCP_WAIT_FOR_RECEIVE = 2,
    IOCP_WAIT_FOR_TRANSMITFILE = 3,
    IOCP_SHUTDOWN = 4
} io_state_e;

/* Queue for managing the passing of COMP_CONTEXTs from 
 * the accept thread to the worker threads and back again
 */
apr_lock_t  *qlock;
COMP_CONTEXT *qhead = NULL;
COMP_CONTEXT *qtail = NULL;

static HANDLE ThreadDispatchIOCP = NULL;

/* Definitions of WINNT MPM specific config globals */
static server_rec *server_conf;
static apr_pool_t *pconf;
static apr_pool_t *pchild = NULL;
static int workers_may_exit = 0;
static int shutdown_in_progress = 0;
static unsigned int g_blocked_threads = 0;
static int ap_max_requests_per_child=0;

static HANDLE shutdown_event;	/* used to signal the parent to shutdown */
static HANDLE restart_event;	/* used to signal the parent to restart */
static HANDLE exit_event;       /* used by parent to signal the child to exit */
static HANDLE maintenance_event;

static char ap_coredump_dir[MAX_STRING_LEN];

static int one_process = 0;
static char const* signal_arg = NULL;

OSVERSIONINFO osver; /* VER_PLATFORM_WIN32_NT */

apr_lock_t *start_mutex;
static DWORD my_pid;
static DWORD parent_pid;

int ap_threads_per_child = 0;
int ap_daemons_to_start=0;

/* ap_get_max_daemons and ap_my_generation are used by the scoreboard
 * code
 */
ap_generation_t volatile ap_my_generation=0; /* Used by the scoreboard */

/* This is the helper code to resolve late bound entry points 
 * missing from one or more releases of the Win32 API...
 * but it sure would be nice if we didn't duplicate this code
 * from the APR ;-)
 */
static const char* const lateDllName[DLL_defined] = {
    "kernel32", "advapi32", "mswsock",  "ws2_32"  };
static HMODULE lateDllHandle[DLL_defined] = {
    NULL,       NULL,       NULL,       NULL      };

FARPROC ap_load_dll_func(ap_dlltoken_e fnLib, char* fnName, int ordinal)
{
    if (!lateDllHandle[fnLib]) { 
        lateDllHandle[fnLib] = LoadLibrary(lateDllName[fnLib]);
        if (!lateDllHandle[fnLib])
            return NULL;
    }
    if (ordinal)
        return GetProcAddress(lateDllHandle[fnLib], (char *) ordinal);
    else
        return GetProcAddress(lateDllHandle[fnLib], fnName);
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
    apr_set_os_error(0);
    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)
	|| apr_get_os_error()) {
        LocalFree( pSD );
        LocalFree( sa );
        return NULL;
    }
    if (!SetSecurityDescriptorDacl(pSD, TRUE, (PACL) NULL, FALSE)
	|| apr_get_os_error()) {
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
                min(MAXIMUM_WAIT_OBJECTS, nCount - (dwIndex * MAXIMUM_WAIT_OBJECTS)),
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
/*
 * Initialise the signal names, in the global variables signal_name_prefix, 
 * signal_restart_name and signal_shutdown_name.
 */
#define MAX_SIGNAL_NAME 30  /* Long enough for apPID_shutdown, where PID is an int */
char signal_name_prefix[MAX_SIGNAL_NAME];
char signal_restart_name[MAX_SIGNAL_NAME]; 
char signal_shutdown_name[MAX_SIGNAL_NAME];
void setup_signal_names(char *prefix)
{
    apr_snprintf(signal_name_prefix, sizeof(signal_name_prefix), prefix);    
    apr_snprintf(signal_shutdown_name, sizeof(signal_shutdown_name), 
	"%s_shutdown", signal_name_prefix);    
    apr_snprintf(signal_restart_name, sizeof(signal_restart_name), 
	"%s_restart", signal_name_prefix);    
}

void signal_parent(int type)
{
    HANDLE e;
    char *signal_name;
    
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
	ap_log_error(APLOG_MARK, APLOG_EMERG, apr_get_os_error(), server_conf,
                     "OpenEvent on %s event", signal_name);
	return;
    }
    if (SetEvent(e) == 0) {
	/* Same problem as above */
	ap_log_error(APLOG_MARK, APLOG_EMERG, apr_get_os_error(), server_conf,
                     "SetEvent on %s event", signal_name);
	CloseHandle(e);
	return;
    }
    CloseHandle(e);
}

static int volatile is_graceful = 0;

AP_DECLARE(int) ap_graceful_stop_signalled(void)
{
    return is_graceful;
}

AP_DECLARE(void) ap_start_shutdown(void)
{
    signal_parent(0);
}

AP_DECLARE(void) ap_start_restart(int gracefully)
{
    is_graceful = gracefully;
    signal_parent(1);
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

/* 
 * get_listeners_from_parent()
 * The listen sockets are opened in the parent. This function, which runs
 * exclusively in the child process, receives them from the parent and
 * makes them availeble in the child.
 */
static int get_listeners_from_parent(server_rec *s)
{
    WSAPROTOCOL_INFO WSAProtocolInfo;
    HANDLE pipe;
    ap_listen_rec *lr;
    DWORD BytesRead;
    int num_listeners = 0;
    SOCKET nsd;

    /* Set up a default listener if necessary */
    if (ap_listeners == NULL) {
        ap_listen_rec *lr;
        lr = apr_palloc(s->process->pool, sizeof(ap_listen_rec));
        if (!lr)
            return 0;
        lr->sd = NULL;
        lr->next = ap_listeners;
        ap_listeners = lr;
    }

    /* Open the pipe to the parent process to receive the inherited socket
     * data. The sockets have been set to listening in the parent process.
     */
    pipe = GetStdHandle(STD_INPUT_HANDLE);
    for (lr = ap_listeners; lr; lr = lr->next) {
        if (!ReadFile(pipe, &WSAProtocolInfo, sizeof(WSAPROTOCOL_INFO), 
                      &BytesRead, (LPOVERLAPPED) NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                         "setup_inherited_listeners: Unable to read socket data from parent");
            signal_parent(0);	/* tell parent to die */
            exit(1);
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: setup_inherited_listener() read = %d bytes of WSAProtocolInfo.", my_pid);
        nsd = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                        &WSAProtocolInfo, 0, 0);
        if (nsd == INVALID_SOCKET) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), server_conf,
                         "Child %d: setup_inherited_listeners(), WSASocket failed to open the inherited socket.", my_pid);
            signal_parent(0);	/* tell parent to die */
            exit(1);
        }
        apr_os_sock_put(&lr->sd, &nsd, pconf);
        num_listeners++;
    }
    CloseHandle(pipe);
    return num_listeners;
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
    apr_lock_t *jobmutex;
    int jobcount;
} globals;

globals allowed_globals = {NULL, NULL, NULL, NULL, 0};
#define MAX_SELECT_ERRORS 100

static void add_job(int sock)
{
    joblist *new_job;

    new_job = (joblist *) malloc(sizeof(joblist));
    if (new_job == NULL) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "Ouch!  Out of memory in add_job()!");
        return;
    }
    new_job->next = NULL;
    new_job->sock = sock;

    apr_lock_acquire(allowed_globals.jobmutex);

    if (allowed_globals.jobtail != NULL)
	allowed_globals.jobtail->next = new_job;
    allowed_globals.jobtail = new_job;
    if (!allowed_globals.jobhead)
	allowed_globals.jobhead = new_job;
    allowed_globals.jobcount++;
    ReleaseSemaphore(allowed_globals.jobsemaphore, 1, NULL);

    apr_lock_release(allowed_globals.jobmutex);
}

static int remove_job(void)
{
    joblist *job;
    int sock;

    WaitForSingleObject(allowed_globals.jobsemaphore, INFINITE);
    apr_lock_acquire(allowed_globals.jobmutex);

    if (shutdown_in_progress && !allowed_globals.jobhead) {
        apr_lock_release(allowed_globals.jobmutex);
	return (-1);
    }
    job = allowed_globals.jobhead;
    ap_assert(job);
    allowed_globals.jobhead = job->next;
    if (allowed_globals.jobhead == NULL)
	allowed_globals.jobtail = NULL;
    apr_lock_release(allowed_globals.jobmutex);
    sock = job->sock;
    free(job);

    return (sock);
}

static void win9x_accept(void * dummy)
{
    int requests_this_child = 0;
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
        if (ap_max_requests_per_child && (requests_this_child > ap_max_requests_per_child)) {
            break;
	}

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
            ap_log_error(APLOG_MARK, APLOG_INFO, apr_get_netos_error(), server_conf, 
                         "select failed with error %d", apr_get_netos_error());
            count_select_errors++;
            if (count_select_errors > MAX_SELECT_ERRORS) {
                shutdown_in_progress = 1;
                ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_netos_error(), server_conf,
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
            if (csd == INVALID_SOCKET) {
                csd = -1;
            }
        } while (csd < 0 && APR_STATUS_IS_EINTR(apr_get_netos_error()));

	if (csd < 0) {
            if (APR_STATUS_IS_ECONNABORTED(apr_get_netos_error())) {
		ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_netos_error(), server_conf,
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

    if (context == NULL) {
        /* allocate the completion context and the transaction pool */
        context = apr_pcalloc(pconf, sizeof(COMP_CONTEXT));
        if (!context) {
            ap_log_error(APLOG_MARK,APLOG_ERR, apr_get_os_error(), server_conf,
                         "win9x_get_connection: apr_pcalloc() failed. Process will exit.");
            return NULL;
        }
        apr_pool_create(&context->ptrans, pconf);
    }
    

    while (1) {
        apr_pool_clear(context->ptrans);        
        context->accept_socket = remove_job();
        if (context->accept_socket == -1) {
            return NULL;
        }
	len = sizeof(struct sockaddr);
        context->sa_server = apr_palloc(context->ptrans, len);
        if (getsockname(context->accept_socket, 
                        context->sa_server, &len)== SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_netos_error(), server_conf, 
                         "getsockname failed");
            continue;
        }
        len = sizeof(struct sockaddr);
        context->sa_client = apr_palloc(context->ptrans, len);
        if ((getpeername(context->accept_socket,
                         context->sa_client, &len)) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, apr_get_netos_error(), server_conf, 
                         "getpeername failed");
            memset(&context->sa_client, '\0', sizeof(context->sa_client));
        }

        /* do we NEED_DUPPED_CSD ?? */
        
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
static void winnt_accept(void *listen_socket) 
{
    static int num_completion_contexts = 0;
    static int requests_this_child = 0;
    PCOMP_CONTEXT pCompContext;
    DWORD BytesRead;
    SOCKET nlsd;
    int lasterror;

    nlsd = (SOCKET) listen_socket;

    while (!shutdown_in_progress) {
        if (ap_max_requests_per_child && (requests_this_child > ap_max_requests_per_child)) {
            break;
	}
        pCompContext = NULL;
        /* Grab a context off the queue */
        apr_lock_acquire(qlock);
        if (qhead) {
            pCompContext = qhead;
            qhead = qhead->next;
            if (!qhead)
                qtail = NULL;
        }
        apr_lock_release(qlock);

        /* If we failed to grab a context off the queue, alloc one out of 
         * the child pool. There may be up to ap_threads_per_child contexts
         * in the system at once.
         */
        if (!pCompContext) {
            if (num_completion_contexts >= ap_threads_per_child) {
                static int reported = 0;
                if (!reported) {
                    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, server_conf,
                                 "Server ran out of threads to serve requests. Consider "
                                 "raising the ThreadsPerChild setting");
                    reported = 1;
                }
                Sleep(500);
                continue;
            }
            pCompContext = (PCOMP_CONTEXT) apr_pcalloc(pchild, sizeof(COMP_CONTEXT));

            pCompContext->Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); 
            if (pCompContext->Overlapped.hEvent == NULL) {
                ap_log_error(APLOG_MARK,APLOG_ERR, apr_get_os_error(), server_conf,
                             "winnt_accept: CreateEvent failed. Process will exit.");
                // return -1;
            }
            pCompContext->accept_socket = INVALID_SOCKET;
            num_completion_contexts++;
        }

    again:            
        /* Create and initialize the accept socket */
        if (pCompContext->accept_socket == INVALID_SOCKET) {
            pCompContext->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        
            if (pCompContext->accept_socket == INVALID_SOCKET) {
                ap_log_error(APLOG_MARK,APLOG_ERR, apr_get_netos_error(), server_conf,
                             "winnt_accept: socket() failed. Process will exit.");
                // return -1;
            }

            /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */
            if (setsockopt(pCompContext->accept_socket, SOL_SOCKET,
                           SO_UPDATE_ACCEPT_CONTEXT, (char *)&nlsd,
                           sizeof(nlsd))) {
                ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_netos_error(), server_conf,
                             "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed.");
                /* Not a failure condition. Keep running. */
            }
        }

        /* AcceptEx on the completion context. The completion context will be 
         * signaled when a connection is accepted. 
         */
        if (!AcceptEx(nlsd, pCompContext->accept_socket,
                      pCompContext->buff,
                      0,
                      PADDED_ADDR_SIZE, 
                      PADDED_ADDR_SIZE,
                      &BytesRead,
                      &pCompContext->Overlapped)) {
            lasterror = apr_get_netos_error();
            if (lasterror == APR_FROM_OS_ERROR(WSAEINVAL)) {
                /* Hack alert. Occasionally, TransmitFile will not recycle the 
                 * accept socket (usually when the client disconnects early). 
                 * Get a new socket and try the call again.
                 */
                pCompContext->accept_socket = INVALID_SOCKET;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, lasterror, server_conf,
                             "winnt_accept: AcceptEx failed. Reallocate the accept socket and try again.");
                if (shutdown_in_progress)
                    break;
                else
                    goto again;
            }
            else if (lasterror != APR_FROM_OS_ERROR(ERROR_IO_PENDING)) {
                ap_log_error(APLOG_MARK,APLOG_ERR, lasterror, server_conf,
                             "winnt_accept: AcceptEx failed. Process will exit.");
                // return -1;
            }

            /* Wait for pending i/o */
            WaitForSingleObject(pCompContext->Overlapped.hEvent, INFINITE);
        }

        /* When a connection is received, send an io completion notification to
         * the ThreadDispatchIOCP
         */
        PostQueuedCompletionStatus(ThreadDispatchIOCP, 0, IOCP_CONNECTION_ACCEPTED,
                                   &pCompContext->Overlapped);
        requests_this_child++;
    }

    if (!shutdown_in_progress) {
        /* Yow, hit an irrecoverable error! Tell the child to die. */
        SetEvent(exit_event);
    }
}
static PCOMP_CONTEXT winnt_get_connection(PCOMP_CONTEXT pCompContext)
{
    int requests_this_child = 0;
    int rc;
    DWORD BytesRead;
    DWORD CompKey;
    LPOVERLAPPED pol;

    /* Recycle the completion context.
     * - destroy the ptrans pool
     * - put the context on the queue to be consumed by the accept thread
     * Note: pCompContext->accept_socket may be in a disconnected
     * but reusable state so -don't- close it.
     */
    if (pCompContext) {
        apr_pool_clear(pCompContext->ptrans);
        apr_pool_destroy(pCompContext->ptrans);
        pCompContext->ptrans = NULL;
        pCompContext->next = NULL;
        apr_lock_acquire(qlock);
        if (qtail)
            qtail->next = pCompContext;
        else
            qhead = pCompContext;
        qtail = pCompContext;
        apr_lock_release(qlock);
    }

    g_blocked_threads++;        
    while (1) {
        if (workers_may_exit) {
            g_blocked_threads--;
            return NULL;
        }
        rc = GetQueuedCompletionStatus(ThreadDispatchIOCP, &BytesRead, &CompKey,
                                       &pol, INFINITE);
        if (!rc) {
            rc = apr_get_os_error();
            ap_log_error(APLOG_MARK,APLOG_DEBUG, rc, server_conf,
                             "Child %d: GetQueuedComplationStatus returned %d", my_pid, rc);
            continue;
        }

        switch (CompKey) {
        case IOCP_CONNECTION_ACCEPTED:
            pCompContext = CONTAINING_RECORD(pol, COMP_CONTEXT, Overlapped);
            break;
        case IOCP_SHUTDOWN:
            g_blocked_threads--;
            return NULL;
        default:
            g_blocked_threads--;
            return NULL;
        }
        break;
    }

    g_blocked_threads--;    

    if ((rc = apr_pool_create(&pCompContext->ptrans, pconf)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK,APLOG_DEBUG, rc, server_conf,
                     "Child %d: apr_pool_create failed with rc %d", my_pid, rc);
    }

    /* Get the local & remote address */
    GetAcceptExSockaddrs(pCompContext->buff,
                         0,
                         PADDED_ADDR_SIZE,
                         PADDED_ADDR_SIZE,
                         &pCompContext->sa_server,
                         &pCompContext->sa_server_len,
                         &pCompContext->sa_client,
                         &pCompContext->sa_client_len);

    return pCompContext;

}

/*
 * worker_main()
 * Main entry point for the worker threads. Worker threads block in 
 * win*_get_connection() awaiting a connection to service.
 */
static void worker_main(int thread_num)
{
    PCOMP_CONTEXT context = NULL;
    apr_os_sock_info_t sockinfo;

    while (1) {
        conn_rec *c;
        apr_int32_t disconnected;

        ap_update_child_status(0, thread_num, SERVER_READY, 
                               (request_rec *) NULL);

        /* Grab a connection off the network */
        if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
            context = win9x_get_connection(context);
        }
        else {
            context = winnt_get_connection(context);
        }

        if (!context)
            break;

        sockinfo.os_sock = &context->accept_socket;
        sockinfo.local   = context->sa_server;
        sockinfo.remote  = context->sa_client;
        sockinfo.family  = APR_INET;
        sockinfo.type    = SOCK_STREAM;
        /* ### is this correct?  Shouldn't be inheritable (at this point) */
        apr_os_sock_make(&context->sock, &sockinfo, context->ptrans);

        c = ap_new_connection(context->ptrans, server_conf, context->sock,
                              thread_num);

        if (c) {
            ap_process_connection(c);
            apr_getsocketopt(context->sock, APR_SO_DISCONNECTED, &disconnected);
            if (!disconnected) {
                context->accept_socket = INVALID_SOCKET;
                ap_lingering_close(c);
            }
        }
        else {
            /* ap_new_connection closes the socket on failure */
            context->accept_socket = INVALID_SOCKET;
        }
    }

    ap_update_child_status(0, thread_num, SERVER_DEAD, (request_rec *) NULL);

    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                 "Child %d: Thread exiting.", my_pid);
}

static void cleanup_thread(thread *handles, int *thread_cnt, int thread_to_clean)
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
static void child_main()
{
    apr_status_t status;
    HANDLE child_events[2];
    char* exit_event_name;
    int nthreads = ap_threads_per_child;
    int tid;
    thread *child_handles;
    int rv;
    time_t end_time;
    int i;
    int cld;

    /* This is the child process or we are running in single process mode. */
    exit_event_name = apr_psprintf(pconf, "apC%d", my_pid);
    setup_signal_names(apr_psprintf(pconf,"ap%d", parent_pid));

    if (one_process) {
        /* Single process mode */
        apr_lock_create(&start_mutex, APR_MUTEX, APR_CROSS_PROCESS,
                        signal_name_prefix, pconf);
        exit_event = CreateEvent(NULL, TRUE, FALSE, exit_event_name);
    }
    else {
        /* Child process mode */
        apr_lock_child_init(&start_mutex, signal_name_prefix, pconf);
        exit_event = OpenEvent(EVENT_ALL_ACCESS, FALSE, exit_event_name);
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: exit_event_name = %s", my_pid, exit_event_name);
    }

    /* Initialize the child_events */
    maintenance_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    child_events[0] = exit_event;
    child_events[1] = maintenance_event;

    ap_assert(start_mutex);
    ap_assert(exit_event);
    ap_assert(maintenance_event);

    apr_pool_create(&pchild, pconf);
    allowed_globals.jobsemaphore = CreateSemaphore(NULL, 0, 1000000, NULL);
    apr_lock_create(&allowed_globals.jobmutex, APR_MUTEX, APR_INTRAPROCESS, NULL, pchild);

    /*
     * Wait until we have permission to start accepting connections.
     * start_mutex is used to ensure that only one child ever
     * goes into the listen/accept loop at once.
     */
    status = apr_lock_acquire(start_mutex);
    if (status != APR_SUCCESS) {
	ap_log_error(APLOG_MARK,APLOG_ERR, status, server_conf,
                     "Child %d: Failed to acquire the start_mutex. Process will exit.", my_pid);
        signal_parent(0);	/* tell parent to die */
	exit(0);
    }
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Acquired the start mutex.", my_pid);

    /*
     * Create the worker thread dispatch IOCompletionPort
     * on Windows NT/2000
     */
    if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS) {
        /* Create the worker thread dispatch IOCP */
        ThreadDispatchIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                                    NULL,
                                                    0,
                                                    0); /* CONCURRENT ACTIVE THREADS */
        apr_lock_create(&qlock, APR_MUTEX, APR_INTRAPROCESS, NULL, pchild);
    }

    /* 
     * Create the pool of worker threads
     */
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Starting %d worker threads.", my_pid, nthreads);
    child_handles = (thread) alloca(nthreads * sizeof(int));
    for (i = 0; i < nthreads; i++) {
        ap_update_child_status(0, i, SERVER_STARTING, (request_rec *) NULL);
        child_handles[i] = (thread) _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE) worker_main,
                                                   (void *) i, 0, &tid);
    }

    /* 
     * Start the accept thread
     */
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE) win9x_accept,
                       (void *) i, 0, &tid);
    } else {
        /* Start an accept thread per listener */
        SOCKET nlsd; /* native listening sock descriptor */
        ap_listen_rec *lr;
        for (lr = ap_listeners; lr; lr = lr->next) {
            if (lr->sd != NULL) {
                apr_os_sock_get(&nlsd, lr->sd);
                _beginthreadex(NULL, 1000, (LPTHREAD_START_ROUTINE) winnt_accept,
                               (void *) nlsd, 0, &tid);
            }
        }
    }

    /* Wait for one of three events:
     * exit_event: 
     *    The exit_event is signaled by the parent process to notify 
     *    the child that it is time to exit.
     *
     * maintenance_event: 
     *    This event is signaled by the worker thread pool to direct 
     *    this thread to create more completion contexts.
     *
     * TIMEOUT:
     *    To do periodic maintenance on the server (check for thread exits,
     *    number of completion contexts, etc.)
     */
    while (1) {
        rv = WaitForMultipleObjects(2, (HANDLE *) child_events, FALSE, 1000);
        cld = rv - WAIT_OBJECT_0;
        if (rv == WAIT_FAILED) {
            /* Something serious is wrong */
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                         "Child %d: WAIT_FAILED -- shutting down server");
            break;
        }
        else if (rv == WAIT_TIMEOUT) {
            apr_proc_other_child_check();
        }
        else if (cld == 0) {
            /* Exit event was signaled */
            ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                         "Child %d: Exit event signaled. Child process is ending.", my_pid);
            break;
        }
        else {
            /* Child maintenance event signaled */
            ResetEvent(maintenance_event);
            ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                         "Child %d: Child maintenance event signaled.", my_pid);
        }
    }

    /* Setting is_graceful will cause keep-alive connections to be closed
     * rather than block on the next network read.
     */
    is_graceful = 1;

    /* Setting shutdown_in_progress prevents new connections from
     * being accepted but allows the worker threads to continue
     * handling connections that have already been accepted.
     */
    shutdown_in_progress = 1;

    /* Close the listening sockets */
    {
        ap_listen_rec *lr;
        for (lr = ap_listeners; lr ; lr = lr->next) {
            apr_socket_close(lr->sd);
        }
    }

    /* Give the worker threads time to handle already accepted connections */
    Sleep(1000);

    /* Release the start_mutex to let the new process (in the restart
     * scenario) a chance to begin accepting and servicing requests 
     */
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Releasing the start mutex", my_pid);
    apr_lock_release(start_mutex);

    /* Tell the worker threads they may exit when done handling
     * a connection.
     */
    workers_may_exit = 1;

    /* Shutdown the worker threads */
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        for (i = 0; i < nthreads; i++) {
            add_job(-1);
        }
    }
    else { /* Windows NT/2000 */
        /* Post worker threads blocked on the ThreadDispatch IOCompletion port */
        while (g_blocked_threads > 0) {
            ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                         "Child %d: %d threads blocked on the completion port", my_pid, g_blocked_threads);
            for (i=g_blocked_threads; i > 0; i--) {
                PostQueuedCompletionStatus(ThreadDispatchIOCP, 0, IOCP_SHUTDOWN, NULL);
            }
            Sleep(1000);
        }
        /* Empty the accept queue of completion contexts */
        apr_lock_acquire(qlock);
        while (qhead) {
            CloseHandle(qhead->Overlapped.hEvent);
            closesocket(qhead->accept_socket);
            qhead = qhead->next;
        }
        apr_lock_release(qlock);
    }

    /* Give busy worker threads a chance to service their connections */
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Waiting for %d threads to die.", my_pid, nthreads);
    end_time = time(NULL) + 180;
    while (nthreads) {
        rv = wait_for_many_objects(nthreads, child_handles, end_time - time(NULL));
	if (rv != WAIT_TIMEOUT) {
	    rv = rv - WAIT_OBJECT_0;
	    ap_assert((rv >= 0) && (rv < nthreads));
	    cleanup_thread(child_handles, &nthreads, rv);
            continue;
        }
        break;
    }

    /* Kill remaining threads off the hard way */
    for (i = 0; i < nthreads; i++) {
        TerminateThread(child_handles[i], 1);
        CloseHandle(child_handles[i]);
    }
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: All worker threads have ended.", my_pid);

    CloseHandle(allowed_globals.jobsemaphore);
    apr_lock_destroy(allowed_globals.jobmutex);
    if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS)
    	apr_lock_destroy(qlock);

    apr_pool_destroy(pchild);
    CloseHandle(exit_event);
}

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

static int create_process(apr_pool_t *p, HANDLE *handles, HANDLE *events, int *processes)
{
    int rv;
    char buf[1024];
    char *pCommand;
    char *pEnvVar;
    char *pEnvBlock;
    int i;
    int iEnvBlockLen;
    STARTUPINFO si;           /* Filled in prior to call to CreateProcess */
    PROCESS_INFORMATION pi;   /* filled in on call to CreateProcess */

    ap_listen_rec *lr;
    DWORD BytesWritten;
    HANDLE hPipeRead = NULL;
    HANDLE hPipeWrite = NULL;
    SECURITY_ATTRIBUTES sa = {0};  

    HANDLE kill_event;
    LPWSAPROTOCOL_INFO  lpWSAProtocolInfo;

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* Build the command line. Should look something like this:
     * C:/apache/bin/apache.exe -f ap_server_confname 
     * First, get the path to the executable...
     */
    rv = GetModuleFileName(NULL, buf, sizeof(buf));
    if (rv == sizeof(buf)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, ERROR_BAD_PATHNAME, server_conf,
                     "Parent: Path to Apache process too long");
        return -1;
    } else if (rv == 0) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                     "Parent: GetModuleFileName() returned NULL for current process.");
        return -1;
    }

    /* Build the command line */
    pCommand = apr_psprintf(p, "\"%s\"", buf);  
    for (i = 1; i < server_conf->process->argc; i++) {
        pCommand = apr_pstrcat(p, pCommand, " \"", server_conf->process->argv[i], "\"", NULL);
    }

    /* Build the environment, since Win9x disrespects the active env */
    pEnvVar = apr_psprintf(p, "AP_PARENT_PID=%i", parent_pid);
    /*
     * Win32's CreateProcess call requires that the environment
     * be passed in an environment block, a null terminated block of
     * null terminated strings.
     */  
    i = 0;
    iEnvBlockLen = 1;
    while (_environ[i]) {
        iEnvBlockLen += strlen(_environ[i]) + 1;
        i++;
    }

    pEnvBlock = (char *)apr_pcalloc(p, iEnvBlockLen + strlen(pEnvVar) + 1);
    strcpy(pEnvBlock, pEnvVar);
    pEnvVar = strchr(pEnvBlock, '\0') + 1;

    i = 0;
    while (_environ[i]) {
        strcpy(pEnvVar, _environ[i]);
        pEnvVar = strchr(pEnvVar, '\0') + 1;
        i++;
    }
    pEnvVar = '\0';
    /* Create a pipe to send socket info to the child */
    if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                     "Parent: Unable to create pipe to child process.");
        return -1;
    }

    /* Give the read end of the pipe (hPipeRead) to the child as stdin. The 
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
                       pEnvBlock,          /* Environment block */
                       NULL,
                       &si, &pi)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                     "Parent: Not able to create the child process.");
        /*
         * We must close the handles to the new process and its main thread
         * to prevent handle and memory leaks.
         */ 
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }
    
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                 "Parent: Created child process %d", pi.dwProcessId);

    SetEnvironmentVariable("AP_PARENT_PID",NULL);

    /* Create the exit_event, apCchild_pid */
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;        
    kill_event = CreateEvent(&sa, TRUE, FALSE, apr_psprintf(pconf,"apC%d", pi.dwProcessId));
    if (!kill_event) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
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

    /* Important:
     * Give the child process a chance to run before dup'ing the sockets.
     * We have already set the listening sockets noninheritable, but if 
     * WSADuplicateSocket runs before the child process initializes
     * the listeners will be inherited anyway.
     */
    Sleep(1000);

    /* Run the chain of open sockets. For each socket, duplicate it 
     * for the target process then send the WSAPROTOCOL_INFO 
     * (returned by dup socket) to the child.
     */
    for (lr = ap_listeners; lr; lr = lr->next) {
        int nsd;
        lpWSAProtocolInfo = apr_pcalloc(p, sizeof(WSAPROTOCOL_INFO));
        apr_os_sock_get(&nsd,lr->sd);
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Parent: Duplicating socket %d and sending it to child process %d", nsd, pi.dwProcessId);
        if (WSADuplicateSocket(nsd, pi.dwProcessId,
                               lpWSAProtocolInfo) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), server_conf,
                         "Parent: WSADuplicateSocket failed for socket %d. Check the FAQ.", lr->sd );
            return -1;
        }

        if (!WriteFile(hPipeWrite, lpWSAProtocolInfo, (DWORD) sizeof(WSAPROTOCOL_INFO),
                       &BytesWritten,
                       (LPOVERLAPPED) NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                         "Parent: Unable to write duplicated socket %d to the child.", lr->sd );
            return -1;
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, server_conf,
                     "Parent: BytesWritten = %d WSAProtocolInfo = %x20", BytesWritten, *lpWSAProtocolInfo);
    }

    CloseHandle(hPipeRead);
    CloseHandle(hPipeWrite);        

    return 0;
}

/**********************************************************************
 * master_main()
 * This is the parent process. master_main() creates a multithreaded
 * child process to handle connections, then blocks waiting to receive
 * a shutdown, restart event or child exit event. 
 * 
 * restart_event 
 * - Child is signaled to die gracefully
 * shutdown_event 
 * - Child is signaled to die gracefully
 * child_exit_event 
 * - Child has died, either normally (max_request_per_child)
 * or abnormally (seg fault, irrecoverable error condition detected by the 
 * child)
 **********************************************************************/
#define MAX_PROCESSES 50 /* must be < MAX_WAIT_OBJECTS-1 */
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


    /* Create child process 
     * Should only be one in this version of Apache for WIN32 
     */
    while (remaining_children_to_start--) {
        if (create_process(pconf, process_handles, process_kill_events, 
                           &current_live_processes) < 0) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                         "master_main: create child process failed. Exiting.");
            shutdown_pending = 1;
            goto die_now;
        }
    }
    
    restart_pending = shutdown_pending = 0;

    if (!strcasecmp(signal_arg, "runservice"))
        mpm_service_started();

    /* Wait for shutdown or restart events or for child death */
    process_handles[current_live_processes] = shutdown_event;
    process_handles[current_live_processes+1] = restart_event;

    rv = WaitForMultipleObjects(current_live_processes+2, (HANDLE *)process_handles, 
                                FALSE, INFINITE);
    cld = rv - WAIT_OBJECT_0;
    if (rv == WAIT_FAILED) {
        /* Something serious is wrong */
        ap_log_error(APLOG_MARK,APLOG_CRIT, apr_get_os_error(), server_conf,
                     "master_main: WaitForMultipeObjects WAIT_FAILED -- doing server shutdown");
        shutdown_pending = 1;
    }
    else if (rv == WAIT_TIMEOUT) {
        /* Hey, this cannot happen */
        ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                     "master_main: WaitForMultipeObjects with INFINITE wait exited with WAIT_TIMEOUT");
        shutdown_pending = 1;
    }
    else if (cld == current_live_processes) {
        /* shutdown_event signalled */
        shutdown_pending = 1;
        printf("shutdown event signaled\n");
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, s, 
                     "Parent: SHUTDOWN EVENT SIGNALED -- Shutting down the server.");
        if (ResetEvent(shutdown_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                         "ResetEvent(shutdown_event)");
        }

    }
    else if (cld == current_live_processes+1) {
        /* restart_event signalled */
        int children_to_kill = current_live_processes;
        restart_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s, 
                     "Parent: RESTART EVENT SIGNALED -- Restarting the server.");
        if (ResetEvent(restart_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                         "master_main: ResetEvent(restart_event) failed.");
        }
        /* Signal each child process to die 
         * We are making a big assumption here that the child process, once signaled,
         * will REALLY go away. Since this is a restart, we do not want to hold the 
         * new child process up waiting for the old child to die. Remove the old 
         * child out of the process_handles apr_table_t and hope for the best...
         */
        for (i = 0; i < children_to_kill; i++) {
            if (SetEvent(process_kill_events[i]) == 0)
                ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                             "master_main: SetEvent for child process in slot #%d failed", i);
            cleanup_process(process_handles, process_kill_events, i, &current_live_processes);
        }
    } 
    else {
        /* A child process must have exited because of a fatal error condition (seg fault, etc.). 
         * Remove the dead process 
         * from the process_handles and process_kill_events apr_table_t and create a new
         * child process.
         * TODO: Consider restarting the child immediately without looping through http_main
         * and without rereading the configuration. Will need this if we ever support multiple 
         * children. One option, create a parent thread which waits on child death and restarts it.
         * Consider, however, that if the user makes httpd.conf invalid, we want to die before
         * our child tries it... otherwise we have a nasty loop.
         */
        restart_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, server_conf, 
                     "Parent: CHILD PROCESS FAILED -- Restarting the child process.");
        ap_assert(cld < current_live_processes);
        cleanup_process(process_handles, process_kill_events, cld, &current_live_processes);
        /* APD2("main_process: child in slot %d died", rv); */
        /* restart_child(process_hancles, process_kill_events, cld, &current_live_processes); */
    }

die_now:
    if (shutdown_pending) 
    {
        int tmstart = time(NULL);
        
        if (strcasecmp(signal_arg, "runservice")) {
            mpm_service_stopping();
        }
        /* Signal each child processes to die */
        for (i = 0; i < current_live_processes; i++) {
            printf("SetEvent handle = %d\n", process_kill_events[i]);
            if (SetEvent(process_kill_events[i]) == 0)
                ap_log_error(APLOG_MARK,APLOG_ERR, apr_get_os_error(), server_conf,
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
            ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, APR_SUCCESS, server_conf,
                         "Parent: Forcing termination of child #%d (handle %d)", i, process_handles[i]);
            TerminateProcess((HANDLE) process_handles[i], 1);
        }
        return 0;  /* Tell the caller we do not want to restart */
    }

    return 1;      /* Tell the caller we want a restart */
}

/* set_listeners_noninheritable()
 * Make the listening socket handles noninheritable by processes
 * started out of this process.
 */
static int set_listeners_noninheritable(apr_pool_t *p) 
{
    ap_listen_rec *lr;
    HANDLE dup;
    SOCKET nsd;
    HANDLE hProcess = GetCurrentProcess();

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_os_sock_get(&nsd,lr->sd);
        if (!DuplicateHandle(hProcess, (HANDLE) nsd, hProcess, &dup, 0,
                             FALSE,     /* Inherit flag */
                             DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), 
                         server_conf,
                         "set_listeners_noninheritable: DuplicateHandle failed.");
            return 0;
        }
        nsd = (SOCKET) dup;
        apr_os_sock_put(&lr->sd, &nsd, p);
    }
    return 1;
}

/* service_nt_main_fn needs to append the StartService() args 
 * outside of our call stack and thread as the service starts...
 */
apr_array_header_t *mpm_new_argv;

/* Remember service_to_start failures to log and fail in pre_config.
 * Remember inst_argc and inst_argv for installing or starting the
 * service after we preflight the config.
 */

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = MAXIMUM_WAIT_OBJECTS;
            return APR_SUCCESS;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_STATIC;
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
            *result = ap_threads_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DEAMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:    
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DEAMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
} 

#define SERVICE_UNSET (-1)
static apr_status_t service_set = SERVICE_UNSET;
static apr_status_t service_to_start_success;
static int inst_argc;
static const char * const *inst_argv;
static char *service_name = NULL;
    
void winnt_rewrite_args(process_rec *process) 
{
    /* Handle the following SCM aspects in this phase:
     *
     *   -k runservice [transition for WinNT, nothing for Win9x]
     *   -k (!)install [error out if name is not installed]
     *
     * We can't leave this phase until we know our identity
     * and modify the command arguments appropriately.
     */
    apr_status_t rv;
    char *def_server_root;
    char fnbuf[MAX_PATH];
    char optbuf[3];
    const char *optarg;
    int fixed_args;
    char *pid;
    apr_getopt_t *opt;
    int running_as_service = 1;

    osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osver);

    /* AP_PARENT_PID is only valid in the child */
    pid = getenv("AP_PARENT_PID");
    if (pid) 
    {
        /* This is the child */
        my_pid = GetCurrentProcessId();
        parent_pid = (DWORD) atol(pid);

        /* The parent is responsible for providing the
         * COMPLETE ARGUMENTS REQUIRED to the child.
         *
         * No further argument parsing is needed, but
         * for good measure we will provide a simple
         * signal string for later testing.
         */
        signal_arg = "runchild";
        return;
    }
    
    /* This is the parent, we have a long way to go :-) */
    parent_pid = my_pid = GetCurrentProcessId();
    
    /* Rewrite process->argv[]; 
     *
     * strip out -k signal into signal_arg
     * strip out -n servicename and set the names
     * add default -d serverroot from the path of this executable
     * 
     * The end result will look like:
     *
     * The invocation command (%0)
     *     The -d serverroot default from the running executable
     *         The requested service's (-n) registry ConfigArgs
     *             The WinNT SCM's StartService() args
     */
    if (!GetModuleFileName(NULL, fnbuf, sizeof(fnbuf))) {
        rv = apr_get_os_error();
        ap_log_error(APLOG_MARK,APLOG_CRIT, rv, NULL, 
                     "Failed to get the path of Apache.exe");
        exit(1);
    }
    /* WARNING: There is an implict assumption here that the
     * executable resides in ServerRoot or ServerRoot\bin
     */
    def_server_root = (char *) apr_filename_of_pathname(fnbuf);
    if (def_server_root > fnbuf) {
        *(def_server_root - 1) = '\0';
        def_server_root = (char *) apr_filename_of_pathname(fnbuf);
        if (!strcasecmp(def_server_root, "bin"))
            *(def_server_root - 1) = '\0';
    }
    def_server_root = ap_os_canonical_filename(process->pool, fnbuf);

    /* Use process->pool so that the rewritten argv
     * lasts for the lifetime of the server process,
     * because pconf will be destroyed after the 
     * initial pre-flight of the config parser.
     */
    mpm_new_argv = apr_array_make(process->pool, process->argc + 2,
                                  sizeof(const char *));
    *(const char **)apr_array_push(mpm_new_argv) = process->argv[0];
    *(const char **)apr_array_push(mpm_new_argv) = "-d";
    *(const char **)apr_array_push(mpm_new_argv) = def_server_root;

    fixed_args = mpm_new_argv->nelts;

    optbuf[0] = '-';
    optbuf[2] = '\0';
    apr_getopt_init(&opt, process->pool, process->argc, (char**) process->argv);
    while (apr_getopt(opt, "n:k:iu" AP_SERVER_BASEARGS, 
                      optbuf + 1, &optarg) == APR_SUCCESS) {
        switch (optbuf[1]) {
        case 'n':
            service_set = mpm_service_set_name(process->pool, &service_name, 
                                               optarg);
            break;
        case 'k':
            signal_arg = optarg;
            break;
        case 'i':
            ap_log_error(APLOG_MARK,APLOG_WARNING, 0, NULL,
                "-i is deprecated.  Use -k install.");
            signal_arg = "install";
            break;
        case 'u':
            ap_log_error(APLOG_MARK,APLOG_WARNING, 0, NULL,
                "-u is deprecated.  Use -k uninstall.");
            signal_arg = "uninstall";
            break;
        default:
            *(const char **)apr_array_push(mpm_new_argv) =
                apr_pstrdup(process->pool, optbuf);

            if (optarg) {
                *(const char **)apr_array_push(mpm_new_argv) = optarg;
            }
            break;
        }
    }
    
    /* Track the number of args actually entered by the user */
    inst_argc = mpm_new_argv->nelts - fixed_args;

    /* Provide a default 'run' -k arg to simplify signal_arg tests */
    if (!signal_arg)
    {
        signal_arg = "run";
        running_as_service = 0;
    }

    if (!strcasecmp(signal_arg, "runservice")) 
    {
        /* Start the NT Service _NOW_ because the WinNT SCM is 
         * expecting us to rapidly assume control of our own 
         * process, the SCM will tell us our service name, and
         * may have extra StartService() command arguments to
         * add for us.
         *
         * Any other process has a console, so we don't to begin
         * a Win9x service until the configuration is parsed and
         * any command line errors are reported.
         *
         * We hold the return value so that we can die in pre_config
         * after logging begins, and the failure can land in the log.
         */
        if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT) {
            service_to_start_success = mpm_service_to_start(&service_name);
            if (service_to_start_success == APR_SUCCESS)
                service_set = APR_SUCCESS;
        }
    }

    /* Get the default for any -k option, except run */
    if (service_set == SERVICE_UNSET && strcasecmp(signal_arg, "run")) {
        service_set = mpm_service_set_name(process->pool, &service_name,
                                           AP_DEFAULT_SERVICE_NAME);
    }

    if (!strcasecmp(signal_arg, "install")) /* -k install */
    {
        if (service_set == APR_SUCCESS) 
        {
            ap_log_error(APLOG_MARK,APLOG_ERR, 0, NULL,
                 "%s: Service is already installed.", service_name);
            exit(1);
        }
    }
    else if (running_as_service)
    {
        if (service_set == APR_SUCCESS) 
        {
            rv = mpm_merge_service_args(process->pool, mpm_new_argv, 
                                        fixed_args);
            if (rv == APR_SUCCESS) {
                ap_log_error(APLOG_MARK,APLOG_NOERRNO|APLOG_INFO, 0, NULL,
                             "Using ConfigArgs of the installed service "
                             "\"%s\".", service_name);
            }
	    else  {
                ap_log_error(APLOG_MARK,APLOG_WARNING, rv, NULL,
                             "No installed ConfigArgs for the service "
                             "\"%s\", using Apache defaults.", service_name);
	    }
        }
        else
        {
            ap_log_error(APLOG_MARK,APLOG_ERR, service_set, NULL,
                 "No installed service named \"%s\".", service_name);
            exit(1);
        }
    }
    if (strcasecmp(signal_arg, "install") && service_set && service_set != SERVICE_UNSET) 
    {
        ap_log_error(APLOG_MARK,APLOG_ERR, service_set, NULL,
             "No installed service named \"%s\".", service_name);
        exit(1);
    }
    
    /* Track the args actually entered by the user.
     * These will be used for the -k install parameters, as well as
     * for the -k start service override arguments.
     */
    inst_argv = (const char * const *)mpm_new_argv->elts
        + mpm_new_argv->nelts - inst_argc;

    process->argc = mpm_new_argv->nelts; 
    process->argv = (const char * const *) mpm_new_argv->elts;
}


static void winnt_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp) 
{
    /* Handle the following SCM aspects in this phase:
     *
     *   -k runservice [WinNT errors logged from rewrite_args]
     *   -k uninstall
     *   -k stop
     *
     * in these cases we -don't- care if httpd.conf has config errors!
     */
    apr_status_t rv;

    if (ap_exists_config_define("ONE_PROCESS"))
        one_process = -1;

    if (!strcasecmp(signal_arg, "runservice")
            && (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
            && (service_to_start_success != APR_SUCCESS)) {
        ap_log_error(APLOG_MARK,APLOG_CRIT, service_to_start_success, NULL, 
                     "%s: Unable to start the service manager.",
                     service_name);
        exit(1);
    }

    if (!strcasecmp(signal_arg, "uninstall")) {
        rv = mpm_service_uninstall();
        exit(rv);
    }

    if (!strcasecmp(signal_arg, "stop")) {
        mpm_signal_service(ptemp, 0);
        exit(0);
    }

    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_NUM_DAEMON;
    ap_threads_per_child = DEFAULT_START_THREAD;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void winnt_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec* server)
{
    static int restart_num = 0;
    apr_status_t rv = 0;

    server_conf = server;
    
    /* Handle the following SCM aspects in this phase:
     *
     *   -k install
     *   -k start
     *   -k restart
     *   -k runservice [Win95, only once - after we parsed the config]
     *
     * because all of these signals are useful _only_ if there
     * is a valid conf\httpd.conf environment to start.
     *
     * We reached this phase by avoiding errors that would cause
     * these options to fail unexpectedly in another process.
     */

    if (!strcasecmp(signal_arg, "install")) {
        rv = mpm_service_install(ptemp, inst_argc, inst_argv);
        exit (rv);
    }

    if (!strcasecmp(signal_arg, "start")) {
        rv = mpm_service_start(ptemp, inst_argc, inst_argv);
        exit (rv);
    }

    if (!strcasecmp(signal_arg, "restart")) {
        mpm_signal_service(ptemp, 1);
        exit (rv);
    }

    if (parent_pid == my_pid) 
    {
        if (restart_num++ == 1) 
        {
            /* This code should be run once in the parent and not run
             * across a restart
             */
            PSECURITY_ATTRIBUTES sa = GetNullACL();  /* returns NULL if invalid (Win95?) */
            setup_signal_names(apr_psprintf(pconf,"ap%d", parent_pid));

            ap_log_pid(pconf, ap_pid_fname);
            
            /* Create shutdown event, apPID_shutdown, where PID is the parent 
             * Apache process ID. Shutdown is signaled by 'apache -k shutdown'.
             */
            shutdown_event = CreateEvent(sa, FALSE, FALSE, signal_shutdown_name);
            if (!shutdown_event) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                             "Parent: Cannot create shutdown event %s", signal_shutdown_name);
                CleanNullACL((void *)sa);
                exit(1);
            }

            /* Create restart event, apPID_restart, where PID is the parent 
             * Apache process ID. Restart is signaled by 'apache -k restart'.
             */
            restart_event = CreateEvent(sa, FALSE, FALSE, signal_restart_name);
            if (!restart_event) {
                CloseHandle(shutdown_event);
                ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), server_conf,
                             "Parent: Cannot create restart event %s", signal_restart_name);
                CleanNullACL((void *)sa);
                exit(1);
            }
            CleanNullACL((void *)sa);

            /* Now that we are flying at 15000 feet... 
             * wipe out the Win95 service console,
             * signal the SCM the WinNT service started, or
             * if not a service, setup console handlers instead.
             */
            if (!strcasecmp(signal_arg, "runservice"))
            {
                if (osver.dwPlatformId != VER_PLATFORM_WIN32_NT) 
                {
                    rv = mpm_service_to_start(&service_name);
                    if (rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK,APLOG_ERR, rv, server_conf,
                                     "%s: Unable to start the service manager.",
                                     service_name);
                        exit(1);
                    }            
                }
            }
            else /* ! -k runservice */
            {
                mpm_start_console_handler();
            }

            /* Create the start mutex, apPID, where PID is the parent Apache process ID.
             * Ths start mutex is used during a restart to prevent more than one 
             * child process from entering the accept loop at once.
             */
            apr_lock_create(&start_mutex,APR_MUTEX, APR_CROSS_PROCESS, signal_name_prefix,
                               server_conf->process->pool);
        }
    }
    else /* parent_pid != my_pid */
    {
        mpm_start_child_console_handler();
    }
}

AP_DECLARE(int) ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s )
{
    static int restart = 0;            /* Default is "not a restart" */

    pconf = _pconf;
    server_conf = s;

    if ((parent_pid != my_pid) || one_process) {
        /* Child process or in one_process (debug) mode */
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: Child process is running", my_pid);

        /* Set up the scoreboard. */
        ap_run_pre_mpm(pconf, SB_NOT_SHARED);
        if (one_process) {
            if (ap_setup_listeners(server_conf) < 1) {
                return 1;
            }
        }
        else {
            get_listeners_from_parent(server_conf);
        }
        if (!set_listeners_noninheritable(pconf)) {
            return 1;
        }
        child_main();

        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: Child process is exiting", my_pid);        
        return 1;
    }
    else { 
        /* Parent process */
        if (ap_setup_listeners(server_conf) < 1) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, s,
                         "no listening sockets available, shutting down");
            return 1;
        }
        if (!set_listeners_noninheritable(pconf)) {
            return 1;
        }
        restart = master_main(server_conf, shutdown_event, restart_event);

        if (!restart) {
            /* Shutting down. Clean up... */
            const char *pidfile = ap_server_root_relative (pconf, ap_pid_fname);

            if (pidfile != NULL && unlink(pidfile) == 0) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS,
                             server_conf, "removed PID file %s (pid=%ld)",
                             pidfile, GetCurrentProcessId());
            }
            apr_lock_destroy(start_mutex);

            CloseHandle(restart_event);
            CloseHandle(shutdown_event);

            return 1;
        }
    }  /* Parent process */

    return 0; /* Restart */
}

static void winnt_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(winnt_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(winnt_post_config, NULL, NULL, 0);
}

/* 
 * Command processors 
 */

static const char *set_threads_per_child (cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_per_child = atoi(arg);
    if (ap_threads_per_child > HARD_THREAD_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: ThreadsPerChild of %d exceeds compile time"
                     " limit of %d threads,", ap_threads_per_child, 
                     HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     " lowering ThreadsPerChild to %d. To increase, please"
                     " see the  HARD_THREAD_LIMIT define in %s.", 
                     HARD_THREAD_LIMIT, AP_MPM_HARD_LIMITS_FILE);
        ap_threads_per_child = HARD_THREAD_LIMIT;
    }
    else if (ap_threads_per_child < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: Require ThreadsPerChild > 0, setting to 1");
	ap_threads_per_child = 1;
    }
    return NULL;
}

/* Stub functions until this MPM supports the connection status API */

AP_DECLARE(void) ap_update_connection_status(long conn_id, const char *key, \
                                             const char *value)
{
    /* NOP */
}

AP_DECLARE(void) ap_reset_connection_status(long conn_id)
{
    /* NOP */
}

AP_DECLARE(apr_array_header_t *) ap_get_status_table(apr_pool_t *p)
{
    /* NOP */
    return NULL;
}

static const command_rec winnt_cmds[] = {
LISTEN_COMMANDS
{ "ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF, TAKE1,
  "Number of threads each child creates" },
{ NULL }
};

AP_MODULE_DECLARE_DATA module mpm_winnt_module = {
    MPM20_MODULE_STUFF,
    winnt_rewrite_args,         /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    winnt_cmds,		        /* command apr_table_t */
    winnt_hooks 		/* register_hooks */
};
