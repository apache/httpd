/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
#include "ap_mpm.h"
#include "ap_config.h"
#include "apr_listen.h"
#include "mpm_default.h"
#include "ap_iol.h"
#include "mpm_winnt.h"
#include "mpm_common.h"

/*
 * Definitions of WINNT MPM specific config globals
 */
static int workers_may_exit = 0;
static int shutdown_in_progress = 0;
static unsigned int g_blocked_threads = 0;

static char *ap_pid_fname = NULL;
static int ap_threads_per_child = 0;

static int max_requests_per_child = 0;
static HANDLE shutdown_event;	/* used to signal shutdown to parent */
static HANDLE restart_event;	/* used to signal a restart to parent */

#define MAX_SIGNAL_NAME 30  /* Long enough for apPID_shutdown, where PID is an int */
char signal_name_prefix[MAX_SIGNAL_NAME];
char signal_restart_name[MAX_SIGNAL_NAME]; 
char signal_shutdown_name[MAX_SIGNAL_NAME];

static struct fd_set listenfds;
static int num_listenfds = 0;
static SOCKET listenmaxfd = INVALID_SOCKET;

static apr_pool_t *pconf;		/* Pool for config stuff */

static char ap_coredump_dir[MAX_STRING_LEN];

static server_rec *server_conf;
static HANDLE AcceptExCompPort = NULL;

static int one_process = 0;
static char *signal_arg;

OSVERSIONINFO osver; /* VER_PLATFORM_WIN32_NT */

int ap_max_requests_per_child=0;
int ap_daemons_to_start=0;

static event *exit_event;
HANDLE maintenance_event;
apr_lock_t *start_mutex;
DWORD my_pid;
DWORD parent_pid;

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

static apr_status_t socket_cleanup(void *sock)
{
    apr_socket_t *thesocket = sock;
    SOCKET sd;
    if (apr_get_os_sock(&sd, thesocket) == APR_SUCCESS) {
        closesocket(sd);
    }
    return APR_SUCCESS;
}

/* A bunch or routines from os/win32/multithread.c that need to be merged into APR
 * or thrown out entirely...
 */

typedef void semaphore;
typedef void event;

static semaphore *
create_semaphore(int initial)
{
    return(CreateSemaphore(NULL, initial, 1000000, NULL));
}

static void acquire_semaphore(semaphore *semaphore_id)
{
    int rv;
    
    rv = WaitForSingleObject(semaphore_id, INFINITE);
    
    return;
}

static int release_semaphore(semaphore *semaphore_id)
{
    return(ReleaseSemaphore(semaphore_id, 1, NULL));
}

static void destroy_semaphore(semaphore *semaphore_id)
{
    CloseHandle(semaphore_id);
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
	ap_log_error(APLOG_MARK, APLOG_EMERG, GetLastError(), server_conf,
                     "OpenEvent on %s event", signal_name);
	return;
    }
    if (SetEvent(e) == 0) {
	/* Same problem as above */
	ap_log_error(APLOG_MARK, APLOG_EMERG, GetLastError(), server_conf,
                     "SetEvent on %s event", signal_name);
	CloseHandle(e);
	return;
    }
    CloseHandle(e);
}

static int volatile is_graceful = 0;

API_EXPORT(int) ap_graceful_stop_signalled(void)
{
    return is_graceful;
}

API_EXPORT(void) ap_start_shutdown(void)
{
    signal_parent(0);
}

API_EXPORT(void) ap_start_restart(int gracefully)
{
    is_graceful = gracefully;
    signal_parent(1);
}

/*
 * Initialise the signal names, in the global variables signal_name_prefix, 
 * signal_restart_name and signal_shutdown_name.
 */

void setup_signal_names(char *prefix)
{
    apr_snprintf(signal_name_prefix, sizeof(signal_name_prefix), prefix);    
    apr_snprintf(signal_shutdown_name, sizeof(signal_shutdown_name), 
	"%s_shutdown", signal_name_prefix);    
    apr_snprintf(signal_restart_name, sizeof(signal_restart_name), 
	"%s_restart", signal_name_prefix);    
}

/*
 * Routines that deal with sockets, some are WIN32 specific...
 */

static void sock_disable_nagle(int s) 
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
	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, server_conf,
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
    SOCKET nsd;

    for (lr = head_listener; lr ; lr = lr->next) {
        apr_get_os_sock(&nsd, lr->sd);
	if (FD_ISSET(nsd, main_fds)) {
	    head_listener = lr->next;
            if (head_listener == NULL)
                head_listener = ap_listeners;

	    return (lr);
	}
    }
    return NULL;
}

static int setup_listeners(server_rec *s)
{
    ap_listen_rec *lr;
    int num_listeners = 0;
    SOCKET nsd;

    /* Setup the listeners */
    FD_ZERO(&listenfds);

    if (ap_listen_open(s->process, s->port)) {
       return 0;
    }
    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
        if (lr->sd != NULL) {
            apr_get_os_sock(&nsd, lr->sd);
            FD_SET(nsd, &listenfds);
            if (listenmaxfd == INVALID_SOCKET || nsd > listenmaxfd) {
                listenmaxfd = nsd;
            }
        }
        lr->count = 0;
    }

    head_listener = ap_listeners;

    return num_listeners;
}

static int setup_inherited_listeners(server_rec *s)
{
    WSAPROTOCOL_INFO WSAProtocolInfo;
    HANDLE pipe;
    ap_listen_rec *lr;
    DWORD BytesRead;
    int num_listeners = 0;
    SOCKET nsd;

    /* Setup the listeners */
    FD_ZERO(&listenfds);

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
            ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
                         "setup_inherited_listeners: Unable to read socket data from parent");
            signal_parent(0);	/* tell parent to die */
            exit(1);
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: setup_inherited_listener() read = %d bytes of WSAProtocolInfo.", my_pid);
        nsd = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                        &WSAProtocolInfo, 0, 0);
        if (nsd == INVALID_SOCKET) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, WSAGetLastError(), server_conf,
                         "Child %d: setup_inherited_listeners(), WSASocket failed to open the inherited socket.", my_pid);
            signal_parent(0);	/* tell parent to die */
            exit(1);
        }
        if (nsd >= 0) {
            FD_SET(nsd, &listenfds);
            if (listenmaxfd == INVALID_SOCKET || nsd > listenmaxfd) {
                listenmaxfd = nsd;
            }
        }
        apr_put_os_sock(&lr->sd, &nsd, pconf);
        lr->count = 0;
    }
    /* Now, read the AcceptExCompPort from the parent */
    ReadFile(pipe, &AcceptExCompPort, sizeof(AcceptExCompPort), &BytesRead, (LPOVERLAPPED) NULL);
    CloseHandle(pipe);

    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }

    head_listener = ap_listeners;
    return num_listeners;
}

static void bind_listeners_to_completion_port()
{
    /* Associate the open listeners with the completion port.
     * Bypass the operation for Windows 95/98
     */
    ap_listen_rec *lr;

    if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS) {
        for (lr = ap_listeners; lr; lr = lr->next) {
            int nsd;
            apr_get_os_sock(&nsd,lr->sd);
            CreateIoCompletionPort((HANDLE) nsd, AcceptExCompPort, 0, 0);
        }
    }
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
 * In the code, the "main" thread is running within the child_main()
 * function. The first thing this function does is create the
 * worker threads, which operate in the child_sub_main() function. The
 * main thread then goes into a loop within child_main() where they
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
    apr_lock_t *jobmutex;
    int jobcount;

} globals;

globals allowed_globals =
{NULL, NULL, NULL, NULL, 0};
#define MAX_SELECT_ERRORS 100
#define PADDED_ADDR_SIZE sizeof(SOCKADDR_IN)+16

/* Windows 9x specific code...
 * Accept processing for on Windows 95/98 uses a producer/consumer queue 
 * model. A single thread accepts connections and queues the accepted socket 
 * to the accept queue for consumption by a pool of worker threads.
 *
 * win9x_get_connection()
 *    Calls remove_job() to pull a job from the accept queue. All the worker 
 *    threads block on remove_job.
 * accept_and_queue_connections()
 *    The accept threads runs this function, which accepts connections off 
 *    the network and calls add_job() to queue jobs to the accept_queue.
 * add_job()/remove_job()
 *    Add or remove an accepted socket from the list of sockets 
 *    connected to clients. allowed_globals.jobmutex protects
 *    against multiple concurrent access to the linked list of jobs.
 */
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

    apr_lock(allowed_globals.jobmutex);

    if (allowed_globals.jobtail != NULL)
	allowed_globals.jobtail->next = new_job;
    allowed_globals.jobtail = new_job;
    if (!allowed_globals.jobhead)
	allowed_globals.jobhead = new_job;
    allowed_globals.jobcount++;
    release_semaphore(allowed_globals.jobsemaphore);

    apr_unlock(allowed_globals.jobmutex);
}

static int remove_job(void)
{
    joblist *job;
    int sock;

    acquire_semaphore(allowed_globals.jobsemaphore);
    apr_lock(allowed_globals.jobmutex);

    if (shutdown_in_progress && !allowed_globals.jobhead) {
        apr_unlock(allowed_globals.jobmutex);
	return (-1);
    }
    job = allowed_globals.jobhead;
    ap_assert(job);
    allowed_globals.jobhead = job->next;
    if (allowed_globals.jobhead == NULL)
	allowed_globals.jobtail = NULL;
    apr_unlock(allowed_globals.jobmutex);
    sock = job->sock;
    free(job);

    return (sock);
}

static void accept_and_queue_connections(void * dummy)
{
    int requests_this_child = 0;
    struct timeval tv;
    fd_set main_fds;
    int wait_time = 1;
    int csd;
    int nsd = INVALID_SOCKET;
    struct sockaddr_in sa_client;
    int count_select_errors = 0;
    int rc;
    int clen;

    while (!shutdown_in_progress) {
        if (ap_max_requests_per_child && (requests_this_child > ap_max_requests_per_child)) {
            break;
	}

	tv.tv_sec = wait_time;
	tv.tv_usec = 0;
	memcpy(&main_fds, &listenfds, sizeof(fd_set));

	rc = select(listenmaxfd + 1, &main_fds, NULL, NULL, &tv);

        if (rc == 0 || (rc == SOCKET_ERROR && h_errno == WSAEINTR)) {
            count_select_errors = 0;    /* reset count of errors */            
            continue;
        }
        else if (rc == SOCKET_ERROR) {
            /* A "real" error occurred, log it and increment the count of
             * select errors. This count is used to ensure we don't go into
             * a busy loop of continuous errors.
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, h_errno, server_conf, 
                         "select failed with errno %d", h_errno);
            count_select_errors++;
            if (count_select_errors > MAX_SELECT_ERRORS) {
                shutdown_in_progress = 1;
                ap_log_error(APLOG_MARK, APLOG_ERR, h_errno, server_conf,
                             "Too many errors in select loop. Child process exiting.");
                break;
            }
	} else {
	    ap_listen_rec *lr;

	    lr = find_ready_listener(&main_fds);
	    if (lr != NULL) {
                /* fetch the native socket descriptor */
                apr_get_os_sock(&nsd, lr->sd);
	    }
	}

	do {
            clen = sizeof(sa_client);
            csd = accept(nsd, (struct sockaddr *) &sa_client, &clen);
            if (csd == INVALID_SOCKET) {
                csd = -1;
            }
        } while (csd < 0 && h_errno == WSAEINTR);

	if (csd < 0) {
            if (h_errno != WSAECONNABORTED) {
		ap_log_error(APLOG_MARK, APLOG_ERR, h_errno, server_conf,
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
            ap_log_error(APLOG_MARK,APLOG_ERR, GetLastError(), server_conf,
                         "win9x_get_connection: apr_pcalloc() failed. Process will exit.");
            return NULL;
        }
        apr_create_pool(&context->ptrans, pconf);
    }
    

    while (1) {
        apr_clear_pool(context->ptrans);        
        context->accept_socket = remove_job();
        if (context->accept_socket == -1) {
            return NULL;
        }
	len = sizeof(struct sockaddr);
        context->sa_server = apr_palloc(context->ptrans, len);
        if (getsockname(context->accept_socket, 
                        context->sa_server, &len)== SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, WSAGetLastError(), server_conf, 
                         "getsockname failed");
            continue;
        }
        len = sizeof(struct sockaddr);
        context->sa_client = apr_palloc(context->ptrans, len);
        if ((getpeername(context->accept_socket,
                         context->sa_client, &len)) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, WSAGetLastError(), server_conf, 
                         "getpeername failed");
            memset(&context->sa_client, '\0', sizeof(context->sa_client));
        }

        context->conn_io = ap_bcreate(context->ptrans, B_RDWR);

        /* do we NEED_DUPPED_CSD ?? */
        
        return context;
    }
}

/* 
 * Windows 2000/NT specific code...
 * create_acceptex_context()
 * reset_acceptex_context()
 * drain_acceptex_complport()
 * winnt_get_connection()
 *
 * TODO: Insert a discussion of 'completion contexts' and what these function do here...
 */
static void drain_acceptex_complport(HANDLE hComplPort, BOOLEAN bCleanUp) 
{
    LPOVERLAPPED pol;
    PCOMP_CONTEXT context;
    int rc;
    DWORD BytesRead;
    DWORD CompKey;

    while (1) {
        context = NULL;
        rc = GetQueuedCompletionStatus(hComplPort, &BytesRead, &CompKey,
                                       &pol, 1000);
        if (!rc) {
            rc = GetLastError();
            if (rc == ERROR_OPERATION_ABORTED) {
                ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                             "Child %d: - Draining an ABORTED packet off "
                             "the AcceptEx completion port.", my_pid);
                continue;
            }
            break;
        }
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: - Draining and discarding an active connection "
                     "off the AcceptEx completion port.", my_pid);
        context = (PCOMP_CONTEXT) pol;
        if (context && bCleanUp) {
            /* It is only valid to clean-up in the process that initiated the I/O */
            closesocket(context->accept_socket);
            CloseHandle(context->Overlapped.hEvent);
        }
    }
}
static int create_acceptex_context(apr_pool_t *_pconf, ap_listen_rec *lr) 
{
    PCOMP_CONTEXT context;
    DWORD BytesRead;
    SOCKET nsd;
    int lasterror;

    /* allocate the completion context */
    context = apr_pcalloc(_pconf, sizeof(COMP_CONTEXT));
    if (!context) {
        ap_log_error(APLOG_MARK,APLOG_ERR, GetLastError(), server_conf,
                     "create_acceptex_context: apr_pcalloc() failed. Process will exit.");
        return -1;
    }

    /* initialize the completion context */
    context->lr = lr;
    context->Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); 
    if (context->Overlapped.hEvent == NULL) {
        ap_log_error(APLOG_MARK,APLOG_ERR, GetLastError(), server_conf,
                     "create_acceptex_context: CreateEvent() failed. Process will exit.");
        return -1;
    }

    /* create and initialize the accept socket */
    apr_get_os_sock(&nsd, context->lr->sd);
    context->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (context->accept_socket == INVALID_SOCKET) {
        ap_log_error(APLOG_MARK,APLOG_ERR, WSAGetLastError(), server_conf,
                     "create_acceptex_context: socket() failed. Process will exit.");
        return -1;
    }

    /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */
    if (setsockopt(context->accept_socket, SOL_SOCKET,
                   SO_UPDATE_ACCEPT_CONTEXT, (char *)&nsd,
                   sizeof(nsd))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, WSAGetLastError(), server_conf,
                     "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed.");
        /* Not a failure condition. Keep running. */
    }

    apr_create_pool(&context->ptrans, _pconf);
    context->conn_io = ap_bcreate(context->ptrans, B_RDWR);
    context->recv_buf = context->conn_io->inbase;
    context->recv_buf_size = context->conn_io->bufsiz - 2*PADDED_ADDR_SIZE;


    /* AcceptEx on the completion context. The completion context will be signaled
     * when a connection is accepted. */
    if (!AcceptEx(nsd, context->accept_socket,
                  context->recv_buf, 
                  0, //context->recv_buf_size,
                  PADDED_ADDR_SIZE, PADDED_ADDR_SIZE,
                  &BytesRead,
                  (LPOVERLAPPED) context)) {
        lasterror = WSAGetLastError();
        if (lasterror != ERROR_IO_PENDING) {
            ap_log_error(APLOG_MARK,APLOG_ERR, WSAGetLastError(), server_conf,
                         "create_acceptex_context: AcceptEx failed. Process will exit.");
            return -1;
        }

    }
    lr->count++;

    return 0;
}
static ap_inline apr_status_t reset_acceptex_context(PCOMP_CONTEXT context) 
{
    DWORD BytesRead;
    SOCKET nsd;
    int rc;

    context->lr->count++;

    /* recreate and initialize the accept socket if it is not being reused */
    apr_get_os_sock(&nsd, context->lr->sd);
    if (context->accept_socket == INVALID_SOCKET) {
        context->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (context->accept_socket == INVALID_SOCKET) {
            rc = WSAGetLastError();
            ap_log_error(APLOG_MARK,APLOG_ERR, rc, server_conf,
                         "reset_acceptex_context: socket() failed. Process will exit.");
            return rc;
        }
        
        /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */
        if (setsockopt(context->accept_socket, SOL_SOCKET,
                       SO_UPDATE_ACCEPT_CONTEXT, (char *)&nsd,
                       sizeof(nsd))) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, WSAGetLastError(),
                         server_conf,
                         "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed.");
            /* Not a failure condition. Keep running. */
        }
    }

    /* reset the completion context */
    apr_clear_pool(context->ptrans);
    context->sock = NULL;
    context->conn_io = ap_bcreate(context->ptrans, B_RDWR);
    context->recv_buf = context->conn_io->inbase;
    context->recv_buf_size = context->conn_io->bufsiz - 2*PADDED_ADDR_SIZE;

    /* AcceptEx on the completion context. The completion context will be signaled
     * when a connection is accepted. */
    if (!AcceptEx(nsd, context->accept_socket, context->recv_buf, 0,
                  PADDED_ADDR_SIZE, PADDED_ADDR_SIZE, &BytesRead, 
                  (LPOVERLAPPED) context)) {
        rc = WSAGetLastError();
        if (rc != ERROR_IO_PENDING) {
            ap_log_error(APLOG_MARK, APLOG_INFO, rc, server_conf,
                         "reset_acceptex_context: AcceptEx failed for "
                         "listening socket: %d and accept socket: %d", 
                         nsd, context->accept_socket);
            return rc;
        }
    }

    return APR_SUCCESS;
}
static PCOMP_CONTEXT winnt_get_connection(PCOMP_CONTEXT context)
{
    int requests_this_child = 0;
    int rc;
    LPOVERLAPPED pol;
    DWORD CompKey;
    DWORD BytesRead;


    if (context != NULL) {
        if (shutdown_in_progress) {
            /* Clean-up the AcceptEx completion context */
            CloseHandle(context->Overlapped.hEvent);
            if (context->accept_socket != INVALID_SOCKET)
                closesocket(context->accept_socket);
        }
        else {
            /* Prepare the completion context for reuse */
            if ((rc = reset_acceptex_context(context)) != APR_SUCCESS) {
                /* Retry once, this time requesting a new socket */
                if (context->accept_socket != INVALID_SOCKET) {
                    closesocket(context->accept_socket);
                    context->accept_socket = INVALID_SOCKET;
                }
                if ((rc = reset_acceptex_context(context)) != APR_SUCCESS) {
                    /* Failed again, so give up, but leave the thread up 
                     * Should we signal a shutdown now? 
                     */
                    ap_log_error(APLOG_MARK, APLOG_ERR, rc, server_conf,
                                 "Child %d: winnt_get_connection: reset_acceptex_context failed.",
                                 my_pid); 
                    if (context->accept_socket != INVALID_SOCKET)
                        closesocket(context->accept_socket);
                    CloseHandle(context->Overlapped.hEvent);
                }
            }
        }
    }

    /* May need to atomize the workers_may_exit check with the 
     * g_blocked_threads++ */
    if (workers_may_exit) {
        return NULL;
    }
    g_blocked_threads++;
        
    while (1) {
        rc = GetQueuedCompletionStatus(AcceptExCompPort, &BytesRead, &CompKey,
                                       &pol, INFINITE);
        if (!rc) {
            rc = GetLastError();
            if (rc != ERROR_OPERATION_ABORTED) {
                /* Is this a deadly condition? Hummm... */
                ap_log_error(APLOG_MARK,APLOG_ERR, rc, server_conf,
                             "Child %d: - GetQueuedCompletionStatus() failed", 
                             my_pid);
            }
            else {
                /* Sometimes we catch ERROR_OPERATION_ABORTED completion packets
                 * from the old child process (during a restart). Ignore them.
                 */
                ap_log_error(APLOG_MARK,APLOG_INFO, rc, server_conf,
                             "Child %d: - Draining ERROR_OPERATION_ABORTED packet off "
                             "the completion port.", my_pid);

            }
            continue;
        }

        if (CompKey != 0) {
            /* CompKey == my_pid means this thread was unblocked by
             * the shutdown code (not by io completion).
             */
            if (CompKey == my_pid) {
                g_blocked_threads--;
                return NULL;
            }
            /* Sometimes we catch shutdown io completion packets
             * posted by the old child process (during a restart). Ignore them.
             */
            continue;
        }

        context = (PCOMP_CONTEXT) pol;
        break;
    }

    g_blocked_threads--;

    /* Check to see if we need to create more completion contexts,
     * but only if we are not in the process of shutting down
     */
    if (!shutdown_in_progress) {
        apr_lock(allowed_globals.jobmutex);
        context->lr->count--;
        if (context->lr->count < 2) {
            SetEvent(maintenance_event);
        }
        apr_unlock(allowed_globals.jobmutex);
    }

    /* Received a connection */
    context->conn_io->incnt = BytesRead;
    GetAcceptExSockaddrs(context->recv_buf, 
                         0, //context->recv_buf_size,
                         PADDED_ADDR_SIZE,
                         PADDED_ADDR_SIZE,
                         &context->sa_server,
                         &context->sa_server_len,
                         &context->sa_client,
                         &context->sa_client_len);

    return context;

}
/*
 * worker_main() - this is the main loop for the worker threads
 *
 * Windows 95/98
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

static void worker_main(int child_num)
{
    PCOMP_CONTEXT context = NULL;

    while (1) {
        conn_rec *c;
        ap_iol *iol;
        apr_int32_t disconnected;

        /* Grab a connection off the network */
        if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
            context = win9x_get_connection(context);
        }
        else {
            context = winnt_get_connection(context);
        }

        if (!context)
            break;
        sock_disable_nagle(context->accept_socket);
        apr_put_os_sock(&context->sock, &context->accept_socket, context->ptrans);

        iol = ap_iol_attach_socket(context->ptrans, context->sock);
        if (iol == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_ENOMEM, server_conf,
                         "worker_main: attach_socket() failed. Continuing...");
            closesocket(context->accept_socket);
            continue;
        }
        ap_bpush_iol(context->conn_io, iol);
        c = ap_new_connection(context->ptrans, server_conf, context->conn_io,
                              (struct sockaddr_in *) context->sa_client,
                              (struct sockaddr_in *) context->sa_server,
                              child_num);

        ap_process_connection(c);


        apr_getsocketopt(context->sock, APR_SO_DISCONNECTED, &disconnected);
        if (disconnected) {
            /* Kill the clean-up registered by the iol. We want to leave 
             * the accept socket open because we are about to try to 
             * reuse it
             */
            ap_bpop_iol(&iol, context->conn_io);
        }
        else {
            context->accept_socket = INVALID_SOCKET;
            /* Disable lingering close for the moment to fix a seg fault.
             * All the sendfile code needs some serious work to return 
             * proper error values, handle updating bytes_sent, etc.
             * I'll enable lingering close after I've fixed the sendfile
             * code
             * ap_lingering_close(c);
             */
            ap_bclose(c->client);
        }
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                 "Child %d: Thread exiting.", my_pid);
#if 0

    SetEvent(exit_event);
#endif
    /* TODO: Add code to clean-up completion contexts here */
}

static void cleanup_thread(thread **handles, int *thread_cnt, int thread_to_clean)
{
    int i;

    CloseHandle(handles[thread_to_clean]);
    for (i = thread_to_clean; i < ((*thread_cnt) - 1); i++)
	handles[i] = handles[i + 1];
    (*thread_cnt)--;
}

static void create_listeners() 
{
#define NUM_LISTENERS 5
    ap_listen_rec *lr;
    for (lr = ap_listeners; lr != NULL; lr = lr->next) {
        while (lr->count < NUM_LISTENERS) {
            if (create_acceptex_context(pconf, lr) == -1) {
                ap_log_error(APLOG_MARK,APLOG_ERR, GetLastError(), server_conf,
                             "Unable to create an AcceptEx completion context -- process will exit");
                signal_parent(0);	/* tell parent to die */
            }
        }
    }
}
/*
 * child_main() runs the main control thread for the child process. 
 *
 * The control thread:
 * - sets up the worker thread pool
 * - starts the accept thread (Win 9x)
 * - creates AcceptEx contexts (Win NT)
 * - waits for exit_event, maintenance_event or maintenance timeout
 *   and does the right thing depending on which event is received.
 */
static void child_main()
{
    apr_status_t status;
    HANDLE child_events[2];
    char* exit_event_name;
    int nthreads = ap_threads_per_child;
    int tid;
    thread **child_handles;
    int rv;
    time_t end_time;
    int i;
    int cld;
    apr_pool_t *pchild;


    /* This is the child process or we are running in single process
     * mode.
     */
    exit_event_name = apr_psprintf(pconf, "apC%d", my_pid);
    setup_signal_names(apr_psprintf(pconf,"ap%d", parent_pid));

    if (one_process) {
        /* Single process mode */
        apr_create_lock(&start_mutex,APR_MUTEX, APR_CROSS_PROCESS,signal_name_prefix,pconf);
        exit_event = CreateEvent(NULL, TRUE, FALSE, exit_event_name);

        setup_listeners(server_conf);
        bind_listeners_to_completion_port();
    }
    else {
        /* Child process mode */
        apr_child_init_lock(&start_mutex, signal_name_prefix, pconf);
        exit_event = OpenEvent(EVENT_ALL_ACCESS, FALSE, exit_event_name);
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: exit_event_name = %s", my_pid, exit_event_name);

        setup_inherited_listeners(server_conf);
    }

    /* Initialize the child_events */
    maintenance_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    child_events[0] = exit_event;
    child_events[1] = maintenance_event;

    ap_assert(start_mutex);
    ap_assert(exit_event);
    ap_assert(maintenance_event);

    apr_create_pool(&pchild, pconf);
    allowed_globals.jobsemaphore = create_semaphore(0);
    apr_create_lock(&allowed_globals.jobmutex, APR_MUTEX, APR_INTRAPROCESS, NULL, pchild);

    /*
     * Wait until we have permission to start accepting connections.
     * start_mutex is used to ensure that only one child ever
     * goes into the listen/accept loop at once.
     */
    status = apr_lock(start_mutex);
    if (status != APR_SUCCESS) {
	ap_log_error(APLOG_MARK,APLOG_ERR, status, server_conf,
                     "Child %d: Failed to acquire the start_mutex. Process will exit.", my_pid);
        signal_parent(0);	/* tell parent to die */
	exit(0);
    }
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Acquired the start mutex.", my_pid);

    /* Create the worker thread pool */
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Starting %d worker threads.", my_pid, nthreads);
    child_handles = (thread *) alloca(nthreads * sizeof(int));
    for (i = 0; i < nthreads; i++) {
        child_handles[i] = (thread *) _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE) worker_main,
                                                     NULL, 0, &tid);
    }

    /* Begin accepting connections */
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        /* Win95/98: Start the accept thread */
        _beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE) accept_and_queue_connections,
                       (void *) i, 0, &tid);
    } else {
        /* Windows NT/2000: Create AcceptEx completion contexts */
        create_listeners();
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
        rv = WaitForMultipleObjects(2, (HANDLE *) child_events, FALSE, INFINITE);
        cld = rv - WAIT_OBJECT_0;
        if (rv == WAIT_FAILED) {
            /* Something serious is wrong */
            ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
                         "Child %d: WAIT_FAILED -- shutting down server");
            break;
        }
        else if (rv == WAIT_TIMEOUT) {
            /* Hey, this cannot happen */
            ap_log_error(APLOG_MARK, APLOG_CRIT, APR_SUCCESS, server_conf,
                         "Child %d: WAIT_TIMEOUT -- shutting down server", my_pid);
            break;
        }
        else if (cld == 0) {
            /* Exit event was signaled */
            ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                         "Child %d: Exit event signaled. Child process is ending.", my_pid);
            break;
        }
        else {
            /* Child maintenance event signaled */
            if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS) {
                create_listeners();
            }
            ResetEvent(maintenance_event);
            ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                         "Child %d: Child maintenance event signaled.", my_pid);
        }
    }

    /* Setting is_graceful will close keep-alive connections */
    is_graceful = 1;

    /* Shutdown the worker threads */
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        /* workers_may_exit = 1; Not used on Win9x */
        shutdown_in_progress = 1;
        for (i = 0; i < nthreads; i++) {
            add_job(-1);
        }
    }
    else { /* Windows NT/2000 */
        SOCKET nsd;
        ap_listen_rec *lr;
        /*
         * Setting shutdown_in_progress prevents new AcceptEx completion 
         * contexts from being queued to the port but allows threads to 
         * continue consuming from the port. This gives the server a 
         * chance to handle any accepted connections.
         */
        shutdown_in_progress = 1;
        Sleep(1000);
        
        /* Setting workers_may_exit prevents threads from consumimg from the 
         * completion port (especially threads that unblock off of keep-alive
         * connections later on).
         */
        workers_may_exit = 1;

        /* Unblock threads blocked on the completion port */
        apr_lock(allowed_globals.jobmutex);
        while (g_blocked_threads > 0) {
            ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                         "Child %d: %d threads blocked on the completion port", my_pid, g_blocked_threads);
            for (i=g_blocked_threads; i > 0; i--) {
                PostQueuedCompletionStatus(AcceptExCompPort, 0, my_pid, NULL);
            }
            Sleep(1000);
        }
        apr_unlock(allowed_globals.jobmutex);

        /* Cancel any remaining pending AcceptEx completion contexts */
        for (lr = ap_listeners; lr != NULL; lr = lr->next) {
            apr_get_os_sock(&nsd,lr->sd);
            CancelIo((HANDLE) nsd);
        }

        /* Drain the canceled contexts off the port */
        drain_acceptex_complport(AcceptExCompPort, TRUE);
    }

    /* Release the start_mutex to let the new process (in the restart
     * scenario) a chance to begin servicing requests 
     */
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: Releasing the start mutex", my_pid);
    apr_unlock(start_mutex);

    /* Give busy worker threads a chance to service their connections.
     * Kill them off if they take too long
     */
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
    for (i = 0; i < nthreads; i++) {
        TerminateThread(child_handles[i], 1);
        CloseHandle(child_handles[i]);
    }
    ap_log_error(APLOG_MARK,APLOG_INFO, APR_SUCCESS, server_conf, 
                 "Child %d: All worker threads have ended.", my_pid);

    CloseHandle(AcceptExCompPort);
    destroy_semaphore(allowed_globals.jobsemaphore);
    apr_destroy_lock(allowed_globals.jobmutex);

    apr_destroy_pool(pchild);
    CloseHandle(exit_event);
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
    HANDLE hDupedCompPort;

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
        ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
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
        int nsd;
        lpWSAProtocolInfo = apr_pcalloc(p, sizeof(WSAPROTOCOL_INFO));
        apr_get_os_sock(&nsd,lr->sd);
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Parent: Duplicating socket %d and sending it to child process %d", nsd, pi.dwProcessId);
        if (WSADuplicateSocket(nsd, pi.dwProcessId,
                               lpWSAProtocolInfo) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, h_errno, server_conf,
                         "Parent: WSADuplicateSocket failed for socket %d.", lr->sd );
            return -1;
        }

        if (!WriteFile(hPipeWrite, lpWSAProtocolInfo, (DWORD) sizeof(WSAPROTOCOL_INFO),
                       &BytesWritten,
                       (LPOVERLAPPED) NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
                         "Parent: Unable to write duplicated socket %d to the child.", lr->sd );
            return -1;
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, server_conf,
                     "Parent: BytesWritten = %d WSAProtocolInfo = %x20", BytesWritten, *lpWSAProtocolInfo);
    }
    if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS) {
        /* Now, send the AcceptEx completion port to the child */
        if (!DuplicateHandle(GetCurrentProcess(), AcceptExCompPort, 
                             pi.hProcess, &hDupedCompPort,  0,
                             TRUE, DUPLICATE_SAME_ACCESS)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
                         "Parent: Unable to duplicate AcceptEx completion port. Shutting down.");
            return -1;
        }

        WriteFile(hPipeWrite, &hDupedCompPort, (DWORD) sizeof(hDupedCompPort), &BytesWritten, (LPOVERLAPPED) NULL);
    }
    
    CloseHandle(hPipeRead);
    CloseHandle(hPipeWrite);        

    return 0;
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

    setup_listeners(s);
    bind_listeners_to_completion_port();

    /* Create child process 
     * Should only be one in this version of Apache for WIN32 
     */
    while (remaining_children_to_start--) {
        if (create_process(pconf, process_handles, process_kill_events, 
                           &current_live_processes) < 0) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, GetLastError(), server_conf,
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
        ap_log_error(APLOG_MARK,APLOG_CRIT, GetLastError(), server_conf,
                     "master_main: WaitForMultipeObjects WAIT_FAILED -- doing server shutdown");
        shutdown_pending = 1;
    }
    else if (rv == WAIT_TIMEOUT) {
        /* Hey, this cannot happen */
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), s,
                     "master_main: WaitForMultipeObjects with INFINITE wait exited with WAIT_TIMEOUT");
        shutdown_pending = 1;
    }
    else if (cld == current_live_processes) {
        /* shutdown_event signalled */
        shutdown_pending = 1;
        printf("shutdown event signaled\n");
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS, s, 
                     "master_main: Shutdown event signaled -- doing server shutdown.");
        if (ResetEvent(shutdown_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), s,
                         "ResetEvent(shutdown_event)");
        }

    }
    else if (cld == current_live_processes+1) {
        /* restart_event signalled */
        int children_to_kill = current_live_processes;
        restart_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s, 
                     "master_main: Restart event signaled. Doing a graceful restart.");
        if (ResetEvent(restart_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), s,
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
                ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), s,
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
                     "master_main: Child process failed. Restarting the child process.");
        ap_assert(cld < current_live_processes);
        cleanup_process(process_handles, process_kill_events, cld, &current_live_processes);
        /* APD2("main_process: child in slot %d died", rv); */
        /* restart_child(process_hancles, process_kill_events, cld, &current_live_processes); */

        /* Drain the AcceptEx completion port of any outstanding I/O pending for the dead 
         * process. */
        drain_acceptex_complport(AcceptExCompPort, FALSE);
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
                ap_log_error(APLOG_MARK,APLOG_ERR, GetLastError(), server_conf,
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
                         "forcing termination of child #%d (handle %d)", i, process_handles[i]);
            TerminateProcess((HANDLE) process_handles[i], 1);
        }
        return 0;  /* Tell the caller we do not want to restart */
    }

    return 1;      /* Tell the caller we want a restart */
}


#define SERVICE_UNNAMED -1

/* service_nt_main_fn needs to append the StartService() args 
 * outside of our call stack and thread as the service starts...
 */
apr_array_header_t *mpm_new_argv;

/* Remember service_to_start failures to log and fail in pre_config.
 * Remember inst_argc and inst_argv for installing or starting the
 * service after we preflight the config.
 */

static apr_status_t service_to_start_success;
static int inst_argc;
static char **inst_argv;
    
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
    apr_status_t service_named = SERVICE_UNNAMED;
    apr_status_t rv;
    char *def_server_root;
    char fnbuf[MAX_PATH];
    char optbuf[3];
    char **new_arg;
    int fixed_args;
    char *pid;
    int opt;

    one_process = !!getenv("ONE_PROCESS");

    osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osver);

    /* AP_PARENT_PID is only valid in the child */
    pid = getenv("AP_PARENT_PID");
    if (pid) 
    {
        /* This is the child */
        parent_pid = (DWORD) atol(pid);
        my_pid = GetCurrentProcessId();

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
     * strip out -n servicename into service_name & display_name
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
        /* WARNING: There is an implict assumption here that the
         * executable resides in the ServerRoot!
         */
        rv = GetLastError();
        ap_log_error(APLOG_MARK,APLOG_ERR, rv, NULL, 
                     "Failed to get the running module's file name");
        exit(1);
    }
    def_server_root = (char *) apr_filename_of_pathname(fnbuf);
    if (def_server_root > fnbuf) {
        *(def_server_root - 1) = '\0';
        def_server_root = ap_os_canonical_filename(process->pool, fnbuf);
    }

    /* Use process->pool so that the rewritten argv
     * lasts for the lifetime of the server process,
     * because pconf will be destroyed after the 
     * initial pre-flight of the config parser.
     */

    mpm_new_argv = apr_make_array(process->pool, process->argc + 2, sizeof(char *));
    new_arg = (char**) apr_push_array(mpm_new_argv);
    *new_arg = (char *) process->argv[0];
    
    new_arg = (char**) apr_push_array(mpm_new_argv);
    *new_arg = "-d";
    new_arg = (char**) apr_push_array(mpm_new_argv);
    *new_arg = def_server_root;

    fixed_args = mpm_new_argv->nelts;

    optbuf[0] = '-'; optbuf[2] = '\0';
    while (apr_getopt(process->argc, (char**) process->argv, 
                     "n:k:iu" AP_SERVER_BASEARGS, 
                     &opt, process->pool) == APR_SUCCESS) {
        switch (opt) {
        case 'n':
            service_named = mpm_service_set_name(process->pool, ap_optarg);
            break;
        case 'k':
            signal_arg = ap_optarg;
            break;
        case 'i':
            /* TODO: warn of depreciated syntax, "use -k install instead" */
            signal_arg = "install";
            break;
        case 'u':
            /* TODO: warn of depreciated syntax, "use -k uninstall instead" */
            signal_arg = "uninstall";
            break;
        default:
            optbuf[1] = (char) opt;
            new_arg = (char**) apr_push_array(mpm_new_argv);
            *new_arg = apr_pstrdup(process->pool, optbuf);
            if (ap_optarg) {
                new_arg = (char**) apr_push_array(mpm_new_argv);
                *new_arg = ap_optarg;
            }
            break;
        }
    }
    /* Set optreset and optind to allow apr_getopt to work correctly
     * when called from http_main.c
     */
    ap_optreset = 1;
    ap_optind = 1;
    
    /* Track the number of args actually entered by the user */
    inst_argc = mpm_new_argv->nelts - fixed_args;

    /* Provide a default 'run' -k arg to simplify signal_arg tests */
    if (!signal_arg)
        signal_arg = "run";

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
            service_to_start_success = mpm_service_to_start();
            if (service_to_start_success == APR_SUCCESS)
                service_named = APR_SUCCESS;
        }
    }

    if (service_named == SERVICE_UNNAMED) {
        service_named = mpm_service_set_name(process->pool, 
                                             DEFAULT_SERVICE_NAME);
    }

    if (!strcasecmp(signal_arg, "install")) /* -k install */
    {
        if (service_named == APR_SUCCESS) 
        {
            ap_log_error(APLOG_MARK,APLOG_ERR, 0, NULL,
                 "%s: Service is already installed.", display_name);
            exit(1);
        }
    }
    else
    {
        if (service_named == APR_SUCCESS) 
        {
            rv = mpm_merge_service_args(process->pool, mpm_new_argv, 
                                        fixed_args);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK,APLOG_ERR, rv, NULL,
                             "%s: ConfigArgs are missing from the registry.",
                             display_name);
            }
        }
        else
        {
            ap_log_error(APLOG_MARK,APLOG_ERR, 0, NULL,
                 "%s: No installed service by that name.", display_name);
            exit(1);
        }
    }
    
    /* Track the args actually entered by the user.
     * These will be used for the -k install parameters, as well as
     * for the -k start service override arguments.
     */
    inst_argv = (char**) mpm_new_argv->elts + mpm_new_argv->nelts - inst_argc;

    process->argc = mpm_new_argv->nelts; 
    process->argv = (char**) mpm_new_argv->elts;
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

    if (!strcasecmp(signal_arg, "runservice")
            && (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
            && (service_to_start_success != APR_SUCCESS)) {
        ap_log_error(APLOG_MARK,APLOG_ERR, service_to_start_success, NULL, 
                     "%s: Unable to start the service manager.",
                     display_name);
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
    max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;

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
            if (osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS) {
                /* Create the AcceptEx IoCompletionPort once in the parent.
                 * The completion port persists across restarts. 
                 */
                AcceptExCompPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                                          NULL,
                                                          0,
                                                          0); /* CONCURRENT ACTIVE THREADS */
                if (AcceptExCompPort == NULL) {
                    ap_log_error(APLOG_MARK,APLOG_ERR, GetLastError(), server_conf,
                                 "Parent: Unable to create the AcceptExCompletionPort -- process will exit");
                    exit(1);
                }
            }

            ap_log_pid(pconf, ap_pid_fname);
            
            /* Create shutdown event, apPID_shutdown, where PID is the parent 
             * Apache process ID. Shutdown is signaled by 'apache -k shutdown'.
             */
            shutdown_event = CreateEvent(sa, FALSE, FALSE, signal_shutdown_name);
            if (!shutdown_event) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, GetLastError(), server_conf,
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
                ap_log_error(APLOG_MARK, APLOG_EMERG, GetLastError(), server_conf,
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
                    rv = mpm_service_to_start();
                    if (rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK,APLOG_ERR, rv, server_conf,
                                     "%s: Unable to start the service manager.",
                                     display_name);
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
            apr_create_lock(&start_mutex,APR_MUTEX, APR_CROSS_PROCESS, signal_name_prefix,
                               server_conf->process->pool);
        }
    }
    else /* parent_pid != my_pid */
    {
        mpm_start_child_console_handler();
    }
}

API_EXPORT(int) ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s )
{
    static int restart = 0;            /* Default is "not a restart" */

    pconf = _pconf;
    server_conf = s;

    if ((parent_pid != my_pid) || one_process) {
        /* Running as Child process or in one_process (debug) mode */
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: Child process is running", my_pid);
        child_main();
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, server_conf,
                     "Child %d: Child process is exiting", my_pid);        

        return 1;
    }  /* Child or single process */
    else { /* Parent process */
        restart = master_main(server_conf, shutdown_event, restart_event);

        if (!restart) {
            /* Shutting down. Clean up... */
            const char *pidfile = ap_server_root_relative (pconf, ap_pid_fname);

            if (pidfile != NULL && unlink(pidfile) == 0) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, APR_SUCCESS,
                             server_conf, "removed PID file %s (pid=%ld)",
                             pidfile, GetCurrentProcessId());
            }
            apr_destroy_lock(start_mutex);

            CloseHandle(restart_event);
            CloseHandle(shutdown_event);

            return 1;
        }
    }  /* Parent process */

    return 0; /* Restart */
}

static void winnt_hooks(void)
{
    one_process = 0;
    ap_hook_pre_config(winnt_pre_config, NULL, NULL, AP_HOOK_MIDDLE);
    ap_hook_post_config(winnt_post_config, NULL, NULL, 0);
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
    ap_pid_fname = arg;
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
    apr_finfo_t finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    if ((apr_stat(&finfo, fname, cmd->pool) != APR_SUCCESS) || 
        (finfo.filetype != APR_DIR)) {
	return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname, 
			  " does not exist or is not a directory", NULL);
    }
    apr_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
}

/* Stub functions until this MPM supports the connection status API */

API_EXPORT(void) ap_update_connection_status(long conn_id, const char *key, \
                                             const char *value)
{
    /* NOP */
}

API_EXPORT(void) ap_reset_connection_status(long conn_id)
{
    /* NOP */
}

API_EXPORT(apr_array_header_t *) ap_get_status_table(apr_pool_t *p)
{
    /* NOP */
    return NULL;
}

static const command_rec winnt_cmds[] = {
LISTEN_COMMANDS
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
{ "ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF, TAKE1,
  "Number of threads each child creates" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1,
  "Maximum number of requests a particular child serves before dying." },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1,
  "The location of the directory Apache changes to before dumping core" },
{ NULL }
};

MODULE_VAR_EXPORT module mpm_winnt_module = {
    MPM20_MODULE_STUFF,
    winnt_rewrite_args,         /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    winnt_cmds,		        /* command apr_table_t */
    NULL,			/* handlers */
    winnt_hooks 		/* register_hooks */
};
