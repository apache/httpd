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
/*
 * Actual definitions of WINNT MPM specific config globals
 */
int ap_max_requests_per_child=0;
int ap_daemons_to_start=0;
static char *mpm_pid_fname=NULL;
static int ap_threads_per_child = 0;
//static int ap_max_threads_per_child = 0;
static int workers_may_exit = 0;
static int max_requests_per_child = 0;
static int requests_this_child;
static int num_listenfds = 0;
static struct pollfd *listenfds;
static pool *pconf;		/* Pool for config stuff */

static char ap_coredump_dir[MAX_STRING_LEN];


static server_rec *server_conf;
/*static int sd; ZZZ why is the global...? Only seems to be needed on Win32*/

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


/* *Non*-shared winnt.c globals... */
event *exit_event;
mutex *start_mutex;
int my_pid;
int parent_pid;
int listenmaxfd;

/* a clean exit from a child with proper cleanup 
   static void clean_child_exit(int code) __attribute__ ((noreturn)); 
void clean_child_exit(int code)
{
    if (pchild) {
	ap_destroy_pool(pchild);
    }
    exit(code);
}
*/
/*****************************************************************
 * Connection structures and accounting...
 */

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;

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

void ap_start_shutdown(void)
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
void ap_start_restart(int graceful)
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
    ap_start_restart(1);
}

static ap_listen_rec *old_listeners;
static ap_listen_rec *head_listener;
static int setup_listeners(pool *pconf, server_rec *s)
{
    ap_listen_rec *lr;
    int num_listeners = 0;

    if (ap_listen_open(pconf, s->port)) {
       return 0;
    }
    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }
    return num_listeners;
}

static int find_listener(ap_listen_rec *lr)
{
    ap_listen_rec *or;

    for (or = old_listeners; or; or = or->next) {
	if (!memcmp(&or->local_addr, &lr->local_addr, sizeof(or->local_addr))) {
//	    or->used = 1;
	    return or->fd;
	}
    }
    return -1;
}


static void close_unused_listeners(void)
{
    ap_listen_rec *or, *next;

    for (or = old_listeners; or; or = next) {
	next = or->next;
//	if (!or->used)
	    closesocket(or->fd);
	free(or);
    }
    old_listeners = NULL;
}

/*
 * Find a listener which is ready for accept().  This advances the
 * head_listener global.
 */
static ap_inline ap_listen_rec *find_ready_listener(fd_set * main_fds)
//static ap_listen_rec *find_ready_listener(fd_set * main_fds)
{
    ap_listen_rec *lr;

    lr = head_listener;
    do {
	if (FD_ISSET(lr->fd, main_fds)) {
	    head_listener = lr->next;
	    return (lr);
	}
	lr = lr->next;
    } while (lr != head_listener);
    return NULL;
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

//    APD2("signal_parent signalling event \"%s\"", signal_name);

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


/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

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

/* The code protected by #ifdef UNGRACEFUL_RESTARTS/#endif sections
 * could implement a sort-of ungraceful restart for Win32. instead of
 * graceful restarts. 
 *
 * However it does not work too well because it does not intercept a
 * connection already in progress (in child_sub_main()). We'd have to
 * get that to poll on the exit event. 
 */

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
#ifdef UNGRACEFUL_RESTART
    HANDLE thread_exit_event;
#else
    int exit_now;
#endif
    semaphore *jobsemaphore;
    joblist *jobhead;
    joblist *jobtail;
    mutex *jobmutex;
    int jobcount;
} globals;

globals allowed_globals =
{0, NULL, NULL, NULL, NULL, 0};

/*
 * add_job()/remove_job() - add or remove an accepted socket from the
 * list of sockets connected to clients. allowed_globals.jobmutex protects
 * against multiple concurrent access to the linked list of jobs.
 */

void add_job(int sock)
{
    joblist *new_job;

    ap_assert(allowed_globals.jobmutex);
    /* TODO: If too many jobs in queue, sleep, check for problems */
    ap_acquire_mutex(allowed_globals.jobmutex);
    new_job = (joblist *) malloc(sizeof(joblist));
    if (new_job == NULL) {
	fprintf(stderr, "Ouch!  Out of memory in add_job()!\n");
    }
    new_job->next = NULL;
    new_job->sock = sock;
    if (allowed_globals.jobtail != NULL)
	allowed_globals.jobtail->next = new_job;
    allowed_globals.jobtail = new_job;
    if (!allowed_globals.jobhead)
	allowed_globals.jobhead = new_job;
    allowed_globals.jobcount++;
    release_semaphore(allowed_globals.jobsemaphore);
    ap_release_mutex(allowed_globals.jobmutex);
}

int remove_job(void)
{
    joblist *job;
    int sock;

#ifdef UNGRACEFUL_RESTART
    HANDLE hObjects[2];
    int rv;

    hObjects[0] = allowed_globals.jobsemaphore;
    hObjects[1] = allowed_globals.thread_exit_event;

    rv = WaitForMultipleObjects(2, hObjects, FALSE, INFINITE);
    ap_assert(rv != WAIT_FAILED);
    if (rv == WAIT_OBJECT_0 + 1) {
	/* thread_exit_now */
//	APD1("thread got exit now event");
	return -1;
    }
    /* must be semaphore */
#else
    acquire_semaphore(allowed_globals.jobsemaphore);
#endif
    ap_assert(allowed_globals.jobmutex);

#ifdef UNGRACEFUL_RESTART
    if (!allowed_globals.jobhead) {
#else
    ap_acquire_mutex(allowed_globals.jobmutex);
    if (allowed_globals.exit_now && !allowed_globals.jobhead) {
#endif
	ap_release_mutex(allowed_globals.jobmutex);
	return (-1);
    }
    job = allowed_globals.jobhead;
    ap_assert(job);
    allowed_globals.jobhead = job->next;
    if (allowed_globals.jobhead == NULL)
	allowed_globals.jobtail = NULL;
    ap_release_mutex(allowed_globals.jobmutex);
    sock = job->sock;
    free(job);
    return (sock);
}

/*
 * child_sub_main() - this is the main loop for the worker threads
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

static void child_sub_main(int child_num)
{
    NET_SIZE_T clen;
    struct sockaddr sa_server;
    struct sockaddr sa_client;
    pool *ptrans;
    int requests_this_child = 0;
    int csd = -1;
    int dupped_csd = -1;
    int srv = 0;

    /* Note: current_conn used to be a defined at file scope as follows... Since the signal code is
       not being used in WIN32, make the variable local */
    //    static APACHE_TLS conn_rec *volatile current_conn;
    conn_rec *current_conn;

    ptrans = ap_make_sub_pool(pconf);

#if 0
    /* ZZZ scoreboard */
    (void) ap_update_child_status(child_num, SERVER_READY, (request_rec *) NULL);
#endif

    /*
     * Setup the jump buffers so that we can return here after a timeout.
     */
#if 0 /* ZZZ */
#if defined(USE_LONGJMP)
    setjmp(jmpbuffer);
#else
    sigsetjmp(jmpbuffer, 1);
#endif
#ifdef SIGURG
    signal(SIGURG, timeout);
#endif
#endif

    while (1) {
	BUFF *conn_io;
	request_rec *r;

	/*
	 * (Re)initialize this child to a pre-connection state.
	 */
#if 0   /* ZZZ Alarms... */
	ap_set_callback_and_alarm(NULL, 0); /* Cancel any outstanding alarms */
#endif
#if 0   /* ZZZ what is this? It's not thread safe! */
	timeout_req = NULL;                 /* No request in progress */
#endif
	current_conn = NULL;

	ap_clear_pool(ptrans);

#if 0
        /* ZZZ scoreboard */
	(void) ap_update_child_status(child_num, SERVER_READY,
	                              (request_rec *) NULL);
#endif

	/* Get job from the job list. This will block until a job is ready.
	 * If -1 is returned then the main thread wants us to exit.
	 */
	csd = remove_job();
	if (csd == -1)
	    break;		/* time to exit */
	requests_this_child++;

	ap_note_cleanups_for_socket(ptrans, csd);

	/*
	 * We now have a connection, so set it up with the appropriate
	 * socket options, file descriptors, and read/write buffers.
	 */

	clen = sizeof(sa_server);
	if (getsockname(csd, &sa_server, &clen) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, server_conf, "getsockname");
	    continue;
	}
	clen = sizeof(sa_client);
	if ((getpeername(csd, &sa_client, &clen)) < 0) {
	    /* get peername will fail if the input isn't a socket */
	    perror("getpeername");
	    memset(&sa_client, '\0', sizeof(sa_client));
	}

	sock_disable_nagle(csd);
#if 0
        /* ZZZ scoreboard */
	(void) ap_update_child_status(child_num, SERVER_BUSY_READ,
				   (request_rec *) NULL);
#endif

/* ZZZ . This will break CGIs since they need to know whether a fd is a socket or
   a file handle... Fix with APR
*/
	conn_io = ap_bcreate(ptrans, B_RDWR | B_SOCKET);
//	conn_io = ap_bcreate(ptrans, B_RDWR);
	dupped_csd = csd;
#if defined(NEED_DUPPED_CSD)
	if ((dupped_csd = dup(csd)) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
			"dup: couldn't duplicate csd");
	    dupped_csd = csd;	/* Oh well... */
	}
	ap_note_cleanups_for_socket(ptrans, dupped_csd);
#endif
        ap_bpushfd(conn_io, csd); /* ap_bpushfd(conn_io, csd, dupped_csd); why did we drop duped fd? */
        
	current_conn = ap_new_connection(ptrans, server_conf, conn_io,
                                         (struct sockaddr_in *) &sa_client,
                                         (struct sockaddr_in *) &sa_server,
                                         child_num, 0); /* Set my_thread_num to 0 for now */
        
        ap_process_connection(current_conn);
    }        
}


void child_main(int child_num_arg)
{
    /*
     * Only reason for this function, is to pass in
     * arguments to child_sub_main() on its stack so
     * that longjump doesn't try to corrupt its local
     * variables and I don't need to make those
     * damn variables static/global
     */
    child_sub_main(child_num_arg);
}



void cleanup_thread(thread **handles, int *thread_cnt, int thread_to_clean)
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

//extern void main_control_server(void *); /* in hellop.c */

#define MAX_SELECT_ERRORS 100

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

static void setup_inherited_listeners(pool *p)
{
    HANDLE pipe;
    ap_listen_rec *lr;
    int fd;
    WSAPROTOCOL_INFO WSAProtocolInfo;
    DWORD BytesRead;

    /* Open the pipe to the parent process to receive the inherited socket
     * data. The sockets have been set to listening in the parent process.
     */
    pipe = GetStdHandle(STD_INPUT_HANDLE);

    /* Setup the listeners */
    listenmaxfd = -1;
    FD_ZERO(&listenfds);
    lr = ap_listeners;

    FD_ZERO(&listenfds);

    for (;;) {
	fd = find_listener(lr);
	if (fd < 0) {
            if (!ReadFile(pipe, 
                          &WSAProtocolInfo, sizeof(WSAPROTOCOL_INFO),
                          &BytesRead,
                          (LPOVERLAPPED) NULL)){
                ap_log_error(APLOG_MARK, APLOG_WIN32ERROR|APLOG_CRIT, server_conf,
                             "setup_inherited_listeners: Unable to read socket data from parent");
                exit(1);
            }
            fd = WSASocket(FROM_PROTOCOL_INFO,
                           FROM_PROTOCOL_INFO,
                           FROM_PROTOCOL_INFO,
                           &WSAProtocolInfo,
                           0,
                           0);
            if (fd == INVALID_SOCKET) {
                ap_log_error(APLOG_MARK, APLOG_WIN32ERROR|APLOG_CRIT, server_conf,
                             "setup_inherited_listeners: WSASocket failed to get inherit the socket.");
                exit(1);
            }
//            APD2("setup_inherited_listeners: WSASocket() returned socket %d", fd);
	}
	else {
	    ap_note_cleanups_for_socket(p, fd);
	}
	if (fd >= 0) {
	    FD_SET(fd, &listenfds);
	    if (fd > listenmaxfd)
		listenmaxfd = fd;
	}
	lr->fd = fd;
	if (lr->next == NULL)
	    break;
	lr = lr->next;
    }
    /* turn the list into a ring */
    lr->next = ap_listeners;
    head_listener = ap_listeners;
    close_unused_listeners();
    CloseHandle(pipe);
    return;
}

/*
 * worker_main() is main loop for the child process. The loop in
 * this function becomes the controlling thread for the actually working
 * threads (which run in a loop in child_sub_main()).
 */

void worker_main(void)
{
    int nthreads;
    fd_set main_fds;
    int srv;
    int clen;
    int csd;
    int sd = -1; // made this local and not global
    struct sockaddr_in sa_client;
    int total_jobs = 0;
    thread **child_handles;
    int rv;
    time_t end_time;
    int i;
    struct timeval tv;
    int wait_time = 1;
    HANDLE hObjects[2];
    int count_select_errors = 0;
    pool *pchild;

    pchild = ap_make_sub_pool(pconf);

//    ap_standalone = 1;
//    sd = -1; ?? this variable is global in 1.3.x!
    nthreads = ap_threads_per_child;

    if (nthreads <= 0) /* maybe this is not needed... Should be checked in config... */
	nthreads = 1;

    my_pid = getpid();


    ap_restart_time = time(NULL);

//    reinit_scoreboard(pconf);

    /*
     * Wait until we have permission to start accepting connections.
     * start_mutex is used to ensure that only one child ever
     * goes into the listen/accept loop at once. Also wait on exit_event,
     * in case we (this child) is told to die before we get a chance to
     * serve any requests.
     */
    hObjects[0] = (HANDLE)start_mutex;
    hObjects[1] = (HANDLE)exit_event;
    rv = WaitForMultipleObjects(2, hObjects, FALSE, INFINITE);
    if (rv == WAIT_FAILED) {
	ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                     "Waiting for start_mutex or exit_event -- process will exit");

	ap_destroy_pool(pchild);
//	cleanup_scoreboard();
	exit(0);
    }
    if (rv == WAIT_OBJECT_0 + 1) {
	/* exit event signalled - exit now */
	ap_destroy_pool(pchild);
//	cleanup_scoreboard();
	exit(0);
    }
    /* start_mutex obtained, continue into the select() loop */
    if (one_process) {
        setup_listeners(pconf, server_conf);
    } else {
        /* Get listeners from the parent process */
        setup_inherited_listeners(pconf);
    }

    if (listenmaxfd == -1) {
	/* Help, no sockets were made, better log something and exit */
	ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, NULL,
		    "No sockets were created for listening");

	signal_parent(0);	/* tell parent to die */

	ap_destroy_pool(pchild);
//	cleanup_scoreboard();
	exit(0);
    }
//    set_signals();

//    ap_child_init_modules(pconf, server_conf);

    allowed_globals.jobsemaphore = create_semaphore(0);
    allowed_globals.jobmutex = ap_create_mutex(NULL);

    /* spawn off the threads */
    child_handles = (thread *) alloca(nthreads * sizeof(int));
    for (i = 0; i < nthreads; i++) {
	child_handles[i] = create_thread((void (*)(void *)) child_main, (void *) i);
    }

    while (1) {
        if (ap_max_requests_per_child && (total_jobs > ap_max_requests_per_child)) {
            /* MaxRequestsPerChild hit...
             */
            break;
	}
        /* Always check for the exit event being signaled.
         */
        rv = WaitForSingleObject(exit_event, 0);
        ap_assert((rv == WAIT_TIMEOUT) || (rv == WAIT_OBJECT_0));
        if (rv == WAIT_OBJECT_0) {
//            APD1("child: exit event signalled, exiting");
            break;
        }

	tv.tv_sec = wait_time;
	tv.tv_usec = 0;

	memcpy(&main_fds, &listenfds, sizeof(fd_set));
	srv = ap_select(listenmaxfd + 1, &main_fds, NULL, NULL, &tv);
#ifdef WIN32
	if (srv == SOCKET_ERROR) {
	    /* Map the Win32 error into a standard Unix error condition */
	    errno = WSAGetLastError();
	    srv = -1;
	}
#endif /* WIN32 */

	if (srv < 0) {
	    /* Error occurred - if EINTR, loop around with problem */
	    if (errno != EINTR) {
		/* A "real" error occurred, log it and increment the count of
		 * select errors. This count is used to ensure we don't go into
		 * a busy loop of continuous errors.
		 */
		ap_log_error(APLOG_MARK, APLOG_ERR, server_conf, "select: (listen)");
		count_select_errors++;
		if (count_select_errors > MAX_SELECT_ERRORS) {
		    ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, server_conf,
			"Too many errors in select loop. Child process exiting.");
		    break;
		}
	    }
	    continue;
	}
	count_select_errors = 0;    /* reset count of errors */
	if (srv == 0) {
            continue;
	}

	{
	    ap_listen_rec *lr;

	    lr = find_ready_listener(&main_fds);
	    if (lr != NULL) {
		sd = lr->fd;
	    }
	}
	do {
	    clen = sizeof(sa_client);
	    csd = accept(sd, (struct sockaddr *) &sa_client, &clen);
#ifdef WIN32
	    if (csd == INVALID_SOCKET) {
		csd = -1;
		errno = WSAGetLastError();
	    }
#endif /* WIN32 */
	} while (csd < 0 && errno == EINTR);

	if (csd < 0) {
#if defined(EPROTO) && defined(ECONNABORTED)
	    if ((errno != EPROTO) && (errno != ECONNABORTED))
#elif defined(EPROTO)
	    if (errno != EPROTO)
#elif defined(ECONNABORTED)
	    if (errno != ECONNABORTED)
#endif
		ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
			    "accept: (client socket)");
	}
	else {
	    add_job(csd);
	    total_jobs++;
	}
    }
      
//    APD2("process PID %d exiting", my_pid);

    /* Get ready to shutdown and exit */
    allowed_globals.exit_now = 1;
    ap_release_mutex(start_mutex);

#ifdef UNGRACEFUL_RESTART
    SetEvent(allowed_globals.thread_exit_event);
#else
    for (i = 0; i < nthreads; i++) {
	add_job(-1);
    }
#endif

//    APD2("process PID %d waiting for worker threads to exit", my_pid);
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

//    APD2("process PID %d killing remaining worker threads", my_pid);
    for (i = 0; i < nthreads; i++) {
	kill_thread(child_handles[i]);
	free_thread(child_handles[i]);
    }
#ifdef UNGRACEFUL_RESTART
    ap_assert(CloseHandle(allowed_globals.thread_exit_event));
#endif
    destroy_semaphore(allowed_globals.jobsemaphore);
    ap_destroy_mutex(allowed_globals.jobmutex);

//    ap_child_exit_modules(pconf, server_conf);
    ap_destroy_pool(pchild);

//    cleanup_scoreboard();

//    APD2("process PID %d exited", my_pid);
//    clean_parent_exit(0);
}				/* standalone_main */

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

//    APD4("cleanup_processes: removed child in slot %d handle %d, max=%d", position, handle, *processes);
}

static int create_process(pool *p, HANDLE *handles, HANDLE *events, 
                          int *processes, int *child_num, char *kill_event_name)
{

    int rv, i;
    HANDLE kill_event;
    char buf[1024];
    char exit_event_name[40]; /* apPID_C# */
    char *pCommand;
    char *pEnvBlock;

    STARTUPINFO si;           /* Filled in prior to call to CreateProcess */
    PROCESS_INFORMATION pi;   /* filled in on call to CreateProces */
    LPWSAPROTOCOL_INFO  lpWSAProtocolInfo;
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
    
    /* Create the exit event (apPID_C#). Parent signals this event to tell the
     * child to exit 
     */
    ap_snprintf(exit_event_name, sizeof(exit_event_name), "%s_C%d", kill_event_name, ++(*child_num));
    kill_event = CreateEvent(NULL, TRUE, FALSE, exit_event_name);
    if (!kill_event) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, server_conf,
                     "Parent: Could not create exit event for child process");
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

    pEnvBlock = ap_psprintf(p, "AP_PARENT_PID=%d\0AP_CHILD_NUM=%d\0\0",parent_pid,*child_num);

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
                       TRUE,      /* Inherit handles */
                       0,         /* Creation flags */
                       pEnvBlock, /* Environment block */
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
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, server_conf,
                     "Parent: Created child process %d", pi.dwProcessId);

        /* Assume the child process lives. Update the process and event tables */
        handles[*processes] = pi.hProcess;
        events[*processes] = kill_event;
        (*processes)++;

        /* We never store the thread's handle, so close it now. */
        CloseHandle(pi.hThread);

        /* Run the chain of open sockets. For each socket, duplicate it 
         * for the target process then send the WSAPROTOCOL_INFO 
         * (returned by dup socket) to the child */
        lr = ap_listeners;
        while (lr != NULL) {
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

            lr = lr->next;
            if (lr == ap_listeners)
                break;
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

    /* Create child process 
     * Should only be one in this version of Apache for WIN32 
     */
    while (remaining_children_to_start--) {
        if (create_process(pconf, process_handles, process_kill_events, 
                           &current_live_processes, &child_num, signal_prefix_string) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, server_conf,
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
        /* Signal each child processes to die */
        for (i = 0; i < current_live_processes; i++) {
//                APD3("master_main: signalling child %d, handle %d to die", i, process_handles[i]);
            if (SetEvent(process_kill_events[i]) == 0)
                ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_WIN32ERROR, server_conf,
                             "master_main: SetEvent for child process in slot #%d failed", i);
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
        while (current_live_processes && ((tmstart+60) > time(NULL))) {
            rv = WaitForMultipleObjects(current_live_processes, (HANDLE *)process_handles, FALSE, 2000);
            if (rv == WAIT_TIMEOUT)
                continue;
            ap_assert(rv != WAIT_FAILED);
            cld = rv - WAIT_OBJECT_0;
            ap_assert(rv < current_live_processes);
//            APD4("main_process: child in #%d handle %d died, left=%d", 
//                 rv, process_handles[rv], current_live_processes);
            cleanup_process(process_handles, process_kill_events, cld, &current_live_processes);
        }
        for (i = 0; i < current_live_processes; i++) {
            ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, server_conf,
                         "forcing termination of child #%d (handle %d)", i, process_handles[i]);
            TerminateProcess((HANDLE) process_handles[i], 1);
        }
        return (0); /* Tell the caller we are shutting down */
    }

    return (1); /* Tell the call we want a restart */
}

/* 
 * winnt_pre_config()
 * Gets called twice at startup. 
 */
static void winnt_pre_config(pool *pconf, pool *plog, pool *ptemp) 
{
    char *pid;
    one_process = !!getenv("ONE_PROCESS");

    /* Track parent/child pids... */
    pid = getenv("AP_PARENT_PID");
    if (pid) {
        /* AP_PARENT_PID is only valid in the child */
        parent_pid = atoi(pid);
        my_pid = getpid();
    }
    else {
        /* This is the parent... */
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

/*
Need to register this hook if we want it...
*/
static void winnt_post_config(pool *pconf, pool *plog, pool *ptemp, server_rec* server_conf)
{
    server_conf = server_conf;
}

API_EXPORT(int) ap_mpm_run(pool *_pconf, pool *plog, server_rec *s )
{

    int child_num;
    char* exit_event_name;

    int i;
    time_t tmstart;
    HANDLE shutdown_event;	/* used to signal shutdown to parent */
    HANDLE restart_event;	/* used to signal a restart to parent */

    pconf = _pconf;
    server_conf = s;

    if ((parent_pid != my_pid) || one_process) {
        /* Child process */
        child_num = atoi(getenv("AP_CHILD_NUM"));
        exit_event_name = ap_psprintf(pconf, "ap_%d_C%d", parent_pid, child_num);
        exit_event = open_event(exit_event_name);
        setup_signal_names(ap_psprintf(pconf,"ap_%d", parent_pid));
        start_mutex = ap_open_mutex(signal_name_prefix);
        ap_assert(start_mutex);

        worker_main();


        destroy_event(exit_event);
    }
    else {
        /* Parent process */
        static int restart = 0;
        PSECURITY_ATTRIBUTES sa = GetNullACL();  /* returns NULL if invalid (Win95?) */
        ap_clear_pool(plog);
        ap_open_logs(server_conf, plog);

        if (!restart) {
            /* service_set_status(SERVICE_START_PENDING);*/

            setup_signal_names(ap_psprintf(pconf,"ap_%d", parent_pid));
        
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
            start_mutex = ap_create_mutex(signal_prefix_string);        
            /* TOTD: Add some code to detect failure */
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
   /*
    ap_hook_post_config()...);
    ap_hook_open_logs(xxx,NULL,NULL,HOOK_MIDDLE);
   */

/*
    ap_hook_translate_name(xxx,NULL,NULL,HOOK_REALLY_LAST);
    ap_hook_process_connection(xxx,NULL,NULL,
			       HOOK_REALLY_LAST);
    ap_hook_http_method(xxx,NULL,NULL,HOOK_REALLY_LAST);
    ap_hook_default_port(xxx,NULL,NULL,HOOK_REALLY_LAST);

    // FIXME: I suspect we can eliminate the need for these - Ben
    ap_hook_type_checker(xxx,NULL,NULL,HOOK_REALLY_LAST);
*/
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
                "limit of %d threads,\n", ap_threads_per_child,
                HARD_THREAD_LIMIT);
        fprintf(stderr, " lowering ThreadsPerChild to %d. To increase, please"
                "see the\n", HARD_THREAD_LIMIT);
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
    NULL, 			/* child_init */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    winnt_cmds,		        /* command table */
    NULL,			/* handlers */
    NULL,			/* check auth */
    NULL,			/* check access */
    winnt_hooks 		/* register_hooks */
};

/* force Expat to be linked into the server executable */
#if defined(USE_EXPAT) && !defined(SHARED_CORE_BOOTSTRAP)
#include "xmlparse.h"
const XML_LChar *suck_in_expat(void);
const XML_LChar *suck_in_expat(void)
{
    return XML_ErrorString(XML_ERROR_NONE);
}
#endif /* USE_EXPAT */
