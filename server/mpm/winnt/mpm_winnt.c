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


/* scoreboard.c does the heavy lifting; all we do is create the child
 * score by moving a handle down the pipe into the child's stdin.
 */
extern apr_shm_t *ap_scoreboard_shm;
server_rec *ap_server_conf;

/* Definitions of WINNT MPM specific config globals */
static HANDLE shutdown_event;	/* used to signal the parent to shutdown */
static HANDLE restart_event;	/* used to signal the parent to restart */

static char ap_coredump_dir[MAX_STRING_LEN];

static int one_process = 0;
static char const* signal_arg = NULL;

OSVERSIONINFO osver; /* VER_PLATFORM_WIN32_NT */

static DWORD parent_pid;
DWORD my_pid;

int ap_threads_per_child = 0;
int use_acceptex = 1;
static int thread_limit = DEFAULT_THREAD_LIMIT;
static int first_thread_limit = 0;
static int changed_limit_at_restart;
int winnt_mpm_state = AP_MPMQ_STARTING;

/* ap_my_generation are used by the scoreboard code */
ap_generation_t volatile ap_my_generation=0;


/* shared by service.c as global, although 
 * perhaps it should be private.
 */
apr_pool_t *pconf;


/* definitions from child.c */
void child_main(apr_pool_t *pconf);

/* used by parent to signal the child to start and exit
 * NOTE: these are not sophisticated enough for multiple children
 * so they ultimately should not be shared with child.c
 */
extern apr_proc_mutex_t *start_mutex;
extern HANDLE exit_event;  


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
    if (ap_threads_per_child > thread_limit) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: ThreadsPerChild of %d exceeds ThreadLimit "
                     "value of %d threads,", ap_threads_per_child, 
                     thread_limit);
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     " lowering ThreadsPerChild to %d. To increase, please"
                     " see the", thread_limit);
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     " ThreadLimit directive.");
        ap_threads_per_child = thread_limit;
    }
    else if (ap_threads_per_child < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require ThreadsPerChild > 0, setting to 1");
	ap_threads_per_child = 1;
    }
    return NULL;
}
static const char *set_thread_limit (cmd_parms *cmd, void *dummy, const char *arg) 
{
    int tmp_thread_limit;
    
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    tmp_thread_limit = atoi(arg);
    /* you cannot change ThreadLimit across a restart; ignore
     * any such attempts
     */
    if (first_thread_limit &&
        tmp_thread_limit != thread_limit) {
        /* how do we log a message?  the error log is a bit bucket at this
         * point; we'll just have to set a flag so that ap_mpm_run()
         * logs a warning later
         */
        changed_limit_at_restart = 1;
        return NULL;
    }
    thread_limit = tmp_thread_limit;
    
    if (thread_limit > MAX_THREAD_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    "WARNING: ThreadLimit of %d exceeds compile time limit "
                    "of %d threads,", thread_limit, MAX_THREAD_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                    " lowering ThreadLimit to %d.", MAX_THREAD_LIMIT);
       thread_limit = MAX_THREAD_LIMIT;
    } 
    else if (thread_limit < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "WARNING: Require ThreadLimit > 0, setting to 1");
	thread_limit = 1;
    }
    return NULL;
}
static const char *set_disable_acceptex(cmd_parms *cmd, void *dummy, char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                     "Ignoring Win32EnableAcceptEx configuration directive. "
                     "The directive is not valid on Windows 9x");
        return NULL;
    }

    use_acceptex = 0;

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                         "Disabled use AcceptEx WinSock2 API");
    return NULL;
}

static const command_rec winnt_cmds[] = {
LISTEN_COMMANDS,
AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
  "Number of threads each child creates" ),
AP_INIT_TAKE1("ThreadLimit", set_thread_limit, NULL, RSRC_CONF,
  "Maximum worker threads in a server for this run of Apache"),
AP_INIT_NO_ARGS("Win32DisableAcceptEx", set_disable_acceptex, NULL, RSRC_CONF,
  "Disable use of the high performance AcceptEx WinSock2 API to work around buggy VPN or Firewall software"),

{ NULL }
};


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

int volatile is_graceful = 0;

AP_DECLARE(int) ap_graceful_stop_signalled(void)
{
    return is_graceful;
}

AP_DECLARE(void) ap_signal_parent(ap_signal_parent_e type)
{
    HANDLE e;
    char *signal_name;
    
    if (parent_pid == my_pid) {
        switch(type) {
           case SIGNAL_PARENT_SHUTDOWN: 
           {
               winnt_mpm_state = AP_MPMQ_STOPPING;
               SetEvent(shutdown_event); 
               break;
           }
           /* This MPM supports only graceful restarts right now */
           case SIGNAL_PARENT_RESTART: 
           case SIGNAL_PARENT_RESTART_GRACEFUL:
           {
               winnt_mpm_state = AP_MPMQ_STOPPING;
               is_graceful = 1;
               SetEvent(restart_event); 
               break;
           }
        }
	return;
    }

    switch(type) {
       case SIGNAL_PARENT_SHUTDOWN: 
       {
           winnt_mpm_state = AP_MPMQ_STOPPING;
           signal_name = signal_shutdown_name; 
           break;
       }
       /* This MPM supports only graceful restarts right now */
       case SIGNAL_PARENT_RESTART: 
       case SIGNAL_PARENT_RESTART_GRACEFUL:
       {
           winnt_mpm_state = AP_MPMQ_STOPPING;
           signal_name = signal_restart_name;     
           is_graceful = 1;
           break;
       }
       default: 
           return;
    }

    e = OpenEvent(EVENT_MODIFY_STATE, FALSE, signal_name);
    if (!e) {
	/* Um, problem, can't signal the parent, which means we can't
	 * signal ourselves to die. Ignore for now...
	 */
	ap_log_error(APLOG_MARK, APLOG_EMERG, apr_get_os_error(), ap_server_conf,
                     "OpenEvent on %s event", signal_name);
	return;
    }
    if (SetEvent(e) == 0) {
	/* Same problem as above */
	ap_log_error(APLOG_MARK, APLOG_EMERG, apr_get_os_error(), ap_server_conf,
                     "SetEvent on %s event", signal_name);
	CloseHandle(e);
	return;
    }
    CloseHandle(e);
}


/*
 * Passed the following handles [in sync with send_handles_to_child()]
 *
 *   ready event [signal the parent immediately, then close]
 *   exit event  [save to poll later]
 *   start mutex [signal from the parent to begin accept()]
 *   scoreboard shm handle [to recreate the ap_scoreboard]
 */
void get_handles_from_parent(server_rec *s, HANDLE *child_exit_event,
                             apr_proc_mutex_t **child_start_mutex,
                             apr_shm_t **scoreboard_shm)
{
    HANDLE pipe;
    HANDLE hScore;
    HANDLE ready_event;
    HANDLE os_start;
    DWORD BytesRead;
    void *sb_shared;
    apr_status_t rv;
    
    pipe = GetStdHandle(STD_INPUT_HANDLE);
    if (!ReadFile(pipe, &ready_event, sizeof(HANDLE),
                  &BytesRead, (LPOVERLAPPED) NULL)
        || (BytesRead != sizeof(HANDLE))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Child %d: Unable to retrieve the ready event from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }

    SetEvent(ready_event);
    CloseHandle(ready_event);

    if (!ReadFile(pipe, child_exit_event, sizeof(HANDLE),
                  &BytesRead, (LPOVERLAPPED) NULL)
        || (BytesRead != sizeof(HANDLE))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Child %d: Unable to retrieve the exit event from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }

    if (!ReadFile(pipe, &os_start, sizeof(os_start),
                  &BytesRead, (LPOVERLAPPED) NULL)
        || (BytesRead != sizeof(os_start))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Child %d: Unable to retrieve the start_mutex from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }
    *child_start_mutex = NULL;
    if ((rv = apr_os_proc_mutex_put(child_start_mutex, &os_start, s->process->pool))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Child %d: Unable to access the start_mutex from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }

    if (!ReadFile(pipe, &hScore, sizeof(hScore),
                  &BytesRead, (LPOVERLAPPED) NULL)
        || (BytesRead != sizeof(hScore))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Child %d: Unable to retrieve the scoreboard from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }
    *scoreboard_shm = NULL;
    if ((rv = apr_os_shm_put(scoreboard_shm, &hScore, s->process->pool)) 
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Child %d: Unable to access the scoreboard from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }

    rv = ap_reopen_scoreboard(s->process->pool, scoreboard_shm, 1);
    if (rv || !(sb_shared = apr_shm_baseaddr_get(*scoreboard_shm))) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, 
                     "Child %d: Unable to reopen the scoreboard from the parent", my_pid);
        exit(APEXIT_CHILDINIT);
    }
    /* We must 'initialize' the scoreboard to relink all the
     * process-local pointer arrays into the shared memory block.
     */
    ap_init_scoreboard(sb_shared);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "Child %d: Retrieved our scoreboard from the parent.", my_pid);
}


static int send_handles_to_child(apr_pool_t *p, 
                                 HANDLE child_ready_event,
                                 HANDLE child_exit_event, 
                                 apr_proc_mutex_t *child_start_mutex,
                                 apr_shm_t *scoreboard_shm,
                                 HANDLE hProcess, 
                                 apr_file_t *child_in)
{
    apr_status_t rv;
    HANDLE hCurrentProcess = GetCurrentProcess();
    HANDLE hDup;
    HANDLE os_start;
    HANDLE hScore;
    DWORD BytesWritten;

    if (!DuplicateHandle(hCurrentProcess, child_ready_event, hProcess, &hDup,
        EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, 0)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Parent: Unable to duplicate the ready event handle for the child");
        return -1;
    }
    if ((rv = apr_file_write_full(child_in, &hDup, sizeof(hDup), &BytesWritten))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Unable to send the exit event handle to the child");
        return -1;
    }
    if (!DuplicateHandle(hCurrentProcess, child_exit_event, hProcess, &hDup,
                         EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, 0)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Parent: Unable to duplicate the exit event handle for the child");
        return -1;
    }
    if ((rv = apr_file_write_full(child_in, &hDup, sizeof(hDup), &BytesWritten))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Unable to send the exit event handle to the child");
        return -1;
    }
    if ((rv = apr_os_proc_mutex_get(&os_start, child_start_mutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Unable to retrieve the start mutex for the child");
        return -1;
    }
    if (!DuplicateHandle(hCurrentProcess, os_start, hProcess, &hDup,
                         SYNCHRONIZE, FALSE, 0)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Parent: Unable to duplicate the start mutex to the child");
        return -1;
    }
    if ((rv = apr_file_write_full(child_in, &hDup, sizeof(hDup), &BytesWritten))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Unable to send the start mutex to the child");
        return -1;
    }
    if ((rv = apr_os_shm_get(&hScore, scoreboard_shm)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Unable to retrieve the scoreboard handle for the child");
        return -1;
    }
    if (!DuplicateHandle(hCurrentProcess, hScore, hProcess, &hDup,
                         FILE_MAP_READ | FILE_MAP_WRITE, FALSE, 0)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Parent: Unable to duplicate the scoreboard handle to the child");
        return -1;
    }
    if ((rv = apr_file_write_full(child_in, &hDup, sizeof(hDup), &BytesWritten))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Unable to send the scoreboard handle to the child");
        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "Parent: Sent the scoreboard to the child");
    return 0;
}


/* 
 * get_listeners_from_parent()
 * The listen sockets are opened in the parent. This function, which runs
 * exclusively in the child process, receives them from the parent and
 * makes them availeble in the child.
 */
void get_listeners_from_parent(server_rec *s)
{
    WSAPROTOCOL_INFO WSAProtocolInfo;
    HANDLE pipe;
    ap_listen_rec *lr;
    DWORD BytesRead;
    int lcnt = 0;
    SOCKET nsd;

    /* Set up a default listener if necessary */
    if (ap_listeners == NULL) {
        ap_listen_rec *lr;
        lr = apr_palloc(s->process->pool, sizeof(ap_listen_rec));
        lr->sd = NULL;
        lr->next = ap_listeners;
        ap_listeners = lr;
    }

    /* Open the pipe to the parent process to receive the inherited socket
     * data. The sockets have been set to listening in the parent process.
     */
    pipe = GetStdHandle(STD_INPUT_HANDLE);

    for (lr = ap_listeners; lr; lr = lr->next, ++lcnt) {
        if (!ReadFile(pipe, &WSAProtocolInfo, sizeof(WSAPROTOCOL_INFO), 
                      &BytesRead, (LPOVERLAPPED) NULL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                         "setup_inherited_listeners: Unable to read socket data from parent");
            exit(APEXIT_CHILDINIT);
        }
        nsd = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                        &WSAProtocolInfo, 0, 0);
        if (nsd == INVALID_SOCKET) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), ap_server_conf,
                         "Child %d: setup_inherited_listeners(), WSASocket failed to open the inherited socket.", my_pid);
            exit(APEXIT_CHILDINIT);
        }

        if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
            HANDLE hProcess = GetCurrentProcess();
            HANDLE dup;
            if (DuplicateHandle(hProcess, (HANDLE) nsd, hProcess, &dup, 
                                0, FALSE, DUPLICATE_SAME_ACCESS)) {
                closesocket(nsd);
                nsd = (SOCKET) dup;
            }
        }
        else {
            /* A different approach.  Many users report errors such as 
             * (32538)An operation was attempted on something that is not 
             * a socket.  : Parent: WSADuplicateSocket failed...
             *
             * This appears that the duplicated handle is no longer recognized
             * as a socket handle.  SetHandleInformation should overcome that
             * problem by not altering the handle identifier.  But this won't
             * work on 9x - it's unsupported.
             */
            if (!SetHandleInformation((HANDLE)nsd, HANDLE_FLAG_INHERIT, 0)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), ap_server_conf,
                             "set_listeners_noninheritable: SetHandleInformation failed.");
            }
        }
        apr_os_sock_put(&lr->sd, &nsd, s->process->pool);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "Child %d: retrieved %d listeners from parent", my_pid, lcnt);
}


static int send_listeners_to_child(apr_pool_t *p, DWORD dwProcessId, 
                                   apr_file_t *child_in)
{
    apr_status_t rv;
    int lcnt = 0;
    ap_listen_rec *lr;
    LPWSAPROTOCOL_INFO  lpWSAProtocolInfo;
    DWORD BytesWritten;

    /* Run the chain of open sockets. For each socket, duplicate it 
     * for the target process then send the WSAPROTOCOL_INFO 
     * (returned by dup socket) to the child.
     */
    for (lr = ap_listeners; lr; lr = lr->next, ++lcnt) {
        int nsd;
        lpWSAProtocolInfo = apr_pcalloc(p, sizeof(WSAPROTOCOL_INFO));
        apr_os_sock_get(&nsd,lr->sd);
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, ap_server_conf,
                     "Parent: Duplicating socket %d and sending it to child process %d", 
                     nsd, dwProcessId);
        if (WSADuplicateSocket(nsd, dwProcessId,
                               lpWSAProtocolInfo) == SOCKET_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_netos_error(), ap_server_conf,
                         "Parent: WSADuplicateSocket failed for socket %d. Check the FAQ.", lr->sd );
            return -1;
        }

        if ((rv = apr_file_write_full(child_in, lpWSAProtocolInfo, 
                                      sizeof(WSAPROTOCOL_INFO), &BytesWritten))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                         "Parent: Unable to write duplicated socket %d to the child.", lr->sd );
            return -1;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "Parent: Sent %d listeners to child %d", lcnt, dwProcessId);
    return 0;
}

enum waitlist_e {
    waitlist_ready = 0,
    waitlist_term = 1
};

static int create_process(apr_pool_t *p, HANDLE *child_proc, HANDLE *child_exit_event, 
                          DWORD *child_pid)
{
    /* These NEVER change for the lifetime of this parent 
     */
    static char **args = NULL;
    static char **env = NULL;
    static char pidbuf[28];

    apr_status_t rv;
    apr_pool_t *ptemp;
    apr_procattr_t *attr;
    apr_file_t *child_out;
    apr_file_t *child_err;
    apr_proc_t new_child;
    HANDLE hExitEvent;
    HANDLE waitlist[2];  /* see waitlist_e */
    char *cmd;
    char *cwd;

    apr_pool_create_ex(&ptemp, p, NULL, NULL);

    /* Build the command line. Should look something like this:
     * C:/apache/bin/apache.exe -f ap_server_confname 
     * First, get the path to the executable...
     */
    apr_procattr_create(&attr, ptemp);
    apr_procattr_cmdtype_set(attr, APR_PROGRAM);
    apr_procattr_detach_set(attr, 1);
    if (((rv = apr_filepath_get(&cwd, 0, ptemp)) != APR_SUCCESS)
           || ((rv = apr_procattr_dir_set(attr, cwd)) != APR_SUCCESS)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Failed to get the current path");
    }

    if (!args) {
        /* Build the args array, only once since it won't change 
         * for the lifetime of this parent process.
         */
        if ((rv = ap_os_proc_filepath(&cmd, ptemp))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, ERROR_BAD_PATHNAME, ap_server_conf,
                         "Parent: Failed to get full path of %s", 
                         ap_server_conf->process->argv[0]);
            apr_pool_destroy(ptemp);
            return -1;
        }
        
        args = malloc((ap_server_conf->process->argc + 1) * sizeof (char*));
        memcpy(args + 1, ap_server_conf->process->argv + 1, 
               (ap_server_conf->process->argc - 1) * sizeof (char*));
        args[0] = malloc(strlen(cmd) + 1);
        strcpy(args[0], cmd);
        args[ap_server_conf->process->argc] = NULL;
    }
    else {
        cmd = args[0];
    }

    /* Create a pipe to send handles to the child */
    if ((rv = apr_procattr_io_set(attr, APR_FULL_BLOCK, 
                                  APR_NO_PIPE, APR_NO_PIPE)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                        "Parent: Unable to create child stdin pipe.\n");
        apr_pool_destroy(ptemp);
        return -1;
    }

    /* Open a null handle to soak info from the child */
    if (((rv = apr_file_open(&child_out, "NUL", APR_READ | APR_WRITE, 
                             APR_OS_DEFAULT, ptemp)) != APR_SUCCESS)
        || ((rv = apr_procattr_child_out_set(attr, child_out, NULL)) 
                != APR_SUCCESS)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                        "Parent: Unable to connect child stdout to NUL.\n");
        apr_pool_destroy(ptemp);
        return -1;
    }

    /* Connect the child's initial stderr to our main server error log 
     * or share our own stderr handle.
     */
    if (ap_server_conf->error_log) {
        child_err = ap_server_conf->error_log;
    }
    else {
        rv = apr_file_open_stderr(&child_err, ptemp);
    }
    if (rv == APR_SUCCESS) {
        if ((rv = apr_procattr_child_err_set(attr, child_err, NULL))
                != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                            "Parent: Unable to connect child stderr.\n");
            apr_pool_destroy(ptemp);
            return -1;
        }
    }

    /* Create the child_ready_event */
    waitlist[waitlist_ready] = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!waitlist[waitlist_ready]) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Parent: Could not create ready event for child process");
        apr_pool_destroy (ptemp);
        return -1;
    }

    /* Create the child_exit_event */
    hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hExitEvent) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "Parent: Could not create exit event for child process");
        apr_pool_destroy(ptemp);
        CloseHandle(waitlist[waitlist_ready]);
        return -1;
    }

    if (!env) 
    {
        /* Build the env array, only once since it won't change 
         * for the lifetime of this parent process.
         */
        int envc;
        for (envc = 0; _environ[envc]; ++envc) {
            ;
        }
        env = malloc((envc + 2) * sizeof (char*));
        memcpy(env, _environ, envc * sizeof (char*));
        apr_snprintf(pidbuf, sizeof(pidbuf), "AP_PARENT_PID=%i", parent_pid);
        env[envc] = pidbuf;
        env[envc + 1] = NULL;
    }

    rv = apr_proc_create(&new_child, cmd, args, env, attr, ptemp);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                     "Parent: Failed to create the child process.");
        apr_pool_destroy(ptemp);
        CloseHandle(hExitEvent);
        CloseHandle(waitlist[waitlist_ready]);
        CloseHandle(new_child.hproc);
        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                 "Parent: Created child process %d", new_child.pid);

    if (send_handles_to_child(ptemp, waitlist[waitlist_ready], hExitEvent,
                              start_mutex, ap_scoreboard_shm,
                              new_child.hproc, new_child.in)) {
        /*
         * This error is fatal, mop up the child and move on
         * We toggle the child's exit event to cause this child 
         * to quit even as it is attempting to start.
         */
        SetEvent(hExitEvent);
        apr_pool_destroy(ptemp);
        CloseHandle(hExitEvent);
        CloseHandle(waitlist[waitlist_ready]);
        CloseHandle(new_child.hproc);
        return -1;
    }

    /* Important:
     * Give the child process a chance to run before dup'ing the sockets.
     * We have already set the listening sockets noninheritable, but if 
     * WSADuplicateSocket runs before the child process initializes
     * the listeners will be inherited anyway.
     */
    waitlist[waitlist_term] = new_child.hproc;
    rv = WaitForMultipleObjects(2, waitlist, FALSE, INFINITE);
    CloseHandle(waitlist[waitlist_ready]);
    if (rv != WAIT_OBJECT_0) {
        /* 
         * Outch... that isn't a ready signal. It's dead, Jim!
         */
        SetEvent(hExitEvent);
        apr_pool_destroy(ptemp);
        CloseHandle(hExitEvent);
        CloseHandle(new_child.hproc);
        return -1;
    }

    if (send_listeners_to_child(ptemp, new_child.pid, new_child.in)) {
        /*
         * This error is fatal, mop up the child and move on
         * We toggle the child's exit event to cause this child 
         * to quit even as it is attempting to start.
         */
        SetEvent(hExitEvent);
        apr_pool_destroy(ptemp);
        CloseHandle(hExitEvent);
        CloseHandle(new_child.hproc);
        return -1;
    }

    *child_exit_event = hExitEvent;
    *child_proc = new_child.hproc;
    *child_pid = new_child.pid;

    return 0;
}

/***********************************************************************
 * master_main()
 * master_main() runs in the parent process.  It creates the child 
 * process which handles HTTP requests then waits on one of three 
 * events:
 *
 * restart_event
 * -------------
 * The restart event causes master_main to start a new child process and
 * tells the old child process to exit (by setting the child_exit_event).
 * The restart event is set as a result of one of the following:
 * 1. An apache -k restart command on the command line
 * 2. A command received from Windows service manager which gets 
 *    translated into an ap_signal_parent(SIGNAL_PARENT_RESTART)
 *    call by code in service.c.
 * 3. The child process calling ap_signal_parent(SIGNAL_PARENT_RESTART)
 *    as a result of hitting MaxRequestsPerChild.
 *
 * shutdown_event 
 * --------------
 * The shutdown event causes master_main to tell the child process to 
 * exit and that the server is shutting down. The shutdown event is
 * set as a result of one of the following:
 * 1. An apache -k shutdown command on the command line
 * 2. A command received from Windows service manager which gets
 *    translated into an ap_signal_parent(SIGNAL_PARENT_SHUTDOWN)
 *    call by code in service.c.
 *
 * child process handle
 * --------------------
 * The child process handle will be signaled if the child process 
 * exits for any reason. In a normal running server, the signaling
 * of this event means that the child process has exited prematurely
 * due to a seg fault or other irrecoverable error. For server
 * robustness, master_main will restart the child process under this 
 * condtion.
 *
 * master_main uses the child_exit_event to signal the child process
 * to exit.
 **********************************************************************/
#define NUM_WAIT_HANDLES 3
#define CHILD_HANDLE     0
#define SHUTDOWN_HANDLE  1
#define RESTART_HANDLE   2
static int master_main(server_rec *s, HANDLE shutdown_event, HANDLE restart_event)
{
    int rv, cld;
    int restart_pending;
    int shutdown_pending;
    HANDLE child_exit_event;
    HANDLE event_handles[NUM_WAIT_HANDLES];
    DWORD child_pid;

    restart_pending = shutdown_pending = 0;

    event_handles[SHUTDOWN_HANDLE] = shutdown_event;
    event_handles[RESTART_HANDLE] = restart_event;

    /* Create a single child process */
    rv = create_process(pconf, &event_handles[CHILD_HANDLE], 
                        &child_exit_event, &child_pid);
    if (rv < 0) 
    {
        ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "master_main: create child process failed. Exiting.");
        shutdown_pending = 1;
        goto die_now;
    }
    if (!strcasecmp(signal_arg, "runservice")) {
        mpm_service_started();
    }

    /* Update the scoreboard. Note that there is only a single active
     * child at once.
     */
    ap_scoreboard_image->parent[0].quiescing = 0;
    ap_scoreboard_image->parent[0].pid = child_pid;

    /* Wait for shutdown or restart events or for child death */
    rv = WaitForMultipleObjects(NUM_WAIT_HANDLES, (HANDLE *) event_handles, FALSE, INFINITE);
    cld = rv - WAIT_OBJECT_0;
    if (rv == WAIT_FAILED) {
        /* Something serious is wrong */
        ap_log_error(APLOG_MARK,APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                     "master_main: WaitForMultipeObjects WAIT_FAILED -- doing server shutdown");
        shutdown_pending = 1;
    }
    else if (rv == WAIT_TIMEOUT) {
        /* Hey, this cannot happen */
        ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                     "master_main: WaitForMultipeObjects with INFINITE wait exited with WAIT_TIMEOUT");
        shutdown_pending = 1;
    }
    else if (cld == SHUTDOWN_HANDLE) {
        /* shutdown_event signalled */
        shutdown_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, s, 
                     "Parent: Received shutdown signal -- Shutting down the server.");
        if (ResetEvent(shutdown_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                         "ResetEvent(shutdown_event)");
        }
    }
    else if (cld == RESTART_HANDLE) {
        /* Received a restart event. Prepare the restart_event to be reused 
         * then signal the child process to exit. 
         */
        restart_pending = 1;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
                     "Parent: Received restart signal -- Restarting the server.");
        if (ResetEvent(restart_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                         "Parent: ResetEvent(restart_event) failed.");
        }
        if (SetEvent(child_exit_event) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, apr_get_os_error(), s,
                         "Parent: SetEvent for child process %d failed.", 
                         event_handles[CHILD_HANDLE]);
        }
        /* Don't wait to verify that the child process really exits, 
         * just move on with the restart.
         */
        CloseHandle(event_handles[CHILD_HANDLE]);
        event_handles[CHILD_HANDLE] = NULL;
    }
    else {
        /* The child process exited prematurely due to a fatal error. */
        DWORD exitcode;
        if (!GetExitCodeProcess(event_handles[CHILD_HANDLE], &exitcode)) {
            /* HUH? We did exit, didn't we? */
            exitcode = APEXIT_CHILDFATAL;
        }
        if (   exitcode == APEXIT_CHILDFATAL 
            || exitcode == APEXIT_CHILDINIT
            || exitcode == APEXIT_INIT) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, 
                         "Parent: child process exited with status %u -- Aborting.", exitcode);
        }
        else {
            int i;
            restart_pending = 1;
            ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, ap_server_conf, 
                         "Parent: child process exited with status %u -- Restarting.", exitcode);
            for (i = 0; i < ap_threads_per_child; i++) {
                ap_update_child_status_from_indexes(0, i, SERVER_DEAD, NULL);
            }
        }
        CloseHandle(event_handles[CHILD_HANDLE]);
        event_handles[CHILD_HANDLE] = NULL;
    }
    if (restart_pending) {
        ++ap_my_generation;
        ap_scoreboard_image->global->running_generation = ap_my_generation;
    }
die_now:
    if (shutdown_pending) 
    {
        int timeout = 30000;  /* Timeout is milliseconds */

        /* This shutdown is only marginally graceful. We will give the 
         * child a bit of time to exit gracefully. If the time expires,
         * the child will be wacked.
         */
        if (!strcasecmp(signal_arg, "runservice")) {
            mpm_service_stopping();
        }
        /* Signal the child processes to exit */
        if (SetEvent(child_exit_event) == 0) {
                ap_log_error(APLOG_MARK,APLOG_ERR, apr_get_os_error(), ap_server_conf,
                             "Parent: SetEvent for child process %d failed", event_handles[CHILD_HANDLE]);
        }
        if (event_handles[CHILD_HANDLE]) {
            rv = WaitForSingleObject(event_handles[CHILD_HANDLE], timeout);
            if (rv == WAIT_OBJECT_0) {
                ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                             "Parent: Child process exited successfully.");
                CloseHandle(event_handles[CHILD_HANDLE]);
                event_handles[CHILD_HANDLE] = NULL;
            }
            else {
                ap_log_error(APLOG_MARK,APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                             "Parent: Forcing termination of child process %d ", event_handles[CHILD_HANDLE]);
                TerminateProcess(event_handles[CHILD_HANDLE], 1);
                CloseHandle(event_handles[CHILD_HANDLE]);
                event_handles[CHILD_HANDLE] = NULL;
            }
        }
        return 0;  /* Tell the caller we do not want to restart */
    }

    return 1;      /* Tell the caller we want a restart */
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
            *result = thread_limit;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_THREADS:
            *result = ap_threads_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
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
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MPM_STATE:
            *result = winnt_mpm_state;
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
     *   -k uninstall
     *   -k stop
     *   -k shutdown (same as -k stop). Maintained for backward compatability.
     *
     * We can't leave this phase until we know our identity
     * and modify the command arguments appropriately.
     *
     * We do not care if the .conf file exists or is parsable when
     * attempting to stop or uninstall a service.
     */
    apr_status_t rv;
    char *def_server_root;
    char *binpath;
    char optbuf[3];
    const char *optarg;
    int fixed_args;
    char *pid;
    apr_getopt_t *opt;
    int running_as_service = 1;
    int errout = 0;

    pconf = process->pconf;

    osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osver);

    /* AP_PARENT_PID is only valid in the child */
    pid = getenv("AP_PARENT_PID");
    if (pid) 
    {
        /* This is the child */
        my_pid = GetCurrentProcessId();
        parent_pid = (DWORD) atol(pid);

        /* Prevent holding open the (nonexistant) console */
        real_exit_code = 0;

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

    /* This behavior is voided by setting real_exit_code to 0 */
    atexit(hold_console_open_on_error);

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
    if ((rv = ap_os_proc_filepath(&binpath, process->pconf))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK,APLOG_CRIT, rv, NULL, 
                     "Failed to get the full path of %s", process->argv[0]);
        exit(APEXIT_INIT);
    }
    /* WARNING: There is an implict assumption here that the
     * executable resides in ServerRoot or ServerRoot\bin
     */
    def_server_root = (char *) apr_filepath_name_get(binpath);
    if (def_server_root > binpath) {
        *(def_server_root - 1) = '\0';
        def_server_root = (char *) apr_filepath_name_get(binpath);
        if (!strcasecmp(def_server_root, "bin"))
            *(def_server_root - 1) = '\0';
    }
    apr_filepath_merge(&def_server_root, NULL, binpath, 
                       APR_FILEPATH_TRUENAME, process->pool);

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
    opt->errfn = NULL;
    while ((rv = apr_getopt(opt, "wn:k:" AP_SERVER_BASEARGS, 
                            optbuf + 1, &optarg)) == APR_SUCCESS) {
        switch (optbuf[1]) {

        /* Shortcuts; include the -w option to hold the window open on error.
         * This must not be toggled once we reset real_exit_code to 0!
         */
        case 'w':
            if (real_exit_code)
                real_exit_code = 2;
            break;

        case 'n':
            service_set = mpm_service_set_name(process->pool, &service_name, 
                                               optarg);
            break;

        case 'k':
            signal_arg = optarg;
            break;

        case 'E':
            errout = 1;
            /* Fall through so the Apache main() handles the 'E' arg */
        default:
            *(const char **)apr_array_push(mpm_new_argv) =
                apr_pstrdup(process->pool, optbuf);

            if (optarg) {
                *(const char **)apr_array_push(mpm_new_argv) = optarg;
            }
            break;
        }
    }
    
    /* back up to capture the bad argument */
    if (rv == APR_BADCH || rv == APR_BADARG) {
        opt->ind--;
    }

    while (opt->ind < opt->argc) {
        *(const char **)apr_array_push(mpm_new_argv) =
            apr_pstrdup(process->pool, opt->argv[opt->ind++]);
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
         * The SCM will generally invoke the executable with
         * the c:\win\system32 default directory.  This is very
         * lethal if folks use ServerRoot /foopath on windows
         * without a drive letter.  Change to the default root
         * (path to apache root, above /bin) for safety.
         */
        apr_filepath_set(def_server_root, process->pool);
        
        /* Any other process has a console, so we don't to begin
         * a Win9x service until the configuration is parsed and
         * any command line errors are reported.
         *
         * We hold the return value so that we can die in pre_config
         * after logging begins, and the failure can land in the log.
         */
        if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT) 
        {
            if (!errout) {
                mpm_nt_eventlog_stderr_open(service_name, process->pool);
            }
            service_to_start_success = mpm_service_to_start(&service_name,
                                                            process->pool);
            if (service_to_start_success == APR_SUCCESS) {
                service_set = APR_SUCCESS;
            }
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
            exit(APEXIT_INIT);
        }
    }
    else if (running_as_service)
    {
        if (service_set == APR_SUCCESS) 
        {
            /* Attempt to Uninstall, or stop, before 
             * we can read the arguments or .conf files
             */
            if (!strcasecmp(signal_arg, "uninstall")) {
                rv = mpm_service_uninstall();
                exit(rv);
            }

            if ((!strcasecmp(signal_arg, "stop")) || 
                (!strcasecmp(signal_arg, "shutdown"))) {
                mpm_signal_service(process->pool, 0);
                exit(0);
            }

            rv = mpm_merge_service_args(process->pool, mpm_new_argv, 
                                        fixed_args);
            if (rv == APR_SUCCESS) {
                ap_log_error(APLOG_MARK,APLOG_INFO, 0, NULL,
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
            exit(APEXIT_INIT);
        }
    }
    if (strcasecmp(signal_arg, "install") && service_set && service_set != SERVICE_UNSET) 
    {
        ap_log_error(APLOG_MARK,APLOG_ERR, service_set, NULL,
             "No installed service named \"%s\".", service_name);
        exit(APEXIT_INIT);
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


static int winnt_pre_config(apr_pool_t *pconf_, apr_pool_t *plog, apr_pool_t *ptemp) 
{
    /* Handle the following SCM aspects in this phase:
     *
     *   -k runservice [WinNT errors logged from rewrite_args]
     */

    /* Initialize shared static objects. 
     * TODO: Put config related statics into an sconf structure.
     */
    pconf = pconf_;

    if (ap_exists_config_define("ONE_PROCESS") ||
        ap_exists_config_define("DEBUG"))
        one_process = -1;

    if (!strcasecmp(signal_arg, "runservice")
            && (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
            && (service_to_start_success != APR_SUCCESS)) {
        ap_log_error(APLOG_MARK,APLOG_CRIT, service_to_start_success, NULL, 
                     "%s: Unable to start the service manager.",
                     service_name);
        exit(APEXIT_INIT);
    }

    ap_listen_pre_config();
    ap_threads_per_child = DEFAULT_THREADS_PER_CHILD;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
	ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;
#endif
    /* use_acceptex which is enabled by default is not available on Win9x.
     */
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
        use_acceptex = 0;
    }

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));

    return OK;
}

static int winnt_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec* s)
{
    static int restart_num = 0;
    apr_status_t rv = 0;

    /* Handle the following SCM aspects in this phase:
     *
     *   -k install
     *   -k config
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
        rv = mpm_service_install(ptemp, inst_argc, inst_argv, 0);
        exit (rv);
    }
    if (!strcasecmp(signal_arg, "config")) {
        rv = mpm_service_install(ptemp, inst_argc, inst_argv, 1);
        exit (rv);
    }

    if (!strcasecmp(signal_arg, "start")) {
        ap_listen_rec *lr;

        /* Close the listening sockets. */
        for (lr = ap_listeners; lr; lr = lr->next) {
            apr_socket_close(lr->sd);
            lr->active = 0;
        }
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
                ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                             "Parent: Cannot create shutdown event %s", signal_shutdown_name);
                CleanNullACL((void *)sa);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            /* Create restart event, apPID_restart, where PID is the parent 
             * Apache process ID. Restart is signaled by 'apache -k restart'.
             */
            restart_event = CreateEvent(sa, FALSE, FALSE, signal_restart_name);
            if (!restart_event) {
                CloseHandle(shutdown_event);
                ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), ap_server_conf,
                             "Parent: Cannot create restart event %s", signal_restart_name);
                CleanNullACL((void *)sa);
                return HTTP_INTERNAL_SERVER_ERROR;
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
                    rv = mpm_service_to_start(&service_name,
                                              s->process->pool);
                    if (rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK,APLOG_ERR, rv, ap_server_conf,
                                     "%s: Unable to start the service manager.",
                                     service_name);
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                }
            }
            else /* ! -k runservice */
            {
                mpm_start_console_handler();
            }

            /* Create the start mutex, as an unnamed object for security.
             * Ths start mutex is used during a restart to prevent more than 
             * one child process from entering the accept loop at once.
             */
            rv =  apr_proc_mutex_create(&start_mutex, NULL,
                                        APR_LOCK_DEFAULT,
                                        ap_server_conf->process->pool);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK,APLOG_ERR, rv, ap_server_conf,
                             "%s: Unable to create the start_mutex.",
                             service_name);
                return HTTP_INTERNAL_SERVER_ERROR;
            }            
        }
    }
    else /* parent_pid != my_pid */
    {
        mpm_start_child_console_handler();
    }
    return OK;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 */
static int winnt_open_logs(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    /* Initialize shared static objects. 
     */
    ap_server_conf = s;

    if (parent_pid != my_pid) {
        return OK;
    }

    /* We cannot initialize our listeners if we are restarting
     * (the parent process already has glomed on to them)
     * nor should we do so for service reconfiguration 
     * (since the service may already be running.)
     */
    if (!strcasecmp(signal_arg, "restart") 
            || !strcasecmp(signal_arg, "config")) {
        return OK;
    }

    if (ap_setup_listeners(s) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_STARTUP, 0, 
                     NULL, "no listening sockets available, shutting down");
        return DONE;
    }

    return OK;
}

static void winnt_child_init(apr_pool_t *pchild, struct server_rec *s)
{
    apr_status_t rv;

    setup_signal_names(apr_psprintf(pchild,"ap%d", parent_pid));

    /* This is a child process, not in single process mode */
    if (!one_process) {
        /* Set up events and the scoreboard */
        get_handles_from_parent(s, &exit_event, &start_mutex, 
                                &ap_scoreboard_shm);

        /* Set up the listeners */
        get_listeners_from_parent(s);

        ap_my_generation = ap_scoreboard_image->global->running_generation;
    }
    else {
        /* Single process mode - this lock doesn't even need to exist */
        rv = apr_proc_mutex_create(&start_mutex, signal_name_prefix, 
                                   APR_LOCK_DEFAULT, s->process->pool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK,APLOG_ERR, rv, ap_server_conf,
                         "%s child %d: Unable to init the start_mutex.",
                         service_name, my_pid);
            exit(APEXIT_CHILDINIT);
        }
        
        /* Borrow the shutdown_even as our _child_ loop exit event */
        exit_event = shutdown_event;
    }
}


AP_DECLARE(int) ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s )
{
    static int restart = 0;            /* Default is "not a restart" */

    if (!restart) {
        first_thread_limit = thread_limit;
    }

    if (changed_limit_at_restart) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, ap_server_conf,
                     "WARNING: Attempt to change ThreadLimit ignored "
                     "during restart");
        changed_limit_at_restart = 0;
    }
    
    /* ### If non-graceful restarts are ever introduced - we need to rerun 
     * the pre_mpm hook on subsequent non-graceful restarts.  But Win32 
     * has only graceful style restarts - and we need this hook to act 
     * the same on Win32 as on Unix.
     */
    if (!restart && ((parent_pid == my_pid) || one_process)) {
        /* Set up the scoreboard. */
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            return 1;
        }
    }
    
    if ((parent_pid != my_pid) || one_process) 
    {
        /* The child process or in one_process (debug) mode 
         */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                     "Child %d: Child process is running", my_pid);

        child_main(pconf);

        ap_log_error(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, ap_server_conf,
                     "Child %d: Child process is exiting", my_pid);        
        return 1;
    }
    else 
    {
        /* A real-honest to goodness parent */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                     "%s configured -- resuming normal operations",
                     ap_get_server_version());
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                     "Server built: %s", ap_get_server_built());

        restart = master_main(ap_server_conf, shutdown_event, restart_event);

        if (!restart) 
        {
            /* Shutting down. Clean up... */
            const char *pidfile = ap_server_root_relative (pconf, ap_pid_fname);

            if (pidfile != NULL && unlink(pidfile) == 0) {
                ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS,
                             ap_server_conf, "removed PID file %s (pid=%ld)",
                             pidfile, GetCurrentProcessId());
            }
            apr_proc_mutex_destroy(start_mutex);

            CloseHandle(restart_event);
            CloseHandle(shutdown_event);

            return 1;
        }
    }

    return 0; /* Restart */
}

static void winnt_hooks(apr_pool_t *p)
{
    /* The prefork open_logs phase must run before the core's, or stderr
     * will be redirected to a file, and the messages won't print to the
     * console.
     */
    static const char *const aszSucc[] = {"core.c", NULL};

    ap_hook_pre_config(winnt_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(winnt_post_config, NULL, NULL, 0);
    ap_hook_child_init(winnt_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_open_logs(winnt_open_logs, NULL, aszSucc, APR_HOOK_MIDDLE);
}

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

#endif /* def WIN32 */
