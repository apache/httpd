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

/* The purpose of this file is to store the code that MOST mpm's will need
 * this does not mean a function only goes into this file if every MPM needs
 * it.  It means that if a function is needed by more than one MPM, and
 * future maintenance would be served by making the code common, then the
 * function belongs here.
 *
 * This is going in src/main because it is not platform specific, it is
 * specific to multi-process servers, but NOT to Unix.  Which is why it
 * does not belong in src/os/unix
 */

/**
 * @file  mpm_common.h
 * @brief Multi-Processing Modules functions
 *
 * @defgroup APACHE_MPM Multi-Processing Modules
 * @ingroup  APACHE
 * @{
 */

#ifndef APACHE_MPM_COMMON_H
#define APACHE_MPM_COMMON_H

#include "ap_config.h"
#include "ap_mpm.h"

#if APR_HAVE_NETINET_TCP_H
#include <netinet/tcp.h>    /* for TCP_NODELAY */
#endif

#include "apr_proc_mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The maximum length of the queue of pending connections, as defined
 * by listen(2).  Under some systems, it should be increased if you
 * are experiencing a heavy TCP SYN flood attack.
 *
 * It defaults to 511 instead of 512 because some systems store it 
 * as an 8-bit datatype; 512 truncated to 8-bits is 0, while 511 is 
 * 255 when truncated.
 */
#ifndef DEFAULT_LISTENBACKLOG
#define DEFAULT_LISTENBACKLOG 511
#endif
        
/* Signal used to gracefully restart */
#define AP_SIG_GRACEFUL SIGUSR1

/* Signal used to gracefully restart (without SIG prefix) */
#define AP_SIG_GRACEFUL_SHORT USR1

/* Signal used to gracefully restart (as a quoted string) */
#define AP_SIG_GRACEFUL_STRING "SIGUSR1"

/* Signal used to gracefully stop */
#define AP_SIG_GRACEFUL_STOP SIGWINCH

/* Signal used to gracefully stop (without SIG prefix) */
#define AP_SIG_GRACEFUL_STOP_SHORT WINCH

/* Signal used to gracefully stop (as a quoted string) */
#define AP_SIG_GRACEFUL_STOP_STRING "SIGWINCH"

/**
 * Make sure all child processes that have been spawned by the parent process
 * have died.  This includes process registered as "other_children".
 * @param terminate Either 1 or 0.  If 1, send the child processes SIGTERM
 *        each time through the loop.  If 0, give the process time to die
 *        on its own before signalling it.
 * @note This function requires that a hook is implemented by the MPM: <pre>
 *  mpm_note_child_killed -- Note the child died in the scoreboard
 * </pre>
 *
 * @note The MPM child processes which are reclaimed are those listed
 * in the scoreboard as well as those currently registered via
 * ap_register_extra_mpm_process().
 */
void ap_reclaim_child_processes(int terminate);

/**
 * Catch any child processes that have been spawned by the parent process
 * which have exited. This includes processes registered as "other_children".
 *
 * @note This function requires that a hook is implemented by the MPM: <pre>
 *  mpm_note_child_killed -- Note the child died in the scoreboard
 * </pre>
 *
 * @note The MPM child processes which are relieved are those listed
 * in the scoreboard as well as those currently registered via
 * ap_register_extra_mpm_process().
 */
void ap_relieve_child_processes(void);

/**
 * Tell ap_reclaim_child_processes() and ap_relieve_child_processes() about 
 * an MPM child process which has no entry in the scoreboard.
 * @param pid The process id of an MPM child process which should be
 * reclaimed when ap_reclaim_child_processes() is called.
 *
 * @note If an extra MPM child process terminates prior to calling
 * ap_reclaim_child_processes(), remove it from the list of such processes
 * by calling ap_unregister_extra_mpm_process().
 */
void ap_register_extra_mpm_process(pid_t pid);

/**
 * Unregister an MPM child process which was previously registered by a
 * call to ap_register_extra_mpm_process().
 * @param pid The process id of an MPM child process which no longer needs to
 * be reclaimed.
 * @return 1 if the process was found and removed, 0 otherwise
 */
int ap_unregister_extra_mpm_process(pid_t pid);

/**
 * Safely signal an MPM child process, if the process is in the
 * current process group.  Otherwise fail.
 * @param pid the process id of a child process to signal
 * @param sig the signal number to send
 * @return APR_SUCCESS if signal is sent, otherwise an error as per kill(3);
 * APR_EINVAL is returned if passed either an invalid (< 1) pid, or if
 * the pid is not in the current process group
 */
apr_status_t ap_mpm_safe_kill(pid_t pid, int sig);

/**
 * Determine if any child process has died.  If no child process died, then
 * this process sleeps for the amount of time specified by the MPM defined
 * macro SCOREBOARD_MAINTENANCE_INTERVAL.
 * @param status The return code if a process has died
 * @param exitcode The returned exit status of the child, if a child process 
 *                 dies, or the signal that caused the child to die.
 * @param ret The process id of the process that died
 * @param p The pool to allocate out of
 * @param s The server_rec to pass
 */
void ap_wait_or_timeout(apr_exit_why_e *status, int *exitcode, apr_proc_t *ret, 
                        apr_pool_t *p, server_rec *s);

/**
 * Log why a child died to the error log, if the child died without the
 * parent signalling it.
 * @param pid The child that has died
 * @param why The return code of the child process
 * @param status The status returned from ap_wait_or_timeout
 * @return 0 on success, APEXIT_CHILDFATAL if MPM should terminate
 */
int ap_process_child_status(apr_proc_t *pid, apr_exit_why_e why, int status);

#if defined(TCP_NODELAY)
/**
 * Turn off the nagle algorithm for the specified socket.  The nagle algorithm
 * says that we should delay sending partial packets in the hopes of getting
 * more data.  There are bad interactions between persistent connections and
 * Nagle's algorithm that have severe performance penalties.
 * @param s The socket to disable nagle for.
 */
void ap_sock_disable_nagle(apr_socket_t *s);
#else
#define ap_sock_disable_nagle(s)        /* NOOP */
#endif

#ifdef HAVE_GETPWNAM
/**
 * Convert a username to a numeric ID
 * @param name The name to convert
 * @return The user id corresponding to a name
 * @fn uid_t ap_uname2id(const char *name)
 */
AP_DECLARE(uid_t) ap_uname2id(const char *name);
#endif

#ifdef HAVE_GETGRNAM
/**
 * Convert a group name to a numeric ID
 * @param name The name to convert
 * @return The group id corresponding to a name
 * @fn gid_t ap_gname2id(const char *name)
 */
AP_DECLARE(gid_t) ap_gname2id(const char *name);
#endif

typedef struct ap_pod_t ap_pod_t;

struct ap_pod_t {
    apr_file_t *pod_in;
    apr_file_t *pod_out;
    apr_pool_t *p;
};

/**
 * Open the pipe-of-death.  The pipe of death is used to tell all child
 * processes that it is time to die gracefully.
 * @param p The pool to use for allocating the pipe
 * @param pod the pipe-of-death that is created.
 */
AP_DECLARE(apr_status_t) ap_mpm_pod_open(apr_pool_t *p, ap_pod_t **pod);

/**
 * Check the pipe to determine if the process has been signalled to die.
 */
AP_DECLARE(apr_status_t) ap_mpm_pod_check(ap_pod_t *pod);

/**
 * Close the pipe-of-death
 *
 * @param pod the pipe-of-death to close.
 */
AP_DECLARE(apr_status_t) ap_mpm_pod_close(ap_pod_t *pod);

/**
 * Write data to the pipe-of-death, signalling that one child process
 * should die.
 * @param pod the pipe-of-death to write to.
 */
AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod);

/**
 * Write data to the pipe-of-death, signalling that all child process
 * should die.
 * @param pod The pipe-of-death to write to.
 * @param num The number of child processes to kill
 */
AP_DECLARE(void) ap_mpm_pod_killpg(ap_pod_t *pod, int num);

/*
 * These data members are common to all mpms. Each new mpm
 * should either use the appropriate ap_mpm_set_* function
 * in their command table or create their own for custom or
 * OS specific needs. These should work for most.
 */

/**
 * The maximum number of requests each child thread or
 * process handles before dying off
 */
extern int ap_max_requests_per_child;
const char *ap_mpm_set_max_requests(cmd_parms *cmd, void *dummy,
                                    const char *arg);

/**
 * The filename used to store the process id.
 */
extern const char *ap_pid_fname;
const char *ap_mpm_set_pidfile(cmd_parms *cmd, void *dummy,
                               const char *arg);

/**
 * The name of lockfile used when Apache needs to lock the accept() call.
 */
extern const char *ap_lock_fname;
const char *ap_mpm_set_lockfile(cmd_parms *cmd, void *dummy,
                                const char *arg);

/**
 * The system mutex implementation to use for the accept mutex.
 */
extern apr_lockmech_e ap_accept_lock_mech;
const char *ap_mpm_set_accept_lock_mech(cmd_parms *cmd, void *dummy,
                                        const char *arg);

/*
 * Set the scorboard file.
 */
const char *ap_mpm_set_scoreboard(cmd_parms *cmd, void *dummy,
                                  const char *arg);

/*
 * The directory that the server changes directory to dump core.
 */
extern char ap_coredump_dir[MAX_STRING_LEN];
extern int ap_coredumpdir_configured;
const char *ap_mpm_set_coredumpdir(cmd_parms *cmd, void *dummy,
                                   const char *arg);

/**
 * Set the timeout period for a graceful shutdown.
 */
extern int ap_graceful_shutdown_timeout;
const char *ap_mpm_set_graceful_shutdown(cmd_parms *cmd, void *dummy,
                                         const char *arg);
#define AP_GRACEFUL_SHUTDOWN_TIMEOUT_COMMAND \
AP_INIT_TAKE1("GracefulShutdownTimeout", ap_mpm_set_graceful_shutdown, NULL, \
              RSRC_CONF, "Maximum time in seconds to wait for child "        \
              "processes to complete transactions during shutdown")


int ap_signal_server(int *, apr_pool_t *);
void ap_mpm_rewrite_args(process_rec *);

extern apr_uint32_t ap_max_mem_free;
extern const char *ap_mpm_set_max_mem_free(cmd_parms *cmd, void *dummy,
                                           const char *arg);

extern apr_size_t ap_thread_stacksize;
extern const char *ap_mpm_set_thread_stacksize(cmd_parms *cmd, void *dummy,
                                               const char *arg);

extern apr_status_t ap_fatal_signal_setup(server_rec *s, apr_pool_t *pconf);
extern apr_status_t ap_fatal_signal_child_setup(server_rec *s);

#if AP_ENABLE_EXCEPTION_HOOK
extern const char *ap_mpm_set_exception_hook(cmd_parms *cmd, void *dummy,
                                             const char *arg);
#endif

AP_DECLARE(apr_status_t) ap_mpm_note_child_killed(int childnum);

AP_DECLARE_HOOK(int,monitor,(apr_pool_t *p, server_rec *s))

/* register modules that undertake to manage system security */
AP_DECLARE(int) ap_sys_privileges_handlers(int inc);
AP_DECLARE_HOOK(int, drop_privileges, (apr_pool_t * pchild, server_rec * s))

/* implement the ap_mpm_query() function
 * The MPM should return OK+APR_ENOTIMPL for any unimplemented query codes;
 * modules which intercede for specific query codes should DECLINE for others.
 */
AP_DECLARE_HOOK(int, mpm_query, (int query_code, int *result, apr_status_t *rv))

/* child specified by index has been killed */
AP_DECLARE_HOOK(apr_status_t, mpm_note_child_killed, (int childnum))

/* register the specified callback */
AP_DECLARE_HOOK(apr_status_t, mpm_register_timed_callback,
                (apr_time_t t, ap_mpm_callback_fn_t *cbfn, void *baton))

/* get MPM name (e.g., "prefork" or "event") */
AP_DECLARE_HOOK(const char *,mpm_get_name,(void))

#ifdef __cplusplus
}
#endif

#endif /* !APACHE_MPM_COMMON_H */
/** @} */
