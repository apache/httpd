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

/* Multi-process, multi-threaded MPM for OS/2
 *
 * Server consists of
 * - a main, parent process
 * - a small, static number of child processes
 *
 * The parent process's job is to manage the child processes. This involves
 * spawning children as required to ensure there are always ap_daemons_to_start
 * processes accepting connections.
 *
 * Each child process consists of a a pool of worker threads and a
 * main thread that accepts connections & passes them to the workers via
 * a work queue. The worker thread pool is dynamic, managed by a maintanence
 * thread so that the number of idle threads is kept between
 * min_spare_threads & max_spare_threads.
 *
 */

/*
 Todo list
 - Enforce MaxClients somehow
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
#include "ap_mpm.h"
#include "ap_listen.h"
#include "apr_portable.h"
#include "mpm_common.h"
#include "scoreboard.h"
#include "apr_strings.h"
#include <os2.h>
#include <process.h>

/* We don't need many processes,
 * they're only for redundancy in the event of a crash
 */
#define HARD_SERVER_LIMIT 10

/* Limit on the total number of threads per process
 */
#ifndef HARD_THREAD_LIMIT
#define HARD_THREAD_LIMIT 256
#endif

server_rec *ap_server_conf;
static apr_pool_t *pconf = NULL;  /* Pool for config stuff */
static const char *ap_pid_fname=NULL;

/* Config globals */
static int one_process = 0;
static int ap_daemons_to_start = 0;
static int ap_thread_limit = 0;
static int ap_max_requests_per_child = 0;
int ap_min_spare_threads = 0;
int ap_max_spare_threads = 0;

/* Keep track of a few interesting statistics */
int ap_max_daemons_limit = -1;

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful = 0;
ap_generation_t volatile ap_my_generation=0; /* Used by the scoreboard */
static int is_parent_process=TRUE;
HMTX ap_mpm_accept_mutex = 0;

/* An array of these is stored in a shared memory area for passing
 * sockets from the parent to child processes
 */
typedef struct {
    struct sockaddr_in name;
    apr_os_sock_t listen_fd;
} listen_socket_t;

typedef struct {
    HMTX accept_mutex;
    listen_socket_t listeners[1];
} parent_info_t;

static char master_main();
static void spawn_child(int slot);
void ap_mpm_child_main(apr_pool_t *pconf);
static void set_signals();


static int mpmt_os2_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s )
{
    char *listener_shm_name;
    parent_info_t *parent_info;
    ULONG rc;
    pconf = _pconf;
    ap_server_conf = s;
    restart_pending = 0;

    DosSetMaxFH(ap_thread_limit * 2);
    listener_shm_name = apr_psprintf(pconf, "/sharemem/httpd/parent_info.%d", getppid());
    rc = DosGetNamedSharedMem((PPVOID)&parent_info, listener_shm_name, PAG_READ);
    is_parent_process = rc != 0;
    ap_scoreboard_fname = apr_psprintf(pconf, "/sharemem/httpd/scoreboard.%d", is_parent_process ? getpid() : getppid());

    if (rc == 0) {
        /* Child process */
        ap_listen_rec *lr;
        int num_listeners = 0;

        ap_mpm_accept_mutex = parent_info->accept_mutex;

        /* Set up a default listener if necessary */
        if (ap_listeners == NULL) {
            ap_listen_rec *lr = apr_pcalloc(s->process->pool, sizeof(ap_listen_rec));
            ap_listeners = lr;
            apr_sockaddr_info_get(&lr->bind_addr, "0.0.0.0", APR_UNSPEC,
                                  DEFAULT_HTTP_PORT, 0, s->process->pool);
            apr_socket_create(&lr->sd, lr->bind_addr->family,
                              SOCK_STREAM, 0, s->process->pool);
        }

        for (lr = ap_listeners; lr; lr = lr->next) {
            apr_sockaddr_t *sa;
            apr_os_sock_put(&lr->sd, &parent_info->listeners[num_listeners].listen_fd, pconf);
            apr_socket_addr_get(&sa, APR_LOCAL, lr->sd);
            num_listeners++;
        }

        DosFreeMem(parent_info);

        /* Do the work */
        ap_mpm_child_main(pconf);

        /* Outta here */
        return 1;
    }
    else {
        /* Parent process */
        char restart;
        is_parent_process = TRUE;

        if (ap_setup_listeners(ap_server_conf) < 1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s,
                         "no listening sockets available, shutting down");
            return 1;
        }

        ap_log_pid(pconf, ap_pid_fname);

        restart = master_main();
        ++ap_my_generation;
        ap_scoreboard_image->global->running_generation = ap_my_generation;

        if (!restart) {
            const char *pidfile = ap_server_root_relative(pconf, ap_pid_fname);

            if (pidfile != NULL && remove(pidfile) == 0) {
                ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS,
                             ap_server_conf, "removed PID file %s (pid=%d)",
                             pidfile, getpid());
            }

            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                         "caught SIGTERM, shutting down");
            return 1;
        }
    }  /* Parent process */

    return 0; /* Restart */
}



/* Main processing of the parent process
 * returns TRUE if restarting
 */
static char master_main()
{
    server_rec *s = ap_server_conf;
    ap_listen_rec *lr;
    parent_info_t *parent_info;
    char *listener_shm_name;
    int listener_num, num_listeners, slot;
    ULONG rc;

    printf("%s \n", ap_get_server_description());
    set_signals();

    if (ap_setup_listeners(ap_server_conf) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s,
                     "no listening sockets available, shutting down");
        return FALSE;
    }

    /* Allocate a shared memory block for the array of listeners */
    for (num_listeners = 0, lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }

    listener_shm_name = apr_psprintf(pconf, "/sharemem/httpd/parent_info.%d", getpid());
    rc = DosAllocSharedMem((PPVOID)&parent_info, listener_shm_name,
                           sizeof(parent_info_t) + num_listeners * sizeof(listen_socket_t),
                           PAG_READ|PAG_WRITE|PAG_COMMIT);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, APR_FROM_OS_ERROR(rc), s,
                     "failure allocating shared memory, shutting down");
        return FALSE;
    }

    /* Store the listener sockets in the shared memory area for our children to see */
    for (listener_num = 0, lr = ap_listeners; lr; lr = lr->next, listener_num++) {
        apr_os_sock_get(&parent_info->listeners[listener_num].listen_fd, lr->sd);
    }

    /* Create mutex to prevent multiple child processes from detecting
     * a connection with apr_poll()
     */

    rc = DosCreateMutexSem(NULL, &ap_mpm_accept_mutex, DC_SEM_SHARED, FALSE);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, APR_FROM_OS_ERROR(rc), s,
                     "failure creating accept mutex, shutting down");
        return FALSE;
    }

    parent_info->accept_mutex = ap_mpm_accept_mutex;

    /* Allocate shared memory for scoreboard */
    if (ap_scoreboard_image == NULL) {
        void *sb_mem;
        rc = DosAllocSharedMem(&sb_mem, ap_scoreboard_fname,
                               ap_calc_scoreboard_size(),
                               PAG_COMMIT|PAG_READ|PAG_WRITE);

        if (rc) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                         "unable to allocate shared memory for scoreboard , exiting");
            return FALSE;
        }

        ap_init_scoreboard(sb_mem);
    }

    ap_scoreboard_image->global->restart_time = apr_time_now();
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf,
                "%s configured -- resuming normal operations",
                ap_get_server_description());
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
                "Server built: %s", ap_get_server_built());
    if (one_process) {
        ap_scoreboard_image->parent[0].pid = getpid();
        ap_mpm_child_main(pconf);
        return FALSE;
    }

    while (!restart_pending && !shutdown_pending) {
        RESULTCODES proc_rc;
        PID child_pid;
        int active_children = 0;

        /* Count number of active children */
        for (slot=0; slot < HARD_SERVER_LIMIT; slot++) {
            active_children += ap_scoreboard_image->parent[slot].pid != 0 &&
                !ap_scoreboard_image->parent[slot].quiescing;
        }

        /* Spawn children if needed */
        for (slot=0; slot < HARD_SERVER_LIMIT && active_children < ap_daemons_to_start; slot++) {
            if (ap_scoreboard_image->parent[slot].pid == 0) {
                spawn_child(slot);
                active_children++;
            }
        }

        rc = DosWaitChild(DCWA_PROCESSTREE, DCWW_NOWAIT, &proc_rc, &child_pid, 0);

        if (rc == 0) {
            /* A child has terminated, remove its scoreboard entry & terminate if necessary */
            for (slot=0; ap_scoreboard_image->parent[slot].pid != child_pid && slot < HARD_SERVER_LIMIT; slot++);

            if (slot < HARD_SERVER_LIMIT) {
                ap_scoreboard_image->parent[slot].pid = 0;
                ap_scoreboard_image->parent[slot].quiescing = 0;

                if (proc_rc.codeTerminate == TC_EXIT) {
                    /* Child terminated normally, check its exit code and
                     * terminate server if child indicates a fatal error
                     */
                    if (proc_rc.codeResult == APEXIT_CHILDFATAL)
                        break;
                }
            }
        } else if (rc == ERROR_CHILD_NOT_COMPLETE) {
            /* No child exited, lets sleep for a while.... */
            apr_sleep(SCOREBOARD_MAINTENANCE_INTERVAL);
        }
    }

    /* Signal children to shut down, either gracefully or immediately */
    for (slot=0; slot<HARD_SERVER_LIMIT; slot++) {
      kill(ap_scoreboard_image->parent[slot].pid, is_graceful ? SIGHUP : SIGTERM);
    }

    DosFreeMem(parent_info);
    return restart_pending;
}



static void spawn_child(int slot)
{
    PPIB ppib;
    PTIB ptib;
    char fail_module[100];
    char progname[CCHMAXPATH];
    RESULTCODES proc_rc;
    ULONG rc;

    ap_scoreboard_image->parent[slot].generation = ap_my_generation;
    DosGetInfoBlocks(&ptib, &ppib);
    DosQueryModuleName(ppib->pib_hmte, sizeof(progname), progname);
    rc = DosExecPgm(fail_module, sizeof(fail_module), EXEC_ASYNCRESULT,
                    ppib->pib_pchcmd, NULL, &proc_rc, progname);

    if (rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(rc), ap_server_conf,
                     "error spawning child, slot %d", slot);
    }

    if (ap_max_daemons_limit < slot) {
        ap_max_daemons_limit = slot;
    }

    ap_scoreboard_image->parent[slot].pid = proc_rc.codeTerminate;
}



/* Signal handling routines */

static void sig_term(int sig)
{
    shutdown_pending = 1;
    signal(SIGTERM, SIG_DFL);
}



static void sig_restart(int sig)
{
    if (sig == SIGUSR1) {
        is_graceful = 1;
    }

    restart_pending = 1;
}



static void set_signals()
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sig_term;

    if (sigaction(SIGTERM, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGTERM)");

    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGINT)");

    sa.sa_handler = sig_restart;

    if (sigaction(SIGHUP, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGUSR1)");
}



/* Enquiry functions used get MPM status info */

static apr_status_t mpmt_os2_query(int query_code, int *result, apr_status_t *rv)
{
    *rv = APR_SUCCESS;

    switch (query_code) {
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_max_daemons_limit;
            break;

        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_DYNAMIC;
            break;

        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_NOT_SUPPORTED;
            break;

        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            break;

        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = HARD_THREAD_LIMIT;
            break;

        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            break;

        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            break;

        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_child;
            break;

        case AP_MPMQ_GENERATION:
            *result = ap_my_generation;
            break;

        default:
            *rv = APR_ENOTIMPL;
            break;
    }

    return OK;
}



static const char *mpmt_os2_note_child_killed(int childnum)
{
  ap_scoreboard_image->parent[childnum].pid = 0;
  return APR_SUCCESS;
}



static const char *mpmt_os2_get_name(void)
{
    return "mpmt_os2";
}




/* Configuration handling stuff */

static int mpmt_os2_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    one_process = ap_exists_config_define("ONE_PROCESS") ||
                  ap_exists_config_define("DEBUG");
    is_graceful = 0;
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    ap_thread_limit = HARD_THREAD_LIMIT;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;
    ap_min_spare_threads = DEFAULT_MIN_SPARE_THREAD;
    ap_max_spare_threads = DEFAULT_MAX_SPARE_THREAD;
#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
        ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;
#endif
    ap_sys_privileges_handlers(1);

    return OK;
}



static int mpmt_os2_check_config(apr_pool_t *p, apr_pool_t *plog,
                                 apr_pool_t *ptemp, server_rec *s)
{
    static int restart_num = 0;
    int startup = 0;

    /* we want this only the first time around */
    if (restart_num++ == 0) {
        startup = 1;
    }

    if (ap_daemons_to_start < 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: StartServers of %d not allowed, "
                         "increasing to 1.", ap_daemons_to_start);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "StartServers of %d not allowed, increasing to 1",
                         ap_daemons_to_start);
        }
        ap_daemons_to_start = 1;
    }

    if (ap_min_spare_threads < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         "WARNING: MinSpareThreads of %d not allowed, "
                         "increasing to 1", ap_min_spare_threads);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " to avoid almost certain server failure.");
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         " Please read the documentation.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "MinSpareThreads of %d not allowed, increasing to 1",
                         ap_min_spare_threads);
        }
        ap_min_spare_threads = 1;
    }

    return OK;
}



static void mpmt_os2_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(mpmt_os2_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(mpmt_os2_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm(mpmt_os2_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(mpmt_os2_query, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_get_name(mpmt_os2_get_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_note_child_killed(mpmt_os2_note_child_killed, NULL, NULL, APR_HOOK_MIDDLE);
}



static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}



static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    ap_min_spare_threads = atoi(arg);
    return NULL;
}



static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    ap_max_spare_threads = atoi(arg);
    return NULL;
}



static const char *ignore_cmd(cmd_parms *cmd, void *dummy, const char *arg)
{
    return NULL;
}



static const command_rec mpmt_os2_cmds[] = {
LISTEN_COMMANDS,
AP_INIT_TAKE1( "StartServers", set_daemons_to_start, NULL, RSRC_CONF,
  "Number of child processes launched at server startup" ),
AP_INIT_TAKE1("MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
  "Minimum number of idle children, to handle request spikes"),
AP_INIT_TAKE1("MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
  "Maximum number of idle children"),
AP_INIT_TAKE1("User", ignore_cmd, NULL, RSRC_CONF,
  "Not applicable on this platform"),
AP_INIT_TAKE1("Group", ignore_cmd, NULL, RSRC_CONF,
  "Not applicable on this platform"),
AP_INIT_TAKE1("ScoreBoardFile", ignore_cmd, NULL, RSRC_CONF, \
  "Not applicable on this platform"),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_mpmt_os2_module = {
    MPM20_MODULE_STUFF,
    NULL,            /* hook to run before apache parses args */
    NULL,            /* create per-directory config structure */
    NULL,            /* merge per-directory config structures */
    NULL,            /* create per-server config structure */
    NULL,            /* merge per-server config structures */
    mpmt_os2_cmds,   /* command apr_table_t */
    mpmt_os2_hooks,  /* register_hooks */
};
