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

#include "apr.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_getopt.h"
#include "apr_optional.h"
#include "apr_allocator.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "ap_listen.h"
#include "mpm_default.h"

#ifdef AP_MPM_WANT_SET_SCOREBOARD
#include "scoreboard.h"
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#if AP_ENABLE_EXCEPTION_HOOK
APR_HOOK_STRUCT(
    APR_HOOK_LINK(fatal_exception)
    APR_HOOK_LINK(monitor)
)
AP_IMPLEMENT_HOOK_RUN_ALL(int, fatal_exception,
                          (ap_exception_info_t *ei), (ei), OK, DECLINED)
#else
APR_HOOK_STRUCT(
    APR_HOOK_LINK(monitor)
)
#endif
AP_IMPLEMENT_HOOK_RUN_ALL(int, monitor,
                          (apr_pool_t *p), (p), OK, DECLINED)


#ifdef AP_MPM_WANT_RECLAIM_CHILD_PROCESSES

typedef enum {DO_NOTHING, SEND_SIGTERM, SEND_SIGKILL, GIVEUP} action_t;

typedef struct extra_process_t {
    struct extra_process_t *next;
    pid_t pid;
} extra_process_t;

static extra_process_t *extras;

void ap_register_extra_mpm_process(pid_t pid)
{
    extra_process_t *p = (extra_process_t *)malloc(sizeof(extra_process_t));

    p->next = extras;
    p->pid = pid;
    extras = p;
}

int ap_unregister_extra_mpm_process(pid_t pid)
{
    extra_process_t *cur = extras;
    extra_process_t *prev = NULL;

    while (cur && cur->pid != pid) {
        prev = cur;
        cur = cur->next;
    }

    if (cur) {
        if (prev) {
            prev->next = cur->next;
        }
        else {
            extras = cur->next;
        }
        free(cur);
        return 1; /* found */
    }
    else {
        /* we don't know about any such process */
        return 0;
    }
}

static int reclaim_one_pid(pid_t pid, action_t action)
{
    apr_proc_t proc;
    apr_status_t waitret;

    /* Ensure pid sanity. */
    if (pid < 1) {
        return 1;
    }        

    proc.pid = pid;
    waitret = apr_proc_wait(&proc, NULL, NULL, APR_NOWAIT);
    if (waitret != APR_CHILD_NOTDONE) {
        return 1;
    }

    switch(action) {
    case DO_NOTHING:
        break;

    case SEND_SIGTERM:
        /* ok, now it's being annoying */
        ap_log_error(APLOG_MARK, APLOG_WARNING,
                     0, ap_server_conf,
                     "child process %" APR_PID_T_FMT
                     " still did not exit, "
                     "sending a SIGTERM",
                     pid);
        kill(pid, SIGTERM);
        break;

    case SEND_SIGKILL:
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     0, ap_server_conf,
                     "child process %" APR_PID_T_FMT
                     " still did not exit, "
                     "sending a SIGKILL",
                     pid);
#ifndef BEOS
        kill(pid, SIGKILL);
#else
        /* sending a SIGKILL kills the entire team on BeOS, and as
         * httpd thread is part of that team it removes any chance
         * of ever doing a restart.  To counter this I'm changing to
         * use a kinder, gentler way of killing a specific thread
         * that is just as effective.
         */
        kill_thread(pid);
#endif
        break;

    case GIVEUP:
        /* gave it our best shot, but alas...  If this really
         * is a child we are trying to kill and it really hasn't
         * exited, we will likely fail to bind to the port
         * after the restart.
         */
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     0, ap_server_conf,
                     "could not make child process %" APR_PID_T_FMT
                     " exit, "
                     "attempting to continue anyway",
                     pid);
        break;
    }

    return 0;
}

void ap_reclaim_child_processes(int terminate)
{
    apr_time_t waittime = 1024 * 16;
    int i;
    extra_process_t *cur_extra;
    int not_dead_yet;
    int max_daemons;
    apr_time_t starttime = apr_time_now();
    /* this table of actions and elapsed times tells what action is taken
     * at which elapsed time from starting the reclaim
     */
    struct {
        action_t action;
        apr_time_t action_time;
    } action_table[] = {
        {DO_NOTHING, 0}, /* dummy entry for iterations where we reap
                          * children but take no action against
                          * stragglers
                          */
        {SEND_SIGTERM, apr_time_from_sec(3)},
        {SEND_SIGTERM, apr_time_from_sec(5)},
        {SEND_SIGTERM, apr_time_from_sec(7)},
        {SEND_SIGKILL, apr_time_from_sec(9)},
        {GIVEUP,       apr_time_from_sec(10)}
    };
    int cur_action;      /* index of action we decided to take this
                          * iteration
                          */
    int next_action = 1; /* index of first real action */

    ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons);

    do {
        apr_sleep(waittime);
        /* don't let waittime get longer than 1 second; otherwise, we don't
         * react quickly to the last child exiting, and taking action can
         * be delayed
         */
        waittime = waittime * 4;
        if (waittime > apr_time_from_sec(1)) {
            waittime = apr_time_from_sec(1);
        }

        /* see what action to take, if any */
        if (action_table[next_action].action_time <= apr_time_now() - starttime) {
            cur_action = next_action;
            ++next_action;
        }
        else {
            cur_action = 0; /* nothing to do */
        }

        /* now see who is done */
        not_dead_yet = 0;
        for (i = 0; i < max_daemons; ++i) {
            pid_t pid = MPM_CHILD_PID(i);

            if (pid == 0) {
                continue; /* not every scoreboard entry is in use */
            }

            if (reclaim_one_pid(pid, action_table[cur_action].action)) {
                MPM_NOTE_CHILD_KILLED(i);
            }
            else {
                ++not_dead_yet;
            }
        }

        cur_extra = extras;
        while (cur_extra) {
            extra_process_t *next = cur_extra->next;

            if (reclaim_one_pid(cur_extra->pid, action_table[cur_action].action)) {
                AP_DEBUG_ASSERT(1 == ap_unregister_extra_mpm_process(cur_extra->pid));
            }
            else {
                ++not_dead_yet;
            }
            cur_extra = next;
        }
#if APR_HAS_OTHER_CHILD
        apr_proc_other_child_refresh_all(APR_OC_REASON_RESTART);
#endif

    } while (not_dead_yet > 0 &&
             action_table[cur_action].action != GIVEUP);
}

void ap_relieve_child_processes(void)
{
    int i;
    extra_process_t *cur_extra;
    int max_daemons;

    ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons);

    /* now see who is done */
    for (i = 0; i < max_daemons; ++i) {
        pid_t pid = MPM_CHILD_PID(i);

        if (pid == 0) {
            continue; /* not every scoreboard entry is in use */
        }

        if (reclaim_one_pid(pid, DO_NOTHING)) {
            MPM_NOTE_CHILD_KILLED(i);
        }
    }

    cur_extra = extras;
    while (cur_extra) {
        extra_process_t *next = cur_extra->next;

        if (reclaim_one_pid(cur_extra->pid, DO_NOTHING)) {
            AP_DEBUG_ASSERT(1 == ap_unregister_extra_mpm_process(cur_extra->pid));
        }
        cur_extra = next;
    }
}

/* Before sending the signal to the pid this function verifies that
 * the pid is a member of the current process group; either using
 * apr_proc_wait(), where waitpid() guarantees to fail for non-child
 * processes; or by using getpgid() directly, if available. */
apr_status_t ap_mpm_safe_kill(pid_t pid, int sig)
{
#ifndef HAVE_GETPGID
    apr_proc_t proc;
    apr_status_t rv;
    apr_exit_why_e why;
    int status;

    /* Ensure pid sanity */
    if (pid < 1) {
        return APR_EINVAL;
    }

    proc.pid = pid;
    rv = apr_proc_wait(&proc, &status, &why, APR_NOWAIT);
    if (rv == APR_CHILD_DONE) {
#ifdef AP_MPM_WANT_PROCESS_CHILD_STATUS
        /* The child already died - log the termination status if
         * necessary: */
        ap_process_child_status(&proc, why, status);
#endif
        return APR_EINVAL;
    }
    else if (rv != APR_CHILD_NOTDONE) {
        /* The child is already dead and reaped, or was a bogus pid -
         * log this either way. */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, ap_server_conf,
                     "cannot send signal %d to pid %ld (non-child or "
                     "already dead)", sig, (long)pid);
        return APR_EINVAL;
    }
#else
    pid_t pg;

    /* Ensure pid sanity. */
    if (pid < 1) {
        return APR_EINVAL;
    }

    pg = getpgid(pid);    
    if (pg == -1) {
        /* Process already dead... */
        return errno;
    }

    if (pg != getpgrp()) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, ap_server_conf,
                     "refusing to send signal %d to pid %ld outside "
                     "process group", sig, (long)pid);
        return APR_EINVAL;
    }
#endif        

    return kill(pid, sig) ? errno : APR_SUCCESS;
}
#endif /* AP_MPM_WANT_RECLAIM_CHILD_PROCESSES */

#ifdef AP_MPM_WANT_WAIT_OR_TIMEOUT

/* number of calls to wait_or_timeout between writable probes */
#ifndef INTERVAL_OF_WRITABLE_PROBES
#define INTERVAL_OF_WRITABLE_PROBES 10
#endif
static int wait_or_timeout_counter;

void ap_wait_or_timeout(apr_exit_why_e *status, int *exitcode, apr_proc_t *ret,
                        apr_pool_t *p)
{
    apr_status_t rv;

    ++wait_or_timeout_counter;
    if (wait_or_timeout_counter == INTERVAL_OF_WRITABLE_PROBES) {
        wait_or_timeout_counter = 0;
        ap_run_monitor(p);
    }

    rv = apr_proc_wait_all_procs(ret, exitcode, status, APR_NOWAIT, p);
    if (APR_STATUS_IS_EINTR(rv)) {
        ret->pid = -1;
        return;
    }

    if (APR_STATUS_IS_CHILD_DONE(rv)) {
        return;
    }

#ifdef NEED_WAITPID
    if ((ret = reap_children(exitcode, status)) > 0) {
        return;
    }
#endif

    apr_sleep(SCOREBOARD_MAINTENANCE_INTERVAL);
    ret->pid = -1;
    return;
}
#endif /* AP_MPM_WANT_WAIT_OR_TIMEOUT */

#ifdef AP_MPM_WANT_PROCESS_CHILD_STATUS
int ap_process_child_status(apr_proc_t *pid, apr_exit_why_e why, int status)
{
    int signum = status;
    const char *sigdesc = apr_signal_description_get(signum);

    /* Child died... if it died due to a fatal error,
     * we should simply bail out.  The caller needs to
     * check for bad rc from us and exit, running any
     * appropriate cleanups.
     *
     * If the child died due to a resource shortage,
     * the parent should limit the rate of forking
     */
    if (APR_PROC_CHECK_EXIT(why)) {
        if (status == APEXIT_CHILDSICK) {
            return status;
        }

        if (status == APEXIT_CHILDFATAL) {
            ap_log_error(APLOG_MARK, APLOG_ALERT,
                         0, ap_server_conf,
                         "Child %" APR_PID_T_FMT
                         " returned a Fatal error... Apache is exiting!",
                         pid->pid);
            return APEXIT_CHILDFATAL;
        }

        return 0;
    }

    if (APR_PROC_CHECK_SIGNALED(why)) {
        switch (signum) {
        case SIGTERM:
        case SIGHUP:
        case AP_SIG_GRACEFUL:
        case SIGKILL:
            break;

        default:
            if (APR_PROC_CHECK_CORE_DUMP(why)) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE,
                             0, ap_server_conf,
                             "child pid %ld exit signal %s (%d), "
                             "possible coredump in %s",
                             (long)pid->pid, sigdesc, signum,
                             ap_coredump_dir);
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_NOTICE,
                             0, ap_server_conf,
                             "child pid %ld exit signal %s (%d)",
                             (long)pid->pid, sigdesc, signum);
            }
        }
    }
    return 0;
}
#endif /* AP_MPM_WANT_PROCESS_CHILD_STATUS */

#if defined(TCP_NODELAY) && !defined(MPE) && !defined(TPF)
void ap_sock_disable_nagle(apr_socket_t *s)
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
    apr_status_t status = apr_socket_opt_set(s, APR_TCP_NODELAY, 1);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, status, ap_server_conf,
                     "apr_socket_opt_set: (TCP_NODELAY)");
    }
}
#endif

#ifdef HAVE_GETPWNAM
AP_DECLARE(uid_t) ap_uname2id(const char *name)
{
    struct passwd *ent;

    if (name[0] == '#')
        return (atoi(&name[1]));

    if (!(ent = getpwnam(name))) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "%s: bad user name %s", ap_server_argv0, name);
        exit(1);
    }

    return (ent->pw_uid);
}
#endif

#ifdef HAVE_GETGRNAM
AP_DECLARE(gid_t) ap_gname2id(const char *name)
{
    struct group *ent;

    if (name[0] == '#')
        return (atoi(&name[1]));

    if (!(ent = getgrnam(name))) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "%s: bad group name %s", ap_server_argv0, name);
        exit(1);
    }

    return (ent->gr_gid);
}
#endif

#ifndef HAVE_INITGROUPS
int initgroups(const char *name, gid_t basegid)
{
#if defined(QNX) || defined(MPE) || defined(BEOS) || defined(_OSD_POSIX) || defined(TPF) || defined(__TANDEM) || defined(OS2) || defined(WIN32) || defined(NETWARE)
/* QNX, MPE and BeOS do not appear to support supplementary groups. */
    return 0;
#else /* ndef QNX */
    gid_t groups[NGROUPS_MAX];
    struct group *g;
    int index = 0;

    setgrent();

    groups[index++] = basegid;

    while (index < NGROUPS_MAX && ((g = getgrent()) != NULL)) {
        if (g->gr_gid != basegid) {
            char **names;

            for (names = g->gr_mem; *names != NULL; ++names) {
                if (!strcmp(*names, name))
                    groups[index++] = g->gr_gid;
            }
        }
    }

    endgrent();

    return setgroups(index, groups);
#endif /* def QNX */
}
#endif /* def NEED_INITGROUPS */

#ifdef AP_MPM_USES_POD

AP_DECLARE(apr_status_t) ap_mpm_pod_open(apr_pool_t *p, ap_pod_t **pod)
{
    apr_status_t rv;

    *pod = apr_palloc(p, sizeof(**pod));
    rv = apr_file_pipe_create(&((*pod)->pod_in), &((*pod)->pod_out), p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_file_pipe_timeout_set((*pod)->pod_in, 0);
    (*pod)->p = p;

    /* close these before exec. */
    apr_file_inherit_unset((*pod)->pod_in);
    apr_file_inherit_unset((*pod)->pod_out);

    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_check(ap_pod_t *pod)
{
    char c;
    apr_size_t len = 1;
    apr_status_t rv;

    rv = apr_file_read(pod->pod_in, &c, &len);

    if ((rv == APR_SUCCESS) && (len == 1)) {
        return APR_SUCCESS;
    }

    if (rv != APR_SUCCESS) {
        return rv;
    }

    return AP_NORESTART;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_close(ap_pod_t *pod)
{
    apr_status_t rv;

    rv = apr_file_close(pod->pod_out);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_file_close(pod->pod_in);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t pod_signal_internal(ap_pod_t *pod)
{
    apr_status_t rv;
    char char_of_death = '!';
    apr_size_t one = 1;

    rv = apr_file_write(pod->pod_out, &char_of_death, &one);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "write pipe_of_death");
    }

    return rv;
}

/* This function connects to the server, then immediately closes the connection.
 * This permits the MPM to skip the poll when there is only one listening
 * socket, because it provides a alternate way to unblock an accept() when
 * the pod is used.
 */
static apr_status_t dummy_connection(ap_pod_t *pod)
{
    char *srequest;
    apr_status_t rv;
    apr_socket_t *sock;
    apr_pool_t *p;
    apr_size_t len;

    /* create a temporary pool for the socket.  pconf stays around too long */
    rv = apr_pool_create(&p, pod->p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_create(&sock, ap_listeners->bind_addr->family,
                           SOCK_STREAM, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "get socket to connect to listener");
        apr_pool_destroy(p);
        return rv;
    }

    /* on some platforms (e.g., FreeBSD), the kernel won't accept many
     * queued connections before it starts blocking local connects...
     * we need to keep from blocking too long and instead return an error,
     * because the MPM won't want to hold up a graceful restart for a
     * long time
     */
    rv = apr_socket_timeout_set(sock, apr_time_from_sec(3));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "set timeout on socket to connect to listener");
        apr_socket_close(sock);
        apr_pool_destroy(p);
        return rv;
    }

    rv = apr_socket_connect(sock, ap_listeners->bind_addr);
    if (rv != APR_SUCCESS) {
        int log_level = APLOG_WARNING;

        if (APR_STATUS_IS_TIMEUP(rv)) {
            /* probably some server processes bailed out already and there
             * is nobody around to call accept and clear out the kernel
             * connection queue; usually this is not worth logging
             */
            log_level = APLOG_DEBUG;
        }

        ap_log_error(APLOG_MARK, log_level, rv, ap_server_conf,
                     "connect to listener on %pI", ap_listeners->bind_addr);
    }

    /* Create the request string. We include a User-Agent so that
     * adminstrators can track down the cause of the odd-looking
     * requests in their logs.
     */
    srequest = apr_pstrcat(p, "OPTIONS * HTTP/1.0\r\nUser-Agent: ",
                           ap_get_server_banner(),
                           " (internal dummy connection)\r\n\r\n", NULL);

    /* Since some operating systems support buffering of data or entire
     * requests in the kernel, we send a simple request, to make sure
     * the server pops out of a blocking accept().
     */
    /* XXX: This is HTTP specific. We should look at the Protocol for each
     * listener, and send the correct type of request to trigger any Accept
     * Filters.
     */
    len = strlen(srequest);
    apr_socket_send(sock, srequest, &len);
    apr_socket_close(sock);
    apr_pool_destroy(p);

    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod)
{
    apr_status_t rv;

    rv = pod_signal_internal(pod);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return dummy_connection(pod);
}

void ap_mpm_pod_killpg(ap_pod_t *pod, int num)
{
    int i;
    apr_status_t rv = APR_SUCCESS;

    /* we don't write anything to the pod here...  we assume
     * that the would-be reader of the pod has another way to
     * see that it is time to die once we wake it up
     *
     * writing lots of things to the pod at once is very
     * problematic... we can fill the kernel pipe buffer and
     * be blocked until somebody consumes some bytes or
     * we hit a timeout...  if we hit a timeout we can't just
     * keep trying because maybe we'll never successfully
     * write again...  but then maybe we'll leave would-be
     * readers stranded (a number of them could be tied up for
     * a while serving time-consuming requests)
     */
    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        rv = dummy_connection(pod);
    }
}
#endif /* #ifdef AP_MPM_USES_POD */

/* standard mpm configuration handling */
#ifdef AP_MPM_WANT_SET_PIDFILE
const char *ap_pid_fname = NULL;

const char *ap_mpm_set_pidfile(cmd_parms *cmd, void *dummy,
                               const char *arg)
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
#endif

#ifdef AP_MPM_WANT_SET_SCOREBOARD
const char * ap_mpm_set_scoreboard(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_scoreboard_fname = arg;
    return NULL;
}
#endif

#ifdef AP_MPM_WANT_SET_LOCKFILE
const char *ap_lock_fname = NULL;

const char *ap_mpm_set_lockfile(cmd_parms *cmd, void *dummy,
                                const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_lock_fname = arg;
    return NULL;
}
#endif

#ifdef AP_MPM_WANT_SET_MAX_REQUESTS
int ap_max_requests_per_child = 0;

const char *ap_mpm_set_max_requests(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_max_requests_per_child = atoi(arg);

    return NULL;
}
#endif

#ifdef AP_MPM_WANT_SET_COREDUMPDIR
char ap_coredump_dir[MAX_STRING_LEN];
int ap_coredumpdir_configured;

const char *ap_mpm_set_coredumpdir(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    if (!fname) {
        return apr_pstrcat(cmd->pool, "Invalid CoreDumpDirectory path ",
                           arg, NULL);
    }
    if ((rv = apr_stat(&finfo, fname, APR_FINFO_TYPE, cmd->pool)) != APR_SUCCESS) {
        return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname,
                           " does not exist", NULL);
    }
    if (finfo.filetype != APR_DIR) {
        return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname,
                           " is not a directory", NULL);
    }
    apr_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    ap_coredumpdir_configured = 1;
    return NULL;
}
#endif

#ifdef AP_MPM_WANT_SET_GRACEFUL_SHUTDOWN
int ap_graceful_shutdown_timeout = 0;

const char * ap_mpm_set_graceful_shutdown(cmd_parms *cmd, void *dummy,
                                          const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_graceful_shutdown_timeout = atoi(arg);
    return NULL;
}
#endif

#ifdef AP_MPM_WANT_SET_ACCEPT_LOCK_MECH
apr_lockmech_e ap_accept_lock_mech = APR_LOCK_DEFAULT;

const char ap_valid_accept_mutex_string[] =
    "Valid accept mutexes for this platform and MPM are: default"
#if APR_HAS_FLOCK_SERIALIZE
    ", flock"
#endif
#if APR_HAS_FCNTL_SERIALIZE
    ", fcntl"
#endif
#if APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)
    ", sysvsem"
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    ", posixsem"
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    ", pthread"
#endif
    ".";

AP_DECLARE(const char *) ap_mpm_set_accept_lock_mech(cmd_parms *cmd,
                                                     void *dummy,
                                                     const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "default")) {
        ap_accept_lock_mech = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FLOCK_SERIALIZE
    else if (!strcasecmp(arg, "flock")) {
        ap_accept_lock_mech = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_FCNTL_SERIALIZE
    else if (!strcasecmp(arg, "fcntl")) {
        ap_accept_lock_mech = APR_LOCK_FCNTL;
    }
#endif

    /* perchild can't use SysV sems because the permissions on the accept
     * mutex can't be set to allow all processes to use the mutex and
     * at the same time keep all users from being able to dink with the
     * mutex
     */
#if APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)
    else if (!strcasecmp(arg, "sysvsem")) {
        ap_accept_lock_mech = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    else if (!strcasecmp(arg, "posixsem")) {
        ap_accept_lock_mech = APR_LOCK_POSIXSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(arg, "pthread")) {
        ap_accept_lock_mech = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return apr_pstrcat(cmd->pool, arg, " is an invalid mutex mechanism; ",
                           ap_valid_accept_mutex_string, NULL);
    }
    return NULL;
}

#endif

#ifdef AP_MPM_WANT_SIGNAL_SERVER

static const char *dash_k_arg;

static int send_signal(pid_t pid, int sig)
{
    if (kill(pid, sig) < 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL,
                     "sending signal to server");
        return 1;
    }
    return 0;
}

int ap_signal_server(int *exit_status, apr_pool_t *pconf)
{
    apr_status_t rv;
    pid_t otherpid;
    int running = 0;
    int have_pid_file = 0;
    const char *status;

    *exit_status = 0;

    rv = ap_read_pid(pconf, ap_pid_fname, &otherpid);
    if (rv != APR_SUCCESS) {
        if (rv != APR_ENOENT) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, NULL,
                         "Error retrieving pid file %s", ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                         "Remove it before continuing if it is corrupted.");
            *exit_status = 1;
            return 1;
        }
        status = "httpd (no pid file) not running";
    }
    else {
        have_pid_file = 1;
        if (kill(otherpid, 0) == 0) {
            running = 1;
            status = apr_psprintf(pconf,
                                  "httpd (pid %" APR_PID_T_FMT ") already "
                                  "running", otherpid);
        }
        else {
            status = apr_psprintf(pconf,
                                  "httpd (pid %" APR_PID_T_FMT "?) not running",
                                  otherpid);
        }
    }

    if (!strcmp(dash_k_arg, "start")) {
        if (running) {
            printf("%s\n", status);
            return 1;
        }
    }

    if (!strcmp(dash_k_arg, "stop")) {
        if (!running) {
            printf("%s\n", status);
        }
        else {
            send_signal(otherpid, SIGTERM);
        }
        return 1;
    }

    if (!strcmp(dash_k_arg, "restart")) {
        if (!running) {
            printf("httpd not running, trying to start\n");
        }
        else {
            *exit_status = send_signal(otherpid, SIGHUP);
            return 1;
        }
    }

    if (!strcmp(dash_k_arg, "graceful")) {
        if (!running) {
            printf("httpd not running, trying to start\n");
        }
        else {
            *exit_status = send_signal(otherpid, AP_SIG_GRACEFUL);
            return 1;
        }
    }

    if (!strcmp(dash_k_arg, "graceful-stop")) {
#ifdef AP_MPM_WANT_SET_GRACEFUL_SHUTDOWN
        if (!running) {
            printf("%s\n", status);
        }
        else {
            *exit_status = send_signal(otherpid, AP_SIG_GRACEFUL_STOP);
        }
#else
        printf("httpd MPM \"" MPM_NAME "\" does not support graceful-stop\n");
#endif
        return 1;
    }

    return 0;
}

void ap_mpm_rewrite_args(process_rec *process)
{
    apr_array_header_t *mpm_new_argv;
    apr_status_t rv;
    apr_getopt_t *opt;
    char optbuf[3];
    const char *optarg;
    int fixed_args;

    mpm_new_argv = apr_array_make(process->pool, process->argc,
                                  sizeof(const char **));
    *(const char **)apr_array_push(mpm_new_argv) = process->argv[0];
    fixed_args = mpm_new_argv->nelts;
    apr_getopt_init(&opt, process->pool, process->argc, process->argv);
    opt->errfn = NULL;
    optbuf[0] = '-';
    /* option char returned by apr_getopt() will be stored in optbuf[1] */
    optbuf[2] = '\0';
    while ((rv = apr_getopt(opt, "k:" AP_SERVER_BASEARGS,
                            optbuf + 1, &optarg)) == APR_SUCCESS) {
        switch(optbuf[1]) {
        case 'k':
            if (!dash_k_arg) {
                if (!strcmp(optarg, "start") || !strcmp(optarg, "stop") ||
                    !strcmp(optarg, "restart") || !strcmp(optarg, "graceful") ||
                    !strcmp(optarg, "graceful-stop")) {
                    dash_k_arg = optarg;
                    break;
                }
            }
        default:
            *(const char **)apr_array_push(mpm_new_argv) =
                apr_pstrdup(process->pool, optbuf);
            if (optarg) {
                *(const char **)apr_array_push(mpm_new_argv) = optarg;
            }
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

    process->argc = mpm_new_argv->nelts;
    process->argv = (const char * const *)mpm_new_argv->elts;

    if (dash_k_arg) {
        APR_REGISTER_OPTIONAL_FN(ap_signal_server);
    }
}

#endif /* AP_MPM_WANT_SIGNAL_SERVER */

#ifdef AP_MPM_WANT_SET_MAX_MEM_FREE
apr_uint32_t ap_max_mem_free = APR_ALLOCATOR_MAX_FREE_UNLIMITED;

const char *ap_mpm_set_max_mem_free(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    long value;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    value = strtol(arg, NULL, 0);
    if (value < 0 || errno == ERANGE)
        return apr_pstrcat(cmd->pool, "Invalid MaxMemFree value: ",
                           arg, NULL);

    ap_max_mem_free = (apr_uint32_t)value * 1024;

    return NULL;
}

#endif /* AP_MPM_WANT_SET_MAX_MEM_FREE */

#ifdef AP_MPM_WANT_SET_STACKSIZE
apr_size_t ap_thread_stacksize = 0; /* use system default */

const char *ap_mpm_set_thread_stacksize(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    long value;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    value = strtol(arg, NULL, 0);
    if (value < 0 || errno == ERANGE)
        return apr_pstrcat(cmd->pool, "Invalid ThreadStackSize value: ",
                           arg, NULL);

    ap_thread_stacksize = (apr_size_t)value;

    return NULL;
}

#endif /* AP_MPM_WANT_SET_STACKSIZE */

#ifdef AP_MPM_WANT_FATAL_SIGNAL_HANDLER

static pid_t parent_pid, my_pid;
apr_pool_t *pconf;

#if AP_ENABLE_EXCEPTION_HOOK

static int exception_hook_enabled;

const char *ap_mpm_set_exception_hook(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (cmd->server->is_virtual) {
        return "EnableExceptionHook directive not allowed in <VirtualHost>";
    }

    if (strcasecmp(arg, "on") == 0) {
        exception_hook_enabled = 1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        exception_hook_enabled = 0;
    }
    else {
        return "parameter must be 'on' or 'off'";
    }

    return NULL;
}

static void run_fatal_exception_hook(int sig)
{
    ap_exception_info_t ei = {0};

    if (exception_hook_enabled &&
        geteuid() != 0 &&
        my_pid != parent_pid) {
        ei.sig = sig;
        ei.pid = my_pid;
        ap_run_fatal_exception(&ei);
    }
}
#endif /* AP_ENABLE_EXCEPTION_HOOK */

/* handle all varieties of core dumping signals */
static void sig_coredump(int sig)
{
    apr_filepath_set(ap_coredump_dir, pconf);
    apr_signal(sig, SIG_DFL);
#if AP_ENABLE_EXCEPTION_HOOK
    run_fatal_exception_hook(sig);
#endif
    /* linuxthreads issue calling getpid() here:
     *   This comparison won't match if the crashing thread is
     *   some module's thread that runs in the parent process.
     *   The fallout, which is limited to linuxthreads:
     *   The special log message won't be written when such a
     *   thread in the parent causes the parent to crash.
     */
    if (getpid() == parent_pid) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE,
                     0, ap_server_conf,
                     "seg fault or similar nasty error detected "
                     "in the parent process");
        /* XXX we can probably add some rudimentary cleanup code here,
         * like getting rid of the pid file.  If any additional bad stuff
         * happens, we are protected from recursive errors taking down the
         * system since this function is no longer the signal handler   GLA
         */
    }
    kill(getpid(), sig);
    /* At this point we've got sig blocked, because we're still inside
     * the signal handler.  When we leave the signal handler it will
     * be unblocked, and we'll take the signal... and coredump or whatever
     * is appropriate for this particular Unix.  In addition the parent
     * will see the real signal we received -- whereas if we called
     * abort() here, the parent would only see SIGABRT.
     */
}

apr_status_t ap_fatal_signal_child_setup(server_rec *s)
{
    my_pid = getpid();
    return APR_SUCCESS;
}

apr_status_t ap_fatal_signal_setup(server_rec *s, apr_pool_t *in_pconf)
{
#ifndef NO_USE_SIGACTION
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);

#if defined(SA_ONESHOT)
    sa.sa_flags = SA_ONESHOT;
#elif defined(SA_RESETHAND)
    sa.sa_flags = SA_RESETHAND;
#else
    sa.sa_flags = 0;
#endif

    sa.sa_handler = sig_coredump;
    if (sigaction(SIGSEGV, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, "sigaction(SIGSEGV)");
#ifdef SIGBUS
    if (sigaction(SIGBUS, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, "sigaction(SIGBUS)");
#endif
#ifdef SIGABORT
    if (sigaction(SIGABORT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, "sigaction(SIGABORT)");
#endif
#ifdef SIGABRT
    if (sigaction(SIGABRT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, "sigaction(SIGABRT)");
#endif
#ifdef SIGILL
    if (sigaction(SIGILL, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, "sigaction(SIGILL)");
#endif
#ifdef SIGFPE
    if (sigaction(SIGFPE, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, "sigaction(SIGFPE)");
#endif

#else /* NO_USE_SIGACTION */

    apr_signal(SIGSEGV, sig_coredump);
#ifdef SIGBUS
    apr_signal(SIGBUS, sig_coredump);
#endif /* SIGBUS */
#ifdef SIGABORT
    apr_signal(SIGABORT, sig_coredump);
#endif /* SIGABORT */
#ifdef SIGABRT
    apr_signal(SIGABRT, sig_coredump);
#endif /* SIGABRT */
#ifdef SIGILL
    apr_signal(SIGILL, sig_coredump);
#endif /* SIGILL */
#ifdef SIGFPE
    apr_signal(SIGFPE, sig_coredump);
#endif /* SIGFPE */

#endif /* NO_USE_SIGACTION */

    pconf = in_pconf;
    parent_pid = my_pid = getpid();

    return APR_SUCCESS;
}

#endif /* AP_MPM_WANT_FATAL_SIGNAL_HANDLER */
