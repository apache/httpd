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

#ifndef WIN32

#include "mpm_unix.h"

#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_getopt.h"
#include "apr_optional.h"
#include "apr_allocator.h"
#include "apr_atomic.h"
#include "apr_errno.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "scoreboard.h"
#include "util_mutex.h"

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif


/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

typedef enum {
    DO_NOTHING,
    SEND_SIGTERM,
    SEND_SIGTERM_NOLOG,
    SEND_SIGKILL,
    GIVEUP
} action_t;

typedef struct extra_process_t {
    struct extra_process_t *next;
    pid_t pid;
    ap_generation_t gen;
} extra_process_t;

static extra_process_t *extras;

AP_DECLARE(void) ap_register_extra_mpm_process(pid_t pid, ap_generation_t gen)
{
    extra_process_t *p = (extra_process_t *)ap_malloc(sizeof(extra_process_t));

    p->next = extras;
    p->pid = pid;
    p->gen = gen;
    extras = p;
}

AP_DECLARE(int) ap_unregister_extra_mpm_process(pid_t pid, ap_generation_t *old_gen)
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
        *old_gen = cur->gen;
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
    apr_exit_why_e why;
    int status;

    /* Ensure pid sanity. */
    if (pid < 1) {
        return 1;
    }

    proc.pid = pid;
    waitret = apr_proc_wait(&proc, &status, &why, APR_NOWAIT);
    if (waitret != APR_CHILD_NOTDONE) {
        if (waitret == APR_CHILD_DONE)
            ap_process_child_status(&proc, why, status);
        return 1;
    }

    switch(action) {
    case DO_NOTHING:
        break;

    case SEND_SIGTERM:
        /* ok, now it's being annoying */
        ap_log_error(APLOG_MARK, APLOG_WARNING,
                     0, ap_server_conf, APLOGNO(00045)
                     "child process %" APR_PID_T_FMT
                     " still did not exit, "
                     "sending a SIGTERM",
                     pid);
        /* FALLTHROUGH */
    case SEND_SIGTERM_NOLOG:
        kill(pid, SIGTERM);
        break;

    case SEND_SIGKILL:
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     0, ap_server_conf, APLOGNO(00046)
                     "child process %" APR_PID_T_FMT
                     " still did not exit, "
                     "sending a SIGKILL",
                     pid);
        kill(pid, SIGKILL);
        break;

    case GIVEUP:
        /* gave it our best shot, but alas...  If this really
         * is a child we are trying to kill and it really hasn't
         * exited, we will likely fail to bind to the port
         * after the restart.
         */
        ap_log_error(APLOG_MARK, APLOG_ERR,
                     0, ap_server_conf, APLOGNO(00047)
                     "could not make child process %" APR_PID_T_FMT
                     " exit, "
                     "attempting to continue anyway",
                     pid);
        break;
    }

    return 0;
}

AP_DECLARE(void) ap_reclaim_child_processes(int terminate,
                                            ap_reclaim_callback_fn_t *mpm_callback)
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
        {SEND_SIGTERM_NOLOG, 0}, /* skipped if terminate == 0 */
        {SEND_SIGTERM, apr_time_from_sec(3)},
        {SEND_SIGTERM, apr_time_from_sec(5)},
        {SEND_SIGTERM, apr_time_from_sec(7)},
        {SEND_SIGKILL, apr_time_from_sec(9)},
        {GIVEUP,       apr_time_from_sec(10)}
    };
    int cur_action;      /* index of action we decided to take this
                          * iteration
                          */
    int next_action = terminate ? 1 : 2; /* index of first real action */

    ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons);

    do {
        if (action_table[next_action].action_time > 0) {
            apr_sleep(waittime);
            /* don't let waittime get longer than 1 second; otherwise, we don't
             * react quickly to the last child exiting, and taking action can
             * be delayed
             */
            waittime = waittime * 4;
            if (waittime > apr_time_from_sec(1)) {
                waittime = apr_time_from_sec(1);
            }
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
            process_score *ps = ap_get_scoreboard_process(i);
            pid_t pid = ps->pid;

            if (pid == 0) {
                continue; /* not every scoreboard entry is in use */
            }

            if (reclaim_one_pid(pid, action_table[cur_action].action)) {
                mpm_callback(i, 0, 0);
            }
            else {
                ++not_dead_yet;
            }
        }

        cur_extra = extras;
        while (cur_extra) {
            ap_generation_t old_gen;
            extra_process_t *next = cur_extra->next;

            if (reclaim_one_pid(cur_extra->pid, action_table[cur_action].action)) {
                if (ap_unregister_extra_mpm_process(cur_extra->pid, &old_gen) == 1) {
                    mpm_callback(-1, cur_extra->pid, old_gen);
                }
                else {
                    AP_DEBUG_ASSERT(1 == 0);
                }
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

AP_DECLARE(void) ap_relieve_child_processes(ap_reclaim_callback_fn_t *mpm_callback)
{
    int i;
    extra_process_t *cur_extra;
    int max_daemons;

    ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons);

    /* now see who is done */
    for (i = 0; i < max_daemons; ++i) {
        process_score *ps = ap_get_scoreboard_process(i);
        pid_t pid = ps->pid;

        if (pid == 0) {
            continue; /* not every scoreboard entry is in use */
        }

        if (reclaim_one_pid(pid, DO_NOTHING)) {
            mpm_callback(i, 0, 0);
        }
    }

    cur_extra = extras;
    while (cur_extra) {
        ap_generation_t old_gen;
        extra_process_t *next = cur_extra->next;

        if (reclaim_one_pid(cur_extra->pid, DO_NOTHING)) {
            if (ap_unregister_extra_mpm_process(cur_extra->pid, &old_gen) == 1) {
                mpm_callback(-1, cur_extra->pid, old_gen);
            }
            else {
                AP_DEBUG_ASSERT(1 == 0);
            }
        }
        cur_extra = next;
    }
}

/* Before sending the signal to the pid this function verifies that
 * the pid is a member of the current process group; either using
 * apr_proc_wait(), where waitpid() guarantees to fail for non-child
 * processes; or by using getpgid() directly, if available. */
AP_DECLARE(apr_status_t) ap_mpm_safe_kill(pid_t pid, int sig)
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
        /* The child already died - log the termination status if
         * necessary: */
        ap_process_child_status(&proc, why, status);
        return APR_EINVAL;
    }
    else if (rv != APR_CHILD_NOTDONE) {
        /* The child is already dead and reaped, or was a bogus pid -
         * log this either way. */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, ap_server_conf, APLOGNO(00048)
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
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, ap_server_conf, APLOGNO(00049)
                     "refusing to send signal %d to pid %ld outside "
                     "process group", sig, (long)pid);
        return APR_EINVAL;
    }
#endif

    return kill(pid, sig) ? errno : APR_SUCCESS;
}


AP_DECLARE(int) ap_process_child_status(apr_proc_t *pid, apr_exit_why_e why,
                                        int status)
{
    int signum = status;
    const char *sigdesc;

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
                         0, ap_server_conf, APLOGNO(00050)
                         "Child %" APR_PID_T_FMT
                         " returned a Fatal error... Apache is exiting!",
                         pid->pid);
            return APEXIT_CHILDFATAL;
        }

        return 0;
    }

    if (APR_PROC_CHECK_SIGNALED(why)) {
        sigdesc = apr_signal_description_get(signum);

        switch (signum) {
        case SIGTERM:
        case SIGHUP:
        case AP_SIG_GRACEFUL:
        case SIGKILL:
            break;

        default:
            if (APR_PROC_CHECK_CORE_DUMP(why)) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE,
                             0, ap_server_conf, APLOGNO(00051)
                             "child pid %ld exit signal %s (%d), "
                             "possible coredump in %s",
                             (long)pid->pid, sigdesc, signum,
                             ap_coredump_dir);
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_NOTICE,
                             0, ap_server_conf, APLOGNO(00052)
                             "child pid %ld exit signal %s (%d)",
                             (long)pid->pid, sigdesc, signum);
            }
        }
    }
    return 0;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_open(apr_pool_t *p, ap_pod_t **pod)
{
    apr_status_t rv;

    *pod = apr_palloc(p, sizeof(**pod));
    rv = apr_file_pipe_create_ex(&((*pod)->pod_in), &((*pod)->pod_out),
                                 APR_WRITE_BLOCK, p);
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
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, APLOGNO(00053)
                     "write pipe_of_death");
    }

    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_podx_open(apr_pool_t *p, ap_pod_t **pod)
{
    apr_status_t rv;

    *pod = apr_palloc(p, sizeof(**pod));
    rv = apr_file_pipe_create(&((*pod)->pod_in), &((*pod)->pod_out), p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    /*
     apr_file_pipe_timeout_set((*pod)->pod_in, 0);
     */
    (*pod)->p = p;

    /* close these before exec. */
    apr_file_inherit_unset((*pod)->pod_in);
    apr_file_inherit_unset((*pod)->pod_out);

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_mpm_podx_check(ap_pod_t *pod)
{
    char c;
    apr_os_file_t fd;
    int rc;

    /* we need to surface EINTR so we'll have to grab the
     * native file descriptor and do the OS read() ourselves
     */
    apr_os_file_get(&fd, pod->pod_in);
    rc = read(fd, &c, 1);
    if (rc == 1) {
        switch (c) {
            case AP_MPM_PODX_RESTART_CHAR:
                return AP_MPM_PODX_RESTART;
            case AP_MPM_PODX_GRACEFUL_CHAR:
                return AP_MPM_PODX_GRACEFUL;
        }
    }
    return AP_MPM_PODX_NORESTART;
}

AP_DECLARE(apr_status_t) ap_mpm_podx_close(ap_pod_t *pod)
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
    return rv;
}

static apr_status_t podx_signal_internal(ap_pod_t *pod,
                                        ap_podx_restart_t graceful)
{
    apr_status_t rv;
    apr_size_t one = 1;
    char char_of_death = ' ';
    switch (graceful) {
        case AP_MPM_PODX_RESTART:
            char_of_death = AP_MPM_PODX_RESTART_CHAR;
            break;
        case AP_MPM_PODX_GRACEFUL:
            char_of_death = AP_MPM_PODX_GRACEFUL_CHAR;
            break;
        case AP_MPM_PODX_NORESTART:
            break;
    }

    rv = apr_file_write(pod->pod_out, &char_of_death, &one);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, APLOGNO(02404)
                     "write pipe_of_death");
    }
    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_podx_signal(ap_pod_t * pod,
                                            ap_podx_restart_t graceful)
{
    return podx_signal_internal(pod, graceful);
}

AP_DECLARE(void) ap_mpm_podx_killpg(ap_pod_t * pod, int num,
                                    ap_podx_restart_t graceful)
{
    int i;
    apr_status_t rv = APR_SUCCESS;

    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        rv = podx_signal_internal(pod, graceful);
    }
}

/* This function connects to the server and sends enough data to
 * ensure the child wakes up and processes a new connection.  This
 * permits the MPM to skip the poll when there is only one listening
 * socket, because it provides a alternate way to unblock an accept()
 * when the pod is used.  */
static apr_status_t dummy_connection(ap_pod_t *pod)
{
    const char *data;
    apr_status_t rv;
    apr_socket_t *sock;
    apr_pool_t *p;
    apr_size_t len;
    ap_listen_rec *lp;

    /* create a temporary pool for the socket.  pconf stays around too long */
    rv = apr_pool_create(&p, pod->p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* If possible, find a listener which is configured for
     * plain-HTTP, not SSL; using an SSL port would either be
     * expensive to do correctly (performing a complete SSL handshake)
     * or cause log spam by doing incorrectly (simply sending EOF). */
    lp = ap_listeners;
    while (lp && lp->protocol && ap_cstr_casecmp(lp->protocol, "http") != 0) {
        lp = lp->next;
    }
    if (!lp) {
        lp = ap_listeners;
    }

    rv = apr_socket_create(&sock, lp->bind_addr->family, SOCK_STREAM, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, APLOGNO(00054)
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
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, APLOGNO(00055)
                     "set timeout on socket to connect to listener");
        apr_socket_close(sock);
        apr_pool_destroy(p);
        return rv;
    }

    rv = apr_socket_connect(sock, lp->bind_addr);
    if (rv != APR_SUCCESS) {
        int log_level = APLOG_WARNING;

        if (APR_STATUS_IS_TIMEUP(rv)) {
            /* probably some server processes bailed out already and there
             * is nobody around to call accept and clear out the kernel
             * connection queue; usually this is not worth logging
             */
            log_level = APLOG_DEBUG;
        }

        ap_log_error(APLOG_MARK, log_level, rv, ap_server_conf, APLOGNO(00056)
                     "connect to listener on %pI", lp->bind_addr);
        apr_pool_destroy(p);
        return rv;
    }

    if (lp->protocol && ap_cstr_casecmp(lp->protocol, "https") == 0) {
        /* Send a TLS 1.0 close_notify alert.  This is perhaps the
         * "least wrong" way to open and cleanly terminate an SSL
         * connection.  It should "work" without noisy error logs if
         * the server actually expects SSLv3/TLSv1.  With
         * SSLv23_server_method() OpenSSL's SSL_accept() fails
         * ungracefully on receipt of this message, since it requires
         * an 11-byte ClientHello message and this is too short. */
        static const unsigned char tls10_close_notify[7] = {
            '\x15',         /* TLSPlainText.type = Alert (21) */
            '\x03', '\x01', /* TLSPlainText.version = {3, 1} */
            '\x00', '\x02', /* TLSPlainText.length = 2 */
            '\x01',         /* Alert.level = warning (1) */
            '\x00'          /* Alert.description = close_notify (0) */
        };
        data = (const char *)tls10_close_notify;
        len = sizeof(tls10_close_notify);
    }
    else /* ... XXX other request types here? */ {
        /* Create an HTTP request string.  We include a User-Agent so
         * that adminstrators can track down the cause of the
         * odd-looking requests in their logs.  A complete request is
         * used since kernel-level filtering may require that much
         * data before returning from accept(). */
        data = apr_pstrcat(p, "OPTIONS * HTTP/1.0\r\nUser-Agent: ",
                           ap_get_server_description(),
                           " (internal dummy connection)\r\n\r\n", NULL);
        len = strlen(data);
    }

    apr_socket_send(sock, data, &len);
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
    /* Recall: we only worry about IDLE child processes here */
    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        if (ap_scoreboard_image->servers[i][0].status != SERVER_READY ||
            ap_scoreboard_image->servers[i][0].pid == 0) {
            continue;
        }
        rv = dummy_connection(pod);
    }
}

static const char *dash_k_arg = NULL;
static const char *dash_k_arg_noarg = "noarg";

static int send_signal(pid_t pid, int sig)
{
    if (kill(pid, sig) < 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL, APLOGNO(00057)
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
    const char *status;

    *exit_status = 0;

    rv = ap_read_pid(pconf, ap_pid_fname, &otherpid);
    if (rv != APR_SUCCESS) {
        if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, rv, NULL, APLOGNO(00058)
                         "Error retrieving pid file %s", ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, APLOGNO(00059)
                         "Remove it before continuing if it is corrupted.");
            *exit_status = 1;
            return 1;
        }
        status = "httpd (no pid file) not running";
    }
    else {
        /* With containerization, httpd may get the same PID at each startup,
         * handle it as if it were not running (it obviously can't).
         */
        if (otherpid != getpid() && kill(otherpid, 0) == 0) {
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

    if (!strcmp(dash_k_arg, "start") || dash_k_arg == dash_k_arg_noarg) {
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
        if (!running) {
            printf("%s\n", status);
        }
        else {
            *exit_status = send_signal(otherpid, AP_SIG_GRACEFUL_STOP);
        }
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

    mpm_new_argv = apr_array_make(process->pool, process->argc,
                                  sizeof(const char **));
    *(const char **)apr_array_push(mpm_new_argv) = process->argv[0];
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

    if (NULL == dash_k_arg) {
        dash_k_arg = dash_k_arg_noarg;
    }

    APR_REGISTER_OPTIONAL_FN(ap_signal_server);
}

static pid_t parent_pid, my_pid;
static apr_pool_t *pconf;

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
                     0, ap_server_conf, APLOGNO(00060)
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

AP_DECLARE(apr_status_t) ap_fatal_signal_child_setup(server_rec *s)
{
    my_pid = getpid();
    return APR_SUCCESS;
}

/* We can't call sig_coredump (ap_log_error) once pconf is destroyed, so
 * avoid double faults by restoring each default signal handler on cleanup.
 */
static apr_status_t fatal_signal_cleanup(void *unused)
{
    (void)unused;

    apr_signal(SIGSEGV, SIG_DFL);
#ifdef SIGBUS
    apr_signal(SIGBUS, SIG_DFL);
#endif /* SIGBUS */
#ifdef SIGABORT
    apr_signal(SIGABORT, SIG_DFL);
#endif /* SIGABORT */
#ifdef SIGABRT
    apr_signal(SIGABRT, SIG_DFL);
#endif /* SIGABRT */
#ifdef SIGILL
    apr_signal(SIGILL, SIG_DFL);
#endif /* SIGILL */
#ifdef SIGFPE
    apr_signal(SIGFPE, SIG_DFL);
#endif /* SIGFPE */

    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_fatal_signal_setup(server_rec *s,
                                               apr_pool_t *in_pconf)
{
#ifndef NO_USE_SIGACTION
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);

#if defined(SA_ONESHOT)
    sa.sa_flags = SA_ONESHOT;
#elif defined(SA_RESETHAND)
    sa.sa_flags = SA_RESETHAND;
#endif

    sa.sa_handler = sig_coredump;
    if (sigaction(SIGSEGV, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, APLOGNO(00061) "sigaction(SIGSEGV)");
#ifdef SIGBUS
    if (sigaction(SIGBUS, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, APLOGNO(00062) "sigaction(SIGBUS)");
#endif
#ifdef SIGABORT
    if (sigaction(SIGABORT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, APLOGNO(00063) "sigaction(SIGABORT)");
#endif
#ifdef SIGABRT
    if (sigaction(SIGABRT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, APLOGNO(00064) "sigaction(SIGABRT)");
#endif
#ifdef SIGILL
    if (sigaction(SIGILL, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, APLOGNO(00065) "sigaction(SIGILL)");
#endif
#ifdef SIGFPE
    if (sigaction(SIGFPE, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s, APLOGNO(00066) "sigaction(SIGFPE)");
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
    apr_pool_cleanup_register(pconf, NULL, fatal_signal_cleanup,
                              fatal_signal_cleanup);

    return APR_SUCCESS;
}


/* 
 * fdqueue code used by MPMs event and worker.
 * Not part of the API, so not AP_DECLARE()d.
 */

static const apr_uint32_t zero_pt = APR_UINT32_MAX/2;

struct recycled_pool
{
    apr_pool_t *pool;
    struct recycled_pool *next;
};

struct fd_queue_info_t
{
    apr_uint32_t volatile idlers; /**
                                   * >= zero_pt: number of idle worker threads
                                   * <  zero_pt: number of threads blocked,
                                   *             waiting for an idle worker
                                   */
    apr_thread_mutex_t *idlers_mutex;
    apr_thread_cond_t *wait_for_idler;
    int terminated;
    int max_idlers;
    int max_recycled_pools;
    apr_uint32_t recycled_pools_count;
    struct recycled_pool *volatile recycled_pools;
};

struct fd_queue_elem_t
{
    apr_socket_t *sd;
    apr_pool_t *p;
    void *baton;
};

static apr_status_t queue_info_cleanup(void *data_)
{
    fd_queue_info_t *qi = data_;
    apr_thread_cond_destroy(qi->wait_for_idler);
    apr_thread_mutex_destroy(qi->idlers_mutex);

    /* Clean up any pools in the recycled list */
    for (;;) {
        struct recycled_pool *first_pool = qi->recycled_pools;
        if (first_pool == NULL) {
            break;
        }
        if (apr_atomic_casptr((void *)&qi->recycled_pools, first_pool->next,
                              first_pool) == first_pool) {
            apr_pool_destroy(first_pool->pool);
        }
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_create(fd_queue_info_t **queue_info,
                                  apr_pool_t *pool, int max_idlers,
                                  int max_recycled_pools)
{
    apr_status_t rv;
    fd_queue_info_t *qi;

    qi = apr_pcalloc(pool, sizeof(*qi));

    rv = apr_thread_mutex_create(&qi->idlers_mutex, APR_THREAD_MUTEX_DEFAULT,
                                 pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_thread_cond_create(&qi->wait_for_idler, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    qi->recycled_pools = NULL;
    qi->max_recycled_pools = max_recycled_pools;
    qi->max_idlers = max_idlers;
    qi->idlers = zero_pt;
    apr_pool_cleanup_register(pool, qi, queue_info_cleanup,
                              apr_pool_cleanup_null);

    *queue_info = qi;

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                    apr_pool_t *pool_to_recycle)
{
    apr_status_t rv;

    ap_push_pool(queue_info, pool_to_recycle);

    /* If other threads are waiting on a worker, wake one up */
    if (apr_atomic_inc32(&queue_info->idlers) < zero_pt) {
        rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            AP_DEBUG_ASSERT(0);
            return rv;
        }
        rv = apr_thread_cond_signal(queue_info->wait_for_idler);
        if (rv != APR_SUCCESS) {
            apr_thread_mutex_unlock(queue_info->idlers_mutex);
            return rv;
        }
        rv = apr_thread_mutex_unlock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_try_get_idler(fd_queue_info_t *queue_info)
{
    /* Don't block if there isn't any idle worker. */
    for (;;) {
        apr_uint32_t idlers = queue_info->idlers;
        if (idlers <= zero_pt) {
            return APR_EAGAIN;
        }
        if (apr_atomic_cas32(&queue_info->idlers, idlers - 1,
                             idlers) == idlers) {
            return APR_SUCCESS;
        }
    }
}

apr_status_t ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info,
                                          int *had_to_block)
{
    apr_status_t rv;

    /* Block if there isn't any idle worker.
     * apr_atomic_add32(x, -1) does the same as dec32(x), except
     * that it returns the previous value (unlike dec32's bool).
     */
    if (apr_atomic_add32(&queue_info->idlers, -1) <= zero_pt) {
        rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            AP_DEBUG_ASSERT(0);
            apr_atomic_inc32(&(queue_info->idlers));    /* back out dec */
            return rv;
        }
        /* Re-check the idle worker count to guard against a
         * race condition.  Now that we're in the mutex-protected
         * region, one of two things may have happened:
         *   - If the idle worker count is still negative, the
         *     workers are all still busy, so it's safe to
         *     block on a condition variable.
         *   - If the idle worker count is non-negative, then a
         *     worker has become idle since the first check
         *     of queue_info->idlers above.  It's possible
         *     that the worker has also signaled the condition
         *     variable--and if so, the listener missed it
         *     because it wasn't yet blocked on the condition
         *     variable.  But if the idle worker count is
         *     now non-negative, it's safe for this function to
         *     return immediately.
         *
         *     A "negative value" (relative to zero_pt) in
         *     queue_info->idlers tells how many
         *     threads are waiting on an idle worker.
         */
        if (queue_info->idlers < zero_pt) {
            *had_to_block = 1;
            rv = apr_thread_cond_wait(queue_info->wait_for_idler,
                                      queue_info->idlers_mutex);
            if (rv != APR_SUCCESS) {
                apr_status_t rv2;
                AP_DEBUG_ASSERT(0);
                rv2 = apr_thread_mutex_unlock(queue_info->idlers_mutex);
                if (rv2 != APR_SUCCESS) {
                    return rv2;
                }
                return rv;
            }
        }
        rv = apr_thread_mutex_unlock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    if (queue_info->terminated) {
        return APR_EOF;
    }
    else {
        return APR_SUCCESS;
    }
}

apr_uint32_t ap_queue_info_num_idlers(fd_queue_info_t *queue_info)
{
    apr_uint32_t val;
    val = apr_atomic_read32(&queue_info->idlers);
    if (val <= zero_pt)
        return 0;
    return val - zero_pt;
}

void ap_push_pool(fd_queue_info_t *queue_info, apr_pool_t *pool_to_recycle)
{
    struct recycled_pool *new_recycle;
    /* If we have been given a pool to recycle, atomically link
     * it into the queue_info's list of recycled pools
     */
    if (!pool_to_recycle)
        return;

    if (queue_info->max_recycled_pools >= 0) {
        apr_uint32_t cnt = apr_atomic_read32(&queue_info->recycled_pools_count);
        if (cnt >= queue_info->max_recycled_pools) {
            apr_pool_destroy(pool_to_recycle);
            return;
        }
        apr_atomic_inc32(&queue_info->recycled_pools_count);
    }

    apr_pool_clear(pool_to_recycle);
    new_recycle = apr_palloc(pool_to_recycle, sizeof *new_recycle);
    new_recycle->pool = pool_to_recycle;
    for (;;) {
        /*
         * Save queue_info->recycled_pool in local variable next because
         * new_recycle->next can be changed after apr_atomic_casptr
         * function call. For gory details see PR 44402.
         */
        struct recycled_pool *next = queue_info->recycled_pools;
        new_recycle->next = next;
        if (apr_atomic_casptr((void*) &(queue_info->recycled_pools),
                              new_recycle, next) == next)
            break;
    }
}

void ap_pop_pool(apr_pool_t **recycled_pool, fd_queue_info_t *queue_info)
{
    /* Atomically pop a pool from the recycled list */

    /* This function is safe only as long as it is single threaded because
     * it reaches into the queue and accesses "next" which can change.
     * We are OK today because it is only called from the listener thread.
     * cas-based pushes do not have the same limitation - any number can
     * happen concurrently with a single cas-based pop.
     */

    *recycled_pool = NULL;


    /* Atomically pop a pool from the recycled list */
    for (;;) {
        struct recycled_pool *first_pool = queue_info->recycled_pools;
        if (first_pool == NULL) {
            break;
        }
        if (apr_atomic_casptr((void *)&queue_info->recycled_pools,
                              first_pool->next, first_pool) == first_pool) {
            *recycled_pool = first_pool->pool;
            if (queue_info->max_recycled_pools >= 0)
                apr_atomic_dec32(&queue_info->recycled_pools_count);
            break;
        }
    }
}

void ap_free_idle_pools(fd_queue_info_t *queue_info)
{
    apr_pool_t *p;

    queue_info->max_recycled_pools = 0;
    for (;;) {
        ap_pop_pool(&p, queue_info);
        if (p == NULL)
            break;
        apr_pool_destroy(p);
    }
    apr_atomic_set32(&queue_info->recycled_pools_count, 0);
}


apr_status_t ap_queue_info_term(fd_queue_info_t *queue_info)
{
    apr_status_t rv;
    rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    queue_info->terminated = 1;
    apr_thread_cond_broadcast(queue_info->wait_for_idler);
    return apr_thread_mutex_unlock(queue_info->idlers_mutex);
}

/**
 * Detects when the fd_queue_t is full. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ap_queue_full(queue) ((queue)->nelts == (queue)->bounds)

/**
 * Detects when the fd_queue_t is empty. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ap_queue_empty(queue) ((queue)->nelts == 0 && APR_RING_EMPTY(&queue->timers ,timer_event_t, link))

/**
 * Callback routine that is called to destroy this
 * fd_queue_t when its pool is destroyed.
 */
static apr_status_t ap_queue_destroy(void *data)
{
    fd_queue_t *queue = data;

    /* Ignore errors here, we can't do anything about them anyway.
     * XXX: We should at least try to signal an error here, it is
     * indicative of a programmer error. -aaron */
    apr_thread_cond_destroy(queue->not_empty);
    apr_thread_mutex_destroy(queue->one_big_mutex);

    return APR_SUCCESS;
}

/**
 * Initialize the fd_queue_t.
 */
apr_status_t ap_queue_init(fd_queue_t *queue, int queue_capacity,
                           apr_pool_t *a)
{
    int i;
    apr_status_t rv;

    if ((rv = apr_thread_mutex_create(&queue->one_big_mutex,
                                      APR_THREAD_MUTEX_DEFAULT,
                                      a)) != APR_SUCCESS) {
        return rv;
    }
    if ((rv = apr_thread_cond_create(&queue->not_empty, a)) != APR_SUCCESS) {
        return rv;
    }

    APR_RING_INIT(&queue->timers, timer_event_t, link);

    queue->data = apr_palloc(a, queue_capacity * sizeof(fd_queue_elem_t));
    queue->bounds = queue_capacity;
    queue->nelts = 0;
    queue->in = 0;
    queue->out = 0;

    /* Set all the sockets in the queue to NULL */
    for (i = 0; i < queue_capacity; ++i)
        queue->data[i].sd = NULL;

    apr_pool_cleanup_register(a, queue, ap_queue_destroy,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

/**
 * Push a new socket onto the queue.
 *
 * precondition: ap_queue_info_wait_for_idler has already been called
 *               to reserve an idle worker thread
 */
apr_status_t ap_queue_push(fd_queue_t *queue, apr_socket_t *sd,
                           void *baton, apr_pool_t *p)
{
    fd_queue_elem_t *elem;
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    AP_DEBUG_ASSERT(!queue->terminated);
    AP_DEBUG_ASSERT(!ap_queue_full(queue));

    elem = &queue->data[queue->in];
    queue->in++;
    if (queue->in >= queue->bounds)
        queue->in -= queue->bounds;
    elem->sd = sd;
    elem->baton = baton;
    elem->p = p;
    queue->nelts++;

    apr_thread_cond_signal(queue->not_empty);

    if ((rv = apr_thread_mutex_unlock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_push_timer(fd_queue_t *queue, timer_event_t *te)
{
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    AP_DEBUG_ASSERT(!queue->terminated);

    APR_RING_INSERT_TAIL(&queue->timers, te, timer_event_t, link);

    apr_thread_cond_signal(queue->not_empty);

    if ((rv = apr_thread_mutex_unlock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    return APR_SUCCESS;
}

/**
 * Retrieves the next available socket from the queue. If there are no
 * sockets available, it will block until one becomes available.
 * Once retrieved, the socket is placed into the address specified by
 * 'sd'.
 */
apr_status_t ap_queue_pop_something(fd_queue_t *queue, apr_socket_t **sd,
                                    void **baton, apr_pool_t **p,
                                    timer_event_t **te_out)
{
    fd_queue_elem_t *elem;
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    /* Keep waiting until we wake up and find that the queue is not empty. */
    if (ap_queue_empty(queue)) {
        if (!queue->terminated) {
            apr_thread_cond_wait(queue->not_empty, queue->one_big_mutex);
        }
        /* If we wake up and it's still empty, then we were interrupted */
        if (ap_queue_empty(queue)) {
            rv = apr_thread_mutex_unlock(queue->one_big_mutex);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            if (queue->terminated) {
                return APR_EOF; /* no more elements ever again */
            }
            else {
                return APR_EINTR;
            }
        }
    }

    *te_out = NULL;

    if (!APR_RING_EMPTY(&queue->timers, timer_event_t, link)) {
        *te_out = APR_RING_FIRST(&queue->timers);
        APR_RING_REMOVE(*te_out, link);
    }
    else {
        elem = &queue->data[queue->out];
        queue->out++;
        if (queue->out >= queue->bounds)
            queue->out -= queue->bounds;
        queue->nelts--;
        *sd = elem->sd;
        *baton = elem->baton;
        *p = elem->p;
#ifdef AP_DEBUG
        elem->sd = NULL;
        elem->p = NULL;
#endif /* AP_DEBUG */
    }

    rv = apr_thread_mutex_unlock(queue->one_big_mutex);
    return rv;
}

static apr_status_t queue_interrupt(fd_queue_t *queue, int all, int term)
{
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }
    /* we must hold one_big_mutex when setting this... otherwise,
     * we could end up setting it and waking everybody up just after a
     * would-be popper checks it but right before they block
     */
    if (term) {
        queue->terminated = 1;
    }
    if (all)
        apr_thread_cond_broadcast(queue->not_empty);
    else
        apr_thread_cond_signal(queue->not_empty);
    return apr_thread_mutex_unlock(queue->one_big_mutex);
}

apr_status_t ap_queue_interrupt_all(fd_queue_t *queue)
{
    return queue_interrupt(queue, 1, 0);
}

apr_status_t ap_queue_interrupt_one(fd_queue_t *queue)
{
    return queue_interrupt(queue, 0, 0);
}

apr_status_t ap_queue_term(fd_queue_t *queue)
{
    return queue_interrupt(queue, 1, 1);
}

#endif /* WIN32 */
