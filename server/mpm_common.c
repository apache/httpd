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
#include "apr_lock.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_main.h"
#include "mpm.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "ap_listen.h"

#ifdef AP_MPM_WANT_SET_SCOREBOARD
#include "scoreboard.h"
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef AP_MPM_WANT_RECLAIM_CHILD_PROCESSES
void ap_reclaim_child_processes(int terminate)
{
    int i;
    long int waittime = 1024 * 16;      /* in usecs */
    apr_status_t waitret;
    int tries;
    int not_dead_yet;
    int max_daemons;

    ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_daemons);
    MPM_SYNC_CHILD_TABLE();

    for (tries = terminate ? 4 : 1; tries <= 9; ++tries) {
        /* don't want to hold up progress any more than
         * necessary, but we need to allow children a few moments to exit.
         * Set delay with an exponential backoff.
         */
        waittime = waittime * 4;
        apr_sleep(waittime);

        /* now see who is done */
        not_dead_yet = 0;
        for (i = 0; i < max_daemons; ++i) {
            pid_t pid = MPM_CHILD_PID(i);
            apr_proc_t proc;

            if (pid == 0)
                continue;

            proc.pid = pid;
            waitret = apr_proc_wait(&proc, APR_NOWAIT);
            if (waitret != APR_CHILD_NOTDONE) {
                MPM_NOTE_CHILD_KILLED(i);
                continue;
            }
            ++not_dead_yet;
            switch (tries) {
            case 1:     /*  16ms */
            case 2:     /*  82ms */
            case 3:     /* 344ms */
            case 4:     /*  16ms */
                break;
            case 5:     /*  82ms */
            case 6:     /* 344ms */
            case 7:     /* 1.4sec */
                /* ok, now it's being annoying */
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING,
                             0, ap_server_conf,
                   "child process %ld still did not exit, sending a SIGTERM",
                             (long)pid);
                kill(pid, SIGTERM);
                break;
            case 8:     /*  6 sec */
                /* die child scum */
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
                             0, ap_server_conf,
                   "child process %ld still did not exit, sending a SIGKILL",
                             (long)pid);
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
            case 9:     /* 14 sec */
                /* gave it our best shot, but alas...  If this really
                 * is a child we are trying to kill and it really hasn't
                 * exited, we will likely fail to bind to the port
                 * after the restart.
                 */
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
                             0, ap_server_conf,
                             "could not make child process %ld exit, "
                             "attempting to continue anyway", (long)pid);
                break;
            }
        }
#if APR_HAS_OTHER_CHILD
        apr_proc_other_child_check();
#endif
        if (!not_dead_yet) {
            /* nothing left to wait for */
            break;
        }
    }
}
#endif /* AP_MPM_WANT_RECLAIM_CHILD_PROCESSES */

#ifdef AP_MPM_WANT_WAIT_OR_TIMEOUT

/* number of calls to wait_or_timeout between writable probes */
#ifndef INTERVAL_OF_WRITABLE_PROBES
#define INTERVAL_OF_WRITABLE_PROBES 10
#endif
static int wait_or_timeout_counter;

void ap_wait_or_timeout(apr_wait_t *status, apr_proc_t *ret, apr_pool_t *p)
{
    apr_status_t rv;

    ++wait_or_timeout_counter;
    if (wait_or_timeout_counter == INTERVAL_OF_WRITABLE_PROBES) {
        wait_or_timeout_counter = 0;
    }
    rv = apr_proc_wait_all_procs(ret, status, APR_NOWAIT, p);
    if (APR_STATUS_IS_EINTR(rv)) {
        ret->pid = -1;
        return;
    }
    if (APR_STATUS_IS_CHILD_DONE(rv)) {
        return;
    }
#ifdef NEED_WAITPID
    if ((ret = reap_children(status)) > 0) {
        return;
    }
#endif
    apr_sleep(SCOREBOARD_MAINTENANCE_INTERVAL);
    ret->pid = -1;
    return;
}
#endif /* AP_MPM_WANT_WAIT_OR_TIMEOUT */

#ifdef AP_MPM_WANT_PROCESS_CHILD_STATUS
void ap_process_child_status(apr_proc_t *pid, apr_wait_t status)
{
    int signum = WTERMSIG(status);
    const char *sigdesc = apr_signal_get_description(signum);

    /* Child died... if it died due to a fatal error,
        * we should simply bail out.
        */
    if ((WIFEXITED(status)) &&
        WEXITSTATUS(status) == APEXIT_CHILDFATAL) {
        ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, 0, ap_server_conf,
                        "Child %ld returned a Fatal error..." APR_EOL_STR
                        "Apache is exiting!",
                        (long)pid->pid);
        exit(APEXIT_CHILDFATAL);
    }

    if (WIFSIGNALED(status)) {
        switch (signum) {
        case SIGTERM:
        case SIGHUP:
        case SIGWINCH:
        case SIGKILL:
            break;
        default:
#ifdef WCOREDUMP
            if (WCOREDUMP(status)) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, ap_server_conf,
                             "child pid %ld exit signal %s (%d), "
                             "possible coredump in %s",
                             (long)pid->pid, sigdesc, signum,
                             ap_coredump_dir);
            }
            else
#endif
            {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, ap_server_conf,
                             "child pid %ld exit signal %s (%d)",
                             (long)pid->pid, sigdesc, signum);
            }
        }
    }
}
#endif /* AP_MPM_WANT_PROCESS_CHILD_STATUS */

#if defined(TCP_NODELAY) && !defined(MPE) && !defined(TPF) && !defined(WIN32)
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
    apr_status_t status = apr_setsocketopt(s, APR_TCP_NODELAY, 1);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, status, ap_server_conf,
                    "setsockopt: (TCP_NODELAY)");
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
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, "%s: bad user name %s", ap_server_argv0, name);
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
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, "%s: bad group name %s", ap_server_argv0, name);                                               exit(1);
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

    while (index < NGROUPS_MAX && ((g = getgrent()) != NULL))
        if (g->gr_gid != basegid) {
            char **names;

            for (names = g->gr_mem; *names != NULL; ++names)
                if (!strcmp(*names, name))
                    groups[index++] = g->gr_gid;
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
    
    apr_sockaddr_info_get(&(*pod)->sa, "127.0.0.1", APR_UNSPEC, ap_listeners->bind_addr->port, 0, p);

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
    return rv;
}

AP_DECLARE(apr_status_t) ap_mpm_pod_signal(ap_pod_t *pod)
{
    apr_socket_t *sock;
    apr_status_t rv;
    char char_of_death = '!';
    apr_size_t one = 1;
    apr_pool_t *p;

    do {
        rv = apr_file_write(pod->pod_out, &char_of_death, &one);
    } while (APR_STATUS_IS_EINTR(rv));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "write pipe_of_death");
        return rv;
    }

    /* create a temporary pool for the socket.  pconf stays around too long */
    rv = apr_pool_create(&p, pod->p);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    rv = apr_socket_create(&sock, pod->sa->family, SOCK_STREAM, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "get socket to connect to listener");
        return rv;
    }
    /* on some platforms (e.g., FreeBSD), the kernel won't accept many
     * queued connections before it starts blocking local connects...
     * we need to keep from blocking too long and instead return an error,
     * because the MPM won't want to hold up a graceful restart for a
     * long time
     */
    rv = apr_setsocketopt(sock, APR_SO_TIMEOUT, 3 * APR_USEC_PER_SEC);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                     "set timeout on socket to connect to listener");
        return rv;
    }
    
    rv = apr_connect(sock, pod->sa);    
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
                     "connect to listener");
        return rv;
    }
    apr_socket_close(sock);
    apr_pool_destroy(p);

    return APR_SUCCESS;
}

void ap_mpm_pod_killpg(ap_pod_t *pod, int num)
{
    int i;
    apr_status_t rv = APR_SUCCESS;

    for (i = 0; i < num && rv == APR_SUCCESS; i++) {
        rv = ap_mpm_pod_signal(pod);
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
AP_DECLARE(const char *) ap_mpm_set_scoreboard(cmd_parms *cmd, void *dummy,
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
AP_DECLARE(const char *) ap_mpm_set_lockfile(cmd_parms *cmd, void *dummy,
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
const char *ap_mpm_set_coredumpdir(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    apr_finfo_t finfo;
    const char *fname;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    fname = ap_server_root_relative(cmd->pool, arg);
    if ((apr_stat(&finfo, fname, APR_FINFO_TYPE, cmd->pool) != APR_SUCCESS)
        || (finfo.filetype != APR_DIR)) {
	return apr_pstrcat(cmd->pool, "CoreDumpDirectory ", fname,
			   " does not exist or is not a directory", NULL);
    }
    apr_cpystrn(ap_coredump_dir, fname, sizeof(ap_coredump_dir));
    return NULL;
}
#endif

#ifdef AP_MPM_WANT_SET_ACCEPT_LOCK_MECH
apr_lockmech_e_np ap_accept_lock_mech = APR_LOCK_DEFAULT;
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
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(arg, "proc_pthread")) {
        ap_accept_lock_mech = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return apr_pstrcat(cmd->pool, arg, " is an invalid mutex mechanism; valid "
                           "ones for this platform and MPM are: default"
#if APR_HAS_FLOCK_SERIALIZE
                           ", flock"
#endif
#if APR_HAS_FCNTL_SERIALIZE
                           ", fcntl"
#endif
#if APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)
                           ", sysvsem"
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
                           ", proc_pthread"
#endif
                           , NULL);
    }
    return NULL;
}
#endif
