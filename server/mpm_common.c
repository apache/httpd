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

#include "apr_thread_proc.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "mpm.h"
#include "mpm_common.h"

#if HAVE_SYS_TIME_H
#include <sys/time.h> /* for timeval definitions */
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h> /* for setsockopt prototype */
#endif

#ifdef MPM_NEEDS_RECLAIM_CHILD_PROCESSES
void ap_reclaim_child_processes(int terminate)
{
    int i;
    long int waittime = 1024 * 16;      /* in usecs */
    apr_status_t waitret;
    int tries;
    int not_dead_yet;
    int max_daemons = ap_get_max_daemons();

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
            waitret = apr_wait_proc(&proc, APR_NOWAIT);
            if (waitret != APR_CHILD_NOTDONE) {
                MPM_NOTE_CHILD_KILLED(i);
                continue;
            }
            ++not_dead_yet;
            switch (tries) {
            case 1:     /*  16ms */
            case 2:     /*  82ms */
                break;
            case 3:     /* 344ms */
            case 4:     /*  16ms */
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
        apr_check_other_child();
        if (!not_dead_yet) {
            /* nothing left to wait for */
            break;
        }
    }
}
#endif /* NEED_RECLAIM_CHILD_PROCESSES */

/* number of calls to wait_or_timeout between writable probes */
#ifndef INTERVAL_OF_WRITABLE_PROBES
#define INTERVAL_OF_WRITABLE_PROBES 10
#endif
static int wait_or_timeout_counter;

void ap_wait_or_timeout(ap_wait_t *status, apr_proc_t *ret, apr_pool_t *p)
{
    apr_status_t rv;

    ++wait_or_timeout_counter;
    if (wait_or_timeout_counter == INTERVAL_OF_WRITABLE_PROBES) {
        wait_or_timeout_counter = 0;
#if APR_HAS_OTHER_CHILD
        apr_probe_writable_fds();
#endif
    }
    rv = apr_wait_all_procs(ret, status, APR_NOWAIT, p);
    if (apr_canonical_error(rv) == APR_EINTR) {
        ret->pid = -1;
        return;
    }
    if (rv == APR_CHILD_DONE) {
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

void ap_process_child_status(apr_proc_t *pid, ap_wait_t status)
{
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
        switch (WTERMSIG(status)) {
        case SIGTERM:
        case SIGHUP:
        case SIGUSR1:
        case SIGKILL:
            break;
        default:
#ifdef SYS_SIGLIST
#ifdef WCOREDUMP
            if (WCOREDUMP(status)) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, ap_server_conf,
                             "child pid %ld exit signal %s (%d), "
                             "possible coredump in %s",
                             (long)pid->pid, (WTERMSIG(status) >= NumSIG) ? "" :
                             SYS_SIGLIST[WTERMSIG(status)], WTERMSIG(status),
                             ap_coredump_dir);
            }
            else {
#endif
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, ap_server_conf,
                             "child pid %ld exit signal %s (%d)",
                             (long)pid->pid,
                             SYS_SIGLIST[WTERMSIG(status)], WTERMSIG(status));
#ifdef WCOREDUMP
            }
#endif
#else
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                         0, ap_server_conf,
                         "child pid %ld exit signal %d",
                         (long)pid->pid, WTERMSIG(status));
#endif
        }
    }
}

#if defined(TCP_NODELAY) && !defined(MPE) && !defined(TPF)
void ap_sock_disable_nagle(int s)
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
                   sizeof(int)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf,
                    "setsockopt: (TCP_NODELAY)");
    }
}
#endif
