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

#ifdef DEXTER_MPM
#define CHILD_INFO_TABLE     ap_child_table
#elif defined(MPMT_PTHREAD_MPM) || defined (PREFORK_MPM)
#define CHILD_INFO_TABLE     ap_scoreboard_image->parent
#endif 


void ap_reclaim_child_processes(int terminate)
{
    int i, status;
    long int waittime = 1024 * 16;      /* in usecs */
    struct timeval tv;
    int waitret, tries;
    int not_dead_yet;

#ifndef DEXTER_MPM
    ap_sync_scoreboard_image();
#endif

    for (tries = terminate ? 4 : 1; tries <= 9; ++tries) {
        /* don't want to hold up progress any more than
         * necessary, but we need to allow children a few moments to exit.
         * Set delay with an exponential backoff.
         */
        tv.tv_sec = waittime / 1000000;
        tv.tv_usec = waittime % 1000000;
        waittime = waittime * 4;
        ap_select(0, NULL, NULL, NULL, &tv);

        /* now see who is done */
        not_dead_yet = 0;
        for (i = 0; i < ap_max_daemons_limit; ++i) {
            int pid = CHILD_INFO_TABLE[i].pid;

#ifdef DEXTER_MPM
            if (ap_child_table[i].status == SERVER_DEAD)
#elif defined(MPMT_PTHREAD_MPM) || defined (PREFORK_MPM)
            if (pid == ap_my_pid || pid == 0)
#endif
                continue;

            waitret = waitpid(pid, &status, WNOHANG);
            if (waitret == pid || waitret == -1) {
#ifdef DEXTER_MPM
                ap_child_table[i].status = SERVER_DEAD;
#elif defined(MPMT_PTHREAD_MPM) || defined(PREFORK_MPM)
                ap_scoreboard_image->parent[i].pid = 0;
#endif
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
                   "child process %d still did not exit, sending a SIGTERM",
                            pid);
                kill(pid, SIGTERM);
                break;
            case 8:     /*  6 sec */
                /* die child scum */
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, ap_server_conf,
                   "child process %d still did not exit, sending a SIGKILL",
                            pid);
                kill(pid, SIGKILL);
                break;
            case 9:     /* 14 sec */
                /* gave it our best shot, but alas...  If this really
                 * is a child we are trying to kill and it really hasn't
                 * exited, we will likely fail to bind to the port
                 * after the restart.
                 */
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, ap_server_conf,
                            "could not make child process %d exit, "
                            "attempting to continue anyway", pid);
                break;
            }
        }
        ap_check_other_child();
        if (!not_dead_yet) {
            /* nothing left to wait for */
            break;
        }
    }
}


