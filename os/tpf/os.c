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

/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "httpd.h"
#include "http_core.h"
#include "os.h"
#include "scoreboard.h"
#include "http_log.h"

static FILE *sock_fp;

#ifndef __PIPE_
int pipe(int fildes[2])
{
    errno = ENOSYS;
    return(-1);
}
#endif
  
/* fork and exec functions are not defined on
   TPF due to the implementation of tpf_fork() */
 
pid_t fork(void)
{
    errno = ENOSYS;
    return(-1);
}

int execl(const char *path, const char *arg0, ...)
{
    errno = ENOSYS;
    return(-1);
}

int execle(const char *path, const char *arg0, ...)
{
    errno = ENOSYS;
    return(-1);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    errno = ENOSYS;
    return(-1);
}

int execvp(const char *file, char *const argv[])
{
    errno = ENOSYS;
    return(-1);
}


pid_t os_fork(server_rec *s, int slot)
{
    struct tpf_fork_input fork_input;
    APACHE_TPF_INPUT input_parms;
    int count;
    listen_rec *lr;

    fflush(stdin);
    if (dup2(fileno(sock_fp), STDIN_FILENO) == -1)
        ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s,
        "unable to replace stdin with sock device driver");
    fflush(stdout);
    if (dup2(fileno(sock_fp), STDOUT_FILENO) == -1)
        ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s,
        "unable to replace stdout with sock device driver");
    input_parms.generation = ap_my_generation;
    input_parms.scoreboard_heap = ap_scoreboard_image;

    lr = ap_listeners;
    count = 0;
    do {
        input_parms.listeners[count] = lr->fd;
        lr = lr->next;
        count++;
    } while(lr != ap_listeners);

    input_parms.slot = slot;
    input_parms.restart_time = ap_restart_time;
    fork_input.ebw_data = &input_parms;
    fork_input.program = ap_server_argv0;
    fork_input.prog_type = TPF_FORK_NAME;
    fork_input.istream = TPF_FORK_IS_BALANCE;
    fork_input.ebw_data_length = sizeof(input_parms);
    fork_input.parm_data = "-x";
    return tpf_fork(&fork_input);
}

int os_check_server(char *server) {
#ifndef USE_TPF_DAEMON
    int rv;
    int *current_acn;
    if((rv = inetd_getServerStatus(server)) == INETD_SERVER_STATUS_INACTIVE)
        return 1;
    else {
        current_acn = (int *)cinfc_fast(CINFC_CMMACNUM);
        if(ecbp2()->ce2acn != *current_acn)
            return 1;
    }
#endif
    return 0;
}

AP_DECLARE(apr_status_t) ap_os_create_privileged_process(
    const request_rec *r,
    apr_proc_t *newproc, const char *progname,
    const char * const *args,
    const char * const *env,
    apr_procattr_t *attr, apr_pool_t *p)
{
    return apr_proc_create(newproc, progname, args, env, attr, p);
}
