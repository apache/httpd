
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
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


/*
 * http_log.c: Dealing with the logs and errors
 * 
 * Rob McCool
 * 
 */


#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#include <stdarg.h>

void error_log_child (void *cmd)
{
    /* Child process code for 'ErrorLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    
    cleanup_for_exec();
    signal (SIGHUP, SIG_IGN);
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
    exit (1);
}

void open_error_log(server_rec *s, pool *p)
{
    char *fname;
  
    fname = server_root_relative (p, s->error_fname);

    if (*fname == '|') {
      FILE *dummy;

      spawn_child(p, error_log_child, (void *)(fname+1),
                    kill_after_timeout, &dummy, NULL);

        if (dummy == NULL) {
            fprintf (stderr, "Couldn't fork child for ErrorLog process\n");
            exit (1);
      }
    } else {
        if(!(s->error_log = pfopen(p, fname, "a"))) {
            fprintf(stderr,"httpd: could not open error log file %s.\n", fname);
            perror("fopen");
            exit(1);
      }
    }
}

void open_logs (server_rec *s_main, pool *p)
{
    server_rec *virt, *q;

    open_error_log (s_main, p);

    for (virt = s_main->next; virt; virt = virt->next) {
	if (virt->error_fname)
	{
	    for (q=s_main; q != virt; q = q->next)
		if (q->error_fname != NULL &&
		    strcmp(q->error_fname, virt->error_fname) == 0)
		    break;
	    if (q == virt) open_error_log (virt, p);
	    else virt->error_log = q->error_log;
	}
	else
	    virt->error_log = s_main->error_log;
    }
}

void error_log2stderr(server_rec *s) {
    if(fileno(s->error_log) != STDERR_FILENO)
        dup2(fileno(s->error_log),STDERR_FILENO);
}

void log_pid(pool *p, char *pid_fname) {
    FILE *pid_file;

    if (!pid_fname) return;
    pid_fname = server_root_relative (p, pid_fname);
    if(!(pid_file = fopen(pid_fname,"w"))) {
	perror("fopen");
        fprintf(stderr,"httpd: could not log pid to file %s\n", pid_fname);
        exit(1);
    }
    fprintf(pid_file,"%ld\n",(long)getpid());
    fclose(pid_file);
}

void log_error(char *err, server_rec *s) {
    fprintf(s->error_log, "[%s] %s\n",get_time(),err);
    fflush(s->error_log);
}

void
log_unixerr(const char *routine, const char *file, const char *msg,
	    server_rec *s)
{
    const char *p, *q;

    p = strerror(errno);
    q = get_time();

    if (file != NULL)
	fprintf(s->error_log, "[%s] %s: %s: %s\n", q, routine, file, p);
    else
	fprintf(s->error_log, "[%s] %s: %s\n", q, routine, p);
    if (msg != NULL) fprintf(s->error_log, "[%s] - %s\n", q, msg);

    fflush(s->error_log);
}

void
log_printf(const server_rec *s, const char *fmt, ...)
{
    va_list args;
    
    fprintf(s->error_log, "[%s] ", get_time());
    va_start (args, fmt);
    vfprintf (s->error_log, fmt, args);
    va_end (args);

    fputc('\n', s->error_log);
    fflush(s->error_log);
}

void log_reason(char *reason, char *file, request_rec *r) {
    fprintf (r->server->error_log,
	     "[%s] access to %s failed for %s, reason: %s\n",
	     get_time(), file,
	     get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME),
	     reason);
    fflush (r->server->error_log);
}

