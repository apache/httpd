/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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


#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#include <stdarg.h>

#ifdef HAVE_SYSLOG
#include <syslog.h>

static TRANS facilities[] = {
    {"auth",	LOG_AUTH},
#ifdef LOG_AUTHPRIV
    {"authpriv",LOG_AUTHPRIV},
#endif
    {"cron", 	LOG_CRON},
    {"daemon",	LOG_DAEMON},
#ifdef LOG_FTP
    {"ftp",	LOG_FTP},
#endif
    {"kern",	LOG_KERN},
    {"lpr",	LOG_LPR},
    {"mail",	LOG_MAIL},
    {"news",	LOG_NEWS},
    {"syslog",	LOG_SYSLOG},
    {"user",	LOG_USER},
    {"uucp",	LOG_UUCP},
    {"local0",	LOG_LOCAL0},
    {"local1",	LOG_LOCAL1},
    {"local2",	LOG_LOCAL2},
    {"local3",	LOG_LOCAL3},
    {"local4",	LOG_LOCAL4},
    {"local5",	LOG_LOCAL5},
    {"local6",	LOG_LOCAL6},
    {"local7",	LOG_LOCAL7},
    {NULL,		-1},
};
#endif

static TRANS priorities[] = {
    {"emerg",	APLOG_EMERG},
    {"alert",	APLOG_ALERT},
    {"crit",	APLOG_CRIT},
    {"error",	APLOG_ERR},
    {"warn",	APLOG_WARNING},
    {"notice",	APLOG_NOTICE},
    {"info",	APLOG_INFO},
    {"debug",	APLOG_DEBUG},
    {NULL,	-1},
};

static int error_log_child (void *cmd)
{
    /* Child process code for 'ErrorLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    int child_pid = 0;

    cleanup_for_exec();
#ifdef SIGHUP
    /* No concept of a child process on Win32 */
    signal (SIGHUP, SIG_IGN);
#endif /* ndef SIGHUP */
#if defined(WIN32)
    child_pid = spawnl (_P_NOWAIT, SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
    return(child_pid);
#elif defined(__EMX__)
    /* For OS/2 we need to use a '/' */
    execl (SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
#else    
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
#endif    
    exit (1);
    return(child_pid);
}

void open_error_log (server_rec *s, pool *p)
{
    char *fname;
#ifdef HAVE_SYSLOG
    register TRANS *fac;
#endif


    if (*s->error_fname == '|') {
	FILE *dummy;

	if (!spawn_child (p, error_log_child, (void *)(s->error_fname+1),
			  kill_after_timeout, &dummy, NULL)) {
	    perror ("spawn_child");
	    fprintf (stderr, "Couldn't fork child for ErrorLog process\n");
	    exit (1);
	}

	s->error_log = dummy;
    }
#ifdef HAVE_SYSLOG
    else if (!strncasecmp(s->error_fname, "syslog", 6)) {
	if ((fname = strchr(s->error_fname, ':'))) {
	    fname++;
	    for (fac = facilities; fac->t_name; fac++) {
		if (!strcasecmp(fname, fac->t_name)) {
		    openlog("httpd", LOG_NDELAY|LOG_CONS|LOG_PID, fac->t_val);
		    s->error_log = NULL;
		    return;
		}
	    }
	}
	else
	    openlog("httpd", LOG_NDELAY|LOG_CONS|LOG_PID, LOG_LOCAL7);

	s->error_log = NULL;
    }
#endif
    else {
	fname = server_root_relative (p, s->error_fname);
        if(!(s->error_log = pfopen(p, fname, "a"))) {
            perror("fopen");
            fprintf(stderr,"httpd: could not open error log file %s.\n", fname);
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

API_EXPORT(void) error_log2stderr (server_rec *s) {
    if(fileno(s->error_log) != STDERR_FILENO)
        dup2(fileno(s->error_log),STDERR_FILENO);
}

API_EXPORT(void) aplog_error (const char *file, int line, int level,
			      const server_rec *s, const char *fmt, ...)
{
    va_list args;
    char errstr[MAX_STRING_LEN];
    static TRANS *pname = priorities;
    

    if (level > s->loglevel)
	return;

    switch (s->loglevel) {
    case APLOG_DEBUG:
	ap_snprintf(errstr, sizeof(errstr), "[%s] %d: %s: %s: %d: ",
		    pname[level].t_name, errno, strerror(errno), file, line);
	break;
    case APLOG_EMERG:
    case APLOG_CRIT:
    case APLOG_ALERT:
	ap_snprintf(errstr, sizeof(errstr), "[%s] %d: %s: ",
		    pname[level].t_name, errno, strerror(errno));
	break;
    case APLOG_INFO:
    case APLOG_ERR:
    case APLOG_WARNING:
    case APLOG_NOTICE:
	ap_snprintf(errstr, sizeof(errstr), "[%s] ", pname[level].t_name);
	break;
    }
	
    va_start(args, fmt);

    /* NULL if we are logging to syslog */
    if (s->error_log) {
	fprintf(s->error_log, "[%s] %s", get_time(), errstr);
	vfprintf(s->error_log, fmt, args);
	fprintf(s->error_log, "\n");
	fflush(s->error_log);
    }
#ifdef HAVE_SYSLOG
    else {
	vsprintf(errstr + strlen(errstr), fmt, args);
	syslog(level, "%s", errstr);
    }
#endif
    
    va_end(args);
}

void log_pid (pool *p, char *pid_fname)
{
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

API_EXPORT(void) log_error (const char *err, server_rec *s)
{
    aplog_error(APLOG_MARK, APLOG_ERR, s, err);
}

API_EXPORT(void) log_unixerr (const char *routine, const char *file,
			      const char *msg, server_rec *s)
{
    aplog_error(file, 0, APLOG_ERR, s, msg);
}

API_EXPORT(void) log_printf (const server_rec *s, const char *fmt, ...)
{
    char buf[MAX_STRING_LEN];
    va_list args;
    
    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    aplog_error(APLOG_MARK, APLOG_ERR, s, buf);
    va_end(args);
}

API_EXPORT(void) log_reason (const char *reason, const char *file, request_rec *r) 
{
    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
		"access to %s failed for %s, reason: %s",
		file,
		get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME),
		reason);
}

API_EXPORT(void) log_assert (const char *szExp, const char *szFile, int nLine)
{
    fprintf(stderr, "[%s] file %s, line %d, assertion \"%s\" failed\n",
	    get_time(), szFile, nLine, szExp);
#ifndef WIN32
    /* unix assert does an abort leading to a core dump */
    abort();
#else
    exit(1);
#endif
}
