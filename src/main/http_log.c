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
#include "http_main.h"

#include <stdarg.h>


#ifdef HAVE_SYSLOG
#include <syslog.h>

static TRANS facilities[] = {
    {"auth",	LOG_AUTH},
#ifdef LOG_AUTHPRIV
    {"authpriv",LOG_AUTHPRIV},
#endif
#ifdef LOG_CRON
    {"cron", 	LOG_CRON},
#endif
#ifdef LOG_DAEMON
    {"daemon",	LOG_DAEMON},
#endif
#ifdef LOG_FTP
    {"ftp",	LOG_FTP},
#endif
#ifdef LOG_KERN
    {"kern",	LOG_KERN},
#endif
#ifdef LOG_LPR
    {"lpr",	LOG_LPR},
#endif
#ifdef LOG_MAIL
    {"mail",	LOG_MAIL},
#endif
#ifdef LOG_NEWS
    {"news",	LOG_NEWS},
#endif
#ifdef LOG_SYSLOG
    {"syslog",	LOG_SYSLOG},
#endif
#ifdef LOG_USER
    {"user",	LOG_USER},
#endif
#ifdef LOG_UUCP
    {"uucp",	LOG_UUCP},
#endif
#ifdef LOG_LOCAL0
    {"local0",	LOG_LOCAL0},
#endif
#ifdef LOG_LOCAL1
    {"local1",	LOG_LOCAL1},
#endif
#ifdef LOG_LOCAL2
    {"local2",	LOG_LOCAL2},
#endif
#ifdef LOG_LOCAL3
    {"local3",	LOG_LOCAL3},
#endif
#ifdef LOG_LOCAL4
    {"local4",	LOG_LOCAL4},
#endif
#ifdef LOG_LOCAL5
    {"local5",	LOG_LOCAL5},
#endif
#ifdef LOG_LOCAL6
    {"local6",	LOG_LOCAL6},
#endif
#ifdef LOG_LOCAL7
    {"local7",	LOG_LOCAL7},
#endif
    {NULL,		-1},
};
#endif

static TRANS priorities[] = {
    {"notice",	APLOG_NOTICE},
    {"emerg",	APLOG_EMERG},
    {"alert",	APLOG_ALERT},
    {"crit",	APLOG_CRIT},
    {"error",	APLOG_ERR},
    {"warn",	APLOG_WARNING},
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
#ifndef WIN32
    int replace_stderr;
#endif

    open_error_log (s_main, p);

#ifndef WIN32
    replace_stderr = 1;
    if (s_main->error_log) {
	/* replace stderr with this new log */
	fflush(stderr);
	if (dup2(fileno(s_main->error_log), 2) == -1) {
	    aplog_error(APLOG_MARK, APLOG_CRIT, s_main,
		"unable to replace stderr with error_log: %s",
		strerror(errno));
	} else {
	    replace_stderr = 0;
	}
    }
    /* note that stderr may still need to be replaced with something
     * because it points to the old error log, or back to the tty
     * of the submitter.
     */
    if (replace_stderr && freopen("/dev/null", "w", stderr) == NULL) {
	aplog_error(APLOG_MARK, APLOG_CRIT, s_main,
	    "unable to replace stderr with /dev/null: %s",
	    strerror(errno));
    }
#endif

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
    size_t len;
    int save_errno = errno;
    FILE *logf;

    if (s && (level & APLOG_LEVELMASK) > s->loglevel)
	return;

    if (!s) {
	logf = stderr;
    } else if (s && s->error_log) {
	logf = s->error_log;
    } else {
	logf = NULL;
    }

    if (logf) {
	len = ap_snprintf(errstr, sizeof(errstr), "[%s] ", get_time());
    } else {
	len = 0;
    }

    len += ap_snprintf(errstr + len, sizeof(errstr) - len,
	    "[%s] ", pname[level & APLOG_LEVELMASK].t_name);

    if (!(level & APLOG_NOERRNO)) {
	len += ap_snprintf(errstr + len, sizeof(errstr) - len,
		"%d: %s: ", save_errno, strerror(save_errno));
    }
    if (file && (level & APLOG_LEVELMASK) == APLOG_DEBUG) {
	len += ap_snprintf(errstr + len, sizeof(errstr) - len,
		"%s: %d: ", file, line);
    }

    va_start(args, fmt);
    len += ap_vsnprintf(errstr + len, sizeof(errstr) - len, fmt, args);
    va_end(args);

    /* NULL if we are logging to syslog */
    if (logf) {
	fputs(errstr, logf);
	fputc('\n', logf);
	fflush(logf);
    }
#ifdef HAVE_SYSLOG
    else {
	syslog(level & APLOG_LEVELMASK, "%s", errstr);
    }
#endif
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

/* piped log support */

#ifndef NO_RELIABLE_PIPED_LOGS
/* forward declaration */
static void piped_log_maintenance (int reason, void *data, int status);

static int piped_log_spawn (piped_log *pl)
{
    int pid;

    block_alarms();
    pid = fork();
    if (pid == 0) {
	/* XXX: this needs porting to OS2 and WIN32 */
	/* XXX: need to check what open fds the logger is actually passed,
	 * XXX: and CGIs for that matter ... cleanup_for_exec *should*
	 * XXX: close all the relevant stuff, but hey, it could be broken. */
	/* we're now in the child */
	close (STDIN_FILENO);
	dup2 (pl->fds[0], STDIN_FILENO);

	cleanup_for_exec ();
	signal (SIGCHLD, SIG_DFL);	/* for HPUX */
	signal (SIGHUP, SIG_IGN);
	execl (SHELL_PATH, SHELL_PATH, "-c", pl->program, NULL);
	fprintf (stderr,
	    "piped_log_spawn: unable to exec %s -c '%s': %s\n",
	    SHELL_PATH, pl->program, strerror (errno));
	exit (1);
    }
    if (pid == -1) {
	fprintf (stderr,
	    "piped_log_spawn: unable to fork(): %s\n", strerror (errno));
	unblock_alarms ();
	return -1;
    }
    unblock_alarms();
    pl->pid = pid;
    register_other_child (pid, piped_log_maintenance, pl, pl->fds[1]);
    return 0;
}


static void piped_log_maintenance (int reason, void *data, int status)
{
    piped_log *pl = data;

    switch (reason) {
    case OC_REASON_DEATH:
    case OC_REASON_LOST:
	pl->pid = -1;
	unregister_other_child (pl);
	if (pl->program == NULL) {
	    /* during a restart */
	    break;
	}
	if (piped_log_spawn (pl) == -1) {
	    /* what can we do?  This could be the error log we're having
	     * problems opening up... */
	    fprintf (stderr,
		"piped_log_maintenance: unable to respawn '%s': %s\n",
		pl->program, strerror (errno));
	}
	break;
    
    case OC_REASON_UNWRITABLE:
	if (pl->pid != -1) {
	    kill (pl->pid, SIGTERM);
	}
	break;
    
    case OC_REASON_RESTART:
	pl->program = NULL;
	if (pl->pid != -1) {
	    kill (pl->pid, SIGTERM);
	}
	break;

    case OC_REASON_UNREGISTER:
	break;
    }
}


static void piped_log_cleanup (void *data)
{
    piped_log *pl = data;

    if (pl->pid != -1) {
	kill (pl->pid, SIGTERM);
    }
    unregister_other_child (pl);
    close (pl->fds[0]);
    close (pl->fds[1]);
}


static void piped_log_cleanup_for_exec (void *data)
{
    piped_log *pl = data;

    close (pl->fds[0]);
    close (pl->fds[1]);
}


API_EXPORT(piped_log *) open_piped_log (pool *p, const char *program)
{
    piped_log *pl;

    pl = palloc (p, sizeof (*pl));
    pl->p = p;
    pl->program = pstrdup (p, program);
    pl->pid = -1;
    block_alarms ();
    if (pipe (pl->fds) == -1) {
	int save_errno = errno;
	unblock_alarms();
	errno = save_errno;
	return NULL;
    }
    register_cleanup (p, pl, piped_log_cleanup, piped_log_cleanup_for_exec);
    if (piped_log_spawn (pl) == -1) {
	int save_errno = errno;
	kill_cleanup (p, pl, piped_log_cleanup);
	close (pl->fds[0]);
	close (pl->fds[1]);
	unblock_alarms ();
	errno = save_errno;
	return NULL;
    }
    unblock_alarms ();
    return pl;
}

API_EXPORT(void) close_piped_log (piped_log *pl)
{
    block_alarms ();
    piped_log_cleanup (pl);
    kill_cleanup (pl->p, pl, piped_log_cleanup);
    unblock_alarms ();
}

#else
static int piped_log_child (void *cmd)
{
    /* Child process code for 'TransferLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    int child_pid = 1;

    cleanup_for_exec();
#ifdef SIGHUP
    signal (SIGHUP, SIG_IGN);
#endif
#if defined(WIN32)
    child_pid = spawnl (_P_NOWAIT, SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
    return(child_pid);
#elif defined(__EMX__)
    /* For OS/2 we need to use a '/' */
    execl (SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
#else
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
#endif
    perror ("exec");
    fprintf (stderr, "Exec of shell for logging failed!!!\n");
    return(child_pid);
}


API_EXPORT(piped_log *) open_piped_log (pool *p, const char *program)
{
    piped_log *pl;
    FILE *dummy;
    
    if (!spawn_child (p, piped_log_child, (void *)program,
		kill_after_timeout, &dummy, NULL)) {
	perror ("spawn_child");
	fprintf (stderr, "Couldn't fork child for piped log process\n");
	exit (1);
    }
    pl = palloc (p, sizeof (*pl));
    pl->p = p;
    pl->write_f = dummy;
    return pl;
}


API_EXPORT(void) close_piped_log (piped_log *pl)
{
    pfclose (pl->p, pl->write_f);
}
#endif
