/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
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
#include "apr_lib.h"
#include "apr_portable.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"

#include <stdarg.h>

typedef struct {
	char	*t_name;
	int	t_val;
} TRANS;

#ifdef HAVE_SYSLOG

static const TRANS facilities[] = {
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

static const TRANS priorities[] = {
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

static int log_child(ap_context_t *p, const char *progname,
                     ap_file_t **fpout, ap_file_t **fpin,
                     ap_file_t **fperr)
{
    /* Child process code for 'ErrorLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    int rc = -1;
    ap_procattr_t *procattr;
    ap_proc_t *procnew;
    ap_os_proc_t fred;

    ap_block_alarms();
    ap_cleanup_for_exec();

#ifdef SIGHUP
    /* No concept of a child process on Win32 */
    signal(SIGHUP, SIG_IGN);
#endif /* ndef SIGHUP */

    if ((ap_createprocattr_init(&procattr, p)          != APR_SUCCESS) ||
        (ap_setprocattr_io(procattr,
                           fpin  ? 1 : 0,
                           fpout ? 1 : 0,
                           fperr ? 1 : 0)              != APR_SUCCESS) ||
        (ap_setprocattr_dir(procattr, progname)        != APR_SUCCESS)) {
        /* Something bad happened, give up and go away. */
        rc = -1;
    }
    else {
        rc = ap_create_process(&procnew, progname, NULL, NULL, procattr, p);
    
        if (rc == APR_SUCCESS) {
#ifndef WIN32
            /* pjr - this is a cheap hack for now to get the basics working in
             *       stages. ap_note_subprocess and free_proc need to be redone
             *       to make use of ap_proc_t instead of pid.
             */
            ap_get_os_proc(&fred, procnew);
            ap_note_subprocess(p, fred, kill_after_timeout);
#endif
            if (fpin) {
                ap_get_childin(fpin, procnew);
            }

            if (fpout) {
                ap_get_childout(fpout, procnew);
            }

            if (fperr) {
                ap_get_childerr(fperr, procnew);
            }
        }
    }

    ap_unblock_alarms();

    return(rc);
}

static void open_error_log(server_rec *s, ap_context_t *p)
{
    const char *fname;
    int rc;

    if (*s->error_fname == '|') {
	ap_file_t *dummy;

        /* This starts a new process... */
        rc = log_child (p, s->error_fname+1, NULL, &dummy, NULL);
        if (rc != APR_SUCCESS) {
	    perror("ap_spawn_child");
	    fprintf(stderr, "Couldn't fork child for ErrorLog process\n");
	    exit(1);
	}

        s->error_log = dummy;
    }

#ifdef HAVE_SYSLOG
    else if (!strncasecmp(s->error_fname, "syslog", 6)) {
	if ((fname = strchr(s->error_fname, ':'))) {
	    const TRANS *fac;

	    fname++;
	    for (fac = facilities; fac->t_name; fac++) {
		if (!strcasecmp(fname, fac->t_name)) {
		    openlog(ap_server_argv0, LOG_NDELAY|LOG_CONS|LOG_PID,
			    fac->t_val);
		    s->error_log = NULL;
		    return;
		}
	    }
	}
	else
	    openlog(ap_server_argv0, LOG_NDELAY|LOG_CONS|LOG_PID, LOG_LOCAL7);

	s->error_log = NULL;
    }
#endif
    else {
	fname = ap_server_root_relative(p, s->error_fname);
	/*  Change to AP funcs. */
        if (ap_open(&s->error_log, fname, APR_APPEND | 
                    APR_READ | APR_WRITE | APR_CREATE, APR_OS_DEFAULT, p) != APR_SUCCESS) {
            perror("fopen");
            fprintf(stderr, "%s: could not open error log file %s.\n",
		    ap_server_argv0, fname);
            exit(1);
	}
    }
}

void ap_open_logs(server_rec *s_main, ap_context_t *p)
{
    server_rec *virt, *q;
    int replace_stderr;
    int errfile;

    open_error_log(s_main, p);

    replace_stderr = 1;
    if (s_main->error_log) {
	/* replace stderr with this new log */
	fflush(stderr);
        ap_get_os_file(&errfile, s_main->error_log);
	if (dup2(errfile, STDERR_FILENO) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s_main,
		"unable to replace stderr with error_log");
	} else {
	    replace_stderr = 0;
	}
    }
    /* note that stderr may still need to be replaced with something
     * because it points to the old error log, or back to the tty
     * of the submitter.
     */
    if (replace_stderr && freopen("/dev/null", "w", stderr) == NULL) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s_main,
	    "unable to replace stderr with /dev/null");
    }

    for (virt = s_main->next; virt; virt = virt->next) {
	if (virt->error_fname) {
	    for (q=s_main; q != virt; q = q->next)
		if (q->error_fname != NULL &&
		    strcmp(q->error_fname, virt->error_fname) == 0)
		    break;
	    if (q == virt)
		open_error_log(virt, p);
	    else 
		virt->error_log = q->error_log;
	}
	else
	    virt->error_log = s_main->error_log;
    }
}

API_EXPORT(void) ap_error_log2stderr(server_rec *s) {
    int errfile;

    ap_get_os_file(&errfile, s->error_log);
    if (   s->error_log != NULL
        && errfile != STDERR_FILENO)
        dup2(errfile, STDERR_FILENO);
}

static void log_error_core(const char *file, int line, int level, 
                           ap_status_t status, const server_rec *s, 
                           const request_rec *r, const char *fmt, va_list args)
{
    char errstr[MAX_STRING_LEN + 1];    /* + 1 to have room for '\n' */
    size_t len;
    ap_file_t *logf = NULL;
    int errfileno = STDERR_FILENO;

    if (s == NULL) {
	/*
	 * If we are doing stderr logging (startup), don't log messages that are
	 * above the default server log level unless it is a startup/shutdown
	 * notice
	 */
	if (((level & APLOG_LEVELMASK) != APLOG_NOTICE) &&
	    ((level & APLOG_LEVELMASK) > DEFAULT_LOGLEVEL))
	    return;
	ap_put_os_file(&logf, &errfileno, NULL);
    }
    else if (s->error_log) {
	/*
	 * If we are doing normal logging, don't log messages that are
	 * above the server log level unless it is a startup/shutdown notice
	 */
	if (((level & APLOG_LEVELMASK) != APLOG_NOTICE) &&
	    ((level & APLOG_LEVELMASK) > s->loglevel))
	    return;
	logf = s->error_log;
    }
#ifdef TPF
    else if (tpf_child) {
    /*
     * If we are doing normal logging, don't log messages that are
     * above the server log level unless it is a startup/shutdown notice
     */
    if (((level & APLOG_LEVELMASK) != APLOG_NOTICE) &&
        ((level & APLOG_LEVELMASK) > s->loglevel))
        return;
    logf = stderr;
    }
#endif /* TPF */
    else {
	/*
	 * If we are doing syslog logging, don't log messages that are
	 * above the server log level (including a startup/shutdown notice)
	 */
	if ((level & APLOG_LEVELMASK) > s->loglevel)
	    return;
	logf = NULL;
    }

    if (logf) {
	len = ap_snprintf(errstr, MAX_STRING_LEN, "[%s] ", ap_get_time());
    } else {
	len = 0;
    }

    len += ap_snprintf(errstr + len, MAX_STRING_LEN - len,
	    "[%s] ", priorities[level & APLOG_LEVELMASK].t_name);

#ifndef TPF
    if (file && (level & APLOG_LEVELMASK) == APLOG_DEBUG) {
#ifdef _OSD_POSIX
	char tmp[256];
	char *e = strrchr(file, '/');

	/* In OSD/POSIX, the compiler returns for __FILE__
	 * a string like: __FILE__="*POSIX(/usr/include/stdio.h)"
	 * (it even returns an absolute path for sources in
	 * the current directory). Here we try to strip this
	 * down to the basename.
	 */
	if (e != NULL && e[1] != '\0') {
	    ap_snprintf(tmp, sizeof(tmp), "%s", &e[1]);
	    e = &tmp[strlen(tmp)-1];
	    if (*e == ')')
		*e = '\0';
	    file = tmp;
	}
#endif /*_OSD_POSIX*/
	len += ap_snprintf(errstr + len, MAX_STRING_LEN - len,
		"%s(%d): ", file, line);
    }
#endif /* TPF */
    if (r && r->connection) {
	/* XXX: TODO: add a method of selecting whether logged client
	 * addresses are in dotted quad or resolved form... dotted
	 * quad is the most secure, which is why I'm implementing it
	 * first. -djg
	 */
	len += ap_snprintf(errstr + len, MAX_STRING_LEN - len,
		"[client %s] ", r->connection->remote_ip);
    }
    if (!(level & APLOG_NOERRNO)
	&& (status != 0)
#ifdef WIN32
	&& !(level & APLOG_WIN32ERROR)
#endif
	) {
	len += ap_snprintf(errstr + len, MAX_STRING_LEN - len,
		"(%d)%s: ", status, strerror(status));
    }
#ifdef WIN32
    if (level & APLOG_WIN32ERROR) {
	int nChars;
	int nErrorCode;

	nErrorCode = GetLastError();
	len += ap_snprintf(errstr + len, MAX_STRING_LEN - len,
	    "(%d)", nErrorCode);

	nChars = FormatMessage( 
	    FORMAT_MESSAGE_FROM_SYSTEM,
	    NULL,
	    nErrorCode,
	    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* // Default language */
	    (LPTSTR) errstr + len,
	    MAX_STRING_LEN - len,
	    NULL 
	);
	len += nChars;
	if (nChars == 0) {
	    /* Um, error occurred, but we can't recurse to log it again
	     * (and it would probably only fail anyway), so lets just
	     * log the numeric value.
	     */
	    nErrorCode = GetLastError();
	    len += ap_snprintf(errstr + len, MAX_STRING_LEN - len,
			       "(FormatMessage failed with code %d): ",
			       nErrorCode);
	}
	else {
	    /* FormatMessage put the message in the buffer, but it may
	     * have appended a newline (\r\n). So remove it and use
	     * ": " instead like the Unix errors. The error may also
	     * end with a . before the return - if so, trash it.
	     */
	    if (len > 1 && errstr[len-2] == '\r' && errstr[len-1] == '\n') {
		if (len > 2 && errstr[len-3] == '.')
		    len--;
		errstr[len-2] = ':';
		errstr[len-1] = ' ';
	    }
	}
    }
#endif

    len += ap_vsnprintf(errstr + len, MAX_STRING_LEN - len, fmt, args);

    /* NULL if we are logging to syslog */
    if (logf) {
        /* We know that we have one more character of space available because
         * the array is sized that way */
        /* ap_assert(len < MAX_STRING_LEN) */
        errstr[len++] = '\n';
        errstr[len] = '\0';
	ap_puts(errstr, logf);
	ap_flush(logf);
    }
#ifdef HAVE_SYSLOG
    else {
	syslog(level & APLOG_LEVELMASK, "%s", errstr);
    }
#endif
}
    
API_EXPORT(void) ap_log_error(const char *file, int line, int level,
			      ap_status_t status, const server_rec *s, 
                              const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, level, status, s, NULL, fmt, args);
    va_end(args);
}

API_EXPORT(void) ap_log_rerror(const char *file, int line, int level,
			       ap_status_t status, const request_rec *r, 
                               const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, level, status, r->server, r, fmt, args);
    /*
     * IF the error level is 'warning' or more severe,
     * AND there isn't already error text associated with this request,
     * THEN make the message text available to ErrorDocument and
     * other error processors.  This can be disabled by stuffing
     * something, even an empty string, into the "error-notes" cell
     * before calling this routine.
     */
    va_end(args);
    va_start(args,fmt); 
    if (((level & APLOG_LEVELMASK) <= APLOG_WARNING)
	&& (ap_table_get(r->notes, "error-notes") == NULL)) {
	ap_table_setn(r->notes, "error-notes",
		      ap_pvsprintf(r->pool, fmt, args));
    }
    va_end(args);
}

void ap_log_pid(ap_context_t *p, const char *fname)
{
    ap_file_t *pid_file;
    struct stat finfo;
    static pid_t saved_pid = -1;
    pid_t mypid;

    if (!fname) 
	return;

    fname = ap_server_root_relative(p, fname);
    mypid = getpid();
    if (mypid != saved_pid && stat(fname, &finfo) == 0) {
      /* WINCH and HUP call this on each restart.
       * Only warn on first time through for this pid.
       *
       * XXX: Could just write first time through too, although
       *      that may screw up scripts written to do something
       *      based on the last modification time of the pid file.
       */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, NULL,
		     ap_psprintf(p,
                                 "pid file %s overwritten -- Unclean shutdown of previous Apache run?",
                     fname)
			       );
    }

    if(ap_open(&pid_file, fname, APR_WRITE | APR_CREATE, APR_OS_DEFAULT, p) != APR_SUCCESS) {
	perror("fopen");
        fprintf(stderr, "%s: could not log pid to file %s\n",
		ap_server_argv0, fname);
        exit(1);
    }
    ap_fprintf(pid_file, "%ld\n", (long)mypid);
    ap_close(pid_file);
    saved_pid = mypid;
}

API_EXPORT(void) ap_log_error_old(const char *err, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, "%s", err);
}

API_EXPORT(void) ap_log_unixerr(const char *routine, const char *file,
			      const char *msg, server_rec *s)
{
    ap_log_error(file, 0, APLOG_ERR, errno, s, "%s", msg);
}

API_EXPORT(void) ap_log_printf(const server_rec *s, const char *fmt, ...)
{
    va_list args;
    
    va_start(args, fmt);
    log_error_core(APLOG_MARK, APLOG_ERR, errno, s, NULL, fmt, args);
    va_end(args);
}

API_EXPORT(void) ap_log_reason(const char *reason, const char *file, request_rec *r) 
{
    ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
		"access to %s failed for %s, reason: %s",
		file,
		ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME),
		reason);
}

API_EXPORT(void) ap_log_assert(const char *szExp, const char *szFile, int nLine)
{
  /* Use AP funcs to output message and abort program.  */
    fprintf(stderr, "[%s] file %s, line %d, assertion \"%s\" failed\n",
	    ap_get_time(), szFile, nLine, szExp);
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
static void piped_log_maintenance(int reason, void *data, ap_wait_t status);

static int piped_log_spawn(piped_log *pl)
{
    int rc;
    ap_procattr_t *procattr;
    ap_os_proc_t pid;
    ap_proc_t *procnew;

    /* pjr - calls to block and unblock alarms weren't here before, was this */
    /*       an oversight or intentional?                                    */
/*  ap_block_alarms();   */

    ap_cleanup_for_exec();
#ifdef SIGHUP
    signal(SIGHUP, SIG_IGN);
#endif
    if ((ap_createprocattr_init(pl->p, &procattr)         != APR_SUCCESS) ||
        (ap_setprocattr_dir(procattr, pl->program)        != APR_SUCCESS) ||
        (ap_set_childin(procattr, pl->fds[0], pl->fds[1]) != APR_SUCCESS)) {
        /* Something bad happened, give up and go away. */
	fprintf(stderr,
	    "piped_log_spawn: unable to exec %s -c '%s': %s\n",
	    SHELL_PATH, pl->program, strerror (errno));
        rc = -1;
    }
    else {
        rc = ap_create_process(&procnew, pl->program, NULL, NULL, procattr, pl->p);
    
        if (rc == APR_SUCCESS) {            /* pjr - This no longer happens inside the child, */
            RAISE_SIGSTOP(PIPED_LOG_SPAWN); /*   I am assuming that if ap_create_process was  */
                                            /*   successful that the child is running.        */
            pl->pid = procnew;
            ap_get_os_proc(&pid, &procnew);
            ap_register_other_child(pid, piped_log_maintenance, pl, pl->fds[1]);
        }
    }
    
/*  ap_unblock_alarms(); */
    
    return 0;
}


static void piped_log_maintenance(int reason, void *data, ap_wait_t status)
{
    piped_log *pl = data;

    switch (reason) {
    case OC_REASON_DEATH:
    case OC_REASON_LOST:
	pl->pid = NULL;
	ap_unregister_other_child(pl);
	if (pl->program == NULL) {
	    /* during a restart */
	    break;
	}
	if (piped_log_spawn(pl) != APR_SUCCESS) {
	    /* what can we do?  This could be the error log we're having
	     * problems opening up... */
	    fprintf(stderr,
		"piped_log_maintenance: unable to respawn '%s': %s\n",
		pl->program, strerror(errno));
	}
	break;
    
    case OC_REASON_UNWRITABLE:
	if (pl->pid != NULL) {
	    ap_kill(pl->pid, SIGTERM);
	}
	break;
    
    case OC_REASON_RESTART:
	pl->program = NULL;
	if (pl->pid != NULL) {
	    ap_kill(pl->pid, SIGTERM);
	}
	break;

    case OC_REASON_UNREGISTER:
	break;
    }
}


static void piped_log_cleanup(void *data)
{
    piped_log *pl = data;

    if (pl->pid != NULL) {
	ap_kill(pl->pid, SIGTERM);
    }
    ap_unregister_other_child(pl);
    ap_close(pl->fds[0]);
    ap_close(pl->fds[1]);
}


static void piped_log_cleanup_for_exec(void *data)
{
    piped_log *pl = data;

    ap_close(pl->fds[0]);
    ap_close(pl->fds[1]);
}


API_EXPORT(piped_log *) ap_open_piped_log(ap_context_t *p, const char *program)
{
    piped_log *pl;

    pl = ap_palloc(p, sizeof (*pl));
    pl->p = p;
    pl->program = ap_pstrdup(p, program);
    pl->pid = NULL;
    if (ap_create_pipe(p, &pl->fds[0], &pl->fds[1]) != APR_SUCCESS) {
	int save_errno = errno;
	errno = save_errno;
	return NULL;
    }
    ap_register_cleanup(p, pl, piped_log_cleanup, piped_log_cleanup_for_exec);
    if (piped_log_spawn(pl) == -1) {
	int save_errno = errno;
	ap_kill_cleanup(p, pl, piped_log_cleanup);
	ap_close(pl->fds[0]);
	ap_close(pl->fds[1]);
	errno = save_errno;
	return NULL;
    }
    return pl;
}

API_EXPORT(void) ap_close_piped_log(piped_log *pl)
{
    piped_log_cleanup(pl);
    ap_kill_cleanup(pl->p, pl, piped_log_cleanup);
}

#else
API_EXPORT(piped_log *) ap_open_piped_log(ap_context_t *p, const char *program)
{
    piped_log *pl;
    ap_file_t *dummy;
    int rc;

    rc = log_child(p, program, NULL, &dummy, NULL);
    if (rc != APR_SUCCESS) {
	perror("ap_spawn_child");
	fprintf(stderr, "Couldn't fork child for piped log process\n");
	exit (1);
    }

    pl = ap_palloc(p, sizeof (*pl));
    pl->p = p;
    pl->write_f = dummy;

    return pl;
}


API_EXPORT(void) ap_close_piped_log(piped_log *pl)
{
    ap_close(pl->write_f);
}
#endif
