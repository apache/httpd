/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 * http_log.c: Dealing with the logs and errors
 * 
 * Rob McCool
 * 
 */


#define CORE_PRIVATE
#include "httpd.h"
#include "http_conf_globals.h"
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

static int error_log_child(void *cmd, child_info *pinfo)
{
    /* Child process code for 'ErrorLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    int child_pid = 0;
#if defined(WIN32)
    char *shellcmd;
#endif

    ap_cleanup_for_exec();
#ifdef SIGHUP
    /* No concept of a child process on Win32 */
    signal(SIGHUP, SIG_IGN);
#endif /* ndef SIGHUP */
#if defined(NETWARE)
    child_pid = spawnlp(P_NOWAIT, SHELL_PATH, (char *)cmd);
    return(child_pid);
#elif defined(WIN32)
    shellcmd = getenv("COMSPEC");
    if (!shellcmd)
        shellcmd = SHELL_PATH;
    child_pid = spawnl(_P_NOWAIT, shellcmd, shellcmd, "/c", (char *)cmd, NULL);
    return(child_pid);
#elif defined(OS2)
    /* For OS/2 we need to use a '/' and spawn the child rather than exec as
     * we haven't forked */
    child_pid = spawnl(P_NOWAIT, SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
    return(child_pid);
#else    
    execl(SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
#endif    
    exit(1);
    /* NOT REACHED */
    return(child_pid);
}

static void open_error_log(server_rec *s, pool *p)
{
    char *fname;

    if (*s->error_fname == '|') {
	FILE *dummy;
#ifdef TPF
        TPF_FORK_CHILD cld;
        cld.filename = s->error_fname+1;
        cld.subprocess_env = NULL;
        cld.prog_type = FORK_NAME;
        if (!ap_spawn_child(p, NULL, &cld,
                            kill_after_timeout, &dummy, NULL, NULL)) {
#else
	if (!ap_spawn_child(p, error_log_child, (void *)(s->error_fname+1),
			    kill_after_timeout, &dummy, NULL, NULL)) {
#endif /* TPF */
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
        if (!(s->error_log = ap_pfopen(p, fname, "a"))) {
            perror("fopen");
            fprintf(stderr, "%s: could not open error log file %s.\n",
		    ap_server_argv0, fname);
            exit(1);
	}
    }
}

API_EXPORT(void) ap_open_logs(server_rec *s_main, pool *p)
{
    server_rec *virt, *q;
    int replace_stderr;

#ifdef OS390
    /*
     * Cause errno2 (reason code) information to be generated whenever
     * strerror(errno) is invoked.
     */
    setenv("_EDC_ADD_ERRNO2", "1", 1);
#endif

    open_error_log(s_main, p);

    replace_stderr = 1;
    if (s_main->error_log) {
	/* replace stderr with this new log */
	fflush(stderr);
	if (dup2(fileno(s_main->error_log), STDERR_FILENO) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_CRIT, s_main,
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
	ap_log_error(APLOG_MARK, APLOG_CRIT, s_main,
	    "unable to replace stderr with /dev/null");
    }

    for (virt = s_main->next; virt; virt = virt->next) {
	if (virt->error_fname)
	{
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
    if (   s->error_log != NULL
        && fileno(s->error_log) != STDERR_FILENO)
        dup2(fileno(s->error_log), STDERR_FILENO);
}

static void log_error_core(const char *file, int line, int level,
			   const server_rec *s, const request_rec *r,
			   const char *fmt, va_list args)
{
    char errstr[MAX_STRING_LEN], scratch[MAX_STRING_LEN];
    size_t len;
    int save_errno = errno;
    FILE *logf;

    if (s == NULL) {
	/*
	 * If we are doing stderr logging (startup), don't log messages that are
	 * above the default server log level unless it is a startup/shutdown
	 * notice
	 */
	if (((level & APLOG_LEVELMASK) != APLOG_NOTICE) &&
	    ((level & APLOG_LEVELMASK) > DEFAULT_LOGLEVEL))
	    return;
	logf = stderr;
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
	len = ap_snprintf(errstr, sizeof(errstr), "[%s] ", ap_get_time());
    } else {
	len = 0;
    }

    len += ap_snprintf(errstr + len, sizeof(errstr) - len,
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
	len += ap_snprintf(errstr + len, sizeof(errstr) - len,
		"%s(%d): ", file, line);
    }
#endif /* TPF */
    if (r) {
	/* XXX: TODO: add a method of selecting whether logged client
	 * addresses are in dotted quad or resolved form... dotted
	 * quad is the most secure, which is why I'm implementing it
	 * first. -djg
	 */
	len += ap_snprintf(errstr + len, sizeof(errstr) - len,
		"[client %s] ", r->connection->remote_ip);
    }
    if (!(level & APLOG_NOERRNO)
	&& (save_errno != 0)
#ifdef WIN32
	&& !(level & APLOG_WIN32ERROR)
#endif
	) {
	len += ap_snprintf(errstr + len, sizeof(errstr) - len,
		"(%d)%s: ", save_errno, strerror(save_errno));
    }
#ifdef WIN32
    if (level & APLOG_WIN32ERROR) {
	int nChars;
	int nErrorCode;

	nErrorCode = GetLastError();
	len += ap_snprintf(errstr + len, sizeof(errstr) - len,
	    "(%d)", nErrorCode);

	nChars = FormatMessage( 
	    FORMAT_MESSAGE_FROM_SYSTEM,
	    NULL,
	    nErrorCode,
	    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
	    (LPTSTR) errstr + len,
	    sizeof(errstr) - len,
	    NULL 
	);
	len += nChars;
	if (nChars == 0) {
	    /* Um, error occurred, but we can't recurse to log it again
	     * (and it would probably only fail anyway), so lets just
	     * log the numeric value.
	     */
	    nErrorCode = GetLastError();
	    len += ap_snprintf(errstr + len, sizeof(errstr) - len,
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

    if (ap_vsnprintf(scratch, sizeof(scratch) - len, fmt, args)) {
        len += ap_escape_errorlog_item(errstr + len, scratch,
                                       sizeof(errstr) - len);
    }

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
    
API_EXPORT_NONSTD(void) ap_log_error(const char *file, int line, int level,
			      const server_rec *s, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, level, s, NULL, fmt, args);
    va_end(args);
}

API_EXPORT_NONSTD(void) ap_log_rerror(const char *file, int line, int level,
			       const request_rec *r, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_error_core(file, line, level, r->server, r, fmt, args);
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
		      ap_escape_html(r->pool, ap_pvsprintf(r->pool, fmt, 
		      args)));
    }
    va_end(args);
}

API_EXPORT(void) ap_log_pid(pool *p, char *fname)
{
    FILE *pid_file;
    struct stat finfo;
    static pid_t saved_pid = -1;
    pid_t mypid;
#ifndef WIN32
    mode_t u;
#endif

    if (!fname) 
	return;

    fname = ap_server_root_relative(p, fname);
    mypid = getpid();
    if (mypid != saved_pid && stat(fname, &finfo) == 0) {
      /* USR1 and HUP call this on each restart.
       * Only warn on first time through for this pid.
       *
       * XXX: Could just write first time through too, although
       *      that may screw up scripts written to do something
       *      based on the last modification time of the pid file.
       */
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, NULL,
		   ap_psprintf(p,
			       "pid file %s overwritten -- Unclean shutdown of previous Apache run?",
			       fname)
		   );
    }

#ifndef WIN32
    u = umask(022);
    (void) umask(u | 022);
#endif
    if(!(pid_file = fopen(fname, "w"))) {
	perror("fopen");
        fprintf(stderr, "%s: could not log pid to file %s\n",
		ap_server_argv0, fname);
        exit(1);
    }
#ifndef WIN32
    (void) umask(u);
#endif
    fprintf(pid_file, "%ld\n", (long)mypid);
    fclose(pid_file);
    saved_pid = mypid;
}

API_EXPORT(void) ap_log_error_old(const char *err, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, s, "%s", err);
}

API_EXPORT(void) ap_log_unixerr(const char *routine, const char *file,
			      const char *msg, server_rec *s)
{
    ap_log_error(file, 0, APLOG_ERR, s, "%s", msg);
}

API_EXPORT_NONSTD(void) ap_log_printf(const server_rec *s, const char *fmt, ...)
{
    va_list args;
    
    va_start(args, fmt);
    log_error_core(APLOG_MARK, APLOG_ERR, s, NULL, fmt, args);
    va_end(args);
}

API_EXPORT(void) ap_log_reason(const char *reason, const char *file, request_rec *r) 
{
    ap_log_error(APLOG_MARK, APLOG_ERR, r->server,
		"access to %s failed for %s, reason: %s",
		file,
		ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME),
		reason);
}

API_EXPORT(void) ap_log_assert(const char *szExp, const char *szFile, int nLine)
{
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

#ifndef NO_PIPED_LOGS
#ifndef NO_RELIABLE_PIPED_LOGS
/* forward declaration */
static void piped_log_maintenance(int reason, void *data, ap_wait_t status);

static int piped_log_spawn(piped_log *pl)
{
    int pid;

    ap_block_alarms();
    pid = fork();
    if (pid == 0) {
	/* XXX: this needs porting to OS2 and WIN32 */
	/* XXX: need to check what open fds the logger is actually passed,
	 * XXX: and CGIs for that matter ... cleanup_for_exec *should*
	 * XXX: close all the relevant stuff, but hey, it could be broken. */
	RAISE_SIGSTOP(PIPED_LOG_SPAWN);
	/* we're now in the child */
	close(STDIN_FILENO);
	dup2(pl->fds[0], STDIN_FILENO);

	ap_cleanup_for_exec();
	signal(SIGCHLD, SIG_DFL);	/* for HPUX */
	signal(SIGHUP, SIG_IGN);
	execl(SHELL_PATH, SHELL_PATH, "-c", pl->program, NULL);
	fprintf(stderr,
	    "piped_log_spawn: unable to exec %s -c '%s': %s\n",
	    SHELL_PATH, pl->program, strerror (errno));
	exit(1);
    }
    if (pid == -1) {
	fprintf(stderr,
	    "piped_log_spawn: unable to fork(): %s\n", strerror (errno));
	ap_unblock_alarms();
	return -1;
    }
    ap_unblock_alarms();
    pl->pid = pid;
    ap_register_other_child(pid, piped_log_maintenance, pl, pl->fds[1]);
    return 0;
}


static void piped_log_maintenance(int reason, void *data, ap_wait_t status)
{
    piped_log *pl = data;

    switch (reason) {
    case OC_REASON_DEATH:
    case OC_REASON_LOST:
	pl->pid = -1;
	ap_unregister_other_child(pl);
	if (pl->program == NULL) {
	    /* during a restart */
	    break;
	}
	if (piped_log_spawn(pl) == -1) {
	    /* what can we do?  This could be the error log we're having
	     * problems opening up... */
	    fprintf(stderr,
		"piped_log_maintenance: unable to respawn '%s': %s\n",
		pl->program, strerror(errno));
	}
	break;
    
    case OC_REASON_UNWRITABLE:
        /* We should not kill off the pipe here, since it may only be full.
         * If it really is locked, we should kill it off manually. */
	break;
    
    case OC_REASON_RESTART:
	pl->program = NULL;
	if (pl->pid != -1) {
	    kill(pl->pid, SIGTERM);
	}
	break;

    case OC_REASON_UNREGISTER:
	break;
    }
}


static void piped_log_cleanup(void *data)
{
    piped_log *pl = data;

    if (pl->pid != -1) {
	kill(pl->pid, SIGTERM);
    }
    ap_unregister_other_child(pl);
    close(pl->fds[0]);
    close(pl->fds[1]);
}


static void piped_log_cleanup_for_exec(void *data)
{
    piped_log *pl = data;

    close(pl->fds[0]);
    close(pl->fds[1]);
}

static int piped_log_magic_cleanup(void *data)
{
    piped_log *pl = data;

    /* Yes, I _do_ mean a binary and */
    return ap_close_fd_on_exec(pl->fds[0]) & ap_close_fd_on_exec(pl->fds[1]);
}

API_EXPORT(piped_log *) ap_open_piped_log(pool *p, const char *program)
{
    piped_log *pl;

    pl = ap_palloc(p, sizeof (*pl));
    pl->p = p;
    pl->program = ap_pstrdup(p, program);
    pl->pid = -1;
    ap_block_alarms ();
    if (pipe(pl->fds) == -1) {
	int save_errno = errno;
	ap_unblock_alarms();
	errno = save_errno;
	return NULL;
    }
    ap_register_cleanup_ex(p, pl, piped_log_cleanup, piped_log_cleanup_for_exec,
			 piped_log_magic_cleanup);
    if (piped_log_spawn(pl) == -1) {
	int save_errno = errno;
	ap_kill_cleanup(p, pl, piped_log_cleanup);
	close(pl->fds[0]);
	close(pl->fds[1]);
	ap_unblock_alarms();
	errno = save_errno;
	return NULL;
    }
    ap_unblock_alarms();
    return pl;
}

API_EXPORT(void) ap_close_piped_log(piped_log *pl)
{
    ap_block_alarms();
    piped_log_cleanup(pl);
    ap_kill_cleanup(pl->p, pl, piped_log_cleanup);
    ap_unblock_alarms();
}

#else
static int piped_log_child(void *cmd, child_info *pinfo)
{
    /* Child process code for 'TransferLog "|..."';
     * may want a common framework for this, since I expect it will
     * be common for other foo-loggers to want this sort of thing...
     */
    int child_pid = 1;
#if defined(WIN32)
    char *shellcmd;
#endif

    ap_cleanup_for_exec();
#ifdef SIGHUP
    signal(SIGHUP, SIG_IGN);
#endif
#if defined(NETWARE)
    child_pid = spawnlp(P_NOWAIT, SHELL_PATH, (char *)cmd);
    return(child_pid);
#elif defined(WIN32)
    shellcmd = getenv("COMSPEC");
    if (!shellcmd)
        shellcmd = SHELL_PATH;
    child_pid = spawnl(_P_NOWAIT, shellcmd, shellcmd, "/c", (char *)cmd, NULL);
    return(child_pid);
#elif defined(OS2)
    /* For OS/2 we need to use a '/' and spawn the child rather than exec as
     * we haven't forked */
    child_pid = spawnl(P_NOWAIT, SHELL_PATH, SHELL_PATH, "/c", (char *)cmd, NULL);
    return(child_pid);
#else
    execl (SHELL_PATH, SHELL_PATH, "-c", (char *)cmd, NULL);
#endif
    perror("exec");
    fprintf(stderr, "Exec of shell for logging failed!!!\n");
    return(child_pid);
}


API_EXPORT(piped_log *) ap_open_piped_log(pool *p, const char *program)
{
    piped_log *pl;
    FILE *dummy;
    if (!ap_spawn_child(p, piped_log_child, (void *)program,
			kill_after_timeout, &dummy, NULL, NULL)) {
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
    ap_pfclose(pl->p, pl->write_f);
}
#endif
#endif
