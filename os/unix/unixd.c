/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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

#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "unixd.h"

unixd_config_rec unixd_config;

void unixd_detach(void)
{
    int x;
    pid_t pgrp;

    chdir("/");
#if !defined(MPE) && !defined(OS2) && !defined(TPF)
/* Don't detach for MPE because child processes can't survive the death of
   the parent. */
    if ((x = fork()) > 0)
	exit(0);
    else if (x == -1) {
	perror("fork");
	fprintf(stderr, "%s: unable to fork new process\n", ap_server_argv0);
	exit(1);
    }
    RAISE_SIGSTOP(DETACH);
#endif
#ifndef NO_SETSID
    if ((pgrp = setsid()) == -1) {
	perror("setsid");
	fprintf(stderr, "%s: setsid failed\n", ap_server_argv0);
	exit(1);
    }
#elif defined(NEXT) || defined(NEWSOS)
    if (setpgrp(0, getpid()) == -1 || (pgrp = getpgrp(0)) == -1) {
	perror("setpgrp");
	fprintf(stderr, "%s: setpgrp or getpgrp failed\n", ap_server_argv0);
	exit(1);
    }
#elif defined(OS2) || defined(TPF)
    /* OS/2 and TPF don't support process group IDs */
    pgrp = getpid();
#elif defined(MPE)
    /* MPE uses negative pid for process group */
    pgrp = -getpid();
#else
    if ((pgrp = setpgrp(getpid(), 0)) == -1) {
	perror("setpgrp");
	fprintf(stderr, "%s: setpgrp failed\n", ap_server_argv0);
	exit(1);
    }
#endif

    /* close out the standard file descriptors */
    if (freopen("/dev/null", "r", stdin) == NULL) {
	fprintf(stderr, "%s: unable to replace stdin with /dev/null: %s\n",
		ap_server_argv0, strerror(errno));
	/* continue anyhow -- note we can't close out descriptor 0 because we
	 * have nothing to replace it with, and if we didn't have a descriptor
	 * 0 the next file would be created with that value ... leading to
	 * havoc.
	 */
    }
    if (freopen("/dev/null", "w", stdout) == NULL) {
	fprintf(stderr, "%s: unable to replace stdout with /dev/null: %s\n",
		ap_server_argv0, strerror(errno));
    }
    /* stderr is a tricky one, we really want it to be the error_log,
     * but we haven't opened that yet.  So leave it alone for now and it'll
     * be reopened moments later.
     */
}

/* Set group privileges.
 *
 * Note that we use the username as set in the config files, rather than
 * the lookup of to uid --- the same uid may have multiple passwd entries,
 * with different sets of groups for each.
 */

static int set_group_privs(void)
{
    if (!geteuid()) {
	char *name;

	/* Get username if passed as a uid */

	if (unixd_config.user_name[0] == '#') {
	    struct passwd *ent;
	    uid_t uid = atoi(&unixd_config.user_name[1]);

	    if ((ent = getpwuid(uid)) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			 "getpwuid: couldn't determine user name from uid %u, "
			 "you probably need to modify the User directive",
			 (unsigned)uid);
		return -1;
	    }

	    name = ent->pw_name;
	}
	else
	    name = unixd_config.user_name;

#if !defined(OS2) && !defined(TPF)
	/* OS/2 and TPF don't support groups. */

	/*
	 * Set the GID before initgroups(), since on some platforms
	 * setgid() is known to zap the group list.
	 */
	if (setgid(unixd_config.group_id) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"setgid: unable to set group id to Group %u",
			(unsigned)unixd_config.group_id);
	    return -1;
	}

	/* Reset `groups' attributes. */

	if (initgroups(name, unixd_config.group_id) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"initgroups: unable to set groups for User %s "
			"and Group %u", name, (unsigned)unixd_config.group_id);
	    return -1;
	}
#endif /* !defined(OS2) && !defined(TPF) */
    }
    return 0;
}


int unixd_setup_child(void)
{
    if (set_group_privs()) {
	return -1;
    }
#ifdef MPE
    /* Only try to switch if we're running as MANAGER.SYS */
    if (geteuid() == 1 && unixd_config.user_id > 1) {
	GETPRIVMODE();
	if (setuid(unixd_config.user_id) == -1) {
	    GETUSERMODE();
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"setuid: unable to change to uid: %ld",
                        (long) unixd_config.user_id);
	    exit(1);
	}
	GETUSERMODE();
    }
#else
    /* Only try to switch if we're running as root */
    if (!geteuid() && (
#ifdef _OSD_POSIX
	os_init_job_environment(server_conf, unixd_config.user_name, one_process) != 0 || 
#endif
	setuid(unixd_config.user_id) == -1)) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "setuid: unable to change to uid: %ld",
                    (long) unixd_config.user_id);
	return -1;
    }
#endif
    return 0;
}


const char *unixd_set_user(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    unixd_config.user_name = arg;
    unixd_config.user_id = ap_uname2id(arg);
#if !defined (BIG_SECURITY_HOLE) && !defined (OS2)
    if (unixd_config.user_id == 0) {
	return "Error:\tApache has not been designed to serve pages while\n"
		"\trunning as root.  There are known race conditions that\n"
		"\twill allow any local user to read any file on the system.\n"
		"\tIf you still desire to serve pages as root then\n"
		"\tadd -DBIG_SECURITY_HOLE to the EXTRA_CFLAGS line in your\n"
		"\tsrc/Configuration file and rebuild the server.  It is\n"
		"\tstrongly suggested that you instead modify the User\n"
		"\tdirective in your httpd.conf file to list a non-root\n"
		"\tuser.\n";
    }
#endif

    return NULL;
}

const char *unixd_set_group(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    unixd_config.group_id = ap_gname2id(arg);

    return NULL;
}

void unixd_pre_config(void)
{
    unixd_config.user_name = DEFAULT_USER;
    unixd_config.user_id = ap_uname2id(DEFAULT_USER);
    unixd_config.group_id = ap_gname2id(DEFAULT_GROUP);
}

#ifdef NEED_AP_SYS_SIGLIST

const char *ap_sys_siglist[NumSIG];

void unixd_siglist_init(void)
{
    int sig;

    ap_sys_siglist[0] = "Signal 0";
#ifdef SIGHUP
    ap_sys_siglist[SIGHUP] = "Hangup";
#endif
#ifdef SIGINT
    ap_sys_siglist[SIGINT] = "Interrupt";
#endif
#ifdef SIGQUIT
    ap_sys_siglist[SIGQUIT] = "Quit";
#endif
#ifdef SIGILL
    ap_sys_siglist[SIGILL] = "Illegal instruction";
#endif
#ifdef SIGTRAP
    ap_sys_siglist[SIGTRAP] = "Trace/BPT trap";
#endif
#ifdef SIGIOT
    ap_sys_siglist[SIGIOT] = "IOT instruction";
#endif
#ifdef SIGABRT
    ap_sys_siglist[SIGABRT] = "Abort";
#endif
#ifdef SIGEMT
    ap_sys_siglist[SIGEMT] = "Emulator trap";
#endif
#ifdef SIGFPE
    ap_sys_siglist[SIGFPE] = "Arithmetic exception";
#endif
#ifdef SIGKILL
    ap_sys_siglist[SIGKILL] = "Killed";
#endif
#ifdef SIGBUS
    ap_sys_siglist[SIGBUS] = "Bus error";
#endif
#ifdef SIGSEGV
    ap_sys_siglist[SIGSEGV] = "Segmentation fault";
#endif
#ifdef SIGSYS
    ap_sys_siglist[SIGSYS] = "Bad system call";
#endif
#ifdef SIGPIPE
    ap_sys_siglist[SIGPIPE] = "Broken pipe";
#endif
#ifdef SIGALRM
    ap_sys_siglist[SIGALRM] = "Alarm clock";
#endif
#ifdef SIGTERM
    ap_sys_siglist[SIGTERM] = "Terminated";
#endif
#ifdef SIGUSR1
    ap_sys_siglist[SIGUSR1] = "User defined signal 1";
#endif
#ifdef SIGUSR2
    ap_sys_siglist[SIGUSR2] = "User defined signal 2";
#endif
#ifdef SIGCLD
    ap_sys_siglist[SIGCLD] = "Child status change";
#endif
#ifdef SIGCHLD
    ap_sys_siglist[SIGCHLD] = "Child status change";
#endif
#ifdef SIGPWR
    ap_sys_siglist[SIGPWR] = "Power-fail restart";
#endif
#ifdef SIGWINCH
    ap_sys_siglist[SIGWINCH] = "Window changed";
#endif
#ifdef SIGURG
    ap_sys_siglist[SIGURG] = "urgent socket condition";
#endif
#ifdef SIGPOLL
    ap_sys_siglist[SIGPOLL] = "Pollable event occurred";
#endif
#ifdef SIGIO
    ap_sys_siglist[SIGIO] = "socket I/O possible";
#endif
#ifdef SIGSTOP
    ap_sys_siglist[SIGSTOP] = "Stopped (signal)";
#endif
#ifdef SIGTSTP
    ap_sys_siglist[SIGTSTP] = "Stopped";
#endif
#ifdef SIGCONT
    ap_sys_siglist[SIGCONT] = "Continued";
#endif
#ifdef SIGTTIN
    ap_sys_siglist[SIGTTIN] = "Stopped (tty input)";
#endif
#ifdef SIGTTOU
    ap_sys_siglist[SIGTTOU] = "Stopped (tty output)";
#endif
#ifdef SIGVTALRM
    ap_sys_siglist[SIGVTALRM] = "virtual timer expired";
#endif
#ifdef SIGPROF
    ap_sys_siglist[SIGPROF] = "profiling timer expired";
#endif
#ifdef SIGXCPU
    ap_sys_siglist[SIGXCPU] = "exceeded cpu limit";
#endif
#ifdef SIGXFSZ
    ap_sys_siglist[SIGXFSZ] = "exceeded file size limit";
#endif
    for (sig=0; sig < sizeof(ap_sys_siglist)/sizeof(ap_sys_siglist[0]); ++sig)
        if (ap_sys_siglist[sig] == NULL)
            ap_sys_siglist[sig] = "";
}
#endif /* NEED_AP_SYS_SIGLIST */
 
