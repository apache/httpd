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

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "unixd.h"
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

unixd_config_rec unixd_config;

/* Set group privileges.
 *
 * Note that we use the username as set in the config files, rather than
 * the lookup of to uid --- the same uid may have multiple passwd entries,
 * with different sets of groups for each.
 */

static int set_group_privs(void)
{
    if (!geteuid()) {
	const char *name;

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


const char *unixd_set_user(cmd_parms *cmd, void *dummy, const char *arg)
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

const char *unixd_set_group(cmd_parms *cmd, void *dummy, const char *arg)
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

#define store_str(array,index,string) \
(ap_assert(index < (sizeof(array)/sizeof(array[0]))),array[index]=string)

void unixd_siglist_init(void)
{
    int sig;

    ap_sys_siglist[0] = "Signal 0";
#ifdef SIGHUP
    store_str(ap_sys_siglist,SIGHUP,"Hangup");
#endif
#ifdef SIGINT
    store_str(ap_sys_siglist,SIGINT,"Interrupt");
#endif
#ifdef SIGQUIT
    store_str(ap_sys_siglist,SIGQUIT,"Quit");
#endif
#ifdef SIGILL
    store_str(ap_sys_siglist,SIGILL,"Illegal instruction");
#endif
#ifdef SIGTRAP
    store_str(ap_sys_siglist,SIGTRAP,"Trace/BPT trap");
#endif
#ifdef SIGIOT
    store_str(ap_sys_siglist,SIGIOT,"IOT instruction");
#endif
#ifdef SIGABRT
    store_str(ap_sys_siglist,SIGABRT,"Abort");
#endif
#ifdef SIGEMT
    store_str(ap_sys_siglist,SIGEMT,"Emulator trap");
#endif
#ifdef SIGFPE
    store_str(ap_sys_siglist,SIGFPE,"Arithmetic exception");
#endif
#ifdef SIGKILL
    store_str(ap_sys_siglist,SIGKILL,"Killed");
#endif
#ifdef SIGBUS
    store_str(ap_sys_siglist,SIGBUS,"Bus error");
#endif
#ifdef SIGSEGV
    store_str(ap_sys_siglist,SIGSEGV,"Segmentation fault");
#endif
#ifdef SIGSYS
    store_str(ap_sys_siglist,SIGSYS,"Bad system call");
#endif
#ifdef SIGPIPE
    store_str(ap_sys_siglist,SIGPIPE,"Broken pipe");
#endif
#ifdef SIGALRM
    store_str(ap_sys_siglist,SIGALRM,"Alarm clock");
#endif
#ifdef SIGTERM
    store_str(ap_sys_siglist,SIGTERM,"Terminated");
#endif
#ifdef SIGUSR1
    store_str(ap_sys_siglist,SIGUSR1,"User defined signal 1");
#endif
#ifdef SIGUSR2
    store_str(ap_sys_siglist,SIGUSR2,"User defined signal 2");
#endif
#ifdef SIGCLD
    store_str(ap_sys_siglist,SIGCLD,"Child status change");
#endif
#ifdef SIGCHLD
    store_str(ap_sys_siglist,SIGCHLD,"Child status change");
#endif
#ifdef SIGPWR
    store_str(ap_sys_siglist,SIGPWR,"Power-fail restart");
#endif
#ifdef SIGWINCH
    store_str(ap_sys_siglist,SIGWINCH,"Window changed");
#endif
#ifdef SIGURG
    store_str(ap_sys_siglist,SIGURG,"urgent socket condition");
#endif
#ifdef SIGPOLL
    store_str(ap_sys_siglist,SIGPOLL,"Pollable event occurred");
#endif
#ifdef SIGIO
    store_str(ap_sys_siglist,SIGIO,"socket I/O possible");
#endif
#ifdef SIGSTOP
    store_str(ap_sys_siglist,SIGSTOP,"Stopped (signal)");
#endif
#ifdef SIGTSTP
    store_str(ap_sys_siglist,SIGTSTP,"Stopped");
#endif
#ifdef SIGCONT
    store_str(ap_sys_siglist,SIGCONT,"Continued");
#endif
#ifdef SIGTTIN
    store_str(ap_sys_siglist,SIGTTIN,"Stopped (tty input)");
#endif
#ifdef SIGTTOU
    store_str(ap_sys_siglist,SIGTTOU,"Stopped (tty output)");
#endif
#ifdef SIGVTALRM
    store_str(ap_sys_siglist,SIGVTALRM,"virtual timer expired");
#endif
#ifdef SIGPROF
    store_str(ap_sys_siglist,SIGPROF,"profiling timer expired");
#endif
#ifdef SIGXCPU
    store_str(ap_sys_siglist,SIGXCPU,"exceeded cpu limit");
#endif
#ifdef SIGXFSZ
    store_str(ap_sys_siglist,SIGXFSZ,"exceeded file size limit");
#endif
    for (sig=0; sig < sizeof(ap_sys_siglist)/sizeof(ap_sys_siglist[0]); ++sig)
        if (ap_sys_siglist[sig] == NULL)
            ap_sys_siglist[sig] = "";
}
#endif /* NEED_AP_SYS_SIGLIST */

#if defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC) || defined(RLIMIT_AS)
API_EXPORT(void) unixd_set_rlimit(cmd_parms *cmd, struct rlimit **plimit, 
                           const char *arg, const char * arg2, int type)
{
    char *str;
    struct rlimit *limit;
    /* If your platform doesn't define rlim_t then typedef it in ap_config.h */
    rlim_t cur = 0;
    rlim_t max = 0;

    *plimit = (struct rlimit *)apr_pcalloc(cmd->pool, sizeof(**plimit));
    limit = *plimit;
    if ((getrlimit(type, limit)) != 0)  {
        *plimit = NULL;
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, cmd->server,
                     "%s: getrlimit failed", cmd->cmd->name);
        return;
    }

    if ((str = ap_getword_conf(cmd->pool, &arg))) {
        if (!strcasecmp(str, "max")) {
            cur = limit->rlim_max;
        }
        else {
            cur = atol(str);
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, cmd->server,
                     "Invalid parameters for %s", cmd->cmd->name);
        return;
    }

    if (arg2 && (str = ap_getword_conf(cmd->pool, &arg2))) {
        max = atol(str);
    }

    /* if we aren't running as root, cannot increase max */
    if (geteuid()) {
        limit->rlim_cur = cur;
        if (max) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, cmd->server,
                         "Must be uid 0 to raise maximum %s", cmd->cmd->name);
        }
    }
    else {
        if (cur) {
            limit->rlim_cur = cur;
        }
        if (max) {
            limit->rlim_max = max;
        }
    }
}
#endif

