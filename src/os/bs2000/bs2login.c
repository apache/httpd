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

#ifdef _OSD_POSIX
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include <ctype.h>
#include <sys/utsname.h>

#define ACCT_LEN 8
#define USER_LEN 8

static const char *bs2000_account = NULL;


static void ap_pad(char *dest, size_t size, char ch)
{
    int i = strlen(dest); /* Leave space for trailing '\0' */
    
    while (i < size-1)
	dest[i++] = ch;

    dest[size-1] = '\0';	/* Guarantee for trailing '\0' */
}

static void ap_str_toupper(char *str)
{
    while (*str) {
	*str = ap_toupper(*str);
	++str;
    }
}

/* This routine is called by http_core for the BS2000Account directive */
/* It stores the account name for later use */
const char *os_set_account(pool *p, const char *account)
{
    char account_temp[ACCT_LEN+1];

    ap_cpystrn(account_temp, account, sizeof account_temp);

    /* Make account all upper case */
    ap_str_toupper(account_temp);

    /* Pad to length 8 */
    ap_pad(account_temp, sizeof account_temp, ' ');

    bs2000_account = ap_pstrdup(p, account_temp);
    return NULL;
}

/* This routine complements the setuid() call: it causes the BS2000 job
 * environment to be switched to the target user's user id.
 * That is important if CGI scripts try to execute native BS2000 commands.
 */
int os_init_job_environment(server_rec *server, const char *user_name, int one_process)
{
    _rini_struct            inittask; 
    char                    username[USER_LEN+1];
    int                     save_errno;

    /* We can be sure that no change to uid==0 is possible because of
     * the checks in http_core.c:set_user()
     */

    /* The _rini() function works only after a prior _rfork().
     * In the case of one_process, it would fail.
     */
    /* An Account is required for _rini() */
    if (bs2000_account == NULL)
    {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server,
		     "No BS2000Account configured - cannot switch to User %s",
		     user_name);
	exit(APEXIT_CHILDFATAL);
    }

    /* The one_process test is placed _behind_ the BS2000Account test
     * because we never want the user to forget configuring an account.
     */
    if (one_process) {
	ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, server,
		     "The debug mode of Apache should only "
		     "be started by an unprivileged user!");
	return 0;
    }

    ap_cpystrn(username, user_name, sizeof username);

    /* Make user name all upper case */
    ap_str_toupper(username);

    /* Pad to length 8 */
    ap_pad(username, sizeof username, ' ');

    inittask.username       = username;
    inittask.account        = bs2000_account;
    inittask.processor_name = "        ";

    /* Switch to the new logon user (setuid() and setgid() are done later) */
    /* Only the super use can switch identities. */
    if (_rini(&inittask) != 0) {
	save_errno = errno;

	ap_log_error(APLOG_MARK, APLOG_ALERT, server,
		     "_rini: BS2000 auth failed for user \"%s\" acct \"%s\"",
		     inittask.username, inittask.account);

	if (save_errno == EAGAIN) {
	    /* This funny error code does NOT mean that the operation should
	     * be retried. Instead it means that authentication failed
	     * because of possibly incompatible `JOBCLASS'es between
	     * the calling (SYSROOT) and the target non-privileged user id.
	     * Help the administrator by logging a hint.
	     */
	    char *curr_user, curr_uid[L_cuserid];

	    if ((curr_user = cuserid(curr_uid)) == NULL) {
		/* This *SHOULD* not occur. But if it does, deal with it. */
		ap_snprintf(curr_uid, sizeof curr_uid, "#%u", getuid());
		curr_user = curr_uid;
	    }

	    ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server,
		     "_rini: Hint: Possible reason: JOBCLASS of user %s "
		     "not compatible with that of user %s ?",
		     curr_user, inittask.username);
	}
	exit(APEXIT_CHILDFATAL);
    }

    return 0;
}

/* BS2000 requires a "special" version of fork() before a setuid()/_rini() call */
/* Additionally, there's an OS release dependency here :-((( */
/* I'm sorry, but there was no other way to make it work.  -Martin */
pid_t os_fork(void)
{
    struct utsname os_version;

    /*
     * When we run as a normal user (and bypass setuid() and _rini()),
     * we use the regular fork().
     */
    if (getuid() != 0) {
	return fork();
    }

    if (uname(&os_version) >= 0)
    {
	/*
	 * Old versions (before XPG4 SPEC1170) don't work with Apache
	 * and they require a fork(), not a _rfork()
	 */
	if (strcmp(os_version.release, "01.0A") == 0 ||
	    strcmp(os_version.release, "02.0A") == 0 ||
	    strcmp(os_version.release, "02.1A") == 0)
	{
	    return fork();
	}

	/* The following versions are special:
	 * OS versions before A17 work with regular fork() only,
	 * later versions with _rfork() only.
	 */
	if (strcmp(os_version.release, "01.1A") == 0 ||
	    strcmp(os_version.release, "03.0A") == 0 ||
	    strcmp(os_version.release, "03.1A") == 0 ||
	    strcmp(os_version.release, "04.0A") == 0)
	{
		return (strcmp (os_version.version, "A17") < 0)
			? fork() : _rfork();
	}
    }

    /* All later OS versions will require _rfork()
     * to prepare for authorization with _rini()
     */
    return _rfork();
}

#else /* _OSD_POSIX */
void bs2login_is_not_here()
{
}
#endif /* _OSD_POSIX */
