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
typedef enum
{
    bs2_unknown,     /* not initialized yet. */
    bs2_noFORK,      /* no fork() because -X flag was specified */
    bs2_FORK,        /* only fork() because uid != 0 */
    bs2_FORK_RINI,   /* prior to A17, regular fork() and _rini() was used. */
    bs2_RFORK_RINI,  /* for A17, use of _rfork() and _rini() was required */
    bs2_UFORK        /* As of A18, the new ufork() is used. */
} bs2_ForkType;

static bs2_ForkType forktype = bs2_unknown;


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

/* Determine the method for forking off a child in such a way as to
 * set both the POSIX and BS2000 user id's to the unprivileged user.
 */
static bs2_ForkType os_forktype(void)
{
    struct utsname os_version;

    /* have we checked the OS version before? If yes return the previous
     * result - the OS release isn't going to change suddenly!
     */
    if (forktype != bs2_unknown) {
	return forktype;
    }

    /* If the user is unprivileged, use the normal fork() only. */
    if (getuid() != 0) {
	return forktype = bs2_FORK;
    }

    if (uname(&os_version) < 0)
    {
	ap_log_error(APLOG_MARK, APLOG_ALERT, NULL,
		     "uname() failed - aborting.");
	exit(APEXIT_CHILDFATAL);
    }

    /*
     * Old BS2000/OSD versions (before XPG4 SPEC1170) don't work with Apache.
     * Anyway, simply return a fork().
     */
    if (strcmp(os_version.release, "01.0A") == 0 ||
	strcmp(os_version.release, "02.0A") == 0 ||
	strcmp(os_version.release, "02.1A") == 0)
    {
	ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, NULL,
		     "Error: unsupported OS version. "
		     "You may encounter problems.");
	forktype = bs2_FORK;
    }

    /* The following versions are special:
     * OS versions before A17 needs regular fork() and _rini().
     * A17 requires _rfork() and _rini(),
     * and later versions need ufork().
     */
    else if (strcmp(os_version.release, "01.1A") == 0 ||
	     strcmp(os_version.release, "03.0A") == 0 ||
	     strcmp(os_version.release, "03.1A") == 0 ||
	     strcmp(os_version.release, "04.0A") == 0)
    {
        if (strcmp (os_version.version, "A18") >= 0)
            forktype = bs2_UFORK;

	else if (strcmp (os_version.version, "A17") < 0)
            forktype = bs2_FORK_RINI;

	else
	    forktype = bs2_RFORK_RINI;
    }

    /* All later OS versions will hopefully use ufork() only  ;-) */
    else
        forktype = bs2_UFORK;

    return forktype;
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
    bs2_ForkType            type = os_forktype();

    /* We can be sure that no change to uid==0 is possible because of
     * the checks in http_core.c:set_user()
     */

    /* The _rini() function works only after a prior _rfork().
     * In the case of one_process, it would fail.
     */
    if (one_process) {

	type = forktype = bs2_noFORK;

	ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, server,
		     "The debug mode of Apache should only "
		     "be started by an unprivileged user!");
	return 0;
    }

    /* If no _rini() is required, then return quickly. */
    if (type != bs2_RFORK_RINI && type != bs2_FORK_RINI)
	return 0;

    /* An Account is required for _rini() */
    if (bs2000_account == NULL)
    {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server,
		     "No BS2000Account configured - cannot switch to User %s",
		     user_name);
	exit(APEXIT_CHILDFATAL);
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
    /* Only the super user can switch identities. */
    if (_rini(&inittask) != 0) {

	ap_log_error(APLOG_MARK, APLOG_ALERT, server,
		     "_rini: BS2000 auth failed for user \"%s\" acct \"%s\"",
		     inittask.username, inittask.account);

	exit(APEXIT_CHILDFATAL);
    }

    return 0;
}

/* BS2000 requires a "special" version of fork() before a setuid()/_rini() call */
pid_t os_fork(const char *user)
{
    pid_t pid;
    char  username[USER_LEN+1];

    switch (os_forktype()) {
      case bs2_FORK:
      case bs2_FORK_RINI:
	pid = fork();
	break;

      case bs2_RFORK_RINI:
	pid = _rfork();
	break;

      case bs2_UFORK:
	ap_cpystrn(username, user, sizeof username);

	/* Make user name all upper case - for some versions of ufork() */
	ap_str_toupper(username);

	pid = ufork(username);
	if (pid == -1 && errno == EPERM) {
	    ap_log_error(APLOG_MARK, APLOG_EMERG,
			 NULL, "ufork: Possible mis-configuration "
			 "for user %s - Aborting.", user);
	    exit(1);
	}
	break;

      default:
	pid = 0;
	break;
    }

    return pid;
}

#else /* _OSD_POSIX */
void bs2login_is_not_here()
{
}
#endif /* _OSD_POSIX */
