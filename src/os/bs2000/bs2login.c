/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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

static const char *bs2000_authfile = NULL;


/* This routine is called by http_core for the BS2000AuthFile directive */
/* It stores the file name (after a quick check for validity) for later use */
const char *os_set_authfile(pool *p, const char *name)
{
    struct stat stbuf;
    char *filename;

    filename = ap_server_root_relative(p, name);

    /* auth file must exist */
    if (stat(filename, &stbuf) != 0) {
	return ap_pstrcat(p, "Unable to access bs2000 auth file ",
		       filename, NULL);
	exit(APEXIT_CHILDFATAL);
    }

    /* auth file must be owned by root, and not readable/writable by everyone else */
    if (stbuf.st_uid != 0) {
	return ap_pstrcat(p, "BS2000 auth file ", filename,
		       " is not owned by SYSROOT - "
		       "change owner!", NULL);
    }

    if (stbuf.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
	return ap_pstrcat(p, "BS2000 auth file ", filename,
		       " is readable/writable by others - "
		       "check permissions!", NULL);
    }

    bs2000_authfile = filename;
    return NULL;
}

int os_init_job_environment(server_rec *server, const char *user_name)
{
    _checkuser_struct       chk_usr;
    _rini_struct            inittask; 
    struct {
	char username[8+1];     /* Length of a user name including \0 */
	char password[8+1];     /* Length of a password including \0 */
	char account [8+1];     /* Length of a account number including \0 */
	char exp_date[10+1];    /* Length of a date including \0 */
	char exp_pass[10+1];    /* Length of a date including \0 */
	char processor[8+1];
    } lcl_data;
    char *cp;
    FILE *pwfile;
    struct stat stbuf;

    memset (&lcl_data, '\0', sizeof lcl_data);

    /* BS2000 requires the user name to be in upper case for authentication */
    ap_snprintf(lcl_data.username, sizeof lcl_data.username,
		"%s", user_name);
    for (cp = lcl_data.username; *cp; ++cp) {
	*cp = ap_toupper(*cp);
    }

    if (bs2000_authfile == NULL) {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server,
		     "Use the 'BS2000AuthFile <passwdfile>' directive to specify "
		     "an authorization file for User %s",
		     user_name);
	exit(APEXIT_CHILDFATAL);
    }

    if ((pwfile = fopen(bs2000_authfile, "r")) == NULL) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, server,
		     "Unable to open bs2000 auth file %s for User %s",
		     bs2000_authfile, user_name);
	exit(APEXIT_CHILDFATAL);
    }

    if (fgets(lcl_data.password, sizeof lcl_data.password, pwfile) == NULL
	|| strlen(lcl_data.password) == 0) {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server,
		     "Unable ro read BS2000 auth file %s",
		     bs2000_authfile);
	exit(APEXIT_CHILDFATAL);
    }

    fclose(pwfile);

    chk_usr.username      = lcl_data.username;
    chk_usr.password      = lcl_data.password;
    chk_usr.account       = lcl_data.account; /* Account and Expiration go here*/
    chk_usr.logon_expdate = lcl_data.exp_date;
    chk_usr.pw_expdate    = lcl_data.exp_pass;

    /* Now perform validity check of user and password, filling in account */
    if(_checkuser(&chk_usr) != 0) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, server,
		     "_checkuser: BS2000 auth failed for user %s", chk_usr.username);
	exit(APEXIT_CHILDFATAL);
    }

    inittask.username = chk_usr.username;
    inittask.account  = chk_usr.account;
    inittask.processor_name = strncpy(lcl_data.processor,
				      "        ",
				      sizeof lcl_data.processor);

    /* And switch to the new logon user (setuid() and setgid() are done later) */
    if (_rini(&inittask) != 0) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, server,
		     "_rini: BS2000 auth failed for user %s",
		     inittask.username);
	exit(APEXIT_CHILDFATAL);
    }

    /*ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, server,
		     "BS2000 logon for user %s account=%s completed, pid=%d.",
		     inittask.username, inittask.account, getpid());*/

    /* Don't leave the password on the stack */
    memset (&lcl_data, '\0', sizeof lcl_data);

    return 0;
}

#else /* _OSD_POSIX */
void bs2login_is_not_here()
{
}
#endif /* _OSD_POSIX */
