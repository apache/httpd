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

static const char *bs2000_account = NULL;


/* This routine is called by http_core for the BS2000Account directive */
/* It stores the account name for later use */
const char *os_set_account(pool *p, const char *account)
{
    if (bs2000_account != NULL && strcasecmp(bs2000_account, account) != 0)
        return "BS2000Account: can be defined only once.";

    bs2000_account = ap_pstrdup(p, account);
    return NULL;
}

int os_init_job_environment(server_rec *server, const char *user_name)
{
    _rini_struct            inittask; 

    /* We can be sure that no change to uid==0 is possible because of
     * the checks in http_core.c:set_user()
     */

    /* An Account is required for _rini() */
    if (bs2000_account == NULL)
    {
	ap_log_error(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, server,
		     "No BS2000Account configured - cannot switch to User %S",
		     user_name);
	exit(APEXIT_CHILDFATAL);
    }

    inittask.username       = user_name;
    inittask.account        = bs2000_account;
    inittask.processor_name = "        ";

    /* Switch to the new logon user (setuid() and setgid() are done later) */
    /* Only the super use can switch identities. */
    if (_rini(&inittask) != 0) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, server,
		     "_rini: BS2000 auth failed for user \"%s\" acct \"%s\"",
		     inittask.username, inittask.account);
	exit(APEXIT_CHILDFATAL);
    }

    return 0;
}

#else /* _OSD_POSIX */
void bs2login_is_not_here()
{
}
#endif /* _OSD_POSIX */
