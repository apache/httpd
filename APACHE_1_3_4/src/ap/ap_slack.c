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
 * ap_slack.c: File descriptor preallocation
 * 
 * 3/21/93 Rob McCool
 * 1995-96 Many changes by the Apache Group
 * 
 */

#include "httpd.h"
#include "http_log.h"

#ifndef NO_SLACK
int ap_slack(int fd, int line)
{
#if !defined(F_DUPFD)
    return fd;
#else
    static int low_warned;
    int new_fd;

#ifdef HIGH_SLACK_LINE
    if (line == AP_SLACK_HIGH && fd < HIGH_SLACK_LINE) {
	new_fd = fcntl(fd, F_DUPFD, HIGH_SLACK_LINE);
	if (new_fd != -1) {
	    close(fd);
	    return new_fd;
	}
    }
#endif
    /* otherwise just assume line == AP_SLACK_LOW */
    if (fd >= LOW_SLACK_LINE) {
	return fd;
    }
    new_fd = fcntl(fd, F_DUPFD, LOW_SLACK_LINE);
    if (new_fd == -1) {
	if (!low_warned) {
	    /* Give them a warning here, because we really can't predict
	     * how libraries and such are going to fail.  If we can't
	     * do this F_DUPFD there's a good chance that apache has too
	     * few descriptors available to it.  Note we don't warn on
	     * the high line, because if it fails we'll eventually try
	     * the low line...
	     */
	    ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		        "unable to open a file descriptor above %u, "
			"you may need to increase the number of descriptors",
			LOW_SLACK_LINE);
	    low_warned = 1;
	}
	return fd;
    }
    close(fd);
    return new_fd;
#endif
}
#else
/* need at least one function in the file for some linkers */
void ap_slack_is_not_here(void) {}
#endif /* NO_SLACK */
