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
 * rfc1413() speaks a common subset of the RFC 1413, AUTH, TAP and IDENT
 * protocols. The code queries an RFC 1413 etc. compatible daemon on a remote
 * host to look up the owner of a connection. The information should not be
 * used for authentication purposes. This routine intercepts alarm signals.
 * 
 * Diagnostics are reported through syslog(3).
 * 
 * Author: Wietse Venema, Eindhoven University of Technology,
 * The Netherlands.
 */

/* Some small additions for Apache --- ditch the "sccsid" var if
 * compiling with gcc (it *has* changed), include conf.h for the
 * prototypes it defines on at least one system (SunlOSs) which has
 * them missing from the standard header files, and one minor change
 * below (extra parens around assign "if (foo = bar) ..." to shut up
 * gcc -Wall).
 */

/* Rewritten by David Robinson */

#include "httpd.h"    /* for server_rec, conn_rec, ap_longjmp, etc. */
#include "http_log.h" /* for log_unixerr */
#include "rfc1413.h"

#ifndef SCO
extern char *strchr();
extern char *inet_ntoa();
#endif

/* Local stuff. */
/* Semi-well-known port */
#define	RFC1413_PORT	113
/* maximum allowed length of userid */
#define RFC1413_USERLEN 512
/* rough limit on the amount of data we accept. */
#define RFC1413_MAXDATA 1000

#ifndef RFC1413_TIMEOUT
#define RFC1413_TIMEOUT	30
#endif
#define	ANY_PORT	0		/* Any old port will do */
#define FROM_UNKNOWN  "unknown"

int rfc1413_timeout = RFC1413_TIMEOUT;  /* Global so it can be changed */

JMP_BUF timebuf;

/* bind_connect - bind both ends of a socket */

static int
get_rfc1413(int sock, const struct sockaddr_in *our_sin,
	  const struct sockaddr_in *rmt_sin, char user[256], server_rec *srv)
{
    struct sockaddr_in rmt_query_sin, our_query_sin;
    unsigned int rmt_port, our_port;
    int i;
    char *cp;
    char buffer[RFC1413_MAXDATA+1];

    /*
     * Bind the local and remote ends of the query socket to the same
     * IP addresses as the connection under investigation. We go
     * through all this trouble because the local or remote system
     * might have more than one network address. The RFC1413 etc.
     * client sends only port numbers; the server takes the IP
     * addresses from the query socket.
     */

    our_query_sin = *our_sin;
    our_query_sin.sin_port = htons(ANY_PORT);
    rmt_query_sin = *rmt_sin;
    rmt_query_sin.sin_port = htons(RFC1413_PORT);

    if (bind(sock, (struct sockaddr *)&our_query_sin,
	     sizeof(struct sockaddr_in)) < 0)
    {
	log_unixerr("bind", NULL, "rfc1413: Error binding to local port", srv);
	return -1;
    }

/*
 * errors from connect usually imply the remote machine doesn't support
 * the service
 */
    if (connect(sock, (struct sockaddr *)&rmt_query_sin,
		sizeof(struct sockaddr_in)) < 0)
	return -1;

/* send the data */
    ap_snprintf(buffer, sizeof(buffer), "%u,%u\r\n", ntohs(rmt_sin->sin_port),
	    ntohs(our_sin->sin_port));
    do i = write(sock, buffer, strlen(buffer));
    while (i == -1 && errno == EINTR);
    if (i == -1)
    {
	log_unixerr("write", NULL, "rfc1413: error sending request", srv);
	return -1;
    }

    /*
     * Read response from server. We assume that all the data
     * comes in a single packet.
     */
    
    do i = read(sock, buffer, RFC1413_MAXDATA);
    while (i == -1 && errno == EINTR);
    if (i == -1)
    {
	log_unixerr("read", NULL, "rfc1413: error reading response", srv);
	return -1;
    }

    buffer[i] = '\0';
/* RFC1413_USERLEN = 512 */
    if (sscanf(buffer, "%u , %u : USERID :%*[^:]:%512s", &rmt_port, &our_port,
	       user) != 3 || ntohs(rmt_sin->sin_port) != rmt_port
	|| ntohs(our_sin->sin_port) != our_port) return -1;

    /*
     * Strip trailing carriage return. It is part of the
     * protocol, not part of the data.
     */
    
    if ((cp = strchr(user, '\r'))) *cp = '\0';

    return 0;
}

/* ident_timeout - handle timeouts */
static void
ident_timeout(int sig)
{
    ap_longjmp(timebuf, sig);
}

/* rfc1413 - return remote user name, given socket structures */
char *
rfc1413(conn_rec *conn, server_rec *srv)
{
    static char user[RFC1413_USERLEN+1]; /* XXX */
    static char *result;
    static int sock;

    result = FROM_UNKNOWN;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
    {
	log_unixerr("socket", NULL, "rfc1413: error creating socket", srv);
	conn->remote_logname = result;
    }

    /*
     * Set up a timer so we won't get stuck while waiting for the server.
     */
    if (ap_setjmp(timebuf) == 0)
    {
	signal(SIGALRM, ident_timeout);
	alarm(rfc1413_timeout);
	
	if (get_rfc1413(sock, &conn->local_addr, &conn->remote_addr, user,
		      srv)
	    >= 0)
	    result = user;

	alarm(0);
    }
    close(sock);
    conn->remote_logname = result;

    return conn->remote_logname;
}
