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
 * compiling with gcc (it *has* changed), include ap_config.h for the
 * prototypes it defines on at least one system (SunlOSs) which has
 * them missing from the standard header files, and one minor change
 * below (extra parens around assign "if (foo = bar) ..." to shut up
 * gcc -Wall).
 */

/* Rewritten by David Robinson */

#include "httpd.h"		/* for server_rec, conn_rec, ap_longjmp, etc. */
#include "http_log.h"		/* for aplog_error */
#include "rfc1413.h"
#include "http_main.h"		/* set_callback_and_alarm */
#include "apr_network_io.h"

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
#define	ANY_PORT	0	/* Any old port will do */
#define FROM_UNKNOWN  "unknown"

int ap_rfc1413_timeout = RFC1413_TIMEOUT;	/* Global so it can be changed */

static JMP_BUF timebuf;

/* bind_connect - bind both ends of a socket */
/* Ambarish fix this. Very broken */
static int get_rfc1413(ap_socket_t *sock, const char *local_ip,
		       const char *rmt_ip, 
		       char user[RFC1413_USERLEN+1], server_rec *srv)
{
    unsigned int rmt_port, our_port;
    unsigned int sav_rmt_port, sav_our_port;
    int i;
    char *cp;
    char buffer[RFC1413_MAXDATA + 1];
    int buflen;

    /*
     * Bind the local and remote ends of the query socket to the same
     * IP addresses as the connection under investigation. We go
     * through all this trouble because the local or remote system
     * might have more than one network address. The RFC1413 etc.
     * client sends only port numbers; the server takes the IP
     * addresses from the query socket.
     */

    ap_setport(sock, ANY_PORT);
    ap_setipaddr(sock, local_ip); 

    if (ap_bind(sock) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, srv,
		    "bind: rfc1413: Error binding to local port");
	return -1;
    }
    ap_getport(sock, &sav_our_port);

/*
 * errors from connect usually imply the remote machine doesn't support
 * the service
 */
    ap_setport(sock, RFC1413_PORT);
    ap_setipaddr(sock, rmt_ip); 
                    
    if (ap_connect(sock, NULL) != APR_SUCCESS)
        return -1;
    ap_getport(sock, &sav_rmt_port);

/* send the data */
    buflen = ap_snprintf(buffer, sizeof(buffer), "%u,%u\r\n", sav_rmt_port,
		sav_our_port);

    /* send query to server. Handle short write. */
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(&buffer, &buffer, buflen);
#endif
    i = 0;
    while(i < strlen(buffer)) {
        int j = strlen(buffer + i);
        ap_status_t stat;
	stat  = ap_send(sock, buffer+i, &j);
	if (stat != APR_SUCCESS && stat != APR_EINTR) {
	  ap_log_error(APLOG_MARK, APLOG_CRIT, srv,
		       "write: rfc1413: error sending request");
	  return -1;
	}
	else if (j > 0) {
	    i+=j; 
	}
    }

    /*
     * Read response from server. - the response should be newline 
     * terminated according to rfc - make sure it doesn't stomp it's
     * way out of the buffer.
     */

    i = 0;
    memset(buffer, '\0', sizeof(buffer));
    /*
     * Note that the strchr function below checks for 10 instead of '\n'
     * this allows it to work on both ASCII and EBCDIC machines.
     */
    while((cp = strchr(buffer, '\012')) == NULL && i < sizeof(buffer) - 1) {
        int j = sizeof(buffer) - 1 - i;
        ap_status_t stat;
	stat = ap_recv(sock, buffer+i, &j);
	if (stat != APR_SUCCESS && stat != APR_EINTR) {
	   ap_log_error(APLOG_MARK, APLOG_CRIT, srv,
			"read: rfc1413: error reading response");
	   return -1;
	}
	else if (j > 0) {
	    i+=j; 
	}
    }

/* RFC1413_USERLEN = 512 */
#ifdef CHARSET_EBCDIC
    ascii2ebcdic(&buffer, &buffer, (size_t)i);
#endif
    if (sscanf(buffer, "%u , %u : USERID :%*[^:]:%512s", &rmt_port, &our_port,
	       user) != 3 || sav_rmt_port != rmt_port
	|| sav_our_port != our_port)
	return -1;

    /*
     * Strip trailing carriage return. It is part of the
     * protocol, not part of the data.
     */

    if ((cp = strchr(user, '\r')))
	*cp = '\0';

    return 0;
}

/* rfc1413 - return remote user name, given socket structures */
char *ap_rfc1413(conn_rec *conn, server_rec *srv)
{
    static char user[RFC1413_USERLEN + 1];	/* XXX */
    static char *result;
    static ap_socket_t *sock;

    result = FROM_UNKNOWN;

    if (ap_create_tcp_socket(conn->pool, &sock) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, srv,
		    "socket: rfc1413: error creating socket");
	conn->remote_logname = result;
    }

    /*
     * Set up a timer so we won't get stuck while waiting for the server.
     */
    if (ap_setjmp(timebuf) == 0) {

	if (get_rfc1413(sock, conn->local_ip, conn->remote_ip, user, srv) >= 0)
	    result = user;
    }
    ap_close_socket(sock);
    conn->remote_logname = result;

    return conn->remote_logname;
}
