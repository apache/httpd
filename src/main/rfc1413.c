/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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

#if (defined (NETWARE) || defined (WIN32))
#define write(a,b,c) send(a,b,c,0)
#define read(a,b,c) recv(a,b,c,0)
#endif

#ifdef MULTITHREAD
#define RFC_USER_STATIC 

static int setsocktimeout (int sock, int timeout)
{
#if (defined (NETWARE) || defined (WIN32))
    u_long msec = 0;

    /* Make sure that we are in blocking mode */
    if (ioctlsocket(sock, FIONBIO, &msec) == SOCKET_ERROR) {
        return h_errno;
    }

    /* Win32 timeouts are in msec, represented as int */
    msec = timeout * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, 
               (char *) &msec, sizeof(msec));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, 
               (char *) &msec, sizeof(msec));
#else
    /* XXX Needs to be implemented for non-winsock platforms */
#endif
    return 0;
}
#else /* MULTITHREAD */

#define RFC_USER_STATIC static
static JMP_BUF timebuf;

/* ident_timeout - handle timeouts */
static void ident_timeout(int sig)
{
    ap_longjmp(timebuf, sig);
}
#endif

/* bind_connect - bind both ends of a socket */
/* Ambarish fix this. Very broken */
static int get_rfc1413(int sock, const struct sockaddr_in *our_sin,
		       const struct sockaddr_in *rmt_sin, 
		       char user[RFC1413_USERLEN+1], server_rec *srv)
{
    struct sockaddr_in rmt_query_sin, our_query_sin;
    unsigned int rmt_port, our_port;
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

    our_query_sin = *our_sin;
    our_query_sin.sin_port = htons(ANY_PORT);
#ifdef MPE 
    our_query_sin.sin_addr.s_addr = INADDR_ANY;
#endif
    rmt_query_sin = *rmt_sin;
    rmt_query_sin.sin_port = htons(RFC1413_PORT);

    if (bind(sock, (struct sockaddr *) &our_query_sin,
	     sizeof(struct sockaddr_in)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, srv,
		    "bind: rfc1413: Error binding to local port");
	return -1;
    }

/*
 * errors from connect usually imply the remote machine doesn't support
 * the service
 */
    if (connect(sock, (struct sockaddr *) &rmt_query_sin,
		sizeof(struct sockaddr_in)) < 0)
	            return -1;

/* send the data */
    buflen = ap_snprintf(buffer, sizeof(buffer), "%u,%u\r\n", ntohs(rmt_sin->sin_port),
		ntohs(our_sin->sin_port));

    /* send query to server. Handle short write. */
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buffer, buffer, buflen);
#endif
    i = 0;
    while(i < (int)strlen(buffer)) {
        int j;
	j = write(sock, buffer+i, (strlen(buffer+i)));
	if (j < 0 && errno != EINTR) {
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
     * Note that the strchr function below checks for \012 instead of '\n'
     * this allows it to work on both ASCII and EBCDIC machines.
     */
    while((cp = strchr(buffer, '\012')) == NULL && i < sizeof(buffer) - 1) {
        int j;
  
#ifdef TPF
        /*
         * socket read on TPF doesn't get interrupted by
         * signals so additional processing is needed
         */
        j = ap_set_callback_and_alarm(NULL, 0);
        ap_set_callback_and_alarm(ident_timeout, j);
        j = select(&sock, 1, 0, 0, j * 1000);
        if (j < 1) {
            ap_set_callback_and_alarm(NULL, 0);
            ap_check_signals();
            return -1;
        }
#endif /* TPF */
	j = read(sock, buffer+i, (sizeof(buffer) - 1) - i);
	if (j < 0 && errno != EINTR) {
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
    ascii2ebcdic(buffer, buffer, (size_t)i);
#endif
    if (sscanf(buffer, "%u , %u : USERID :%*[^:]:%512s", &rmt_port, &our_port,
	       user) != 3 || ntohs(rmt_sin->sin_port) != rmt_port
	|| ntohs(our_sin->sin_port) != our_port)
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
API_EXPORT(char *) ap_rfc1413(conn_rec *conn, server_rec *srv)
{
    RFC_USER_STATIC char user[RFC1413_USERLEN + 1];	/* XXX */
    RFC_USER_STATIC char *result;
    RFC_USER_STATIC int sock;

    result = FROM_UNKNOWN;

    sock = ap_psocket_ex(conn->pool, AF_INET, SOCK_STREAM, IPPROTO_TCP, 1);
    if (sock < 0) {
    	ap_log_error(APLOG_MARK, APLOG_CRIT, srv,
    		    "socket: rfc1413: error creating socket");
    	conn->remote_logname = result;
    }

    /*
     * Set up a timer so we won't get stuck while waiting for the server.
     */
#ifdef MULTITHREAD
    if (setsocktimeout(sock, ap_rfc1413_timeout) == 0) {
        if (get_rfc1413(sock, &conn->local_addr, &conn->remote_addr, user, srv) >= 0)
            result = ap_pstrdup (conn->pool, user);
    }
#else
    if (ap_setjmp(timebuf) == 0) {
	ap_set_callback_and_alarm(ident_timeout, ap_rfc1413_timeout);

	if (get_rfc1413(sock, &conn->local_addr, &conn->remote_addr, user, srv) >= 0)
	    result = user;
    }
    ap_set_callback_and_alarm(NULL, 0);
#endif
    ap_pclosesocket(conn->pool, sock);
    conn->remote_logname = result;

    return conn->remote_logname;
}

