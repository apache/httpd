/* Copyright 1999-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* TODO - put timeouts back in */
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

#include "apr.h"
#include "apr_network_io.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_inherit.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"		/* for server_rec, conn_rec, etc. */
#include "http_log.h"		/* for aplog_error */
#include "rfc1413.h"
#include "http_main.h"		/* set_callback_and_alarm */
#include "util_ebcdic.h"

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
#define FROM_UNKNOWN  "unknown"

int ap_rfc1413_timeout = RFC1413_TIMEOUT;	/* Global so it can be changed */

static apr_status_t rfc1413_connect(apr_socket_t **newsock, conn_rec *conn,
                                    server_rec *srv)
{
    apr_status_t rv;
    apr_sockaddr_t *localsa, *destsa;

    if ((rv = apr_sockaddr_info_get(&localsa, conn->local_ip, APR_UNSPEC, 
                              0, /* ephemeral port */
                              0, conn->pool)) != APR_SUCCESS) {
        /* This should not fail since we have a numeric address string
         * as the host. */
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, srv,
                     "rfc1413: apr_sockaddr_info_get(%s) failed",
                     conn->local_ip);
        return rv;
    }
    
    if ((rv = apr_sockaddr_info_get(&destsa, conn->remote_ip, 
                              localsa->family, /* has to match */
                              RFC1413_PORT, 0, conn->pool)) != APR_SUCCESS) {
        /* This should not fail since we have a numeric address string
         * as the host. */
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, srv,
                     "rfc1413: apr_sockaddr_info_get(%s) failed",
                     conn->remote_ip);
        return rv;
    }

    if ((rv = apr_socket_create(newsock, 
                                localsa->family, /* has to match */
                                SOCK_STREAM, conn->pool)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, rv, srv,
                     "rfc1413: error creating query socket");
        return rv;
    }

    if ((rv = apr_socket_timeout_set(*newsock, apr_time_from_sec(ap_rfc1413_timeout)))
            != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, srv,
                     "rfc1413: error setting query socket timeout");
        apr_socket_close(*newsock);
        return rv;
    }

/*
 * Bind the local and remote ends of the query socket to the same
 * IP addresses as the connection under investigation. We go
 * through all this trouble because the local or remote system
 * might have more than one network address. The RFC1413 etc.
 * client sends only port numbers; the server takes the IP
 * addresses from the query socket.
 */

    if ((rv = apr_bind(*newsock, localsa)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, rv, srv,
                     "rfc1413: Error binding query socket to local port");
        apr_socket_close(*newsock);
	return rv;
    }

/*
 * errors from connect usually imply the remote machine doesn't support
 * the service; don't log such an error
 */
    if ((rv = apr_connect(*newsock, destsa)) != APR_SUCCESS) {
        apr_socket_close(*newsock);
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t rfc1413_query(apr_socket_t *sock, conn_rec *conn, 
                                  server_rec *srv)
{
    apr_port_t rmt_port, our_port;
    apr_port_t sav_rmt_port, sav_our_port;
    apr_size_t i;
    char *cp;
    char buffer[RFC1413_MAXDATA + 1];
    char user[RFC1413_USERLEN + 1];	/* XXX */
    apr_size_t buflen;

    apr_sockaddr_port_get(&sav_our_port, conn->local_addr);
    apr_sockaddr_port_get(&sav_rmt_port, conn->remote_addr);

    /* send the data */
    buflen = apr_snprintf(buffer, sizeof(buffer), "%hu,%hu\r\n", sav_rmt_port,
                          sav_our_port);
    ap_xlate_proto_to_ascii(buffer, buflen);

    /* send query to server. Handle short write. */
    i = 0;
    while (i < buflen) {
        apr_size_t j = strlen(buffer + i);
        apr_status_t status;
	status  = apr_send(sock, buffer+i, &j);
	if (status != APR_SUCCESS) {
	    ap_log_error(APLOG_MARK, APLOG_CRIT, status, srv,
		         "write: rfc1413: error sending request");
	    return status;
	}
	else if (j > 0) {
	    i+=j; 
	}
    }

    /*
     * Read response from server. - the response should be newline 
     * terminated according to rfc - make sure it doesn't stomp its
     * way out of the buffer.
     */

    i = 0;
    memset(buffer, '\0', sizeof(buffer));
    /*
     * Note that the strchr function below checks for \012 instead of '\n'
     * this allows it to work on both ASCII and EBCDIC machines.
     */
    while((cp = strchr(buffer, '\012')) == NULL && i < sizeof(buffer) - 1) {
        apr_size_t j = sizeof(buffer) - 1 - i;
        apr_status_t status;
	status = apr_recv(sock, buffer+i, &j);
	if (status != APR_SUCCESS) {
	    ap_log_error(APLOG_MARK, APLOG_CRIT, status, srv,
			"read: rfc1413: error reading response");
	    return status;
	}
	else if (j > 0) {
	    i+=j; 
	}
        else if (status == APR_SUCCESS && j == 0) {
            /* Oops... we ran out of data before finding newline */
            return APR_EINVAL;
        }
    }

/* RFC1413_USERLEN = 512 */
    ap_xlate_proto_from_ascii(buffer, i);
    if (sscanf(buffer, "%hu , %hu : USERID :%*[^:]:%512s", &rmt_port, &our_port,
	       user) != 3 || sav_rmt_port != rmt_port
	|| sav_our_port != our_port)
	return APR_EINVAL;

    /*
     * Strip trailing carriage return. It is part of the
     * protocol, not part of the data.
     */

    if ((cp = strchr(user, '\r')))
	*cp = '\0';

    conn->remote_logname = apr_pstrdup(conn->pool, user);

    return APR_SUCCESS;
}

char *ap_rfc1413(conn_rec *conn, server_rec *srv)
{
    apr_socket_t *sock;
    apr_status_t rv;

    rv = rfc1413_connect(&sock, conn, srv);
    if (rv == APR_SUCCESS) {
        rv = rfc1413_query(sock, conn, srv);
        apr_socket_close(sock);
    }
    if (rv != APR_SUCCESS) {
        conn->remote_logname = FROM_UNKNOWN;
    }
    return conn->remote_logname;
}
