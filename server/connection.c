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

#define CORE_PRIVATE
#include "ap_config.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_mpm.h"
#include "mpm_default.h"
#include "http_config.h"
#include "http_vhost.h"
#include "scoreboard.h"
#include "http_log.h"
#include "util_filter.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

APR_HOOK_STRUCT(
	    APR_HOOK_LINK(pre_connection)
	    APR_HOOK_LINK(process_connection)
)

AP_IMPLEMENT_HOOK_RUN_ALL(int,pre_connection,(conn_rec *c),(c),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,process_connection,(conn_rec *c),(c),DECLINED)

/*
 * More machine-dependent networking gooo... on some systems,
 * you've got to be *really* sure that all the packets are acknowledged
 * before closing the connection, since the client will not be able
 * to see the last response if their TCP buffer is flushed by a RST
 * packet from us, which is what the server's TCP stack will send
 * if it receives any request data after closing the connection.
 *
 * In an ideal world, this function would be accomplished by simply
 * setting the socket option SO_LINGER and handling it within the
 * server's TCP stack while the process continues on to the next request.
 * Unfortunately, it seems that most (if not all) operating systems
 * block the server process on close() when SO_LINGER is used.
 * For those that don't, see USE_SO_LINGER below.  For the rest,
 * we have created a home-brew lingering_close.
 *
 * Many operating systems tend to block, puke, or otherwise mishandle
 * calls to shutdown only half of the connection.  You should define
 * NO_LINGCLOSE in ap_config.h if such is the case for your system.
 */
#ifndef MAX_SECS_TO_LINGER
#define MAX_SECS_TO_LINGER 30
#endif

#ifdef USE_SO_LINGER
#define NO_LINGCLOSE		/* The two lingering options are exclusive */

static void sock_enable_linger(int s) 
{
    struct linger li;                 

    li.l_onoff = 1;
    li.l_linger = MAX_SECS_TO_LINGER;

    if (setsockopt(s, SOL_SOCKET, SO_LINGER, 
		   (char *) &li, sizeof(struct linger)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, server_conf,
	            "setsockopt: (SO_LINGER)");
	/* not a fatal error */
    }
}

#else
#define sock_enable_linger(s)	/* NOOP */
#endif /* USE_SO_LINGER */

AP_CORE_DECLARE(void) ap_flush_conn(conn_rec *c)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(c->pool);
    b = apr_bucket_create_flush();
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(c->output_filters, bb);
}

/* we now proceed to read from the client until we get EOF, or until
 * MAX_SECS_TO_LINGER has passed.  the reasons for doing this are
 * documented in a draft:
 *
 * http://www.ics.uci.edu/pub/ietf/http/draft-ietf-http-connection-00.txt
 *
 * in a nutshell -- if we don't make this effort we risk causing
 * TCP RST packets to be sent which can tear down a connection before
 * all the response data has been sent to the client.
 */

void ap_lingering_close(conn_rec *c)
{
    char dummybuf[512];
    apr_time_t start;
    apr_size_t nbytes;
    apr_status_t rc;
    int timeout;

#ifdef NO_LINGCLOSE
    ap_flush_conn(c);	/* just close it */
    apr_close_socket(c->client_socket);
    return;
#endif

    /* Close the connection, being careful to send out whatever is still
     * in our buffers.  If possible, try to avoid a hard close until the
     * client has ACKed our FIN and/or has stopped sending us data.
     */

    /* Send any leftover data to the client, but never try to again */
    ap_flush_conn(c);

    if (c->aborted) {
        apr_close_socket(c->client_socket);
        return;
    }

    /* Shut down the socket for write, which will send a FIN
     * to the peer.
     */
    
    if (apr_shutdown(c->client_socket, APR_SHUTDOWN_WRITE) != APR_SUCCESS || 
        c->aborted) {
        apr_close_socket(c->client_socket);
        return;
    }

    /* Read all data from the peer until we reach "end-of-file" (FIN
     * from peer) or we've exceeded our overall timeout.
     */
    
    start = apr_now();
    timeout = MAX_SECS_TO_LINGER * APR_USEC_PER_SEC;
    for (;;) {
        apr_setsocketopt(c->client_socket, APR_SO_TIMEOUT, timeout);
        nbytes = sizeof(dummybuf);
        rc = apr_recv(c->client_socket, dummybuf, &nbytes);
        if (rc != APR_SUCCESS || nbytes == 0) break;

        /* how much time has elapsed? */
        timeout = (int)((apr_now() - start) / APR_USEC_PER_SEC);
        if (timeout >= MAX_SECS_TO_LINGER) break;

        /* figure out the new timeout */
        timeout = (int)((MAX_SECS_TO_LINGER - timeout) * APR_USEC_PER_SEC);
    }

    apr_close_socket(c->client_socket);
}

AP_CORE_DECLARE(void) ap_process_connection(conn_rec *c)
{
    ap_update_vhost_given_ip(c);

    ap_run_pre_connection(c);

    ap_run_process_connection(c);

}

int ap_pre_http_connection(conn_rec *c)
{
    ap_add_input_filter("HTTP_IN", NULL, NULL, c);
    ap_add_input_filter("CORE_IN", NULL, NULL, c);
    ap_add_output_filter("CORE", NULL, NULL, c);
    return OK;
}

AP_CORE_DECLARE_NONSTD(int) ap_process_http_connection(conn_rec *c)
{
    request_rec *r;

    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */

    ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_BUSY_READ, NULL);
    while ((r = ap_read_request(c)) != NULL) {

	/* process the request if it was read without error */

        ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_BUSY_WRITE, NULL); 
	if (r->status == HTTP_OK)
	    ap_process_request(r);

	if (!c->keepalive || c->aborted)
	    break;

        ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_BUSY_KEEPALIVE, NULL);
	apr_destroy_pool(r->pool);

	if (ap_graceful_stop_signalled())
            break;
    }

    ap_update_child_status(AP_CHILD_THREAD_FROM_ID(c->id), SERVER_READY, NULL);
    return OK;
}

/* Clearly some of this stuff doesn't belong in a generalised connection
   structure, but for now...
*/

conn_rec *ap_new_connection(apr_pool_t *p, server_rec *server, 
                            apr_socket_t *inout, long id)
{
    conn_rec *conn = (conn_rec *) apr_pcalloc(p, sizeof(conn_rec));
    apr_status_t rv;

    /* Got a connection structure, so initialize what fields we can
     * (the rest are zeroed out by pcalloc).
     */

    conn->conn_config=ap_create_conn_config(p);
    conn->notes = apr_make_table(p, 5);

    conn->pool = p;
    if ((rv = apr_get_sockaddr(&conn->local_addr, APR_LOCAL, inout)) 
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, server,
                     "apr_get_sockaddr(APR_LOCAL)");
        apr_close_socket(inout);
        return NULL;
    }
    apr_get_ipaddr(&conn->local_ip, conn->local_addr);
    if ((rv = apr_get_sockaddr(&conn->remote_addr, APR_REMOTE, inout))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, server,
                     "apr_get_sockaddr(APR_REMOTE)");
        apr_close_socket(inout);
        return NULL;
    }
    apr_get_ipaddr(&conn->remote_ip, conn->remote_addr);
    conn->base_server = server;
    conn->client_socket = inout;

    conn->id = id;

    return conn;
}
