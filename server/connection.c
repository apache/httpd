/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

#include "apr.h"
#include "apr_strings.h"

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_mpm.h"
#include "mpm_default.h"
#include "http_config.h"
#include "http_core.h"
#include "http_vhost.h"
#include "scoreboard.h"
#include "http_log.h"
#include "util_filter.h"

APR_HOOK_STRUCT(
            APR_HOOK_LINK(create_connection)
	    APR_HOOK_LINK(process_connection)
	    APR_HOOK_LINK(pre_connection)
)
AP_IMPLEMENT_HOOK_RUN_FIRST(conn_rec *,create_connection,
                            (apr_pool_t *p, server_rec *server, apr_socket_t *csd, long conn_id, void *sbh, apr_bucket_alloc_t *alloc),
                            (p, server, csd, conn_id, sbh, alloc), NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,process_connection,(conn_rec *c),(c),DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,pre_connection,(conn_rec *c, void *csd),(c, csd),OK,DECLINED)
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

AP_CORE_DECLARE(void) ap_flush_conn(conn_rec *c)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(c->pool, c->bucket_alloc);
    b = apr_bucket_flush_create(c->bucket_alloc);
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
#define SECONDS_TO_LINGER  2
AP_DECLARE(void) ap_lingering_close(conn_rec *c)
{
    char dummybuf[512];
    apr_size_t nbytes = sizeof(dummybuf);
    apr_status_t rc;
    apr_int32_t timeout;
    apr_int32_t total_linger_time = 0;
    apr_socket_t *csd = ap_get_module_config(c->conn_config, &core_module);

    if (!csd) {
        return;
    }

    ap_update_child_status(c->sbh, SERVER_CLOSING, NULL);

#ifdef NO_LINGCLOSE
    ap_flush_conn(c); /* just close it */
    apr_socket_close(csd);
    return;
#endif

    /* Close the connection, being careful to send out whatever is still
     * in our buffers.  If possible, try to avoid a hard close until the
     * client has ACKed our FIN and/or has stopped sending us data.
     */

    /* Send any leftover data to the client, but never try to again */
    ap_flush_conn(c);

    if (c->aborted) {
        apr_socket_close(csd);
        return;
    }

    /* Shut down the socket for write, which will send a FIN
     * to the peer.
     */
    if (apr_shutdown(csd, APR_SHUTDOWN_WRITE) != APR_SUCCESS
        || c->aborted) {
        apr_socket_close(csd);
        return;
    }

    /* Read all data from the peer until we reach "end-of-file" (FIN
     * from peer) or we've exceeded our overall timeout. If the client does
     * not send us bytes within 2 seconds (a value pulled from Apache 1.3
     * which seems to work well), close the connection.
     */
    timeout = apr_time_from_sec(SECONDS_TO_LINGER);
    apr_socket_timeout_set(csd, timeout);
    apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 1);
    while (1) {
        nbytes = sizeof(dummybuf);
        rc = apr_recv(csd, dummybuf, &nbytes);
        if (rc != APR_SUCCESS || nbytes == 0)
            break;

        total_linger_time += SECONDS_TO_LINGER;
        if (total_linger_time >= MAX_SECS_TO_LINGER) {
            break;
        }
    }

    apr_socket_close(csd);
    return;
}

AP_CORE_DECLARE(void) ap_process_connection(conn_rec *c, void *csd)
{
    int rc;
    ap_update_vhost_given_ip(c);

    rc = ap_run_pre_connection(c, csd);
    if (rc != OK && rc != DONE) {
        c->aborted = 1;
    }
    
    if (!c->aborted) {
        ap_run_process_connection(c);
    }
}

