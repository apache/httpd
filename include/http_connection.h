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
 */

#ifndef APACHE_HTTP_CONNECTION_H
#define APACHE_HTTP_CONNECTION_H

#include "apr_hooks.h"
#include "apr_network_io.h"
#include "apr_buckets.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Apache connection library
 */
#ifdef CORE_PRIVATE
/**
 * This is the protocol module driver.  This calls all of the
 * pre-connection and connection hooks for all protocol modules.
 * @param c The connection on which the request is read
 * @param csd The mechanism on which this connection is to be read.  
 *            Most times this will be a socket, but it is up to the module
 *            that accepts the request to determine the exact type.
 * @deffunc void ap_process_connection(conn_rec *c, void *csd)
 */
AP_CORE_DECLARE(void) ap_process_connection(conn_rec *c, void *csd);

AP_CORE_DECLARE(void) ap_flush_conn(conn_rec *c);

/**
 * This function is responsible for the following cases:
 * <pre>
 * we now proceed to read from the client until we get EOF, or until
 * MAX_SECS_TO_LINGER has passed.  the reasons for doing this are
 * documented in a draft:
 *
 * http://www.ics.uci.edu/pub/ietf/http/draft-ietf-http-connection-00.txt
 *
 * in a nutshell -- if we don't make this effort we risk causing
 * TCP RST packets to be sent which can tear down a connection before
 * all the response data has been sent to the client.
 * </pre>
 * @param c The connection we are closing
 */
AP_DECLARE(void) ap_lingering_close(conn_rec *c);
#endif

  /* Hooks */
/**
 * create_connection is a RUN_FIRST hook which allows modules to create 
 * connections. In general, you should not install filters with the 
 * create_connection hook. If you require vhost configuration information 
 * to make filter installation decisions, you must use the pre_connection
 * or install_network_transport hook. This hook should close the connection
 * if it encounters a fatal error condition.
 *
 * @param p The pool from which to allocate the connection record
 * @param csd The socket that has been accepted
 * @param conn_id A unique identifier for this connection.  The ID only
 *                needs to be unique at that time, not forever.
 * @param sbh A handle to scoreboard information for this connection.
 * @return An allocated connection record or NULL.
 */
AP_DECLARE_HOOK(conn_rec *, create_connection,
                (apr_pool_t *p, server_rec *server, apr_socket_t *csd,
                 long conn_id, void *sbh, apr_bucket_alloc_t *alloc))
   
/**
 * This hook gives protocol modules an opportunity to set everything up
 * before calling the protocol handler.  All pre-connection hooks are
 * run until one returns something other than ok or decline
 * @param c The connection on which the request has been received.
 * @param csd The mechanism on which this connection is to be read.  
 *            Most times this will be a socket, but it is up to the module
 *            that accepts the request to determine the exact type.
 * @return OK or DECLINED
 * @deffunc int ap_run_pre_connection(conn_rec *c, void *csd)
 */
AP_DECLARE_HOOK(int,pre_connection,(conn_rec *c, void *csd))

/**
 * This hook implements different protocols.  After a connection has been
 * established, the protocol module must read and serve the request.  This
 * function does that for each protocol module.  The first protocol module
 * to handle the request is the last module run.
 * @param c The connection on which the request has been received.
 * @return OK or DECLINED
 * @deffunc int ap_run_process_connection(conn_rec *c)
 */
AP_DECLARE_HOOK(int,process_connection,(conn_rec *c))

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_REQUEST_H */
