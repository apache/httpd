/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Apache connection library
 */

#ifdef CORE_PRIVATE
/**
 * Create a new connection. 
 * @param p Pool to allocate data structures out of
 * @param server The server to create the connection for
 * @param inout The socket to use for all communication with the client
 * @param id ID of this connection; unique at any point in time.
 * @return new conn_rec, or NULL if the connection has already been reset
 */
AP_CORE_DECLARE(conn_rec *)ap_new_connection(apr_pool_t *p, server_rec *server, 
                            apr_socket_t *inout, long id);

/**
 * This is the protocol module driver.  This calls all of the
 * pre-connection and connection hooks for all protocol modules.
 * @param c The connection on which the request is read
 * @deffunc void ap_process_connection(conn_rec *)
 */
AP_CORE_DECLARE(void) ap_process_connection(conn_rec *);

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
apr_status_t ap_lingering_close(void *dummy);
#endif

  /* Hooks */
/**
 * This hook gives protocol modules an opportunity to set everything up
 * before calling the protocol handler.  All pre-connection hooks are
 * run until one returns something other than ok or decline
 * @param c The connection on which the request has been received.
 * @return OK or DECLINED
 * @deffunc int ap_run_pre_connection(conn_rec *c)
 */
AP_DECLARE_HOOK(int,pre_connection,(conn_rec *c))

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

/**
 */
AP_DECLARE_HOOK(conn_rec *, create_connection,
                (apr_pool_t *p, apr_socket_t *csd, int child_num))

/* This is NOT staying here.  It is necessary to quiet warnings
 * while I would on the next patch. rbb
 */

AP_CORE_DECLARE(conn_rec *)ap_core_new_connection(apr_pool_t *p,
                            server_rec *server, apr_socket_t *inout,
                            core_net_rec *net, long id);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_REQUEST_H */
