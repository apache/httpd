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

#ifndef AP_LISTEN_H
#define AP_LISTEN_H

#include "apr_network_io.h"
#include "httpd.h"
#include "http_config.h"

/**
 * @package Apache Listeners Library
 */

typedef struct ap_listen_rec ap_listen_rec;
typedef apr_status_t (*accept_function)(void **csd, ap_listen_rec *lr, apr_pool_t *ptrans);

/**
 * Apache's listeners record.  These are used in the Multi-Processing Modules
 * to setup all of the sockets for the MPM to listen to and accept on.
 */
struct ap_listen_rec {
    /**
     * The next listener in the list
     */
    ap_listen_rec *next;
    /**
     * The actual socket 
     */
    apr_socket_t *sd;
    /**
     * The sockaddr the socket should bind to
     */
    apr_sockaddr_t *bind_addr;
    /**
     * The accept function for this socket
     */
    accept_function accept_func;
    /**
     * Is this socket currently active 
     */
    int active;
/* more stuff here, like which protocol is bound to the port */
};

/**
 * The global list of ap_listen_rec structures
 */
AP_DECLARE_DATA extern ap_listen_rec *ap_listeners;

/**
 * Setup all of the defaults for the listener list
 */
void ap_listen_pre_config(void);
#if !defined(SPMT_OS2_MPM)
/**
 * Loop through the global ap_listen_rec list and create all of the required
 * sockets.  This executes the listen and bind on the sockets.
 * @param s The global server_rec
 * @return The number of open sockets.
 * @warning This function is not available to Windows platforms, or the
 * Prefork or SPMT_OS2 MPMs.
 */ 
int ap_setup_listeners(server_rec *s);
#endif
/* Split into two #if's to make the exports scripts easier.
 */
#if defined(SPMT_OS2_MPM)
/**
 * Create and open a socket on the specified port.  This includes listening
 * and binding the socket.
 * @param process The process record for the currently running server
 * @param port The port to open a socket on.
 * @return The number of open sockets
 * @warning This function is only available to Windows platforms, or the
 * Prefork or SPMT_OS2 MPMs.
 */
int ap_listen_open(process_rec *process, apr_port_t port);
#endif

/* Although these functions are exported from libmain, they are not really
 * public functions.  These functions are actually called while parsing the
 * config file, when one of the LISTEN_COMMANDS directives is read.  These
 * should not ever be called by external modules.  ALL MPMs should include
 * LISTEN_COMMANDS in their command_rec table so that these functions are
 * called.
 */ 
const char *ap_set_listenbacklog(cmd_parms *cmd, void *dummy, const char *arg);
const char *ap_set_listener(cmd_parms *cmd, void *dummy, const char *ips);
const char *ap_set_send_buffer_size(cmd_parms *cmd, void *dummy,
				    const char *arg);

#define LISTEN_COMMANDS	\
AP_INIT_TAKE1("ListenBacklog", ap_set_listenbacklog, NULL, RSRC_CONF, \
  "Maximum length of the queue of pending connections, as used by listen(2)"), \
AP_INIT_TAKE1("Listen", ap_set_listener, NULL, RSRC_CONF, \
  "A port number or a numeric IP address and a port number"), \
AP_INIT_TAKE1("SendBufferSize", ap_set_send_buffer_size, NULL, RSRC_CONF, \
  "Send buffer size in bytes")

#endif
