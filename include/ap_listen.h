/* Copyright 2000-2004 Apache Software Foundation
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
