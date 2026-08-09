/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
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

#ifndef H3_SOCKET_H
#define H3_SOCKET_H

#include <httpd.h>

#include <apr_network_io.h>
#include <apr_portable.h>

/**
 * Open a non-blocking IPv6 dual-stack UDP socket and bind it to the given port.
 * Sets SO_REUSEADDR; on non-Windows also tries SO_REUSEPORT so multiple
 * children can share the port.
 * @param port  Port to bind; 0 lets the OS pick.
 * @param pool  Pool used for the underlying apr_socket_t lifetime.
 * @param out_fd Out parameter: the resulting OS-level fd (suitable for
 *               SSL_set_fd on OpenSSL QUIC).
 * @return APR_SUCCESS, APR_EAGAIN if the port is already bound, or another
 *         APR error code.
 */
apr_status_t h3_socket_open(apr_port_t port, apr_pool_t* pool, int* out_fd);

/**
 * Close a UDP socket previously returned by h3_socket_open.
 * Safe to call with a negative fd (no-op).
 * @param fd The OS-level fd to close.
 */
void h3_socket_close(int fd);

/**
 * A way to interrupt the event thread's poll from another thread.
 *
 * Loopback UDP rather than a pipe: Windows can only poll sockets.
 */
typedef struct h3_wakeup
{
    apr_socket_t* reader;
    apr_socket_t* writer;
    apr_os_sock_t reader_fd; /**< The reader's native socket, for the poll set. */
} h3_wakeup;

/**
 * Create a wakeup pair on loopback. Both sockets are non-blocking.
 * @param pool Pool owning both sockets.
 * @param w    Out: the initialized pair; reset to reader_fd -1 on failure.
 * @return APR_SUCCESS or an APR error code.
 */
apr_status_t h3_wakeup_create(apr_pool_t* pool, h3_wakeup* w);

/**
 * Wake the event thread. Safe from any thread; a blocked send is dropped.
 * @param w The pair to signal; NULL or uncreated is ignored.
 */
void h3_wakeup_signal(h3_wakeup* w);

/**
 * Discard everything queued on the reader, after poll reports it readable.
 * @param w The pair to drain; NULL or uncreated is ignored.
 */
void h3_wakeup_drain(h3_wakeup* w);

#endif /* H3_SOCKET_H */
