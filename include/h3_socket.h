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

#endif /* H3_SOCKET_H */
