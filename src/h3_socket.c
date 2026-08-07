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

#include <apr_portable.h>

#include <string.h>

#include "h3_check.h"
#include "h3_os.h"
#include "h3_socket.h"

apr_status_t h3_socket_open(apr_port_t port, apr_pool_t* pool, int* out_fd)
{
    CHECK(pool);
    CHECK(out_fd);
    apr_socket_t* sock = NULL;
    apr_status_t rv = apr_socket_create(&sock, APR_INET6, SOCK_DGRAM, APR_PROTO_UDP, pool);
    if (rv != APR_SUCCESS)
    {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "h3_socket_open: apr_socket_create failed");
        return rv;
    }
    apr_socket_opt_set(sock, APR_IPV6_V6ONLY, 0);
    apr_sockaddr_t* addr = NULL;
    rv = apr_sockaddr_info_get(&addr, NULL, APR_INET6, port, 0, pool);
    if (rv != APR_SUCCESS)
    {
        apr_socket_close(sock);
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "h3_socket_open: apr_sockaddr_info_get failed");
        return rv;
    }
    rv = apr_socket_bind(sock, addr);
    if (rv != APR_SUCCESS)
    {
        apr_socket_close(sock);
        if (h3_socket_os_is_eaddrinuse(rv))
        {
            ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool, "bind(%d) skipped (port already owned)", (int)port);
            return APR_EAGAIN;
        }
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "bind(%d) failed", (int)port);
        return rv;
    }
    rv = apr_socket_timeout_set(sock, 0);
    if (rv != APR_SUCCESS)
    {
        apr_socket_close(sock);
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "set nonblocking on %d failed", (int)port);
        return rv;
    }
    apr_os_sock_t os_sock;
    rv = apr_os_sock_get(&os_sock, sock);
    if (rv != APR_SUCCESS)
    {
        apr_socket_close(sock);
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "h3_socket_open: apr_os_sock_get failed");
        return rv;
    }
    *out_fd = (int)os_sock;
    return APR_SUCCESS;
}

void h3_socket_close(int fd)
{
    if (fd >= 0)
    {
        h3_socket_os_close(fd);
    }
}

apr_status_t h3_wakeup_create(apr_pool_t* pool, h3_wakeup* w)
{
    CHECK(pool);
    CHECK(w);
    memset(w, 0, sizeof(*w));
    w->reader_fd = -1;

    apr_sockaddr_t* loopback = NULL;
    apr_status_t rv = apr_sockaddr_info_get(&loopback, "127.0.0.1", APR_INET, 0, 0, pool);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }
    if ((rv = apr_socket_create(&w->reader, APR_INET, SOCK_DGRAM, APR_PROTO_UDP, pool)) != APR_SUCCESS)
    {
        return rv;
    }
    if ((rv = apr_socket_bind(w->reader, loopback)) != APR_SUCCESS)
    {
        return rv;
    }

    /* Ask the reader which port the bind landed on, then aim the writer at it. */
    apr_sockaddr_t* bound = NULL;
    if ((rv = apr_socket_addr_get(&bound, APR_LOCAL, w->reader)) != APR_SUCCESS)
    {
        return rv;
    }
    if ((rv = apr_socket_create(&w->writer, APR_INET, SOCK_DGRAM, APR_PROTO_UDP, pool)) != APR_SUCCESS)
    {
        return rv;
    }
    if ((rv = apr_socket_connect(w->writer, bound)) != APR_SUCCESS)
    {
        return rv;
    }

    if ((rv = apr_socket_timeout_set(w->reader, 0)) != APR_SUCCESS || (rv = apr_socket_timeout_set(w->writer, 0)) != APR_SUCCESS)
    {
        return rv;
    }

    apr_os_sock_t os_sock;
    if ((rv = apr_os_sock_get(&os_sock, w->reader)) != APR_SUCCESS)
    {
        return rv;
    }
    w->reader_fd = (int)os_sock;
    return APR_SUCCESS;
}

void h3_wakeup_signal(h3_wakeup* w)
{
    if (!w || !w->writer)
    {
        return;
    }
    char byte = '1';
    apr_size_t len = 1;
    (void)apr_socket_send(w->writer, &byte, &len);
}

void h3_wakeup_drain(h3_wakeup* w)
{
    if (!w || !w->reader)
    {
        return;
    }
    char buf[64];
    for (;;)
    {
        apr_size_t len = sizeof(buf);
        if (apr_socket_recv(w->reader, buf, &len) != APR_SUCCESS || len == 0)
        {
            return;
        }
    }
}
