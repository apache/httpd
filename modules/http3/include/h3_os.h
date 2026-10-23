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

#ifndef H3_OS_H
#define H3_OS_H

/* Socket headers, and the names that differ across platforms. */

#if defined(_WIN32)

    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>

    #include <ws2tcpip.h>

    #include <process.h>

#else

    #include <netdb.h>
    #include <netinet/in.h>
    #include <poll.h>
    #include <sys/socket.h>
    #include <unistd.h>

#endif

#include <apr_errno.h>

/** Mark a parameter as deliberately unused. */
#if defined(__GNUC__) || defined(__clang__)
    #define H3_UNUSED __attribute__((unused))
#else
    #define H3_UNUSED
#endif

/* WSAPoll matches poll() field for field here, but counts with ULONG. */
#if defined(_WIN32)
    #define h3_poll WSAPoll
    #define h3_getpid _getpid
typedef ULONG h3_nfds_t;
#else
    #define h3_poll poll
    #define h3_getpid getpid
typedef nfds_t h3_nfds_t;
#endif

/**
 * Close a socket by its OS-level descriptor.
 * @param fd Descriptor to close; already known to be valid.
 */
void h3_socket_os_close(int fd);

/**
 * Whether an APR status is this platform's "address already in use".
 * @param rv Status returned by apr_socket_bind.
 * @return Non-zero when the port is already bound.
 */
int h3_socket_os_is_eaddrinuse(apr_status_t rv);

#endif /* H3_OS_H */
