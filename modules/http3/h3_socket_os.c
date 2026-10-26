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

#include "h3_os.h"

#ifndef _WIN32
    #include <errno.h>
#endif

void h3_socket_os_close(int fd)
{
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

int h3_socket_os_is_eaddrinuse(apr_status_t rv)
{
#ifdef _WIN32
    return rv == APR_FROM_OS_ERROR(WSAEADDRINUSE);
#else
    return rv == APR_FROM_OS_ERROR(EADDRINUSE);
#endif
}
