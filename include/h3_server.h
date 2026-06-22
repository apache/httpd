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

#ifndef H3_SERVER_H
#define H3_SERVER_H

#include <httpd.h>

#include <apr_pools.h>

#include "h3_config.h"

/**
 * ap_child_init hook: bring up the QUIC listener in the first available
 * child process. Idempotent across children: subsequent children detect the
 * port is already owned and skip socket creation.
 * @param pchild The child process pool.
 * @param s      The server_rec for the listener's vhost.
 */
void h3_child_init(apr_pool_t* pchild, server_rec* s);

/**
 * Child-stop hook: tear down the QUIC listener, join worker threads, and
 * release the SSL context. No-op if the child never owned the listener.
 * @param pool     The pool used for any teardown allocations.
 * @param graceful Non-zero for a graceful stop, zero for immediate.
 */
void h3_c1_child_stopping(apr_pool_t* pool, int graceful);

#endif /* H3_SERVER_H */
