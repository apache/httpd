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

#ifndef MOD_HTTP3_H
#define MOD_HTTP3_H

#include <httpd.h>

#include <apr_network_io.h>
#include <apr_thread_proc.h>

#include "h3_config.h"

struct h3_stuff
{
    apr_pool_t* pchild;
    server_rec* s;
    h3_server_conf* conf;
};

extern apr_socket_t* dummy_socket;

void* APR_THREAD_FUNC worker_thread_main(apr_thread_t* thread, void* data);
void h3_child_init(apr_pool_t* pchild, server_rec* s);

#endif /* MOD_HTTP3_H */
