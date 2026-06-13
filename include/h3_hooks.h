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

#ifndef H3_HOOKS_H
#define H3_HOOKS_H

#include <httpd.h>

int h3_hook_process_connection(conn_rec* c);
int h3_hook_pre_connection(conn_rec* c, void* csd);
int h3_hook_post_read_request(request_rec* r);
void h3_hook_pre_read_request(request_rec* r, conn_rec* c);
int h3_hook_http_create_request(request_rec* r);
void h3_filter_last(request_rec* r);
void h3_c1_child_stopping(apr_pool_t* pool, int graceful);

#endif /* H3_HOOKS_H */
