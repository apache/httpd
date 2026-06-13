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

#ifndef H3_POLL_H
#define H3_POLL_H

#include <httpd.h>

#include <apr_pools.h>

#include <openssl/ssl.h>

#include "h3_ssl.h"

int read_from_ssl_ids(struct ssl_id* ssl_ids, struct activeh3ssl* activeh3ssl, apr_pool_t* p, server_rec* s);
void handle_events_from_ids(struct ssl_id* ssl_ids, server_rec* s);
int wait_for_activity(server_rec* s, SSL* ssl);

#endif /* H3_POLL_H */
