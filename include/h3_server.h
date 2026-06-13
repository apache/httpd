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

#include <openssl/ssl.h>

#include "h3_ssl.h"

int run_quic_server(apr_pool_t* p, server_rec* s, SSL_CTX* ctx, int fd, struct ssl_id* ssl_ids);
int process_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* p);
int server(apr_pool_t* p, server_rec* s, unsigned long port, const char* cert_path, const char* key_path);

#endif /* H3_SERVER_H */
