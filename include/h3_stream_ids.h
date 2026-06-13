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

#ifndef H3_STREAM_IDS_H
#define H3_STREAM_IDS_H

#include <httpd.h>

#include <apr_pools.h>

#include <openssl/ssl.h>

#include "h3_ssl.h"

void init_ids(struct ssl_id* ssl_ids);

int add_id_status(uint64_t id, SSL* ssl, struct ssl_id* ssl_ids, int status, struct h3ssl* h3ssl);
int add_id(uint64_t id, SSL* ssl, struct ssl_id* ssl_ids, struct h3ssl* h3ssl);
int add_ids_listener(SSL* ssl, struct ssl_id* ssl_ids);
int add_ids_connection(struct ssl_id* ssl_ids, SSL* ssl, struct h3ssl* h3ssl);

SSL* get_ids_connection(struct ssl_id* ssl_ids, struct h3ssl* h3ssl);
void clean_ids_connection(struct ssl_id* ssl_ids, struct h3ssl* h3ssl);

void ssl_ids_store607(struct ssl_id* ssl_ids, uint64_t id, struct h3ssl* h3ssl);
int ssl_ids_get607(struct ssl_id* ssl_ids, uint64_t id, struct h3ssl* h3ssl);

void check_finish_ids(struct ssl_id* ssl_ids, server_rec* s);
struct h3ssl* get_h3ssl_ssl(struct ssl_id* ssl_ids, SSL* ssl);
void reset_active_h3ssl(struct activeh3ssl* activeh3ssl);
void add_active_h3ssl(struct activeh3ssl* activeh3ssl, struct h3ssl* h3ssl);
struct h3ssl* next_active_h3ssl(struct activeh3ssl* activeh3ssl);
void remove_marked_ids(struct ssl_id* ssl_ids);
void set_id_status(uint64_t id, int status, struct ssl_id* ssl_ids);
int get_id_status(uint64_t id, struct ssl_id* ssl_ids);
int are_all_clientid_closed(struct h3ssl* h3ssl, struct ssl_id* ssl_ids);

void close_all_ids(struct h3ssl* h3ssl, struct ssl_id* ssl_ids);
void close_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* p);
void clean_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* p);

#endif /* H3_STREAM_IDS_H */
