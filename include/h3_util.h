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

#ifndef H3_UTIL_H
#define H3_UTIL_H

#include <apr_pools.h>

#include <nghttp3/nghttp3.h>

#include "h3_ssl.h"

void make_nv(nghttp3_nv* nv, const char* name, const char* value);
char* get_openssl_error_string(apr_pool_t* p);
void ERR_print_errors_log(struct h3ssl* h3ssl);

#endif /* H3_UTIL_H */
