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

#ifndef H3_CONFIG_H
#define H3_CONFIG_H

#include <httpd.h>

#include <http_config.h>

#include <apr_pools.h>

/* Server configuration structure */
typedef struct
{
    const char* cert_path;
    const char* key_path;
    apr_port_t host_port;
} h3_server_conf;

void* h3_create_server_config(apr_pool_t* p, server_rec* s);
void* h3_merge_server_config(apr_pool_t* p, void* base_conf, void* new_conf);
int h3_post_config(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp, server_rec* s);
extern const command_rec h3_cmds[];

#endif /* H3_CONFIG_H */
