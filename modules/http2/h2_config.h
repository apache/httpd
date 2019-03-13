/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __mod_h2__h2_config_h__
#define __mod_h2__h2_config_h__

#undef PACKAGE_VERSION
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT

typedef enum {
    H2_CONF_MAX_STREAMS,
    H2_CONF_WIN_SIZE,
    H2_CONF_MIN_WORKERS,
    H2_CONF_MAX_WORKERS,
    H2_CONF_MAX_WORKER_IDLE_SECS,
    H2_CONF_STREAM_MAX_MEM,
    H2_CONF_ALT_SVCS,
    H2_CONF_ALT_SVC_MAX_AGE,
    H2_CONF_SER_HEADERS,
    H2_CONF_DIRECT,
    H2_CONF_MODERN_TLS_ONLY,
    H2_CONF_UPGRADE,
    H2_CONF_TLS_WARMUP_SIZE,
    H2_CONF_TLS_COOLDOWN_SECS,
    H2_CONF_PUSH,
    H2_CONF_PUSH_DIARY_SIZE,
    H2_CONF_COPY_FILES,
    H2_CONF_EARLY_HINTS,
    H2_CONF_PADDING_BITS,
    H2_CONF_PADDING_ALWAYS,
} h2_config_var_t;

struct apr_hash_t;
struct h2_priority;
struct h2_push_res;

typedef struct h2_push_res {
    const char *uri_ref;
    int critical;
} h2_push_res;


void *h2_config_create_dir(apr_pool_t *pool, char *x);
void *h2_config_merge_dir(apr_pool_t *pool, void *basev, void *addv);
void *h2_config_create_svr(apr_pool_t *pool, server_rec *s);
void *h2_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);

extern const command_rec h2_cmds[];

int h2_config_geti(request_rec *r, server_rec *s, h2_config_var_t var);
apr_int64_t h2_config_geti64(request_rec *r, server_rec *s, h2_config_var_t var);

/** 
 * Get the configured value for variable <var> at the given connection.
 */
int h2_config_cgeti(conn_rec *c, h2_config_var_t var);
apr_int64_t h2_config_cgeti64(conn_rec *c, h2_config_var_t var);

/** 
 * Get the configured value for variable <var> at the given server.
 */
int h2_config_sgeti(server_rec *s, h2_config_var_t var);
apr_int64_t h2_config_sgeti64(server_rec *s, h2_config_var_t var);

/** 
 * Get the configured value for variable <var> at the given request,
 * if configured for the request location. 
 * Fallback to request server config otherwise.
 */
int h2_config_rgeti(request_rec *r, h2_config_var_t var);
apr_int64_t h2_config_rgeti64(request_rec *r, h2_config_var_t var);

apr_array_header_t *h2_config_push_list(request_rec *r);
apr_array_header_t *h2_config_alt_svcs(request_rec *r);


void h2_get_num_workers(server_rec *s, int *minw, int *maxw);
void h2_config_init(apr_pool_t *pool);

const struct h2_priority *h2_cconfig_get_priority(conn_rec *c, const char *content_type);
       
#endif /* __mod_h2__h2_config_h__ */

