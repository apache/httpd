/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
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
    H2_CONF_SESSION_FILES,
    H2_CONF_MODERN_TLS_ONLY,
    H2_CONF_UPGRADE,
    H2_CONF_TLS_WARMUP_SIZE,
    H2_CONF_TLS_COOLDOWN_SECS,
    H2_CONF_PUSH,
    H2_CONF_PUSH_DIARY_SIZE,
    H2_CONF_COPY_FILES,
    H2_CONF_EARLY_HINTS,
} h2_config_var_t;

struct apr_hash_t;
struct h2_priority;
struct h2_push_res;

typedef struct h2_push_res {
    const char *uri_ref;
    int critical;
} h2_push_res;

/* Apache httpd module configuration for h2. */
typedef struct h2_config {
    const char *name;
    int h2_max_streams;           /* max concurrent # streams (http2) */
    int h2_window_size;           /* stream window size (http2) */
    int min_workers;              /* min # of worker threads/child */
    int max_workers;              /* max # of worker threads/child */
    int max_worker_idle_secs;     /* max # of idle seconds for worker */
    int stream_max_mem_size;      /* max # bytes held in memory/stream */
    apr_array_header_t *alt_svcs; /* h2_alt_svc specs for this server */
    int alt_svc_max_age;          /* seconds clients can rely on alt-svc info*/
    int serialize_headers;        /* Use serialized HTTP/1.1 headers for 
                                     processing, better compatibility */
    int h2_direct;                /* if mod_h2 is active directly */
    int session_extra_files;      /* # of extra files a session may keep open */  
    int modern_tls_only;          /* Accept only modern TLS in HTTP/2 connections */  
    int h2_upgrade;               /* Allow HTTP/1 upgrade to h2/h2c */
    apr_int64_t tls_warmup_size;  /* Amount of TLS data to send before going full write size */
    int tls_cooldown_secs;        /* Seconds of idle time before going back to small TLS records */
    int h2_push;                  /* if HTTP/2 server push is enabled */
    struct apr_hash_t *priorities;/* map of content-type to h2_priority records */
    
    int push_diary_size;          /* # of entries in push diary */
    int copy_files;               /* if files shall be copied vs setaside on output */
    apr_array_header_t *push_list;/* list of h2_push_res configurations */
    int early_hints;              /* support status code 103 */
} h2_config;


void *h2_config_create_dir(apr_pool_t *pool, char *x);
void *h2_config_merge_dir(apr_pool_t *pool, void *basev, void *addv);
void *h2_config_create_svr(apr_pool_t *pool, server_rec *s);
void *h2_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);

extern const command_rec h2_cmds[];

const h2_config *h2_config_get(conn_rec *c);
const h2_config *h2_config_sget(server_rec *s);
const h2_config *h2_config_rget(request_rec *r);

int h2_config_geti(const h2_config *conf, h2_config_var_t var);
apr_int64_t h2_config_geti64(const h2_config *conf, h2_config_var_t var);

void h2_config_init(apr_pool_t *pool);

const struct h2_priority *h2_config_get_priority(const h2_config *conf, 
                                                 const char *content_type);
       
#endif /* __mod_h2__h2_config_h__ */

