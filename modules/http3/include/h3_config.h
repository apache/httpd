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

#ifndef H3_CONFIG_H
#define H3_CONFIG_H

#include <httpd.h>

#include <http_config.h>

extern const command_rec h3_cmds[];

typedef struct h3_server_conf h3_server_conf;

typedef enum
{
    H3_FLAG_UNSET = 0,
    H3_FLAG_ON,
    H3_FLAG_OFF
} h3_tri_flag;

struct h3_server_conf
{
    apr_port_t host_port;

    /** QUIC TLS context, built from mod_ssl's certificate when the host lists h3 in Protocols. */
    struct ssl_ctx_st* ssl_ctx;

    apr_port_t h3_port;
    apr_uint32_t h3_max_concurrent_streams;
    apr_uint32_t h3_max_connections;
    apr_size_t h3_stream_buffer_size;
    apr_size_t h3_max_request_body_size;
    apr_size_t h3_max_response_body_size;
    h3_tri_flag h3_alt_svc;
    h3_tri_flag h3_address_validation;
    apr_uint32_t h3_alt_svc_max_age;
    apr_uint32_t h3_handshake_timeout;
    apr_uint32_t h3_idle_timeout;
    apr_size_t h3_socket_buffer_size;
    h3_tri_flag h3_session_tickets;
    h3_tri_flag h3_early_data;
    apr_uint32_t h3_stream_timeout;
    apr_uint32_t h3_max_stream_errors;
    int h3_qpack_capacity_set;
    int h3_qpack_blocked_set;
    apr_uint32_t h3_qpack_table_capacity;
    apr_uint32_t h3_qpack_blocked_streams;
    apr_uint32_t h3_min_workers;
    apr_uint32_t h3_max_workers;
    apr_uint32_t h3_max_worker_idle_seconds;
};

/**
 * Look up the TCP Listen port of a vhost by scanning its `Port` and
 * `Listen` directive state.
 * @param s The server_rec.
 * @return The TCP port, or 0 if undetermined.
 */
apr_port_t get_server_port(const server_rec* s);

/**
 * ap_create_server_config callback: allocate a fresh zero-initialised
 * h3_server_conf from @p p. All fields start as NULL/0.
 * @param p Pool used for the allocation.
 * @param s The vhost the config belongs to (unused).
 * @return The new h3_server_conf.
 */
void* h3_create_server_config(apr_pool_t* p, server_rec* s);

/**
 * ap_merge_server_config callback: produce a child vhost config that
 * inherits each unset field from the parent.
 * @param p         Pool for the merged config.
 * @param base_conf Parent h3_server_conf.
 * @param new_conf  Child h3_server_conf.
 * @return The merged h3_server_conf.
 */
void* h3_merge_server_config(apr_pool_t* p, void* base_conf, void* new_conf);

/**
 * ap_create_dir_config callback. mod_http3 has no per-directory state;
 * returns a 1-byte allocation so httpd takes ownership of a non-NULL
 * pointer.
 * @param p   Pool for the allocation.
 * @param dir The directory path (unused).
 * @return A 1-byte zero-initialised block.
 */
void* h3_create_dir_config(apr_pool_t* p, char* dir);

/**
 * ap_merge_dir_config callback. Identity merge: per-directory config is
 * a no-op for mod_http3, so the base is returned unchanged.
 * @param p    Pool for any allocation (unused).
 * @param base Base per-dir config.
 * @param add  Per-dir config being merged in (unused).
 * @return The base per-dir config.
 */
void* h3_merge_dir_config(apr_pool_t* p, void* base, void* add);

/**
 * ap_ssl_add_cert_files hook: mod_ssl runs it for every SSLEngine vhost with
 * the certificate and key files it is about to load (SSLCertificateFile plus
 * anything mod_md added). When the vhost lists h3 in Protocols, builds its
 * QUIC TLS context from them, here, before the server drops privileges.
 * @param s          The vhost being configured.
 * @param p          Config pool; owns the context.
 * @param cert_files Certificate chain files, const char* elements.
 * @param key_files  Private key files, const char* elements.
 * @return DECLINED, or HTTP_INTERNAL_SERVER_ERROR if the files do not load.
 */
int h3_ssl_add_cert_files(server_rec* s, apr_pool_t* p, apr_array_header_t* cert_files, apr_array_header_t* key_files);

/**
 * ap_post_config hook: fill in defaults on every vhost that serves HTTP/3;
 * the first one owns the listener, and an SNI callback swaps in each other
 * host's certificate by name. No-op in AP_SQ_MS_CREATE_PRE_CONFIG.
 * @param p     Config pool; owns the SNI host table.
 * @param plog  Log pool (unused).
 * @param ptemp Temp pool (unused).
 * @param s     The first server_rec in the configuration.
 * @return OK, or HTTP_INTERNAL_SERVER_ERROR if no vhost serves HTTP/3.
 */
int h3_post_config(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp, server_rec* s);

#endif /* H3_CONFIG_H */
