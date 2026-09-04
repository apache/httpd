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

#include <httpd.h>

#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_ssl.h>
#include <http_vhost.h>

#include <apr_atomic.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_filter.h"
#include "h3_hooks.h"
#include "h3_io.h"
#include "h3_os.h"
#include "h3_session.h"
#include "mod_http3.h"

const char* h3_hook_http_scheme(const request_rec* r)
{
    return IS_H3_REQUEST(r) ? "https" : NULL;
}

apr_port_t h3_hook_default_port(const request_rec* r)
{
    return IS_H3_REQUEST(r) ? APR_URI_HTTPS_DEFAULT_PORT : 0;
}

int h3_hook_ssl_conn_is_ssl(conn_rec* c)
{
    return IS_H3_CONN(c) ? OK : DECLINED;
}

int h3_hook_fixups(request_rec* r)
{
    if (!ap_is_initial_req(r))
    {
        return DECLINED;
    }

    if (IS_H3_REQUEST(r))
    {
        /* mod_ssl does not manage this connection, so it publishes no TLS environment. */
        apr_table_setn(r->subprocess_env, "HTTPS", "on");

        h3_conn_ctx_t* ctx = ap_get_module_config(r->request_config, &http3_module);
        const h3_tls_env* tls = (ctx && ctx->stream && ctx->stream->session) ? &ctx->stream->session->tls_env : NULL;
        if (tls && tls->protocol)
        {
            apr_table_setn(r->subprocess_env, "SSL_PROTOCOL", tls->protocol);
            apr_table_setn(r->subprocess_env, "SSL_CIPHER", tls->cipher);
            apr_table_setn(r->subprocess_env, "SSL_CIPHER_USEKEYSIZE", tls->cipher_usekeysize);
            apr_table_setn(r->subprocess_env, "SSL_CIPHER_ALGKEYSIZE", tls->cipher_algkeysize);
            apr_table_setn(r->subprocess_env, "SSL_CIPHER_EXPORT", tls->cipher_export);
            apr_table_setn(r->subprocess_env, "SSL_SESSION_RESUMED", tls->session_resumed);
        }
    }

    h3_server_conf* conf = ap_get_module_config(r->server->module_config, &http3_module);

    if (!conf || !conf->h3_cert_path || !conf->h3_key_path || conf->h3_port == 0)
    {
        return DECLINED;
    }

    if (conf->h3_alt_svc == H3_FLAG_OFF)
    {
        return DECLINED;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "h3_hook_fixups called");

    if (apr_table_get(r->headers_out, "Alt-Svc"))
    {
        return DECLINED;
    }

    apr_table_setn(r->headers_out, "Alt-Svc", apr_psprintf(r->pool, "h3=\":%d\"; ma=%u; persist=1", (int)conf->h3_port, (unsigned)conf->h3_alt_svc_max_age));
    return OK;
}

int h3_hook_post_read_request(request_rec* r)
{
    CHECK(r);
    if (!IS_H3_REQUEST(r))
    {
        return DECLINED;
    }
    r->protocol = "HTTP/3.0";
    r->proto_num = HTTP_VERSION(3, 0);
    return OK;
}

void h3_hook_pre_read_request(request_rec* r H3_UNUSED, conn_rec* c H3_UNUSED)
{
}

int h3_hook_access_checker(request_rec* r)
{
    if (!IS_H3_REQUEST(r))
    {
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "h3_hook_access_checker called");
    /* Reject unprocessable bodies early. */
    h3_conn_ctx_t* ctx = ap_get_module_config(r->request_config, &http3_module);
    h3_stream* stream = ctx ? ctx->stream : NULL;
    if (stream && stream->request_body_overflow)
    {
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    if (stream && stream->body_truncated)
    {
        return HTTP_BAD_REQUEST;
    }
    return OK;
}

int h3_hook_http_create_request(request_rec* r)
{
    CHECK(r);
    if (!IS_H3_REQUEST(r) || r->main != NULL)
    {
        return DECLINED;
    }
    ap_add_input_filter_handle(h3_proto_in_filter_handle, NULL, r, r->connection);
    ap_add_input_filter_handle(h3_net_in_filter_handle, NULL, NULL, r->connection);
    ap_add_output_filter_handle(h3_net_out_filter_handle, NULL, NULL, r->connection);
    r->output_filters = r->connection->output_filters;
    r->proto_output_filters = r->connection->output_filters;
    return OK;
}

int h3_status_handler(request_rec* r)
{
    if (strcmp(r->handler, "http3-status"))
    {
        return DECLINED;
    }

    if (r->method_number != M_GET)
    {
        return DECLINED;
    }

    ap_set_content_type(r, "application/json");

    if (!child_h3_io)
    {
        ap_rputs("{\"error\": \"HTTP/3 not enabled or initialized on this child process\"}\n", r);
        return OK;
    }

    apr_uint32_t live = apr_atomic_read32(&child_h3_io->active_session_count);
    apr_uint32_t conns = apr_atomic_read32(&child_h3_io->total_connections);
    apr_uint32_t streams = apr_atomic_read32(&child_h3_io->total_streams);
    apr_uint64_t bytes_in = apr_atomic_read64(&child_h3_io->total_bytes_read);
    apr_uint64_t bytes_out = apr_atomic_read64(&child_h3_io->total_bytes_written);

    ap_rprintf(r,
               "{\n"
               "  \"live_workers\": %u,\n"
               "  \"total_connections\": %u,\n"
               "  \"total_streams\": %u,\n"
               "  \"total_bytes_read\": %" APR_UINT64_T_FMT ",\n"
               "  \"total_bytes_written\": %" APR_UINT64_T_FMT "\n"
               "}\n",
               live, conns, streams, bytes_in, bytes_out);

    return OK;
}
