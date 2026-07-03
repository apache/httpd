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

#include "h3_config.h"
#include <httpd.h>

#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_vhost.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_filter.h"
#include "h3_hooks.h"
#include "h3_session.h"
#include "mod_http3.h"

int h3_hook_fixups(request_rec* r)
{
    CHECK(r);
    if (!ap_is_initial_req(r))
    {
        return DECLINED;
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

void h3_hook_pre_read_request(request_rec* /*r*/, conn_rec* /*c*/)
{
}

int h3_hook_access_checker(request_rec* r)
{
    CHECK(r);
    if (!IS_H3_REQUEST(r))
    {
        return DECLINED;
    }
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
