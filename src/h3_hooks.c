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
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include "h3_filter.h"
#include "h3_hooks.h"

int h3_hook_process_connection(conn_rec* c)
{
    const char* is_mod_http3 = apr_table_get(c->notes, "IS_mod_http3");
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "h3_hook_process_connection %s", is_mod_http3);
    if (is_mod_http3 == NULL)
        return DECLINED;
    return OK;
}

int h3_hook_pre_connection(conn_rec* c, void* /*csd*/)
{
    const char* is_mod_http3 = apr_table_get(c->notes, "IS_mod_http3");
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "h3_hook_pre_connection %s", is_mod_http3);
    if (is_mod_http3 == NULL)
        return DECLINED;
    return OK;
}

int h3_hook_post_read_request(request_rec* r)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_ap_hook_post_read_request");
    return OK;
}

void h3_hook_pre_read_request(request_rec* r, conn_rec* /*c*/)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_ap_hook_pre_read_request");
}

int h3_hook_http_create_request(request_rec* r)
{
    const char* is_mod_http3 = apr_table_get(r->connection->notes, "IS_mod_http3");
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_http_create_request %s", is_mod_http3);
    if (is_mod_http3 == NULL)
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_http_create_request status %d", r->status);
    if (r->main != NULL)
    {
        return DECLINED;
    }

    /* Add the filter for the response here */
    ap_add_input_filter_handle(h3_proto_in_filter_handle, NULL, r, r->connection);
    ap_add_input_filter_handle(h3_net_in_filter_handle, NULL, NULL, r->connection);
    ap_add_output_filter_handle(h3_net_out_filter_handle, NULL, NULL, r->connection);

    return OK;
}

void h3_filter_last(request_rec* r)
{
    const char* is_mod_http3 = apr_table_get(r->connection->notes, "IS_mod_http3");
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_filter_last %s", is_mod_http3);
    if (is_mod_http3 == NULL)
        return;
    ap_add_output_filter_handle(h3_proto_out_filter_handle, NULL, r, r->connection); /* HACKING */
}

void h3_c1_child_stopping(apr_pool_t* /*pool*/, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, NULL, "h3_c1_child_stopping %d", graceful);
}
