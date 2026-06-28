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
#include <http_vhost.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_filter.h"
#include "h3_hooks.h"
#include "mod_http3.h"

int h3_hook_post_read_request(request_rec* r)
{
    (void)r;
    return OK;
}

void h3_hook_pre_read_request(request_rec* r, conn_rec* c)
{
    (void)r;
    (void)c;
}

int h3_hook_access_checker(request_rec* r)
{
    return IS_H3_REQUEST(r) ? OK : DECLINED;
}

int h3_hook_http_create_request(request_rec* r)
{
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
