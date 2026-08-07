/*
 * Copyright (c) 2023-2026 The mod_http3 Project Authors. All rights reserved.
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
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_ssl.h>
#include <mpm_common.h>

#include <apr_pools.h>

#include "h3_config.h"
#include "h3_filter.h"
#include "h3_hooks.h"
#include "h3_os.h"
#include "h3_server.h"
#include "mod_http3.h"

static void register_hooks(apr_pool_t* p H3_UNUSED)
{
    ap_hook_handler(h3_status_handler, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_post_config(h3_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(h3_hook_http_create_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_pre_read_request(h3_hook_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(h3_hook_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_access_checker(h3_hook_access_checker, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(h3_hook_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_scheme(h3_hook_http_scheme, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(h3_hook_default_port, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_ssl_conn_is_ssl(h3_hook_ssl_conn_is_ssl, NULL, NULL, APR_HOOK_MIDDLE);

    h3_net_out_filter_handle = ap_register_output_filter("H3_NET_OUT", h3_filter_out, NULL, AP_FTYPE_NETWORK);
    h3_net_in_filter_handle = ap_register_input_filter("H3_NET_IN", h3_filter_in, NULL, AP_FTYPE_NETWORK);

    h3_proto_out_filter_handle = ap_register_output_filter("H3_NET_OUT_PROTO", h3_filter_out_proto, NULL, AP_FTYPE_PROTOCOL);

    h3_proto_in_filter_handle = ap_register_input_filter("H3_NET_IN_PROTO", h3_filter_in_proto, NULL, AP_FTYPE_PROTOCOL);

    ap_hook_child_init(h3_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_stopping(h3_c1_child_stopping, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef AP_HAS_RESPONSE_BUCKETS
    #error Not supported for the moment.
#endif
}

HTTP3_PUBLIC module http3_module = {
    STANDARD20_MODULE_STUFF,
    h3_create_dir_config,    /* create per-directory config structure */
    h3_merge_dir_config,     /* merge per-directory config structures */
    h3_create_server_config, /* create per-server config structure */
    h3_merge_server_config,  /* merge per-server config structures */
    h3_cmds,                 /* command apr_table_t */
    register_hooks,          /* register hooks */
    AP_MODULE_FLAG_NONE      /* flags */
};
