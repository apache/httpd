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
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <mpm_common.h>

#include <apr_strings.h>

#include <unistd.h>

#include "h3_config.h"
#include "h3_conn.h"
#include "h3_filter.h"
#include "h3_hooks.h"
#include "h3_private.h"
#include "h3_server.h"
#include "mod_http3.h"

ap_filter_rec_t* h3_net_out_filter_handle;
ap_filter_rec_t* h3_net_in_filter_handle;
ap_filter_rec_t* h3_proto_out_filter_handle;
ap_filter_rec_t* h3_proto_in_filter_handle;

apr_socket_t* dummy_socket;

void* APR_THREAD_FUNC worker_thread_main(apr_thread_t* /*thread*/, void* data)
{
    struct h3_stuff* h3 = (struct h3_stuff*)data;
    apr_pool_t* pool;
    server_rec* s = h3->s;
    apr_pool_create(&pool, h3->pchild);
    apr_pool_tag(pool, "h3_main");
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "worker_thread_main");
    server(pool, s, h3->conf->host_port, h3->conf->cert_path, h3->conf->key_path);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "worker_thread_main exited!");
    return NULL;
}

void h3_child_init(apr_pool_t* pchild, server_rec* s)
{
    apr_status_t rv;
    apr_thread_t* worker_thread;
    struct h3_stuff* h3;
    h3_server_conf* conf;

    /* Find the server config with cert/key configured */
    server_rec* current_server = s;
    conf = NULL;
    while (current_server)
    {
        h3_server_conf* tmp_conf = ap_get_module_config(current_server->module_config, &http3_module);
        if (tmp_conf->cert_path && tmp_conf->key_path)
        {
            conf = tmp_conf;
            break;
        }
        current_server = current_server->next;
    }

    h3 = apr_palloc(pchild, sizeof(struct h3_stuff));
    h3->pchild = pchild;
    h3->s = s;
    h3->conf = conf;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "h3_child_init");
    rv = apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP, pchild);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "h3_child_init: Failed to create dummy socket: %d", rv);
    }
    rv = ap_thread_create(&worker_thread, NULL, worker_thread_main, (void*)h3, pchild);
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "h3_child_init: Failed to create worker thread: %d", rv);
    }
}

static void register_hooks(apr_pool_t* /*p*/)
{
    ap_hook_post_config(h3_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(h3_hook_pre_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_process_connection(h3_hook_process_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_create_request(h3_hook_http_create_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_pre_read_request(h3_hook_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(h3_hook_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    h3_net_out_filter_handle = ap_register_output_filter("H3_NET_OUT", h3_filter_out, NULL, AP_FTYPE_NETWORK);
    h3_net_in_filter_handle = ap_register_input_filter("H3_NET_IN", h3_filter_in, NULL, AP_FTYPE_NETWORK);

    h3_proto_out_filter_handle = ap_register_output_filter("H3_NET_OUT_PROTO", h3_filter_out_proto, NULL, AP_FTYPE_PROTOCOL);

    h3_proto_in_filter_handle = ap_register_input_filter("H3_NET_IN_PROTO", h3_filter_in_proto, NULL, AP_FTYPE_PROTOCOL);
    ap_hook_insert_filter(h3_filter_last, NULL, NULL, APR_HOOK_LAST);

    ap_hook_child_init(h3_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_stopping(h3_c1_child_stopping, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef AP_HAS_RESPONSE_BUCKETS
    #error Not supported for the moment.
#endif
}

HTTP3_PUBLIC module http3_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                    /* create per-directory config structure */
    NULL,                    /* merge per-directory config structures */
    h3_create_server_config, /* create per-server config structure */
    h3_merge_server_config,  /* merge per-server config structures */
    h3_cmds,                 /* command apr_table_t */
    register_hooks,          /* register hooks */
    AP_MODULE_FLAG_NONE      /* flags */
};
