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
#include <http_request.h>

#include <apr_network_io.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "h3_conn.h"
#include "h3_private.h"

h3_conn_rec_t* create_connection(apr_pool_t* p, server_rec* s)
{
    h3_conn_rec_t* c3;
    conn_rec* c;
    apr_pool_t* pool;
    apr_sockaddr_t* fake_from;
    apr_sockaddr_t* fake_local;
    apr_pool_create(&pool, p);
    apr_pool_tag(pool, "h3_c_conn");
    c = (conn_rec*)apr_palloc(pool, sizeof(conn_rec));
    c->pool = pool;
    c->base_server = s;
    c->conn_config = ap_create_conn_config(pool);
    c->notes = apr_table_make(pool, 5);
    c->input_filters = NULL;
    c->output_filters = NULL;
    c->keepalives = 0;
    c->filter_conn_ctx = NULL;
    c->bucket_alloc = apr_bucket_alloc_create(pool);
    /* prevent mpm_event from making wrong assumptions about this connection,
     * like e.g. using its socket for an async read check. */
    c->clogging_input_filters = 1;
    c->log = NULL;
    c->aborted = 0;

    /* We cannot install the master connection socket on the secondary, as
     * modules mess with timeouts/blocking of the socket, with
     * unwanted side effects to the master connection processing.
     * Fortunately, since we never use the secondary socket, we can just install
     * a single, process-wide dummy and everyone is happy.
     */
    /* TODO: these should be unique to this thread */
    c->sbh = NULL;
    /* Use a fake local_addr and client_addr for the moment */
    apr_sockaddr_info_get(&fake_from, "127.0.0.1", APR_INET, 4242, 0, pool);
    apr_sockaddr_info_get(&fake_local, "127.0.0.1", APR_INET, 4242, 0, pool);
    c->local_addr = fake_local;
    c->client_addr = fake_from;
    c->client_ip = "127.0.0.1"; // Prevent core in ap_log_cerror?
    c->remote_host = "localhost";
    apr_table_set(c->notes, "IS_mod_http3", "1");

    c3 = (h3_conn_rec_t*)apr_palloc(pool, sizeof(h3_conn_rec_t));
    c3->c = c;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "c3 created");
    return c3;
}

apr_status_t process_connection(apr_pool_t* /*p*/, server_rec* s, conn_rec* c)
{

    /* We need to process the connection we have created */
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_connection");
    c->master = NULL; /* reset it */
    c->cs = NULL;
    ap_run_pre_connection(c, &dummy_socket);
    ap_run_process_connection(c);

    return APR_SUCCESS;
}

apr_status_t process_request(request_rec* r, h3_conn_ctx_t* h3ctx)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "process_request before ap_process_request(%s)", r->uri);
    r->proxyreq = 0;
    r->filename = NULL;
    r->per_dir_config = ap_create_per_dir_config(r->pool);
    r->per_dir_config = ap_merge_per_dir_configs(r->pool, r->server->lookup_defaults, r->per_dir_config);
    ap_set_module_config(r->request_config, &http3_module, h3ctx);
    if (!r->the_request && r->method && r->uri && r->protocol)
    {
        r->the_request = apr_psprintf(r->pool, "%s %s %s", r->method, r->uri, r->protocol);
    }
    ap_process_request(r);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "process_request after ap_process_request()");
    return OK;
}
