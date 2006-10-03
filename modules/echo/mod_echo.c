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

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"

#include "apr_buckets.h"
#include "util_filter.h"

module AP_MODULE_DECLARE_DATA echo_module;

typedef struct {
    int bEnabled;
} EchoConfig;

static void *create_echo_server_config(apr_pool_t *p, server_rec *s)
{
    EchoConfig *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;

    return pConfig;
}

static const char *echo_on(cmd_parms *cmd, void *dummy, int arg)
{
    EchoConfig *pConfig = ap_get_module_config(cmd->server->module_config,
                                               &echo_module);
    pConfig->bEnabled = arg;

    return NULL;
}

static int process_echo_connection(conn_rec *c)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    apr_status_t rv;
    EchoConfig *pConfig = ap_get_module_config(c->base_server->module_config,
                                               &echo_module);

    if (!pConfig->bEnabled) {
        return DECLINED;
    }

    do {
        bb = apr_brigade_create(c->pool, c->bucket_alloc);

        /* Get a single line of input from the client */
        if (((rv = ap_get_brigade(c->input_filters, bb, AP_MODE_GETLINE,
                                 APR_BLOCK_READ, 0)) != APR_SUCCESS) ||
             APR_BRIGADE_EMPTY(bb)) {
            apr_brigade_destroy(bb);
            break;
        }

        /* Make sure the data is flushed to the client */
        b = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        /* Send back the data. */
        rv = ap_pass_brigade(c->output_filters, bb);
    } while (rv == APR_SUCCESS);

    return OK;
}

static const command_rec echo_cmds[] =
{
    AP_INIT_FLAG("ProtocolEcho", echo_on, NULL, RSRC_CONF,
                 "Run an echo server on this host"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_process_connection(process_echo_connection, NULL, NULL,
                               APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA echo_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_echo_server_config,  /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    echo_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};
