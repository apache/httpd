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

/*
 * Written by Bojan Smojver <bojan rexursive.com>.
 */

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "mod_log_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_protocol.h"

module AP_MODULE_DECLARE_DATA logio_module;

static const char logio_filter_name[] = "LOG_INPUT_OUTPUT";

/*
 * Logging of input and output config...
 */

typedef struct logio_config_t {
    apr_off_t bytes_in;
    apr_off_t bytes_out;
    apr_off_t bytes_last_request;
} logio_config_t;

/*
 * Optional function for the core to add to bytes_out
 */

static void ap_logio_add_bytes_out(conn_rec *c, apr_off_t bytes){
    logio_config_t *cf = ap_get_module_config(c->conn_config, &logio_module);

    cf->bytes_out += bytes;
}

/*
 * Optional function for modules to adjust bytes_in
 */

static void ap_logio_add_bytes_in(conn_rec *c, apr_off_t bytes){
    logio_config_t *cf = ap_get_module_config(c->conn_config, &logio_module);

    cf->bytes_in += bytes;
}

/*
 * Optional function to get total byte count of last request for
 * ap_increment_counts.
 */

static apr_off_t ap_logio_get_last_bytes(conn_rec *c)
{
    logio_config_t *cf = ap_get_module_config(c->conn_config, &logio_module);

    return cf->bytes_last_request;
}

/*
 * Format items...
 */

static const char *log_bytes_in(request_rec *r, char *a)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &logio_module);

    return apr_off_t_toa(r->pool, cf->bytes_in);
}

static const char *log_bytes_out(request_rec *r, char *a)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &logio_module);

    return apr_off_t_toa(r->pool, cf->bytes_out);
}

static const char *log_bytes_combined(request_rec *r, char *a)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &logio_module);

    return apr_off_t_toa(r->pool, cf->bytes_out + cf->bytes_in);
}

/*
 * Reset counters after logging...
 */

static int logio_transaction(request_rec *r)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &logio_module);

    /* need to save byte count of last request for ap_increment_counts */
    cf->bytes_last_request = cf->bytes_in + cf->bytes_out;
    cf->bytes_in = cf->bytes_out = 0;

    return OK;
}

/*
 * Logging of input filter...
 */

static apr_status_t logio_in_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes) {
    apr_off_t length;
    apr_status_t status;
    logio_config_t *cf = ap_get_module_config(f->c->conn_config, &logio_module);

    status = ap_get_brigade(f->next, bb, mode, block, readbytes);

    apr_brigade_length (bb, 0, &length);

    if (length > 0)
        cf->bytes_in += length;

    return status;
}

/*
 * The hooks...
 */

static int logio_pre_conn(conn_rec *c, void *csd) {
    logio_config_t *cf = apr_pcalloc(c->pool, sizeof(*cf));

    ap_set_module_config(c->conn_config, &logio_module, cf);

    ap_add_input_filter(logio_filter_name, NULL, NULL, c);

    return OK;
}

static int logio_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "I", log_bytes_in, 0);
        log_pfn_register(p, "O", log_bytes_out, 0);
        log_pfn_register(p, "S", log_bytes_combined, 0);
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char *pre[] = { "mod_log_config.c", NULL };

    ap_hook_pre_connection(logio_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(logio_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(logio_transaction, pre, NULL, APR_HOOK_MIDDLE);

    ap_register_input_filter(logio_filter_name, logio_in_filter, NULL,
                             AP_FTYPE_NETWORK - 1);

    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_out);
    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_in);
    APR_REGISTER_OPTIONAL_FN(ap_logio_get_last_bytes);
}

AP_DECLARE_MODULE(logio) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
