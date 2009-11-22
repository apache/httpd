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

#include "apr_strings.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_protocol.h"   /* For index_of_response().  Grump. */
#include "http_request.h"

#include "util_filter.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#include "mod_core.h"

/* Handles for core filters */
AP_DECLARE_DATA ap_filter_rec_t *ap_http_input_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_http_header_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_chunk_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_http_outerror_filter_handle;
AP_DECLARE_DATA ap_filter_rec_t *ap_byterange_filter_handle;

/* If we are using an MPM That Supports Async Connections,
 * use a different processing function
 */
static int async_mpm = 0;

static const char *set_keep_alive_timeout(cmd_parms *cmd, void *dummy,
                                          const char *arg)
{
    apr_interval_time_t timeout;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    /* Stolen from mod_proxy.c */
    if (ap_timeout_parameter_parse(arg, &timeout, "s") != APR_SUCCESS)
        return "KeepAliveTimeout has wrong format";
    cmd->server->keep_alive_timeout = timeout;
    return NULL;
}

static const char *set_keep_alive(cmd_parms *cmd, void *dummy,
                                  int arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive = arg;
    return NULL;
}

static const char *set_keep_alive_max(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive_max = atoi(arg);
    return NULL;
}

static const command_rec http_cmds[] = {
    AP_INIT_TAKE1("KeepAliveTimeout", set_keep_alive_timeout, NULL, RSRC_CONF,
                  "Keep-Alive timeout duration (sec)"),
    AP_INIT_TAKE1("MaxKeepAliveRequests", set_keep_alive_max, NULL, RSRC_CONF,
                  "Maximum number of Keep-Alive requests per connection, "
                  "or 0 for infinite"),
    AP_INIT_FLAG("KeepAlive", set_keep_alive, NULL, RSRC_CONF,
                  "Whether persistent connections should be On or Off"),
    { NULL }
};

static const char *http_scheme(const request_rec *r)
{
    /* 
     * The http module shouldn't return anything other than 
     * "http" (the default) or "https".
     */
    if (r->server->server_scheme &&
        (strcmp(r->server->server_scheme, "https") == 0))
        return "https";
    
    return "http";
}

static apr_port_t http_port(const request_rec *r)
{
    if (r->server->server_scheme &&
        (strcmp(r->server->server_scheme, "https") == 0))
        return DEFAULT_HTTPS_PORT;
    
    return DEFAULT_HTTP_PORT;
}

static int ap_process_http_async_connection(conn_rec *c)
{
    request_rec *r;
    conn_state_t *cs = c->cs;

    AP_DEBUG_ASSERT(cs->state == CONN_STATE_READ_REQUEST_LINE);

    while (cs->state == CONN_STATE_READ_REQUEST_LINE) {
        ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);

        if ((r = ap_read_request(c))) {

            c->keepalive = AP_CONN_UNKNOWN;
            /* process the request if it was read without error */

            ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
            if (r->status == HTTP_OK) {
                cs->state = CONN_STATE_HANDLER;
                ap_process_async_request(r);
                /* After the call to ap_process_request, the
                 * request pool may have been deleted.  We set
                 * r=NULL here to ensure that any dereference
                 * of r that might be added later in this function
                 * will result in a segfault immediately instead
                 * of nondeterministic failures later.
                 */
                r = NULL;
            }

            if (cs->state != CONN_STATE_WRITE_COMPLETION && 
                cs->state != CONN_STATE_SUSPENDED) {
                /* Something went wrong; close the connection */
                cs->state = CONN_STATE_LINGER;
            }
        }
        else {   /* ap_read_request failed - client may have closed */
            cs->state = CONN_STATE_LINGER;
        }
    }

    return OK;
}

static int ap_process_http_sync_connection(conn_rec *c)
{
    request_rec *r;
    conn_state_t *cs = c->cs;
    apr_socket_t *csd = NULL;
    int mpm_state = 0;

    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */

    ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);
    while ((r = ap_read_request(c)) != NULL) {

        c->keepalive = AP_CONN_UNKNOWN;
        /* process the request if it was read without error */

        ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
        if (r->status == HTTP_OK) {
            cs->state = CONN_STATE_HANDLER;
            ap_process_request(r);
            /* After the call to ap_process_request, the
             * request pool will have been deleted.  We set
             * r=NULL here to ensure that any dereference
             * of r that might be added later in this function
             * will result in a segfault immediately instead
             * of nondeterministic failures later.
             */
            r = NULL;
        }

        if (c->keepalive != AP_CONN_KEEPALIVE || c->aborted)
            break;

        ap_update_child_status(c->sbh, SERVER_BUSY_KEEPALIVE, NULL);

        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
            break;
        }

        if (mpm_state == AP_MPMQ_STOPPING) {
          break;
        }

        if (!csd) {
            csd = ap_get_module_config(c->conn_config, &core_module);
        }
        apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 1);
        apr_socket_timeout_set(csd, c->base_server->keep_alive_timeout);
        /* Go straight to select() to wait for the next request */
    }

    return OK;
}

static int ap_process_http_connection(conn_rec *c)
{
    if (async_mpm && !c->clogging_input_filters) {
        return ap_process_http_async_connection(c);
    }
    else {
        return ap_process_http_sync_connection(c);
    }
}

static int http_create_request(request_rec *r)
{
    if (!r->main && !r->prev) {
        ap_add_output_filter_handle(ap_byterange_filter_handle,
                                    NULL, r, r->connection);
        ap_add_output_filter_handle(ap_content_length_filter_handle,
                                    NULL, r, r->connection);
        ap_add_output_filter_handle(ap_http_header_filter_handle,
                                    NULL, r, r->connection);
        ap_add_output_filter_handle(ap_http_outerror_filter_handle,
                                    NULL, r, r->connection);
    }

    return OK;
}

static int http_send_options(request_rec *r)
{
    if ((r->method_number == M_OPTIONS) && r->uri && (r->uri[0] == '*') &&
         (r->uri[1] == '\0')) {
        return DONE;           /* Send HTTP pong, without Allow header */
    }
    return DECLINED;
}

static int http_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    if (ap_mpm_query(AP_MPMQ_IS_ASYNC, &async_mpm) != APR_SUCCESS) {
        async_mpm = 0;
    }
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(http_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(ap_process_http_connection, NULL, NULL,
                               APR_HOOK_REALLY_LAST);
    ap_hook_map_to_storage(ap_send_http_trace,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_map_to_storage(http_send_options,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_http_scheme(http_scheme,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_default_port(http_port,NULL,NULL,APR_HOOK_REALLY_LAST);
    ap_hook_create_request(http_create_request, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_http_input_filter_handle =
        ap_register_input_filter("HTTP_IN", ap_http_filter,
                                 NULL, AP_FTYPE_PROTOCOL);
    ap_http_header_filter_handle =
        ap_register_output_filter("HTTP_HEADER", ap_http_header_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_chunk_filter_handle =
        ap_register_output_filter("CHUNK", ap_http_chunk_filter,
                                  NULL, AP_FTYPE_TRANSCODE);
    ap_http_outerror_filter_handle =
        ap_register_output_filter("HTTP_OUTERROR", ap_http_outerror_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_byterange_filter_handle =
        ap_register_output_filter("BYTERANGE", ap_byterange_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
    ap_method_registry_init(p);
}

module AP_MODULE_DECLARE_DATA http_module = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    http_cmds,         /* command apr_table_t */
    register_hooks     /* register hooks */
};
