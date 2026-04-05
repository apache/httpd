/*
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

#include <httpd.h>

#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <unistd.h>
#include <util_script.h>
#ifdef HAVE_UNIX_SUEXEC
    #include <unixd.h>
#endif
#include <apr_strings.h>
#include <mpm_common.h>
#include <scoreboard.h>
#include <stdio.h>

#include "ossl-nghttp3.h"

module AP_MODULE_DECLARE_DATA http3_module;

/* Server configuration structure */
typedef struct
{
    const char* cert_path;
    const char* key_path;
    apr_port_t host_port;
} h3_server_conf;

static ap_filter_rec_t* h3_net_out_filter_handle;
static ap_filter_rec_t* h3_net_in_filter_handle;
static ap_filter_rec_t* h3_proto_out_filter_handle;
static ap_filter_rec_t* h3_proto_in_filter_handle;

static apr_socket_t* dummy_socket;

static apr_port_t get_server_port(server_rec* s)
{
    server_addr_rec* sar;

    for (sar = s->addrs; sar; sar = sar->next)
    {
        if (sar->host_port != 0)
            return sar->host_port;
    }
    return 4433; /* XXX doc or arrange ? */
}

/* Create server configuration */
static void* h3_create_server_config(apr_pool_t* p, server_rec* s)
{
    h3_server_conf* conf = apr_pcalloc(p, sizeof(h3_server_conf));
    conf->cert_path = NULL;
    conf->key_path = NULL;
    return conf;
}

/* Merge server configuration */
static void* h3_merge_server_config(apr_pool_t* p, void* base_conf, void* new_conf)
{
    h3_server_conf* merged = apr_pcalloc(p, sizeof(h3_server_conf));
    h3_server_conf* base = (h3_server_conf*)base_conf;
    h3_server_conf* new = (h3_server_conf*)new_conf;

    merged->cert_path = new->cert_path ? new->cert_path : base->cert_path;
    merged->key_path = new->key_path ? new->key_path : base->key_path;

    return merged;
}

/* Configuration directive handlers */
static const char* set_h3_cert_path(cmd_parms* cmd, void* dummy, const char* arg)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    conf->cert_path = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char* set_h3_key_path(cmd_parms* cmd, void* dummy, const char* arg)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    conf->key_path = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static int h3_post_config(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp, server_rec* s)
{
    h3_server_conf* conf;
    (void)plog;
    (void)ptemp;
    (void)p;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    {
        return OK;
    }

    /* Loop for all the VirtualHost */
    server_rec* current_server = s;
    while (current_server)
    {
        conf = ap_get_module_config(current_server->module_config, &http3_module);
        if (conf->cert_path && conf->key_path)
        {
            conf->host_port = get_server_port(current_server);
            break;
        }
        current_server = current_server->next;
    }

    /* Check if certificate path is configured */
    if (!conf->cert_path)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: H3CertificatePath directive is required but not configured");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check if key path is configured */
    if (!conf->key_path)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: H3CertificateKeyPath directive is required but not configured");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "h3_post_config: %d cert_path=%s key_path=%s", getpid(), conf->cert_path, conf->key_path);
    return OK;
}

/* WE DON'T NEED THAT ONE */
static int h3_hook_process_connection(conn_rec* c)
{
    const char* is_mod_http3 = apr_table_get(c->notes, "IS_mod_http3");
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "h3_hook_process_connection %d", is_mod_http3);
    if (is_mod_http3 == NULL)
        return DECLINED;
    return OK;
}

static int h3_hook_pre_connection(conn_rec* c, void* csd)
{
    const char* is_mod_http3 = apr_table_get(c->notes, "IS_mod_http3");
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "h3_hook_pre_connection %d", is_mod_http3);
    if (is_mod_http3 == NULL)
        return DECLINED;
    return OK;
}

static int h3_hook_post_read_request(request_rec* r)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_ap_hook_post_read_request");
    return OK;
}
static void h3_hook_pre_read_request(request_rec* r, conn_rec* c)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_ap_hook_pre_read_request");
}

static apr_status_t h3_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket* b;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out");
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_METADATA(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_METADATA");
        }
        if (APR_BUCKET_IS_FLUSH(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_EOS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_EOS");
        }
        if (AP_BUCKET_IS_ERROR(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_ERROR");
        }
        if (AP_BUCKET_IS_EOC(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_EOC");
        }
        if (APR_BUCKET_IS_FILE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_FILE");
        }
        if (AP_BUCKET_IS_HEADERS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_HEADERS");
        }
        if (APR_BUCKET_IS_FLUSH(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_IMMORTAL(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_IMMORTAL");
        }
        if (APR_BUCKET_IS_HEAP(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_HEAP");
        }
        if (APR_BUCKET_IS_MMAP(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out APR_BUCKET_IS_MMAP");
        }
        if (AP_BUCKET_IS_EOR(b))
        {
            /* the response/request done */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_EOR");
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out DONE");
            return DONE;
        }
        if (AP_BUCKET_IS_RESPONSE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out AP_BUCKET_IS_RESPONSE");
        }
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out DONE");
    return APR_SUCCESS;
}

static int print_table_entry(void* rec, const char* key, const char* value)
{
    const conn_rec* c = (conn_rec*)rec;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "h3_filter_out_proto print_table_entry %s %s", key, value);
    return 1;
}

static apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket* b;
    apr_status_t rv;
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d START", ctx);
    if (ctx == NULL)
        return ap_pass_brigade(f->next, bb);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d", f->r->status);

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_METADATA(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_METADATA");
        }
        if (APR_BUCKET_IS_FLUSH(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FLUSH");
        }
        else if (APR_BUCKET_IS_EOS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_EOS");
        }
        else if (AP_BUCKET_IS_ERROR(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR");
        }
        else if (AP_BUCKET_IS_EOC(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOC");
        }
        else if (APR_BUCKET_IS_FILE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE");
        }
        else if (AP_BUCKET_IS_HEADERS(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_HEADERS");
        }
        else if (APR_BUCKET_IS_HEAP(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_HEAP");
        }
        else if (AP_BUCKET_IS_EOR(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOR");
        }
        else if (AP_BUCKET_IS_RESPONSE(b))
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE");
        }
        else
        {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_SOMETHING %s", b->type->name);
        }

        if (AP_BUCKET_IS_ERROR(b))
        {
            /* Should we generate the error page here */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR");
            ap_send_error_response(f->r, 0);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR after ap_send_error_response()");
            return OK;
        }
        if (APR_BUCKET_IS_FILE(b) || APR_BUCKET_IS_MMAP(b))
        {
            h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto add to otherpart %s", b->type->name);
            if (ctx != NULL)
            {
                /* we will need to read the file and send it */
                APR_BUCKET_REMOVE(b);
                apr_bucket_setaside(b, ctx->c3reqpool);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto add to otherpart otherpart %d b: %d", ctx->otherpart, b);
                ctx->otherpart = b;
                if (ctx->dataheap != NULL)
                    abort();
            }
            else
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE NO CTX");
            }
        }
        if (AP_BUCKET_IS_RESPONSE(b))
        {
            ap_bucket_response* resp = b->data;
            h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
            /* we will process the response information */
            APR_BUCKET_REMOVE(b);
            apr_bucket_setaside(b, ctx->c3reqpool);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE");
            if (ctx != NULL)
            {
                ctx->resp = resp;
                if (ctx->otherpart != NULL)
                {
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE otherpart %s", ctx->otherpart->type->name);
                }
            }
            else
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE NO CTX!!!!");
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto status: %d", resp->status);
            /* XXX: just debug information */
            if (resp->reason != NULL)
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto reason: %s", resp->reason);
            }
            if (resp->headers != NULL)
            {
                apr_table_do(print_table_entry, (void*)f->c, resp->headers, NULL);
            }
            if (resp->notes != NULL)
            {
                apr_table_do(print_table_entry, (void*)f->c, resp->notes, NULL);
            }
        }
        if (APR_BUCKET_IS_HEAP(b))
        {
            h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_HEAP");
            if (ctx != NULL && b->data != NULL)
            {
                const char* data;
                apr_size_t len;
                /* We will process it. */
                APR_BUCKET_REMOVE(b);
                apr_bucket_setaside(b, ctx->c3reqpool);
                apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                ctx->dataheap = (char*)data;
                ctx->dataheaplen = len;
            }
            else
            {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_HEAP NO CTX or NO DATA!!!!");
            }
        }
        if (AP_BUCKET_IS_EOR(b))
        {
            /* EOR belongs to network filters! */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOR");
        }
    }
    if (ctx != NULL && ctx->otherpart != NULL && ctx->resp != NULL)
    {
        /* we are done, just return */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d %d %d DONE", rv, f->r->status, f->r->connection);
        return OK;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto CALLING ap_pass_brigade() on next");
    rv = ap_pass_brigade(f->next, bb);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_out_proto %d %d %d DONE", rv, f->r->status, f->r->connection);

    return rv;
}

static apr_status_t h3_filter_in_proto(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_status_t rv;
    h3_conn_ctx_t* ctx = (h3_conn_ctx_t*)ap_get_module_config(f->r->request_config, &http3_module);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto %d", ctx);
    if (ctx == NULL)
        return ap_get_brigade(f->next, bb, mode, block, readbytes);

    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto let's do nothing!");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    ap_remove_input_filter(f);
    if (mode == AP_MODE_READBYTES)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto AP_MODE_READBYTES status %d %d", f->r->status, f->r->clength);
        if (APR_BRIGADE_EMPTY(bb))
        {
            const char* postdata = apr_table_get(f->r->notes, "H3POSTDATA");
            const char* postdatalen = apr_table_get(f->r->notes, "H3POSTDATALEN");
            if (postdatalen && postdata)
            {
                apr_int64_t data_len64 = apr_atoi64(postdatalen);
                if (data_len64 < 0 || data_len64 > APR_SIZE_MAX)
                {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto: invalid data length");
                    return APR_EGENERAL;
                }
                apr_size_t data_len = (apr_size_t)data_len64;
                apr_status_t rv = apr_brigade_write(bb, NULL, NULL, postdata, data_len);
                if (rv != APR_SUCCESS)
                {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, "h3_filter_in_proto: brigade write failed");
                    return rv;
                }
                f->r->clength = data_len;
            }
            ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto AP_MODE_READBYTES add EOS");
            apr_bucket* eos;
            eos = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, eos);
        }
        return APR_SUCCESS;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto OTHER status %d", f->r->status);
    rv = ap_pass_brigade(f->next, bb);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in_proto %d %d %d", rv, mode, AP_MODE_READBYTES);
    return APR_SUCCESS;
}

static apr_status_t h3_filter_in(ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in mode %d", mode);
    if (mode == AP_MODE_READBYTES)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, f->c, "h3_filter_in AP_MODE_READBYTES");
        if (f->ctx == NULL)
        {
            apr_bucket* e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            f->ctx = (void*)1;
            return APR_EOF;
        }
        ap_remove_input_filter(f);
    }
    return APR_EOF;
}
struct h3_stuff
{
    apr_pool_t* pchild;
    server_rec* s;
    h3_server_conf* conf;
};

/* Create a connection */
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

/* Process a connection */
/* the create_connection has been called in ossl-nghttp3.c */
apr_status_t process_connection(apr_pool_t* p, server_rec* s, conn_rec* c)
{

    /* We need to process the connection we have created */
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_connection");
    c->master = NULL; /* reset it */
    c->cs = NULL;
    ap_run_pre_connection(c, &dummy_socket);
    ap_run_process_connection(c);

    return APR_SUCCESS;
}
/* Process a request */
/* the request has been created in ossl-nghttp3.c */
apr_status_t process_request(request_rec* r, h3_conn_ctx_t* h3ctx)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "process_request before ap_process_request(%s)", r->uri);
    r->proxyreq = 0;
    r->filename = NULL;
    r->per_dir_config = ap_create_per_dir_config(r->pool);
    r->per_dir_config = ap_merge_per_dir_configs(r->pool, r->server->lookup_defaults, r->per_dir_config);
    ap_set_module_config(r->request_config, &http3_module, h3ctx);
    ap_process_request(r);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "process_request after ap_process_request()");
    return OK;
}

static void* APR_THREAD_FUNC worker_thread_main(apr_thread_t* thread, void* data)
{
    struct h3_stuff* h3 = (struct h3_stuff*)data;
    apr_pool_t* pool;
    server_rec* s = h3->s;
    apr_pool_create(&pool, h3->pchild);
    apr_pool_tag(pool, "h3_main");
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "worker_thread_main");
    server(pool, s, h3->conf->host_port, h3->conf->cert_path, h3->conf->key_path);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "worker_thread_main exited!");
}

/* The child creates a thread that waits on the udp socket and create another thread to process a request */
static void h3_child_init(apr_pool_t* pchild, server_rec* s)
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
static void h3_c1_child_stopping(apr_pool_t* pool, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, NULL, "h3_c1_child_stopping %d", graceful);
}
static int h3_hook_http_create_request(request_rec* r)
{
    const char* is_mod_http3 = apr_table_get(r->connection->notes, "IS_mod_http3");
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_hook_http_create_request %d", is_mod_http3);
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
static void h3_filter_last(request_rec* r)
{
    const char* is_mod_http3 = apr_table_get(r->connection->notes, "IS_mod_http3");
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "h3_filter_last %d", is_mod_http3);
    if (is_mod_http3 == NULL)
        return;
    ap_add_output_filter_handle(h3_proto_out_filter_handle, NULL, r, r->connection); /* HACKING */
}

/* Configuration directives */
static const command_rec h3_cmds[] = {AP_INIT_TAKE1("H3CertificatePath", set_h3_cert_path, NULL, RSRC_CONF, "Path to the SSL certificate file for HTTP/3"), AP_INIT_TAKE1("H3CertificateKeyPath", set_h3_key_path, NULL, RSRC_CONF, "Path to the SSL certificate key file for HTTP/3"), {NULL}};

static void register_hooks(apr_pool_t* p)
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

AP_DECLARE_MODULE(http3) = {
    STANDARD20_MODULE_STUFF,
    NULL,                    /* create per-directory config structure */
    NULL,                    /* merge per-directory config structures */
    h3_create_server_config, /* create per-server config structure */
    h3_merge_server_config,  /* merge per-server config structures */
    h3_cmds,                 /* command apr_table_t */
    register_hooks,          /* register hooks */
    AP_MODULE_FLAG_NONE      /* flags */
};
