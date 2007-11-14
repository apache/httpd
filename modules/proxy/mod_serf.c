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

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"

#include "serf.h"
#include "serf_bucket_types.h"
#include "serf_bucket_util.h"
#include "apr_uri.h"

module AP_MODULE_DECLARE_DATA serf_module;

typedef struct {
    int on;
    apr_uri_t url;
} serf_config_rec;

typedef struct {
    int rstatus;
    int want_ssl;
    int done_headers;
    int keep_reading;
    request_rec *r;
    serf_config_rec *conf;
    serf_ssl_context_t *ssl_ctx;
    serf_bucket_alloc_t *bkt_alloc;
} s_baton_t;


static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    s_baton_t *ctx = closed_baton;

    if (why) {
        /* justin says that error handling isn't done yet. hah. */
        /* XXXXXX: review */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, why, ctx->r, "Closed Connection Error");
        ctx->rstatus = HTTP_INTERNAL_SERVER_ERROR;
        return;
    }
}

static serf_bucket_t* conn_setup(apr_socket_t *sock,
                                 void *setup_baton,
                                 apr_pool_t *pool)
{
    serf_bucket_t *c;
    s_baton_t *ctx = setup_baton;

    c = serf_bucket_socket_create(sock, ctx->bkt_alloc);
    if (ctx->want_ssl) {
        c = serf_bucket_ssl_decrypt_create(c, ctx->ssl_ctx, ctx->bkt_alloc);
    }

    return c;
}

int copy_headers_in(void *vbaton, const char *key, const char *value)
{
    serf_bucket_t *hdrs_bkt = (serf_bucket_t *)vbaton;

    /* XXXXX: List of headers not to copy to serf. serf's serf_bucket_headers_setn, 
     * doesn't actually overwrite a header if we set it once, so we need to ignore anything
     * we might want to toggle or combine.
     */
    switch (key[0]) {
    case 'a':
    case 'A':
        if (strcasecmp("Accept-Encoding", key) == 0) {
            return 0;
        }
        break;
    case 'c':
    case 'C':
        if (strcasecmp("Connection", key) == 0) {
            return 0;
        }
        break;
    case 'h':
    case 'H':
        if (strcasecmp("Host", key) == 0) {
            return 0;
        }
        break;
    case 'k':
    case 'K':
        if (strcasecmp("Keep-Alive", key) == 0) {
            return 0;
        }
        break;
    case 't':
    case 'T':
        if (strcasecmp("TE", key) == 0) {
            return 0;
        }
        if (strcasecmp("Trailer", key) == 0) {
            return 0;
        }
        break;
    case 'u':
    case 'U':
        if (strcasecmp("Upgrade", key) == 0) {
            return 0;
        }
        break;
    default:
        break;
    }

    serf_bucket_headers_setn(hdrs_bkt, key, value);
    return 0;
}

int copy_headers_out(void *vbaton, const char *key, const char *value)
{
    s_baton_t *ctx = vbaton;
    int done = 0;

    /* XXXXX: Special Treatment required for MANY other headers. fixme.*/
    switch (key[0]) {
    case 'c':
    case 'C':
        if (strcasecmp("Content-Type", key) == 0) {
            ap_set_content_type(ctx->r, value);
            done = 1;
            break;
        }
        else if (strcasecmp("Connection", key) == 0) {
            done = 1;
            break;
        }
        else if (strcasecmp("Content-Encoding", key) == 0) {
            done = 1;
            break;
        }
        else if (strcasecmp("Content-Length", key) == 0) {
            done = 1;
            break;
        }
        break;
    case 't':
    case 'T':
        if (strcasecmp("Transfer-Encoding", key) == 0) {
            done = 1;
            break;
        }
        break;
    default:
            break;
    }

    if (!done) {
        apr_table_addn(ctx->r->headers_out, key, value);
    }

    return 0;
}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      serf_bucket_t *stream,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;

    /* get the per-request bucket allocator */
    bkt_alloc = serf_request_get_alloc(request);

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(stream, bkt_alloc);

    return serf_bucket_response_create(c, bkt_alloc);
}

static apr_status_t handle_response(serf_request_t *request,
                                    serf_bucket_t *response,
                                    void *vbaton,
                                    apr_pool_t *pool)
{
    apr_status_t rv;
    s_baton_t *ctx = vbaton;
    const char *data;
    apr_size_t len;
    serf_status_line sl;

    /* XXXXXXX: Create better error message. */
    rv = serf_bucket_response_status(response, &sl);
    if (rv) {
        if (APR_STATUS_IS_EAGAIN(rv)) {
            return APR_SUCCESS;
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, ctx->r, "serf_bucket_response_status...");

        ctx->rstatus = HTTP_INTERNAL_SERVER_ERROR;

        return rv;
    }
    
    /**
     * XXXXX: If I understood serf buckets better, it might be possible to not 
     * copy all of the data here, and better stream it to the client.
     **/

    do {
        rv = serf_bucket_read(response, AP_IOBUFSIZE, &data, &len);

        if (SERF_BUCKET_READ_ERROR(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, ctx->r, "serf_bucket_read(response)");
            return rv;
        }

        if (!ctx->done_headers) {
            serf_bucket_t *hdrs;
            hdrs = serf_bucket_response_get_headers(response);
            serf_bucket_headers_do(hdrs, copy_headers_out, ctx);
            ctx->done_headers = 1;
        }
        
        /* XXXX: write to brigades and stuff. meh */
        ap_rwrite(data, len, ctx->r);

        if (APR_STATUS_IS_EOF(rv)) {
            ctx->keep_reading = 0;
            return APR_EOF;
        }

        /* XXXX: Should we send a flush now? */
        if (APR_STATUS_IS_EAGAIN(rv)) {
            return APR_SUCCESS;
        }

    } while (1);
}


static apr_status_t setup_request(serf_request_t *request,
                                  void *vbaton,
                                  serf_bucket_t **req_bkt,
                                  serf_response_acceptor_t *acceptor,
                                  void **acceptor_baton,
                                  serf_response_handler_t *handler,
                                  void **handler_baton,
                                  apr_pool_t *pool)
{
    s_baton_t *ctx = vbaton;
    serf_bucket_t *hdrs_bkt;
    serf_bucket_t *body_bkt = NULL;


    /* XXXXX: handle incoming request bodies */
    *req_bkt = serf_bucket_request_create(ctx->r->method, ctx->r->unparsed_uri, body_bkt,
                                          serf_request_get_alloc(request));

    hdrs_bkt = serf_bucket_request_get_headers(*req_bkt);

    apr_table_do(copy_headers_in, hdrs_bkt, ctx->r->headers_in, NULL);

    /* XXXXXX: SerfPreserveHost on */
    serf_bucket_headers_setn(hdrs_bkt, "Host", ctx->conf->url.hostname);

    serf_bucket_headers_setn(hdrs_bkt, "Accept-Encoding", "gzip");

    if (ctx->want_ssl) {
        serf_bucket_alloc_t *req_alloc;

        req_alloc = serf_request_get_alloc(request);

        if (ctx->ssl_ctx == NULL) {
            *req_bkt = serf_bucket_ssl_encrypt_create(*req_bkt, NULL,
                                           ctx->bkt_alloc);
            ctx->ssl_ctx = serf_bucket_ssl_encrypt_context_get(*req_bkt);
        }
        else {
            *req_bkt = serf_bucket_ssl_encrypt_create(*req_bkt, ctx->ssl_ctx,
                                                      ctx->bkt_alloc);
        }
    }
    
    *acceptor = accept_response;
    *acceptor_baton = ctx;
    *handler = handle_response;
    *handler_baton = ctx;

    return APR_SUCCESS;
}

static int drive_serf(request_rec *r, serf_config_rec *conf)
{
    apr_status_t rv;
    apr_pool_t *pool = r->pool;
    apr_sockaddr_t *address;
    s_baton_t baton;
    /* XXXXX: make persistent/per-process or something.*/
    serf_context_t *serfme;
    serf_connection_t *conn;
    serf_request_t *srequest;

    /* XXXXX: cache dns? */
    rv = apr_sockaddr_info_get(&address, conf->url.hostname,
                               APR_UNSPEC, conf->url.port, 0,
                               pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Unable to resolve: %s", conf->url.hostname);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    serfme = serf_context_create(pool);

    baton.r = r;
    baton.conf = conf;
    baton.bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    baton.ssl_ctx = NULL;
    baton.rstatus = OK;

    baton.done_headers = 0;
    baton.keep_reading = 1;

    if (strcasecmp(conf->url.scheme, "https") == 0) {
        baton.want_ssl = 1;
    }
    else {
        baton.want_ssl = 0;
    }

    conn = serf_connection_create(serfme, address,
                                  conn_setup, &baton,
                                  closed_connection, &baton,
                                  pool);

    srequest = serf_connection_request_create(conn, setup_request,
                                              &baton);

    do {
        rv = serf_context_run(serfme, SERF_DURATION_FOREVER, pool);

        /* XXXX: Handle timeouts */
        if (APR_STATUS_IS_TIMEUP(rv)) {
            continue;
        }

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "serf_context_run()");
            return HTTP_INTERNAL_SERVER_ERROR;       
        }

        serf_debug__closed_conn(baton.bkt_alloc);
    } while (baton.keep_reading);

    return baton.rstatus;
}

typedef struct {
    serf_context_t *serf_ctx;
    serf_bucket_alloc_t *serf_bkt_alloc;
    serf_bucket_t *serf_in_bucket;
    serf_bucket_t *serf_out_bucket;
    apr_bucket_brigade *out_brigade;
    apr_bucket_brigade *tmp_brigade;
    apr_status_t serf_bucket_status;
} serf_core_ctx_t;

typedef struct {
    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;
    serf_core_ctx_t *core_ctx;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmp_bb;
} brigade_bucket_ctx_t;

/* Forward-declare */
const serf_bucket_type_t serf_bucket_type_brigade;

static serf_bucket_t * brigade_create(ap_filter_t *f, serf_core_ctx_t *core_ctx)
{
    brigade_bucket_ctx_t *ctx;

    ctx = serf_bucket_mem_alloc(core_ctx->serf_bkt_alloc, sizeof(*ctx));
    ctx->allocator = core_ctx->serf_bkt_alloc;
    ctx->pool = serf_bucket_allocator_get_pool(ctx->allocator);
    ctx->core_ctx = core_ctx;
    ctx->bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
    ctx->tmp_bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);

    return serf_bucket_create(&serf_bucket_type_brigade, ctx->allocator, ctx);
}

static apr_status_t brigade_read(serf_bucket_t *bucket,
                                 apr_size_t requested,
                                 const char **data, apr_size_t *len)
{
    brigade_bucket_ctx_t *ctx = bucket->data;
    apr_status_t status;
    apr_bucket *b, *end, *f;

    b = APR_BRIGADE_FIRST(ctx->bb);
    status = apr_bucket_read(b, data, len, APR_BLOCK_READ);

    if (requested < *len) {
        *len = requested;
    }
    status = apr_brigade_partition(ctx->bb, *len, &end);
    f = APR_BRIGADE_FIRST(ctx->bb);
    while (f != end && f != APR_BRIGADE_SENTINEL(ctx->bb)) {
        apr_bucket_delete(f);
        f = APR_BRIGADE_FIRST(ctx->bb);
    }
    return status;
}

static apr_status_t brigade_readline(serf_bucket_t *bucket,
                                     int acceptable, int *found,
                                     const char **data, apr_size_t *len)
{
    brigade_bucket_ctx_t *ctx = bucket->data;
    apr_status_t status;

    status = apr_brigade_split_line(ctx->tmp_bb, ctx->bb,
                                    APR_BLOCK_READ, HUGE_STRING_LEN);
    if (APR_STATUS_IS_EAGAIN(status)) {
        if (found) {
            *found = SERF_NEWLINE_NONE;
        }
        status = APR_SUCCESS;
    }
    apr_brigade_pflatten(ctx->bb, data, len, ctx->pool);
    return status;
}

static apr_status_t brigade_peek(serf_bucket_t *bucket,
                                 const char **data,
                                 apr_size_t *len)
{
    return APR_ENOTIMPL;
}

static void brigade_destroy(serf_bucket_t *bucket)
{
    serf_default_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type_brigade = {
    brigade_read,
    brigade_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    brigade_peek,
    brigade_destroy,
};

static serf_core_ctx_t* init_ctx(ap_filter_t *f, apr_socket_t *socket)
{
    serf_core_ctx_t *ctx;

    ctx = apr_pcalloc(f->c->pool, sizeof(*ctx));

    ctx->serf_ctx = serf_context_create(f->c->pool);
    ctx->serf_bkt_alloc = serf_bucket_allocator_create(f->c->pool, NULL, NULL);
    ctx->serf_in_bucket = serf_bucket_socket_create(socket,
                                                    ctx->serf_bkt_alloc);
    ctx->serf_out_bucket = serf_bucket_aggregate_create(ctx->serf_bkt_alloc);

    ctx->out_brigade = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
    ctx->tmp_brigade = apr_brigade_create(f->c->pool, f->c->bucket_alloc);

    return ctx;
}

static int serf_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                             ap_input_mode_t mode, apr_read_type_e block,
                             apr_off_t readbytes)
{
    apr_status_t status;
    core_net_rec *net = f->ctx;
    serf_core_ctx_t *ctx = (serf_core_ctx_t*)net->in_ctx;

    if (mode == AP_MODE_INIT) {
        return APR_SUCCESS;
    }
    if (!ctx)
    {
        ctx = init_ctx(f, net->client_socket);
    }

    if (mode == AP_MODE_GETLINE) {
        const char *data;
        apr_size_t len;
        int found;
        apr_bucket *b;

        ctx->serf_bucket_status = serf_bucket_readline(ctx->serf_in_bucket,
                                                       SERF_NEWLINE_ANY,
                                                       &found, &data, &len);
        b = apr_bucket_transient_create(data, len, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        return APR_SUCCESS;
    }
    if (mode == AP_MODE_READBYTES) {
        const char *data;
        apr_size_t len;
        apr_bucket *b;

        ctx->serf_bucket_status = serf_bucket_read(ctx->serf_in_bucket,
                                                   readbytes, &data, &len);
        b = apr_bucket_transient_create(data, len, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        return APR_SUCCESS;
    }

    if (mode == AP_MODE_EATCRLF || mode == AP_MODE_EXHAUSTIVE ||
        mode == AP_MODE_SPECULATIVE) {
        abort();
    }
}

static apr_status_t serf_output_filter(ap_filter_t *f,
                                       apr_bucket_brigade *new_bb)
{
    conn_rec *c = f->c;
    core_net_rec *net = f->ctx;
    serf_core_ctx_t *ctx = (serf_core_ctx_t*)net->in_ctx;
    if (!ctx) {
        ctx = init_ctx(f, net->client_socket);
    }

    ap_save_brigade(f, &ctx->tmp_brigade, &new_bb, c->pool);
    apr_brigade_destroy(new_bb);
    APR_BRIGADE_CONCAT(ctx->out_brigade, ctx->tmp_brigade);

    return APR_SUCCESS;
}

static ap_filter_rec_t *serf_input_filter_handle;
static ap_filter_rec_t *serf_output_filter_handle;

static int serf_pre_connection(conn_rec *c, void *csd)
{
    core_net_rec *net = apr_palloc(c->pool, sizeof(*net));
    apr_status_t status;

    net->c = c;
    net->in_ctx = NULL;
    net->out_ctx = NULL;
    net->client_socket = csd;

    ap_set_module_config(net->c->conn_config, &serf_module, csd);
    ap_add_input_filter_handle(serf_input_filter_handle, net, NULL, net->c);
    ap_add_output_filter_handle(serf_output_filter_handle, net, NULL, net->c);

    return DONE;
}

static int serf_handler(request_rec *r)
{
    serf_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                 &serf_module);

    if (conf->on == 0) {
        return DECLINED;
    }

    return drive_serf(r, conf);
}

static const char *add_pass(cmd_parms *cmd, void *vconf,
                            const char *vdest)
{
    apr_status_t rv;
    serf_config_rec *conf = (serf_config_rec *) vconf;

    rv = apr_uri_parse(cmd->pool, vdest, &conf->url);

    if (rv != APR_SUCCESS) {
        return "mod_serf: Unable to parse SerfPass url.";
    }

    /* XXXX: These are bugs in apr_uri_parse. Fixme. */
    if (!conf->url.port) {
        conf->url.port = apr_uri_port_of_scheme(conf->url.scheme);
    }

    if (!conf->url.path) {
        conf->url.path = "/";
    }

    conf->on = 1;

    return NULL;
}

static void *create_config(apr_pool_t *p, char *dummy)
{
    serf_config_rec *new = (serf_config_rec *) apr_pcalloc(p, sizeof(serf_config_rec));
    new->on = 0;
    return new;
}

static const command_rec serf_cmds[] =
{
    AP_INIT_TAKE1("SerfPass", add_pass, NULL, OR_INDEXES/*making shit up*/,
     "A prefix and destination"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_connection(serf_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(serf_handler, NULL, NULL, APR_HOOK_FIRST);

    serf_input_filter_handle =
        ap_register_input_filter("SERF_IN", serf_input_filter, NULL,
                                 AP_FTYPE_NETWORK);
    serf_output_filter_handle =
        ap_register_output_filter("SERF_OUT", serf_output_filter, NULL,
                                  AP_FTYPE_NETWORK);

}

module AP_MODULE_DECLARE_DATA serf_module =
{
    STANDARD20_MODULE_STUFF,
    create_config,
    NULL,
    NULL,
    NULL,
    serf_cmds,
    register_hooks
};
