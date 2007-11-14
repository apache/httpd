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
    ap_hook_handler(serf_handler, NULL, NULL, APR_HOOK_FIRST);
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
