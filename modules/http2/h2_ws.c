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

#include <assert.h>

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_sha1.h"
#include "apr_strmatch.h"

#include <ap_mmn.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_ssl.h>
#include <http_vhost.h>
#include <util_filter.h>
#include <ap_mpm.h>

#include "h2_private.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_headers.h"
#include "h2_request.h"
#include "h2_ws.h"

#if H2_USE_WEBSOCKETS

#include "apr_encode.h" /* H2_USE_WEBSOCKETS is conditional on APR 1.6+ */

static ap_filter_rec_t *c2_ws_out_filter_handle;

struct ws_filter_ctx {
    const char *ws_accept_base64;
    int has_final_response;
    int override_body;
};

/**
 * Generate the "Sec-WebSocket-Accept" header field for the given key
 * (base64 encoded) as defined in RFC 6455 ch. 4.2.2 step 5.3
 */
static const char *gen_ws_accept(conn_rec *c, const char *key_base64)
{
    apr_byte_t dgst[APR_SHA1_DIGESTSIZE];
    const char ws_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    apr_sha1_ctx_t sha1_ctx;

    apr_sha1_init(&sha1_ctx);
    apr_sha1_update(&sha1_ctx, key_base64, (unsigned int)strlen(key_base64));
    apr_sha1_update(&sha1_ctx, ws_guid, (unsigned int)strlen(ws_guid));
    apr_sha1_final(dgst, &sha1_ctx);

    return apr_pencode_base64_binary(c->pool, dgst, sizeof(dgst),
                                     APR_ENCODE_NONE, NULL);
}

const h2_request *h2_ws_rewrite_request(const h2_request *req,
                                        conn_rec *c2, int no_body)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);
    h2_request *wsreq;
    unsigned char key_raw[16];
    const char *key_base64, *accept_base64;
    struct ws_filter_ctx *ws_ctx;
    apr_status_t rv;

    if (!conn_ctx || !req->protocol || strcmp("websocket", req->protocol))
        return req;

    if (ap_cstr_casecmp("CONNECT", req->method)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket request with method %s",
                      conn_ctx->id, conn_ctx->stream_id, req->method);
        return req;
    }
    if (!req->scheme) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket CONNECT without :scheme",
                      conn_ctx->id, conn_ctx->stream_id);
        return req;
    }
    if (!req->path) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket CONNECT without :path",
                      conn_ctx->id, conn_ctx->stream_id);
        return req;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                  "h2_c2(%s-%d): websocket CONNECT for %s",
                  conn_ctx->id, conn_ctx->stream_id, req->path);
    /* Transform the HTTP/2 extended CONNECT to an internal GET using
     * the HTTP/1.1 version of websocket connection setup. */
    wsreq = h2_request_clone(c2->pool, req);
    wsreq->method = "GET";
    wsreq->protocol = NULL;
    apr_table_set(wsreq->headers, "Upgrade", "websocket");
    apr_table_add(wsreq->headers, "Connection", "Upgrade");
    /* add Sec-WebSocket-Key header */
    rv = apr_generate_random_bytes(key_raw, sizeof(key_raw));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(10461)
                     "error generating secret");
        return NULL;
    }
    key_base64 = apr_pencode_base64_binary(c2->pool, key_raw, sizeof(key_raw),
                                           APR_ENCODE_NONE, NULL);
    apr_table_set(wsreq->headers, "Sec-WebSocket-Key", key_base64);
    /* This is now the request to process internally */

    /* When this request gets processed and delivers a 101 response,
     * we expect it to carry a "Sec-WebSocket-Accept" header with
     * exactly the following value, as per RFC 6455. */
    accept_base64 = gen_ws_accept(c2, key_base64);
    /* Add an output filter that intercepts generated responses:
     * - if a valid WebSocket negotiation happens, transform the
     *   101 response to a 200
     * - if a 2xx response happens, that does not pass the Accept test,
     *   return a 502 indicating that the URI seems not support the websocket
     *   protocol (RFC 8441 does not define this, but it seems the best
     *   choice)
     * - if a 3xx, 4xx or 5xx response happens, forward this unchanged.
     */
    ws_ctx = apr_pcalloc(c2->pool, sizeof(*ws_ctx));
    ws_ctx->ws_accept_base64 = accept_base64;
    /* insert our filter just before the C2 core filter */
    ap_remove_output_filter_byhandle(c2->output_filters, "H2_C2_NET_OUT");
    ap_add_output_filter("H2_C2_WS_OUT", ws_ctx, NULL, c2);
    ap_add_output_filter("H2_C2_NET_OUT", NULL, NULL, c2);
    /* Mark the connection as being an Upgrade, with some special handling
     * since the request needs an EOS, without the stream being closed  */
    conn_ctx->is_upgrade = 1;

    return wsreq;
}

static apr_bucket *make_valid_resp(conn_rec *c2, int status,
                                   apr_table_t *headers, apr_table_t *notes)
{
    apr_table_t *nheaders, *nnotes;

    ap_assert(headers);
    nheaders = apr_table_clone(c2->pool, headers);
    apr_table_unset(nheaders, "Connection");
    apr_table_unset(nheaders, "Upgrade");
    apr_table_unset(nheaders, "Sec-WebSocket-Accept");
    nnotes = notes? apr_table_clone(c2->pool, notes) :
                    apr_table_make(c2->pool, 10);
#if AP_HAS_RESPONSE_BUCKETS
    return ap_bucket_response_create(status, NULL, nheaders, nnotes,
                                     c2->pool, c2->bucket_alloc);
#else
    return h2_bucket_headers_create(c2->bucket_alloc,
                                    h2_headers_create(status, nheaders,
                                                      nnotes, 0, c2->pool));
#endif
}

static apr_bucket *make_invalid_resp(conn_rec *c2, int status,
                                     apr_table_t *notes)
{
    apr_table_t *nheaders, *nnotes;

    nheaders = apr_table_make(c2->pool, 10);
    apr_table_setn(nheaders, "Content-Length", "0");
    nnotes = notes? apr_table_clone(c2->pool, notes) :
                    apr_table_make(c2->pool, 10);
#if AP_HAS_RESPONSE_BUCKETS
    return ap_bucket_response_create(status, NULL, nheaders, nnotes,
                                     c2->pool, c2->bucket_alloc);
#else
    return h2_bucket_headers_create(c2->bucket_alloc,
                                    h2_headers_create(status, nheaders,
                                                      nnotes, 0, c2->pool));
#endif
}

static void ws_handle_resp(conn_rec *c2, h2_conn_ctx_t *conn_ctx,
                           struct ws_filter_ctx *ws_ctx, apr_bucket *b)
{
#if AP_HAS_RESPONSE_BUCKETS
    ap_bucket_response *resp = b->data;
#else /* AP_HAS_RESPONSE_BUCKETS */
    h2_headers *resp = h2_bucket_headers_get(b);
#endif /* !AP_HAS_RESPONSE_BUCKETS */
    apr_bucket *b_override = NULL;
    int is_final = 0;
    int override_body = 0;

    if (ws_ctx->has_final_response) {
        /* already did, nop */
        return;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                  "h2_c2(%s-%d): H2_C2_WS_OUT inspecting response %d",
                  conn_ctx->id, conn_ctx->stream_id, resp->status);
    if (resp->status == HTTP_SWITCHING_PROTOCOLS) {
        /* The resource agreed to switch protocol. But this is only valid
         * if it send back the correct Sec-WebSocket-Accept header value */
        const char *hd = apr_table_get(resp->headers, "Sec-WebSocket-Accept");
        if (hd && !strcmp(ws_ctx->ws_accept_base64, hd)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                          "h2_c2(%s-%d): websocket CONNECT, valid 101 Upgrade"
                          ", converting to 200 response",
                          conn_ctx->id, conn_ctx->stream_id);
            b_override = make_valid_resp(c2, HTTP_OK, resp->headers, resp->notes);
            is_final = 1;
        }
        else {
            if (!hd) {
                /* This points to someone being confused */
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c2, APLOGNO(10462)
                              "h2_c2(%s-%d): websocket CONNECT, got 101 response "
                              "without Sec-WebSocket-Accept header",
                              conn_ctx->id, conn_ctx->stream_id);
            }
            else {
                /* This points to a bug, either in our WebSockets negotiation
                 * or in the request processings implementation of WebSockets */
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c2, APLOGNO(10463)
                              "h2_c2(%s-%d): websocket CONNECT, 101 response "
                              "with 'Sec-WebSocket-Accept: %s' but expected %s",
                              conn_ctx->id, conn_ctx->stream_id, hd,
                              ws_ctx->ws_accept_base64);
            }
            b_override = make_invalid_resp(c2, HTTP_BAD_GATEWAY, resp->notes);
            override_body = is_final = 1;
        }
    }
    else if (resp->status < 200) {
        /* other intermediate response, pass through */
    }
    else if (resp->status < 300) {
        /* Failure, we might be talking to a plain http resource */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket CONNECT, invalid response %d",
                      conn_ctx->id, conn_ctx->stream_id, resp->status);
        b_override = make_invalid_resp(c2, HTTP_BAD_GATEWAY, resp->notes);
        override_body = is_final = 1;
    }
    else {
        /* error response, pass through. */
        ws_ctx->has_final_response = 1;
    }

    if (b_override) {
        APR_BUCKET_INSERT_BEFORE(b, b_override);
        apr_bucket_delete(b);
        b = b_override;
    }
    if (override_body) {
        APR_BUCKET_INSERT_AFTER(b, apr_bucket_eos_create(c2->bucket_alloc));
        ws_ctx->override_body = 1;
    }
    if (is_final) {
        ws_ctx->has_final_response = 1;
        conn_ctx->has_final_response = 1;
    }
}

static apr_status_t h2_c2_ws_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    struct ws_filter_ctx *ws_ctx = f->ctx;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(f->c);
    apr_bucket *b, *bnext;

    ap_assert(conn_ctx);
    if (ws_ctx->override_body) {
        /* We have overridden the original response and also its body.
         * If this filter is called again, we signal a hard abort to
         * allow processing to terminate at the earliest. */
        f->c->aborted = 1;
        return APR_ECONNABORTED;
    }

    /* Inspect the brigade, looking for RESPONSE/HEADER buckets.
     * Remember, this filter is only active for client websocket CONNECT
     * requests that we translated to an internal GET with websocket
     * headers.
     * We inspect the repsone to see if the internal resource actually
     * agrees to talk websocket or is "just" a normal HTTP resource that
     * ignored the websocket request headers. */
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = bnext)
    {
        bnext = APR_BUCKET_NEXT(b);
        if (APR_BUCKET_IS_METADATA(b)) {
#if AP_HAS_RESPONSE_BUCKETS
            if (AP_BUCKET_IS_RESPONSE(b)) {
#else
            if (H2_BUCKET_IS_HEADERS(b)) {
#endif /* !AP_HAS_RESPONSE_BUCKETS */
                ws_handle_resp(f->c, conn_ctx, ws_ctx, b);
                continue;
            }
        }
        else if (ws_ctx->override_body) {
            apr_bucket_delete(b);
        }
    }
    return ap_pass_brigade(f->next, bb);
}

static int ws_post_read(request_rec *r)
{

    if (r->connection->master) {
        h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(r->connection);
        if (conn_ctx && conn_ctx->is_upgrade &&
            !h2_config_sgeti(r->server, H2_CONF_WEBSOCKETS)) {
            return HTTP_NOT_IMPLEMENTED;
        }
    }
    return DECLINED;
}

void h2_ws_register_hooks(void)
{
    ap_hook_post_read_request(ws_post_read, NULL, NULL, APR_HOOK_MIDDLE);
    c2_ws_out_filter_handle =
        ap_register_output_filter("H2_C2_WS_OUT", h2_c2_ws_filter_out,
                                  NULL, AP_FTYPE_NETWORK);
}

#else /* H2_USE_WEBSOCKETS */

const h2_request *h2_ws_rewrite_request(const h2_request *req,
                                        conn_rec *c2, int no_body)
{
    (void)c2;
    (void)no_body;
    /* no rewriting */
    return req;
}

void h2_ws_register_hooks(void)
{
    /*  NOP */
}

#endif /* H2_USE_WEBSOCKETS (else part) */
