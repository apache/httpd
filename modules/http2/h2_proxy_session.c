/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <apr_strings.h>
#include <nghttp2/nghttp2.h>

#include <httpd.h>
#include <mod_proxy.h>
#include <mod_http2.h>

#include "h2.h"
#include "h2_request.h"
#include "h2_util.h"
#include "h2_proxy_session.h"

APLOG_USE_MODULE(proxy_http2);

static int ngstatus_from_apr_status(apr_status_t rv)
{
    if (rv == APR_SUCCESS) {
        return NGHTTP2_NO_ERROR;
    }
    else if (APR_STATUS_IS_EAGAIN(rv)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    else if (APR_STATUS_IS_EOF(rv)) {
            return NGHTTP2_ERR_EOF;
    }
    return NGHTTP2_ERR_PROTO;
}


static apr_status_t proxy_session_shutdown(void *theconn)
{
    proxy_conn_rec *p_conn = (proxy_conn_rec *)theconn;
    h2_proxy_session *session = p_conn->data;

    if (session && session->ngh2) {
        if (session->c && !session->c->aborted && !session->goaway_sent) {
            nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 
                                  session->max_stream_recv, 0, NULL, 0);
            nghttp2_session_send(session->ngh2);
        }

        nghttp2_session_del(session->ngh2);
        session->ngh2 = NULL;
        p_conn->data = NULL;
    }
    return APR_SUCCESS;
}

static int proxy_pass_brigade(apr_bucket_alloc_t *bucket_alloc,
                              proxy_conn_rec *p_conn,
                              conn_rec *origin, apr_bucket_brigade *bb,
                              int flush)
{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    apr_brigade_length(bb, 0, &transferred);
    if (transferred != -1)
        p_conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, bb);
    /* Cleanup the brigade now to avoid buckets lifetime
     * issues in case of error returned below. */
    apr_brigade_cleanup(bb);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, origin, APLOGNO(01084)
                      "pass request body failed to %pI (%s)",
                      p_conn->addr, p_conn->hostname);
        if (origin->aborted) {
            const char *ssl_note;

            if (((ssl_note = apr_table_get(origin->notes, "SSL_connect_rv"))
                 != NULL) && (strcmp(ssl_note, "err") == 0)) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            return HTTP_GATEWAY_TIME_OUT;
        }
        else {
            return HTTP_BAD_REQUEST;
        }
    }
    return OK;
}

static ssize_t raw_send(nghttp2_session *ngh2, const uint8_t *data,
                        size_t length, int flags, void *user_data)
{
    h2_proxy_session *session = user_data;
    apr_bucket *b;
    apr_status_t status;
    int flush = 1;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                  "h2_proxy_sesssion(%ld): raw_send %d bytes, flush=%d", 
                  session->c->id, (int)length, flush);
    b = apr_bucket_transient_create((const char*)data, length, 
                                    session->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(session->output, b);

    status = proxy_pass_brigade(session->c->bucket_alloc,  
                                session->p_conn, session->c, 
                                session->output, flush);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, 
                      "h2_proxy_sesssion(%ld): sending", session->c->id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return length;
}

static int on_frame_recv(nghttp2_session *ngh2, const nghttp2_frame *frame,
                         void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    int eos;
    
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO()
                      "h2_session(%ld): recv FRAME[%s]",
                      session->c->id, buffer);
    }

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            stream = nghttp2_session_get_stream_user_data(ngh2, frame->hd.stream_id);
            eos = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM);

            break;
        case NGHTTP2_PUSH_PROMISE:
            break;
        case NGHTTP2_GOAWAY:
            session->goaway_recvd = 1;
            /* TODO: close handling */
            break;
        default:
            break;
    }
    return 0;
}

static int before_frame_send(nghttp2_session *ngh2,
                             const nghttp2_frame *frame, void *user_data)
{
    h2_proxy_session *session = user_data;
    if (APLOGcdebug(session->c)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03068)
                      "h2_session(%ld): sent FRAME[%s]",
                      session->c->id, buffer);
    }
    return 0;
}

static int add_header(void *table, const char *n, const char *v)
{
    apr_table_addn(table, n, v);
    return 1;
}

static void process_proxy_header(request_rec *r, const char *n, const char *v)
{
    static const struct {
        const char *name;
        ap_proxy_header_reverse_map_fn func;
    } transform_hdrs[] = {
        { "Location", ap_proxy_location_reverse_map },
        { "Content-Location", ap_proxy_location_reverse_map },
        { "URI", ap_proxy_location_reverse_map },
        { "Destination", ap_proxy_location_reverse_map },
        { "Set-Cookie", ap_proxy_cookie_reverse_map },
        { NULL, NULL }
    };
    proxy_dir_conf *dconf;
    int i;
    
    for (i = 0; transform_hdrs[i].name; ++i) {
        if (!ap_casecmpstr(transform_hdrs[i].name, n)) {
            dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
            apr_table_add(r->headers_out, n,
                          (*transform_hdrs[i].func)(r, dconf, v));
            return;
       }
    }
    apr_table_add(r->headers_out, n, v);
}

static apr_status_t h2_proxy_stream_add_header_out(h2_proxy_stream *stream,
                                                   const char *n, apr_size_t nlen,
                                                   const char *v, apr_size_t vlen)
{
    if (n[0] == ':') {
        if (!stream->data_received && !strncmp(":status", n, nlen)) {
            char *s = apr_pstrndup(stream->pool, v, vlen);
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                          "h2_proxy_stream(%ld-%d): got status %s", 
                          stream->session->c->id, stream->id, s);
            stream->r->status = (int)apr_atoi64(s);
            if (stream->r->status <= 0) {
                stream->r->status = 500;
                return APR_EGENERAL;
            }
        }
        return APR_SUCCESS;
    }
    
    if (!h2_proxy_res_ignore_header(n, nlen)) {
        char *hname, *hvalue;
    
        hname = apr_pstrndup(stream->pool, n, nlen);
        h2_util_camel_case_header(hname, nlen);
        hvalue = apr_pstrndup(stream->pool, v, vlen);
        
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c, 
                      "h2_proxy_stream(%ld-%d): got header %s: %s", 
                      stream->session->c->id, stream->id, hname, hvalue);
        process_proxy_header(stream->r, hname, hvalue);
    }
    return APR_SUCCESS;
}

static int log_header(void *ctx, const char *key, const char *value)
{
    h2_proxy_stream *stream = ctx;
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, stream->r, 
                  "h2_proxy_stream(%ld-%d), header_out %s: %s", 
                  stream->session->c->id, stream->id, key, value);
    return 1;
}

static void h2_proxy_stream_end_headers_out(h2_proxy_stream *stream) 
{
    h2_proxy_session *session = stream->session;
    request_rec *r = stream->r;
    apr_pool_t *p = r->pool;
    
    /* Now, add in the cookies from the response to the ones already saved */
    apr_table_do(add_header, stream->saves, r->headers_out, "Set-Cookie", NULL);
    
    /* and now load 'em all in */
    if (!apr_is_empty_table(stream->saves)) {
        apr_table_unset(r->headers_out, "Set-Cookie");
        r->headers_out = apr_table_overlay(p, r->headers_out, stream->saves);
    }
    
    /* handle Via header in response */
    if (session->conf->viaopt != via_off 
        && session->conf->viaopt != via_block) {
        const char *server_name = ap_get_server_name(stream->r);
        apr_port_t port = ap_get_server_port(stream->r);
        char portstr[32];
        
        /* If USE_CANONICAL_NAME_OFF was configured for the proxy virtual host,
         * then the server name returned by ap_get_server_name() is the
         * origin server name (which does make too much sense with Via: headers)
         * so we use the proxy vhost's name instead.
         */
        if (server_name == stream->r->hostname) {
            server_name = stream->r->server->server_hostname;
        }
        if (ap_is_default_port(port, stream->r)) {
            portstr[0] = '\0';
        }
        else {
            apr_snprintf(portstr, sizeof(portstr), ":%d", port);
        }

        /* create a "Via:" response header entry and merge it */
        apr_table_addn(r->headers_out, "Via",
                       (session->conf->viaopt == via_full)
                       ? apr_psprintf(p, "%d.%d %s%s (%s)",
                                      HTTP_VERSION_MAJOR(r->proto_num),
                                      HTTP_VERSION_MINOR(r->proto_num),
                                      server_name, portstr,
                                      AP_SERVER_BASEVERSION)
                       : apr_psprintf(p, "%d.%d %s%s",
                                      HTTP_VERSION_MAJOR(r->proto_num),
                                      HTTP_VERSION_MINOR(r->proto_num),
                                      server_name, portstr)
                       );
    }
    
    if (APLOGrtrace2(stream->r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, stream->r, 
                      "h2_proxy_stream(%ld-%d), header_out after merging", 
                      stream->session->c->id, stream->id);
        apr_table_do(log_header, stream, stream->r->headers_out, NULL);
    }
}

static int on_data_chunk_recv(nghttp2_session *ngh2, uint8_t flags,
                              int32_t stream_id, const uint8_t *data,
                              size_t len, void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    apr_bucket *b;
    apr_status_t status;
    
    nghttp2_session_consume(ngh2, stream_id, len);
    stream = nghttp2_session_get_stream_user_data(ngh2, stream_id);
    if (!stream) {
        return 0;
    }
    
    if (!stream->data_received) {
        /* last chance to manipulate response headers.
         * after this, only trailers */
        h2_proxy_stream_end_headers_out(stream);
        stream->data_received = 1;
    }
    
    b = apr_bucket_transient_create((const char*)data, len, 
                                    stream->r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(stream->output, b);
    status = ap_pass_brigade(stream->r->output_filters, stream->output);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, APLOGNO()
                      "h2_session(%ld-%d): passing output", 
                      session->c->id, stream->id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int on_stream_close(nghttp2_session *ngh2, int32_t stream_id,
                           uint32_t error_code, void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    
    stream = nghttp2_session_get_stream_user_data(ngh2, stream_id);
    if (!stream) {
        return 0;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c, 
                  "h2_proxy_sesssion(%ld): closing stream(%d)", 
                  session->c->id, stream_id);

    if (!stream->data_received) {
        /* last chance to manipulate response headers.
         * after this, only trailers */
        stream->data_received = 1;
    }
    stream->state = H2_STREAM_ST_CLOSED;
    return 0;
}

static int on_header(nghttp2_session *ngh2, const nghttp2_frame *frame,
                     const uint8_t *namearg, size_t nlen,
                     const uint8_t *valuearg, size_t vlen, uint8_t flags,
                     void *user_data) 
{
    h2_proxy_session *session = user_data;
    h2_proxy_stream *stream;
    const char *n = (const char*)namearg;
    const char *v = (const char*)valuearg;
    
    (void)session;
    if (frame->hd.type == NGHTTP2_HEADERS && nlen) {
        stream = nghttp2_session_get_stream_user_data(ngh2, frame->hd.stream_id);
        if (stream) {
            if (h2_proxy_stream_add_header_out(stream, n, nlen, v, vlen)) {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        }
    }
    else if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    }
    
    return 0;
}

static ssize_t stream_data_read(nghttp2_session *ngh2, int32_t stream_id, 
                                uint8_t *buf, size_t length,
                                uint32_t *data_flags, 
                                nghttp2_data_source *source, void *user_data)
{
    h2_proxy_stream *stream;
    apr_status_t status = APR_SUCCESS;
    
    *data_flags = 0;
    stream = nghttp2_session_get_stream_user_data(ngh2, stream_id);
    if (!stream) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (APR_BRIGADE_EMPTY(stream->input)) {
        status = ap_get_brigade(stream->r->input_filters, stream->input,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                H2MIN(APR_BUCKET_BUFF_SIZE, length));
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, status, stream->r, 
                      "h2_proxy_stream(%d): request body read", 
                      stream->id);
    }

    if (status == APR_SUCCESS) {
        ssize_t readlen = 0;
        while (status == APR_SUCCESS 
               && (readlen < length)
               && !APR_BRIGADE_EMPTY(stream->input)) {
            apr_bucket* b = APR_BRIGADE_FIRST(stream->input);
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                }
                else {
                    /* we do nothing more regarding any meta here */
                }
            }
            else {
                const char *bdata = NULL;
                apr_size_t blen = 0;
                status = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
                
                if (status == APR_SUCCESS && blen > 0) {
                    ssize_t copylen = H2MIN(length - readlen, blen);
                    memcpy(buf, bdata, copylen);
                    buf += copylen;
                    readlen += copylen;
                    if (copylen < blen) {
                        /* We have data left in the bucket. Split it. */
                        status = apr_bucket_split(b, copylen);
                    }
                }
            }
            apr_bucket_delete(b);
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, status, stream->r, 
                      "h2_proxy_stream(%d): request body read %ld bytes, flags=%d", 
                      stream->id, (long)readlen, (int)*data_flags);
        return readlen;
    }
    else if (APR_STATUS_IS_EAGAIN(status)) {
        return NGHTTP2_ERR_DEFERRED;
    }
    return ngstatus_from_apr_status(status);
}

h2_proxy_session *h2_proxy_session_setup(request_rec *r, proxy_conn_rec *p_conn,
                                         proxy_server_conf *conf)
{
    if (!p_conn->data) {
        h2_proxy_session *session;
        nghttp2_settings_entry settings[2];
        nghttp2_session_callbacks *cbs;
        int add_conn_window;
        int rv;
        
        session = apr_pcalloc(p_conn->scpool, sizeof(*session));
        apr_pool_pre_cleanup_register(p_conn->scpool, p_conn, proxy_session_shutdown);
        p_conn->data = session;
        
        session->c = p_conn->connection;
        session->p_conn = p_conn;
        session->conf = conf;
        session->pool = p_conn->scpool;
        session->window_bits_default    = 30;
        session->window_bits_connection = 30;
    
        session->input = apr_brigade_create(session->pool, session->c->bucket_alloc);
        session->output = apr_brigade_create(session->pool, session->c->bucket_alloc);
    
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);
        nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
        nghttp2_session_callbacks_set_before_frame_send_callback(cbs, before_frame_send);
        nghttp2_session_callbacks_set_send_callback(cbs, raw_send);
        
        nghttp2_session_client_new(&session->ngh2, cbs, session);
        nghttp2_session_callbacks_del(cbs);

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      "setup session for %s", p_conn->hostname);
        
        settings[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
        settings[0].value = 0;
        settings[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
        settings[1].value = (1 << session->window_bits_default) - 1;
        
        rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE, settings, 
                                     H2_ALEN(settings));

        /* If the connection window is larger than our default, trigger a WINDOW_UPDATE */
        add_conn_window = ((1 << session->window_bits_connection) - 1 -
                           NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE);
        if (!rv && add_conn_window != 0) {
            rv = nghttp2_submit_window_update(session->ngh2, NGHTTP2_FLAG_NONE, 0, add_conn_window);
        }
    }
    return p_conn->data;
}


apr_status_t h2_proxy_session_open_stream(h2_proxy_session *session, const char *url,
                                          request_rec *r, h2_proxy_stream **pstream)
{
    h2_proxy_stream *stream;
    apr_uri_t puri;
    const char *authority, *scheme, *path;

    stream = apr_pcalloc(r->pool, sizeof(*stream));

    stream->pool = r->pool;
    stream->url = url;
    stream->r = r;
    stream->session = session;
    stream->state = H2_STREAM_ST_IDLE;
    
    stream->input = apr_brigade_create(stream->pool, session->c->bucket_alloc);
    stream->output = apr_brigade_create(stream->pool, session->c->bucket_alloc);
    
    stream->req = h2_request_create(1, stream->pool, 0);

    apr_uri_parse(stream->pool, url, &puri);
    scheme = (strcmp(puri.scheme, "h2")? "http" : "https");
    authority = puri.hostname;
    if (!ap_strchr_c(authority, ':') && puri.port
        && apr_uri_port_of_scheme(scheme) != puri.port) {
        /* port info missing and port is not default for scheme: append */
        authority = apr_psprintf(stream->pool, "%s:%d", authority, puri.port);
    }
    path = apr_uri_unparse(stream->pool, &puri, APR_URI_UNP_OMITSITEPART);
    h2_request_make(stream->req, stream->pool, r->method, scheme,
                    authority, path, r->headers_in);

    /* Tuck away all already existing cookies */
    stream->saves = apr_table_make(r->pool, 2);
    apr_table_do(add_header, stream->saves, r->headers_out,"Set-Cookie", NULL);

    *pstream = stream;
    
    return APR_SUCCESS;
}

static apr_status_t feed_brigade(h2_proxy_session *session, apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    apr_size_t readlen = 0;
    ssize_t n;
    
    while (status == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb)) {
        apr_bucket* b = APR_BRIGADE_FIRST(bb);
        
        if (!APR_BUCKET_IS_METADATA(b)) {
            const char *bdata = NULL;
            apr_size_t blen = 0;
            
            status = apr_bucket_read(b, &bdata, &blen, APR_NONBLOCK_READ);
            if (status == APR_SUCCESS && blen > 0) {
                n = nghttp2_session_mem_recv(session->ngh2, (const uint8_t *)bdata, blen);
                if (n < 0) {
                    if (nghttp2_is_fatal((int)n)) {
                        return APR_EGENERAL;
                    }
                }
                else {
                    readlen += n;
                    if (n < blen) {
                        apr_bucket_split(b, n);
                    }
                }
            }
        }
        apr_bucket_delete(b);
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c, 
                  "h2_session(%ld): fed %ld bytes of input", session->c->id, (long)readlen);
    if (readlen == 0 && status == APR_SUCCESS) {
        return APR_EAGAIN;
    }
    return status;
}


static apr_status_t stream_loop(h2_proxy_stream *stream) 
{
    h2_proxy_session *session = stream->session;
    apr_status_t status = APR_SUCCESS;
    int want_read, want_write;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c, 
                  "h2_session(%ld): start loop for stream %d", 
                  session->c->id, stream->id);
    while ((status == APR_SUCCESS || APR_STATUS_IS_EAGAIN(status))
           && stream->state != H2_STREAM_ST_CLOSED) {
           
        want_read = nghttp2_session_want_read(session->ngh2);
        want_write = nghttp2_session_want_write(session->ngh2);
               
        if (want_write) {
            int rv = nghttp2_session_send(session->ngh2);
            if (rv < 0 && nghttp2_is_fatal(rv)) {
                status = APR_EGENERAL;
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c, 
                              "h2_session(%ld): write, rv=%d", session->c->id, rv);
                break;
            }
        }

        if (want_read) {
            status = ap_get_brigade(session->c->input_filters, session->input, 
                                    AP_MODE_READBYTES, 
                                    (want_write? APR_NONBLOCK_READ : APR_BLOCK_READ), 
                                    APR_BUCKET_BUFF_SIZE);
            if (status == APR_SUCCESS) {
                status = feed_brigade(session, session->input);
            }
            else if (!APR_STATUS_IS_EAGAIN(status)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c, 
                              "h2_session(%ld): read", session->c->id);
                break;
            }
        }
        
        if (!want_read && !want_write) {
            status = APR_EGENERAL;
            break;
        }
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, session->c, 
                  "h2_session(%ld): end loop for stream %d", 
                  session->c->id, stream->id);
    return status;
}

apr_status_t h2_proxy_stream_process(h2_proxy_stream *stream)
{
    h2_proxy_session *session = stream->session;
    h2_ngheader *hd;
    nghttp2_data_provider *pp = NULL;
    nghttp2_data_provider provider;
    int rv;
    apr_status_t status;

    hd = h2_util_ngheader_make_req(stream->pool, stream->req);
    
    status = ap_get_brigade(stream->r->input_filters, stream->input,
                            AP_MODE_READBYTES, APR_NONBLOCK_READ,
                            APR_BUCKET_BUFF_SIZE);
    if ((status == APR_SUCCESS && !APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(stream->input)))
        || APR_STATUS_IS_EAGAIN(status)) {
        /* there might be data coming */
        provider.source.fd = 0;
        provider.source.ptr = NULL;
        provider.read_callback = stream_data_read;
        pp = &provider;
    }

    rv = nghttp2_submit_request(session->ngh2, NULL, 
                                hd->nv, hd->nvlen, pp, stream);
                                
    if (APLOGcdebug(session->c)) {
        const char *task_id = apr_table_get(stream->r->connection->notes, 
                                            H2_TASK_ID_NOTE);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      "h2_session(%ld): submit %s%s -> %d (task %s)", 
                      session->c->id, stream->req->authority, stream->req->path,
                      rv, task_id);
    }
    if (rv > 0) {
        stream->id = rv;
        stream->state = H2_STREAM_ST_OPEN;
        
        return stream_loop(stream);
    }
    return APR_EGENERAL;
}

