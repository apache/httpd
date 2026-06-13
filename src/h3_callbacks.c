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

#include <http_log.h>
#include <http_protocol.h>

#include <apr_strings.h>

#include "h3_callbacks.h"
#include "h3_request.h"
#include "h3_ssl.h"

int on_recv_header(nghttp3_conn* /*conn*/, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t /*flags*/, void* user_data, void* /*stream_user_data*/)
{
    nghttp3_vec vname, vvalue;
    struct h3ssl* h3ssl = (struct h3ssl*)user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);
    request_rec* r;

    if (h3req == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_recv_header, create request");
        h3req = create_h3_request(h3ssl, stream_id);
    }

    r = h3req->r;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_recv_header, add header to request");
    h3req->num_headers++;
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    /* Process uri */
    if (token == NGHTTP3_QPACK_TOKEN__PATH)
    {
        /* :path */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Path too long or empty: %zu bytes (max %d)", vvalue.len, MAXURL);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        r->uri = apr_pcalloc(r->pool, len);
        memcpy(r->uri, vvalue.base, vvalue.len);

        /* add the unparsed_uri */
        r->unparsed_uri = r->uri;
        apr_uri_parse(r->pool, r->uri, &r->parsed_uri);
        return 0;
    }

    /* Process scheme */
    if (token == NGHTTP3_QPACK_TOKEN__SCHEME)
    {
        /* :scheme */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Scheme too long or empty: %zu bytes", vvalue.len);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        char* scheme = apr_pcalloc(r->pool, len);
        memcpy(scheme, vvalue.base, vvalue.len);
        apr_table_setn(r->headers_in, "Scheme", scheme);
        return 0;
    }

    /* Process method */
    if (token == NGHTTP3_QPACK_TOKEN__METHOD)
    {
        /* :method */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Invalid method length: %zu", vvalue.len);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        r->method = apr_pcalloc(r->pool, len);
        memcpy((char*)r->method, vvalue.base, vvalue.len);
        return 0;
    }

    /* Process authority */
    if (token == NGHTTP3_QPACK_TOKEN__AUTHORITY)
    {
        /* :authority = Host */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Authority too long or empty: %zu bytes", vvalue.len);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        char* host = apr_pcalloc(r->pool, len);
        memcpy(host, vvalue.base, vvalue.len);
        apr_table_setn(r->headers_in, "Host", host);
        return 0;
    }

    /* Received a single HTTP header. */
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);
    if (vname.len == 0 || vname.len >= MAXHEADER)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Header name too long or empty: %zu bytes", vname.len);
        return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    }
    if (vvalue.len >= MAXHEADER)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Header value too long: %zu bytes", vvalue.len);
        return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    }
    size_t ln = vname.len + 1;
    size_t lv = vvalue.len + 1;
    char* sname = apr_pcalloc(r->pool, ln);
    memcpy(sname, vname.base, vname.len);
    char* svalue = apr_pcalloc(r->pool, lv);
    memcpy(svalue, vvalue.base, vvalue.len);
    apr_table_setn(r->headers_in, sname, svalue);
    return 0;
}

int on_end_headers(nghttp3_conn* /*conn*/, int64_t stream_id, int /*fin*/, void* user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_end_headers!");
    h3req->end_headers_received = 1;
    return 0;
}

int on_recv_data(nghttp3_conn* /*conn*/, int64_t stream_id, const uint8_t* data, size_t datalen, void* conn_user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)conn_user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);
    request_rec* r;
    char* postdata;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_recv_data! %ld", (unsigned long)datalen);
    if (h3req == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "on_recv_data: h3req is NULL for stream %" PRIu64, stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    r = h3req->r;
    if (r == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "on_recv_data: request_rec is NULL!");
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    postdata = apr_palloc(r->pool, datalen);
    memcpy(postdata, data, datalen);
    apr_table_set(r->notes, "H3POSTDATA", postdata);
    apr_table_set(r->notes, "H3POSTDATALEN", apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, datalen));
    return 0;
}

int on_end_stream(nghttp3_conn* /*h3conn*/, int64_t stream_id, void* conn_user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)conn_user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_end_stream on %" PRIu64, stream_id);
    h3req->endstream = 1;
    return 0;
}

int on_stream_close(nghttp3_conn* /*h3conn*/, int64_t stream_id, uint64_t /*app_error_code*/, void* conn_user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)conn_user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    h3req->closestream = 1;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_stream_close on %" PRIu64, stream_id);
    cleanup_h3_request(h3ssl, h3req, stream_id);
    return 0;
}
