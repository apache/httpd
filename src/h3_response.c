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
#include <http_log.h>

#include <apr_buckets.h>
#include <apr_strings.h>

#include "h3.h"
#include "h3_conn.h"
#include "h3_quic_io.h"
#include "h3_request.h"
#include "h3_response.h"
#include "h3_ssl.h"
#include "h3_stream_ids.h"
#include "h3_util.h"

static int add_header_entry(void* rec, const char* key, const char* value)
{
    h3_nvs_t* h3_nvs = (h3_nvs_t*)rec;
    size_t cur_nv = h3_nvs->cur_nv;
    char* header_name;
    char* header_value;
    nghttp3_nv* resp = h3_nvs->resp;
    if (cur_nv == h3_nvs->max_nv)
        return 0; /* stop not enough space */
    header_name = apr_pstrdup(h3_nvs->p, key);
    ap_str_tolower(header_name);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3_nvs->s, "add_header_entry: %s %s", header_name, value);
    header_value = apr_pstrdup(h3_nvs->p, value);
    make_nv(&resp[cur_nv++], header_name, header_value);
    h3_nvs->cur_nv = cur_nv;
    return 1;
}

void build_nv_from_response(nghttp3_nv* resp, size_t* num_nv, size_t max_nv, h3_conn_ctx_t* h3ctx)
{
    h3_nvs_t h3_nvs;
    ap_bucket_response* response = h3ctx->resp;
    size_t cur_nv = *num_nv;
    char* stringstatus;
    h3_nvs.resp = resp;
    h3_nvs.cur_nv = cur_nv;
    h3_nvs.max_nv = max_nv;
    h3_nvs.s = h3ctx->s;
    h3_nvs.p = h3ctx->c3reqpool;

    /* set response->status */
    stringstatus = apr_psprintf(h3ctx->c3reqpool, "%d", response->status);
    make_nv(&resp[cur_nv++], ":status", stringstatus);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ctx->s, "build_nv_from_response status %s", stringstatus);

    /* set response->reason */
    if (response->reason != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ctx->s, "build_nv_from_response reason %s", response->reason);
    }

    h3_nvs.cur_nv = cur_nv;
    if (response->headers != NULL)
    {
        apr_table_do(add_header_entry, (void*)&h3_nvs, response->headers, NULL);
    }
    *num_nv = h3_nvs.cur_nv;
}

int quic_server_write_response(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* /*p*/)
{
    int ok = -1;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response");
    for (;;)
    {
        nghttp3_vec vec[256];
        nghttp3_ssize sveccnt;
        int fin, i;
        int64_t streamid;

        sveccnt = nghttp3_conn_writev_stream(h3ssl->h3conn, &streamid, &fin, vec, nghttp3_arraylen(vec));
        if (sveccnt <= 0)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: nghttp3_conn_writev_stream done: %ld on %" PRIu64 " fin %d", (long int)sveccnt, (uint64_t)streamid, fin);
            if (streamid != -1 && fin)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: Sending end data on %" PRIu64 " fin %d", (uint64_t)streamid, fin);
                nghttp3_conn_add_write_offset(h3ssl->h3conn, streamid, 0);
                continue;
            }
            break; /* Done */
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: nghttp3_conn_writev_stream: %ld fin: %d", (long int)sveccnt, fin);
        for (i = 0; i < sveccnt; i++)
        {
            size_t numbytes = vec[i].len;
            int flagwrite = 0;

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: quic_server_write on %" PRIu64 " for %ld", (uint64_t)streamid, (unsigned long)vec[i].len);
            if (get_id_status((uint64_t)streamid, ssl_ids) & RETRYWRITE)
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write RETRYWRITE");
            if (fin && i == sveccnt - 1)
            {
                /* mark that we are using fin */
                struct h3_request* h3req = get_h3_request(h3ssl, streamid);
                h3req->finsend = 1;
                flagwrite = SSL_WRITE_FLAG_CONCLUDE;
            }
            if (!quic_server_write(ssl_ids, (uint64_t)streamid, vec[i].base, vec[i].len, (uint64_t)flagwrite, &numbytes))
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write failed!");
                goto err;
            }
            else
            {
                if (numbytes == 0)
                {
                    /* we need to retry the flow stopped us (quic_server_write sets the RETRYWRITE for us? */
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write RETRYWRITE %" PRIu64 " status: %d", (uint64_t)streamid, get_id_status((uint64_t)streamid, ssl_ids));
                    // return WAIT_RETRY;
                    continue; // We ignore it...
                }
                if (get_id_status((uint64_t)streamid, ssl_ids) & RETRYWRITE)
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write RETRYWRITE %" PRIu64 " OK", (uint64_t)streamid);
            }
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response %d %ld on %" PRIu64 " len: %zu", i, (long)sveccnt, (uint64_t)streamid, (size_t)nghttp3_vec_len(vec, (size_t)i));
        if (nghttp3_conn_add_write_offset(h3ssl->h3conn, streamid, (size_t)nghttp3_vec_len(vec, (size_t)i)))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: nghttp3_conn_add_write_offset failed!");
            return ERROR_LOGIC;
        }
    }

    ok = 0;
err:
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response DONE!!!");
    if (ok)
        ERR_print_errors_log(h3ssl);

    return ok;
}

int process_h3response(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, struct h3_request* h3req, server_rec* s, apr_pool_t* p)
{
    int ok = -1;
    nghttp3_nv resp[10];
    size_t num_nv = 0;
    nghttp3_data_reader dr;
    h3_conn_ctx_t* h3ctx;

    h3req->end_headers_received = 0;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "end_headers_received!!!");
    if (!h3ssl->has_uni)
    {
        /* time to create those otherwise we can't push anything to the client */
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Create uni");
        if (quic_server_h3streams(h3ssl->h3conn, h3ssl, ssl_ids) == -1)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_h3streams failed!");
            goto err;
        }
        h3ssl->has_uni = 1;
    }

    /* we have receive the request build the response and send it */
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server processing request!");
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server %d %d", h3req->datadone, h3req->num_headers);
    if (h3req->datadone)
        abort(); // JFC logical problem...

    h3ctx = h3req->h3ctx;
    if (process_request(h3req->r, h3ctx) != APR_SUCCESS)
    {
        /* Probably we should return a bad request or something the like */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server processing request FAILED!");
        goto err;
    }
    if (h3ctx->resp == NULL)
    {
        /* Probably we should return a bad request or something the like */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server no response!");
        goto err;
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server processing response part!");
    }
    build_nv_from_response(resp, &num_nv, 10, h3ctx);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server num_nv: %zu", num_nv);

    /* Process the other bucket */
    uint8_t* buffer;
    apr_size_t len = 0;
    if (h3ctx->otherpart != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server has other part %p %p %p", (void*)h3ctx, (void*)h3ctx->otherpart, (void*)h3ctx->dataheap);
        if (h3ctx->dataheap != NULL)
        {
            abort();
        }
        if (APR_BUCKET_IS_FILE(h3ctx->otherpart))
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_FILE");
            apr_bucket_file* f = (apr_bucket_file*)h3ctx->otherpart->data;
            apr_file_t* fd = f->fd;
            apr_off_t offset = h3ctx->otherpart->start;
            apr_status_t rv;

            len = h3ctx->otherpart->length;
            rv = apr_file_seek(fd, APR_SET, &offset);
            if (rv != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_file_seek failed %d %d", rv, APR_EOF);
                abort(); /* Problem */
            }
            buffer = apr_palloc(p, len);
            rv = apr_file_read(fd, buffer, &len);
            if (rv != APR_SUCCESS && rv != APR_EOF)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_file_read failed %d", rv);
                abort(); /* Problem */
            }
            h3req->ptr_data = buffer;
        }
        else if (APR_BUCKET_IS_MMAP(h3ctx->otherpart))
        {
            const char* data = NULL;
            apr_status_t rv;

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_MMAP");
            len = h3ctx->otherpart->length;
            rv = apr_bucket_read(h3ctx->otherpart, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_bucket_read failed %d %d", rv, APR_EOF);
                abort(); /* Problem */
            }
            if (data == (char*)-1)
            {
                // abort(); /* Problem */
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_bucket_read %s not yet supported", h3ctx->otherpart->type->name);
                buffer = apr_palloc(p, len);
                memset(buffer, 'A', len);
                h3req->ptr_data = buffer;
            }
            else if (len > 0 && data != NULL)
            {
                buffer = apr_palloc(p, len);
                memcpy(buffer, data, len);
                h3req->ptr_data = buffer;
            }
            else
                abort(); /* Problem */
        }
        else if (APR_BUCKET_IS_HEAP(h3ctx->otherpart))
        {
            const char* data;
            apr_size_t datalen;
            const char* cl_str;
            uint8_t* ptr;

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_HEAP");
            // Look up the Content-Length header
            cl_str = apr_table_get(h3req->r->headers_in, "Content-Length");

            if (cl_str)
            {
                // Convert string to an off_t (large integer)
                datalen = (apr_size_t)apr_atoi64(cl_str);
            }
            else
                abort();

            buffer = apr_palloc(p, datalen);
            len = datalen;
            h3req->ptr_data = buffer;

            ptr = buffer;
            apr_bucket_read(h3ctx->otherpart, &data, &len, APR_BLOCK_READ);
            memcpy(ptr, data, len);

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_HEAP %zu", datalen);
        }
        else
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server %s not yet supported", h3ctx->otherpart->type->name);
            abort(); /* For the moment the otherpart is a FILE bucket */
        }
    }
    if (h3ctx->dataheap != NULL)
    {
        if (h3ctx->otherpart != NULL)
        {
            abort();
        }
        /* We have read the buffer in mod_http3.c */
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server has APR_BUCKET_IS_HEAP %p %zu", (void*)h3ctx, h3ctx->dataheaplen);
        h3req->ptr_data = (uint8_t*)h3ctx->dataheap;
        len = h3ctx->dataheaplen;
    }
    /* Just trying */
    h3req->ldata = len;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server num_nv: %zu Just trying!!!", num_nv);

    dr.read_data = step_read_data;
    if (nghttp3_conn_submit_response(h3ssl->h3conn, h3req->id_bidi, resp, num_nv, &dr))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "nghttp3_conn_submit_response failed!");
        goto err;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "nghttp3_conn_submit_response on %" PRIu64 "...", (uint64_t)h3req->id_bidi);
    ok = quic_server_write_response(h3ssl, ssl_ids, s, p);
    if (ok == -1)
        goto err; /* SSL error, troubles */
    if (ok == ERROR_LOGIC)
        return ERROR_LOGIC;
    if (ok == WAIT_RETRY)
    {
        /* we need to figure out here */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "nghttp3_conn_submit_response PARTIAL!!!");
        return ok;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "nghttp3_conn_submit_response DONE!!!");

    ok = 0;
err:
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server Done!");
    if (ok)
        ERR_print_errors_log(h3ssl);

    return ok;
}
