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

#include <assert.h>
#include <stdio.h>

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_connection.h>

#include "h2_private.h"
#include "h2_mplx.h"
#include "h2_response.h"
#include "h2_task.h"
#include "h2_to_h1.h"
#include "h2_util.h"


h2_to_h1 *h2_to_h1_create(int stream_id, apr_pool_t *pool, 
                          apr_bucket_alloc_t *bucket_alloc, 
                          const char *method, 
                          const char *scheme, 
                          const char *authority, 
                          const char *path,
                          struct h2_mplx *m)
{
    h2_to_h1 *to_h1;
    if (!method) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, m->c,
                      APLOGNO(02943) 
                      "h2_to_h1: header start but :method missing");
        return NULL;
    }
    if (!path) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, m->c,
                      APLOGNO(02944) 
                      "h2_to_h1: header start but :path missing");
        return NULL;
    }
    
    to_h1 = apr_pcalloc(pool, sizeof(h2_to_h1));
    if (to_h1) {
        to_h1->stream_id = stream_id;
        to_h1->pool = pool;
        to_h1->method = method;
        to_h1->scheme = scheme;
        to_h1->authority = authority;
        to_h1->path = path;
        to_h1->m = m;
        to_h1->headers = apr_table_make(to_h1->pool, 10);
        to_h1->bb = apr_brigade_create(pool, bucket_alloc);
        to_h1->chunked = 0; /* until we see a content-type and no length */
        to_h1->content_len = -1;
    }
    return to_h1;
}

void h2_to_h1_destroy(h2_to_h1 *to_h1)
{
    to_h1->bb = NULL;
}

apr_status_t h2_to_h1_add_header(h2_to_h1 *to_h1,
                                 const char *name, size_t nlen,
                                 const char *value, size_t vlen)
{
    char *hname, *hvalue;
    if (H2_HD_MATCH_LIT("transfer-encoding", name, nlen)) {
        if (!apr_strnatcasecmp("chunked", value)) {
            /* This should never arrive here in a HTTP/2 request */
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_BADARG, to_h1->m->c,
                          APLOGNO(02945) 
                          "h2_to_h1: 'transfer-encoding: chunked' received");
            return APR_BADARG;
        }
    }
    else if (H2_HD_MATCH_LIT("content-length", name, nlen)) {
        char *end;
        to_h1->content_len = apr_strtoi64(value, &end, 10);
        if (value == end) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, to_h1->m->c,
                          APLOGNO(02959) 
                          "h2_request(%d): content-length value not parsed: %s",
                          to_h1->stream_id, value);
            return APR_EINVAL;
        }
        to_h1->remain_len = to_h1->content_len;
        to_h1->chunked = 0;
    }
    else if (H2_HD_MATCH_LIT("content-type", name, nlen)) {
        /* If we see a content-type and have no length (yet),
         * we need to chunk. */
        to_h1->chunked = (to_h1->content_len == -1);
    }
    else if ((to_h1->seen_host && H2_HD_MATCH_LIT("host", name, nlen))
             || H2_HD_MATCH_LIT("expect", name, nlen)
             || H2_HD_MATCH_LIT("upgrade", name, nlen)
             || H2_HD_MATCH_LIT("connection", name, nlen)
             || H2_HD_MATCH_LIT("proxy-connection", name, nlen)
             || H2_HD_MATCH_LIT("keep-alive", name, nlen)
             || H2_HD_MATCH_LIT("http2-settings", name, nlen)) {
        /* ignore these. */
        return APR_SUCCESS;
    }
    else if (H2_HD_MATCH_LIT("cookie", name, nlen)) {
        const char *existing = apr_table_get(to_h1->headers, "cookie");
        if (existing) {
            char *nval;
            
            /* Cookie headers come separately in HTTP/2, but need
             * to be merged by "; " (instead of default ", ")
             */
            hvalue = apr_pstrndup(to_h1->pool, value, vlen);
            nval = apr_psprintf(to_h1->pool, "%s; %s", existing, hvalue);
            apr_table_setn(to_h1->headers, "Cookie", nval);
            return APR_SUCCESS;
        }
    }
    else if (H2_HD_MATCH_LIT("host", name, nlen)) {
        to_h1->seen_host = 1;
    }
    
    hname = apr_pstrndup(to_h1->pool, name, nlen);
    hvalue = apr_pstrndup(to_h1->pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);
    apr_table_mergen(to_h1->headers, hname, hvalue);
    
    return APR_SUCCESS;
}

static int set_header(void *ctx, const char *key, const char *value)
{
    h2_to_h1 *to_h1 = (h2_to_h1*)ctx;
    h2_to_h1_add_header(to_h1, key, strlen(key), value, strlen(value));
    return 1;
}

apr_status_t h2_to_h1_add_headers(h2_to_h1 *to_h1, apr_table_t *headers)
{
    apr_table_do(set_header, to_h1, headers, NULL);
    return APR_SUCCESS;
}

apr_status_t h2_to_h1_end_headers(h2_to_h1 *to_h1, h2_task *task, int eos)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, to_h1->m->c,
                  "h2_to_h1(%ld-%d): end headers", 
                  to_h1->m->id, to_h1->stream_id);
    
    if (to_h1->eoh) {
        return APR_EINVAL;
    }
    
    if (!to_h1->seen_host) {
        /* Need to add a "Host" header if not already there to
         * make virtual hosts work correctly. */
        if (!to_h1->authority) {
            return APR_BADARG;
        }
        apr_table_set(to_h1->headers, "Host", to_h1->authority);
    }

    if (eos && to_h1->chunked) {
        /* We had chunking figured out, but the EOS is already there.
         * unmark chunking and set a definitive content-length.
         */
        to_h1->chunked = 0;
        apr_table_setn(to_h1->headers, "Content-Length", "0");
    }
    else if (to_h1->chunked) {
        /* We have not seen a content-length. We therefore must
         * pass any request content in chunked form.
         */
        apr_table_mergen(to_h1->headers, "Transfer-Encoding", "chunked");
    }
    
    h2_task_set_request(task, to_h1->method, 
                        to_h1->scheme, 
                        to_h1->authority, 
                        to_h1->path, 
                        to_h1->headers, eos);
    to_h1->eoh = 1;
    
    if (eos) {
        apr_status_t status = h2_to_h1_close(to_h1);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, to_h1->m->c,
                          APLOGNO(02960) 
                          "h2_to_h1(%ld-%d): end headers, eos=%d", 
                          to_h1->m->id, to_h1->stream_id, eos);
        }
        return status;
    }
    return APR_SUCCESS;
}

static apr_status_t flush(apr_bucket_brigade *bb, void *ctx) 
{
    (void)bb;
    return h2_to_h1_flush((h2_to_h1*)ctx);
}

static apr_status_t h2_to_h1_add_data_raw(h2_to_h1 *to_h1,
                                          const char *data, size_t len)
{
    apr_status_t status = APR_SUCCESS;

    if (to_h1->eos || !to_h1->eoh) {
        return APR_EINVAL;
    }
    
    status = apr_brigade_write(to_h1->bb, flush, to_h1, data, len);
    if (status == APR_SUCCESS) {
        status = h2_to_h1_flush(to_h1);
    }
    return status;
}


apr_status_t h2_to_h1_add_data(h2_to_h1 *to_h1,
                               const char *data, size_t len)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, to_h1->m->c,
                  "h2_to_h1(%ld-%d): add %ld data bytes", 
                  to_h1->m->id, to_h1->stream_id, (long)len);
    
    if (to_h1->chunked) {
        /* if input may have a body and we have not seen any
         * content-length header, we need to chunk the input data.
         */
        apr_status_t status = apr_brigade_printf(to_h1->bb, NULL, NULL,
                                                 "%lx\r\n", (unsigned long)len);
        if (status == APR_SUCCESS) {
            status = h2_to_h1_add_data_raw(to_h1, data, len);
            if (status == APR_SUCCESS) {
                status = apr_brigade_puts(to_h1->bb, NULL, NULL, "\r\n");
            }
        }
        return status;
    }
    else {
        to_h1->remain_len -= len;
        if (to_h1->remain_len < 0) {
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, to_h1->m->c,
                          APLOGNO(02961) 
                          "h2_to_h1(%ld-%d): got %ld more content bytes than announced "
                          "in content-length header: %ld", 
                          to_h1->m->id, to_h1->stream_id, 
                          (long)to_h1->content_len, -(long)to_h1->remain_len);
        }
        return h2_to_h1_add_data_raw(to_h1, data, len);
    }
}

apr_status_t h2_to_h1_flush(h2_to_h1 *to_h1)
{
    apr_status_t status = APR_SUCCESS;
    if (!APR_BRIGADE_EMPTY(to_h1->bb)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, to_h1->m->c,
                      "h2_to_h1(%ld-%d): flush request bytes", 
                      to_h1->m->id, to_h1->stream_id);
        
        status = h2_mplx_in_write(to_h1->m, to_h1->stream_id, to_h1->bb);
        if (status != APR_SUCCESS) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, to_h1->m->c,
                          APLOGNO(02946) "h2_request(%d): pushing request data",
                          to_h1->stream_id);
        }
    }
    return status;
}

apr_status_t h2_to_h1_close(h2_to_h1 *to_h1)
{
    apr_status_t status = APR_SUCCESS;
    if (!to_h1->eos) {
        if (to_h1->chunked) {
            status = h2_to_h1_add_data_raw(to_h1, "0\r\n\r\n", 5);
        }
        to_h1->eos = 1;
        status = h2_to_h1_flush(to_h1);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, to_h1->m->c,
                      "h2_to_h1(%d): close", to_h1->stream_id);
        
        status = h2_mplx_in_close(to_h1->m, to_h1->stream_id);
    }
    return status;
}


