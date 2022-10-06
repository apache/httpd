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
#include <stdio.h>

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <util_time.h>

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2_protocol.h"
#include "h2_config.h"
#include "h2_util.h"
#include "h2_request.h"
#include "h2_headers.h"

#if !AP_HAS_RESPONSE_BUCKETS

static int is_unsafe(server_rec *s) 
{
    core_server_config *conf = ap_get_core_module_config(s->module_config);
    return (conf->http_conformance == AP_HTTP_CONFORMANCE_UNSAFE);
}

typedef struct {
    apr_bucket_refcount refcount;
    h2_headers *headers;
} h2_bucket_headers;
 
static apr_status_t bucket_read(apr_bucket *b, const char **str,
                                apr_size_t *len, apr_read_type_e block)
{
    (void)b;
    (void)block;
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

apr_bucket * h2_bucket_headers_make(apr_bucket *b, h2_headers *r)
{
    h2_bucket_headers *br;

    br = apr_bucket_alloc(sizeof(*br), b->list);
    br->headers = r;

    b = apr_bucket_shared_make(b, br, 0, 0);
    b->type = &h2_bucket_type_headers;
    b->length = 0;
    
    return b;
} 

apr_bucket * h2_bucket_headers_create(apr_bucket_alloc_t *list, 
                                       h2_headers *r)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b = h2_bucket_headers_make(b, r);
    return b;
}
                                       
h2_headers *h2_bucket_headers_get(apr_bucket *b)
{
    if (H2_BUCKET_IS_HEADERS(b)) {
        return ((h2_bucket_headers *)b->data)->headers;
    }
    return NULL;
}

const apr_bucket_type_t h2_bucket_type_headers = {
    "H2HEADERS", 5, APR_BUCKET_METADATA,
    apr_bucket_destroy_noop,
    bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

apr_bucket *h2_bucket_headers_clone(apr_bucket *b, apr_pool_t *pool,
                                    apr_bucket_alloc_t *list)
{
    h2_headers *hdrs = ((h2_bucket_headers *)b->data)->headers;
    return h2_bucket_headers_create(list, h2_headers_clone(pool, hdrs));
}


h2_headers *h2_headers_create(int status, const apr_table_t *headers_in, 
                              const apr_table_t *notes, apr_off_t raw_bytes,
                              apr_pool_t *pool)
{
    h2_headers *headers = apr_pcalloc(pool, sizeof(h2_headers));
    headers->status    = status;
    headers->headers   = (headers_in? apr_table_clone(pool, headers_in)
                           : apr_table_make(pool, 5));
    headers->notes     = (notes? apr_table_clone(pool, notes)
                           : apr_table_make(pool, 5));
    return headers;
}

static int add_header_lengths(void *ctx, const char *name, const char *value) 
{
    apr_size_t *plen = ctx;
    *plen += strlen(name) + strlen(value); 
    return 1;
}

apr_size_t h2_headers_length(h2_headers *headers)
{
    apr_size_t len = 0;
    apr_table_do(add_header_lengths, &len, headers->headers, NULL);
    return len;
}

apr_size_t h2_bucket_headers_headers_length(apr_bucket *b)
{
    h2_headers *h = h2_bucket_headers_get(b);
    return h? h2_headers_length(h) : 0;
}

h2_headers *h2_headers_rcreate(request_rec *r, int status,
                               const apr_table_t *header, apr_pool_t *pool)
{
    h2_headers *headers = h2_headers_create(status, header, r->notes, 0, pool);
    if (headers->status == HTTP_FORBIDDEN) {
        request_rec *r_prev;
        for (r_prev = r; r_prev != NULL; r_prev = r_prev->prev) {
            const char *cause = apr_table_get(r_prev->notes, "ssl-renegotiate-forbidden");
            if (cause) {
                /* This request triggered a TLS renegotiation that is not allowed
                 * in HTTP/2. Tell the client that it should use HTTP/1.1 for this.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, headers->status, r,
                              APLOGNO(10399)
                              "h2_headers(%ld): renegotiate forbidden, cause: %s",
                              (long)r->connection->id, cause);
                headers->status = H2_ERR_HTTP_1_1_REQUIRED;
                break;
            }
        }
    }
    if (is_unsafe(r->server)) {
        apr_table_setn(headers->notes, H2_HDR_CONFORMANCE, H2_HDR_CONFORMANCE_UNSAFE);
    }
    if (h2_config_rgeti(r, H2_CONF_PUSH) == 0 && h2_config_sgeti(r->server, H2_CONF_PUSH) != 0) {
        apr_table_setn(headers->notes, H2_PUSH_MODE_NOTE, "0");
    }
    return headers;
}

h2_headers *h2_headers_copy(apr_pool_t *pool, h2_headers *h)
{
    return h2_headers_create(h->status, h->headers, h->notes, h->raw_bytes, pool);
}

h2_headers *h2_headers_clone(apr_pool_t *pool, h2_headers *h)
{
    return h2_headers_create(h->status, h->headers, h->notes, h->raw_bytes, pool);
}

h2_headers *h2_headers_die(apr_status_t type,
                             const h2_request *req, apr_pool_t *pool)
{
    h2_headers *headers;
    char *date;
    
    headers = apr_pcalloc(pool, sizeof(h2_headers));
    headers->status    = (type >= 200 && type < 600)? type : 500;
    headers->headers        = apr_table_make(pool, 5);
    headers->notes          = apr_table_make(pool, 5);

    date = apr_palloc(pool, APR_RFC822_DATE_LEN);
    ap_recent_rfc822_date(date, req? req->request_time : apr_time_now());
    apr_table_setn(headers->headers, "Date", date);
    apr_table_setn(headers->headers, "Server", ap_get_server_banner());
    
    return headers;
}

int h2_headers_are_final_response(h2_headers *headers)
{
    return headers->status >= 200;
}

#endif /* !AP_HAS_RESPONSE_BUCKETS */
