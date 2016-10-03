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
#include <util_time.h>

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2_h2.h"
#include "h2_util.h"
#include "h2_request.h"
#include "h2_headers.h"


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

apr_bucket *h2_bucket_headers_beam(struct h2_bucket_beam *beam,
                                    apr_bucket_brigade *dest,
                                    const apr_bucket *src)
{
    if (H2_BUCKET_IS_HEADERS(src)) {
        h2_headers *r = ((h2_bucket_headers *)src->data)->headers;
        apr_bucket *b = h2_bucket_headers_create(dest->bucket_alloc, r);
        APR_BRIGADE_INSERT_TAIL(dest, b);
        return b;
    }
    return NULL;
}


h2_headers *h2_headers_create(int status, apr_table_t *headers_in, 
                                apr_table_t *notes, apr_pool_t *pool)
{
    h2_headers *headers = apr_pcalloc(pool, sizeof(h2_headers));
    headers->status    = status;
    headers->headers   = (headers_in? apr_table_copy(pool, headers_in)
                           : apr_table_make(pool, 5));
    headers->notes     = (notes? apr_table_copy(pool, notes)
                           : apr_table_make(pool, 5));
    return headers;
}

h2_headers *h2_headers_rcreate(request_rec *r, int status,
                                 apr_table_t *header, apr_pool_t *pool)
{
    h2_headers *headers = h2_headers_create(status, header, r->notes, pool);
    if (headers->status == HTTP_FORBIDDEN) {
        const char *cause = apr_table_get(r->notes, "ssl-renegotiate-forbidden");
        if (cause) {
            /* This request triggered a TLS renegotiation that is now allowed 
             * in HTTP/2. Tell the client that it should use HTTP/1.1 for this.
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, headers->status, r,
                          APLOGNO(03061) 
                          "h2_headers(%ld): renegotiate forbidden, cause: %s",
                          (long)r->connection->id, cause);
            headers->status = H2_ERR_HTTP_1_1_REQUIRED;
        }
    }
    return headers;
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

int h2_headers_are_response(h2_headers *headers)
{
    return headers->status >= 200;
}

