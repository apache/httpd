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

#include "http_protocol.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#if APR_HAVE_STRINGS_H
#include <strings.h>
#endif

static apr_status_t dummy_read(apr_bucket *b, const char **str,
                               apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

static void request_bucket_destroy(void *data)
{
    ap_bucket_request *h = data;

    if (apr_bucket_shared_destroy(h)) {
        apr_bucket_free(h);
    }
}

AP_DECLARE(apr_bucket *) ap_bucket_request_make(
            apr_bucket *b,
            const char *method,
            const char *uri,
            const char *protocol,
            apr_table_t *headers,
            apr_pool_t *p)
{
    return ap_bucket_request_maken(b, apr_pstrdup(p, method),
                                   apr_pstrdup(p, uri), protocol,
                                   headers? apr_table_clone(p, headers) : NULL,
                                   p);
}

AP_DECLARE(apr_bucket *) ap_bucket_request_maken(
            apr_bucket *b,
            const char *method,
            const char *uri,
            const char *protocol,
            apr_table_t *headers,
            apr_pool_t *p)
{
    ap_bucket_request *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->pool = p;
    h->method = method;
    h->uri = uri;
    h->protocol = protocol;
    h->headers = headers;

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_request;
    return b;
}

AP_DECLARE(apr_bucket *) ap_bucket_request_create(
            const char *method,
            const char *uri,
            const char *protocol,
            apr_table_t *headers,
            apr_pool_t *p,
            apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return ap_bucket_request_make(b, method, uri, protocol, headers, p);
}

AP_DECLARE(apr_bucket *) ap_bucket_request_createn(
            const char *method,
            const char *uri,
            const char *protocol,
            apr_table_t *headers,
            apr_pool_t *p,
            apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return ap_bucket_request_maken(b, method, uri, protocol, headers, p);
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_request = {
    "REQUEST", 5, APR_BUCKET_METADATA,
    request_bucket_destroy,
    dummy_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

AP_DECLARE(apr_bucket *) ap_bucket_request_clone(
        apr_bucket *source,
        apr_pool_t *p,
        apr_bucket_alloc_t *list)
{
    ap_bucket_request *sreq = source->data;

    AP_DEBUG_ASSERT(AP_BUCKET_IS_REQUEST(source));
    return ap_bucket_request_create(sreq->method, sreq->uri,
                                    sreq->protocol, sreq->headers, p, list);
}

static void response_bucket_destroy(void *data)
{
    ap_bucket_response *h = data;

    if (apr_bucket_shared_destroy(h)) {
        apr_bucket_free(h);
    }
}

AP_DECLARE(apr_bucket *) ap_bucket_response_make(apr_bucket *b, int status,
                                                 const char *reason,
                                                 apr_table_t *headers,
                                                 apr_table_t *notes,
                                                 apr_pool_t *p)
{
    ap_bucket_response *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->pool = p;
    h->status = status;
    h->reason = reason? apr_pstrdup(p, reason) : NULL;
    h->headers = headers? apr_table_copy(p, headers) : apr_table_make(p, 5);
    h->notes = notes? apr_table_copy(p, notes) : apr_table_make(p, 5);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_response;
    return b;
}

AP_DECLARE(apr_bucket *) ap_bucket_response_create(int status, const char *reason,
                                                   apr_table_t *headers,
                                                   apr_table_t *notes,
                                                   apr_pool_t *p,
                                                   apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return ap_bucket_response_make(b, status, reason, headers, notes, p);
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_response = {
    "RESPONSE", 5, APR_BUCKET_METADATA,
    response_bucket_destroy,
    dummy_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

AP_DECLARE(apr_bucket *) ap_bucket_response_clone(apr_bucket *source,
                                                  apr_pool_t *p,
                                                  apr_bucket_alloc_t *list)
{
    ap_bucket_response *sresp = source->data;
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    ap_bucket_response *h;

    AP_DEBUG_ASSERT(AP_BUCKET_IS_RESPONSE(source));
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->status = sresp->status;
    h->reason = sresp->reason? apr_pstrdup(p, sresp->reason) : NULL;
    h->headers = apr_table_clone(p, sresp->headers);
    h->notes = apr_table_clone(p, sresp->notes);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_response;
    return b;
}

static void headers_bucket_destroy(void *data)
{
    ap_bucket_headers *h = data;

    if (apr_bucket_shared_destroy(h)) {
        apr_bucket_free(h);
    }
}

AP_DECLARE(apr_bucket *) ap_bucket_headers_make(apr_bucket *b,
                                                apr_table_t *headers,
                                                apr_pool_t *p)
{
    ap_bucket_headers *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->pool = p;
    h->headers = headers? apr_table_copy(p, headers) : apr_table_make(p, 5);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_headers;
    return b;
}

AP_DECLARE(apr_bucket *) ap_bucket_headers_create(apr_table_t *headers,
                                                  apr_pool_t *p,
                                                  apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return ap_bucket_headers_make(b, headers, p);
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_headers = {
    "HEADERS", 5, APR_BUCKET_METADATA,
    headers_bucket_destroy,
    dummy_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

AP_DECLARE(apr_bucket *) ap_bucket_headers_clone(apr_bucket *source,
                                                 apr_pool_t *p,
                                                 apr_bucket_alloc_t *list)
{
    ap_bucket_headers *shdrs = source->data;
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    ap_bucket_headers *h;

    AP_DEBUG_ASSERT(AP_BUCKET_IS_HEADERS(source));
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->headers = apr_table_clone(p, shdrs->headers);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_headers;
    return b;
}

