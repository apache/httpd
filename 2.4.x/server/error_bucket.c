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

static apr_status_t error_bucket_read(apr_bucket *b, const char **str,
                                      apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

static void error_bucket_destroy(void *data)
{
    ap_bucket_error *h = data;

    if (apr_bucket_shared_destroy(h)) {
        apr_bucket_free(h);
    }
}

AP_DECLARE(apr_bucket *) ap_bucket_error_make(apr_bucket *b, int error,
                                              const char *buf, apr_pool_t *p)
{
    ap_bucket_error *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->status = error;
    h->data = apr_pstrdup(p, buf);

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_error;
    return b;
}

AP_DECLARE(apr_bucket *) ap_bucket_error_create(int error, const char *buf,
                                                apr_pool_t *p,
                                                apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    if (!ap_is_HTTP_VALID_RESPONSE(error)) {
        error = HTTP_INTERNAL_SERVER_ERROR;
    }
    return ap_bucket_error_make(b, error, buf, p);
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_error = {
    "ERROR", 5, APR_BUCKET_METADATA,
    error_bucket_destroy,
    error_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};
