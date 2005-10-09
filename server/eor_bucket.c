/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

#include "httpd.h"
#include "http_request.h"

static apr_status_t eor_bucket_read(apr_bucket *b, const char **str, 
                                    apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

AP_DECLARE(apr_bucket *) ap_bucket_eor_make(apr_bucket *b, request_rec *r)
{
    b->length      = 0;
    b->start       = 0;
    b->data        = r;
    b->type        = &ap_bucket_type_eor;
    
    return b;
}

AP_DECLARE(apr_bucket *) ap_bucket_eor_create(apr_bucket_alloc_t *list,
                                              request_rec *r)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return ap_bucket_eor_make(b, r);
}

static void eor_bucket_destroy(void *data)
{
    request_rec *r = (request_rec *)data;
    if (r != NULL) {
        ap_run_log_transaction(r);
        apr_pool_destroy(r->pool);
    }
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_eor = {
    "EOR", 5, APR_BUCKET_METADATA,
    eor_bucket_destroy,
    eor_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_simple_copy
};

