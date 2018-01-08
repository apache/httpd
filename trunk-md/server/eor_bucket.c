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

#include "httpd.h"
#include "http_request.h"
#include "http_protocol.h"
#include "scoreboard.h"

typedef struct {
    apr_bucket_refcount refcount;
    request_rec *data;
} ap_bucket_eor;

static apr_status_t eor_bucket_cleanup(void *data)
{
    request_rec **rp = data;

    if (*rp) {
        request_rec *r = *rp;
        /*
         * If eor_bucket_destroy is called after us, this prevents
         * eor_bucket_destroy from trying to destroy the pool again.
         */
        *rp = NULL;
        /* Update child status and log the transaction */
        ap_update_child_status(r->connection->sbh, SERVER_BUSY_LOG, r);
        ap_run_log_transaction(r);
        if (ap_extended_status) {
            ap_increment_counts(r->connection->sbh, r);
        }
    }
    return APR_SUCCESS;
}

static apr_status_t eor_bucket_read(apr_bucket *b, const char **str,
                                    apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

AP_DECLARE(apr_bucket *) ap_bucket_eor_make(apr_bucket *b, request_rec *r)
{
    ap_bucket_eor *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->data = r;

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &ap_bucket_type_eor;
    return b;
}

AP_DECLARE(apr_bucket *) ap_bucket_eor_create(apr_bucket_alloc_t *list,
                                              request_rec *r)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b = ap_bucket_eor_make(b, r);
    if (r) {
        ap_bucket_eor *h = b->data;
        /*
         * Register a cleanup for the request pool as the eor bucket could
         * have been allocated from a different pool then the request pool
         * e.g. the parent pool of the request pool. In this case
         * eor_bucket_destroy might be called at a point of time when the
         * request pool had been already destroyed.
         * We need to use a pre-cleanup here because a module may create a
         * sub-pool which is still needed during the log_transaction hook.
         */
        apr_pool_pre_cleanup_register(r->pool, &h->data, eor_bucket_cleanup);
    }
    return b;
}

static void eor_bucket_destroy(void *data)
{
    ap_bucket_eor *h = data;

    if (apr_bucket_shared_destroy(h)) {
        request_rec *r = h->data;
        if (r) {
            /* eor_bucket_cleanup will be called when the pool gets destroyed */
            apr_pool_destroy(r->pool);
        }
        apr_bucket_free(h);
    }
}

AP_DECLARE_DATA const apr_bucket_type_t ap_bucket_type_eor = {
    "EOR", 5, APR_BUCKET_METADATA,
    eor_bucket_destroy,
    eor_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

