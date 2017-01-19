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
#include <stddef.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_mplx.h"
#include "h2_session.h"
#include "h2_bucket_eoc.h"

typedef struct {
    apr_bucket_refcount refcount;
    h2_session *session;
} h2_bucket_eoc;

static apr_status_t bucket_read(apr_bucket *b, const char **str,
                                apr_size_t *len, apr_read_type_e block)
{
    (void)b;
    (void)block;
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

apr_bucket * h2_bucket_eoc_make(apr_bucket *b, h2_session *session)
{
    h2_bucket_eoc *h;

    h = apr_bucket_alloc(sizeof(*h), b->list);
    h->session = session;

    b = apr_bucket_shared_make(b, h, 0, 0);
    b->type = &h2_bucket_type_eoc;
    
    return b;
}

apr_bucket * h2_bucket_eoc_create(apr_bucket_alloc_t *list, h2_session *session)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return h2_bucket_eoc_make(b, session);
}

static void bucket_destroy(void *data)
{
    h2_bucket_eoc *h = data;

    if (apr_bucket_shared_destroy(h)) {
        h2_session *session = h->session;
        apr_bucket_free(h);
        h2_session_eoc_callback(session);
    }
}

const apr_bucket_type_t h2_bucket_type_eoc = {
    "H2EOC", 5, APR_BUCKET_METADATA,
    bucket_destroy,
    bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};

