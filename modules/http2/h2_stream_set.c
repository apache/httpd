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
#include <stddef.h>

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_task.h"
#include "h2_stream_set.h"

#define H2_STREAM_IDX(list, i) ((h2_stream**)(list)->elts)[i]

struct h2_stream_set {
    apr_array_header_t *list;
};

h2_stream_set *h2_stream_set_create(apr_pool_t *pool)
{
    h2_stream_set *sp = apr_pcalloc(pool, sizeof(h2_stream_set));
    if (sp) {
        sp->list = apr_array_make(pool, 100, sizeof(h2_stream*));
        if (!sp->list) {
            return NULL;
        }
    }
    return sp;
}

void h2_stream_set_destroy(h2_stream_set *sp)
{
    (void)sp;
}

static int h2_stream_id_cmp(const void *s1, const void *s2)
{
    h2_stream **pstream1 = (h2_stream **)s1;
    h2_stream **pstream2 = (h2_stream **)s2;
    return (*pstream1)->id - (*pstream2)->id;
}

h2_stream *h2_stream_set_get(h2_stream_set *sp, int stream_id)
{
    /* we keep the array sorted by id, so lookup can be done
     * by bsearch.
     */
    h2_stream key;
    memset(&key, 0, sizeof(key));
    key.id = stream_id;
    h2_stream *pkey = &key;
    h2_stream **ps = bsearch(&pkey, sp->list->elts, sp->list->nelts, 
                             sp->list->elt_size, h2_stream_id_cmp);
    return ps? *ps : NULL;
}

static void h2_stream_set_sort(h2_stream_set *sp)
{
    qsort(sp->list->elts, sp->list->nelts, sp->list->elt_size, 
          h2_stream_id_cmp);
}

apr_status_t h2_stream_set_add(h2_stream_set *sp, h2_stream *stream)
{
    h2_stream *existing = h2_stream_set_get(sp, stream->id);
    if (!existing) {
        APR_ARRAY_PUSH(sp->list, h2_stream*) = stream;
        /* Normally, streams get added in ascending order if id. We
         * keep the array sorted, so we just need to check of the newly
         * appended stream has a lower id than the last one. if not,
         * sorting is not necessary.
         */
        int last = sp->list->nelts - 1;
        if (last > 0 
            && (H2_STREAM_IDX(sp->list, last)->id 
                < H2_STREAM_IDX(sp->list, last-1)->id)) {
            h2_stream_set_sort(sp);
        }
    }
    return APR_SUCCESS;
}

h2_stream *h2_stream_set_remove(h2_stream_set *sp, h2_stream *stream)
{
    for (int i = 0; i < sp->list->nelts; ++i) {
        h2_stream *s = H2_STREAM_IDX(sp->list, i);
        if (s == stream) {
            --sp->list->nelts;
            int n = sp->list->nelts - i;
            if (n > 0) {
                /* Close the hole in the array by moving the upper
                 * parts down one step.
                 */
                h2_stream **selts = (h2_stream**)sp->list->elts;
                memmove(selts+i, selts+i+1, n * sizeof(h2_stream*));
            }
            return s;
        }
    }
    return NULL;
}

void h2_stream_set_remove_all(h2_stream_set *sp)
{
    sp->list->nelts = 0;
}

int h2_stream_set_is_empty(h2_stream_set *sp)
{
    AP_DEBUG_ASSERT(sp);
    return sp->list->nelts == 0;
}

h2_stream *h2_stream_set_find(h2_stream_set *sp,
                              h2_stream_set_match_fn match, void *ctx)
{
    h2_stream *s = NULL;
    for (int i = 0; !s && i < sp->list->nelts; ++i) {
        s = match(ctx, H2_STREAM_IDX(sp->list, i));
    }
    return s;
}

void h2_stream_set_iter(h2_stream_set *sp,
                        h2_stream_set_iter_fn *iter, void *ctx)
{
    for (int i = 0; i < sp->list->nelts; ++i) {
        h2_stream *s = H2_STREAM_IDX(sp->list, i);
        if (!iter(ctx, s)) {
            break;
        }
    }
}

apr_size_t h2_stream_set_size(h2_stream_set *sp)
{
    return sp->list->nelts;
}

