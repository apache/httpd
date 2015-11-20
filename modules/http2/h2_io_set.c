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
#include "h2_io.h"
#include "h2_io_set.h"

#define h2_io_IDX(list, i) ((h2_io**)(list)->elts)[i]

struct h2_io_set {
    apr_array_header_t *list;
};

h2_io_set *h2_io_set_create(apr_pool_t *pool)
{
    h2_io_set *sp = apr_pcalloc(pool, sizeof(h2_io_set));
    if (sp) {
        sp->list = apr_array_make(pool, 100, sizeof(h2_io*));
        if (!sp->list) {
            return NULL;
        }
    }
    return sp;
}

void h2_io_set_destroy(h2_io_set *sp)
{
    int i;
    for (i = 0; i < sp->list->nelts; ++i) {
        h2_io *io = h2_io_IDX(sp->list, i);
        h2_io_destroy(io);
    }
    sp->list->nelts = 0;
}

static int h2_stream_id_cmp(const void *s1, const void *s2)
{
    h2_io **pio1 = (h2_io **)s1;
    h2_io **pio2 = (h2_io **)s2;
    return (*pio1)->id - (*pio2)->id;
}

h2_io *h2_io_set_get(h2_io_set *sp, int stream_id)
{
    /* we keep the array sorted by id, so lookup can be done
     * by bsearch.
     */
    h2_io **ps;
    h2_io key;
    h2_io *pkey = &key;

    memset(&key, 0, sizeof(key));
    key.id = stream_id;
    ps = bsearch(&pkey, sp->list->elts, sp->list->nelts, 
                         sp->list->elt_size, h2_stream_id_cmp);
    return ps? *ps : NULL;
}

static void h2_io_set_sort(h2_io_set *sp)
{
    qsort(sp->list->elts, sp->list->nelts, sp->list->elt_size, 
          h2_stream_id_cmp);
}

apr_status_t h2_io_set_add(h2_io_set *sp, h2_io *io)
{
    h2_io *existing = h2_io_set_get(sp, io->id);
    if (!existing) {
        int last;
        APR_ARRAY_PUSH(sp->list, h2_io*) = io;
        /* Normally, streams get added in ascending order if id. We
         * keep the array sorted, so we just need to check of the newly
         * appended stream has a lower id than the last one. if not,
         * sorting is not necessary.
         */
        last = sp->list->nelts - 1;
        if (last > 0 
            && (h2_io_IDX(sp->list, last)->id 
                < h2_io_IDX(sp->list, last-1)->id)) {
                h2_io_set_sort(sp);
            }
    }
    return APR_SUCCESS;
}

static void remove_idx(h2_io_set *sp, int idx)
{
    int n;
    --sp->list->nelts;
    n = sp->list->nelts - idx;
    if (n > 0) {
        /* Close the hole in the array by moving the upper
         * parts down one step.
         */
        h2_io **selts = (h2_io**)sp->list->elts;
        memmove(selts + idx, selts + idx + 1, n * sizeof(h2_io*));
    }
}

h2_io *h2_io_set_remove(h2_io_set *sp, h2_io *io)
{
    int i;
    for (i = 0; i < sp->list->nelts; ++i) {
        h2_io *e = h2_io_IDX(sp->list, i);
        if (e == io) {
            remove_idx(sp, i);
            return e;
        }
    }
    return NULL;
}

h2_io *h2_io_set_pop_highest_prio(h2_io_set *set)
{
    /* For now, this just removes the first element in the set.
     * the name is misleading...
     */
    if (set->list->nelts > 0) {
        h2_io *io = h2_io_IDX(set->list, 0);
        remove_idx(set, 0);
        return io;
    }
    return NULL;
}

void h2_io_set_destroy_all(h2_io_set *sp)
{
    int i;
    for (i = 0; i < sp->list->nelts; ++i) {
        h2_io *io = h2_io_IDX(sp->list, i);
        h2_io_destroy(io);
    }
    sp->list->nelts = 0;
}

void h2_io_set_remove_all(h2_io_set *sp)
{
    sp->list->nelts = 0;
}

int h2_io_set_is_empty(h2_io_set *sp)
{
    AP_DEBUG_ASSERT(sp);
    return sp->list->nelts == 0;
}

void h2_io_set_iter(h2_io_set *sp,
                        h2_io_set_iter_fn *iter, void *ctx)
{
    int i;
    for (i = 0; i < sp->list->nelts; ++i) {
        h2_io *s = h2_io_IDX(sp->list, i);
        if (!iter(ctx, s)) {
            break;
        }
    }
}

apr_size_t h2_io_set_size(h2_io_set *sp)
{
    return sp->list->nelts;
}

