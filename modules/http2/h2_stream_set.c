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

#include <apr_hash.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_stream.h"
#include "h2_stream_set.h"


struct h2_stream_set {
    apr_hash_t *hash;
};

static unsigned int stream_hash(const char *key, apr_ssize_t *klen)
{
    return (unsigned int)(*((int*)key));
}

h2_stream_set *h2_stream_set_create(apr_pool_t *pool, int max)
{
    h2_stream_set *sp = apr_pcalloc(pool, sizeof(h2_stream_set));
    sp->hash = apr_hash_make_custom(pool, stream_hash);

    return sp;
}

void h2_stream_set_destroy(h2_stream_set *sp)
{
    (void)sp;
}

h2_stream *h2_stream_set_get(h2_stream_set *sp, int stream_id)
{
    return apr_hash_get(sp->hash, &stream_id, sizeof(stream_id));
}

void h2_stream_set_add(h2_stream_set *sp, h2_stream *stream)
{
    apr_hash_set(sp->hash, &stream->id, sizeof(stream->id), stream);
}

void h2_stream_set_remove(h2_stream_set *sp, int stream_id)
{
    apr_hash_set(sp->hash, &stream_id, sizeof(stream_id), NULL);
}

int h2_stream_set_is_empty(h2_stream_set *sp)
{
    return apr_hash_count(sp->hash) == 0;
}

apr_size_t h2_stream_set_size(h2_stream_set *sp)
{
    return apr_hash_count(sp->hash);
}

typedef struct {
    h2_stream_set_iter_fn *iter;
    void *ctx;
} iter_ctx;

static int hash_iter(void *ctx, const void *key, apr_ssize_t klen, 
                     const void *val)
{
    iter_ctx *ictx = ctx;
    return ictx->iter(ictx->ctx, (h2_stream*)val);
}

void h2_stream_set_iter(h2_stream_set *sp,
                        h2_stream_set_iter_fn *iter, void *ctx)
{
    iter_ctx ictx;
    ictx.iter = iter;
    ictx.ctx = ctx;
    apr_hash_do(hash_iter, &ictx, sp->hash);
}

static int unsubmitted_iter(void *ctx, h2_stream *stream)
{
    if (h2_stream_needs_submit(stream)) {
        *((int *)ctx) = 1;
        return 0;
    }
    return 1;
}

int h2_stream_set_has_unsubmitted(h2_stream_set *sp)
{
    int has_unsubmitted = 0;
    h2_stream_set_iter(sp, unsubmitted_iter, &has_unsubmitted);
    return has_unsubmitted;
}

static int input_open_iter(void *ctx, h2_stream *stream)
{
    if (h2_stream_input_is_open(stream)) {
        *((int *)ctx) = 1;
        return 0;
    }
    return 1;
}

int h2_stream_set_has_open_input(h2_stream_set *sp)
{
    int has_input_open = 0;
    h2_stream_set_iter(sp, input_open_iter, &has_input_open);
    return has_input_open;
}

static int suspended_iter(void *ctx, h2_stream *stream)
{
    if (h2_stream_is_suspended(stream)) {
        *((int *)ctx) = 1;
        return 0;
    }
    return 1;
}

int h2_stream_set_has_suspended(h2_stream_set *sp)
{
    int has_suspended = 0;
    h2_stream_set_iter(sp, suspended_iter, &has_suspended);
    return has_suspended;
}

