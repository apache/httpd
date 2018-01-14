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

/*
 * mod_buffer.c --- Buffer the input and output filter stacks, collapse
 *                  many small buckets into fewer large buckets.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"

#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

static const char bufferFilterName[] = "BUFFER";
module AP_MODULE_DECLARE_DATA buffer_module;

#define DEFAULT_BUFFER_SIZE 128*1024

typedef struct buffer_conf {
    apr_off_t size; /* size of the buffer */
    int size_set; /* has the size been set */
} buffer_conf;

typedef struct buffer_ctx {
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmp;
    buffer_conf *conf;
    apr_off_t remaining;
    int seen_eos;
} buffer_ctx;

/**
 * Buffer buckets being written to the output filter stack.
 */
static apr_status_t buffer_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    buffer_ctx *ctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;
    int move = 0;

    /* first time in? create a context */
    if (!ctx) {

        /* buffering won't work on subrequests, it would be nice if
         * it did. Within subrequests, we have no EOS to check for,
         * so we don't know when to flush the buffer to the network
         */
        if (f->r->main) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->conf = ap_get_module_config(f->r->per_dir_config, &buffer_module);
    }

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    /* Empty buffer means we can potentially optimise below */
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        move = 1;
    }

    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(bb)) {
        const char *data;
        apr_off_t len;
        apr_size_t size;

        e = APR_BRIGADE_FIRST(bb);

        /* EOS means we are done. */
        if (APR_BUCKET_IS_EOS(e)) {

            /* should we add an etag? */

            /* pass the EOS across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            continue;
        }

        /* A flush takes precedence over buffering */
        if (APR_BUCKET_IS_FLUSH(e)) {

            /* pass the flush bucket across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            continue;
        }

        /* metadata buckets are preserved as is */
        if (APR_BUCKET_IS_METADATA(e)) {
            /*
             * Remove meta data bucket from old brigade and insert into the
             * new.
             */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        /* is our buffer full?
         * If so, send what we have down the filter chain. If the buffer
         * gets full, we can no longer compute a content length.
         */
        apr_brigade_length(ctx->bb, 1, &len);
        if (len > ctx->conf->size) {

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv) {
                /* should break out of the loop, since our write to the client
                 * failed in some way. */
                continue;
            }
        }

        /* at this point we are ready to buffer.
         * Buffering takes advantage of an optimisation in the handling of
         * bucket brigades. Heap buckets are always created at a fixed
         * size, regardless of the size of the data placed into them.
         * The apr_brigade_write() call will first try and pack the data
         * into any free space in the most recent heap bucket, before
         * allocating a new bucket if necessary.
         */
        if (APR_SUCCESS == (rv = apr_bucket_read(e, &data, &size,
                APR_BLOCK_READ))) {

            /* further optimisation: if the buckets are already heap
             * buckets, and the buckets stay exactly APR_BUCKET_BUFF_SIZE
             * long (as they would be if we were reading bits of a
             * large bucket), then move the buckets instead of copying
             * them.
             */
            if (move && APR_BUCKET_IS_HEAP(e)) {
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                if (APR_BUCKET_BUFF_SIZE != size) {
                    move = 0;
                }
            } else {
                apr_brigade_write(ctx->bb, NULL, NULL, data, size);
                apr_bucket_delete(e);
            }

        }

    }

    return rv;

}

/**
 * Buffer buckets being read from the input filter stack.
 */
static apr_status_t buffer_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *e, *after;
    apr_status_t rv;
    buffer_ctx *ctx = f->ctx;

    /* buffer on main requests only */
    if (!ap_is_initial_req(f->r)) {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* first time in? create a context */
    if (!ctx) {
        ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->tmp = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->conf = ap_get_module_config(f->r->per_dir_config, &buffer_module);
    }

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* if our buffer is empty, read off the network until the buffer is full */
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        int seen_flush = 0;

        ctx->remaining = ctx->conf->size;

        while (!ctx->seen_eos && !seen_flush && ctx->remaining > 0) {
            const char *data;
            apr_size_t size = 0;

            if (APR_BRIGADE_EMPTY(ctx->tmp)) {
                rv = ap_get_brigade(f->next, ctx->tmp, mode, block,
                                    ctx->remaining);

                /* if an error was received, bail out now. If the error is
                 * EAGAIN and we have not yet seen an EOS, we will definitely
                 * be called again, at which point we will send our buffered
                 * data. Instead of sending EAGAIN, some filters return an
                 * empty brigade instead when data is not yet available. In
                 * this case, pass through the APR_SUCCESS and emulate the
                 * underlying filter.
                 */
                if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(ctx->tmp)) {
                    return rv;
                }
            }

            do {
                e = APR_BRIGADE_FIRST(ctx->tmp);

                /* if we see an EOS, we are done */
                if (APR_BUCKET_IS_EOS(e)) {
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                    ctx->seen_eos = 1;
                    break;
                }

                /* flush buckets clear the buffer */
                if (APR_BUCKET_IS_FLUSH(e)) {
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                    seen_flush = 1;
                    break;
                }

                /* pass metadata buckets through */
                if (APR_BUCKET_IS_METADATA(e)) {
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                    continue;
                }

                /* read the bucket in, pack it into the buffer */
                if (APR_SUCCESS == (rv = apr_bucket_read(e, &data, &size,
                                                         APR_BLOCK_READ))) {
                    apr_brigade_write(ctx->bb, NULL, NULL, data, size);
                    ctx->remaining -= size;
                    apr_bucket_delete(e);
                } else {
                    return rv;
                }

            } while (!APR_BRIGADE_EMPTY(ctx->tmp));
        }
    }

    /* give the caller the data they asked for from the buffer */
    apr_brigade_partition(ctx->bb, readbytes, &after);
    e = APR_BRIGADE_FIRST(ctx->bb);
    while (e != after) {
        if (APR_BUCKET_IS_EOS(e)) {
            /* last bucket read, step out of the way */
            ap_remove_input_filter(f);
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = APR_BRIGADE_FIRST(ctx->bb);
    }

    return APR_SUCCESS;
}

static void *create_buffer_config(apr_pool_t *p, char *dummy)
{
    buffer_conf *new = (buffer_conf *) apr_pcalloc(p, sizeof(buffer_conf));

    new->size_set = 0; /* unset */
    new->size = DEFAULT_BUFFER_SIZE; /* default size */

    return (void *) new;
}

static void *merge_buffer_config(apr_pool_t *p, void *basev, void *addv)
{
    buffer_conf *new = (buffer_conf *) apr_pcalloc(p, sizeof(buffer_conf));
    buffer_conf *add = (buffer_conf *) addv;
    buffer_conf *base = (buffer_conf *) basev;

    new->size = (add->size_set == 0) ? base->size : add->size;
    new->size_set = add->size_set || base->size_set;

    return new;
}

static const char *set_buffer_size(cmd_parms *cmd, void *dconf, const char *arg)
{
    buffer_conf *conf = dconf;

    if (APR_SUCCESS != apr_strtoff(&(conf->size), arg, NULL, 10) || conf->size
            <= 0) {
        return "BufferSize must be a size in bytes, and greater than zero";
    }
    conf->size_set = 1;

    return NULL;
}

static const command_rec buffer_cmds[] = { AP_INIT_TAKE1("BufferSize",
        set_buffer_size, NULL, ACCESS_CONF,
        "Maximum size of the buffer used by the buffer filter"), { NULL } };

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(bufferFilterName, buffer_out_filter, NULL,
            AP_FTYPE_CONTENT_SET);
    ap_register_input_filter(bufferFilterName, buffer_in_filter, NULL,
            AP_FTYPE_CONTENT_SET);
}

AP_DECLARE_MODULE(buffer) = {
    STANDARD20_MODULE_STUFF,
    create_buffer_config, /* create per-directory config structure */
    merge_buffer_config, /* merge per-directory config structures */
    NULL, /* create per-server config structure */
    NULL, /* merge per-server config structures */
    buffer_cmds, /* command apr_table_t */
    register_hooks /* register hooks */
};
