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
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"

#include "mod_ratelimit.h"

#define RATE_LIMIT_FILTER_NAME "RATE_LIMIT"
#define RATE_INTERVAL_MS (200)

typedef enum rl_state_e
{
    RATE_LIMIT,
    RATE_FULLSPEED
} rl_state_e;

typedef struct rl_ctx_t
{
    int speed;
    int chunk_size;
    int burst;
    int do_sleep;
    rl_state_e state;
    apr_bucket_brigade *tmpbb;
    apr_bucket_brigade *holdingbb;
} rl_ctx_t;

#if defined(RLFDEBUG)
static void brigade_dump(request_rec *r, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    int i = 0;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e), i++) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(03193)
                      "brigade: [%d] %s", i, e->type->name);

    }
}
#endif /* RLFDEBUG */

static apr_status_t
rate_limit_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_status_t rv = APR_SUCCESS;
    rl_ctx_t *ctx = f->ctx;
    apr_bucket_alloc_t *ba = f->r->connection->bucket_alloc;

    /* Set up our rl_ctx_t on first use */
    if (ctx == NULL) {
        const char *rl = NULL;
        int ratelimit;
        int burst = 0;

        /* no subrequests. */
        if (f->r->main != NULL) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* Configuration: rate limit */
        rl = apr_table_get(f->r->subprocess_env, "rate-limit");

        if (rl == NULL) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }
        
        /* rl is in kilo bytes / second  */
        ratelimit = atoi(rl) * 1024;
        if (ratelimit <= 0) {
            /* remove ourselves */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                          APLOGNO(03488) "rl: disabling: rate-limit = %s (too high?)", rl);
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* Configuration: optional initial burst */
        rl = apr_table_get(f->r->subprocess_env, "rate-initial-burst");
        if (rl != NULL) {
            burst = atoi(rl) * 1024;
            if (burst <= 0) {
               ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                             APLOGNO(03489) "rl: disabling burst: rate-initial-burst = %s (too high?)", rl);
               burst = 0;
            }
        }

        /* Set up our context */
        ctx = apr_palloc(f->r->pool, sizeof(rl_ctx_t));
        f->ctx = ctx;
        ctx->state = RATE_LIMIT;
        ctx->speed = ratelimit;
        ctx->burst = burst;
        ctx->do_sleep = 0;

        /* calculate how many bytes / interval we want to send */
        /* speed is bytes / second, so, how many  (speed / 1000 % interval) */
        ctx->chunk_size = (ctx->speed / (1000 / RATE_INTERVAL_MS));
        ctx->tmpbb = apr_brigade_create(f->r->pool, ba);
        ctx->holdingbb = apr_brigade_create(f->r->pool, ba);
    }
    else {
        APR_BRIGADE_PREPEND(bb, ctx->holdingbb);
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *e;

        if (ctx->state == RATE_FULLSPEED) {
            /* Find where we 'stop' going full speed. */
            for (e = APR_BRIGADE_FIRST(bb);
                 e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
                if (AP_RL_BUCKET_IS_END(e)) {
                    apr_brigade_split_ex(bb, e, ctx->holdingbb);
                    ctx->state = RATE_LIMIT;
                    break;
                }
            }

            e = apr_bucket_flush_create(ba);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            rv = ap_pass_brigade(f->next, bb);
            apr_brigade_cleanup(bb);

            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, f->r, APLOGNO(01455)
                              "rl: full speed brigade pass failed.");
                return rv;
            }
        }
        else {
            for (e = APR_BRIGADE_FIRST(bb);
                 e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
                if (AP_RL_BUCKET_IS_START(e)) {
                    apr_brigade_split_ex(bb, e, ctx->holdingbb);
                    ctx->state = RATE_FULLSPEED;
                    break;
                }
            }

            while (!APR_BRIGADE_EMPTY(bb)) {
                apr_off_t len = ctx->chunk_size + ctx->burst;

                APR_BRIGADE_CONCAT(ctx->tmpbb, bb);

                /*
                 * Pull next chunk of data; the initial amount is our
                 * burst allotment (if any) plus a chunk.  All subsequent
                 * iterations are just chunks with whatever remaining
                 * burst amounts we have left (in case not done in the
                 * first bucket).
                 */
                rv = apr_brigade_partition(ctx->tmpbb, len, &e);
                if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01456)
                                  "rl: partition failed.");
                    return rv;
                }
                /* Send next metadata now if any */
                while (e != APR_BRIGADE_SENTINEL(ctx->tmpbb)
                       && APR_BUCKET_IS_METADATA(e)) {
                    e = APR_BUCKET_NEXT(e);
                }
                if (e != APR_BRIGADE_SENTINEL(ctx->tmpbb)) {
                    apr_brigade_split_ex(ctx->tmpbb, e, bb);
                }
                else {
                    apr_brigade_length(ctx->tmpbb, 1, &len);
                }

                /*
                 * Adjust the burst amount depending on how much
                 * we've done up to now.
                 */
                if (ctx->burst) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                        APLOGNO(03485) "rl: burst %d; len %"APR_OFF_T_FMT, ctx->burst, len);
                    if (len < ctx->burst) {
                        ctx->burst -= len;
                    }
                    else {
                        ctx->burst = 0;
                    }
                }

                e = APR_BRIGADE_LAST(ctx->tmpbb);
                if (APR_BUCKET_IS_EOS(e)) {
                    ap_remove_output_filter(f);
                }
                else if (!APR_BUCKET_IS_FLUSH(e)) {
                    if (APR_BRIGADE_EMPTY(bb)) {
                        /* Wait for more (or next call) */
                        break;
                    }
                    e = apr_bucket_flush_create(ba);
                    APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, e);
                }

#if defined(RLFDEBUG)
                brigade_dump(f->r, ctx->tmpbb);
                brigade_dump(f->r, bb);
#endif /* RLFDEBUG */

                if (ctx->do_sleep) {
                    apr_sleep(RATE_INTERVAL_MS * 1000);
                }
                else {
                    ctx->do_sleep = 1;
                }

                rv = ap_pass_brigade(f->next, ctx->tmpbb);
                apr_brigade_cleanup(ctx->tmpbb);

                if (rv != APR_SUCCESS) {
                    /* Most often, user disconnects from stream */
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, f->r, APLOGNO(01457)
                                  "rl: brigade pass failed.");
                    return rv;
                }
            }
        }

        if (!APR_BRIGADE_EMPTY(ctx->holdingbb)) {
            /* Any rate-limited data in tmpbb is sent unlimited along
             * with the rest.
             */
            APR_BRIGADE_CONCAT(bb, ctx->tmpbb);
            APR_BRIGADE_CONCAT(bb, ctx->holdingbb);
        }
    }

#if defined(RLFDEBUG)
    brigade_dump(f->r, ctx->tmpbb);
#endif /* RLFDEBUG */

    /* Save remaining tmpbb with the correct lifetime for the next call */
    return ap_save_brigade(f, &ctx->holdingbb, &ctx->tmpbb, f->r->pool);
}


static apr_status_t
rl_bucket_read(apr_bucket *b, const char **str,
               apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

AP_RL_DECLARE(apr_bucket *)
    ap_rl_end_create(apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->length = 0;
    b->start = 0;
    b->data = NULL;
    b->type = &ap_rl_bucket_type_end;

    return b;
}

AP_RL_DECLARE(apr_bucket *)
    ap_rl_start_create(apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->length = 0;
    b->start = 0;
    b->data = NULL;
    b->type = &ap_rl_bucket_type_start;

    return b;
}



AP_RL_DECLARE_DATA const apr_bucket_type_t ap_rl_bucket_type_end = {
    "RL_END", 5, APR_BUCKET_METADATA,
    apr_bucket_destroy_noop,
    rl_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_simple_copy
};


AP_RL_DECLARE_DATA const apr_bucket_type_t ap_rl_bucket_type_start = {
    "RL_START", 5, APR_BUCKET_METADATA,
    apr_bucket_destroy_noop,
    rl_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_simple_copy
};




static void register_hooks(apr_pool_t *p)
{
    /* run after mod_deflate etc etc, but not at connection level, ie, mod_ssl. */
    ap_register_output_filter(RATE_LIMIT_FILTER_NAME, rate_limit_filter,
                              NULL, AP_FTYPE_CONNECTION - 1);
}

AP_DECLARE_MODULE(ratelimit) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    register_hooks
};
