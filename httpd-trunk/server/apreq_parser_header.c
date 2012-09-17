/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/
#include <assert.h>
#include "apreq_parser.h"
#include "apreq_error.h"
#include "apreq_util.h"

#define PARSER_STATUS_CHECK(PREFIX)   do {         \
    if (ctx->status == PREFIX##_ERROR)             \
        return APREQ_ERROR_GENERAL;                \
    else if (ctx->status == PREFIX##_COMPLETE)     \
        return APR_SUCCESS;                        \
    else if (bb == NULL)                           \
        return APR_INCOMPLETE;                     \
} while (0);


struct hdr_ctx {
    apr_bucket_brigade *bb;
    apr_size_t          nlen;
    apr_size_t          glen;
    apr_size_t          vlen;
    enum {
        HDR_NAME,
        HDR_GAP,
        HDR_VALUE,
        HDR_NEWLINE,
        HDR_CONTINUE,
        HDR_COMPLETE,
        HDR_ERROR
    }                   status;
};

/********************* header parsing utils ********************/


static apr_status_t split_header_line(apreq_param_t **p,
                                      apr_pool_t *pool,
                                      apr_bucket_brigade *bb,
                                      apr_size_t nlen,
                                      apr_size_t glen,
                                      apr_size_t vlen)
{
    apreq_param_t *param;
    apreq_value_t *v;
    apr_bucket *e, *f;
    apr_status_t s;
    struct iovec vec[APREQ_DEFAULT_NELTS], *iov, *end;
    apr_array_header_t arr;
    char *dest;
    const char *data;
    apr_size_t dlen;

    if (nlen == 0)
        return APR_EBADARG;

    param = apreq_param_make(pool, NULL, nlen, NULL, vlen - 1); /*drop (CR)LF */
    *(const apreq_value_t **)&v = &param->v;

    arr.pool     = pool;
    arr.elt_size = sizeof(struct iovec);
    arr.nelts    = 0;
    arr.nalloc   = APREQ_DEFAULT_NELTS;
    arr.elts     = (char *)vec;

    e = APR_BRIGADE_FIRST(bb);

    /* store name in a temporary iovec array */

    while (nlen > 0) {
        apr_size_t len;
        end = apr_array_push(&arr);
        s = apr_bucket_read(e, (const char **)&end->iov_base,
                            &len, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        assert(nlen >= len);
        end->iov_len = len;
        nlen -= len;

        e = APR_BUCKET_NEXT(e);
    }

    /* skip gap */

    while (glen > 0) {
        s = apr_bucket_read(e, &data, &dlen, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        assert(glen >= dlen);
        glen -= dlen;
        e = APR_BUCKET_NEXT(e);
    }

    /* copy value */
    assert(vlen > 0);
    dest = v->data;
    while (vlen > 0) {

        s = apr_bucket_read(e, &data, &dlen, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        memcpy(dest, data, dlen);
        dest += dlen;
        assert(vlen >= dlen);
        vlen -= dlen;
        e = APR_BUCKET_NEXT(e);
    }

    assert(dest[-1] == '\n');

    if (dest[-2] == '\r')
        --dest;

    dest[-1] = 0;
    v->dlen = (dest - v->data) - 1;

    /* write name */
    v->name = dest;
    iov = (struct iovec *)arr.elts;

    while (iov <= end) {
        memcpy(dest, iov->iov_base, iov->iov_len);
        dest += iov->iov_len;
        ++iov;
    }
    *dest = 0;

    while ((f = APR_BRIGADE_FIRST(bb)) != e)
        apr_bucket_delete(f);

    apreq_param_tainted_on(param);
    *p = param;
    return APR_SUCCESS;

}


APREQ_DECLARE_PARSER(apreq_parse_headers)
{
    apr_pool_t *pool = parser->pool;
    apr_bucket *e;
    struct hdr_ctx *ctx;

    if (parser->ctx == NULL) {
        ctx = apr_pcalloc(pool, sizeof *ctx);
        ctx->bb = apr_brigade_create(pool, parser->bucket_alloc);
        parser->ctx = ctx;
        ctx->status = HDR_NAME;
    }
    else
        ctx = parser->ctx;

    PARSER_STATUS_CHECK(HDR);
    e = APR_BRIGADE_LAST(ctx->bb);
    APR_BRIGADE_CONCAT(ctx->bb, bb);

 parse_hdr_brigade:


    /* parse the brigade for CRLF_CRLF-terminated header block,
     * each time starting from the front of the brigade.
     */

    for (e = APR_BUCKET_NEXT(e);
         e != APR_BRIGADE_SENTINEL(ctx->bb);
         e = APR_BUCKET_NEXT(e))
    {
        apr_size_t off = 0, dlen;
        const char *data;
        apr_status_t s;
        apreq_param_t *param = NULL; /* silences gcc-4.0 warning */

        if (APR_BUCKET_IS_EOS(e)) {
            ctx->status = HDR_COMPLETE;
            APR_BRIGADE_CONCAT(bb, ctx->bb);
            return APR_SUCCESS;
        }
        s = apr_bucket_read(e, &data, &dlen, APR_BLOCK_READ);

        if ( s != APR_SUCCESS ) {
            ctx->status = HDR_ERROR;
            return s;
        }
        if (dlen == 0)
            continue;

    parse_hdr_bucket:

        /*              gap           nlen = 13
         *              vvv           glen =  3
         * Sample-Header:  grape      vlen =  5
         * ^^^^^^^^^^^^^   ^^^^^
         *     name        value
         */

        switch (ctx->status) {

        case HDR_NAME:

            while (off < dlen) {
                switch (data[off++]) {

                case '\n':
                    if (off < dlen)
                        apr_bucket_split(e, off);
                    e = APR_BUCKET_NEXT(e);

                    do {
                        apr_bucket *f = APR_BRIGADE_FIRST(ctx->bb);
                        apr_bucket_delete(f);
                    } while (e != APR_BRIGADE_FIRST(ctx->bb));
                    APR_BRIGADE_CONCAT(bb, ctx->bb);
                    ctx->status = HDR_COMPLETE;
                    return APR_SUCCESS;

                case ':':
                    if (off > 1) {
                        apr_bucket_split(e, off - 1);
                        dlen -= off - 1;
                        data += off - 1;
                        off = 1;
                        e = APR_BUCKET_NEXT(e);
                    }
                    ++ctx->glen;
                    ctx->status = HDR_GAP;
                    goto parse_hdr_bucket;

                default:
                    ++ctx->nlen;
                }

            }

            break;


        case HDR_GAP:

            while (off < dlen) {
                switch (data[off++]) {
                case ' ':
                case '\t':
                    ++ctx->glen;
                    break;

                case '\n':
                    ctx->status = HDR_NEWLINE;
                    goto parse_hdr_bucket;

                default:
                    ctx->status = HDR_VALUE;
                    if (off > 1) {
                        apr_bucket_split(e, off - 1);
                        dlen -= off - 1;
                        data += off - 1;
                        off = 1;
                        e = APR_BUCKET_NEXT(e);
                    }
                    ++ctx->vlen;
                    goto parse_hdr_bucket;
                }
            }
            break;


        case HDR_VALUE:

            while (off < dlen) {
                ++ctx->vlen;
                if (data[off++] == '\n') {
                    ctx->status = HDR_NEWLINE;
                    goto parse_hdr_bucket;
                }
            }
            break;


        case HDR_NEWLINE:

            if (off == dlen)
                break;
            else {
                switch (data[off]) {

                case ' ':
                case '\t':
                    ctx->status = HDR_CONTINUE;
                    ++off;
                    ++ctx->vlen;
                    break;

                default:
                    /* can parse brigade now */
                    if (off > 0)
                        apr_bucket_split(e, off);
                    s = split_header_line(&param, pool, ctx->bb, ctx->nlen, ctx->glen, ctx->vlen);
                    if (parser->hook != NULL && s == APR_SUCCESS)
                        s = apreq_hook_run(parser->hook, param, NULL);

                    if (s != APR_SUCCESS) {
                        ctx->status = HDR_ERROR;
                        return s;
                    }

                    apreq_value_table_add(&param->v, t);
                    e = APR_BRIGADE_SENTINEL(ctx->bb);
                    ctx->status = HDR_NAME;
                    ctx->nlen = 0;
                    ctx->vlen = 0;
                    ctx->glen = 0;

                    goto parse_hdr_brigade;
                }

                /* cases ' ', '\t' fall through to HDR_CONTINUE */
            }


        case HDR_CONTINUE:

            while (off < dlen) {
                switch (data[off++]) {
                case ' ':
                case '\t':
                    ++ctx->vlen;
                    break;

                case '\n':
                    ctx->status = HDR_NEWLINE;
                    goto parse_hdr_bucket;

                default:
                    ctx->status = HDR_VALUE;
                    ++ctx->vlen;
                    goto parse_hdr_bucket;
                }
            }
            break;

        default:
            ; /* not reached */
        }
    }
    apreq_brigade_setaside(ctx->bb,pool);
    return APR_INCOMPLETE;
}
