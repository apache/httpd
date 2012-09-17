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

#include "apreq_parser.h"
#include "apreq_util.h"
#include "apreq_error.h"


#define PARSER_STATUS_CHECK(PREFIX)   do {         \
    if (ctx->status == PREFIX##_ERROR)             \
        return APREQ_ERROR_GENERAL;                \
    else if (ctx->status == PREFIX##_COMPLETE)     \
        return APR_SUCCESS;                        \
    else if (bb == NULL)                           \
        return APR_INCOMPLETE;                     \
} while (0);



struct url_ctx {
    apr_bucket_brigade *bb;
    apr_size_t          nlen;
    apr_size_t          vlen;
    enum {
        URL_NAME,
        URL_VALUE,
        URL_COMPLETE,
        URL_ERROR
    }                   status;
};


/******************** application/x-www-form-urlencoded ********************/

static apr_status_t split_urlword(apreq_param_t **p, apr_pool_t *pool,
                                  apr_bucket_brigade *bb,
                                  apr_size_t nlen,
                                  apr_size_t vlen)
{
    apreq_param_t *param;
    apreq_value_t *v;
    apr_bucket *e, *f;
    apr_status_t s;
    struct iovec vec[APREQ_DEFAULT_NELTS];
    apr_array_header_t arr;
    apr_size_t mark;
    apreq_charset_t charset;

    if (nlen == 0)
        return APR_EBADARG;

    param = apreq_param_make(pool, NULL, nlen, NULL, vlen);
    *(const apreq_value_t **)&v = &param->v;

    arr.pool     = pool;
    arr.elt_size = sizeof(struct iovec);
    arr.nelts    = 0;
    arr.nalloc   = APREQ_DEFAULT_NELTS;
    arr.elts     = (char *)vec;

    ++nlen, ++vlen;
    e = APR_BRIGADE_FIRST(bb);

    while (!APR_BUCKET_IS_EOS(e)) {
        struct iovec *iov = apr_array_push(&arr);
        apr_size_t len;
        s = apr_bucket_read(e, (const char **)&iov->iov_base,
                            &len, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        iov->iov_len = len;
        nlen -= len;

        e = APR_BUCKET_NEXT(e);

        if (nlen == 0) {
            iov->iov_len--;
            break;
        }
    }

    mark = arr.nelts;

    while (!APR_BUCKET_IS_EOS(e)) {
        struct iovec *iov = apr_array_push(&arr);
        apr_size_t len;
        s = apr_bucket_read(e, (const char **)&iov->iov_base,
                            &len, APR_BLOCK_READ);
        if (s != APR_SUCCESS)
            return s;

        iov->iov_len = len;
        vlen -= len;

        e = APR_BUCKET_NEXT(e);

        if (vlen == 0) {
            iov->iov_len--;
            break;
        }

    }

    s = apreq_decodev(v->data, &vlen,
                      (struct iovec *)arr.elts + mark, arr.nelts - mark);
    if (s != APR_SUCCESS)
        return s;

    charset = apreq_charset_divine(v->data, vlen);

    v->name = v->data + vlen + 1;
    v->dlen = vlen;

    s = apreq_decodev(v->name, &nlen, (struct iovec *)arr.elts, mark);
    if (s != APR_SUCCESS)
        return s;

    switch (apreq_charset_divine(v->name, nlen)) {
    case APREQ_CHARSET_UTF8:
        if (charset == APREQ_CHARSET_ASCII)
            charset = APREQ_CHARSET_UTF8;
    case APREQ_CHARSET_ASCII:
        break;

    case APREQ_CHARSET_LATIN1:
        if (charset != APREQ_CHARSET_CP1252)
            charset = APREQ_CHARSET_LATIN1;
        break;
    case APREQ_CHARSET_CP1252:
        charset = APREQ_CHARSET_CP1252;
    }

    v->nlen = nlen;

    while ((f = APR_BRIGADE_FIRST(bb)) != e)
        apr_bucket_delete(f);

    apreq_param_tainted_on(param);
    apreq_param_charset_set(param, charset);
    *p = param;
    return APR_SUCCESS;
}

APREQ_DECLARE_PARSER(apreq_parse_urlencoded)
{
    apr_pool_t *pool = parser->pool;
    apr_bucket *e;
    struct url_ctx *ctx;

    if (parser->ctx == NULL) {
        ctx = apr_pcalloc(pool, sizeof *ctx);
        ctx->bb = apr_brigade_create(pool, parser->bucket_alloc);
        parser->ctx = ctx;
        ctx->status = URL_NAME;
    }
    else
        ctx = parser->ctx;

    PARSER_STATUS_CHECK(URL);
    e = APR_BRIGADE_LAST(ctx->bb);
    APR_BRIGADE_CONCAT(ctx->bb, bb);

 parse_url_brigade:

    for (e  = APR_BUCKET_NEXT(e);
         e != APR_BRIGADE_SENTINEL(ctx->bb);
         e  = APR_BUCKET_NEXT(e))
    {
        apreq_param_t *param;
        apr_size_t off = 0, dlen;
        const char *data;
        apr_status_t s;

        if (APR_BUCKET_IS_EOS(e)) {
            if (ctx->status == URL_NAME) {
                s = APR_SUCCESS;
            }
            else {
                s = split_urlword(&param, pool, ctx->bb, ctx->nlen, ctx->vlen);
                if (parser->hook != NULL && s == APR_SUCCESS)
                    s = apreq_hook_run(parser->hook, param, NULL);

                if (s == APR_SUCCESS) {
                    apreq_value_table_add(&param->v, t);
                    ctx->status = URL_COMPLETE;
                }
                else {
                    ctx->status = URL_ERROR;
                }
            }

            APR_BRIGADE_CONCAT(bb, ctx->bb);
            return s;
        }

        s = apr_bucket_read(e, &data, &dlen, APR_BLOCK_READ);
        if ( s != APR_SUCCESS ) {
            ctx->status = URL_ERROR;
            return s;
        }

    parse_url_bucket:

        switch (ctx->status) {

        case URL_NAME:
            while (off < dlen) {
                switch (data[off++]) {
                case '=':
                    apr_bucket_split(e, off);
                    dlen -= off;
                    data += off;
                    off = 0;
                    e = APR_BUCKET_NEXT(e);
                    ctx->status = URL_VALUE;
                    goto parse_url_bucket;
                default:
                    ++ctx->nlen;
                }
            }
            break;

        case URL_VALUE:
            while (off < dlen) {

                switch (data[off++]) {
                case '&':
                case ';':
                    apr_bucket_split(e, off);
                    s = split_urlword(&param, pool, ctx->bb,
                                      ctx->nlen, ctx->vlen);
                    if (parser->hook != NULL && s == APR_SUCCESS)
                        s = apreq_hook_run(parser->hook, param, NULL);

                    if (s != APR_SUCCESS) {
                        ctx->status = URL_ERROR;
                        return s;
                    }

                    apreq_value_table_add(&param->v, t);
                    ctx->status = URL_NAME;
                    ctx->nlen = 0;
                    ctx->vlen = 0;
                    e = APR_BRIGADE_SENTINEL(ctx->bb);
                    goto parse_url_brigade;

                default:
                    ++ctx->vlen;
                }
            }
            break;
        default:
            ; /* not reached */
        }
    }
    apreq_brigade_setaside(ctx->bb, pool);
    return APR_INCOMPLETE;
}


