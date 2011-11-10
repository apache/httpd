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

#include "apreq_error.h"
#include "apreq_parser.h"
#include "apreq_util.h"
#include "apr_strings.h"
#include "apr_xml.h"
#include "apr_hash.h"

#define PARSER_STATUS_CHECK(PREFIX)   do {         \
    if (ctx->status == PREFIX##_ERROR)             \
        return APREQ_ERROR_GENERAL;                \
    else if (ctx->status == PREFIX##_COMPLETE)     \
        return APR_SUCCESS;                        \
    else if (bb == NULL)                           \
        return APR_INCOMPLETE;                     \
} while (0);

APREQ_DECLARE(apreq_parser_t *) apreq_parser_make(apr_pool_t *pool,
                                                  apr_bucket_alloc_t *ba,
                                                  const char *content_type,
                                                  apreq_parser_function_t pfn,
                                                  apr_size_t brigade_limit,
                                                  const char *temp_dir,
                                                  apreq_hook_t *hook,
                                                  void *ctx)
{
    apreq_parser_t *p = apr_palloc(pool, sizeof *p);
    p->content_type = content_type;
    p->parser = pfn;
    p->hook = hook;
    p->pool = pool;
    p->bucket_alloc = ba;
    p->brigade_limit = brigade_limit;
    p->temp_dir = temp_dir;
    p->ctx = ctx;
    return p;
}

APREQ_DECLARE(apreq_hook_t *) apreq_hook_make(apr_pool_t *pool,
                                              apreq_hook_function_t hook,
                                              apreq_hook_t *next,
                                              void *ctx)
{
    apreq_hook_t *h = apr_palloc(pool, sizeof *h);
    h->hook = hook;
    h->next = next;
    h->pool = pool;
    h->ctx = ctx;
    return h;
}


/*XXX this may need to check the parser's state before modifying the hook list */
APREQ_DECLARE(apr_status_t) apreq_parser_add_hook(apreq_parser_t *p,
                                                  apreq_hook_t *h)
{
    apreq_hook_t *last = h;

    while (last->next)
        last = last->next;

    last->next = p->hook;
    p->hook = h;

    return APR_SUCCESS;
}

static int default_parsers_lock = 0;
static apr_hash_t *default_parsers = NULL;
static apr_pool_t *default_parser_pool = NULL;

static apr_status_t apreq_parsers_cleanup(void *data)
{
    default_parsers_lock = 0;
    default_parsers = NULL;
    default_parser_pool = NULL;

    return APR_SUCCESS;
}

APREQ_DECLARE(apr_status_t) apreq_pre_initialize(apr_pool_t *pool)
{
    apr_status_t status;

    if (default_parser_pool != NULL)
        return APR_SUCCESS;

    if (default_parsers_lock)
        return APREQ_ERROR_GENERAL;

    status = apr_pool_create(&default_parser_pool, pool);
    if (status != APR_SUCCESS)
        return status;

    apr_pool_cleanup_register(default_parser_pool, NULL,
                              apreq_parsers_cleanup,
                              apr_pool_cleanup_null);

    default_parsers = apr_hash_make(default_parser_pool);

    apreq_register_parser("application/x-www-form-urlencoded",
                          apreq_parse_urlencoded);
    apreq_register_parser("multipart/form-data", apreq_parse_multipart);
    apreq_register_parser("multipart/related", apreq_parse_multipart);

    return APR_SUCCESS;
}

APREQ_DECLARE(apr_status_t) apreq_post_initialize(apr_pool_t *pool)
{
    (void)pool;

    if (default_parser_pool == NULL)
        return APREQ_ERROR_GENERAL;

    default_parsers_lock = 1;
    return APR_SUCCESS;
}

APREQ_DECLARE(apr_status_t) apreq_initialize(apr_pool_t *pool)
{
    apr_status_t s = apreq_pre_initialize(pool);

    if (s != APR_SUCCESS)
        return s;

    return apreq_post_initialize(pool);
}


APREQ_DECLARE(apr_status_t) apreq_register_parser(const char *enctype,
                                                  apreq_parser_function_t pfn)
{
    apreq_parser_function_t *f = NULL;

    if (default_parsers == NULL)
        return APR_EINIT;

    if (enctype == NULL)
        return APR_EINVAL;

    if (default_parsers_lock)
        return APREQ_ERROR_GENERAL;

    if (pfn != NULL) {
        f = apr_palloc(default_parser_pool, sizeof *f);
        *f = pfn;
    }
    apr_hash_set(default_parsers, apr_pstrdup(default_parser_pool, enctype),
                 APR_HASH_KEY_STRING, f);

    return APR_SUCCESS;
}

APREQ_DECLARE(apreq_parser_function_t)apreq_parser(const char *enctype)
{
    apreq_parser_function_t *f;
    apr_size_t tlen = 0;

    if (enctype == NULL || default_parsers_lock == 0)
        return NULL;

    while(enctype[tlen] && enctype[tlen] != ';')
        ++tlen;

    f = apr_hash_get(default_parsers, enctype, tlen);

    if (f != NULL)
        return *f;
    else
        return NULL;
}

APREQ_DECLARE_HOOK(apreq_hook_disable_uploads)
{
    return (bb == NULL) ? APR_SUCCESS : APREQ_ERROR_GENERAL;
}

APREQ_DECLARE_HOOK(apreq_hook_discard_brigade)
{
    apr_status_t s = APR_SUCCESS;
    if (hook->next)
        s = apreq_hook_run(hook->next, param, bb);
    if (bb != NULL)
        apr_brigade_cleanup(bb);
    return s;
}


/* generic parser */

struct gen_ctx {
    apreq_param_t               *param;
    enum {
        GEN_INCOMPLETE,
        GEN_COMPLETE,
        GEN_ERROR
    }                            status;
};

APREQ_DECLARE_PARSER(apreq_parse_generic)
{
    struct gen_ctx *ctx = parser->ctx;
    apr_pool_t *pool = parser->pool;
    apr_status_t s = APR_SUCCESS;
    apr_bucket *e = APR_BRIGADE_LAST(bb);
    unsigned saw_eos = 0;

    if (ctx == NULL) {
        parser->ctx = ctx = apr_palloc(pool, sizeof *ctx);
        ctx->status = GEN_INCOMPLETE;
        ctx->param = apreq_param_make(pool,
                                      "_dummy_", strlen("_dummy_"), "", 0);
        ctx->param->upload = apr_brigade_create(pool, parser->bucket_alloc);
        ctx->param->info = apr_table_make(pool, APREQ_DEFAULT_NELTS);
    }


    PARSER_STATUS_CHECK(GEN);

    while (e != APR_BRIGADE_SENTINEL(bb)) {
        if (APR_BUCKET_IS_EOS(e)) {
            saw_eos = 1;
            break;
        }
        e = APR_BUCKET_PREV(e);
    }

    if (parser->hook != NULL) {
        s = apreq_hook_run(parser->hook, ctx->param, bb);
        if (s != APR_SUCCESS) {
            ctx->status = GEN_ERROR;
            return s;
        }
    }

    apreq_brigade_setaside(bb, pool);
    s = apreq_brigade_concat(pool, parser->temp_dir, parser->brigade_limit,
                             ctx->param->upload, bb);

    if (s != APR_SUCCESS) {
        ctx->status = GEN_ERROR;
        return s;
    }

    if (saw_eos) {
        ctx->status = GEN_COMPLETE;
        return APR_SUCCESS;
    }
    else
        return APR_INCOMPLETE;
}


struct xml_ctx {
    apr_xml_doc                 *doc;
    apr_xml_parser              *xml_parser;
    enum {
        XML_INCOMPLETE,
        XML_COMPLETE,
        XML_ERROR
    }                            status;
};


APREQ_DECLARE_HOOK(apreq_hook_apr_xml_parser)
{
    apr_pool_t *pool = hook->pool;
    struct xml_ctx *ctx = hook->ctx;
    apr_status_t s = APR_SUCCESS;
    apr_bucket *e;

    if (ctx == NULL) {
        hook->ctx = ctx = apr_palloc(pool, sizeof *ctx);
        ctx->doc = NULL;
        ctx->xml_parser = apr_xml_parser_create(pool);
        ctx->status = XML_INCOMPLETE;
    }

    PARSER_STATUS_CHECK(XML);

    for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        const char *data;
        apr_size_t dlen;

        if (APR_BUCKET_IS_EOS(e)) {
            s = apr_xml_parser_done(ctx->xml_parser, &ctx->doc);
            if (s == APR_SUCCESS) {
                ctx->status = XML_COMPLETE;
                if (hook->next)
                    s = apreq_hook_run(hook->next, param, bb);
            }
            else {
                ctx->status = XML_ERROR;
            }
           return s;
        }
        else if (APR_BUCKET_IS_METADATA(e)) {
            continue;
        }

        s = apr_bucket_read(e, &data, &dlen, APR_BLOCK_READ);

        if (s != APR_SUCCESS) {
            ctx->status = XML_ERROR;
            return s;
        }

        s = apr_xml_parser_feed(ctx->xml_parser, data, dlen);

        if (s != APR_SUCCESS) {
            ctx->status = XML_ERROR;
            return s;
        }

    }

    if (hook->next)
        return apreq_hook_run(hook->next, param, bb);

    return APR_SUCCESS;
}


APREQ_DECLARE_HOOK(apreq_hook_find_param)
{
    apreq_hook_find_param_ctx_t *ctx = hook->ctx;
    int is_final = (bb == NULL) || APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb));
    apr_status_t s = (hook->next == NULL)
        ? APR_SUCCESS : apreq_hook_run(hook->next, param, bb);

    if (is_final && s == APR_SUCCESS
        && strcasecmp(ctx->name, param->v.name) == 0) {
        ctx->param = param;
        ctx->prev->next = hook->next;
    }
    return s;
}
