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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"
#include "apr_tables.h"
#include "apr_buckets.h"
#include "http_request.h"
#include "apr_strings.h"

#include "apreq_module_apache2.h"
#include "apreq_private_apache2.h"
#include "apreq_error.h"
#include "apreq_util.h"

static void *apreq_create_dir_config(apr_pool_t *p, char *d)
{
    /* d == OR_ALL */
    struct dir_config *dc = apr_palloc(p, sizeof *dc);
    dc->temp_dir      = NULL;
    dc->read_limit    = -1;
    dc->brigade_limit = -1;
    return dc;
}

static void *apreq_merge_dir_config(apr_pool_t *p, void *a_, void *b_)
{
    struct dir_config *a = a_, *b = b_, *c = apr_palloc(p, sizeof *c);

    c->temp_dir      = (b->temp_dir != NULL)            /* overrides ok */
                      ? b->temp_dir : a->temp_dir;

    c->brigade_limit = (b->brigade_limit == (apr_size_t)-1) /* overrides ok */
                      ? a->brigade_limit : b->brigade_limit;

    c->read_limit    = (b->read_limit < a->read_limit)  /* yes, min */
                      ? b->read_limit : a->read_limit;

    return c;
}

static const char *apreq_set_temp_dir(cmd_parms *cmd, void *data,
                                      const char *arg)
{
    struct dir_config *conf = data;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    conf->temp_dir = arg;
    return NULL;
}

static const char *apreq_set_read_limit(cmd_parms *cmd, void *data,
                                        const char *arg)
{
    struct dir_config *conf = data;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    conf->read_limit = apreq_atoi64f(arg);
    return NULL;
}

static const char *apreq_set_brigade_limit(cmd_parms *cmd, void *data,
                                           const char *arg)
{
    struct dir_config *conf = data;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    conf->brigade_limit = apreq_atoi64f(arg);
    return NULL;
}


static const command_rec apreq_cmds[] =
{
    AP_INIT_TAKE1("APREQ2_TempDir", apreq_set_temp_dir, NULL, OR_ALL,
                  "Default location of temporary directory"),
    AP_INIT_TAKE1("APREQ2_ReadLimit", apreq_set_read_limit, NULL, OR_ALL,
                  "Maximum amount of data that will be fed into a parser."),
    AP_INIT_TAKE1("APREQ2_BrigadeLimit", apreq_set_brigade_limit, NULL, OR_ALL,
                  "Maximum in-memory bytes a brigade may use."),
    { NULL }
};


void apreq_filter_init_context(ap_filter_t *f)
{
    request_rec *r = f->r;
    struct filter_ctx *ctx = f->ctx;
    apr_bucket_alloc_t *ba = r->connection->bucket_alloc;
    const char *cl_header;

    if (r->method_number == M_GET) {
        /* Don't parse GET (this protects against subrequest body parsing). */
        ctx->body_status = APREQ_ERROR_NODATA;
        return;
    }

    cl_header = apr_table_get(r->headers_in, "Content-Length");

    if (cl_header != NULL) {
        char *dummy;
        apr_uint64_t content_length = apr_strtoi64(cl_header,&dummy,0);

        if (dummy == NULL || *dummy != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r, APLOGNO(02045)
                          "Invalid Content-Length header (%s)", cl_header);
            ctx->body_status = APREQ_ERROR_BADHEADER;
            return;
        }
        else if (content_length > ctx->read_limit) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r, APLOGNO(02046)
                          "Content-Length header (%s) exceeds configured "
                          "max_body limit (%" APR_UINT64_T_FMT ")",
                          cl_header, ctx->read_limit);
            ctx->body_status = APREQ_ERROR_OVERLIMIT;
            return;
        }
    }

    if (ctx->parser == NULL) {
        const char *ct_header = apr_table_get(r->headers_in, "Content-Type");

        if (ct_header != NULL) {
            apreq_parser_function_t pf = apreq_parser(ct_header);

            if (pf != NULL) {
                ctx->parser = apreq_parser_make(r->pool, ba, ct_header, pf,
                                                ctx->brigade_limit,
                                                ctx->temp_dir,
                                                ctx->hook_queue,
                                                NULL);
            }
            else {
                ctx->body_status = APREQ_ERROR_NOPARSER;
                return;
            }
        }
        else {
            ctx->body_status = APREQ_ERROR_NOHEADER;
            return;
        }
    }
    else {
        if (ctx->parser->brigade_limit > ctx->brigade_limit)
            ctx->parser->brigade_limit = ctx->brigade_limit;
        if (ctx->temp_dir != NULL)
            ctx->parser->temp_dir = ctx->temp_dir;
        if (ctx->hook_queue != NULL)
            apreq_parser_add_hook(ctx->parser, ctx->hook_queue);
    }

    ctx->hook_queue = NULL;
    ctx->bb    = apr_brigade_create(r->pool, ba);
    ctx->bbtmp = apr_brigade_create(r->pool, ba);
    ctx->spool = apr_brigade_create(r->pool, ba);
    ctx->body  = apr_table_make(r->pool, APREQ_DEFAULT_NELTS);
    ctx->body_status = APR_INCOMPLETE;
}


/*
 * Situations to contend with:
 *
 * 1) Often the filter will be added by the content handler itself,
 *    so the apreq_filter_init hook will not be run.
 * 2) If an auth handler uses apreq, the apreq_filter will ensure
 *    it's part of the protocol filters.  apreq_filter_init does NOT need
 *    to notify the protocol filter that it must not continue parsing,
 *    the apreq filter can perform this check itself.  apreq_filter_init
 *    just needs to ensure cfg->f does not point at it.
 * 3) If req->proto_input_filters and req->input_filters are apreq
 *    filters, and req->input_filters->next == req->proto_input_filters,
 *    it is safe for apreq_filter to "steal" the proto filter's context
 *    and subsequently drop it from the chain.
 */


/* Examines the input_filter chain and moves the apreq filter(s) around
 * before the filter chain is stacked by ap_get_brigade.
 */


static apr_status_t apreq_filter_init(ap_filter_t *f)
{
    request_rec *r = f->r;
    struct filter_ctx *ctx = f->ctx;
    struct apache2_handle *handle =
        (struct apache2_handle *)apreq_handle_apache2(r);

    /* Don't parse GET (this protects against subrequest body parsing). */
    if (f->r->method_number == M_GET)
        return APR_SUCCESS;

    if (ctx == NULL || ctx->body_status == APR_EINIT) {
        if (f == r->input_filters) {
            handle->f = f;
        }
        else if (r->input_filters->frec->filter_func.in_func == apreq_filter) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02047)
                          "removing intermediate apreq filter");
            if (handle->f == f)
                handle->f = r->input_filters;
            ap_remove_input_filter(f);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02048)
                          "relocating intermediate apreq filter");
            apreq_filter_relocate(f);
            handle->f = f;
        }
        return APR_SUCCESS;
    }

    /* else this is a protocol filter which may still be active.
     * if it is, we must deregister it now.
     */
    if (handle->f == f) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02049)
                     "disabling stale protocol filter");
        if (ctx->body_status == APR_INCOMPLETE)
            ctx->body_status = APREQ_ERROR_INTERRUPT;
        handle->f = NULL;
    }
    return APR_SUCCESS;
}



apr_status_t apreq_filter_prefetch(ap_filter_t *f, apr_off_t readbytes)
{
    struct filter_ctx *ctx = f->ctx;
    request_rec *r = f->r;
    apr_status_t rv;
    apr_off_t len;

    if (ctx->body_status == APR_EINIT)
        apreq_filter_init_context(f);

    if (ctx->body_status != APR_INCOMPLETE || readbytes == 0)
        return ctx->body_status;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02050)
                  "prefetching %" APR_OFF_T_FMT " bytes", readbytes);

    rv = ap_get_brigade(f->next, ctx->bb, AP_MODE_READBYTES,
                       APR_BLOCK_READ, readbytes);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02051)
                      "ap_get_brigade failed during prefetch");
        ctx->filter_error = rv;
        return ctx->body_status = APREQ_ERROR_GENERAL;
    }

    apreq_brigade_setaside(ctx->bb, r->pool);
    apreq_brigade_copy(ctx->bbtmp, ctx->bb);

    rv = apreq_brigade_concat(r->pool, ctx->temp_dir, ctx->brigade_limit,
                              ctx->spool, ctx->bbtmp);
    if (rv != APR_SUCCESS && rv != APR_EOF) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02052)
                      "apreq_brigade_concat failed; TempDir problem?");
        ctx->filter_error = APR_EGENERAL;
        return ctx->body_status = rv;
    }

    /* Adding "f" to the protocol filter chain ensures the
     * spooled data is preserved across internal redirects.
     */

    if (f != r->proto_input_filters) {
        ap_filter_t *in;
        for (in = r->input_filters; in != r->proto_input_filters;
             in = in->next)
        {
            if (f == in) {
                r->proto_input_filters = f;
                break;
            }
        }
    }

    apr_brigade_length(ctx->bb, 1, &len);
    ctx->bytes_read += len;

    if (ctx->bytes_read > ctx->read_limit) {
        ctx->body_status = APREQ_ERROR_OVERLIMIT;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, ctx->body_status, r, APLOGNO(02053)
                      "Bytes read (%" APR_UINT64_T_FMT
                      ") exceeds configured read limit (%" APR_UINT64_T_FMT ")",
                      ctx->bytes_read, ctx->read_limit);
        return ctx->body_status;
    }

    ctx->body_status = apreq_parser_run(ctx->parser, ctx->body, ctx->bb);
    apr_brigade_cleanup(ctx->bb);

    return ctx->body_status;
}



apr_status_t apreq_filter(ap_filter_t *f,
                          apr_bucket_brigade *bb,
                          ap_input_mode_t mode,
                          apr_read_type_e block,
                          apr_off_t readbytes)
{
    request_rec *r = f->r;
    struct filter_ctx *ctx;
    apr_status_t rv;
    apr_off_t len;

    switch (mode) {
    case AP_MODE_READBYTES:
        /* only the modes above are supported */
        break;

    case AP_MODE_EXHAUSTIVE: /* not worth supporting at this level */
    case AP_MODE_GETLINE: /* chunked trailers are b0rked in ap_http_filter */
        return ap_get_brigade(f->next, bb, mode, block, readbytes);

    default:
        return APR_ENOTIMPL;
    }

    if (f->ctx == NULL)
        apreq_filter_make_context(f);

    ctx = f->ctx;

    if (ctx->body_status == APR_EINIT)
        apreq_filter_init_context(f);

    if (ctx->spool && !APR_BRIGADE_EMPTY(ctx->spool)) {
        apr_bucket *e;
        rv = apr_brigade_partition(ctx->spool, readbytes, &e);
        if (rv != APR_SUCCESS && rv != APR_INCOMPLETE)
            return rv;

        if (APR_BUCKET_IS_EOS(e))
            e = APR_BUCKET_NEXT(e);

        apreq_brigade_move(bb, ctx->spool, e);
        return APR_SUCCESS;
    }
    else if (ctx->body_status != APR_INCOMPLETE) {
        if (ctx->filter_error)
            return ctx->filter_error;

        rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
        ap_remove_input_filter(f);
        return rv;
    }


    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (rv != APR_SUCCESS)
        return rv;

    apreq_brigade_copy(ctx->bb, bb);
    apr_brigade_length(bb, 1, &len);
    ctx->bytes_read += len;

    if (ctx->bytes_read > ctx->read_limit) {
        ctx->body_status = APREQ_ERROR_OVERLIMIT;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, ctx->body_status, r, APLOGNO(02054)
                      "Bytes read (%" APR_UINT64_T_FMT
                      ") exceeds configured max_body limit (%"
                      APR_UINT64_T_FMT ")",
                      ctx->bytes_read, ctx->read_limit);
    }
    else {
        ctx->body_status = apreq_parser_run(ctx->parser, ctx->body, ctx->bb);
        apr_brigade_cleanup(ctx->bb);
    }
    return APR_SUCCESS;
}


static int apreq_pre_init(apr_pool_t *p, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *base_server)
{
    apr_status_t status;

    status = apreq_pre_initialize(p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, status, base_server, APLOGNO(02055)
                     "Failed to pre-initialize libapreq2");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_REGISTER_OPTIONAL_FN(apreq_handle_apache2);
    return OK;
}

static int apreq_post_init(apr_pool_t *p, apr_pool_t *plog,
                           apr_pool_t *ptemp, server_rec *base_server)
{
    apr_status_t status;

    status = apreq_post_initialize(p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, status, base_server, APLOGNO(02056)
                     "Failed to post-initialize libapreq2");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}

static void register_hooks (apr_pool_t *p)
{
    /* APR_HOOK_FIRST because we want other modules to be able to
     * register parsers in their post_config hook via APR_HOOK_MIDDLE.
     */
    ap_hook_post_config(apreq_pre_init, NULL, NULL, APR_HOOK_FIRST);

    /* APR_HOOK_LAST because we need to lock the default_parsers hash
     * (to prevent further modifications) before the server forks.
     */
    ap_hook_post_config(apreq_post_init, NULL, NULL, APR_HOOK_LAST);

    ap_register_input_filter(APREQ_FILTER_NAME, apreq_filter, apreq_filter_init,
                             AP_FTYPE_PROTOCOL-1);
}



/** @} */


module AP_MODULE_DECLARE_DATA apreq_module = {
#line __LINE__ "mod_apreq2.c"
	STANDARD20_MODULE_STUFF,
	apreq_create_dir_config,
	apreq_merge_dir_config,
	NULL,
	NULL,
	apreq_cmds,
	register_hooks,
};


void apreq_filter_make_context(ap_filter_t *f)
{
    request_rec *r;
    struct filter_ctx *ctx;
    struct dir_config *d;

    r = f->r;
    d = ap_get_module_config(r->per_dir_config, &apreq_module);

    if (f == r->input_filters
        && r->proto_input_filters == f->next
        && f->next->frec->filter_func.in_func == apreq_filter
        && f->r->method_number != M_GET)
    {

        ctx = f->next->ctx;

        switch (ctx->body_status) {

        case APREQ_ERROR_INTERRUPT:
            ctx->body_status = APR_INCOMPLETE;
            /* fall thru */

        case APR_SUCCESS:

            if (d != NULL) {
                ctx->temp_dir      = d->temp_dir;
                ctx->read_limit    = d->read_limit;
                ctx->brigade_limit = d->brigade_limit;

                if (ctx->parser != NULL) {
                    ctx->parser->temp_dir = d->temp_dir;
                    ctx->parser->brigade_limit = d->brigade_limit;
                }

            }

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02057)
                          "stealing filter context");
            f->ctx = ctx;
            r->proto_input_filters = f;
            ap_remove_input_filter(f->next);

            return;

        default:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, ctx->body_status, r, APLOGNO(02058)
                          "cannot steal context: bad filter status");
        }
    }

    ctx = apr_pcalloc(r->pool, sizeof *ctx);
    ctx->body_status = APR_EINIT;

    if (d == NULL) {
        ctx->read_limit    = (apr_uint64_t)-1;
        ctx->brigade_limit = APREQ_DEFAULT_BRIGADE_LIMIT;
    } else {
        ctx->temp_dir      = d->temp_dir;
        ctx->read_limit    = (d->read_limit == (apr_uint64_t)-1)
            ? APREQ_DEFAULT_READ_LIMIT : d->read_limit;
        ctx->brigade_limit = (d->brigade_limit == (apr_size_t)-1)
            ? APREQ_DEFAULT_BRIGADE_LIMIT : d->brigade_limit;
    }

    f->ctx = ctx;
}
