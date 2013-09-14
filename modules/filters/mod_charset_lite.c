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
 * simple hokey charset recoding configuration module
 *
 * See mod_ebcdic and mod_charset for more thought-out examples.  This
 * one is just so Jeff can learn how a module works and experiment with
 * basic character set recoding configuration.
 *
 * !!!This is an extremely cheap ripoff of mod_charset.c from Russian Apache!!!
 */

#include "httpd.h"
#include "http_config.h"

#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_charset.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_xlate.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#define OUTPUT_XLATE_BUF_SIZE (16*1024) /* size of translation buffer used on output */
#define INPUT_XLATE_BUF_SIZE  (8*1024)  /* size of translation buffer used on input */

#define XLATE_MIN_BUFF_LEFT 128  /* flush once there is no more than this much
                                  * space left in the translation buffer
                                  */

#define FATTEST_CHAR  8          /* we don't handle chars wider than this that straddle
                                  * two buckets
                                  */

/* extended error status codes; this is used in addition to an apr_status_t to
 * track errors in the translation filter
 */
typedef enum {
    EES_INIT = 0,   /* no error info yet; value must be 0 for easy init */
    EES_LIMIT,      /* built-in restriction encountered */
    EES_INCOMPLETE_CHAR, /* incomplete multi-byte char at end of content */
    EES_BUCKET_READ,
    EES_DOWNSTREAM, /* something bad happened in a filter below xlate */
    EES_BAD_INPUT   /* input data invalid */
} ees_t;

/* registered name of the output translation filter */
#define XLATEOUT_FILTER_NAME "XLATEOUT"
/* registered name of input translation filter */
#define XLATEIN_FILTER_NAME  "XLATEIN"

typedef struct charset_dir_t {
    const char *charset_source; /* source encoding */
    const char *charset_default; /* how to ship on wire */
    /** module does ap_add_*_filter()? */
    enum {IA_INIT, IA_IMPADD, IA_NOIMPADD} implicit_add;
    /** treat all mimetypes as text? */
    enum {FX_INIT, FX_FORCE, FX_NOFORCE} force_xlate;
} charset_dir_t;

/* charset_filter_ctx_t is created for each filter instance; because the same
 * filter code is used for translating in both directions, we need this context
 * data to tell the filter which translation handle to use; it also can hold a
 * character which was split between buckets
 */
typedef struct charset_filter_ctx_t {
    apr_xlate_t *xlate;
    int is_sb;              /* single-byte translation? */
    charset_dir_t *dc;
    ees_t ees;              /* extended error status */
    apr_size_t saved;
    char buf[FATTEST_CHAR]; /* we want to be able to build a complete char here */
    int ran;                /* has filter instance run before? */
    int noop;               /* should we pass brigades through unchanged? */
    char *tmp;              /* buffer for input filtering */
    apr_bucket_brigade *bb; /* input buckets we couldn't finish translating */
    apr_bucket_brigade *tmpbb; /* used for passing downstream */
} charset_filter_ctx_t;

/* charset_req_t is available via r->request_config if any translation is
 * being performed
 */
typedef struct charset_req_t {
    charset_dir_t *dc;
    charset_filter_ctx_t *output_ctx, *input_ctx;
} charset_req_t;

module AP_MODULE_DECLARE_DATA charset_lite_module;

static void *create_charset_dir_conf(apr_pool_t *p,char *dummy)
{
    charset_dir_t *dc = (charset_dir_t *)apr_pcalloc(p,sizeof(charset_dir_t));

    return dc;
}

static void *merge_charset_dir_conf(apr_pool_t *p, void *basev, void *overridesv)
{
    charset_dir_t *a = (charset_dir_t *)apr_pcalloc (p, sizeof(charset_dir_t));
    charset_dir_t *base = (charset_dir_t *)basev,
        *over = (charset_dir_t *)overridesv;

    /* If it is defined in the current container, use it.  Otherwise, use the one
     * from the enclosing container.
     */

    a->charset_default =
        over->charset_default ? over->charset_default : base->charset_default;
    a->charset_source =
        over->charset_source ? over->charset_source : base->charset_source;
    a->implicit_add =
        over->implicit_add != IA_INIT ? over->implicit_add : base->implicit_add;
    a->force_xlate=
        over->force_xlate != FX_INIT ? over->force_xlate : base->force_xlate;
    return a;
}

/* CharsetSourceEnc charset
 */
static const char *add_charset_source(cmd_parms *cmd, void *in_dc,
                                      const char *name)
{
    charset_dir_t *dc = in_dc;

    dc->charset_source = name;
    return NULL;
}

/* CharsetDefault charset
 */
static const char *add_charset_default(cmd_parms *cmd, void *in_dc,
                                       const char *name)
{
    charset_dir_t *dc = in_dc;

    dc->charset_default = name;
    return NULL;
}

/* CharsetOptions optionflag...
 */
static const char *add_charset_options(cmd_parms *cmd, void *in_dc,
                                       const char *flag)
{
    charset_dir_t *dc = in_dc;

    if (!strcasecmp(flag, "ImplicitAdd")) {
        dc->implicit_add = IA_IMPADD;
    }
    else if (!strcasecmp(flag, "NoImplicitAdd")) {
        dc->implicit_add = IA_NOIMPADD;
    }
    else if (!strcasecmp(flag, "TranslateAllMimeTypes")) {
        dc->force_xlate = FX_FORCE;
    }
    else if (!strcasecmp(flag, "NoTranslateAllMimeTypes")) {
        dc->force_xlate = FX_NOFORCE;
    }
    else {
        return apr_pstrcat(cmd->temp_pool,
                           "Invalid CharsetOptions option: ",
                           flag,
                           NULL);
    }

    return NULL;
}

/* find_code_page() is a fixup hook that checks if the module is
 * configured and the input or output potentially need to be translated.
 * If so, context is initialized for the filters.
 */
static int find_code_page(request_rec *r)
{
    charset_dir_t *dc = ap_get_module_config(r->per_dir_config,
                                             &charset_lite_module);
    charset_req_t *reqinfo;
    charset_filter_ctx_t *input_ctx, *output_ctx;
    apr_status_t rv;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                  "uri: %s file: %s method: %d "
                  "imt: %s flags: %s%s%s %s->%s",
                  r->uri,
                  r->filename ? r->filename : "(none)",
                  r->method_number,
                  r->content_type ? r->content_type : "(unknown)",
                  r->main     ? "S" : "",    /* S if subrequest */
                  r->prev     ? "R" : "",    /* R if redirect */
                  r->proxyreq ? "P" : "",    /* P if proxy */
                  dc->charset_source, dc->charset_default);

    /* If we don't have a full directory configuration, bail out.
     */
    if (!dc->charset_source || !dc->charset_default) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01448)
                      "incomplete configuration: src %s, dst %s",
                      dc->charset_source ? dc->charset_source : "unspecified",
                      dc->charset_default ? dc->charset_default : "unspecified");
        return DECLINED;
    }

    /* catch proxy requests */
    if (r->proxyreq) {
        return DECLINED;
    }

    /* mod_rewrite indicators */
    if (r->filename
        && (!strncmp(r->filename, "redirect:", 9)
            || !strncmp(r->filename, "gone:", 5)
            || !strncmp(r->filename, "passthrough:", 12)
            || !strncmp(r->filename, "forbidden:", 10))) {
        return DECLINED;
    }

    /* no translation when server and network charsets are set to the same value */
    if (!strcasecmp(dc->charset_source, dc->charset_default)) {
        return DECLINED;
    }

    /* Get storage for the request data and the output filter context.
     * We rarely need the input filter context, so allocate that separately.
     */
    reqinfo = (charset_req_t *)apr_pcalloc(r->pool,
                                           sizeof(charset_req_t) +
                                           sizeof(charset_filter_ctx_t));
    output_ctx = (charset_filter_ctx_t *)(reqinfo + 1);

    reqinfo->dc = dc;
    output_ctx->dc = dc;
    output_ctx->tmpbb = apr_brigade_create(r->pool,
                                           r->connection->bucket_alloc);
    ap_set_module_config(r->request_config, &charset_lite_module, reqinfo);

    reqinfo->output_ctx = output_ctx;

    switch (r->method_number) {
    case M_PUT:
    case M_POST:
        /* Set up input translation.  Note: A request body can be included
         * with the OPTIONS method, but for now we don't set up translation
         * of it.
         */
        input_ctx = apr_pcalloc(r->pool, sizeof(charset_filter_ctx_t));
        input_ctx->bb = apr_brigade_create(r->pool,
                                           r->connection->bucket_alloc);
        input_ctx->tmp = apr_palloc(r->pool, INPUT_XLATE_BUF_SIZE);
        input_ctx->dc = dc;
        reqinfo->input_ctx = input_ctx;
        rv = apr_xlate_open(&input_ctx->xlate, dc->charset_source,
                            dc->charset_default, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01449)
                          "can't open translation %s->%s",
                          dc->charset_default, dc->charset_source);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (apr_xlate_sb_get(input_ctx->xlate, &input_ctx->is_sb) != APR_SUCCESS) {
            input_ctx->is_sb = 0;
        }
    }

    return DECLINED;
}

static int configured_in_list(request_rec *r, const char *filter_name,
                              struct ap_filter_t *filter_list)
{
    struct ap_filter_t *filter = filter_list;

    while (filter) {
        if (!strcasecmp(filter_name, filter->frec->name)) {
            return 1;
        }
        filter = filter->next;
    }
    return 0;
}

static int configured_on_input(request_rec *r, const char *filter_name)
{
    return configured_in_list(r, filter_name, r->input_filters);
}

static int configured_on_output(request_rec *r, const char *filter_name)
{
    return configured_in_list(r, filter_name, r->output_filters);
}

/* xlate_insert_filter() is a filter hook which decides whether or not
 * to insert a translation filter for the current request.
 */
static void xlate_insert_filter(request_rec *r)
{
    /* Hey... don't be so quick to use reqinfo->dc here; reqinfo may be NULL */
    charset_req_t *reqinfo = ap_get_module_config(r->request_config,
                                                  &charset_lite_module);
    charset_dir_t *dc = ap_get_module_config(r->per_dir_config,
                                             &charset_lite_module);

    if (dc && (dc->implicit_add == IA_NOIMPADD)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE6, 0, r,
                      "xlate output filter not added implicitly because "
                      "CharsetOptions included 'NoImplicitAdd'");
        return;
    }

    if (reqinfo) {
        if (reqinfo->output_ctx && !configured_on_output(r, XLATEOUT_FILTER_NAME)) {
            ap_add_output_filter(XLATEOUT_FILTER_NAME, reqinfo->output_ctx, r,
                                 r->connection);
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "xlate output filter not added implicitly because %s",
                      !reqinfo->output_ctx ?
                      "no output configuration available" :
                      "another module added the filter");

        if (reqinfo->input_ctx && !configured_on_input(r, XLATEIN_FILTER_NAME)) {
            ap_add_input_filter(XLATEIN_FILTER_NAME, reqinfo->input_ctx, r,
                                r->connection);
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "xlate input filter not added implicitly because %s",
                      !reqinfo->input_ctx ?
                      "no input configuration available" :
                      "another module added the filter");
    }
}

/* stuff that sucks that I know of:
 *
 * bucket handling:
 *  why create an eos bucket when we see it come down the stream?  just send the one
 *  passed as input...  news flash: this will be fixed when xlate_out_filter() starts
 *  using the more generic xlate_brigade()
 *
 * translation mechanics:
 *   we don't handle characters that straddle more than two buckets; an error
 *   will be generated
 */

static apr_status_t send_bucket_downstream(ap_filter_t *f, apr_bucket *b)
{
    charset_filter_ctx_t *ctx = f->ctx;
    apr_status_t rv;

    APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);
    rv = ap_pass_brigade(f->next, ctx->tmpbb);
    if (rv != APR_SUCCESS) {
        ctx->ees = EES_DOWNSTREAM;
    }
    apr_brigade_cleanup(ctx->tmpbb);
    return rv;
}

/* send_downstream() is passed the translated data; it puts it in a single-
 * bucket brigade and passes the brigade to the next filter
 */
static apr_status_t send_downstream(ap_filter_t *f, const char *tmp, apr_size_t len)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *b;

    b = apr_bucket_transient_create(tmp, len, c->bucket_alloc);
    return send_bucket_downstream(f, b);
}

static apr_status_t send_eos(ap_filter_t *f)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    charset_filter_ctx_t *ctx = f->ctx;
    apr_status_t rv;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(f->next, bb);
    if (rv != APR_SUCCESS) {
        ctx->ees = EES_DOWNSTREAM;
    }
    return rv;
}

static apr_status_t set_aside_partial_char(charset_filter_ctx_t *ctx,
                                           const char *partial,
                                           apr_size_t partial_len)
{
    apr_status_t rv;

    if (sizeof(ctx->buf) > partial_len) {
        ctx->saved = partial_len;
        memcpy(ctx->buf, partial, partial_len);
        rv = APR_SUCCESS;
    }
    else {
        rv = APR_INCOMPLETE;
        ctx->ees = EES_LIMIT; /* we don't handle chars this wide which straddle
                               * buckets
                               */
    }
    return rv;
}

static apr_status_t finish_partial_char(charset_filter_ctx_t *ctx,
                                        /* input buffer: */
                                        const char **cur_str,
                                        apr_size_t *cur_len,
                                        /* output buffer: */
                                        char **out_str,
                                        apr_size_t *out_len)
{
    apr_status_t rv;
    apr_size_t tmp_input_len;

    /* Keep adding bytes from the input string to the saved string until we
     *    1) finish the input char
     *    2) get an error
     * or 3) run out of bytes to add
     */

    do {
        ctx->buf[ctx->saved] = **cur_str;
        ++ctx->saved;
        ++*cur_str;
        --*cur_len;
        tmp_input_len = ctx->saved;
        rv = apr_xlate_conv_buffer(ctx->xlate,
                                   ctx->buf,
                                   &tmp_input_len,
                                   *out_str,
                                   out_len);
    } while (rv == APR_INCOMPLETE && *cur_len);

    if (rv == APR_SUCCESS) {
        ctx->saved = 0;
    }
    else {
        ctx->ees = EES_LIMIT; /* code isn't smart enough to handle chars
                               * straddling more than two buckets
                               */
    }

    return rv;
}

static void log_xlate_error(ap_filter_t *f, apr_status_t rv)
{
    charset_filter_ctx_t *ctx = f->ctx;
    const char *msg;
    char msgbuf[100];
    apr_size_t len;

    switch(ctx->ees) {
    case EES_LIMIT:
        rv = 0;
        msg = APLOGNO(02193) "xlate filter - a built-in restriction was encountered";
        break;
    case EES_BAD_INPUT:
        rv = 0;
        msg = APLOGNO(02194) "xlate filter - an input character was invalid";
        break;
    case EES_BUCKET_READ:
        rv = 0;
        msg = APLOGNO(02195) "xlate filter - bucket read routine failed";
        break;
    case EES_INCOMPLETE_CHAR:
        rv = 0;
        strcpy(msgbuf, APLOGNO(02196) "xlate filter - incomplete char at end of input - ");
        len = ctx->saved;

        /* We must ensure not to process more than what would fit in the
         * remaining of the destination buffer, including terminating NULL */
        if (len > (sizeof(msgbuf) - strlen(msgbuf) - 1) / 2)
            len = (sizeof(msgbuf) - strlen(msgbuf) - 1) / 2;

        ap_bin2hex(ctx->buf, len, msgbuf + strlen(msgbuf));
        msg = msgbuf;
        break;
    case EES_DOWNSTREAM:
        msg = APLOGNO(02197) "xlate filter - an error occurred in a lower filter";
        break;
    default:
        msg = APLOGNO(02198) "xlate filter - returning error";
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, "%s", msg);
}

/* chk_filter_chain() is called once per filter instance; it tries to
 * determine if the current filter instance should be disabled because
 * its translation is incompatible with the translation of an existing
 * instance of the translate filter
 *
 * Example bad scenario:
 *
 *   configured filter chain for the request:
 *     INCLUDES XLATEOUT(8859-1->UTS-16)
 *   configured filter chain for the subrequest:
 *     XLATEOUT(8859-1->UTS-16)
 *
 *   When the subrequest is processed, the filter chain will be
 *     XLATEOUT(8859-1->UTS-16) XLATEOUT(8859-1->UTS-16)
 *   This makes no sense, so the instance of XLATEOUT added for the
 *   subrequest will be noop-ed.
 *
 * Example good scenario:
 *
 *   configured filter chain for the request:
 *     INCLUDES XLATEOUT(8859-1->UTS-16)
 *   configured filter chain for the subrequest:
 *     XLATEOUT(IBM-1047->8859-1)
 *
 *   When the subrequest is processed, the filter chain will be
 *     XLATEOUT(IBM-1047->8859-1) XLATEOUT(8859-1->UTS-16)
 *   This makes sense, so the instance of XLATEOUT added for the
 *   subrequest will be left alone and it will translate from
 *   IBM-1047->8859-1.
 */
static void chk_filter_chain(ap_filter_t *f)
{
    ap_filter_t *curf;
    charset_filter_ctx_t *curctx, *last_xlate_ctx = NULL,
        *ctx = f->ctx;
    int output = !strcasecmp(f->frec->name, XLATEOUT_FILTER_NAME);

    if (ctx->noop) {
        return;
    }

    /* walk the filter chain; see if it makes sense for our filter to
     * do any translation
     */
    curf = output ? f->r->output_filters : f->r->input_filters;
    while (curf) {
        if (!strcasecmp(curf->frec->name, f->frec->name) &&
            curf->ctx) {
            curctx = (charset_filter_ctx_t *)curf->ctx;
            if (!last_xlate_ctx) {
                last_xlate_ctx = curctx;
            }
            else {
                if (strcmp(last_xlate_ctx->dc->charset_default,
                           curctx->dc->charset_source)) {
                    /* incompatible translation
                     * if our filter instance is incompatible with an instance
                     * already in place, noop our instance
                     * Notes:
                     * . We are only willing to noop our own instance.
                     * . It is possible to noop another instance which has not
                     *   yet run, but this is not currently implemented.
                     *   Hopefully it will not be needed.
                     * . It is not possible to noop an instance which has
                     *   already run.
                     */
                    if (last_xlate_ctx == f->ctx) {
                        last_xlate_ctx->noop = 1;
                        if (APLOGrtrace1(f->r)) {
                            const char *symbol = output ? "->" : "<-";

                            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,
                                          0, f->r, APLOGNO(01451)
                                          "%s %s - disabling "
                                          "translation %s%s%s; existing "
                                          "translation %s%s%s",
                                          f->r->uri ? "uri" : "file",
                                          f->r->uri ? f->r->uri : f->r->filename,
                                          last_xlate_ctx->dc->charset_source,
                                          symbol,
                                          last_xlate_ctx->dc->charset_default,
                                          curctx->dc->charset_source,
                                          symbol,
                                          curctx->dc->charset_default);
                        }
                    }
                    else {
                        const char *symbol = output ? "->" : "<-";

                        ap_log_rerror(APLOG_MARK, APLOG_ERR,
                                      0, f->r, APLOGNO(01452)
                                      "chk_filter_chain() - can't disable "
                                      "translation %s%s%s; existing "
                                      "translation %s%s%s",
                                      last_xlate_ctx->dc->charset_source,
                                      symbol,
                                      last_xlate_ctx->dc->charset_default,
                                      curctx->dc->charset_source,
                                      symbol,
                                      curctx->dc->charset_default);
                    }
                    break;
                }
            }
        }
        curf = curf->next;
    }
}

/* xlate_brigade() is used to filter request and response bodies
 *
 * we'll stop when one of the following occurs:
 * . we run out of buckets
 * . we run out of space in the output buffer
 * . we hit an error or metadata
 *
 * inputs:
 *   bb:               brigade to process
 *   buffer:           storage to hold the translated characters
 *   buffer_avail:     size of buffer
 *   (and a few more uninteresting parms)
 *
 * outputs:
 *   return value:     APR_SUCCESS or some error code
 *   bb:               we've removed any buckets representing the
 *                     translated characters; the eos bucket, if
 *                     present, will be left in the brigade
 *   buffer:           filled in with translated characters
 *   buffer_avail:     updated with the bytes remaining
 *   hit_eos:          did we hit an EOS bucket?
 */
static apr_status_t xlate_brigade(charset_filter_ctx_t *ctx,
                                  apr_bucket_brigade *bb,
                                  char *buffer,
                                  apr_size_t *buffer_avail,
                                  int *hit_eos)
{
    apr_bucket *b = NULL; /* set to NULL only to quiet some gcc */
    apr_bucket *consumed_bucket;
    const char *bucket;
    apr_size_t bytes_in_bucket; /* total bytes read from current bucket */
    apr_size_t bucket_avail;    /* bytes left in current bucket */
    apr_status_t rv = APR_SUCCESS;

    *hit_eos = 0;
    bucket_avail = 0;
    consumed_bucket = NULL;
    while (1) {
        if (!bucket_avail) { /* no bytes left to process in the current bucket... */
            if (consumed_bucket) {
                apr_bucket_delete(consumed_bucket);
                consumed_bucket = NULL;
            }
            b = APR_BRIGADE_FIRST(bb);
            if (b == APR_BRIGADE_SENTINEL(bb) ||
                APR_BUCKET_IS_METADATA(b)) {
                break;
            }
            rv = apr_bucket_read(b, &bucket, &bytes_in_bucket, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                ctx->ees = EES_BUCKET_READ;
                break;
            }
            bucket_avail = bytes_in_bucket;
            consumed_bucket = b;   /* for axing when we're done reading it */
        }
        if (bucket_avail) {
            /* We've got data, so translate it. */
            if (ctx->saved) {
                /* Rats... we need to finish a partial character from the previous
                 * bucket.
                 *
                 * Strangely, finish_partial_char() increments the input buffer
                 * pointer but does not increment the output buffer pointer.
                 */
                apr_size_t old_buffer_avail = *buffer_avail;
                rv = finish_partial_char(ctx,
                                         &bucket, &bucket_avail,
                                         &buffer, buffer_avail);
                buffer += old_buffer_avail - *buffer_avail;
            }
            else {
                apr_size_t old_buffer_avail = *buffer_avail;
                apr_size_t old_bucket_avail = bucket_avail;
                rv = apr_xlate_conv_buffer(ctx->xlate,
                                           bucket, &bucket_avail,
                                           buffer,
                                           buffer_avail);
                buffer  += old_buffer_avail - *buffer_avail;
                bucket  += old_bucket_avail - bucket_avail;

                if (rv == APR_INCOMPLETE) { /* partial character at end of input */
                    /* We need to save the final byte(s) for next time; we can't
                     * convert it until we look at the next bucket.
                     */
                    rv = set_aside_partial_char(ctx, bucket, bucket_avail);
                    bucket_avail = 0;
                }
            }
            if (rv != APR_SUCCESS) {
                /* bad input byte or partial char too big to store */
                break;
            }
            if (*buffer_avail < XLATE_MIN_BUFF_LEFT) {
                /* if any data remains in the current bucket, split there */
                if (bucket_avail) {
                    apr_bucket_split(b, bytes_in_bucket - bucket_avail);
                }
                apr_bucket_delete(b);
                break;
            }
        }
    }

    if (!APR_BRIGADE_EMPTY(bb)) {
        b = APR_BRIGADE_FIRST(bb);
        if (APR_BUCKET_IS_EOS(b)) {
            /* Leave the eos bucket in the brigade for reporting to
             * subsequent filters.
             */
            *hit_eos = 1;
            if (ctx->saved) {
                /* Oops... we have a partial char from the previous bucket
                 * that won't be completed because there's no more data.
                 */
                rv = APR_INCOMPLETE;
                ctx->ees = EES_INCOMPLETE_CHAR;
            }
        }
    }

    return rv;
}

/* xlate_out_filter() handles (almost) arbitrary conversions from one charset
 * to another...
 * translation is determined in the fixup hook (find_code_page), which is
 * where the filter's context data is set up... the context data gives us
 * the translation handle
 */
static apr_status_t xlate_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    charset_req_t *reqinfo = ap_get_module_config(f->r->request_config,
                                                  &charset_lite_module);
    charset_dir_t *dc = ap_get_module_config(f->r->per_dir_config,
                                             &charset_lite_module);
    charset_filter_ctx_t *ctx = f->ctx;
    apr_bucket *dptr, *consumed_bucket;
    const char *cur_str;
    apr_size_t cur_len, cur_avail;
    char tmp[OUTPUT_XLATE_BUF_SIZE];
    apr_size_t space_avail;
    int done;
    apr_status_t rv = APR_SUCCESS;

    if (!ctx) {
        /* this is SetOutputFilter path; grab the preallocated context,
         * if any; note that if we decided not to do anything in an earlier
         * handler, we won't even have a reqinfo
         */
        if (reqinfo) {
            ctx = f->ctx = reqinfo->output_ctx;
            reqinfo->output_ctx = NULL; /* prevent SNAFU if user coded us twice
                                         * in the filter chain; we can't have two
                                         * instances using the same context
                                         */
        }
        if (!ctx) {                   /* no idea how to translate; don't do anything */
            ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(charset_filter_ctx_t));
            ctx->dc = dc;
            ctx->noop = 1;
        }
    }

    /* Check the mime type to see if translation should be performed.
     */
    if (!ctx->noop && ctx->xlate == NULL) {
        const char *mime_type = f->r->content_type;

        if (mime_type && (strncasecmp(mime_type, "text/", 5) == 0 ||
#if APR_CHARSET_EBCDIC
        /* On an EBCDIC machine, be willing to translate mod_autoindex-
         * generated output.  Otherwise, it doesn't look too cool.
         *
         * XXX This isn't a perfect fix because this doesn't trigger us
         * to convert from the charset of the source code to ASCII.  The
         * general solution seems to be to allow a generator to set an
         * indicator in the r specifying that the body is coded in the
         * implementation character set (i.e., the charset of the source
         * code).  This would get several different types of documents
         * translated properly: mod_autoindex output, mod_status output,
         * mod_info output, hard-coded error documents, etc.
         */
            strcmp(mime_type, DIR_MAGIC_TYPE) == 0 ||
#endif
            strncasecmp(mime_type, "message/", 8) == 0 ||
            dc->force_xlate == FX_FORCE)) {

            rv = apr_xlate_open(&ctx->xlate,
                                dc->charset_default, dc->charset_source, f->r->pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01453)
                              "can't open translation %s->%s",
                              dc->charset_source, dc->charset_default);
                ctx->noop = 1;
            }
            else {
                if (apr_xlate_sb_get(ctx->xlate, &ctx->is_sb) != APR_SUCCESS) {
                    ctx->is_sb = 0;
                }
            }
        }
        else {
            ctx->noop = 1;
            if (mime_type) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE6, 0, f->r,
                              "mime type is %s; no translation selected",
                              mime_type);
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE6, 0, f->r,
                  "xlate_out_filter() - "
                  "charset_source: %s charset_default: %s",
                  dc && dc->charset_source ? dc->charset_source : "(none)",
                  dc && dc->charset_default ? dc->charset_default : "(none)");

    if (!ctx->ran) {  /* filter never ran before */
        chk_filter_chain(f);
        ctx->ran = 1;
        if (!ctx->noop && !ctx->is_sb) {
            /* We're not converting between two single-byte charsets, so unset
             * Content-Length since it is unlikely to remain the same.
             */
            apr_table_unset(f->r->headers_out, "Content-Length");
        }
    }

    if (ctx->noop) {
        return ap_pass_brigade(f->next, bb);
    }

    dptr = APR_BRIGADE_FIRST(bb);
    done = 0;
    cur_len = 0;
    space_avail = sizeof(tmp);
    consumed_bucket = NULL;
    while (!done) {
        if (!cur_len) { /* no bytes left to process in the current bucket... */
            if (consumed_bucket) {
                apr_bucket_delete(consumed_bucket);
                consumed_bucket = NULL;
            }
            if (dptr == APR_BRIGADE_SENTINEL(bb)) {
                break;
            }
            if (APR_BUCKET_IS_EOS(dptr)) {
                cur_len = -1; /* XXX yuck, but that tells us to send
                                 * eos down; when we minimize our bb construction
                                 * we'll fix this crap */
                if (ctx->saved) {
                    /* Oops... we have a partial char from the previous bucket
                     * that won't be completed because there's no more data.
                     */
                    rv = APR_INCOMPLETE;
                    ctx->ees = EES_INCOMPLETE_CHAR;
                }
                break;
            }
            if (APR_BUCKET_IS_METADATA(dptr)) {
                apr_bucket *metadata_bucket;
                metadata_bucket = dptr;
                dptr = APR_BUCKET_NEXT(dptr);
                APR_BUCKET_REMOVE(metadata_bucket);
                rv = send_bucket_downstream(f, metadata_bucket);
                if (rv != APR_SUCCESS) {
                    done = 1;
                }
                continue;
            }
            rv = apr_bucket_read(dptr, &cur_str, &cur_len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                ctx->ees = EES_BUCKET_READ;
                break;
            }
            consumed_bucket = dptr; /* for axing when we're done reading it */
            dptr = APR_BUCKET_NEXT(dptr); /* get ready for when we access the
                                          * next bucket */
        }
        /* Try to fill up our tmp buffer with translated data. */
        cur_avail = cur_len;

        if (cur_len) { /* maybe we just hit the end of a pipe (len = 0) ? */
            if (ctx->saved) {
                /* Rats... we need to finish a partial character from the previous
                 * bucket.
                 */
                char *tmp_tmp;

                tmp_tmp = tmp + sizeof(tmp) - space_avail;
                rv = finish_partial_char(ctx,
                                         &cur_str, &cur_len,
                                         &tmp_tmp, &space_avail);
            }
            else {
                rv = apr_xlate_conv_buffer(ctx->xlate,
                                           cur_str, &cur_avail,
                                           tmp + sizeof(tmp) - space_avail, &space_avail);

                /* Update input ptr and len after consuming some bytes */
                cur_str += cur_len - cur_avail;
                cur_len = cur_avail;

                if (rv == APR_INCOMPLETE) { /* partial character at end of input */
                    /* We need to save the final byte(s) for next time; we can't
                     * convert it until we look at the next bucket.
                     */
                    rv = set_aside_partial_char(ctx, cur_str, cur_len);
                    cur_len = 0;
                }
            }
        }

        if (rv != APR_SUCCESS) {
            /* bad input byte or partial char too big to store */
            done = 1;
        }

        if (space_avail < XLATE_MIN_BUFF_LEFT) {
            /* It is time to flush, as there is not enough space left in the
             * current output buffer to bother with converting more data.
             */
            rv = send_downstream(f, tmp, sizeof(tmp) - space_avail);
            if (rv != APR_SUCCESS) {
                done = 1;
            }

            /* tmp is now empty */
            space_avail = sizeof(tmp);
        }
    }

    if (rv == APR_SUCCESS) {
        if (space_avail < sizeof(tmp)) { /* gotta write out what we converted */
            rv = send_downstream(f, tmp, sizeof(tmp) - space_avail);
        }
    }
    if (rv == APR_SUCCESS) {
        if (cur_len == -1) {
            rv = send_eos(f);
        }
    }
    else {
        log_xlate_error(f, rv);
    }

    return rv;
}

static apr_status_t xlate_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                    ap_input_mode_t mode, apr_read_type_e block,
                                    apr_off_t readbytes)
{
    apr_status_t rv;
    charset_req_t *reqinfo = ap_get_module_config(f->r->request_config,
                                                  &charset_lite_module);
    charset_dir_t *dc = ap_get_module_config(f->r->per_dir_config,
                                             &charset_lite_module);
    charset_filter_ctx_t *ctx = f->ctx;
    apr_size_t buffer_size;
    int hit_eos;

    if (!ctx) {
        /* this is SetInputFilter path; grab the preallocated context,
         * if any; note that if we decided not to do anything in an earlier
         * handler, we won't even have a reqinfo
         */
        if (reqinfo) {
            ctx = f->ctx = reqinfo->input_ctx;
            reqinfo->input_ctx = NULL; /* prevent SNAFU if user coded us twice
                                        * in the filter chain; we can't have two
                                        * instances using the same context
                                        */
        }
        if (!ctx) {                   /* no idea how to translate; don't do anything */
            ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(charset_filter_ctx_t));
            ctx->dc = dc;
            ctx->noop = 1;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE6, 0, f->r,
                 "xlate_in_filter() - "
                 "charset_source: %s charset_default: %s",
                 dc && dc->charset_source ? dc->charset_source : "(none)",
                 dc && dc->charset_default ? dc->charset_default : "(none)");

    if (!ctx->ran) {  /* filter never ran before */
        chk_filter_chain(f);
        ctx->ran = 1;
        if (!ctx->noop && !ctx->is_sb
            && apr_table_get(f->r->headers_in, "Content-Length")) {
            /* A Content-Length header is present, but it won't be valid after
             * conversion because we're not converting between two single-byte
             * charsets.  This will affect most CGI scripts and may affect
             * some modules.
             * Content-Length can't be unset here because that would break
             * being able to read the request body.
             * Processing of chunked request bodies is not impacted by this
             * filter since the the length was not declared anyway.
             */
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, f->r,
                          "Request body length may change, resulting in "
                          "misprocessing by some modules or scripts");
        }
    }

    if (ctx->noop) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        if ((rv = ap_get_brigade(f->next, bb, mode, block,
                                 readbytes)) != APR_SUCCESS) {
            return rv;
        }
    }
    else {
        APR_BRIGADE_PREPEND(bb, ctx->bb); /* first use the leftovers */
    }

    buffer_size = INPUT_XLATE_BUF_SIZE;
    rv = xlate_brigade(ctx, bb, ctx->tmp, &buffer_size, &hit_eos);
    if (rv == APR_SUCCESS) {
        if (!hit_eos) {
            /* move anything leftover into our context for next time;
             * we don't currently "set aside" since the data came from
             * down below, but I suspect that for long-term we need to
             * do that
             */
            APR_BRIGADE_CONCAT(ctx->bb, bb);
        }
        if (buffer_size < INPUT_XLATE_BUF_SIZE) { /* do we have output? */
            apr_bucket *e;

            e = apr_bucket_heap_create(ctx->tmp,
                                       INPUT_XLATE_BUF_SIZE - buffer_size,
                                       NULL, f->r->connection->bucket_alloc);
            /* make sure we insert at the head, because there may be
             * an eos bucket already there, and the eos bucket should
             * come after the data
             */
            APR_BRIGADE_INSERT_HEAD(bb, e);
        }
        else {
            /* XXX need to get some more data... what if the last brigade
             * we got had only the first byte of a multibyte char?  we need
             * to grab more data from the network instead of returning an
             * empty brigade
             */
        }
        /* If we have any metadata at the head of ctx->bb, go ahead and move it
         * onto the end of bb to be returned to our caller.
         */
        if (!APR_BRIGADE_EMPTY(ctx->bb)) {
            apr_bucket *b = APR_BRIGADE_FIRST(ctx->bb);
            while (b != APR_BRIGADE_SENTINEL(ctx->bb)
                   && APR_BUCKET_IS_METADATA(b)) {
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(bb, b);
                b = APR_BRIGADE_FIRST(ctx->bb);
            }
        }
    }
    else {
        log_xlate_error(f, rv);
    }

    return rv;
}

static const command_rec cmds[] =
{
    AP_INIT_TAKE1("CharsetSourceEnc",
                  add_charset_source,
                  NULL,
                  OR_FILEINFO,
                  "source (html,cgi,ssi) file charset"),
    AP_INIT_TAKE1("CharsetDefault",
                  add_charset_default,
                  NULL,
                  OR_FILEINFO,
                  "name of default charset"),
    AP_INIT_ITERATE("CharsetOptions",
                    add_charset_options,
                    NULL,
                    OR_FILEINFO,
                    "valid options: ImplicitAdd, NoImplicitAdd, TranslateAllMimeTypes, "
                    "NoTranslateAllMimeTypes"),
    {NULL}
};

static void charset_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(find_code_page, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_filter(xlate_insert_filter, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_register_output_filter(XLATEOUT_FILTER_NAME, xlate_out_filter, NULL,
                              AP_FTYPE_RESOURCE);
    ap_register_input_filter(XLATEIN_FILTER_NAME, xlate_in_filter, NULL,
                             AP_FTYPE_RESOURCE);
}

AP_DECLARE_MODULE(charset_lite) =
{
    STANDARD20_MODULE_STUFF,
    create_charset_dir_conf,
    merge_charset_dir_conf,
    NULL,
    NULL,
    cmds,
    charset_register_hooks
};

