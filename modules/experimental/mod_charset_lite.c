/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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
#include "ap_buckets.h"
#include "util_filter.h"
#include "apr_strings.h"

#ifndef APACHE_XLATE
#error mod_charset_lite cannot work without APACHE_XLATE enabled
#endif

#define XLATE_BUF_SIZE (16*1024) /* we try to send down brigades of this len, but... */
#define XLATE_MIN_BUFF_LEFT 128  /* flush once there is no more than this much
                                  * space is left in the translation buffer 
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
    EES_BAD_INPUT   /* input data invalid */
} ees_t;

/* registered name of the output translation filter */
#define XLATEOUT_FILTER_NAME "XLATEOUT"
/* registered name of input translation filter */
#define XLATEIN_FILTER_NAME  "XLATEIN" 

typedef struct charset_dir_t {
    /** debug level; -1 means uninitialized, 0 means no debug */
    int debug;
    const char *charset_source; /* source encoding */
    const char *charset_default; /* how to ship on wire */
    /** module does ap_add_*_filter()? */    
    enum {IA_INIT, IA_IMPADD, IA_NOIMPADD} implicit_add; 
} charset_dir_t;

/* charset_filter_ctx_t is created for each filter instance; because the same
 * filter code is used for translating in both directions, we need this context
 * data to tell the filter which translation handle to use; it also can hold a
 * character which was split between buckets
 */
typedef struct charset_filter_ctx_t {
    apr_xlate_t *xlate;
    charset_dir_t *dc;
    ees_t ees;              /* extended error status */
    apr_ssize_t saved;
    char buf[FATTEST_CHAR]; /* we want to be able to build a complete char here */
    int ran;                /* has filter instance run before? */
    int noop;               /* should we pass brigades through unchanged? */
    char *tmp;              /* buffer for input filtering */
} charset_filter_ctx_t;

#define INPUT_BUFFER_SIZE     16384    /* real big because we don't handle running out of space now :) */

/* charset_req_t is available via r->request_config if any translation is
 * being performed
 */
typedef struct charset_req_t {
    charset_dir_t *dc;
    charset_filter_ctx_t *output_ctx, *input_ctx;
} charset_req_t;

/* debug level definitions */
#define DBGLVL_GORY           9 /* gory details */
#define DBGLVL_FLOW           4 /* enough messages to see what happens on
                                 * each request */
#define DBGLVL_PMC            2 /* messages about possible misconfiguration */

module charset_lite_module;

static void *create_charset_dir_conf(apr_pool_t *p,char *dummy)
{
    charset_dir_t *dc = (charset_dir_t *)apr_pcalloc(p,sizeof(charset_dir_t));

    dc->debug = -1;
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

    a->debug = 
        over->debug != -1 ? over->debug : base->debug;
    a->charset_default = 
        over->charset_default ? over->charset_default : base->charset_default;
    a->charset_source = 
        over->charset_source ? over->charset_source : base->charset_source;
    a->implicit_add =
        over->implicit_add != IA_INIT ? over->implicit_add : base->implicit_add;
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
    else if (!strncasecmp(flag, "DebugLevel=", 11)) {
        dc->debug = atoi(flag + 11);
    }
    else {
        return apr_pstrcat(cmd->temp_pool, 
                           "Invalid CharsetOptions option: ",
                           flag,
                           NULL);
    }

    return NULL;
}

/* find_code_page() is a fixup hook that decides if translation should be
 * enabled; if so, it sets up request data for use by the filter registration
 * hook so that it knows what to do
 */
static int find_code_page(request_rec *r)
{
    charset_dir_t *dc = ap_get_module_config(r->per_dir_config, 
                                             &charset_lite_module);
    charset_req_t *reqinfo;
    charset_filter_ctx_t *input_ctx, *output_ctx;
    apr_status_t rv;
    const char *mime_type;

    if (dc->debug >= DBGLVL_FLOW) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                      "uri: %s file: %s method: %d "
                      "imt: %s flags: %s%s%s %s->%s",
                      r->uri, r->filename, r->method_number,
                      r->content_type ? r->content_type : "(unknown)",
                      r->main     ? "S" : "",    /* S if subrequest */
                      r->prev     ? "R" : "",    /* R if redirect */
                      r->proxyreq ? "P" : "",    /* P if proxy */
                      dc->charset_source, dc->charset_default);
    }

    /* If we don't have a full directory configuration, bail out.
     */
    if (!dc->charset_source || !dc->charset_default) {
        if (dc->debug >= DBGLVL_PMC) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                          "incomplete configuration: src %s, dst %s",
                          dc->charset_source ? dc->charset_source : "unspecified",
                          dc->charset_default ? dc->charset_default : "unspecified");
        }
        return DECLINED;
    }

    /* catch proxy requests */
    if (r->proxyreq) return DECLINED;
    /* mod_rewrite indicators */
    if (!strncmp(r->filename, "redirect:", 9)) return DECLINED; 
    if (!strncmp(r->filename, "gone:", 5)) return DECLINED; 
    if (!strncmp(r->filename, "passthrough:", 12)) return DECLINED; 
    if (!strncmp(r->filename, "forbidden:", 10)) return DECLINED; 
    
    mime_type = r->content_type ? r->content_type : ap_default_type(r);

    /* If mime type isn't text or message, bail out.
     */

/* XXX When we handle translation of the request body, watch out here as
 *     1.3 allowed additional mime types: multipart and 
 *     application/x-www-form-urlencoded
 */
             
    if (strncasecmp(mime_type, "text/", 5) &&
        strncasecmp(mime_type, "message/", 8)) {
        if (dc->debug >= DBGLVL_GORY) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                          "mime type is %s; no translation selected",
                          mime_type);
        }
        return DECLINED;
    }

    if (dc->debug >= DBGLVL_GORY) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                      "charset_source: %s charset_default: %s",
                      dc && dc->charset_source ? dc->charset_source : "(none)",
                      dc && dc->charset_default ? dc->charset_default : "(none)");
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
    ap_set_module_config(r->request_config, &charset_lite_module, reqinfo);

    reqinfo->output_ctx = output_ctx;
    rv = apr_xlate_open(&output_ctx->xlate, 
                        dc->charset_default, dc->charset_source, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "can't open translation %s->%s",
                      dc->charset_source, dc->charset_default);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    switch (r->method_number) {
    case M_PUT:
    case M_POST:
        /* Set up input translation.  Note: A request body can be included 
         * with the OPTIONS method, but for now we don't set up translation 
         * of it.
         */
        input_ctx = apr_pcalloc(r->pool, sizeof(charset_filter_ctx_t));
        input_ctx->dc = dc;
        reqinfo->input_ctx = input_ctx;
        rv = apr_xlate_open(&input_ctx->xlate, dc->charset_source, 
                            dc->charset_default, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "can't open translation %s->%s",
                          dc->charset_default, dc->charset_source);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return DECLINED;
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

    if (dc->debug >= DBGLVL_GORY) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                      "xlate_insert_filter() - "
                      "charset_source: %s charset_default: %s "
                      "impadd %d",
                      dc && dc->charset_source ? dc->charset_source : "(none)",
                      dc && dc->charset_default ? dc->charset_default : "(none)",
                      (int)dc->implicit_add);
    }

    if (reqinfo && 
        dc->implicit_add == IA_IMPADD) {
        if (reqinfo->output_ctx) {
            ap_add_output_filter(XLATEOUT_FILTER_NAME, reqinfo->output_ctx, r, 
                                 r->connection);
        }
        if (reqinfo->input_ctx) {
            ap_add_input_filter(XLATEIN_FILTER_NAME, reqinfo->input_ctx, r,
                                r->connection);
        }
    }
}

/* stuff that sucks that I know of:
 *
 * bucket handling:
 *  why create an eos bucket when we see it come down the stream?  just send the one
 *  passed as input
 *
 * translation mechanics:
 *   we don't handle characters that straddle more than two buckets; an error
 *   will be generated
 */

/* send_downstream() is passed the translated data; it puts it in a single-
 * bucket brigade and passes the brigade to the next filter
 */
static apr_status_t send_downstream(ap_filter_t *f, const char *tmp, apr_ssize_t len)
{
    ap_bucket_brigade *bb;
    ap_bucket *b;

    bb = ap_brigade_create(f->r->pool);
    b = ap_bucket_create_transient(tmp, len);
    AP_BRIGADE_INSERT_TAIL(bb, b);
    return ap_pass_brigade(f->next, bb);
}

static apr_status_t send_eos(ap_filter_t *f)
{
    ap_bucket_brigade *bb;
    ap_bucket *b;

    bb = ap_brigade_create(f->r->pool);
    b = ap_bucket_create_eos();
    AP_BRIGADE_INSERT_TAIL(bb, b);
    return ap_pass_brigade(f->next, bb);
}

static apr_status_t set_aside_partial_char(ap_filter_t *f, const char *partial,
                                           apr_ssize_t partial_len)
{
    charset_filter_ctx_t *ctx = f->ctx;
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

static apr_status_t finish_partial_char(ap_filter_t *f,
                                        charset_req_t *reqinfo,
                                        /* input buffer: */
                                        const char **cur_str, 
                                        apr_ssize_t *cur_len,
                                        /* output buffer: */
                                        char **out_str,
                                        apr_ssize_t *out_len)
{
    apr_status_t rv;
    charset_filter_ctx_t *ctx = f->ctx;
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
        ctx->ees = EES_LIMIT; /* code isn't smart enough to handle chars '
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
    int cur;

    switch(ctx->ees) {
    case EES_LIMIT:
        msg = "xlate filter - a built-in restriction was encountered";
        break;
    case EES_BAD_INPUT:
        msg = "xlate filter - an input character was invalid";
        break;
    case EES_BUCKET_READ:
        msg = "xlate filter - bucket read routine failed";
        break;
    case EES_INCOMPLETE_CHAR:
        strcpy(msgbuf, "xlate filter - incomplete char at end of input - ");
        cur = 0;
        while (cur < ctx->saved) {
            apr_snprintf(msgbuf + strlen(msgbuf), sizeof(msgbuf) - strlen(msgbuf), 
                         "%02X", (unsigned)ctx->buf[cur]);
            ++cur;
        }
        msg = msgbuf;
        break;
    default:
        msg = "xlate filter - returning error";
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, rv, f->r,
                  "%s", msg);
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
    charset_filter_ctx_t *curctx, *last_xlate_ctx = NULL;
    int debug = ((charset_filter_ctx_t *)f->ctx)->dc->debug;
    int output = !strcasecmp(f->frec->name, XLATEOUT_FILTER_NAME);

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
                if (strcasecmp(last_xlate_ctx->dc->charset_default,
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
                        if (debug >= DBGLVL_PMC) {
                            const char *symbol = output ? "->" : "<-";

                            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO,
                                          0, f->r,
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

                        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO,
                                      0, f->r,
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
 */

static apr_status_t xlate_brigade(ap_filter_t *f, 
                                  charset_req_t *reqinfo,
                                  charset_dir_t *dc,
                                  ap_bucket_brigade *bb,
                                  char *buffer, 
                                  apr_size_t *buffer_size,
                                  int output)
{
    charset_filter_ctx_t *ctx = f->ctx;
    ap_bucket *dptr, *consumed_bucket;
    const char *cur_str;
    apr_ssize_t cur_len, cur_bucket_len, cur_avail;
    apr_ssize_t space_avail;
    int done;
    apr_status_t rv = APR_SUCCESS;

    dptr = AP_BRIGADE_FIRST(bb);
    done = 0;
    cur_len = 0;
    space_avail = *buffer_size;
    consumed_bucket = NULL;
    while (!done) {
        if (!cur_len) { /* no bytes left to process in the current bucket... */
            if (consumed_bucket) {
                AP_BUCKET_REMOVE(consumed_bucket);
                ap_bucket_destroy(consumed_bucket);
                consumed_bucket = NULL;
            }
            if (dptr == AP_BRIGADE_SENTINEL(bb)) {
                done = 1;
                break;
            }
            if (AP_BUCKET_IS_EOS(dptr)) {
                done = 1;
                cur_len = AP_END_OF_BRIGADE; /* XXX yuck, but that tells us to send
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
            rv = ap_bucket_read(dptr, &cur_str, &cur_len, 0);
            if (rv != APR_SUCCESS) {
                done = 1;
                ctx->ees = EES_BUCKET_READ;
                break;
            }
            cur_bucket_len = cur_len;
            consumed_bucket = dptr; /* for axing when we're done reading it */
            dptr = AP_BUCKET_NEXT(dptr); /* get ready for when we access the 
                                          * next bucket */
        }
        /* Try to fill up our buffer with translated data. */
        cur_avail = cur_len;

        if (cur_len) { /* maybe we just hit the end of a pipe (len = 0) ? */
            if (ctx->saved) {
                /* Rats... we need to finish a partial character from the previous
                 * bucket.
                 */
                char *tmp_tmp;
                
                tmp_tmp = buffer + *buffer_size - space_avail;
                rv = finish_partial_char(f, reqinfo, 
                                         &cur_str, &cur_len,
                                         &tmp_tmp, &space_avail);
            }
            else {
                rv = apr_xlate_conv_buffer(ctx->xlate,
                                           cur_str, &cur_avail,
                                           buffer + *buffer_size - space_avail, 
                                           &space_avail);
                
                /* Update input ptr and len after consuming some bytes */
                cur_str += cur_len - cur_avail;
                cur_len = cur_avail;
                
                if (rv == APR_INCOMPLETE) { /* partial character at end of input */
                    /* We need to save the final byte(s) for next time; we can't
                     * convert it until we look at the next bucket.
                     */
                    rv = set_aside_partial_char(f, cur_str, cur_len);
                    cur_len = 0;
                }
            }
        }

        if (rv != APR_SUCCESS) {
            /* bad input byte or partial char too big to store */
            done = 1;
        }

        if (space_avail < XLATE_MIN_BUFF_LEFT) {
            if (output) {
                /* It is time to flush, as there is not enough space left in the
                 * current output buffer to bother with converting more data.
                 */
                rv = send_downstream(f, buffer, *buffer_size - space_avail);
                if (rv != APR_SUCCESS) {
                    done = 1;
                }
            
                /* the buffer is now empty */
                space_avail = *buffer_size;
            }
            else {
                /* if any data remains in the current bucket, split there */
                if (cur_len) {
                    ap_assert(1 != 1);
                }
                break;
            }
        }
    }
    if (!output) {
        /* tell caller how many bytes are now in the buffer */
        *buffer_size = space_avail;
    }
    return rv;
}

/* xlate_out_filter() handles (almost) arbitrary conversions from one charset 
 * to another...
 * translation is determined in the fixup hook (find_code_page), which is
 * where the filter's context data is set up... the context data gives us
 * the translation handle
 */
static apr_status_t xlate_out_filter(ap_filter_t *f, ap_bucket_brigade *bb)
{
    charset_req_t *reqinfo = ap_get_module_config(f->r->request_config,
                                                  &charset_lite_module);
    charset_dir_t *dc = reqinfo->dc;
    charset_filter_ctx_t *ctx = f->ctx;
    ap_bucket *dptr, *consumed_bucket;
    const char *cur_str;
    apr_ssize_t cur_len, cur_avail;
    char tmp[XLATE_BUF_SIZE];
    apr_ssize_t space_avail;
    int done;
    apr_status_t rv = APR_SUCCESS;

    if (!ctx) { 
        /* this is AddOutputFilter path */
        AP_DEBUG_ASSERT(dc->implicit_add == IA_NOIMPADD); 
        if (!strcmp(f->frec->name, XLATEOUT_FILTER_NAME)) {
            ctx = f->ctx = reqinfo->output_ctx;
        }
        else {
            ap_assert(1 != 1);
        }
    }

    if (dc->debug >= DBGLVL_GORY) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, f->r,
                     "xlate_out_filter() - "
                     "charset_source: %s charset_default: %s",
                     dc && dc->charset_source ? dc->charset_source : "(none)",
                     dc && dc->charset_default ? dc->charset_default : "(none)");
    }

    if (!ctx->ran) {  /* filter never ran before */
        chk_filter_chain(f);
        ctx->ran = 1;
    }

    if (ctx->noop) {
        return ap_pass_brigade(f->next, bb);
    }

    dptr = AP_BRIGADE_FIRST(bb);
    done = 0;
    cur_len = 0;
    space_avail = sizeof(tmp);
    consumed_bucket = NULL;
    while (!done) {
        if (!cur_len) { /* no bytes left to process in the current bucket... */
            if (consumed_bucket) {
                AP_BUCKET_REMOVE(consumed_bucket);
                ap_bucket_destroy(consumed_bucket);
                consumed_bucket = NULL;
            }
            if (dptr == AP_BRIGADE_SENTINEL(bb)) {
                done = 1;
                break;
            }
            if (AP_BUCKET_IS_EOS(dptr)) {
                done = 1;
                cur_len = AP_END_OF_BRIGADE; /* XXX yuck, but that tells us to send
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
            rv = ap_bucket_read(dptr, &cur_str, &cur_len, 0);
            if (rv != APR_SUCCESS) {
                done = 1;
                ctx->ees = EES_BUCKET_READ;
                break;
            }
            consumed_bucket = dptr; /* for axing when we're done reading it */
            dptr = AP_BUCKET_NEXT(dptr); /* get ready for when we access the 
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
                rv = finish_partial_char(f, reqinfo, 
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
                    rv = set_aside_partial_char(f, cur_str, cur_len);
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
        if (cur_len == AP_END_OF_BRIGADE) {
            rv = send_eos(f);
        }
    }
    else {
        log_xlate_error(f, rv);
    }

    return rv;
}

static int xlate_in_filter(ap_filter_t *f, ap_bucket_brigade *bb, 
                           ap_input_mode_t mode)
{
    apr_status_t rv;
    charset_req_t *reqinfo = ap_get_module_config(f->r->request_config,
                                                  &charset_lite_module);
    charset_dir_t *dc = reqinfo->dc;
    charset_filter_ctx_t *ctx = f->ctx;
    apr_size_t buffer_size;

    if (!ctx) { /* this is AddInputFilter path */
        AP_DEBUG_ASSERT(dc->implicit_add == IA_NOIMPADD);
        if (!strcmp(f->frec->name, XLATEOUT_FILTER_NAME)) {
            ctx = f->ctx = reqinfo->output_ctx;
        }
        else {
            ap_assert(1 != 1);
        }
    }

    if (dc->debug >= DBGLVL_GORY) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, f->r,
                     "xlate_in_filter() - "
                     "charset_source: %s charset_default: %s",
                     dc && dc->charset_source ? dc->charset_source : "(none)",
                     dc && dc->charset_default ? dc->charset_default : "(none)");
    }

    if (!ctx->ran) {  /* filter never ran before */
        /* we don't chk_filter_chain(f) on input yet; it makes sense to 
         * do so to catch some incorrect configurations */
        ctx->ran = 1;
        ctx->tmp = apr_palloc(f->r->pool, INPUT_BUFFER_SIZE);
    }

    if ((rv = ap_get_brigade(f->next, bb, mode)) != APR_SUCCESS) {
        return rv;
    }

    if (ctx->noop) {
        return APR_SUCCESS;
    }

    buffer_size = INPUT_BUFFER_SIZE;
    rv = xlate_brigade(f, reqinfo, dc, bb, ctx->tmp, &buffer_size, 
                       0 /* input */);

    if (rv == APR_SUCCESS) {
        ap_bucket *e;

        e = ap_bucket_create_heap(ctx->tmp, 
                                  INPUT_BUFFER_SIZE - buffer_size, 1, 
                                  NULL);
        AP_BRIGADE_INSERT_HEAD(bb, e);
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
                    "valid options: ImplicitAdd, NoImplicitAdd, DebugLevel=n"),
    {NULL}
};

static void charset_register_hooks(void)
{
    ap_hook_fixups(find_code_page, NULL, NULL, AP_HOOK_MIDDLE);
    ap_hook_insert_filter(xlate_insert_filter, NULL, NULL, AP_HOOK_MIDDLE);
    ap_register_output_filter(XLATEOUT_FILTER_NAME, xlate_out_filter, 
                              AP_FTYPE_CONTENT);
    ap_register_input_filter(XLATEIN_FILTER_NAME, xlate_in_filter, 
                             AP_FTYPE_CONTENT);
}

module charset_lite_module =
{
    STANDARD20_MODULE_STUFF,
    create_charset_dir_conf,
    merge_charset_dir_conf,
    NULL, 
    NULL,
    cmds,
    NULL,
    charset_register_hooks,
};

