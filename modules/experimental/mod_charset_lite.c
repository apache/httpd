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

#define XLATEOUT_FILTER_NAME "XLATEOUT" /* registered name of the translation filter */

typedef struct charset_dir_t {
    enum {NO_DEBUG = 1, DEBUG} debug; /* whether or not verbose logging is enabled; 0
                                        means uninitialized */
    const char *charset_source; /* source encoding */
    const char *charset_default; /* how to ship on wire */
    enum {IA_INIT, IA_IMPADD, IA_NOIMPADD} implicit_add; /* tmp hack! module does ap_add_filter()? */
} charset_dir_t;

/* charset_filter_ctx_t is created for each filter instance; because the same
 * filter code is used for translating in both directions, we need this context
 * data to tell the filter which translation handle to use; it also can hold a
 * character which was split between buckets
 */
typedef struct charset_filter_ctx_t {
    apr_xlate_t *xlate;
    ees_t ees;              /* extended error status */
    apr_ssize_t saved;
    char buf[FATTEST_CHAR]; /* we want to be able to build a complete char here */
} charset_filter_ctx_t;

/* charset_req_t is available via r->request_config if any translation is
 * being performed
 */
typedef struct charset_req_t {
    charset_dir_t *dc;
    charset_filter_ctx_t *output_ctx, *input_ctx;
} charset_req_t;

module charset_lite_module;

static void *create_charset_dir_conf(apr_pool_t *p,char *dummy)
{
  return apr_pcalloc(p,sizeof(charset_dir_t));
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
        over->debug ? over->debug : base->debug;
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

/* CharsetDebug on/off
 */
static const char *add_charset_debug(cmd_parms *cmd, void *in_dc, int arg)
{
    charset_dir_t *dc = in_dc;

    if (arg) {
        dc->debug = DEBUG;
    }
    else {
        dc->debug = NO_DEBUG;
    }

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
    int debug = dc->debug == DEBUG;

    if (debug) {
        ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                     "Entering handler, URI: %s FILENAME: %s METHOD: %d ARGS: %s PATH_INFO: %s "
                     "MIMETYPE: %s FLAGS: %d SUBREQ: %s, REDIR: %s, PROXY: %s",
                     r->uri, r->filename, r->method_number, r->args, r->path_info, 
                     r->content_type ? r->content_type : "(unknown)",
                     r->rrx ? 1 : 0,
                     r->main?"YES":"NO",r->prev?"YES":"NO",
                     r->proxyreq ? "YES" : "NO");
    }

    /* If we don't have a full directory configuration, bail out.
     */
    if (!dc->charset_source || !dc->charset_default) {
        if (debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
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
    if (strncasecmp(mime_type, "text/", 5) &&
        strncasecmp(mime_type, "message/", 8)) {
        if (debug) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                         "mime type is %s; no translation selected",
                         mime_type);
        }
        return DECLINED;
    }

    if (debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                     "dc: %X charset_source: %s charset_default: %s",
                     (unsigned)dc,
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
    ap_set_module_config(r->request_config, &charset_lite_module, reqinfo);

    reqinfo->output_ctx = output_ctx;
    rv = apr_xlate_open(&output_ctx->xlate, 
                        dc->charset_default, dc->charset_source, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
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
        reqinfo->input_ctx = input_ctx;
        rv = apr_xlate_open(&input_ctx->xlate, dc->charset_source, 
                            dc->charset_default, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                         "can't open translation %s->%s",
                         dc->charset_default, dc->charset_source);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

/* Can't delete this yet :( #ifdef OLD */
        rv = ap_set_content_xlate(r, 0, input_ctx->xlate);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                         "can't set content input translation");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
/* #endif */
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
    int debug = dc->debug == DEBUG;

    if (debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
                     "xlate_insert_filter() - "
                     "dc: %X charset_source: %s charset_default: %s",
                     (unsigned)dc,
                     dc && dc->charset_source ? dc->charset_source : "(none)",
                     dc && dc->charset_default ? dc->charset_default : "(none)");
    }

    if (reqinfo && 
        dc->implicit_add == IA_IMPADD &&
        reqinfo->output_ctx) {
        ap_add_filter(XLATEOUT_FILTER_NAME, reqinfo->output_ctx, r);
    }
    
#ifdef NOT_YET /* no input filters yet; we still rely on BUFF */
    if (reqinfo && 
        dc->implicit_add == IA_IMPADD &&
        reqinfo->input_ctx) {
        /* ap_add_filter(XLATEIN_FILTER_NAME, reqinfo->input_ctx, r); */
    }
#endif
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
        msg = "xlate_filter() - a built-in restriction was encountered";
        break;
    case EES_BAD_INPUT:
        msg = "xlate_filter() - an input character was invalid";
        break;
    case EES_BUCKET_READ:
        msg = "xlate_filter() - bucket read routine failed";
        break;
    case EES_INCOMPLETE_CHAR:
        strcpy(msgbuf, "xlate_filter() - incomplete char at end of input - ");
        cur = 0;
        while (cur < ctx->saved) {
            apr_snprintf(msgbuf + strlen(msgbuf), sizeof(msgbuf) - strlen(msgbuf), 
                         "%02X", (unsigned)ctx->buf[cur]);
            ++cur;
        }
        msg = msgbuf;
        break;
    default:
        msg = "xlate_filter() - returning error";
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, rv, f->r,
                  "%s", msg);
}

/* xlate_filter() handles (almost) arbitrary conversions from one charset 
 * to another...
 * translation is determined in the fixup hook (find_code_page), which is
 * where the filter's context data is set up... the context data gives us
 * the translation handle
 */
static apr_status_t xlate_filter(ap_filter_t *f, ap_bucket_brigade *bb)
{
    charset_req_t *reqinfo = ap_get_module_config(f->r->request_config,
                                                  &charset_lite_module);
    charset_dir_t *dc = reqinfo->dc;
    charset_filter_ctx_t *ctx = f->ctx;
    int debug = dc->debug == DEBUG;
    ap_bucket *dptr, *consumed_bucket;
    const char *cur_str;
    apr_ssize_t cur_len, cur_avail;
    char tmp[XLATE_BUF_SIZE];
    apr_ssize_t space_avail;
    int done;
    apr_status_t rv = APR_SUCCESS;

    if (!ctx) { /* this is AddOutputFilter path */
        ap_assert(dc->implicit_add == IA_NOIMPADD); 
        if (!strcmp(f->frec->name, XLATEOUT_FILTER_NAME)) {
            ctx = f->ctx = reqinfo->output_ctx;
        }
        else {
            ap_assert(1 != 1);
        }
    }

    if (debug) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, f->r->server,
                     "xlate_filter() - "
                     "dc: %X charset_source: %s charset_default: %s",
                     (unsigned)dc,
                     dc && dc->charset_source ? dc->charset_source : "(none)",
                     dc && dc->charset_default ? dc->charset_default : "(none)");
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
            if (dptr->type == AP_BUCKET_EOS) {
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
            rv = dptr->read(dptr, &cur_str, &cur_len, 0);
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
    AP_INIT_FLAG("CharsetDebug",
                 add_charset_debug,
                 NULL,
                 OR_FILEINFO,
                 "mod_charset_lite debug flag"),
    AP_INIT_ITERATE("CharsetOptions",
                    add_charset_options,
                    NULL,
                    OR_FILEINFO,
                    "valid options: ImplicitAdd, NoImplicitAdd"),
    {NULL}
};

static void charset_register_hooks(void)
{
    ap_hook_fixups(find_code_page, NULL, NULL, AP_HOOK_MIDDLE);
    ap_hook_insert_filter(xlate_insert_filter, NULL, NULL, AP_HOOK_MIDDLE);
    ap_register_output_filter(XLATEOUT_FILTER_NAME, xlate_filter, AP_FTYPE_CONTENT);
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

