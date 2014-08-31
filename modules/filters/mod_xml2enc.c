/*      Copyright (c) 2007-11, WebThing Ltd
 *      Copyright (c) 2011-, The Apache Software Foundation
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

#if defined(WIN32)
#define XML2ENC_DECLARE_EXPORT
#endif

#include <ctype.h>

/* libxml2 */
#include <libxml/encoding.h>

#include "http_protocol.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_xlate.h"

#include "apr_optional.h"
#include "mod_xml2enc.h"

module AP_MODULE_DECLARE_DATA xml2enc_module;

#define BUFLEN 8192
#define BUF_MIN 4096
#define APR_BRIGADE_DO(b,bb) for (b = APR_BRIGADE_FIRST(bb); \
                                  b != APR_BRIGADE_SENTINEL(bb); \
                                  b = APR_BUCKET_NEXT(b))

#define ENC_INITIALISED 0x100
#define ENC_SEEN_EOS 0x200
#define ENC_SKIPTO ENCIO_SKIPTO

#define HAVE_ENCODING(enc) \
        (((enc)!=XML_CHAR_ENCODING_NONE)&&((enc)!=XML_CHAR_ENCODING_ERROR))

/*
 * XXX: Check all those ap_assert()s ans replace those that should not happen
 * XXX: with AP_DEBUG_ASSERT and those that may happen with proper error
 * XXX: handling.
 */
typedef struct {
    xmlCharEncoding xml2enc;
    char* buf;
    apr_size_t bytes;
    apr_xlate_t* convset;
    unsigned int flags;
    apr_off_t bblen;
    apr_bucket_brigade* bbnext;
    apr_bucket_brigade* bbsave;
    const char* encoding;
} xml2ctx;

typedef struct {
    const char* default_charset;
    xmlCharEncoding default_encoding;
    apr_array_header_t* skipto;
} xml2cfg;

typedef struct {
    const char* val;
} tattr;

static ap_regex_t* seek_meta_ctype;
static ap_regex_t* seek_charset;

static apr_status_t xml2enc_filter(request_rec* r, const char* enc,
                                   unsigned int mode)
{
    /* set up a ready-initialised ctx to convert to enc, and insert filter */
    apr_xlate_t* convset; 
    apr_status_t rv;
    unsigned int flags = (mode ^ ENCIO);
    if ((mode & ENCIO) == ENCIO_OUTPUT) {
        rv = apr_xlate_open(&convset, enc, "UTF-8", r->pool);
        flags |= ENC_INITIALISED;
    }
    else if ((mode & ENCIO) == ENCIO_INPUT) {
        rv = apr_xlate_open(&convset, "UTF-8", enc, r->pool);
        flags |= ENC_INITIALISED;
    }
    else if ((mode & ENCIO) == ENCIO_INPUT_CHECKS) {
        convset = NULL;
        rv = APR_SUCCESS; /* we'll initialise later by sniffing */
    }
    else {
        rv = APR_EGENERAL;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01426)
                      "xml2enc: bad mode %x", mode);
    }
    if (rv == APR_SUCCESS) {
        xml2ctx* ctx = apr_pcalloc(r->pool, sizeof(xml2ctx));
        ctx->flags = flags;
        if (flags & ENC_INITIALISED) {
            ctx->convset = convset;
            ctx->bblen = BUFLEN;
            ctx->buf = apr_palloc(r->pool, (apr_size_t)ctx->bblen);
        }
        ap_add_output_filter("xml2enc", ctx, r, r->connection);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01427)
                      "xml2enc: Charset %s not supported.", enc) ;
    }
    return rv;
}

/* This needs to operate only when we're using htmlParser */
/* Different modules may apply different rules here.  Ho, hum.  */
static void fix_skipto(request_rec* r, xml2ctx* ctx)
{
    apr_status_t rv;
    xml2cfg* cfg = ap_get_module_config(r->per_dir_config, &xml2enc_module);
    if ((cfg->skipto != NULL) && (ctx->flags | ENC_SKIPTO)) {
        int found = 0;
        char* p = ap_strchr(ctx->buf, '<');
        tattr* starts = (tattr*) cfg->skipto->elts;
        while (!found && p && *p) {
            int i;
            for (i = 0; i < cfg->skipto->nelts; ++i) {
                if (!strncasecmp(p+1, starts[i].val, strlen(starts[i].val))) {
                    /* found a starting element. Strip all that comes before. */
                    apr_bucket* b;
                    apr_bucket* bstart;
                    rv = apr_brigade_partition(ctx->bbsave, (p-ctx->buf),
                                               &bstart);
                    ap_assert(rv == APR_SUCCESS);
                    while (b = APR_BRIGADE_FIRST(ctx->bbsave), b != bstart) {
                        apr_bucket_delete(b);
                    }
                    ctx->bytes -= (p-ctx->buf);
                    ctx->buf = p ;
                    found = 1;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01428)
                                  "Skipped to first <%s> element",
                                  starts[i].val) ;
                    break;
                }
            }
            p = ap_strchr(p+1, '<');
        }
        if (p == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01429)
                          "Failed to find start of recognised HTML!");
        }
    }
}
static void sniff_encoding(request_rec* r, xml2ctx* ctx)
{
    xml2cfg* cfg = NULL; /* initialise to shut compiler warnings up */
    char* p ;
    apr_bucket* cutb;
    apr_bucket* cute;
    apr_bucket* b;
    ap_regmatch_t match[2] ;
    apr_status_t rv;
    const char* ctype = r->content_type;

    if (ctype) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01430)
                      "Content-Type is %s", ctype) ;

        /* If we've got it in the HTTP headers, there's nothing to do */
        if (ctype && (p = ap_strcasestr(ctype, "charset=") , p != NULL)) {
            p += 8 ;
            if (ctx->encoding = apr_pstrndup(r->pool, p, strcspn(p, " ;") ),
                ctx->encoding) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01431)
                              "Got charset %s from HTTP headers", ctx->encoding) ;
                ctx->xml2enc = xmlParseCharEncoding(ctx->encoding);
            }
        }
    }
  
    /* to sniff, first we look for BOM */
    if (ctx->xml2enc == XML_CHAR_ENCODING_NONE) {
        ctx->xml2enc = xmlDetectCharEncoding((const xmlChar*)ctx->buf,
                                             ctx->bytes); 
        if (HAVE_ENCODING(ctx->xml2enc)) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01432)
                          "Got charset from XML rules.") ;
            ctx->encoding = xmlGetCharEncodingName(ctx->xml2enc);
        }
    }

    /* If none of the above, look for a META-thingey */
    /* also we're probably about to invalidate it, so we remove it. */
    if (ap_regexec(seek_meta_ctype, ctx->buf, 1, match, 0) == 0 ) {
        /* get markers on the start and end of the match */
        rv = apr_brigade_partition(ctx->bbsave, match[0].rm_eo, &cute);
        ap_assert(rv == APR_SUCCESS);
        rv = apr_brigade_partition(ctx->bbsave, match[0].rm_so, &cutb);
        ap_assert(rv == APR_SUCCESS);
        /* now set length of useful buf for start-of-data hooks */
        ctx->bytes = match[0].rm_so;
        if (ctx->encoding == NULL) {
            p = apr_pstrndup(r->pool, ctx->buf + match[0].rm_so,
                             match[0].rm_eo - match[0].rm_so) ;
            if (ap_regexec(seek_charset, p, 2, match, 0) == 0) {
                if (ctx->encoding = apr_pstrndup(r->pool, p+match[1].rm_so,
                                               match[1].rm_eo - match[1].rm_so),
                    ctx->encoding) {
                    ctx->xml2enc = xmlParseCharEncoding(ctx->encoding);
                    if (HAVE_ENCODING(ctx->xml2enc))
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01433)
                                      "Got charset %s from HTML META", ctx->encoding) ;
                }
            }
        }

        /* cut out the <meta> we're invalidating */
        while (cutb != cute) {
            b = APR_BUCKET_NEXT(cutb);
            apr_bucket_delete(cutb);
            cutb = b;
        }
        /* and leave a string */
        ctx->buf[ctx->bytes] = 0;
    }

    /* either it's set to something we found or it's still the default */
    /* Aaargh!  libxml2 has undocumented <META-crap> support.  So this fails
     * if metafix is not active.  Have to make it conditional.
     *
     * No, that means no-metafix breaks things.  Deal immediately with
     * this particular instance of metafix.
     */
    if (!HAVE_ENCODING(ctx->xml2enc)) {
        cfg = ap_get_module_config(r->per_dir_config, &xml2enc_module);
        if (!ctx->encoding) {
            ctx->encoding = cfg->default_charset?cfg->default_charset:"ISO-8859-1";
        }
        /* Unsupported charset. Can we get (iconv) support through apr_xlate? */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01434)
                      "Charset %s not supported by libxml2; trying apr_xlate",
                      ctx->encoding);
        if (apr_xlate_open(&ctx->convset, "UTF-8", ctx->encoding, r->pool)
            == APR_SUCCESS) {
            ctx->xml2enc = XML_CHAR_ENCODING_UTF8 ;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01435)
                          "Charset %s not supported.  Consider aliasing it?",
                          ctx->encoding) ;
        }
    }

    if (!HAVE_ENCODING(ctx->xml2enc)) {
        /* Use configuration default as a last resort */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01436)
                  "No usable charset information; using configuration default");
        ctx->xml2enc = (cfg->default_encoding == XML_CHAR_ENCODING_NONE)
                        ? XML_CHAR_ENCODING_8859_1 : cfg->default_encoding ;
    }
    if (ctype && ctx->encoding) {
        if (ap_regexec(seek_charset, ctype, 2, match, 0)) {
            r->content_type = apr_pstrcat(r->pool, ctype, ";charset=utf-8",
                                          NULL);
        } else {
            char* str = apr_palloc(r->pool, strlen(r->content_type) + 13
                                   - (match[0].rm_eo - match[0].rm_so) + 1);
            memcpy(str, r->content_type, match[1].rm_so);
            memcpy(str + match[1].rm_so, "utf-8", 5);
            strcpy(str + match[1].rm_so + 5, r->content_type+match[1].rm_eo);
            r->content_type = str;
        }
    }
}

static apr_status_t xml2enc_filter_init(ap_filter_t* f)
{
    xml2ctx* ctx;
    if (!f->ctx) {
        xml2cfg* cfg = ap_get_module_config(f->r->per_dir_config,
                                            &xml2enc_module);
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(xml2ctx));
        ctx->xml2enc = XML_CHAR_ENCODING_NONE;
        if (cfg->skipto != NULL) {
            ctx->flags |= ENC_SKIPTO;
        }
    }
    return APR_SUCCESS;
}
static apr_status_t xml2enc_ffunc(ap_filter_t* f, apr_bucket_brigade* bb)
{
    xml2ctx* ctx = f->ctx;
    apr_status_t rv;
    apr_bucket* b;
    apr_bucket* bstart;
    apr_size_t insz = 0;
    char *ctype;
    char *p;

    if (!ctx || !f->r->content_type) {
        /* log error about configuring this */
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb) ;
    }

    ctype = apr_pstrdup(f->r->pool, f->r->content_type);
    for (p = ctype; *p; ++p)
        if (isupper(*p))
            *p = tolower(*p);

    /* only act if starts-with "text/" or contains "xml" */
    if (strncmp(ctype, "text/", 5) && !strstr(ctype, "xml"))  {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb) ;
    }

    if (ctx->bbsave == NULL) {
        ctx->bbsave = apr_brigade_create(f->r->pool,
                                         f->r->connection->bucket_alloc);
    }
    /* append to any data left over from last time */
    APR_BRIGADE_CONCAT(ctx->bbsave, bb);

    if (!(ctx->flags & ENC_INITIALISED)) {
        /* some kind of initialisation required */
        /* Turn all this off when post-processing */

        /* if we don't have enough data to sniff but more's to come, wait */
        apr_brigade_length(ctx->bbsave, 0, &ctx->bblen);
        if ((ctx->bblen < BUF_MIN) && (ctx->bblen != -1)) {
            APR_BRIGADE_DO(b, ctx->bbsave) {
                if (APR_BUCKET_IS_EOS(b)) {
                    ctx->flags |= ENC_SEEN_EOS;
                    break;
                }
            }
            if (!(ctx->flags & ENC_SEEN_EOS)) {
                /* not enough data to sniff.  Wait for more */
                APR_BRIGADE_DO(b, ctx->bbsave) {
                    rv = apr_bucket_setaside(b, f->r->pool);
                    ap_assert(rv == APR_SUCCESS);
                }
                return APR_SUCCESS;
            }
        }
        if (ctx->bblen == -1) {
            ctx->bblen = BUFLEN-1;
        }

        /* flatten it into a NULL-terminated string */
        ctx->buf = apr_palloc(f->r->pool, (apr_size_t)(ctx->bblen+1));
        ctx->bytes = (apr_size_t)ctx->bblen;
        rv = apr_brigade_flatten(ctx->bbsave, ctx->buf, &ctx->bytes);
        ap_assert(rv == APR_SUCCESS);
        ctx->buf[ctx->bytes] = 0;
        sniff_encoding(f->r, ctx);

        /* FIXME: hook here for rewriting start-of-data? */
        /* nah, we only have one action here - call it inline */
        fix_skipto(f->r, ctx);

        /* we might change the Content-Length, so let's force its re-calculation */
        apr_table_unset(f->r->headers_out, "Content-Length");

        /* consume the data we just sniffed */
        /* we need to omit any <meta> we just invalidated */
        ctx->flags |= ENC_INITIALISED;
        ap_set_module_config(f->r->request_config, &xml2enc_module, ctx);
    }
    if (ctx->bbnext == NULL) {
        ctx->bbnext = apr_brigade_create(f->r->pool,
                                         f->r->connection->bucket_alloc);
    }

    if (!ctx->convset) {
        rv = ap_pass_brigade(f->next, ctx->bbsave);
        apr_brigade_cleanup(ctx->bbsave);
        ap_remove_output_filter(f);
        return rv;
    }
    /* move the data back to bb */
    APR_BRIGADE_CONCAT(bb, ctx->bbsave);

    while (b = APR_BRIGADE_FIRST(bb), b != APR_BRIGADE_SENTINEL(bb)) {
        ctx->bytes = 0;
        if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            if (APR_BUCKET_IS_EOS(b)) {
                /* send remaining data */
                APR_BRIGADE_INSERT_TAIL(ctx->bbnext, b);
                return ap_fflush(f->next, ctx->bbnext);
            } else if (APR_BUCKET_IS_FLUSH(b)) {
                ap_fflush(f->next, ctx->bbnext);
            }
            apr_bucket_destroy(b);
        }
        else {        /* data bucket */
            char* buf;
            apr_size_t bytes = 0;
            char fixbuf[BUFLEN];
            apr_bucket* bdestroy = NULL;
            if (insz > 0) { /* we have dangling data.  Flatten it. */
                buf = fixbuf;
                bytes = BUFLEN;
                rv = apr_brigade_flatten(bb, buf, &bytes);
                ap_assert(rv == APR_SUCCESS);
                if (bytes == insz) {
                    /* this is only what we've already tried to convert.
                     * The brigade is exhausted.
                     * Save remaining data for next time round
                     */
          
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(01437)
                                  "xml2enc: Setting aside %" APR_SIZE_T_FMT
                                  " unconverted bytes", bytes);
                    rv = ap_fflush(f->next, ctx->bbnext);
                    APR_BRIGADE_CONCAT(ctx->bbsave, bb);
                    APR_BRIGADE_DO(b, ctx->bbsave) {
                        ap_assert(apr_bucket_setaside(b, f->r->pool)
                                  == APR_SUCCESS);
                    }
                    return rv;
                }
                /* remove the data we've just read */
                rv = apr_brigade_partition(bb, bytes, &bstart);
                while (b = APR_BRIGADE_FIRST(bb), b != bstart) {
                    apr_bucket_delete(b);
                }
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(01438)
                              "xml2enc: consuming %" APR_SIZE_T_FMT
                              " bytes flattened", bytes);
            }
            else {
                rv = apr_bucket_read(b, (const char**)&buf, &bytes,
                                     APR_BLOCK_READ);
                APR_BUCKET_REMOVE(b);
                bdestroy = b;  /* can't destroy until finished with the data */
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(01439)
                              "xml2enc: consuming %" APR_SIZE_T_FMT
                              " bytes from bucket", bytes);
            }
            /* OK, we've got some input we can use in [buf,bytes] */
            if (rv == APR_SUCCESS) {
                apr_size_t consumed;
                xml2enc_run_preprocess(f, &buf, &bytes);
                consumed = insz = bytes;
                while (insz > 0) {
                    apr_status_t rv2;
                    if (ctx->bytes == ctx->bblen) {
                        /* nothing was converted last time!
                         * break out of this loop! 
                         */
                        b = apr_bucket_transient_create(buf+(bytes - insz), insz,
                                                        bb->bucket_alloc);
                        APR_BRIGADE_INSERT_HEAD(bb, b);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(01440)
                                      "xml2enc: reinserting %" APR_SIZE_T_FMT
                                      " unconsumed bytes from bucket", insz);
                        break;
                    }
                    ctx->bytes = (apr_size_t)ctx->bblen;
                    rv = apr_xlate_conv_buffer(ctx->convset, buf+(bytes - insz),
                                               &insz, ctx->buf, &ctx->bytes);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r, APLOGNO(01441)
                                  "xml2enc: converted %" APR_SIZE_T_FMT
                                  "/%" APR_OFF_T_FMT " bytes", consumed - insz,
                                  ctx->bblen - ctx->bytes);
                    consumed = insz;
                    rv2 = ap_fwrite(f->next, ctx->bbnext, ctx->buf,
                                    (apr_size_t)ctx->bblen - ctx->bytes);
                    if (rv2 != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv2, f->r, APLOGNO(01442)
                                      "ap_fwrite failed");
                        return rv2;
                    }
                    switch (rv) {
                    case APR_SUCCESS:
                        continue;
                    case APR_EINCOMPLETE:
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(01443)
                                      "INCOMPLETE");
                        continue;     /* If outbuf too small, go round again.
                                       * If it was inbuf, we'll break out when
                                       * we test ctx->bytes == ctx->bblen
                                       */
                    case APR_EINVAL: /* try skipping one bad byte */
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(01444)
                                   "Skipping invalid byte(s) in input stream!");
                        --insz;
                        continue;
                    default:
                        /* Erk!  What's this?
                         * Bail out, flush, and hope to eat the buf raw
                         */
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01445)
                                      "Failed to convert input; trying it raw") ;
                        ctx->convset = NULL;
                        rv = ap_fflush(f->next, ctx->bbnext);
                        if (rv != APR_SUCCESS)
                            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r, APLOGNO(01446)
                                          "ap_fflush failed");
                        else
                            rv = ap_pass_brigade(f->next, ctx->bbnext);
                    }
                }
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, APLOGNO(01447)
                              "xml2enc: error reading data") ;
            }
            if (bdestroy)
                apr_bucket_destroy(bdestroy);
            if (rv != APR_SUCCESS)
                return rv;
        }
    }
    return APR_SUCCESS;
}
static apr_status_t xml2enc_charset(request_rec* r, xmlCharEncoding* encp,
                                    const char** encoding)
{
    xml2ctx* ctx = ap_get_module_config(r->request_config, &xml2enc_module);
    if (!ctx || !(ctx->flags & ENC_INITIALISED)) {
        return APR_EAGAIN;
    }
    *encp = ctx->xml2enc;
    *encoding = ctx->encoding;
    return HAVE_ENCODING(ctx->xml2enc) ? APR_SUCCESS : APR_EGENERAL;
}

#define PROTO_FLAGS AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH
static void xml2enc_hooks(apr_pool_t* pool)
{
    ap_register_output_filter_protocol("xml2enc", xml2enc_ffunc,
                                       xml2enc_filter_init,
                                       AP_FTYPE_RESOURCE, PROTO_FLAGS);
    APR_REGISTER_OPTIONAL_FN(xml2enc_filter);
    APR_REGISTER_OPTIONAL_FN(xml2enc_charset);
    seek_meta_ctype = ap_pregcomp(pool,
                       "(<meta[^>]*http-equiv[ \t\r\n='\"]*content-type[^>]*>)",
                                  AP_REG_EXTENDED|AP_REG_ICASE) ;
    seek_charset = ap_pregcomp(pool, "charset=([A-Za-z0-9_-]+)",
                               AP_REG_EXTENDED|AP_REG_ICASE) ;
}
static const char* set_alias(cmd_parms* cmd, void* CFG,
                             const char* charset, const char* alias)
{
    const char* errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (errmsg != NULL)
        return errmsg ;
    else if (xmlAddEncodingAlias(charset, alias) == 0)
        return NULL;
    else
        return "Error setting charset alias";
}

static const char* set_default(cmd_parms* cmd, void* CFG, const char* charset)
{
    xml2cfg* cfg = CFG;
    cfg->default_charset = charset;
    cfg->default_encoding = xmlParseCharEncoding(charset);
    switch(cfg->default_encoding) {
    case XML_CHAR_ENCODING_NONE:
        return "Default charset not found";
    case XML_CHAR_ENCODING_ERROR:
        return "Invalid or unsupported default charset";
    default:
        return NULL;
    }
}
static const char* set_skipto(cmd_parms* cmd, void* CFG, const char* arg)
{
    tattr* attr;
    xml2cfg* cfg = CFG;
    if (cfg->skipto == NULL)
        cfg->skipto = apr_array_make(cmd->pool, 4, sizeof(tattr));
    attr = apr_array_push(cfg->skipto) ;
    attr->val = arg;
    return NULL;
}

static const command_rec xml2enc_cmds[] = {
    AP_INIT_TAKE1("xml2EncDefault", set_default, NULL, OR_ALL,
                  "Usage: xml2EncDefault charset"),
    AP_INIT_ITERATE2("xml2EncAlias", set_alias, NULL, RSRC_CONF,
                     "EncodingAlias charset alias [more aliases]"),
    AP_INIT_ITERATE("xml2StartParse", set_skipto, NULL, OR_ALL,
                    "Ignore anything in front of the first of these elements"),
    { NULL }
};
static void* xml2enc_config(apr_pool_t* pool, char* x)
{
    xml2cfg* ret = apr_pcalloc(pool, sizeof(xml2cfg));
    ret->default_encoding = XML_CHAR_ENCODING_NONE ;
    return ret;
}

static void* xml2enc_merge(apr_pool_t* pool, void* BASE, void* ADD)
{
    xml2cfg* base = BASE;
    xml2cfg* add = ADD;
    xml2cfg* ret = apr_pcalloc(pool, sizeof(xml2cfg));
    ret->default_encoding = (add->default_encoding == XML_CHAR_ENCODING_NONE)
                          ? base->default_encoding : add->default_encoding ;
    ret->default_charset = add->default_charset
                         ? add->default_charset : base->default_charset;
    ret->skipto = add->skipto ? add->skipto : base->skipto;
    return ret;
}

AP_DECLARE_MODULE(xml2enc) = {
    STANDARD20_MODULE_STUFF,
    xml2enc_config,
    xml2enc_merge,
    NULL,
    NULL,
    xml2enc_cmds,
    xml2enc_hooks
};

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(xml2enc, XML2ENC, int, preprocess,
                      (ap_filter_t *f, char** bufp, apr_size_t* bytesp),
                      (f, bufp, bytesp), OK, DECLINED)
