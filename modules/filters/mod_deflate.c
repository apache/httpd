/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 * (zlib functions gz_open and gzwrite)
 */

/*
 * mod_deflate.c: Perform deflate transfer-encoding on the fly
 *
 * Written by Ian Holsman
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "zlib.h"

#ifdef HAVE_ZUTIL_H
#include "zutil.h"
#else
/* As part of the encoding process, we must send what our OS_CODE is
 * (or so it seems based on what I can tell of how gzip encoding works).
 *
 * zutil.h is not always included with zlib distributions (it is a private
 * header), so this is straight from zlib 1.1.3's zutil.h.
 */
#ifdef OS2
#define OS_CODE  0x06
#endif

#ifdef WIN32 /* Window 95 & Windows NT */
#define OS_CODE  0x0b
#endif

#if defined(VAXC) || defined(VMS)
#define OS_CODE  0x02
#endif

#ifdef AMIGA
#define OS_CODE  0x01
#endif

#if defined(ATARI) || defined(atarist)
#define OS_CODE  0x05
#endif

#if defined(MACOS) || defined(TARGET_OS_MAC)
#define OS_CODE  0x07
#endif

#ifdef __50SERIES /* Prime/PRIMOS */
#define OS_CODE  0x0F
#endif

#ifdef TOPS20
#define OS_CODE  0x0a
#endif

#ifndef OS_CODE
#define OS_CODE  0x03  /* assume Unix */
#endif
#endif

static const char deflateFilterName[] = "DEFLATE";
module AP_MODULE_DECLARE_DATA deflate_module;

typedef struct deflate_filter_config_t
{
    int windowSize;
    int memlevel;
    int compressionlevel;
    apr_size_t bufferSize;
    char *note_ratio_name;
    char *note_input_name;
    char *note_output_name;
} deflate_filter_config;

/* windowsize is negative to suppress Zlib header */
#define DEFAULT_COMPRESSION Z_DEFAULT_COMPRESSION
#define DEFAULT_WINDOWSIZE -15
#define DEFAULT_MEMLEVEL 9
#define DEFAULT_BUFFERSIZE 8096

/* Outputs a long in LSB order to the given file
 * only the bottom 4 bits are required for the deflate file format.
 */
static void putLong(unsigned char *string, unsigned long x)
{
    string[0] = (unsigned char)(x & 0xff);
    string[1] = (unsigned char)((x & 0xff00) >> 8);
    string[2] = (unsigned char)((x & 0xff0000) >> 16);
    string[3] = (unsigned char)((x & 0xff000000) >> 24);
}

/* Inputs a string and returns a long.
 */
static unsigned long getLong(unsigned char *string)
{
    return ((unsigned long)string[0])
          | (((unsigned long)string[1]) << 8)
          | (((unsigned long)string[2]) << 16)
          | (((unsigned long)string[3]) << 24);
}

static void *create_deflate_server_config(apr_pool_t *p, server_rec *s)
{
    deflate_filter_config *c = apr_pcalloc(p, sizeof *c);

    c->memlevel   = DEFAULT_MEMLEVEL;
    c->windowSize = DEFAULT_WINDOWSIZE;
    c->bufferSize = DEFAULT_BUFFERSIZE;
    c->compressionlevel = DEFAULT_COMPRESSION;

    return c;
}

static const char *deflate_set_window_size(cmd_parms *cmd, void *dummy,
                                           const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config,
                                                    &deflate_module);
    int i;

    i = atoi(arg);

    if (i < 1 || i > 15)
        return "DeflateWindowSize must be between 1 and 15";

    c->windowSize = i * -1;

    return NULL;
}

static const char *deflate_set_buffer_size(cmd_parms *cmd, void *dummy,
                                           const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config,
                                                    &deflate_module);
    int n = atoi(arg);

    if (n <= 0) {
        return "DeflateBufferSize should be positive";
    }

    c->bufferSize = (apr_size_t)n;

    return NULL;
}
static const char *deflate_set_note(cmd_parms *cmd, void *dummy,
                                    const char *arg1, const char *arg2)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config,
                                                    &deflate_module);
    
    if (arg2 == NULL) {
        c->note_ratio_name = apr_pstrdup(cmd->pool, arg1);
    }
    else if (!strcasecmp(arg1, "ratio")) {
        c->note_ratio_name = apr_pstrdup(cmd->pool, arg2);
    }
    else if (!strcasecmp(arg1, "input")) {
        c->note_input_name = apr_pstrdup(cmd->pool, arg2);
    }
    else if (!strcasecmp(arg1, "output")) {
        c->note_output_name = apr_pstrdup(cmd->pool, arg2);
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown note type %s", arg1);
    }

    return NULL;
}

static const char *deflate_set_memlevel(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config,
                                                    &deflate_module);
    int i;

    i = atoi(arg);

    if (i < 1 || i > 9)
        return "DeflateMemLevel must be between 1 and 9";

    c->memlevel = i;

    return NULL;
}

static const char *deflate_set_compressionlevel(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config,
                                                    &deflate_module);
    int i;

    i = atoi(arg);

    if (i < 1 || i > 9)
        return "Compression Level must be between 1 and 9";

    c->compressionlevel = i;

    return NULL;
}

/* magic header */
static char deflate_magic[2] = { '\037', '\213' };

typedef struct deflate_ctx_t
{
    z_stream stream;
    unsigned char *buffer;
    unsigned long crc;
    apr_bucket_brigade *bb, *proc_bb;
} deflate_ctx;

static apr_status_t deflate_out_filter(ap_filter_t *f,
                                       apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    deflate_filter_config *c = ap_get_module_config(r->server->module_config,
                                                    &deflate_module);

    /* If we don't have a context, we need to ensure that it is okay to send
     * the deflated content.  If we have a context, that means we've done
     * this before and we liked it.
     * This could be not so nice if we always fail.  But, if we succeed,
     * we're in better shape.
     */
    if (!ctx) {
        char *buf, *token;
        const char *encoding, *accepts;

        /* only work on main request/no subrequests */
        if (r->main) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* some browsers might have problems, so set no-gzip
         * (with browsermatch) for them
         */
        if (apr_table_get(r->subprocess_env, "no-gzip")) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* Some browsers might have problems with content types
         * other than text/html, so set gzip-only-text/html
         * (with browsermatch) for them
         */
        if (r->content_type == NULL
             || strncmp(r->content_type, "text/html", 9)) {
            const char *env_value = apr_table_get(r->subprocess_env,
                                                  "gzip-only-text/html");
            if ( env_value && (strcmp(env_value,"1") == 0) ) {
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }            
        }

        /* Let's see what our current Content-Encoding is.
         * If it's already encoded, don't compress again.
         * (We could, but let's not.)
         */
        encoding = apr_table_get(r->headers_out, "Content-Encoding");
        if (encoding) {
            const char *err_enc;

            err_enc = apr_table_get(r->err_headers_out, "Content-Encoding");
            if (err_enc) {
                encoding = apr_pstrcat(r->pool, encoding, ",", err_enc, NULL);
            }
        }
        else {
            encoding = apr_table_get(r->err_headers_out, "Content-Encoding");
        }

        if (r->content_encoding) {
            encoding = encoding ? apr_pstrcat(r->pool, encoding, ",",
                                              r->content_encoding, NULL)
                                : r->content_encoding;
        }

        if (encoding) {
            const char *tmp = encoding;

            token = ap_get_token(r->pool, &tmp, 0);
            while (token && *token) {
                /* stolen from mod_negotiation: */
                if (strcmp(token, "identity") && strcmp(token, "7bit") &&
                    strcmp(token, "8bit") && strcmp(token, "binary")) {

                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);			
                }

                /* Otherwise, skip token */
                if (*tmp) {
                    ++tmp;
                }
                token = (*tmp) ? ap_get_token(r->pool, &tmp, 0) : NULL;
            }
        }

        /* Even if we don't accept this request based on it not having
         * the Accept-Encoding, we need to note that we were looking
         * for this header and downstream proxies should be aware of that.
         */
        apr_table_setn(r->headers_out, "Vary", "Accept-Encoding");

        /* if they don't have the line, then they can't play */
        accepts = apr_table_get(r->headers_in, "Accept-Encoding");
        if (accepts == NULL) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        token = ap_get_token(r->pool, &accepts, 0);
        while (token && token[0] && strcasecmp(token, "gzip")) {
            /* skip parameters, XXX: ;q=foo evaluation? */
            while (*accepts == ';') { 
                ++accepts;
                token = ap_get_token(r->pool, &accepts, 1);
            }

            /* retrieve next token */
            if (*accepts == ',') {
                ++accepts;
            }
            token = (*accepts) ? ap_get_token(r->pool, &accepts, 0) : NULL;
        }

        /* No acceptable token found. */
        if (token == NULL || token[0] == '\0') {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* We're cool with filtering this. */
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->buffer = apr_palloc(r->pool, c->bufferSize);

        zRC = deflateInit2(&ctx->stream, c->compressionlevel, Z_DEFLATED,
                           c->windowSize, c->memlevel,
                           Z_DEFAULT_STRATEGY);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unable to init Zlib: "
                          "deflateInit2 returned %d: URL %s",
                          zRC, r->uri);
            return ap_pass_brigade(f->next, bb);
        }

        /* RFC 1952 Section 2.3 dictates the gzip header:
         *
         * +---+---+---+---+---+---+---+---+---+---+
         * |ID1|ID2|CM |FLG|     MTIME     |XFL|OS |
         * +---+---+---+---+---+---+---+---+---+---+
         *
         * If we wish to populate in MTIME (as hinted in RFC 1952), do:
         * putLong(date_array, apr_time_now() / APR_USEC_PER_SEC);
         * where date_array is a char[4] and then print date_array in the
         * MTIME position.  WARNING: ENDIANNESS ISSUE HERE.
         */
        buf = apr_psprintf(r->pool, "%c%c%c%c%c%c%c%c%c%c", deflate_magic[0],
                           deflate_magic[1], Z_DEFLATED, 0 /* flags */,
                           0, 0, 0, 0 /* 4 chars for mtime */,
                           0 /* xflags */, OS_CODE);
        e = apr_bucket_pool_create(buf, 10, r->pool, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        /* If the entire Content-Encoding is "identity", we can replace it. */
        if (!encoding || !strcasecmp(encoding, "identity")) {
            apr_table_setn(r->headers_out, "Content-Encoding", "gzip");
        }
        else {
            apr_table_mergen(r->headers_out, "Content-Encoding", "gzip");
        }
        apr_table_unset(r->headers_out, "Content-Length");

        /* initialize deflate output buffer */
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;
    }
    
    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        const char *data;
        apr_bucket *b;
        apr_size_t len;

        int done = 0;

        if (APR_BUCKET_IS_EOS(e)) {
            char *buf;
            unsigned int deflate_len;

            ctx->stream.avail_in = 0; /* should be zero already anyway */
            for (;;) {
                deflate_len = c->bufferSize - ctx->stream.avail_out;

                if (deflate_len != 0) {
                    b = apr_bucket_heap_create((char *)ctx->buffer,
                                               deflate_len, NULL,
                                               f->c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
                    ctx->stream.next_out = ctx->buffer;
                    ctx->stream.avail_out = c->bufferSize;
                }

                if (done) {
                    break;
                }

                zRC = deflate(&ctx->stream, Z_FINISH);

                if (deflate_len == 0 && zRC == Z_BUF_ERROR) {
                    zRC = Z_OK;
                }

                done = (ctx->stream.avail_out != 0 || zRC == Z_STREAM_END);

                if (zRC != Z_OK && zRC != Z_STREAM_END) {
                    break;
                }
            }

            buf = apr_palloc(r->pool, 8);
            putLong((unsigned char *)&buf[0], ctx->crc);
            putLong((unsigned char *)&buf[4], ctx->stream.total_in);

            b = apr_bucket_pool_create(buf, 8, r->pool, f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "Zlib: Compressed %ld to %ld : URL %s",
                          ctx->stream.total_in, ctx->stream.total_out, r->uri);

            /* leave notes for logging */
            if (c->note_input_name) {
                apr_table_setn(r->notes, c->note_input_name,
                               (ctx->stream.total_in > 0)
                                ? apr_off_t_toa(r->pool,
                                                ctx->stream.total_in)
                                : "-");
            }

            if (c->note_output_name) {
                apr_table_setn(r->notes, c->note_output_name,
                               (ctx->stream.total_in > 0)
                                ? apr_off_t_toa(r->pool,
                                                ctx->stream.total_out)
                                : "-");
            }

            if (c->note_ratio_name) {
                apr_table_setn(r->notes, c->note_ratio_name,
                               (ctx->stream.total_in > 0)
                                ? apr_itoa(r->pool,
                                           (int)(ctx->stream.total_out
                                                 * 100
                                                 / ctx->stream.total_in))
                                : "-");
            }

            deflateEnd(&ctx->stream);

            /* Remove EOS from the old list, and insert into the new. */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* Okay, we've seen the EOS.
             * Time to pass it along down the chain.
             */
            return ap_pass_brigade(f->next, ctx->bb);
        }

        if (APR_BUCKET_IS_FLUSH(e)) {
            apr_bucket *bkt;
            apr_status_t rv;
            if (ctx->stream.avail_in > 0) {
                zRC = deflate(&(ctx->stream), Z_SYNC_FLUSH);
                if (zRC != Z_OK) {
                    return APR_EGENERAL;
                }
            }

            ctx->stream.next_out = ctx->buffer;
            len = c->bufferSize - ctx->stream.avail_out;

            b = apr_bucket_heap_create((char *)ctx->buffer, len,
                                       NULL, f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ctx->stream.avail_out = c->bufferSize;

            bkt = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, bkt);
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            continue;
        }

        /* read */
        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);

        /* This crc32 function is from zlib. */
        ctx->crc = crc32(ctx->crc, (const Bytef *)data, len);

        /* write */
        ctx->stream.next_in = (unsigned char *)data; /* We just lost const-ness,
                                                      * but we'll just have to
                                                      * trust zlib */
        ctx->stream.avail_in = len;

        while (ctx->stream.avail_in != 0) {
            if (ctx->stream.avail_out == 0) {
                apr_status_t rv;

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;

                b = apr_bucket_heap_create((char *)ctx->buffer, len,
                                           NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
                ctx->stream.avail_out = c->bufferSize;
                /* Send what we have right now to the next filter. */
                rv = ap_pass_brigade(f->next, ctx->bb);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
            }

            zRC = deflate(&(ctx->stream), Z_NO_FLUSH);

            if (zRC != Z_OK)
                return APR_EGENERAL;
        }
    }

    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

/* This is the deflate input filter (inflates).  */
static apr_status_t deflate_in_filter(ap_filter_t *f,
                                      apr_bucket_brigade *bb,
                                      ap_input_mode_t mode,
                                      apr_read_type_e block,
                                      apr_off_t readbytes)
{
    apr_bucket *bkt;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_status_t rv;
    deflate_filter_config *c;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);

    if (!ctx) {
        int found = 0;
        char *token, deflate_hdr[10];
        const char *encoding;
        apr_size_t len;

        /* only work on main request/no subrequests */
        if (r->main) {
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        /* Let's see what our current Content-Encoding is.
         * If gzip is present, don't gzip again.  (We could, but let's not.)
         */
        encoding = apr_table_get(r->headers_in, "Content-Encoding");
        if (encoding) {
            const char *tmp = encoding;

            token = ap_get_token(r->pool, &tmp, 0);
            while (token && token[0]) {
                if (!strcasecmp(token, "gzip")) {
                    found = 1;
                    break;
                }
                /* Otherwise, skip token */
                tmp++;
                token = ap_get_token(r->pool, &tmp, 0);
            }
        }

        if (found == 0) {
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->proc_bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->buffer = apr_palloc(r->pool, c->bufferSize);

        rv = ap_get_brigade(f->next, ctx->bb, AP_MODE_READBYTES, block, 10);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        len = 10; 
        rv = apr_brigade_flatten(ctx->bb, deflate_hdr, &len); 
        if (rv != APR_SUCCESS) {
            return rv;
        }

        /* We didn't get the magic bytes. */
        if (len != 10 ||
            deflate_hdr[0] != deflate_magic[0] ||
            deflate_hdr[1] != deflate_magic[1]) {
            return APR_EGENERAL;
        }

        /* We can't handle flags for now. */
        if (deflate_hdr[3] != 0) {
            return APR_EGENERAL;
        }

        zRC = inflateInit2(&ctx->stream, c->windowSize);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            inflateEnd(&ctx->stream);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unable to init Zlib: "
                          "inflateInit2 returned %d: URL %s",
                          zRC, r->uri);
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        /* initialize deflate output buffer */
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;

        apr_brigade_cleanup(ctx->bb);
    }

    if (APR_BRIGADE_EMPTY(ctx->proc_bb)) {
        rv = ap_get_brigade(f->next, ctx->bb, mode, block, readbytes);

        if (rv != APR_SUCCESS) {
            /* What about APR_EAGAIN errors? */
            inflateEnd(&ctx->stream);
            return rv;
        }

        for (bkt = APR_BRIGADE_FIRST(ctx->bb);
             bkt != APR_BRIGADE_SENTINEL(ctx->bb);
             bkt = APR_BUCKET_NEXT(bkt))
        {
            const char *data;
            apr_size_t len;

            /* If we actually see the EOS, that means we screwed up! */
            if (APR_BUCKET_IS_EOS(bkt)) {
                inflateEnd(&ctx->stream);
                return APR_EGENERAL;
            }

            if (APR_BUCKET_IS_FLUSH(bkt)) {
                apr_bucket *tmp_heap;
                zRC = inflate(&(ctx->stream), Z_SYNC_FLUSH);
                if (zRC != Z_OK) {
                    inflateEnd(&ctx->stream);
                    return APR_EGENERAL;
                }

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len,
                                                 NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
                ctx->stream.avail_out = c->bufferSize;

                /* Move everything to the returning brigade. */
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_CONCAT(bb, ctx->bb);
                break;
            }

            /* read */
            apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);

            /* pass through zlib inflate. */
            ctx->stream.next_in = (unsigned char *)data;
            ctx->stream.avail_in = len;

            zRC = Z_OK;

            while (ctx->stream.avail_in != 0) {
                if (ctx->stream.avail_out == 0) {
                    apr_bucket *tmp_heap;
                    ctx->stream.next_out = ctx->buffer;
                    len = c->bufferSize - ctx->stream.avail_out;

                    ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                    tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len,
                                                      NULL, f->c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
                    ctx->stream.avail_out = c->bufferSize;
                }

                zRC = inflate(&ctx->stream, Z_NO_FLUSH);

                if (zRC == Z_STREAM_END) {
                    break;
                }

                if (zRC != Z_OK) {
                    inflateEnd(&ctx->stream);
                    return APR_EGENERAL;
                }
            }
            if (zRC == Z_STREAM_END) {
                apr_bucket *tmp_heap, *eos;

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "Zlib: Inflated %ld to %ld : URL %s",
                              ctx->stream.total_in, ctx->stream.total_out,
                              r->uri);

                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len,
                                                  NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
                ctx->stream.avail_out = c->bufferSize;

                /* Is the remaining 8 bytes already in the avail stream? */
                if (ctx->stream.avail_in >= 8) {
                    unsigned long compCRC, compLen;
                    compCRC = getLong(ctx->stream.next_in);
                    if (ctx->crc != compCRC) {
                        inflateEnd(&ctx->stream);
                        return APR_EGENERAL;
                    }
                    ctx->stream.next_in += 4;
                    compLen = getLong(ctx->stream.next_in);
                    if (ctx->stream.total_out != compLen) {
                        inflateEnd(&ctx->stream);
                        return APR_EGENERAL;
                    }
                }
                else {
                    /* FIXME: We need to grab the 8 verification bytes
                     * from the wire! */
                    inflateEnd(&ctx->stream);
                    return APR_EGENERAL;
                }

                inflateEnd(&ctx->stream);

                eos = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, eos); 
                break;
            }

        }
        apr_brigade_cleanup(ctx->bb);
    }

    /* If we are about to return nothing for a 'blocking' read and we have
     * some data in our zlib buffer, flush it out so we can return something.
     */
    if (block == APR_BLOCK_READ &&
        APR_BRIGADE_EMPTY(ctx->proc_bb) &&
        ctx->stream.avail_out < c->bufferSize) {
        apr_bucket *tmp_heap;
        apr_size_t len;
        ctx->stream.next_out = ctx->buffer;
        len = c->bufferSize - ctx->stream.avail_out;

        ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
        tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len,
                                          NULL, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
        ctx->stream.avail_out = c->bufferSize;
    }

    if (!APR_BRIGADE_EMPTY(ctx->proc_bb)) {
        apr_bucket_brigade *newbb;

        /* May return APR_INCOMPLETE which is fine by us. */
        apr_brigade_partition(ctx->proc_bb, readbytes, &bkt);

        newbb = apr_brigade_split(ctx->proc_bb, bkt);
        APR_BRIGADE_CONCAT(bb, ctx->proc_bb);
        APR_BRIGADE_CONCAT(ctx->proc_bb, newbb);
    }

    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(deflateFilterName, deflate_out_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
    ap_register_input_filter(deflateFilterName, deflate_in_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
}

static const command_rec deflate_filter_cmds[] = {
    AP_INIT_TAKE12("DeflateFilterNote", deflate_set_note, NULL, RSRC_CONF,
                  "Set a note to report on compression ratio"),
    AP_INIT_TAKE1("DeflateWindowSize", deflate_set_window_size, NULL,
                  RSRC_CONF, "Set the Deflate window size (1-15)"),
    AP_INIT_TAKE1("DeflateBufferSize", deflate_set_buffer_size, NULL, RSRC_CONF,
                  "Set the Deflate Buffer Size"),
    AP_INIT_TAKE1("DeflateMemLevel", deflate_set_memlevel, NULL, RSRC_CONF,
                  "Set the Deflate Memory Level (1-9)"),
    AP_INIT_TAKE1("DeflateCompressionLevel", deflate_set_compressionlevel, NULL, RSRC_CONF,
                  "Set the Deflate Compression Level (1-9)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA deflate_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                         /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    create_deflate_server_config, /* server config */
    NULL,                         /* merge server config */
    deflate_filter_cmds,          /* command table */
    register_hooks                /* register hooks */
};
