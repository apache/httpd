/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
 * Written by Ian Holsman (IanH@apache.org)
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
#  define OS_CODE  0x06
#endif

#ifdef WIN32 /* Window 95 & Windows NT */
#  define OS_CODE  0x0b
#endif

#if defined(VAXC) || defined(VMS)
#  define OS_CODE  0x02
#endif

#ifdef AMIGA
#  define OS_CODE  0x01
#endif

#if defined(ATARI) || defined(atarist)
#  define OS_CODE  0x05
#endif

#if defined(MACOS) || defined(TARGET_OS_MAC)
#  define OS_CODE  0x07
#endif

#ifdef __50SERIES /* Prime/PRIMOS */
#  define OS_CODE  0x0F
#endif

#ifdef TOPS20
#  define OS_CODE  0x0a
#endif

#ifndef OS_CODE
#  define OS_CODE  0x03  /* assume Unix */
#endif
#endif

static const char deflateFilterName[] = "DEFLATE";
module AP_MODULE_DECLARE_DATA deflate_module;

typedef struct deflate_filter_config_t
{
    int windowSize;
    int memlevel;
    char *noteName;
} deflate_filter_config;

/* windowsize is negative to suppress Zlib header */
#define DEFAULT_WINDOWSIZE -15        
#define DEFAULT_MEMLEVEL 9
#define FILTER_BUFSIZE 8096

/* Outputs a long in LSB order to the given file
 * only the bottom 4 bits are required for the deflate file format.
 */
static void putLong(char *string, unsigned long x)
{
    int n;
    for (n = 0; n < 4; n++) {
        string[n] = (int) (x & 0xff);
        x >>= 8;
    }
}

static void *create_deflate_server_config(apr_pool_t *p, server_rec *s)
{
    deflate_filter_config *c = apr_pcalloc(p, sizeof *c);

    c->memlevel   = DEFAULT_MEMLEVEL;
    c->windowSize = DEFAULT_WINDOWSIZE;

    return c;
}
static const char *deflate_set_window_size(cmd_parms * cmd, void *dummy, 
                                           const char* arg)
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

static const char *deflate_set_note(cmd_parms * cmd, void *dummy, 
                                    const char* arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config,
                                                    &deflate_module);
    c->noteName = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char *deflate_set_memlevel(cmd_parms * cmd, void *dummy, 
                                        const char* arg)
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

/* magic header */
static int deflate_magic[2] = { 0x1f, 0x8b };        

typedef struct deflate_ctx_t
{
    z_stream stream;
    unsigned char buffer[FILTER_BUFSIZE];
    unsigned long crc;
    apr_bucket_brigade *bb;
} deflate_ctx;

static apr_status_t deflate_out_filter(ap_filter_t *f, 
                                       apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *accepts;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    char *token = NULL;
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
        char *buf;

        /* only work on main request/no subrequests */
        if (r->main) {
            return ap_pass_brigade(f->next, bb);
        }

        /* some browsers might have problems, so set no-gzip 
         * (with browsermatch) for them */
        if (apr_table_get(r->subprocess_env, "no-gzip")) {
            return ap_pass_brigade(f->next, bb);
        }

        /* if they don't have the line, then they can't play */
        accepts = apr_table_get(r->headers_in, "Accept-Encoding");
        if (accepts == NULL) {
            return ap_pass_brigade(f->next, bb);
        }

        token = ap_get_token(r->pool, &accepts, 0);
        while (token && token[0] && strcmp(token, "gzip")) {
            /* skip token */
            accepts++; 
            token = ap_get_token(r->pool, &accepts, 0);
        }

        /* No acceptable token found. */
        if (token == NULL || token[0] == '\0') {
            return ap_pass_brigade(f->next, bb);
        }

        /* We're cool with filtering this. */
        ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(f->r->pool);
/*
        ctx->stream.zalloc = (alloc_func) 0;
        ctx->stream.zfree = (free_func) 0;
        ctx->stream.opaque = (voidpf) 0;
        ctx->crc = 0L;
*/
        zRC = deflateInit2(&ctx->stream, Z_BEST_SPEED, Z_DEFLATED,
                           c->windowSize, c->memlevel,
                           Z_DEFAULT_STRATEGY);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                        "unable to init Zlib: deflateInit2 returned %d: URL %s",
                        zRC, r->uri);
            return ap_pass_brigade(f->next, bb);
        }
        buf = apr_psprintf(r->pool, "%c%c%c%c%c%c%c%c%c%c", deflate_magic[0],
                           deflate_magic[1], Z_DEFLATED, 0 /*flags */ , 0, 0, 
                           0, 0 /*time */ , 0 /*xflags */ , OS_CODE);
        e = apr_bucket_pool_create(buf, 10, r->pool);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        apr_table_setn(r->headers_out, "Content-Encoding", "gzip");
        apr_table_setn(r->headers_out, "Vary", "Accept-Encoding");
        apr_table_unset(r->headers_out, "Content-Length");
    }

    APR_BRIGADE_FOREACH(e, bb) {
        const char *data;
        apr_bucket *b;
        apr_size_t len;

        int done = 0;

        if (APR_BUCKET_IS_EOS(e)) {
            char *buf, *p;
            char crc_array[4], len_array[4];
            unsigned int deflate_len;

            ctx->stream.avail_in = 0;        /* should be zero already anyway */
            for (;;) {
                deflate_len = FILTER_BUFSIZE - ctx->stream.avail_out;

                if (deflate_len != 0) {
                    b = apr_bucket_heap_create((char *)ctx->buffer, deflate_len, 1);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
                    ctx->stream.next_out = ctx->buffer;
                    ctx->stream.avail_out = FILTER_BUFSIZE;
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
            putLong(crc_array, ctx->crc);
            putLong(len_array, ctx->stream.total_in);

            p = buf = apr_palloc(r->pool, 8);
            *p++ = crc_array[0];
            *p++ = crc_array[1];
            *p++ = crc_array[2];
            *p++ = crc_array[3];
            *p++ = len_array[0];
            *p++ = len_array[1];
            *p++ = len_array[2];
            *p++ = len_array[3];

            b = apr_bucket_pool_create(buf, 8, r->pool);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
                          "Zlib: Compressed %ld to %ld : URL %s",
                          ctx->stream.total_in, ctx->stream.total_out, r->uri);

            if (c->noteName) {
                 if (ctx->stream.total_in > 0) {
                    int total;

                    total = ctx->stream.total_out * 100 / ctx->stream.total_in;

                    apr_table_setn(r->notes, c->noteName, 
                                   apr_itoa(r->pool, total));
                 } else {
                    apr_table_setn(r->notes, c->noteName, "-");
                 }
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
            /* XXX FIX: do we need the Content-Size set, or can we stream?  
             * we should be able to stream */
            /* ignore flush buckets for the moment.. we can't stream as we 
             * need the size ;( */
            continue;
        }

        /* read */
        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        /* This crc32 function is from zlib. */
        ctx->crc = crc32(ctx->crc, (const Bytef *)data, len);

        /* write */
        ctx->stream.next_in = (unsigned char *)data; /* we just lost const-ness,
                                              but we'll just have to trust zlib */
        ctx->stream.avail_in = len;
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = FILTER_BUFSIZE;

        while (ctx->stream.avail_in != 0) {
            if (ctx->stream.avail_out == 0) {

                ctx->stream.next_out = ctx->buffer;
                len = FILTER_BUFSIZE - ctx->stream.avail_out;

                b = apr_bucket_heap_create((char *)ctx->buffer, len, 1);
                APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
                ctx->stream.avail_out = FILTER_BUFSIZE;
            }

            zRC = deflate(&(ctx->stream), Z_NO_FLUSH);

            if (zRC != Z_OK)
                return APR_EGENERAL;
        }
    }
    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t * p)
{
    ap_register_output_filter(deflateFilterName, deflate_out_filter,
                              AP_FTYPE_HTTP_HEADER);
}

static const command_rec deflate_filter_cmds[] = {
    AP_INIT_TAKE1("DeflateFilterNote", deflate_set_note, NULL, RSRC_CONF,
                  "Set a note to report on compression ratio"),
    AP_INIT_TAKE1("DeflateWindowSize", deflate_set_window_size, NULL, 
                  RSRC_CONF, "Set the Deflate window size (1-15)"),
    AP_INIT_TAKE1("DeflateMemLevel", deflate_set_memlevel, NULL, RSRC_CONF,
                  "Set the Deflate Memory Level (1-9)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA deflate_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_deflate_server_config,
    NULL,
    deflate_filter_cmds,
    register_hooks
};
