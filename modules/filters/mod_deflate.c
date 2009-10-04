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
 * mod_deflate.c: Perform deflate content-encoding on the fly
 *
 * Written by Ian Holsman, Justin Erenkrantz, and Nick Kew
 */

/*
 * Portions of this software are based upon zlib code by Jean-loup Gailly
 * (zlib functions gz_open and gzwrite, check_header)
 */

/* zlib flags */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */


#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "zlib.h"

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

/* RFC 1952 Section 2.3 defines the gzip header:
 *
 * +---+---+---+---+---+---+---+---+---+---+
 * |ID1|ID2|CM |FLG|     MTIME     |XFL|OS |
 * +---+---+---+---+---+---+---+---+---+---+
 */
static const char gzip_header[10] =
{ '\037', '\213', Z_DEFLATED, 0,
  0, 0, 0, 0, /* mtime */
  0, 0x03 /* Unix OS_CODE */
};

/* magic header */
static const char deflate_magic[2] = { '\037', '\213' };

/* windowsize is negative to suppress Zlib header */
#define DEFAULT_COMPRESSION Z_DEFAULT_COMPRESSION
#define DEFAULT_WINDOWSIZE -15
#define DEFAULT_MEMLEVEL 9
#define DEFAULT_BUFFERSIZE 8096


/* Check whether a request is gzipped, so we can un-gzip it.
 * If a request has multiple encodings, we need the gzip
 * to be the outermost non-identity encoding.
 */
static int check_gzip(request_rec *r, apr_table_t *hdrs1, apr_table_t *hdrs2)
{
    int found = 0;
    apr_table_t *hdrs = hdrs1;
    const char *encoding = apr_table_get(hdrs, "Content-Encoding");

    if (!encoding && (hdrs2 != NULL)) {
        /* the output filter has two tables and a content_encoding to check */
        encoding = apr_table_get(hdrs2, "Content-Encoding");
        hdrs = hdrs2;
        if (!encoding) {
            encoding = r->content_encoding;
            hdrs = NULL;
        }
    }
    if (encoding && *encoding) {

        /* check the usual/simple case first */
        if (!strcasecmp(encoding, "gzip")
            || !strcasecmp(encoding, "x-gzip")) {
            found = 1;
            if (hdrs) {
                apr_table_unset(hdrs, "Content-Encoding");
            }
            else {
                r->content_encoding = NULL;
            }
        }
        else if (ap_strchr_c(encoding, ',') != NULL) {
            /* If the outermost encoding isn't gzip, there's nowt
             * we can do.  So only check the last non-identity token
             */
            char *new_encoding = apr_pstrdup(r->pool, encoding);
            char *ptr;
            for(;;) {
                char *token = ap_strrchr(new_encoding, ',');
                if (!token) {        /* gzip:identity or other:identity */
                    if (!strcasecmp(new_encoding, "gzip")
                        || !strcasecmp(new_encoding, "x-gzip")) {
                        found = 1;
                        if (hdrs) {
                            apr_table_unset(hdrs, "Content-Encoding");
                        }
                        else {
                            r->content_encoding = NULL;
                        }
                    }
                    break; /* seen all tokens */
                }
                for (ptr=token+1; apr_isspace(*ptr); ++ptr);
                if (!strcasecmp(ptr, "gzip")
                    || !strcasecmp(ptr, "x-gzip")) {
                    *token = '\0';
                    if (hdrs) {
                        apr_table_setn(hdrs, "Content-Encoding", new_encoding);
                    }
                    else {
                        r->content_encoding = new_encoding;
                    }
                    found = 1;
                }
                else if (!ptr[0] || !strcasecmp(ptr, "identity")) {
                    *token = '\0';
                    continue; /* strip the token and find the next one */
                }
                break; /* found a non-identity token */
            }
        }
    }
    /*
     * If we have dealt with the headers above but content_encoding was set
     * before sync it with the new value in the hdrs table as
     * r->content_encoding takes precedence later on in the http_header_filter
     * and hence would destroy what we have just set in the hdrs table.
     */
    if (hdrs && r->content_encoding) {
        r->content_encoding = apr_table_get(hdrs, "Content-Encoding");
    }
    return found;
}

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

typedef struct deflate_ctx_t
{
    z_stream stream;
    unsigned char *buffer;
    unsigned long crc;
    apr_bucket_brigade *bb, *proc_bb;
    int (*libz_end_func)(z_streamp);
    unsigned char *validation_buffer;
    apr_size_t validation_buffer_length;
    int inflate_init;
} deflate_ctx;

/* Number of validation bytes (CRC and length) after the compressed data */
#define VALIDATION_SIZE 8
/* Do not update ctx->crc, see comment in flush_libz_buffer */
#define NO_UPDATE_CRC 0
/* Do update ctx->crc, see comment in flush_libz_buffer */
#define UPDATE_CRC 1

static int flush_libz_buffer(deflate_ctx *ctx, deflate_filter_config *c,
                             struct apr_bucket_alloc_t *bucket_alloc,
                             int (*libz_func)(z_streamp, int), int flush,
                             int crc)
{
    int zRC = Z_OK;
    int done = 0;
    unsigned int deflate_len;
    apr_bucket *b;

    for (;;) {
         deflate_len = c->bufferSize - ctx->stream.avail_out;

         if (deflate_len != 0) {
             /*
              * Do we need to update ctx->crc? Usually this is the case for
              * inflate action where we need to do a crc on the output, whereas
              * in the deflate case we need to do a crc on the input
              */
             if (crc) {
                 ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer,
                                  deflate_len);
             }
             b = apr_bucket_heap_create((char *)ctx->buffer,
                                        deflate_len, NULL,
                                        bucket_alloc);
             APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
             ctx->stream.next_out = ctx->buffer;
             ctx->stream.avail_out = c->bufferSize;
         }

         if (done)
             break;

         zRC = libz_func(&ctx->stream, flush);

         /*
          * We can ignore Z_BUF_ERROR because:
          * When we call libz_func we can assume that
          *
          * - avail_in is zero (due to the surrounding code that calls
          *   flush_libz_buffer)
          * - avail_out is non zero due to our actions some lines above
          *
          * So the only reason for Z_BUF_ERROR is that the internal libz
          * buffers are now empty and thus we called libz_func one time
          * too often. This does not hurt. It simply says that we are done.
          */
         if (zRC == Z_BUF_ERROR) {
             zRC = Z_OK;
             break;
         }

         done = (ctx->stream.avail_out != 0 || zRC == Z_STREAM_END);

         if (zRC != Z_OK && zRC != Z_STREAM_END)
             break;
    }
    return zRC;
}

static apr_status_t deflate_ctx_cleanup(void *data)
{
    deflate_ctx *ctx = (deflate_ctx *)data;

    if (ctx)
        ctx->libz_end_func(&ctx->stream);
    return APR_SUCCESS;
}

/* ETag must be unique among the possible representations, so a change
 * to content-encoding requires a corresponding change to the ETag.
 * This routine appends -transform (e.g., -gzip) to the entity-tag
 * value inside the double-quotes if an ETag has already been set
 * and its value already contains double-quotes. PR 39727
 */
static void deflate_check_etag(request_rec *r, const char *transform)
{
    const char *etag = apr_table_get(r->headers_out, "ETag");
    apr_size_t etaglen;

    if ((etag && ((etaglen = strlen(etag)) > 2))) {
        if (etag[etaglen - 1] == '"') {
            apr_size_t transformlen = strlen(transform);
            char *newtag = apr_palloc(r->pool, etaglen + transformlen + 2);
            char *d = newtag;
            char *e = d + etaglen - 1;
            const char *s = etag;

            for (; d < e; ++d, ++s) {
                *d = *s;          /* copy etag to newtag up to last quote */
            }
            *d++ = '-';           /* append dash to newtag */
            s = transform;
            e = d + transformlen;
            for (; d < e; ++d, ++s) {
                *d = *s;          /* copy transform to newtag */
            }
            *d++ = '"';           /* append quote to newtag */
            *d   = '\0';          /* null terminate newtag */

            apr_table_setn(r->headers_out, "ETag", newtag);
        }
    }   
}

static apr_status_t deflate_out_filter(ap_filter_t *f,
                                       apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    deflate_filter_config *c;

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    c = ap_get_module_config(r->server->module_config,
                             &deflate_module);

    /* If we don't have a context, we need to ensure that it is okay to send
     * the deflated content.  If we have a context, that means we've done
     * this before and we liked it.
     * This could be not so nice if we always fail.  But, if we succeed,
     * we're in better shape.
     */
    if (!ctx) {
        char *token;
        const char *encoding;

        /*
         * Only work on main request, not subrequests,
         * that are not a 204 response with no content
         * and are not tagged with the no-gzip env variable
         * and not a partial response to a Range request.
         */
        if ((r->main != NULL) || (r->status == HTTP_NO_CONTENT) ||
            apr_table_get(r->subprocess_env, "no-gzip") ||
            apr_table_get(r->headers_out, "Content-Range")
           ) {
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
        apr_table_mergen(r->headers_out, "Vary", "Accept-Encoding");

        /* force-gzip will just force it out regardless if the browser
         * can actually do anything with it.
         */
        if (!apr_table_get(r->subprocess_env, "force-gzip")) {
            const char *accepts;
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
        }

        /* At this point we have decided to filter the content, so change
         * important content metadata before sending any response out.
         */

        /* If the entire Content-Encoding is "identity", we can replace it. */
        if (!encoding || !strcasecmp(encoding, "identity")) {
            apr_table_setn(r->headers_out, "Content-Encoding", "gzip");
        }
        else {
            apr_table_mergen(r->headers_out, "Content-Encoding", "gzip");
        }
        /* Fix r->content_encoding if it was set before */
        if (r->content_encoding) {
            r->content_encoding = apr_table_get(r->headers_out,
                                                "Content-Encoding");
        }
        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Content-MD5");
        deflate_check_etag(r, "gzip");

        /* For a 304 response, only change the headers */
        if (r->status == HTTP_NOT_MODIFIED) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->buffer = apr_palloc(r->pool, c->bufferSize);
        ctx->libz_end_func = deflateEnd;

        zRC = deflateInit2(&ctx->stream, c->compressionlevel, Z_DEFLATED,
                           c->windowSize, c->memlevel,
                           Z_DEFAULT_STRATEGY);

        if (zRC != Z_OK) {
            deflateEnd(&ctx->stream);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unable to init Zlib: "
                          "deflateInit2 returned %d: URL %s",
                          zRC, r->uri);
            /*
             * Remove ourselves as it does not make sense to return:
             * We are not able to init libz and pass data down the chain
             * uncompressed.
             */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }
        /*
         * Register a cleanup function to ensure that we cleanup the internal
         * libz resources.
         */
        apr_pool_cleanup_register(r->pool, ctx, deflate_ctx_cleanup,
                                  apr_pool_cleanup_null);

        /* add immortal gzip header */
        e = apr_bucket_immortal_create(gzip_header, sizeof gzip_header,
                                       f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        /* initialize deflate output buffer */
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;
    }

    while (!APR_BRIGADE_EMPTY(bb))
    {
        const char *data;
        apr_bucket *b;
        apr_size_t len;

        e = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(e)) {
            char *buf;

            ctx->stream.avail_in = 0; /* should be zero already anyway */
            /* flush the remaining data from the zlib buffers */
            flush_libz_buffer(ctx, c, f->c->bucket_alloc, deflate, Z_FINISH,
                              NO_UPDATE_CRC);

            buf = apr_palloc(r->pool, VALIDATION_SIZE);
            putLong((unsigned char *)&buf[0], ctx->crc);
            putLong((unsigned char *)&buf[4], ctx->stream.total_in);

            b = apr_bucket_pool_create(buf, VALIDATION_SIZE, r->pool,
                                       f->c->bucket_alloc);
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
            /* No need for cleanup any longer */
            apr_pool_cleanup_kill(r->pool, ctx, deflate_ctx_cleanup);

            /* Remove EOS from the old list, and insert into the new. */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* Okay, we've seen the EOS.
             * Time to pass it along down the chain.
             */
            return ap_pass_brigade(f->next, ctx->bb);
        }

        if (APR_BUCKET_IS_FLUSH(e)) {
            apr_status_t rv;

            /* flush the remaining data from the zlib buffers */
            zRC = flush_libz_buffer(ctx, c, f->c->bucket_alloc, deflate,
                                    Z_SYNC_FLUSH, NO_UPDATE_CRC);
            if (zRC != Z_OK) {
                return APR_EGENERAL;
            }

            /* Remove flush bucket from old brigade anf insert into the new. */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            continue;
        }

        if (APR_BUCKET_IS_METADATA(e)) {
            /*
             * Remove meta data bucket from old brigade and insert into the
             * new.
             */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
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

            if (zRC != Z_OK) {
                return APR_EGENERAL;
            }
        }

        apr_bucket_delete(e);
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
        char deflate_hdr[10];
        apr_size_t len;

        /* only work on main request/no subrequests */
        if (!ap_is_initial_req(r)) {
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        /* We can't operate on Content-Ranges */
        if (apr_table_get(r->headers_in, "Content-Range") != NULL) {
            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        /* Check whether request body is gzipped.
         *
         * If it is, we're transforming the contents, invalidating
         * some request headers including Content-Encoding.
         *
         * If not, we just remove ourself.
         */
        if (check_gzip(r, r->headers_in, NULL) == 0) {
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

        apr_table_unset(r->headers_in, "Content-Length");
        apr_table_unset(r->headers_in, "Content-MD5");

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
        /* May return APR_INCOMPLETE which is fine by us. */
        apr_brigade_partition(ctx->proc_bb, readbytes, &bkt);

        APR_BRIGADE_CONCAT(bb, ctx->proc_bb);
        apr_brigade_split_ex(bb, bkt, ctx->proc_bb);
    }

    return APR_SUCCESS;
}


/* Filter to inflate for a content-transforming proxy.  */
static apr_status_t inflate_out_filter(ap_filter_t *f,
                                      apr_bucket_brigade *bb)
{
    int zlib_method;
    int zlib_flags;
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_status_t rv;
    deflate_filter_config *c;

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);

    if (!ctx) {

        /*
         * Only work on main request, not subrequests,
         * that are not a 204 response with no content
         * and not a partial response to a Range request,
         * and only when Content-Encoding ends in gzip.
         */
        if (!ap_is_initial_req(r) || (r->status == HTTP_NO_CONTENT) ||
            (apr_table_get(r->headers_out, "Content-Range") != NULL) ||
            (check_gzip(r, r->headers_out, r->err_headers_out) == 0)
           ) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /*
         * At this point we have decided to filter the content, so change
         * important content metadata before sending any response out.
         * Content-Encoding was already reset by the check_gzip() call.
         */
        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Content-MD5");
        deflate_check_etag(r, "gunzip");

        /* For a 304 response, only change the headers */
        if (r->status == HTTP_NOT_MODIFIED) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->buffer = apr_palloc(r->pool, c->bufferSize);
        ctx->libz_end_func = inflateEnd;
        ctx->validation_buffer = NULL;
        ctx->validation_buffer_length = 0;

        zRC = inflateInit2(&ctx->stream, c->windowSize);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            inflateEnd(&ctx->stream);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unable to init Zlib: "
                          "inflateInit2 returned %d: URL %s",
                          zRC, r->uri);
            /*
             * Remove ourselves as it does not make sense to return:
             * We are not able to init libz and pass data down the chain
             * compressed.
             */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /*
         * Register a cleanup function to ensure that we cleanup the internal
         * libz resources.
         */
        apr_pool_cleanup_register(r->pool, ctx, deflate_ctx_cleanup,
                                  apr_pool_cleanup_null);

        /* initialize inflate output buffer */
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;

        ctx->inflate_init = 0;
    }

    while (!APR_BRIGADE_EMPTY(bb))
    {
        const char *data;
        apr_bucket *b;
        apr_size_t len;

        e = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(e)) {
            /*
             * We are really done now. Ensure that we never return here, even
             * if a second EOS bucket falls down the chain. Thus remove
             * ourselves.
             */
            ap_remove_output_filter(f);
            /* should be zero already anyway */
            ctx->stream.avail_in = 0;
            /*
             * Flush the remaining data from the zlib buffers. It is correct
             * to use Z_SYNC_FLUSH in this case and not Z_FINISH as in the
             * deflate case. In the inflate case Z_FINISH requires to have a
             * large enough output buffer to put ALL data in otherwise it
             * fails, whereas in the deflate case you can empty a filled output
             * buffer and call it again until no more output can be created.
             */
            flush_libz_buffer(ctx, c, f->c->bucket_alloc, inflate, Z_SYNC_FLUSH,
                              UPDATE_CRC);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "Zlib: Inflated %ld to %ld : URL %s",
                          ctx->stream.total_in, ctx->stream.total_out, r->uri);

            if (ctx->validation_buffer_length == VALIDATION_SIZE) {
                unsigned long compCRC, compLen;
                compCRC = getLong(ctx->validation_buffer);
                if (ctx->crc != compCRC) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Zlib: Checksum of inflated stream invalid");
                    return APR_EGENERAL;
                }
                ctx->validation_buffer += VALIDATION_SIZE / 2;
                compLen = getLong(ctx->validation_buffer);
                if (ctx->stream.total_out != compLen) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Zlib: Length of inflated stream invalid");
                    return APR_EGENERAL;
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Zlib: Validation bytes not present");
                return APR_EGENERAL;
            }

            inflateEnd(&ctx->stream);
            /* No need for cleanup any longer */
            apr_pool_cleanup_kill(r->pool, ctx, deflate_ctx_cleanup);

            /* Remove EOS from the old list, and insert into the new. */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /*
             * Okay, we've seen the EOS.
             * Time to pass it along down the chain.
             */
            return ap_pass_brigade(f->next, ctx->bb);
        }

        if (APR_BUCKET_IS_FLUSH(e)) {
            apr_status_t rv;

            /* flush the remaining data from the zlib buffers */
            zRC = flush_libz_buffer(ctx, c, f->c->bucket_alloc, inflate,
                                    Z_SYNC_FLUSH, UPDATE_CRC);
            if (zRC != Z_OK) {
                return APR_EGENERAL;
            }

            /* Remove flush bucket from old brigade anf insert into the new. */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            continue;
        }

        if (APR_BUCKET_IS_METADATA(e)) {
            /*
             * Remove meta data bucket from old brigade and insert into the
             * new.
             */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        /* read */
        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);

        /* first bucket contains zlib header */
        if (!ctx->inflate_init++) {
            if (len < 10) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Insufficient data for inflate");
                return APR_EGENERAL;
            }
            else  {
                zlib_method = data[2];
                zlib_flags = data[3];
                if (zlib_method != Z_DEFLATED) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "inflate: data not deflated!");
                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }
                if (data[0] != deflate_magic[0] ||
                    data[1] != deflate_magic[1] ||
                    (zlib_flags & RESERVED) != 0) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "inflate: bad header");
                    return APR_EGENERAL ;
                }
                data += 10 ;
                len -= 10 ;
           }
           if (zlib_flags & EXTRA_FIELD) {
               unsigned int bytes = (unsigned int)(data[0]);
               bytes += ((unsigned int)(data[1])) << 8;
               bytes += 2;
               if (len < bytes) {
                   ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                 "inflate: extra field too big (not "
                                 "supported)");
                   return APR_EGENERAL;
               }
               data += bytes;
               len -= bytes;
           }
           if (zlib_flags & ORIG_NAME) {
               while (len-- && *data++);
           }
           if (zlib_flags & COMMENT) {
               while (len-- && *data++);
           }
           if (zlib_flags & HEAD_CRC) {
                len -= 2;
                data += 2;
           }
        }

        /* pass through zlib inflate. */
        ctx->stream.next_in = (unsigned char *)data;
        ctx->stream.avail_in = len;

        if (ctx->validation_buffer) {
            if (ctx->validation_buffer_length < VALIDATION_SIZE) {
                apr_size_t copy_size;

                copy_size = VALIDATION_SIZE - ctx->validation_buffer_length;
                if (copy_size > ctx->stream.avail_in)
                    copy_size = ctx->stream.avail_in;
                memcpy(ctx->validation_buffer + ctx->validation_buffer_length,
                       ctx->stream.next_in, copy_size);
                /* Saved copy_size bytes */
                ctx->stream.avail_in -= copy_size;
                ctx->validation_buffer_length += copy_size;
            }
            if (ctx->stream.avail_in) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "Zlib: %d bytes of garbage at the end of "
                              "compressed stream.", ctx->stream.avail_in);
                /*
                 * There is nothing worth consuming for zlib left, because it is
                 * either garbage data or the data has been copied to the
                 * validation buffer (processing validation data is no business
                 * for zlib). So set ctx->stream.avail_in to zero to indicate
                 * this to the following while loop.
                 */
                ctx->stream.avail_in = 0;
            }
        }

        zRC = Z_OK;

        while (ctx->stream.avail_in != 0) {
            if (ctx->stream.avail_out == 0) {

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
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

            zRC = inflate(&ctx->stream, Z_NO_FLUSH);

            if (zRC == Z_STREAM_END) {
                /*
                 * We have inflated all data. Now try to capture the
                 * validation bytes. We may not have them all available
                 * right now, but capture what is there.
                 */
                ctx->validation_buffer = apr_pcalloc(f->r->pool,
                                                     VALIDATION_SIZE);
                if (ctx->stream.avail_in > VALIDATION_SIZE) {
                    ctx->validation_buffer_length = VALIDATION_SIZE;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "Zlib: %d bytes of garbage at the end of "
                                  "compressed stream.",
                                  ctx->stream.avail_in - VALIDATION_SIZE);
                } else if (ctx->stream.avail_in > 0) {
                           ctx->validation_buffer_length = ctx->stream.avail_in;
                }
                if (ctx->validation_buffer_length)
                    memcpy(ctx->validation_buffer, ctx->stream.next_in,
                           ctx->validation_buffer_length);
                break;
            }

            if (zRC != Z_OK) {
                return APR_EGENERAL;
            }
        }

        apr_bucket_delete(e);
    }

    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

#define PROTO_FLAGS AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH
static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(deflateFilterName, deflate_out_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
    ap_register_output_filter("INFLATE", inflate_out_filter, NULL,
                              AP_FTYPE_RESOURCE-1);
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
