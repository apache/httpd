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
#include "http_core.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "mod_ssl.h"

#include "zlib.h"

static const char deflateFilterName[] = "DEFLATE";
module AP_MODULE_DECLARE_DATA deflate_module;

#define AP_INFLATE_RATIO_LIMIT 200
#define AP_INFLATE_RATIO_BURST 3

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

typedef struct deflate_dirconf_t {
    apr_off_t inflate_limit;
    int ratio_limit,
        ratio_burst;
} deflate_dirconf_t;

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

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *mod_deflate_ssl_var = NULL;

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
            /* If the outermost encoding isn't gzip, there's nothing
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

static void *create_deflate_dirconf(apr_pool_t *p, char *dummy)
{
    deflate_dirconf_t *dc = apr_pcalloc(p, sizeof(*dc));
    dc->ratio_limit = AP_INFLATE_RATIO_LIMIT;
    dc->ratio_burst = AP_INFLATE_RATIO_BURST;
    return dc;
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


static const char *deflate_set_inflate_limit(cmd_parms *cmd, void *dirconf,
                                      const char *arg)
{
    deflate_dirconf_t *dc = (deflate_dirconf_t*) dirconf;
    char *errp;

    if (APR_SUCCESS != apr_strtoff(&dc->inflate_limit, arg, &errp, 10)) {
        return "DeflateInflateLimitRequestBody is not parsable.";
    }
    if (*errp || dc->inflate_limit < 0) {
        return "DeflateInflateLimitRequestBody requires a non-negative integer.";
    }

    return NULL;
}

static const char *deflate_set_inflate_ratio_limit(cmd_parms *cmd,
                                                   void *dirconf,
                                                   const char *arg)
{
    deflate_dirconf_t *dc = (deflate_dirconf_t*) dirconf;
    int i;

    i = atoi(arg);
    if (i <= 0)
        return "DeflateInflateRatioLimit must be positive";

    dc->ratio_limit = i;

    return NULL;
}

static const char *deflate_set_inflate_ratio_burst(cmd_parms *cmd,
                                                   void *dirconf,
                                                   const char *arg)
{
    deflate_dirconf_t *dc = (deflate_dirconf_t*) dirconf;
    int i;

    i = atoi(arg);
    if (i <= 0)
        return "DeflateInflateRatioBurst must be positive";

    dc->ratio_burst = i;

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
    char header[10]; /* sizeof(gzip_header) */
    apr_size_t header_len;
    int zlib_flags;
    int ratio_hits;
    apr_off_t inflate_total;
    unsigned int consume_pos,
                 consume_len;
    unsigned int filter_init:1;
    unsigned int done:1;
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

/* Check whether the (inflate) ratio exceeds the configured limit/burst. */
static int check_ratio(request_rec *r, deflate_ctx *ctx,
                       const deflate_dirconf_t *dc)
{
    if (ctx->stream.total_in) {
        int ratio = ctx->stream.total_out / ctx->stream.total_in;
        if (ratio < dc->ratio_limit) {
            ctx->ratio_hits = 0;
        }
        else if (++ctx->ratio_hits > dc->ratio_burst) {
            return 0;
        }
    }
    return 1;
}

static int have_ssl_compression(request_rec *r)
{
    const char *comp;
    if (mod_deflate_ssl_var == NULL)
        return 0;
    comp = mod_deflate_ssl_var(r->pool, r->server, r->connection, r,
                               "SSL_COMPRESS_METHOD");
    if (comp == NULL || *comp == '\0' || strcmp(comp, "NULL") == 0)
        return 0;
    return 1;
}

static apr_status_t deflate_out_filter(ap_filter_t *f,
                                       apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_size_t len = 0, blen;
    const char *data;
    deflate_filter_config *c;

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
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

        if (have_ssl_compression(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "Compression enabled at SSL level; not compressing "
                          "at HTTP level.");
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* We have checked above that bb is not empty */
        e = APR_BRIGADE_LAST(bb);
        if (APR_BUCKET_IS_EOS(e)) {
            /*
             * If we already know the size of the response, we can skip
             * compression on responses smaller than the compression overhead.
             * However, if we compress, we must initialize deflate_out before
             * calling ap_pass_brigade() for the first time.  Otherwise the
             * headers will be sent to the client without
             * "Content-Encoding: gzip".
             */
            e = APR_BRIGADE_FIRST(bb);
            while (1) {
                apr_status_t rc;
                if (APR_BUCKET_IS_EOS(e)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                                  "Not compressing very small response of %"
                                  APR_SIZE_T_FMT " bytes", len);
                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }
                if (APR_BUCKET_IS_METADATA(e)) {
                    e = APR_BUCKET_NEXT(e);
                    continue;
                }

                rc = apr_bucket_read(e, &data, &blen, APR_BLOCK_READ);
                if (rc != APR_SUCCESS)
                    return rc;
                len += blen;
                /* 50 is for Content-Encoding and Vary headers and ETag suffix */
                if (len > sizeof(gzip_header) + VALIDATION_SIZE + 50)
                    break;

                e = APR_BUCKET_NEXT(e);
            }
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));

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
            if (APLOG_R_IS_LEVEL(r, APLOG_TRACE1)) {
                const char *reason =
                    (r->main != NULL)                           ? "subrequest" :
                    (r->status == HTTP_NO_CONTENT)              ? "no content" :
                    apr_table_get(r->subprocess_env, "no-gzip") ? "no-gzip" :
                    "content-range";
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                              "Not compressing (%s)", reason);
            }
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
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                              "Not compressing, (gzip-only-text/html)");
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
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                                  "Not compressing (content-encoding already "
                                  " set: %s)", token);
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
                    ap_get_token(r->pool, &accepts, 1);
                }

                /* retrieve next token */
                if (*accepts == ',') {
                    ++accepts;
                }
                token = (*accepts) ? ap_get_token(r->pool, &accepts, 0) : NULL;
            }

            /* No acceptable token found. */
            if (token == NULL || token[0] == '\0') {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                              "Not compressing (no Accept-Encoding: gzip)");
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "Forcing compression (force-gzip set)");
        }

        /* At this point we have decided to filter the content. Let's try to
         * to initialize zlib (except for 304 responses, where we will only
         * send out the headers).
         */

        if (r->status != HTTP_NOT_MODIFIED) {
            ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
            ctx->buffer = apr_palloc(r->pool, c->bufferSize);
            ctx->libz_end_func = deflateEnd;

            zRC = deflateInit2(&ctx->stream, c->compressionlevel, Z_DEFLATED,
                               c->windowSize, c->memlevel,
                               Z_DEFAULT_STRATEGY);

            if (zRC != Z_OK) {
                deflateEnd(&ctx->stream);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01383)
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

            /* Set the filter init flag so subsequent invocations know we are
             * active.
             */
            ctx->filter_init = 1;
        }

        /*
         * Zlib initialization worked, so we can now change the important
         * content metadata before sending the response out.
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

        /* add immortal gzip header */
        e = apr_bucket_immortal_create(gzip_header, sizeof gzip_header,
                                       f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        /* initialize deflate output buffer */
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;
    } else if (!ctx->filter_init) {
        /* Hmm.  We've run through the filter init before as we have a ctx,
         * but we never initialized.  We probably have a dangling ref.  Bail.
         */
        return ap_pass_brigade(f->next, bb);
    }

    while (!APR_BRIGADE_EMPTY(bb))
    {
        apr_bucket *b;

        /*
         * Optimization: If we are a HEAD request and bytes_sent is not zero
         * it means that we have passed the content-length filter once and
         * have more data to sent. This means that the content-length filter
         * could not determine our content-length for the response to the
         * HEAD request anyway (the associated GET request would deliver the
         * body in chunked encoding) and we can stop compressing.
         */
        if (r->header_only && r->bytes_sent) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01384)
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01385)
                              "Zlib error %d flushing zlib output buffer (%s)",
                              zRC, ctx->stream.msg);
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
        if (!len) {
            apr_bucket_delete(e);
            continue;
        }
        if (len > APR_INT32_MAX) {
            apr_bucket_split(e, APR_INT32_MAX);
            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        }

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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01386)
                              "Zlib error %d deflating data (%s)", zRC,
                              ctx->stream.msg);
                return APR_EGENERAL;
            }
        }

        apr_bucket_delete(e);
    }

    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

static apr_status_t consume_zlib_flags(deflate_ctx *ctx,
                                       const char **data, apr_size_t *len)
{
    if ((ctx->zlib_flags & EXTRA_FIELD)) {
        /* Consume 2 bytes length prefixed data. */
        if (ctx->consume_pos == 0) {
            if (!*len) {
                return APR_INCOMPLETE;
            }
            ctx->consume_len = (unsigned int)**data;
            ctx->consume_pos++;
            ++*data;
            --*len;
        }
        if (ctx->consume_pos == 1) {
            if (!*len) {
                return APR_INCOMPLETE;
            }
            ctx->consume_len += ((unsigned int)**data) << 8;
            ctx->consume_pos++;
            ++*data;
            --*len;
        }
        if (*len < ctx->consume_len) {
            ctx->consume_len -= *len;
            *len = 0;
            return APR_INCOMPLETE;
        }
        *data += ctx->consume_len;
        *len -= ctx->consume_len;

        ctx->consume_len = ctx->consume_pos = 0;
        ctx->zlib_flags &= ~EXTRA_FIELD;
    }

    if ((ctx->zlib_flags & ORIG_NAME)) {
        /* Consume nul terminated string. */
        while (*len && **data) {
            ++*data;
            --*len;
        }
        if (!*len) {
            return APR_INCOMPLETE;
        }
        /* .. and nul. */
        ++*data;
        --*len;

        ctx->zlib_flags &= ~ORIG_NAME;
    }

    if ((ctx->zlib_flags & COMMENT)) {
        /* Consume nul terminated string. */
        while (*len && **data) {
            ++*data;
            --*len;
        }
        if (!*len) {
            return APR_INCOMPLETE;
        }
        /* .. and nul. */
        ++*data;
        --*len;

        ctx->zlib_flags &= ~COMMENT;
    }

    if ((ctx->zlib_flags & HEAD_CRC)) {
        /* Consume CRC16 (2 octets). */
        if (ctx->consume_pos == 0) {
            if (!*len) {
                return APR_INCOMPLETE;
            }
            ctx->consume_pos++;
            ++*data;
            --*len;
        }
        if (!*len) {
            return APR_INCOMPLETE;
        }
        ++*data;
        --*len;
        
        ctx->consume_pos = 0;
        ctx->zlib_flags &= ~HEAD_CRC;
    }

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
    deflate_dirconf_t *dc;
    apr_off_t inflate_limit;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);
    dc = ap_get_module_config(r->per_dir_config, &deflate_module);

    if (!ctx || ctx->header_len < sizeof(ctx->header)) {
        apr_size_t len;

        if (!ctx) {
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
        }

        do {
            apr_brigade_cleanup(ctx->bb);

            len = sizeof(ctx->header) - ctx->header_len;
            rv = ap_get_brigade(f->next, ctx->bb, AP_MODE_READBYTES, block,
                                len);

            /* ap_get_brigade may return success with an empty brigade for
             * a non-blocking read which would block (an empty brigade for
             * a blocking read is an issue which is simply forwarded here).
             */
            if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(ctx->bb)) {
                return rv;
            }

            /* zero length body? step aside */
            bkt = APR_BRIGADE_FIRST(ctx->bb);
            if (APR_BUCKET_IS_EOS(bkt)) {
                if (ctx->header_len) {
                    /* If the header was (partially) read it's an error, this
                     * is not a gzip Content-Encoding, as claimed.
                     */
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02619)
                                  "Encountered premature end-of-stream while "
                                  "reading inflate header");
                    return APR_EGENERAL;
                }
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_INSERT_TAIL(bb, bkt);
                ap_remove_input_filter(f);
                return APR_SUCCESS;
            }

            rv = apr_brigade_flatten(ctx->bb,
                                     ctx->header + ctx->header_len, &len);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            if (len && !ctx->header_len) {
                apr_table_unset(r->headers_in, "Content-Length");
                apr_table_unset(r->headers_in, "Content-MD5");
            }
            ctx->header_len += len;

        } while (ctx->header_len < sizeof(ctx->header));

        /* We didn't get the magic bytes. */
        if (ctx->header[0] != deflate_magic[0] ||
            ctx->header[1] != deflate_magic[1]) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01387)
                          "Zlib: Invalid header");
            return APR_EGENERAL;
        }

        ctx->zlib_flags = ctx->header[3];
        if ((ctx->zlib_flags & RESERVED)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01388)
                          "Zlib: Invalid flags %02x", ctx->zlib_flags);
            return APR_EGENERAL;
        }

        zRC = inflateInit2(&ctx->stream, c->windowSize);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            inflateEnd(&ctx->stream);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01389)
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

    inflate_limit = dc->inflate_limit; 
    if (inflate_limit == 0) { 
        /* The core is checking the deflated body, we'll check the inflated */
        inflate_limit = ap_get_limit_req_body(f->r);
    }

    if (APR_BRIGADE_EMPTY(ctx->proc_bb)) {
        rv = ap_get_brigade(f->next, ctx->bb, mode, block, readbytes);

        /* Don't terminate on EAGAIN (or success with an empty brigade in
         * non-blocking mode), just return focus.
         */
        if (block == APR_NONBLOCK_READ
                && (APR_STATUS_IS_EAGAIN(rv)
                    || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(ctx->bb)))) {
            return rv;
        }
        if (rv != APR_SUCCESS) {
            inflateEnd(&ctx->stream);
            return rv;
        }

        for (bkt = APR_BRIGADE_FIRST(ctx->bb);
             bkt != APR_BRIGADE_SENTINEL(ctx->bb);
             bkt = APR_BUCKET_NEXT(bkt))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bkt)) {
                if (!ctx->done) {
                    inflateEnd(&ctx->stream);
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02481)
                                  "Encountered premature end-of-stream while inflating");
                    return APR_EGENERAL;
                }

                /* Move everything to the returning brigade. */
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, bkt);
                break;
            }

            if (APR_BUCKET_IS_FLUSH(bkt)) {
                apr_bucket *tmp_b;
                zRC = inflate(&(ctx->stream), Z_SYNC_FLUSH);
                if (zRC != Z_OK) {
                    inflateEnd(&ctx->stream);
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01391)
                                  "Zlib error %d inflating data (%s)", zRC,
                                  ctx->stream.msg);
                    return APR_EGENERAL;
                }

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;
 
                ctx->inflate_total += len;
                if (inflate_limit && ctx->inflate_total > inflate_limit) { 
                    inflateEnd(&ctx->stream);
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02647)
                            "Inflated content length of %" APR_OFF_T_FMT
                            " is larger than the configured limit"
                            " of %" APR_OFF_T_FMT, 
                            ctx->inflate_total, inflate_limit);
                    return APR_ENOSPC;
                }

                if (!check_ratio(r, ctx, dc)) {
                    inflateEnd(&ctx->stream);
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02805)
                            "Inflated content ratio is larger than the "
                            "configured limit %i by %i time(s)",
                            dc->ratio_limit, dc->ratio_burst);
                    return APR_EINVAL;
                }

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_b = apr_bucket_heap_create((char *)ctx->buffer, len,
                                                NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_b);
                ctx->stream.avail_out = c->bufferSize;

                /* Flush everything so far in the returning brigade, but continue
                 * reading should EOS/more follow (don't lose them).
                 */
                tmp_b = APR_BUCKET_PREV(bkt);
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, bkt);
                bkt = tmp_b;
                continue;
            }

            /* sanity check - data after completed compressed body and before eos? */
            if (ctx->done) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02482)
                              "Encountered extra data after compressed data");
                return APR_EGENERAL;
            }

            /* read */
            apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
            if (!len) {
                continue;
            }
            if (len > APR_INT32_MAX) {
                apr_bucket_split(bkt, APR_INT32_MAX);
                apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
            }

            if (ctx->zlib_flags) {
                rv = consume_zlib_flags(ctx, &data, &len);
                if (rv == APR_SUCCESS) {
                    ctx->zlib_flags = 0;
                }
                if (!len) {
                    continue;
                }
            }

            /* pass through zlib inflate. */
            ctx->stream.next_in = (unsigned char *)data;
            ctx->stream.avail_in = (int)len;

            zRC = Z_OK;

            if (!ctx->validation_buffer) {
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

                    len = ctx->stream.avail_out;
                    zRC = inflate(&ctx->stream, Z_NO_FLUSH);

                    if (zRC != Z_OK && zRC != Z_STREAM_END) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01392)
                                      "Zlib error %d inflating data (%s)", zRC,
                                      ctx->stream.msg);
                        return APR_EGENERAL;
                    }

                    ctx->inflate_total += len - ctx->stream.avail_out;
                    if (inflate_limit && ctx->inflate_total > inflate_limit) { 
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02648)
                                "Inflated content length of %" APR_OFF_T_FMT
                                " is larger than the configured limit"
                                " of %" APR_OFF_T_FMT, 
                                ctx->inflate_total, inflate_limit);
                        return APR_ENOSPC;
                    }

                    if (!check_ratio(r, ctx, dc)) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02649)
                                "Inflated content ratio is larger than the "
                                "configured limit %i by %i time(s)",
                                dc->ratio_limit, dc->ratio_burst);
                        return APR_EINVAL;
                    }

                    if (zRC == Z_STREAM_END) {
                        ctx->validation_buffer = apr_pcalloc(r->pool,
                                                             VALIDATION_SIZE);
                        ctx->validation_buffer_length = 0;
                        break;
                    }
                }
            }

            if (ctx->validation_buffer) {
                apr_bucket *tmp_heap;
                apr_size_t avail, valid;
                unsigned char *buf = ctx->validation_buffer;

                avail = ctx->stream.avail_in;
                valid = (apr_size_t)VALIDATION_SIZE -
                         ctx->validation_buffer_length;

                /*
                 * We have inflated all data. Now try to capture the
                 * validation bytes. We may not have them all available
                 * right now, but capture what is there.
                 */
                if (avail < valid) {
                    memcpy(buf + ctx->validation_buffer_length,
                           ctx->stream.next_in, avail);
                    ctx->validation_buffer_length += avail;
                    continue;
                }
                memcpy(buf + ctx->validation_buffer_length,
                       ctx->stream.next_in, valid);
                ctx->validation_buffer_length += valid;

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01393)
                              "Zlib: Inflated %ld to %ld : URL %s",
                              ctx->stream.total_in, ctx->stream.total_out,
                              r->uri);

                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len,
                                                  NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
                ctx->stream.avail_out = c->bufferSize;

                {
                    unsigned long compCRC, compLen;
                    compCRC = getLong(buf);
                    if (ctx->crc != compCRC) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01394)
                                      "Zlib: CRC error inflating data");
                        return APR_EGENERAL;
                    }
                    compLen = getLong(buf + VALIDATION_SIZE / 2);
                    /* gzip stores original size only as 4 byte value */
                    if ((ctx->stream.total_out & 0xFFFFFFFF) != compLen) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01395)
                                      "Zlib: Length %ld of inflated data does "
                                      "not match expected value %ld",
                                      ctx->stream.total_out, compLen);
                        return APR_EGENERAL;
                    }
                }

                inflateEnd(&ctx->stream);

                ctx->done = 1;

                /* Did we have trailing data behind the closing 8 bytes? */
                if (avail > valid) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02485)
                                  "Encountered extra data after compressed data");
                    return APR_EGENERAL;
                }
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
        if (apr_brigade_partition(ctx->proc_bb, readbytes, &bkt) == APR_INCOMPLETE) {
            APR_BRIGADE_CONCAT(bb, ctx->proc_bb);
        }
        else {
            APR_BRIGADE_CONCAT(bb, ctx->proc_bb);
            apr_brigade_split_ex(bb, bkt, ctx->proc_bb);
        }
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
            ap_remove_input_filter(f);
        }
    }

    return APR_SUCCESS;
}


/* Filter to inflate for a content-transforming proxy.  */
static apr_status_t inflate_out_filter(ap_filter_t *f,
                                      apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_status_t rv;
    deflate_filter_config *c;
    deflate_dirconf_t *dc;

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);
    dc = ap_get_module_config(r->per_dir_config, &deflate_module);

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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01397)
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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01398)
                          "Zlib: Inflated %ld to %ld : URL %s",
                          ctx->stream.total_in, ctx->stream.total_out, r->uri);

            if (ctx->validation_buffer_length == VALIDATION_SIZE) {
                unsigned long compCRC, compLen;
                compCRC = getLong(ctx->validation_buffer);
                if (ctx->crc != compCRC) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01399)
                                  "Zlib: Checksum of inflated stream invalid");
                    return APR_EGENERAL;
                }
                ctx->validation_buffer += VALIDATION_SIZE / 2;
                compLen = getLong(ctx->validation_buffer);
                /* gzip stores original size only as 4 byte value */
                if ((ctx->stream.total_out & 0xFFFFFFFF) != compLen) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01400)
                                  "Zlib: Length of inflated stream invalid");
                    return APR_EGENERAL;
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01401)
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
            if (zRC == Z_STREAM_END) {
                if (ctx->validation_buffer == NULL) {
                    ctx->validation_buffer = apr_pcalloc(f->r->pool,
                                                         VALIDATION_SIZE);
                }
            }
            else if (zRC != Z_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01402)
                              "Zlib error %d flushing inflate buffer (%s)",
                              zRC, ctx->stream.msg);
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
        if (!len) {
            apr_bucket_delete(e);
            continue;
        }
        if (len > APR_INT32_MAX) {
            apr_bucket_split(e, APR_INT32_MAX);
            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        }

        /* first bucket contains zlib header */
        if (ctx->header_len < sizeof(ctx->header)) {
            apr_size_t rem;

            rem = sizeof(ctx->header) - ctx->header_len;
            if (len < rem) {
                memcpy(ctx->header + ctx->header_len, data, len);
                ctx->header_len += len;
                apr_bucket_delete(e);
                continue;
            }
            memcpy(ctx->header + ctx->header_len, data, rem);
            ctx->header_len += rem;
            {
                int zlib_method;
                zlib_method = ctx->header[2];
                if (zlib_method != Z_DEFLATED) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01404)
                                  "inflate: data not deflated!");
                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }
                if (ctx->header[0] != deflate_magic[0] ||
                    ctx->header[1] != deflate_magic[1]) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01405)
                                      "inflate: bad header");
                    return APR_EGENERAL ;
                }
                ctx->zlib_flags = ctx->header[3];
                if ((ctx->zlib_flags & RESERVED)) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02620)
                                  "inflate: bad flags %02x",
                                  ctx->zlib_flags);
                    return APR_EGENERAL;
                }
            }
            if (len == rem) {
                apr_bucket_delete(e);
                continue;
            }
            data += rem;
            len -= rem;
        }

        if (ctx->zlib_flags) {
            rv = consume_zlib_flags(ctx, &data, &len);
            if (rv == APR_SUCCESS) {
                ctx->zlib_flags = 0;
            }
            if (!len) {
                apr_bucket_delete(e);
                continue;
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
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01407)
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

            if (zRC != Z_OK && zRC != Z_STREAM_END) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01409)
                              "Zlib error %d inflating data (%s)", zRC,
                              ctx->stream.msg);
                return APR_EGENERAL;
            }

            if (!check_ratio(r, ctx, dc)) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02650)
                              "Inflated content ratio is larger than the "
                              "configured limit %i by %i time(s)",
                              dc->ratio_limit, dc->ratio_burst);
                return APR_EINVAL;
            }

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
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01408)
                                  "Zlib: %d bytes of garbage at the end of "
                                  "compressed stream.",
                                  ctx->stream.avail_in - VALIDATION_SIZE);
                }
                else if (ctx->stream.avail_in > 0) {
                    ctx->validation_buffer_length = ctx->stream.avail_in;
                }
                if (ctx->validation_buffer_length)
                    memcpy(ctx->validation_buffer, ctx->stream.next_in,
                           ctx->validation_buffer_length);
                break;
            }
        }

        apr_bucket_delete(e);
    }

    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

static int mod_deflate_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    mod_deflate_ssl_var = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    return OK;
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
    ap_hook_post_config(mod_deflate_post_config, NULL, NULL, APR_HOOK_MIDDLE);
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
    AP_INIT_TAKE1("DeflateInflateLimitRequestBody", deflate_set_inflate_limit, NULL, OR_ALL,
                  "Set a limit on size of inflated input"),
    AP_INIT_TAKE1("DeflateInflateRatioLimit", deflate_set_inflate_ratio_limit, NULL, OR_ALL,
                  "Set the inflate ratio limit above which inflation is "
                  "aborted (default: " APR_STRINGIFY(AP_INFLATE_RATIO_LIMIT) ")"),
    AP_INIT_TAKE1("DeflateInflateRatioBurst", deflate_set_inflate_ratio_burst, NULL, OR_ALL,
                  "Set the maximum number of following inflate ratios above limit "
                  "(default: " APR_STRINGIFY(AP_INFLATE_RATIO_BURST) ")"),
    {NULL}
};

AP_DECLARE_MODULE(deflate) = {
    STANDARD20_MODULE_STUFF,
    create_deflate_dirconf,       /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    create_deflate_server_config, /* server config */
    NULL,                         /* merge server config */
    deflate_filter_cmds,          /* command table */
    register_hooks                /* register hooks */
};
