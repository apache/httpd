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
 * mod_data.c --- Turn the response into an rfc2397 data URL, suitable for
 *                displaying as inline content on a page.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_base64.h"
#include "apr_lib.h"

#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#define DATA_FILTER "DATA"

module AP_MODULE_DECLARE_DATA data_module;

typedef struct data_ctx
{
    unsigned char overflow[3];
    int count;
    apr_bucket_brigade *bb;
} data_ctx;

/**
 * Create a data URL as follows:
 *
 * data:[<mime-type>;][charset=<charset>;]base64,<payload>
 *
 * Where:
 *
 * mime-type: The mime type of the original response.
 * charset: The optional character set corresponding to the mime type.
 * payload: A base64 version of the response body.
 *
 * The content type of the response is set to text/plain.
 *
 * The Content-Length header, if present, is updated with the new content
 * length based on the increase in size expected from the base64 conversion.
 * If the Content-Length header is too large to fit into an int, we remove
 * the Content-Length header instead.
 */
static apr_status_t data_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e, *ee;
    request_rec *r = f->r;
    data_ctx *ctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;

    /* first time in? create a context */
    if (!ctx) {
        char *type;
        char *charset = NULL;
        char *end;
        const char *content_length;

        /* base64-ing won't work on subrequests, it would be nice if
         * it did. Within subrequests, we have no EOS to check for,
         * so we don't know when to flush the tail to the network.
         */
        if (!ap_is_initial_req(f->r)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

        type = apr_pstrdup(r->pool, r->content_type);
        if (type) {
            charset = strchr(type, ' ');
            if (charset) {
                *charset++ = 0;
                end = strchr(charset, ' ');
                if (end) {
                    *end++ = 0;
                }
            }
        }

        apr_brigade_printf(ctx->bb, NULL, NULL, "data:%s%s;base64,",
                type ? type : "", charset ? charset : "");

        content_length = apr_table_get(r->headers_out, "Content-Length");
        if (content_length) {
            apr_off_t len, clen;
            apr_brigade_length(ctx->bb, 1, &len);
            if (ap_parse_strict_length(&clen, content_length)
                    && clen < APR_INT32_MAX) {
                ap_set_content_length(r, len +
                                      apr_base64_encode_len((int)clen) - 1);
            }
            else {
                apr_table_unset(r->headers_out, "Content-Length");
            }
        }

        ap_set_content_type_ex(r, "text/plain", 1);

    }

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(bb)) {
        const char *data;
        apr_size_t size;
        apr_size_t tail;
        apr_size_t len;
        /* buffer big enough for 8000 encoded bytes (6000 raw bytes) and terminator */
        char buffer[APR_BUCKET_BUFF_SIZE + 1];
        char encoded[((sizeof(ctx->overflow)) / 3) * 4 + 1];

        e = APR_BRIGADE_FIRST(bb);

        /* EOS means we are done. */
        if (APR_BUCKET_IS_EOS(e)) {

            /* write away the tail */
            if (ctx->count) {
                len = apr_base64_encode_binary(encoded, ctx->overflow,
                        ctx->count);
                apr_brigade_write(ctx->bb, NULL, NULL, encoded, len - 1);
                ctx->count = 0;
            }

            /* pass the EOS across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            ap_remove_output_filter(f);
            rv = ap_pass_brigade(f->next, ctx->bb);

            /* pass any stray buckets after the EOS down the stack */
            if ((APR_SUCCESS == rv) && (!APR_BRIGADE_EMPTY(bb))) {
               rv = ap_pass_brigade(f->next, bb);
            }
            continue;
        }

        /* flush what we can, we can't flush the tail until EOS */
        if (APR_BUCKET_IS_FLUSH(e)) {

            /* pass the flush bucket across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            continue;
        }

        /* metadata buckets are preserved as is */
        if (APR_BUCKET_IS_METADATA(e)) {
            /*
             * Remove meta data bucket from old brigade and insert into the
             * new.
             */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        /* make sure we don't read more than 6000 bytes at a time */
        apr_brigade_partition(bb, (APR_BUCKET_BUFF_SIZE / 4 * 3), &ee);

        /* size will never be more than 6000 bytes */
        if (APR_SUCCESS == (rv = apr_bucket_read(e, &data, &size,
                APR_BLOCK_READ))) {

            /* fill up and write out our overflow buffer if partially used */
            while (size && ctx->count && ctx->count < sizeof(ctx->overflow)) {
                ctx->overflow[ctx->count++] = *data++;
                size--;
            }
            if (ctx->count == sizeof(ctx->overflow)) {
                len = apr_base64_encode_binary(encoded, ctx->overflow,
                        sizeof(ctx->overflow));
                apr_brigade_write(ctx->bb, NULL, NULL, encoded, len - 1);
                ctx->count = 0;
            }

            /* write the main base64 chunk */
            tail = size % sizeof(ctx->overflow);
            size -= tail;
            if (size) {
                len = apr_base64_encode_binary(buffer,
                        (const unsigned char *) data, size);
                apr_brigade_write(ctx->bb, NULL, NULL, buffer, len - 1);
            }

            /* save away any tail in the overflow buffer */
            if (tail) {
                memcpy(ctx->overflow, data + size, tail);
                ctx->count += tail;
            }

            apr_bucket_delete(e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv) {
                /* should break out of the loop, since our write to the client
                 * failed in some way. */
                continue;
            }

        }

    }

    return rv;

}

static const command_rec data_cmds[] = { { NULL } };

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(DATA_FILTER, data_out_filter, NULL,
            AP_FTYPE_RESOURCE);
}
AP_DECLARE_MODULE(data) = { STANDARD20_MODULE_STUFF,
    NULL,  /* create per-directory config structure */
    NULL, /* merge per-directory config structures */
    NULL, /* create per-server config structure */
    NULL, /* merge per-server config structures */
    data_cmds, /* command apr_table_t */
    register_hooks /* register hooks */
};
