/*
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

#include "fcgid_bucket.h"
#include "fcgid_protocol.h"
#include "fcgid_bridge.h"

#define FCGID_FEED_LEN 8192
static apr_status_t fcgid_feed_data(fcgid_bucket_ctx * ctx,
                                    apr_bucket_alloc_t * bucketalloc,
                                    char **buffer, apr_size_t * bufferlen)
{
    apr_status_t rv;

    if (!ctx->buffer) {
        *buffer = apr_bucket_alloc(FCGID_FEED_LEN, bucketalloc);

        *bufferlen = FCGID_FEED_LEN;
        if ((rv =
             proc_read_ipc(&ctx->ipc, *buffer,
                           bufferlen)) != APR_SUCCESS) {
            ctx->has_error = 1;
            apr_bucket_free(*buffer);
            return rv;
        }

        ctx->buffer =
            apr_bucket_heap_create(*buffer, FCGID_FEED_LEN,
                                   apr_bucket_free, bucketalloc);
        if (*bufferlen != FCGID_FEED_LEN) {
            apr_bucket *buckettmp;

            apr_bucket_split(ctx->buffer, *bufferlen);
            buckettmp = APR_BUCKET_NEXT(ctx->buffer);
            apr_bucket_delete(buckettmp);
        }
    } else {
        apr_bucket_read(ctx->buffer, (const char **) buffer, bufferlen,
                        APR_BLOCK_READ);
    }
    return APR_SUCCESS;
}

static void fcgid_ignore_bytes(fcgid_bucket_ctx * ctx,
                               apr_size_t ignorebyte)
{
    apr_bucket *buckettmp;

    if (ignorebyte == ctx->buffer->length) {
        apr_bucket_destroy(ctx->buffer);
        ctx->buffer = NULL;
    } else {
        apr_bucket_split(ctx->buffer, ignorebyte);
        buckettmp = ctx->buffer;
        ctx->buffer = APR_BUCKET_NEXT(ctx->buffer);
        apr_bucket_delete(buckettmp);
    }
}

static apr_status_t fcgid_header_bucket_read(apr_bucket * b,
                                             const char **str,
                                             apr_size_t * len,
                                             apr_read_type_e block)
{
    fcgid_bucket_ctx *ctx = (fcgid_bucket_ctx *) b->data;
    apr_status_t rv;
    apr_size_t hasread, bodysize;
    FCGI_Header header;
    apr_bucket *curbucket = b;

    /* Keep reading until I get a fastcgi header */
    hasread = 0;
    while (hasread < sizeof(header)) {
        char *buffer;
        apr_size_t bufferlen, putsize;

        /* Feed some data if necessary */
        if ((rv =
             fcgid_feed_data(ctx, b->list, &buffer,
                             &bufferlen)) != APR_SUCCESS)
            return rv;

        /* Initialize header */
        putsize = fcgid_min(bufferlen, sizeof(header) - hasread);
        memcpy((apr_byte_t *)&header + hasread, buffer, putsize);
        hasread += putsize;

        /* Ignore the bytes that have read */
        fcgid_ignore_bytes(ctx, putsize);
    }

    /* Get the body size */
    bodysize = header.contentLengthB1;
    bodysize <<= 8;
    bodysize += header.contentLengthB0;

    /* Handle FCGI_STDERR body, write the content to log file */
    if (header.type == FCGI_STDERR) {
        char *logbuf = apr_bucket_alloc(APR_BUCKET_BUFF_SIZE, b->list);
        char *line;
        apr_size_t hasput;

        memset(logbuf, 0, APR_BUCKET_BUFF_SIZE);

        hasread = 0;
        hasput = 0;
        while (hasread < bodysize) {
            char *buffer;
            apr_size_t bufferlen, canput, willput;

            /* Feed some data if necessary */
            if ((rv =
                 fcgid_feed_data(ctx, b->list, &buffer,
                                 &bufferlen)) != APR_SUCCESS) {
                apr_bucket_free(logbuf);
                return rv;
            }

            canput = fcgid_min(bufferlen, bodysize - hasread);
            willput =
                fcgid_min(canput, APR_BUCKET_BUFF_SIZE - hasput - 1);
            memcpy(logbuf + hasput, buffer, willput);
            hasread += canput;
            hasput += willput;

            /* Ignore the "canput" bytes */
            fcgid_ignore_bytes(ctx, canput);
        }

        /* Now I get the log data, write log and release the buffer */
        line = logbuf;
        while (*line) {
            char *end = strpbrk(line, "\r\n");

            if (end != NULL) {
                *end = '\0';
            }
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, ctx->ipc.request,
                          "mod_fcgid: stderr: %s", line);
            if (end == NULL) {
                break;
            }
            ++end;
            line = end + strspn(end, "\r\n");
        }

        apr_bucket_free(logbuf);
    }

    /* if( header.type==FCGI_STDERR ) */
    /* Now handle FCGI_STDOUT */
    else if (header.type == FCGI_STDOUT) {
        hasread = 0;
        while (hasread < bodysize) {
            char *buffer;
            apr_size_t bufferlen, canput;
            apr_bucket *buckettmp;

            /* Feed some data if necessary */
            if ((rv =
                 fcgid_feed_data(ctx, b->list, &buffer,
                                 &bufferlen)) != APR_SUCCESS)
                return rv;

            canput = fcgid_min(bufferlen, bodysize - hasread);

            /* Change the current bucket to refer to what we read */
            buckettmp = ctx->buffer;
            if (canput == (bodysize - hasread)) {
                apr_bucket_split(ctx->buffer, canput);
                ctx->buffer = APR_BUCKET_NEXT(ctx->buffer);
                APR_BUCKET_REMOVE(buckettmp);
            } else {
                /* canput==bufferlen */
                ctx->buffer = NULL;
            }

            APR_BUCKET_INSERT_AFTER(curbucket, buckettmp);
            curbucket = buckettmp;
            hasread += canput;
        }                       /* while( hasread<bodysize ) */
    }

    /* if( header.type==FCGI_STDOUT ) */
    /* Now FCGI_END_REQUEST */
    else if (header.type == FCGI_END_REQUEST) {
        /* Just ignore the body */
        hasread = 0;
        while (hasread < bodysize) {
            char *buffer;
            apr_size_t bufferlen, canignore;

            /* Feed some data if necessary */
            if ((rv =
                 fcgid_feed_data(ctx, b->list, &buffer,
                                 &bufferlen)) != APR_SUCCESS)
                return rv;

            canignore = fcgid_min(bufferlen, bodysize);
            hasread += canignore;

            /* Ignore the bytes */
            fcgid_ignore_bytes(ctx, canignore);
        }
    }

    /* Now ignore padding data */
    hasread = 0;
    while (hasread < header.paddingLength) {
        char *buffer;
        apr_size_t bufferlen, canignore;

        /* Feed some data if necessary */
        if ((rv =
             fcgid_feed_data(ctx, b->list, &buffer,
                             &bufferlen)) != APR_SUCCESS)
            return rv;

        canignore = fcgid_min(bufferlen, header.paddingLength - hasread);
        hasread += canignore;

        /* Ignore the bytes */
        fcgid_ignore_bytes(ctx, canignore);
    }

    /* Tail another fastcgi header bucket if it's not ending */
    if (header.type != FCGI_END_REQUEST) {
        apr_bucket *headerbucket =
            ap_bucket_fcgid_header_create(b->list, ctx);
        APR_BUCKET_INSERT_AFTER(curbucket, headerbucket);
    } else {
        /* Release the process ASAP */
        if ((rv = apr_pool_cleanup_run(ctx->ipc.request->pool,
                                       ctx,
                                       bucket_ctx_cleanup)) != APR_SUCCESS)
            return rv;
    }

    b = apr_bucket_immortal_make(b, "", 0);
    return apr_bucket_read(b, str, len, APR_BLOCK_READ);
}

apr_bucket *ap_bucket_fcgid_header_make(apr_bucket * b,
                                        fcgid_bucket_ctx * ctx)
{
    b->length = (apr_size_t) (-1);
    b->start = -1;
    b->data = ctx;
    b->type = &ap_bucket_type_fcgid_header;

    return b;
}

apr_bucket *ap_bucket_fcgid_header_create(apr_bucket_alloc_t * list,
                                          fcgid_bucket_ctx * ctx)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return ap_bucket_fcgid_header_make(b, ctx);
}

const apr_bucket_type_t ap_bucket_type_fcgid_header = {
    "FCGID_HEADER", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    fcgid_header_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};
