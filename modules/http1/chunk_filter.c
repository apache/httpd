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
 * chunk_filter.c --- HTTP/1.1 chunked transfer encoding filter.
 */

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"  /* For index_of_response().  Grump. */
#include "http_request.h"

#include "util_filter.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#include "apr_date.h"           /* For apr_date_parse_http and APR_DATE_BAD */
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"

#include "mod_core.h"
#include "mod_http1.h"


APLOG_USE_MODULE(http1);


typedef struct chunk_out_ctx {
    int bad_gateway_seen;
    apr_table_t *trailers;
} chunk_out_ctx;


apr_status_t ap_http_chunk_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    conn_rec *c = f->r->connection;
    chunk_out_ctx *ctx = f->ctx;
    apr_bucket_brigade *more, *tmp;
    apr_bucket *e;
    apr_status_t rv;

    if (!ctx) {
        ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
    }

    for (more = tmp = NULL; b; b = more, more = NULL) {
        apr_off_t bytes = 0;
        apr_bucket *eos = NULL;
        apr_bucket *flush = NULL;
        /* XXX: chunk_hdr must remain at this scope since it is used in a
         *      transient bucket.
         */
        char chunk_hdr[20]; /* enough space for the snprintf below */


        for (e = APR_BRIGADE_FIRST(b);
             e != APR_BRIGADE_SENTINEL(b);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_METADATA(e)) {
                if (APR_BUCKET_IS_EOS(e)) {
                    /* there shouldn't be anything after the eos */
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, f->r,
                                  "ap_http_chunk_filter eos seen, removing filter");
                    ap_remove_output_filter(f);
                    eos = e;
                    break;
                }
                if (AP_BUCKET_IS_ERROR(e) &&
                    (((ap_bucket_error *)(e->data))->status == HTTP_BAD_GATEWAY ||
                     ((ap_bucket_error *)(e->data))->status == HTTP_GATEWAY_TIME_OUT)) {
                    /*
                     * We had a broken backend. Memorize this in the filter
                     * context.
                     */
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, f->r,
                                  "ap_http_chunk_filter bad gateway error, suppressing end chunk");
                    ctx->bad_gateway_seen = 1;
                    continue;
                }
                if (APR_BUCKET_IS_FLUSH(e)) {
                    flush = e;
                    if (e != APR_BRIGADE_LAST(b)) {
                        more = apr_brigade_split_ex(b, APR_BUCKET_NEXT(e), tmp);
                    }
                    break;
                }
                if (AP_BUCKET_IS_HEADERS(e)) {
                    ap_bucket_headers *hdrs = e->data;
                    if (!hdrs->status && !apr_is_empty_table(hdrs->headers)) {
                        if (!ctx->trailers) {
                            ctx->trailers = apr_table_make(f->r->pool, 5);
                        }
                        apr_table_overlap(ctx->trailers, hdrs->headers, APR_OVERLAP_TABLES_MERGE);
                    }
                }
            }
            else if (e->length == (apr_size_t)-1) {
                /* unknown amount of data (e.g. a pipe) */
                const char *data;
                apr_size_t len;

                rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
                if (len > 0) {
                    /*
                     * There may be a new next bucket representing the
                     * rest of the data stream on which a read() may
                     * block so we pass down what we have so far.
                     */
                    bytes += len;
                    more = apr_brigade_split_ex(b, APR_BUCKET_NEXT(e), tmp);
                    break;
                }
                else {
                    /* If there was nothing in this bucket then we can
                     * safely move on to the next one without pausing
                     * to pass down what we have counted up so far.
                     */
                    continue;
                }
            }
            else {
                bytes += e->length;
            }
        }

        /*
         * XXX: if there aren't very many bytes at this point it may
         * be a good idea to set them aside and return for more,
         * unless we haven't finished counting this brigade yet.
         */
        /* if there are content bytes, then wrap them in a chunk */
        if (bytes > 0) {
            apr_size_t hdr_len;
            /*
             * Insert the chunk header, specifying the number of bytes in
             * the chunk.
             */
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, f->r,
                          "ap_http_chunk_filter sending chunk of %"
                          APR_UINT64_T_HEX_FMT " bytes", (apr_uint64_t)bytes);
            hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                                   "%" APR_UINT64_T_HEX_FMT CRLF, (apr_uint64_t)bytes);
            ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
            e = apr_bucket_transient_create(chunk_hdr, hdr_len,
                                            c->bucket_alloc);
            APR_BRIGADE_INSERT_HEAD(b, e);

            /*
             * Insert the end-of-chunk CRLF before an EOS or
             * FLUSH bucket, or appended to the brigade
             */
            e = apr_bucket_immortal_create(CRLF_ASCII, 2, c->bucket_alloc);
            if (eos != NULL) {
                APR_BUCKET_INSERT_BEFORE(eos, e);
            }
            else if (flush != NULL) {
                APR_BUCKET_INSERT_BEFORE(flush, e);
            }
            else {
                APR_BRIGADE_INSERT_TAIL(b, e);
            }
        }

        /* RFC 2616, Section 3.6.1
         *
         * If there is an EOS bucket, then prefix it with:
         *   1) the last-chunk marker ("0" CRLF)
         *   2) the trailer
         *   3) the end-of-chunked body CRLF
         *
         * We only do this if we have not seen an error bucket with
         * status HTTP_BAD_GATEWAY. We have memorized an
         * error bucket that we had seen in the filter context.
         * The error bucket with status HTTP_BAD_GATEWAY indicates that the
         * connection to the backend (mod_proxy) broke in the middle of the
         * response. In order to signal the client that something went wrong
         * we do not create the last-chunk marker and set c->keepalive to
         * AP_CONN_CLOSE in the core output filter.
         *
         * XXX: it would be nice to combine this with the end-of-chunk
         * marker above, but this is a bit more straight-forward for
         * now.
         */
        if (eos && !ctx->bad_gateway_seen) {
            if (!ctx->trailers || apr_is_empty_table(ctx->trailers)) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, f->r,
                              "ap_http_chunk_filter sending empty end chunk");
                e = apr_bucket_immortal_create(ZERO_ASCII CRLF_ASCII
                                               /* <trailers> */
                                               CRLF_ASCII, 5, c->bucket_alloc);
                APR_BUCKET_INSERT_BEFORE(eos, e);
            }
            else {
                const char *line = ZERO_ASCII CRLF_ASCII;
                ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, f->r,
                              "ap_http_chunk_filter sending end chunk with trailers");
                more = apr_brigade_split_ex(b, eos, tmp);
                apr_brigade_write(b, NULL, NULL, line, strlen(line));
                http1_append_headers(b, f->r, ctx->trailers);
                http1_terminate_header(b);
                APR_BRIGADE_CONCAT(b, more);
            }
        }

        /* pass the brigade to the next filter. */
        rv = ap_pass_brigade(f->next, b);
        apr_brigade_cleanup(b);
        if (rv != APR_SUCCESS || eos != NULL) {
            return rv;
        }
        tmp = b;
    }
    return APR_SUCCESS;
}

typedef struct http_filter_ctx
{
    apr_off_t remaining;
    apr_off_t limit;
    apr_off_t limit_used;
    apr_int32_t chunk_used;
    apr_int32_t chunk_bws;
    apr_int32_t chunkbits;
    enum
    {
        BODY_NONE, /* streamed data */
        BODY_LENGTH, /* data constrained by content length */
        BODY_CHUNK, /* chunk expected */
        BODY_CHUNK_PART, /* chunk digits */
        BODY_CHUNK_EXT, /* chunk extension */
        BODY_CHUNK_CR, /* got space(s) after digits, expect [CR]LF or ext */
        BODY_CHUNK_LF, /* got CR after digits or ext, expect LF */
        BODY_CHUNK_DATA, /* data constrained by chunked encoding */
        BODY_CHUNK_END, /* chunked data terminating CRLF */
        BODY_CHUNK_END_LF, /* got CR after data, expect LF */
        BODY_CHUNK_TRAILER /* trailers */
    } state;
    unsigned int at_eos:1,
                 seen_data:1;
} http_ctx_t;

/**
 * Parse a chunk line with optional extension, detect overflow.
 * There are several error cases:
 *  1) If the chunk link is misformatted, APR_EINVAL is returned.
 *  2) If the conversion would require too many bits, APR_EGENERAL is returned.
 *  3) If the conversion used the correct number of bits, but an overflow
 *     caused only the sign bit to flip, then APR_ENOSPC is returned.
 * A negative chunk length always indicates an overflow error.
 */
static apr_status_t parse_chunk_size(http_ctx_t *ctx, const char *buffer,
                                     apr_size_t len, int linelimit, int strict)
{
    apr_size_t i = 0;

    while (i < len) {
        char c = buffer[i];

        ap_xlate_proto_from_ascii(&c, 1);

        /* handle CRLF after the chunk */
        if (ctx->state == BODY_CHUNK_END
                || ctx->state == BODY_CHUNK_END_LF) {
            if (c == LF) {
                if (strict && (ctx->state != BODY_CHUNK_END_LF)) {
                    /*
                     * CR missing before LF.
                     */
                    return APR_EINVAL;
                }
                ctx->state = BODY_CHUNK;
            }
            else if (c == CR && ctx->state == BODY_CHUNK_END) {
                ctx->state = BODY_CHUNK_END_LF;
            }
            else {
                /*
                 * CRLF expected.
                 */
                return APR_EINVAL;
            }
            i++;
            continue;
        }

        /* handle start of the chunk */
        if (ctx->state == BODY_CHUNK) {
            if (!apr_isxdigit(c)) {
                /*
                 * Detect invalid character at beginning. This also works for
                 * empty chunk size lines.
                 */
                return APR_EINVAL;
            }
            else {
                ctx->state = BODY_CHUNK_PART;
            }
            ctx->remaining = 0;
            /* The maximum number of bits that can be handled in a
             * chunk size is in theory sizeof(apr_off_t)*8-1 since
             * off_t is signed, but use -4 to avoid undefined
             * behaviour when bitshifting left. */
            ctx->chunkbits = sizeof(apr_off_t) * 8 - 4;
            ctx->chunk_used = 0;
            ctx->chunk_bws = 0;
        }

        if (c == LF) {
            if (strict && (ctx->state != BODY_CHUNK_LF)) {
                /*
                 * CR missing before LF.
                 */
                return APR_EINVAL;
            }
            if (ctx->remaining) {
                ctx->state = BODY_CHUNK_DATA;
            }
            else {
                ctx->state = BODY_CHUNK_TRAILER;
            }
        }
        else if (ctx->state == BODY_CHUNK_LF) {
            /*
             * LF expected.
             */
            return APR_EINVAL;
        }
        else if (c == CR) {
            ctx->state = BODY_CHUNK_LF;
        }
        else if (c == ';') {
            ctx->state = BODY_CHUNK_EXT;
        }
        else if (ctx->state == BODY_CHUNK_EXT) {
            /*
             * Control chars (excluding tabs) are invalid.
             * TODO: more precisely limit input
             */
            if (c != '\t' && apr_iscntrl(c)) {
                return APR_EINVAL;
            }
        }
        else if (c == ' ' || c == '\t') {
            /* Be lenient up to 10 implied *LWS, a legacy of RFC 2616,
             * and noted as errata to RFC7230;
             * https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4667
             */
            ctx->state = BODY_CHUNK_CR;
            if (++ctx->chunk_bws > 10) {
                return APR_EINVAL;
            }
        }
        else if (ctx->state == BODY_CHUNK_CR) {
            /*
             * ';', CR or LF expected.
             */
            return APR_EINVAL;
        }
        else if (ctx->state == BODY_CHUNK_PART) {
            int xvalue;

            /* ignore leading zeros */
            if (!ctx->remaining && c == '0') {
                i++;
                continue;
            }

            ctx->chunkbits -= 4;
            if (ctx->chunkbits < 0) {
                /* overflow */
                return APR_ENOSPC;
            }

            if (c >= '0' && c <= '9') {
                xvalue = c - '0';
            }
            else if (c >= 'A' && c <= 'F') {
                xvalue = c - 'A' + 0xa;
            }
            else if (c >= 'a' && c <= 'f') {
                xvalue = c - 'a' + 0xa;
            }
            else {
                /* bogus character */
                return APR_EINVAL;
            }

            ctx->remaining = (ctx->remaining << 4) | xvalue;
            if (ctx->remaining < 0) {
                /* Overflow - should be unreachable since the
                 * chunkbits limit will be reached first. */
                return APR_ENOSPC;
            }
        }
        else {
            /* Should not happen */
            return APR_EGENERAL;
        }

        i++;
    }

    /* sanity check */
    ctx->chunk_used += len;
    if (ctx->chunk_used < 0 || ctx->chunk_used > linelimit) {
        return APR_ENOSPC;
    }

    return APR_SUCCESS;
}

static apr_status_t read_chunked_trailers(http_ctx_t *ctx, ap_filter_t *f,
                                          apr_bucket_brigade *b)
{
    int rv;
    apr_bucket *e;
    request_rec *r = f->r;
    apr_table_t *trailers;
    apr_table_t *saved_headers_in = r->headers_in;
    int saved_status = r->status;

    trailers = apr_table_make(r->pool, 5);
    r->status = HTTP_OK;
    r->headers_in = trailers;
    ap_get_mime_headers(r);
    r->headers_in = saved_headers_in;

    if (r->status == HTTP_OK) {
        r->status = saved_status;

        if (!apr_is_empty_table(trailers)) {
            e = ap_bucket_headers_create(0, NULL, trailers,
                                         NULL, r->pool, b->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(b, e);
        }
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        ctx->at_eos = 1;
        rv = APR_SUCCESS;
    }
    else {
        const char *error_notes = apr_table_get(r->notes,
                                                "error-notes");
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02656)
                      "Error while reading HTTP trailer: %i%s%s",
                      r->status, error_notes ? ": " : "",
                      error_notes ? error_notes : "");
        rv = APR_EINVAL;
    }

    return rv;
}

/* This is the HTTP1_TRANSCODE_IN filter for HTTP/1.x requests
 * and responses from proxied servers (mod_proxy).
 * It handles chunked and content-length bodies. This can only
 * be inserted/used after the headers are successfully parsed
 * on a HTTP/1.x connection.
 */
apr_status_t ap_http1_transcode_in_filter(ap_filter_t *f,
                                          apr_bucket_brigade *b,
                                          ap_input_mode_t mode,
                                          apr_read_type_e block,
                                          apr_off_t readbytes)
{
    core_server_config *conf =
        (core_server_config *) ap_get_module_config(f->r->server->module_config,
                                                    &core_module);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    apr_bucket *e;
    http_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    int again;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, f->r,
                  "ap_http1_transcode_in_filter: start read");
    if (!ctx) {
        const char *tenc, *lenp;
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->state = BODY_NONE;

        /* LimitRequestBody does not apply to proxied responses.
         * Consider implementing this check in its own filter.
         * Would adding a directive to limit the size of proxied
         * responses be useful?
         */
        if (f->r->proxyreq != PROXYREQ_RESPONSE) {
            ctx->limit = ap_get_limit_req_body(f->r);
        }
        else {
            ctx->limit = 0;
        }

        tenc = apr_table_get(f->r->headers_in, "Transfer-Encoding");
        lenp = apr_table_get(f->r->headers_in, "Content-Length");

        if (tenc) {
            if (ap_is_chunked(f->r->pool, tenc)) {
                ctx->state = BODY_CHUNK;
            }
            else if (f->r->proxyreq == PROXYREQ_RESPONSE) {
                /* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
                 * Section 3.3.3.3: "If a Transfer-Encoding header field is
                 * present in a response and the chunked transfer coding is not
                 * the final encoding, the message body length is determined by
                 * reading the connection until it is closed by the server."
                 */
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(02555)
                              "Unknown Transfer-Encoding: %s; "
                              "using read-until-close", tenc);
                tenc = NULL;
            }
            else {
                /* Something that isn't a HTTP request, unless some future
                 * edition defines new transfer encodings, is unsupported.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01585)
                              "Unknown Transfer-Encoding: %s", tenc);
                ap_die(HTTP_NOT_IMPLEMENTED, f->r);
                return APR_EGENERAL;
            }
            lenp = NULL;
        }
        if (lenp) {
            ctx->state = BODY_LENGTH;

            /* Protects against over/underflow, non-digit chars in the
             * string, leading plus/minus signs, trailing characters and
             * a negative number.
             */
            if (!ap_parse_strict_length(&ctx->remaining, lenp)) {
                ctx->remaining = 0;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01587)
                              "Invalid Content-Length");

                return APR_EINVAL;
            }

            /* If we have a limit in effect and we know the C-L ahead of
             * time, stop it here if it is invalid.
             */
            if (ctx->limit && ctx->limit < ctx->remaining) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01588)
                          "Requested content-length of %" APR_OFF_T_FMT
                          " is larger than the configured limit"
                          " of %" APR_OFF_T_FMT, ctx->remaining, ctx->limit);
                return APR_ENOSPC;
            }
        }

        /* If we don't have a request entity indicated by the headers, EOS.
         * (BODY_NONE is a valid intermediate state due to trailers,
         *  but it isn't a valid starting state.)
         *
         * RFC 2616 Section 4.4 note 5 states that connection-close
         * is invalid for a request entity - request bodies must be
         * denoted by C-L or T-E: chunked.
         *
         * Note that since the proxy uses this filter to handle the
         * proxied *response*, proxy responses MUST be exempt.
         */
        if (ctx->state == BODY_NONE && f->r->proxyreq != PROXYREQ_RESPONSE) {
            ctx->at_eos = 1; /* send EOS below */
        }
    }

    /* sanity check in case we're read twice */
    if (ctx->at_eos) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, f->r,
                      "ap_http1_transcode_in_filter: return eos");
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        return APR_SUCCESS;
    }

    do {
        apr_brigade_cleanup(b);
        again = 0; /* until further notice */

        /* read and handle the brigade */
        switch (ctx->state) {
        case BODY_CHUNK:
        case BODY_CHUNK_PART:
        case BODY_CHUNK_EXT:
        case BODY_CHUNK_CR:
        case BODY_CHUNK_LF:
        case BODY_CHUNK_END:
        case BODY_CHUNK_END_LF: {

            rv = ap_get_brigade(f->next, b, AP_MODE_GETLINE, block, 0);

            /* for timeout */
            if (block == APR_NONBLOCK_READ
                    && ((rv == APR_SUCCESS && APR_BRIGADE_EMPTY(b))
                            || (APR_STATUS_IS_EAGAIN(rv)))) {
                return APR_EAGAIN;
            }

            if (rv == APR_EOF) {
                return APR_INCOMPLETE;
            }

            if (rv != APR_SUCCESS) {
                return rv;
            }

            e = APR_BRIGADE_FIRST(b);
            while (e != APR_BRIGADE_SENTINEL(b)) {
                const char *buffer;
                apr_size_t len;

                if (!APR_BUCKET_IS_METADATA(e)) {
                    rv = apr_bucket_read(e, &buffer, &len, APR_BLOCK_READ);
                    if (rv == APR_SUCCESS) {
                        if (len > 0) {
                            ctx->seen_data = 1;
                        }
                        rv = parse_chunk_size(ctx, buffer, len,
                                f->r->server->limit_req_fieldsize, strict);
                    }
                    if (rv != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, f->r, APLOGNO(01590)
                                      "Error reading/parsing chunk %s ",
                                      (APR_ENOSPC == rv) ? "(overflow)" : "");
                        return rv;
                    }
                }

                apr_bucket_delete(e);
                e = APR_BRIGADE_FIRST(b);
            }
            again = 1; /* come around again */

            if (ctx->state == BODY_CHUNK_TRAILER) {
                /* Treat UNSET as DISABLE - trailers aren't merged by default */
                return read_chunked_trailers(ctx, f, b);
            }

            break;
        }
        case BODY_NONE:
        case BODY_LENGTH:
        case BODY_CHUNK_DATA: {

            /* Ensure that the caller can not go over our boundary point. */
            if (ctx->state != BODY_NONE && ctx->remaining < readbytes) {
                readbytes = ctx->remaining;
            }
            if (readbytes > 0) {
                apr_off_t totalread;

                rv = ap_get_brigade(f->next, b, mode, block, readbytes);

                /* for timeout */
                if (block == APR_NONBLOCK_READ
                        && ((rv == APR_SUCCESS && APR_BRIGADE_EMPTY(b))
                                || (APR_STATUS_IS_EAGAIN(rv)))) {
                    return APR_EAGAIN;
                }

                if (rv == APR_EOF && ctx->state != BODY_NONE
                        && ctx->remaining > 0) {
                    return APR_INCOMPLETE;
                }

                if (rv != APR_SUCCESS) {
                    return rv;
                }

                /* How many bytes did we just read? */
                apr_brigade_length(b, 0, &totalread);
                if (totalread > 0) {
                    ctx->seen_data = 1;
                }

                /* If this happens, we have a bucket of unknown length.  Die because
                 * it means our assumptions have changed. */
                AP_DEBUG_ASSERT(totalread >= 0);

                if (ctx->state != BODY_NONE) {
                    ctx->remaining -= totalread;
                    if (ctx->remaining > 0) {
                        e = APR_BRIGADE_LAST(b);
                        if (APR_BUCKET_IS_EOS(e)) {
                            apr_bucket_delete(e);
                            return APR_INCOMPLETE;
                        }
                    }
                    else if (ctx->state == BODY_CHUNK_DATA) {
                        /* next chunk please */
                        ctx->state = BODY_CHUNK_END;
                        ctx->chunk_used = 0;
                    }
                }

                /* We have a limit in effect. */
                if (ctx->limit) {
                    /* FIXME: Note that we might get slightly confused on
                     * chunked inputs as we'd need to compensate for the chunk
                     * lengths which may not really count.  This seems to be up
                     * for interpretation.
                     */
                    ctx->limit_used += totalread;
                    if (ctx->limit < ctx->limit_used) {
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      APLOGNO(01591) "Read content length of "
                                      "%" APR_OFF_T_FMT " is larger than the "
                                      "configured limit of %" APR_OFF_T_FMT,
                                      ctx->limit_used, ctx->limit);
                        return APR_ENOSPC;
                    }
                }
            }

            /* If we have no more bytes remaining on a C-L request,
             * save the caller a round trip to discover EOS.
             */
            if (ctx->state == BODY_LENGTH && ctx->remaining == 0) {
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(b, e);
                ctx->at_eos = 1;
            }

            break;
        }
        case BODY_CHUNK_TRAILER: {

            rv = ap_get_brigade(f->next, b, mode, block, readbytes);

            /* for timeout */
            if (block == APR_NONBLOCK_READ
                    && ((rv == APR_SUCCESS && APR_BRIGADE_EMPTY(b))
                            || (APR_STATUS_IS_EAGAIN(rv)))) {
                return APR_EAGAIN;
            }

            if (rv != APR_SUCCESS) {
                return rv;
            }

            break;
        }
        default: {
            /* Should not happen */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(02901)
                          "Unexpected body state (%i)", (int)ctx->state);
            return APR_EGENERAL;
        }
        }

    } while (again);

    return APR_SUCCESS;
}
