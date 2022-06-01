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
 * http_filter.c --- HTTP routines which either filters or deal with filters.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"

#define APR_WANT_STDIO          /* for sscanf */
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_connection.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "apr_date.h"           /* For apr_date_parse_http and APR_DATE_BAD */
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

APLOG_USE_MODULE(http);

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
    unsigned int eos_sent :1,
                 seen_data:1;
    apr_bucket_brigade *bb;
} http_ctx_t;

/* bail out if some error in the HTTP input filter happens */
static apr_status_t bail_out_on_error(http_ctx_t *ctx,
                                      ap_filter_t *f,
                                      int http_error)
{
    apr_bucket *e;
    apr_bucket_brigade *bb = ctx->bb;

    apr_brigade_cleanup(bb);

    if (f->r->proxyreq == PROXYREQ_RESPONSE) {
        switch (http_error) {
        case HTTP_REQUEST_ENTITY_TOO_LARGE:
            return APR_ENOSPC;

        case HTTP_REQUEST_TIME_OUT:
            return APR_INCOMPLETE;

        case HTTP_NOT_IMPLEMENTED:
            return APR_ENOTIMPL;

        default:
            return APR_EGENERAL;
        }
    }

    e = ap_bucket_error_create(http_error,
                               NULL, f->r->pool,
                               f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    e = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ctx->eos_sent = 1;
    /* If chunked encoding / content-length are corrupt, we may treat parts
     * of this request's body as the next one's headers.
     * To be safe, disable keep-alive.
     */
    f->r->connection->keepalive = AP_CONN_CLOSE;
    return ap_pass_brigade(f->r->output_filters, bb);
}

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
            ctx->chunkbits = sizeof(apr_off_t) * 8;
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
                /* overflow */
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
                                          apr_bucket_brigade *b, int merge)
{
    int rv;
    apr_bucket *e;
    request_rec *r = f->r;
    apr_table_t *saved_headers_in = r->headers_in;
    int saved_status = r->status;

    r->status = HTTP_OK;
    r->headers_in = r->trailers_in;
    apr_table_clear(r->headers_in);
    ap_get_mime_headers(r);

    if(r->status == HTTP_OK) {
        r->status = saved_status;
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        ctx->eos_sent = 1;
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

    if(!merge) {
        r->headers_in = saved_headers_in;
    }
    else {
        r->headers_in = apr_table_overlay(r->pool, saved_headers_in,
                r->trailers_in);
    }

    return rv;
}

/* This is the HTTP_INPUT filter for HTTP requests and responses from
 * proxied servers (mod_proxy).  It handles chunked and content-length
 * bodies.  This can only be inserted/used after the headers
 * are successfully parsed.
 */
apr_status_t ap_http_filter(ap_filter_t *f, apr_bucket_brigade *b,
                            ap_input_mode_t mode, apr_read_type_e block,
                            apr_off_t readbytes)
{
    core_server_config *conf =
        (core_server_config *) ap_get_module_config(f->r->server->module_config,
                                                    &core_module);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    apr_bucket *e;
    http_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    int http_error = HTTP_REQUEST_ENTITY_TOO_LARGE;
    int again;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    if (!ctx) {
        const char *tenc, *lenp;
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->state = BODY_NONE;
        ctx->bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

        /* LimitRequestBody does not apply to proxied responses.
         * Consider implementing this check in its own filter.
         * Would adding a directive to limit the size of proxied
         * responses be useful?
         */
        if (!f->r->proxyreq) {
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
                return bail_out_on_error(ctx, f, HTTP_BAD_REQUEST);
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

                return bail_out_on_error(ctx, f, HTTP_BAD_REQUEST);
            }

            /* If we have a limit in effect and we know the C-L ahead of
             * time, stop it here if it is invalid.
             */
            if (ctx->limit && ctx->limit < ctx->remaining) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01588)
                          "Requested content-length of %" APR_OFF_T_FMT
                          " is larger than the configured limit"
                          " of %" APR_OFF_T_FMT, ctx->remaining, ctx->limit);
                return bail_out_on_error(ctx, f, HTTP_REQUEST_ENTITY_TOO_LARGE);
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
            e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(b, e);
            ctx->eos_sent = 1;
            return APR_SUCCESS;
        }
    }

    /* Since we're about to read data, send 100-Continue if needed.
     * Only valid on chunked and C-L bodies where the C-L is > 0.
     *
     * If the read is to be nonblocking though, the caller may not want to
     * handle this just now (e.g. mod_proxy_http), and is prepared to read
     * nothing if the client really waits for 100 continue, so we don't
     * send it now and wait for later blocking read.
     *
     * In any case, even if r->expecting remains set at the end of the
     * request handling, ap_set_keepalive() will finally do the right
     * thing (i.e. "Connection: close" the connection).
     */
    if (block == APR_BLOCK_READ
            && (ctx->state == BODY_CHUNK
                || (ctx->state == BODY_LENGTH && ctx->remaining > 0))
            && f->r->expecting_100 && f->r->proto_num >= HTTP_VERSION(1,1)
            && !(ctx->eos_sent || f->r->eos_sent || f->r->bytes_sent)) {
        if (!ap_is_HTTP_SUCCESS(f->r->status)) {
            ctx->state = BODY_NONE;
            ctx->eos_sent = 1; /* send EOS below */
        }
        else if (!ctx->seen_data) {
            int saved_status = f->r->status;
            const char *saved_status_line = f->r->status_line;
            f->r->status = HTTP_CONTINUE;
            f->r->status_line = NULL;
            ap_send_interim_response(f->r, 0);
            AP_DEBUG_ASSERT(!f->r->expecting_100);
            f->r->status_line = saved_status_line;
            f->r->status = saved_status;
        }
        else {
            /* https://tools.ietf.org/html/rfc7231#section-5.1.1
             *   A server MAY omit sending a 100 (Continue) response if it
             *   has already received some or all of the message body for
             *   the corresponding request [...]
             */
            f->r->expecting_100 = 0;
        }
    }

    /* sanity check in case we're read twice */
    if (ctx->eos_sent) {
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
                    int parsing = 0;

                    rv = apr_bucket_read(e, &buffer, &len, APR_BLOCK_READ);
                    if (rv == APR_SUCCESS) {
                        parsing = 1;
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
                        if (parsing) {
                            if (rv != APR_ENOSPC) {
                                http_error = HTTP_BAD_REQUEST;
                            }
                            return bail_out_on_error(ctx, f, http_error);
                        }
                        return rv;
                    }
                }

                apr_bucket_delete(e);
                e = APR_BRIGADE_FIRST(b);
            }
            again = 1; /* come around again */

            if (ctx->state == BODY_CHUNK_TRAILER) {
                /* Treat UNSET as DISABLE - trailers aren't merged by default */
                return read_chunked_trailers(ctx, f, b,
                            conf->merge_trailers == AP_MERGE_TRAILERS_ENABLE);
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
                        return bail_out_on_error(ctx, f,
                                                 HTTP_REQUEST_ENTITY_TOO_LARGE);
                    }
                }
            }

            /* If we have no more bytes remaining on a C-L request,
             * save the caller a round trip to discover EOS.
             */
            if (ctx->state == BODY_LENGTH && ctx->remaining == 0) {
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(b, e);
                ctx->eos_sent = 1;
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

struct check_header_ctx {
    request_rec *r;
    int strict;
};

/* check a single header, to be used with apr_table_do() */
static int check_header(struct check_header_ctx *ctx,
                        const char *name, const char **val)
{
    const char *pos, *end;
    char *dst = NULL;

    if (name[0] == '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, APLOGNO(02428)
                      "Empty response header name, aborting request");
        return 0;
    }

    if (ctx->strict) { 
        end = ap_scan_http_token(name);
    }
    else {
        end = ap_scan_vchar_obstext(name);
    }
    if (*end) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, APLOGNO(02429)
                      "Response header name '%s' contains invalid "
                      "characters, aborting request",
                      name);
        return 0;
    }

    for (pos = *val; *pos; pos = end) {
        end = ap_scan_http_field_content(pos);
        if (*end) {
            if (end[0] != CR || end[1] != LF || (end[2] != ' ' &&
                                                 end[2] != '\t')) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->r, APLOGNO(02430)
                              "Response header '%s' value of '%s' contains "
                              "invalid characters, aborting request",
                              name, pos);
                return 0;
            }
            if (!dst) {
                *val = dst = apr_palloc(ctx->r->pool, strlen(*val) + 1);
            }
        }
        if (dst) {
            memcpy(dst, pos, end - pos);
            dst += end - pos;
            if (*end) {
                /* skip folding and replace with a single space */
                end += 3 + strspn(end + 3, "\t ");
                *dst++ = ' ';
            }
        }
    }
    if (dst) {
        *dst = '\0';
    }
    return 1;
}

static int check_headers_table(apr_table_t *t, struct check_header_ctx *ctx)
{
    const apr_array_header_t *headers = apr_table_elts(t);
    apr_table_entry_t *header;
    int i;

    for (i = 0; i < headers->nelts; ++i) {
        header = &APR_ARRAY_IDX(headers, i, apr_table_entry_t);
        if (!header->key) {
            continue;
        }
        if (!check_header(ctx, header->key, (const char **)&header->val)) {
            return 0;
        }
    }
    return 1;
}

/**
 * Check headers for HTTP conformance
 * @return 1 if ok, 0 if bad
 */
static APR_INLINE int check_headers(request_rec *r)
{
    struct check_header_ctx ctx;
    core_server_config *conf =
            ap_get_core_module_config(r->server->module_config);

    ctx.r = r;
    ctx.strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    return check_headers_table(r->headers_out, &ctx) &&
           check_headers_table(r->err_headers_out, &ctx);
}

static int check_headers_recursion(request_rec *r)
{
    void *check = NULL;
    apr_pool_userdata_get(&check, "check_headers_recursion", r->pool);
    if (check) {
        return 1;
    }
    apr_pool_userdata_setn("true", "check_headers_recursion", NULL, r->pool);
    return 0;
}

typedef struct header_struct {
    apr_pool_t *pool;
    apr_bucket_brigade *bb;
} header_struct;

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to apr_table_do(), so don't change its interface.
 * It returns true unless there was a write error of some kind.
 */
static int form_header_field(header_struct *h,
                             const char *fieldname, const char *fieldval)
{
#if APR_CHARSET_EBCDIC
    char *headfield;
    apr_size_t len;

    headfield = apr_pstrcat(h->pool, fieldname, ": ", fieldval, CRLF, NULL);
    len = strlen(headfield);

    ap_xlate_proto_to_ascii(headfield, len);
    apr_brigade_write(h->bb, NULL, NULL, headfield, len);
#else
    struct iovec vec[4];
    struct iovec *v = vec;
    v->iov_base = (void *)fieldname;
    v->iov_len = strlen(fieldname);
    v++;
    v->iov_base = ": ";
    v->iov_len = sizeof(": ") - 1;
    v++;
    v->iov_base = (void *)fieldval;
    v->iov_len = strlen(fieldval);
    v++;
    v->iov_base = CRLF;
    v->iov_len = sizeof(CRLF) - 1;
    apr_brigade_writev(h->bb, NULL, NULL, vec, 4);
#endif /* !APR_CHARSET_EBCDIC */
    return 1;
}

/* This routine is called by apr_table_do and merges all instances of
 * the passed field values into a single array that will be further
 * processed by some later routine.  Originally intended to help split
 * and recombine multiple Vary fields, though it is generic to any field
 * consisting of comma/space-separated tokens.
 */
static int uniq_field_values(void *d, const char *key, const char *val)
{
    apr_array_header_t *values;
    char *start;
    char *e;
    char **strpp;
    int  i;

    values = (apr_array_header_t *)d;

    e = apr_pstrdup(values->pool, val);

    do {
        /* Find a non-empty fieldname */

        while (*e == ',' || apr_isspace(*e)) {
            ++e;
        }
        if (*e == '\0') {
            break;
        }
        start = e;
        while (*e != '\0' && *e != ',' && !apr_isspace(*e)) {
            ++e;
        }
        if (*e != '\0') {
            *e++ = '\0';
        }

        /* Now add it to values if it isn't already represented.
         * Could be replaced by a ap_array_strcasecmp() if we had one.
         */
        for (i = 0, strpp = (char **) values->elts; i < values->nelts;
             ++i, ++strpp) {
            if (*strpp && ap_cstr_casecmp(*strpp, start) == 0) {
                break;
            }
        }
        if (i == values->nelts) {  /* if not found */
            *(char **)apr_array_push(values) = start;
        }
    } while (*e != '\0');

    return 1;
}

/*
 * Since some clients choke violently on multiple Vary fields, or
 * Vary fields with duplicate tokens, combine any multiples and remove
 * any duplicates.
 */
static void fixup_vary(request_rec *r)
{
    apr_array_header_t *varies;

    varies = apr_array_make(r->pool, 5, sizeof(char *));

    /* Extract all Vary fields from the headers_out, separate each into
     * its comma-separated fieldname values, and then add them to varies
     * if not already present in the array.
     */
    apr_table_do(uniq_field_values, varies, r->headers_out, "Vary", NULL);

    /* If we found any, replace old Vary fields with unique-ified value */

    if (varies->nelts > 0) {
        apr_table_setn(r->headers_out, "Vary",
                       apr_array_pstrcat(r->pool, varies, ','));
    }
}

/* Send a request's HTTP response headers to the client.
 */
static apr_status_t send_all_header_fields(header_struct *h,
                                           const request_rec *r)
{
    const apr_array_header_t *elts;
    const apr_table_entry_t *t_elt;
    const apr_table_entry_t *t_end;
    struct iovec *vec;
    struct iovec *vec_next;

    elts = apr_table_elts(r->headers_out);
    if (elts->nelts == 0) {
        return APR_SUCCESS;
    }
    t_elt = (const apr_table_entry_t *)(elts->elts);
    t_end = t_elt + elts->nelts;
    vec = (struct iovec *)apr_palloc(h->pool, 4 * elts->nelts *
                                     sizeof(struct iovec));
    vec_next = vec;

    /* For each field, generate
     *    name ": " value CRLF
     */
    do {
        vec_next->iov_base = (void*)(t_elt->key);
        vec_next->iov_len = strlen(t_elt->key);
        vec_next++;
        vec_next->iov_base = ": ";
        vec_next->iov_len = sizeof(": ") - 1;
        vec_next++;
        vec_next->iov_base = (void*)(t_elt->val);
        vec_next->iov_len = strlen(t_elt->val);
        vec_next++;
        vec_next->iov_base = CRLF;
        vec_next->iov_len = sizeof(CRLF) - 1;
        vec_next++;
        t_elt++;
    } while (t_elt < t_end);

    if (APLOGrtrace4(r)) {
        t_elt = (const apr_table_entry_t *)(elts->elts);
        do {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "  %s: %s",
                          ap_escape_logitem(r->pool, t_elt->key),
                          ap_escape_logitem(r->pool, t_elt->val));
            t_elt++;
        } while (t_elt < t_end);
    }

#if APR_CHARSET_EBCDIC
    {
        apr_size_t len;
        char *tmp = apr_pstrcatv(r->pool, vec, vec_next - vec, &len);
        ap_xlate_proto_to_ascii(tmp, len);
        return apr_brigade_write(h->bb, NULL, NULL, tmp, len);
    }
#else
    return apr_brigade_writev(h->bb, NULL, NULL, vec, vec_next - vec);
#endif
}

/* Confirm that the status line is well-formed and matches r->status.
 * If they don't match, a filter may have negated the status line set by a
 * handler.
 * Zap r->status_line if bad.
 */
static apr_status_t validate_status_line(request_rec *r)
{
    char *end;

    if (r->status_line) {
        int len = strlen(r->status_line);
        if (len < 3
            || apr_strtoi64(r->status_line, &end, 10) != r->status
            || (end - 3) != r->status_line
            || (len >= 4 && ! apr_isspace(r->status_line[3]))) {
            r->status_line = NULL;
            return APR_EGENERAL;
        }
        /* Since we passed the above check, we know that length three
         * is equivalent to only a 3 digit numeric http status.
         * RFC2616 mandates a trailing space, let's add it.
         */
        if (len == 3) {
            r->status_line = apr_pstrcat(r->pool, r->status_line, " ", NULL);
            return APR_EGENERAL;
        }
        return APR_SUCCESS;
    }
    return APR_EGENERAL;
}

/*
 * Determine the protocol to use for the response. Potentially downgrade
 * to HTTP/1.0 in some situations and/or turn off keepalives.
 *
 * also prepare r->status_line.
 */
static void basic_http_header_check(request_rec *r,
                                    const char **protocol)
{
    apr_status_t rv;

    if (r->assbackwards) {
        /* no such thing as a response protocol */
        return;
    }

    rv = validate_status_line(r);

    if (!r->status_line) {
        r->status_line = ap_get_status_line(r->status);
    } else if (rv != APR_SUCCESS) {
        /* Status line is OK but our own reason phrase
         * would be preferred if defined
         */
        const char *tmp = ap_get_status_line(r->status);
        if (!strncmp(tmp, r->status_line, 3)) {
            r->status_line = tmp;
        }
    }

    /* Note that we must downgrade before checking for force responses. */
    if (r->proto_num > HTTP_VERSION(1,0)
        && apr_table_get(r->subprocess_env, "downgrade-1.0")) {
        r->proto_num = HTTP_VERSION(1,0);
    }

    /* kludge around broken browsers when indicated by force-response-1.0
     */
    if (r->proto_num == HTTP_VERSION(1,0)
        && apr_table_get(r->subprocess_env, "force-response-1.0")) {
        *protocol = "HTTP/1.0";
        r->connection->keepalive = AP_CONN_CLOSE;
    }
    else {
        *protocol = AP_SERVER_PROTOCOL;
    }

}

/* fill "bb" with a barebones/initial HTTP response header */
static void basic_http_header(request_rec *r, apr_bucket_brigade *bb,
                              const char *protocol)
{
    char *date = NULL;
    const char *proxy_date = NULL;
    const char *server = NULL;
    const char *us = ap_get_server_banner();
    header_struct h;
    struct iovec vec[4];

    if (r->assbackwards) {
        /* there are no headers to send */
        return;
    }

    /* Output the HTTP/1.x Status-Line and the Date and Server fields */

    vec[0].iov_base = (void *)protocol;
    vec[0].iov_len  = strlen(protocol);
    vec[1].iov_base = (void *)" ";
    vec[1].iov_len  = sizeof(" ") - 1;
    vec[2].iov_base = (void *)(r->status_line);
    vec[2].iov_len  = strlen(r->status_line);
    vec[3].iov_base = (void *)CRLF;
    vec[3].iov_len  = sizeof(CRLF) - 1;
#if APR_CHARSET_EBCDIC
    {
        char *tmp;
        apr_size_t len;
        tmp = apr_pstrcatv(r->pool, vec, 4, &len);
        ap_xlate_proto_to_ascii(tmp, len);
        apr_brigade_write(bb, NULL, NULL, tmp, len);
    }
#else
    apr_brigade_writev(bb, NULL, NULL, vec, 4);
#endif

    h.pool = r->pool;
    h.bb = bb;

    /*
     * keep the set-by-proxy server and date headers, otherwise
     * generate a new server header / date header
     */
    if (r->proxyreq != PROXYREQ_NONE) {
        proxy_date = apr_table_get(r->headers_out, "Date");
        if (!proxy_date) {
            /*
             * proxy_date needs to be const. So use date for the creation of
             * our own Date header and pass it over to proxy_date later to
             * avoid a compiler warning.
             */
            date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
            ap_recent_rfc822_date(date, r->request_time);
        }
        server = apr_table_get(r->headers_out, "Server");
    }
    else {
        date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(date, r->request_time);
    }

    form_header_field(&h, "Date", proxy_date ? proxy_date : date );

    if (!server && *us)
        server = us;
    if (server)
        form_header_field(&h, "Server", server);

    if (APLOGrtrace3(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "Response sent with status %d%s",
                      r->status,
                      APLOGrtrace4(r) ? ", headers:" : "");

        /*
         * Date and Server are less interesting, use TRACE5 for them while
         * using TRACE4 for the other headers.
         */
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "  Date: %s",
                      proxy_date ? proxy_date : date );
        if (server)
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "  Server: %s",
                          server);
    }


    /* unset so we don't send them again */
    apr_table_unset(r->headers_out, "Date");        /* Avoid bogosity */
    if (server) {
        apr_table_unset(r->headers_out, "Server");
    }
}

AP_DECLARE(void) ap_basic_http_header(request_rec *r, apr_bucket_brigade *bb)
{
    const char *protocol = NULL;

    basic_http_header_check(r, &protocol);
    basic_http_header(r, bb, protocol);
}

static void terminate_header(apr_bucket_brigade *bb)
{
    char crlf[] = CRLF;
    apr_size_t buflen;

    buflen = strlen(crlf);
    ap_xlate_proto_to_ascii(crlf, buflen);
    apr_brigade_write(bb, NULL, NULL, crlf, buflen);
}

AP_DECLARE_NONSTD(int) ap_send_http_trace(request_rec *r)
{
    core_server_config *conf;
    int rv;
    apr_bucket_brigade *bb;
    header_struct h;
    apr_bucket *b;
    int body;
    char *bodyread = NULL, *bodyoff;
    apr_size_t bodylen = 0;
    apr_size_t bodybuf;
    long res = -1; /* init to avoid gcc -Wall warning */

    if (r->method_number != M_TRACE) {
        return DECLINED;
    }

    /* Get the original request */
    while (r->prev) {
        r = r->prev;
    }
    conf = ap_get_core_module_config(r->server->module_config);

    if (conf->trace_enable == AP_TRACE_DISABLE) {
        apr_table_setn(r->notes, "error-notes",
                      "TRACE denied by server configuration");
        return HTTP_METHOD_NOT_ALLOWED;
    }

    if (conf->trace_enable == AP_TRACE_EXTENDED)
        /* XXX: should be = REQUEST_CHUNKED_PASS */
        body = REQUEST_CHUNKED_DECHUNK;
    else
        body = REQUEST_NO_BODY;

    if ((rv = ap_setup_client_block(r, body))) {
        if (rv == HTTP_REQUEST_ENTITY_TOO_LARGE)
            apr_table_setn(r->notes, "error-notes",
                          "TRACE with a request body is not allowed");
        return rv;
    }

    if (ap_should_client_block(r)) {

        if (r->remaining > 0) {
            if (r->remaining > 65536) {
                apr_table_setn(r->notes, "error-notes",
                       "Extended TRACE request bodies cannot exceed 64k\n");
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
            /* always 32 extra bytes to catch chunk header exceptions */
            bodybuf = (apr_size_t)r->remaining + 32;
        }
        else {
            /* Add an extra 8192 for chunk headers */
            bodybuf = 73730;
        }

        bodyoff = bodyread = apr_palloc(r->pool, bodybuf);

        /* only while we have enough for a chunked header */
        while ((!bodylen || bodybuf >= 32) &&
               (res = ap_get_client_block(r, bodyoff, bodybuf)) > 0) {
            bodylen += res;
            bodybuf -= res;
            bodyoff += res;
        }
        if (res > 0 && bodybuf < 32) {
            /* discard_rest_of_request_body into our buffer */
            while (ap_get_client_block(r, bodyread, bodylen) > 0)
                ;
            apr_table_setn(r->notes, "error-notes",
                   "Extended TRACE request bodies cannot exceed 64k\n");
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        if (res < 0) {
            return HTTP_BAD_REQUEST;
        }
    }

    ap_set_content_type(r, "message/http");

    /* Now we recreate the request, and echo it back */

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
#if APR_CHARSET_EBCDIC
    {
        char *tmp;
        apr_size_t len;
        len = strlen(r->the_request);
        tmp = apr_pmemdup(r->pool, r->the_request, len);
        ap_xlate_proto_to_ascii(tmp, len);
        apr_brigade_putstrs(bb, NULL, NULL, tmp, CRLF_ASCII, NULL);
    }
#else
    apr_brigade_putstrs(bb, NULL, NULL, r->the_request, CRLF, NULL);
#endif
    h.pool = r->pool;
    h.bb = bb;
    apr_table_do((int (*) (void *, const char *, const char *))
                 form_header_field, (void *) &h, r->headers_in, NULL);
    apr_brigade_puts(bb, NULL, NULL, CRLF_ASCII);

    /* If configured to accept a body, echo the body */
    if (bodylen) {
        b = apr_bucket_pool_create(bodyread, bodylen,
                                   r->pool, bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }

    ap_pass_brigade(r->output_filters,  bb);

    return DONE;
}

typedef struct header_filter_ctx {
    int headers_sent;
} header_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
                                                           apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    const char *clheader;
    int header_only = (r->header_only || AP_STATUS_IS_HEADER_ONLY(r->status));
    const char *protocol = NULL;
    apr_bucket *e;
    apr_bucket_brigade *b2;
    header_struct h;
    header_filter_ctx *ctx = f->ctx;
    const char *ctype;
    ap_bucket_error *eb = NULL;
    apr_status_t rv = APR_SUCCESS;
    int recursive_error = 0;

    AP_DEBUG_ASSERT(!r->main);

    if (!ctx) {
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(header_filter_ctx));
    }
    else if (ctx->headers_sent) {
        /* Eat body if response must not have one. */
        if (header_only) {
            /* Still next filters may be waiting for EOS, so pass it (alone)
             * when encountered and be done with this filter.
             */
            e = APR_BRIGADE_LAST(b);
            if (e != APR_BRIGADE_SENTINEL(b) && APR_BUCKET_IS_EOS(e)) {
                APR_BUCKET_REMOVE(e);
                apr_brigade_cleanup(b);
                APR_BRIGADE_INSERT_HEAD(b, e);
                ap_remove_output_filter(f);
                rv = ap_pass_brigade(f->next, b);
            }
            apr_brigade_cleanup(b);
            return rv;
        }
    }

    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = APR_BUCKET_NEXT(e))
    {
        if (AP_BUCKET_IS_ERROR(e) && !eb) {
            eb = e->data;
            continue;
        }
        /*
         * If we see an EOC bucket it is a signal that we should get out
         * of the way doing nothing.
         */
        if (AP_BUCKET_IS_EOC(e)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, b);
        }
    }

    if (!ctx->headers_sent && !check_headers(r)) {
        /* We may come back here from ap_die() below,
         * so clear anything from this response.
         */
        apr_table_clear(r->headers_out);
        apr_table_clear(r->err_headers_out);
        apr_brigade_cleanup(b);

        /* Don't recall ap_die() if we come back here (from its own internal
         * redirect or error response), otherwise we can end up in infinite
         * recursion; better fall through with 500, minimal headers and an
         * empty body (EOS only).
         */
        if (!check_headers_recursion(r)) {
            ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
            return AP_FILTER_ERROR;
        }
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        e = ap_bucket_eoc_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        e = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        r->content_type = r->content_encoding = NULL;
        r->content_languages = NULL;
        ap_set_content_length(r, 0);
        recursive_error = 1;
    }
    else if (eb) {
        int status;
        status = eb->status;
        apr_brigade_cleanup(b);
        ap_die(status, r);
        return AP_FILTER_ERROR;
    }

    if (r->assbackwards) {
        r->sent_bodyct = 1;
        ap_remove_output_filter(f);
        rv = ap_pass_brigade(f->next, b);
        goto out;
    }

    /*
     * Now that we are ready to send a response, we need to combine the two
     * header field tables into a single table.  If we don't do this, our
     * later attempts to set or unset a given fieldname might be bypassed.
     */
    if (!apr_is_empty_table(r->err_headers_out)) {
        r->headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                           r->headers_out);
    }

    /*
     * Remove the 'Vary' header field if the client can't handle it.
     * Since this will have nasty effects on HTTP/1.1 caches, force
     * the response into HTTP/1.0 mode.
     *
     * Note: the force-response-1.0 should come before the call to
     *       basic_http_header_check()
     */
    if (apr_table_get(r->subprocess_env, "force-no-vary") != NULL) {
        apr_table_unset(r->headers_out, "Vary");
        r->proto_num = HTTP_VERSION(1,0);
        apr_table_setn(r->subprocess_env, "force-response-1.0", "1");
    }
    else {
        fixup_vary(r);
    }

    /*
     * Now remove any ETag response header field if earlier processing
     * says so (such as a 'FileETag None' directive).
     */
    if (apr_table_get(r->notes, "no-etag") != NULL) {
        apr_table_unset(r->headers_out, "ETag");
    }

    /* determine the protocol and whether we should use keepalives. */
    basic_http_header_check(r, &protocol);
    ap_set_keepalive(r);

    if (AP_STATUS_IS_HEADER_ONLY(r->status)) {
        apr_table_unset(r->headers_out, "Transfer-Encoding");
        apr_table_unset(r->headers_out, "Content-Length");
        r->content_type = r->content_encoding = NULL;
        r->content_languages = NULL;
        r->clength = r->chunked = 0;
    }
    else if (r->chunked) {
        apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
        apr_table_unset(r->headers_out, "Content-Length");
    }

    ctype = ap_make_content_type(r, r->content_type);
    if (ctype) {
        apr_table_setn(r->headers_out, "Content-Type", ctype);
    }

    if (r->content_encoding) {
        apr_table_setn(r->headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    if (!apr_is_empty_array(r->content_languages)) {
        int i;
        char *token;
        char **languages = (char **)(r->content_languages->elts);
        const char *field = apr_table_get(r->headers_out, "Content-Language");

        while (field && (token = ap_get_list_item(r->pool, &field)) != NULL) {
            for (i = 0; i < r->content_languages->nelts; ++i) {
                if (!ap_cstr_casecmp(token, languages[i]))
                    break;
            }
            if (i == r->content_languages->nelts) {
                *((char **) apr_array_push(r->content_languages)) = token;
            }
        }

        field = apr_array_pstrcat(r->pool, r->content_languages, ',');
        apr_table_setn(r->headers_out, "Content-Language", field);
    }

    /*
     * Control cachability for non-cacheable responses if not already set by
     * some other part of the server configuration.
     */
    if (r->no_cache && !apr_table_get(r->headers_out, "Expires")) {
        char *date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(date, r->request_time);
        apr_table_addn(r->headers_out, "Expires", date);
    }

    /* This is a hack, but I can't find anyway around it.  The idea is that
     * we don't want to send out 0 Content-Lengths if it is a head request.
     * This happens when modules try to outsmart the server, and return
     * if they see a HEAD request.  Apache 1.3 handlers were supposed to
     * just return in that situation, and the core handled the HEAD.  In
     * 2.0, if a handler returns, then the core sends an EOS bucket down
     * the filter stack, and the content-length filter computes a C-L of
     * zero and that gets put in the headers, and we end up sending a
     * zero C-L to the client.  We can't just remove the C-L filter,
     * because well behaved 2.0 handlers will send their data down the stack,
     * and we will compute a real C-L for the head request. RBB
     */
    if (r->header_only
        && (clheader = apr_table_get(r->headers_out, "Content-Length"))
        && !strcmp(clheader, "0")) {
        apr_table_unset(r->headers_out, "Content-Length");
    }

    b2 = apr_brigade_create(r->pool, c->bucket_alloc);
    basic_http_header(r, b2, protocol);

    h.pool = r->pool;
    h.bb = b2;

    send_all_header_fields(&h, r);

    terminate_header(b2);

    if (header_only) {
        e = APR_BRIGADE_LAST(b);
        if (e != APR_BRIGADE_SENTINEL(b) && APR_BUCKET_IS_EOS(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(b2, e);
            ap_remove_output_filter(f);
        }
        apr_brigade_cleanup(b);
    }

    rv = ap_pass_brigade(f->next, b2);
    apr_brigade_cleanup(b2);
    ctx->headers_sent = 1;

    if (rv != APR_SUCCESS || header_only) {
        goto out;
    }

    r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */

    if (r->chunked) {
        /* We can't add this filter until we have already sent the headers.
         * If we add it before this point, then the headers will be chunked
         * as well, and that is just wrong.
         */
        ap_add_output_filter("CHUNK", NULL, r, r->connection);
    }

    /* Don't remove this filter until after we have added the CHUNK filter.
     * Otherwise, f->next won't be the CHUNK filter and thus the first
     * brigade won't be chunked properly.
     */
    ap_remove_output_filter(f);
    rv = ap_pass_brigade(f->next, b);
out:
    if (recursive_error) {
        return AP_FILTER_ERROR;
    }
    return rv;
}

/*
 * Map specific APR codes returned by the filter stack to HTTP error
 * codes, or the default status code provided. Use it as follows:
 *
 * return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
 *
 * If the filter has already handled the error, AP_FILTER_ERROR will
 * be returned, which is cleanly passed through.
 *
 * These mappings imply that the filter stack is reading from the
 * downstream client, the proxy will map these codes differently.
 */
AP_DECLARE(int) ap_map_http_request_error(apr_status_t rv, int status)
{
    switch (rv) {
    case AP_FILTER_ERROR:
        return AP_FILTER_ERROR;

    case APR_ENOSPC:
        return HTTP_REQUEST_ENTITY_TOO_LARGE;

    case APR_ENOTIMPL:
        return HTTP_NOT_IMPLEMENTED;

    case APR_TIMEUP:
    case APR_ETIMEDOUT:
        return HTTP_REQUEST_TIME_OUT;

    default:
        return status;
    }
}

/* In HTTP/1.1, any method can have a body.  However, most GET handlers
 * wouldn't know what to do with a request body if they received one.
 * This helper routine tests for and reads any message body in the request,
 * simply discarding whatever it receives.  We need to do this because
 * failing to read the request body would cause it to be interpreted
 * as the next request on a persistent connection.
 *
 * Since we return an error status if the request is malformed, this
 * routine should be called at the beginning of a no-body handler, e.g.,
 *
 *    if ((retval = ap_discard_request_body(r)) != OK) {
 *        return retval;
 *    }
 */
AP_DECLARE(int) ap_discard_request_body(request_rec *r)
{
    int rc = OK;
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;

    /* Sometimes we'll get in a state where the input handling has
     * detected an error where we want to drop the connection, so if
     * that's the case, don't read the data as that is what we're trying
     * to avoid.
     *
     * This function is also a no-op on a subrequest.
     */
    if (r->main || c->keepalive == AP_CONN_CLOSE) {
        return OK;
    }
    if (ap_status_drops_connection(r->status)) {
        c->keepalive = AP_CONN_CLOSE;
        return OK;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    for (;;) {
        apr_status_t rv;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            rc = ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
            goto cleanup;
        }

        while (!APR_BRIGADE_EMPTY(bb)) {
            apr_bucket *b = APR_BRIGADE_FIRST(bb);

            if (APR_BUCKET_IS_EOS(b)) {
                goto cleanup;
            }

            /* There is no need to read empty or metadata buckets or
             * buckets of known length, but we MUST read buckets of
             * unknown length in order to exhaust them.
             */
            if (b->length == (apr_size_t)-1) {
                apr_size_t len;
                const char *data;

                rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    rc = HTTP_BAD_REQUEST;
                    goto cleanup;
                }
            }

            apr_bucket_delete(b);
        }
    }

cleanup:
    apr_brigade_cleanup(bb);
    if (rc != OK) {
        c->keepalive = AP_CONN_CLOSE;
    }
    return rc;
}

/* Here we deal with getting the request message body from the client.
 * Whether or not the request contains a body is signaled by the presence
 * of a non-zero Content-Length or by a Transfer-Encoding: chunked.
 *
 * Note that this is more complicated than it was in Apache 1.1 and prior
 * versions, because chunked support means that the module does less.
 *
 * The proper procedure is this:
 *
 * 1. Call ap_setup_client_block() near the beginning of the request
 *    handler. This will set up all the necessary properties, and will
 *    return either OK, or an error code. If the latter, the module should
 *    return that error code. The second parameter selects the policy to
 *    apply if the request message indicates a body, and how a chunked
 *    transfer-coding should be interpreted. Choose one of
 *
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 *    REQUEST_CHUNKED_PASS     If chunked, pass the chunk headers with body.
 *
 *    In order to use the last two options, the caller MUST provide a buffer
 *    large enough to hold a chunk-size line, including any extensions.
 *
 * 2. When you are ready to read a body (if any), call ap_should_client_block().
 *    This will tell the module whether or not to read input. If it is 0,
 *    the module should assume that there is no message body to read.
 *
 * 3. Finally, call ap_get_client_block in a loop. Pass it a buffer and its size.
 *    It will put data into the buffer (not necessarily a full buffer), and
 *    return the length of the input block. When it is done reading, it will
 *    return 0 if EOF, or -1 if there was an error.
 *    If an error occurs on input, we force an end to keepalive.
 *
 *    This step also sends a 100 Continue response to HTTP/1.1 clients if appropriate.
 */

AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy)
{
    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");
    apr_off_t limit_req_body = ap_get_limit_req_body(r);

    r->read_body = read_policy;
    r->read_chunked = 0;
    r->remaining = 0;

    if (tenc) {
        if (ap_cstr_casecmp(tenc, "chunked")) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01592)
                          "Unknown Transfer-Encoding %s", tenc);
            return HTTP_NOT_IMPLEMENTED;
        }
        if (r->read_body == REQUEST_CHUNKED_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01593)
                          "chunked Transfer-Encoding forbidden: %s", r->uri);
            return (lenp) ? HTTP_BAD_REQUEST : HTTP_LENGTH_REQUIRED;
        }

        r->read_chunked = 1;
    }
    else if (lenp) {
        if (!ap_parse_strict_length(&r->remaining, lenp)) {
            r->remaining = 0;
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01594)
                          "Invalid Content-Length '%s'", lenp);
            return HTTP_BAD_REQUEST;
        }
    }

    if ((r->read_body == REQUEST_NO_BODY)
        && (r->read_chunked || (r->remaining > 0))) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01595)
                      "%s with body is not allowed for %s", r->method, r->uri);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    if (limit_req_body > 0 && (r->remaining > limit_req_body)) {
        /* will be logged when the body is discarded */
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

#ifdef AP_DEBUG
    {
        /* Make sure ap_getline() didn't leave any droppings. */
        core_request_config *req_cfg =
            (core_request_config *)ap_get_core_module_config(r->request_config);
        AP_DEBUG_ASSERT(APR_BRIGADE_EMPTY(req_cfg->bb));
    }
#endif

    return OK;
}

AP_DECLARE(int) ap_should_client_block(request_rec *r)
{
    /* First check if we have already read the request body */

    if (r->read_length || (!r->read_chunked && (r->remaining <= 0))) {
        return 0;
    }

    return 1;
}

/* get_client_block is called in a loop to get the request message body.
 * This is quite simple if the client includes a content-length
 * (the normal case), but gets messy if the body is chunked. Note that
 * r->remaining is used to maintain state across calls and that
 * r->read_length is the total number of bytes given to the caller
 * across all invocations.  It is messy because we have to be careful not
 * to read past the data provided by the client, since these reads block.
 * Returns 0 on End-of-body, -1 on error or premature chunk end.
 *
 */
AP_DECLARE(long) ap_get_client_block(request_rec *r, char *buffer,
                                     apr_size_t bufsiz)
{
    apr_status_t rv;
    apr_bucket_brigade *bb;

    if (r->remaining < 0 || (!r->read_chunked && r->remaining == 0)) {
        return 0;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (bb == NULL) {
        r->connection->keepalive = AP_CONN_CLOSE;
        return -1;
    }

    rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                        APR_BLOCK_READ, bufsiz);

    /* We lose the failure code here.  This is why ap_get_client_block should
     * not be used.
     */
    if (rv == AP_FILTER_ERROR) {
        /* AP_FILTER_ERROR means a filter has responded already,
         * we are DONE.
         */
        apr_brigade_destroy(bb);
        return -1;
    }
    if (rv != APR_SUCCESS) {
        /* if we actually fail here, we want to just return and
         * stop trying to read data from the client.
         */
        r->connection->keepalive = AP_CONN_CLOSE;
        apr_brigade_destroy(bb);
        return -1;
    }

    /* If this fails, it means that a filter is written incorrectly and that
     * it needs to learn how to properly handle APR_BLOCK_READ requests by
     * returning data when requested.
     */
    AP_DEBUG_ASSERT(!APR_BRIGADE_EMPTY(bb));

    /* Check to see if EOS in the brigade.
     *
     * If so, we have to leave a nugget for the *next* ap_get_client_block
     * call to return 0.
     */
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
        if (r->read_chunked) {
            r->remaining = -1;
        }
        else {
            r->remaining = 0;
        }
    }

    rv = apr_brigade_flatten(bb, buffer, &bufsiz);
    if (rv != APR_SUCCESS) {
        apr_brigade_destroy(bb);
        return -1;
    }

    /* XXX yank me? */
    r->read_length += bufsiz;

    apr_brigade_destroy(bb);
    return bufsiz;
}

/* Context struct for ap_http_outerror_filter */
typedef struct {
    int seen_eoc;
    int first_error;
} outerror_filter_ctx_t;

/* Filter to handle any error buckets on output */
apr_status_t ap_http_outerror_filter(ap_filter_t *f,
                                     apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    outerror_filter_ctx_t *ctx = (outerror_filter_ctx_t *)(f->ctx);
    apr_bucket *e;

    /* Create context if none is present */
    if (!ctx) {
        ctx = apr_pcalloc(r->pool, sizeof(outerror_filter_ctx_t));
        f->ctx = ctx;
    }
    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = APR_BUCKET_NEXT(e))
    {
        if (AP_BUCKET_IS_ERROR(e)) {
            /*
             * Start of error handling state tree. Just one condition
             * right now :)
             */
            if (((ap_bucket_error *)(e->data))->status == HTTP_BAD_GATEWAY) {
                /* stream aborted and we have not ended it yet */
                r->connection->keepalive = AP_CONN_CLOSE;
            }
            /*
             * Memorize the status code of the first error bucket for possible
             * later use.
             */
            if (!ctx->first_error) {
                ctx->first_error = ((ap_bucket_error *)(e->data))->status;
            }
            continue;
        }
        /* Detect EOC buckets and memorize this in the context. */
        if (AP_BUCKET_IS_EOC(e)) {
            r->connection->keepalive = AP_CONN_CLOSE;
            ctx->seen_eoc = 1;
        }
    }
    /*
     * Remove all data buckets that are in a brigade after an EOC bucket
     * was seen, as an EOC bucket tells us that no (further) resource
     * and protocol data should go out to the client. OTOH meta buckets
     * are still welcome as they might trigger needed actions down in
     * the chain (e.g. in network filters like SSL).
     * Remark 1: It is needed to dump ALL data buckets in the brigade
     *           since an filter in between might have inserted data
     *           buckets BEFORE the EOC bucket sent by the original
     *           sender and we do NOT want this data to be sent.
     * Remark 2: Dumping all data buckets here does not necessarily mean
     *           that no further data is send to the client as:
     *           1. Network filters like SSL can still be triggered via
     *              meta buckets to talk with the client e.g. for a
     *              clean shutdown.
     *           2. There could be still data that was buffered before
     *              down in the chain that gets flushed by a FLUSH or an
     *              EOS bucket.
     */
    if (ctx->seen_eoc) {
        /*
         * Set the request status to the status of the first error bucket.
         * This should ensure that we log an appropriate status code in
         * the access log.
         * We need to set r->status on each call after we noticed an EOC as
         * data bucket generators like ap_die might have changed the status
         * code. But we know better in this case and insist on the status
         * code that we have seen in the error bucket.
         */
        if (ctx->first_error) {
            r->status = ctx->first_error;
        }
        for (e = APR_BRIGADE_FIRST(b);
             e != APR_BRIGADE_SENTINEL(b);
             e = APR_BUCKET_NEXT(e))
        {
            if (!APR_BUCKET_IS_METADATA(e)) {
                APR_BUCKET_REMOVE(e);
            }
        }
    }

    return ap_pass_brigade(f->next,  b);
}
