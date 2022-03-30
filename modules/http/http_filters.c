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
    unsigned int at_trailers:1;
    unsigned int at_eos:1;
    unsigned int seen_data:1;
} http1_in_ctx_t;

/* This is the HTTP_INPUT filter for HTTP requests and responses from
 * proxied servers (mod_proxy).  It handles incoming trailers from
 * HEADER buckets and ensures EOS on repeated reads.
 */
apr_status_t ap_http_filter(ap_filter_t *f, apr_bucket_brigade *b,
                            ap_input_mode_t mode, apr_read_type_e block,
                            apr_off_t readbytes)
{
    apr_bucket *e, *next;
    http1_in_ctx_t *ctx = f->ctx;
    request_rec *r = f->r;
    apr_status_t rv;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
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
            && r->expecting_100 && r->proto_num >= HTTP_VERSION(1,1)
            && !(ctx->at_eos || r->eos_sent || r->bytes_sent)) {
        if (!ap_is_HTTP_SUCCESS(r->status)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                          "ap_http_in_filter: status != OK, not sending 100-continue");
            ctx->at_eos = 1; /* send EOS below */
        }
        else if (!ctx->seen_data) {
            int saved_status = r->status;
            const char *saved_status_line = r->status_line;
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                          "ap_http_in_filter: sending 100-continue");
            r->status = HTTP_CONTINUE;
            r->status_line = NULL;
            ap_send_interim_response(r, 0);
            AP_DEBUG_ASSERT(!r->expecting_100);
            r->status_line = saved_status_line;
            r->status = saved_status;
        }
        else {
            /* https://tools.ietf.org/html/rfc7231#section-5.1.1
             *   A server MAY omit sending a 100 (Continue) response if it
             *   has already received some or all of the message body for
             *   the corresponding request [...]
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10260)
                          "request body already/partly received while "
                          "100-continue is expected, omit sending interim "
                          "response");
            r->expecting_100 = 0;
        }
    }

    /* sanity check in case we're read twice */
    if (ctx->at_eos) {
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        rv = APR_SUCCESS;
        goto cleanup;
    }

    rv = ap_get_brigade(f->next, b, mode, block, readbytes);
    if (APR_SUCCESS == rv) {
        for (e = APR_BRIGADE_FIRST(b);
             e != APR_BRIGADE_SENTINEL(b);
             e = next)
        {
            next = APR_BUCKET_NEXT(e);
            if (!APR_BUCKET_IS_METADATA(e)) {
                if (e->length != 0) {
                    ctx->seen_data = 1;
                }
                if (ctx->at_trailers) {
                    /* DATA after trailers? Someone smuggling something? */
                    rv = AP_FILTER_ERROR;
                    goto cleanup;
                }
                continue;
            }
            if (AP_BUCKET_IS_HEADERS(e)) {
                /* trailers */
                ap_bucket_headers * hdrs = e->data;

                /* Allow multiple HEADERS buckets carrying trailers here,
                 * will not happen from HTTP/1.x and current H2 implementation,
                 * but is an option. */
                ctx->at_trailers = 1;
                if (!apr_is_empty_table(hdrs->headers)) {
                    r->trailers_in = apr_table_overlay(r->pool, r->trailers_in, hdrs->headers);
                }
                apr_bucket_delete(e);
            }
            if (APR_BUCKET_IS_EOS(e)) {
                ctx->at_eos = 1;
                if (!apr_is_empty_table(r->trailers_in)) {
                    core_server_config *conf = ap_get_module_config(
                        r->server->module_config, &core_module);
                    if (conf->merge_trailers == AP_MERGE_TRAILERS_ENABLE) {
                        r->headers_in = apr_table_overlay(r->pool, r->headers_in, r->trailers_in);
                    }
                }
                goto cleanup;
            }
        }
    }

cleanup:
    return rv;
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
static void basic_http_header_check(request_rec *r)
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
}

static const char *get_status_reason(const char *status_line)
{
    if (status_line && strlen(status_line) > 4) {
        return status_line + 4;
    }
    return NULL;
}

static apr_bucket *create_response_bucket(request_rec *r, apr_bucket_alloc_t *bucket_alloc)
{
    const char *ctype;

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
    basic_http_header_check(r);

    if (AP_STATUS_IS_HEADER_ONLY(r->status)) {
        apr_table_unset(r->headers_out, "Content-Length");
        r->content_type = r->content_encoding = NULL;
        r->content_languages = NULL;
        r->clength = r->chunked = 0;
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

    /* r->headers_out fully prepared. Create a headers bucket
     * containing the response to send down the filter chain.
     */
    return ap_bucket_response_create(r->status, get_status_reason(r->status_line),
                                     r->headers_out, r->notes, r->pool, bucket_alloc);
}

static apr_bucket *create_trailers_bucket(request_rec *r, apr_bucket_alloc_t *bucket_alloc)
{
    if (r->trailers_out && !apr_is_empty_table(r->trailers_out)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "sending trailers");
        return ap_bucket_headers_create(r->trailers_out, r->pool, bucket_alloc);
    }
    return NULL;
}

AP_DECLARE(void) ap_basic_http_header(request_rec *r, apr_bucket_brigade *bb)
{
    apr_bucket *b;

    basic_http_header_check(r);
    b = create_response_bucket(r, bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
}

typedef struct header_filter_ctx {
    int final_status;
    int final_header_only;
    int dying;
} header_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
                                                           apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *e, *respb = NULL, *trigger = NULL, *eos = NULL;
    header_filter_ctx *ctx = f->ctx;
    ap_bucket_error *eb = NULL;
    apr_status_t rv = APR_SUCCESS;
    int recursive_error = 0;

    AP_DEBUG_ASSERT(!r->main);

    if (!ctx) {
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(header_filter_ctx));
    }

    if (ctx->final_status) {
        /* Sent the final status, eat body if response must not have one. */
        if (ctx->final_header_only) {
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
    else {
        /* Determine if it is time to insert the response bucket for
         * the request. Request handlers just write content or an EOS
         * and that needs to take the current state of request_rec to
         * send on status and headers as a response bucket.
         *
         * But we also send interim responses (as response buckets)
         * through this filter and that must not trigger generating
         * an additional response bucket.
         *
         * Waiting on a DATA/ERROR/EOS bucket alone is not enough,
         * unfortunately, as some handlers trigger response generation
         * by just writing a FLUSH (see mod_lua's websocket for example).
         */
        for (e = APR_BRIGADE_FIRST(b);
             e != APR_BRIGADE_SENTINEL(b) && !trigger;
             e = APR_BUCKET_NEXT(e))
        {
            if (AP_BUCKET_IS_RESPONSE(e)) {
                /* remember the last one if there are many. */
                respb = e;
            }
            else if (APR_BUCKET_IS_FLUSH(e)) {
                /* flush without response bucket triggers */
                if (!respb) trigger = e;
            }
            else if (APR_BUCKET_IS_EOS(e)) {
                trigger = e;
            }
            else if (AP_BUCKET_IS_ERROR(e)) {
                /* Need to handle this below via ap_die() */
                break;
            }
            else {
                /* First content bucket, always triggering the response.*/
                trigger = e;
            }
        }

        if (respb) {
            ap_bucket_response *resp = respb->data;
            if (resp->status >= 200 || resp->status == 101) {
                /* Someone is passing the final response, remember it
                 * so we no longer generate one. */
                ctx->final_status = resp->status;
                ctx->final_header_only = AP_STATUS_IS_HEADER_ONLY(resp->status);
            }
        }

        if (trigger && !ctx->final_status) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                          "ap_http_header_filter prep response status %d",
                          r->status);
            if (!check_headers(r)) {
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
            respb = create_response_bucket(r, b->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(trigger, respb);
            ctx->final_status = r->status;
            ctx->final_header_only = (r->header_only || AP_STATUS_IS_HEADER_ONLY(r->status));
            r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */
        }
    }

    /* Look for ERROR/EOC/EOS that require special handling. */
    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = APR_BUCKET_NEXT(e))
    {
        if (APR_BUCKET_IS_METADATA(e)) {
            if (APR_BUCKET_IS_EOS(e)) {
                if (!eos) eos = e;
            }
            else if (AP_BUCKET_IS_EOC(e)) {
                /* If we see an EOC bucket it is a signal that we should get out
                 * of the way doing nothing.
                 */
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, b);
            }
            else if (AP_BUCKET_IS_ERROR(e)) {
                int status;
                eb = e->data;
                status = eb->status;
                apr_brigade_cleanup(b);
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                              "ap_http_header_filter error bucket, die with %d and error",
                              status);
                /* This will invoke us again */
                ctx->dying = 1;
                ap_die(status, r);
                return AP_FILTER_ERROR;
            }
        }
    }

    if (r->assbackwards) {
        r->sent_bodyct = 1;
        ap_remove_output_filter(f);
        rv = ap_pass_brigade(f->next, b);
        goto out;
    }

    if (eos) {
        e = create_trailers_bucket(r, b->bucket_alloc);
        if (e) {
            APR_BUCKET_INSERT_BEFORE(eos, e);
        }
        ap_remove_output_filter(f);
    }
    else if (ctx->final_status == 101) {
        /* switching protocol, whatever comes next is not HTTP/1.x */
        ap_remove_output_filter(f);
    }

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

    case APR_EGENERAL:
        return HTTP_BAD_REQUEST;

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
 * of a non-zero Content-Length or r->body_indeterminate.
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
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");

    r->read_body = read_policy;
    r->read_chunked = 0;
    r->remaining = 0;

    if (r->body_indeterminate) {
        /* Protocols like HTTP/2 can carry bodies without length and
         * HTTP/1.1 has chunked encoding signalled via this note.
         */
        if (r->read_body == REQUEST_CHUNKED_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01593)
                          "indeterminate request body length forbidden: %s", r->uri);
            r->read_chunked = 0;
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
        apr_bucket *e;

        /* work around our silent swallowing of error messages by mapping
         * error codes at this point, and sending an error bucket back
         * upstream.
         */
        apr_brigade_cleanup(bb);

        e = ap_bucket_error_create(
                ap_map_http_request_error(rv, HTTP_BAD_REQUEST), NULL, r->pool,
                r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);

        e = apr_bucket_eos_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);

        rv = ap_pass_brigade(r->output_filters, bb);
        if (APR_SUCCESS != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, APLOGNO(02484)
                          "Error while writing error response");
        }

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
            if (((ap_bucket_error *)(e->data))->status == HTTP_BAD_GATEWAY ||
                ((ap_bucket_error *)(e->data))->status == HTTP_GATEWAY_TIME_OUT) {
                /* stream aborted and we have not ended it yet */
                r->connection->keepalive = AP_CONN_CLOSE;
            }
            continue;
        }
        /* Detect EOC buckets and memorize this in the context. */
        if (AP_BUCKET_IS_EOC(e)) {
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
        e = APR_BRIGADE_FIRST(b);
        while (e != APR_BRIGADE_SENTINEL(b)) {
            apr_bucket *c = e;
            e = APR_BUCKET_NEXT(e);
            if (!APR_BUCKET_IS_METADATA(c)) {
                apr_bucket_delete(c);
            }
        }
    }

    return ap_pass_brigade(f->next,  b);
}
