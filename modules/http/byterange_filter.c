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
 * byterange_filter.c --- HTTP byterange filter and friends.
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

#define CORE_PRIVATE
#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
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

#ifndef AP_DEFAULT_MAX_RANGES
#define AP_DEFAULT_MAX_RANGES 200
#endif

static int ap_set_byterange(request_rec *r, apr_off_t clength,
                            apr_array_header_t **indexes);

/*
 * Here we try to be compatible with clients that want multipart/x-byteranges
 * instead of multipart/byteranges (also see above), as per HTTP/1.1. We
 * look for the Request-Range header (e.g. Netscape 2 and 3) as an indication
 * that the browser supports an older protocol. We also check User-Agent
 * for Microsoft Internet Explorer 3, which needs this as well.
 */
static int use_range_x(request_rec *r)
{
    const char *ua;
    return (apr_table_get(r->headers_in, "Request-Range")
            || ((ua = apr_table_get(r->headers_in, "User-Agent"))
                && ap_strstr_c(ua, "MSIE 3")));
}

#define BYTERANGE_FMT "%" APR_OFF_T_FMT "-%" APR_OFF_T_FMT "/%" APR_OFF_T_FMT

static apr_status_t copy_brigade_range(apr_bucket_brigade *bb,
                                       apr_bucket_brigade *bbout,
                                       apr_off_t start,
                                       apr_off_t end)
{
    apr_bucket *first = NULL, *last = NULL, *out_first = NULL, *e;
    apr_uint64_t pos = 0, off_first = 0, off_last = 0;
    apr_status_t rv;
    apr_uint64_t start64, end64;
    apr_off_t pofft = 0;

    /*
     * Once we know that start and end are >= 0 convert everything to apr_uint64_t.
     * See the comments in apr_brigade_partition why.
     * In short apr_off_t (for values >= 0)and apr_size_t fit into apr_uint64_t.
     */
    start64 = (apr_uint64_t)start;
    end64 = (apr_uint64_t)end;

    if (start < 0 || end < 0 || start64 > end64)
        return APR_EINVAL;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        apr_uint64_t elen64;
        /* we know that no bucket has undefined length (-1) */
        AP_DEBUG_ASSERT(e->length != (apr_size_t)(-1));
        elen64 = (apr_uint64_t)e->length;
        if (!first && (elen64 + pos > start64)) {
            first = e;
            off_first = pos;
        }
        if (elen64 + pos > end64) {
            last = e;
            off_last = pos;
            break;
        }
        pos += elen64;
    }
    if (!first || !last)
        return APR_EINVAL;

    e = first;
    while (1)
    {
        apr_bucket *copy;
        AP_DEBUG_ASSERT(e != APR_BRIGADE_SENTINEL(bb));
        rv = apr_bucket_copy(e, &copy);
        if (rv != APR_SUCCESS) {
            apr_brigade_cleanup(bbout);
            return rv;
        }

        APR_BRIGADE_INSERT_TAIL(bbout, copy);
        if (e == first) {
            if (off_first != start64) {
                rv = apr_bucket_split(copy, (apr_size_t)(start64 - off_first));
                if (rv != APR_SUCCESS) {
                    apr_brigade_cleanup(bbout);
                    return rv;
                }
                out_first = APR_BUCKET_NEXT(copy);
                APR_BUCKET_REMOVE(copy);
                apr_bucket_destroy(copy);
            }
            else {
                out_first = copy;
            }
        }
        if (e == last) {
            if (e == first) {
                off_last += start64 - off_first;
                copy = out_first;
            }
            if (end64 - off_last != (apr_uint64_t)e->length) {
                rv = apr_bucket_split(copy, (apr_size_t)(end64 + 1 - off_last));
                if (rv != APR_SUCCESS) {
                    apr_brigade_cleanup(bbout);
                    return rv;
                }
                copy = APR_BUCKET_NEXT(copy);
                if (copy != APR_BRIGADE_SENTINEL(bbout)) {
                    APR_BUCKET_REMOVE(copy);
                    apr_bucket_destroy(copy);
                }
            }
            break;
        }
        e = APR_BUCKET_NEXT(e);
    }

    AP_DEBUG_ASSERT(APR_SUCCESS == apr_brigade_length(bbout, 1, &pofft));
    pos = (apr_uint64_t)pofft;
    AP_DEBUG_ASSERT(pos == end64 - start64 + 1);
    return APR_SUCCESS;
}

typedef struct indexes_t {
    apr_off_t start;
    apr_off_t end;
} indexes_t;

static int get_max_ranges(request_rec *r) { 
    core_dir_config *core_conf = ap_get_module_config(r->per_dir_config, 
                                                      &core_module);
    if (core_conf->max_ranges >= 0 || core_conf->max_ranges == AP_MAXRANGES_UNLIMITED) { 
        return core_conf->max_ranges;
    }

    /* Any other negative val means the default */
    return AP_DEFAULT_MAX_RANGES;
}

static apr_status_t send_416(ap_filter_t *f, apr_bucket_brigade *tmpbb)
{
    apr_bucket *e;
    conn_rec *c = f->r->connection;
    ap_remove_output_filter(f);
    f->r->status = HTTP_OK;
    e = ap_bucket_error_create(HTTP_RANGE_NOT_SATISFIABLE, NULL,
                               f->r->pool, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(tmpbb, e);
    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(tmpbb, e);
    return ap_pass_brigade(f->next, tmpbb);
}

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_byterange_filter(ap_filter_t *f,
                                                         apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *e;
    apr_bucket_brigade *bsend;
    apr_bucket_brigade *tmpbb;
    apr_off_t range_start;
    apr_off_t range_end;
    apr_off_t clength = 0;
    apr_status_t rv;
    int found = 0;
    int num_ranges;
    char *boundary = NULL;
    char *bound_head = NULL;
    apr_array_header_t *indexes;
    indexes_t *idx;
    int i;
    int original_status;
    int max_ranges = get_max_ranges(r);

    /*
     * Iterate through the brigade until reaching EOS or a bucket with
     * unknown length.
     */
    for (e = APR_BRIGADE_FIRST(bb);
         (e != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(e)
          && e->length != (apr_size_t)-1);
         e = APR_BUCKET_NEXT(e)) {
        clength += e->length;
    }

    /*
     * Don't attempt to do byte range work if this brigade doesn't
     * contain an EOS, or if any of the buckets has an unknown length;
     * this avoids the cases where it is expensive to perform
     * byteranging (i.e. may require arbitrary amounts of memory).
     */
    if (!APR_BUCKET_IS_EOS(e) || clength <= 0) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    original_status = r->status;
    num_ranges = ap_set_byterange(r, clength, &indexes);

    /* We have nothing to do, get out of the way. */
    if (num_ranges == 0 || (max_ranges >= 0 && num_ranges > max_ranges)) {
        r->status = original_status;
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    /* this brigade holds what we will be sending */
    bsend = apr_brigade_create(r->pool, c->bucket_alloc);

    if (num_ranges < 0)
        return send_416(f, bsend);

    if (num_ranges > 1) {
        /* Is ap_make_content_type required here? */
        const char *orig_ct = ap_make_content_type(r, r->content_type);
        boundary = apr_psprintf(r->pool, "%" APR_UINT64_T_HEX_FMT "%lx",
                                (apr_uint64_t)r->request_time, c->id);

        ap_set_content_type(r, apr_pstrcat(r->pool, "multipart",
                                           use_range_x(r) ? "/x-" : "/",
                                           "byteranges; boundary=",
                                           boundary, NULL));

        if (strcasecmp(orig_ct, NO_CONTENT_TYPE)) {
            bound_head = apr_pstrcat(r->pool,
                                     CRLF "--", boundary,
                                     CRLF "Content-type: ",
                                     orig_ct,
                                     CRLF "Content-range: bytes ",
                                     NULL);
        }
        else {
            /* if we have no type for the content, do our best */
            bound_head = apr_pstrcat(r->pool,
                                     CRLF "--", boundary,
                                     CRLF "Content-range: bytes ",
                                     NULL);
        }
        ap_xlate_proto_to_ascii(bound_head, strlen(bound_head));
    }

    tmpbb = apr_brigade_create(r->pool, c->bucket_alloc);

    idx = (indexes_t *)indexes->elts;
    for (i = 0; i < indexes->nelts; i++, idx++) {
        range_start = idx->start;
        range_end = idx->end;

        rv = copy_brigade_range(bb, tmpbb, range_start, range_end);
        if (rv != APR_SUCCESS ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "copy_brigade_range() failed [%" APR_OFF_T_FMT
                          "-%" APR_OFF_T_FMT ",%" APR_OFF_T_FMT "]",
                          range_start, range_end, clength);
            continue;
        }
        found = 1;

        /*
         * For single range requests, we must produce Content-Range header.
         * Otherwise, we need to produce the multipart boundaries.
         */
        if (num_ranges == 1) {
            apr_table_setn(r->headers_out, "Content-Range",
                           apr_psprintf(r->pool, "bytes " BYTERANGE_FMT,
                                        range_start, range_end, clength));
        }
        else {
            char *ts;

            e = apr_bucket_pool_create(bound_head, strlen(bound_head),
                                       r->pool, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bsend, e);

            ts = apr_psprintf(r->pool, BYTERANGE_FMT CRLF CRLF,
                              range_start, range_end, clength);
            ap_xlate_proto_to_ascii(ts, strlen(ts));
            e = apr_bucket_pool_create(ts, strlen(ts), r->pool,
                                       c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bsend, e);
        }

        APR_BRIGADE_CONCAT(bsend, tmpbb);
        if (i && !(i & 0x1F)) {
            /*
             * Every now and then, pass what we have down the filter chain.
             * In this case, the content-length filter cannot calculate and
             * set the content length and we must remove any Content-Length
             * header already present.
             */
            apr_table_unset(r->headers_out, "Content-Length");
            if ((rv = ap_pass_brigade(f->next, bsend)) != APR_SUCCESS)
                return rv;
            apr_brigade_cleanup(bsend);
        }
    }

    if (found == 0) {
        /* bsend is assumed to be empty if we get here. */
        return send_416(f, bsend);
    }

    if (num_ranges > 1) {
        char *end;

        /* add the final boundary */
        end = apr_pstrcat(r->pool, CRLF "--", boundary, "--" CRLF, NULL);
        ap_xlate_proto_to_ascii(end, strlen(end));
        e = apr_bucket_pool_create(end, strlen(end), r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bsend, e);
    }

    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bsend, e);

    /* we're done with the original content - all of our data is in bsend. */
    apr_brigade_cleanup(bb);
    apr_brigade_destroy(tmpbb);

    /* send our multipart output */
    return ap_pass_brigade(f->next, bsend);
}

static int ap_set_byterange(request_rec *r, apr_off_t clength,
                            apr_array_header_t **indexes)
{
    const char *range;
    const char *if_range;
    const char *match;
    const char *ct;
    char *cur;
    int num_ranges = 0, unsatisfiable = 0;
    apr_off_t sum_lengths = 0;
    indexes_t *idx;
    int ranges = 1;
    const char *it;

    if (r->assbackwards) {
        return 0;
    }

    /*
     * Check for Range request-header (HTTP/1.1) or Request-Range for
     * backwards-compatibility with second-draft Luotonen/Franks
     * byte-ranges (e.g. Netscape Navigator 2-3).
     *
     * We support this form, with Request-Range, and (farther down) we
     * send multipart/x-byteranges instead of multipart/byteranges for
     * Request-Range based requests to work around a bug in Netscape
     * Navigator 2-3 and MSIE 3.
     */

    if (!(range = apr_table_get(r->headers_in, "Range"))) {
        range = apr_table_get(r->headers_in, "Request-Range");
    }

    if (!range || strncasecmp(range, "bytes=", 6) || r->status != HTTP_OK) {
        return 0;
    }

    /* is content already a single range? */
    if (apr_table_get(r->headers_out, "Content-Range")) {
       return 0;
    }

    /* is content already a multiple range? */
    if ((ct = apr_table_get(r->headers_out, "Content-Type"))
        && (!strncasecmp(ct, "multipart/byteranges", 20)
            || !strncasecmp(ct, "multipart/x-byteranges", 22))) {
       return 0;
    }

    /*
     * Check the If-Range header for Etag or Date.
     * Note that this check will return false (as required) if either
     * of the two etags are weak.
     */
    if ((if_range = apr_table_get(r->headers_in, "If-Range"))) {
        if (if_range[0] == '"') {
            if (!(match = apr_table_get(r->headers_out, "Etag"))
                || (strcmp(if_range, match) != 0)) {
                return 0;
            }
        }
        else if (!(match = apr_table_get(r->headers_out, "Last-Modified"))
                 || (strcmp(if_range, match) != 0)) {
            return 0;
        }
    }

    range += 6;
    it = range;
    while (*it) {
        if (*it++ == ',') {
            ranges++;
        }
    }
    it = range;
    *indexes = apr_array_make(r->pool, ranges, sizeof(indexes_t));
    while ((cur = ap_getword(r->pool, &range, ','))) {
        char *dash;
        char *errp;
        apr_off_t number, start, end;

        if (!*cur)
            break;

        /*
         * Per RFC 2616 14.35.1: If there is at least one syntactically invalid
         * byte-range-spec, we must ignore the whole header.
         */

        if (!(dash = strchr(cur, '-'))) {
            return 0;
        }

        if (dash == cur) {
            /* In the form "-5" */
            if (apr_strtoff(&number, dash+1, &errp, 10) || *errp) {
                return 0;
            }
            if (number < 1) {
                return 0;
            }
            start = clength - number;
            end = clength - 1;
        }
        else {
            *dash++ = '\0';
            if (apr_strtoff(&number, cur, &errp, 10) || *errp) {
                return 0;
            }
            start = number;
            if (*dash) {
                if (apr_strtoff(&number, dash, &errp, 10) || *errp) {
                    return 0;
                }
                end = number;
                if (start > end) {
                    return 0;
                }
            }
            else {                  /* "5-" */
                end = clength - 1;
            }
        }

        if (start < 0) {
            start = 0;
        }
        if (start >= clength) {
            unsatisfiable = 1;
            continue;
        }
        if (end >= clength) {
            end = clength - 1;
        }

        idx = (indexes_t *)apr_array_push(*indexes);
        idx->start = start;
        idx->end = end;
        sum_lengths += end - start + 1;
        /* new set again */
        num_ranges++;
    }

    if (num_ranges == 0 && unsatisfiable) {
        /* If all ranges are unsatisfiable, we should return 416 */
        return -1;
    }
    if (sum_lengths >= clength) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Sum of ranges not smaller than file, ignoring.");
        return 0;
    }

    r->status = HTTP_PARTIAL_CONTENT;
    r->range = it;

    return num_ranges;
}
