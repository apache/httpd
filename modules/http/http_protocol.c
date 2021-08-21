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
 * http_protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
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
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "apr_date.h"           /* For apr_date_parse_http and APR_DATE_BAD */
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"
#include "ap_mpm.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

APLOG_USE_MODULE(http);

/* New Apache routine to map status codes into array indices
 *  e.g.  100 -> 0,  101 -> 1,  200 -> 2 ...
 * The number of status lines must equal the value of
 * RESPONSE_CODES (httpd.h) and must be listed in order.
 * No gaps are allowed between X00 and the largest Xnn
 * for any X (see ap_index_of_response).
 * When adding a new code here, add a define to httpd.h
 * as well.
 */

static const char * const status_lines[RESPONSE_CODES] =
{
    "100 Continue",
    "101 Switching Protocols",
    "102 Processing",
#define LEVEL_200  3
    "200 OK",
    "201 Created",
    "202 Accepted",
    "203 Non-Authoritative Information",
    "204 No Content",
    "205 Reset Content",
    "206 Partial Content",
    "207 Multi-Status",
    "208 Already Reported",
    NULL, /* 209 */
    NULL, /* 210 */
    NULL, /* 211 */
    NULL, /* 212 */
    NULL, /* 213 */
    NULL, /* 214 */
    NULL, /* 215 */
    NULL, /* 216 */
    NULL, /* 217 */
    NULL, /* 218 */
    NULL, /* 219 */
    NULL, /* 220 */
    NULL, /* 221 */
    NULL, /* 222 */
    NULL, /* 223 */
    NULL, /* 224 */
    NULL, /* 225 */
    "226 IM Used",
#define LEVEL_300 30
    "300 Multiple Choices",
    "301 Moved Permanently",
    "302 Found",
    "303 See Other",
    "304 Not Modified",
    "305 Use Proxy",
    NULL, /* 306 */
    "307 Temporary Redirect",
    "308 Permanent Redirect",
#define LEVEL_400 39
    "400 Bad Request",
    "401 Unauthorized",
    "402 Payment Required",
    "403 Forbidden",
    "404 Not Found",
    "405 Method Not Allowed",
    "406 Not Acceptable",
    "407 Proxy Authentication Required",
    "408 Request Timeout",
    "409 Conflict",
    "410 Gone",
    "411 Length Required",
    "412 Precondition Failed",
    "413 Request Entity Too Large",
    "414 Request-URI Too Long",
    "415 Unsupported Media Type",
    "416 Requested Range Not Satisfiable",
    "417 Expectation Failed",
    NULL, /* 418 */
    NULL, /* 419 */
    NULL, /* 420 */
    "421 Misdirected Request",
    "422 Unprocessable Entity",
    "423 Locked",
    "424 Failed Dependency",
    NULL, /* 425 */
    "426 Upgrade Required",
    NULL, /* 427 */
    "428 Precondition Required",
    "429 Too Many Requests",
    NULL, /* 430 */
    "431 Request Header Fields Too Large",
    NULL, /* 432 */
    NULL, /* 433 */
    NULL, /* 434 */
    NULL, /* 435 */
    NULL, /* 436 */
    NULL, /* 437 */
    NULL, /* 438 */
    NULL, /* 439 */
    NULL, /* 440 */
    NULL, /* 441 */
    NULL, /* 442 */
    NULL, /* 443 */
    NULL, /* 444 */
    NULL, /* 445 */
    NULL, /* 446 */
    NULL, /* 447 */
    NULL, /* 448 */
    NULL, /* 449 */
    NULL, /* 450 */
    "451 Unavailable For Legal Reasons",
#define LEVEL_500 91
    "500 Internal Server Error",
    "501 Not Implemented",
    "502 Bad Gateway",
    "503 Service Unavailable",
    "504 Gateway Timeout",
    "505 HTTP Version Not Supported",
    "506 Variant Also Negotiates",
    "507 Insufficient Storage",
    "508 Loop Detected",
    NULL, /* 509 */
    "510 Not Extended",
    "511 Network Authentication Required"
};

APR_HOOK_STRUCT(
    APR_HOOK_LINK(insert_error_filter)
)

AP_IMPLEMENT_HOOK_VOID(insert_error_filter, (request_rec *r), (r))

/* The index of the first bit field that is used to index into a limit
 * bitmask. M_INVALID + 1 to METHOD_NUMBER_LAST.
 */
#define METHOD_NUMBER_FIRST (M_INVALID + 1)

/* The max method number. Method numbers are used to shift bitmasks,
 * so this cannot exceed 63, and all bits high is equal to -1, which is a
 * special flag, so the last bit used has index 62.
 */
#define METHOD_NUMBER_LAST  62

static int is_mpm_running(void)
{
    int mpm_state = 0;

    if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
      return 0;
    }

    if (mpm_state == AP_MPMQ_STOPPING) {
      return 0;
    }

    return 1;
}


AP_DECLARE(int) ap_set_keepalive(request_rec *r)
{
    int ka_sent = 0;
    int left = r->server->keep_alive_max - r->connection->keepalives;
    int wimpy = ap_find_token(r->pool,
                              apr_table_get(r->headers_out, "Connection"),
                              "close");
    const char *conn = apr_table_get(r->headers_in, "Connection");

    /* The following convoluted conditional determines whether or not
     * the current connection should remain persistent after this response
     * (a.k.a. HTTP Keep-Alive) and whether or not the output message
     * body should use the HTTP/1.1 chunked transfer-coding.  In English,
     *
     *   IF  we have not marked this connection as errored;
     *   and the client isn't expecting 100-continue (PR47087 - more
     *       input here could be the client continuing when we're
     *       closing the request).
     *   and the response body has a defined length due to the status code
     *       being 304 or 204, the request method being HEAD, already
     *       having defined Content-Length or Transfer-Encoding: chunked, or
     *       the request version being HTTP/1.1 and thus capable of being set
     *       as chunked [we know the (r->chunked = 1) side-effect is ugly];
     *   and the server configuration enables keep-alive;
     *   and the server configuration has a reasonable inter-request timeout;
     *   and there is no maximum # requests or the max hasn't been reached;
     *   and the response status does not require a close;
     *   and the response generator has not already indicated close;
     *   and the client did not request non-persistence (Connection: close);
     *   and    we haven't been configured to ignore the buggy twit
     *       or they're a buggy twit coming through a HTTP/1.1 proxy
     *   and    the client is requesting an HTTP/1.0-style keep-alive
     *       or the client claims to be HTTP/1.1 compliant (perhaps a proxy);
     *   and this MPM process is not already exiting
     *   THEN we can be persistent, which requires more headers be output.
     *
     * Note that the condition evaluation order is extremely important.
     */
    if ((r->connection->keepalive != AP_CONN_CLOSE)
        && !r->expecting_100
        && (r->header_only
            || AP_STATUS_IS_HEADER_ONLY(r->status)
            || apr_table_get(r->headers_out, "Content-Length")
            || ap_is_chunked(r->pool,
                                  apr_table_get(r->headers_out,
                                                "Transfer-Encoding"))
            || ((r->proto_num >= HTTP_VERSION(1,1))
                && (r->chunked = 1))) /* THIS CODE IS CORRECT, see above. */
        && r->server->keep_alive
        && (r->server->keep_alive_timeout > 0)
        && ((r->server->keep_alive_max == 0)
            || (left > 0))
        && !ap_status_drops_connection(r->status)
        && !wimpy
        && !ap_find_token(r->pool, conn, "close")
        && (!apr_table_get(r->subprocess_env, "nokeepalive")
            || apr_table_get(r->headers_in, "Via"))
        && ((ka_sent = ap_find_token(r->pool, conn, "keep-alive"))
            || (r->proto_num >= HTTP_VERSION(1,1)))
        && is_mpm_running()) {

        r->connection->keepalive = AP_CONN_KEEPALIVE;
        r->connection->keepalives++;

        /* If they sent a Keep-Alive token, send one back */
        if (ka_sent) {
            if (r->server->keep_alive_max) {
                apr_table_setn(r->headers_out, "Keep-Alive",
                       apr_psprintf(r->pool, "timeout=%d, max=%d",
                            (int)apr_time_sec(r->server->keep_alive_timeout),
                            left));
            }
            else {
                apr_table_setn(r->headers_out, "Keep-Alive",
                      apr_psprintf(r->pool, "timeout=%d",
                            (int)apr_time_sec(r->server->keep_alive_timeout)));
            }
            apr_table_mergen(r->headers_out, "Connection", "Keep-Alive");
        }

        return 1;
    }

    /* Otherwise, we need to indicate that we will be closing this
     * connection immediately after the current response.
     *
     * We only really need to send "close" to HTTP/1.1 clients, but we
     * always send it anyway, because a broken proxy may identify itself
     * as HTTP/1.0, but pass our request along with our HTTP/1.1 tag
     * to a HTTP/1.1 client. Better safe than sorry.
     */
    if (!wimpy) {
        apr_table_mergen(r->headers_out, "Connection", "close");
    }

    /*
     * If we had previously been a keepalive connection and this
     * is the last one, then bump up the number of keepalives
     * we've had
     */
    if ((r->connection->keepalive != AP_CONN_CLOSE)
        && r->server->keep_alive_max
        && !left) {
        r->connection->keepalives++;
    }
    r->connection->keepalive = AP_CONN_CLOSE;

    return 0;
}

AP_DECLARE(ap_condition_e) ap_condition_if_match(request_rec *r,
        apr_table_t *headers)
{
    const char *if_match, *etag;

    /* A server MUST use the strong comparison function (see section 13.3.3)
     * to compare the entity tags in If-Match.
     */
    if ((if_match = apr_table_get(r->headers_in, "If-Match")) != NULL) {
        if (if_match[0] == '*'
                || ((etag = apr_table_get(headers, "ETag")) != NULL
                        && ap_find_etag_strong(r->pool, if_match, etag))) {
            return AP_CONDITION_STRONG;
        }
        else {
            return AP_CONDITION_NOMATCH;
        }
    }

    return AP_CONDITION_NONE;
}

AP_DECLARE(ap_condition_e) ap_condition_if_unmodified_since(request_rec *r,
        apr_table_t *headers)
{
    const char *if_unmodified;

    if_unmodified = apr_table_get(r->headers_in, "If-Unmodified-Since");
    if (if_unmodified) {
        apr_int64_t mtime, reqtime;

        apr_time_t ius = apr_time_sec(apr_date_parse_http(if_unmodified));

        /* All of our comparisons must be in seconds, because that's the
         * highest time resolution the HTTP specification allows.
         */
        mtime = apr_time_sec(apr_date_parse_http(
                        apr_table_get(headers, "Last-Modified")));
        if (mtime == APR_DATE_BAD) {
            mtime = apr_time_sec(r->mtime ? r->mtime : apr_time_now());
        }

        reqtime = apr_time_sec(apr_date_parse_http(
                        apr_table_get(headers, "Date")));
        if (!reqtime) {
            reqtime = apr_time_sec(r->request_time);
        }

        if ((ius != APR_DATE_BAD) && (mtime > ius)) {
            if (reqtime < mtime + 60) {
                if (apr_table_get(r->headers_in, "Range")) {
                    /* weak matches not allowed with Range requests */
                    return AP_CONDITION_NOMATCH;
                }
                else {
                    return AP_CONDITION_WEAK;
                }
            }
            else {
                return AP_CONDITION_STRONG;
            }
        }
        else {
            return AP_CONDITION_NOMATCH;
        }
    }

    return AP_CONDITION_NONE;
}

AP_DECLARE(ap_condition_e) ap_condition_if_none_match(request_rec *r,
        apr_table_t *headers)
{
    const char *if_nonematch, *etag;

    if_nonematch = apr_table_get(r->headers_in, "If-None-Match");
    if (if_nonematch != NULL) {

        if (if_nonematch[0] == '*') {
            return AP_CONDITION_STRONG;
        }

        /* See section 13.3.3 for rules on how to determine if two entities tags
         * match. The weak comparison function can only be used with GET or HEAD
         * requests.
         */
        if (r->method_number == M_GET) {
            if ((etag = apr_table_get(headers, "ETag")) != NULL) {
                if (apr_table_get(r->headers_in, "Range")) {
                    if (ap_find_etag_strong(r->pool, if_nonematch, etag)) {
                        return AP_CONDITION_STRONG;
                    }
                }
                else {
                    if (ap_find_etag_weak(r->pool, if_nonematch, etag)) {
                        return AP_CONDITION_WEAK;
                    }
                }
            }
        }

        else if ((etag = apr_table_get(headers, "ETag")) != NULL
                && ap_find_etag_strong(r->pool, if_nonematch, etag)) {
            return AP_CONDITION_STRONG;
        }
        return AP_CONDITION_NOMATCH;
    }

    return AP_CONDITION_NONE;
}

AP_DECLARE(ap_condition_e) ap_condition_if_modified_since(request_rec *r,
        apr_table_t *headers)
{
    const char *if_modified_since;

    if ((if_modified_since = apr_table_get(r->headers_in, "If-Modified-Since"))
            != NULL) {
        apr_int64_t mtime;
        apr_int64_t ims, reqtime;

        /* All of our comparisons must be in seconds, because that's the
         * highest time resolution the HTTP specification allows.
         */

        mtime = apr_time_sec(apr_date_parse_http(
                        apr_table_get(headers, "Last-Modified")));
        if (mtime == APR_DATE_BAD) {
            mtime = apr_time_sec(r->mtime ? r->mtime : apr_time_now());
        }

        reqtime = apr_time_sec(apr_date_parse_http(
                        apr_table_get(headers, "Date")));
        if (!reqtime) {
            reqtime = apr_time_sec(r->request_time);
        }

        ims = apr_time_sec(apr_date_parse_http(if_modified_since));

        if (ims >= mtime && ims <= reqtime) {
            if (reqtime < mtime + 60) {
                if (apr_table_get(r->headers_in, "Range")) {
                    /* weak matches not allowed with Range requests */
                    return AP_CONDITION_NOMATCH;
                }
                else {
                    return AP_CONDITION_WEAK;
                }
            }
            else {
                return AP_CONDITION_STRONG;
            }
        }
        else {
            return AP_CONDITION_NOMATCH;
        }
    }

    return AP_CONDITION_NONE;
}

AP_DECLARE(ap_condition_e) ap_condition_if_range(request_rec *r,
        apr_table_t *headers)
{
    const char *if_range, *etag;

    if ((if_range = apr_table_get(r->headers_in, "If-Range"))
            && apr_table_get(r->headers_in, "Range")) {
        if (if_range[0] == '"') {

            if ((etag = apr_table_get(headers, "ETag"))
                    && !strcmp(if_range, etag)) {
                return AP_CONDITION_STRONG;
            }
            else {
                return AP_CONDITION_NOMATCH;
            }

        }
        else {
            apr_int64_t mtime;
            apr_int64_t rtime, reqtime;

            /* All of our comparisons must be in seconds, because that's the
             * highest time resolution the HTTP specification allows.
             */

            mtime = apr_time_sec(apr_date_parse_http(
                            apr_table_get(headers, "Last-Modified")));
            if (mtime == APR_DATE_BAD) {
                mtime = apr_time_sec(r->mtime ? r->mtime : apr_time_now());
            }

            reqtime = apr_time_sec(apr_date_parse_http(
                            apr_table_get(headers, "Date")));
            if (!reqtime) {
                reqtime = apr_time_sec(r->request_time);
            }

            rtime = apr_time_sec(apr_date_parse_http(if_range));

            if (rtime == mtime) {
                if (reqtime < mtime + 60) {
                    /* weak matches not allowed with Range requests */
                    return AP_CONDITION_NOMATCH;
                }
                else {
                    return AP_CONDITION_STRONG;
                }
            }
            else {
                return AP_CONDITION_NOMATCH;
            }
        }
    }

    return AP_CONDITION_NONE;
}

AP_DECLARE(int) ap_meets_conditions(request_rec *r)
{
    int not_modified = -1; /* unset by default */
    ap_condition_e cond;

    /* Check for conditional requests --- note that we only want to do
     * this if we are successful so far and we are not processing a
     * subrequest or an ErrorDocument.
     *
     * The order of the checks is important, since ETag checks are supposed
     * to be more accurate than checks relative to the modification time.
     * However, not all documents are guaranteed to *have* ETags, and some
     * might have Last-Modified values w/o ETags, so this gets a little
     * complicated.
     */

    if (!ap_is_HTTP_SUCCESS(r->status) || r->no_local_copy) {
        return OK;
    }

    /* If an If-Match request-header field was given
     * AND the field value is not "*" (meaning match anything)
     * AND if our strong ETag does not match any entity tag in that field,
     *     respond with a status of 412 (Precondition Failed).
     */
    cond = ap_condition_if_match(r, r->headers_out);
    if (AP_CONDITION_NOMATCH == cond) {
        return HTTP_PRECONDITION_FAILED;
    }

    /* Else if a valid If-Unmodified-Since request-header field was given
     * AND the requested resource has been modified since the time
     * specified in this field, then the server MUST
     *     respond with a status of 412 (Precondition Failed).
     */
    cond = ap_condition_if_unmodified_since(r, r->headers_out);
    if (AP_CONDITION_NOMATCH == cond) {
        not_modified = 0;
    }
    else if (cond >= AP_CONDITION_WEAK) {
        return HTTP_PRECONDITION_FAILED;
    }

    /* If an If-None-Match request-header field was given
     * AND the field value is "*" (meaning match anything)
     *     OR our ETag matches any of the entity tags in that field, fail.
     *
     * If the request method was GET or HEAD, failure means the server
     *    SHOULD respond with a 304 (Not Modified) response.
     * For all other request methods, failure means the server MUST
     *    respond with a status of 412 (Precondition Failed).
     *
     * GET or HEAD allow weak etag comparison, all other methods require
     * strong comparison.  We can only use weak if it's not a range request.
     */
    cond = ap_condition_if_none_match(r, r->headers_out);
    if (AP_CONDITION_NOMATCH == cond) {
        not_modified = 0;
    }
    else if (cond >= AP_CONDITION_WEAK) {
        if (r->method_number == M_GET) {
            if (not_modified) {
                not_modified = 1;
            }
        }
        else {
            return HTTP_PRECONDITION_FAILED;
        }
    }

    /* If a valid If-Modified-Since request-header field was given
     * AND it is a GET or HEAD request
     * AND the requested resource has not been modified since the time
     * specified in this field, then the server MUST
     *    respond with a status of 304 (Not Modified).
     * A date later than the server's current request time is invalid.
     */
    cond = ap_condition_if_modified_since(r, r->headers_out);
    if (AP_CONDITION_NOMATCH == cond) {
        not_modified = 0;
    }
    else if (cond >= AP_CONDITION_WEAK) {
        if (r->method_number == M_GET) {
            if (not_modified) {
                not_modified = 1;
            }
        }
    }

    /* If an If-Range and an Range header is present, we must return
     * 200 OK. The byterange filter will convert it to a range response.
     */
    cond = ap_condition_if_range(r, r->headers_out);
    if (cond > AP_CONDITION_NONE) {
        return OK;
    }

    if (not_modified == 1) {
        return HTTP_NOT_MODIFIED;
    }

    return OK;
}

/**
 * Singleton registry of additional methods. This maps new method names
 * such as "MYGET" to methnums, which are int offsets into bitmasks.
 *
 * This follows the same technique as standard M_GET, M_POST, etc. These
 * are dynamically assigned when modules are loaded and <Limit GET MYGET>
 * directives are processed.
 */
static apr_hash_t *methods_registry = NULL;
static int cur_method_number = METHOD_NUMBER_FIRST;

/* internal function to register one method/number pair */
static void register_one_method(apr_pool_t *p, const char *methname,
                                int methnum)
{
    int *pnum = apr_palloc(p, sizeof(*pnum));

    *pnum = methnum;
    apr_hash_set(methods_registry, methname, APR_HASH_KEY_STRING, pnum);
}

/* This internal function is used to clear the method registry
 * and reset the cur_method_number counter.
 */
static apr_status_t ap_method_registry_destroy(void *notused)
{
    methods_registry = NULL;
    cur_method_number = METHOD_NUMBER_FIRST;
    return APR_SUCCESS;
}

AP_DECLARE(void) ap_method_registry_init(apr_pool_t *p)
{
    methods_registry = apr_hash_make(p);
    apr_pool_cleanup_register(p, NULL,
                              ap_method_registry_destroy,
                              apr_pool_cleanup_null);

    /* put all the standard methods into the registry hash to ease the
     * mapping operations between name and number
     * HEAD is a special-instance of the GET method and shares the same ID
     */
    register_one_method(p, "GET", M_GET);
    register_one_method(p, "HEAD", M_GET);
    register_one_method(p, "PUT", M_PUT);
    register_one_method(p, "POST", M_POST);
    register_one_method(p, "DELETE", M_DELETE);
    register_one_method(p, "CONNECT", M_CONNECT);
    register_one_method(p, "OPTIONS", M_OPTIONS);
    register_one_method(p, "TRACE", M_TRACE);
    register_one_method(p, "PATCH", M_PATCH);
    register_one_method(p, "PROPFIND", M_PROPFIND);
    register_one_method(p, "PROPPATCH", M_PROPPATCH);
    register_one_method(p, "MKCOL", M_MKCOL);
    register_one_method(p, "COPY", M_COPY);
    register_one_method(p, "MOVE", M_MOVE);
    register_one_method(p, "LOCK", M_LOCK);
    register_one_method(p, "UNLOCK", M_UNLOCK);
    register_one_method(p, "VERSION-CONTROL", M_VERSION_CONTROL);
    register_one_method(p, "CHECKOUT", M_CHECKOUT);
    register_one_method(p, "UNCHECKOUT", M_UNCHECKOUT);
    register_one_method(p, "CHECKIN", M_CHECKIN);
    register_one_method(p, "UPDATE", M_UPDATE);
    register_one_method(p, "LABEL", M_LABEL);
    register_one_method(p, "REPORT", M_REPORT);
    register_one_method(p, "MKWORKSPACE", M_MKWORKSPACE);
    register_one_method(p, "MKACTIVITY", M_MKACTIVITY);
    register_one_method(p, "BASELINE-CONTROL", M_BASELINE_CONTROL);
    register_one_method(p, "MERGE", M_MERGE);
}

AP_DECLARE(int) ap_method_register(apr_pool_t *p, const char *methname)
{
    int *methnum;

    if (methods_registry == NULL) {
        ap_method_registry_init(p);
    }

    if (methname == NULL) {
        return M_INVALID;
    }

    /* Check if the method was previously registered.  If it was
     * return the associated method number.
     */
    methnum = (int *)apr_hash_get(methods_registry, methname,
                                  APR_HASH_KEY_STRING);
    if (methnum != NULL)
        return *methnum;

    if (cur_method_number > METHOD_NUMBER_LAST) {
        /* The method registry  has run out of dynamically
         * assignable method numbers. Log this and return M_INVALID.
         */
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, APLOGNO(01610)
                      "Maximum new request methods %d reached while "
                      "registering method %s.",
                      METHOD_NUMBER_LAST, methname);
        return M_INVALID;
    }

    register_one_method(p, methname, cur_method_number);
    return cur_method_number++;
}

#define UNKNOWN_METHOD (-1)

static int lookup_builtin_method(const char *method, apr_size_t len)
{
    /* Note: the following code was generated by the "shilka" tool from
       the "cocom" parsing/compilation toolkit. It is an optimized lookup
       based on analysis of the input keywords. Postprocessing was done
       on the shilka output, but the basic structure and analysis is
       from there. Should new HTTP methods be added, then manual insertion
       into this code is fine, or simply re-running the shilka tool on
       the appropriate input. */

    /* Note: it is also quite reasonable to just use our method_registry,
       but I'm assuming (probably incorrectly) we want more speed here
       (based on the optimizations the previous code was doing). */

    switch (len)
    {
    case 3:
        switch (method[0])
        {
        case 'P':
            return (method[1] == 'U'
                    && method[2] == 'T'
                    ? M_PUT : UNKNOWN_METHOD);
        case 'G':
            return (method[1] == 'E'
                    && method[2] == 'T'
                    ? M_GET : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 4:
        switch (method[0])
        {
        case 'H':
            return (method[1] == 'E'
                    && method[2] == 'A'
                    && method[3] == 'D'
                    ? M_GET : UNKNOWN_METHOD);
        case 'P':
            return (method[1] == 'O'
                    && method[2] == 'S'
                    && method[3] == 'T'
                    ? M_POST : UNKNOWN_METHOD);
        case 'M':
            return (method[1] == 'O'
                    && method[2] == 'V'
                    && method[3] == 'E'
                    ? M_MOVE : UNKNOWN_METHOD);
        case 'L':
            return (method[1] == 'O'
                    && method[2] == 'C'
                    && method[3] == 'K'
                    ? M_LOCK : UNKNOWN_METHOD);
        case 'C':
            return (method[1] == 'O'
                    && method[2] == 'P'
                    && method[3] == 'Y'
                    ? M_COPY : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 5:
        switch (method[2])
        {
        case 'T':
            return (memcmp(method, "PATCH", 5) == 0
                    ? M_PATCH : UNKNOWN_METHOD);
        case 'R':
            return (memcmp(method, "MERGE", 5) == 0
                    ? M_MERGE : UNKNOWN_METHOD);
        case 'C':
            return (memcmp(method, "MKCOL", 5) == 0
                    ? M_MKCOL : UNKNOWN_METHOD);
        case 'B':
            return (memcmp(method, "LABEL", 5) == 0
                    ? M_LABEL : UNKNOWN_METHOD);
        case 'A':
            return (memcmp(method, "TRACE", 5) == 0
                    ? M_TRACE : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 6:
        switch (method[0])
        {
        case 'U':
            switch (method[5])
            {
            case 'K':
                return (memcmp(method, "UNLOCK", 6) == 0
                        ? M_UNLOCK : UNKNOWN_METHOD);
            case 'E':
                return (memcmp(method, "UPDATE", 6) == 0
                        ? M_UPDATE : UNKNOWN_METHOD);
            default:
                return UNKNOWN_METHOD;
            }
        case 'R':
            return (memcmp(method, "REPORT", 6) == 0
                    ? M_REPORT : UNKNOWN_METHOD);
        case 'D':
            return (memcmp(method, "DELETE", 6) == 0
                    ? M_DELETE : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 7:
        switch (method[1])
        {
        case 'P':
            return (memcmp(method, "OPTIONS", 7) == 0
                    ? M_OPTIONS : UNKNOWN_METHOD);
        case 'O':
            return (memcmp(method, "CONNECT", 7) == 0
                    ? M_CONNECT : UNKNOWN_METHOD);
        case 'H':
            return (memcmp(method, "CHECKIN", 7) == 0
                    ? M_CHECKIN : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 8:
        switch (method[0])
        {
        case 'P':
            return (memcmp(method, "PROPFIND", 8) == 0
                    ? M_PROPFIND : UNKNOWN_METHOD);
        case 'C':
            return (memcmp(method, "CHECKOUT", 8) == 0
                    ? M_CHECKOUT : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 9:
        return (memcmp(method, "PROPPATCH", 9) == 0
                ? M_PROPPATCH : UNKNOWN_METHOD);

    case 10:
        switch (method[0])
        {
        case 'U':
            return (memcmp(method, "UNCHECKOUT", 10) == 0
                    ? M_UNCHECKOUT : UNKNOWN_METHOD);
        case 'M':
            return (memcmp(method, "MKACTIVITY", 10) == 0
                    ? M_MKACTIVITY : UNKNOWN_METHOD);
        default:
            return UNKNOWN_METHOD;
        }

    case 11:
        return (memcmp(method, "MKWORKSPACE", 11) == 0
                ? M_MKWORKSPACE : UNKNOWN_METHOD);

    case 15:
        return (memcmp(method, "VERSION-CONTROL", 15) == 0
                ? M_VERSION_CONTROL : UNKNOWN_METHOD);

    case 16:
        return (memcmp(method, "BASELINE-CONTROL", 16) == 0
                ? M_BASELINE_CONTROL : UNKNOWN_METHOD);

    default:
        return UNKNOWN_METHOD;
    }

    /* NOTREACHED */
}

/* Get the method number associated with the given string, assumed to
 * contain an HTTP method.  Returns M_INVALID if not recognized.
 *
 * This is the first step toward placing method names in a configurable
 * list.  Hopefully it (and other routines) can eventually be moved to
 * something like a mod_http_methods.c, complete with config stuff.
 */
AP_DECLARE(int) ap_method_number_of(const char *method)
{
    int len = strlen(method);
    int which = lookup_builtin_method(method, len);

    if (which != UNKNOWN_METHOD)
        return which;

    /* check if the method has been dynamically registered */
    if (methods_registry != NULL) {
        int *methnum = apr_hash_get(methods_registry, method, len);

        if (methnum != NULL) {
            return *methnum;
        }
    }

    return M_INVALID;
}

/*
 * Turn a known method number into a name.
 */
AP_DECLARE(const char *) ap_method_name_of(apr_pool_t *p, int methnum)
{
    apr_hash_index_t *hi = apr_hash_first(p, methods_registry);

    /* scan through the hash table, looking for a value that matches
       the provided method number. */
    for (; hi; hi = apr_hash_next(hi)) {
        const void *key;
        void *val;

        apr_hash_this(hi, &key, NULL, &val);
        if (*(int *)val == methnum)
            return key;
    }

    /* it wasn't found in the hash */
    return NULL;
}

/* The index is found by its offset from the x00 code of each level.
 * Although this is fast, it will need to be replaced if some nutcase
 * decides to define a high-numbered code before the lower numbers.
 * If that sad event occurs, replace the code below with a linear search
 * from status_lines[shortcut[i]] to status_lines[shortcut[i+1]-1];
 * or use NULL to fill the gaps.
 */
static int index_of_response(int status)
{
    static int shortcut[6] = {0, LEVEL_200, LEVEL_300, LEVEL_400, LEVEL_500,
                                 RESPONSE_CODES};
    int i, pos;

    if (status < 100) {     /* Below 100 is illegal for HTTP status */
        return -1;
    }
    if (status > 999) {     /* Above 999 is also illegal for HTTP status */
        return -1;
    }

    for (i = 0; i < 5; i++) {
        status -= 100;
        if (status < 100) {
            pos = (status + shortcut[i]);
            if (pos < shortcut[i + 1] && status_lines[pos] != NULL) {
                return pos;
            }
            else {
                break;
            }
        }
    }
    return -2;              /* Status unknown (falls in gap) or above 600 */
}

AP_DECLARE(int) ap_index_of_response(int status)
{
    int index = index_of_response(status);
    return (index < 0) ? LEVEL_500 : index;
}

AP_DECLARE(const char *) ap_get_status_line_ex(apr_pool_t *p, int status)
{
    int index = index_of_response(status);
    if (index >= 0) {
        return status_lines[index];
    }
    else if (index == -2) {
        return apr_psprintf(p, "%i Status %i", status, status);
    }
    return status_lines[LEVEL_500];
}

AP_DECLARE(const char *) ap_get_status_line(int status)
{
    return status_lines[ap_index_of_response(status)];
}

/* Build the Allow field-value from the request handler method mask.
 */
static char *make_allow(request_rec *r)
{
    apr_int64_t mask;
    apr_array_header_t *allow = apr_array_make(r->pool, 10, sizeof(char *));
    apr_hash_index_t *hi = apr_hash_first(r->pool, methods_registry);
    /* For TRACE below */
    core_server_config *conf =
        ap_get_core_module_config(r->server->module_config);

    mask = r->allowed_methods->method_mask;

    for (; hi; hi = apr_hash_next(hi)) {
        const void *key;
        void *val;

        apr_hash_this(hi, &key, NULL, &val);
        if ((mask & (AP_METHOD_BIT << *(int *)val)) != 0) {
            APR_ARRAY_PUSH(allow, const char *) = key;
        }
    }

    /* TRACE is tested on a per-server basis */
    if (conf->trace_enable != AP_TRACE_DISABLE)
        *(const char **)apr_array_push(allow) = "TRACE";

    /* ### this is rather annoying. we should enforce registration of
       ### these methods */
    if ((mask & (AP_METHOD_BIT << M_INVALID))
        && (r->allowed_methods->method_list != NULL)
        && (r->allowed_methods->method_list->nelts != 0)) {
        apr_array_cat(allow, r->allowed_methods->method_list);
    }

    return apr_array_pstrcat(r->pool, allow, ',');
}

AP_DECLARE(int) ap_send_http_options(request_rec *r)
{
    if (r->assbackwards) {
        return DECLINED;
    }

    apr_table_setn(r->headers_out, "Allow", make_allow(r));

    /* the request finalization will send an EOS, which will flush all
     * the headers out (including the Allow header)
     */

    return OK;
}

AP_DECLARE(void) ap_set_content_type(request_rec *r, const char *ct)
{
    if (!ct) {
        r->content_type = NULL;
    }
    else if (!r->content_type || strcmp(r->content_type, ct)) {
        r->content_type = ct;
    }
}

AP_DECLARE(void) ap_set_accept_ranges(request_rec *r)
{
    core_dir_config *d = ap_get_core_module_config(r->per_dir_config);
    apr_table_setn(r->headers_out, "Accept-Ranges",
                  (d->max_ranges == AP_MAXRANGES_NORANGES) ? "none"
                                                           : "bytes");
}
static const char *add_optional_notes(request_rec *r,
                                      const char *prefix,
                                      const char *key,
                                      const char *suffix)
{
    const char *notes, *result;

    if ((notes = apr_table_get(r->notes, key)) == NULL) {
        result = apr_pstrcat(r->pool, prefix, suffix, NULL);
    }
    else {
        result = apr_pstrcat(r->pool, prefix, notes, suffix, NULL);
    }

    return result;
}

/* construct and return the default error message for a given
 * HTTP defined error code
 */
static const char *get_canned_error_string(int status,
                                           request_rec *r,
                                           const char *location)
{
    apr_pool_t *p = r->pool;
    const char *error_notes, *h1, *s1;

    switch (status) {
    case HTTP_MOVED_PERMANENTLY:
    case HTTP_MOVED_TEMPORARILY:
    case HTTP_TEMPORARY_REDIRECT:
    case HTTP_PERMANENT_REDIRECT:
        return(apr_pstrcat(p,
                           "<p>The document has moved <a href=\"",
                           ap_escape_html(r->pool, location),
                           "\">here</a>.</p>\n",
                           NULL));
    case HTTP_SEE_OTHER:
        return(apr_pstrcat(p,
                           "<p>The answer to your request is located "
                           "<a href=\"",
                           ap_escape_html(r->pool, location),
                           "\">here</a>.</p>\n",
                           NULL));
    case HTTP_USE_PROXY:
        return("<p>This resource is only accessible "
               "through the proxy\n"
               "<br />\nYou will need to configure "
               "your client to use that proxy.</p>\n");
    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
    case HTTP_UNAUTHORIZED:
        return("<p>This server could not verify that you\n"
               "are authorized to access the document\n"
               "requested.  Either you supplied the wrong\n"
               "credentials (e.g., bad password), or your\n"
               "browser doesn't understand how to supply\n"
               "the credentials required.</p>\n");
    case HTTP_BAD_REQUEST:
        return(add_optional_notes(r,
                                  "<p>Your browser sent a request that "
                                  "this server could not understand.<br />\n",
                                  "error-notes",
                                  "</p>\n"));
    case HTTP_FORBIDDEN:
        return(add_optional_notes(r, "<p>You don't have permission to access this resource.", "error-notes", "</p>\n"));
    case HTTP_NOT_FOUND:
        return("<p>The requested URL was not found on this server.</p>\n");
    case HTTP_METHOD_NOT_ALLOWED:
        return(apr_pstrcat(p,
                           "<p>The requested method ",
                           ap_escape_html(r->pool, r->method),
                           " is not allowed for this URL.</p>\n",
                           NULL));
    case HTTP_NOT_ACCEPTABLE:
        return(add_optional_notes(r, 
            "<p>An appropriate representation of the requested resource "
            "could not be found on this server.</p>\n",
            "variant-list", ""));
    case HTTP_MULTIPLE_CHOICES:
        return(add_optional_notes(r, "", "variant-list", ""));
    case HTTP_LENGTH_REQUIRED:
        s1 = apr_pstrcat(p,
                         "<p>A request of the requested method ",
                         ap_escape_html(r->pool, r->method),
                         " requires a valid Content-length.<br />\n",
                         NULL);
        return(add_optional_notes(r, s1, "error-notes", "</p>\n"));
    case HTTP_PRECONDITION_FAILED:
        return("<p>The precondition on the request "
               "for this URL evaluated to false.</p>\n");
    case HTTP_NOT_IMPLEMENTED:
        s1 = apr_pstrcat(p,
                         "<p>",
                         ap_escape_html(r->pool, r->method),
                         " not supported for current URL.<br />\n",
                         NULL);
        return(add_optional_notes(r, s1, "error-notes", "</p>\n"));
    case HTTP_BAD_GATEWAY:
        s1 = "<p>The proxy server received an invalid" CRLF
            "response from an upstream server.<br />" CRLF;
        return(add_optional_notes(r, s1, "error-notes", "</p>\n"));
    case HTTP_VARIANT_ALSO_VARIES:
        return("<p>A variant for the requested "
               "resource\n<pre>\n"
               "\n</pre>\nis itself a negotiable resource. "
               "This indicates a configuration error.</p>\n");
    case HTTP_REQUEST_TIME_OUT:
        return("<p>Server timeout waiting for the HTTP request from the client.</p>\n");
    case HTTP_GONE:
        return("<p>The requested resource is no longer available on this server"
               " and there is no forwarding address.\n"
               "Please remove all references to this resource.</p>\n");
    case HTTP_REQUEST_ENTITY_TOO_LARGE:
        return(apr_pstrcat(p,
                           "The requested resource does not allow request data with ",
                           ap_escape_html(r->pool, r->method),
                           " requests, or the amount of data provided in\n"
                           "the request exceeds the capacity limit.\n",
                           NULL));
    case HTTP_REQUEST_URI_TOO_LARGE:
        s1 = "<p>The requested URL's length exceeds the capacity\n"
             "limit for this server.<br />\n";
        return(add_optional_notes(r, s1, "error-notes", "</p>\n"));
    case HTTP_UNSUPPORTED_MEDIA_TYPE:
        return("<p>The supplied request data is not in a format\n"
               "acceptable for processing by this resource.</p>\n");
    case HTTP_RANGE_NOT_SATISFIABLE:
        return("<p>None of the range-specifier values in the Range\n"
               "request-header field overlap the current extent\n"
               "of the selected resource.</p>\n");
    case HTTP_EXPECTATION_FAILED:
        s1 = apr_table_get(r->headers_in, "Expect");
        if (s1)
            s1 = apr_pstrcat(p,
                     "<p>The expectation given in the Expect request-header\n"
                     "field could not be met by this server.\n"
                     "The client sent<pre>\n    Expect: ",
                     ap_escape_html(r->pool, s1), "\n</pre>\n",
                     NULL);
        else
            s1 = "<p>No expectation was seen, the Expect request-header \n"
                 "field was not presented by the client.\n";
        return add_optional_notes(r, s1, "error-notes", "</p>"
                   "<p>Only the 100-continue expectation is supported.</p>\n");
    case HTTP_UNPROCESSABLE_ENTITY:
        return("<p>The server understands the media type of the\n"
               "request entity, but was unable to process the\n"
               "contained instructions.</p>\n");
    case HTTP_LOCKED:
        return("<p>The requested resource is currently locked.\n"
               "The lock must be released or proper identification\n"
               "given before the method can be applied.</p>\n");
    case HTTP_FAILED_DEPENDENCY:
        return("<p>The method could not be performed on the resource\n"
               "because the requested action depended on another\n"
               "action and that other action failed.</p>\n");
    case HTTP_UPGRADE_REQUIRED:
        return("<p>The requested resource can only be retrieved\n"
               "using SSL.  The server is willing to upgrade the current\n"
               "connection to SSL, but your client doesn't support it.\n"
               "Either upgrade your client, or try requesting the page\n"
               "using https://\n");
    case HTTP_PRECONDITION_REQUIRED:
        return("<p>The request is required to be conditional.</p>\n");
    case HTTP_TOO_MANY_REQUESTS:
        return("<p>The user has sent too many requests\n"
               "in a given amount of time.</p>\n");
    case HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE:
        return("<p>The server refused this request because\n"
               "the request header fields are too large.</p>\n");
    case HTTP_INSUFFICIENT_STORAGE:
        return("<p>The method could not be performed on the resource\n"
               "because the server is unable to store the\n"
               "representation needed to successfully complete the\n"
               "request.  There is insufficient free space left in\n"
               "your storage allocation.</p>\n");
    case HTTP_SERVICE_UNAVAILABLE:
        return("<p>The server is temporarily unable to service your\n"
               "request due to maintenance downtime or capacity\n"
               "problems. Please try again later.</p>\n");
    case HTTP_GATEWAY_TIME_OUT:
        return("<p>The gateway did not receive a timely response\n"
               "from the upstream server or application.</p>\n");
    case HTTP_LOOP_DETECTED:
        return("<p>The server terminated an operation because\n"
               "it encountered an infinite loop.</p>\n");
    case HTTP_NOT_EXTENDED:
        return("<p>A mandatory extension policy in the request is not\n"
               "accepted by the server for this resource.</p>\n");
    case HTTP_NETWORK_AUTHENTICATION_REQUIRED:
        return("<p>The client needs to authenticate to gain\n"
               "network access.</p>\n");
    case HTTP_MISDIRECTED_REQUEST:
        return("<p>The client needs a new connection for this\n"
               "request as the requested host name does not match\n"
               "the Server Name Indication (SNI) in use for this\n"
               "connection.</p>\n");
    case HTTP_UNAVAILABLE_FOR_LEGAL_REASONS:
        return(add_optional_notes(r, 
               "<p>Access to this URL has been denied for legal reasons.<br />\n",
               "error-notes", "</p>\n"));
    default:                    /* HTTP_INTERNAL_SERVER_ERROR */
        /*
         * This comparison to expose error-notes could be modified to
         * use a configuration directive and export based on that
         * directive.  For now "*" is used to designate an error-notes
         * that is totally safe for any user to see (ie lacks paths,
         * database passwords, etc.)
         */
        if (((error_notes = apr_table_get(r->notes,
                                          "error-notes")) != NULL)
            && (h1 = apr_table_get(r->notes, "verbose-error-to")) != NULL
            && (strcmp(h1, "*") == 0)) {
            return(apr_pstrcat(p, error_notes, "<p />\n", NULL));
        }
        else {
            return(apr_pstrcat(p,
                               "<p>The server encountered an internal "
                               "error or\n"
                               "misconfiguration and was unable to complete\n"
                               "your request.</p>\n"
                               "<p>Please contact the server "
                               "administrator at \n ",
                               ap_escape_html(r->pool,
                                              r->server->server_admin),
                               " to inform them of the time this "
                               "error occurred,\n"
                               " and the actions you performed just before "
                               "this error.</p>\n"
                               "<p>More information about this error "
                               "may be available\n"
                               "in the server error log.</p>\n",
                               NULL));
        }
        /*
         * It would be nice to give the user the information they need to
         * fix the problem directly since many users don't have access to
         * the error_log (think University sites) even though they can easily
         * get this error by misconfiguring an htaccess file.  However, the
         * e error notes tend to include the real file pathname in this case,
         * which some people consider to be a breach of privacy.  Until we
         * can figure out a way to remove the pathname, leave this commented.
         *
         * if ((error_notes = apr_table_get(r->notes,
         *                                  "error-notes")) != NULL) {
         *     return(apr_pstrcat(p, error_notes, "<p />\n", NULL);
         * }
         * else {
         *     return "";
         * }
         */
    }
}

/* We should have named this send_canned_response, since it is used for any
 * response that can be generated by the server from the request record.
 * This includes all 204 (no content), 3xx (redirect), 4xx (client error),
 * and 5xx (server error) messages that have not been redirected to another
 * handler via the ErrorDocument feature.
 */
AP_DECLARE(void) ap_send_error_response(request_rec *r, int recursive_error)
{
    int status = r->status;
    int idx = ap_index_of_response(status);
    char *custom_response;
    const char *location = apr_table_get(r->headers_out, "Location");

    /* At this point, we are starting the response over, so we have to reset
     * this value.
     */
    r->eos_sent = 0;

    /* and we need to get rid of any RESOURCE filters that might be lurking
     * around, thinking they are in the middle of the original request
     */

    r->output_filters = r->proto_output_filters;

    ap_run_insert_error_filter(r);

    /* We need to special-case the handling of 204 and 304 responses,
     * since they have specific HTTP requirements and do not include a
     * message body.  Note that being assbackwards here is not an option.
     */
    if (AP_STATUS_IS_HEADER_ONLY(status)) {
        ap_finalize_request_protocol(r);
        return;
    }

    /*
     * It's possible that the Location field might be in r->err_headers_out
     * instead of r->headers_out; use the latter if possible, else the
     * former.
     */
    if (location == NULL) {
        location = apr_table_get(r->err_headers_out, "Location");
    }

    if (!r->assbackwards) {
        apr_table_t *tmp = r->headers_out;

        /* For all HTTP/1.x responses for which we generate the message,
         * we need to avoid inheriting the "normal status" header fields
         * that may have been set by the request handler before the
         * error or redirect, except for Location on external redirects.
         */
        r->headers_out = r->err_headers_out;
        r->err_headers_out = tmp;
        apr_table_clear(r->err_headers_out);

        if (ap_is_HTTP_REDIRECT(status) || (status == HTTP_CREATED)) {
            if ((location != NULL) && *location) {
                apr_table_setn(r->headers_out, "Location", location);
            }
            else {
                location = "";   /* avoids coredump when printing, below */
            }
        }

        r->content_languages = NULL;
        r->content_encoding = NULL;
        r->clength = 0;

        if (apr_table_get(r->subprocess_env,
                          "suppress-error-charset") != NULL) {
            core_request_config *request_conf =
                        ap_get_core_module_config(r->request_config);
            request_conf->suppress_charset = 1; /* avoid adding default
                                                 * charset later
                                                 */
            ap_set_content_type(r, "text/html");
        }
        else {
            ap_set_content_type(r, "text/html; charset=iso-8859-1");
        }

        if ((status == HTTP_METHOD_NOT_ALLOWED)
            || (status == HTTP_NOT_IMPLEMENTED)) {
            apr_table_setn(r->headers_out, "Allow", make_allow(r));
        }

        if (r->header_only) {
            ap_finalize_request_protocol(r);
            return;
        }
    }

    if ((custom_response = ap_response_code_string(r, idx))) {
        /*
         * We have a custom response output. This should only be
         * a text-string to write back. But if the ErrorDocument
         * was a local redirect and the requested resource failed
         * for any reason, the custom_response will still hold the
         * redirect URL. We don't really want to output this URL
         * as a text message, so first check the custom response
         * string to ensure that it is a text-string (using the
         * same test used in ap_die(), i.e. does it start with a ").
         *
         * If it's not a text string, we've got a recursive error or
         * an external redirect.  If it's a recursive error, ap_die passes
         * us the second error code so we can write both, and has already
         * backed up to the original error.  If it's an external redirect,
         * it hasn't happened yet; we may never know if it fails.
         */
        if (custom_response[0] == '\"') {
            ap_rputs(custom_response + 1, r);
            ap_finalize_request_protocol(r);
            return;
        }
    }
    {
        const char *title = status_lines[idx];
        const char *h1;

        /* Accept a status_line set by a module, but only if it begins
         * with the correct 3 digit status code
         */
        if (r->status_line) {
            char *end;
            int len = strlen(r->status_line);
            if (len >= 3
                && apr_strtoi64(r->status_line, &end, 10) == r->status
                && (end - 3) == r->status_line
                && (len < 4 || apr_isspace(r->status_line[3]))
                && (len < 5 || apr_isalnum(r->status_line[4]))) {
                /* Since we passed the above check, we know that length three
                 * is equivalent to only a 3 digit numeric http status.
                 * RFC2616 mandates a trailing space, let's add it.
                 * If we have an empty reason phrase, we also add "Unknown Reason".
                 */
                if (len == 3) {
                    r->status_line = apr_pstrcat(r->pool, r->status_line, " Unknown Reason", NULL);
                } else if (len == 4) {
                    r->status_line = apr_pstrcat(r->pool, r->status_line, "Unknown Reason", NULL);
                }
                title = r->status_line;
            }
        }

        /* folks decided they didn't want the error code in the H1 text */
        h1 = &title[4];

        /* can't count on a charset filter being in place here,
         * so do ebcdic->ascii translation explicitly (if needed)
         */

        ap_rvputs_proto_in_ascii(r,
                  DOCTYPE_HTML_2_0
                  "<html><head>\n<title>", title,
                  "</title>\n</head><body>\n<h1>", h1, "</h1>\n",
                  NULL);

        ap_rvputs_proto_in_ascii(r,
                                 get_canned_error_string(status, r, location),
                                 NULL);

        if (recursive_error) {
            ap_rvputs_proto_in_ascii(r, "<p>Additionally, a ",
                      status_lines[ap_index_of_response(recursive_error)],
                      "\nerror was encountered while trying to use an "
                      "ErrorDocument to handle the request.</p>\n", NULL);
        }
        ap_rvputs_proto_in_ascii(r, ap_psignature("<hr>\n", r), NULL);
        ap_rvputs_proto_in_ascii(r, "</body></html>\n", NULL);
    }
    ap_finalize_request_protocol(r);
}

/*
 * Create a new method list with the specified number of preallocated
 * extension slots.
 */
AP_DECLARE(ap_method_list_t *) ap_make_method_list(apr_pool_t *p, int nelts)
{
    ap_method_list_t *ml;

    ml = (ap_method_list_t *) apr_palloc(p, sizeof(ap_method_list_t));
    ml->method_mask = 0;
    ml->method_list = apr_array_make(p, nelts, sizeof(char *));
    return ml;
}

/*
 * Make a copy of a method list (primarily for subrequests that may
 * subsequently change it; don't want them changing the parent's, too!).
 */
AP_DECLARE(void) ap_copy_method_list(ap_method_list_t *dest,
                                     ap_method_list_t *src)
{
    int i;
    char **imethods;
    char **omethods;

    dest->method_mask = src->method_mask;
    imethods = (char **) src->method_list->elts;
    for (i = 0; i < src->method_list->nelts; ++i) {
        omethods = (char **) apr_array_push(dest->method_list);
        *omethods = apr_pstrdup(dest->method_list->pool, imethods[i]);
    }
}

/*
 * Return true if the specified HTTP method is in the provided
 * method list.
 */
AP_DECLARE(int) ap_method_in_list(ap_method_list_t *l, const char *method)
{
    int methnum;

    /*
     * If it's one of our known methods, use the shortcut and check the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    if (methnum != M_INVALID) {
        return !!(l->method_mask & (AP_METHOD_BIT << methnum));
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if ((l->method_list == NULL) || (l->method_list->nelts == 0)) {
        return 0;
    }

    return ap_array_str_contains(l->method_list, method);
}

/*
 * Add the specified method to a method list (if it isn't already there).
 */
AP_DECLARE(void) ap_method_list_add(ap_method_list_t *l, const char *method)
{
    int methnum;
    const char **xmethod;

    /*
     * If it's one of our known methods, use the shortcut and use the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    if (methnum != M_INVALID) {
        l->method_mask |= (AP_METHOD_BIT << methnum);
        return;
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if (ap_array_str_contains(l->method_list, method)) {
        return;
    }

    xmethod = (const char **) apr_array_push(l->method_list);
    *xmethod = method;
}

/*
 * Remove the specified method from a method list.
 */
AP_DECLARE(void) ap_method_list_remove(ap_method_list_t *l,
                                       const char *method)
{
    int methnum;
    char **methods;

    /*
     * If it's a known methods, either builtin or registered
     * by a module, use the bitmask.
     */
    methnum = ap_method_number_of(method);
    if (methnum != M_INVALID) {
        l->method_mask &= ~(AP_METHOD_BIT << methnum);
        return;
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if (l->method_list->nelts != 0) {
        int i, j, k;
        methods = (char **)l->method_list->elts;
        for (i = 0; i < l->method_list->nelts; ) {
            if (strcmp(method, methods[i]) == 0) {
                for (j = i, k = i + 1; k < l->method_list->nelts; ++j, ++k) {
                    methods[j] = methods[k];
                }
                --l->method_list->nelts;
            }
            else {
                ++i;
            }
        }
    }
}

/*
 * Reset a method list to be completely empty.
 */
AP_DECLARE(void) ap_clear_method_list(ap_method_list_t *l)
{
    l->method_mask = 0;
    l->method_list->nelts = 0;
}

