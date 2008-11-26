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
#include "ap_mpm.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* New Apache routine to map status codes into array indicies
 *  e.g.  100 -> 0,  101 -> 1,  200 -> 2 ...
 * The number of status lines must equal the value of RESPONSE_CODES (httpd.h)
 * and must be listed in order.
 */

#ifdef UTS21
/* The second const triggers an assembler bug on UTS 2.1.
 * Another workaround is to move some code out of this file into another,
 *   but this is easier.  Dave Dykstra, 3/31/99
 */
static const char * status_lines[RESPONSE_CODES] =
#else
static const char * const status_lines[RESPONSE_CODES] =
#endif
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
#define LEVEL_300 11
    "300 Multiple Choices",
    "301 Moved Permanently",
    "302 Found",
    "303 See Other",
    "304 Not Modified",
    "305 Use Proxy",
    "306 unused",
    "307 Temporary Redirect",
#define LEVEL_400 19
    "400 Bad Request",
    "401 Authorization Required",
    "402 Payment Required",
    "403 Forbidden",
    "404 Not Found",
    "405 Method Not Allowed",
    "406 Not Acceptable",
    "407 Proxy Authentication Required",
    "408 Request Time-out",
    "409 Conflict",
    "410 Gone",
    "411 Length Required",
    "412 Precondition Failed",
    "413 Request Entity Too Large",
    "414 Request-URI Too Large",
    "415 Unsupported Media Type",
    "416 Requested Range Not Satisfiable",
    "417 Expectation Failed",
    "418 unused",
    "419 unused",
    "420 unused",
    "421 unused",
    "422 Unprocessable Entity",
    "423 Locked",
    "424 Failed Dependency",
    /* This is a hack, but it is required for ap_index_of_response
     * to work with 426.
     */
    "425 No code",
    "426 Upgrade Required",
#define LEVEL_500 46
    "500 Internal Server Error",
    "501 Method Not Implemented",
    "502 Bad Gateway",
    "503 Service Temporarily Unavailable",
    "504 Gateway Time-out",
    "505 HTTP Version Not Supported",
    "506 Variant Also Negotiates",
    "507 Insufficient Storage",
    "508 unused",
    "509 unused",
    "510 Not Extended"
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
        && ((r->status == HTTP_NOT_MODIFIED)
            || (r->status == HTTP_NO_CONTENT)
            || r->header_only
            || apr_table_get(r->headers_out, "Content-Length")
            || ap_find_last_token(r->pool,
                                  apr_table_get(r->headers_out,
                                                "Transfer-Encoding"),
                                  "chunked")
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
        && !ap_graceful_stop_signalled()) {

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

AP_DECLARE(int) ap_meets_conditions(request_rec *r)
{
    const char *etag;
    const char *if_match, *if_modified_since, *if_unmodified, *if_nonematch;
    apr_time_t tmp_time;
    apr_int64_t mtime;
    int not_modified = 0;

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

    etag = apr_table_get(r->headers_out, "ETag");

    /* All of our comparisons must be in seconds, because that's the
     * highest time resolution the HTTP specification allows.
     */
    /* XXX: we should define a "time unset" constant */
    tmp_time = ((r->mtime != 0) ? r->mtime : apr_time_now());
    mtime =  apr_time_sec(tmp_time);

    /* If an If-Match request-header field was given
     * AND the field value is not "*" (meaning match anything)
     * AND if our strong ETag does not match any entity tag in that field,
     *     respond with a status of 412 (Precondition Failed).
     */
    if ((if_match = apr_table_get(r->headers_in, "If-Match")) != NULL) {
        if (if_match[0] != '*'
            && (etag == NULL || etag[0] == 'W'
                || !ap_find_list_item(r->pool, if_match, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    else {
        /* Else if a valid If-Unmodified-Since request-header field was given
         * AND the requested resource has been modified since the time
         * specified in this field, then the server MUST
         *     respond with a status of 412 (Precondition Failed).
         */
        if_unmodified = apr_table_get(r->headers_in, "If-Unmodified-Since");
        if (if_unmodified != NULL) {
            apr_time_t ius = apr_date_parse_http(if_unmodified);

            if ((ius != APR_DATE_BAD) && (mtime > apr_time_sec(ius))) {
                return HTTP_PRECONDITION_FAILED;
            }
        }
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
    if_nonematch = apr_table_get(r->headers_in, "If-None-Match");
    if (if_nonematch != NULL) {
        if (r->method_number == M_GET) {
            if (if_nonematch[0] == '*') {
                not_modified = 1;
            }
            else if (etag != NULL) {
                if (apr_table_get(r->headers_in, "Range")) {
                    not_modified = etag[0] != 'W'
                                   && ap_find_list_item(r->pool,
                                                        if_nonematch, etag);
                }
                else {
                    not_modified = ap_find_list_item(r->pool,
                                                     if_nonematch, etag);
                }
            }
        }
        else if (if_nonematch[0] == '*'
                 || (etag != NULL
                     && ap_find_list_item(r->pool, if_nonematch, etag))) {
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
    if (r->method_number == M_GET
        && (not_modified || !if_nonematch)
        && (if_modified_since =
              apr_table_get(r->headers_in,
                            "If-Modified-Since")) != NULL) {
        apr_time_t ims_time;
        apr_int64_t ims, reqtime;

        ims_time = apr_date_parse_http(if_modified_since);
        ims = apr_time_sec(ims_time);
        reqtime = apr_time_sec(r->request_time);

        not_modified = ims >= mtime && ims <= reqtime;
    }

    if (not_modified) {
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
       mapping operations between name and number */
    register_one_method(p, "GET", M_GET);
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
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p,
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
 */
AP_DECLARE(int) ap_index_of_response(int status)
{
    static int shortcut[6] = {0, LEVEL_200, LEVEL_300, LEVEL_400,
    LEVEL_500, RESPONSE_CODES};
    int i, pos;

    if (status < 100) {               /* Below 100 is illegal for HTTP status */
        return LEVEL_500;
    }

    for (i = 0; i < 5; i++) {
        status -= 100;
        if (status < 100) {
            pos = (status + shortcut[i]);
            if (pos < shortcut[i + 1]) {
                return pos;
            }
            else {
                return LEVEL_500;            /* status unknown (falls in gap) */
            }
        }
    }
    return LEVEL_500;                         /* 600 or above is also illegal */
}

AP_DECLARE(const char *) ap_get_status_line(int status)
{
    return status_lines[ap_index_of_response(status)];
}

/* Build the Allow field-value from the request handler method mask.
 * Note that we always allow TRACE, since it is handled below.
 */
static char *make_allow(request_rec *r)
{
    char *list;
    apr_int64_t mask;
    apr_array_header_t *allow = apr_array_make(r->pool, 10, sizeof(char *));
    apr_hash_index_t *hi = apr_hash_first(r->pool, methods_registry);
    /* For TRACE below */
    core_server_config *conf =
        ap_get_module_config(r->server->module_config, &core_module);

    mask = r->allowed_methods->method_mask;

    for (; hi; hi = apr_hash_next(hi)) {
        const void *key;
        void *val;

        apr_hash_this(hi, &key, NULL, &val);
        if ((mask & (AP_METHOD_BIT << *(int *)val)) != 0) {
            *(const char **)apr_array_push(allow) = key;

            /* the M_GET method actually refers to two methods */
            if (*(int *)val == M_GET)
                *(const char **)apr_array_push(allow) = "HEAD";
        }
    }

    /* TRACE is tested on a per-server basis */
    if (conf->trace_enable != AP_TRACE_DISABLE)
        *(const char **)apr_array_push(allow) = "TRACE";

    list = apr_array_pstrcat(r->pool, allow, ',');

    /* ### this is rather annoying. we should enforce registration of
       ### these methods */
    if ((mask & (AP_METHOD_BIT << M_INVALID))
        && (r->allowed_methods->method_list != NULL)
        && (r->allowed_methods->method_list->nelts != 0)) {
        int i;
        char **xmethod = (char **) r->allowed_methods->method_list->elts;

        /*
         * Append all of the elements of r->allowed_methods->method_list
         */
        for (i = 0; i < r->allowed_methods->method_list->nelts; ++i) {
            list = apr_pstrcat(r->pool, list, ",", xmethod[i], NULL);
        }
    }

    return list;
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

        /* Insert filters requested by the AddOutputFiltersByType
         * configuration directive. Content-type filters must be
         * inserted after the content handlers have run because
         * only then, do we reliably know the content-type.
         */
        ap_add_output_filters_by_type(r);
    }
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
        return(apr_pstrcat(p,
                           "<p>This resource is only accessible "
                           "through the proxy\n",
                           ap_escape_html(r->pool, location),
                           "<br />\nYou will need to configure "
                           "your client to use that proxy.</p>\n",
                           NULL));
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
        return(apr_pstrcat(p,
                           "<p>You don't have permission to access ",
                           ap_escape_html(r->pool, r->uri),
                           "\non this server.</p>\n",
                           NULL));
    case HTTP_NOT_FOUND:
        return(apr_pstrcat(p,
                           "<p>The requested URL ",
                           ap_escape_html(r->pool, r->uri),
                           " was not found on this server.</p>\n",
                           NULL));
    case HTTP_METHOD_NOT_ALLOWED:
        return(apr_pstrcat(p,
                           "<p>The requested method ",
                           ap_escape_html(r->pool, r->method),
                           " is not allowed for the URL ",
                           ap_escape_html(r->pool, r->uri),
                           ".</p>\n",
                           NULL));
    case HTTP_NOT_ACCEPTABLE:
        s1 = apr_pstrcat(p,
                         "<p>An appropriate representation of the "
                         "requested resource ",
                         ap_escape_html(r->pool, r->uri),
                         " could not be found on this server.</p>\n",
                         NULL);
        return(add_optional_notes(r, s1, "variant-list", ""));
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
        return(apr_pstrcat(p,
                           "<p>The precondition on the request "
                           "for the URL ",
                           ap_escape_html(r->pool, r->uri),
                           " evaluated to false.</p>\n",
                           NULL));
    case HTTP_NOT_IMPLEMENTED:
        s1 = apr_pstrcat(p,
                         "<p>",
                         ap_escape_html(r->pool, r->method), " to ",
                         ap_escape_html(r->pool, r->uri),
                         " not supported.<br />\n",
                         NULL);
        return(add_optional_notes(r, s1, "error-notes", "</p>\n"));
    case HTTP_BAD_GATEWAY:
        s1 = "<p>The proxy server received an invalid" CRLF
            "response from an upstream server.<br />" CRLF;
        return(add_optional_notes(r, s1, "error-notes", "</p>\n"));
    case HTTP_VARIANT_ALSO_VARIES:
        return(apr_pstrcat(p,
                           "<p>A variant for the requested "
                           "resource\n<pre>\n",
                           ap_escape_html(r->pool, r->uri),
                           "\n</pre>\nis itself a negotiable resource. "
                           "This indicates a configuration error.</p>\n",
                           NULL));
    case HTTP_REQUEST_TIME_OUT:
        return("<p>Server timeout waiting for the HTTP request from the client.</p>\n");
    case HTTP_GONE:
        return(apr_pstrcat(p,
                           "<p>The requested resource<br />",
                           ap_escape_html(r->pool, r->uri),
                           "<br />\nis no longer available on this server "
                           "and there is no forwarding address.\n"
                           "Please remove all references to this "
                           "resource.</p>\n",
                           NULL));
    case HTTP_REQUEST_ENTITY_TOO_LARGE:
        return(apr_pstrcat(p,
                           "The requested resource<br />",
                           ap_escape_html(r->pool, r->uri), "<br />\n",
                           "does not allow request data with ",
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
        return(apr_pstrcat(p,
                           "<p>The expectation given in the Expect "
                           "request-header"
                           "\nfield could not be met by this server.</p>\n"
                           "<p>The client sent<pre>\n    Expect: ",
                           ap_escape_html(r->pool, apr_table_get(r->headers_in, "Expect")),
                           "\n</pre>\n"
                           "but we only allow the 100-continue "
                           "expectation.</p>\n",
                           NULL));
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
        return("<p>The proxy server did not receive a timely response\n"
               "from the upstream server.</p>\n");
    case HTTP_NOT_EXTENDED:
        return("<p>A mandatory extension policy in the request is not\n"
               "accepted by the server for this resource.</p>\n");
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
                               "administrator,\n ",
                               ap_escape_html(r->pool,
                                              r->server->server_admin),
                               " and inform them of the time the "
                               "error occurred,\n"
                               "and anything you might have done that "
                               "may have\n"
                               "caused the error.</p>\n"
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

    /*
     * It's possible that the Location field might be in r->err_headers_out
     * instead of r->headers_out; use the latter if possible, else the
     * former.
     */
    if (location == NULL) {
        location = apr_table_get(r->err_headers_out, "Location");
    }
    /* We need to special-case the handling of 204 and 304 responses,
     * since they have specific HTTP requirements and do not include a
     * message body.  Note that being assbackwards here is not an option.
     */
    if (status == HTTP_NOT_MODIFIED) {
        ap_finalize_request_protocol(r);
        return;
    }

    if (status == HTTP_NO_CONTENT) {
        ap_finalize_request_protocol(r);
        return;
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
                        ap_get_module_config(r->request_config, &core_module);
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
         * with the 3 digit status code
         */
        if (r->status_line != NULL
            && strlen(r->status_line) > 4       /* long enough */
            && apr_isdigit(r->status_line[0])
            && apr_isdigit(r->status_line[1])
            && apr_isdigit(r->status_line[2])
            && apr_isspace(r->status_line[3])
            && apr_isalnum(r->status_line[4])) {
            title = r->status_line;
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
    int i;
    char **methods;

    /*
     * If it's one of our known methods, use the shortcut and check the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    if (methnum != M_INVALID) {
        return !!(l->method_mask & (AP_METHOD_BIT << methnum));
    }
    /*
     * Otherwise, see if the method name is in the array or string names
     */
    if ((l->method_list == NULL) || (l->method_list->nelts == 0)) {
        return 0;
    }
    methods = (char **)l->method_list->elts;
    for (i = 0; i < l->method_list->nelts; ++i) {
        if (strcmp(method, methods[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Add the specified method to a method list (if it isn't already there).
 */
AP_DECLARE(void) ap_method_list_add(ap_method_list_t *l, const char *method)
{
    int methnum;
    int i;
    const char **xmethod;
    char **methods;

    /*
     * If it's one of our known methods, use the shortcut and use the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    l->method_mask |= (AP_METHOD_BIT << methnum);
    if (methnum != M_INVALID) {
        return;
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if (l->method_list->nelts != 0) {
        methods = (char **)l->method_list->elts;
        for (i = 0; i < l->method_list->nelts; ++i) {
            if (strcmp(method, methods[i]) == 0) {
                return;
            }
        }
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
    l->method_mask |= ~(AP_METHOD_BIT << methnum);
    if (methnum != M_INVALID) {
        return;
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if (l->method_list->nelts != 0) {
        register int i, j, k;
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

