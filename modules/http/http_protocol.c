/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
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
            || (r->server->keep_alive_max > r->connection->keepalives))
        && !ap_status_drops_connection(r->status)
        && !wimpy
        && !ap_find_token(r->pool, conn, "close")
        && (!apr_table_get(r->subprocess_env, "nokeepalive")
            || apr_table_get(r->headers_in, "Via"))
        && ((ka_sent = ap_find_token(r->pool, conn, "keep-alive"))
            || (r->proto_num >= HTTP_VERSION(1,1)))) {
        int left = r->server->keep_alive_max - r->connection->keepalives;

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

    r->connection->keepalive = AP_CONN_CLOSE;

    return 0;
}

AP_DECLARE(int) ap_meets_conditions(request_rec *r)
{
    const char *etag;
    const char *if_match, *if_modified_since, *if_unmodified, *if_nonematch;
    apr_time_t tmp_time;
    apr_int64_t mtime;

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
                return HTTP_NOT_MODIFIED;
            }
            if (etag != NULL) {
                if (apr_table_get(r->headers_in, "Range")) {
                    if (etag[0] != 'W'
                        && ap_find_list_item(r->pool, if_nonematch, etag)) {
                        return HTTP_NOT_MODIFIED;
                    }
                }
                else if (ap_strstr_c(if_nonematch, etag)) {
                    return HTTP_NOT_MODIFIED;
                }
            }
        }
        else if (if_nonematch[0] == '*'
                 || (etag != NULL
                     && ap_find_list_item(r->pool, if_nonematch, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    /* Else if a valid If-Modified-Since request-header field was given
     * AND it is a GET or HEAD request
     * AND the requested resource has not been modified since the time
     * specified in this field, then the server MUST
     *    respond with a status of 304 (Not Modified).
     * A date later than the server's current request time is invalid.
     */
    else if ((r->method_number == M_GET)
             && ((if_modified_since =
                  apr_table_get(r->headers_in,
                                "If-Modified-Since")) != NULL)) {
        apr_time_t ims_time;
        apr_int64_t ims, reqtime;

        ims_time = apr_date_parse_http(if_modified_since);
        ims = apr_time_sec(ims_time);
        reqtime = apr_time_sec(r->request_time);

        if ((ims >= mtime) && (ims <= reqtime)) {
            return HTTP_NOT_MODIFIED;
        }
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

static long get_chunk_size(char *);

typedef struct http_filter_ctx {
    apr_off_t remaining;
    apr_off_t limit;
    apr_off_t limit_used;
    enum {
        BODY_NONE,
        BODY_LENGTH,
        BODY_CHUNK
    } state;
    int eos_sent;
} http_ctx_t;

/* This is the HTTP_INPUT filter for HTTP requests and responses from 
 * proxied servers (mod_proxy).  It handles chunked and content-length 
 * bodies.  This can only be inserted/used after the headers
 * are successfully parsed. 
 */
apr_status_t ap_http_filter(ap_filter_t *f, apr_bucket_brigade *b,
                            ap_input_mode_t mode, apr_read_type_e block,
                            apr_off_t readbytes)
{
    apr_bucket *e;
    http_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    apr_off_t totalread;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    if (!ctx) {
        const char *tenc, *lenp;
        f->ctx = ctx = apr_palloc(f->r->pool, sizeof(*ctx));
        ctx->state = BODY_NONE;
        ctx->remaining = 0;
        ctx->limit_used = 0;
        ctx->eos_sent = 0;

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
            if (!strcasecmp(tenc, "chunked")) {
                ctx->state = BODY_CHUNK;
            }
        }
        else if (lenp) {
            int conversion_error = 0;
            char *endstr;

            ctx->state = BODY_LENGTH;
            errno = 0;
            ctx->remaining = strtol(lenp, &endstr, 10);	/* we depend on ANSI */

            /* This protects us from over/underflow (the errno check),
             * non-digit chars in the string (excluding leading space)
             * (the endstr checks) and a negative number. Depending
             * on the strtol implementation, the errno check may also
             * trigger on an all whitespace string */
            if (errno || (endstr && *endstr) || (ctx->remaining < 0)) {
                 conversion_error = 1; 
            }

            if (conversion_error) {
                apr_bucket_brigade *bb;

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                              "Invalid Content-Length");

                bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
                e = ap_bucket_error_create(HTTP_REQUEST_ENTITY_TOO_LARGE, NULL,
                                           f->r->pool, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                ctx->eos_sent = 1;
                return ap_pass_brigade(f->r->output_filters, bb);
            }
            
            /* If we have a limit in effect and we know the C-L ahead of
             * time, stop it here if it is invalid. 
             */ 
            if (ctx->limit && ctx->limit < ctx->remaining) {
                apr_bucket_brigade *bb;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                          "Requested content-length of %" APR_OFF_T_FMT 
                          " is larger than the configured limit"
                          " of %" APR_OFF_T_FMT, ctx->remaining, ctx->limit);
                bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
                e = ap_bucket_error_create(HTTP_REQUEST_ENTITY_TOO_LARGE, NULL,
                                           f->r->pool, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                ctx->eos_sent = 1;
                return ap_pass_brigade(f->r->output_filters, bb);
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

        /* Since we're about to read data, send 100-Continue if needed.
         * Only valid on chunked and C-L bodies where the C-L is > 0. */
        if ((ctx->state == BODY_CHUNK || 
            (ctx->state == BODY_LENGTH && ctx->remaining > 0)) &&
            f->r->expecting_100 && f->r->proto_num >= HTTP_VERSION(1,1)) {
            char *tmp;
            apr_bucket_brigade *bb;

            tmp = apr_pstrcat(f->r->pool, AP_SERVER_PROTOCOL, " ",
                              status_lines[0], CRLF CRLF, NULL);
            bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
            e = apr_bucket_pool_create(tmp, strlen(tmp), f->r->pool,
                                       f->c->bucket_alloc);
            APR_BRIGADE_INSERT_HEAD(bb, e);
            e = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);

            ap_pass_brigade(f->c->output_filters, bb);
        }

        /* We can't read the chunk until after sending 100 if required. */
        if (ctx->state == BODY_CHUNK) {
            char line[30];
            apr_bucket_brigade *bb;
            apr_size_t len = 30;
            apr_off_t brigade_length;

            bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

            rv = ap_get_brigade(f->next, bb, AP_MODE_GETLINE,
                                APR_BLOCK_READ, 0);

            if (rv == APR_SUCCESS) {
                /* We have to check the length of the brigade we got back.
                 * We will not accept partial lines.
                 */
                rv = apr_brigade_length(bb, 1, &brigade_length);
                if (rv == APR_SUCCESS
                    && brigade_length > f->r->server->limit_req_line) {
                    rv = APR_ENOSPC;
                }
                if (rv == APR_SUCCESS) {
                    rv = apr_brigade_flatten(bb, line, &len);
                    if (rv == APR_SUCCESS) {
                        ctx->remaining = get_chunk_size(line);
                    }
                }
            }
            apr_brigade_cleanup(bb);

            /* Detect chunksize error (such as overflow) */
            if (rv != APR_SUCCESS || ctx->remaining < 0) {
                ctx->remaining = 0; /* Reset it in case we have to
                                     * come back here later */
                e = ap_bucket_error_create(HTTP_REQUEST_ENTITY_TOO_LARGE, NULL,
                                           f->r->pool,
                                           f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
                ctx->eos_sent = 1;
                return ap_pass_brigade(f->r->output_filters, bb);
            }

            if (!ctx->remaining) {
                /* Handle trailers by calling ap_get_mime_headers again! */
                ctx->state = BODY_NONE;
                ap_get_mime_headers(f->r);
                e = apr_bucket_eos_create(f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(b, e);
                ctx->eos_sent = 1;
                return APR_SUCCESS;
            }
        } 
    }

    if (ctx->eos_sent) {
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
        return APR_SUCCESS;
    }
        
    if (!ctx->remaining) {
        switch (ctx->state) {
        case BODY_NONE:
            break;
        case BODY_LENGTH:
            e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(b, e);
            ctx->eos_sent = 1;
            return APR_SUCCESS;
        case BODY_CHUNK:
            {
                char line[30];
                apr_bucket_brigade *bb;
                apr_size_t len = 30;

                bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

                /* We need to read the CRLF after the chunk.  */
                rv = ap_get_brigade(f->next, bb, AP_MODE_GETLINE,
                                    APR_BLOCK_READ, 0);
                apr_brigade_cleanup(bb);

                if (rv == APR_SUCCESS) {
                    /* Read the real chunk line. */
                    rv = ap_get_brigade(f->next, bb, AP_MODE_GETLINE,
                                        APR_BLOCK_READ, 0);
                    if (rv == APR_SUCCESS) {
                        rv = apr_brigade_flatten(bb, line, &len);
                        if (rv == APR_SUCCESS) {
                            ctx->remaining = get_chunk_size(line);
                        }
                    }
                    apr_brigade_cleanup(bb);
                }

                /* Detect chunksize error (such as overflow) */
                if (rv != APR_SUCCESS || ctx->remaining < 0) {
                    ctx->remaining = 0; /* Reset it in case we have to
                                         * come back here later */
                    e = ap_bucket_error_create(HTTP_REQUEST_ENTITY_TOO_LARGE,
                                               NULL, f->r->pool,
                                               f->c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(bb, e);
                    e = apr_bucket_eos_create(f->c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(bb, e);
                    ctx->eos_sent = 1;
                    return ap_pass_brigade(f->r->output_filters, bb);
                }

                if (!ctx->remaining) {
                    /* Handle trailers by calling ap_get_mime_headers again! */
                    ctx->state = BODY_NONE;
                    ap_get_mime_headers(f->r);
                    e = apr_bucket_eos_create(f->c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(b, e);
                    ctx->eos_sent = 1;
                    return APR_SUCCESS;
                }
            }
            break;
        }
    }

    /* Ensure that the caller can not go over our boundary point. */
    if (ctx->state == BODY_LENGTH || ctx->state == BODY_CHUNK) {
        if (ctx->remaining < readbytes) {
            readbytes = ctx->remaining;
        }
        AP_DEBUG_ASSERT(readbytes > 0);
    }

    rv = ap_get_brigade(f->next, b, mode, block, readbytes);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* How many bytes did we just read? */
    apr_brigade_length(b, 0, &totalread);

    /* If this happens, we have a bucket of unknown length.  Die because
     * it means our assumptions have changed. */
    AP_DEBUG_ASSERT(totalread >= 0);

    if (ctx->state != BODY_NONE) {
        ctx->remaining -= totalread;
    }

    /* If we have no more bytes remaining on a C-L request, 
     * save the callter a roundtrip to discover EOS.
     */
    if (ctx->state == BODY_LENGTH && ctx->remaining == 0) {
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(b, e);
    }

    /* We have a limit in effect. */
    if (ctx->limit) {
        /* FIXME: Note that we might get slightly confused on chunked inputs
         * as we'd need to compensate for the chunk lengths which may not
         * really count.  This seems to be up for interpretation.  */
        ctx->limit_used += totalread;
        if (ctx->limit < ctx->limit_used) {
            apr_bucket_brigade *bb;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                          "Read content-length of %" APR_OFF_T_FMT 
                          " is larger than the configured limit"
                          " of %" APR_OFF_T_FMT, ctx->limit_used, ctx->limit);
            bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
            e = ap_bucket_error_create(HTTP_REQUEST_ENTITY_TOO_LARGE, NULL,
                                       f->r->pool,
                                       f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            ctx->eos_sent = 1;
            return ap_pass_brigade(f->r->output_filters, bb);
        }
    }

    return APR_SUCCESS;
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

typedef struct header_struct {
    apr_pool_t *pool;
    apr_bucket_brigade *bb;
} header_struct;

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to table_do(), so their interfaces are co-dependent.
 * In other words, don't change this one without checking table_do in alloc.c.
 * It returns true unless there was a write error of some kind.
 */
static int form_header_field(header_struct *h,
                             const char *fieldname, const char *fieldval)
{
#if APR_CHARSET_EBCDIC
    char *headfield;
    apr_size_t len;
    apr_size_t name_len;
    apr_size_t val_len;
    char *next;

    name_len = strlen(fieldname);
    val_len = strlen(fieldval);
    len = name_len + val_len + 4; /* 4 for ": " plus CRLF */
    headfield = (char *)apr_palloc(h->pool, len + 1);
    memcpy(headfield, fieldname, name_len);
    next = headfield + name_len;
    *next++ = ':';
    *next++ = ' ';
    memcpy(next, fieldval, val_len);
    next += val_len;
    *next++ = CR;
    *next++ = LF;
    *next = 0;
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

    return apr_brigade_writev(h->bb, NULL, NULL, vec, vec_next - vec);
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
    if (r->assbackwards) {
        /* no such thing as a response protocol */
        return;
    }

    if (!r->status_line) {
        r->status_line = status_lines[ap_index_of_response(r->status)];
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
    const char *date;
    const char *server;
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

    /* keep a previously set date header (possibly from proxy), otherwise
     * generate a new date header */
    if ((date = apr_table_get(r->headers_out, "Date")) != NULL) {
        form_header_field(&h, "Date", date);
    }
    else {
        char *now = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(now, r->request_time);

        h.pool = r->pool;
        h.bb = bb;
        form_header_field(&h, "Date", now);
    }

    /* keep a previously set server header (possibly from proxy), otherwise
     * generate a new server header */
    if ((server = apr_table_get(r->headers_out, "Server")) != NULL) {
        form_header_field(&h, "Server", server);
    }
    else {
        form_header_field(&h, "Server", ap_get_server_version());
    }

    /* unset so we don't send them again */
    apr_table_unset(r->headers_out, "Date");
    apr_table_unset(r->headers_out, "Server");
}

AP_DECLARE(void) ap_basic_http_header(request_rec *r, apr_bucket_brigade *bb)
{
    const char *protocol;

    basic_http_header_check(r, &protocol);
    basic_http_header(r, bb, protocol);
}

/* Navigator versions 2.x, 3.x and 4.0 betas up to and including 4.0b2
 * have a header parsing bug.  If the terminating \r\n occur starting
 * at offset 256, 257 or 258 of output then it will not properly parse
 * the headers.  Curiously it doesn't exhibit this problem at 512, 513.
 * We are guessing that this is because their initial read of a new request
 * uses a 256 byte buffer, and subsequent reads use a larger buffer.
 * So the problem might exist at different offsets as well.
 *
 * This should also work on keepalive connections assuming they use the
 * same small buffer for the first read of each new request.
 *
 * At any rate, we check the bytes written so far and, if we are about to
 * tickle the bug, we instead insert a bogus padding header.  Since the bug
 * manifests as a broken image in Navigator, users blame the server.  :(
 * It is more expensive to check the User-Agent than it is to just add the
 * bytes, so we haven't used the BrowserMatch feature here.
 */
static void terminate_header(apr_bucket_brigade *bb)
{
    char tmp[] = "X-Pad: avoid browser bug" CRLF;
    char crlf[] = CRLF;
    apr_off_t len;
    apr_size_t buflen;

    (void) apr_brigade_length(bb, 1, &len);

    if (len >= 255 && len <= 257) {
        buflen = strlen(tmp);
        ap_xlate_proto_to_ascii(tmp, buflen);
        apr_brigade_write(bb, NULL, NULL, tmp, buflen);
    }
    buflen = strlen(crlf);
    ap_xlate_proto_to_ascii(crlf, buflen);
    apr_brigade_write(bb, NULL, NULL, crlf, buflen);
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

    /* TRACE is always allowed */
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

AP_DECLARE_NONSTD(int) ap_send_http_trace(request_rec *r)
{
    int rv;
    apr_bucket_brigade *b;
    header_struct h;

    if (r->method_number != M_TRACE) {
        return DECLINED;
    }

    /* Get the original request */
    while (r->prev) {
        r = r->prev;
    }

    if ((rv = ap_setup_client_block(r, REQUEST_NO_BODY))) {
        return rv;
    }

    ap_set_content_type(r, "message/http");

    /* Now we recreate the request, and echo it back */

    b = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_brigade_putstrs(b, NULL, NULL, r->the_request, CRLF, NULL);
    h.pool = r->pool;
    h.bb = b;
    apr_table_do((int (*) (void *, const char *, const char *))
                 form_header_field, (void *) &h, r->headers_in, NULL);
    apr_brigade_puts(b, NULL, NULL, CRLF);
    ap_pass_brigade(r->output_filters, b);

    return DONE;
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
            if (*strpp && strcasecmp(*strpp, start) == 0) {
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
    apr_table_do((int (*)(void *, const char *, const char *))uniq_field_values,
                 (void *) varies, r->headers_out, "Vary", NULL);

    /* If we found any, replace old Vary fields with unique-ified value */

    if (varies->nelts > 0) {
        apr_table_setn(r->headers_out, "Vary",
                       apr_array_pstrcat(r->pool, varies, ','));
    }
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

typedef struct header_filter_ctx {
    int headers_sent;
} header_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f,
                                                           apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    const char *clheader;
    const char *protocol;
    apr_bucket *e;
    apr_bucket_brigade *b2;
    header_struct h;
    header_filter_ctx *ctx = f->ctx;

    AP_DEBUG_ASSERT(!r->main);

    if (r->header_only) {
        if (!ctx) {
            ctx = f->ctx = apr_pcalloc(r->pool, sizeof(header_filter_ctx));
        }
        else if (ctx->headers_sent) {
            apr_brigade_destroy(b);
            return OK;
        }
    }

    APR_BRIGADE_FOREACH(e, b) {
        if (e->type == &ap_bucket_type_error) {
            ap_bucket_error *eb = e->data;

            ap_die(eb->status, r);
            return AP_FILTER_ERROR;
        }
    }

    if (r->assbackwards) {
        r->sent_bodyct = 1;
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, b);
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
        apr_table_set(r->subprocess_env, "force-response-1.0", "1");
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

    if (r->chunked) {
        apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
        apr_table_unset(r->headers_out, "Content-Length");
    }

    apr_table_setn(r->headers_out, "Content-Type", 
                   ap_make_content_type(r, r->content_type));

    if (r->content_encoding) {
        apr_table_setn(r->headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    if (!apr_is_empty_array(r->content_languages)) {
        int i;
        char **languages = (char **)(r->content_languages->elts);
        for (i = 0; i < r->content_languages->nelts; ++i) {
            apr_table_mergen(r->headers_out, "Content-Language", languages[i]);
        }
    }

    /*
     * Control cachability for non-cachable responses if not already set by
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

    if (r->status == HTTP_NOT_MODIFIED) {
        apr_table_do((int (*)(void *, const char *, const char *)) form_header_field,
                     (void *) &h, r->headers_out,
                     "Connection",
                     "Keep-Alive",
                     "ETag",
                     "Content-Location",
                     "Expires",
                     "Cache-Control",
                     "Vary",
                     "Warning",
                     "WWW-Authenticate",
                     "Proxy-Authenticate",
                     NULL);
    }
    else {
        send_all_header_fields(&h, r);
    }

    terminate_header(b2);

    ap_pass_brigade(f->next, b2);

    if (r->header_only) {
        apr_brigade_destroy(b);
        ctx->headers_sent = 1;
        return OK;
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
    return ap_pass_brigade(f->next, b);
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
 * 1. Call setup_client_block() near the beginning of the request
 *    handler. This will set up all the necessary properties, and will
 *    return either OK, or an error code. If the latter, the module should
 *    return that error code. The second parameter selects the policy to
 *    apply if the request message indicates a body, and how a chunked
 *    transfer-coding should be interpreted. Choose one of
 *
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 *
 *    In order to use the last two options, the caller MUST provide a buffer
 *    large enough to hold a chunk-size line, including any extensions.
 *
 * 2. When you are ready to read a body (if any), call should_client_block().
 *    This will tell the module whether or not to read input. If it is 0,
 *    the module should assume that there is no message body to read.
 *    This step also sends a 100 Continue response to HTTP/1.1 clients,
 *    so should not be called until the module is *definitely* ready to
 *    read content. (otherwise, the point of the 100 response is defeated).
 *    Never call this function more than once.
 *
 * 3. Finally, call get_client_block in a loop. Pass it a buffer and its size.
 *    It will put data into the buffer (not necessarily a full buffer), and
 *    return the length of the input block. When it is done reading, it will
 *    return 0 if EOF, or -1 if there was an error.
 *    If an error occurs on input, we force an end to keepalive.
 */

AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy)
{
    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");

    r->read_body = read_policy;
    r->read_chunked = 0;
    r->remaining = 0;

    if (tenc) {
        if (strcasecmp(tenc, "chunked")) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Unknown Transfer-Encoding %s", tenc);
            return HTTP_NOT_IMPLEMENTED;
        }
        if (r->read_body == REQUEST_CHUNKED_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "chunked Transfer-Encoding forbidden: %s", r->uri);
            return (lenp) ? HTTP_BAD_REQUEST : HTTP_LENGTH_REQUIRED;
        }

        r->read_chunked = 1;
    }
    else if (lenp) {
        int conversion_error = 0;
        char *endstr;

        errno = 0;
        r->remaining = strtol(lenp, &endstr, 10); /* depend on ANSI */

        /* See comments in ap_http_filter() */
        if (errno || (endstr && *endstr) || (r->remaining < 0)) {
            conversion_error = 1; 
        }

        if (conversion_error) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid Content-Length");
            return HTTP_BAD_REQUEST;
        }
    }

    if ((r->read_body == REQUEST_NO_BODY)
        && (r->read_chunked || (r->remaining > 0))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "%s with body is not allowed for %s", r->method, r->uri);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

#ifdef AP_DEBUG
    {
        /* Make sure ap_getline() didn't leave any droppings. */
        core_request_config *req_cfg =
            (core_request_config *)ap_get_module_config(r->request_config,
                                                        &core_module);
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

/**
 * Parse a chunk extension, detect overflow.
 * There are two error cases:
 *  1) If the conversion would require too many bits, a -1 is returned.
 *  2) If the conversion used the correct number of bits, but an overflow
 *     caused only the sign bit to flip, then that negative number is
 *     returned.
 * In general, any negative number can be considered an overflow error.
 */
static long get_chunk_size(char *b)
{
    long chunksize = 0;
    size_t chunkbits = sizeof(long) * 8;

    /* Skip leading zeros */
    while (*b == '0') {
        ++b;
    }

    while (apr_isxdigit(*b) && (chunkbits > 0)) {
        int xvalue = 0;

        if (*b >= '0' && *b <= '9') {
            xvalue = *b - '0';
        }
        else if (*b >= 'A' && *b <= 'F') {
            xvalue = *b - 'A' + 0xa;
        }
        else if (*b >= 'a' && *b <= 'f') {
            xvalue = *b - 'a' + 0xa;
        }

        chunksize = (chunksize << 4) | xvalue;
        chunkbits -= 4;
        ++b;
    }
    if (apr_isxdigit(*b) && (chunkbits <= 0)) {
        /* overflow */
        return -1;
    }

    return chunksize;
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
    apr_bucket_brigade *bb;
    int rv, seen_eos;

    /* Sometimes we'll get in a state where the input handling has
     * detected an error where we want to drop the connection, so if
     * that's the case, don't read the data as that is what we're trying
     * to avoid.
     *
     * This function is also a no-op on a subrequest.
     */
    if (r->main || r->connection->keepalive == AP_CONN_CLOSE ||
        ap_status_drops_connection(r->status)) {
        return OK;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    seen_eos = 0;
    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            /* FIXME: If we ever have a mapping from filters (apr_status_t)
             * to HTTP error codes, this would be a good place for them.
             * 
             * If we received the special case AP_FILTER_ERROR, it means
             * that the filters have already handled this error.
             * Otherwise, we should assume we have a bad request.
             */
            if (rv == AP_FILTER_ERROR) {
                apr_brigade_destroy(bb);
                return rv;
            }
            else {
                apr_brigade_destroy(bb);
                return HTTP_BAD_REQUEST;
            }
        }

        APR_BRIGADE_FOREACH(bucket, bb) {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* These are metadata buckets. */
            if (bucket->length == 0) {
                continue;
            }

            /* We MUST read because in case we have an unknown-length
             * bucket or one that morphs, we want to exhaust it.
             */
            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                apr_brigade_destroy(bb);
                return HTTP_BAD_REQUEST;
            }
        }
        apr_brigade_cleanup(bb);
    } while (!seen_eos);

    return OK;
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
                           "<p>The requested method ", r->method,
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
                         r->method,
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
                           r->method,
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
                           apr_table_get(r->headers_in, "Expect"),
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
        ap_set_content_type(r, "text/html; charset=iso-8859-1");

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
        ap_rvputs_proto_in_ascii(r, ap_psignature("<hr />\n", r), NULL);
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
    ml->method_list = apr_array_make(p, sizeof(char *), nelts);
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
 * Invoke a callback routine for each method in the specified list.
 */
AP_DECLARE_NONSTD(void) ap_method_list_do(int (*comp) (void *urec,
                                                       const char *mname,
                                                       int mnum),
                                          void *rec,
                                          const ap_method_list_t *ml, ...)
{
    va_list vp;
    va_start(vp, ml);
    ap_method_list_vdo(comp, rec, ml, vp);
    va_end(vp);
}

AP_DECLARE(void) ap_method_list_vdo(int (*comp) (void *mrec,
                                                 const char *mname,
                                                 int mnum),
                                    void *rec, const ap_method_list_t *ml,
                                    va_list vp)
{

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

/* Generate the human-readable hex representation of an unsigned long
 * (basically a faster version of 'sprintf("%lx")')
 */
#define HEX_DIGITS "0123456789abcdef"
static char *etag_ulong_to_hex(char *next, unsigned long u)
{
    int printing = 0;
    int shift = sizeof(unsigned long) * 8 - 4;
    do {
        unsigned long next_digit = ((u >> shift) & (unsigned long)0xf);
        if (next_digit) {
            *next++ = HEX_DIGITS[next_digit];
            printing = 1;
        }
        else if (printing) {
            *next++ = HEX_DIGITS[next_digit];
        }
        shift -= 4;
    } while (shift);
    *next++ = HEX_DIGITS[u & (unsigned long)0xf];
    return next;
}

#define ETAG_WEAK "W/"
#define CHARS_PER_UNSIGNED_LONG (sizeof(unsigned long) * 2)
/*
 * Construct an entity tag (ETag) from resource information.  If it's a real
 * file, build in some of the file characteristics.  If the modification time
 * is newer than (request-time minus 1 second), mark the ETag as weak - it
 * could be modified again in as short an interval.  We rationalize the
 * modification time we're given to keep it from being in the future.
 */
AP_DECLARE(char *) ap_make_etag(request_rec *r, int force_weak)
{
    char *weak;
    apr_size_t weak_len;
    char *etag;
    char *next;
    core_dir_config *cfg;
    etag_components_t etag_bits;
    etag_components_t bits_added;

    cfg = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                  &core_module);
    etag_bits = (cfg->etag_bits & (~ cfg->etag_remove)) | cfg->etag_add;
    
    /*
     * If it's a file (or we wouldn't be here) and no ETags
     * should be set for files, return an empty string and
     * note it for the header-sender to ignore.
     */
    if (etag_bits & ETAG_NONE) {
        apr_table_setn(r->notes, "no-etag", "omit");
        return "";
    }

    if (etag_bits == ETAG_UNSET) {
        etag_bits = ETAG_BACKWARD;
    }
    /*
     * Make an ETag header out of various pieces of information. We use
     * the last-modified date and, if we have a real file, the
     * length and inode number - note that this doesn't have to match
     * the content-length (i.e. includes), it just has to be unique
     * for the file.
     *
     * If the request was made within a second of the last-modified date,
     * we send a weak tag instead of a strong one, since it could
     * be modified again later in the second, and the validation
     * would be incorrect.
     */
    if ((r->request_time - r->mtime > (1 * APR_USEC_PER_SEC)) &&
        !force_weak) {
        weak = NULL;
        weak_len = 0;
    }
    else {
        weak = ETAG_WEAK;
        weak_len = sizeof(ETAG_WEAK);
    }

    if (r->finfo.filetype != 0) {
        /*
         * ETag gets set to [W/]"inode-size-mtime", modulo any
         * FileETag keywords.
         */
        etag = apr_palloc(r->pool, weak_len + sizeof("\"--\"") +
                          3 * CHARS_PER_UNSIGNED_LONG + 1);
        next = etag;
        if (weak) {
            while (*weak) {
                *next++ = *weak++;
            }
        }
        *next++ = '"';
        bits_added = 0;
        if (etag_bits & ETAG_INODE) {
            next = etag_ulong_to_hex(next, (unsigned long)r->finfo.inode);
            bits_added |= ETAG_INODE;
        }
        if (etag_bits & ETAG_SIZE) {
            if (bits_added != 0) {
                *next++ = '-';
            }
            next = etag_ulong_to_hex(next, (unsigned long)r->finfo.size);
            bits_added |= ETAG_SIZE;
        }
        if (etag_bits & ETAG_MTIME) {
            if (bits_added != 0) {
                *next++ = '-';
            }
            next = etag_ulong_to_hex(next, (unsigned long)r->mtime);
        }
        *next++ = '"';
        *next = '\0';
    }
    else {
        /*
         * Not a file document, so just use the mtime: [W/]"mtime"
         */
        etag = apr_palloc(r->pool, weak_len + sizeof("\"\"") +
                          CHARS_PER_UNSIGNED_LONG + 1);
        next = etag;
        if (weak) {
            while (*weak) {
                *next++ = *weak++;
            }
        }
        *next++ = '"';
        next = etag_ulong_to_hex(next, (unsigned long)r->mtime);
        *next++ = '"';
        *next = '\0';
    }

    return etag;
}

AP_DECLARE(void) ap_set_etag(request_rec *r)
{
    char *etag;
    char *variant_etag, *vlv;
    int vlv_weak;

    if (!r->vlist_validator) {
        etag = ap_make_etag(r, 0);
    
        /* If we get a blank etag back, don't set the header. */
        if (!etag[0]) {
            return;
        }
    }
    else {
        /* If we have a variant list validator (vlv) due to the
         * response being negotiated, then we create a structured
         * entity tag which merges the variant etag with the variant
         * list validator (vlv).  This merging makes revalidation
         * somewhat safer, ensures that caches which can deal with
         * Vary will (eventually) be updated if the set of variants is
         * changed, and is also a protocol requirement for transparent
         * content negotiation.
         */

        /* if the variant list validator is weak, we make the whole
         * structured etag weak.  If we would not, then clients could
         * have problems merging range responses if we have different
         * variants with the same non-globally-unique strong etag.
         */

        vlv = r->vlist_validator;
        vlv_weak = (vlv[0] == 'W');

        variant_etag = ap_make_etag(r, vlv_weak);

        /* If we get a blank etag back, don't append vlv and stop now. */
        if (!variant_etag[0]) {
            return;
        }

        /* merge variant_etag and vlv into a structured etag */
        variant_etag[strlen(variant_etag) - 1] = '\0';
        if (vlv_weak) {
            vlv += 3;
        }
        else {
            vlv++;
        }
        etag = apr_pstrcat(r->pool, variant_etag, ";", vlv, NULL);
    }

    apr_table_setn(r->headers_out, "ETag", etag);
}

static int parse_byterange(char *range, apr_off_t clength,
                           apr_off_t *start, apr_off_t *end)
{
    char *dash = strchr(range, '-');

    if (!dash) {
        return 0;
    }

    if ((dash == range)) {
        /* In the form "-5" */
        *start = clength - apr_atoi64(dash + 1);
        *end = clength - 1;
    }
    else {
        *dash = '\0';
        dash++;
        *start = apr_atoi64(range);
        if (*dash) {
            *end = apr_atoi64(dash);
        }
        else {                  /* "5-" */
            *end = clength - 1;
        }
    }

    if (*start < 0) {
        *start = 0;
    }

    if (*end >= clength) {
        *end = clength - 1;
    }

    if (*start > *end) {
        return -1;
    }

    return (*start > 0 || *end < clength);
}

static int ap_set_byterange(request_rec *r);

typedef struct byterange_ctx {
    apr_bucket_brigade *bb;
    int num_ranges;
    char *boundary;
    char *bound_head;
} byterange_ctx;

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
#define PARTITION_ERR_FMT "apr_brigade_partition() failed " \
                          "[%" APR_OFF_T_FMT ",%" APR_OFF_T_FMT "]"

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_byterange_filter(ap_filter_t *f,
                                                         apr_bucket_brigade *bb)
{
#define MIN_LENGTH(len1, len2) ((len1 > len2) ? len2 : len1)
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    byterange_ctx *ctx = f->ctx;
    apr_bucket *e;
    apr_bucket_brigade *bsend;
    apr_off_t range_start;
    apr_off_t range_end;
    char *current;
    apr_off_t bb_length;
    apr_off_t clength = 0;
    apr_status_t rv;
    int found = 0;

    if (!ctx) {
        int num_ranges = ap_set_byterange(r);

        /* We have nothing to do, get out of the way. */
        if (num_ranges == 0) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->num_ranges = num_ranges;
        /* create a brigade in case we never call ap_save_brigade() */
        ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);

        if (ctx->num_ranges > 1) {
            /* Is ap_make_content_type required here? */
            const char *orig_ct = ap_make_content_type(r, r->content_type);
            ctx->boundary = apr_psprintf(r->pool, "%" APR_UINT64_T_HEX_FMT "%lx",
                                         (apr_uint64_t)r->request_time, (long) getpid());

            ap_set_content_type(r, apr_pstrcat(r->pool, "multipart",
                                               use_range_x(r) ? "/x-" : "/",
                                               "byteranges; boundary=",
                                               ctx->boundary, NULL));

            ctx->bound_head = apr_pstrcat(r->pool,
                                    CRLF "--", ctx->boundary,
                                    CRLF "Content-type: ",
                                    orig_ct,
                                    CRLF "Content-range: bytes ",
                                    NULL);
            ap_xlate_proto_to_ascii(ctx->bound_head, strlen(ctx->bound_head));
        }
    }

    /* We can't actually deal with byte-ranges until we have the whole brigade
     * because the byte-ranges can be in any order, and according to the RFC,
     * we SHOULD return the data in the same order it was requested.
     *
     * XXX: We really need to dump all bytes prior to the start of the earliest
     * range, and only slurp up to the end of the latest range.  By this we
     * mean that we should peek-ahead at the lowest first byte of any range,
     * and the highest last byte of any range.
     */
    if (!APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
        ap_save_brigade(f, &ctx->bb, &bb, r->pool);
        return APR_SUCCESS;
    }

    /* Prepend any earlier saved brigades. */
    APR_BRIGADE_PREPEND(bb, ctx->bb);

    /* It is possible that we won't have a content length yet, so we have to
     * compute the length before we can actually do the byterange work.
     */
    apr_brigade_length(bb, 1, &bb_length);
    clength = (apr_off_t)bb_length;

    /* this brigade holds what we will be sending */
    bsend = apr_brigade_create(r->pool, c->bucket_alloc);

    while ((current = ap_getword(r->pool, &r->range, ','))
           && (rv = parse_byterange(current, clength, &range_start,
                                    &range_end))) {
        apr_bucket *e2;
        apr_bucket *ec;

        if (rv == -1) {
            continue;
        }

        /* these calls to apr_brigade_partition() should theoretically
         * never fail because of the above call to apr_brigade_length(),
         * but what the heck, we'll check for an error anyway */
        if ((rv = apr_brigade_partition(bb, range_start, &ec)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          PARTITION_ERR_FMT, range_start, clength);
            continue;
        }
        if ((rv = apr_brigade_partition(bb, range_end+1, &e2)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          PARTITION_ERR_FMT, range_end+1, clength);
            continue;
        }

        found = 1;

        /* For single range requests, we must produce Content-Range header.
         * Otherwise, we need to produce the multipart boundaries.
         */
        if (ctx->num_ranges == 1) {
            apr_table_setn(r->headers_out, "Content-Range",
                           apr_psprintf(r->pool, "bytes " BYTERANGE_FMT,
                                        range_start, range_end, clength));
        }
        else {
            char *ts;

            e = apr_bucket_pool_create(ctx->bound_head, strlen(ctx->bound_head),
                                       r->pool, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bsend, e);

            ts = apr_psprintf(r->pool, BYTERANGE_FMT CRLF CRLF,
                              range_start, range_end, clength);
            ap_xlate_proto_to_ascii(ts, strlen(ts));
            e = apr_bucket_pool_create(ts, strlen(ts), r->pool,
                                       c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bsend, e);
        }

        do {
            apr_bucket *foo;
            const char *str;
            apr_size_t len;

            if (apr_bucket_copy(ec, &foo) != APR_SUCCESS) {
                /* this shouldn't ever happen due to the call to
                 * apr_brigade_length() above which normalizes
                 * indeterminate-length buckets.  just to be sure,
                 * though, this takes care of uncopyable buckets that
                 * do somehow manage to slip through.
                 */
                /* XXX: check for failure? */
                apr_bucket_read(ec, &str, &len, APR_BLOCK_READ);
                apr_bucket_copy(ec, &foo);
            }
            APR_BRIGADE_INSERT_TAIL(bsend, foo);
            ec = APR_BUCKET_NEXT(ec);
        } while (ec != e2);
    }

    if (found == 0) {
        ap_remove_output_filter(f);
        r->status = HTTP_OK;
        /* bsend is assumed to be empty if we get here. */
        e = ap_bucket_error_create(HTTP_RANGE_NOT_SATISFIABLE, NULL,
                                   r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bsend, e);
        e = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bsend, e);
        return ap_pass_brigade(f->next, bsend);
    }

    if (ctx->num_ranges > 1) {
        char *end;

        /* add the final boundary */
        end = apr_pstrcat(r->pool, CRLF "--", ctx->boundary, "--" CRLF, NULL);
        ap_xlate_proto_to_ascii(end, strlen(end));
        e = apr_bucket_pool_create(end, strlen(end), r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bsend, e);
    }

    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bsend, e);

    /* we're done with the original content - all of our data is in bsend. */
    apr_brigade_destroy(bb);

    /* send our multipart output */
    return ap_pass_brigade(f->next, bsend);
}

static int ap_set_byterange(request_rec *r)
{
    const char *range;
    const char *if_range;
    const char *match;
    const char *ct;
    int num_ranges;

    if (r->assbackwards) {
        return 0;
    }

    /* Check for Range request-header (HTTP/1.1) or Request-Range for
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

    /* Check the If-Range header for Etag or Date.
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

    if (!ap_strchr_c(range, ',')) {
        /* a single range */
        num_ranges = 1;
    }
    else {
        /* a multiple range */
        num_ranges = 2;
    }

    r->status = HTTP_PARTIAL_CONTENT;
    r->range = range + 6;

    return num_ranges;
}
