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
 * protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_strmatch.h"

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
#include "mod_core.h"
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"
#include "scoreboard.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

/* get the length of the field name for logging, but no more than 80 bytes */
#define LOG_NAME_MAX_LEN 80
static int field_name_len(const char *field)
{
    const char *end = ap_strchr_c(field, ':');
    if (end == NULL || end - field > LOG_NAME_MAX_LEN)
        return LOG_NAME_MAX_LEN;
    return end - field;
}

typedef enum {
    http_error_none,
    http_error_badprotocol,
    http_error_reject09,
    http_error_badmethod09,
} http_error;

static http_error r_assign_protocol(request_rec *r,
                                    const char *protocol,
                                    int strict)
{
    int proto_num;
    http_error error = http_error_none;

    if (protocol[0] == 'H' && protocol[1] == 'T'
            && protocol[2] == 'T' && protocol[3] == 'P'
            && protocol[4] == '/' && apr_isdigit(protocol[5])
            && protocol[6] == '.' && apr_isdigit(protocol[7])
            && !protocol[8] && protocol[5] != '0') {
        r->assbackwards = 0;
        proto_num = HTTP_VERSION(protocol[5] - '0', protocol[7] - '0');
    }
    else if ((protocol[0] == 'H' || protocol[0] == 'h')
                 && (protocol[1] == 'T' || protocol[1] == 't')
                 && (protocol[2] == 'T' || protocol[2] == 't')
                 && (protocol[3] == 'P' || protocol[3] == 'p')
                 && protocol[4] == '/' && apr_isdigit(protocol[5])
                 && protocol[6] == '.' && apr_isdigit(protocol[7])
                 && !protocol[8] && protocol[5] != '0') {
        r->assbackwards = 0;
        proto_num = HTTP_VERSION(protocol[5] - '0', protocol[7] - '0');
        if (strict && error == http_error_none)
            error = http_error_badprotocol;
        else
            protocol = apr_psprintf(r->pool, "HTTP/%d.%d", HTTP_VERSION_MAJOR(proto_num),
                                    HTTP_VERSION_MINOR(proto_num));
    }
    else if (protocol[0]) {
        proto_num = HTTP_VERSION(0, 9);
        if (error == http_error_none)
            error = http_error_badprotocol;
    }
    else {
        r->assbackwards = 1;
        protocol = "HTTP/0.9";
        proto_num = HTTP_VERSION(0, 9);
    }
    r->protocol = protocol;
    r->proto_num = proto_num;
    return error;
}

AP_DECLARE(int) ap_assign_request(request_rec *r,
                                  const char *method, const char *uri,
                                  const char *protocol)
{
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    http_error error = r_assign_protocol(r, protocol, strict);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "assigned protocol: %s, error=%d", r->protocol, error);

    /* Determine the method_number and parse the uri prior to invoking error
     * handling, such that these fields are available for substitution
     */
    r->method = method;
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H')
        r->header_only = 1;

    /* For internal integrity and palloc efficiency, reconstruct the_request
     * in one palloc, using only single SP characters, per spec.
     */
    r->the_request = apr_pstrcat(r->pool, r->method, *uri ? " " : NULL, uri,
                                 *r->protocol ? " " : NULL, r->protocol, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "assigned request_line: %s, error=%d", r->the_request, error);

    ap_parse_uri(r, uri);
    if (r->status == HTTP_OK
            && (r->parsed_uri.path != NULL)
            && (r->parsed_uri.path[0] != '/')
            && (r->method_number != M_OPTIONS
                || strcmp(r->parsed_uri.path, "*") != 0)) {
        /* Invalid request-target per RFC 7230 section 5.3 */
        r->status = HTTP_BAD_REQUEST;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "parsed uri: r->status=%d, error=%d", r->status, error);
    /* With the request understood, we can consider HTTP/0.9 specific errors */
    if (r->proto_num == HTTP_VERSION(0, 9) && error == http_error_none) {
        if (conf->http09_enable == AP_HTTP09_DISABLE)
            error = http_error_reject09;
        else if (strict && (r->method_number != M_GET || r->header_only))
            error = http_error_badmethod09;
    }

    /* Now that the method, uri and protocol are all processed,
     * we can safely resume any deferred error reporting
     */
    if (error != http_error_none) {
        switch (error) {
        case http_error_badprotocol:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10388)
                          "HTTP Request: Unrecognized protocol '%.*s' "
                          "(perhaps whitespace was injected?)",
                          field_name_len(r->protocol), r->protocol);
            break;
        case http_error_reject09:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02401)
                          "HTTP Request: Rejected HTTP/0.9 request");
            break;
        case http_error_badmethod09:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03444)
                          "HTTP Request: Invalid method token: '%.*s'"
                          " (only GET is allowed for HTTP/0.9 requests)",
                          field_name_len(r->method), r->method);
            break;
        default:
            break;
        }
        r->status = HTTP_BAD_REQUEST;
        goto failed;
    }

    if (conf->http_methods == AP_HTTP_METHODS_REGISTERED
            && r->method_number == M_INVALID) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02423)
                      "HTTP Request Line; Unrecognized HTTP method: '%.*s' "
                      "(disallowed by RegisteredMethods)",
                      field_name_len(r->method), r->method);
        r->status = HTTP_NOT_IMPLEMENTED;
        /* This can't happen in an HTTP/0.9 request, we verified GET above */
        goto failed;
    }

    if (r->status != HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03450)
                      "HTTP Request Line; Unable to parse URI: '%.*s'",
                      field_name_len(r->uri), r->uri);
        goto failed;
    }

    if (strict) {
        if (r->parsed_uri.fragment) {
            /* RFC3986 3.5: no fragment */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02421)
                          "HTTP Request Line; URI must not contain a fragment");
            r->status = HTTP_BAD_REQUEST;
            goto failed;
        }
        if (r->parsed_uri.user || r->parsed_uri.password) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02422)
                          "HTTP Request Line; URI must not contain a "
                          "username/password");
            r->status = HTTP_BAD_REQUEST;
            goto failed;
        }
    }
    return 1;

failed:
    if (error != http_error_none && r->proto_num == HTTP_VERSION(0, 9)) {
        /* Send all parsing and protocol error response with 1.x behavior,
         * and reserve 505 errors for actual HTTP protocols presented.
         * As called out in RFC7230 3.5, any errors parsing the protocol
         * from the request line are nearly always misencoded HTTP/1.x
         * requests. Only a valid 0.9 request with no parsing errors
         * at all may be treated as a simple request, if allowed.
         */
        r->assbackwards = 0;
        r->connection->keepalive = AP_CONN_CLOSE;
        r->proto_num = HTTP_VERSION(1, 0);
        r->protocol  = "HTTP/1.0";
    }
    return 0;

}
