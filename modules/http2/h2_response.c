/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <util_time.h>

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2_filter.h"
#include "h2_h2.h"
#include "h2_util.h"
#include "h2_request.h"
#include "h2_response.h"


static apr_table_t *parse_headers(apr_array_header_t *hlines, apr_pool_t *pool)
{
    if (hlines) {
        apr_table_t *headers = apr_table_make(pool, hlines->nelts);        
        int i;
        
        for (i = 0; i < hlines->nelts; ++i) {
            char *hline = ((char **)hlines->elts)[i];
            char *sep = ap_strchr(hline, ':');
            if (!sep) {
                ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, pool,
                              APLOGNO(02955) "h2_response: invalid header[%d] '%s'",
                              i, (char*)hline);
                /* not valid format, abort */
                return NULL;
            }
            (*sep++) = '\0';
            while (*sep == ' ' || *sep == '\t') {
                ++sep;
            }
            
            if (!h2_util_ignore_header(hline)) {
                apr_table_merge(headers, hline, sep);
            }
        }
        return headers;
    }
    else {
        return apr_table_make(pool, 0);        
    }
}

static const char *get_sos_filter(apr_table_t *notes) 
{
    return notes? apr_table_get(notes, H2_RESP_SOS_NOTE) : NULL;
}

static h2_response *h2_response_create_int(int stream_id,
                                           int rst_error,
                                           int http_status,
                                           apr_table_t *headers,
                                           apr_table_t *notes,
                                           apr_pool_t *pool)
{
    h2_response *response;
    const char *s;

    if (!headers) {
        return NULL;
    }
    
    response = apr_pcalloc(pool, sizeof(h2_response));
    if (response == NULL) {
        return NULL;
    }
    
    response->stream_id      = stream_id;
    response->rst_error      = rst_error;
    response->http_status    = http_status? http_status : 500;
    response->content_length = -1;
    response->headers        = headers;
    response->sos_filter     = get_sos_filter(notes);
    
    s = apr_table_get(headers, "Content-Length");
    if (s) {
        char *end;
        
        response->content_length = apr_strtoi64(s, &end, 10);
        if (s == end) {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, 
                          pool, APLOGNO(02956) 
                          "h2_response: content-length"
                          " value not parsed: %s", s);
            response->content_length = -1;
        }
    }
    return response;
}


h2_response *h2_response_create(int stream_id,
                                int rst_error,
                                int http_status,
                                apr_array_header_t *hlines,
                                apr_table_t *notes,
                                apr_pool_t *pool)
{
    return h2_response_create_int(stream_id, rst_error, http_status,
                                  parse_headers(hlines, pool), notes, pool);
}

h2_response *h2_response_rcreate(int stream_id, request_rec *r,
                                 apr_table_t *header, apr_pool_t *pool)
{
    h2_response *response = apr_pcalloc(pool, sizeof(h2_response));
    if (response == NULL) {
        return NULL;
    }
    
    response->stream_id      = stream_id;
    response->http_status    = r->status;
    response->content_length = -1;
    response->headers        = header;
    response->sos_filter     = get_sos_filter(r->notes);

    if (response->http_status == HTTP_FORBIDDEN) {
        const char *cause = apr_table_get(r->notes, "ssl-renegotiate-forbidden");
        if (cause) {
            /* This request triggered a TLS renegotiation that is now allowed 
             * in HTTP/2. Tell the client that it should use HTTP/1.1 for this.
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, response->http_status, r, 
                          "h2_response(%ld-%d): renegotiate forbidden, cause: %s",
                          (long)r->connection->id, stream_id, cause);
            response->rst_error = H2_ERR_HTTP_1_1_REQUIRED;
        }
    }
    
    return response;
}

h2_response *h2_response_die(int stream_id, apr_status_t type,
                             const struct h2_request *req, apr_pool_t *pool)
{
    apr_table_t *headers = apr_table_make(pool, 5);
    char *date = NULL;
    
    date = apr_palloc(pool, APR_RFC822_DATE_LEN);
    ap_recent_rfc822_date(date, req->request_time);
    apr_table_setn(headers, "Date", date);
    apr_table_setn(headers, "Server", ap_get_server_banner());
    
    return h2_response_create_int(stream_id, 0, 500, headers, NULL, pool);
}

h2_response *h2_response_clone(apr_pool_t *pool, h2_response *from)
{
    h2_response *to = apr_pcalloc(pool, sizeof(h2_response));
    
    to->stream_id      = from->stream_id;
    to->http_status    = from->http_status;
    to->content_length = from->content_length;
    to->sos_filter     = from->sos_filter;
    if (from->headers) {
        to->headers    = apr_table_clone(pool, from->headers);
    }
    if (from->trailers) {
        to->trailers   = apr_table_clone(pool, from->trailers);
    }
    return to;
}

void h2_response_set_trailers(h2_response *response, apr_table_t *trailers)
{
    response->trailers = trailers;
}

