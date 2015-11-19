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

#include <nghttp2/nghttp2.h>

#include "h2_private.h"
#include "h2_h2.h"
#include "h2_util.h"
#include "h2_response.h"


h2_response *h2_response_create(int stream_id,
                                int rst_error,
                                int http_status,
                                apr_array_header_t *hlines,
                                apr_pool_t *pool)
{
    apr_table_t *header;
    h2_response *response = apr_pcalloc(pool, sizeof(h2_response));
    int i;
    if (response == NULL) {
        return NULL;
    }
    
    response->stream_id = stream_id;
    response->rst_error = rst_error;
    response->http_status = http_status? http_status : 500;
    response->content_length = -1;
    
    if (hlines) {
        header = apr_table_make(pool, hlines->nelts);        
        for (i = 0; i < hlines->nelts; ++i) {
            char *hline = ((char **)hlines->elts)[i];
            char *sep = ap_strchr(hline, ':');
            if (!sep) {
                ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, pool,
                              APLOGNO(02955) "h2_response(%d): invalid header[%d] '%s'",
                              response->stream_id, i, (char*)hline);
                /* not valid format, abort */
                return NULL;
            }
            (*sep++) = '\0';
            while (*sep == ' ' || *sep == '\t') {
                ++sep;
            }
            
            if (!h2_util_ignore_header(hline)) {
                apr_table_merge(header, hline, sep);
                if (*sep && H2_HD_MATCH_LIT_CS("content-length", hline)) {
                    char *end;
                    response->content_length = apr_strtoi64(sep, &end, 10);
                    if (sep == end) {
                        ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, 
                                      pool, APLOGNO(02956) 
                                      "h2_response(%d): content-length"
                                      " value not parsed: %s", 
                                      response->stream_id, sep);
                        response->content_length = -1;
                    }
                }
            }
        }
    }
    else {
        header = apr_table_make(pool, 0);        
    }

    response->header = header;
    return response;
}

h2_response *h2_response_rcreate(int stream_id, request_rec *r,
                                 apr_table_t *header, apr_pool_t *pool)
{
    h2_response *response = apr_pcalloc(pool, sizeof(h2_response));
    if (response == NULL) {
        return NULL;
    }
    
    response->stream_id = stream_id;
    response->http_status = r->status;
    response->content_length = -1;
    response->header = header;

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

void h2_response_destroy(h2_response *response)
{
    (void)response;
}

h2_response *h2_response_copy(apr_pool_t *pool, h2_response *from)
{
    h2_response *to = apr_pcalloc(pool, sizeof(h2_response));
    to->stream_id = from->stream_id;
    to->http_status = from->http_status;
    to->content_length = from->content_length;
    if (from->header) {
        to->header = apr_table_clone(pool, from->header);
    }
    return to;
}


