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

#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_mplx.h"
#include "h2_to_h1.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_util.h"


h2_request *h2_request_create(int id, apr_pool_t *pool, 
                              apr_bucket_alloc_t *bucket_alloc)
{
    h2_request *req = apr_pcalloc(pool, sizeof(h2_request));
    if (req) {
        req->id = id;
        req->pool = pool;
        req->bucket_alloc = bucket_alloc;
    }
    return req;
}

void h2_request_destroy(h2_request *req)
{
    if (req->to_h1) {
        h2_to_h1_destroy(req->to_h1);
        req->to_h1 = NULL;
    }
}

static apr_status_t insert_request_line(h2_request *req, h2_mplx *m);

apr_status_t h2_request_rwrite(h2_request *req, request_rec *r, h2_mplx *m)
{
    req->method = r->method;
    req->path = r->uri;
    req->authority = r->hostname;
    if (!strchr(req->authority, ':') && r->parsed_uri.port_str) {
        req->authority = apr_psprintf(req->pool, "%s:%s", req->authority,
                                      r->parsed_uri.port_str);
    }
    req->scheme = NULL;
    
    
    apr_status_t status = insert_request_line(req, m);
    if (status == APR_SUCCESS) {
        status = h2_to_h1_add_headers(req->to_h1, r->headers_in);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                  "h2_request(%d): written request %s %s, host=%s",
                  req->id, req->method, req->path, req->authority);
    
    return status;
}

apr_status_t h2_request_write_header(h2_request *req,
                                     const char *name, size_t nlen,
                                     const char *value, size_t vlen,
                                     h2_mplx *m)
{
    apr_status_t status = APR_SUCCESS;
    
    if (nlen <= 0) {
        return status;
    }
    
    if (name[0] == ':') {
        /* pseudo header, see ch. 8.1.2.3, always should come first */
        if (req->to_h1) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, req->pool,
                          "h2_request(%d): pseudo header after request start",
                          req->id);
            return APR_EGENERAL;
        }
        
        if (H2_HEADER_METHOD_LEN == nlen
            && !strncmp(H2_HEADER_METHOD, name, nlen)) {
            req->method = apr_pstrndup(req->pool, value, vlen);
        }
        else if (H2_HEADER_SCHEME_LEN == nlen
                 && !strncmp(H2_HEADER_SCHEME, name, nlen)) {
            req->scheme = apr_pstrndup(req->pool, value, vlen);
        }
        else if (H2_HEADER_PATH_LEN == nlen
                 && !strncmp(H2_HEADER_PATH, name, nlen)) {
            req->path = apr_pstrndup(req->pool, value, vlen);
        }
        else if (H2_HEADER_AUTH_LEN == nlen
                 && !strncmp(H2_HEADER_AUTH, name, nlen)) {
            req->authority = apr_pstrndup(req->pool, value, vlen);
        }
        else {
            char buffer[32];
            memset(buffer, 0, 32);
            strncpy(buffer, name, (nlen > 31)? 31 : nlen);
            ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, req->pool,
                          "h2_request(%d): ignoring unknown pseudo header %s",
                          req->id, buffer);
        }
    }
    else {
        /* non-pseudo header, append to work bucket of stream */
        if (!req->to_h1) {
            status = insert_request_line(req, m);
            if (status != APR_SUCCESS) {
                return status;
            }
        }
        
        if (status == APR_SUCCESS) {
            status = h2_to_h1_add_header(req->to_h1,
                                         name, nlen, value, vlen);
        }
    }
    
    return status;
}

apr_status_t h2_request_write_data(h2_request *req,
                                   const char *data, size_t len)
{
    return h2_to_h1_add_data(req->to_h1, data, len);
}

apr_status_t h2_request_end_headers(h2_request *req, struct h2_mplx *m,
                                    h2_task *task, int eos)
{
    if (!req->to_h1) {
        apr_status_t status = insert_request_line(req, m);
        if (status != APR_SUCCESS) {
            return status;
        }
    }
    return h2_to_h1_end_headers(req->to_h1, task, eos);
}

apr_status_t h2_request_close(h2_request *req)
{
    return h2_to_h1_close(req->to_h1);
}

static apr_status_t insert_request_line(h2_request *req, h2_mplx *m)
{
    req->to_h1 = h2_to_h1_create(req->id, req->pool, req->bucket_alloc, 
                                 req->method, req->path, req->authority, m);
    return req->to_h1? APR_SUCCESS : APR_ENOMEM;
}

apr_status_t h2_request_flush(h2_request *req)
{
    return h2_to_h1_flush(req->to_h1);
}

