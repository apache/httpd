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
 
#include <assert.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "md_http.h"
#include "md_log.h"

struct md_http_t {
    apr_pool_t *pool;
    apr_bucket_alloc_t *bucket_alloc;
    apr_off_t resp_limit;
    md_http_impl_t *impl;
    const char *user_agent;
    const char *proxy_url;
};

static md_http_impl_t *cur_impl;
static int cur_init_done;

void md_http_use_implementation(md_http_impl_t *impl)
{
    if (cur_impl != impl) {
        cur_impl = impl;
        cur_init_done = 0;
    }
}

static long next_req_id;

apr_status_t md_http_create(md_http_t **phttp, apr_pool_t *p, const char *user_agent,
                            const char *proxy_url)
{
    md_http_t *http;
    apr_status_t rv = APR_SUCCESS;

    if (!cur_impl) {
        *phttp = NULL;
        return APR_ENOTIMPL;
    }
    
    if (!cur_init_done) {
        if (APR_SUCCESS == (rv = cur_impl->init())) {
            cur_init_done = 1;
        }
        else {
            return rv;
        }
    }
    
    http = apr_pcalloc(p, sizeof(*http));
    http->pool = p;
    http->impl = cur_impl;
    http->user_agent = apr_pstrdup(p, user_agent);
    http->proxy_url = proxy_url? apr_pstrdup(p, proxy_url) : NULL;
    http->bucket_alloc = apr_bucket_alloc_create(p);
    if (!http->bucket_alloc) {
        return APR_EGENERAL;
    }
    *phttp = http;
    return APR_SUCCESS;
}

void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit)
{
    http->resp_limit = resp_limit;
}

static apr_status_t req_create(md_http_request_t **preq, md_http_t *http, 
                               const char *method, const char *url, struct apr_table_t *headers,
                               md_http_cb *cb, void *baton)
{
    md_http_request_t *req;
    apr_pool_t *pool;
    apr_status_t rv;
    
    rv = apr_pool_create(&pool, http->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    req = apr_pcalloc(pool, sizeof(*req));
    req->id = next_req_id++;
    req->pool = pool;
    req->bucket_alloc = http->bucket_alloc;
    req->http = http;
    req->method = method;
    req->url = url;
    req->headers = headers? apr_table_copy(req->pool, headers) : apr_table_make(req->pool, 5);
    req->resp_limit = http->resp_limit;
    req->cb = cb;
    req->baton = baton;
    req->user_agent = http->user_agent;
    req->proxy_url = http->proxy_url;

    *preq = req;
    return rv;
}

void md_http_req_destroy(md_http_request_t *req) 
{
    if (req->internals) {
        req->http->impl->req_cleanup(req);
        req->internals = NULL;
    }
    apr_pool_destroy(req->pool);
}

static apr_status_t schedule(md_http_request_t *req, 
                             apr_bucket_brigade *body, int detect_clen,
                             long *preq_id) 
{
    apr_status_t rv;
    
    req->body = body;
    req->body_len = body? -1 : 0;

    if (req->body && detect_clen) {
        rv = apr_brigade_length(req->body, 1, &req->body_len);
        if (rv != APR_SUCCESS) {
            md_http_req_destroy(req);
            return rv;
        }
    }
    
    if (req->body_len == 0 && apr_strnatcasecmp("GET", req->method)) {
        apr_table_setn(req->headers, "Content-Length", "0");
    }
    else if (req->body_len > 0) {
        apr_table_setn(req->headers, "Content-Length", apr_off_t_toa(req->pool, req->body_len));
    }
    
    if (preq_id) {
        *preq_id = req->id;
    }
    
    /* we send right away */
    rv = req->http->impl->perform(req);
    
    return rv;
}

apr_status_t md_http_GET(struct md_http_t *http, 
                         const char *url, struct apr_table_t *headers,
                         md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "GET", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    return schedule(req, NULL, 0, preq_id);
}

apr_status_t md_http_HEAD(struct md_http_t *http, 
                          const char *url, struct apr_table_t *headers,
                          md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "HEAD", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    return schedule(req, NULL, 0, preq_id);
}

apr_status_t md_http_POST(struct md_http_t *http, const char *url, 
                          struct apr_table_t *headers, const char *content_type, 
                          apr_bucket_brigade *body,
                          md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "POST", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    if (content_type) {
        apr_table_set(req->headers, "Content-Type", content_type); 
    }
    return schedule(req, body, 1, preq_id);
}

apr_status_t md_http_POSTd(md_http_t *http, const char *url, 
                           struct apr_table_t *headers, const char *content_type, 
                           const char *data, size_t data_len, 
                           md_http_cb *cb, void *baton, long *preq_id)
{
    md_http_request_t *req;
    apr_status_t rv;
    apr_bucket_brigade *body = NULL;
    
    rv = req_create(&req, http, "POST", url, headers, cb, baton);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (data && data_len > 0) {
        body = apr_brigade_create(req->pool, req->http->bucket_alloc);
        rv = apr_brigade_write(body, NULL, NULL, data, data_len);
        if (rv != APR_SUCCESS) {
            md_http_req_destroy(req);
            return rv;
        }
    }
    
    if (content_type) {
        apr_table_set(req->headers, "Content-Type", content_type); 
    }
     
    return schedule(req, body, 1, preq_id);
}

apr_status_t md_http_await(md_http_t *http, long req_id)
{
    (void)http;
    (void)req_id;
    return APR_SUCCESS;
}

