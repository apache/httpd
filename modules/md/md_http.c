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
#include "md_util.h"

struct md_http_t {
    apr_pool_t *pool;
    apr_bucket_alloc_t *bucket_alloc;
    int next_id;
    apr_off_t resp_limit;
    md_http_impl_t *impl;
    void *impl_data;         /* to be used by the implementation */
    const char *user_agent;
    const char *proxy_url;
    const char *unix_socket_path;
    md_http_timeouts_t timeout;
    const char *ca_file;
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

static apr_status_t http_cleanup(void *data)
{
    md_http_t *http = data;
    if (http && http->impl && http->impl->cleanup) {
        http->impl->cleanup(http, http->pool);
    }
    return APR_SUCCESS;
}

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
    apr_pool_cleanup_register(p, http, http_cleanup, apr_pool_cleanup_null);
    *phttp = http;
    return APR_SUCCESS;
}

apr_status_t md_http_clone(md_http_t **phttp,
                           apr_pool_t *p, md_http_t *source_http)
{
    apr_status_t rv;

    rv = md_http_create(phttp, p, source_http->user_agent, source_http->proxy_url);
    if (APR_SUCCESS == rv) {
        (*phttp)->resp_limit = source_http->resp_limit;
        (*phttp)->timeout = source_http->timeout;
        if (source_http->unix_socket_path) {
            (*phttp)->unix_socket_path = apr_pstrdup(p, source_http->unix_socket_path);
        }
        if (source_http->ca_file) {
            (*phttp)->ca_file = apr_pstrdup(p, source_http->ca_file);
        }
    }
    return rv;
}

void md_http_set_impl_data(md_http_t *http, void *data)
{
    http->impl_data = data;
}

void *md_http_get_impl_data(md_http_t *http)
{
    return http->impl_data;
}

void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit)
{
    http->resp_limit = resp_limit;
}

void md_http_set_timeout_default(md_http_t *http, apr_time_t timeout)
{
    http->timeout.overall = timeout;
}

void md_http_set_timeout(md_http_request_t *req, apr_time_t timeout)
{
    req->timeout.overall = timeout;
}

void md_http_set_connect_timeout_default(md_http_t *http, apr_time_t timeout)
{
    http->timeout.connect = timeout;
}

void md_http_set_connect_timeout(md_http_request_t *req, apr_time_t timeout)
{
    req->timeout.connect = timeout;
}

void md_http_set_stalling_default(md_http_t *http, long bytes_per_sec, apr_time_t timeout)
{
    http->timeout.stall_bytes_per_sec = bytes_per_sec;
    http->timeout.stalled = timeout;
}

void md_http_set_stalling(md_http_request_t *req, long bytes_per_sec, apr_time_t timeout)
{
    req->timeout.stall_bytes_per_sec = bytes_per_sec;
    req->timeout.stalled = timeout;
}

void md_http_set_ca_file(md_http_t *http, const char *ca_file)
{
    http->ca_file = ca_file;
}

void md_http_set_unix_socket_path(md_http_t *http, const char *path)
{
    http->unix_socket_path = path;
}

static apr_status_t req_set_body(md_http_request_t *req, const char *content_type,
                                 apr_bucket_brigade *body, apr_off_t body_len,
                                 int detect_len)
{
    apr_status_t rv = APR_SUCCESS;
    
    if (body && detect_len) {
        rv = apr_brigade_length(body, 1, &body_len);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    req->body = body;
    req->body_len = body? body_len : 0;
    if (content_type) {
        apr_table_set(req->headers, "Content-Type", content_type); 
    }
    else {
        apr_table_unset(req->headers, "Content-Type"); 
    }
    return rv;
}

static apr_status_t req_set_body_data(md_http_request_t *req, const char *content_type,
                                      const md_data_t *body)
{
    apr_bucket_brigade *bbody = NULL;
    apr_status_t rv;
    
    if (body && body->len > 0) {
        bbody = apr_brigade_create(req->pool, req->http->bucket_alloc);
        rv = apr_brigade_write(bbody, NULL, NULL, body->data, body->len);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    return req_set_body(req, content_type, bbody, body? (apr_off_t)body->len : 0, 0);
}

static apr_status_t req_create(md_http_request_t **preq, md_http_t *http, 
                               const char *method, const char *url, 
                               struct apr_table_t *headers)
{
    md_http_request_t *req;
    apr_pool_t *pool;
    apr_status_t rv;
    
    rv = apr_pool_create(&pool, http->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    apr_pool_tag(pool, "md_http_req");
    
    req = apr_pcalloc(pool, sizeof(*req));
    req->pool = pool;
    req->id = http->next_id++;
    req->bucket_alloc = http->bucket_alloc;
    req->http = http;
    req->method = method;
    req->url = url;
    req->headers = headers? apr_table_copy(req->pool, headers) : apr_table_make(req->pool, 5);
    req->resp_limit = http->resp_limit;
    req->user_agent = http->user_agent;
    req->proxy_url = http->proxy_url;
    req->timeout = http->timeout;
    req->ca_file = http->ca_file;
    req->unix_socket_path = http->unix_socket_path;
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

void md_http_set_on_status_cb(md_http_request_t *req, md_http_status_cb *cb, void *baton)
{
    req->cb.on_status = cb;
    req->cb.on_status_data = baton;
}

void md_http_set_on_response_cb(md_http_request_t *req, md_http_response_cb *cb, void *baton)
{
    req->cb.on_response = cb;
    req->cb.on_response_data = baton;
}

apr_status_t md_http_perform(md_http_request_t *req)
{
    return req->http->impl->perform(req);
}

typedef struct {
    md_http_next_req *nextreq;
    void *baton;
} nextreq_proxy_t;

static apr_status_t proxy_nextreq(md_http_request_t **preq, void *baton, 
                                      md_http_t *http, int in_flight)
{
    nextreq_proxy_t *proxy = baton;
    
    return proxy->nextreq(preq, proxy->baton, http, in_flight);
}

apr_status_t md_http_multi_perform(md_http_t *http, md_http_next_req *nextreq, void *baton)
{
    nextreq_proxy_t proxy;
    
    proxy.nextreq = nextreq;
    proxy.baton = baton;
    return http->impl->multi_perform(http, http->pool, proxy_nextreq, &proxy);
}

apr_status_t md_http_GET_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                struct apr_table_t *headers)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "GET", url, headers);
    *preq = (APR_SUCCESS == rv)? req : NULL;
    return rv;
}

apr_status_t md_http_HEAD_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                 struct apr_table_t *headers)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "HEAD", url, headers);
    *preq = (APR_SUCCESS == rv)? req : NULL;
    return rv;
}

apr_status_t md_http_POST_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                 struct apr_table_t *headers, const char *content_type, 
                                 struct apr_bucket_brigade *body, int detect_len)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "POST", url, headers);
    if (APR_SUCCESS == rv) {
        rv = req_set_body(req, content_type, body, -1, detect_len);
    }
    *preq = (APR_SUCCESS == rv)? req : NULL;
    return rv;
}

apr_status_t md_http_POSTd_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                  struct apr_table_t *headers, const char *content_type, 
                                  const struct md_data_t *body)
{
    md_http_request_t *req;
    apr_status_t rv;
    
    rv = req_create(&req, http, "POST", url, headers);
    if (APR_SUCCESS != rv) goto cleanup;
    rv = req_set_body_data(req, content_type, body);
cleanup:
    if (APR_SUCCESS == rv) {
        *preq = req;
    }
    else {
        *preq = NULL;
        if (req) md_http_req_destroy(req);
    }
    return rv;
}

apr_status_t md_http_GET_perform(struct md_http_t *http, 
                                 const char *url, struct apr_table_t *headers,
                                 md_http_response_cb *cb, void *baton)
{
    md_http_request_t *req;
    apr_status_t rv;

    rv = md_http_GET_create(&req, http, url, headers);
    if (APR_SUCCESS == rv) md_http_set_on_response_cb(req, cb, baton);
    return (APR_SUCCESS == rv)? md_http_perform(req) : rv;
}

apr_status_t md_http_HEAD_perform(struct md_http_t *http, 
                                  const char *url, struct apr_table_t *headers,
                                  md_http_response_cb *cb, void *baton)
{
    md_http_request_t *req;
    apr_status_t rv;

    rv = md_http_HEAD_create(&req, http, url, headers);
    if (APR_SUCCESS == rv) md_http_set_on_response_cb(req, cb, baton);
    return (APR_SUCCESS == rv)? md_http_perform(req) : rv;
}

apr_status_t md_http_POST_perform(struct md_http_t *http, const char *url, 
                                  struct apr_table_t *headers, const char *content_type, 
                                  apr_bucket_brigade *body, int detect_len, 
                                  md_http_response_cb *cb, void *baton)
{
    md_http_request_t *req;
    apr_status_t rv;

    rv = md_http_POST_create(&req, http, url, headers, content_type, body, detect_len);
    if (APR_SUCCESS == rv) md_http_set_on_response_cb(req, cb, baton);
    return (APR_SUCCESS == rv)? md_http_perform(req) : rv;
}

apr_status_t md_http_POSTd_perform(md_http_t *http, const char *url, 
                                   struct apr_table_t *headers, const char *content_type, 
                                   const md_data_t *body, 
                                   md_http_response_cb *cb, void *baton)
{
    md_http_request_t *req;
    apr_status_t rv;

    rv = md_http_POSTd_create(&req, http, url, headers, content_type, body);
    if (APR_SUCCESS == rv) md_http_set_on_response_cb(req, cb, baton);
    return (APR_SUCCESS == rv)? md_http_perform(req) : rv;
}
