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

#include <curl/curl.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "md_http.h"
#include "md_log.h"
#include "md_util.h"
#include "md_curl.h"

/**************************************************************************************************/
/* md_http curl implementation */


static apr_status_t curl_status(unsigned int curl_code)
{
    switch (curl_code) {
        case CURLE_OK:                   return APR_SUCCESS;
        case CURLE_UNSUPPORTED_PROTOCOL: return APR_ENOTIMPL; 
        case CURLE_NOT_BUILT_IN:         return APR_ENOTIMPL; 
        case CURLE_URL_MALFORMAT:        return APR_EINVAL;
        case CURLE_COULDNT_RESOLVE_PROXY:return APR_ECONNREFUSED;
        case CURLE_COULDNT_RESOLVE_HOST: return APR_ECONNREFUSED;
        case CURLE_COULDNT_CONNECT:      return APR_ECONNREFUSED;
        case CURLE_REMOTE_ACCESS_DENIED: return APR_EACCES;
        case CURLE_OUT_OF_MEMORY:        return APR_ENOMEM;
        case CURLE_OPERATION_TIMEDOUT:   return APR_TIMEUP;
        case CURLE_SSL_CONNECT_ERROR:    return APR_ECONNABORTED;
        case CURLE_AGAIN:                return APR_EAGAIN;
        default:                         return APR_EGENERAL;
    }
}

typedef struct {
    CURL *curl;
    CURLM *curlm;
    struct curl_slist *req_hdrs;
    md_http_response_t *response;
    apr_status_t rv;
    int status_fired;
} md_curl_internals_t;

static size_t req_data_cb(void *data, size_t len, size_t nmemb, void *baton)
{
    apr_bucket_brigade *body = baton;
    size_t blen, read_len = 0, max_len = len * nmemb;
    const char *bdata;
    char *rdata = data;
    apr_bucket *b;
    apr_status_t rv;
    
    while (body && !APR_BRIGADE_EMPTY(body) && max_len > 0) {
        b = APR_BRIGADE_FIRST(body);
        if (APR_BUCKET_IS_METADATA(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                body = NULL;
            }
        }
        else {
            rv = apr_bucket_read(b, &bdata, &blen, APR_BLOCK_READ);
            if (rv == APR_SUCCESS) {
                if (blen > max_len) {
                    apr_bucket_split(b, max_len);
                    blen = max_len;
                }
                memcpy(rdata, bdata, blen);
                read_len += blen;
                max_len -= blen;
                rdata += blen;
            }
            else {
                body = NULL;
                if (!APR_STATUS_IS_EOF(rv)) {
                    /* everything beside EOF is an error */
                    read_len = CURL_READFUNC_ABORT;
                }
            }
            
        }
        apr_bucket_delete(b);
    }
    
    return read_len;
}

static size_t resp_data_cb(void *data, size_t len, size_t nmemb, void *baton)
{
    md_curl_internals_t *internals = baton;
    md_http_response_t *res = internals->response;
    size_t blen = len * nmemb;
    apr_status_t rv;
    
    if (res->body) {
        if (res->req->resp_limit) {
            apr_off_t body_len = 0;
            apr_brigade_length(res->body, 0, &body_len);
            if (body_len + (apr_off_t)blen > res->req->resp_limit) {
                return 0; /* signal curl failure */
            }
        }
        rv = apr_brigade_write(res->body, NULL, NULL, (const char *)data, blen);
        if (rv != APR_SUCCESS) {
            /* returning anything != blen will make CURL fail this */
            return 0;
        }
    }
    return blen;
}

static size_t header_cb(void *buffer, size_t elen, size_t nmemb, void *baton)
{
    md_curl_internals_t *internals = baton;
    md_http_response_t *res = internals->response;
    size_t len, clen = elen * nmemb;
    const char *name = NULL, *value = "", *b = buffer;
    apr_size_t i;
    
    len = (clen && b[clen-1] == '\n')? clen-1 : clen;
    len = (len && b[len-1] == '\r')? len-1 : len;
    for (i = 0; i < len; ++i) {
        if (b[i] == ':') {
            name = apr_pstrndup(res->req->pool, b, i);
            ++i;
            while (i < len && b[i] == ' ') {
                ++i;
            }
            if (i < len) {
                value = apr_pstrndup(res->req->pool, b+i, len - i);
            }
            break;
        }
    }
    
    if (name != NULL) {
        apr_table_add(res->headers, name, value);
    }
    return clen;
}

typedef struct {
    md_http_request_t *req;
    struct curl_slist *hdrs;
    apr_status_t rv;
} curlify_hdrs_ctx;

static int curlify_headers(void *baton, const char *key, const char *value)
{
    curlify_hdrs_ctx *ctx = baton;
    const char *s;
    
    if (strchr(key, '\r') || strchr(key, '\n')
        || strchr(value, '\r') || strchr(value, '\n')) {
        ctx->rv = APR_EINVAL;
        return 0;
    }
    s = apr_psprintf(ctx->req->pool, "%s: %s", key, value);
    ctx->hdrs = curl_slist_append(ctx->hdrs, s);
    return 1;
}

/* Convert timeout values for curl. Since curl uses 0 to disable
 * timeout, return at least 1 if the apr_time_t value is non-zero. */
static long timeout_msec(apr_time_t timeout)
{
    long ms = (long)apr_time_as_msec(timeout);
    return ms? ms : (timeout? 1 : 0);
}

static long timeout_sec(apr_time_t timeout)
{
    long s = (long)apr_time_sec(timeout);
    return s? s : (timeout? 1 : 0);
}

static int curl_debug_log(CURL *curl, curl_infotype type, char *data, size_t size, void *baton)
{
    md_http_request_t *req = baton;
    
    (void)curl;
    switch (type) {
        case CURLINFO_TEXT:
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, req->pool, 
                          "req[%d]: info %s", req->id, apr_pstrndup(req->pool, data, size));
            break;
        case CURLINFO_HEADER_OUT:
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, req->pool, 
                          "req[%d]: header --> %s", req->id, apr_pstrndup(req->pool, data, size));
            break;
        case CURLINFO_HEADER_IN:
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, req->pool, 
                          "req[%d]: header <-- %s", req->id, apr_pstrndup(req->pool, data, size));
            break;
        case CURLINFO_DATA_OUT:
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, req->pool, 
                          "req[%d]: data --> %ld bytes", req->id, (long)size);
            if (md_log_is_level(req->pool, MD_LOG_TRACE5)) {
                md_data_t d;
                const char *s;
                md_data_init(&d, data, size);
                md_data_to_hex(&s, 0, req->pool, &d);
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE5, 0, req->pool, 
                              "req[%d]: data(hex) -->  %s", req->id, s);
            }
            break;
        case CURLINFO_DATA_IN:
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, req->pool, 
                          "req[%d]: data <-- %ld bytes", req->id, (long)size);
            if (md_log_is_level(req->pool, MD_LOG_TRACE5)) {
                md_data_t d;
                const char *s;
                md_data_init(&d, data, size);
                md_data_to_hex(&s, 0, req->pool, &d);
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE5, 0, req->pool, 
                              "req[%d]: data(hex) <-- %s", req->id, s);
            }
            break;
        default:
            break;
    }
    return 0;
}

static apr_status_t internals_setup(md_http_request_t *req)
{
    md_curl_internals_t *internals;
    CURL *curl;
    apr_status_t rv = APR_SUCCESS;

    curl = md_http_get_impl_data(req->http);
    if (!curl) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool, "creating curl instance");
        curl = curl_easy_init();
        if (!curl) {
            rv = APR_EGENERAL;
            goto leave;
        }
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, req_data_cb);
        curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_data_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool, "reusing curl instance from http");
    }

    internals = apr_pcalloc(req->pool, sizeof(*internals));
    internals->curl = curl;
        
    internals->response = apr_pcalloc(req->pool, sizeof(md_http_response_t));
    internals->response->req = req;
    internals->response->status = 400;
    internals->response->headers = apr_table_make(req->pool, 5);
    internals->response->body = apr_brigade_create(req->pool, req->bucket_alloc);
    
    curl_easy_setopt(curl, CURLOPT_URL, req->url);
    if (!apr_strnatcasecmp("GET", req->method)) {
        /* nop */
    }
    else if (!apr_strnatcasecmp("HEAD", req->method)) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }
    else if (!apr_strnatcasecmp("POST", req->method)) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }
    else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req->method);
    }
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, internals);
    curl_easy_setopt(curl, CURLOPT_READDATA, req->body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, internals);
    
    if (req->timeout.overall > 0) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_msec(req->timeout.overall));
    }
    if (req->timeout.connect > 0) {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_msec(req->timeout.connect));
    }
    if (req->timeout.stalled > 0) {
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, req->timeout.stall_bytes_per_sec);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, timeout_sec(req->timeout.stalled));
    }
    if (req->ca_file) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, req->ca_file);
    }
    if (req->unix_socket_path) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, req->unix_socket_path);
    }

    if (req->body_len >= 0) {
        /* set the Content-Length */
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)req->body_len);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)req->body_len);
    }
    
    if (req->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, req->user_agent);
    }
    if (req->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, req->proxy_url);
    }
    if (!apr_is_empty_table(req->headers)) {
        curlify_hdrs_ctx ctx;
        
        ctx.req = req;
        ctx.hdrs = NULL;
        ctx.rv = APR_SUCCESS;
        apr_table_do(curlify_headers, &ctx, req->headers, NULL);
        internals->req_hdrs = ctx.hdrs;
        if (ctx.rv == APR_SUCCESS) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, internals->req_hdrs);
        }
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool, 
                  "req[%d]: %s %s", req->id, req->method, req->url);
    
    if (md_log_is_level(req->pool, MD_LOG_TRACE4)) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_log);
        curl_easy_setopt(curl, CURLOPT_DEBUGDATA, req);
    }
    
leave:
    req->internals = (APR_SUCCESS == rv)? internals : NULL;
    return rv;
}

static apr_status_t update_status(md_http_request_t *req)
{
    md_curl_internals_t *internals = req->internals;
    long l;
    apr_status_t rv = APR_SUCCESS;

    if (internals) {
        rv = curl_status(curl_easy_getinfo(internals->curl, CURLINFO_RESPONSE_CODE, &l));
        if (APR_SUCCESS == rv) {
            internals->response->status = (int)l;
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, req->pool,
                          "req[%d]: http status is %d",
                          req->id, internals->response->status);
        }
    }
    return rv;
}

static void fire_status(md_http_request_t *req, apr_status_t rv)
{
    md_curl_internals_t *internals = req->internals;
        
    if (internals && !internals->status_fired) {
        internals->status_fired = 1;
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, req->pool, 
                      "req[%d] fire callbacks", req->id);
        if ((APR_SUCCESS == rv) && req->cb.on_response) {
            rv = req->cb.on_response(internals->response, req->cb.on_response_data);
        }
    
        internals->rv = rv;
        if (req->cb.on_status) {
            req->cb.on_status(req, rv, req->cb.on_status_data);
        }
    }
}

static apr_status_t md_curl_perform(md_http_request_t *req)
{
    apr_status_t rv = APR_SUCCESS;
    CURLcode curle;
    md_curl_internals_t *internals;
    long l;

    if (APR_SUCCESS != (rv = internals_setup(req))) goto leave;
    internals = req->internals;
    
    curle = curl_easy_perform(internals->curl);
    
    rv = curl_status(curle);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->pool, 
                      "request failed(%d): %s", curle, curl_easy_strerror(curle));
        goto leave;
    }
    
    rv = curl_status(curl_easy_getinfo(internals->curl, CURLINFO_RESPONSE_CODE, &l));
    if (APR_SUCCESS == rv) {
        internals->response->status = (int)l;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, req->pool, "request <-- %d", 
                  internals->response->status);
    
    if (req->cb.on_response) {
        rv = req->cb.on_response(internals->response, req->cb.on_response_data);
        req->cb.on_response = NULL;
    }
    
leave:
    fire_status(req, rv);
    md_http_req_destroy(req);
    return rv;
}

static md_http_request_t *find_curl_request(apr_array_header_t *requests, CURL *curl)
{
    md_http_request_t *req;
    md_curl_internals_t *internals;
    int i;
    
    for (i = 0; i < requests->nelts; ++i) {
        req = APR_ARRAY_IDX(requests, i, md_http_request_t*);
        internals = req->internals;
        if (internals && internals->curl == curl) {
            return req;
        }
    }
    return NULL;
}

static void add_to_curlm(md_http_request_t *req, CURLM *curlm)
{
    md_curl_internals_t *internals = req->internals;
    
    assert(curlm);
    assert(internals);
    if (internals->curlm == NULL) {
        internals->curlm = curlm;
    }
    assert(internals->curlm == curlm);
    curl_multi_add_handle(curlm, internals->curl);
}

static void remove_from_curlm_and_destroy(md_http_request_t *req, CURLM *curlm)
{
    md_curl_internals_t *internals = req->internals;

    assert(curlm);
    assert(internals);
    assert(internals->curlm == curlm);
    curl_multi_remove_handle(curlm, internals->curl);
    internals->curlm = NULL;
    md_http_req_destroy(req);
}
    
static apr_status_t md_curl_multi_perform(md_http_t *http, apr_pool_t *p,
                                          md_http_next_req *nextreq, void *baton)
{
    md_http_t *sub_http;
    md_http_request_t *req;
    CURLM *curlm = NULL;
    CURLMcode mc;
    struct CURLMsg *curlmsg;
    apr_array_header_t *http_spares;
    apr_array_header_t *requests;
    int i, running, numfds, slowdown, msgcount;
    apr_status_t rv;
    
    http_spares = apr_array_make(p, 10, sizeof(md_http_t*));
    requests = apr_array_make(p, 10, sizeof(md_http_request_t*));
    curlm = curl_multi_init();
    if (!curlm) {
        rv = APR_ENOMEM;
        goto leave;
    }
    
    running = 1;
    slowdown = 0;
    while(1) {
        while (1) {
            /* fetch as many requests as nextreq gives us */
            if (http_spares->nelts > 0) {
                sub_http = *(md_http_t **)(apr_array_pop(http_spares));
            }
            else {
                rv = md_http_clone(&sub_http, p, http);
                if (APR_SUCCESS != rv) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p,
                                  "multi_perform[%d reqs]: setup failed", requests->nelts);
                    goto leave;
                }
            }

            rv = nextreq(&req, baton, sub_http, requests->nelts);
            if (APR_STATUS_IS_ENOENT(rv)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p,
                              "multi_perform[%d reqs]: no more requests", requests->nelts);
                if (!requests->nelts) {
                    goto leave;
                }
                break;
            }
            else if (APR_SUCCESS != rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p,
                              "multi_perform[%d reqs]: nextreq() failed", requests->nelts);
                APR_ARRAY_PUSH(http_spares, md_http_t*) = sub_http;
                goto leave;
            }

            if (APR_SUCCESS != (rv = internals_setup(req))) {
                if (req->cb.on_status) req->cb.on_status(req, rv, req->cb.on_status_data);
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p,
                              "multi_perform[%d reqs]: setup failed", requests->nelts);
                APR_ARRAY_PUSH(http_spares, md_http_t*) = sub_http;
                goto leave;
            }

            APR_ARRAY_PUSH(requests, md_http_request_t*) = req;
            add_to_curlm(req, curlm);
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p,
                          "multi_perform[%d reqs]: added request", requests->nelts);
        }
    
        mc = curl_multi_perform(curlm, &running);
        if (CURLM_OK == mc) {
            mc = curl_multi_wait(curlm, NULL, 0, 1000, &numfds);
            if (numfds) slowdown = 0;
        }
        if (CURLM_OK != mc) {
            rv = APR_ECONNABORTED;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                          "multi_perform[%d reqs] failed(%d): %s", 
                          requests->nelts, mc, curl_multi_strerror(mc));
            goto leave;
        }
        if (!numfds) {
            /* no activity on any connection, timeout */
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, 
                          "multi_perform[%d reqs]: slowdown %d", requests->nelts, slowdown);
            if (slowdown) apr_sleep(apr_time_from_msec(100));
            ++slowdown;
        }

        /* process status messages, e.g. that a request is done */
        while (running < requests->nelts) {
            curlmsg = curl_multi_info_read(curlm, &msgcount);
            if (!curlmsg) break;
            if (curlmsg->msg == CURLMSG_DONE) {
                req = find_curl_request(requests, curlmsg->easy_handle);
                if (req) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p,
                                  "multi_perform[%d reqs]: req[%d] done", 
                                  requests->nelts, req->id);
                    update_status(req);
                    fire_status(req, curl_status(curlmsg->data.result));
                    md_array_remove(requests, req);
                    sub_http = req->http;
                    APR_ARRAY_PUSH(http_spares, md_http_t*) = sub_http;
                    remove_from_curlm_and_destroy(req, curlm);
                }
                else {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                                  "multi_perform[%d reqs]: req done, but not found by handle", 
                                  requests->nelts);
                }
            }
        }
    };

leave:
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, 
                  "multi_perform[%d reqs]: leaving", requests->nelts);
    for (i = 0; i < requests->nelts; ++i) {
        req = APR_ARRAY_IDX(requests, i, md_http_request_t*);
        fire_status(req, APR_SUCCESS);
        sub_http = req->http;
        APR_ARRAY_PUSH(http_spares, md_http_t*) = sub_http;
        remove_from_curlm_and_destroy(req, curlm);
    }
    if (curlm) curl_multi_cleanup(curlm);
    return rv;
}

static int initialized;

static apr_status_t md_curl_init(void) {
    if (!initialized) {
        initialized = 1;
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    return APR_SUCCESS;
}

static void md_curl_req_cleanup(md_http_request_t *req) 
{
    md_curl_internals_t *internals = req->internals;
    if (internals) {
        if (internals->curl) {
            CURL *curl = md_http_get_impl_data(req->http);
            if (curl == internals->curl) {
                /* NOP: we have this curl at the md_http_t already */
            }
            else if (!curl) {
                /* no curl at the md_http_t yet, install this one */
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->pool, "register curl instance at http");
                md_http_set_impl_data(req->http, internals->curl);
            }
            else {
                /* There already is a curl at the md_http_t and it's not this one. */
                curl_easy_cleanup(internals->curl);
            }
        }
        if (internals->req_hdrs) curl_slist_free_all(internals->req_hdrs);
        req->internals = NULL;
    }
}

static void md_curl_cleanup(md_http_t *http, apr_pool_t *pool)
{
    CURL *curl;

    curl = md_http_get_impl_data(http);
    if (curl) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, pool, "cleanup curl instance");
        md_http_set_impl_data(http, NULL);
        curl_easy_cleanup(curl);
    }
}

static md_http_impl_t impl = {
    md_curl_init,
    md_curl_req_cleanup,
    md_curl_perform,
    md_curl_multi_perform,
    md_curl_cleanup,
};

md_http_impl_t * md_curl_get_impl(apr_pool_t *p)
{
    /* trigger early global curl init, before we are down a rabbit hole */
    (void)p;
    md_curl_init();
    return &impl;
}
