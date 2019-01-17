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
#include "md_curl.h"

/**************************************************************************************************/
/* md_http curl implementation */


static apr_status_t curl_status(int curl_code)
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

static size_t req_data_cb(void *data, size_t len, size_t nmemb, void *baton)
{
    apr_bucket_brigade *body = baton;
    size_t blen, read_len = 0, max_len = len * nmemb;
    const char *bdata;
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
                memcpy(data, bdata, blen);
                read_len += blen;
                max_len -= blen;
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
    md_http_response_t *res = baton;
    size_t blen = len * nmemb;
    apr_status_t rv;
    
    if (res->body) {
        if (res->req->resp_limit) {
            apr_off_t body_len = 0;
            apr_brigade_length(res->body, 0, &body_len);
            if (body_len + (apr_off_t)len > res->req->resp_limit) {
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
    md_http_response_t *res = baton;
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

static apr_status_t curl_init(md_http_request_t *req)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        return APR_EGENERAL;
    }
    
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, NULL);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, req_data_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_data_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    
    req->internals = curl;
    return APR_SUCCESS;
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

static apr_status_t curl_perform(md_http_request_t *req)
{
    apr_status_t rv = APR_SUCCESS;
    CURLcode curle;
    md_http_response_t *res;
    CURL *curl;
    struct curl_slist *req_hdrs = NULL;

    rv = curl_init(req);
    curl = req->internals;
    
    res = apr_pcalloc(req->pool, sizeof(*res));
    
    res->req = req;
    res->rv = APR_SUCCESS;
    res->status = 400;
    res->headers = apr_table_make(req->pool, 5);
    res->body = apr_brigade_create(req->pool, req->bucket_alloc);
    
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
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, res);
    curl_easy_setopt(curl, CURLOPT_READDATA, req->body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, res);
    
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
        req_hdrs = ctx.hdrs;
        if (ctx.rv == APR_SUCCESS) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
        }
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, 
                  "request %ld --> %s %s", req->id, req->method, req->url);
    
    if (md_log_is_level(req->pool, MD_LOG_TRACE3)) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    
    curle = curl_easy_perform(curl);
    res->rv = curl_status(curle);
    
    if (APR_SUCCESS == res->rv) {
        long l;
        res->rv = curl_status(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &l));
        if (APR_SUCCESS == res->rv) {
            res->status = (int)l;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, res->rv, req->pool, 
                      "request %ld <-- %d", req->id, res->status);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, res->rv, req->pool, 
                      "request %ld failed(%d): %s", req->id, curle, 
                      curl_easy_strerror(curle));
    }
    
    if (req->cb) {
        res->rv = req->cb(res);
    }
    
    rv = res->rv;
    md_http_req_destroy(req);
    if (req_hdrs) {
        curl_slist_free_all(req_hdrs);
    }
    
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

static void curl_req_cleanup(md_http_request_t *req) 
{
    if (req->internals) {
        curl_easy_cleanup(req->internals);
        req->internals = NULL;
    }
}

static md_http_impl_t impl = {
    md_curl_init,
    curl_req_cleanup,
    curl_perform
};

md_http_impl_t * md_curl_get_impl(apr_pool_t *p)
{
    /* trigger early global curl init, before we are down a rabbit hole */
    (void)p;
    md_curl_init();
    return &impl;
}
