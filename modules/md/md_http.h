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

#ifndef mod_md_md_http_h
#define mod_md_md_http_h

struct apr_table_t;
struct apr_bucket_brigade;
struct apr_bucket_alloc_t;
struct md_data_t;

typedef struct md_http_t md_http_t;

typedef struct md_http_request_t md_http_request_t;
typedef struct md_http_response_t md_http_response_t;

/**
 * Callback invoked once per request, either when an error was encountered
 * or when everything succeeded and the request is about to be released. Only
 * in the last case will the status be APR_SUCCESS.
 */
typedef apr_status_t md_http_status_cb(const md_http_request_t *req, apr_status_t status, void *data);

/**
 * Callback invoked when the complete response has been received.
 */
typedef apr_status_t md_http_response_cb(const md_http_response_t *res, void *data);

typedef struct md_http_callbacks_t md_http_callbacks_t;
struct md_http_callbacks_t {
    md_http_status_cb *on_status;
    void *on_status_data;
    md_http_response_cb *on_response;
    void *on_response_data;
};

typedef struct md_http_timeouts_t md_http_timeouts_t;
struct md_http_timeouts_t {
    apr_time_t overall;
    apr_time_t connect;
    long stall_bytes_per_sec;
    apr_time_t stalled;
};

struct md_http_request_t {
    md_http_t *http;
    apr_pool_t *pool;
    int id;
    struct apr_bucket_alloc_t *bucket_alloc;
    const char *method;
    const char *url;
    const char *user_agent;
    const char *proxy_url;
    const char *ca_file;
    const char *unix_socket_path;
    apr_table_t *headers;
    struct apr_bucket_brigade *body;
    apr_off_t body_len;
    apr_off_t resp_limit;
    md_http_timeouts_t timeout;
    md_http_callbacks_t cb;
    void *internals;
};

struct md_http_response_t {
    md_http_request_t *req;
    int status;
    apr_table_t *headers;
    struct apr_bucket_brigade *body;
};

apr_status_t md_http_create(md_http_t **phttp, apr_pool_t *p, const char *user_agent,
                            const char *proxy_url);

void md_http_set_response_limit(md_http_t *http, apr_off_t resp_limit);

/**
 * Clone a http instance, inheriting all settings from source_http.
 * The cloned instance is not tied in any way to the source.
 */
apr_status_t md_http_clone(md_http_t **phttp,
                           apr_pool_t *p, md_http_t *source_http);

/**
 * Set the timeout for the complete request. This needs to take everything from
 * DNS looksups, to conntects, to transfer of all data into account and should
 * be sufficiently large.
 * Set to 0 the have no timeout for this.
 */
void md_http_set_timeout_default(md_http_t *http, apr_time_t timeout);
void md_http_set_timeout(md_http_request_t *req, apr_time_t timeout);

/**
 * Set the timeout for establishing a connection. 
 * Set to 0 the have no special timeout for this.
 */
void md_http_set_connect_timeout_default(md_http_t *http, apr_time_t timeout);
void md_http_set_connect_timeout(md_http_request_t *req, apr_time_t timeout);

/**
 * Set the condition for when a transfer is considered "stalled", e.g. does not
 * progress at a sufficient rate and will be aborted.
 * Set to 0 the have no stall detection in place.
 */
void md_http_set_stalling_default(md_http_t *http, long bytes_per_sec, apr_time_t timeout);
void md_http_set_stalling(md_http_request_t *req, long bytes_per_sec, apr_time_t timeout);

/**
 * Set a CA file (in PERM format) to use for root certificates when
 * verifying SSL connections. If not set (or set to NULL), the systems
 * certificate store will be used.
 */
void md_http_set_ca_file(md_http_t *http, const char *ca_file);

/**
 * Set the path of a unix domain socket for use instead of TCP
 * in a connection. Disable by providing NULL as path.
 */
void md_http_set_unix_socket_path(md_http_t *http, const char *path);

/**
 * Perform the request. Then this function returns, the request and
 * all its memory has been freed and must no longer be used.
 */
apr_status_t md_http_perform(md_http_request_t *request);

/**
 * Set the callback to be invoked once the status of a request is known.
 * @param req       the request
 * @param cb        the callback to invoke on the response
 * @param baton     data passed to the callback    
 */
void md_http_set_on_status_cb(md_http_request_t *req, md_http_status_cb *cb, void *baton);

/**
 * Set the callback to be invoked when the complete 
 * response has been successfully received. The HTTP status may
 * be 500, however.
 * @param req       the request
 * @param cb        the callback to invoke on the response
 * @param baton     data passed to the callback    
 */
void md_http_set_on_response_cb(md_http_request_t *req, md_http_response_cb *cb, void *baton);

/**
 * Create a GET request.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 */
apr_status_t md_http_GET_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                struct apr_table_t *headers);

/**
 * Create a HEAD request.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 */
apr_status_t md_http_HEAD_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                 struct apr_table_t *headers);

/**
 * Create a POST request with a bucket brigade as request body.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 * @param content_type the content_type of the body or NULL
 * @param body      the body of the request or NULL
 * @param detect_len scan the body to detect its length
 */
apr_status_t md_http_POST_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                 struct apr_table_t *headers, const char *content_type, 
                                 struct apr_bucket_brigade *body, int detect_len);

/**
 * Create a POST request with known request body data.
 * @param preq      the created request after success
 * @param http      the md_http instance 
 * @param url       the url to GET
 * @param headers   request headers
 * @param content_type the content_type of the body or NULL
 * @param body      the body of the request or NULL
 */
apr_status_t md_http_POSTd_create(md_http_request_t **preq, md_http_t *http, const char *url, 
                                  struct apr_table_t *headers, const char *content_type, 
                                  const struct md_data_t *body);

/*
 * Convenience functions for create+perform.
 */
apr_status_t md_http_GET_perform(md_http_t *http, const char *url, 
                                 struct apr_table_t *headers,
                                 md_http_response_cb *cb, void *baton);
apr_status_t md_http_HEAD_perform(md_http_t *http, const char *url, 
                                  struct apr_table_t *headers,
                                  md_http_response_cb *cb, void *baton);
apr_status_t md_http_POST_perform(md_http_t *http, const char *url, 
                                  struct apr_table_t *headers, const char *content_type, 
                                  struct apr_bucket_brigade *body, int detect_len, 
                                  md_http_response_cb *cb, void *baton);
apr_status_t md_http_POSTd_perform(md_http_t *http, const char *url, 
                                   struct apr_table_t *headers, const char *content_type, 
                                   const struct md_data_t *body, 
                                   md_http_response_cb *cb, void *baton);

void md_http_req_destroy(md_http_request_t *req);

/** Return the next request for processing on APR_SUCCESS. Return ARP_ENOENT
 * when no request is available. Anything else is an error.
 */
typedef apr_status_t md_http_next_req(md_http_request_t **preq, void *baton, 
                                      md_http_t *http, int in_flight);

/**
 * Perform requests in parallel as retrieved from the nextreq function.
 * There are as many requests in flight as the nextreq functions provides. 
 *
 * To limit the number of parallel requests, nextreq should return APR_ENOENT when the limit
 * is reached. It will be called again when the number of in_flight requests changes.
 * 
 * When all requests are done, nextreq will be called one more time. Should it not
 * return anything, this function returns.
 */
apr_status_t md_http_multi_perform(md_http_t *http, md_http_next_req *nextreq, void *baton);

/**************************************************************************************************/
/* interface to implementation */

typedef apr_status_t md_http_init_cb(void);
typedef void md_http_cleanup_cb(md_http_t *req, apr_pool_t *p);
typedef void md_http_req_cleanup_cb(md_http_request_t *req);
typedef apr_status_t md_http_perform_cb(md_http_request_t *req);
typedef apr_status_t md_http_multi_perform_cb(md_http_t *http, apr_pool_t *p, 
                                              md_http_next_req *nextreq, void *baton);

typedef struct md_http_impl_t md_http_impl_t;
struct md_http_impl_t {
    md_http_init_cb *init;
    md_http_req_cleanup_cb *req_cleanup;
    md_http_perform_cb *perform;
    md_http_multi_perform_cb *multi_perform;
    md_http_cleanup_cb *cleanup;
};

void md_http_use_implementation(md_http_impl_t *impl);

/**
 * get/set data the implementation wants to remember between requests
 * in the same md_http_t instance.
 */
void md_http_set_impl_data(md_http_t *http, void *data);
void *md_http_get_impl_data(md_http_t *http);


#endif /* md_http_h */
