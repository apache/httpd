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

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_strmatch.h"

#include <ap_mmn.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_ssl.h>
#include <http_vhost.h>
#include <util_filter.h>
#include <ap_mpm.h>
#include <mod_core.h>
#include <scoreboard.h>

#include "h2_private.h"
#include "h2_config.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_util.h"


h2_request *h2_request_create(int id, apr_pool_t *pool, const char *method,
                              const char *scheme, const char *authority,
                              const char *path, apr_table_t *header)
{
    h2_request *req = apr_pcalloc(pool, sizeof(h2_request));

    req->method         = method;
    req->scheme         = scheme;
    req->authority      = authority;
    req->path           = path;
    req->headers        = header? header : apr_table_make(pool, 10);
    req->request_time   = apr_time_now();

    return req;
}

typedef struct {
    apr_table_t *headers;
    apr_pool_t *pool;
    apr_status_t status;
} h1_ctx;

static int set_h1_header(void *ctx, const char *key, const char *value)
{
    h1_ctx *x = ctx;
    int was_added;
    h2_req_add_header(x->headers, x->pool, key, strlen(key), value, strlen(value), 0, &was_added);
    return 1;
}

apr_status_t h2_request_rcreate(h2_request **preq, apr_pool_t *pool, 
                                request_rec *r)
{
    h2_request *req;
    const char *scheme, *authority, *path;
    h1_ctx x;
    
    *preq = NULL;
    scheme = apr_pstrdup(pool, r->parsed_uri.scheme? r->parsed_uri.scheme
              : ap_http_scheme(r));
    authority = apr_pstrdup(pool, r->hostname);
    path = apr_uri_unparse(pool, &r->parsed_uri, APR_URI_UNP_OMITSITEPART);
    
    if (!r->method || !scheme || !r->hostname || !path) {
        return APR_EINVAL;
    }

    if (!ap_strchr_c(authority, ':') && r->server && r->server->port) {
        apr_port_t defport = apr_uri_port_of_scheme(scheme);
        if (defport != r->server->port) {
            /* port info missing and port is not default for scheme: append */
            authority = apr_psprintf(pool, "%s:%d", authority,
                                     (int)r->server->port);
        }
    }
    
    req = apr_pcalloc(pool, sizeof(*req));
    req->method      = apr_pstrdup(pool, r->method);
    req->scheme      = scheme;
    req->authority   = authority;
    req->path        = path;
    req->headers     = apr_table_make(pool, 10);
    req->http_status = H2_HTTP_STATUS_UNSET;

    x.pool = pool;
    x.headers = req->headers;
    x.status = APR_SUCCESS;
    apr_table_do(set_h1_header, &x, r->headers_in, NULL);
    
    *preq = req;
    return x.status;
}

apr_status_t h2_request_add_header(h2_request *req, apr_pool_t *pool, 
                                   const char *name, size_t nlen,
                                   const char *value, size_t vlen,
                                   size_t max_field_len, int *pwas_added)
{
    apr_status_t status = APR_SUCCESS;
    
    *pwas_added = 0;
    if (nlen <= 0) {
        return status;
    }
    
    if (name[0] == ':') {
        /* pseudo header, see ch. 8.1.2.3, always should come first */
        if (!apr_is_empty_table(req->headers)) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                          APLOGNO(02917) 
                          "h2_request: pseudo header after request start");
            return APR_EGENERAL;
        }
        
        if (H2_HEADER_METHOD_LEN == nlen
            && !strncmp(H2_HEADER_METHOD, name, nlen)) {
            req->method = apr_pstrndup(pool, value, vlen);
        }
        else if (H2_HEADER_SCHEME_LEN == nlen
                 && !strncmp(H2_HEADER_SCHEME, name, nlen)) {
            req->scheme = apr_pstrndup(pool, value, vlen);
        }
        else if (H2_HEADER_PATH_LEN == nlen
                 && !strncmp(H2_HEADER_PATH, name, nlen)) {
            req->path = apr_pstrndup(pool, value, vlen);
        }
        else if (H2_HEADER_AUTH_LEN == nlen
                 && !strncmp(H2_HEADER_AUTH, name, nlen)) {
            req->authority = apr_pstrndup(pool, value, vlen);
        }
        else {
            char buffer[32];
            memset(buffer, 0, 32);
            strncpy(buffer, name, (nlen > 31)? 31 : nlen);
            ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, pool,
                          APLOGNO(02954) 
                          "h2_request: ignoring unknown pseudo header %s",
                          buffer);
        }
    }
    else {
        /* non-pseudo header, add to table */
        status = h2_req_add_header(req->headers, pool, name, nlen, value, vlen, 
                                   max_field_len, pwas_added);
    }
    
    return status;
}

apr_status_t h2_request_end_headers(h2_request *req, apr_pool_t *pool, int eos, size_t raw_bytes)
{
    const char *s;

    /* rfc7540, ch. 8.1.2.3:
     * - if we have :authority, it overrides any Host header 
     * - :authority MUST be omitted when converting h1->h2, so we
     *   might get a stream without, but then Host needs to be there */
    if (!req->authority) {
        const char *host = apr_table_get(req->headers, "Host");
        if (!host) {
            return APR_BADARG;
        }
        req->authority = host;
    }
    else {
        apr_table_setn(req->headers, "Host", req->authority);
    }

    s = apr_table_get(req->headers, "Content-Length");
    if (!s) {
        /* HTTP/2 does not need a Content-Length for framing, but our
         * internal request processing is used to HTTP/1.1, so we
         * need to either add a Content-Length or a Transfer-Encoding
         * if any content can be expected. */
        if (!eos) {
            /* We have not seen a content-length and have no eos,
             * simulate a chunked encoding for our HTTP/1.1 infrastructure,
             * in case we have "H2SerializeHeaders on" here
             */
            req->chunked = 1;
            apr_table_mergen(req->headers, "Transfer-Encoding", "chunked");
        }
        else if (apr_table_get(req->headers, "Content-Type")) {
            /* If we have a content-type, but already seen eos, no more
             * data will come. Signal a zero content length explicitly.
             */
            apr_table_setn(req->headers, "Content-Length", "0");
        }
    }
    req->raw_bytes += raw_bytes;

    return APR_SUCCESS;
}

h2_request *h2_request_clone(apr_pool_t *p, const h2_request *src)
{
    h2_request *dst = apr_pmemdup(p, src, sizeof(*dst));
    dst->method       = apr_pstrdup(p, src->method);
    dst->scheme       = apr_pstrdup(p, src->scheme);
    dst->authority    = apr_pstrdup(p, src->authority);
    dst->path         = apr_pstrdup(p, src->path);
    dst->headers      = apr_table_clone(p, src->headers);
    return dst;
}

#if !AP_MODULE_MAGIC_AT_LEAST(20120211, 106)
static request_rec *my_ap_create_request(conn_rec *c)
{
    apr_pool_t *p;
    request_rec *r;

    apr_pool_create(&p, c->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)c);
    r->pool            = p;
    r->connection      = c;
    r->server          = c->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 5);
    r->trailers_in     = apr_table_make(r->pool, 5);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */

    r->proto_output_filters = c->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = c->input_filters;
    r->input_filters   = r->proto_input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  /* Until further notice */
    r->header_only     = 0;
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    r->useragent_addr = c->client_addr;
    r->useragent_ip = c->client_ip;
    return r;
}
#endif

request_rec *h2_create_request_rec(const h2_request *req, conn_rec *c)
{
    int access_status = HTTP_OK;    

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 106)
    request_rec *r = ap_create_request(c);
#else
    request_rec *r = my_ap_create_request(c);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 107)
    ap_run_pre_read_request(r, c);

    /* Time to populate r with the data we have. */
    r->request_time = req->request_time;
    AP_DEBUG_ASSERT(req->authority);
    if (req->scheme && (ap_cstr_casecmp(req->scheme,
                        ap_ssl_conn_is_ssl(c->master? c->master : c)? "https" : "http")
                        || !ap_cstr_casecmp("CONNECT", req->method))) {
        /* Client sent a non-matching ':scheme' pseudo header. Forward this
         * via an absolute URI in the request line.
         */
        r->the_request = apr_psprintf(r->pool, "%s %s://%s%s HTTP/2.0",
                                      req->method, req->scheme, req->authority,
                                      req->path ? req->path : "");
    }
    else if (req->path) {
        r->the_request = apr_psprintf(r->pool, "%s %s HTTP/2.0",
                                      req->method, req->path);
    }
    else {
        /* We should only come here on a request that is errored already.
         * create a request line that passes parsing, we'll die anyway.
         */
        AP_DEBUG_ASSERT(req->http_status != H2_HTTP_STATUS_UNSET);
        r->the_request = apr_psprintf(r->pool, "%s / HTTP/2.0", req->method);
    }

    r->headers_in = apr_table_copy(r->pool, req->headers);

    /* Start with r->hostname = NULL, ap_check_request_header() will get it
     * form Host: header, otherwise we get complains about port numbers.
     */
    r->hostname = NULL;

    /* Validate HTTP/1 request and select vhost. */
    if (!ap_parse_request_line(r) || !ap_check_request_header(r)) {
        /* we may have switched to another server still */
        r->per_dir_config = r->server->lookup_defaults;
        if (req->http_status != H2_HTTP_STATUS_UNSET) {
            access_status = req->http_status;
            /* Be safe and close the connection */
            c->keepalive = AP_CONN_CLOSE;
        }
        else {
            access_status = r->status;
        }
        r->status = HTTP_OK;
        goto die;
    }
#else
    {
        const char *s;

        r->headers_in = apr_table_clone(r->pool, req->headers);
        ap_run_pre_read_request(r, c);

        /* Time to populate r with the data we have. */
        r->request_time = req->request_time;
        r->method = apr_pstrdup(r->pool, req->method);
        /* Provide quick information about the request method as soon as known */
        r->method_number = ap_method_number_of(r->method);
        if (r->method_number == M_GET && r->method[0] == 'H') {
            r->header_only = 1;
        }
        ap_parse_uri(r, req->path ? req->path : "");
        r->protocol = (char*)"HTTP/2.0";
        r->proto_num = HTTP_VERSION(2, 0);
        r->the_request = apr_psprintf(r->pool, "%s %s HTTP/2.0",
                                      r->method, req->path ? req->path : "");

        /* Start with r->hostname = NULL, ap_check_request_header() will get it
         * form Host: header, otherwise we get complains about port numbers.
         */
        r->hostname = NULL;
        ap_update_vhost_from_headers(r);

         /* we may have switched to another server */
         r->per_dir_config = r->server->lookup_defaults;

         s = apr_table_get(r->headers_in, "Expect");
         if (s && s[0]) {
            if (ap_cstr_casecmp(s, "100-continue") == 0) {
                r->expecting_100 = 1;
            }
            else {
                r->status = HTTP_EXPECTATION_FAILED;
                access_status = r->status;
                goto die;
            }
         }
    }
#endif

    /* we may have switched to another server */
    r->per_dir_config = r->server->lookup_defaults;

    if (req->http_status != H2_HTTP_STATUS_UNSET) {
        access_status = req->http_status;
        r->status = HTTP_OK;
        /* Be safe and close the connection */
        c->keepalive = AP_CONN_CLOSE;
        goto die;
    }

    /*
     * Add the HTTP_IN filter here to ensure that ap_discard_request_body
     * called by ap_die and by ap_send_error_response works correctly on
     * status codes that do not cause the connection to be dropped and
     * in situations where the connection should be kept alive.
     */
    ap_add_input_filter_handle(ap_http_input_filter_handle,
                               NULL, r, r->connection);
    
    if ((access_status = ap_post_read_request(r))) {
        /* Request check post hooks failed. An example of this would be a
         * request for a vhost where h2 is disabled --> 421.
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03367)
                      "h2_request: access_status=%d, request_create failed",
                      access_status);
        goto die;
    }

    AP_READ_REQUEST_SUCCESS((uintptr_t)r, (char *)r->method, 
                            (char *)r->uri, (char *)r->server->defn_name, 
                            r->status);
    return r;

die:
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "ap_die(%d) for %s", access_status, r->the_request);
    ap_die(access_status, r);

    /* ap_die() sent the response through the output filters, we must now
     * end the request with an EOR bucket for stream/pipeline accounting.
     */
    {
        apr_bucket_brigade *eor_bb;
#if AP_MODULE_MAGIC_AT_LEAST(20180905, 1)
        eor_bb = ap_acquire_brigade(c);
        APR_BRIGADE_INSERT_TAIL(eor_bb,
                                ap_bucket_eor_create(c->bucket_alloc, r));
        ap_pass_brigade(c->output_filters, eor_bb);
        ap_release_brigade(c, eor_bb);
#else
        eor_bb = apr_brigade_create(c->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(eor_bb,
                                ap_bucket_eor_create(c->bucket_alloc, r));
        ap_pass_brigade(c->output_filters, eor_bb);
        apr_brigade_destroy(eor_bb);
#endif
    }

    r = NULL;
    AP_READ_REQUEST_FAILURE((uintptr_t)r);
    return NULL;
}



