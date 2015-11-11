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
#include "h2_request.h"
#include "h2_task.h"
#include "h2_util.h"


h2_request *h2_request_create(int id, apr_pool_t *pool)
{
    h2_request *req = apr_pcalloc(pool, sizeof(h2_request));
    
    req->id = id;
    req->headers = apr_table_make(pool, 10);
    req->content_length = -1;
    
    return req;
}

void h2_request_destroy(h2_request *req)
{
}

static apr_status_t add_h1_header(h2_request *req, apr_pool_t *pool, 
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    char *hname, *hvalue;
    
    if (H2_HD_MATCH_LIT("transfer-encoding", name, nlen)) {
        if (!apr_strnatcasecmp("chunked", value)) {
            /* This should never arrive here in a HTTP/2 request */
            ap_log_perror(APLOG_MARK, APLOG_ERR, APR_BADARG, pool,
                          APLOGNO(02945) 
                          "h2_request: 'transfer-encoding: chunked' received");
            return APR_BADARG;
        }
    }
    else if (H2_HD_MATCH_LIT("content-length", name, nlen)) {
        char *end;
        req->content_length = apr_strtoi64(value, &end, 10);
        if (value == end) {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, pool,
                          APLOGNO(02959) 
                          "h2_request(%d): content-length value not parsed: %s",
                          req->id, value);
            return APR_EINVAL;
        }
        req->chunked = 0;
    }
    else if (H2_HD_MATCH_LIT("content-type", name, nlen)) {
        /* If we see a content-type and have no length (yet),
         * we need to chunk. */
        req->chunked = (req->content_length == -1);
    }
    else if ((req->seen_host && H2_HD_MATCH_LIT("host", name, nlen))
             || H2_HD_MATCH_LIT("expect", name, nlen)
             || H2_HD_MATCH_LIT("upgrade", name, nlen)
             || H2_HD_MATCH_LIT("connection", name, nlen)
             || H2_HD_MATCH_LIT("proxy-connection", name, nlen)
             || H2_HD_MATCH_LIT("keep-alive", name, nlen)
             || H2_HD_MATCH_LIT("http2-settings", name, nlen)) {
        /* ignore these. */
        return APR_SUCCESS;
    }
    else if (H2_HD_MATCH_LIT("cookie", name, nlen)) {
        const char *existing = apr_table_get(req->headers, "cookie");
        if (existing) {
            char *nval;
            
            /* Cookie headers come separately in HTTP/2, but need
             * to be merged by "; " (instead of default ", ")
             */
            hvalue = apr_pstrndup(pool, value, vlen);
            nval = apr_psprintf(pool, "%s; %s", existing, hvalue);
            apr_table_setn(req->headers, "Cookie", nval);
            return APR_SUCCESS;
        }
    }
    else if (H2_HD_MATCH_LIT("host", name, nlen)) {
        req->seen_host = 1;
    }
    
    hname = apr_pstrndup(pool, name, nlen);
    hvalue = apr_pstrndup(pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);
    apr_table_mergen(req->headers, hname, hvalue);
    
    return APR_SUCCESS;
}

typedef struct {
    h2_request *req;
    apr_pool_t *pool;
} h1_ctx;

static int set_h1_header(void *ctx, const char *key, const char *value)
{
    h1_ctx *x = ctx;
    add_h1_header(x->req, x->pool, key, strlen(key), value, strlen(value));
    return 1;
}

static apr_status_t add_h1_headers(h2_request *req, apr_pool_t *pool, 
                                   apr_table_t *headers)
{
    h1_ctx x;
    x.req = req;
    x.pool = pool;
    apr_table_do(set_h1_header, &x, headers, NULL);
    return APR_SUCCESS;
}


apr_status_t h2_request_rwrite(h2_request *req, request_rec *r)
{
    apr_status_t status;
    
    req->method    = r->method;
    req->authority = r->hostname;
    req->path      = r->uri;
    req->scheme    = (r->parsed_uri.scheme? r->parsed_uri.scheme
                      : r->server->server_scheme);
    
    if (!ap_strchr_c(req->authority, ':') && r->parsed_uri.port_str) {
        req->authority = apr_psprintf(r->pool, "%s:%s", req->authority,
                                      r->parsed_uri.port_str);
    }
    
    status = add_h1_headers(req, r->pool, r->headers_in);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                  "h2_request(%d): rwrite %s host=%s://%s%s",
                  req->id, req->method, req->scheme, req->authority, req->path);
    
    return status;
}

apr_status_t h2_request_add_header(h2_request *req, apr_pool_t *pool, 
                                   const char *name, size_t nlen,
                                   const char *value, size_t vlen)
{
    apr_status_t status = APR_SUCCESS;
    
    if (nlen <= 0) {
        return status;
    }
    
    if (name[0] == ':') {
        /* pseudo header, see ch. 8.1.2.3, always should come first */
        if (!apr_is_empty_table(req->headers)) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                          APLOGNO(02917) 
                          "h2_request(%d): pseudo header after request start",
                          req->id);
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
                          "h2_request(%d): ignoring unknown pseudo header %s",
                          req->id, buffer);
        }
    }
    else {
        /* non-pseudo header, append to work bucket of stream */
        status = add_h1_header(req, pool, name, nlen, value, vlen);
    }
    
    return status;
}

apr_status_t h2_request_end_headers(h2_request *req, apr_pool_t *pool, int eos)
{
    if (req->eoh) {
        return APR_EINVAL;
    }
    
    if (!req->seen_host) {
        /* Need to add a "Host" header if not already there to
         * make virtual hosts work correctly. */
        if (!req->authority) {
            return APR_BADARG;
        }
        apr_table_set(req->headers, "Host", req->authority);
    }

    if (eos && req->chunked) {
        /* We had chunking figured out, but the EOS is already there.
         * unmark chunking and set a definitive content-length.
         */
        req->chunked = 0;
        apr_table_setn(req->headers, "Content-Length", "0");
    }
    else if (req->chunked) {
        /* We have not seen a content-length. We therefore must
         * pass any request content in chunked form.
         */
        apr_table_mergen(req->headers, "Transfer-Encoding", "chunked");
    }
    
    req->eoh = 1;
    
    return APR_SUCCESS;
}

#define OPT_COPY(p, s)  ((s)? apr_pstrdup(p, s) : NULL)

void h2_request_copy(apr_pool_t *p, h2_request *dst, const h2_request *src)
{
    /* keep the dst id */
    dst->method         = OPT_COPY(p, src->method);
    dst->scheme         = OPT_COPY(p, src->method);
    dst->authority      = OPT_COPY(p, src->method);
    dst->path           = OPT_COPY(p, src->method);
    dst->headers        = apr_table_clone(p, src->headers);
    dst->content_length = src->content_length;
    dst->chunked        = src->chunked;
    dst->eoh            = src->eoh;
    dst->seen_host      = src->seen_host;  
}

