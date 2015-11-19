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
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_util.h"


h2_request *h2_request_create(int id, apr_pool_t *pool)
{
    return h2_request_createn(id, pool, NULL, NULL, NULL, NULL, NULL);
}

h2_request *h2_request_createn(int id, apr_pool_t *pool,
                               const char *method, const char *scheme,
                               const char *authority, const char *path,
                               apr_table_t *header)
{
    h2_request *req = apr_pcalloc(pool, sizeof(h2_request));
    
    req->id             = id;
    req->method         = method;
    req->scheme         = scheme;
    req->authority      = authority;
    req->path           = path;
    req->headers        = header? header : apr_table_make(pool, 10);
    
    return req;
}

void h2_request_destroy(h2_request *req)
{
}

static apr_status_t inspect_clen(h2_request *req, const char *s)
{
    char *end;
    req->content_length = apr_strtoi64(s, &end, 10);
    return (s == end)? APR_EINVAL : APR_SUCCESS;
}

static apr_status_t add_h1_header(h2_request *req, apr_pool_t *pool, 
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    char *hname, *hvalue;
    
    if (H2_HD_MATCH_LIT("expect", name, nlen)
        || H2_HD_MATCH_LIT("upgrade", name, nlen)
        || H2_HD_MATCH_LIT("connection", name, nlen)
        || H2_HD_MATCH_LIT("proxy-connection", name, nlen)
        || H2_HD_MATCH_LIT("transfer-encoding", name, nlen)
        || H2_HD_MATCH_LIT("keep-alive", name, nlen)
        || H2_HD_MATCH_LIT("http2-settings", name, nlen)) {
        /* ignore these. */
        return APR_SUCCESS;
    }
    else if (H2_HD_MATCH_LIT("cookie", name, nlen)) {
        const char *existing = apr_table_get(req->headers, "cookie");
        if (existing) {
            char *nval;
            
            /* Cookie header come separately in HTTP/2, but need
             * to be merged by "; " (instead of default ", ")
             */
            hvalue = apr_pstrndup(pool, value, vlen);
            nval = apr_psprintf(pool, "%s; %s", existing, hvalue);
            apr_table_setn(req->headers, "Cookie", nval);
            return APR_SUCCESS;
        }
    }
    else if (H2_HD_MATCH_LIT("host", name, nlen)) {
        if (apr_table_get(req->headers, "Host")) {
            return APR_SUCCESS; /* ignore duplicate */
        }
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

static apr_status_t add_all_h1_header(h2_request *req, apr_pool_t *pool, 
                                      apr_table_t *header)
{
    h1_ctx x;
    x.req = req;
    x.pool = pool;
    apr_table_do(set_h1_header, &x, header, NULL);
    return APR_SUCCESS;
}


apr_status_t h2_request_rwrite(h2_request *req, request_rec *r)
{
    apr_status_t status;
    
    req->method    = r->method;
    req->scheme    = (r->parsed_uri.scheme? r->parsed_uri.scheme
                      : ap_http_scheme(r));
    req->authority = r->hostname;
    req->path      = apr_uri_unparse(r->pool, &r->parsed_uri, 
                                     APR_URI_UNP_OMITSITEPART);

    if (!ap_strchr_c(req->authority, ':') && r->server) {
        req->authority = apr_psprintf(r->pool, "%s:%d", req->authority,
                                      (int)r->server->port);
    }
    
    AP_DEBUG_ASSERT(req->scheme);
    AP_DEBUG_ASSERT(req->authority);
    AP_DEBUG_ASSERT(req->path);
    AP_DEBUG_ASSERT(req->method);

    status = add_all_h1_header(req, r->pool, r->headers_in);

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
    const char *s;
    
    if (req->eoh) {
        return APR_EINVAL;
    }

    /* be safe, some header we do not accept on h2(c) */
    apr_table_unset(req->headers, "expect");
    apr_table_unset(req->headers, "upgrade");
    apr_table_unset(req->headers, "connection");
    apr_table_unset(req->headers, "proxy-connection");
    apr_table_unset(req->headers, "transfer-encoding");
    apr_table_unset(req->headers, "keep-alive");
    apr_table_unset(req->headers, "http2-settings");

    if (!apr_table_get(req->headers, "Host")) {
        /* Need to add a "Host" header if not already there to
         * make virtual hosts work correctly. */
        if (!req->authority) {
            return APR_BADARG;
        }
        apr_table_set(req->headers, "Host", req->authority);
    }

    s = apr_table_get(req->headers, "Content-Length");
    if (s) {
        if (inspect_clen(req, s) != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, pool,
                          APLOGNO(02959) 
                          "h2_request(%d): content-length value not parsed: %s",
                          req->id, s);
            return APR_EINVAL;
        }
    }
    else {
        /* no content-length given */
        req->content_length = -1;
        if (!eos) {
            /* We have not seen a content-length and have no eos,
             * simulate a chunked encoding for our HTTP/1.1 infrastructure,
             * in case we have "H2SerializeHeaders on" here
             */
            req->chunked = 1;
            apr_table_mergen(req->headers, "Transfer-Encoding", "chunked");
        }
        else if (apr_table_get(req->headers, "Content-Type")) {
            /* If we have a content-type, but already see eos, no more
             * data will come. Signal a zero content length explicitly.
             */
            apr_table_setn(req->headers, "Content-Length", "0");
        }
    }

    req->eoh = 1;
    
    /* In the presence of trailers, force behaviour of chunked encoding */
    s = apr_table_get(req->headers, "Trailer");
    if (s && s[0]) {
        req->trailers = apr_table_make(pool, 5);
        if (!req->chunked) {
            req->chunked = 1;
            apr_table_mergen(req->headers, "Transfer-Encoding", "chunked");
        }
    }
    
    return APR_SUCCESS;
}

static apr_status_t add_h1_trailer(h2_request *req, apr_pool_t *pool, 
                                   const char *name, size_t nlen,
                                   const char *value, size_t vlen)
{
    char *hname, *hvalue;
    
    if (H2_HD_MATCH_LIT("expect", name, nlen)
        || H2_HD_MATCH_LIT("upgrade", name, nlen)
        || H2_HD_MATCH_LIT("connection", name, nlen)
        || H2_HD_MATCH_LIT("host", name, nlen)
        || H2_HD_MATCH_LIT("proxy-connection", name, nlen)
        || H2_HD_MATCH_LIT("transfer-encoding", name, nlen)
        || H2_HD_MATCH_LIT("keep-alive", name, nlen)
        || H2_HD_MATCH_LIT("http2-settings", name, nlen)) {
        /* ignore these. */
        return APR_SUCCESS;
    }
    
    hname = apr_pstrndup(pool, name, nlen);
    hvalue = apr_pstrndup(pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);

    apr_table_mergen(req->trailers, hname, hvalue);
    
    return APR_SUCCESS;
}


apr_status_t h2_request_add_trailer(h2_request *req, apr_pool_t *pool,
                                    const char *name, size_t nlen,
                                    const char *value, size_t vlen)
{
    if (!req->trailers) {
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, APR_EINVAL, pool,
                      "h2_request(%d): unanounced trailers",
                      req->id);
        return APR_EINVAL;
    }
    if (nlen == 0 || name[0] == ':') {
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, APR_EINVAL, pool,
                      "h2_request(%d): pseudo header in trailer",
                      req->id);
        return APR_EINVAL;
    }
    return add_h1_trailer(req, pool, name, nlen, value, vlen);
}

#define OPT_COPY(p, s)  ((s)? apr_pstrdup(p, s) : NULL)

void h2_request_copy(apr_pool_t *p, h2_request *dst, const h2_request *src)
{
    /* keep the dst id */
    dst->method         = OPT_COPY(p, src->method);
    dst->scheme         = OPT_COPY(p, src->scheme);
    dst->authority      = OPT_COPY(p, src->authority);
    dst->path           = OPT_COPY(p, src->path);
    dst->headers        = apr_table_clone(p, src->headers);
    dst->content_length = src->content_length;
    dst->chunked        = src->chunked;
    dst->eoh            = src->eoh;
}

