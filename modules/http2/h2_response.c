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

static h2_ngheader *make_ngheader(apr_pool_t *pool, const char *status,
                                  apr_table_t *header);

static int ignore_header(const char *name) 
{
    return (H2_HD_MATCH_LIT_CS("connection", name)
            || H2_HD_MATCH_LIT_CS("proxy-connection", name)
            || H2_HD_MATCH_LIT_CS("upgrade", name)
            || H2_HD_MATCH_LIT_CS("keep-alive", name)
            || H2_HD_MATCH_LIT_CS("transfer-encoding", name));
}

h2_response *h2_response_create(int stream_id,
                                int rst_error,
                                const char *http_status,
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
    response->status = http_status? http_status : "500";
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
            if (ignore_header(hline)) {
                /* never forward, ch. 8.1.2.2 */
            }
            else {
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

    response->rheader = header;
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
    response->status = apr_psprintf(pool, "%d", r->status);
    response->content_length = -1;
    response->rheader = header;

    if (r->status == HTTP_FORBIDDEN) {
        const char *cause = apr_table_get(r->notes, "ssl-renegotiate-forbidden");
        if (cause) {
            /* This request triggered a TLS renegotiation that is now allowed 
             * in HTTP/2. Tell the client that it should use HTTP/1.1 for this.
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, r->status, r, 
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
    to->status = apr_pstrdup(pool, from->status);
    to->content_length = from->content_length;
    if (from->rheader) {
        to->ngheader = make_ngheader(pool, to->status, from->rheader);
    }
    return to;
}

typedef struct {
    nghttp2_nv *nv;
    size_t nvlen;
    size_t nvstrlen;
    size_t offset;
    char *strbuf;
    apr_pool_t *pool;
} nvctx_t;

static int count_header(void *ctx, const char *key, const char *value)
{
    if (!ignore_header(key)) {
        nvctx_t *nvctx = (nvctx_t*)ctx;
        nvctx->nvlen++;
        nvctx->nvstrlen += strlen(key) + strlen(value) + 2;
    }
    return 1;
}

#define NV_ADD_LIT_CS(nv, k, v)     addnv_lit_cs(nv, k, sizeof(k) - 1, v, strlen(v))
#define NV_ADD_CS_CS(nv, k, v)      addnv_cs_cs(nv, k, strlen(k), v, strlen(v))
#define NV_BUF_ADD(nv, s, len)      memcpy(nv->strbuf, s, len); \
s = nv->strbuf; \
nv->strbuf += len + 1

static void addnv_cs_cs(nvctx_t *ctx, const char *key, size_t key_len,
                        const char *value, size_t val_len)
{
    nghttp2_nv *nv = &ctx->nv[ctx->offset];
    
    NV_BUF_ADD(ctx, key, key_len);
    NV_BUF_ADD(ctx, value, val_len);
    
    nv->name = (uint8_t*)key;
    nv->namelen = key_len;
    nv->value = (uint8_t*)value;
    nv->valuelen = val_len;
    
    ctx->offset++;
}

static void addnv_lit_cs(nvctx_t *ctx, const char *key, size_t key_len,
                         const char *value, size_t val_len)
{
    nghttp2_nv *nv = &ctx->nv[ctx->offset];
    
    NV_BUF_ADD(ctx, value, val_len);
    
    nv->name = (uint8_t*)key;
    nv->namelen = key_len;
    nv->value = (uint8_t*)value;
    nv->valuelen = val_len;
    
    ctx->offset++;
}

static int add_header(void *ctx, const char *key, const char *value)
{
    if (!ignore_header(key)) {
        nvctx_t *nvctx = (nvctx_t*)ctx;
        NV_ADD_CS_CS(nvctx, key, value);
    }
    return 1;
}

static h2_ngheader *make_ngheader(apr_pool_t *pool, const char *status,
                                  apr_table_t *header)
{
    size_t n;
    h2_ngheader *h;
    nvctx_t ctx;
    
    ctx.nv       = NULL;
    ctx.nvlen    = 1;
    ctx.nvstrlen = strlen(status) + 1;
    ctx.offset   = 0;
    ctx.strbuf   = NULL;
    ctx.pool     = pool;
    
    apr_table_do(count_header, &ctx, header, NULL);
    
    n =  (sizeof(h2_ngheader)
                 + (ctx.nvlen * sizeof(nghttp2_nv)) + ctx.nvstrlen); 
    h = apr_pcalloc(pool, n);
    if (h) {
        ctx.nv = (nghttp2_nv*)(h + 1);
        ctx.strbuf = (char*)&ctx.nv[ctx.nvlen];
        
        NV_ADD_LIT_CS(&ctx, ":status", status);
        apr_table_do(add_header, &ctx, header, NULL);
        
        h->nv = ctx.nv;
        h->nvlen = ctx.nvlen;
    }
    return h;
}

