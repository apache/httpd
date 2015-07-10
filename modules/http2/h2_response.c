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
#include "h2_util.h"
#include "h2_response.h"

static void convert_header(h2_response *response, apr_table_t *headers,
                           const char *http_status, request_rec *r);
static int ignore_header(const char *name) 
{
    return (H2_HD_MATCH_LIT_CS("connection", name)
            || H2_HD_MATCH_LIT_CS("proxy-connection", name)
            || H2_HD_MATCH_LIT_CS("upgrade", name)
            || H2_HD_MATCH_LIT_CS("keep-alive", name)
            || H2_HD_MATCH_LIT_CS("transfer-encoding", name));
}

h2_response *h2_response_create(int stream_id,
                                const char *http_status,
                                apr_array_header_t *hlines,
                                apr_pool_t *pool)
{
    apr_table_t *header;
    h2_response *response = apr_pcalloc(pool, sizeof(h2_response));
    if (response == NULL) {
        return NULL;
    }
    
    response->stream_id = stream_id;
    response->content_length = -1;
    
    if (hlines) {
        header = apr_table_make(pool, hlines->nelts);        
        for (int i = 0; i < hlines->nelts; ++i) {
            char *hline = ((char **)hlines->elts)[i];
            char *sep = strchr(hline, ':');
            if (!sep) {
                ap_log_perror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, pool,
                              "h2_response(%d): invalid header[%d] '%s'",
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
                                      pool, "h2_response(%d): content-length"
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
    
    convert_header(response, header, http_status, NULL);
    return response->headers? response : NULL;
}

h2_response *h2_response_rcreate(int stream_id, request_rec *r,
                                 apr_table_t *header, apr_pool_t *pool)
{
    h2_response *response = apr_pcalloc(pool, sizeof(h2_response));
    if (response == NULL) {
        return NULL;
    }
    
    response->stream_id = stream_id;
    response->content_length = -1;
    convert_header(response, header, apr_psprintf(pool, "%d", r->status), r);
    
    return response->headers? response : NULL;
}

void h2_response_cleanup(h2_response *response)
{
    if (response->headers) {
        if (--response->headers->refs == 0) {
            free(response->headers);
        }
        response->headers = NULL;
    }
}

void h2_response_destroy(h2_response *response)
{
    h2_response_cleanup(response);
}

void h2_response_copy(h2_response *to, h2_response *from)
{
    h2_response_cleanup(to);
    *to = *from;
    if (from->headers) {
        ++from->headers->refs;
    }
}

typedef struct {
    nghttp2_nv *nv;
    size_t nvlen;
    size_t nvstrlen;
    size_t offset;
    char *strbuf;
    h2_response *response;
    int debug;
    request_rec *r;
} nvctx_t;

static int count_headers(void *ctx, const char *key, const char *value)
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
        if (nvctx->debug) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_EINVAL, 
                          nvctx->r, "h2_response(%d) header -> %s: %s",
                          nvctx->response->stream_id, key, value);
        }
        NV_ADD_CS_CS(ctx, key, value);
    }
    return 1;
}

static void convert_header(h2_response *response, apr_table_t *headers,
                           const char *status, request_rec *r)
{
    nvctx_t ctx = { NULL, 1, strlen(status) + 1, 0, NULL, 
        response, r? APLOGrdebug(r) : 0, r };
    
    apr_table_do(count_headers, &ctx, headers, NULL);
    
    size_t n =  (sizeof(h2_headers)
                 + (ctx.nvlen * sizeof(nghttp2_nv)) + ctx.nvstrlen); 
    h2_headers *h = calloc(1, n);
    if (h) {
        ctx.nv = (nghttp2_nv*)(h + 1);
        ctx.strbuf = (char*)&ctx.nv[ctx.nvlen];
        
        NV_ADD_LIT_CS(&ctx, ":status", status);
        apr_table_do(add_header, &ctx, headers, NULL);
        
        h->nv = ctx.nv;
        h->nvlen = ctx.nvlen;
        h->status = (const char *)ctx.nv[0].value;
        h->refs = 1;
        response->headers = h;
    }
}

