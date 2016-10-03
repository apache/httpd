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
#include <http_log.h>
#include <http_request.h>

#include <nghttp2/nghttp2.h>

#include "h2.h"
#include "h2_proxy_util.h"

/* h2_log2(n) iff n is a power of 2 */
unsigned char h2_log2(apr_uint32_t n)
{
    int lz = 0;
    if (!n) {
        return 0;
    }
    if (!(n & 0xffff0000u)) {
        lz += 16;
        n = (n << 16);
    }
    if (!(n & 0xff000000u)) {
        lz += 8;
        n = (n << 8);
    }
    if (!(n & 0xf0000000u)) {
        lz += 4;
        n = (n << 4);
    }
    if (!(n & 0xc0000000u)) {
        lz += 2;
        n = (n << 2);
    }
    if (!(n & 0x80000000u)) {
        lz += 1;
    }
    
    return 31 - lz;
}

/*******************************************************************************
 * ihash - hash for structs with int identifier
 ******************************************************************************/
struct h2_ihash_t {
    apr_hash_t *hash;
    size_t ioff;
};

static unsigned int ihash(const char *key, apr_ssize_t *klen)
{
    return (unsigned int)(*((int*)key));
}

h2_ihash_t *h2_ihash_create(apr_pool_t *pool, size_t offset_of_int)
{
    h2_ihash_t *ih = apr_pcalloc(pool, sizeof(h2_ihash_t));
    ih->hash = apr_hash_make_custom(pool, ihash);
    ih->ioff = offset_of_int;
    return ih;
}

size_t h2_ihash_count(h2_ihash_t *ih)
{
    return apr_hash_count(ih->hash);
}

int h2_ihash_empty(h2_ihash_t *ih)
{
    return apr_hash_count(ih->hash) == 0;
}

void *h2_ihash_get(h2_ihash_t *ih, int id)
{
    return apr_hash_get(ih->hash, &id, sizeof(id));
}

typedef struct {
    h2_ihash_iter_t *iter;
    void *ctx;
} iter_ctx;

static int ihash_iter(void *ctx, const void *key, apr_ssize_t klen, 
                     const void *val)
{
    iter_ctx *ictx = ctx;
    return ictx->iter(ictx->ctx, (void*)val); /* why is this passed const?*/
}

int h2_ihash_iter(h2_ihash_t *ih, h2_ihash_iter_t *fn, void *ctx)
{
    iter_ctx ictx;
    ictx.iter = fn;
    ictx.ctx = ctx;
    return apr_hash_do(ihash_iter, &ictx, ih->hash);
}

void h2_ihash_add(h2_ihash_t *ih, void *val)
{
    apr_hash_set(ih->hash, ((char *)val + ih->ioff), sizeof(int), val);
}

void h2_ihash_remove(h2_ihash_t *ih, int id)
{
    apr_hash_set(ih->hash, &id, sizeof(id), NULL);
}

void h2_ihash_remove_val(h2_ihash_t *ih, void *val)
{
    int id = *((int*)((char *)val + ih->ioff));
    apr_hash_set(ih->hash, &id, sizeof(id), NULL);
}


void h2_ihash_clear(h2_ihash_t *ih)
{
    apr_hash_clear(ih->hash);
}

typedef struct {
    h2_ihash_t *ih;
    void **buffer;
    size_t max;
    size_t len;
} collect_ctx;

static int collect_iter(void *x, void *val)
{
    collect_ctx *ctx = x;
    if (ctx->len < ctx->max) {
        ctx->buffer[ctx->len++] = val;
        return 1;
    }
    return 0;
}

size_t h2_ihash_shift(h2_ihash_t *ih, void **buffer, size_t max)
{
    collect_ctx ctx;
    size_t i;
    
    ctx.ih = ih;
    ctx.buffer = buffer;
    ctx.max = max;
    ctx.len = 0;
    h2_ihash_iter(ih, collect_iter, &ctx);
    for (i = 0; i < ctx.len; ++i) {
        h2_ihash_remove_val(ih, buffer[i]);
    }
    return ctx.len;
}

typedef struct {
    h2_ihash_t *ih;
    int *buffer;
    size_t max;
    size_t len;
} icollect_ctx;

static int icollect_iter(void *x, void *val)
{
    icollect_ctx *ctx = x;
    if (ctx->len < ctx->max) {
        ctx->buffer[ctx->len++] = *((int*)((char *)val + ctx->ih->ioff));
        return 1;
    }
    return 0;
}

size_t h2_ihash_ishift(h2_ihash_t *ih, int *buffer, size_t max)
{
    icollect_ctx ctx;
    size_t i;
    
    ctx.ih = ih;
    ctx.buffer = buffer;
    ctx.max = max;
    ctx.len = 0;
    h2_ihash_iter(ih, icollect_iter, &ctx);
    for (i = 0; i < ctx.len; ++i) {
        h2_ihash_remove(ih, buffer[i]);
    }
    return ctx.len;
}

/*******************************************************************************
 * iqueue - sorted list of int
 ******************************************************************************/

static void iq_grow(h2_iqueue *q, int nlen);
static void iq_swap(h2_iqueue *q, int i, int j);
static int iq_bubble_up(h2_iqueue *q, int i, int top, 
                        h2_iq_cmp *cmp, void *ctx);
static int iq_bubble_down(h2_iqueue *q, int i, int bottom, 
                          h2_iq_cmp *cmp, void *ctx);

h2_iqueue *h2_iq_create(apr_pool_t *pool, int capacity)
{
    h2_iqueue *q = apr_pcalloc(pool, sizeof(h2_iqueue));
    if (q) {
        q->pool = pool;
        iq_grow(q, capacity);
        q->nelts = 0;
    }
    return q;
}

int h2_iq_empty(h2_iqueue *q)
{
    return q->nelts == 0;
}

int h2_iq_count(h2_iqueue *q)
{
    return q->nelts;
}


void h2_iq_add(h2_iqueue *q, int sid, h2_iq_cmp *cmp, void *ctx)
{
    int i;
    
    if (q->nelts >= q->nalloc) {
        iq_grow(q, q->nalloc * 2);
    }
    
    i = (q->head + q->nelts) % q->nalloc;
    q->elts[i] = sid;
    ++q->nelts;
    
    if (cmp) {
        /* bubble it to the front of the queue */
        iq_bubble_up(q, i, q->head, cmp, ctx);
    }
}

int h2_iq_remove(h2_iqueue *q, int sid)
{
    int i;
    for (i = 0; i < q->nelts; ++i) {
        if (sid == q->elts[(q->head + i) % q->nalloc]) {
            break;
        }
    }
    
    if (i < q->nelts) {
        ++i;
        for (; i < q->nelts; ++i) {
            q->elts[(q->head+i-1)%q->nalloc] = q->elts[(q->head+i)%q->nalloc];
        }
        --q->nelts;
        return 1;
    }
    return 0;
}

void h2_iq_clear(h2_iqueue *q)
{
    q->nelts = 0;
}

void h2_iq_sort(h2_iqueue *q, h2_iq_cmp *cmp, void *ctx)
{
    /* Assume that changes in ordering are minimal. This needs,
     * best case, q->nelts - 1 comparisons to check that nothing
     * changed.
     */
    if (q->nelts > 0) {
        int i, ni, prev, last;
        
        /* Start at the end of the queue and create a tail of sorted
         * entries. Make that tail one element longer in each iteration.
         */
        last = i = (q->head + q->nelts - 1) % q->nalloc;
        while (i != q->head) {
            prev = (q->nalloc + i - 1) % q->nalloc;
            
            ni = iq_bubble_up(q, i, prev, cmp, ctx);
            if (ni == prev) {
                /* i bubbled one up, bubble the new i down, which
                 * keeps all tasks below i sorted. */
                iq_bubble_down(q, i, last, cmp, ctx);
            }
            i = prev;
        };
    }
}


int h2_iq_shift(h2_iqueue *q)
{
    int sid;
    
    if (q->nelts <= 0) {
        return 0;
    }
    
    sid = q->elts[q->head];
    q->head = (q->head + 1) % q->nalloc;
    q->nelts--;
    
    return sid;
}

static void iq_grow(h2_iqueue *q, int nlen)
{
    if (nlen > q->nalloc) {
        int *nq = apr_pcalloc(q->pool, sizeof(int) * nlen);
        if (q->nelts > 0) {
            int l = ((q->head + q->nelts) % q->nalloc) - q->head;
            
            memmove(nq, q->elts + q->head, sizeof(int) * l);
            if (l < q->nelts) {
                /* elts wrapped, append elts in [0, remain] to nq */
                int remain = q->nelts - l;
                memmove(nq + l, q->elts, sizeof(int) * remain);
            }
        }
        q->elts = nq;
        q->nalloc = nlen;
        q->head = 0;
    }
}

static void iq_swap(h2_iqueue *q, int i, int j)
{
    int x = q->elts[i];
    q->elts[i] = q->elts[j];
    q->elts[j] = x;
}

static int iq_bubble_up(h2_iqueue *q, int i, int top, 
                        h2_iq_cmp *cmp, void *ctx) 
{
    int prev;
    while (((prev = (q->nalloc + i - 1) % q->nalloc), i != top) 
           && (*cmp)(q->elts[i], q->elts[prev], ctx) < 0) {
        iq_swap(q, prev, i);
        i = prev;
    }
    return i;
}

static int iq_bubble_down(h2_iqueue *q, int i, int bottom, 
                          h2_iq_cmp *cmp, void *ctx)
{
    int next;
    while (((next = (q->nalloc + i + 1) % q->nalloc), i != bottom) 
           && (*cmp)(q->elts[i], q->elts[next], ctx) > 0) {
        iq_swap(q, next, i);
        i = next;
    }
    return i;
}

/*******************************************************************************
 * h2_ngheader
 ******************************************************************************/
#define H2_HD_MATCH_LIT_CS(l, name)  \
    ((strlen(name) == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))

static int h2_util_ignore_header(const char *name) 
{
    /* never forward, ch. 8.1.2.2 */
    return (H2_HD_MATCH_LIT_CS("connection", name)
            || H2_HD_MATCH_LIT_CS("proxy-connection", name)
            || H2_HD_MATCH_LIT_CS("upgrade", name)
            || H2_HD_MATCH_LIT_CS("keep-alive", name)
            || H2_HD_MATCH_LIT_CS("transfer-encoding", name));
}

static int count_header(void *ctx, const char *key, const char *value)
{
    if (!h2_util_ignore_header(key)) {
        (*((size_t*)ctx))++;
    }
    return 1;
}

#define NV_ADD_LIT_CS(nv, k, v)     add_header(nv, k, sizeof(k) - 1, v, strlen(v))
#define NV_ADD_CS_CS(nv, k, v)      add_header(nv, k, strlen(k), v, strlen(v))

static int add_header(h2_ngheader *ngh, 
                      const char *key, size_t key_len,
                      const char *value, size_t val_len)
{
    nghttp2_nv *nv = &ngh->nv[ngh->nvlen++];
    
    nv->name = (uint8_t*)key;
    nv->namelen = key_len;
    nv->value = (uint8_t*)value;
    nv->valuelen = val_len;
    return 1;
}

static int add_table_header(void *ctx, const char *key, const char *value)
{
    if (!h2_util_ignore_header(key)) {
        add_header(ctx, key, strlen(key), value, strlen(value));
    }
    return 1;
}

h2_ngheader *h2_util_ngheader_make_req(apr_pool_t *p, 
                                       const struct h2_request *req)
{
    
    h2_ngheader *ngh;
    size_t n;
    
    AP_DEBUG_ASSERT(req);
    AP_DEBUG_ASSERT(req->scheme);
    AP_DEBUG_ASSERT(req->authority);
    AP_DEBUG_ASSERT(req->path);
    AP_DEBUG_ASSERT(req->method);

    n = 4;
    apr_table_do(count_header, &n, req->headers, NULL);
    
    ngh = apr_pcalloc(p, sizeof(h2_ngheader));
    ngh->nv =  apr_pcalloc(p, n * sizeof(nghttp2_nv));
    NV_ADD_LIT_CS(ngh, ":scheme", req->scheme);
    NV_ADD_LIT_CS(ngh, ":authority", req->authority);
    NV_ADD_LIT_CS(ngh, ":path", req->path);
    NV_ADD_LIT_CS(ngh, ":method", req->method);
    apr_table_do(add_table_header, ngh, req->headers, NULL);

    return ngh;
}

/*******************************************************************************
 * header HTTP/1 <-> HTTP/2 conversions
 ******************************************************************************/
 
typedef struct {
    const char *name;
    size_t len;
} literal;

#define H2_DEF_LITERAL(n)   { (n), (sizeof(n)-1) }
#define H2_LIT_ARGS(a)      (a),H2_ALEN(a)

static literal IgnoredRequestHeaders[] = {
    H2_DEF_LITERAL("expect"),
    H2_DEF_LITERAL("upgrade"),
    H2_DEF_LITERAL("connection"),
    H2_DEF_LITERAL("keep-alive"),
    H2_DEF_LITERAL("http2-settings"),
    H2_DEF_LITERAL("proxy-connection"),
    H2_DEF_LITERAL("transfer-encoding"),
};
static literal IgnoredProxyRespHds[] = {
    H2_DEF_LITERAL("alt-svc"),
};

static int ignore_header(const literal *lits, size_t llen,
                         const char *name, size_t nlen)
{
    const literal *lit;
    int i;
    
    for (i = 0; i < llen; ++i) {
        lit = &lits[i];
        if (lit->len == nlen && !apr_strnatcasecmp(lit->name, name)) {
            return 1;
        }
    }
    return 0;
}

static int h2_req_ignore_header(const char *name, size_t len)
{
    return ignore_header(H2_LIT_ARGS(IgnoredRequestHeaders), name, len);
}

int h2_proxy_res_ignore_header(const char *name, size_t len)
{
    return (h2_req_ignore_header(name, len) 
            || ignore_header(H2_LIT_ARGS(IgnoredProxyRespHds), name, len));
}

void h2_util_camel_case_header(char *s, size_t len)
{
    size_t start = 1;
    size_t i;
    for (i = 0; i < len; ++i) {
        if (start) {
            if (s[i] >= 'a' && s[i] <= 'z') {
                s[i] -= 'a' - 'A';
            }
            
            start = 0;
        }
        else if (s[i] == '-') {
            start = 1;
        }
    }
}

/*******************************************************************************
 * h2 request handling
 ******************************************************************************/

/** Match a header value against a string constance, case insensitive */
#define H2_HD_MATCH_LIT(l, name, nlen)  \
    ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))

static apr_status_t h2_headers_add_h1(apr_table_t *headers, apr_pool_t *pool, 
                                      const char *name, size_t nlen,
                                      const char *value, size_t vlen)
{
    char *hname, *hvalue;
    
    if (h2_req_ignore_header(name, nlen)) {
        return APR_SUCCESS;
    }
    else if (H2_HD_MATCH_LIT("cookie", name, nlen)) {
        const char *existing = apr_table_get(headers, "cookie");
        if (existing) {
            char *nval;
            
            /* Cookie header come separately in HTTP/2, but need
             * to be merged by "; " (instead of default ", ")
             */
            hvalue = apr_pstrndup(pool, value, vlen);
            nval = apr_psprintf(pool, "%s; %s", existing, hvalue);
            apr_table_setn(headers, "Cookie", nval);
            return APR_SUCCESS;
        }
    }
    else if (H2_HD_MATCH_LIT("host", name, nlen)) {
        if (apr_table_get(headers, "Host")) {
            return APR_SUCCESS; /* ignore duplicate */
        }
    }
    
    hname = apr_pstrndup(pool, name, nlen);
    hvalue = apr_pstrndup(pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);
    apr_table_mergen(headers, hname, hvalue);
    
    return APR_SUCCESS;
}

static h2_request *h2_req_createn(int id, apr_pool_t *pool, const char *method, 
                                  const char *scheme, const char *authority, 
                                  const char *path, apr_table_t *header, 
                                  int serialize)
{
    h2_request *req = apr_pcalloc(pool, sizeof(h2_request));
    
    req->method         = method;
    req->scheme         = scheme;
    req->authority      = authority;
    req->path           = path;
    req->headers        = header? header : apr_table_make(pool, 10);
    req->request_time   = apr_time_now();
    req->serialize      = serialize;
    
    return req;
}

h2_request *h2_req_create(int id, apr_pool_t *pool, int serialize)
{
    return h2_req_createn(id, pool, NULL, NULL, NULL, NULL, NULL, serialize);
}

typedef struct {
    apr_table_t *headers;
    apr_pool_t *pool;
} h1_ctx;

static int set_h1_header(void *ctx, const char *key, const char *value)
{
    h1_ctx *x = ctx;
    size_t klen = strlen(key);
    if (!h2_req_ignore_header(key, klen)) {
        h2_headers_add_h1(x->headers, x->pool, key, klen, value, strlen(value));
    }
    return 1;
}

apr_status_t h2_req_make(h2_request *req, apr_pool_t *pool,
                         const char *method, const char *scheme, 
                         const char *authority, const char *path, 
                         apr_table_t *headers)
{
    h1_ctx x;

    req->method    = method;
    req->scheme    = scheme;
    req->authority = authority;
    req->path      = path;

    AP_DEBUG_ASSERT(req->scheme);
    AP_DEBUG_ASSERT(req->authority);
    AP_DEBUG_ASSERT(req->path);
    AP_DEBUG_ASSERT(req->method);

    x.pool = pool;
    x.headers = req->headers;
    apr_table_do(set_h1_header, &x, headers, NULL);
    return APR_SUCCESS;
}

/*******************************************************************************
 * frame logging
 ******************************************************************************/

int h2_util_frame_print(const nghttp2_frame *frame, char *buffer, size_t maxlen)
{
    char scratch[128];
    size_t s_len = sizeof(scratch)/sizeof(scratch[0]);
    
    switch (frame->hd.type) {
        case NGHTTP2_DATA: {
            return apr_snprintf(buffer, maxlen,
                                "DATA[length=%d, flags=%d, stream=%d, padlen=%d]",
                                (int)frame->hd.length, frame->hd.flags,
                                frame->hd.stream_id, (int)frame->data.padlen);
        }
        case NGHTTP2_HEADERS: {
            return apr_snprintf(buffer, maxlen,
                                "HEADERS[length=%d, hend=%d, stream=%d, eos=%d]",
                                (int)frame->hd.length,
                                !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS),
                                frame->hd.stream_id,
                                !!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM));
        }
        case NGHTTP2_PRIORITY: {
            return apr_snprintf(buffer, maxlen,
                                "PRIORITY[length=%d, flags=%d, stream=%d]",
                                (int)frame->hd.length,
                                frame->hd.flags, frame->hd.stream_id);
        }
        case NGHTTP2_RST_STREAM: {
            return apr_snprintf(buffer, maxlen,
                                "RST_STREAM[length=%d, flags=%d, stream=%d]",
                                (int)frame->hd.length,
                                frame->hd.flags, frame->hd.stream_id);
        }
        case NGHTTP2_SETTINGS: {
            if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
                return apr_snprintf(buffer, maxlen,
                                    "SETTINGS[ack=1, stream=%d]",
                                    frame->hd.stream_id);
            }
            return apr_snprintf(buffer, maxlen,
                                "SETTINGS[length=%d, stream=%d]",
                                (int)frame->hd.length, frame->hd.stream_id);
        }
        case NGHTTP2_PUSH_PROMISE: {
            return apr_snprintf(buffer, maxlen,
                                "PUSH_PROMISE[length=%d, hend=%d, stream=%d]",
                                (int)frame->hd.length,
                                !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS),
                                frame->hd.stream_id);
        }
        case NGHTTP2_PING: {
            return apr_snprintf(buffer, maxlen,
                                "PING[length=%d, ack=%d, stream=%d]",
                                (int)frame->hd.length,
                                frame->hd.flags&NGHTTP2_FLAG_ACK,
                                frame->hd.stream_id);
        }
        case NGHTTP2_GOAWAY: {
            size_t len = (frame->goaway.opaque_data_len < s_len)?
                frame->goaway.opaque_data_len : s_len-1;
            memcpy(scratch, frame->goaway.opaque_data, len);
            scratch[len] = '\0';
            return apr_snprintf(buffer, maxlen, "GOAWAY[error=%d, reason='%s', "
                                "last_stream=%d]", frame->goaway.error_code, 
                                scratch, frame->goaway.last_stream_id);
        }
        case NGHTTP2_WINDOW_UPDATE: {
            return apr_snprintf(buffer, maxlen,
                                "WINDOW_UPDATE[stream=%d, incr=%d]",
                                frame->hd.stream_id, 
                                frame->window_update.window_size_increment);
        }
        default:
            return apr_snprintf(buffer, maxlen,
                                "type=%d[length=%d, flags=%d, stream=%d]",
                                frame->hd.type, (int)frame->hd.length,
                                frame->hd.flags, frame->hd.stream_id);
    }
}
