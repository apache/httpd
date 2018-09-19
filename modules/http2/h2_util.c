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
#include <apr_strings.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>

#include <nghttp2/nghttp2.h>

#include "h2.h"
#include "h2_util.h"

/* h2_log2(n) iff n is a power of 2 */
unsigned char h2_log2(int n)
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

size_t h2_util_hex_dump(char *buffer, size_t maxlen,
                        const char *data, size_t datalen)
{
    size_t offset = 0;
    size_t maxoffset = (maxlen-4);
    size_t i;
    for (i = 0; i < datalen && offset < maxoffset; ++i) {
        const char *sep = (i && i % 16 == 0)? "\n" : " ";
        int n = apr_snprintf(buffer+offset, maxoffset-offset,
                             "%2x%s", ((unsigned int)data[i]&0xff), sep);
        offset += n;
    }
    strcpy(buffer+offset, (i<datalen)? "..." : "");
    return strlen(buffer);
}

size_t h2_util_header_print(char *buffer, size_t maxlen,
                            const char *name, size_t namelen,
                            const char *value, size_t valuelen)
{
    size_t offset = 0;
    size_t i;
    for (i = 0; i < namelen && offset < maxlen; ++i, ++offset) {
        buffer[offset] = name[i];
    }
    for (i = 0; i < 2 && offset < maxlen; ++i, ++offset) {
        buffer[offset] = ": "[i];
    }
    for (i = 0; i < valuelen && offset < maxlen; ++i, ++offset) {
        buffer[offset] = value[i];
    }
    buffer[offset] = '\0';
    return offset;
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

/* base64 url encoding ****************************************************************************/

#define N6 (unsigned int)-1

static const unsigned int BASE64URL_UINT6[] = {
/*   0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f        */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  0 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  1 */ 
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, 62, N6, N6, /*  2 */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, N6, N6, N6, N6, N6, N6, /*  3 */ 
    N6, 0,  1,  2,  3,  4,  5,  6,   7,  8,  9, 10, 11, 12, 13, 14, /*  4 */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, N6, N6, N6, N6, 63, /*  5 */
    N6, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*  6 */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, N6, N6, N6, N6, N6, /*  7 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  8 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  9 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  a */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  b */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  c */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  d */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  e */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6  /*  f */
};
static const unsigned char BASE64URL_CHARS[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', /*  0 -  9 */
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', /* 10 - 19 */
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', /* 20 - 29 */
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', /* 30 - 39 */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', /* 40 - 49 */
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', /* 50 - 59 */
    '8', '9', '-', '_', ' ', ' ', ' ', ' ', ' ', ' ', /* 60 - 69 */
};

#define BASE64URL_CHAR(x)    BASE64URL_CHARS[ (unsigned int)(x) & 0x3fu ]

apr_size_t h2_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool)
{
    const unsigned char *e = (const unsigned char *)encoded;
    const unsigned char *p = e;
    unsigned char *d;
    unsigned int n;
    long len, mlen, remain, i;
    
    while (*p && BASE64URL_UINT6[ *p ] != N6) {
        ++p;
    }
    len = (int)(p - e);
    mlen = (len/4)*4;
    *decoded = apr_pcalloc(pool, (apr_size_t)len + 1);
    
    i = 0;
    d = (unsigned char*)*decoded;
    for (; i < mlen; i += 4) {
        n = ((BASE64URL_UINT6[ e[i+0] ] << 18) +
             (BASE64URL_UINT6[ e[i+1] ] << 12) +
             (BASE64URL_UINT6[ e[i+2] ] << 6) +
             (BASE64URL_UINT6[ e[i+3] ]));
        *d++ = (unsigned char)(n >> 16);
        *d++ = (unsigned char)(n >> 8 & 0xffu);
        *d++ = (unsigned char)(n & 0xffu);
    }
    remain = len - mlen;
    switch (remain) {
        case 2:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12));
            *d++ = (unsigned char)(n >> 16);
            remain = 1;
            break;
        case 3:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12) +
                 (BASE64URL_UINT6[ e[mlen+2] ] << 6));
            *d++ = (unsigned char)(n >> 16);
            *d++ = (unsigned char)(n >> 8 & 0xffu);
            remain = 2;
            break;
        default: /* do nothing */
            break;
    }
    return (apr_size_t)(mlen/4*3 + remain);
}

const char *h2_util_base64url_encode(const char *data, 
                                     apr_size_t dlen, apr_pool_t *pool)
{
    int i, len = (int)dlen;
    apr_size_t slen = ((dlen+2)/3)*4 + 1; /* 0 terminated */
    const unsigned char *udata = (const unsigned char*)data;
    unsigned char *enc, *p = apr_pcalloc(pool, slen);
    
    enc = p;
    for (i = 0; i < len-2; i+= 3) {
        *p++ = BASE64URL_CHAR( (udata[i]   >> 2) );
        *p++ = BASE64URL_CHAR( (udata[i]   << 4) + (udata[i+1] >> 4) );
        *p++ = BASE64URL_CHAR( (udata[i+1] << 2) + (udata[i+2] >> 6) );
        *p++ = BASE64URL_CHAR( (udata[i+2]) );
    }
    
    if (i < len) {
        *p++ = BASE64URL_CHAR( (udata[i] >> 2) );
        if (i == (len - 1)) {
            *p++ = BASE64URL_CHARS[ ((unsigned int)udata[i] << 4) & 0x3fu ];
        }
        else {
            *p++ = BASE64URL_CHAR( (udata[i] << 4) + (udata[i+1] >> 4) );
            *p++ = BASE64URL_CHAR( (udata[i+1] << 2) );
        }
    }
    *p++ = '\0';
    return (char *)enc;
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


int h2_iq_add(h2_iqueue *q, int sid, h2_iq_cmp *cmp, void *ctx)
{
    int i;
    
    if (h2_iq_contains(q, sid)) {
        return 0;
    }
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
    return 1;
}

int h2_iq_append(h2_iqueue *q, int sid)
{
    return h2_iq_add(q, sid, NULL, NULL);
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
     * best case, q->nelts - 1 comparisions to check that nothing
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

size_t h2_iq_mshift(h2_iqueue *q, int *pint, size_t max)
{
    int i;
    for (i = 0; i < max; ++i) {
        pint[i] = h2_iq_shift(q);
        if (pint[i] == 0) {
            break;
        }
    }
    return i;
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

int h2_iq_contains(h2_iqueue *q, int sid)
{
    int i;
    for (i = 0; i < q->nelts; ++i) {
        if (sid == q->elts[(q->head + i) % q->nalloc]) {
            return 1;
        }
    }
    return 0;
}

/*******************************************************************************
 * FIFO queue
 ******************************************************************************/

struct h2_fifo {
    void **elems;
    int nelems;
    int set;
    int head;
    int count;
    int aborted;
    apr_thread_mutex_t *lock;
    apr_thread_cond_t  *not_empty;
    apr_thread_cond_t  *not_full;
};

static int nth_index(h2_fifo *fifo, int n) 
{
    return (fifo->head + n) % fifo->nelems;
}

static apr_status_t fifo_destroy(void *data) 
{
    h2_fifo *fifo = data;

    apr_thread_cond_destroy(fifo->not_empty);
    apr_thread_cond_destroy(fifo->not_full);
    apr_thread_mutex_destroy(fifo->lock);

    return APR_SUCCESS;
}

static int index_of(h2_fifo *fifo, void *elem)
{
    int i;
    
    for (i = 0; i < fifo->count; ++i) {
        if (elem == fifo->elems[nth_index(fifo, i)]) {
            return i;
        }
    }
    return -1;
}

static apr_status_t create_int(h2_fifo **pfifo, apr_pool_t *pool, 
                               int capacity, int as_set)
{
    apr_status_t rv;
    h2_fifo *fifo;
    
    fifo = apr_pcalloc(pool, sizeof(*fifo));
    if (fifo == NULL) {
        return APR_ENOMEM;
    }

    rv = apr_thread_mutex_create(&fifo->lock,
                                 APR_THREAD_MUTEX_UNNESTED, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_thread_cond_create(&fifo->not_empty, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_thread_cond_create(&fifo->not_full, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    fifo->elems = apr_pcalloc(pool, capacity * sizeof(void*));
    if (fifo->elems == NULL) {
        return APR_ENOMEM;
    }
    fifo->nelems = capacity;
    fifo->set = as_set;
    
    *pfifo = fifo;
    apr_pool_cleanup_register(pool, fifo, fifo_destroy, apr_pool_cleanup_null);

    return APR_SUCCESS;
}

apr_status_t h2_fifo_create(h2_fifo **pfifo, apr_pool_t *pool, int capacity)
{
    return create_int(pfifo, pool, capacity, 0);
}

apr_status_t h2_fifo_set_create(h2_fifo **pfifo, apr_pool_t *pool, int capacity)
{
    return create_int(pfifo, pool, capacity, 1);
}

apr_status_t h2_fifo_term(h2_fifo *fifo)
{
    apr_status_t rv;
    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        fifo->aborted = 1;
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_fifo_interrupt(h2_fifo *fifo)
{
    apr_status_t rv;
    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        apr_thread_cond_broadcast(fifo->not_empty);
        apr_thread_cond_broadcast(fifo->not_full);
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

int h2_fifo_count(h2_fifo *fifo)
{
    return fifo->count;
}

static apr_status_t check_not_empty(h2_fifo *fifo, int block)
{
    while (fifo->count == 0) {
        if (!block) {
            return APR_EAGAIN;
        }
        if (fifo->aborted) {
            return APR_EOF;
        }
        apr_thread_cond_wait(fifo->not_empty, fifo->lock);
    }
    return APR_SUCCESS;
}

static apr_status_t fifo_push_int(h2_fifo *fifo, void *elem, int block)
{
    if (fifo->aborted) {
        return APR_EOF;
    }

    if (fifo->set && index_of(fifo, elem) >= 0) {
        /* set mode, elem already member */
        return APR_EEXIST;
    }
    else if (fifo->count == fifo->nelems) {
        if (block) {
            while (fifo->count == fifo->nelems) {
                if (fifo->aborted) {
                    return APR_EOF;
                }
                apr_thread_cond_wait(fifo->not_full, fifo->lock);
            }
        }
        else {
            return APR_EAGAIN;
        }
    }
    
    ap_assert(fifo->count < fifo->nelems);
    fifo->elems[nth_index(fifo, fifo->count)] = elem;
    ++fifo->count;
    if (fifo->count == 1) {
        apr_thread_cond_broadcast(fifo->not_empty);
    }
    return APR_SUCCESS;
}

static apr_status_t fifo_push(h2_fifo *fifo, void *elem, int block)
{
    apr_status_t rv;
    
    if (fifo->aborted) {
        return APR_EOF;
    }

    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        rv = fifo_push_int(fifo, elem, block);
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_fifo_push(h2_fifo *fifo, void *elem)
{
    return fifo_push(fifo, elem, 1);
}

apr_status_t h2_fifo_try_push(h2_fifo *fifo, void *elem)
{
    return fifo_push(fifo, elem, 0);
}

static apr_status_t pull_head(h2_fifo *fifo, void **pelem, int block)
{
    apr_status_t rv;
    
    if ((rv = check_not_empty(fifo, block)) != APR_SUCCESS) {
        *pelem = NULL;
        return rv;
    }
    *pelem = fifo->elems[fifo->head];
    --fifo->count;
    if (fifo->count > 0) {
        fifo->head = nth_index(fifo, 1);
        if (fifo->count+1 == fifo->nelems) {
            apr_thread_cond_broadcast(fifo->not_full);
        }
    }
    return APR_SUCCESS;
}

static apr_status_t fifo_pull(h2_fifo *fifo, void **pelem, int block)
{
    apr_status_t rv;
    
    if (fifo->aborted) {
        return APR_EOF;
    }
    
    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        rv = pull_head(fifo, pelem, block);
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_fifo_pull(h2_fifo *fifo, void **pelem)
{
    return fifo_pull(fifo, pelem, 1);
}

apr_status_t h2_fifo_try_pull(h2_fifo *fifo, void **pelem)
{
    return fifo_pull(fifo, pelem, 0);
}

static apr_status_t fifo_peek(h2_fifo *fifo, h2_fifo_peek_fn *fn, void *ctx, int block)
{
    apr_status_t rv;
    void *elem;
    
    if (fifo->aborted) {
        return APR_EOF;
    }
    
    if (APR_SUCCESS == (rv = apr_thread_mutex_lock(fifo->lock))) {
        if (APR_SUCCESS == (rv = pull_head(fifo, &elem, block))) {
            switch (fn(elem, ctx)) {
                case H2_FIFO_OP_PULL:
                    break;
                case H2_FIFO_OP_REPUSH:
                    rv = fifo_push_int(fifo, elem, block);
                    break;
            }
        }
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_fifo_peek(h2_fifo *fifo, h2_fifo_peek_fn *fn, void *ctx)
{
    return fifo_peek(fifo, fn, ctx, 1);
}

apr_status_t h2_fifo_try_peek(h2_fifo *fifo, h2_fifo_peek_fn *fn, void *ctx)
{
    return fifo_peek(fifo, fn, ctx, 0);
}

apr_status_t h2_fifo_remove(h2_fifo *fifo, void *elem)
{
    apr_status_t rv;
    
    if (fifo->aborted) {
        return APR_EOF;
    }

    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        int i, rc;
        void *e;
        
        rc = 0;
        for (i = 0; i < fifo->count; ++i) {
            e = fifo->elems[nth_index(fifo, i)];
            if (e == elem) {
                ++rc;
            }
            else if (rc) {
                fifo->elems[nth_index(fifo, i-rc)] = e;
            }
        }
        if (rc) {
            fifo->count -= rc;
            if (fifo->count + rc == fifo->nelems) {
                apr_thread_cond_broadcast(fifo->not_full);
            }
            rv = APR_SUCCESS;
        }
        else {
            rv = APR_EAGAIN;
        }
        
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

/*******************************************************************************
 * FIFO int queue
 ******************************************************************************/

struct h2_ififo {
    int *elems;
    int nelems;
    int set;
    int head;
    int count;
    int aborted;
    apr_thread_mutex_t *lock;
    apr_thread_cond_t  *not_empty;
    apr_thread_cond_t  *not_full;
};

static int inth_index(h2_ififo *fifo, int n) 
{
    return (fifo->head + n) % fifo->nelems;
}

static apr_status_t ififo_destroy(void *data) 
{
    h2_ififo *fifo = data;

    apr_thread_cond_destroy(fifo->not_empty);
    apr_thread_cond_destroy(fifo->not_full);
    apr_thread_mutex_destroy(fifo->lock);

    return APR_SUCCESS;
}

static int iindex_of(h2_ififo *fifo, int id)
{
    int i;
    
    for (i = 0; i < fifo->count; ++i) {
        if (id == fifo->elems[inth_index(fifo, i)]) {
            return i;
        }
    }
    return -1;
}

static apr_status_t icreate_int(h2_ififo **pfifo, apr_pool_t *pool, 
                                int capacity, int as_set)
{
    apr_status_t rv;
    h2_ififo *fifo;
    
    fifo = apr_pcalloc(pool, sizeof(*fifo));
    if (fifo == NULL) {
        return APR_ENOMEM;
    }

    rv = apr_thread_mutex_create(&fifo->lock,
                                 APR_THREAD_MUTEX_UNNESTED, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_thread_cond_create(&fifo->not_empty, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_thread_cond_create(&fifo->not_full, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    fifo->elems = apr_pcalloc(pool, capacity * sizeof(int));
    if (fifo->elems == NULL) {
        return APR_ENOMEM;
    }
    fifo->nelems = capacity;
    fifo->set = as_set;
    
    *pfifo = fifo;
    apr_pool_cleanup_register(pool, fifo, ififo_destroy, apr_pool_cleanup_null);

    return APR_SUCCESS;
}

apr_status_t h2_ififo_create(h2_ififo **pfifo, apr_pool_t *pool, int capacity)
{
    return icreate_int(pfifo, pool, capacity, 0);
}

apr_status_t h2_ififo_set_create(h2_ififo **pfifo, apr_pool_t *pool, int capacity)
{
    return icreate_int(pfifo, pool, capacity, 1);
}

apr_status_t h2_ififo_term(h2_ififo *fifo)
{
    apr_status_t rv;
    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        fifo->aborted = 1;
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_ififo_interrupt(h2_ififo *fifo)
{
    apr_status_t rv;
    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        apr_thread_cond_broadcast(fifo->not_empty);
        apr_thread_cond_broadcast(fifo->not_full);
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

int h2_ififo_count(h2_ififo *fifo)
{
    return fifo->count;
}

static apr_status_t icheck_not_empty(h2_ififo *fifo, int block)
{
    while (fifo->count == 0) {
        if (!block) {
            return APR_EAGAIN;
        }
        if (fifo->aborted) {
            return APR_EOF;
        }
        apr_thread_cond_wait(fifo->not_empty, fifo->lock);
    }
    return APR_SUCCESS;
}

static apr_status_t ififo_push_int(h2_ififo *fifo, int id, int block)
{
    if (fifo->aborted) {
        return APR_EOF;
    }

    if (fifo->set && iindex_of(fifo, id) >= 0) {
        /* set mode, elem already member */
        return APR_EEXIST;
    }
    else if (fifo->count == fifo->nelems) {
        if (block) {
            while (fifo->count == fifo->nelems) {
                if (fifo->aborted) {
                    return APR_EOF;
                }
                apr_thread_cond_wait(fifo->not_full, fifo->lock);
            }
        }
        else {
            return APR_EAGAIN;
        }
    }
    
    ap_assert(fifo->count < fifo->nelems);
    fifo->elems[inth_index(fifo, fifo->count)] = id;
    ++fifo->count;
    if (fifo->count == 1) {
        apr_thread_cond_broadcast(fifo->not_empty);
    }
    return APR_SUCCESS;
}

static apr_status_t ififo_push(h2_ififo *fifo, int id, int block)
{
    apr_status_t rv;
    
    if (fifo->aborted) {
        return APR_EOF;
    }

    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        rv = ififo_push_int(fifo, id, block);
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_ififo_push(h2_ififo *fifo, int id)
{
    return ififo_push(fifo, id, 1);
}

apr_status_t h2_ififo_try_push(h2_ififo *fifo, int id)
{
    return ififo_push(fifo, id, 0);
}

static apr_status_t ipull_head(h2_ififo *fifo, int *pi, int block)
{
    apr_status_t rv;
    
    if ((rv = icheck_not_empty(fifo, block)) != APR_SUCCESS) {
        *pi = 0;
        return rv;
    }
    *pi = fifo->elems[fifo->head];
    --fifo->count;
    if (fifo->count > 0) {
        fifo->head = inth_index(fifo, 1);
        if (fifo->count+1 == fifo->nelems) {
            apr_thread_cond_broadcast(fifo->not_full);
        }
    }
    return APR_SUCCESS;
}

static apr_status_t ififo_pull(h2_ififo *fifo, int *pi, int block)
{
    apr_status_t rv;
    
    if (fifo->aborted) {
        return APR_EOF;
    }
    
    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        rv = ipull_head(fifo, pi, block);
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_ififo_pull(h2_ififo *fifo, int *pi)
{
    return ififo_pull(fifo, pi, 1);
}

apr_status_t h2_ififo_try_pull(h2_ififo *fifo, int *pi)
{
    return ififo_pull(fifo, pi, 0);
}

static apr_status_t ififo_peek(h2_ififo *fifo, h2_ififo_peek_fn *fn, void *ctx, int block)
{
    apr_status_t rv;
    int id;
    
    if (fifo->aborted) {
        return APR_EOF;
    }
    
    if (APR_SUCCESS == (rv = apr_thread_mutex_lock(fifo->lock))) {
        if (APR_SUCCESS == (rv = ipull_head(fifo, &id, block))) {
            switch (fn(id, ctx)) {
                case H2_FIFO_OP_PULL:
                    break;
                case H2_FIFO_OP_REPUSH:
                    rv = ififo_push_int(fifo, id, block);
                    break;
            }
        }
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

apr_status_t h2_ififo_peek(h2_ififo *fifo, h2_ififo_peek_fn *fn, void *ctx)
{
    return ififo_peek(fifo, fn, ctx, 1);
}

apr_status_t h2_ififo_try_peek(h2_ififo *fifo, h2_ififo_peek_fn *fn, void *ctx)
{
    return ififo_peek(fifo, fn, ctx, 0);
}

apr_status_t h2_ififo_remove(h2_ififo *fifo, int id)
{
    apr_status_t rv;
    
    if (fifo->aborted) {
        return APR_EOF;
    }

    if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
        int i, rc;
        int e;
        
        rc = 0;
        for (i = 0; i < fifo->count; ++i) {
            e = fifo->elems[inth_index(fifo, i)];
            if (e == id) {
                ++rc;
            }
            else if (rc) {
                fifo->elems[inth_index(fifo, i-rc)] = e;
            }
        }
        if (rc) {
            fifo->count -= rc;
            if (fifo->count + rc == fifo->nelems) {
                apr_thread_cond_broadcast(fifo->not_full);
            }
            rv = APR_SUCCESS;
        }
        else {
            rv = APR_EAGAIN;
        }
        
        apr_thread_mutex_unlock(fifo->lock);
    }
    return rv;
}

/*******************************************************************************
 * h2_util for apt_table_t
 ******************************************************************************/
 
typedef struct {
    apr_size_t bytes;
    apr_size_t pair_extra;
} table_bytes_ctx;

static int count_bytes(void *x, const char *key, const char *value)
{
    table_bytes_ctx *ctx = x;
    if (key) {
        ctx->bytes += strlen(key);
    }
    if (value) {
        ctx->bytes += strlen(value);
    }
    ctx->bytes += ctx->pair_extra;
    return 1;
}

apr_size_t h2_util_table_bytes(apr_table_t *t, apr_size_t pair_extra)
{
    table_bytes_ctx ctx;
    
    ctx.bytes = 0;
    ctx.pair_extra = pair_extra;
    apr_table_do(count_bytes, &ctx, t, NULL);
    return ctx.bytes;
}


/*******************************************************************************
 * h2_util for bucket brigades
 ******************************************************************************/

static apr_status_t last_not_included(apr_bucket_brigade *bb, 
                                      apr_off_t maxlen, 
                                      int same_alloc,
                                      apr_size_t *pfile_buckets_allowed,
                                      apr_bucket **pend)
{
    apr_bucket *b;
    apr_status_t status = APR_SUCCESS;
    int files_allowed = pfile_buckets_allowed? (int)*pfile_buckets_allowed : 0;
    
    if (maxlen >= 0) {
        /* Find the bucket, up to which we reach maxlen/mem bytes */
        for (b = APR_BRIGADE_FIRST(bb); 
             (b != APR_BRIGADE_SENTINEL(bb));
             b = APR_BUCKET_NEXT(b)) {
            
            if (APR_BUCKET_IS_METADATA(b)) {
                /* included */
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    const char *ign;
                    apr_size_t ilen;
                    status = apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (status != APR_SUCCESS) {
                        return status;
                    }
                }
                
                if (maxlen == 0 && b->length > 0) {
                    *pend = b;
                    return status;
                }
                
                if (same_alloc && APR_BUCKET_IS_FILE(b)) {
                    /* we like it move it, always */
                }
                else if (files_allowed > 0 && APR_BUCKET_IS_FILE(b)) {
                    /* this has no memory footprint really unless
                     * it is read, disregard it in length count,
                     * unless we do not move the file buckets */
                    --files_allowed;
                }
                else if (maxlen < (apr_off_t)b->length) {
                    apr_bucket_split(b, (apr_size_t)maxlen);
                    maxlen = 0;
                }
                else {
                    maxlen -= b->length;
                }
            }
        }
    }
    *pend = APR_BRIGADE_SENTINEL(bb);
    return status;
}

apr_status_t h2_brigade_concat_length(apr_bucket_brigade *dest, 
                                      apr_bucket_brigade *src,
                                      apr_off_t length)
{
    apr_bucket *b;
    apr_off_t remain = length;
    apr_status_t status = APR_SUCCESS;
    
    while (!APR_BRIGADE_EMPTY(src)) {
        b = APR_BRIGADE_FIRST(src); 
        
        if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(dest, b);
        }
        else {
            if (remain == b->length) {
                /* fall through */
            }
            else if (remain <= 0) {
                return status;
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    const char *ign;
                    apr_size_t ilen;
                    status = apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (status != APR_SUCCESS) {
                        return status;
                    }
                }
            
                if (remain < b->length) {
                    apr_bucket_split(b, remain);
                }
            }
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(dest, b);
            remain -= b->length;
        }
    }
    return status;
}

apr_status_t h2_brigade_copy_length(apr_bucket_brigade *dest, 
                                    apr_bucket_brigade *src,
                                    apr_off_t length)
{
    apr_bucket *b, *next;
    apr_off_t remain = length;
    apr_status_t status = APR_SUCCESS;
    
    for (b = APR_BRIGADE_FIRST(src); 
         b != APR_BRIGADE_SENTINEL(src);
         b = next) {
        next = APR_BUCKET_NEXT(b);
        
        if (APR_BUCKET_IS_METADATA(b)) {
            /* fall through */
        }
        else {
            if (remain == b->length) {
                /* fall through */
            }
            else if (remain <= 0) {
                return status;
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    const char *ign;
                    apr_size_t ilen;
                    status = apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (status != APR_SUCCESS) {
                        return status;
                    }
                }
            
                if (remain < b->length) {
                    apr_bucket_split(b, remain);
                }
            }
        }
        status = apr_bucket_copy(b, &b);
        if (status != APR_SUCCESS) {
            return status;
        }
        APR_BRIGADE_INSERT_TAIL(dest, b);
        remain -= b->length;
    }
    return status;
}

int h2_util_has_eos(apr_bucket_brigade *bb, apr_off_t len)
{
    apr_bucket *b, *end;
    
    apr_status_t status = last_not_included(bb, len, 0, 0, &end);
    if (status != APR_SUCCESS) {
        return status;
    }
    
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb) && b != end;
         b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_EOS(b)) {
            return 1;
        }
    }
    return 0;
}

apr_status_t h2_util_bb_avail(apr_bucket_brigade *bb, 
                              apr_off_t *plen, int *peos)
{
    apr_status_t status;
    apr_off_t blen = 0;

    /* test read to determine available length */
    status = apr_brigade_length(bb, 1, &blen);
    if (status != APR_SUCCESS) {
        return status;
    }
    else if (blen == 0) {
        /* brigade without data, does it have an EOS bucket somwhere? */
        *plen = 0;
        *peos = h2_util_has_eos(bb, -1);
    }
    else {
        /* data in the brigade, limit the length returned. Check for EOS
         * bucket only if we indicate data. This is required since plen == 0
         * means "the whole brigade" for h2_util_hash_eos()
         */
        if (blen < *plen || *plen < 0) {
            *plen = blen;
        }
        *peos = h2_util_has_eos(bb, *plen);
    }
    return APR_SUCCESS;
}

apr_status_t h2_util_bb_readx(apr_bucket_brigade *bb, 
                              h2_util_pass_cb *cb, void *ctx, 
                              apr_off_t *plen, int *peos)
{
    apr_status_t status = APR_SUCCESS;
    int consume = (cb != NULL);
    apr_off_t written = 0;
    apr_off_t avail = *plen;
    apr_bucket *next, *b;
    
    /* Pass data in our brigade through the callback until the length
     * is satisfied or we encounter an EOS.
     */
    *peos = 0;
    for (b = APR_BRIGADE_FIRST(bb);
         (status == APR_SUCCESS) && (b != APR_BRIGADE_SENTINEL(bb));
         b = next) {
        
        if (APR_BUCKET_IS_METADATA(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                *peos = 1;
            }
            else {
                /* ignore */
            }
        }
        else if (avail <= 0) {
            break;
        } 
        else {
            const char *data = NULL;
            apr_size_t data_len;
            
            if (b->length == ((apr_size_t)-1)) {
                /* read to determine length */
                status = apr_bucket_read(b, &data, &data_len, APR_NONBLOCK_READ);
            }
            else {
                data_len = b->length;
            }
            
            if (data_len > avail) {
                apr_bucket_split(b, avail);
                data_len = (apr_size_t)avail;
            }
            
            if (consume) {
                if (!data) {
                    status = apr_bucket_read(b, &data, &data_len, 
                                             APR_NONBLOCK_READ);
                }
                if (status == APR_SUCCESS) {
                    status = cb(ctx, data, data_len);
                }
            }
            else {
                data_len = b->length;
            }
            avail -= data_len;
            written += data_len;
        }
        
        next = APR_BUCKET_NEXT(b);
        if (consume) {
            apr_bucket_delete(b);
        }
    }
    
    *plen = written;
    if (status == APR_SUCCESS && !*peos && !*plen) {
        return APR_EAGAIN;
    }
    return status;
}

apr_size_t h2_util_bucket_print(char *buffer, apr_size_t bmax, 
                                apr_bucket *b, const char *sep)
{
    apr_size_t off = 0;
    if (sep && *sep) {
        off += apr_snprintf(buffer+off, bmax-off, "%s", sep);
    }
    
    if (bmax <= off) {
        return off;
    }
    else if (APR_BUCKET_IS_METADATA(b)) {
        off += apr_snprintf(buffer+off, bmax-off, "%s", b->type->name);
    }
    else if (bmax > off) {
        off += apr_snprintf(buffer+off, bmax-off, "%s[%ld]", 
                            b->type->name, 
                            (long)(b->length == ((apr_size_t)-1)? 
                                   -1 : b->length));
    }
    return off;
}

apr_size_t h2_util_bb_print(char *buffer, apr_size_t bmax, 
                            const char *tag, const char *sep, 
                            apr_bucket_brigade *bb)
{
    apr_size_t off = 0;
    const char *sp = "";
    apr_bucket *b;
    
    if (bmax > 1) {
        if (bb) {
            memset(buffer, 0, bmax--);
            off += apr_snprintf(buffer+off, bmax-off, "%s(", tag);
            for (b = APR_BRIGADE_FIRST(bb); 
                 (bmax > off) && (b != APR_BRIGADE_SENTINEL(bb));
                 b = APR_BUCKET_NEXT(b)) {
                
                off += h2_util_bucket_print(buffer+off, bmax-off, b, sp);
                sp = " ";
            }
            if (bmax > off) {
                off += apr_snprintf(buffer+off, bmax-off, ")%s", sep);
            }
        }
        else {
            off += apr_snprintf(buffer+off, bmax-off, "%s(null)%s", tag, sep);
        }
    }
    return off;
}

apr_status_t h2_append_brigade(apr_bucket_brigade *to,
                               apr_bucket_brigade *from, 
                               apr_off_t *plen,
                               int *peos,
                               h2_bucket_gate *should_append)
{
    apr_bucket *e;
    apr_off_t len = 0, remain = *plen;
    apr_status_t rv;

    *peos = 0;
    
    while (!APR_BRIGADE_EMPTY(from)) {
        e = APR_BRIGADE_FIRST(from);
        
        if (!should_append(e)) {
            goto leave;
        }
        else if (APR_BUCKET_IS_METADATA(e)) {
            if (APR_BUCKET_IS_EOS(e)) {
                *peos = 1;
                apr_bucket_delete(e);
                continue;
            }
        }
        else {        
            if (remain > 0 && e->length == ((apr_size_t)-1)) {
                const char *ign;
                apr_size_t ilen;
                rv = apr_bucket_read(e, &ign, &ilen, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
            }
            
            if (remain < e->length) {
                if (remain <= 0) {
                    goto leave;
                }
                apr_bucket_split(e, (apr_size_t)remain);
            }
        }
        
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(to, e);
        len += e->length;
        remain -= e->length;
    }
leave:
    *plen = len;
    return APR_SUCCESS;
}

apr_off_t h2_brigade_mem_size(apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_off_t total = 0;

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        total += sizeof(*b);
        if (b->length > 0) {
            if (APR_BUCKET_IS_HEAP(b)
                || APR_BUCKET_IS_POOL(b)) {
                total += b->length;
            }
        }
    }
    return total;
}


/*******************************************************************************
 * h2_ngheader
 ******************************************************************************/
 
int h2_util_ignore_header(const char *name) 
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

static const char *inv_field_name_chr(const char *token)
{
    const char *p = ap_scan_http_token(token);
    if (p == token && *p == ':') {
        p = ap_scan_http_token(++p);
    }
    return (p && *p)? p : NULL;
}

static const char *inv_field_value_chr(const char *token)
{
    const char *p = ap_scan_http_field_content(token);
    return (p && *p)? p : NULL;
}

typedef struct ngh_ctx {
    apr_pool_t *p;
    int unsafe;
    h2_ngheader *ngh;
    apr_status_t status;
} ngh_ctx;

static int add_header(ngh_ctx *ctx, const char *key, const char *value)
{
    nghttp2_nv *nv = &(ctx->ngh)->nv[(ctx->ngh)->nvlen++];
    const char *p;

    if (!ctx->unsafe) {
        if ((p = inv_field_name_chr(key))) {
            ap_log_perror(APLOG_MARK, APLOG_TRACE1, APR_EINVAL, ctx->p,
                          "h2_request: head field '%s: %s' has invalid char %s", 
                          key, value, p);
            ctx->status = APR_EINVAL;
            return 0;
        }
        if ((p = inv_field_value_chr(value))) {
            ap_log_perror(APLOG_MARK, APLOG_TRACE1, APR_EINVAL, ctx->p,
                          "h2_request: head field '%s: %s' has invalid char %s", 
                          key, value, p);
            ctx->status = APR_EINVAL;
            return 0;
        }
    }
    nv->name = (uint8_t*)key;
    nv->namelen = strlen(key);
    nv->value = (uint8_t*)value;
    nv->valuelen = strlen(value);
    
    return 1;
}

static int add_table_header(void *ctx, const char *key, const char *value)
{
    if (!h2_util_ignore_header(key)) {
        add_header(ctx, key, value);
    }
    return 1;
}

static apr_status_t ngheader_create(h2_ngheader **ph, apr_pool_t *p, 
                                    int unsafe, size_t key_count, 
                                    const char *keys[], const char *values[],
                                    apr_table_t *headers)
{
    ngh_ctx ctx;
    size_t n, i;
    
    ctx.p = p;
    ctx.unsafe = unsafe;
    
    n = key_count;
    apr_table_do(count_header, &n, headers, NULL);
    
    *ph = ctx.ngh = apr_pcalloc(p, sizeof(h2_ngheader));
    if (!ctx.ngh) {
        return APR_ENOMEM;
    }
    
    ctx.ngh->nv =  apr_pcalloc(p, n * sizeof(nghttp2_nv));
    if (!ctx.ngh->nv) {
        return APR_ENOMEM;
    }
    
    ctx.status = APR_SUCCESS;
    for (i = 0; i < key_count; ++i) {
        if (!add_header(&ctx, keys[i], values[i])) {
            return ctx.status;
        }
    }
    
    apr_table_do(add_table_header, &ctx, headers, NULL);

    return ctx.status;
}

static int is_unsafe(h2_headers *h)
{
    const char *v = apr_table_get(h->notes, H2_HDR_CONFORMANCE);
    return (v && !strcmp(v, H2_HDR_CONFORMANCE_UNSAFE));
}

apr_status_t h2_res_create_ngtrailer(h2_ngheader **ph, apr_pool_t *p, 
                                    h2_headers *headers)
{
    return ngheader_create(ph, p, is_unsafe(headers), 
                           0, NULL, NULL, headers->headers);
}
                                     
apr_status_t h2_res_create_ngheader(h2_ngheader **ph, apr_pool_t *p,
                                    h2_headers *headers) 
{
    const char *keys[] = {
        ":status"
    };
    const char *values[] = {
        apr_psprintf(p, "%d", headers->status)
    };
    return ngheader_create(ph, p, is_unsafe(headers),  
                           H2_ALEN(keys), keys, values, headers->headers);
}

apr_status_t h2_req_create_ngheader(h2_ngheader **ph, apr_pool_t *p, 
                                    const struct h2_request *req)
{
    
    const char *keys[] = {
        ":scheme", 
        ":authority", 
        ":path", 
        ":method", 
    };
    const char *values[] = {
        req->scheme,
        req->authority, 
        req->path, 
        req->method, 
    };
    
    ap_assert(req->scheme);
    ap_assert(req->authority);
    ap_assert(req->path);
    ap_assert(req->method);

    return ngheader_create(ph, p, 0, H2_ALEN(keys), keys, values, req->headers);
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
    H2_DEF_LITERAL("upgrade"),
    H2_DEF_LITERAL("connection"),
    H2_DEF_LITERAL("keep-alive"),
    H2_DEF_LITERAL("http2-settings"),
    H2_DEF_LITERAL("proxy-connection"),
    H2_DEF_LITERAL("transfer-encoding"),
};
static literal IgnoredRequestTrailers[] = { /* Ignore, see rfc7230, ch. 4.1.2 */
    H2_DEF_LITERAL("te"),
    H2_DEF_LITERAL("host"),
    H2_DEF_LITERAL("range"),
    H2_DEF_LITERAL("cookie"),
    H2_DEF_LITERAL("expect"),
    H2_DEF_LITERAL("pragma"),
    H2_DEF_LITERAL("max-forwards"),
    H2_DEF_LITERAL("cache-control"),
    H2_DEF_LITERAL("authorization"),
    H2_DEF_LITERAL("content-length"),       
    H2_DEF_LITERAL("proxy-authorization"),
};    
static literal IgnoredResponseTrailers[] = {
    H2_DEF_LITERAL("age"),
    H2_DEF_LITERAL("date"),
    H2_DEF_LITERAL("vary"),
    H2_DEF_LITERAL("cookie"),
    H2_DEF_LITERAL("expires"),
    H2_DEF_LITERAL("warning"),
    H2_DEF_LITERAL("location"),
    H2_DEF_LITERAL("retry-after"),
    H2_DEF_LITERAL("cache-control"),
    H2_DEF_LITERAL("www-authenticate"),
    H2_DEF_LITERAL("proxy-authenticate"),
};

static int ignore_header(const literal *lits, size_t llen,
                         const char *name, size_t nlen)
{
    const literal *lit;
    size_t i;
    
    for (i = 0; i < llen; ++i) {
        lit = &lits[i];
        if (lit->len == nlen && !apr_strnatcasecmp(lit->name, name)) {
            return 1;
        }
    }
    return 0;
}

int h2_req_ignore_header(const char *name, size_t len)
{
    return ignore_header(H2_LIT_ARGS(IgnoredRequestHeaders), name, len);
}

int h2_req_ignore_trailer(const char *name, size_t len)
{
    return (h2_req_ignore_header(name, len) 
            || ignore_header(H2_LIT_ARGS(IgnoredRequestTrailers), name, len));
}

int h2_res_ignore_trailer(const char *name, size_t len)
{
    return ignore_header(H2_LIT_ARGS(IgnoredResponseTrailers), name, len);
}

apr_status_t h2_req_add_header(apr_table_t *headers, apr_pool_t *pool, 
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

/*******************************************************************************
 * h2 request handling
 ******************************************************************************/

h2_request *h2_req_create(int id, apr_pool_t *pool, const char *method, 
                          const char *scheme, const char *authority, 
                          const char *path, apr_table_t *header, int serialize)
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

/*******************************************************************************
 * push policy
 ******************************************************************************/
int h2_push_policy_determine(apr_table_t *headers, apr_pool_t *p, int push_enabled)
{
    h2_push_policy policy = H2_PUSH_NONE;
    if (push_enabled) {
        const char *val = apr_table_get(headers, "accept-push-policy");
        if (val) {
            if (ap_find_token(p, val, "fast-load")) {
                policy = H2_PUSH_FAST_LOAD;
            }
            else if (ap_find_token(p, val, "head")) {
                policy = H2_PUSH_HEAD;
            }
            else if (ap_find_token(p, val, "default")) {
                policy = H2_PUSH_DEFAULT;
            }
            else if (ap_find_token(p, val, "none")) {
                policy = H2_PUSH_NONE;
            }
            else {
                /* nothing known found in this header, go by default */
                policy = H2_PUSH_DEFAULT;
            }
        }
        else {
            policy = H2_PUSH_DEFAULT;
        }
    }
    return policy;
}

