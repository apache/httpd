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

#include "h2_private.h"
#include "h2_request.h"
#include "h2_util.h"

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

static const int BASE64URL_UINT6[] = {
/*   0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f        */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  0 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  1 */ 
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, /*  2 */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /*  3 */ 
    -1, 0,  1,  2,  3,  4,  5,  6,   7,  8,  9, 10, 11, 12, 13, 14, /*  4 */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, /*  5 */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*  6 */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*  7 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  8 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  9 */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  a */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  b */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  c */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  d */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*  e */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /*  f */
};
static const char BASE64URL_CHARS[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', /*  0 -  9 */
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', /* 10 - 19 */
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', /* 20 - 29 */
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', /* 30 - 39 */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', /* 40 - 49 */
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', /* 50 - 59 */
    '8', '9', '-', '_', ' ', ' ', ' ', ' ', ' ', ' ', /* 60 - 69 */
};

apr_size_t h2_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool)
{
    const unsigned char *e = (const unsigned char *)encoded;
    const unsigned char *p = e;
    unsigned char *d;
    int n;
    apr_size_t len, mlen, remain, i;
    
    while (*p && BASE64URL_UINT6[ *p ] != -1) {
        ++p;
    }
    len = p - e;
    mlen = (len/4)*4;
    *decoded = apr_pcalloc(pool, len+1);
    
    i = 0;
    d = (unsigned char*)*decoded;
    for (; i < mlen; i += 4) {
        n = ((BASE64URL_UINT6[ e[i+0] ] << 18) +
             (BASE64URL_UINT6[ e[i+1] ] << 12) +
             (BASE64URL_UINT6[ e[i+2] ] << 6) +
             (BASE64URL_UINT6[ e[i+3] ]));
        *d++ = n >> 16;
        *d++ = n >> 8 & 0xffu;
        *d++ = n & 0xffu;
    }
    remain = len - mlen;
    switch (remain) {
        case 2:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12));
            *d++ = n >> 16;
            break;
        case 3:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12) +
                 (BASE64URL_UINT6[ e[mlen+2] ] << 6));
            *d++ = n >> 16;
            *d++ = n >> 8 & 0xffu;
            break;
        default: /* do nothing */
            break;
    }
    return mlen/4*3 + remain;
}

const char *h2_util_base64url_encode(const char *data, 
                                     apr_size_t len, apr_pool_t *pool)
{
    apr_size_t mlen = ((len+2)/3)*3;
    apr_size_t slen = (mlen/3)*4;
    apr_size_t i;
    const unsigned char *udata = (const unsigned char*)data;
    char *enc, *p = apr_pcalloc(pool, slen+1); /* 0 terminated */
    
    enc = p;
    for (i = 0; i < mlen; i+= 3) {
        *p++ = BASE64URL_CHARS[ (udata[i] >> 2) & 0x3fu ];
        *p++ = BASE64URL_CHARS[ ((udata[i] << 4) + 
                                 ((i+1 < len)? (udata[i+1] >> 4) : 0)) & 0x3fu ];
        *p++ = BASE64URL_CHARS[ ((udata[i+1] << 2) + 
                                 ((i+2 < len)? (udata[i+2] >> 6) : 0)) & 0x3fu ];
        if (i+2 < len) {
            *p++ = BASE64URL_CHARS[ udata[i+2] & 0x3fu ];
        }
    }
    
    return enc;
}

int h2_util_contains_token(apr_pool_t *pool, const char *s, const char *token)
{
    char *c;
    if (s) {
        if (!apr_strnatcasecmp(s, token)) {   /* the simple life */
            return 1;
        }
        
        for (c = ap_get_token(pool, &s, 0); c && *c;
             c = *s? ap_get_token(pool, &s, 0) : NULL) {
            if (!apr_strnatcasecmp(c, token)) { /* seeing the token? */
                return 1;
            }
            while (*s++ == ';') {            /* skip parameters */
                ap_get_token(pool, &s, 0);
            }
            if (*s++ != ',') {               /* need comma separation */
                return 0;
            }
        }
    }
    return 0;
}

const char *h2_util_first_token_match(apr_pool_t *pool, const char *s, 
                                      const char *tokens[], apr_size_t len)
{
    char *c;
    apr_size_t i;
    if (s && *s) {
        for (c = ap_get_token(pool, &s, 0); c && *c;
             c = *s? ap_get_token(pool, &s, 0) : NULL) {
            for (i = 0; i < len; ++i) {
                if (!apr_strnatcasecmp(c, tokens[i])) {
                    return tokens[i];
                }
            }
            while (*s++ == ';') {            /* skip parameters */
                ap_get_token(pool, &s, 0);
            }
            if (*s++ != ',') {               /* need comma separation */
                return 0;
            }
        }
    }
    return NULL;
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

int h2_ihash_is_empty(h2_ihash_t *ih)
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

void h2_ihash_clear(h2_ihash_t *ih)
{
    apr_hash_clear(ih->hash);
}

/*******************************************************************************
 * ilist - sorted list for structs with int identifier
 ******************************************************************************/

#define h2_ilist_IDX(list, i) ((int**)(list)->elts)[i]

struct h2_ilist_t {
    apr_array_header_t *l;
};

h2_ilist_t *h2_ilist_create(apr_pool_t *pool)
{
    h2_ilist_t *list = apr_pcalloc(pool, sizeof(h2_ilist_t));
    if (list) {
        list->l = apr_array_make(pool, 100, sizeof(int*));
        if (!list->l) {
            return NULL;
        }
    }
    return list;
}

static int h2_ilist_cmp(const void *s1, const void *s2)
{
    int **pi1 = (int **)s1;
    int **pi2 = (int **)s2;
    return *(*pi1) - *(*pi2);
}

void *h2_ilist_get(h2_ilist_t *list, int id)
{
    /* we keep the array sorted by id, so lookup can be done
     * by bsearch.
     */
    int **pi;
    int *pkey = &id;

    pi = bsearch(&pkey, list->l->elts, list->l->nelts, 
                 list->l->elt_size, h2_ilist_cmp);
    return pi? *pi : NULL;
}

static void h2_ilist_sort(h2_ilist_t *list)
{
    qsort(list->l->elts, list->l->nelts, list->l->elt_size, h2_ilist_cmp);
}

apr_status_t h2_ilist_add(h2_ilist_t *list, void *val)
{
    int *pi = val;
    void *existing = h2_ilist_get(list, *pi);
    if (!existing) {
        int last;
        APR_ARRAY_PUSH(list->l, void*) = val;
        /* Often, values get added in ascending order of id. We
         * keep the array sorted, so we just need to check if the newly
         * appended stream has a lower id than the last one. if not,
         * sorting is not necessary.
         */
        last = list->l->nelts - 1;
        if (last > 0 
            && *h2_ilist_IDX(list->l, last) < *h2_ilist_IDX(list->l, last-1)) {
            h2_ilist_sort(list);
        }
    }
    return APR_SUCCESS;
}

static void remove_idx(h2_ilist_t *list, int idx)
{
    int n;
    --list->l->nelts;
    n = list->l->nelts - idx;
    if (n > 0) {
        /* There are n h2_io* behind idx. Move the rest down */
        int **selts = (int**)list->l->elts;
        memmove(selts + idx, selts + idx + 1, n * sizeof(int*));
    }
}

void *h2_ilist_remove(h2_ilist_t *list, int id)
{
    int i;
    for (i = 0; i < list->l->nelts; ++i) {
        int *e = h2_ilist_IDX(list->l, i);
        if (id == *e) {
            remove_idx(list, i);
            return e;
        }
    }
    return NULL;
}

void *h2_ilist_shift(h2_ilist_t *list)
{
    if (list->l->nelts > 0) {
        int *pi = h2_ilist_IDX(list->l, 0);
        remove_idx(list, 0);
        return pi;
    }
    return NULL;
}

int h2_ilist_empty(h2_ilist_t *list)
{
    return list->l->nelts == 0;
}

int h2_ilist_iter(h2_ilist_t *list, h2_ilist_iter_t *iter, void *ctx)
{
    int i;
    for (i = 0; i < list->l->nelts; ++i) {
        int *pi = h2_ilist_IDX(list->l, i);
        if (!iter(ctx, pi)) {
            return 0;
        }
    }
    return 1;
}

apr_size_t h2_ilist_count(h2_ilist_t *list)
{
    return list->l->nelts;
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
    int files_allowed = pfile_buckets_allowed? *pfile_buckets_allowed : 0;
    
    if (maxlen >= 0) {
        /* Find the bucket, up to which we reach maxlen/mem bytes */
        for (b = APR_BRIGADE_FIRST(bb); 
             (b != APR_BRIGADE_SENTINEL(bb));
             b = APR_BUCKET_NEXT(b)) {
            
            if (APR_BUCKET_IS_METADATA(b)) {
                /* included */
            }
            else {
                if (maxlen == 0) {
                    *pend = b;
                    return status;
                }
                
                if (b->length == ((apr_size_t)-1)) {
                    const char *ign;
                    apr_size_t ilen;
                    status = apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (status != APR_SUCCESS) {
                        return status;
                    }
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
                else if (maxlen < b->length) {
                    apr_bucket_split(b, maxlen);
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
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(dest, b);
        remain -= b->length;
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

int h2_util_bb_has_data(apr_bucket_brigade *bb)
{
    apr_bucket *b;
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (!AP_BUCKET_IS_EOR(b)) {
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
                data_len = avail;
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
    
    if (APR_BUCKET_IS_METADATA(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            off += apr_snprintf(buffer+off, bmax-off, "eos");
        }
        else if (APR_BUCKET_IS_FLUSH(b)) {
            off += apr_snprintf(buffer+off, bmax-off, "flush");
        }
        else if (AP_BUCKET_IS_EOR(b)) {
            off += apr_snprintf(buffer+off, bmax-off, "eor");
        }
        else {
            off += apr_snprintf(buffer+off, bmax-off, "meta(unknown)");
        }
    }
    else {
        const char *btype = "data";
        if (APR_BUCKET_IS_FILE(b)) {
            btype = "file";
        }
        else if (APR_BUCKET_IS_PIPE(b)) {
            btype = "pipe";
        }
        else if (APR_BUCKET_IS_SOCKET(b)) {
            btype = "socket";
        }
        else if (APR_BUCKET_IS_HEAP(b)) {
            btype = "heap";
        }
        else if (APR_BUCKET_IS_TRANSIENT(b)) {
            btype = "transient";
        }
        else if (APR_BUCKET_IS_IMMORTAL(b)) {
            btype = "immortal";
        }
#if APR_HAS_MMAP
        else if (APR_BUCKET_IS_MMAP(b)) {
            btype = "mmap";
        }
#endif
        else if (APR_BUCKET_IS_POOL(b)) {
            btype = "pool";
        }
        
        off += apr_snprintf(buffer+off, bmax-off, "%s[%ld]", 
                            btype, 
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
    
    if (bb) {
        memset(buffer, 0, bmax--);
        off += apr_snprintf(buffer+off, bmax-off, "%s(", tag);
        for (b = APR_BRIGADE_FIRST(bb); 
             bmax && (b != APR_BRIGADE_SENTINEL(bb));
             b = APR_BUCKET_NEXT(b)) {
            
            off += h2_util_bucket_print(buffer+off, bmax-off, b, sp);
            sp = " ";
        }
        off += apr_snprintf(buffer+off, bmax-off, ")%s", sep);
    }
    else {
        off += apr_snprintf(buffer+off, bmax-off, "%s(null)%s", tag, sep);
    }
    return off;
}

void h2_util_bb_log(conn_rec *c, int stream_id, int level, 
                    const char *tag, apr_bucket_brigade *bb)
{
    char buffer[4 * 1024];
    const char *line = "(null)";
    apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
    
    len = h2_util_bb_print(buffer, bmax, tag, "", bb);
    /* Intentional no APLOGNO */
    ap_log_cerror(APLOG_MARK, level, 0, c, "bb_dump(%ld-%d): %s", 
                  c->id, stream_id, len? buffer : line);
}

apr_status_t h2_append_brigade(apr_bucket_brigade *to,
                               apr_bucket_brigade *from, 
                               apr_off_t *plen,
                               int *peos)
{
    apr_bucket *e;
    apr_off_t len = 0, remain = *plen;
    apr_status_t rv;

    *peos = 0;
    
    while (!APR_BRIGADE_EMPTY(from)) {
        e = APR_BRIGADE_FIRST(from);
        
        if (APR_BUCKET_IS_METADATA(e)) {
            if (APR_BUCKET_IS_EOS(e)) {
                *peos = 1;
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
                    return APR_SUCCESS;
                }
                apr_bucket_split(e, remain);
            }
        }
        
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(to, e);
        len += e->length;
        remain -= e->length;
    }
    
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


h2_ngheader *h2_util_ngheader_make(apr_pool_t *p, apr_table_t *header)
{
    h2_ngheader *ngh;
    size_t n;
    
    n = 0;
    apr_table_do(count_header, &n, header, NULL);
    
    ngh = apr_pcalloc(p, sizeof(h2_ngheader));
    ngh->nv =  apr_pcalloc(p, n * sizeof(nghttp2_nv));
    apr_table_do(add_table_header, ngh, header, NULL);

    return ngh;
}

h2_ngheader *h2_util_ngheader_make_res(apr_pool_t *p, 
                                       int http_status, 
                                       apr_table_t *header)
{
    h2_ngheader *ngh;
    size_t n;
    
    n = 1;
    apr_table_do(count_header, &n, header, NULL);
    
    ngh = apr_pcalloc(p, sizeof(h2_ngheader));
    ngh->nv =  apr_pcalloc(p, n * sizeof(nghttp2_nv));
    NV_ADD_LIT_CS(ngh, ":status", apr_psprintf(p, "%d", http_status));
    apr_table_do(add_table_header, ngh, header, NULL);

    return ngh;
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

int h2_proxy_res_ignore_header(const char *name, size_t len)
{
    return (h2_req_ignore_header(name, len) 
            || ignore_header(H2_LIT_ARGS(IgnoredProxyRespHds), name, len));
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
void h2_push_policy_determine(struct h2_request *req, apr_pool_t *p, int push_enabled)
{
    h2_push_policy policy = H2_PUSH_NONE;
    if (push_enabled) {
        const char *val = apr_table_get(req->headers, "accept-push-policy");
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
    req->push_policy = policy;
}

/*******************************************************************************
 * ap_casecmpstr, when will it be backported?
 ******************************************************************************/
#if !APR_CHARSET_EBCDIC
/*
 * Provide our own known-fast implementation of str[n]casecmp()
 * NOTE: Only ASCII alpha characters 41-5A are folded to 61-7A,
 * other 8-bit latin alphabetics are never case-folded!
 */
static const unsigned char ucharmap[] = {
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40,  'a',  'b',  'c',  'd',  'e',  'f',  'g',
     'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
     'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
     'x',  'y',  'z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60,  'a',  'b',  'c',  'd',  'e',  'f',  'g',
     'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
     'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
     'x',  'y',  'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

#else /* APR_CHARSET_EBCDIC */
/* Derived from apr-iconv/ccs/cp037.c for EBCDIC case comparison,
   provides unique identity of every char value (strict ISO-646
   conformance, arbitrary election of an ISO-8859-1 ordering, and
   very arbitrary control code assignments into C1 to achieve
   identity and a reversible mapping of code points),
   then folding the equivalences of ASCII 41-5A into 61-7A, 
   presenting comparison results in a somewhat ISO/IEC 10646
   (ASCII-like) order, depending on the EBCDIC code page in use.
 */
static const unsigned char ucharmap[] = {
	0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F,
	0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x9D, 0x85, 0x08, 0x87,
	0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x0A, 0x17, 0x1B,
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,
	0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04,
	0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,
	0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5,
	0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
	0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF,
	0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0xAC,
	0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5,
	0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
	0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF,
	0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
	0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,
	0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
	0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,
	0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0xDD, 0xDE, 0xAE,
	0x5E, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC,
	0xBD, 0xBE, 0x5B, 0x5D, 0xAF, 0xA8, 0xB4, 0xD7,
	0x7B, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,
	0x7D, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
	0x71, 0x72, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,
	0x5C, 0xF7, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F
};
#endif

int h2_casecmpstr(const char *s1, const char *s2)
{
    const unsigned char *ps1 = (const unsigned char *) s1;
    const unsigned char *ps2 = (const unsigned char *) s2;

    while (ucharmap[*ps1] == ucharmap[*ps2]) {
        if (*ps1++ == '\0') {
            return (0);
        }
        ps2++;
    }
    return (ucharmap[*ps1] - ucharmap[*ps2]);
}

int h2_casecmpstrn(const char *s1, const char *s2, apr_size_t n)
{
    const unsigned char *ps1 = (const unsigned char *) s1;
    const unsigned char *ps2 = (const unsigned char *) s2;
    while (n--) {
        if (ucharmap[*ps1] != ucharmap[*ps2]) {
            return (ucharmap[*ps1] - ucharmap[*ps2]);
        }
        if (*ps1++ == '\0') {
            break;
        }
        ps2++;
    }
    return (0);
}

