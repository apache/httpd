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
#include "h2_util.h"

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


char *h2_strlwr(char *s)
{
    char *p;
    for (p = s; *p; ++p) {
        if (*p >= 'A' && *p <= 'Z') {
            *p += 'a' - 'A';
        }
    }
    return s;
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

static const int BASE64URL_TABLE[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57,
    58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,
    7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1
};

apr_size_t h2_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool)
{
    const unsigned char *e = (const unsigned char *)encoded;
    const unsigned char *p = e;
    unsigned char *d;
    int n;
    apr_size_t len, mlen, remain, i;
    
    while (*p && BASE64URL_TABLE[ *p ] == -1) {
        ++p;
    }
    len = p - e;
    mlen = (len/4)*4;
    *decoded = apr_pcalloc(pool, len+1);
    
    i = 0;
    d = (unsigned char*)*decoded;
    for (; i < mlen; i += 4) {
        n = ((BASE64URL_TABLE[ e[i+0] ] << 18) +
             (BASE64URL_TABLE[ e[i+1] ] << 12) +
             (BASE64URL_TABLE[ e[i+2] ] << 6) +
             BASE64URL_TABLE[ e[i+3] ]);
        *d++ = n >> 16;
        *d++ = n >> 8 & 0xffu;
        *d++ = n & 0xffu;
    }
    remain = len - mlen;
    switch (remain) {
        case 2:
            n = ((BASE64URL_TABLE[ e[mlen+0] ] << 18) +
                 (BASE64URL_TABLE[ e[mlen+1] ] << 12));
            *d++ = n >> 16;
            break;
        case 3:
            n = ((BASE64URL_TABLE[ e[mlen+0] ] << 18) +
                 (BASE64URL_TABLE[ e[mlen+1] ] << 12) +
                 (BASE64URL_TABLE[ e[mlen+2] ] << 6));
            *d++ = n >> 16;
            *d++ = n >> 8 & 0xffu;
            break;
        default: /* do nothing */
            break;
    }
    return len;
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

/* DEEP_COPY==0 crashes under load. I think the setaside is fine, 
 * however buckets moved to another thread will still be
 * free'd against the old bucket_alloc. *And* if the old
 * pool gets destroyed too early, the bucket disappears while
 * still needed.
 */
static const int DEEP_COPY = 1;
static const int FILE_MOVE = 1;

static apr_status_t last_not_included(apr_bucket_brigade *bb, 
                                      apr_size_t maxlen, 
                                      int same_alloc,
                                      int *pfile_buckets_allowed,
                                      apr_bucket **pend)
{
    apr_bucket *b;
    apr_status_t status = APR_SUCCESS;
    int files_allowed = pfile_buckets_allowed? *pfile_buckets_allowed : 0;
    
    if (maxlen > 0) {
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

#define LOG_BUCKETS     0
#define LOG_LEVEL APLOG_INFO

apr_status_t h2_util_move(apr_bucket_brigade *to, apr_bucket_brigade *from, 
                          apr_size_t maxlen, int *pfile_handles_allowed, 
                          const char *msg)
{
    apr_status_t status = APR_SUCCESS;
    int same_alloc;
    
    AP_DEBUG_ASSERT(to);
    AP_DEBUG_ASSERT(from);
    same_alloc = (to->bucket_alloc == from->bucket_alloc);

    if (!FILE_MOVE) {
        pfile_handles_allowed = NULL;
    }
    
    if (!APR_BRIGADE_EMPTY(from)) {
        apr_bucket *b, *end;
        
        status = last_not_included(from, maxlen, same_alloc,
                                   pfile_handles_allowed, &end);
        if (status != APR_SUCCESS) {
            return status;
        }
        
        while (!APR_BRIGADE_EMPTY(from) && status == APR_SUCCESS) {
            b = APR_BRIGADE_FIRST(from);
            if (b == end) {
                break;
            }
            
            if (same_alloc || (b->list == to->bucket_alloc)) {
                /* both brigades use the same bucket_alloc and auto-cleanups
                 * have the same life time. It's therefore safe to just move
                 * directly. */
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(to, b);
#if LOG_BUCKETS
                ap_log_perror(APLOG_MARK, LOG_LEVEL, 0, to->p,
                              "h2_util_move: %s, passed bucket(same bucket_alloc) "
                              "%ld-%ld, type=%s",
                              msg, (long)b->start, (long)b->length, 
                              APR_BUCKET_IS_METADATA(b)? 
                              (APR_BUCKET_IS_EOS(b)? "EOS": 
                               (APR_BUCKET_IS_FLUSH(b)? "FLUSH" : "META")) : 
                              (APR_BUCKET_IS_FILE(b)? "FILE" : "DATA"));
#endif
            }
            else if (DEEP_COPY) {
                /* we have not managed the magic of passing buckets from
                 * one thread to another. Any attempts result in
                 * cleanup of pools scrambling memory.
                 */
                if (APR_BUCKET_IS_METADATA(b)) {
                    if (APR_BUCKET_IS_EOS(b)) {
                        APR_BRIGADE_INSERT_TAIL(to, apr_bucket_eos_create(to->bucket_alloc));
                    }
                    else if (APR_BUCKET_IS_FLUSH(b)) {
                        APR_BRIGADE_INSERT_TAIL(to, apr_bucket_flush_create(to->bucket_alloc));
                    }
                    else {
                        /* ignore */
                    }
                }
                else if (pfile_handles_allowed 
                         && *pfile_handles_allowed > 0 
                         && APR_BUCKET_IS_FILE(b)) {
                    /* We do not want to read files when passing buckets, if
                     * we can avoid it. However, what we've come up so far
                     * is not working corrently, resulting either in crashes or
                     * too many open file descriptors.
                     */
                    apr_bucket_file *f = (apr_bucket_file *)b->data;
                    apr_file_t *fd = f->fd;
                    int setaside = (f->readpool != to->p);
#if LOG_BUCKETS
                    ap_log_perror(APLOG_MARK, LOG_LEVEL, 0, to->p,
                                  "h2_util_move: %s, moving FILE bucket %ld-%ld "
                                  "from=%lx(p=%lx) to=%lx(p=%lx), setaside=%d",
                                  msg, (long)b->start, (long)b->length, 
                                  (long)from, (long)from->p, 
                                  (long)to, (long)to->p, setaside);
#endif
                    if (setaside) {
                        status = apr_file_setaside(&fd, fd, to->p);
                        if (status != APR_SUCCESS) {
                            ap_log_perror(APLOG_MARK, APLOG_ERR, status, to->p,
                                          APLOGNO(02947) "h2_util: %s, setaside FILE", 
                                          msg);
                            return status;
                        }
                    }
                    apr_brigade_insert_file(to, fd, b->start, b->length, 
                                            to->p);
                    --(*pfile_handles_allowed);
                }
                else {
                    const char *data;
                    apr_size_t len;
                    status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                    if (status == APR_SUCCESS && len > 0) {
                        status = apr_brigade_write(to, NULL, NULL, data, len);
#if LOG_BUCKETS
                        ap_log_perror(APLOG_MARK, LOG_LEVEL, 0, to->p,
                                      "h2_util_move: %s, copied bucket %ld-%ld "
                                      "from=%lx(p=%lx) to=%lx(p=%lx)",
                                      msg, (long)b->start, (long)b->length, 
                                      (long)from, (long)from->p, 
                                      (long)to, (long)to->p);
#endif
                    }
                }
                apr_bucket_delete(b);
            }
            else {
                apr_bucket_setaside(b, to->p);
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(to, b);
#if LOG_BUCKETS
                ap_log_perror(APLOG_MARK, LOG_LEVEL, 0, to->p,
                              "h2_util_move: %s, passed setaside bucket %ld-%ld "
                              "from=%lx(p=%lx) to=%lx(p=%lx)",
                              msg, (long)b->start, (long)b->length, 
                              (long)from, (long)from->p, 
                              (long)to, (long)to->p);
#endif
            }
        }
    }
    
    return status;
}

apr_status_t h2_util_copy(apr_bucket_brigade *to, apr_bucket_brigade *from, 
                          apr_size_t maxlen, const char *msg)
{
    apr_status_t status = APR_SUCCESS;
    int same_alloc;

    (void)msg;
    AP_DEBUG_ASSERT(to);
    AP_DEBUG_ASSERT(from);
    same_alloc = (to->bucket_alloc == from->bucket_alloc);

    if (!APR_BRIGADE_EMPTY(from)) {
        apr_bucket *b, *end, *cpy;
        
        status = last_not_included(from, maxlen, 0, 0, &end);
        if (status != APR_SUCCESS) {
            return status;
        }

        for (b = APR_BRIGADE_FIRST(from);
             b != APR_BRIGADE_SENTINEL(from) && b != end;
             b = APR_BUCKET_NEXT(b))
        {
            if (same_alloc) {
                status = apr_bucket_copy(b, &cpy);
                if (status != APR_SUCCESS) {
                    break;
                }
                APR_BRIGADE_INSERT_TAIL(to, cpy);
            }
            else {
                if (APR_BUCKET_IS_METADATA(b)) {
                    if (APR_BUCKET_IS_EOS(b)) {
                        APR_BRIGADE_INSERT_TAIL(to, apr_bucket_eos_create(to->bucket_alloc));
                    }
                    else if (APR_BUCKET_IS_FLUSH(b)) {
                        APR_BRIGADE_INSERT_TAIL(to, apr_bucket_flush_create(to->bucket_alloc));
                    }
                    else {
                        /* ignore */
                    }
                }
                else {
                    const char *data;
                    apr_size_t len;
                    status = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
                    if (status == APR_SUCCESS && len > 0) {
                        status = apr_brigade_write(to, NULL, NULL, data, len);
#if LOG_BUCKETS                        
                        ap_log_perror(APLOG_MARK, LOG_LEVEL, 0, to->p,
                                      "h2_util_copy: %s, copied bucket %ld-%ld "
                                      "from=%lx(p=%lx) to=%lx(p=%lx)",
                                      msg, (long)b->start, (long)b->length, 
                                      (long)from, (long)from->p, 
                                      (long)to, (long)to->p);
#endif
                    }
                }
            }
        }
    }
    return status;
}

int h2_util_has_flush_or_eos(apr_bucket_brigade *bb) {
    apr_bucket *b;
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_EOS(b) || APR_BUCKET_IS_FLUSH(b)) {
            return 1;
        }
    }
    return 0;
}

int h2_util_has_eos(apr_bucket_brigade *bb, apr_size_t len)
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
        if (!APR_BUCKET_IS_METADATA(b)) {
            return 1;
        }
    }
    return 0;
}

int h2_util_bb_has_data_or_eos(apr_bucket_brigade *bb)
{
    apr_bucket *b;
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_METADATA(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                return 1;
            }
        }
        else {
            return 1;
        }
    }
    return 0;
}

apr_status_t h2_util_bb_avail(apr_bucket_brigade *bb, 
                              apr_size_t *plen, int *peos)
{
    apr_status_t status;
    apr_off_t blen = 0;

    /* test read to determine available length */
    status = apr_brigade_length(bb, 1, &blen);
    if (status != APR_SUCCESS) {
        return status;
    }
    else if (blen == 0) {
        /* empty brigade, does it have an EOS bucket somwhere? */
        *plen = 0;
        *peos = h2_util_has_eos(bb, 0);
    }
    else if (blen > 0) {
        /* data in the brigade, limit the length returned. Check for EOS
         * bucket only if we indicate data. This is required since plen == 0
         * means "the whole brigade" for h2_util_hash_eos()
         */
        if (blen < (apr_off_t)*plen) {
            *plen = blen;
        }
        *peos = (*plen > 0)? h2_util_has_eos(bb, *plen) : 0;
    }
    else if (blen < 0) {
        /* famous SHOULD NOT HAPPEN, sinc we told apr_brigade_length to readall
         */
        *plen = 0;
        *peos = h2_util_has_eos(bb, 0);
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}

apr_status_t h2_util_bb_readx(apr_bucket_brigade *bb, 
                              h2_util_pass_cb *cb, void *ctx, 
                              apr_size_t *plen, int *peos)
{
    apr_status_t status = APR_SUCCESS;
    int consume = (cb != NULL);
    apr_size_t written = 0;
    apr_size_t avail = *plen;
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
                status = apr_bucket_read(b, &data, &data_len, 
                                         APR_NONBLOCK_READ);
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

void h2_util_bb_log(conn_rec *c, int stream_id, int level, 
                    const char *tag, apr_bucket_brigade *bb)
{
    char buffer[16 * 1024];
    const char *line = "(null)";
    apr_size_t bmax = sizeof(buffer)/sizeof(buffer[0]);
    int off = 0;
    apr_bucket *b;
    
    if (bb) {
        memset(buffer, 0, bmax--);
        for (b = APR_BRIGADE_FIRST(bb); 
             bmax && (b != APR_BRIGADE_SENTINEL(bb));
             b = APR_BUCKET_NEXT(b)) {
            
            if (APR_BUCKET_IS_METADATA(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    off += apr_snprintf(buffer+off, bmax-off, "eos ");
                }
                else if (APR_BUCKET_IS_FLUSH(b)) {
                    off += apr_snprintf(buffer+off, bmax-off, "flush ");
                }
                else if (AP_BUCKET_IS_EOR(b)) {
                    off += apr_snprintf(buffer+off, bmax-off, "eor ");
                }
                else {
                    off += apr_snprintf(buffer+off, bmax-off, "meta(unknown) ");
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
                
                off += apr_snprintf(buffer+off, bmax-off, "%s[%ld] ", 
                                    btype, 
                                    (long)(b->length == ((apr_size_t)-1)? 
                                           -1 : b->length));
            }
        }
        line = *buffer? buffer : "(empty)";
    }
    ap_log_cerror(APLOG_MARK, level, 0, c, "bb_dump(%ld-%d)-%s: %s", 
                  c->id, stream_id, tag, line);

}

AP_DECLARE(apr_status_t) h2_transfer_brigade(apr_bucket_brigade *to,
                                             apr_bucket_brigade *from, 
                                             apr_pool_t *p,
                                             apr_size_t *plen,
                                             int *peos)
{
    apr_bucket *e;
    apr_size_t len = 0, remain = *plen;
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
        
        rv = apr_bucket_setaside(e, p);
        
        /* If the bucket type does not implement setaside, then
         * (hopefully) morph it into a bucket type which does, and set
         * *that* aside... */
        if (rv == APR_ENOTIMPL) {
            const char *s;
            apr_size_t n;
            
            rv = apr_bucket_read(e, &s, &n, APR_BLOCK_READ);
            if (rv == APR_SUCCESS) {
                rv = apr_bucket_setaside(e, p);
            }
        }
        
        if (rv != APR_SUCCESS) {
            /* Return an error but still save the brigade if
             * ->setaside() is really not implemented. */
            if (rv != APR_ENOTIMPL) {
                return rv;
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

