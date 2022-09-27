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

#ifndef __mod_h2__h2_push__
#define __mod_h2__h2_push__

#include <http_protocol.h>

#include "h2.h"
#include "h2_headers.h"

struct h2_request;
struct h2_ngheader;
struct h2_session;
struct h2_stream;

typedef struct h2_push {
    const struct h2_request *req;
    h2_priority *priority;
} h2_push;

typedef enum {
    H2_PUSH_DIGEST_APR_HASH,
    H2_PUSH_DIGEST_SHA256
} h2_push_digest_type;

/*******************************************************************************
 * push diary 
 *
 * - The push diary keeps track of resources already PUSHed via HTTP/2 on this
 *   connection. It records a hash value from the absolute URL of the resource
 *   pushed.
 * - Lacking openssl, 
 * - with openssl, it uses SHA256 to calculate the hash value, otherwise it
 *   falls back to apr_hashfunc_default()
 * - whatever the method to generate the hash, the diary keeps a maximum of 64
 *   bits per hash, limiting the memory consumption to about 
 *      H2PushDiarySize * 8 
 *   bytes. Entries are sorted by most recently used and oldest entries are
 *   forgotten first.
 * - While useful by itself to avoid duplicated PUSHes on the same connection,
 *   the original idea was that clients provided a 'Cache-Digest' header with
 *   the values of *their own* cached resources. This was described in
 *   <https://datatracker.ietf.org/doc/draft-kazuho-h2-cache-digest/> 
 *   and some subsequent revisions that tweaked values but kept the overall idea.
 * - The draft was abandoned by the IETF http-wg, as support from major clients,
 *   e.g. browsers, was lacking for various reasons.
 * - For these reasons, mod_h2 abandoned its support for client supplied values
 *   but keeps the diary. It seems to provide value for applications using PUSH,
 *   is configurable in size and defaults to a very moderate amount of memory
 *   used.
 * - The cache digest header is a Golomb Coded Set of hash values, but it may
 *   limit the amount of bits per hash value even further. For a good description
 *   of GCS, read here:
 *   <http://giovanni.bajo.it/post/47119962313/golomb-coded-sets-smaller-than-bloom-filters>
 ******************************************************************************/
 
 
/*
 * The push diary is based on the abandoned draft 
 * <https://datatracker.ietf.org/doc/draft-kazuho-h2-cache-digest/>
 * that describes how to use golomb filters.
 */

typedef struct h2_push_diary h2_push_diary;

typedef void h2_push_digest_calc(h2_push_diary *diary, apr_uint64_t *phash, h2_push *push);

struct h2_push_diary {
    apr_array_header_t  *entries;
    int         NMax; /* Maximum for N, should size change be necessary */
    int         N;    /* Current maximum number of entries, power of 2 */
    apr_uint64_t         mask; /* mask for relevant bits */
    unsigned int         mask_bits; /* number of relevant bits */
    const char          *authority;
    h2_push_digest_type  dtype;
    h2_push_digest_calc *dcalc;
};

/**
 * Determine the list of h2_push'es to send to the client on behalf of
 * the given request/response pair.
 *
 * @param p the pool to use
 * @param req the requst from the client
 * @param res the response from the server
 * @return array of h2_push addresses or NULL
 */
#if AP_HAS_RESPONSE_BUCKETS
apr_array_header_t *h2_push_collect(apr_pool_t *p,
                                    const struct h2_request *req,
                                    apr_uint32_t push_policy,
                                    const ap_bucket_response *res);
#else
apr_array_header_t *h2_push_collect(apr_pool_t *p,
                                    const struct h2_request *req,
                                    apr_uint32_t push_policy,
                                    const struct h2_headers *res);
#endif

/**
 * Create a new push diary for the given maximum number of entries.
 *
 * @param p the pool to use
 * @param N the max number of entries, rounded up to 2^x
 * @return the created diary, might be NULL of max_entries is 0
 */
h2_push_diary *h2_push_diary_create(apr_pool_t *p, int N);

/**
 * Filters the given pushes against the diary and returns only those pushes
 * that were newly entered in the diary.
 */
apr_array_header_t *h2_push_diary_update(struct h2_session *session, apr_array_header_t *pushes);

/**
 * Collect pushes for the given request/response pair, enter them into the
 * diary and return those pushes newly entered.
 */
#if AP_HAS_RESPONSE_BUCKETS
apr_array_header_t *h2_push_collect_update(struct h2_stream *stream,
                                           const struct h2_request *req,
                                           const ap_bucket_response *res);
#else
apr_array_header_t *h2_push_collect_update(struct h2_stream *stream,
                                           const struct h2_request *req,
                                           const struct h2_headers *res);
#endif

/**
 * Get a cache digest as described in 
 * https://datatracker.ietf.org/doc/draft-kazuho-h2-cache-digest/
 * from the contents of the push diary.
 *
 * @param diary the diary to calculdate the digest from
 * @param p the pool to use
 * @param authority the authority to get the data for, use NULL/"*" for all
 * @param pdata on successful return, the binary cache digest
 * @param plen on successful return, the length of the binary data
 */
apr_status_t h2_push_diary_digest_get(h2_push_diary *diary, apr_pool_t *p, 
                                      int maxP, const char *authority, 
                                      const char **pdata, apr_size_t *plen);

#endif /* defined(__mod_h2__h2_push__) */
