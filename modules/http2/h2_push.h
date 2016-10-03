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
#ifndef __mod_h2__h2_push__
#define __mod_h2__h2_push__

#include "h2.h"

struct h2_request;
struct h2_headers;
struct h2_ngheader;
struct h2_session;
struct h2_stream;

typedef struct h2_push {
    const struct h2_request *req;
} h2_push;

typedef enum {
    H2_PUSH_DIGEST_APR_HASH,
    H2_PUSH_DIGEST_SHA256
} h2_push_digest_type;

typedef struct h2_push_diary h2_push_diary;

typedef void h2_push_digest_calc(h2_push_diary *diary, apr_uint64_t *phash, h2_push *push);

struct h2_push_diary {
    apr_array_header_t  *entries;
    apr_uint32_t         NMax; /* Maximum for N, should size change be necessary */
    apr_uint32_t         N;    /* Current maximum number of entries, power of 2 */
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
apr_array_header_t *h2_push_collect(apr_pool_t *p, 
                                    const struct h2_request *req, 
                                    int push_policy, 
                                    const struct h2_headers *res);

/**
 * Create a new push diary for the given maximum number of entries.
 * 
 * @param p the pool to use
 * @param N the max number of entries, rounded up to 2^x
 * @return the created diary, might be NULL of max_entries is 0
 */
h2_push_diary *h2_push_diary_create(apr_pool_t *p, apr_size_t N);

/**
 * Filters the given pushes against the diary and returns only those pushes
 * that were newly entered in the diary.
 */
apr_array_header_t *h2_push_diary_update(struct h2_session *session, apr_array_header_t *pushes);

/**
 * Collect pushes for the given request/response pair, enter them into the
 * diary and return those pushes newly entered.
 */
apr_array_header_t *h2_push_collect_update(struct h2_stream *stream, 
                                           const struct h2_request *req, 
                                           const struct h2_headers *res);
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
                                      apr_uint32_t maxP, const char *authority, 
                                      const char **pdata, apr_size_t *plen);

/**
 * Initialize the push diary by a cache digest as described in 
 * https://datatracker.ietf.org/doc/draft-kazuho-h2-cache-digest/
 * .
 * @param diary the diary to set the digest into
 * @param authority the authority to set the data for
 * @param data the binary cache digest
 * @param len the length of the cache digest
 * @return APR_EINVAL if digest was not successfully parsed
 */
apr_status_t h2_push_diary_digest_set(h2_push_diary *diary, const char *authority, 
                                      const char *data, apr_size_t len);

apr_status_t h2_push_diary_digest64_set(h2_push_diary *diary, const char *authority, 
                                        const char *data64url, apr_pool_t *pool);

#endif /* defined(__mod_h2__h2_push__) */
