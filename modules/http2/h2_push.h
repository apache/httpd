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

struct h2_request;
struct h2_response;
struct h2_ngheader;
struct h2_session;
struct h2_stream;

typedef enum {
    H2_PUSH_NONE,
    H2_PUSH_DEFAULT,
    H2_PUSH_HEAD,
    H2_PUSH_FAST_LOAD,
} h2_push_policy;

typedef struct h2_push {
    const struct h2_request *req;
} h2_push;

typedef enum {
    H2_PUSH_DIGEST_APR_HASH,
    H2_PUSH_DIGEST_SHA256
} h2_push_digest_t;

typedef struct h2_push_digest {
    union {
        unsigned int apr_hash;
        unsigned char sha256[32];
    } val;
} h2_push_digest;

typedef void h2_push_digest_calc(h2_push_digest *d, h2_push *push);
typedef int h2_push_digest_cmp(h2_push_digest *d1, h2_push_digest *d2);

typedef struct h2_push_diary_entry {
    h2_push_digest digest;
    apr_time_t last_accessed;
} h2_push_diary_entry;


typedef struct h2_push_diary {
    apr_array_header_t  *entries;
    apr_size_t           max_entries;
    h2_push_digest_t     dtype;
    h2_push_digest_calc *dcalc;
    h2_push_digest_cmp  *dcmp;
} h2_push_diary;

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
                                    const struct h2_response *res);

/**
 * Set the push policy for the given request. Takes request headers into 
 * account, see draft https://tools.ietf.org/html/draft-ruellan-http-accept-push-policy-00
 * for details.
 * 
 * @param req the request to determine the policy for
 * @param p the pool to use
 * @param push_enabled if HTTP/2 server push is generally enabled for this request
 */
void h2_push_policy_determine(struct h2_request *req, apr_pool_t *p, int push_enabled);

/**
 * Create a new push diary for the given maximum number of entries.
 * 
 * @oaram p the pool to use
 * @param max_entries the maximum number of entries the diary should hold
 * @return the created diary, might be NULL of max_entries is 0
 */
h2_push_diary *h2_push_diary_create(apr_pool_t *p, apr_size_t max_entries);

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
                                           const struct h2_response *res);

#endif /* defined(__mod_h2__h2_push__) */
