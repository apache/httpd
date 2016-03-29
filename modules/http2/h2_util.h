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

#ifndef __mod_h2__h2_util__
#define __mod_h2__h2_util__

/*******************************************************************************
 * some debugging/format helpers
 ******************************************************************************/
struct h2_request;
struct nghttp2_frame;

size_t h2_util_hex_dump(char *buffer, size_t maxlen,
                        const char *data, size_t datalen);

size_t h2_util_header_print(char *buffer, size_t maxlen,
                            const char *name, size_t namelen,
                            const char *value, size_t valuelen);

void h2_util_camel_case_header(char *s, size_t len);

int h2_util_frame_print(const nghttp2_frame *frame, char *buffer, size_t maxlen);

/*******************************************************************************
 * ihash - hash for structs with int identifier
 ******************************************************************************/
typedef struct h2_ihash_t h2_ihash_t;
typedef int h2_ihash_iter_t(void *ctx, void *val);

/**
 * Create a hash for structures that have an identifying int member.
 * @param pool the pool to use
 * @param offset_of_int the offsetof() the int member in the struct
 */
h2_ihash_t *h2_ihash_create(apr_pool_t *pool, size_t offset_of_int);

size_t h2_ihash_count(h2_ihash_t *ih);
int h2_ihash_is_empty(h2_ihash_t *ih);
void *h2_ihash_get(h2_ihash_t *ih, int id);

/**
 * Iterate over the hash members (without defined order) and invoke
 * fn for each member until 0 is returned.
 * @param ih the hash to iterate over
 * @param fn the function to invoke on each member
 * @param ctx user supplied data passed into each iteration call
 * @param 0 if one iteration returned 0, otherwise != 0
 */
int h2_ihash_iter(h2_ihash_t *ih, h2_ihash_iter_t *fn, void *ctx);

void h2_ihash_add(h2_ihash_t *ih, void *val);
void h2_ihash_remove(h2_ihash_t *ih, int id);
void h2_ihash_clear(h2_ihash_t *ih);
 
/*******************************************************************************
 * common helpers
 ******************************************************************************/
/* h2_log2(n) iff n is a power of 2 */
unsigned char h2_log2(apr_uint32_t n);

/**
 * Count the bytes that all key/value pairs in a table have
 * in length (exlucding terminating 0s), plus additional extra per pair.
 *
 * @param t the table to inspect
 * @param pair_extra the extra amount to add per pair
 * @return the number of bytes all key/value pairs have
 */
apr_size_t h2_util_table_bytes(apr_table_t *t, apr_size_t pair_extra);

/**
 * Return != 0 iff the string s contains the token, as specified in
 * HTTP header syntax, rfc7230.
 */
int h2_util_contains_token(apr_pool_t *pool, const char *s, const char *token);

const char *h2_util_first_token_match(apr_pool_t *pool, const char *s, 
                                      const char *tokens[], apr_size_t len);

/** Match a header value against a string constance, case insensitive */
#define H2_HD_MATCH_LIT(l, name, nlen)  \
    ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))

/*******************************************************************************
 * HTTP/2 header helpers
 ******************************************************************************/
int h2_req_ignore_header(const char *name, size_t len);
int h2_req_ignore_trailer(const char *name, size_t len);
int h2_res_ignore_trailer(const char *name, size_t len);
int h2_proxy_res_ignore_header(const char *name, size_t len);

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

/*******************************************************************************
 * base64 url encoding, different table from normal base64
 ******************************************************************************/
/**
 * I always wanted to write my own base64url decoder...not. See 
 * https://tools.ietf.org/html/rfc4648#section-5 for description.
 */
apr_size_t h2_util_base64url_decode(const char **decoded, 
                                    const char *encoded, 
                                    apr_pool_t *pool);
const char *h2_util_base64url_encode(const char *data, 
                                     apr_size_t len, apr_pool_t *pool);

/*******************************************************************************
 * nghttp2 helpers
 ******************************************************************************/

#define H2_HD_MATCH_LIT_CS(l, name)  \
    ((strlen(name) == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))

#define H2_CREATE_NV_LIT_CS(nv, NAME, VALUE) nv->name = (uint8_t *)NAME;      \
                                             nv->namelen = sizeof(NAME) - 1;  \
                                             nv->value = (uint8_t *)VALUE;    \
                                             nv->valuelen = strlen(VALUE)

#define H2_CREATE_NV_CS_LIT(nv, NAME, VALUE) nv->name = (uint8_t *)NAME;      \
                                             nv->namelen = strlen(NAME);      \
                                             nv->value = (uint8_t *)VALUE;    \
                                             nv->valuelen = sizeof(VALUE) - 1

#define H2_CREATE_NV_CS_CS(nv, NAME, VALUE) nv->name = (uint8_t *)NAME;       \
                                            nv->namelen = strlen(NAME);       \
                                            nv->value = (uint8_t *)VALUE;     \
                                            nv->valuelen = strlen(VALUE)

int h2_util_ignore_header(const char *name);

typedef struct h2_ngheader {
    nghttp2_nv *nv;
    apr_size_t nvlen;
} h2_ngheader;

h2_ngheader *h2_util_ngheader_make(apr_pool_t *p, apr_table_t *header);
h2_ngheader *h2_util_ngheader_make_res(apr_pool_t *p, 
                                       int http_status, 
                                       apr_table_t *header);
h2_ngheader *h2_util_ngheader_make_req(apr_pool_t *p, 
                                       const struct h2_request *req);

/*******************************************************************************
 * apr brigade helpers
 ******************************************************************************/
/**
 * Moves data from one brigade into another. If maxlen > 0, it only
 * moves up to maxlen bytes into the target brigade, making bucket splits
 * if needed.
 * @param to the brigade to move the data to
 * @param from the brigade to get the data from
 * @param maxlen of bytes to move, <= 0 for all
 * @param pfile_buckets_allowed how many file buckets may be moved, 
 *        may be 0 or NULL
 * @param msg message for use in logging
 */
apr_status_t h2_util_move(apr_bucket_brigade *to, apr_bucket_brigade *from, 
                          apr_off_t maxlen, apr_size_t *pfile_buckets_allowed, 
                          const char *msg);

/**
 * Copies buckets from one brigade into another. If maxlen > 0, it only
 * copies up to maxlen bytes into the target brigade, making bucket splits
 * if needed.
 * @param to the brigade to copy the data to
 * @param from the brigade to get the data from
 * @param maxlen of bytes to copy, <= 0 for all
 * @param msg message for use in logging
 */
apr_status_t h2_util_copy(apr_bucket_brigade *to, apr_bucket_brigade *from, 
                          apr_off_t maxlen, const char *msg);

/**
 * Return != 0 iff there is a FLUSH or EOS bucket in the brigade.
 * @param bb the brigade to check on
 * @return != 0 iff brigade holds FLUSH or EOS bucket (or both)
 */
int h2_util_has_eos(apr_bucket_brigade *bb, apr_off_t len);
int h2_util_bb_has_data(apr_bucket_brigade *bb);
int h2_util_bb_has_data_or_eos(apr_bucket_brigade *bb);

/**
 * Check how many bytes of the desired amount are available and if the
 * end of stream is reached by that amount.
 * @param bb the brigade to check
 * @param plen the desired length and, on return, the available length
 * @param on return, if eos has been reached
 */
apr_status_t h2_util_bb_avail(apr_bucket_brigade *bb, 
                              apr_off_t *plen, int *peos);

typedef apr_status_t h2_util_pass_cb(void *ctx, 
                                     const char *data, apr_off_t len);

/**
 * Read at most *plen bytes from the brigade and pass them into the
 * given callback. If cb is NULL, just return the amount of data that
 * could have been read.
 * If an EOS was/would be encountered, set *peos != 0.
 * @param bb the brigade to read from
 * @param cb the callback to invoke for the read data
 * @param ctx optional data passed to callback
 * @param plen inout, as input gives the maximum number of bytes to read,
 *    on return specifies the actual/would be number of bytes
 * @param peos != 0 iff an EOS bucket was/would be encountered.
 */
apr_status_t h2_util_bb_readx(apr_bucket_brigade *bb, 
                              h2_util_pass_cb *cb, void *ctx, 
                              apr_off_t *plen, int *peos);

/**
 * Logs the bucket brigade (which bucket types with what length)
 * to the log at the given level.
 * @param c the connection to log for
 * @param stream_id the stream identifier this brigade belongs to
 * @param level the log level (as in APLOG_*)
 * @param tag a short message text about the context
 * @param bb the brigade to log
 */
void h2_util_bb_log(conn_rec *c, int stream_id, int level, 
                    const char *tag, apr_bucket_brigade *bb);

/**
 * Transfer buckets from one brigade to another with a limit on the 
 * maximum amount of bytes transfered. Sets aside the buckets to
 * pool p.
 * @param to   brigade to transfer buckets to
 * @param from brigades to remove buckets from
 * @param p    pool that buckets should be setaside to
 * @param plen maximum bytes to transfer, actual bytes transferred
 * @param peos if an EOS bucket was transferred
 */
apr_status_t h2_ltransfer_brigade(apr_bucket_brigade *to,
                                  apr_bucket_brigade *from, 
                                  apr_pool_t *p,
                                  apr_off_t *plen,
                                  int *peos);

/**
 * Transfer all buckets from one brigade to another. Sets aside the buckets to
 * pool p.
 * @param to   brigade to transfer buckets to
 * @param from brigades to remove buckets from
 * @param p    pool that buckets should be setaside to
 */
apr_status_t h2_transfer_brigade(apr_bucket_brigade *to,
                                 apr_bucket_brigade *from, 
                                 apr_pool_t *p);

/**
 * Transfer buckets from one brigade to another with a limit on the 
 * maximum amount of bytes transfered. Does no setaside magic, lifetime
 * of brigades must fit. 
 * @param to   brigade to transfer buckets to
 * @param from brigades to remove buckets from
 * @param plen maximum bytes to transfer, actual bytes transferred
 * @param peos if an EOS bucket was transferred
 */
apr_status_t h2_append_brigade(apr_bucket_brigade *to,
                               apr_bucket_brigade *from, 
                               apr_off_t *plen,
                               int *peos);

/**
 * Get an approximnation of the memory footprint of the given
 * brigade. This varies from apr_brigade_length as
 * - no buckets are ever read
 * - only buckets known to allocate memory (HEAP+POOL) are counted
 * - the bucket struct itself is counted
 */
apr_off_t h2_brigade_mem_size(apr_bucket_brigade *bb);

#endif /* defined(__mod_h2__h2_util__) */
