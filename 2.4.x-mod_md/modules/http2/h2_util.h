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

#include <nghttp2/nghttp2.h>

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
int h2_ihash_empty(h2_ihash_t *ih);
void *h2_ihash_get(h2_ihash_t *ih, int id);

/**
 * Iterate over the hash members (without defined order) and invoke
 * fn for each member until 0 is returned.
 * @param ih the hash to iterate over
 * @param fn the function to invoke on each member
 * @param ctx user supplied data passed into each iteration call
 * @return 0 if one iteration returned 0, otherwise != 0
 */
int h2_ihash_iter(h2_ihash_t *ih, h2_ihash_iter_t *fn, void *ctx);

void h2_ihash_add(h2_ihash_t *ih, void *val);
void h2_ihash_remove(h2_ihash_t *ih, int id);
void h2_ihash_remove_val(h2_ihash_t *ih, void *val);
void h2_ihash_clear(h2_ihash_t *ih);

size_t h2_ihash_shift(h2_ihash_t *ih, void **buffer, size_t max);

/*******************************************************************************
 * iqueue - sorted list of int with user defined ordering
 ******************************************************************************/
typedef struct h2_iqueue {
    int *elts;
    int head;
    int nelts;
    int nalloc;
    apr_pool_t *pool;
} h2_iqueue;

/**
 * Comparator for two int to determine their order.
 *
 * @param i1 first int to compare
 * @param i2 second int to compare
 * @param ctx provided user data
 * @return value is the same as for strcmp() and has the effect:
 *    == 0: s1 and s2 are treated equal in ordering
 *     < 0: s1 should be sorted before s2
 *     > 0: s2 should be sorted before s1
 */
typedef int h2_iq_cmp(int i1, int i2, void *ctx);

/**
 * Allocate a new queue from the pool and initialize.
 * @param id the identifier of the queue
 * @param pool the memory pool
 */
h2_iqueue *h2_iq_create(apr_pool_t *pool, int capacity);

/**
 * Return != 0 iff there are no tasks in the queue.
 * @param q the queue to check
 */
int h2_iq_empty(h2_iqueue *q);

/**
 * Return the number of int in the queue.
 * @param q the queue to get size on
 */
int h2_iq_count(h2_iqueue *q);

/**
 * Add a stream id to the queue. 
 *
 * @param q the queue to append the id to
 * @param sid the stream id to add
 * @param cmp the comparator for sorting
 * @param ctx user data for comparator
 * @return != 0 iff id was not already there 
 */
int h2_iq_add(h2_iqueue *q, int sid, h2_iq_cmp *cmp, void *ctx);

/**
 * Append the id to the queue if not already present. 
 *
 * @param q the queue to append the id to
 * @param sid the id to append
 * @return != 0 iff id was not already there 
 */
int h2_iq_append(h2_iqueue *q, int sid);

/**
 * Remove the stream id from the queue. Return != 0 iff task
 * was found in queue.
 * @param q the task queue
 * @param sid the stream id to remove
 * @return != 0 iff task was found in queue
 */
int h2_iq_remove(h2_iqueue *q, int sid);

/**
 * Remove all entries in the queue.
 */
void h2_iq_clear(h2_iqueue *q);

/**
 * Sort the stream idqueue again. Call if the task ordering
 * has changed.
 *
 * @param q the queue to sort
 * @param cmp the comparator for sorting
 * @param ctx user data for the comparator 
 */
void h2_iq_sort(h2_iqueue *q, h2_iq_cmp *cmp, void *ctx);

/**
 * Get the first id from the queue or 0 if the queue is empty. 
 * The id is being removed.
 *
 * @param q the queue to get the first id from
 * @return the first id of the queue, 0 if empty
 */
int h2_iq_shift(h2_iqueue *q);

/**
 * Get the first max ids from the queue. All these ids will be removed.
 *
 * @param q the queue to get the first task from
 * @param pint the int array to receive the values
 * @param max the maximum number of ids to shift
 * @return the actual number of ids shifted
 */
size_t h2_iq_mshift(h2_iqueue *q, int *pint, size_t max);

/**
 * Determine if int is in the queue already
 *
 * @parm q the queue
 * @param sid the integer id to check for
 * @return != 0 iff sid is already in the queue
 */
int h2_iq_contains(h2_iqueue *q, int sid);

/*******************************************************************************
 * FIFO queue (void* elements)
 ******************************************************************************/

/**
 * A thread-safe FIFO queue with some extra bells and whistles, if you
 * do not need anything special, better use 'apr_queue'.
 */
typedef struct h2_fifo h2_fifo;

/**
 * Create a FIFO queue that can hold up to capacity elements. Elements can
 * appear several times.
 */
apr_status_t h2_fifo_create(h2_fifo **pfifo, apr_pool_t *pool, int capacity);

/**
 * Create a FIFO set that can hold up to capacity elements. Elements only
 * appear once. Pushing an element already present does not change the
 * queue and is successful.
 */
apr_status_t h2_fifo_set_create(h2_fifo **pfifo, apr_pool_t *pool, int capacity);

apr_status_t h2_fifo_term(h2_fifo *fifo);
apr_status_t h2_fifo_interrupt(h2_fifo *fifo);

int h2_fifo_count(h2_fifo *fifo);

/**
 * Push en element into the queue. Blocks if there is no capacity left.
 * 
 * @param fifo the FIFO queue
 * @param elem the element to push
 * @return APR_SUCCESS on push, APR_EAGAIN on try_push on a full queue,
 *         APR_EEXIST when in set mode and elem already there.
 */
apr_status_t h2_fifo_push(h2_fifo *fifo, void *elem);
apr_status_t h2_fifo_try_push(h2_fifo *fifo, void *elem);

apr_status_t h2_fifo_pull(h2_fifo *fifo, void **pelem);
apr_status_t h2_fifo_try_pull(h2_fifo *fifo, void **pelem);

typedef enum {
    H2_FIFO_OP_PULL,   /* pull the element from the queue, ie discard it */
    H2_FIFO_OP_REPUSH, /* pull and immediatley re-push it */
} h2_fifo_op_t;

typedef h2_fifo_op_t h2_fifo_peek_fn(void *head, void *ctx);

/**
 * Call given function on the head of the queue, once it exists, and
 * perform the returned operation on it. The queue will hold its lock during
 * this time, so no other operations on the queue are possible.
 * @param fifo the queue to peek at
 * @param fn   the function to call on the head, once available
 * @param ctx  context to pass in call to function
 */
apr_status_t h2_fifo_peek(h2_fifo *fifo, h2_fifo_peek_fn *fn, void *ctx);

/**
 * Non-blocking version of h2_fifo_peek.
 */
apr_status_t h2_fifo_try_peek(h2_fifo *fifo, h2_fifo_peek_fn *fn, void *ctx);

/**
 * Remove the elem from the queue, will remove multiple appearances.
 * @param elem  the element to remove
 * @return APR_SUCCESS iff > 0 elems were removed, APR_EAGAIN otherwise.
 */
apr_status_t h2_fifo_remove(h2_fifo *fifo, void *elem);

/*******************************************************************************
 * iFIFO queue (int elements)
 ******************************************************************************/

/**
 * A thread-safe FIFO queue with some extra bells and whistles, if you
 * do not need anything special, better use 'apr_queue'.
 */
typedef struct h2_ififo h2_ififo;

/**
 * Create a FIFO queue that can hold up to capacity int. ints can
 * appear several times.
 */
apr_status_t h2_ififo_create(h2_ififo **pfifo, apr_pool_t *pool, int capacity);

/**
 * Create a FIFO set that can hold up to capacity integers. Ints only
 * appear once. Pushing an int already present does not change the
 * queue and is successful.
 */
apr_status_t h2_ififo_set_create(h2_ififo **pfifo, apr_pool_t *pool, int capacity);

apr_status_t h2_ififo_term(h2_ififo *fifo);
apr_status_t h2_ififo_interrupt(h2_ififo *fifo);

int h2_ififo_count(h2_ififo *fifo);

/**
 * Push an int into the queue. Blocks if there is no capacity left.
 * 
 * @param fifo the FIFO queue
 * @param id  the int to push
 * @return APR_SUCCESS on push, APR_EAGAIN on try_push on a full queue,
 *         APR_EEXIST when in set mode and elem already there.
 */
apr_status_t h2_ififo_push(h2_ififo *fifo, int id);
apr_status_t h2_ififo_try_push(h2_ififo *fifo, int id);

apr_status_t h2_ififo_pull(h2_ififo *fifo, int *pi);
apr_status_t h2_ififo_try_pull(h2_ififo *fifo, int *pi);

typedef h2_fifo_op_t h2_ififo_peek_fn(int head, void *ctx);

/**
 * Call given function on the head of the queue, once it exists, and
 * perform the returned operation on it. The queue will hold its lock during
 * this time, so no other operations on the queue are possible.
 * @param fifo the queue to peek at
 * @param fn   the function to call on the head, once available
 * @param ctx  context to pass in call to function
 */
apr_status_t h2_ififo_peek(h2_ififo *fifo, h2_ififo_peek_fn *fn, void *ctx);

/**
 * Non-blocking version of h2_fifo_peek.
 */
apr_status_t h2_ififo_try_peek(h2_ififo *fifo, h2_ififo_peek_fn *fn, void *ctx);

/**
 * Remove the integer from the queue, will remove multiple appearances.
 * @param id  the integer to remove
 * @return APR_SUCCESS iff > 0 ints were removed, APR_EAGAIN otherwise.
 */
apr_status_t h2_ififo_remove(h2_ififo *fifo, int id);

/*******************************************************************************
 * common helpers
 ******************************************************************************/
/* h2_log2(n) iff n is a power of 2 */
unsigned char h2_log2(int n);

/**
 * Count the bytes that all key/value pairs in a table have
 * in length (exlucding terminating 0s), plus additional extra per pair.
 *
 * @param t the table to inspect
 * @param pair_extra the extra amount to add per pair
 * @return the number of bytes all key/value pairs have
 */
apr_size_t h2_util_table_bytes(apr_table_t *t, apr_size_t pair_extra);

/** Match a header value against a string constance, case insensitive */
#define H2_HD_MATCH_LIT(l, name, nlen)  \
    ((nlen == sizeof(l) - 1) && !apr_strnatcasecmp(l, name))

/*******************************************************************************
 * HTTP/2 header helpers
 ******************************************************************************/
int h2_req_ignore_header(const char *name, size_t len);
int h2_req_ignore_trailer(const char *name, size_t len);
int h2_res_ignore_trailer(const char *name, size_t len);

/**
 * Set the push policy for the given request. Takes request headers into 
 * account, see draft https://tools.ietf.org/html/draft-ruellan-http-accept-push-policy-00
 * for details.
 * 
 * @param headers the http headers to inspect
 * @param p the pool to use
 * @param push_enabled if HTTP/2 server push is generally enabled for this request
 * @return the push policy desired
 */
int h2_push_policy_determine(apr_table_t *headers, apr_pool_t *p, int push_enabled);

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

struct h2_headers;

typedef struct h2_ngheader {
    nghttp2_nv *nv;
    apr_size_t nvlen;
} h2_ngheader;

apr_status_t h2_res_create_ngtrailer(h2_ngheader **ph, apr_pool_t *p, 
                                     struct h2_headers *headers); 
apr_status_t h2_res_create_ngheader(h2_ngheader **ph, apr_pool_t *p, 
                                    struct h2_headers *headers); 
apr_status_t h2_req_create_ngheader(h2_ngheader **ph, apr_pool_t *p, 
                                    const struct h2_request *req);

apr_status_t h2_req_add_header(apr_table_t *headers, apr_pool_t *pool, 
                               const char *name, size_t nlen,
                               const char *value, size_t vlen);

/*******************************************************************************
 * h2_request helpers
 ******************************************************************************/

struct h2_request *h2_req_create(int id, apr_pool_t *pool, const char *method, 
                                 const char *scheme, const char *authority, 
                                 const char *path, apr_table_t *header,
                                 int serialize);

/*******************************************************************************
 * apr brigade helpers
 ******************************************************************************/

/**
 * Concatenate at most length bytes from src to dest brigade, splitting
 * buckets if necessary and reading buckets of indeterminate length.
 */
apr_status_t h2_brigade_concat_length(apr_bucket_brigade *dest, 
                                      apr_bucket_brigade *src,
                                      apr_off_t length);
                                
/**
 * Copy at most length bytes from src to dest brigade, splitting
 * buckets if necessary and reading buckets of indeterminate length.
 */
apr_status_t h2_brigade_copy_length(apr_bucket_brigade *dest, 
                                    apr_bucket_brigade *src,
                                    apr_off_t length);
                                
/**
 * Return != 0 iff there is a FLUSH or EOS bucket in the brigade.
 * @param bb the brigade to check on
 * @return != 0 iff brigade holds FLUSH or EOS bucket (or both)
 */
int h2_util_has_eos(apr_bucket_brigade *bb, apr_off_t len);

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
 * Print a bucket's meta data (type and length) to the buffer.
 * @return number of characters printed
 */
apr_size_t h2_util_bucket_print(char *buffer, apr_size_t bmax, 
                                apr_bucket *b, const char *sep);
                                
/**
 * Prints the brigade bucket types and lengths into the given buffer
 * up to bmax.
 * @return number of characters printed
 */
apr_size_t h2_util_bb_print(char *buffer, apr_size_t bmax, 
                            const char *tag, const char *sep, 
                            apr_bucket_brigade *bb);
/**
 * Logs the bucket brigade (which bucket types with what length)
 * to the log at the given level.
 * @param c the connection to log for
 * @param sid the stream identifier this brigade belongs to
 * @param level the log level (as in APLOG_*)
 * @param tag a short message text about the context
 * @param bb the brigade to log
 */
#define h2_util_bb_log(c, sid, level, tag, bb) \
do { \
    char buffer[4 * 1024]; \
    const char *line = "(null)"; \
    apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]); \
    len = h2_util_bb_print(buffer, bmax, (tag), "", (bb)); \
    ap_log_cerror(APLOG_MARK, level, 0, (c), "bb_dump(%ld): %s", \
        ((c)->master? (c)->master->id : (c)->id), (len? buffer : line)); \
} while(0)


typedef int h2_bucket_gate(apr_bucket *b);
/**
 * Transfer buckets from one brigade to another with a limit on the 
 * maximum amount of bytes transferred. Does no setaside magic, lifetime
 * of brigades must fit. 
 * @param to   brigade to transfer buckets to
 * @param from brigades to remove buckets from
 * @param plen maximum bytes to transfer, actual bytes transferred
 * @param peos if an EOS bucket was transferred
 */
apr_status_t h2_append_brigade(apr_bucket_brigade *to,
                               apr_bucket_brigade *from, 
                               apr_off_t *plen,
                               int *peos,
                               h2_bucket_gate *should_append);

/**
 * Get an approximnation of the memory footprint of the given
 * brigade. This varies from apr_brigade_length as
 * - no buckets are ever read
 * - only buckets known to allocate memory (HEAP+POOL) are counted
 * - the bucket struct itself is counted
 */
apr_off_t h2_brigade_mem_size(apr_bucket_brigade *bb);

#endif /* defined(__mod_h2__h2_util__) */
