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

#ifndef __mod_h2__h2_proxy_util__
#define __mod_h2__h2_proxy_util__

/*******************************************************************************
 * some debugging/format helpers
 ******************************************************************************/
struct h2_request;
struct nghttp2_frame;

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
size_t h2_ihash_ishift(h2_ihash_t *ih, int *buffer, size_t max);

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
 * @param q the queue to append the task to
 * @param sid the stream id to add
 * @param cmp the comparator for sorting
 * @param ctx user data for comparator 
 */
void h2_iq_add(h2_iqueue *q, int sid, h2_iq_cmp *cmp, void *ctx);

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
 * Get the first stream id from the queue or NULL if the queue is empty. 
 * The task will be removed.
 *
 * @param q the queue to get the first task from
 * @return the first stream id of the queue, 0 if empty
 */
int h2_iq_shift(h2_iqueue *q);

/*******************************************************************************
 * common helpers
 ******************************************************************************/
/* h2_log2(n) iff n is a power of 2 */
unsigned char h2_log2(int n);

/*******************************************************************************
 * HTTP/2 header helpers
 ******************************************************************************/
void h2_util_camel_case_header(char *s, size_t len);
int h2_proxy_res_ignore_header(const char *name, size_t len);

/*******************************************************************************
 * nghttp2 helpers
 ******************************************************************************/
typedef struct h2_ngheader {
    nghttp2_nv *nv;
    apr_size_t nvlen;
} h2_ngheader;
h2_ngheader *h2_util_ngheader_make_req(apr_pool_t *p, 
                                       const struct h2_request *req);

/*******************************************************************************
 * h2_request helpers
 ******************************************************************************/
struct h2_request *h2_req_create(int id, apr_pool_t *pool, int serialize);
apr_status_t h2_req_make(struct h2_request *req, apr_pool_t *pool,
                         const char *method, const char *scheme, 
                         const char *authority, const char *path, 
                         apr_table_t *headers);



#endif /* defined(__mod_h2__h2_proxy_util__) */
