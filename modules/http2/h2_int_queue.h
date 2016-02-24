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

#ifndef __mod_h2__h2_int_queue__
#define __mod_h2__h2_int_queue__

/**
 * h2_int_queue keeps a list of sorted h2_task* in ascending order.
 */
typedef struct h2_int_queue h2_int_queue;

struct h2_int_queue {
    int *elts;
    int head;
    int nelts;
    int nalloc;
    apr_pool_t *pool;
};

/**
 * Comparator for two task to determine their order.
 *
 * @param s1 stream id to compare
 * @param s2 stream id to compare
 * @param ctx provided user data
 * @return value is the same as for strcmp() and has the effect:
 *    == 0: s1 and s2 are treated equal in ordering
 *     < 0: s1 should be sorted before s2
 *     > 0: s2 should be sorted before s1
 */
typedef int h2_iq_cmp(int s1, int s2, void *ctx);


/**
 * Allocate a new queue from the pool and initialize.
 * @param id the identifier of the queue
 * @param pool the memory pool
 */
h2_int_queue *h2_iq_create(apr_pool_t *pool, int capacity);

/**
 * Return != 0 iff there are no tasks in the queue.
 * @param q the queue to check
 */
int h2_iq_empty(h2_int_queue *q);

/**
 * Return the number of int in the queue.
 * @param q the queue to get size on
 */
int h2_iq_size(h2_int_queue *q);

/**
 * Add a stream idto the queue. 
 *
 * @param q the queue to append the task to
 * @param sid the stream id to add
 * @param cmp the comparator for sorting
 * @param ctx user data for comparator 
 */
void h2_iq_add(h2_int_queue *q, int sid, h2_iq_cmp *cmp, void *ctx);

/**
 * Remove the stream id from the queue. Return != 0 iff task
 * was found in queue.
 * @param q the task queue
 * @param sid the stream id to remove
 * @return != 0 iff task was found in queue
 */
int h2_iq_remove(h2_int_queue *q, int sid);

/**
 * Remove all entries in the queue.
 */
void h2_iq_clear(h2_int_queue *q);

/**
 * Sort the stream idqueue again. Call if the task ordering
 * has changed.
 *
 * @param q the queue to sort
 * @param cmp the comparator for sorting
 * @param ctx user data for the comparator 
 */
void h2_iq_sort(h2_int_queue *q, h2_iq_cmp *cmp, void *ctx);

/**
 * Get the first stream id from the queue or NULL if the queue is empty. 
 * The task will be removed.
 *
 * @param q the queue to get the first task from
 * @return the first stream id of the queue, 0 if empty
 */
int h2_iq_shift(h2_int_queue *q);

#endif /* defined(__mod_h2__h2_int_queue__) */
