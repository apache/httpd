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

#ifndef __mod_h2__h2_task_queue__
#define __mod_h2__h2_task_queue__

struct h2_task;

/**
 * h2_task_queue keeps a list of sorted h2_task* in ascending order.
 */
typedef struct h2_task_queue h2_task_queue;

struct h2_task_queue {
    struct h2_task **elts;
    int head;
    int nelts;
    int nalloc;
    apr_pool_t *pool;
};

/**
 * Comparator for two task to determine their order.
 *
 * @param t1 task to compare
 * @param t2 task to compare
 * @param ctx provided user data
 * @return value is the same as for strcmp() and has the effect:
 *    == 0: t1 and t2 are treated equal in ordering
 *     < 0: t1 should be sorted before t2
 *     > 0: t2 should be sorted before t1
 */
typedef int h2_tq_cmp(struct h2_task *t1, struct h2_task *t2, void *ctx);


/**
 * Allocate a new queue from the pool and initialize.
 * @param id the identifier of the queue
 * @param pool the memory pool
 */
h2_task_queue *h2_tq_create(apr_pool_t *pool, int capacity);

/**
 * Return != 0 iff there are no tasks in the queue.
 * @param q the queue to check
 */
int h2_tq_empty(h2_task_queue *q);

/**
 * Add the task to the queue. 
 *
 * @param q the queue to append the task to
 * @param task the task to add
 * @param cmp the comparator for sorting
 * @param ctx user data for comparator 
 */
void h2_tq_add(h2_task_queue *q, struct h2_task *task,
               h2_tq_cmp *cmp, void *ctx);

/**
 * Sort the tasks queue again. Call if the task ordering
 * has changed.
 *
 * @param q the queue to sort
 * @param cmp the comparator for sorting
 * @param ctx user data for the comparator 
 */
void h2_tq_sort(h2_task_queue *q, h2_tq_cmp *cmp, void *ctx);

/**
 * Get the first task from the queue or NULL if the queue is empty. 
 * The task will be removed.
 *
 * @param q the queue to get the first task from
 * @return the first task of the queue, NULL if empty
 */
h2_task *h2_tq_shift(h2_task_queue *q);

#endif /* defined(__mod_h2__h2_task_queue__) */
