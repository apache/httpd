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
 * A simple ring of rings that keeps a list of h2_tasks and can
 * be ringed itself, using the APR RING macros.
 */
typedef struct h2_task_queue h2_task_queue;

struct h2_task_queue {
    apr_pool_t *pool;
    struct h2_task **elts;
    int nelts;
    int nalloc;
};

/**
 * Allocate a new queue from the pool and initialize.
 * @param id the identifier of the queue
 * @param pool the memory pool
 */
h2_task_queue *h2_tq_create(apr_pool_t *pool, int capacity);

/**
 * Release all queue tasks.
 * @param q the queue to destroy
 */
void h2_tq_destroy(h2_task_queue *q);

/**
 * Return != 0 iff there are no tasks in the queue.
 * @param q the queue to check
 */
int h2_tq_empty(h2_task_queue *q);

typedef int h2_tq_cmp(struct h2_task *t1, struct h2_task *t2, void *ctx);

/**
 * Add the task to the sorted queue. For optimiztation, it is assumed
 * that the order of the existing tasks has not changed.
 *
 * @param q the queue to append the task to
 * @param task the task to add
 * @param cmp the compare function for sorting
 * @param ctx user data for the compare function 
 */
void h2_tq_add(h2_task_queue *q, struct h2_task *task,
               h2_tq_cmp *cmp, void *ctx);

/**
 * Sort the tasks queue again. Useful to call if the task order
 * has changed.
 *
 * @param q the queue to sort
 * @param cmp the compare function for sorting
 * @param ctx user data for the compare function 
 */
void h2_tq_sort(h2_task_queue *q, h2_tq_cmp *cmp, void *ctx);

/**
 * Remove a task from the queue. Return APR_SUCCESS if the task
 * was indeed queued, APR_NOTFOUND otherwise.
 * @param q the queue to remove from
 * @param task the task to remove
 */
apr_status_t h2_tq_remove(h2_task_queue *q, struct h2_task *task);

/**
 * Get the first task from the queue or NULL if the queue is empty. 
 * The task will be removed.
 * @param q the queue to get the first task from
 */
h2_task *h2_tq_shift(h2_task_queue *q);

#endif /* defined(__mod_h2__h2_task_queue__) */
