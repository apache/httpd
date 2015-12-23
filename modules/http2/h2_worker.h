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

#ifndef __mod_h2__h2_worker__
#define __mod_h2__h2_worker__

struct apr_thread_cond_t;
struct h2_mplx;
struct h2_request;
struct h2_task;

/* h2_worker is a basically a apr_thread_t that reads fromt he h2_workers
 * task queue and runs h2_tasks it is given.
 */
typedef struct h2_worker h2_worker;

/* Invoked when the worker wants a new task to process. Will block
 * until a h2_mplx becomes available or the worker itself
 * gets aborted (idle timeout, for example). */
typedef apr_status_t h2_worker_mplx_next_fn(h2_worker *worker,
                                            struct h2_mplx **pm,
                                            const struct h2_request **preq,
                                            void *ctx);

/* Invoked just before the worker thread exits. */
typedef void h2_worker_done_fn(h2_worker *worker, void *ctx);


struct h2_worker {
    /** Links to the rest of the workers */
    APR_RING_ENTRY(h2_worker) link;
    
    int id;
    apr_thread_t *thread;
    apr_pool_t *pool;
    apr_pool_t *task_pool;
    struct apr_thread_cond_t *io;
    apr_socket_t *socket;
    
    h2_worker_mplx_next_fn *get_next;
    h2_worker_done_fn *worker_done;
    void *ctx;
    
    unsigned int aborted : 1;
};

/**
 * The magic pointer value that indicates the head of a h2_worker list
 * @param  b The worker list
 * @return The magic pointer value
 */
#define H2_WORKER_LIST_SENTINEL(b)	APR_RING_SENTINEL((b), h2_worker, link)

/**
 * Determine if the worker list is empty
 * @param b The list to check
 * @return true or false
 */
#define H2_WORKER_LIST_EMPTY(b)	APR_RING_EMPTY((b), h2_worker, link)

/**
 * Return the first worker in a list
 * @param b The list to query
 * @return The first worker in the list
 */
#define H2_WORKER_LIST_FIRST(b)	APR_RING_FIRST(b)

/**
 * Return the last worker in a list
 * @param b The list to query
 * @return The last worker int he list
 */
#define H2_WORKER_LIST_LAST(b)	APR_RING_LAST(b)

/**
 * Insert a single worker at the front of a list
 * @param b The list to add to
 * @param e The worker to insert
 */
#define H2_WORKER_LIST_INSERT_HEAD(b, e) do {				\
	h2_worker *ap__b = (e);                                        \
	APR_RING_INSERT_HEAD((b), ap__b, h2_worker, link);	\
    } while (0)

/**
 * Insert a single worker at the end of a list
 * @param b The list to add to
 * @param e The worker to insert
 */
#define H2_WORKER_LIST_INSERT_TAIL(b, e) do {				\
	h2_worker *ap__b = (e);					\
	APR_RING_INSERT_TAIL((b), ap__b, h2_worker, link);	\
    } while (0)

/**
 * Get the next worker in the list
 * @param e The current worker
 * @return The next worker
 */
#define H2_WORKER_NEXT(e)	APR_RING_NEXT((e), link)
/**
 * Get the previous worker in the list
 * @param e The current worker
 * @return The previous worker
 */
#define H2_WORKER_PREV(e)	APR_RING_PREV((e), link)

/**
 * Remove a worker from its list
 * @param e The worker to remove
 */
#define H2_WORKER_REMOVE(e)	APR_RING_REMOVE((e), link)


/* Create a new worker with given id, pool and attributes, callbacks
 * callback parameter.
 */
h2_worker *h2_worker_create(int id,
                            apr_pool_t *pool,
                            apr_threadattr_t *attr,
                            h2_worker_mplx_next_fn *get_next,
                            h2_worker_done_fn *worker_done,
                            void *ctx);

apr_status_t h2_worker_destroy(h2_worker *worker);

void h2_worker_abort(h2_worker *worker);

int h2_worker_get_id(h2_worker *worker);

int h2_worker_is_aborted(h2_worker *worker);

struct h2_task *h2_worker_create_task(h2_worker *worker, struct h2_mplx *m, 
                                      const struct h2_request *req);
                                      
#endif /* defined(__mod_h2__h2_worker__) */
