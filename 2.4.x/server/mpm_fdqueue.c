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

#include "mpm_fdqueue.h"

#if APR_HAS_THREADS

#include <apr_atomic.h>

static const apr_uint32_t zero_pt = APR_UINT32_MAX/2;

struct recycled_pool
{
    apr_pool_t *pool;
    struct recycled_pool *next;
};

struct fd_queue_info_t
{
    apr_uint32_t volatile idlers; /**
                                   * >= zero_pt: number of idle worker threads
                                   * <  zero_pt: number of threads blocked,
                                   *             waiting for an idle worker
                                   */
    apr_thread_mutex_t *idlers_mutex;
    apr_thread_cond_t *wait_for_idler;
    int terminated;
    int max_idlers;
    int max_recycled_pools;
    apr_uint32_t recycled_pools_count;
    struct recycled_pool *volatile recycled_pools;
};

struct fd_queue_elem_t
{
    apr_socket_t *sd;
    void *sd_baton;
    apr_pool_t *p;
};

static apr_status_t queue_info_cleanup(void *data_)
{
    fd_queue_info_t *qi = data_;
    apr_thread_cond_destroy(qi->wait_for_idler);
    apr_thread_mutex_destroy(qi->idlers_mutex);

    /* Clean up any pools in the recycled list */
    for (;;) {
        struct recycled_pool *first_pool = qi->recycled_pools;
        if (first_pool == NULL) {
            break;
        }
        if (apr_atomic_casptr((void *)&qi->recycled_pools, first_pool->next,
                              first_pool) == first_pool) {
            apr_pool_destroy(first_pool->pool);
        }
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_create(fd_queue_info_t **queue_info,
                                  apr_pool_t *pool, int max_idlers,
                                  int max_recycled_pools)
{
    apr_status_t rv;
    fd_queue_info_t *qi;

    qi = apr_pcalloc(pool, sizeof(*qi));

    rv = apr_thread_mutex_create(&qi->idlers_mutex, APR_THREAD_MUTEX_DEFAULT,
                                 pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_thread_cond_create(&qi->wait_for_idler, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    qi->recycled_pools = NULL;
    qi->max_recycled_pools = max_recycled_pools;
    qi->max_idlers = max_idlers;
    qi->idlers = zero_pt;
    apr_pool_cleanup_register(pool, qi, queue_info_cleanup,
                              apr_pool_cleanup_null);

    *queue_info = qi;

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                    apr_pool_t *pool_to_recycle)
{
    apr_status_t rv;

    ap_queue_info_push_pool(queue_info, pool_to_recycle);

    /* If other threads are waiting on a worker, wake one up */
    if (apr_atomic_inc32(&queue_info->idlers) < zero_pt) {
        rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            AP_DEBUG_ASSERT(0);
            return rv;
        }
        rv = apr_thread_cond_signal(queue_info->wait_for_idler);
        if (rv != APR_SUCCESS) {
            apr_thread_mutex_unlock(queue_info->idlers_mutex);
            return rv;
        }
        rv = apr_thread_mutex_unlock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_try_get_idler(fd_queue_info_t *queue_info)
{
    /* Don't block if there isn't any idle worker. */
    for (;;) {
        apr_uint32_t idlers = queue_info->idlers;
        if (idlers <= zero_pt) {
            return APR_EAGAIN;
        }
        if (apr_atomic_cas32(&queue_info->idlers, idlers - 1,
                             idlers) == idlers) {
            return APR_SUCCESS;
        }
    }
}

apr_status_t ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info,
                                          int *had_to_block)
{
    apr_status_t rv;

    /* Block if there isn't any idle worker.
     * apr_atomic_add32(x, -1) does the same as dec32(x), except
     * that it returns the previous value (unlike dec32's bool).
     */
    if (apr_atomic_add32(&queue_info->idlers, -1) <= zero_pt) {
        rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            AP_DEBUG_ASSERT(0);
            apr_atomic_inc32(&(queue_info->idlers));    /* back out dec */
            return rv;
        }
        /* Re-check the idle worker count to guard against a
         * race condition.  Now that we're in the mutex-protected
         * region, one of two things may have happened:
         *   - If the idle worker count is still negative, the
         *     workers are all still busy, so it's safe to
         *     block on a condition variable.
         *   - If the idle worker count is non-negative, then a
         *     worker has become idle since the first check
         *     of queue_info->idlers above.  It's possible
         *     that the worker has also signaled the condition
         *     variable--and if so, the listener missed it
         *     because it wasn't yet blocked on the condition
         *     variable.  But if the idle worker count is
         *     now non-negative, it's safe for this function to
         *     return immediately.
         *
         *     A "negative value" (relative to zero_pt) in
         *     queue_info->idlers tells how many
         *     threads are waiting on an idle worker.
         */
        if (queue_info->idlers < zero_pt) {
            if (had_to_block) {
                *had_to_block = 1;
            }
            rv = apr_thread_cond_wait(queue_info->wait_for_idler,
                                      queue_info->idlers_mutex);
            if (rv != APR_SUCCESS) {
                AP_DEBUG_ASSERT(0);
                apr_thread_mutex_unlock(queue_info->idlers_mutex);
                return rv;
            }
        }
        rv = apr_thread_mutex_unlock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    if (queue_info->terminated) {
        return APR_EOF;
    }
    else {
        return APR_SUCCESS;
    }
}

apr_uint32_t ap_queue_info_num_idlers(fd_queue_info_t *queue_info)
{
    apr_uint32_t val;
    val = apr_atomic_read32(&queue_info->idlers);
    return (val > zero_pt) ? val - zero_pt : 0;
}

void ap_queue_info_push_pool(fd_queue_info_t *queue_info,
                             apr_pool_t *pool_to_recycle)
{
    struct recycled_pool *new_recycle;
    /* If we have been given a pool to recycle, atomically link
     * it into the queue_info's list of recycled pools
     */
    if (!pool_to_recycle)
        return;

    if (queue_info->max_recycled_pools >= 0) {
        apr_uint32_t n = apr_atomic_read32(&queue_info->recycled_pools_count);
        if (n >= queue_info->max_recycled_pools) {
            apr_pool_destroy(pool_to_recycle);
            return;
        }
        apr_atomic_inc32(&queue_info->recycled_pools_count);
    }

    apr_pool_clear(pool_to_recycle);
    new_recycle = apr_palloc(pool_to_recycle, sizeof *new_recycle);
    new_recycle->pool = pool_to_recycle;
    for (;;) {
        /*
         * Save queue_info->recycled_pool in local variable next because
         * new_recycle->next can be changed after apr_atomic_casptr
         * function call. For gory details see PR 44402.
         */
        struct recycled_pool *next = queue_info->recycled_pools;
        new_recycle->next = next;
        if (apr_atomic_casptr((void *)&queue_info->recycled_pools,
                              new_recycle, next) == next)
            break;
    }
}

void ap_queue_info_pop_pool(fd_queue_info_t *queue_info,
                            apr_pool_t **recycled_pool)
{
    /* Atomically pop a pool from the recycled list */

    /* This function is safe only as long as it is single threaded because
     * it reaches into the queue and accesses "next" which can change.
     * We are OK today because it is only called from the listener thread.
     * cas-based pushes do not have the same limitation - any number can
     * happen concurrently with a single cas-based pop.
     */

    *recycled_pool = NULL;


    /* Atomically pop a pool from the recycled list */
    for (;;) {
        struct recycled_pool *first_pool = queue_info->recycled_pools;
        if (first_pool == NULL) {
            break;
        }
        if (apr_atomic_casptr((void *)&queue_info->recycled_pools,
                              first_pool->next, first_pool) == first_pool) {
            *recycled_pool = first_pool->pool;
            if (queue_info->max_recycled_pools >= 0)
                apr_atomic_dec32(&queue_info->recycled_pools_count);
            break;
        }
    }
}

void ap_queue_info_free_idle_pools(fd_queue_info_t *queue_info)
{
    apr_pool_t *p;

    queue_info->max_recycled_pools = 0;
    for (;;) {
        ap_queue_info_pop_pool(queue_info, &p);
        if (p == NULL)
            break;
        apr_pool_destroy(p);
    }
    apr_atomic_set32(&queue_info->recycled_pools_count, 0);
}


apr_status_t ap_queue_info_term(fd_queue_info_t *queue_info)
{
    apr_status_t rv;

    rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    queue_info->terminated = 1;
    apr_thread_cond_broadcast(queue_info->wait_for_idler);

    return apr_thread_mutex_unlock(queue_info->idlers_mutex);
}

/**
 * Detects when the fd_queue_t is full. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ap_queue_full(queue) ((queue)->nelts == (queue)->bounds)

/**
 * Detects when the fd_queue_t is empty. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ap_queue_empty(queue) ((queue)->nelts == 0 && \
                               APR_RING_EMPTY(&queue->timers, \
                                              timer_event_t, link))

/**
 * Callback routine that is called to destroy this
 * fd_queue_t when its pool is destroyed.
 */
static apr_status_t ap_queue_destroy(void *data)
{
    fd_queue_t *queue = data;

    /* Ignore errors here, we can't do anything about them anyway.
     * XXX: We should at least try to signal an error here, it is
     * indicative of a programmer error. -aaron */
    apr_thread_cond_destroy(queue->not_empty);
    apr_thread_mutex_destroy(queue->one_big_mutex);

    return APR_SUCCESS;
}

/**
 * Initialize the fd_queue_t.
 */
apr_status_t ap_queue_create(fd_queue_t **pqueue, int capacity, apr_pool_t *p)
{
    apr_status_t rv;
    fd_queue_t *queue;

    queue = apr_pcalloc(p, sizeof *queue);

    if ((rv = apr_thread_mutex_create(&queue->one_big_mutex,
                                      APR_THREAD_MUTEX_DEFAULT,
                                      p)) != APR_SUCCESS) {
        return rv;
    }
    if ((rv = apr_thread_cond_create(&queue->not_empty, p)) != APR_SUCCESS) {
        return rv;
    }

    APR_RING_INIT(&queue->timers, timer_event_t, link);

    queue->data = apr_pcalloc(p, capacity * sizeof(fd_queue_elem_t));
    queue->bounds = capacity;

    apr_pool_cleanup_register(p, queue, ap_queue_destroy,
                              apr_pool_cleanup_null);
    *pqueue = queue;

    return APR_SUCCESS;
}

/**
 * Push a new socket onto the queue.
 *
 * precondition: ap_queue_info_wait_for_idler has already been called
 *               to reserve an idle worker thread
 */
apr_status_t ap_queue_push_socket(fd_queue_t *queue,
                                  apr_socket_t *sd, void *sd_baton,
                                  apr_pool_t *p)
{
    fd_queue_elem_t *elem;
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    AP_DEBUG_ASSERT(!queue->terminated);
    AP_DEBUG_ASSERT(!ap_queue_full(queue));

    elem = &queue->data[queue->in++];
    if (queue->in >= queue->bounds)
        queue->in -= queue->bounds;
    elem->sd = sd;
    elem->sd_baton = sd_baton;
    elem->p = p;
    queue->nelts++;

    apr_thread_cond_signal(queue->not_empty);

    return apr_thread_mutex_unlock(queue->one_big_mutex);
}

apr_status_t ap_queue_push_timer(fd_queue_t *queue, timer_event_t *te)
{
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    AP_DEBUG_ASSERT(!queue->terminated);

    APR_RING_INSERT_TAIL(&queue->timers, te, timer_event_t, link);

    apr_thread_cond_signal(queue->not_empty);

    return apr_thread_mutex_unlock(queue->one_big_mutex);
}

/**
 * Retrieves the next available socket from the queue. If there are no
 * sockets available, it will block until one becomes available.
 * Once retrieved, the socket is placed into the address specified by
 * 'sd'.
 */
apr_status_t ap_queue_pop_something(fd_queue_t *queue,
                                    apr_socket_t **sd, void **sd_baton,
                                    apr_pool_t **p, timer_event_t **te_out)
{
    fd_queue_elem_t *elem;
    timer_event_t *te;
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    /* Keep waiting until we wake up and find that the queue is not empty. */
    if (ap_queue_empty(queue)) {
        if (!queue->terminated) {
            apr_thread_cond_wait(queue->not_empty, queue->one_big_mutex);
        }
        /* If we wake up and it's still empty, then we were interrupted */
        if (ap_queue_empty(queue)) {
            rv = apr_thread_mutex_unlock(queue->one_big_mutex);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            if (queue->terminated) {
                return APR_EOF; /* no more elements ever again */
            }
            else {
                return APR_EINTR;
            }
        }
    }

    te = NULL;
    if (te_out) {
        if (!APR_RING_EMPTY(&queue->timers, timer_event_t, link)) {
            te = APR_RING_FIRST(&queue->timers);
            APR_RING_REMOVE(te, link);
        }
        *te_out = te;
    }
    if (!te) {
        elem = &queue->data[queue->out++];
        if (queue->out >= queue->bounds)
            queue->out -= queue->bounds;
        queue->nelts--;

        *sd = elem->sd;
        if (sd_baton) {
            *sd_baton = elem->sd_baton;
        }
        *p = elem->p;
#ifdef AP_DEBUG
        elem->sd = NULL;
        elem->p = NULL;
#endif /* AP_DEBUG */
    }

    return apr_thread_mutex_unlock(queue->one_big_mutex);
}

static apr_status_t queue_interrupt(fd_queue_t *queue, int all, int term)
{
    apr_status_t rv;

    if ((rv = apr_thread_mutex_lock(queue->one_big_mutex)) != APR_SUCCESS) {
        return rv;
    }

    /* we must hold one_big_mutex when setting this... otherwise,
     * we could end up setting it and waking everybody up just after a
     * would-be popper checks it but right before they block
     */
    if (term) {
        queue->terminated = 1;
    }
    if (all)
        apr_thread_cond_broadcast(queue->not_empty);
    else
        apr_thread_cond_signal(queue->not_empty);

    return apr_thread_mutex_unlock(queue->one_big_mutex);
}

apr_status_t ap_queue_interrupt_all(fd_queue_t *queue)
{
    return queue_interrupt(queue, 1, 0);
}

apr_status_t ap_queue_interrupt_one(fd_queue_t *queue)
{
    return queue_interrupt(queue, 0, 0);
}

apr_status_t ap_queue_term(fd_queue_t *queue)
{
    return queue_interrupt(queue, 1, 1);
}

#endif /* APR_HAS_THREADS */
