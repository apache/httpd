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

#define ZERO_PT (APR_UINT32_MAX / 2)

APR_RING_HEAD(fd_queue_ring, fd_queue_elem_t);

struct fd_queue_t
{
    struct fd_queue_ring elts;
    apr_uint32_t nelts;
    apr_uint32_t bounds;
    apr_pool_t *spare_pool;
    fd_queue_elem_t *spare_elems;
    apr_thread_mutex_t *one_big_mutex;
    apr_thread_cond_t *not_empty;
    apr_uint32_t num_waiters;
    apr_uint32_t interrupted;
    apr_uint32_t terminated;
};

struct recycled_pool
{
    apr_pool_t *pool;
    struct recycled_pool *next;
};

struct fd_queue_info_t
{
    apr_uint32_t volatile idlers; /* >= ZERO_PT: number of idle worker threads
                                   *  < ZERO_PT: number of events in backlog
                                   *             (waiting for an idle thread) */
    apr_thread_mutex_t *idlers_mutex;
    apr_thread_cond_t *wait_for_idler;
    apr_uint32_t max_idlers;
    apr_uint32_t terminated;
    struct recycled_pool *volatile recycled_pools;
    apr_uint32_t recycled_pools_count;
    apr_uint32_t max_recycled_pools;
};

struct fd_queue_elem_t
{
    APR_RING_ENTRY(fd_queue_elem_t) link; /* in ring */
    struct fd_queue_elem_t *next; /* in spare list */
    sock_event_t self_sock_event;
    ap_queue_event_t self_event;
    ap_queue_event_t *event;
};

static apr_status_t queue_info_cleanup(void *qi)
{
    /* Clean up all pools in the recycled list */
    ap_queue_info_free_idle_pools(qi);
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_queue_info_create(fd_queue_info_t **queue_info,
                                              apr_pool_t *pool, int max_recycled_pools)
{
    apr_status_t rv;
    fd_queue_info_t *qi;

    qi = apr_pcalloc(pool, sizeof(*qi));

    rv = apr_thread_mutex_create(&qi->idlers_mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    rv = apr_thread_cond_create(&qi->wait_for_idler, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    qi->idlers = ZERO_PT;
    if (max_recycled_pools >= 0) {
        qi->max_recycled_pools = max_recycled_pools;
    }
    else {
        qi->max_recycled_pools = APR_INT32_MAX;
    }

    apr_pool_cleanup_register(pool, qi, queue_info_cleanup,
                              apr_pool_cleanup_null);

    *queue_info = qi;
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                                apr_pool_t *pool_to_recycle)
{
    apr_status_t rv;

    ap_queue_info_push_pool(queue_info, pool_to_recycle);

    /* If other threads are waiting on a worker, wake one up */
    if (apr_atomic_inc32(&queue_info->idlers) < ZERO_PT) {
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

AP_DECLARE(apr_status_t) ap_queue_info_try_get_idler(fd_queue_info_t *queue_info)
{
    /* Don't block if there isn't any idle worker. */
    apr_uint32_t idlers = queue_info->idlers, val;
    for (;;) {
        if (idlers <= ZERO_PT) {
            return APR_EAGAIN;
        }

        val = apr_atomic_cas32(&queue_info->idlers, idlers - 1, idlers);
        if (val == idlers) {
            return APR_SUCCESS;
        }

        idlers = val;
    }
}

AP_DECLARE(apr_status_t) ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info)
{
    apr_status_t rv;

    /* Block if there isn't any idle worker.
     * apr_atomic_add32(x, -1) does the same as dec32(x), except
     * that it returns the previous value (unlike dec32's bool).
     */
    if (apr_atomic_add32(&queue_info->idlers, -1) <= ZERO_PT) {
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
         *     A "negative value" (relative to ZERO_PT) in
         *     queue_info->idlers tells how many
         *     threads are waiting on an idle worker.
         */
        if (apr_atomic_read32(&queue_info->idlers) < ZERO_PT) {
            if (queue_info->terminated) {
                apr_thread_mutex_unlock(queue_info->idlers_mutex);
                return APR_EOF;
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

    if (apr_atomic_read32(&queue_info->terminated)) {
        return APR_EOF;
    }
    else {
        return APR_SUCCESS;
    }
}

AP_DECLARE(apr_uint32_t) ap_queue_info_num_idlers(fd_queue_info_t *queue_info)
{
    apr_uint32_t val = apr_atomic_read32(&queue_info->idlers);
    return (val > ZERO_PT) ? val - ZERO_PT : 0;
}

AP_DECLARE(apr_int32_t) ap_queue_info_idlers_count(fd_queue_info_t *queue_info)
{
    return apr_atomic_read32(&queue_info->idlers) - ZERO_PT;
}

AP_DECLARE(apr_int32_t) ap_queue_info_idlers_inc(fd_queue_info_t *queue_info)
{
     /* apr_atomic_add32() returns the previous value, we return the new one */
    return apr_atomic_add32(&queue_info->idlers, +1) + 1 - ZERO_PT;
}

AP_DECLARE(apr_int32_t) ap_queue_info_idlers_dec(fd_queue_info_t *queue_info)
{
     /* apr_atomic_add32() returns the previous value, we return the new one */
    return apr_atomic_add32(&queue_info->idlers, -1) - 1 - ZERO_PT;
}

AP_DECLARE(void) ap_queue_info_push_pool(fd_queue_info_t *queue_info,
                                         apr_pool_t *pool_to_recycle)
{
    struct recycled_pool *new_recycle, *first_pool, *val;
    apr_uint32_t count;

    /* If we have been given a pool to recycle, atomically link
     * it into the queue_info's list of recycled pools
     */
    if (!pool_to_recycle)
        return;

    /* The counting is racy but we don't mind recycling a few more/less pools,
     * it's lighter than a compare & swap loop or an inc + dec to back out.
     */
    count = apr_atomic_read32(&queue_info->recycled_pools_count);
    if (count >= queue_info->max_recycled_pools) {
        apr_pool_destroy(pool_to_recycle);
        return;
    }
    apr_atomic_inc32(&queue_info->recycled_pools_count);

    apr_pool_clear(pool_to_recycle);
    new_recycle = apr_palloc(pool_to_recycle, sizeof *new_recycle);
    new_recycle->pool = pool_to_recycle;

    first_pool = queue_info->recycled_pools;
    for (;;) {
        new_recycle->next = first_pool;
        val = apr_atomic_casptr((void *)&queue_info->recycled_pools,
                                new_recycle, first_pool);
        /* Don't compare with new_recycle->next because it can change
         * after apr_atomic_casptr(). For gory details see PR 44402.
         */
        if (val == first_pool) {
            return;
        }

        first_pool = val;
    }
}

AP_DECLARE(apr_pool_t *) ap_queue_info_pop_pool(fd_queue_info_t *queue_info)
{
    struct recycled_pool *first_pool, *val;

    /* Atomically pop a pool from the recycled list */

    /* This function is safe only as long as it is single threaded because
     * it reaches into the queue and accesses "next" which can change.
     * We are OK today because it is only called from the listener thread.
     * cas-based pushes do not have the same limitation - any number can
     * happen concurrently with a single cas-based pop.
     */

    first_pool = queue_info->recycled_pools;
    for (;;) {
        if (first_pool == NULL) {
            return NULL;
        }

        val = apr_atomic_casptr((void *)&queue_info->recycled_pools,
                                first_pool->next, first_pool);
        if (val == first_pool) {
            apr_atomic_dec32(&queue_info->recycled_pools_count);
            return first_pool->pool;
        }

        first_pool = val;
    }
}

AP_DECLARE(void) ap_queue_info_free_idle_pools(fd_queue_info_t *queue_info)
{
    apr_pool_t *p;

    /* Atomically free the recycled list */

    /* Per ap_queue_info_pop_pool() should not be called concurrently, but
     * it's only from the listener thread for now.
     */

    for (;;) {
        p = ap_queue_info_pop_pool(queue_info);
        if (p == NULL)
            return;
        apr_pool_destroy(p);
    }
}


AP_DECLARE(apr_status_t) ap_queue_info_term(fd_queue_info_t *queue_info)
{
    apr_status_t rv;

    rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_atomic_set32(&queue_info->terminated, 1);
    apr_thread_cond_broadcast(queue_info->wait_for_idler);

    return apr_thread_mutex_unlock(queue_info->idlers_mutex);
}

/*
 * Lock/unlock the fd_queue_t.
 */
#define queue_lock(q)   apr_thread_mutex_lock((q)->one_big_mutex)
#define queue_unlock(q) apr_thread_mutex_unlock((q)->one_big_mutex)

/*
 * Detects when the fd_queue_t is full. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define queue_full(q) ((q)->nelts == (q)->bounds)

/*
 * Detects when the fd_queue_t is empty. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define queue_empty(q) ((q)->nelts == 0)

/*
 * Initialize the fd_queue_t.
 */
AP_DECLARE(apr_status_t) ap_queue_create(fd_queue_t **pqueue, int capacity,
                                         apr_pool_t *p)
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

    apr_pool_create(&queue->spare_pool, p);
    APR_RING_INIT(&queue->elts, fd_queue_elem_t, link);
    if (capacity > 0) {
        queue->bounds = capacity;
    }
    else {
        queue->bounds = APR_UINT32_MAX;
    }

    *pqueue = queue;
    return APR_SUCCESS;
}

static APR_INLINE fd_queue_elem_t *get_spare_elem(fd_queue_t *queue)
{
    fd_queue_elem_t *elem = queue->spare_elems;
    if (elem == NULL) {
        elem = apr_pcalloc(queue->spare_pool, sizeof(*elem));
    }
    else {
        queue->spare_elems = elem->next;
        elem->next = NULL;
    }
    return elem;
}

static APR_INLINE void put_spare_elem(fd_queue_t *queue, fd_queue_elem_t *elem)
{
    elem->event = NULL;
    elem->next = queue->spare_elems;
    queue->spare_elems = elem;
}

static APR_INLINE void enqueue_elem(fd_queue_t *queue, fd_queue_elem_t *elem,
                                    ap_queue_event_t *event)
{
    if (event) {
        elem->event = event;
    }
    else {
        elem->event = &elem->self_event;
    }
    elem->event->elem = elem;

    APR_RING_INSERT_TAIL(&queue->elts, elem, fd_queue_elem_t, link);
    queue->nelts++;
}

static APR_INLINE void dequeue_elem(fd_queue_t *queue, fd_queue_elem_t *elem)
{
    elem->event->elem = NULL;
    ap_assert(queue->nelts > 0);
    APR_RING_REMOVE(elem, link);
    APR_RING_ELEM_INIT(elem, link);
    queue->nelts--;
}

/* Pushes the last available element to the queue. */
static void push_elem(fd_queue_t *queue, fd_queue_elem_t **pushed_elem,
                      ap_queue_event_t *event)
{
    fd_queue_elem_t *elem;

    AP_DEBUG_ASSERT(!queue_full(queue));
    AP_DEBUG_ASSERT(!queue->terminated);

    elem = get_spare_elem(queue);
    enqueue_elem(queue, elem, event);

    if (pushed_elem) {
        *pushed_elem = elem;
    }
}

/*
 * Retrieves the oldest available element from the queue, waiting until one
 * becomes available.
 */
static apr_status_t pop_elem(fd_queue_t *queue, fd_queue_elem_t **pelem)
{
    apr_status_t rv;

    for (;;) {
        if (queue->terminated) {
            return APR_EOF; /* no more elements ever again */
        }

        if (queue->interrupted) {
            queue->interrupted--;
            return APR_EINTR;
        }

        if (!queue_empty(queue)) {
            *pelem = APR_RING_FIRST(&queue->elts);
            dequeue_elem(queue, *pelem);
            return APR_SUCCESS;
        }

        queue->num_waiters++;
        rv = apr_thread_cond_wait(queue->not_empty, queue->one_big_mutex);
        queue->num_waiters--;
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
}

AP_DECLARE(apr_status_t) ap_queue_push_event(fd_queue_t *queue,
                                             ap_queue_event_t *event)
{
    apr_status_t rv;

    if ((rv = queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    switch (event->type) {
    case AP_QUEUE_EVENT_SOCK:
    case AP_QUEUE_EVENT_TIMER:
    case AP_QUEUE_EVENT_BATON:
        push_elem(queue, NULL, event);
        if (event->cb) {
            event->cb(event->cb_baton, 1);
        }
        apr_thread_cond_signal(queue->not_empty);
        break;

    default:
        rv = APR_EINVAL;
        break;
    }

    queue_unlock(queue);
    return rv;
}

AP_DECLARE(apr_status_t) ap_queue_pop_event(fd_queue_t *queue,
                                            ap_queue_event_t **pevent)
{
    apr_status_t rv;
    fd_queue_elem_t *elem;

    *pevent = NULL;

    if ((rv = queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    rv = pop_elem(queue, &elem);
    if (rv == APR_SUCCESS) {
        ap_queue_event_t *event = elem->event;
        ap_assert(event && event != &elem->self_event);
        put_spare_elem(queue, elem);
        if (event->cb) {
            event->cb(event->cb_baton, 0);
        }
        *pevent = event;
    }

    queue_unlock(queue);
    return rv;
}

AP_DECLARE(void) ap_queue_kill_event_locked(fd_queue_t *queue,
                                            ap_queue_event_t *event)
{
    fd_queue_elem_t *elem = event->elem;
    ap_assert(elem && APR_RING_NEXT(elem, link) != elem);

    dequeue_elem(queue, elem);
    put_spare_elem(queue, elem);
    if (event->cb) {
        event->cb(event->cb_baton, 0);
    }
}

AP_DECLARE(apr_status_t) ap_queue_lock(fd_queue_t *queue)
{
    return queue_lock(queue);
}

AP_DECLARE(apr_status_t) ap_queue_unlock(fd_queue_t *queue)
{
    return queue_unlock(queue);
}

/**
 * Push a socket onto the queue.
 */
AP_DECLARE(apr_status_t) ap_queue_push_socket(fd_queue_t *queue, apr_socket_t *sd,
                                              apr_pool_t *p)
{
    apr_status_t rv;
    fd_queue_elem_t *elem;

    ap_assert(sd != NULL);

    if ((rv = queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    push_elem(queue, &elem, NULL);
    elem->event->type = AP_QUEUE_EVENT_SOCK;
    elem->event->data.se = &elem->self_sock_event;
    elem->event->data.se->baton = NULL;
    elem->event->data.se->sd = sd;
    elem->event->data.se->p = p;

    apr_thread_cond_signal(queue->not_empty);

    queue_unlock(queue);
    return APR_SUCCESS;
}

/**
 * Pop a socket from the queue.
 */
AP_DECLARE(apr_status_t) ap_queue_pop_socket(fd_queue_t *queue, apr_socket_t **psd,
                                             apr_pool_t **pp)
{
    apr_status_t rv;
    fd_queue_elem_t *elem;

    if (psd) {
        *psd = NULL;
    }
    if (pp) {
        *pp = NULL;
    }

    if ((rv = queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    rv = pop_elem(queue, &elem);
    if (rv == APR_SUCCESS) {
        ap_queue_event_t *event = elem->event;
        ap_assert(event && event == &elem->self_event);
        ap_assert(event->data.se == &elem->self_sock_event);
        ap_assert(event->type == AP_QUEUE_EVENT_SOCK);
        if (psd) {
            *psd = event->data.se->sd;
        }
        if (pp) {
            *pp = event->data.se->p;
        }
        put_spare_elem(queue, elem);
    }

    queue_unlock(queue);
    return rv;
}

static apr_status_t queue_interrupt(fd_queue_t *queue, int all, int term)
{
    apr_status_t rv;

    if ((rv = queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    /* we must hold one_big_mutex when setting this... otherwise,
     * we could end up setting it and waking everybody up just after a
     * would-be popper checks it but right before they block
     */
    queue->interrupted = 1;
    if (term) {
        queue->terminated = 1;
    }
    if (all) {
        if (queue->num_waiters > 1)
            queue->interrupted += queue->num_waiters - 1;
        apr_thread_cond_broadcast(queue->not_empty);
    }
    else {
        apr_thread_cond_signal(queue->not_empty);
    }

    queue_unlock(queue);
    return APR_SUCCESS;
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
