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

struct recycled_pool
{
    apr_pool_t *pool;
    struct recycled_pool *next;
};

struct ap_queue_t
{
    APR_RING_HEAD(ap_queue_ring, ap_queue_elem_t) elts;
    apr_uint32_t nelts;
    apr_uint32_t bounds;
    apr_pool_t *spare_pool;
    ap_queue_elem_t *spare_elems;
    apr_thread_mutex_t *one_big_mutex;
    apr_thread_cond_t *not_empty;
    apr_uint32_t num_waiters;
    apr_uint32_t interrupted;
    apr_uint32_t terminated;
};

struct ap_queue_info_t
{
    volatile apr_uint32_t idlers; /* >= ZERO_PT: number of idle worker threads
                                   *  < ZERO_PT: number of events in backlog
                                   *             (waiting for an idle thread) */
    apr_thread_mutex_t *idlers_mutex;
    apr_thread_cond_t *wait_for_idler;
    apr_uint32_t terminated;
    int max_idlers;
    int max_recycled_pools;
    apr_uint32_t num_waiters;
    apr_uint32_t recycled_pools_count;
    struct recycled_pool *volatile recycled_pools;
};

struct ap_queue_elem_t
{
    APR_RING_ENTRY(ap_queue_elem_t) link; /* in ring */
    struct ap_queue_elem_t *next; /* in spare list */
    sock_event_t my_sock_event;
    ap_queue_event_t my_event;
    ap_queue_event_t *event;
};

static apr_status_t queue_info_cleanup(void *data_)
{
    ap_queue_info_t *qi = data_;
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

apr_status_t ap_queue_info_create(ap_queue_info_t **queue_info,
                                  apr_pool_t *pool, int max_idlers,
                                  int max_recycled_pools)
{
    apr_status_t rv;
    ap_queue_info_t *qi;

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
    apr_atomic_set32(&qi->idlers, ZERO_PT);
    apr_pool_cleanup_register(pool, qi, queue_info_cleanup,
                              apr_pool_cleanup_null);

    *queue_info = qi;

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_set_idle(ap_queue_info_t *queue_info,
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
        if (queue_info->num_waiters) {
            rv = apr_thread_cond_signal(queue_info->wait_for_idler);
            if (rv != APR_SUCCESS) {
                apr_thread_mutex_unlock(queue_info->idlers_mutex);
                return rv;
            }
        }
        rv = apr_thread_mutex_unlock(queue_info->idlers_mutex);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    return APR_SUCCESS;
}

apr_status_t ap_queue_info_try_get_idler(ap_queue_info_t *queue_info)
{
    /* Don't block if there isn't any idle worker. */
    for (;;) {
        apr_uint32_t idlers = apr_atomic_read32(&queue_info->idlers);
        if (idlers <= ZERO_PT) {
            return APR_EAGAIN;
        }
        if (apr_atomic_cas32(&queue_info->idlers, idlers - 1,
                             idlers) == idlers) {
            return APR_SUCCESS;
        }
    }
}

apr_status_t ap_queue_info_wait_for_idler(ap_queue_info_t *queue_info,
                                          int *had_to_block)
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
        while (queue_info->idlers < ZERO_PT) {
            if (queue_info->terminated) {
                apr_thread_mutex_unlock(queue_info->idlers_mutex);
                return APR_EOF;
            }
            if (had_to_block) {
                *had_to_block = 1;
            }
            queue_info->num_waiters++;
            rv = apr_thread_cond_wait(queue_info->wait_for_idler,
                                      queue_info->idlers_mutex);
            queue_info->num_waiters--;
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

apr_uint32_t ap_queue_info_num_idlers(ap_queue_info_t *queue_info)
{
    apr_uint32_t val = apr_atomic_read32(&queue_info->idlers);
    return (val > ZERO_PT) ? val - ZERO_PT : 0;
}

apr_int32_t ap_queue_info_set_idler(ap_queue_info_t *queue_info)
{
     /* apr_atomic_add32() returns the previous value, we return the new one */
    return apr_atomic_add32(&queue_info->idlers, +1) + 1 - ZERO_PT;
}

apr_int32_t ap_queue_info_get_idler(ap_queue_info_t *queue_info)
{
     /* apr_atomic_add32() returns the previous value, we return the new one */
    return apr_atomic_add32(&queue_info->idlers, -1) - 1 - ZERO_PT;
}

apr_int32_t ap_queue_info_count(ap_queue_info_t *queue_info)
{
    return apr_atomic_read32(&queue_info->idlers) - ZERO_PT;
}

void ap_queue_info_push_pool(ap_queue_info_t *queue_info,
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
        struct recycled_pool *next;
        new_recycle->next = next = queue_info->recycled_pools;
        if (apr_atomic_casptr((void *)&queue_info->recycled_pools,
                              new_recycle, next) == next)
            break;
    }
}

void ap_queue_info_pop_pool(ap_queue_info_t *queue_info,
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

void ap_queue_info_free_idle_pools(ap_queue_info_t *queue_info)
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


apr_status_t ap_queue_info_term(ap_queue_info_t *queue_info)
{
    apr_status_t rv;

    rv = apr_thread_mutex_lock(queue_info->idlers_mutex);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_atomic_set32(&queue_info->terminated, 1);
    if (queue_info->num_waiters) {
        apr_thread_cond_broadcast(queue_info->wait_for_idler);
    }

    return apr_thread_mutex_unlock(queue_info->idlers_mutex);
}

/*
 * Detects when the ap_queue_t is full. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ap_queue_full(queue) ((queue)->nelts == (queue)->bounds)

/*
 * Detects when the ap_queue_t is empty. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ap_queue_empty(queue) ((queue)->nelts == 0)

/*
 * Initialize the ap_queue_t.
 */
apr_status_t ap_queue_create(ap_queue_t **pqueue, int capacity, apr_pool_t *p)
{
    apr_status_t rv;
    ap_queue_t *queue;

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
    APR_RING_INIT(&queue->elts, ap_queue_elem_t, link);
    queue->bounds = (capacity > 0) ? capacity : APR_UINT32_MAX;

    *pqueue = queue;
    return APR_SUCCESS;
}

static ap_queue_elem_t *get_spare_elem(ap_queue_t *queue)
{
    ap_queue_elem_t *elem = queue->spare_elems;
    if (elem == NULL) {
        elem = apr_pcalloc(queue->spare_pool, sizeof(*elem));
    }
    else {
        queue->spare_elems = elem->next;
        elem->next = NULL;
    }
    return elem;
}

static void put_spare_elem(ap_queue_t *queue, ap_queue_elem_t *elem)
{
    elem->next = queue->spare_elems;
    queue->spare_elems = elem;
    elem->event = NULL;
}

/* Pushes the last available element to the queue. */
static void push_elem(ap_queue_t *queue, ap_queue_elem_t **pushed_elem,
                      ap_queue_event_t *event)
{
    ap_queue_elem_t *elem;

    AP_DEBUG_ASSERT(!ap_queue_full(queue));
    AP_DEBUG_ASSERT(!queue->terminated);

    elem = get_spare_elem(queue);
    if (event) {
        elem->event = event;
    }
    else {
        elem->event = &elem->my_event;
    }
    elem->event->elem = elem;

    APR_RING_INSERT_TAIL(&queue->elts, elem, ap_queue_elem_t, link);
    queue->nelts++;

    if (pushed_elem) {
        *pushed_elem = elem;
    }
}

static void APR_INLINE unlink_elem(ap_queue_t *queue, ap_queue_elem_t *elem)
{
    elem->event->elem = NULL;
    APR_RING_REMOVE(elem, link);
    APR_RING_ELEM_INIT(elem, link);
    ap_assert(queue->nelts > 0);
    queue->nelts--;
}

/*
 * Retrieves the oldest available element from the queue, waiting until one
 * becomes available.
 */
static apr_status_t pop_elem(ap_queue_t *queue, ap_queue_elem_t **pelem)
{
    for (;;) {
        apr_status_t rv;

        if (queue->terminated) {
            return APR_EOF; /* no more elements ever again */
        }

        if (!ap_queue_empty(queue)) {
            *pelem = APR_RING_FIRST(&queue->elts);
            unlink_elem(queue, *pelem);
            return APR_SUCCESS;
        }

        queue->num_waiters++;
        rv = apr_thread_cond_wait(queue->not_empty, queue->one_big_mutex);
        queue->num_waiters--;
        if (rv != APR_SUCCESS) {
            return rv;
        }

        if (queue->interrupted) {
            queue->interrupted--;
            return queue->terminated ? APR_EOF : APR_EINTR;
        }
    }
}

apr_status_t ap_queue_push_event(ap_queue_t *queue, ap_queue_event_t *event)
{
    apr_status_t rv;

    if ((rv = ap_queue_lock(queue)) != APR_SUCCESS) {
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
        if (queue->num_waiters) {
            apr_thread_cond_signal(queue->not_empty);
        }
        break;

    default:
        rv = APR_EINVAL;
        break;
    }

    ap_queue_unlock(queue);
    return rv;
}

apr_status_t ap_queue_pop_event(ap_queue_t *queue, ap_queue_event_t **pevent)
{
    apr_status_t rv;
    ap_queue_elem_t *elem;

    *pevent = NULL;

    if ((rv = ap_queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    rv = pop_elem(queue, &elem);
    if (rv == APR_SUCCESS) {
        ap_queue_event_t *event = elem->event;
        ap_assert(event && event != &elem->my_event);
        put_spare_elem(queue, elem);
        if (event->cb) {
            event->cb(event->cb_baton, 0);
        }
        *pevent = event;
    }

    ap_queue_unlock(queue);
    return rv;
}

void ap_queue_kill_event_locked(ap_queue_t *queue, ap_queue_event_t *event)
{
    ap_queue_elem_t *elem = event->elem;
    ap_assert(elem && APR_RING_NEXT(elem, link) != elem);

    unlink_elem(queue, elem);
    put_spare_elem(queue, elem);
    if (event->cb) {
        event->cb(event->cb_baton, 0);
    }
}

apr_status_t ap_queue_lock(ap_queue_t *queue)
{
    return apr_thread_mutex_lock(queue->one_big_mutex);
}

apr_status_t ap_queue_unlock(ap_queue_t *queue)
{
    return apr_thread_mutex_unlock(queue->one_big_mutex);
}

/**
 * Push something onto the queue.
 */
apr_status_t ap_queue_push_something(ap_queue_t *queue,
                                     apr_socket_t *sd, void *baton,
                                     apr_pool_t *p, timer_event_t *te)
{
    apr_status_t rv;
    ap_queue_elem_t *elem;

    ap_assert(sd || te);

    if ((rv = ap_queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    push_elem(queue, &elem, NULL);
    if (te) {
        elem->event->type = AP_QUEUE_EVENT_TIMER;
        elem->event->data.te = te;
    }
    else {
        elem->event->type = AP_QUEUE_EVENT_SOCK;
        elem->event->data.se = &elem->my_sock_event;
        elem->event->data.se->sd = sd;
        elem->event->data.se->baton = baton;
        elem->event->data.se->p = p;
    }

    if (queue->num_waiters) {
        apr_thread_cond_signal(queue->not_empty);
    }

    ap_queue_unlock(queue);
    return APR_SUCCESS;
}

/**
 * Pop something from the queue.
 */
apr_status_t ap_queue_pop_something(ap_queue_t *queue,
                                    apr_socket_t **sd, void **baton,
                                    apr_pool_t **p, timer_event_t **te)
{
    apr_status_t rv;
    ap_queue_elem_t *elem;

    ap_assert(sd);

    if (sd) {
        *sd = NULL;
    }
    if (baton) {
        *baton = NULL;
    }
    if (p) {
        *p = NULL;
    }
    if (te) {
        *te = NULL;
    }

    if ((rv = ap_queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    rv = pop_elem(queue, &elem);
    if (rv == APR_SUCCESS) {
        ap_queue_event_t *event = elem->event;
        ap_assert(event && event == &elem->my_event);
        switch (event->type) {
        case AP_QUEUE_EVENT_SOCK:
            ap_assert(sd && event->data.se);
            *sd = event->data.se->sd;
            if (baton) {
                *baton = event->data.se->baton;
            }
            if (p) {
                *p = event->data.se->p;
            }
            break;

        case AP_QUEUE_EVENT_TIMER:
            ap_assert(te && event->data.te);
            *te = event->data.te;
            break;

        case AP_QUEUE_EVENT_BATON:
            ap_assert(baton && event->data.baton);
            *baton = event->data.baton;
            break;

        default:
            ap_assert(0);
            break;
        }
        put_spare_elem(queue, elem);
    }

    ap_queue_unlock(queue);
    return rv;
}

static apr_status_t queue_interrupt(ap_queue_t *queue, int all, int term)
{
    apr_status_t rv;

    if ((rv = ap_queue_lock(queue)) != APR_SUCCESS) {
        return rv;
    }

    /* we must hold one_big_mutex when setting this... otherwise,
     * we could end up setting it and waking everybody up just after a
     * would-be popper checks it but right before they block
     */
    if (term) {
        apr_atomic_set32(&queue->terminated, 1);
    }
    if (queue->num_waiters) {
        if (all) {
            queue->interrupted = queue->num_waiters;
            apr_thread_cond_broadcast(queue->not_empty);
        }
        else {
            queue->interrupted = 1;
            apr_thread_cond_signal(queue->not_empty);
        }
    }

    ap_queue_unlock(queue);
    return APR_SUCCESS;
}

apr_status_t ap_queue_interrupt_all(ap_queue_t *queue)
{
    return queue_interrupt(queue, 1, 0);
}

apr_status_t ap_queue_interrupt_one(ap_queue_t *queue)
{
    return queue_interrupt(queue, 0, 0);
}

apr_status_t ap_queue_term(ap_queue_t *queue)
{
    return queue_interrupt(queue, 1, 1);
}

#endif /* APR_HAS_THREADS */
