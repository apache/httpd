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

#include <assert.h>
#include <apr_atomic.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "h2.h"
#include "h2_private.h"
#include "h2_mplx.h"
#include "h2_task.h"
#include "h2_workers.h"
#include "h2_util.h"

typedef struct h2_slot h2_slot;
struct h2_slot {
    int id;
    int sticks;
    h2_slot *next;
    h2_workers *workers;
    h2_task *task;
    apr_thread_t *thread;
    apr_thread_mutex_t *lock;
    apr_thread_cond_t *not_idle;
    volatile apr_uint32_t timed_out;
};

static h2_slot *pop_slot(h2_slot *volatile *phead) 
{
    /* Atomically pop a slot from the list */
    for (;;) {
        h2_slot *first = *phead;
        if (first == NULL) {
            return NULL;
        }
        if (apr_atomic_casptr((void*)phead, first->next, first) == first) {
            first->next = NULL;
            return first;
        }
    }
}

static void push_slot(h2_slot *volatile *phead, h2_slot *slot)
{
    /* Atomically push a slot to the list */
    ap_assert(!slot->next);
    for (;;) {
        h2_slot *next = slot->next = *phead;
        if (apr_atomic_casptr((void*)phead, slot, next) == next) {
            return;
        }
    }
}

static void* APR_THREAD_FUNC slot_run(apr_thread_t *thread, void *wctx);
static void slot_done(h2_slot *slot);

static apr_status_t activate_slot(h2_workers *workers, h2_slot *slot) 
{
    apr_status_t rv;
    
    slot->workers = workers;
    slot->task = NULL;

    apr_thread_mutex_lock(workers->lock);
    if (!slot->lock) {
        rv = apr_thread_mutex_create(&slot->lock,
                                         APR_THREAD_MUTEX_DEFAULT,
                                         workers->pool);
        if (rv != APR_SUCCESS) goto cleanup;
    }

    if (!slot->not_idle) {
        rv = apr_thread_cond_create(&slot->not_idle, workers->pool);
        if (rv != APR_SUCCESS) goto cleanup;
    }
    
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, workers->s,
                 "h2_workers: new thread for slot %d", slot->id); 

    /* thread will either immediately start work or add itself
     * to the idle queue */
    apr_atomic_inc32(&workers->worker_count);
    slot->timed_out = 0;
    rv = apr_thread_create(&slot->thread, workers->thread_attr,
                               slot_run, slot, workers->pool);
    if (rv != APR_SUCCESS) {
        apr_atomic_dec32(&workers->worker_count);
    }

cleanup:
    apr_thread_mutex_unlock(workers->lock);
    if (rv != APR_SUCCESS) {
        push_slot(&workers->free, slot);
    }
    return rv;
}

static apr_status_t add_worker(h2_workers *workers)
{
    h2_slot *slot = pop_slot(&workers->free);
    if (slot) {
        return activate_slot(workers, slot);
    }
    return APR_EAGAIN;
}

static void wake_idle_worker(h2_workers *workers) 
{
    h2_slot *slot = pop_slot(&workers->idle);
    if (slot) {
        int timed_out = 0;
        apr_thread_mutex_lock(slot->lock);
        timed_out = slot->timed_out;
        if (!timed_out) {
            apr_thread_cond_signal(slot->not_idle);
        }
        apr_thread_mutex_unlock(slot->lock);
        if (timed_out) {
            slot_done(slot);
            wake_idle_worker(workers);
        }
    }
    else if (workers->dynamic && !workers->shutdown) {
        add_worker(workers);
    }
}

static void join_zombies(h2_workers *workers)
{
    h2_slot *slot;
    while ((slot = pop_slot(&workers->zombies))) {
        apr_status_t status;
        ap_assert(slot->thread != NULL);
        apr_thread_join(&status, slot->thread);
        slot->thread = NULL;

        push_slot(&workers->free, slot);
    }
}

static apr_status_t slot_pull_task(h2_slot *slot, h2_mplx *m)
{
    apr_status_t rv;
    
    rv = h2_mplx_s_pop_task(m, &slot->task);
    if (slot->task) {
        /* Ok, we got something to give back to the worker for execution. 
         * If we still have idle workers, we let the worker be sticky, 
         * e.g. making it poll the task's h2_mplx instance for more work 
         * before asking back here. */
        slot->sticks = slot->workers->max_workers;
        return rv;            
    }
    slot->sticks = 0;
    return APR_EOF;
}

static h2_fifo_op_t mplx_peek(void *head, void *ctx)
{
    h2_mplx *m = head;
    h2_slot *slot = ctx;
    
    if (slot_pull_task(slot, m) == APR_EAGAIN) {
        wake_idle_worker(slot->workers);
        return H2_FIFO_OP_REPUSH;
    } 
    return H2_FIFO_OP_PULL;
}

/**
 * Get the next task for the given worker. Will block until a task arrives
 * or the max_wait timer expires and more than min workers exist.
 */
static int get_next(h2_slot *slot)
{
    h2_workers *workers = slot->workers;
    int non_essential = slot->id >= workers->min_workers;
    apr_status_t rv;

    while (!workers->aborted && !slot->timed_out) {
        ap_assert(slot->task == NULL);
        if (non_essential && workers->shutdown) {
            /* Terminate non-essential worker on shutdown */
            break;
        }
        if (h2_fifo_try_peek(workers->mplxs, mplx_peek, slot) == APR_EOF) {
            /* The queue is terminated with the MPM child being cleaned up,
             * just leave. */
            break;
        }
        if (slot->task) {
            return 1;
        }
        
        join_zombies(workers);

        apr_thread_mutex_lock(slot->lock);
        if (!workers->aborted) {

            push_slot(&workers->idle, slot);
            if (non_essential && workers->max_idle_duration) {
                rv = apr_thread_cond_timedwait(slot->not_idle, slot->lock,
                                               workers->max_idle_duration);
                if (APR_TIMEUP == rv) {
                    slot->timed_out = 1;
                }
            }
            else {
                apr_thread_cond_wait(slot->not_idle, slot->lock);
            }
        }
        apr_thread_mutex_unlock(slot->lock);
    }

    return 0;
}

static void slot_done(h2_slot *slot)
{
    h2_workers *workers = slot->workers;

    push_slot(&workers->zombies, slot);

    /* If this worker is the last one exiting and the MPM child is stopping,
     * unblock workers_pool_cleanup().
     */
    if (!apr_atomic_dec32(&workers->worker_count) && workers->aborted) {
        apr_thread_mutex_lock(workers->lock);
        apr_thread_cond_signal(workers->all_done);
        apr_thread_mutex_unlock(workers->lock);
    }
}


static void* APR_THREAD_FUNC slot_run(apr_thread_t *thread, void *wctx)
{
    h2_slot *slot = wctx;
    
    /* Get the h2_task(s) from the ->mplxs queue. */
    while (get_next(slot)) {
        ap_assert(slot->task != NULL);
        do {
            h2_task_do(slot->task, thread, slot->id);
            
            /* Report the task as done. If stickyness is left, offer the
             * mplx the opportunity to give us back a new task right away.
             */
            if (!slot->workers->aborted && --slot->sticks > 0) {
                h2_mplx_s_task_done(slot->task->mplx, slot->task, &slot->task);
            }
            else {
                h2_mplx_s_task_done(slot->task->mplx, slot->task, NULL);
                slot->task = NULL;
            }
        } while (slot->task);
    }

    if (!slot->timed_out) {
        slot_done(slot);
    }

    apr_thread_exit(thread, APR_SUCCESS);
    return NULL;
}

static void wake_non_essential_workers(h2_workers *workers)
{
    h2_slot *slot;
    /* pop all idle, signal the non essentials and add the others again */
    if ((slot = pop_slot(&workers->idle))) {
        wake_non_essential_workers(workers);
        if (slot->id > workers->min_workers) {
            apr_thread_mutex_lock(slot->lock);
            apr_thread_cond_signal(slot->not_idle);
            apr_thread_mutex_unlock(slot->lock);
        }
        else {
            push_slot(&workers->idle, slot);
        }
    }
}

static void workers_abort_idle(h2_workers *workers)
{
    h2_slot *slot;

    workers->shutdown = 1;
    workers->aborted = 1;
    h2_fifo_term(workers->mplxs);

    /* abort all idle slots */
    while ((slot = pop_slot(&workers->idle))) {
        apr_thread_mutex_lock(slot->lock);
        apr_thread_cond_signal(slot->not_idle);
        apr_thread_mutex_unlock(slot->lock);
    }
}

static apr_status_t workers_pool_cleanup(void *data)
{
    h2_workers *workers = data;

    workers_abort_idle(workers);

    /* wait for all the workers to become zombies and join them */
    apr_thread_mutex_lock(workers->lock);
    if (apr_atomic_read32(&workers->worker_count)) {
        apr_thread_cond_wait(workers->all_done, workers->lock);
    }
    apr_thread_mutex_unlock(workers->lock);
    join_zombies(workers);

    return APR_SUCCESS;
}

h2_workers *h2_workers_create(server_rec *s, apr_pool_t *pchild,
                              int min_workers, int max_workers,
                              int idle_secs)
{
    apr_status_t rv;
    h2_workers *workers;
    apr_pool_t *pool;
    int i, n;

    ap_assert(s);
    ap_assert(pchild);

    /* let's have our own pool that will be parent to all h2_worker
     * instances we create. This happens in various threads, but always
     * guarded by our lock. Without this pool, all subpool creations would
     * happen on the pool handed to us, which we do not guard.
     */
    apr_pool_create(&pool, pchild);
    apr_pool_tag(pool, "h2_workers");
    workers = apr_pcalloc(pool, sizeof(h2_workers));
    if (!workers) {
        return NULL;
    }
    
    workers->s = s;
    workers->pool = pool;
    workers->min_workers = min_workers;
    workers->max_workers = max_workers;
    workers->max_idle_duration = apr_time_from_sec((idle_secs > 0)? idle_secs : 10);

    /* FIXME: the fifo set we use here has limited capacity. Once the
     * set is full, connections with new requests do a wait. Unfortunately,
     * we have optimizations in place there that makes such waiting "unfair"
     * in the sense that it may take connections a looong time to get scheduled.
     *
     * Need to rewrite this to use one of our double-linked lists and a mutex
     * to have unlimited capacity and fair scheduling.
     *
     * For now, we just make enough room to have many connections inside one
     * process.
     */
    rv = h2_fifo_set_create(&workers->mplxs, pool, 8 * 1024);
    if (rv != APR_SUCCESS) goto cleanup;

    rv = apr_threadattr_create(&workers->thread_attr, workers->pool);
    if (rv != APR_SUCCESS) goto cleanup;

    if (ap_thread_stacksize != 0) {
        apr_threadattr_stacksize_set(workers->thread_attr,
                                     ap_thread_stacksize);
        ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                     "h2_workers: using stacksize=%ld", 
                     (long)ap_thread_stacksize);
    }
    
    rv = apr_thread_mutex_create(&workers->lock,
                                 APR_THREAD_MUTEX_DEFAULT,
                                 workers->pool);
    if (rv != APR_SUCCESS) goto cleanup;
    rv = apr_thread_cond_create(&workers->all_done, workers->pool);
    if (rv != APR_SUCCESS) goto cleanup;

    n = workers->nslots = workers->max_workers;
    workers->slots = apr_pcalloc(workers->pool, n * sizeof(h2_slot));
    if (workers->slots == NULL) {
        n = workers->nslots = 0;
        rv = APR_ENOMEM;
        goto cleanup;
    }
    for (i = 0; i < n; ++i) {
        workers->slots[i].id = i;
    }
    /* we activate all for now, TODO: support min_workers again.
     * do this in reverse for vanity reasons so slot 0 will most
     * likely be at head of idle queue. */
    n = workers->min_workers;
    for (i = n-1; i >= 0; --i) {
        rv = activate_slot(workers, &workers->slots[i]);
        if (rv != APR_SUCCESS) goto cleanup;
    }
    /* the rest of the slots go on the free list */
    for(i = n; i < workers->nslots; ++i) {
        push_slot(&workers->free, &workers->slots[i]);
    }
    workers->dynamic = (workers->worker_count < workers->max_workers);

cleanup:
    if (rv == APR_SUCCESS) {
        /* Stop/join the workers threads when the MPM child exits (pchild is
         * destroyed), and as a pre_cleanup of pchild thus before the threads
         * pools (children of workers->pool) so that they are not destroyed
         * before/under us.
         */
        apr_pool_pre_cleanup_register(pchild, workers, workers_pool_cleanup);    
        return workers;
    }
    return NULL;
}

apr_status_t h2_workers_register(h2_workers *workers, struct h2_mplx *m)
{
    apr_status_t status = h2_fifo_push(workers->mplxs, m);
    wake_idle_worker(workers);
    return status;
}

apr_status_t h2_workers_unregister(h2_workers *workers, struct h2_mplx *m)
{
    return h2_fifo_remove(workers->mplxs, m);
}

void h2_workers_graceful_shutdown(h2_workers *workers)
{
    workers->shutdown = 1;
    h2_fifo_term(workers->mplxs);
    wake_non_essential_workers(workers);
}
