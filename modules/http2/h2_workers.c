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
    h2_slot *next;
    h2_workers *workers;
    int aborted;
    int sticks;
    h2_task *task;
    apr_thread_t *thread;
    apr_thread_cond_t *not_idle;
};

static h2_slot *pop_slot(h2_slot **phead) 
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

static void push_slot(h2_slot **phead, h2_slot *slot)
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

static void wake_idle_worker(h2_workers *workers) 
{
    h2_slot *slot = pop_slot(&workers->idle);
    if (slot) {
        apr_thread_mutex_lock(workers->lock);
        apr_thread_cond_signal(slot->not_idle);
        apr_thread_mutex_unlock(workers->lock);
    }
}

static void cleanup_zombies(h2_workers *workers)
{
    h2_slot *slot;
    while ((slot = pop_slot(&workers->zombies))) {
        if (slot->thread) {
            apr_status_t status;
            apr_thread_join(&status, slot->thread);
            slot->thread = NULL;
        }
        --workers->worker_count;
        push_slot(&workers->free, slot);
    }
}

static apr_status_t slot_pull_task(h2_slot *slot, h2_mplx *m)
{
    int has_more;
    slot->task = h2_mplx_pop_task(m, &has_more);
    if (slot->task) {
        /* Ok, we got something to give back to the worker for execution. 
         * If we still have idle workers, we let the worker be sticky, 
         * e.g. making it poll the task's h2_mplx instance for more work 
         * before asking back here. */
        slot->sticks = slot->workers->max_workers;
        return has_more? APR_EAGAIN : APR_SUCCESS;            
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
static apr_status_t get_next(h2_slot *slot)
{
    h2_workers *workers = slot->workers;
    apr_status_t status;
    
    slot->task = NULL;
    while (!slot->aborted) {
        if (!slot->task) {
            status = h2_fifo_try_peek(workers->mplxs, mplx_peek, slot);
        }
        
        if (slot->task) {
            return APR_SUCCESS;
        }
        
        apr_thread_mutex_lock(workers->lock);
        ++workers->idle_workers;
        cleanup_zombies(workers);
        if (slot->next == NULL) {
            push_slot(&workers->idle, slot);
        }
        apr_thread_cond_wait(slot->not_idle, workers->lock);
        apr_thread_mutex_unlock(workers->lock);
    }
    return APR_EOF;
}

static void slot_done(h2_slot *slot)
{
    push_slot(&(slot->workers->zombies), slot);
}


static void* APR_THREAD_FUNC slot_run(apr_thread_t *thread, void *wctx)
{
    h2_slot *slot = wctx;
    
    while (!slot->aborted) {

        /* Get a h2_task from the mplxs queue. */
        get_next(slot);
        while (slot->task) {
        
            h2_task_do(slot->task, thread, slot->id);
            
            /* Report the task as done. If stickyness is left, offer the
             * mplx the opportunity to give us back a new task right away.
             */
            if (!slot->aborted && (--slot->sticks > 0)) {
                h2_mplx_task_done(slot->task->mplx, slot->task, &slot->task);
            }
            else {
                h2_mplx_task_done(slot->task->mplx, slot->task, NULL);
                slot->task = NULL;
            }
        }
    }

    slot_done(slot);
    return NULL;
}

static apr_status_t activate_slot(h2_workers *workers)
{
    h2_slot *slot = pop_slot(&workers->free);
    if (slot) {
        apr_status_t status;
        
        slot->workers = workers;
        slot->aborted = 0;
        slot->task = NULL;
        if (!slot->not_idle) {
            status = apr_thread_cond_create(&slot->not_idle, workers->pool);
            if (status != APR_SUCCESS) {
                push_slot(&workers->free, slot);
                return status;
            }
        }
        
        apr_thread_create(&slot->thread, workers->thread_attr, slot_run, slot, 
                          workers->pool);
        if (!slot->thread) {
            push_slot(&workers->free, slot);
            return APR_ENOMEM;
        }

        ++workers->worker_count;
        return APR_SUCCESS;
    }
    return APR_EAGAIN;
}

static apr_status_t workers_pool_cleanup(void *data)
{
    h2_workers *workers = data;
    h2_slot *slot;
    
    if (!workers->aborted) {
        apr_thread_mutex_lock(workers->lock);
        workers->aborted = 1;
        /* before we go, cleanup any zombies and abort the rest */
        cleanup_zombies(workers);
        for (;;) {
            slot = pop_slot(&workers->idle);
            if (slot) {
                slot->aborted = 1;
                apr_thread_cond_signal(slot->not_idle);
            }
            else {
                break;
            }
        }
        apr_thread_mutex_unlock(workers->lock);

        h2_fifo_term(workers->mplxs);
        h2_fifo_interrupt(workers->mplxs);
    }
    return APR_SUCCESS;
}

h2_workers *h2_workers_create(server_rec *s, apr_pool_t *server_pool,
                              int min_workers, int max_workers,
                              int idle_secs)
{
    apr_status_t status;
    h2_workers *workers;
    apr_pool_t *pool;
    int i;

    ap_assert(s);
    ap_assert(server_pool);

    /* let's have our own pool that will be parent to all h2_worker
     * instances we create. This happens in various threads, but always
     * guarded by our lock. Without this pool, all subpool creations would
     * happen on the pool handed to us, which we do not guard.
     */
    apr_pool_create(&pool, server_pool);
    apr_pool_tag(pool, "h2_workers");
    workers = apr_pcalloc(pool, sizeof(h2_workers));
    if (!workers) {
        return NULL;
    }
    
    workers->s = s;
    workers->pool = pool;
    workers->min_workers = min_workers;
    workers->max_workers = max_workers;
    workers->max_idle_secs = (idle_secs > 0)? idle_secs : 10;

    status = h2_fifo_create(&workers->mplxs, pool, workers->max_workers);
    if (status != APR_SUCCESS) {
        return NULL;
    }
    
    status = apr_threadattr_create(&workers->thread_attr, workers->pool);
    if (status != APR_SUCCESS) {
        return NULL;
    }
    
    if (ap_thread_stacksize != 0) {
        apr_threadattr_stacksize_set(workers->thread_attr,
                                     ap_thread_stacksize);
        ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                     "h2_workers: using stacksize=%ld", 
                     (long)ap_thread_stacksize);
    }
    
    status = apr_thread_mutex_create(&workers->lock,
                                     APR_THREAD_MUTEX_DEFAULT,
                                     workers->pool);
    if (status == APR_SUCCESS) {        
        int n = workers->nslots = workers->max_workers;
        workers->slots = apr_pcalloc(workers->pool, n * sizeof(h2_slot));
        if (workers->slots == NULL) {
            status = APR_ENOMEM;
        }
    }
    if (status == APR_SUCCESS) {        
        workers->free = &workers->slots[0];
        for (i = 0; i < workers->nslots-1; ++i) {
            workers->slots[i].next = &workers->slots[i+1];
            workers->slots[i].id = i;
        }
        while (workers->worker_count < workers->max_workers 
               && status == APR_SUCCESS) {
            status = activate_slot(workers);
        }
    }
    if (status == APR_SUCCESS) {
        apr_pool_pre_cleanup_register(pool, workers, workers_pool_cleanup);    
        return workers;
    }
    return NULL;
}

apr_status_t h2_workers_register(h2_workers *workers, struct h2_mplx *m)
{
    apr_status_t status;
    if ((status = h2_fifo_try_push(workers->mplxs, m)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_TRACE3, status, workers->s,
                     "h2_workers: unable to push mplx(%ld)", m->id);
    } 
    wake_idle_worker(workers);
    return status;
}

apr_status_t h2_workers_unregister(h2_workers *workers, struct h2_mplx *m)
{
    return h2_fifo_remove(workers->mplxs, m);
}
