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
#include <apr_ring.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>

#include "h2.h"
#include "h2_private.h"
#include "h2_mplx.h"
#include "h2_c2.h"
#include "h2_workers.h"
#include "h2_util.h"

typedef enum {
    PROD_IDLE,
    PROD_ACTIVE,
    PROD_JOINED,
} prod_state_t;

struct ap_conn_producer_t {
    APR_RING_ENTRY(ap_conn_producer_t) link;
    const char *name;
    void *baton;
    ap_conn_producer_next *fn_next;
    ap_conn_producer_done *fn_done;
    volatile prod_state_t state;
    volatile int conns_active;
};


typedef enum {
    H2_SLOT_FREE,
    H2_SLOT_RUN,
    H2_SLOT_ZOMBIE,
} h2_slot_state_t;

typedef struct h2_slot h2_slot;
struct h2_slot {
    APR_RING_ENTRY(h2_slot) link;
    int id;
    h2_slot_state_t state;
    volatile int should_shutdown;
    volatile int is_idle;
    volatile apr_time_t processing_start;
    h2_workers *workers;
    ap_conn_producer_t *prod;
    apr_thread_t *thread;
    struct apr_thread_cond_t *more_work;
    int activations;
};

typedef struct perf_tuner_t perf_tuner_t;
struct perf_tuner_t {
    h2_workers *workers;
    apr_thread_t *thread;
    struct apr_thread_cond_t *wait;
    apr_time_t wait_time;

    apr_time_t measure_action_delay;
    apr_time_t measure_start;
    apr_uint32_t measures;
    apr_uint32_t advised_average;
};

struct h2_workers {
    server_rec *s;
    apr_pool_t *pool;

    apr_uint32_t max_slots;
    apr_uint32_t min_active;
    volatile int max_idle_secs;
    volatile int aborted;
    volatile int shutdown;
    int dynamic;

    apr_uint32_t fast_slots;
    apr_time_t long_duration;
    volatile apr_uint32_t max_active;
    volatile apr_uint32_t active_slots;
    volatile apr_uint32_t idle_slots;
    volatile apr_uint32_t busy_slots;

    apr_threadattr_t *thread_attr;
    h2_slot *slots;
    perf_tuner_t tuner;

    APR_RING_HEAD(h2_slots_free, h2_slot) free;
    APR_RING_HEAD(h2_slots_idle, h2_slot) idle;
    APR_RING_HEAD(h2_slots_busy, h2_slot) busy;
    APR_RING_HEAD(h2_slots_zombie, h2_slot) zombie;

    APR_RING_HEAD(ap_conn_producer_active, ap_conn_producer_t) prod_active;
    APR_RING_HEAD(ap_conn_producer_idle, ap_conn_producer_t) prod_idle;

    struct apr_thread_mutex_t *lock;
    struct apr_thread_cond_t *prod_done;
    struct apr_thread_cond_t *all_done;
};


static void* APR_THREAD_FUNC slot_run(apr_thread_t *thread, void *wctx);

static apr_status_t activate_slot(h2_workers *workers)
{
    h2_slot *slot;
    apr_status_t rv;

    if (APR_RING_EMPTY(&workers->free, h2_slot, link)) {
        return APR_EAGAIN;
    }
    slot = APR_RING_FIRST(&workers->free);
    ap_assert(slot->state == H2_SLOT_FREE);
    APR_RING_REMOVE(slot, link);

    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, workers->s,
                 "h2_workers: activate slot %d", slot->id);

    slot->state = H2_SLOT_RUN;
    slot->should_shutdown = 0;
    slot->is_idle = 0;
    ++workers->active_slots;
    rv = ap_thread_create(&slot->thread, workers->thread_attr,
                          slot_run, slot, workers->pool);

    if (rv != APR_SUCCESS) {
        AP_DEBUG_ASSERT(0);
        slot->state = H2_SLOT_FREE;
        APR_RING_INSERT_TAIL(&workers->free, slot, h2_slot, link);
        --workers->active_slots;
    }
    return rv;
}

static void join_zombies(h2_workers *workers)
{
    h2_slot *slot;
    apr_status_t status;

    while (!APR_RING_EMPTY(&workers->zombie, h2_slot, link)) {
        slot = APR_RING_FIRST(&workers->zombie);
        APR_RING_REMOVE(slot, link);
        ap_assert(slot->state == H2_SLOT_ZOMBIE);
        ap_assert(slot->thread != NULL);

        apr_thread_mutex_unlock(workers->lock);
        apr_thread_join(&status, slot->thread);
        apr_thread_mutex_lock(workers->lock);

        slot->thread = NULL;
        slot->state = H2_SLOT_FREE;
        APR_RING_INSERT_TAIL(&workers->free, slot, h2_slot, link);
    }
}

static void* APR_THREAD_FUNC tuner_run(apr_thread_t *thread, void *wctx)
{
    perf_tuner_t *tuner = wctx;
    h2_workers *workers = tuner->workers;
    apr_status_t rv;

    apr_thread_mutex_lock(workers->lock);
    for (;;) {
        rv = apr_thread_cond_timedwait(tuner->wait, workers->lock,
                                       tuner->wait_time);
        if (workers->aborted || workers->shutdown) {
            break;
        }

        if (APR_TIMEUP == rv) {
            int long_runners = 0, i, desired, delta;
            apr_time_t now = apr_time_now();

            if (APR_RING_EMPTY(&workers->prod_active, ap_conn_producer_t, link)) {
                /* no pending work, no adjustments necessary */
                continue;
            }

            /* Count the long running processing slots. */
            if (!APR_RING_EMPTY(&workers->busy, h2_slot, link)) {
                h2_slot *slot;

                for (slot = APR_RING_FIRST(&workers->busy);
                     slot != APR_RING_SENTINEL(&workers->busy, h2_slot, link);
                     slot = APR_RING_NEXT(slot, link)) {
                    apr_time_t started = slot->processing_start;
                    if (started && now - started >= workers->long_duration) {
                        ++long_runners;
                    }
                }
            }

            /* what change in number of active slots would we like to see? */
            desired = H2MIN(workers->max_slots,
                            workers->fast_slots + long_runners);
            if (desired == workers->max_active) {
                /* number of active workers is as it should be */
                tuner->measures = 0;
                ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, workers->s,
                             "h2_workers tune, all fine: slots[%d,%d], active=%d",
                             workers->min_active, workers->max_slots,
                             workers->active_slots);
                continue;
            }

            join_zombies(workers);

            if (!tuner->measures) {
                tuner->measure_start = now;
                tuner->measures = 1;
                tuner->advised_average = desired;
            }
            else {
                desired = ((tuner->advised_average * tuner->measures) + desired);
                ++tuner->measures;
                tuner->advised_average = (desired / tuner->measures);
            }

            delta = tuner->advised_average - workers->active_slots;
            if (delta > 0) {
                /* indications that we need more workers are acted on immediately */
                workers->max_active = tuner->advised_average;
                tuner->measures = 0;
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, workers->s,
                             "h2_workers tune, increase: slots[%d,%d], active=%d, "
                             "new max_active=%d, long_runners=%d",
                             workers->min_active, workers->max_slots,
                             workers->active_slots, workers->max_active,
                             long_runners);

                /* revert shutdown slots that have not already done so */
                for (i = 0; i < workers->max_slots && delta > 0; ++i) {
                    if (workers->slots[i].should_shutdown
                        && workers->slots[i].state == H2_SLOT_RUN) {
                        workers->slots[i].should_shutdown = 0;
                        --delta;
                        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, workers->s,
                                     "h2_workers tune: un-shutdown slot[%d]", workers->slots[i].id);
                    }
                }
                if (delta > 0) {
                    /* if still not enough, activate another slot */
                    ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, workers->s,
                                 "h2_workers tune: activate slot");
                    activate_slot(workers);
                }
            }
            else if (delta < 0 && (now - tuner->measure_start) >= tuner->measure_action_delay) {
                /* reductions of workers we do only after a certain delay on more samples */
                workers->max_active = tuner->advised_average;
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, workers->s,
                             "h2_workers tune, decrease: slots[%d,%d], active=%d, "
                             "adviced_active=%d (%d measures), long_runners=%d",
                             workers->min_active, workers->max_slots,
                             workers->active_slots, workers->max_active,
                             tuner->measures, long_runners);
                tuner->measures = 0;

                /* discounts slots, we already told to shutdown. */
                for (i = workers->min_active; i < workers->max_slots; ++i) {
                    if (workers->slots[i].should_shutdown) {
                        ++delta;
                        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, workers->s,
                                     "h2_workers tune: already shutdown slot[%d]", workers->slots[i].id);
                    }
                }
                /* And tell more to shutdown if necessary */
                for (i = workers->min_active; i < workers->max_slots && delta < 0; ++i) {
                    if (!workers->slots[i].should_shutdown
                        && workers->slots[i].state == H2_SLOT_RUN) {
                        workers->slots[i].should_shutdown = 1;
                        ++delta;
                        apr_thread_cond_signal(workers->slots[i].more_work);
                        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, workers->s,
                                     "h2_workers tune: shutdown slot[%d]", workers->slots[i].id);
                    }
                }
            }
        }
        else {
            /* awoken by someone's need? */
        }
    }
    apr_thread_mutex_unlock(workers->lock);

    apr_thread_exit(thread, APR_SUCCESS);
    return NULL;
}

static apr_status_t tuner_start(h2_workers *workers)
{
    perf_tuner_t *tuner = &workers->tuner;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, workers->s,
                 "h2_workers: start tuner");
    tuner->workers = workers;
    tuner->wait_time = apr_time_from_msec(100);
    tuner->measure_action_delay = apr_time_from_msec(1000);
    tuner->measures = 0;
    tuner->measure_start = apr_time_now();

    rv = apr_thread_cond_create(&tuner->wait, workers->pool);
    if (rv != APR_SUCCESS) goto cleanup;

    rv = ap_thread_create(&tuner->thread, workers->thread_attr,
                          tuner_run, tuner, workers->pool);
cleanup:
    return rv;
}

static void wake_idle_worker(h2_workers *workers, ap_conn_producer_t *prod)
{
    if (!APR_RING_EMPTY(&workers->idle, h2_slot, link)) {
        h2_slot *slot;
        for (slot = APR_RING_FIRST(&workers->idle);
             slot != APR_RING_SENTINEL(&workers->idle, h2_slot, link);
             slot = APR_RING_NEXT(slot, link)) {
             if (slot->is_idle && !slot->should_shutdown) {
                apr_thread_cond_signal(slot->more_work);
                slot->is_idle = 0;
                return;
             }
        }
    }
    if (workers->dynamic && !workers->shutdown
        && (workers->active_slots < workers->max_active)) {
        activate_slot(workers);
    }
}

/**
 * Get the next connection to work on.
 */
static conn_rec *get_next(h2_slot *slot)
{
    h2_workers *workers = slot->workers;
    conn_rec *c = NULL;
    ap_conn_producer_t *prod;
    int has_more;

    slot->prod = NULL;
    if (!APR_RING_EMPTY(&workers->prod_active, ap_conn_producer_t, link)) {
        slot->prod = prod = APR_RING_FIRST(&workers->prod_active);
        APR_RING_REMOVE(prod, link);
        AP_DEBUG_ASSERT(PROD_ACTIVE == prod->state);

        c = prod->fn_next(prod->baton, &has_more);
        if (c && has_more) {
            APR_RING_INSERT_TAIL(&workers->prod_active, prod, ap_conn_producer_t, link);
            wake_idle_worker(workers, slot->prod);
        }
        else {
            prod->state = PROD_IDLE;
            APR_RING_INSERT_TAIL(&workers->prod_idle, prod, ap_conn_producer_t, link);
        }
        if (c) {
            ++prod->conns_active;
        }
    }

    return c;
}

static void* APR_THREAD_FUNC slot_run(apr_thread_t *thread, void *wctx)
{
    h2_slot *slot = wctx;
    h2_workers *workers = slot->workers;
    apr_uint32_t idle_secs;
    conn_rec *c;
    apr_status_t rv;

    apr_thread_mutex_lock(workers->lock);
    slot->state = H2_SLOT_RUN;
    ++slot->activations;
    APR_RING_ELEM_INIT(slot, link);
    for(;;) {
        if (APR_RING_NEXT(slot, link) != slot) {
            /* slot is part of the idle ring from the last loop */
            APR_RING_REMOVE(slot, link);
            --workers->idle_slots;
        }
        slot->is_idle = 0;
        slot->processing_start = 0;

        if (!workers->aborted && !slot->should_shutdown) {
            APR_RING_INSERT_TAIL(&workers->busy, slot, h2_slot, link);
            ++workers->busy_slots;
            do {
                c = get_next(slot);
                if (!c) {
                    break;
                }
                slot->processing_start = apr_time_now();
                apr_thread_mutex_unlock(workers->lock);
                /* See the discussion at <https://github.com/icing/mod_h2/issues/195>
                 *
                 * Each conn_rec->id is supposed to be unique at a point in time. Since
                 * some modules (and maybe external code) uses this id as an identifier
                 * for the request_rec they handle, it needs to be unique for secondary
                 * connections also.
                 *
                 * The MPM module assigns the connection ids and mod_unique_id is using
                 * that one to generate identifier for requests. While the implementation
                 * works for HTTP/1.x, the parallel execution of several requests per
                 * connection will generate duplicate identifiers on load.
                 *
                 * The original implementation for secondary connection identifiers used
                 * to shift the master connection id up and assign the stream id to the
                 * lower bits. This was cramped on 32 bit systems, but on 64bit there was
                 * enough space.
                 *
                 * As issue 195 showed, mod_unique_id only uses the lower 32 bit of the
                 * connection id, even on 64bit systems. Therefore collisions in request ids.
                 *
                 * The way master connection ids are generated, there is some space "at the
                 * top" of the lower 32 bits on allmost all systems. If you have a setup
                 * with 64k threads per child and 255 child processes, you live on the edge.
                 *
                 * The new implementation shifts 8 bits and XORs in the worker
                 * id. This will experience collisions with > 256 h2 workers and heavy
                 * load still. There seems to be no way to solve this in all possible
                 * configurations by mod_h2 alone.
                 */
                if (c->master) {
                    c->id = (c->master->id << 8)^slot->id;
                }
                c->current_thread = thread;
                AP_DEBUG_ASSERT(slot->prod);

                ap_process_connection(c, ap_get_conn_socket(c));
                slot->prod->fn_done(slot->prod->baton, c);

                apr_thread_mutex_lock(workers->lock);
                if (--slot->prod->conns_active <= 0) {
                    apr_thread_cond_broadcast(workers->prod_done);
                }

            } while (!workers->aborted && !slot->should_shutdown);
            APR_RING_REMOVE(slot, link); /* no longer busy */
            --workers->busy_slots;
            slot->processing_start = 0;
        }

        if (workers->aborted || slot->should_shutdown) {
            break;
        }

        join_zombies(workers);

        /* we are idle */
        APR_RING_INSERT_TAIL(&workers->idle, slot, h2_slot, link);
        ++workers->idle_slots;
        slot->is_idle = 1;
        if (slot->id >= workers->min_active
            && (idle_secs = workers->max_idle_secs)) {
            rv = apr_thread_cond_timedwait(slot->more_work, workers->lock,
                                           apr_time_from_sec(idle_secs));
            if (APR_TIMEUP == rv) {
                APR_RING_REMOVE(slot, link);
                --workers->idle_slots;
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, workers->s,
                             "h2_workers: idle timeout slot %d in state %d (%d activations)",
                             slot->id, slot->state, slot->activations);
                break;
            }
        }
        else {
            apr_thread_cond_wait(slot->more_work, workers->lock);
        }
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, workers->s,
                 "h2_workers: terminate slot %d in state %d (%d activations)",
                 slot->id, slot->state, slot->activations);
    slot->is_idle = 0;
    slot->state = H2_SLOT_ZOMBIE;
    slot->should_shutdown = 0;
    APR_RING_INSERT_TAIL(&workers->zombie, slot, h2_slot, link);
    --workers->active_slots;
    if (workers->active_slots <= 0) {
        apr_thread_cond_broadcast(workers->all_done);
    }
    apr_thread_mutex_unlock(workers->lock);

    apr_thread_exit(thread, APR_SUCCESS);
    return NULL;
}

static void wake_all_idles(h2_workers *workers)
{
    h2_slot *slot;
    for (slot = APR_RING_FIRST(&workers->idle);
         slot != APR_RING_SENTINEL(&workers->idle, h2_slot, link);
         slot = APR_RING_NEXT(slot, link))
    {
        apr_thread_cond_signal(slot->more_work);
    }
}

static apr_status_t workers_pool_cleanup(void *data)
{
    h2_workers *workers = data;
    apr_time_t end, timeout = apr_time_from_sec(1);
    apr_status_t rv;
    int n, wait_sec = 5;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, workers->s,
                 "h2_workers: cleanup %d workers (%d busy, %d idle)",
                 workers->active_slots, workers->busy_slots, workers->idle_slots);
    apr_thread_mutex_lock(workers->lock);
    workers->shutdown = 1;
    workers->aborted = 1;
    wake_all_idles(workers);
    apr_thread_cond_signal(workers->tuner.wait);
    apr_thread_mutex_unlock(workers->lock);

    /* wait for all the workers to become zombies and join them.
     * this gets called after the mpm shuts down and all connections
     * have either been handled (graceful) or we are forced exiting
     * (ungrateful). Either way, we show limited patience. */
    end = apr_time_now() + apr_time_from_sec(wait_sec);
    while (apr_time_now() < end) {
        apr_thread_mutex_lock(workers->lock);
        if (!(n = workers->active_slots)) {
            apr_thread_mutex_unlock(workers->lock);
            break;
        }
        wake_all_idles(workers);
        apr_thread_cond_signal(workers->tuner.wait);
        rv = apr_thread_cond_timedwait(workers->all_done, workers->lock, timeout);
        apr_thread_mutex_unlock(workers->lock);

        if (APR_TIMEUP == rv) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, workers->s,
                         APLOGNO(10290) "h2_workers: waiting for workers to close, "
                         "still seeing %d workers (%d busy, %d idle) living",
                         workers->active_slots, workers->busy_slots, workers->idle_slots);
        }
    }
    if (n) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, workers->s,
                     APLOGNO(10291) "h2_workers: cleanup, %d workers (%d busy, %d idle) "
                     "did not exit after %d seconds.",
                     n, workers->busy_slots, workers->idle_slots, wait_sec);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, workers->s,
                 "h2_workers: cleanup all workers terminated");
    apr_thread_mutex_lock(workers->lock);
    join_zombies(workers);
    apr_thread_mutex_unlock(workers->lock);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, workers->s,
                 "h2_workers: cleanup zombie workers joined");
    apr_thread_join(&rv, workers->tuner.thread);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, workers->s,
                 "h2_workers: tuner thread joined");

    return APR_SUCCESS;
}

h2_workers *h2_workers_create(server_rec *s, apr_pool_t *pchild,
                              int min_active, int max_slots,
                              int idle_secs)
{
    apr_status_t rv;
    h2_workers *workers;
    apr_pool_t *pool;
    int i, locked = 0;

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
    workers->min_active = min_active;
    workers->max_slots = max_slots;
    workers->max_idle_secs = (idle_secs > 0)? idle_secs : 10;
    workers->fast_slots = H2MIN(H2MAX(min_active, 20), max_slots);
    workers->long_duration = apr_time_from_msec(50);
    workers->max_active = workers->fast_slots;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, workers->s,
                 "h2_workers: created with min=%d max=%d idle_timeout=%d sec",
                 workers->min_active, workers->max_slots,
                 (int)workers->max_idle_secs);

    APR_RING_INIT(&workers->idle, h2_slot, link);
    APR_RING_INIT(&workers->busy, h2_slot, link);
    APR_RING_INIT(&workers->free, h2_slot, link);
    APR_RING_INIT(&workers->zombie, h2_slot, link);

    APR_RING_INIT(&workers->prod_active, ap_conn_producer_t, link);
    APR_RING_INIT(&workers->prod_idle, ap_conn_producer_t, link);

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
    rv = apr_thread_cond_create(&workers->prod_done, workers->pool);
    if (rv != APR_SUCCESS) goto cleanup;

    apr_thread_mutex_lock(workers->lock);
    locked = 1;

    /* create the slots and put them on the free list */
    workers->dynamic = (workers->min_active < workers->max_slots);
    workers->slots = apr_pcalloc(workers->pool, workers->max_slots * sizeof(h2_slot));

    for (i = 0; i < workers->max_slots; ++i) {
        workers->slots[i].id = i;
        workers->slots[i].state = H2_SLOT_FREE;
        workers->slots[i].workers = workers;
        APR_RING_ELEM_INIT(&workers->slots[i], link);
        APR_RING_INSERT_TAIL(&workers->free, &workers->slots[i], h2_slot, link);
        rv = apr_thread_cond_create(&workers->slots[i].more_work, workers->pool);
        if (rv != APR_SUCCESS) goto cleanup;
    }

    /* activate the min amount of workers */
    for (i = 0; i < workers->min_active; ++i) {
        rv = activate_slot(workers);
        if (rv != APR_SUCCESS) goto cleanup;
    }

    rv = tuner_start(workers);
    if (rv != APR_SUCCESS) goto cleanup;


cleanup:
    if (locked) {
        apr_thread_mutex_unlock(workers->lock);
    }
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

apr_size_t h2_workers_get_max_workers(h2_workers *workers)
{
    return workers->max_slots;
}

void h2_workers_graceful_shutdown(h2_workers *workers)
{
    apr_thread_mutex_lock(workers->lock);
    workers->shutdown = 1;
    workers->max_idle_secs = 1;
    wake_all_idles(workers);
    apr_thread_mutex_unlock(workers->lock);
}

ap_conn_producer_t *h2_workers_register(h2_workers *workers,
                                        apr_pool_t *producer_pool,
                                        const char *name,
                                        ap_conn_producer_next *fn_next,
                                        ap_conn_producer_done *fn_done,
                                        void *baton)
{
    ap_conn_producer_t *prod;

    prod = apr_pcalloc(producer_pool, sizeof(*prod));
    APR_RING_ELEM_INIT(prod, link);
    prod->name = name;
    prod->fn_next = fn_next;
    prod->fn_done = fn_done;
    prod->baton = baton;

    apr_thread_mutex_lock(workers->lock);
    prod->state = PROD_IDLE;
    APR_RING_INSERT_TAIL(&workers->prod_idle, prod, ap_conn_producer_t, link);
    apr_thread_mutex_unlock(workers->lock);

    return prod;
}

apr_status_t h2_workers_join(h2_workers *workers, ap_conn_producer_t *prod)
{
    apr_status_t rv = APR_SUCCESS;

    apr_thread_mutex_lock(workers->lock);
    if (PROD_JOINED == prod->state) {
        AP_DEBUG_ASSERT(APR_RING_NEXT(prod, link) == prod); /* should be in no ring */
        rv = APR_EINVAL;
    }
    else {
        AP_DEBUG_ASSERT(PROD_ACTIVE == prod->state || PROD_IDLE == prod->state);
        APR_RING_REMOVE(prod, link);
        prod->state = PROD_JOINED; /* prevent further activations */
        while (prod->conns_active > 0) {
            apr_thread_cond_wait(workers->prod_done, workers->lock);
        }
        APR_RING_ELEM_INIT(prod, link); /* make it link to itself */
    }
    apr_thread_mutex_unlock(workers->lock);
    return rv;
}

apr_status_t h2_workers_activate(h2_workers *workers, ap_conn_producer_t *prod)
{
    apr_status_t rv = APR_SUCCESS;
    apr_thread_mutex_lock(workers->lock);
    if (PROD_IDLE == prod->state) {
        APR_RING_REMOVE(prod, link);
        prod->state = PROD_ACTIVE;
        APR_RING_INSERT_TAIL(&workers->prod_active, prod, ap_conn_producer_t, link);
        wake_idle_worker(workers, prod);
    }
    else if (PROD_JOINED == prod->state) {
        rv = APR_EINVAL;
    }
    apr_thread_mutex_unlock(workers->lock);
    return rv;
}
