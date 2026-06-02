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

#include "motorz.h"

/* Upper bound on the number of transaction pools kept on the recycle
 * free-list (motorz_ptrans_get/put). Beyond this, freed pools are destroyed
 * outright so a burst of connections does not pin memory forever.
 */
#define MAX_RECYCLED_POOLS 64

/* Lingering close timeouts. Not exported by the core, so mirror the values
 * connection.c uses (also mirrored this way by mpm_event). MAX_SECS_TO_LINGER
 * bounds the whole non-blocking drain; SECONDS_TO_LINGER is the shortened
 * period used when a module requested it (e.g. DoS mitigation).
 */
#ifndef MAX_SECS_TO_LINGER
#define MAX_SECS_TO_LINGER 30
#endif
#define SECONDS_TO_LINGER  2

/**
 * config globals
 */
static motorz_core_t *g_motorz_core;
static int threads_per_child = 16;
static int ap_num_kids = DEFAULT_START_DAEMON;
/* Number of poll threads per child (#2 / scaling). 0 means "auto": derive from
 * online CPUs in child_main, capped so a small box doesn't over-thread. Each
 * poller owns its own pollset/timer-ring/recycle-list and a shard of the
 * connections, lifting the single-poll-thread throughput ceiling.
 */
static int num_pollers = 0;
#define MOTORZ_MAX_POLLERS 8

/* Async HTTP/2 handoff is ENABLED (MOTORZ_ENABLE_ASYNC 1).
 *
 * When motorz advertises AP_MPMQ_IS_ASYNC=1, mod_http2 hands the master (c1)
 * connection back to the MPM between requests; motorz then re-dispatches it on
 * a fresh worker thread when its socket is readable. This previously raced
 * mod_http2's stream lifecycle under rapid HTTP/2 connection churn: motorz
 * could drive the c1 close/cleanup faster than a just-finished stream's
 * secondary (c2) worker called c2_prod_done(), so the stream was still
 * "running" at cleanup and its in-flight response got aborted -- the client
 * saw a dropped request.
 *
 * That race is now FIXED in mod_http2 (h2_session.c): a graceful client GOAWAY
 * with streams still in flight no longer transits the session straight to DONE;
 * the session keeps running until those streams' c2s have finished and flushed
 * (open_streams == 0), and only then -- from the IDLE state -- sends our GOAWAY
 * and closes. The c1 connection is therefore handed to LINGER only after every
 * c2 is done, so async handoff is lossless under churn. The full analysis,
 * reproduction recipe, and the fix are in MOTORZ.README ("HTTP/2 async
 * handoff").
 *
 * This remains a single flip point: set to 0 to fall back to the old workaround
 * (report IS_ASYNC=0 so mod_http2 keeps c1 on one worker, driving its own
 * multiplexer pollset until every c2 completes) should a regression ever
 * reappear. It gates both AP_MPMQ_IS_ASYNC and AP_MPMQ_CAN_WAITIO
 * (CONN_STATE_ASYNC_WAITIO is only meaningful when async).
 */
#define MOTORZ_ENABLE_ASYNC 1
/* Upper bound for ThreadsPerChild; matches worker/event in using
 * DEFAULT_THREAD_LIMIT rather than an arbitrary fraction of MAX_THREAD_LIMIT.
 */
static int thread_limit = DEFAULT_THREAD_LIMIT;

/* Unique connection ID: child_slot * thread_limit + per-child sequence number.
 * Mirrors the formula used by the worker and event MPMs so that c->id values
 * are globally unique across children and connections within a child.
 * conn_seq is a per-child atomic counter; thread_limit slots per child ensures
 * no overlap between children.
 */
#define ID_FROM_CHILD_THREAD(c, t) ((long)(c) * (long)thread_limit + (long)(t))
static apr_uint32_t conn_seq = 0;

/* one_process --- debugging mode variable; can be set from the command line
 * with the -X flag.  If set, this gets you the child_main loop running
 * in the process which originally started up (no detach, no make_child),
 * which is a pretty nice debugging environment.  (You'll get a SIGHUP
 * early in standalone_main; just continue through.  This is the server
 * trying to kill off any child processes which it might have lying
 * around --- Apache doesn't keep track of their pids, it just sends
 * SIGHUP to the process group, ignoring it in the root process.
 * Continue through and you'll be fine.).
 */
static int one_process = 0;

static apr_pool_t *pconf;               /* Pool for config stuff */
static apr_pool_t *pchild;              /* Pool for httpd child stuff */

static pid_t ap_my_pid; /* it seems silly to call getpid all the time */
static pid_t parent_pid;
static int my_child_num;
/* Number of connections accepted by this child so far; compared against
 * ap_max_requests_per_child. Written by the accepting poller thread
 * (motorz_io_accept) and read by the supervisor on the main thread
 * (motorz_supervise). volatile ensures neither side caches a stale value;
 * a torn read is harmless for a monotone counter used only for a soft cap.
 */
static volatile int requests_this_child;
/* Set to stop the child's main loop. volatile because it's updated from a
 * signal handler (stop_listening), from poller threads, and from the
 * supervisor. On ARM (Apple Silicon) the poller->mtx lock/unlock performed
 * on every poll-loop iteration provides acquire/release barriers, so the
 * practical visibility lag is bounded by the 500ms poll timeout at worst.
 */
static int volatile die_now = 0;
static motorz_child_bucket *all_buckets, /* All listeners buckets */
                            *my_bucket;   /* Current child bucket */

static void clean_child_exit(int code) __attribute__ ((noreturn));


static apr_status_t motorz_io_process(motorz_conn_t *scon);
static void motorz_pollset_del(motorz_poller_t *poller, motorz_conn_t *scon);
static void motorz_conn_claim(motorz_poller_t *poller, motorz_conn_t *scon);
static void motorz_conn_done(motorz_conn_t *scon);
static void motorz_start_lingering_close(motorz_conn_t *scon);
static apr_status_t motorz_lingering_close(motorz_conn_t *scon);
static void motorz_update_listeners(motorz_poller_t *poller);

static motorz_core_t *motorz_core_get(void)
{
    return g_motorz_core;
}

/* Obtain a transaction pool for a new connection, reusing one from the
 * recycle free-list if available, otherwise creating a fresh one with its
 * own allocator (so per-connection memory is released as a unit and the
 * allocator's free blocks can be reused).
 *
 * SINGLE-CONSUMER: the lock-free CAS pop below is only safe with one popper,
 * because it dereferences first->next without atomicity (see mpm_fdqueue.c's
 * ap_queue_info_pop_pool and its PR caveat). This MUST be called only from the
 * owning poller's thread (its sole caller is motorz_io_accept, which runs on
 * that poller). Each poller has its own free-list, so "one popper" holds.
 * Concurrent lock-free pushes (motorz_ptrans_put, from any worker) are fine.
 */
static apr_pool_t *motorz_ptrans_get(motorz_poller_t *poller)
{
    apr_pool_t *ptrans;

    for (;;) {
        motorz_recycled_pool *first = poller->recycled_pools;
        if (first == NULL) {
            break;
        }
        if (apr_atomic_casptr((void *)&poller->recycled_pools,
                              first->next, first) == first) {
            apr_atomic_dec32(&poller->num_recycled);
            /* The node lived inside the pool it describes; the pool is now
             * ours to hand out (it will be cleared again on next reuse).
             */
            return first->pool;
        }
        /* CAS lost a race with another pop... but there is only one popper, so
         * this only happens transiently vs. a push changing the head; retry.
         */
    }

    {
        apr_allocator_t *allocator;
        apr_allocator_create(&allocator);
        apr_allocator_max_free_set(allocator, ap_max_mem_free);
        apr_pool_create_ex(&ptrans, pconf, NULL, allocator);
        apr_allocator_owner_set(allocator, ptrans);
        apr_pool_tag(ptrans, "transaction");
    }
    return ptrans;
}

/* Return a finished connection's transaction pool to the recycle free-list,
 * or destroy it if the list is already at MAX_RECYCLED_POOLS. Clearing the
 * pool runs all its cleanups (closing the socket, de-registering timers) and
 * resets it for reuse.
 *
 * MULTI-PRODUCER: the lock-free CAS push is safe from any thread (workers and
 * the poll thread), concurrently with each other and with a single popper.
 */
static void motorz_ptrans_put(motorz_poller_t *poller, apr_pool_t *ptrans)
{
    motorz_recycled_pool *node;

    /* Bound the free-list. apr_atomic_read32 + inc is not a strict CAS, so the
     * count may momentarily overshoot MAX_RECYCLED_POOLS under concurrency;
     * that is harmless (it just caps roughly).
     */
    if (apr_atomic_read32(&poller->num_recycled) >= MAX_RECYCLED_POOLS) {
        apr_pool_destroy(ptrans);
        return;
    }
    apr_atomic_inc32(&poller->num_recycled);

    /* Clear (don't destroy) to keep the allocator and its free blocks; this
     * also runs the pool's cleanups (closing the socket, de-registering any
     * timer). Then carve the list node out of the now-empty pool.
     */
    apr_pool_clear(ptrans);
    apr_pool_tag(ptrans, "transaction");
    node = apr_palloc(ptrans, sizeof(*node));
    node->pool = ptrans;

    for (;;) {
        /* Save the current head in a local before the CAS: node->next must not
         * be re-read after a successful CAS, as a concurrent pusher may have
         * already changed it (see mpm_fdqueue.c push_pool, PR 44402).
         */
        motorz_recycled_pool *next = poller->recycled_pools;
        node->next = next;
        if (apr_atomic_casptr((void *)&poller->recycled_pools, node, next) == next) {
            break;
        }
    }
}

static int timer_comp(void *a, void *b)
{
    motorz_timer_t *ta = (motorz_timer_t *) a;
    motorz_timer_t *tb = (motorz_timer_t *) b;
    apr_time_t t1 = ta->expires;
    apr_time_t t2 = tb->expires;
    AP_DEBUG_ASSERT(t1);
    AP_DEBUG_ASSERT(t2);
    /* Identity match: required so that apr_skiplist_remove() (which relies on
     * the compare function returning 0) can locate the exact timer node. We
     * must never return 0 for two *distinct* timers, otherwise
     * apr_skiplist_insert() would drop duplicates (timers created within the
     * same microsecond) and remove() could delete the wrong connection's
     * timer. Equal expiry on distinct timers therefore falls back to a stable
     * total order on the timer address.
     */
    if (ta == tb) {
        return 0;
    }
    if (t1 < t2) {
        return -1;
    }
    if (t1 > t2) {
        return 1;
    }
    return (ta < tb) ? -1 : 1;
}

static apr_status_t motorz_conn_pool_cleanup(void *baton)
{
    motorz_conn_t *scon = (motorz_conn_t *)baton;

    if (scon->timer.expires) {
        motorz_poller_t *poller = scon->poller;

        apr_thread_mutex_lock(poller->mtx);
        apr_skiplist_remove(poller->timeout_ring, &scon->timer, NULL);
        apr_thread_mutex_unlock(poller->mtx);
    }

    return APR_SUCCESS;
}

static APR_INLINE apr_interval_time_t
motorz_get_timeout(motorz_conn_t *scon)
{
    if (scon->c->base_server) {
        return scon->c->base_server->timeout;
    }
    else {
        return ap_server_conf->timeout;
    }
}

static APR_INLINE apr_interval_time_t
motorz_get_keep_alive_timeout(motorz_conn_t *scon)
{
    if (scon->c->base_server) {
        return scon->c->base_server->keep_alive_timeout;
    }
    else {
        return ap_server_conf->keep_alive_timeout;
    }
}

static void motorz_io_timeout_cb(motorz_core_t *mz, void *baton)
{

    motorz_conn_t *scon = (motorz_conn_t *) baton;
    conn_rec *c = scon->c;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02842)
                 "io timeout hit scon: %pp, c: %pp", scon, c);

    /* The keep-alive/write timeout expired. Begin a non-blocking lingering
     * close rather than blocking this worker; scon is handed to the poll loop
     * or torn down inside, and is invalid afterwards. The timer has already
     * been popped from the ring by the caller.
     */
    motorz_start_lingering_close(scon);
}

static void *motorz_io_setup_conn(apr_thread_t *thread, void *baton)
{
    apr_status_t status;
    ap_sb_handle_t *sbh;
    long conn_id;
    motorz_sb_t *sb;
    motorz_conn_t *scon = (motorz_conn_t *) baton;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03316)
                         "motorz_io_setup_conn(): entered");

    /* Derive a unique connection ID matching worker/event's formula.
     * apr_atomic_inc32 returns the value BEFORE increment, so add 1 to get
     * the sequence number for this connection (sequence starts at 1).
     * my_child_num is set once at child startup and read-only from here.
     */
    conn_id = ID_FROM_CHILD_THREAD(my_child_num,
                                   (apr_uint32_t)apr_atomic_inc32(&conn_seq) + 1);
    ap_create_sb_handle(&sbh, scon->pool, my_child_num, 0);
    scon->sbh = sbh;
    scon->ba = apr_bucket_alloc_create(scon->pool);

    scon->c = ap_run_create_connection(scon->pool, ap_server_conf, scon->sock,
                                       conn_id, sbh, scon->ba);
    if (scon->c == NULL) {
        /* create_connection failed (e.g. a module declined or hit a resource
         * limit). There is no conn_rec to process or linger-close; just
         * release the transaction pool, which closes the accepted socket via
         * its pool cleanup.
         */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(10547)
                     "motorz_io_setup_conn: ap_run_create_connection failed");
        motorz_conn_done(scon);
        return NULL;
    }

    scon->c->cs = &scon->cs;
    sb = apr_pcalloc(scon->pool, sizeof(motorz_sb_t));

    scon->c->current_thread = thread;

    scon->pfd.p = scon->pool;
    scon->pfd.desc_type = APR_POLL_SOCKET;
    scon->pfd.desc.s = scon->sock;
    scon->pfd.reqevents = APR_POLLIN;

    sb->type = PT_CSD;
    sb->baton = scon;
    scon->pfd.client_data = sb;

    ap_update_vhost_given_ip(scon->c);

    status = ap_pre_connection(scon->c, scon->sock);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03317)
                         "motorz_io_setup_conn(): did pre-conn");
    if (status != OK && status != DONE) {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(02843)
                     "motorz_io_setup_conn: connection aborted");
    }

    /* pfd is initialized here to ensure reqevents == 0, so the defensive
     * pollset_remove guard in motorz_io_process is a no-op on this first call.
     */
    scon->pfd.reqevents = 0;
    scon->cs.state = CONN_STATE_PROCESSING;
    scon->cs.sense = CONN_SENSE_DEFAULT;

    status = motorz_io_process(scon);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, status, ap_server_conf, APLOGNO(02844)
                 "motorz_io_setup_conn: motorz_io_process status: %d", (int)status);
    return NULL;
}

static apr_status_t motorz_io_user(motorz_poller_t *poller, motorz_sb_t *sb)
{
    /* PT_USER poll events are not implemented yet. Nothing currently
     * registers a PT_USER descriptor in the pollset, so reaching here means
     * an unexpected event; log it rather than silently dropping it.
     */
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(10548)
                 "motorz_io_user: PT_USER poll events are not implemented");
    return APR_SUCCESS;
}

static apr_status_t motorz_io_accept(motorz_poller_t *poller, motorz_sb_t *sb)
{
    motorz_core_t *mz = poller->mz;
    apr_status_t rv;
    apr_pool_t *ptrans;
    apr_socket_t *socket = NULL;
    ap_listen_rec *lr = (ap_listen_rec *) sb->baton;
    motorz_conn_t *scon;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03318)
                 "motorz_io_accept(): entered");

    /* Drain the kernel accept queue in one poll wakeup instead of returning
     * to apr_pollset_poll() for each connection. Without this, N queued
     * connections require N round-trips through the poll loop, costing O(N)
     * wakeups under burst. The loop stops when accept() returns EAGAIN (queue
     * empty), on a fatal error, when admission control disables the listener,
     * or when the child is shutting down.
     *
     * ap_unixd_accept() outcome buckets:
     *   - APR_SUCCESS + socket set: a connection was accepted;
     *   - APR_EGENERAL: fatal/resource condition (E[MN]FILE, ENETDOWN, etc.) --
     *     stop gracefully rather than spin;
     *   - any other non-success (EAGAIN, EINTR, ECONNABORTED, ...): transient,
     *     log and stop draining.
     * socket == NULL on every non-SUCCESS path.
     */
    do {
        ptrans = motorz_ptrans_get(poller);
        socket = NULL;
        rv = lr->accept_func((void *)&socket, lr, ptrans);

        if (rv == APR_SUCCESS && socket != NULL) {
            static apr_uint32_t rr;
            motorz_poller_t *target;

            scon = apr_pcalloc(ptrans, sizeof(motorz_conn_t));
            scon->pool = ptrans;
            scon->sock = socket;
            scon->mz = mz;

            /* Shard I/O across pollers round-robin. The accepting poller is
             * always poller 0, so this counter needs no atomics.
             */
            target = mz->pollers[rr % (apr_uint32_t)mz->num_pollers];
            rr++;
            scon->poller = target;

            /* Recycling is NOT sharded: the ptrans came from THIS poller's
             * free-list (its single-consumer pop home). Return it here.
             */
            scon->pool_poller = poller;

            requests_this_child++;

            apr_pool_cleanup_register(scon->pool, scon, motorz_conn_pool_cleanup,
                                      apr_pool_cleanup_null);

            rv = apr_thread_pool_push(mz->workers,
                                      motorz_io_setup_conn,
                                      scon,
                                      APR_THREAD_TASK_PRIORITY_HIGHEST, NULL);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                             APLOGNO(03319)
                             "motorz_io_accept: could not queue connection to "
                             "worker pool");
                motorz_ptrans_put(poller, ptrans);
            }

            /* Re-check admission after each accept: if the worker pool has
             * become saturated, motorz_update_listeners() will remove the
             * listener from the pollset and set listeners_disabled, which
             * terminates the drain loop below.
             */
            motorz_update_listeners(poller);
        }
        else {
            /* Nothing accepted (EAGAIN/EINTR/error): recycle the pool. */
            motorz_ptrans_put(poller, ptrans);

            if (rv == APR_EGENERAL) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                             APLOGNO(02845)
                             "motorz_io_accept: accept failed, shutting down "
                             "child gracefully");
                mz->mpm->mpm_state = AP_MPMQ_STOPPING;
                die_now = 1;
            }
            else if (ap_accept_error_is_nonfatal(rv)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf,
                             APLOGNO(10549)
                             "accept() on client socket failed");
            }

            break;
        }
    } while (!poller->listeners_disabled && !die_now);

    return APR_SUCCESS;
}

static void *motorz_timer_invoke(apr_thread_t *thread, void *baton)
{
    motorz_timer_t *ep = (motorz_timer_t *)baton;
    motorz_conn_t *scon = (motorz_conn_t *)ep->baton;

    scon->c->current_thread = thread;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03320)
                         "motorz_timer_invoke(): entered");

    ep->cb(ep->mz, ep->baton);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03321)
                         "motorz_timer_invoke(): exited");

    return NULL;
}

static apr_status_t motorz_timer_event_process(motorz_poller_t *poller, motorz_timer_t *te)
{
    motorz_conn_t *scon = (motorz_conn_t *)te->baton;
    scon->timer.expires = 0;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03322)
                         "motorz_timer_event_process(): entered");

    /* Claim the connection on the poll thread before dispatching the timeout
     * (fix #5). The timer has already been popped from the ring by the caller
     * (so there is nothing to remove there -- and we must not take poller->mtx
     * here as the caller holds it), but the connection's descriptor may still
     * be armed in the pollset; disarm it so a concurrent/subsequent poll
     * cannot dispatch the same scon while the timeout worker is closing it.
     * apr_pollset_remove() takes only the (leaf) pollset lock, so calling it
     * under poller->mtx introduces no lock-ordering inversion.
     */
    motorz_pollset_del(poller, scon);

    return apr_thread_pool_push(poller->mz->workers,
                                motorz_timer_invoke,
                                te, APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
}

static void *motorz_io_invoke(apr_thread_t *thread, void *baton)
{
    motorz_sb_t *sb = (motorz_sb_t *) baton;
    motorz_conn_t *scon = (motorz_conn_t *) sb->baton;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03323)
                         "motorz_io_invoke(): entered");
    scon->c->current_thread = thread;

    rv = motorz_io_process(scon);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, rv, ap_server_conf, APLOGNO(02846)
                     "motorz_io_invoke: motorz_io_process failed (?)");
    }
    return NULL;
}

static apr_status_t motorz_io_event_process(motorz_poller_t *poller, motorz_sb_t *sb)
{
    motorz_conn_t *scon = (motorz_conn_t *) sb->baton;

    /* Take ownership of this connection on the poll thread before handing it
     * to a worker: disarm its pollset entry and cancel any pending timeout
     * (fix #5). This guarantees the poll thread cannot dispatch the same scon
     * again -- neither re-reported by the pollset nor via timer expiry --
     * until the worker re-arms it at the end of motorz_io_process(). Without
     * this, two workers could race on one scon and, now that the transaction
     * pool is freed on teardown, that race is a use-after-free.
     *
     * The identity-correct timer_comp (fix #3) is what makes the targeted
     * skiplist removal reliable.
     */
    motorz_conn_claim(poller, scon);

    return apr_thread_pool_push(poller->mz->workers,
                                motorz_io_invoke,
                                sb, APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
}

static apr_status_t motorz_io_callback(void *baton, const apr_pollfd_t *pfd)
{
    apr_status_t status = APR_SUCCESS;
    motorz_poller_t *poller = (motorz_poller_t *) baton;
    motorz_sb_t *sb = pfd->client_data;


    if (sb->type == PT_ACCEPT) {
        status = motorz_io_accept(poller, sb);
    }
    else if (sb->type == PT_CSD) {
        status = motorz_io_event_process(poller, sb);
    }
    else if (sb->type == PT_USER) {
        status = motorz_io_user(poller, sb);
    }
    return status;
}

/* Insert/refresh scon's timer in the ring. CALLER MUST HOLD mz->mtx.
 *
 * Everything that touches the sort key (expires) and the ring must happen
 * under mz->mtx. In particular:
 *
 *  - If this connection's timer is still linked in the ring from an earlier
 *    registration (expires != 0 is, under the lock, exactly the "in ring"
 *    predicate), remove it first -- using its *current* expiry as the key,
 *    before we overwrite it.
 *  - Only then mutate expires and re-insert.
 *
 * Re-inserting the same node, or mutating a linked node's sort key in place,
 * corrupts the skiplist and sends apr_skiplist_insert()'s insert_compare()
 * into an infinite loop *while holding mz->mtx*, which deadlocks the entire
 * child. (Found by a load test with StartServers 1 and MaxRequestsPerChild
 * churn.)
 */
static void motorz_register_timeout_locked(motorz_conn_t *scon,
                                           motorz_timer_cb cb,
                                           apr_interval_time_t relative_time)
{
    apr_time_t t = apr_time_now() + relative_time;
    motorz_timer_t *elem = &scon->timer;
    motorz_poller_t *poller = scon->poller;

    if (elem->expires) {
        apr_skiplist_remove(poller->timeout_ring, elem, NULL);
    }

    elem->expires = t;
    elem->cb = cb;
    elem->baton = scon;
    elem->pool = scon->pool;
    elem->mz = poller->mz;
    elem->poller = poller;

#ifdef AP_DEBUG
    ap_assert(apr_skiplist_insert(poller->timeout_ring, elem));
#else
    apr_skiplist_insert(poller->timeout_ring, elem);
#endif
}

/* Hand a connection back to the poll thread: arm its pollset entry for
 * 'reqevents' AND register its timeout, atomically under mz->mtx. This is the
 * ONLY safe way for a worker to release a connection it still holds a pointer
 * to: once either the timer or the pollset entry is armed, the poll thread may
 * fire the timeout (or a readable event) and tear the connection down --
 * freeing scon. Doing both under one lock, and touching scon nowhere after
 * this returns, closes the use-after-free window. MUST be the worker's last
 * action on scon; returns the pollset_add status (scon may already be freed
 * on a concurrent timeout by the time we look at the return, so the caller
 * must not deref scon regardless of it).
 */
static apr_status_t motorz_conn_register(motorz_conn_t *scon,
                                         apr_int16_t reqevents,
                                         motorz_timer_cb cb,
                                         apr_interval_time_t timeout)
{
    motorz_poller_t *poller = scon->poller;
    apr_status_t rv;

    apr_thread_mutex_lock(poller->mtx);
    scon->pfd.reqevents = reqevents;
    scon->cs.sense = CONN_SENSE_DEFAULT;
    motorz_register_timeout_locked(scon, cb, timeout);
    rv = apr_pollset_add(poller->pollset, &scon->pfd);
    if (rv != APR_SUCCESS) {
        /* Roll back the timer so the half-armed connection isn't left
         * reachable via the ring with no pollset entry; the caller will tear
         * it down.
         */
        if (scon->pfd.reqevents != 0) {
            scon->pfd.reqevents = 0;
        }
        apr_skiplist_remove(poller->timeout_ring, &scon->timer, NULL);
        scon->timer.expires = 0;
    }
    apr_thread_mutex_unlock(poller->mtx);
    return rv;
}

/* Remove scon's descriptor from the pollset if it is currently armed, and
 * mark it disarmed. Does NOT touch the timer ring. Safe to call without
 * holding mz->mtx: the pollset is created APR_POLLSET_THREADSAFE, and APR's
 * pollset lock is never held while acquiring mz->mtx (or vice versa), so no
 * lock-ordering inversion is possible.
 *
 * Some pollset backends (kqueue, epoll) automatically drop a descriptor when
 * its socket is closed, so APR_NOTFOUND is an acceptable, non-error result.
 */
static void motorz_pollset_del(motorz_poller_t *poller, motorz_conn_t *scon)
{
    if (scon->pfd.reqevents != 0) {
        apr_status_t rv = apr_pollset_remove(poller->pollset, &scon->pfd);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rv)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, ap_server_conf,
                         "motorz_pollset_del: apr_pollset_remove failure");
        }
        scon->pfd.reqevents = 0;
    }
}

/* Claim a connection on behalf of a worker, on the poll/main thread, before
 * dispatching it. This is the heart of the per-connection ownership model
 * (fix #5): it makes the connection invisible to the poll thread for as long
 * as a worker owns it, so the same scon can never be dispatched twice (once
 * for an I/O event and again for a timeout, or re-reported by a level-
 * triggered pollset before the worker has run).
 *
 * It removes scon's descriptor from the pollset and cancels any pending
 * timeout. The worker re-arms the connection (pollset_add + register_timeout)
 * only at the very end of motorz_io_process(), at which point ownership
 * returns to the poll thread. MUST be called on the poll thread only.
 */
static void motorz_conn_claim(motorz_poller_t *poller, motorz_conn_t *scon)
{
    motorz_pollset_del(poller, scon);

    if (scon->timer.expires) {
        apr_thread_mutex_lock(poller->mtx);
        apr_skiplist_remove(poller->timeout_ring, &scon->timer, NULL);
        scon->timer.expires = 0;
        apr_thread_mutex_unlock(poller->mtx);
    }
}

/* Terminal teardown for a connection: remove it from the pollset (if still
 * registered) and recycle its transaction pool. Clearing the pool (inside
 * motorz_ptrans_put) releases the conn_rec, bucket allocator and scoreboard
 * handle allocated within it, and fires motorz_conn_pool_cleanup(), which
 * de-registers any pending timer from the ring under mz->mtx.
 *
 * This MUST be called exactly once per connection, on every path that ends
 * it (lingering close, abort, or fired timeout). It runs on a worker-pool
 * thread; removing from the pollset concurrently with the polling thread is
 * safe because the pollset is created APR_POLLSET_THREADSAFE. By the time a
 * worker reaches a terminal state the connection has already been claimed
 * (disarmed) by the poll thread, so motorz_pollset_del() is normally a no-op
 * here -- it remains as a defensive backstop.
 */
static void motorz_conn_done(motorz_conn_t *scon)
{
    motorz_poller_t *poller = scon->poller;
    motorz_poller_t *pool_poller = scon->pool_poller;
    apr_pool_t *ptrans = scon->pool;

    ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                 "motorz_conn_done(): scon: %pp", scon);

    /* Disarm on the I/O poller (its pollset), then recycle to the accepting
     * poller's free-list (its single-consumer pop home -- not the I/O poller).
     */
    motorz_pollset_del(poller, scon);

    /* scon lives in ptrans, so it (and scon->pool) are invalid afterwards. */
    motorz_ptrans_put(pool_poller, ptrans);
}

/* Timer callback for a lingering close that ran out of time: force the
 * connection closed. Mirrors motorz_io_timeout_cb but for the linger phase.
 */
static void motorz_linger_timeout_cb(motorz_core_t *mz, void *baton)
{
    motorz_conn_t *scon = (motorz_conn_t *) baton;

    ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                 "motorz_linger_timeout_cb(): scon: %pp", scon);

    /* The timer has already been popped from the ring; tear down. */
    motorz_conn_done(scon);
}

/* Drain and discard any data the peer is still sending, without blocking.
 * Called (on a worker thread) when a lingering socket is readable or its
 * linger timer fires. Returns when the peer has closed/erred (-> teardown)
 * or there is nothing more to read right now (-> re-arm in the pollset).
 */
static apr_status_t motorz_lingering_close(motorz_conn_t *scon)
{
    apr_socket_t *csd = scon->sock;
    char dummybuf[512];
    apr_size_t nbytes;
    apr_status_t rv;

    do {
        nbytes = sizeof(dummybuf);
        rv = apr_socket_recv(csd, dummybuf, &nbytes);
    } while (rv == APR_SUCCESS);

    if (!APR_STATUS_IS_EAGAIN(rv)) {
        /* Peer closed, reset, or hard error: we are done. */
        motorz_conn_done(scon);
        return APR_SUCCESS;
    }

    /* Nothing left to read for now; wait for more readability, bounded by the
     * linger timeout. A readable PT_CSD dispatch goes through
     * motorz_conn_claim(), which cancels this connection's timer, so we must
     * (re)register the linger timeout here alongside (re)arming the pollset.
     * This means a peer that keeps dribbling data resets the deadline each
     * time -- the same bounded imprecision mpm_event accepts for its linger
     * queues, and exactly the slow-drain case the timeout exists to cap.
     * Honour a module's request for a shortened linger period.
     *
     * Arm pollset + timer atomically (motorz_conn_register); after it returns
     * scon may already have been freed by a concurrent timeout, so we must not
     * touch it again -- including on the error path, where the rollback inside
     * motorz_conn_register has disarmed it and we just close.
     */
    {
        apr_interval_time_t linger =
            apr_table_get(scon->c->notes, "short-lingering-close")
                ? apr_time_from_sec(SECONDS_TO_LINGER)
                : apr_time_from_sec(MAX_SECS_TO_LINGER);
        rv = motorz_conn_register(scon,
                                  APR_POLLIN | APR_POLLHUP | APR_POLLERR,
                                  motorz_linger_timeout_cb, linger);
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, ap_server_conf,
                     "motorz_lingering_close: apr_pollset_add failed; closing");
        motorz_conn_done(scon);
    }
    return APR_SUCCESS;
}

/* Begin a non-blocking lingering close (fix #3/A3). Runs on a worker thread,
 * but unlike the old inline ap_lingering_close() it never blocks the worker
 * for up to MAX_SECS_TO_LINGER: it shuts the write side down, then arms a
 * linger timeout and hands the socket back to the poll loop, which drives the
 * drain via motorz_lingering_close() as data arrives.
 *
 * Pre-condition: scon has already been claimed (not in the pollset, no timer).
 */
static void motorz_start_lingering_close(motorz_conn_t *scon)
{
    conn_rec *c = scon->c;
    apr_socket_t *csd = scon->sock;

    scon->cs.state = CONN_STATE_LINGER;

    /* ap_start_lingering_close() flushes and shuts down the write side. A
     * true return means there is nothing to linger over (aborted or no
     * half-close needed), so close immediately.
     */
    if (ap_start_lingering_close(c)) {
        motorz_conn_done(scon);
        return;
    }

    scon->linger_started = 1;

    /* All draining from here is non-blocking. */
    apr_socket_timeout_set(csd, 0);
    apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 0);

    /* First drain attempt. If the peer still has data to send,
     * motorz_lingering_close() arms both the pollset and the linger timeout;
     * otherwise it tears the connection down here. We deliberately do not
     * pre-register a timer (the drain owns that), so scon->timer is inserted
     * into the ring at most once at a time.
     */
    motorz_lingering_close(scon);
}

/* Park a connection that a process_connection hook left in
 * CONN_STATE_SUSPENDED (A4). Ownership passes to the module, which interacts
 * with the MPM only through the suspend/resume_connection hooks until it calls
 * ap_mpm_resume_suspended() -> motorz_resume_suspended(). The connection is
 * intentionally left out of the pollset and timer ring (it has been claimed),
 * and its transaction pool is NOT recycled, so nothing here tears it down --
 * which is what previously leaked. Runs on a worker thread.
 */
static void motorz_suspend_connection(motorz_conn_t *scon)
{
    conn_rec *c = scon->c;

    ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                 "motorz_suspend_connection(): scon: %pp", scon);

    c->suspended_baton = scon;
    scon->suspended = 1;
    ap_run_suspend_connection(c, scon->r);
    /* sbh is owned by the (now parked) connection; drop our reference like
     * mpm_event's notify_suspend() does.
     */
    c->sbh = NULL;
}

static apr_status_t motorz_io_process(motorz_conn_t *scon)
{
    apr_status_t rv;
    conn_rec *c;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf, APLOGNO(03325)
                         "motorz_io_process(): entered");

    /* A connection already in non-blocking lingering close (its socket became
     * readable again, or it was re-dispatched) just continues draining. It
     * has been claimed, so its pollset entry/timer were cleared; the drain
     * re-arms them or tears down.
     */
    if (scon->linger_started) {
        return motorz_lingering_close(scon);
    }

    if (scon->c->clogging_input_filters && !scon->c->aborted) {
        /* Since we have an input filter which 'clogs' the input stream,
         * like mod_ssl used to, lets just do the normal read from input
         * filters, like the Worker MPM does. Filters that need to write
         * where they would otherwise read, or read where they would
         * otherwise write, should set the sense appropriately.
         *
         * This path bypasses the normal motorz_conn_claim() that precedes
         * every other call to motorz_io_process(). Do a full claim now:
         * disarm the pollset entry AND cancel any pending timer under the
         * poller mutex. Without the timer cancel, a concurrent timer expiry
         * can dispatch a timeout worker on the same scon while this worker
         * is inside ap_run_process_connection() -- a use-after-free race.
         */
        motorz_conn_claim(scon->poller, scon);
        ap_run_process_connection(scon->c);
        /* The process_connection hooks set the next connection state on
         * return; honor it and let the dispatch below act on it, mirroring
         * the event MPM (see event.c:process_socket()). Async modules reach
         * this clogging path too: mod_http2's secondary (c2) connections set
         * clogging_input_filters unconditionally, and come back wanting either
         * to wait for I/O (CONN_STATE_ASYNC_WAITIO), flush
         * (CONN_STATE_WRITE_COMPLETION), or suspend -- all of which must be
         * preserved rather than force-closed.
         *
         * A hook-returned CONN_STATE_KEEPALIVE is mapped to
         * CONN_STATE_WRITE_COMPLETION (as event does) so it flushes any
         * pending output and then waits for the next request: passing bare
         * KEEPALIVE through to the dispatch below would hit the
         * KEEPALIVE -> PROCESSING entry transition and synchronously re-run
         * ap_run_process_connection() instead of returning to the poller.
         *
         * Anything left unfinished -- still CONN_STATE_PROCESSING because a
         * hook returned DECLINED or OK without setting a state, as a non-async
         * module would -- gets a lingering close, like the worker MPM. That
         * also keeps us out of the CONN_STATE_PROCESSING branch below.
         */
        if (scon->cs.state == CONN_STATE_KEEPALIVE) {
            scon->cs.state = CONN_STATE_WRITE_COMPLETION;
        }
        else if (scon->cs.state != CONN_STATE_ASYNC_WAITIO
                 && scon->cs.state != CONN_STATE_WRITE_COMPLETION
                 && scon->cs.state != CONN_STATE_SUSPENDED) {
            scon->cs.state = CONN_STATE_LINGER;
        }
    }

    c = scon->c;

    if (!c->aborted) {

        /* On the normal dispatch path (from motorz_io_event_process or
         * motorz_io_setup_conn), the connection has already been claimed --
         * pollset entry removed and reqevents cleared -- before reaching here.
         * No redundant apr_pollset_remove() is needed or performed.
         */

        if (scon->cs.state == CONN_STATE_KEEPALIVE) {
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(03327)
                         "motorz_io_process(): keepalive -> processing");
            scon->cs.state = CONN_STATE_PROCESSING;
        }
        else if (scon->cs.state == CONN_STATE_ASYNC_WAITIO) {
            /* The socket this connection was waiting on (CONN_STATE_ASYNC_WAITIO,
             * armed below) became readable/writable, so we were re-dispatched:
             * re-enter the process_connection hooks, mirroring how event's loop
             * maps ASYNC_WAITIO back to PROCESSING. (A Timeout expiry does not
             * arrive here -- motorz_io_timeout_cb lingers/closes directly.)
             */
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(10559)
                         "motorz_io_process(): async waitio -> processing");
            scon->cs.state = CONN_STATE_PROCESSING;
        }

read_request:
        if (scon->cs.state == CONN_STATE_PROCESSING) {
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(03328) "motorz_io_process(): processing");
            if (!c->aborted) {
                ap_update_child_status(scon->sbh, SERVER_BUSY_READ, NULL);
                ap_run_process_connection(c);
                /* state will be updated upon return
                 * fall thru to either wait for readability/timeout or
                 * do lingering close
                 */
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                             APLOGNO(03330)
                             "motorz_io_process(): aborted -> linger");
                scon->cs.state = CONN_STATE_LINGER;
            }
        }

        if (scon->cs.state == CONN_STATE_SUSPENDED) {
            /* A module has taken the connection asynchronous (A4). Park it;
             * ownership returns only via motorz_resume_suspended(). Do not
             * re-arm the pollset/timer or tear it down.
             */
            ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                         APLOGNO(10550)
                         "motorz_io_process(): suspended");
            motorz_suspend_connection(scon);
            return APR_SUCCESS;
        }

        if (scon->cs.state == CONN_STATE_ASYNC_WAITIO) {
            /* A process_connection hook wants the MPM to wait for the
             * connection to become readable or writable (per c->cs->sense,
             * defaulting to read) within the configured Timeout, and then
             * re-enter the hooks. This is the same wait the WANT_READ
             * workaround does through WRITE_COMPLETION, but explicit and
             * without first checking ap_run_output_pending() -- the hook has
             * told us it is done writing and is now waiting on I/O. Arm the
             * pollset + timer atomically and do not touch scon afterwards (a
             * concurrent timeout may free it). On failure scon is already
             * disarmed by the rollback; close it.
             */
            apr_int16_t reqevents;

            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(10557)
                         "motorz_io_process(): async waitio");

            ap_update_child_status(scon->sbh, SERVER_BUSY_READ, NULL);

            reqevents =
                (scon->cs.sense == CONN_SENSE_WANT_WRITE ? APR_POLLOUT
                                                         : APR_POLLIN)
                | APR_POLLHUP | APR_POLLERR;
            rv = motorz_conn_register(scon, reqevents,
                                      motorz_io_timeout_cb,
                                      motorz_get_timeout(scon));
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                             ap_server_conf, APLOGNO(10558)
                             "apr_pollset_add: failed in async waitio");
                motorz_conn_done(scon);
            }
            return APR_SUCCESS;
        }

        if (scon->cs.state == CONN_STATE_WRITE_COMPLETION) {
            int pending;

            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(03331)
                         "motorz_io_process(): write completion");

            ap_update_child_status(scon->sbh, SERVER_BUSY_WRITE, NULL);

            pending = ap_run_output_pending(c);
            if (pending == OK) {
                /* Still in WRITE_COMPLETION_STATE: set a write timeout and let
                 * the poll thread wait for writeability. Arm pollset + timer
                 * atomically and do not touch scon afterwards (it may be freed
                 * by a concurrent timeout). On failure scon is already
                 * disarmed by the rollback; close it.
                 */
                apr_int16_t reqevents =
                    (scon->cs.sense == CONN_SENSE_WANT_READ ? APR_POLLIN
                                                            : APR_POLLOUT)
                    | APR_POLLHUP | APR_POLLERR;
                rv = motorz_conn_register(scon, reqevents,
                                          motorz_io_timeout_cb,
                                          motorz_get_timeout(scon));
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                                 ap_server_conf, APLOGNO(02849)
                                 "apr_pollset_add: failed in write completion");
                    motorz_conn_done(scon);
                }
                return APR_SUCCESS;
            }
            if (pending != DECLINED
                    || c->keepalive != AP_CONN_KEEPALIVE
                    || c->aborted) {
                scon->cs.state = CONN_STATE_LINGER;
            }
            else if (ap_run_input_pending(c) == OK) {
                scon->cs.state = CONN_STATE_PROCESSING;
                goto read_request;
            }
            else {
                scon->cs.state = CONN_STATE_KEEPALIVE;
            }
        }

        if (scon->cs.state == CONN_STATE_LINGER) {
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(03332) "motorz_io_process(): linger");
            /* Begin a non-blocking lingering close instead of blocking this
             * worker for up to MAX_SECS_TO_LINGER (A3). scon may be torn down
             * or handed back to the poll loop inside; invalid afterwards.
             */
            motorz_start_lingering_close(scon);
            return APR_SUCCESS;
        }

        if (scon->cs.state == CONN_STATE_KEEPALIVE) {
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         APLOGNO(03333) "motorz_io_process(): keepalive");
            /* Arm pollset + keep-alive timer atomically; do not touch scon
             * afterwards (a concurrent timeout may free it). On failure scon
             * is already disarmed by the rollback; close it.
             */
            rv = motorz_conn_register(scon,
                                      APR_POLLIN | APR_POLLHUP | APR_POLLERR,
                                      motorz_io_timeout_cb,
                                      motorz_get_keep_alive_timeout(scon));
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                             APLOGNO(02850)
                             "process_socket: apr_pollset_add failure in "
                             "read request line");
                motorz_conn_done(scon);
                return APR_SUCCESS;
            }
        }
    } else {
        /* Aborted: begin (non-blocking) lingering close. */
        motorz_start_lingering_close(scon);
        return APR_SUCCESS;
    }
    return APR_SUCCESS;
}

/* mpm_resume_suspended hook (A4): a module that previously suspended this
 * connection is handing it back. Recover scon from the suspended_baton, run
 * the resume_connection hooks, and re-inject it into the worker pool to
 * continue in write-completion (flush, then keep-alive or close). May be
 * called from a module's own thread, so we hand off rather than process
 * inline.
 */
static apr_status_t motorz_resume_suspended(conn_rec *c)
{
    motorz_conn_t *scon = (motorz_conn_t *) c->suspended_baton;
    motorz_core_t *mz;

    if (scon == NULL || !scon->suspended) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, APLOGNO(10551)
                      "motorz_resume_suspended: connection not suspended");
        return APR_EGENERAL;
    }
    mz = scon->mz;

    c->suspended_baton = NULL;
    scon->suspended = 0;

    /* Restore sbh before running resume hooks: motorz_suspend_connection
     * NULLed c->sbh (matching event's notify_suspend), but any module or
     * filter calling ap_update_child_status(c->sbh, ...) after resume would
     * dereference NULL without this. scon->sbh is valid for the connection's
     * lifetime (it lives in scon->pool which is not recycled during suspend).
     */
    c->sbh = scon->sbh;
    ap_run_resume_connection(c, scon->r);

    /* Continue where a normal request would after processing: flush pending
     * output, then decide keep-alive vs. close.
     */
    scon->cs.state = CONN_STATE_WRITE_COMPLETION;
    scon->cs.sense = CONN_SENSE_DEFAULT;

    return apr_thread_pool_push(mz->workers, motorz_io_invoke,
                                scon->pfd.client_data,
                                APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
}

/* One poll thread per poller drives accept/dispatch/timer work for the
 * connections bound to it; workers only process. Each child runs num_pollers
 * of these in parallel. See "Scaling / architecture limits" in MOTORZ.README.
 */
static apr_status_t motorz_pollset_cb(motorz_poller_t *poller, apr_interval_time_t timeout)
{
    apr_status_t rc;
    const apr_pollfd_t *out_pfd = NULL;
    apr_int32_t num = 0;

    rc = apr_pollset_poll(poller->pollset, timeout, &num, &out_pfd);
    if (rc != APR_SUCCESS) {
        if (APR_STATUS_IS_EINTR(rc) || APR_STATUS_IS_TIMEUP(rc)) {
                return APR_SUCCESS;
        } else {
            return rc;
        }
    }
    while (num > 0) {
        rc = motorz_io_callback(poller, out_pfd);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rc, NULL, APLOGNO(03334)
                         "Call to motorz_io_callback() failed");
        }
        out_pfd++;
        num--;
    }
    return APR_SUCCESS;
}

/**
 * Create worker thread pool.
 */
static apr_status_t motorz_setup_workers(motorz_core_t *mz)
{
    apr_status_t rv;

    rv = apr_thread_pool_create(&mz->workers,
                                threads_per_child,
                                threads_per_child, mz->pool);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(02851)
                     "motorz_setup_workers: apr_thread_pool_create with %d threads failed",
                     threads_per_child);
        return rv;
    }

    return APR_SUCCESS;
}

static int motorz_setup_pollset(motorz_poller_t *poller)
{
    int i;
    apr_status_t rv;
    int good_methods[] = {APR_POLLSET_KQUEUE, APR_POLLSET_PORT, APR_POLLSET_EPOLL};

    /* The pollset is mutated (apr_pollset_{add,remove}) from worker-pool
     * threads while this poller's thread is blocked in apr_pollset_poll(), so
     * it MUST be thread-safe. All the preferred backends below
     * (kqueue/port/epoll) support APR_POLLSET_THREADSAFE.
     */
    for (i = 0; i < sizeof(good_methods) / sizeof(good_methods[0]); i++) {
        rv = apr_pollset_create_ex(&poller->pollset,
                                  512,
                                  poller->pool,
                                  APR_POLLSET_NODEFAULT | APR_POLLSET_THREADSAFE,
                                  good_methods[i]);
        if (rv == APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02852)
                         "motorz_setup_pollset: apr_pollset_create_ex using %s", apr_pollset_method_name(poller->pollset));

            break;
        }
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, ap_server_conf, APLOGNO(02853)
                     "motorz_setup_pollset: apr_pollset_create_ex failed for all possible backends!");
        rv = apr_pollset_create(&poller->pollset,
                                    512,
                                    poller->pool,
                                    APR_POLLSET_THREADSAFE);
    }
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(02854)
                     "motorz_setup_pollset: apr_pollset_create failed for all possible backends!");
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(03335)
                 "motorz_setup_pollset: Using %s", apr_pollset_method_name(poller->pollset));
    return rv;
}

static void motorz_note_child_killed(int childnum, pid_t pid,
                                      ap_generation_t gen)
{
    AP_DEBUG_ASSERT(childnum != -1); /* no scoreboard squatting with this MPM */
    ap_run_child_status(ap_server_conf,
                        ap_scoreboard_image->parent[childnum].pid,
                        ap_scoreboard_image->parent[childnum].generation,
                        childnum, MPM_CHILD_EXITED);
    ap_scoreboard_image->parent[childnum].pid = 0;
}

static void motorz_note_child_started(motorz_core_t *mz, int slot, pid_t pid)
{
    ap_generation_t gen = mz->mpm->my_generation;
    ap_scoreboard_image->parent[slot].pid = pid;
    ap_scoreboard_image->parent[slot].generation = gen;
    ap_run_child_status(ap_server_conf, pid, gen, slot, MPM_CHILD_STARTED);
}

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code)
{
    motorz_core_t *mz = motorz_core_get();

    mz->mpm->mpm_state = AP_MPMQ_STOPPING;

    apr_signal(SIGHUP, SIG_IGN);
    apr_signal(SIGTERM, SIG_IGN);

    /* Drain the worker thread pool before tearing down pools. Without this,
     * worker threads executing motorz_io_process or motorz_conn_done (which
     * call ap_log_error and apr_pool_clear) may still be running when pchild
     * and its log state are destroyed, causing use-after-free crashes.
     * apr_thread_pool_destroy() joins all worker threads before returning.
     * mz->workers is NULL only if motorz_setup_workers() was never called
     * (i.e. we're exiting very early, before child_main set up workers).
     */
    if (mz->workers) {
        apr_thread_pool_destroy(mz->workers);
        mz->workers = NULL;
    }

    if (pchild) {
        apr_pool_destroy(pchild);
    }

    if (one_process) {
        motorz_note_child_killed(/* slot */ 0, 0, 0);
    }

    ap_mpm_pod_close(my_bucket->pod);
    exit(code);
}

#if 0 /* unused for now */
static apr_status_t accept_mutex_on(void)
{
    motorz_core_t *mz = motorz_core_get();
    apr_status_t rv = apr_proc_mutex_lock(my_bucket->mutex);
    if (rv != APR_SUCCESS) {
        const char *msg = "couldn't grab the accept mutex";

        if (mz->mpm->my_generation !=
            ap_scoreboard_image->global->running_generation) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02855) "%s", msg);
            clean_child_exit(0);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(02856) "%s", msg);
            exit(APEXIT_CHILDFATAL);
        }
    }
    return APR_SUCCESS;
}

static apr_status_t accept_mutex_off(void)
{
    motorz_core_t *mz = motorz_core_get();
    apr_status_t rv = apr_proc_mutex_unlock(my_bucket->mutex);
    if (rv != APR_SUCCESS) {
        const char *msg = "couldn't release the accept mutex";

        if (mz->mpm->my_generation !=
            ap_scoreboard_image->global->running_generation) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf, APLOGNO(02857) "%s", msg);
            /* don't exit here... we have a connection to
             * process, after which point we'll see that the
             * generation changed and we'll exit cleanly
             */
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(02858) "%s", msg);
            exit(APEXIT_CHILDFATAL);
        }
    }
    return APR_SUCCESS;
}
#endif

/* On some architectures it's safe to do unserialized accept()s in the single
 * Listen case.  But it's never safe to do it in the case where there's
 * multiple Listen statements.  Define SINGLE_LISTEN_UNSERIALIZED_ACCEPT
 * when it's safe in the single Listen case.
 */
#ifdef SINGLE_LISTEN_UNSERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) (ap_listeners->next ? (stmt) : APR_SUCCESS)
#else
#define SAFE_ACCEPT(stmt) (stmt)
#endif

static int motorz_query(int query_code, int *result, apr_status_t *rv)
{
    motorz_core_t *mz = motorz_core_get();
    *rv = APR_SUCCESS;
    switch(query_code){
    case AP_MPMQ_IS_ASYNC:
        /* See MOTORZ_ENABLE_ASYNC at the top of this file: async HTTP/2 handoff
         * is disabled pending a mod_http2 c1/c2 close-ordering fix. */
        *result = MOTORZ_ENABLE_ASYNC;
        break;
    case AP_MPMQ_CAN_SUSPEND:
        *result = 1;
        break;
    case AP_MPMQ_CAN_WAITIO:
        /* CONN_STATE_ASYNC_WAITIO is only requested by modules when the MPM is
         * async; motorz honors it (polls per c->cs->sense under Timeout and
         * re-enters the process_connection hooks -- see motorz_io_process()),
         * but gate it on MOTORZ_ENABLE_ASYNC so it tracks IS_ASYNC. */
        *result = MOTORZ_ENABLE_ASYNC;
        break;
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_IS_THREADED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_IS_FORKED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_HARD_LIMIT_DAEMONS:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_HARD_LIMIT_THREADS:
        *result = thread_limit;
        break;
    case AP_MPMQ_MAX_THREADS:
        *result = threads_per_child;
        break;
    case AP_MPMQ_MIN_SPARE_DAEMONS:
        *result = 0;
        break;
    case AP_MPMQ_MIN_SPARE_THREADS:
        *result = 0;
        break;
    case AP_MPMQ_MAX_SPARE_DAEMONS:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_MAX_SPARE_THREADS:
        *result = 0;
        break;
    case AP_MPMQ_MAX_REQUESTS_DAEMON:
        *result = 0;
        break;
    case AP_MPMQ_MAX_DAEMONS:
        *result = ap_num_kids;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = mz->mpm->mpm_state;
        break;
    case AP_MPMQ_GENERATION:
        *result = mz->mpm->my_generation;
        break;
    default:
        *rv = APR_ENOTIMPL;
        break;
    }
    return OK;
}

static const char *motorz_get_name(void)
{
    return "motorz";
}

/*****************************************************************
 * Connection structures and accounting...
 */

static void just_die(int sig)
{
    clean_child_exit(0);
}

static void stop_listening(int sig)
{
    motorz_core_t *mz = motorz_core_get();

    mz->mpm->mpm_state = AP_MPMQ_STOPPING;
    ap_close_listeners_ex(my_bucket->listeners);

    /* For a graceful stop, we want the child to exit when done */
    die_now = 1;
}

/*****************************************************************
 * Child process main loop.
 * The following vars are static to avoid getting clobbered by longjmp();
 * they are really private to child_main.
 */

static int num_listensocks = 0;

/* Listener admission control (#1). The listener pollfds live in the poller
 * that owns the listeners (poller 0); only that poller toggles them, on its
 * own thread, so no locking is needed. The hysteresis band is derived from
 * threads_per_child in child_main.
 */
static apr_size_t motorz_throttle_hi;
static apr_size_t motorz_throttle_lo;

/* Stop accepting: remove the listener sockets from the poller's pollset so it
 * stops dispatching new connections while workers are saturated. Runs on the
 * owning poller's thread only; idempotent.
 */
static void motorz_disable_listeners(motorz_poller_t *poller)
{
    int i;

    if (poller->listeners_disabled) {
        return;
    }
    for (i = 0; i < poller->num_listener_pfds; i++) {
        apr_status_t rv = apr_pollset_remove(poller->pollset,
                                             poller->listener_pfds[i]);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rv)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, ap_server_conf,
                         "motorz_disable_listeners: apr_pollset_remove failed");
        }
    }
    poller->listeners_disabled = 1;
    if (my_child_num >= 0) {
        ap_scoreboard_image->parent[my_child_num].not_accepting = 1;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(10552)
                 "Workers busy, not accepting new connections in this child");
}

/* Resume accepting: re-add the listener sockets to the poller's pollset. Runs
 * on the owning poller's thread only; idempotent; a no-op while shutting down.
 */
static void motorz_enable_listeners(motorz_poller_t *poller)
{
    int i;

    if (!poller->listeners_disabled || die_now) {
        return;
    }
    for (i = 0; i < poller->num_listener_pfds; i++) {
        apr_status_t rv = apr_pollset_add(poller->pollset,
                                          poller->listener_pfds[i]);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, ap_server_conf,
                         "motorz_enable_listeners: apr_pollset_add failed");
        }
    }
    poller->listeners_disabled = 0;
    if (my_child_num >= 0) {
        ap_scoreboard_image->parent[my_child_num].not_accepting = 0;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(10553)
                 "Accepting new connections again in this child");
}

/* Reconsider admission once per poll-loop iteration (owning poller's thread).
 * Disable listeners when the worker pool is saturated and re-enable once it has
 * drained. Three complementary saturation signals:
 *
 *  1. idle == 0: no thread is free to pick up a new connection right now.
 *  2. pending >= throttle_hi: the push queue has a full wave of unstarted tasks
 *     (each accepted connection becomes one task), so we are ahead of the workers.
 *  3. active >= threads_per_child: all threads are occupied, including those
 *     blocked in I/O waits -- catches the slow-client / keep-alive-heavy case
 *     where the task queue looks empty but workers are fully tied up.
 *
 * The hysteresis band (hi/lo) on the pending count avoids enable/disable
 * flapping. A poller that does not own listeners (num_listener_pfds == 0) no-ops.
 */
static void motorz_update_listeners(motorz_poller_t *poller)
{
    apr_size_t idle, pending, active;

    if (poller->num_listener_pfds == 0) {
        return;
    }
    /* Read total before idle: if a thread exits between the two reads,
     * reading idle first risks unsigned underflow (idle > total -> wrap).
     * Clamp the subtraction to zero so a transient race never yields a
     * spuriously huge 'active' value that trips the saturation check.
     */
    {
        apr_size_t total;
        total   = apr_thread_pool_threads_count(poller->mz->workers);
        idle    = apr_thread_pool_idle_count(poller->mz->workers);
        active  = (total > idle) ? (total - idle) : 0;
    }
    pending = apr_thread_pool_tasks_count(poller->mz->workers);

    if (!poller->listeners_disabled) {
        if (idle == 0
                || pending >= motorz_throttle_hi
                || active >= (apr_size_t)threads_per_child) {
            motorz_disable_listeners(poller);
        }
    }
    else if (idle > 0
                 && pending <= motorz_throttle_lo
                 && active < (apr_size_t)threads_per_child) {
        motorz_enable_listeners(poller);
    }
}

/* Create and initialize one poller context (its own pool, pollset, timer ring
 * and ring mutex). The recycle free-list and listener state start zeroed.
 * 'owns_listeners' marks the poller that holds the accept sockets.
 */
static motorz_poller_t *motorz_poller_create(motorz_core_t *mz, int index)
{
    apr_status_t rv;
    motorz_poller_t *poller = apr_pcalloc(mz->pool, sizeof(*poller));

    poller->mz = mz;
    poller->index = index;
    apr_pool_create(&poller->pool, mz->pool);
    apr_pool_tag(poller->pool, "motorz-poller");

    rv = apr_thread_mutex_create(&poller->mtx, APR_THREAD_MUTEX_DEFAULT,
                                 poller->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(02966)
                     "motorz_poller_create: apr_thread_mutex_create failed");
        clean_child_exit(APEXIT_CHILDSICK);
    }

    apr_skiplist_init(&poller->timeout_ring, poller->pool);
    apr_skiplist_set_compare(poller->timeout_ring, timer_comp, timer_comp);

    rv = motorz_setup_pollset(poller);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(02869)
                     "Couldn't setup pollset in child; check system or user limits");
        clean_child_exit(APEXIT_CHILDSICK); /* assume temporary resource issue */
    }

    return poller;
}

/* Add this child's listening sockets to 'poller' and capture them so admission
 * control can pause/resume accepting (#1). Only the listener-owning poller
 * calls this.
 */
static void motorz_poller_add_listeners(motorz_poller_t *poller)
{
    apr_status_t status;
    ap_listen_rec *lr;
    int i;

    poller->listener_pfds = apr_pcalloc(poller->pool,
                                        num_listensocks * sizeof(apr_pollfd_t *));
    poller->num_listener_pfds = 0;
    poller->listeners_disabled = 0;

    for (lr = my_bucket->listeners, i = num_listensocks; i--; lr = lr->next) {
        apr_pollfd_t *pfd = apr_pcalloc(poller->pool, sizeof *pfd);
        motorz_sb_t *sb = apr_pcalloc(poller->pool, sizeof(motorz_sb_t));

        pfd->desc_type = APR_POLL_SOCKET;
        pfd->desc.s = lr->sd;
        pfd->reqevents = APR_POLLIN;
        pfd->p = poller->pool;
        pfd->client_data = sb;

        sb->type = PT_ACCEPT;
        sb->baton = lr;

        poller->listener_pfds[poller->num_listener_pfds++] = pfd;

        status = apr_socket_opt_set(pfd->desc.s, APR_SO_NONBLOCK, 1);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, status, NULL, APLOGNO(02870)
                         "apr_socket_opt_set(APR_SO_NONBLOCK = 1) failed on %pI",
                         lr->bind_addr);
            clean_child_exit(0);
        }

        status = apr_pollset_add(poller->pollset, pfd);
        if (status != APR_SUCCESS) {
            /* If the child processed a SIGWINCH before setting up the
             * pollset, this error path is expected and harmless,
             * since the listener fd was already closed; so don't
             * pollute the logs in that case.
             */
            if (!die_now) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf, APLOGNO(02871)
                             "Couldn't add listener to pollset; check system or user limits");
                clean_child_exit(APEXIT_CHILDSICK);
            }
            clean_child_exit(0);
        }

        lr->accept_func = ap_unixd_accept;
    }
}

/* One poller's poll loop: poll, dispatch ready events to workers, expire
 * timers, reconsider admission. Runs until die_now / shutdown / restart. Each
 * poller runs this on its own thread; the child's main thread is the
 * supervisor (motorz_supervise) that owns the MaxRequestsPerChild / pod /
 * generation checks and sets die_now. A fatal poll error sets die_now and
 * returns rather than exiting the process, so the other pollers can wind down
 * and the supervisor can clean up.
 */
static void *APR_THREAD_FUNC motorz_poller_main(apr_thread_t *thread, void *baton)
{
    motorz_poller_t *poller = (motorz_poller_t *) baton;
    motorz_core_t *mz = poller->mz;
    apr_status_t status;

    while (!die_now
           && !mz->mpm->shutdown_pending
           && !mz->mpm->restart_pending) {
        apr_time_t tnow = apr_time_now();
        motorz_timer_t *te;
        apr_interval_time_t timeout = apr_time_from_msec(500);

        apr_thread_mutex_lock(poller->mtx);
        te = apr_skiplist_peek(poller->timeout_ring);

        if (te) {
            if (tnow < te->expires) {
                timeout = (te->expires - tnow);
                if (timeout > apr_time_from_msec(500)) {
                    timeout = apr_time_from_msec(500);
                }
            }
            else {
                timeout = 0;
            }
        }
        apr_thread_mutex_unlock(poller->mtx);

        status = motorz_pollset_cb(poller, timeout);

        tnow = apr_time_now();

        if (status != APR_SUCCESS) {
            if (!APR_STATUS_IS_EINTR(status) && !APR_STATUS_IS_TIMEUP(status)) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, status, NULL, APLOGNO(03117)
                             "motorz_main_loop: apr_pollcb_poll failed");
                die_now = 1;
                break;
            }
        }

        apr_thread_mutex_lock(poller->mtx);

        /* Now iterate any expired timers and push them to the worker
         * pool. The loop is driven entirely off a fresh peek taken under
         * the lock rather than the 'te' cached before the poll: while the
         * lock was dropped for polling, a worker thread may have inserted
         * a timer that is now the earliest in the ring. Peeking and
         * popping the minimum in lock-step keeps the popped node and the
         * processed node consistent.
         */
        while ((te = apr_skiplist_peek(poller->timeout_ring))
               && te->expires < tnow) {
            apr_skiplist_pop(poller->timeout_ring, NULL);
            motorz_timer_event_process(poller, te);
        }

        apr_thread_mutex_unlock(poller->mtx);

        /* Admission control (#1): pause/resume accepting based on worker-pool
         * saturation. Done here, on the poll thread and outside poller->mtx,
         * once per iteration. While listeners are disabled the loop still wakes
         * via the 500ms timeout floor and timer expiries, bounding resume
         * latency. No-op on pollers that do not own the listeners.
         */
        motorz_update_listeners(poller);
    }

    return NULL;
}

/* Child supervisor loop, run on the child's main thread while the poller
 * threads do the I/O. Watches MaxRequestsPerChild and the pipe-of-death /
 * generation change, setting die_now so the pollers wind down. Returns when
 * the child should exit.
 */
static void motorz_supervise(motorz_core_t *mz, ap_sb_handle_t *sbh)
{
    while (!die_now
           && !mz->mpm->shutdown_pending
           && !mz->mpm->restart_pending) {

        /* requests_this_child is bumped per accepted connection by the
         * listener-owning poller; once the cap is reached, wind down.
         */
        if (ap_max_requests_per_child > 0
            && requests_this_child >= ap_max_requests_per_child) {
            die_now = 1;
            break;
        }

        ap_update_child_status(sbh, SERVER_READY, NULL);

        if (ap_mpm_pod_check(my_bucket->pod) == APR_SUCCESS) { /* idle kill? */
            die_now = 1;
        }
        else if (mz->mpm->my_generation !=
                 ap_scoreboard_image->global->running_generation) { /* restart? */
            /* yeah, this could be non-graceful restart, in which case the
             * parent will kill us soon enough, but why bother checking?
             */
            die_now = 1;
        }
        else {
            /* Nothing to do; sleep briefly so we don't spin. The pollers run
             * independently, so the supervisor only needs coarse latency.
             */
            apr_sleep(apr_time_from_msec(100));
        }
    }
}

static void child_main(motorz_core_t *mz, int child_num_arg, int child_bucket)
{
#if APR_HAS_THREADS
    apr_thread_t *thd = NULL;
    apr_os_thread_t osthd;
#endif
    apr_status_t status;
    int i;
    ap_sb_handle_t *sbh;
    const char *lockfile;
    motorz_poller_t *poller;

    /* for benefit of any hooks that run as this child initializes */
    mz->mpm->mpm_state = AP_MPMQ_STARTING;

    my_child_num = child_num_arg;
    ap_my_pid = getpid();
    requests_this_child = 0;

    ap_fatal_signal_child_setup(ap_server_conf);

    /* Get a sub context for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    apr_pool_create(&pchild, pconf);
    apr_pool_tag(pchild, "pchild");

#if APR_HAS_THREADS
    osthd = apr_os_thread_current();
    apr_os_thread_put(&thd, &osthd, pchild);
#endif

    /* close unused listeners and pods */
    for (i = 0; i < mz->mpm->num_buckets; i++) {
        if (i != child_bucket) {
            ap_close_listeners_ex(all_buckets[i].listeners);
            ap_mpm_pod_close(all_buckets[i].pod);
        }
    }

    /* needs to be done before we switch UIDs so we have permissions */
    ap_reopen_scoreboard(pchild, NULL, 0);
    status = SAFE_ACCEPT(apr_proc_mutex_child_init(&my_bucket->mutex,
                                    apr_proc_mutex_lockfile(my_bucket->mutex),
                                    pchild));
    if (status != APR_SUCCESS) {
        lockfile = apr_proc_mutex_lockfile(my_bucket->mutex);
        ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf, APLOGNO(02867)
                     "Couldn't initialize cross-process lock in child "
                     "(%s) (%s)",
                     lockfile ? lockfile : "none",
                     apr_proc_mutex_name(my_bucket->mutex));
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (ap_run_drop_privileges(pchild, ap_server_conf)) {
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_run_child_init(pchild, ap_server_conf);

    ap_create_sb_handle(&sbh, pchild, my_child_num, 0);

    ap_update_child_status(sbh, SERVER_READY, NULL);

    status = motorz_setup_workers(mz);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, ap_server_conf, APLOGNO(02868)
                     "child_main: motorz_setup_workers failed");
        clean_child_exit(APEXIT_CHILDSICK);
    }

    /* Admission-control hysteresis band: pause accepting once the pending
     * backlog reaches a full wave (threads_per_child) and resume once it
     * drains to 75%. The 75% low-water mark (vs. the old 50%) re-enables the
     * listener sooner, reducing latency spikes at the cost of slightly more
     * frequent enable/disable transitions -- a good trade under variable load.
     */
    motorz_throttle_hi = threads_per_child;
    motorz_throttle_lo = (threads_per_child * 3) / 4;

    /* Resolve the poller count: explicit PollersPerChild, else auto from online
     * CPUs (capped). Never more pollers than worker threads, and at least 1.
     */
    mz->num_pollers = num_pollers;
    if (mz->num_pollers <= 0) {
#ifdef _SC_NPROCESSORS_ONLN
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        mz->num_pollers = (ncpu > 0) ? (int)ncpu : 1;
#else
        mz->num_pollers = 1;
#endif
        if (mz->num_pollers > MOTORZ_MAX_POLLERS) {
            mz->num_pollers = MOTORZ_MAX_POLLERS;
        }
    }
    if (mz->num_pollers > threads_per_child) {
        mz->num_pollers = threads_per_child;
    }
    if (mz->num_pollers < 1) {
        mz->num_pollers = 1;
    }

    /* Create N pollers, each on its own thread, supervised by this thread.
     * Poller 0 owns the listening sockets (and thus does the accepting);
     * Stage 3 will shard accepted connections across all pollers. With a
     * single poller this is behaviourally identical to the old design.
     */
    mz->pollers = apr_pcalloc(mz->pool,
                              mz->num_pollers * sizeof(motorz_poller_t *));
    for (i = 0; i < mz->num_pollers; i++) {
        mz->pollers[i] = motorz_poller_create(mz, i);
    }
    /* Listeners live in poller 0. */
    motorz_poller_add_listeners(mz->pollers[0]);

    mz->mpm->mpm_state = AP_MPMQ_RUNNING;

    /* die_now is set when AP_SIG_GRACEFUL is received in the child;
     * {shutdown,restart}_pending are set when a signal is received while
     * running in single process mode.
     */
    for (i = 0; i < mz->num_pollers; i++) {
        poller = mz->pollers[i];
        status = apr_thread_create(&poller->thread, NULL,
                                   motorz_poller_main, poller, pchild);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf, APLOGNO(10554)
                         "child_main: apr_thread_create failed for poller %d", i);
            die_now = 1;
            clean_child_exit(APEXIT_CHILDSICK);
        }
    }

    /* Supervise on this thread; returns when the child should wind down. */
    motorz_supervise(mz, sbh);

    /* die_now is now set; join the poller threads so their pollsets/rings are
     * quiescent before we tear the child down.
     */
    for (i = 0; i < mz->num_pollers; i++) {
        if (mz->pollers[i]->thread) {
            apr_status_t pstatus;
            apr_thread_join(&pstatus, mz->pollers[i]->thread);
        }
    }

    clean_child_exit(0);
}

static int make_child(motorz_core_t *mz, server_rec *s, int slot)
{
    int bucket = slot % mz->mpm->num_buckets;
    int pid;

    if (slot + 1 > mz->max_daemons_limit) {
        mz->max_daemons_limit = slot + 1;
    }

    if (one_process) {
        my_bucket = &all_buckets[0];

        motorz_note_child_started(mz, slot, getpid());
        child_main(mz, slot, 0);
        /* NOTREACHED */
        ap_assert(0);
        return -1;
    }

    ap_update_child_status_from_indexes(slot, 0, SERVER_STARTING, NULL);

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, APLOGNO(02872) "fork: Unable to fork new process");

        /* fork didn't succeed. Fix the scoreboard or else
         * it will say SERVER_STARTING forever and ever
         */
        ap_update_child_status_from_indexes(slot, 0, SERVER_DEAD, NULL);

        /* In case system resources are maxxed out, we don't want
         * Apache running away with the CPU trying to fork over and
         * over and over again.
         */
        sleep(10);

        return -1;
    }

    if (!pid) {
        my_bucket = &all_buckets[bucket];

#ifdef HAVE_BINDPROCESSOR
        /* by default AIX binds to a single processor
         * this bit unbinds children which will then bind to another cpu
         */
        int status = bindprocessor(BINDPROCESS, (int)getpid(),
                                   PROCESSOR_CLASS_ANY);
        if (status != OK) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, errno,
                         ap_server_conf, APLOGNO(02873) "processor unbind failed");
        }
#endif
        RAISE_SIGSTOP(MAKE_CHILD);
        AP_MONCONTROL(1);
        /* Disable the parent's signal handlers and set up proper handling in
         * the child.
         */
        apr_signal(SIGHUP, just_die);
        apr_signal(SIGTERM, just_die);
        /* Ignore SIGINT in child. This fixes race-condition in signals
         * handling when httpd is running on foreground and user hits ctrl+c.
         * In this case, SIGINT is sent to all children followed by SIGTERM
         * from the main process, which interrupts the SIGINT handler and
         * leads to inconsistency.
         */
        apr_signal(SIGINT, SIG_IGN);
        /* The child process just closes listeners on AP_SIG_GRACEFUL.
         * The pod is used for signalling the graceful restart.
         */
        apr_signal(AP_SIG_GRACEFUL, stop_listening);
        child_main(mz, slot, bucket);
    }

    motorz_note_child_started(mz, slot, pid);

    return 0;
}


/* start up a bunch of children */
static void startup_children(motorz_core_t *mz, int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_num_kids; ++i) {
        if (ap_scoreboard_image->servers[i][0].status != SERVER_DEAD) {
            continue;
        }
        if (make_child(mz, ap_server_conf, i) < 0) {
            break;
        }
        --number_to_start;
    }
}

static void perform_idle_server_maintenance(motorz_core_t *mz, apr_pool_t *p)
{
    int free_length;
    int free_slots[1];

    int i;
    worker_score *ws;

    int active = 0;
    free_length = 0;
    free_slots[0] = 0;

    for (i = 0; i < ap_num_kids; ++i) {
        int status;
        ws = &ap_scoreboard_image->servers[i][0];
        status = ws->status;
        if (status == SERVER_DEAD && !free_length) {
            free_slots[free_length] = i;
            free_length++;
        }
        if (status >= SERVER_READY) {
            active++;
        }
    }
    if (active > ap_num_kids) {
        static int bucket_kill_child_record = -1;
        /* kill off one child... we use the pod because that'll cause it to
         * shut down gracefully, in case it happened to pick up a request
         * while we were counting
         */
        bucket_kill_child_record = (bucket_kill_child_record + 1) % mz->mpm->num_buckets;
        ap_mpm_pod_signal(all_buckets[bucket_kill_child_record].pod);
    }
    else if (active < ap_num_kids) {
        make_child(mz, ap_server_conf, free_slots[0]);
    }
}

/*****************************************************************
 * Executive routines.
 */

static int motorz_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int index;
    int remaining_children_to_start;
    int i;
    motorz_core_t *mz = motorz_core_get();

    ap_log_pid(pconf, ap_pid_fname);

    if (!mz->mpm->was_graceful) {
        if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
            mz->mpm->mpm_state = AP_MPMQ_STOPPING;
            return !OK;
        }
        /* fix the generation number in the global score; we just got a new,
         * cleared scoreboard
         */
        ap_scoreboard_image->global->running_generation = mz->mpm->my_generation;
    }

    ap_unixd_mpm_set_signals(pconf, one_process);

    if (one_process) {
        AP_MONCONTROL(1);
        make_child(mz, ap_server_conf, 0);
        /* NOTREACHED */
        ap_assert(0);
        return !OK;
    }

    /* Don't thrash since num_buckets depends on the
     * system and the number of online CPU cores...
     */
    if (ap_num_kids < mz->mpm->num_buckets)
        ap_num_kids = mz->mpm->num_buckets;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens pretty
     * rapidly... and for each one that exits we'll start a new one until
     * we reach at least daemons_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = ap_num_kids;
    if (!mz->mpm->was_graceful) {
        startup_children(mz, remaining_children_to_start);
        remaining_children_to_start = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02874)
                "%s configured -- resuming normal operations",
                ap_get_server_description());
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(02875)
                "Server built: %s", ap_get_server_built());
    ap_log_command_line(plog, s);
    ap_log_mpm_common(s);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02876)
                "Accept mutex: %s (default: %s)",
                (all_buckets[0].mutex)
                    ? apr_proc_mutex_name(all_buckets[0].mutex)
                    : "none",
                apr_proc_mutex_defname());

    mz->mpm->mpm_state = AP_MPMQ_RUNNING;

    while (!mz->mpm->restart_pending && !mz->mpm->shutdown_pending) {
        int child_slot;
        apr_exit_why_e exitwhy;
        int status, processed_status;
        /* this is a memory leak, but I'll fix it later. */
        apr_proc_t pid;

        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf, ap_server_conf);

        /* XXX: if it takes longer than 1 second for all our children
         * to start up and get into IDLE state then we may spawn an
         * extra child
         */
        if (pid.pid != -1) {
            processed_status = ap_process_child_status(&pid, exitwhy, status);
            child_slot = ap_find_child_by_pid(&pid);
            if (processed_status == APEXIT_CHILDFATAL) {
                /* fix race condition found in PR 39311
                 * A child created at the same time as a graceful happens
                 * can find the lock missing and create a fatal error.
                 * It is not fatal for the last generation to be in this state.
                 */
                if (child_slot < 0
                    || ap_get_scoreboard_process(child_slot)->generation
                       == mz->mpm->my_generation) {
                    mz->mpm->mpm_state = AP_MPMQ_STOPPING;
                    return !OK;
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(02877)
                                 "Ignoring fatal error in child of previous "
                                 "generation (pid %ld).",
                                 (long)pid.pid);
                }
            }

            /* non-fatal death... note that it's gone in the scoreboard. */
            if (child_slot >= 0) {
                ap_update_child_status_from_indexes(child_slot, 0,
                                                    SERVER_DEAD, NULL);
                motorz_note_child_killed(child_slot, 0, 0);
                if (remaining_children_to_start
                    && child_slot < ap_num_kids) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_child(mz, ap_server_conf, child_slot);
                    --remaining_children_to_start;
                }
#if APR_HAS_OTHER_CHILD
            }
            else if (apr_proc_other_child_alert(&pid, APR_OC_REASON_DEATH, status) == APR_SUCCESS) {
                /* handled */
#endif
            }
            else if (mz->mpm->was_graceful) {
                /* Great, we've probably just lost a slot in the
                 * scoreboard.  Somehow we don't know about this
                 * child.
                 */
                ap_log_error(APLOG_MARK, APLOG_WARNING,
                            0, ap_server_conf, APLOGNO(02878)
                            "long lost child came home! (pid %ld)", (long)pid.pid);
            }
            /* Don't perform idle maintenance when a child dies,
             * only do it when there's a timeout.  Remember only a
             * finite number of children can die, and it's pretty
             * pathological for a lot to die suddenly.
             */
            continue;
        }
        else if (remaining_children_to_start) {
            /* we hit a 1 second timeout in which none of the previous
             * generation of children needed to be reaped... so assume
             * they're all done, and pick up the slack if any is left.
             */
            startup_children(mz, remaining_children_to_start);
            remaining_children_to_start = 0;
            /* In any event we really shouldn't do the code below because
             * few of the servers we just started are in the IDLE state
             * yet, so we'd mistakenly create an extra server.
             */
            continue;
        }

        perform_idle_server_maintenance(mz, pconf);
    }

    mz->mpm->mpm_state = AP_MPMQ_STOPPING;

    if (mz->mpm->shutdown_pending && mz->mpm->is_ungraceful) {
        /* Time to shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        if (ap_unixd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(02879) "killpg SIGTERM");
        }
        ap_reclaim_child_processes(1, /* Start with SIGTERM */
                                   motorz_note_child_killed);

        /* cleanup pid file on normal shutdown */
        ap_remove_pid(pconf, ap_pid_fname);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02880)
                    "caught SIGTERM, shutting down");

        return DONE;
    }

    if (mz->mpm->shutdown_pending) {
        /* Time to perform a graceful shut down:
         * Reap the inactive children, and ask the active ones
         * to close their listeners, then wait until they are
         * all done to exit.
         */
        int active_children;
        apr_time_t cutoff = 0;

        /* Stop listening */
        ap_close_listeners();

        /* kill off the idle ones */
        for (i = 0; i < mz->mpm->num_buckets; i++) {
            ap_mpm_pod_killpg(all_buckets[i].pod, mz->max_daemons_limit);
        }

        /* Send SIGUSR1 to the active children */
        active_children = 0;
        for (index = 0; index < ap_num_kids; ++index) {
            if (ap_scoreboard_image->servers[index][0].status != SERVER_DEAD) {
                /* Ask each child to close its listeners. */
                ap_mpm_safe_kill(MPM_CHILD_PID(index), AP_SIG_GRACEFUL);
                active_children++;
            }
        }

        /* Allow each child which actually finished to exit */
        ap_relieve_child_processes(motorz_note_child_killed);

        /* cleanup pid file */
        ap_remove_pid(pconf, ap_pid_fname);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02881)
           "caught " AP_SIG_GRACEFUL_STOP_STRING ", shutting down gracefully");

        if (ap_graceful_shutdown_timeout) {
            cutoff = apr_time_now() +
                     apr_time_from_sec(ap_graceful_shutdown_timeout);
        }

        /* Don't really exit until each child has finished */
        mz->mpm->shutdown_pending = 0;
        do {
            /* Pause for a second */
            sleep(1);

            /* Relieve any children which have now exited */
            ap_relieve_child_processes(motorz_note_child_killed);

            active_children = 0;
            for (index = 0; index < ap_num_kids; ++index) {
                if (ap_mpm_safe_kill(MPM_CHILD_PID(index), 0) == APR_SUCCESS) {
                    active_children = 1;
                    /* Having just one child is enough to stay around */
                    break;
                }
            }
        } while (!mz->mpm->shutdown_pending && active_children &&
                 (!ap_graceful_shutdown_timeout || apr_time_now() < cutoff));

        /* We might be here because we received SIGTERM, either
         * way, try and make sure that all of our processes are
         * really dead.
         */
        ap_unixd_killpg(getpgrp(), SIGTERM);

        return DONE;
    }

    /* we've been told to restart */
    if (one_process) {
        /* not worth thinking about */
        return DONE;
    }

    /* advance to the next generation */
    /* XXX: we really need to make sure this new generation number isn't in
     * use by any of the children.
     */
    ++mz->mpm->my_generation;
    ap_scoreboard_image->global->running_generation = mz->mpm->my_generation;

    if (!mz->mpm->is_ungraceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02882)
                    "Graceful restart requested, doing restart");

        /* kill off the idle ones */
        for (i = 0; i < mz->mpm->num_buckets; i++) {
            ap_mpm_pod_killpg(all_buckets[i].pod, mz->max_daemons_limit);
        }

        /* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.  This will break
         * in a very nasty way if we ever have the scoreboard totally
         * file-based (no shared memory)
         */
        for (index = 0; index < ap_num_kids; ++index) {
            if (ap_scoreboard_image->servers[index][0].status != SERVER_DEAD) {
                ap_scoreboard_image->servers[index][0].status = SERVER_GRACEFUL;
                /* Ask each child to close its listeners.
                 *
                 * NOTE: we use the scoreboard, because if we send SIGUSR1
                 * to every process in the group, this may include CGI's,
                 * piped loggers, etc. They almost certainly won't handle
                 * it gracefully.
                 */
                ap_mpm_safe_kill(ap_scoreboard_image->parent[index].pid, AP_SIG_GRACEFUL);
            }
        }
    }
    else {
        /* Kill 'em off */
        if (ap_unixd_killpg(getpgrp(), SIGHUP) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, APLOGNO(02883) "killpg SIGHUP");
        }
        ap_reclaim_child_processes(0, /* Not when just starting up */
                                   motorz_note_child_killed);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(02884)
                    "SIGHUP received.  Attempting to restart");
    }

    return OK;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 */
static int motorz_open_logs(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;
    int level_flags = 0;
    ap_listen_rec **listen_buckets;
    apr_status_t rv;
    char id[16];
    int i;

    motorz_core_t *mz = motorz_core_get();
    pconf = p;

    /* the reverse of pre_config, we want this only the first time around */
    if (mz->mpm->module_loads == 1) {
        startup = 1;
        level_flags |= APLOG_STARTUP;
    }

    if ((num_listensocks = ap_setup_listeners(ap_server_conf)) < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, 0,
                     (startup ? NULL : s), APLOGNO(03275)
                     "no listening sockets available, shutting down");
        return !OK;
    }

    if (one_process) {
        mz->mpm->num_buckets = 1;
    }
    else if (!mz->mpm->was_graceful) {
        /* Preserve the number of buckets on graceful restarts. */
        mz->mpm->num_buckets = 0;
    }
    if ((rv = ap_duplicate_listeners(pconf, ap_server_conf,
                                     &listen_buckets, &mz->mpm->num_buckets))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                     (startup ? NULL : s), APLOGNO(03276)
                     "could not duplicate listeners");
        return !OK;
    }
    all_buckets = apr_pcalloc(pconf, mz->mpm->num_buckets *
                                     sizeof(motorz_child_bucket));
    for (i = 0; i < mz->mpm->num_buckets; i++) {
        if ((rv = ap_mpm_pod_open(pconf, &all_buckets[i].pod))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                         (startup ? NULL : s), APLOGNO(03277)
                         "could not open pipe-of-death");
            return !OK;
        }
        /* Initialize cross-process accept lock (safe accept needed only) */
        if ((rv = SAFE_ACCEPT((apr_snprintf(id, sizeof id, "%i", i),
                               ap_proc_mutex_create(&all_buckets[i].mutex,
                                                    NULL, AP_ACCEPT_MUTEX_TYPE,
                                                    id, s, pconf, 0))))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT | level_flags, rv,
                         (startup ? NULL : s), APLOGNO(03278)
                         "could not create accept mutex");
            return !OK;
        }
        all_buckets[i].listeners = listen_buckets[i];
    }

    return OK;
}

static int motorz_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    int no_detach, debug, foreground;
    apr_status_t rv;
    const char *userdata_key = "mpm_motorz_module";
    motorz_core_t *mz;

    debug = ap_exists_config_define("DEBUG");

    if (debug) {
        foreground = one_process = 1;
        no_detach = 0;
    }
    else
    {
        no_detach = ap_exists_config_define("NO_DETACH");
        one_process = ap_exists_config_define("ONE_PROCESS");
        foreground = ap_exists_config_define("FOREGROUND");
    }

    ap_mutex_register(p, AP_ACCEPT_MUTEX_TYPE, NULL, APR_LOCK_DEFAULT, 0);

    mz = g_motorz_core = ap_retained_data_get(userdata_key);
    if (!g_motorz_core) {
        mz = g_motorz_core = ap_retained_data_create(userdata_key, sizeof(*g_motorz_core));
        mz->mpm = ap_unixd_mpm_get_retained_data();
        mz->mpm->baton = mz;
        mz->max_daemons_limit = -1;
        /* Pollsets, timer rings and their mutexes are now per-poller and are
         * created per child in motorz_poller_create(); nothing to seed here.
         */
    }
    else if (mz->mpm->baton != mz) {
        /* If the MPM changes on restart, be ungraceful */
        mz->mpm->baton = mz;
        mz->mpm->was_graceful = 0;
    }
    mz->mpm->mpm_state = AP_MPMQ_STARTING;
    ++mz->mpm->module_loads;

    /* sigh, want this only the second time around */
    if (mz->mpm->module_loads == 2) {
        if (!one_process && !foreground) {
            /* before we detach, setup crash handlers to log to errorlog */
            ap_fatal_signal_setup(ap_server_conf, p /* pconf */);
            rv = apr_proc_detach(no_detach ? APR_PROC_DETACH_FOREGROUND
                                           : APR_PROC_DETACH_DAEMONIZE);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(02885)
                             "apr_proc_detach failed");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        apr_pool_create(&mz->pool, ap_pglobal);
        apr_pool_tag(mz->pool, "motorz-mpm-core");
        /* Per-poller ring mutexes are created in motorz_poller_create(). */
    }

    parent_pid = ap_my_pid = getpid();

    ap_listen_pre_config();
    ap_num_kids = DEFAULT_START_DAEMON;
    ap_extended_status = 0;

    return OK;
}

static int motorz_check_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;
    motorz_core_t *mz = motorz_core_get();

    /* the reverse of pre_config, we want this only the first time around */
    if (mz->mpm->module_loads == 1) {
        startup = 1;
    }

    if (ap_num_kids > DEFAULT_SERVER_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(02886)
                         "WARNING: StartServers of %d exceeds compile-time "
                         "limit of %d servers, decreasing to %d.",
                         ap_num_kids, DEFAULT_SERVER_LIMIT, DEFAULT_SERVER_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02887)
                         "StartServers of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         ap_num_kids, DEFAULT_SERVER_LIMIT);
        }
        ap_num_kids = DEFAULT_SERVER_LIMIT;
    }
    else if (ap_num_kids < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(02888)
                         "WARNING: StartServers of %d not allowed, "
                         "increasing to 1.", ap_num_kids);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02889)
                         "StartServers of %d not allowed, increasing to 1",
                         ap_num_kids);
        }
        ap_num_kids = 1;
    }

    if (thread_limit > MAX_THREAD_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(10015)
                         "WARNING: ThreadLimit of %d exceeds compile-time "
                         "limit of %d threads, decreasing to %d.",
                         thread_limit, MAX_THREAD_LIMIT, MAX_THREAD_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10016)
                         "ThreadLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         thread_limit, MAX_THREAD_LIMIT);
        }
        thread_limit = MAX_THREAD_LIMIT;
    }
    else if (thread_limit < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(10017)
                         "WARNING: ThreadLimit of %d not allowed, "
                         "increasing to 1.", thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10018)
                         "ThreadLimit of %d not allowed, increasing to 1",
                         thread_limit);
        }
        thread_limit = 1;
    }

    if (threads_per_child > thread_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(03336)
                         "WARNING: ThreadsPerChild of %d exceeds run-time "
                         "limit of", threads_per_child);
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(03337)
                         " %d servers, decreasing to %d.",
                         thread_limit, thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(03338)
                         "ThreadsPerChild of %d exceeds run-time limit "
                         "of %d, decreasing to match",
                         threads_per_child, thread_limit);
        }
        threads_per_child = thread_limit;
    }
    else if (threads_per_child < 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(03339)
                         "WARNING: ThreadsPerChild of %d not allowed, "
                         "increasing to 1.", threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(03340)
                         "ThreadsPerChild of %d not allowed, increasing to 1",
                         threads_per_child);
        }
        threads_per_child = 1;
    }

    /* Warn about ThreadsPerChild 1: the admission-control low-water mark
     * becomes (1*3)/4 = 0, so listeners only re-enable when the task queue
     * is completely empty, causing severe throughput degradation under any
     * sustained load. ThreadsPerChild >= 4 is strongly recommended.
     */
    if (threads_per_child == 1) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL,
                         APLOGNO(10555)
                         "WARNING: ThreadsPerChild 1 causes severe throughput "
                         "degradation in motorz due to admission-control "
                         "hysteresis. Use ThreadsPerChild >= 4.");
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10556)
                         "ThreadsPerChild 1 causes severe throughput "
                         "degradation in motorz. Use ThreadsPerChild >= 4.");
        }
    }

    return OK;
}

static void motorz_hooks(apr_pool_t *p)
{
    /* Our open_logs hook function must run before the core's, or stderr
     * will be redirected to a file, and the messages won't print to the
     * console.
     */
    static const char *const aszSucc[] = {"core.c", NULL};
    ap_force_set_tz(p);

    ap_hook_open_logs(motorz_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);
    /* we need to set the MPM state before other pre-config hooks use MPM query
     * to retrieve it, so register as REALLY_FIRST
     */
    ap_hook_pre_config(motorz_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_check_config(motorz_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm(motorz_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(motorz_query, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_get_name(motorz_get_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_resume_suspended(motorz_resume_suspended, NULL, NULL,
                                 APR_HOOK_MIDDLE);
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_num_kids = atoi(arg);
    return NULL;
}

static const char *set_threads_per_child(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    threads_per_child = atoi(arg);
    return NULL;
}

static const char *set_thread_limit (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    thread_limit = atoi(arg);
    return NULL;
}

static const char *set_pollers_per_child(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    num_pollers = atoi(arg);
    return NULL;
}

static const command_rec motorz_cmds[] = {
LISTEN_COMMANDS,
AP_INIT_TAKE1("StartServers", set_daemons_to_start, NULL, RSRC_CONF,
              "Number of child processes launched at server startup"),
AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
              "Number of threads each child creates"),
AP_INIT_TAKE1("ThreadLimit", set_thread_limit, NULL, RSRC_CONF,
  "Maximum number of worker threads per child process for this run of Apache - Upper limit for ThreadsPerChild"),
AP_INIT_TAKE1("PollersPerChild", set_pollers_per_child, NULL, RSRC_CONF,
  "Number of poll threads per child process (0 = auto from online CPUs)"),
AP_GRACEFUL_SHUTDOWN_TIMEOUT_COMMAND,
{ NULL }
};

AP_DECLARE_MODULE(mpm_motorz) = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    motorz_cmds,               /* command apr_table_t */
    motorz_hooks,              /* register hooks */
};
