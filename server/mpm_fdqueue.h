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

/**
 * @file  server/mpm_fdqueue.h
 * @brief fd queue declarations
 *
 * @addtogroup APACHE_MPM_EVENT
 * @{
 */

#ifndef MPM_FDQUEUE_H
#define MPM_FDQUEUE_H

#include <apr.h>

/* This code is not AP_DECLARE()ed/exported, and used by MPMs event/worker
 * only (for now), not worth thinking about w/o threads either...
 */
#if APR_HAS_THREADS

#include "ap_mpm.h"

#include <apr_ring.h>
#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <apr_network_io.h>

struct ap_queue_t;      /* opaque */
struct ap_queue_info_t; /* opaque */
struct ap_queue_elem_t; /* opaque */
typedef struct ap_queue_t ap_queue_t;
typedef struct ap_queue_info_t ap_queue_info_t;
typedef struct ap_queue_elem_t ap_queue_elem_t;

AP_DECLARE(apr_status_t) ap_queue_info_create(ap_queue_info_t **queue_info,
                                              apr_pool_t *pool, int max_idlers,
                                              int max_recycled_pools);
AP_DECLARE(apr_status_t) ap_queue_info_set_idle(ap_queue_info_t *queue_info,
                                                apr_pool_t *pool_to_recycle);
AP_DECLARE(apr_status_t) ap_queue_info_try_get_idler(ap_queue_info_t *queue_info);
AP_DECLARE(apr_status_t) ap_queue_info_wait_for_idler(ap_queue_info_t *queue_info,
                                                      int *had_to_block);
AP_DECLARE(apr_uint32_t) ap_queue_info_num_idlers(ap_queue_info_t *queue_info);
AP_DECLARE(apr_status_t) ap_queue_info_term(ap_queue_info_t *queue_info);

/* Async API */
AP_DECLARE(apr_int32_t) ap_queue_info_set_idler(ap_queue_info_t *queue_info);
AP_DECLARE(apr_int32_t) ap_queue_info_get_idler(ap_queue_info_t *queue_info);
AP_DECLARE(apr_int32_t) ap_queue_info_count(ap_queue_info_t *queue_info);

AP_DECLARE(void) ap_queue_info_pop_pool(ap_queue_info_t *queue_info,
                                        apr_pool_t **recycled_pool);
AP_DECLARE(void) ap_queue_info_push_pool(ap_queue_info_t *queue_info,
                                         apr_pool_t *pool_to_recycle);
AP_DECLARE(void) ap_queue_info_free_idle_pools(ap_queue_info_t *queue_info);

enum ap_queue_event_type_e
{
    AP_QUEUE_EVENT_SOCK,
    AP_QUEUE_EVENT_TIMER,
    AP_QUEUE_EVENT_BATON,
};
typedef enum ap_queue_event_type_e ap_queue_event_type_e;

struct sock_event_t
{
    apr_pool_t *p;
    apr_socket_t *sd;
    void *baton;
};
typedef struct sock_event_t sock_event_t;

struct timer_event_t
{
    APR_RING_ENTRY(timer_event_t) link;
    apr_time_t when;
    ap_mpm_callback_fn_t *cbfunc;
    void *baton;
    int canceled;
    apr_array_header_t *pfds;
    apr_interval_time_t timeout;
};
typedef struct timer_event_t timer_event_t;

struct ap_queue_event_t
{
    /* ref to container when queued (for internal use) */
    ap_queue_elem_t *elem;

    /* called back when the even is pushed and (later) popped,
     * under the queue lock (must not block!)
     */
    void (*cb)(void *cb_baton, int pushed);
    void *cb_baton;

    /* event data */
    ap_queue_event_type_e type;
    union {
        sock_event_t *se;
        timer_event_t *te;
        void *baton;
    } data;
};
typedef struct ap_queue_event_t ap_queue_event_t;

apr_status_t ap_queue_create(ap_queue_t **queue, int capacity, apr_pool_t *p);

/* mpm_event API */
AP_DECLARE(apr_status_t) ap_queue_push_event(ap_queue_t *queue,
                                             ap_queue_event_t *event);
AP_DECLARE(apr_status_t) ap_queue_pop_event(ap_queue_t *queue,
                                            ap_queue_event_t **event);
AP_DECLARE(apr_status_t) ap_queue_lock(ap_queue_t *queue);
AP_DECLARE(void) ap_queue_kill_event_locked(ap_queue_t *queue,
                                            ap_queue_event_t *event);
AP_DECLARE(apr_status_t) ap_queue_unlock(ap_queue_t *queue);

#define ap_queue_push_timer(q_, t_) \
    ap_queue_push_something((q_), NULL, NULL, NULL, (t_))

/* mpm_worker API */
AP_DECLARE(apr_status_t) ap_queue_push_something(ap_queue_t *queue,
                                                 apr_socket_t *sd, void *sd_baton,
                                                 apr_pool_t *p, timer_event_t *te);
AP_DECLARE(apr_status_t) ap_queue_pop_something(ap_queue_t *queue,
                                                apr_socket_t **sd, void **sd_baton,
                                                apr_pool_t **p, timer_event_t **te);
#define ap_queue_push_socket(q_, s_, b_, p_) \
    ap_queue_push_something((q_), (s_), (b_), (p_), NULL)
#define ap_queue_pop_socket(q_, s_, p_) \
    ap_queue_pop_something((q_), (s_), NULL, (p_), NULL)

/* common API */
AP_DECLARE(apr_status_t) ap_queue_interrupt_all(ap_queue_t *queue);
AP_DECLARE(apr_status_t) ap_queue_interrupt_one(ap_queue_t *queue);
AP_DECLARE(apr_status_t) ap_queue_term(ap_queue_t *queue);

#endif /* APR_HAS_THREADS */

#endif /* MPM_FDQUEUE_H */
/** @} */
