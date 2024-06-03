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

/* This code is AP_DECLARE()ed/exportedbut  used by MPMs event/worker
 * only (for now), not worth thinking about w/o threads either...
 */
#if APR_HAS_THREADS

#include "ap_mpm.h"

#include <apr_ring.h>
#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <apr_network_io.h>

struct fd_queue_t;      /* opaque */
struct fd_queue_info_t; /* opaque */
struct fd_queue_elem_t; /* opaque */
typedef struct fd_queue_t fd_queue_t;
typedef struct fd_queue_info_t fd_queue_info_t;
typedef struct fd_queue_elem_t fd_queue_elem_t;

AP_DECLARE(apr_status_t) ap_queue_info_create(fd_queue_info_t **queue_info,
                                              apr_pool_t *pool, int max_recycled_pools);
AP_DECLARE(apr_status_t) ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                                apr_pool_t *pool_to_recycle);
AP_DECLARE(apr_status_t) ap_queue_info_try_get_idler(fd_queue_info_t *queue_info);
AP_DECLARE(apr_status_t) ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info);
AP_DECLARE(apr_uint32_t) ap_queue_info_num_idlers(fd_queue_info_t *queue_info);
AP_DECLARE(apr_status_t) ap_queue_info_term(fd_queue_info_t *queue_info);

/* Async API */
AP_DECLARE(apr_int32_t) ap_queue_info_idlers_inc(fd_queue_info_t *queue_info);
AP_DECLARE(apr_int32_t) ap_queue_info_idlers_dec(fd_queue_info_t *queue_info);
AP_DECLARE(apr_int32_t) ap_queue_info_idlers_count(fd_queue_info_t *queue_info);

AP_DECLARE(apr_pool_t *) ap_queue_info_pop_pool(fd_queue_info_t *queue_info);
AP_DECLARE(void) ap_queue_info_push_pool(fd_queue_info_t *queue_info,
                                         apr_pool_t *pool_to_recycle);
AP_DECLARE(void) ap_queue_info_free_idle_pools(fd_queue_info_t *queue_info);

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
    /* event data */
    ap_queue_event_type_e type;
    union {
        sock_event_t *se;
        timer_event_t *te;
        void *baton;
    } data;

    /* called back when the event is pushed/popped,
     * under the queue lock (must not block!)
     */
    void (*cb)(void *baton, int pushed);
    void *cb_baton;

    /* link in container when queued (for internal use) */
    fd_queue_elem_t *elem;
};
typedef struct ap_queue_event_t ap_queue_event_t;

AP_DECLARE(apr_status_t) ap_queue_create(fd_queue_t **pqueue, int capacity,
                                         apr_pool_t *p);

/* mpm_event API (queue of any event) */
AP_DECLARE(apr_status_t) ap_queue_push_event(fd_queue_t *queue,
                                             ap_queue_event_t *event);
AP_DECLARE(apr_status_t) ap_queue_pop_event(fd_queue_t *queue,
                                            ap_queue_event_t **pevent);
AP_DECLARE(apr_status_t) ap_queue_lock(fd_queue_t *queue);
AP_DECLARE(void) ap_queue_kill_event_locked(fd_queue_t *queue,
                                            ap_queue_event_t *event);
AP_DECLARE(apr_status_t) ap_queue_unlock(fd_queue_t *queue);

/* mpm_worker API (queue of socket_event_t only) */
AP_DECLARE(apr_status_t) ap_queue_push_socket(fd_queue_t *queue, apr_socket_t *sd,
                                              apr_pool_t *p);
AP_DECLARE(apr_status_t) ap_queue_pop_socket(fd_queue_t *queue, apr_socket_t **psd,
                                             apr_pool_t **pp);

/* common API */
AP_DECLARE(apr_status_t) ap_queue_interrupt_all(fd_queue_t *queue);
AP_DECLARE(apr_status_t) ap_queue_interrupt_one(fd_queue_t *queue);
AP_DECLARE(apr_status_t) ap_queue_term(fd_queue_t *queue);

#endif /* APR_HAS_THREADS */

#endif /* MPM_FDQUEUE_H */
/** @} */
