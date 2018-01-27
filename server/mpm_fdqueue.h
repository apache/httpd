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

struct fd_queue_info_t; /* opaque */
struct fd_queue_elem_t; /* opaque */
typedef struct fd_queue_info_t fd_queue_info_t;
typedef struct fd_queue_elem_t fd_queue_elem_t;

AP_DECLARE(apr_status_t) ap_queue_info_create(fd_queue_info_t **queue_info,
                                              apr_pool_t *pool, int max_idlers,
                                              int max_recycled_pools);
AP_DECLARE(apr_status_t) ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                                apr_pool_t *pool_to_recycle);
AP_DECLARE(apr_status_t) ap_queue_info_try_get_idler(fd_queue_info_t *queue_info);
AP_DECLARE(apr_status_t) ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info,
                                                      int *had_to_block);
AP_DECLARE(apr_uint32_t) ap_queue_info_num_idlers(fd_queue_info_t *queue_info);
AP_DECLARE(apr_status_t) ap_queue_info_term(fd_queue_info_t *queue_info);

AP_DECLARE(void) ap_queue_info_pop_pool(fd_queue_info_t *queue_info,
                                        apr_pool_t **recycled_pool);
AP_DECLARE(void) ap_queue_info_push_pool(fd_queue_info_t *queue_info,
                                         apr_pool_t *pool_to_recycle);
AP_DECLARE(void) ap_queue_info_free_idle_pools(fd_queue_info_t *queue_info);

struct timer_event_t
{
    APR_RING_ENTRY(timer_event_t) link;
    apr_time_t when;
    ap_mpm_callback_fn_t *cbfunc;
    void *baton;
    int canceled;
    apr_array_header_t *remove;
};
typedef struct timer_event_t timer_event_t;

struct fd_queue_t
{
    APR_RING_HEAD(timers_t, timer_event_t) timers;
    fd_queue_elem_t *data;
    unsigned int nelts;
    unsigned int bounds;
    unsigned int in;
    unsigned int out;
    apr_thread_mutex_t *one_big_mutex;
    apr_thread_cond_t *not_empty;
    int terminated;
};
typedef struct fd_queue_t fd_queue_t;

AP_DECLARE(apr_status_t) ap_queue_create(fd_queue_t **pqueue,
                                         int capacity, apr_pool_t *p);
AP_DECLARE(apr_status_t) ap_queue_push_socket(fd_queue_t *queue,
                                              apr_socket_t *sd, void *sd_baton,
                                              apr_pool_t *p);
AP_DECLARE(apr_status_t) ap_queue_push_timer(fd_queue_t *queue,
                                             timer_event_t *te);
AP_DECLARE(apr_status_t) ap_queue_pop_something(fd_queue_t *queue,
                                                apr_socket_t **sd, void **sd_baton,
                                                apr_pool_t **p, timer_event_t **te);
#define                  ap_queue_pop_socket(q_, s_, p_) \
                            ap_queue_pop_something((q_), (s_), NULL, (p_), NULL)

AP_DECLARE(apr_status_t) ap_queue_interrupt_all(fd_queue_t *queue);
AP_DECLARE(apr_status_t) ap_queue_interrupt_one(fd_queue_t *queue);
AP_DECLARE(apr_status_t) ap_queue_term(fd_queue_t *queue);

#endif /* APR_HAS_THREADS */

#endif /* MPM_FDQUEUE_H */
/** @} */
