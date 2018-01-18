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
 * @file  mpm_unix.h
 * @brief fd queue declarations
 *
 * @defgroup APACHE_MPM Multi-Processing Modules
 * @ingroup  APACHE
 * @{
 */

#ifndef MPM_UNIX_H
#define MPM_UNIX_H

#ifndef WIN32

#include <apr.h>
#include <apr_ring.h>
#include <apr_pools.h>
#include <apr_network_io.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include "ap_mpm.h"

struct fd_queue_info_t; /* opaque */
struct fd_queue_elem_t; /* opaque */
typedef struct fd_queue_info_t fd_queue_info_t;
typedef struct fd_queue_elem_t fd_queue_elem_t;

apr_status_t ap_queue_info_create(fd_queue_info_t **queue_info,
                                  apr_pool_t *pool, int max_idlers,
                                  int max_recycled_pools);
apr_status_t ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                    apr_pool_t *pool_to_recycle);
apr_status_t ap_queue_info_try_get_idler(fd_queue_info_t *queue_info);
apr_status_t ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info,
                                          int *had_to_block);
apr_uint32_t ap_queue_info_num_idlers(fd_queue_info_t *queue_info);
apr_status_t ap_queue_info_term(fd_queue_info_t *queue_info);

typedef struct timer_event_t timer_event_t;

struct timer_event_t
{
    APR_RING_ENTRY(timer_event_t) link;
    apr_time_t when;
    ap_mpm_callback_fn_t *cbfunc;
    void *baton;
    int canceled;
    apr_array_header_t *remove;
};

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

void ap_pop_pool(apr_pool_t **recycled_pool, fd_queue_info_t *queue_info);
void ap_push_pool(fd_queue_info_t *queue_info, apr_pool_t *pool_to_recycle);
void ap_free_idle_pools(fd_queue_info_t *queue_info);

apr_status_t ap_queue_init(fd_queue_t *queue, int queue_capacity,
                           apr_pool_t *a);
apr_status_t ap_queue_push(fd_queue_t *queue, apr_socket_t *sd,
                           void *baton, apr_pool_t *p);
apr_status_t ap_queue_push_timer(fd_queue_t *queue, timer_event_t *te);
apr_status_t ap_queue_pop_something(fd_queue_t *queue, apr_socket_t **sd,
                                    void **baton, apr_pool_t **p,
                                    timer_event_t **te);
apr_status_t ap_queue_interrupt_all(fd_queue_t *queue);
apr_status_t ap_queue_interrupt_one(fd_queue_t *queue);
apr_status_t ap_queue_term(fd_queue_t *queue);

#endif /* WIN32 */

#endif /* MPM_UNIX_H */
/** @} */
