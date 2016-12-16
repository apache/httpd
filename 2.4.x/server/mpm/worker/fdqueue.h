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
 * @file  worker/fdqueue.h
 * @brief fd queue declarations
 *
 * @addtogroup APACHE_MPM_WORKER
 * @{
 */

#ifndef FDQUEUE_H
#define FDQUEUE_H
#include "httpd.h"
#include <stdlib.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>
#include <sys/types.h>
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <apr_errno.h>

typedef struct fd_queue_info_t fd_queue_info_t;

apr_status_t ap_queue_info_create(fd_queue_info_t **queue_info,
                                  apr_pool_t *pool, int max_idlers);
apr_status_t ap_queue_info_set_idle(fd_queue_info_t *queue_info,
                                    apr_pool_t *pool_to_recycle);
apr_status_t ap_queue_info_wait_for_idler(fd_queue_info_t *queue_info,
                                          apr_pool_t **recycled_pool);
apr_status_t ap_queue_info_term(fd_queue_info_t *queue_info);

struct fd_queue_elem_t {
    apr_socket_t      *sd;
    apr_pool_t        *p;
};
typedef struct fd_queue_elem_t fd_queue_elem_t;

struct fd_queue_t {
    fd_queue_elem_t    *data;
    unsigned int       nelts;
    unsigned int       bounds;
    unsigned int       in;
    unsigned int       out;
    apr_thread_mutex_t *one_big_mutex;
    apr_thread_cond_t  *not_empty;
    int                 terminated;
};
typedef struct fd_queue_t fd_queue_t;

apr_status_t ap_queue_init(fd_queue_t *queue, int queue_capacity, apr_pool_t *a);
apr_status_t ap_queue_push(fd_queue_t *queue, apr_socket_t *sd, apr_pool_t *p);
apr_status_t ap_queue_pop(fd_queue_t *queue, apr_socket_t **sd, apr_pool_t **p);
apr_status_t ap_queue_interrupt_all(fd_queue_t *queue);
apr_status_t ap_queue_term(fd_queue_t *queue);

#endif /* FDQUEUE_H */
/** @} */
