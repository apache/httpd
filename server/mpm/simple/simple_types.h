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

#include "apr.h"
#include "apr_pools.h"
#include "apr_poll.h"
#include "apr_hash.h"
#include "apr_ring.h"
#include "apr_thread_pool.h"
#include "apr_buckets.h"
#include "httpd.h"

#ifndef APACHE_MPM_SIMPLE_TYPES_H
#define APACHE_MPM_SIMPLE_TYPES_H

typedef struct simple_core_t simple_core_t;

typedef struct
{
    int proc_count;
    int thread_count;
    int max_requests_per_child;
} simple_proc_mgr_t;

#define SIMPLE_MAX_PROC (500000)
#define SIMPLE_DEF_PROC (5)
#define SIMPLE_MIN_PROC (1)
#define SIMPLE_MAX_THREADS (500000)
#define SIMPLE_DEF_THREADS (5)
#define SIMPLE_MIN_THREADS (1)

typedef void (*simple_timer_cb) (simple_core_t * sc, void *baton);
typedef void (*simple_io_sock_cb) (simple_core_t * sc, apr_socket_t * sock,
                                   int flags, void *baton);
typedef void (*simple_io_file_cb) (simple_core_t * sc, apr_socket_t * sock,
                                   int flags, void *baton);

typedef struct simple_sb_t simple_sb_t;

typedef enum
{
    SIMPLE_PT_CORE_ACCEPT,
    SIMPLE_PT_CORE_IO,
    /* pqXXXXXX: User IO not defined yet. */
    SIMPLE_PT_USER
} simple_poll_type_e;

typedef enum
{
    SIMPLE_SPAWN_FORK,
    SIMPLE_SPAWN_EXEC,
} simple_spawn_type_e;

struct simple_sb_t
{
    simple_poll_type_e type;
    void *baton;
};

typedef struct simple_timer_t simple_timer_t;
struct simple_timer_t
{
    APR_RING_ENTRY(simple_timer_t) link;
    apr_time_t expires;
    simple_timer_cb cb;
    void *baton;
    apr_pool_t *pool;
    simple_core_t *sc;
};

typedef struct simple_child_t simple_child_t;
struct simple_child_t
{
    /* TODO: More is needed here. */
    pid_t pid;
};

struct simple_core_t
{
    apr_pool_t *pool;
    apr_thread_mutex_t *mtx;

    int mpm_state;
    int restart_num;

    int run_single_process;
    int run_foreground;
    simple_spawn_type_e spawn_via;

    simple_proc_mgr_t procmgr;

    /* PID -> simple_child_t map */
    apr_hash_t *children;

    apr_pollcb_t *pollcb;

    /* List of upcoming timers, sorted by nearest first.
     */
    APR_RING_HEAD(simple_timer_ring_t, simple_timer_t) timer_ring;

    apr_thread_pool_t *workers;
};

typedef struct simple_conn_t simple_conn_t;
struct simple_conn_t
{
    apr_pool_t *pool;
    simple_core_t *sc;
    apr_socket_t *sock;
    apr_bucket_alloc_t *ba;
    conn_rec *c;
};

simple_core_t *simple_core_get(void);

/* Allocates/initializes data retained over the life of the process */
apr_status_t simple_core_init_once(void);

#endif /* APACHE_MPM_SIMPLE_TYPES_H */
