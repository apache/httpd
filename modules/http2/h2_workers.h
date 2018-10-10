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

#ifndef __mod_h2__h2_workers__
#define __mod_h2__h2_workers__

/* Thread pool specific to executing h2_tasks. Has a minimum and maximum 
 * number of workers it creates. Starts with minimum workers and adds
 * some on load, reduces the number again when idle.
 *
 */
struct apr_thread_mutex_t;
struct apr_thread_cond_t;
struct h2_mplx;
struct h2_request;
struct h2_task;
struct h2_fifo;

struct h2_slot;

typedef struct h2_workers h2_workers;

struct h2_workers {
    server_rec *s;
    apr_pool_t *pool;
    
    int next_worker_id;
    apr_uint32_t min_workers;
    apr_uint32_t max_workers;
    int max_idle_secs;
    
    int aborted;
    int dynamic;

    apr_threadattr_t *thread_attr;
    int nslots;
    struct h2_slot *slots;
    
    volatile apr_uint32_t worker_count;
    
    struct h2_slot *free;
    struct h2_slot *idle;
    struct h2_slot *zombies;
    
    struct h2_fifo *mplxs;
    
    struct apr_thread_mutex_t *lock;
};


/* Create a worker pool with the given minimum and maximum number of
 * threads.
 */
h2_workers *h2_workers_create(server_rec *s, apr_pool_t *pool,
                              int min_size, int max_size, int idle_secs);

/**
 * Registers a h2_mplx for task scheduling. If this h2_mplx runs
 * out of tasks, it will be automatically be unregistered. Should
 * new tasks arrive, it needs to be registered again.
 */
apr_status_t h2_workers_register(h2_workers *workers, struct h2_mplx *m);

/**
 * Remove a h2_mplx from the worker registry.
 */
apr_status_t h2_workers_unregister(h2_workers *workers, struct h2_mplx *m);

#endif /* defined(__mod_h2__h2_workers__) */
