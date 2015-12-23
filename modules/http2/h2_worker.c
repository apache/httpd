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

#include <apr_thread_cond.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2_conn.h"
#include "h2_ctx.h"
#include "h2_h2.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_task.h"
#include "h2_worker.h"

static void* APR_THREAD_FUNC execute(apr_thread_t *thread, void *wctx)
{
    h2_worker *worker = (h2_worker *)wctx;
    apr_status_t status = APR_SUCCESS;
    h2_mplx *m;
    const h2_request *req;
    h2_task *task;
    conn_rec *c, *master;
    int stream_id;
    
    (void)thread;
    
    /* Furthermore, other code might want to see the socket for
     * this connection. Allocate one without further function...
     */
    status = apr_socket_create(&worker->socket,
                               APR_INET, SOCK_STREAM,
                               APR_PROTO_TCP, worker->pool);
    if (status != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, status, worker->pool,
                      APLOGNO(02948) "h2_worker(%d): alloc socket", 
                      worker->id);
        worker->worker_done(worker, worker->ctx);
        return NULL;
    }
    
    m = NULL;
    while (!worker->aborted) {
        status = worker->get_next(worker, &m, &req, worker->ctx);
        
        if (req) {
            stream_id = req->id;
            master = m->c;
            c = h2_slave_create(master, worker->task_pool, 
                                worker->thread, worker->socket);
            if (!c) {
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, status, c,
                              APLOGNO(02957) "h2_task(%s): error setting up slave connection", 
                              task->id);
                h2_mplx_out_rst(m, task->stream_id, H2_ERR_INTERNAL_ERROR);
            }
            else {
                task = h2_task_create(m->id, req, worker->task_pool, m);
                h2_ctx_create_for(c, task);
                h2_task_do(task, c, worker->io, worker->socket);
                
                apr_thread_cond_signal(worker->io);
            }
            apr_pool_clear(worker->task_pool);
            /* task is gone */
            task = NULL;
            h2_mplx_task_done(m, stream_id);
        }
    }

    if (m) {
        /* Hand "m" back to other workers */
        status = worker->get_next(worker, &m, NULL, worker->ctx);
        m = NULL;
    }
    
    if (worker->socket) {
        apr_socket_close(worker->socket);
        worker->socket = NULL;
    }
    
    worker->worker_done(worker, worker->ctx);
    return NULL;
}

static apr_status_t cleanup_join_thread(void *ctx)
{
    h2_worker *w = ctx;
    /* do the join only when the worker is aborted. Otherwise,
     * we are probably in a process shutdown.
     */
    if (w->thread && w->aborted) {
        apr_status_t rv;
        apr_thread_join(&rv, w->thread);
    }
    return APR_SUCCESS;
}

h2_worker *h2_worker_create(int id,
                            apr_pool_t *parent_pool,
                            apr_threadattr_t *attr,
                            h2_worker_mplx_next_fn *get_next,
                            h2_worker_done_fn *worker_done,
                            void *ctx)
{
    apr_allocator_t *allocator = NULL;
    apr_pool_t *pool = NULL;
    h2_worker *w;
    apr_status_t status;
    
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    apr_pool_create_ex(&pool, parent_pool, NULL, allocator);
    apr_allocator_owner_set(allocator, pool);

    w = apr_pcalloc(pool, sizeof(h2_worker));
    if (w) {
        APR_RING_ELEM_INIT(w, link);
        
        w->id = id;
        w->pool = pool;

        w->get_next = get_next;
        w->worker_done = worker_done;
        w->ctx = ctx;
        
        status = apr_thread_cond_create(&w->io, w->pool);
        if (status != APR_SUCCESS) {
            return NULL;
        }
        
        apr_pool_pre_cleanup_register(w->pool, w, cleanup_join_thread);
        apr_pool_create(&w->task_pool, w->pool);
        apr_thread_create(&w->thread, attr, execute, w, w->pool);
    }
    return w;
}

apr_status_t h2_worker_destroy(h2_worker *worker)
{
    if (worker->io) {
        apr_thread_cond_destroy(worker->io);
        worker->io = NULL;
    }
    if (worker->pool) {
        apr_pool_destroy(worker->pool);
        /* worker is gone */
    }
    return APR_SUCCESS;
}

int h2_worker_get_id(h2_worker *worker)
{
    return worker->id;
}

void h2_worker_abort(h2_worker *worker)
{
    worker->aborted = 1;
}

int h2_worker_is_aborted(h2_worker *worker)
{
    return worker->aborted;
}

h2_task *h2_worker_create_task(h2_worker *worker, h2_mplx *m, 
                               const h2_request *req)
{
    h2_task *task;
    
    task = h2_task_create(m->id, req, worker->task_pool, m);
    return task;
}


