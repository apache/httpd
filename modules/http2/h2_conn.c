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

#include <ap_mpm.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>

#include "h2_private.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_mplx.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_stream_set.h"
#include "h2_h2.h"
#include "h2_task.h"
#include "h2_worker.h"
#include "h2_workers.h"
#include "h2_conn.h"

static struct h2_workers *workers;

static h2_mpm_type_t mpm_type = H2_MPM_UNKNOWN;
static module *mpm_module;
static int checked;

static void check_modules(void) 
{
    int i;
    if (!checked) {
        for (i = 0; ap_loaded_modules[i]; ++i) {
            module *m = ap_loaded_modules[i];
            if (!strcmp("event.c", m->name)) {
                mpm_type = H2_MPM_EVENT;
                mpm_module = m;
            }
            else if (!strcmp("worker.c", m->name)) {
                mpm_type = H2_MPM_WORKER;
                mpm_module = m;
            }
            else if (!strcmp("prefork.c", m->name)) {
                mpm_type = H2_MPM_PREFORK;
                mpm_module = m;
            }
        }
        checked = 1;
    }
}

apr_status_t h2_conn_child_init(apr_pool_t *pool, server_rec *s)
{
    const h2_config *config = h2_config_sget(s);
    apr_status_t status = APR_SUCCESS;
    int minw = h2_config_geti(config, H2_CONF_MIN_WORKERS);
    int maxw = h2_config_geti(config, H2_CONF_MAX_WORKERS);
    
    int max_threads_per_child = 0;
    int threads_limit = 0;
    int idle_secs = 0;
    int i;

    h2_config_init(pool);
    
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads_per_child);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &threads_limit);
    
    for (i = 0; ap_loaded_modules[i]; ++i) {
        module *m = ap_loaded_modules[i];
        if (!strcmp("event.c", m->name)) {
            mpm_type = H2_MPM_EVENT;
            mpm_module = m;
        }
        else if (!strcmp("worker.c", m->name)) {
            mpm_type = H2_MPM_WORKER;
            mpm_module = m;
        }
        else if (!strcmp("prefork.c", m->name)) {
            mpm_type = H2_MPM_PREFORK;
            mpm_module = m;
        }
    }
    
    if (minw <= 0) {
        minw = max_threads_per_child;
    }
    if (maxw <= 0) {
        maxw = threads_limit;
        if (maxw < minw) {
            maxw = minw;
        }
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "h2_workers: min=%d max=%d, mthrpchild=%d, thr_limit=%d", 
                 minw, maxw, max_threads_per_child, threads_limit);
    
    workers = h2_workers_create(s, pool, minw, maxw);
    idle_secs = h2_config_geti(config, H2_CONF_MAX_WORKER_IDLE_SECS);
    h2_workers_set_max_idle_secs(workers, idle_secs);
    
    return status;
}

h2_mpm_type_t h2_conn_mpm_type(void) {
    check_modules();
    return mpm_type;
}

static module *h2_conn_mpm_module(void) {
    check_modules();
    return mpm_module;
}

apr_status_t h2_conn_process(conn_rec *c, request_rec *r, server_rec *s)
{
    apr_status_t status;
    h2_session *session;
    const h2_config *config;
    int rv;
    
    if (!workers) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02911) 
                      "workers not initialized");
        return APR_EGENERAL;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "h2_conn_process start");
    
    if (!s && r) {
        s = r->server;
    }
    
    config = s? h2_config_sget(s) : h2_config_get(c);
    if (r) {
        session = h2_session_rcreate(r, config, workers);
    }
    else {
        session = h2_session_create(c, config, workers);
    }
    
    if (!h2_is_acceptable_connection(c, 1)) {
        nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 0,
                              NGHTTP2_INADEQUATE_SECURITY, NULL, 0);
    } 

    ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);
    status = h2_session_start(session, &rv);
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                  "h2_session(%ld): starting on %s:%d", session->id,
                  session->c->base_server->server_hostname,
                  session->c->local_addr->port);
    if (status != APR_SUCCESS) {
        h2_session_abort(session, status, rv);
        h2_session_eoc_callback(session);
        return status;
    }
    
    status = h2_session_process(session);

    ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, session->c,
                  "h2_session(%ld): done", session->id);
    /* Make sure this connection gets closed properly. */
    ap_update_child_status_from_conn(c->sbh, SERVER_CLOSING, c);
    c->keepalive = AP_CONN_CLOSE;
    if (c->cs) {
        c->cs->state = CONN_STATE_WRITE_COMPLETION;
    }

    h2_session_close(session);
    /* hereafter session will be gone */
    return status;
}


static void fix_event_conn(conn_rec *c, conn_rec *master);

conn_rec *h2_conn_create(conn_rec *master, apr_pool_t *pool)
{
    conn_rec *c;
    
    AP_DEBUG_ASSERT(master);

    /* This is like the slave connection creation from 2.5-DEV. A
     * very efficient way - not sure how compatible this is, since
     * the core hooks are no longer run.
     * But maybe it's is better this way, not sure yet.
     */
    c = (conn_rec *) apr_palloc(pool, sizeof(conn_rec));
    if (c == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, pool, 
                      APLOGNO(02913) "h2_task: creating conn");
        return NULL;
    }
    
    memcpy(c, master, sizeof(conn_rec));
    c->id = (master->id & (long)pool);
    c->master = master;
    c->input_filters = NULL;
    c->output_filters = NULL;
    c->pool = pool;        
    return c;
}

apr_status_t h2_conn_setup(h2_task *task, apr_bucket_alloc_t *bucket_alloc,
                           apr_thread_t *thread, apr_socket_t *socket)
{
    conn_rec *master = task->mplx->c;
    
    ap_log_perror(APLOG_MARK, APLOG_TRACE3, 0, task->pool,
                  "h2_conn(%ld): created from master", master->id);
    
    /* Ok, we are just about to start processing the connection and
     * the worker is calling us to setup all necessary resources.
     * We can borrow some from the worker itself and some we do as
     * sub-resources from it, so that we get a nice reuse of
     * pools.
     */
    task->c->pool = task->pool;
    task->c->current_thread = thread;
    task->c->bucket_alloc = bucket_alloc;
    
    task->c->conn_config = ap_create_conn_config(task->pool);
    task->c->notes = apr_table_make(task->pool, 5);
    
    /* In order to do this in 2.4.x, we need to add a member to conn_rec */
    task->c->master = master;
    
    ap_set_module_config(task->c->conn_config, &core_module, socket);
    
    /* This works for mpm_worker so far. Other mpm modules have 
     * different needs, unfortunately. The most interesting one 
     * being mpm_event...
     */
    switch (h2_conn_mpm_type()) {
        case H2_MPM_WORKER:
            /* all fine */
            break;
        case H2_MPM_EVENT: 
            fix_event_conn(task->c, master);
            break;
        default:
            /* fingers crossed */
            break;
    }
    
    /* TODO: we simulate that we had already a request on this connection.
     * This keeps the mod_ssl SNI vs. Host name matcher from answering 
     * 400 Bad Request
     * when names do not match. We prefer a predictable 421 status.
     */
    task->c->keepalives = 1;
    
    return APR_SUCCESS;
}

/* This is an internal mpm event.c struct which is disguised
 * as a conn_state_t so that mpm_event can have special connection
 * state information without changing the struct seen on the outside.
 *
 * For our task connections we need to create a new beast of this type
 * and fill it with enough meaningful things that mpm_event reads and
 * starts processing out task request.
 */
typedef struct event_conn_state_t event_conn_state_t;
struct event_conn_state_t {
    /** APR_RING of expiration timeouts */
    APR_RING_ENTRY(event_conn_state_t) timeout_list;
    /** the expiration time of the next keepalive timeout */
    apr_time_t expiration_time;
    /** connection record this struct refers to */
    conn_rec *c;
    /** request record (if any) this struct refers to */
    request_rec *r;
    /** is the current conn_rec suspended?  (disassociated with
     * a particular MPM thread; for suspend_/resume_connection
     * hooks)
     */
    int suspended;
    /** memory pool to allocate from */
    apr_pool_t *p;
    /** bucket allocator */
    apr_bucket_alloc_t *bucket_alloc;
    /** poll file descriptor information */
    apr_pollfd_t pfd;
    /** public parts of the connection state */
    conn_state_t pub;
};
APR_RING_HEAD(timeout_head_t, event_conn_state_t);

static void fix_event_conn(conn_rec *c, conn_rec *master) 
{
    event_conn_state_t *master_cs = ap_get_module_config(master->conn_config, 
                                                         h2_conn_mpm_module());
    event_conn_state_t *cs = apr_pcalloc(c->pool, sizeof(event_conn_state_t));
    cs->bucket_alloc = apr_bucket_alloc_create(c->pool);
    
    ap_set_module_config(c->conn_config, h2_conn_mpm_module(), cs);
    
    cs->c = c;
    cs->r = NULL;
    cs->p = master_cs->p;
    cs->pfd = master_cs->pfd;
    cs->pub = master_cs->pub;
    cs->pub.state = CONN_STATE_READ_REQUEST_LINE;
    
    c->cs = &(cs->pub);
}

