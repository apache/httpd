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
#include "h2_task.h"
#include "h2_worker.h"
#include "h2_workers.h"
#include "h2_conn.h"

static struct h2_workers *workers;

static apr_status_t h2_session_process(h2_session *session);

static h2_mpm_type_t mpm_type = H2_MPM_UNKNOWN;
static module *mpm_module;
static module *ssl_module;
static int checked;

static void check_modules() 
{
    if (!checked) {
        for (int i = 0; ap_loaded_modules[i]; ++i) {
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
            else if (!strcmp("mod_ssl.c", m->name)) {
                ssl_module = m;
            }
        }
        checked = 1;
    }
}

apr_status_t h2_conn_child_init(apr_pool_t *pool, server_rec *s)
{
    h2_config *config = h2_config_sget(s);
    apr_status_t status = APR_SUCCESS;
    int minw = h2_config_geti(config, H2_CONF_MIN_WORKERS);
    int maxw = h2_config_geti(config, H2_CONF_MAX_WORKERS);
    
    int max_threads_per_child = 0;
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads_per_child);
    int threads_limit = 0;
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &threads_limit);
    
    if (minw <= 0) {
        minw = max_threads_per_child;
    }
    if (maxw <= 0) {
        maxw = threads_limit;
        if (maxw < minw) {
            maxw = minw;
        }
    }
    
    for (int i = 0; ap_loaded_modules[i]; ++i) {
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
            /* prefork reports 1 thread per child, also as max */
            if (maxw == 1) {
                maxw = 8; /* number of cores maybe? */
            }
        }
        else if (!strcmp("mod_ssl.c", m->name)) {
            ssl_module = m;
        }
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "h2_workers: min=%d max=%d, mthrpchild=%d, thr_limit=%d", 
                 minw, maxw, max_threads_per_child, threads_limit);
    
    workers = h2_workers_create(s, pool, minw, maxw);
    int idle_secs = h2_config_geti(config, H2_CONF_MAX_WORKER_IDLE_SECS);
    h2_workers_set_max_idle_secs(workers, idle_secs);
    
    return status;
}

h2_mpm_type_t h2_conn_mpm_type(void) {
    check_modules();
    return mpm_type;
}

module *h2_conn_mpm_module(void) {
    check_modules();
    return mpm_module;
}

apr_status_t h2_conn_rprocess(request_rec *r)
{
    h2_config *config = h2_config_rget(r);
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "h2_conn_process start");
    if (!workers) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "workers not initialized");
        return APR_EGENERAL;
    }
    
    h2_session *session = h2_session_rcreate(r, config, workers);
    if (!session) {
        return APR_EGENERAL;
    }
    
    return h2_session_process(session);
}

apr_status_t h2_conn_main(conn_rec *c)
{
    h2_config *config = h2_config_get(c);
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "h2_conn_main start");
    if (!workers) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "workers not initialized");
        return APR_EGENERAL;
    }
    
    h2_session *session = h2_session_create(c, config, workers);
    if (!session) {
        return APR_EGENERAL;
    }
    
    return h2_session_process(session);
}

apr_status_t h2_session_process(h2_session *session)
{
    apr_status_t status = APR_SUCCESS;
    int rv = 0;
    
    /* Start talking to the client. Apart from protocol meta data,
     * we mainly will see new http/2 streams opened by the client, which
     * basically are http requests we need to dispatch.
     *
     * There will be bursts of new streams, to be served concurrently,
     * followed by long pauses of no activity.
     *
     * Since the purpose of http/2 is to allow siumultaneous streams, we
     * need to dispatch the handling of each stream into a separate worker
     * thread, keeping this thread open for sending responses back as
     * soon as they arrive.
     * At the same time, we need to continue reading new frames from
     * our client, which may be meta (WINDOWS_UPDATEs, PING, SETTINGS) or
     * new streams.
     *
     * As long as we have streams open in this session, we cannot really rest
     * since there are two conditions to wait on: 1. new data from the client,
     * 2. new data from the open streams to send back.
     *
     * Only when we have no more streams open, can we do a blocking read
     * on our connection.
     *
     * TODO: implement graceful GO_AWAY after configurable idle time
     */
    
    ap_update_child_status_from_conn(session->c->sbh, SERVER_BUSY_READ, 
                                     session->c);

    if (APLOGctrace2(session->c)) {
        ap_filter_t *filter = session->c->input_filters;
        while (filter) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c,
                          "h2_conn(%ld), has connection filter %s",
                          session->id, filter->frec->name);
            filter = filter->next;
        }
    }
    
    status = h2_session_start(session, &rv);
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c,
                  "h2_session(%ld): starting on %s:%d", session->id,
                  session->c->base_server->defn_name,
                  session->c->local_addr->port);
    if (status != APR_SUCCESS) {
        h2_session_abort(session, status, rv);
        h2_session_destroy(session);
        return status;
    }
    
    apr_interval_time_t wait_micros = 0;
    static const int MAX_WAIT_MICROS = 200 * 1000;
    
    while (!h2_session_is_done(session)) {
        int have_written = 0;
        int have_read = 0;
        
        status = h2_session_write(session, wait_micros);
        if (status == APR_SUCCESS) {
            have_written = 1;
            wait_micros = 0;
        }
        else if (status == APR_EAGAIN) {
            /* nop */
        }
        else if (status == APR_TIMEUP) {
            wait_micros *= 2;
            if (wait_micros > MAX_WAIT_MICROS) {
                wait_micros = MAX_WAIT_MICROS;
            }
        }
        else {
            ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, session->c,
                          "h2_session(%ld): writing, terminating",
                          session->id);
            h2_session_abort(session, status, 0);
            break;
        }
        
        /* We would like to do blocking reads as often as possible as they
         * are more efficient in regard to server resources.
         * We can do them under the following circumstances:
         * - we have no open streams and therefore have nothing to write
         * - we have just started the session and are waiting for the first
         *   two frames to come in. There will always be at least 2 frames as
         *   * h2 will send SETTINGS and SETTINGS-ACK
         *   * h2c will count the header settings as one frame and we
         *     submit our settings and need the ACK.
         */
        int got_streams = !h2_stream_set_is_empty(session->streams);
        status = h2_session_read(session, 
                                 (!got_streams 
                                  || session->frames_received <= 1)?
                                 APR_BLOCK_READ : APR_NONBLOCK_READ);
        switch (status) {
            case APR_SUCCESS:
                /* successful read, reset our idle timers */
                have_read = 1;
                wait_micros = 0;
                break;
            case APR_EAGAIN:
                break;
            case APR_EBADF:
            case APR_EOF:
            case APR_ECONNABORTED:
            case ECONNRESET:
                ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, session->c,
                              "h2_session(%ld): reading",
                              session->id);
                h2_session_abort(session, status, 0);
                break;
            default:
                ap_log_cerror( APLOG_MARK, APLOG_WARNING, status, session->c,
                              "h2_session(%ld): error reading, terminating",
                              session->id);
                h2_session_abort(session, status, 0);
                break;
        }
        
        if (!have_read && !have_written) {
            /* Nothing to read or write, we may have sessions, but
             * the have no data yet ready to be delivered. Slowly
             * back off to give others a chance to do their work.
             */
            if (wait_micros == 0) {
                wait_micros = 10;
            }
        }
    }
    
    ap_log_cerror( APLOG_MARK, APLOG_DEBUG, status, session->c,
                  "h2_session(%ld): done", session->id);
    
    ap_update_child_status_from_conn(session->c->sbh, SERVER_CLOSING, 
                                     session->c);

    h2_session_close(session);
    h2_session_destroy(session);
    
    return DONE;
}


static void fix_event_conn(conn_rec *c, conn_rec *master);

conn_rec *h2_conn_create(conn_rec *master, apr_pool_t *pool)
{
    apr_socket_t *socket;
    
    AP_DEBUG_ASSERT(master);
    
    /* CAVEAT: it seems necessary to setup the conn_rec in the master
     * connection thread. Other attempts crashed. 
     * HOWEVER: we setup the connection using the pools and other items
     * from the master connection, since we do not want to allocate 
     * lots of resources here. 
     * Lets allocated pools and everything else when we actually start
     * working on this new connection.
     */
    /* Not sure about the scoreboard handle. Reusing the one from the main
     * connection could make sense, is not really correct, but we cannot
     * easily create new handles for our worker threads either.
     * TODO
     */
    socket = ap_get_module_config(master->conn_config, &core_module);
    conn_rec *c = ap_run_create_connection(pool, master->base_server,
                                           socket,
                                           master->id^((long)pool), 
                                           master->sbh,
                                           master->bucket_alloc);
    if (c == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, pool,
                      "h2_task: creating conn");
        return NULL;
    }
    return c;
}

apr_status_t h2_conn_prep(h2_task_env *env, conn_rec *master, h2_worker *worker)
{
    h2_config *cfg = h2_config_get(master);
    
    ap_log_perror(APLOG_MARK, APLOG_TRACE3, 0, env->pool,
                  "h2_conn(%ld): created from master", master->id);
    
    /* Ok, we are just about to start processing the connection and
     * the worker is calling us to setup all necessary resources.
     * We can borrow some from the worker itself and some we do as
     * sub-resources from it, so that we get a nice reuse of
     * pools.
     */
    env->c.pool = env->pool;
    env->c.bucket_alloc = h2_worker_get_bucket_alloc(worker);
    env->c.current_thread = h2_worker_get_thread(worker);
    
    env->c.conn_config = ap_create_conn_config(env->pool);
    env->c.notes = apr_table_make(env->pool, 5);

    ap_set_module_config(env->c.conn_config, &core_module, 
                         h2_worker_get_socket(worker));
    
    if (ssl_module) {
        /* See #19, there is a range of SSL variables to be gotten from
         * the main connection that should be available in request handlers
         */
        void *sslcfg = ap_get_module_config(master->conn_config, ssl_module);
        if (sslcfg) {
            ap_set_module_config(env->c.conn_config, ssl_module, sslcfg);
        }
    }
    
    /* This works for mpm_worker so far. Other mpm modules have 
     * different needs, unfortunately. The most interesting one 
     * being mpm_event...
     */
    switch (h2_conn_mpm_type()) {
        case H2_MPM_WORKER:
            /* all fine */
            break;
        case H2_MPM_EVENT: 
            if (h2_config_geti(cfg, H2_CONF_HACK_MPM_EVENT)) {
                fix_event_conn(&env->c, master);
            }
            break;
        default:
            /* fingers crossed */
            break;
    }
    
    return APR_SUCCESS;
}

apr_status_t h2_conn_setup(struct h2_task_env *env, struct h2_worker *worker)
{
    return h2_conn_prep(env, env->mplx->c, worker);
}

apr_status_t h2_conn_init(struct h2_task_env *env, struct h2_worker *worker)
{
    conn_rec *master = env->mplx->c;
    h2_config *cfg = h2_config_get(master);
    
    apr_socket_t *socket = ap_get_module_config(master->conn_config, 
                                                &core_module);
    conn_rec *c = ap_run_create_connection(env->pool, master->base_server,
                                           socket,
                                           master->id^((long)env->pool), 
                                           master->sbh,
                                           master->bucket_alloc);
    if (c == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, env->pool,
                      "h2_task: creating conn");
        return APR_ENOMEM;
    }
    
    env->c = *c;
    env->c.bucket_alloc = h2_worker_get_bucket_alloc(worker);
    env->c.current_thread = h2_worker_get_thread(worker);
    
    ap_set_module_config(env->c.conn_config, &core_module, socket);
    if (ssl_module) {
        /* See #19, there is a range of SSL variables to be gotten from
         * the main connection that should be available in request handlers
         */
        void *sslcfg = ap_get_module_config(master->conn_config, ssl_module);
        if (sslcfg) {
            ap_set_module_config(env->c.conn_config, ssl_module, sslcfg);
        }
    }
    
    /* This works for mpm_worker so far. Other mpm modules have 
     * different needs, unfortunately. The most interesting one 
     * being mpm_event...
     */
    switch (h2_conn_mpm_type()) {
        case H2_MPM_WORKER:
            /* all fine */
            break;
        case H2_MPM_EVENT: 
            if (h2_config_geti(cfg, H2_CONF_HACK_MPM_EVENT)) {
                fix_event_conn(&env->c, master);
            }
            break;
        default:
            /* fingers crossed */
            break;
    }
    
    return APR_SUCCESS;
}

apr_status_t h2_conn_post(conn_rec *c, h2_worker *worker)
{
    (void)worker;
    
    /* be sure no one messes with this any more */
    memset(c, 0, sizeof(*c)); 
    return APR_SUCCESS;
}

apr_status_t h2_conn_process(conn_rec *c, apr_socket_t *socket)
{
    AP_DEBUG_ASSERT(c);
    
    c->clogging_input_filters = 1;
    ap_process_connection(c, socket);
    
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

