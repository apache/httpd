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
 
#include <assert.h>
#include <apr_strings.h>

#include <ap_mpm.h>
#include <ap_mmn.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>

#include <mpm_common.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_filter.h"
#include "h2_mplx.h"
#include "h2_session.h"
#include "h2_h2.h"
#include "h2_task.h"
#include "h2_workers.h"
#include "h2_conn.h"
#include "h2_version.h"

static struct h2_workers *workers;

static h2_mpm_type_t mpm_type = H2_MPM_UNKNOWN;
static module *mpm_module;
static int async_mpm;
static int mpm_supported = 1;
static apr_socket_t *dummy_socket;

static void check_modules(int force) 
{
    static int checked = 0;
    int i;

    if (force || !checked) {
        for (i = 0; ap_loaded_modules[i]; ++i) {
            module *m = ap_loaded_modules[i];
            
            if (!strcmp("event.c", m->name)) {
                mpm_type = H2_MPM_EVENT;
                mpm_module = m;
                break;
            }
            else if (!strcmp("motorz.c", m->name)) {
                mpm_type = H2_MPM_MOTORZ;
                mpm_module = m;
                break;
            }
            else if (!strcmp("mpm_netware.c", m->name)) {
                mpm_type = H2_MPM_NETWARE;
                mpm_module = m;
                break;
            }
            else if (!strcmp("prefork.c", m->name)) {
                mpm_type = H2_MPM_PREFORK;
                mpm_module = m;
                /* While http2 can work really well on prefork, it collides
                 * today's use case for prefork: runnning single-thread app engines
                 * like php. If we restrict h2_workers to 1 per process, php will
                 * work fine, but browser will be limited to 1 active request at a
                 * time. */
                mpm_supported = 0;
                break;
            }
            else if (!strcmp("simple_api.c", m->name)) {
                mpm_type = H2_MPM_SIMPLE;
                mpm_module = m;
                mpm_supported = 0;
                break;
            }
            else if (!strcmp("mpm_winnt.c", m->name)) {
                mpm_type = H2_MPM_WINNT;
                mpm_module = m;
                break;
            }
            else if (!strcmp("worker.c", m->name)) {
                mpm_type = H2_MPM_WORKER;
                mpm_module = m;
                break;
            }
        }
        checked = 1;
    }
}

apr_status_t h2_conn_child_init(apr_pool_t *pool, server_rec *s)
{
    apr_status_t status = APR_SUCCESS;
    int minw, maxw;
    int max_threads_per_child = 0;
    int idle_secs = 0;

    check_modules(1);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads_per_child);
    
    status = ap_mpm_query(AP_MPMQ_IS_ASYNC, &async_mpm);
    if (status != APR_SUCCESS) {
        /* some MPMs do not implemnent this */
        async_mpm = 0;
        status = APR_SUCCESS;
    }

    h2_config_init(pool);
    
    h2_get_num_workers(s, &minw, &maxw);
    
    idle_secs = h2_config_sgeti(s, H2_CONF_MAX_WORKER_IDLE_SECS);
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                 "h2_workers: min=%d max=%d, mthrpchild=%d, idle_secs=%d", 
                 minw, maxw, max_threads_per_child, idle_secs);
    workers = h2_workers_create(s, pool, minw, maxw, idle_secs);
 
    ap_register_input_filter("H2_IN", h2_filter_core_input,
                             NULL, AP_FTYPE_CONNECTION);
   
    status = h2_mplx_child_init(pool, s);

    if (status == APR_SUCCESS) {
        status = apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM,
                                   APR_PROTO_TCP, pool);
    }

    return status;
}

h2_mpm_type_t h2_conn_mpm_type(void)
{
    check_modules(0);
    return mpm_type;
}

const char *h2_conn_mpm_name(void)
{
    check_modules(0);
    return mpm_module? mpm_module->name : "unknown";
}

int h2_mpm_supported(void)
{
    check_modules(0);
    return mpm_supported;
}

static module *h2_conn_mpm_module(void)
{
    check_modules(0);
    return mpm_module;
}

apr_status_t h2_conn_setup(conn_rec *c, request_rec *r, server_rec *s)
{
    h2_session *session;
    h2_ctx *ctx;
    apr_status_t status;
    
    if (!workers) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02911) 
                      "workers not initialized");
        return APR_EGENERAL;
    }
    
    if (APR_SUCCESS == (status = h2_session_create(&session, c, r, s, workers))) {
        ctx = h2_ctx_get(c, 1);
        h2_ctx_session_set(ctx, session);
    }
    
    return status;
}

apr_status_t h2_conn_run(conn_rec *c)
{
    apr_status_t status;
    int mpm_state = 0;
    h2_session *session = h2_ctx_get_session(c);
    
    ap_assert(session);
    do {
        if (c->cs) {
            c->cs->sense = CONN_SENSE_DEFAULT;
            c->cs->state = CONN_STATE_HANDLER;
        }
    
        status = h2_session_process(session, async_mpm);
        
        if (APR_STATUS_IS_EOF(status)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c, 
                          H2_SSSN_LOG(APLOGNO(03045), session, 
                          "process, closing conn"));
            c->keepalive = AP_CONN_CLOSE;
        }
        else {
            c->keepalive = AP_CONN_KEEPALIVE;
        }
        
        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
            break;
        }
    } while (!async_mpm
             && c->keepalive == AP_CONN_KEEPALIVE 
             && mpm_state != AP_MPMQ_STOPPING);

    if (c->cs) {
        switch (session->state) {
            case H2_SESSION_ST_INIT:
            case H2_SESSION_ST_IDLE:
            case H2_SESSION_ST_BUSY:
            case H2_SESSION_ST_WAIT:
                c->cs->state = CONN_STATE_WRITE_COMPLETION;
                break;
            case H2_SESSION_ST_CLEANUP:
            case H2_SESSION_ST_DONE:
            default:
                c->cs->state = CONN_STATE_LINGER;
            break;
        }
    }

    return APR_SUCCESS;
}

apr_status_t h2_conn_pre_close(struct h2_ctx *ctx, conn_rec *c)
{
    h2_session *session = h2_ctx_get_session(c);
    
    (void)c;
    if (session) {
        apr_status_t status = h2_session_pre_close(session, async_mpm);
        return (status == APR_SUCCESS)? DONE : status;
    }
    return DONE;
}

/* APR callback invoked if allocation fails. */
static int abort_on_oom(int retcode)
{
    ap_abort_on_oom();
    return retcode; /* unreachable, hopefully. */
}

conn_rec *h2_slave_create(conn_rec *master, int slave_id, apr_pool_t *parent)
{
    apr_allocator_t *allocator;
    apr_status_t status;
    apr_pool_t *pool;
    conn_rec *c;
    void *cfg;
    module *mpm;
    
    ap_assert(master);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, master,
                  "h2_stream(%ld-%d): create slave", master->id, slave_id);
    
    /* We create a pool with its own allocator to be used for
     * processing a request. This is the only way to have the processing
     * independant of its parent pool in the sense that it can work in
     * another thread. Also, the new allocator needs its own mutex to
     * synchronize sub-pools.
     */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    status = apr_pool_create_ex(&pool, parent, NULL, allocator);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, master, 
                      APLOGNO(10004) "h2_session(%ld-%d): create slave pool",
                      master->id, slave_id);
        return NULL;
    }
    apr_allocator_owner_set(allocator, pool);
    apr_pool_abort_set(abort_on_oom, pool);
    apr_pool_tag(pool, "h2_slave_conn");

    c = (conn_rec *) apr_palloc(pool, sizeof(conn_rec));
    if (c == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, master, 
                      APLOGNO(02913) "h2_session(%ld-%d): create slave",
                      master->id, slave_id);
        apr_pool_destroy(pool);
        return NULL;
    }
    
    memcpy(c, master, sizeof(conn_rec));
        
    c->master                 = master;
    c->pool                   = pool;   
    c->conn_config            = ap_create_conn_config(pool);
    c->notes                  = apr_table_make(pool, 5);
    c->input_filters          = NULL;
    c->output_filters         = NULL;
    c->keepalives             = 0;
#if AP_MODULE_MAGIC_AT_LEAST(20180903, 1)
    c->filter_conn_ctx        = NULL;
#endif
    c->bucket_alloc           = apr_bucket_alloc_create(pool);
#if !AP_MODULE_MAGIC_AT_LEAST(20180720, 1)
    c->data_in_input_filters  = 0;
    c->data_in_output_filters = 0;
#endif
    /* prevent mpm_event from making wrong assumptions about this connection,
     * like e.g. using its socket for an async read check. */
    c->clogging_input_filters = 1;
    c->log                    = NULL;
    c->log_id                 = apr_psprintf(pool, "%ld-%d", 
                                             master->id, slave_id);
    c->aborted                = 0;
    /* We cannot install the master connection socket on the slaves, as
     * modules mess with timeouts/blocking of the socket, with
     * unwanted side effects to the master connection processing.
     * Fortunately, since we never use the slave socket, we can just install
     * a single, process-wide dummy and everyone is happy.
     */
    ap_set_module_config(c->conn_config, &core_module, dummy_socket);
    /* TODO: these should be unique to this thread */
    c->sbh                    = master->sbh;
    /* TODO: not all mpm modules have learned about slave connections yet.
     * copy their config from master to slave.
     */
    if ((mpm = h2_conn_mpm_module()) != NULL) {
        cfg = ap_get_module_config(master->conn_config, mpm);
        ap_set_module_config(c->conn_config, mpm, cfg);
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c, 
                  "h2_slave(%s): created", c->log_id);
    return c;
}

void h2_slave_destroy(conn_rec *slave)
{
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, slave, "h2_slave(%s): destroy", slave->log_id);
    slave->sbh = NULL;
    apr_pool_destroy(slave->pool);
}

apr_status_t h2_slave_run_pre_connection(conn_rec *slave, apr_socket_t *csd)
{
    if (slave->keepalives == 0) {
        /* Simulate that we had already a request on this connection. Some
         * hooks trigger special behaviour when keepalives is 0. 
         * (Not necessarily in pre_connection, but later. Set it here, so it
         * is in place.) */
        slave->keepalives = 1;
        /* We signal that this connection will be closed after the request.
         * Which is true in that sense that we throw away all traffic data
         * on this slave connection after each requests. Although we might
         * reuse internal structures like memory pools.
         * The wanted effect of this is that httpd does not try to clean up
         * any dangling data on this connection when a request is done. Which
         * is unneccessary on a h2 stream.
         */
        slave->keepalive = AP_CONN_CLOSE;
        return ap_run_pre_connection(slave, csd);
    }
    ap_assert(slave->output_filters);
    return APR_SUCCESS;
}

