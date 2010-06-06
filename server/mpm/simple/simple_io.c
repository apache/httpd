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

#include "httpd.h"
#include "http_log.h"
#include "ap_listen.h"
#include "simple_types.h"
#include "simple_io.h"
#include "simple_event.h"

#include "http_connection.h"
#include "util_filter.h"
#include "http_main.h"
#include "scoreboard.h"
#include "http_vhost.h"

APLOG_USE_MODULE(mpm_simple);

static void simple_io_timeout_cb(simple_core_t * sc, void *baton)
{
    simple_conn_t *scon = (simple_conn_t *) baton;
    /* pqXXXXX: handle timeouts. */
    conn_rec *c = scon->c;
    conn_state_t *cs = c->cs;

    cs = NULL;

    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf,
                 "io timeout hit (?)");
}

static apr_status_t simple_io_process(simple_conn_t * scon)
{
    apr_status_t rv;
    simple_core_t *sc;
    conn_rec *c;
    conn_state_t *cs;

    if (scon->c->clogging_input_filters && !scon->c->aborted) {
        /* Since we have an input filter which 'cloggs' the input stream,
         * like mod_ssl, lets just do the normal read from input filters,
         * like the Worker MPM does.
         */
        ap_run_process_connection(scon->c);
        if (scon->c->cs->state != CONN_STATE_SUSPENDED) {
            scon->c->cs->state = CONN_STATE_LINGER;
        }
    }

    sc = scon->sc;
    c = scon->c;
    cs = c->cs;

    while (!c->aborted) {

        if (cs->pfd.reqevents != 0) {
            rv = apr_pollcb_remove(sc->pollcb, &cs->pfd);
            if (rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                             "simple_io_process: apr_pollcb_remove failure");
                /*AP_DEBUG_ASSERT(rv == APR_SUCCESS);*/
            }
            cs->pfd.reqevents = 0;
        }

        if (cs->state == CONN_STATE_READ_REQUEST_LINE) {
            if (!c->aborted) {
                ap_run_process_connection(c);
                /* state will be updated upon return
                 * fall thru to either wait for readability/timeout or
                 * do lingering close
                 */
            }
            else {
                cs->state = CONN_STATE_LINGER;
            }
        }

        if (cs->state == CONN_STATE_WRITE_COMPLETION) {
            ap_filter_t *output_filter = c->output_filters;
            while (output_filter->next != NULL) {
                output_filter = output_filter->next;
            }

            rv = output_filter->frec->filter_func.out_func(output_filter,
                                                           NULL);

            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                             "network write failure in core output filter");
                cs->state = CONN_STATE_LINGER;
            }
            else if (c->data_in_output_filters) {
                /* Still in WRITE_COMPLETION_STATE:
                 * Set a write timeout for this connection, and let the
                 * event thread poll for writeability.
                 */

                simple_register_timer(scon->sc,
                                      simple_io_timeout_cb,
                                      scon,
                                      scon->c->base_server !=
                                      NULL ? scon->c->base_server->
                                      timeout : ap_server_conf->timeout,
                                      scon->pool);

                cs->pfd.reqevents = APR_POLLOUT | APR_POLLHUP | APR_POLLERR;

                rv = apr_pollcb_add(sc->pollcb, &cs->pfd);

                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                                 ap_server_conf,
                                 "apr_pollcb_add: failed in write completion");
                    AP_DEBUG_ASSERT(rv == APR_SUCCESS);
                }
                return APR_SUCCESS;
            }
            else if (c->keepalive != AP_CONN_KEEPALIVE || c->aborted) {
                c->cs->state = CONN_STATE_LINGER;
            }
            else if (c->data_in_input_filters) {
                cs->state = CONN_STATE_READ_REQUEST_LINE;
            }
            else {
                cs->state = CONN_STATE_CHECK_REQUEST_LINE_READABLE;
            }
        }

        if (cs->state == CONN_STATE_LINGER) {
            ap_lingering_close(c);
            apr_pool_destroy(scon->pool);
            return APR_SUCCESS;
        }

        if (cs->state == CONN_STATE_CHECK_REQUEST_LINE_READABLE) {
            simple_register_timer(scon->sc,
                                  simple_io_timeout_cb,
                                  scon,
                                  scon->c->base_server !=
                                  NULL ? scon->c->base_server->
                                  timeout : ap_server_conf->timeout,
                                  scon->pool);

            cs->pfd.reqevents = APR_POLLIN;

            rv = apr_pollcb_add(sc->pollcb, &cs->pfd);

            if (rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                             "process_socket: apr_pollcb_add failure in read request line");
                AP_DEBUG_ASSERT(rv == APR_SUCCESS);
            }

            return APR_SUCCESS;
        }
    }

    ap_lingering_close(c);
    apr_pool_destroy(scon->pool);
    return APR_SUCCESS;
}

static void *simple_io_invoke(apr_thread_t * thread, void *baton)
{
    simple_sb_t *sb = (simple_sb_t *) baton;
    simple_conn_t *scon = (simple_conn_t *) sb->baton;
    apr_status_t rv;

    scon->c->current_thread = thread;

    rv = simple_io_process(scon);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf,
                     "simple_io_invoke: simple_io_process failed (?)");
    }

    return NULL;
}

static void *simple_io_setup_conn(apr_thread_t * thread, void *baton)
{
    apr_status_t rv;
    ap_sb_handle_t *sbh;
    conn_state_t *cs;
    long conn_id = 0;
    simple_sb_t *sb;
    simple_conn_t *scon = (simple_conn_t *) baton;

    /* pqXXXXX: remove this. */
    ap_create_sb_handle(&sbh, scon->pool, 0, 0);

    scon->ba = apr_bucket_alloc_create(scon->pool);

    scon->c = ap_run_create_connection(scon->pool, ap_server_conf, scon->sock,
                                       conn_id, sbh, scon->ba);

    scon->c->cs = apr_pcalloc(scon->pool, sizeof(conn_state_t));
    cs = scon->c->cs;
    sb = apr_pcalloc(scon->pool, sizeof(simple_sb_t));

    scon->c->current_thread = thread;

    cs->pfd.p = scon->pool;
    cs->pfd.desc_type = APR_POLL_SOCKET;
    cs->pfd.desc.s = scon->sock;
    cs->pfd.reqevents = APR_POLLIN;

    sb->type = SIMPLE_PT_CORE_IO;
    sb->baton = scon;
    cs->pfd.client_data = sb;

    ap_update_vhost_given_ip(scon->c);

    rv = ap_run_pre_connection(scon->c, scon->sock);
    if (rv != OK && rv != DONE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "simple_io_setup_conn: connection aborted");
        scon->c->aborted = 1;
    }

    scon->c->cs->state = CONN_STATE_READ_REQUEST_LINE;

    rv = simple_io_process(scon);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ap_server_conf,
                     "simple_io_setup_conn: simple_io_process failed (?)");
    }

    return NULL;
}

apr_status_t simple_io_accept(simple_core_t * sc, simple_sb_t * sb)
{
    apr_status_t rv;
    apr_pool_t *ptrans;
    apr_socket_t *socket;
    ap_listen_rec *lr = (ap_listen_rec *) sb->baton;

    /* pqXXXXXX: Consider doing pool recycling like the event/worker MPMs do. */
    apr_pool_create(&ptrans, NULL);

    apr_pool_tag(ptrans, "transaction");

    rv = apr_socket_accept(&socket, lr->sd, ptrans);
    if (rv) {
        /* pqXXXXXX: unixd.c has _tons_ of custom handling on return values
         * from accept, but it seems really crazy, it either worked, or didn't, 
         * but taking this approach of swallowing the error it is possible we have a 
         * fatal error on our listening socket, but we don't notice.  
         * 
         * Need to discuss this on dev@
         */
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "simple_io_accept: apr_socket_accept failed");
        return APR_SUCCESS;
    }
    else {
        simple_conn_t *scon = apr_pcalloc(ptrans, sizeof(simple_conn_t));
        scon->pool = ptrans;
        scon->sock = socket;
        scon->sc = sc;

        return apr_thread_pool_push(sc->workers,
                                    simple_io_setup_conn,
                                    scon,
                                    APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
    }

    return APR_SUCCESS;
}

apr_status_t simple_io_event_process(simple_core_t * sc, simple_sb_t * sb)
{
    /* pqXXXXX: In theory, if we have non-blocking operations on the connection
     *  we can do them here, before pushing to another thread, thats just
     * not implemented right now.
     */
    return apr_thread_pool_push(sc->workers,
                                simple_io_invoke,
                                sb, APR_THREAD_TASK_PRIORITY_NORMAL, NULL);
}
