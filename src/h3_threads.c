/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>

#include <http_config.h>
#include <http_log.h>

#include <apr_atomic.h>

#include <openssl/ssl.h>

#include "h3_io.h"
#include "h3_session.h"
#include "h3_threads.h"
#include "mod_http3.h"

void* APR_THREAD_FUNC quic_event_thread(apr_thread_t* thread, void* data)
{
    (void)thread;
    h3_io_t* io = data;
    if (!io)
    {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "quic_event_thread: NULL io");
        return NULL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "event thread started");
    while (io->thread_running || io->active_sessions->nelts > 0)
    {
        wait_for_event(io);
        SSL_handle_events(io->ssl_listener);

        if (io->thread_running)
        {
            for (;;)
            {
                SSL* conn = SSL_accept_connection(io->ssl_listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
                if (!conn)
                {
                    break;
                }
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "accepted new QUIC connection");
                if (h3_io_at_connection_limit(io))
                {
                    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, io->server, "dropping QUIC connection: at H3MaxConnections limit (%u)", conf->h3_max_connections);
                    SSL_free(conn);
                    continue;
                }
                if (!prepare_accepted_connection(io, conn))
                {
                    SSL_free(conn);
                }
            }
            progress_pending_handshakes(io);
        }

        for (int i = 0; i < io->active_sessions->nelts; )
        {
            h3_session* session = ((h3_session**)io->active_sessions->elts)[i];
            service_session_pass(io, session);

            if (session->aborted)
            {
                int shutdown_done = 0;
                int ret;
                uint64_t flags = (!io->thread_running) ? SSL_SHUTDOWN_FLAG_RAPID : 0;
                
                if (session->ngh3_dead)
                {
                    SSL_SHUTDOWN_EX_ARGS args = {.quic_error_code = session->abort_quic_error_code, .quic_reason = session->abort_reason};
                    ret = SSL_shutdown_ex(session->ssl_conn, flags, &args, sizeof(args));
                }
                else
                {
                    if (flags != 0)
                    {
                        SSL_SHUTDOWN_EX_ARGS args = {0};
                        ret = SSL_shutdown_ex(session->ssl_conn, flags, &args, sizeof(args));
                    }
                    else
                    {
                        ret = SSL_shutdown(session->ssl_conn);
                    }
                }

                if (ret == 1)
                {
                    shutdown_done = 1;
                    session->aborted = 1;
                }
                else if (ret < 0)
                {
                    int err = SSL_get_error(session->ssl_conn, ret);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    {
                        shutdown_done = 1;
                        session->aborted = 1;
                    }
                }

                if (shutdown_done && apr_atomic_read32(&session->active_tasks) == 0)
                {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "connection servicing done");
                    h3_session_destroy(session);
                    if (io->note_conn_removed)
                    {
                        io->note_conn_removed();
                    }
                    if (i < io->active_sessions->nelts - 1)
                    {
                        ((h3_session**)io->active_sessions->elts)[i] = ((h3_session**)io->active_sessions->elts)[io->active_sessions->nelts - 1];
                    }
                    io->active_sessions->nelts--;
                    apr_atomic_dec32(&io->active_session_count);
                    continue; /* Do not increment i, as we swapped the last element into this slot */
                }
            }
            i++;
        }
    }
    while (io->pending_handshakes->nelts > 0)
    {
        remove_pending_handshake(io, 0, 1);
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "event thread exiting");
    return NULL;
}
