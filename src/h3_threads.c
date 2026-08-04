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

#include "h3_io.h"
#include "h3_session.h"
#include "h3_threads.h"
#include "mod_http3.h"
#include "quic/h3q.h"
#include "quic/h3q_conn.h"

void* APR_THREAD_FUNC h3_event_thread(apr_thread_t* thread, void* data)
{
    (void)thread;
    h3_io_t* io = data;
    if (!io)
    {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "h3_event_thread: NULL io");
        return NULL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "event thread started");
    int work_pending = 0;
    while (io->thread_running || io->active_sessions->nelts > 0)
    {
        if (!work_pending)
        {
            wait_for_event(io);
        }
        work_pending = 0;
        if (h3q_engine_pump(io->qengine))
        {
            work_pending = 1;
        }

        if (io->thread_running)
        {
            for (;;)
            {
                h3q_conn* conn = h3q_engine_accept_conn(io->qengine);
                if (!conn)
                {
                    break;
                }
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "accepted new QUIC connection");
                if (h3_io_at_connection_limit(io))
                {
                    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, io->server, "dropping QUIC connection: at H3MaxConnections limit (%u)", conf->h3_max_connections);
                    h3q_conn_free(conn);
                    continue;
                }
                if (!prepare_accepted_connection(io, conn))
                {
                    h3q_conn_free(conn);
                }
            }
            progress_pending_handshakes(io);
        }

        for (int i = 0; i < io->active_sessions->nelts; )
        {
            h3_session* session = ((h3_session**)io->active_sessions->elts)[i];
            if (service_session_pass(io, session))
            {
                work_pending = 1;
            }

            if (session->aborted)
            {
                int is_rapid = (!io->thread_running);
                int shutdown_done = h3q_conn_shutdown(session->qconn, is_rapid, session->abort_quic_error_code, session->ngh3_dead ? session->abort_reason : NULL);

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
                    continue; /* Do not increment i: the last element was swapped into this slot. */
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
