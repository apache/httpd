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

#include "h3_threads.h"
#include "h3_io.h"
#include "mod_http3.h"
#include <apr_atomic.h>
#include <http_config.h>
#include <http_log.h>
#include <httpd.h>
#include <openssl/ssl.h>

void* APR_THREAD_FUNC worker_thread(apr_thread_t* thread, void* data)
{
    (void)thread;
    struct worker_args* args = data;
    if (!args)
    {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "worker_thread: NULL args");
        return NULL;
    }
    service_connection(args->io, args->session);
    apr_atomic_dec32(&args->io->live_workers);
    if (args->io->note_conn_removed)
    {
        args->io->note_conn_removed();
    }
    return NULL;
}

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
    while (io->thread_running)
    {
        wait_for_event(io->udp_fd, io->ssl_listener, 1);
        SSL_handle_events(io->ssl_listener);

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
    while (io->pending_handshakes->nelts > 0)
    {
        remove_pending_handshake(io, 0, 1);
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "event thread exiting");
    return NULL;
}
