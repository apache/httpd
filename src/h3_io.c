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

#include <apr_allocator.h>
#include <apr_atomic.h>
#include <apr_pools.h>
#include <apr_portable.h>
#include <apr_thread_pool.h>
#include <apr_thread_proc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_io.h"
#include "h3_os.h"
#include "h3_request.h"
#include "h3_session.h"
#include "h3_socket.h"
#include "h3_stream.h"
#include "h3_threads.h"
#include "h3_version.h"
#include "mod_http3.h"
#include "quic/h3q.h"
#include "quic/h3q_conn.h"
#include "quic/h3q_stream.h"

h3_io_t* child_h3_io = NULL;

int h3_io_at_connection_limit(h3_io_t* io)
{
    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
    apr_uint32_t active = (apr_uint32_t)io->active_sessions->nelts + (apr_uint32_t)io->pending_handshakes->nelts;
    return active >= conf->h3_max_connections;
}

static void teardown(h3_io_t* io)
{
    CHECK(io);
    if (io->event_thread)
    {
        io->thread_running = 0;
        h3_wakeup_signal(&io->wakeup);
        apr_status_t status;
        apr_thread_join(&status, io->event_thread);
        io->event_thread = NULL;
    }
    if (io->h3_worker_pool)
    {
        apr_thread_pool_destroy(io->h3_worker_pool);
        io->h3_worker_pool = NULL;
    }
    if (io->active_sessions)
    {
        apr_time_t next_warning = apr_time_now() + apr_time_from_sec(5);
        while (io->active_sessions->nelts > 0)
        {
            if (apr_time_now() >= next_warning)
            {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, io->server, "teardown waiting for %d connections to finish in-flight streams", io->active_sessions->nelts);
                next_warning = apr_time_now() + apr_time_from_sec(5);
            }
            apr_sleep(50 * 1000);
        }
    }
    if (io->qengine)
    {
        h3q_engine_destroy(io->qengine);
        io->qengine = NULL;
    }
    if (io->udp_fd >= 0)
    {
        h3_socket_close(io->udp_fd);
        io->udp_fd = -1;
    }
    /* Both wakeup sockets belong to the child pool and close with it. */
}

static apr_status_t listen_stop_cleanup(void* data)
{
    h3_io_t* io = data;
    if (io && io->draining)
    {
        h3_io_listen_stop(io);
    }
    return APR_SUCCESS;
}

apr_status_t h3_io_listen_start(apr_pool_t* pchild, server_rec* s, h3_server_conf* conf, int udp_fd)
{
    CHECK(pchild);
    CHECK(s);
    CHECK(conf);
    h3_io_t* io = apr_pcalloc(pchild, sizeof(*io));
    io->pool = pchild;
    io->server = s;
    io->udp_fd = udp_fd;
    io->active_sessions = apr_array_make(pchild, 8, sizeof(h3_session*));
    io->pending_handshakes = apr_array_make(pchild, 4, sizeof(h3_pending_handshake));
    if (h3_wakeup_create(pchild, &io->wakeup) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_wakeup_create failed");
        return APR_EGENERAL;
    }
    if (apr_thread_pool_create(&io->h3_worker_pool, 16, 64, pchild) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_thread_pool_create failed");
        return APR_EGENERAL;
    }

    char qerr[H3Q_ERRLEN] = {0};
    h3q_config qcfg = {
        .cert_path = conf->h3_cert_path,
        .key_path = conf->h3_key_path,
        .address_validation = (conf->h3_address_validation != H3_FLAG_OFF),
    };
    io->qengine = h3q_engine_create(&qcfg, udp_fd, qerr, sizeof(qerr));
    if (!io->qengine)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "QUIC engine initialization failed: %s", qerr);
        teardown(io);
        return APR_EGENERAL;
    }

    io->note_conn_added = APR_RETRIEVE_OPTIONAL_FN(ap_mpm_note_extra_connection_added);
    io->note_conn_removed = APR_RETRIEVE_OPTIONAL_FN(ap_mpm_note_extra_connection_removed);
    if (!io->note_conn_added || !io->note_conn_removed)
    {
        io->note_conn_added = NULL;
        io->note_conn_removed = NULL;
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "active MPM '%s' does not report externally accepted connections; graceful child shutdown may end active HTTP/3 connections early (an MPM with ap_mpm_note_extra_connection_added/_removed avoids this)", ap_show_mpm());
    }

    io->thread_running = 1;
    child_h3_io = io;
    apr_threadattr_t* attr = NULL;
    if (apr_threadattr_create(&attr, pchild) != APR_SUCCESS || apr_thread_create(&io->event_thread, attr, h3_event_thread, io, pchild) != APR_SUCCESS)
    {
        io->thread_running = 0;
        teardown(io);
        child_h3_io = NULL;
        return APR_EGENERAL;
    }
    apr_pool_pre_cleanup_register(pchild, io, listen_stop_cleanup);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "mod_http3 loaded with version: %d (%s) on pid=%d port=%d; built against httpd %d.%d.%d MMN %d:%d (%s)", MOD_HTTP3_VERSION, MOD_HTTP3_VERSION_STRING, h3_getpid(), (int)conf->h3_port, AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER,
                 AP_SERVER_PATCHLEVEL_NUMBER, MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR, H3_DEVEL ? "devel" : "stable");
    return APR_SUCCESS;
}

void h3_io_listen_drain(h3_io_t* io)
{
    if (io && !io->draining)
    {
        io->draining = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "graceful stop: draining %d connection(s), the MPM waits for them to finish", io->active_sessions ? io->active_sessions->nelts : 0);
        h3_wakeup_signal(&io->wakeup);
    }
}

void h3_io_listen_stop(h3_io_t* io)
{
    if (io)
    {
        teardown(io);
        if (child_h3_io == io)
        {
            child_h3_io = NULL;
        }
    }
}

void wait_for_event(h3_io_t* io)
{
    if (!io)
    {
        return;
    }
    int want_read = 0;
    int want_write = 0;
    int timeout_ms = 1000;
    h3q_engine_want(io->qengine, &want_read, &want_write, &timeout_ms);

    struct pollfd pfds[2] = {{.fd = io->udp_fd, .events = 0}, {.fd = -1, .events = POLLIN}};
    h3_nfds_t npfds = 1;
    if (io->wakeup.reader && io->wakeup.reader_fd != (apr_os_sock_t)-1)
    {
        pfds[1].fd = io->wakeup.reader_fd;
        npfds = 2;
    }

    if (want_read)
    {
        pfds[0].events |= POLLIN;
    }
    if (want_write)
    {
        pfds[0].events |= POLLOUT;
    }
    if (!pfds[0].events)
    {
        pfds[0].events = POLLIN; /* force POLLIN to avoid missing UDP packets */
    }

    /* revents is undefined after a failure, and WSAPoll ignores errno. */
    if (h3_poll(pfds, npfds, timeout_ms) < 0)
    {
        return;
    }

    if (npfds == 2 && (pfds[1].revents & POLLIN))
    {
        h3_wakeup_drain(&io->wakeup);
    }
}

void remove_pending_handshake(h3_io_t* io, int index, int free_conn)
{
    h3_pending_handshake* pending = (h3_pending_handshake*)io->pending_handshakes->elts;
    if (free_conn)
    {
        h3q_conn_free(pending[index].conn);
    }
    if (io->note_conn_removed)
    {
        io->note_conn_removed();
    }
    if (index < io->pending_handshakes->nelts - 1)
    {
        pending[index] = pending[io->pending_handshakes->nelts - 1];
    }
    io->pending_handshakes->nelts--;
}

static apr_status_t spawn_serviced_session(h3_io_t* io, h3q_conn* conn)
{
    apr_allocator_t* allocator = NULL;
    apr_pool_t* session_pool = NULL;
    if (apr_allocator_create(&allocator) != APR_SUCCESS || apr_pool_create_ex(&session_pool, io->pool, NULL, allocator) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "failed to create session pool for new connection");
        if (allocator)
        {
            apr_allocator_destroy(allocator);
        }
        h3q_conn_free(conn);
        return APR_EGENERAL;
    }
    apr_allocator_owner_set(allocator, session_pool);
    apr_pool_tag(session_pool, "h3_session");

    h3_session* session = NULL;
    if (h3_session_create(&session, io->server, conn, session_pool) != APR_SUCCESS)
    {
        h3q_conn_free(conn);
        apr_pool_destroy(session_pool);
        return APR_EGENERAL;
    }
    if (h3_session_create_control_streams(session) != APR_SUCCESS)
    {
        h3_session_destroy(session);
        return APR_EGENERAL;
    }
    if (h3q_conn_is_closed(conn))
    {
        h3_session_destroy(session);
        return APR_EGENERAL;
    }
    conn_rec* c = h3_synth_conn(session);
    if (!c)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "h3_synth_conn failed");
        h3_session_destroy(session);
        return APR_EGENERAL;
    }
    *(h3_session**)apr_array_push(io->active_sessions) = session;
    apr_atomic_inc32(&io->active_session_count);
    if (io->note_conn_added)
    {
        io->note_conn_added();
    }
    return APR_SUCCESS;
}

void progress_pending_handshakes(h3_io_t* io)
{
    CHECK(io);
    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
    CHECK(conf);
    apr_time_t now = apr_time_now();
    apr_time_t timeout = apr_time_from_sec(conf->h3_handshake_timeout);

    for (int i = 0; i < io->pending_handshakes->nelts;)
    {
        h3_pending_handshake* pending = &((h3_pending_handshake*)io->pending_handshakes->elts)[i];
        h3q_conn* conn = pending->conn;

        if (now - pending->accepted_at >= timeout)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "QUIC handshake timed out after %u second(s)", (unsigned)conf->h3_handshake_timeout);
            remove_pending_handshake(io, i, 1);
            continue;
        }

        int finished = 0;
        int rv = 0;
        const char* why = NULL;

        if (h3q_conn_is_closed(conn))
        {
            rv = -1;
            why = "peer closed the connection during the handshake";
        }
        else if (h3q_conn_is_handshake_done(conn))
        {
            rv = 1;
        }

        if (rv == 1)
        {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "QUIC handshake complete");
            spawn_serviced_session(io, conn);
            remove_pending_handshake(io, i, 0);
            finished = 1;
        }
        else if (rv == -1)
        {
            char detail[H3Q_ERRLEN] = {0};
            h3q_conn_close_reason(conn, detail, sizeof(detail));
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "QUIC handshake did not complete: %s close=[%s]", why, detail);
            remove_pending_handshake(io, i, 1);
            finished = 1;
        }

        if (!finished)
        {
            i++;
        }
    }
}

int prepare_accepted_connection(h3_io_t* io, h3q_conn* conn)
{
    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
    if (!h3q_conn_prepare(conn, conf->h3_idle_timeout))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "h3q_conn_prepare failed for accepted connection - dropping it");
        return 0;
    }

    h3_pending_handshake* pending = (h3_pending_handshake*)apr_array_push(io->pending_handshakes);
    pending->conn = conn;
    pending->accepted_at = apr_time_now();
    apr_atomic_inc32(&io->total_connections);
    if (io->note_conn_added)
    {
        io->note_conn_added();
    }
    return 1;
}

int service_session_pass(h3_io_t* io, h3_session* session)
{
    CHECK(io);
    CHECK(session);
    server_rec* s = session->s;
    h3q_conn* conn = session->qconn;

    if (session->aborted)
    {
        return 0;
    }

    if (io->draining || !io->thread_running)
    {
        apr_thread_mutex_lock(session->lock);
        if (!session->goaway_sent)
        {
            nghttp3_conn_submit_shutdown_notice(session->ngh3);
        }
        flush_nghttp3(session);
        int drained = nghttp3_conn_is_drained2(session->ngh3);
        apr_thread_mutex_unlock(session->lock);
        if (!session->goaway_sent)
        {
            session->goaway_sent = 1;
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "sent HTTP/3 GOAWAY; letting in-flight streams finish");
        }
        if (!io->thread_running && !session->goaway_deadline)
        {
            session->goaway_deadline = apr_time_now() + apr_time_from_sec(H3_GOAWAY_GRACE_SECS);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "stopping: allowing up to %d more second(s) for in-flight streams", H3_GOAWAY_GRACE_SECS);
        }
        if (drained || (session->goaway_deadline && apr_time_now() >= session->goaway_deadline))
        {
            apr_thread_mutex_lock(session->lock);
            nghttp3_conn_shutdown(session->ngh3);
            flush_nghttp3(session);
            apr_thread_mutex_unlock(session->lock);
            session->aborted = 1;
            return 0;
        }
    }

    if (h3q_conn_is_closed(conn))
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "QUIC connection terminated (idle timeout, peer close, or transport error)");
        session->aborted = 1;
        return 0;
    }

    apr_pool_t* scratch = NULL;
    if (apr_pool_create(&scratch, session->pool) != APR_SUCCESS)
    {
        return 0;
    }

    for (h3q_stream* s2 = NULL; (s2 = h3q_conn_accept_stream(conn)) != NULL;)
    {
        apr_atomic_inc32(&io->total_streams);
        int64_t sid = h3q_stream_id(s2);
        if (sid < 0)
        {
            h3q_stream_free(s2);
            continue;
        }
        apr_thread_mutex_lock(session->lock);
        h3_stream* tracked = track_stream(session, sid, s2);
        if (!tracked)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "track_stream failed for sid=%lld - freeing stream", (long long)sid);
            h3q_stream_free(s2);
        }
        apr_thread_mutex_unlock(session->lock);
    }

    int data_read = 0;
    apr_thread_mutex_lock(session->lock);
    apr_array_header_t* completed = drain_ready_streams(session, scratch, &data_read);
    flush_nghttp3(session);
    apr_thread_mutex_unlock(session->lock);

    if (session->ngh3_dead)
    {
        session->aborted = 1;
        apr_pool_destroy(scratch);
        return 0;
    }

    for (int i = 0; i < completed->nelts; i++)
    {
        h3_stream* h3s = ((h3_stream**)completed->elts)[i];
        h3_process_request(session, h3s);
    }

    apr_thread_mutex_lock(session->lock);
    flush_nghttp3(session);
    apr_thread_mutex_unlock(session->lock);
    apr_pool_destroy(scratch);
    return data_read;
}
