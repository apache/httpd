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

#include "h3_version.h"
#include <httpd.h>

#include <http_config.h>
#include <http_log.h>

#include <apr_allocator.h>
#include <apr_atomic.h>
#include <apr_pools.h>
#include <apr_thread_proc.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/select.h>
#include <unistd.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_io.h"
#include "h3_request.h"
#include "h3_session.h"
#include "h3_socket.h"
#include "h3_ssl.h"
#include "h3_stream.h"
#include "mod_http3.h"

h3_io_t* child_h3_io = NULL;

static apr_status_t build_ssl_listener(h3_io_t* io, const char* cert, const char* key)
{
    CHECK(io);
    CHECK(cert);
    CHECK(key);
    io->ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!io->ssl_ctx || SSL_CTX_use_certificate_chain_file(io->ssl_ctx, cert) <= 0 || SSL_CTX_use_PrivateKey_file(io->ssl_ctx, key, SSL_FILETYPE_PEM) <= 0)
    {
        return APR_EGENERAL;
    }
    SSL_CTX_set_alpn_select_cb(io->ssl_ctx, h3_alpn_select_cb, io->server);
    io->ssl_listener = SSL_new_listener(io->ssl_ctx, 0);
    if (!io->ssl_listener || !SSL_set_fd(io->ssl_listener, io->udp_fd) || !SSL_listen(io->ssl_listener) || !SSL_set_blocking_mode(io->ssl_listener, 0))
    {
        return APR_EGENERAL;
    }
    BIO_set_nbio(SSL_get_rbio(io->ssl_listener), 1);
    return APR_SUCCESS;
}

static void teardown(h3_io_t* io)
{
    CHECK(io);
    if (io->event_thread)
    {
        io->thread_running = 0;
        apr_sleep(1000 * 1000);
        apr_thread_detach(io->event_thread);
        io->event_thread = NULL;
    }
    if (io->workers)
    {
        /*
         * Wait for all workers still using udp_fd/ssl_listener
         * to finish before freeing shared state; log progress while
         * live_workers > 0.
         */
        apr_time_t next_warning = apr_time_now() + apr_time_from_sec(5);
        apr_uint32_t remaining;
        while ((remaining = apr_atomic_read32(&io->live_workers)) > 0)
        {
            if (apr_time_now() >= next_warning)
            {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, io->server, "teardown waiting for %u workers to finish in-flight connections", remaining);
                next_warning = apr_time_now() + apr_time_from_sec(5);
            }
            apr_sleep(50 * 1000);
        }
        apr_thread_mutex_lock(io->workers_lock);
        for (int i = 0; i < io->workers->nelts; i++)
        {
            apr_thread_t* t = ((apr_thread_t**)io->workers->elts)[i];
            if (t)
            {
                apr_thread_detach(t);
            }
        }
        io->workers->nelts = 0;
        apr_thread_mutex_unlock(io->workers_lock);
    }
    if (io->ssl_listener)
    {
        SSL_free(io->ssl_listener);
        io->ssl_listener = NULL;
    }
    if (io->ssl_ctx)
    {
        SSL_CTX_free(io->ssl_ctx);
        io->ssl_ctx = NULL;
    }
    if (io->udp_fd >= 0)
    {
        h3_socket_close(io->udp_fd);
        io->udp_fd = -1;
    }
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
    io->workers = apr_array_make(pchild, 8, sizeof(apr_thread_t*));
    if (apr_thread_mutex_create(&io->workers_lock, APR_THREAD_MUTEX_DEFAULT, pchild) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_thread_mutex_create failed");
        return APR_EGENERAL;
    }
    if (build_ssl_listener(io, conf->h3_cert_path, conf->h3_key_path) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "listener setup failed");
        teardown(io);
        return APR_EGENERAL;
    }

    io->note_conn_added = APR_RETRIEVE_OPTIONAL_FN(ap_mpm_note_extra_connection_added);
    io->note_conn_removed = APR_RETRIEVE_OPTIONAL_FN(ap_mpm_note_extra_connection_removed);
    if (!io->note_conn_added || !io->note_conn_removed)
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "active MPM lacks connection-count notifications; this child may exit while connections are still active");
    }

    io->thread_running = 1;
    apr_threadattr_t* attr = NULL;
    if (apr_threadattr_create(&attr, pchild) != APR_SUCCESS || apr_thread_create(&io->event_thread, attr, quic_event_thread, io, pchild) != APR_SUCCESS)
    {
        io->thread_running = 0;
        teardown(io);
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "mod_http3 loaded with version: %d (%s) on pid=%d port=%d", MOD_HTTP3_VERSION, MOD_HTTP3_VERSION_STRING, getpid(), (int)conf->h3_port);
    child_h3_io = io;
    return APR_SUCCESS;
}

void h3_io_listen_stop(h3_io_t* io)
{
    if (io)
    {
        teardown(io);
    }
}

static void wait_for_event(int fd, SSL* ssl, int want_write)
{
    struct timeval max_tv = {1, 0}, tv = {0}, *tvp = &max_tv;
    int inf = 0;
    if (SSL_get_event_timeout(ssl, &tv, &inf) && !inf && (tv.tv_sec > 0 || tv.tv_usec > 0) && tv.tv_sec <= 1)
    {
        tvp = &tv;
    }
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_SET(fd, &rfds);
    if (want_write && SSL_net_write_desired(ssl))
    {
        FD_SET(fd, &wfds);
    }
    if (select(fd + 1, &rfds, &wfds, NULL, tvp) < 0 && errno == EINTR)
    {
        return;
    }
}

static int tick_engine(SSL* conn)
{
    CHECK(conn);
    return SSL_handle_events(conn) == 1;
}

static void service_connection(h3_io_t* io, h3_session* session)
{
    CHECK(io);
    CHECK(session);
    server_rec* s = session->s;
    SSL* conn = session->ssl_conn;

    while (!SSL_is_init_finished(conn) && io->thread_running)
    {
        wait_for_event(io->udp_fd, conn, 0);
        if (!tick_engine(conn) || SSL_get_shutdown(conn))
        {
            break;
        }
    }

    if (!SSL_is_init_finished(conn))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "QUIC handshake did not complete");
        h3_session_destroy(session);
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "connection servicing done");
        return;
    }

    if (h3_session_create_control_streams(session) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_session_create_control_streams failed");
    }
    else
    {
        conn_rec* c = h3_synth_conn(session);
        if (!c)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_synth_conn failed");
        }
        else
        {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "servicing new QUIC connection");
            apr_pool_t* loop_pool = session->pool;
            apr_time_t goaway_deadline = 0;
            while (!session->aborted)
            {
                if (!io->thread_running && goaway_deadline == 0)
                {
                    /* Send GOAWAY to stop new streams. */
                    apr_thread_mutex_lock(session->lock);
                    nghttp3_conn_submit_shutdown_notice(session->ngh3);
                    flush_nghttp3(session);
                    apr_thread_mutex_unlock(session->lock);
                    goaway_deadline = apr_time_now() + apr_time_from_sec(H3_GOAWAY_GRACE_SECS);
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "sent HTTP/3 GOAWAY; allowing up to %d more second(s) for in-flight streams", H3_GOAWAY_GRACE_SECS);
                }
                if (goaway_deadline != 0)
                {
                    apr_thread_mutex_lock(session->lock);
                    int drained = nghttp3_conn_is_drained2(session->ngh3);
                    apr_thread_mutex_unlock(session->lock);
                    if (drained || apr_time_now() >= goaway_deadline)
                    {
                        break;
                    }
                }

                wait_for_event(io->udp_fd, conn, 0);
                if (!tick_engine(conn))
                {
                    break;
                }
                if (SSL_get_shutdown(conn))
                {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "QUIC connection terminated (idle timeout, peer close, or transport error)");
                    break;
                }

                for (SSL* s2 = NULL; (s2 = SSL_accept_stream(conn, SSL_ACCEPT_STREAM_NO_BLOCK)) != NULL;)
                {
                    int64_t sid = (int64_t)SSL_get_stream_id(s2);
                    if (sid < 0)
                    {
                        SSL_free(s2);
                        continue;
                    }
                    apr_thread_mutex_lock(session->lock);
                    h3_stream* tracked = track_stream(session, sid, s2);
                    if (!tracked)
                    {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "track_stream failed for sid=%lld - freeing stream", (long long)sid);
                        SSL_free(s2);
                    }
                    apr_thread_mutex_unlock(session->lock);
                }

                apr_thread_mutex_lock(session->lock);
                apr_array_header_t* completed = drain_ready_streams(session, loop_pool);
                flush_nghttp3(session);
                apr_thread_mutex_unlock(session->lock);

                if (session->ngh3_dead)
                {
                    session->aborted = 1;
                    break;
                }

                for (int i = 0; i < completed->nelts; i++)
                {
                    h3_stream* h3s = ((h3_stream**)completed->elts)[i];
                    h3_process_request(session, h3s);
                }

                apr_thread_mutex_lock(session->lock);
                flush_nghttp3(session);
                apr_thread_mutex_unlock(session->lock);
            }
            if (goaway_deadline != 0 && !session->ngh3_dead)
            {
                apr_thread_mutex_lock(session->lock);
                nghttp3_conn_shutdown(session->ngh3);
                apr_thread_mutex_unlock(session->lock);
            }
            apr_pool_destroy(c->pool);
        }
    }
    if (session->ngh3_dead)
    {
        SSL_SHUTDOWN_EX_ARGS args = {.quic_error_code = session->abort_quic_error_code, .quic_reason = session->abort_reason};
        for (int i = 0; i < 5 && SSL_shutdown_ex(conn, 0, &args, sizeof(args)) != 1; i++)
        {
            wait_for_event(io->udp_fd, conn, 1);
            tick_engine(conn);
        }
    }
    else
    {
        for (int i = 0; i < 5 && SSL_shutdown(conn) != 1; i++)
        {
            wait_for_event(io->udp_fd, conn, 1);
            tick_engine(conn);
        }
    }

    h3_session_destroy(session);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "connection servicing done");
}

struct worker_args
{
    h3_io_t* io;
    h3_session* session;
};

static void* APR_THREAD_FUNC worker_thread(apr_thread_t* /*thread*/, void* data)
{
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

apr_status_t h3_io_spawn_worker(h3_io_t* io, h3_session* session)
{
    CHECK(io);
    CHECK(session);
    struct worker_args* args = apr_palloc(io->pool, sizeof(*args));
    args->io = io;
    args->session = session;
    apr_atomic_inc32(&io->live_workers);
    /*
     * Tell the MPM about this connection before the worker thread can
     * possibly finish and remove it, so the added/removed calls are
     * strictly paired even if thread creation below fails right after.
     */
    if (io->note_conn_added)
    {
        io->note_conn_added();
    }
    apr_threadattr_t* attr = NULL;
    if (apr_threadattr_create(&attr, io->pool) != APR_SUCCESS)
    {
        apr_atomic_dec32(&io->live_workers);
        if (io->note_conn_removed)
        {
            io->note_conn_removed();
        }
        return APR_EGENERAL;
    }
    apr_thread_t* t = NULL;
    if (apr_thread_create(&t, attr, worker_thread, args, io->pool) != APR_SUCCESS)
    {
        apr_atomic_dec32(&io->live_workers);
        if (io->note_conn_removed)
        {
            io->note_conn_removed();
        }
        return APR_EGENERAL;
    }
    apr_thread_mutex_lock(io->workers_lock);
    *(apr_thread_t**)apr_array_push(io->workers) = t;
    apr_thread_mutex_unlock(io->workers_lock);
    return APR_SUCCESS;
}

void* APR_THREAD_FUNC quic_event_thread(apr_thread_t* /*thread*/, void* data)
{
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
        SSL* conn = SSL_accept_connection(io->ssl_listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (!conn)
        {
            continue;
        }
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "accepted new QUIC connection");
        /* Make connection non-blocking. */
        if (!SSL_set_blocking_mode(conn, 0))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "SSL_set_blocking_mode failed for accepted connection - dropping it");
            SSL_free(conn);
            continue;
        }
        SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

        apr_allocator_t* allocator = NULL;
        apr_pool_t* session_pool = NULL;
        if (apr_allocator_create(&allocator) != APR_SUCCESS || apr_pool_create_ex(&session_pool, io->pool, NULL, allocator) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "failed to create session pool for new connection");
            if (allocator)
            {
                apr_allocator_destroy(allocator);
            }
            SSL_free(conn);
            continue;
        }
        apr_allocator_owner_set(allocator, session_pool);
        apr_pool_tag(session_pool, "h3_session");

        h3_session* session = NULL;
        if (h3_session_create(&session, io->server, io->ssl_listener, conn, session_pool) == APR_SUCCESS)
        {
            if (h3_io_spawn_worker(io, session) != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "failed to spawn worker for new connection");
                h3_session_destroy(session);
            }
        }
        else
        {
            SSL_free(conn);
            apr_pool_destroy(session_pool);
        }
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "event thread exiting");
    return NULL;
}
