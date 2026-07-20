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
#include <apr_thread_proc.h>
#include <apr_portable.h>
#include <apr_thread_pool.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <poll.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_io.h"
#include "h3_request.h"
#include "h3_session.h"
#include "h3_socket.h"
#include "h3_ssl.h"
#include "h3_stream.h"
#include "h3_threads.h"
#include "h3_version.h"
#include "mod_http3.h"

h3_io_t* child_h3_io = NULL;

int h3_io_at_connection_limit(h3_io_t* io)
{
    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
    apr_uint32_t active = (apr_uint32_t)io->active_sessions->nelts + (apr_uint32_t)io->pending_handshakes->nelts;
    return active >= conf->h3_max_connections;
}

/* h3_keylog_cb lives in h3_ssl.c on trunk; the upstream chain defines it inline here. */

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
    if (getenv("SSLKEYLOGFILE"))
    {
        SSL_CTX_set_keylog_callback(io->ssl_ctx, h3_keylog_cb);
    }
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
        /* Wait for event_thread to shut down and remove all active sessions. */
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
    if (io->wakeup_pipe[0])
    {
        apr_file_close(io->wakeup_pipe[0]);
        apr_file_close(io->wakeup_pipe[1]);
        io->wakeup_pipe[0] = NULL;
        io->wakeup_pipe[1] = NULL;
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
    io->active_sessions = apr_array_make(pchild, 8, sizeof(h3_session*));
    io->pending_handshakes = apr_array_make(pchild, 4, sizeof(h3_pending_handshake));
    if (apr_file_pipe_create_ex(&io->wakeup_pipe[0], &io->wakeup_pipe[1], APR_FULL_NONBLOCK, pchild) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_file_pipe_create_ex failed");
        return APR_EGENERAL;
    }
    if (apr_thread_pool_create(&io->h3_worker_pool, 16, 64, pchild) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_thread_pool_create failed");
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
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, "active MPM '%s' lacks connection-count notifications; upgrade your httpd to a version that supports mod_http3", ap_show_mpm());
        teardown(io);
        return APR_EGENERAL;
    }

    io->thread_running = 1;
    child_h3_io = io;
    apr_threadattr_t* attr = NULL;
    if (apr_threadattr_create(&attr, pchild) != APR_SUCCESS || apr_thread_create(&io->event_thread, attr, quic_event_thread, io, pchild) != APR_SUCCESS)
    {
        io->thread_running = 0;
        teardown(io);
        child_h3_io = NULL;
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "mod_http3 loaded with version: %d (%s) on pid=%d port=%d", MOD_HTTP3_VERSION, MOD_HTTP3_VERSION_STRING, getpid(), (int)conf->h3_port);
    return APR_SUCCESS;
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
    /* poll(), not select(): descriptors can exceed FD_SETSIZE. */
    int timeout_ms = 1000;
    struct timeval tv = {0};
    int inf = 0;
    if (SSL_get_event_timeout(io->ssl_listener, &tv, &inf) && !inf && (tv.tv_sec > 0 || tv.tv_usec > 0) && tv.tv_sec <= 1)
    {
        timeout_ms = (int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
        if (timeout_ms <= 0)
        {
            timeout_ms = 1;
        }
    }

    struct pollfd pfds[2] = {{.fd = io->udp_fd, .events = 0}, {.fd = -1, .events = POLLIN}};
    nfds_t npfds = 1;
    if (io->wakeup_pipe[0])
    {
        apr_os_file_t wakeup_fd = -1;
        apr_os_file_get(&wakeup_fd, io->wakeup_pipe[0]);
        pfds[1].fd = wakeup_fd;
        npfds = 2;
    }

    if (SSL_net_read_desired(io->ssl_listener))
    {
        pfds[0].events |= POLLIN;
    }
    if (SSL_net_write_desired(io->ssl_listener))
    {
        pfds[0].events |= POLLOUT;
    }
    if (!pfds[0].events && npfds == 1)
    {
        pfds[0].events = POLLIN;
    }
    if (!pfds[0].events)
    {
        pfds[0].events = POLLIN; /* force POLLIN to avoid missing UDP packets! */
    }
    if (poll(pfds, npfds, timeout_ms) < 0 && errno == EINTR)
    {
        return;
    }

    if (npfds == 2 && (pfds[1].revents & POLLIN))
    {
        char buf[64];
        apr_size_t len = sizeof(buf);
        apr_file_read(io->wakeup_pipe[0], buf, &len);
    }
}

int tick_engine(SSL* conn)
{
    CHECK(conn);
    return SSL_handle_events(conn) == 1;
}

void remove_pending_handshake(h3_io_t* io, int index, int free_conn)
{
    h3_pending_handshake* pending = (h3_pending_handshake*)io->pending_handshakes->elts;
    if (free_conn)
    {
        SSL_free(pending[index].conn);
    }
    if (index < io->pending_handshakes->nelts - 1)
    {
        pending[index] = pending[io->pending_handshakes->nelts - 1];
    }
    io->pending_handshakes->nelts--;
}

static apr_status_t spawn_serviced_session(h3_io_t* io, SSL* conn)
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
        SSL_free(conn);
        return APR_EGENERAL;
    }
    apr_allocator_owner_set(allocator, session_pool);
    apr_pool_tag(session_pool, "h3_session");

    h3_session* session = NULL;
    if (h3_session_create(&session, io->server, io->ssl_listener, conn, session_pool) != APR_SUCCESS)
    {
        /* Ownership of conn stays here until a session holds it. */
        SSL_free(conn);
        apr_pool_destroy(session_pool);
        return APR_EGENERAL;
    }
    if (h3_session_create_control_streams(session) != APR_SUCCESS)
    {
        h3_session_destroy(session);
        return APR_EGENERAL;
    }
    if (SSL_get_shutdown(conn))
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
        SSL* conn = pending->conn;

        if (now - pending->accepted_at >= timeout)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "QUIC handshake timed out after %u second(s)", (unsigned)conf->h3_handshake_timeout);
            remove_pending_handshake(io, i, 1);
            continue;
        }

        int finished = 0;
        do
        {
            int rv = 0;
            const char* why = NULL;

            if (!tick_engine(io->ssl_listener))
            {
                rv = -1;
                why = "listener event processing failed";
            }
            else if (SSL_get_shutdown(conn))
            {
                rv = -1;
                why = "peer closed the connection during the handshake";
            }
            else if (SSL_is_init_finished(conn))
            {
                rv = 1;
            }

            if (rv == 1)
            {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, io->server, "QUIC handshake complete");
                spawn_serviced_session(io, conn);
                remove_pending_handshake(io, i, 0);
                finished = 1;
                break;
            }
            if (rv == -1)
            {
                char errbuf[256] = {0};
                ERR_error_string_n(ERR_peek_last_error(), errbuf, sizeof(errbuf));
                SSL_CONN_CLOSE_INFO cci;
                memset(&cci, 0, sizeof(cci));
                if (SSL_get_conn_close_info(conn, &cci, sizeof(cci)))
                {
                    const char* origin = (cci.flags & SSL_CONN_CLOSE_FLAG_LOCAL) ? "local" : "remote";
                    const char* layer = (cci.flags & SSL_CONN_CLOSE_FLAG_TRANSPORT) ? "transport" : "app";
                    const char* reason = cci.reason ? cci.reason : "";
                    char detail[320];

                    snprintf(detail, sizeof(detail), "%s %s err=0x%llx frame=0x%llx reason=\"%.*s\"", origin, layer, (unsigned long long)cci.error_code, (unsigned long long)cci.frame_type, (int)cci.reason_len, reason);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "QUIC handshake did not complete: %s (%s) close=[%s]", why, errbuf, detail);
                }
                else
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "QUIC handshake did not complete: %s (%s)", why, errbuf);
                }
                remove_pending_handshake(io, i, 1);
                finished = 1;
                break;
            }
        } while (SSL_net_read_desired(io->ssl_listener) || SSL_net_write_desired(io->ssl_listener));

        if (!finished)
        {
            i++;
        }
    }
}

int prepare_accepted_connection(h3_io_t* io, SSL* conn)
{
    if (!SSL_set_blocking_mode(conn, 0))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, io->server, "SSL_set_blocking_mode failed for accepted connection - dropping it");
        return 0;
    }
    SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE);
    SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
    h3_server_conf* conf = ap_get_module_config(io->server->module_config, &http3_module);
    SSL_set_generic_value_uint(conn, SSL_VALUE_QUIC_IDLE_TIMEOUT, conf->h3_idle_timeout * 1000);

    h3_pending_handshake* pending = (h3_pending_handshake*)apr_array_push(io->pending_handshakes);
    pending->conn = conn;
    pending->accepted_at = apr_time_now();
    apr_atomic_inc32(&io->total_connections);
    return 1;
}

void service_session_pass(h3_io_t* io, h3_session* session)
{
    CHECK(io);
    CHECK(session);
    server_rec* s = session->s;
    SSL* conn = session->ssl_conn;

    if (session->aborted)
    {
        return;
    }

    if (!io->thread_running)
    {
        /* Tell the client to stop opening new streams but finish in-flight ones */
        apr_thread_mutex_lock(session->lock);
        if (!session->goaway_deadline)
        {
            nghttp3_conn_submit_shutdown_notice(session->ngh3);
        }
        flush_nghttp3(session);
        int drained = nghttp3_conn_is_drained2(session->ngh3);
        apr_thread_mutex_unlock(session->lock);
        if (!session->goaway_deadline)
        {
            session->goaway_deadline = apr_time_now() + apr_time_from_sec(H3_GOAWAY_GRACE_SECS);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "sent HTTP/3 GOAWAY; allowing up to %d more second(s) for in-flight streams", H3_GOAWAY_GRACE_SECS);
        }
        if (drained || apr_time_now() >= session->goaway_deadline)
        {
            apr_thread_mutex_lock(session->lock);
            nghttp3_conn_shutdown(session->ngh3);
            flush_nghttp3(session);
            apr_thread_mutex_unlock(session->lock);
            session->aborted = 1;
            return;
        }
    }

    if (SSL_get_shutdown(conn))
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "QUIC connection terminated (idle timeout, peer close, or transport error)");
        session->aborted = 1;
        return;
    }

    apr_pool_t* scratch = NULL;
    if (apr_pool_create(&scratch, session->pool) != APR_SUCCESS)
    {
        return;
    }

    for (SSL* s2 = NULL; (s2 = SSL_accept_stream(conn, SSL_ACCEPT_STREAM_NO_BLOCK)) != NULL;)
    {
        apr_atomic_inc32(&io->total_streams);
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

    int data_read = 0;
    apr_thread_mutex_lock(session->lock);
    apr_array_header_t* completed = drain_ready_streams(session, scratch, &data_read);
    flush_nghttp3(session);
    apr_thread_mutex_unlock(session->lock);
    (void)data_read;

    if (session->ngh3_dead)
    {
        session->aborted = 1;
        apr_pool_destroy(scratch);
        return;
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
}
