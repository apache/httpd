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
#include <http_connection.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_vhost.h>

#include <apr_atomic.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_pool.h>

#include <stdlib.h>

#include <nghttp3/nghttp3.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_filter.h"
#include "h3_io.h"
#include "h3_request.h"
#include "h3_session.h"
#include "mod_http3.h"

static volatile apr_uint32_t h3_conn_id_seq = 0;

/// modules/loggers/mod_logio.c:52
typedef struct
{
    apr_off_t bytes_in;
    apr_off_t bytes_out;
    apr_off_t bytes_last_request;
} h3_logio_config_t;

conn_rec* h3_synth_conn(h3_session* session)
{
    CHECK(session);
    server_rec* s = session->s;
    apr_pool_t* cpool = NULL;
    if (apr_pool_create(&cpool, session->pool) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_synth_conn: apr_pool_create failed");
        return NULL;
    }

    conn_rec* c = apr_pcalloc(cpool, sizeof(conn_rec));
    c->pool = cpool;
    c->base_server = s;
    c->master = c;
    c->conn_config = ap_create_conn_config(cpool);
    c->notes = apr_table_make(cpool, 5);
    c->id = (long)apr_atomic_inc32(&h3_conn_id_seq);
    c->local_ip = apr_pstrdup(cpool, "0.0.0.0");
    c->client_ip = apr_pstrdup(cpool, "0.0.0.0");
    c->remote_host = apr_pstrdup(cpool, "unknown");
    h3_server_conf* conf = ap_get_module_config(s->module_config, &http3_module);
    apr_port_t vhost_port = (conf && conf->host_port) ? conf->host_port : (conf ? conf->h3_port : 0);
    apr_sockaddr_info_get(&c->client_addr, c->client_ip, APR_INET, 0, 0, cpool);
    apr_sockaddr_info_get(&c->local_addr, c->local_ip, APR_INET, vhost_port, 0, cpool);
    if (child_h3_io && h3_io_get_client_addr(child_h3_io, session->ssl_conn, cpool, &c->client_addr, &c->client_ip) == APR_SUCCESS)
    {
        c->remote_host = NULL;
    }
    c->bucket_alloc = apr_bucket_alloc_create(cpool);
    c->log = &s->log;
    c->slaves = apr_array_make(cpool, 4, sizeof(void*));
    c->requests = apr_array_make(cpool, 4, sizeof(void*));
    c->async_filter = -1;
    c->clogging_input_filters = 1;
#if APR_HAS_THREADS
    c->current_thread = ap_thread_current();
#endif
    apr_table_setn(c->notes, "IS_mod_http3", "1");
    apr_table_setn(c->notes, "ssl-bypass", "1");
    ap_update_vhost_given_ip(c);

    module* logio = ap_find_linked_module("mod_logio.c");
    if (logio)
    {
        ap_set_module_config(c->conn_config, logio, apr_pcalloc(cpool, sizeof(h3_logio_config_t)));
    }

    session->c = c;
    return c;
}

static int is_connection_specific(const char* k)
{
    return !ap_cstr_casecmp(k, "Connection") || !ap_cstr_casecmp(k, "Keep-Alive") || !ap_cstr_casecmp(k, "Proxy-Connection") || !ap_cstr_casecmp(k, "Transfer-Encoding") || !ap_cstr_casecmp(k, "Upgrade") || !ap_cstr_casecmp(k, "TE");
}

static size_t build_response_nva(nghttp3_nv* nva, size_t nva_cap, request_rec* r, h3_conn_ctx_t* h3ctx, apr_pool_t* dst_pool)
{
    apr_table_t* hdrs = (h3ctx->resp && h3ctx->resp->headers) ? h3ctx->resp->headers : r->headers_out;
    int status = (h3ctx->resp && h3ctx->resp->status) ? h3ctx->resp->status : r->status;
    char* status_str = apr_psprintf(dst_pool, "%d", status);
    NV_SET(nva, 0, ":status", status_str);
    size_t nvlen = 1;

    if (hdrs != NULL)
    {
        const char* conn_hdr = apr_table_get(hdrs, "Connection");
        const apr_array_header_t* tarr = apr_table_elts(hdrs);
        const apr_table_entry_t* telts = (const apr_table_entry_t*)tarr->elts;
        for (int i = 0; i < tarr->nelts && nvlen < nva_cap; i++)
        {
            const char* k = telts[i].key;
            const char* v = telts[i].val;
            if (!k || !v || k[0] == ':')
            {
                continue;
            }
            if (is_connection_specific(k) || (conn_hdr && ap_find_token(dst_pool, conn_hdr, k)))
            {
                continue;
            }
            NV_SET(nva, nvlen, apr_pstrdup(dst_pool, k), apr_pstrdup(dst_pool, v));
            nvlen++;
        }
    }
    return nvlen;
}

static void wake_event_thread(void)
{
    if (child_h3_io && child_h3_io->wakeup_pipe[1])
    {
        char wake = '1';
        apr_size_t len = 1;
        (void)apr_file_write(child_h3_io->wakeup_pipe[1], &wake, &len);
    }
}

static apr_status_t submit_response_nva(h3_stream* h3s, nghttp3_nv* nva, size_t nvlen)
{
    h3_session* session = h3s->session;
    apr_thread_mutex_lock(session->lock);
    if (h3s->response_submitted)
    {
        apr_thread_mutex_unlock(session->lock);
        return APR_SUCCESS;
    }
    if (h3s->response_cancelled || session->aborted || session->ngh3_dead || !session->ngh3)
    {
        apr_thread_mutex_unlock(session->lock);
        return APR_ECONNABORTED;
    }
    nghttp3_data_reader dr = {.read_data = h3_session_read_data};
    int rv = nghttp3_conn_submit_response(session->ngh3, h3s->stream_id, nva, nvlen, &dr);
    if (rv == 0)
    {
        h3s->response_submitted = 1;
    }
    else
    {
        h3_stream_response_cancel_locked(h3s);
    }
    apr_thread_mutex_unlock(session->lock);
    if (rv != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, session->s, "nghttp3_conn_submit_response failed for stream %" APR_INT64_T_FMT ": %d", h3s->stream_id, rv);
        return APR_EGENERAL;
    }
    wake_event_thread();
    return APR_SUCCESS;
}

apr_status_t h3_response_start(request_rec* r, h3_conn_ctx_t* h3ctx)
{
    if (!r || !h3ctx || !h3ctx->stream)
    {
        return APR_EINVAL;
    }
    h3_stream* h3s = h3ctx->stream;
    nghttp3_nv nva[64] = {0};
    size_t nvlen = build_response_nva(nva, OSSL_NELEM(nva), r, h3ctx, h3s->pool);
    return submit_response_nva(h3s, nva, nvlen);
}

typedef struct h3_stream_task
{
    h3_session* session;
    h3_stream* h3s;
    conn_rec* c;
} h3_stream_task;

static void set_stream_dispatched(h3_session* session, h3_stream* h3s, int dispatched)
{
    apr_thread_mutex_lock(session->lock);
    h3s->dispatched = dispatched;
    apr_thread_mutex_unlock(session->lock);
}

static void* APR_THREAD_FUNC stream_worker(apr_thread_t* thd, void* data)
{
    h3_stream_task* task = data;
    h3_session* session = task->session;
    h3_stream* h3s = task->h3s;
    conn_rec* c = task->c;
    server_rec* s = session->s;

#if APR_HAS_THREADS
    c->current_thread = thd;
#endif

    request_rec* r = ap_create_request(c);
    if (!r)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "stream_worker: ap_create_request returned NULL");
        set_stream_dispatched(session, h3s, 0);
        apr_atomic_dec32(&session->active_tasks);
        apr_pool_destroy(c->pool);
        return NULL;
    }
    r->log = c->log ? c->log : &s->log;
    r->request_time = apr_time_now();
    r->connection->keepalive = AP_CONN_KEEPALIVE;
    r->protocol = "HTTP/3.0";
    r->proto_num = HTTP_VERSION(3, 0);
    r->method = apr_pstrdup(r->pool, h3s->method ? h3s->method : "GET");
    r->method_number = ap_method_number_of(r->method);
    h3s->r = r;

    if (h3s->path)
    {
        ap_parse_uri(r, h3s->path);
        r->the_request = apr_pstrcat(r->pool, r->method, " ", r->unparsed_uri, " ", r->protocol, NULL);
    }
    if (h3s->authority)
    {
        apr_table_setn(r->headers_in, "Host", apr_pstrdup(r->pool, h3s->authority));
    }
    if (h3s->scheme)
    {
        apr_table_setn(r->headers_in, "Scheme", apr_pstrdup(r->pool, h3s->scheme));
    }
    if (h3s->headers)
    {
        apr_table_overlap(r->headers_in, h3s->headers, APR_OVERLAP_TABLES_SET);
    }
    if (h3s->request_body_len > 0)
    {
        apr_table_setn(r->headers_in, "Content-Length", apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, h3s->request_body_len));

        const char* method = h3s->method ? h3s->method : "?";
        const char* overflow = h3s->request_body_overflow ? " (overflow)" : "";
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "h3 stream %" APR_INT64_T_FMT " %s body=%" APR_SIZE_T_FMT "%s", h3s->stream_id, method, h3s->request_body_len, overflow);
    }

    apr_pool_t* c3reqpool = NULL;
    if (apr_pool_create(&c3reqpool, r->pool) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_pool_create for h3ctx failed");
        set_stream_dispatched(session, h3s, 0);
        apr_atomic_dec32(&session->active_tasks);
        apr_pool_destroy(c->pool);
        return NULL;
    }
    h3_conn_ctx_t* h3ctx = apr_pcalloc(c3reqpool, sizeof(h3_conn_ctx_t));
    h3ctx->c3reqpool = c3reqpool;
    h3ctx->s = s;
    h3ctx->stream = h3s;
    h3_server_conf* h3conf = ap_get_module_config(s->module_config, &http3_module);
    h3ctx->streaming = !h3conf || h3conf->h3_max_response_body_size == H3_MAX_RESPONSE_BODY_SIZE_DEFAULT;
    ap_set_module_config(r->request_config, &http3_module, h3ctx);

    ap_add_output_filter_handle(h3_proto_out_filter_handle, h3ctx, r, r->connection);

    ap_update_vhost_from_headers(r);
    r->per_dir_config = r->server->lookup_defaults;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "before ap_process_request");
    if (r->status != HTTP_OK)
    {
        int err = r->status;
        r->status = HTTP_OK;
        ap_die(err, r);
    }
    else if (h3s->request_body_overflow)
    {
        ap_die(HTTP_REQUEST_ENTITY_TOO_LARGE, r);
    }
    else
    {
        ap_process_request(r);
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "after ap_process_request");

    int status;
    const uint8_t* buffered_body = NULL;
    size_t buffered_body_len = 0;
    apr_status_t response_rv;
    if (h3ctx->response_too_large)
    {
        /* The partial body and its Content-Length no longer agree; send a clean error. */
        static const char oversized_msg[] = "Response exceeded H3MaxResponseBodySize\n";
        status = HTTP_INTERNAL_SERVER_ERROR;
        char* status_str = apr_psprintf(h3s->pool, "%d", status);
        nghttp3_nv nva[2] = {0};
        NV_SET(nva, 0, ":status", status_str);
        NV_SET(nva, 1, "content-type", "text/plain");
        response_rv = submit_response_nva(h3s, nva, OSSL_NELEM(nva));
        buffered_body = (const uint8_t*)oversized_msg;
        buffered_body_len = sizeof(oversized_msg) - 1;
    }
    else
    {
        status = r->status;
        if (status == 0)
        {
            status = 200;
        }
        response_rv = h3_response_start(r, h3ctx);
        if (!h3ctx->streaming && h3ctx->dataheap && h3ctx->dataheaplen > 0)
        {
            buffered_body = (const uint8_t*)h3ctx->dataheap;
            buffered_body_len = h3ctx->dataheaplen;
        }
    }

    if (response_rv == APR_SUCCESS && buffered_body_len > 0)
    {
        response_rv = h3_stream_response_append(h3s, buffered_body, buffered_body_len);
    }
    h3_stream_response_complete(h3s);

    size_t body_len = h3s->response_len;
    int64_t sid = h3s->stream_id;
    if (response_rv != APR_SUCCESS && response_rv != APR_ECONNABORTED)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, response_rv, s, "failed to queue response for stream %" APR_INT64_T_FMT, sid);
    }
    else if (response_rv == APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "queued response for stream %" APR_INT64_T_FMT ", status=%d, body=%" APR_SIZE_T_FMT, sid, status, body_len);
    }

    apr_pool_destroy(c->pool);
    apr_thread_mutex_lock(session->lock);
    h3s->worker_done = 1;
    apr_thread_mutex_unlock(session->lock);
    apr_atomic_dec32(&session->active_tasks);
    return NULL;
}

void h3_process_request(h3_session* session, h3_stream* h3s)
{
    CHECK(session);
    CHECK(h3s);
    server_rec* s = session->s;

    /* Reserve before queuing: the event loop can revisit the session before the worker starts. */
    apr_thread_mutex_lock(session->lock);
    if (h3s->dispatched)
    {
        apr_thread_mutex_unlock(session->lock);
        return;
    }
    h3s->dispatched = 1;
    apr_thread_mutex_unlock(session->lock);

    apr_allocator_t* c_alloc = NULL;
    apr_pool_t* cpool = NULL;
    if (apr_allocator_create(&c_alloc) != APR_SUCCESS || apr_pool_create_ex(&cpool, NULL, NULL, c_alloc) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_pool_create_ex failed for slave conn");
        if (c_alloc)
        {
            apr_allocator_destroy(c_alloc);
        }
        set_stream_dispatched(session, h3s, 0);
        return;
    }
    apr_allocator_owner_set(c_alloc, cpool);

    conn_rec* c = apr_pcalloc(cpool, sizeof(*c));
    *c = *session->c;
    c->pool = cpool;
    c->master = session->c;
    c->sbh = NULL;
    c->requests = apr_array_make(cpool, 4, sizeof(void*));
    c->notes = apr_table_copy(cpool, session->c->notes);
    c->conn_config = ap_create_conn_config(cpool);
    c->bucket_alloc = apr_bucket_alloc_create(cpool);

    module* logio = ap_find_linked_module("mod_logio.c");
    if (logio)
    {
        ap_set_module_config(c->conn_config, logio, apr_pcalloc(cpool, sizeof(h3_logio_config_t)));
    }

    h3_stream_task* task = apr_pcalloc(cpool, sizeof(*task));
    task->session = session;
    task->h3s = h3s;
    task->c = c;

    apr_atomic_inc32(&session->active_tasks);
    apr_status_t rv = apr_thread_pool_push(child_h3_io->h3_worker_pool, stream_worker, task, 0, NULL);
    if (rv != APR_SUCCESS)
    {
        set_stream_dispatched(session, h3s, 0);
        apr_atomic_dec32(&session->active_tasks);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "apr_thread_pool_push failed");
        apr_pool_destroy(cpool);
    }
}
