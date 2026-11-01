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

#include <httpd.h>

#include <http_config.h>
#include <http_log.h>

#include <apr_pools.h>
#include <apr_thread_proc.h>
#include <apr_time.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_io.h"
#include "h3_os.h"
#include "h3_server.h"
#include "h3_socket.h"
#include "mod_http3.h"

static volatile int child_stopping = 0;

static apr_thread_t* port_acquire_thread = NULL;

struct port_acquire_args
{
    apr_pool_t* pool;
    server_rec* vhost;
    h3_server_conf* conf;
};

static void* APR_THREAD_FUNC port_acquire_thread_fn(apr_thread_t* thread H3_UNUSED, void* data)
{
    struct port_acquire_args* args = data;
    /* Each attempt allocates; clear them, or retrying leaks for the life
     * of the child. A successful attempt's socket stays in ptry. */
    apr_pool_t* ptry = NULL;
    if (apr_pool_create(&ptry, args->pool) != APR_SUCCESS)
    {
        return NULL;
    }
    while (!child_stopping)
    {
        int udp_fd = -1;
        apr_status_t rv = h3_socket_open(args->conf->h3_port, args->conf->h3_socket_buffer_size, ptry, &udp_fd);
        if (rv == APR_EAGAIN)
        {
            apr_pool_clear(ptry);
            apr_sleep(apr_time_from_msec(H3_PORT_ACQUIRE_RETRY_MS));
            continue;
        }
        if (rv != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, args->vhost, "port acquirer: h3_socket_open failed, giving up");
            break;
        }
        if (child_stopping)
        {
            h3_socket_close(udp_fd);
            break;
        }
        if (h3_io_listen_start(args->pool, args->vhost, args->conf, udp_fd) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, args->vhost, "port acquirer: h3_io_listen_start failed");
            h3_socket_close(udp_fd);
            break;
        }
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, args->vhost, "port acquirer: pid=%d acquired QUIC port after retrying", h3_getpid());
        break;
    }
    return NULL;
}

static h3_server_conf* find_h3_server(server_rec* s, server_rec** out_server)
{
    h3_server_conf* conf = NULL;
    server_rec* current = s;
    while (current)
    {
        h3_server_conf* tmp = ap_get_module_config(current->module_config, &http3_module);
        if (tmp && tmp->h3_cert_path && tmp->h3_key_path && !conf)
        {
            conf = tmp;
            conf->host_port = get_server_port(current);
            *out_server = current;
            break;
        }
        current = current->next;
    }
    return conf;
}

static void stop_child_threads(int graceful);

/* mod_http3 allocates from its own threads, so it gets a pool of its own
 * whose allocator has a mutex. The child pool's allocator may have none:
 * prefork shares it, unlocked, with the pool of every request. */
static apr_status_t create_h3_pool(apr_pool_t* pchild, apr_pool_t** out)
{
    apr_allocator_t* allocator = NULL;
    apr_thread_mutex_t* mutex = NULL;
    apr_status_t rv = apr_allocator_create(&allocator);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }
    rv = apr_pool_create_ex(out, pchild, NULL, allocator);
    if (rv != APR_SUCCESS)
    {
        apr_allocator_destroy(allocator);
        return rv;
    }
    apr_allocator_owner_set(allocator, *out);
    apr_pool_tag(*out, "h3_child");
    rv = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT, *out);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }
    apr_allocator_mutex_set(allocator, mutex);
    return APR_SUCCESS;
}

/* The threads must be gone before the child pool they run from is
 * destroyed, and before exit() runs OpenSSL's cleanup under them. Most
 * MPMs stop them through the child_stopping hook, but prefork skips that
 * hook when a child exits from a signal handler. */
static apr_status_t child_pool_cleanup(void* data H3_UNUSED)
{
    stop_child_threads(0);
    return APR_SUCCESS;
}

void h3_child_init(apr_pool_t* pchild, server_rec* s)
{
    server_rec* vhost = NULL;
    h3_server_conf* conf = find_h3_server(s, &vhost);
    if (!conf)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "h3_child_init: no H3 cert/key configured, skipping");
        return;
    }
    apr_pool_pre_cleanup_register(pchild, NULL, child_pool_cleanup);
    apr_pool_t* pool = NULL;
    if (create_h3_pool(pchild, &pool) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, APLOGNO() "h3_child_init: could not create the HTTP/3 pool");
        return;
    }

    int udp_fd = -1;
    apr_status_t rv = h3_socket_open(conf->h3_port, conf->h3_socket_buffer_size, pool, &udp_fd);
    if (rv == APR_EAGAIN)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, vhost, "h3_child_init: pid=%d port already owned, will keep retrying in background", h3_getpid());
        struct port_acquire_args* args = apr_palloc(pool, sizeof(*args));
        args->pool = pool;
        args->vhost = vhost;
        args->conf = conf;
        apr_threadattr_t* attr = NULL;
        if (apr_threadattr_create(&attr, pool) != APR_SUCCESS || apr_thread_create(&port_acquire_thread, attr, port_acquire_thread_fn, args, pool) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: failed to start port acquirer thread");
            port_acquire_thread = NULL;
        }
        return;
    }
    if (rv != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: h3_socket_open failed");
        return;
    }
    if (h3_io_listen_start(pool, vhost, conf, udp_fd) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: h3_io_listen_start failed");
        h3_socket_close(udp_fd);
    }
}

static void stop_child_threads(int graceful)
{
    child_stopping = 1;
    if (port_acquire_thread)
    {
        apr_status_t ignored;
        apr_thread_join(&ignored, port_acquire_thread);
        port_acquire_thread = NULL;
    }
    if (graceful)
    {
        h3_io_listen_drain(child_h3_io);
        return;
    }
    h3_io_listen_stop(child_h3_io);
}

void h3_c1_child_stopping(apr_pool_t* p H3_UNUSED, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_http3: child stopping (graceful=%d)", graceful);
    stop_child_threads(graceful);
}

#if H3_DEVEL

void h3_c1_child_stopped(apr_pool_t* p H3_UNUSED, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_http3: child stopped (graceful=%d)", graceful);
    h3_io_listen_stop(child_h3_io);
}

#endif
