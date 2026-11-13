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

#include <apr_atomic.h>
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
#include "h3_threads.h"
#include "mod_http3.h"

static volatile int child_stopping = 0;

static volatile apr_uint32_t port_acquire_running = 0;

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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, args->vhost, "port acquirer: could not create a pool");
        apr_atomic_set32(&port_acquire_running, 0);
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
    apr_atomic_set32(&port_acquire_running, 0);
    return NULL;
}

static h3_server_conf* find_h3_server(server_rec* s, server_rec** out_server)
{
    h3_server_conf* conf = NULL;
    server_rec* current = s;
    while (current)
    {
        h3_server_conf* tmp = ap_get_module_config(current->module_config, &http3_module);
        /* httpd prepends virtual hosts: the last match is the first one defined, mod_ssl's default. */
        if (tmp && tmp->ssl_ctx)
        {
            conf = tmp;
            *out_server = current;
        }
        current = current->next;
    }
    if (conf)
    {
        conf->host_port = get_server_port(*out_server);
    }
    return conf;
}

/* The threads must be gone before the child pool they run from is
 * destroyed, and before exit() runs OpenSSL's cleanup under them. Most
 * MPMs stop them through the child_stopping hook, but prefork skips that
 * hook when a child exits from a signal handler. */
static apr_status_t child_pool_cleanup(void* data H3_UNUSED)
{
    h3_c1_child_stopping(NULL, 0);
    return APR_SUCCESS;
}

void h3_child_init(apr_pool_t* pchild, server_rec* s)
{
    server_rec* vhost = NULL;
    h3_server_conf* conf = find_h3_server(s, &vhost);
    apr_pool_t* pool = NULL;
    int udp_fd = -1;
    apr_status_t rv;
    if (!conf)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "h3_child_init: no H3 cert/key configured, skipping");
        return;
    }
    apr_pool_pre_cleanup_register(pchild, NULL, child_pool_cleanup);
    if (h3_thread_safe_pool_create(pchild, "h3_child", &pool) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: could not create the HTTP/3 pool");
        return;
    }

    rv = h3_socket_open(conf->h3_port, conf->h3_socket_buffer_size, pool, &udp_fd);
    if (rv == APR_EAGAIN)
    {
        struct port_acquire_args* args = apr_palloc(pool, sizeof(*args));
        apr_threadattr_t* attr = NULL;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, vhost, "h3_child_init: pid=%d port already owned, will keep retrying in background", h3_getpid());
        args->pool = pool;
        args->vhost = vhost;
        args->conf = conf;
        if (apr_threadattr_create(&attr, pool) != APR_SUCCESS || apr_threadattr_detach_set(attr, 1) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: failed to create thread attributes");
        }
        else
        {
            apr_thread_t* thd = NULL;
            apr_atomic_set32(&port_acquire_running, 1);
            if (apr_thread_create(&thd, attr, port_acquire_thread_fn, args, pool) != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: failed to start port acquirer thread");
                apr_atomic_set32(&port_acquire_running, 0);
            }
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

void h3_c1_child_stopping(apr_pool_t* p H3_UNUSED, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_http3: child stopping (graceful=%d)", graceful);
    child_stopping = 1;
    while (apr_atomic_read32(&port_acquire_running))
    {
        apr_sleep(apr_time_from_msec(5));
    }
    if (graceful)
    {
        h3_io_listen_drain(child_h3_io);
        return;
    }
    h3_io_listen_stop(child_h3_io);
}

#if H3_DEVEL

void h3_c1_child_stopped(apr_pool_t* p H3_UNUSED, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_http3: child stopped (graceful=%d)", graceful);
    h3_io_listen_stop(child_h3_io);
}

#endif
