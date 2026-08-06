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
    apr_pool_t* pchild;
    server_rec* vhost;
    h3_server_conf* conf;
};

static void* APR_THREAD_FUNC port_acquire_thread_fn(apr_thread_t* thread H3_UNUSED, void* data)
{
    struct port_acquire_args* args = data;
    while (!child_stopping)
    {
        int udp_fd = -1;
        apr_status_t rv = h3_socket_open(args->conf->h3_port, args->pchild, &udp_fd);
        if (rv == APR_EAGAIN)
        {
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
        if (h3_io_listen_start(args->pchild, args->vhost, args->conf, udp_fd) != APR_SUCCESS)
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

void h3_child_init(apr_pool_t* pchild, server_rec* s)
{
    server_rec* vhost = NULL;
    h3_server_conf* conf = find_h3_server(s, &vhost);
    if (!conf)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "h3_child_init: no H3 cert/key configured, skipping");
        return;
    }

    int udp_fd = -1;
    apr_status_t rv = h3_socket_open(conf->h3_port, pchild, &udp_fd);
    if (rv == APR_EAGAIN)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, vhost, "h3_child_init: pid=%d port already owned, will keep retrying in background", h3_getpid());
        struct port_acquire_args* args = apr_palloc(pchild, sizeof(*args));
        args->pchild = pchild;
        args->vhost = vhost;
        args->conf = conf;
        apr_threadattr_t* attr = NULL;
        if (apr_threadattr_create(&attr, pchild) != APR_SUCCESS || apr_thread_create(&port_acquire_thread, attr, port_acquire_thread_fn, args, pchild) != APR_SUCCESS)
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
    if (h3_io_listen_start(pchild, vhost, conf, udp_fd) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, vhost, "h3_child_init: h3_io_listen_start failed");
        h3_socket_close(udp_fd);
    }
}

void h3_c1_child_stopping(apr_pool_t* p H3_UNUSED, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_http3: child stopping (graceful=%d)", graceful);
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

#if H3_DEVEL

void h3_c1_child_stopped(apr_pool_t* p H3_UNUSED, int graceful)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "mod_http3: child stopped (graceful=%d)", graceful);
    h3_io_listen_stop(child_h3_io);
}

#endif
