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

#include <ap_listen.h>
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

#ifdef __linux__
    #include <stddef.h>
    #include <stdio.h>
    #include <sys/un.h>
#endif

static volatile int child_stopping = 0;

static apr_thread_t* port_acquire_thread = NULL;

struct port_acquire_args
{
    apr_pool_t* pchild;
    server_rec* vhost;
    h3_server_conf* conf;
};

#ifdef __linux__
/* The parent binds the QUIC sockets while still privileged and keeps them across restarts.
 * One SO_REUSEPORT socket per httpd listener bucket (ListenCoresBucketsRatio), so the kernel hash stays stable when children come and go. */
typedef struct
{
    apr_pool_t* pool;
    int* fds;
    int n;
    apr_port_t port;
} h3_parent_socket;

static h3_parent_socket* parent_socket(server_rec* s)
{
    void* ps = NULL;
    apr_pool_userdata_get(&ps, "mod_http3.parent_socket", s->process->pool);
    return ps;
}

/* The children inherit them; the child that binds the abstract name of a bucket owns its socket, and exit releases it. */
static int owner_lock = -1;

static int own_port(apr_port_t port, int bucket)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    int n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1, "mod_http3.%d.%d", (int)port, bucket);
    if (owner_lock < 0)
    {
        owner_lock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    }
    return owner_lock >= 0 && bind(owner_lock, (struct sockaddr*)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + (size_t)n)) == 0;
}
#endif

/* Get this child the QUIC socket, or APR_EAGAIN while another child has it. */
static apr_status_t acquire_port(apr_pool_t* pchild, server_rec* s, h3_server_conf* conf, int* fd)
{
#ifdef __linux__
    h3_parent_socket* ps = parent_socket(s);
    if (ps && ps->n && ps->port == conf->h3_port)
    {
        for (int i = 0; i < ps->n; i++)
        {
            if (own_port(ps->port, i))
            {
                *fd = ps->fds[i];
                return APR_SUCCESS;
            }
        }
        return APR_EAGAIN;
    }
#endif
    return h3_socket_open(conf->h3_port, conf->h3_socket_buffer_size, pchild, 0, fd);
}

/* Give the port back when this child cannot serve it after all. */
static void release_port(int fd)
{
    h3_socket_close(fd);
#ifdef __linux__
    if (owner_lock >= 0)
    {
        close(owner_lock);
        owner_lock = -1;
    }
#endif
}

static void* APR_THREAD_FUNC port_acquire_thread_fn(apr_thread_t* thread H3_UNUSED, void* data)
{
    struct port_acquire_args* args = data;
    while (!child_stopping)
    {
        int udp_fd = -1;
        apr_status_t rv = acquire_port(args->pchild, args->vhost, args->conf, &udp_fd);
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
            release_port(udp_fd);
            break;
        }
        if (h3_io_listen_start(args->pchild, args->vhost, args->conf, udp_fd) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, args->vhost, "port acquirer: h3_io_listen_start failed");
            release_port(udp_fd);
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
    apr_status_t rv = acquire_port(pchild, vhost, conf, &udp_fd);
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
        release_port(udp_fd);
    }
}

void h3_server_post_config(server_rec* s)
{
#ifdef __linux__
    h3_parent_socket* ps = parent_socket(s);
    if (!ps)
    {
        ps = apr_pcalloc(s->process->pool, sizeof(*ps));
        apr_pool_userdata_set(ps, "mod_http3.parent_socket", apr_pool_cleanup_null, s->process->pool);
    }
    server_rec* vhost = NULL;
    h3_server_conf* conf = find_h3_server(s, &vhost);
    int n = ap_num_listen_buckets > 0 ? ap_num_listen_buckets : 1;
    /* ponytail: a new port or bucket count binds again. An old single socket without SO_REUSEPORT blocks this until its children stop. */
    if (ps->n && (!conf || conf->h3_port != ps->port || n != ps->n))
    {
        apr_pool_destroy(ps->pool); /* closes the old sockets */
        ps->pool = NULL;
        ps->n = 0;
    }
    if (!conf || ps->n)
    {
        return;
    }
    int ok = apr_pool_create(&ps->pool, s->process->pool) == APR_SUCCESS;
    if (ok)
    {
        ps->fds = apr_palloc(ps->pool, sizeof(int) * (size_t)n);
    }
    for (int i = 0; ok && i < n; i++)
    {
        ok = h3_socket_open(conf->h3_port, conf->h3_socket_buffer_size, ps->pool, n > 1, &ps->fds[i]) == APR_SUCCESS;
    }
    if (!ok)
    {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, vhost, "mod_http3: binding UDP port %d before the privilege drop failed; the children bind it themselves", (int)conf->h3_port);
        if (ps->pool)
        {
            apr_pool_destroy(ps->pool);
        }
        ps->pool = NULL;
        return;
    }
    ps->n = n;
    ps->port = conf->h3_port;
#else
    (void)s;
#endif
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
