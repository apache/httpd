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

#include <unistd.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_io.h"
#include "h3_server.h"
#include "h3_socket.h"
#include "mod_http3.h"

static h3_server_conf* find_h3_server(server_rec* s, server_rec** out_server)
{
    h3_server_conf* conf = NULL;
    server_rec* current = s;
    while (current)
    {
        h3_server_conf* tmp = ap_get_module_config(current->module_config, &http3_module);
        if (tmp && tmp->cert_path && tmp->key_path && !conf)
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, vhost, "h3_child_init: pid=%d skipping QUIC (port already owned)", getpid());
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

void h3_c1_child_stopping(apr_pool_t* p, int graceful)
{
    (void)p;
    (void)graceful;
    h3_io_listen_stop(child_h3_io);
}
