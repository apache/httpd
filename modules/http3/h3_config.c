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

#include <ap_mpm.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_protocol.h>

#include <apr_cstr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include <stdint.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "h3_os.h"
#include "h3_request.h"
#include "h3_server.h"
#include "mod_http3.h"
#include "quic/detail/h3q_tls.h"

apr_port_t get_server_port(const server_rec* s)
{
    for (const server_addr_rec* sar = s->addrs; sar != NULL; sar = sar->next)
    {
        if (sar->host_port != 0)
        {
            return sar->host_port;
        }
    }
    return 0;
}

void* h3_create_server_config(apr_pool_t* p, server_rec* s H3_UNUSED)
{
    return apr_pcalloc(p, sizeof(h3_server_conf));
}

void* h3_merge_server_config(apr_pool_t* p, void* base_conf, void* new_conf)
{
    h3_server_conf* merged = apr_pcalloc(p, sizeof(h3_server_conf));
    h3_server_conf* base = (h3_server_conf*)base_conf;
    h3_server_conf* new = (h3_server_conf*)new_conf;

    merged->h3_port = new->h3_port ? new->h3_port : base->h3_port;
    merged->h3_max_concurrent_streams = new->h3_max_concurrent_streams ? new->h3_max_concurrent_streams : base->h3_max_concurrent_streams;
    merged->h3_max_connections = new->h3_max_connections ? new->h3_max_connections : base->h3_max_connections;
    merged->h3_stream_buffer_size = new->h3_stream_buffer_size ? new->h3_stream_buffer_size : base->h3_stream_buffer_size;
    merged->h3_max_request_body_size = new->h3_max_request_body_size ? new->h3_max_request_body_size : base->h3_max_request_body_size;
    merged->h3_max_response_body_size = new->h3_max_response_body_size ? new->h3_max_response_body_size : base->h3_max_response_body_size;
    merged->h3_alt_svc = new->h3_alt_svc != H3_FLAG_UNSET ? new->h3_alt_svc : base->h3_alt_svc;
    merged->h3_address_validation = new->h3_address_validation != H3_FLAG_UNSET ? new->h3_address_validation : base->h3_address_validation;
    merged->h3_alt_svc_max_age = new->h3_alt_svc_max_age ? new->h3_alt_svc_max_age : base->h3_alt_svc_max_age;
    merged->h3_handshake_timeout = new->h3_handshake_timeout ? new->h3_handshake_timeout : base->h3_handshake_timeout;
    merged->h3_idle_timeout = new->h3_idle_timeout ? new->h3_idle_timeout : base->h3_idle_timeout;
    merged->h3_socket_buffer_size = new->h3_socket_buffer_size ? new->h3_socket_buffer_size : base->h3_socket_buffer_size;
    merged->h3_max_window = new->h3_max_window ? new->h3_max_window : base->h3_max_window;
    merged->h3_session_tickets = new->h3_session_tickets != H3_FLAG_UNSET ? new->h3_session_tickets : base->h3_session_tickets;
    merged->h3_early_data = new->h3_early_data != H3_FLAG_UNSET ? new->h3_early_data : base->h3_early_data;
    merged->h3_stream_timeout = new->h3_stream_timeout ? new->h3_stream_timeout : base->h3_stream_timeout;
    merged->h3_max_stream_errors = new->h3_max_stream_errors ? new->h3_max_stream_errors : base->h3_max_stream_errors;
    merged->h3_qpack_capacity_set = new->h3_qpack_capacity_set ? new->h3_qpack_capacity_set : base->h3_qpack_capacity_set;
    merged->h3_qpack_table_capacity = new->h3_qpack_capacity_set ? new->h3_qpack_table_capacity : base->h3_qpack_table_capacity;
    merged->h3_qpack_blocked_set = new->h3_qpack_blocked_set ? new->h3_qpack_blocked_set : base->h3_qpack_blocked_set;
    merged->h3_qpack_blocked_streams = new->h3_qpack_blocked_set ? new->h3_qpack_blocked_streams : base->h3_qpack_blocked_streams;
    merged->h3_min_workers = new->h3_min_workers ? new->h3_min_workers : base->h3_min_workers;
    merged->h3_max_workers = new->h3_max_workers ? new->h3_max_workers : base->h3_max_workers;
    merged->h3_max_worker_idle_seconds = new->h3_max_worker_idle_seconds ? new->h3_max_worker_idle_seconds : base->h3_max_worker_idle_seconds;

    return merged;
}

/// Value of an MPM query, or -1 when the active MPM does not answer it.
static int mpm_query(int code)
{
    int value = 0;
    return ap_mpm_query(code, &value) == APR_SUCCESS ? value : -1;
}

static const char* set_h3_port(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3Port: empty port number";
    }
    apr_int64_t port = 0;
    apr_status_t rv = apr_cstr_atoi64(&port, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3Port: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3Port: '%s' is out of representable range", arg);
    }
    if (port < 1 || port > 65535)
    {
        return apr_psprintf(cmd->pool, "H3Port: '%s' is out of allowed range (1-65535)", arg);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_port = (apr_port_t)port;
    return NULL;
}

static const char* set_h3_max_concurrent_streams(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxConcurrentStreams: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxConcurrentStreams: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxConcurrentStreams: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > UINT16_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxConcurrentStreams: '%s' is out of allowed range (1-%u)", arg, (unsigned)UINT16_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_concurrent_streams = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_max_connections(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxConnections: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxConnections: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxConnections: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_MAX_CONNECTIONS_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxConnections: '%s' is out of allowed range (1-%u)", arg, (unsigned)H3_MAX_CONNECTIONS_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_connections = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_stream_buffer_size(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3StreamBufferSize: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3StreamBufferSize: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3StreamBufferSize: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_STREAM_BUFFER_SIZE_MAX)
    {
        return apr_psprintf(cmd->pool, "H3StreamBufferSize: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_STREAM_BUFFER_SIZE_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_stream_buffer_size = (apr_size_t)val;
    return NULL;
}

static const char* set_h3_max_window(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    apr_uint64_t val = 0;
    if (apr_cstr_atoui64(&val, arg) != APR_SUCCESS || val < H3_MAX_WINDOW_MIN || val > H3_MAX_WINDOW_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxWindow: '%s' must be a byte count from %lu to %lu", arg, (unsigned long)H3_MAX_WINDOW_MIN, (unsigned long)H3_MAX_WINDOW_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_window = (apr_size_t)val;
    return NULL;
}

static const char* set_h3_socket_buffer_size(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3SocketBufferSize: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3SocketBufferSize: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3SocketBufferSize: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_SOCKET_BUFFER_SIZE_MAX)
    {
        return apr_psprintf(cmd->pool, "H3SocketBufferSize: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_SOCKET_BUFFER_SIZE_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_socket_buffer_size = (apr_size_t)val;
    return NULL;
}

static const char* set_h3_stream_timeout(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3StreamTimeout: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3StreamTimeout: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3StreamTimeout: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_STREAM_TIMEOUT_MAX)
    {
        return apr_psprintf(cmd->pool, "H3StreamTimeout: '%s' is out of allowed range (1-%u)", arg, (unsigned)H3_STREAM_TIMEOUT_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_stream_timeout = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_max_stream_errors(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxStreamErrors: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxStreamErrors: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxStreamErrors: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_MAX_STREAM_ERRORS_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxStreamErrors: '%s' is out of allowed range (1-%u)", arg, (unsigned)H3_MAX_STREAM_ERRORS_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_stream_errors = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_qpack_table_capacity(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3QpackTableCapacity: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3QpackTableCapacity: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3QpackTableCapacity: '%s' is out of representable range", arg);
    }
    if (val > H3_QPACK_TABLE_CAPACITY_MAX)
    {
        return apr_psprintf(cmd->pool, "H3QpackTableCapacity: '%s' is out of allowed range (0-%lu)", arg, (unsigned long)H3_QPACK_TABLE_CAPACITY_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_qpack_table_capacity = (apr_uint32_t)val;
    conf->h3_qpack_capacity_set = 1;
    return NULL;
}

static const char* set_h3_qpack_blocked_streams(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3QpackBlockedStreams: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3QpackBlockedStreams: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3QpackBlockedStreams: '%s' is out of representable range", arg);
    }
    if (val > H3_QPACK_BLOCKED_STREAMS_MAX)
    {
        return apr_psprintf(cmd->pool, "H3QpackBlockedStreams: '%s' is out of allowed range (0-%lu)", arg, (unsigned long)H3_QPACK_BLOCKED_STREAMS_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_qpack_blocked_streams = (apr_uint32_t)val;
    conf->h3_qpack_blocked_set = 1;
    return NULL;
}

static const char* set_h3_min_workers(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MinWorkers: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MinWorkers: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MinWorkers: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_WORKERS_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MinWorkers: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_WORKERS_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_min_workers = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_max_workers(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxWorkers: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxWorkers: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxWorkers: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_WORKERS_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxWorkers: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_WORKERS_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_workers = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_max_worker_idle_seconds(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxWorkerIdleSeconds: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxWorkerIdleSeconds: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxWorkerIdleSeconds: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_MAX_WORKER_IDLE_SECONDS_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxWorkerIdleSeconds: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_MAX_WORKER_IDLE_SECONDS_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_worker_idle_seconds = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_max_request_body_size(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxRequestBodySize: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxRequestBodySize: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxRequestBodySize: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_MAX_REQUEST_BODY_SIZE_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxRequestBodySize: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_MAX_REQUEST_BODY_SIZE_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_request_body_size = (apr_size_t)val;
    return NULL;
}

static const char* set_h3_max_response_body_size(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3MaxResponseBodySize: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3MaxResponseBodySize: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3MaxResponseBodySize: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_MAX_RESPONSE_BODY_SIZE_MAX)
    {
        return apr_psprintf(cmd->pool, "H3MaxResponseBodySize: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_MAX_RESPONSE_BODY_SIZE_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_max_response_body_size = (apr_size_t)val;
    return NULL;
}

static const char* set_h3_handshake_timeout(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3HandshakeTimeout: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3HandshakeTimeout: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3HandshakeTimeout: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_HANDSHAKE_TIMEOUT_MAX)
    {
        return apr_psprintf(cmd->pool, "H3HandshakeTimeout: '%s' is out of allowed range (1-%u)", arg, (unsigned)H3_HANDSHAKE_TIMEOUT_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_handshake_timeout = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_idle_timeout(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3IdleTimeout: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3IdleTimeout: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3IdleTimeout: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_IDLE_TIMEOUT_MAX)
    {
        return apr_psprintf(cmd->pool, "H3IdleTimeout: '%s' is out of allowed range (1-%u)", arg, (unsigned)H3_IDLE_TIMEOUT_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_idle_timeout = (apr_uint32_t)val;
    return NULL;
}

static const char* set_h3_session_tickets(cmd_parms* cmd, void* dummy H3_UNUSED, int flag)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_session_tickets = flag ? H3_FLAG_ON : H3_FLAG_OFF;
    return NULL;
}

static const char* set_h3_early_data(cmd_parms* cmd, void* dummy H3_UNUSED, int flag)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_early_data = flag ? H3_FLAG_ON : H3_FLAG_OFF;
    return NULL;
}

static const char* set_h3_alt_svc(cmd_parms* cmd, void* dummy H3_UNUSED, int flag)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_alt_svc = flag ? H3_FLAG_ON : H3_FLAG_OFF;
    return NULL;
}

static const char* set_h3_address_validation(cmd_parms* cmd, void* dummy H3_UNUSED, int flag)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_address_validation = flag ? H3_FLAG_ON : H3_FLAG_OFF;
    return NULL;
}

static const char* set_h3_alt_svc_max_age(cmd_parms* cmd, void* dummy H3_UNUSED, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3AltSvcMaxAge: empty value";
    }
    apr_uint64_t val = 0;
    apr_status_t rv = apr_cstr_atoui64(&val, arg);
    if (rv == APR_EINVAL)
    {
        return apr_psprintf(cmd->pool, "H3AltSvcMaxAge: '%s' is not a number", arg);
    }
    if (rv == APR_ERANGE)
    {
        return apr_psprintf(cmd->pool, "H3AltSvcMaxAge: '%s' is out of representable range", arg);
    }
    if (val == 0 || val > H3_ALT_SVC_MAX_AGE_MAX)
    {
        return apr_psprintf(cmd->pool, "H3AltSvcMaxAge: '%s' is out of allowed range (1-%lu)", arg, (unsigned long)H3_ALT_SVC_MAX_AGE_MAX);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_alt_svc_max_age = (apr_uint32_t)val;
    return NULL;
}

static apr_status_t ssl_ctx_cleanup(void* data)
{
    SSL_CTX_free(data);
    return APR_SUCCESS;
}

int h3_ssl_add_cert_files(server_rec* s, apr_pool_t* p, apr_array_header_t* cert_files, apr_array_header_t* key_files)
{
    CHECK(s && p && cert_files && key_files, return DECLINED;);
    h3_server_conf* conf = ap_get_module_config(s->module_config, &http3_module);
    if (!conf || ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG || !ap_is_allowed_protocol(NULL, NULL, s, "h3") || cert_files->nelts == 0)
    {
        return DECLINED;
    }
    /* Still privileged here, so a root-only key loads the way it does for mod_ssl. */
    char err[H3Q_ERRLEN] = {0};
    conf->ssl_ctx = h3q_tls_ctx_create((const char* const*)cert_files->elts, (size_t)cert_files->nelts, (const char* const*)key_files->elts, (size_t)key_files->nelts, conf->h3_session_tickets != H3_FLAG_OFF, err, sizeof(err));
    if (!conf->ssl_ctx)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: %s", err);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_pool_cleanup_register(p, conf->ssl_ctx, ssl_ctx_cleanup, apr_pool_cleanup_null);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "mod_http3: serving HTTP/3 with mod_ssl certificate %s", APR_ARRAY_IDX(cert_files, 0, const char*));
    return DECLINED;
}

/** One HTTP/3 host name and the TLS context that carries its certificate. */
typedef struct
{
    const char* name;
    SSL_CTX* ctx;
} h3_sni_host;

/// cert_cb: serve each host its own certificate over one listener, selected by SNI.
/// SSL_set_SSL_CTX does not switch the certificate of a QUIC connection; applying
/// the matched host's certificate, key and chain to the connection does.
static int h3_sni_select_cert(SSL* ssl, void* arg)
{
    const apr_array_header_t* hosts = arg;
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    for (int i = 0; sni && i < hosts->nelts; i++)
    {
        const h3_sni_host* h = &APR_ARRAY_IDX(hosts, i, h3_sni_host);
        /* httpd's ServerAlias matcher: wildcards for wild_names, exact otherwise. */
        if (ap_strcasecmp_match(sni, h->name) == 0)
        {
            STACK_OF(X509)* chain = NULL;
            SSL_CTX_get0_chain_certs(h->ctx, &chain);
            return SSL_use_certificate(ssl, SSL_CTX_get0_certificate(h->ctx)) == 1 && SSL_use_PrivateKey(ssl, SSL_CTX_get0_privatekey(h->ctx)) == 1 && (!chain || SSL_set1_chain(ssl, chain) == 1);
        }
    }
    return 1; /* no match: the listener's own certificate */
}

int h3_post_config(apr_pool_t* p, apr_pool_t* plog H3_UNUSED, apr_pool_t* ptemp, server_rec* s)
{
    CHECK(p);
    CHECK(ptemp);
    CHECK(s);
    h3_server_conf* conf = NULL;
    server_rec* owner = NULL;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    {
        return OK;
    }

    /* Names of every HTTP/3 host, so the listener can pick a certificate by SNI. */
    apr_array_header_t* sni = apr_array_make(p, 4, sizeof(h3_sni_host));

    for (server_rec* vs = s; vs; vs = vs->next)
    {
        h3_server_conf* vc = ap_get_module_config(vs->module_config, &http3_module);
        if (vc->ssl_ctx)
        {
            if (vs->server_hostname)
            {
                h3_sni_host* e = apr_array_push(sni);
                e->name = vs->server_hostname;
                e->ctx = vc->ssl_ctx;
            }
            /* ServerAlias: httpd keeps exact names in names and wildcards in wild_names. */
            for (int i = 0; vs->names && i < vs->names->nelts; i++)
            {
                h3_sni_host* e = apr_array_push(sni);
                e->name = APR_ARRAY_IDX(vs->names, i, const char*);
                e->ctx = vc->ssl_ctx;
            }
            for (int i = 0; vs->wild_names && i < vs->wild_names->nelts; i++)
            {
                h3_sni_host* e = apr_array_push(sni);
                e->name = APR_ARRAY_IDX(vs->wild_names, i, const char*);
                e->ctx = vc->ssl_ctx;
            }
            vc->host_port = get_server_port(vs);
            if (vc->h3_port == 0)
            {
                vc->h3_port = vc->host_port;
            }
            if (vc->h3_max_concurrent_streams == 0)
            {
                vc->h3_max_concurrent_streams = H3_MAX_CONCURRENT_STREAMS_DEFAULT;
            }
            if (vc->h3_max_connections == 0)
            {
                vc->h3_max_connections = H3_MAX_CONNECTIONS_DEFAULT;
            }
            if (vc->h3_stream_buffer_size == 0)
            {
                vc->h3_stream_buffer_size = H3_STREAM_BUFFER_SIZE_DEFAULT;
            }
            if (vc->h3_socket_buffer_size == 0)
            {
                vc->h3_socket_buffer_size = H3_SOCKET_BUFFER_SIZE_DEFAULT;
            }
            if (vc->h3_max_window == 0)
            {
                vc->h3_max_window = H3_MAX_WINDOW_DEFAULT;
            }
            if (vc->h3_max_stream_errors == 0)
            {
                vc->h3_max_stream_errors = H3_MAX_STREAM_ERRORS_DEFAULT;
            }
            if (!vc->h3_qpack_capacity_set)
            {
                vc->h3_qpack_table_capacity = H3_QPACK_TABLE_CAPACITY_DEFAULT;
            }
            if (!vc->h3_qpack_blocked_set)
            {
                vc->h3_qpack_blocked_streams = H3_QPACK_BLOCKED_STREAMS_DEFAULT;
            }
            if (vc->h3_min_workers == 0)
            {
                vc->h3_min_workers = H3_MIN_WORKERS_DEFAULT;
            }
            if (vc->h3_max_workers == 0)
            {
                vc->h3_max_workers = H3_MAX_WORKERS_DEFAULT;
            }
            if (vc->h3_max_workers < vc->h3_min_workers)
            {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, vs, "mod_http3: H3MaxWorkers (%u) is below H3MinWorkers (%u); raising it to match", (unsigned)vc->h3_max_workers, (unsigned)vc->h3_min_workers);
                vc->h3_max_workers = vc->h3_min_workers;
            }
            if (vc->h3_max_worker_idle_seconds == 0)
            {
                vc->h3_max_worker_idle_seconds = H3_MAX_WORKER_IDLE_SECONDS_DEFAULT;
            }
            if (vc->h3_max_request_body_size == 0)
            {
                vc->h3_max_request_body_size = H3_MAX_REQUEST_BODY_SIZE_DEFAULT;
            }
            if (vc->h3_max_response_body_size == 0)
            {
                vc->h3_max_response_body_size = H3_MAX_RESPONSE_BODY_SIZE_DEFAULT;
            }
            if (vc->h3_alt_svc == H3_FLAG_UNSET)
            {
                vc->h3_alt_svc = H3_FLAG_ON;
            }
            if (vc->h3_address_validation == H3_FLAG_UNSET)
            {
                vc->h3_address_validation = H3_FLAG_ON;
            }
            if (vc->h3_session_tickets == H3_FLAG_UNSET)
            {
                vc->h3_session_tickets = H3_FLAG_ON;
            }
            if (vc->h3_early_data == H3_FLAG_UNSET)
            {
                vc->h3_early_data = H3_FLAG_OFF;
            }
            if (vc->h3_alt_svc_max_age == 0)
            {
                vc->h3_alt_svc_max_age = H3_ALT_SVC_MAX_AGE_DEFAULT;
            }
            if (vc->h3_handshake_timeout == 0)
            {
                vc->h3_handshake_timeout = H3_HANDSHAKE_TIMEOUT_DEFAULT;
            }
            if (vc->h3_idle_timeout == 0)
            {
                vc->h3_idle_timeout = H3_IDLE_TIMEOUT_DEFAULT;
            }
            /* httpd prepends virtual hosts, so the last match is the first one defined:
             * it owns the listener, as it is mod_ssl's default; the rest still advertise it. */
            conf = vc;
            owner = vs;
        }
    }

    if (!conf)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: no host serves HTTP/3: add h3 to Protocols on a host with SSLEngine on");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, owner, "h3_post_config: pid=%d h3_port=%d mpm=%s threaded=%d forked=%d max_threads=%d", h3_getpid(), (int)conf->h3_port, ap_show_mpm(), mpm_query(AP_MPMQ_IS_THREADED), mpm_query(AP_MPMQ_IS_FORKED), mpm_query(AP_MPMQ_MAX_THREADS));

    /* The listener serves conf's certificate by default and swaps by SNI. */
    SSL_CTX_set_cert_cb(conf->ssl_ctx, h3_sni_select_cert, sni);

    h3_request_init();
    h3_server_post_config(s);
    return OK;
}

void* h3_create_dir_config(apr_pool_t* p, char* dir H3_UNUSED)
{
    CHECK(p);
    return apr_pcalloc(p, 1);
}

void* h3_merge_dir_config(apr_pool_t* p H3_UNUSED, void* base, void* add H3_UNUSED)
{
    CHECK(base);
    return base;
}

const command_rec h3_cmds[] = {
    AP_INIT_TAKE1("H3Port", set_h3_port, NULL, RSRC_CONF, "UDP port to listen on for QUIC/HTTP-3 (default: same as main server)"),
    AP_INIT_TAKE1("H3MaxConcurrentStreams", set_h3_max_concurrent_streams, NULL, RSRC_CONF, "Maximum number of concurrent HTTP/3 streams per connection (default: 100)"),
    AP_INIT_TAKE1("H3MaxConnections", set_h3_max_connections, NULL, RSRC_CONF, "Maximum concurrent QUIC/HTTP/3 connections per child process (default: 256)"),
    AP_INIT_TAKE1("H3StreamBufferSize", set_h3_stream_buffer_size, NULL, RSRC_CONF, "Per-stream request and streaming-response buffer size in bytes (default: 65536)"),
    AP_INIT_TAKE1("H3MaxRequestBodySize", set_h3_max_request_body_size, NULL, RSRC_CONF, "Maximum HTTP/3 request body size in bytes, fully buffered in memory (default: 10485760)"),
    AP_INIT_FLAG("H3AltSvc", set_h3_alt_svc, NULL, RSRC_CONF, "Whether to advertise HTTP/3 support via an Alt-Svc response header, required for browser discovery (default: on)"),
    AP_INIT_TAKE1("H3AltSvcMaxAge", set_h3_alt_svc_max_age, NULL, RSRC_CONF, "Seconds a client may cache the Alt-Svc HTTP/3 advertisement for (default: 86400)"),
    AP_INIT_TAKE1("H3HandshakeTimeout", set_h3_handshake_timeout, NULL, RSRC_CONF, "Timeout in seconds for QUIC handshakes to complete (default: 10)"),
    AP_INIT_TAKE1("H3IdleTimeout", set_h3_idle_timeout, NULL, RSRC_CONF, "Idle timeout in seconds for QUIC connections (default: 300)"),
    AP_INIT_TAKE1("H3MaxResponseBodySize", set_h3_max_response_body_size, NULL, RSRC_CONF, "Maximum HTTP/3 response body size in bytes; an explicit limit enables bounded whole-response buffering (default: unlimited streaming)"),
    AP_INIT_FLAG("H3AddressValidation", set_h3_address_validation, NULL, RSRC_CONF, "Whether to validate client addresses with a QUIC Retry packet before accepting a connection (default: on)"),
    AP_INIT_TAKE1("H3SocketBufferSize", set_h3_socket_buffer_size, NULL, RSRC_CONF, "Bytes requested for the QUIC socket send and receive buffers; the OS may grant less (default: 2097152)"),
    AP_INIT_TAKE1("H3MaxWindow", set_h3_max_window, NULL, RSRC_CONF, "Largest flow-control window, per connection and per stream, that autotuning may grow a client upload window to (default: 6291456)"),
    AP_INIT_FLAG("H3SessionTickets", set_h3_session_tickets, NULL, RSRC_CONF, "Whether to issue TLS session tickets so returning clients can resume instead of running a full handshake (default: on)"),
    AP_INIT_FLAG("H3EarlyData", set_h3_early_data, NULL, RSRC_CONF, "Whether to accept 0-RTT request data on resumed connections; unsafe methods wait for the handshake (default: off)"),
    AP_INIT_TAKE1("H3StreamTimeout", set_h3_stream_timeout, NULL, RSRC_CONF, "Seconds a response may make no progress before the stream is aborted (default: the server Timeout)"),
    AP_INIT_TAKE1("H3MaxStreamErrors", set_h3_max_stream_errors, NULL, RSRC_CONF, "Stream errors one connection may cause before it is closed with H3_EXCESSIVE_LOAD (default: 8)"),
    AP_INIT_TAKE1("H3QpackTableCapacity", set_h3_qpack_table_capacity, NULL, RSRC_CONF, "Bytes of QPACK dynamic table a client may use for request headers; 0 disables it (default: 4096)"),
    AP_INIT_TAKE1("H3QpackBlockedStreams", set_h3_qpack_blocked_streams, NULL, RSRC_CONF, "Requests that may wait on a QPACK table insert that has not arrived; each one is unbounded memory (default: 0)"),
    AP_INIT_TAKE1("H3MinWorkers", set_h3_min_workers, NULL, RSRC_CONF, "Request worker threads started per child process (default: 16)"),
    AP_INIT_TAKE1("H3MaxWorkers", set_h3_max_workers, NULL, RSRC_CONF, "Maximum request worker threads per child process (default: 64)"),
    AP_INIT_TAKE1("H3MaxWorkerIdleSeconds", set_h3_max_worker_idle_seconds, NULL, RSRC_CONF, "Seconds an idle request worker is kept before it exits (default: 600)"),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL),
};
