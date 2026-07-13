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
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>

#include <apr_cstr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include <stdint.h>
#include <unistd.h>

#include "h3.h"
#include "h3_check.h"
#include "h3_config.h"
#include "mod_http3.h"

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

void* h3_create_server_config(apr_pool_t* p, server_rec* /*s*/)
{
    return apr_pcalloc(p, sizeof(h3_server_conf));
}

void* h3_merge_server_config(apr_pool_t* p, void* base_conf, void* new_conf)
{
    h3_server_conf* merged = apr_pcalloc(p, sizeof(h3_server_conf));
    h3_server_conf* base = (h3_server_conf*)base_conf;
    h3_server_conf* new = (h3_server_conf*)new_conf;

    merged->h3_cert_path = new->h3_cert_path ? new->h3_cert_path : base->h3_cert_path;
    merged->h3_key_path = new->h3_key_path ? new->h3_key_path : base->h3_key_path;
    merged->h3_port = new->h3_port ? new->h3_port : base->h3_port;
    merged->h3_max_concurrent_streams = new->h3_max_concurrent_streams ? new->h3_max_concurrent_streams : base->h3_max_concurrent_streams;
    merged->h3_max_connections = new->h3_max_connections ? new->h3_max_connections : base->h3_max_connections;
    merged->h3_stream_buffer_size = new->h3_stream_buffer_size ? new->h3_stream_buffer_size : base->h3_stream_buffer_size;
    merged->h3_max_request_body_size = new->h3_max_request_body_size ? new->h3_max_request_body_size : base->h3_max_request_body_size;
    merged->h3_alt_svc = new->h3_alt_svc != H3_FLAG_UNSET ? new->h3_alt_svc : base->h3_alt_svc;
    merged->h3_alt_svc_max_age = new->h3_alt_svc_max_age ? new->h3_alt_svc_max_age : base->h3_alt_svc_max_age;

    return merged;
}

static const char* set_string(cmd_parms* cmd, const char* arg, const char* field)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    if (!conf)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server, "mod_http3: server config missing in directive");
        return "mod_http3: internal error: no server config";
    }
    *(const char**)((char*)conf + (apr_size_t)field) = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char* set_h3_cert_path(cmd_parms* cmd, void* /*dummy*/, const char* arg)
{
    return set_string(cmd, arg, (const char*)offsetof(h3_server_conf, h3_cert_path));
}

static const char* set_h3_key_path(cmd_parms* cmd, void* /*dummy*/, const char* arg)
{
    return set_string(cmd, arg, (const char*)offsetof(h3_server_conf, h3_key_path));
}

static const char* set_h3_port(cmd_parms* cmd, void* /*dummy*/, const char* arg)
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

static const char* set_h3_max_concurrent_streams(cmd_parms* cmd, void* /*dummy*/, const char* arg)
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

static const char* set_h3_max_connections(cmd_parms* cmd, void* /*dummy*/, const char* arg)
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

static const char* set_h3_stream_buffer_size(cmd_parms* cmd, void* /*dummy*/, const char* arg)
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

static const char* set_h3_max_request_body_size(cmd_parms* cmd, void* /*dummy*/, const char* arg)
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

static const char* set_h3_alt_svc(cmd_parms* cmd, void* /*dummy*/, int flag)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    CHECK(conf);
    conf->h3_alt_svc = flag ? H3_FLAG_ON : H3_FLAG_OFF;
    return NULL;
}

static const char* set_h3_alt_svc_max_age(cmd_parms* cmd, void* /*dummy*/, const char* arg)
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

int h3_post_config(apr_pool_t* /*p*/, apr_pool_t* /*plog*/, apr_pool_t* ptemp, server_rec* s)
{
    CHECK(ptemp);
    CHECK(s);
    h3_server_conf* conf = NULL;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    {
        return OK;
    }

    for (server_rec* vs = s; vs; vs = vs->next)
    {
        h3_server_conf* vc = ap_get_module_config(vs->module_config, &http3_module);
        if (vc->h3_cert_path && vc->h3_key_path)
        {
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
            if (vc->h3_max_request_body_size == 0)
            {
                vc->h3_max_request_body_size = H3_MAX_REQUEST_BODY_SIZE_DEFAULT;
            }
            if (vc->h3_alt_svc == H3_FLAG_UNSET)
            {
                vc->h3_alt_svc = H3_FLAG_ON;
            }
            if (vc->h3_alt_svc_max_age == 0)
            {
                vc->h3_alt_svc_max_age = H3_ALT_SVC_MAX_AGE_DEFAULT;
            }
            conf = vc;
            break;
        }
    }

    CHECK(conf && conf->h3_cert_path && conf->h3_key_path, return HTTP_INTERNAL_SERVER_ERROR;);

    /* Validate cert and key files are readable */
    apr_file_t* f = NULL;
    if (apr_file_open(&f, conf->h3_cert_path, APR_READ, APR_OS_DEFAULT, ptemp) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: H3CertificatePath not readable: %s", conf->h3_cert_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_file_close(f);
    f = NULL;

    if (apr_file_open(&f, conf->h3_key_path, APR_READ, APR_OS_DEFAULT, ptemp) != APR_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: H3CertificateKeyPath not readable: %s", conf->h3_key_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_file_close(f);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "h3_post_config: pid=%d cert=%s key=%s h3_port=%d", getpid(), conf->h3_cert_path, conf->h3_key_path, (int)conf->h3_port);
    return OK;
}

void* h3_create_dir_config(apr_pool_t* p, char* /*dir*/)
{
    CHECK(p);
    return apr_pcalloc(p, 1);
}

void* h3_merge_dir_config(apr_pool_t* /*p*/, void* base, void* /*add*/)
{
    CHECK(base);
    return base;
}

const command_rec cmd_1 = AP_INIT_TAKE1("H3CertificatePath", set_h3_cert_path, NULL, RSRC_CONF, "Path to the SSL certificate file for HTTP/3");
const command_rec cmd_2 = AP_INIT_TAKE1("H3CertificateKeyPath", set_h3_key_path, NULL, RSRC_CONF, "Path to the SSL certificate key file for HTTP/3");
const command_rec cmd_3 = AP_INIT_TAKE1("H3Port", set_h3_port, NULL, RSRC_CONF, "UDP port to listen on for QUIC/HTTP-3 (default: same as main server)");
const command_rec cmd_4 = AP_INIT_TAKE1("H3MaxConcurrentStreams", set_h3_max_concurrent_streams, NULL, RSRC_CONF, "Maximum number of concurrent HTTP/3 streams per connection (default: 100)");
const command_rec cmd_5 = AP_INIT_TAKE1("H3MaxConnections", set_h3_max_connections, NULL, RSRC_CONF, "Maximum concurrent QUIC/HTTP/3 connections per child process (default: 256)");
const command_rec cmd_6 = AP_INIT_TAKE1("H3StreamBufferSize", set_h3_stream_buffer_size, NULL, RSRC_CONF, "Per-stream read/write buffer size in bytes (default: 65536)");
const command_rec cmd_7 = AP_INIT_TAKE1("H3MaxRequestBodySize", set_h3_max_request_body_size, NULL, RSRC_CONF, "Maximum HTTP/3 request body size in bytes, fully buffered in memory (default: 10485760)");
const command_rec cmd_8 = AP_INIT_FLAG("H3AltSvc", set_h3_alt_svc, NULL, RSRC_CONF, "Whether to advertise HTTP/3 support via an Alt-Svc response header, required for browser discovery (default: on)");
const command_rec cmd_9 = AP_INIT_TAKE1("H3AltSvcMaxAge", set_h3_alt_svc_max_age, NULL, RSRC_CONF, "Seconds a client may cache the Alt-Svc HTTP/3 advertisement for (default: 86400)");

const command_rec cmd_end = AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL);
const command_rec h3_cmds[] = {cmd_1, cmd_2, cmd_3, cmd_4, cmd_5, cmd_6, cmd_7, cmd_8, cmd_9, cmd_end};
