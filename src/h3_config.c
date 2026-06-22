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

#include <apr_pools.h>
#include <apr_strings.h>

#include <unistd.h>

#include "h3_check.h"
#include "h3_config.h"
#include "mod_http3.h"

apr_port_t get_server_port(server_rec* s)
{
    server_addr_rec* sar = NULL;

    for (sar = s->addrs; sar; sar = sar->next)
    {
        if (sar->host_port != 0)
        {
            return sar->host_port;
        }
    }
    return 4433;
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

    merged->cert_path = new->cert_path ? new->cert_path : base->cert_path;
    merged->key_path = new->key_path ? new->key_path : base->key_path;
    merged->h3_port = new->h3_port ? new->h3_port : base->h3_port;

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
    return set_string(cmd, arg, (const char*)offsetof(h3_server_conf, cert_path));
}

static const char* set_h3_key_path(cmd_parms* cmd, void* /*dummy*/, const char* arg)
{
    return set_string(cmd, arg, (const char*)offsetof(h3_server_conf, key_path));
}

static const char* set_h3_port(cmd_parms* cmd, void* /*dummy*/, const char* arg)
{
    if (!arg || !*arg)
    {
        return "H3Port: empty port number";
    }
    char* end = NULL;
    long port = strtol(arg, &end, 10);
    if (*end || port <= 0 || port > 65535)
    {
        return apr_psprintf(cmd->pool, "H3Port: invalid port number '%s'", arg);
    }
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    if (!conf)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server, "mod_http3: server config missing in H3Port");
        return "mod_http3: internal error: no server config";
    }
    conf->h3_port = (apr_port_t)port;
    return NULL;
}

int h3_post_config(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptemp, server_rec* s)
{
    h3_server_conf* conf = NULL;
    (void)plog;
    (void)ptemp;
    (void)p;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    {
        return OK;
    }

    server_rec* current_server = s;
    while (current_server)
    {
        conf = ap_get_module_config(current_server->module_config, &http3_module);
        if (conf->cert_path && conf->key_path)
        {
            conf->host_port = get_server_port(current_server);
            if (conf->h3_port == 0)
            {
                conf->h3_port = conf->host_port;
            }
            break;
        }
        current_server = current_server->next;
    }

    if (!conf || !conf->cert_path || !conf->key_path)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: no server configured with H3CertificatePath and H3CertificateKeyPath");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "h3_post_config: pid=%d cert=%s key=%s h3_port=%d", getpid(), conf->cert_path, conf->key_path, (int)conf->h3_port);
    return OK;
}

void* h3_create_dir_config(apr_pool_t* p, char* dir)
{
    (void)dir;
    return apr_pcalloc(p, 1);
}

void* h3_merge_dir_config(apr_pool_t* p, void* base, void* add)
{
    (void)base;
    (void)add;
    return apr_pcalloc(p, 1);
}

const command_rec cmd_1 = AP_INIT_TAKE1("H3CertificatePath", set_h3_cert_path, NULL, RSRC_CONF, "Path to the SSL certificate file for HTTP/3");
const command_rec cmd_2 = AP_INIT_TAKE1("H3CertificateKeyPath", set_h3_key_path, NULL, RSRC_CONF, "Path to the SSL certificate key file for HTTP/3");
const command_rec cmd_3 = AP_INIT_TAKE1("H3Port", set_h3_port, NULL, RSRC_CONF, "UDP port to listen on for QUIC/HTTP-3 (default: same as main server)");

const command_rec cmd_end = AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL);
const command_rec h3_cmds[] = {cmd_1, cmd_2, cmd_3, cmd_end};
