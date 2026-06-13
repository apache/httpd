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

#include "h3_config.h"
#include "h3_private.h"

static apr_port_t get_server_port(server_rec* s)
{
    server_addr_rec* sar;

    for (sar = s->addrs; sar; sar = sar->next)
    {
        if (sar->host_port != 0)
            return sar->host_port;
    }
    return 4433; /* XXX doc or arrange ? */
}

void* h3_create_server_config(apr_pool_t* p, server_rec* /*s*/)
{
    h3_server_conf* conf = apr_pcalloc(p, sizeof(h3_server_conf));
    conf->cert_path = NULL;
    conf->key_path = NULL;
    return conf;
}

void* h3_merge_server_config(apr_pool_t* p, void* base_conf, void* new_conf)
{
    h3_server_conf* merged = apr_pcalloc(p, sizeof(h3_server_conf));
    h3_server_conf* base = (h3_server_conf*)base_conf;
    h3_server_conf* new = (h3_server_conf*)new_conf;

    merged->cert_path = new->cert_path ? new->cert_path : base->cert_path;
    merged->key_path = new->key_path ? new->key_path : base->key_path;

    return merged;
}

static const char* set_h3_cert_path(cmd_parms* cmd, void* /*dummy*/, const char* arg)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    conf->cert_path = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char* set_h3_key_path(cmd_parms* cmd, void* /*dummy*/, const char* arg)
{
    h3_server_conf* conf = ap_get_module_config(cmd->server->module_config, &http3_module);
    conf->key_path = apr_pstrdup(cmd->pool, arg);
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

    /* Loop for all the VirtualHost */
    server_rec* current_server = s;
    while (current_server)
    {
        conf = ap_get_module_config(current_server->module_config, &http3_module);
        if (conf->cert_path && conf->key_path)
        {
            conf->host_port = get_server_port(current_server);
            break;
        }
        current_server = current_server->next;
    }

    if (conf == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: no server configuration found");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check if certificate path is configured */
    if (!conf->cert_path)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: H3CertificatePath directive is required but not configured");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check if key path is configured */
    if (!conf->key_path)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "mod_http3: H3CertificateKeyPath directive is required but not configured");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "h3_post_config: %d cert_path=%s key_path=%s", getpid(), conf->cert_path, conf->key_path);
    return OK;
}

const command_rec h3_cmds[] = {AP_INIT_TAKE1("H3CertificatePath", set_h3_cert_path, NULL, RSRC_CONF, "Path to the SSL certificate file for HTTP/3"), AP_INIT_TAKE1("H3CertificateKeyPath", set_h3_key_path, NULL, RSRC_CONF, "Path to the SSL certificate key file for HTTP/3"), {NULL}};
