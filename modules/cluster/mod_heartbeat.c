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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"

#include "ap_mpm.h"
#include "scoreboard.h"
#include "mod_watchdog.h"

#ifndef HEARTBEAT_INTERVAL
#define HEARTBEAT_INTERVAL (1)
#endif

module AP_MODULE_DECLARE_DATA heartbeat_module;

typedef struct hb_ctx_t
{
    int active;
    apr_sockaddr_t *mcast_addr;
    int server_limit;
    int thread_limit;
    apr_status_t status;
} hb_ctx_t;

static const char *msg_format = "v=%u&ready=%u&busy=%u";

#define MSG_VERSION (1)

static int hb_monitor(hb_ctx_t *ctx, apr_pool_t *p)
{
    apr_size_t len;
    apr_socket_t *sock = NULL;
    char buf[256];
    int i, j;
    apr_uint32_t ready = 0;
    apr_uint32_t busy = 0;
    ap_generation_t mpm_generation;

    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);

    for (i = 0; i < ctx->server_limit; i++) {
        process_score *ps;
        ps = ap_get_scoreboard_process(i);

        for (j = 0; j < ctx->thread_limit; j++) {
            int res;

            worker_score *ws = NULL;

            ws = &ap_scoreboard_image->servers[i][j];

            res = ws->status;

            if (res == SERVER_READY && ps->generation == mpm_generation) {
                ready++;
            }
            else if (res != SERVER_DEAD &&
                     res != SERVER_STARTING && res != SERVER_IDLE_KILL &&
                     ps->generation == mpm_generation) {
                busy++;
            }
        }
    }

    len = apr_snprintf(buf, sizeof(buf), msg_format, MSG_VERSION, ready, busy);

    do {
        apr_status_t rv;
        rv = apr_socket_create(&sock, ctx->mcast_addr->family,
                               SOCK_DGRAM, APR_PROTO_UDP, p);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                         NULL, "Heartbeat: apr_socket_create failed");
            break;
        }

        rv = apr_mcast_loopback(sock, 1);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                         NULL, "Heartbeat: apr_mcast_loopback failed");
            break;
        }

        rv = apr_socket_sendto(sock, ctx->mcast_addr, 0, buf, &len);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                         NULL, "Heartbeat: apr_socket_sendto failed");
            break;
        }
    } while (0);

    if (sock) {
        apr_socket_close(sock);
    }

    return OK;
}

static int hb_watchdog_init(server_rec *s, const char *name, apr_pool_t *pool)
{
    apr_status_t rv;
    hb_ctx_t *ctx = ap_get_module_config(s->module_config, &heartbeat_module);

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &ctx->thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &ctx->server_limit);

    return OK;
}

static int hb_watchdog_exit(server_rec *s, const char *name, apr_pool_t *pool)
{
    apr_status_t rv;
    hb_ctx_t *ctx = ap_get_module_config(s->module_config, &heartbeat_module);

    return OK;
}

static int hb_watchdog_step(server_rec *s, const char *name, apr_pool_t *pool)
{
    apr_status_t rv;
    hb_ctx_t *ctx = ap_get_module_config(s->module_config, &heartbeat_module);

    if (!ctx->active && strcmp(name, AP_WATCHDOG_SINGLETON)) {
        return OK;
    }
    return hb_monitor(ctx, pool);
}

static int hb_watchdog_need(server_rec *s, const char *name,
                          int parent, int singleton)
{
    hb_ctx_t *ctx = ap_get_module_config(s->module_config, &heartbeat_module);

    if (ctx->active && singleton && !strcmp(name, AP_WATCHDOG_SINGLETON))
        return OK;
    else
        return DECLINED;
}

static void hb_register_hooks(apr_pool_t *p)
{
    ap_hook_watchdog_need(hb_watchdog_need, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_watchdog_init(hb_watchdog_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_watchdog_step(hb_watchdog_step, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_watchdog_exit(hb_watchdog_exit, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *hb_create_config(apr_pool_t *p, server_rec *s)
{
    hb_ctx_t *cfg = (hb_ctx_t *) apr_pcalloc(p, sizeof(hb_ctx_t));

    return cfg;
}

static const char *cmd_hb_address(cmd_parms *cmd,
                                  void *dconf, const char *addr)
{
    apr_status_t rv;
    const char *tmpdir = NULL;
    char *path;
    char *host_str;
    char *scope_id;
    apr_port_t port = 0;
    apr_pool_t *p = cmd->pool;
    hb_ctx_t *ctx =
        (hb_ctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &heartbeat_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (!ctx->active) {
        ctx->active = 1;
    }
    else {
        return "HeartbeatAddress: May only be specified once.";
    }

    rv = apr_parse_addr_port(&host_str, &scope_id, &port, addr, cmd->temp_pool);

    if (rv) {
        return "HeartbeatAddress: Unable to parse address.";
    }

    if (host_str == NULL) {
        return "HeartbeatAddress: No host provided in address";
    }

    if (port == 0) {
        return "HeartbeatAddress: No port provided in address";
    }

    rv = apr_sockaddr_info_get(&ctx->mcast_addr, host_str, APR_INET, port, 0,
                               p);

    if (rv) {
        return "HeartbeatAddress: apr_sockaddr_info_get failed.";
    }

    return NULL;
}

static const command_rec hb_cmds[] = {
    AP_INIT_TAKE1("HeartbeatAddress", cmd_hb_address, NULL, RSRC_CONF,
                  "Address to send heartbeat requests"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA heartbeat_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    hb_create_config,           /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    hb_cmds,                    /* command apr_table_t */
    hb_register_hooks
};
