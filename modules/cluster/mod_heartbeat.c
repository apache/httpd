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
    volatile int keep_running;
    apr_proc_mutex_t *mutex;
    const char *mutex_path;
    apr_thread_mutex_t *start_mtx;
    apr_thread_t *thread;
    apr_file_t *lockf;
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

#ifndef apr_time_from_msec
#define apr_time_from_msec(x) (x * 1000)
#endif

static void* APR_THREAD_FUNC hb_worker(apr_thread_t *thd, void *data)
{
    apr_pool_t *tpool;
    hb_ctx_t *ctx = (hb_ctx_t *) data;
    apr_status_t rv;

    apr_pool_t *pool = apr_thread_pool_get(thd);
    apr_pool_tag(pool, "heartbeat_worker");
    ctx->status = APR_SUCCESS;
    ctx->keep_running = 1;
    apr_thread_mutex_unlock(ctx->start_mtx);

    while (ctx->keep_running) {
        rv = apr_proc_mutex_trylock(ctx->mutex);
        if (rv == APR_SUCCESS) {
            break;
        }
        apr_sleep(apr_time_from_msec(200));
    }

    apr_pool_create(&tpool, pool);
    apr_pool_tag(tpool, "heartbeat_worker_temp");
    while (ctx->keep_running) {
        int mpm_state = 0;
        apr_pool_clear(tpool);

        rv = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state);

        if (rv != APR_SUCCESS) {
            break;
        }

        if (mpm_state == AP_MPMQ_STOPPING) {
            ctx->keep_running = 0;
            break;
        }

        hb_monitor(ctx, tpool);
        apr_sleep(apr_time_from_sec(HEARTBEAT_INTERVAL));
    }

    apr_pool_destroy(tpool);
    apr_proc_mutex_unlock(ctx->mutex);
    apr_thread_exit(ctx->thread, APR_SUCCESS);

    return NULL;
}

static apr_status_t hb_pool_cleanup(void *baton)
{
    apr_status_t rv;
    hb_ctx_t *ctx = (hb_ctx_t *) baton;

    ctx->keep_running = 0;

    apr_thread_join(&rv, ctx->thread);

    return rv;
}

static void start_hb_worker(apr_pool_t *p, hb_ctx_t *ctx)
{
    apr_status_t rv;

    rv = apr_thread_mutex_create(&ctx->start_mtx, APR_THREAD_MUTEX_UNNESTED,
                                 p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartbeat: apr_thread_mutex_create failed");
        ctx->status = rv;
        return;
    }

    /* This mutex fixes problems with a fast start/fast end, where the pool 
     * cleanup was being invoked before the thread completely spawned. 
     */
    apr_thread_mutex_lock(ctx->start_mtx);

    apr_pool_cleanup_register(p, ctx, hb_pool_cleanup, apr_pool_cleanup_null);

    rv = apr_thread_create(&ctx->thread, NULL, hb_worker, ctx, p);
    if (rv) {
        apr_pool_cleanup_kill(p, ctx, hb_pool_cleanup);
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartbeat: apr_thread_create failed");
        ctx->status = rv;
    }

    apr_thread_mutex_lock(ctx->start_mtx);
    apr_thread_mutex_unlock(ctx->start_mtx);
    apr_thread_mutex_destroy(ctx->start_mtx);
}

static void hb_child_init(apr_pool_t *p, server_rec *s)
{
    hb_ctx_t *ctx = ap_get_module_config(s->module_config, &heartbeat_module);

    if (ctx->active) {
        apr_proc_mutex_child_init(&ctx->mutex, ctx->mutex_path, p);
        
        ctx->status = APR_EGENERAL;
        
        start_hb_worker(p, ctx);
        if (ctx->status) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, ctx->status, s,
                         "Heartbeat: Failed to start worker thread.");
            return;
        }
    }

    return;
}

static int hb_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                   server_rec *s)
{
    apr_lockmech_e mech;
    apr_status_t rv;
    hb_ctx_t *ctx = ap_get_module_config(s->module_config, &heartbeat_module);

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &ctx->thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &ctx->server_limit);

    if (!ctx->active) {
        return OK;
    }

#if APR_HAS_FCNTL_SERIALIZE
    mech = APR_LOCK_FCNTL;
#else
#if APR_HAS_FLOCK_SERIALIZE
    mech = APR_LOCK_FLOCK;
#else
#error port me to a non crap platform.
#endif
#endif
    
    rv = apr_proc_mutex_create(&ctx->mutex, ctx->mutex_path,
                               mech,
                               p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "Heartbeat: mutex failed creation at %s (type=%d)",
                     ctx->mutex_path, mech);
        return !OK;
    }

    return OK;
}

static void hb_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(hb_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(hb_child_init, NULL, NULL, APR_HOOK_MIDDLE);
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

    rv = apr_temp_dir_get(&tmpdir, cmd->temp_pool);
    if (rv) {
        return "HeartbeatAddress: unable to find temp directory.";
    }

    path = apr_pstrcat(cmd->temp_pool, tmpdir, "/hb-tmp.XXXXXX", NULL);

    rv = apr_file_mktemp(&ctx->lockf, path, 0, cmd->temp_pool);

    if (rv) {
        return "HeartbeatAddress: unable to allocate temp file.";
    }

    rv = apr_file_name_get(&ctx->mutex_path, ctx->lockf);

    if (rv) {
        return "HeartbeatAddress: unable to get lockf name.";
    }

    apr_file_close(ctx->lockf);

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
