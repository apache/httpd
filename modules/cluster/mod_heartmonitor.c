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
#include "apr_hash.h"
#include "ap_mpm.h"
#include "scoreboard.h"


#ifndef HN_UPDATE_SEC
/* How often we update the stats file */
/* TODO: Make a runtime config */
#define HN_UPDATE_SEC (5)
#endif

module AP_MODULE_DECLARE_DATA heartmonitor_module;

typedef struct hm_server_t
{
    const char *ip;
    int busy;
    int ready;
    apr_time_t seen;
} hm_server_t;

typedef struct hm_ctx_t
{
    int active;
    const char *storage_path;
    apr_proc_mutex_t *mutex;
    const char *mutex_path;
    apr_sockaddr_t *mcast_addr;
    apr_status_t status;
    volatile int keep_running;
    apr_thread_mutex_t *start_mtx;
    apr_thread_t *thread;
    apr_socket_t *sock;
    apr_pool_t *p;
    apr_hash_t *servers;
} hm_ctx_t;

static apr_status_t hm_listen(hm_ctx_t *ctx)
{
    apr_status_t rv;

    rv = apr_socket_create(&ctx->sock, ctx->mcast_addr->family,
                           SOCK_DGRAM, APR_PROTO_UDP, ctx->p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Failed to create listening socket.");
        return rv;
    }

    rv = apr_socket_opt_set(ctx->sock, APR_SO_REUSEADDR, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Failed to set APR_SO_REUSEADDR to 1 on socket.");
        return rv;
    }


    rv = apr_socket_opt_set(ctx->sock, APR_SO_NONBLOCK, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Failed to set APR_SO_REUSEADDR to 1 on socket.");
        return rv;
    }

    rv = apr_socket_bind(ctx->sock, ctx->mcast_addr);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Failed to bind on socket.");
        return rv;
    }

    rv = apr_mcast_join(ctx->sock, ctx->mcast_addr, NULL, NULL);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Failed to join multicast group");
        return rv;
    }

    rv = apr_mcast_loopback(ctx->sock, 1);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Failed to accept localhost mulitcast on socket.");
        return rv;
    }

    ctx->servers = apr_hash_make(ctx->p);

    return APR_SUCCESS;
}

static void qs_to_table(const char *input, apr_table_t *parms,
                        apr_pool_t *p)
{
    char *key;
    char *value;
    char *query_string;
    char *strtok_state;

    if (input == NULL) {
        return;
    }

    query_string = apr_pstrdup(p, input);

    key = apr_strtok(query_string, "&", &strtok_state);
    while (key) {
        value = strchr(key, '=');
        if (value) {
            *value = '\0';      /* Split the string in two */
            value++;            /* Skip passed the = */
        }
        else {
            value = "1";
        }
        ap_unescape_url(key);
        ap_unescape_url(value);
        apr_table_set(parms, key, value);
        /*
           ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
           "Found query arg: %s = %s", key, value);
         */
        key = apr_strtok(NULL, "&", &strtok_state);
    }
}


#define SEEN_TIMEOUT (30)

static apr_status_t hm_update_stats(hm_ctx_t *ctx, apr_pool_t *p)
{
    apr_status_t rv;
    apr_file_t *fp;
    apr_hash_index_t *hi;
    apr_time_t now;
    char *path = apr_pstrcat(p, ctx->storage_path, ".tmp.XXXXXX", NULL);
    /* TODO: Update stats file (!) */
    rv = apr_file_mktemp(&fp, path, APR_CREATE | APR_WRITE, p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Unable to open tmp file: %s", path);
        return rv;
    }

    now = apr_time_now();
    for (hi = apr_hash_first(p, ctx->servers);
         hi != NULL; hi = apr_hash_next(hi)) {
        hm_server_t *s = NULL;
        apr_uint32_t seen;
        apr_hash_this(hi, NULL, NULL, (void **) &s);
        seen = apr_time_sec(now - s->seen);
        if (seen > SEEN_TIMEOUT) {
            /*
             * Skip this entry from the heartbeat file -- when it comes back,
             * we will reuse the memory...
             */
        }
        else {
            apr_file_printf(fp, "%s &ready=%u&busy=%u&lastseen=%u\n",
                            s->ip, s->ready, s->busy, seen);
        }
    }

    rv = apr_file_flush(fp);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                   "Heartmonitor: Unable to flush file: %s", path);
      return rv;
    }

    rv = apr_file_close(fp);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                   "Heartmonitor: Unable to close file: %s", path);
      return rv;
    }
  
    rv = apr_file_perms_set(path,
                            APR_FPROT_UREAD | APR_FPROT_GREAD |
                            APR_FPROT_WREAD);
    if (rv && rv != APR_INCOMPLETE) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Unable to set file permssions on %s",
                     path);
        return rv;
    }

    rv = apr_file_rename(path, ctx->storage_path, p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Unable to move file: %s -> %s", path,
                     ctx->storage_path);
        return rv;
    }

    return APR_SUCCESS;
}

static hm_server_t *hm_get_server(hm_ctx_t *ctx, const char *ip)
{
    hm_server_t *s;

    s = apr_hash_get(ctx->servers, ip, APR_HASH_KEY_STRING);

    if (s == NULL) {
        s = apr_palloc(ctx->p, sizeof(hm_server_t));
        s->ip = apr_pstrdup(ctx->p, ip);
        s->ready = 0;
        s->busy = 0;
        s->seen = 0;
        apr_hash_set(ctx->servers, s->ip, APR_HASH_KEY_STRING, s);
    }

    return s;
}

#define MAX_MSG_LEN (1000)
static apr_status_t hm_recv(hm_ctx_t *ctx, apr_pool_t *p)
{
    char buf[MAX_MSG_LEN + 1];
    apr_sockaddr_t from;
    apr_size_t len = MAX_MSG_LEN;
    apr_status_t rv;
    apr_table_t *tbl;

    from.pool = p;

    rv = apr_socket_recvfrom(&from, ctx->sock, 0, buf, &len);

    if (APR_STATUS_IS_EAGAIN(rv)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: would block");
        return APR_SUCCESS;
    }
    else if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: recvfrom failed");
        return rv;
    }

    buf[len] = '\0';

    tbl = apr_table_make(p, 10);

    qs_to_table(buf, tbl, p);

    if (apr_table_get(tbl, "v") != NULL &&
        apr_table_get(tbl, "busy") != NULL &&
        apr_table_get(tbl, "ready") != NULL) {
        char *ip;
        hm_server_t *s;
        /* TODO: REMOVE ME BEFORE PRODUCTION (????) */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, NULL,
                     "Heartmonitor: %pI busy=%s ready=%s", &from,
                     apr_table_get(tbl, "busy"), apr_table_get(tbl, "ready"));

        apr_sockaddr_ip_get(&ip, &from);

        s = hm_get_server(ctx, ip);

        s->busy = atoi(apr_table_get(tbl, "busy"));
        s->ready = atoi(apr_table_get(tbl, "ready"));
        s->seen = apr_time_now();
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: malformed multicast message from %pI",
                     &from);
    }

    return rv;
}


#ifndef apr_time_from_msec
#define apr_time_from_msec(x) (x * 1000)
#endif

static void* APR_THREAD_FUNC hm_worker(apr_thread_t *thd, void *data)
{
    apr_time_t last;
    hm_ctx_t *ctx = (hm_ctx_t *) data;
    apr_status_t rv;

    ctx->p = apr_thread_pool_get(thd);
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

    rv = hm_listen(ctx);

    if (rv) {
        ctx->status = rv;
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: Unable to listen for connections!");
        apr_proc_mutex_unlock(ctx->mutex);
        apr_thread_exit(ctx->thread, rv);
        return NULL;
    }


    last = apr_time_now();
    while (ctx->keep_running) {
        int n;
        apr_pool_t *p;
        apr_pollfd_t pfd;
        apr_interval_time_t timeout;
        apr_time_t now;
        apr_pool_create(&p, ctx->p);

        now = apr_time_now();

        if (apr_time_sec((now - last)) > HN_UPDATE_SEC) {
            hm_update_stats(ctx, p);
            apr_pool_clear(p);
            last = now;
        }

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = ctx->sock;
        pfd.p = p;
        pfd.reqevents = APR_POLLIN;

        timeout = apr_time_from_sec(1);

        rv = apr_poll(&pfd, 1, &n, timeout);

        if (!ctx->keep_running) {
            break;
        }

        if (rv) {
            apr_pool_destroy(p);
            continue;
        }

        if (pfd.rtnevents & APR_POLLIN) {
            hm_recv(ctx, p);
        }

        apr_pool_destroy(p);
    }

    apr_proc_mutex_unlock(ctx->mutex);
    apr_thread_exit(ctx->thread, APR_SUCCESS);

    return NULL;
}

static apr_status_t hm_pool_cleanup(void *baton)
{
    apr_status_t rv;
    hm_ctx_t *ctx = (hm_ctx_t *) baton;

    ctx->keep_running = 0;

    apr_thread_join(&rv, ctx->thread);

    return rv;
}

static void start_hm_worker(apr_pool_t *p, hm_ctx_t *ctx)
{
    apr_status_t rv;

    rv = apr_thread_mutex_create(&ctx->start_mtx, APR_THREAD_MUTEX_UNNESTED,
                                 p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: apr_thread_mutex_create failed");
        ctx->status = rv;
        return;
    }

    /* This mutex fixes problems with a fast start/fast end, where the pool 
     * cleanup was being invoked before the thread completely spawned. 
     */
    apr_thread_mutex_lock(ctx->start_mtx);

    apr_pool_cleanup_register(p, ctx, hm_pool_cleanup, apr_pool_cleanup_null);

    rv = apr_thread_create(&ctx->thread, NULL, hm_worker, ctx, p);
    if (rv) {
        apr_pool_cleanup_kill(p, ctx, hm_pool_cleanup);
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "Heartmonitor: apr_thread_create failed");
        ctx->status = rv;
    }

    apr_thread_mutex_lock(ctx->start_mtx);
    apr_thread_mutex_unlock(ctx->start_mtx);
    apr_thread_mutex_destroy(ctx->start_mtx);
}

static void hm_child_init(apr_pool_t *p, server_rec *s)
{
    hm_ctx_t *ctx =
        ap_get_module_config(s->module_config, &heartmonitor_module);

    if (!ctx->active) {
        return;
    }

    apr_proc_mutex_child_init(&ctx->mutex, ctx->mutex_path, p);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "Heartmonitor: Starting Listener Thread. mcast=%pI",
                 ctx->mcast_addr);

    ctx->status = APR_EGENERAL;

    start_hm_worker(p, ctx);

    if (ctx->status) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, ctx->status, s,
                     "Heartmonitor: Failed to start listener thread.");
        return;
    }

    return;
}

static int hm_post_config(apr_pool_t *p, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    apr_lockmech_e mech;
    apr_status_t rv;
    hm_ctx_t *ctx = ap_get_module_config(s->module_config,
                                         &heartmonitor_module);


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
    
    rv = apr_proc_mutex_create(&ctx->mutex,
                                            ctx->mutex_path,
                                            mech,
                                            p);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "Heartmonitor: Failed to create listener "
                     "mutex at %s (type=%d)", ctx->mutex_path,
                     mech);
        return !OK;
    }

    return OK;
}

static void hm_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(hm_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(hm_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *hm_create_config(apr_pool_t *p, server_rec *s)
{
    hm_ctx_t *ctx = (hm_ctx_t *) apr_palloc(p, sizeof(hm_ctx_t));

    ctx->active = 0;
    ctx->storage_path = ap_server_root_relative(p, "logs/hb.dat");
    ctx->mutex_path = 
        ap_server_root_relative(p, apr_pstrcat(p, ctx->storage_path, ".hm-lock", NULL));

    return ctx;
}

static const char *cmd_hm_storage(cmd_parms *cmd,
                                  void *dconf, const char *path)
{
    apr_pool_t *p = cmd->pool;
    hm_ctx_t *ctx =
        (hm_ctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &heartmonitor_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    ctx->storage_path = ap_server_root_relative(p, path);
    ctx->mutex_path =
        ap_server_root_relative(p, apr_pstrcat(p, path, ".hm-lock", NULL));

    return NULL;
}

static const char *cmd_hm_listen(cmd_parms *cmd,
                                 void *dconf, const char *mcast_addr)
{
    apr_status_t rv;
    char *host_str;
    char *scope_id;
    apr_port_t port = 0;
    apr_pool_t *p = cmd->pool;
    hm_ctx_t *ctx =
        (hm_ctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &heartmonitor_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (!ctx->active) {
        ctx->active = 1;
    }
    else {
        return "HeartbeatListen: May only be specified once.";
    }

    rv = apr_parse_addr_port(&host_str, &scope_id, &port, mcast_addr, cmd->temp_pool);

    if (rv) {
        return "HeartbeatListen: Unable to parse multicast address.";
    }

    if (host_str == NULL) {
        return "HeartbeatListen: No host provided in multicast address";
    }

    if (port == 0) {
        return "HeartbeatListen: No port provided in multicast address";
    }

    rv = apr_sockaddr_info_get(&ctx->mcast_addr, host_str, APR_INET, port, 0,
                               p);

    if (rv) {
        return
            "HeartbeatListen: apr_sockaddr_info_get failed on multicast address";
    }

    return NULL;
}

static const command_rec hm_cmds[] = {
    AP_INIT_TAKE1("HeartbeatListen", cmd_hm_listen, NULL, RSRC_CONF,
                  "Address to listen for heartbeat requests"),
    AP_INIT_TAKE1("HeartbeatStorage", cmd_hm_storage, NULL, RSRC_CONF,
                  "Path to store heartbeat data."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA heartmonitor_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    hm_create_config,           /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    hm_cmds,                    /* command apr_table_t */
    hm_register_hooks
};
