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


/* The use of the scoreboard in this module is based on a similar
 * but simpler module, mod_antiloris by Kees Monshouwer, from
 * ftp://ftp.monshouwer.eu/pub/linux/mod_antiloris/
 * Note the FIXME that affects both modules.
 *
 * The major difference is that mod_antiloris checks the scoreboard
 * on every request.  This implies a per-request overhead that grows
 * with the scoreboard, and gets very expensive on a big server.
 * On the other hand, this module (mod_noloris) may be slower to
 * react to a DoS attack, and in the case of a very small server
 * it might be too late.
 *
 * Author's untested instinct: mod_antiloris will suit servers with
 * Prefork MPM and low traffic.  A server with a threaded MPM
 * (or possibly a big prefork server with lots of memory) should
 * raise MaxClients and use mod_noloris.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_log.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "apr_hash.h"
#include "scoreboard.h"

module AP_MODULE_DECLARE_DATA noloris_module;
module AP_MODULE_DECLARE_DATA core_module;

#define ADDR_MAX_SIZE 48

static unsigned int default_max_connections;
static apr_hash_t *trusted;
static apr_interval_time_t recheck_time;
static apr_shm_t *shm;
static apr_size_t shm_size;
static int server_limit;
static int thread_limit;

static int noloris_conn(conn_rec *conn)
{
    struct { int child_num; int thread_num; } *sbh = conn->sbh;

    char *shm_rec;
    if (shm == NULL) {
        return DECLINED;  /* we're disabled */
    }

    /* check the IP is not banned */
    shm_rec = apr_shm_baseaddr_get(shm);
    while (shm_rec[0] != '\0') {
        if (!strcmp(shm_rec, conn->remote_ip)) {
            apr_socket_t *csd = ap_get_module_config(conn->conn_config, &core_module);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn,
                          "Dropping connection from banned IP %s",
                          conn->remote_ip);
            apr_socket_close(csd);

            return DONE;
        }
        shm_rec += ADDR_MAX_SIZE;
    }

    /* store this client IP for the monitor to pick up */
 
    ap_update_child_status_from_conn(conn->sbh, SERVER_READY, conn);

    return DECLINED;
}
static int noloris_monitor(apr_pool_t *pool, server_rec *s)
{
    static apr_hash_t *connections = NULL;
    static apr_time_t last_check = 0;
    static int *totals;

    int i, j;
    int *n;
    int index = 0;
    apr_hash_index_t *hi;
    char *ip;
    apr_time_t time_now;
    char *shm_rec;
    worker_score *ws;

    /* do nothing if disabled */
    if (shm == NULL) {
        return 0;
    }

    /* skip check if it's not due yet */
    time_now = apr_time_now();
    if (time_now - last_check < recheck_time) {
        return 0;
    }
    last_check = time_now;

    /* alloc lots of stuff at start, so we don't leak memory per-call */
    if (connections == NULL) {
        connections = apr_hash_make(pool);
        totals = apr_palloc(pool, server_limit*thread_limit);
        ip = apr_palloc(pool, ADDR_MAX_SIZE);
    }

    /* Get a per-client count of connections in READ state */
    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            ws = ap_get_scoreboard_worker_from_indexes(i, j);
            if (ws->status == SERVER_BUSY_READ) {
                n = apr_hash_get(connections, ws->client, APR_HASH_KEY_STRING);
                if (n == NULL) {
                    n = totals + index++ ;
                    *n = 0;
                }
                ++*n;
                apr_hash_set(connections, ws->client, APR_HASH_KEY_STRING, n);
            }
        }
    }

    /* reset shm before writing to it.
     * We're only dealing with approx. counts, so we ignore the race condition
     * with our prospective readers
     */
    shm_rec = apr_shm_baseaddr_get(shm);
    memset(shm_rec, 0, shm_size);

    /* Now check the hash for clients with too many connections in READ state */
    for (hi = apr_hash_first(NULL, connections); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, (const void**) &ip, NULL, (void**)&n);
        if (*n >= default_max_connections) {
            /* if this isn't a trusted proxy, we mark it as bad */
            if (!apr_hash_get(trusted, ip, APR_HASH_KEY_STRING)) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, 0,
                       "noloris: banning %s with %d connections in READ state",
                       ip, *n);
                strcpy(shm_rec, ip);
                shm_rec += ADDR_MAX_SIZE;
            }
        }
    }
    apr_hash_clear(connections);
    return 0;
}
static int noloris_post(apr_pool_t *pconf, apr_pool_t *ptmp, apr_pool_t *plog,
                        server_rec *s)
{
    apr_status_t rv;
    int max_bans = thread_limit * server_limit / default_max_connections;
    shm_size = ADDR_MAX_SIZE * max_bans;

    rv = apr_shm_create(&shm, shm_size, NULL, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "Failed to create shm segment; mod_noloris disabled");
        apr_hash_clear(trusted);
        shm = NULL;
    }
    return 0;
}
static int noloris_pre(apr_pool_t *pconf, apr_pool_t *ptmp, apr_pool_t *plog)
{
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    /* set up default config stuff here */
    trusted = apr_hash_make(pconf);
    default_max_connections = 50;
    recheck_time = apr_time_from_sec(10);
    return 0;
}
static void noloris_hooks(apr_pool_t *p)
{
    ap_hook_process_connection(noloris_conn, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_pre_config(noloris_pre, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(noloris_post, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_monitor(noloris_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}
static const char *noloris_trusted(cmd_parms *cmd, void *cfg, const char *val)
{
    const char* err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (!err) {
        apr_hash_set(trusted, val, APR_HASH_KEY_STRING, &noloris_module);
    }
    return err;
}
static const char *noloris_recheck(cmd_parms *cmd, void *cfg, const char *val)
{
    const char* err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (!err) {
        recheck_time = apr_time_from_sec(atoi(val));
    }
    return err;
}
static const char *noloris_max_conn(cmd_parms *cmd, void *cfg, const char *val)
{
    const char* err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (!err) {
        default_max_connections = atoi(val);
    }
    return err;
}
static const command_rec noloris_cmds[] = {
    AP_INIT_ITERATE("TrustedProxy", noloris_trusted, NULL, RSRC_CONF,
                    "IP addresses from which to allow unlimited connections"),
    AP_INIT_TAKE1("ClientRecheckTime", noloris_recheck, NULL, RSRC_CONF,
                  "Time interval for rechecking client connection tables"),
    AP_INIT_TAKE1("MaxClientConnections", noloris_max_conn, NULL, RSRC_CONF,
            "Max connections in READ state to permit from an untrusted client"),
    {NULL}
};
AP_DECLARE_MODULE(noloris) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    noloris_cmds,
    noloris_hooks
};
