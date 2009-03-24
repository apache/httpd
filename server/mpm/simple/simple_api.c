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

#include "ap_mpm.h"
#include "httpd.h"
#include "http_config.h"
#include "mpm_common.h"
#include "http_log.h"
#include "scoreboard.h"
#include "ap_listen.h"
#include "simple_types.h"
#include "simple_run.h"
#include "http_core.h"

/* This file contains the absolute minimal MPM API, to interface with httpd. */

static int simple_run(apr_pool_t * pconf, apr_pool_t * plog, server_rec * s)
{
    simple_core_t *sc = simple_core_get();

    sc->mpm_state = AP_MPMQ_RUNNING;

    if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
        sc->mpm_state = AP_MPMQ_STOPPING;
        return 1;
    }

    return simple_main_loop(sc);
}

static apr_status_t simple_query(int query_code, int *result)
{
    simple_core_t *sc = simple_core_get();

    switch (query_code) {
    case AP_MPMQ_IS_THREADED:
        *result = AP_MPMQ_STATIC;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_IS_FORKED:
        *result = AP_MPMQ_DYNAMIC;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_IS_ASYNC:
        *result = 1;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = sc->procmgr.proc_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_HARD_LIMIT_DAEMONS:
        *result = sc->procmgr.proc_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_HARD_LIMIT_THREADS:
        *result = sc->procmgr.thread_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MAX_THREADS:
        *result = sc->procmgr.thread_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MAX_SPARE_DAEMONS:
        *result = sc->procmgr.proc_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MIN_SPARE_DAEMONS:
        *result = sc->procmgr.proc_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MIN_SPARE_THREADS:
    case AP_MPMQ_MAX_SPARE_THREADS:
        *result = sc->procmgr.thread_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MAX_REQUESTS_DAEMON:
        *result = sc->procmgr.max_requests_per_child;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MAX_DAEMONS:
        *result = sc->procmgr.proc_count;
        return APR_SUCCESS;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = sc->mpm_state;
        return APR_SUCCESS;
    case AP_MPMQ_GENERATION:
        *result = 0;
        return APR_SUCCESS;
    default:
        break;
    }

    return APR_ENOTIMPL;
}

static int
simple_open_logs(apr_pool_t * p,
                 apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
    int nsock;

    nsock = ap_setup_listeners(s);

    if (nsock < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0,
                     s,
                     "simple_open_logs: no listening sockets available, shutting down");
        return DONE;
    }

    return OK;
}

static int
simple_pre_config(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp)
{
    int run_debug;
    apr_status_t rv;
    simple_core_t *sc = simple_core_get();

    sc->restart_num++;

    run_debug = ap_exists_config_define("DEBUG");

    if (run_debug) {
        sc->run_foreground = 1;
        sc->run_single_process = 1;
    }
    else {
        sc->run_foreground = ap_exists_config_define("FOREGROUND");
    }

    if (sc->restart_num == 2) {

        if (sc->run_foreground) {
            rv = apr_proc_detach(APR_PROC_DETACH_FOREGROUND);
        }
        else {
            rv = apr_proc_detach(APR_PROC_DETACH_DAEMONIZE);
        }

        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                         "simple_pre_config: apr_proc_detach(%s) failed",
                         sc->run_foreground ? "FOREGROUND" : "DAEMONIZE");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

static void simple_process_start(process_rec * process)
{
    apr_status_t rv;

    /* this is our first 'real' entry point, so setup everything here. */
    rv = simple_core_init(simple_core_get(), process->pool);

    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "simple_core_init: Fatal Error Encountered");
        exit(EXIT_FAILURE);
    }

    ap_mpm_rewrite_args(process);
}

static int
simple_check_config(apr_pool_t * p, apr_pool_t * plog,
                    apr_pool_t * ptemp, server_rec * s)
{
    simple_core_t *sc = simple_core_get();

    if (sc->procmgr.proc_count > SIMPLE_MAX_PROC) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "simple_check_config: SimpleProcCount must be at most %d",
                     SIMPLE_MAX_PROC);
        return !OK;
    }

    if (sc->procmgr.proc_count < SIMPLE_MIN_PROC) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "simple_check_config: SimpleProcCount must be at least %d",
                     SIMPLE_MIN_PROC);
        return !OK;
    }

    if (sc->procmgr.thread_count > SIMPLE_MAX_THREADS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "simple_check_config: SimpleThreadCount must be at most %d",
                     SIMPLE_MAX_THREADS);
        return !OK;
    }

    if (sc->procmgr.thread_count < SIMPLE_MIN_THREADS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "simple_check_config: SimpleThreadCount must be at least %d",
                     SIMPLE_MIN_THREADS);
        return !OK;
    }

    return OK;
}

static void simple_hooks(apr_pool_t * p)
{
    static const char *const aszSucc[] = { "core.c", NULL };

    ap_hook_open_logs(simple_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);

    ap_hook_pre_config(simple_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);

    ap_hook_check_config(simple_check_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_mpm(simple_run, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_mpm_query(simple_query, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_proccount(cmd_parms * cmd, void *baton,
                                 const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    simple_core_get()->procmgr.proc_count = atoi(arg);
    return NULL;
}


static const char *set_threadcount(cmd_parms * cmd, void *baton,
                                   const char *arg)
{
    simple_core_t *sc = simple_core_get();
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    sc->procmgr.thread_count = atoi(arg);

    return NULL;
}

static const command_rec simple_cmds[] = {
    AP_INIT_TAKE1("SimpleProcCount", set_proccount, NULL, RSRC_CONF,
                  "Number of child processes launched at server startup"),
    AP_INIT_TAKE1("SimpleThreadCount", set_threadcount, NULL, RSRC_CONF,
                  "Set the number of Worker Threads Per-Process"),
    /* pqXXXXXXXXX: These do NOT belong in the MPM configuration commands. */
    LISTEN_COMMANDS,
    {NULL}
};



module AP_MODULE_DECLARE_DATA mpm_simple_module = {
    MPM20_MODULE_STUFF,
    simple_process_start,       /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    simple_cmds,                /* command apr_table_t */
    simple_hooks                /* register_hooks */
};
