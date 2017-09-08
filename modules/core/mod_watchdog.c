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

/* Watchdog module.
 */

#include "apr.h"
#include "mod_watchdog.h"
#include "ap_provider.h"
#include "ap_mpm.h"
#include "http_core.h"
#include "util_mutex.h"

#define AP_WATCHDOG_PGROUP    "watchdog"
#define AP_WATCHDOG_PVERSION  "parent"
#define AP_WATCHDOG_CVERSION  "child"

typedef struct watchdog_list_t watchdog_list_t;

struct watchdog_list_t
{
    struct watchdog_list_t *next;
    ap_watchdog_t *wd;
    apr_status_t status;
    apr_interval_time_t interval;
    apr_interval_time_t step;
    const void *data;
    ap_watchdog_callback_fn_t *callback_fn;
};

struct ap_watchdog_t
{
    apr_thread_mutex_t   *startup;
    apr_proc_mutex_t     *mutex;
    const char           *name;
    watchdog_list_t      *callbacks;
    int                   is_running;
    int                   singleton;
    int                   active;
    apr_interval_time_t   step;
    apr_thread_t         *thread;
    apr_pool_t           *pool;
};

typedef struct wd_server_conf_t wd_server_conf_t;
struct wd_server_conf_t
{
    int child_workers;
    int parent_workers;
    apr_pool_t *pool;
    server_rec *s;
};

static wd_server_conf_t *wd_server_conf = NULL;
static apr_interval_time_t wd_interval = AP_WD_TM_INTERVAL;
static int mpm_is_forked = AP_MPMQ_NOT_SUPPORTED;
static const char *wd_proc_mutex_type = "watchdog-callback";

static apr_status_t wd_worker_cleanup(void *data)
{
    apr_status_t rv;
    ap_watchdog_t *w = (ap_watchdog_t *)data;

    if (w->is_running) {
        watchdog_list_t *wl = w->callbacks;
        while (wl) {
            if (wl->status == APR_SUCCESS) {
                /* Execute watchdog callback with STOPPING state */
                (*wl->callback_fn)(AP_WATCHDOG_STATE_STOPPING,
                                    (void *)wl->data, w->pool);
                wl->status = APR_EOF;
            }
            wl = wl->next;
        }
    }
    w->is_running = 0;
    apr_thread_join(&rv, w->thread);
    return rv;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Main watchdog worker thread.                                             */
/* For singleton workers child thread that first obtains the process       */
/* mutex is running. Threads in other child's are locked on mutex.          */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static void* APR_THREAD_FUNC wd_worker(apr_thread_t *thread, void *data)
{
    ap_watchdog_t *w = (ap_watchdog_t *)data;
    apr_status_t rv;
    int locked = 0;
    int probed = 0;
    int inited = 0;
    int mpmq_s = 0;

    w->pool = apr_thread_pool_get(thread);
    w->is_running = 1;

    apr_thread_mutex_unlock(w->startup);
    if (w->mutex) {
        while (w->is_running) {
            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s) != APR_SUCCESS) {
                w->is_running = 0;
                break;
            }
            if (mpmq_s == AP_MPMQ_STOPPING) {
                w->is_running = 0;
                break;
            }
            rv = apr_proc_mutex_trylock(w->mutex);
            if (rv == APR_SUCCESS) {
                if (probed) {
                    /* Sleep after we were locked
                     * up to 1 second. Httpd can be
                     * in the middle of shutdown, and
                     * our child didn't yet received
                     * the shutdown signal.
                     */
                    probed = 10;
                    while (w->is_running && probed > 0) {
                        apr_sleep(AP_WD_TM_INTERVAL);
                        probed--;
                        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s) != APR_SUCCESS) {
                            w->is_running = 0;
                            break;
                        }
                        if (mpmq_s == AP_MPMQ_STOPPING) {
                            w->is_running = 0;
                            break;
                        }
                    }
                }
                locked = 1;
                break;
            }
            probed = 1;
            apr_sleep(AP_WD_TM_SLICE);
        }
    }
    if (w->is_running) {
        watchdog_list_t *wl = w->callbacks;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd_server_conf->s,
                     APLOGNO(02972) "%sWatchdog (%s) running",
                     w->singleton ? "Singleton " : "", w->name);
        apr_time_clock_hires(w->pool);
        if (wl) {
            apr_pool_t *ctx = NULL;
            apr_pool_create(&ctx, w->pool);
            while (wl && w->is_running) {
                /* Execute watchdog callback */
                wl->status = (*wl->callback_fn)(AP_WATCHDOG_STATE_STARTING,
                                                (void *)wl->data, ctx);
                wl = wl->next;
            }
            apr_pool_destroy(ctx);
        }
        else {
            ap_run_watchdog_init(wd_server_conf->s, w->name, w->pool);
            inited = 1;
        }
    }

    /* Main execution loop */
    while (w->is_running) {
        apr_pool_t *ctx = NULL;
        apr_time_t curr;
        watchdog_list_t *wl = w->callbacks;

        apr_sleep(AP_WD_TM_SLICE);
        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s) != APR_SUCCESS) {
            w->is_running = 0;
        }
        if (mpmq_s == AP_MPMQ_STOPPING) {
            w->is_running = 0;
        }
        if (!w->is_running) {
            break;
        }
        curr = apr_time_now() - AP_WD_TM_SLICE;
        while (wl && w->is_running) {
            if (wl->status == APR_SUCCESS) {
                wl->step += (apr_time_now() - curr);
                if (wl->step >= wl->interval) {
                    if (!ctx)
                        apr_pool_create(&ctx, w->pool);
                    wl->step = 0;
                    /* Execute watchdog callback */
                    wl->status = (*wl->callback_fn)(AP_WATCHDOG_STATE_RUNNING,
                                                    (void *)wl->data, ctx);
                    if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s) != APR_SUCCESS) {
                        w->is_running = 0;
                    }
                    if (mpmq_s == AP_MPMQ_STOPPING) {
                        w->is_running = 0;
                    }
                }
            }
            wl = wl->next;
        }
        if (w->is_running && w->callbacks == NULL) {
            /* This is hook mode watchdog
             * running on WatchogInterval
             */
            w->step += (apr_time_now() - curr);
            if (w->step >= wd_interval) {
                if (!ctx)
                    apr_pool_create(&ctx, w->pool);
                w->step = 0;
                /* Run watchdog step hook */
                ap_run_watchdog_step(wd_server_conf->s, w->name, ctx);
            }
        }
        if (ctx)
            apr_pool_destroy(ctx);
        if (!w->is_running) {
            break;
        }
    }
    if (inited) {
        /* Run the watchdog exit hooks.
         * If this was singleton watchdog the init hook
         * might never been called, so skip the exit hook
         * in that case as well.
         */
        ap_run_watchdog_exit(wd_server_conf->s, w->name, w->pool);
    }
    else {
        watchdog_list_t *wl = w->callbacks;
        while (wl) {
            if (wl->status == APR_SUCCESS) {
                /* Execute watchdog callback with STOPPING state */
                (*wl->callback_fn)(AP_WATCHDOG_STATE_STOPPING,
                                   (void *)wl->data, w->pool);
            }
            wl = wl->next;
        }
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd_server_conf->s,
                 APLOGNO(02973) "%sWatchdog (%s) stopping",
                 w->singleton ? "Singleton " : "", w->name);

    if (locked)
        apr_proc_mutex_unlock(w->mutex);
    apr_thread_exit(w->thread, APR_SUCCESS);

    return NULL;
}

static apr_status_t wd_startup(ap_watchdog_t *w, apr_pool_t *p)
{
    apr_status_t rc;

    /* Create thread startup mutex */
    rc = apr_thread_mutex_create(&w->startup, APR_THREAD_MUTEX_UNNESTED, p);
    if (rc != APR_SUCCESS)
        return rc;

    if (w->singleton) {
        /* Initialize singleton mutex in child */
        rc = apr_proc_mutex_child_init(&w->mutex,
                                       apr_proc_mutex_lockfile(w->mutex), p);
        if (rc != APR_SUCCESS)
            return rc;
    }

    /* This mutex fixes problems with a fast start/fast end, where the pool
     * cleanup was being invoked before the thread completely spawned.
     */
    apr_thread_mutex_lock(w->startup);
    apr_pool_pre_cleanup_register(p, w, wd_worker_cleanup);

    /* Start the newly created watchdog */
    rc = apr_thread_create(&w->thread, NULL, wd_worker, w, p);
    if (rc) {
        apr_pool_cleanup_kill(p, w, wd_worker_cleanup);
    }

    apr_thread_mutex_lock(w->startup);
    apr_thread_mutex_unlock(w->startup);
    apr_thread_mutex_destroy(w->startup);

    return rc;
}

static apr_status_t ap_watchdog_get_instance(ap_watchdog_t **watchdog,
                                             const char *name,
                                             int parent,
                                             int singleton,
                                             apr_pool_t *p)
{
    ap_watchdog_t *w;
    const char *pver = parent ? AP_WATCHDOG_PVERSION : AP_WATCHDOG_CVERSION;

    if (parent && mpm_is_forked != AP_MPMQ_NOT_SUPPORTED) {
        /* Parent threads are not supported for
         * forked mpm's
         */
        *watchdog = NULL;
        return APR_ENOTIMPL;
    }
    w = ap_lookup_provider(AP_WATCHDOG_PGROUP, name, pver);
    if (w) {
        *watchdog = w;
        return APR_SUCCESS;
    }
    w = apr_pcalloc(p, sizeof(ap_watchdog_t));
    w->name      = name;
    w->pool      = p;
    w->singleton = parent ? 0 : singleton;
    *watchdog    = w;
    return ap_register_provider(p, AP_WATCHDOG_PGROUP, name,
                                pver, *watchdog);
}

static apr_status_t ap_watchdog_set_callback_interval(ap_watchdog_t *w,
                                                      apr_interval_time_t interval,
                                                      const void *data,
                                                      ap_watchdog_callback_fn_t *callback)
{
    watchdog_list_t *c = w->callbacks;
    apr_status_t rv = APR_EOF;

    while (c) {
        if (c->data == data && c->callback_fn == callback) {
            /* We have existing callback.
             * Update the interval and reset status, so the
             * callback and continue execution if stopped earlier.
             */
            c->interval = interval;
            c->step     = 0;
            c->status   = APR_SUCCESS;
            rv          = APR_SUCCESS;
            break;
        }
        c = c->next;
    }
    return rv;
}

static apr_status_t ap_watchdog_register_callback(ap_watchdog_t *w,
                                                  apr_interval_time_t interval,
                                                  const void *data,
                                                  ap_watchdog_callback_fn_t *callback)
{
    watchdog_list_t *c = w->callbacks;

    while (c) {
        if (c->data == data && c->callback_fn == callback) {
            /* We have already registered callback.
             * Do not allow callbacks that have the same
             * function and data pointers.
             */
            return APR_EEXIST;
        }
        c = c->next;
    }
    c = apr_palloc(w->pool, sizeof(watchdog_list_t));
    c->data        = data;
    c->callback_fn = callback;
    c->interval    = interval;
    c->step        = 0;
    c->status      = APR_EINIT;

    c->wd          = w;
    c->next        = w->callbacks;
    w->callbacks   = c;
    w->active++;

    return APR_SUCCESS;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Pre config hook.                                                         */
/* Create default watchdogs for parent and child                            */
/* Parent watchdog executes inside parent process so it doesn't need the    */
/* singleton mutex                                                          */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static int wd_pre_config_hook(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp)
{
    apr_status_t rv;
    ap_watchdog_t *w;

    ap_mpm_query(AP_MPMQ_IS_FORKED, &mpm_is_forked);
    if ((rv = ap_watchdog_get_instance(&w,
                AP_WATCHDOG_SINGLETON, 0, 1, pconf)) != APR_SUCCESS) {
        return rv;
    }
    if ((rv = ap_watchdog_get_instance(&w,
                AP_WATCHDOG_DEFAULT, 0, 0, pconf)) != APR_SUCCESS) {
        return rv;
    }
    if (mpm_is_forked == AP_MPMQ_NOT_SUPPORTED) {
        /* Create parent process watchdog for
         * non forked mpm's only.
         */
        if ((rv = ap_watchdog_get_instance(&w,
                    AP_WATCHDOG_DEFAULT, 1, 0, pconf)) != APR_SUCCESS) {
            return rv;
        }
    }

    if ((rv = ap_mutex_register(pconf, wd_proc_mutex_type, NULL,
                                APR_LOCK_DEFAULT, 0)) != APR_SUCCESS) {
        return rv;
    }

    return OK;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Post config hook.                                                        */
/* Create watchdog thread in parent and initializes Watchdog module         */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static int wd_post_config_hook(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    const char *pk = "watchdog_init_module_tag";
    apr_pool_t *ppconf = pconf;
    const apr_array_header_t *wl;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
        /* First time config phase -- skip. */
        return OK;

    apr_pool_userdata_get((void *)&wd_server_conf, pk, ppconf);
    if (!wd_server_conf) {
        if (!(wd_server_conf = apr_pcalloc(ppconf, sizeof(wd_server_conf_t))))
            return APR_ENOMEM;
        apr_pool_create(&wd_server_conf->pool, ppconf);
        apr_pool_userdata_set(wd_server_conf, pk, apr_pool_cleanup_null, ppconf);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(010033)
                 "Watchdog: Running with WatchdogInterval %"
                 APR_TIME_T_FMT "ms", apr_time_as_msec(wd_interval));
    wd_server_conf->s = s;
    if ((wl = ap_list_provider_names(pconf, AP_WATCHDOG_PGROUP,
                                            AP_WATCHDOG_PVERSION))) {
        const ap_list_provider_names_t *wn;
        int i;

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02974)
                "Watchdog: found parent providers.");

        wn = (ap_list_provider_names_t *)wl->elts;
        for (i = 0; i < wl->nelts; i++) {
            ap_watchdog_t *w = ap_lookup_provider(AP_WATCHDOG_PGROUP,
                                                  wn[i].provider_name,
                                                  AP_WATCHDOG_PVERSION);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02975)
                    "Watchdog: Looking for parent (%s).", wn[i].provider_name);
            if (w) {
                if (!w->active) {
                    int status = ap_run_watchdog_need(s, w->name, 1,
                                                      w->singleton);
                    if (status == OK) {
                        /* One of the modules returned OK to this watchog.
                         * Mark it as active
                         */
                        w->active = 1;
                    }
                }
                if (w->active) {
                    /* We have active watchdog.
                     * Create the watchdog thread
                     */
                    if ((rv = wd_startup(w, wd_server_conf->pool)) != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(01571)
                                "Watchdog: Failed to create parent worker thread.");
                        return rv;
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(02976)
                            "Watchdog: Created parent worker thread (%s).", w->name);
                    wd_server_conf->parent_workers++;
                }
            }
        }
    }
    if (wd_server_conf->parent_workers) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01572)
                     "Spawned %d parent worker threads.",
                     wd_server_conf->parent_workers);
    }
    if ((wl = ap_list_provider_names(pconf, AP_WATCHDOG_PGROUP,
                                            AP_WATCHDOG_CVERSION))) {
        const ap_list_provider_names_t *wn;
        int i;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02977)
                "Watchdog: found child providers.");

        wn = (ap_list_provider_names_t *)wl->elts;
        for (i = 0; i < wl->nelts; i++) {
            ap_watchdog_t *w = ap_lookup_provider(AP_WATCHDOG_PGROUP,
                                                  wn[i].provider_name,
                                                  AP_WATCHDOG_CVERSION);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02978)
                    "Watchdog: Looking for child (%s).", wn[i].provider_name);
            if (w) {
                if (!w->active) {
                    int status = ap_run_watchdog_need(s, w->name, 0,
                                                      w->singleton);
                    if (status == OK) {
                        /* One of the modules returned OK to this watchog.
                         * Mark it as active
                         */
                        w->active = 1;
                    }
                }
                if (w->active) {
                    /* We have some callbacks registered.
                     * Create mutexes for singleton watchdogs
                     */
                    if (w->singleton) {
                        rv = ap_proc_mutex_create(&w->mutex, NULL, wd_proc_mutex_type,
                                                  w->name, s,
                                                  wd_server_conf->pool, 0);
                        if (rv != APR_SUCCESS) {
                            return rv;
                        }
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(02979)
                            "Watchdog: Created child worker thread (%s).", w->name);
                    wd_server_conf->child_workers++;
                }
            }
        }
    }
    return OK;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Child init hook.                                                         */
/* Create watchdog threads and initializes Mutexes in child                 */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static void wd_child_init_hook(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv = OK;
    const apr_array_header_t *wl;

    if (!wd_server_conf->child_workers) {
        /* We don't have anything configured, bail out.
         */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(02980)
                     "Watchdog: nothing configured?");
        return;
    }
    if ((wl = ap_list_provider_names(p, AP_WATCHDOG_PGROUP,
                                        AP_WATCHDOG_CVERSION))) {
        const ap_list_provider_names_t *wn;
        int i;
        wn = (ap_list_provider_names_t *)wl->elts;
        for (i = 0; i < wl->nelts; i++) {
            ap_watchdog_t *w = ap_lookup_provider(AP_WATCHDOG_PGROUP,
                                                  wn[i].provider_name,
                                                  AP_WATCHDOG_CVERSION);
            if (w && w->active) {
                /* We have some callbacks registered.
                 * Kick of the watchdog
                 */
                if ((rv = wd_startup(w, wd_server_conf->pool)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(01573)
                                 "Watchdog: Failed to create worker thread.");
                    /* No point to continue */
                    return;
                }
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(02981)
                             "Watchdog: Created worker thread (%s).", wn[i].provider_name);
            }
        }
    }
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* WatchdogInterval directive                                               */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static const char *wd_cmd_watchdog_int(cmd_parms *cmd, void *dummy,
                                       const char *arg)
{
    apr_status_t rv;
    const char *errs = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (errs != NULL)
        return errs;
    rv = ap_timeout_parameter_parse(arg, &wd_interval, "s");

    if (rv != APR_SUCCESS)
        return "Unparse-able WatchdogInterval setting";
    if (wd_interval < AP_WD_TM_SLICE) {
        return apr_psprintf(cmd->pool, "Invalid WatchdogInterval: minimal value %"
                APR_TIME_T_FMT "ms", apr_time_as_msec(AP_WD_TM_SLICE));
    }

    return NULL;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* List of directives specific to our module.                               */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static const command_rec wd_directives[] =
{
    AP_INIT_TAKE1(
        "WatchdogInterval",                 /* directive name               */
        wd_cmd_watchdog_int,                /* config action routine        */
        NULL,                               /* argument to include in call  */
        RSRC_CONF,                          /* where available              */
        "Watchdog interval in seconds"
    ),
    {NULL}
};

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Which functions are responsible for which hooks in the server.           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static void wd_register_hooks(apr_pool_t *p)
{

    /* Only the mpm_winnt has child init hook handler.
     * Make sure that we are called after the mpm child init handler
     * initializes.
     */
    static const char *const after_mpm[]      = { "mpm_winnt.c", NULL};

    /* Pre config handling
     */
    ap_hook_pre_config(wd_pre_config_hook,
                       NULL,
                       NULL,
                       APR_HOOK_FIRST);

    /* Post config handling
     */
    ap_hook_post_config(wd_post_config_hook,
                        NULL,
                        NULL,
                        APR_HOOK_LAST);

    /* Child init hook
     */
    ap_hook_child_init(wd_child_init_hook,
                       after_mpm,
                       NULL,
                       APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(ap_watchdog_get_instance);
    APR_REGISTER_OPTIONAL_FN(ap_watchdog_register_callback);
    APR_REGISTER_OPTIONAL_FN(ap_watchdog_set_callback_interval);
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* The list of callback routines and data structures that provide           */
/* the static hooks into our module from the other parts of the server.     */
/*                                                                          */
/*--------------------------------------------------------------------------*/
AP_DECLARE_MODULE(watchdog) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure    */
    NULL,                       /* merge per-directory config structures    */
    NULL,                       /* create per-server config structure       */
    NULL,                       /* merge per-server config structures       */
    wd_directives,              /* command apr_table_t                      */
    wd_register_hooks           /* register hooks                           */
};

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* The list of optional hooks that we provide                               */
/*                                                                          */
/*--------------------------------------------------------------------------*/
APR_HOOK_STRUCT(
    APR_HOOK_LINK(watchdog_need)
    APR_HOOK_LINK(watchdog_init)
    APR_HOOK_LINK(watchdog_exit)
    APR_HOOK_LINK(watchdog_step)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, AP_WD, int, watchdog_need,
                                      (server_rec *s, const char *name,
                                       int parent, int singleton),
                                      (s, name, parent, singleton),
                                      DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, AP_WD, int, watchdog_init,
                                    (server_rec *s, const char *name,
                                     apr_pool_t *pool),
                                    (s, name, pool),
                                    OK, DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, AP_WD, int, watchdog_exit,
                                    (server_rec *s, const char *name,
                                     apr_pool_t *pool),
                                    (s, name, pool),
                                    OK, DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, AP_WD, int, watchdog_step,
                                    (server_rec *s, const char *name,
                                     apr_pool_t *pool),
                                    (s, name, pool),
                                    OK, DECLINED)
