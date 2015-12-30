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

#include "mod_proxy.h"
#include "mod_watchdog.h"
#include "ap_slotmem.h"


module AP_MODULE_DECLARE_DATA proxy_hcheck_module;

#define HCHECK_WATHCHDOG_NAME ("_proxy_hcheck_")
/* default to health check every 30 seconds */
#define HCHECK_WATHCHDOG_SEC (30)
/* The watchdog runs every 5 seconds, which is also the minimal check */
#define HCHECK_WATHCHDOG_INTERVAL (5)

static char *methods[] = {
      "NULL", "OPTIONS", "HEAD", "GET", "POST", "CPING", NULL
};

typedef struct hc_template_t {
    char *name;
    int method;
    int passes;
    int fails;
    apr_interval_time_t interval;
    char *hurl;
} hc_template_t;

typedef struct sctx_t {
    apr_pool_t *p;
    apr_array_header_t *templates;
    ap_watchdog_t *watchdog;
    server_rec *s;
} sctx_t;

static void *hc_create_config(apr_pool_t *p, server_rec *s)
{
    sctx_t *ctx = (sctx_t *) apr_palloc(p, sizeof(sctx_t));
    apr_pool_create(&ctx->p, p);
    ctx->templates = apr_array_make(ctx->p, 10, sizeof(hc_template_t));
    ctx->s = s;

    return ctx;
}

/*
 * This serves double duty by not only validating (and creating)
 * the health-check template, but also ties into set_worker_param()
 * which does the actual setting of worker params in shm.
 */
static const char *set_worker_hc_param(apr_pool_t *p,
                                    server_rec *s,
                                    proxy_worker *worker,
                                    const char *key,
                                    const char *val,
                                    void *v)
{
    int ival;
    hc_template_t *temp;
    sctx_t *ctx = (sctx_t *) ap_get_module_config(s->module_config,
                                                  &proxy_hcheck_module);
    if (!worker && !v) {
        return "Bad call to set_worker_hc_param()";
    }
    temp = (hc_template_t *)v;
    if (!strcasecmp(key, "hcheck")) {
        hc_template_t *template;
        template = (hc_template_t *)ctx->templates->elts;
        for (ival = 0; ival < ctx->templates->nelts; ival++, template++) {
            if (!ap_casecmpstr(template->name, val)) {
                if (worker) {
                    worker->s->method = template->method;
                    worker->s->interval = template->interval;
                    worker->s->passes = template->passes;
                    worker->s->fails = template->fails;
                    PROXY_STRNCPY(worker->s->hurl, template->hurl);
                } else {
                    temp->method = template->method;
                    temp->interval = template->interval;
                    temp->passes = template->passes;
                    temp->fails = template->fails;
                    temp->hurl = apr_pstrdup(p, template->hurl);
                }
                return NULL;
            }
        }
        return apr_psprintf(p, "Unknown HCheckTemplate name: %s", val);
    }
    else if (!strcasecmp(key, "method")) {
        for (ival = 1; methods[ival]; ival++) {
            if (!ap_casecmpstr(val, methods[ival])) {
                if (worker) {
                    worker->s->method = ival;
                } else {
                    temp->method = ival;
                }
                return NULL;
            }
        }
        return "Unknown method";
    }
    else if (!strcasecmp(key, "interval")) {
        ival = atoi(val);
        if (ival < 5)
            return "Interval must be a positive value greater than 5 seconds";
        if (worker) {
            worker->s->interval = apr_time_from_sec(ival);
        } else {
            temp->interval = apr_time_from_sec(ival);
        }
    }
    else if (!strcasecmp(key, "passes")) {
        ival = atoi(val);
        if (ival < 0)
            return "Passes must be a positive value";
        if (worker) {
            worker->s->passes = ival;
        } else {
            temp->passes = ival;
        }
    }
    else if (!strcasecmp(key, "fails")) {
        ival = atoi(val);
        if (ival < 0)
            return "Fails must be a positive value";
        if (worker) {
            worker->s->fails = ival;
        } else {
            temp->fails = ival;
        }
    }
    else if (!strcasecmp(key, "hurl")) {
        if (strlen(val) >= sizeof(worker->s->hurl))
            return apr_psprintf(p, "Health check hurl length must be < %d characters",
                    (int)sizeof(worker->s->hurl));
        if (worker) {
            PROXY_STRNCPY(worker->s->hurl, val);
        } else {
            temp->hurl = apr_pstrdup(p, val);
        }
    }
    else {
        return "unknown Worker hcheck parameter";
    }
    return NULL;
}

static const char *set_hcheck(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *name = NULL;
    char *word, *val;
    hc_template_t *template;
    sctx_t *ctx;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;
    ctx = (sctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &proxy_hcheck_module);

    template = (hc_template_t *)apr_array_push(ctx->templates);

    template->name = apr_pstrdup(ctx->p, ap_getword_conf(cmd->temp_pool, &arg));
    template->method = template->passes = template->fails = 1;
    template->interval = apr_time_from_sec(HCHECK_WATHCHDOG_SEC);
    template->hurl = NULL;
    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid HCheckTemplate parameter. Parameter must be "
                   "in the form 'key=value'";
        }
        else
            *val++ = '\0';
        err = set_worker_hc_param(ctx->p, ctx->s, NULL, word, val, template);

        if (err) {
            void *v;
            /* get rid of recently pushed (bad) template */
            v = apr_array_pop(ctx->templates);
            return apr_pstrcat(cmd->temp_pool, "HCheckTemplate: ", err, " ", word, "=", val, "; ", name, NULL);
        }
        /* No error means we have a valid template */
    }

    return NULL;
}

static void hc_check(apr_pool_t *p, server_rec *s, apr_time_t now,
                     proxy_worker *worker)
{
    /* TODO: REMOVE ap_log_error call */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                 "Health check (%s).", worker->s->name);
    return;
}

static apr_status_t hc_watchdog_callback(int state, void *data,
                                         apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t now = apr_time_now();
    proxy_balancer *balancer;
    sctx_t *ctx = (sctx_t *)data;
    server_rec *s = ctx->s;
    proxy_server_conf *conf;
    apr_pool_t *p;
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                         "%s watchdog started.",
                         HCHECK_WATHCHDOG_NAME);
            break;

        case AP_WATCHDOG_STATE_RUNNING:
            /* loop thru all workers */
            /* TODO: REMOVE ap_log_error call */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                         "Run of %s watchdog.",
                         HCHECK_WATHCHDOG_NAME);
            apr_pool_create(&p, pool);
            while (s) {
                int i;
                conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
                balancer = (proxy_balancer *)conf->balancers->elts;
                for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
                    int n;
                    proxy_worker **workers;
                    proxy_worker *worker;
                    workers = (proxy_worker **)balancer->workers->elts;
                    for (n = 0; n < balancer->workers->nelts; n++) {
                        worker = *workers;
                        /* TODO: REMOVE ap_log_error call */
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                                     "Checking worker: %s:%d (%lu %lu %lu)",
                                     worker->s->name, worker->s->method, (unsigned long)now,
                                     (unsigned long)worker->s->updated, (unsigned long)worker->s->interval);
                        if (worker->s->method && (now > worker->s->updated + worker->s->interval)) {
                            hc_check(p, s, now, worker);
                        }
                        workers++;
                    }
                }
                s = s->next;
            }
            apr_pool_destroy(p);
            break;

        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                         "stopping %s watchdog.",
                         HCHECK_WATHCHDOG_NAME);
            break;
    }
    return rv;
}

static int hc_post_config(apr_pool_t *p, apr_pool_t *plog,
                       apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    sctx_t *ctx;

    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *hc_watchdog_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *hc_watchdog_register_callback;

    hc_watchdog_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    hc_watchdog_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!hc_watchdog_get_instance || !hc_watchdog_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO()
                     "mod_watchdog is required");
        return !OK;
    }
    ctx = (sctx_t *) ap_get_module_config(s->module_config,
                                          &proxy_hcheck_module);

    rv = hc_watchdog_get_instance(&ctx->watchdog,
                                  HCHECK_WATHCHDOG_NAME,
                                  0, 1, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "Failed to create watchdog instance (%s)",
                     HCHECK_WATHCHDOG_NAME);
        return !OK;
    }
    rv = hc_watchdog_register_callback(ctx->watchdog,
            apr_time_from_sec(HCHECK_WATHCHDOG_INTERVAL),
            ctx,
            hc_watchdog_callback);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "Failed to register watchdog callback (%s)",
                     HCHECK_WATHCHDOG_NAME);
        return !OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                 "watchdog callback registered (%s)", HCHECK_WATHCHDOG_NAME);
    return OK;
}

static const command_rec command_table[] = {
    AP_INIT_RAW_ARGS("HCheckTemplate", set_hcheck, NULL, OR_FILEINFO,
                     "Health check template"),
    { NULL }
};

static void hc_register_hooks(apr_pool_t *p)
{
    static const char *const runAfter[] = { "mod_watchdog.c", "mod_proxy_balancer.c", NULL};
    APR_REGISTER_OPTIONAL_FN(set_worker_hc_param);
    ap_hook_post_config(hc_post_config, NULL, runAfter, APR_HOOK_LAST);
}

/* the main config structure */

AP_DECLARE_MODULE(proxy_hcheck) =
{
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-dir config structures */
    NULL,              /* merge  per-dir config structures */
    hc_create_config,  /* create per-server config structures */
    NULL,              /* merge  per-server config structures */
    command_table,     /* table of config file commands */
    hc_register_hooks  /* register hooks */
};
