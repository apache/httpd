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

module AP_MODULE_DECLARE_DATA proxy_hcheck_module;

#define HCHECK_WATHCHDOG_NAME ("_proxy_hcheck_")
/* default to health check every 30 seconds */
#define HCHECK_WATHCHDOG_SEC (30)
/* The watchdog runs every 5 seconds, which is also the minimal check */
#define HCHECK_WATHCHDOG_INTERVAL (5)

static char *methods[] = {
      "NULL", "OPTIONS", "HEAD", "GET", "POST", "CPING"
};

typedef struct hcheck_template_t {
    char *name;
    int method;
    int passes;
    int fails;
    apr_interval_time_t interval;
    char *hurl;
} hcheck_template_t;

static apr_pool_t *ptemplate = NULL;
static apr_array_header_t *templates = NULL;
static ap_watchdog_t *watchdog;

/*
 * This is not as clean as it should be, because we are using
 * the same to both update the actual worker as well as verifying
 * and populating the health check 'template' as well.
 */
static const char *set_worker_hc_param(apr_pool_t *p,
                                    proxy_worker *worker,
                                    const char *key,
                                    const char *val,
                                    void *tmp)
{
    int ival;
    hcheck_template_t *ctx;

    if (!worker && !tmp) {
        return "Bad call to set_worker_hc_param()";
    }
    ctx = (hcheck_template_t *)tmp;
    if (!strcasecmp(key, "hcheck")) {
        hcheck_template_t *template;
        template = (hcheck_template_t *)templates->elts;
        for (ival = 0; ival < templates->nelts; ival++, template++) {
            if (!ap_casecmpstr(template->name, val)) {
                worker->s->method = template->method;
                worker->s->interval = template->interval;
                worker->s->passes = template->passes;
                worker->s->fails = template->fails;
                PROXY_STRNCPY(worker->s->hurl, template->hurl);
                return NULL;
            }
        }
        return apr_psprintf(p, "Unknown HCheckTemplate name: %s", val);
    }
    else if (!strcasecmp(key, "method")) {
        for (ival = 1; ival < sizeof(methods); ival++) {
            if (!ap_casecmpstr(val, methods[ival])) {
                if (worker) {
                    worker->s->method = ival;
                } else {
                    ctx->method = ival;
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
            ctx->interval = apr_time_from_sec(ival);
        }
    }
    else if (!strcasecmp(key, "passes")) {
        ival = atoi(val);
        if (ival < 0)
            return "Passes must be a positive value";
        if (worker) {
            worker->s->passes = ival;
        } else {
            ctx->passes = ival;
        }
    }
    else if (!strcasecmp(key, "fails")) {
        ival = atoi(val);
        if (ival < 0)
            return "Fails must be a positive value";
        if (worker) {
            worker->s->fails = ival;
        } else {
            ctx->fails = ival;
        }
    }
    else if (!strcasecmp(key, "hurl")) {
        if (strlen(val) >= sizeof(worker->s->hurl))
            return apr_psprintf(p, "Health check hurl length must be < %d characters",
                    (int)sizeof(worker->s->hurl));
        if (worker) {
            PROXY_STRNCPY(worker->s->hurl, val);
        } else {
            ctx->hurl = apr_pstrdup(p, val);
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
    hcheck_template_t template;
    hcheck_template_t *tpush;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    template.name = ap_getword_conf(cmd->temp_pool, &arg);
    template.method = template.passes = template.fails = 1;
    template.interval = apr_time_from_sec(HCHECK_WATHCHDOG_SEC);
    template.hurl = NULL;
    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid HCheckTemplate parameter. Parameter must be "
                   "in the form 'key=value'";
        }
        else
            *val++ = '\0';
        err = set_worker_hc_param(cmd->pool, NULL, word, val, &template);

        if (err)
            return apr_pstrcat(cmd->temp_pool, "HCheckTemplate: ", err, " ", word, "=", val, "; ", name, NULL);
        /* No error means we have a valid template */
        tpush = (hcheck_template_t *)apr_array_push(templates);
        memcpy(tpush, &template, sizeof(hcheck_template_t));
    }

    return NULL;
}

static apr_status_t hc_watchdog_callback(int state, void *data,
                                         apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t cur, now;


    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO()
                         "%s watchdog started.",
                         HCHECK_WATHCHDOG_NAME);
        break;
        case AP_WATCHDOG_STATE_RUNNING:
            cur = now = apr_time_sec(apr_time_now());
            /*
            while ((now - cur) < apr_time_sec(ctx->interval)) {
                break;
            }
             */
        break;
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO()
                         "stopping %s watchdog.",
                         HCHECK_WATHCHDOG_NAME);

        break;
    }
    return rv;
}

static int hc_pre_config(apr_pool_t *p, apr_pool_t *plog,
                      apr_pool_t *ptemp)
{
    if (!ptemplate) {
        apr_pool_create(&ptemplate, p);
    }
    if (!templates) {
        templates = apr_array_make(ptemplate, 10, sizeof(hcheck_template_t));
    }
    return OK;
}

static int hc_post_config(apr_pool_t *p, apr_pool_t *plog,
                       apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *hc_watchdog_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *hc_watchdog_register_callback;

    hc_watchdog_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    hc_watchdog_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!hc_watchdog_get_instance || !hc_watchdog_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO()
                     "mod_watchdog is required");
        return !OK;
    }

    rv = hc_watchdog_get_instance(&watchdog,
                                  HCHECK_WATHCHDOG_NAME,
                                  0, 1, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "Failed to create watchdog instance (%s)",
                     HCHECK_WATHCHDOG_NAME);
        return !OK;
    }
    rv = hc_watchdog_register_callback(watchdog,
            apr_time_from_sec(HCHECK_WATHCHDOG_INTERVAL),
            NULL,
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
    static const char *const runAfter[] = { "mod_watchdog.c", NULL};
    APR_REGISTER_OPTIONAL_FN(set_worker_hc_param);
    ap_hook_pre_config(hc_pre_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(hc_post_config, NULL, runAfter, APR_HOOK_LAST);
}

/* the main config structure */

AP_DECLARE_MODULE(proxy_hcheck) =
{
    STANDARD20_MODULE_STUFF,
    NULL,           /* create per-dir config structures */
    NULL,           /* merge  per-dir config structures */
    NULL,           /* create per-server config structures */
    NULL,           /* merge  per-server config structures */
    command_table,  /* table of config file commands */
    hc_register_hooks  /* register hooks */
};
