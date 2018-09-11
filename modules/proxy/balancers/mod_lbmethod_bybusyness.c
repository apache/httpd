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
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "ap_hooks.h"

module AP_MODULE_DECLARE_DATA lbmethod_bybusyness_module;

static APR_OPTIONAL_FN_TYPE(proxy_balancer_get_best_worker)
                            *ap_proxy_balancer_get_best_worker_fn = NULL;

static int is_best_bybusyness(proxy_worker *current, proxy_worker *prev_best, void *baton)
{
    int *total_factor = (int *)baton;

    current->s->lbstatus += current->s->lbfactor;
    *total_factor += current->s->lbfactor;

    return (
        !prev_best
        || (current->s->busy < prev_best->s->busy)
        || (
            (current->s->busy == prev_best->s->busy)
            && (current->s->lbstatus > prev_best->s->lbstatus)
        )
    );
}

static proxy_worker *find_best_bybusyness(proxy_balancer *balancer,
                                          request_rec *r)
{
    int total_factor = 0;
    proxy_worker *worker =
        ap_proxy_balancer_get_best_worker_fn(balancer, r, is_best_bybusyness,
                                          &total_factor);

    if (worker) {
        worker->s->lbstatus -= total_factor;
    }

    return worker;
}

/* assumed to be mutex protected by caller */
static apr_status_t reset(proxy_balancer *balancer, server_rec *s)
{
    int i;
    proxy_worker **worker;
    worker = (proxy_worker **)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++, worker++) {
        (*worker)->s->lbstatus = 0;
        (*worker)->s->busy = 0;
    }
    return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *s)
{
    return APR_SUCCESS;
}

static const proxy_balancer_method bybusyness =
{
    "bybusyness",
    &find_best_bybusyness,
    NULL,
    &reset,
    &age,
    NULL
};

/* post_config hook: */
static int lbmethod_bybusyness_post_config(apr_pool_t *pconf, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{

    /* lbmethod_bybusyness_post_config() will be called twice during startup.  So, don't
     * set up the static data the 1st time through. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_proxy_balancer_get_best_worker_fn =
                 APR_RETRIEVE_OPTIONAL_FN(proxy_balancer_get_best_worker);
    if (!ap_proxy_balancer_get_best_worker_fn) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10151)
                     "mod_proxy must be loaded for mod_lbmethod_bybusyness");
        return !OK;
    }

    return OK;
}

static void register_hook(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_LBMETHOD, "bybusyness", "0", &bybusyness);
    ap_hook_post_config(lbmethod_bybusyness_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(lbmethod_bybusyness) = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    register_hook /* register hooks */
};
