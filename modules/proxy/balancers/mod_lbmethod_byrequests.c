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

module AP_MODULE_DECLARE_DATA lbmethod_byrequests_module;

static APR_OPTIONAL_FN_TYPE(proxy_balancer_get_best_worker)
                            *ap_proxy_balancer_get_best_worker_fn = NULL;

static int is_best_byrequests(proxy_worker *current, proxy_worker *prev_best, void *baton)
{
    int *total_factor = (int *)baton;

    current->s->lbstatus += current->s->lbfactor;
    *total_factor += current->s->lbfactor;

    return (!prev_best || (current->s->lbstatus > prev_best->s->lbstatus));
}

/*
 * The idea behind the find_best_byrequests scheduler is the following:
 *
 * lbfactor is "how much we expect this worker to work", or "the worker's
 * normalized work quota".
 *
 * lbstatus is "how urgent this worker has to work to fulfill its quota
 * of work".
 *
 * We distribute each worker's work quota to the worker, and then look
 * which of them needs to work most urgently (biggest lbstatus).  This
 * worker is then selected for work, and its lbstatus reduced by the
 * total work quota we distributed to all workers.  Thus the sum of all
 * lbstatus does not change.(*)
 *
 * If some workers are disabled, the others will
 * still be scheduled correctly.
 *
 * If a balancer is configured as follows:
 *
 * worker     a    b    c    d
 * lbfactor  25   25   25   25
 *
 * And b gets disabled, the following schedule is produced:
 *
 *    a c d a c d a c d ...
 *
 * Note that the above lbfactor setting is the *exact* same as:
 *
 * worker     a    b    c    d
 * lbfactor   1    1    1    1
 *
 * Asymmetric configurations work as one would expect. For
 * example:
 *
 * worker     a    b    c    d
 * lbfactor   1    1    1    2
 *
 * would have a, b and c all handling about the same
 * amount of load with d handling twice what a or b
 * or c handles individually. So we could see:
 *
 *   b a d c d a c d b d ...
 *
 */
static proxy_worker *find_best_byrequests(proxy_balancer *balancer,
                                request_rec *r)
{
    int total_factor = 0;
    proxy_worker *worker = ap_proxy_balancer_get_best_worker_fn(balancer, r, is_best_byrequests, &total_factor);

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
    }
    return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *s)
{
    return APR_SUCCESS;
}

/*
 * How to add additional lbmethods:
 *   1. Create func which determines "best" candidate worker
 *      (eg: find_best_bytraffic, above)
 *   2. Register it as a provider.
 */
static const proxy_balancer_method byrequests =
{
    "byrequests",
    &find_best_byrequests,
    NULL,
    &reset,
    &age,
    NULL
};

/* post_config hook: */
static int lbmethod_byrequests_post_config(apr_pool_t *pconf, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{

    /* lbmethod_byrequests_post_config() will be called twice during startup.  So, don't
     * set up the static data the 1st time through. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_proxy_balancer_get_best_worker_fn =
                 APR_RETRIEVE_OPTIONAL_FN(proxy_balancer_get_best_worker);
    if (!ap_proxy_balancer_get_best_worker_fn) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10152)
                     "mod_proxy must be loaded for mod_lbmethod_byrequests");
        return !OK;
    }

    return OK;
}

static void register_hook(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_LBMETHOD, "byrequests", "0", &byrequests);
    ap_hook_post_config(lbmethod_byrequests_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(lbmethod_byrequests) = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    register_hook /* register hooks */
};
