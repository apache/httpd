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

module AP_MODULE_DECLARE_DATA lbmethod_bytraffic_module;

static APR_OPTIONAL_FN_TYPE(proxy_balancer_get_best_worker)
                            *ap_proxy_balancer_get_best_worker_fn = NULL;

static int is_best_bytraffic(proxy_worker *current, proxy_worker *prev_best, void *baton)
{
    apr_off_t *min_traffic = (apr_off_t *)baton;
    apr_off_t traffic = (current->s->transferred / current->s->lbfactor)
                        + (current->s->read / current->s->lbfactor);

    if (!prev_best || (traffic < *min_traffic)) {
        *min_traffic = traffic;

        return TRUE;
    }

    return FALSE;
}

/*
 * The idea behind the find_best_bytraffic scheduler is the following:
 *
 * We know the amount of traffic (bytes in and out) handled by each
 * worker. We normalize that traffic by each workers' weight. So assuming
 * a setup as below:
 *
 * worker     a    b    c
 * lbfactor   1    1    3
 *
 * the scheduler will allow worker c to handle 3 times the
 * traffic of a and b. If each request/response results in the
 * same amount of traffic, then c would be accessed 3 times as
 * often as a or b. If, for example, a handled a request that
 * resulted in a large i/o bytecount, then b and c would be
 * chosen more often, to even things out.
 */
static proxy_worker *find_best_bytraffic(proxy_balancer *balancer,
                                         request_rec *r)
{
    apr_off_t min_traffic = 0;

    return ap_proxy_balancer_get_best_worker_fn(balancer, r, is_best_bytraffic,
                                             &min_traffic);
}

/* assumed to be mutex protected by caller */
static apr_status_t reset(proxy_balancer *balancer, server_rec *s)
{
    int i;
    proxy_worker **worker;
    worker = (proxy_worker **)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++, worker++) {
        (*worker)->s->transferred = 0;
        (*worker)->s->read = 0;
    }
    return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *s)
{
    return APR_SUCCESS;
}

static const proxy_balancer_method bytraffic =
{
    "bytraffic",
    &find_best_bytraffic,
    NULL,
    &reset,
    &age,
    NULL
};

/* post_config hook: */
static int lbmethod_bytraffic_post_config(apr_pool_t *pconf, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{

    /* lbmethod_bytraffic_post_config() will be called twice during startup.  So, don't
     * set up the static data the 1st time through. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_proxy_balancer_get_best_worker_fn =
                 APR_RETRIEVE_OPTIONAL_FN(proxy_balancer_get_best_worker);
    if (!ap_proxy_balancer_get_best_worker_fn) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10150)
                     "mod_proxy must be loaded for mod_lbmethod_bytraffic");
        return !OK;
    }

    return OK;
}

static void register_hook(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_LBMETHOD, "bytraffic", "0", &bytraffic);
    ap_hook_post_config(lbmethod_bytraffic_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(lbmethod_bytraffic) = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    register_hook /* register hooks */
};
