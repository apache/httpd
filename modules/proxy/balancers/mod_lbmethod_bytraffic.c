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
#include "apr_hooks.h"

module AP_MODULE_DECLARE_DATA lbmethod_bytraffic_module;

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
    int i;
    apr_off_t mytraffic = 0;
    apr_off_t curmin = 0;
    proxy_worker **worker;
    proxy_worker *mycandidate = NULL;
    int cur_lbset = 0;
    int max_lbset = 0;
    int checking_standby;
    int checked_standby;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Entering bytraffic for BALANCER (%s)",
                 balancer->name);

    /* First try to see if we have available candidate */
    do {
        checking_standby = checked_standby = 0;
        while (!mycandidate && !checked_standby) {
            worker = (proxy_worker **)balancer->workers->elts;
            for (i = 0; i < balancer->workers->nelts; i++, worker++) {
                if (!checking_standby) {    /* first time through */
                    if ((*worker)->s->lbset > max_lbset)
                        max_lbset = (*worker)->s->lbset;
                }
                if ((*worker)->s->lbset != cur_lbset)
                    continue;
                if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(*worker) : PROXY_WORKER_IS_STANDBY(*worker)) )
                    continue;
                /* If the worker is in error state run
                 * retry on that worker. It will be marked as
                 * operational if the retry timeout is elapsed.
                 * The worker might still be unusable, but we try
                 * anyway.
                 */
                if (!PROXY_WORKER_IS_USABLE(*worker))
                    ap_proxy_retry_worker("BALANCER", *worker, r->server);
                /* Take into calculation only the workers that are
                 * not in error state or not disabled.
                 */
                if (PROXY_WORKER_IS_USABLE(*worker)) {
                    mytraffic = ((*worker)->s->transferred/(*worker)->s->lbfactor) +
                                ((*worker)->s->read/(*worker)->s->lbfactor);
                    if (!mycandidate || mytraffic < curmin) {
                        mycandidate = *worker;
                        curmin = mytraffic;
                    }
                }
            }
            checked_standby = checking_standby++;
        }
        cur_lbset++;
    } while (cur_lbset <= max_lbset && !mycandidate);

    if (mycandidate) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: bytraffic selected worker \"%s\" : busy %" APR_SIZE_T_FMT,
                     mycandidate->name, mycandidate->s->busy);

    }

    return mycandidate;
}

static apr_status_t reset(proxy_balancer *balancer, server_rec *s) {
        return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *s) {
        return APR_SUCCESS;
}

static const proxy_balancer_method bytraffic =
{
    "bytraffic",
    &find_best_bytraffic,
    NULL,
    &reset,
    &age
};

static void register_hook(apr_pool_t *p)
{
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes and after the mod_proxy
     */
    ap_register_provider(p, PROXY_LBMETHOD, "bytraffic", "0", &bytraffic);
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
