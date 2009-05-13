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

module AP_MODULE_DECLARE_DATA lbmethod_bybusyness_module;

static proxy_worker *find_best_bybusyness(proxy_balancer *balancer,
                                request_rec *r)
{

    int i;
    proxy_worker **worker;
    proxy_worker *mycandidate = NULL;
    int cur_lbset = 0;
    int max_lbset = 0;
    int checking_standby;
    int checked_standby;

    int total_factor = 0;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Entering bybusyness for BALANCER (%s)",
                 balancer->name);

    /* First try to see if we have available candidate */
    do {

        checking_standby = checked_standby = 0;
        while (!mycandidate && !checked_standby) {

            worker = (proxy_worker **)balancer->workers->elts;
            for (i = 0; i < balancer->workers->nelts; i++, worker++) {
                if  (!checking_standby) {    /* first time through */
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

                    (*worker)->s->lbstatus += (*worker)->s->lbfactor;
                    total_factor += (*worker)->s->lbfactor;
                    
                    if (!mycandidate
                        || (*worker)->s->busy < mycandidate->s->busy
                        || ((*worker)->s->busy == mycandidate->s->busy && (*worker)->s->lbstatus > mycandidate->s->lbstatus))
                        mycandidate = *worker;

                }

            }

            checked_standby = checking_standby++;

        }

        cur_lbset++;

    } while (cur_lbset <= max_lbset && !mycandidate);

    if (mycandidate) {
        mycandidate->s->lbstatus -= total_factor;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: bybusyness selected worker \"%s\" : busy %" APR_SIZE_T_FMT " : lbstatus %d",
                     mycandidate->name, mycandidate->s->busy, mycandidate->s->lbstatus);

    }

    return mycandidate;

}

static apr_status_t reset(proxy_balancer *balancer, server_rec *s) {
        return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *s) {
        return APR_SUCCESS;
}

static const proxy_balancer_method bybusyness =
{
    "bybusyness",
    &find_best_bybusyness,
    NULL,
    &reset,
    &age
};


static void register_hook(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_LBMETHOD, "bybusyness", "0", &bybusyness);
}

module AP_MODULE_DECLARE_DATA lbmethod_bybusyness_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    register_hook /* register hooks */
};
