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

/* Round Robin lbmethod EXAMPLE module for Apache proxy */

/* NOTE: This is designed simply to provide some info on how to create
         extra lbmethods via sub-modules... This code is ugly
         and needs work to actually do round-robin "right"
         but that is left as an exercise for the reader */

#include "mod_proxy.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "apr_hooks.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

module AP_MODULE_DECLARE_DATA proxy_balancer_rr_module;

typedef struct {
    int index;
} rr_data ;

/*
 */
static proxy_worker *find_best_roundrobin(proxy_balancer *balancer,
                                         request_rec *r)
{
    int i;
    proxy_worker **worker;
    proxy_worker *mycandidate = NULL;
    int checking_standby;
    int checked_standby;
    rr_data *ctx;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Entering roundrobin for BALANCER %s (%d)",
                 balancer->name, (int)getpid());
    
    /* The index of the candidate last chosen is stored in ctx->index */
    if (!balancer->context) {
        /* UGLY */
        ctx = apr_pcalloc(r->server->process->pconf, sizeof(rr_data));
        balancer->context = (void *)ctx;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Creating roundrobin ctx for BALANCER %s (%d)",
                 balancer->name, (int)getpid());
    } else {
        ctx = (rr_data *)balancer->context;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: roundrobin index: %d (%d)",
                 ctx->index, (int)getpid());

    checking_standby = checked_standby = 0;
    while (!mycandidate && !checked_standby) {
        worker = (proxy_worker **)balancer->workers->elts;

        for (i = 0; i < balancer->workers->nelts; i++, worker++) {
            if (i < ctx->index)
                continue;
            if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(*worker) : PROXY_WORKER_IS_STANDBY(*worker)) )
                continue;
            if (!PROXY_WORKER_IS_USABLE(*worker))
                ap_proxy_retry_worker("BALANCER", *worker, r->server);
            if (PROXY_WORKER_IS_USABLE(*worker)) {
                mycandidate = *worker;
                break;
            }
        }
        checked_standby = checking_standby++;
    }


    ctx->index += 1;
    if (ctx->index >= balancer->workers->nelts) {
        ctx->index = 0;
    }
    return mycandidate;
}

static apr_status_t reset(proxy_balancer *balancer, server_rec *r) {
        return APR_SUCCESS;
}

static apr_status_t age(proxy_balancer *balancer, server_rec *r) {
        return APR_SUCCESS;
}

static const proxy_balancer_method roundrobin =
{
    "roundrobin",
    &find_best_roundrobin,
    NULL,
    &reset,
    &age
};


static void ap_proxy_rr_register_hook(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_LBMETHOD, "roundrobin", "0", &roundrobin);
}

module AP_MODULE_DECLARE_DATA proxy_balancer_rr_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    ap_proxy_rr_register_hook /* register hooks */
};
