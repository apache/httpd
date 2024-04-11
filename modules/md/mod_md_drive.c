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
 
#include <assert.h>
#include <apr_optional.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_date.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "mod_watchdog.h"

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_event.h"
#include "md_http.h"
#include "md_json.h"
#include "md_status.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_private.h"
#include "mod_md_config.h"
#include "mod_md_status.h"
#include "mod_md_drive.h"

/**************************************************************************************************/
/* watchdog based impl. */

#define MD_RENEW_WATCHDOG_NAME   "_md_renew_"

static APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *wd_get_instance;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *wd_register_callback;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *wd_set_interval;

struct md_renew_ctx_t {
    apr_pool_t *p;
    server_rec *s;
    md_mod_conf_t *mc;
    ap_watchdog_t *watchdog;
    
    apr_array_header_t *jobs;
};

static void process_drive_job(md_renew_ctx_t *dctx, md_job_t *job, apr_pool_t *ptemp)
{
    const md_t *md;
    md_result_t *result = NULL;
    apr_status_t rv;
    
    md_job_load(job);
    /* Evaluate again on loaded value. Values will change when watchdog switches child process */
    if (apr_time_now() < job->next_run) return;
    
    job->next_run = 0;
    if (job->finished && job->notified_renewed) {
        /* finished and notification handled, nothing to do. */
        goto leave;
    }
    
    md = md_get_by_name(dctx->mc->mds, job->mdomain);
    AP_DEBUG_ASSERT(md);

    result = md_result_md_make(ptemp, md->name);
    if (job->last_result) md_result_assign(result, job->last_result);
    
    if (md->state == MD_S_MISSING_INFORMATION) {
        /* Missing information, this will not change until configuration
         * is changed and server reloaded. */
        job->fatal_error = 1;
        job->next_run = 0;
        goto leave;
    }
    
    if (md_will_renew_cert(md)) {
        /* Renew the MDs credentials in a STAGING area. Might be invoked repeatedly
         * without discarding previous/intermediate results.
         * Only returns SUCCESS when the renewal is complete, e.g. STAGING has a
         * complete set of new credentials.
         */
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10052) 
                     "md(%s): state=%d, driving", job->mdomain, md->state);

        if (md->stapling && dctx->mc->ocsp &&
            md_reg_has_revoked_certs(dctx->mc->reg, dctx->mc->ocsp, md, dctx->p)) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10500)
                         "md(%s): has revoked certificates", job->mdomain);
        }
        else if (!md_reg_should_renew(dctx->mc->reg, md, dctx->p)) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10053) 
                         "md(%s): no need to renew", job->mdomain);
            goto expiry;
        }
    
        /* The (possibly configured) event handler may veto renewals. This
         * is used in cluster installtations, see #233. */
        rv = md_event_raise("renewing", md->name, job, result, ptemp);
        if (APR_SUCCESS != rv) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, dctx->s, APLOGNO(10060)
                             "%s: event-handler for 'renewing' returned %d, preventing renewal to proceed.",
                             job->mdomain, rv);
                goto leave;
        }

        md_job_start_run(job, result, md_reg_store_get(dctx->mc->reg));
        md_reg_renew(dctx->mc->reg, md, dctx->mc->env, 0, job->error_runs, result, ptemp);
        md_job_end_run(job, result);
        
        if (APR_SUCCESS == result->status) {
            /* Finished jobs might take a while before the results become valid.
             * If that is in the future, request to run then */
            if (apr_time_now() < result->ready_at) {
                md_job_retry_at(job, result->ready_at);
                goto leave;
            }
            
            if (!job->notified_renewed) {
                md_job_save(job, result, ptemp);
                md_job_notify(job, "renewed", result);
            }
        }
        else {
            ap_log_error( APLOG_MARK, APLOG_ERR, result->status, dctx->s, APLOGNO(10056) 
                         "processing %s: %s", job->mdomain, result->detail);
            md_job_log_append(job, "renewal-error", result->problem, result->detail);
            md_event_holler("errored", job->mdomain, job, result, ptemp);
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, dctx->s, APLOGNO(10057) 
                         "%s: encountered error for the %d. time, next run in %s",
                         job->mdomain, job->error_runs, 
                         md_duration_print(ptemp, job->next_run - apr_time_now()));
        }
    }

expiry:
    if (!job->finished && md_reg_should_warn(dctx->mc->reg, md, dctx->p)) {
        ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, dctx->s,
                     "md(%s): warn about expiration", md->name);
        md_job_start_run(job, result, md_reg_store_get(dctx->mc->reg));
        md_job_notify(job, "expiring", result);
        md_job_end_run(job, result);
    }

leave:
    if (job->dirty && result) {
        rv = md_job_save(job, result, ptemp);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, dctx->s, "%s: saving job props", job->mdomain);
    }
}

int md_will_renew_cert(const md_t *md)
{
    if (md->renew_mode == MD_RENEW_MANUAL) {
        return 0;
    }
    else if (md->renew_mode == MD_RENEW_AUTO && md->cert_files && md->cert_files->nelts) {
        return 0;
    } 
    return 1;
}

static apr_time_t next_run_default(md_renew_ctx_t *dctx)
{
    unsigned char c;
    apr_time_t delay = dctx->mc->check_interval;

    md_rand_bytes(&c, sizeof(c), dctx->p);
    return apr_time_now() + delay + (delay * (c - 128) / 256);
}

static apr_status_t run_watchdog(int state, void *baton, apr_pool_t *ptemp)
{
    md_renew_ctx_t *dctx = baton;
    md_job_t *job;
    apr_time_t next_run, wait_time;
    int i;
    
    /* mod_watchdog invoked us as a single thread inside the whole server (on this machine).
     * This might be a repeated run inside the same child (mod_watchdog keeps affinity as
     * long as the child lives) or another/new child.
     */
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10054)
                         "md watchdog start, auto drive %d mds", dctx->jobs->nelts);
            break;
            
        case AP_WATCHDOG_STATE_RUNNING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10055)
                         "md watchdog run, auto drive %d mds", dctx->jobs->nelts);
                         
            /* Process all drive jobs. They will update their next_run property
             * and we schedule ourself at the earliest of all. A job may specify 0
             * as next_run to indicate that it wants to participate in the normal
             * regular runs. */
            next_run = next_run_default(dctx);
            for (i = 0; i < dctx->jobs->nelts; ++i) {
                job = APR_ARRAY_IDX(dctx->jobs, i, md_job_t *);
                
                if (apr_time_now() >= job->next_run) {
                    process_drive_job(dctx, job, ptemp);
                }
                
                if (job->next_run && job->next_run < next_run) {
                    next_run = job->next_run;
                }
            }

            wait_time = next_run - apr_time_now();
            if (APLOGdebug(dctx->s)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10107)
                             "next run in %s", md_duration_print(ptemp, wait_time));
            }
            wd_set_interval(dctx->watchdog, wait_time, dctx, run_watchdog);
            break;
            
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, dctx->s, APLOGNO(10058)
                         "md watchdog stopping");
            break;
    }
    
    return APR_SUCCESS;
}

apr_status_t md_renew_start_watching(md_mod_conf_t *mc, server_rec *s, apr_pool_t *p)
{
    apr_allocator_t *allocator;
    md_renew_ctx_t *dctx;
    apr_pool_t *dctxp;
    apr_status_t rv;
    md_t *md;
    md_job_t *job;
    int i;
    
    /* We use mod_watchdog to run a single thread in one of the child processes
     * to monitor the MDs marked as watched, using the const data in the list
     * mc->mds of our MD structures.
     *
     * The data in mc cannot be changed, as we may spawn copies in new child processes
     * of the original data at any time. The child which hosts the watchdog thread
     * may also die or be recycled, which causes a new watchdog thread to run
     * in another process with the original data.
     * 
     * Instead, we use our store to persist changes in group STAGING. This is
     * kept writable to child processes, but the data stored there is not live.
     * However, mod_watchdog makes sure that we only ever have a single thread in
     * our server (on this machine) that writes there. Other processes, e.g. informing
     * the user about progress, only read from there.
     *
     * All changes during driving an MD are stored as files in MG_SG_STAGING/<MD.name>.
     * All will have "md.json" and "job.json". There may be a range of other files used
     * by the protocol obtaining the certificate/keys.
     * 
     * 
     */
    wd_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    wd_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    wd_set_interval = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_set_callback_interval);
    
    if (!wd_get_instance || !wd_register_callback || !wd_set_interval) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10061) "mod_watchdog is required");
        return !OK;
    }
    
    /* We want our own pool with own allocator to keep data across watchdog invocations.
     * Since we'll run in a single watchdog thread, using our own allocator will prevent 
     * any confusion in the parent pool. */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, 1);
    rv = apr_pool_create_ex(&dctxp, p, NULL, allocator);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10062) "md_renew_watchdog: create pool");
        return rv;
    }
    apr_allocator_owner_set(allocator, dctxp);
    apr_pool_tag(dctxp, "md_renew_watchdog");

    dctx = apr_pcalloc(dctxp, sizeof(*dctx));
    dctx->p = dctxp;
    dctx->s = s;
    dctx->mc = mc;
    
    dctx->jobs = apr_array_make(dctx->p, mc->mds->nelts, sizeof(md_job_t *));
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        if (!md || !md->watched) continue;
        
        job = md_reg_job_make(mc->reg, md->name, p);
        APR_ARRAY_PUSH(dctx->jobs, md_job_t*) = job;
        ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, dctx->s,  
                     "md(%s): state=%d, created drive job", md->name, md->state);
        
        md_job_load(job);
        if (job->error_runs) {
            /* Server has just restarted. If we encounter an MD job with errors
             * on a previous driving, we purge its STAGING area.
             * This will reset the driving for the MD. It may run into the same
             * error again, or in case of race/confusion/our error/CA error, it
             * might allow the MD to succeed by a fresh start.
             */
            ap_log_error( APLOG_MARK, APLOG_NOTICE, 0, dctx->s, APLOGNO(10064) 
                         "md(%s): previous drive job showed %d errors, purging STAGING "
                         "area to reset.", md->name, job->error_runs);
            md_store_purge(md_reg_store_get(dctx->mc->reg), p, MD_SG_STAGING, md->name);
            md_store_purge(md_reg_store_get(dctx->mc->reg), p, MD_SG_CHALLENGES, md->name);
            job->error_runs = 0;
        }
    }

    if (!dctx->jobs->nelts) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10065)
                     "no managed domain to drive, no watchdog needed.");
        apr_pool_destroy(dctx->p);
        return APR_SUCCESS;
    }
    
    if (APR_SUCCESS != (rv = wd_get_instance(&dctx->watchdog, MD_RENEW_WATCHDOG_NAME, 0, 1, dctx->p))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(10066) 
                     "create md renew watchdog(%s)", MD_RENEW_WATCHDOG_NAME);
        return rv;
    }
    rv = wd_register_callback(dctx->watchdog, 0, dctx, run_watchdog);
    ap_log_error(APLOG_MARK, rv? APLOG_CRIT : APLOG_DEBUG, rv, s, APLOGNO(10067) 
                 "register md renew watchdog(%s)", MD_RENEW_WATCHDOG_NAME);
    return rv;
}
