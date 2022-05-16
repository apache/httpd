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
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <apr_date.h>

#include "md_json.h"
#include "md.h"
#include "md_acme.h"
#include "md_crypt.h"
#include "md_event.h"
#include "md_log.h"
#include "md_ocsp.h"
#include "md_store.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_status.h"

#define MD_STATUS_WITH_SCTS     0

/**************************************************************************************************/
/* certificate status information */

static apr_status_t status_get_cert_json(md_json_t **pjson, const md_cert_t *cert, apr_pool_t *p)
{
    const char *finger;
    apr_status_t rv = APR_SUCCESS;
    md_timeperiod_t valid;
    md_json_t *json;
    
    json = md_json_create(p);
    valid.start = md_cert_get_not_before(cert);
    valid.end = md_cert_get_not_after(cert);
    md_json_set_timeperiod(&valid, json, MD_KEY_VALID, NULL);
    md_json_sets(md_cert_get_serial_number(cert, p), json, MD_KEY_SERIAL, NULL);
    if (APR_SUCCESS != (rv = md_cert_to_sha256_fingerprint(&finger, cert, p))) goto leave;
    md_json_sets(finger, json, MD_KEY_SHA256_FINGERPRINT, NULL);

#if MD_STATUS_WITH_SCTS
    do {
        apr_array_header_t *scts;
        const char *hex;
        const md_sct *sct;
        md_json_t *sctj;
        int i;
        
        scts = apr_array_make(p, 5, sizeof(const md_sct*));
        if (APR_SUCCESS == md_cert_get_ct_scts(scts, p, cert)) {
            for (i = 0; i < scts->nelts; ++i) {
                sct = APR_ARRAY_IDX(scts, i, const md_sct*);
                sctj = md_json_create(p);
                
                apr_rfc822_date(ts, sct->timestamp);
                md_json_sets(ts, sctj, "signed", NULL);
                md_json_setl(sct->version, sctj, MD_KEY_VERSION, NULL);
                md_data_to_hex(&hex, 0, p, sct->logid);
                md_json_sets(hex, sctj, "logid", NULL);
                md_data_to_hex(&hex, 0, p, sct->signature);
                md_json_sets(hex, sctj, "signature", NULL);
                md_json_sets(md_nid_get_sname(sct->signature_type_nid), sctj, "signature-type", NULL);
                md_json_addj(sctj, json, "scts", NULL);
            }
        }
    while (0);
#endif
leave:
    *pjson = (APR_SUCCESS == rv)? json : NULL;
    return rv;
}

static apr_status_t job_loadj(md_json_t **pjson, md_store_group_t group, const char *name,
                              struct md_reg_t *reg, int with_log, apr_pool_t *p)
{
    apr_status_t rv;

    md_store_t *store = md_reg_store_get(reg);
    rv = md_store_load_json(store, group, name, MD_FN_JOB, pjson, p);
    if (APR_SUCCESS == rv && !with_log) md_json_del(*pjson, MD_KEY_LOG, NULL);
    return rv;
}

static apr_status_t status_get_cert_json_ex(
    md_json_t **pjson,
    const md_cert_t *cert,
    const md_t *md,
    md_reg_t *reg,
    md_ocsp_reg_t *ocsp,
    int with_logs,
    apr_pool_t *p)
{
    md_json_t *certj, *jobj;
    md_timeperiod_t ocsp_valid;
    md_ocsp_cert_stat_t cert_stat;
    apr_status_t rv;

    if (APR_SUCCESS != (rv = status_get_cert_json(&certj, cert, p))) goto leave;
    if (md->stapling && ocsp) {
        rv = md_ocsp_get_meta(&cert_stat, &ocsp_valid, ocsp, cert, p, md);
        if (APR_SUCCESS == rv) {
            md_json_sets(md_ocsp_cert_stat_name(cert_stat), certj, MD_KEY_OCSP, MD_KEY_STATUS, NULL);
            md_json_set_timeperiod(&ocsp_valid, certj, MD_KEY_OCSP, MD_KEY_VALID, NULL);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) goto leave;
        rv = APR_SUCCESS;
        if (APR_SUCCESS == job_loadj(&jobj, MD_SG_OCSP, md->name, reg, with_logs, p)) {
            md_json_setj(jobj, certj, MD_KEY_OCSP, MD_KEY_RENEWAL, NULL);
        }
    }
leave:
    *pjson = (APR_SUCCESS == rv)? certj : NULL;
    return rv;
}

static int get_cert_count(const md_t *md, int from_staging)
{
    if (!from_staging && md->cert_files && md->cert_files->nelts) {
        return md->cert_files->nelts;
    }
    return md_pkeys_spec_count(md->pks);
}

static const char *get_cert_name(const md_t *md, int i, int from_staging, apr_pool_t *p)
{
    if (!from_staging && md->cert_files && md->cert_files->nelts) {
        /* static files configured, not from staging, used index names */
        return apr_psprintf(p, "%d", i);
    }
    return md_pkey_spec_name(md_pkeys_spec_get(md->pks, i));
}

static apr_status_t status_get_certs_json(md_json_t **pjson, apr_array_header_t *certs,
                                          int from_staging,
                                          const md_t *md, md_reg_t *reg,  
                                          md_ocsp_reg_t *ocsp, int with_logs,
                                          apr_pool_t *p)
{
    md_json_t *json, *certj;
    md_timeperiod_t certs_valid = {0, 0}, valid;
    md_cert_t *cert;
    int i;
    apr_status_t rv = APR_SUCCESS;   
    
    json = md_json_create(p);
    for (i = 0; i < get_cert_count(md, from_staging); ++i) {
        cert = APR_ARRAY_IDX(certs, i, md_cert_t*);
        if (!cert) continue;

        rv = status_get_cert_json_ex(&certj, cert, md, reg, ocsp, with_logs, p);
        if (APR_SUCCESS != rv) goto leave;
        valid = md_cert_get_valid(cert);
        certs_valid = i? md_timeperiod_common(&certs_valid, &valid) : valid;
        md_json_setj(certj, json, get_cert_name(md, i, from_staging, p), NULL);
    }
    
    if (certs_valid.start) {
        md_json_set_timeperiod(&certs_valid, json, MD_KEY_VALID, NULL);
    }
leave:
    *pjson = (APR_SUCCESS == rv)? json : NULL;
    return rv;
}

static apr_status_t get_staging_certs_json(md_json_t **pjson, const md_t *md, 
                                           md_reg_t *reg, apr_pool_t *p)
{ 
    md_pkey_spec_t *spec;
    int i;
    apr_array_header_t *chain, *certs;
    const md_cert_t *cert;
    apr_status_t rv;
    
    certs = apr_array_make(p, 5, sizeof(md_cert_t*));
    for (i = 0; i < get_cert_count(md, 1); ++i) {
        spec = md_pkeys_spec_get(md->pks, i);
        cert = NULL;
        rv = md_pubcert_load(md_reg_store_get(reg), MD_SG_STAGING, md->name, spec, &chain, p);
        if (APR_SUCCESS == rv) {
            cert = APR_ARRAY_IDX(chain, 0, const md_cert_t*);
        }
        APR_ARRAY_PUSH(certs, const md_cert_t*) = cert;
    }
    return status_get_certs_json(pjson, certs, 1, md, reg, NULL, 0, p);
}

static apr_status_t status_get_md_json(md_json_t **pjson, const md_t *md, 
                                       md_reg_t *reg, md_ocsp_reg_t *ocsp, 
                                       int with_logs, apr_pool_t *p)
{
    md_json_t *mdj, *certsj, *jobj;
    int renew;
    const md_pubcert_t *pubcert;
    const md_cert_t *cert = NULL;
    apr_array_header_t *certs;
    apr_status_t rv = APR_SUCCESS;
    apr_time_t renew_at;
    int i;

    mdj = md_to_public_json(md, p);
    certs = apr_array_make(p, 5, sizeof(md_cert_t*));
    for (i = 0; i < get_cert_count(md, 0); ++i) {
        cert = NULL;
        if (APR_SUCCESS == md_reg_get_pubcert(&pubcert, reg, md, i, p)) {
            cert = APR_ARRAY_IDX(pubcert->certs, 0, const md_cert_t*);
        }
        APR_ARRAY_PUSH(certs, const md_cert_t*) = cert;
    }
    
    rv = status_get_certs_json(&certsj, certs, 0, md, reg, ocsp, with_logs, p);
    if (APR_SUCCESS != rv) goto leave;
    md_json_setj(certsj, mdj, MD_KEY_CERT, NULL);
    
    renew_at = md_reg_renew_at(reg, md, p);
    if (renew_at > 0) {
        md_json_set_time(renew_at, mdj, MD_KEY_RENEW_AT, NULL);
    }
    
    md_json_setb(md->stapling, mdj, MD_KEY_STAPLING, NULL);
    md_json_setb(md->watched, mdj, MD_KEY_WATCHED, NULL);
    renew = md_reg_should_renew(reg, md, p);
    if (renew) {
        md_json_setb(renew, mdj, MD_KEY_RENEW, NULL);
        rv = job_loadj(&jobj, MD_SG_STAGING, md->name, reg, with_logs, p);
        if (APR_SUCCESS == rv) {
            if (APR_SUCCESS == get_staging_certs_json(&certsj, md, reg, p)) {
                md_json_setj(certsj, jobj, MD_KEY_CERT, NULL);
            }
            md_json_setj(jobj, mdj, MD_KEY_RENEWAL, NULL);
        }
        else if (APR_STATUS_IS_ENOENT(rv)) rv = APR_SUCCESS;
        else goto leave;
    }
    
leave:
    if (APR_SUCCESS != rv) {
        md_json_setl(rv, mdj, MD_KEY_ERROR, NULL);
    }
    *pjson = mdj;
    return rv;
}

apr_status_t md_status_get_md_json(md_json_t **pjson, const md_t *md, 
                                   md_reg_t *reg, md_ocsp_reg_t *ocsp, apr_pool_t *p)
{
    return status_get_md_json(pjson, md, reg, ocsp, 1, p);
}

apr_status_t md_status_get_json(md_json_t **pjson, apr_array_header_t *mds, 
                                md_reg_t *reg, md_ocsp_reg_t *ocsp, apr_pool_t *p) 
{
    md_json_t *json, *mdj;
    const md_t *md;
    int i;
    
    json = md_json_create(p);
    md_json_sets(MOD_MD_VERSION, json, MD_KEY_VERSION, NULL);
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, const md_t *);
        status_get_md_json(&mdj, md, reg, ocsp, 0, p);
        md_json_addj(mdj, json, MD_KEY_MDS, NULL);
    }
    *pjson = json;
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* drive job persistence */

md_job_t *md_job_make(apr_pool_t *p, md_store_t *store,
                      md_store_group_t group, const char *name,
                      apr_time_t min_delay)
{
    md_job_t *job = apr_pcalloc(p, sizeof(*job));
    job->group = group;
    job->mdomain = apr_pstrdup(p, name);
    job->store = store;
    job->p = p;
    job->max_log = 128;
    job->min_delay = min_delay;
    return job;
}

void md_job_set_group(md_job_t *job, md_store_group_t group)
{
    job->group = group;
}

static void md_job_from_json(md_job_t *job, md_json_t *json, apr_pool_t *p)
{
    const char *s;
    
    /* not good, this is malloced from a temp pool */
    /*job->mdomain = md_json_gets(json, MD_KEY_NAME, NULL);*/
    job->finished = md_json_getb(json, MD_KEY_FINISHED, NULL);
    job->notified = md_json_getb(json, MD_KEY_NOTIFIED, NULL);
    job->notified_renewed = md_json_getb(json, MD_KEY_NOTIFIED_RENEWED, NULL);
    s = md_json_dups(p, json, MD_KEY_NEXT_RUN, NULL);
    if (s && *s) job->next_run = apr_date_parse_rfc(s);
    s = md_json_dups(p, json, MD_KEY_LAST_RUN, NULL);
    if (s && *s) job->last_run = apr_date_parse_rfc(s);
    s = md_json_dups(p, json, MD_KEY_VALID_FROM, NULL);
    if (s && *s) job->valid_from = apr_date_parse_rfc(s);
    job->error_runs = (int)md_json_getl(json, MD_KEY_ERRORS, NULL);
    if (md_json_has_key(json, MD_KEY_LAST, NULL)) {
        job->last_result = md_result_from_json(md_json_getcj(json, MD_KEY_LAST, NULL), p);
    }
    job->log = md_json_getj(json, MD_KEY_LOG, NULL);
}

static void job_to_json(md_json_t *json, const md_job_t *job, 
                        md_result_t *result, apr_pool_t *p)
{
    char ts[APR_RFC822_DATE_LEN];

    md_json_sets(job->mdomain, json, MD_KEY_NAME, NULL);
    md_json_setb(job->finished, json, MD_KEY_FINISHED, NULL);
    md_json_setb(job->notified, json, MD_KEY_NOTIFIED, NULL);
    md_json_setb(job->notified_renewed, json, MD_KEY_NOTIFIED_RENEWED, NULL);
    if (job->next_run > 0) {
        apr_rfc822_date(ts, job->next_run);
        md_json_sets(ts, json, MD_KEY_NEXT_RUN, NULL);
    }
    if (job->last_run > 0) {
        apr_rfc822_date(ts, job->last_run);
        md_json_sets(ts, json, MD_KEY_LAST_RUN, NULL);
    }
    if (job->valid_from > 0) {
        apr_rfc822_date(ts, job->valid_from);
        md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
    }
    md_json_setl(job->error_runs, json, MD_KEY_ERRORS, NULL);
    if (!result) result = job->last_result;
    if (result) {
        md_json_setj(md_result_to_json(result, p), json, MD_KEY_LAST, NULL);
    }
    if (job->log) md_json_setj(job->log, json, MD_KEY_LOG, NULL);
}

apr_status_t md_job_load(md_job_t *job)
{
    md_json_t *jprops;
    apr_status_t rv;
    
    rv = md_store_load_json(job->store, job->group, job->mdomain, MD_FN_JOB, &jprops, job->p);
    if (APR_SUCCESS == rv) {
        md_job_from_json(job, jprops, job->p);
    }
    return rv;
}

apr_status_t md_job_save(md_job_t *job, md_result_t *result, apr_pool_t *p)
{
    md_json_t *jprops;
    apr_status_t rv;
    
    jprops = md_json_create(p);
    job_to_json(jprops, job, result, p);
    rv = md_store_save_json(job->store, p, job->group, job->mdomain, MD_FN_JOB, jprops, 0);
    if (APR_SUCCESS == rv) job->dirty = 0;
    return rv;
}

void md_job_log_append(md_job_t *job, const char *type, 
                       const char *status, const char *detail)
{
    md_json_t *entry;
    char ts[APR_RFC822_DATE_LEN];
    
    entry = md_json_create(job->p);
    apr_rfc822_date(ts, apr_time_now());
    md_json_sets(ts, entry, MD_KEY_WHEN, NULL);
    md_json_sets(type, entry, MD_KEY_TYPE, NULL);
    if (status) md_json_sets(status, entry, MD_KEY_STATUS, NULL);
    if (detail) md_json_sets(detail, entry, MD_KEY_DETAIL, NULL);
    if (!job->log) job->log = md_json_create(job->p);
    md_json_insertj(entry, 0, job->log, MD_KEY_ENTRIES, NULL);
    md_json_limita(job->max_log, job->log, MD_KEY_ENTRIES, NULL);
    job->dirty = 1;
}

typedef struct {
    md_job_t *job;
    const char *type;
    md_json_t *entry;
    size_t index;
} log_find_ctx;

static int find_first_log_entry(void *baton, size_t index, md_json_t *entry)
{
    log_find_ctx *ctx = baton;
    const char *etype;
    
    etype = md_json_gets(entry, MD_KEY_TYPE, NULL);
    if (etype == ctx->type || (etype && ctx->type && !strcmp(etype, ctx->type))) {
        ctx->entry = entry;
        ctx->index = index;
        return 0;
    }
    return 1;
}

md_json_t *md_job_log_get_latest(md_job_t *job, const char *type)

{
    log_find_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.job = job;
    ctx.type = type;
    if (job->log) md_json_itera(find_first_log_entry, &ctx, job->log, MD_KEY_ENTRIES, NULL);
    return ctx.entry;
}

apr_time_t md_job_log_get_time_of_latest(md_job_t *job, const char *type)
{
    md_json_t *entry;
    const char *s;
    
    entry = md_job_log_get_latest(job, type);
    if (entry) {
        s = md_json_gets(entry, MD_KEY_WHEN, NULL);
        if (s) return apr_date_parse_rfc(s);
    }
    return 0;
}

void  md_status_take_stock(md_json_t **pjson, apr_array_header_t *mds, 
                           md_reg_t *reg, apr_pool_t *p)
{
    const md_t *md;
    md_job_t *job;
    int i, complete, renewing, errored, ready, total;
    md_json_t *json;

    json = md_json_create(p);
    complete = renewing = errored = ready = total = 0;
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, const md_t *);
        ++total;
        switch (md->state) {
            case MD_S_COMPLETE: ++complete; /* fall through */
            case MD_S_INCOMPLETE:
                if (md_reg_should_renew(reg, md, p)) {
                    ++renewing;
                    job = md_reg_job_make(reg, md->name, p);
                    if (APR_SUCCESS == md_job_load(job)) {
                        if (job->error_runs > 0 
                            || (job->last_result && job->last_result->status != APR_SUCCESS)) {
                            ++errored;
                        }
                        else if (job->finished) {
                            ++ready;
                        }
                    }
                }
                break;
            default: ++errored; break;
        }
    }
    md_json_setl(total, json, MD_KEY_TOTAL, NULL);
    md_json_setl(complete, json, MD_KEY_COMPLETE, NULL);
    md_json_setl(renewing, json, MD_KEY_RENEWING, NULL);
    md_json_setl(errored, json, MD_KEY_ERRORED, NULL);
    md_json_setl(ready, json, MD_KEY_READY, NULL);
    *pjson = json;
}

typedef struct {
    apr_pool_t *p;
    md_job_t *job;
    md_store_t *store;
    md_result_t *last;
    apr_time_t last_save;
} md_job_result_ctx;

static void job_result_update(md_result_t *result, void *data)
{
    md_job_result_ctx *ctx = data;
    apr_time_t now;
    const char *msg, *sep;
    
    if (md_result_cmp(ctx->last, result)) {
        now = apr_time_now();
        md_result_assign(ctx->last, result);
        if (result->activity || result->problem || result->detail) {
            msg = sep = "";
            if (result->activity) {
                msg = apr_psprintf(result->p, "%s", result->activity);
                sep = ": ";
            }
            if (result->detail) {
                msg = apr_psprintf(result->p, "%s%s%s", msg, sep, result->detail);
                sep = ", ";
            }
            if (result->problem) {
                msg = apr_psprintf(result->p, "%s%sproblem: %s", msg, sep, result->problem);
                sep = " ";
            }
            md_job_log_append(ctx->job, "progress", NULL, msg);

            if (ctx->store && apr_time_as_msec(now - ctx->last_save) > 500) {
                md_job_save(ctx->job, result, ctx->p);
                ctx->last_save = now;
            }
        }
    }
}

static apr_status_t job_result_raise(md_result_t *result, void *data, const char *event, apr_pool_t *p)
{
    md_job_result_ctx *ctx = data;
    (void)p;
    if (result == ctx->job->observing) {
        return md_job_notify(ctx->job, event, result);
    }
    return APR_SUCCESS;
}

static void job_result_holler(md_result_t *result, void *data, const char *event, apr_pool_t *p)
{
    md_job_result_ctx *ctx = data;
    if (result == ctx->job->observing) {
        md_event_holler(event, ctx->job->mdomain, ctx->job, result, p);
    }
}

static void job_observation_start(md_job_t *job, md_result_t *result, md_store_t *store)
{
    md_job_result_ctx *ctx;

    if (job->observing) md_result_on_change(job->observing, NULL, NULL);
    job->observing = result;
    
    ctx = apr_pcalloc(result->p, sizeof(*ctx));
    ctx->p = result->p;
    ctx->job = job;
    ctx->store = store;
    ctx->last = md_result_md_make(result->p, APR_SUCCESS);
    md_result_assign(ctx->last, result);
    md_result_on_change(result, job_result_update, ctx);
    md_result_on_raise(result, job_result_raise, ctx);
    md_result_on_holler(result, job_result_holler, ctx);
}

static void job_observation_end(md_job_t *job)
{
    if (job->observing) md_result_on_change(job->observing, NULL, NULL);
    job->observing = NULL; 
} 

void md_job_start_run(md_job_t *job, md_result_t *result, md_store_t *store)
{
    job->fatal_error = 0;
    job->last_run = apr_time_now();
    job_observation_start(job, result, store);
    md_job_log_append(job, "starting", NULL, NULL);
}

apr_time_t md_job_delay_on_errors(md_job_t *job, int err_count, const char *last_problem)
{
    apr_time_t delay = 0, max_delay = apr_time_from_sec(24*60*60); /* daily */
    unsigned char c;

    if (last_problem && md_acme_problem_is_input_related(last_problem)) {
        /* If ACME server reported a problem and that problem indicates that our
         * input values, e.g. our configuration, has something wrong, we always
         * go to max delay as frequent retries are unlikely to resolve the situation.
         * However, we should nevertheless retry daily, bc. it might be that there
         * is a bug in the server. Unlikely, but... */
        delay = max_delay;
    }
    else if (err_count > 0) {
        /* back off duration, depending on the errors we encounter in a row */
        delay = job->min_delay << (err_count - 1);
        if (delay > max_delay) {
            delay = max_delay;
        }
    }
    if (delay > 0) {
        /* jitter the delay by +/- 0-50%.
         * Background: we see retries of jobs being too regular (e.g. all at midnight),
         * possibly cumulating from many installations that restart their Apache at a
         * fixed hour. This can contribute to an overload at the CA and a continuation
         * of failure.
         */
        md_rand_bytes(&c, sizeof(c), job->p);
        delay += apr_time_from_sec((apr_time_sec(delay) * (c - 128)) / 256);
    }
    return delay;
}

void md_job_end_run(md_job_t *job, md_result_t *result)
{
    if (APR_SUCCESS == result->status) {
        job->finished = 1;
        job->valid_from = result->ready_at;
        job->error_runs = 0;
        job->dirty = 1;
        md_job_log_append(job, "finished", NULL, NULL);
    }
    else {
        ++job->error_runs;
        job->dirty = 1;
        job->next_run = apr_time_now() + md_job_delay_on_errors(job, job->error_runs, result->problem);
    }
    job_observation_end(job);
}

void md_job_retry_at(md_job_t *job, apr_time_t later)
{
    job->next_run = later;
    job->dirty = 1;
}

apr_status_t md_job_notify(md_job_t *job, const char *reason, md_result_t *result)
{
    apr_status_t rv;
    
    md_result_set(result, APR_SUCCESS, NULL);
    rv = md_event_raise(reason, job->mdomain, job, result, job->p);
    job->dirty = 1;
    if (APR_SUCCESS == rv && APR_SUCCESS == result->status) {
        job->notified = 1;
        if (!strcmp("renewed", reason)) {
            job->notified_renewed = 1;
        }
    }
    else {
        ++job->error_runs;
        job->next_run = apr_time_now() + md_job_delay_on_errors(job, job->error_runs, result->problem);
    }
    return result->status;
}

