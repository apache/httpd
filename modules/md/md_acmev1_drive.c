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
#include <apr_buckets.h>
#include <apr_hash.h>
#include <apr_uri.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_http.h"
#include "md_log.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"
#include "md_acme_order.h"

#include "md_acme_drive.h"
#include "md_acmev1_drive.h"

/**************************************************************************************************/
/* authz/challenge setup */

/**
 * Pre-Req: we have an account for the ACME server that has accepted the current license agreement
 * For each domain in MD: 
 * - check if there already is a valid AUTHZ resource
 * - if ot, create an AUTHZ resource with challenge data 
 */
static apr_status_t ad_setup_order(md_proto_driver_t *d, md_result_t *result)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    md_t *md = ad->md;
    const char *url;
    md_acme_authz_t *authz;
    apr_array_header_t *domains_covered;
    int i;
    int changed = 0;
    
    assert(ad->md);
    assert(ad->acme);

    md_result_activity_printf(result, "Setup order resource for %s", ad->md->name);
    
    /* For each domain in MD: AUTHZ setup
     * if an AUTHZ resource is known, check if it is still valid
     * if known AUTHZ resource is not valid, remove, goto 4.1.1
     * if no AUTHZ available, create a new one for the domain, store it
     */
    rv = md_acme_order_load(d->store, MD_SG_STAGING, md->name, &ad->order, d->p);
    if (!ad->order || APR_STATUS_IS_ENOENT(rv)) {
        ad->order = md_acme_order_create(d->p);
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading authz data", md->name);
        md_acme_order_purge(d->store, d->p, MD_SG_STAGING, md->name, d->env);
        return APR_EAGAIN;
    }
    
    /* Retrieve all known authz from ACME server and check status etc. */
    domains_covered = apr_array_make(d->p, 5, sizeof(const char *));
    
    for (i = 0; i < ad->order->authz_urls->nelts;) {
        url = APR_ARRAY_IDX(ad->order->authz_urls, i, const char*);
        rv = md_acme_authz_retrieve(ad->acme, d->p, url, &authz);
        if (APR_SUCCESS == rv) {
            if (md_array_str_index(ad->domains, authz->domain, 0, 0) < 0) {
                md_acme_order_remove(ad->order, url);
                changed = 1;
                continue;
            }
        
            APR_ARRAY_PUSH(domains_covered, const char *) = authz->domain;
            ++i;
        }
        else if (APR_STATUS_IS_ENOENT(rv)) {
            md_acme_order_remove(ad->order, url);
            changed = 1;
            continue;
        }
        else {
            goto leave;
        }
    }
    
    /* Do we have authz urls for all domains? If not, register a new one */
    for (i = 0; i < ad->domains->nelts && APR_SUCCESS == rv; ++i) {
        const char *domain = APR_ARRAY_IDX(ad->domains, i, const char *);
    
        if (md_array_str_index(domains_covered, domain, 0, 0) < 0) {
            md_result_activity_printf(result, "Creating authz resource for %s", domain);
            rv = md_acme_authz_register(&authz, ad->acme, domain, d->p);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: created authz for %s (last problem: %s)", 
                          md->name, domain, ad->acme->last->problem);
            if (APR_SUCCESS != rv) goto leave;
            rv = md_acme_order_add(ad->order, authz->url);
            changed = 1;
        }
    }
    
    if (changed) {
        rv = md_acme_order_save(d->store, d->p, MD_SG_STAGING, md->name, ad->order, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, "%s: saved", md->name);
    }
    
leave:
    md_acme_report_result(ad->acme, rv, result);
    return rv;
}

apr_status_t md_acmev1_drive_renew(md_acme_driver_t *ad, md_proto_driver_t *d, md_result_t *result)
{
    apr_status_t rv = APR_SUCCESS;
    const char *required;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: (ACMEv1) need certificate", d->md->name);
    
    /* Chose (or create) and ACME account to use */
    if (APR_SUCCESS != (rv = md_acme_drive_set_acct(d, result))) goto leave;
    
    /* Check that the account agreed to the terms-of-service, otherwise
     * requests for new authorizations are denied. ToS may change during the
     * lifetime of an account */
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                  "%s: (ACMEv1) check Tems-of-Service agreement", d->md->name);
    
    rv = md_acme_check_agreement(ad->acme, d->p, ad->md->ca_agreement, &required);
    if (APR_STATUS_IS_INCOMPLETE(rv) && required) {
        /* The CA wants the user to agree to Terms-of-Services. Until the user
         * has reconfigured and restarted the server, this MD cannot be
         * driven further */
        ad->md->state = MD_S_MISSING_INFORMATION;
        md_save(d->store, d->p, MD_SG_STAGING, ad->md, 0);
        md_result_printf(result, rv, 
            "the CA requires you to accept the terms-of-service as specified in <%s>. "
            "Please read the document that you find at that URL and, if you agree to "
            "the conditions, configure \"MDCertificateAgreement accepted\" "
            "in your Apache. Then (graceful) restart the server to activate.", 
            required);
        goto leave;
    }
    else if (APR_SUCCESS != rv) goto leave;
    
    if (!md_array_is_empty(ad->certs)) goto leave;
    
    rv = ad_setup_order(d, result);
    if (APR_SUCCESS != rv) goto leave;
    
    rv = md_acme_order_start_challenges(ad->order, ad->acme, ad->ca_challenges,
                                        d->store, d->md, d->env, result, d->p);
    if (APR_SUCCESS != rv) goto leave;
    
    rv = md_acme_order_monitor_authzs(ad->order, ad->acme, d->md,
                                      ad->authz_monitor_timeout, result, d->p);
    if (APR_SUCCESS != rv) goto leave;
    
    rv = md_acme_drive_setup_certificate(d, result);

leave:    
    md_result_log(result, MD_LOG_DEBUG);
    return result->status;
}

