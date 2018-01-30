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
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"

typedef struct {
    md_proto_driver_t *driver;
    
    const char *phase;
    int complete;

    md_pkey_t *privkey;              /* the new private key */
    apr_array_header_t *pubcert;     /* the new certificate + chain certs */
    
    md_cert_t *cert;                 /* the new certificate */
    apr_array_header_t *chain;       /* the chain certificates */
    const char *next_up_link;        /* where the next chain cert is */
    
    md_acme_t *acme;
    md_t *md;
    const md_creds_t *ncreds;
    
    apr_array_header_t *ca_challenges;
    md_acme_authz_set_t *authz_set;
    apr_interval_time_t authz_monitor_timeout;
    
    const char *csr_der_64;
    apr_interval_time_t cert_poll_timeout;
    
} md_acme_driver_t;

/**************************************************************************************************/
/* account setup */

static apr_status_t ad_set_acct(md_proto_driver_t *d) 
{
    md_acme_driver_t *ad = d->baton;
    md_t *md = ad->md;
    apr_status_t rv = APR_SUCCESS;
    int update = 0, acct_installed = 0;
    
    ad->phase = "setup acme";
    if (!ad->acme 
        && APR_SUCCESS != (rv = md_acme_create(&ad->acme, d->p, md->ca_url, d->proxy_url))) {
        goto out;
    }

    ad->phase = "choose account";
    /* Do we have a staged (modified) account? */
    if (APR_SUCCESS == (rv = md_acme_use_acct_staged(ad->acme, d->store, md, d->p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "re-using staged account");
        md->ca_account = MD_ACME_ACCT_STAGED;
        acct_installed = 1;
    }
    else if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }
    
    /* Get an account for the ACME server for this MD */
    if (md->ca_account && !acct_installed) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "re-use account '%s'", md->ca_account);
        rv = md_acme_use_acct(ad->acme, d->store, d->p, md->ca_account);
        if (APR_STATUS_IS_ENOENT(rv) || APR_STATUS_IS_EINVAL(rv)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "rejected %s", md->ca_account);
            md->ca_account = NULL;
            update = 1;
            rv = APR_SUCCESS;
        }
    }

    if (APR_SUCCESS == rv && !md->ca_account) {
        /* Find a local account for server, store at MD */ 
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: looking at existing accounts",
                      d->proto->protocol);
        if (APR_SUCCESS == md_acme_find_acct(ad->acme, d->store, d->p)) {
            md->ca_account = md_acme_get_acct_id(ad->acme);
            update = 1;
        }
    }
    
    if (APR_SUCCESS == rv && !md->ca_account) {
        /* 2.2 No local account exists, create a new one */
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: creating new account", 
                      d->proto->protocol);
        
        if (!ad->md->contacts || apr_is_empty_array(md->contacts)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, d->p, 
                          "no contact information for md %s", md->name);            
            rv = APR_EINVAL;
            goto out;
        }
    
        if (APR_SUCCESS == (rv = md_acme_create_acct(ad->acme, d->p, md->contacts, 
                                                     md->ca_agreement))
            && APR_SUCCESS == (rv = md_acme_acct_save_staged(ad->acme, d->store, md, d->p))) {
            md->ca_account = MD_ACME_ACCT_STAGED;
            update = 1;
        }
    }
    
out:
    if (APR_SUCCESS == rv) {
        const char *agreement = md_acme_get_agreement(ad->acme);
        /* Persist the account chosen at the md so we use the same on future runs */
        if (agreement && !md->ca_agreement) { 
            md->ca_agreement = agreement;
            update = 1;
        }
        if (update) {
            rv = md_save(d->store, d->p, MD_SG_STAGING, ad->md, 0);
        }
    }
    return rv;
}

/**************************************************************************************************/
/* authz/challenge setup */

/**
 * Pre-Req: we have an account for the ACME server that has accepted the current license agreement
 * For each domain in MD: 
 * - check if there already is a valid AUTHZ resource
 * - if ot, create an AUTHZ resource with challenge data 
 */
static apr_status_t ad_setup_authz(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    md_t *md = ad->md;
    md_acme_authz_t *authz;
    int i, changed;
    
    assert(ad->md);
    assert(ad->acme);

    ad->phase = "check authz";
    
    /* For each domain in MD: AUTHZ setup
     * if an AUTHZ resource is known, check if it is still valid
     * if known AUTHZ resource is not valid, remove, goto 4.1.1
     * if no AUTHZ available, create a new one for the domain, store it
     */
    rv = md_acme_authz_set_load(d->store, MD_SG_STAGING, md->name, &ad->authz_set, d->p);
    if (!ad->authz_set || APR_STATUS_IS_ENOENT(rv)) {
        ad->authz_set = md_acme_authz_set_create(d->p);
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: loading authz data", md->name);
        md_acme_authz_set_purge(d->store, MD_SG_STAGING, d->p, md->name);
        return APR_EAGAIN;
    }
    
    /* Remove anything we no longer need */
    for (i = 0; i < ad->authz_set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        if (!md_contains(md, authz->domain, 0)) {
            md_acme_authz_set_remove(ad->authz_set, authz->domain);
            changed = 1;
        }
    }
    
    /* Add anything we do not already have */
    for (i = 0; i < md->domains->nelts && APR_SUCCESS == rv; ++i) {
        const char *domain = APR_ARRAY_IDX(md->domains, i, const char *);
        changed = 0;
        authz = md_acme_authz_set_get(ad->authz_set, domain);
        if (authz) {
            /* check valid */
            rv = md_acme_authz_update(authz, ad->acme, d->store, d->p);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: updated authz for %s", 
                          md->name, domain);
            if (APR_SUCCESS != rv) {
                md_acme_authz_set_remove(ad->authz_set, domain);
                authz = NULL;
                changed = 1;
            }
        }
        if (!authz) {
            /* create new one */
            rv = md_acme_authz_register(&authz, ad->acme, d->store, domain, d->p);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: created authz for %s", 
                          md->name, domain);
            if (APR_SUCCESS == rv) {
                rv = md_acme_authz_set_add(ad->authz_set, authz);
                changed = 1;
            }
        }
    }
    
    /* Save any changes */
    if (APR_SUCCESS == rv && changed) {
        rv = md_acme_authz_set_save(d->store, d->p, MD_SG_STAGING, md->name, ad->authz_set, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, "%s: saved", md->name);
    }
    
    return rv;
}

/**
 * Pre-Req: all domains have a AUTHZ resources at the ACME server
 * For each domain in MD: 
 * - if AUTHZ resource is 'valid' -> continue
 * - if AUTHZ resource is 'pending':
 *   - find preferred challenge choice
 *   - calculate challenge data for httpd to find
 *   - POST challenge start to ACME server
 * For each domain in MD where AUTHZ is 'pending', until overall timeout: 
 *   - wait a certain time, check status again
 * If not all AUTHZ are valid, fail
 */
static apr_status_t ad_start_challenges(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv = APR_SUCCESS;
    md_acme_authz_t *authz;
    int i, changed = 0;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->authz_set);

    ad->phase = "start challenges";

    for (i = 0; i < ad->authz_set->authzs->nelts && APR_SUCCESS == rv; ++i) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: check AUTHZ for %s", 
                      ad->md->name, authz->domain);
        if (APR_SUCCESS != (rv = md_acme_authz_update(authz, ad->acme, d->store, d->p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: check authz for %s",
                          ad->md->name, authz->domain);
            break;
        }

        switch (authz->state) {
            case MD_ACME_AUTHZ_S_VALID:
                break;
                
            case MD_ACME_AUTHZ_S_PENDING:
                rv = md_acme_authz_respond(authz, ad->acme, d->store, ad->ca_challenges, 
                                           d->md->pkey_spec, d->p);
                changed = 1;
                break;
                
            default:
                rv = APR_EINVAL;
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                              "%s: unexpected AUTHZ state %d at %s", 
                              authz->domain, authz->state, authz->location);
                break;
        }
    }
    
    if (APR_SUCCESS == rv && changed) {
        rv = md_acme_authz_set_save(d->store, d->p, MD_SG_STAGING, ad->md->name, ad->authz_set, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, "%s: saved", ad->md->name);
    }
    return rv;
}

static apr_status_t check_challenges(void *baton, int attempt)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    md_acme_authz_t *authz;
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ad->authz_set->authzs->nelts && APR_SUCCESS == rv; ++i) {
        authz = APR_ARRAY_IDX(ad->authz_set->authzs, i, md_acme_authz_t*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: check AUTHZ for %s(%d. attempt)", 
                      ad->md->name, authz->domain, attempt);
        if (APR_SUCCESS == (rv = md_acme_authz_update(authz, ad->acme, d->store, d->p))) {
            switch (authz->state) {
                case MD_ACME_AUTHZ_S_VALID:
                    break;
                case MD_ACME_AUTHZ_S_PENDING:
                    rv = APR_EAGAIN;
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
                                  "%s: status pending at %s", authz->domain, authz->location);
                    break;
                default:
                    rv = APR_EINVAL;
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                                  "%s: unexpected AUTHZ state %d at %s", 
                                  authz->domain, authz->state, authz->location);
                    break;
            }
        }
    }
    return rv;
}

static apr_status_t ad_monitor_challenges(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->authz_set);

    ad->phase = "monitor challenges";
    rv = md_util_try(check_challenges, d, 0, ad->authz_monitor_timeout, 0, 0, 1);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, d->p, 
                  "%s: checked all domain authorizations", ad->md->name);
    return rv;
}

/**************************************************************************************************/
/* poll cert */

static void get_up_link(md_proto_driver_t *d, apr_table_t *headers)
{
    md_acme_driver_t *ad = d->baton;

    ad->next_up_link = md_link_find_relation(headers, d->p, "up");
    if (ad->next_up_link) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, 
                      "server reports up link as %s", ad->next_up_link);
    }
} 

static apr_status_t read_http_cert(md_cert_t **pcert, apr_pool_t *p,
                                   const md_http_response_t *res)
{
    apr_status_t rv = APR_SUCCESS;
    
    if (APR_SUCCESS != (rv = md_cert_read_http(pcert, p, res))
        && APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_EAGAIN;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                      "cert not in response from %s", res->req->url);
    }
    return rv;
}

static apr_status_t on_got_cert(md_acme_t *acme, const md_http_response_t *res, void *baton)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv = APR_SUCCESS;
    
    (void)acme;
    if (APR_SUCCESS == (rv = read_http_cert(&ad->cert, d->p, res))) {
        rv = md_store_save(d->store, d->p, MD_SG_STAGING, ad->md->name, MD_FN_CERT, 
                           MD_SV_CERT, ad->cert, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "cert parsed and saved");
        if (APR_SUCCESS == rv) {
            get_up_link(d, res->headers);
        }
    }
    return rv;
}

static apr_status_t get_cert(void *baton, int attempt)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    
    (void)attempt;
    return md_acme_GET(ad->acme, ad->md->cert_url, NULL, NULL, on_got_cert, d);
}

static apr_status_t ad_cert_poll(md_proto_driver_t *d, int only_once)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    
    assert(ad->md);
    assert(ad->acme);
    assert(ad->md->cert_url);
    
    ad->phase = "poll certificate";
    if (only_once) {
        rv = get_cert(d, 0);
    }
    else {
        rv = md_util_try(get_cert, d, 1, ad->cert_poll_timeout, 0, 0, 1);
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "poll for cert at %s", ad->md->cert_url);
    return rv;
}

/**************************************************************************************************/
/* cert setup */

static apr_status_t on_init_csr_req(md_acme_req_t *req, void *baton)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("new-cert", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_sets(ad->csr_der_64, jpayload, MD_KEY_CSR, NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t csr_req(md_acme_t *acme, const md_http_response_t *res, void *baton)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv = APR_SUCCESS;
    
    (void)acme;
    ad->md->cert_url = apr_table_get(res->headers, "location");
    if (!ad->md->cert_url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, d->p, 
                      "cert created without giving its location header");
        return APR_EINVAL;
    }
    if (APR_SUCCESS != (rv = md_save(d->store, d->p, MD_SG_STAGING, ad->md, 0))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, d->p, 
                      "%s: saving cert url %s", ad->md->name, ad->md->cert_url);
        return rv;
    }
    
    /* Check if it already was sent with this response */
    ad->next_up_link = NULL;
    if (APR_SUCCESS == (rv = md_cert_read_http(&ad->cert, d->p, res))) {
        rv = md_cert_save(d->store, d->p, MD_SG_STAGING, ad->md->name, ad->cert, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "cert parsed and saved");
        if (APR_SUCCESS == rv) {
            get_up_link(d, res->headers);
        }
    }
    else if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
                      "cert not in response, need to poll %s", ad->md->cert_url);
    }
    
    return rv;
}

/**
 * Pre-Req: all domains have been validated by the ACME server, e.g. all have AUTHZ
 * resources that have status 'valid'
 * - Setup private key, if not already there
 * - Generate a CSR with org, contact, etc
 * - Optionally enable must-staple OCSP extension
 * - Submit CSR, expect 201 with location
 * - POLL location for certificate
 * - store certificate
 * - retrieve cert chain information from cert
 * - GET cert chain
 * - store cert chain
 */
static apr_status_t ad_setup_certificate(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    md_pkey_t *privkey;
    apr_status_t rv;

    ad->phase = "setup cert privkey";
    
    rv = md_pkey_load(d->store, MD_SG_STAGING, ad->md->name, &privkey, d->p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        if (APR_SUCCESS == (rv = md_pkey_gen(&privkey, d->p, d->md->pkey_spec))) {
            rv = md_pkey_save(d->store, d->p, MD_SG_STAGING, ad->md->name, privkey, 1);
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: generate privkey", ad->md->name);
    }

    if (APR_SUCCESS == rv) {
        ad->phase = "setup csr";
        rv = md_cert_req_create(&ad->csr_der_64, ad->md, privkey, d->p);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: create CSR", ad->md->name);
    }

    if (APR_SUCCESS == rv) {
        ad->phase = "submit csr";
        rv = md_acme_POST(ad->acme, ad->acme->new_cert, on_init_csr_req, NULL, csr_req, d);
    }

    if (APR_SUCCESS == rv) {
        if (!ad->cert) {
            rv = ad_cert_poll(d, 0);
        }
    }
    return rv;
}

/**************************************************************************************************/
/* cert chain retrieval */

static apr_status_t on_add_chain(md_acme_t *acme, const md_http_response_t *res, void *baton)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv = APR_SUCCESS;
    md_cert_t *cert;
    const char *ct;
    
    (void)acme;
    ct = apr_table_get(res->headers, "Content-Type");
    if (ct && !strcmp("application/x-pkcs7-mime", ct)) {
        /* root cert most likely, end it here */
        return APR_SUCCESS;
    }
    
    if (APR_SUCCESS == (rv = read_http_cert(&cert, d->p, res))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "chain cert parsed");
        APR_ARRAY_PUSH(ad->chain, md_cert_t *) = cert;
        if (APR_SUCCESS == rv) {
            get_up_link(d, res->headers);
        }
    }
    return rv;
}

static apr_status_t get_chain(void *baton, int attempt)
{
    md_proto_driver_t *d = baton;
    md_acme_driver_t *ad = d->baton;
    const char *prev_link = NULL;
    apr_status_t rv = APR_SUCCESS;

    while (APR_SUCCESS == rv && ad->chain->nelts < 10) {
        int nelts = ad->chain->nelts;
        
        if (ad->next_up_link && (!prev_link || strcmp(prev_link, ad->next_up_link))) {
            prev_link = ad->next_up_link;

            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, 
                          "next issuer is  %s", ad->next_up_link);
            rv = md_acme_GET(ad->acme, ad->next_up_link, NULL, NULL, on_add_chain, d);
            
            if (APR_SUCCESS == rv && nelts == ad->chain->nelts) {
                break;
            }
        }
        else {
            rv = APR_SUCCESS;
            break;
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, 
                  "got chain with %d certs (%d. attempt)", ad->chain->nelts, attempt);
    return rv;
}

static apr_status_t ad_chain_install(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;
    
    /* We should have that from initial cert retrieval, but if we restarted
     * or switched child process, we need to retrieve this again from the 
     * certificate resources. */
    if (!ad->next_up_link) {
        if (APR_SUCCESS != (rv = ad_cert_poll(d, 0))) {
            return rv;
        }
        if (!ad->next_up_link) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                "server reports no link header 'up' for certificate at %s", ad->md->cert_url);
            return APR_EINVAL;
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, 
                  "chain starts at %s", ad->next_up_link);
    
    ad->chain = apr_array_make(d->p, 5, sizeof(md_cert_t *));
    if (APR_SUCCESS == (rv = md_util_try(get_chain, d, 0, ad->cert_poll_timeout, 0, 0, 0))) {
        rv = md_store_save(d->store, d->p, MD_SG_STAGING, ad->md->name, MD_FN_CHAIN, 
                           MD_SV_CHAIN, ad->chain, 0);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "chain fetched and saved");
    }
    return rv;
}

/**************************************************************************************************/
/* ACME driver init */

static apr_status_t acme_driver_init(md_proto_driver_t *d)
{
    md_acme_driver_t *ad;
    apr_status_t rv = APR_SUCCESS;

    ad = apr_pcalloc(d->p, sizeof(*ad));
    
    d->baton = ad;
    ad->driver = d;
    
    ad->authz_monitor_timeout = apr_time_from_sec(30);
    ad->cert_poll_timeout = apr_time_from_sec(30);

    /* We can only support challenges if the server is reachable from the outside
     * via port 80 and/or 443. These ports might be mapped for httpd to something
     * else, but a mapping needs to exist. */
    ad->ca_challenges = apr_array_make(d->p, 3, sizeof(const char *)); 
    if (d->challenge) {
        /* we have been told to use this type */
        APR_ARRAY_PUSH(ad->ca_challenges, const char*) = apr_pstrdup(d->p, d->challenge);
    }
    else if (d->md->ca_challenges && d->md->ca_challenges->nelts > 0) {
        /* pre-configured set for this managed domain */
        apr_array_cat(ad->ca_challenges, d->md->ca_challenges);
    }
    else {
        /* free to chose. Add all we support and see what we get offered */
        APR_ARRAY_PUSH(ad->ca_challenges, const char*) = MD_AUTHZ_TYPE_HTTP01;
        APR_ARRAY_PUSH(ad->ca_challenges, const char*) = MD_AUTHZ_TYPE_TLSSNI01;
    }
    
    if (!d->can_http && !d->can_https) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, d->p, "%s: the server seems neither "
                      "reachable via http (port 80) nor https (port 443). The ACME protocol "
                      "needs at least one of those so the CA can talk to the server and verify "
                      "a domain ownership.", d->md->name);
        return APR_EGENERAL;
    }
    
    if (!d->can_http) {
        ad->ca_challenges = md_array_str_remove(d->p, ad->ca_challenges, MD_AUTHZ_TYPE_HTTP01, 0);
    }
    if (!d->can_https) {
        ad->ca_challenges = md_array_str_remove(d->p, ad->ca_challenges, MD_AUTHZ_TYPE_TLSSNI01, 0);
    }

    if (apr_is_empty_array(ad->ca_challenges)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, d->p, "%s: specific CA challenge methods "
                      "have been configured, but the server is unable to use any of those. "
                      "For 'http-01' it needs to be reachable on port 80, for 'tls-sni-01'"
                      " port 443 is needed.", d->md->name);
        return APR_EGENERAL;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, d->p, "%s: init driver", d->md->name);
    
    return rv;
}

/**************************************************************************************************/
/* ACME staging */

static apr_status_t acme_stage(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    int reset_staging = d->reset;
    apr_status_t rv = APR_SUCCESS;
    int renew = 1;

    if (md_log_is_level(d->p, MD_LOG_DEBUG)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, d->p, "%s: staging started, "
                      "state=%d, can_http=%d, can_https=%d, challenges='%s'",
                      d->md->name, d->md->state, d->can_http, d->can_https,
                      apr_array_pstrcat(d->p, ad->ca_challenges, ' '));
    }

    if (!reset_staging) {
        rv = md_load(d->store, MD_SG_STAGING, d->md->name, &ad->md, d->p);
        if (APR_SUCCESS == rv) {
            /* So, we have a copy in staging, but is it a recent or an old one? */
            if (md_is_newer(d->store, MD_SG_DOMAINS, MD_SG_STAGING, d->md->name, d->p)) {
                reset_staging = 1;
            }
        }
        else if (APR_STATUS_IS_ENOENT(rv)) {
            reset_staging = 1;
            rv = APR_SUCCESS;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, d->p, 
                      "%s: checked staging area, will%s reset",
                      d->md->name, reset_staging? "" : " not");
    }
    
    if (reset_staging) {
        /* reset the staging area for this domain */
        rv = md_store_purge(d->store, d->p, MD_SG_STAGING, d->md->name);
        if (APR_SUCCESS != rv && !APR_STATUS_IS_ENOENT(rv)) {
            return rv;
        }
        rv = APR_SUCCESS;
        ad->md = NULL;
    }
    
    if (ad->md && ad->md->state == MD_S_MISSING) {
        /* There is config information missing. It makes no sense to drive this MD further */
        rv = APR_INCOMPLETE;
        goto out;
    }
    
    if (ad->md) {
        /* staging in progress. look for new ACME account information collected there */
        rv = md_reg_creds_get(&ad->ncreds, d->reg, MD_SG_STAGING, d->md, d->p);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: checked creds", d->md->name);
        if (APR_STATUS_IS_ENOENT(rv)) {
            rv = APR_SUCCESS;
        }
    }
    
    /* Find out where we're at with this managed domain */
    if (ad->ncreds && ad->ncreds->privkey && ad->ncreds->pubcert) {
        /* There is a full set staged, to be loaded */
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: all data staged", d->md->name);
        renew = 0;
    }
    
    if (renew) {
        if (APR_SUCCESS != (rv = md_acme_create(&ad->acme, d->p, d->md->ca_url, d->proxy_url)) 
            || APR_SUCCESS != (rv = md_acme_setup(ad->acme))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, "%s: setup ACME(%s)", 
                          d->md->name, d->md->ca_url);
            return rv;
        }

        if (!ad->md) {
            /* re-initialize staging */
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: setup staging", d->md->name);
            md_store_purge(d->store, d->p, MD_SG_STAGING, d->md->name);
            ad->md = md_copy(d->p, d->md);
            ad->md->cert_url = NULL; /* do not retrieve the old cert */
            rv = md_save(d->store, d->p, MD_SG_STAGING, ad->md, 0);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: save staged md", 
                          ad->md->name);
        }

        if (APR_SUCCESS == rv && !ad->cert) {
            md_cert_load(d->store, MD_SG_STAGING, ad->md->name, &ad->cert, d->p);
        }

        if (APR_SUCCESS == rv && !ad->cert) {
            ad->phase = "get certificate";
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, "%s: need certificate", d->md->name);
            
            /* Chose (or create) and ACME account to use */
            rv = ad_set_acct(d);
            
            /* Check that the account agreed to the terms-of-service, otherwise
             * requests for new authorizations are denied. ToS may change during the
             * lifetime of an account */
            if (APR_SUCCESS == rv) {
                const char *required;
                
                ad->phase = "check agreement";
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: check Terms-of-Service agreement", d->md->name);
                
                rv = md_acme_check_agreement(ad->acme, d->p, ad->md->ca_agreement, &required);
                
                if (APR_STATUS_IS_INCOMPLETE(rv) && required) {
                    /* The CA wants the user to agree to Terms-of-Services. Until the user
                     * has reconfigured and restarted the server, this MD cannot be
                     * driven further */
                    ad->md->state = MD_S_MISSING;
                    md_save(d->store, d->p, MD_SG_STAGING, ad->md, 0);

                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, d->p, 
                                  "%s: the CA requires you to accept the terms-of-service "
                                  "as specified in <%s>. "
                                  "Please read the document that you find at that URL and, "
                                  "if you agree to the conditions, configure "
                                  "\"MDCertificateAgreement url\" "
                                  "with exactly that URL in your Apache. "
                                  "Then (graceful) restart the server to activate.", 
                                  ad->md->name, required);
                    goto out;
                }
            }
            
            /* If we know a cert's location, try to get it. Previous download might
             * have failed. If server 404 it, we clear our memory of it. */
            if (APR_SUCCESS == rv && ad->md->cert_url) {
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: polling certificate", d->md->name);
                rv = ad_cert_poll(d, 1);
                if (APR_STATUS_IS_ENOENT(rv)) {
                    /* Server reports to know nothing about it. */
                    ad->md->cert_url = NULL;
                    rv = md_reg_update(d->reg, d->p, ad->md->name, ad->md, MD_UPD_CERT_URL);
                }
            }
            
            if (APR_SUCCESS == rv && !ad->cert) {
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: setup new authorization", d->md->name);
                if (APR_SUCCESS != (rv = ad_setup_authz(d))) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup authz resource", 
                                  ad->md->name);
                    goto out;
                }
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: setup new challenges", d->md->name);
                if (APR_SUCCESS != (rv = ad_start_challenges(d))) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: start challenges", 
                                  ad->md->name);
                    goto out;
                }
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: monitoring challenge status", d->md->name);
                if (APR_SUCCESS != (rv = ad_monitor_challenges(d))) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: monitor challenges", 
                                  ad->md->name);
                    goto out;
                }
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: creating certificate request", d->md->name);
                if (APR_SUCCESS != (rv = ad_setup_certificate(d))) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: setup certificate", 
                                  ad->md->name);
                    goto out;
                }
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                              "%s: received certificate", d->md->name);
            }
            
        }
        
        if (APR_SUCCESS == rv && !ad->chain) {
            /* have we created this already? */
            md_chain_load(d->store, MD_SG_STAGING, ad->md->name, &ad->chain, d->p);
        }
        if (APR_SUCCESS == rv && !ad->chain) {
            ad->phase = "install chain";
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, d->p, 
                          "%s: retrieving certificate chain", d->md->name);
            rv = ad_chain_install(d);
        }

        if (APR_SUCCESS == rv && !ad->pubcert) {
            /* have we created this already? */
            md_pubcert_load(d->store, MD_SG_STAGING, ad->md->name, &ad->pubcert, d->p);
        }
        if (APR_SUCCESS == rv && !ad->pubcert) {
            /* combine cert + chain into the pubcert */
            ad->pubcert = apr_array_make(d->p, ad->chain->nelts + 1, sizeof(md_cert_t*));
            APR_ARRAY_PUSH(ad->pubcert, md_cert_t *) = ad->cert;
            apr_array_cat(ad->pubcert, ad->chain);
            rv = md_pubcert_save(d->store, d->p, MD_SG_STAGING, ad->md->name, ad->pubcert, 0);
        }

        if (APR_SUCCESS == rv && ad->cert) {
            apr_time_t now = apr_time_now();
            apr_interval_time_t max_delay, delay_activation; 
            
            /* determine when this cert should be activated */
            d->stage_valid_from = md_cert_get_not_before(ad->cert);
            if (d->md->state == MD_S_COMPLETE && d->md->expires > now) {            
                /**
                 * The MD is complete and un-expired. This is a renewal run. 
                 * Give activation 24 hours leeway (if we have that time) to
                 * accommodate for clients with somewhat weird clocks.
                 */
                delay_activation = apr_time_from_sec(MD_SECS_PER_DAY);
                if (delay_activation > (max_delay = d->md->expires - now)) {
                    delay_activation = max_delay;
                }
                d->stage_valid_from += delay_activation;
            }
        }
    }
out:    
    return rv;
}

static apr_status_t acme_driver_stage(md_proto_driver_t *d)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;

    ad->phase = "ACME staging";
    if (APR_SUCCESS == (rv = acme_stage(d))) {
        ad->phase = "staging done";
    }
        
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: %s, %s", 
                  d->md->name, d->proto->protocol, ad->phase);
    return rv;
}

/**************************************************************************************************/
/* ACME preload */

static apr_status_t acme_preload(md_store_t *store, md_store_group_t load_group, 
                                 const char *name, const char *proxy_url, apr_pool_t *p) 
{
    apr_status_t rv;
    md_pkey_t *privkey, *acct_key;
    md_t *md;
    apr_array_header_t *pubcert;
    struct md_acme_acct_t *acct;

    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "%s: preload start", name);
    /* Load all data which will be taken into the DOMAIN storage group.
     * This serves several purposes:
     *  1. It's a format check on the input data. 
     *  2. We write back what we read, creating data with our own access permissions
     *  3. We ignore any other accumulated data in STAGING
     *  4. Once TMP is verified, we can swap/archive groups with a rename
     *  5. Reading/Writing the data will apply/remove any group specific data encryption.
     *     With the exemption that DOMAINS and TMP must apply the same policy/keys.
     */
    if (APR_SUCCESS != (rv = md_load(store, MD_SG_STAGING, name, &md, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading md json", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_pkey_load(store, MD_SG_STAGING, name, &privkey, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading staging private key", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_pubcert_load(store, MD_SG_STAGING, name, &pubcert, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: loading pubcert", name);
        return rv;
    }

    /* See if staging holds a new or modified account data */
    rv = md_acme_acct_load(&acct, &acct_key, store, MD_SG_STAGING, name, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        acct = NULL;
        acct_key = NULL;
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS != rv) {
        return rv; 
    }

    /* Remove any authz information we have here or in MD_SG_CHALLENGES */
    md_acme_authz_set_purge(store, MD_SG_STAGING, p, name);

    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                  "%s: staged data load, purging tmp space", name);
    rv = md_store_purge(store, p, load_group, name);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: error purging preload storage", name);
        return rv;
    }
    
    if (acct) {
        md_acme_t *acme;
        
        if (APR_SUCCESS != (rv = md_acme_create(&acme, p, md->ca_url, proxy_url))
            || APR_SUCCESS != (rv = md_acme_acct_save(store, p, acme, acct, acct_key))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: error saving acct", name);
            return rv;
        }
        md->ca_account = acct->id;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: saved ACME account %s", 
                      name, acct->id);
    }
    
    if (APR_SUCCESS != (rv = md_save(store, p, load_group, md, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving md json", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_pubcert_save(store, p, load_group, name, pubcert, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving cert chain", name);
        return rv;
    }
    if (APR_SUCCESS != (rv = md_pkey_save(store, p, load_group, name, privkey, 1))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: saving private key", name);
        return rv;
    }
    
    return rv;
}

static apr_status_t acme_driver_preload(md_proto_driver_t *d, md_store_group_t group)
{
    md_acme_driver_t *ad = d->baton;
    apr_status_t rv;

    ad->phase = "ACME preload";
    if (APR_SUCCESS == (rv = acme_preload(d->store, group, d->md->name, d->proxy_url, d->p))) {
        ad->phase = "preload done";
    }
        
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, d->p, "%s: %s, %s", 
                  d->md->name, d->proto->protocol, ad->phase);
    return rv;
}

static md_proto_t ACME_PROTO = {
    MD_PROTO_ACME, acme_driver_init, acme_driver_stage, acme_driver_preload
};
 
apr_status_t md_acme_protos_add(apr_hash_t *protos, apr_pool_t *p)
{
    (void)p;
    apr_hash_set(protos, MD_PROTO_ACME, sizeof(MD_PROTO_ACME)-1, &ACME_PROTO);
    return APR_SUCCESS;
}
