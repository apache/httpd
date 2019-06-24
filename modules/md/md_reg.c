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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_uri.h>

#include "md.h"
#include "md_crypt.h"
#include "md_log.h"
#include "md_json.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_status.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"

struct md_reg_t {
    apr_pool_t *p;
    struct md_store_t *store;
    struct apr_hash_t *protos;
    struct apr_hash_t *certs;
    int can_http;
    int can_https;
    const char *proxy_url;
    int domains_frozen;
    const md_timeslice_t *renew_window;
    const md_timeslice_t *warn_window;
};

/**************************************************************************************************/
/* life cycle */

static apr_status_t load_props(md_reg_t *reg, apr_pool_t *p)
{
    md_json_t *json;
    apr_status_t rv;
    
    rv = md_store_load(reg->store, MD_SG_NONE, NULL, MD_FN_HTTPD_JSON, 
                       MD_SV_JSON, (void**)&json, p);
    if (APR_SUCCESS == rv) {
        if (md_json_has_key(json, MD_KEY_PROTO, MD_KEY_HTTP, NULL)) {
            reg->can_http = md_json_getb(json, MD_KEY_PROTO, MD_KEY_HTTP, NULL);
        }
        if (md_json_has_key(json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL)) {
            reg->can_https = md_json_getb(json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL);
        }
    }
    else if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store,
                           const char *proxy_url)
{
    md_reg_t *reg;
    apr_status_t rv;
    
    reg = apr_pcalloc(p, sizeof(*reg));
    reg->p = p;
    reg->store = store;
    reg->protos = apr_hash_make(p);
    reg->certs = apr_hash_make(p);
    reg->can_http = 1;
    reg->can_https = 1;
    reg->proxy_url = proxy_url? apr_pstrdup(p, proxy_url) : NULL;
    
    md_timeslice_create(&reg->renew_window, p, MD_TIME_LIFE_NORM, MD_TIME_RENEW_WINDOW_DEF); 
    md_timeslice_create(&reg->warn_window, p, MD_TIME_LIFE_NORM, MD_TIME_WARN_WINDOW_DEF); 
    
    if (APR_SUCCESS == (rv = md_acme_protos_add(reg->protos, p))) {
        rv = load_props(reg, p);
    }
    
    *preg = (rv == APR_SUCCESS)? reg : NULL;
    return rv;
}

struct md_store_t *md_reg_store_get(md_reg_t *reg)
{
    return reg->store;
}

/**************************************************************************************************/
/* checks */

static apr_status_t check_values(md_reg_t *reg, apr_pool_t *p, const md_t *md, int fields)
{
    apr_status_t rv = APR_SUCCESS;
    const char *err = NULL;
    
    if (MD_UPD_DOMAINS & fields) {
        const md_t *other;
        const char *domain;
        int i;
        
        if (!md->domains || md->domains->nelts <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_EINVAL, p, 
                          "empty domain list: %s", md->name);
            return APR_EINVAL;
        }
        
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char *);
            if (!md_dns_is_name(p, domain, 1) && !md_dns_is_wildcard(p, domain)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                              "md %s with invalid domain name: %s", md->name, domain);
                return APR_EINVAL;
            }
        }

        if (NULL != (other = md_reg_find_overlap(reg, md, &domain, p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "md %s shares domain '%s' with md %s", 
                          md->name, domain, other->name);
            return APR_EINVAL;
        }
    }
    
    if (MD_UPD_CONTACTS & fields) {
        const char *contact;
        int i;

        for (i = 0; i < md->contacts->nelts && !err; ++i) {
            contact = APR_ARRAY_IDX(md->contacts, i, const char *);
            rv = md_util_abs_uri_check(p, contact, &err);
            
            if (err) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                              "contact for %s invalid (%s): %s", md->name, err, contact);
                return APR_EINVAL;
            }
        }
    }
    
    if ((MD_UPD_CA_URL & fields) && md->ca_url) { /* setting to empty is ok */
        rv = md_util_abs_uri_check(p, md->ca_url, &err);
        if (err) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s invalid (%s): %s", md->name, err, md->ca_url);
            return APR_EINVAL;
        }
    }
    
    if ((MD_UPD_CA_PROTO & fields) && md->ca_proto) { /* setting to empty is ok */
        /* Do we want to restrict this to "known" protocols? */
    }
    
    if ((MD_UPD_CA_ACCOUNT & fields) && md->ca_account) { /* setting to empty is ok */
        /* hmm, in case we know the protocol, some checks could be done */
    }

    if ((MD_UPD_AGREEMENT & fields) && md->ca_agreement
        && strcmp("accepted", md->ca_agreement)) { /* setting to empty is ok */
        rv = md_util_abs_uri_check(p, md->ca_agreement, &err);
        if (err) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, 
                          "CA url for %s invalid (%s): %s", md->name, err, md->ca_agreement);
            return APR_EINVAL;
        }
    }

    return rv;
}

/**************************************************************************************************/
/* state assessment */

static apr_status_t state_init(md_reg_t *reg, apr_pool_t *p, md_t *md)
{
    md_state_t state = MD_S_UNKNOWN;
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    apr_status_t rv;

    if (md->renew_window == NULL) md->renew_window = reg->renew_window;
    if (md->warn_window == NULL) md->warn_window = reg->warn_window;

    if (APR_SUCCESS == (rv = md_reg_get_pubcert(&pub, reg, md, p))) {
        cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
        if (!md_is_covered_by_alt_names(md, pub->alt_names)) {
            state = MD_S_INCOMPLETE;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                          "md{%s}: incomplete, cert no longer covers all domains, "
                          "needs sign up for a new certificate", md->name);
            goto out;
        }
        if (!md->must_staple != !md_cert_must_staple(cert)) {
            state = MD_S_INCOMPLETE;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                          "md{%s}: OCSP Stapling is%s requested, but certificate "
                          "has it%s enabled. Need to get a new certificate.", md->name,
                          md->must_staple? "" : " not", 
                          !md->must_staple? "" : " not");
            goto out;
        }
        
        state = MD_S_COMPLETE;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md{%s}: is complete", md->name);
    }
    else if (APR_STATUS_IS_ENOENT(rv)) {
        state = MD_S_INCOMPLETE;
        rv = APR_SUCCESS;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                      "md{%s}: incomplete, credentials not all there", md->name);
    }

out:    
    if (APR_SUCCESS != rv) {
        state = MD_S_ERROR;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "md{%s}: error", md->name);
    }
    md->state = state;
    return rv;
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    md_reg_t *reg;
    md_reg_do_cb *cb;
    void *baton;
    const char *exclude;
    const void *result;
} reg_do_ctx;

static int reg_md_iter(void *baton, md_store_t *store, md_t *md, apr_pool_t *ptemp)
{
    reg_do_ctx *ctx = baton;
    
    (void)store;
    if (!ctx->exclude || strcmp(ctx->exclude, md->name)) {
        state_init(ctx->reg, ptemp, (md_t*)md);
        return ctx->cb(ctx->baton, ctx->reg, md);
    }
    return 1;
}

static int reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg, apr_pool_t *p, const char *exclude)
{
    reg_do_ctx ctx;
    
    ctx.reg = reg;
    ctx.cb = cb;
    ctx.baton = baton;
    ctx.exclude = exclude;
    return md_store_md_iter(reg_md_iter, &ctx, reg->store, p, MD_SG_DOMAINS, "*");
}


int md_reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg, apr_pool_t *p)
{
    return reg_do(cb, baton, reg, p, NULL);
}

/**************************************************************************************************/
/* lookup */

md_t *md_reg_get(md_reg_t *reg, const char *name, apr_pool_t *p)
{
    md_t *md;
    
    if (APR_SUCCESS == md_load(reg->store, MD_SG_DOMAINS, name, &md, p)) {
        state_init(reg, p, md);
        return md;
    }
    return NULL;
}

apr_status_t md_reg_reinit_state(md_reg_t *reg, md_t *md, apr_pool_t *p)
{
    return state_init(reg, p, md);
}

typedef struct {
    const char *domain;
    md_t *md;
} find_domain_ctx;

static int find_domain(void *baton, md_reg_t *reg, md_t *md)
{
    find_domain_ctx *ctx = baton;
    
    (void)reg;
    if (md_contains(md, ctx->domain, 0)) {
        ctx->md = md;
        return 0;
    }
    return 1;
}

md_t *md_reg_find(md_reg_t *reg, const char *domain, apr_pool_t *p)
{
    find_domain_ctx ctx;

    ctx.domain = domain;
    ctx.md = NULL;
    
    md_reg_do(find_domain, &ctx, reg, p);
    if (ctx.md) {
        state_init(reg, p, ctx.md);
    }
    return ctx.md;
}

typedef struct {
    const md_t *md_checked;
    md_t *md;
    const char *s;
} find_overlap_ctx;

static int find_overlap(void *baton, md_reg_t *reg, md_t *md)
{
    find_overlap_ctx *ctx = baton;
    const char *overlap;
    
    (void)reg;
    if ((overlap = md_common_name(ctx->md_checked, md))) {
        ctx->md = md;
        ctx->s = overlap;
        return 0;
    }
    return 1;
}

md_t *md_reg_find_overlap(md_reg_t *reg, const md_t *md, const char **pdomain, apr_pool_t *p)
{
    find_overlap_ctx ctx;
    
    ctx.md_checked = md;
    ctx.md = NULL;
    ctx.s = NULL;
    
    reg_do(find_overlap, &ctx, reg, p, md->name);
    if (pdomain && ctx.s) {
        *pdomain = ctx.s;
    }
    if (ctx.md) {
        state_init(reg, p, ctx.md);
    }
    return ctx.md;
}

/**************************************************************************************************/
/* manipulation */

static apr_status_t p_md_add(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    md_t *md, *mine;
    int do_check;
    
    md = va_arg(ap, md_t *);
    do_check = va_arg(ap, int);

    if (reg->domains_frozen) return APR_EACCES; 
    mine = md_clone(ptemp, md);
    if (do_check && APR_SUCCESS != (rv = check_values(reg, ptemp, md, MD_UPD_ALL))) goto leave;
    if (APR_SUCCESS != (rv = state_init(reg, ptemp, mine))) goto leave;
    rv = md_save(reg->store, p, MD_SG_DOMAINS, mine, 1);
leave:
    return rv;
}

static apr_status_t add_md(md_reg_t *reg, md_t *md, apr_pool_t *p, int do_checks)
{
    return md_util_pool_vdo(p_md_add, reg, p, md, do_checks, NULL);
}

apr_status_t md_reg_add(md_reg_t *reg, md_t *md, apr_pool_t *p)
{
    return add_md(reg, md, p, 1);
}

static apr_status_t p_md_update(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    const char *name;
    const md_t *md, *updates;
    int fields, do_checks;
    md_t *nmd;
    
    name = va_arg(ap, const char *);
    updates = va_arg(ap, const md_t *);
    fields = va_arg(ap, int);
    do_checks = va_arg(ap, int);
    
    if (NULL == (md = md_reg_get(reg, name, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_ENOENT, ptemp, "md %s", name);
        return APR_ENOENT;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "update md %s", name);
    
    if (do_checks && APR_SUCCESS != (rv = check_values(reg, ptemp, updates, fields))) {
        return rv;
    }
    
    if (reg->domains_frozen) return APR_EACCES; 
    nmd = md_copy(ptemp, md);
    if (MD_UPD_DOMAINS & fields) {
        nmd->domains = updates->domains;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update domains: %s", name);
    }
    if (MD_UPD_CA_URL & fields) {
        nmd->ca_url = updates->ca_url;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update ca url: %s", name);
    }
    if (MD_UPD_CA_PROTO & fields) {
        nmd->ca_proto = updates->ca_proto;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update ca protocol: %s", name);
    }
    if (MD_UPD_CA_ACCOUNT & fields) {
        nmd->ca_account = updates->ca_account;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update account: %s", name);
    }
    if (MD_UPD_CONTACTS & fields) {
        nmd->contacts = updates->contacts;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update contacts: %s", name);
    }
    if (MD_UPD_AGREEMENT & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update agreement: %s", name);
        nmd->ca_agreement = updates->ca_agreement;
    }
    if (MD_UPD_DRIVE_MODE & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update drive-mode: %s", name);
        nmd->renew_mode = updates->renew_mode;
    }
    if (MD_UPD_RENEW_WINDOW & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update renew-window: %s", name);
        nmd->renew_window = updates->renew_window;
    }
    if (MD_UPD_WARN_WINDOW & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update warn-window: %s", name);
        nmd->warn_window = updates->warn_window;
    }
    if (MD_UPD_CA_CHALLENGES & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update ca challenges: %s", name);
        nmd->ca_challenges = (updates->ca_challenges? 
                              apr_array_copy(p, updates->ca_challenges) : NULL);
    }
    if (MD_UPD_PKEY_SPEC & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update pkey spec: %s", name);
        nmd->pkey_spec = NULL;
        if (updates->pkey_spec) {
            nmd->pkey_spec = apr_pmemdup(p, updates->pkey_spec, sizeof(md_pkey_spec_t));
        }
    }
    if (MD_UPD_REQUIRE_HTTPS & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update require-https: %s", name);
        nmd->require_https = updates->require_https;
    }
    if (MD_UPD_TRANSITIVE & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update transitive: %s", name);
        nmd->transitive = updates->transitive;
    }
    if (MD_UPD_MUST_STAPLE & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update must-staple: %s", name);
        nmd->must_staple = updates->must_staple;
    }
    if (MD_UPD_PROTO & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update proto: %s", name);
        nmd->acme_tls_1_domains = updates->acme_tls_1_domains;
    }
    
    if (fields && APR_SUCCESS == (rv = md_save(reg->store, p, MD_SG_DOMAINS, nmd, 0))) {
        rv = state_init(reg, ptemp, nmd);
    }
    return rv;
}

static apr_status_t update_md(md_reg_t *reg, apr_pool_t *p, 
                              const char *name, const md_t *md, 
                              int fields, int do_checks)
{
    return md_util_pool_vdo(p_md_update, reg, p, name, md, fields, do_checks, NULL);
}

apr_status_t md_reg_update(md_reg_t *reg, apr_pool_t *p, 
                           const char *name, const md_t *md, int fields)
{
    return update_md(reg, p, name, md, fields, 1);
}

apr_status_t md_reg_delete_acct(md_reg_t *reg, apr_pool_t *p, const char *acct_id) 
{
    apr_status_t rv = APR_SUCCESS;
    
    rv = md_store_remove(reg->store, MD_SG_ACCOUNTS, acct_id, MD_FN_ACCOUNT, p, 1);
    if (APR_SUCCESS == rv) {
        md_store_remove(reg->store, MD_SG_ACCOUNTS, acct_id, MD_FN_ACCT_KEY, p, 1);
    }
    return rv;
}

/**************************************************************************************************/
/* certificate related */

static apr_status_t pubcert_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_array_header_t *certs;
    md_pubcert_t *pubcert, **ppubcert;
    const md_t *md;
    const md_cert_t *cert;
    md_cert_state_t cert_state;
    md_store_group_t group;
    apr_status_t rv;
    
    ppubcert = va_arg(ap, md_pubcert_t **);
    group = (md_store_group_t)va_arg(ap, int);
    md = va_arg(ap, const md_t *);
    
    if (md->cert_file) {
        rv = md_chain_fload(&certs, p, md->cert_file);
    }
    else {
        rv = md_pubcert_load(reg->store, group, md->name, &certs, p);
    }
    if (APR_SUCCESS != rv) goto leave;
            
    pubcert = apr_pcalloc(p, sizeof(*pubcert));
    pubcert->certs = certs;
    cert = APR_ARRAY_IDX(certs, 0, const md_cert_t *);
    if (APR_SUCCESS != (rv = md_cert_get_alt_names(&pubcert->alt_names, cert, p))) goto leave;
    switch ((cert_state = md_cert_state_get(cert))) {
        case MD_CERT_VALID:
        case MD_CERT_EXPIRED:
            break;
        default:
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, ptemp, 
                          "md %s has unexpected cert state: %d", md->name, cert_state);
            rv = APR_ENOTIMPL;
            break;
    }
leave:
    *ppubcert = (APR_SUCCESS == rv)? pubcert : NULL;
    return rv;
}

apr_status_t md_reg_get_pubcert(const md_pubcert_t **ppubcert, md_reg_t *reg, 
                                const md_t *md, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    const md_pubcert_t *pubcert;
    const char *name;

    pubcert = apr_hash_get(reg->certs, md->name, (apr_ssize_t)strlen(md->name));
    if (!pubcert && !reg->domains_frozen) {
        rv = md_util_pool_vdo(pubcert_load, reg, reg->p, &pubcert, MD_SG_DOMAINS, md, NULL);
        if (APR_STATUS_IS_ENOENT(rv)) {
            /* We cache it missing with an empty record */
            pubcert = apr_pcalloc(reg->p, sizeof(*pubcert));
        }
        else if (APR_SUCCESS != rv) goto leave;
        name = (p != reg->p)? apr_pstrdup(reg->p, md->name) : md->name;
        apr_hash_set(reg->certs, name, (apr_ssize_t)strlen(name), pubcert);
    }
leave:
    if (APR_SUCCESS == rv && (!pubcert || !pubcert->certs)) {
        rv = APR_ENOENT;
    }
    *ppubcert = (APR_SUCCESS == rv)? pubcert : NULL;
    return rv;
}

apr_status_t md_reg_get_cred_files(const char **pkeyfile, const char **pcertfile,
                                   md_reg_t *reg, md_store_group_t group, 
                                   const md_t *md, apr_pool_t *p)
{
    apr_status_t rv;
    
    if (md->cert_file) {
        /* With fixed files configured, we use those without further checking them ourself */
        *pcertfile = md->cert_file;
        *pkeyfile = md->pkey_file;
        return APR_SUCCESS;
    }
    rv = md_store_get_fname(pkeyfile, reg->store, group, md->name, MD_FN_PRIVKEY, p);
    if (APR_SUCCESS != rv) return rv;
    if (!md_file_exists(*pkeyfile, p)) return APR_ENOENT;
    rv = md_store_get_fname(pcertfile, reg->store, group, md->name, MD_FN_PUBCERT, p);
    if (APR_SUCCESS != rv) return rv;
    if (!md_file_exists(*pcertfile, p)) return APR_ENOENT;
    return APR_SUCCESS;
}

int md_reg_should_renew(md_reg_t *reg, const md_t *md, apr_pool_t *p) 
{
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    md_timeperiod_t certlife, renewal;
    apr_status_t rv;
    
    if (md->state == MD_S_INCOMPLETE) return 1;
    rv = md_reg_get_pubcert(&pub, reg, md, p);
    if (APR_STATUS_IS_ENOENT(rv)) return 1;
    if (APR_SUCCESS == rv) {
        cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
        certlife.start = md_cert_get_not_before(cert);
        certlife.end = md_cert_get_not_after(cert);

        renewal = md_timeperiod_slice_before_end(&certlife, md->renew_window);
        if (md_log_is_level(p, MD_LOG_TRACE1)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p, 
                          "md[%s]: cert-life[%s] renewal[%s]", md->name, 
                          md_timeperiod_print(p, &certlife),
                          md_timeperiod_print(p, &renewal));
        }
        return md_timeperiod_has_started(&renewal, apr_time_now());
    }
    return 0;
}

int md_reg_should_warn(md_reg_t *reg, const md_t *md, apr_pool_t *p)
{
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    md_timeperiod_t certlife, warn;
    apr_status_t rv;
    
    if (md->state == MD_S_INCOMPLETE) return 0;
    rv = md_reg_get_pubcert(&pub, reg, md, p);
    if (APR_STATUS_IS_ENOENT(rv)) return 0;
    if (APR_SUCCESS == rv) {
        cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
        certlife.start = md_cert_get_not_before(cert);
        certlife.end = md_cert_get_not_after(cert);

        warn = md_timeperiod_slice_before_end(&certlife, md->warn_window);
        if (md_log_is_level(p, MD_LOG_TRACE1)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p, 
                          "md[%s]: cert-life[%s] warn[%s]", md->name, 
                          md_timeperiod_print(p, &certlife),
                          md_timeperiod_print(p, &warn));
        }
        return md_timeperiod_has_started(&warn, apr_time_now());
    }
    return 0;
}

/**************************************************************************************************/
/* synching */

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *store_mds;
} sync_ctx;

static int do_add_md(void *baton, md_store_t *store, md_t *md, apr_pool_t *ptemp)
{
    sync_ctx *ctx = baton;

    (void)store;
    (void)ptemp;
    APR_ARRAY_PUSH(ctx->store_mds, const md_t*) = md_clone(ctx->p, md);
    return 1;
}

static apr_status_t read_store_mds(md_reg_t *reg, sync_ctx *ctx)
{
    int rv;
    
    apr_array_clear(ctx->store_mds);
    rv = md_store_md_iter(do_add_md, ctx, reg->store, ctx->p, MD_SG_DOMAINS, "*");
    if (APR_STATUS_IS_ENOENT(rv) || APR_STATUS_IS_EINVAL(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

apr_status_t md_reg_set_props(md_reg_t *reg, apr_pool_t *p, int can_http, int can_https)
{
    if (reg->can_http != can_http || reg->can_https != can_https) {
        md_json_t *json;
        
        if (reg->domains_frozen) return APR_EACCES; 
        reg->can_http = can_http;
        reg->can_https = can_https;
        
        json = md_json_create(p);
        md_json_setb(can_http, json, MD_KEY_PROTO, MD_KEY_HTTP, NULL);
        md_json_setb(can_https, json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL);
        
        return md_store_save(reg->store, p, MD_SG_NONE, NULL, MD_FN_HTTPD_JSON, MD_SV_JSON, json, 0);
    }
    return APR_SUCCESS;
}

static apr_status_t update_md(md_reg_t *reg, apr_pool_t *p, 
                              const char *name, const md_t *md, 
                              int fields, int do_checks);
 
/**
 * Procedure:
 * 1. Collect all defined "managed domains" (MD). It does not matter where a MD is defined. 
 *    All MDs need to be unique and have no overlaps in their domain names. 
 *    Fail the config otherwise. Also, if a vhost matches an MD, it
 *    needs to *only* have ServerAliases from that MD. There can be no more than one
 *    matching MD for a vhost. But an MD can apply to several vhosts.
 * 2. Synchronize with the persistent store. Iterate over all configured MDs and 
 *   a. create them in the store if they do not already exist, neither under the
 *      name or with a common domain.
 *   b. compare domain lists from store and config, if
 *      - store has dns name in other MD than from config, remove dns name from store def,
 *        issue WARNING.
 *      - store misses dns name from config, add dns name and update store
 *   c. compare MD acme url/protocol, update if changed
 */
apr_status_t md_reg_sync(md_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, 
                         apr_array_header_t *master_mds) 
{
    sync_ctx ctx;
    apr_status_t rv;

    ctx.p = ptemp;
    ctx.store_mds = apr_array_make(ptemp, 100, sizeof(md_t *));
    rv = read_store_mds(reg, &ctx);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                  "sync: found %d mds in store", ctx.store_mds->nelts);
    if (reg->domains_frozen) return APR_EACCES; 
    if (APR_SUCCESS == rv) {
        int i, fields;
        md_t *md, *config_md, *smd, *omd;
        const char *common;
        
        for (i = 0; i < master_mds->nelts; ++i) {
            md = APR_ARRAY_IDX(master_mds, i, md_t *);
            
            /* find the store md that is closest match for the configured md */
            smd = md_find_closest_match(ctx.store_mds, md);
            if (smd) {
                fields = 0;
                
                /* Did the name change? This happens when the order of names in configuration
                 * changes or when the first name is removed. Use the name from the store, but
                 * remember the original one. We try to align this later on. */
                if (strcmp(md->name, smd->name)) {
                    md->configured_name = md->name;
                    md->name = apr_pstrdup(p, smd->name);
                }
                
                /* Make the stored domain list *exactly* the same, even if
                 * someone only changed upper/lowercase, we'd like to persist that. */
                if (!md_equal_domains(md, smd, 1)) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                                 "%s: domains changed", smd->name);
                    smd->domains = md_array_str_clone(ptemp, md->domains);
                    fields |= MD_UPD_DOMAINS;
                }
                
                /* Look for other store mds which have domains now being part of smd */
                while (APR_SUCCESS == rv && (omd = md_get_by_dns_overlap(ctx.store_mds, md))) {
                    /* find the name now duplicate */
                    common = md_common_name(md, omd);
                    assert(common);
                    
                    /* Is this md still configured or has it been abandoned in the config? */
                    config_md = md_get_by_name(master_mds, omd->name);
                    if (config_md && md_contains(config_md, common, 0)) {
                        /* domain used in two configured mds, not allowed */
                        rv = APR_EINVAL;
                        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                                      "domain %s used in md %s and %s", 
                                      common, md->name, omd->name);
                    }
                    else {
                        /* remove it from the other md and update store, or, if it
                         * is now empty, move it into the archive */
                        omd->domains = md_array_str_remove(ptemp, omd->domains, common, 0);
                        if (apr_is_empty_array(omd->domains)) {
                            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                                          "All domains of the MD %s have moved elsewhere, "
                                          " moving it to the archive. ", omd->name);
                            md_reg_remove(reg, ptemp, omd->name, 1); /* best effort */
                        }
                        else {
                            rv = update_md(reg, ptemp, omd->name, omd, MD_UPD_DOMAINS, 0);
                        }
                    }
                }

                /* If no CA url/proto is configured for the MD, take the default */
                if (!md->ca_url) {
                    md->ca_url = MD_ACME_DEF_URL;
                    md->ca_proto = MD_PROTO_ACME; 
                }
                
                if (MD_SVAL_UPDATE(md, smd, ca_url)) {
                    smd->ca_url = md->ca_url;
                    fields |= MD_UPD_CA_URL;
                }
                if (MD_SVAL_UPDATE(md, smd, ca_proto)) {
                    smd->ca_proto = md->ca_proto;
                    fields |= MD_UPD_CA_PROTO;
                }
                if (MD_SVAL_UPDATE(md, smd, ca_agreement)) {
                    smd->ca_agreement = md->ca_agreement;
                    fields |= MD_UPD_AGREEMENT;
                }
                if (MD_VAL_UPDATE(md, smd, transitive)) {
                    smd->transitive = md->transitive;
                    fields |= MD_UPD_TRANSITIVE;
                }
                if (MD_VAL_UPDATE(md, smd, renew_mode)) {
                    smd->renew_mode = md->renew_mode;
                    fields |= MD_UPD_DRIVE_MODE;
                }
                if (!apr_is_empty_array(md->contacts) 
                    && !md_array_str_eq(md->contacts, smd->contacts, 0)) {
                    smd->contacts = md->contacts;
                    fields |= MD_UPD_CONTACTS;
                }
                if (!md_timeslice_eq(md->renew_window, smd->renew_window)) {
                    smd->renew_window = md->renew_window;
                    fields |= MD_UPD_RENEW_WINDOW;
                }
                if (!md_timeslice_eq(md->warn_window, smd->warn_window)) {
                    smd->warn_window = md->warn_window;
                    fields |= MD_UPD_WARN_WINDOW;
                }
                if (md->ca_challenges) {
                    md->ca_challenges = md_array_str_compact(p, md->ca_challenges, 0);
                    if (!smd->ca_challenges 
                        || !md_array_str_eq(md->ca_challenges, smd->ca_challenges, 0)) {
                        smd->ca_challenges = apr_array_copy(ptemp, md->ca_challenges);
                        fields |= MD_UPD_CA_CHALLENGES;
                    }
                }
                else if (smd->ca_challenges) {
                    smd->ca_challenges = NULL;
                    fields |= MD_UPD_CA_CHALLENGES;
                }
                if (!md_pkey_spec_eq(md->pkey_spec, smd->pkey_spec)) {
                    fields |= MD_UPD_PKEY_SPEC;
                    smd->pkey_spec = NULL;
                    if (md->pkey_spec) {
                        smd->pkey_spec = apr_pmemdup(p, md->pkey_spec, sizeof(md_pkey_spec_t));
                    }
                }
                if (MD_VAL_UPDATE(md, smd, require_https)) {
                    smd->require_https = md->require_https;
                    fields |= MD_UPD_REQUIRE_HTTPS;
                }
                if (MD_VAL_UPDATE(md, smd, must_staple)) {
                    smd->must_staple = md->must_staple;
                    fields |= MD_UPD_MUST_STAPLE;
                }
                if (!md_array_str_eq(md->acme_tls_1_domains, smd->acme_tls_1_domains, 0)) {
                    smd->acme_tls_1_domains = md->acme_tls_1_domains;
                    fields |= MD_UPD_PROTO;
                }
                
                if (fields) {
                    rv = update_md(reg, ptemp, smd->name, smd, fields, 0);
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md %s updated", smd->name);
                }
            }
            else {
                /* new managed domain */
                /* If no CA url/proto is configured for the MD, take the default */
                if (!md->ca_url) {
                    md->ca_url = MD_ACME_DEF_URL;
                    md->ca_proto = MD_PROTO_ACME; 
                }
                rv = add_md(reg, md, ptemp, 0);
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "new md %s added", md->name);
            }
        }
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "loading mds");
    }
    
    return rv;
}

apr_status_t md_reg_remove(md_reg_t *reg, apr_pool_t *p, const char *name, int archive)
{
    if (reg->domains_frozen) return APR_EACCES; 
    return md_store_move(reg->store, p, MD_SG_DOMAINS, MD_SG_ARCHIVE, name, archive);
}

typedef struct {
    md_reg_t *reg;
    apr_pool_t *p;
    apr_array_header_t *mds;
} cleanup_challenge_ctx;
 
static apr_status_t cleanup_challenge_inspector(void *baton, const char *dir, const char *name, 
                                                md_store_vtype_t vtype, void *value, 
                                                apr_pool_t *ptemp)
{
    cleanup_challenge_ctx *ctx = baton;
    const md_t *md;
    int i, used;
    apr_status_t rv;
    
    (void)value;
    (void)vtype;
    (void)dir;
    for (used = 0, i = 0; i < ctx->mds->nelts && !used; ++i) {
        md = APR_ARRAY_IDX(ctx->mds, i, const md_t *);
        used = !strcmp(name, md->name);
    }
    if (!used) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, 
                      "challenges/%s: not in use, purging", name);
        rv = md_store_purge(ctx->reg->store, ctx->p, MD_SG_CHALLENGES, name);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, ptemp, 
                          "challenges/%s: unable to purge", name);
        }
    }
    return APR_SUCCESS;
}

apr_status_t md_reg_cleanup_challenges(md_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, 
                                       apr_array_header_t *mds)
{
    apr_status_t rv;
    cleanup_challenge_ctx ctx;

    (void)p;
    ctx.reg = reg;
    ctx.p = ptemp;
    ctx.mds = mds;
    rv = md_store_iter_names(cleanup_challenge_inspector, &ctx, reg->store, ptemp, 
                             MD_SG_CHALLENGES, "*");
    return rv;
}


/**************************************************************************************************/
/* driving */

static apr_status_t run_init(void *baton, apr_pool_t *p, ...)
{
    va_list ap;
    md_reg_t *reg = baton;
    const md_t *md;
    md_proto_driver_t *driver, **pdriver;
    md_result_t *result;
    apr_table_t *env;
    
    (void)p;
    va_start(ap, p);
    pdriver = va_arg(ap, md_proto_driver_t **);
    md = va_arg(ap, const md_t *);
    env = va_arg(ap, apr_table_t *);
    result = va_arg(ap, md_result_t *); 
    va_end(ap);
    
    *pdriver = driver = apr_pcalloc(p, sizeof(*driver));

    driver->p = p;
    driver->env = env? apr_table_copy(p, env) : apr_table_make(p, 10);
    driver->reg = reg;
    driver->store = md_reg_store_get(reg);
    driver->proxy_url = reg->proxy_url;
    driver->md = md;
    driver->can_http = reg->can_http;
    driver->can_https = reg->can_https;

    if (!md->ca_proto) {
        md_result_printf(result, APR_EGENERAL, "CA protocol is not defined"); 
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "md[%s]: %s", md->name, result->detail);
        goto leave;
    }
    
    driver->proto = apr_hash_get(reg->protos, md->ca_proto, (apr_ssize_t)strlen(md->ca_proto));
    if (!driver->proto) {
        md_result_printf(result, APR_EGENERAL, "Unknown CA protocol '%s'", md->ca_proto); 
        goto leave;
    }
    
    result->status = driver->proto->init(driver, result);

leave:
    if (APR_SUCCESS != result->status) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, result->status, p, "md[%s]: %s", md->name, 
                      result->detail? result->detail : "<see error log for details>");
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "%s: init done", md->name);
    }
    return result->status;
}

static apr_status_t run_test_init(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const md_t *md;
    apr_table_t *env;
    md_result_t *result;
    md_proto_driver_t *driver;
    
    (void)p;
    md = va_arg(ap, const md_t *);
    env = va_arg(ap, apr_table_t *);
    result = va_arg(ap, md_result_t *); 

    return run_init(baton, ptemp, &driver, md, env, result, NULL);
}

apr_status_t md_reg_test_init(md_reg_t *reg, const md_t *md, struct apr_table_t *env, 
                              md_result_t *result, apr_pool_t *p)
{
    return md_util_pool_vdo(run_test_init, reg, p, md, env, result, NULL);
}

static apr_status_t run_renew(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    const md_t *md;
    int reset;
    md_proto_driver_t *driver;
    apr_table_t *env;
    apr_status_t rv;
    md_result_t *result;
    
    (void)p;
    md = va_arg(ap, const md_t *);
    env = va_arg(ap, apr_table_t *);
    reset = va_arg(ap, int); 
    result = va_arg(ap, md_result_t *); 

    rv = run_init(baton, ptemp, &driver, md, env, result, NULL);
    if (APR_SUCCESS == rv) { 
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "%s: run staging", md->name);
        driver->reset = reset;
        rv = driver->proto->renew(driver, result);
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "%s: staging done", md->name);
    return rv;
}

apr_status_t md_reg_renew(md_reg_t *reg, const md_t *md, apr_table_t *env, 
                          int reset, md_result_t *result, apr_pool_t *p)
{
    return md_util_pool_vdo(run_renew, reg, p, md, env, reset, result, NULL);
}

static apr_status_t run_load_staging(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    const md_t *md;
    md_proto_driver_t *driver;
    md_result_t *result;
    apr_table_t *env;
    md_job_t *job;
    apr_status_t rv;
    
    /* For the MD,  check if something is in the STAGING area. If none is there, 
     * return that status. Otherwise ask the protocol driver to preload it into
     * a new, temporary area. 
     * If that succeeds, we move the TEMP area over the DOMAINS (causing the 
     * existing one go to ARCHIVE).
     * Finally, we clean up the data from CHALLENGES and STAGING.
     */
    md = va_arg(ap, const md_t*);
    env =  va_arg(ap, apr_table_t*);
    result =  va_arg(ap, md_result_t*);
    
    if (APR_STATUS_IS_ENOENT(rv = md_load(reg->store, MD_SG_STAGING, md->name, NULL, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, ptemp, "%s: nothing staged", md->name);
        goto out;
    }
    
    rv = run_init(baton, ptemp, &driver, md, env, result, NULL);
    if (APR_SUCCESS != rv) goto out;
    
    apr_hash_set(reg->certs, md->name, (apr_ssize_t)strlen(md->name), NULL);
    md_result_activity_setn(result, "preloading staged to tmp");
    rv = driver->proto->preload(driver, MD_SG_TMP, result);
    if (APR_SUCCESS != rv) goto out;

    /* If we had a job saved in STAGING, copy it over too */
    job = md_job_make(ptemp, md->name);
    if (APR_SUCCESS == md_job_load(job, reg, MD_SG_STAGING, ptemp)) {
        md_job_save(job, reg, MD_SG_TMP, NULL, ptemp);
    }
    
    /* swap */
    md_result_activity_setn(result, "moving tmp to become new domains");
    rv = md_store_move(reg->store, p, MD_SG_TMP, MD_SG_DOMAINS, md->name, 1);
    if (APR_SUCCESS != rv) {
        md_result_set(result, rv, NULL);
        goto out;
    }
    
    md_store_purge(reg->store, p, MD_SG_STAGING, md->name);
    md_store_purge(reg->store, p, MD_SG_CHALLENGES, md->name);
    md_result_set(result, APR_SUCCESS, "new certificate successfully saved in domains");

out:
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "%s: load done", md->name);
    return rv;
}

apr_status_t md_reg_load_staging(md_reg_t *reg, const md_t *md, apr_table_t *env, 
                                 md_result_t *result, apr_pool_t *p)
{
    if (reg->domains_frozen) return APR_EACCES;
    return md_util_pool_vdo(run_load_staging, reg, p, md, env, result, NULL);
}

apr_status_t md_reg_freeze_domains(md_reg_t *reg, apr_array_header_t *mds)
{
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    const md_pubcert_t *pubcert;
    int i;
    
    assert(!reg->domains_frozen);
    /* prefill the certs cache for all mds */
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, md_t*);
        rv = md_reg_get_pubcert(&pubcert, reg, md, reg->p);
        if (APR_SUCCESS != rv && !APR_STATUS_IS_ENOENT(rv)) goto leave;
    }
    reg->domains_frozen = 1;
leave:
    return rv;
}

void md_reg_set_renew_window_default(md_reg_t *reg, const md_timeslice_t *renew_window)
{
    reg->renew_window = renew_window;
}

void md_reg_set_warn_window_default(md_reg_t *reg, const md_timeslice_t *warn_window)
{
    reg->warn_window = warn_window;
}
