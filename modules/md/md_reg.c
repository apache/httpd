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
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_acct.h"

struct md_reg_t {
    struct md_store_t *store;
    struct apr_hash_t *protos;
    int can_http;
    int can_https;
    const char *proxy_url;
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

apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *p, struct md_store_t *store,
                         const char *proxy_url)
{
    md_reg_t *reg;
    apr_status_t rv;
    
    reg = apr_pcalloc(p, sizeof(*reg));
    reg->store = store;
    reg->protos = apr_hash_make(p);
    reg->can_http = 1;
    reg->can_https = 1;
    reg->proxy_url = proxy_url? apr_pstrdup(p, proxy_url) : NULL;
    
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
            if (!md_util_is_dns_name(p, domain, 1)) {
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

    if ((MD_UPD_AGREEMENT & fields) && md->ca_agreement) { /* setting to empty is ok */
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

static apr_status_t state_init(md_reg_t *reg, apr_pool_t *p, md_t *md, int save_changes)
{
    md_state_t state = MD_S_UNKNOWN;
    const md_creds_t *creds;
    const md_cert_t *cert;
    apr_time_t expires = 0, valid_from = 0;
    apr_status_t rv;
    int i;

    if (APR_SUCCESS == (rv = md_reg_creds_get(&creds, reg, MD_SG_DOMAINS, md, p))) {
        state = MD_S_INCOMPLETE;
        if (!creds->privkey) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                          "md{%s}: incomplete, without private key", md->name);
        }
        else if (!creds->cert) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                          "md{%s}: incomplete, has key but no certificate", md->name);
        }
        else {
            valid_from = md_cert_get_not_before(creds->cert);
            expires = md_cert_get_not_after(creds->cert);
            if (md_cert_has_expired(creds->cert)) {
                state = MD_S_EXPIRED;
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                              "md{%s}: expired, certificate has expired", md->name);
                goto out;
            }
            if (!md_cert_is_valid_now(creds->cert)) {
                state = MD_S_ERROR;
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                              "md{%s}: error, certificate valid in future (clock wrong?)", 
                              md->name);
                goto out;
            }
            if (!md_cert_covers_md(creds->cert, md)) {
                state = MD_S_INCOMPLETE;
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, 
                              "md{%s}: incomplete, cert no longer covers all domains, "
                              "needs sign up for a new certificate", md->name);
                goto out;
            }
            if (!md->must_staple != !md_cert_must_staple(creds->cert)) {
                state = MD_S_INCOMPLETE;
                md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, 
                              "md{%s}: OCSP Stapling is%s requested, but certificate "
                              "has it%s enabled. Need to get a new certificate.", md->name,
                              md->must_staple? "" : " not", 
                              !md->must_staple? "" : " not");
                goto out;
            }

            for (i = 1; i < creds->pubcert->nelts; ++i) {
                cert = APR_ARRAY_IDX(creds->pubcert, i, const md_cert_t *);
                if (!md_cert_is_valid_now(cert)) {
                    state = MD_S_ERROR;
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                                  "md{%s}: error, the certificate itself is valid, however the %d. "
                                  "certificate in the chain is not valid now (clock wrong?).", 
                                  md->name, i);
                    goto out;
                }
            } 

            state = MD_S_COMPLETE;
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md{%s}: is complete", md->name);
        }
    }

out:    
    if (APR_SUCCESS != rv) {
        state = MD_S_ERROR;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "md{%s}: error", md->name);
    }
    
    if (save_changes && md->state == state
        && md->valid_from == valid_from && md->expires == expires) {
        save_changes = 0;
    }
    md->state = state;
    md->valid_from = valid_from;
    md->expires = expires;
    if (save_changes && APR_SUCCESS == rv) {
        return md_save(reg->store, p, MD_SG_DOMAINS, md, 0);
    }
    return rv;
}

apr_status_t md_reg_assess(md_reg_t *reg, md_t *md, int *perrored, int *prenew, apr_pool_t *p)
{
    int renew = 0;
    int errored = 0;
    
    (void)reg;
    switch (md->state) {
        case MD_S_UNKNOWN:
            md_log_perror( MD_LOG_MARK, MD_LOG_ERR, 0, p, "md(%s): in unknown state.", md->name);
            break;
        case MD_S_ERROR:
            md_log_perror( MD_LOG_MARK, MD_LOG_ERR, 0, p,  
                         "md(%s): in error state, unable to drive forward. If unable to "
                         " detect the cause, you may remove the staging or even domain "
                         " sub-directory for this MD and start all over.", md->name);
            errored = 1;
            break;
        case MD_S_COMPLETE:
            if (!md->expires) {
                md_log_perror( MD_LOG_MARK, MD_LOG_WARNING, 0, p,  
                             "md(%s): looks complete, but has unknown expiration date.", md->name);
                errored = 1;
            }
            else if (md->expires <= apr_time_now()) {
                /* Maybe we hibernated in the meantime? */
                md->state = MD_S_EXPIRED;
                renew = 1;
            }
            else {
                renew = md_should_renew(md);
            }
            break;
        case MD_S_INCOMPLETE:
        case MD_S_EXPIRED:
            renew = 1;
            break;
        case MD_S_MISSING:
            break;
    }
    *prenew = renew;
    *perrored = errored;
    return APR_SUCCESS;
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
        state_init(ctx->reg, ptemp, (md_t*)md, 1);
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
        state_init(reg, p, md, 1);
        return md;
    }
    return NULL;
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
        state_init(reg, p, ctx.md, 1);
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
        state_init(reg, p, ctx.md, 1);
    }
    return ctx.md;
}

apr_status_t md_reg_get_cred_files(md_reg_t *reg, const md_t *md, apr_pool_t *p,
                                   const char **pkeyfile, const char **pcertfile)
{
    apr_status_t rv;
    
    rv = md_store_get_fname(pkeyfile, reg->store, MD_SG_DOMAINS, md->name, MD_FN_PRIVKEY, p);
    if (APR_SUCCESS == rv) {
        rv = md_store_get_fname(pcertfile, reg->store, MD_SG_DOMAINS, md->name, MD_FN_PUBCERT, p);
    }
    return rv;
}

/**************************************************************************************************/
/* manipulation */

static apr_status_t p_md_add(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    md_t *md, *mine;
    
    md = va_arg(ap, md_t *);
    mine = md_clone(ptemp, md);
    if (APR_SUCCESS == (rv = check_values(reg, ptemp, md, MD_UPD_ALL))
        && APR_SUCCESS == (rv = state_init(reg, ptemp, mine, 0))
        && APR_SUCCESS == (rv = md_save(reg->store, p, MD_SG_DOMAINS, mine, 1))) {
    }
    return rv;
}

apr_status_t md_reg_add(md_reg_t *reg, md_t *md, apr_pool_t *p)
{
    return md_util_pool_vdo(p_md_add, reg, p, md, NULL);
}

static apr_status_t p_md_update(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    apr_status_t rv = APR_SUCCESS;
    const char *name;
    const md_t *md, *updates;
    int fields;
    md_t *nmd;
    
    name = va_arg(ap, const char *);
    updates = va_arg(ap, const md_t *);
    fields = va_arg(ap, int);
    
    if (NULL == (md = md_reg_get(reg, name, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, APR_ENOENT, ptemp, "md %s", name);
        return APR_ENOENT;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "update md %s", name);
    
    if (APR_SUCCESS != (rv = check_values(reg, ptemp, updates, fields))) {
        return rv;
    }
    
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
    if (MD_UPD_CERT_URL & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update cert url: %s", name);
        nmd->cert_url = updates->cert_url;
    }
    if (MD_UPD_DRIVE_MODE & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update drive-mode: %s", name);
        nmd->drive_mode = updates->drive_mode;
    }
    if (MD_UPD_RENEW_WINDOW & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update renew-window: %s", name);
        nmd->renew_norm = updates->renew_norm;
        nmd->renew_window = updates->renew_window;
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
    
    if (fields && APR_SUCCESS == (rv = md_save(reg->store, p, MD_SG_DOMAINS, nmd, 0))) {
        rv = state_init(reg, ptemp, nmd, 0);
    }
    return rv;
}

apr_status_t md_reg_update(md_reg_t *reg, apr_pool_t *p, 
                           const char *name, const md_t *md, int fields)
{
    return md_util_pool_vdo(p_md_update, reg, p, name, md, fields, NULL);
}

/**************************************************************************************************/
/* certificate related */

static int ok_or_noent(apr_status_t rv) 
{
    return (APR_SUCCESS == rv || APR_ENOENT == rv);
}

static apr_status_t creds_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    md_pkey_t *privkey;
    apr_array_header_t *pubcert;
    md_creds_t *creds, **pcreds;
    const md_t *md;
    md_cert_state_t cert_state;
    md_store_group_t group;
    apr_status_t rv;
    
    pcreds = va_arg(ap, md_creds_t **);
    group = (md_store_group_t)va_arg(ap, int);
    md = va_arg(ap, const md_t *);
    
    if (ok_or_noent(rv = md_pkey_load(reg->store, group, md->name, &privkey, p))
        && ok_or_noent(rv = md_pubcert_load(reg->store, group, md->name, &pubcert, p))) {
        rv = APR_SUCCESS;
            
        creds = apr_pcalloc(p, sizeof(*creds));
        creds->privkey = privkey;
        if (pubcert && pubcert->nelts > 0) {
            creds->pubcert = pubcert;
            creds->cert = APR_ARRAY_IDX(pubcert, 0, md_cert_t *);
        }
        if (creds->cert) {
            switch ((cert_state = md_cert_state_get(creds->cert))) {
                case MD_CERT_VALID:
                    creds->expired = 0;
                    break;
                case MD_CERT_EXPIRED:
                    creds->expired = 1;
                    break;
                default:
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, ptemp, 
                                  "md %s has unexpected cert state: %d", md->name, cert_state);
                    rv = APR_ENOTIMPL;
                    break;
            }
        }
    }
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

apr_status_t md_reg_creds_get(const md_creds_t **pcreds, md_reg_t *reg, 
                              md_store_group_t group, const md_t *md, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    md_creds_t *creds;
    
    rv = md_util_pool_vdo(creds_load, reg, p, &creds, group, md, NULL);
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

/**************************************************************************************************/
/* synching */

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *conf_mds;
    apr_array_header_t *store_mds;
} sync_ctx;

static int find_changes(void *baton, md_store_t *store, md_t *md, apr_pool_t *ptemp)
{
    sync_ctx *ctx = baton;

    (void)store;
    (void)ptemp;
    APR_ARRAY_PUSH(ctx->store_mds, const md_t*) = md_clone(ctx->p, md);
    return 1;
}

apr_status_t md_reg_set_props(md_reg_t *reg, apr_pool_t *p, int can_http, int can_https)
{
    if (reg->can_http != can_http || reg->can_https != can_https) {
        md_json_t *json;
        
        reg->can_http = can_http;
        reg->can_https = can_https;
        
        json = md_json_create(p);
        md_json_setb(can_http, json, MD_KEY_PROTO, MD_KEY_HTTP, NULL);
        md_json_setb(can_https, json, MD_KEY_PROTO, MD_KEY_HTTPS, NULL);
        
        return md_store_save(reg->store, p, MD_SG_NONE, NULL, MD_FN_HTTPD_JSON, MD_SV_JSON, json, 0);
    }
    return APR_SUCCESS;
}
 
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
    md_store_t *store = reg->store;
    apr_status_t rv;

    ctx.p = ptemp;
    ctx.conf_mds = master_mds;
    ctx.store_mds = apr_array_make(ptemp, 100, sizeof(md_t *));
    
    rv = md_store_md_iter(find_changes, &ctx, store, ptemp, MD_SG_DOMAINS, "*");
    if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                  "sync: found %d mds in store", ctx.store_mds->nelts);
    if (APR_SUCCESS == rv) {
        int i, fields;
        md_t *md, *config_md, *smd, *omd;
        const char *common;
        
        for (i = 0; i < ctx.conf_mds->nelts; ++i) {
            md = APR_ARRAY_IDX(ctx.conf_mds, i, md_t *);
            
            /* find the store md that is closest match for the configured md */
            smd = md_find_closest_match(ctx.store_mds, md);
            if (smd) {
                fields = 0;
                
                /* Once stored, we keep the name */
                if (strcmp(md->name, smd->name)) {
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
                    config_md = md_get_by_name(ctx.conf_mds, omd->name);
                    if (config_md && md_contains(config_md, common, 0)) {
                        /* domain used in two configured mds, not allowed */
                        rv = APR_EINVAL;
                        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                                      "domain %s used in md %s and %s", 
                                      common, md->name, omd->name);
                    }
                    else if (config_md) {
                        /* domain stored in omd, but no longer has the offending domain,
                           remove it from the store md. */
                        omd->domains = md_array_str_remove(ptemp, omd->domains, common, 0);
                        rv = md_reg_update(reg, ptemp, omd->name, omd, MD_UPD_DOMAINS);
                    }
                    else {
                        /* domain in a store md that is no longer configured, warn about it.
                         * Remove the domain here, so we can progress, but never save it. */
                        omd->domains = md_array_str_remove(ptemp, omd->domains, common, 0);
                        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                                      "domain %s, configured in md %s, is part of the stored md %s."
                                      " That md however is no longer mentioned in the config. "
                                      "If you longer want it, remove the md from the store.", 
                                      common, md->name, omd->name);
                    }
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
                if (MD_VAL_UPDATE(md, smd, drive_mode)) {
                    smd->drive_mode = md->drive_mode;
                    fields |= MD_UPD_DRIVE_MODE;
                }
                if (!apr_is_empty_array(md->contacts) 
                    && !md_array_str_eq(md->contacts, smd->contacts, 0)) {
                    smd->contacts = md->contacts;
                    fields |= MD_UPD_CONTACTS;
                }
                if (MD_VAL_UPDATE(md, smd, renew_window) 
                    || MD_VAL_UPDATE(md, smd, renew_norm)) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                                  "%s: update renew norm=%ld, window=%ld", 
                                  smd->name, (long)md->renew_norm, (long)md->renew_window);
                    smd->renew_norm = md->renew_norm;
                    smd->renew_window = md->renew_window;
                    fields |= MD_UPD_RENEW_WINDOW;
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
                
                if (fields) {
                    rv = md_reg_update(reg, ptemp, smd->name, smd, fields);
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md %s updated", smd->name);
                }
            }
            else {
                /* new managed domain */
                rv = md_reg_add(reg, md, ptemp);
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "new md %s added", md->name);
            }
        }
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "loading mds");
    }
    
    return rv;
}


/**************************************************************************************************/
/* driving */

static apr_status_t init_proto_driver(md_proto_driver_t *driver, const md_proto_t *proto, 
                                      md_reg_t *reg, const md_t *md, 
                                      const char *challenge, int reset, apr_pool_t *p) 
{
    apr_status_t rv = APR_SUCCESS;

    /* If this registry instance was not synched before (and obtained server
     * properties that way), read them from the store.
     */
    driver->proto = proto;
    driver->p = p;
    driver->challenge = challenge;
    driver->can_http = reg->can_http;
    driver->can_https = reg->can_https;
    driver->reg = reg;
    driver->store = md_reg_store_get(reg);
    driver->proxy_url = reg->proxy_url;
    driver->md = md;
    driver->reset = reset;

    return rv;
}

static apr_status_t run_stage(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    const md_proto_t *proto;
    const md_t *md;
    int reset;
    md_proto_driver_t *driver;
    const char *challenge;
    apr_time_t *pvalid_from;
    apr_status_t rv;
    
    (void)p;
    proto = va_arg(ap, const md_proto_t *);
    md = va_arg(ap, const md_t *);
    challenge = va_arg(ap, const char *);
    reset = va_arg(ap, int); 
    pvalid_from = va_arg(ap, apr_time_t*);
    
    driver = apr_pcalloc(ptemp, sizeof(*driver));
    rv = init_proto_driver(driver, proto, reg, md, challenge, reset, ptemp);
    if (APR_SUCCESS == rv && 
        APR_SUCCESS == (rv = proto->init(driver))) {
        
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "%s: run staging", md->name);
        rv = proto->stage(driver);

        if (APR_SUCCESS == rv && pvalid_from) {
            *pvalid_from = driver->stage_valid_from;
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "%s: staging done", md->name);
    return rv;
}

apr_status_t md_reg_stage(md_reg_t *reg, const md_t *md, const char *challenge, 
                          int reset, apr_time_t *pvalid_from, apr_pool_t *p)
{
    const md_proto_t *proto;
    
    if (!md->ca_proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "md %s has no CA protocol", md->name);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_SUCCESS;
    }
    
    proto = apr_hash_get(reg->protos, md->ca_proto, (apr_ssize_t)strlen(md->ca_proto));
    if (!proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, 
                      "md %s has unknown CA protocol: %s", md->name, md->ca_proto);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_EINVAL;
    }
    
    return md_util_pool_vdo(run_stage, reg, p, proto, md, challenge, reset, pvalid_from, NULL);
}

static apr_status_t run_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    const char *name;
    const md_proto_t *proto;
    const md_t *md, *nmd;
    md_proto_driver_t *driver;
    apr_status_t rv;
    
    name = va_arg(ap, const char *);
    
    if (APR_STATUS_IS_ENOENT(rv = md_load(reg->store, MD_SG_STAGING, name, NULL, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, ptemp, "%s: nothing staged", name);
        return APR_ENOENT;
    }
    
    md = md_reg_get(reg, name, p);
    if (!md) {
        return APR_ENOENT;
    }
    
    if (!md->ca_proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "md %s has no CA protocol", name);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_EINVAL;
    }
    
    proto = apr_hash_get(reg->protos, md->ca_proto, (apr_ssize_t)strlen(md->ca_proto));
    if (!proto) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, 
                      "md %s has unknown CA protocol: %s", md->name, md->ca_proto);
        ((md_t *)md)->state = MD_S_ERROR;
        return APR_EINVAL;
    }
    
    driver = apr_pcalloc(ptemp, sizeof(*driver));
    init_proto_driver(driver, proto, reg, md, NULL, 0, ptemp);

    if (APR_SUCCESS == (rv = proto->init(driver))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "%s: run load", md->name);
        
        if (APR_SUCCESS == (rv = proto->preload(driver, MD_SG_TMP))) {
            /* swap */
            rv = md_store_move(reg->store, p, MD_SG_TMP, MD_SG_DOMAINS, md->name, 1);
            if (APR_SUCCESS == rv) {
                /* load again */
                nmd = md_reg_get(reg, md->name, p);
                if (!nmd) {
                    rv = APR_ENOENT;
                    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "loading md after staging");
                }
                else if (nmd->state != MD_S_COMPLETE) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                                  "md has state %d after load", nmd->state);
                }
                
                md_store_purge(reg->store, p, MD_SG_STAGING, md->name);
                md_store_purge(reg->store, p, MD_SG_CHALLENGES, md->name);
            }
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "%s: load done", md->name);
    return rv;
}

apr_status_t md_reg_load(md_reg_t *reg, const char *name, apr_pool_t *p)
{
    return md_util_pool_vdo(run_load, reg, p, name, NULL);
}

