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
#include "md_event.h"
#include "md_log.h"
#include "md_json.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_ocsp.h"
#include "md_store.h"
#include "md_status.h"
#include "md_tailscale.h"
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
    const char *ca_file;
    int domains_frozen;
    md_timeslice_t *renew_window;
    md_timeslice_t *warn_window;
    md_job_notify_cb *notify;
    void *notify_ctx;
    apr_time_t min_delay;
    int retry_failover;
    int use_store_locks;
    apr_time_t lock_wait_timeout;
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
                           const char *proxy_url, const char *ca_file,
                           apr_time_t min_delay, int retry_failover,
                           int use_store_locks, apr_time_t lock_wait_timeout)
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
    reg->ca_file = (ca_file && apr_strnatcasecmp("none", ca_file))?
                    apr_pstrdup(p, ca_file) : NULL;
    reg->min_delay = min_delay;
    reg->retry_failover = retry_failover;
    reg->use_store_locks = use_store_locks;
    reg->lock_wait_timeout = lock_wait_timeout;

    md_timeslice_create(&reg->renew_window, p, MD_TIME_LIFE_NORM, MD_TIME_RENEW_WINDOW_DEF); 
    md_timeslice_create(&reg->warn_window, p, MD_TIME_LIFE_NORM, MD_TIME_WARN_WINDOW_DEF); 
    
    if (APR_SUCCESS == (rv = md_acme_protos_add(reg->protos, p))
        && APR_SUCCESS == (rv = md_tailscale_protos_add(reg->protos, p))) {
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
    
    if ((MD_UPD_CA_URL & fields) && md->ca_urls) { /* setting to empty is ok */
        int i;
        const char *url;
        for (i = 0; i < md->ca_urls->nelts; ++i) {
            url = APR_ARRAY_IDX(md->ca_urls, i, const char*);
            rv = md_util_abs_uri_check(p, url, &err);
            if (err) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p,
                              "CA url for %s invalid (%s): %s", md->name, err, url);
                return APR_EINVAL;
            }
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
    md_state_t state = MD_S_COMPLETE;
    const char *state_descr = NULL;
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    const md_pkey_spec_t *spec;
    apr_status_t rv = APR_SUCCESS;
    int i;

    if (md->renew_window == NULL) md->renew_window = reg->renew_window;
    if (md->warn_window == NULL) md->warn_window = reg->warn_window;

    if (md->domains && md->domains->pool != p) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p,
                      "md{%s}: state_init called with foreign pool", md->name);
    }

    for (i = 0; i < md_cert_count(md); ++i) {
        spec = md_pkeys_spec_get(md->pks, i);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, p,
                      "md{%s}: check cert %s", md->name, md_pkey_spec_name(spec));
        rv = md_reg_get_pubcert(&pub, reg, md, i, p);
        if (APR_SUCCESS == rv) {
            cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
            if (!md_is_covered_by_alt_names(md, pub->alt_names)) {
                state = MD_S_INCOMPLETE;
                state_descr = apr_psprintf(p, "certificate(%s) does not cover all domains.",
                                           md_pkey_spec_name(spec));
                goto cleanup;
            }
            if (!md->must_staple != !md_cert_must_staple(cert)) {
                state = MD_S_INCOMPLETE;
                state_descr = apr_psprintf(p, "'must-staple' is%s requested, but "
                              "certificate(%s) has it%s enabled.",
                              md->must_staple? "" : " not",
                              md_pkey_spec_name(spec),
                              !md->must_staple? "" : " not");
                goto cleanup;
            }
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "md{%s}: certificate(%d) is ok",
                          md->name, i);
        }
        else if (APR_STATUS_IS_ENOENT(rv)) {
            state = MD_S_INCOMPLETE;
            state_descr = apr_psprintf(p, "certificate(%s) is missing",
                                       md_pkey_spec_name(spec));
            rv = APR_SUCCESS;
            goto cleanup;
        }
        else {
            state = MD_S_ERROR;
            state_descr = "error initializing";
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "md{%s}: error", md->name);
            goto cleanup;
        }
    }

cleanup:
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, p, "md{%s}: state=%d, %s",
                  md->name, state, state_descr);
    md->state = state;
    md->state_descr = state_descr;
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
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "md[%s]: update store", name);
    
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
        nmd->ca_urls = (updates->ca_urls?
                        apr_array_copy(p, updates->ca_urls) : NULL);
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
        *nmd->renew_window = *updates->renew_window;
    }
    if (MD_UPD_WARN_WINDOW & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update warn-window: %s", name);
        *nmd->warn_window = *updates->warn_window;
    }
    if (MD_UPD_CA_CHALLENGES & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update ca challenges: %s", name);
        nmd->ca_challenges = (updates->ca_challenges? 
                              apr_array_copy(p, updates->ca_challenges) : NULL);
    }
    if (MD_UPD_PKEY_SPEC & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update pkey spec: %s", name);
        nmd->pks = md_pkeys_spec_clone(p, updates->pks);
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
    if (MD_UPD_STAPLING & fields) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "update stapling: %s", name);
        nmd->stapling = updates->stapling;
    }
    
    if (fields && APR_SUCCESS == (rv = md_save(reg->store, p, MD_SG_DOMAINS, nmd, 0))) {
        rv = state_init(reg, ptemp, nmd);
    }
    return rv;
}

apr_status_t md_reg_update(md_reg_t *reg, apr_pool_t *p, 
                           const char *name, const md_t *md, int fields, 
                           int do_checks)
{
    return md_util_pool_vdo(p_md_update, reg, p, name, md, fields, do_checks, NULL);
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
    int index;
    const md_cert_t *cert;
    md_cert_state_t cert_state;
    md_store_group_t group;
    apr_status_t rv;
    
    ppubcert = va_arg(ap, md_pubcert_t **);
    group = (md_store_group_t)va_arg(ap, int);
    md = va_arg(ap, const md_t *);
    index = va_arg(ap, int);
    
    if (md->cert_files && md->cert_files->nelts) {
        rv = md_chain_fload(&certs, p, APR_ARRAY_IDX(md->cert_files, index, const char *));
    }
    else {
        md_pkey_spec_t *spec = md_pkeys_spec_get(md->pks, index);;
        rv = md_pubcert_load(reg->store, group, md->name, spec, &certs, p);
    }
    if (APR_SUCCESS != rv) goto leave;
    if (certs->nelts == 0) {
        rv = APR_ENOENT;
        goto leave;
    }

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
                                const md_t *md, int i, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    const md_pubcert_t *pubcert;
    const char *name;

    name = apr_psprintf(p, "%s[%d]", md->name, i);
    pubcert = apr_hash_get(reg->certs, name, (apr_ssize_t)strlen(name));
    if (!pubcert && !reg->domains_frozen) {
        rv = md_util_pool_vdo(pubcert_load, reg, reg->p, &pubcert, MD_SG_DOMAINS, md, i, NULL);
        if (APR_STATUS_IS_ENOENT(rv)) {
            /* We cache it missing with an empty record */
            pubcert = apr_pcalloc(reg->p, sizeof(*pubcert));
        }
        else if (APR_SUCCESS != rv) goto leave;
        if (p != reg->p) name = apr_pstrdup(reg->p, name);
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
                                   const md_t *md, md_pkey_spec_t *spec, apr_pool_t *p)
{
    apr_status_t rv;
    
    rv = md_store_get_fname(pkeyfile, reg->store, group, md->name, md_pkey_filename(spec, p), p);
    if (APR_SUCCESS != rv) return rv;
    if (!md_file_exists(*pkeyfile, p)) return APR_ENOENT;
    rv = md_store_get_fname(pcertfile, reg->store, group, md->name, md_chain_filename(spec, p), p);
    if (APR_SUCCESS != rv) return rv;
    if (!md_file_exists(*pcertfile, p)) return APR_ENOENT;
    return APR_SUCCESS;
}

apr_time_t md_reg_valid_until(md_reg_t *reg, const md_t *md, apr_pool_t *p)
{
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    int i;
    apr_time_t t, valid_until = 0;
    apr_status_t rv;
    
    for (i = 0; i < md_cert_count(md); ++i) {
        rv = md_reg_get_pubcert(&pub, reg, md, i, p);
        if (APR_SUCCESS == rv) {
            cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
            t = md_cert_get_not_after(cert);
            if (valid_until == 0 || t < valid_until) {
                valid_until = t;
            }
        }
    }
    return valid_until;
}

apr_time_t md_reg_renew_at(md_reg_t *reg, const md_t *md, apr_pool_t *p)
{
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    md_timeperiod_t certlife, renewal;
    int i;
    apr_time_t renew_at = 0;
    apr_status_t rv;
    
    if (md->state == MD_S_INCOMPLETE) return apr_time_now();
    for (i = 0; i < md_cert_count(md); ++i) {
        rv = md_reg_get_pubcert(&pub, reg, md, i, p);
        if (APR_STATUS_IS_ENOENT(rv)) return apr_time_now();
        if (APR_SUCCESS == rv) {
            cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
            certlife.start = md_cert_get_not_before(cert);
            certlife.end = md_cert_get_not_after(cert);

            renewal = md_timeperiod_slice_before_end(&certlife, md->renew_window);
            if (md_log_is_level(p, MD_LOG_TRACE1)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, 
                              "md[%s]: certificate(%d) valid[%s] renewal[%s]", 
                              md->name, i,  
                              md_timeperiod_print(p, &certlife),
                              md_timeperiod_print(p, &renewal));
            }
            
            if (renew_at == 0 || renewal.start < renew_at) {
                renew_at = renewal.start; 
            }
        }
    }
    return renew_at;
}

int md_reg_should_renew(md_reg_t *reg, const md_t *md, apr_pool_t *p) 
{
    apr_time_t renew_at;
    
    renew_at = md_reg_renew_at(reg, md, p);
    return renew_at && (renew_at <= apr_time_now());
}

int md_reg_should_warn(md_reg_t *reg, const md_t *md, apr_pool_t *p)
{
    const md_pubcert_t *pub;
    const md_cert_t *cert;
    md_timeperiod_t certlife, warn;
    int i;
    apr_status_t rv;
    
    if (md->state == MD_S_INCOMPLETE) return 0;
    for (i = 0; i < md_cert_count(md); ++i) {
        rv = md_reg_get_pubcert(&pub, reg, md, i, p);
        if (APR_STATUS_IS_ENOENT(rv)) return 0;
        if (APR_SUCCESS == rv) {
            cert = APR_ARRAY_IDX(pub->certs, 0, const md_cert_t*);
            certlife.start = md_cert_get_not_before(cert);
            certlife.end = md_cert_get_not_after(cert);
            
            warn = md_timeperiod_slice_before_end(&certlife, md->warn_window);
            if (md_log_is_level(p, MD_LOG_TRACE1)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, 
                              "md[%s]: certificate(%d) life[%s] warn[%s]", 
                              md->name, i,  
                              md_timeperiod_print(p, &certlife),
                              md_timeperiod_print(p, &warn));
            }
            if (md_timeperiod_has_started(&warn, apr_time_now())) {
                return 1;
            }
        }
    }
    return 0;
}

/**************************************************************************************************/
/* syncing */

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

static md_t *find_closest_match(apr_array_header_t *mds, const md_t *md)
{
    md_t *candidate, *m;
    apr_size_t cand_n, n;
    int i;
    
    candidate = md_get_by_name(mds, md->name);
    if (!candidate) {
        /* try to find an instance that contains all domain names from md */ 
        for (i = 0; i < mds->nelts; ++i) {
            m = APR_ARRAY_IDX(mds, i, md_t *);
            if (md_contains_domains(m, md)) {
                return m;
            }
        }
        /* no matching name and no md in the list has all domains.
         * We consider that managed domain as closest match that contains at least one
         * domain name from md, ONLY if there is no other one that also has.
         */
        cand_n = 0;
        for (i = 0; i < mds->nelts; ++i) {
            m = APR_ARRAY_IDX(mds, i, md_t *);
            n = md_common_name_count(md, m);
            if (n > cand_n) {
                candidate = m;
                cand_n = n;
            }
        }
    }
    return candidate;
}

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *master_mds;
    apr_array_header_t *store_names;
    apr_array_header_t *maybe_new_mds;
    apr_array_header_t *new_mds;
    apr_array_header_t *unassigned_mds;
} sync_ctx_v2;

static int iter_add_name(void *baton, const char *dir, const char *name, 
                         md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
{
    sync_ctx_v2 *ctx = baton;
    
    (void)dir;
    (void)value;
    (void)ptemp;
    (void)vtype;
    APR_ARRAY_PUSH(ctx->store_names, const char*) = apr_pstrdup(ctx->p, name);
    return APR_SUCCESS;
}

/* A better scaling version:
 *  1. The consistency of the MDs in 'master_mds' has already been verified. E.g.
 *     that no domain lists overlap etc.
 *  2. All MD storage that exists will be overwritten by the settings we have.
 *     And "exists" meaning that "store/MD_SG_DOMAINS/name" exists.
 *  3. For MDs that have no directory in "store/MD_SG_DOMAINS", we load all MDs
 *     outside the list of known names from MD_SG_DOMAINS. In this list, we
 *     look for the MD with the most domain overlap. 
 *      - if we find it, we assume this is a rename and move the old MD to the new name.
 *      - if not, MD is completely new.
 *  4. Any MD in store that does not match the "master_mds" will just be left as is. 
 */
apr_status_t md_reg_sync_start(md_reg_t *reg, apr_array_header_t *master_mds, apr_pool_t *p) 
{
    sync_ctx_v2 ctx;
    apr_status_t rv;
    md_t *md, *oldmd;
    const char *name;
    int i, idx;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "sync MDs, start");
     
    ctx.p = p;
    ctx.master_mds = master_mds;
    ctx.store_names = apr_array_make(p, master_mds->nelts + 100, sizeof(const char*));
    ctx.maybe_new_mds = apr_array_make(p, master_mds->nelts, sizeof(md_t*));
    ctx.new_mds = apr_array_make(p, master_mds->nelts, sizeof(md_t*));
    ctx.unassigned_mds = apr_array_make(p, master_mds->nelts, sizeof(md_t*));
    
    rv = md_store_iter_names(iter_add_name, &ctx, reg->store, p, MD_SG_DOMAINS, "*");
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "listing existing store MD names"); 
        goto leave;
    }
    
    /* Get all MDs that are not already present in store */
    for (i = 0; i < ctx.master_mds->nelts; ++i) {
        md = APR_ARRAY_IDX(ctx.master_mds, i, md_t*);
        idx = md_array_str_index(ctx.store_names, md->name, 0, 1);
        if (idx < 0) {
            APR_ARRAY_PUSH(ctx.maybe_new_mds, md_t*) = md;
            md_array_remove_at(ctx.store_names, idx);
        }
    }
    
    if (ctx.maybe_new_mds->nelts == 0) goto leave; /* none new */
    if (ctx.store_names->nelts == 0) goto leave;   /* all new */
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                  "sync MDs, %d potentially new MDs detected, looking for renames among "
                  "the %d unassigned store domains", (int)ctx.maybe_new_mds->nelts,
                  (int)ctx.store_names->nelts);
    for (i = 0; i < ctx.store_names->nelts; ++i) {
        name = APR_ARRAY_IDX(ctx.store_names, i, const char*);
        if (APR_SUCCESS == md_load(reg->store, MD_SG_DOMAINS, name, &md, p)) {
            APR_ARRAY_PUSH(ctx.unassigned_mds, md_t*) = md;
        } 
    }
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                  "sync MDs, %d MDs maybe new, checking store", (int)ctx.maybe_new_mds->nelts);
    for (i = 0; i < ctx.maybe_new_mds->nelts; ++i) {
        md = APR_ARRAY_IDX(ctx.maybe_new_mds, i, md_t*);
        oldmd = find_closest_match(ctx.unassigned_mds, md);
        if (oldmd) {
            /* found the rename, move the domains and possible staging directory */
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                          "sync MDs, found MD %s under previous name %s", md->name, oldmd->name);
            rv = md_store_rename(reg->store, p, MD_SG_DOMAINS, oldmd->name, md->name);
            if (APR_SUCCESS != rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, 
                              "sync MDs, renaming MD %s to %s failed", oldmd->name, md->name);
                /* ignore it? */
            }
            md_store_rename(reg->store, p, MD_SG_STAGING, oldmd->name, md->name);
            md_array_remove(ctx.unassigned_mds, oldmd);
        }
        else {
            APR_ARRAY_PUSH(ctx.new_mds, md_t*) = md;
        }
    }

leave:
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                  "sync MDs, %d existing, %d moved, %d new.", 
                  (int)ctx.master_mds->nelts - ctx.maybe_new_mds->nelts,
                  (int)ctx.maybe_new_mds->nelts - ctx.new_mds->nelts,
                  (int)ctx.new_mds->nelts);
    return rv;
}

/** 
 * Finish syncing an MD with the store. 
 * 1. if there are changed properties (or if the MD is new), save it.
 * 2. read any existing certificate and init the state of the memory MD
 */
apr_status_t md_reg_sync_finish(md_reg_t *reg, md_t *md, apr_pool_t *p, apr_pool_t *ptemp)
{
    md_t *old;
    apr_status_t rv;
    int changed = 1;
    md_proto_t *proto;
    
    if (!md->ca_proto) {
        md->ca_proto = MD_PROTO_ACME;
    }
    proto = apr_hash_get(reg->protos, md->ca_proto, (apr_ssize_t)strlen(md->ca_proto));
    if (!proto) {
        rv = APR_ENOTIMPL;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp,
                      "[%s] uses unknown CA protocol '%s'",
                      md->name, md->ca_proto);
        goto leave;
    }
    rv = proto->complete_md(md, p);
    if (APR_SUCCESS != rv) goto leave;

    rv = state_init(reg, p, md);
    if (APR_SUCCESS != rv) goto leave;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "loading md %s", md->name);
    if (APR_SUCCESS == md_load(reg->store, MD_SG_DOMAINS, md->name, &old, ptemp)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "loaded md %s", md->name);
        /* Some parts are kept from old, lacking new values */
        if ((!md->contacts || apr_is_empty_array(md->contacts)) && old->contacts) {
            md->contacts = md_array_str_clone(p, old->contacts);
        } 
        if (md->ca_challenges && old->ca_challenges) {
            if (!md_array_str_eq(md->ca_challenges, old->ca_challenges, 0)) {
                md->ca_challenges = md_array_str_compact(p, md->ca_challenges, 0);
            }
        }
        if (!md->ca_effective && old->ca_effective) {
            md->ca_effective = apr_pstrdup(p, old->ca_effective);
        }
        if (!md->ca_account && old->ca_account) {
            md->ca_account = apr_pstrdup(p, old->ca_account);
        }
        
        /* if everything remains the same, spare the write back */
        if (!MD_VAL_UPDATE(md, old, state)
            && md_array_str_eq(md->ca_urls, old->ca_urls, 0)
            && !MD_SVAL_UPDATE(md, old, ca_proto)
            && !MD_SVAL_UPDATE(md, old, ca_agreement)
            && !MD_VAL_UPDATE(md, old, transitive)
            && md_equal_domains(md, old, 1)
            && !MD_VAL_UPDATE(md, old, renew_mode)
            && md_timeslice_eq(md->renew_window, old->renew_window)
            && md_timeslice_eq(md->warn_window, old->warn_window)
            && md_pkeys_spec_eq(md->pks, old->pks)
            && !MD_VAL_UPDATE(md, old, require_https)
            && !MD_VAL_UPDATE(md, old, must_staple)
            && md_array_str_eq(md->acme_tls_1_domains, old->acme_tls_1_domains, 0)
            && !MD_VAL_UPDATE(md, old, stapling)
            && md_array_str_eq(md->contacts, old->contacts, 0)
            && md_array_str_eq(md->cert_files, old->cert_files, 0)
            && md_array_str_eq(md->pkey_files, old->pkey_files, 0)
            && md_array_str_eq(md->ca_challenges, old->ca_challenges, 0)) {
            changed = 0;
        }
    }
    if (changed) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "saving md %s", md->name);
        rv = md_save(reg->store, ptemp, MD_SG_DOMAINS, md, 0);
    }
leave:
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "sync MDs, finish done");
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
    const char *s;
    int preload;
    
    (void)p;
    va_start(ap, p);
    pdriver = va_arg(ap, md_proto_driver_t **);
    md = va_arg(ap, const md_t *);
    preload = va_arg(ap, int);
    env = va_arg(ap, apr_table_t *);
    result = va_arg(ap, md_result_t *); 
    va_end(ap);
    
    *pdriver = driver = apr_pcalloc(p, sizeof(*driver));

    driver->p = p;
    driver->env = env? apr_table_copy(p, env) : apr_table_make(p, 10);
    driver->reg = reg;
    driver->store = md_reg_store_get(reg);
    driver->proxy_url = reg->proxy_url;
    driver->ca_file = reg->ca_file;
    driver->md = md;
    driver->can_http = reg->can_http;
    driver->can_https = reg->can_https;
    
    s = apr_table_get(driver->env, MD_KEY_ACTIVATION_DELAY);
    if (!s || APR_SUCCESS != md_duration_parse(&driver->activation_delay, s, "d")) {
        driver->activation_delay = 0;
    }

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
    
    if (preload) {
        result->status = driver->proto->init_preload(driver, result);
    }
    else {
        result->status = driver->proto->init(driver, result);
    }

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

    return run_init(baton, ptemp, &driver, md, 0, env, result, NULL);
}

apr_status_t md_reg_test_init(md_reg_t *reg, const md_t *md, struct apr_table_t *env, 
                              md_result_t *result, apr_pool_t *p)
{
    return md_util_pool_vdo(run_test_init, reg, p, md, env, result, NULL);
}

static apr_status_t run_renew(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_reg_t *reg = baton;
    const md_t *md;
    int reset, attempt;
    md_proto_driver_t *driver;
    apr_table_t *env;
    apr_status_t rv;
    md_result_t *result;
    
    (void)p;
    md = va_arg(ap, const md_t *);
    env = va_arg(ap, apr_table_t *);
    reset = va_arg(ap, int); 
    attempt = va_arg(ap, int);
    result = va_arg(ap, md_result_t *);

    rv = run_init(reg, ptemp, &driver, md, 0, env, result, NULL);
    if (APR_SUCCESS == rv) { 
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "%s: run staging", md->name);
        driver->reset = reset;
        driver->attempt = attempt;
        driver->retry_failover = reg->retry_failover;
        rv = driver->proto->renew(driver, result);
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "%s: staging done", md->name);
    return rv;
}

apr_status_t md_reg_renew(md_reg_t *reg, const md_t *md, apr_table_t *env, 
                          int reset, int attempt,
                          md_result_t *result, apr_pool_t *p)
{
    return md_util_pool_vdo(run_renew, reg, p, md, env, reset, attempt, result, NULL);
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
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, ptemp, "%s: nothing staged", md->name);
        goto out;
    }
    
    rv = run_init(baton, ptemp, &driver, md, 1, env, result, NULL);
    if (APR_SUCCESS != rv) goto out;
    
    apr_hash_set(reg->certs, md->name, (apr_ssize_t)strlen(md->name), NULL);
    md_result_activity_setn(result, "preloading staged to tmp");
    rv = driver->proto->preload(driver, MD_SG_TMP, result);
    if (APR_SUCCESS != rv) goto out;

    /* If we had a job saved in STAGING, copy it over too */
    job = md_reg_job_make(reg, md->name, ptemp);
    if (APR_SUCCESS == md_job_load(job)) {
        md_job_set_group(job, MD_SG_TMP);
        md_job_save(job, NULL, ptemp);
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
    md_event_holler("installed", md->name, job, result, ptemp);
    if (job->dirty) md_job_save(job, result, ptemp);
    
out:
    if (!APR_STATUS_IS_ENOENT(rv)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ptemp, "%s: load done", md->name);
    }
    return rv;
}

apr_status_t md_reg_load_staging(md_reg_t *reg, const md_t *md, apr_table_t *env, 
                                 md_result_t *result, apr_pool_t *p)
{
    if (reg->domains_frozen) return APR_EACCES;
    return md_util_pool_vdo(run_load_staging, reg, p, md, env, result, NULL);
}

apr_status_t md_reg_load_stagings(md_reg_t *reg, apr_array_header_t *mds,
                                  apr_table_t *env, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    md_result_t *result;
    int i;

    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, md_t *);
        result = md_result_md_make(p, md->name);
        rv = md_reg_load_staging(reg, md, env, result, p);
        if (APR_SUCCESS == rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, APLOGNO(10068)
                          "%s: staged set activated", md->name);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, APLOGNO(10069)
                          "%s: error loading staged set", md->name);
        }
    }

    return rv;
}

apr_status_t md_reg_lock_global(md_reg_t *reg, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;

    if (reg->use_store_locks) {
        rv = md_store_lock_global(reg->store, p, reg->lock_wait_timeout);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p,
                          "unable to acquire global store lock");
        }
    }
    return rv;
}

void md_reg_unlock_global(md_reg_t *reg, apr_pool_t *p)
{
    if (reg->use_store_locks) {
        md_store_unlock_global(reg->store, p);
    }
}

apr_status_t md_reg_freeze_domains(md_reg_t *reg, apr_array_header_t *mds)
{
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    const md_pubcert_t *pubcert;
    int i, j;
    
    assert(!reg->domains_frozen);
    /* prefill the certs cache for all mds */
    for (i = 0; i < mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mds, i, md_t*);
        for (j = 0; j < md_cert_count(md); ++j) {
            rv = md_reg_get_pubcert(&pubcert, reg, md, i, reg->p);
            if (APR_SUCCESS != rv && !APR_STATUS_IS_ENOENT(rv)) goto leave;
        }
    }
    reg->domains_frozen = 1;
leave:
    return rv;
}

void md_reg_set_renew_window_default(md_reg_t *reg, md_timeslice_t *renew_window)
{
    *reg->renew_window = *renew_window;
}

void md_reg_set_warn_window_default(md_reg_t *reg, md_timeslice_t *warn_window)
{
    *reg->warn_window = *warn_window;
}

md_job_t *md_reg_job_make(md_reg_t *reg, const char *mdomain, apr_pool_t *p)
{
    return md_job_make(p, reg->store, MD_SG_STAGING, mdomain, reg->min_delay);
}

static int get_cert_count(const md_t *md)
{
    if (md->cert_files && md->cert_files->nelts) {
        return md->cert_files->nelts;
    }
    return md_pkeys_spec_count(md->pks);
}

int md_reg_has_revoked_certs(md_reg_t *reg, struct md_ocsp_reg_t *ocsp,
                             const md_t *md, apr_pool_t *p)
{
    const md_pubcert_t *pubcert;
    const md_cert_t *cert;
    md_timeperiod_t ocsp_valid;
    md_ocsp_cert_stat_t cert_stat;
    apr_status_t rv = APR_SUCCESS;
    int i;

    if (!md->stapling || !ocsp)
        return 0;

    for (i = 0; i < get_cert_count(md); ++i) {
        if (APR_SUCCESS != md_reg_get_pubcert(&pubcert, reg, md, i, p))
            continue;
        cert = APR_ARRAY_IDX(pubcert->certs, 0, const md_cert_t*);
        if(!cert)
            continue;
        rv = md_ocsp_get_meta(&cert_stat, &ocsp_valid, ocsp, cert, p, md);
        if (APR_SUCCESS == rv && cert_stat == MD_OCSP_CERT_ST_REVOKED) {
            return 1;
        }
    }
    return 0;
}
