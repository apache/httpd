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
#include <stdio.h>

#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_jws.h"
#include "md_log.h"
#include "md_store.h"
#include "md_util.h"
#include "md_version.h"

#include "md_acme.h"
#include "md_acme_acct.h"

static apr_status_t acct_make(md_acme_acct_t **pacct, apr_pool_t *p, 
                              const char *ca_url, apr_array_header_t *contacts)
{
    md_acme_acct_t *acct;
    
    acct = apr_pcalloc(p, sizeof(*acct));

    acct->ca_url = ca_url;
    if (!contacts || apr_is_empty_array(contacts)) {
        acct->contacts = apr_array_make(p, 5, sizeof(const char *));
    }
    else {
        acct->contacts = apr_array_copy(p, contacts);
    }
    
    *pacct = acct;
    return APR_SUCCESS;
}


static const char *mk_acct_id(apr_pool_t *p, md_acme_t *acme, int i)
{
    return apr_psprintf(p, "ACME-%s-%04d", acme->sname, i);
}

static const char *mk_acct_pattern(apr_pool_t *p, md_acme_t *acme)
{
    return apr_psprintf(p, "ACME-%s-*", acme->sname);
}
 
/**************************************************************************************************/
/* json load/save */

static md_acme_acct_st acct_st_from_str(const char *s) 
{
    if (s) {
        if (!strcmp("valid", s)) {
            return MD_ACME_ACCT_ST_VALID;
        }
        else if (!strcmp("deactivated", s)) {
            return MD_ACME_ACCT_ST_DEACTIVATED;
        }
        else if (!strcmp("revoked", s)) {
            return MD_ACME_ACCT_ST_REVOKED;
        }
    }
    return MD_ACME_ACCT_ST_UNKNOWN;
}

md_json_t *md_acme_acct_to_json(md_acme_acct_t *acct, apr_pool_t *p)
{
    md_json_t *jacct;
    const char *s;

    assert(acct);
    jacct = md_json_create(p);
    switch (acct->status) {
        case MD_ACME_ACCT_ST_VALID:
            s = "valid";
            break;
        case MD_ACME_ACCT_ST_DEACTIVATED:
            s = "deactivated";
            break;
        case MD_ACME_ACCT_ST_REVOKED:
            s = "revoked";
            break;
        default:
            s = NULL;
            break;
    }    
    if (s) {
        md_json_sets(s, jacct, MD_KEY_STATUS, NULL);
    }
    md_json_sets(acct->url, jacct, MD_KEY_URL, NULL);
    md_json_sets(acct->ca_url, jacct, MD_KEY_CA_URL, NULL);
    md_json_setsa(acct->contacts, jacct, MD_KEY_CONTACT, NULL);
    md_json_setj(acct->registration, jacct, MD_KEY_REGISTRATION, NULL);
    if (acct->agreement) {
        md_json_sets(acct->agreement, jacct, MD_KEY_AGREEMENT, NULL);
    }
    if (acct->orders) {
        md_json_sets(acct->orders, jacct, MD_KEY_ORDERS, NULL);
    }
    
    return jacct;
}

apr_status_t md_acme_acct_from_json(md_acme_acct_t **pacct, md_json_t *json, apr_pool_t *p)
{
    apr_status_t rv = APR_EINVAL;
    md_acme_acct_t *acct;
    md_acme_acct_st status = MD_ACME_ACCT_ST_UNKNOWN;
    const char *ca_url, *url;
    apr_array_header_t *contacts;
    
    if (md_json_has_key(json, MD_KEY_STATUS, NULL)) {
        status = acct_st_from_str(md_json_gets(json, MD_KEY_STATUS, NULL));
    }
    else {
        /* old accounts only had disabled boolean field */
        status = md_json_getb(json, MD_KEY_DISABLED, NULL)? 
            MD_ACME_ACCT_ST_DEACTIVATED : MD_ACME_ACCT_ST_VALID;
    }
    
    url = md_json_gets(json, MD_KEY_URL, NULL);
    if (!url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no url");
        goto out;
    }

    ca_url = md_json_gets(json, MD_KEY_CA_URL, NULL);
    if (!ca_url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "account has no CA url: %s", url);
        goto out;
    }
    
    contacts = apr_array_make(p, 5, sizeof(const char *));
    if (md_json_has_key(json, MD_KEY_CONTACT, NULL)) {
        md_json_getsa(contacts, json, MD_KEY_CONTACT, NULL);
    }
    else {
        md_json_getsa(contacts, json, MD_KEY_REGISTRATION, MD_KEY_CONTACT, NULL);
    }
    rv = acct_make(&acct, p, ca_url, contacts);
    if (APR_SUCCESS == rv) {
        acct->status = status;
        acct->url = url;
        acct->agreement = md_json_gets(json, "terms-of-service", NULL);
        acct->orders = md_json_gets(json, MD_KEY_ORDERS, NULL);
    }

out:
    *pacct = (APR_SUCCESS == rv)? acct : NULL;
    return rv;
}

apr_status_t md_acme_acct_save(md_store_t *store, apr_pool_t *p, md_acme_t *acme, 
                               const char **pid, md_acme_acct_t *acct, md_pkey_t *acct_key)
{
    md_json_t *jacct;
    apr_status_t rv;
    int i;
    const char *id = pid? *pid : NULL;
    
    jacct = md_acme_acct_to_json(acct, p);
    if (id) {
        rv = md_store_save(store, p, MD_SG_ACCOUNTS, id, MD_FN_ACCOUNT, MD_SV_JSON, jacct, 0);
    }
    else {
        rv = APR_EAGAIN;
        for (i = 0; i < 1000 && APR_SUCCESS != rv; ++i) {
            id = mk_acct_id(p, acme, i);
            rv = md_store_save(store, p, MD_SG_ACCOUNTS, id, MD_FN_ACCOUNT, MD_SV_JSON, jacct, 1);
        }
    }
    if (APR_SUCCESS == rv) {
        if (pid) *pid = id;
        rv = md_store_save(store, p, MD_SG_ACCOUNTS, id, MD_FN_ACCT_KEY, MD_SV_PKEY, acct_key, 0);
    }
    return rv;
}

apr_status_t md_acme_acct_load(md_acme_acct_t **pacct, md_pkey_t **ppkey,
                               md_store_t *store, md_store_group_t group, 
                               const char *name, apr_pool_t *p)
{
    md_json_t *json;
    apr_status_t rv;

    rv = md_store_load_json(store, group, name, MD_FN_ACCOUNT, &json, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        goto out;
    }
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "error reading account: %s", name);
        goto out;
    }
    
    rv = md_acme_acct_from_json(pacct, json, p);
    if (APR_SUCCESS == rv) {
        rv = md_store_load(store, group, name, MD_FN_ACCT_KEY, MD_SV_PKEY, (void**)ppkey, p);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "loading key: %s", name);
            goto out;
        }
    }
out:
    if (APR_SUCCESS != rv) {
        *pacct = NULL;
        *ppkey = NULL;
    } 
    return rv;
}

/**************************************************************************************************/
/* Lookup */

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    int url_match;
    const char *id;
} find_ctx;

static int find_acct(void *baton, const char *name, const char *aspect,
                     md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
{
    find_ctx *ctx = baton;
    int disabled;
    const char *ca_url, *status;
    
    (void)aspect;
    (void)ptemp;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, "account candidate %s/%s", name, aspect); 
    if (MD_SV_JSON == vtype) {
        md_json_t *json = value;
        
        status = md_json_gets(json, MD_KEY_STATUS, NULL);
        disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
        ca_url = md_json_gets(json, MD_KEY_CA_URL, NULL);
        
        if ((!status || !strcmp("valid", status)) && !disabled 
            && (!ctx->url_match || (ca_url && !strcmp(ctx->acme->url, ca_url)))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, 
                          "found account %s for %s: %s, status=%s, disabled=%d, ca-url=%s", 
                          name, ctx->acme->url, aspect, status, disabled, ca_url);
            ctx->id = apr_pstrdup(ctx->p, name);
            return 0;
        }
    }
    return 1;
}

static apr_status_t acct_find(const char **pid, md_acme_acct_t **pacct, md_pkey_t **ppkey, 
                              md_store_t *store, md_store_group_t group,
                              const char *name_pattern, int url_match, 
                              md_acme_t *acme, apr_pool_t *p)
{
    apr_status_t rv;
    find_ctx ctx;
    
    ctx.p = p;
    ctx.acme = acme;
    ctx.id = NULL;
    ctx.url_match = url_match;
    *pid = NULL;
    
    rv = md_store_iter(find_acct, &ctx, store, p, group, name_pattern, MD_FN_ACCOUNT, MD_SV_JSON);
    if (ctx.id) {
        *pid = ctx.id;
        rv = md_acme_acct_load(pacct, ppkey, store, group, ctx.id, p);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "loading account %s", ctx.id);
    }
    else {
        *pacct = NULL;
        rv = APR_ENOENT;
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p, "acct_find: none found"); 
    }
    return rv;
}

static apr_status_t acct_find_and_verify(md_store_t *store, md_store_group_t group, 
                                         const char *name_pattern, md_acme_t *acme, apr_pool_t *p)
{
    md_acme_acct_t *acct;
    md_pkey_t *pkey;
    const char *id;
    apr_status_t rv;

    if (APR_SUCCESS == (rv = acct_find(&id, &acct, &pkey, store, group, name_pattern, 1, acme, p))) {
        acme->acct_id = (MD_SG_STAGING == group)? NULL : id;
        acme->acct = acct;
        acme->acct_key = pkey;
        rv = md_acme_acct_validate(acme, NULL, p);
    
        if (APR_SUCCESS != rv) {
            acme->acct_id = NULL;
            acme->acct = NULL;
            acme->acct_key = NULL;
            if (APR_STATUS_IS_ENOENT(rv)) {
                /* verification failed and account has been disabled.
                   Indicate to caller that he may try again. */
                rv = APR_EAGAIN;
            }
        }
    }
    return rv;
}

apr_status_t md_acme_find_acct(md_acme_t *acme, md_store_t *store)
{
    apr_status_t rv;
    
    while (APR_EAGAIN == (rv = acct_find_and_verify(store, MD_SG_ACCOUNTS, 
                                                    mk_acct_pattern(acme->p, acme), 
                                                    acme, acme->p))) {
        /* nop */
    }
    
    if (APR_STATUS_IS_ENOENT(rv)) {
        /* No suitable account found in MD_SG_ACCOUNTS. Maybe a new account
         * can already be found in MD_SG_STAGING? */
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, 
                      "no account found, looking in STAGING");
        while (APR_EAGAIN == (rv = acct_find_and_verify(store, MD_SG_STAGING, "*", 
                                                        acme, acme->p))) {
            /* nop */
        }
    }
    return rv;
}

typedef struct {
    apr_pool_t *p;
    const char *url;
    const char *id;
} load_ctx;

static int id_by_url(void *baton, const char *name, const char *aspect,
                     md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
{
    load_ctx *ctx = baton;
    int disabled;
    const char *acct_url, *status;
    
    (void)aspect;
    (void)ptemp;
    if (MD_SV_JSON == vtype) {
        md_json_t *json = value;
        
        status = md_json_gets(json, MD_KEY_STATUS, NULL);
        disabled = md_json_getb(json, MD_KEY_DISABLED, NULL);
        acct_url = md_json_gets(json, MD_KEY_URL, NULL);
        
        if ((!status || !strcmp("valid", status)) && !disabled 
            && acct_url && !strcmp(ctx->url, acct_url)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ctx->p, 
                          "found account %s for url %s: %s, status=%s, disabled=%d", 
                          name, ctx->url, aspect, status, disabled);
            ctx->id = apr_pstrdup(ctx->p, name);
            return 0;
        }
    }
    return 1;
}

apr_status_t md_acme_acct_id_for_url(const char **pid, md_store_t *store, 
                                     md_store_group_t group, const char *url, apr_pool_t *p)
{
    apr_status_t rv;
    load_ctx ctx;
    
    ctx.p = p;
    ctx.url = url;
    ctx.id = NULL;
    
    rv = md_store_iter(id_by_url, &ctx, store, p, group, "*", MD_FN_ACCOUNT, MD_SV_JSON);
    *pid = (APR_SUCCESS == rv)? ctx.id : NULL;
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "acct_id_by_url %s -> %s", url, *pid);
    return rv;
}

/**************************************************************************************************/
/* acct operation context */
typedef struct {
    md_acme_t *acme;
    apr_pool_t *p;
    const char *agreement;
} acct_ctx_t;

/**************************************************************************************************/
/* acct update */

static apr_status_t on_init_acct_upd(md_acme_req_t *req, void *baton)
{
    md_json_t *jpayload;

    (void)baton;
    jpayload = md_json_create(req->p);
    switch (MD_ACME_VERSION_MAJOR(req->acme->version)) {
        case 1:
            md_json_sets("reg", jpayload, MD_KEY_RESOURCE, NULL);
            break;
        default:
            break;
    }
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t acct_upd(md_acme_t *acme, apr_pool_t *p, 
                             const apr_table_t *hdrs, md_json_t *body, void *baton)
{
    acct_ctx_t *ctx = baton;
    apr_status_t rv = APR_SUCCESS;
    md_acme_acct_t *acct = acme->acct;
    
    if (!acct->url) {
        const char *location = apr_table_get(hdrs, "location");
        if (!location) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, APR_EINVAL, p, "new acct without location");
            return APR_EINVAL;
        }
        acct->url = apr_pstrdup(ctx->p, location);
    }
    
    apr_array_clear(acct->contacts);
    md_json_dupsa(acct->contacts, acme->p, body, MD_KEY_CONTACT, NULL);
    if (md_json_has_key(body, MD_KEY_STATUS, NULL)) {
        acct->status = acct_st_from_str(md_json_gets(body, MD_KEY_STATUS, NULL));
    }
    if (md_json_has_key(body, MD_KEY_AGREEMENT, NULL)) {
        acct->agreement = md_json_dups(acme->p, body, MD_KEY_AGREEMENT, NULL);
    }
    if (md_json_has_key(body, MD_KEY_ORDERS, NULL)) {
        acct->orders = md_json_dups(acme->p, body, MD_KEY_ORDERS, NULL);
    }
    acct->registration = md_json_clone(ctx->p, body);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "updated acct %s", acct->url);
    return rv;
}

apr_status_t md_acme_acct_update(md_acme_t *acme)
{
    acct_ctx_t ctx;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "acct update");
    if (!acme->acct) {
        return APR_EINVAL;
    }
    ctx.acme = acme;
    ctx.p = acme->p;
    return md_acme_POST(acme, acme->acct->url, on_init_acct_upd, acct_upd, NULL, NULL, &ctx);
}

apr_status_t md_acme_acct_validate(md_acme_t *acme, md_store_t *store, apr_pool_t *p)
{
    apr_status_t rv;
    
    if (APR_SUCCESS != (rv = md_acme_acct_update(acme))) {
        if (acme->acct && (APR_ENOENT == rv || APR_EACCES == rv)) {
            if (MD_ACME_ACCT_ST_VALID == acme->acct->status) {
                acme->acct->status = MD_ACME_ACCT_ST_UNKNOWN;
                if (store) {
                    md_acme_acct_save(store, p, acme, &acme->acct_id, acme->acct, acme->acct_key); 
                }
            }
            acme->acct = NULL;
            acme->acct_key = NULL;
            rv = APR_ENOENT;
        }
    }
    return rv;
}

/**************************************************************************************************/
/* Register a new account */

static apr_status_t on_init_acct_new(md_acme_req_t *req, void *baton)
{
    acct_ctx_t *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    
    switch (MD_ACME_VERSION_MAJOR(req->acme->version)) {
        case 1:
            md_json_sets("new-reg", jpayload, MD_KEY_RESOURCE, NULL);
            md_json_setsa(ctx->acme->acct->contacts, jpayload, MD_KEY_CONTACT, NULL);
            if (ctx->agreement) {
                md_json_sets(ctx->agreement, jpayload, MD_KEY_AGREEMENT, NULL);
            }
            break;
        default:
            md_json_setsa(ctx->acme->acct->contacts, jpayload, MD_KEY_CONTACT, NULL);
            if (ctx->agreement) {
                md_json_setb(1, jpayload, "termsOfServiceAgreed", NULL);
            }
        break;
    }
    
    return md_acme_req_body_init(req, jpayload);
} 

apr_status_t md_acme_acct_register(md_acme_t *acme, md_store_t *store, apr_pool_t *p, 
                                   apr_array_header_t *contacts, const char *agreement)
{
    apr_status_t rv;
    md_pkey_t *pkey;
    const char *err = NULL, *uri;
    md_pkey_spec_t spec;
    int i;
    acct_ctx_t ctx;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "create new account");
    
    ctx.acme = acme;
    ctx.p = p;
    /* The agreement URL is submitted when the ACME server announces Terms-of-Service
     * in its directory meta data. The magic value "accepted" will always use the
     * advertised URL. */
    ctx.agreement = NULL;
    if (acme->ca_agreement && agreement) {
        ctx.agreement = !strcmp("accepted", agreement)? acme->ca_agreement : agreement;
    }
    
    if (ctx.agreement) {
        if (APR_SUCCESS != (rv = md_util_abs_uri_check(acme->p, ctx.agreement, &err))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, 
                          "invalid agreement uri (%s): %s", err, ctx.agreement);
            goto out;
        }
    }
    
    for (i = 0; i < contacts->nelts; ++i) {
        uri = APR_ARRAY_IDX(contacts, i, const char *);
        if (APR_SUCCESS != (rv = md_util_abs_uri_check(acme->p, uri, &err))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, 
                          "invalid contact uri (%s): %s", err, uri);
            goto out;
        }
    }
    
    /* If there is no key selected yet, try to find an existing one for the same host. 
     * Let's Encrypt identifies accounts by their key for their ACMEv1 and v2 services.
     * Although the account appears on both services with different urls, it is 
     * internally the same one.
     * I think this is beneficial if someone migrates from ACMEv1 to v2 and not a leak
     * of identifying information.
     */
    if (!acme->acct_key) {
        find_ctx fctx;
    
        fctx.p = p;
        fctx.acme = acme;
        fctx.id = NULL;
        fctx.url_match = 0;
        
        md_store_iter(find_acct, &fctx, store, p, MD_SG_ACCOUNTS, 
                      mk_acct_pattern(p, acme), MD_FN_ACCOUNT, MD_SV_JSON);
        if (fctx.id) {
            rv = md_store_load(store, MD_SG_ACCOUNTS, fctx.id, MD_FN_ACCT_KEY, MD_SV_PKEY, 
                               (void**)&acme->acct_key, p);
            if (APR_SUCCESS == rv) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "reusing key from account %s", fctx.id);
            }
            else {
                acme->acct_key = NULL;
            }
        }
    }
    
    /* If we still have no key, generate a new one */
    if (!acme->acct_key) {
        spec.type = MD_PKEY_TYPE_RSA;
        spec.params.rsa.bits = MD_ACME_ACCT_PKEY_BITS;
        
        if (APR_SUCCESS != (rv = md_pkey_gen(&pkey, acme->p, &spec))) goto out;
        acme->acct_key = pkey;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "created new account key");
    }
    
    if (APR_SUCCESS != (rv = acct_make(&acme->acct,  p, acme->url, contacts))) goto out;
    rv = md_acme_POST_new_account(acme,  on_init_acct_new, acct_upd, NULL, NULL, &ctx);
    if (APR_SUCCESS == rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, p, 
                      "registered new account %s", acme->acct->url);
    }

out:    
    if (APR_SUCCESS != rv && acme->acct) {
        acme->acct = NULL;
    }
    return rv;
}

/**************************************************************************************************/
/* Deactivate the account */

static apr_status_t on_init_acct_del(md_acme_req_t *req, void *baton)
{
    md_json_t *jpayload;

    (void)baton;
    jpayload = md_json_create(req->p);
    switch (MD_ACME_VERSION_MAJOR(req->acme->version)) {
        case 1:
            md_json_sets("reg", jpayload, MD_KEY_RESOURCE, NULL);
            md_json_setb(1, jpayload, "delete", NULL);
            break;
        default:
            md_json_sets("deactivated", jpayload, MD_KEY_STATUS, NULL);
            break;
    }
    return md_acme_req_body_init(req, jpayload);
} 

apr_status_t md_acme_acct_deactivate(md_acme_t *acme, apr_pool_t *p)
{
    md_acme_acct_t *acct = acme->acct;
    acct_ctx_t ctx;
    
    (void)p;
    if (!acct) {
        return APR_EINVAL;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "delete account %s from %s", 
                  acct->url, acct->ca_url);
    ctx.acme = acme;
    ctx.p = p;
    return md_acme_POST(acme, acct->url, on_init_acct_del, acct_upd, NULL, NULL, &ctx);
}

/**************************************************************************************************/
/* terms-of-service */

static apr_status_t on_init_agree_tos(md_acme_req_t *req, void *baton)
{
    acct_ctx_t *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    switch (MD_ACME_VERSION_MAJOR(req->acme->version)) {
        case 1:
            md_json_sets("reg", jpayload, MD_KEY_RESOURCE, NULL);
            md_json_sets(ctx->acme->acct->agreement, jpayload, MD_KEY_AGREEMENT, NULL);
            break;
        default:
            if (ctx->acme->acct->agreement) {
                md_json_setb(1, jpayload, "termsOfServiceAgreed", NULL);
            }
            break;
    }
    return md_acme_req_body_init(req, jpayload);
} 

apr_status_t md_acme_agree(md_acme_t *acme, apr_pool_t *p, const char *agreement)
{
    acct_ctx_t ctx;
    
    acme->acct->agreement = agreement;
    if (!strcmp("accepted", agreement) && acme->ca_agreement) {
        acme->acct->agreement = acme->ca_agreement;
    }
    
    ctx.acme = acme;
    ctx.p = p;
    return md_acme_POST(acme, acme->acct->url, on_init_agree_tos, acct_upd, NULL, NULL, &ctx);
}

apr_status_t md_acme_check_agreement(md_acme_t *acme, apr_pool_t *p, 
                                     const char *agreement, const char **prequired)
{
    apr_status_t rv = APR_SUCCESS;
    
    /* We used to really check if the account agreement and the one indicated in meta
     * are the very same. However, LE is happy if the account has agreed to a ToS in 
     * the past and does not require a renewed acceptance.
     */
    *prequired = NULL;
    if (!acme->acct->agreement && acme->ca_agreement) {
        if (agreement) {
            rv = md_acme_agree(acme, p, acme->ca_agreement);
        }
        else {
            *prequired = acme->ca_agreement;
            rv = APR_INCOMPLETE;
        }
    }
    return rv;
}        
