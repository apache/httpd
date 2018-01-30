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
#include <apr_buckets.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_jws.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_authz.h"

md_acme_authz_t *md_acme_authz_create(apr_pool_t *p)
{
    md_acme_authz_t *authz;
    authz = apr_pcalloc(p, sizeof(*authz));
    
    return authz;
}

md_acme_authz_set_t *md_acme_authz_set_create(apr_pool_t *p)
{
    md_acme_authz_set_t *authz_set;
    
    authz_set = apr_pcalloc(p, sizeof(*authz_set));
    authz_set->authzs = apr_array_make(p, 5, sizeof(md_acme_authz_t *));
    
    return authz_set;
}

md_acme_authz_t *md_acme_authz_set_get(md_acme_authz_set_t *set, const char *domain)
{
    md_acme_authz_t *authz;
    int i;
    
    assert(domain);
    for (i = 0; i < set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(set->authzs, i, md_acme_authz_t *);
        if (!apr_strnatcasecmp(domain, authz->domain)) {
            return authz;
        }
    }
    return NULL;
}

apr_status_t md_acme_authz_set_add(md_acme_authz_set_t *set, md_acme_authz_t *authz)
{
    md_acme_authz_t *existing;
    
    assert(authz->domain);
    if (NULL != (existing = md_acme_authz_set_get(set, authz->domain))) {
        return APR_EINVAL;
    }
    APR_ARRAY_PUSH(set->authzs, md_acme_authz_t*) = authz;
    return APR_SUCCESS;
}

apr_status_t md_acme_authz_set_remove(md_acme_authz_set_t *set, const char *domain)
{
    md_acme_authz_t *authz;
    int i;
    
    assert(domain);
    for (i = 0; i < set->authzs->nelts; ++i) {
        authz = APR_ARRAY_IDX(set->authzs, i, md_acme_authz_t *);
        if (!apr_strnatcasecmp(domain, authz->domain)) {
            int n = i + 1;
            if (n < set->authzs->nelts) {
                void **elems = (void **)set->authzs->elts;
                memmove(elems + i, elems + n, (size_t)(set->authzs->nelts - n)); 
            }
            --set->authzs->nelts;
            return APR_SUCCESS;
        }
    }
    return APR_ENOENT;
}

/**************************************************************************************************/
/* Register a new authorization */

typedef struct {
    size_t index;
    const char *type;
    const char *uri;
    const char *token;
    const char *key_authz;
} md_acme_authz_cha_t;

typedef struct {
    apr_pool_t *p;
    md_acme_t *acme;
    const char *domain;
    md_acme_authz_t *authz;
    md_acme_authz_cha_t *challenge;
} authz_req_ctx;

static void authz_req_ctx_init(authz_req_ctx *ctx, md_acme_t *acme, 
                               const char *domain, md_acme_authz_t *authz, apr_pool_t *p)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->p = p;
    ctx->acme = acme;
    ctx->domain = domain;
    ctx->authz = authz;
}

static apr_status_t on_init_authz(md_acme_req_t *req, void *baton)
{
    authz_req_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("new-authz", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_sets("dns", jpayload, MD_KEY_IDENTIFIER, MD_KEY_TYPE, NULL);
    md_json_sets(ctx->domain, jpayload, MD_KEY_IDENTIFIER, MD_KEY_VALUE, NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t authz_created(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
                                  md_json_t *body, void *baton)
{
    authz_req_ctx *ctx = baton;
    const char *location = apr_table_get(hdrs, "location");
    apr_status_t rv = APR_SUCCESS;
    
    (void)acme;
    (void)p;
    if (location) {
        ctx->authz = md_acme_authz_create(ctx->p);
        ctx->authz->domain = apr_pstrdup(ctx->p, ctx->domain);
        ctx->authz->location = apr_pstrdup(ctx->p, location);
        ctx->authz->resource = md_json_clone(ctx->p, body);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ctx->p, "authz_new at %s", location);
    }
    else {
        rv = APR_EINVAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, ctx->p, "new authz, no location header");
    }
    return rv;
}

apr_status_t md_acme_authz_register(struct md_acme_authz_t **pauthz, md_acme_t *acme, 
                                    md_store_t *store, const char *domain, apr_pool_t *p)
{
    apr_status_t rv;
    authz_req_ctx ctx;
    
    (void)store;
    authz_req_ctx_init(&ctx, acme, domain, NULL, p);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "create new authz");
    rv = md_acme_POST(acme, acme->new_authz, on_init_authz, authz_created, NULL, &ctx);
    
    *pauthz = (APR_SUCCESS == rv)? ctx.authz : NULL;
    return rv;
}

/**************************************************************************************************/
/* Update an existing authorization */

apr_status_t md_acme_authz_update(md_acme_authz_t *authz, md_acme_t *acme, 
                                  md_store_t *store, apr_pool_t *p)
{
    md_json_t *json;
    const char *s, *err;
    md_log_level_t log_level;
    apr_status_t rv;
    MD_CHK_VARS;
    
    (void)store;
    assert(acme);
    assert(acme->http);
    assert(authz);
    assert(authz->location);

    authz->state = MD_ACME_AUTHZ_S_UNKNOWN;
    json = NULL;
    err = "unable to parse response";
    log_level = MD_LOG_ERR;
    
    if (MD_OK(md_acme_get_json(&json, acme, authz->location, p))
        && (s = md_json_gets(json, MD_KEY_IDENTIFIER, MD_KEY_TYPE, NULL))
        && !strcmp(s, "dns")
        && (s = md_json_gets(json, MD_KEY_IDENTIFIER, MD_KEY_VALUE, NULL))
        && !strcmp(s, authz->domain)
        && (s = md_json_gets(json, MD_KEY_STATUS, NULL))) {
        
        authz->resource = json;
        if (!strcmp(s, "pending")) {
            authz->state = MD_ACME_AUTHZ_S_PENDING;
            err = "challenge 'pending'";
            log_level = MD_LOG_DEBUG;
        }
        else if (!strcmp(s, "valid")) {
            authz->state = MD_ACME_AUTHZ_S_VALID;
            err = "challenge 'valid'";
            log_level = MD_LOG_DEBUG;
        }
        else if (!strcmp(s, "invalid")) {
            authz->state = MD_ACME_AUTHZ_S_INVALID;
            err = "challenge 'invalid'";
        }
    }

    if (json && authz->state == MD_ACME_AUTHZ_S_UNKNOWN) {
        err = "unable to understand response";
        rv = APR_EINVAL;
    }
    
    if (md_log_is_level(p, log_level)) {
        md_log_perror(MD_LOG_MARK, log_level, rv, p, "ACME server authz: %s for %s at %s. "
                      "Exact repsonse was: %s", err? err : "", authz->domain, authz->location,
                      json? md_json_writep(json, p, MD_JSON_FMT_COMPACT) : "not available");
    }
    
    return rv;
}

/**************************************************************************************************/
/* response to a challenge */

static md_acme_authz_cha_t *cha_from_json(apr_pool_t *p, size_t index, md_json_t *json)
{
    md_acme_authz_cha_t * cha;
    
    cha = apr_pcalloc(p, sizeof(*cha));
    cha->index = index;
    cha->type = md_json_dups(p, json, MD_KEY_TYPE, NULL);
    cha->uri = md_json_dups(p, json, MD_KEY_URI, NULL);
    cha->token = md_json_dups(p, json, MD_KEY_TOKEN, NULL);
    cha->key_authz = md_json_dups(p, json, MD_KEY_KEYAUTHZ, NULL);

    return cha;
}

static apr_status_t on_init_authz_resp(md_acme_req_t *req, void *baton)
{
    authz_req_ctx *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_sets("challenge", jpayload, MD_KEY_RESOURCE, NULL);
    md_json_sets(ctx->challenge->key_authz, jpayload, MD_KEY_KEYAUTHZ, NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t authz_http_set(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
                                   md_json_t *body, void *baton)
{
    authz_req_ctx *ctx = baton;
    
    (void)acme;
    (void)p;
    (void)hdrs;
    (void)body;
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "updated authz %s", ctx->authz->location);
    return APR_SUCCESS;
}

static apr_status_t setup_key_authz(md_acme_authz_cha_t *cha, md_acme_authz_t *authz,
                                    md_acme_t *acme, apr_pool_t *p, int *pchanged)
{
    const char *thumb64, *key_authz;
    apr_status_t rv;
    MD_CHK_VARS;
    
    (void)authz;
    assert(cha);
    assert(cha->token);
    
    *pchanged = 0;
    if (MD_OK(md_jws_pkey_thumb(&thumb64, p, acme->acct_key))) {
        key_authz = apr_psprintf(p, "%s.%s", cha->token, thumb64);
        if (cha->key_authz) {
            if (strcmp(key_authz, cha->key_authz)) {
                /* Hu? Did the account change key? */
                cha->key_authz = NULL;
            }
        }
        if (!cha->key_authz) {
            cha->key_authz = key_authz;
            *pchanged = 1;
        }
    }
    return rv;
}

static apr_status_t cha_http_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                      md_acme_t *acme, md_store_t *store, 
                                      md_pkey_spec_t *key_spec, apr_pool_t *p)
{
    const char *data;
    apr_status_t rv;
    int notify_server;
    MD_CHK_VARS;
    
    (void)key_spec;
    if (!MD_OK(setup_key_authz(cha, authz, acme, p, &notify_server))) {
        goto out;
    }
    
    rv = md_store_load(store, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                       MD_SV_TEXT, (void**)&data, p);
    if ((APR_SUCCESS == rv && strcmp(cha->key_authz, data)) || APR_STATUS_IS_ENOENT(rv)) {
        rv = md_store_save(store, p, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                           MD_SV_TEXT, (void*)cha->key_authz, 0);
        authz->dir = authz->domain;
        notify_server = 1;
    }
    
    if (APR_SUCCESS == rv && notify_server) {
        authz_req_ctx ctx;

        /* challenge is setup or was changed from previous data, tell ACME server
         * so it may (re)try verification */        
        authz_req_ctx_init(&ctx, acme, NULL, authz, p);
        ctx.challenge = cha;
        rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, &ctx);
    }
out:
    return rv;
}

static apr_status_t setup_cha_dns(const char **pdns, md_acme_authz_cha_t *cha, apr_pool_t *p)
{
    const char *dhex;
    char *dns;
    apr_size_t dhex_len;
    apr_status_t rv;
    
    rv = md_crypt_sha256_digest_hex(&dhex, p, cha->key_authz, strlen(cha->key_authz));
    if (APR_SUCCESS == rv) {
        dhex = md_util_str_tolower((char*)dhex);
        dhex_len = strlen(dhex); 
        assert(dhex_len > 32);
        dns = apr_pcalloc(p, dhex_len + 1 + sizeof(MD_TLSSNI01_DNS_SUFFIX));
        strncpy(dns, dhex, 32);
        dns[32] = '.';
        strncpy(dns+33, dhex+32, dhex_len-32);
        memcpy(dns+(dhex_len+1), MD_TLSSNI01_DNS_SUFFIX, sizeof(MD_TLSSNI01_DNS_SUFFIX));
    }
    *pdns = (APR_SUCCESS == rv)? dns : NULL;
    return rv;
}

static apr_status_t cha_tls_sni_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                         md_acme_t *acme, md_store_t *store, 
                                         md_pkey_spec_t *key_spec, apr_pool_t *p)
{
    md_cert_t *cha_cert;
    md_pkey_t *cha_key;
    const char *cha_dns;
    apr_status_t rv;
    int notify_server;
    apr_array_header_t *domains;
    MD_CHK_VARS;
    
    if (   !MD_OK(setup_key_authz(cha, authz, acme, p, &notify_server))
        || !MD_OK(setup_cha_dns(&cha_dns, cha, p))) {
        goto out;
    }

    rv = md_store_load(store, MD_SG_CHALLENGES, cha_dns, MD_FN_TLSSNI01_CERT,
                       MD_SV_CERT, (void**)&cha_cert, p);
    if ((APR_SUCCESS == rv && !md_cert_covers_domain(cha_cert, cha_dns)) 
        || APR_STATUS_IS_ENOENT(rv)) {
        
        if (APR_SUCCESS != (rv = md_pkey_gen(&cha_key, p, key_spec))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create tls-sni-01 challenge key",
                          authz->domain);
            goto out;
        }

        /* setup a certificate containing the challenge dns */
        domains = apr_array_make(p, 5, sizeof(const char*));
        APR_ARRAY_PUSH(domains, const char*) = cha_dns;
        if (!MD_OK(md_cert_self_sign(&cha_cert, authz->domain, domains, cha_key, 
                                     apr_time_from_sec(7 * MD_SECS_PER_DAY), p))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: setup self signed cert for %s",
                          authz->domain, cha_dns);
            goto out;
        }
        
        if (MD_OK(md_store_save(store, p, MD_SG_CHALLENGES, cha_dns, MD_FN_TLSSNI01_PKEY,
                                MD_SV_PKEY, (void*)cha_key, 0))) {
            rv = md_store_save(store, p, MD_SG_CHALLENGES, cha_dns, MD_FN_TLSSNI01_CERT,
                               MD_SV_CERT, (void*)cha_cert, 0);
        }
        authz->dir = cha_dns;
        notify_server = 1;
    }
    
    if (APR_SUCCESS == rv && notify_server) {
        authz_req_ctx ctx;

        /* challenge is setup or was changed from previous data, tell ACME server
         * so it may (re)try verification */        
        authz_req_ctx_init(&ctx, acme, NULL, authz, p);
        ctx.challenge = cha;
        rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, &ctx);
    }
out:    
    return rv;
}

typedef apr_status_t cha_starter(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                 md_acme_t *acme, md_store_t *store, 
                                 md_pkey_spec_t *key_spec, apr_pool_t *p);
                                 
typedef struct {
    const char *name;
    cha_starter *start;
} cha_type;

static const cha_type CHA_TYPES[] = {
    { MD_AUTHZ_TYPE_HTTP01,     cha_http_01_setup },
    { MD_AUTHZ_TYPE_TLSSNI01,   cha_tls_sni_01_setup },
};
static const apr_size_t CHA_TYPES_LEN = (sizeof(CHA_TYPES)/sizeof(CHA_TYPES[0]));

typedef struct {
    apr_pool_t *p;
    const char *type;
    md_acme_authz_cha_t *accepted;
    apr_array_header_t *offered;
} cha_find_ctx;

static apr_status_t collect_offered(void *baton, size_t index, md_json_t *json)
{
    cha_find_ctx *ctx = baton;
    const char *ctype;
    
    (void)index;
    if ((ctype = md_json_gets(json, MD_KEY_TYPE, NULL))) {
        APR_ARRAY_PUSH(ctx->offered, const char*) = apr_pstrdup(ctx->p, ctype);
    }
    return 1;
}

static apr_status_t find_type(void *baton, size_t index, md_json_t *json)
{
    cha_find_ctx *ctx = baton;
    
    const char *ctype = md_json_gets(json, MD_KEY_TYPE, NULL);
    if (ctype && !apr_strnatcasecmp(ctx->type, ctype)) {
        ctx->accepted = cha_from_json(ctx->p, index, json);
        return 0;
    }
    return 1;
}

apr_status_t md_acme_authz_respond(md_acme_authz_t *authz, md_acme_t *acme, md_store_t *store, 
                                   apr_array_header_t *challenges, 
                                   md_pkey_spec_t *key_spec, apr_pool_t *p)
{
    apr_status_t rv;
    int i;
    cha_find_ctx fctx;
    
    assert(acme);
    assert(authz);
    assert(authz->resource);

    fctx.p = p;
    fctx.accepted = NULL;
    
    /* Look in the order challenge types are defined */
    for (i = 0; i < challenges->nelts && !fctx.accepted; ++i) {
        fctx.type = APR_ARRAY_IDX(challenges, i, const char *);
        md_json_itera(find_type, &fctx, authz->resource, MD_KEY_CHALLENGES, NULL);
    }
    
    if (!fctx.accepted) {
        rv = APR_EINVAL;
        fctx.offered = apr_array_make(p, 5, sizeof(const char*));
        md_json_itera(collect_offered, &fctx, authz->resource, MD_KEY_CHALLENGES, NULL);
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                      "%s: the server offers no ACME challenge that is configured "
                      "for this MD. The server offered '%s' and available for this "
                      "MD are: '%s' (via %s).",
                      authz->domain, 
                      apr_array_pstrcat(p, fctx.offered, ' '),
                      apr_array_pstrcat(p, challenges, ' '),
                      authz->location);
        return rv;
    }
    
    for (i = 0; i < (int)CHA_TYPES_LEN; ++i) {
        if (!apr_strnatcasecmp(CHA_TYPES[i].name, fctx.accepted->type)) {
            return CHA_TYPES[i].start(fctx.accepted, authz, acme, store, key_spec, p);
        }
    }
    
    rv = APR_ENOTIMPL;
    md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                  "%s: no implementation found for challenge '%s'",
                  authz->domain, fctx.accepted->type);
    return rv;
}

/**************************************************************************************************/
/* Delete an existing authz resource */

typedef struct {
    apr_pool_t *p;
    md_acme_authz_t *authz;
} del_ctx;

static apr_status_t on_init_authz_del(md_acme_req_t *req, void *baton)
{
    md_json_t *jpayload;

    (void)baton;
    jpayload = md_json_create(req->p);
    md_json_sets("deactivated", jpayload, MD_KEY_STATUS, NULL);
    
    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t authz_del(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
                              md_json_t *body, void *baton)
{
    authz_req_ctx *ctx = baton;
    
    (void)p;
    (void)body;
    (void)hdrs;
    md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, ctx->p, "deleted authz %s", ctx->authz->location);
    acme->acct = NULL;
    return APR_SUCCESS;
}

apr_status_t md_acme_authz_del(md_acme_authz_t *authz, md_acme_t *acme, 
                               md_store_t *store, apr_pool_t *p)
{
    authz_req_ctx ctx;
    
    (void)store;
    ctx.p = p;
    ctx.authz = authz;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "delete authz for %s from %s", 
                  authz->domain, authz->location);
    return md_acme_POST(acme, authz->location, on_init_authz_del, authz_del, NULL, &ctx);
}

/**************************************************************************************************/
/* authz conversion */

md_json_t *md_acme_authz_to_json(md_acme_authz_t *a, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_sets(a->domain, json, MD_KEY_DOMAIN, NULL);
        md_json_sets(a->location, json, MD_KEY_LOCATION, NULL);
        md_json_sets(a->dir, json, MD_KEY_DIR, NULL);
        md_json_setl(a->state, json, MD_KEY_STATE, NULL);
        return json;
    }
    return NULL;
}

md_acme_authz_t *md_acme_authz_from_json(struct md_json_t *json, apr_pool_t *p)
{
    md_acme_authz_t *authz = md_acme_authz_create(p);
    if (authz) {
        authz->domain = md_json_dups(p, json, MD_KEY_DOMAIN, NULL);            
        authz->location = md_json_dups(p, json, MD_KEY_LOCATION, NULL);            
        authz->dir = md_json_dups(p, json, MD_KEY_DIR, NULL);            
        authz->state = (md_acme_authz_state_t)md_json_getl(json, MD_KEY_STATE, NULL);            
        return authz;
    }
    return NULL;
}

/**************************************************************************************************/
/* authz_set conversion */

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_AUTHZS           "authorizations"

static apr_status_t authz_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    return md_json_setj(md_acme_authz_to_json(value, p), json, NULL);
}

static apr_status_t authz_from_json(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    *pvalue = md_acme_authz_from_json(json, p);
    return (*pvalue)? APR_SUCCESS : APR_EINVAL;
}

md_json_t *md_acme_authz_set_to_json(md_acme_authz_set_t *set, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        md_json_seta(set->authzs, authz_to_json, NULL, json, MD_KEY_AUTHZS, NULL);
        return json;
    }
    return NULL;
}

md_acme_authz_set_t *md_acme_authz_set_from_json(md_json_t *json, apr_pool_t *p)
{
    md_acme_authz_set_t *set = md_acme_authz_set_create(p);
    if (set) {
        md_json_geta(set->authzs, authz_from_json, NULL, json, MD_KEY_AUTHZS, NULL);
        return set;
    }
    return NULL;
}

/**************************************************************************************************/
/* persistence */

apr_status_t md_acme_authz_set_load(struct md_store_t *store, md_store_group_t group, 
                                    const char *md_name, md_acme_authz_set_t **pauthz_set, 
                                    apr_pool_t *p)
{
    apr_status_t rv;
    md_json_t *json;
    md_acme_authz_set_t *authz_set;
    
    rv = md_store_load_json(store, group, md_name, MD_FN_AUTHZ, &json, p);
    if (APR_SUCCESS == rv) {
        authz_set = md_acme_authz_set_from_json(json, p);
    }
    *pauthz_set = (APR_SUCCESS == rv)? authz_set : NULL;
    return rv;  
}

static apr_status_t p_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_json_t *json;
    md_store_group_t group;
    md_acme_authz_set_t *set;
    const char *md_name;
    int create;
 
    (void)p;   
    group = (md_store_group_t)va_arg(ap, int);
    md_name = va_arg(ap, const char *);
    set = va_arg(ap, md_acme_authz_set_t *);
    create = va_arg(ap, int);

    json = md_acme_authz_set_to_json(set, ptemp);
    assert(json);
    return md_store_save_json(store, ptemp, group, md_name, MD_FN_AUTHZ, json, create);
}

apr_status_t md_acme_authz_set_save(struct md_store_t *store, apr_pool_t *p,
                                    md_store_group_t group, const char *md_name, 
                                    md_acme_authz_set_t *authz_set, int create)
{
    return md_util_pool_vdo(p_save, store, p, group, md_name, authz_set, create, NULL);
}

static apr_status_t p_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_acme_authz_set_t *authz_set;
    const md_acme_authz_t *authz;
    md_store_group_t group;
    const char *md_name;
    int i;

    group = (md_store_group_t)va_arg(ap, int);
    md_name = va_arg(ap, const char *);

    if (APR_SUCCESS == md_acme_authz_set_load(store, group, md_name, &authz_set, p)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "authz_set loaded for %s", md_name);
        for (i = 0; i < authz_set->authzs->nelts; ++i) {
            authz = APR_ARRAY_IDX(authz_set->authzs, i, const md_acme_authz_t*);
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "authz check %s", authz->domain);
            if (authz->dir) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "authz purge %s", authz->dir);
                md_store_purge(store, p, MD_SG_CHALLENGES, authz->dir);
            }
        }
    }
    return md_store_remove(store, group, md_name, MD_FN_AUTHZ, ptemp, 1);
}

apr_status_t md_acme_authz_set_purge(md_store_t *store, md_store_group_t group,
                                     apr_pool_t *p, const char *md_name)
{
    return md_util_pool_vdo(p_purge, store, p, group, md_name, NULL);
}

