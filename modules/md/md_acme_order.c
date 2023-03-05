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
#include "md_result.h"
#include "md_store.h"
#include "md_util.h"

#include "md_acme.h"
#include "md_acme_authz.h"
#include "md_acme_order.h"


md_acme_order_t *md_acme_order_create(apr_pool_t *p)
{
    md_acme_order_t *order;
    
    order = apr_pcalloc(p, sizeof(*order));
    order->p = p;
    order->authz_urls = apr_array_make(p, 5, sizeof(const char *));
    order->challenge_setups = apr_array_make(p, 5, sizeof(const char *));
    
    return order;
}

/**************************************************************************************************/
/* order conversion */

#define MD_KEY_CHALLENGE_SETUPS   "challenge-setups"

static md_acme_order_st order_st_from_str(const char *s) 
{
    if (s) {
        if (!strcmp("valid", s)) {
            return MD_ACME_ORDER_ST_VALID;
        }
        else if (!strcmp("invalid", s)) {
            return MD_ACME_ORDER_ST_INVALID;
        }
        else if (!strcmp("ready", s)) {
            return MD_ACME_ORDER_ST_READY;
        }
        else if (!strcmp("pending", s)) {
            return MD_ACME_ORDER_ST_PENDING;
        }
        else if (!strcmp("processing", s)) {
            return MD_ACME_ORDER_ST_PROCESSING;
        }
    }
    return MD_ACME_ORDER_ST_PENDING;
}

static const char *order_st_to_str(md_acme_order_st status) 
{
    switch (status) {
        case MD_ACME_ORDER_ST_PENDING:
            return "pending";
        case MD_ACME_ORDER_ST_READY:
            return "ready";
        case MD_ACME_ORDER_ST_PROCESSING:
            return "processing";
        case MD_ACME_ORDER_ST_VALID:
            return "valid";
        case MD_ACME_ORDER_ST_INVALID:
            return "invalid";
        default:
            return "invalid";
    }
}

md_json_t *md_acme_order_to_json(md_acme_order_t *order, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);

    if (order->url) {
        md_json_sets(order->url, json, MD_KEY_URL, NULL);
    }
    md_json_sets(order_st_to_str(order->status), json, MD_KEY_STATUS, NULL);
    md_json_setsa(order->authz_urls, json, MD_KEY_AUTHORIZATIONS, NULL);
    md_json_setsa(order->challenge_setups, json, MD_KEY_CHALLENGE_SETUPS, NULL);
    if (order->finalize) {
        md_json_sets(order->finalize, json, MD_KEY_FINALIZE, NULL);
    }
    if (order->certificate) {
        md_json_sets(order->certificate, json, MD_KEY_CERTIFICATE, NULL);
    }
    return json;
}

static void order_update_from_json(md_acme_order_t *order, md_json_t *json, apr_pool_t *p)
{
    if (!order->url && md_json_has_key(json, MD_KEY_URL, NULL)) {
        order->url = md_json_dups(p, json, MD_KEY_URL, NULL);
    }
    order->status = order_st_from_str(md_json_gets(json, MD_KEY_STATUS, NULL));
    if (md_json_has_key(json, MD_KEY_AUTHORIZATIONS, NULL)) {
        md_json_dupsa(order->authz_urls, p, json, MD_KEY_AUTHORIZATIONS, NULL);
    }
    if (md_json_has_key(json, MD_KEY_CHALLENGE_SETUPS, NULL)) {
        md_json_dupsa(order->challenge_setups, p, json, MD_KEY_CHALLENGE_SETUPS, NULL);
    }
    if (md_json_has_key(json, MD_KEY_FINALIZE, NULL)) {
        order->finalize = md_json_dups(p, json, MD_KEY_FINALIZE, NULL);
    }
    if (md_json_has_key(json, MD_KEY_CERTIFICATE, NULL)) {
        order->certificate = md_json_dups(p, json, MD_KEY_CERTIFICATE, NULL);
    }
}

md_acme_order_t *md_acme_order_from_json(md_json_t *json, apr_pool_t *p)
{
    md_acme_order_t *order = md_acme_order_create(p);

    order_update_from_json(order, json, p);
    return order;
}

apr_status_t md_acme_order_add(md_acme_order_t *order, const char *authz_url)
{
    assert(authz_url);
    if (md_array_str_index(order->authz_urls, authz_url, 0, 1) < 0) {
        APR_ARRAY_PUSH(order->authz_urls, const char*) = apr_pstrdup(order->p, authz_url);
    }
    return APR_SUCCESS;
}

apr_status_t md_acme_order_remove(md_acme_order_t *order, const char *authz_url)
{
    int i;
    
    assert(authz_url);
    i = md_array_str_index(order->authz_urls, authz_url, 0, 1);
    if (i >= 0) {
        order->authz_urls = md_array_str_remove(order->p, order->authz_urls, authz_url, 1);
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

static apr_status_t add_setup_token(md_acme_order_t *order, const char *token)
{
    if (md_array_str_index(order->challenge_setups, token, 0, 1) < 0) {
        APR_ARRAY_PUSH(order->challenge_setups, const char*) = apr_pstrdup(order->p, token);
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* persistence */

apr_status_t md_acme_order_load(struct md_store_t *store, md_store_group_t group, 
                                    const char *md_name, md_acme_order_t **pauthz_set, 
                                    apr_pool_t *p)
{
    apr_status_t rv;
    md_json_t *json;
    md_acme_order_t *authz_set;
    
    rv = md_store_load_json(store, group, md_name, MD_FN_ORDER, &json, p);
    if (APR_SUCCESS == rv) {
        authz_set = md_acme_order_from_json(json, p);
    }
    *pauthz_set = (APR_SUCCESS == rv)? authz_set : NULL;
    return rv;  
}

static apr_status_t p_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_json_t *json;
    md_store_group_t group;
    md_acme_order_t *set;
    const char *md_name;
    int create;
 
    (void)p;   
    group = (md_store_group_t)va_arg(ap, int);
    md_name = va_arg(ap, const char *);
    set = va_arg(ap, md_acme_order_t *);
    create = va_arg(ap, int);

    json = md_acme_order_to_json(set, ptemp);
    assert(json);
    return md_store_save_json(store, ptemp, group, md_name, MD_FN_ORDER, json, create);
}

apr_status_t md_acme_order_save(struct md_store_t *store, apr_pool_t *p,
                                    md_store_group_t group, const char *md_name, 
                                    md_acme_order_t *authz_set, int create)
{
    return md_util_pool_vdo(p_save, store, p, group, md_name, authz_set, create, NULL);
}

static apr_status_t p_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_t *store = baton;
    md_acme_order_t *order;
    md_store_group_t group;
    const md_t *md;
    const char *setup_token;
    apr_table_t *env;
    int i;

    group = (md_store_group_t)va_arg(ap, int);
    md = va_arg(ap, const md_t *);
    env = va_arg(ap, apr_table_t *);

    if (APR_SUCCESS == md_acme_order_load(store, group, md->name, &order, p)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "order loaded for %s", md->name);
        for (i = 0; i < order->challenge_setups->nelts; ++i) {
            setup_token = APR_ARRAY_IDX(order->challenge_setups, i, const char*);
            if (setup_token) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                              "order teardown setup %s", setup_token);
                md_acme_authz_teardown(store, setup_token, md, env, p);
            }
        }
    }
    return md_store_remove(store, group, md->name, MD_FN_ORDER, ptemp, 1);
}

apr_status_t md_acme_order_purge(md_store_t *store, apr_pool_t *p, md_store_group_t group,
                                 const md_t *md, apr_table_t *env)
{
    return md_util_pool_vdo(p_purge, store, p, group, md, env, NULL);
}

/**************************************************************************************************/
/* ACMEv2 order requests */

typedef struct {
    apr_pool_t *p;
    md_acme_order_t *order;
    md_acme_t *acme;
    const char *name;
    apr_array_header_t *domains;
    md_result_t *result;
} order_ctx_t;

#define ORDER_CTX_INIT(ctx, p, o, a, n, d, r) \
    (ctx)->p = (p); (ctx)->order = (o); (ctx)->acme = (a); \
    (ctx)->name = (n); (ctx)->domains = d; (ctx)->result = r

static apr_status_t identifier_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    md_json_t *jid;
    
    (void)baton;
    jid = md_json_create(p);
    md_json_sets("dns", jid, "type", NULL);
    md_json_sets(value, jid, "value", NULL);
    return md_json_setj(jid, json, NULL);
}

static apr_status_t on_init_order_register(md_acme_req_t *req, void *baton)
{
    order_ctx_t *ctx = baton;
    md_json_t *jpayload;

    jpayload = md_json_create(req->p);
    md_json_seta(ctx->domains, identifier_to_json, NULL, jpayload, "identifiers", NULL);

    return md_acme_req_body_init(req, jpayload);
} 

static apr_status_t on_order_upd(md_acme_t *acme, apr_pool_t *p, const apr_table_t *hdrs, 
                                 md_json_t *body, void *baton)
{
    order_ctx_t *ctx = baton;
    const char *location = apr_table_get(hdrs, "location");
    apr_status_t rv = APR_SUCCESS;
    
    (void)acme;
    (void)p;
    if (!ctx->order) {
        if (location) {
            ctx->order = md_acme_order_create(ctx->p);
            ctx->order->url = apr_pstrdup(ctx->p, location);
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ctx->p, "new order at %s", location);
        }
        else {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, ctx->p, "new order, no location header");
            goto out;
        }
    }
    
    order_update_from_json(ctx->order, body, ctx->p);
out:
    return rv;
}

apr_status_t md_acme_order_register(md_acme_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
                                    const char *name, apr_array_header_t *domains)
{
    order_ctx_t ctx;
    apr_status_t rv;
    
    assert(MD_ACME_VERSION_MAJOR(acme->version) > 1);
    ORDER_CTX_INIT(&ctx, p, NULL, acme, name, domains, NULL);
    rv = md_acme_POST(acme, acme->api.v2.new_order, on_init_order_register, on_order_upd, NULL, NULL, &ctx);
    *porder = (APR_SUCCESS == rv)? ctx.order : NULL;
    return rv;
}

apr_status_t md_acme_order_update(md_acme_order_t *order, md_acme_t *acme, 
                                  md_result_t *result, apr_pool_t *p)
{
    order_ctx_t ctx;
    apr_status_t rv;
    
    assert(MD_ACME_VERSION_MAJOR(acme->version) > 1);
    ORDER_CTX_INIT(&ctx, p, order, acme, NULL, NULL, result);
    rv = md_acme_GET(acme, order->url, NULL, on_order_upd, NULL, NULL, &ctx);
    if (APR_SUCCESS != rv && APR_SUCCESS != acme->last->status) {
        md_result_dup(result, acme->last);
    }
    return rv;
}

static apr_status_t await_ready(void *baton, int attempt)
{
    order_ctx_t *ctx = baton;
    apr_status_t rv = APR_SUCCESS;
    
    (void)attempt;
    if (APR_SUCCESS != (rv = md_acme_order_update(ctx->order, ctx->acme,
                                                  ctx->result, ctx->p))) goto out;
    switch (ctx->order->status) {
        case MD_ACME_ORDER_ST_READY:
        case MD_ACME_ORDER_ST_PROCESSING:
        case MD_ACME_ORDER_ST_VALID:
            break;
        case MD_ACME_ORDER_ST_PENDING:
            rv = APR_EAGAIN;
            break;
        default:
            rv = APR_EINVAL;
            break;
    }
out:    
    return rv;
}

apr_status_t md_acme_order_await_ready(md_acme_order_t *order, md_acme_t *acme, 
                                       const md_t *md, apr_interval_time_t timeout, 
                                       md_result_t *result, apr_pool_t *p)
{
    order_ctx_t ctx;
    apr_status_t rv;
    
    assert(MD_ACME_VERSION_MAJOR(acme->version) > 1);
    ORDER_CTX_INIT(&ctx, p, order, acme, md->name, NULL, result);

    md_result_activity_setn(result, "Waiting for order to become ready");
    rv = md_util_try(await_ready, &ctx, 0, timeout, 0, 0, 1);
    md_result_log(result, MD_LOG_DEBUG);
    return rv;
}

static apr_status_t await_valid(void *baton, int attempt)
{
    order_ctx_t *ctx = baton;
    apr_status_t rv = APR_SUCCESS;

    (void)attempt;
    if (APR_SUCCESS != (rv = md_acme_order_update(ctx->order, ctx->acme, 
                                                  ctx->result, ctx->p))) goto out;
    switch (ctx->order->status) {
        case MD_ACME_ORDER_ST_VALID:
            md_result_set(ctx->result, APR_EINVAL, "ACME server order status is 'valid'.");
            break;
        case MD_ACME_ORDER_ST_PROCESSING:
            rv = APR_EAGAIN;
            break;
        case MD_ACME_ORDER_ST_INVALID:
            md_result_set(ctx->result, APR_EINVAL, "ACME server order status is 'invalid'.");
            rv = APR_EINVAL;
            break;
        default:
            rv = APR_EINVAL;
            break;
    }
out:    
    return rv;
}

apr_status_t md_acme_order_await_valid(md_acme_order_t *order, md_acme_t *acme, 
                                       const md_t *md, apr_interval_time_t timeout, 
                                       md_result_t *result, apr_pool_t *p)
{
    order_ctx_t ctx;
    apr_status_t rv;
    
    assert(MD_ACME_VERSION_MAJOR(acme->version) > 1);
    ORDER_CTX_INIT(&ctx, p, order, acme, md->name, NULL, result);

    md_result_activity_setn(result, "Waiting for finalized order to become valid");
    rv = md_util_try(await_valid, &ctx, 0, timeout, 0, 0, 1);
    md_result_log(result, MD_LOG_DEBUG);
    return rv;
}

/**************************************************************************************************/
/* processing */

apr_status_t md_acme_order_start_challenges(md_acme_order_t *order, md_acme_t *acme, 
                                            apr_array_header_t *challenge_types,
                                            md_store_t *store, const md_t *md, 
                                            apr_table_t *env, md_result_t *result, 
                                            apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    md_acme_authz_t *authz;
    const char *url, *setup_token;
    int i;
    
    md_result_activity_printf(result, "Starting challenges for domains");
    for (i = 0; i < order->authz_urls->nelts; ++i) {
        url = APR_ARRAY_IDX(order->authz_urls, i, const char*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: check AUTHZ at %s", md->name, url);
        
        if (APR_SUCCESS != (rv = md_acme_authz_retrieve(acme, p, url, &authz))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: check authz for %s",
                          md->name, authz->domain);
            goto leave;
        }

        switch (authz->state) {
            case MD_ACME_AUTHZ_S_VALID:
                break;
                
            case MD_ACME_AUTHZ_S_PENDING:
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p,
                              "%s: authorization pending for %s",
                              md->name, authz->domain);
                rv = md_acme_authz_respond(authz, acme, store, challenge_types,
                                           md->pks,
                                           md->acme_tls_1_domains, md,
                                           env, p, &setup_token, result);
                if (APR_SUCCESS != rv) {
                    goto leave;
                }
                add_setup_token(order, setup_token);
                md_acme_order_save(store, p, MD_SG_STAGING, md->name, order, 0);
                break;
                
            case MD_ACME_AUTHZ_S_INVALID:
                rv = APR_EINVAL;
                if (authz->error_type) {
                    md_result_problem_set(result, rv, authz->error_type, authz->error_detail, NULL);
                    goto leave;
                }
                /* fall through */
            default:
                rv = APR_EINVAL;
                md_result_printf(result, rv, "unexpected AUTHZ state %d for domain %s", 
                                 authz->state, authz->domain);
                md_result_log(result, MD_LOG_ERR);
                goto leave;
        }
    }
leave:    
    return rv;
}

static apr_status_t check_challenges(void *baton, int attempt)
{
    order_ctx_t *ctx = baton;
    const char *url;
    md_acme_authz_t *authz;
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < ctx->order->authz_urls->nelts; ++i) {
        url = APR_ARRAY_IDX(ctx->order->authz_urls, i, const char*);
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ctx->p, "%s: check AUTHZ at %s (attempt %d)", 
                      ctx->name, url, attempt);
        
        rv = md_acme_authz_retrieve(ctx->acme, ctx->p, url, &authz);
        if (APR_SUCCESS == rv) {
            switch (authz->state) {
                case MD_ACME_AUTHZ_S_VALID:
                    md_result_printf(ctx->result, rv, 
                                     "domain authorization for %s is valid", authz->domain);
                    break;
                case MD_ACME_AUTHZ_S_PENDING:
                    rv = APR_EAGAIN;
                    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ctx->p, 
                                  "%s: status pending at %s", authz->domain, authz->url);
                    goto leave;
                case MD_ACME_AUTHZ_S_INVALID:
                    rv = APR_EINVAL;
                    md_result_printf(ctx->result, rv,
                                     "domain authorization for %s failed, CA considers "
                                     "answer to challenge invalid%s.",
                                     authz->domain, authz->error_type? "" : ", no error given");
                    md_result_log(ctx->result, MD_LOG_ERR);
                    goto leave;
                default:
                    rv = APR_EINVAL;
                    md_result_printf(ctx->result, rv, 
                                     "domain authorization for %s failed with state %d", 
                                     authz->domain, authz->state);
                    md_result_log(ctx->result, MD_LOG_ERR);
                    goto leave;
            }
        }
        else {
            md_result_printf(ctx->result, rv, "authorization retrieval failed for domain %s", 
                             authz->domain);
        }
    }
leave:
    return rv;
}

apr_status_t md_acme_order_monitor_authzs(md_acme_order_t *order, md_acme_t *acme, 
                                          const md_t *md, apr_interval_time_t timeout, 
                                          md_result_t *result, apr_pool_t *p)
{
    order_ctx_t ctx;
    apr_status_t rv;
    
    ORDER_CTX_INIT(&ctx, p, order, acme, md->name, NULL, result);
    
    md_result_activity_printf(result, "Monitoring challenge status for %s", md->name);
    rv = md_util_try(check_challenges, &ctx, 0, timeout, 0, 0, 1);
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: checked authorizations", md->name);
    return rv;
}

