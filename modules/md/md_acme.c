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
#include "md_store.h"
#include "md_util.h"
#include "md_version.h"

#include "md_acme.h"
#include "md_acme_acct.h"


static const char *base_product;

typedef struct acme_problem_status_t acme_problem_status_t;

struct acme_problem_status_t {
    const char *type;
    apr_status_t rv;
};

static acme_problem_status_t Problems[] = {
    { "acme:error:badCSR",                       APR_EINVAL },
    { "acme:error:badNonce",                     APR_EAGAIN },
    { "acme:error:badSignatureAlgorithm",        APR_EINVAL },
    { "acme:error:invalidContact",               APR_BADARG },
    { "acme:error:unsupportedContact",           APR_EGENERAL },
    { "acme:error:malformed",                    APR_EINVAL },
    { "acme:error:rateLimited",                  APR_BADARG },
    { "acme:error:rejectedIdentifier",           APR_BADARG },
    { "acme:error:serverInternal",               APR_EGENERAL },
    { "acme:error:unauthorized",                 APR_EACCES },
    { "acme:error:unsupportedIdentifier",        APR_BADARG },
    { "acme:error:userActionRequired",           APR_EAGAIN },
    { "acme:error:badRevocationReason",          APR_EINVAL },
    { "acme:error:caa",                          APR_EGENERAL },
    { "acme:error:dns",                          APR_EGENERAL },
    { "acme:error:connection",                   APR_EGENERAL },
    { "acme:error:tls",                          APR_EGENERAL },
    { "acme:error:incorrectResponse",            APR_EGENERAL },
};

static apr_status_t problem_status_get(const char *type) {
    size_t i;

    if (strstr(type, "urn:ietf:params:") == type) {
        type += strlen("urn:ietf:params:");
    }
    else if (strstr(type, "urn:") == type) {
        type += strlen("urn:");
    }
     
    for(i = 0; i < (sizeof(Problems)/sizeof(Problems[0])); ++i) {
        if (!apr_strnatcasecmp(type, Problems[i].type)) {
            return Problems[i].rv;
        }
    }
    return APR_EGENERAL;
}

apr_status_t md_acme_init(apr_pool_t *p, const char *base)
{
    base_product = base;
    return md_crypt_init(p);
}

apr_status_t md_acme_create(md_acme_t **pacme, apr_pool_t *p, const char *url,
                            const char *proxy_url)
{
    md_acme_t *acme;
    const char *err = NULL;
    apr_status_t rv;
    apr_uri_t uri_parsed;
    size_t len;
    
    if (!url) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, APR_EINVAL, p, "create ACME without url");
        return APR_EINVAL;
    }
    
    if (APR_SUCCESS != (rv = md_util_abs_uri_check(p, url, &err))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "invalid ACME uri (%s): %s", err, url);
        return rv;
    }
    
    acme = apr_pcalloc(p, sizeof(*acme));
    acme->url = url;
    acme->p = p;
    acme->user_agent = apr_psprintf(p, "%s mod_md/%s", 
                                    base_product, MOD_MD_VERSION);
    acme->proxy_url = proxy_url? apr_pstrdup(p, proxy_url) : NULL;
    acme->max_retries = 3;
    
    if (APR_SUCCESS != (rv = apr_uri_parse(p, url, &uri_parsed))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "parsing ACME uri: %s", url);
        return APR_EINVAL;
    }
    
    len = strlen(uri_parsed.hostname);
    acme->sname = (len <= 16)? uri_parsed.hostname : apr_pstrdup(p, uri_parsed.hostname + len - 16);
    
    *pacme = (APR_SUCCESS == rv)? acme : NULL;
    return rv;
}

apr_status_t md_acme_setup(md_acme_t *acme)
{
    apr_status_t rv;
    md_json_t *json;
    
    assert(acme->url);
    if (!acme->http && APR_SUCCESS != (rv = md_http_create(&acme->http, acme->p,
                                                           acme->user_agent, acme->proxy_url))) {
        return rv;
    }
    md_http_set_response_limit(acme->http, 1024*1024);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "get directory from %s", acme->url);
    
    rv = md_acme_get_json(&json, acme, acme->url, acme->p);
    if (APR_SUCCESS == rv) {
        acme->new_authz = md_json_gets(json, "new-authz", NULL);
        acme->new_cert = md_json_gets(json, "new-cert", NULL);
        acme->new_reg = md_json_gets(json, "new-reg", NULL);
        acme->revoke_cert = md_json_gets(json, "revoke-cert", NULL);
        if (acme->new_authz && acme->new_cert && acme->new_reg && acme->revoke_cert) {
            return APR_SUCCESS;
        }
        rv = APR_EINVAL;
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, acme->p, "unsuccessful in contacting ACME "
                      "server at %s. If this problem persists, please check your network "
                      "connectivity from your Apache server to the ACME server. Also, older "
                      "servers might have trouble verifying the certificates of the ACME "
                      "server. You can check if you are able to contact it manually via the "
                      "curl command. Sometimes, the ACME server might be down for maintenance, "
                      "so failing to contact it is not an immediate problem. mod_md will "
                      "continue retrying this.", acme->url);
    }
    return rv;
}

/**************************************************************************************************/
/* acme requests */

static void req_update_nonce(md_acme_t *acme, apr_table_t *hdrs)
{
    if (hdrs) {
        const char *nonce = apr_table_get(hdrs, "Replay-Nonce");
        if (nonce) {
            acme->nonce = apr_pstrdup(acme->p, nonce);
        }
    }
}

static apr_status_t http_update_nonce(const md_http_response_t *res)
{
    if (res->headers) {
        const char *nonce = apr_table_get(res->headers, "Replay-Nonce");
        if (nonce) {
            md_acme_t *acme = res->req->baton;
            acme->nonce = apr_pstrdup(acme->p, nonce);
        }
    }
    return res->rv;
}

static apr_status_t md_acme_new_nonce(md_acme_t *acme)
{
    apr_status_t rv;
    long id;
    
    rv = md_http_HEAD(acme->http, acme->new_reg, NULL, http_update_nonce, acme, &id);
    md_http_await(acme->http, id);
    return rv;
}

static md_acme_req_t *md_acme_req_create(md_acme_t *acme, const char *method, const char *url)
{
    apr_pool_t *pool;
    md_acme_req_t *req;
    apr_status_t rv;
    
    rv = apr_pool_create(&pool, acme->p);
    if (rv != APR_SUCCESS) {
        return NULL;
    }
    
    req = apr_pcalloc(pool, sizeof(*req));
    if (!req) {
        apr_pool_destroy(pool);
        return NULL;
    }
        
    req->acme = acme;
    req->p = pool;
    req->method = method;
    req->url = url;
    req->prot_hdrs = apr_table_make(pool, 5);
    if (!req->prot_hdrs) {
        apr_pool_destroy(pool);
        return NULL;
    }
    req->max_retries = acme->max_retries;
    
    return req;
}
 
apr_status_t md_acme_req_body_init(md_acme_req_t *req, md_json_t *jpayload)
{
    const char *payload;
    size_t payload_len;

    if (!req->acme->acct) {
        return APR_EINVAL;
    }

    payload = md_json_writep(jpayload, req->p, MD_JSON_FMT_COMPACT);
    if (!payload) {
        return APR_EINVAL;
    }

    payload_len = strlen(payload);
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->p, 
                  "acct payload(len=%" APR_SIZE_T_FMT "): %s", payload_len, payload);
    return md_jws_sign(&req->req_json, req->p, payload, payload_len,
                       req->prot_hdrs, req->acme->acct_key, NULL);
} 


static apr_status_t inspect_problem(md_acme_req_t *req, const md_http_response_t *res)
{
    const char *ctype;
    md_json_t *problem;
    
    ctype = apr_table_get(req->resp_hdrs, "content-type");
    if (ctype && !strcmp(ctype, "application/problem+json")) {
        /* RFC 7807 */
        md_json_read_http(&problem, req->p, res);
        if (problem) {
            const char *ptype, *pdetail;
            
            req->resp_json = problem;
            ptype = md_json_gets(problem, MD_KEY_TYPE, NULL); 
            pdetail = md_json_gets(problem, MD_KEY_DETAIL, NULL);
            req->rv = problem_status_get(ptype);
            
            if (APR_STATUS_IS_EAGAIN(req->rv)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, req->rv, req->p,
                              "acme reports %s: %s", ptype, pdetail);
            }
            else {
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, req->rv, req->p,
                              "acme problem %s: %s", ptype, pdetail);
            }
            return req->rv;
        }
    }
    
    if (APR_SUCCESS == res->rv) {
        switch (res->status) {
            case 400:
                return APR_EINVAL;
            case 403:
                return APR_EACCES;
            case 404:
                return APR_ENOENT;
            default:
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, req->p,
                              "acme problem unknown: http status %d", res->status);
                return APR_EGENERAL;
        }
    }
    return res->rv;
}

/**************************************************************************************************/
/* ACME requests with nonce handling */

static apr_status_t md_acme_req_done(md_acme_req_t *req)
{
    apr_status_t rv = req->rv;
    if (req->p) {
        apr_pool_destroy(req->p);
    }
    return rv;
}

static apr_status_t on_response(const md_http_response_t *res)
{
    md_acme_req_t *req = res->req->baton;
    apr_status_t rv = res->rv;
    
    if (APR_SUCCESS != rv) {
        goto out;
    }
    
    req->resp_hdrs = apr_table_clone(req->p, res->headers);
    req_update_nonce(req->acme, res->headers);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, req->p, "response: %d", res->status);
    if (res->status >= 200 && res->status < 300) {
        int processed = 0;
        
        if (req->on_json) {
            processed = 1;
            rv = md_json_read_http(&req->resp_json, req->p, res);
            if (APR_SUCCESS == rv) {
                if (md_log_is_level(req->p, MD_LOG_TRACE2)) {
                    const char *s;
                    s = md_json_writep(req->resp_json, req->p, MD_JSON_FMT_INDENT);
                    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, req->p,
                                  "response: %s",
                                  s ? s : "<failed to serialize!>");
                }
                rv = req->on_json(req->acme, req->p, req->resp_hdrs, req->resp_json, req->baton);
            }        
            else if (APR_STATUS_IS_ENOENT(rv)) {
                /* not JSON content, fall through */
                processed = 0;
            }
            else {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, req->p, "parsing JSON body");
            }
        }
        
        if (!processed && req->on_res) {
            processed = 1;
            rv = req->on_res(req->acme, res, req->baton);
        }
        
        if (!processed) {
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, req->p, 
                          "response: %d, content-type=%s", res->status, 
                          apr_table_get(res->headers, "Content-Type"));
        }
    }
    else if (APR_EAGAIN == (rv = inspect_problem(req, res))) {
        /* leave req alive */
        return rv;
    }

out:
    md_acme_req_done(req);
    return rv;
}

static apr_status_t md_acme_req_send(md_acme_req_t *req)
{
    apr_status_t rv;
    md_acme_t *acme = req->acme;
    const char *body = NULL;

    assert(acme->url);
    
    if (strcmp("GET", req->method) && strcmp("HEAD", req->method)) {
        if (!acme->new_authz) {
            if (APR_SUCCESS != (rv = md_acme_setup(acme))) {
                return rv;
            }
        }
        if (!acme->nonce) {
            if (APR_SUCCESS != (rv = md_acme_new_nonce(acme))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, req->p, 
                              "error retrieving new nonce from ACME server");
                return rv;
            }
        }
        
        apr_table_set(req->prot_hdrs, "nonce", acme->nonce);
        acme->nonce = NULL;
    }
    
    rv = req->on_init? req->on_init(req, req->baton) : APR_SUCCESS;
    
    if ((rv == APR_SUCCESS) && req->req_json) {
        body = md_json_writep(req->req_json, req->p, MD_JSON_FMT_INDENT);
        if (!body) {
            rv = APR_EINVAL;
        }
    }

    if (rv == APR_SUCCESS) {
        long id = 0;
        
        if (body && md_log_is_level(req->p, MD_LOG_TRACE2)) {
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, req->p, 
                          "req: POST %s, body:\n%s", req->url, body);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, req->p, 
                          "req: POST %s", req->url);
        }
        if (!strcmp("GET", req->method)) {
            rv = md_http_GET(req->acme->http, req->url, NULL, on_response, req, &id);
        }
        else if (!strcmp("POST", req->method)) {
            rv = md_http_POSTd(req->acme->http, req->url, NULL, "application/json",  
                               body, body? strlen(body) : 0, on_response, req, &id);
        }
        else if (!strcmp("HEAD", req->method)) {
            rv = md_http_HEAD(req->acme->http, req->url, NULL, on_response, req, &id);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, req->p, 
                          "HTTP method %s against: %s", req->method, req->url);
            rv = APR_ENOTIMPL;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->p, "req sent");
        md_http_await(acme->http, id);
        
        if (APR_EAGAIN == rv && req->max_retries > 0) {
            --req->max_retries;
            return md_acme_req_send(req);
        }
        req = NULL;
    }

    if (req) {
        md_acme_req_done(req);
    }
    return rv;
}

apr_status_t md_acme_POST(md_acme_t *acme, const char *url,
                          md_acme_req_init_cb *on_init,
                          md_acme_req_json_cb *on_json,
                          md_acme_req_res_cb *on_res,
                          void *baton)
{
    md_acme_req_t *req;
    
    assert(url);
    assert(on_json || on_res);

    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, acme->p, "add acme POST: %s", url);
    req = md_acme_req_create(acme, "POST", url);
    req->on_init = on_init;
    req->on_json = on_json;
    req->on_res = on_res;
    req->baton = baton;
    
    return md_acme_req_send(req);
}

apr_status_t md_acme_GET(md_acme_t *acme, const char *url,
                         md_acme_req_init_cb *on_init,
                         md_acme_req_json_cb *on_json,
                         md_acme_req_res_cb *on_res,
                         void *baton)
{
    md_acme_req_t *req;
    
    assert(url);
    assert(on_json || on_res);

    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, acme->p, "add acme GET: %s", url);
    req = md_acme_req_create(acme, "GET", url);
    req->on_init = on_init;
    req->on_json = on_json;
    req->on_res = on_res;
    req->baton = baton;
    
    return md_acme_req_send(req);
}

/**************************************************************************************************/
/* GET JSON */

typedef struct {
    apr_pool_t *pool;
    md_json_t *json;
} json_ctx;

static apr_status_t on_got_json(md_acme_t *acme, apr_pool_t *p, const apr_table_t *headers, 
                                md_json_t *jbody, void *baton)
{
    json_ctx *ctx = baton;

    (void)acme;
    (void)p;
    (void)headers;
    ctx->json = md_json_clone(ctx->pool, jbody);
    return APR_SUCCESS;
}

apr_status_t md_acme_get_json(struct md_json_t **pjson, md_acme_t *acme, 
                              const char *url, apr_pool_t *p)
{
    apr_status_t rv;
    json_ctx ctx;
    
    ctx.pool = p;
    ctx.json = NULL;
    
    rv = md_acme_GET(acme, url, NULL, on_got_json, NULL, &ctx);
    *pjson = (APR_SUCCESS == rv)? ctx.json : NULL;
    return rv;
}

