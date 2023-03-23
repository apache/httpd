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
#include "md_result.h"
#include "md_util.h"
#include "md_version.h"

#include "md_acme.h"
#include "md_acme_acct.h"


static const char *base_product= "-";

typedef struct acme_problem_status_t acme_problem_status_t;

struct acme_problem_status_t {
    const char *type; /* the ACME error string */
    apr_status_t rv;  /* what Apache status code we give it */
    int input_related; /* if error indicates wrong input value */
};

static acme_problem_status_t Problems[] = {
    { "acme:error:badCSR",                       APR_EINVAL,   1 },
    { "acme:error:badNonce",                     APR_EAGAIN,   0 },
    { "acme:error:badSignatureAlgorithm",        APR_EINVAL,   1 },
    { "acme:error:externalAccountRequired",      APR_EINVAL,   1 },
    { "acme:error:invalidContact",               APR_BADARG,   1 },
    { "acme:error:unsupportedContact",           APR_EGENERAL, 1 },
    { "acme:error:malformed",                    APR_EINVAL,   1 },
    { "acme:error:rateLimited",                  APR_BADARG,   0 },
    { "acme:error:rejectedIdentifier",           APR_BADARG,   1 },
    { "acme:error:serverInternal",               APR_EGENERAL, 0 },
    { "acme:error:unauthorized",                 APR_EACCES,   0 },
    { "acme:error:unsupportedIdentifier",        APR_BADARG,   1 },
    { "acme:error:userActionRequired",           APR_EAGAIN,   0 },
    { "acme:error:badRevocationReason",          APR_EINVAL,   1 },
    { "acme:error:caa",                          APR_EGENERAL, 0 },
    { "acme:error:dns",                          APR_EGENERAL, 0 },
    { "acme:error:connection",                   APR_EGENERAL, 0 },
    { "acme:error:tls",                          APR_EGENERAL, 0 },
    { "acme:error:incorrectResponse",            APR_EGENERAL, 0 },
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

int md_acme_problem_is_input_related(const char *problem) {
    size_t i;

    if (!problem) return 0;
    if (strstr(problem, "urn:ietf:params:") == problem) {
        problem += strlen("urn:ietf:params:");
    }
    else if (strstr(problem, "urn:") == problem) {
        problem += strlen("urn:");
    }

    for(i = 0; i < (sizeof(Problems)/sizeof(Problems[0])); ++i) {
        if (!apr_strnatcasecmp(problem, Problems[i].type)) {
            return Problems[i].input_related;
        }
    }
    return 0;
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

static apr_status_t http_update_nonce(const md_http_response_t *res, void *data)
{
    req_update_nonce(data, res->headers);
    return APR_SUCCESS;
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
    apr_pool_tag(pool, "md_acme_req");
    
    req = apr_pcalloc(pool, sizeof(*req));
    if (!req) {
        apr_pool_destroy(pool);
        return NULL;
    }
        
    req->acme = acme;
    req->p = pool;
    req->method = method;
    req->url = url;
    req->prot_fields = md_json_create(pool);
    req->max_retries = acme->max_retries;
    req->result = md_result_make(req->p, APR_SUCCESS);
    return req;
}
 
static apr_status_t acmev2_new_nonce(md_acme_t *acme)
{
    return md_http_HEAD_perform(acme->http, acme->api.v2.new_nonce, NULL, http_update_nonce, acme);
}


apr_status_t md_acme_init(apr_pool_t *p, const char *base,  int init_ssl)
{
    base_product = base;
    return init_ssl? md_crypt_init(p) : APR_SUCCESS;
}

static apr_status_t inspect_problem(md_acme_req_t *req, const md_http_response_t *res)
{
    const char *ctype;
    md_json_t *problem = NULL;
    apr_status_t rv;

    ctype = apr_table_get(req->resp_hdrs, "content-type");
    ctype = md_util_parse_ct(res->req->pool, ctype);
    if (ctype && !strcmp(ctype, "application/problem+json")) {
        /* RFC 7807 */
        rv = md_json_read_http(&problem, req->p, res);
        if (rv == APR_SUCCESS && problem) {
            const char *ptype, *pdetail;
            
            req->resp_json = problem;
            ptype = md_json_gets(problem, MD_KEY_TYPE, NULL); 
            pdetail = md_json_gets(problem, MD_KEY_DETAIL, NULL);
            req->rv = problem_status_get(ptype);
            md_result_problem_set(req->result, req->rv, ptype, pdetail,
                                  md_json_getj(problem, MD_KEY_SUBPROBLEMS, NULL));
            
            
            
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
    
    switch (res->status) {
        case 400:
            return APR_EINVAL;
        case 401: /* sectigo returns this instead of 403 */
        case 403:
            return APR_EACCES;
        case 404:
            return APR_ENOENT;
        default:
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, req->p,
                          "acme problem unknown: http status %d", res->status);
            md_result_printf(req->result, APR_EGENERAL, "unexpected http status: %d",
                             res->status);
            return req->result->status;
    }
    return APR_SUCCESS;
}

/**************************************************************************************************/
/* ACME requests with nonce handling */

static apr_status_t acmev2_req_init(md_acme_req_t *req, md_json_t *jpayload)
{
    md_data_t payload;

    md_data_null(&payload);
    if (!req->acme->acct) {
        return APR_EINVAL;
    }
    if (jpayload) {
        payload.data = md_json_writep(jpayload, req->p, MD_JSON_FMT_COMPACT);
        if (!payload.data) {
            return APR_EINVAL;
        }
    }
    else {
        payload.data = "";
    }

    payload.len = strlen(payload.data);
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->p, 
                  "acme payload(len=%" APR_SIZE_T_FMT "): %s", payload.len, payload.data);
    return md_jws_sign(&req->req_json, req->p, &payload,
                       req->prot_fields, req->acme->acct_key, req->acme->acct->url);
}

apr_status_t md_acme_req_body_init(md_acme_req_t *req, md_json_t *payload)
{
    return req->acme->req_init_fn(req, payload);
}

static apr_status_t md_acme_req_done(md_acme_req_t *req, apr_status_t rv)
{
    if (req->result->status != APR_SUCCESS) {
        if (req->on_err) {
            req->on_err(req, req->result, req->baton);
        }
    }
    /* An error in rv superceeds the result->status */
    if (APR_SUCCESS != rv) req->result->status = rv;
    rv = req->result->status;
    /* transfer results into the acme's central result for longer life and later inspection */
    md_result_dup(req->acme->last, req->result);
    if (req->p) {
        apr_pool_destroy(req->p);
    }
    return rv;
}

static apr_status_t on_response(const md_http_response_t *res, void *data)
{
    md_acme_req_t *req = data;
    apr_status_t rv = APR_SUCCESS;
    
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
            md_result_printf(req->result, rv, "unable to process the response: "
                             "http-status=%d, content-type=%s", 
                             res->status, apr_table_get(res->headers, "Content-Type"));
            md_result_log(req->result, MD_LOG_ERR);
        }
    }
    else if (APR_EAGAIN == (rv = inspect_problem(req, res))) {
        /* leave req alive */
        return rv;
    }

    md_acme_req_done(req, rv);
    return rv;
}

static apr_status_t acmev2_GET_as_POST_init(md_acme_req_t *req, void *baton)
{
    (void)baton;
    return md_acme_req_body_init(req, NULL);
}

static apr_status_t md_acme_req_send(md_acme_req_t *req)
{
    apr_status_t rv;
    md_acme_t *acme = req->acme;
    md_data_t *body = NULL;
    md_result_t *result;

    assert(acme->url);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, req->p, 
                  "sending req: %s %s", req->method, req->url);
    md_result_reset(req->acme->last);
    result = md_result_make(req->p, APR_SUCCESS);
    
    /* Whom are we talking to? */
    if (acme->version == MD_ACME_VERSION_UNKNOWN) {
        rv = md_acme_setup(acme, result);
        if (APR_SUCCESS != rv) goto leave;
    }
    
    if (!strcmp("GET", req->method) && !req->on_init && !req->req_json) {
        /* See <https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.6.3>
         * and <https://mailarchive.ietf.org/arch/msg/acme/sotffSQ0OWV-qQJodLwWYWcEVKI>
         * and <https://community.letsencrypt.org/t/acme-v2-scheduled-deprecation-of-unauthenticated-resource-gets/74380>
         * We implement this change in ACMEv2 and higher as keeping the md_acme_GET() methods,
         * but switching them to POSTs with a empty, JWS signed, body when we call
         * our HTTP client. */
        req->method = "POST";
        req->on_init = acmev2_GET_as_POST_init;
        /*req->max_retries = 0;  don't do retries on these "GET"s */
    }
    
    /* Besides GET/HEAD, we always need a fresh nonce */
    if (strcmp("GET", req->method) && strcmp("HEAD", req->method)) {
        if (acme->version == MD_ACME_VERSION_UNKNOWN) {
            rv = md_acme_setup(acme, result);
            if (APR_SUCCESS != rv) goto leave;
        }
        if (!acme->nonce && (APR_SUCCESS != (rv = acme->new_nonce_fn(acme)))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, req->p, 
                          "error retrieving new nonce from ACME server");
            goto leave;
        }

        md_json_sets(acme->nonce, req->prot_fields, "nonce", NULL);
        md_json_sets(req->url, req->prot_fields, "url", NULL);
        acme->nonce = NULL;
    }
    
    rv = req->on_init? req->on_init(req, req->baton) : APR_SUCCESS;
    if (APR_SUCCESS != rv) goto leave;
    
    if (req->req_json) {
        body = apr_pcalloc(req->p, sizeof(*body));
        body->data = md_json_writep(req->req_json, req->p, MD_JSON_FMT_INDENT);
        body->len = strlen(body->data);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, req->p,
                      "sending JSON body: %s", body->data);
    }

    if (body && md_log_is_level(req->p, MD_LOG_TRACE4)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, req->p,
                      "req: %s %s, body:\n%s", req->method, req->url, body->data);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, req->p, 
                      "req: %s %s", req->method, req->url);
    }
    
    if (!strcmp("GET", req->method)) {
        rv = md_http_GET_perform(req->acme->http, req->url, NULL, on_response, req);
    }
    else if (!strcmp("POST", req->method)) {
        rv = md_http_POSTd_perform(req->acme->http, req->url, NULL, "application/jose+json",  
                                   body, on_response, req);
    }
    else if (!strcmp("HEAD", req->method)) {
        rv = md_http_HEAD_perform(req->acme->http, req->url, NULL, on_response, req);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, req->p, 
                      "HTTP method %s against: %s", req->method, req->url);
        rv = APR_ENOTIMPL;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, req->p, "req sent");
    
    if (APR_EAGAIN == rv && req->max_retries > 0) {
        --req->max_retries;
        rv = md_acme_req_send(req);
    }
    req = NULL;

leave:
    if (req) md_acme_req_done(req, rv);
    return rv;
}

apr_status_t md_acme_POST(md_acme_t *acme, const char *url,
                          md_acme_req_init_cb *on_init,
                          md_acme_req_json_cb *on_json,
                          md_acme_req_res_cb *on_res,
                          md_acme_req_err_cb *on_err,
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
    req->on_err = on_err;
    req->baton = baton;
    
    return md_acme_req_send(req);
}

apr_status_t md_acme_GET(md_acme_t *acme, const char *url,
                         md_acme_req_init_cb *on_init,
                         md_acme_req_json_cb *on_json,
                         md_acme_req_res_cb *on_res,
                          md_acme_req_err_cb *on_err,
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
    req->on_err = on_err;
    req->baton = baton;
    
    return md_acme_req_send(req);
}

void md_acme_report_result(md_acme_t *acme, apr_status_t rv, struct md_result_t *result)
{
    if (acme->last->status == APR_SUCCESS) {
        md_result_set(result, rv, NULL);
    }
    else {
        md_result_problem_set(result, acme->last->status, acme->last->problem, 
                              acme->last->detail, acme->last->subproblems);
    }
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
    
    rv = md_acme_GET(acme, url, NULL, on_got_json, NULL, NULL, &ctx);
    *pjson = (APR_SUCCESS == rv)? ctx.json : NULL;
    return rv;
}

/**************************************************************************************************/
/* Generic ACME operations */

void md_acme_clear_acct(md_acme_t *acme)
{
    acme->acct_id = NULL;
    acme->acct = NULL;
    acme->acct_key = NULL;
}

const char *md_acme_acct_id_get(md_acme_t *acme)
{
    return acme->acct_id;
}

const char *md_acme_acct_url_get(md_acme_t *acme)
{
    return acme->acct? acme->acct->url : NULL;
}

apr_status_t md_acme_use_acct(md_acme_t *acme, md_store_t *store,
                              apr_pool_t *p, const char *acct_id)
{
    md_acme_acct_t *acct;
    md_pkey_t *pkey;
    apr_status_t rv;

    if (APR_SUCCESS == (rv = md_acme_acct_load(&acct, &pkey,
                                               store, MD_SG_ACCOUNTS, acct_id, acme->p))) {
        if (md_acme_acct_matches_url(acct, acme->url)) {
            acme->acct_id = apr_pstrdup(p, acct_id);
            acme->acct = acct;
            acme->acct_key = pkey;
            rv = md_acme_acct_validate(acme, store, p);
        }
        else {
            /* account is from another server or, more likely, from another
             * protocol endpoint on the same server */
            rv = APR_ENOENT;
        }
    }
    return rv;
}

apr_status_t md_acme_use_acct_for_md(md_acme_t *acme, struct md_store_t *store,
                                     apr_pool_t *p, const char *acct_id,
                                     const md_t *md)
{
    md_acme_acct_t *acct;
    md_pkey_t *pkey;
    apr_status_t rv;

    if (APR_SUCCESS == (rv = md_acme_acct_load(&acct, &pkey,
                                               store, MD_SG_ACCOUNTS, acct_id, acme->p))) {
        if (md_acme_acct_matches_md(acct, md)) {
            acme->acct_id = apr_pstrdup(p, acct_id);
            acme->acct = acct;
            acme->acct_key = pkey;
            rv = md_acme_acct_validate(acme, store, p);
        }
        else {
            /* account is from another server or, more likely, from another
             * protocol endpoint on the same server */
            rv = APR_ENOENT;
        }
    }
    return rv;
}

apr_status_t md_acme_save_acct(md_acme_t *acme, apr_pool_t *p, md_store_t *store)
{
    return md_acme_acct_save(store, p, acme, &acme->acct_id, acme->acct, acme->acct_key);
}

static apr_status_t acmev2_POST_new_account(md_acme_t *acme,
                                            md_acme_req_init_cb *on_init,
                                            md_acme_req_json_cb *on_json,
                                            md_acme_req_res_cb *on_res,
                                            md_acme_req_err_cb *on_err,
                                            void *baton)
{
    return md_acme_POST(acme, acme->api.v2.new_account, on_init, on_json, on_res, on_err, baton);
}

apr_status_t md_acme_POST_new_account(md_acme_t *acme, 
                                      md_acme_req_init_cb *on_init,
                                      md_acme_req_json_cb *on_json,
                                      md_acme_req_res_cb *on_res,
                                      md_acme_req_err_cb *on_err,
                                      void *baton)
{
    return acme->post_new_account_fn(acme, on_init, on_json, on_res, on_err, baton);
}

/**************************************************************************************************/
/* ACME setup */

apr_status_t md_acme_create(md_acme_t **pacme, apr_pool_t *p, const char *url,
                            const char *proxy_url, const char *ca_file)
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
    acme->max_retries = 99;
    acme->ca_file = ca_file;

    if (APR_SUCCESS != (rv = apr_uri_parse(p, url, &uri_parsed))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "parsing ACME uri: %s", url);
        return APR_EINVAL;
    }
    
    len = strlen(uri_parsed.hostname);
    acme->sname = (len <= 16)? uri_parsed.hostname : apr_pstrdup(p, uri_parsed.hostname + len - 16);
    acme->version = MD_ACME_VERSION_UNKNOWN;
    acme->last = md_result_make(acme->p, APR_SUCCESS);
    
    *pacme = acme;
    return rv;
}

typedef struct {
    md_acme_t *acme;
    md_result_t *result;
} update_dir_ctx;

static apr_status_t update_directory(const md_http_response_t *res, void *data)
{
    md_http_request_t *req = res->req;
    md_acme_t *acme = ((update_dir_ctx *)data)->acme;
    md_result_t *result = ((update_dir_ctx *)data)->result;
    apr_status_t rv;
    md_json_t *json;
    const char *s;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, req->pool, "directory lookup response: %d", res->status);
    if (res->status == 503) {
        md_result_printf(result, APR_EAGAIN,
            "The ACME server at <%s> reports that Service is Unavailable (503). This "
            "may happen during maintenance for short periods of time.", acme->url); 
        md_result_log(result, MD_LOG_INFO);
        rv = result->status;
        goto leave;
    }
    else if (res->status < 200 || res->status >= 300) {
        md_result_printf(result, APR_EAGAIN,
            "The ACME server at <%s> responded with HTTP status %d. This "
            "is unusual. Please verify that the URL is correct and that you can indeed "
            "make request from the server to it by other means, e.g. invoking curl/wget.", 
            acme->url, res->status);
        rv = result->status;
        goto leave;
    }
    
    rv = md_json_read_http(&json, req->pool, res);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, req->pool, "reading JSON body");
        goto leave;
    }
    
    if (md_log_is_level(acme->p, MD_LOG_TRACE2)) {
        s = md_json_writep(json, req->pool, MD_JSON_FMT_INDENT);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, req->pool,
                      "response: %s", s ? s : "<failed to serialize!>");
    }
    
    /* What have we got? */
    if ((s = md_json_dups(acme->p, json, "newAccount", NULL))) {
        acme->api.v2.new_account = s;
        acme->api.v2.new_order = md_json_dups(acme->p, json, "newOrder", NULL);
        acme->api.v2.revoke_cert = md_json_dups(acme->p, json, "revokeCert", NULL);
        acme->api.v2.key_change = md_json_dups(acme->p, json, "keyChange", NULL);
        acme->api.v2.new_nonce = md_json_dups(acme->p, json, "newNonce", NULL);
        /* RFC 8555 only requires "directory" and "newNonce" resources.
         * mod_md uses "newAccount" and "newOrder" so check for them.
         * But mod_md does not use the "revokeCert" or "keyChange"
         * resources, so tolerate the absence of those keys.  In the
         * future if mod_md implements revocation or key rollover then
         * the use of those features should be predicated on the
         * server's advertised capabilities. */
        if (acme->api.v2.new_account
            && acme->api.v2.new_order
            && acme->api.v2.new_nonce) {
            acme->version = MD_ACME_VERSION_2;
        }
        acme->ca_agreement = md_json_dups(acme->p, json, "meta", MD_KEY_TOS, NULL);
        acme->eab_required = md_json_getb(json, "meta", MD_KEY_EAB_REQUIRED, NULL);
        acme->new_nonce_fn = acmev2_new_nonce;
        acme->req_init_fn = acmev2_req_init;
        acme->post_new_account_fn = acmev2_POST_new_account;
    }
    else if ((s = md_json_dups(acme->p, json, "new-authz", NULL))) {
        acme->api.v1.new_authz = s;
        acme->api.v1.new_cert = md_json_dups(acme->p, json, "new-cert", NULL);
        acme->api.v1.new_reg = md_json_dups(acme->p, json, "new-reg", NULL);
        acme->api.v1.revoke_cert = md_json_dups(acme->p, json, "revoke-cert", NULL);
        if (acme->api.v1.new_authz && acme->api.v1.new_cert
            && acme->api.v1.new_reg && acme->api.v1.revoke_cert) {
            acme->version = MD_ACME_VERSION_1;
        }
        acme->ca_agreement = md_json_dups(acme->p, json, "meta", "terms-of-service", NULL);
        /* we init that far, but will not use the v1 api */
    }

    if (MD_ACME_VERSION_UNKNOWN == acme->version) {
        md_result_printf(result, APR_EINVAL,
            "Unable to understand ACME server response from <%s>. "
            "Wrong ACME protocol version or link?", acme->url); 
        md_result_log(result, MD_LOG_WARNING);
        rv = result->status;
    }
leave:
    return rv;
}

apr_status_t md_acme_setup(md_acme_t *acme, md_result_t *result)
{
    apr_status_t rv;
    update_dir_ctx ctx;
   
    assert(acme->url);
    acme->version = MD_ACME_VERSION_UNKNOWN;
    
    if (!acme->http && APR_SUCCESS != (rv = md_http_create(&acme->http, acme->p,
                                                           acme->user_agent, acme->proxy_url))) {
        return rv;
    }
    /* TODO: maybe this should be configurable. Let's take some reasonable 
     * defaults for now that protect our client */
    md_http_set_response_limit(acme->http, 1024*1024);
    md_http_set_timeout_default(acme->http, apr_time_from_sec(10 * 60));
    md_http_set_connect_timeout_default(acme->http, apr_time_from_sec(30));
    md_http_set_stalling_default(acme->http, 10, apr_time_from_sec(30));
    md_http_set_ca_file(acme->http, acme->ca_file);
    
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, acme->p, "get directory from %s", acme->url);
    
    ctx.acme = acme;
    ctx.result = result;
    rv = md_http_GET_perform(acme->http, acme->url, NULL, update_directory, &ctx);
    
    if (APR_SUCCESS != rv && APR_SUCCESS == result->status) {
        /* If the result reports no error, we never got a response from the server */
        md_result_printf(result, rv, 
            "Unsuccessful in contacting ACME server at <%s>. If this problem persists, "
            "please check your network connectivity from your Apache server to the "
            "ACME server. Also, older servers might have trouble verifying the certificates "
            "of the ACME server. You can check if you are able to contact it manually via the "
            "curl command. Sometimes, the ACME server might be down for maintenance, "
            "so failing to contact it is not an immediate problem. Apache will "
            "continue retrying this.", acme->url);
        md_result_log(result, MD_LOG_WARNING);
    }
    return rv;
}


