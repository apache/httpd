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

md_acme_authz_t *md_acme_authz_create(apr_pool_t *p)
{
    md_acme_authz_t *authz;
    authz = apr_pcalloc(p, sizeof(*authz));
    
    return authz;
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

/**************************************************************************************************/
/* Update an existing authorization */

apr_status_t md_acme_authz_retrieve(md_acme_t *acme, apr_pool_t *p, const char *url, 
                                    md_acme_authz_t **pauthz)
{
    md_acme_authz_t *authz;
    apr_status_t rv;
    
    authz = apr_pcalloc(p, sizeof(*authz));
    authz->url = apr_pstrdup(p, url);
    rv = md_acme_authz_update(authz, acme, p);
    
    *pauthz = (APR_SUCCESS == rv)? authz : NULL;
    return rv;
}

typedef struct {
    apr_pool_t *p;
    md_acme_authz_t *authz;
} error_ctx_t;

static int copy_challenge_error(void *baton, size_t index, md_json_t *json)
{
    error_ctx_t *ctx = baton;
    
    (void)index;
    if (md_json_has_key(json, MD_KEY_ERROR, NULL)) {
        ctx->authz->error_type = md_json_dups(ctx->p, json, MD_KEY_ERROR, MD_KEY_TYPE, NULL);
        ctx->authz->error_detail = md_json_dups(ctx->p, json, MD_KEY_ERROR, MD_KEY_DETAIL, NULL);
        ctx->authz->error_subproblems = md_json_dupj(ctx->p, json, MD_KEY_ERROR, MD_KEY_SUBPROBLEMS, NULL);
    }
    return 1;
}

apr_status_t md_acme_authz_update(md_acme_authz_t *authz, md_acme_t *acme, apr_pool_t *p)
{
    md_json_t *json;
    const char *s, *err;
    md_log_level_t log_level;
    apr_status_t rv;
    error_ctx_t ctx;
    
    assert(acme);
    assert(acme->http);
    assert(authz);
    assert(authz->url);

    authz->state = MD_ACME_AUTHZ_S_UNKNOWN;
    json = NULL;
    authz->error_type = authz->error_detail = NULL;
    authz->error_subproblems = NULL;
    err = "unable to parse response";
    log_level = MD_LOG_ERR;
    
    if (APR_SUCCESS == (rv = md_acme_get_json(&json, acme, authz->url, p))
        && (s = md_json_gets(json, MD_KEY_STATUS, NULL))) {
            
        authz->domain = md_json_gets(json, MD_KEY_IDENTIFIER, MD_KEY_VALUE, NULL); 
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
            ctx.p = p;
            ctx.authz = authz;
            authz->state = MD_ACME_AUTHZ_S_INVALID;
            md_json_itera(copy_challenge_error, &ctx, json, MD_KEY_CHALLENGES, NULL);
            err = "challenge 'invalid'";
        }
    }

    if (json && authz->state == MD_ACME_AUTHZ_S_UNKNOWN) {
        err = "unable to understand response";
        rv = APR_EINVAL;
    }
    
    if (md_log_is_level(p, log_level)) {
        md_log_perror(MD_LOG_MARK, log_level, rv, p, "ACME server authz: %s for %s at %s. "
                      "Exact response was: %s", err, authz->domain, authz->url,
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
    if (md_json_has_key(json, MD_KEY_URL, NULL)) { /* ACMEv2 */
        cha->uri = md_json_dups(p, json, MD_KEY_URL, NULL);
    }
    else {                                         /* ACMEv1 */
        cha->uri = md_json_dups(p, json, MD_KEY_URI, NULL);
    }
    cha->token = md_json_dups(p, json, MD_KEY_TOKEN, NULL);
    cha->key_authz = md_json_dups(p, json, MD_KEY_KEYAUTHZ, NULL);

    return cha;
}

static apr_status_t on_init_authz_resp(md_acme_req_t *req, void *baton)
{
    md_json_t *jpayload;

    (void)baton;
    jpayload = md_json_create(req->p);
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
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ctx->p, "updated authz %s", ctx->authz->url);
    return APR_SUCCESS;
}

static apr_status_t setup_key_authz(md_acme_authz_cha_t *cha, md_acme_authz_t *authz,
                                    md_acme_t *acme, apr_pool_t *p, int *pchanged)
{
    const char *thumb64, *key_authz;
    apr_status_t rv;
    
    (void)authz;
    assert(cha);
    assert(cha->token);
    
    *pchanged = 0;
    if (APR_SUCCESS == (rv = md_jws_pkey_thumb(&thumb64, p, acme->acct_key))) {
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
                                      md_pkeys_spec_t *key_specs,
                                      apr_array_header_t *acme_tls_1_domains, const md_t *md,
                                      apr_table_t *env, md_result_t *result,
                                      const char **psetup_token, apr_pool_t *p)
{
    const char *data;
    apr_status_t rv;
    int notify_server;
    
    (void)key_specs;
    (void)env;
    (void)acme_tls_1_domains;
    (void)md;

    if (APR_SUCCESS != (rv = setup_key_authz(cha, authz, acme, p, &notify_server))) {
        goto out;
    }
    
    rv = md_store_load(store, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                       MD_SV_TEXT, (void**)&data, p);
    if ((APR_SUCCESS == rv && strcmp(cha->key_authz, data)) || APR_STATUS_IS_ENOENT(rv)) {
        const char *content = apr_psprintf(p, "%s\n", cha->key_authz);
        rv = md_store_save(store, p, MD_SG_CHALLENGES, authz->domain, MD_FN_HTTP01,
                           MD_SV_TEXT, (void*)content, 0);
        notify_server = 1;
    }
    
    if (APR_SUCCESS == rv && notify_server) {
        authz_req_ctx ctx;
        const char *event;

        /* Raise event that challenge data has been set up before we tell the
           ACME server. Clusters might want to distribute it. */
        event = apr_psprintf(p, "challenge-setup:%s:%s", MD_AUTHZ_TYPE_HTTP01, authz->domain);
        rv = md_result_raise(result, event, p);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p,
                          "%s: event '%s' failed. aborting challenge setup",
                          authz->domain, event);
            goto out;
        }
        /* challenge is setup or was changed from previous data, tell ACME server
         * so it may (re)try verification */        
        authz_req_ctx_init(&ctx, acme, NULL, authz, p);
        ctx.challenge = cha;
        rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, NULL, &ctx);
    }
out:
    *psetup_token = (APR_SUCCESS == rv)?
        apr_psprintf(p, "%s:%s", MD_AUTHZ_TYPE_HTTP01, authz->domain) : NULL;
    return rv;
}

void tls_alpn01_fnames(apr_pool_t *p, md_pkey_spec_t *kspec, char **keyfn, char **certfn )
{
    *keyfn  = apr_pstrcat(p, "acme-tls-alpn-01-", md_pkey_filename(kspec, p), NULL);
    *certfn = apr_pstrcat(p, "acme-tls-alpn-01-", md_chain_filename(kspec, p), NULL);
}

static apr_status_t cha_tls_alpn_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                          md_acme_t *acme, md_store_t *store, 
                                          md_pkeys_spec_t *key_specs,
                                          apr_array_header_t *acme_tls_1_domains, const md_t *md,
                                          apr_table_t *env, md_result_t *result,
                                          const char **psetup_token, apr_pool_t *p)
{
    const char *acme_id, *token;
    apr_status_t rv;
    int notify_server;
    md_data_t data;
    int i;

    (void)env;
    (void)md;
    if (md_array_str_index(acme_tls_1_domains, authz->domain, 0, 0) < 0) {
        rv = APR_ENOTIMPL;
        if (acme_tls_1_domains->nelts) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p,
                          "%s: protocol 'acme-tls/1' seems not enabled for this domain, "
                          "but is enabled for other associated domains. "
                          "Continuing with fingers crossed.", authz->domain);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, 0, p,
                          "%s: protocol 'acme-tls/1' seems not enabled for this or "
                          "any other associated domain. Not attempting challenge "
                          "type tls-alpn-01.", authz->domain);
            goto out;
        }
    }
    if (APR_SUCCESS != (rv = setup_key_authz(cha, authz, acme, p, &notify_server))) {
        goto out;
    }

    /* Create a "tls-alpn-01" certificate for the domain we want to authenticate.
     * The server will need to answer a TLS connection with SNI == authz->domain
     * and ALPN protocol "acme-tls/1" with this certificate.
     */
    md_data_init_str(&data, cha->key_authz);
    rv = md_crypt_sha256_digest_hex(&token, p, &data);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create tls-alpn-01 validation token",
                      authz->domain);
        goto out;
    }
    acme_id = apr_psprintf(p, "critical,DER:04:20:%s", token);

    /* Each configured key type must be generated to ensure:
     * that any fallback certs already given to mod_ssl are replaced.
     * We expect that the validation client (at the CA) can deal with at
     * least one of them.
     */

    for (i = 0; i < md_pkeys_spec_count(key_specs); ++i) {
        char *kfn, *cfn;
        md_cert_t *cha_cert;
        md_pkey_t *cha_key;
        md_pkey_spec_t *key_spec;

        key_spec = md_pkeys_spec_get(key_specs, i);
        tls_alpn01_fnames(p, key_spec, &kfn, &cfn);

        rv = md_store_load(store, MD_SG_CHALLENGES, authz->domain, cfn,
                           MD_SV_CERT, (void**)&cha_cert, p);
        if ((APR_SUCCESS == rv && !md_cert_covers_domain(cha_cert, authz->domain))
            || APR_STATUS_IS_ENOENT(rv)) {
            if (APR_SUCCESS != (rv = md_pkey_gen(&cha_key, p, key_spec))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create tls-alpn-01 %s challenge key",
                              authz->domain, md_pkey_spec_name(key_spec));
                goto out;
            }

            if (APR_SUCCESS != (rv = md_cert_make_tls_alpn_01(&cha_cert, authz->domain, acme_id, cha_key,
                                                              apr_time_from_sec(7 * MD_SECS_PER_DAY), p))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create tls-alpn-01 %s challenge cert",
                              authz->domain, md_pkey_spec_name(key_spec));
                goto out;
            }
        
            if (APR_SUCCESS == (rv = md_store_save(store, p, MD_SG_CHALLENGES, authz->domain, kfn,
                                                   MD_SV_PKEY, (void*)cha_key, 0))) {
                rv = md_store_save(store, p, MD_SG_CHALLENGES, authz->domain, cfn,
                                   MD_SV_CERT, (void*)cha_cert, 0);
            }
            ++notify_server;
        }
    }
    
    if (APR_SUCCESS == rv && notify_server) {
        authz_req_ctx ctx;
        const char *event;

        /* Raise event that challenge data has been set up before we tell the
           ACME server. Clusters might want to distribute it. */
        event = apr_psprintf(p, "challenge-setup:%s:%s", MD_AUTHZ_TYPE_TLSALPN01, authz->domain);
        rv = md_result_raise(result, event, p);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p,
                          "%s: event '%s' failed. aborting challenge setup",
                          authz->domain, event);
            goto out;
        }
        /* challenge is setup or was changed from previous data, tell ACME server
         * so it may (re)try verification */        
        authz_req_ctx_init(&ctx, acme, NULL, authz, p);
        ctx.challenge = cha;
        rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, NULL, &ctx);
    }
out:    
    *psetup_token = (APR_SUCCESS == rv)?
        apr_psprintf(p, "%s:%s", MD_AUTHZ_TYPE_TLSALPN01, authz->domain) : NULL;
    return rv;
}

static apr_status_t cha_dns_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                                     md_acme_t *acme, md_store_t *store, 
                                     md_pkeys_spec_t *key_specs,
                                     apr_array_header_t *acme_tls_1_domains, const md_t *md,
                                     apr_table_t *env, md_result_t *result,
                                     const char **psetup_token, apr_pool_t *p)
{
    const char *token;
    const char * const *argv;
    const char *cmdline, *dns01_cmd;
    apr_status_t rv;
    int exit_code, notify_server;
    authz_req_ctx ctx;
    md_data_t data;
    const char *event;

    (void)store;
    (void)key_specs;
    (void)acme_tls_1_domains;

    dns01_cmd = md->dns01_cmd;
    if (!dns01_cmd)
      dns01_cmd = apr_table_get(env, MD_KEY_CMD_DNS01);
    if (!dns01_cmd) {
        rv = APR_ENOTIMPL;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: dns-01 command not set", 
                      authz->domain);
        goto out;
    }
    
    if (APR_SUCCESS != (rv = setup_key_authz(cha, authz, acme, p, &notify_server))) {
        goto out;
    }
    
    md_data_init_str(&data, cha->key_authz);
    rv = md_crypt_sha256_digest64(&token, p, &data);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: create dns-01 token for %s",
                      md->name, authz->domain);
        goto out;
    }

    cmdline = apr_psprintf(p, "%s setup %s %s", dns01_cmd, authz->domain, token); 
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
                  "%s: dns-01 setup command: %s", authz->domain, cmdline);

    apr_tokenize_to_argv(cmdline, (char***)&argv, p);
    if (APR_SUCCESS != (rv = md_util_exec(p, argv[0], argv, &exit_code))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                      "%s: dns-01 setup command failed to execute for %s", md->name, authz->domain);
        goto out;
    }
    if (exit_code) {
        rv = APR_EGENERAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, 
                      "%s: dns-01 setup command returns %d for %s", md->name, exit_code, authz->domain);
        goto out;
    }
    
    /* Raise event that challenge data has been set up before we tell the
       ACME server. Clusters might want to distribute it. */
    event = apr_psprintf(p, "challenge-setup:%s:%s", MD_AUTHZ_TYPE_DNS01, authz->domain);
    rv = md_result_raise(result, event, p);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p,
                      "%s: event '%s' failed. aborting challenge setup",
                      authz->domain, event);
        goto out;
    }
    /* challenge is setup, tell ACME server so it may (re)try verification */
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "%s: dns-01 setup succeeded for %s",
       md->name, authz->domain);
    authz_req_ctx_init(&ctx, acme, NULL, authz, p);
    ctx.challenge = cha;
    rv = md_acme_POST(acme, cha->uri, on_init_authz_resp, authz_http_set, NULL, NULL, &ctx);
    
out:    
    *psetup_token = (APR_SUCCESS == rv)?
        apr_psprintf(p, "%s:%s %s", MD_AUTHZ_TYPE_DNS01, authz->domain, token) : NULL;
    return rv;
}

static apr_status_t cha_dns_01_teardown(md_store_t *store, const char *domain, const md_t *md,
                                        apr_table_t *env, apr_pool_t *p)
{
    const char * const *argv;
    const char *cmdline, *dns01_cmd, *dns01v;
    char *tmp, *s;
    apr_status_t rv;
    int exit_code;
    
    (void)store;

    dns01_cmd = md->dns01_cmd;
    if (!dns01_cmd)
      dns01_cmd = apr_table_get(env, MD_KEY_CMD_DNS01);
    if (!dns01_cmd) {
        rv = APR_ENOTIMPL;
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "%s: dns-01 command not set for %s",
            md->name, domain);
        goto out;
    }
    dns01v = apr_table_get(env, MD_KEY_DNS01_VERSION);
    if (!dns01v || strcmp(dns01v, "2")) {
        /* use older version of teardown args with only domain, remove token */
        tmp = apr_pstrdup(p, domain);
        s = strchr(tmp, ' ');
        if (s) {
            *s = '\0';
            domain = tmp;
        }
    }

    cmdline = apr_psprintf(p, "%s teardown %s", dns01_cmd, domain); 
    apr_tokenize_to_argv(cmdline, (char***)&argv, p);
    if (APR_SUCCESS != (rv = md_util_exec(p, argv[0], argv, &exit_code)) || exit_code) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                      "%s: dns-01 teardown command failed (exit code=%d) for %s",
                      md->name, exit_code, domain);
    }
out:    
    return rv;
}

static apr_status_t cha_teardown_dir(md_store_t *store, const char *domain, const md_t *md,
                                     apr_table_t *env, apr_pool_t *p)
{
    (void)md;
    (void)env;
    return md_store_purge(store, p, MD_SG_CHALLENGES, domain);
}

typedef apr_status_t cha_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *authz, 
                               md_acme_t *acme, md_store_t *store, 
                               md_pkeys_spec_t *key_specs,
                               apr_array_header_t *acme_tls_1_domains, const md_t *md,
                               apr_table_t *env, md_result_t *result,
                               const char **psetup_token, apr_pool_t *p);
                               
typedef apr_status_t cha_teardown(md_store_t *store, const char *domain, const md_t *md,
                                  apr_table_t *env, apr_pool_t *p);
                                 
typedef struct {
    const char *name;
    cha_setup *setup;
    cha_teardown *teardown;
} cha_type;

static const cha_type CHA_TYPES[] = {
    { MD_AUTHZ_TYPE_HTTP01,     cha_http_01_setup,      cha_teardown_dir },
    { MD_AUTHZ_TYPE_TLSALPN01,  cha_tls_alpn_01_setup,  cha_teardown_dir },
    { MD_AUTHZ_TYPE_DNS01,      cha_dns_01_setup,       cha_dns_01_teardown },
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
                                   apr_array_header_t *challenges, md_pkeys_spec_t *key_specs,
                                   apr_array_header_t *acme_tls_1_domains, const md_t *md,
                                   apr_table_t *env, apr_pool_t *p, const char **psetup_token,
                                   md_result_t *result)
{
    apr_status_t rv;
    int i, j;
    cha_find_ctx fctx;

    assert(acme);
    assert(authz);
    assert(authz->resource);

    fctx.p = p;
    fctx.accepted = NULL;
    
    /* Look in the order challenge types are defined:
     * - if they are offered by the CA, try to set it up
     * - if setup was successful, we are done and the CA will evaluate us
     * - if setup failed, continue to look for another supported challenge type
     * - if there is no overlap in types, tell the user that she has to configure
     *   either more types (dns, tls-alpn-01), make ports available or refrain
     *   from using wildcard domains when dns is not available. etc.
     * - if there was an overlap, but no setup was successful, report that. We
     *   will retry this, maybe the failure is temporary (e.g. command to setup DNS
     */
     md_result_printf(result, 0, "%s: selecting suitable authorization challenge "
                      "type, this domain supports %s",
                      authz->domain, apr_array_pstrcat(p, challenges, ' '));
    rv = APR_ENOTIMPL;
    *psetup_token = NULL;
    for (i = 0; i < challenges->nelts; ++i) {
        fctx.type = APR_ARRAY_IDX(challenges, i, const char *);
        fctx.accepted = NULL;
        md_json_itera(find_type, &fctx, authz->resource, MD_KEY_CHALLENGES, NULL);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p,
                      "%s: challenge type '%s' for %s: %s",
                      authz->domain, fctx.type, md->name,
                      fctx.accepted? "maybe acceptable" : "not applicable");

        if (fctx.accepted) {
            for (j = 0; j < (int)CHA_TYPES_LEN; ++j) {
                if (!apr_strnatcasecmp(CHA_TYPES[j].name, fctx.accepted->type)) {
                    md_result_activity_printf(result, "Setting up challenge '%s' for domain %s", 
                                              fctx.accepted->type, authz->domain);
                    rv = CHA_TYPES[j].setup(fctx.accepted, authz, acme, store, key_specs,
                                            acme_tls_1_domains, md, env, result,
                                            psetup_token, p);
                    if (APR_SUCCESS == rv) {
                        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, 
                                      "%s: set up challenge '%s' for %s", 
                                      authz->domain, fctx.accepted->type, md->name);
                        goto out;
                    }
                    md_result_printf(result, rv, "error setting up challenge '%s' for %s, "
                                     "for domain %s, looking for other option",
                                     fctx.accepted->type, authz->domain, md->name);
                    md_result_log(result, MD_LOG_INFO);
                }
            }
        }
    }
    
out:
    if (!fctx.accepted || APR_ENOTIMPL == rv) {
        rv = APR_EINVAL;
        fctx.offered = apr_array_make(p, 5, sizeof(const char*));
        md_json_itera(collect_offered, &fctx, authz->resource, MD_KEY_CHALLENGES, NULL);
        md_result_printf(result, rv, "None of offered challenge types for domain %s are supported. "
                      "The server offered '%s' and available are: '%s'.",
                      authz->domain, 
                      apr_array_pstrcat(p, fctx.offered, ' '),
                      apr_array_pstrcat(p, challenges, ' '));
        result->problem = "challenge-mismatch";
        md_result_log(result, MD_LOG_ERR);
    }
    else if (APR_SUCCESS != rv) {
        fctx.offered = apr_array_make(p, 5, sizeof(const char*));
        md_json_itera(collect_offered, &fctx, authz->resource, MD_KEY_CHALLENGES, NULL);
        md_result_printf(result, rv, "None of the offered challenge types %s offered "
                         "for domain %s could be setup successfully. Please check the "
                         "log for errors.", authz->domain, 
                         apr_array_pstrcat(p, fctx.offered, ' '));
        result->problem = "challenge-setup-failure";
        md_result_log(result, MD_LOG_ERR);
    }
    return rv;
}

apr_status_t md_acme_authz_teardown(struct md_store_t *store, const char *token,
                                    const md_t *md, apr_table_t *env, apr_pool_t *p)
{
    char *challenge, *domain;
    int i;
    
    if (strchr(token, ':')) {
        challenge = apr_pstrdup(p, token);
        domain = strchr(challenge, ':');
        *domain = '\0'; domain++;
        for (i = 0; i < (int)CHA_TYPES_LEN; ++i) {
            if (!apr_strnatcasecmp(CHA_TYPES[i].name, challenge)) {
                if (CHA_TYPES[i].teardown) {
                    return CHA_TYPES[i].teardown(store, domain, md, env, p);
                }
                break;
            }
        }
    }
    return APR_SUCCESS;
}

