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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_engine_config.c
 *  Apache Configuration Directives
 */
                                      /* ``Damned if you do,
                                           damned if you don't.''
                                               -- Unknown        */
#include <stdio.h>
#include <stdlib.h>

#include "ssl_private.h"
#include "ssl_policies.h"
#include "util_mutex.h"
#include "ap_provider.h"

/*  _________________________________________________________________
**
**  Support for Global Configuration
**  _________________________________________________________________
*/

#define SSL_MOD_CONFIG_KEY "ssl_module"

SSLModConfigRec *ssl_config_global_create(server_rec *s)
{
    apr_pool_t *pool = s->process->pool;
    SSLModConfigRec *mc;
    void *vmc;

    apr_pool_userdata_get(&vmc, SSL_MOD_CONFIG_KEY, pool);
    if (vmc) {
        return vmc; /* reused for lifetime of the server */
    }

    /*
     * allocate an own subpool which survives server restarts
     */
    mc = (SSLModConfigRec *)apr_palloc(pool, sizeof(*mc));
    mc->pPool = pool;
    mc->bFixed = FALSE;

    /*
     * initialize per-module configuration
     */
    mc->sesscache_mode         = SSL_SESS_CACHE_OFF;
    mc->sesscache              = NULL;
    mc->pMutex                 = NULL;
    mc->aRandSeed              = apr_array_make(pool, 4,
                                                sizeof(ssl_randseed_t));
    mc->tVHostKeys             = apr_hash_make(pool);
    mc->tPrivateKey            = apr_hash_make(pool);
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
    mc->szCryptoDevice         = NULL;
#endif
#ifdef HAVE_OCSP_STAPLING
    mc->stapling_cache         = NULL;
    mc->stapling_cache_mutex   = NULL;
    mc->stapling_refresh_mutex = NULL;
#endif

    apr_pool_userdata_set(mc, SSL_MOD_CONFIG_KEY,
                          apr_pool_cleanup_null,
                          pool);

    return mc;
}

void ssl_config_global_fix(SSLModConfigRec *mc)
{
    mc->bFixed = TRUE;
}

BOOL ssl_config_global_isfixed(SSLModConfigRec *mc)
{
    return mc->bFixed;
}

/*  _________________________________________________________________
**
**  Configuration handling
**  _________________________________________________________________
*/

#ifdef HAVE_SSL_CONF_CMD
static apr_status_t modssl_ctx_config_cleanup(void *ctx)
{
    SSL_CONF_CTX_free(ctx);
    return APR_SUCCESS;
}
#endif

static void modssl_ctx_init(modssl_ctx_t *mctx, apr_pool_t *p)
{
    mctx->sc                  = NULL; /* set during module init */

    mctx->ssl_ctx             = NULL; /* set during module init */

    mctx->pks                 = NULL;
    mctx->pkp                 = NULL;

#ifdef HAVE_TLS_SESSION_TICKETS
    mctx->ticket_key          = NULL;
#endif

    mctx->protocol            = SSL_PROTOCOL_DEFAULT;
    mctx->protocol_set        = 0;

    mctx->pphrase_dialog_type = SSL_PPTYPE_UNSET;
    mctx->pphrase_dialog_path = NULL;

    mctx->cert_chain          = NULL;

    mctx->crl_path            = NULL;
    mctx->crl_file            = NULL;
    mctx->crl_check_mask      = UNSET;

    mctx->auth.ca_cert_path   = NULL;
    mctx->auth.ca_cert_file   = NULL;
    mctx->auth.cipher_suite   = NULL;
    mctx->auth.verify_depth   = UNSET;
    mctx->auth.verify_mode    = SSL_CVERIFY_UNSET;

    mctx->ocsp_enabled        = UNSET;
    mctx->ocsp_force_default  = UNSET;
    mctx->ocsp_responder      = NULL;
    mctx->ocsp_resptime_skew  = UNSET;
    mctx->ocsp_resp_maxage    = UNSET;
    mctx->ocsp_responder_timeout = UNSET;
    mctx->ocsp_use_request_nonce = UNSET;
    mctx->proxy_uri              = NULL;

/* Set OCSP Responder Certificate Verification variable */
    mctx->ocsp_noverify       = UNSET;
/* Set OCSP Responder File variables */
    mctx->ocsp_verify_flags   = 0;
    mctx->ocsp_certs_file     = NULL;
    mctx->ocsp_certs          = NULL;

#ifdef HAVE_OCSP_STAPLING
    mctx->stapling_enabled           = UNSET;
    mctx->stapling_resptime_skew     = UNSET;
    mctx->stapling_resp_maxage       = UNSET;
    mctx->stapling_cache_timeout     = UNSET;
    mctx->stapling_return_errors     = UNSET;
    mctx->stapling_fake_trylater     = UNSET;
    mctx->stapling_errcache_timeout  = UNSET;
    mctx->stapling_responder_timeout = UNSET;
    mctx->stapling_force_url         = NULL;
#endif

#ifdef HAVE_SRP
    mctx->srp_vfile =             NULL;
    mctx->srp_unknown_user_seed = NULL;
    mctx->srp_vbase =             NULL;
#endif
#ifdef HAVE_SSL_CONF_CMD
    mctx->ssl_ctx_config = SSL_CONF_CTX_new();
    apr_pool_cleanup_register(p, mctx->ssl_ctx_config,
                              modssl_ctx_config_cleanup,
                              apr_pool_cleanup_null);
    SSL_CONF_CTX_set_flags(mctx->ssl_ctx_config, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_flags(mctx->ssl_ctx_config, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(mctx->ssl_ctx_config, SSL_CONF_FLAG_CERTIFICATE);
    mctx->ssl_ctx_param = apr_array_make(p, 5, sizeof(ssl_ctx_param_t));
#endif

    mctx->ssl_check_peer_cn     = UNSET;
    mctx->ssl_check_peer_name   = UNSET;
    mctx->ssl_check_peer_expire = UNSET;
}

static void modssl_ctx_init_server(SSLSrvConfigRec *sc,
                                   apr_pool_t *p)
{
    modssl_ctx_t *mctx;

    mctx = sc->server = apr_palloc(p, sizeof(*sc->server));

    modssl_ctx_init(mctx, p);

    mctx->pks = apr_pcalloc(p, sizeof(*mctx->pks));

    mctx->pks->cert_files = apr_array_make(p, 3, sizeof(char *));
    mctx->pks->key_files  = apr_array_make(p, 3, sizeof(char *));

#ifdef HAVE_TLS_SESSION_TICKETS
    mctx->ticket_key = apr_pcalloc(p, sizeof(*mctx->ticket_key));
#endif
}

static SSLSrvConfigRec *ssl_config_server_new(apr_pool_t *p)
{
    SSLSrvConfigRec *sc = apr_palloc(p, sizeof(*sc));

    sc->mc                     = NULL;
    sc->enabled                = SSL_ENABLED_UNSET;
    sc->vhost_id               = NULL;  /* set during module init */
    sc->vhost_id_len           = 0;     /* set during module init */
    sc->session_cache_timeout  = UNSET;
    sc->cipher_server_pref     = UNSET;
    sc->insecure_reneg         = UNSET;
#ifdef HAVE_TLSEXT
    sc->strict_sni_vhost_check = SSL_ENABLED_UNSET;
#endif
#ifdef HAVE_FIPS
    sc->fips                   = UNSET;
#endif
#ifndef OPENSSL_NO_COMP
    sc->compression            = UNSET;
#endif
    sc->session_tickets        = UNSET;
    sc->policies               = NULL;
    sc->error_policy           = NULL;
    sc->enabled_on             = NULL;

    modssl_ctx_init_server(sc, p);

    return sc;
}

/*
 *  Create per-server SSL configuration
 */
void *ssl_config_server_create(apr_pool_t *p, server_rec *s)
{
    SSLSrvConfigRec *sc = ssl_config_server_new(p);

    sc->mc = ssl_config_global_create(s);

    return sc;
}

#define cfgMerge(el,unset)  mrg->el = (add->el == (unset)) ? base->el : add->el
#define cfgMergeArray(el)   mrg->el = apr_array_append(p, base->el, add->el)
#define cfgMergeString(el)  cfgMerge(el, NULL)
#define cfgMergeBool(el)    cfgMerge(el, UNSET)
#define cfgMergeInt(el)     cfgMerge(el, UNSET)

/*
 *  Merge per-server SSL configurations
 */

static void modssl_ctx_cfg_merge(apr_pool_t *p,
                                 modssl_ctx_t *base,
                                 modssl_ctx_t *add,
                                 modssl_ctx_t *mrg)
{
    if (add->protocol_set) {
        mrg->protocol = add->protocol;
    }
    else {
        mrg->protocol = base->protocol;
    }

    cfgMerge(pphrase_dialog_type, SSL_PPTYPE_UNSET);
    cfgMergeString(pphrase_dialog_path);

    cfgMergeString(cert_chain);

    cfgMerge(crl_path, NULL);
    cfgMerge(crl_file, NULL);
    cfgMergeInt(crl_check_mask);

    cfgMergeString(auth.ca_cert_path);
    cfgMergeString(auth.ca_cert_file);
    cfgMergeString(auth.cipher_suite);
    cfgMergeInt(auth.verify_depth);
    cfgMerge(auth.verify_mode, SSL_CVERIFY_UNSET);

    cfgMergeBool(ocsp_enabled);
    cfgMergeBool(ocsp_force_default);
    cfgMerge(ocsp_responder, NULL);
    cfgMergeInt(ocsp_resptime_skew);
    cfgMergeInt(ocsp_resp_maxage);
    cfgMergeInt(ocsp_responder_timeout);
    cfgMergeBool(ocsp_use_request_nonce);
    cfgMerge(proxy_uri, NULL);

/* Set OCSP Responder Certificate Verification directive */
    cfgMergeBool(ocsp_noverify);  
/* Set OCSP Responder File directive for importing */
    cfgMerge(ocsp_certs_file, NULL);

#ifdef HAVE_OCSP_STAPLING
    cfgMergeBool(stapling_enabled);
    cfgMergeInt(stapling_resptime_skew);
    cfgMergeInt(stapling_resp_maxage);
    cfgMergeInt(stapling_cache_timeout);
    cfgMergeBool(stapling_return_errors);
    cfgMergeBool(stapling_fake_trylater);
    cfgMergeInt(stapling_errcache_timeout);
    cfgMergeInt(stapling_responder_timeout);
    cfgMerge(stapling_force_url, NULL);
#endif

#ifdef HAVE_SRP
    cfgMergeString(srp_vfile);
    cfgMergeString(srp_unknown_user_seed);
#endif

#ifdef HAVE_SSL_CONF_CMD
    cfgMergeArray(ssl_ctx_param);
#endif

    cfgMergeBool(ssl_check_peer_cn);
    cfgMergeBool(ssl_check_peer_name);
    cfgMergeBool(ssl_check_peer_expire);
}

static void modssl_ctx_cfg_merge_server(apr_pool_t *p,
                                        modssl_ctx_t *base,
                                        modssl_ctx_t *add,
                                        modssl_ctx_t *mrg)
{
    modssl_ctx_cfg_merge(p, base, add, mrg);

    cfgMergeArray(pks->cert_files);
    cfgMergeArray(pks->key_files);

    cfgMergeString(pks->ca_name_path);
    cfgMergeString(pks->ca_name_file);

#ifdef HAVE_TLS_SESSION_TICKETS
    cfgMergeString(ticket_key->file_path);
#endif
}

static void ssl_policy_apply(SSLSrvConfigRec *sc, apr_pool_t *p);
static void ssl_dir_policy_apply(SSLDirConfigRec *dc, apr_pool_t *p);

void *ssl_config_server_merge(apr_pool_t *p, void *basev, void *addv)
{
    SSLSrvConfigRec *base = (SSLSrvConfigRec *)basev;
    SSLSrvConfigRec *add  = (SSLSrvConfigRec *)addv;
    SSLSrvConfigRec *mrg  = ssl_config_server_new(p);

    /* This is a NOP, unless a policy has not been applied yet */
    ssl_policy_apply(base, p);
    ssl_policy_apply(add, p);
    
    cfgMerge(mc, NULL);
    cfgMerge(enabled, SSL_ENABLED_UNSET);
    cfgMergeInt(session_cache_timeout);
    cfgMergeBool(cipher_server_pref);
    cfgMergeBool(insecure_reneg);
#ifdef HAVE_TLSEXT
    cfgMerge(strict_sni_vhost_check, SSL_ENABLED_UNSET);
#endif
#ifdef HAVE_FIPS
    cfgMergeBool(fips);
#endif
#ifndef OPENSSL_NO_COMP
    cfgMergeBool(compression);
#endif
    cfgMergeBool(session_tickets);

    mrg->policies = NULL;
    cfgMergeString(error_policy);

    mrg->enabled_on = (add->enabled == SSL_ENABLED_UNSET)? base->enabled_on : add->enabled_on;
                         
    modssl_ctx_cfg_merge_server(p, base->server, add->server, mrg->server);

    return mrg;
}

/*
 *  Create per-directory SSL configuration
 */

static void modssl_ctx_init_proxy(SSLDirConfigRec *dc,
                                  apr_pool_t *p)
{
    modssl_ctx_t *mctx;

    mctx = dc->proxy = apr_palloc(p, sizeof(*dc->proxy));

    modssl_ctx_init(mctx, p);

    mctx->pkp = apr_palloc(p, sizeof(*mctx->pkp));

    mctx->pkp->cert_file = NULL;
    mctx->pkp->cert_path = NULL;
    mctx->pkp->ca_cert_file = NULL;
    mctx->pkp->certs     = NULL;
    mctx->pkp->ca_certs  = NULL;
}

void *ssl_config_perdir_create(apr_pool_t *p, char *dir)
{
    SSLDirConfigRec *dc = apr_palloc(p, sizeof(*dc));

    dc->bSSLRequired  = FALSE;
    dc->aRequirement  = apr_array_make(p, 4, sizeof(ssl_require_t));
    dc->nOptions      = SSL_OPT_NONE|SSL_OPT_RELSET;
    dc->nOptionsAdd   = SSL_OPT_NONE;
    dc->nOptionsDel   = SSL_OPT_NONE;

    dc->szCipherSuite          = NULL;
    dc->nVerifyClient          = SSL_CVERIFY_UNSET;
    dc->nVerifyDepth           = UNSET;

    dc->szUserName             = NULL;

    dc->nRenegBufferSize = UNSET;

    dc->proxy_enabled = UNSET;
    modssl_ctx_init_proxy(dc, p);
    dc->proxy_post_config = FALSE;

    dc->policies = NULL;
    dc->error_policy = NULL;
    
    return dc;
}

/*
 *  Merge per-directory SSL configurations
 */

static void modssl_ctx_cfg_merge_proxy(apr_pool_t *p,
                                       modssl_ctx_t *base,
                                       modssl_ctx_t *add,
                                       modssl_ctx_t *mrg)
{
    modssl_ctx_cfg_merge(p, base, add, mrg);

    cfgMergeString(pkp->cert_file);
    cfgMergeString(pkp->cert_path);
    cfgMergeString(pkp->ca_cert_file);
}

void *ssl_config_perdir_merge(apr_pool_t *p, void *basev, void *addv)
{
    SSLDirConfigRec *base = (SSLDirConfigRec *)basev;
    SSLDirConfigRec *add  = (SSLDirConfigRec *)addv;
    SSLDirConfigRec *mrg  = (SSLDirConfigRec *)apr_palloc(p, sizeof(*mrg));

    ssl_dir_policy_apply(base, p);
    ssl_dir_policy_apply(add, p);
    
    cfgMerge(bSSLRequired, FALSE);
    cfgMergeArray(aRequirement);

    if (add->nOptions & SSL_OPT_RELSET) {
        mrg->nOptionsAdd =
            (base->nOptionsAdd & ~(add->nOptionsDel)) | add->nOptionsAdd;
        mrg->nOptionsDel =
            (base->nOptionsDel & ~(add->nOptionsAdd)) | add->nOptionsDel;
        mrg->nOptions    =
            (base->nOptions    & ~(mrg->nOptionsDel)) | mrg->nOptionsAdd;
    }
    else {
        mrg->nOptions    = add->nOptions;
        mrg->nOptionsAdd = add->nOptionsAdd;
        mrg->nOptionsDel = add->nOptionsDel;
    }

    cfgMergeString(szCipherSuite);
    cfgMerge(nVerifyClient, SSL_CVERIFY_UNSET);
    cfgMergeInt(nVerifyDepth);

    cfgMergeString(szUserName);

    cfgMergeInt(nRenegBufferSize);

    mrg->proxy_post_config = add->proxy_post_config;
    if (!add->proxy_post_config) {
        cfgMergeBool(proxy_enabled);
        modssl_ctx_init_proxy(mrg, p);
        modssl_ctx_cfg_merge_proxy(p, base->proxy, add->proxy, mrg->proxy);
    }
    else {
        /* post_config hook has already merged and initialized the
         * proxy context, use it.
         */
        mrg->proxy_enabled = add->proxy_enabled;
        mrg->proxy = add->proxy;
    }

    mrg->policies = NULL;
    cfgMergeString(error_policy);

    return mrg;
}

/* Simply merge conf with base into conf, no third party. */
void ssl_config_proxy_merge(apr_pool_t *p,
                            SSLDirConfigRec *base,
                            SSLDirConfigRec *conf)
{
    if (conf->proxy_enabled == UNSET) {
        conf->proxy_enabled = base->proxy_enabled;
    }
    modssl_ctx_cfg_merge_proxy(p, base->proxy, conf->proxy, conf->proxy);
}

/*  _________________________________________________________________
**
**  Policy handling
**  _________________________________________________________________
*/

static void add_policy(apr_hash_t *policies, apr_pool_t *p, const char *name,
                       int protocols, const char *ciphers, 
                       int honor_order, int compression, int session_tickets,
                       ssl_verify_t proxy_verify_mode, int proxy_verify_depth)
{
    SSLPolicyRec *policy;
    
    policy = apr_pcalloc(p, sizeof(*policy));
    policy->name = name;
    policy->sc = ssl_config_server_new(p);
    policy->dc = ssl_config_perdir_create(p, "/");
    
    if (protocols || ciphers) {
        policy->sc->server->protocol_set      = 1;
        policy->sc->server->protocol          = protocols;
        policy->dc->proxy->protocol_set       = 1;
        policy->dc->proxy->protocol           = protocols;
    }
    
    if (ciphers) {
        policy->sc->server->auth.cipher_suite = ciphers;
        policy->dc->proxy->auth.cipher_suite = ciphers;
    }

    policy->sc->compression               = compression ? TRUE : FALSE;
    policy->sc->session_tickets           = session_tickets ? TRUE : FALSE;
    
    policy->dc->proxy->auth.verify_mode  = proxy_verify_mode;
    if (proxy_verify_depth >= 0) {
        policy->dc->proxy->auth.verify_depth = proxy_verify_depth;
    }
    
    apr_hash_set(policies, policy->name, APR_HASH_KEY_STRING, policy);
}

static apr_hash_t *get_policies(apr_pool_t *p, int create)
{
    apr_hash_t *policies;
    void *vp;
    
    apr_pool_userdata_get(&vp, SSL_MOD_POLICIES_KEY, p);
    if (vp) {
        return vp; /* reused for lifetime of the pool */
    }
    if (create) {
        policies = apr_hash_make(p);
        
#if SSL_POLICY_MODERN
        add_policy(policies, p, "modern", 
                   SSL_POLICY_MODERN_PROTOCOLS, 
                   SSL_POLICY_MODERN_CIPHERS, 
                   SSL_POLICY_HONOR_ORDER, 
                   SSL_POLICY_COMPRESSION, 
                   SSL_POLICY_SESSION_TICKETS, 
                   SSL_POLICY_PROXY_VERIFY_MODE, 
                   SSL_POLICY_PROXY_VERIFY_DEPTH);
#endif        
#if SSL_POLICY_INTERMEDIATE
        add_policy(policies, p, "intermediate", 
                   SSL_POLICY_INTERMEDIATE_PROTOCOLS, 
                   SSL_POLICY_INTERMEDIATE_CIPHERS, 
                   SSL_POLICY_HONOR_ORDER, 
                   SSL_POLICY_COMPRESSION, 
                   SSL_POLICY_SESSION_TICKETS, 
                   SSL_POLICY_PROXY_VERIFY_MODE, 
                   SSL_POLICY_PROXY_VERIFY_DEPTH);
#endif        
#if SSL_POLICY_OLD
        add_policy(policies, p, "old", 
                   SSL_POLICY_OLD_PROTOCOLS, 
                   SSL_POLICY_OLD_CIPHERS, 
                   SSL_POLICY_HONOR_ORDER, 
                   SSL_POLICY_COMPRESSION, 
                   SSL_POLICY_SESSION_TICKETS, 
                   SSL_CVERIFY_NONE, 
                   SSL_POLICY_PROXY_VERIFY_DEPTH);
#endif        
        
        apr_pool_userdata_set(policies, SSL_MOD_POLICIES_KEY,
                              apr_pool_cleanup_null, p);
        return policies;
    }
    return NULL;
}

static int policy_collect_names(void *baton, const void *key, apr_ssize_t klen, const void *val)
{
    apr_array_header_t *names = baton;
    APR_ARRAY_PUSH(names, const char *) = (const char*)key;
    return 1;
}

static int qstrcmp(const void *v1, const void *v2)
{
    return strcmp(*(const char**)v1, *(const char**)v2);
}

static apr_array_header_t *get_policy_names(apr_pool_t *p, int create)
{
    apr_array_header_t *names = apr_array_make(p, 10, sizeof(const char*));
    apr_hash_t *policies = get_policies(p, create);
    
    if (policies) {
        apr_hash_do(policy_collect_names, names, policies);
        qsort(names->elts, names->nelts, sizeof(const char*), qstrcmp);
    }
    return names;
}

SSLPolicyRec *ssl_policy_lookup(apr_pool_t *pool, const char *name)
{
    apr_hash_t *policies = get_policies(pool, 0);
    if (policies) {
        return apr_hash_get(policies, name, APR_HASH_KEY_STRING);
    }
    else if ((pool = apr_pool_parent_get(pool))) {
        return ssl_policy_lookup(pool, name);
    }
    return NULL;
}

static void ssl_policy_set(apr_pool_t *pool, SSLPolicyRec *policy)
{
    apr_hash_t *policies = get_policies(pool, 1);
    return apr_hash_set(policies, policy->name, APR_HASH_KEY_STRING, policy);
}

const char *ssl_cmd_SSLPolicyDefine(cmd_parms *cmd, void *mconfig, const char *arg)
{
    server_rec *s = cmd->server;
    SSLSrvConfigRec *sc = mySrvConfig(s);
    SSLDirConfigRec *dc = ap_get_module_config(s->lookup_defaults, &ssl_module);
    SSLPolicyRec *policy;
    const char *endp = ap_strrchr_c(arg, '>');
    const char *err, *name;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
        
    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, "> directive missing closing '>'", NULL);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp-arg);
    if (!arg || !*arg) {
        return "<SSLPolicy > block must specify a name";
    }

    name = ap_getword_white(cmd->pool, &arg);
    if (*arg != '\0') {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, "> takes only 1 argument", NULL);
    }
    
    policy = apr_pcalloc(cmd->pool, sizeof(*policy));
    policy->name = name;
    policy->sc = ssl_config_server_new(cmd->pool);
    policy->dc = ssl_config_perdir_create(cmd->pool, "/");/* TODO */

    ap_set_module_config(s->module_config,  &ssl_module, policy->sc);
    ap_set_module_config(s->lookup_defaults,  &ssl_module, policy->dc);
    
    err = ap_walk_config(cmd->directive->first_child, cmd, cmd->context);
    if (!err) {
        /* If this new policy uses other policies, we need to merge it
         * before adding, otherwise a policy cannot re-use an existing one */
        ssl_policy_apply(policy->sc, cmd->pool);
        ssl_dir_policy_apply(policy->dc, cmd->pool);
        /* time to persist */
        ssl_policy_set(cmd->pool, policy);
    }
    
    ap_set_module_config(s->module_config,  &ssl_module, sc);
    ap_set_module_config(s->lookup_defaults,  &ssl_module, dc);

    return err;
}

const char *ssl_cmd_SSLPolicyApply(cmd_parms *cmd, void *mconfig, const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    
    if (!sc->policies) {
        sc->policies = apr_array_make(cmd->pool, 5, sizeof(const char*));
    }
    APR_ARRAY_PUSH(sc->policies, const char *) = arg;

    /* Also apply the proxy parts of the policy */
    return ssl_cmd_SSLProxyPolicyApply(cmd, mconfig, arg);
}

const char *ssl_cmd_SSLProxyPolicyApply(cmd_parms *cmd, void *mconfig, const char *arg)
{
    SSLDirConfigRec *dc = ap_get_module_config(cmd->server->lookup_defaults, &ssl_module);
    
    if (!dc->policies) {
        dc->policies = apr_array_make(cmd->pool, 5, sizeof(const char*));
    }
    APR_ARRAY_PUSH(dc->policies, const char *) = arg;

    return NULL;
}

void ssl_policy_apply(SSLSrvConfigRec *sc, apr_pool_t *p)
{
    SSLSrvConfigRec *mrg;
    SSLPolicyRec *policy;
    apr_array_header_t *policies;
    const char *name;
    int i;

    policies = sc->policies;
    if (policies && policies->nelts > 0 && !sc->error_policy) {
        sc->policies = NULL;
        for (i = policies->nelts - 1; i >= 0; --i) {
            name = APR_ARRAY_IDX(policies, i, const char *);
            policy = ssl_policy_lookup(p, name);
            if (policy) {
                mrg = ssl_config_server_merge(p, policy->sc, sc);
                /* apply in place */
                memcpy(sc, mrg, sizeof(*sc));
            }
            else {
                sc->error_policy = name;
                break;
                /* report error policies in post_config */
            }
        }
    }
}

void ssl_dir_policy_apply(SSLDirConfigRec *dc, apr_pool_t *p)
{
    SSLDirConfigRec *mrg;
    SSLPolicyRec *policy;
    apr_array_header_t *policies;
    const char *name;
    int i;
    
    policies = dc->policies;
    if (policies && policies->nelts > 0 &&!dc->error_policy) {
        dc->policies = NULL;
        for (i = policies->nelts - 1; i >= 0; --i) {
            name = APR_ARRAY_IDX(policies, i, const char *);
            policy = ssl_policy_lookup(p, name);
            if (policy) {
                mrg = ssl_config_perdir_merge(p, policy->dc, dc);
                /* apply in place */
                memcpy(dc, mrg, sizeof(*dc));
            }
            else {
                dc->error_policy = name;
                break;
                /* report error policies in post_config */
            }
        }
    }
}

/*
 *  Configuration functions for particular directives
 */

const char *ssl_cmd_SSLPassPhraseDialog(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;
    int arglen = strlen(arg);

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (strcEQ(arg, "builtin")) {
        sc->server->pphrase_dialog_type  = SSL_PPTYPE_BUILTIN;
        sc->server->pphrase_dialog_path = NULL;
    }
    else if ((arglen > 5) && strEQn(arg, "exec:", 5)) {
        sc->server->pphrase_dialog_type  = SSL_PPTYPE_FILTER;
        sc->server->pphrase_dialog_path =
            ap_server_root_relative(cmd->pool, arg+5);
        if (!sc->server->pphrase_dialog_path) {
            return apr_pstrcat(cmd->pool,
                               "Invalid SSLPassPhraseDialog exec: path ",
                               arg+5, NULL);
        }
        if (!ssl_util_path_check(SSL_PCM_EXISTS,
                                 sc->server->pphrase_dialog_path,
                                 cmd->pool))
        {
            return apr_pstrcat(cmd->pool,
                               "SSLPassPhraseDialog: file '",
                               sc->server->pphrase_dialog_path,
                               "' does not exist", NULL);
        }

    }
    else if ((arglen > 1) && (arg[0] == '|')) {
        sc->server->pphrase_dialog_type  = SSL_PPTYPE_PIPE;
        sc->server->pphrase_dialog_path = arg + 1;
    }
    else {
        return "SSLPassPhraseDialog: Invalid argument";
    }

    return NULL;
}

#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
const char *ssl_cmd_SSLCryptoDevice(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err;
    ENGINE *e;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (strcEQ(arg, "builtin")) {
        mc->szCryptoDevice = NULL;
    }
    else if ((e = ENGINE_by_id(arg))) {
        mc->szCryptoDevice = arg;
        ENGINE_free(e);
    }
    else {
        err = "SSLCryptoDevice: Invalid argument; must be one of: "
              "'builtin' (none)";
        e = ENGINE_get_first();
        while (e) {
            err = apr_pstrcat(cmd->pool, err, ", '", ENGINE_get_id(e),
                                         "' (", ENGINE_get_name(e), ")", NULL);
            /* Iterate; this call implicitly decrements the refcount
             * on the 'old' e, per the docs in engine.h. */
            e = ENGINE_get_next(e);
        }
        return err;
    }

    return NULL;
}
#endif

const char *ssl_cmd_SSLRandomSeed(cmd_parms *cmd,
                                  void *dcfg,
                                  const char *arg1,
                                  const char *arg2,
                                  const char *arg3)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err;
    ssl_randseed_t *seed;
    int arg2len = strlen(arg2);

    /* replace: check_no_policy_and(flags) */
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (ssl_config_global_isfixed(mc)) {
        return NULL;
    }

    seed = apr_array_push(mc->aRandSeed);

    if (strcEQ(arg1, "startup")) {
        seed->nCtx = SSL_RSCTX_STARTUP;
    }
    else if (strcEQ(arg1, "connect")) {
        seed->nCtx = SSL_RSCTX_CONNECT;
    }
    else {
        return apr_pstrcat(cmd->pool, "SSLRandomSeed: "
                           "invalid context: `", arg1, "'",
                           NULL);
    }

    if ((arg2len > 5) && strEQn(arg2, "file:", 5)) {
        seed->nSrc   = SSL_RSSRC_FILE;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+5);
    }
    else if ((arg2len > 5) && strEQn(arg2, "exec:", 5)) {
        seed->nSrc   = SSL_RSSRC_EXEC;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+5);
    }
    else if ((arg2len > 4) && strEQn(arg2, "egd:", 4)) {
#ifdef HAVE_RAND_EGD
        seed->nSrc   = SSL_RSSRC_EGD;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+4);
#else
        return apr_pstrcat(cmd->pool, "Invalid SSLRandomSeed entropy source `",
                           arg2, "': This version of " MODSSL_LIBRARY_NAME
                           " does not support the Entropy Gathering Daemon "
                           "(EGD).", NULL);
#endif
    }
    else if (strcEQ(arg2, "builtin")) {
        seed->nSrc   = SSL_RSSRC_BUILTIN;
        seed->cpPath = NULL;
    }
    else {
        seed->nSrc   = SSL_RSSRC_FILE;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2);
    }

    if (seed->nSrc != SSL_RSSRC_BUILTIN) {
        if (!seed->cpPath) {
            return apr_pstrcat(cmd->pool,
                               "Invalid SSLRandomSeed path ",
                               arg2, NULL);
        }
        if (!ssl_util_path_check(SSL_PCM_EXISTS, seed->cpPath, cmd->pool)) {
            return apr_pstrcat(cmd->pool,
                               "SSLRandomSeed: source path '",
                               seed->cpPath, "' does not exist", NULL);
        }
    }

    if (!arg3) {
        seed->nBytes = 0; /* read whole file */
    }
    else {
        if (seed->nSrc == SSL_RSSRC_BUILTIN) {
            return "SSLRandomSeed: byte specification not "
                   "allowed for builtin seed source";
        }

        seed->nBytes = atoi(arg3);

        if (seed->nBytes < 0) {
            return "SSLRandomSeed: invalid number of bytes specified";
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLEngine(cmd_parms *cmd, void *dcfg, const char *args)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *w, *err;
    server_addr_rec **psar;
    server_rec s;
        
    w = ap_getword_conf(cmd->pool, &args);

    if (*w == '\0') {
        return "SSLEngine takes at least one argument";
    }
    
    if (*args == 0) {
        if (!strcasecmp(w, "On")) {
            sc->enabled = SSL_ENABLED_TRUE;
            sc->enabled_on = NULL;
            return NULL;
        }
        else if (!strcasecmp(w, "Off")) {
            sc->enabled = SSL_ENABLED_FALSE;
            sc->enabled_on = NULL;
            return NULL;
        }
        else if (!strcasecmp(w, "Optional")) {
            sc->enabled = SSL_ENABLED_OPTIONAL;
            sc->enabled_on = NULL;
            return NULL;
        }
    }
    
    memset(&s, 0, sizeof(s));
    err = ap_parse_vhost_addrs(cmd->pool, w, &s);
    sc->enabled_on = s.addrs;
    sc->enabled = SSL_ENABLED_TRUE;
    
    if (!err && *args) {
        s.addrs = NULL;
        err = ap_parse_vhost_addrs(cmd->pool, args, &s);
        if (!err && s.addrs) {
            psar = &sc->enabled_on;
            while (*psar) {
                psar = &(*psar)->next;
            }
            *psar = s.addrs;
        }
    }
    return err;
}

const char *ssl_cmd_SSLFIPS(cmd_parms *cmd, void *dcfg, int flag)
{
#ifdef HAVE_FIPS
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
#endif
    const char *err;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

#ifdef HAVE_FIPS
    if ((sc->fips != UNSET) && (sc->fips != (BOOL)(flag ? TRUE : FALSE)))
        return "Conflicting SSLFIPS options, cannot be both On and Off";
    sc->fips = flag ? TRUE : FALSE;
#else
    if (flag)
        return "SSLFIPS invalid, rebuild httpd and openssl compiled for FIPS";
#endif

    return NULL;
}

const char *ssl_cmd_SSLCipherSuite(cmd_parms *cmd,
                                   void *dcfg,
                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    /* always disable null and export ciphers */
    arg = apr_pstrcat(cmd->pool, arg, ":!aNULL:!eNULL:!EXP", NULL);

    if (cmd->path) {
        dc->szCipherSuite = arg;
    }
    else {
        sc->server->auth.cipher_suite = arg;
    }

    return NULL;
}

#define SSL_FLAGS_CHECK_FILE \
    (SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO)

#define SSL_FLAGS_CHECK_DIR \
    (SSL_PCM_EXISTS|SSL_PCM_ISDIR)

static const char *ssl_cmd_check_file(cmd_parms *parms,
                                      const char **file)
{
    const char *filepath = ap_server_root_relative(parms->pool, *file);

    if (!filepath) {
        return apr_pstrcat(parms->pool, parms->cmd->name,
                           ": Invalid file path ", *file, NULL);
    }
    *file = filepath;

    if (ssl_util_path_check(SSL_FLAGS_CHECK_FILE, *file, parms->pool)) {
        return NULL;
    }

    return apr_pstrcat(parms->pool, parms->cmd->name,
                       ": file '", *file,
                       "' does not exist or is empty", NULL);

}

const char *ssl_cmd_SSLCompression(cmd_parms *cmd, void *dcfg, int flag)
{
#if !defined(OPENSSL_NO_COMP)
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
#ifndef SSL_OP_NO_COMPRESSION
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
        return "This version of OpenSSL does not support enabling "
               "SSLCompression within <VirtualHost> sections.";
#endif
    if (flag) {
        /* Some (packaged) versions of OpenSSL do not support
         * compression by default.  Enabling this directive would not
         * have the desired effect, so fail with an error. */
        STACK_OF(SSL_COMP) *meths = SSL_COMP_get_compression_methods();

        if (sk_SSL_COMP_num(meths) == 0) {
            return "This version of OpenSSL does not have any compression methods "
                "available, cannot enable SSLCompression.";
        }
    }
    sc->compression = flag ? TRUE : FALSE;
    return NULL;
#else
    return "Setting Compression mode unsupported; not implemented by the SSL library";
#endif
}

const char *ssl_cmd_SSLHonorCipherOrder(cmd_parms *cmd, void *dcfg, int flag)
{
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->cipher_server_pref = flag?TRUE:FALSE;
    return NULL;
#else
    return "SSLHonorCipherOrder unsupported; not implemented by the SSL library";
#endif
}

const char *ssl_cmd_SSLSessionTickets(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
#ifndef SSL_OP_NO_TICKET
    return "This version of OpenSSL does not support using "
           "SSLSessionTickets.";
#endif
    sc->session_tickets = flag ? TRUE : FALSE;
    return NULL;
}

const char *ssl_cmd_SSLInsecureRenegotiation(cmd_parms *cmd, void *dcfg, int flag)
{
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->insecure_reneg = flag?TRUE:FALSE;
    return NULL;
#else
    return "The SSLInsecureRenegotiation directive is not available "
        "with this SSL library";
#endif
}


static const char *ssl_cmd_check_dir(cmd_parms *parms,
                                     const char **dir)
{
    const char *dirpath = ap_server_root_relative(parms->pool, *dir);

    if (!dirpath) {
        return apr_pstrcat(parms->pool, parms->cmd->name,
                           ": Invalid dir path ", *dir, NULL);
    }
    *dir = dirpath;

    if (ssl_util_path_check(SSL_FLAGS_CHECK_DIR, *dir, parms->pool)) {
        return NULL;
    }

    return apr_pstrcat(parms->pool, parms->cmd->name,
                       ": directory '", *dir,
                       "' does not exist", NULL);

}

const char *ssl_cmd_SSLCertificateFile(cmd_parms *cmd,
                                       void *dcfg,
                                       const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    *(const char **)apr_array_push(sc->server->pks->cert_files) = arg;
    
    return NULL;
}

const char *ssl_cmd_SSLCertificateKeyFile(cmd_parms *cmd,
                                          void *dcfg,
                                          const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    *(const char **)apr_array_push(sc->server->pks->key_files) = arg;

    return NULL;
}

const char *ssl_cmd_SSLCertificateChainFile(cmd_parms *cmd,
                                            void *dcfg,
                                            const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->server->cert_chain = arg;

    return NULL;
}

#ifdef HAVE_TLS_SESSION_TICKETS
const char *ssl_cmd_SSLSessionTicketKeyFile(cmd_parms *cmd,
                                            void *dcfg,
                                            const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->server->ticket_key->file_path = arg;

    return NULL;
}
#endif

#define NO_PER_DIR_SSL_CA \
    "Your SSL library does not have support for per-directory CA"

const char *ssl_cmd_SSLCACertificatePath(cmd_parms *cmd,
                                         void *dcfg,
                                         const char *arg)
{
    /*SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;*/
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    if (cmd->path) {
        return NO_PER_DIR_SSL_CA;
    }

    /* XXX: bring back per-dir */
    sc->server->auth.ca_cert_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLCACertificateFile(cmd_parms *cmd,
                                         void *dcfg,
                                         const char *arg)
{
    /*SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;*/
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    if (cmd->path) {
        return NO_PER_DIR_SSL_CA;
    }

    /* XXX: bring back per-dir */
    sc->server->auth.ca_cert_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLCADNRequestPath(cmd_parms *cmd, void *dcfg,
                                       const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->server->pks->ca_name_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLCADNRequestFile(cmd_parms *cmd, void *dcfg,
                                       const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->server->pks->ca_name_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLCARevocationPath(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->server->crl_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLCARevocationFile(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->server->crl_file = arg;

    return NULL;
}

static const char *ssl_cmd_crlcheck_parse(cmd_parms *parms,
                                          const char *arg,
                                          int *mask)
{
    const char *w;

    w = ap_getword_conf(parms->temp_pool, &arg);
    if (strcEQ(w, "none")) {
        *mask = SSL_CRLCHECK_NONE;
    }
    else if (strcEQ(w, "leaf")) {
        *mask = SSL_CRLCHECK_LEAF;
    }
    else if (strcEQ(w, "chain")) {
        *mask = SSL_CRLCHECK_CHAIN;
    }
    else {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                           ": Invalid argument '", w, "'",
                           NULL);
    }

    while (*arg) {
        w = ap_getword_conf(parms->temp_pool, &arg);
        if (strcEQ(w, "no_crl_for_cert_ok")) {
            *mask |= SSL_CRLCHECK_NO_CRL_FOR_CERT_OK;
        }
        else {
            return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                               ": Invalid argument '", w, "'",
                               NULL);
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLCARevocationCheck(cmd_parms *cmd,
                                         void *dcfg,
                                         const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    return ssl_cmd_crlcheck_parse(cmd, arg, &sc->server->crl_check_mask);
}

static const char *ssl_cmd_verify_parse(cmd_parms *parms,
                                        const char *arg,
                                        ssl_verify_t *id)
{
    if (strcEQ(arg, "none") || strcEQ(arg, "off")) {
        *id = SSL_CVERIFY_NONE;
    }
    else if (strcEQ(arg, "optional")) {
        *id = SSL_CVERIFY_OPTIONAL;
    }
    else if (strcEQ(arg, "require") || strcEQ(arg, "on")) {
        *id = SSL_CVERIFY_REQUIRE;
    }
    else if (strcEQ(arg, "optional_no_ca")) {
        *id = SSL_CVERIFY_OPTIONAL_NO_CA;
    }
    else {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                           ": Invalid argument '", arg, "'",
                           NULL);
    }

    return NULL;
}

const char *ssl_cmd_SSLVerifyClient(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    ssl_verify_t mode = SSL_CVERIFY_NONE;
    const char *err;

    if ((err = ssl_cmd_verify_parse(cmd, arg, &mode))) {
        return err;
    }

    if (cmd->path) {
        dc->nVerifyClient = mode;
    }
    else {
        sc->server->auth.verify_mode = mode;
    }

    return NULL;
}

static const char *ssl_cmd_verify_depth_parse(cmd_parms *parms,
                                              const char *arg,
                                              int *depth)
{
    if ((*depth = atoi(arg)) >= 0) {
        return NULL;
    }

    return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                       ": Invalid argument '", arg, "'",
                       NULL);
}

const char *ssl_cmd_SSLVerifyDepth(cmd_parms *cmd,
                                   void *dcfg,
                                   const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    int depth;
    const char *err;

    if ((err = ssl_cmd_verify_depth_parse(cmd, arg, &depth))) {
        return err;
    }

    if (cmd->path) {
        dc->nVerifyDepth = depth;
    }
    else {
        sc->server->auth.verify_depth = depth;
    }

    return NULL;
}

const char *ssl_cmd_SSLSessionCache(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err, *sep, *name;
    long enabled_flags;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    /* The OpenSSL session cache mode must have both the flags
     * SSL_SESS_CACHE_SERVER and SSL_SESS_CACHE_NO_INTERNAL set if a
     * session cache is configured; NO_INTERNAL prevents the
     * OpenSSL-internal session cache being used in addition to the
     * "external" (mod_ssl-provided) cache, which otherwise causes
     * additional memory consumption. */
    enabled_flags = SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL;

    if (strcEQ(arg, "none")) {
        /* Nothing to do; session cache will be off. */
    }
    else if (strcEQ(arg, "nonenotnull")) {
        /* ### Having a separate mode for this seems logically
         * unnecessary; the stated purpose of sending non-empty
         * session IDs would be better fixed in OpenSSL or simply
         * doing it by default if "none" is used. */
        mc->sesscache_mode = enabled_flags;
    }
    else {
        /* Argument is of form 'name:args' or just 'name'. */
        sep = ap_strchr_c(arg, ':');
        if (sep) {
            name = apr_pstrmemdup(cmd->pool, arg, sep - arg);
            sep++;
        }
        else {
            name = arg;
        }

        /* Find the provider of given name. */
        mc->sesscache = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                           name,
                                           AP_SOCACHE_PROVIDER_VERSION);
        if (mc->sesscache) {
            /* Cache found; create it, passing anything beyond the colon. */
            mc->sesscache_mode = enabled_flags;
            err = mc->sesscache->create(&mc->sesscache_context, sep,
                                        cmd->temp_pool, cmd->pool);
        }
        else {
            apr_array_header_t *name_list;
            const char *all_names;

            /* Build a comma-separated list of all registered provider
             * names: */
            name_list = ap_list_provider_names(cmd->pool,
                                               AP_SOCACHE_PROVIDER_GROUP,
                                               AP_SOCACHE_PROVIDER_VERSION);
            all_names = apr_array_pstrcat(cmd->pool, name_list, ',');

            err = apr_psprintf(cmd->pool, "'%s' session cache not supported "
                               "(known names: %s). Maybe you need to load the "
                               "appropriate socache module (mod_socache_%s?).",
                               name, all_names, name);
        }
    }

    if (err) {
        return apr_psprintf(cmd->pool, "SSLSessionCache: %s", err);
    }

    return NULL;
}

const char *ssl_cmd_SSLSessionCacheTimeout(cmd_parms *cmd,
                                           void *dcfg,
                                           const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->session_cache_timeout = atoi(arg);

    if (sc->session_cache_timeout < 0) {
        return "SSLSessionCacheTimeout: Invalid argument";
    }

    return NULL;
}

const char *ssl_cmd_SSLOptions(cmd_parms *cmd,
                               void *dcfg,
                               const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    ssl_opt_t opt;
    int first = TRUE;
    char action, *w;

    while (*arg) {
        w = ap_getword_conf(cmd->temp_pool, &arg);
        action = NUL;

        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }
        else if (first) {
            dc->nOptions = SSL_OPT_NONE;
            first = FALSE;
        }

        if (strcEQ(w, "StdEnvVars")) {
            opt = SSL_OPT_STDENVVARS;
        }
        else if (strcEQ(w, "ExportCertData")) {
            opt = SSL_OPT_EXPORTCERTDATA;
        }
        else if (strcEQ(w, "FakeBasicAuth")) {
            opt = SSL_OPT_FAKEBASICAUTH;
        }
        else if (strcEQ(w, "StrictRequire")) {
            opt = SSL_OPT_STRICTREQUIRE;
        }
        else if (strcEQ(w, "OptRenegotiate")) {
            opt = SSL_OPT_OPTRENEGOTIATE;
        }
        else if (strcEQ(w, "LegacyDNStringFormat")) {
            opt = SSL_OPT_LEGACYDNFORMAT;
        }
        else {
            return apr_pstrcat(cmd->pool,
                               "SSLOptions: Illegal option '", w, "'",
                               NULL);
        }

        if (action == '-') {
            dc->nOptionsAdd &= ~opt;
            dc->nOptionsDel |=  opt;
            dc->nOptions    &= ~opt;
        }
        else if (action == '+') {
            dc->nOptionsAdd |=  opt;
            dc->nOptionsDel &= ~opt;
            dc->nOptions    |=  opt;
        }
        else {
            dc->nOptions    = opt;
            dc->nOptionsAdd = opt;
            dc->nOptionsDel = SSL_OPT_NONE;
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLRequireSSL(cmd_parms *cmd, void *dcfg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->bSSLRequired = TRUE;

    return NULL;
}

const char *ssl_cmd_SSLRequire(cmd_parms *cmd,
                               void *dcfg,
                               const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
    ssl_require_t *require;
    const char *errstring;

    info->flags = AP_EXPR_FLAG_SSL_EXPR_COMPAT;
    info->filename = cmd->directive->filename;
    info->line_number = cmd->directive->line_num;
    info->module_index = APLOG_MODULE_INDEX;
    errstring = ap_expr_parse(cmd->pool, cmd->temp_pool, info, arg, NULL);
    if (errstring) {
        return apr_pstrcat(cmd->pool, "SSLRequire: ", errstring, NULL);
    }

    require = apr_array_push(dc->aRequirement);
    require->cpExpr = arg;
    require->mpExpr = info;

    return NULL;
}

const char *ssl_cmd_SSLRenegBufferSize(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLDirConfigRec *dc = dcfg;
    int val;

    val = atoi(arg);
    if (val < 0) {
        return apr_pstrcat(cmd->pool, "Invalid size for SSLRenegBufferSize: ",
                           arg, NULL);
    }
    dc->nRenegBufferSize = val;

    return NULL;
}

static const char *ssl_cmd_protocol_parse(cmd_parms *parms,
                                          const char *arg,
                                          ssl_proto_t *options)
{
    ssl_proto_t thisopt;

    *options = SSL_PROTOCOL_NONE;

    while (*arg) {
        char *w = ap_getword_conf(parms->temp_pool, &arg);
        char action = '\0';

        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }

        if (strcEQ(w, "SSLv2")) {
            if (action == '-') {
                continue;
            }
            else {
                return "SSLProtocol: SSLv2 is no longer supported";
            }
        }
        else if (strcEQ(w, "SSLv3")) {
#ifdef OPENSSL_NO_SSL3
            if (action != '-') {
                return "SSLv3 not supported by this version of OpenSSL";
            }
            /* Nothing to do, the flag is not present to be toggled */
            continue;
#else
            thisopt = SSL_PROTOCOL_SSLV3;
#endif
        }
        else if (strcEQ(w, "TLSv1")) {
            thisopt = SSL_PROTOCOL_TLSV1;
        }
#ifdef HAVE_TLSV1_X
        else if (strcEQ(w, "TLSv1.1")) {
            thisopt = SSL_PROTOCOL_TLSV1_1;
        }
        else if (strcEQ(w, "TLSv1.2")) {
            thisopt = SSL_PROTOCOL_TLSV1_2;
        }
#endif
        else if (strcEQ(w, "all")) {
            thisopt = SSL_PROTOCOL_ALL;
        }
        else {
            return apr_pstrcat(parms->temp_pool,
                               parms->cmd->name,
                               ": Illegal protocol '", w, "'", NULL);
        }

        if (action == '-') {
            *options &= ~thisopt;
        }
        else if (action == '+') {
            *options |= thisopt;
        }
        else {
            if (*options != SSL_PROTOCOL_NONE) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, parms->server, APLOGNO(02532)
                             "%s: Protocol '%s' overrides already set parameter(s). "
                             "Check if a +/- prefix is missing.",
                             parms->cmd->name, w);
            }
            *options = thisopt;
        }
    }

    return NULL;
}

const char *ssl_cmd_SSLProtocol(cmd_parms *cmd,
                                void *dcfg,
                                const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->protocol_set = 1;
    return ssl_cmd_protocol_parse(cmd, arg, &sc->server->protocol);
}

const char *ssl_cmd_SSLProxyEngine(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->proxy_enabled = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyProtocol(cmd_parms *cmd,
                                     void *dcfg,
                                     const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->proxy->protocol_set = 1;
    return ssl_cmd_protocol_parse(cmd, arg, &dc->proxy->protocol);
}

const char *ssl_cmd_SSLProxyCipherSuite(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    /* always disable null and export ciphers */
    arg = apr_pstrcat(cmd->pool, arg, ":!aNULL:!eNULL:!EXP", NULL);

    dc->proxy->auth.cipher_suite = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyVerify(cmd_parms *cmd,
                                   void *dcfg,
                                   const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    ssl_verify_t mode = SSL_CVERIFY_NONE;
    const char *err;

    if ((err = ssl_cmd_verify_parse(cmd, arg, &mode))) {
        return err;
    }

    dc->proxy->auth.verify_mode = mode;

    return NULL;
}

const char *ssl_cmd_SSLProxyVerifyDepth(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    int depth;
    const char *err;

    if ((err = ssl_cmd_verify_depth_parse(cmd, arg, &depth))) {
        return err;
    }

    dc->proxy->auth.verify_depth = depth;

    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificateFile(cmd_parms *cmd,
                                              void *dcfg,
                                              const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    dc->proxy->auth.ca_cert_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificatePath(cmd_parms *cmd,
                                              void *dcfg,
                                              const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    dc->proxy->auth.ca_cert_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCARevocationPath(cmd_parms *cmd,
                                             void *dcfg,
                                             const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    dc->proxy->crl_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCARevocationFile(cmd_parms *cmd,
                                             void *dcfg,
                                             const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    dc->proxy->crl_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCARevocationCheck(cmd_parms *cmd,
                                              void *dcfg,
                                              const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    return ssl_cmd_crlcheck_parse(cmd, arg, &dc->proxy->crl_check_mask);
}

const char *ssl_cmd_SSLProxyMachineCertificateFile(cmd_parms *cmd,
                                                   void *dcfg,
                                                   const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    dc->proxy->pkp->cert_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificatePath(cmd_parms *cmd,
                                                   void *dcfg,
                                                   const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    dc->proxy->pkp->cert_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificateChainFile(cmd_parms *cmd,
                                                   void *dcfg,
                                                   const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    dc->proxy->pkp->ca_cert_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLUserName(cmd_parms *cmd, void *dcfg,
                                const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    dc->szUserName = arg;
    return NULL;
}

const char *ssl_cmd_SSLOCSPEnable(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->ocsp_enabled = flag ? TRUE : FALSE;

#ifdef OPENSSL_NO_OCSP
    if (flag) {
        return "OCSP support disabled in SSL library; cannot enable "
            "OCSP validation";
    }
#endif

    return NULL;
}

const char *ssl_cmd_SSLOCSPOverrideResponder(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->ocsp_force_default = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLOCSPDefaultResponder(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->ocsp_responder = arg;

    return NULL;
}

const char *ssl_cmd_SSLOCSPResponseTimeSkew(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->ocsp_resptime_skew = atoi(arg);
    if (sc->server->ocsp_resptime_skew < 0) {
        return "SSLOCSPResponseTimeSkew: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLOCSPResponseMaxAge(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->ocsp_resp_maxage = atoi(arg);
    if (sc->server->ocsp_resp_maxage < 0) {
        return "SSLOCSPResponseMaxAge: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLOCSPResponderTimeout(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->ocsp_responder_timeout = apr_time_from_sec(atoi(arg));
    if (sc->server->ocsp_responder_timeout < 0) {
        return "SSLOCSPResponderTimeout: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLOCSPUseRequestNonce(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->ocsp_use_request_nonce = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLOCSPProxyURL(cmd_parms *cmd, void *dcfg,
                                    const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->proxy_uri = apr_palloc(cmd->pool, sizeof(apr_uri_t));
    if (apr_uri_parse(cmd->pool, arg, sc->server->proxy_uri) != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "SSLOCSPProxyURL: Cannot parse URL %s", arg);
    }
    return NULL;
}

/* Set OCSP responder certificate verification directive */
const char *ssl_cmd_SSLOCSPNoVerify(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->ocsp_noverify = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyCheckPeerExpire(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->proxy->ssl_check_peer_expire = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyCheckPeerCN(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->proxy->ssl_check_peer_cn = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyCheckPeerName(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->proxy->ssl_check_peer_name = flag ? TRUE : FALSE;

    return NULL;
}

const char  *ssl_cmd_SSLStrictSNIVHostCheck(cmd_parms *cmd, void *dcfg, int flag)
{
#ifdef HAVE_TLSEXT
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->strict_sni_vhost_check = flag ? SSL_ENABLED_TRUE : SSL_ENABLED_FALSE;

    return NULL;
#else
    return "SSLStrictSNIVHostCheck failed; OpenSSL is not built with support "
           "for TLS extensions and SNI indication. Refer to the "
           "documentation, and build a compatible version of OpenSSL.";
#endif
}

#ifdef HAVE_OCSP_STAPLING

const char *ssl_cmd_SSLStaplingCache(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err, *sep, *name;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    /* Argument is of form 'name:args' or just 'name'. */
    sep = ap_strchr_c(arg, ':');
    if (sep) {
        name = apr_pstrmemdup(cmd->pool, arg, sep - arg);
        sep++;
    }
    else {
        name = arg;
    }

    /* Find the provider of given name. */
    mc->stapling_cache = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                            name,
                                            AP_SOCACHE_PROVIDER_VERSION);
    if (mc->stapling_cache) {
        /* Cache found; create it, passing anything beyond the colon. */
        err = mc->stapling_cache->create(&mc->stapling_cache_context,
                                         sep, cmd->temp_pool,
                                         cmd->pool);
    }
    else {
        apr_array_header_t *name_list;
        const char *all_names;

        /* Build a comma-separated list of all registered provider
         * names: */
        name_list = ap_list_provider_names(cmd->pool,
                                           AP_SOCACHE_PROVIDER_GROUP,
                                           AP_SOCACHE_PROVIDER_VERSION);
        all_names = apr_array_pstrcat(cmd->pool, name_list, ',');

        err = apr_psprintf(cmd->pool, "'%s' stapling cache not supported "
                           "(known names: %s) Maybe you need to load the "
                           "appropriate socache module (mod_socache_%s?)",
                           name, all_names, name);
    }

    if (err) {
        return apr_psprintf(cmd->pool, "SSLStaplingCache: %s", err);
    }

    return NULL;
}

const char *ssl_cmd_SSLUseStapling(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_enabled = flag ? TRUE : FALSE;
    return NULL;
}

const char *ssl_cmd_SSLStaplingResponseTimeSkew(cmd_parms *cmd, void *dcfg,
                                                    const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_resptime_skew = atoi(arg);
    if (sc->server->stapling_resptime_skew < 0) {
        return "SSLStaplingResponseTimeSkew: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLStaplingResponseMaxAge(cmd_parms *cmd, void *dcfg,
                                                    const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_resp_maxage = atoi(arg);
    if (sc->server->stapling_resp_maxage < 0) {
        return "SSLStaplingResponseMaxAge: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLStaplingStandardCacheTimeout(cmd_parms *cmd, void *dcfg,
                                                    const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_cache_timeout = atoi(arg);
    if (sc->server->stapling_cache_timeout < 0) {
        return "SSLStaplingStandardCacheTimeout: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLStaplingErrorCacheTimeout(cmd_parms *cmd, void *dcfg,
                                                 const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_errcache_timeout = atoi(arg);
    if (sc->server->stapling_errcache_timeout < 0) {
        return "SSLStaplingErrorCacheTimeout: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLStaplingReturnResponderErrors(cmd_parms *cmd,
                                                     void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_return_errors = flag ? TRUE : FALSE;
    return NULL;
}

const char *ssl_cmd_SSLStaplingFakeTryLater(cmd_parms *cmd,
                                            void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_fake_trylater = flag ? TRUE : FALSE;
    return NULL;
}

const char *ssl_cmd_SSLStaplingResponderTimeout(cmd_parms *cmd, void *dcfg,
                                                const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_responder_timeout = atoi(arg);
    sc->server->stapling_responder_timeout *= APR_USEC_PER_SEC;
    if (sc->server->stapling_responder_timeout < 0) {
        return "SSLStaplingResponderTimeout: invalid argument";
    }
    return NULL;
}

const char *ssl_cmd_SSLStaplingForceURL(cmd_parms *cmd, void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->server->stapling_force_url = arg;
    return NULL;
}

#endif /* HAVE_OCSP_STAPLING */

#ifdef HAVE_SSL_CONF_CMD
const char *ssl_cmd_SSLOpenSSLConfCmd(cmd_parms *cmd, void *dcfg,
                                      const char *arg1, const char *arg2)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    SSL_CONF_CTX *cctx = sc->server->ssl_ctx_config;
    int value_type = SSL_CONF_cmd_value_type(cctx, arg1);
    const char *err;
    ssl_ctx_param_t *param;

    if (value_type == SSL_CONF_TYPE_UNKNOWN) {
        return apr_psprintf(cmd->pool,
                            "'%s': invalid OpenSSL configuration command",
                            arg1);
    }

    if (value_type == SSL_CONF_TYPE_FILE) {
        if ((err = ssl_cmd_check_file(cmd, &arg2)))
            return err;
    }
    else if (value_type == SSL_CONF_TYPE_DIR) {
        if ((err = ssl_cmd_check_dir(cmd, &arg2)))
            return err;
    }

    if (strcEQ(arg1, "CipherString")) {
        /* always disable null and export ciphers */
        arg2 = apr_pstrcat(cmd->pool, arg2, ":!aNULL:!eNULL:!EXP", NULL);
    }

    param = apr_array_push(sc->server->ssl_ctx_param);
    param->name = arg1;
    param->value = arg2;
    return NULL;
}
#endif

#ifdef HAVE_SRP

const char *ssl_cmd_SSLSRPVerifierFile(cmd_parms *cmd, void *dcfg,
                                       const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg)))
        return err;
    /* SRP_VBASE_init takes char*, not const char*  */
    sc->server->srp_vfile = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

const char *ssl_cmd_SSLSRPUnknownUserSeed(cmd_parms *cmd, void *dcfg,
                                          const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    /* SRP_VBASE_new takes char*, not const char*  */
    sc->server->srp_unknown_user_seed = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

#endif /* HAVE_SRP */

/* OCSP Responder File Function to read in value */
const char *ssl_cmd_SSLOCSPResponderCertificateFile(cmd_parms *cmd, void *dcfg, 
					   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->server->ocsp_certs_file = arg;
    return NULL;
}

static void ssl_srv_dump(SSLSrvConfigRec *sc, apr_pool_t *p, 
                            apr_file_t *out, const char *indent, const char **psep);
static void ssl_dir_dump(SSLDirConfigRec *dc, apr_pool_t *p, 
                         apr_file_t *out, const char *indent, const char **psep);
static void ssl_policy_dump(SSLPolicyRec *policy, apr_pool_t *p, 
                            apr_file_t *out, const char *indent);

void ssl_hook_ConfigTest(apr_pool_t *pconf, server_rec *s)
{
    apr_file_t *out = NULL;
    if (ap_exists_config_define("DUMP_CERTS") &&
        ap_exists_config_define("DUMP_CA_CERTS")) {
        return;
    }

    if (ap_exists_config_define("DUMP_CERTS")) {
        apr_file_open_stdout(&out, pconf);
        apr_file_printf(out, "Server certificates:\n");

        /* Dump the filenames of all configured server certificates to
        * stdout. */
        while (s) {
            SSLSrvConfigRec *sc = mySrvConfig(s);

            if (sc && sc->server && sc->server->pks) {
                modssl_pk_server_t *const pks = sc->server->pks;
                int i;

                for (i = 0; (i < pks->cert_files->nelts) &&
                            APR_ARRAY_IDX(pks->cert_files, i, const char *);
                     i++) {
                    apr_file_printf(out, "  %s\n",
                                    APR_ARRAY_IDX(pks->cert_files,
                                                  i, const char *));
                }
            }

            s = s->next;
        }
        return;
    }

    if (ap_exists_config_define("DUMP_CA_CERTS")) {
        apr_file_open_stdout(&out, pconf);
        apr_file_printf(out, "Server CA certificates:\n");

        /* Dump the filenames of all configured server CA certificates to
        * stdout. */
        while (s) {
            SSLSrvConfigRec *sc = mySrvConfig(s);

            if (sc && sc->server) {
                if (sc->server->auth.ca_cert_path) {
                    apr_file_printf(out, "  %s\n",
                                    sc->server->auth.ca_cert_path);
                }
                if (sc->server->auth.ca_cert_file) {
                    apr_file_printf(out, "  %s\n",
                                    sc->server->auth.ca_cert_file);
                }
            }

            s = s->next;
        }
        return;
    }

    if (ap_exists_config_define("DUMP_SSL_POLICIES")) {
        apr_array_header_t *names = get_policy_names(pconf, 1);
        SSLPolicyRec *policy;
        const char *name, *sep = "";
        int i;
        
        apr_file_open_stdout(&out, pconf);
        apr_file_printf(out, "SSLPolicies: {");
        for (i = 0; i < names->nelts; ++i) {
            name = APR_ARRAY_IDX(names, i, const char*);
            policy = ssl_policy_lookup(pconf, name);
            if (policy) {
                apr_file_printf(out, "%s\n  \"%s\": {", sep, name);
                sep = ", ";
                ssl_policy_dump(policy, pconf, out, "    ");
                apr_file_printf(out, "\n  }");
            }
        }
        apr_file_printf(out, "\n}\n");
        return;
    }
}

/*  _________________________________________________________________
**
**  Dump Config Data
**  _________________________________________________________________
*/

static const char *json_quote(const char *s, apr_pool_t *p)
{
    const char *src, *dq = s;
    int n = 0;
    
    while ((dq = ap_strchr_c(dq, '\"'))) {
        ++n;
        ++dq;
    }
    if (n > 0) {
        char *dst, c;
        src = s;
        s = dst = apr_pcalloc(p, strlen(s) + n + 1);
        while ((c = *src++)) {
            if (c == '\"') {
                *dst++ = '\\';
            }
            *dst++ = c;
        }
    }
    return s;
}

static void val_str_dump(apr_file_t *out, const char *key, const char *val, 
                         apr_pool_t *p, const char *indent, const char **psep)
{
    if (val) {
        /* TODO: JSON quite string val */
        apr_file_printf(out, "%s\n%s\"%s\": \"%s\"", *psep, indent, key, json_quote(val, p));
        *psep = ", ";
    }
}

static void val_str_array_dump(apr_file_t *out, const char *key, apr_array_header_t *val, 
                               apr_pool_t *p, const char *indent, const char **psep)
{
    if (val && val->nelts > 0) {
        const char *s; 
        int i;
        
        for (i = 0; i < val->nelts; ++i) {
            s = APR_ARRAY_IDX(val, i, const char*);
            val_str_dump(out, key, s, p, indent, psep);
        }
    }
}

static void val_long_dump(apr_file_t *out, const char *key, long val, 
                          apr_pool_t *p, const char *indent, const char **psep)
{
    if (val != UNSET) {
        apr_file_printf(out, "%s\n%s\"%s\": %ld", *psep, indent, key, val);
        *psep = ", ";
    }
}

static void val_itime_dump(apr_file_t *out, const char *key, apr_interval_time_t val, 
                           apr_pool_t *p, const char *indent, const char **psep)
{
    if (val != UNSET) {
        apr_file_printf(out, "%s\n%s\"%s\": %f", *psep, indent, key, 
                        ((double)val/APR_USEC_PER_SEC));
        *psep = ", ";
    }
}

static void val_onoff_dump(apr_file_t *out, const char *key, BOOL val, 
                           apr_pool_t *p, const char *indent, const char **psep)
{
    if (val != UNSET) {
        val_str_dump(out, key, val? "on" : "off", p, indent, psep);
    }
}

static void val_uri_dump(apr_file_t *out, const char *key, apr_uri_t *val, 
                         apr_pool_t *p, const char *indent, const char **psep)
{
    if (val) {
        val_str_dump(out, key, apr_uri_unparse(p, val, 0), p, indent, psep);
    }
}

static void val_verify_dump(apr_file_t *out, const char *key, ssl_verify_t mode, 
                            apr_pool_t *p, const char *indent, const char **psep)
{
    switch (mode) {
        case SSL_CVERIFY_NONE:
            val_str_dump(out, key, "none", p, indent, psep);
            return;
        case SSL_CVERIFY_OPTIONAL:
            val_str_dump(out, key, "optional", p, indent, psep);
            return;
        case SSL_CVERIFY_REQUIRE:
            val_str_dump(out, key, "require", p, indent, psep);
            return;
        case SSL_CVERIFY_OPTIONAL_NO_CA:
            val_str_dump(out, key, "optional_no_ca", p, indent, psep);
            return;
        default:
            return;
    }
}

static void val_enabled_dump(apr_file_t *out, const char *key, ssl_enabled_t val, 
                             apr_pool_t *p, const char *indent, const char **psep)
{
    switch (val) {
        case SSL_ENABLED_FALSE:
            val_str_dump(out, key, "off", p, indent, psep);
            return;
        case SSL_ENABLED_TRUE:
            val_str_dump(out, key, "on", p, indent, psep);
            return;
        case SSL_ENABLED_OPTIONAL:
            val_str_dump(out, key, "optional", p, indent, psep);
            return;
        default:                   
            return;
    }
}

static void val_pphrase_dump(apr_file_t *out, const char *key, 
                             ssl_pphrase_t pphrase_type, const char *path, 
                             apr_pool_t *p, const char *indent, const char **psep)
{
    switch (pphrase_type) {
        case SSL_PPTYPE_BUILTIN: 
            val_str_dump(out, key, "builtin", p, indent, psep);
            return;
        case SSL_PPTYPE_FILTER: 
            val_str_dump(out, key, apr_pstrcat(p, "|", path, NULL), p, indent, psep);
            return;
        case SSL_PPTYPE_PIPE: 
            val_str_dump(out, key, apr_pstrcat(p, "exec:", path, NULL), p, indent, psep);
            return;
        default:
            return;
    }
}

static void val_crl_check_dump(apr_file_t *out, const char *key, int mask, 
                               apr_pool_t *p, const char *indent, const char **psep)
{
    if (mask != UNSET) {
        if (mask == SSL_CRLCHECK_NONE) {
            val_str_dump(out, key, "none", p, indent, psep);
        }
        else if (mask == SSL_CRLCHECK_LEAF) {
            val_str_dump(out, key, "leaf", p, indent, psep);
        }
        else if (mask == SSL_CRLCHECK_CHAIN) {
            val_str_dump(out, key, "chain", p, indent, psep);
        }
        else if (mask == (SSL_CRLCHECK_CHAIN|SSL_CRLCHECK_NO_CRL_FOR_CERT_OK)) {
            val_str_dump(out, key, "chain no_crl_for_cert_ok", p, indent, psep);
        }
        else {
            val_str_dump(out, key, "???", p, indent, psep);
        }
    }
}

static void val_option_dump(apr_file_t *out, const char *key, const char *optname,
                            int val, int set_mask, int add_mask, int del_mask, 
                            apr_pool_t *p, const char *indent, const char **psep)
{
    const char *op = ((val & set_mask)? "" : 
                      ((val & add_mask)? "+" :
                       (val & del_mask)? "-" : NULL));
    if (op) {
        apr_file_printf(out, "%s\n%s\"%s\": \"%s%s\"", *psep, indent, key, op, 
                        json_quote(optname, p));
        *psep = ", ";
    }
}

static const char *protocol_str(ssl_proto_t proto, apr_pool_t *p)
{
    if (SSL_PROTOCOL_NONE == proto) {
        return "none";
    }
    else if (SSL_PROTOCOL_ALL == proto) {
        return "all";
    }
    else {
        /* icing: I think it is nuts that we define our own IETF protocol constants
         * only whent the linked *SSL lib supports them. */
        apr_array_header_t *names = apr_array_make(p, 5, sizeof(const char*));
        if ((1<<4) & proto) {
            APR_ARRAY_PUSH(names, const char*) = "+TLSv1.2";
        }
        if ((1<<3) & proto) {
            APR_ARRAY_PUSH(names, const char*) = "+TLSv1.1";
        }
        if ((1<<2) & proto) {
            APR_ARRAY_PUSH(names, const char*) = "+TLSv1.0";
        }
        if ((1<<1) & proto) {
            APR_ARRAY_PUSH(names, const char*) = "+SSLv3";
        }
        return apr_array_pstrcat(p, names, ' ');
    }
}

#define DMP_STRING(k,v) \
    val_str_dump(out, k, v, p, indent, psep)
#define DMP_LONG(k,v) \
    val_long_dump(out, k, v, p, indent, psep)
#define DMP_ITIME(k,v) \
    val_itime_dump(out, k, v, p, indent, psep)
#define DMP_STRARR(k,v) \
    val_str_array_dump(out, k, v, p, indent, psep)
#define DMP_VERIFY(k,v) \
    val_verify_dump(out, k, v, p, indent, psep)
#define DMP_ON_OFF(k,v) \
    val_onoff_dump(out, k, v, p, indent, psep)
#define DMP_URI(k,v) \
    val_uri_dump(out, k, v, p, indent, psep)
#define DMP_CRLCHK(k,v) \
    val_crl_check_dump(out, k, v, p, indent, psep)
#define DMP_PHRASE(k,v, v2) \
    val_pphrase_dump(out, k, v, v2, p, indent, psep)
#define DMP_ENABLD(k,v) \
    val_enabled_dump(out, k, v, p, indent, psep)
#define DMP_OPTION(n,v) \
    val_option_dump(out, "SSLOption", n, v, \
                    dc->nOptions, dc->nOptionsAdd, dc->nOptionsDel, p, indent, psep);

static void modssl_auth_ctx_dump(modssl_auth_ctx_t *auth, apr_pool_t *p, int proxy,
                                 apr_file_t *out, const char *indent, const char **psep)
{
    DMP_STRING(proxy? "SSLProxyCipherSuite" : "SSLCipherSuite", auth->cipher_suite);
    DMP_VERIFY(proxy? "SSLProxyVerify" : "SSLVerifyClient", auth->verify_mode);
    DMP_LONG(  proxy? "SSLProxyVerify" : "SSLVerifyDepth", auth->verify_depth);
    DMP_STRING(proxy? "SSLProxyCACertificateFile" : "SSLCACertificateFile", auth->ca_cert_file);
    DMP_STRING(proxy? "SSLProxyCACertificatePath" : "SSLCACertificatePath", auth->ca_cert_path);
}

static void modssl_ctx_dump(modssl_ctx_t *ctx, apr_pool_t *p, int proxy,
                            apr_file_t *out, const char *indent, const char **psep)
{
#ifdef HAVE_SSL_CONF_CMD
    int i;
#endif

    if (ctx->protocol_set) {
        DMP_STRING(proxy? "SSLProxyProtocol" : "SSLProtocol", protocol_str(ctx->protocol, p));
    }

    modssl_auth_ctx_dump(&ctx->auth, p, proxy, out, indent, psep);

    DMP_STRING(proxy? "SSLProxyCARevocationFile" : "SSLCARevocationFile", ctx->crl_file);
    DMP_STRING(proxy? "SSLProxyCARevocationPath" : "SSLCARevocationPath", ctx->crl_path);
    DMP_CRLCHK(proxy? "SSLProxyCARevocationCheck" : "SSLCARevocationCheck", ctx->crl_check_mask);
    if (!proxy) {
        DMP_PHRASE("SSLPassPhraseDialog", ctx->pphrase_dialog_type, ctx->pphrase_dialog_path);
        if (ctx->pks) {
            DMP_STRING("SSLCADNRequestFile", ctx->pks->ca_name_file);
            DMP_STRING("SSLCADNRequestPath", ctx->pks->ca_name_path);
            DMP_STRARR("SSLCertificateFile", ctx->pks->cert_files);
            DMP_STRARR("SSLCertificateKeyFile", ctx->pks->key_files);
        }
#ifdef HAVE_OCSP_STAPLING
        DMP_ON_OFF("SSLUseStapling", ctx->stapling_enabled);
        DMP_LONG(  "SSLStaplingResponseTimeSkew", ctx->stapling_resptime_skew);
        DMP_LONG(  "SSLStaplingResponseMaxAge", ctx->stapling_resp_maxage);
        DMP_LONG(  "SSLStaplingStandardCacheTimeout", ctx->stapling_cache_timeout);
        DMP_ON_OFF("SSLStaplingReturnResponderErrors", ctx->stapling_return_errors);
        DMP_ON_OFF("SSLStaplingFakeTryLater", ctx->stapling_fake_trylater);
        DMP_LONG(  "SSLStaplingErrorCacheTimeout", ctx->stapling_errcache_timeout);
        DMP_ITIME( "SSLStaplingResponderTimeout", ctx->stapling_responder_timeout);
        DMP_STRING("SSLStaplingForceURL", ctx->stapling_force_url);
#endif /* if HAVE_OCSP_STAPLING */ 

#ifdef HAVE_SRP
        DMP_STRING("SSLSRPUnknownUserSeed", ctx->srp_unknown_user_seed);
        DMP_STRING("SSLSRPVerifierFile", ctx->srp_vfile);
#endif
        DMP_ON_OFF("SSLOCSPEnable", ctx->ocsp_enabled);
        DMP_ON_OFF("SSLOCSPOverrideResponder", ctx->ocsp_force_default);
        DMP_STRING("SSLOCSPDefaultResponder", ctx->ocsp_responder);
        DMP_LONG(  "SSLOCSPResponseTimeSkew", ctx->ocsp_resptime_skew);
        DMP_LONG(  "SSLOCSPResponseMaxAge", ctx->ocsp_resp_maxage);
        DMP_ITIME( "SSLOCSPResponderTimeout", ctx->ocsp_responder_timeout);
        DMP_ON_OFF("SSLOCSPUseRequestNonce", ctx->ocsp_use_request_nonce);
        DMP_URI(   "SSLOCSPProxyURL", ctx->proxy_uri);
        DMP_ON_OFF("SSLOCSPNoVerify", ctx->ocsp_noverify);
        DMP_STRING("SSLOCSPResponderCertificateFile", ctx->ocsp_certs_file);

#ifdef HAVE_SSL_CONF_CMD
        if (ctx->ssl_ctx_param && ctx->ssl_ctx_param->nelts > 0) {
            ssl_ctx_param_t *param = (ssl_ctx_param_t *)ctx->ssl_ctx_param->elts;
            for (i = 0; i < ctx->ssl_ctx_param->nelts; ++i, ++param) {
                apr_file_printf(out, "%s\n%s\"%s\": \"%s %s\"", *psep, indent, 
                                "SSLOpenSSLConfCmd", json_quote(param->name, p), 
                                json_quote(param->value, p));
                *psep = ", ";
            }
        }
#endif

#ifdef HAVE_TLS_SESSION_TICKETS
        if (ctx->ticket_key) {
            DMP_STRING("SSLSessionTicketKeyFile", ctx->ticket_key->file_path);
        }
#endif
    }
    else { /* proxy */
        if (ctx->pkp) {
            DMP_STRING("SSLProxyMachineCertificateFile", ctx->pkp->cert_file);
            DMP_STRING("SSLProxyMachineCertificatePath", ctx->pkp->cert_path);
            DMP_STRING("SSLProxyMachineCertificateChainFile", ctx->pkp->ca_cert_file);
        }
        DMP_ON_OFF("SSLProxyCheckPeerCN", ctx->ssl_check_peer_cn);
        DMP_ON_OFF("SSLProxyCheckPeerName", ctx->ssl_check_peer_cn);
        DMP_ON_OFF("SSLProxyCheckPeerExpire", ctx->ssl_check_peer_expire);
    }
}

static void ssl_srv_dump(SSLSrvConfigRec *sc, apr_pool_t *p, 
                            apr_file_t *out, const char *indent, const char **psep)
{
    DMP_ENABLD("SSLEngine", sc->enabled);
    DMP_ON_OFF("SSLHonorCipherOrder", sc->cipher_server_pref);

#ifndef OPENSSL_NO_COMP
    DMP_ON_OFF("SSLCompression", sc->compression);
#endif

    modssl_ctx_dump(sc->server, p, 0, out, indent, psep);

    DMP_LONG(  "SSLSessionCacheTimeout", sc->session_cache_timeout);
    DMP_ON_OFF("SSLInsecureRenegotiation", sc->insecure_reneg);
    DMP_ON_OFF("SSLStrictSNIVHostCheck", sc->strict_sni_vhost_check);
#ifdef HAVE_FIPS
    DMP_ON_OFF("SSLFIPS", sc->fips);
#endif
    DMP_ON_OFF("SSLSessionTickets", sc->session_tickets);
    DMP_STRARR("SSLPolicy", sc->policies);
}

static void ssl_dir_dump(SSLDirConfigRec *dc, apr_pool_t *p, 
                         apr_file_t *out, const char *indent, const char **psep)
{
    int i;
    
    DMP_ON_OFF("SSLProxyEngine", dc->proxy_enabled);

    modssl_ctx_dump(dc->proxy, p, 1, out, indent, psep);

    if (dc->bSSLRequired == TRUE) {
        DMP_ON_OFF("SSLRequireSSL", dc->bSSLRequired);
    }
    if (dc->aRequirement && dc->aRequirement->nelts > 0) {
        ssl_require_t *r = (ssl_require_t *)dc->aRequirement->elts;
        for (i = 0; i < dc->aRequirement->nelts; ++i, ++r) {
            DMP_STRING("SSLRequire", r->cpExpr);
        }
    }
    DMP_OPTION("StdEnvVars", SSL_OPT_STDENVVARS);
    DMP_OPTION("ExportCertData", SSL_OPT_EXPORTCERTDATA);
    DMP_OPTION("FakeBasicAuth", SSL_OPT_FAKEBASICAUTH);
    DMP_OPTION("StrictRequire", SSL_OPT_STRICTREQUIRE);
    DMP_OPTION("OptRenegotiate", SSL_OPT_OPTRENEGOTIATE);
    DMP_OPTION("LegacyDNStringFormat", SSL_OPT_LEGACYDNFORMAT);
    DMP_STRARR("SSLProxyPolicy", dc->policies);
}

static void ssl_policy_dump(SSLPolicyRec *policy, apr_pool_t *p, 
                            apr_file_t *out, const char *indent)
{
    const char *sep = "";
    if (policy->sc) {
        ssl_srv_dump(policy->sc, p, out, indent, &sep);
    }
    if (policy->dc) {
        ssl_dir_dump(policy->dc, p, out, indent, &sep);
    }
}



