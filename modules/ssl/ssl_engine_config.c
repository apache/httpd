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
#include "ssl_private.h"
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

static void modssl_ctx_init(modssl_ctx_t *mctx, apr_pool_t *p)
{
    mctx->sc                  = NULL; /* set during module init */

    mctx->ssl_ctx             = NULL; /* set during module init */

    mctx->pks                 = NULL;
    mctx->pkp                 = NULL;

#ifdef HAVE_TLS_SESSION_TICKETS
    mctx->ticket_key          = NULL;
#endif

    mctx->protocol            = SSL_PROTOCOL_ALL;
    mctx->protocol_set        = 0;

    mctx->pphrase_dialog_type = SSL_PPTYPE_UNSET;
    mctx->pphrase_dialog_path = NULL;

    mctx->cert_chain          = NULL;

    mctx->crl_path            = NULL;
    mctx->crl_file            = NULL;
    mctx->crl_check_mode      = SSL_CRLCHECK_UNSET;

    mctx->auth.ca_cert_path   = NULL;
    mctx->auth.ca_cert_file   = NULL;
    mctx->auth.cipher_suite   = NULL;
    mctx->auth.verify_depth   = UNSET;
    mctx->auth.verify_mode    = SSL_CVERIFY_UNSET;

    mctx->ocsp_enabled        = FALSE;
    mctx->ocsp_force_default  = FALSE;
    mctx->ocsp_responder      = NULL;
    mctx->ocsp_resptime_skew  = UNSET;
    mctx->ocsp_resp_maxage    = UNSET;
    mctx->ocsp_responder_timeout = UNSET;
    mctx->ocsp_use_request_nonce = UNSET;

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
    SSL_CONF_CTX_set_flags(mctx->ssl_ctx_config, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_flags(mctx->ssl_ctx_config, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(mctx->ssl_ctx_config, SSL_CONF_FLAG_CERTIFICATE);
    mctx->ssl_ctx_param = apr_array_make(p, 5, sizeof(ssl_ctx_param_t));
#endif
}

static void modssl_ctx_init_proxy(SSLSrvConfigRec *sc,
                                  apr_pool_t *p)
{
    modssl_ctx_t *mctx;

    mctx = sc->proxy = apr_palloc(p, sizeof(*sc->proxy));

    modssl_ctx_init(mctx, p);

    mctx->pkp = apr_palloc(p, sizeof(*mctx->pkp));

    mctx->pkp->cert_file = NULL;
    mctx->pkp->cert_path = NULL;
    mctx->pkp->ca_cert_file = NULL;
    mctx->pkp->certs     = NULL;
    mctx->pkp->ca_certs  = NULL;
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
    sc->proxy_enabled          = UNSET;
    sc->vhost_id               = NULL;  /* set during module init */
    sc->vhost_id_len           = 0;     /* set during module init */
    sc->session_cache_timeout  = UNSET;
    sc->cipher_server_pref     = UNSET;
    sc->insecure_reneg         = UNSET;
    sc->proxy_ssl_check_peer_expire = SSL_ENABLED_UNSET;
    sc->proxy_ssl_check_peer_cn     = SSL_ENABLED_UNSET;
    sc->proxy_ssl_check_peer_name   = SSL_ENABLED_UNSET;
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

    modssl_ctx_init_proxy(sc, p);

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
    cfgMerge(crl_check_mode, SSL_CRLCHECK_UNSET);

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
}

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

static void modssl_ctx_cfg_merge_certkeys_array(apr_pool_t *p,
                                                apr_array_header_t *base,
                                                apr_array_header_t *add,
                                                apr_array_header_t *mrg)
{
    int i;

    /*
     * pick up to CERTKEYS_IDX_MAX+1 entries from "add" (in which case they
     * they "knock out" their corresponding entries in "base", emulating
     * the behavior with cfgMergeString in releases up to 2.4.7)
     */
    for (i = 0; i < add->nelts && i <= CERTKEYS_IDX_MAX; i++) {
        APR_ARRAY_PUSH(mrg, const char *) = APR_ARRAY_IDX(add, i, const char *);
    }

    /* add remaining ones from "base" */
    while (i < base->nelts) {
        APR_ARRAY_PUSH(mrg, const char *) = APR_ARRAY_IDX(base, i, const char *);
        i++;
    }

    /* and finally, append the rest of "add" (if there are any) */
    for (i = CERTKEYS_IDX_MAX+1; i < add->nelts; i++) {
        APR_ARRAY_PUSH(mrg, const char *) = APR_ARRAY_IDX(add, i, const char *);
    }
}

static void modssl_ctx_cfg_merge_server(apr_pool_t *p,
                                        modssl_ctx_t *base,
                                        modssl_ctx_t *add,
                                        modssl_ctx_t *mrg)
{
    modssl_ctx_cfg_merge(p, base, add, mrg);

    /*
     * For better backwards compatibility with releases up to 2.4.7,
     * merging global and vhost-level SSLCertificateFile and
     * SSLCertificateKeyFile directives needs special treatment.
     * See also PR 56306 and 56353.
     */
    modssl_ctx_cfg_merge_certkeys_array(p, base->pks->cert_files,
                                        add->pks->cert_files,
                                        mrg->pks->cert_files);
    modssl_ctx_cfg_merge_certkeys_array(p, base->pks->key_files,
                                        add->pks->key_files,
                                        mrg->pks->key_files);

    cfgMergeString(pks->ca_name_path);
    cfgMergeString(pks->ca_name_file);

#ifdef HAVE_TLS_SESSION_TICKETS
    cfgMergeString(ticket_key->file_path);
#endif
}

/*
 *  Merge per-server SSL configurations
 */
void *ssl_config_server_merge(apr_pool_t *p, void *basev, void *addv)
{
    SSLSrvConfigRec *base = (SSLSrvConfigRec *)basev;
    SSLSrvConfigRec *add  = (SSLSrvConfigRec *)addv;
    SSLSrvConfigRec *mrg  = ssl_config_server_new(p);

    cfgMerge(mc, NULL);
    cfgMerge(enabled, SSL_ENABLED_UNSET);
    cfgMergeBool(proxy_enabled);
    cfgMergeInt(session_cache_timeout);
    cfgMergeBool(cipher_server_pref);
    cfgMergeBool(insecure_reneg);
    cfgMerge(proxy_ssl_check_peer_expire, SSL_ENABLED_UNSET);
    cfgMerge(proxy_ssl_check_peer_cn, SSL_ENABLED_UNSET);
    cfgMerge(proxy_ssl_check_peer_name, SSL_ENABLED_UNSET);
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

    modssl_ctx_cfg_merge_proxy(p, base->proxy, add->proxy, mrg->proxy);

    modssl_ctx_cfg_merge_server(p, base->server, add->server, mrg->server);

    return mrg;
}

/*
 *  Create per-directory SSL configuration
 */
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

    dc->szCACertificatePath    = NULL;
    dc->szCACertificateFile    = NULL;
    dc->szUserName             = NULL;

    dc->nRenegBufferSize = UNSET;

    return dc;
}

/*
 *  Merge per-directory SSL configurations
 */
void *ssl_config_perdir_merge(apr_pool_t *p, void *basev, void *addv)
{
    SSLDirConfigRec *base = (SSLDirConfigRec *)basev;
    SSLDirConfigRec *add  = (SSLDirConfigRec *)addv;
    SSLDirConfigRec *mrg  = (SSLDirConfigRec *)apr_palloc(p, sizeof(*mrg));

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

    cfgMergeString(szCACertificatePath);
    cfgMergeString(szCACertificateFile);
    cfgMergeString(szUserName);

    cfgMergeInt(nRenegBufferSize);

    return mrg;
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
                           arg2, "': This version of " SSL_LIBRARY_NAME
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

const char *ssl_cmd_SSLEngine(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    if (!strcasecmp(arg, "On")) {
        sc->enabled = SSL_ENABLED_TRUE;
        return NULL;
    }
    else if (!strcasecmp(arg, "Off")) {
        sc->enabled = SSL_ENABLED_FALSE;
        return NULL;
    }
    else if (!strcasecmp(arg, "Optional")) {
        sc->enabled = SSL_ENABLED_OPTIONAL;
        return NULL;
    }

    return "Argument must be On, Off, or Optional";
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
    arg = apr_pstrcat(cmd->pool, "!aNULL:!eNULL:!EXP:", arg, NULL);

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
        return "This version of openssl does not support configuring "
               "compression within <VirtualHost> sections.";
#endif
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

    *(const char **)apr_array_push(sc->server->pks->cert_files) =
        apr_pstrdup(cmd->pool, arg);
    
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

    *(const char **)apr_array_push(sc->server->pks->key_files) =
        apr_pstrdup(cmd->pool, arg);

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
                                          ssl_crlcheck_t *mode)
{
    if (strcEQ(arg, "none")) {
        *mode = SSL_CRLCHECK_NONE;
    }
    else if (strcEQ(arg, "leaf")) {
        *mode = SSL_CRLCHECK_LEAF;
    }
    else if (strcEQ(arg, "chain")) {
        *mode = SSL_CRLCHECK_CHAIN;
    }
    else {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                           ": Invalid argument '", arg, "'",
                           NULL);
    }

    return NULL;
}

const char *ssl_cmd_SSLCARevocationCheck(cmd_parms *cmd,
                                         void *dcfg,
                                         const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    return ssl_cmd_crlcheck_parse(cmd, arg, &sc->server->crl_check_mode);
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
    ssl_verify_t mode;
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
    require->cpExpr = apr_pstrdup(cmd->pool, arg);
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
            thisopt = SSL_PROTOCOL_SSLV3;
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
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy_enabled = flag ? TRUE : FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyProtocol(cmd_parms *cmd,
                                     void *dcfg,
                                     const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy->protocol_set = 1;
    return ssl_cmd_protocol_parse(cmd, arg, &sc->proxy->protocol);
}

const char *ssl_cmd_SSLProxyCipherSuite(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    /* always disable null and export ciphers */
    arg = apr_pstrcat(cmd->pool, "!aNULL:!eNULL:!EXP:", arg, NULL);

    sc->proxy->auth.cipher_suite = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyVerify(cmd_parms *cmd,
                                   void *dcfg,
                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    ssl_verify_t mode;
    const char *err;

    if ((err = ssl_cmd_verify_parse(cmd, arg, &mode))) {
        return err;
    }

    sc->proxy->auth.verify_mode = mode;

    return NULL;
}

const char *ssl_cmd_SSLProxyVerifyDepth(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    int depth;
    const char *err;

    if ((err = ssl_cmd_verify_depth_parse(cmd, arg, &depth))) {
        return err;
    }

    sc->proxy->auth.verify_depth = depth;

    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificateFile(cmd_parms *cmd,
                                              void *dcfg,
                                              const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->proxy->auth.ca_cert_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificatePath(cmd_parms *cmd,
                                              void *dcfg,
                                              const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->proxy->auth.ca_cert_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCARevocationPath(cmd_parms *cmd,
                                             void *dcfg,
                                             const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->proxy->crl_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCARevocationFile(cmd_parms *cmd,
                                             void *dcfg,
                                             const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->proxy->crl_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyCARevocationCheck(cmd_parms *cmd,
                                              void *dcfg,
                                              const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    return ssl_cmd_crlcheck_parse(cmd, arg, &sc->proxy->crl_check_mode);
}

const char *ssl_cmd_SSLProxyMachineCertificateFile(cmd_parms *cmd,
                                                   void *dcfg,
                                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->proxy->pkp->cert_file = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificatePath(cmd_parms *cmd,
                                                   void *dcfg,
                                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_dir(cmd, &arg))) {
        return err;
    }

    sc->proxy->pkp->cert_path = arg;

    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificateChainFile(cmd_parms *cmd,
                                                   void *dcfg,
                                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ssl_cmd_check_file(cmd, &arg))) {
        return err;
    }

    sc->proxy->pkp->ca_cert_file = arg;

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

const char *ssl_cmd_SSLProxyCheckPeerExpire(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy_ssl_check_peer_expire = flag ? SSL_ENABLED_TRUE : SSL_ENABLED_FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyCheckPeerCN(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy_ssl_check_peer_cn = flag ? SSL_ENABLED_TRUE : SSL_ENABLED_FALSE;

    return NULL;
}

const char *ssl_cmd_SSLProxyCheckPeerName(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy_ssl_check_peer_name = flag ? SSL_ENABLED_TRUE : SSL_ENABLED_FALSE;

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

void ssl_hook_ConfigTest(apr_pool_t *pconf, server_rec *s)
{
    apr_file_t *out = NULL;
    if (!ap_exists_config_define("DUMP_CERTS")) {
        return;
    }
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

}
