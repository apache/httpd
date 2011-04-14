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
    mc->nSessionCacheMode      = SSL_SCMODE_UNSET;
    mc->szSessionCacheDataFile = NULL;
    mc->nSessionCacheDataSize  = 0;
    mc->pSessionCacheDataMM    = NULL;
    mc->pSessionCacheDataRMM   = NULL;
    mc->tSessionCacheDataTable = NULL;
    mc->nMutexMode             = SSL_MUTEXMODE_UNSET;
    mc->nMutexMech             = APR_LOCK_DEFAULT;
    mc->szMutexFile            = NULL;
    mc->pMutex                 = NULL;
    mc->aRandSeed              = apr_array_make(pool, 4,
                                                sizeof(ssl_randseed_t));
    mc->tVHostKeys             = apr_hash_make(pool);
    mc->tPrivateKey            = apr_hash_make(pool);
    mc->tPublicCert            = apr_hash_make(pool);
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
    mc->szCryptoDevice         = NULL;
#endif

    memset(mc->pTmpKeys, 0, sizeof(mc->pTmpKeys));

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

static void modssl_ctx_init(modssl_ctx_t *mctx)
{
    mctx->sc                  = NULL; /* set during module init */

    mctx->ssl_ctx             = NULL; /* set during module init */

    mctx->pks                 = NULL;
    mctx->pkp                 = NULL;

    mctx->protocol            = SSL_PROTOCOL_ALL;

    mctx->pphrase_dialog_type = SSL_PPTYPE_UNSET;
    mctx->pphrase_dialog_path = NULL;

    mctx->cert_chain          = NULL;

    mctx->crl_path            = NULL;
    mctx->crl_file            = NULL;
    mctx->crl                 = NULL; /* set during module init */

    mctx->auth.ca_cert_path   = NULL;
    mctx->auth.ca_cert_file   = NULL;
    mctx->auth.cipher_suite   = NULL;
    mctx->auth.verify_depth   = UNSET;
    mctx->auth.verify_mode    = SSL_CVERIFY_UNSET;
}

static void modssl_ctx_init_proxy(SSLSrvConfigRec *sc,
                                  apr_pool_t *p)
{
    modssl_ctx_t *mctx;

    mctx = sc->proxy = apr_palloc(p, sizeof(*sc->proxy));

    modssl_ctx_init(mctx);

    mctx->pkp = apr_palloc(p, sizeof(*mctx->pkp));

    mctx->pkp->cert_file = NULL;
    mctx->pkp->cert_path = NULL;
    mctx->pkp->certs     = NULL;
}

static void modssl_ctx_init_server(SSLSrvConfigRec *sc,
                                   apr_pool_t *p)
{
    modssl_ctx_t *mctx;

    mctx = sc->server = apr_palloc(p, sizeof(*sc->server));

    modssl_ctx_init(mctx);

    mctx->pks = apr_pcalloc(p, sizeof(*mctx->pks));

    /* mctx->pks->... certs/keys are set during module init */
}

static SSLSrvConfigRec *ssl_config_server_new(apr_pool_t *p)
{
    SSLSrvConfigRec *sc = apr_palloc(p, sizeof(*sc));

    sc->mc                     = NULL;
    sc->enabled                = SSL_ENABLED_FALSE;
    sc->proxy_enabled          = UNSET;
    sc->vhost_id               = NULL;  /* set during module init */
    sc->vhost_id_len           = 0;     /* set during module init */
    sc->session_cache_timeout  = UNSET;
    sc->cipher_server_pref     = UNSET;
    sc->insecure_reneg         = UNSET;
    sc->proxy_ssl_check_peer_expire = SSL_ENABLED_UNSET;
    sc->proxy_ssl_check_peer_cn     = SSL_ENABLED_UNSET;
#ifndef OPENSSL_NO_TLSEXT
    sc->strict_sni_vhost_check = SSL_ENABLED_UNSET;
#endif
#ifdef HAVE_FIPS
    sc->fips                   = UNSET;
#endif

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
#define cfgMergeArray(el)   mrg->el = apr_array_append(p, add->el, base->el)
#define cfgMergeString(el)  cfgMerge(el, NULL)
#define cfgMergeBool(el)    cfgMerge(el, UNSET)
#define cfgMergeInt(el)     cfgMerge(el, UNSET)

static void modssl_ctx_cfg_merge(modssl_ctx_t *base,
                                 modssl_ctx_t *add,
                                 modssl_ctx_t *mrg)
{
    cfgMerge(protocol, SSL_PROTOCOL_ALL);

    cfgMerge(pphrase_dialog_type, SSL_PPTYPE_UNSET);
    cfgMergeString(pphrase_dialog_path);

    cfgMergeString(cert_chain);

    cfgMerge(crl_path, NULL);
    cfgMerge(crl_file, NULL);

    cfgMergeString(auth.ca_cert_path);
    cfgMergeString(auth.ca_cert_file);
    cfgMergeString(auth.cipher_suite);
    cfgMergeInt(auth.verify_depth);
    cfgMerge(auth.verify_mode, SSL_CVERIFY_UNSET);
}

static void modssl_ctx_cfg_merge_proxy(modssl_ctx_t *base,
                                       modssl_ctx_t *add,
                                       modssl_ctx_t *mrg)
{
    modssl_ctx_cfg_merge(base, add, mrg);

    cfgMergeString(pkp->cert_file);
    cfgMergeString(pkp->cert_path);
}

static void modssl_ctx_cfg_merge_server(modssl_ctx_t *base,
                                        modssl_ctx_t *add,
                                        modssl_ctx_t *mrg)
{
    int i;

    modssl_ctx_cfg_merge(base, add, mrg);

    for (i = 0; i < SSL_AIDX_MAX; i++) {
        cfgMergeString(pks->cert_files[i]);
        cfgMergeString(pks->key_files[i]);
    }

    cfgMergeString(pks->ca_name_path);
    cfgMergeString(pks->ca_name_file);
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
#ifndef OPENSSL_NO_TLSEXT
    cfgMerge(strict_sni_vhost_check, SSL_ENABLED_UNSET);
#endif
#ifdef HAVE_FIPS
    cfgMergeBool(fips);
#endif

    modssl_ctx_cfg_merge_proxy(base->proxy, add->proxy, mrg->proxy);

    modssl_ctx_cfg_merge_server(base->server, add->server, mrg->server);

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

const char *ssl_cmd_SSLMutex(cmd_parms *cmd,
                             void *dcfg,
                             const char *arg_)
{
    const char *err;
    SSLModConfigRec *mc = myModConfig(cmd->server);
    /* Split arg_ into meth and file */
    char *meth = apr_pstrdup(cmd->temp_pool, arg_);
    char *file = strchr(meth, ':');
    if (file) {
        *(file++) = '\0';
        if (!*file) {
            file = NULL;
        }
    }

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (ssl_config_global_isfixed(mc)) {
        return NULL;
    }
    if (!strcasecmp(meth, "none") || !strcasecmp(meth, "no")) {
        mc->nMutexMode  = SSL_MUTEXMODE_NONE;
        return NULL;
    }

    /* APR determines temporary filename unless overridden below,
     * we presume file indicates an szMutexFile is a file path
     * unless the method sets szMutexFile=file and NULLs file
     */
    mc->nMutexMode  = SSL_MUTEXMODE_USED;
    mc->szMutexFile = NULL;

    /* NOTE: previously, 'yes' implied 'sem' */
    if (!strcasecmp(meth, "default") || !strcasecmp(meth, "yes")) {
        mc->nMutexMech = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FCNTL_SERIALIZE
    else if ((!strcasecmp(meth, "fcntl") || !strcasecmp(meth, "file")) && file) {
        mc->nMutexMech = APR_LOCK_FCNTL;
    }
#endif
#if APR_HAS_FLOCK_SERIALIZE
    else if ((!strcasecmp(meth, "flock") || !strcasecmp(meth, "file")) && file) {
        mc->nMutexMech = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    else if (!strcasecmp(meth, "posixsem") || !strcasecmp(meth, "sem")) {
        mc->nMutexMech = APR_LOCK_POSIXSEM;
        /* Posix/SysV semaphores aren't file based, use the literal name
         * if provided and fall back on APR's default if not.  Today, APR
         * will ignore it, but once supported it has an absurdly short limit.
         */
        if (file) {
            mc->szMutexFile = apr_pstrdup(cmd->server->process->pool, file);

            file = NULL;
        }
    }
#endif
#if APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)
    else if (!strcasecmp(meth, "sysvsem") || !strcasecmp(meth, "sem")) {
        mc->nMutexMech = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(meth, "pthread")) {
        mc->nMutexMech = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return apr_pstrcat(cmd->pool, "Invalid SSLMutex argument ", arg_,
                           " (", ssl_valid_ssl_mutex_string, ")", NULL);
    }

    /* Unless the method above assumed responsibility for setting up
     * mc->szMutexFile and NULLing out file, presume it is a file we
     * are looking to use
     */
    if (file) {
        mc->szMutexFile = ap_server_root_relative(cmd->server->process->pool, file);
        if (!mc->szMutexFile) {
            return apr_pstrcat(cmd->pool, "Invalid SSLMutex ", meth,
                               ": filepath ", file, NULL);
        }
    }

    return NULL;
}

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
            ENGINE *en;
            err = apr_pstrcat(cmd->pool, err, ", '", ENGINE_get_id(e),
                                         "' (", ENGINE_get_name(e), ")", NULL);
            en = ENGINE_get_next(e);
            ENGINE_free(e);
            e = en;
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
#ifdef HAVE_SSL_RAND_EGD
        seed->nSrc   = SSL_RSSRC_EGD;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+4);
#else
    return "egd not supported with this SSL toolkit";
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

const char *ssl_cmd_SSLHonorCipherOrder(cmd_parms *cmd, void *dcfg, int flag)
{
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    sc->cipher_server_pref = flag?TRUE:FALSE;
    return NULL;
#else
    return "SSLHonorCiperOrder unsupported; not implemented by the SSL library";
#endif
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

#define SSL_AIDX_CERTS 1
#define SSL_AIDX_KEYS  2

static const char *ssl_cmd_check_aidx_max(cmd_parms *parms,
                                          const char *arg,
                                          int idx)
{
    SSLSrvConfigRec *sc = mySrvConfig(parms->server);
    const char *err, *desc=NULL, **files=NULL;
    int i;

    if ((err = ssl_cmd_check_file(parms, &arg))) {
        return err;
    }

    switch (idx) {
      case SSL_AIDX_CERTS:
        desc = "certificates";
        files = sc->server->pks->cert_files;
        break;
      case SSL_AIDX_KEYS:
        desc = "private keys";
        files = sc->server->pks->key_files;
        break;
    }

    for (i = 0; i < SSL_AIDX_MAX; i++) {
        if (!files[i]) {
            files[i] = arg;
            return NULL;
        }
    }

    return apr_psprintf(parms->pool,
                        "%s: only up to %d "
                        "different %s per virtual host allowed",
                         parms->cmd->name, SSL_AIDX_MAX, desc);
}

const char *ssl_cmd_SSLCertificateFile(cmd_parms *cmd,
                                       void *dcfg,
                                       const char *arg)
{

    const char *err;

    if ((err = ssl_cmd_check_aidx_max(cmd, arg, SSL_AIDX_CERTS))) {
        return err;
    }

    return NULL;
}

const char *ssl_cmd_SSLCertificateKeyFile(cmd_parms *cmd,
                                          void *dcfg,
                                          const char *arg)
{
    const char *err;

    if ((err = ssl_cmd_check_aidx_max(cmd, arg, SSL_AIDX_KEYS))) {
        return err;
    }

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

#define NO_PER_DIR_SSL_CA \
    "Your ssl library does not have support for per-directory CA"

#ifdef HAVE_SSL_SET_CERT_STORE
#   define MODSSL_HAVE_SSL_SET_CERT_STORE 1
#else
#   define MODSSL_HAVE_SSL_SET_CERT_STORE 0
#endif

#define MODSSL_SET_CA(f) \
    if (cmd->path) \
        if (MODSSL_HAVE_SSL_SET_CERT_STORE) \
            dc->f = arg; \
        else \
            return NO_PER_DIR_SSL_CA; \
    else \
        sc->f = arg \

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

#define MODSSL_NO_SHARED_MEMORY_ERROR \
    "SSLSessionCache: shared memory cache not useable on this platform"

const char *ssl_cmd_SSLSessionCache(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err, *colon;
    char *cp, *cp2;
    int arglen = strlen(arg);

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (ssl_config_global_isfixed(mc)) {
        return NULL;
    }

    if (strcEQ(arg, "none")) {
        mc->nSessionCacheMode      = SSL_SCMODE_NONE;
        mc->szSessionCacheDataFile = NULL;
    }
    else if (strcEQ(arg, "nonenotnull")) {
        mc->nSessionCacheMode      = SSL_SCMODE_NONE_NOT_NULL;
        mc->szSessionCacheDataFile = NULL;
    }
    else if ((arglen > 4) && strcEQn(arg, "dbm:", 4)) {
        mc->nSessionCacheMode      = SSL_SCMODE_DBM;
        mc->szSessionCacheDataFile = ap_server_root_relative(mc->pPool, arg+4);
        if (!mc->szSessionCacheDataFile) {
            return apr_psprintf(cmd->pool,
                                "SSLSessionCache: Invalid cache file path %s",
                                arg+4);
        }
    }
    else if (((arglen > 4) && strcEQn(arg, "shm:", 4)) ||
             ((arglen > 6) && strcEQn(arg, "shmht:", 6)) ||
             ((arglen > 6) && strcEQn(arg, "shmcb:", 6))) {
#if !APR_HAS_SHARED_MEMORY
        return MODSSL_NO_SHARED_MEMORY_ERROR;
#endif
        mc->nSessionCacheMode      = SSL_SCMODE_SHMCB;
        colon = ap_strchr_c(arg, ':');
        mc->szSessionCacheDataFile =
            ap_server_root_relative(mc->pPool, colon+1);
        if (!mc->szSessionCacheDataFile) {
            return apr_psprintf(cmd->pool,
                                "SSLSessionCache: Invalid cache file path %s",
                                colon+1);
        }
        mc->tSessionCacheDataTable = NULL;
        mc->nSessionCacheDataSize  = 1024*512; /* 512KB */

        if ((cp = strchr(mc->szSessionCacheDataFile, '('))) {
            *cp++ = NUL;

            if (!(cp2 = strchr(cp, ')'))) {
                return "SSLSessionCache: Invalid argument: "
                       "no closing parenthesis";
            }

            *cp2 = NUL;

            mc->nSessionCacheDataSize = atoi(cp);

            if (mc->nSessionCacheDataSize < 8192) {
                return "SSLSessionCache: Invalid argument: "
                       "size has to be >= 8192 bytes";

            }

            if (mc->nSessionCacheDataSize >= APR_SHM_MAXSIZE) {
                return apr_psprintf(cmd->pool,
                                    "SSLSessionCache: Invalid argument: "
                                    "size has to be < %d bytes on this "
                                    "platform", APR_SHM_MAXSIZE);

            }
        }
    }
    else if ((arglen > 3) && strcEQn(arg, "dc:", 3)) {
#ifdef HAVE_DISTCACHE
        mc->nSessionCacheMode      = SSL_SCMODE_DC;
        mc->szSessionCacheDataFile = apr_pstrdup(mc->pPool, arg+3);
        if (!mc->szSessionCacheDataFile) {
            return apr_pstrcat(cmd->pool,
                               "SSLSessionCache: Invalid cache file path: ",
                               arg+3, NULL);
        }
#else
        return "SSLSessionCache: distcache support disabled";
#endif
    }
    else {
        return "SSLSessionCache: Invalid argument";
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
        w = ap_getword_conf(cmd->pool, &arg);
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
    ssl_expr *expr;
    ssl_require_t *require;

    if (!(expr = ssl_expr_comp(cmd->pool, (char *)arg))) {
        return apr_pstrcat(cmd->pool, "SSLRequire: ",
                           ssl_expr_get_error(), NULL);
    }

    require = apr_array_push(dc->aRequirement);
    require->cpExpr = apr_pstrdup(cmd->pool, arg);
    require->mpExpr = expr;

    return NULL;
}

const char *ssl_cmd_SSLRenegBufferSize(cmd_parms *cmd, void *dcfg, const char *arg)
{
    SSLDirConfigRec *dc = dcfg;
    
    dc->nRenegBufferSize = atoi(arg);
    if (dc->nRenegBufferSize < 0) {
        return apr_pstrcat(cmd->pool, "Invalid size for SSLRenegBufferSize: ",
                           arg, NULL);
    }

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
#ifdef OPENSSL_NO_SSL2
            if (action != '-') {
                return "SSLv2 not supported by this version of OpenSSL";
            }
#endif
            thisopt = SSL_PROTOCOL_SSLV2;
        }
        else if (strcEQ(w, "SSLv3")) {
            thisopt = SSL_PROTOCOL_SSLV3;
        }
        else if (strcEQ(w, "TLSv1")) {
            thisopt = SSL_PROTOCOL_TLSV1;
        }
        else if (strcEQ(w, "all")) {
            thisopt = SSL_PROTOCOL_ALL;
        }
        else {
            return apr_pstrcat(parms->temp_pool,
                               parms->cmd->name,
                               ": Illegal protocol '",
                               w, "'", NULL);
        }

        if (action == '-') {
            *options &= ~thisopt;
        }
        else if (action == '+') {
            *options |= thisopt;
        }
        else {
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

    return ssl_cmd_protocol_parse(cmd, arg, &sc->proxy->protocol);
}

const char *ssl_cmd_SSLProxyCipherSuite(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

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


const char *ssl_cmd_SSLUserName(cmd_parms *cmd, void *dcfg,
                                const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    dc->szUserName = arg;
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

const char  *ssl_cmd_SSLStrictSNIVHostCheck(cmd_parms *cmd, void *dcfg, int flag)
{
#ifndef OPENSSL_NO_TLSEXT
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->strict_sni_vhost_check = flag ? SSL_ENABLED_TRUE : SSL_ENABLED_FALSE;

    return NULL;
#else
    return "SSLStrictSNIVHostCheck failed; OpenSSL is not built with support "
           "for TLS extensions and SNI indication. Refer to the "
           "documentation, and build a compatible version of OpenSSL.";
#endif
}

void ssl_hook_ConfigTest(apr_pool_t *pconf, server_rec *s)
{
    if (!ap_exists_config_define("DUMP_CERTS")) {
        return;
    }

    /* Dump the filenames of all configured server certificates to
     * stdout. */
    while (s) {
        SSLSrvConfigRec *sc = mySrvConfig(s);

        if (sc && sc->server && sc->server->pks) {
            modssl_pk_server_t *const pks = sc->server->pks;
            int i;

            for (i = 0; (i < SSL_AIDX_MAX) && pks->cert_files[i]; i++) {
                printf("%s\n", pks->cert_files[i]);
            }
        }

        s = s->next;
    }

}
