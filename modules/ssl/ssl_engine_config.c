/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_config.c
**  Apache Configuration Directives
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

                                      /* ``Damned if you do,
                                           damned if you don't.''
                                               -- Unknown        */
#include "mod_ssl.h"


/*  _________________________________________________________________
**
**  Support for Global Configuration
**  _________________________________________________________________
*/

void ssl_hook_AddModule(module *m)
{
    if (m == &ssl_module) {
        /*
         * Announce us for the configuration files
         */
        ap_add_config_define("MOD_SSL");

        /*
         * Link ourself into the Apache kernel
         */
        ssl_var_register();
        ssl_ext_register();
        ssl_io_register();
#if defined(SSL_VENDOR) && defined(SSL_VENDOR_OBJS)
        ssl_vendor_register();
#endif
    }
    return;
}

void ssl_hook_RemoveModule(module *m)
{
    if (m == &ssl_module) {
        /*
         * Unlink ourself from the Apache kernel
         */
        ssl_var_unregister();
        ssl_ext_unregister();
        ssl_io_unregister();
#if defined(SSL_VENDOR) && defined(SSL_VENDOR_OBJS)
        ssl_vendor_unregister();
#endif
    }
    return;
}

void ssl_config_global_create(void)
{
    pool *pPool;
    SSLModConfigRec *mc;

    mc = ap_ctx_get(ap_global_ctx, "ssl_module");
    if (mc == NULL) {
        /*
         * allocate an own subpool which survives server restarts
         */
        pPool = ap_make_sub_pool(NULL);
        mc = (SSLModConfigRec *)ap_palloc(pPool, sizeof(SSLModConfigRec));
        mc->pPool = pPool;
        mc->bFixed = FALSE;

        /*
         * initialize per-module configuration
         */
        mc->nInitCount             = 0;
        mc->nSessionCacheMode      = SSL_SCMODE_UNSET;
        mc->szSessionCacheDataFile = NULL;
        mc->nSessionCacheDataSize  = 0;
        mc->pSessionCacheDataMM    = NULL;
        mc->tSessionCacheDataTable = NULL;
        mc->nMutexMode             = SSL_MUTEXMODE_UNSET;
        mc->szMutexFile            = NULL;
        mc->nMutexFD               = -1;
        mc->nMutexSEMID            = -1;
        mc->aRandSeed              = ap_make_array(pPool, 4, sizeof(ssl_randseed_t));
        mc->tPrivateKey            = ssl_ds_table_make(pPool, sizeof(ssl_asn1_t));
        mc->tPublicCert            = ssl_ds_table_make(pPool, sizeof(ssl_asn1_t));
        mc->tTmpKeys               = ssl_ds_table_make(pPool, sizeof(ssl_asn1_t));
#ifdef SSL_EXPERIMENTAL_ENGINE
        mc->szCryptoDevice         = NULL;
#endif

        (void)memset(mc->pTmpKeys, 0, SSL_TKPIDX_MAX*sizeof(void *));

#ifdef SSL_VENDOR
        mc->ctx = ap_ctx_new(pPool);
        ap_hook_use("ap::mod_ssl::vendor::config_global_create",
                AP_HOOK_SIG2(void,ptr), AP_HOOK_MODE_ALL, mc);
#endif

        /*
         * And push it into Apache's global context
         */
        ap_ctx_set(ap_global_ctx, "ssl_module", mc);
    }
    return;
}

void ssl_config_global_fix(void)
{
    SSLModConfigRec *mc = myModConfig();
    mc->bFixed = TRUE;
    return;
}

BOOL ssl_config_global_isfixed(void)
{
    SSLModConfigRec *mc = myModConfig();
    return (mc->bFixed);
}


/*  _________________________________________________________________
**
**  Configuration handling
**  _________________________________________________________________
*/

/*
 *  Create per-server SSL configuration
 */
void *ssl_config_server_create(pool *p, server_rec *s)
{
    SSLSrvConfigRec *sc;

    ssl_config_global_create();

    sc = ap_palloc(p, sizeof(SSLSrvConfigRec));
    sc->bEnabled               = UNSET;
    sc->szCACertificatePath    = NULL;
    sc->szCACertificateFile    = NULL;
    sc->szCertificateChain     = NULL;
    sc->szLogFile              = NULL;
    sc->szCipherSuite          = NULL;
    sc->nLogLevel              = SSL_LOG_NONE;
    sc->nVerifyDepth           = UNSET;
    sc->nVerifyClient          = SSL_CVERIFY_UNSET;
    sc->nSessionCacheTimeout   = UNSET;
    sc->nPassPhraseDialogType  = SSL_PPTYPE_UNSET;
    sc->szPassPhraseDialogPath = NULL;
    sc->nProtocol              = SSL_PROTOCOL_ALL;
    sc->fileLogFile            = NULL;
    sc->pSSLCtx                = NULL;
    sc->szCARevocationPath     = NULL;
    sc->szCARevocationFile     = NULL;
    sc->pRevocationStore       = NULL;

#ifdef SSL_EXPERIMENTAL_PROXY
    sc->nProxyVerifyDepth             = UNSET;
    sc->szProxyCACertificatePath      = NULL;
    sc->szProxyCACertificateFile      = NULL;
    sc->szProxyClientCertificateFile  = NULL;
    sc->szProxyClientCertificatePath  = NULL;
    sc->szProxyCipherSuite            = NULL;
    sc->nProxyProtocol                = SSL_PROTOCOL_ALL & ~SSL_PROTOCOL_TLSV1;
    sc->bProxyVerify                  = UNSET;
    sc->pSSLProxyCtx                  = NULL;
#endif

    (void)memset(sc->szPublicCertFile, 0, SSL_AIDX_MAX*sizeof(char *));
    (void)memset(sc->szPrivateKeyFile, 0, SSL_AIDX_MAX*sizeof(char *));
    (void)memset(sc->pPublicCert, 0, SSL_AIDX_MAX*sizeof(X509 *));
    (void)memset(sc->pPrivateKey, 0, SSL_AIDX_MAX*sizeof(EVP_PKEY *));

#ifdef SSL_VENDOR
    sc->ctx = ap_ctx_new(p);
    ap_hook_use("ap::mod_ssl::vendor::config_server_create",
                AP_HOOK_SIG4(void,ptr,ptr,ptr), AP_HOOK_MODE_ALL,
                p, s, sc);
#endif

    return sc;
}

/*
 *  Merge per-server SSL configurations
 */
void *ssl_config_server_merge(pool *p, void *basev, void *addv)
{
    SSLSrvConfigRec *base = (SSLSrvConfigRec *)basev;
    SSLSrvConfigRec *add  = (SSLSrvConfigRec *)addv;
    SSLSrvConfigRec *new  = (SSLSrvConfigRec *)ap_palloc(p, sizeof(SSLSrvConfigRec));
    int i;

    cfgMergeBool(bEnabled);
    cfgMergeString(szCACertificatePath);
    cfgMergeString(szCACertificateFile);
    cfgMergeString(szCertificateChain);
    cfgMergeString(szLogFile);
    cfgMergeString(szCipherSuite);
    cfgMerge(nLogLevel, SSL_LOG_NONE);
    cfgMergeInt(nVerifyDepth);
    cfgMerge(nVerifyClient, SSL_CVERIFY_UNSET);
    cfgMergeInt(nSessionCacheTimeout);
    cfgMerge(nPassPhraseDialogType, SSL_PPTYPE_UNSET);
    cfgMergeString(szPassPhraseDialogPath);
    cfgMerge(nProtocol, SSL_PROTOCOL_ALL);
    cfgMerge(fileLogFile, NULL);
    cfgMerge(pSSLCtx, NULL);
    cfgMerge(szCARevocationPath, NULL);
    cfgMerge(szCARevocationFile, NULL);
    cfgMerge(pRevocationStore, NULL);

    for (i = 0; i < SSL_AIDX_MAX; i++) {
        cfgMergeString(szPublicCertFile[i]);
        cfgMergeString(szPrivateKeyFile[i]);
        cfgMerge(pPublicCert[i], NULL);
        cfgMerge(pPrivateKey[i], NULL);
    }

#ifdef SSL_VENDOR
    cfgMergeCtx(ctx);
    ap_hook_use("ap::mod_ssl::vendor::config_server_merge",
                AP_HOOK_SIG5(void,ptr,ptr,ptr,ptr), AP_HOOK_MODE_ALL,
                p, base, add, new);
#endif

#ifdef SSL_EXPERIMENTAL_PROXY
    cfgMergeInt(nProxyVerifyDepth);
    cfgMergeString(szProxyCACertificatePath);
    cfgMergeString(szProxyCACertificateFile);
    cfgMergeString(szProxyClientCertificateFile);
    cfgMergeString(szProxyClientCertificatePath);
    cfgMergeString(szProxyCipherSuite);
    cfgMerge(nProxyProtocol, (SSL_PROTOCOL_ALL & ~SSL_PROTOCOL_TLSV1));
    cfgMergeBool(bProxyVerify);
    cfgMerge(pSSLProxyCtx, NULL);
#endif

    return new;
}

/*
 *  Create per-directory SSL configuration
 */
void *ssl_config_perdir_create(pool *p, char *dir)
{
    SSLDirConfigRec *dc = ap_palloc(p, sizeof(SSLDirConfigRec));

    dc->bSSLRequired  = FALSE;
    dc->aRequirement  = ap_make_array(p, 4, sizeof(ssl_require_t));
    dc->nOptions      = SSL_OPT_NONE|SSL_OPT_RELSET;
    dc->nOptionsAdd   = SSL_OPT_NONE;
    dc->nOptionsDel   = SSL_OPT_NONE;

    dc->szCipherSuite          = NULL;
    dc->nVerifyClient          = SSL_CVERIFY_UNSET;
    dc->nVerifyDepth           = UNSET;
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    dc->szCACertificatePath    = NULL;
    dc->szCACertificateFile    = NULL;
#endif

#ifdef SSL_VENDOR
    dc->ctx = ap_ctx_new(p);
    ap_hook_use("ap::mod_ssl::vendor::config_perdir_create",
                AP_HOOK_SIG4(void,ptr,ptr,ptr), AP_HOOK_MODE_ALL,
                p, dir, dc);
#endif

    return dc;
}

/*
 *  Merge per-directory SSL configurations
 */
void *ssl_config_perdir_merge(pool *p, void *basev, void *addv)
{
    SSLDirConfigRec *base = (SSLDirConfigRec *)basev;
    SSLDirConfigRec *add  = (SSLDirConfigRec *)addv;
    SSLDirConfigRec *new  = (SSLDirConfigRec *)ap_palloc(p,
                                               sizeof(SSLDirConfigRec));

    cfgMerge(bSSLRequired, FALSE);
    cfgMergeArray(aRequirement);

    if (add->nOptions & SSL_OPT_RELSET) {
        new->nOptionsAdd = (base->nOptionsAdd & ~(add->nOptionsDel)) | add->nOptionsAdd;
        new->nOptionsDel = (base->nOptionsDel & ~(add->nOptionsAdd)) | add->nOptionsDel;
        new->nOptions    = (base->nOptions    & ~(new->nOptionsDel)) | new->nOptionsAdd;
    }
    else {
        new->nOptions    = add->nOptions;
        new->nOptionsAdd = add->nOptionsAdd;
        new->nOptionsDel = add->nOptionsDel;
    }

    cfgMergeString(szCipherSuite);
    cfgMerge(nVerifyClient, SSL_CVERIFY_UNSET);
    cfgMergeInt(nVerifyDepth);
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    cfgMergeString(szCACertificatePath);
    cfgMergeString(szCACertificateFile);
#endif

#ifdef SSL_VENDOR
    cfgMergeCtx(ctx);
    ap_hook_use("ap::mod_ssl::vendor::config_perdir_merge",
                AP_HOOK_SIG5(void,ptr,ptr,ptr,ptr), AP_HOOK_MODE_ALL,
                p, base, add, new);
#endif

    return new;
}

/*
 * Directive Rewriting
 */

char *ssl_hook_RewriteCommand(cmd_parms *cmd, void *config, const char *cmd_line)
{
#ifdef SSL_COMPAT
    return ssl_compat_directive(cmd->server, cmd->pool, cmd_line);
#else
    return NULL;
#endif
}

/*
 *  Configuration functions for particular directives
 */

const char *ssl_cmd_SSLMutex(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    const char *err;
    SSLModConfigRec *mc = myModConfig();

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)) != NULL)
        return err;
    if (ssl_config_global_isfixed())
        return NULL;
    if (strcEQ(arg, "none")) {
        mc->nMutexMode  = SSL_MUTEXMODE_NONE;
    }
    else if (strlen(arg) > 5 && strcEQn(arg, "file:", 5)) {
#ifndef WIN32
        mc->nMutexMode  = SSL_MUTEXMODE_FILE;
        mc->szMutexFile = ap_psprintf(mc->pPool, "%s.%lu",
                                      ssl_util_server_root_relative(cmd->pool, "mutex", arg+5),
                                      (unsigned long)getpid());
#else
        return "SSLMutex: Lockfiles not available on this platform";
#endif
    }
    else if (strcEQ(arg, "sem")) {
#ifdef SSL_CAN_USE_SEM
        mc->nMutexMode  = SSL_MUTEXMODE_SEM;
#else
        return "SSLMutex: Semaphores not available on this platform";
#endif
    }
    else
        return "SSLMutex: Invalid argument";
    return NULL;
}

const char *ssl_cmd_SSLPassPhraseDialog(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)) != NULL)
        return err;
    if (strcEQ(arg, "builtin")) {
        sc->nPassPhraseDialogType  = SSL_PPTYPE_BUILTIN;
        sc->szPassPhraseDialogPath = NULL;
    }
    else if (strlen(arg) > 5 && strEQn(arg, "exec:", 5)) {
        sc->nPassPhraseDialogType  = SSL_PPTYPE_FILTER;
        sc->szPassPhraseDialogPath = ssl_util_server_root_relative(cmd->pool, "dialog", arg+5);
        if (!ssl_util_path_check(SSL_PCM_EXISTS, sc->szPassPhraseDialogPath))
            return ap_pstrcat(cmd->pool, "SSLPassPhraseDialog: file '",
                              sc->szPassPhraseDialogPath, "' not exists", NULL);
    }
    else
        return "SSLPassPhraseDialog: Invalid argument";
    return NULL;
}

#ifdef SSL_EXPERIMENTAL_ENGINE
const char *ssl_cmd_SSLCryptoDevice(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLModConfigRec *mc = myModConfig();
    const char *err;
    ENGINE *e;
#if SSL_LIBRARY_VERSION >= 0x00907000
    static int loaded_engines = FALSE;

    /* early loading to make sure the engines are already 
       available for ENGINE_by_id() above... */
    if (!loaded_engines) {
        ENGINE_load_builtin_engines();
        loaded_engines = TRUE;
    }
#endif
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)) != NULL)
        return err;
    if (strcEQ(arg, "builtin")) {
        mc->szCryptoDevice = NULL;
    }
    else if ((e = ENGINE_by_id(arg)) != NULL) {
        mc->szCryptoDevice = arg;
        ENGINE_free(e);
    }
    else
        return "SSLCryptoDevice: Invalid argument";
    return NULL;
}
#endif

const char *ssl_cmd_SSLRandomSeed(
    cmd_parms *cmd, char *struct_ptr, char *arg1, char *arg2, char *arg3)
{
    SSLModConfigRec *mc = myModConfig();
    const char *err;
    ssl_randseed_t *pRS;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)) != NULL)
        return err;
    if (ssl_config_global_isfixed())
        return NULL;
    pRS = ap_push_array(mc->aRandSeed);
    if (strcEQ(arg1, "startup"))
        pRS->nCtx = SSL_RSCTX_STARTUP;
    else if (strcEQ(arg1, "connect"))
        pRS->nCtx = SSL_RSCTX_CONNECT;
    else
        return ap_pstrcat(cmd->pool, "SSLRandomSeed: "
                          "invalid context: `", arg1, "'");
    if (strlen(arg2) > 5 && strEQn(arg2, "file:", 5)) {
        pRS->nSrc   = SSL_RSSRC_FILE;
        pRS->cpPath = ap_pstrdup(mc->pPool, ssl_util_server_root_relative(cmd->pool, "random", arg2+5));
    }
    else if (strlen(arg2) > 5 && strEQn(arg2, "exec:", 5)) {
        pRS->nSrc   = SSL_RSSRC_EXEC;
        pRS->cpPath = ap_pstrdup(mc->pPool, ssl_util_server_root_relative(cmd->pool, "random", arg2+5));
    }
#if SSL_LIBRARY_VERSION >= 0x00905100
    else if (strlen(arg2) > 4 && strEQn(arg2, "egd:", 4)) {
        pRS->nSrc   = SSL_RSSRC_EGD;
        pRS->cpPath = ap_pstrdup(mc->pPool, ssl_util_server_root_relative(cmd->pool, "random", arg2+4));
    }
#endif
    else if (strcEQ(arg2, "builtin")) {
        pRS->nSrc   = SSL_RSSRC_BUILTIN;
        pRS->cpPath = NULL;
    }
    else {
        pRS->nSrc   = SSL_RSSRC_FILE;
        pRS->cpPath = ap_pstrdup(mc->pPool, ssl_util_server_root_relative(cmd->pool, "random", arg2));
    }
    if (pRS->nSrc != SSL_RSSRC_BUILTIN)
        if (!ssl_util_path_check(SSL_PCM_EXISTS, pRS->cpPath))
            return ap_pstrcat(cmd->pool, "SSLRandomSeed: source path '",
                              pRS->cpPath, "' not exists", NULL);
    if (arg3 == NULL)
        pRS->nBytes = 0; /* read whole file */
    else {
        if (pRS->nSrc == SSL_RSSRC_BUILTIN)
            return "SSLRandomSeed: byte specification not "
                   "allowed for builtin seed source";
        pRS->nBytes = atoi(arg3);
        if (pRS->nBytes < 0)
            return "SSLRandomSeed: invalid number of bytes specified";
    }
    return NULL;
}

const char *ssl_cmd_SSLEngine(
    cmd_parms *cmd, char *struct_ptr, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->bEnabled = (flag ? TRUE : FALSE);
    return NULL;
}

const char *ssl_cmd_SSLCipherSuite(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    if (cmd->path == NULL || dc == NULL)
        sc->szCipherSuite = arg;
    else
        dc->szCipherSuite = arg;
    return NULL;
}

const char *ssl_cmd_SSLCertificateFile(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;
    int i;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCertificateFile: file '",
                          cpPath, "' not exists or empty", NULL);
    for (i = 0; i < SSL_AIDX_MAX && sc->szPublicCertFile[i] != NULL; i++)
        ;
    if (i == SSL_AIDX_MAX)
        return ap_psprintf(cmd->pool, "SSLCertificateFile: only up to %d "
                          "different certificates per virtual host allowed", 
                          SSL_AIDX_MAX);
    sc->szPublicCertFile[i] = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLCertificateKeyFile(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;
    int i;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCertificateKeyFile: file '",
                          cpPath, "' not exists or empty", NULL);
    for (i = 0; i < SSL_AIDX_MAX && sc->szPrivateKeyFile[i] != NULL; i++)
        ;
    if (i == SSL_AIDX_MAX)
        return ap_psprintf(cmd->pool, "SSLCertificateKeyFile: only up to %d "
                          "different private keys per virtual host allowed", 
                          SSL_AIDX_MAX);
    sc->szPrivateKeyFile[i] = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLCertificateChainFile(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCertificateChainFile: file '",
                          cpPath, "' not exists or empty", NULL);
    sc->szCertificateChain = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLCACertificatePath(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISDIR, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCACertificatePath: directory '",
                          cpPath, "' not exists", NULL);
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    if (cmd->path == NULL || dc == NULL)
        sc->szCACertificatePath = cpPath;
    else
        dc->szCACertificatePath = cpPath;
#else
    sc->szCACertificatePath = cpPath;
#endif
    return NULL;
}

const char *ssl_cmd_SSLCACertificateFile(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCACertificateFile: file '",
                          cpPath, "' not exists or empty", NULL);
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    if (cmd->path == NULL || dc == NULL)
        sc->szCACertificateFile = cpPath;
    else
        dc->szCACertificateFile = cpPath;
#else
    sc->szCACertificateFile = cpPath;
#endif
    return NULL;
}

const char *ssl_cmd_SSLCARevocationPath(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISDIR, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCARecocationPath: directory '",
                          cpPath, "' not exists", NULL);
    sc->szCARevocationPath = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLCARevocationFile(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLCARevocationFile: file '",
                          cpPath, "' not exists or empty", NULL);
    sc->szCARevocationFile = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLVerifyClient(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *level)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    ssl_verify_t id;

    if (strEQ(level, "0") || strcEQ(level, "none"))
        id = SSL_CVERIFY_NONE;
    else if (strEQ(level, "1") || strcEQ(level, "optional"))
        id = SSL_CVERIFY_OPTIONAL;
    else if (strEQ(level, "2") || strcEQ(level, "require"))
        id = SSL_CVERIFY_REQUIRE;
    else if (strEQ(level, "3") || strcEQ(level, "optional_no_ca"))
        id = SSL_CVERIFY_OPTIONAL_NO_CA;
    else
        return "SSLVerifyClient: Invalid argument";
    if (cmd->path == NULL || dc == NULL)
        sc->nVerifyClient = id;
    else
        dc->nVerifyClient = id;
    return NULL;
}

const char *ssl_cmd_SSLVerifyDepth(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    int d;

    d = atoi(arg);
    if (d < 0)
        return "SSLVerifyDepth: Invalid argument";
    if (cmd->path == NULL || dc == NULL)
        sc->nVerifyDepth = d;
    else
        dc->nVerifyDepth = d;
    return NULL;
}

const char *ssl_cmd_SSLSessionCache(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    const char *err;
    SSLModConfigRec *mc = myModConfig();
    char *cp, *cp2;
    int maxsize;

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY)) != NULL)
        return err;
    if (ssl_config_global_isfixed())
        return NULL;
    if (strcEQ(arg, "none")) {
        mc->nSessionCacheMode      = SSL_SCMODE_NONE;
        mc->szSessionCacheDataFile = NULL;
    }
    else if (strlen(arg) > 4 && strcEQn(arg, "dbm:", 4)) {
        mc->nSessionCacheMode      = SSL_SCMODE_DBM;
        mc->szSessionCacheDataFile = ap_pstrdup(mc->pPool,
                                     ssl_util_server_root_relative(cmd->pool, "scache", arg+4));
    }
    else if (   (strlen(arg) > 4 && strcEQn(arg, "shm:",   4)) 
             || (strlen(arg) > 6 && strcEQn(arg, "shmht:", 6))) {
        if (!ap_mm_useable())
            return "SSLSessionCache: shared memory cache not useable on this platform";
        mc->nSessionCacheMode      = SSL_SCMODE_SHMHT;
        cp = strchr(arg, ':');
        mc->szSessionCacheDataFile = ap_pstrdup(mc->pPool,
                                     ssl_util_server_root_relative(cmd->pool, "scache", cp+1));
        mc->tSessionCacheDataTable = NULL;
        mc->nSessionCacheDataSize  = 1024*512; /* 512KB */
        if ((cp = strchr(mc->szSessionCacheDataFile, '(')) != NULL) {
            *cp++ = NUL;
            if ((cp2 = strchr(cp, ')')) == NULL)
                return "SSLSessionCache: Invalid argument: no closing parenthesis";
            *cp2 = NUL;
            mc->nSessionCacheDataSize = atoi(cp);
            if (mc->nSessionCacheDataSize <= 8192)
                return "SSLSessionCache: Invalid argument: size has to be >= 8192 bytes";
            maxsize = ap_mm_core_maxsegsize();
            if (mc->nSessionCacheDataSize >= maxsize)
                return ap_psprintf(cmd->pool, "SSLSessionCache: Invalid argument: "
                                   "size has to be < %d bytes on this platform", maxsize);
        }
    }
    else if (strlen(arg) > 6 && strcEQn(arg, "shmcb:", 6)) {
        if (!ap_mm_useable())
            return "SSLSessionCache: shared memory cache not useable on this platform";
        mc->nSessionCacheMode      = SSL_SCMODE_SHMCB;
        mc->szSessionCacheDataFile = ap_pstrdup(mc->pPool,
                                     ap_server_root_relative(cmd->pool, arg+6));
        mc->tSessionCacheDataTable = NULL;
        mc->nSessionCacheDataSize  = 1024*512; /* 512KB */
        if ((cp = strchr(mc->szSessionCacheDataFile, '(')) != NULL) {
            *cp++ = NUL;
            if ((cp2 = strchr(cp, ')')) == NULL)
                return "SSLSessionCache: Invalid argument: no closing parenthesis";
            *cp2 = NUL;
            mc->nSessionCacheDataSize = atoi(cp);
            if (mc->nSessionCacheDataSize <= 8192)
                return "SSLSessionCache: Invalid argument: size has to be >= 8192 bytes";
            maxsize = ap_mm_core_maxsegsize();
            if (mc->nSessionCacheDataSize >= maxsize)
                return ap_psprintf(cmd->pool, "SSLSessionCache: Invalid argument: "
                                   "size has to be < %d bytes on this platform", maxsize);
        }
    }
	else
#ifdef SSL_VENDOR
        if (!ap_hook_use("ap::mod_ssl::vendor::cmd_sslsessioncache",
             AP_HOOK_SIG4(void,ptr,ptr,ptr), AP_HOOK_MODE_ALL,
             cmd, arg, mc))
#endif
        return "SSLSessionCache: Invalid argument";
    return NULL;
}

const char *ssl_cmd_SSLSessionCacheTimeout(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->nSessionCacheTimeout = atoi(arg);
    if (sc->nSessionCacheTimeout < 0)
        return "SSLSessionCacheTimeout: Invalid argument";
    return NULL;
}

const char *ssl_cmd_SSLLog(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd,  NOT_IN_LIMIT|NOT_IN_DIRECTORY
                                         |NOT_IN_LOCATION|NOT_IN_FILES )) != NULL)
        return err;
    sc->szLogFile = arg;
    return NULL;
}

const char *ssl_cmd_SSLLogLevel(
    cmd_parms *cmd, char *struct_ptr, char *level)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    const char *err;

    if ((err = ap_check_cmd_context(cmd,  NOT_IN_LIMIT|NOT_IN_DIRECTORY
                                         |NOT_IN_LOCATION|NOT_IN_FILES )) != NULL)
        return err;
    if (strcEQ(level, "none"))
        sc->nLogLevel = SSL_LOG_NONE;
    else if (strcEQ(level, "error"))
        sc->nLogLevel = SSL_LOG_ERROR;
    else if (strcEQ(level, "warn"))
        sc->nLogLevel = SSL_LOG_WARN;
    else if (strcEQ(level, "info"))
        sc->nLogLevel = SSL_LOG_INFO;
    else if (strcEQ(level, "trace"))
        sc->nLogLevel = SSL_LOG_TRACE;
    else if (strcEQ(level, "debug"))
        sc->nLogLevel = SSL_LOG_DEBUG;
    else
        return "SSLLogLevel: Invalid argument";
    return NULL;
}

const char *ssl_cmd_SSLOptions(
    cmd_parms *cmd, SSLDirConfigRec *dc, const char *cpLine)
{
    ssl_opt_t opt;
    int first;
    char action;
    char *w;

    first = TRUE;
    while (cpLine[0] != NUL) {
        w = ap_getword_conf(cmd->pool, &cpLine);
        action = NUL;

        if (*w == '+' || *w == '-') {
            action = *(w++);
        }
        else if (first) {
            dc->nOptions = SSL_OPT_NONE;
            first = FALSE;
        }

        if (strcEQ(w, "StdEnvVars"))
            opt = SSL_OPT_STDENVVARS;
        else if (strcEQ(w, "CompatEnvVars"))
            opt = SSL_OPT_COMPATENVVARS;
        else if (strcEQ(w, "ExportCertData"))
            opt = SSL_OPT_EXPORTCERTDATA;
        else if (strcEQ(w, "FakeBasicAuth"))
            opt = SSL_OPT_FAKEBASICAUTH;
        else if (strcEQ(w, "StrictRequire"))
            opt = SSL_OPT_STRICTREQUIRE;
        else if (strcEQ(w, "OptRenegotiate"))
            opt = SSL_OPT_OPTRENEGOTIATE;
        else
            return ap_pstrcat(cmd->pool, "SSLOptions: Illegal option '", w, "'", NULL);

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

const char *ssl_cmd_SSLRequireSSL(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *cipher)
{
    dc->bSSLRequired = TRUE;
    return NULL;
}

const char *ssl_cmd_SSLRequire(
    cmd_parms *cmd, SSLDirConfigRec *dc, char *cpExpr)
{
    ssl_expr *mpExpr;
    ssl_require_t *pReqRec;

    if ((mpExpr = ssl_expr_comp(cmd->pool, cpExpr)) == NULL)
        return ap_pstrcat(cmd->pool, "SSLRequire: ", ssl_expr_get_error(), NULL);
    pReqRec = ap_push_array(dc->aRequirement);
    pReqRec->cpExpr = ap_pstrdup(cmd->pool, cpExpr);
    pReqRec->mpExpr = mpExpr;
    return NULL;
}

const char *ssl_cmd_SSLProtocol(
    cmd_parms *cmd, char *struct_ptr, const char *opt)
{
    SSLSrvConfigRec *sc;
    ssl_proto_t options, thisopt;
    char action;
    char *w;

    sc = mySrvConfig(cmd->server);
    options = SSL_PROTOCOL_NONE;
    while (opt[0] != NUL) {
        w = ap_getword_conf(cmd->pool, &opt);

        action = NUL;
        if (*w == '+' || *w == '-')
            action = *(w++);

        if (strcEQ(w, "SSLv2"))
            thisopt = SSL_PROTOCOL_SSLV2;
        else if (strcEQ(w, "SSLv3"))
            thisopt = SSL_PROTOCOL_SSLV3;
        else if (strcEQ(w, "TLSv1"))
            thisopt = SSL_PROTOCOL_TLSV1;
        else if (strcEQ(w, "all"))
            thisopt = SSL_PROTOCOL_ALL;
        else
            return ap_pstrcat(cmd->pool, "SSLProtocol: Illegal protocol '", w, "'", NULL);

        if (action == '-')
            options &= ~thisopt;
        else if (action == '+')
            options |= thisopt;
        else
            options = thisopt;
    }
    sc->nProtocol = options;
    return NULL;
}

#ifdef SSL_EXPERIMENTAL_PROXY

const char *ssl_cmd_SSLProxyProtocol(
    cmd_parms *cmd, char *struct_ptr, const char *opt)
{
    SSLSrvConfigRec *sc;
    ssl_proto_t options, thisopt;
    char action;
    char *w;

    sc = mySrvConfig(cmd->server);
    options = SSL_PROTOCOL_NONE;
    while (opt[0] != NUL) {
        w = ap_getword_conf(cmd->pool, &opt);

        action = NUL;
        if (*w == '+' || *w == '-')
            action = *(w++);

        if (strcEQ(w, "SSLv2"))
            thisopt = SSL_PROTOCOL_SSLV2;
        else if (strcEQ(w, "SSLv3"))
            thisopt = SSL_PROTOCOL_SSLV3;
        else if (strcEQ(w, "TLSv1"))
            thisopt = SSL_PROTOCOL_TLSV1;
        else if (strcEQ(w, "all"))
            thisopt = SSL_PROTOCOL_ALL;
        else
            return ap_pstrcat(cmd->pool, "SSLProxyProtocol: "
                              "Illegal protocol '", w, "'", NULL);
        if (action == '-')
            options &= ~thisopt;
        else if (action == '+')
            options |= thisopt;
        else
            options = thisopt;
    }
    sc->nProxyProtocol = options;
    return NULL;
}

const char *ssl_cmd_SSLProxyCipherSuite(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->szProxyCipherSuite = arg;
    return NULL;
}

const char *ssl_cmd_SSLProxyVerify(
    cmd_parms *cmd, char *struct_ptr, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->bProxyVerify = (flag ? TRUE : FALSE);
    return NULL;
}

const char *ssl_cmd_SSLProxyVerifyDepth(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    int d;

    d = atoi(arg);
    if (d < 0)
        return "SSLProxyVerifyDepth: Invalid argument";
    sc->nProxyVerifyDepth = d;
    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificateFile(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLProxyCACertificateFile: file '",
                          cpPath, "' not exists or empty", NULL);
    sc->szProxyCACertificateFile = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLProxyCACertificatePath(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISDIR, cpPath))
        return ap_pstrcat(cmd->pool, "SSLProxyCACertificatePath: directory '",
                          cpPath, "' does not exists", NULL);
    sc->szProxyCACertificatePath = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificateFile(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISREG|SSL_PCM_ISNONZERO, cpPath))
        return ap_pstrcat(cmd->pool, "SSLProxyMachineCertFile: file '",
                          cpPath, "' not exists or empty", NULL);
    sc->szProxyClientCertificateFile = cpPath;
    return NULL;
}

const char *ssl_cmd_SSLProxyMachineCertificatePath(
    cmd_parms *cmd, char *struct_ptr, char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    char *cpPath;

    cpPath = ssl_util_server_root_relative(cmd->pool, "certkey", arg);
    if (!ssl_util_path_check(SSL_PCM_EXISTS|SSL_PCM_ISDIR, cpPath))
        return ap_pstrcat(cmd->pool, "SSLProxyMachineCertPath: directory '",
                          cpPath, "' does not exists", NULL);
    sc->szProxyClientCertificatePath = cpPath;
    return NULL;
}

#endif /* SSL_EXPERIMENTAL_PROXY */

