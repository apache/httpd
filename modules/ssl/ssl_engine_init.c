/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_init.c
**  Initialization of Servers
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */
                             /* ``Recursive, adj.;
                                  see Recursive.''
                                        -- Unknown   */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  Module Initialization
**  _________________________________________________________________
*/

static char * ssl_add_version_component(apr_pool_t *p,
                                        server_rec *s,
                                        char *name)
{
    char *val = ssl_var_lookup(p, s, NULL, NULL, name);

    if (val && *val) {
        ap_add_version_component(p, val);
    }

    return val;
}

static char *version_components[] = {
    "SSL_VERSION_PRODUCT",
    "SSL_VERSION_INTERFACE",
    "SSL_VERSION_LIBRARY",
    NULL
};

static void ssl_add_version_components(apr_pool_t *p,
                                       server_rec *s)
{
    char *vals[sizeof(version_components)/sizeof(char *)];
    int i;

    for (i=0; version_components[i]; i++) {
        vals[i] = ssl_add_version_component(p, s,
                                            version_components[i]);
    }

    ssl_log(s, SSL_LOG_INFO,
            "Server: %s, Interface: %s, Library: %s",
            AP_SERVER_BASEVERSION,
            vals[1],  /* SSL_VERSION_INTERFACE */
            vals[2]); /* SSL_VERSION_LIBRARY */
}


/*
 *  Initialize SSL library
 */
static void ssl_init_SSLLibrary(server_rec *s)
{
    ssl_log(s, SSL_LOG_INFO,
            "Init: Initializing %s library", SSL_LIBRARY_NAME);

    CRYPTO_malloc_init();
    SSL_load_error_strings();
    SSL_library_init();
    X509V3_add_standard_extensions();
}

/*
 *  Per-module initialization
 */
int ssl_init_Module(apr_pool_t *p, apr_pool_t *plog,
                    apr_pool_t *ptemp,
                    server_rec *base_server)
{
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc;
    server_rec *s;

    /*
     * Let us cleanup on restarts and exists
     */
    apr_pool_cleanup_register(p, base_server,
                              ssl_init_ModuleKill,
                              ssl_init_ChildKill);

    /*
     * Any init round fixes the global config
     */
    ssl_config_global_create(base_server); /* just to avoid problems */
    ssl_config_global_fix(mc);

    /*
     *  try to fix the configuration and open the dedicated SSL
     *  logfile as early as possible
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        /* Fix up stuff that may not have been set */
        if (sc->bEnabled == UNSET) {
            sc->bEnabled = FALSE;
        }

        if (sc->nVerifyClient == SSL_CVERIFY_UNSET) {
            sc->nVerifyClient = SSL_CVERIFY_NONE;
        }

        if (sc->nVerifyDepth == UNSET) {
            sc->nVerifyDepth = 1;
        }

#ifdef SSL_EXPERIMENTAL_PROXY
        if (sc->nProxyVerifyDepth == UNSET) {
            sc->nProxyVerifyDepth = 1;
        }
#endif

        if (sc->nSessionCacheTimeout == UNSET) {
            sc->nSessionCacheTimeout = SSL_SESSION_CACHE_TIMEOUT;
        }

        if (sc->nPassPhraseDialogType == SSL_PPTYPE_UNSET) {
            sc->nPassPhraseDialogType = SSL_PPTYPE_BUILTIN;
        }

        /* Open the dedicated SSL logfile */
        ssl_log_open(base_server, s, p);
    }

    ssl_init_SSLLibrary(base_server);

#if APR_HAS_THREADS
    ssl_util_thread_setup(base_server, p);
#endif

    ssl_pphrase_Handle(base_server, p);
    ssl_init_TmpKeysHandle(SSL_TKP_GEN, base_server, p);

    /*
     * SSL external crypto device ("engine") support
     */
#ifdef SSL_EXPERIMENTAL_ENGINE
    ssl_init_Engine(base_server, p);
#endif

    /*
     * Warn the user that he should use the session cache.
     * But we can operate without it, of course.
     */
    if (mc->nSessionCacheMode == SSL_SCMODE_UNSET) {
        ssl_log(base_server, SSL_LOG_WARN,
                "Init: Session Cache is not configured "
                "[hint: SSLSessionCache]");
        mc->nSessionCacheMode = SSL_SCMODE_NONE;
    }

    /*
     * initialize the mutex handling
     */
    if (!ssl_mutex_init(base_server, p)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * initialize session caching
     */
    ssl_scache_init(base_server, p);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     */
    ssl_rand_seed(base_server, p, SSL_RSCTX_STARTUP, "Init: ");

    /*
     *  allocate the temporary RSA keys and DH params
     */
    ssl_init_TmpKeysHandle(SSL_TKP_ALLOC, base_server, p);

    /*
     *  initialize servers
     */
    ssl_log(base_server, SSL_LOG_INFO,
            "Init: Initializing (virtual) servers for SSL");

    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);
        /*
         * Either now skip this server when SSL is disabled for
         * it or give out some information about what we're
         * configuring.
         */
        if (!sc->bEnabled) {
            continue;
        }

        ssl_log(s, SSL_LOG_INFO,
                "Init: Configuring server %s for SSL protocol",
                ssl_util_vhostid(p, s));

        /*
         * Read the server certificate and key
         */
        ssl_init_ConfigureServer(s, p, sc);
    }

    /*
     * Configuration consistency checks
     */
    ssl_init_CheckServers(base_server, p);

    /*
     *  Announce mod_ssl and SSL library in HTTP Server field
     *  as ``mod_ssl/X.X.X OpenSSL/X.X.X''
     */
    ssl_add_version_components(p, base_server);

    SSL_init_app_data2_idx(); /* for SSL_get_app_data2() at request time */

    return OK;
}

/*
 * Support for external a Crypto Device ("engine"), usually
 * a hardware accellerator card for crypto operations.
 */
#ifdef SSL_EXPERIMENTAL_ENGINE
void ssl_init_Engine(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    ENGINE *e;

    if (mc->szCryptoDevice) {
        if (!(e = ENGINE_by_id(mc->szCryptoDevice))) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: Failed to load Crypto Device API `%s'",
                    mc->szCryptoDevice);
            ssl_die();
        }

        if (strEQ(mc->szCryptoDevice, "chil")) {
            ENGINE_ctrl(e, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
        }

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: Failed to enable Crypto Device API `%s'",
                    mc->szCryptoDevice);
            ssl_die();
        }

        ENGINE_free(e);
    }
}
#endif

#define MODSSL_TEMP_KEY_FREE(mc, type, idx) \
    if (mc->pTmpKeys[idx]) { \
        type##_free((type *)mc->pTmpKeys[idx]); \
        mc->pTmpKeys[idx] = NULL; \
    }

#define MODSSL_TEMP_KEYS_FREE(mc, type) \
    MODSSL_TEMP_KEY_FREE(mc, type, SSL_TKPIDX_##type##512); \
    MODSSL_TEMP_KEY_FREE(mc, type, SSL_TKPIDX_##type##1024)

/*
 * Handle the Temporary RSA Keys and DH Params
 */
void ssl_init_TmpKeysHandle(int action, server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    ssl_asn1_t *asn1;
    unsigned char *ptr;
    long int length;
    RSA *rsa;
    DH *dh;

    if (action == SSL_TKP_GEN) { /* Generate Keys and Params */
        /* seed PRNG */
        ssl_rand_seed(s, p, SSL_RSCTX_STARTUP, "Init: ");

        /* generate 512 bit RSA key */
        ssl_log(s, SSL_LOG_INFO,
                "Init: Generating temporary RSA private keys (512/1024 bits)");

        if (!(rsa = RSA_generate_key(512, RSA_F4, NULL, NULL))) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR, 
                    "Init: Failed to generate temporary "
                    "512 bit RSA private key");
            ssl_die();
        }

        length = i2d_RSAPrivateKey(rsa, NULL);
        ptr = ssl_asn1_table_set(mc->tTmpKeys, "RSA:512", length);
        (void)i2d_RSAPrivateKey(rsa, &ptr); /* 2nd arg increments */
        RSA_free(rsa);

        /* generate 1024 bit RSA key */
        if (!(rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL))) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR, 
                    "Init: Failed to generate temporary "
                    "1024 bit RSA private key");
            ssl_die();
        }

        length = i2d_RSAPrivateKey(rsa, NULL);
        ptr = ssl_asn1_table_set(mc->tTmpKeys, "RSA:1024", length);
        (void)i2d_RSAPrivateKey(rsa, &ptr); /* 2nd arg increments */
        RSA_free(rsa);

        ssl_log(s, SSL_LOG_INFO,
                "Init: Configuring temporary DH parameters (512/1024 bits)");

        /* import 512 bit DH param */
        if (!(dh = ssl_dh_GetTmpParam(512))) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: Failed to import temporary "
                    "512 bit DH parameters");
            ssl_die();
        }

        length = i2d_DHparams(dh, NULL);
        ptr = ssl_asn1_table_set(mc->tTmpKeys, "DH:512", length);
        (void)i2d_DHparams(dh, &ptr); /* 2nd arg increments */
        DH_free(dh);

        /* import 1024 bit DH param */
        if (!(dh = ssl_dh_GetTmpParam(1024))) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: Failed to import temporary "
                    "1024 bit DH parameters");
            ssl_die();
        }

        length = i2d_DHparams(dh, NULL);
        ptr = ssl_asn1_table_set(mc->tTmpKeys, "DH:1024", length);
        (void)i2d_DHparams(dh, &ptr); /* 2nd arg increments */
        DH_free(dh);
    }
    else if (action == SSL_TKP_ALLOC) { /* Allocate Keys and Params */
        ssl_log(s, SSL_LOG_INFO,
                "Init: Configuring temporary "
                "RSA private keys (512/1024 bits)");

        /* allocate 512 bit RSA key */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "RSA:512"))) {
            ptr = asn1->cpData;
            if (!(mc->pTmpKeys[SSL_TKPIDX_RSA512] = 
                  d2i_RSAPrivateKey(NULL, &ptr, asn1->nData)))
            {
                ssl_log(s, SSL_LOG_ERROR,
                        "Init: Failed to load temporary "
                        "512 bit RSA private key");
                ssl_die();
            }
        }

        /* allocate 1024 bit RSA key */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "RSA:1024"))) {
            ptr = asn1->cpData;
            if (!(mc->pTmpKeys[SSL_TKPIDX_RSA1024] = 
                  d2i_RSAPrivateKey(NULL, &ptr, asn1->nData)))
            {
                ssl_log(s, SSL_LOG_ERROR,
                        "Init: Failed to load temporary "
                        "1024 bit RSA private key");
                ssl_die();
            }
        }

        ssl_log(s, SSL_LOG_INFO,
                "Init: Configuring temporary "
                "DH parameters (512/1024 bits)");

        /* allocate 512 bit DH param */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "DH:512"))) {
            ptr = asn1->cpData;
            if (!(mc->pTmpKeys[SSL_TKPIDX_DH512] = 
                  d2i_DHparams(NULL, &ptr, asn1->nData)))
            {
                ssl_log(s, SSL_LOG_ERROR,
                        "Init: Failed to load temporary "
                        "512 bit DH parameters");
                ssl_die();
            }
        }

        /* allocate 1024 bit DH param */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "DH:1024"))) {
            ptr = asn1->cpData;
            if (!(mc->pTmpKeys[SSL_TKPIDX_DH1024] = 
                  d2i_DHparams(NULL, &ptr, asn1->nData)))
            {
                ssl_log(s, SSL_LOG_ERROR,
                        "Init: Failed to load temporary "
                        "1024 bit DH parameters");
                ssl_die();
            }
        }
    }
    else if (action == SSL_TKP_FREE) { /* Free Keys and Params */
        MODSSL_TEMP_KEYS_FREE(mc, RSA);
        MODSSL_TEMP_KEYS_FREE(mc, DH);
    }
}

/*
 * Configure a particular server
 */
void ssl_init_ConfigureServer(server_rec *s, apr_pool_t *p,
                              SSLSrvConfigRec *sc)
{
    SSLModConfigRec *mc = myModConfig(s);
    int verify = SSL_VERIFY_NONE;
    char *cp, *vhost_id;
    EVP_PKEY *pkey;
    SSL_CTX *ctx;
    STACK_OF(X509_NAME) *ca_list;
    ssl_asn1_t *asn1;
    unsigned char *ptr;
    BOOL ok = FALSE;
    int is_ca, pathlen;
    int i, n;
    long cache_mode;

    /*
     * Create the server host:port string because we need it a lot
     */
    sc->szVHostID = vhost_id = ssl_util_vhostid(p, s);
    sc->nVHostID_length = strlen(sc->szVHostID);

    /*
     * Now check for important parameters and the
     * possibility that the user forgot to set them.
     */
    if (!sc->szPublicCertFile[0]) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) No SSL Certificate set [hint: SSLCertificateFile]",
                vhost_id);
        ssl_die();
    }

    /*
     *  Check for problematic re-initializations
     */
    if (sc->pPublicCert[SSL_AIDX_RSA] ||
        sc->pPublicCert[SSL_AIDX_DSA])
    {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) Illegal attempt to re-initialise SSL for server "
                "(theoretically shouldn't happen!)", vhost_id);
        ssl_die();
    }

    /*
     *  Create the new per-server SSL context
     */
    if (sc->nProtocol == SSL_PROTOCOL_NONE) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) No SSL protocols available [hint: SSLProtocol]",
                vhost_id);
        ssl_die();
    }

    cp = apr_pstrcat(p,
                     (sc->nProtocol & SSL_PROTOCOL_SSLV2 ? "SSLv2, " : ""),
                     (sc->nProtocol & SSL_PROTOCOL_SSLV3 ? "SSLv3, " : ""),
                     (sc->nProtocol & SSL_PROTOCOL_TLSV1 ? "TLSv1, " : ""),
                     NULL);
    cp[strlen(cp)-2] = NUL;

    ssl_log(s, SSL_LOG_TRACE,
            "Init: (%s) Creating new SSL context (protocols: %s)",
            vhost_id, cp);

    if (sc->nProtocol == SSL_PROTOCOL_SSLV2) {
        ctx = SSL_CTX_new(SSLv2_server_method());  /* only SSLv2 is left */
    }
    else {
        ctx = SSL_CTX_new(SSLv23_server_method()); /* be more flexible */
    }

    SSL_CTX_set_options(ctx, SSL_OP_ALL);

    if (!(sc->nProtocol & SSL_PROTOCOL_SSLV2)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    }

    if (!(sc->nProtocol & SSL_PROTOCOL_SSLV3)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    }

    if (!(sc->nProtocol & SSL_PROTOCOL_TLSV1)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    }

    SSL_CTX_set_app_data(ctx, s);
    sc->pSSLCtx = ctx;

    /*
     * Configure additional context ingredients
     */
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

    if (mc->nSessionCacheMode == SSL_SCMODE_NONE) {
        cache_mode = SSL_SESS_CACHE_OFF;
    }
    else {
        /* SSL_SESS_CACHE_NO_INTERNAL_LOOKUP will force OpenSSL
         * to ignore process local-caching and
         * to always get/set/delete sessions using mod_ssl's callbacks.
         */
        cache_mode = SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
    }

    SSL_CTX_set_session_cache_mode(ctx, cache_mode);

    /*
     *  Configure callbacks for SSL context
     */
    if (sc->nVerifyClient == SSL_CVERIFY_REQUIRE) {
        verify |= SSL_VERIFY_PEER_STRICT;
    }

    if ((sc->nVerifyClient == SSL_CVERIFY_OPTIONAL) ||
        (sc->nVerifyClient == SSL_CVERIFY_OPTIONAL_NO_CA))
    {
        verify |= SSL_VERIFY_PEER;
    }

    SSL_CTX_set_verify(ctx, verify,  ssl_callback_SSLVerify);

    SSL_CTX_sess_set_new_cb(ctx,      ssl_callback_NewSessionCacheEntry);
    SSL_CTX_sess_set_get_cb(ctx,      ssl_callback_GetSessionCacheEntry);
    SSL_CTX_sess_set_remove_cb(ctx,   ssl_callback_DelSessionCacheEntry);

    SSL_CTX_set_tmp_rsa_callback(ctx, ssl_callback_TmpRSA);
    SSL_CTX_set_tmp_dh_callback(ctx,  ssl_callback_TmpDH);

    if (sc->nLogLevel >= SSL_LOG_INFO) {
        /* this callback only logs if SSLLogLevel >= info */
        SSL_CTX_set_info_callback(ctx, ssl_callback_LogTracingState);
    }

    /*
     *  Configure SSL Cipher Suite
     */
    if (sc->szCipherSuite) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring permitted SSL ciphers [%s]", 
                vhost_id, sc->szCipherSuite);

        if (!SSL_CTX_set_cipher_list(ctx, sc->szCipherSuite)) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure permitted SSL ciphers",
                    vhost_id);
            ssl_die();
        }
    }

    /*
     * Configure Client Authentication details
     */
    if (sc->szCACertificateFile || sc->szCACertificatePath) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring client authentication", vhost_id);

        if (!SSL_CTX_load_verify_locations(ctx,
                                           sc->szCACertificateFile,
                                           sc->szCACertificatePath))
        {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure verify locations "
                    "for client authentication", vhost_id);
            ssl_die();
        }

        ca_list = ssl_init_FindCAList(s, p,
                                      sc->szCACertificateFile,
                                      sc->szCACertificatePath);
        if (!ca_list) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: (%s) Unable to determine list of available "
                    "CA certificates for client authentication",
                    vhost_id);
            ssl_die();
        }

        SSL_CTX_set_client_CA_list(sc->pSSLCtx, (STACK *)ca_list);
    }

    /*
     * Configure Certificate Revocation List (CRL) Details
     */
    if (sc->szCARevocationFile || sc->szCARevocationPath) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring certificate revocation facility",
                vhost_id);

        sc->pRevocationStore =
                SSL_X509_STORE_create((char *)sc->szCARevocationFile,
                                      (char *)sc->szCARevocationPath);

        if (!sc->pRevocationStore) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure X.509 CRL storage "
                    "for certificate revocation",
                    vhost_id);
            ssl_die();
        }
    }

    /*
     * Give a warning when no CAs were configured but client authentication
     * should take place. This cannot work.
     */
    if (sc->nVerifyClient == SSL_CVERIFY_REQUIRE) {
        ca_list = (STACK_OF(X509_NAME) *)SSL_CTX_get_client_CA_list(ctx);

        if (sk_X509_NAME_num(ca_list) == 0) {
            ssl_log(s, SSL_LOG_WARN,
                    "Init: Ops, you want to request client authentication, "
                    "but no CAs are known for verification!? "
                    "[Hint: SSLCACertificate*]");
        }
    }

    /*
     *  Configure server certificate(s)
     */
    cp = apr_psprintf(p, "%s:RSA", vhost_id);

    if ((asn1 = ssl_asn1_table_get(mc->tPublicCert, cp))) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring RSA server certificate",
                vhost_id);

        ptr = asn1->cpData;
        if (!(sc->pPublicCert[SSL_AIDX_RSA] =
              d2i_X509(NULL, &ptr, asn1->nData)))
        {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import RSA server certificate",
                    vhost_id);
            ssl_die();
        }

        if (SSL_CTX_use_certificate(ctx, sc->pPublicCert[SSL_AIDX_RSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure RSA server certificate",
                    vhost_id);
            ssl_die();
        }

        ok = TRUE;
    }

    cp = apr_psprintf(p, "%s:DSA", vhost_id);

    if ((asn1 = ssl_asn1_table_get(mc->tPublicCert, cp))) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring DSA server certificate",
                vhost_id);

        ptr = asn1->cpData;
        if (!(sc->pPublicCert[SSL_AIDX_DSA] =
              d2i_X509(NULL, &ptr, asn1->nData)))
        {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import DSA server certificate",
                    vhost_id);
            ssl_die();
        }

        if (SSL_CTX_use_certificate(ctx, sc->pPublicCert[SSL_AIDX_DSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure DSA server certificate",
                    vhost_id);
            ssl_die();
        }

        ok = TRUE;
    }

    if (!ok) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) Ops, no RSA or DSA server certificate found?!",
                vhost_id);
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) You have to perform a *full* server restart "
                "when you added or removed a certificate and/or key file",
                vhost_id);
        ssl_die();
    }

    /*
     * Some information about the certificate(s)
     */
    for (i = 0; i < SSL_AIDX_MAX; i++) {
        if (sc->pPublicCert[i]) {
            if (SSL_X509_isSGC(sc->pPublicCert[i])) {
                ssl_log(s, SSL_LOG_INFO,
                        "Init: (%s) %s server certificate enables "
                        "Server Gated Cryptography (SGC)", 
                        vhost_id, (i == SSL_AIDX_RSA ? "RSA" : "DSA"));
            }

            if (SSL_X509_getBC(sc->pPublicCert[i], &is_ca, &pathlen)) {
                if (is_ca) {
                    ssl_log(s, SSL_LOG_WARN,
                            "Init: (%s) %s server certificate "
                            "is a CA certificate "
                            "(BasicConstraints: CA == TRUE !?)",
                            vhost_id, (i == SSL_AIDX_RSA ? "RSA" : "DSA"));
                }

                if (pathlen > 0) {
                    ssl_log(s, SSL_LOG_WARN,
                            "Init: (%s) %s server certificate "
                            "is not a leaf certificate "
                            "(BasicConstraints: pathlen == %d > 0 !?)",
                            vhost_id, (i == SSL_AIDX_RSA ? "RSA" : "DSA"),
                            pathlen);
                }
            }

            if (SSL_X509_getCN(p, sc->pPublicCert[i], &cp)) {
                int fnm_flags = FNM_PERIOD|FNM_CASE_BLIND;

                if (apr_is_fnmatch(cp) &&
                    (apr_fnmatch(cp, s->server_hostname,
                                 fnm_flags) == FNM_NOMATCH))
                {
                    ssl_log(s, SSL_LOG_WARN,
                            "Init: (%s) %s server certificate "
                            "wildcard CommonName (CN) `%s' "
                            "does NOT match server name!?",
                            vhost_id, (i == SSL_AIDX_RSA ? "RSA" : "DSA"),
                            cp);
                }
                else if (strNE(s->server_hostname, cp)) {
                    ssl_log(s, SSL_LOG_WARN,
                            "Init: (%s) %s server certificate "
                            "CommonName (CN) `%s' "
                            "does NOT match server name!?",
                            vhost_id, (i == SSL_AIDX_RSA ? "RSA" : "DSA"),
                            cp);
                }
            }
        }
    }

    /*
     *  Configure server private key(s)
     */
    ok = FALSE;
    cp = apr_psprintf(p, "%s:RSA", vhost_id);

    if ((asn1 = ssl_asn1_table_get(mc->tPrivateKey, cp))) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring RSA server private key",
                vhost_id);

        ptr = asn1->cpData;
        if (!(sc->pPrivateKey[SSL_AIDX_RSA] = 
              d2i_PrivateKey(EVP_PKEY_RSA, NULL, &ptr, asn1->nData)))
        {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import RSA server private key",
                    vhost_id);
            ssl_die();
        }

        if (SSL_CTX_use_PrivateKey(ctx, sc->pPrivateKey[SSL_AIDX_RSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure RSA server private key",
                    vhost_id);
            ssl_die();
        }

        ok = TRUE;
    }

    cp = apr_psprintf(p, "%s:DSA", vhost_id);

    if ((asn1 = ssl_asn1_table_get(mc->tPrivateKey, cp))) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring DSA server private key",
                vhost_id);

        ptr = asn1->cpData;
        if (!(sc->pPrivateKey[SSL_AIDX_DSA] = 
              d2i_PrivateKey(EVP_PKEY_DSA, NULL, &ptr, asn1->nData)))
        {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import DSA server private key",
                    vhost_id);
            ssl_die();
        }

        if (SSL_CTX_use_PrivateKey(ctx, sc->pPrivateKey[SSL_AIDX_DSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure DSA server private key",
                    vhost_id);
            ssl_die();
        }

        ok = TRUE;
    }

    if (!ok) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) Ops, no RSA or DSA server private key found?!",
                vhost_id);
        ssl_die();
    }

    /*
     * Optionally copy DSA parameters for certificate from private key
     * (see http://www.psy.uq.edu.au/~ftp/Crypto/ssleay/TODO.html)
     */
    if (sc->pPublicCert[SSL_AIDX_DSA] &&
        sc->pPrivateKey[SSL_AIDX_DSA])
    {
        pkey = X509_get_pubkey(sc->pPublicCert[SSL_AIDX_DSA]);

        if (pkey && (EVP_PKEY_key_type(pkey) == EVP_PKEY_DSA) &&
            EVP_PKEY_missing_parameters(pkey))
        {
            EVP_PKEY_copy_parameters(pkey,
                                     sc->pPrivateKey[SSL_AIDX_DSA]);
        }
    }

    /* 
     * Optionally configure extra server certificate chain certificates.
     * This is usually done by OpenSSL automatically when one of the
     * server cert issuers are found under SSLCACertificatePath or in
     * SSLCACertificateFile. But because these are intended for client
     * authentication it can conflict. For instance when you use a
     * Global ID server certificate you've to send out the intermediate
     * CA certificate, too. When you would just configure this with
     * SSLCACertificateFile and also use client authentication mod_ssl
     * would accept all clients also issued by this CA. Obviously this
     * isn't what we want in this situation. So this feature here exists
     * to allow one to explicity configure CA certificates which are
     * used only for the server certificate chain.
     */
    if (sc->szCertificateChain) {
        BOOL skip_first = FALSE;

        for (i = 0; (i < SSL_AIDX_MAX) && sc->szPublicCertFile[i]; i++) {
            if (strEQ(sc->szPublicCertFile[i], sc->szCertificateChain)) {
                skip_first = TRUE;
                break;
            }
        }

        n = SSL_CTX_use_certificate_chain(ctx,
                                          (char *)sc->szCertificateChain, 
                                          skip_first, NULL);
        if (n < 0) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: (%s) Failed to configure CA certificate chain!",
                    vhost_id);
            ssl_die();
        }

        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring server certificate chain "
                "(%d CA certificate%s)",
                vhost_id, n, n == 1 ? "" : "s");
    }
}

void ssl_init_CheckServers(server_rec *base_server, apr_pool_t *p)
{
    server_rec *s, **ps;
    SSLSrvConfigRec *sc;
    ssl_ds_table *table;
    apr_pool_t *subpool;
    char *key;
    BOOL conflict = FALSE;

    /*
     * Give out warnings when a server has HTTPS configured 
     * for the HTTP port or vice versa
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        if (sc->bEnabled && (s->port == DEFAULT_HTTP_PORT)) {
            ssl_log(base_server, SSL_LOG_WARN,
                    "Init: (%s) You configured HTTPS(%d) "
                    "on the standard HTTP(%d) port!",
                    ssl_util_vhostid(p, s),
                    DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT);
        }

        if (!sc->bEnabled && (s->port == DEFAULT_HTTPS_PORT)) {
            ssl_log(base_server, SSL_LOG_WARN,
                    "Init: (%s) You configured HTTP(%d) "
                    "on the standard HTTPS(%d) port!",
                    ssl_util_vhostid(p, s),
                    DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT);
        }
    }

    /*
     * Give out warnings when more than one SSL-aware virtual server uses the
     * same IP:port. This doesn't work because mod_ssl then will always use
     * just the certificate/keys of one virtual host (which one cannot be said
     * easily - but that doesn't matter here).
     */
    apr_pool_create(&subpool, p);
    table = ssl_ds_table_make(subpool, sizeof(server_rec *));

    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        if (!sc->bEnabled) {
            continue;
        }

        key = apr_psprintf(subpool, "%pA:%u",
                           &s->addrs->host_addr, s->addrs->host_port);
        
        if ((ps = ssl_ds_table_get(table, key))) {
            ssl_log(base_server, SSL_LOG_WARN,
                    "Init: SSL server IP/port conflict: "
                    "%s (%s:%d) vs. %s (%s:%d)",
                    ssl_util_vhostid(p, s), 
                    (s->defn_name ? s->defn_name : "unknown"),
                    s->defn_line_number,
                    ssl_util_vhostid(p, *ps),
                    ((*ps)->defn_name ? (*ps)->defn_name : "unknown"), 
                    (*ps)->defn_line_number);
            conflict = TRUE;
            continue;
        }

        ps = ssl_ds_table_push(table, key);
        *ps = s;
    }

    ssl_ds_table_kill(table);
    /* XXX - It was giving some problem earlier - check it out - TBD */
    apr_pool_destroy(subpool);

    if (conflict) {
        ssl_log(base_server, SSL_LOG_WARN,
                "Init: You should not use name-based "
                "virtual hosts in conjunction with SSL!!");
    }
}

static int ssl_init_FindCAList_X509NameCmp(X509_NAME **a, X509_NAME **b)
{
    return(X509_NAME_cmp(*a, *b));
}

static void ssl_init_PushCAList(STACK_OF(X509_NAME) *ca_list,
                                server_rec *s, const char *file)
{
    int n;
    STACK_OF(X509_NAME) *sk;

    sk = (STACK_OF(X509_NAME) *)SSL_load_client_CA_file(file);

    if (!sk) {
        return;
    }

    for (n = 0; n < sk_X509_NAME_num(sk); n++) {
        char name_buf[256];
        X509_NAME *name = sk_X509_NAME_value(sk, n);

        ssl_log(s, SSL_LOG_TRACE,
                "CA certificate: %s",
                X509_NAME_oneline(name, name_buf, sizeof(name_buf)));

        /*
         * note that SSL_load_client_CA_file() checks for duplicates,
         * but since we call it multiple times when reading a directory
         * we must also check for duplicates ourselves.
         */

        if (sk_X509_NAME_find(ca_list, name) < 0) {
            /* this will be freed when ca_list is */
            sk_X509_NAME_push(ca_list, name);
        }
        else {
            /* need to free this ourselves, else it will leak */
            X509_NAME_free(name);
        }
    }

    sk_X509_NAME_free(sk);
}

STACK_OF(X509_NAME) *ssl_init_FindCAList(server_rec *s,
                                         apr_pool_t *p,
                                         const char *ca_file,
                                         const char *ca_path)
{
    STACK_OF(X509_NAME) *ca_list;
    apr_pool_t *subpool;

    /*
     * Use a subpool so we don't bloat up the server pool which
     * is remains in memory for the complete operation time of
     * the server.
     */
    apr_pool_sub_make(&subpool, p, NULL);

    /*
     * Start with a empty stack/list where new
     * entries get added in sorted order.
     */
    ca_list = sk_X509_NAME_new(ssl_init_FindCAList_X509NameCmp);

    /*
     * Process CA certificate bundle file
     */
    if (ca_file) {
        ssl_init_PushCAList(ca_list, s, ca_file);
    }

    /*
     * Process CA certificate path files
     */
    if (ca_path) {
        apr_dir_t *dir;
        apr_finfo_t direntry;
        apr_int32_t finfo_flags = APR_FINFO_MIN|APR_FINFO_NAME;

        if (apr_dir_open(&dir, ca_path, subpool) != APR_SUCCESS) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                    "Init: Failed to open SSLCACertificatePath `%s'",
                    ca_path);
            ssl_die();
        }

        while ((apr_dir_read(&direntry, finfo_flags, dir)) == APR_SUCCESS) {
            const char *file;
            if (direntry.filetype == APR_DIR) {
                continue; /* don't try to load directories */
            }
            file = apr_pstrcat(subpool, ca_path, "/", direntry.name, NULL);
            ssl_init_PushCAList(ca_list, s, file);
        }

        apr_dir_close(dir);
    }

    /*
     * Cleanup
     */
    sk_X509_NAME_set_cmp_func(ca_list, NULL);
    apr_pool_destroy(subpool);

    return ca_list;
}

void ssl_init_Child(apr_pool_t *p, server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    mc->pid = getpid(); /* only call getpid() once per-process */

    /* XXX: there should be an ap_srand() function */
    srand((unsigned int)time(NULL));

    /* open the mutex lockfile */
    ssl_mutex_reinit(s, p);
}

apr_status_t ssl_init_ChildKill(void *data)
{
    /* server_rec *s = (server_rec *)data; */
    /* currently nothing to do */
    return APR_SUCCESS;
}

#define MODSSL_CFG_ITEM_FREE(func, item) \
    if (item) { \
        func(item); \
        item = NULL; \
    }

apr_status_t ssl_init_ModuleKill(void *data)
{
    SSLSrvConfigRec *sc;
    server_rec *base_server = (server_rec *)data;
    server_rec *s;

    /*
     * Drop the session cache and mutex
     */
    ssl_scache_kill(base_server);

    /* 
     * Destroy the temporary keys and params
     */
    ssl_init_TmpKeysHandle(SSL_TKP_FREE, base_server, NULL);

    /*
     * Free the non-pool allocated structures
     * in the per-server configurations
     */
    for (s = base_server; s; s = s->next) {
        int i;
        sc = mySrvConfig(s);

        for (i=0; i < SSL_AIDX_MAX; i++) {
            MODSSL_CFG_ITEM_FREE(X509_free,
                                 sc->pPublicCert[i]);

            MODSSL_CFG_ITEM_FREE(EVP_PKEY_free,
                                 sc->pPrivateKey[i]);
        }

        MODSSL_CFG_ITEM_FREE(X509_STORE_free,
                             sc->pRevocationStore);

        MODSSL_CFG_ITEM_FREE(SSL_CTX_free,
                             sc->pSSLCtx);
    }

    /*
     * Try to kill the internals of the SSL library.
     */
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();

    return APR_SUCCESS;
}

