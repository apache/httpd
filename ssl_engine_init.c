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

/*
 *  Per-module initialization
 */
int ssl_init_Module(apr_pool_t *p, apr_pool_t *plog,
    apr_pool_t *ptemp, server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc;
    server_rec *s2;
    char *cp;

    /*
     * Let us cleanup on restarts and exists
     */
    apr_pool_cleanup_register(p, s, ssl_init_ModuleKill, ssl_init_ChildKill);

    /*
     * Any init round fixes the global config
     */
    ssl_config_global_create(s); /* just to avoid problems */
    ssl_config_global_fix(mc);

    /*
     *  try to fix the configuration and open the dedicated SSL
     *  logfile as early as possible
     */
    for (s2 = s; s2 != NULL; s2 = s2->next) {
        sc = mySrvConfig(s2);

        /* Fix up stuff that may not have been set */
        if (sc->bEnabled == UNSET)
            sc->bEnabled = FALSE;
        if (sc->nVerifyClient == SSL_CVERIFY_UNSET)
            sc->nVerifyClient = SSL_CVERIFY_NONE;
        if (sc->nVerifyDepth == UNSET)
            sc->nVerifyDepth = 1;
#ifdef SSL_EXPERIMENTAL_PROXY
        if (sc->nProxyVerifyDepth == UNSET)
            sc->nProxyVerifyDepth = 1;
#endif
        if (sc->nSessionCacheTimeout == UNSET)
            sc->nSessionCacheTimeout = SSL_SESSION_CACHE_TIMEOUT;
        if (sc->nPassPhraseDialogType == SSL_PPTYPE_UNSET)
            sc->nPassPhraseDialogType = SSL_PPTYPE_BUILTIN;

        /* Open the dedicated SSL logfile */
        ssl_log_open(s, s2, p);
    }

    /*
     * Identification
     */
    ssl_log(s, SSL_LOG_INFO, "Server: %s, Interface: %s, Library: %s",
            AP_SERVER_BASEVERSION,
            ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_INTERFACE"),
            ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_LIBRARY"));

    ssl_log(s, SSL_LOG_INFO, "Init: Initializing %s library",
            SSL_LIBRARY_NAME);

    ssl_init_SSLLibrary();

#if APR_HAS_THREADS
    ssl_util_thread_setup(s, p);
#endif

    ssl_pphrase_Handle(s, p);
    ssl_init_TmpKeysHandle(SSL_TKP_GEN, s, p);

    /*
     * SSL external crypto device ("engine") support
     */
#ifdef SSL_EXPERIMENTAL_ENGINE
    ssl_init_Engine(s, p);
#endif

    /*
     * Warn the user that he should use the session cache.
     * But we can operate without it, of course.
     */
    if (mc->nSessionCacheMode == SSL_SCMODE_UNSET) {
        ssl_log(s, SSL_LOG_WARN,
                "Init: Session Cache is not configured [hint: SSLSessionCache]");
        mc->nSessionCacheMode = SSL_SCMODE_NONE;
    }

    /*
     *  initialize the mutex handling and session caching
     */
    if (!ssl_mutex_init(s, p)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ssl_scache_init(s, p);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     *
     * Note: scoreboard size must be fetched at init time because
     * ap_calc_scoreboard_size() is not threadsafe
     */
    mc->nScoreboardSize = ap_calc_scoreboard_size();
    ssl_rand_seed(s, p, SSL_RSCTX_STARTUP, "Init: ");

    /*
     *  allocate the temporary RSA keys and DH params
     */
    ssl_init_TmpKeysHandle(SSL_TKP_ALLOC, s, p);

    /*
     *  initialize servers
     */
    ssl_log(s, SSL_LOG_INFO, "Init: Initializing (virtual) servers for SSL");
    for (s2 = s; s2 != NULL; s2 = s2->next) {
        sc = mySrvConfig(s2);
        /*
         * Either now skip this server when SSL is disabled for
         * it or give out some information about what we're
         * configuring.
         */
        if (!sc->bEnabled)
            continue;
        ssl_log(s2, SSL_LOG_INFO,
                "Init: Configuring server %s for SSL protocol",
                ssl_util_vhostid(p, s2));

        /*
         * Read the server certificate and key
         */
        ssl_init_ConfigureServer(s2, p, sc);
    }

    /*
     * Configuration consistency checks
     */
    ssl_init_CheckServers(s, p);

    /*
     *  Announce mod_ssl and SSL library in HTTP Server field
     *  as ``mod_ssl/X.X.X OpenSSL/X.X.X''
     */
    if ((cp = ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_PRODUCT")) != NULL && cp[0] != NUL)
        ap_add_version_component(p, cp);
    ap_add_version_component(p, ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_INTERFACE"));
    ap_add_version_component(p, ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_LIBRARY"));

    SSL_init_app_data2_idx(); /* for SSL_get_app_data2() at request time */
    return OK;
}

/*
 *  Initialize SSL library (also already needed for the pass phrase dialog)
 */
void ssl_init_SSLLibrary(void)
{
    CRYPTO_malloc_init();
    SSL_load_error_strings();
    SSL_library_init();
    /* XXX CRYPTO_set_locking_callback(); */
    X509V3_add_standard_extensions();
    return;
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

    if (mc->szCryptoDevice != NULL) {
        if ((e = ENGINE_by_id(mc->szCryptoDevice)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR, "Init: Failed to load Crypto Device API `%s'",
                    mc->szCryptoDevice);
            ssl_die();
        }
        if (strEQ(mc->szCryptoDevice, "chil")) 
            ENGINE_ctrl(e, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ssl_log(s, SSL_LOG_ERROR, "Init: Failed to enable Crypto Device API `%s'",
                    mc->szCryptoDevice);
            ssl_die();
        }
        ENGINE_free(e);
    }
    return;
}
#endif

#if SSL_LIBRARY_VERSION >= 0x00907000
#define SSL_UCP_CAST(ucp) (const unsigned char **)ucp
#else
#define SSL_UCP_CAST(ucp) ucp
#endif

/*
 * Handle the Temporary RSA Keys and DH Params
 */
void ssl_init_TmpKeysHandle(int action, server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    ssl_asn1_t *asn1;
    unsigned char *ucp;
    long int length;
    RSA *rsa;
    DH *dh;

    /* Generate Keys and Params */
    if (action == SSL_TKP_GEN) {

        /* seed PRNG */
        ssl_rand_seed(s, p, SSL_RSCTX_STARTUP, "Init: ");

        /* generate 512 bit RSA key */
        ssl_log(s, SSL_LOG_INFO, "Init: Generating temporary RSA private keys (512/1024 bits)");
        if ((rsa = RSA_generate_key(512, RSA_F4, NULL, NULL)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR, 
                    "Init: Failed to generate temporary 512 bit RSA private key");
            ssl_die();
        }

        length = i2d_RSAPrivateKey(rsa, NULL);
        ucp = ssl_asn1_table_set(mc->tTmpKeys, "RSA:512", length);
        (void)i2d_RSAPrivateKey(rsa, &ucp); /* 2nd arg increments */
        RSA_free(rsa);

        /* generate 1024 bit RSA key */
        if ((rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR, 
                    "Init: Failed to generate temporary 1024 bit RSA private key");
            ssl_die();
        }

        length = i2d_RSAPrivateKey(rsa, NULL);
        ucp = ssl_asn1_table_set(mc->tTmpKeys, "RSA:1024", length);
        (void)i2d_RSAPrivateKey(rsa, &ucp); /* 2nd arg increments */
        RSA_free(rsa);

        ssl_log(s, SSL_LOG_INFO, "Init: Configuring temporary DH parameters (512/1024 bits)");

        /* import 512 bit DH param */
        if ((dh = ssl_dh_GetTmpParam(512)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR, "Init: Failed to import temporary 512 bit DH parameters");
            ssl_die();
        }

        length = i2d_DHparams(dh, NULL);
        ucp = ssl_asn1_table_set(mc->tTmpKeys, "DH:512", length);
        (void)i2d_DHparams(dh, &ucp); /* 2nd arg increments */
        /* no need to free dh, it's static */

        /* import 1024 bit DH param */
        if ((dh = ssl_dh_GetTmpParam(1024)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR, "Init: Failed to import temporary 1024 bit DH parameters");
            ssl_die();
        }

        length = i2d_DHparams(dh, NULL);
        ucp = ssl_asn1_table_set(mc->tTmpKeys, "DH:1024", length);
        (void)i2d_DHparams(dh, &ucp); /* 2nd arg increments */
        /* no need to free dh, it's static */
    }

    /* Allocate Keys and Params */
    else if (action == SSL_TKP_ALLOC) {

        ssl_log(s, SSL_LOG_INFO, "Init: Configuring temporary RSA private keys (512/1024 bits)");

        /* allocate 512 bit RSA key */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "RSA:512")) != NULL) {
            ucp = asn1->cpData;
            if ((mc->pTmpKeys[SSL_TKPIDX_RSA512] = 
                 (void *)d2i_RSAPrivateKey(NULL, SSL_UCP_CAST(&ucp), asn1->nData)) == NULL) {
                ssl_log(s, SSL_LOG_ERROR, "Init: Failed to load temporary 512 bit RSA private key");
                ssl_die();
            }
        }

        /* allocate 1024 bit RSA key */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "RSA:1024")) != NULL) {
            ucp = asn1->cpData;
            if ((mc->pTmpKeys[SSL_TKPIDX_RSA1024] = 
                 (void *)d2i_RSAPrivateKey(NULL, SSL_UCP_CAST(&ucp), asn1->nData)) == NULL) {
                ssl_log(s, SSL_LOG_ERROR, "Init: Failed to load temporary 1024 bit RSA private key");
                ssl_die();
            }
        }

        ssl_log(s, SSL_LOG_INFO, "Init: Configuring temporary DH parameters (512/1024 bits)");

        /* allocate 512 bit DH param */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "DH:512")) != NULL) {
            ucp = asn1->cpData;
            if ((mc->pTmpKeys[SSL_TKPIDX_DH512] = 
                 (void *)d2i_DHparams(NULL, SSL_UCP_CAST(&ucp), asn1->nData)) == NULL) {
                ssl_log(s, SSL_LOG_ERROR, "Init: Failed to load temporary 512 bit DH parameters");
                ssl_die();
            }
        }

        /* allocate 1024 bit DH param */
        if ((asn1 = ssl_asn1_table_get(mc->tTmpKeys, "DH:1024")) != NULL) {
            ucp = asn1->cpData;
            if ((mc->pTmpKeys[SSL_TKPIDX_DH1024] = 
                 (void *)d2i_DHparams(NULL, SSL_UCP_CAST(&ucp), asn1->nData)) == NULL) {
                ssl_log(s, SSL_LOG_ERROR, "Init: Failed to load temporary 1024 bit DH parameters");
                ssl_die();
            }
        }
    }

    /* Free Keys and Params */
    else if (action == SSL_TKP_FREE) {
        if (mc->pTmpKeys[SSL_TKPIDX_RSA512] != NULL) {
            RSA_free((RSA *)mc->pTmpKeys[SSL_TKPIDX_RSA512]);
            mc->pTmpKeys[SSL_TKPIDX_RSA512] = NULL;
        }
        if (mc->pTmpKeys[SSL_TKPIDX_RSA1024] != NULL) {
            RSA_free((RSA *)mc->pTmpKeys[SSL_TKPIDX_RSA1024]);
            mc->pTmpKeys[SSL_TKPIDX_RSA1024] = NULL;
        }
        if (mc->pTmpKeys[SSL_TKPIDX_DH512] != NULL) {
            DH_free((DH *)mc->pTmpKeys[SSL_TKPIDX_DH512]);
            mc->pTmpKeys[SSL_TKPIDX_DH512] = NULL;
        }
        if (mc->pTmpKeys[SSL_TKPIDX_DH1024] != NULL) {
            DH_free((DH *)mc->pTmpKeys[SSL_TKPIDX_DH1024]);
            mc->pTmpKeys[SSL_TKPIDX_DH1024] = NULL;
        }
    }
    return;
}

/*
 * Configure a particular server
 */
void ssl_init_ConfigureServer(server_rec *s, apr_pool_t *p, SSLSrvConfigRec *sc)
{
    SSLModConfigRec *mc = myModConfig(s);
    int nVerify;
    char *cpVHostID;
    EVP_PKEY *pKey;
    SSL_CTX *ctx;
    STACK_OF(X509_NAME) *skCAList;
    ssl_asn1_t *asn1;
    unsigned char *ucp;
    char *cp;
    BOOL ok;
    BOOL bSkipFirst;
    int isca, pathlen;
    int i, n;
    long cache_mode;

    /*
     * Create the server host:port string because we need it a lot
     */
    sc->szVHostID = cpVHostID = ssl_util_vhostid(p, s);
    sc->nVHostID_length = strlen(sc->szVHostID);

    /*
     * Now check for important parameters and the
     * possibility that the user forgot to set them.
     */
    if (sc->szPublicCertFile[0] == NULL) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) No SSL Certificate set [hint: SSLCertificateFile]",
                cpVHostID);
        ssl_die();
    }

    /*
     *  Check for problematic re-initializations
     */
    if (sc->pPublicCert[SSL_AIDX_RSA] != NULL ||
        sc->pPublicCert[SSL_AIDX_DSA] != NULL   ) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) Illegal attempt to re-initialise SSL for server "
                "(theoretically shouldn't happen!)", cpVHostID);
        ssl_die();
    }

    /*
     *  Create the new per-server SSL context
     */
    if (sc->nProtocol == SSL_PROTOCOL_NONE) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) No SSL protocols available [hint: SSLProtocol]",
                cpVHostID);
        ssl_die();
    }
    cp = apr_pstrcat(p, (sc->nProtocol & SSL_PROTOCOL_SSLV2 ? "SSLv2, " : ""),
                        (sc->nProtocol & SSL_PROTOCOL_SSLV3 ? "SSLv3, " : ""),
                        (sc->nProtocol & SSL_PROTOCOL_TLSV1 ? "TLSv1, " : ""), NULL);
    cp[strlen(cp)-2] = NUL;
    ssl_log(s, SSL_LOG_TRACE,
            "Init: (%s) Creating new SSL context (protocols: %s)", cpVHostID, cp);
    if (sc->nProtocol == SSL_PROTOCOL_SSLV2)
        ctx = SSL_CTX_new(SSLv2_server_method());  /* only SSLv2 is left */
    else
        ctx = SSL_CTX_new(SSLv23_server_method()); /* be more flexible */
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    if (!(sc->nProtocol & SSL_PROTOCOL_SSLV2))
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (!(sc->nProtocol & SSL_PROTOCOL_SSLV3))
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    if (!(sc->nProtocol & SSL_PROTOCOL_TLSV1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
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
    nVerify = SSL_VERIFY_NONE;
    if (sc->nVerifyClient == SSL_CVERIFY_REQUIRE)
        nVerify |= SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (   (sc->nVerifyClient == SSL_CVERIFY_OPTIONAL)
        || (sc->nVerifyClient == SSL_CVERIFY_OPTIONAL_NO_CA) )
        nVerify |= SSL_VERIFY_PEER;
    SSL_CTX_set_verify(ctx, nVerify,  ssl_callback_SSLVerify);
    SSL_CTX_sess_set_new_cb(ctx,      ssl_callback_NewSessionCacheEntry);
    SSL_CTX_sess_set_get_cb(ctx,      ssl_callback_GetSessionCacheEntry);
    SSL_CTX_sess_set_remove_cb(ctx,   ssl_callback_DelSessionCacheEntry);
    SSL_CTX_set_tmp_rsa_callback(ctx, ssl_callback_TmpRSA);
    SSL_CTX_set_tmp_dh_callback(ctx,  ssl_callback_TmpDH);

    if (sc->nLogLevel >= SSL_LOG_INFO) {
        /* this callback only logs if SSLLogLevel >= info */
        SSL_CTX_set_info_callback(ctx,ssl_callback_LogTracingState);
    }

    /*
     *  Configure SSL Cipher Suite
     */
    if (sc->szCipherSuite != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring permitted SSL ciphers [%s]", 
                cpVHostID, sc->szCipherSuite);
        if (!SSL_CTX_set_cipher_list(ctx, sc->szCipherSuite)) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure permitted SSL ciphers",
                    cpVHostID);
            ssl_die();
        }
    }

    /*
     * Configure Client Authentication details
     */
    if (sc->szCACertificateFile != NULL || sc->szCACertificatePath != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring client authentication", cpVHostID);
        if (!SSL_CTX_load_verify_locations(ctx,
                                           sc->szCACertificateFile,
                                           sc->szCACertificatePath)) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure verify locations "
                    "for client authentication", cpVHostID);
            ssl_die();
        }
        if ((skCAList = ssl_init_FindCAList(s, p, sc->szCACertificateFile,
                                            sc->szCACertificatePath)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: (%s) Unable to determine list of available "
                    "CA certificates for client authentication", cpVHostID);
            ssl_die();
        }
        SSL_CTX_set_client_CA_list(sc->pSSLCtx, (STACK *)skCAList);
    }

    /*
     * Configure Certificate Revocation List (CRL) Details
     */
    if (sc->szCARevocationFile != NULL || sc->szCARevocationPath != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring certificate revocation facility", cpVHostID);
        if ((sc->pRevocationStore =
                SSL_X509_STORE_create((char*)sc->szCARevocationFile,
                                      (char*)sc->szCARevocationPath)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure X.509 CRL storage "
                    "for certificate revocation", cpVHostID);
            ssl_die();
        }
    }

    /*
     * Give a warning when no CAs were configured but client authentication
     * should take place. This cannot work.
     */
    if (sc->nVerifyClient == SSL_CVERIFY_REQUIRE) {
        skCAList = (STACK_OF(X509_NAME) *)SSL_CTX_get_client_CA_list(ctx);
        if (sk_X509_NAME_num(skCAList) == 0)
            ssl_log(s, SSL_LOG_WARN,
                    "Init: Ops, you want to request client authentication, "
                    "but no CAs are known for verification!? "
                    "[Hint: SSLCACertificate*]");
    }

    /*
     *  Configure server certificate(s)
     */
    ok = FALSE;
    cp = apr_psprintf(p, "%s:RSA", cpVHostID);
    if ((asn1 = ssl_asn1_table_get(mc->tPublicCert, cp)) != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring RSA server certificate", cpVHostID);
        ucp = asn1->cpData;
        if ((sc->pPublicCert[SSL_AIDX_RSA] = d2i_X509(NULL, &ucp, asn1->nData)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import RSA server certificate",
                    cpVHostID);
            ssl_die();
        }
        if (SSL_CTX_use_certificate(ctx, sc->pPublicCert[SSL_AIDX_RSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure RSA server certificate",
                    cpVHostID);
            ssl_die();
        }
        ok = TRUE;
    }
    cp = apr_psprintf(p, "%s:DSA", cpVHostID);
    if ((asn1 = ssl_asn1_table_get(mc->tPublicCert, cp)) != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring DSA server certificate", cpVHostID);
        ucp = asn1->cpData;
        if ((sc->pPublicCert[SSL_AIDX_DSA] = d2i_X509(NULL, &ucp, asn1->nData)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import DSA server certificate",
                    cpVHostID);
            ssl_die();
        }
        if (SSL_CTX_use_certificate(ctx, sc->pPublicCert[SSL_AIDX_DSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure DSA server certificate",
                    cpVHostID);
            ssl_die();
        }
        ok = TRUE;
    }
    if (!ok) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) Ops, no RSA or DSA server certificate found?!", cpVHostID);
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) You have to perform a *full* server restart when you added or removed a certificate and/or key file", cpVHostID);
        ssl_die();
    }

    /*
     * Some information about the certificate(s)
     */
    for (i = 0; i < SSL_AIDX_MAX; i++) {
        if (sc->pPublicCert[i] != NULL) {
            if (SSL_X509_isSGC(sc->pPublicCert[i])) {
                ssl_log(s, SSL_LOG_INFO,
                        "Init: (%s) %s server certificate enables "
                        "Server Gated Cryptography (SGC)", 
                        cpVHostID, (i == SSL_AIDX_RSA ? "RSA" : "DSA"));
            }
            if (SSL_X509_getBC(sc->pPublicCert[i], &isca, &pathlen)) {
                if (isca)
                    ssl_log(s, SSL_LOG_WARN,
                        "Init: (%s) %s server certificate is a CA certificate "
                        "(BasicConstraints: CA == TRUE !?)",
                        cpVHostID, (i == SSL_AIDX_RSA ? "RSA" : "DSA"));
                if (pathlen > 0)
                    ssl_log(s, SSL_LOG_WARN,
                        "Init: (%s) %s server certificate is not a leaf certificate "
                        "(BasicConstraints: pathlen == %d > 0 !?)",
                        cpVHostID, (i == SSL_AIDX_RSA ? "RSA" : "DSA"), pathlen);
            }
            if (SSL_X509_getCN(p, sc->pPublicCert[i], &cp)) {
                if (apr_is_fnmatch(cp) &&
                    apr_fnmatch(cp, s->server_hostname,
                                FNM_PERIOD|FNM_CASE_BLIND) == FNM_NOMATCH) {
                    ssl_log(s, SSL_LOG_WARN,
                        "Init: (%s) %s server certificate wildcard CommonName (CN) `%s' "
                        "does NOT match server name!?", cpVHostID, 
                        (i == SSL_AIDX_RSA ? "RSA" : "DSA"), cp);
                }
                else if (strNE(s->server_hostname, cp)) {
                    ssl_log(s, SSL_LOG_WARN,
                        "Init: (%s) %s server certificate CommonName (CN) `%s' "
                        "does NOT match server name!?", cpVHostID, 
                        (i == SSL_AIDX_RSA ? "RSA" : "DSA"), cp);
                }
            }
        }
    }

    /*
     *  Configure server private key(s)
     */
    ok = FALSE;
    cp = apr_psprintf(p, "%s:RSA", cpVHostID);
    if ((asn1 = ssl_asn1_table_get(mc->tPrivateKey, cp)) != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring RSA server private key", cpVHostID);
        ucp = asn1->cpData;
        if ((sc->pPrivateKey[SSL_AIDX_RSA] = 
             d2i_PrivateKey(EVP_PKEY_RSA, NULL, &ucp, asn1->nData)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import RSA server private key",
                    cpVHostID);
            ssl_die();
        }
        if (SSL_CTX_use_PrivateKey(ctx, sc->pPrivateKey[SSL_AIDX_RSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure RSA server private key",
                    cpVHostID);
            ssl_die();
        }
        ok = TRUE;
    }
    cp = apr_psprintf(p, "%s:DSA", cpVHostID);
    if ((asn1 = ssl_asn1_table_get(mc->tPrivateKey, cp)) != NULL) {
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring DSA server private key", cpVHostID);
        ucp = asn1->cpData;
        if ((sc->pPrivateKey[SSL_AIDX_DSA] = 
             d2i_PrivateKey(EVP_PKEY_DSA, NULL, &ucp, asn1->nData)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to import DSA server private key",
                    cpVHostID);
            ssl_die();
        }
        if (SSL_CTX_use_PrivateKey(ctx, sc->pPrivateKey[SSL_AIDX_DSA]) <= 0) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to configure DSA server private key",
                    cpVHostID);
            ssl_die();
        }
        ok = TRUE;
    }
    if (!ok) {
        ssl_log(s, SSL_LOG_ERROR,
                "Init: (%s) Ops, no RSA or DSA server private key found?!", cpVHostID);
        ssl_die();
    }

    /*
     * Optionally copy DSA parameters for certificate from private key
     * (see http://www.psy.uq.edu.au/~ftp/Crypto/ssleay/TODO.html)
     */
    if (   sc->pPublicCert[SSL_AIDX_DSA] != NULL
        && sc->pPrivateKey[SSL_AIDX_DSA] != NULL) {
        pKey = X509_get_pubkey(sc->pPublicCert[SSL_AIDX_DSA]);
        if (   pKey != NULL
            && EVP_PKEY_key_type(pKey) == EVP_PKEY_DSA 
            && EVP_PKEY_missing_parameters(pKey))
            EVP_PKEY_copy_parameters(pKey, sc->pPrivateKey[SSL_AIDX_DSA]);
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
    if (sc->szCertificateChain != NULL) {
        bSkipFirst = FALSE;
        for (i = 0; i < SSL_AIDX_MAX && sc->szPublicCertFile[i] != NULL; i++) {
            if (strEQ(sc->szPublicCertFile[i], sc->szCertificateChain)) {
                bSkipFirst = TRUE;
                break;
            }
        }
        if ((n = SSL_CTX_use_certificate_chain(ctx, (char*)sc->szCertificateChain, 
                                               bSkipFirst, NULL)) < 0) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: (%s) Failed to configure CA certificate chain!", cpVHostID);
            ssl_die();
        }
        ssl_log(s, SSL_LOG_TRACE, "Init: (%s) Configuring "
                "server certificate chain (%d CA certificate%s)", cpVHostID,
                n, n == 1 ? "" : "s");
    }

    return;
}

void ssl_init_CheckServers(server_rec *sm, apr_pool_t *p)
{
    server_rec *s;
    server_rec **ps;
    SSLSrvConfigRec *sc;
    ssl_ds_table *t;
    apr_pool_t *sp;
    char *key;
    BOOL bConflict;

    /*
     * Give out warnings when a server has HTTPS configured 
     * for the HTTP port or vice versa
     */
    for (s = sm; s != NULL; s = s->next) {
        sc = mySrvConfig(s);
        if (sc->bEnabled && s->port == DEFAULT_HTTP_PORT)
            ssl_log(sm, SSL_LOG_WARN,
                    "Init: (%s) You configured HTTPS(%d) on the standard HTTP(%d) port!",
                    ssl_util_vhostid(p, s), DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT);
        if (!sc->bEnabled && s->port == DEFAULT_HTTPS_PORT)
            ssl_log(sm, SSL_LOG_WARN,
                    "Init: (%s) You configured HTTP(%d) on the standard HTTPS(%d) port!",
                    ssl_util_vhostid(p, s), DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT);
    }

    /*
     * Give out warnings when more than one SSL-aware virtual server uses the
     * same IP:port. This doesn't work because mod_ssl then will always use
     * just the certificate/keys of one virtual host (which one cannot be said
     * easily - but that doesn't matter here).
     */
    apr_pool_create(&sp, p);
    t = ssl_ds_table_make(sp, sizeof(server_rec *));
    bConflict = FALSE;
    for (s = sm; s != NULL; s = s->next) {
        sc = mySrvConfig(s);
        if (!sc->bEnabled)
            continue;
        key = apr_psprintf(sp, "%pA:%u", &s->addrs->host_addr, s->addrs->host_port);
        ps = ssl_ds_table_get(t, key);
        if (ps != NULL) {
            ssl_log(sm, SSL_LOG_WARN,
                    "Init: SSL server IP/port conflict: %s (%s:%d) vs. %s (%s:%d)",
                    ssl_util_vhostid(p, s), 
                    (s->defn_name != NULL ? s->defn_name : "unknown"),
                    s->defn_line_number,
                    ssl_util_vhostid(p, *ps),
                    ((*ps)->defn_name != NULL ? (*ps)->defn_name : "unknown"), 
                    (*ps)->defn_line_number);
            bConflict = TRUE;
            continue;
        }
        ps = ssl_ds_table_push(t, key);
        *ps = s;
    }
    ssl_ds_table_kill(t);
    /* XXX - It was giving some problem earlier - check it out - TBD */
    apr_pool_destroy(sp);
    if (bConflict)
        ssl_log(sm, SSL_LOG_WARN,
                "Init: You should not use name-based virtual hosts in conjunction with SSL!!");

    return;
}

static int ssl_init_FindCAList_X509NameCmp(X509_NAME **a, X509_NAME **b)
{
    return(X509_NAME_cmp(*a, *b));
}

STACK_OF(X509_NAME) *ssl_init_FindCAList(server_rec *s, apr_pool_t *pp, const char *cpCAfile, const char *cpCApath)
{
    STACK_OF(X509_NAME) *skCAList;
    STACK_OF(X509_NAME) *sk;
    apr_dir_t *dir;
    apr_finfo_t direntry;
    char *cp;
    apr_pool_t *p;
    int n;

    /*
     * Use a subpool so we don't bloat up the server pool which
     * is remains in memory for the complete operation time of
     * the server.
     */
    apr_pool_sub_make(&p, pp, NULL);

    /*
     * Start with a empty stack/list where new
     * entries get added in sorted order.
     */
    skCAList = sk_X509_NAME_new(ssl_init_FindCAList_X509NameCmp);

    /*
     * Process CA certificate bundle file
     */
    if (cpCAfile != NULL) {
        sk = (STACK_OF(X509_NAME) *)SSL_load_client_CA_file(cpCAfile);
        for(n = 0; sk != NULL && n < sk_X509_NAME_num(sk); n++) {
            ssl_log(s, SSL_LOG_TRACE,
                    "CA certificate: %s",
                    X509_NAME_oneline(sk_X509_NAME_value(sk, n), NULL, 0));
            if (sk_X509_NAME_find(skCAList, sk_X509_NAME_value(sk, n)) < 0)
                sk_X509_NAME_push(skCAList, sk_X509_NAME_value(sk, n));
        }
    }

    /*
     * Process CA certificate path files
     */
    if (cpCApath != NULL) {
        apr_dir_open(&dir, cpCApath, p);
        while ((apr_dir_read(&direntry, APR_FINFO_DIRENT, dir)) != APR_SUCCESS) {
            cp = apr_pstrcat(p, cpCApath, "/", direntry.name, NULL);
            sk = (STACK_OF(X509_NAME) *)SSL_load_client_CA_file(cp);
            for(n = 0; sk != NULL && n < sk_X509_NAME_num(sk); n++) {
                ssl_log(s, SSL_LOG_TRACE,
                        "CA certificate: %s",
                        X509_NAME_oneline(sk_X509_NAME_value(sk, n), NULL, 0));
                if (sk_X509_NAME_find(skCAList, sk_X509_NAME_value(sk, n)) < 0)
                    sk_X509_NAME_push(skCAList, sk_X509_NAME_value(sk, n));
            }
        }
        apr_dir_close(dir);
    }

    /*
     * Cleanup
     */
    sk_X509_NAME_set_cmp_func(skCAList, NULL);
    apr_pool_destroy(p);

    return skCAList;
}

void ssl_init_Child(apr_pool_t *p, server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    mc->pid = getpid(); /* only call getpid() once per-process */

    /* XXX: there should be an ap_srand() function */
    srand((unsigned int)time(NULL));

    /* open the mutex lockfile */
    ssl_mutex_reinit(s, p);
    return;
}

apr_status_t ssl_init_ChildKill(void *data)
{
    /* server_rec *s = (server_rec *)data; */
    /* currently nothing to do */
    return APR_SUCCESS;
}

apr_status_t ssl_init_ModuleKill(void *data)
{
    SSLSrvConfigRec *sc;
    server_rec *s = (server_rec *)data;

    /*
     * Drop the session cache and mutex
     */
    ssl_scache_kill(s);

    /* 
     * Destroy the temporary keys and params
     */
    ssl_init_TmpKeysHandle(SSL_TKP_FREE, s, NULL);

    /*
     * Free the non-pool allocated structures
     * in the per-server configurations
     */
    for (; s != NULL; s = s->next) {
        sc = mySrvConfig(s);
        if (sc->pPublicCert[SSL_AIDX_RSA] != NULL) {
            X509_free(sc->pPublicCert[SSL_AIDX_RSA]);
            sc->pPublicCert[SSL_AIDX_RSA] = NULL;
        }
        if (sc->pPublicCert[SSL_AIDX_DSA] != NULL) {
            X509_free(sc->pPublicCert[SSL_AIDX_DSA]);
            sc->pPublicCert[SSL_AIDX_DSA] = NULL;
        }
        if (sc->pPrivateKey[SSL_AIDX_RSA] != NULL) {
            EVP_PKEY_free(sc->pPrivateKey[SSL_AIDX_RSA]);
            sc->pPrivateKey[SSL_AIDX_RSA] = NULL;
        }
        if (sc->pPrivateKey[SSL_AIDX_DSA] != NULL) {
            EVP_PKEY_free(sc->pPrivateKey[SSL_AIDX_DSA]);
            sc->pPrivateKey[SSL_AIDX_DSA] = NULL;
        }
        if (sc->pSSLCtx != NULL) {
            SSL_CTX_free(sc->pSSLCtx);
            sc->pSSLCtx = NULL;
        }
    }

    /*
     * Try to kill the internals of the SSL library.
     */
#ifdef SHARED_MODULE
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();
#endif

    return APR_SUCCESS;
}

