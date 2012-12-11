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
 *  ssl_engine_init.c
 *  Initialization of Servers
 */
                             /* ``Recursive, adj.;
                                  see Recursive.''
                                        -- Unknown   */
#include "ssl_private.h"
#include "mpm_common.h"

/*  _________________________________________________________________
**
**  Module Initialization
**  _________________________________________________________________
*/

#ifndef OPENSSL_NO_EC
#define KEYTYPES "RSA, DSA or ECC"
#else 
#define KEYTYPES "RSA or DSA"
#endif

static void ssl_add_version_components(apr_pool_t *p,
                                       server_rec *s)
{
    char *modver = ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_INTERFACE");
    char *libver = ssl_var_lookup(p, s, NULL, NULL, "SSL_VERSION_LIBRARY");
    char *incver = ssl_var_lookup(p, s, NULL, NULL,
                                  "SSL_VERSION_LIBRARY_INTERFACE");

    ap_add_version_component(p, libver);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01876)
                 "%s compiled against Server: %s, Library: %s",
                 modver, AP_SERVER_BASEVERSION, incver);
}


/*
 * Handle the Temporary RSA Keys and DH Params
 */

#define MODSSL_TMP_KEY_FREE(mc, type, idx) \
    if (mc->pTmpKeys[idx]) { \
        type##_free((type *)mc->pTmpKeys[idx]); \
        mc->pTmpKeys[idx] = NULL; \
    }

#define MODSSL_TMP_KEYS_FREE(mc, type) \
    MODSSL_TMP_KEY_FREE(mc, type, SSL_TMP_KEY_##type##_512); \
    MODSSL_TMP_KEY_FREE(mc, type, SSL_TMP_KEY_##type##_1024)

static void ssl_tmp_keys_free(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    MODSSL_TMP_KEYS_FREE(mc, RSA);
    MODSSL_TMP_KEYS_FREE(mc, DH);
#ifndef OPENSSL_NO_EC
    MODSSL_TMP_KEY_FREE(mc, EC_KEY, SSL_TMP_KEY_EC_256);
#endif
}

static int ssl_tmp_key_init_rsa(server_rec *s,
                                int bits, int idx)
{
    SSLModConfigRec *mc = myModConfig(s);

#ifdef HAVE_FIPS

    if (FIPS_mode() && bits < 1024) {
        mc->pTmpKeys[idx] = NULL;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01877)
                     "Init: Skipping generating temporary "
                     "%d bit RSA private key in FIPS mode", bits);
        return OK;
    }

#endif
#ifdef HAVE_GENERATE_EX
    {
        RSA *tkey;
        BIGNUM *bn_f4;
        if (!(tkey = RSA_new())
          || !(bn_f4 = BN_new())
          || !BN_set_word(bn_f4, RSA_F4)
          || !RSA_generate_key_ex(tkey, bits, bn_f4, NULL))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01878)
                         "Init: Failed to generate temporary "
                         "%d bit RSA private key", bits);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            return !OK;
        }
        BN_free(bn_f4);
        mc->pTmpKeys[idx] = tkey;
    }
#else
    if (!(mc->pTmpKeys[idx] =
          RSA_generate_key(bits, RSA_F4, NULL, NULL)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01879)
                     "Init: Failed to generate temporary "
                     "%d bit RSA private key", bits);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
        return !OK;
    }
#endif

    return OK;
}

static int ssl_tmp_key_init_dh(server_rec *s,
                               int bits, int idx)
{
    SSLModConfigRec *mc = myModConfig(s);

#ifdef HAVE_FIPS

    if (FIPS_mode() && bits < 1024) {
        mc->pTmpKeys[idx] = NULL;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01880)
                     "Init: Skipping generating temporary "
                     "%d bit DH parameters in FIPS mode", bits);
        return OK;
    }

#endif

    if (!(mc->pTmpKeys[idx] =
          ssl_dh_GetTmpParam(bits)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01881)
                     "Init: Failed to generate temporary "
                     "%d bit DH parameters", bits);
        return !OK;
    }

    return OK;
}

#ifndef OPENSSL_NO_EC
static int ssl_tmp_key_init_ec(server_rec *s,
                               int bits, int idx)
{
    SSLModConfigRec *mc = myModConfig(s);
    EC_KEY *ecdh = NULL;

    /* XXX: Are there any FIPS constraints we should enforce? */

    if (bits != 256) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02298)
                     "Init: Failed to generate temporary "
                     "%d bit EC parameters, only 256 bits supported", bits);
        return !OK;
    }

    if ((ecdh = EC_KEY_new()) == NULL ||
        EC_KEY_set_group(ecdh, EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) != 1)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02299)
                     "Init: Failed to generate temporary "
                     "%d bit EC parameters", bits);
        return !OK;
    }

    mc->pTmpKeys[idx] = ecdh;
    return OK;
}

#define MODSSL_TMP_KEY_INIT_EC(s, bits) \
    ssl_tmp_key_init_ec(s, bits, SSL_TMP_KEY_EC_##bits)

#endif

#define MODSSL_TMP_KEY_INIT_RSA(s, bits) \
    ssl_tmp_key_init_rsa(s, bits, SSL_TMP_KEY_RSA_##bits)

#define MODSSL_TMP_KEY_INIT_DH(s, bits) \
    ssl_tmp_key_init_dh(s, bits, SSL_TMP_KEY_DH_##bits)

static int ssl_tmp_keys_init(server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                 "Init: Generating temporary RSA private keys (512/1024 bits)");

    if (MODSSL_TMP_KEY_INIT_RSA(s, 512) ||
        MODSSL_TMP_KEY_INIT_RSA(s, 1024)) {
        return !OK;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                 "Init: Generating temporary DH parameters (512/1024 bits)");

    if (MODSSL_TMP_KEY_INIT_DH(s, 512) ||
        MODSSL_TMP_KEY_INIT_DH(s, 1024)) {
        return !OK;
    }

#ifndef OPENSSL_NO_EC
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                 "Init: Generating temporary EC parameters (256 bits)");

    if (MODSSL_TMP_KEY_INIT_EC(s, 256)) {
        return !OK;
    }
#endif

    return OK;
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

    if (SSLeay() < SSL_LIBRARY_VERSION) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(01882)
                     "Init: this version of mod_ssl was compiled against "
                     "a newer library (%s, version currently loaded is %s)"
                     " - may result in undefined or erroneous behavior",
                     SSL_LIBRARY_TEXT, SSLeay_version(SSLEAY_VERSION));
    }

    /* We initialize mc->pid per-process in the child init,
     * but it should be initialized for startup before we
     * call ssl_rand_seed() below.
     */
    mc->pid = getpid();

    /*
     * Let us cleanup on restarts and exits
     */
    apr_pool_cleanup_register(p, base_server,
                              ssl_init_ModuleKill,
                              apr_pool_cleanup_null);

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

        if (sc->server) {
            sc->server->sc = sc;
        }

        if (sc->proxy) {
            sc->proxy->sc = sc;
        }

        /*
         * Create the server host:port string because we need it a lot
         */
        sc->vhost_id = ssl_util_vhostid(p, s);
        sc->vhost_id_len = strlen(sc->vhost_id);

        if (ap_get_server_protocol(s) &&
            strcmp("https", ap_get_server_protocol(s)) == 0) {
            sc->enabled = SSL_ENABLED_TRUE;
        }

       /* If sc->enabled is UNSET, then SSL is optional on this vhost  */
        /* Fix up stuff that may not have been set */
        if (sc->enabled == SSL_ENABLED_UNSET) {
            sc->enabled = SSL_ENABLED_FALSE;
        }
        if (sc->proxy_enabled == UNSET) {
            sc->proxy_enabled = FALSE;
        }

        if (sc->session_cache_timeout == UNSET) {
            sc->session_cache_timeout = SSL_SESSION_CACHE_TIMEOUT;
        }

        if (sc->server && sc->server->pphrase_dialog_type == SSL_PPTYPE_UNSET) {
            sc->server->pphrase_dialog_type = SSL_PPTYPE_BUILTIN;
        }

#ifdef HAVE_FIPS
        if (sc->fips == UNSET) {
            sc->fips = FALSE;
        }
#endif
    }

#if APR_HAS_THREADS
    ssl_util_thread_setup(p);
#endif

    /*
     * SSL external crypto device ("engine") support
     */
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
    ssl_init_Engine(base_server, p);
#endif

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01883)
                 "Init: Initialized %s library", SSL_LIBRARY_NAME);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     * only need ptemp here; nothing inside allocated from the pool
     * needs to live once we return from ssl_rand_seed().
     */
    ssl_rand_seed(base_server, ptemp, SSL_RSCTX_STARTUP, "Init: ");

#ifdef HAVE_FIPS
    if(sc->fips) {
        if (!FIPS_mode()) {
            if (FIPS_mode_set(1)) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(01884)
                             "Operating in SSL FIPS mode");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01885) "FIPS mode failed");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
                ssl_die(s);
            }
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(01886)
                     "SSL FIPS mode disabled");
    }
#endif

    /*
     * read server private keys/public certs into memory.
     * decrypting any encrypted keys via configured SSLPassPhraseDialogs
     * anything that needs to live longer than ptemp needs to also survive
     * restarts, in which case they'll live inside s->process->pool.
     */
    ssl_pphrase_Handle(base_server, ptemp);

    if (ssl_tmp_keys_init(base_server)) {
        return !OK;
    }

    /*
     * initialize the mutex handling
     */
    if (!ssl_mutex_init(base_server, p)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#ifdef HAVE_OCSP_STAPLING
    ssl_stapling_ex_init();
#endif

    /*
     * initialize session caching
     */
    ssl_scache_init(base_server, p);

    /*
     *  initialize servers
     */
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server, APLOGNO(01887)
                 "Init: Initializing (virtual) servers for SSL");

    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);
        /*
         * Either now skip this server when SSL is disabled for
         * it or give out some information about what we're
         * configuring.
         */

        /*
         * Read the server certificate and key
         */
        ssl_init_ConfigureServer(s, p, ptemp, sc);
    }

    /*
     * Configuration consistency checks
     */
    ssl_init_CheckServers(base_server, ptemp);

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
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
void ssl_init_Engine(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    ENGINE *e;

    if (mc->szCryptoDevice) {
        if (!(e = ENGINE_by_id(mc->szCryptoDevice))) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01888)
                         "Init: Failed to load Crypto Device API `%s'",
                         mc->szCryptoDevice);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            ssl_die(s);
        }

        if (strEQ(mc->szCryptoDevice, "chil")) {
            ENGINE_ctrl(e, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
        }

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01889)
                         "Init: Failed to enable Crypto Device API `%s'",
                         mc->szCryptoDevice);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            ssl_die(s);
        }
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01890)
                     "Init: loaded Crypto Device API `%s'",
                     mc->szCryptoDevice);

        ENGINE_free(e);
    }
}
#endif

static void ssl_init_server_check(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modssl_ctx_t *mctx)
{
    /*
     * check for important parameters and the
     * possibility that the user forgot to set them.
     */
    if (!mctx->pks->cert_files[0] && !mctx->pkcs7) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01891)
                "No SSL Certificate set [hint: SSLCertificateFile]");
        ssl_die(s);
    }

    /*
     *  Check for problematic re-initializations
     */
    if (mctx->pks->certs[SSL_AIDX_RSA] ||
        mctx->pks->certs[SSL_AIDX_DSA]
#ifndef OPENSSL_NO_EC
      || mctx->pks->certs[SSL_AIDX_ECC]
#endif
        )
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01892)
                "Illegal attempt to re-initialise SSL for server "
                "(SSLEngine On should go in the VirtualHost, not in global scope.)");
        ssl_die(s);
    }
}

#ifndef OPENSSL_NO_TLSEXT
static void ssl_init_ctx_tls_extensions(server_rec *s,
                                        apr_pool_t *p,
                                        apr_pool_t *ptemp,
                                        modssl_ctx_t *mctx)
{
    /*
     * Configure TLS extensions support
     */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01893)
                 "Configuring TLS extension handling");

    /*
     * Server name indication (SNI)
     */
    if (!SSL_CTX_set_tlsext_servername_callback(mctx->ssl_ctx,
                          ssl_callback_ServerNameIndication) ||
        !SSL_CTX_set_tlsext_servername_arg(mctx->ssl_ctx, mctx)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01894)
                     "Unable to initialize TLS servername extension "
                     "callback (incompatible OpenSSL version?)");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

#ifdef HAVE_OCSP_STAPLING
    /*
     * OCSP Stapling support, status_request extension
     */
    if ((mctx->pkp == FALSE) && (mctx->stapling_enabled == TRUE)) {
        modssl_init_stapling(s, p, ptemp, mctx);
    }
#endif

#ifndef OPENSSL_NO_SRP
    /*
     * TLS-SRP support
     */
    if (mctx->srp_vfile != NULL) {
        int err;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02308)
                     "Using SRP verifier file [%s]", mctx->srp_vfile);

        if (!(mctx->srp_vbase = SRP_VBASE_new(mctx->srp_unknown_user_seed))) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02309)
                         "Unable to initialize SRP verifier structure "
                         "[%s seed]",
                         mctx->srp_unknown_user_seed ? "with" : "without");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            ssl_die(s);
        }

        err = SRP_VBASE_init(mctx->srp_vbase, mctx->srp_vfile);
        if (err != SRP_NO_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02310)
                         "Unable to load SRP verifier file [error %d]", err);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            ssl_die(s);
        }

        SSL_CTX_set_srp_username_callback(mctx->ssl_ctx,
                                          ssl_callback_SRPServerParams);
        SSL_CTX_set_srp_cb_arg(mctx->ssl_ctx, mctx);
    }
#endif
}
#endif

static void ssl_init_ctx_protocol(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = NULL;
    MODSSL_SSL_METHOD_CONST SSL_METHOD *method = NULL;
    char *cp;
    int protocol = mctx->protocol;
    SSLSrvConfigRec *sc = mySrvConfig(s);

    /*
     *  Create the new per-server SSL context
     */
    if (protocol == SSL_PROTOCOL_NONE) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02231)
                "No SSL protocols available [hint: SSLProtocol]");
        ssl_die(s);
    }

    cp = apr_pstrcat(p,
                     (protocol & SSL_PROTOCOL_SSLV3 ? "SSLv3, " : ""),
                     (protocol & SSL_PROTOCOL_TLSV1 ? "TLSv1, " : ""),
#ifdef HAVE_TLSV1_X
                     (protocol & SSL_PROTOCOL_TLSV1_1 ? "TLSv1.1, " : ""),
                     (protocol & SSL_PROTOCOL_TLSV1_2 ? "TLSv1.2, " : ""),
#endif
                     NULL);
    cp[strlen(cp)-2] = NUL;

    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                 "Creating new SSL context (protocols: %s)", cp);

    if (protocol == SSL_PROTOCOL_SSLV3) {
        method = mctx->pkp ?
            SSLv3_client_method() : /* proxy */
            SSLv3_server_method();  /* server */
    }
    else if (protocol == SSL_PROTOCOL_TLSV1) {
        method = mctx->pkp ?
            TLSv1_client_method() : /* proxy */
            TLSv1_server_method();  /* server */
    }
#ifdef HAVE_TLSV1_X
    else if (protocol == SSL_PROTOCOL_TLSV1_1) {
        method = mctx->pkp ?
            TLSv1_1_client_method() : /* proxy */
            TLSv1_1_server_method();  /* server */
    }
    else if (protocol == SSL_PROTOCOL_TLSV1_2) {
        method = mctx->pkp ?
            TLSv1_2_client_method() : /* proxy */
            TLSv1_2_server_method();  /* server */
    }
#endif
    else { /* For multiple protocols, we need a flexible method */
        method = mctx->pkp ?
            SSLv23_client_method() : /* proxy */
            SSLv23_server_method();  /* server */
    }
    ctx = SSL_CTX_new(method);

    mctx->ssl_ctx = ctx;

    SSL_CTX_set_options(ctx, SSL_OP_ALL);

    /* always disable SSLv2, as per RFC 6176 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    if (!(protocol & SSL_PROTOCOL_SSLV3)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    }

    if (!(protocol & SSL_PROTOCOL_TLSV1)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    }

#ifdef HAVE_TLSV1_X
    if (!(protocol & SSL_PROTOCOL_TLSV1_1)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    }

    if (!(protocol & SSL_PROTOCOL_TLSV1_2)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
    }
#endif

#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    if (sc->cipher_server_pref == TRUE) {
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }
#endif


#ifndef OPENSSL_NO_COMP
    if (sc->compression != TRUE) {
#ifdef SSL_OP_NO_COMPRESSION
        /* OpenSSL >= 1.0 only */
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#elif OPENSSL_VERSION_NUMBER >= 0x00908000L
        sk_SSL_COMP_zero(SSL_COMP_get_compression_methods());
#endif
    }
#endif

#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    if (sc->insecure_reneg == TRUE) {
        SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
    }
#endif

    SSL_CTX_set_app_data(ctx, s);

    /*
     * Configure additional context ingredients
     */
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    /*
     * Disallow a session from being resumed during a renegotiation,
     * so that an acceptable cipher suite can be negotiated.
     */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    /* If httpd is configured to reduce mem usage, ask openssl to do so, too */
    if (ap_max_mem_free != APR_ALLOCATOR_MAX_FREE_UNLIMITED)
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
}

static void ssl_init_ctx_session_cache(server_rec *s,
                                       apr_pool_t *p,
                                       apr_pool_t *ptemp,
                                       modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;
    SSLModConfigRec *mc = myModConfig(s);

    SSL_CTX_set_session_cache_mode(ctx, mc->sesscache_mode);

    if (mc->sesscache) {
        SSL_CTX_sess_set_new_cb(ctx,    ssl_callback_NewSessionCacheEntry);
        SSL_CTX_sess_set_get_cb(ctx,    ssl_callback_GetSessionCacheEntry);
        SSL_CTX_sess_set_remove_cb(ctx, ssl_callback_DelSessionCacheEntry);
    }
}

static void ssl_init_ctx_callbacks(server_rec *s,
                                   apr_pool_t *p,
                                   apr_pool_t *ptemp,
                                   modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;

    SSL_CTX_set_tmp_rsa_callback(ctx, ssl_callback_TmpRSA);
    SSL_CTX_set_tmp_dh_callback(ctx,  ssl_callback_TmpDH);
#ifndef OPENSSL_NO_EC
    SSL_CTX_set_tmp_ecdh_callback(ctx,ssl_callback_TmpECDH);
#endif

    SSL_CTX_set_info_callback(ctx, ssl_callback_Info);
}

static void ssl_init_ctx_verify(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;

    int verify = SSL_VERIFY_NONE;
    STACK_OF(X509_NAME) *ca_list;

    if (mctx->auth.verify_mode == SSL_CVERIFY_UNSET) {
        mctx->auth.verify_mode = SSL_CVERIFY_NONE;
    }

    if (mctx->auth.verify_depth == UNSET) {
        mctx->auth.verify_depth = 1;
    }

    /*
     *  Configure callbacks for SSL context
     */
    if (mctx->auth.verify_mode == SSL_CVERIFY_REQUIRE) {
        verify |= SSL_VERIFY_PEER_STRICT;
    }

    if ((mctx->auth.verify_mode == SSL_CVERIFY_OPTIONAL) ||
        (mctx->auth.verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA))
    {
        verify |= SSL_VERIFY_PEER;
    }

    SSL_CTX_set_verify(ctx, verify, ssl_callback_SSLVerify);

    /*
     * Configure Client Authentication details
     */
    if (mctx->auth.ca_cert_file || mctx->auth.ca_cert_path) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                     "Configuring client authentication");

        if (!SSL_CTX_load_verify_locations(ctx,
                                           mctx->auth.ca_cert_file,
                                           mctx->auth.ca_cert_path))
        {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01895)
                    "Unable to configure verify locations "
                    "for client authentication");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            ssl_die(s);
        }

        if (mctx->pks && (mctx->pks->ca_name_file || mctx->pks->ca_name_path)) {
            ca_list = ssl_init_FindCAList(s, ptemp,
                                          mctx->pks->ca_name_file,
                                          mctx->pks->ca_name_path);
        } else
            ca_list = ssl_init_FindCAList(s, ptemp,
                                          mctx->auth.ca_cert_file,
                                          mctx->auth.ca_cert_path);
        if (sk_X509_NAME_num(ca_list) <= 0) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01896)
                    "Unable to determine list of acceptable "
                    "CA certificates for client authentication");
            ssl_die(s);
        }

        SSL_CTX_set_client_CA_list(ctx, ca_list);
    }

    /*
     * Give a warning when no CAs were configured but client authentication
     * should take place. This cannot work.
     */
    if (mctx->auth.verify_mode == SSL_CVERIFY_REQUIRE) {
        ca_list = SSL_CTX_get_client_CA_list(ctx);

        if (sk_X509_NAME_num(ca_list) == 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01897)
                         "Init: Oops, you want to request client "
                         "authentication, but no CAs are known for "
                         "verification!?  [Hint: SSLCACertificate*]");
        }
    }
}

static void ssl_init_ctx_cipher_suite(server_rec *s,
                                      apr_pool_t *p,
                                      apr_pool_t *ptemp,
                                      modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;
    const char *suite = mctx->auth.cipher_suite;

    /*
     *  Configure SSL Cipher Suite
     */
    if (!suite) {
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                 "Configuring permitted SSL ciphers [%s]",
                 suite);

    if (!SSL_CTX_set_cipher_list(ctx, suite)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01898)
                "Unable to configure permitted SSL ciphers");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }
}

static void ssl_init_ctx_crl(server_rec *s,
                             apr_pool_t *p,
                             apr_pool_t *ptemp,
                             modssl_ctx_t *mctx)
{
    X509_STORE *store = SSL_CTX_get_cert_store(mctx->ssl_ctx);
    unsigned long crlflags = 0;
    char *cfgp = mctx->pkp ? "SSLProxy" : "SSL";

    /*
     * Configure Certificate Revocation List (CRL) Details
     */

    if (!(mctx->crl_file || mctx->crl_path)) {
        if (mctx->crl_check_mode == SSL_CRLCHECK_LEAF ||
            mctx->crl_check_mode == SSL_CRLCHECK_CHAIN) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01899)
                         "Host %s: CRL checking has been enabled, but "
                         "neither %sCARevocationFile nor %sCARevocationPath "
                         "is configured", mctx->sc->vhost_id, cfgp, cfgp);
            ssl_die(s);
        }
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01900)
                 "Configuring certificate revocation facility");

    if (!store || !X509_STORE_load_locations(store, mctx->crl_file,
                                             mctx->crl_path)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01901)
                     "Host %s: unable to configure X.509 CRL storage "
                     "for certificate revocation", mctx->sc->vhost_id);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

    switch (mctx->crl_check_mode) {
       case SSL_CRLCHECK_LEAF:
           crlflags = X509_V_FLAG_CRL_CHECK;
           break;
       case SSL_CRLCHECK_CHAIN:
           crlflags = X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL;
           break;
       default:
           crlflags = 0;
    }

    if (crlflags) {
        X509_STORE_set_flags(store, crlflags);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01902)
                     "Host %s: X.509 CRL storage locations configured, "
                     "but CRL checking (%sCARevocationCheck) is not "
                     "enabled", mctx->sc->vhost_id, cfgp);
    }
}

static void ssl_init_ctx_pkcs7_cert_chain(server_rec *s, modssl_ctx_t *mctx)
{
    STACK_OF(X509) *certs = ssl_read_pkcs7(s, mctx->pkcs7);
    int n;
    STACK_OF(X509) *extra_certs = NULL;

#ifdef OPENSSL_NO_SSL_INTERN
    SSL_CTX_get_extra_chain_certs(mctx->ssl_ctx, &extra_certs);
#else
    extra_certs = mctx->ssl_ctx->extra_certs;
#endif

    if (!extra_certs)
        for (n = 1; n < sk_X509_num(certs); ++n)
             SSL_CTX_add_extra_chain_cert(mctx->ssl_ctx, sk_X509_value(certs, n));
}

static void ssl_init_ctx_cert_chain(server_rec *s,
                                    apr_pool_t *p,
                                    apr_pool_t *ptemp,
                                    modssl_ctx_t *mctx)
{
    BOOL skip_first = FALSE;
    int i, n;
    const char *chain = mctx->cert_chain;

    if (mctx->pkcs7) {
        ssl_init_ctx_pkcs7_cert_chain(s, mctx);
        return;
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
    if (!chain) {
        return;
    }

    for (i = 0; (i < SSL_AIDX_MAX) && mctx->pks->cert_files[i]; i++) {
        if (strEQ(mctx->pks->cert_files[i], chain)) {
            skip_first = TRUE;
            break;
        }
    }

    n = SSL_CTX_use_certificate_chain(mctx->ssl_ctx,
                                      (char *)chain,
                                      skip_first, NULL);
    if (n < 0) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01903)
                "Failed to configure CA certificate chain!");
        ssl_die(s);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01904)
                 "Configuring server certificate chain "
                 "(%d CA certificate%s)",
                 n, n == 1 ? "" : "s");
}

static void ssl_init_ctx(server_rec *s,
                         apr_pool_t *p,
                         apr_pool_t *ptemp,
                         modssl_ctx_t *mctx)
{
    ssl_init_ctx_protocol(s, p, ptemp, mctx);

    ssl_init_ctx_session_cache(s, p, ptemp, mctx);

    ssl_init_ctx_callbacks(s, p, ptemp, mctx);

    ssl_init_ctx_verify(s, p, ptemp, mctx);

    ssl_init_ctx_cipher_suite(s, p, ptemp, mctx);

    ssl_init_ctx_crl(s, p, ptemp, mctx);

    if (mctx->pks) {
        /* XXX: proxy support? */
        ssl_init_ctx_cert_chain(s, p, ptemp, mctx);
#ifndef OPENSSL_NO_TLSEXT
        ssl_init_ctx_tls_extensions(s, p, ptemp, mctx);
#endif
    }
}

static int ssl_server_import_cert(server_rec *s,
                                  modssl_ctx_t *mctx,
                                  const char *id,
                                  int idx)
{
    SSLModConfigRec *mc = myModConfig(s);
    ssl_asn1_t *asn1;
    MODSSL_D2I_X509_CONST unsigned char *ptr;
    const char *type = ssl_asn1_keystr(idx);
    X509 *cert;

    if (!(asn1 = ssl_asn1_table_get(mc->tPublicCert, id))) {
        return FALSE;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02232)
                 "Configuring %s server certificate", type);

    ptr = asn1->cpData;
    if (!(cert = d2i_X509(NULL, &ptr, asn1->nData))) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02233)
                "Unable to import %s server certificate", type);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

    if (SSL_CTX_use_certificate(mctx->ssl_ctx, cert) <= 0) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02234)
                "Unable to configure %s server certificate", type);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

#ifdef HAVE_OCSP_STAPLING
    if ((mctx->pkp == FALSE) && (mctx->stapling_enabled == TRUE)) {
        if (!ssl_stapling_init_cert(s, mctx, cert)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02235)
                         "Unable to configure server certificate for stapling");
        }
    }
#endif

    mctx->pks->certs[idx] = cert;

    return TRUE;
}

static int ssl_server_import_key(server_rec *s,
                                 modssl_ctx_t *mctx,
                                 const char *id,
                                 int idx)
{
    SSLModConfigRec *mc = myModConfig(s);
    ssl_asn1_t *asn1;
    MODSSL_D2I_PrivateKey_CONST unsigned char *ptr;
    const char *type = ssl_asn1_keystr(idx);
    int pkey_type;
    EVP_PKEY *pkey;

#ifndef OPENSSL_NO_EC
    if (idx == SSL_AIDX_ECC)
      pkey_type = EVP_PKEY_EC;
    else
#endif
    pkey_type = (idx == SSL_AIDX_RSA) ? EVP_PKEY_RSA : EVP_PKEY_DSA;

    if (!(asn1 = ssl_asn1_table_get(mc->tPrivateKey, id))) {
        return FALSE;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02236)
                 "Configuring %s server private key", type);

    ptr = asn1->cpData;
    if (!(pkey = d2i_PrivateKey(pkey_type, NULL, &ptr, asn1->nData)))
    {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02237)
                "Unable to import %s server private key", type);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

    if (SSL_CTX_use_PrivateKey(mctx->ssl_ctx, pkey) <= 0) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02238)
                "Unable to configure %s server private key", type);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

    /*
     * XXX: wonder if this is still needed, this is old todo doc.
     * (see http://www.psy.uq.edu.au/~ftp/Crypto/ssleay/TODO.html)
     */
    if ((pkey_type == EVP_PKEY_DSA) && mctx->pks->certs[idx]) {
        EVP_PKEY *pubkey = X509_get_pubkey(mctx->pks->certs[idx]);

        if (pubkey && EVP_PKEY_missing_parameters(pubkey)) {
            EVP_PKEY_copy_parameters(pubkey, pkey);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02239)
                    "Copying DSA parameters from private key to certificate");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            EVP_PKEY_free(pubkey);
        }
    }

    mctx->pks->keys[idx] = pkey;

    return TRUE;
}

static void ssl_check_public_cert(server_rec *s,
                                  apr_pool_t *ptemp,
                                  X509 *cert,
                                  int type)
{
    int is_ca, pathlen;
    apr_array_header_t *ids;

    if (!cert) {
        return;
    }

    /*
     * Some information about the certificate(s)
     */

    if (SSL_X509_isSGC(cert)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01905)
                     "%s server certificate enables "
                     "Server Gated Cryptography (SGC)",
                     ssl_asn1_keystr(type));
    }

    if (SSL_X509_getBC(cert, &is_ca, &pathlen)) {
        if (is_ca) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01906)
                         "%s server certificate is a CA certificate "
                         "(BasicConstraints: CA == TRUE !?)",
                         ssl_asn1_keystr(type));
        }

        if (pathlen > 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01907)
                         "%s server certificate is not a leaf certificate "
                         "(BasicConstraints: pathlen == %d > 0 !?)",
                         ssl_asn1_keystr(type), pathlen);
        }
    }

    /*
     * Check if the server name is covered by the certificate.
     * Consider both dNSName entries in the subjectAltName extension
     * and, as a fallback, commonName attributes in the subject DN.
     * (DNS-IDs and CN-IDs as defined in RFC 6125).
     */
    if (SSL_X509_getIDs(ptemp, cert, &ids)) {
        char *cp;
        int i;
        char **id = (char **)ids->elts;
        BOOL is_wildcard, matched = FALSE;

        for (i = 0; i < ids->nelts; i++) {
            if (!id[i])
                continue;

            /*
             * Determine if it is a wildcard ID - we're restrictive
             * in the sense that we require the wildcard character to be
             * THE left-most label (i.e., the ID must start with "*.")
             */
            is_wildcard = (*id[i] == '*' && *(id[i]+1) == '.') ? TRUE : FALSE;

            /*
             * If the ID includes a wildcard character, check if it matches
             * for the left-most DNS label (i.e., the wildcard character
             * is not allowed to match a dot). Otherwise, try a simple
             * string compare, case insensitively.
             */
            if ((is_wildcard == TRUE &&
                 (cp = strchr(s->server_hostname, '.')) &&
                 !strcasecmp(id[i]+1, cp)) ||
                !strcasecmp(id[i], s->server_hostname)) {
                matched = TRUE;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01908)
                             "%sID '%s' in %s certificate configured "
                             "for %s matches server name",
                             is_wildcard ? "Wildcard " : "",
                             id[i], ssl_asn1_keystr(type),
                             (mySrvConfig(s))->vhost_id);
                break;
            }
        }

        if (matched == FALSE) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01909)
                         "%s certificate configured for %s does NOT include "
                         "an ID which matches the server name",
                         ssl_asn1_keystr(type), (mySrvConfig(s))->vhost_id);
        }
    }
}

static void ssl_init_server_certs(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modssl_ctx_t *mctx)
{
    const char *rsa_id, *dsa_id;
#ifndef OPENSSL_NO_EC
    const char *ecc_id;
#endif
    const char *vhost_id = mctx->sc->vhost_id;
    int i;
    int have_rsa, have_dsa;
#ifndef OPENSSL_NO_EC
    int have_ecc;
#endif

    rsa_id = ssl_asn1_table_keyfmt(ptemp, vhost_id, SSL_AIDX_RSA);
    dsa_id = ssl_asn1_table_keyfmt(ptemp, vhost_id, SSL_AIDX_DSA);
#ifndef OPENSSL_NO_EC
    ecc_id = ssl_asn1_table_keyfmt(ptemp, vhost_id, SSL_AIDX_ECC);
#endif

    have_rsa = ssl_server_import_cert(s, mctx, rsa_id, SSL_AIDX_RSA);
    have_dsa = ssl_server_import_cert(s, mctx, dsa_id, SSL_AIDX_DSA);
#ifndef OPENSSL_NO_EC
    have_ecc = ssl_server_import_cert(s, mctx, ecc_id, SSL_AIDX_ECC);
#endif

    if (!(have_rsa || have_dsa
#ifndef OPENSSL_NO_EC
        || have_ecc
#endif
)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01910)
                "Oops, no " KEYTYPES " server certificate found "
                "for '%s:%d'?!", s->server_hostname, s->port);
        ssl_die(s);
    }

    for (i = 0; i < SSL_AIDX_MAX; i++) {
        ssl_check_public_cert(s, ptemp, mctx->pks->certs[i], i);
    }

    have_rsa = ssl_server_import_key(s, mctx, rsa_id, SSL_AIDX_RSA);
    have_dsa = ssl_server_import_key(s, mctx, dsa_id, SSL_AIDX_DSA);
#ifndef OPENSSL_NO_EC
    have_ecc = ssl_server_import_key(s, mctx, ecc_id, SSL_AIDX_ECC);
#endif

    if (!(have_rsa || have_dsa
#ifndef OPENSSL_NO_EC
        || have_ecc
#endif
          )) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01911)
                "Oops, no " KEYTYPES " server private key found?!");
        ssl_die(s);
    }
}

#ifdef HAVE_TLS_SESSION_TICKETS
static void ssl_init_ticket_key(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                modssl_ctx_t *mctx)
{
    apr_status_t rv;
    apr_file_t *fp;
    apr_size_t len;
    char buf[TLSEXT_TICKET_KEY_LEN];
    char *path;
    modssl_ticket_key_t *ticket_key = mctx->ticket_key;

    if (!ticket_key->file_path) {
        return;
    }

    path = ap_server_root_relative(p, ticket_key->file_path);

    rv = apr_file_open(&fp, path, APR_READ|APR_BINARY,
                       APR_OS_DEFAULT, ptemp);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02286)
                     "Failed to open ticket key file %s: (%d) %pm",
                     path, rv, &rv);
        ssl_die(s);
    }

    rv = apr_file_read_full(fp, &buf[0], TLSEXT_TICKET_KEY_LEN, &len);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02287)
                     "Failed to read %d bytes from %s: (%d) %pm",
                     TLSEXT_TICKET_KEY_LEN, path, rv, &rv);
        ssl_die(s);
    }

    memcpy(ticket_key->key_name, buf, 16);
    memcpy(ticket_key->hmac_secret, buf + 16, 16);
    memcpy(ticket_key->aes_key, buf + 32, 16);

    if (!SSL_CTX_set_tlsext_ticket_key_cb(mctx->ssl_ctx,
                                          ssl_callback_SessionTicket)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01913)
                     "Unable to initialize TLS session ticket key callback "
                     "(incompatible OpenSSL version?)");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02288)
                 "TLS session ticket key for %s successfully loaded from %s",
                 (mySrvConfig(s))->vhost_id, path);
}
#endif

static void ssl_init_proxy_certs(server_rec *s,
                                 apr_pool_t *p,
                                 apr_pool_t *ptemp,
                                 modssl_ctx_t *mctx)
{
    int n, ncerts = 0;
    STACK_OF(X509_INFO) *sk;
    modssl_pk_proxy_t *pkp = mctx->pkp;
    STACK_OF(X509) *chain;
    X509_STORE_CTX *sctx;
    X509_STORE *store = SSL_CTX_get_cert_store(mctx->ssl_ctx);

    SSL_CTX_set_client_cert_cb(mctx->ssl_ctx,
                               ssl_callback_proxy_cert);

    if (!(pkp->cert_file || pkp->cert_path)) {
        return;
    }

    sk = sk_X509_INFO_new_null();

    if (pkp->cert_file) {
        SSL_X509_INFO_load_file(ptemp, sk, pkp->cert_file);
    }

    if (pkp->cert_path) {
        SSL_X509_INFO_load_path(ptemp, sk, pkp->cert_path);
    }

    if ((ncerts = sk_X509_INFO_num(sk)) <= 0) {
        sk_X509_INFO_free(sk);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02206)
                     "no client certs found for SSL proxy");
        return;
    }

    /* Check that all client certs have got certificates and private
     * keys. */
    for (n = 0; n < ncerts; n++) {
        X509_INFO *inf = sk_X509_INFO_value(sk, n);

        if (!inf->x509 || !inf->x_pkey) {
            sk_X509_INFO_free(sk);
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s, APLOGNO(02252)
                         "incomplete client cert configured for SSL proxy "
                         "(missing or encrypted private key?)");
            ssl_die(s);
            return;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02207)
                 "loaded %d client certs for SSL proxy",
                 ncerts);
    pkp->certs = sk;


    if (!pkp->ca_cert_file || !store) {
        return;
    }

    /* Load all of the CA certs and construct a chain */
    pkp->ca_certs = (STACK_OF(X509) **) apr_pcalloc(p, ncerts * sizeof(sk));
    sctx = X509_STORE_CTX_new();

    if (!sctx) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02208)
                     "SSL proxy client cert initialization failed");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        ssl_die(s);
    }

    X509_STORE_load_locations(store, pkp->ca_cert_file, NULL);

    for (n = 0; n < ncerts; n++) {
        int i;

        X509_INFO *inf = sk_X509_INFO_value(pkp->certs, n);
        X509_STORE_CTX_init(sctx, store, inf->x509, NULL);

        /* Attempt to verify the client cert */
        if (X509_verify_cert(sctx) != 1) {
            int err = X509_STORE_CTX_get_error(sctx);
            ssl_log_xerror(SSLLOG_MARK, APLOG_WARNING, 0, ptemp, s, inf->x509,
                           APLOGNO(02270) "SSL proxy client cert chain "
                           "verification failed: %s :",
                           X509_verify_cert_error_string(err));
        }

        /* Clear X509_verify_cert errors */
        ERR_clear_error();

        /* Obtain a copy of the verified chain */
        chain = X509_STORE_CTX_get1_chain(sctx);

        if (chain != NULL) {
            /* Discard end entity cert from the chain */
            X509_free(sk_X509_shift(chain));

            if ((i = sk_X509_num(chain)) > 0) {
                /* Store the chain for later use */
                pkp->ca_certs[n] = chain;
            }
            else {
                /* Discard empty chain */
                sk_X509_pop_free(chain, X509_free);
                pkp->ca_certs[n] = NULL;
            }

            ssl_log_xerror(SSLLOG_MARK, APLOG_DEBUG, 0, ptemp, s, inf->x509,
                           APLOGNO(02271)
                           "loaded %i intermediate CA%s for cert %i: ",
                           i, i == 1 ? "" : "s", n);
            if (i > 0) {
                int j;
                for (j = 0; j < i; j++) {
                    ssl_log_xerror(SSLLOG_MARK, APLOG_DEBUG, 0, ptemp, s,
                                   sk_X509_value(chain, j), "%i:", j);
                }
            }
        }

        /* get ready for next X509_STORE_CTX_init */
        X509_STORE_CTX_cleanup(sctx);
    }

    X509_STORE_CTX_free(sctx);
}

static void ssl_init_proxy_ctx(server_rec *s,
                               apr_pool_t *p,
                               apr_pool_t *ptemp,
                               SSLSrvConfigRec *sc)
{
    ssl_init_ctx(s, p, ptemp, sc->proxy);

    ssl_init_proxy_certs(s, p, ptemp, sc->proxy);
}

static void ssl_init_server_ctx(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                SSLSrvConfigRec *sc)
{
    ssl_init_server_check(s, p, ptemp, sc->server);

    ssl_init_ctx(s, p, ptemp, sc->server);

    ssl_init_server_certs(s, p, ptemp, sc->server);

#ifdef HAVE_TLS_SESSION_TICKETS
    ssl_init_ticket_key(s, p, ptemp, sc->server);
#endif
}

/*
 * Configure a particular server
 */
void ssl_init_ConfigureServer(server_rec *s,
                              apr_pool_t *p,
                              apr_pool_t *ptemp,
                              SSLSrvConfigRec *sc)
{
    /* Initialize the server if SSL is enabled or optional.
     */
    if ((sc->enabled == SSL_ENABLED_TRUE) || (sc->enabled == SSL_ENABLED_OPTIONAL)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01914)
                     "Configuring server %s for SSL protocol", sc->vhost_id);
        ssl_init_server_ctx(s, p, ptemp, sc);
    }

    if (sc->proxy_enabled) {
        ssl_init_proxy_ctx(s, p, ptemp, sc);
    }
}

void ssl_init_CheckServers(server_rec *base_server, apr_pool_t *p)
{
    server_rec *s, *ps;
    SSLSrvConfigRec *sc;
    apr_hash_t *table;
    const char *key;
    apr_ssize_t klen;

    BOOL conflict = FALSE;

    /*
     * Give out warnings when a server has HTTPS configured
     * for the HTTP port or vice versa
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        if ((sc->enabled == SSL_ENABLED_TRUE) && (s->port == DEFAULT_HTTP_PORT)) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                         base_server, APLOGNO(01915)
                         "Init: (%s) You configured HTTPS(%d) "
                         "on the standard HTTP(%d) port!",
                         ssl_util_vhostid(p, s),
                         DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT);
        }

        if ((sc->enabled == SSL_ENABLED_FALSE) && (s->port == DEFAULT_HTTPS_PORT)) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                         base_server, APLOGNO(01916)
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
    table = apr_hash_make(p);

    for (s = base_server; s; s = s->next) {
        char *addr;

        sc = mySrvConfig(s);

        if (!((sc->enabled == SSL_ENABLED_TRUE) && s->addrs)) {
            continue;
        }

        apr_sockaddr_ip_get(&addr, s->addrs->host_addr);
        key = apr_psprintf(p, "%s:%u", addr, s->addrs->host_port);
        klen = strlen(key);

        if ((ps = (server_rec *)apr_hash_get(table, key, klen))) {
#ifdef OPENSSL_NO_TLSEXT
            int level = APLOG_WARNING;
            const char *problem = "conflict";
#else
            int level = APLOG_DEBUG;
            const char *problem = "overlap";
#endif
            ap_log_error(APLOG_MARK, level, 0, base_server,
                         "Init: SSL server IP/port %s: "
                         "%s (%s:%d) vs. %s (%s:%d)",
                         problem, ssl_util_vhostid(p, s),
                         (s->defn_name ? s->defn_name : "unknown"),
                         s->defn_line_number,
                         ssl_util_vhostid(p, ps),
                         (ps->defn_name ? ps->defn_name : "unknown"),
                         ps->defn_line_number);
            conflict = TRUE;
            continue;
        }

        apr_hash_set(table, key, klen, s);
    }

    if (conflict) {
#ifdef OPENSSL_NO_TLSEXT
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(01917)
                     "Init: You should not use name-based "
                     "virtual hosts in conjunction with SSL!!");
#else
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(02292)
                     "Init: Name-based SSL virtual hosts only "
                     "work for clients with TLS server name indication "
                     "support (RFC 4366)");
#endif
    }
}

static int ssl_init_FindCAList_X509NameCmp(const X509_NAME * const *a,
                                           const X509_NAME * const *b)
{
    return(X509_NAME_cmp(*a, *b));
}

static void ssl_init_PushCAList(STACK_OF(X509_NAME) *ca_list,
                                server_rec *s, apr_pool_t *ptemp,
                                const char *file)
{
    int n;
    STACK_OF(X509_NAME) *sk;

    sk = (STACK_OF(X509_NAME) *)
             SSL_load_client_CA_file(file);

    if (!sk) {
        return;
    }

    for (n = 0; n < sk_X509_NAME_num(sk); n++) {
        X509_NAME *name = sk_X509_NAME_value(sk, n);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02209)
                     "CA certificate: %s",
                     SSL_X509_NAME_to_string(ptemp, name, 0));

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
                                         apr_pool_t *ptemp,
                                         const char *ca_file,
                                         const char *ca_path)
{
    STACK_OF(X509_NAME) *ca_list;

    /*
     * Start with a empty stack/list where new
     * entries get added in sorted order.
     */
    ca_list = sk_X509_NAME_new(ssl_init_FindCAList_X509NameCmp);

    /*
     * Process CA certificate bundle file
     */
    if (ca_file) {
        ssl_init_PushCAList(ca_list, s, ptemp, ca_file);
        /*
         * If ca_list is still empty after trying to load ca_file
         * then the file failed to load, and users should hear about that.
         */
        if (sk_X509_NAME_num(ca_list) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02210)
                    "Failed to load SSLCACertificateFile: %s", ca_file);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
        }
    }

    /*
     * Process CA certificate path files
     */
    if (ca_path) {
        apr_dir_t *dir;
        apr_finfo_t direntry;
        apr_int32_t finfo_flags = APR_FINFO_TYPE|APR_FINFO_NAME;
        apr_status_t rv;

        if ((rv = apr_dir_open(&dir, ca_path, ptemp)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(02211)
                    "Failed to open Certificate Path `%s'",
                    ca_path);
            ssl_die(s);
        }

        while ((apr_dir_read(&direntry, finfo_flags, dir)) == APR_SUCCESS) {
            const char *file;
            if (direntry.filetype == APR_DIR) {
                continue; /* don't try to load directories */
            }
            file = apr_pstrcat(ptemp, ca_path, "/", direntry.name, NULL);
            ssl_init_PushCAList(ca_list, s, ptemp, file);
        }

        apr_dir_close(dir);
    }

    /*
     * Cleanup
     */
    (void) sk_X509_NAME_set_cmp_func(ca_list, NULL);

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
#ifdef HAVE_OCSP_STAPLING
    ssl_stapling_mutex_reinit(s, p);
#endif
}

#define MODSSL_CFG_ITEM_FREE(func, item) \
    if (item) { \
        func(item); \
        item = NULL; \
    }

static void ssl_init_ctx_cleanup(modssl_ctx_t *mctx)
{
    MODSSL_CFG_ITEM_FREE(SSL_CTX_free, mctx->ssl_ctx);

#ifndef OPENSSL_NO_SRP
    if (mctx->srp_vbase != NULL) {
        SRP_VBASE_free(mctx->srp_vbase);
        mctx->srp_vbase = NULL;
    }
#endif
}

static void ssl_init_ctx_cleanup_proxy(modssl_ctx_t *mctx)
{
    ssl_init_ctx_cleanup(mctx);

    if (mctx->pkp->certs) {
        int i = 0;
        int ncerts = sk_X509_INFO_num(mctx->pkp->certs);

        if (mctx->pkp->ca_certs) {
            for (i = 0; i < ncerts; i++) {
                if (mctx->pkp->ca_certs[i] != NULL) {
                    sk_X509_pop_free(mctx->pkp->ca_certs[i], X509_free);
                }
            }
        }

        sk_X509_INFO_pop_free(mctx->pkp->certs, X509_INFO_free);
        mctx->pkp->certs = NULL;
    }
}

static void ssl_init_ctx_cleanup_server(modssl_ctx_t *mctx)
{
    int i;

    ssl_init_ctx_cleanup(mctx);

    for (i=0; i < SSL_AIDX_MAX; i++) {
        MODSSL_CFG_ITEM_FREE(X509_free,
                             mctx->pks->certs[i]);

        MODSSL_CFG_ITEM_FREE(EVP_PKEY_free,
                             mctx->pks->keys[i]);
    }
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
    ssl_tmp_keys_free(base_server);

    /*
     * Free the non-pool allocated structures
     * in the per-server configurations
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        ssl_init_ctx_cleanup_proxy(sc->proxy);

        ssl_init_ctx_cleanup_server(sc->server);
    }

    return APR_SUCCESS;
}

