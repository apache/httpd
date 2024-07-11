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
#include "mod_md.h"

static apr_status_t ssl_init_ca_cert_path(server_rec *, apr_pool_t *, const char *,
                                          STACK_OF(X509_NAME) *, STACK_OF(X509_INFO) *);

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, init_server,
                                    (server_rec *s,apr_pool_t *p,int is_proxy,SSL_CTX *ctx),
                                    (s,p,is_proxy,ctx), OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, add_cert_files,
                                    (server_rec *s, apr_pool_t *p, 
                                    apr_array_header_t *cert_files, apr_array_header_t *key_files),
                                    (s, p, cert_files, key_files),
                                    OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, add_fallback_cert_files,
                                    (server_rec *s, apr_pool_t *p, 
                                    apr_array_header_t *cert_files, apr_array_header_t *key_files),
                                    (s, p, cert_files, key_files),
                                    OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, answer_challenge,
                                    (conn_rec *c, const char *server_name, 
                                    X509 **pcert, EVP_PKEY **pkey),
                                    (c, server_name, pcert, pkey),
                                    DECLINED, DECLINED)


/*  _________________________________________________________________
**
**  Module Initialization
**  _________________________________________________________________
*/

#ifdef HAVE_ECC
#define KEYTYPES "RSA, DSA or ECC"
#else 
#define KEYTYPES "RSA or DSA"
#endif

#if MODSSL_USE_OPENSSL_PRE_1_1_API
/* OpenSSL Pre-1.1.0 compatibility */
/* Taken from OpenSSL 1.1.0 snapshot 20160410 */
static int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* q is optional */
    if (p == NULL || g == NULL)
        return 0;
    BN_free(dh->p);
    BN_free(dh->q);
    BN_free(dh->g);
    dh->p = p;
    dh->q = q;
    dh->g = g;

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

/*
 * Grab well-defined DH parameters from OpenSSL, see the BN_get_rfc*
 * functions in <openssl/bn.h> for all available primes.
 */
static DH *make_dh_params(BIGNUM *(*prime)(BIGNUM *))
{
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (!dh) {
        return NULL;
    }
    p = prime(NULL);
    g = BN_new();
    if (g != NULL) {
        BN_set_word(g, 2);
    }
    if (!p || !g || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

/* Storage and initialization for DH parameters. */
static struct dhparam {
    BIGNUM *(*const prime)(BIGNUM *); /* function to generate... */
    DH *dh;                           /* ...this, used for keys.... */
    const unsigned int min;           /* ...of length >= this. */
} dhparams[] = {
    { BN_get_rfc3526_prime_8192, NULL, 6145 },
    { BN_get_rfc3526_prime_6144, NULL, 4097 },
    { BN_get_rfc3526_prime_4096, NULL, 3073 },
    { BN_get_rfc3526_prime_3072, NULL, 2049 },
    { BN_get_rfc3526_prime_2048, NULL, 1025 },
    { BN_get_rfc2409_prime_1024, NULL, 0 }
};

static void init_dh_params(void)
{
    unsigned n;

    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
        dhparams[n].dh = make_dh_params(dhparams[n].prime);
}

static void free_dh_params(void)
{
    unsigned n;

    /* DH_free() is a noop for a NULL parameter, so these are harmless
     * in the (unexpected) case where these variables are already
     * NULL. */
    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++) {
        DH_free(dhparams[n].dh);
        dhparams[n].dh = NULL;
    }
}

/* Hand out the same DH structure though once generated as we leak
 * memory otherwise and freeing the structure up after use would be
 * hard to track and in fact is not needed at all as it is safe to
 * use the same parameters over and over again security wise (in
 * contrast to the keys itself) and code safe as the returned structure
 * is duplicated by OpenSSL anyway. Hence no modification happens
 * to our copy. */
DH *modssl_get_dh_params(unsigned keylen)
{
    unsigned n;

    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
        if (keylen >= dhparams[n].min)
            return dhparams[n].dh;
        
    return NULL; /* impossible to reach. */
}
#endif

static void ssl_add_version_components(apr_pool_t *ptemp, apr_pool_t *pconf,
                                       server_rec *s)
{
    char *modver = ssl_var_lookup(ptemp, s, NULL, NULL, "SSL_VERSION_INTERFACE");
    char *libver = ssl_var_lookup(ptemp, s, NULL, NULL, "SSL_VERSION_LIBRARY");
    char *incver = ssl_var_lookup(ptemp, s, NULL, NULL,
                                  "SSL_VERSION_LIBRARY_INTERFACE");

    ap_add_version_component(pconf, libver);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01876)
                 "%s compiled against Server: %s, Library: %s",
                 modver, AP_SERVER_BASEVERSION, incver);
}

/*  _________________________________________________________________
**
**  Let other answer special connection attempts. 
**  Used in ACME challenge handling by mod_md.
**  _________________________________________________________________
*/

int ssl_is_challenge(conn_rec *c, const char *servername, 
                     X509 **pcert, EVP_PKEY **pkey,
                     const char **pcert_pem, const char **pkey_pem)
{
    *pcert = NULL;
    *pkey = NULL;
    *pcert_pem = *pkey_pem = NULL;
    if (ap_ssl_answer_challenge(c, servername, pcert_pem, pkey_pem)) {
        return 1;
    }
    else if (OK == ssl_run_answer_challenge(c, servername, pcert, pkey)) {
        return 1;
    }
    return 0;
}

#ifdef HAVE_FIPS
static apr_status_t modssl_fips_cleanup(void *data)
{
    modssl_fips_enable(0);
    return APR_SUCCESS;
}
#endif

static APR_INLINE unsigned long modssl_runtime_lib_version(void)
{
#if MODSSL_USE_OPENSSL_PRE_1_1_API
    return SSLeay();
#else
    return OpenSSL_version_num();
#endif
}


/*
 *  Per-module initialization
 */
apr_status_t ssl_init_Module(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp,
                             server_rec *base_server)
{
    unsigned long runtime_lib_version = modssl_runtime_lib_version();
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc;
    server_rec *s;
    apr_status_t rv;
    apr_array_header_t *pphrases;

    AP_DEBUG_ASSERT(mc);

    if (runtime_lib_version < MODSSL_LIBRARY_VERSION) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(01882)
                     "Init: this version of mod_ssl was compiled against "
                     "a newer library (%s (%s), version currently loaded is 0x%lX)"
                     " - may result in undefined or erroneous behavior",
                    MODSSL_LIBRARY_TEXT, MODSSL_LIBRARY_DYNTEXT,
                    runtime_lib_version);
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

        /*
         * Create the server host:port string because we need it a lot
         */
        if (sc->vhost_id) {
            /* already set. This should only happen if this config rec is
             * shared with another server. Argh! */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10104) 
                         "%s, SSLSrvConfigRec shared from %s", 
                         ssl_util_vhostid(p, s), sc->vhost_id);
        }
        sc->vhost_id = ssl_util_vhostid(p, s);
        sc->vhost_id_len = strlen(sc->vhost_id);

        /* Default to enabled if SSLEngine is not set explicitly, and
         * the protocol is https. */
        if (ap_get_server_protocol(s) 
            && strcmp("https", ap_get_server_protocol(s)) == 0
            && sc->enabled == SSL_ENABLED_UNSET
            && (!apr_is_empty_array(sc->server->pks->cert_files))) {
            sc->enabled = SSL_ENABLED_TRUE;
        }

        /* Fix up stuff that may not have been set.  If sc->enabled is
         * UNSET, then SSL is disabled on this vhost.  */
        if (sc->enabled == SSL_ENABLED_UNSET) {
            sc->enabled = SSL_ENABLED_FALSE;
        }

        if (sc->session_cache_timeout == UNSET) {
            sc->session_cache_timeout = SSL_SESSION_CACHE_TIMEOUT;
        }

        if (sc->server && sc->server->pphrase_dialog_type == SSL_PPTYPE_UNSET) {
            sc->server->pphrase_dialog_type = SSL_PPTYPE_BUILTIN;
        }
    }

#if APR_HAS_THREADS && MODSSL_USE_OPENSSL_PRE_1_1_API
    ssl_util_thread_setup(p);
#endif

    /*
     * SSL external crypto device ("engine") support
     */
    if ((rv = ssl_init_Engine(base_server, p)) != APR_SUCCESS) {
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server, APLOGNO(01883)
                 "Init: Initialized %s library", MODSSL_LIBRARY_NAME);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     * only need ptemp here; nothing inside allocated from the pool
     * needs to live once we return from ssl_rand_seed().
     */
    ssl_rand_seed(base_server, ptemp, SSL_RSCTX_STARTUP, "Init: ");

#ifdef HAVE_FIPS
    if (!modssl_fips_is_enabled() && mc->fips == TRUE) {
        if (!modssl_fips_enable(1)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, base_server, APLOGNO(01885)
                         "Could not enable FIPS mode");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, base_server);
            return ssl_die(base_server);
        }

        apr_pool_cleanup_register(p, NULL, modssl_fips_cleanup,
                                  apr_pool_cleanup_null);
    }

    /* Log actual FIPS mode which the SSL library is operating under,
     * which may have been set outside of the mod_ssl
     * configuration. */
    if (modssl_fips_is_enabled()) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, base_server, APLOGNO(01884)
                     MODSSL_LIBRARY_NAME " has FIPS mode enabled");
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(01886)
                     MODSSL_LIBRARY_NAME " has FIPS mode disabled");
    }
#endif

    /*
     * initialize the mutex handling
     */
    if (!ssl_mutex_init(base_server, p)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#ifdef HAVE_OCSP_STAPLING
    ssl_stapling_certinfo_hash_init(p);
#endif

    /*
     * initialize session caching
     */
    if ((rv = ssl_scache_init(base_server, p)) != APR_SUCCESS) {
        return rv;
    }

    pphrases = apr_array_make(ptemp, 2, sizeof(char *));

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
        if ((rv = ssl_init_ConfigureServer(s, p, ptemp, sc, pphrases))
            != APR_SUCCESS) {
            return rv;
        }
    }

    if (pphrases->nelts > 0) {
        memset(pphrases->elts, 0, pphrases->elt_size * pphrases->nelts);
        pphrases->nelts = 0;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02560)
                     "Init: Wiped out the queried pass phrases from memory");
    }

    /*
     * Configuration consistency checks
     */
    if ((rv = ssl_init_CheckServers(base_server, ptemp)) != APR_SUCCESS) {
        return rv;
    }

    for (s = base_server; s; s = s->next) {
        SSLDirConfigRec *sdc = ap_get_module_config(s->lookup_defaults,
                                                    &ssl_module);

        sc = mySrvConfig(s);
        if (sc->enabled == SSL_ENABLED_TRUE || sc->enabled == SSL_ENABLED_OPTIONAL) {
            if ((rv = ssl_run_init_server(s, p, 0, sc->server->ssl_ctx)) != APR_SUCCESS) {
                return rv;
            }
        }

        if (sdc->proxy_enabled) {
            rv = ssl_run_init_server(s, p, 1, sdc->proxy->ssl_ctx);
            if (rv != APR_SUCCESS) {
                return rv;
            }
        }
    }

    /*
     *  Announce mod_ssl and SSL library in HTTP Server field
     *  as ``mod_ssl/X.X.X OpenSSL/X.X.X''
     */
    ssl_add_version_components(ptemp, p, base_server);

    modssl_init_app_data2_idx(); /* for modssl_get_app_data2() at request time */

#if MODSSL_USE_OPENSSL_PRE_1_1_API
    init_dh_params();
#else
    init_bio_methods();
#endif

#ifdef HAVE_OPENSSL_KEYLOG
    {
        const char *logfn = getenv("SSLKEYLOGFILE");

        if (logfn) {
            rv = apr_file_open(&mc->keylog_file, logfn,
                               APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_FOPEN_APPEND|APR_FOPEN_LARGEFILE,
                               APR_FPROT_UREAD|APR_FPROT_UWRITE,
                               mc->pPool);
            if (rv) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, s, APLOGNO(10226)
                             "Could not open log file '%s' configured via SSLKEYLOGFILE",
                             logfn);
                return rv;
            }

            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(10227)
                         "Init: Logging SSL private key material to %s", logfn);
        }
    }
#endif
    
    return OK;
}

/*
 * Support for external a Crypto Device ("engine"), usually
 * a hardware accelerator card for crypto operations.
 */
apr_status_t ssl_init_Engine(server_rec *s, apr_pool_t *p)
{
#if MODSSL_HAVE_ENGINE_API
    SSLModConfigRec *mc = myModConfig(s);
    ENGINE *e;

    if (mc->szCryptoDevice) {
        if (!(e = ENGINE_by_id(mc->szCryptoDevice))) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01888)
                         "Init: Failed to load Crypto Device API `%s'",
                         mc->szCryptoDevice);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
        }

#ifdef ENGINE_CTRL_CHIL_SET_FORKCHECK
        if (strEQ(mc->szCryptoDevice, "chil")) {
            ENGINE_ctrl(e, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
        }
#endif

        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01889)
                         "Init: Failed to enable Crypto Device API `%s'",
                         mc->szCryptoDevice);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
        }
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01890)
                     "Init: loaded Crypto Device API `%s'",
                     mc->szCryptoDevice);

        ENGINE_free(e);
    }
#endif
    return APR_SUCCESS;
}

#ifdef HAVE_TLSEXT
static apr_status_t ssl_init_ctx_tls_extensions(server_rec *s,
                                                apr_pool_t *p,
                                                apr_pool_t *ptemp,
                                                modssl_ctx_t *mctx)
{
    apr_status_t rv;

    /*
     * Configure TLS extensions support
     */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01893)
                 "Configuring TLS extension handling");

    /*
     * The Server Name Indication (SNI) provided by the ClientHello can be
     * used to select the right (name-based-)vhost and its SSL configuration
     * before the handshake takes place.
     */
    if (!SSL_CTX_set_tlsext_servername_callback(mctx->ssl_ctx,
                          ssl_callback_ServerNameIndication) ||
        !SSL_CTX_set_tlsext_servername_arg(mctx->ssl_ctx, mctx)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01894)
                     "Unable to initialize TLS servername extension "
                     "callback (incompatible OpenSSL version?)");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
    /*
     * The ClientHello callback also allows to retrieve the SNI, but since it
     * runs at the earliest possible connection stage we can even set the TLS
     * protocol version(s) according to the selected (name-based-)vhost, which
     * is not possible at the SNI callback stage (due to OpenSSL internals).
     */
    SSL_CTX_set_client_hello_cb(mctx->ssl_ctx, ssl_callback_ClientHello, NULL);
#endif

#ifdef HAVE_OCSP_STAPLING
    /*
     * OCSP Stapling support, status_request extension
     */
    if ((mctx->pkp == FALSE) && (mctx->stapling_enabled == TRUE)) {
        if ((rv = modssl_init_stapling(s, p, ptemp, mctx)) != APR_SUCCESS) {
            return rv;
        }
    }
#endif

#ifdef HAVE_SRP
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
            return ssl_die(s);
        }

        err = SRP_VBASE_init(mctx->srp_vbase, mctx->srp_vfile);
        if (err != SRP_NO_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02310)
                         "Unable to load SRP verifier file [error %d]", err);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
        }

        SSL_CTX_set_srp_username_callback(mctx->ssl_ctx,
                                          ssl_callback_SRPServerParams);
        SSL_CTX_set_srp_cb_arg(mctx->ssl_ctx, mctx);
    }
#endif
    return APR_SUCCESS;
}
#endif

static apr_status_t ssl_init_ctx_protocol(server_rec *s,
                                          apr_pool_t *p,
                                          apr_pool_t *ptemp,
                                          modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = NULL;
    MODSSL_SSL_METHOD_CONST SSL_METHOD *method = NULL;
    char *cp;
    int protocol = mctx->protocol;
    SSLSrvConfigRec *sc = mySrvConfig(s);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    int prot;
#endif

    /*
     *  Create the new per-server SSL context
     */
    if (protocol == SSL_PROTOCOL_NONE) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02231)
                "No SSL protocols available [hint: SSLProtocol]");
        return ssl_die(s);
    }

    cp = apr_pstrcat(p,
#ifndef OPENSSL_NO_SSL3
                     (protocol & SSL_PROTOCOL_SSLV3 ? "SSLv3, " : ""),
#endif
                     (protocol & SSL_PROTOCOL_TLSV1 ? "TLSv1, " : ""),
#ifdef HAVE_TLSV1_X
                     (protocol & SSL_PROTOCOL_TLSV1_1 ? "TLSv1.1, " : ""),
                     (protocol & SSL_PROTOCOL_TLSV1_2 ? "TLSv1.2, " : ""),
#if SSL_HAVE_PROTOCOL_TLSV1_3
                     (protocol & SSL_PROTOCOL_TLSV1_3 ? "TLSv1.3, " : ""),
#endif
#endif
                     NULL);
    cp[strlen(cp)-2] = NUL;

    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                 "Creating new SSL context (protocols: %s)", cp);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef OPENSSL_NO_SSL3
    if (protocol == SSL_PROTOCOL_SSLV3) {
        method = mctx->pkp ?
            SSLv3_client_method() : /* proxy */
            SSLv3_server_method();  /* server */
    }
    else
#endif
    if (protocol == SSL_PROTOCOL_TLSV1) {
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
#if SSL_HAVE_PROTOCOL_TLSV1_3
    else if (protocol == SSL_PROTOCOL_TLSV1_3) {
        method = mctx->pkp ?
            TLSv1_3_client_method() : /* proxy */
            TLSv1_3_server_method();  /* server */
    }
#endif
#endif
    else { /* For multiple protocols, we need a flexible method */
        method = mctx->pkp ?
            SSLv23_client_method() : /* proxy */
            SSLv23_server_method();  /* server */
    }
#else
    method = mctx->pkp ?
        TLS_client_method() : /* proxy */
        TLS_server_method();  /* server */
#endif
    ctx = SSL_CTX_new(method);

    mctx->ssl_ctx = ctx;

    SSL_CTX_set_options(ctx, SSL_OP_ALL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L  || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20800000L)
    /* always disable SSLv2, as per RFC 6176 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

#ifndef OPENSSL_NO_SSL3
    if (!(protocol & SSL_PROTOCOL_SSLV3)) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    }
#endif

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
#if SSL_HAVE_PROTOCOL_TLSV1_3
    ssl_set_ctx_protocol_option(s, ctx, SSL_OP_NO_TLSv1_3,
                                protocol & SSL_PROTOCOL_TLSV1_3, "TLSv1.3");
#endif
#endif

#else /* #if OPENSSL_VERSION_NUMBER < 0x10100000L */
    /* We first determine the maximum protocol version we should provide */
#if SSL_HAVE_PROTOCOL_TLSV1_3
    if (protocol & SSL_PROTOCOL_TLSV1_3) {
        prot = TLS1_3_VERSION;
    } else
#endif
    if (protocol & SSL_PROTOCOL_TLSV1_2) {
        prot = TLS1_2_VERSION;
    } else if (protocol & SSL_PROTOCOL_TLSV1_1) {
        prot = TLS1_1_VERSION;
    } else if (protocol & SSL_PROTOCOL_TLSV1) {
        prot = TLS1_VERSION;
#ifndef OPENSSL_NO_SSL3
    } else if (protocol & SSL_PROTOCOL_SSLV3) {
        prot = SSL3_VERSION;
#endif
    } else {
        SSL_CTX_free(ctx);
        mctx->ssl_ctx = NULL;
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(03378)
                "No SSL protocols available [hint: SSLProtocol]");
        return ssl_die(s);
    }
    SSL_CTX_set_max_proto_version(ctx, prot);

    /* Next we scan for the minimal protocol version we should provide,
     * but we do not allow holes between max and min */
#if SSL_HAVE_PROTOCOL_TLSV1_3
    if (prot == TLS1_3_VERSION && protocol & SSL_PROTOCOL_TLSV1_2) {
        prot = TLS1_2_VERSION;
    }
#endif
    if (prot == TLS1_2_VERSION && protocol & SSL_PROTOCOL_TLSV1_1) {
        prot = TLS1_1_VERSION;
    }
    if (prot == TLS1_1_VERSION && protocol & SSL_PROTOCOL_TLSV1) {
        prot = TLS1_VERSION;
    }
#ifndef OPENSSL_NO_SSL3
    if (prot == TLS1_VERSION && protocol & SSL_PROTOCOL_SSLV3) {
        prot = SSL3_VERSION;
    }
#endif
    SSL_CTX_set_min_proto_version(ctx, prot);
#endif /* if OPENSSL_VERSION_NUMBER < 0x10100000L */

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
#else
        sk_SSL_COMP_zero(SSL_COMP_get_compression_methods());
#endif
    }
#endif

#ifdef SSL_OP_NO_TICKET
    /*
     * Configure using RFC 5077 TLS session tickets
     * for session resumption.
     */
    if (sc->session_tickets == FALSE) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
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
#ifdef HAVE_ECC
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
#endif

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

#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    /* For OpenSSL >=1.1.1, disable auto-retry mode so it's possible
     * to consume handshake records without blocking for app-data.
     * https://github.com/openssl/openssl/issues/7178 */
    SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);
#endif

#ifdef HAVE_OPENSSL_KEYLOG
    if (mctx->sc->mc->keylog_file) {
        SSL_CTX_set_keylog_callback(ctx, modssl_callback_keylog);
    }
#endif

#ifdef SSL_OP_NO_RENEGOTIATION
    /* For server-side SSL_CTX, disable renegotiation by default.. */
    if (!mctx->pkp) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
    }
#endif

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    /* For server-side SSL_CTX, enable ignoring unexpected EOF */
    /* (OpenSSL 1.1.1 behavioural compatibility).. */
    if (!mctx->pkp) {
        SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
    }
#endif
    
    return APR_SUCCESS;
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

#ifdef SSL_OP_NO_RENEGOTIATION
/* OpenSSL-level renegotiation protection. */
#define MODSSL_BLOCKS_RENEG (0)
#else
/* mod_ssl-level renegotiation protection. */
#define MODSSL_BLOCKS_RENEG (1)
#endif

static void ssl_init_ctx_callbacks(server_rec *s,
                                   apr_pool_t *p,
                                   apr_pool_t *ptemp,
                                   modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;

#if MODSSL_USE_OPENSSL_PRE_1_1_API
    /* Note that for OpenSSL>=1.1, auto selection is enabled via
     * SSL_CTX_set_dh_auto(,1) if no parameter is configured. */
    SSL_CTX_set_tmp_dh_callback(ctx,  ssl_callback_TmpDH);
#endif

    /* The info callback is used for debug-level tracing.  For OpenSSL
     * versions where SSL_OP_NO_RENEGOTIATION is not available, the
     * callback is also used to prevent use of client-initiated
     * renegotiation.  Enable it in either case. */
    if (APLOGdebug(s) || MODSSL_BLOCKS_RENEG) {
        SSL_CTX_set_info_callback(ctx, ssl_callback_Info);
    }

#ifdef HAVE_TLS_ALPN
    SSL_CTX_set_alpn_select_cb(ctx, ssl_callback_alpn_select, NULL);
#endif
}

static APR_INLINE
int modssl_CTX_load_verify_locations(SSL_CTX *ctx,
                                     const char *file,
                                     const char *path)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!SSL_CTX_load_verify_locations(ctx, file, path))
        return 0;
#else
    if (file && !SSL_CTX_load_verify_file(ctx, file))
        return 0;
    if (path && !SSL_CTX_load_verify_dir(ctx, path))
        return 0;
#endif
    return 1;
}

static apr_status_t ssl_init_ctx_verify(server_rec *s,
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

        if (!modssl_CTX_load_verify_locations(ctx, mctx->auth.ca_cert_file,
                                                   mctx->auth.ca_cert_path)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01895)
                    "Unable to configure verify locations "
                    "for client authentication");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
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
            return ssl_die(s);
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

    return APR_SUCCESS;
}

static apr_status_t ssl_init_ctx_cipher_suite(server_rec *s,
                                              apr_pool_t *p,
                                              apr_pool_t *ptemp,
                                              modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;
    const char *suite;

    /*
     *  Configure SSL Cipher Suite. Always disable NULL and export ciphers,
     *  see also ssl_engine_config.c:ssl_cmd_SSLCipherSuite().
     *  OpenSSL's SSL_DEFAULT_CIPHER_LIST includes !aNULL:!eNULL from 0.9.8f,
     *  and !EXP from 0.9.8zf/1.0.1m/1.0.2a, so append them while we support
     *  earlier versions.
     */
    suite = mctx->auth.cipher_suite ? mctx->auth.cipher_suite :
            apr_pstrcat(ptemp, SSL_DEFAULT_CIPHER_LIST, ":!aNULL:!eNULL:!EXP",
                        NULL);

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                 "Configuring permitted SSL ciphers [%s]",
                 suite);

    if (!SSL_CTX_set_cipher_list(ctx, suite)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01898)
                "Unable to configure permitted SSL ciphers");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }
#if SSL_HAVE_PROTOCOL_TLSV1_3
    if (mctx->auth.tls13_ciphers 
        && !SSL_CTX_set_ciphersuites(ctx, mctx->auth.tls13_ciphers)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10127)
                "Unable to configure permitted TLSv1.3 ciphers");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }
#endif
    return APR_SUCCESS;
}

static APR_INLINE
int modssl_X509_STORE_load_locations(X509_STORE *store,
                                     const char *file,
                                     const char *path)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!X509_STORE_load_locations(store, file, path))
        return 0;
#else
    if (file && !X509_STORE_load_file(store, file))
        return 0;
    if (path && !X509_STORE_load_path(store, path))
        return 0;
#endif
    return 1;
}

static apr_status_t ssl_init_ctx_crl(server_rec *s,
                                     apr_pool_t *p,
                                     apr_pool_t *ptemp,
                                     modssl_ctx_t *mctx)
{
    X509_STORE *store = SSL_CTX_get_cert_store(mctx->ssl_ctx);
    unsigned long crlflags = 0;
    char *cfgp = mctx->pkp ? "SSLProxy" : "SSL";
    int crl_check_mode;

    if (mctx->ocsp_mask == UNSET) {
        mctx->ocsp_mask = SSL_OCSPCHECK_NONE;
    }

    if (mctx->crl_check_mask == UNSET) {
        mctx->crl_check_mask = SSL_CRLCHECK_NONE;
    }
    crl_check_mode = mctx->crl_check_mask & ~SSL_CRLCHECK_FLAGS;

    /*
     * Configure Certificate Revocation List (CRL) Details
     */

    if (!(mctx->crl_file || mctx->crl_path)) {
        if (crl_check_mode == SSL_CRLCHECK_LEAF ||
            crl_check_mode == SSL_CRLCHECK_CHAIN) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01899)
                         "Host %s: CRL checking has been enabled, but "
                         "neither %sCARevocationFile nor %sCARevocationPath "
                         "is configured", mctx->sc->vhost_id, cfgp, cfgp);
            return ssl_die(s);
        }
        return APR_SUCCESS;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01900)
                 "Configuring certificate revocation facility");

    if (!store || !modssl_X509_STORE_load_locations(store, mctx->crl_file,
                                                           mctx->crl_path)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01901)
                     "Host %s: unable to configure X.509 CRL storage "
                     "for certificate revocation", mctx->sc->vhost_id);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

    switch (crl_check_mode) {
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

    return APR_SUCCESS;
}

/*
 * Read a file that optionally contains the server certificate in PEM
 * format, possibly followed by a sequence of CA certificates that
 * should be sent to the peer in the SSL Certificate message.
 */
static int use_certificate_chain(
    SSL_CTX *ctx, char *file, int skipfirst, pem_password_cb *cb)
{
    BIO *bio;
    X509 *x509;
    unsigned long err;
    int n;

    if ((bio = BIO_new(BIO_s_file())) == NULL)
        return -1;
    if (BIO_read_filename(bio, file) <= 0) {
        BIO_free(bio);
        return -1;
    }
    /* optionally skip a leading server certificate */
    if (skipfirst) {
        if ((x509 = PEM_read_bio_X509(bio, NULL, cb, NULL)) == NULL) {
            BIO_free(bio);
            return -1;
        }
        X509_free(x509);
    }
    /* free a perhaps already configured extra chain */
#ifdef OPENSSL_NO_SSL_INTERN
    SSL_CTX_clear_extra_chain_certs(ctx);
#else
    if (ctx->extra_certs != NULL) {
        sk_X509_pop_free((STACK_OF(X509) *)ctx->extra_certs, X509_free);
        ctx->extra_certs = NULL;
    }
#endif

    /* create new extra chain by loading the certs */
    n = 0;
    ERR_clear_error();
    while ((x509 = PEM_read_bio_X509(bio, NULL, cb, NULL)) != NULL) {
        if (!SSL_CTX_add_extra_chain_cert(ctx, x509)) {
            X509_free(x509);
            BIO_free(bio);
            return -1;
        }
        n++;
    }
    /* Make sure that only the error is just an EOF */
    if ((err = ERR_peek_error()) > 0) {
        if (!(   ERR_GET_LIB(err) == ERR_LIB_PEM
              && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
            BIO_free(bio);
            return -1;
        }
        while (ERR_get_error() > 0) ;
    }
    BIO_free(bio);
    return n;
}

static apr_status_t ssl_init_ctx_cert_chain(server_rec *s,
                                            apr_pool_t *p,
                                            apr_pool_t *ptemp,
                                            modssl_ctx_t *mctx)
{
    BOOL skip_first = FALSE;
    int i, n;
    const char *chain = mctx->cert_chain;

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
     * to allow one to explicitly configure CA certificates which are
     * used only for the server certificate chain.
     */
    if (!chain) {
        return APR_SUCCESS;
    }

    for (i = 0; (i < mctx->pks->cert_files->nelts) &&
         APR_ARRAY_IDX(mctx->pks->cert_files, i, const char *); i++) {
        if (strEQ(APR_ARRAY_IDX(mctx->pks->cert_files, i, const char *), chain)) {
            skip_first = TRUE;
            break;
        }
    }

    n = use_certificate_chain(mctx->ssl_ctx, (char *)chain, skip_first, NULL);
    if (n < 0) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01903)
                "Failed to configure CA certificate chain!");
        return ssl_die(s);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01904)
                 "Configuring server certificate chain "
                 "(%d CA certificate%s)",
                 n, n == 1 ? "" : "s");

    return APR_SUCCESS;
}

static apr_status_t ssl_init_ctx(server_rec *s,
                                 apr_pool_t *p,
                                 apr_pool_t *ptemp,
                                 modssl_ctx_t *mctx)
{
    apr_status_t rv;

    if ((rv = ssl_init_ctx_protocol(s, p, ptemp, mctx)) != APR_SUCCESS) {
        return rv;
    }

    ssl_init_ctx_session_cache(s, p, ptemp, mctx);

    ssl_init_ctx_callbacks(s, p, ptemp, mctx);

    if ((rv = ssl_init_ctx_verify(s, p, ptemp, mctx)) != APR_SUCCESS) {
        return rv;
    }

    if ((rv = ssl_init_ctx_cipher_suite(s, p, ptemp, mctx)) != APR_SUCCESS) {
        return rv;
    }

    if ((rv = ssl_init_ctx_crl(s, p, ptemp, mctx)) != APR_SUCCESS) {
        return rv;
    }

    if (mctx->pks) {
        /* XXX: proxy support? */
        if ((rv = ssl_init_ctx_cert_chain(s, p, ptemp, mctx)) != APR_SUCCESS) {
            return rv;
        }
#ifdef HAVE_TLSEXT
        if ((rv = ssl_init_ctx_tls_extensions(s, p, ptemp, mctx)) !=
            APR_SUCCESS) {
            return rv;
        }
#endif
    }

    return APR_SUCCESS;
}

static void ssl_check_public_cert(server_rec *s,
                                  apr_pool_t *ptemp,
                                  X509 *cert,
                                  const char *key_id)
{
    int is_ca, pathlen;

    if (!cert) {
        return;
    }

    /*
     * Some information about the certificate(s)
     */

    if (modssl_X509_getBC(cert, &is_ca, &pathlen)) {
        if (is_ca) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01906)
                         "%s server certificate is a CA certificate "
                         "(BasicConstraints: CA == TRUE !?)", key_id);
        }

        if (pathlen > 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01907)
                         "%s server certificate is not a leaf certificate "
                         "(BasicConstraints: pathlen == %d > 0 !?)",
                         key_id, pathlen);
        }
    }

    if (modssl_X509_match_name(ptemp, cert, (const char *)s->server_hostname,
                               TRUE, s) == FALSE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(01909)
                     "%s server certificate does NOT include an ID "
                     "which matches the server name", key_id);
    }
}

/* prevent OpenSSL from showing its "Enter PEM pass phrase:" prompt */
static int ssl_no_passwd_prompt_cb(char *buf, int size, int rwflag,
                                   void *userdata) {
   return 0;
}

/* SSL_CTX_use_PrivateKey_file() can fail either because the private
 * key was encrypted, or due to a mismatch between an already-loaded
 * cert and the key - a common misconfiguration - from calling
 * X509_check_private_key().  This macro is passed the last error code
 * off the OpenSSL stack and evaluates to true only for the first
 * case.  With OpenSSL < 3 the second case is identifiable by the
 * function code, but function codes are not used from 3.0. */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define CHECK_PRIVKEY_ERROR(ec) (ERR_GET_FUNC(ec) != X509_F_X509_CHECK_PRIVATE_KEY)
#else
#define CHECK_PRIVKEY_ERROR(ec) (ERR_GET_LIB(ec) != ERR_LIB_X509            \
                                 || (ERR_GET_REASON(ec) != X509_R_KEY_TYPE_MISMATCH \
                                     && ERR_GET_REASON(ec) != X509_R_KEY_VALUES_MISMATCH \
                                     && ERR_GET_REASON(ec) != X509_R_UNKNOWN_KEY_TYPE))
#endif

static apr_status_t ssl_init_server_certs(server_rec *s,
                                          apr_pool_t *p,
                                          apr_pool_t *ptemp,
                                          modssl_ctx_t *mctx,
                                          apr_array_header_t *pphrases)
{
    SSLModConfigRec *mc = myModConfig(s);
    const char *vhost_id = mctx->sc->vhost_id, *key_id, *certfile, *keyfile;
    int i;
    EVP_PKEY *pkey;
    int custom_dh_done = 0;
#ifdef HAVE_ECC
    EC_GROUP *ecgroup = NULL;
    int curve_nid = 0;
#endif

    /* no OpenSSL default prompts for any of the SSL_CTX_use_* calls, please */
    SSL_CTX_set_default_passwd_cb(mctx->ssl_ctx, ssl_no_passwd_prompt_cb);

    /* Iterate over the SSLCertificateFile array */
    for (i = 0; (i < mctx->pks->cert_files->nelts) &&
                (certfile = APR_ARRAY_IDX(mctx->pks->cert_files, i,
                                          const char *));
         i++) {
        X509 *cert = NULL;
        const char *engine_certfile = NULL;

        key_id = apr_psprintf(ptemp, "%s:%d", vhost_id, i);

        ERR_clear_error();

        /* first the certificate (public key) */
        if (modssl_is_engine_id(certfile)) {
            engine_certfile = certfile;
        }
        else if (mctx->cert_chain) {
            if ((SSL_CTX_use_certificate_file(mctx->ssl_ctx, certfile,
                                              SSL_FILETYPE_PEM) < 1)) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02561)
                             "Failed to configure certificate %s, check %s",
                             key_id, certfile);
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
                return APR_EGENERAL;
            }
        } else {
            if ((SSL_CTX_use_certificate_chain_file(mctx->ssl_ctx,
                                                    certfile) < 1)) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02562)
                             "Failed to configure certificate %s (with chain),"
                             " check %s", key_id, certfile);
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
                return APR_EGENERAL;
            }
        }

        /* and second, the private key */
        if (i < mctx->pks->key_files->nelts) {
            keyfile = APR_ARRAY_IDX(mctx->pks->key_files, i, const char *);
        } else {
            keyfile = certfile;
        }

        ERR_clear_error();

        if (modssl_is_engine_id(keyfile)) {
            apr_status_t rv;

            if ((rv = modssl_load_engine_keypair(s, p, ptemp, vhost_id,
                                                 engine_certfile, keyfile,
                                                 &cert, &pkey))) {
                return rv;
            }

            if (cert) {
                if (SSL_CTX_use_certificate(mctx->ssl_ctx, cert) < 1) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10137)
                                 "Failed to configure certificate %s from %s, check %s",
                                 key_id, mc->szCryptoDevice ?
                                             mc->szCryptoDevice : "provider",
                                 certfile);
                    ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
                    return APR_EGENERAL;
                }

                /* SSL_CTX now owns the cert. */
                X509_free(cert);
            }                    
            
            if (SSL_CTX_use_PrivateKey(mctx->ssl_ctx, pkey) < 1) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10130)
                             "Failed to configure private key %s from %s",
                             keyfile, mc->szCryptoDevice ?
                                          mc->szCryptoDevice : "provider");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
                return APR_EGENERAL;
            }

            /* SSL_CTX now owns the key */
            EVP_PKEY_free(pkey);
        }
        else if ((SSL_CTX_use_PrivateKey_file(mctx->ssl_ctx, keyfile,
                                              SSL_FILETYPE_PEM) < 1)
                 && CHECK_PRIVKEY_ERROR(ERR_peek_last_error())) {
            ssl_asn1_t *asn1;
            const unsigned char *ptr;

            ERR_clear_error();

            /* perhaps it's an encrypted private key, so try again */
            ssl_load_encrypted_pkey(s, ptemp, i, keyfile, &pphrases);

            if (!(asn1 = ssl_asn1_table_get(mc->tPrivateKey, key_id)) ||
                !(ptr = asn1->cpData) ||
                !(pkey = d2i_AutoPrivateKey(NULL, &ptr, asn1->nData)) ||
                (SSL_CTX_use_PrivateKey(mctx->ssl_ctx, pkey) < 1)) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02564)
                             "Failed to configure encrypted (?) private key %s,"
                             " check %s", key_id, keyfile);
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
                return APR_EGENERAL;
            }
        }

        if (SSL_CTX_check_private_key(mctx->ssl_ctx) < 1) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02565)
                         "Certificate and private key %s from %s and %s "
                         "do not match", key_id, certfile, keyfile);
            return APR_EGENERAL;
        }

#ifdef HAVE_SSL_CONF_CMD
        /* 
         * workaround for those OpenSSL versions where SSL_CTX_get0_certificate
         * is not yet available: create an SSL struct which we dispose of
         * as soon as we no longer need access to the cert. (Strictly speaking,
         * SSL_CTX_get0_certificate does not depend on the SSL_CONF stuff,
         * but there's no reliable way to check for its existence, so we
         * assume that if SSL_CONF is available, it's OpenSSL 1.0.2 or later,
         * and SSL_CTX_get0_certificate is implemented.)
         */
        cert = SSL_CTX_get0_certificate(mctx->ssl_ctx);
#else
        {
            SSL *ssl = SSL_new(mctx->ssl_ctx);
            if (ssl) {
                /* Workaround bug in SSL_get_certificate in OpenSSL 0.9.8y */
                SSL_set_connect_state(ssl);
                cert = SSL_get_certificate(ssl);
                SSL_free(ssl);
            }
        }
#endif
        if (!cert) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02566)
                         "Unable to retrieve certificate %s", key_id);
            return APR_EGENERAL;
        }

        /* warn about potential cert issues */
        ssl_check_public_cert(s, ptemp, cert, key_id);

#if defined(HAVE_OCSP_STAPLING) && !defined(SSL_CTRL_SET_CURRENT_CERT)
        /* 
         * OpenSSL up to 1.0.1: configure stapling as we go. In 1.0.2
         * and later, there's SSL_CTX_set_current_cert, which allows
         * iterating over all certs in an SSL_CTX (including those possibly
         * loaded via SSLOpenSSLConfCmd Certificate), so for 1.0.2 and
         * later, we defer to the code in ssl_init_server_ctx.
         */
        if (!ssl_stapling_init_cert(s, p, ptemp, mctx, cert)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02567)
                         "Unable to configure certificate %s for stapling",
                         key_id);
        }
#endif

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02568)
                     "Certificate and private key %s configured from %s and %s",
                     key_id, certfile, keyfile);
    }

    /*
     * Try to read DH parameters from the (first) SSLCertificateFile
     */
    certfile = APR_ARRAY_IDX(mctx->pks->cert_files, 0, const char *);
    if (certfile && !modssl_is_engine_id(certfile)) {
        int num_bits = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        DH *dh = modssl_dh_from_file(certfile);
        if (dh) {
            num_bits = DH_bits(dh);
            SSL_CTX_set_tmp_dh(mctx->ssl_ctx, dh);
            DH_free(dh);
            custom_dh_done = 1;
        }
#else
        pkey = modssl_dh_pkey_from_file(certfile);
        if (pkey) {
            num_bits = EVP_PKEY_get_bits(pkey);
            if (!SSL_CTX_set0_tmp_dh_pkey(mctx->ssl_ctx, pkey)) {
                EVP_PKEY_free(pkey);
            }
            else {
                custom_dh_done = 1;
            }
        }
#endif
        if (custom_dh_done) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02540)
                         "Custom DH parameters (%d bits) for %s loaded from %s",
                         num_bits, vhost_id, certfile);
        }
    }
#if !MODSSL_USE_OPENSSL_PRE_1_1_API
    if (!custom_dh_done) {
        /* If no parameter is manually configured, enable auto
         * selection. */
        SSL_CTX_set_dh_auto(mctx->ssl_ctx, 1);
    }
#endif

#ifdef HAVE_ECC
    /*
     * Similarly, try to read the ECDH curve name from SSLCertificateFile...
     */
    if (certfile && !modssl_is_engine_id(certfile)
        && (ecgroup = modssl_ec_group_from_file(certfile))
        && (curve_nid = EC_GROUP_get_curve_name(ecgroup))) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        EC_KEY *eckey = EC_KEY_new_by_curve_name(curve_nid);
        if (eckey) {
            SSL_CTX_set_tmp_ecdh(mctx->ssl_ctx, eckey);
            EC_KEY_free(eckey);
        }
        else {
            curve_nid = 0;
        }
#else
        if (!SSL_CTX_set1_curves(mctx->ssl_ctx, &curve_nid, 1)) {
            curve_nid = 0;
        }
#endif
        if (curve_nid) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02541)
                         "ECDH curve %s for %s specified in %s",
                         OBJ_nid2sn(curve_nid), vhost_id, certfile);
        }
    }
    /*
     * ...otherwise, enable auto curve selection (OpenSSL 1.0.2)
     * or configure NIST P-256 (required to enable ECDHE for earlier versions)
     * ECDH is always enabled in 1.1.0 unless excluded from SSLCipherList
     */
#if MODSSL_USE_OPENSSL_PRE_1_1_API
    if (!curve_nid) {
#if defined(SSL_CTX_set_ecdh_auto)
        SSL_CTX_set_ecdh_auto(mctx->ssl_ctx, 1);
#else
        EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (eckey) {
            SSL_CTX_set_tmp_ecdh(mctx->ssl_ctx, eckey);
            EC_KEY_free(eckey);
        }
#endif
    }
#endif
    /* OpenSSL assures us that _free() is NULL-safe */
    EC_GROUP_free(ecgroup);
#endif

    return APR_SUCCESS;
}

#ifdef HAVE_TLS_SESSION_TICKETS
static apr_status_t ssl_init_ticket_key(server_rec *s,
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
    int res;

    if (!ticket_key->file_path) {
        return APR_SUCCESS;
    }

    path = ap_server_root_relative(p, ticket_key->file_path);

    rv = apr_file_open(&fp, path, APR_READ|APR_BINARY,
                       APR_OS_DEFAULT, ptemp);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02286)
                     "Failed to open ticket key file %s: (%d) %pm",
                     path, rv, &rv);
        return ssl_die(s);
    }

    rv = apr_file_read_full(fp, &buf[0], TLSEXT_TICKET_KEY_LEN, &len);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02287)
                     "Failed to read %d bytes from %s: (%d) %pm",
                     TLSEXT_TICKET_KEY_LEN, path, rv, &rv);
        return ssl_die(s);
    }

    memcpy(ticket_key->key_name, buf, 16);
    memcpy(ticket_key->aes_key, buf + 32, 16);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    memcpy(ticket_key->hmac_secret, buf + 16, 16);
    res = SSL_CTX_set_tlsext_ticket_key_cb(mctx->ssl_ctx,
                                           ssl_callback_SessionTicket);
#else
    ticket_key->mac_params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, buf + 16, 16);
    ticket_key->mac_params[1] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "sha256", 0);
    ticket_key->mac_params[2] =
        OSSL_PARAM_construct_end();
    res = SSL_CTX_set_tlsext_ticket_key_evp_cb(mctx->ssl_ctx,
                                               ssl_callback_SessionTicket);
#endif
    if (!res) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01913)
                     "Unable to initialize TLS session ticket key callback "
                     "(incompatible OpenSSL version?)");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02288)
                 "TLS session ticket key for %s successfully loaded from %s",
                 (mySrvConfig(s))->vhost_id, path);

    return APR_SUCCESS;
}
#endif

static BOOL load_x509_info(apr_pool_t *ptemp,
                           STACK_OF(X509_INFO) *sk,
                           const char *filename)
{
    BIO *in;

    if (!(in = BIO_new(BIO_s_file()))) {
        return FALSE;
    }

    if (BIO_read_filename(in, filename) <= 0) {
        BIO_free(in);
        return FALSE;
    }

    ERR_clear_error();

    PEM_X509_INFO_read_bio(in, sk, NULL, NULL);

    BIO_free(in);

    return TRUE;
}

static apr_status_t ssl_init_proxy_certs(server_rec *s,
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
    int addl_chain = 0; /* non-zero if additional chain certs were
                         * added to store */

    ap_assert(store != NULL); /* safe to assume always non-NULL? */

#if OPENSSL_VERSION_NUMBER >= 0x1010100fL && !defined(LIBRESSL_VERSION_NUMBER)
    /* For OpenSSL >=1.1.1, turn on client cert support which is
     * otherwise turned off by default (by design).
     * https://github.com/openssl/openssl/issues/6933 */
    SSL_CTX_set_post_handshake_auth(mctx->ssl_ctx, 1);
#endif
    
    SSL_CTX_set_client_cert_cb(mctx->ssl_ctx,
                               ssl_callback_proxy_cert);

    if (!(pkp->cert_file || pkp->cert_path)) {
        return APR_SUCCESS;
    }

    sk = sk_X509_INFO_new_null();

    if (pkp->cert_file) {
        load_x509_info(ptemp, sk, pkp->cert_file);
    }

    if (pkp->cert_path) {
        ssl_init_ca_cert_path(s, ptemp, pkp->cert_path, NULL, sk);
    }

    /* Check that all client certs have got certificates and private
     * keys.  Note the number of certs in the stack may decrease
     * during the loop. */
    for (n = 0; n < sk_X509_INFO_num(sk); n++) {
        X509_INFO *inf = sk_X509_INFO_value(sk, n);
        int has_privkey = inf->x_pkey && inf->x_pkey->dec_pkey;

        /* For a lone certificate in the file, trust it as a
         * CA/intermediate certificate. */
        if (inf->x509 && !has_privkey && !inf->enc_data) {
            ssl_log_xerror(SSLLOG_MARK, APLOG_DEBUG, 0, ptemp, s, inf->x509,
                           APLOGNO(10261) "Trusting non-leaf certificate");
            X509_STORE_add_cert(store, inf->x509); /* increments inf->x509 */
            /* Delete from the stack and iterate again. */
            X509_INFO_free(inf);
            sk_X509_INFO_delete(sk, n);
            n--;
            addl_chain = 1;
            continue;
        }

        if (!has_privkey || inf->enc_data) {
            sk_X509_INFO_free(sk);
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, s, APLOGNO(02252)
                         "incomplete client cert configured for SSL proxy "
                         "(missing or encrypted private key?)");
            return ssl_die(s);
        }
        
        if (X509_check_private_key(inf->x509, inf->x_pkey->dec_pkey) != 1) {
            ssl_log_xerror(SSLLOG_MARK, APLOG_STARTUP, 0, ptemp, s, inf->x509,
                           APLOGNO(02326) "proxy client certificate and "
                           "private key do not match");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            return ssl_die(s);
        }
    }

    if ((ncerts = sk_X509_INFO_num(sk)) <= 0) {
        sk_X509_INFO_free(sk);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02206)
                     "no client certs found for SSL proxy");
        return APR_SUCCESS;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02207)
                 "loaded %d client certs for SSL proxy",
                 ncerts);
    pkp->certs = sk;

    /* If any chain certs are configured, build the ->ca_certs chains
     * corresponding to the loaded keypairs. */
    if (!pkp->ca_cert_file && !addl_chain) {
        return APR_SUCCESS;
    }

    /* If SSLProxyMachineCertificateChainFile is configured, load all
     * the CA certs and have OpenSSL attempt to construct a full chain
     * from each configured end-entity cert up to a root.  This will
     * allow selection of the correct cert given a list of root CA
     * names in the certificate request from the server.  */
    pkp->ca_certs = (STACK_OF(X509) **) apr_pcalloc(p, ncerts * sizeof(sk));
    sctx = X509_STORE_CTX_new();

    if (!sctx) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02208)
                     "SSL proxy client cert initialization failed");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        sk_X509_INFO_free(sk);
        return ssl_die(s);
    }

    modssl_X509_STORE_load_locations(store, pkp->ca_cert_file, NULL);

    for (n = 0; n < ncerts; n++) {
        int i;

        X509_INFO *inf = sk_X509_INFO_value(pkp->certs, n);
        if (!X509_STORE_CTX_init(sctx, store, inf->x509, NULL)) {
            sk_X509_INFO_free(sk);
            X509_STORE_CTX_free(sctx);
            return ssl_die(s);
        }

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
                                   sk_X509_value(chain, j), APLOGNO(03039)
                                   "%i:", j);
                }
            }
        }

        /* get ready for next X509_STORE_CTX_init */
        X509_STORE_CTX_cleanup(sctx);
    }

    X509_STORE_CTX_free(sctx);

    return APR_SUCCESS;
}

#define MODSSL_CFG_ITEM_FREE(func, item) \
    if (item) { \
        func(item); \
        item = NULL; \
    }

static void ssl_init_ctx_cleanup(modssl_ctx_t *mctx)
{
    MODSSL_CFG_ITEM_FREE(SSL_CTX_free, mctx->ssl_ctx);

#ifdef HAVE_SRP
    if (mctx->srp_vbase != NULL) {
        SRP_VBASE_free(mctx->srp_vbase);
        mctx->srp_vbase = NULL;
    }
#endif
}

static apr_status_t ssl_cleanup_proxy_ctx(void *data)
{
    modssl_ctx_t *mctx = data;

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

    return APR_SUCCESS;
}

static apr_status_t ssl_init_proxy_ctx(server_rec *s,
                                       apr_pool_t *p,
                                       apr_pool_t *ptemp,
                                       modssl_ctx_t *proxy)
{
    apr_status_t rv;

    if (proxy->ssl_ctx) {
        /* Merged/initialized already */
        return APR_SUCCESS;
    }

    apr_pool_cleanup_register(p, proxy,
                              ssl_cleanup_proxy_ctx,
                              apr_pool_cleanup_null);

    if ((rv = ssl_init_ctx(s, p, ptemp, proxy)) != APR_SUCCESS) {
        return rv;
    }

    if ((rv = ssl_init_proxy_certs(s, p, ptemp, proxy)) != APR_SUCCESS) {
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_init_server_ctx(server_rec *s,
                                        apr_pool_t *p,
                                        apr_pool_t *ptemp,
                                        SSLSrvConfigRec *sc,
                                        apr_array_header_t *pphrases)
{
    apr_status_t rv;
    modssl_pk_server_t *pks;
#ifdef HAVE_SSL_CONF_CMD
    ssl_ctx_param_t *param = (ssl_ctx_param_t *)sc->server->ssl_ctx_param->elts;
    SSL_CONF_CTX *cctx = sc->server->ssl_ctx_config;
    int i;
#endif
    int n;

    /*
     *  Check for problematic re-initializations
     */
    if (sc->server->ssl_ctx) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02569)
                     "Illegal attempt to re-initialise SSL for server "
                     "(SSLEngine On should go in the VirtualHost, not in global scope.)");
        return APR_EGENERAL;
    }

    /* Allow others to provide certificate files */
    pks = sc->server->pks;
    n = pks->cert_files->nelts;
    ap_ssl_add_cert_files(s, p, pks->cert_files, pks->key_files);
    ssl_run_add_cert_files(s, p, pks->cert_files, pks->key_files);

    if (apr_is_empty_array(pks->cert_files)) {
        /* does someone propose a certiciate to fall back on here? */
        ap_ssl_add_fallback_cert_files(s, p, pks->cert_files, pks->key_files);
        ssl_run_add_fallback_cert_files(s, p, pks->cert_files, pks->key_files);
        if (n < pks->cert_files->nelts) {
            pks->service_unavailable = 1;
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10085)
                         "Init: %s will respond with '503 Service Unavailable' for now. There "
                         "are no SSL certificates configured and no other module contributed any.",
                         ssl_util_vhostid(p, s));
        }
    }
    
    if (n < pks->cert_files->nelts) {
        /* additionally installed certs overrides any old chain configuration */
        sc->server->cert_chain = NULL;
    }
    
    if ((rv = ssl_init_ctx(s, p, ptemp, sc->server)) != APR_SUCCESS) {
        return rv;
    }

    if ((rv = ssl_init_server_certs(s, p, ptemp, sc->server, pphrases))
        != APR_SUCCESS) {
        return rv;
    }

#ifdef HAVE_SSL_CONF_CMD
    SSL_CONF_CTX_set_ssl_ctx(cctx, sc->server->ssl_ctx);
    for (i = 0; i < sc->server->ssl_ctx_param->nelts; i++, param++) {
        ERR_clear_error();
        if (SSL_CONF_cmd(cctx, param->name, param->value) <= 0) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02407)
                         "\"SSLOpenSSLConfCmd %s %s\" failed for %s",
                         param->name, param->value, sc->vhost_id);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02556)
                         "\"SSLOpenSSLConfCmd %s %s\" applied to %s",
                         param->name, param->value, sc->vhost_id);
        }
    }

    if (SSL_CONF_CTX_finish(cctx) == 0) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02547)
                         "SSL_CONF_CTX_finish() failed");
            SSL_CONF_CTX_free(cctx);
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
            return ssl_die(s);
    }
#endif

    if (SSL_CTX_check_private_key(sc->server->ssl_ctx) != 1) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02572)
                     "Failed to configure at least one certificate and key "
                     "for %s", sc->vhost_id);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_EMERG, s);
        return ssl_die(s);
    }

#if defined(HAVE_OCSP_STAPLING) && defined(SSL_CTRL_SET_CURRENT_CERT)
    /*
     * OpenSSL 1.0.2 and later allows iterating over all SSL_CTX certs
     * by means of SSL_CTX_set_current_cert. Enabling stapling at this
     * (late) point makes sure that we catch both certificates loaded
     * via SSLCertificateFile and SSLOpenSSLConfCmd Certificate.
     */
    do {
        X509 *cert;
        int i = 0;
        int ret = SSL_CTX_set_current_cert(sc->server->ssl_ctx,
                                           SSL_CERT_SET_FIRST);
        while (ret) {
            cert = SSL_CTX_get0_certificate(sc->server->ssl_ctx);
            if (!cert || !ssl_stapling_init_cert(s, p, ptemp, sc->server,
                                                 cert)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02604)
                             "Unable to configure certificate %s:%d "
                             "for stapling", sc->vhost_id, i);
            }
            ret = SSL_CTX_set_current_cert(sc->server->ssl_ctx,
                                           SSL_CERT_SET_NEXT);
            i++;
        }
    } while(0);
#endif

#ifdef HAVE_TLS_SESSION_TICKETS
    if ((rv = ssl_init_ticket_key(s, p, ptemp, sc->server)) != APR_SUCCESS) {
        return rv;
    }
#endif

    SSL_CTX_set_timeout(sc->server->ssl_ctx,
                        sc->session_cache_timeout == UNSET ?
                        SSL_SESSION_CACHE_TIMEOUT : sc->session_cache_timeout);

    return APR_SUCCESS;
}

/*
 * Configure a particular server
 */
apr_status_t ssl_init_ConfigureServer(server_rec *s,
                                      apr_pool_t *p,
                                      apr_pool_t *ptemp,
                                      SSLSrvConfigRec *sc,
                                      apr_array_header_t *pphrases)
{
    SSLDirConfigRec *sdc = ap_get_module_config(s->lookup_defaults,
                                                &ssl_module);
    apr_status_t rv;

    /* Initialize the server if SSL is enabled or optional.
     */
    if ((sc->enabled == SSL_ENABLED_TRUE) || (sc->enabled == SSL_ENABLED_OPTIONAL)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01914)
                     "Configuring server %s for SSL protocol", sc->vhost_id);
        if ((rv = ssl_init_server_ctx(s, p, ptemp, sc, pphrases))
            != APR_SUCCESS) {
            return rv;
        }

	/* Initialize OCSP Responder certificate if OCSP enabled */
	#ifndef OPENSSL_NO_OCSP
        	ssl_init_ocsp_certificates(s, sc->server);
	#endif

    }

    sdc->proxy->sc = sc;
    if (sdc->proxy_enabled == TRUE) {
        rv = ssl_init_proxy_ctx(s, p, ptemp, sdc->proxy);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    else {
        sdc->proxy_enabled = FALSE;
    }
    sdc->proxy_post_config = 1;

    return APR_SUCCESS;
}

apr_status_t ssl_init_CheckServers(server_rec *base_server, apr_pool_t *p)
{
    server_rec *s;
    SSLSrvConfigRec *sc;
#ifndef HAVE_TLSEXT
    server_rec *ps;
    apr_hash_t *table;
    const char *key;
    apr_ssize_t klen;

    BOOL conflict = FALSE;
#endif

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

#ifndef HAVE_TLSEXT
    /*
     * Give out warnings when more than one SSL-aware virtual server uses the
     * same IP:port and an OpenSSL version without support for TLS extensions
     * (SNI in particular) is used.
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
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(02662)
                         "Init: SSL server IP/port conflict: "
                         "%s (%s:%d) vs. %s (%s:%d)",
                         ssl_util_vhostid(p, s),
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
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(01917)
                     "Init: Name-based SSL virtual hosts require "
                     "an OpenSSL version with support for TLS extensions "
                     "(RFC 6066 - Server Name Indication / SNI), "
                     "but the currently used library version (%s) is "
                     "lacking this feature", MODSSL_LIBRARY_DYNTEXT);
    }
#endif

    return APR_SUCCESS;
}

int ssl_proxy_section_post_config(apr_pool_t *p, apr_pool_t *plog,
                                  apr_pool_t *ptemp, server_rec *s,
                                  ap_conf_vector_t *section_config)
{
    SSLDirConfigRec *sdc = ap_get_module_config(s->lookup_defaults,
                                                &ssl_module);
    SSLDirConfigRec *pdc = ap_get_module_config(section_config,
                                                &ssl_module);
    if (pdc) {
        pdc->proxy->sc = mySrvConfig(s);
        ssl_config_proxy_merge(p, sdc, pdc);
        if (pdc->proxy_enabled) {
            apr_status_t rv;

            rv = ssl_init_proxy_ctx(s, p, ptemp, pdc->proxy);
            if (rv != APR_SUCCESS) {
                return !OK;
            }

            rv = ssl_run_init_server(s, p, 1, pdc->proxy->ssl_ctx);
            if (rv != APR_SUCCESS) {
                return !OK;
            }
        }
        pdc->proxy_post_config = 1;
    }
    return OK;
}

static apr_status_t ssl_init_ca_cert_path(server_rec *s,
                                          apr_pool_t *ptemp,
                                          const char *path,
                                          STACK_OF(X509_NAME) *ca_list,
                                          STACK_OF(X509_INFO) *xi_list)
{
    apr_dir_t *dir;
    apr_finfo_t direntry;
    apr_int32_t finfo_flags = APR_FINFO_TYPE|APR_FINFO_NAME;

    if (!path || (!ca_list && !xi_list) ||
        (apr_dir_open(&dir, path, ptemp) != APR_SUCCESS)) {
        return APR_EGENERAL;
    }

    while ((apr_dir_read(&direntry, finfo_flags, dir)) == APR_SUCCESS) {
        const char *file;
        if (direntry.filetype == APR_DIR) {
            continue; /* don't try to load directories */
        }
        file = apr_pstrcat(ptemp, path, "/", direntry.name, NULL);
        if (ca_list) {
            SSL_add_file_cert_subjects_to_stack(ca_list, file);
        }
        if (xi_list) {
            load_x509_info(ptemp, xi_list, file);
        }
    }

    apr_dir_close(dir);

    return APR_SUCCESS;
}

STACK_OF(X509_NAME) *ssl_init_FindCAList(server_rec *s,
                                         apr_pool_t *ptemp,
                                         const char *ca_file,
                                         const char *ca_path)
{
    STACK_OF(X509_NAME) *ca_list = sk_X509_NAME_new_null();;

    /*
     * Process CA certificate bundle file
     */
    if (ca_file) {
        SSL_add_file_cert_subjects_to_stack(ca_list, ca_file);
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
    if (ca_path &&
        ssl_init_ca_cert_path(s, ptemp,
                              ca_path, ca_list, NULL) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02211)
                     "Failed to open Certificate Path `%s'", ca_path);
        sk_X509_NAME_pop_free(ca_list, X509_NAME_free);
        return NULL;
    }

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
     * Free the non-pool allocated structures
     * in the per-server configurations
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        ssl_init_ctx_cleanup(sc->server);

	/* Not Sure but possibly clear X509 trusted cert file */
	#ifndef OPENSSL_NO_OCSP
		sk_X509_pop_free(sc->server->ocsp_certs, X509_free);
	#endif

    }

#if MODSSL_USE_OPENSSL_PRE_1_1_API
    free_dh_params();
#else
    free_bio_methods();
#endif

    return APR_SUCCESS;
}
