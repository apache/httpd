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
 *  mod_ssl.c
 *  Apache API interface structures
 */

#include "ssl_private.h"

#include "util_md5.h"
#include "util_mutex.h"
#include "ap_provider.h"
#include "http_config.h"

#include "mod_proxy.h" /* for proxy_hook_section_post_config() */

#include <assert.h>

static int modssl_running_statically = 0;

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, pre_handshake,
                                    (conn_rec *c,SSL *ssl,int is_proxy),
                                    (c,ssl,is_proxy), OK, DECLINED);

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|OR_AUTHCFG, desc),

#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF, desc),

#define SSL_CMD_PXY(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|PROXY_CONF, desc),

#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, OR_##type, desc),

#define AP_END_CMD { NULL }

static const command_rec ssl_config_cmds[] = {
    /*
     * Global (main-server) context configuration directives
     */
    SSL_CMD_SRV(PassPhraseDialog, TAKE1,
                "SSL dialog mechanism for the pass phrase query "
                "('builtin', '|/path/to/pipe_program', "
                "or 'exec:/path/to/cgi_program')")
    SSL_CMD_SRV(SessionCache, TAKE1,
                "SSL Session Cache storage "
                "('none', 'nonenotnull', 'dbm:/path/to/file')")
    SSL_CMD_SRV(CryptoDevice, TAKE1,
                "SSL external Crypto Device usage "
                "('builtin', '...')")
    SSL_CMD_SRV(RandomSeed, TAKE23,
                "SSL Pseudo Random Number Generator (PRNG) seeding source "
                "('startup|connect builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, TAKE1,
                "SSL switch for the protocol engine "
                "('on', 'off')")
    SSL_CMD_SRV(FIPS, FLAG,
                "Enable FIPS-140 mode "
                "(`on', `off')")
    SSL_CMD_ALL(CipherSuite, TAKE12,
                "Colon-delimited list of permitted SSL Ciphers, optional preceded "
                "by protocol identifier ('XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(CertificateFile, TAKE1,
                "SSL Server Certificate file "
                "('/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateKeyFile, TAKE1,
                "SSL Server Private Key file "
                "('/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateChainFile, TAKE1,
                "SSL Server CA Certificate Chain file "
                "('/path/to/file' - PEM encoded)")
#ifdef HAVE_TLS_SESSION_TICKETS
    SSL_CMD_SRV(SessionTicketKeyFile, TAKE1,
                "TLS session ticket encryption/decryption key file (RFC 5077) "
                "('/path/to/file' - file with 48 bytes of random data)")
#endif
    SSL_CMD_ALL(CACertificatePath, TAKE1,
                "SSL CA Certificate path "
                "('/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_ALL(CACertificateFile, TAKE1,
                "SSL CA Certificate file "
                "('/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(CADNRequestPath, TAKE1,
                "SSL CA Distinguished Name path "
                "('/path/to/dir' - symlink hashes to PEM of acceptable CA names to request)")
    SSL_CMD_SRV(CADNRequestFile, TAKE1,
                "SSL CA Distinguished Name file "
                "('/path/to/file' - PEM encoded to derive acceptable CA names to request)")
    SSL_CMD_SRV(CARevocationPath, TAKE1,
                "SSL CA Certificate Revocation List (CRL) path "
                "('/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(CARevocationFile, TAKE1,
                "SSL CA Certificate Revocation List (CRL) file "
                "('/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(CARevocationCheck, RAW_ARGS,
                "SSL CA Certificate Revocation List (CRL) checking mode")
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client verify type "
                "('none', 'optional', 'require', 'optional_no_ca')")
    SSL_CMD_ALL(VerifyDepth, TAKE1,
                "SSL Client verify depth "
                "('N' - number of intermediate certificates)")
    SSL_CMD_SRV(SessionCacheTimeout, TAKE1,
                "SSL Session Cache object lifetime "
                "('N' - number of seconds)")
#ifdef OPENSSL_NO_SSL3
#define SSLv3_PROTO_PREFIX ""
#else
#define SSLv3_PROTO_PREFIX "SSLv3|"
#endif
#ifdef HAVE_TLSV1_X
#define SSL_PROTOCOLS SSLv3_PROTO_PREFIX "TLSv1|TLSv1.1|TLSv1.2"
#else
#define SSL_PROTOCOLS SSLv3_PROTO_PREFIX "TLSv1"
#endif
    SSL_CMD_SRV(Protocol, RAW_ARGS,
                "Enable or disable various SSL protocols "
                "('[+-][" SSL_PROTOCOLS "] ...' - see manual)")
    SSL_CMD_SRV(HonorCipherOrder, FLAG,
                "Use the server's cipher ordering preference")
    SSL_CMD_SRV(Compression, FLAG,
                "Enable SSL level compression "
                "(`on', `off')")
    SSL_CMD_SRV(SessionTickets, FLAG,
                "Enable or disable TLS session tickets"
                "(`on', `off')")
    SSL_CMD_SRV(InsecureRenegotiation, FLAG,
                "Enable support for insecure renegotiation")
    SSL_CMD_ALL(UserName, TAKE1,
                "Set user name to SSL variable value")
    SSL_CMD_SRV(StrictSNIVHostCheck, FLAG,
                "Strict SNI virtual host checking")

#ifdef HAVE_SRP
    SSL_CMD_SRV(SRPVerifierFile, TAKE1,
                "SRP verifier file "
                "('/path/to/file' - created by srptool)")
    SSL_CMD_SRV(SRPUnknownUserSeed, TAKE1,
                "SRP seed for unknown users (to avoid leaking a user's existence) "
                "('some secret text')")
#endif

    /*
     * Proxy configuration for remote SSL connections
     */
    SSL_CMD_PXY(ProxyEngine, FLAG,
                "SSL switch for the proxy protocol engine "
                "('on', 'off')")
    SSL_CMD_PXY(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
                "('[+-][" SSL_PROTOCOLS "] ...' - see manual)")
    SSL_CMD_PXY(ProxyCipherSuite, TAKE12,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               ", optionally preceded by protocol specifier ('XXX:...:XXX' - see manual)")
    SSL_CMD_PXY(ProxyVerify, TAKE1,
               "SSL Proxy: whether to verify the remote certificate "
               "('on' or 'off')")
    SSL_CMD_PXY(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "('N' - number of intermediate certificates)")
    SSL_CMD_PXY(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "('/path/to/file' - PEM encoded certificates)")
    SSL_CMD_PXY(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "('/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_PXY(ProxyCARevocationPath, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) path "
                "('/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_PXY(ProxyCARevocationFile, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) file "
                "('/path/to/file' - PEM encoded)")
    SSL_CMD_PXY(ProxyCARevocationCheck, RAW_ARGS,
                "SSL Proxy: CA Certificate Revocation List (CRL) checking mode")
    SSL_CMD_PXY(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "('/path/to/file' - PEM encoded certificates)")
    SSL_CMD_PXY(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "('/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_PXY(ProxyMachineCertificateChainFile, TAKE1,
               "SSL Proxy: file containing issuing certificates "
               "of the client certificate "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_PXY(ProxyCheckPeerExpire, FLAG,
                "SSL Proxy: check the peer certificate's expiration date")
    SSL_CMD_PXY(ProxyCheckPeerCN, FLAG,
                "SSL Proxy: check the peer certificate's CN")
    SSL_CMD_PXY(ProxyCheckPeerName, FLAG,
                "SSL Proxy: check the peer certificate's name "
                "(must be present in subjectAltName extension or CN")

    /*
     * Per-directory context configuration directives
     */
    SSL_CMD_DIR(Options, OPTIONS, RAW_ARGS,
               "Set one or more options to configure the SSL engine"
               "('[+-]option[=value] ...' - see manual)")
    SSL_CMD_DIR(RequireSSL, AUTHCFG, NO_ARGS,
               "Require the SSL protocol for the per-directory context "
               "(no arguments)")
    SSL_CMD_DIR(Require, AUTHCFG, RAW_ARGS,
               "Require a boolean expression to evaluate to true for granting access"
               "(arbitrary complex boolean expression - see manual)")
    SSL_CMD_DIR(RenegBufferSize, AUTHCFG, TAKE1,
                "Configure the amount of memory that will be used for buffering the "
                "request body if a per-location SSL renegotiation is required due to "
                "changed access control requirements")

    SSL_CMD_SRV(OCSPEnable, RAW_ARGS,
               "Enable use of OCSP to verify certificate revocation mode ('on', 'leaf', 'off')")
    SSL_CMD_SRV(OCSPDefaultResponder, TAKE1,
               "URL of the default OCSP Responder")
    SSL_CMD_SRV(OCSPOverrideResponder, FLAG,
               "Force use of the default responder URL ('on', 'off')")
    SSL_CMD_SRV(OCSPResponseTimeSkew, TAKE1,
                "Maximum time difference in OCSP responses")
    SSL_CMD_SRV(OCSPResponseMaxAge, TAKE1,
                "Maximum age of OCSP responses")
    SSL_CMD_SRV(OCSPResponderTimeout, TAKE1,
                "OCSP responder query timeout")
    SSL_CMD_SRV(OCSPUseRequestNonce, FLAG,
                "Whether OCSP queries use a nonce or not ('on', 'off')")
    SSL_CMD_SRV(OCSPProxyURL, TAKE1,
                "Proxy URL to use for OCSP requests")

/* Define OCSP Responder Certificate Verification Directive */
    SSL_CMD_SRV(OCSPNoVerify, FLAG,
                "Do not verify OCSP Responder certificate ('on', 'off')")
/* Define OCSP Responder File Configuration Directive */
    SSL_CMD_SRV(OCSPResponderCertificateFile, TAKE1,
               "Trusted OCSP responder certificates"
               "(`/path/to/file' - PEM encoded certificates)")

#ifdef HAVE_OCSP_STAPLING
    /*
     * OCSP Stapling options
     */
    SSL_CMD_SRV(StaplingCache, TAKE1,
                "SSL Stapling Response Cache storage "
                "(`dbm:/path/to/file')")
    SSL_CMD_SRV(UseStapling, FLAG,
                "SSL switch for the OCSP Stapling protocol " "(`on', `off')")
    SSL_CMD_SRV(StaplingResponseTimeSkew, TAKE1,
                "SSL stapling option for maximum time difference in OCSP responses")
    SSL_CMD_SRV(StaplingResponderTimeout, TAKE1,
                "SSL stapling option for OCSP responder timeout")
    SSL_CMD_SRV(StaplingResponseMaxAge, TAKE1,
                "SSL stapling option for maximum age of OCSP responses")
    SSL_CMD_SRV(StaplingStandardCacheTimeout, TAKE1,
                "SSL stapling option for normal OCSP Response Cache Lifetime")
    SSL_CMD_SRV(StaplingReturnResponderErrors, FLAG,
                "SSL stapling switch to return Status Errors Back to Client"
                "(`on', `off')")
    SSL_CMD_SRV(StaplingFakeTryLater, FLAG,
                "SSL stapling switch to send tryLater response to client on error "
                "(`on', `off')")
    SSL_CMD_SRV(StaplingErrorCacheTimeout, TAKE1,
                "SSL stapling option for OCSP Response Error Cache Lifetime")
    SSL_CMD_SRV(StaplingForceURL, TAKE1,
                "SSL stapling option to Force the OCSP Stapling URL")
#endif

#ifdef HAVE_SSL_CONF_CMD
    SSL_CMD_SRV(OpenSSLConfCmd, TAKE2,
                "OpenSSL configuration command")
#endif

    /* Deprecated directives. */
    AP_INIT_RAW_ARGS("SSLLog", ap_set_deprecated, NULL, OR_ALL,
      "SSLLog directive is no longer supported - use ErrorLog."),
    AP_INIT_RAW_ARGS("SSLLogLevel", ap_set_deprecated, NULL, OR_ALL,
      "SSLLogLevel directive is no longer supported - use LogLevel."),

    AP_END_CMD
};

/*
 *  the various processing hooks
 */
static int modssl_is_prelinked(void)
{
    apr_size_t i = 0;
    const module *mod;
    while ((mod = ap_prelinked_modules[i++])) {
        if (strcmp(mod->name, "mod_ssl.c") == 0) {
            return 1;
        }
    }
    return 0;
}

static apr_status_t ssl_cleanup_pre_config(void *data)
{
#if HAVE_OPENSSL_INIT_SSL || (OPENSSL_VERSION_NUMBER >= 0x10100000L && \
                              !defined(LIBRESSL_VERSION_NUMBER))
    /* Openssl v1.1+ handles all termination automatically from
     * OPENSSL_init_ssl(). Do nothing in this case.
     */

#else
    /* Termination below is for legacy Openssl versions v1.0.x and
     * older.
     */

    /* Corresponds to OBJ_create()s */
    OBJ_cleanup();
    /* Corresponds to OPENSSL_load_builtin_modules() */
    CONF_modules_free();
    /* Corresponds to SSL_library_init: */
    EVP_cleanup();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_cleanup();
#endif
#if OPENSSL_VERSION_NUMBER >= 0x1000200fL
#ifndef OPENSSL_NO_COMP
    SSL_COMP_free_compression_methods();
#endif
#endif

    /* Usually needed per thread, but this parent process is single-threaded */
#if MODSSL_USE_OPENSSL_PRE_1_1_API
#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
    ERR_remove_thread_state(NULL);
#else
    ERR_remove_state(0);
#endif
#endif

    /* Don't call ERR_free_strings in earlier versions, ERR_load_*_strings only
     * actually loaded the error strings once per process due to static
     * variable abuse in OpenSSL. */
#if (OPENSSL_VERSION_NUMBER >= 0x00090805f)
    ERR_free_strings();
#endif

    /* Also don't call CRYPTO_cleanup_all_ex_data when linked statically here;
     * any registered ex_data indices may have been cached in static variables
     * in OpenSSL; removing them may cause havoc.  Notably, with OpenSSL
     * versions >= 0.9.8f, COMP_CTX cleanups would not be run, which
     * could result in a per-connection memory leak (!). */
    if (!modssl_running_statically) {
        CRYPTO_cleanup_all_ex_data();
    }
#endif

    /*
     * TODO: determine somewhere we can safely shove out diagnostics
     *       (when enabled) at this late stage in the game:
     * CRYPTO_mem_leaks_fp(stderr);
     */

    return APR_SUCCESS;
}

static int ssl_hook_pre_config(apr_pool_t *pconf,
                               apr_pool_t *plog,
                               apr_pool_t *ptemp)
{
    modssl_running_statically = modssl_is_prelinked();

#if HAVE_OPENSSL_INIT_SSL || (OPENSSL_VERSION_NUMBER >= 0x10100000L && \
                              !defined(LIBRESSL_VERSION_NUMBER))
    /* Openssl v1.1+ handles all initialisation automatically, apart
     * from hints as to how we want to use the library.
     *
     * We tell openssl we want to include engine support.
     */
    OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);

#else
    /* Configuration below is for legacy versions Openssl v1.0 and
     * older.
     */

#if APR_HAS_THREADS && MODSSL_USE_OPENSSL_PRE_1_1_API
    ssl_util_thread_id_setup(pconf);
#endif
#if MODSSL_USE_OPENSSL_PRE_1_1_API || defined(LIBRESSL_VERSION_NUMBER)
    (void)CRYPTO_malloc_init();
#else
    OPENSSL_malloc_init();
#endif
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_library_init();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_load_builtin_engines();
#endif
    OpenSSL_add_all_algorithms();
    OPENSSL_load_builtin_modules();
#endif

    if (OBJ_txt2nid("id-on-dnsSRV") == NID_undef) {
        (void)OBJ_create("1.3.6.1.5.5.7.8.7", "id-on-dnsSRV",
                         "SRVName otherName form");
    }

    /* Start w/o errors (e.g. OBJ_txt2nid() above) */
    ERR_clear_error();

    /*
     * Let us cleanup the ssl library when the module is unloaded
     */
    apr_pool_cleanup_register(pconf, NULL, ssl_cleanup_pre_config,
                                           apr_pool_cleanup_null);

    /* Register us to handle mod_log_config %c/%x variables */
    ssl_var_log_config_register(pconf);

    /* Register to handle mod_status status page generation */
    ssl_scache_status_register(pconf);

    /* Register mutex type names so they can be configured with Mutex */
    ap_mutex_register(pconf, SSL_CACHE_MUTEX_TYPE, NULL, APR_LOCK_DEFAULT, 0);
#ifdef HAVE_OCSP_STAPLING
    ap_mutex_register(pconf, SSL_STAPLING_CACHE_MUTEX_TYPE, NULL,
                      APR_LOCK_DEFAULT, 0);
    ap_mutex_register(pconf, SSL_STAPLING_REFRESH_MUTEX_TYPE, NULL,
                      APR_LOCK_DEFAULT, 0);
#endif

    return OK;
}

static SSLConnRec *ssl_init_connection_ctx(conn_rec *c,
                                           ap_conf_vector_t *per_dir_config,
                                           int reinit)
{
    SSLConnRec *sslconn = myConnConfig(c);
    int need_setup = 0;

    /* mod_proxy's (r->)per_dir_config has the lifetime of the request, thus
     * it uses ssl_engine_set() to reset sslconn->dc when reusing SSL backend
     * connections, so we must fall through here. But in the case where we are
     * called from ssl_init_ssl_connection() with no per_dir_config (which also
     * includes mod_proxy's later run_pre_connection call), sslconn->dc should
     * be preserved if it's already set.
     */
    if (!sslconn) {
        sslconn = apr_pcalloc(c->pool, sizeof(*sslconn));
        need_setup = 1;
    }
    else if (!reinit) {
        return sslconn;
    }

    /* Reinit dc in any case because it may be r->per_dir_config scoped
     * and thus a caller like mod_proxy needs to update it per request.
     */
    if (per_dir_config) {
        sslconn->dc = ap_get_module_config(per_dir_config, &ssl_module);
    }
    else {
        sslconn->dc = ap_get_module_config(c->base_server->lookup_defaults,
                                           &ssl_module);
    }

    if (need_setup) {
        sslconn->server = c->base_server;
        sslconn->verify_depth = UNSET;
        if (c->outgoing) {
            sslconn->cipher_suite = sslconn->dc->proxy->auth.cipher_suite;
        }
        else {
            SSLSrvConfigRec *sc = mySrvConfig(c->base_server);
            sslconn->cipher_suite = sc->server->auth.cipher_suite;
        }

        myConnConfigSet(c, sslconn);
    }

    return sslconn;
}

static int ssl_engine_status(conn_rec *c, SSLConnRec *sslconn)
{
    if (c->master) {
        return DECLINED;
    }
    if (sslconn) {
        /* This connection has already been configured. Check what applies. */
        if (sslconn->disabled) {
            return SUSPENDED;
        }
        if (c->outgoing) {
            if (!sslconn->dc->proxy_enabled) {
                return DECLINED;
            }
        }
        else {
            if (mySrvConfig(sslconn->server)->enabled != SSL_ENABLED_TRUE) {
                return DECLINED;
            }
        }
    }
    else {
        /* we decline by default for outgoing connections and for incoming
         * where the base_server is not enabled. */
        if (c->outgoing || mySrvConfig(c->base_server)->enabled != SSL_ENABLED_TRUE) {
            return DECLINED;
        }
    }
    return OK;
}

static int ssl_hook_ssl_bind_outgoing(conn_rec *c,
                                 ap_conf_vector_t *per_dir_config,
                                 int enable_ssl)
{
    SSLConnRec *sslconn;
    int status;

    sslconn = ssl_init_connection_ctx(c, per_dir_config, 1);
    if (sslconn->ssl) {
        /* we are already bound to this connection. We have rebound
         * or removed the reference to a previous per_dir_config,
         * there is nothing more to do. */
        return OK;
    }

    status = ssl_engine_status(c, sslconn);
    if (enable_ssl) {
        if (status != OK) {
            SSLSrvConfigRec *sc = mySrvConfig(sslconn->server);
            sslconn->disabled = 1;
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(10272)
                          "SSL Proxy requested for %s but not enabled for us.",
                          sc->vhost_id);
        }
        else {
            sslconn->disabled = 0;
            return OK;
        }
    }
    else {
        sslconn->disabled = 1;
    }
    return DECLINED;
}

int ssl_init_ssl_connection(conn_rec *c, request_rec *r)
{
    SSLSrvConfigRec *sc;
    SSL *ssl;
    SSLConnRec *sslconn;
    char *vhost_md5;
    int rc;
    modssl_ctx_t *mctx;
    server_rec *server;

    /*
     * Create or retrieve SSL context
     */
    sslconn = ssl_init_connection_ctx(c, r ? r->per_dir_config : NULL, 0);
    server = sslconn->server;
    sc = mySrvConfig(server);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     */
    ssl_rand_seed(server, c->pool, SSL_RSCTX_CONNECT,
                  c->outgoing ? "Proxy: " : "Server: ");

    mctx = myConnCtxConfig(c, sc);

    /*
     * Create a new SSL connection with the configured server SSL context and
     * attach this to the socket. Additionally we register this attachment
     * so we can detach later.
     */
    if (!(sslconn->ssl = ssl = SSL_new(mctx->ssl_ctx))) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(01962)
                      "Unable to create a new SSL connection from the SSL "
                      "context");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    rc = ssl_run_pre_handshake(c, ssl, c->outgoing ? 1 : 0);
    if (rc != OK && rc != DECLINED) {
        return rc;
    }

    vhost_md5 = ap_md5_binary(c->pool, (unsigned char *)sc->vhost_id,
                              sc->vhost_id_len);

    if (!SSL_set_session_id_context(ssl, (unsigned char *)vhost_md5,
                                    APR_MD5_DIGESTSIZE*2))
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(01963)
                      "Unable to set session id context to '%s'", vhost_md5);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    SSL_set_app_data(ssl, c);
    modssl_set_app_data2(ssl, NULL); /* will be request_rec */

    SSL_set_verify_result(ssl, X509_V_OK);

    ssl_io_filter_init(c, r, ssl);

    return APR_SUCCESS;
}

static const char *ssl_hook_http_scheme(const request_rec *r)
{
    return modssl_request_is_tls(r, NULL) ? "https" : NULL;
}

static apr_port_t ssl_hook_default_port(const request_rec *r)
{
    return modssl_request_is_tls(r, NULL) ? 443 : 0;
}

static int ssl_hook_pre_connection(conn_rec *c, void *csd)
{
    SSLSrvConfigRec *sc;
    SSLConnRec *sslconn = myConnConfig(c);

    /*
     * Immediately stop processing if SSL is disabled for this connection
     */
    if (ssl_engine_status(c, sslconn) != OK) {
        return DECLINED;
    }

    if (sslconn) {
        sc = mySrvConfig(sslconn->server);
    }
    else {
        sc = mySrvConfig(c->base_server);
    }

    /*
     * Remember the connection information for
     * later access inside callback functions
     */

    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(01964)
                  "Connection to child %ld established "
                  "(server %s)", c->id, sc->vhost_id);

    return ssl_init_ssl_connection(c, NULL);
}

static int ssl_hook_process_connection(conn_rec* c)
{
    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn && !sslconn->disabled) {
        /* On an active SSL connection, let the input filters initialize
         * themselves which triggers the handshake, which again triggers
         * all kinds of useful things such as SNI and ALPN.
         */
        apr_bucket_brigade* temp;

        temp = apr_brigade_create(c->pool, c->bucket_alloc);
        ap_get_brigade(c->input_filters, temp,
                       AP_MODE_INIT, APR_BLOCK_READ, 0);
        apr_brigade_destroy(temp);
    }
    
    return DECLINED;
}

/*
 *  the module registration phase
 */

static void ssl_register_hooks(apr_pool_t *p)
{
    /* ssl_hook_ReadReq needs to use the BrowserMatch settings so must
     * run after mod_setenvif's post_read_request hook. */
    static const char *pre_prr[] = { "mod_setenvif.c", NULL };
    /* The ssl_init_Module post_config hook should run before mod_proxy's
     * for the ssl proxy main configs to be merged with vhosts' before being
     * themselves merged with mod_proxy's in proxy_hook_section_post_config.
     */
    static const char *b_pc[] = { "mod_proxy.c", NULL};


    ssl_io_filter_register(p);

    ap_hook_pre_connection(ssl_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(ssl_hook_process_connection, 
                                                   NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_test_config   (ssl_hook_ConfigTest,    NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config   (ssl_init_Module,        NULL,b_pc, APR_HOOK_MIDDLE);
    ap_hook_http_scheme   (ssl_hook_http_scheme,   NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port  (ssl_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config    (ssl_hook_pre_config,    NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init    (ssl_init_Child,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_check_authn   (ssl_hook_UserCheck,     NULL,NULL, APR_HOOK_FIRST,
                           AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_fixups        (ssl_hook_Fixup,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_check_access  (ssl_hook_Access,        NULL,NULL, APR_HOOK_MIDDLE,
                           AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_check_authz   (ssl_hook_Auth,          NULL,NULL, APR_HOOK_MIDDLE,
                           AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_post_read_request(ssl_hook_ReadReq, pre_prr,NULL, APR_HOOK_MIDDLE);

    APR_OPTIONAL_HOOK(proxy, section_post_config,
                      ssl_proxy_section_post_config, NULL, NULL,
                      APR_HOOK_MIDDLE);

    ssl_var_register(p);
    ap_hook_ssl_bind_outgoing  (ssl_hook_ssl_bind_outgoing, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ssl",
                              AUTHZ_PROVIDER_VERSION,
                              &ssl_authz_provider_require_ssl,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ssl-verify-client",
                              AUTHZ_PROVIDER_VERSION,
                              &ssl_authz_provider_verify_client,
                              AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA ssl_module = {
    STANDARD20_MODULE_STUFF,
    ssl_config_perdir_create,   /* create per-dir    config structures */
    ssl_config_perdir_merge,    /* merge  per-dir    config structures */
    ssl_config_server_create,   /* create per-server config structures */
    ssl_config_server_merge,    /* merge  per-server config structures */
    ssl_config_cmds,            /* table of configuration directives   */
    ssl_register_hooks          /* register hooks */
#if defined(AP_MODULE_HAS_FLAGS)
   ,AP_MODULE_FLAG_ALWAYS_MERGE /* flags */
#endif
};
