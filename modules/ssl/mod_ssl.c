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
#include "mod_ssl.h"
#include "util_md5.h"
#include "util_mutex.h"
#include "ap_provider.h"

#include <assert.h>

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|OR_AUTHCFG, desc),

#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF, desc),

#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, OR_##type, desc),

#define AP_END_CMD { NULL }

static const command_rec ssl_config_cmds[] = {
    /*
     * Global (main-server) context configuration directives
     */
    SSL_CMD_SRV(Mutex, TAKE1, AP_ALL_AVAILABLE_MUTEXES_STRING)
    SSL_CMD_SRV(PassPhraseDialog, TAKE1,
                "SSL dialog mechanism for the pass phrase query "
                "('builtin', '|/path/to/pipe_program', "
                "or 'exec:/path/to/cgi_program')")
    SSL_CMD_SRV(SessionCache, TAKE1,
                "SSL Session Cache storage "
                "('none', 'nonenotnull', 'dbm:/path/to/file')")
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
    SSL_CMD_SRV(CryptoDevice, TAKE1,
                "SSL external Crypto Device usage "
                "('builtin', '...')")
#endif
    SSL_CMD_SRV(RandomSeed, TAKE23,
                "SSL Pseudo Random Number Generator (PRNG) seeding source "
                "('startup|connect builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, TAKE1,
                "SSL switch for the protocol engine "
                "('on', 'off')")
    SSL_CMD_ALL(CipherSuite, TAKE1,
                "Colon-delimited list of permitted SSL Ciphers "
                "('XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(CertificateFile, TAKE1,
                "SSL Server Certificate file "
                "('/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateKeyFile, TAKE1,
                "SSL Server Private Key file "
                "('/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateChainFile, TAKE1,
                "SSL Server CA Certificate Chain file "
                "('/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(PKCS7CertificateFile, TAKE1,
                "PKCS#7 file containing server certificate and chain"
                " certificates ('/path/to/file' - PEM encoded)")
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
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client verify type "
                "('none', 'optional', 'require', 'optional_no_ca')")
    SSL_CMD_ALL(VerifyDepth, TAKE1,
                "SSL Client verify depth "
                "('N' - number of intermediate certificates)")
    SSL_CMD_SRV(SessionCacheTimeout, TAKE1,
                "SSL Session Cache object lifetime "
                "('N' - number of seconds)")
    SSL_CMD_SRV(Protocol, RAW_ARGS,
                "Enable or disable various SSL protocols"
                "('[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(HonorCipherOrder, FLAG,
                "Use the server's cipher ordering preference")
    SSL_CMD_ALL(UserName, TAKE1,
                "Set user name to SSL variable value")
    SSL_CMD_SRV(LogLevelDebugDump, TAKE1,
                "Include I/O Dump when LogLevel is set to Debug "
                "([ None (default) | IO (not bytes) | Bytes ])")
    SSL_CMD_SRV(StrictSNIVHostCheck, FLAG,
                "Strict SNI virtual host checking")

    /*
     * Proxy configuration for remote SSL connections
     */
    SSL_CMD_SRV(ProxyEngine, FLAG,
                "SSL switch for the proxy protocol engine "
                "('on', 'off')")
    SSL_CMD_SRV(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
               "('[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(ProxyCipherSuite, TAKE1,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               "('XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(ProxyVerify, TAKE1,
               "SSL Proxy: whether to verify the remote certificate "
               "('on' or 'off')")
    SSL_CMD_SRV(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "('N' - number of intermediate certificates)")
    SSL_CMD_SRV(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "('/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "('/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCARevocationPath, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) path "
                "('/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(ProxyCARevocationFile, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) file "
                "('/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "('/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "('/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCheckPeerExpire, FLAG,
                "SSL Proxy: check the peers certificate expiration date")
    SSL_CMD_SRV(ProxyCheckPeerCN, FLAG,
                "SSL Proxy: check the peers certificate CN")

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

    SSL_CMD_SRV(OCSPEnable, FLAG,
               "Enable use of OCSP to verify certificate revocation ('on', 'off')")
    SSL_CMD_SRV(OCSPDefaultResponder, TAKE1,
               "URL of the default OCSP Responder")
    SSL_CMD_SRV(OCSPOverrideResponder, FLAG,
               "Force use of the default responder URL ('on', 'off')")

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
static apr_status_t ssl_cleanup_pre_config(void *data)
{
    /*
     * Try to kill the internals of the SSL library.
     */
#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x00907001
    /* Corresponds to OPENSSL_load_builtin_modules():
     * XXX: borrowed from apps.h, but why not CONF_modules_free()
     * which also invokes CONF_modules_finish()?
     */
    CONF_modules_unload(1);
#endif
#endif
    /* Corresponds to SSL_library_init: */
    EVP_cleanup();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_cleanup();
#endif
    ERR_remove_state(0);

    /* Don't call ERR_free_strings here; ERR_load_*_strings only
     * actually load the error strings once per process due to static
     * variable abuse in OpenSSL. */

    /* Also don't call CRYPTO_cleanup_all_ex_data here; any registered
     * ex_data indices may have been cached in static variables in
     * OpenSSL; removing them may cause havoc.  Notably, with OpenSSL
     * versions >= 0.9.8f, COMP_CTX cleanups would not be run, which
     * could result in a per-connection memory leak (!). */

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
    /* We must register the library in full, to ensure our configuration
     * code can successfully test the SSL environment.
     */
    CRYPTO_malloc_init();
#ifdef HAVE_OPENSSL
    ERR_load_crypto_strings();
#endif
    SSL_load_error_strings();
    SSL_library_init();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_load_builtin_engines();
#endif
#ifdef HAVE_OPENSSL
    OpenSSL_add_all_algorithms();
#if OPENSSL_VERSION_NUMBER >= 0x00907001
    OPENSSL_load_builtin_modules();
#endif
#endif

    /*
     * Let us cleanup the ssl library when the module is unloaded
     */
    apr_pool_cleanup_register(pconf, NULL, ssl_cleanup_pre_config,
                                           apr_pool_cleanup_null);

    /* Register us to handle mod_log_config %c/%x variables */
    ssl_var_log_config_register(pconf);

    /* Register to handle mod_status status page generation */
    ssl_scache_status_register(pconf);

    return OK;
}

static SSLConnRec *ssl_init_connection_ctx(conn_rec *c)
{
    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        return sslconn;
    }

    sslconn = apr_pcalloc(c->pool, sizeof(*sslconn));

    sslconn->server = c->base_server;

    myConnConfigSet(c, sslconn);

    return sslconn;
}

int ssl_proxy_enable(conn_rec *c)
{
    SSLSrvConfigRec *sc;

    SSLConnRec *sslconn = ssl_init_connection_ctx(c);
    sc = mySrvConfig(sslconn->server);

    if (!sc->proxy_enabled) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "SSL Proxy requested for %s but not enabled "
                      "[Hint: SSLProxyEngine]", sc->vhost_id);

        return 0;
    }

    sslconn->is_proxy = 1;
    sslconn->disabled = 0;

    return 1;
}

int ssl_engine_disable(conn_rec *c)
{
    SSLSrvConfigRec *sc;

    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        sc = mySrvConfig(sslconn->server);
    }
    else {
        sc = mySrvConfig(c->base_server);
    }
    if (sc->enabled == SSL_ENABLED_FALSE) {
        return 0;
    }

    sslconn = ssl_init_connection_ctx(c);

    sslconn->disabled = 1;

    return 1;
}

int ssl_init_ssl_connection(conn_rec *c, request_rec *r)
{
    SSLSrvConfigRec *sc;
    SSL *ssl;
    SSLConnRec *sslconn = myConnConfig(c);
    char *vhost_md5;
    modssl_ctx_t *mctx;
    server_rec *server;

    if (!sslconn) {
        sslconn = ssl_init_connection_ctx(c);
    }
    server = sslconn->server;
    sc = mySrvConfig(server);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     */
    ssl_rand_seed(server, c->pool, SSL_RSCTX_CONNECT, "");

    mctx = sslconn->is_proxy ? sc->proxy : sc->server;

    /*
     * Create a new SSL connection with the configured server SSL context and
     * attach this to the socket. Additionally we register this attachment
     * so we can detach later.
     */
    if (!(ssl = SSL_new(mctx->ssl_ctx))) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "Unable to create a new SSL connection from the SSL "
                      "context");
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    vhost_md5 = ap_md5_binary(c->pool, (unsigned char *)sc->vhost_id,
                              sc->vhost_id_len);

    if (!SSL_set_session_id_context(ssl, (unsigned char *)vhost_md5,
                                    APR_MD5_DIGESTSIZE*2))
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "Unable to set session id context to '%s'", vhost_md5);
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    SSL_set_app_data(ssl, c);
    SSL_set_app_data2(ssl, NULL); /* will be request_rec */

    sslconn->ssl = ssl;

    /*
     *  Configure callbacks for SSL connection
     */
    SSL_set_tmp_rsa_callback(ssl, ssl_callback_TmpRSA);
    SSL_set_tmp_dh_callback(ssl,  ssl_callback_TmpDH);

    SSL_set_verify_result(ssl, X509_V_OK);

    ssl_io_filter_init(c, r, ssl);

    return APR_SUCCESS;
}

static const char *ssl_hook_http_scheme(const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == SSL_ENABLED_FALSE || sc->enabled == SSL_ENABLED_OPTIONAL) {
        return NULL;
    }

    return "https";
}

static apr_port_t ssl_hook_default_port(const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == SSL_ENABLED_FALSE || sc->enabled == SSL_ENABLED_OPTIONAL) {
        return 0;
    }

    return 443;
}

static int ssl_hook_pre_connection(conn_rec *c, void *csd)
{
    SSLSrvConfigRec *sc;
    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        sc = mySrvConfig(sslconn->server);
    }
    else {
        sc = mySrvConfig(c->base_server);
    }
    /*
     * Immediately stop processing if SSL is disabled for this connection
     */
    if (!(sc && (sc->enabled == SSL_ENABLED_TRUE ||
                 (sslconn && sslconn->is_proxy))))
    {
        return DECLINED;
    }

    /*
     * Create SSL context
     */
    if (!sslconn) {
        sslconn = ssl_init_connection_ctx(c);
    }

    if (sslconn->disabled) {
        return DECLINED;
    }

    /*
     * Remember the connection information for
     * later access inside callback functions
     */

    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c,
                  "Connection to child %ld established "
                  "(server %s)", c->id, sc->vhost_id);

    return ssl_init_ssl_connection(c, NULL);
}

/*
 *  the module registration phase
 */

static void ssl_register_hooks(apr_pool_t *p)
{
    /* ssl_hook_ReadReq needs to use the BrowserMatch settings so must
     * run after mod_setenvif's post_read_request hook. */
    static const char *pre_prr[] = { "mod_setenvif.c", NULL };

    ssl_io_filter_register(p);

    ap_hook_pre_connection(ssl_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_test_config   (ssl_hook_ConfigTest,    NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config   (ssl_init_Module,        NULL,NULL, APR_HOOK_MIDDLE);
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

    ssl_var_register(p);

    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
}

module AP_MODULE_DECLARE_DATA ssl_module = {
    STANDARD20_MODULE_STUFF,
    ssl_config_perdir_create,   /* create per-dir    config structures */
    ssl_config_perdir_merge,    /* merge  per-dir    config structures */
    ssl_config_server_create,   /* create per-server config structures */
    ssl_config_server_merge,    /* merge  per-server config structures */
    ssl_config_cmds,            /* table of configuration directives   */
    ssl_register_hooks          /* register hooks */
};
