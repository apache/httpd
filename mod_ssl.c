/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  mod_ssl.c
**  Apache API interface structures
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

#include "mod_ssl.h"
#include "util_md5.h"
#include <assert.h>

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, NULL, RSRC_CONF|OR_AUTHCFG, desc),
#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, NULL, RSRC_CONF, desc),
#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, NULL, OR_##type, desc),
#define AP_END_CMD { NULL }

static const command_rec ssl_config_cmds[] = {

    /*
     * Global (main-server) context configuration directives
     */
    SSL_CMD_SRV(Mutex, TAKE1,
                "SSL lock for handling internal mutual exclusions "
                "(`none', `file:/path/to/file')")
    SSL_CMD_SRV(PassPhraseDialog, TAKE1,
                "SSL dialog mechanism for the pass phrase query "
                "(`builtin', `exec:/path/to/program')")
    SSL_CMD_SRV(SessionCache, TAKE1,
                "SSL Session Cache storage "
                "(`none', `dbm:/path/to/file')")
#ifdef SSL_EXPERIMENTAL_ENGINE
    SSL_CMD_SRV(CryptoDevice, TAKE1,
                "SSL external Crypto Device usage "
                "(`builtin', `...')")
#endif
    SSL_CMD_SRV(RandomSeed, TAKE23,
                "SSL Pseudo Random Number Generator (PRNG) seeding source "
                "(`startup|connect builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, FLAG,
                "SSL switch for the protocol engine "
                "(`on', `off')")
    SSL_CMD_ALL(CipherSuite, TAKE1,
                "Colon-delimited list of permitted SSL Ciphers "
                "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(CertificateFile, TAKE1,
                "SSL Server Certificate file "
                "(`/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateKeyFile, TAKE1,
                "SSL Server Private Key file "
                "(`/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateChainFile, TAKE1,
                "SSL Server CA Certificate Chain file "
                "(`/path/to/file' - PEM encoded)")
#ifdef SSL_EXPERIMENTAL_PERDIRCA
    SSL_CMD_ALL(CACertificatePath, TAKE1,
                "SSL CA Certificate path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_ALL(CACertificateFile, TAKE1,
                "SSL CA Certificate file "
                "(`/path/to/file' - PEM encoded)")
#else
    SSL_CMD_SRV(CACertificatePath, TAKE1,
                "SSL CA Certificate path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(CACertificateFile, TAKE1,
                "SSL CA Certificate file "
                "(`/path/to/file' - PEM encoded)")
#endif
    SSL_CMD_SRV(CARevocationPath, TAKE1,
                "SSL CA Certificate Revocation List (CRL) path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(CARevocationFile, TAKE1,
                "SSL CA Certificate Revocation List (CRL) file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client verify type "
                "(`none', `optional', `require', `optional_no_ca')")
    SSL_CMD_ALL(VerifyDepth, TAKE1,
                "SSL Client verify depth "
                "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(SessionCacheTimeout, TAKE1,
                "SSL Session Cache object lifetime "
                "(`N' - number of seconds)")
    SSL_CMD_SRV(Log, TAKE1,
                "SSL logfile for SSL-related messages "
                "(`/path/to/file', `|/path/to/program')")
    SSL_CMD_SRV(LogLevel, TAKE1,
                "SSL logfile verbosity level "
                "(`none', `error', `warn', `info', `debug')")
    SSL_CMD_SRV(Protocol, RAW_ARGS,
                "Enable or disable various SSL protocols"
                "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")

#ifdef SSL_EXPERIMENTAL_PROXY
    /* 
     * Proxy configuration for remote SSL connections
     */
    SSL_CMD_SRV(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
               "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(ProxyCipherSuite, TAKE1,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(ProxyVerify, FLAG,
               "SSL Proxy: whether to verify the remote certificate "
               "(`on' or `off')")
    SSL_CMD_SRV(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
#endif

    /*
     * Per-directory context configuration directives
     */
    SSL_CMD_DIR(Options, OPTIONS, RAW_ARGS,
               "Set one or more options to configure the SSL engine"
               "(`[+-]option[=value] ...' - see manual)")
    SSL_CMD_DIR(RequireSSL, AUTHCFG, NO_ARGS,
               "Require the SSL protocol for the per-directory context "
               "(no arguments)")
    SSL_CMD_DIR(Require, AUTHCFG, RAW_ARGS,
               "Require a boolean expression to evaluate to true for granting access"
               "(arbitrary complex boolean expression - see manual)")

    AP_END_CMD
};

/*
 *  the various processing hooks
 */

static void ssl_hook_pre_config(
    apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    ssl_ext_register(pconf);
}

static int ssl_hook_pre_connection(conn_rec *c)
{
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);
    apr_table_t *apctx;
    SSL *ssl;
    unsigned char *cpVHostID;
    char *cpVHostMD5;

    /*
     * Create SSL context
     */
    apr_table_setn(c->notes, "ssl", NULL);

    /*
     * Immediately stop processing if SSL is disabled for this connection
     */
    if (sc == NULL || !sc->bEnabled)
        return DECLINED;

    /*
     * Remember the connection information for
     * later access inside callback functions
     */
    cpVHostID = (unsigned char *)ssl_util_vhostid(c->pool,c->base_server);
    ssl_log(c->base_server, SSL_LOG_INFO, "Connection to child %d established "
            "(server %s, client %s)", c->id, cpVHostID, 
            c->remote_ip != NULL ? c->remote_ip : "unknown");

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     */
    ssl_rand_seed(c->base_server, c->pool, SSL_RSCTX_CONNECT, "");

    /*
     * Create a new SSL connection with the configured server SSL context and
     * attach this to the socket. Additionally we register this attachment
     * so we can detach later.
     */
    if ((ssl = SSL_new(sc->pSSLCtx)) == NULL) {
        ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                "Unable to create a new SSL connection from the SSL context");
        apr_table_setn(c->notes, "ssl", NULL);
        c->aborted = 1;
        return DECLINED; /* XXX */
    }
    SSL_clear(ssl);
    cpVHostMD5 = ap_md5(c->pool, cpVHostID);
    if (!SSL_set_session_id_context(ssl, (unsigned char *)cpVHostMD5,
            strlen(cpVHostMD5))) {
        ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                "Unable to set session id context to `%s'", cpVHostMD5);
        apr_table_setn(c->notes, "ssl", NULL);
        c->aborted = 1;
        return DECLINED; /* XXX */
    }
    SSL_set_app_data(ssl, c);
    apctx = apr_table_make(c->pool, AP_CTX_MAX_ENTRIES);
    apr_table_setn(apctx, "ssl::request_rec", NULL);
    apr_table_setn(apctx, "ssl::verify::depth", AP_CTX_NUM2PTR(0));
    SSL_set_app_data2(ssl, apctx);

    apr_table_setn(c->notes, "ssl", (const char *)ssl);

    /*
     *  Configure callbacks for SSL connection
     */
    SSL_set_tmp_rsa_callback(ssl, ssl_callback_TmpRSA);
    SSL_set_tmp_dh_callback(ssl,  ssl_callback_TmpDH);
#if 0 /* XXX */
    if (sc->nLogLevel >= SSL_LOG_DEBUG) {
        BIO_set_callback(SSL_get_rbio(ssl), ssl_io_data_cb);
        BIO_set_callback_arg(SSL_get_rbio(ssl), ssl);
    }
#endif
    /*
     * Predefine some client verification results
     */
    apr_table_setn(c->notes, "ssl::client::dn", NULL);
    apr_table_setn(c->notes, "ssl::verify::error", NULL);
    apr_table_setn(c->notes, "ssl::verify::info", NULL);
    SSL_set_verify_result(ssl, X509_V_OK);

    /*
     * We have to manage a I/O timeout ourself, because Apache
     * does it the first time when reading the request, but we're
     * working some time before this happens.
     */
    ssl_util_setmodconfig(c->base_server, "ssl::handshake::timeout", (void *)FALSE);
#if 0 /* XXX */
    ap_set_callback_and_alarm(ssl_hook_TimeoutConnection, c->base_server->timeout);
#endif
    ssl_io_filter_init(c, ssl);

    return APR_SUCCESS;
}

/*
 * The hook is NOT registered with ap_hook_process_connection. Instead, it is
 * called manually from the churn () before it tries to read any data.
 * There is some problem if I accept conn_rec *. Still investigating..
 * Adv. if conn_rec * can be accepted is we can hook this function using the
 * ap_hook_process_connection hook.
 */
int ssl_hook_process_connection(SSLFilterRec *pRec)
{
    int n, err;
    conn_rec *c = SSL_get_app_data (pRec->pssl);

    if (!SSL_is_init_finished(pRec->pssl))
    {
        if ((n = SSL_accept(pRec->pssl)) <= 0) {

            if ((err = SSL_get_error(pRec->pssl, n)) == SSL_ERROR_ZERO_RETURN) {
                /*
                 * The case where the connection was closed before any data
                 * was transferred. That's not a real error and can occur
                 * sporadically with some clients.
                 */
                ssl_log(c->base_server, SSL_LOG_INFO,
                        "SSL handshake stopped: connection was closed");
            }
            else if (err == SSL_ERROR_WANT_READ) {
                /*
                 * This is in addition to what was present earlier. It is 
                 * borrowed from openssl_state_machine.c [mod_tls].
                 * TBD.
                 */
                return 0;
            }
            else if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
                /*
                 * The case where OpenSSL has recognized a HTTP request:
                 * This means the client speaks plain HTTP on our HTTPS port.
                 * Hmmmm...  At least for this error we can be more friendly
                 * and try to provide him with a HTML error page. We have only
                 * one problem:OpenSSL has already read some bytes from the HTTP
                 * request. So we have to skip the request line manually and
                 * instead provide a faked one in order to continue the internal
                 * Apache processing.
                 *
                 */

#if 0 /* XXX */
                /*
                 * Still need to be ported to Apache 2.0 style
                 */
                char ca[2];
                int rv;

                /* log the situation */
                ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "SSL handshake failed: HTTP spoken on HTTPS port; "
                        "trying to send HTML error page");
                /* first: skip the remaining bytes of the request line */
                do {
                    do {
                        rv = read(fb->fd, ca, 1);
                    } while (rv == -1 && errno == EINTR);
                } while (rv > 0 && ca[0] != '\012' /*LF*/);

                /* second: fake the request line */
                fb->inbase = ap_palloc(fb->pool, fb->bufsiz);
                ap_cpystrn((char *)fb->inbase, "GET /mod_ssl:error:HTTP-request HTTP/1.0\r\n",
                           fb->bufsiz);
                fb->inptr = fb->inbase;
                fb->incnt = strlen((char *)fb->inptr);
#else
                ssl_log(c->base_server, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "SSL handshake failed: HTTP spoken on HTTPS port");
#endif
            }
            else if (ssl_util_getmodconfig_ssl(pRec->pssl, "ssl::handshake::timeout")
               == (void *)TRUE) {
                ssl_log(c->base_server, SSL_LOG_ERROR,
                        "SSL handshake timed out (client %s, server %s)",
                        c->remote_ip != NULL ? c->remote_ip : "unknown", 
                        ssl_util_vhostid(c->pool,c->base_server));
            }
            else if ((SSL_get_error(pRec->pssl, n) == SSL_ERROR_SYSCALL) 
                && (errno != EINTR)) {
                if (errno > 0)
                    ssl_log(c->base_server,
                             SSL_LOG_ERROR|SSL_ADD_SSLERR|SSL_ADD_ERRNO,
                            "SSL handshake interrupted by system "
                            "[Hint: Stop button pressed in browser?!]");
                else
                    ssl_log(c->base_server,
                        SSL_LOG_INFO|SSL_ADD_SSLERR|SSL_ADD_ERRNO,
                        "Spurious SSL handshake interrupt [Hint: "
                        "Usually just one of those OpenSSL confusions!?]");
            }
            else {
                /*
                 * Ok, anything else is a fatal error
                 */
                ssl_log(c->base_server,
                        SSL_LOG_ERROR|SSL_ADD_SSLERR|SSL_ADD_ERRNO,
                        "SSL handshake failed (server %s, client %s)",
                        ssl_util_vhostid(c->pool,c->base_server),
                        c->remote_ip != NULL ? c->remote_ip : "unknown");
            }
            /*
             * try to gracefully shutdown the connection:
             * - send an own shutdown message (be gracefully)
             * - don't wait for peer's shutdown message (deadloop)
             * - kick away the SSL stuff immediately
             * - block the socket, so Apache cannot operate any more
             */
            SSL_set_shutdown(pRec->pssl, SSL_RECEIVED_SHUTDOWN);
            SSL_smart_shutdown(pRec->pssl);
            SSL_free(pRec->pssl);
            pRec->pssl = NULL; /* so filters know we've been shutdown */
            apr_table_setn(c->notes, "ssl", NULL);
            c->aborted = 1;
            return APR_EGENERAL;
        }
    }
    return APR_SUCCESS;
}

static const char *ssl_hook_http_method (const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->bEnabled == FALSE)
        return NULL;

    return "https";
}

static apr_port_t ssl_hook_default_port (const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->bEnabled == FALSE)
        return 0;
    return 443;
}

/*
 *  the module registration phase
 */

static void ssl_register_hooks(apr_pool_t *p)
{
    ssl_io_filter_register(p);

    ap_hook_pre_connection(ssl_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config   (ssl_init_Module,        NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method   (ssl_hook_http_method,   NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port  (ssl_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_handler       (ssl_hook_Handler,       NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config    (ssl_hook_pre_config,    NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init    (ssl_init_Child,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(ssl_hook_Translate,     NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id (ssl_hook_Auth,          NULL,NULL, APR_HOOK_FIRST);
    ap_hook_fixups        (ssl_hook_Fixup,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(ssl_hook_Access,        NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker  (ssl_hook_UserCheck,     NULL,NULL, APR_HOOK_MIDDLE);

    ssl_var_register();
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
