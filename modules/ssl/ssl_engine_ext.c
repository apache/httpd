/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_ext.c
**  Extensions to other Apache parts
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
                             /* ``Only those who attempt the absurd
                                  can achieve the impossible.''
                                           -- Unknown             */
#include "mod_ssl.h"


#if 0 /* XXX this is for mod_proxy hackers, which optional_fn's to create? */
/*  _________________________________________________________________
**
**  SSL Extension to mod_proxy
**  _________________________________________________________________
*/

static int   ssl_ext_mp_canon(request_rec *, char *);
static int   ssl_ext_mp_handler(request_rec *, void *, char *, char *, int, char *);
static int   ssl_ext_mp_set_destport(request_rec *);
static char *ssl_ext_mp_new_connection(request_rec *, BUFF *, char *);
static void  ssl_ext_mp_close_connection(void *);
static int   ssl_ext_mp_write_host_header(request_rec *, BUFF *, char *, int, char *);
#ifdef SSL_EXPERIMENTAL_PROXY
static void  ssl_ext_mp_init(server_rec *, pool *);
static int   ssl_ext_mp_verify_cb(int, X509_STORE_CTX *);
static int   ssl_ext_mp_clientcert_cb(SSL *, X509 **, EVP_PKEY **);
#endif

/*
 * register us ...
 */
void ssl_ext_proxy_register(apr_pool_t *pconf)
{
#ifdef SSL_EXPERIMENTAL_PROXY
    ap_hook_register("ap::mod_proxy::init",
                     ssl_ext_mp_init, AP_HOOK_NOCTX);
#endif
    ap_hook_register("ap::mod_proxy::canon",
                     ssl_ext_mp_canon, AP_HOOK_NOCTX);
    ap_hook_register("ap::mod_proxy::handler",
                     ssl_ext_mp_handler, AP_HOOK_NOCTX);
    ap_hook_register("ap::mod_proxy::http::handler::set_destport",
                     ssl_ext_mp_set_destport, AP_HOOK_NOCTX);
    ap_hook_register("ap::mod_proxy::http::handler::new_connection",
                     ssl_ext_mp_new_connection, AP_HOOK_NOCTX);
    ap_hook_register("ap::mod_proxy::http::handler::write_host_header",
                     ssl_ext_mp_write_host_header, AP_HOOK_NOCTX);
    return;
}

/*
 * SSL proxy initialization
 */
#ifdef SSL_EXPERIMENTAL_PROXY
static void ssl_ext_mp_init(server_rec *s, pool *p)
{
    SSLSrvConfigRec *sc;
    char *cpVHostID;
    int nVerify;
    SSL_CTX *ctx;
    char *cp;
    STACK_OF(X509_INFO) *sk;

    /*
     * Initialize each virtual server 
     */
    ERR_clear_error();
    for (; s != NULL; s = s->next) {
        sc = mySrvConfig(s);
        cpVHostID = ssl_util_vhostid(p, s);
        
        if (sc->bProxyVerify == UNSET)
            sc->bProxyVerify = FALSE;

        /*
         *  Create new SSL context and configure callbacks
         */
        if (sc->nProxyProtocol == SSL_PROTOCOL_NONE) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: (%s) No Proxy SSL protocols available [hint: SSLProxyProtocol]",
                    cpVHostID);
            ssl_die();
        }
        cp = ap_pstrcat(p, (sc->nProxyProtocol & SSL_PROTOCOL_SSLV2 ? "SSLv2, " : ""), 
                           (sc->nProxyProtocol & SSL_PROTOCOL_SSLV3 ? "SSLv3, " : ""), 
                           (sc->nProxyProtocol & SSL_PROTOCOL_TLSV1 ? "TLSv1, " : ""), NULL);
        cp[strlen(cp)-2] = NUL;
        ssl_log(s, SSL_LOG_TRACE, 
                "Init: (%s) Creating new proxy SSL context (protocols: %s)", 
                cpVHostID, cp);
        if (sc->nProxyProtocol == SSL_PROTOCOL_SSLV2)
            ctx = SSL_CTX_new(SSLv2_client_method());  /* only SSLv2 is left */ 
        else
            ctx = SSL_CTX_new(SSLv23_client_method()); /* be more flexible */
        if (ctx == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                    "Init: (%s) Unable to create SSL Proxy context", cpVHostID);
            ssl_die();
        }
        sc->pSSLProxyCtx = ctx;
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
        if (!(sc->nProxyProtocol & SSL_PROTOCOL_SSLV2))
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        if (!(sc->nProxyProtocol & SSL_PROTOCOL_SSLV3))
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
        if (!(sc->nProxyProtocol & SSL_PROTOCOL_TLSV1)) 
            SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);

        if (sc->szProxyClientCertificateFile || sc->szProxyClientCertificatePath) {
            sk = sk_X509_INFO_new_null();
            if (sc->szProxyClientCertificateFile) 
                SSL_load_CrtAndKeyInfo_file(p, sk, sc->szProxyClientCertificateFile);
            if (sc->szProxyClientCertificatePath)
                SSL_load_CrtAndKeyInfo_path(p, sk, sc->szProxyClientCertificatePath);
            ssl_log(s, SSL_LOG_TRACE, "Init: (%s) loaded %d client certs for SSL proxy",
                    cpVHostID, sk_X509_INFO_num(sk));
            if (sk_X509_INFO_num(sk) > 0) {
                SSL_CTX_set_client_cert_cb(ctx, ssl_ext_mp_clientcert_cb);
                sc->skProxyClientCerts = sk;
            }
        }

        /*
         * Calculate OpenSSL verify type for verifying the remote server
         * certificate. We either verify it against our list of CA's, or don't
         * bother at all.
         */
        nVerify = SSL_VERIFY_NONE;
        if (sc->bProxyVerify)
            nVerify |= SSL_VERIFY_PEER;
        if (   nVerify & SSL_VERIFY_PEER 
            && sc->szProxyCACertificateFile == NULL 
            && sc->szProxyCACertificatePath == NULL) {
            ssl_log(s, SSL_LOG_ERROR,
                    "Init: (%s) SSLProxyVerify set to On but no CA certificates configured",
                    cpVHostID);
            ssl_die();
        }
        if (   nVerify & SSL_VERIFY_NONE
            && (   sc->szProxyCACertificateFile != NULL
                || sc->szProxyCACertificatePath != NULL)) {
            ssl_log(s, SSL_LOG_WARN, 
                    "init: (%s) CA certificates configured but ignored because SSLProxyVerify is Off",
                    cpVHostID);
        }
        SSL_CTX_set_verify(ctx, nVerify, ssl_ext_mp_verify_cb);

        /*
         * Enable session caching. We can safely use the same cache
         * as used for communicating with the other clients.
         */
        SSL_CTX_sess_set_new_cb(sc->pSSLProxyCtx,    ssl_callback_NewSessionCacheEntry);
        SSL_CTX_sess_set_get_cb(sc->pSSLProxyCtx,    ssl_callback_GetSessionCacheEntry);
        SSL_CTX_sess_set_remove_cb(sc->pSSLProxyCtx, ssl_callback_DelSessionCacheEntry);

        /*
         *  Configure SSL Cipher Suite
         */
        ssl_log(s, SSL_LOG_TRACE,
                "Init: (%s) Configuring permitted SSL ciphers for SSL proxy", cpVHostID);
        if (sc->szProxyCipherSuite != NULL) {
            if (!SSL_CTX_set_cipher_list(sc->pSSLProxyCtx, sc->szProxyCipherSuite)) {
                ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR,
                        "Init: (%s) Unable to configure permitted SSL ciphers for SSL Proxy",
                        cpVHostID);
                ssl_die();
            }
        }

        /*
         * Configure Client Authentication details
         */
        if (sc->szProxyCACertificateFile != NULL || sc->szProxyCACertificatePath != NULL) {
             ssl_log(s, SSL_LOG_DEBUG, 
                     "Init: (%s) Configuring client verification locations for SSL Proxy", 
                     cpVHostID);
             if (!SSL_CTX_load_verify_locations(sc->pSSLProxyCtx,
                                                sc->szProxyCACertificateFile,
                                                sc->szProxyCACertificatePath)) {
                 ssl_log(s, SSL_LOG_ERROR|SSL_ADD_SSLERR, 
                         "Init: (%s) Unable to configure SSL verify locations for SSL proxy",
                         cpVHostID);
                 ssl_die();
             }
        }
    }
    return;
}
#endif /* SSL_EXPERIMENTAL_PROXY */

static int ssl_ext_mp_canon(request_rec *r, char *url)
{
    int rc;

    if (strcEQn(url, "https:", 6)) {
        rc = OK;
        ap_hook_call("ap::mod_proxy::http::canon",
                     &rc, r, url+6, "https", DEFAULT_HTTPS_PORT);
        return rc;
    }
    return DECLINED;
}

static int ssl_ext_mp_handler(
    request_rec *r, void *cr, char *url, char *proxyhost, int proxyport, char *protocol)
{
    int rc;

    if (strcEQ(protocol, "https")) {
        ap_ctx_set(r->ctx, "ssl::proxy::enabled", PTRUE);
        ap_hook_call("ap::mod_proxy::http::handler",
                     &rc, r, cr, url, proxyhost, proxyport);
        return rc;
    }
    else {
        ap_ctx_set(r->ctx, "ssl::proxy::enabled", PFALSE);
    }
    return DECLINED;
}

static int ssl_ext_mp_set_destport(request_rec *r)
{
    if (ap_ctx_get(r->ctx, "ssl::proxy::enabled") == PTRUE)
        return DEFAULT_HTTPS_PORT;
    else
        return DEFAULT_HTTP_PORT;
}

static char *ssl_ext_mp_new_connection(request_rec *r, BUFF *fb, char *peer)
{
#ifndef SSL_EXPERIMENTAL_PROXY
    SSL_CTX *ssl_ctx;
#endif
    SSL *ssl;
    char *errmsg;
    int rc;
    char *cpVHostID;
    char *cpVHostMD5;
#ifdef SSL_EXPERIMENTAL_PROXY
    SSLSrvConfigRec *sc;
    char *cp;
#endif

    if (ap_ctx_get(r->ctx, "ssl::proxy::enabled") == PFALSE)
        return NULL;

    /*
     * Find context
     */
#ifdef SSL_EXPERIMENTAL_PROXY
    sc = mySrvConfig(r->server);
#endif
    cpVHostID = ssl_util_vhostid(r->pool, r->server);

    /*
     * Create a SSL context and handle
     */
#ifdef SSL_EXPERIMENTAL_PROXY
    ssl = SSL_new(sc->pSSLProxyCtx);
#else
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    ssl = SSL_new(ssl_ctx);
#endif
    if (ssl == NULL) {
        errmsg = ap_psprintf(r->pool, "SSL proxy new failed (%s): peer %s: %s",
                             cpVHostID, peer, ERR_reason_error_string(ERR_get_error()));
        ap_ctx_set(fb->ctx, "ssl", NULL);
        return errmsg;
    }
    SSL_clear(ssl);
    cpVHostMD5 = ap_md5(r->pool, (unsigned char *)cpVHostID);
    if (!SSL_set_session_id_context(ssl, (unsigned char *)cpVHostMD5, strlen(cpVHostMD5))) {
        errmsg = ap_psprintf(r->pool, "Unable to set session id context to `%s': peer %s: %s",
                             cpVHostMD5, peer, ERR_reason_error_string(ERR_get_error()));
        ap_ctx_set(fb->ctx, "ssl", NULL);
        return errmsg;
    }
    SSL_set_fd(ssl, fb->fd);
#ifdef SSL_EXPERIMENTAL_PROXY
    SSL_set_app_data(ssl, fb->ctx);
#endif
    ap_ctx_set(fb->ctx, "ssl", ssl);
#ifdef SSL_EXPERIMENTAL_PROXY
    ap_ctx_set(fb->ctx, "ssl::proxy::server_rec", r->server);
    ap_ctx_set(fb->ctx, "ssl::proxy::peer", peer);
    ap_ctx_set(fb->ctx, "ssl::proxy::servername", cpVHostID);
    ap_ctx_set(fb->ctx, "ssl::proxy::verifyerror", NULL);
#endif

    /*
     * Give us a chance to gracefully close the connection
     */
    ap_register_cleanup(r->pool, (void *)fb,
                        ssl_ext_mp_close_connection, ssl_ext_mp_close_connection);

    /*
     * Establish the SSL connection
     */
    if ((rc = SSL_connect(ssl)) <= 0) {
#ifdef SSL_EXPERIMENTAL_PROXY
        if ((cp = (char *)ap_ctx_get(fb->ctx, "ssl::proxy::verifyerror")) != NULL) {
            SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN); 
            SSL_smart_shutdown(ssl);
            SSL_free(ssl);
            ap_ctx_set(fb->ctx, "ssl", NULL);
            ap_bsetflag(fb, B_EOF|B_EOUT, 1);
            return NULL;
        }
#endif
        errmsg = ap_psprintf(r->pool, "SSL proxy connect failed (%s): peer %s: %s",
                             cpVHostID, peer, ERR_reason_error_string(ERR_get_error()));
        ssl_log(r->server, SSL_LOG_ERROR, errmsg);
        SSL_free(ssl);
        ap_ctx_set(fb->ctx, "ssl", NULL);
        return errmsg;
    }

    return NULL;
}

static void ssl_ext_mp_close_connection(void *_fb)
{
    BUFF *fb = _fb;
    SSL *ssl;
#ifndef SSL_EXPERIMENTAL_PROXY
    SSL_CTX *ctx;
#endif

    ssl = ap_ctx_get(fb->ctx, "ssl");
    if (ssl != NULL) {
#ifndef SSL_EXPERIMENTAL_PROXY
        ctx = SSL_get_SSL_CTX(ssl);
#endif
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_smart_shutdown(ssl);
        SSL_free(ssl);
        ap_ctx_set(fb->ctx, "ssl", NULL);
#ifndef SSL_EXPERIMENTAL_PROXY
        if (ctx != NULL)
            SSL_CTX_free(ctx);
#endif
    }
    return;
}

static int ssl_ext_mp_write_host_header(
    request_rec *r, BUFF *fb, char *host, int port, char *portstr)
{
    if (ap_ctx_get(r->ctx, "ssl::proxy::enabled") == PFALSE)
        return DECLINED;

    if (portstr != NULL && port != DEFAULT_HTTPS_PORT) {
        ap_bvputs(fb, "Host: ", host, ":", portstr, "\r\n", NULL);
        return OK;
    }
    return DECLINED;
}

#ifdef SSL_EXPERIMENTAL_PROXY

/* 
 * Callback for client certificate stuff.
 * If the remote site sent us a SSLv3 list of acceptable CA's then trawl the
 * table of client certs and send the first one that matches.
 */
static int ssl_ext_mp_clientcert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey) 
{
    SSLSrvConfigRec *sc;
    X509_NAME *xnx;
    X509_NAME *issuer;
    X509_INFO *xi;
    char *peer;
    char *servername;
    server_rec *s;
    ap_ctx *pCtx;
    STACK_OF(X509_NAME) *sk;
    STACK_OF(X509_INFO) *pcerts;
    char *cp;
    int i, j;
    
    pCtx       = (ap_ctx *)SSL_get_app_data(ssl);
    s          = ap_ctx_get(pCtx, "ssl::proxy::server_rec");
    peer       = ap_ctx_get(pCtx, "ssl::proxy::peer");
    servername = ap_ctx_get(pCtx, "ssl::proxy::servername");

    sc         = mySrvConfig(s);
    pcerts     = sc->skProxyClientCerts;

    ssl_log(s, SSL_LOG_DEBUG, 
            "Proxy client certificate callback: (%s) entered", servername);

    if ((pcerts == NULL) || (sk_X509_INFO_num(pcerts) <= 0)) {
        ssl_log(s, SSL_LOG_TRACE,
                "Proxy client certificate callback: (%s) "
                "site wanted client certificate but none available", 
                servername);
        return 0;
    }                                                                     

    sk = SSL_get_client_CA_list(ssl);

    if ((sk == NULL) || (sk_X509_NAME_num(sk) <= 0)) {
        /* 
         * remote site didn't send us a list of acceptable CA certs, 
         * so lets send the first one we came across 
         */   
        xi = sk_X509_INFO_value(pcerts, 0);
        cp  = X509_NAME_oneline(X509_get_subject_name(xi->x509), NULL, 0);
        ssl_log(s, SSL_LOG_DEBUG,
                "SSL Proxy: (%s) no acceptable CA list, sending %s", 
                servername, cp != NULL ? cp : "-unknown-");
        free(cp);
        /* export structures to the caller */
        *x509 = xi->x509;
        *pkey = xi->x_pkey->dec_pkey;
        /* prevent OpenSSL freeing these structures */
        CRYPTO_add(&((*x509)->references), +1, CRYPTO_LOCK_X509_PKEY);
        CRYPTO_add(&((*pkey)->references), +1, CRYPTO_LOCK_X509_PKEY);
        return 1;
    }         

    for (i = 0; i < sk_X509_NAME_num(sk); i++) {
        xnx = sk_X509_NAME_value(sk, i);
        for (j = 0; j < sk_X509_INFO_num(pcerts); j++) {
            xi = sk_X509_INFO_value(pcerts,j);
            issuer = X509_get_issuer_name(xi->x509);
            if (X509_NAME_cmp(issuer, xnx) == 0) {
                cp = X509_NAME_oneline(X509_get_subject_name(xi->x509), NULL, 0);
                ssl_log(s, SSL_LOG_DEBUG, "SSL Proxy: (%s) sending %s", 
                        servername, cp != NULL ? cp : "-unknown-");
                free(cp);
                /* export structures to the caller */
                *x509 = xi->x509;
                *pkey = xi->x_pkey->dec_pkey;
                /* prevent OpenSSL freeing these structures */
                CRYPTO_add(&((*x509)->references), +1, CRYPTO_LOCK_X509_PKEY);
                CRYPTO_add(&((*pkey)->references), +1, CRYPTO_LOCK_X509_PKEY);
                return 1;
            }
        }
    }
    ssl_log(s, SSL_LOG_TRACE,
            "Proxy client certificate callback: (%s) "
            "no client certificate found!?", servername);
    return 0; 
}

/*
 * This is the verify callback when we are connecting to a remote SSL server
 * from the proxy. Information is passed in via the SSL "ctx" app_data
 * mechanism. We pass in an Apache context in this field, which contains
 * server_rec of the server making the proxy connection from the
 * "ssl::proxy::server_rec" context.
 *
 * The result of the verification is passed back out to SSLERR via the return
 * value. We also store the error message in the "proxyverifyfailed" context,
 * so the caller of SSL_connect() can log a detailed error message.
 */
static int ssl_ext_mp_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    SSLSrvConfigRec *sc;
    X509 *xs;
    int errnum;
    int errdepth;
    char *cp, *cp2;
    ap_ctx *pCtx;
    server_rec *s;
    SSL *ssl;
    char *peer;
    char *servername;

    ssl        = (SSL *)X509_STORE_CTX_get_app_data(ctx);
    pCtx       = (ap_ctx *)SSL_get_app_data(ssl);
    s          = ap_ctx_get(pCtx, "ssl::proxy::server_rec");
    peer       = ap_ctx_get(pCtx, "ssl::proxy::peer");
    servername = ap_ctx_get(pCtx, "ssl::proxy::servername");
    sc         = mySrvConfig(s);

    /*
     * Unless stated otherwise by the configuration, we really don't
     * care if the verification was okay or not, so lets return now
     * before we do anything involving memory or time.
     */
    if (sc->bProxyVerify == FALSE)
        return ok;
                     
    /*
     * Get verify ingredients
     */
    xs       = X509_STORE_CTX_get_current_cert(ctx);
    errnum   = X509_STORE_CTX_get_error(ctx);
    errdepth = X509_STORE_CTX_get_error_depth(ctx);

    /* 
     * Log verification information
     */
    cp  = X509_NAME_oneline(X509_get_subject_name(xs), NULL, 0);
    cp2 = X509_NAME_oneline(X509_get_issuer_name(xs),  NULL, 0);
    ssl_log(s, SSL_LOG_DEBUG,
            "SSL Proxy: (%s) Certificate Verification for remote server %s: "
            "depth: %d, subject: %s, issuer: %s", 
            servername, peer != NULL ? peer : "-unknown-",
            errdepth, cp != NULL ? cp : "-unknown-", 
            cp2 != NULL ? cp2 : "-unknown");
    free(cp);
    free(cp2);

    /*
     * If we already know it's not ok, log the real reason
     */
    if (!ok) {
        ssl_log(s, SSL_LOG_ERROR,
                "SSL Proxy: (%s) Certificate Verification failed for %s: "
                "Error (%d): %s", servername,
                peer != NULL ? peer : "-unknown-",
                errnum, X509_verify_cert_error_string(errnum));
        ap_ctx_set(pCtx, "ssl::proxy::verifyerror", 
                   (void *)X509_verify_cert_error_string(errnum));
        return ok;
    }

    /*
     * Check the depth of the certificate chain
     */
    if (sc->nProxyVerifyDepth > 0) {
        if (errdepth > sc->nProxyVerifyDepth) {
            ssl_log(s, SSL_LOG_ERROR,
                "SSL Proxy: (%s) Certificate Verification failed for %s: "
                "Certificate Chain too long "
                "(chain has %d certificates, but maximum allowed are only %d)", 
                servername, peer, errdepth, sc->nProxyVerifyDepth);
            ap_ctx_set(pCtx, "ssl::proxy::verifyerror",
                       (void *)X509_verify_cert_error_string(X509_V_ERR_CERT_CHAIN_TOO_LONG));
            ok = FALSE;
        }
    }

    /*
     * And finally signal OpenSSL the (perhaps changed) state
     */
    return (ok);
}

#endif /* SSL_EXPERIMENTAL_PROXY */

#endif /* XXX */