/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_kernel.c
**  The SSL engine kernel
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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
                             /* ``It took me fifteen years to discover
                                  I had no talent for programming, but
                                  I couldn't give it up because by that
                                  time I was too famous.''
                                            -- Unknown                */
#include "mod_ssl.h"

/*
 *  Post Read Request Handler
 */
int ssl_hook_ReadReq(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSL *ssl;

    if (!sslconn) {
        return DECLINED;
    }

    if (sslconn->non_ssl_request) {
        const char *errmsg;
        char *thisurl;
        char *thisport = "";
        int port = ap_get_server_port(r);

        if (!ap_is_default_port(port, r)) {
            thisport = apr_psprintf(r->pool, ":%u", port);
        }

        thisurl = ap_escape_html(r->pool,
                                 apr_psprintf(r->pool, "https://%s%s/",
                                              ap_get_server_name(r),
                                              thisport));

        errmsg = apr_psprintf(r->pool,
                              "Reason: You're speaking plain HTTP "
                              "to an SSL-enabled server port.<br />\n"
                              "Instead use the HTTPS scheme to access "
                              "this URL, please.<br />\n"
                              "<blockquote>Hint: "
                              "<a href=\"%s\"><b>%s</b></a></blockquote>",
                              thisurl, thisurl);

        apr_table_setn(r->notes, "error-notes", errmsg);

        /* Now that we have caught this error, forget it. we are done
         * with using SSL on this request.
         */
        sslconn->non_ssl_request = 0;
        

        return HTTP_BAD_REQUEST;
    }

    /*
     * Get the SSL connection structure and perform the
     * delayed interlinking from SSL back to request_rec
     */
    if ((ssl = sslconn->ssl)) {
        SSL_set_app_data2(ssl, r);
    }

    return DECLINED;
}

/*
 * Move SetEnvIf information from request_rec to conn_rec/BUFF
 * to allow the close connection handler to use them.
 */

static void ssl_configure_env(request_rec *r, SSLConnRec *sslconn)
{
    int i;
    const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
    const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;

    sslconn->shutdown_type = SSL_SHUTDOWN_TYPE_STANDARD;

    for (i = 0; i < arr->nelts; i++) {
        const char *key = elts[i].key;

        switch (*key) {
          case 's':
            /* being case-sensitive here.
             * and not checking for the -shutdown since these are the only
             * SetEnvIf "flags" we support
             */
            if (!strncmp(key+1, "sl-", 3)) {
                key += 4;
                if (!strncmp(key, "unclean", 7)) {
                    sslconn->shutdown_type = SSL_SHUTDOWN_TYPE_UNCLEAN;
                }
                else if (!strncmp(key, "accurate", 8)) {
                    sslconn->shutdown_type = SSL_SHUTDOWN_TYPE_ACCURATE;
                }
                return; /* should only ever be one ssl-*-shutdown */
            }
            break;
        }
    }
}

/*
 *  URL Translation Handler
 */
int ssl_hook_Translate(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);

    if (!(sslconn && sslconn->ssl)) {
        return DECLINED;
    }

    /*
     * Log information about incoming HTTPS requests
     */
    if (r->server->loglevel >= APLOG_INFO && ap_is_initial_req(r)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "%s HTTPS request received for child %ld (server %s)",
                     (r->connection->keepalives <= 0 ?
                     "Initial (No.1)" :
                     apr_psprintf(r->pool, "Subsequent (No.%d)",
                                  r->connection->keepalives+1)),
                     r->connection->id,
                     ssl_util_vhostid(r->pool, r->server));
    }

    /* SetEnvIf ssl-*-shutdown flags can only be per-server,
     * so they won't change across keepalive requests
     */
    if (sslconn->shutdown_type == SSL_SHUTDOWN_TYPE_UNSET) {
        ssl_configure_env(r, sslconn);
    }

    return DECLINED;
}

/*
 *  Access Handler
 */
int ssl_hook_Access(request_rec *r)
{
    SSLDirConfigRec *dc = myDirConfig(r);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSL *ssl            = sslconn ? sslconn->ssl : NULL;
    SSL_CTX *ctx = NULL;
    apr_array_header_t *requires;
    ssl_require_t *ssl_requires;
    char *cp;
    int ok, i;
    BOOL renegotiate = FALSE, renegotiate_quick = FALSE;
    X509 *cert;
    X509 *peercert;
    X509_STORE *cert_store = NULL;
    X509_STORE_CTX cert_store_ctx;
    STACK_OF(SSL_CIPHER) *cipher_list_old = NULL, *cipher_list = NULL;
    SSL_CIPHER *cipher = NULL;
    int depth, verify_old, verify, n;

    if (ssl) {
        ctx = SSL_get_SSL_CTX(ssl);
    }

    /*
     * Support for SSLRequireSSL directive
     */
    if (dc->bSSLRequired && !ssl) {
        if (sc->enabled == UNSET) {
            /* This vhost was configured for optional SSL, just tell the
             * client that we need to upgrade.
             */
            apr_table_setn(r->err_headers_out, "Upgrade", "TLS/1.0, HTTP/1.1");
            apr_table_setn(r->err_headers_out, "Connection", "Upgrade");

            return HTTP_UPGRADE_REQUIRED;
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "access to %s failed, reason: %s",
                      r->filename, "SSL connection required");

        /* remember forbidden access for strict require option */
        apr_table_setn(r->notes, "ssl-access-forbidden", "1");

        return HTTP_FORBIDDEN;
    }

    /*
     * Check to see if SSL protocol is on
     */
    if (!(sc->enabled || ssl)) {
        return DECLINED;
    }
    /*
     * Support for per-directory reconfigured SSL connection parameters.
     *
     * This is implemented by forcing an SSL renegotiation with the
     * reconfigured parameter suite. But Apache's internal API processing
     * makes our life very hard here, because when internal sub-requests occur
     * we nevertheless should avoid multiple unnecessary SSL handshakes (they
     * require extra network I/O and especially time to perform). 
     * 
     * But the optimization for filtering out the unnecessary handshakes isn't
     * obvious and trivial.  Especially because while Apache is in its
     * sub-request processing the client could force additional handshakes,
     * too. And these take place perhaps without our notice. So the only
     * possibility is to explicitly _ask_ OpenSSL whether the renegotiation
     * has to be performed or not. It has to performed when some parameters
     * which were previously known (by us) are not those we've now
     * reconfigured (as known by OpenSSL) or (in optimized way) at least when
     * the reconfigured parameter suite is stronger (more restrictions) than
     * the currently active one.
     */

    /*
     * Override of SSLCipherSuite
     *
     * We provide two options here:
     *
     * o The paranoid and default approach where we force a renegotiation when
     *   the cipher suite changed in _any_ way (which is straight-forward but
     *   often forces renegotiations too often and is perhaps not what the
     *   user actually wanted).
     *
     * o The optimized and still secure way where we force a renegotiation
     *   only if the currently active cipher is no longer contained in the
     *   reconfigured/new cipher suite. Any other changes are not important
     *   because it's the servers choice to select a cipher from the ones the
     *   client supports. So as long as the current cipher is still in the new
     *   cipher suite we're happy. Because we can assume we would have
     *   selected it again even when other (better) ciphers exists now in the
     *   new cipher suite. This approach is fine because the user explicitly
     *   has to enable this via ``SSLOptions +OptRenegotiate''. So we do no
     *   implicit optimizations.
     */
    if (dc->szCipherSuite) {
        /* remember old state */

        if (dc->nOptions & SSL_OPT_OPTRENEGOTIATE) {
            cipher = SSL_get_current_cipher(ssl);
        }
        else {
            cipher_list_old = (STACK_OF(SSL_CIPHER) *)SSL_get_ciphers(ssl);

            if (cipher_list_old) {
                cipher_list_old = sk_SSL_CIPHER_dup(cipher_list_old);
            }
        }

        /* configure new state */
        if (!modssl_set_cipher_list(ssl, dc->szCipherSuite)) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                         r->server,
                         "Unable to reconfigure (per-directory) "
                         "permitted SSL ciphers");
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, r->server);

            if (cipher_list_old) {
                sk_SSL_CIPHER_free(cipher_list_old);
            }

            return HTTP_FORBIDDEN;
        }

        /* determine whether a renegotiation has to be forced */
        cipher_list = (STACK_OF(SSL_CIPHER) *)SSL_get_ciphers(ssl);

        if (dc->nOptions & SSL_OPT_OPTRENEGOTIATE) {
            /* optimized way */
            if ((!cipher && cipher_list) ||
                (cipher && !cipher_list))
            {
                renegotiate = TRUE;
            }
            else if (cipher && cipher_list &&
                     (sk_SSL_CIPHER_find(cipher_list, cipher) < 0))
            {
                renegotiate = TRUE;
            }
        }
        else {
            /* paranoid way */
            if ((!cipher_list_old && cipher_list) ||
                (cipher_list_old && !cipher_list))
            {
                renegotiate = TRUE;
            }
            else if (cipher_list_old && cipher_list) {
                for (n = 0;
                     !renegotiate && (n < sk_SSL_CIPHER_num(cipher_list));
                     n++)
                {
                    SSL_CIPHER *value = sk_SSL_CIPHER_value(cipher_list, n);

                    if (sk_SSL_CIPHER_find(cipher_list_old, value) < 0) {
                        renegotiate = TRUE;
                    }
                }

                for (n = 0;
                     !renegotiate && (n < sk_SSL_CIPHER_num(cipher_list_old));
                     n++)
                {
                    SSL_CIPHER *value = sk_SSL_CIPHER_value(cipher_list_old, n);

                    if (sk_SSL_CIPHER_find(cipher_list, value) < 0) {
                        renegotiate = TRUE;
                    }
                }
            }
        }

        /* cleanup */
        if (cipher_list_old) {
            sk_SSL_CIPHER_free(cipher_list_old);
        }

        /* tracing */
        if (renegotiate) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Reconfigured cipher suite will force renegotiation");
        }
    }

    /*
     * override of SSLVerifyDepth
     *
     * The depth checks are handled by us manually inside the verify callback
     * function and not by OpenSSL internally (and our function is aware of
     * both the per-server and per-directory contexts). So we cannot ask
     * OpenSSL about the currently verify depth. Instead we remember it in our
     * ap_ctx attached to the SSL* of OpenSSL.  We've to force the
     * renegotiation if the reconfigured/new verify depth is less than the
     * currently active/remembered verify depth (because this means more
     * restriction on the certificate chain).
     */
    if (dc->nVerifyDepth != UNSET) {
        /* XXX: doesnt look like sslconn->verify_depth is actually used */
        if (!(n = sslconn->verify_depth)) {
            sslconn->verify_depth = n = sc->server->auth.verify_depth;
        }

        /* determine whether a renegotiation has to be forced */
        if (dc->nVerifyDepth < n) {
            renegotiate = TRUE;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Reduced client verification depth will force "
                         "renegotiation");
        }
    }

    /*
     * override of SSLVerifyClient
     *
     * We force a renegotiation if the reconfigured/new verify type is
     * stronger than the currently active verify type. 
     *
     * The order is: none << optional_no_ca << optional << require
     *
     * Additionally the following optimization is possible here: When the
     * currently active verify type is "none" but a client certificate is
     * already known/present, it's enough to manually force a client
     * verification but at least skip the I/O-intensive renegotation
     * handshake.
     */
    if (dc->nVerifyClient != SSL_CVERIFY_UNSET) {
        /* remember old state */
        verify_old = SSL_get_verify_mode(ssl);
        /* configure new state */
        verify = SSL_VERIFY_NONE;

        if (dc->nVerifyClient == SSL_CVERIFY_REQUIRE) {
            verify |= SSL_VERIFY_PEER_STRICT;
        }

        if ((dc->nVerifyClient == SSL_CVERIFY_OPTIONAL) ||
            (dc->nVerifyClient == SSL_CVERIFY_OPTIONAL_NO_CA))
        {
            verify |= SSL_VERIFY_PEER;
        }

        modssl_set_verify(ssl, verify, ssl_callback_SSLVerify);
        SSL_set_verify_result(ssl, X509_V_OK);

        /* determine whether we've to force a renegotiation */
        if (!renegotiate && verify != verify_old) {
            if (((verify_old == SSL_VERIFY_NONE) &&
                 (verify     != SSL_VERIFY_NONE)) ||

                (!(verify_old & SSL_VERIFY_PEER) &&
                  (verify     & SSL_VERIFY_PEER)) ||

                (!(verify_old & SSL_VERIFY_PEER_STRICT) &&
                  (verify     & SSL_VERIFY_PEER_STRICT)))
            {
                renegotiate = TRUE;
                /* optimization */

                if ((dc->nOptions & SSL_OPT_OPTRENEGOTIATE) &&
                    (verify_old == SSL_VERIFY_NONE) &&
                    ((peercert = SSL_get_peer_certificate(ssl)) != NULL))
                {
                    renegotiate_quick = TRUE;
                    X509_free(peercert);
                }

                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                             r->server,
                             "Changed client verification type will force "
                             "%srenegotiation",
                             renegotiate_quick ? "quick " : "");
             }
        }
    }

    /*
     * override SSLCACertificateFile & SSLCACertificatePath
     * This is only enabled if the SSL_set_cert_store() function
     * is available in the ssl library.  the 1.x based mod_ssl
     * used SSL_CTX_set_cert_store which is not thread safe.
     */

#ifdef HAVE_SSL_SET_CERT_STORE
    /*
     * check if per-dir and per-server config field are not the same.
     * if f is defined in per-dir and not defined in per-server
     * or f is defined in both but not the equal ...
     */
#define MODSSL_CFG_NE(f) \
     (dc->f && (!sc->f || (sc->f && strNE(dc->f, sc->f))))

#define MODSSL_CFG_CA(f) \
     (dc->f ? dc->f : sc->f)

    if (MODSSL_CFG_NE(szCACertificateFile) ||
        MODSSL_CFG_NE(szCACertificatePath))
    {
        STACK_OF(X509_NAME) *ca_list;
        const char *ca_file = MODSSL_CFG_CA(szCACertificateFile);
        const char *ca_path = MODSSL_CFG_CA(szCACertificatePath);

        cert_store = X509_STORE_new();

        if (!X509_STORE_load_locations(cert_store, ca_file, ca_path)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "Unable to reconfigure verify locations "
                         "for client authentication");
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, r->server);

            X509_STORE_free(cert_store);

            return HTTP_FORBIDDEN;
        }

        /* SSL_free will free cert_store */
        SSL_set_cert_store(ssl, cert_store);

        if (!(ca_list = ssl_init_FindCAList(r->server, r->pool,
                                            ca_file, ca_path)))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "Unable to determine list of available "
                         "CA certificates for client authentication");

            return HTTP_FORBIDDEN;
        }

        SSL_set_client_CA_list(ssl, ca_list);
        renegotiate = TRUE;

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "Changed client verification locations will force "
                     "renegotiation");
    }
#endif /* HAVE_SSL_SET_CERT_STORE */

    /* 
     * SSL renegotiations in conjunction with HTTP
     * requests using the POST method are not supported.
     *
     * Background:
     *
     * 1. When the client sends a HTTP/HTTPS request, Apache's core code
     * reads only the request line ("METHOD /path HTTP/x.y") and the
     * attached MIME headers ("Foo: bar") up to the terminating line ("CR
     * LF"). An attached request body (for instance the data of a POST
     * method) is _NOT_ read. Instead it is read by mod_cgi's content
     * handler and directly passed to the CGI script.
     *
     * 2. mod_ssl supports per-directory re-configuration of SSL parameters.
     * This is implemented by performing an SSL renegotiation of the
     * re-configured parameters after the request is read, but before the
     * response is sent. In more detail: the renegotiation happens after the
     * request line and MIME headers were read, but _before_ the attached
     * request body is read. The reason simply is that in the HTTP protocol
     * usually there is no acknowledgment step between the headers and the
     * body (there is the 100-continue feature and the chunking facility
     * only), so Apache has no API hook for this step.
     *
     * 3. the problem now occurs when the client sends a POST request for
     * URL /foo via HTTPS the server and the server has SSL parameters
     * re-configured on a per-URL basis for /foo. Then mod_ssl has to
     * perform an SSL renegotiation after the request was read and before
     * the response is sent. But the problem is the pending POST body data
     * in the receive buffer of SSL (which Apache still has not read - it's
     * pending until mod_cgi sucks it in). When mod_ssl now tries to perform
     * the renegotiation the pending data leads to an I/O error.
     *
     * Solution Idea:
     *
     * There are only two solutions: Either to simply state that POST
     * requests to URLs with SSL re-configurations are not allowed, or to
     * renegotiate really after the _complete_ request (i.e. including
     * the POST body) was read. Obviously the latter would be preferred,
     * but it cannot be done easily inside Apache, because as already
     * mentioned, there is no API step between the body reading and the body
     * processing. And even when we mod_ssl would hook directly into the
     * loop of mod_cgi, we wouldn't solve the problem for other handlers, of
     * course. So the only general solution is to suck in the pending data
     * of the request body from the OpenSSL BIO into the Apache BUFF. Then
     * the renegotiation can be done and after this step Apache can proceed
     * processing the request as before.
     *
     * Solution Implementation:
     *
     * We cannot simply suck in the data via an SSL_read-based loop because of
     * HTTP chunking. Instead we _have_ to use the Apache API for this step which
     * is aware of HTTP chunking. So the trick is to suck in the pending request
     * data via the Apache API (which uses Apache's BUFF code and in the
     * background mod_ssl's I/O glue code) and re-inject it later into the Apache
     * BUFF code again. This way the data flows twice through the Apache BUFF, of
     * course. But this way the solution doesn't depend on any Apache specifics
     * and is fully transparent to Apache modules.
     *
     * !! BUT ALL THIS IS STILL NOT RE-IMPLEMENTED FOR APACHE 2.0 !!
     */
    if (renegotiate && !renegotiate_quick && (r->method_number == M_POST)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "SSL Re-negotiation in conjunction "
                     "with POST method not supported!\n"
                     "hint: try SSLOptions +OptRenegotiate");

        return HTTP_METHOD_NOT_ALLOWED;
    }

    /*
     * now do the renegotiation if anything was actually reconfigured
     */
    if (renegotiate) {
        /*
         * Now we force the SSL renegotation by sending the Hello Request
         * message to the client. Here we have to do a workaround: Actually
         * OpenSSL returns immediately after sending the Hello Request (the
         * intent AFAIK is because the SSL/TLS protocol says it's not a must
         * that the client replies to a Hello Request). But because we insist
         * on a reply (anything else is an error for us) we have to go to the
         * ACCEPT state manually. Using SSL_set_accept_state() doesn't work
         * here because it resets too much of the connection.  So we set the
         * state explicitly and continue the handshake manually.
         */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "Requesting connection re-negotiation");

        if (renegotiate_quick) {
            STACK_OF(X509) *cert_stack;

            /* perform just a manual re-verification of the peer */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Performing quick renegotiation: "
                         "just re-verifying the peer");

            cert_stack = (STACK_OF(X509) *)SSL_get_peer_cert_chain(ssl);

            cert = SSL_get_peer_certificate(ssl);

            if (!cert_stack && cert) {
                /* client cert is in the session cache, but there is
                 * no chain, since ssl3_get_client_certificate()
                 * sk_X509_shift-ed the peer cert out of the chain.
                 * we put it back here for the purpose of quick_renegotiation.
                 */
                cert_stack = sk_new_null();
                sk_X509_push(cert_stack, MODSSL_PCHAR_CAST cert);
            }

            if (!cert_stack || (sk_X509_num(cert_stack) == 0)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Cannot find peer certificate chain");

                return HTTP_FORBIDDEN;
            }

            if (!(cert_store ||
                  (cert_store = SSL_CTX_get_cert_store(ctx))))
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Cannot find certificate storage");

                return HTTP_FORBIDDEN;
            }

            if (!cert) {
                cert = sk_X509_value(cert_stack, 0);
            }

            X509_STORE_CTX_init(&cert_store_ctx, cert_store, cert, cert_stack);
            depth = SSL_get_verify_depth(ssl);

            if (depth >= 0) {
                X509_STORE_CTX_set_depth(&cert_store_ctx, depth);
            }

            X509_STORE_CTX_set_ex_data(&cert_store_ctx,
                                       SSL_get_ex_data_X509_STORE_CTX_idx(),
                                       (char *)ssl);

            if (!modssl_X509_verify_cert(&cert_store_ctx)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Re-negotiation verification step failed");
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, r->server);
            }

            SSL_set_verify_result(ssl, cert_store_ctx.error);
            X509_STORE_CTX_cleanup(&cert_store_ctx);

            if (cert_stack != SSL_get_peer_cert_chain(ssl)) {
                /* we created this ourselves, so free it */
                sk_X509_pop_free(cert_stack, X509_free);
            }
        }
        else {
            request_rec *id = r->main ? r->main : r;

            /* do a full renegotiation */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Performing full renegotiation: "
                         "complete handshake protocol");

            SSL_set_session_id_context(ssl,
                                       (unsigned char *)&id,
                                       sizeof(id));

            SSL_renegotiate(ssl);
            SSL_do_handshake(ssl);

            if (SSL_get_state(ssl) != SSL_ST_OK) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Re-negotiation request failed");

                r->connection->aborted = 1;
                return HTTP_FORBIDDEN;
            }

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "Awaiting re-negotiation handshake");

            /* XXX: Should replace SSL_set_state with SSL_renegotiate(ssl);
             * However, this causes failures in perl-framework currently, 
             * perhaps pre-test if we have already negotiated?
             */
            SSL_set_state(ssl, SSL_ST_ACCEPT);
            SSL_do_handshake(ssl);

            if (SSL_get_state(ssl) != SSL_ST_OK) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Re-negotiation handshake failed: "
                        "Not accepted by client!?");

                r->connection->aborted = 1;
                return HTTP_FORBIDDEN;
            }
        }

        /*
         * Remember the peer certificate's DN
         */
        if ((cert = SSL_get_peer_certificate(ssl))) {
            if (sslconn->client_cert) {
                X509_free(sslconn->client_cert);
            }
            sslconn->client_cert = cert;
            sslconn->client_dn = NULL;
        }

        /*
         * Finally check for acceptable renegotiation results
         */
        if (dc->nVerifyClient != SSL_CVERIFY_NONE) {
            BOOL do_verify = (dc->nVerifyClient == SSL_CVERIFY_REQUIRE);

            if (do_verify && (SSL_get_verify_result(ssl) != X509_V_OK)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Re-negotiation handshake failed: "
                             "Client verification failed");

                return HTTP_FORBIDDEN;
            }

            if (do_verify) {
                if ((peercert = SSL_get_peer_certificate(ssl)) == NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                 "Re-negotiation handshake failed: "
                                 "Client certificate missing");

                    return HTTP_FORBIDDEN;
                }

                X509_free(peercert);
            }
        }
    }

    /*
     * Check SSLRequire boolean expressions
     */
    requires = dc->aRequirement;
    ssl_requires = (ssl_require_t *)requires->elts;

    for (i = 0; i < requires->nelts; i++) {
        ssl_require_t *req = &ssl_requires[i];
        ok = ssl_expr_exec(r, req->mpExpr);

        if (ok < 0) {
            cp = apr_psprintf(r->pool,
                              "Failed to execute "
                              "SSL requirement expression: %s",
                              ssl_expr_get_error());

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "access to %s failed, reason: %s",
                          r->filename, cp);

            /* remember forbidden access for strict require option */
            apr_table_setn(r->notes, "ssl-access-forbidden", "1");

            return HTTP_FORBIDDEN;
        }

        if (ok != 1) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "Access to %s denied for %s "
                         "(requirement expression not fulfilled)",
                         r->filename, r->connection->remote_ip);

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "Failed expression: %s", req->cpExpr);

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "access to %s failed, reason: %s",
                          r->filename,
                          "SSL requirement expression not fulfilled "
                          "(see SSL logfile for more details)");

            /* remember forbidden access for strict require option */
            apr_table_setn(r->notes, "ssl-access-forbidden", "1");

            return HTTP_FORBIDDEN;
        }
    }

    /*
     * Else access is granted from our point of view (except vendor
     * handlers override). But we have to return DECLINED here instead
     * of OK, because mod_auth and other modules still might want to
     * deny access.
     */

    return DECLINED;
}

/*
 *  Authentication Handler:
 *  Fake a Basic authentication from the X509 client certificate.
 *
 *  This must be run fairly early on to prevent a real authentication from
 *  occuring, in particular it must be run before anything else that
 *  authenticates a user.  This means that the Module statement for this
 *  module should be LAST in the Configuration file.
 */
int ssl_hook_UserCheck(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLDirConfigRec *dc = myDirConfig(r);
    char buf1[MAX_STRING_LEN], buf2[MAX_STRING_LEN];
    char *clientdn;
    const char *auth_line, *username, *password;

    /*
     * Additionally forbid access (again)
     * when strict require option is used.
     */
    if ((dc->nOptions & SSL_OPT_STRICTREQUIRE) &&
        (apr_table_get(r->notes, "ssl-access-forbidden")))
    {
        return HTTP_FORBIDDEN;
    }

    /*
     * We decline when we are in a subrequest.  The Authorization header
     * would already be present if it was added in the main request.
     */
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /*
     * Make sure the user is not able to fake the client certificate
     * based authentication by just entering an X.509 Subject DN
     * ("/XX=YYY/XX=YYY/..") as the username and "password" as the
     * password.
     */
    if ((auth_line = apr_table_get(r->headers_in, "Authorization"))) {
        if (strcEQ(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
            while ((*auth_line == ' ') || (*auth_line == '\t')) {
                auth_line++;
            }

            auth_line = ap_pbase64decode(r->pool, auth_line);
            username = ap_getword_nulls(r->pool, &auth_line, ':');
            password = auth_line;

            if ((username[0] == '/') && strEQ(password, "password")) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "Encountered FakeBasicAuth spoof: %s", username);
                return HTTP_FORBIDDEN;
            }
        }
    }

    /*
     * We decline operation in various situations...
     * - SSLOptions +FakeBasicAuth not configured
     * - r->user already authenticated
     * - ssl not enabled
     * - client did not present a certificate
     */
    if (!(sc->enabled && sslconn->ssl && sslconn->client_cert) ||
        !(dc->nOptions & SSL_OPT_FAKEBASICAUTH) || r->user)
    {
        return DECLINED;
    }
    
    if (!sslconn->client_dn) {
        X509_NAME *name = X509_get_subject_name(sslconn->client_cert);
        char *cp = X509_NAME_oneline(name, NULL, 0);
        sslconn->client_dn = apr_pstrdup(r->connection->pool, cp);
        modssl_free(cp);
    }

    clientdn = (char *)sslconn->client_dn;

    /*
     * Fake a password - which one would be immaterial, as, it seems, an empty
     * password in the users file would match ALL incoming passwords, if only
     * we were using the standard crypt library routine. Unfortunately, OpenSSL
     * "fixes" a "bug" in crypt and thus prevents blank passwords from
     * working.  (IMHO what they really fix is a bug in the users of the code
     * - failing to program correctly for shadow passwords).  We need,
     * therefore, to provide a password. This password can be matched by
     * adding the string "xxj31ZMTZzkVA" as the password in the user file.
     * This is just the crypted variant of the word "password" ;-)
     */
    apr_snprintf(buf1, sizeof(buf1), "%s:password", clientdn);
    ssl_util_uuencode(buf2, buf1, FALSE);

    apr_snprintf(buf1, sizeof(buf1), "Basic %s", buf2);
    apr_table_set(r->headers_in, "Authorization", buf1);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                 "Faking HTTP Basic Auth header: \"Authorization: %s\"", buf1);

    return DECLINED;
}

/* authorization phase */
int ssl_hook_Auth(request_rec *r)
{
    SSLDirConfigRec *dc = myDirConfig(r);

    /*
     * Additionally forbid access (again)
     * when strict require option is used.
     */
    if ((dc->nOptions & SSL_OPT_STRICTREQUIRE) &&
        (apr_table_get(r->notes, "ssl-access-forbidden")))
    {
        return HTTP_FORBIDDEN;
    }

    return DECLINED;
}

/*
 *   Fixup Handler
 */

static const char *ssl_hook_Fixup_vars[] = {
    "SSL_VERSION_INTERFACE",
    "SSL_VERSION_LIBRARY",
    "SSL_PROTOCOL",
    "SSL_CIPHER",
    "SSL_CIPHER_EXPORT",
    "SSL_CIPHER_USEKEYSIZE",
    "SSL_CIPHER_ALGKEYSIZE",
    "SSL_CLIENT_VERIFY",
    "SSL_CLIENT_M_VERSION",
    "SSL_CLIENT_M_SERIAL",
    "SSL_CLIENT_V_START",
    "SSL_CLIENT_V_END",
    "SSL_CLIENT_S_DN",
    "SSL_CLIENT_S_DN_C",
    "SSL_CLIENT_S_DN_ST",
    "SSL_CLIENT_S_DN_L",
    "SSL_CLIENT_S_DN_O",
    "SSL_CLIENT_S_DN_OU",
    "SSL_CLIENT_S_DN_CN",
    "SSL_CLIENT_S_DN_T",
    "SSL_CLIENT_S_DN_I",
    "SSL_CLIENT_S_DN_G",
    "SSL_CLIENT_S_DN_S",
    "SSL_CLIENT_S_DN_D",
    "SSL_CLIENT_S_DN_UID",
    "SSL_CLIENT_S_DN_Email",
    "SSL_CLIENT_I_DN",
    "SSL_CLIENT_I_DN_C",
    "SSL_CLIENT_I_DN_ST",
    "SSL_CLIENT_I_DN_L",
    "SSL_CLIENT_I_DN_O",
    "SSL_CLIENT_I_DN_OU",
    "SSL_CLIENT_I_DN_CN",
    "SSL_CLIENT_I_DN_T",
    "SSL_CLIENT_I_DN_I",
    "SSL_CLIENT_I_DN_G",
    "SSL_CLIENT_I_DN_S",
    "SSL_CLIENT_I_DN_D",
    "SSL_CLIENT_I_DN_UID",
    "SSL_CLIENT_I_DN_Email",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
    "SSL_SERVER_S_DN",
    "SSL_SERVER_S_DN_C",
    "SSL_SERVER_S_DN_ST",
    "SSL_SERVER_S_DN_L",
    "SSL_SERVER_S_DN_O",
    "SSL_SERVER_S_DN_OU",
    "SSL_SERVER_S_DN_CN",
    "SSL_SERVER_S_DN_T",
    "SSL_SERVER_S_DN_I",
    "SSL_SERVER_S_DN_G",
    "SSL_SERVER_S_DN_S",
    "SSL_SERVER_S_DN_D",
    "SSL_SERVER_S_DN_UID",
    "SSL_SERVER_S_DN_Email",
    "SSL_SERVER_I_DN",
    "SSL_SERVER_I_DN_C",
    "SSL_SERVER_I_DN_ST",
    "SSL_SERVER_I_DN_L",
    "SSL_SERVER_I_DN_O",
    "SSL_SERVER_I_DN_OU",
    "SSL_SERVER_I_DN_CN",
    "SSL_SERVER_I_DN_T",
    "SSL_SERVER_I_DN_I",
    "SSL_SERVER_I_DN_G",
    "SSL_SERVER_I_DN_S",
    "SSL_SERVER_I_DN_D",
    "SSL_SERVER_I_DN_UID",
    "SSL_SERVER_I_DN_Email",
    "SSL_SERVER_A_KEY",
    "SSL_SERVER_A_SIG",
    "SSL_SESSION_ID",
    NULL
};

int ssl_hook_Fixup(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLDirConfigRec *dc = myDirConfig(r);
    apr_table_t *env = r->subprocess_env;
    char *var, *val = "";
    STACK_OF(X509) *peer_certs;
    SSL *ssl;
    int i;

    if (sc->enabled == UNSET) {
        apr_table_setn(r->headers_out, "Upgrade", "TLS/1.0, HTTP/1.1");
    }

    /*
     * Check to see if SSL is on
     */
    if (!(sc->enabled && sslconn && (ssl = sslconn->ssl))) {
        return DECLINED;
    }

    /*
     * Annotate the SSI/CGI environment with standard SSL information
     */
    /* the always present HTTPS (=HTTP over SSL) flag! */
    apr_table_setn(env, "HTTPS", "on"); 

    /* standard SSL environment variables */
    if (dc->nOptions & SSL_OPT_STDENVVARS) {
        for (i = 0; ssl_hook_Fixup_vars[i]; i++) {
            var = (char *)ssl_hook_Fixup_vars[i];
            val = ssl_var_lookup(r->pool, r->server, r->connection, r, var);
            if (!strIsEmpty(val)) {
                apr_table_setn(env, var, val);
            }
        }
    }

    /*
     * On-demand bloat up the SSI/CGI environment with certificate data
     */
    if (dc->nOptions & SSL_OPT_EXPORTCERTDATA) {
        val = ssl_var_lookup(r->pool, r->server, r->connection,
                             r, "SSL_SERVER_CERT");

        apr_table_setn(env, "SSL_SERVER_CERT", val);

        val = ssl_var_lookup(r->pool, r->server, r->connection,
                             r, "SSL_CLIENT_CERT");

        apr_table_setn(env, "SSL_CLIENT_CERT", val);

        if ((peer_certs = (STACK_OF(X509) *)SSL_get_peer_cert_chain(ssl))) {
            for (i = 0; i < sk_X509_num(peer_certs); i++) {
                var = apr_psprintf(r->pool, "SSL_CLIENT_CERT_CHAIN_%d", i);
                val = ssl_var_lookup(r->pool, r->server, r->connection,
                                     r, var);
                if (val) {
                    apr_table_setn(env, var, val);
                }
            }
        }
    }

    return DECLINED;
}

/*  _________________________________________________________________
**
**  OpenSSL Callback Functions
**  _________________________________________________________________
*/

/*
 * Handle out temporary RSA private keys on demand
 *
 * The background of this as the TLSv1 standard explains it:
 *
 * | D.1. Temporary RSA keys
 * |
 * |    US Export restrictions limit RSA keys used for encryption to 512
 * |    bits, but do not place any limit on lengths of RSA keys used for
 * |    signing operations. Certificates often need to be larger than 512
 * |    bits, since 512-bit RSA keys are not secure enough for high-value
 * |    transactions or for applications requiring long-term security. Some
 * |    certificates are also designated signing-only, in which case they
 * |    cannot be used for key exchange.
 * |
 * |    When the public key in the certificate cannot be used for encryption,
 * |    the server signs a temporary RSA key, which is then exchanged. In
 * |    exportable applications, the temporary RSA key should be the maximum
 * |    allowable length (i.e., 512 bits). Because 512-bit RSA keys are
 * |    relatively insecure, they should be changed often. For typical
 * |    electronic commerce applications, it is suggested that keys be
 * |    changed daily or every 500 transactions, and more often if possible.
 * |    Note that while it is acceptable to use the same temporary key for
 * |    multiple transactions, it must be signed each time it is used.
 * |
 * |    RSA key generation is a time-consuming process. In many cases, a
 * |    low-priority process can be assigned the task of key generation.
 * |    Whenever a new key is completed, the existing temporary key can be
 * |    replaced with the new one.
 *
 * XXX: base on comment above, if thread support is enabled,
 * we should spawn a low-priority thread to generate new keys
 * on the fly.
 *
 * So we generated 512 and 1024 bit temporary keys on startup
 * which we now just hand out on demand....
 */

RSA *ssl_callback_TmpRSA(SSL *ssl, int export, int keylen)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    SSLModConfigRec *mc = myModConfig(c->base_server);
    int idx;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
                 "handing out temporary %d bit RSA key", keylen);

    /* doesn't matter if export flag is on,
     * we won't be asked for keylen > 512 in that case.
     * if we are asked for a keylen > 1024, it is too expensive
     * to generate on the fly.
     * XXX: any reason not to generate 2048 bit keys at startup?
     */

    switch (keylen) {
      case 512:
        idx = SSL_TMP_KEY_RSA_512;
        break;

      case 1024:
      default:
        idx = SSL_TMP_KEY_RSA_1024;
    }

    return (RSA *)mc->pTmpKeys[idx];
}

/* 
 * Hand out the already generated DH parameters...
 */
DH *ssl_callback_TmpDH(SSL *ssl, int export, int keylen)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    SSLModConfigRec *mc = myModConfig(c->base_server);
    int idx;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
                 "handing out temporary %d bit DH key", keylen);

    switch (keylen) {
      case 512:
        idx = SSL_TMP_KEY_DH_512;
        break;

      case 1024:
      default:
        idx = SSL_TMP_KEY_DH_1024;
    }

    return (DH *)mc->pTmpKeys[idx];
}

/*
 * This OpenSSL callback function is called when OpenSSL
 * does client authentication and verifies the certificate chain.
 */
int ssl_callback_SSLVerify(int ok, X509_STORE_CTX *ctx)
{
    /* Get Apache context back through OpenSSL context */
    SSL *ssl            = (SSL *)X509_STORE_CTX_get_app_data(ctx);
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s       = conn->base_server;
    request_rec *r      = (request_rec *)SSL_get_app_data2(ssl);

    SSLSrvConfigRec *sc = mySrvConfig(s);
    SSLDirConfigRec *dc = r ? myDirConfig(r) : NULL;
    SSLConnRec *sslconn = myConnConfig(conn);
    modssl_ctx_t *mctx  = myCtxConfig(sslconn, sc);

    /* Get verify ingredients */
    int errnum   = X509_STORE_CTX_get_error(ctx);
    int errdepth = X509_STORE_CTX_get_error_depth(ctx);
    int depth, verify;

    /*
     * Log verification information
     */
    if (s->loglevel >= APLOG_DEBUG) {
        X509 *cert  = X509_STORE_CTX_get_current_cert(ctx);
        char *sname = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char *iname = X509_NAME_oneline(X509_get_issuer_name(cert),  NULL, 0);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "Certificate Verification: "
                     "depth: %d, subject: %s, issuer: %s",
                     errdepth,
                     sname ? sname : "-unknown-",
                     iname ? iname : "-unknown-");

        if (sname) {
            modssl_free(sname);
        }

        if (iname) {
            modssl_free(iname);
        }
    }

    /*
     * Check for optionally acceptable non-verifiable issuer situation
     */
    if (dc && (dc->nVerifyClient != SSL_CVERIFY_UNSET)) {
        verify = dc->nVerifyClient;
    }
    else {
        verify = mctx->auth.verify_mode;
    }

    if (verify == SSL_CVERIFY_NONE) {
        /* 
         * SSLProxyVerify is either not configured or set to "none".
         * (this callback doesn't happen in the server context if SSLVerify
         *  is not configured or set to "none")
         */
        return TRUE;
    }

    if (ssl_verify_error_is_optional(errnum) &&
        (verify == SSL_CVERIFY_OPTIONAL_NO_CA))
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "Certificate Verification: Verifiable Issuer is "
                     "configured as optional, therefore we're accepting "
                     "the certificate");

        sslconn->verify_info = "GENEROUS";
        ok = TRUE;
    }

    /*
     * Additionally perform CRL-based revocation checks
     */
    if (ok) {
        if (!(ok = ssl_callback_SSLVerify_CRL(ok, ctx, conn))) {
            errnum = X509_STORE_CTX_get_error(ctx);
        }
    }

    /*
     * If we already know it's not ok, log the real reason
     */
    if (!ok) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Certificate Verification: Error (%d): %s",
                     errnum, X509_verify_cert_error_string(errnum));

        if (sslconn->client_cert) {
            X509_free(sslconn->client_cert);
            sslconn->client_cert = NULL;
        }
        sslconn->client_dn = NULL;
        sslconn->verify_error = X509_verify_cert_error_string(errnum);
    }

    /*
     * Finally check the depth of the certificate verification
     */
    if (dc && (dc->nVerifyDepth != UNSET)) {
        depth = dc->nVerifyDepth;
    }
    else {
        depth = mctx->auth.verify_depth;
    }

    if (errdepth > depth) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Certificate Verification: Certificate Chain too long "
                     "(chain has %d certificates, but maximum allowed are "
                     "only %d)",
                     errdepth, depth);

        errnum = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        sslconn->verify_error = X509_verify_cert_error_string(errnum);

        ok = FALSE;
    }

    /*
     * And finally signal OpenSSL the (perhaps changed) state
     */
    return ok;
}

int ssl_callback_SSLVerify_CRL(int ok, X509_STORE_CTX *ctx, conn_rec *c)
{
    server_rec *s       = c->base_server;
    SSLSrvConfigRec *sc = mySrvConfig(s);
    SSLConnRec *sslconn = myConnConfig(c);
    modssl_ctx_t *mctx  = myCtxConfig(sslconn, sc);
    X509_OBJECT obj;
    X509_NAME *subject, *issuer;
    X509 *cert;
    X509_CRL *crl;
    EVP_PKEY *pubkey;
    int i, n, rc;

    /*
     * Unless a revocation store for CRLs was created we
     * cannot do any CRL-based verification, of course.
     */
    if (!mctx->crl) {
        return ok;
    }

    /*
     * Determine certificate ingredients in advance
     */
    cert    = X509_STORE_CTX_get_current_cert(ctx);
    subject = X509_get_subject_name(cert);
    issuer  = X509_get_issuer_name(cert);

    /*
     * OpenSSL provides the general mechanism to deal with CRLs but does not
     * use them automatically when verifying certificates, so we do it
     * explicitly here. We will check the CRL for the currently checked
     * certificate, if there is such a CRL in the store.
     *
     * We come through this procedure for each certificate in the certificate
     * chain, starting with the root-CA's certificate. At each step we've to
     * both verify the signature on the CRL (to make sure it's a valid CRL)
     * and it's revocation list (to make sure the current certificate isn't
     * revoked).  But because to check the signature on the CRL we need the
     * public key of the issuing CA certificate (which was already processed
     * one round before), we've a little problem. But we can both solve it and
     * at the same time optimize the processing by using the following
     * verification scheme (idea and code snippets borrowed from the GLOBUS
     * project):
     *
     * 1. We'll check the signature of a CRL in each step when we find a CRL
     *    through the _subject_ name of the current certificate. This CRL
     *    itself will be needed the first time in the next round, of course.
     *    But we do the signature processing one round before this where the
     *    public key of the CA is available.
     *
     * 2. We'll check the revocation list of a CRL in each step when
     *    we find a CRL through the _issuer_ name of the current certificate.
     *    This CRLs signature was then already verified one round before.
     *
     * This verification scheme allows a CA to revoke its own certificate as
     * well, of course.
     */

    /*
     * Try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity.
     */
    memset((char *)&obj, 0, sizeof(obj));
    rc = SSL_X509_STORE_lookup(mctx->crl,
                               X509_LU_CRL, subject, &obj);
    crl = obj.data.crl;

    if ((rc > 0) && crl) {
        /*
         * Log information about CRL
         * (A little bit complicated because of ASN.1 and BIOs...)
         */
        if (s->loglevel >= APLOG_DEBUG) {
            char buff[512]; /* should be plenty */
            BIO *bio = BIO_new(BIO_s_mem());

            BIO_printf(bio, "CA CRL: Issuer: ");
            X509_NAME_print(bio, issuer, 0);

            BIO_printf(bio, ", lastUpdate: ");
            ASN1_UTCTIME_print(bio, X509_CRL_get_lastUpdate(crl));

            BIO_printf(bio, ", nextUpdate: ");
            ASN1_UTCTIME_print(bio, X509_CRL_get_nextUpdate(crl));

            n = BIO_read(bio, buff, sizeof(buff));
            buff[n] = '\0';

            BIO_free(bio);

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, buff);
        }

        /*
         * Verify the signature on this CRL
         */
        pubkey = X509_get_pubkey(cert);
        rc = X509_CRL_verify(crl, pubkey);
#ifdef OPENSSL_VERSION_NUMBER
        /* Only refcounted in OpenSSL */
        if (pubkey)
            EVP_PKEY_free(pubkey);
#endif
        if (rc <= 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "Invalid signature on CRL");

            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
            return FALSE;
        }

        /*
         * Check date of CRL to make sure it's not expired
         */
        i = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));

        if (i == 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "Found CRL has invalid nextUpdate field");

            X509_STORE_CTX_set_error(ctx,
                                     X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free_contents(&obj);

            return FALSE;
        }

        if (i < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                         "Found CRL is expired - "
                         "revoking all certificates until you get updated CRL");

            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free_contents(&obj);

            return FALSE;
        }

        X509_OBJECT_free_contents(&obj);
    }

    /*
     * Try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation.
     */
    memset((char *)&obj, 0, sizeof(obj));
    rc = SSL_X509_STORE_lookup(mctx->crl,
                               X509_LU_CRL, issuer, &obj);

    crl = obj.data.crl;
    if ((rc > 0) && crl) {
        /*
         * Check if the current certificate is revoked by this CRL
         */
        n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));

        for (i = 0; i < n; i++) {
            X509_REVOKED *revoked =
                sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);

            ASN1_INTEGER *sn = X509_REVOKED_get_serialNumber(revoked);

            if (!ASN1_INTEGER_cmp(sn, X509_get_serialNumber(cert))) {
                if (s->loglevel >= APLOG_DEBUG) {
                    char *cp = X509_NAME_oneline(issuer, NULL, 0);
                    long serial = ASN1_INTEGER_get(sn);

                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                                 "Certificate with serial %ld (0x%lX) "
                                 "revoked per CRL from issuer %s",
                                 serial, serial, cp);
                    modssl_free(cp);
                }

                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free_contents(&obj);

                return FALSE;
            }
        }

        X509_OBJECT_free_contents(&obj);
    }

    return ok;
}

#define SSLPROXY_CERT_CB_LOG_FMT \
   "Proxy client certificate callback: (%s) "

static void modssl_proxy_info_log(server_rec *s,
                                  X509_INFO *info,
                                  const char *msg)
{
    SSLSrvConfigRec *sc = mySrvConfig(s);
    char name_buf[256];
    X509_NAME *name;
    char *dn;

    if (s->loglevel < APLOG_DEBUG) {
        return;
    }

    name = X509_get_subject_name(info->x509);
    dn = X509_NAME_oneline(name, name_buf, sizeof(name_buf));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 SSLPROXY_CERT_CB_LOG_FMT "%s, sending %s", 
                 sc->vhost_id, msg, dn ? dn : "-uknown-");
}

/*
 * caller will decrement the cert and key reference
 * so we need to increment here to prevent them from
 * being freed.
 */
#define modssl_set_cert_info(info, cert, pkey) \
    *cert = info->x509; \
    X509_reference_inc(*cert); \
    *pkey = info->x_pkey->dec_pkey; \
    EVP_PKEY_reference_inc(*pkey)

int ssl_callback_proxy_cert(SSL *ssl, MODSSL_CLIENT_CERT_CB_ARG_TYPE **x509, EVP_PKEY **pkey) 
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s = c->base_server;
    SSLSrvConfigRec *sc = mySrvConfig(s);
    X509_NAME *ca_name, *issuer;
    X509_INFO *info;
    STACK_OF(X509_NAME) *ca_list;
    STACK_OF(X509_INFO) *certs = sc->proxy->pkp->certs;
    int i, j;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, 
                 SSLPROXY_CERT_CB_LOG_FMT "entered",
                 sc->vhost_id);

    if (!certs || (sk_X509_INFO_num(certs) <= 0)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     SSLPROXY_CERT_CB_LOG_FMT
                     "downstream server wanted client certificate "
                     "but none are configured", sc->vhost_id);
        return FALSE;
    }                                                                     

    ca_list = SSL_get_client_CA_list(ssl);

    if (!ca_list || (sk_X509_NAME_num(ca_list) <= 0)) {
        /* 
         * downstream server didn't send us a list of acceptable CA certs, 
         * so we send the first client cert in the list.
         */   
        info = sk_X509_INFO_value(certs, 0);
        
        modssl_proxy_info_log(s, info, "no acceptable CA list");

        modssl_set_cert_info(info, x509, pkey);

        return TRUE;
    }         

    for (i = 0; i < sk_X509_NAME_num(ca_list); i++) {
        ca_name = sk_X509_NAME_value(ca_list, i);

        for (j = 0; j < sk_X509_INFO_num(certs); j++) {
            info = sk_X509_INFO_value(certs, j);
            issuer = X509_get_issuer_name(info->x509);

            if (X509_NAME_cmp(issuer, ca_name) == 0) {
                modssl_proxy_info_log(s, info, "found acceptable cert");

                modssl_set_cert_info(info, x509, pkey);

                return TRUE;
            }
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 SSLPROXY_CERT_CB_LOG_FMT
                 "no client certificate found!?", sc->vhost_id);

    return FALSE; 
}

static void ssl_session_log(server_rec *s,
                            const char *request,
                            unsigned char *id,
                            unsigned int idlen,
                            const char *status,
                            const char *result,
                            long timeout)
{
    char buf[SSL_SESSION_ID_STRING_LEN];
    char timeout_str[56] = {'\0'};

    if (s->loglevel < APLOG_DEBUG) {
        return;
    }

    if (timeout) {
        apr_snprintf(timeout_str, sizeof(timeout_str),
                     "timeout=%lds ", (timeout - time(NULL)));
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "Inter-Process Session Cache: "
                 "request=%s status=%s id=%s %s(session %s)",
                 request, status,
                 SSL_SESSION_id2sz(id, idlen, buf, sizeof(buf)),
                 timeout_str, result);
}

/*
 *  This callback function is executed by OpenSSL whenever a new SSL_SESSION is
 *  added to the internal OpenSSL session cache. We use this hook to spread the
 *  SSL_SESSION also to the inter-process disk-cache to make share it with our
 *  other Apache pre-forked server processes.
 */
int ssl_callback_NewSessionCacheEntry(SSL *ssl, SSL_SESSION *session)
{
    /* Get Apache context back through OpenSSL context */
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s       = conn->base_server;
    SSLSrvConfigRec *sc = mySrvConfig(s);
    long timeout        = sc->session_cache_timeout;
    BOOL rc;
    unsigned char *id;
    unsigned int idlen;

    /*
     * Set the timeout also for the internal OpenSSL cache, because this way
     * our inter-process cache is consulted only when it's really necessary.
     */
    SSL_set_timeout(session, timeout);

    /*
     * Store the SSL_SESSION in the inter-process cache with the
     * same expire time, so it expires automatically there, too.
     */
    id = SSL_SESSION_get_session_id(session);
    idlen = SSL_SESSION_get_session_id_length(session);

    timeout += modssl_session_get_time(session);

    rc = ssl_scache_store(s, id, idlen, timeout, session);

    ssl_session_log(s, "SET", id, idlen,
                    rc == TRUE ? "OK" : "BAD",
                    "caching", timeout);

    /*
     * return 0 which means to OpenSSL that the session is still
     * valid and was not freed by us with SSL_SESSION_free().
     */
    return 0;
}

/*
 *  This callback function is executed by OpenSSL whenever a
 *  SSL_SESSION is looked up in the internal OpenSSL cache and it
 *  was not found. We use this to lookup the SSL_SESSION in the
 *  inter-process disk-cache where it was perhaps stored by one
 *  of our other Apache pre-forked server processes.
 */
SSL_SESSION *ssl_callback_GetSessionCacheEntry(SSL *ssl,
                                               unsigned char *id,
                                               int idlen, int *do_copy)
{
    /* Get Apache context back through OpenSSL context */
    conn_rec *conn = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s  = conn->base_server;
    SSL_SESSION *session;

    /*
     * Try to retrieve the SSL_SESSION from the inter-process cache
     */
    session = ssl_scache_retrieve(s, id, idlen);

    ssl_session_log(s, "GET", id, idlen,
                    session ? "FOUND" : "MISSED",
                    session ? "reuse" : "renewal", 0);

    /*
     * Return NULL or the retrieved SSL_SESSION. But indicate (by
     * setting do_copy to 0) that the reference count on the
     * SSL_SESSION should not be incremented by the SSL library,
     * because we will no longer hold a reference to it ourself.
     */
    *do_copy = 0;

    return session;
}

/*
 *  This callback function is executed by OpenSSL whenever a
 *  SSL_SESSION is removed from the the internal OpenSSL cache.
 *  We use this to remove the SSL_SESSION in the inter-process
 *  disk-cache, too.
 */
void ssl_callback_DelSessionCacheEntry(SSL_CTX *ctx,
                                       SSL_SESSION *session)
{
    server_rec *s;
    SSLSrvConfigRec *sc;
    unsigned char *id;
    unsigned int idlen;

    /*
     * Get Apache context back through OpenSSL context
     */
    if (!(s = (server_rec *)SSL_CTX_get_app_data(ctx))) {
        return; /* on server shutdown Apache is already gone */
    }

    sc = mySrvConfig(s);

    /*
     * Remove the SSL_SESSION from the inter-process cache
     */
    id = SSL_SESSION_get_session_id(session);
    idlen = SSL_SESSION_get_session_id_length(session);

    ssl_scache_remove(s, id, idlen);

    ssl_session_log(s, "REM", id, idlen,
                    "OK", "dead", 0);

    return;
}

/*
 * This callback function is executed while OpenSSL processes the
 * SSL handshake and does SSL record layer stuff. We use it to
 * trace OpenSSL's processing in out SSL logfile.
 */
void ssl_callback_LogTracingState(MODSSL_INFO_CB_ARG_TYPE ssl, int where, int rc)
{
    conn_rec *c;
    server_rec *s;
    SSLSrvConfigRec *sc;

    /*
     * find corresponding server
     */
    if (!(c = (conn_rec *)SSL_get_app_data((SSL *)ssl))) {
        return;
    }

    s = c->base_server;
    if (!(sc = mySrvConfig(s))) {
        return;
    }

    /*
     * create the various trace messages
     */
    if (s->loglevel >= APLOG_DEBUG) {
        if (where & SSL_CB_HANDSHAKE_START) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: Handshake: start", SSL_LIBRARY_NAME);
        }
        else if (where & SSL_CB_HANDSHAKE_DONE) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: Handshake: done", SSL_LIBRARY_NAME);
        }
        else if (where & SSL_CB_LOOP) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: Loop: %s",
                         SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
        }
        else if (where & SSL_CB_READ) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: Read: %s",
                         SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
        }
        else if (where & SSL_CB_WRITE) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: Write: %s",
                         SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
        }
        else if (where & SSL_CB_ALERT) {
            char *str = (where & SSL_CB_READ) ? "read" : "write";
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s: Alert: %s:%s:%s\n",
                         SSL_LIBRARY_NAME, str,
                         SSL_alert_type_string_long(rc),
                         SSL_alert_desc_string_long(rc));
        }
        else if (where & SSL_CB_EXIT) {
            if (rc == 0) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "%s: Exit: failed in %s",
                             SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
            }
            else if (rc < 0) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "%s: Exit: error in %s",
                             SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
            }
        }
    }

    /*
     * Because SSL renegotations can happen at any time (not only after
     * SSL_accept()), the best way to log the current connection details is
     * right after a finished handshake.
     */
    if (where & SSL_CB_HANDSHAKE_DONE) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Connection: Client IP: %s, Protocol: %s, "
                     "Cipher: %s (%s/%s bits)",
                     ssl_var_lookup(NULL, s, c, NULL, "REMOTE_ADDR"),
                     ssl_var_lookup(NULL, s, c, NULL, "SSL_PROTOCOL"),
                     ssl_var_lookup(NULL, s, c, NULL, "SSL_CIPHER"),
                     ssl_var_lookup(NULL, s, c, NULL, "SSL_CIPHER_USEKEYSIZE"),
                     ssl_var_lookup(NULL, s, c, NULL, "SSL_CIPHER_ALGKEYSIZE"));
    }
}

