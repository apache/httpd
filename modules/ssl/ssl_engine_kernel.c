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
 *  ssl_engine_kernel.c
 *  The SSL engine kernel
 */
                             /* ``It took me fifteen years to discover
                                  I had no talent for programming, but
                                  I couldn't give it up because by that
                                  time I was too famous.''
                                            -- Unknown                */
#include "ssl_private.h"

static void ssl_configure_env(request_rec *r, SSLConnRec *sslconn);
#ifndef OPENSSL_NO_TLSEXT
static int ssl_find_vhost(void *servername, conn_rec *c, server_rec *s);
#endif

#define SWITCH_STATUS_LINE "HTTP/1.1 101 Switching Protocols"
#define UPGRADE_HEADER "Upgrade: TLS/1.0, HTTP/1.1"
#define CONNECTION_HEADER "Connection: Upgrade"

/* Perform an upgrade-to-TLS for the given request, per RFC 2817. */
static apr_status_t upgrade_connection(request_rec *r)
{
    struct conn_rec *conn = r->connection;
    apr_bucket_brigade *bb;
    SSLConnRec *sslconn;
    apr_status_t rv;
    SSL *ssl;

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, 
                  "upgrading connection to TLS");

    bb = apr_brigade_create(r->pool, conn->bucket_alloc);

    rv = ap_fputstrs(conn->output_filters, bb, SWITCH_STATUS_LINE, CRLF,
                     UPGRADE_HEADER, CRLF, CONNECTION_HEADER, CRLF, CRLF, NULL);
    if (rv == APR_SUCCESS) {
        APR_BRIGADE_INSERT_TAIL(bb,
                                apr_bucket_flush_create(conn->bucket_alloc));
        rv = ap_pass_brigade(conn->output_filters, bb);
    }

    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "failed to send 101 interim response for connection "
                      "upgrade");
        return rv;
    }

    ssl_init_ssl_connection(conn, r);
    
    sslconn = myConnConfig(conn);
    ssl = sslconn->ssl;
    
    /* Perform initial SSL handshake. */
    SSL_set_accept_state(ssl);
    SSL_do_handshake(ssl);

    if (SSL_get_state(ssl) != SSL_ST_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "TLS upgrade handshake failed: not accepted by client!?");
        
        return APR_ECONNABORTED;
    }

    return APR_SUCCESS;
}

/*
 *  Post Read Request Handler
 */
int ssl_hook_ReadReq(request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLConnRec *sslconn;
    const char *upgrade;
#ifndef OPENSSL_NO_TLSEXT
    const char *servername;
#endif
    SSL *ssl;
    
    /* Perform TLS upgrade here if "SSLEngine optional" is configured,
     * SSL is not already set up for this connection, and the client
     * has sent a suitable Upgrade header. */
    if (sc->enabled == SSL_ENABLED_OPTIONAL && !myConnConfig(r->connection)
        && (upgrade = apr_table_get(r->headers_in, "Upgrade")) != NULL
        && ap_find_token(r->pool, upgrade, "TLS/1.0")) {
        if (upgrade_connection(r)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    sslconn = myConnConfig(r->connection);
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
    ssl = sslconn->ssl;
    if (!ssl) {
        return DECLINED;
    }
#ifndef OPENSSL_NO_TLSEXT
    if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
        char *host, *scope_id;
        apr_port_t port;
        apr_status_t rv;

        /*
         * The SNI extension supplied a hostname. So don't accept requests
         * with either no hostname or a different hostname.
         */
        if (!r->hostname) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                        "Hostname %s provided via SNI, but no hostname"
                        " provided in HTTP request", servername);
            return HTTP_BAD_REQUEST;
        }
        rv = apr_parse_addr_port(&host, &scope_id, &port, r->hostname, r->pool);
        if (rv != APR_SUCCESS || scope_id) {
            return HTTP_BAD_REQUEST;
        }
        if (strcmp(host, servername)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                        "Hostname %s provided via SNI and hostname %s provided"
                        " via HTTP are different", servername, host);
            return HTTP_BAD_REQUEST;
        }
    }
    else if (r->connection->vhost_lookup_data) {
        /*
         * We are using a name based configuration here, but no hostname was
         * provided via SNI. Don't allow that.
         */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "No hostname was provided via SNI for a name based"
                     " virtual host");
        return HTTP_FORBIDDEN;
    }
#endif
    SSL_set_app_data2(ssl, r);

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
    const SSL_CIPHER *cipher = NULL;
    int depth, verify_old, verify, n;

    if (ssl) {
        ctx = SSL_get_SSL_CTX(ssl);
    }

    /*
     * Support for SSLRequireSSL directive
     */
    if (dc->bSSLRequired && !ssl) {
        if (sc->enabled == SSL_ENABLED_OPTIONAL) {
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
     * Check to see whether SSL is in use; if it's not, then no
     * further access control checks are relevant.  (the test for
     * sc->enabled is probably strictly unnecessary)
     */
    if (sc->enabled == SSL_ENABLED_FALSE || !ssl) {
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
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
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
    if ((sc->server->auth.verify_depth != UNSET) &&
        (dc->nVerifyDepth == UNSET)) {
        /* apply per-vhost setting, if per-directory config is not set */
        dc->nVerifyDepth = sc->server->auth.verify_depth;
    }
    if (dc->nVerifyDepth != UNSET) {
        /* XXX: doesnt look like sslconn->verify_depth is actually used */
        if (!(n = sslconn->verify_depth)) {
            sslconn->verify_depth = n = sc->server->auth.verify_depth;
        }

        /* determine whether a renegotiation has to be forced */
        if (dc->nVerifyDepth < n) {
            renegotiate = TRUE;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
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
    if ((sc->server->auth.verify_mode != SSL_CVERIFY_UNSET) &&
        (dc->nVerifyClient == SSL_CVERIFY_UNSET)) {
        /* apply per-vhost setting, if per-directory config is not set */
        dc->nVerifyClient = sc->server->auth.verify_mode;
    }
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

                (!(verify_old & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) &&
                  (verify     & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)))
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

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "Changed client verification type will force "
                              "%srenegotiation",
                              renegotiate_quick ? "quick " : "");
             }
        }
    }

    /* If a renegotiation is now required for this location, and the
     * request includes a message body (and the client has not
     * requested a "100 Continue" response), then the client will be
     * streaming the request body over the wire already.  In that
     * case, it is not possible to stop and perform a new SSL
     * handshake immediately; once the SSL library moves to the
     * "accept" state, it will reject the SSL packets which the client
     * is sending for the request body.
     *
     * To allow authentication to complete in this auth hook, the
     * solution used here is to fill a (bounded) buffer with the
     * request body, and then to reinject that request body later.
     */
    if (renegotiate && !renegotiate_quick
        && (apr_table_get(r->headers_in, "transfer-encoding")
            || (apr_table_get(r->headers_in, "content-length")
                && strcmp(apr_table_get(r->headers_in, "content-length"), "0")))
        && !r->expecting_100) {
        int rv;
        apr_size_t rsize;

        rsize = dc->nRenegBufferSize == UNSET ? DEFAULT_RENEG_BUFFER_SIZE :
                                                dc->nRenegBufferSize;
        if (rsize > 0) {
            /* Fill the I/O buffer with the request body if possible. */
            rv = ssl_io_buffer_fill(r, rsize);
        }
        else {
            /* If the reneg buffer size is set to zero, just fail. */
            rv = HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "could not buffer message body to allow "
                          "SSL renegotiation to proceed");
            return rv;
        }
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
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "Requesting connection re-negotiation");

        if (renegotiate_quick) {
            STACK_OF(X509) *cert_stack;

            /* perform just a manual re-verification of the peer */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
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
                cert_stack = sk_X509_new_null();
                sk_X509_push(cert_stack, MODSSL_PCHAR_CAST cert);
            }

            if (!cert_stack || (sk_X509_num(cert_stack) == 0)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Cannot find peer certificate chain");

                return HTTP_FORBIDDEN;
            }

            if (!(cert_store ||
                  (cert_store = SSL_CTX_get_cert_store(ctx))))
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "Performing full renegotiation: "
                          "complete handshake protocol");

            SSL_set_session_id_context(ssl,
                                       (unsigned char *)&id,
                                       sizeof(id));

            SSL_renegotiate(ssl);
            SSL_do_handshake(ssl);

            if (SSL_get_state(ssl) != SSL_ST_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Re-negotiation request failed");

                r->connection->aborted = 1;
                return HTTP_FORBIDDEN;
            }

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "Awaiting re-negotiation handshake");

            /* XXX: Should replace SSL_set_state with SSL_renegotiate(ssl);
             * However, this causes failures in perl-framework currently,
             * perhaps pre-test if we have already negotiated?
             */
            SSL_set_state(ssl, SSL_ST_ACCEPT);
            SSL_do_handshake(ssl);

            if (SSL_get_state(ssl) != SSL_ST_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Re-negotiation handshake failed: "
                              "Client verification failed");

                return HTTP_FORBIDDEN;
            }

            if (do_verify) {
                if ((peercert = SSL_get_peer_certificate(ssl)) == NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Re-negotiation handshake failed: "
                                  "Client certificate missing");

                    return HTTP_FORBIDDEN;
                }

                X509_free(peercert);
            }
        }

        /*
         * Also check that SSLCipherSuite has been enforced as expected.
         */
        if (cipher_list) {
            cipher = SSL_get_current_cipher(ssl);
            if (sk_SSL_CIPHER_find(cipher_list, cipher) < 0) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "SSL cipher suite not renegotiated: "
                             "access to %s denied using cipher %s",
                              r->filename,
                              SSL_CIPHER_get_name(cipher));
                return HTTP_FORBIDDEN;
            }
        }
    }

    /* If we're trying to have the user name set from a client
     * certificate then we need to set it here. This should be safe as
     * the user name probably isn't important from an auth checking point
     * of view as the certificate supplied acts in that capacity.
     * However, if FakeAuth is being used then this isn't the case so
     * we need to postpone setting the username until later.
     */
    if ((dc->nOptions & SSL_OPT_FAKEBASICAUTH) == 0 && dc->szUserName) {
        char *val = ssl_var_lookup(r->pool, r->server, r->connection,
                                   r, (char *)dc->szUserName);
        if (val && val[0])
            r->user = val;
        else
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "Failed to set r->user to '%s'", dc->szUserName);
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
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "Access to %s denied for %s "
                          "(requirement expression not fulfilled)",
                          r->filename, r->connection->remote_ip);

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "Failed expression: %s", req->cpExpr);

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "access to %s failed, reason: %s",
                          r->filename,
                          "SSL requirement expression not fulfilled");

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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
    if (!((sc->enabled == SSL_ENABLED_TRUE || sc->enabled == SSL_ENABLED_OPTIONAL)
          && sslconn && sslconn->ssl && sslconn->client_cert) ||
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
    auth_line = apr_pstrcat(r->pool, "Basic ",
                            ap_pbase64encode(r->pool,
                                             apr_pstrcat(r->pool, clientdn,
                                                         ":password", NULL)),
                            NULL);
    apr_table_set(r->headers_in, "Authorization", auth_line);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "Faking HTTP Basic Auth header: \"Authorization: %s\"",
                  auth_line);

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
    "SSL_COMPRESS_METHOD",
    "SSL_CIPHER",
    "SSL_CIPHER_EXPORT",
    "SSL_CIPHER_USEKEYSIZE",
    "SSL_CIPHER_ALGKEYSIZE",
    "SSL_CLIENT_VERIFY",
    "SSL_CLIENT_M_VERSION",
    "SSL_CLIENT_M_SERIAL",
    "SSL_CLIENT_V_START",
    "SSL_CLIENT_V_END",
    "SSL_CLIENT_V_REMAIN",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
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
#ifndef OPENSSL_NO_TLSEXT
    const char *servername;
#endif
    STACK_OF(X509) *peer_certs;
    SSL *ssl;
    int i;

    /* If "SSLEngine optional" is configured, this is not an SSL
     * connection, and this isn't a subrequest, send an Upgrade
     * response header. */
    if (sc->enabled == SSL_ENABLED_OPTIONAL && !(sslconn && sslconn->ssl)
        && !r->main) {
        apr_table_setn(r->headers_out, "Upgrade", "TLS/1.0, HTTP/1.1");
        apr_table_mergen(r->headers_out, "Connection", "upgrade");
    }

    /*
     * Check to see if SSL is on
     */
    if (!(((sc->enabled == SSL_ENABLED_TRUE) || (sc->enabled == SSL_ENABLED_OPTIONAL)) && sslconn && (ssl = sslconn->ssl))) {
        return DECLINED;
    }

    /*
     * Annotate the SSI/CGI environment with standard SSL information
     */
    /* the always present HTTPS (=HTTP over SSL) flag! */
    apr_table_setn(env, "HTTPS", "on");

#ifndef OPENSSL_NO_TLSEXT
    /* add content of SNI TLS extension (if supplied with ClientHello) */
    if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
        apr_table_set(env, "SSL_TLS_SNI", servername);
    }
#endif

    /* standard SSL environment variables */
    if (dc->nOptions & SSL_OPT_STDENVVARS) {
        modssl_var_extract_dns(env, sslconn->ssl, r->pool);

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
    SSLModConfigRec *mc = myModConfigFromConn(c);
    int idx;

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
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
    SSLModConfigRec *mc = myModConfigFromConn(c);
    int idx;

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
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
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s       = mySrvFromConn(conn);
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
    ssl_log_cxerror(APLOG_MARK, APLOG_DEBUG, 0, conn,
                    X509_STORE_CTX_get_current_cert(ctx),
                    "Certificate Verification, depth %d",
                    errdepth);

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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, conn,
                      "Certificate Verification: Verifiable Issuer is "
                      "configured as optional, therefore we're accepting "
                      "the certificate");

        sslconn->verify_info = "GENEROUS";
        ok = TRUE;
    }

    /*
     * Perform OCSP/CRL-based revocation checks
     */
    if (ok) {
        if (!(ok = ssl_callback_SSLVerify_CRL(ok, ctx, conn))) {
            errnum = X509_STORE_CTX_get_error(ctx);
        }
        
#ifdef HAVE_OCSP
        /* If there was an optional verification error, it's not
         * possible to perform OCSP validation since the issuer may be
         * missing/untrusted.  Fail in that case. */
        if (ok && ssl_verify_error_is_optional(errnum)
            && sc->server->ocsp_enabled) {
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
            errnum = X509_V_ERR_APPLICATION_VERIFICATION;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn,
                          "cannot perform OCSP validation for cert "
                          "if issuer has not been verified "
                          "(optional_no_ca configured)");
            ok = FALSE;
        }

        if (ok && sc->server->ocsp_enabled) {
            ok = modssl_verify_ocsp(ctx, sc, s, conn, conn->pool);
            if (!ok) {
                errnum = X509_STORE_CTX_get_error(ctx);
            }
        }
#endif
    }

    /*
     * If we already know it's not ok, log the real reason
     */
    if (!ok) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn,
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
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn,
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
    server_rec *s       = mySrvFromConn(c);
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

            n = BIO_read(bio, buff, sizeof(buff) - 1);
            buff[n] = '\0';

            BIO_free(bio);

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "%s", buff);
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
    server_rec *s = mySrvFromConn(c);
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
    server_rec *s       = mySrvFromConn(conn);
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

    rc = ssl_scache_store(s, id, idlen, timeout, session, conn->pool);

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
    server_rec *s  = mySrvFromConn(conn);
    SSL_SESSION *session;

    /*
     * Try to retrieve the SSL_SESSION from the inter-process cache
     */
    session = ssl_scache_retrieve(s, id, idlen, conn->pool);

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

    /* TODO: Do we need a temp pool here, or are we always shutting down? */
    ssl_scache_remove(s, id, idlen, sc->mc->pPool);

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

    s = mySrvFromConn(c);
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
                         "%s: Alert: %s:%s:%s",
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

#ifndef OPENSSL_NO_TLSEXT
/*
 * This callback function is executed when OpenSSL encounters an extended
 * client hello with a server name indication extension ("SNI", cf. RFC 4366).
 */
int ssl_callback_ServerNameIndication(SSL *ssl, int *al, modssl_ctx_t *mctx)
{
    const char *servername =
                SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (servername) {
        conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
        if (c) {
            if (ap_vhost_iterate_given_conn(c, ssl_find_vhost,
                                            (void *)servername)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                              "SSL virtual host for servername %s found",
                              servername);
                return SSL_TLSEXT_ERR_OK;
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                              "No matching SSL virtual host for servername "
                              "%s found (using default/first virtual host)",
                              servername);
                return SSL_TLSEXT_ERR_ALERT_WARNING;
            }
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

/*
 * Find a (name-based) SSL virtual host where either the ServerName
 * or one of the ServerAliases matches the supplied name (to be used
 * with ap_vhost_iterate_given_conn())
 */
static int ssl_find_vhost(void *servername, conn_rec *c, server_rec *s) 
{
    SSLSrvConfigRec *sc;
    SSL *ssl;
    BOOL found = FALSE;
    apr_array_header_t *names;
    int i;
    SSLConnRec *sslcon;

    /* check ServerName */
    if (!strcasecmp(servername, s->server_hostname)) {
        found = TRUE;
    }

    /* 
     * if not matched yet, check ServerAlias entries
     * (adapted from vhost.c:matches_aliases())
     */
    if (!found) {
        names = s->names;
        if (names) {
            char **name = (char **)names->elts;
            for (i = 0; i < names->nelts; ++i) {
                if (!name[i])
                    continue;
                if (!strcasecmp(servername, name[i])) {
                    found = TRUE;
                    break;
                }
            }
        }
    }

    /* if still no match, check ServerAlias entries with wildcards */
    if (!found) {
        names = s->wild_names;
        if (names) {
            char **name = (char **)names->elts;
            for (i = 0; i < names->nelts; ++i) {
                if (!name[i])
                    continue;
                if (!ap_strcasecmp_match(servername, name[i])) {
                    found = TRUE;
                    break;
                }
            }
        }
    }

    /* set SSL_CTX (if matched) */
    sslcon = myConnConfig(c);
    if (found && (ssl = sslcon->ssl) &&
        (sc = mySrvConfig(s))) {
        SSL_set_SSL_CTX(ssl, sc->server->ssl_ctx);
        /*
         * SSL_set_SSL_CTX() only deals with the server cert,
         * so we need to duplicate a few additional settings
         * from the ctx by hand
         */
        SSL_set_options(ssl, SSL_CTX_get_options(ssl->ctx));
        if ((SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE) ||
            (SSL_num_renegotiations(ssl) == 0)) {
           /*
            * Only initialize the verification settings from the ctx
            * if they are not yet set, or if we're called when a new
            * SSL connection is set up (num_renegotiations == 0).
            * Otherwise, we would possibly reset a per-directory
            * configuration which was put into effect by ssl_hook_Access.
            */
            SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ssl->ctx),
                           SSL_CTX_get_verify_callback(ssl->ctx));
        }

        /*
         * Save the found server into our SSLConnRec for later
         * retrieval
         */
        sslcon->server = s;

        /*
         * There is one special filter callback, which is set
         * very early depending on the base_server's log level.
         * If this is not the first vhost we're now selecting
         * (and the first vhost doesn't use APLOG_DEBUG), then
         * we need to set that callback here.
         */
        if (s->loglevel >= APLOG_DEBUG) {
            BIO_set_callback(SSL_get_rbio(ssl), ssl_io_data_cb);
            BIO_set_callback_arg(SSL_get_rbio(ssl), (void *)ssl);
        }

        return 1;
    }

    return 0;
}
#endif
