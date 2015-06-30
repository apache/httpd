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
#include "mod_ssl.h"
#include "util_md5.h"

static void ssl_configure_env(request_rec *r, SSLConnRec *sslconn);
#ifdef HAVE_TLSEXT
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

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02028)
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02029)
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
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02030)
                      "TLS upgrade handshake failed: not accepted by client!?");

        return APR_ECONNABORTED;
    }

    return APR_SUCCESS;
}

/* Perform a speculative (and non-blocking) read from the connection
 * filters for the given request, to determine whether there is any
 * pending data to read.  Return non-zero if there is, else zero. */
static int has_buffered_data(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_off_t len;
    apr_status_t rv;
    int result;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    rv = ap_get_brigade(r->connection->input_filters, bb, AP_MODE_SPECULATIVE,
                        APR_NONBLOCK_READ, 1);
    result = rv == APR_SUCCESS
        && apr_brigade_length(bb, 1, &len) == APR_SUCCESS
        && len > 0;

    apr_brigade_destroy(bb);

    return result;
}

/*
 *  Post Read Request Handler
 */
int ssl_hook_ReadReq(request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLConnRec *sslconn;
    const char *upgrade;
#ifdef HAVE_TLSEXT
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

    if (sslconn->non_ssl_request == NON_SSL_SET_ERROR_MSG) {
        apr_table_setn(r->notes, "error-notes",
                       "Reason: You're speaking plain HTTP to an SSL-enabled "
                       "server port.<br />\n Instead use the HTTPS scheme to "
                       "access this URL, please.<br />\n");

        /* Now that we have caught this error, forget it. we are done
         * with using SSL on this request.
         */
        sslconn->non_ssl_request = NON_SSL_OK;

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
#ifdef HAVE_TLSEXT
    /*
     * Perform SNI checks only on the initial request.  In particular,
     * if these checks detect a problem, the checks shouldn't return an
     * error again when processing an ErrorDocument redirect for the
     * original problem.
     */
    if (r->proxyreq != PROXYREQ_PROXY && ap_is_initial_req(r)) {
        if ((servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
            char *host, *scope_id;
            apr_port_t port;
            apr_status_t rv;

            /*
             * The SNI extension supplied a hostname. So don't accept requests
             * with either no hostname or a different hostname as this could
             * cause us to end up in a different virtual host as the one that
             * was used for the handshake causing different SSL parameters to
             * be applied as SSLProtocol, SSLCACertificateFile/Path and
             * SSLCADNRequestFile/Path cannot be renegotiated (SSLCA* due
             * to current limitations in OpenSSL, see
             * http://mail-archives.apache.org/mod_mbox/httpd-dev/200806.mbox/%3C48592955.2090303@velox.ch%3E
             * and
             * http://mail-archives.apache.org/mod_mbox/httpd-dev/201312.mbox/%3CCAKQ1sVNpOrdiBm-UPw1hEdSN7YQXRRjeaT-MCWbW_7mN%3DuFiOw%40mail.gmail.com%3E
             * )
             */
            if (!r->hostname) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO(02031)
                            "Hostname %s provided via SNI, but no hostname"
                            " provided in HTTP request", servername);
                return HTTP_BAD_REQUEST;
            }
            rv = apr_parse_addr_port(&host, &scope_id, &port, r->hostname, r->pool);
            if (rv != APR_SUCCESS || scope_id) {
                return HTTP_BAD_REQUEST;
            }
            if (strcasecmp(host, servername)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO(02032)
                            "Hostname %s provided via SNI and hostname %s provided"
                            " via HTTP are different", servername, host);
                return HTTP_BAD_REQUEST;
            }
        }
        else if (((sc->strict_sni_vhost_check == SSL_ENABLED_TRUE)
                 || (mySrvConfig(sslconn->server))->strict_sni_vhost_check
                    == SSL_ENABLED_TRUE)
                 && r->connection->vhost_lookup_data) {
            /*
             * We are using a name based configuration here, but no hostname was
             * provided via SNI. Don't allow that if are requested to do strict
             * checking. Check whether this strict checking was set up either in the
             * server config we used for handshaking or in our current server.
             * This should avoid insecure configuration by accident.
             */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO(02033)
                         "No hostname was provided via SNI for a name based"
                         " virtual host");
            apr_table_setn(r->notes, "error-notes",
                           "Reason: The client software did not provide a "
                           "hostname using Server Name Indication (SNI), "
                           "which is required to access this server.<br />\n");
            return HTTP_FORBIDDEN;
        }
    }
#endif
    SSL_set_app_data2(ssl, r);

    /*
     * Log information about incoming HTTPS requests
     */
    if (APLOGrinfo(r) && ap_is_initial_req(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02034)
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
    SSLDirConfigRec *dc         = myDirConfig(r);
    SSLSrvConfigRec *sc         = mySrvConfig(r->server);
    SSLConnRec *sslconn         = myConnConfig(r->connection);
    SSL *ssl                    = sslconn ? sslconn->ssl : NULL;
    server_rec *handshakeserver = sslconn ? sslconn->server : NULL;
    SSL_CTX *ctx = NULL;
    apr_array_header_t *requires;
    ssl_require_t *ssl_requires;
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

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02219)
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

#ifdef HAVE_SRP
    /*
     * Support for per-directory reconfigured SSL connection parameters
     *
     * We do not force any renegotiation if the user is already authenticated
     * via SRP.
     *
     */
    if (SSL_get_srp_username(ssl)) {
        return DECLINED;
    }
#endif

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
    if (dc->szCipherSuite || (r->server != handshakeserver)) {
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
        if ((dc->szCipherSuite || sc->server->auth.cipher_suite) &&
            !SSL_set_cipher_list(ssl, dc->szCipherSuite ?
                                      dc->szCipherSuite :
                                      sc->server->auth.cipher_suite)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02253)
                          "Unable to reconfigure (per-directory) "
                          "permitted SSL ciphers");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, r->server);

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

        if (renegotiate) {
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
            if (sc->cipher_server_pref == TRUE) {
                SSL_set_options(ssl, SSL_OP_CIPHER_SERVER_PREFERENCE);
            }
#endif
            /* tracing */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02220)
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
     * SSLConnRec attached to the SSL* of OpenSSL.  We've to force the
     * renegotiation if the reconfigured/new verify depth is less than the
     * currently active/remembered verify depth (because this means more
     * restriction on the certificate chain).
     */
    n = (sslconn->verify_depth != UNSET) ?
        sslconn->verify_depth :
        (mySrvConfig(handshakeserver))->server->auth.verify_depth;
    /* determine the new depth */
    sslconn->verify_depth = (dc->nVerifyDepth != UNSET) ?
                            dc->nVerifyDepth : sc->server->auth.verify_depth;
    if (sslconn->verify_depth < n) {
        renegotiate = TRUE;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02254)
                     "Reduced client verification depth will force "
                     "renegotiation");
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
     * verification but at least skip the I/O-intensive renegotiation
     * handshake.
     */
    if ((dc->nVerifyClient != SSL_CVERIFY_UNSET) ||
        (sc->server->auth.verify_mode != SSL_CVERIFY_UNSET)) {
        /* remember old state */
        verify_old = SSL_get_verify_mode(ssl);
        /* configure new state */
        verify = SSL_VERIFY_NONE;

        if ((dc->nVerifyClient == SSL_CVERIFY_REQUIRE) ||
            (sc->server->auth.verify_mode == SSL_CVERIFY_REQUIRE)) {
            verify |= SSL_VERIFY_PEER_STRICT;
        }

        if ((dc->nVerifyClient == SSL_CVERIFY_OPTIONAL) ||
            (dc->nVerifyClient == SSL_CVERIFY_OPTIONAL_NO_CA) ||
            (sc->server->auth.verify_mode == SSL_CVERIFY_OPTIONAL) ||
            (sc->server->auth.verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA))
        {
            verify |= SSL_VERIFY_PEER;
        }

        SSL_set_verify(ssl, verify, ssl_callback_SSLVerify);
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

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02255)
                              "Changed client verification type will force "
                              "%srenegotiation",
                              renegotiate_quick ? "quick " : "");
             }
        }
        /* If we're handling a request for a vhost other than the default one,
         * then we need to make sure that client authentication is properly
         * enforced. For clients supplying an SNI extension, the peer
         * certificate verification has happened in the handshake already
         * (and r->server == handshakeserver). For non-SNI requests,
         * an additional check is needed here. If client authentication
         * is configured as mandatory, then we can only proceed if the
         * CA list doesn't have to be changed (OpenSSL doesn't provide
         * an option to change the list for an existing session).
         */
        if ((r->server != handshakeserver)
            && renegotiate
            && ((verify & SSL_VERIFY_PEER) ||
                (verify & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))) {
            SSLSrvConfigRec *hssc = mySrvConfig(handshakeserver);

#define MODSSL_CFG_CA_NE(f, sc1, sc2) \
            (sc1->server->auth.f && \
             (!sc2->server->auth.f || \
              strNE(sc1->server->auth.f, sc2->server->auth.f)))

            if (MODSSL_CFG_CA_NE(ca_cert_file, sc, hssc) ||
                MODSSL_CFG_CA_NE(ca_cert_path, sc, hssc)) {
                if (verify & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02256)
                         "Non-default virtual host with SSLVerify set to "
                         "'require' and VirtualHost-specific CA certificate "
                         "list is only available to clients with TLS server "
                         "name indication (SNI) support");
                    SSL_set_verify(ssl, verify_old, NULL);
                    return HTTP_FORBIDDEN;
                } else
                    /* let it pass, possibly with an "incorrect" peer cert,
                     * so make sure the SSL_CLIENT_VERIFY environment variable
                     * will indicate partial success only, later on.
                     */
                    sslconn->verify_info = "GENEROUS";
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02257)
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
         * Now we force the SSL renegotiation by sending the Hello Request
         * message to the client. Here we have to do a workaround: Actually
         * OpenSSL returns immediately after sending the Hello Request (the
         * intent AFAIK is because the SSL/TLS protocol says it's not a must
         * that the client replies to a Hello Request). But because we insist
         * on a reply (anything else is an error for us) we have to go to the
         * ACCEPT state manually. Using SSL_set_accept_state() doesn't work
         * here because it resets too much of the connection.  So we set the
         * state explicitly and continue the handshake manually.
         */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02221)
                      "Requesting connection re-negotiation");

        if (renegotiate_quick) {
            STACK_OF(X509) *cert_stack;

            /* perform just a manual re-verification of the peer */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02258)
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
                sk_X509_push(cert_stack, cert);
            }

            if (!cert_stack || (sk_X509_num(cert_stack) == 0)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02222)
                              "Cannot find peer certificate chain");

                return HTTP_FORBIDDEN;
            }

            if (!(cert_store ||
                  (cert_store = SSL_CTX_get_cert_store(ctx))))
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02223)
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

            if (!X509_verify_cert(&cert_store_ctx)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02224)
                              "Re-negotiation verification step failed");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, r->server);
            }

            SSL_set_verify_result(ssl, cert_store_ctx.error);
            X509_STORE_CTX_cleanup(&cert_store_ctx);

            if (cert_stack != SSL_get_peer_cert_chain(ssl)) {
                /* we created this ourselves, so free it */
                sk_X509_pop_free(cert_stack, X509_free);
            }
        }
        else {
            const char *reneg_support;
            request_rec *id = r->main ? r->main : r;

            /* Additional mitigation for CVE-2009-3555: At this point,
             * before renegotiating, an (entire) request has been read
             * from the connection.  An attacker may have sent further
             * data to "prefix" any subsequent request by the victim's
             * client after the renegotiation; this data may already
             * have been read and buffered.  Forcing a connection
             * closure after the response ensures such data will be
             * discarded.  Legimately pipelined HTTP requests will be
             * retried anyway with this approach. */
            if (has_buffered_data(r)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02259)
                              "insecure SSL re-negotiation required, but "
                              "a pipelined request is present; keepalive "
                              "disabled");
                r->connection->keepalive = AP_CONN_CLOSE;
            }

#if defined(SSL_get_secure_renegotiation_support)
            reneg_support = SSL_get_secure_renegotiation_support(ssl) ?
                            "client does" : "client does not";
#else
            reneg_support = "server does not";
#endif
            /* Perform a full renegotiation. */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02260)
                          "Performing full renegotiation: complete handshake "
                          "protocol (%s support secure renegotiation)",
                          reneg_support);

            SSL_set_session_id_context(ssl,
                                       (unsigned char *)&id,
                                       sizeof(id));

            /* Toggle the renegotiation state to allow the new
             * handshake to proceed. */
            sslconn->reneg_state = RENEG_ALLOW;

            SSL_renegotiate(ssl);
            SSL_do_handshake(ssl);

            if (SSL_get_state(ssl) != SSL_ST_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02225)
                              "Re-negotiation request failed");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, r->server);

                r->connection->keepalive = AP_CONN_CLOSE;
                return HTTP_FORBIDDEN;
            }

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02226)
                          "Awaiting re-negotiation handshake");

            /* XXX: Should replace setting state with SSL_renegotiate(ssl);
             * However, this causes failures in perl-framework currently,
             * perhaps pre-test if we have already negotiated?
             */
#ifdef OPENSSL_NO_SSL_INTERN
            SSL_set_state(ssl, SSL_ST_ACCEPT);
#else
            ssl->state = SSL_ST_ACCEPT;
#endif
            SSL_do_handshake(ssl);

            sslconn->reneg_state = RENEG_REJECT;

            if (SSL_get_state(ssl) != SSL_ST_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02261)
                              "Re-negotiation handshake failed: "
                              "Not accepted by client!?");

                r->connection->keepalive = AP_CONN_CLOSE;
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
        if ((dc->nVerifyClient != SSL_CVERIFY_NONE) ||
            (sc->server->auth.verify_mode != SSL_CVERIFY_NONE)) {
            BOOL do_verify = ((dc->nVerifyClient == SSL_CVERIFY_REQUIRE) ||
                              (sc->server->auth.verify_mode == SSL_CVERIFY_REQUIRE));

            if (do_verify && (SSL_get_verify_result(ssl) != X509_V_OK)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02262)
                              "Re-negotiation handshake failed: "
                              "Client verification failed");

                return HTTP_FORBIDDEN;
            }

            if (do_verify) {
                if ((peercert = SSL_get_peer_certificate(ssl)) == NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02263)
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02264)
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
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02227)
                          "Failed to set r->user to '%s'", dc->szUserName);
    }

    /*
     * Check SSLRequire boolean expressions
     */
    requires = dc->aRequirement;
    ssl_requires = (ssl_require_t *)requires->elts;

    for (i = 0; i < requires->nelts; i++) {
        ssl_require_t *req = &ssl_requires[i];
        const char *errstring;
        ok = ap_expr_exec(r, req->mpExpr, &errstring);

        if (ok < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02265)
                          "access to %s failed, reason: Failed to execute "
                          "SSL requirement expression: %s",
                          r->filename, errstring);

            /* remember forbidden access for strict require option */
            apr_table_setn(r->notes, "ssl-access-forbidden", "1");

            return HTTP_FORBIDDEN;
        }

        if (ok != 1) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02266)
                          "Access to %s denied for %s "
                          "(requirement expression not fulfilled)",
                          r->filename, r->useragent_ip);

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02228)
                          "Failed expression: %s", req->cpExpr);

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02229)
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
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02035)
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
        OPENSSL_free(cp);
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
    apr_table_setn(r->headers_in, "Authorization", auth_line);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02036)
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
    "SSL_SECURE_RENEG",
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
    "SSL_CLIENT_S_DN",
    "SSL_CLIENT_I_DN",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
    "SSL_SERVER_S_DN",
    "SSL_SERVER_I_DN",
    "SSL_SERVER_A_KEY",
    "SSL_SERVER_A_SIG",
    "SSL_SESSION_ID",
    "SSL_SESSION_RESUMED",
#ifdef HAVE_SRP
    "SSL_SRP_USER",
    "SSL_SRP_USERINFO",
#endif
    NULL
};

int ssl_hook_Fixup(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLDirConfigRec *dc = myDirConfig(r);
    apr_table_t *env = r->subprocess_env;
    char *var, *val = "";
#ifdef HAVE_TLSEXT
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

#ifdef HAVE_TLSEXT
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


#ifdef SSL_get_secure_renegotiation_support
    apr_table_setn(r->notes, "ssl-secure-reneg",
                   SSL_get_secure_renegotiation_support(ssl) ? "1" : "0");
#endif

    return DECLINED;
}

/*  _________________________________________________________________
**
**  Authz providers for use with mod_authz_core
**  _________________________________________________________________
*/

static authz_status ssl_authz_require_ssl_check(request_rec *r,
                                                const char *require_line,
                                                const void *parsed)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSL *ssl = sslconn ? sslconn->ssl : NULL;

    if (ssl)
        return AUTHZ_GRANTED;
    else
        return AUTHZ_DENIED;
}

static const char *ssl_authz_require_ssl_parse(cmd_parms *cmd,
                                               const char *require_line,
                                               const void **parsed)
{
    if (require_line && require_line[0])
        return "'Require ssl' does not take arguments";

    return NULL;
}

const authz_provider ssl_authz_provider_require_ssl =
{
    &ssl_authz_require_ssl_check,
    &ssl_authz_require_ssl_parse,
};

static authz_status ssl_authz_verify_client_check(request_rec *r,
                                                  const char *require_line,
                                                  const void *parsed)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSL *ssl = sslconn ? sslconn->ssl : NULL;

    if (!ssl)
        return AUTHZ_DENIED;

    if (sslconn->verify_error == NULL &&
        sslconn->verify_info == NULL &&
        SSL_get_verify_result(ssl) == X509_V_OK)
    {
        X509 *xs = SSL_get_peer_certificate(ssl);

        if (xs) {
            X509_free(xs);
            return AUTHZ_GRANTED;
        }
        else {
            X509_free(xs);
        }
    }

    return AUTHZ_DENIED;
}

static const char *ssl_authz_verify_client_parse(cmd_parms *cmd,
                                                 const char *require_line,
                                                 const void **parsed)
{
    if (require_line && require_line[0])
        return "'Require ssl-verify-client' does not take arguments";

    return NULL;
}

const authz_provider ssl_authz_provider_verify_client =
{
    &ssl_authz_verify_client_check,
    &ssl_authz_verify_client_parse,
};



/*  _________________________________________________________________
**
**  OpenSSL Callback Functions
**  _________________________________________________________________
*/

/*
 * Hand out standard DH parameters, based on the authentication strength
 */
DH *ssl_callback_TmpDH(SSL *ssl, int export, int keylen)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    EVP_PKEY *pkey;
    int type;

#ifdef SSL_CERT_SET_SERVER
    /*
     * When multiple certs/keys are configured for the SSL_CTX: make sure
     * that we get the private key which is indeed used for the current
     * SSL connection (available in OpenSSL 1.0.2 or later only)
     */
    SSL_set_current_cert(ssl, SSL_CERT_SET_SERVER);
#endif
    pkey = SSL_get_privatekey(ssl);
    type = pkey ? EVP_PKEY_type(pkey->type) : EVP_PKEY_NONE;

    /*
     * OpenSSL will call us with either keylen == 512 or keylen == 1024
     * (see the definition of SSL_EXPORT_PKEYLENGTH in ssl_locl.h).
     * Adjust the DH parameter length according to the size of the
     * RSA/DSA private key used for the current connection, and always
     * use at least 1024-bit parameters.
     * Note: This may cause interoperability issues with implementations
     * which limit their DH support to 1024 bit - e.g. Java 7 and earlier.
     * In this case, SSLCertificateFile can be used to specify fixed
     * 1024-bit DH parameters (with the effect that OpenSSL skips this
     * callback).
     */
    if ((type == EVP_PKEY_RSA) || (type == EVP_PKEY_DSA)) {
        keylen = EVP_PKEY_bits(pkey);
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "handing out built-in DH parameters for %d-bit authenticated connection", keylen);

    return modssl_get_dh_params(keylen);
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
    request_rec *r      = (request_rec *)SSL_get_app_data2(ssl);
    server_rec *s       = r ? r->server : mySrvFromConn(conn);

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
    ssl_log_cxerror(SSLLOG_MARK, APLOG_DEBUG, 0, conn,
                    X509_STORE_CTX_get_current_cert(ctx), APLOGNO(02275)
                    "Certificate Verification, depth %d, "
                    "CRL checking mode: %s", errdepth,
                    mctx->crl_check_mode == SSL_CRLCHECK_CHAIN ?
                    "chain" : (mctx->crl_check_mode == SSL_CRLCHECK_LEAF ?
                               "leaf" : "none"));

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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, conn, APLOGNO(02037)
                      "Certificate Verification: Verifiable Issuer is "
                      "configured as optional, therefore we're accepting "
                      "the certificate");

        sslconn->verify_info = "GENEROUS";
        ok = TRUE;
    }

    /*
     * Expired certificates vs. "expired" CRLs: by default, OpenSSL
     * turns X509_V_ERR_CRL_HAS_EXPIRED into a "certificate_expired(45)"
     * SSL alert, but that's not really the message we should convey to the
     * peer (at the very least, it's confusing, and in many cases, it's also
     * inaccurate, as the certificate itself may very well not have expired
     * yet). We set the X509_STORE_CTX error to something which OpenSSL's
     * s3_both.c:ssl_verify_alarm_type() maps to SSL_AD_CERTIFICATE_UNKNOWN,
     * i.e. the peer will receive a "certificate_unknown(46)" alert.
     * We do not touch errnum, though, so that later on we will still log
     * the "real" error, as returned by OpenSSL.
     */
    if (!ok && errnum == X509_V_ERR_CRL_HAS_EXPIRED) {
        X509_STORE_CTX_set_error(ctx, -1);
    }

#ifndef OPENSSL_NO_OCSP
    /*
     * Perform OCSP-based revocation checks
     */
    if (ok && sc->server->ocsp_enabled) {
        /* If there was an optional verification error, it's not
         * possible to perform OCSP validation since the issuer may be
         * missing/untrusted.  Fail in that case. */
        if (ssl_verify_error_is_optional(errnum)) {
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
            errnum = X509_V_ERR_APPLICATION_VERIFICATION;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn, APLOGNO(02038)
                          "cannot perform OCSP validation for cert "
                          "if issuer has not been verified "
                          "(optional_no_ca configured)");
            ok = FALSE;
        } else {
            ok = modssl_verify_ocsp(ctx, sc, s, conn, conn->pool);
            if (!ok) {
                errnum = X509_STORE_CTX_get_error(ctx);
            }
        }
    }
#endif

    /*
     * If we already know it's not ok, log the real reason
     */
    if (!ok) {
        if (APLOGcinfo(conn)) {
            ssl_log_cxerror(SSLLOG_MARK, APLOG_INFO, 0, conn,
                            X509_STORE_CTX_get_current_cert(ctx), APLOGNO(02276)
                            "Certificate Verification: Error (%d): %s",
                            errnum, X509_verify_cert_error_string(errnum));
        } else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn, APLOGNO(02039)
                          "Certificate Verification: Error (%d): %s",
                          errnum, X509_verify_cert_error_string(errnum));
        }

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
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, conn, APLOGNO(02040)
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

#define SSLPROXY_CERT_CB_LOG_FMT \
   "Proxy client certificate callback: (%s) "

static void modssl_proxy_info_log(conn_rec *c,
                                  X509_INFO *info,
                                  const char *msg)
{
    ssl_log_cxerror(SSLLOG_MARK, APLOG_DEBUG, 0, c, info->x509, APLOGNO(02277)
                    SSLPROXY_CERT_CB_LOG_FMT "%s, sending",
                    (mySrvConfigFromConn(c))->vhost_id, msg);
}

/*
 * caller will decrement the cert and key reference
 * so we need to increment here to prevent them from
 * being freed.
 */
#define modssl_set_cert_info(info, cert, pkey) \
    *cert = info->x509; \
    CRYPTO_add(&(*cert)->references, +1, CRYPTO_LOCK_X509); \
    *pkey = info->x_pkey->dec_pkey; \
    CRYPTO_add(&(*pkey)->references, +1, CRYPTO_LOCK_X509_PKEY)

int ssl_callback_proxy_cert(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s = mySrvFromConn(c);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    X509_NAME *ca_name, *issuer, *ca_issuer;
    X509_INFO *info;
    X509 *ca_cert;
    STACK_OF(X509_NAME) *ca_list;
    STACK_OF(X509_INFO) *certs = sc->proxy->pkp->certs;
    STACK_OF(X509) *ca_certs;
    STACK_OF(X509) **ca_cert_chains;
    int i, j, k;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02267)
                 SSLPROXY_CERT_CB_LOG_FMT "entered",
                 sc->vhost_id);

    if (!certs || (sk_X509_INFO_num(certs) <= 0)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(02268)
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

        modssl_proxy_info_log(c, info, APLOGNO(02278) "no acceptable CA list");

        modssl_set_cert_info(info, x509, pkey);

        return TRUE;
    }

    ca_cert_chains = sc->proxy->pkp->ca_certs;
    for (i = 0; i < sk_X509_NAME_num(ca_list); i++) {
        ca_name = sk_X509_NAME_value(ca_list, i);

        for (j = 0; j < sk_X509_INFO_num(certs); j++) {
            info = sk_X509_INFO_value(certs, j);
            issuer = X509_get_issuer_name(info->x509);

            /* Search certs (by issuer name) one by one*/
            if (X509_NAME_cmp(issuer, ca_name) == 0) {
                modssl_proxy_info_log(c, info, APLOGNO(02279)
                                      "found acceptable cert");

                modssl_set_cert_info(info, x509, pkey);

                return TRUE;
            }

            if (ca_cert_chains) {
                /*
                 * Failed to find direct issuer - search intermediates
                 * (by issuer name), if provided.
                 */
                ca_certs = ca_cert_chains[j];
                for (k = 0; k < sk_X509_num(ca_certs); k++) {
                    ca_cert = sk_X509_value(ca_certs, k);
                    ca_issuer = X509_get_issuer_name(ca_cert);

                    if(X509_NAME_cmp(ca_issuer, ca_name) == 0 ) {
                        modssl_proxy_info_log(c, info, APLOGNO(02280)
                                              "found acceptable cert by intermediate CA");

                        modssl_set_cert_info(info, x509, pkey);

                        return TRUE;
                    }
                } /* end loop through chained certs */
            }
        } /* end loop through available certs */
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(02269)
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

    if (!APLOGdebug(s)) {
        return;
    }

    if (timeout) {
        apr_snprintf(timeout_str, sizeof(timeout_str),
                     "timeout=%lds ", timeout);
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,
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
#ifdef OPENSSL_NO_SSL_INTERN
    id = (unsigned char *)SSL_SESSION_get_id(session, &idlen);
#else
    id = session->session_id;
    idlen = session->session_id_length;
#endif

    rc = ssl_scache_store(s, id, idlen,
                          apr_time_from_sec(SSL_SESSION_get_time(session)
                                          + timeout),
                          session, conn->pool);

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
#ifdef OPENSSL_NO_SSL_INTERN
    id = (unsigned char *)SSL_SESSION_get_id(session, &idlen);
#else
    id = session->session_id;
    idlen = session->session_id_length;
#endif

    /* TODO: Do we need a temp pool here, or are we always shutting down? */
    ssl_scache_remove(s, id, idlen, sc->mc->pPool);

    ssl_session_log(s, "REM", id, idlen,
                    "OK", "dead", 0);

    return;
}

/* Dump debugginfo trace to the log file. */
static void log_tracing_state(const SSL *ssl, conn_rec *c,
                              server_rec *s, int where, int rc)
{
    /*
     * create the various trace messages
     */
    if (where & SSL_CB_HANDSHAKE_START) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                      "%s: Handshake: start", SSL_LIBRARY_NAME);
    }
    else if (where & SSL_CB_HANDSHAKE_DONE) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                      "%s: Handshake: done", SSL_LIBRARY_NAME);
    }
    else if (where & SSL_CB_LOOP) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                      "%s: Loop: %s",
                      SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
    }
    else if (where & SSL_CB_READ) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                      "%s: Read: %s",
                      SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
    }
    else if (where & SSL_CB_WRITE) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                      "%s: Write: %s",
                      SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
    }
    else if (where & SSL_CB_ALERT) {
        char *str = (where & SSL_CB_READ) ? "read" : "write";
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                      "%s: Alert: %s:%s:%s",
                      SSL_LIBRARY_NAME, str,
                      SSL_alert_type_string_long(rc),
                      SSL_alert_desc_string_long(rc));
    }
    else if (where & SSL_CB_EXIT) {
        if (rc == 0) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                          "%s: Exit: failed in %s",
                          SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
        }
        else if (rc < 0) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c,
                          "%s: Exit: error in %s",
                          SSL_LIBRARY_NAME, SSL_state_string_long(ssl));
        }
    }

    /*
     * Because SSL renegotiations can happen at any time (not only after
     * SSL_accept()), the best way to log the current connection details is
     * right after a finished handshake.
     */
    if (where & SSL_CB_HANDSHAKE_DONE) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02041)
                      "Protocol: %s, Cipher: %s (%s/%s bits)",
                      ssl_var_lookup(NULL, s, c, NULL, "SSL_PROTOCOL"),
                      ssl_var_lookup(NULL, s, c, NULL, "SSL_CIPHER"),
                      ssl_var_lookup(NULL, s, c, NULL, "SSL_CIPHER_USEKEYSIZE"),
                      ssl_var_lookup(NULL, s, c, NULL, "SSL_CIPHER_ALGKEYSIZE"));
    }
}

/*
 * This callback function is executed while OpenSSL processes the SSL
 * handshake and does SSL record layer stuff.  It's used to trap
 * client-initiated renegotiations, and for dumping everything to the
 * log.
 */
void ssl_callback_Info(const SSL *ssl, int where, int rc)
{
    conn_rec *c;
    server_rec *s;
    SSLConnRec *scr;

    /* Retrieve the conn_rec and the associated SSLConnRec. */
    if ((c = (conn_rec *)SSL_get_app_data((SSL *)ssl)) == NULL) {
        return;
    }

    if ((scr = myConnConfig(c)) == NULL) {
        return;
    }

    /* If the reneg state is to reject renegotiations, check the SSL
     * state machine and move to ABORT if a Client Hello is being
     * read. */
    if ((where & SSL_CB_ACCEPT_LOOP) && scr->reneg_state == RENEG_REJECT) {
        int state = SSL_get_state((SSL *)ssl);

        if (state == SSL3_ST_SR_CLNT_HELLO_A
            || state == SSL23_ST_SR_CLNT_HELLO_A) {
            scr->reneg_state = RENEG_ABORT;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02042)
                          "rejecting client initiated renegotiation");
        }
    }
    /* If the first handshake is complete, change state to reject any
     * subsequent client-initiated renegotiation. */
    else if ((where & SSL_CB_HANDSHAKE_DONE) && scr->reneg_state == RENEG_INIT) {
        scr->reneg_state = RENEG_REJECT;
    }

    s = mySrvFromConn(c);
    if (s && APLOGdebug(s)) {
        log_tracing_state(ssl, c, s, where, rc);
    }
}

#ifdef HAVE_TLSEXT
/*
 * This callback function is executed when OpenSSL encounters an extended
 * client hello with a server name indication extension ("SNI", cf. RFC 6066).
 */
int ssl_callback_ServerNameIndication(SSL *ssl, int *al, modssl_ctx_t *mctx)
{
    const char *servername =
                SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);

    if (c) {
        if (servername) {
            if (ap_vhost_iterate_given_conn(c, ssl_find_vhost,
                                            (void *)servername)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02043)
                              "SSL virtual host for servername %s found",
                              servername);
                return SSL_TLSEXT_ERR_OK;
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02044)
                              "No matching SSL virtual host for servername "
                              "%s found (using default/first virtual host)",
                              servername);
                /*
                 * RFC 6066 section 3 says "It is NOT RECOMMENDED to send
                 * a warning-level unrecognized_name(112) alert, because
                 * the client's behavior in response to warning-level alerts
                 * is unpredictable."
                 *
                 * To maintain backwards compatibility in mod_ssl, we
                 * no longer send any alert (neither warning- nor fatal-level),
                 * i.e. we take the second action suggested in RFC 6066:
                 * "If the server understood the ClientHello extension but
                 * does not recognize the server name, the server SHOULD take
                 * one of two actions: either abort the handshake by sending
                 * a fatal-level unrecognized_name(112) alert or continue
                 * the handshake."
                 */
            }
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02645)
                          "Server name not provided via TLS extension "
                          "(using default/first virtual host)");
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
        SSL_CTX *ctx = SSL_set_SSL_CTX(ssl, sc->server->ssl_ctx);
        /*
         * SSL_set_SSL_CTX() only deals with the server cert,
         * so we need to duplicate a few additional settings
         * from the ctx by hand
         */
        SSL_set_options(ssl, SSL_CTX_get_options(ctx));
        if ((SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE) ||
            (SSL_num_renegotiations(ssl) == 0)) {
           /*
            * Only initialize the verification settings from the ctx
            * if they are not yet set, or if we're called when a new
            * SSL connection is set up (num_renegotiations == 0).
            * Otherwise, we would possibly reset a per-directory
            * configuration which was put into effect by ssl_hook_Access.
            */
            SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx),
                           SSL_CTX_get_verify_callback(ctx));
        }

        /*
         * Adjust the session id context. ssl_init_ssl_connection()
         * always picks the configuration of the first vhost when
         * calling SSL_new(), but we want to tie the session to the
         * vhost we have just switched to. Again, we have to make sure
         * that we're not overwriting a session id context which was
         * possibly set in ssl_hook_Access(), before triggering
         * a renegotiation.
         */
        if (SSL_num_renegotiations(ssl) == 0) {
            unsigned char *sid_ctx =
                (unsigned char *)ap_md5_binary(c->pool,
                                               (unsigned char *)sc->vhost_id,
                                               sc->vhost_id_len);
            SSL_set_session_id_context(ssl, sid_ctx, APR_MD5_DIGESTSIZE*2);
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
         * (and the first vhost doesn't use APLOG_TRACE4), then
         * we need to set that callback here.
         */
        if (APLOGtrace4(s)) {
            BIO_set_callback(SSL_get_rbio(ssl), ssl_io_data_cb);
            BIO_set_callback_arg(SSL_get_rbio(ssl), (void *)ssl);
        }

        return 1;
    }

    return 0;
}
#endif /* HAVE_TLSEXT */

#ifdef HAVE_TLS_SESSION_TICKETS
/*
 * This callback function is executed when OpenSSL needs a key for encrypting/
 * decrypting a TLS session ticket (RFC 5077) and a ticket key file has been
 * configured through SSLSessionTicketKeyFile.
 */
int ssl_callback_SessionTicket(SSL *ssl,
                               unsigned char *keyname,
                               unsigned char *iv,
                               EVP_CIPHER_CTX *cipher_ctx,
                               HMAC_CTX *hctx,
                               int mode)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s = mySrvFromConn(c);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    SSLConnRec *sslconn = myConnConfig(c);
    modssl_ctx_t *mctx = myCtxConfig(sslconn, sc);
    modssl_ticket_key_t *ticket_key = mctx->ticket_key;

    if (mode == 1) {
        /* 
         * OpenSSL is asking for a key for encrypting a ticket,
         * see s3_srvr.c:ssl3_send_newsession_ticket()
         */

        if (ticket_key == NULL) {
            /* should never happen, but better safe than sorry */
            return -1;
        }

        memcpy(keyname, ticket_key->key_name, 16);
        RAND_pseudo_bytes(iv, EVP_MAX_IV_LENGTH);
        EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL,
                           ticket_key->aes_key, iv);
        HMAC_Init_ex(hctx, ticket_key->hmac_secret, 16, tlsext_tick_md(), NULL);

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02289)
                      "TLS session ticket key for %s successfully set, "
                      "creating new session ticket", sc->vhost_id);

        return 0;
    }
    else if (mode == 0) {
        /* 
         * OpenSSL is asking for the decryption key,
         * see t1_lib.c:tls_decrypt_ticket()
         */

        /* check key name */
        if (ticket_key == NULL || memcmp(keyname, ticket_key->key_name, 16)) {
            return 0;
        }

        EVP_DecryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL,
                           ticket_key->aes_key, iv);
        HMAC_Init_ex(hctx, ticket_key->hmac_secret, 16, tlsext_tick_md(), NULL);

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(02290)
                      "TLS session ticket key for %s successfully set, "
                      "decrypting existing session ticket", sc->vhost_id);

        return 1;
    }

    /* OpenSSL is not expected to call us with modes other than 1 or 0 */
    return -1;
}
#endif /* HAVE_TLS_SESSION_TICKETS */

static int ssl_array_index(apr_array_header_t *array,
                           const unsigned char *s)
{
    int i;
    for (i = 0; i < array->nelts; i++) {
        const unsigned char *p = APR_ARRAY_IDX(array, i, const unsigned char*);
        if (!strcmp((const char *)p, (const char *)s)) {
            return i;
        }
    }
    return -1;
}

#ifdef HAVE_TLS_ALPN
/*
 * Compare to ALPN protocol proposal. Result is similar to strcmp():
 * 0 gives same precedence, >0 means proto1 is prefered.
 */
static int ssl_cmp_alpn_protos(modssl_ctx_t *ctx,
							   const unsigned char *proto1,
							   const unsigned char *proto2)
{
	/* TODO: we should have a mod_ssl configuration parameter. */
    if (ctx && ctx->ssl_alpn_pref) {
        int index1 = ssl_array_index(ctx->ssl_alpn_pref, proto1);
        int index2 = ssl_array_index(ctx->ssl_alpn_pref, proto2);
        if (index2 > index1) {
            return (index1 >= 0)? 1 : -1;
        }
        else if (index1 > index2) {
            return (index2 >= 0)? -1 : 1;
        }
    }
    /* both have the same index (mabye -1 or no pref configured) and we compare
     * the names so that spdy3 gets precedence over spdy2. That makes
     * the outcome at least deterministic. */
	return strcmp((const char *)proto1, (const char *)proto2);
}

/*
 * This callback function is executed when the TLS Application Layer
 * Protocol Negotiate Extension (ALPN, RFC 7301) is triggered by the client 
 * hello, giving a list of desired protocol names (in descending preference) 
 * to the server.
 * The callback has to select a protocol name or return an error if none of
 * the clients preferences is supported. 
 * The selected protocol does not have to be on the client list, according
 * to RFC 7301, so no checks are performed.
 * The client protocol list is serialized as length byte followed by ascii
 * characters (not null-terminated), followed by the next protocol name.
 */
int ssl_callback_alpn_select(SSL *ssl,
							 const unsigned char **out, unsigned char *outlen,
							 const unsigned char *in, unsigned int inlen, void *arg)
{
	conn_rec *c = (conn_rec*)SSL_get_app_data(ssl);
	SSLConnRec *sslconn = myConnConfig(c);
    server_rec *s       = mySrvFromConn(c);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    modssl_ctx_t *mctx  = myCtxConfig(sslconn, sc);
	const unsigned char *alpn_http1 = (const unsigned char*)"http/1.1";
	apr_array_header_t *client_protos;
	apr_array_header_t *proposed_protos;
	int i;

	/* If the connection object is not available,
	 * then there's nothing for us to do. */
	if (c == NULL) {
		return SSL_TLSEXT_ERR_OK;
	}
	
	if (inlen == 0) {
		// someone tries to trick us?
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02306)
					  "alpn client protocol list empty");
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	
	client_protos = apr_array_make(c->pool, 0, sizeof(char *));
	for (i = 0; i < inlen; /**/) {
		unsigned int plen = in[i++];
		if (plen + i > inlen) {
			// someone tries to trick us?
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02306)
						  "alpn protocol identier too long");
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		}
		APR_ARRAY_PUSH(client_protos, char*) =
			apr_pstrndup(c->pool, (const char *)in+i, plen);
		i += plen;
	}
	
	/* Regardless of installed hooks, the http/1.1 protocol is always
	 * supported by us. Add it to the proposals if the client also
	 * offers it. */
	proposed_protos = apr_array_make(c->pool, client_protos->nelts+1,
									 sizeof(char *));
	if (ssl_array_index(client_protos, alpn_http1) >= 0) {
		APR_ARRAY_PUSH(proposed_protos, const unsigned char*) = alpn_http1;
	}
	
	if (sslconn->alpn_proposefns != NULL) {
		/* Invoke our alpn_propos_proto hooks, giving other modules a chance to
		 * propose protocol names for selection. We might have several such
		 * hooks installed and if two make a proposal, we need to give 
		 * preference to one.
		 */
		for (i = 0; i < sslconn->alpn_proposefns->nelts; i++) {
			ssl_alpn_propose_protos fn =
				APR_ARRAY_IDX(sslconn->alpn_proposefns, i,
							  ssl_alpn_propose_protos);
			
			if (fn(c, client_protos, proposed_protos) == DONE)
				break;
		}
	}

	if (proposed_protos->nelts <= 0) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02306)
					  "none of the client alpn protocols are supported");
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	
	/* Now select the most preferred protocol from the proposals. */
	*out = APR_ARRAY_IDX(proposed_protos, 0, const unsigned char *);
	for (i = 1; i < proposed_protos->nelts; ++i) {
		const unsigned char *proto = APR_ARRAY_IDX(proposed_protos, i,
												   const unsigned char*);
		/* Do we prefer it over existing candidate? */
		if (ssl_cmp_alpn_protos(mctx, *out, proto) < 0) {
			*out = proto;
		}
	}
	
	size_t len = strlen((const char*)*out);
	if (len > 255) {
		ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02306)
					  "alpn negotiated protocol name too long");
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	*outlen = (unsigned char)len;

	return SSL_TLSEXT_ERR_OK;
}

#elif defined(HAVE_TLS_NPN)
/*
 * This callback function is executed when SSL needs to decide what protocols
 * to advertise during Next Protocol Negotiation (NPN).  It must produce a
 * string in wire format -- a sequence of length-prefixed strings -- indicating
 * the advertised protocols.  Refer to SSL_CTX_set_next_protos_advertised_cb
 * in OpenSSL for reference.
 */
int ssl_callback_AdvertiseNextProtos(SSL *ssl, const unsigned char **data_out,
                                     unsigned int *size_out, void *arg)
{
    conn_rec *c = (conn_rec*)SSL_get_app_data(ssl);
    SSLConnRec *sslconn = myConnConfig(c);
    server_rec *s       = mySrvFromConn(c);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    modssl_ctx_t *mctx  = myCtxConfig(sslconn, sc);
    apr_array_header_t *protos;
    int num_protos;
    unsigned int size;
    int i, j;
    unsigned char *data;
    unsigned char *start;

    *data_out = NULL;
    *size_out = 0;

    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02306)
                  "advertisingNextProtos");

    /* If the connection object is not available, or there are no NPN
     * hooks registered, then there's nothing for us to do. */
    if (c == NULL || sslconn->alpn_proposefns == NULL) {
        return SSL_TLSEXT_ERR_OK;
    }

    /* Invoke our alpn_propose_proto hook, giving other modules a chance to
     * add alternate protocol names to advertise. */
    protos = apr_array_make(c->pool, 0, sizeof(char *));
    for (i = 0; i < sslconn->alpn_proposefns->nelts; i++) {
        ssl_alpn_propose_protos fn =
            APR_ARRAY_IDX(sslconn->alpn_proposefns, i, ssl_alpn_propose_protos);
        
        if (fn(c, NULL, protos) == DONE)
            break;
    }
    num_protos = protos->nelts;

    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(02306)
                  "alpn protos %d to advertise, %d in pref config", num_protos, mctx->ssl_alpn_pref->nelts );
	if (num_protos > 1 && mctx->ssl_alpn_pref && mctx->ssl_alpn_pref->nelts > 0) {
		/* Sort the protocol names according to our configured preferences. */
		int insert_idx = 0;
		for (i = 0; i < mctx->ssl_alpn_pref->nelts; ++i) {
			const char *proto = APR_ARRAY_IDX(mctx->ssl_alpn_pref, i, const char*);
			int idx = ssl_array_index(protos, proto);
			if (idx > insert_idx) {
				/* bubble found protocol up */
                for (j = idx; j > insert_idx; --j) {
                    ((const char **)protos->elts)[j] = ((const char **)protos->elts)[j-1];
                }
                ((const char **)protos->elts)[insert_idx] = proto;
				++insert_idx;
			}
		}
	}
    
    /* We now have a list of null-terminated strings; we need to concatenate
     * them together into a single string, where each protocol name is prefixed
     * by its length.  First, calculate how long that string will be. */
    size = 0;
    for (i = 0; i < num_protos; ++i) {
        const char *string = APR_ARRAY_IDX(protos, i, const char*);
        unsigned int length = strlen(string);
        /* If the protocol name is too long (the length must fit in one byte),
         * then log an error and skip it. */
        if (length > 255) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02307)
                          "SSL NPN protocol name too long (length=%u): %s",
                          length, string);
            continue;
        }
        /* Leave room for the length prefix (one byte) plus the protocol name
         * itself. */
        size += 1 + length;
    }

    /* If there is nothing to advertise (either because no modules added
     * anything to the protos array, or because all strings added to the array
     * were skipped), then we're done. */
    if (size == 0) {
        return SSL_TLSEXT_ERR_OK;
    }

    /* Now we can build the string.  Copy each protocol name string into the
     * larger string, prefixed by its length. */
    data = apr_palloc(c->pool, size * sizeof(unsigned char));
    start = data;
    for (i = 0; i < num_protos; ++i) {
        const char *string = APR_ARRAY_IDX(protos, i, const char*);
        apr_size_t length = strlen(string);
        if (length > 255)
            continue;
        *start = (unsigned char)length;
        ++start;
        memcpy(start, string, length * sizeof(unsigned char));
        start += length;
    }

    /* Success. */
    *data_out = data;
    *size_out = size;
    return SSL_TLSEXT_ERR_OK;
}

#endif /* HAVE_TLS_NPN */

#ifdef HAVE_SRP

int ssl_callback_SRPServerParams(SSL *ssl, int *ad, void *arg)
{
    modssl_ctx_t *mctx = (modssl_ctx_t *)arg;
    char *username = SSL_get_srp_username(ssl);
    SRP_user_pwd *u;

    if (username == NULL
        || (u = SRP_VBASE_get_by_user(mctx->srp_vbase, username)) == NULL) {
        *ad = SSL_AD_UNKNOWN_PSK_IDENTITY;
        return SSL3_AL_FATAL;
    }

    if (SSL_set_srp_server_param(ssl, u->N, u->g, u->s, u->v, u->info) < 0) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL3_AL_FATAL;
    }

    /* reset all other options */
    SSL_set_verify(ssl, SSL_VERIFY_NONE,  ssl_callback_SSLVerify);
    return SSL_ERROR_NONE;
}

#endif /* HAVE_SRP */
