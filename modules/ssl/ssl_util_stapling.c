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
 *  ssl_stapling.c
 *  OCSP Stapling Support
 */
                             /* ``Where's the spoons?
                                  Where's the spoons? 
                                  Where's the bloody spoons?''
                                            -- Alexei Sayle          */

#include "ssl_private.h"
#include "ap_mpm.h"
#include "apr_thread_mutex.h"

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#ifdef HAVE_OCSP_STAPLING

/**
 * Maxiumum OCSP stapling response size. This should be the response for a
 * single certificate and will typically include the responder certificate chain
 * so 10K should be more than enough.
 *
 */

#define MAX_STAPLING_DER 10240

/* Cached info stored in certificate ex_info. */
typedef struct {
    /* Index in session cache SHA1 hash of certificate */
    UCHAR idx[20];
    /* Certificate ID for OCSP requests or NULL if ID cannot be determined */
    OCSP_CERTID *cid;
    /* Responder details */
    char *uri;
} certinfo;

static void certinfo_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                        int idx, long argl, void *argp)
{
    certinfo *cinf = ptr;

    if (!cinf)
        return;
    if (cinf->uri)
        OPENSSL_free(cinf->uri);
    OPENSSL_free(cinf);
}

static int stapling_ex_idx = -1;

void ssl_stapling_ex_init(void)
{
    if (stapling_ex_idx != -1)
        return;
    stapling_ex_idx = X509_get_ex_new_index(0, "X509 cached OCSP info", 0, 0,
                                            certinfo_free);
}

static X509 *stapling_get_issuer(modssl_ctx_t *mctx, X509 *x)
{
    X509 *issuer = NULL;
    int i;
    X509_STORE *st = SSL_CTX_get_cert_store(mctx->ssl_ctx);
    X509_STORE_CTX inctx;

    for (i = 0; i < sk_X509_num(mctx->ssl_ctx->extra_certs); i++) {
	issuer = sk_X509_value(mctx->ssl_ctx->extra_certs, i);
        if (X509_check_issued(issuer, x) == X509_V_OK) {
            CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
            return issuer;
        }
    }

    if (!X509_STORE_CTX_init(&inctx, st, NULL, NULL))
        return 0;
    if (X509_STORE_CTX_get1_issuer(&issuer, &inctx, x) <= 0)
	issuer = NULL;
    X509_STORE_CTX_cleanup(&inctx);
    return issuer;

}

int ssl_stapling_init_cert(server_rec *s, modssl_ctx_t *mctx, X509 *x)
{
    certinfo *cinf;
    X509 *issuer = NULL;
    STACK *aia = NULL;

    if (x == NULL)
        return 0;
    cinf  = X509_get_ex_data(x, stapling_ex_idx);
    if (cinf) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                        "ssl_stapling_init_cert: certificate already initialized!");
        return 0;
    }
    cinf = OPENSSL_malloc(sizeof(certinfo));
    if (!cinf) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                        "ssl_stapling_init_cert: error allocating memory!");
        return 0;
    }
    cinf->cid = NULL;
    cinf->uri = NULL;
    X509_set_ex_data(x, stapling_ex_idx, cinf);

    issuer = stapling_get_issuer(mctx, x);

    if (issuer == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "ssl_stapling_init_cert: Can't retrieve issuer certificate!");
        return 0;
    }

    cinf->cid = OCSP_cert_to_id(NULL, x, issuer);
    X509_free(issuer);
    if (!cinf->cid)
        return 0;
    X509_digest(x, EVP_sha1(), cinf->idx, NULL);

    aia = X509_get1_ocsp(x);
    if (aia)
        cinf->uri = sk_pop(aia);
    if (!cinf->uri && !mctx->stapling_force_url) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "ssl_stapling_init_cert: no responder URL");
    }
    if (aia)
        X509_email_free(aia);
    return 1;
}

static certinfo *stapling_get_cert_info(server_rec *s, modssl_ctx_t *mctx,
                                        SSL *ssl)
{
    certinfo *cinf;
    X509 *x;
    x = SSL_get_certificate(ssl);
    if (x == NULL)
        return NULL;
    cinf  = X509_get_ex_data(x, stapling_ex_idx);
    if (cinf && cinf->cid)
        return cinf;
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "stapling_get_cert_info: stapling not supported for certificate");
    return NULL;
}

/*
 * OCSP response caching code. The response is preceded by a flag value
 * which indicates whether the response was invalid when it was stored.
 * the purpose of this flag is to avoid repeated queries to a server
 * which has given an invalid response while allowing a response which
 * has subsequently become invalid to be retried immediately.
 *
 * The key for the cache is the hash of the certificate the response
 * is for.
 */
static BOOL stapling_cache_response(server_rec *s, modssl_ctx_t *mctx,
                                    OCSP_RESPONSE *rsp, certinfo *cinf,
                                    BOOL ok, apr_pool_t *pool)
{
    SSLModConfigRec *mc = myModConfig(s);
    unsigned char resp_der[MAX_STAPLING_DER];
    unsigned char *p;
    int resp_derlen;
    BOOL rv;
    time_t timeout;

    resp_derlen = i2d_OCSP_RESPONSE(rsp, NULL) + 1;

    if (resp_derlen <= 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "OCSP stapling response encode error??");
        return FALSE;
    }

    if (resp_derlen > sizeof resp_der) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "OCSP stapling response too big (%u bytes)", resp_derlen);
        return FALSE;
    }


    p = resp_der;

    if (ok == TRUE) {
        *p++ = 1;
        timeout = mctx->stapling_cache_timeout;
    } else {
        *p++ = 0;
        timeout = mctx->stapling_errcache_timeout;
    }

    timeout += time(NULL);

    i2d_OCSP_RESPONSE(rsp, &p);

    rv = mc->stapling_cache->store(mc->stapling_cache_context, s,
                                   cinf->idx, sizeof(cinf->idx),
                                   timeout, resp_der, resp_derlen, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_cache_response: OCSP response session store error!");
        return FALSE;
    }
    
    return TRUE;
}

static BOOL stapling_get_cached_response(server_rec *s, OCSP_RESPONSE **prsp,
                                         BOOL *pok, certinfo *cinf,
                                         apr_pool_t *pool)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;
    OCSP_RESPONSE *rsp;
    unsigned char resp_der[MAX_STAPLING_DER];
    const unsigned char *p;
    unsigned int resp_derlen = MAX_STAPLING_DER;

    rv = mc->stapling_cache->retrieve(mc->stapling_cache_context, s,
                                      cinf->idx, sizeof(cinf->idx),
                                      resp_der, &resp_derlen, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "stapling_get_cached_response: cache miss");
        return TRUE;
    }
    if (resp_derlen <= 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_get_cached_response: response length invalid??");
        return TRUE;
    }
    p = resp_der;
    if (pok) {
        if (*p)
            *pok = TRUE;
        else
            *pok = FALSE;
    }
    p++;
    resp_derlen--;
    rsp = d2i_OCSP_RESPONSE(NULL, &p, resp_derlen);
    if (!rsp) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_get_cached_response: response parse error??");
        return TRUE;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "stapling_get_cached_response: cache hit");

    *prsp = rsp;
    
    return TRUE;
}

static int stapling_set_response(SSL *ssl, OCSP_RESPONSE *rsp)
{
    int rspderlen;
    unsigned char *rspder = NULL;

    rspderlen = i2d_OCSP_RESPONSE(rsp, &rspder);
    if (rspderlen <= 0)
        return 0;
    SSL_set_tlsext_status_ocsp_resp(ssl, rspder, rspderlen);
    return 1;
}

static int stapling_check_response(server_rec *s, modssl_ctx_t *mctx,
                                   certinfo *cinf, OCSP_RESPONSE *rsp,
                                   BOOL *pok)
{
    int status, reason;
    OCSP_BASICRESP *bs = NULL;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
    int response_status = OCSP_response_status(rsp);

    if (pok)
        *pok = FALSE;
    /* Check to see if response is an error. If so we automatically accept
     * it because it would have expired from the cache if it was time to
     * retry.
     */
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        if (mctx->stapling_return_errors)
            return SSL_TLSEXT_ERR_OK;
        else 
            return SSL_TLSEXT_ERR_NOACK;
    }

    bs = OCSP_response_get1_basic(rsp);
    if (bs == NULL) {
        /* If we can't parse response just pass it to client */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_check_response: Error Parsing Response!");
        return SSL_TLSEXT_ERR_OK;
    }

    if (!OCSP_resp_find_status(bs, cinf->cid, &status, &reason, &rev,
                               &thisupd, &nextupd)) {
        /* If ID not present just pass back to client */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_check_response: certificate ID not present in response!");
    } else {
        if (OCSP_check_validity(thisupd, nextupd,
                                mctx->stapling_resptime_skew,
                                mctx->stapling_resp_maxage)) {
            if (pok)
                *pok = TRUE;
        } 
        else {
            /* If pok is not NULL response was direct from a responder and 
             * the times should be valide. If pok is NULL the response was
             * retrieved from cache and it is expected to subsequently expire
             */
            if (pok) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "stapling_check_response: response times invalid");
            } else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "stapling_check_response: cached response expired");
            }
 
            OCSP_BASICRESP_free(bs); 
            return SSL_TLSEXT_ERR_NOACK;
        }
    }
 
    OCSP_BASICRESP_free(bs); 

    return SSL_TLSEXT_ERR_OK;
}

static BOOL stapling_renew_response(server_rec *s, modssl_ctx_t *mctx, SSL *ssl,
                                    certinfo *cinf, OCSP_RESPONSE **prsp,
                                    apr_pool_t *pool)
{
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    apr_pool_t *vpool;
    OCSP_REQUEST *req = NULL;
    OCSP_CERTID *id = NULL;
    STACK_OF(X509_EXTENSION) *exts;
    int i;
    BOOL ok = FALSE;
    BOOL rv = TRUE;
    const char *ocspuri;
    apr_uri_t uri;

    *prsp = NULL;
    /* Build up OCSP query from server certificate info */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "stapling_renew_response: querying responder");

    req = OCSP_REQUEST_new();
    if (!req)
        goto err;
    id = OCSP_CERTID_dup(cinf->cid);
    if (!id)
        goto err;
    if (!OCSP_request_add0_id(req, id))
        goto err;
    id = NULL;
    /* Add any extensions to the request */
    SSL_get_tlsext_status_exts(ssl, &exts);
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        if (!OCSP_REQUEST_add_ext(req, ext, -1))
            goto err;
    }

    if (mctx->stapling_force_url)
        ocspuri = mctx->stapling_force_url;
    else
        ocspuri = cinf->uri;
    
    /* Create a temporary pool to constrain memory use */
    apr_pool_create(&vpool, conn->pool);

    ok = apr_uri_parse(vpool, ocspuri, &uri);
    if (ok != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_renew_response: Error parsing uri %s",
                      ocspuri);
	rv = FALSE;
	goto done;
    } else if (strcmp(uri.scheme, "http")) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_renew_response: Unsupported uri %s", ocspuri);
	rv = FALSE;
	goto done;
    }

    *prsp = modssl_dispatch_ocsp_request(&uri, mctx->stapling_responder_timeout,
                                         req, conn, vpool);
 
    apr_pool_destroy(vpool);

    if (!*prsp) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_renew_response: responder error");
        if (mctx->stapling_fake_trylater) { 
            *prsp = OCSP_response_create(OCSP_RESPONSE_STATUS_TRYLATER, NULL);
        } 
        else {
            goto done;
        }
    } else {
        int response_status = OCSP_response_status(*prsp);

        if (response_status == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                        "stapling_renew_response: query response received");
            stapling_check_response(s, mctx, cinf, *prsp, &ok);
            if (ok == FALSE) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "stapling_renew_response: error in retreived response!");
            }
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "stapling_renew_response: responder error %s",
                         OCSP_response_status_str(response_status));
        }
    }
    if (stapling_cache_response(s, mctx, *prsp, cinf, ok, pool) == FALSE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "stapling_renew_response: error caching response!");
    }

done:
    if (id)
        OCSP_CERTID_free(id);
    if (req)
        OCSP_REQUEST_free(req);
    return rv;
err:
    rv = FALSE;
    goto done;
}

/*
 * SSLStaplingMutex operations. Similar to SSL mutex except a mutex is
 * mandatory if stapling is enabled.
 */
int ssl_stapling_mutex_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    apr_status_t rv;

    if (mc->stapling_mutex || sc->server->stapling_enabled != TRUE) {
        return TRUE;
    }
    if (mc->stapling_mutex_mode == SSL_MUTEXMODE_NONE
        || mc->stapling_mutex_mode == SSL_MUTEXMODE_UNSET) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "An SSLStaplingMutex is required for OCSP Stapling");
        return FALSE;
    }

    if ((rv = apr_global_mutex_create(&mc->stapling_mutex,
                                      mc->stapling_mutex_file,
                                      mc->stapling_mutex_mech, s->process->pool))
            != APR_SUCCESS) {
        if (mc->stapling_mutex_file)
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot create SSLStaplingMutex with file `%s'",
                         mc->stapling_mutex_file);
        else
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot create SSLStaplingMutex");
        return FALSE;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(mc->stapling_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Could not set permissions on ssl_mutex; check User "
                     "and Group directives");
        return FALSE;
    }
#endif
    return TRUE;
}

int ssl_stapling_mutex_reinit(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if (mc->stapling_mutex == NULL) {
        return TRUE;
    }

    if ((rv = apr_global_mutex_child_init(&mc->stapling_mutex,
                                 mc->stapling_mutex_file, p)) != APR_SUCCESS) {
        if (mc->stapling_mutex_file) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot reinit SSLMutex with file `%s'",
                         mc->szMutexFile);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                         "Cannot reinit SSLMutex");
        }
        return FALSE;
    }
    return TRUE;
}

static int stapling_mutex_on(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if ((rv = apr_global_mutex_lock(mc->stapling_mutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                     "Failed to acquire OCSP stapling lock");
        return FALSE;
    }
    return TRUE;
}

static int stapling_mutex_off(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if ((rv = apr_global_mutex_unlock(mc->stapling_mutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                     "Failed to release OCSP stapling lock");
        return FALSE;
    }
    return TRUE;
}

/* Certificate Status callback. This is called when a client includes a
 * certificate status request extension.
 *
 * Check for cached responses in session cache. If valid send back to
 * client.  If absent or no longer valid query responder and update
 * cache. */
static int stapling_cb(SSL *ssl, void *arg)
{
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s       = conn->base_server;

    SSLSrvConfigRec *sc = mySrvConfig(s);
    SSLConnRec *sslconn = myConnConfig(conn);
    modssl_ctx_t *mctx  = myCtxConfig(sslconn, sc);
    certinfo *cinf = NULL;
    OCSP_RESPONSE *rsp = NULL;
    int rv;
    BOOL ok;

    if (sc->server->stapling_enabled != TRUE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "stapling_cb: OCSP Stapling disabled");
        return SSL_TLSEXT_ERR_NOACK;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "stapling_cb: OCSP Stapling callback called");

    cinf = stapling_get_cert_info(s, mctx, ssl);
    if (cinf == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "stapling_cb: retrieved cached certificate data");

    /* Check to see if we already have a response for this certificate */
    stapling_mutex_on(s);

    rv = stapling_get_cached_response(s, &rsp, &ok, cinf, conn->pool);
    if (rv == FALSE) {
        stapling_mutex_off(s);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rsp) {
        /* see if response is acceptable */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "stapling_cb: retrieved cached response");
        rv = stapling_check_response(s, mctx, cinf, rsp, NULL);
        if (rv == SSL_TLSEXT_ERR_ALERT_FATAL) {
            OCSP_RESPONSE_free(rsp);
            stapling_mutex_off(s);
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        } 
        else if (rv == SSL_TLSEXT_ERR_NOACK) {
            /* Error in response. If this error was not present when it was
             * stored (i.e. response no longer valid) then it can be
             * renewed straight away.
             *
             * If the error *was* present at the time it was stored then we
             * don't renew the response straight away we just wait for the
             * cached response to expire.
             */
            if (ok) {
                OCSP_RESPONSE_free(rsp);
                rsp = NULL;
            }
            else if (!mctx->stapling_return_errors) {
                OCSP_RESPONSE_free(rsp);
                stapling_mutex_off(s);
                return SSL_TLSEXT_ERR_NOACK;
            }
        }
    }

    if (rsp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "stapling_cb: renewing cached response");
        rv = stapling_renew_response(s, mctx, ssl, cinf, &rsp, conn->pool);

        if (rv == FALSE) {
            stapling_mutex_off(s);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "stapling_cb: fatal error");
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }
    stapling_mutex_off(s);

    if (rsp) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "stapling_cb: setting response");
        if (!stapling_set_response(ssl, rsp))
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        return SSL_TLSEXT_ERR_OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "stapling_cb: no response available");

    return SSL_TLSEXT_ERR_NOACK;

}

void modssl_init_stapling(server_rec *s, apr_pool_t *p, apr_pool_t *ptemp, 
                          modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->stapling_cache == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                 "SSLStapling: no stapling cache available");
        ssl_die();
    }
    /* Set some default values for parameters if they are not set */
    if (mctx->stapling_resptime_skew == UNSET) {
        mctx->stapling_resptime_skew = 60 * 5;
    }
    if (mctx->stapling_cache_timeout == UNSET) {
        mctx->stapling_cache_timeout = 3600;
    }
    if (mctx->stapling_return_errors == UNSET) {
        mctx->stapling_return_errors = TRUE;
    }
    if (mctx->stapling_fake_trylater == UNSET) {
        mctx->stapling_fake_trylater = TRUE;
    }
    if (mctx->stapling_errcache_timeout == UNSET) {
        mctx->stapling_errcache_timeout = 600;
    }
    if (mctx->stapling_responder_timeout == UNSET) {
        mctx->stapling_responder_timeout = 10 * APR_USEC_PER_SEC;
    }
    SSL_CTX_set_tlsext_status_cb(ctx, stapling_cb);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "OCSP stapling initialized");
}

#endif
