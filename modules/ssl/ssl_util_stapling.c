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

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, init_stapling_status,
                                    (server_rec *s, apr_pool_t *p, 
                                     X509 *cert, X509 *issuer),
                                     (s, p, cert, issuer),
                                    DECLINED, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, get_stapling_status,
                                    (unsigned char **pder, int *pderlen, 
                                     conn_rec *c, server_rec *s, X509 *cert),
                                     (pder, pderlen, c, s, cert), 
                                    DECLINED, DECLINED)
                         

#ifdef HAVE_OCSP_STAPLING

static int stapling_cache_mutex_on(server_rec *s);
static int stapling_cache_mutex_off(server_rec *s);

static int stapling_cb(SSL *ssl, void *arg);

/**
 * Maximum OCSP stapling response size. This should be the response for a
 * single certificate and will typically include the responder certificate chain
 * so 10K should be more than enough.
 *
 */

#define MAX_STAPLING_DER 10240

/* Cached info stored in the global stapling_certinfo hash. */
typedef struct {
    /* Index in session cache (SHA-1 digest of DER encoded certificate) */
    UCHAR idx[SHA_DIGEST_LENGTH];
    /* Certificate ID for OCSP request */
    OCSP_CERTID *cid;
    /* URI of the OCSP responder */
    char *uri;
} certinfo;

static apr_status_t ssl_stapling_certid_free(void *data)
{
    OCSP_CERTID *cid = data;

    if (cid) {
        OCSP_CERTID_free(cid);
    }

    return APR_SUCCESS;
}

static apr_hash_t *stapling_certinfo;

void ssl_stapling_certinfo_hash_init(apr_pool_t *p)
{
    stapling_certinfo = apr_hash_make(p);
}

static X509 *stapling_get_issuer(modssl_ctx_t *mctx, X509 *x)
{
    X509 *issuer = NULL;
    int i;
    X509_STORE *st = SSL_CTX_get_cert_store(mctx->ssl_ctx);
    X509_STORE_CTX *inctx;
    STACK_OF(X509) *extra_certs = NULL;

#ifdef OPENSSL_NO_SSL_INTERN
    SSL_CTX_get_extra_chain_certs(mctx->ssl_ctx, &extra_certs);
#else
    extra_certs = mctx->ssl_ctx->extra_certs;
#endif

    for (i = 0; i < sk_X509_num(extra_certs); i++) {
        issuer = sk_X509_value(extra_certs, i);
        if (X509_check_issued(issuer, x) == X509_V_OK) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
#else
            X509_up_ref(issuer);
#endif
            return issuer;
        }
    }

    inctx = X509_STORE_CTX_new();
    if (!X509_STORE_CTX_init(inctx, st, NULL, NULL)) {
        X509_STORE_CTX_free(inctx);
        return 0;
    }
    if (X509_STORE_CTX_get1_issuer(&issuer, inctx, x) <= 0)
        issuer = NULL;
    X509_STORE_CTX_cleanup(inctx);
    X509_STORE_CTX_free(inctx);
    return issuer;
}

int ssl_stapling_init_cert(server_rec *s, apr_pool_t *p, apr_pool_t *ptemp,
                           modssl_ctx_t *mctx, X509 *x)
{
    UCHAR idx[SHA_DIGEST_LENGTH];
    certinfo *cinf = NULL;
    X509 *issuer = NULL;
    OCSP_CERTID *cid = NULL;
    STACK_OF(OPENSSL_STRING) *aia = NULL;
    const char *pem = NULL;
    int rv = 1; /* until further notice */

    if (x == NULL)
        return 0;

    if (!(issuer = stapling_get_issuer(mctx, x))) {
        /* In Apache pre 2.4.40, we use to come here only when mod_ssl stapling
         * was enabled. With the new hooks, we give other modules the chance
         * to provide stapling status. However, we do not want to log ssl errors
         * where we did not do so in the past. */
        if (mctx->stapling_enabled == TRUE) {
            ssl_log_xerror(SSLLOG_MARK, APLOG_ERR, 0, ptemp, s, x, APLOGNO(02217)
                           "ssl_stapling_init_cert: can't retrieve issuer "
                           "certificate!");
            return 0;
        }
        return 1;
    }

    if (X509_digest(x, EVP_sha1(), idx, NULL) != 1) {
        rv = 0;
        goto cleanup;
    }

    if (modssl_cert_get_pem(ptemp, x, issuer, &pem) != APR_SUCCESS) {
        rv = 0;
        goto cleanup;
    }

    if (ap_ssl_ocsp_prime(s, p, (const char*)idx, sizeof(idx), pem) == APR_SUCCESS
        || ssl_run_init_stapling_status(s, p, x, issuer) == OK) {
        /* Someone's taken over or mod_ssl's own implementation is not enabled */
        if (mctx->stapling_enabled != TRUE) {
            SSL_CTX_set_tlsext_status_cb(mctx->ssl_ctx, stapling_cb);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10177) "OCSP stapling added via hook");
        }
        goto cleanup;
    }
    
    if (mctx->stapling_enabled != TRUE) {
        /* mod_ssl's own implementation is not enabled */
        goto cleanup;
    }
    
    cinf = apr_hash_get(stapling_certinfo, idx, sizeof(idx));
    if (cinf) {
        /* 
         * We already parsed the certificate, and no OCSP URI was found.
         * The certificate might be used for multiple vhosts, though,
         * so we check for a ForceURL for this vhost.
         */
        if (!cinf->uri && !mctx->stapling_force_url) {
            ssl_log_xerror(SSLLOG_MARK, APLOG_ERR, 0, ptemp, s, x,
                           APLOGNO(02814) "ssl_stapling_init_cert: no OCSP URI "
                           "in certificate and no SSLStaplingForceURL "
                           "configured for server %s", mctx->sc->vhost_id);
            rv = 0;
        }
        goto cleanup;
    }

    cid = OCSP_cert_to_id(NULL, x, issuer);
    if (!cid) {
        ssl_log_xerror(SSLLOG_MARK, APLOG_ERR, 0, ptemp, s, x, APLOGNO(02815)
                       "ssl_stapling_init_cert: can't create CertID "
                       "for OCSP request");
        rv = 0;
        goto cleanup;
    }

    aia = X509_get1_ocsp(x);
    if (!aia && !mctx->stapling_force_url) {
        OCSP_CERTID_free(cid);
        ssl_log_xerror(SSLLOG_MARK, APLOG_ERR, 0, ptemp, s, x,
                       APLOGNO(02218) "ssl_stapling_init_cert: no OCSP URI "
                       "in certificate and no SSLStaplingForceURL set");
        rv = 0;
        goto cleanup;
    }

    /* At this point, we have determined that there's something to store */
    cinf = apr_pcalloc(p, sizeof(certinfo));
    memcpy (cinf->idx, idx, sizeof(idx));
    cinf->cid = cid;
    /* make sure cid is also freed at pool cleanup */
    apr_pool_cleanup_register(p, cid, ssl_stapling_certid_free,
                              apr_pool_cleanup_null);
    if (aia) {
       /* allocate uri from the pconf pool */
       cinf->uri = apr_pstrdup(p, sk_OPENSSL_STRING_value(aia, 0));
       X509_email_free(aia);
    }

    ssl_log_xerror(SSLLOG_MARK, APLOG_TRACE1, 0, ptemp, s, x,
                   "ssl_stapling_init_cert: storing certinfo for server %s",
                   mctx->sc->vhost_id);

    apr_hash_set(stapling_certinfo, cinf->idx, sizeof(cinf->idx), cinf);

cleanup:
    X509_free(issuer);
    return rv;
}

static certinfo *stapling_get_certinfo(server_rec *s, UCHAR *idx, apr_size_t idx_len,
                                       modssl_ctx_t *mctx, SSL *ssl)
{
    certinfo *cinf;
    cinf = apr_hash_get(stapling_certinfo, idx, idx_len);
    if (cinf && cinf->cid)
        return cinf;
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(01926)
                 "stapling_get_certinfo: stapling not supported for certificate");
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
    unsigned char resp_der[MAX_STAPLING_DER]; /* includes one-byte flag + response */
    unsigned char *p;
    int resp_derlen, stored_len;
    BOOL rv;
    apr_time_t expiry;

    resp_derlen = i2d_OCSP_RESPONSE(rsp, NULL);

    if (resp_derlen <= 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01927)
                     "OCSP stapling response encode error??");
        return FALSE;
    }

    stored_len = resp_derlen + 1; /* response + ok flag */
    if (stored_len > sizeof resp_der) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01928)
                     "OCSP stapling response too big (%u bytes)", resp_derlen);
        return FALSE;
    }

    p = resp_der;

    /* TODO: potential optimization; _timeout members as apr_interval_time_t */
    if (ok == TRUE) {
        *p++ = 1;
        expiry = apr_time_from_sec(mctx->stapling_cache_timeout);
    }
    else {
        *p++ = 0;
        expiry = apr_time_from_sec(mctx->stapling_errcache_timeout);
    }

    expiry += apr_time_now();

    i2d_OCSP_RESPONSE(rsp, &p);

    if (mc->stapling_cache->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        stapling_cache_mutex_on(s);
    rv = mc->stapling_cache->store(mc->stapling_cache_context, s,
                                   cinf->idx, sizeof(cinf->idx),
                                   expiry, resp_der, stored_len, pool);
    if (mc->stapling_cache->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        stapling_cache_mutex_off(s);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01929)
                     "stapling_cache_response: OCSP response session store error!");
        return FALSE;
    }

    return TRUE;
}

static void stapling_get_cached_response(server_rec *s, OCSP_RESPONSE **prsp,
                                         BOOL *pok, certinfo *cinf,
                                         apr_pool_t *pool)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;
    OCSP_RESPONSE *rsp;
    unsigned char resp_der[MAX_STAPLING_DER];
    const unsigned char *p;
    unsigned int resp_derlen = MAX_STAPLING_DER;

    if (mc->stapling_cache->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        stapling_cache_mutex_on(s);
    rv = mc->stapling_cache->retrieve(mc->stapling_cache_context, s,
                                      cinf->idx, sizeof(cinf->idx),
                                      resp_der, &resp_derlen, pool);
    if (mc->stapling_cache->flags & AP_SOCACHE_FLAG_NOTMPSAFE)
        stapling_cache_mutex_off(s);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01930)
                     "stapling_get_cached_response: cache miss");
        return;
    }
    if (resp_derlen <= 1) {
        /* should-not-occur; must have at least valid-when-stored flag +
         * OCSPResponseStatus
         */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01931)
                     "stapling_get_cached_response: response length invalid??");
        return;
    }
    p = resp_der;
    if (*p) /* valid when stored */
        *pok = TRUE;
    else
        *pok = FALSE;
    p++;
    resp_derlen--;
    rsp = d2i_OCSP_RESPONSE(NULL, &p, resp_derlen);
    if (!rsp) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01932)
                     "stapling_get_cached_response: response parse error??");
        return;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01933)
                 "stapling_get_cached_response: cache hit");

    *prsp = rsp;
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
    int status = V_OCSP_CERTSTATUS_UNKNOWN;
    int reason = OCSP_REVOKED_STATUS_NOSTATUS;
    OCSP_BASICRESP *bs = NULL;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
    int response_status = OCSP_response_status(rsp);
    int rv = SSL_TLSEXT_ERR_OK;

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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01934)
                     "stapling_check_response: Error Parsing Response!");
        return SSL_TLSEXT_ERR_OK;
    }

    if (!OCSP_resp_find_status(bs, cinf->cid, &status, &reason, &rev,
                               &thisupd, &nextupd)) {
        /* If ID not present pass back to client (if configured so) */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01935)
                     "stapling_check_response: certificate ID not present in response!");
        if (mctx->stapling_return_errors == FALSE)
            rv = SSL_TLSEXT_ERR_NOACK;
    }
    else {
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
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01936)
                             "stapling_check_response: response times invalid");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01937)
                             "stapling_check_response: cached response expired");
            }

            rv = SSL_TLSEXT_ERR_NOACK;
        }

        if (status != V_OCSP_CERTSTATUS_GOOD && pok) {
            char snum[MAX_STRING_LEN] = { '\0' };
            BIO *bio = BIO_new(BIO_s_mem());

            if (bio) {
                int n;
                ASN1_INTEGER *pserial;
                OCSP_id_get0_info(NULL, NULL, NULL, &pserial, cinf->cid);
                if ((i2a_ASN1_INTEGER(bio, pserial) != -1) &&
                    ((n = BIO_read(bio, snum, sizeof snum - 1)) > 0))
                    snum[n] = '\0';
                BIO_free(bio);
            }

            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02969)
                         "stapling_check_response: response has certificate "
                         "status %s (reason: %s) for serial number %s",
                         OCSP_cert_status_str(status),
                         (reason != OCSP_REVOKED_STATUS_NOSTATUS) ?
                         OCSP_crl_reason_str(reason) : "n/a",
                         snum[0] ? snum : "[n/a]");
        }
    }

    OCSP_BASICRESP_free(bs);

    return rv;
}

static BOOL stapling_renew_response(server_rec *s, modssl_ctx_t *mctx, SSL *ssl,
                                    certinfo *cinf, OCSP_RESPONSE **prsp,
                                    BOOL *pok, apr_pool_t *pool)
{
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    apr_pool_t *vpool;
    OCSP_REQUEST *req = NULL;
    OCSP_CERTID *id = NULL;
    STACK_OF(X509_EXTENSION) *exts;
    int i;
    BOOL rv = TRUE;
    const char *ocspuri;
    apr_uri_t uri;

    *prsp = NULL;
    /* Build up OCSP query from server certificate info */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01938)
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

    if (!ocspuri) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(02621)
                     "stapling_renew_response: no uri for responder");
        rv = FALSE;
        goto done;
    }

    /* Create a temporary pool to constrain memory use */
    apr_pool_create(&vpool, conn->pool);
    apr_pool_tag(vpool, "modssl_stapling_renew");

    if (apr_uri_parse(vpool, ocspuri, &uri) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01939)
                     "stapling_renew_response: Error parsing uri %s",
                      ocspuri);
        rv = FALSE;
        goto done;
    }
    else if (strcmp(uri.scheme, "http")) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01940)
                     "stapling_renew_response: Unsupported uri %s", ocspuri);
        rv = FALSE;
        goto done;
    }

    if (!uri.port) {
        uri.port = apr_uri_port_of_scheme(uri.scheme);
    }

    *prsp = modssl_dispatch_ocsp_request(&uri, mctx->stapling_responder_timeout,
                                         req, conn, vpool);

    apr_pool_destroy(vpool);

    if (!*prsp) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01941)
                     "stapling_renew_response: responder error");
        if (mctx->stapling_fake_trylater) {
            *prsp = OCSP_response_create(OCSP_RESPONSE_STATUS_TRYLATER, NULL);
        }
        else {
            goto done;
        }
    }
    else {
        int response_status = OCSP_response_status(*prsp);

        if (response_status == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01942)
                        "stapling_renew_response: query response received");
            stapling_check_response(s, mctx, cinf, *prsp, pok);
            if (*pok == FALSE) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01943)
                             "stapling_renew_response: error in retrieved response!");
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01944)
                         "stapling_renew_response: responder error %s",
                         OCSP_response_status_str(response_status));
            *pok = FALSE;
        }
    }
    if (stapling_cache_response(s, mctx, *prsp, cinf, *pok, pool) == FALSE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01945)
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
 * SSL stapling mutex operations. Similar to SSL mutex except mutexes are
 * mandatory if stapling is enabled.
 */
static int ssl_stapling_mutex_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    apr_status_t rv;

    /* already init or stapling not enabled? */
    if (mc->stapling_refresh_mutex || sc->server->stapling_enabled != TRUE) {
        return TRUE;
    }

    /* need a cache mutex? */
    if (mc->stapling_cache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) {
        if ((rv = ap_global_mutex_create(&mc->stapling_cache_mutex, NULL,
                                         SSL_STAPLING_CACHE_MUTEX_TYPE, NULL, s,
                                         s->process->pool, 0)) != APR_SUCCESS) {
            return FALSE;
        }
    }

    /* always need stapling_refresh_mutex */
    if ((rv = ap_global_mutex_create(&mc->stapling_refresh_mutex, NULL,
                                     SSL_STAPLING_REFRESH_MUTEX_TYPE, NULL, s,
                                     s->process->pool, 0)) != APR_SUCCESS) {
        return FALSE;
    }

    return TRUE;
}

static int stapling_mutex_reinit_helper(server_rec *s, apr_pool_t *p, 
                                        apr_global_mutex_t **mutex,
                                        const char *type)
{
    apr_status_t rv;
    const char *lockfile;

    lockfile = apr_global_mutex_lockfile(*mutex);
    if ((rv = apr_global_mutex_child_init(mutex,
                                          lockfile, p)) != APR_SUCCESS) {
        if (lockfile) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(01946)
                         "Cannot reinit %s mutex with file `%s'",
                         type, lockfile);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s, APLOGNO(01947)
                         "Cannot reinit %s mutex", type);
        }
        return FALSE;
    }
    return TRUE;
}

int ssl_stapling_mutex_reinit(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->stapling_cache_mutex != NULL
        && stapling_mutex_reinit_helper(s, p, &mc->stapling_cache_mutex,
                                        SSL_STAPLING_CACHE_MUTEX_TYPE) == FALSE) {
        return FALSE;
    }

    if (mc->stapling_refresh_mutex != NULL
        && stapling_mutex_reinit_helper(s, p, &mc->stapling_refresh_mutex,
                                        SSL_STAPLING_REFRESH_MUTEX_TYPE) == FALSE) {
        return FALSE;
    }

    return TRUE;
}

static int stapling_mutex_on(server_rec *s, apr_global_mutex_t *mutex,
                             const char *name)
{
    apr_status_t rv;

    if ((rv = apr_global_mutex_lock(mutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s, APLOGNO(01948)
                     "Failed to acquire OCSP %s lock", name);
        return FALSE;
    }
    return TRUE;
}

static int stapling_mutex_off(server_rec *s, apr_global_mutex_t *mutex,
                              const char *name)
{
    apr_status_t rv;

    if ((rv = apr_global_mutex_unlock(mutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s, APLOGNO(01949)
                     "Failed to release OCSP %s lock", name);
        return FALSE;
    }
    return TRUE;
}

static int stapling_cache_mutex_on(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    return stapling_mutex_on(s, mc->stapling_cache_mutex,
                             SSL_STAPLING_CACHE_MUTEX_TYPE);
}

static int stapling_cache_mutex_off(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    return stapling_mutex_off(s, mc->stapling_cache_mutex,
                              SSL_STAPLING_CACHE_MUTEX_TYPE);
}

static int stapling_refresh_mutex_on(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    return stapling_mutex_on(s, mc->stapling_refresh_mutex,
                             SSL_STAPLING_REFRESH_MUTEX_TYPE);
}

static int stapling_refresh_mutex_off(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    return stapling_mutex_off(s, mc->stapling_refresh_mutex,
                              SSL_STAPLING_REFRESH_MUTEX_TYPE);
}

static int get_and_check_cached_response(server_rec *s, modssl_ctx_t *mctx,
                                         OCSP_RESPONSE **rsp, BOOL *pok,
                                         certinfo *cinf, apr_pool_t *p)
{
    BOOL ok = FALSE;
    int rv;

    AP_DEBUG_ASSERT(*rsp == NULL);

    /* Check to see if we already have a response for this certificate */
    stapling_get_cached_response(s, rsp, &ok, cinf, p);

    if (*rsp) {
        /* see if response is acceptable */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01953)
                     "stapling_cb: retrieved cached response");
        rv = stapling_check_response(s, mctx, cinf, *rsp, NULL);
        if (rv == SSL_TLSEXT_ERR_ALERT_FATAL) {
            OCSP_RESPONSE_free(*rsp);
            *rsp = NULL;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        else if (rv == SSL_TLSEXT_ERR_NOACK) {
            /* Error in response. If this error was not present when it was
             * stored (i.e. response no longer valid) then it can be
             * renewed straight away.
             *
             * If the error *was* present at the time it was stored then we
             * don't renew the response straight away; we just wait for the
             * cached response to expire.
             */
            if (ok) {
                OCSP_RESPONSE_free(*rsp);
                *rsp = NULL;
            }
            else if (!mctx->stapling_return_errors) {
                OCSP_RESPONSE_free(*rsp);
                *rsp = NULL;
                *pok = FALSE;
                return SSL_TLSEXT_ERR_NOACK;
            }
        }
    }
    return 0;
}

typedef struct {
    unsigned char *data;
    apr_size_t len;
} ocsp_resp;

static void copy_ocsp_resp(const unsigned char *der, apr_size_t der_len, void *userdata)
{
    ocsp_resp *resp = userdata;

    resp->len = 0;
    resp->data = der? OPENSSL_malloc(der_len) : NULL;
    if (resp->data) {
        memcpy(resp->data, der, der_len);
        resp->len = der_len;
    }
}

/* Certificate Status callback. This is called when a client includes a
 * certificate status request extension.
 *
 * Check for cached responses in session cache. If valid send back to
 * client.  If absent or no longer valid, query responder and update
 * cache.
 */
static int stapling_cb(SSL *ssl, void *arg)
{
    conn_rec *conn      = (conn_rec *)SSL_get_app_data(ssl);
    server_rec *s       = mySrvFromConn(conn);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    modssl_ctx_t *mctx  = myConnCtxConfig(conn, sc);
    UCHAR idx[SHA_DIGEST_LENGTH];
    ocsp_resp resp;
    certinfo *cinf = NULL;
    OCSP_RESPONSE *rsp = NULL;
    int rv;
    BOOL ok = TRUE;
    X509 *x;
    int rspderlen, provided = 0;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01951)
                 "stapling_cb: OCSP Stapling callback called");

    x = SSL_get_certificate(ssl);
    if (x == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (X509_digest(x, EVP_sha1(), idx, NULL) != 1) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (ap_ssl_ocsp_get_resp(s, conn, (const char*)idx, sizeof(idx),
                             copy_ocsp_resp, &resp) == APR_SUCCESS) {
        provided = 1;
    }
    else if (ssl_run_get_stapling_status(&resp.data, &rspderlen, conn, s, x) == APR_SUCCESS) {
        resp.len = (apr_size_t)rspderlen;
        provided = 1;
    }

    if (provided) {
        /* a hook handles stapling for this certificate and determines the response */
        if (resp.data == NULL || resp.len == 0) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        SSL_set_tlsext_status_ocsp_resp(ssl, resp.data, (int)resp.len);
        return SSL_TLSEXT_ERR_OK;
    }
    
    if (sc->server->stapling_enabled != TRUE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01950)
                     "stapling_cb: OCSP Stapling disabled");
        return SSL_TLSEXT_ERR_NOACK;
    }

    if ((cinf = stapling_get_certinfo(s, idx, sizeof(idx), mctx, ssl)) == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01952)
                 "stapling_cb: retrieved cached certificate data");

    rv = get_and_check_cached_response(s, mctx, &rsp, &ok, cinf, conn->pool);
    if (rv != 0) {
        return rv;
    }

    if (rsp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01954)
                     "stapling_cb: renewing cached response");
        stapling_refresh_mutex_on(s);
        /* Maybe another request refreshed the OCSP response while this
         * thread waited for the mutex.  Check again.
         */
        rv = get_and_check_cached_response(s, mctx, &rsp, &ok, cinf,
                                           conn->pool);
        if (rv != 0) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03236)
                         "stapling_cb: error checking for cached response "
                         "after obtaining refresh mutex");
            stapling_refresh_mutex_off(s);
            return rv;
        }
        else if (rsp) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03237)
                         "stapling_cb: don't need to refresh cached response "
                         "after obtaining refresh mutex");
            stapling_refresh_mutex_off(s);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03238)
                         "stapling_cb: still must refresh cached response "
                         "after obtaining refresh mutex");
            rv = stapling_renew_response(s, mctx, ssl, cinf, &rsp, &ok,
                                         conn->pool);
            stapling_refresh_mutex_off(s);

            if (rv == TRUE) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03040)
                             "stapling_cb: success renewing response");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01955)
                             "stapling_cb: fatal error renewing response");
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            }
        }
    }

    if (rsp && ((ok == TRUE) || (mctx->stapling_return_errors == TRUE))) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01956)
                     "stapling_cb: setting response");
        if (!stapling_set_response(ssl, rsp)) {
            rv = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        else {
            rv = SSL_TLSEXT_ERR_OK;
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01957)
                     "stapling_cb: no suitable response available");
        rv = SSL_TLSEXT_ERR_NOACK;
    }
    OCSP_RESPONSE_free(rsp); /* NULL safe */

    return rv;
}

apr_status_t modssl_init_stapling(server_rec *s, apr_pool_t *p,
                                  apr_pool_t *ptemp, modssl_ctx_t *mctx)
{
    SSL_CTX *ctx = mctx->ssl_ctx;
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->stapling_cache == NULL) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01958)
                     "SSLStapling: no stapling cache available");
        return ssl_die(s);
    }
    if (ssl_stapling_mutex_init(s, ptemp) == FALSE) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01959)
                     "SSLStapling: cannot initialise stapling mutex");
        return ssl_die(s);
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
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01960) "OCSP stapling initialized");
    
    return APR_SUCCESS;
}

#endif
