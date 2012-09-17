/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ssl_private.h"

#ifndef OPENSSL_NO_OCSP
#include "apr_base64.h"

/* Return the responder URI specified in the given certificate, or
 * NULL if none specified. */
static const char *extract_responder_uri(X509 *cert, apr_pool_t *pool)
{
    STACK_OF(ACCESS_DESCRIPTION) *values;
    char *result = NULL;
    int j;

    values = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (!values) {
        return NULL;
    }

    for (j = 0; j < sk_ACCESS_DESCRIPTION_num(values) && !result; j++) {
        ACCESS_DESCRIPTION *value = sk_ACCESS_DESCRIPTION_value(values, j);

        /* Name found in extension, and is a URI: */
        if (OBJ_obj2nid(value->method) == NID_ad_OCSP
            && value->location->type == GEN_URI) {
            result = apr_pstrdup(pool,
                                 (char *)value->location->d.uniformResourceIdentifier->data);
        }
    }

    AUTHORITY_INFO_ACCESS_free(values);

    return result;
}

/* Return the responder URI object which should be used in the given
 * configuration for the given certificate, or NULL if none can be
 * determined. */
static apr_uri_t *determine_responder_uri(SSLSrvConfigRec *sc, X509 *cert,
                                          conn_rec *c, apr_pool_t *p)
{
    apr_uri_t *u = apr_palloc(p, sizeof *u);
    const char *s;
    apr_status_t rv;

    /* Use default responder URL if forced by configuration, else use
     * certificate-specified responder, falling back to default if
     * necessary and possible. */
    if (sc->server->ocsp_force_default) {
        s = sc->server->ocsp_responder;
    }
    else {
        s = extract_responder_uri(cert, p);

        if (s == NULL && sc->server->ocsp_responder) {
            s = sc->server->ocsp_responder;
        }
    }

    if (s == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(01918)
                      "no OCSP responder specified in certificate and "
                      "no default configured");
        return NULL;
    }

    rv = apr_uri_parse(p, s, u);
    if (rv || !u->hostname) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO(01919)
                      "failed to parse OCSP responder URI '%s'", s);
        return NULL;
    }

    if (strcasecmp(u->scheme, "http") != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO(01920)
                      "cannot handle OCSP responder URI '%s'", s);
        return NULL;
    }

    if (!u->port) {
        u->port = apr_uri_port_of_scheme(u->scheme);
    }

    return u;
}

/* Create an OCSP request for the given certificate; returning the
 * certificate ID in *certid and *issuer on success.  Returns the
 * request object on success, or NULL on error. */
static OCSP_REQUEST *create_request(X509_STORE_CTX *ctx, X509 *cert,
                                    OCSP_CERTID **certid,
                                    server_rec *s, apr_pool_t *p)
{
    OCSP_REQUEST *req = OCSP_REQUEST_new();

    *certid = OCSP_cert_to_id(NULL, cert, ctx->current_issuer);
    if (!*certid || !OCSP_request_add0_id(req, *certid)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01921)
                     "could not retrieve certificate id");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
        return NULL;
    }

    OCSP_request_add1_nonce(req, 0, -1);

    return req;
}

/* Verify the OCSP status of given certificate.  Returns
 * V_OCSP_CERTSTATUS_* result code. */
static int verify_ocsp_status(X509 *cert, X509_STORE_CTX *ctx, conn_rec *c,
                              SSLSrvConfigRec *sc, server_rec *s,
                              apr_pool_t *pool)
{
    int rc = V_OCSP_CERTSTATUS_GOOD;
    OCSP_RESPONSE *response = NULL;
    OCSP_BASICRESP *basicResponse = NULL;
    OCSP_REQUEST *request = NULL;
    OCSP_CERTID *certID = NULL;
    apr_uri_t *ruri;

    ruri = determine_responder_uri(sc, cert, c, pool);
    if (!ruri) {
        return V_OCSP_CERTSTATUS_UNKNOWN;
    }

    request = create_request(ctx, cert, &certID, s, pool);
    if (request) {
        apr_interval_time_t to = sc->server->ocsp_responder_timeout == UNSET ?
                                 apr_time_from_sec(DEFAULT_OCSP_TIMEOUT) :
                                 sc->server->ocsp_responder_timeout;
        response = modssl_dispatch_ocsp_request(ruri, to, request, c, pool);
    }

    if (!request || !response) {
        rc = V_OCSP_CERTSTATUS_UNKNOWN;
    }

    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        int r = OCSP_response_status(response);

        if (r != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01922)
                         "OCSP response not successful: %d", rc);
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }

    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        basicResponse = OCSP_response_get1_basic(response);
        if (!basicResponse) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(01923)
                          "could not retrieve OCSP basic response");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }

    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        if (OCSP_check_nonce(request, basicResponse) != 1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01924)
                        "Bad OCSP responder answer (bad nonce)");
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }

    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        /* TODO: allow flags configuration. */
        if (OCSP_basic_verify(basicResponse, NULL, ctx->ctx, 0) != 1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(01925)
                        "failed to verify the OCSP response");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }

    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        int reason = -1, status;
        ASN1_GENERALIZEDTIME *thisup = NULL, *nextup = NULL;

        rc = OCSP_resp_find_status(basicResponse, certID, &status,
                                   &reason, NULL, &thisup, &nextup);
        if (rc != 1) {
            ssl_log_cxerror(SSLLOG_MARK, APLOG_ERR, 0, c, cert, APLOGNO(02272)
                            "failed to retrieve OCSP response status");
            ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
        else {
            rc = status;
        }

        /* Check whether the response is inside the defined validity
         * period; otherwise fail.  */
        if (rc != V_OCSP_CERTSTATUS_UNKNOWN) {
            long resptime_skew = sc->server->ocsp_resptime_skew == UNSET ?
                                 DEFAULT_OCSP_MAX_SKEW : sc->server->ocsp_resptime_skew;
            /* oscp_resp_maxage can be passed verbatim - UNSET (-1) means
             * that responses can be of any age as long as nextup is in the
             * future. */
            int vrc  = OCSP_check_validity(thisup, nextup, resptime_skew,
                                           sc->server->ocsp_resp_maxage);
            if (vrc != 1) {
                ssl_log_cxerror(SSLLOG_MARK, APLOG_ERR, 0, c, cert, APLOGNO(02273)
                                "OCSP response outside validity period");
                ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, s);
                rc = V_OCSP_CERTSTATUS_UNKNOWN;
            }
        }

        {
            int level =
                (status == V_OCSP_CERTSTATUS_GOOD) ? APLOG_INFO : APLOG_ERR;
            const char *result =
                status == V_OCSP_CERTSTATUS_GOOD ? "good" :
                (status == V_OCSP_CERTSTATUS_REVOKED ? "revoked" : "unknown");

            ssl_log_cxerror(SSLLOG_MARK, level, 0, c, cert,
                            "OCSP validation completed, "
                            "certificate status: %s (%d, %d)",
                            result, status, reason);
        }
    }

    if (request) OCSP_REQUEST_free(request);
    if (response) OCSP_RESPONSE_free(response);
    if (basicResponse) OCSP_BASICRESP_free(basicResponse);
    /* certID is freed when the request is freed */

    return rc;
}

int modssl_verify_ocsp(X509_STORE_CTX *ctx, SSLSrvConfigRec *sc,
                       server_rec *s, conn_rec *c, apr_pool_t *pool)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    apr_pool_t *vpool;
    int rv;

    if (!cert) {
        /* starting with OpenSSL 1.0, X509_STORE_CTX_get_current_cert()
         * may yield NULL. Return early, but leave the ctx error as is. */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "No cert available to check with OCSP");
        return 1;
    }
    else if (cert->valid && X509_check_issued(cert,cert) == X509_V_OK) {
        /* don't do OCSP checking for valid self-issued certs */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "Skipping OCSP check for valid self-issued cert");
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        return 1;
    }

    /* Create a temporary pool to constrain memory use (the passed-in
     * pool may be e.g. a connection pool). */
    apr_pool_create(&vpool, pool);

    rv = verify_ocsp_status(cert, ctx, c, sc, s, vpool);

    apr_pool_destroy(vpool);

    /* Propagate the verification status back to the passed-in
     * context. */
    switch (rv) {
    case V_OCSP_CERTSTATUS_GOOD:
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        break;

    case V_OCSP_CERTSTATUS_REVOKED:
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
        break;

    case V_OCSP_CERTSTATUS_UNKNOWN:
        /* correct error code for application errors? */
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        break;
    }

    return rv == V_OCSP_CERTSTATUS_GOOD;
}
#endif /* HAVE_OCSP */
