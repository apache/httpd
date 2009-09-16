/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ssl_private.h"

#ifdef HAVE_OCSP
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
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      "no OCSP responder specified in certificate and "
                      "no default configured");
        return NULL;
    }

    rv = apr_uri_parse(p, s, u);
    if (rv || !u->hostname) {    
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, 
                      "failed to parse OCSP responder URI '%s'", s);
        return NULL;
    }

    if (strcasecmp(u->scheme, "http") != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, 
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
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "could not retrieve certificate id");
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
        response = modssl_dispatch_ocsp_request(ruri, 
                                                mySrvFromConn(c)->timeout,
                                                request, c, pool);
    }

    if (!request || !response) {
        rc = V_OCSP_CERTSTATUS_UNKNOWN;
    }
    
    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        int r = OCSP_response_status(response);

        if (r != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "OCSP response not successful: %d", rc);
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }
    
    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        basicResponse = OCSP_response_get1_basic(response);
        if (!basicResponse) {
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                          "could not retrieve OCSP basic response");
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }
    
    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        if (OCSP_check_nonce(request, basicResponse) != 1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                        "Bad OCSP responder answer (bad nonce)");
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }
    
    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        /* TODO: allow flags configuration. */
        if (OCSP_basic_verify(basicResponse, NULL, ctx->ctx, 0) != 1) {
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                        "failed to verify the OCSP response");
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
    }
    
    if (rc == V_OCSP_CERTSTATUS_GOOD) {
        int reason = -1, status;
        ASN1_GENERALIZEDTIME *thisup = NULL, *nextup = NULL;

        rc = OCSP_resp_find_status(basicResponse, certID, &status,
                                   &reason, NULL, &thisup, &nextup);
        if (rc != 1) {
            ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
            ssl_log_cxerror(APLOG_MARK, APLOG_ERR, 0, c, cert,
                            "failed to retrieve OCSP response status");
            rc = V_OCSP_CERTSTATUS_UNKNOWN;
        }
        else {
            rc = status;
        }

        /* TODO: make these configurable. */
#define MAX_SKEW (60)
#define MAX_AGE (360)

        /* Check whether the response is inside the defined validity
         * period; otherwise fail.  */
        if (rc != V_OCSP_CERTSTATUS_UNKNOWN) {
            int vrc  = OCSP_check_validity(thisup, nextup, MAX_SKEW, MAX_AGE);
            
            if (vrc != 1) {
                ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, s);
                ssl_log_cxerror(APLOG_MARK, APLOG_ERR, 0, c, cert,
                                "OCSP response outside validity period");
                rc = V_OCSP_CERTSTATUS_UNKNOWN;
            }
        }

        {
            int level = 
                (status == V_OCSP_CERTSTATUS_GOOD) ? APLOG_INFO : APLOG_ERR;
            const char *result = 
                status == V_OCSP_CERTSTATUS_GOOD ? "good" : 
                (status == V_OCSP_CERTSTATUS_REVOKED ? "revoked" : "unknown");

            ssl_log_cxerror(APLOG_MARK, level, 0, c, cert,
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
