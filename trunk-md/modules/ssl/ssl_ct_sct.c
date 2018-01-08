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


#include "ssl_ct_sct.h"
#include "ssl_ct_util.h"

#include "http_log.h"

APLOG_USE_MODULE(ssl_ct);

static apr_status_t verify_signature(sct_fields_t *sctf,
                                     EVP_PKEY *pkey)
{
    EVP_MD_CTX *ctx;
    int rc;

    if (sctf->signed_data == NULL) {
        return APR_EINVAL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    ctx = EVP_MD_CTX_create();
#else
    ctx = EVP_MD_CTX_new();
#endif
    ap_assert(1 == EVP_VerifyInit(ctx, EVP_sha256()));
    ap_assert(1 == EVP_VerifyUpdate(ctx, sctf->signed_data,
                                    sctf->signed_data_len));
    rc = EVP_VerifyFinal(ctx, sctf->sig, sctf->siglen, pkey);
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    EVP_MD_CTX_destroy(ctx);
#else
    EVP_MD_CTX_free(ctx);
#endif

    return rc == 1 ? APR_SUCCESS : APR_EINVAL;
}

apr_status_t sct_verify_signature(conn_rec *c, sct_fields_t *sctf,
                                  apr_array_header_t *log_config)
{
    apr_status_t rv = APR_EINVAL;
    int i;
    ct_log_config **config_elts;
    int nelts = log_config->nelts;

    ap_assert(sctf->signed_data != NULL);

    config_elts = (ct_log_config **)log_config->elts;

    for (i = 0; i < nelts; i++) {
        EVP_PKEY *pubkey = config_elts[i]->public_key;
        const char *logid = config_elts[i]->log_id;

        if (!pubkey || !logid) {
            continue;
        }

        if (!memcmp(logid, sctf->logid, LOG_ID_SIZE)) {
            if (!log_valid_for_received_sct(config_elts[i], sctf->time)) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                              APLOGNO(02766) "Got SCT from distrusted log, or "
                              "out of trusted time interval");
                return APR_EINVAL;
            }
            rv = verify_signature(sctf, pubkey);
            if (rv != APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, c, APLOGNO(02767)
                              "verify_signature failed");
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03037)
                              "verify_signature succeeded");
            }
            return rv;
        }
    }

    return APR_NOTFOUND;
}

apr_status_t sct_parse(const char *source,
                       server_rec *s, const unsigned char *sct,
                       apr_size_t len, cert_chain *cc,
                       sct_fields_t *fields)
{
    const unsigned char *cur;
    apr_size_t orig_len = len;
    apr_status_t rv;

    memset(fields, 0, sizeof *fields);

    if (len < 1 + LOG_ID_SIZE + 8) {
        /* no room for header */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     APLOGNO(02768) "SCT size %" APR_SIZE_T_FMT " is too small",
                     len);
        return APR_EINVAL;
    }

    cur = sct;

    fields->version = *cur;
    cur++;
    len -= 1;
    memcpy(fields->logid, cur, LOG_ID_SIZE);
    cur += LOG_ID_SIZE;
    len -= LOG_ID_SIZE;
    rv = ctutil_deserialize_uint64(&cur, &len, &fields->timestamp);
    ap_assert(rv == APR_SUCCESS);

    fields->time = apr_time_from_msec(fields->timestamp);

    /* XXX maybe do this only if log level is such that we'll
     *     use it later?
     */
    apr_rfc822_date(fields->timestr, fields->time);


    if (len < 2) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     APLOGNO(02769) "SCT size %" APR_SIZE_T_FMT " has no space "
                     "for extension len", orig_len);
        return APR_EINVAL;
    }

    rv = ctutil_deserialize_uint16(&cur, &len, &fields->extlen);
    ap_assert(rv == APR_SUCCESS);

    if (fields->extlen != 0) {
        if (fields->extlen < len) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         APLOGNO(02770) "SCT size %" APR_SIZE_T_FMT " has no "
                         "space for %hu bytes of extensions",
                         orig_len, fields->extlen);
            return APR_EINVAL;
        }

        fields->extensions = cur;
        cur += fields->extlen;
        len -= fields->extlen;
    }
    else {
        fields->extensions = 0;
    }

    if (len < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     APLOGNO(02771) "SCT size %" APR_SIZE_T_FMT " has no space "
                     "for hash algorithm, signature algorithm, and "
                     "signature len",
                     orig_len);
        return APR_EINVAL;
    }

    fields->hash_alg = *cur;
    cur += 1;
    len -= 1;
    fields->sig_alg = *cur;
    cur += 1;
    len -= 1;
    rv = ctutil_deserialize_uint16(&cur, &len, &fields->siglen);
    ap_assert(rv == APR_SUCCESS);

    if (fields->siglen < len) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     APLOGNO(02772) "SCT has no space for signature");
        return APR_EINVAL;
    }

    fields->sig = cur;
    cur += fields->siglen;
    len -= fields->siglen;

    if (cc) {
        /* If we have the server certificate, we can construct the
         * data over which the signature is computed.
         */

        /* XXX Which part is signed? */
        /* See certificate-transparency/src/proto/serializer.cc,
         * method Serializer::SerializeV1CertSCTSignatureInput()
         */

        apr_size_t orig_len;
        apr_size_t avail;
        int der_length;
        unsigned char *mem;
        unsigned char *orig_mem = NULL;

        der_length = i2d_X509(cc->leaf, NULL);
        if (der_length < 0) {
            rv = APR_EINVAL;
        }

        if (rv == APR_SUCCESS) {
            orig_len = 0
                + 1 /* version 1 */
                + 1 /* CERTIFICATE_TIMESTAMP */
                + 8 /* timestamp */
                + 2 /* X509_ENTRY */
                + 3 + der_length /* 24-bit length + X509 */
                + 2 + fields->extlen /* 16-bit length + extensions */
                ;
            avail = orig_len;
            mem = malloc(avail);
            orig_mem = mem;
            
            rv = ctutil_serialize_uint8(&mem, &avail, 0); /* version 1 */
            if (rv == APR_SUCCESS) {
                rv = ctutil_serialize_uint8(&mem, &avail, 0); /* CERTIFICATE_TIMESTAMP */
            }
            if (rv == APR_SUCCESS) {
                rv = ctutil_serialize_uint64(&mem, &avail, fields->timestamp);
            }
            if (rv == APR_SUCCESS) {
                rv = ctutil_serialize_uint16(&mem, &avail, 0); /* X509_ENTRY */
            }
            if (rv == APR_SUCCESS) {
                /* Get DER encoding of leaf certificate */
                unsigned char *der_buf
                    /* get OpenSSL to allocate: */
                    = NULL;

                der_length = i2d_X509(cc->leaf, &der_buf);
                if (der_length < 0) {
                    rv = APR_EINVAL;
                }
                else {
                    rv = ctutil_write_var24_bytes(&mem, &avail,
                                                  der_buf, der_length);
                    OPENSSL_free(der_buf);
                }
            }
            if (rv == APR_SUCCESS) {
                rv = ctutil_write_var16_bytes(&mem, &avail, fields->extensions,
                                              fields->extlen);
            }
        }

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         APLOGNO(02773) "Failed to reconstruct signed data for "
                         "SCT");
            if (orig_mem != NULL) {
                free(orig_mem);
            }
        }
        else {
            if (avail != 0) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                             APLOGNO(02774) "length miscalculation for signed "
                             "data (%" APR_SIZE_T_FMT
                             " vs. %" APR_SIZE_T_FMT ")",
                             orig_len, avail);
            }
            fields->signed_data_len = orig_len - avail;
            fields->signed_data = orig_mem;
            /* Force invalid signature error: orig_mem[0] = orig_mem[0] + 1; */
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03038)
                 "SCT from %s: version %d timestamp %s hash alg %d sig alg %d",
                 source, fields->version, fields->timestr,
                 fields->hash_alg, fields->sig_alg);
    ap_log_data(APLOG_MARK, APLOG_DEBUG, s, "Log Id",
                fields->logid, sizeof(fields->logid),
                AP_LOG_DATA_SHOW_OFFSET);
    ap_log_data(APLOG_MARK, APLOG_DEBUG, s, "Signature",
                fields->sig, fields->siglen,
                AP_LOG_DATA_SHOW_OFFSET);

    ap_assert(!(fields->signed_data && rv != APR_SUCCESS));

    return rv;
}

void sct_release(sct_fields_t *sctf)
{
    if (sctf->signed_data) {
        free((void *)sctf->signed_data);
        sctf->signed_data = NULL;
    }
}

apr_status_t sct_verify_timestamp(conn_rec *c, sct_fields_t *sctf)
{
    if (sctf->time > apr_time_now()) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      APLOGNO(02775) "Server sent SCT not yet valid (timestamp "
                      "%s)",
                      sctf->timestr);
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}
