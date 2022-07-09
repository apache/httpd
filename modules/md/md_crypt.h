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

#ifndef mod_md_md_crypt_h
#define mod_md_md_crypt_h

#include <apr_file_io.h>

struct apr_array_header_t;
struct md_t;
struct md_http_response_t;
struct md_cert_t;
struct md_pkey_t;
struct md_data_t;
struct md_timeperiod_t;

/**************************************************************************************************/
/* random */

apr_status_t md_rand_bytes(unsigned char *buf, apr_size_t len, apr_pool_t *p);

apr_time_t md_asn1_generalized_time_get(void *ASN1_GENERALIZEDTIME);

/**************************************************************************************************/
/* digests */
apr_status_t md_crypt_sha256_digest64(const char **pdigest64, apr_pool_t *p, 
                                      const struct md_data_t *data);
apr_status_t md_crypt_sha256_digest_hex(const char **pdigesthex, apr_pool_t *p, 
                                        const struct md_data_t *data);

/**************************************************************************************************/
/* private keys */

typedef struct md_pkey_t md_pkey_t;

typedef enum {
    MD_PKEY_TYPE_DEFAULT,
    MD_PKEY_TYPE_RSA,
    MD_PKEY_TYPE_EC,
} md_pkey_type_t;

typedef struct md_pkey_rsa_params_t {
    apr_uint32_t bits;
} md_pkey_rsa_params_t;

typedef struct md_pkey_ec_params_t {
    const char *curve;
} md_pkey_ec_params_t;

typedef struct md_pkey_spec_t {
    md_pkey_type_t type;
    union {
        md_pkey_rsa_params_t rsa;
        md_pkey_ec_params_t ec;
    } params;
} md_pkey_spec_t;

typedef struct md_pkeys_spec_t {
    apr_pool_t *p;
    struct apr_array_header_t *specs;
} md_pkeys_spec_t;

apr_status_t md_crypt_init(apr_pool_t *pool);

const char *md_pkey_spec_name(const md_pkey_spec_t *spec);

md_pkeys_spec_t *md_pkeys_spec_make(apr_pool_t *p);
void md_pkeys_spec_add_default(md_pkeys_spec_t *pks);
int md_pkeys_spec_contains_rsa(md_pkeys_spec_t *pks);
void md_pkeys_spec_add_rsa(md_pkeys_spec_t *pks, unsigned int bits);
int md_pkeys_spec_contains_ec(md_pkeys_spec_t *pks, const char *curve);
void md_pkeys_spec_add_ec(md_pkeys_spec_t *pks, const char *curve);
int md_pkeys_spec_eq(md_pkeys_spec_t *pks1, md_pkeys_spec_t *pks2);
md_pkeys_spec_t *md_pkeys_spec_clone(apr_pool_t *p, const md_pkeys_spec_t *pks);
int md_pkeys_spec_is_empty(const md_pkeys_spec_t *pks);
md_pkey_spec_t *md_pkeys_spec_get(const md_pkeys_spec_t *pks, int index);
int md_pkeys_spec_count(const md_pkeys_spec_t *pks);
void md_pkeys_spec_add(md_pkeys_spec_t *pks, md_pkey_spec_t *spec);

struct md_json_t *md_pkey_spec_to_json(const md_pkey_spec_t *spec, apr_pool_t *p);
md_pkey_spec_t *md_pkey_spec_from_json(struct md_json_t *json, apr_pool_t *p);
struct md_json_t *md_pkeys_spec_to_json(const md_pkeys_spec_t *pks, apr_pool_t *p);
md_pkeys_spec_t *md_pkeys_spec_from_json(struct md_json_t *json, apr_pool_t *p);


apr_status_t md_pkey_gen(md_pkey_t **ppkey, apr_pool_t *p, md_pkey_spec_t *key_props);
void md_pkey_free(md_pkey_t *pkey);

const char *md_pkey_get_rsa_e64(md_pkey_t *pkey, apr_pool_t *p);
const char *md_pkey_get_rsa_n64(md_pkey_t *pkey, apr_pool_t *p);

apr_status_t md_pkey_fload(md_pkey_t **ppkey, apr_pool_t *p, 
                           const char *pass_phrase, apr_size_t pass_len,
                           const char *fname);
apr_status_t md_pkey_fsave(md_pkey_t *pkey, apr_pool_t *p, 
                           const char *pass_phrase, apr_size_t pass_len, 
                           const char *fname, apr_fileperms_t perms);

apr_status_t md_crypt_sign64(const char **psign64, md_pkey_t *pkey, apr_pool_t *p, 
                             const char *d, size_t dlen);

void *md_pkey_get_EVP_PKEY(struct md_pkey_t *pkey);

apr_status_t md_crypt_hmac64(const char **pmac64, const struct md_data_t *hmac_key,
                             apr_pool_t *p, const char *d, size_t dlen);

/**
 * Read a private key from a http response.
 */
apr_status_t md_pkey_read_http(md_pkey_t **ppkey, apr_pool_t *pool,
                               const struct md_http_response_t *res);

/**************************************************************************************************/
/* X509 certificates */

typedef struct md_cert_t md_cert_t;

typedef enum {
    MD_CERT_UNKNOWN,
    MD_CERT_VALID,
    MD_CERT_EXPIRED
} md_cert_state_t;

/**
 * Create a holder of the certificate that will free its memory when the
 * pool is destroyed.
 */
md_cert_t *md_cert_make(apr_pool_t *p, void *x509);

/**
 * Wrap a x509 certificate into our own structure, without taking ownership
 * of its memory. The caller remains responsible.
 */
md_cert_t *md_cert_wrap(apr_pool_t *p, void *x509);

void *md_cert_get_X509(const md_cert_t *cert);

apr_status_t md_cert_fload(md_cert_t **pcert, apr_pool_t *p, const char *fname);
apr_status_t md_cert_fsave(md_cert_t *cert, apr_pool_t *p, 
                           const char *fname, apr_fileperms_t perms);

/**
 * Read a x509 certificate from a http response.
 * Will return APR_ENOENT if content-type is not recognized (currently
 * only "application/pkix-cert" is supported).
 */
apr_status_t md_cert_read_http(md_cert_t **pcert, apr_pool_t *pool, 
                               const struct md_http_response_t *res);

/**
 * Read at least one certificate from the given PEM data.
 */
apr_status_t md_cert_read_chain(apr_array_header_t *chain, apr_pool_t *p,
                                const char *pem, apr_size_t pem_len);

/**
 * Read one or even a chain of certificates from a http response.
 * Will return APR_ENOENT if content-type is not recognized (currently
 * supports only "application/pem-certificate-chain" and "application/pkix-cert").
 * @param chain    must be non-NULL, retrieved certificates will be added.
 */
apr_status_t md_cert_chain_read_http(struct apr_array_header_t *chain,
                                     apr_pool_t *pool, const struct md_http_response_t *res);

md_cert_state_t md_cert_state_get(const md_cert_t *cert);
int md_cert_is_valid_now(const md_cert_t *cert);
int md_cert_has_expired(const md_cert_t *cert);
int md_cert_covers_domain(md_cert_t *cert, const char *domain_name);
int md_cert_covers_md(md_cert_t *cert, const struct md_t *md);
int md_cert_must_staple(const md_cert_t *cert);
apr_time_t md_cert_get_not_after(const md_cert_t *cert);
apr_time_t md_cert_get_not_before(const md_cert_t *cert);
struct md_timeperiod_t md_cert_get_valid(const md_cert_t *cert);

/**
 * Return != 0 iff the hash values of the certificates are equal.
 */
int md_certs_are_equal(const md_cert_t *a, const md_cert_t *b);

apr_status_t md_cert_get_issuers_uri(const char **puri, const md_cert_t *cert, apr_pool_t *p);
apr_status_t md_cert_get_alt_names(apr_array_header_t **pnames, const md_cert_t *cert, apr_pool_t *p);

apr_status_t md_cert_to_base64url(const char **ps64, const md_cert_t *cert, apr_pool_t *p);
apr_status_t md_cert_from_base64url(md_cert_t **pcert, const char *s64, apr_pool_t *p);

apr_status_t md_cert_to_sha256_digest(struct md_data_t **pdigest, const md_cert_t *cert, apr_pool_t *p);
apr_status_t md_cert_to_sha256_fingerprint(const char **pfinger, const md_cert_t *cert, apr_pool_t *p);

const char *md_cert_get_serial_number(const md_cert_t *cert, apr_pool_t *p);

apr_status_t md_chain_fload(struct apr_array_header_t **pcerts, 
                            apr_pool_t *p, const char *fname);
apr_status_t md_chain_fsave(struct apr_array_header_t *certs, 
                            apr_pool_t *p, const char *fname, apr_fileperms_t perms);
apr_status_t md_chain_fappend(struct apr_array_header_t *certs, 
                              apr_pool_t *p, const char *fname);

apr_status_t md_cert_req_create(const char **pcsr_der_64, const char *name,
                                apr_array_header_t *domains, int must_staple, 
                                md_pkey_t *pkey, apr_pool_t *p);

/**
 * Create a self-signed cerftificate with the given cn, key and list
 * of alternate domain names.
 */
apr_status_t md_cert_self_sign(md_cert_t **pcert, const char *cn, 
                               struct apr_array_header_t *domains, md_pkey_t *pkey,
                               apr_interval_time_t valid_for, apr_pool_t *p);
   
/**
 * Create a certificate for answering "tls-alpn-01" ACME challenges 
 * (see <https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01>).
 */
apr_status_t md_cert_make_tls_alpn_01(md_cert_t **pcert, const char *domain, 
                                      const char *acme_id, md_pkey_t *pkey, 
                                      apr_interval_time_t valid_for, apr_pool_t *p);

apr_status_t md_cert_get_ct_scts(apr_array_header_t *scts, apr_pool_t *p, const md_cert_t *cert);

apr_status_t md_cert_get_ocsp_responder_url(const char **purl, apr_pool_t *p, const md_cert_t *cert);

apr_status_t md_check_cert_and_pkey(struct apr_array_header_t *certs, md_pkey_t *pkey);


/**************************************************************************************************/
/* X509 certificate transparency */

const char *md_nid_get_sname(int nid);
const char *md_nid_get_lname(int nid);

typedef struct md_sct md_sct;
struct md_sct {
    int version;
    apr_time_t timestamp;
    struct md_data_t *logid;
    int signature_type_nid;
    struct md_data_t *signature;
};

#endif /* md_crypt_h */
