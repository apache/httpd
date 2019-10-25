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
 
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_file_io.h>
#include <apr_strings.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_http.h"
#include "md_util.h"

/* getpid for *NIX */
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* getpid for Windows */
#if APR_HAVE_PROCESS_H
#include <process.h>
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
/* Missing from LibreSSL */
#define MD_USE_OPENSSL_PRE_1_1_API (LIBRESSL_VERSION_NUMBER < 0x2070000f)
#else /* defined(LIBRESSL_VERSION_NUMBER) */
#define MD_USE_OPENSSL_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
#endif

#if defined(LIBRESSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < 0x10100000L) 
/* Missing from LibreSSL and only available since OpenSSL v1.1.x */
#ifndef OPENSSL_NO_CT
#define OPENSSL_NO_CT
#endif
#endif

#ifndef OPENSSL_NO_CT
#include <openssl/ct.h>
#endif

static int initialized;

struct md_pkey_t {
    apr_pool_t *pool;
    EVP_PKEY   *pkey;
};

#ifdef MD_HAVE_ARC4RANDOM

static void seed_RAND(int pid)
{
    char seed[128];
    
    (void)pid;
    arc4random_buf(seed, sizeof(seed));
    RAND_seed(seed, sizeof(seed));
}

#else /* ifdef MD_HAVE_ARC4RANDOM */

static int rand_choosenum(int l, int h)
{
    int i;
    char buf[50];

    apr_snprintf(buf, sizeof(buf), "%.0f",
                 (((double)(rand()%RAND_MAX)/RAND_MAX)*(h-l)));
    i = atoi(buf)+1;
    if (i < l) i = l;
    if (i > h) i = h;
    return i;
}

static void seed_RAND(int pid)
{   
    unsigned char stackdata[256];
    /* stolen from mod_ssl/ssl_engine_rand.c */
    int n;
    struct {
        time_t t;
        pid_t pid;
    } my_seed;
    
    /*
     * seed in the current time (usually just 4 bytes)
     */
    my_seed.t = time(NULL);
    
    /*
     * seed in the current process id (usually just 4 bytes)
     */
    my_seed.pid = pid;
    
    RAND_seed((unsigned char *)&my_seed, sizeof(my_seed));
    
    /*
     * seed in some current state of the run-time stack (128 bytes)
     */
    n = rand_choosenum(0, sizeof(stackdata)-128-1);
    RAND_seed(stackdata+n, 128);
}

#endif /*ifdef MD_HAVE_ARC4RANDOM (else part) */


apr_status_t md_crypt_init(apr_pool_t *pool)
{
    (void)pool;
    
    if (!initialized) {
        int pid = getpid();
        
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, pool, "initializing RAND"); 
        while (!RAND_status()) {
            seed_RAND(pid);
	}

        initialized = 1;
    }
    return APR_SUCCESS;
}

static apr_status_t fwrite_buffer(void *baton, apr_file_t *f, apr_pool_t *p) 
{
    md_data_t *buf = baton;
    apr_size_t wlen;
    
    (void)p;
    return apr_file_write_full(f, buf->data, buf->len, &wlen);
}

apr_status_t md_rand_bytes(unsigned char *buf, apr_size_t len, apr_pool_t *p)
{
    apr_status_t rv;
    
    if (len > INT_MAX) {
        return APR_ENOTIMPL;
    }
    if (APR_SUCCESS == (rv = md_crypt_init(p))) {
        RAND_bytes((unsigned char*)buf, (int)len);
    }
    return rv;
}

typedef struct {
    const char *pass_phrase;
    int pass_len;
} passwd_ctx;

static int pem_passwd(char *buf, int size, int rwflag, void *baton)
{
    passwd_ctx *ctx = baton;
    
    (void)rwflag;
    if (ctx->pass_len > 0) {
        if (ctx->pass_len < size) {
            size = (int)ctx->pass_len;
        }
        memcpy(buf, ctx->pass_phrase, (size_t)size);
    }
    return ctx->pass_len;
}

/**************************************************************************************************/
/* date time things */

/* Get the apr time (micro seconds, since 1970) from an ASN1 time, as stored in X509
 * certificates. OpenSSL now has a utility function, but other *SSL derivatives have
 * not caughts up yet or chose to ignore. An alternative is implemented, we prefer 
 * however the *SSL to maintain such things.
 */
static apr_time_t md_asn1_time_get(const ASN1_TIME* time)
{
#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
    /* courtesy: https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion#11263731
     * all bugs are mine */
    apr_time_exp_t t;
    apr_time_t ts;
    const char* str = (const char*) time->data;
    apr_size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        t.tm_year = (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    } 
    else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        t.tm_year = (str[i++] - '0') * 1000;
        t.tm_year+= (str[i++] - '0') * 100;
        t.tm_year+= (str[i++] - '0') * 10;
        t.tm_year+= (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon  = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; /* -1 since January is 0 not 1. */
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday+= (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour+= (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');
    
    if (APR_SUCCESS == apr_time_exp_gmt_get(&ts, &t)) {
        return ts;
    }
    return 0;
#else 
    int secs, days;
    apr_time_t ts = apr_time_now();
    
    if (ASN1_TIME_diff(&days, &secs, NULL, time)) {
        ts += apr_time_from_sec((days * MD_SECS_PER_DAY) + secs); 
    }
    return ts;
#endif
}

apr_time_t md_asn1_generalized_time_get(void *ASN1_GENERALIZEDTIME)
{
    return md_asn1_time_get(ASN1_GENERALIZEDTIME);
}


/**************************************************************************************************/
/* private keys */

md_json_t *md_pkey_spec_to_json(const md_pkey_spec_t *spec, apr_pool_t *p)
{
    md_json_t *json = md_json_create(p);
    if (json) {
        switch (spec->type) {
            case MD_PKEY_TYPE_DEFAULT:
                md_json_sets("Default", json, MD_KEY_TYPE, NULL);
                break;
            case MD_PKEY_TYPE_RSA:
                md_json_sets("RSA", json, MD_KEY_TYPE, NULL);
                if (spec->params.rsa.bits >= MD_PKEY_RSA_BITS_MIN) {
                    md_json_setl((long)spec->params.rsa.bits, json, MD_KEY_BITS, NULL);
                }
                break;
            default:
                md_json_sets("Unsupported", json, MD_KEY_TYPE, NULL);
                break;
        }
    }
    return json;    
}

md_pkey_spec_t *md_pkey_spec_from_json(struct md_json_t *json, apr_pool_t *p)
{
    md_pkey_spec_t *spec = apr_pcalloc(p, sizeof(*spec));
    const char *s;
    long l;
    
    if (spec) {
        s = md_json_gets(json, MD_KEY_TYPE, NULL);
        if (!s || !apr_strnatcasecmp("Default", s)) {
            spec->type = MD_PKEY_TYPE_DEFAULT;
        }
        else if (!apr_strnatcasecmp("RSA", s)) {
            spec->type = MD_PKEY_TYPE_RSA;
            l = md_json_getl(json, MD_KEY_BITS, NULL);
            if (l >= MD_PKEY_RSA_BITS_MIN) {
                spec->params.rsa.bits = (unsigned int)l;
            }
            else {
                spec->params.rsa.bits = MD_PKEY_RSA_BITS_DEF;
            }
        }
    }
    return spec;
}

int md_pkey_spec_eq(md_pkey_spec_t *spec1, md_pkey_spec_t *spec2)
{
    if (spec1 == spec2) {
        return 1;
    }
    if (spec1 && spec2 && spec1->type == spec2->type) {
        switch (spec1->type) {
            case MD_PKEY_TYPE_DEFAULT:
                return 1;
            case MD_PKEY_TYPE_RSA:
                if (spec1->params.rsa.bits == spec2->params.rsa.bits) {
                    return 1;
                }
                break;
        }
    }
    return 0;
}

static md_pkey_t *make_pkey(apr_pool_t *p) 
{
    md_pkey_t *pkey = apr_pcalloc(p, sizeof(*pkey));
    pkey->pool = p;
    return pkey;
}

static apr_status_t pkey_cleanup(void *data)
{
    md_pkey_t *pkey = data;
    if (pkey->pkey) {
        EVP_PKEY_free(pkey->pkey);
        pkey->pkey = NULL;
    }
    return APR_SUCCESS;
}

void md_pkey_free(md_pkey_t *pkey)
{
    pkey_cleanup(pkey);
}

void *md_pkey_get_EVP_PKEY(struct md_pkey_t *pkey)
{
    return pkey->pkey;
}

apr_status_t md_pkey_fload(md_pkey_t **ppkey, apr_pool_t *p, 
                           const char *key, apr_size_t key_len,
                           const char *fname)
{
    apr_status_t rv = APR_ENOENT;
    md_pkey_t *pkey;
    BIO *bf;
    passwd_ctx ctx;
    
    pkey =  make_pkey(p);
    if (NULL != (bf = BIO_new_file(fname, "r"))) {
        ctx.pass_phrase = key;
        ctx.pass_len = (int)key_len;
        
        ERR_clear_error();
        pkey->pkey = PEM_read_bio_PrivateKey(bf, NULL, pem_passwd, &ctx);
        BIO_free(bf);
        
        if (pkey->pkey != NULL) {
            rv = APR_SUCCESS;
            apr_pool_cleanup_register(p, pkey, pkey_cleanup, apr_pool_cleanup_null);
        }
        else {
            unsigned long err = ERR_get_error();
            rv = APR_EINVAL;
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                          "error loading pkey %s: %s (pass phrase was %snull)", fname,
                          ERR_error_string(err, NULL), key? "not " : ""); 
        }
    }
    *ppkey = (APR_SUCCESS == rv)? pkey : NULL;
    return rv;
}

static apr_status_t pkey_to_buffer(md_data_t *buf, md_pkey_t *pkey, apr_pool_t *p,
                                   const char *pass, apr_size_t pass_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    const EVP_CIPHER *cipher = NULL;
    pem_password_cb *cb = NULL;
    void *cb_baton = NULL;
    passwd_ctx ctx;
    unsigned long err;
    int i;
    
    if (!bio) {
        return APR_ENOMEM;
    }
    if (pass_len > INT_MAX) {
        return APR_EINVAL;
    }
    if (pass && pass_len > 0) {
        ctx.pass_phrase = pass;
        ctx.pass_len = (int)pass_len;
        cb = pem_passwd;
        cb_baton = &ctx;
        cipher = EVP_aes_256_cbc();
        if (!cipher) {
            return APR_ENOTIMPL;
        }
    }
    
    ERR_clear_error();
    if (!PEM_write_bio_PrivateKey(bio, pkey->pkey, cipher, NULL, 0, cb, cb_baton)) {
        BIO_free(bio);
        err = ERR_get_error();
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "PEM_write key: %ld %s", 
                      err, ERR_error_string(err, NULL)); 
        return APR_EINVAL;
    }

    i = BIO_pending(bio);
    if (i > 0) {
        buf->data = apr_palloc(p, (apr_size_t)i);
        i = BIO_read(bio, (char*)buf->data, i);
        buf->len = (apr_size_t)i;
    }
    BIO_free(bio);
    return APR_SUCCESS;
}

apr_status_t md_pkey_fsave(md_pkey_t *pkey, apr_pool_t *p, 
                           const char *pass_phrase, apr_size_t pass_len,
                           const char *fname, apr_fileperms_t perms)
{
    md_data_t buffer;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = pkey_to_buffer(&buffer, pkey, p, pass_phrase, pass_len))) {
        return md_util_freplace(fname, perms, p, fwrite_buffer, &buffer); 
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p, "save pkey %s (%s pass phrase, len=%d)",
                  fname, pass_len > 0? "with" : "without", (int)pass_len); 
    return rv;
}

static apr_status_t gen_rsa(md_pkey_t **ppkey, apr_pool_t *p, unsigned int bits)
{
    EVP_PKEY_CTX *ctx = NULL;
    apr_status_t rv;
    
    *ppkey = make_pkey(p);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx 
        && EVP_PKEY_keygen_init(ctx) >= 0
        && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)bits) >= 0
        && EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) >= 0) {
        rv = APR_SUCCESS;
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, "error generate pkey RSA %d", bits); 
        *ppkey = NULL;
        rv = APR_EGENERAL;
    }
    
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return rv;
}

apr_status_t md_pkey_gen(md_pkey_t **ppkey, apr_pool_t *p, md_pkey_spec_t *spec)
{
    md_pkey_type_t ptype = spec? spec->type : MD_PKEY_TYPE_DEFAULT;
    switch (ptype) {
        case MD_PKEY_TYPE_DEFAULT:
            return gen_rsa(ppkey, p, MD_PKEY_RSA_BITS_DEF);
        case MD_PKEY_TYPE_RSA:
            return gen_rsa(ppkey, p, spec->params.rsa.bits);
        default:
            return APR_ENOTIMPL;
    }
}

#if MD_USE_OPENSSL_PRE_1_1_API || (defined(LIBRESSL_VERSION_NUMBER) && \
                                   LIBRESSL_VERSION_NUMBER < 0x2070000f)

#ifndef NID_tlsfeature
#define NID_tlsfeature          1020
#endif

static void RSA_get0_key(const RSA *r,
                         const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

#endif

static const char *bn64(const BIGNUM *b, apr_pool_t *p) 
{
    if (b) {
        md_data_t buffer;

        buffer.len = (apr_size_t)BN_num_bytes(b);
        buffer.data = apr_pcalloc(p, buffer.len);
        if (buffer.data) {
            BN_bn2bin(b, (unsigned char *)buffer.data);
            return md_util_base64url_encode(&buffer, p);
        }
    }
    return NULL;
}

const char *md_pkey_get_rsa_e64(md_pkey_t *pkey, apr_pool_t *p)
{
    const BIGNUM *e;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey->pkey);
    
    if (!rsa) {
        return NULL;
    }
    RSA_get0_key(rsa, NULL, &e, NULL);
    return bn64(e, p);
}

const char *md_pkey_get_rsa_n64(md_pkey_t *pkey, apr_pool_t *p)
{
    const BIGNUM *n;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey->pkey);
    
    if (!rsa) {
        return NULL;
    }
    RSA_get0_key(rsa, &n, NULL, NULL);
    return bn64(n, p);
}

apr_status_t md_crypt_sign64(const char **psign64, md_pkey_t *pkey, apr_pool_t *p, 
                             const char *d, size_t dlen)
{
    EVP_MD_CTX *ctx = NULL;
    md_data_t buffer;
    unsigned int blen;
    const char *sign64 = NULL;
    apr_status_t rv = APR_ENOMEM;
    
    buffer.len = (apr_size_t)EVP_PKEY_size(pkey->pkey);
    buffer.data = apr_pcalloc(p, buffer.len);
    if (buffer.data) {
        ctx = EVP_MD_CTX_create();
        if (ctx) {
            rv = APR_ENOTIMPL;
            if (EVP_SignInit_ex(ctx, EVP_sha256(), NULL)) {
                rv = APR_EGENERAL;
                if (EVP_SignUpdate(ctx, d, dlen)) {
                    if (EVP_SignFinal(ctx, (unsigned char*)buffer.data, &blen, pkey->pkey)) {
                        buffer.len = blen;
                        sign64 = md_util_base64url_encode(&buffer, p);
                        if (sign64) {
                            rv = APR_SUCCESS;
                        }
                    }
                }
            }
        }
        
        if (ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    
    if (rv != APR_SUCCESS) {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, "signing"); 
    }
    
    *psign64 = sign64;
    return rv;
}

static apr_status_t sha256_digest(md_data_t **pdigest, apr_pool_t *p, const md_data_t *buf)
{
    EVP_MD_CTX *ctx = NULL;
    md_data_t *digest;
    apr_status_t rv = APR_ENOMEM;
    unsigned int dlen;

    digest = apr_palloc(p, sizeof(*digest));
    if (!digest) goto leave;
    digest->data = apr_pcalloc(p, EVP_MAX_MD_SIZE);
    if (!digest->data) goto leave;
    
    ctx = EVP_MD_CTX_create();
    if (ctx) {
        rv = APR_ENOTIMPL;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
            rv = APR_EGENERAL;
            if (EVP_DigestUpdate(ctx, (unsigned char*)buf->data, buf->len)) {
                if (EVP_DigestFinal(ctx, (unsigned char*)digest->data, &dlen)) {
                    digest->len = dlen;
                    rv = APR_SUCCESS;
                }
            }
        }
    }
leave:
    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
    }
    *pdigest = (APR_SUCCESS == rv)? digest : NULL;
    return rv;
}

apr_status_t md_crypt_sha256_digest64(const char **pdigest64, apr_pool_t *p, const md_data_t *d)
{
    const char *digest64 = NULL;
    md_data_t *digest;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = sha256_digest(&digest, p, d))) {
        if (NULL == (digest64 = md_util_base64url_encode(digest, p))) {
            rv = APR_EGENERAL;
        }
    }
    *pdigest64 = digest64;
    return rv;
}

apr_status_t md_crypt_sha256_digest_hex(const char **pdigesthex, apr_pool_t *p, 
                                        const md_data_t *data)
{
    md_data_t *digest;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = sha256_digest(&digest, p, data))) {
        return md_data_to_hex(pdigesthex, 0, p, digest);
    }
    *pdigesthex = NULL;
    return rv;
}

/**************************************************************************************************/
/* certificates */

struct md_cert_t {
    apr_pool_t *pool;
    X509 *x509;
    apr_array_header_t *alt_names;
};

static apr_status_t cert_cleanup(void *data)
{
    md_cert_t *cert = data;
    if (cert->x509) {
        X509_free(cert->x509);
        cert->x509 = NULL;
    }
    return APR_SUCCESS;
}

md_cert_t *md_cert_wrap(apr_pool_t *p, void *x509) 
{
    md_cert_t *cert = apr_pcalloc(p, sizeof(*cert));
    cert->pool = p;
    cert->x509 = x509;
    return cert;
}

md_cert_t *md_cert_make(apr_pool_t *p, void *x509) 
{
    md_cert_t *cert = md_cert_wrap(p, x509);
    apr_pool_cleanup_register(p, cert, cert_cleanup, apr_pool_cleanup_null);
    return cert;
}

void *md_cert_get_X509(const md_cert_t *cert)
{
    return cert->x509;
}

const char *md_cert_get_serial_number(const md_cert_t *cert, apr_pool_t *p)
{
    const char *s = "";
    BIGNUM *bn; 
    const char *serial;
    const ASN1_INTEGER *ai = X509_get_serialNumber(cert->x509);
    if (ai) {
        bn = ASN1_INTEGER_to_BN(ai, NULL);
        serial = BN_bn2hex(bn);
        s = apr_pstrdup(p, serial);
        OPENSSL_free((void*)serial);
        OPENSSL_free((void*)bn);
    }
    return s;
}

int md_cert_is_valid_now(const md_cert_t *cert)
{
    return ((X509_cmp_current_time(X509_get_notBefore(cert->x509)) < 0)
            && (X509_cmp_current_time(X509_get_notAfter(cert->x509)) > 0));
}

int md_cert_has_expired(const md_cert_t *cert)
{
    return (X509_cmp_current_time(X509_get_notAfter(cert->x509)) <= 0);
}

apr_time_t md_cert_get_not_after(const md_cert_t *cert)
{
    return md_asn1_time_get(X509_get_notAfter(cert->x509));
}

apr_time_t md_cert_get_not_before(const md_cert_t *cert)
{
    return md_asn1_time_get(X509_get_notBefore(cert->x509));
}

int md_cert_covers_domain(md_cert_t *cert, const char *domain_name)
{
    apr_array_header_t *alt_names;

    md_cert_get_alt_names(&alt_names, cert, cert->pool);
    if (alt_names) {
        return md_array_str_index(alt_names, domain_name, 0, 0) >= 0;
    }
    return 0;
}

int md_cert_covers_md(md_cert_t *cert, const md_t *md)
{
    const char *name;
    int i;
    
    if (!cert->alt_names) {
        md_cert_get_alt_names(&cert->alt_names, cert, cert->pool);
    }
    if (cert->alt_names) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, cert->pool, "cert has %d alt names",
                      cert->alt_names->nelts); 
        for (i = 0; i < md->domains->nelts; ++i) {
            name = APR_ARRAY_IDX(md->domains, i, const char *);
            if (!md_dns_domains_match(cert->alt_names, name)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, cert->pool, 
                              "md domain %s not covered by cert", name);
                return 0;
            }
        }
        return 1;
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, cert->pool, "cert has NO alt names");
    }
    return 0;
}

apr_status_t md_cert_get_issuers_uri(const char **puri, const md_cert_t *cert, apr_pool_t *p)
{
    apr_status_t rv = APR_ENOENT;
    STACK_OF(ACCESS_DESCRIPTION) *xinfos;
    const char *uri = NULL;
    unsigned char *buf;
    int i;

    xinfos = X509_get_ext_d2i(cert->x509, NID_info_access, NULL, NULL);
    if (xinfos) {
        for (i = 0; i < sk_ACCESS_DESCRIPTION_num(xinfos); i++) {
            ACCESS_DESCRIPTION *val = sk_ACCESS_DESCRIPTION_value(xinfos, i);
            if (OBJ_obj2nid(val->method) == NID_ad_ca_issuers
                    && val->location && val->location->type == GEN_URI) {
                ASN1_STRING_to_UTF8(&buf, val->location->d.uniformResourceIdentifier);
                uri = apr_pstrdup(p, (char *)buf);
                OPENSSL_free(buf);
                rv = APR_SUCCESS;
                break;
            }
        }
        sk_ACCESS_DESCRIPTION_pop_free(xinfos, ACCESS_DESCRIPTION_free);
    } 
    *puri = (APR_SUCCESS == rv)? uri : NULL;
    return rv;
}

apr_status_t md_cert_get_alt_names(apr_array_header_t **pnames, const md_cert_t *cert, apr_pool_t *p)
{
    apr_array_header_t *names;
    apr_status_t rv = APR_ENOENT;
    STACK_OF(GENERAL_NAME) *xalt_names;
    unsigned char *buf;
    int i;
    
    xalt_names = X509_get_ext_d2i(cert->x509, NID_subject_alt_name, NULL, NULL);
    if (xalt_names) {
        GENERAL_NAME *cval;
        
        names = apr_array_make(p, sk_GENERAL_NAME_num(xalt_names), sizeof(char *));
        for (i = 0; i < sk_GENERAL_NAME_num(xalt_names); ++i) {
            cval = sk_GENERAL_NAME_value(xalt_names, i);
            switch (cval->type) {
                case GEN_DNS:
                case GEN_URI:
                case GEN_IPADD:
                    ASN1_STRING_to_UTF8(&buf, cval->d.ia5);
                    APR_ARRAY_PUSH(names, const char *) = apr_pstrdup(p, (char*)buf);
                    OPENSSL_free(buf);
                    break;
                default:
                    break;
            }
        }
        sk_GENERAL_NAME_pop_free(xalt_names, GENERAL_NAME_free);
        rv = APR_SUCCESS;
    }
    *pnames = (APR_SUCCESS == rv)? names : NULL;
    return rv;
}

apr_status_t md_cert_fload(md_cert_t **pcert, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    md_cert_t *cert;
    X509 *x509;
    
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
    
        x509 = PEM_read_X509(f, NULL, NULL, NULL);
        rv = fclose(f);
        if (x509 != NULL) {
            cert =  md_cert_make(p, x509);
        }
        else {
            rv = APR_EINVAL;
        }
    }

    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    return rv;
}

static apr_status_t cert_to_buffer(md_data_t *buffer, const md_cert_t *cert, apr_pool_t *p)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int i;
    
    if (!bio) {
        return APR_ENOMEM;
    }

    ERR_clear_error();
    PEM_write_bio_X509(bio, cert->x509);
    if (ERR_get_error() > 0) {
        BIO_free(bio);
        return APR_EINVAL;
    }

    i = BIO_pending(bio);
    if (i > 0) {
        buffer->data = apr_palloc(p, (apr_size_t)i);
        i = BIO_read(bio, (char*)buffer->data, i);
        buffer->len = (apr_size_t)i;
    }
    BIO_free(bio);
    return APR_SUCCESS;
}

apr_status_t md_cert_fsave(md_cert_t *cert, apr_pool_t *p, 
                           const char *fname, apr_fileperms_t perms)
{
    md_data_t buffer;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = cert_to_buffer(&buffer, cert, p))) {
        return md_util_freplace(fname, perms, p, fwrite_buffer, &buffer); 
    }
    return rv;
}

apr_status_t md_cert_to_base64url(const char **ps64, const md_cert_t *cert, apr_pool_t *p)
{
    md_data_t buffer;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = cert_to_buffer(&buffer, cert, p))) {
        *ps64 = md_util_base64url_encode(&buffer, p);
        return APR_SUCCESS;
    }
    *ps64 = NULL;
    return rv;
}

apr_status_t md_cert_to_sha256_digest(md_data_t **pdigest, const md_cert_t *cert, apr_pool_t *p)
{
    md_data_t *digest;
    unsigned int dlen;
    apr_status_t rv = APR_ENOMEM;
    
    digest = apr_palloc(p, sizeof(*digest));
    if (!digest) goto leave;
    digest->data = apr_pcalloc(p, EVP_MAX_MD_SIZE);
    if (!digest->data) goto leave;

    X509_digest(cert->x509, EVP_sha256(), (unsigned char*)digest->data, &dlen);
    digest->len = dlen;
    rv = APR_SUCCESS;
leave:
    *pdigest = (APR_SUCCESS == rv)? digest : NULL;
    return rv;
}

apr_status_t md_cert_to_sha256_fingerprint(const char **pfinger, const md_cert_t *cert, apr_pool_t *p)
{
    md_data_t *digest;
    apr_status_t rv;
    
    rv = md_cert_to_sha256_digest(&digest, cert, p);
    if (APR_SUCCESS == rv) {
        return md_data_to_hex(pfinger, 0, p, digest);
    }
    *pfinger = NULL;
    return rv;
}

static int md_cert_read_pem(BIO *bf, apr_pool_t *p, md_cert_t **pcert)
{
    md_cert_t *cert;
    X509 *x509;
    apr_status_t rv;
    
    ERR_clear_error();
    x509 = PEM_read_bio_X509(bf, NULL, NULL, NULL);
    if (x509 == NULL) {
        rv = APR_ENOENT;
        goto out;
    }
    cert = md_cert_make(p, x509);
    rv = APR_SUCCESS;
    
out:
    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    return rv;
}

apr_status_t md_cert_read_http(md_cert_t **pcert, apr_pool_t *p, 
                               const md_http_response_t *res)
{
    const char *ct;
    apr_off_t data_len;
    char *der;
    apr_size_t der_len;
    md_cert_t *cert = NULL;
    apr_status_t rv;
    
    ct = apr_table_get(res->headers, "Content-Type");
    if (!res->body || !ct || strcmp("application/pkix-cert", ct)) {
        rv = APR_ENOENT;
        goto out;
    }
    
    if (APR_SUCCESS == (rv = apr_brigade_length(res->body, 1, &data_len))) {
        if (data_len > 1024*1024) { /* certs usually are <2k each */
            return APR_EINVAL;
        }
        if (APR_SUCCESS == (rv = apr_brigade_pflatten(res->body, &der, &der_len, res->req->pool))) {
            const unsigned char *bf = (const unsigned char*)der;
            X509 *x509;
            
            if (NULL == (x509 = d2i_X509(NULL, &bf, (long)der_len))) {
                rv = APR_EINVAL;
                goto out;
            }
            else {
                cert = md_cert_make(p, x509);
                rv = APR_SUCCESS;
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, "cert parsed");
            }
        }
    }
out:
    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    return rv;
}

apr_status_t md_cert_chain_read_http(struct apr_array_header_t *chain,
                                     apr_pool_t *p, const struct md_http_response_t *res)
{
    const char *ct;
    apr_off_t blen;
    apr_size_t data_len;
    char *data;
    BIO *bf = NULL;
    apr_status_t rv;
    
    if (APR_SUCCESS != (rv = apr_brigade_length(res->body, 1, &blen))) goto out;
    if (blen > 1024*1024) { /* certs usually are <2k each */
        rv = APR_EINVAL;
        goto out;
    }
    
    data_len = (apr_size_t)blen;
    ct = apr_table_get(res->headers, "Content-Type");
    if (!res->body || !ct) {
        rv = APR_ENOENT;
        goto out;
    }
    else if (!strcmp("application/pem-certificate-chain", ct)) {
        if (APR_SUCCESS == (rv = apr_brigade_pflatten(res->body, &data, &data_len, res->req->pool))) {
            int added = 0;
            md_cert_t *cert;
            
            if (NULL == (bf = BIO_new_mem_buf(data, (int)data_len))) {
                rv = APR_ENOMEM;
                goto out;
            }
            
            while (APR_SUCCESS == (rv = md_cert_read_pem(bf, p, &cert))) {
                APR_ARRAY_PUSH(chain, md_cert_t *) = cert;
                added = 1;
            }
            if (APR_ENOENT == rv && added) {
                rv = APR_SUCCESS;
            }
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, "cert parsed");
    }
    else if (!strcmp("application/pkix-cert", ct)) {
        md_cert_t *cert;
        
        rv = md_cert_read_http(&cert, p, res);
        if (APR_SUCCESS == rv) {
            APR_ARRAY_PUSH(chain, md_cert_t *) = cert;
        }
    }
    else {
        /* unrecongized content type */
        rv = APR_ENOENT;
        goto out;
    }
out:
    if (bf) BIO_free(bf);
    return rv;
}

md_cert_state_t md_cert_state_get(const md_cert_t *cert)
{
    if (cert->x509) {
        return md_cert_is_valid_now(cert)? MD_CERT_VALID : MD_CERT_EXPIRED;
    }
    return MD_CERT_UNKNOWN;
}

apr_status_t md_chain_fappend(struct apr_array_header_t *certs, apr_pool_t *p, const char *fname)
{
    FILE *f;
    apr_status_t rv;
    X509 *x509;
    md_cert_t *cert;
    unsigned long err;
    
    rv = md_util_fopen(&f, fname, "r");
    if (rv == APR_SUCCESS) {
        ERR_clear_error();
        while (NULL != (x509 = PEM_read_X509(f, NULL, NULL, NULL))) {
            cert = md_cert_make(p, x509);
            APR_ARRAY_PUSH(certs, md_cert_t *) = cert;
        }
        fclose(f);
        
        if (0 < (err =  ERR_get_error())
            && !(ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
            /* not the expected one when no more PEM encodings are found */
            rv = APR_EINVAL;
            goto out;
        }
        
        if (certs->nelts == 0) {
            /* Did not find any. This is acceptable unless the file has a certain size
             * when we no longer accept it as empty chain file. Something seems to be
             * wrong then. */
            apr_finfo_t info;
            if (APR_SUCCESS == apr_stat(&info, fname, APR_FINFO_SIZE, p) && info.size >= 1024) {
                /* "Too big for a moon." */
                rv = APR_EINVAL;
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                              "no certificates in non-empty chain %s", fname);
                goto out;
            }
        }        
    }
out:
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, "read chain file %s, found %d certs", 
                  fname, certs? certs->nelts : 0);
    return rv;
}

apr_status_t md_chain_fload(apr_array_header_t **pcerts, apr_pool_t *p, const char *fname)
{
    apr_array_header_t *certs;
    apr_status_t rv;

    certs = apr_array_make(p, 5, sizeof(md_cert_t *));
    rv = md_chain_fappend(certs, p, fname);
    *pcerts = (APR_SUCCESS == rv)? certs : NULL;
    return rv;
}

apr_status_t md_chain_fsave(apr_array_header_t *certs, apr_pool_t *p, 
                            const char *fname, apr_fileperms_t perms)
{
    FILE *f;
    apr_status_t rv;
    const md_cert_t *cert;
    unsigned long err = 0;
    int i;
    
    (void)p;
    rv = md_util_fopen(&f, fname, "w");
    if (rv == APR_SUCCESS) {
        apr_file_perms_set(fname, perms);
        ERR_clear_error();
        for (i = 0; i < certs->nelts; ++i) {
            cert = APR_ARRAY_IDX(certs, i, const md_cert_t *);
            assert(cert->x509);
            
            PEM_write_X509(f, cert->x509);
            
            if (0 < (err = ERR_get_error())) {
                break;
            }
            
        }
        rv = fclose(f);
        if (err) {
            rv = APR_EINVAL;
        }
    }
    return rv;
}

/**************************************************************************************************/
/* certificate signing requests */

static const char *alt_names(apr_array_header_t *domains, apr_pool_t *p)
{
    const char *alts = "", *sep = "", *domain;
    int i;
    
    for (i = 0; i < domains->nelts; ++i) {
        domain = APR_ARRAY_IDX(domains, i, const char *);
        alts = apr_psprintf(p, "%s%sDNS:%s", alts, sep, domain);
        sep = ",";
    }
    return alts;
}

static apr_status_t add_ext(X509 *x, int nid, const char *value, apr_pool_t *p)
{
    X509_EXTENSION *ext = NULL;
    X509V3_CTX ctx;
    apr_status_t rv;

    ERR_clear_error();
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    if (NULL == (ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value))) {
        unsigned long err =  ERR_get_error();
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "add_ext, create, nid=%d value='%s' "
                      "(lib=%d, reason=%d)", nid, value, ERR_GET_LIB(err), ERR_GET_REASON(err)); 
        return APR_EGENERAL;
    }
    
    ERR_clear_error();
    rv = X509_add_ext(x, ext, -1)? APR_SUCCESS : APR_EINVAL;
    if (APR_SUCCESS != rv) {
        unsigned long err =  ERR_get_error();
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "add_ext, add, nid=%d value='%s' "
                      "(lib=%d, reason=%d)", nid, value, ERR_GET_LIB(err), ERR_GET_REASON(err)); 
    }
    X509_EXTENSION_free(ext);
    return rv;
}

static apr_status_t sk_add_alt_names(STACK_OF(X509_EXTENSION) *exts,
                                     apr_array_header_t *domains, apr_pool_t *p)
{
    if (domains->nelts > 0) {
        X509_EXTENSION *x;
        
        x = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char*)alt_names(domains, p));
        if (NULL == x) {
            return APR_EGENERAL;
        }
        sk_X509_EXTENSION_push(exts, x);
    }
    return APR_SUCCESS;
}

#define MD_OID_MUST_STAPLE_NUM          "1.3.6.1.5.5.7.1.24"
#define MD_OID_MUST_STAPLE_SNAME        "tlsfeature"
#define MD_OID_MUST_STAPLE_LNAME        "TLS Feature" 

static int get_must_staple_nid(void)
{
    /* Funny API, the OID for must staple might be configured or
     * might be not. In the second case, we need to add it. But adding
     * when it already is there is an error... */
    int nid = OBJ_txt2nid(MD_OID_MUST_STAPLE_NUM);
    if (NID_undef == nid) {
        nid = OBJ_create(MD_OID_MUST_STAPLE_NUM, 
                         MD_OID_MUST_STAPLE_SNAME, MD_OID_MUST_STAPLE_LNAME);
    }
    return nid;
}

int md_cert_must_staple(const md_cert_t *cert)
{
    /* In case we do not get the NID for it, we treat this as not set. */
    int nid = get_must_staple_nid();
    return ((NID_undef != nid)) && X509_get_ext_by_NID(cert->x509, nid, -1) >= 0;
}

static apr_status_t add_must_staple(STACK_OF(X509_EXTENSION) *exts, const char *name, apr_pool_t *p)
{
    X509_EXTENSION *x;
    int nid;
    
    nid = get_must_staple_nid();
    if (NID_undef == nid) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, 
                      "%s: unable to get NID for v3 must-staple TLS feature", name);
        return APR_ENOTIMPL;
    }
    x = X509V3_EXT_conf_nid(NULL, NULL, nid, (char*)"DER:30:03:02:01:05");
    if (NULL == x) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, 
                      "%s: unable to create x509 extension for must-staple", name);
        return APR_EGENERAL;
    }
    sk_X509_EXTENSION_push(exts, x);
    return APR_SUCCESS;
}

apr_status_t md_cert_req_create(const char **pcsr_der_64, const char *name,
                                apr_array_header_t *domains, int must_staple, 
                                md_pkey_t *pkey, apr_pool_t *p)
{
    const char *s, *csr_der_64 = NULL;
    const unsigned char *domain;
    X509_REQ *csr;
    X509_NAME *n = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    apr_status_t rv;
    md_data_t csr_der;
    int csr_der_len;
    
    assert(domains->nelts > 0);
    
    if (NULL == (csr = X509_REQ_new()) 
        || NULL == (exts = sk_X509_EXTENSION_new_null())
        || NULL == (n = X509_NAME_new())) {
        rv = APR_ENOMEM;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: openssl alloc X509 things", name);
        goto out; 
    }

    /* subject name == first domain */
    domain = APR_ARRAY_IDX(domains, 0, const unsigned char *);
    if (!X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, domain, -1, -1, 0)
        || !X509_REQ_set_subject_name(csr, n)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "%s: REQ name add entry", name);
        rv = APR_EGENERAL; goto out;
    }
    /* collect extensions, such as alt names and must staple */
    if (APR_SUCCESS != (rv = sk_add_alt_names(exts, domains, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: collecting alt names", name);
        rv = APR_EGENERAL; goto out;
    }
    if (must_staple && APR_SUCCESS != (rv = add_must_staple(exts, name, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: you requested that a certificate "
            "is created with the 'must-staple' extension, however the SSL library was "
            "unable to initialized that extension. Please file a bug report on which platform "
            "and with which library this happens. To continue before this problem is resolved, "
            "configure 'MDMustStaple off' for your domains", name);
        rv = APR_EGENERAL; goto out;
    }
    /* add extensions to csr */
    if (sk_X509_EXTENSION_num(exts) > 0 && !X509_REQ_add_extensions(csr, exts)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: adding exts", name);
        rv = APR_EGENERAL; goto out;
    }
    /* add our key */
    if (!X509_REQ_set_pubkey(csr, pkey->pkey)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set pkey in csr", name);
        rv = APR_EGENERAL; goto out;
    }
    /* sign, der encode and base64url encode */
    if (!X509_REQ_sign(csr, pkey->pkey, EVP_sha256())) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: sign csr", name);
        rv = APR_EGENERAL; goto out;
    }
    if ((csr_der_len = i2d_X509_REQ(csr, NULL)) < 0) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: der length", name);
        rv = APR_EGENERAL; goto out;
    }
    csr_der.len = (apr_size_t)csr_der_len;
    s = csr_der.data = apr_pcalloc(p, csr_der.len + 1);
    if (i2d_X509_REQ(csr, (unsigned char**)&s) != csr_der_len) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: csr der enc", name);
        rv = APR_EGENERAL; goto out;
    }
    csr_der_64 = md_util_base64url_encode(&csr_der, p);
    rv = APR_SUCCESS;
    
out:
    if (exts) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    if (csr) {
        X509_REQ_free(csr);
    }
    if (n) {
        X509_NAME_free(n);
    }
    *pcsr_der_64 = (APR_SUCCESS == rv)? csr_der_64 : NULL;
    return rv;
}

static apr_status_t mk_x509(X509 **px, md_pkey_t *pkey, const char *cn,
                            apr_interval_time_t valid_for, apr_pool_t *p)
{
    X509 *x = NULL;
    X509_NAME *n = NULL;
    BIGNUM *big_rnd = NULL;
    ASN1_INTEGER *asn1_rnd = NULL;
    unsigned char rnd[20];
    int days;
    apr_status_t rv;
    
    if (NULL == (x = X509_new()) 
        || NULL == (n = X509_NAME_new())) {
        rv = APR_ENOMEM;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "%s: openssl alloc X509 things", cn);
        goto out; 
    }

    if (APR_SUCCESS != (rv = md_rand_bytes(rnd, sizeof(rnd), p))
        || !(big_rnd = BN_bin2bn(rnd, sizeof(rnd), NULL))
        || !(asn1_rnd = BN_to_ASN1_INTEGER(big_rnd, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "%s: setup random serial", cn);
        rv = APR_EGENERAL; goto out;
    }
    if (!X509_set_serialNumber(x, asn1_rnd)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "%s: set serial number", cn);
        rv = APR_EGENERAL; goto out;
    }
    if (1 != X509_set_version(x, 2L)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "%s: setting x.509v3", cn);
        rv = APR_EGENERAL; goto out;
    }
    /* set common name and issuer */
    if (!X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0)
        || !X509_set_subject_name(x, n)
        || !X509_set_issuer_name(x, n)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "%s: name add entry", cn);
        rv = APR_EGENERAL; goto out;
    }
    /* cert are unconstrained (but not very trustworthy) */
    if (APR_SUCCESS != (rv = add_ext(x, NID_basic_constraints, "CA:FALSE, pathlen:0", p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set basic constraints ext", cn);
        goto out;
    }
    /* add our key */
    if (!X509_set_pubkey(x, pkey->pkey)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set pkey in x509", cn);
        rv = APR_EGENERAL; goto out;
    }
    /* validity */
    days = (int)((apr_time_sec(valid_for) + MD_SECS_PER_DAY - 1)/ MD_SECS_PER_DAY);
    if (!X509_set_notBefore(x, ASN1_TIME_set(NULL, time(NULL)))) {
        rv = APR_EGENERAL; goto out;
    }
    if (!X509_set_notAfter(x, ASN1_TIME_adj(NULL, time(NULL), days, 0))) {
        rv = APR_EGENERAL; goto out;
    }

out:
    *px = (APR_SUCCESS == rv)? x : NULL;
    if (APR_SUCCESS != rv && x) X509_free(x);
    if (big_rnd) BN_free(big_rnd);
    if (asn1_rnd) ASN1_INTEGER_free(asn1_rnd);
    if (n) X509_NAME_free(n);
    return rv;
}

apr_status_t md_cert_self_sign(md_cert_t **pcert, const char *cn, 
                               apr_array_header_t *domains, md_pkey_t *pkey,
                               apr_interval_time_t valid_for, apr_pool_t *p)
{
    X509 *x;
    md_cert_t *cert = NULL;
    apr_status_t rv;
    
    assert(domains);

    if (APR_SUCCESS != (rv = mk_x509(&x, pkey, cn, valid_for, p))) goto out;
    
    /* add the domain as alt name */
    if (APR_SUCCESS != (rv = add_ext(x, NID_subject_alt_name, alt_names(domains, p), p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set alt_name ext", cn);
        goto out;
    }

    /* sign with same key */
    if (!X509_sign(x, pkey->pkey, EVP_sha256())) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: sign x509", cn);
        rv = APR_EGENERAL; goto out;
    }

    cert = md_cert_make(p, x);
    rv = APR_SUCCESS;
    
out:
    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    if (!cert && x) X509_free(x);
    return rv;
}

#define MD_OID_ACME_VALIDATION_NUM          "1.3.6.1.5.5.7.1.31"
#define MD_OID_ACME_VALIDATION_SNAME        "pe-acmeIdentifier"
#define MD_OID_ACME_VALIDATION_LNAME        "ACME Identifier" 

static int get_acme_validation_nid(void)
{
    int nid = OBJ_txt2nid(MD_OID_ACME_VALIDATION_NUM);
    if (NID_undef == nid) {
        nid = OBJ_create(MD_OID_ACME_VALIDATION_NUM, 
                         MD_OID_ACME_VALIDATION_SNAME, MD_OID_ACME_VALIDATION_LNAME);
    }
    return nid;
}

apr_status_t md_cert_make_tls_alpn_01(md_cert_t **pcert, const char *domain, 
                                      const char *acme_id, md_pkey_t *pkey, 
                                      apr_interval_time_t valid_for, apr_pool_t *p)
{
    X509 *x;
    md_cert_t *cert = NULL;
    const char *alts;
    apr_status_t rv;

    if (APR_SUCCESS != (rv = mk_x509(&x, pkey, domain, valid_for, p))) goto out;
    
    /* add the domain as alt name */
    alts = apr_psprintf(p, "DNS:%s", domain);
    if (APR_SUCCESS != (rv = add_ext(x, NID_subject_alt_name, alts, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set alt_name ext", domain);
        goto out;
    }

    if (APR_SUCCESS != (rv = add_ext(x, get_acme_validation_nid(), acme_id, p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set pe-acmeIdentifier", domain);
        goto out;
    }

    /* sign with same key */
    if (!X509_sign(x, pkey->pkey, EVP_sha256())) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: sign x509", domain);
        rv = APR_EGENERAL; goto out;
    }

    cert = md_cert_make(p, x);
    rv = APR_SUCCESS;
    
out:
    if (!cert && x) {
        X509_free(x);
    }
    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    return rv;
}

#define MD_OID_CT_SCTS_NUM          "1.3.6.1.4.1.11129.2.4.2"
#define MD_OID_CT_SCTS_SNAME        "CT-SCTs"
#define MD_OID_CT_SCTS_LNAME        "CT Certificate SCTs" 

#ifndef OPENSSL_NO_CT
static int get_ct_scts_nid(void)
{
    int nid = OBJ_txt2nid(MD_OID_CT_SCTS_NUM);
    if (NID_undef == nid) {
        nid = OBJ_create(MD_OID_CT_SCTS_NUM, 
                         MD_OID_CT_SCTS_SNAME, MD_OID_CT_SCTS_LNAME);
    }
    return nid;
}
#endif

const char *md_nid_get_sname(int nid)
{
    return OBJ_nid2sn(nid);
}

const char *md_nid_get_lname(int nid)
{
    return OBJ_nid2ln(nid);
}

apr_status_t md_cert_get_ct_scts(apr_array_header_t *scts, apr_pool_t *p, const md_cert_t *cert)
{
#ifndef OPENSSL_NO_CT
    int nid, i, idx, critical;
    STACK_OF(SCT) *sct_list;
    SCT *sct_handle;
    md_sct *sct;
    size_t len;
    const char *data;
    
    nid = get_ct_scts_nid();
    if (NID_undef == nid) return APR_ENOTIMPL;

    idx = -1;
    while (1) {
        sct_list = X509_get_ext_d2i(cert->x509, nid, &critical, &idx);
        if (sct_list) {
            for (i = 0; i < sk_SCT_num(sct_list); i++) {
               sct_handle = sk_SCT_value(sct_list, i);
                if (sct_handle) {
                    sct = apr_pcalloc(p, sizeof(*sct));
                    sct->version = SCT_get_version(sct_handle);
                    sct->timestamp = apr_time_from_msec(SCT_get_timestamp(sct_handle));
                    len = SCT_get0_log_id(sct_handle, (unsigned char**)&data);
                    sct->logid = md_data_create(p, data, len);
                    sct->signature_type_nid = SCT_get_signature_nid(sct_handle);
                    len = SCT_get0_signature(sct_handle,  (unsigned char**)&data);
                    sct->signature = md_data_create(p, data, len);
                    
                    APR_ARRAY_PUSH(scts, md_sct*) = sct;
                }
            }
        }
        if (idx < 0) break;
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, "ct_sct, found %d SCT extensions", scts->nelts);
    return APR_SUCCESS;
#else
    (void)scts;
    (void)p;
    (void)cert;
    return APR_ENOTIMPL;
#endif
}
