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
#include <httpd.h>
#include <http_core.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_http.h"
#include "md_time.h"
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

#if (defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x3050000fL)) || (OPENSSL_VERSION_NUMBER < 0x10100000L) 
/* Missing from LibreSSL < 3.5.0 and only available since OpenSSL v1.1.x */
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
    } else {
        return 0;
    }
    return size;
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
#if OPENSSL_VERSION_NUMBER < 0x10002000L || (defined(LIBRESSL_VERSION_NUMBER) && \
                                             LIBRESSL_VERSION_NUMBER < 0x3060000fL)
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
/* OID/NID things */

static int get_nid(const char *num, const char *sname, const char *lname)
{
    /* Funny API, an OID for a feature might be configured or
     * maybe not. In the second case, we need to add it. But adding
     * when it already is there is an error... */
    int nid = OBJ_txt2nid(num);
    if (NID_undef == nid) {
        nid = OBJ_create(num, sname, lname);
    }
    return nid;
}

#define MD_GET_NID(x)  get_nid(MD_OID_##x##_NUM, MD_OID_##x##_SNAME, MD_OID_##x##_LNAME)

/**************************************************************************************************/
/* private keys */

md_pkeys_spec_t *md_pkeys_spec_make(apr_pool_t *p)
{
    md_pkeys_spec_t *pks;
    
    pks = apr_pcalloc(p, sizeof(*pks));
    pks->p = p;
    pks->specs = apr_array_make(p, 2, sizeof(md_pkey_spec_t*));
    return pks;
}

void md_pkeys_spec_add(md_pkeys_spec_t *pks, md_pkey_spec_t *spec)
{
    APR_ARRAY_PUSH(pks->specs, md_pkey_spec_t*) = spec;
}

void md_pkeys_spec_add_default(md_pkeys_spec_t *pks)
{
    md_pkey_spec_t *spec;
    
    spec = apr_pcalloc(pks->p, sizeof(*spec));
    spec->type = MD_PKEY_TYPE_DEFAULT;
    md_pkeys_spec_add(pks, spec);
}

int md_pkeys_spec_contains_rsa(md_pkeys_spec_t *pks)
{
    md_pkey_spec_t *spec;
    int i;
    for (i = 0; i < pks->specs->nelts; ++i) {
        spec = APR_ARRAY_IDX(pks->specs, i, md_pkey_spec_t*);
        if (MD_PKEY_TYPE_RSA == spec->type) return 1;   
    }
    return 0;
}

void md_pkeys_spec_add_rsa(md_pkeys_spec_t *pks, unsigned int bits)
{
    md_pkey_spec_t *spec;
    
    spec = apr_pcalloc(pks->p, sizeof(*spec));
    spec->type = MD_PKEY_TYPE_RSA;
    spec->params.rsa.bits = bits;
    md_pkeys_spec_add(pks, spec);
}

int md_pkeys_spec_contains_ec(md_pkeys_spec_t *pks, const char *curve)
{
    md_pkey_spec_t *spec;
    int i;
    for (i = 0; i < pks->specs->nelts; ++i) {
        spec = APR_ARRAY_IDX(pks->specs, i, md_pkey_spec_t*);
        if (MD_PKEY_TYPE_EC == spec->type 
            && !apr_strnatcasecmp(curve, spec->params.ec.curve)) return 1;   
    }
    return 0;
}

void md_pkeys_spec_add_ec(md_pkeys_spec_t *pks, const char *curve)
{
    md_pkey_spec_t *spec;
    
    spec = apr_pcalloc(pks->p, sizeof(*spec));
    spec->type = MD_PKEY_TYPE_EC;
    spec->params.ec.curve = apr_pstrdup(pks->p, curve);
    md_pkeys_spec_add(pks, spec);
}

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
            case MD_PKEY_TYPE_EC:
                md_json_sets("EC", json, MD_KEY_TYPE, NULL);
                if (spec->params.ec.curve) {
                    md_json_sets(spec->params.ec.curve, json, MD_KEY_CURVE, NULL);
                }
                break;
            default:
                md_json_sets("Unsupported", json, MD_KEY_TYPE, NULL);
                break;
        }
    }
    return json;    
}

static apr_status_t spec_to_json(void *value, md_json_t *json, apr_pool_t *p, void *baton)
{
    md_json_t *jspec;
    
    (void)baton;
    jspec = md_pkey_spec_to_json((md_pkey_spec_t*)value, p);
    return md_json_setj(jspec, json, NULL);
}

md_json_t *md_pkeys_spec_to_json(const md_pkeys_spec_t *pks, apr_pool_t *p)
{
    md_json_t *j;
    
    if (pks->specs->nelts == 1) {
        return md_pkey_spec_to_json(md_pkeys_spec_get(pks, 0), p);
    }
    j = md_json_create(p);
    md_json_seta(pks->specs, spec_to_json, (void*)pks, j, "specs", NULL);
    return md_json_getj(j, "specs", NULL);
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
        else if (!apr_strnatcasecmp("EC", s)) {
            spec->type = MD_PKEY_TYPE_EC;
            s = md_json_gets(json, MD_KEY_CURVE, NULL);
            if (s) {
                spec->params.ec.curve = apr_pstrdup(p, s);
            }
            else {
                spec->params.ec.curve = NULL;
            }
        }
    }
    return spec;
}

static apr_status_t spec_from_json(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton)
{
    (void)baton;
    *pvalue = md_pkey_spec_from_json(json, p);
    return APR_SUCCESS;
}

md_pkeys_spec_t *md_pkeys_spec_from_json(struct md_json_t *json, apr_pool_t *p)
{
    md_pkeys_spec_t *pks;
    md_pkey_spec_t *spec;
    
    pks = md_pkeys_spec_make(p);
    if (md_json_is(MD_JSON_TYPE_ARRAY, json, NULL)) {
        md_json_geta(pks->specs, spec_from_json, pks, json, NULL);
    }
    else {
        spec = md_pkey_spec_from_json(json, p);
        md_pkeys_spec_add(pks, spec);
    }
    return pks;
}

static int pkey_spec_eq(md_pkey_spec_t *s1, md_pkey_spec_t *s2)
{
    if (s1 == s2) {
        return 1;
    }
    if (s1 && s2 && s1->type == s2->type) {
        switch (s1->type) {
            case MD_PKEY_TYPE_DEFAULT:
                return 1;
            case MD_PKEY_TYPE_RSA:
                if (s1->params.rsa.bits == s2->params.rsa.bits) {
                    return 1;
                }
                break;
            case MD_PKEY_TYPE_EC:
                if (s1->params.ec.curve == s2->params.ec.curve) {
                    return 1;
                }
                else if (!s1->params.ec.curve || !s2->params.ec.curve) {
                    return 0;
                }
                return !strcmp(s1->params.ec.curve, s2->params.ec.curve);
        }
    }
    return 0;
}

int md_pkeys_spec_eq(md_pkeys_spec_t *pks1, md_pkeys_spec_t *pks2)
{
    int i;
    
    if (pks1 == pks2) {
        return 1;
    }
    if (pks1 && pks2 && pks1->specs->nelts == pks2->specs->nelts) {
        for(i = 0; i < pks1->specs->nelts; ++i) {
            if (!pkey_spec_eq(APR_ARRAY_IDX(pks1->specs, i, md_pkey_spec_t *),
                              APR_ARRAY_IDX(pks2->specs, i, md_pkey_spec_t *))) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

static md_pkey_spec_t *pkey_spec_clone(apr_pool_t *p, md_pkey_spec_t *spec)
{
    md_pkey_spec_t *nspec;
    
    nspec = apr_pcalloc(p, sizeof(*nspec));
    nspec->type = spec->type;
    switch (spec->type) {
        case MD_PKEY_TYPE_DEFAULT:
            break;
        case MD_PKEY_TYPE_RSA:
            nspec->params.rsa.bits = spec->params.rsa.bits;
            break;
        case MD_PKEY_TYPE_EC:
            nspec->params.ec.curve = apr_pstrdup(p, spec->params.ec.curve);
            break;
    }
    return nspec;
}

const char *md_pkey_spec_name(const md_pkey_spec_t *spec)
{
    if (!spec) return "rsa";
    switch (spec->type) {
        case MD_PKEY_TYPE_DEFAULT:
        case MD_PKEY_TYPE_RSA:
            return "rsa";
        case MD_PKEY_TYPE_EC:
            return spec->params.ec.curve;
    }
    return "unknown";
}

int md_pkeys_spec_is_empty(const md_pkeys_spec_t *pks)
{
    return NULL == pks || 0 == pks->specs->nelts;
}

md_pkeys_spec_t *md_pkeys_spec_clone(apr_pool_t *p, const md_pkeys_spec_t *pks)
{
    md_pkeys_spec_t *npks = NULL;
    md_pkey_spec_t *spec;
    int i;
    
    if (pks && pks->specs->nelts > 0) {
        npks = apr_pcalloc(p, sizeof(*npks));
        npks->specs = apr_array_make(p, pks->specs->nelts, sizeof(md_pkey_spec_t*));
        for (i = 0; i < pks->specs->nelts; ++i) {
            spec = APR_ARRAY_IDX(pks->specs, i, md_pkey_spec_t*);
            APR_ARRAY_PUSH(npks->specs, md_pkey_spec_t*) = pkey_spec_clone(p, spec);
        }
    }
    return npks;
}

int md_pkeys_spec_count(const md_pkeys_spec_t *pks)
{
    return md_pkeys_spec_is_empty(pks)? 1 : pks->specs->nelts;
}

static md_pkey_spec_t PkeySpecDef = { MD_PKEY_TYPE_DEFAULT, {{ 0 }} };

md_pkey_spec_t *md_pkeys_spec_get(const md_pkeys_spec_t *pks, int index)
{
    if (md_pkeys_spec_is_empty(pks)) {
        return index == 1? &PkeySpecDef : NULL;
    }
    else if (pks && index >= 0 && index < pks->specs->nelts) {
        return APR_ARRAY_IDX(pks->specs, index, md_pkey_spec_t*);
    }
    return NULL;
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
    apr_status_t rv = APR_SUCCESS;
    passwd_ctx ctx;
    unsigned long err;
    int i;
    
    if (!bio) {
        return APR_ENOMEM;
    }
    if (pass_len > INT_MAX) {
        rv = APR_EINVAL;
        goto cleanup;
    }
    if (pass && pass_len > 0) {
        ctx.pass_phrase = pass;
        ctx.pass_len = (int)pass_len;
        cb = pem_passwd;
        cb_baton = &ctx;
        cipher = EVP_aes_256_cbc();
        if (!cipher) {
            rv = APR_ENOTIMPL;
            goto cleanup;
        }
    }
    
    ERR_clear_error();
#if 1
    if (!PEM_write_bio_PKCS8PrivateKey(bio, pkey->pkey, cipher, NULL, 0, cb, cb_baton)) {
#else 
    if (!PEM_write_bio_PrivateKey(bio, pkey->pkey, cipher, NULL, 0, cb, cb_baton)) {
#endif
        err = ERR_get_error();
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "PEM_write key: %ld %s", 
                      err, ERR_error_string(err, NULL)); 
        rv = APR_EINVAL;
        goto cleanup;
    }

    md_data_null(buf);
    i = BIO_pending(bio);
    if (i > 0) {
        buf->data = apr_palloc(p, (apr_size_t)i);
        i = BIO_read(bio, (char*)buf->data, i);
        buf->len = (apr_size_t)i;
    }

cleanup:
    BIO_free(bio);
    return rv;
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

apr_status_t md_pkey_read_http(md_pkey_t **ppkey, apr_pool_t *pool,
                               const struct md_http_response_t *res)
{
    apr_status_t rv;
    apr_off_t data_len;
    char *pem_data;
    apr_size_t pem_len;
    md_pkey_t *pkey;
    BIO *bf;
    passwd_ctx ctx;

    rv = apr_brigade_length(res->body, 1, &data_len);
    if (APR_SUCCESS != rv) goto leave;
    if (data_len > 1024*1024) { /* certs usually are <2k each */
        rv = APR_EINVAL;
        goto leave;
    }
    rv = apr_brigade_pflatten(res->body, &pem_data, &pem_len, res->req->pool);
    if (APR_SUCCESS != rv) goto leave;

    if (NULL == (bf = BIO_new_mem_buf(pem_data, (int)pem_len))) {
        rv = APR_ENOMEM;
        goto leave;
    }
    pkey = make_pkey(pool);
    ctx.pass_phrase = NULL;
    ctx.pass_len = 0;
    ERR_clear_error();
    pkey->pkey = PEM_read_bio_PrivateKey(bf, NULL, NULL, &ctx);
    BIO_free(bf);

    if (pkey->pkey == NULL) {
        unsigned long err = ERR_get_error();
        rv = APR_EINVAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, pool,
                      "error loading pkey from http response: %s",
                      ERR_error_string(err, NULL));
        goto leave;
    }
    rv = APR_SUCCESS;
    apr_pool_cleanup_register(pool, pkey, pkey_cleanup, apr_pool_cleanup_null);

leave:
    *ppkey = (APR_SUCCESS == rv)? pkey : NULL;
    return rv;
}

/* Determine the message digest used for signing with the given private key. 
 */
static const EVP_MD *pkey_get_MD(md_pkey_t *pkey)
{
    switch (EVP_PKEY_id(pkey->pkey)) {
#ifdef NID_ED25519
    case NID_ED25519:
        return NULL;
#endif
#ifdef NID_ED448
    case NID_ED448:
        return NULL;
#endif
    default:
        return EVP_sha256();
    }
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

static apr_status_t check_EC_curve(int nid, apr_pool_t *p) {
    EC_builtin_curve *curves = NULL;
    size_t nc, i;
    int rv = APR_ENOENT;
    
    nc = EC_get_builtin_curves(NULL, 0);
    if (NULL == (curves = OPENSSL_malloc(sizeof(*curves) * nc)) ||
        nc != EC_get_builtin_curves(curves, nc)) {
        rv = APR_EGENERAL;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, 
                      "error looking up OpenSSL builtin EC curves"); 
        goto leave;
    }
    for (i = 0; i < nc; ++i) {
        if (nid == curves[i].nid) {
            rv = APR_SUCCESS;
            break;
        }
    }
leave:
    OPENSSL_free(curves);
    return rv;
}

static apr_status_t gen_ec(md_pkey_t **ppkey, apr_pool_t *p, const char *curve)
{
    EVP_PKEY_CTX *ctx = NULL;
    apr_status_t rv;
    int curve_nid = NID_undef;

    /* 1. Convert the cure into its registered identifier. Curves can be known under
     *    different names.
     * 2. Determine, if the curve is supported by OpenSSL (or whatever is linked).
     * 3. Generate the key, respecting the specific quirks some curves require.
     */
    curve_nid = EC_curve_nist2nid(curve);
    /* In case this fails, try some names from other standards, like SECG */
#ifdef NID_secp384r1
    if (NID_undef == curve_nid && !apr_strnatcasecmp("secp384r1", curve)) {
        curve_nid = NID_secp384r1;
        curve = EC_curve_nid2nist(curve_nid);
    }
#endif
#ifdef NID_X9_62_prime256v1
    if (NID_undef == curve_nid && !apr_strnatcasecmp("secp256r1", curve)) {
        curve_nid = NID_X9_62_prime256v1;
        curve = EC_curve_nid2nist(curve_nid);
    }
#endif
#ifdef NID_X9_62_prime192v1
    if (NID_undef == curve_nid && !apr_strnatcasecmp("secp192r1", curve)) {
        curve_nid = NID_X9_62_prime192v1;
        curve = EC_curve_nid2nist(curve_nid);
    }
#endif
#if defined(NID_X25519) && (!defined(LIBRESSL_VERSION_NUMBER) || \
                            LIBRESSL_VERSION_NUMBER >= 0x3070000fL)
    if (NID_undef == curve_nid && !apr_strnatcasecmp("X25519", curve)) {
        curve_nid = NID_X25519;
        curve = EC_curve_nid2nist(curve_nid);
    }
#endif
    if (NID_undef == curve_nid) {
        /* OpenSSL object/curve names */
        curve_nid = OBJ_sn2nid(curve);
    }
    if (NID_undef == curve_nid) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "ec curve unknown: %s", curve); 
        rv = APR_ENOTIMPL; goto leave;
    }

    *ppkey = make_pkey(p);
    switch (curve_nid) {

#if defined(NID_X25519) && (!defined(LIBRESSL_VERSION_NUMBER) || \
                            LIBRESSL_VERSION_NUMBER >= 0x3070000fL)
    case NID_X25519:
        /* no parameters */
        if (NULL == (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL))
            || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, 
                          "error generate EC key for group: %s", curve); 
            rv = APR_EGENERAL; goto leave;
        }
        rv = APR_SUCCESS;
        break;
#endif

#if defined(NID_X448) && !defined(LIBRESSL_VERSION_NUMBER)
    case NID_X448:
        /* no parameters */
        if (NULL == (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL))
            || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, 
                          "error generate EC key for group: %s", curve); 
            rv = APR_EGENERAL; goto leave;
        }
        rv = APR_SUCCESS;
        break;
#endif

    default:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (APR_SUCCESS != (rv = check_EC_curve(curve_nid, p))) goto leave;
        if (NULL == (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
            || EVP_PKEY_paramgen_init(ctx) <= 0 
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0
            || EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <= 0 
            || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p, 
                          "error generate EC key for group: %s", curve); 
            rv = APR_EGENERAL; goto leave;
        }
#else
        if (APR_SUCCESS != (rv = check_EC_curve(curve_nid, p))) goto leave;
        if (NULL == (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))
            || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_CTX_ctrl_str(ctx, "ec_paramgen_curve", curve) <= 0
            || EVP_PKEY_keygen(ctx, &(*ppkey)->pkey) <= 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, 0, p,
                          "error generate EC key for group: %s", curve);
            rv = APR_EGENERAL; goto leave;
        }
#endif
        rv = APR_SUCCESS;
        break;
    }
    
leave:
    if (APR_SUCCESS != rv) *ppkey = NULL;
    EVP_PKEY_CTX_free(ctx);
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
        case MD_PKEY_TYPE_EC:
            return gen_ec(ppkey, p, spec->params.ec.curve);
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

        md_data_pinit(&buffer, (apr_size_t)BN_num_bytes(b), p);
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

    md_data_pinit(&buffer, (apr_size_t)EVP_PKEY_size(pkey->pkey), p);
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

    digest = md_data_pmake(EVP_MAX_MD_SIZE, p);
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

apr_status_t md_crypt_hmac64(const char **pmac64, const md_data_t *hmac_key,
                             apr_pool_t *p, const char *d, size_t dlen)
{
    const char *mac64 = NULL;
    unsigned char *s;
    unsigned int digest_len = 0;
    md_data_t *digest;
    apr_status_t rv = APR_SUCCESS;

    digest = md_data_pmake(EVP_MAX_MD_SIZE, p);
    s = HMAC(EVP_sha256(), (const unsigned char*)hmac_key->data, (int)hmac_key->len,
             (const unsigned char*)d, (size_t)dlen,
             (unsigned char*)digest->data, &digest_len);
    if (!s) {
        rv = APR_EINVAL;
        goto cleanup;
    }
    digest->len = digest_len;
    mac64 = md_util_base64url_encode(digest, p);

cleanup:
    *pmac64 = (APR_SUCCESS == rv)? mac64 : NULL;
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

int md_certs_are_equal(const md_cert_t *a, const md_cert_t *b)
{
    return X509_cmp(a->x509, b->x509) == 0;
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

md_timeperiod_t md_cert_get_valid(const md_cert_t *cert)
{
    md_timeperiod_t p;
    p.start = md_cert_get_not_before(cert);
    p.end = md_cert_get_not_after(cert);
    return p;
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
        const unsigned char *ip;
        int len;
        
        names = apr_array_make(p, sk_GENERAL_NAME_num(xalt_names), sizeof(char *));
        for (i = 0; i < sk_GENERAL_NAME_num(xalt_names); ++i) {
            cval = sk_GENERAL_NAME_value(xalt_names, i);
            switch (cval->type) {
                case GEN_DNS:
                case GEN_URI:
                    ASN1_STRING_to_UTF8(&buf, cval->d.ia5);
                    APR_ARRAY_PUSH(names, const char *) = apr_pstrdup(p, (char*)buf);
                    OPENSSL_free(buf);
                    break;
                case GEN_IPADD:
                    len = ASN1_STRING_length(cval->d.iPAddress);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                    ip = ASN1_STRING_data(cval->d.iPAddress);
#else
                    ip = ASN1_STRING_get0_data(cval->d.iPAddress);
#endif
                    if (len ==  4)      /* IPv4 address */
                        APR_ARRAY_PUSH(names, const char *) = apr_psprintf(p, "%u.%u.%u.%u",
                                                                           ip[0], ip[1], ip[2], ip[3]);
                    else if (len == 16) /* IPv6 address */
                        APR_ARRAY_PUSH(names, const char *) = apr_psprintf(p, "%02x%02x%02x%02x:"
                                                                              "%02x%02x%02x%02x:"
                                                                              "%02x%02x%02x%02x:"
                                                                              "%02x%02x%02x%02x",
                                                                           ip[0],  ip[1],  ip[2],  ip[3],
                                                                           ip[4],  ip[5],  ip[6],  ip[7],
                                                                           ip[8],  ip[9],  ip[10], ip[11],
                                                                           ip[12], ip[13], ip[14], ip[15]);
                    else {
                        ; /* Unknown address type - Log?  Assert? */
                    }
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

    md_data_null(&buffer);
    if (APR_SUCCESS == (rv = cert_to_buffer(&buffer, cert, p))) {
        return md_util_freplace(fname, perms, p, fwrite_buffer, &buffer); 
    }
    return rv;
}

apr_status_t md_cert_to_base64url(const char **ps64, const md_cert_t *cert, apr_pool_t *p)
{
    md_data_t buffer;
    apr_status_t rv;

    md_data_null(&buffer);
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

    digest = md_data_pmake(EVP_MAX_MD_SIZE, p);
    X509_digest(cert->x509, EVP_sha256(), (unsigned char*)digest->data, &dlen);
    digest->len = dlen;

    *pdigest = digest;
    return APR_SUCCESS;
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
    apr_status_t rv = APR_ENOENT;
    
    ERR_clear_error();
    x509 = PEM_read_bio_X509(bf, NULL, NULL, NULL);
    if (x509 == NULL) goto cleanup;
    cert = md_cert_make(p, x509);
    rv = APR_SUCCESS;
cleanup:
    *pcert = (APR_SUCCESS == rv)? cert : NULL;
    return rv;
}

apr_status_t md_cert_read_chain(apr_array_header_t *chain, apr_pool_t *p,
                                const char *pem, apr_size_t pem_len)
{
    BIO *bf = NULL;
    apr_status_t rv = APR_SUCCESS;
    md_cert_t *cert;
    int added = 0;

    if (NULL == (bf = BIO_new_mem_buf(pem, (int)pem_len))) {
        rv = APR_ENOMEM;
        goto cleanup;
    }
    while (APR_SUCCESS == (rv = md_cert_read_pem(bf, chain->pool, &cert))) {
        APR_ARRAY_PUSH(chain, md_cert_t *) = cert;
        added = 1;
    }
    if (APR_ENOENT == rv && added) {
        rv = APR_SUCCESS;
    }

cleanup:
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, p, "read chain with %d certs", chain->nelts);
    if (bf) BIO_free(bf);
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
    ct = md_util_parse_ct(res->req->pool, ct);
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
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, p,
                    "parsing cert from content-type=%s, content-length=%ld", ct, (long)data_len);
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
    const char *ct = NULL;
    apr_off_t blen;
    apr_size_t data_len = 0;
    char *data;
    md_cert_t *cert;
    apr_status_t rv = APR_ENOENT;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p,
        "chain_read, processing %d response", res->status);
    if (APR_SUCCESS != (rv = apr_brigade_length(res->body, 1, &blen))) goto cleanup;
    if (blen > 1024*1024) { /* certs usually are <2k each */
        rv = APR_EINVAL;
        goto cleanup;
    }
    
    data_len = (apr_size_t)blen;
    ct = apr_table_get(res->headers, "Content-Type");
    if (!res->body || !ct) goto cleanup;
    ct = md_util_parse_ct(res->req->pool, ct);
    if (!strcmp("application/pkix-cert", ct)) {
        rv = md_cert_read_http(&cert, p, res);
        if (APR_SUCCESS != rv) goto cleanup;
        APR_ARRAY_PUSH(chain, md_cert_t *) = cert;
    }
    else if (!strcmp("application/pem-certificate-chain", ct)
        || !strncmp("text/plain", ct, sizeof("text/plain")-1)) {
        /* Some servers seem to think 'text/plain' is sufficient, see #232 */
        rv = apr_brigade_pflatten(res->body, &data, &data_len, res->req->pool);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = md_cert_read_chain(chain, res->req->pool, data, data_len);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p,
            "attempting to parse certificates from unrecognized content-type: %s", ct);
        rv = apr_brigade_pflatten(res->body, &data, &data_len, res->req->pool);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = md_cert_read_chain(chain, res->req->pool, data, data_len);
        if (APR_SUCCESS == rv && chain->nelts == 0) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p,
                "certificate chain response did not contain any certificates "
                "(suspicious content-type: %s)", ct);
            rv = APR_ENOENT;
        }
    }
cleanup:
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, p,
        "parsed certs from content-type=%s, content-length=%ld", ct, (long)data_len);
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

int md_cert_must_staple(const md_cert_t *cert)
{
    /* In case we do not get the NID for it, we treat this as not set. */
    int nid = MD_GET_NID(MUST_STAPLE);
    return ((NID_undef != nid)) && X509_get_ext_by_NID(cert->x509, nid, -1) >= 0;
}

static apr_status_t add_must_staple(STACK_OF(X509_EXTENSION) *exts, const char *name, apr_pool_t *p)
{
    X509_EXTENSION *x;
    int nid;
    
    nid = MD_GET_NID(MUST_STAPLE);
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
    md_data_null(&csr_der);

    if (NULL == (csr = X509_REQ_new()) 
        || NULL == (exts = sk_X509_EXTENSION_new_null())
        || NULL == (n = X509_NAME_new())) {
        rv = APR_ENOMEM;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: openssl alloc X509 things", name);
        goto out; 
    }

    /* subject name == first domain */
    domain = APR_ARRAY_IDX(domains, 0, const unsigned char *);
    /* Do not set the domain in the CN if it is longer than 64 octets.
     * Instead, let the CA choose a 'proper' name. At the moment (2021-01), LE will
     * inspect all SAN names and use one < 64 chars if it can be found. It will fail
     * otherwise.
     * The reason we do not check this beforehand is that the restrictions on CNs
     * are in flux. They used to be authoritative, now browsers no longer do that, but
     * no one wants to hand out a cert with "google.com" as CN either. So, we leave
     * it for the CA to decide if and how it hands out a cert for this or fails.
     * This solves issue where the name is too long, see #227 */
    if (strlen((const char*)domain) < 64
        && (!X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, domain, -1, -1, 0)
            || !X509_REQ_set_subject_name(csr, n))) {
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
    if (!X509_REQ_sign(csr, pkey->pkey, pkey_get_MD(pkey))) {
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
    if (APR_SUCCESS != (rv = add_ext(x, NID_basic_constraints, "critical,CA:FALSE", p))) {
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

    /* keyUsage, ExtendedKeyUsage */

    if (APR_SUCCESS != (rv = add_ext(x, NID_key_usage, "critical,digitalSignature", p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set keyUsage", cn);
        goto out;
    }
    if (APR_SUCCESS != (rv = add_ext(x, NID_ext_key_usage, "serverAuth", p))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set extKeyUsage", cn);
        goto out;
    }

    /* sign with same key */
    if (!X509_sign(x, pkey->pkey, pkey_get_MD(pkey))) {
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

    if (APR_SUCCESS != (rv = mk_x509(&x, pkey, "tls-alpn-01-challenge", valid_for, p))) goto out;
    
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
    if (!X509_sign(x, pkey->pkey, pkey_get_MD(pkey))) {
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
                    sct->logid = md_data_make_pcopy(p, data, len);
                    sct->signature_type_nid = SCT_get_signature_nid(sct_handle);
                    len = SCT_get0_signature(sct_handle,  (unsigned char**)&data);
                    sct->signature = md_data_make_pcopy(p, data, len);
                    
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

apr_status_t md_cert_get_ocsp_responder_url(const char **purl, apr_pool_t *p, const md_cert_t *cert)
{
    STACK_OF(OPENSSL_STRING) *ssk;
    apr_status_t rv = APR_SUCCESS;
    const char *url = NULL;

    ssk = X509_get1_ocsp(md_cert_get_X509(cert));
    if (!ssk) {
        rv = APR_ENOENT;
        goto cleanup;
    }
    url = apr_pstrdup(p, sk_OPENSSL_STRING_value(ssk, 0));
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, p, "ocsp responder found '%s'", url);

cleanup:
    if (ssk) X509_email_free(ssk);
    *purl = url;
    return rv;
}

apr_status_t md_check_cert_and_pkey(struct apr_array_header_t *certs, md_pkey_t *pkey)
{
    const md_cert_t *cert;

    if (certs->nelts == 0) {
        return APR_ENOENT;
    }

    cert = APR_ARRAY_IDX(certs, 0, const md_cert_t*);

    if (1 != X509_check_private_key(cert->x509, pkey->pkey)) {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}
