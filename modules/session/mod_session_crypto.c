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

#include "mod_session.h"
#include "apu_version.h"
#include "apr_base64.h"                /* for apr_base64_decode et al */
#include "apr_lib.h"
#include "apr_md5.h"
#include "apr_strings.h"
#include "http_log.h"
#include "http_core.h"

#if APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION < 4

#error session_crypto_module requires APU v1.4.0 or later

#elif APU_HAVE_CRYPTO == 0

#error Crypto support must be enabled in APR

#else

#include "apr_crypto.h"                /* for apr_*_crypt et al */

#define CRYPTO_KEY "session_crypto_context"

module AP_MODULE_DECLARE_DATA session_crypto_module;

/**
 * Structure to carry the per-dir session config.
 */
typedef struct {
    apr_array_header_t *passphrases;
    int passphrases_set;
    const char *cipher;
    int cipher_set;
} session_crypto_dir_conf;

/**
 * Structure to carry the server wide session config.
 */
typedef struct {
    const char *library;
    const char *params;
    int library_set;
} session_crypto_conf;

/* Wrappers around apr_siphash24() and apr_crypto_equals(),
 * available in APU-1.6/APR-2.0 only.
 */
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 6)

#include "apr_siphash.h"

#define AP_SIPHASH_DSIZE    APR_SIPHASH_DSIZE
#define AP_SIPHASH_KSIZE    APR_SIPHASH_KSIZE
#define ap_siphash24_auth   apr_siphash24_auth

#define ap_crypto_equals    apr_crypto_equals

#else

#define AP_SIPHASH_DSIZE    8
#define AP_SIPHASH_KSIZE    16

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

#define U8TO64_LE(p) \
    (((apr_uint64_t)((p)[0])      ) | \
     ((apr_uint64_t)((p)[1]) <<  8) | \
     ((apr_uint64_t)((p)[2]) << 16) | \
     ((apr_uint64_t)((p)[3]) << 24) | \
     ((apr_uint64_t)((p)[4]) << 32) | \
     ((apr_uint64_t)((p)[5]) << 40) | \
     ((apr_uint64_t)((p)[6]) << 48) | \
     ((apr_uint64_t)((p)[7]) << 56))

#define U64TO8_LE(p, v) \
do { \
    (p)[0] = (unsigned char)((v)      ); \
    (p)[1] = (unsigned char)((v) >>  8); \
    (p)[2] = (unsigned char)((v) >> 16); \
    (p)[3] = (unsigned char)((v) >> 24); \
    (p)[4] = (unsigned char)((v) >> 32); \
    (p)[5] = (unsigned char)((v) >> 40); \
    (p)[6] = (unsigned char)((v) >> 48); \
    (p)[7] = (unsigned char)((v) >> 56); \
} while (0)

#define SIPROUND() \
do { \
    v0 += v1; v1=ROTL64(v1,13); v1 ^= v0; v0=ROTL64(v0,32); \
    v2 += v3; v3=ROTL64(v3,16); v3 ^= v2; \
    v0 += v3; v3=ROTL64(v3,21); v3 ^= v0; \
    v2 += v1; v1=ROTL64(v1,17); v1 ^= v2; v2=ROTL64(v2,32); \
} while(0)

static apr_uint64_t ap_siphash24(const void *src, apr_size_t len,
                                 const unsigned char key[AP_SIPHASH_KSIZE])
{
    const unsigned char *ptr, *end;
    apr_uint64_t v0, v1, v2, v3, m;
    apr_uint64_t k0, k1;
    unsigned int rem;

    k0 = U8TO64_LE(key + 0);
    k1 = U8TO64_LE(key + 8);
    v3 = k1 ^ (apr_uint64_t)0x7465646279746573ULL;
    v2 = k0 ^ (apr_uint64_t)0x6c7967656e657261ULL;
    v1 = k1 ^ (apr_uint64_t)0x646f72616e646f6dULL;
    v0 = k0 ^ (apr_uint64_t)0x736f6d6570736575ULL;

    rem = (unsigned int)(len & 0x7);
    for (ptr = src, end = ptr + len - rem; ptr < end; ptr += 8) {
        m = U8TO64_LE(ptr);
        v3 ^= m;
        SIPROUND();
        SIPROUND();
        v0 ^= m;
    }
    m = (apr_uint64_t)(len & 0xff) << 56;
    switch (rem) {
        case 7: m |= (apr_uint64_t)ptr[6] << 48;
        case 6: m |= (apr_uint64_t)ptr[5] << 40;
        case 5: m |= (apr_uint64_t)ptr[4] << 32;
        case 4: m |= (apr_uint64_t)ptr[3] << 24;
        case 3: m |= (apr_uint64_t)ptr[2] << 16;
        case 2: m |= (apr_uint64_t)ptr[1] << 8;
        case 1: m |= (apr_uint64_t)ptr[0];
        case 0: break;
    }
    v3 ^= m;
    SIPROUND();
    SIPROUND();
    v0 ^= m;

    v2 ^= 0xff;
    SIPROUND();
    SIPROUND();
    SIPROUND();
    SIPROUND();

    return v0 ^ v1 ^ v2 ^ v3;
}

static void ap_siphash24_auth(unsigned char out[AP_SIPHASH_DSIZE],
                              const void *src, apr_size_t len,
                              const unsigned char key[AP_SIPHASH_KSIZE])
{
    apr_uint64_t h;
    h = ap_siphash24(src, len, key);
    U64TO8_LE(out, h);
}

static int ap_crypto_equals(const void *buf1, const void *buf2,
                            apr_size_t size)
{
    const unsigned char *p1 = buf1;
    const unsigned char *p2 = buf2;
    unsigned char diff = 0;
    apr_size_t i;

    for (i = 0; i < size; ++i) {
        diff |= p1[i] ^ p2[i];
    }

    return 1 & ((diff - 1) >> 8);
}

#endif

static void compute_auth(const void *src, apr_size_t len,
                         const char *passphrase, apr_size_t passlen,
                         unsigned char auth[AP_SIPHASH_DSIZE])
{
    unsigned char key[APR_MD5_DIGESTSIZE];

    /* XXX: if we had a way to get the raw bytes from an apr_crypto_key_t
     *      we could use them directly (not available in APR-1.5.x).
     * MD5 is 128bit too, so use it to get a suitable siphash key
     * from the passphrase.
     */
    apr_md5(key, passphrase, passlen);

    ap_siphash24_auth(auth, src, len, key);
}

/**
 * Initialise the encryption as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t crypt_init(request_rec *r,
        const apr_crypto_t *f, apr_crypto_block_key_type_e **cipher,
        session_crypto_dir_conf * dconf)
{
    apr_status_t res;
    apr_hash_t *ciphers;

    res = apr_crypto_get_block_key_types(&ciphers, f);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01823)
                "no ciphers returned by APR. "
                "session encryption not possible");
        return res;
    }

    *cipher = apr_hash_get(ciphers, dconf->cipher, APR_HASH_KEY_STRING);
    if (!(*cipher)) {
        apr_hash_index_t *hi;
        const void *key;
        apr_ssize_t klen;
        int sum = 0;
        int offset = 0;
        char *options = NULL;

        for (hi = apr_hash_first(r->pool, ciphers); hi; hi = apr_hash_next(hi)) {
            apr_hash_this(hi, NULL, &klen, NULL);
            sum += klen + 2;
        }
        for (hi = apr_hash_first(r->pool, ciphers); hi; hi = apr_hash_next(hi)) {
            apr_hash_this(hi, &key, &klen, NULL);
            if (!options) {
                options = apr_palloc(r->pool, sum + 1);
            }
            else {
                options[offset++] = ',';
                options[offset++] = ' ';
            }
            strncpy(options + offset, key, klen);
            offset += klen;
        }
        options[offset] = 0;

        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01824)
                "cipher '%s' not recognised by crypto driver. "
                "session encryption not possible, options: %s", dconf->cipher, options);

        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

/**
 * Encrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t encrypt_string(request_rec * r, const apr_crypto_t *f,
        session_crypto_dir_conf *dconf, const char *in, char **out)
{
    apr_status_t res;
    apr_crypto_key_t *key = NULL;
    apr_size_t ivSize = 0;
    apr_crypto_block_t *block = NULL;
    unsigned char *encrypt = NULL;
    unsigned char *combined = NULL;
    apr_size_t encryptlen, tlen, combinedlen;
    char *base64;
    apr_size_t blockSize = 0;
    const unsigned char *iv = NULL;
    apr_uuid_t salt;
    apr_crypto_block_key_type_e *cipher;
    const char *passphrase;
    apr_size_t passlen;

    /* use a uuid as a salt value, and prepend it to our result */
    apr_uuid_get(&salt);
    res = crypt_init(r, f, &cipher, dconf);
    if (res != APR_SUCCESS) {
        return res;
    }

    /* encrypt using the first passphrase in the list */
    passphrase = APR_ARRAY_IDX(dconf->passphrases, 0, const char *);
    passlen = strlen(passphrase);
    res = apr_crypto_passphrase(&key, &ivSize, passphrase, passlen,
            (unsigned char *) (&salt), sizeof(apr_uuid_t),
            *cipher, APR_MODE_CBC, 1, 4096, f, r->pool);
    if (APR_STATUS_IS_ENOKEY(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01825)
                "the passphrase '%s' was empty", passphrase);
    }
    if (APR_STATUS_IS_EPADDING(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01826)
                "padding is not supported for cipher");
    }
    if (APR_STATUS_IS_EKEYTYPE(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01827)
                "the key type is not known");
    }
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01828)
                "encryption could not be configured.");
        return res;
    }

    res = apr_crypto_block_encrypt_init(&block, &iv, key, &blockSize, r->pool);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01829)
                "apr_crypto_block_encrypt_init failed");
        return res;
    }

    /* encrypt the given string */
    res = apr_crypto_block_encrypt(&encrypt, &encryptlen,
                                   (const unsigned char *)in, strlen(in),
                                   block);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01830)
                "apr_crypto_block_encrypt failed");
        return res;
    }
    res = apr_crypto_block_encrypt_finish(encrypt + encryptlen, &tlen, block);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01831)
                "apr_crypto_block_encrypt_finish failed");
        return res;
    }
    encryptlen += tlen;

    /* prepend the salt and the iv to the result (keep room for the MAC) */
    combinedlen = AP_SIPHASH_DSIZE + sizeof(apr_uuid_t) + ivSize + encryptlen;
    combined = apr_palloc(r->pool, combinedlen);
    memcpy(combined + AP_SIPHASH_DSIZE, &salt, sizeof(apr_uuid_t));
    memcpy(combined + AP_SIPHASH_DSIZE + sizeof(apr_uuid_t), iv, ivSize);
    memcpy(combined + AP_SIPHASH_DSIZE + sizeof(apr_uuid_t) + ivSize,
           encrypt, encryptlen);
    /* authenticate the whole salt+IV+ciphertext with a leading MAC */
    compute_auth(combined + AP_SIPHASH_DSIZE, combinedlen - AP_SIPHASH_DSIZE,
                 passphrase, passlen, combined);

    /* base64 encode the result (APR handles the trailing '\0') */
    base64 = apr_palloc(r->pool, apr_base64_encode_len(combinedlen));
    apr_base64_encode(base64, (const char *) combined, combinedlen);
    *out = base64;

    return res;

}

/**
 * Decrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t decrypt_string(request_rec * r, const apr_crypto_t *f,
        session_crypto_dir_conf *dconf, const char *in, char **out)
{
    apr_status_t res;
    apr_crypto_key_t *key = NULL;
    apr_size_t ivSize = 0;
    apr_crypto_block_t *block = NULL;
    unsigned char *decrypted = NULL;
    apr_size_t decryptedlen, tlen;
    apr_size_t decodedlen;
    char *decoded;
    apr_size_t blockSize = 0;
    apr_crypto_block_key_type_e *cipher;
    unsigned char auth[AP_SIPHASH_DSIZE];
    int i = 0;

    /* strip base64 from the string */
    decoded = apr_palloc(r->pool, apr_base64_decode_len(in));
    decodedlen = apr_base64_decode(decoded, in);
    decoded[decodedlen] = '\0';

    /* sanity check - decoded too short? */
    if (decodedlen < (AP_SIPHASH_DSIZE + sizeof(apr_uuid_t))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(10005)
                "too short to decrypt, aborting");
        return APR_ECRYPT;
    }

    res = crypt_init(r, f, &cipher, dconf);
    if (res != APR_SUCCESS) {
        return res;
    }

    /* try each passphrase in turn */
    for (; i < dconf->passphrases->nelts; i++) {
        const char *passphrase = APR_ARRAY_IDX(dconf->passphrases, i, char *);
        apr_size_t passlen = strlen(passphrase);
        apr_size_t len = decodedlen - AP_SIPHASH_DSIZE;
        unsigned char *slider = (unsigned char *)decoded + AP_SIPHASH_DSIZE;

        /* Verify authentication of the whole salt+IV+ciphertext by computing
         * the MAC and comparing it (timing safe) with the one in the payload.
         */
        compute_auth(slider, len, passphrase, passlen, auth);
        if (!ap_crypto_equals(auth, decoded, AP_SIPHASH_DSIZE)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(10006)
                    "auth does not match, skipping");
            continue;
        }

        /* encrypt using the first passphrase in the list */
        res = apr_crypto_passphrase(&key, &ivSize, passphrase, passlen,
                                    slider, sizeof(apr_uuid_t),
                                    *cipher, APR_MODE_CBC, 1, 4096,
                                    f, r->pool);
        if (APR_STATUS_IS_ENOKEY(res)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01832)
                    "the passphrase '%s' was empty", passphrase);
            continue;
        }
        else if (APR_STATUS_IS_EPADDING(res)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01833)
                    "padding is not supported for cipher");
            continue;
        }
        else if (APR_STATUS_IS_EKEYTYPE(res)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01834)
                    "the key type is not known");
            continue;
        }
        else if (APR_SUCCESS != res) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01835)
                    "encryption could not be configured.");
            continue;
        }

        /* sanity check - decoded too short? */
        if (len < (sizeof(apr_uuid_t) + ivSize)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(01836)
                    "too short to decrypt, skipping");
            res = APR_ECRYPT;
            continue;
        }

        /* bypass the salt at the start of the decoded block */
        slider += sizeof(apr_uuid_t);
        len -= sizeof(apr_uuid_t);

        res = apr_crypto_block_decrypt_init(&block, &blockSize, slider, key,
                                            r->pool);
        if (APR_SUCCESS != res) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01837)
                    "apr_crypto_block_decrypt_init failed");
            continue;
        }

        /* bypass the iv at the start of the decoded block */
        slider += ivSize;
        len -= ivSize;

        /* decrypt the given string */
        res = apr_crypto_block_decrypt(&decrypted, &decryptedlen,
                                       slider, len, block);
        if (res) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01838)
                    "apr_crypto_block_decrypt failed");
            continue;
        }
        *out = (char *) decrypted;

        res = apr_crypto_block_decrypt_finish(decrypted + decryptedlen, &tlen, block);
        if (APR_SUCCESS != res) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01839)
                    "apr_crypto_block_decrypt_finish failed");
            continue;
        }
        decryptedlen += tlen;
        decrypted[decryptedlen] = 0;

        break;
    }

    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, res, r, APLOGNO(01840)
                "decryption failed");
    }

    return res;

}

/**
 * Crypto encoding for the session.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
static apr_status_t session_crypto_encode(request_rec * r, session_rec * z)
{

    char *encoded = NULL;
    apr_status_t res;
    const apr_crypto_t *f = NULL;
    session_crypto_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
            &session_crypto_module);

    if (dconf->passphrases_set && z->encoded && *z->encoded) {
        apr_pool_userdata_get((void **)&f, CRYPTO_KEY, r->server->process->pconf);
        res = encrypt_string(r, f, dconf, z->encoded, &encoded);
        if (res != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, APLOGNO(01841)
                    "encrypt session failed");
            return res;
        }
        z->encoded = encoded;
    }

    return OK;

}

/**
 * Crypto decoding for the session.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
static apr_status_t session_crypto_decode(request_rec * r,
        session_rec * z)
{

    char *encoded = NULL;
    apr_status_t res;
    const apr_crypto_t *f = NULL;
    session_crypto_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
            &session_crypto_module);

    if ((dconf->passphrases_set) && z->encoded && *z->encoded) {
        apr_pool_userdata_get((void **)&f, CRYPTO_KEY,
                r->server->process->pconf);
        res = decrypt_string(r, f, dconf, z->encoded, &encoded);
        if (res != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, APLOGNO(01842)
                    "decrypt session failed, wrong passphrase?");
            return res;
        }
        z->encoded = encoded;
    }

    return OK;

}

/**
 * Initialise the SSL in the post_config hook.
 */
static int session_crypto_init(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{
    const apr_crypto_driver_t *driver = NULL;
    apr_crypto_t *f = NULL;

    session_crypto_conf *conf = ap_get_module_config(s->module_config,
            &session_crypto_module);

    /* session_crypto_init() will be called twice. Don't bother
     * going through all of the initialization on the first call
     * because it will just be thrown away.*/
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    if (conf->library) {

        const apu_err_t *err = NULL;
        apr_status_t rv;

        rv = apr_crypto_init(p);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(01843)
                    "APR crypto could not be initialised");
            return rv;
        }

        rv = apr_crypto_get_driver(&driver, conf->library, conf->params, &err, p);
        if (APR_EREINIT == rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s, APLOGNO(01844)
                    "warning: crypto for '%s' was already initialised, "
                    "using existing configuration", conf->library);
            rv = APR_SUCCESS;
        }
        if (APR_SUCCESS != rv && err) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(01845)
                    "The crypto library '%s' could not be loaded: %s (%s: %d)", conf->library, err->msg, err->reason, err->rc);
            return rv;
        }
        if (APR_ENOTIMPL == rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(01846)
                    "The crypto library '%s' could not be found",
                    conf->library);
            return rv;
        }
        if (APR_SUCCESS != rv || !driver) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(01847)
                    "The crypto library '%s' could not be loaded",
                    conf->library);
            return rv;
        }

        rv = apr_crypto_make(&f, driver, conf->params, p);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(01848)
                    "The crypto library '%s' could not be initialised",
                    conf->library);
            return rv;
        }

        ap_log_error(APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(01849)
                "The crypto library '%s' was loaded successfully",
                conf->library);

        apr_pool_userdata_set((const void *)f, CRYPTO_KEY,
                apr_pool_cleanup_null, s->process->pconf);

    }

    return OK;
}

static void *create_session_crypto_config(apr_pool_t * p, server_rec *s)
{
    session_crypto_conf *new =
    (session_crypto_conf *) apr_pcalloc(p, sizeof(session_crypto_conf));

    /* if no library has been configured, set the recommended library
     * as a sensible default.
     */
#ifdef APU_CRYPTO_RECOMMENDED_DRIVER
    new->library = APU_CRYPTO_RECOMMENDED_DRIVER;
#endif

    return (void *) new;
}

static void *create_session_crypto_dir_config(apr_pool_t * p, char *dummy)
{
    session_crypto_dir_conf *new =
    (session_crypto_dir_conf *) apr_pcalloc(p, sizeof(session_crypto_dir_conf));

    new->passphrases = apr_array_make(p, 10, sizeof(char *));

    /* default cipher AES256-SHA */
    new->cipher = "aes256";

    return (void *) new;
}

static void *merge_session_crypto_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_crypto_dir_conf *new = (session_crypto_dir_conf *) apr_pcalloc(p, sizeof(session_crypto_dir_conf));
    session_crypto_dir_conf *add = (session_crypto_dir_conf *) addv;
    session_crypto_dir_conf *base = (session_crypto_dir_conf *) basev;

    new->passphrases = (add->passphrases_set == 0) ? base->passphrases : add->passphrases;
    new->passphrases_set = add->passphrases_set || base->passphrases_set;
    new->cipher = (add->cipher_set == 0) ? base->cipher : add->cipher;
    new->cipher_set = add->cipher_set || base->cipher_set;

    return new;
}

static const char *set_crypto_driver(cmd_parms * cmd, void *config, const char *arg)
{
    session_crypto_conf *conf =
    (session_crypto_conf *)ap_get_module_config(cmd->server->module_config,
            &session_crypto_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    conf->library = ap_getword_conf(cmd->pool, &arg);
    conf->params = arg;
    conf->library_set = 1;

    return NULL;
}

static const char *set_crypto_passphrase(cmd_parms * cmd, void *config, const char *arg)
{
    int arglen = strlen(arg);
    char **argv;
    char *result;
    const char **passphrase;
    session_crypto_dir_conf *dconf = (session_crypto_dir_conf *) config;

    passphrase = apr_array_push(dconf->passphrases);

    if ((arglen > 5) && strncmp(arg, "exec:", 5) == 0) {
        if (apr_tokenize_to_argv(arg+5, &argv, cmd->temp_pool) != APR_SUCCESS) {
            return apr_pstrcat(cmd->pool,
                               "Unable to parse exec arguments from ",
                               arg+5, NULL);
        }
        argv[0] = ap_server_root_relative(cmd->temp_pool, argv[0]);

        if (!argv[0]) {
            return apr_pstrcat(cmd->pool,
                               "Invalid SessionCryptoPassphrase exec location:",
                               arg+5, NULL);
        }
        result = ap_get_exec_line(cmd->pool,
                                  (const char*)argv[0], (const char * const *)argv);

        if(!result) {
            return apr_pstrcat(cmd->pool,
                               "Unable to get bind password from exec of ",
                               arg+5, NULL);
        }
        *passphrase = result;
    }
    else {
        *passphrase = arg;
    }

    dconf->passphrases_set = 1;

    return NULL;
}

static const char *set_crypto_passphrase_file(cmd_parms *cmd, void *config,
                                  const char *filename)
{
    char buffer[MAX_STRING_LEN];
    char *arg;
    const char *args;
    ap_configfile_t *file;
    apr_status_t rv;

    filename = ap_server_root_relative(cmd->temp_pool, filename);
    rv = ap_pcfg_openfile(&file, cmd->temp_pool, filename);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool, "%s: Could not open file %s: %pm",
                            cmd->cmd->name, filename, &rv);
    }

    while (!(ap_cfg_getline(buffer, sizeof(buffer), file))) {
        args = buffer;
        while (*(arg = ap_getword_conf(cmd->pool, &args)) != '\0') {
            if (*arg == '#') {
                break;
            }
            set_crypto_passphrase(cmd, config, arg);
        }
    }

    ap_cfg_closefile(file);

    return NULL;
}

static const char *set_crypto_cipher(cmd_parms * cmd, void *config, const char *cipher)
{
    session_crypto_dir_conf *dconf = (session_crypto_dir_conf *) config;

    dconf->cipher = cipher;
    dconf->cipher_set = 1;

    return NULL;
}

static const command_rec session_crypto_cmds[] =
{
    AP_INIT_ITERATE("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF|OR_AUTHCFG,
            "The passphrase(s) used to encrypt the session. First will be used for encryption, all phrases will be accepted for decryption"),
    AP_INIT_TAKE1("SessionCryptoPassphraseFile", set_crypto_passphrase_file, NULL, RSRC_CONF|ACCESS_CONF,
            "File containing passphrase(s) used to encrypt the session, one per line. First will be used for encryption, all phrases will be accepted for decryption"),
    AP_INIT_TAKE1("SessionCryptoCipher", set_crypto_cipher, NULL, RSRC_CONF|OR_AUTHCFG,
            "The underlying crypto cipher to use"),
    AP_INIT_RAW_ARGS("SessionCryptoDriver", set_crypto_driver, NULL, RSRC_CONF,
            "The underlying crypto library driver to use"),
    { NULL }
};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_session_encode(session_crypto_encode, NULL, NULL, APR_HOOK_LAST);
    ap_hook_session_decode(session_crypto_decode, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(session_crypto_init, NULL, NULL, APR_HOOK_LAST);
}

AP_DECLARE_MODULE(session_crypto) =
{
    STANDARD20_MODULE_STUFF,
    create_session_crypto_dir_config, /* dir config creater */
    merge_session_crypto_dir_config, /* dir merger --- default is to override */
    create_session_crypto_config, /* server config */
    NULL, /* merge server config */
    session_crypto_cmds, /* command apr_table_t */
    register_hooks /* register hooks */
};

#endif
