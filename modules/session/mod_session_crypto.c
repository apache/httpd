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

#define CORE_PRIVATE

#include "mod_session.h"
#include "apu_version.h"
#include "apr_base64.h"                /* for apr_base64_decode et al */
#include "apr_ssl.h"                /* for apr_*_encrypt et al */
#include "apr_lib.h"
#include "apr_strings.h"
#include "http_log.h"

#define LOG_PREFIX "mod_session_crypto: "
#define DEFAULT_CIPHER "AES256"
#define DEFAULT_DIGEST "SHA"

module AP_MODULE_DECLARE_DATA session_crypto_module;

/**
 * Structure to carry the per-dir session config.
 */
typedef struct {
    const char *passphrase;
    int passphrase_set;
    const char *certfile;
    int certfile_set;
    const char *keyfile;
    int keyfile_set;
    const char *cipher;
    int cipher_set;
    const char *digest;
    int digest_set;
    const char *engine;
    int engine_set;
} session_crypto_dir_conf;

/**
 * Initialise the encryption as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 3)
static apr_status_t crypt_init(request_rec * r, apr_evp_factory_t ** f, apr_evp_crypt_key_e * key, session_crypto_dir_conf * conf)
{
    apr_status_t res;

    if (!conf->certfile_set && !conf->passphrase_set) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, LOG_PREFIX
                      "encryption not configured, "
                      "no passphrase or certfile/keyfile set");
        return APR_EGENERAL;
    }

    /* set up */
    if (conf->certfile_set) {
        *key = APR_EVP_KEY_PUBLIC;
        res = apr_evp_factory_create(f, conf->keyfile, conf->certfile, NULL,
                   conf->passphrase, conf->engine, conf->digest,
                   APR_EVP_FACTORY_ASYM, r->pool);
        if (APR_ENOTIMPL == res) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "generic public/private key encryption is not supported by "
                    "this version of APR. session encryption not possible");
        }
    }
    else {
        *key = APR_EVP_KEY_SYM;
        res = apr_evp_factory_create(f, NULL, NULL, conf->cipher,
                                     conf->passphrase, conf->engine, conf->digest,
                                     APR_EVP_FACTORY_SYM, r->pool);
        if (APR_ENOTIMPL == res) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                  "generic symmetrical encryption is not supported by this "
                          "version of APR. session encryption not possible");
        }
    }
    if (APR_STATUS_IS_ENOCIPHER(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "the cipher '%s' was not found", conf->cipher);
    }
    if (APR_STATUS_IS_ENODIGEST(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "the digest '%s' was not found", conf->digest);
    }
    if (APR_STATUS_IS_ENOCERT(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                   "the public and private key could not be extracted from "
                      "the certificates");
    }
    if (APR_STATUS_IS_ENOENGINE(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "the engine '%s' was not found", conf->engine);
    }
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "encryption could not be configured. Please check the "
                      "certificates and/or passphrase as appropriate");
        apr_evp_factory_cleanup(*f);
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}
#endif

/**
 * Encrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t encrypt_string(request_rec * r, session_crypto_dir_conf *conf,
                                   const char *in, char **out)
{
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 3)
    apr_status_t res;
    apr_evp_factory_t *f = NULL;
    apr_evp_crypt_t *e = NULL;
    apr_evp_crypt_key_e key;
    unsigned char *encrypt = NULL;
    apr_size_t encryptlen, tlen;
    char *base64;

    /* by default, return an empty string */
    *out = "";

    /* don't attempt to encrypt an empty string, trying to do so causes a segfault */
    if (!in || !*in) {
        return APR_SUCCESS;
    }

    res = crypt_init(r, &f, &key, conf);
    if (res != APR_SUCCESS) {
        return res;
    }

    res = apr_evp_crypt_init(f, &e, APR_EVP_ENCRYPT, key, r->pool);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "encryption could be configured but not initialised");
        apr_evp_factory_cleanup(f);
        return res;
    }

    /* encrypt the given string */
    res = apr_evp_crypt(e, &encrypt, &encryptlen, (unsigned char *) in, strlen(in));
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "attempt to encrypt failed");
        apr_evp_factory_cleanup(f);
        apr_evp_crypt_cleanup(e);
        return res;
    }
    res = apr_evp_crypt_finish(e, encrypt + encryptlen, &tlen);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "attempt to finish the encryption failed");
        apr_evp_factory_cleanup(f);
        apr_evp_crypt_cleanup(e);
        return res;
    }
    encryptlen += tlen;

    /* base64 encode the result */
    base64 = apr_pcalloc(r->pool, apr_base64_encode_len(encryptlen + 1) * sizeof(char));
    apr_base64_encode(base64, (const char *) encrypt, encryptlen);
    *out = base64;

    /* clean up afterwards */
    apr_evp_factory_cleanup(f);
    apr_evp_crypt_cleanup(e);

    return res;

#else
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, r, LOG_PREFIX
                  "crypto is not supported by APR on this platform");
    return APR_ENOTIMPL;
#endif
}

/**
 * Decrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t decrypt_string(request_rec * r, session_crypto_dir_conf *conf,
                                   const char *in, char **out)
{
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 3)
    apr_status_t res;
    apr_evp_factory_t *f = NULL;
    apr_evp_crypt_t *e = NULL;
    apr_evp_crypt_key_e key;
    unsigned char *decrypted = NULL;
    apr_size_t decryptedlen, tlen;
    apr_size_t decodedlen;
    char *decoded;

    res = crypt_init(r, &f, &key, conf);
    if (res != APR_SUCCESS) {
        return res;
    }

    res = apr_evp_crypt_init(f, &e, APR_EVP_DECRYPT, key, r->pool);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "decryption could be configured but not initialised");
        apr_evp_factory_cleanup(f);
        return res;
    }

    /* strip base64 from the string */
    decoded = apr_palloc(r->pool, apr_base64_decode_len(in));
    decodedlen = apr_base64_decode(decoded, in);
    decoded[decodedlen] = '\0';

    /* decrypt the given string */
    res = apr_evp_crypt(e, &decrypted, &decryptedlen, (unsigned char *) decoded, decodedlen);
    if (res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "decrypt: attempt to decrypt failed");
        apr_evp_factory_cleanup(f);
        apr_evp_crypt_cleanup(e);
        return res;
    }
    *out = (char *) decrypted;

    res = apr_evp_crypt_finish(e, decrypted + decryptedlen, &tlen);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                      "attempt to finish the decryption failed");
        apr_evp_factory_cleanup(f);
        apr_evp_crypt_cleanup(e);
        return res;
    }
    decryptedlen += tlen;
    decrypted[decryptedlen] = 0;

    return APR_SUCCESS;

#else
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, r, LOG_PREFIX
                  "crypto is not supported by APR on this platform");
    return APR_ENOTIMPL;
#endif
}


/**
 * Crypto encoding for the session.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
AP_DECLARE(int) ap_session_crypto_encode(request_rec * r, session_rec * z)
{

    char *encoded = NULL;
    apr_status_t res;
    session_crypto_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_crypto_module);

    if (conf->passphrase_set || conf->certfile_set) {
        res = encrypt_string(r, conf, z->encoded, &encoded);
        if (res != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, res, r, LOG_PREFIX
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
AP_DECLARE(int) ap_session_crypto_decode(request_rec * r, session_rec * z)
{

    char *encoded = NULL;
    apr_status_t res;
    session_crypto_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &session_crypto_module);

    if ((conf->passphrase_set || conf->certfile_set) && z->encoded) {
        res = decrypt_string(r, conf, z->encoded, &encoded);
        if (res != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
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
AP_DECLARE(int) ap_session_crypto_init(apr_pool_t *p, apr_pool_t *plog,
                                       apr_pool_t *ptemp, server_rec *s)
{
    apr_ssl_init();
    return OK;
}



static void *create_session_crypto_dir_config(apr_pool_t * p, char *dummy)
{
    session_crypto_dir_conf *new =
    (session_crypto_dir_conf *) apr_pcalloc(p, sizeof(session_crypto_dir_conf));

    /* default cipher AES256-SHA */
    new->cipher = DEFAULT_CIPHER;
    new->digest = DEFAULT_DIGEST;

    return (void *) new;
}

static void *merge_session_crypto_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_crypto_dir_conf *new = (session_crypto_dir_conf *) apr_pcalloc(p, sizeof(session_crypto_dir_conf));
    session_crypto_dir_conf *add = (session_crypto_dir_conf *) addv;
    session_crypto_dir_conf *base = (session_crypto_dir_conf *) basev;

    new->passphrase = (add->passphrase_set == 0) ? base->passphrase : add->passphrase;
    new->passphrase_set = add->passphrase_set || base->passphrase_set;
    new->certfile = (add->certfile_set == 0) ? base->certfile : add->certfile;
    new->certfile_set = add->certfile_set || base->certfile_set;
    new->keyfile = (add->keyfile_set == 0) ? base->keyfile : add->keyfile;
    new->keyfile_set = add->keyfile_set || base->keyfile_set;
    new->cipher = (add->cipher_set == 0) ? base->cipher : add->cipher;
    new->cipher_set = add->cipher_set || base->cipher_set;
    new->digest = (add->digest_set == 0) ? base->digest : add->digest;
    new->digest_set = add->digest_set || base->digest_set;
    new->engine = (add->engine_set == 0) ? base->engine : add->engine;
    new->engine_set = add->engine_set || base->engine_set;

    return new;
}

static const char *check_file(cmd_parms * cmd, const char **file)
{
    apr_finfo_t finfo;
    const char *filepath = ap_server_root_relative(cmd->pool, *file);

    if (!filepath) {
        return apr_pstrcat(cmd->pool, cmd->directive->directive,
                           ": Invalid file path ", *file, NULL);
    }
    if (apr_stat(&finfo, filepath,
                 APR_FINFO_TYPE | APR_FINFO_SIZE, cmd->pool) != 0 ||
        finfo.filetype != APR_REG || finfo.size <= 0) {
        return apr_pstrcat(cmd->pool, cmd->directive->directive,
                           ": File empty or missing ", *file, NULL);
    }
    *file = filepath;

    return NULL;
}

static const char *set_crypto_passphrase(cmd_parms * cmd, void *config, const char *passphrase)
{
    session_crypto_dir_conf *conf = (session_crypto_dir_conf *) config;
    conf->passphrase = passphrase;
    conf->passphrase_set = 1;
    return NULL;
}

static const char *set_crypto_certificate_file(cmd_parms * cmd, void *config, const char *file)
{
    const char *res = check_file(cmd, &file);
    if (!res) {
        session_crypto_dir_conf *conf = (session_crypto_dir_conf *) config;
        conf->certfile = file;
        conf->certfile_set = 1;
    }
    return res;
}

static const char *set_crypto_certificate_keyfile(cmd_parms * cmd, void *config, const char *file)
{
    const char *res = check_file(cmd, &file);
    if (!res) {
        session_crypto_dir_conf *conf = (session_crypto_dir_conf *) config;
        conf->keyfile = file;
        conf->keyfile_set = 1;
    }
    return res;
}

static const char *set_crypto_cipher(cmd_parms * cmd, void *config, const char *cipher)
{
    session_crypto_dir_conf *conf = (session_crypto_dir_conf *) config;
    conf->cipher = cipher;
    conf->cipher_set = 1;
    return NULL;
}

static const char *set_crypto_digest(cmd_parms * cmd, void *config, const char *digest)
{
    session_crypto_dir_conf *conf = (session_crypto_dir_conf *) config;
    conf->digest = digest;
    conf->digest_set = 1;
    return NULL;
}

static const char *set_crypto_engine(cmd_parms * cmd, void *config, const char *engine)
{
    session_crypto_dir_conf *conf = (session_crypto_dir_conf *) config;
    conf->engine = engine;
    conf->engine_set = 1;
    return NULL;
}


static const command_rec session_crypto_cmds[] =
{
    AP_INIT_TAKE1("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF|OR_AUTHCFG,
                  "The passphrase used to encrypt cookies"),
    AP_INIT_TAKE1("SessionCryptoCertificateFile", set_crypto_certificate_file, NULL, RSRC_CONF|OR_AUTHCFG,
                  "The name of a certificate whose public key will be used to encrypt cookies"),
    AP_INIT_TAKE1("SessionCryptoCertificateKeyFile", set_crypto_certificate_keyfile, NULL, RSRC_CONF|OR_AUTHCFG,
                  "The name of a private key which will be used to decrypt cookies"),
    AP_INIT_TAKE1("SessionCryptoCipher", set_crypto_cipher, NULL, RSRC_CONF|OR_AUTHCFG,
                  "The cipher used to encrypt cookies. Defaults to " DEFAULT_CIPHER),
    AP_INIT_TAKE1("SessionCryptoDigest", set_crypto_digest, NULL, RSRC_CONF|OR_AUTHCFG,
                  "The digest used to encrypt cookies. Defaults to " DEFAULT_DIGEST),
    AP_INIT_TAKE1("SessionCryptoEngine", set_crypto_engine, NULL, RSRC_CONF|OR_AUTHCFG,
                  "The optional engine used to encrypt cookies, if supported by the underlying crypto "
                  "toolkit"),
    {NULL}
};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_session_encode(ap_session_crypto_encode, NULL, NULL, APR_HOOK_LAST);
    ap_hook_session_decode(ap_session_crypto_decode, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(ap_session_crypto_init, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA session_crypto_module =
{
    STANDARD20_MODULE_STUFF,
    create_session_crypto_dir_config, /* dir config creater */
    merge_session_crypto_dir_config,  /* dir merger --- default is to
                                       * override */
    NULL,                             /* server config */
    NULL,                             /* merge server config */
    session_crypto_cmds,              /* command apr_table_t */
    register_hooks                    /* register hooks */
};
