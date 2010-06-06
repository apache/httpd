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
#include "apr_strings.h"
#include "http_log.h"

#if APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION < 4

#error session_crypto_module requires APR v1.4.0 or later

#elif APU_HAVE_CRYPTO == 0

#error Crypto support must be enabled in APR

#else

#if APR_MAJOR_VERSION < 2
#define CRYPTO_VERSION 104
#else
#define CRYPTO_VERSION 200
#endif

#include "apr_crypto.h"                /* for apr_*_crypt et al */

#define LOG_PREFIX "mod_session_crypto: "
#define DRIVER_KEY "session_crypto_driver"
#define INIT_KEY "session_crypto_init"

module AP_MODULE_DECLARE_DATA session_crypto_module;

/**
 * Structure to carry the per-dir session config.
 */
typedef struct {
    const char *passphrase;
    apr_array_header_t *params;
    int passphrase_set;
    apr_crypto_block_key_type_e cipher;
    int cipher_set;
}session_crypto_dir_conf;

/**
 * Structure to carry the server wide session config.
 */
typedef struct {
    const char *library;
    apr_array_header_t *params;
    int library_set;
    int noinit;
    int noinit_set;
}session_crypto_conf;

AP_DECLARE(int) ap_session_crypto_encode(request_rec * r, session_rec * z);
AP_DECLARE(int) ap_session_crypto_decode(request_rec * r, session_rec * z);
AP_DECLARE(int) ap_session_crypto_init(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s);

/**
 * Initialise the encryption as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t crypt_init(request_rec * r, const apr_crypto_driver_t *driver, apr_crypto_t **f, apr_crypto_key_t **key, apr_uuid_t *salt, apr_size_t *ivSize, session_crypto_dir_conf * dconf)
{
    apr_status_t res;

    if (!driver) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOG_PREFIX
                "encryption driver not configured, "
                "no SessionCryptoDriver set");
        return APR_EGENERAL;
    }

    if (!dconf->passphrase_set) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, LOG_PREFIX
                "encryption not configured, "
                "no passphrase set");
        return APR_EGENERAL;
    }

    /* set up */
    res = apr_crypto_make(driver, r->pool, dconf->params, f);
    if (APR_ENOTIMPL == res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "generic symmetrical encryption is not supported by this "
                "version of APR. session encryption not possible");
    }

    if (APR_SUCCESS == res) {
#if CRYPTO_VERSION < 200
        res = apr_crypto_passphrase(driver, r->pool, *f, dconf->passphrase,
#else
        res = apr_crypto_passphrase(r->pool, *f, dconf->passphrase,
#endif
                strlen(dconf->passphrase),
                (unsigned char *) salt, salt ? sizeof(apr_uuid_t) : 0, dconf->cipher,
                MODE_CBC, 1, 4096, key, ivSize);
    }

    if (APR_STATUS_IS_ENOKEY(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "the passphrase '%s' was empty", dconf->passphrase);
    }
    if (APR_STATUS_IS_EPADDING(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "padding is not supported for cipher");
    }
    if (APR_STATUS_IS_EKEYTYPE(res)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "the key type is not known");
    }
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "encryption could not be configured. Please check the "
                "certificates and/or passphrase as appropriate");
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

/**
 * Encrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t encrypt_string(request_rec * r, const apr_crypto_driver_t *driver,
        session_crypto_dir_conf *dconf,
        const char *in, char **out)
{
    apr_status_t res;
    apr_crypto_t *f = NULL;
    apr_crypto_key_t *key = NULL;
    apr_size_t ivSize = 0;
    apr_crypto_block_t *block = NULL;
    unsigned char *encrypt = NULL;
    unsigned char *combined = NULL;
    apr_size_t encryptlen, tlen;
    char *base64;
    apr_size_t blockSize = 0;
    const unsigned char *iv = NULL;
    apr_uuid_t salt;

    /* by default, return an empty string */
    *out = "";

    /* don't attempt to encrypt an empty string, trying to do so causes a segfault */
    if (!in || !*in) {
        return APR_SUCCESS;
    }

    /* use a uuid as a salt value, and prepend it to our result */
    apr_uuid_get(&salt);
    res = crypt_init(r, driver, &f, &key, &salt, &ivSize, dconf);
    if (res != APR_SUCCESS) {
        return res;
    }

#if CRYPTO_VERSION < 200
    res = apr_crypto_block_encrypt_init(driver, r->pool, f, key, &iv, &block,
#else
    res = apr_crypto_block_encrypt_init(r->pool, f, key, &iv, &block,
#endif
            &blockSize);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "apr_crypto_block_encrypt_init failed");
        return res;
    }

    /* encrypt the given string */
#if CRYPTO_VERSION < 200
    res = apr_crypto_block_encrypt(driver, block, &encrypt,
#else
    res = apr_crypto_block_encrypt(f, block, &encrypt,
#endif
            &encryptlen, (unsigned char *)in, strlen(in));
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "apr_crypto_block_encrypt failed");
        return res;
    }
#if CRYPTO_VERSION < 200
    res = apr_crypto_block_encrypt_finish(driver, block, encrypt + encryptlen,
#else
    res = apr_crypto_block_encrypt_finish(f, block, encrypt + encryptlen,
#endif
            &tlen);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "apr_crypto_block_encrypt_finish failed");
        return res;
    }
    encryptlen += tlen;

    /* prepend the salt and the iv to the result */
    combined = apr_palloc(r->pool, ivSize + encryptlen + sizeof(apr_uuid_t));
    memcpy(combined, &salt, sizeof(apr_uuid_t));
    memcpy(combined + sizeof(apr_uuid_t), iv, ivSize);
    memcpy(combined + sizeof(apr_uuid_t) + ivSize, encrypt, encryptlen);

    /* base64 encode the result */
    base64 = apr_palloc(r->pool, apr_base64_encode_len(ivSize + encryptlen + sizeof(apr_uuid_t) + 1) * sizeof(char));
    apr_base64_encode(base64, (const char *) combined, ivSize + encryptlen + sizeof(apr_uuid_t));
    *out = base64;

    return res;

}

/**
 * Decrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t decrypt_string(request_rec * r, const apr_crypto_driver_t *driver,
        session_crypto_dir_conf *dconf,
        const char *in, char **out)
{
    apr_status_t res;
    apr_crypto_t *f = NULL;
    apr_crypto_key_t *key = NULL;
    apr_size_t ivSize = 0;
    apr_crypto_block_t *block = NULL;
    unsigned char *decrypted = NULL;
    apr_size_t decryptedlen, tlen;
    apr_size_t decodedlen;
    char *decoded;
    apr_size_t blockSize = 0;

    /* strip base64 from the string */
    decoded = apr_palloc(r->pool, apr_base64_decode_len(in));
    decodedlen = apr_base64_decode(decoded, in);
    decoded[decodedlen] = '\0';

    res = crypt_init(r, driver, &f, &key, (apr_uuid_t *)decoded, &ivSize, dconf);
    if (res != APR_SUCCESS) {
        return res;
    }

    /* sanity check - decoded too short? */
    if (decodedlen < (sizeof(apr_uuid_t) + ivSize)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, LOG_PREFIX
                "too short to decrypt, skipping");
        return APR_ECRYPT;
    }

    /* bypass the salt at the start of the decoded block */
    decoded += sizeof(apr_uuid_t);
    decodedlen -= sizeof(apr_uuid_t);

#if CRYPTO_VERSION < 200
    res = apr_crypto_block_decrypt_init(driver, r->pool, f, key, (unsigned char *)decoded, &block,
#else
    res = apr_crypto_block_decrypt_init(r->pool, f, key, (unsigned char *)decoded, &block,
#endif
            &blockSize);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "apr_crypto_block_decrypt_init failed");
        return res;
    }

    /* bypass the iv at the start of the decoded block */
    decoded += ivSize;
    decodedlen -= ivSize;

    /* decrypt the given string */
#if CRYPTO_VERSION < 200
    res = apr_crypto_block_decrypt(driver, block, &decrypted,
#else
    res = apr_crypto_block_decrypt(f, block, &decrypted,
#endif
            &decryptedlen, (unsigned char *)decoded, decodedlen);
    if (res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "apr_crypto_block_decrypt failed");
        return res;
    }
    *out = (char *) decrypted;

#if CRYPTO_VERSION < 200
    res = apr_crypto_block_decrypt_finish(driver, block, decrypted + decryptedlen,
#else
    res = apr_crypto_block_decrypt_finish(f, block, decrypted + decryptedlen,
#endif
            &tlen);
    if (APR_SUCCESS != res) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r, LOG_PREFIX
                "apr_crypto_block_decrypt_finish failed");
        return res;
    }
    decryptedlen += tlen;
    decrypted[decryptedlen] = 0;

    return APR_SUCCESS;

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
    const apr_crypto_driver_t *driver = NULL;
    session_crypto_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
            &session_crypto_module);

    if (dconf->passphrase_set && z->encoded && *z->encoded) {
        apr_pool_userdata_get((void **)&driver, DRIVER_KEY, r->server->process->pconf);
        res = encrypt_string(r, driver, dconf, z->encoded, &encoded);
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
    const apr_crypto_driver_t *driver = NULL;
    session_crypto_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
            &session_crypto_module);

    if ((dconf->passphrase_set) && z->encoded && *z->encoded) {
        apr_pool_userdata_get((void **)&driver, DRIVER_KEY, r->server->process->pconf);
        res = decrypt_string(r, driver, dconf, z->encoded, &encoded);
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
    void *data;
    const apr_crypto_driver_t *driver = NULL;

    session_crypto_conf *conf = ap_get_module_config(s->module_config,
            &session_crypto_module);

    /* session_crypto_init() will be called twice. Don't bother
     * going through all of the initialization on the first call
     * because it will just be thrown away.*/
    apr_pool_userdata_get(&data, INIT_KEY, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, INIT_KEY,
                apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    if (conf->library) {

        const apu_err_t *err = NULL;
        apr_status_t rv;

        rv = apr_crypto_init(p, NULL);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, LOG_PREFIX
                    "APR crypto could not be initialised");
            return rv;
        }

        rv = apr_crypto_get_driver(p, conf->library, &driver, conf->params, &err);
        if (APR_EREINIT == rv) {
            if (!conf->noinit) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s, LOG_PREFIX
                        "warning: crypto for '%s' was already initialised, "
                        "using existing configuration", conf->library);
            }
            rv = APR_SUCCESS;
        }
        else {
            if (conf->noinit) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s, LOG_PREFIX
                        "warning: crypto for '%s' was not previously initialised "
                        "when it was expected to be, initialised instead by "
                        "mod_session_crypto", conf->library);
            }
        }
        if (APR_SUCCESS != rv && err) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, LOG_PREFIX
                    "%s", err->msg);
            return rv;
        }
        if (APR_ENOTIMPL == rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, LOG_PREFIX
                    "The crypto library '%s' could not be found",
                    conf->library);
            return rv;
        }
        if (APR_SUCCESS != rv || !driver) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, LOG_PREFIX
                    "The crypto library '%s' could not be loaded",
                    conf->library);
            return rv;
        }

        ap_log_error(APLOG_MARK, APLOG_INFO, rv, s, LOG_PREFIX
                "The crypto library '%s' was loaded successfully",
                conf->library);

        apr_pool_userdata_set((const void *)driver, DRIVER_KEY,
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

    /* default cipher AES256-SHA */
    new->cipher = KEY_AES_256;

    return (void *) new;
}

static void *merge_session_crypto_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_crypto_dir_conf *new = (session_crypto_dir_conf *) apr_pcalloc(p, sizeof(session_crypto_dir_conf));
    session_crypto_dir_conf *add = (session_crypto_dir_conf *) addv;
    session_crypto_dir_conf *base = (session_crypto_dir_conf *) basev;

    new->passphrase = (add->passphrase_set == 0) ? base->passphrase : add->passphrase;
    new->params = (add->passphrase_set == 0) ? base->params : add->params;
    new->passphrase_set = add->passphrase_set || base->passphrase_set;
    new->cipher = (add->cipher_set == 0) ? base->cipher : add->cipher;
    new->cipher_set = add->cipher_set || base->cipher_set;

    return new;
}

static const char *set_crypto_driver(cmd_parms * cmd, void *config, const char *arg)
{
    char *word, *val;
    int library_set = 0;
    session_crypto_conf *conf =
        (session_crypto_conf *)ap_get_module_config(cmd->server->module_config,
            &session_crypto_module);
    apr_crypto_param_t *param;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    conf->params = apr_array_make(cmd->pool, 10, sizeof(apr_crypto_param_t));

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            if (!strcasecmp(word, "noinit")) {
                conf->noinit = 1;
                conf->noinit_set = 1;
            }
            else if (!library_set) {
                conf->library = word;
                conf->library_set = 1;
                library_set = 1;
            }
            else {
                return "Invalid SessionCryptoDriver parameter. Parameter must "
                "be in the form 'key=value'.";
            }
        }
        else {
            *val++ = '\0';
            if (!strcasecmp(word, "dir")) {
                param = apr_array_push(conf->params);
                param->type = APR_CRYPTO_CA_TYPE_DIR;
                param->path = val;
            }
            else if (!strcasecmp(word, "key3")) {
                param = apr_array_push(conf->params);
                param->type = APR_CRYPTO_CERT_TYPE_KEY3_DB;
                param->path = val;
            }
            else if (!strcasecmp(word, "cert7")) {
                param = apr_array_push(conf->params);
                param->type = APR_CRYPTO_CA_TYPE_CERT7_DB;
                param->path = val;
            }
            else if (!strcasecmp(word, "secmod")) {
                param = apr_array_push(conf->params);
                param->type = APR_CRYPTO_CA_TYPE_SECMOD;
                param->path = val;
            }
        }
    }

    return NULL;
}

static const char *set_crypto_passphrase(cmd_parms * cmd, void *config, const char *arg)
{
    char *word, *val;
    int passphrase_set = 0;
    session_crypto_dir_conf *dconf = (session_crypto_dir_conf *) config;
    apr_crypto_param_t *param;
    dconf->params = apr_array_make(cmd->pool, 10, sizeof(apr_crypto_param_t));

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            if (!passphrase_set) {
                dconf->passphrase = word;
                dconf->passphrase_set = 1;
                passphrase_set = 1;
            }
            else {
                return "Invalid SessionCryptoPassphrase parameter. Parameter must "
                "be in the form 'key=value'.";
            }
        }
        else {
            *val++ = '\0';
            if (!strcasecmp(word, "engine")) {
                param = apr_array_push(dconf->params);
                param->type = APR_CRYPTO_ENGINE;
                param->path = val;
            }
            else if (!strcasecmp(word, "cipher")) {
                if (!strcasecmp(val, "3des192")) {
                    dconf->cipher = KEY_3DES_192;
                    dconf->cipher_set = 1;
                }
                else if (!strcasecmp(val, "aes256")) {
                    dconf->cipher = KEY_AES_256;
                    dconf->cipher_set = 1;
                }
                else {
                    return "Invalid SessionCryptoPassphrase parameter. Cipher must "
                    "be '3des192' or 'aes256'.";
                }
            }
            else {
                return "Invalid SessionCryptoPassphrase parameter. Parameters must "
                "be 'engine' or 'cipher'.";
            }
        }
    }

    return NULL;
}

static const command_rec session_crypto_cmds[] =
{
    AP_INIT_RAW_ARGS("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF|OR_AUTHCFG,
            "The passphrase used to encrypt the session"),
    AP_INIT_RAW_ARGS("SessionCryptoDriver", set_crypto_driver, NULL, RSRC_CONF,
            "The underlying crypto library driver to use"),
    {    NULL}
};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_session_encode(ap_session_crypto_encode, NULL, NULL, APR_HOOK_LAST);
    ap_hook_session_decode(ap_session_crypto_decode, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(ap_session_crypto_init, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(session_crypto) =
{
    STANDARD20_MODULE_STUFF,
    create_session_crypto_dir_config, /* dir config creater */
    merge_session_crypto_dir_config,  /* dir merger --- default is to
                                       * override */
    create_session_crypto_config,     /* server config */
    NULL,                             /* merge server config */
    session_crypto_cmds,              /* command apr_table_t */
    register_hooks                    /* register hooks */
};

#endif
