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

/**
 * This module adds support for https://tools.ietf.org/html/rfc7519 JWT tokens
 * as https://tools.ietf.org/html/rfc6750 Bearer tokens, both as a generator
 * of JWT bearer tokens, and as an acceptor of JWT Bearer tokens for authentication.
 */

/* apr_jose support requires >= 1.7 */
#if APU_MAJOR_VERSION > 1 || \
    (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION > 6)
#define HAVE_APU_JOSE 1
#endif

#include "httpd.h"
#include "http_config.h"

#ifdef HAVE_APU_JOSE

#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_crypto.h"
#include "apr_jose.h"
#include "apr_lib.h"            /* for apr_isspace */
#include "apr_base64.h"         /* for apr_base64_decode et al */
#define APR_WANT_STRFUNC        /* for strcasecmp */
#include "apr_want.h"

#include "ap_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_md5.h"
#include "ap_provider.h"
#include "ap_expr.h"

#include "mod_auth.h"

#define CRYPTO_KEY "auth_bearer_context"

module AP_MODULE_DECLARE_DATA autht_jwt_module;

typedef enum jws_alg_type_e {
    /** No specific type. */
    JWS_ALG_TYPE_NONE = 0,
    /** HMAC SHA256 */
    JWS_ALG_TYPE_HS256 = 1,
} jws_alg_type_e;

typedef struct {
    unsigned char *secret;
    apr_size_t secret_len;
    jws_alg_type_e jws_alg;
} auth_bearer_signature_rec;

typedef struct {
    apr_hash_t *claims;
    apr_array_header_t *signs;
    apr_array_header_t *verifies;
    int signs_set:1;
    int verifies_set:1;
    int fake_set:1;
} auth_bearer_config_rec;

typedef struct {
    const char *library;
    const char *params;
    apr_crypto_t **crypto;
    int library_set;
} auth_bearer_conf;

static int auth_bearer_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
        server_rec *s) {
    const apr_crypto_driver_t *driver = NULL;

    /* auth_bearer_init() will be called twice. Don't bother
     * going through all of the initialization on the first call
     * because it will just be thrown away.*/
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    while (s) {

        auth_bearer_conf *conf = ap_get_module_config(s->module_config,
                &autht_jwt_module);

        if (conf->library_set && !*conf->crypto) {

            const apu_err_t *err = NULL;
            apr_status_t rv;

            rv = apr_crypto_init(p);
            if (APR_SUCCESS != rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                        APLOGNO(10432) "APR crypto could not be initialised");
                return rv;
            }

            rv = apr_crypto_get_driver(&driver, conf->library, conf->params,
                    &err, p);
            if (APR_EREINIT == rv) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                        APLOGNO(10433) "warning: crypto for '%s' was already initialised, " "using existing configuration",
                        conf->library);
                rv = APR_SUCCESS;
            }
            if (APR_SUCCESS != rv && err) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                        APLOGNO(10434) "The crypto library '%s' could not be loaded: %s (%s: %d)",
                        conf->library, err->msg, err->reason, err->rc);
                return rv;
            }
            if (APR_ENOTIMPL == rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                        APLOGNO(10435) "The crypto library '%s' could not be found",
                        conf->library);
                return rv;
            }
            if (APR_SUCCESS != rv || !driver) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                        APLOGNO(10436) "The crypto library '%s' could not be loaded",
                        conf->library);
                return rv;
            }

            rv = apr_crypto_make(conf->crypto, driver, conf->params, p);
            if (APR_SUCCESS != rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                        APLOGNO(10437) "The crypto library '%s' could not be initialised",
                        conf->library);
                return rv;
            }

            ap_log_error(APLOG_MARK, APLOG_INFO, rv, s,
                    APLOGNO(10438) "The crypto library '%s' was loaded successfully",
                    conf->library);

        }

        s = s->next;
    }

    return OK;
}

static void *create_auth_bearer_config(apr_pool_t * p, server_rec *s)
{
    auth_bearer_conf *new =
    (auth_bearer_conf *) apr_pcalloc(p, sizeof(auth_bearer_conf));

    /* if no library has been configured, set the recommended library
     * as a sensible default.
     */
#ifdef APU_CRYPTO_RECOMMENDED_DRIVER
    new->library = APU_CRYPTO_RECOMMENDED_DRIVER;
#endif
    new->crypto = apr_pcalloc(p, sizeof(apr_crypto_t *));

    return (void *) new;
}

static void *merge_auth_bearer_config(apr_pool_t * p, void *basev, void *addv)
{
    auth_bearer_conf *new = (auth_bearer_conf *) apr_pcalloc(p, sizeof(auth_bearer_conf));
    auth_bearer_conf *add = (auth_bearer_conf *) addv;
    auth_bearer_conf *base = (auth_bearer_conf *) basev;

    new->library = (add->library_set == 0) ? base->library : add->library;
    new->params = (add->library_set == 0) ? base->params : add->params;
    new->library_set = add->library_set || base->library_set;

    new->crypto = base->crypto;

    return (void *) new;
}

static void *create_auth_bearer_dir_config(apr_pool_t *p, char *d)
{
    auth_bearer_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    conf->claims = apr_hash_make(p);
    conf->signs = apr_array_make(p, 1, sizeof(auth_bearer_signature_rec));
    conf->verifies = apr_array_make(p, 1, sizeof(auth_bearer_signature_rec));

    return conf;
}

static void *merge_auth_bearer_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    auth_bearer_config_rec *newconf = apr_pcalloc(p, sizeof(*newconf));
    auth_bearer_config_rec *base = basev;
    auth_bearer_config_rec *overrides = overridesv;

    newconf->claims = apr_hash_overlay(p, overrides->claims,
                                          base->claims);

    newconf->signs =
            overrides->signs_set ? overrides->signs : base->signs;
    newconf->signs_set = overrides->signs_set || base->signs_set;

    newconf->verifies =
            overrides->verifies_set ? overrides->verifies : base->verifies;
    newconf->verifies_set = overrides->verifies_set || base->verifies_set;

    return newconf;
}

static const char *set_jwt_claim(cmd_parms *cmd, void *config,
        const char *op, const char *key, const char *expression)
{
    auth_bearer_config_rec *conf = (auth_bearer_config_rec *) config;
    const char *err;

    if (!strcasecmp(op, "set")) {
        ap_expr_info_t *expr;

        expr = ap_expr_parse_cmd(cmd, expression, AP_EXPR_FLAG_STRING_RESULT,
                &err, NULL);
        if (err) {
            return apr_psprintf(cmd->pool,
                    "Could not parse claim '%s' expression '%s': %s", key,
                    expression, err);
        }

        apr_hash_set(conf->claims, key, APR_HASH_KEY_STRING, expr);

    } else if (!strcasecmp(op, "unset")) {

        apr_hash_set(conf->claims, key, APR_HASH_KEY_STRING, NULL);

    } else {

        return apr_psprintf(cmd->pool,
                "Could not parse claim operation '%s', "
                "values should be 'set' or 'unset'", op);

    }

    return NULL;
}

static const char *set_jwt_sign(cmd_parms * cmd, void *config,
        const char *alg, const char *type, const char *sig)
{
    auth_bearer_config_rec *dconf = (auth_bearer_config_rec *) config;

    auth_bearer_signature_rec *srec = apr_array_push(dconf->signs);

    /* handle the algorithm */
    if (!strcasecmp(alg, "none")) {
        srec->jws_alg = JWS_ALG_TYPE_NONE;
        if (type || sig) {
            return "AuthtJwtSign: algorithm 'none' has extra parameters";
        }
    }
    else if (!strcasecmp(alg, "HS256")) {
        srec->jws_alg = JWS_ALG_TYPE_HS256;
    }
    else {
        return apr_psprintf(cmd->pool, "AuthtJwtSign: algorithm not supported: %s", alg);
    }

    /* handle the file */
    if (type) {
        if (!strcasecmp(type, "file")) {
            apr_file_t *file;
            apr_finfo_t finfo;
            apr_status_t status;

            sig = ap_server_root_relative(cmd->temp_pool, sig);

            status = apr_file_open(&file, sig, APR_READ | APR_BUFFERED,
            APR_OS_DEFAULT, cmd->pool);
            if (status != APR_SUCCESS) {
                char buf[1024];
                apr_strerror(status, buf, sizeof(buf));
                return apr_psprintf(cmd->pool,
                        "AuthtJwtSign: file '%s' could not be opened: %s", sig,
                        buf);
            }

            status = apr_file_info_get(&finfo, APR_FINFO_TYPE | APR_FINFO_SIZE,
                    file);
            if (status != APR_SUCCESS) {
                char buf[1024];
                apr_strerror(status, buf, sizeof(buf));
                return apr_psprintf(cmd->pool,
                        "AuthtJwtSign: info could not be obtained for '%s': %s",
                        sig, buf);
            }

            srec->secret = apr_palloc(cmd->pool, finfo.size);
            srec->secret_len = finfo.size;

            status = apr_file_read_full(file, srec->secret,
                    srec->secret_len, NULL);
            if (status != APR_SUCCESS) {
                char buf[1024];
                apr_strerror(status, buf, sizeof(buf));
                return apr_psprintf(cmd->pool,
                        "AuthtJwtSign: file '%s' could not be read: %s", sig,
                        buf);
            }

            apr_file_close(file);

        }
        else {
            return apr_psprintf(cmd->pool,
                    "AuthtJwtSign: parameter '%s' is not 'file'", type);
        }
    }

    dconf->signs_set = 1;

    return NULL;
}

static const char *set_jwt_verify(cmd_parms * cmd, void *config,
        const char *alg, const char *type, const char *sig)
{
    auth_bearer_config_rec *dconf = (auth_bearer_config_rec *) config;

    auth_bearer_signature_rec *srec = apr_array_push(dconf->verifies);

    /* handle the algorithm */
    if (!strcasecmp(alg, "none")) {
        srec->jws_alg = JWS_ALG_TYPE_NONE;
        if (type || sig) {
            return "AuthtJwtVerify: algorithm 'none' has extra parameters";
        }
    }
    else if (!strcasecmp(alg, "HS256")) {
        srec->jws_alg = JWS_ALG_TYPE_HS256;
    }
    else {
        return apr_psprintf(cmd->pool, "AuthtJwtVerify: algorithm not supported: %s", alg);
    }

    /* handle the file */
    if (type) {
        if (!strcasecmp(type, "file")) {
            apr_file_t *file;
            apr_finfo_t finfo;
            apr_status_t status;

            sig = ap_server_root_relative(cmd->temp_pool, sig);

            status = apr_file_open(&file, sig, APR_READ | APR_BUFFERED,
            APR_OS_DEFAULT, cmd->pool);
            if (status != APR_SUCCESS) {
                char buf[1024];
                apr_strerror(status, buf, sizeof(buf));
                return apr_psprintf(cmd->pool,
                        "AuthtJwtVerify: file '%s' could not be opened: %s", sig,
                        buf);
            }

            status = apr_file_info_get(&finfo, APR_FINFO_TYPE | APR_FINFO_SIZE,
                    file);
            if (status != APR_SUCCESS) {
                char buf[1024];
                apr_strerror(status, buf, sizeof(buf));
                return apr_psprintf(cmd->pool,
                        "AuthtJwtVerify: info could not be obtained for '%s': %s",
                        sig, buf);
            }

            srec->secret = apr_palloc(cmd->pool, finfo.size);
            srec->secret_len = finfo.size;

            status = apr_file_read_full(file, srec->secret,
                    srec->secret_len, NULL);
            if (status != APR_SUCCESS) {
                char buf[1024];
                apr_strerror(status, buf, sizeof(buf));
                return apr_psprintf(cmd->pool,
                        "AuthtJwtVerify: file '%s' could not be read: %s", sig,
                        buf);
            }

            apr_file_close(file);

        }
        else {
            return apr_psprintf(cmd->pool,
                    "AuthtJwtVerify: parameter '%s' is not 'file'", type);
        }
    }

    dconf->verifies_set = 1;

    return NULL;
}

static const char *set_jwt_driver(cmd_parms * cmd, void *config, const char *arg)
{
    auth_bearer_conf *conf =
            (auth_bearer_conf *)ap_get_module_config(cmd->server->module_config,
            &autht_jwt_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    conf->library = ap_getword_conf(cmd->pool, &arg);
    conf->params = arg;
    conf->library_set = 1;

    return NULL;
}

static const command_rec auth_bearer_cmds[] =
{
    AP_INIT_TAKE13("AuthtJwtVerify", set_jwt_verify, NULL, RSRC_CONF|OR_AUTHCFG,
                   "The JWS signing algorithm and passphrase/key to verify an incoming JWT token"),
    AP_INIT_TAKE13("AuthtJwtSign", set_jwt_sign, NULL, RSRC_CONF|OR_AUTHCFG,
            "The JWS signing algorithm and passphrase/key to sign an outgoing JWT token"),

    AP_INIT_TAKE23("AuthtJwtClaim", set_jwt_claim, NULL, OR_AUTHCFG,
            "Set a claim with the given name and expression, or "
            "unset the claim with the given name."),

    AP_INIT_RAW_ARGS("AuthtJwtDriver", set_jwt_driver, NULL, RSRC_CONF,
            "The underlying crypto library driver to use"),

    {NULL}
};

typedef struct claim_iter_t {
    request_rec *r;
    apr_json_value_t *object;
} claim_iter_t;

static int claim_iter(void *ctx, const void *key, apr_ssize_t klen,
                     const void *val)
{
    const char *err, *value;
    claim_iter_t *iter = ctx;
    request_rec *r = iter->r;

    value = ap_expr_str_exec(r, val, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10439)
                "AuthtJwtClaim: could not evaluate '%s' expression "
                "'%s' for URI '%s': %s",
                (char * )key, (char * )val, r->uri, err);
        return FALSE;
    }


    apr_json_object_set(iter->object, key, klen,
            apr_json_string_create(r->pool, value, strlen(value)), r->pool);

    return TRUE;
}

static apr_status_t sign_cb(apr_bucket_brigade *bb, apr_jose_t *jose,
        apr_jose_signature_t *signature, void *ctx, apr_pool_t *pool) {
    auth_bearer_signature_rec *srec = NULL;
    request_rec *r = ctx;

    auth_bearer_conf *sconf = ap_get_module_config(r->server->module_config,
            &autht_jwt_module);

    auth_bearer_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &autht_jwt_module);

    if (conf->signs_set) {
        srec = (auth_bearer_signature_rec *) conf->signs->elts;
    }

    if (srec) {
        switch (srec->jws_alg) {
        case JWS_ALG_TYPE_NONE: {

            return APR_SUCCESS;
        }
        case JWS_ALG_TYPE_HS256: {
            apr_bucket *e;
            apr_crypto_key_rec_t *krec;
            apr_crypto_key_t *key = NULL;
            apr_crypto_digest_t *digest = NULL;
            apr_crypto_digest_rec_t *rec;
            char * buf;
            apr_status_t status;

            if (!*sconf->crypto) {
                jose->result.msg = "token could not be signed";
                jose->result.reason = "no crypto driver configured (set AuthtJwtDriver)";
                return APR_EGENERAL;
            }

            krec = apr_crypto_key_rec_make(APR_CRYPTO_KTYPE_HMAC, pool);

            krec->k.hmac.digest = APR_CRYPTO_DIGEST_SHA256;
            krec->k.hmac.secret = srec->secret;
            krec->k.hmac.secretLen = srec->secret_len;

            status = apr_crypto_key(&key, krec, *sconf->crypto, pool);
            if (status != APR_SUCCESS) {
                jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                apr_strerror(status, buf, HUGE_STRING_LEN);
                jose->result.msg = "token could not be signed";
                return status;
            }

            rec = apr_crypto_digest_rec_make(APR_CRYPTO_DTYPE_SIGN, pool);

            status = apr_crypto_digest_init(&digest, key, rec, pool);
            if (status != APR_SUCCESS) {
                jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                apr_strerror(status, buf, HUGE_STRING_LEN);
                jose->result.msg = "token could not be signed";
                return status;
            }

            for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e =
                    APR_BUCKET_NEXT(e)) {
                const char *str;
                apr_size_t len;

                /* If we see an EOS, don't bother doing anything more. */
                if (APR_BUCKET_IS_EOS(e)) {
                    break;
                }

                status = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
                if (status != APR_SUCCESS) {
                    jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                    apr_strerror(status, buf, HUGE_STRING_LEN);
                    jose->result.msg = "token could not be signed";
                    return status;
                }

                status = apr_crypto_digest_update(digest,
                        (const unsigned char *) str, len);
                if (status != APR_SUCCESS) {
                    jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                    apr_strerror(status, buf, HUGE_STRING_LEN);
                    jose->result.msg = "token could not be signed";
                    return status;
                }
            }

            status = apr_crypto_digest_final(digest);
            if (status != APR_SUCCESS) {
                jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                apr_strerror(status, buf, HUGE_STRING_LEN);
                jose->result.msg = "token could not be signed";
                return status;
            }

            signature->sig.data = rec->d.sign.s;
            signature->sig.len = rec->d.sign.slen;

            return APR_SUCCESS;
        }
        }
    }
    else {
        /* algorithm is none */
        return APR_SUCCESS;
    }

    return APR_ENOTIMPL;
}

/* If we have set claims to be made, create a JWT token.
 */
static const char *jwt_get_token(request_rec *r)
{
    claim_iter_t iter = { 0 };
    apr_json_value_t *claims;
    apr_json_value_t *protect;
    apr_jose_t jwt = { 0 };
    apr_jose_t jws = { 0 };
    apr_jose_signature_t signature = { 0 };
    auth_bearer_signature_rec *srec = NULL;
    apr_bucket_brigade *bb;
    char *auth_line;
    apr_size_t len;
    apr_off_t offset;
    apr_status_t status;

    auth_bearer_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &autht_jwt_module);

    apr_jose_cb_t cb = { 0 };

    cb.sign = sign_cb;
    cb.ctx = r;

    if (!conf->claims || !apr_hash_count(conf->claims)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                APLOGNO(10440) "AuthtJwtClaim: could not encode a JWT token for URI '%s': no claims",
                r->uri);
        return "error:no-claims";
    }

    /* sign with the first key, if present */
    if (conf->signs_set) {
        srec = (auth_bearer_signature_rec *)conf->signs->elts;
    }

    /* create a JWT containing the claims */
    claims = apr_json_object_create(r->pool);
    iter.object = claims;
    iter.r = r;

    /* iterate through our claims */
    if (!apr_hash_do(claim_iter, &iter, conf->claims)) {
        return "error:claim-failed";
    }

    apr_jose_jwt_make(&jwt, claims, r->pool);
    protect = apr_json_object_create(r->pool);

    apr_json_object_set(protect, APR_JOSE_JWSE_TYPE,
            APR_JSON_VALUE_STRING,
            apr_json_string_create(r->pool, APR_JOSE_JWSE_TYPE_JWT,
                    APR_JSON_VALUE_STRING), r->pool);

    if (srec) {
        /* which signature type do we have? */
        switch (srec->jws_alg) {
        case JWS_ALG_TYPE_NONE: {
            apr_json_object_set(protect, APR_JOSE_JWKSE_ALGORITHM,
                    APR_JSON_VALUE_STRING,
                    apr_json_string_create(r->pool, APR_JOSE_JWA_NONE,
                            APR_JSON_VALUE_STRING), r->pool);

            break;
        }
        case JWS_ALG_TYPE_HS256: {
            apr_json_object_set(protect, APR_JOSE_JWKSE_ALGORITHM,
                    APR_JSON_VALUE_STRING,
                    apr_json_string_create(r->pool, APR_JOSE_JWA_HS256,
                            APR_JSON_VALUE_STRING), r->pool);

            break;
        }
        }

    }
    else {
        /* no srec defaults to none */
        apr_json_object_set(protect, APR_JOSE_JWKSE_ALGORITHM,
                APR_JSON_VALUE_STRING,
                apr_json_string_create(r->pool, APR_JOSE_JWA_NONE,
                        APR_JSON_VALUE_STRING), r->pool);
    }

    apr_jose_signature_make(&signature, NULL, protect, r->pool);
    apr_jose_jws_make(&jws, &signature, NULL, &jwt, r->pool);

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    status = apr_jose_encode(bb, NULL, NULL, &jws, &cb, r->pool);
    if (APR_SUCCESS != status) {
        const apu_err_t *err = apr_jose_error(&jws);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                APLOGNO(10441) "AuthtJwtClaim: could not encode a JWT token for URI '%s': %s: %s",
                r->uri, err->msg, err->reason);
        return "error:could-not-encode";
    }

    apr_brigade_length(bb, 1, &offset);
    auth_line = apr_pcalloc(r->pool, offset + 1);
    len = offset;
    apr_brigade_flatten(bb, auth_line, &len);
    auth_line[offset] = 0;

    return auth_line;
}

static const char *jwt_expr_var_fn(ap_expr_eval_ctx_t *ctx, const void *data)
{
    char *var = (char *)data;

    if (var && *var && ctx->r && ap_cstr_casecmp(var, "TOKEN") == 0) {
        return jwt_get_token(ctx->r);
    }
    return NULL;
}

static int jwt_expr_lookup(ap_expr_lookup_parms *parms)
{
    switch (parms->type) {
    case AP_EXPR_FUNC_VAR:
        /* for now, we just handle everything that starts with JWT_.
         */
        if (strncasecmp(parms->name, "JWT_", 4) == 0) {
            *parms->func = jwt_expr_var_fn;
            *parms->data = parms->name + 4;
            return OK;
        }
        break;
    }
    return DECLINED;
}

static apr_status_t verify_cb(apr_bucket_brigade *bb,
        apr_jose_t *jose, apr_jose_signature_t *signature, void *ctx,
        int *vflags, apr_pool_t *pool)
{
    request_rec *r = ctx;
    apr_json_kv_t *alg = NULL;

    auth_bearer_conf *sconf = ap_get_module_config(r->server->module_config,
            &autht_jwt_module);

    auth_bearer_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &autht_jwt_module);

    int alg_supported = 0;

    if (signature) {
        apr_json_value_t *ph = signature->protected_header;

        if (ph && ph->type == APR_JSON_OBJECT) {

            alg = apr_json_object_get(ph, APR_JOSE_JWKSE_ALGORITHM,
                    APR_JSON_VALUE_STRING);

        }
    }

    if (!alg) {
        apr_errprintf(&jose->result, r->pool, "", APR_EGENERAL,
                "JWT token protected header has no '"
                APR_JOSE_JWKSE_ALGORITHM
                "' for URI '%s'",
                r->uri);
        return APR_EGENERAL;
    }

    if (alg->v->type != APR_JSON_STRING) {
        apr_errprintf(&jose->result, r->pool, "", APR_EGENERAL,
                "JWT token protected header '"
                APR_JOSE_JWKSE_ALGORITHM
                "' is not a string for URI '%s'",
                r->uri);
        return APR_EGENERAL;
    }

    /* first pass, is our algorithm supported? */
    for (int i = 0; i < conf->verifies->nelts; i++) {
    	auth_bearer_signature_rec *srec = &APR_ARRAY_IDX(conf->verifies,
    			i, auth_bearer_signature_rec);

    	/* which signature type do we have? */
    	switch (srec->jws_alg) {
    	case JWS_ALG_TYPE_NONE: {
        	if (!strncmp(alg->v->value.string.p, "none",
                        alg->v->value.string.len)) {
        		alg_supported = 1;
        	}
        	break;
    	}
    	case JWS_ALG_TYPE_HS256: {
        	if (!strncmp(alg->v->value.string.p, "HS256",
        			alg->v->value.string.len)) {
        		alg_supported = 1;
        	}
    		break;
    	}
    	}

    }

    /* we don't support the algorithm */
    if (!alg_supported) {
    	apr_errprintf(&jose->result, r->pool, "", APR_ENODIGEST,
    			"JWT token protected header '"
    			APR_JOSE_JWKSE_ALGORITHM
				"' %s is not supported for URI '%s'",
				alg->v->value.string.p, r->uri);
    	return APR_ENODIGEST;
    }

    /* second pass, does the signature match? */
    for (int i = 0; i < conf->verifies->nelts; i++) {
    	auth_bearer_signature_rec *srec = &APR_ARRAY_IDX(conf->verifies,
    			i, auth_bearer_signature_rec);

    	/* which signature type do we have? */
    	switch (srec->jws_alg) {
    	case JWS_ALG_TYPE_NONE: {
        	if (!strncmp(alg->v->value.string.p, "none",
                        alg->v->value.string.len)) {
        		return APR_SUCCESS;
        	}
        	break;
    	}
    	case JWS_ALG_TYPE_HS256: {
        	if (!strncmp(alg->v->value.string.p, "HS256",
        			alg->v->value.string.len)) {

                apr_bucket *e;
                apr_crypto_key_rec_t *krec;
                apr_crypto_key_t *key = NULL;
                apr_crypto_digest_t *digest = NULL;
                apr_crypto_digest_rec_t *rec;
                char * buf;
                apr_status_t status;

                if (!*sconf->crypto) {
                    jose->result.msg = "token could not be verified";
                    jose->result.reason = "no crypto driver configured (set AuthtJwtDriver)";
                    return APR_EGENERAL;
                }

                krec = apr_crypto_key_rec_make(APR_CRYPTO_KTYPE_HMAC, pool);

                krec->k.hmac.digest = APR_CRYPTO_DIGEST_SHA256;
                krec->k.hmac.secret = srec->secret;
                krec->k.hmac.secretLen = srec->secret_len;

                status = apr_crypto_key(&key, krec, *sconf->crypto, pool);
                if (status != APR_SUCCESS) {
                    jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                    apr_strerror(status, buf, HUGE_STRING_LEN);
                    jose->result.msg = "token could not be verified";
                    return status;
                }

                rec = apr_crypto_digest_rec_make(APR_CRYPTO_DTYPE_SIGN, pool);

                status = apr_crypto_digest_init(&digest, key, rec, pool);
                if (status != APR_SUCCESS) {
                    jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                    apr_strerror(status, buf, HUGE_STRING_LEN);
                    jose->result.msg = "token could not be verified";
                    return status;
                }

                for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e =
                        APR_BUCKET_NEXT(e)) {
                    const char *str;
                    apr_size_t len;

                    /* If we see an EOS, don't bother doing anything more. */
                    if (APR_BUCKET_IS_EOS(e)) {
                        break;
                    }

                    status = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
                    if (status != APR_SUCCESS) {
                        jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                        apr_strerror(status, buf, HUGE_STRING_LEN);
                        jose->result.msg = "token could not be verified";
                        return status;
                    }

                    status = apr_crypto_digest_update(digest,
                            (const unsigned char *) str, len);
                    if (status != APR_SUCCESS) {
                        jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                        apr_strerror(status, buf, HUGE_STRING_LEN);
                        jose->result.msg = "token could not be verified";
                        return status;
                    }
                }

                status = apr_crypto_digest_final(digest);
                if (status != APR_SUCCESS) {
                    jose->result.reason = buf = apr_pcalloc(pool, HUGE_STRING_LEN);
                    apr_strerror(status, buf, HUGE_STRING_LEN);
                    jose->result.msg = "token could not be verified";
                    return status;
                }

                if (signature->sig.len == rec->d.sign.slen &&
                		!memcmp(signature->sig.data, rec->d.sign.s, rec->d.sign.slen)) {
                    return APR_SUCCESS;
                }

        	}
    		break;
    	}
    	}

    }

    /* no match, oh well */
	apr_errprintf(&jose->result, r->pool, "", APR_ENODIGEST,
			"JWT token protected header '"
			APR_JOSE_JWKSE_ALGORITHM
			"' %s is not supported for URI '%s'",
			alg->v->value.string.p, r->uri);
    return APR_ENOVERIFY;
}

static autht_status check_token(request_rec *r, const char *type,
                                   const char *token)
{
    apr_bucket_brigade *bb;
    apr_jose_t *jose = NULL;
    apr_json_kv_t *kv;
    apr_status_t status;

    apr_jose_cb_t cb;

    apr_table_t *e = r->subprocess_env;

    const char *aud = NULL;
    const char *sub = NULL;

    apr_int64_t exp;
    apr_int64_t nbf;

    int exp_set = 0;
    int nbf_set = 0;

    cb.verify = verify_cb;
    cb.decrypt = NULL;
    cb.ctx = r;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    if (token) {
        apr_brigade_write(bb, NULL, NULL, token, strlen(token));
    }

    status = apr_jose_decode(&jose, "JWT", bb, &cb, 10, APR_JOSE_FLAG_NONE, r->pool);

    if (APR_SUCCESS != status) {
        const apu_err_t *err = apr_jose_error(jose);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                APLOGNO(10442) "AuthtJwt: could not decode a JWT token for URI '%s': %s: %s",
                r->uri, err->msg, err->reason);
        return AUTHT_DENIED;
    }

    if (jose->type != APR_JOSE_TYPE_JWT) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                APLOGNO(10443) "AuthtJwt: JOSE token was not a JWT token for URI '%s'",
                r->uri);
        return AUTHT_DENIED;
    }

    /* first pass - identity sub and aud */
    kv = apr_json_object_first(jose->jose.jwt->claims);
    do {

        /* ignore any key that isn't a string */
        if (kv->k->type != APR_JSON_STRING) {
            continue;
        }

        if (!strncmp("aud", kv->k->value.string.p, kv->k->value.string.len)) {
            if (kv->v->type == APR_JSON_STRING) {
                aud = apr_pstrndup(r->pool, kv->v->value.string.p,
                        kv->v->value.string.len);
            }
        }

        if (!strncmp("sub", kv->k->value.string.p, kv->k->value.string.len)) {
            if (kv->v->type == APR_JSON_STRING) {
                sub = apr_pstrndup(r->pool, kv->v->value.string.p,
                        kv->v->value.string.len);
            }
        }

        if (!strncmp("exp", kv->k->value.string.p, kv->k->value.string.len)) {
            if (kv->v->type == APR_JSON_LONG) {
                exp = kv->v->value.lnumber;
                exp_set = 1;
            }
        }

        if (!strncmp("nbf", kv->k->value.string.p, kv->k->value.string.len)) {
            if (kv->v->type == APR_JSON_LONG) {
                nbf = kv->v->value.lnumber;
                nbf_set = 1;
            }
        }


    } while ((kv = apr_json_object_next(jose->jose.jwt->claims, kv)));

    if (!aud) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                APLOGNO(10444) "AuthtJwt: JWT token 'aud' value was missing and did not match AuthName '%s' for URI '%s'",
                ap_auth_name(r), r->uri);
        return AUTHT_MISMATCH;
    }

    if (strcmp(aud, ap_auth_name(r))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                APLOGNO(10445) "AuthtJwt: JWT token 'aud' value '%s' did not match AuthName '%s' for URI '%s'",
                aud, ap_auth_name(r), r->uri);
        return AUTHT_MISMATCH;
    }

    if (exp_set || nbf_set) {
        apr_time_t now = apr_time_now();

        if (exp_set &&
                exp < apr_time_sec(now)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                    APLOGNO(10446) "AuthtJwt: JWT token is expired (%"
                    APR_INT64_T_FMT " < %" APR_TIME_T_FMT ") for URI '%s'",
                    exp, apr_time_sec(now), r->uri);
            return AUTHT_EXPIRED;
        }

        if (nbf_set &&
                nbf > apr_time_sec(now)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                    APLOGNO(10447) "AuthtJwt: JWT token is not yet valid (%"
                    APR_INT64_T_FMT " > %" APR_TIME_T_FMT ") for URI '%s'",
                    nbf, apr_time_sec(now), r->uri);
            return AUTHT_INVALID;
        }
    }

    /* we are good at this point - accept the token */

    if (sub) {
        r->user = apr_pstrdup(r->pool, sub);
    }

    /* second pass - add all string claims to the environment, prefixed by TOKEN_ */
    kv = apr_json_object_first(jose->jose.jwt->claims);
    do {
        char *key, *val;
        int j;

        /* ignore anything that isn't a string */
        if (kv->k->type != APR_JSON_STRING || kv->v->type != APR_JSON_STRING) {
            continue;
        }

        key = apr_psprintf(r->pool, AUTHT_PREFIX "%.*s", (int)kv->k->value.string.len, kv->k->value.string.p);
        j = sizeof(AUTHT_PREFIX);
        while (key[j]) {
            if (apr_isalnum(key[j])) {
                key[j] = apr_toupper(key[j]);
            }
            else {
                key[j] = '_';
            }
            j++;
        }

        val = apr_pstrndup(r->pool, kv->v->value.string.p,
                kv->v->value.string.len);

        apr_table_setn(e, key, val);

    } while ((kv = apr_json_object_next(jose->jose.jwt->claims, kv)));

    return AUTHT_GRANTED;
}

static const autht_provider autht_jwt_provider =
{
    &check_token
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHT_PROVIDER_GROUP, "jwt",
                              AUTHT_PROVIDER_VERSION,
                              &autht_jwt_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_expr_lookup(jwt_expr_lookup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(auth_bearer_init, NULL, NULL, APR_HOOK_LAST);
}

AP_DECLARE_MODULE(autht_jwt) =
{
    STANDARD20_MODULE_STUFF,
    create_auth_bearer_dir_config,  /* dir config creater */
    merge_auth_bearer_dir_config,   /* dir merger --- default is to override */
    create_auth_bearer_config,      /* server config */
    merge_auth_bearer_config,       /* merge server config */
    auth_bearer_cmds,               /* command apr_table_t */
    register_hooks                  /* register hooks */
};

#else

static const command_rec auth_bearer_cmds[] =
{
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
}

AP_DECLARE_MODULE(autht_jwt) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                           /* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    auth_bearer_cmds,               /* command apr_table_t */
    register_hooks                  /* register hooks */
};

#endif /* HAVE_APU_JOSE */

