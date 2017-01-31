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

/*
 * mod_crypto.c --- Encrypt / decrypt data in the input and output filter
 *                  stacks.
 */

#include "apr_version.h"
#if !APR_VERSION_AT_LEAST(2,0,0)
#include "apu_version.h"
#endif

#if !APR_VERSION_AT_LEAST(2,0,0) && \
    !(APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 6)
#error This module requires at least v1.6.0 of apr-util.
#else

#include "mod_crypto.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_crypto.h"
#include "apr_base64.h"
#include "apr_escape.h"
#include "util_filter.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "ap_expr.h"

APR_HOOK_STRUCT(APR_HOOK_LINK(crypto_key)
                APR_HOOK_LINK(crypto_iv))
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, CRYPTO, apr_status_t, crypto_key,
                                      (request_rec *r,
                                      apr_crypto_block_key_type_t * cipher,
                                      apr_crypto_block_key_mode_t * mode,
                                      int pad,
                                      const apr_crypto_key_rec_t ** rec),
                                      (r, cipher, mode, pad, rec), DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, CRYPTO, apr_status_t, crypto_iv,
                                      (request_rec *r,
                                      apr_crypto_block_key_type_t * cipher,
                                      const unsigned char **iv), (r, cipher,
                                      iv), DECLINED)
module AP_MODULE_DECLARE_DATA crypto_module;

#define DEFAULT_BUFFER_SIZE 128*1024
#define DEFAULT_CIPHER "aes256"
#define DEFAULT_MODE "cbc"
#define CRYPTO_KEY "crypto_context"

typedef struct pass_conf
{
    const char *scheme;
    const ap_expr_info_t *expr;
    unsigned char *raw;
    apr_size_t size;
} pass_conf;

/**
 * Structure to carry the server wide session config.
 */
typedef struct
{
    const char *library;
    const char *params;
    apr_crypto_t **crypto;
    int library_set;
} crypto_conf;

typedef struct crypto_dir_conf
{
    apr_off_t size;        /* size of the buffer */
    int size_set;          /* has the size been set */
    const char *cipher;
    const char *mode;
    int cipher_set;
    pass_conf *key;
    int key_set;
    pass_conf *iv;
    int iv_set;
} crypto_dir_conf;

typedef struct crypto_ctx
{
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmp;
    crypto_dir_conf *conf;
    unsigned char *out;
    apr_crypto_key_t *key;
    apr_crypto_block_key_type_t *cipher;
    apr_crypto_block_key_mode_t *mode;
    apr_crypto_block_t *block;
    const unsigned char *iv;
    apr_off_t remaining;
    apr_off_t written;
    apr_size_t osize;
    int seen_eos:1;
    int encrypt:1;
    int clength:1;
} crypto_ctx;

static const char *parse_pass_conf_binary(cmd_parms *cmd,
                                          pass_conf * pass,
                                          const char *arg)
{
    apr_status_t rv;
    char ps = *arg;

    if ('f' == ps && !strncmp(arg, "file:", 5)) {
        const char *name;

        arg += 5;
        if (!*arg) {
            return apr_pstrcat(cmd->pool, "No filename specified", NULL);
        }

        name = ap_server_root_relative(cmd->temp_pool, arg);
        if (name) {
            apr_file_t *file;

            rv = apr_file_open(&file, name, APR_FOPEN_READ,
                               APR_FPROT_OS_DEFAULT, cmd->temp_pool);
            if (APR_SUCCESS == rv) {
                apr_finfo_t finfo;

                rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, file);
                if (rv == APR_SUCCESS) {
                    apr_size_t size;

                    pass->scheme = "file";
                    pass->raw = apr_palloc(cmd->pool, finfo.size);
                    pass->size = finfo.size;
                    apr_crypto_clear(cmd->pool, pass->raw, pass->size);

                    rv = apr_file_read_full(file, pass->raw, pass->size,
                                            &size);
                    if (APR_SUCCESS == rv && size != pass->size) {
                        rv = APR_EGENERAL;
                    }

                }
            }
            if (APR_SUCCESS != rv) {
                char buf[120];
                return apr_pstrcat(cmd->pool, "Unable to load from file '",
                                   arg, "': ", apr_strerror(rv, buf,
                                                            sizeof(buf)),
                                   NULL);
            }
        }
        else {
            return apr_pstrcat(cmd->pool, "Unable to locate file from name ",
                               arg, NULL);
        }
    }

    else if ('h' == ps && (!strncmp(arg, "hex:", 4))) {
        const char *expr_err = NULL;
        arg += 4;

        if (!*arg) {
            return apr_pstrcat(cmd->temp_pool,
                               "Cannot parse expression, it is blank", NULL);
        }

        pass->scheme = "hex";
        pass->expr = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
                                       &expr_err, NULL);

        if (expr_err) {
            return apr_pstrcat(cmd->temp_pool, "Cannot parse ", pass->scheme,
                               " expression '", arg, "' in: ", expr_err,
                               NULL);
        }

    }

    else if ('b' == ps && !strncmp(arg, "base64:", 7)) {
        const char *expr_err = NULL;
        arg += 7;

        if (!*arg) {
            return apr_pstrcat(cmd->temp_pool,
                               "Cannot parse expression, it is blank", NULL);
        }

        pass->scheme = "base64";
        pass->expr = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
                                       &expr_err, NULL);

        if (expr_err) {
            return apr_pstrcat(cmd->temp_pool, "Cannot parse ", pass->scheme,
                               " expression '", arg, "' in: ", expr_err,
                               NULL);
        }

    }

    else if ('d' == ps && !strncmp(arg, "decimal:", 8)) {
        const char *expr_err = NULL;
        arg += 8;

        if (!*arg) {
            return apr_pstrcat(cmd->temp_pool,
                               "Cannot parse expression, it is blank", NULL);
        }

        pass->scheme = "decimal";
        pass->expr = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT,
                                       &expr_err, NULL);

        if (expr_err) {
            return apr_pstrcat(cmd->temp_pool, "Cannot parse ", pass->scheme,
                               " expression '", arg, "' in: ", expr_err,
                               NULL);
        }

    }

    else if ('n' == ps && !strcmp(arg, "none")) {
        pass->scheme = arg;
    }

    else {
        return apr_pstrcat(cmd->pool,
                           "Scheme must be 'file:', 'hex:', 'base64:', 'decimal:' or 'none': ",
                           arg, NULL);
    }

    return NULL;
}

static apr_status_t
exec_pass_conf_binary(request_rec *r, pass_conf * pass,
                      const char *description, apr_size_t size,
                      const unsigned char **k)
{

    if (pass) {

        if (pass->raw) {
            *k = pass->raw;

            if (size != pass->size) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r,
                              APLOGNO(03409) "%s has wrong size (was %"
                              APR_SIZE_T_FMT ", must be %" APR_SIZE_T_FMT ")",
                              description, pass->size, size);
                return APR_EGENERAL;
            }

            return APR_SUCCESS;
        }

        else if (pass->expr) {
            char ps = *pass->scheme;
            const char *err = NULL;

            const char *arg = ap_expr_str_exec(r, pass->expr, &err);
            if (err) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r,
                              APLOGNO(03410) "%s could not be parsed: %s",
                              description, err);
                return APR_EGENERAL;
            }

            /* hex */
            if ('h' == ps) {
                apr_size_t len;
                unsigned char *b;

                apr_unescape_hex(NULL, arg, strlen(arg), 1, &len);
                if (len < size) {
                    b = apr_palloc(r->pool, size);
                    memset(b, 0, size - len);
                    apr_unescape_hex(b + size - len, arg, strlen(arg), 1,
                                     &len);
                }
                else {
                    b = apr_palloc(r->pool, len);
                    apr_unescape_hex(b, arg, strlen(arg), 1, NULL);
                    b += len - size;
                }
                *k = b;

            }

            /* base64 */
            else if ('b' == ps) {
                apr_size_t len;
                unsigned char *b;

                len = apr_base64_decode_len(arg);
                if (len < size) {
                    b = apr_palloc(r->pool, size);
                    memset(b, 0, size - len);
                    apr_base64_decode_binary(b + size - len, arg);
                }
                else {
                    b = apr_palloc(r->pool, len);
                    apr_base64_decode_binary(b, arg);
                    b += len - size;
                }
                *k = b;

            }

            /* decimal */
            else if ('d' == ps) {
                apr_size_t len;
                unsigned char *b;
                char n[8];
                apr_uint64_t t;
                int i;

                t = (apr_uint64_t) apr_atoi64(arg);

                for (i = 7; i >= 0; i--) {
                    n[i] = t & 0xFF;
                    t = t >> 8;
                }

                len = sizeof(n);
                if (len < size) {
                    b = apr_palloc(r->pool, size);
                    memset(b, 0, size - len);
                    memcpy(b + size - len, n, len);
                }
                else {
                    b = apr_palloc(r->pool, len);
                    memcpy(b, n, len);
                    b += len - size;
                }
                *k = b;

            }

        }

    }

    return DECLINED;
}

static apr_status_t
init_cipher(request_rec *r,
            apr_crypto_block_key_type_t ** cipher,
            apr_crypto_block_key_mode_t ** mode)
{
    apr_status_t rv;
    apr_hash_t *ciphers;
    apr_hash_t *modes;

    crypto_conf *conf = ap_get_module_config(r->server->module_config,
                                             &crypto_module);
    crypto_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                  &crypto_module);

    if (cipher) {

        rv = apr_crypto_get_block_key_types(&ciphers, *conf->crypto);
        if (APR_SUCCESS != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(03411) "no ciphers returned by APR");
            return rv;
        }

        *cipher = apr_hash_get(ciphers, dconf->cipher, APR_HASH_KEY_STRING);
        if (!*cipher) {
            apr_hash_index_t *hi;
            const void *key;
            apr_ssize_t klen;
            int sum = 0;
            int offset = 0;
            char *options = NULL;

            for (hi = apr_hash_first(r->pool, ciphers); hi;
                 hi = apr_hash_next(hi)) {
                apr_hash_this(hi, NULL, &klen, NULL);
                sum += klen + 2;
            }
            for (hi = apr_hash_first(r->pool, ciphers); hi;
                 hi = apr_hash_next(hi)) {
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

            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(03428) "cipher '%s' not recognised by crypto driver. "
                          "Options: %s", dconf->cipher, options);

            return rv;
        }

    }

    if (mode) {

        rv = apr_crypto_get_block_key_modes(&modes, *conf->crypto);
        if (APR_SUCCESS != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(03412) "no cipher modes returned by APR");
            return rv;
        }

        *mode = apr_hash_get(modes, dconf->mode, APR_HASH_KEY_STRING);
        if (!*mode) {
            apr_hash_index_t *hi;
            const void *key;
            apr_ssize_t klen;
            int sum = 0;
            int offset = 0;
            char *options = NULL;

            for (hi = apr_hash_first(r->pool, modes); hi;
                 hi = apr_hash_next(hi)) {
                apr_hash_this(hi, NULL, &klen, NULL);
                sum += klen + 2;
            }
            for (hi = apr_hash_first(r->pool, modes); hi;
                 hi = apr_hash_next(hi)) {
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

            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(03429) "cipher mode '%s' not recognised by crypto driver. "
                          "Options: %s", dconf->mode, options);

            return rv;
        }

    }

    return APR_SUCCESS;
}

static apr_status_t init_crypt(ap_filter_t * f)
{
    apr_status_t rv;
    crypto_ctx *ctx = f->ctx;
    const apr_crypto_key_rec_t *rec;

    crypto_conf *conf = ap_get_module_config(f->r->server->module_config,
                                             &crypto_module);
    crypto_dir_conf *dconf =
        ap_get_module_config(f->r->per_dir_config, &crypto_module);

    /* sanity check - has crypto been switched on? */
    if (!conf->crypto || !*conf->crypto) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, f->r,
                      APLOGNO(03430) "crypto driver has not been enabled for this server");
        return APR_EGENERAL;
    }

    /* initial setup of the context */
    ctx->bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    ctx->conf = dconf;
    ctx->remaining = ctx->conf->size;
    ctx->written = 0;
    ctx->osize = ctx->conf->size;

    /* fetch the cipher for this location */
    rv = init_cipher(f->r, &ctx->cipher, &ctx->mode);
    if (APR_SUCCESS != rv) {
        return rv;
    }

    /* sanity check - buffer size multiple of block size? */
    if (ctx->conf->size % ctx->cipher->blocksize) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, f->r,
                      APLOGNO(03413) "Buffer size %" APR_OFF_T_FMT
                      " is not a multiple of the block size %d of cipher '%s'",
                      ctx->conf->size, ctx->cipher->blocksize, dconf->cipher);
        return APR_EGENERAL;
    }

    /* fetch the key we'll be using for decryption */
    rv = ap_run_crypto_key(f->r, ctx->cipher, ctx->mode, 1, &rec);
    if (DECLINED == rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                      APLOGNO(03414) "no key specified for this URL");
        return APR_ENOKEY;
    }
    if (APR_SUCCESS != rv || !rec) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03415) "key could not be retrieved");
        return APR_ENOKEY;
    }
    if (rec->ktype != APR_CRYPTO_KTYPE_SECRET) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03416) "key is not a symmetrical key");
        return APR_ENOKEY;
    }

    /* attempt to import the key */
    rv = apr_crypto_key(&ctx->key, rec, *conf->crypto, f->r->pool);
    if (APR_STATUS_IS_ENOKEY(rv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03417) "key could not be loaded");
    }
    if (APR_STATUS_IS_EPADDING(rv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03418) "padding is not supported for cipher");
    }
    if (APR_STATUS_IS_EKEYTYPE(rv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03419) "the key type is not known");
    }
    if (APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03420) "encryption could not be configured.");
        return rv;
    }

    /* fetch the optional iv */
    rv = ap_run_crypto_iv(f->r, ctx->cipher, &ctx->iv);
    if (DECLINED != rv && APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                      APLOGNO(03431) "initialisation vector could not be retrieved");
        return rv;
    }

    return APR_SUCCESS;
}

static int init_encrypt(ap_filter_t * f)
{
    apr_status_t rv;
    crypto_ctx *ctx;

    ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
    ctx->encrypt = 1;

    rv = init_crypt(f);
    if (APR_SUCCESS != rv) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static int init_decrypt(ap_filter_t * f)
{
    apr_status_t rv;
    crypto_ctx *ctx;

    ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
    ctx->encrypt = 0;

    rv = init_crypt(f);
    if (APR_SUCCESS != rv) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

/**
 * Run the crypto algorithm, write to ctx->out
 */
static apr_status_t
do_crypto(ap_filter_t * f, unsigned char *in, apr_off_t size, int finish)
{
    apr_status_t rv;
    crypto_ctx *ctx = f->ctx;
    apr_off_t extra = 0;
    apr_size_t blockSize = 0;
    int need_iv = (ctx->iv == NULL);
    unsigned char *out;
    apr_size_t written;

    /* encrypt the given buffer */
    if (ctx->encrypt) {

        if (!ctx->block) {
            rv = apr_crypto_block_encrypt_init(&ctx->block, &ctx->iv,
                                               ctx->key, &blockSize,
                                               f->r->pool);
            if (APR_SUCCESS != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              APLOGNO(03421) "could not initialise encryption");
                return rv;
            }
        }

        if (!ctx->out) {

            if (need_iv && ctx->iv) {
                ctx->osize += blockSize;
            }

            out = ctx->out = apr_palloc(f->r->pool,
                                        ctx->osize + ctx->cipher->blocksize);
            apr_crypto_clear(f->r->pool, ctx->out,
                             ctx->osize + ctx->cipher->blocksize);

            /* no precomputed iv? write the generated iv as the first block of the stream */
            if (need_iv && ctx->iv) {
                memcpy(out, ctx->iv, blockSize);
                ctx->remaining += blockSize;
                out += blockSize;
                extra = blockSize;
            }

        }
        else {
            out = ctx->out + (ctx->osize - ctx->remaining);
        }

        if (!finish) {
            rv = apr_crypto_block_encrypt(&out, &written, in, size,
                                          ctx->block);
            if (APR_SUCCESS != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              APLOGNO(03422) "crypto: attempt to encrypt failed");
                return rv;
            }
        }

        else {
            rv = apr_crypto_block_encrypt_finish(out, &written, ctx->block);
            if (APR_SUCCESS != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              APLOGNO(03432) "crypto: attempt to finish encrypt failed");
                return rv;
            }
        }
    }

    /* decrypt the given buffer */
    else {

        if (!ctx->out) {
            out = ctx->out = apr_palloc(f->r->pool,
                                        ctx->osize + ctx->cipher->blocksize);
            apr_crypto_clear(f->r->pool, ctx->out,
                             ctx->osize + ctx->cipher->blocksize);
        }
        else {
            out = ctx->out + (ctx->osize - ctx->remaining);
        }

        /* no precomputed iv? assume the first block in the stream is the iv */
        if (need_iv) {
            apr_off_t isize =
                ctx->cipher->blocksize - (ctx->osize - ctx->remaining);
            if (size < isize) {
                memcpy(out, in, size);
                ctx->remaining -= size;
                return APR_SUCCESS;
            }
            else {
                memcpy(out, in, isize);
                ctx->remaining -= isize;
                out += isize;
                ctx->iv = ctx->out;
            }
        }

        if (!ctx->block) {
            rv = apr_crypto_block_decrypt_init(&ctx->block, &blockSize,
                                               ctx->iv, ctx->key, f->r->pool);
            if (APR_SUCCESS != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              APLOGNO(03423) "could not initialise decryption");
                return rv;
            }
        }

        if (!finish) {
            rv = apr_crypto_block_decrypt(&out, &written, in, size,
                                          ctx->block);
            if (APR_SUCCESS != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              APLOGNO(03433) "crypto: attempt to decrypt failed (key/iv incorrect?)");
                return rv;
            }
        }
        else {
            rv = apr_crypto_block_decrypt_finish(out, &written, ctx->block);
            if (APR_SUCCESS != rv) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              APLOGNO(03434) "crypto: attempt to finish decrypt failed (key/iv incorrect?)");
                return rv;
            }
        }
    }

    ctx->remaining -= written;
    ctx->written += written;
    ctx->written += extra;

    return rv;
}

/**
 * Encrypt/decrypt buckets being written to the output filter stack.
 */
static apr_status_t
crypto_out_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
    apr_bucket *e, *after;
    crypto_ctx *ctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    /* clear the content length */
    if (!ctx->clength) {
        ctx->clength = 1;
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    /* make sure we fit in the buffer snugly */
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        apr_brigade_partition(bb, ctx->remaining, &after);
    }

    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(bb)) {
        const char *data;
        apr_size_t size;

        e = APR_BRIGADE_FIRST(bb);

        /* EOS means we are done. */
        if (APR_BUCKET_IS_EOS(e)) {

            /* handle any leftovers */
            do_crypto(f, NULL, 0, 1);
            apr_brigade_write(ctx->bb, NULL, NULL, (const char *) ctx->out,
                              ctx->conf->size - ctx->remaining);
            ctx->remaining = ctx->osize;
            ctx->written = 0;
            apr_brigade_partition(bb, ctx->remaining, &after);

            /* pass the EOS across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);

            ap_remove_output_filter(f);
            continue;
        }

        /* handle flush */
        if (APR_BUCKET_IS_FLUSH(e)) {

            /* we cannot change the laws of physics: crypto can only happen
             * on a block boundary. As a result, just pass the flush bucket
             * through as is, we'll send the rest of the block when it
             * arrives in full.
             */

            /* pass the flush bucket across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            continue;
        }

        /* metadata buckets are preserved as is */
        if (APR_BUCKET_IS_METADATA(e)) {
            /*
             * Remove meta data bucket from old brigade and insert into the
             * new.
             */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        if (APR_SUCCESS
            == (rv = apr_bucket_read(e, &data, &size, APR_BLOCK_READ))) {

            do_crypto(f, (unsigned char *) data, size, 0);
            apr_bucket_delete(e);

            if (!ctx->remaining) {
                apr_brigade_write(ctx->bb, NULL, NULL,
                                  (const char *) ctx->out, ctx->written);
                ctx->remaining = ctx->osize;
                ctx->written = 0;
                apr_brigade_partition(bb, ctx->remaining, &after);
                rv = ap_pass_brigade(f->next, ctx->bb);
            }

        }

    }

    return rv;

}

/**
 * Decrypt/encrypt buckets being read from the input filter stack.
 */
static apr_status_t
crypto_in_filter(ap_filter_t * f, apr_bucket_brigade * bb,
                 ap_input_mode_t mode, apr_read_type_e block,
                 apr_off_t readbytes)
{
    apr_bucket *e, *after;
    apr_status_t rv = APR_SUCCESS;
    crypto_ctx *ctx = f->ctx;

    if (!ctx->tmp) {
        ctx->tmp = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    }

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* if our buffer is empty, read off the network until the buffer is full */
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        ctx->remaining = ctx->osize;
        ctx->written = 0;

        while (!ctx->seen_eos && ctx->remaining > 0) {
            const char *data;
            apr_size_t size = 0;

            if (APR_BRIGADE_EMPTY(ctx->tmp)) {
                rv = ap_get_brigade(f->next, ctx->tmp, mode, block,
                                    ctx->remaining);
            }

            /* if an error was received, bail out now. If the error is
             * EAGAIN and we have not yet seen an EOS, we will definitely
             * be called again, at which point we will send our buffered
             * data. Instead of sending EAGAIN, some filters return an
             * empty brigade instead when data is not yet available. In
             * this case, we drop through and pass buffered data, if any.
             */
            if (APR_STATUS_IS_EAGAIN(rv)
                || (rv == APR_SUCCESS
                    && block == APR_NONBLOCK_READ
                    && APR_BRIGADE_EMPTY(ctx->tmp))) {
                if (APR_BRIGADE_EMPTY(ctx->bb)) {
                    return rv;
                }
                break;
            }
            if (APR_SUCCESS != rv) {
                return rv;
            }

            while (!APR_BRIGADE_EMPTY(ctx->tmp)) {
                e = APR_BRIGADE_FIRST(ctx->tmp);

                /* if we see an EOS, we are done */
                if (APR_BUCKET_IS_EOS(e)) {

                    /* handle any leftovers */
                    do_crypto(f, NULL, 0, 1);
                    apr_brigade_write(ctx->bb, NULL, NULL,
                                      (const char *) ctx->out, ctx->written);

                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                    ctx->seen_eos = 1;
                    break;
                }

                /* flush buckets clear the buffer */
                if (APR_BUCKET_IS_FLUSH(e)) {
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                    break;
                }

                /* pass metadata buckets through */
                if (APR_BUCKET_IS_METADATA(e)) {
                    APR_BUCKET_REMOVE(e);
                    APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
                    continue;
                }

                /* read the bucket in, pack it into the buffer */
                rv = apr_bucket_read(e, &data, &size, block);
                if (APR_STATUS_IS_EAGAIN(rv)) {
                    if (APR_BRIGADE_EMPTY(ctx->bb)) {
                        return rv;
                    }
                    break;
                }
                if (APR_SUCCESS != rv) {
                    return rv;
                }

                do_crypto(f, (unsigned char *) data, size, 0);
                if (!ctx->remaining || APR_STATUS_IS_EAGAIN(rv)) {
                    apr_brigade_write(ctx->bb, NULL, NULL,
                                      (const char *) ctx->out, ctx->written);
                }

                apr_bucket_delete(e);

            }
        }
    }

    /* give the caller the data they asked for from the buffer */
    apr_brigade_partition(ctx->bb, readbytes, &after);
    e = APR_BRIGADE_FIRST(ctx->bb);
    while (e != after) {
        if (APR_BUCKET_IS_EOS(e)) {
            /* last bucket read, step out of the way */
            ap_remove_input_filter(f);
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = APR_BRIGADE_FIRST(ctx->bb);
    }

    /* clear the content length */
    if (!ctx->clength) {
        ctx->clength = 1;
        apr_table_unset(f->r->headers_in, "Content-Length");
    }

    return APR_SUCCESS;
}

static int crypto_handler(request_rec *r)
{
    crypto_conf *conf;
    crypto_dir_conf *dconf;
    apr_status_t rv;

    if (*r->handler != 'c' || strcmp(r->handler, "crypto-key")) {
        return DECLINED;
    }

    conf = ap_get_module_config(r->server->module_config, &crypto_module);
    dconf = ap_get_module_config(r->per_dir_config, &crypto_module);

    /* sanity check - has crypto been switched on? */
    if (!conf->crypto || !*conf->crypto) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r,
                      APLOGNO(03435) "crypto driver has not been enabled for this server");
        return APR_EGENERAL;
    }

    if (dconf->key_set) {
        const apr_crypto_key_rec_t *rec;
        apr_crypto_block_key_type_t *cipher;
        apr_crypto_block_key_mode_t *mode;

        /* fetch the cipher for this location */
        rv = init_cipher(r, &cipher, &mode);
        if (APR_SUCCESS != rv) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* fetch the key we'll be using for encryption / decryption */
        rv = ap_run_crypto_key(r, cipher, mode, 1, &rec);
        if (DECLINED == rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          APLOGNO(03424) "no key specified for this URL");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (APR_SUCCESS != rv || !rec) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(03425) "key could not be retrieved");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (rec->ktype != APR_CRYPTO_KTYPE_SECRET) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          APLOGNO(03426) "key is not a symmetrical key");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        ap_set_content_type(r, "application/octet-stream");
        ap_set_content_length(r, rec->k.secret.secretLen);
        ap_rwrite(rec->k.secret.secret, rec->k.secret.secretLen, r);

        return OK;

    }
    else {

        return HTTP_NOT_FOUND;

    }

}

static void *create_crypto_config(apr_pool_t * p, server_rec *s)
{
    crypto_conf *new = (crypto_conf *) apr_pcalloc(p, sizeof(crypto_conf));

    /* if no library has been configured, set the recommended library
     * as a sensible default.
     */
#ifdef APU_CRYPTO_RECOMMENDED_DRIVER
    new->library = APU_CRYPTO_RECOMMENDED_DRIVER;
#endif
    new->crypto = apr_pcalloc(p, sizeof(apr_crypto_t *));

    return (void *) new;
}

static void *merge_crypto_config(apr_pool_t * p, void *basev, void *addv)
{
    crypto_conf *new = (crypto_conf *) apr_pcalloc(p, sizeof(crypto_conf));
    crypto_conf *add = (crypto_conf *) addv;
    crypto_conf *base = (crypto_conf *) basev;

    new->library = (add->library_set == 0) ? base->library : add->library;
    new->params = (add->library_set == 0) ? base->params : add->params;
    new->library_set = add->library_set || base->library_set;

    new->crypto = base->crypto;

    return (void *) new;
}

static void *create_crypto_dir_config(apr_pool_t * p, char *dummy)
{
    crypto_dir_conf *new =
        (crypto_dir_conf *) apr_pcalloc(p, sizeof(crypto_dir_conf));

    new->size = DEFAULT_BUFFER_SIZE;    /* default size */
    new->cipher = DEFAULT_CIPHER;
    new->mode = DEFAULT_MODE;

    return (void *) new;
}

static void *merge_crypto_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    crypto_dir_conf *new =
        (crypto_dir_conf *) apr_pcalloc(p, sizeof(crypto_dir_conf));
    crypto_dir_conf *add = (crypto_dir_conf *) addv;
    crypto_dir_conf *base = (crypto_dir_conf *) basev;

    new->size = (add->size_set == 0) ? base->size : add->size;
    new->size_set = add->size_set || base->size_set;

    new->cipher = (add->cipher_set == 0) ? base->cipher : add->cipher;
    new->mode = (add->cipher_set == 0) ? base->mode : add->mode;
    new->cipher_set = add->cipher_set || base->cipher_set;

    new->key = (add->key_set == 0) ? base->key : add->key;
    new->key_set = add->key_set || base->key_set;

    new->iv = (add->iv_set == 0) ? base->iv : add->iv;
    new->iv_set = add->iv_set || base->iv_set;

    return new;
}

static const char *set_crypto_size(cmd_parms *cmd, void *dconf,
                                   const char *arg)
{
    crypto_dir_conf *conf = dconf;

    if (APR_SUCCESS != apr_strtoff(&(conf->size), arg, NULL, 10)
        || conf->size <= 0) {
        return "CryptoSize must be a size in bytes, and greater than zero";
    }
    conf->size_set = 1;

    return NULL;
}

static const char *set_crypto_driver(cmd_parms *cmd, void *config,
                                     const char *arg)
{
    crypto_conf *conf =
        (crypto_conf *) ap_get_module_config(cmd->server->module_config,
                                             &crypto_module);

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    conf->library = ap_getword_conf(cmd->pool, &arg);
    conf->params = arg;
    conf->crypto = apr_pcalloc(cmd->pool, sizeof(apr_crypto_t *));
    conf->library_set = 1;

    return NULL;
}

static const char *set_crypto_cipher(cmd_parms *cmd, void *config,
                                     const char *cipher, const char *mode)
{
    crypto_dir_conf *dconf = (crypto_dir_conf *) config;

    dconf->cipher = cipher;
    dconf->mode = mode ? mode : DEFAULT_MODE;
    dconf->cipher_set = 1;

    return NULL;
}

static const char *set_crypto_key(cmd_parms *cmd, void *config,
                                  const char *arg)
{
    crypto_dir_conf *dconf = (crypto_dir_conf *) config;

    pass_conf *key = dconf->key = apr_pcalloc(cmd->pool, sizeof(pass_conf));
    dconf->key_set = 1;

    return parse_pass_conf_binary(cmd, key, arg);
}

static const char *set_crypto_iv(cmd_parms *cmd, void *config,
                                 const char *arg)
{
    crypto_dir_conf *dconf = (crypto_dir_conf *) config;

    pass_conf *iv = dconf->iv = apr_pcalloc(cmd->pool, sizeof(pass_conf));
    dconf->iv_set = 1;

    return parse_pass_conf_binary(cmd, iv, arg);
}

static const command_rec crypto_cmds[] = {
    AP_INIT_TAKE1("CryptoSize", set_crypto_size, NULL, ACCESS_CONF,
                  "Maximum size of the buffer used by the crypto filters"),
    AP_INIT_RAW_ARGS("CryptoDriver", set_crypto_driver, NULL, RSRC_CONF,
                     "The underlying crypto library driver to use"),
    AP_INIT_TAKE12("CryptoCipher", set_crypto_cipher, NULL,
                   RSRC_CONF | OR_AUTHCFG,
                   "The underlying crypto cipher and mode to use. If unspecified, the mode defaults to 'cbc'"),
    AP_INIT_TAKE1("CryptoKey", set_crypto_key, NULL, RSRC_CONF | OR_AUTHCFG,
                  "The crypto key scheme and value to use. Scheme is one of 'none', 'file:', 'hex:', 'base64:' or 'decimal:'"),
    AP_INIT_TAKE1("CryptoIV", set_crypto_iv, NULL, RSRC_CONF | OR_AUTHCFG,
                  "The crypto IV scheme and value to use. Scheme is one of 'none', 'file:', 'hex:', 'base64:' or 'decimal:'"),
    {NULL}
};

/**
 * Initialise the SSL in the post_config hook.
 */
static int
crypto_init(apr_pool_t * p, apr_pool_t * plog,
            apr_pool_t * ptemp, server_rec *s)
{
    const apr_crypto_driver_t *driver = NULL;

    while (s) {

        crypto_conf *conf = ap_get_module_config(s->module_config,
                                                 &crypto_module);

        if (conf->library_set && !*conf->crypto) {

            const apu_err_t *err = NULL;
            apr_status_t rv;

            rv = apr_crypto_init(p);
            if (APR_SUCCESS != rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(03427) "APR crypto could not be initialised");
                return rv;
            }

            rv = apr_crypto_get_driver(&driver, conf->library, conf->params,
                                       &err, p);
            if (APR_EREINIT == rv) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                             APLOGNO(03436) "warning: crypto for '%s' was already initialised, "
                             "using existing configuration", conf->library);
                rv = APR_SUCCESS;
            }
            if (APR_SUCCESS != rv && err) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(03437) "The crypto library '%s' could not be loaded: %s (%s: %d)",
                             conf->library, err->msg, err->reason, err->rc);
                return rv;
            }
            if (APR_ENOTIMPL == rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(03438) "The crypto library '%s' could not be found",
                             conf->library);
                return rv;
            }
            if (APR_SUCCESS != rv || !driver) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(03439) "The crypto library '%s' could not be loaded",
                             conf->library);
                return rv;
            }

            rv = apr_crypto_make(conf->crypto, driver, conf->params, p);
            if (APR_SUCCESS != rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             APLOGNO(03440) "The crypto library '%s' could not be initialised",
                             conf->library);
                return rv;
            }

            ap_log_error(APLOG_MARK, APLOG_INFO, rv, s,
                         APLOGNO(03441) "The crypto library '%s' was loaded successfully",
                         conf->library);

        }
        s = s->next;
    }

    return OK;
}

static apr_status_t
crypto_key(request_rec *r,
           apr_crypto_block_key_type_t * cipher,
           apr_crypto_block_key_mode_t * mode, int pad,
           const apr_crypto_key_rec_t ** recptr)
{
    apr_crypto_key_rec_t *rec;

    crypto_dir_conf *conf =
        ap_get_module_config(r->per_dir_config, &crypto_module);

    pass_conf *key = conf->key;

    *recptr = rec = apr_palloc(r->pool, sizeof(apr_crypto_key_rec_t));
    rec->ktype = APR_CRYPTO_KTYPE_SECRET;
    rec->type = cipher->type;
    rec->mode = mode->mode;
    rec->pad = pad;
    rec->k.secret.secretLen = cipher->keysize;

    return exec_pass_conf_binary(r, key, "key", cipher->keysize,
                                 &(rec->k.secret.secret));
}

static apr_status_t
crypto_iv(request_rec *r,
          apr_crypto_block_key_type_t * cipher, const unsigned char **v)
{
    crypto_dir_conf *conf =
        ap_get_module_config(r->per_dir_config, &crypto_module);

    pass_conf *iv = conf->iv;

    return exec_pass_conf_binary(r, iv, "iv", cipher->ivsize, v);
}

static void register_hooks(apr_pool_t * p)
{
    ap_hook_crypto_key(crypto_key, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_hook_crypto_iv(crypto_iv, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_hook_post_config(crypto_init, NULL, NULL, APR_HOOK_LAST);
    ap_hook_handler(crypto_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter("ENCRYPT", crypto_out_filter, init_encrypt,
                              AP_FTYPE_RESOURCE);
    ap_register_input_filter("ENCRYPT", crypto_in_filter, init_encrypt,
                             AP_FTYPE_RESOURCE);
    ap_register_output_filter("DECRYPT", crypto_out_filter, init_decrypt,
                              AP_FTYPE_RESOURCE);
    ap_register_input_filter("DECRYPT", crypto_in_filter, init_decrypt,
                             AP_FTYPE_RESOURCE);
}

AP_DECLARE_MODULE(crypto) = {
    STANDARD20_MODULE_STUFF,
    create_crypto_dir_config, /* create per-directory config structure */
    merge_crypto_dir_config,  /* merge per-directory config structures */
    create_crypto_config,     /* create per-server config structure */
    merge_crypto_config,      /* merge per-server config structures */
    crypto_cmds,              /* command apr_table_t */
    register_hooks            /* register hooks */
};

#endif
