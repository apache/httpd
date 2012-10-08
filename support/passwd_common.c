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

#include "passwd_common.h"
#include "apr_strings.h"
#include "apr_errno.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#include "apr_md5.h"
#include "apr_sha1.h"
#include <time.h>

#if APR_HAVE_CRYPT_H
#include <crypt.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef WIN32
#include <conio.h>
#define unlink _unlink
#endif

apr_file_t *errfile;

static int generate_salt(char *s, size_t size, const char **errstr,
                         apr_pool_t *pool)
{
    unsigned char rnd[32];
    static const char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    apr_size_t n;
    unsigned int val = 0, bits = 0;
    apr_status_t rv;

    n = (size * 6 + 7)/8;
    if (n > sizeof(rnd)) {
        apr_file_printf(errfile, "generate_salt(): BUG: Buffer too small");
        abort();
    }
    rv = apr_generate_random_bytes(rnd, n);
    if (rv) {
        *errstr = apr_psprintf(pool, "Unable to generate random bytes: %pm",
                               &rv);
        return ERR_RANDOM;
    }
    n = 0;
    while (size > 0) {
        if (bits < 6) {
            val |= (rnd[n++] << bits);
            bits += 8;
        }
        *s++ = itoa64[val & 0x3f];
        size--;
        val >>= 6;
        bits -= 6;
   }
   *s = '\0';
   return 0;
}

void putline(apr_file_t *f, const char *l)
{
    apr_status_t rv;
    rv = apr_file_puts(l, f);
    if (rv != APR_SUCCESS) {
        apr_file_printf(errfile, "Error writing temp file: %pm", &rv);
        apr_file_close(f);
        exit(ERR_FILEPERM);
    }
}

int get_password(struct passwd_ctx *ctx)
{
    if (ctx->passwd_src == PW_STDIN) {
        char *buf = ctx->out;
        apr_file_t *file_stdin;
        apr_size_t nread;
        if (apr_file_open_stdin(&file_stdin, ctx->pool) != APR_SUCCESS) {
            ctx->errstr = "Unable to read from stdin.";
            return ERR_GENERAL;
        }
        if (apr_file_read_full(file_stdin, buf, ctx->out_len - 1,
                               &nread) != APR_EOF
            || nread == ctx->out_len - 1) {
            goto err_too_long;
        }
        buf[nread] = '\0';
        if (nread >= 1 && buf[nread-1] == '\n') {
            buf[nread-1] = '\0';
            if (nread >= 2 && buf[nread-2] == '\r')
                buf[nread-2] = '\0';
        }
        apr_file_close(file_stdin);
    }
    else {
        char buf[MAX_STRING_LEN + 1];
        apr_size_t bufsize = sizeof(buf);
        if (apr_password_get("New password: ", ctx->out, &ctx->out_len) != 0)
            goto err_too_long;
        apr_password_get("Re-type new password: ", buf, &bufsize);
        if (strcmp(ctx->out, buf) != 0) {
            ctx->errstr = "password verification error";
            memset(ctx->out, '\0', ctx->out_len);
            memset(buf, '\0', sizeof(buf));
            return ERR_PWMISMATCH;
        }
        memset(buf, '\0', sizeof(buf));
    }
    return 0;

err_too_long:
    ctx->errstr = apr_psprintf(ctx->pool,
                               "password too long (>%" APR_SIZE_T_FMT ")",
                               ctx->out_len - 1);
    return ERR_OVERFLOW;
}

/*
 * Make a password record from the given information.  A zero return
 * indicates success; on failure, ctx->errstr points to the error message.
 */
int mkhash(struct passwd_ctx *ctx)
{
    char *pw;
    char pwin[MAX_STRING_LEN];
    char salt[16];
    apr_status_t rv;
    int ret = 0;
#if CRYPT_ALGO_SUPPORTED
    char *cbuf;
#endif

    if (ctx->cost != 0 && ctx->alg != ALG_BCRYPT) {
        apr_file_printf(errfile,
                        "Warning: Ignoring -C argument for this algorithm." NL);
    }

    if (ctx->passwd != NULL) {
        pw = ctx->passwd;
    }
    else {
        if ((ret = get_password(ctx)) != 0)
            return ret;
        pw = pwin;
    }

    switch (ctx->alg) {
    case ALG_APSHA:
        /* XXX out >= 28 + strlen(sha1) chars - fixed len SHA */
        apr_sha1_base64(pw, strlen(pw), ctx->out);
        break;

    case ALG_APMD5:
        ret = generate_salt(salt, 8, &ctx->errstr, ctx->pool);
        if (ret != 0)
            break;
        rv = apr_md5_encode(pw, salt, ctx->out, ctx->out_len);
        if (rv != APR_SUCCESS) {
            ctx->errstr = apr_psprintf(ctx->pool,
                                       "could not encode password: %pm", &rv);
            ret = ERR_GENERAL;
        }
        break;

    case ALG_PLAIN:
        /* XXX this len limitation is not in sync with any HTTPd len. */
        apr_cpystrn(ctx->out, pw, ctx->out_len);
        break;

#if CRYPT_ALGO_SUPPORTED
    case ALG_CRYPT:
        ret = generate_salt(salt, 8, &ctx->errstr, ctx->pool);
        if (ret != 0)
            break;
        cbuf = crypt(pw, salt);
        if (cbuf == NULL) {
            rv = APR_FROM_OS_ERROR(errno);
            ctx->errstr = apr_psprintf(ctx->pool, "crypt() failed: %pm", &rv);
            ret = ERR_PWMISMATCH;
            break;
        }

        apr_cpystrn(ctx->out, cbuf, ctx->out_len - 1);
        if (strlen(pw) > 8) {
            char *truncpw = strdup(pw);
            truncpw[8] = '\0';
            if (!strcmp(ctx->out, crypt(truncpw, salt))) {
                apr_file_printf(errfile, "Warning: Password truncated to 8 "
                                "characters by CRYPT algorithm." NL);
            }
            memset(truncpw, '\0', strlen(pw));
            free(truncpw);
        }
        break;
#endif /* CRYPT_ALGO_SUPPORTED */

#if BCRYPT_ALGO_SUPPORTED
    case ALG_BCRYPT:
        rv = apr_generate_random_bytes((unsigned char*)salt, 16);
        if (rv != APR_SUCCESS) {
            ctx->errstr = apr_psprintf(ctx->pool, "Unable to generate random "
                                       "bytes: %pm", &rv);
            ret = ERR_RANDOM;
            break;
        }

        if (ctx->cost == 0)
            ctx->cost = BCRYPT_DEFAULT_COST;
        rv = apr_bcrypt_encode(pw, ctx->cost, (unsigned char*)salt, 16,
                               ctx->out, ctx->out_len);
        if (rv != APR_SUCCESS) {
            ctx->errstr = apr_psprintf(ctx->pool, "Unable to encode with "
                                       "bcrypt: %pm", &rv);
            ret = ERR_PWMISMATCH;
            break;
        }
        break;
#endif /* BCRYPT_ALGO_SUPPORTED */

    default:
        apr_file_printf(errfile, "mkhash(): BUG: invalid algorithm %d",
                        ctx->alg);
        abort();
    }
    memset(pw, '\0', strlen(pw));
    return ret;
}

int parse_common_options(struct passwd_ctx *ctx, char opt,
                          const char *opt_arg)
{
    switch (opt) {
    case 'b':
        ctx->passwd_src = PW_ARG;
        break;
    case 'i':
        ctx->passwd_src = PW_STDIN;
        break;
    case 'm':
        ctx->alg = ALG_APMD5;
        break;
    case 's':
        ctx->alg = ALG_APSHA;
        break;
    case 'p':
        ctx->alg = ALG_PLAIN;
#if !PLAIN_ALGO_SUPPORTED
        /* Backward compatible behavior: Just print a warning */
        apr_file_printf(errfile,
                        "Warning: storing passwords as plain text might just "
                        "not work on this platform." NL);
#endif
        break;
    case 'd':
#if CRYPT_ALGO_SUPPORTED
        ctx->alg = ALG_CRYPT;
#else
        /* Backward compatible behavior: Use MD5. OK since MD5 is more secure */
        apr_file_printf(errfile,
                        "Warning: CRYPT algorithm not supported on this "
                        "platform." NL
                        "Automatically using MD5 format." NL);
        ctx->alg = ALG_APMD5;
#endif
        break;
    case 'B':
#if BCRYPT_ALGO_SUPPORTED
        ctx->alg = ALG_BCRYPT;
#else
        /* Don't fall back to something less secure */
        ctx->errstr = "BCRYPT algorithm not supported on this platform";
        return ERR_ALG_NOT_SUPP;
#endif
        break;
    case 'C': {
            char *endptr;
            long num = strtol(opt_arg, &endptr, 10);
            if (*endptr != '\0' || num <= 0) {
                ctx->errstr = "argument to -C must be a positive integer";
                return ERR_SYNTAX;
            }
            ctx->cost = num;
            break;
        }
    default:
        apr_file_printf(errfile, 
                        "parse_common_options(): BUG: invalid option %c",
                        opt);
        abort();
    }
    return 0;
}
