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

#include "lua_passwd.h"
#include "apr_strings.h"
#include "apr_errno.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif

#include "apr_md5.h"
#include "apr_sha1.h"

#if APR_HAVE_TIME_H
#include <time.h>
#endif
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
#if APR_HAVE_IO_H
#include <io.h>
#endif

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
        *errstr = apr_psprintf(pool, "generate_salt(): BUG: Buffer too small");
        return ERR_RANDOM;
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

/*
 * Make a password record from the given information.  A zero return
 * indicates success; on failure, ctx->errstr points to the error message.
 */
int mk_password_hash(passwd_ctx *ctx)
{
    char *pw;
    char salt[16];
    apr_status_t rv;
    int ret = 0;
#if CRYPT_ALGO_SUPPORTED
    char *cbuf;
#endif

    pw = ctx->passwd;
    switch (ctx->alg) {
    case ALG_APSHA:
        /* XXX out >= 28 + strlen(sha1) chars - fixed len SHA */
        apr_sha1_base64(pw, strlen(pw), ctx->out);
        break;

    case ALG_APMD5:
        ret = generate_salt(salt, 8, &ctx->errstr, ctx->pool);
        if (ret != 0) {
            ret = ERR_GENERAL;
            break;
        }
        rv = apr_md5_encode(pw, salt, ctx->out, ctx->out_len);
        if (rv != APR_SUCCESS) {
            ctx->errstr = apr_psprintf(ctx->pool,
                                       "could not encode password: %pm", &rv);
            ret = ERR_GENERAL;
        }
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
            char *truncpw = apr_pstrdup(ctx->pool, pw);
            truncpw[8] = '\0';
            if (!strcmp(ctx->out, crypt(truncpw, salt))) {
                ctx->errstr = apr_psprintf(ctx->pool,
                                           "Warning: Password truncated to 8 "
                                           "characters by CRYPT algorithm.");
            }
            memset(truncpw, '\0', strlen(pw));
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
        ctx->errstr = apr_psprintf(ctx->pool,
                                  "mk_password_hash(): unsupported algorithm %d",
                                  ctx->alg);
        ret = ERR_GENERAL;
    }
    memset(pw, '\0', strlen(pw));
    return ret;
}


