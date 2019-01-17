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

#ifndef _LUA_PASSWD_H
#define _LUA_PASSWD_H

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_errno.h"
#include "apr_file_io.h"
#include "apr_general.h"
#include "apr_version.h"
#if !APR_VERSION_AT_LEAST(2,0,0)
#include "apu_version.h"
#endif

#define MAX_PASSWD_LEN 256

#define ALG_APMD5  0
#define ALG_APSHA  1
#define ALG_BCRYPT 2
#define ALG_CRYPT  3

#define BCRYPT_DEFAULT_COST 5

#define ERR_FILEPERM 1
#define ERR_SYNTAX 2
#define ERR_PWMISMATCH 3
#define ERR_INTERRUPTED 4
#define ERR_OVERFLOW 5
#define ERR_BADUSER 6
#define ERR_INVALID 7
#define ERR_RANDOM 8
#define ERR_GENERAL 9
#define ERR_ALG_NOT_SUPP 10

#if defined(WIN32) || defined(NETWARE)
#define CRYPT_ALGO_SUPPORTED 0
#define PLAIN_ALGO_SUPPORTED 1
#else
#define CRYPT_ALGO_SUPPORTED 1
#define PLAIN_ALGO_SUPPORTED 0
#endif

#if APR_VERSION_AT_LEAST(2,0,0) || \
    (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 5)
#define BCRYPT_ALGO_SUPPORTED 1
#else
#define BCRYPT_ALGO_SUPPORTED 0
#endif

typedef struct passwd_ctx passwd_ctx;

struct passwd_ctx {
    apr_pool_t      *pool;
    const char      *errstr;
    char            *out;
    apr_size_t      out_len;
    char            *passwd;
    int             alg;
    int             cost;
};


/*
 * The following functions return zero on success; otherwise, one of
 * the ERR_* codes is returned and an error message is stored in ctx->errstr.
 */

/*
 * Make a password record from the given information.
 */
int mk_password_hash(passwd_ctx *ctx);

#endif /* _LUA_PASSWD_H */

