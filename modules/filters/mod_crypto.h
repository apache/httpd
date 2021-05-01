/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _MOD_CRYPTO_H_
#define _MOD_CRYPTO_H_

/* Create a set of CRYPTO_DECLARE(type), CRYPTO_DECLARE_NONSTD(type) and
 * CRYPTO_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define CRYPTO_DECLARE(type)        type
#define CRYPTO_DECLARE_NONSTD(type) type
#define CRYPTO_DECLARE_DATA
#elif defined(CRYPTO_DECLARE_STATIC)
#define CRYPTO_DECLARE(type)        type __stdcall
#define CRYPTO_DECLARE_NONSTD(type) type
#define CRYPTO_DECLARE_DATA
#elif defined(CRYPTO_DECLARE_EXPORT)
#define CRYPTO_DECLARE(type)        __declspec(dllexport) type __stdcall
#define CRYPTO_DECLARE_NONSTD(type) __declspec(dllexport) type
#define CRYPTO_DECLARE_DATA         __declspec(dllexport)
#else
#define CRYPTO_DECLARE(type)        __declspec(dllimport) type __stdcall
#define CRYPTO_DECLARE_NONSTD(type) __declspec(dllimport) type
#define CRYPTO_DECLARE_DATA         __declspec(dllimport)
#endif

/**
 * @file  mod_crypto.h
 * @brief Crypto Module for Apache
 *
 * @defgroup MOD_CRYPTO mod_crypto
 * @ingroup  APACHE_MODS
 * @{
 */

#include "apr.h"
#include "apr_hooks.h"
#include "apr_optional.h"
#include "apr_tables.h"
#include "apr_uuid.h"
#include "apr_pools.h"
#include "apr_time.h"
#include "apr_crypto.h"

#include "httpd.h"
#include "http_config.h"
#include "ap_config.h"

/**
 * Hook to provide a key.
 *
 * @param r The request
 * @param cipher The cipher to use with this key
 * @param rec Pointer to the key record from which to derive the key
 */
APR_DECLARE_EXTERNAL_HOOK(ap, CRYPTO, apr_status_t, crypto_key,
                          (request_rec *r,
                           apr_crypto_block_key_type_t * cipher,
                           apr_crypto_block_key_mode_t * mode, int pad,
                           const apr_crypto_key_rec_t ** rec));

/**
 * Hook to provide an initialization vector (IV).
 *
 * @param r The request
 * @param size The block size of the expected IV.
 * @param iv A pointer to where the iv will be returned
 */
APR_DECLARE_EXTERNAL_HOOK(ap, CRYPTO, apr_status_t, crypto_iv,
                          (request_rec *r,
                           apr_crypto_block_key_type_t * cipher,
                           const unsigned char **iv));

/**
 * The name of the module.
 */
extern module AP_MODULE_DECLARE_DATA crypto_module;

/** @} */

#endif
