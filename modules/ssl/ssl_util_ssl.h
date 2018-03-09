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
 * @verbatim
                        _             _
    _ __ ___   ___   __| |    ___ ___| |  mod_ssl
   | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
   | | | | | | (_) | (_| |   \__ \__ \ |
   |_| |_| |_|\___/ \__,_|___|___/___/_|
                        |_____|
   @endverbatim
 * @file  ssl_util_ssl.h
 * @brief Additional Utility Functions for OpenSSL
 *
 * @defgroup MOD_SSL_UTIL Utilities
 * @ingroup MOD_SSL
 * @{
 */

#ifndef __SSL_UTIL_SSL_H__
#define __SSL_UTIL_SSL_H__

/**
 * SSL library version number
 */

#define MODSSL_LIBRARY_VERSION OPENSSL_VERSION_NUMBER
#define MODSSL_LIBRARY_NAME    "OpenSSL"
#define MODSSL_LIBRARY_TEXT    OPENSSL_VERSION_TEXT
#if MODSSL_USE_OPENSSL_PRE_1_1_API
#define MODSSL_LIBRARY_DYNTEXT SSLeay_version(SSLEAY_VERSION)
#else
#define MODSSL_LIBRARY_DYNTEXT OpenSSL_version(OPENSSL_VERSION)
#endif

/**
 *  Maximum length of a DER encoded session.
 *  FIXME: There is no define in OpenSSL, but OpenSSL uses 1024*10,
 *         so this value should be ok. Although we have no warm feeling.
 */
#define MODSSL_SESSION_MAX_DER 1024*10

/** max length for modssl_SSL_SESSION_id2sz */
#define MODSSL_SESSION_ID_STRING_LEN \
    ((SSL_MAX_SSL_SESSION_ID_LENGTH + 1) * 2)

/**
 *  Additional Functions
 */
void        modssl_init_app_data2_idx(void);
void       *modssl_get_app_data2(SSL *);
void        modssl_set_app_data2(SSL *, void *);
EVP_PKEY   *modssl_read_privatekey(const char *, EVP_PKEY **, pem_password_cb *, void *);
EVP_PKEY   *modssl_read_encrypted_pkey(const char *, EVP_PKEY **, const char *, apr_size_t);
int         modssl_smart_shutdown(SSL *ssl);
BOOL        modssl_X509_getBC(X509 *, int *, int *);
char       *modssl_X509_NAME_ENTRY_to_string(apr_pool_t *p, X509_NAME_ENTRY *xsne,
                                             int raw);
char       *modssl_X509_NAME_to_string(apr_pool_t *, X509_NAME *, int);
BOOL        modssl_X509_getSAN(apr_pool_t *, X509 *, int, const char *, int, apr_array_header_t **);
BOOL        modssl_X509_match_name(apr_pool_t *, X509 *, const char *, BOOL, server_rec *);
char       *modssl_SSL_SESSION_id2sz(IDCONST unsigned char *, int, char *, int);

#endif /* __SSL_UTIL_SSL_H__ */
/** @} */

