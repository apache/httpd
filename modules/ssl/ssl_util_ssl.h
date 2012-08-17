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
 * Determine SSL library version number
 */
#define SSL_NIBBLE(x,n) ((x >> (n * 4)) & 0xF)

#ifdef OPENSSL_VERSION_NUMBER
#define SSL_LIBRARY_VERSION OPENSSL_VERSION_NUMBER
#define SSL_LIBRARY_NAME    "OpenSSL"
#define SSL_LIBRARY_TEXT    OPENSSL_VERSION_TEXT
#define SSL_LIBRARY_DYNTEXT SSLeay_version(SSLEAY_VERSION)
#elif defined(SSLC_VERSION_NUMBER)
#define SSL_LIBRARY_VERSION SSLC_VERSION_NUMBER
#define SSL_LIBRARY_NAME    "SSL-C"
#define SSL_LIBRARY_TEXT    { 'S', 'S', 'L', '-', 'C', ' ', \
                              '0' + SSL_NIBBLE(SSLC_VERSION_NUMBER,3), '.', \
                              '0' + SSL_NIBBLE(SSLC_VERSION_NUMBER,2), '.', \
                              '0' + SSL_NIBBLE(SSLC_VERSION_NUMBER,1), '.', \
                              '0' + SSL_NIBBLE(SSLC_VERSION_NUMBER,0), 0 }
#define SSL_LIBRARY_DYNTEXT SSLC_library_info(SSLC_INFO_VERSION)
#elif !defined(SSL_LIBRARY_VERSION)
#define SSL_LIBRARY_VERSION 0x0000
#define SSL_LIBRARY_NAME    "OtherSSL"
#define SSL_LIBRARY_TEXT    "OtherSSL 0.0.0 00 XXX 0000"
#define SSL_LIBRARY_DYNTEXT "OtherSSL 0.0.0 00 XXX 0000"
#endif

/**
 *  Maximum length of a DER encoded session.
 *  FIXME: There is no define in OpenSSL, but OpenSSL uses 1024*10,
 *         so this value should be ok. Although we have no warm feeling.
 */
#define SSL_SESSION_MAX_DER 1024*10

/** max length for SSL_SESSION_id2sz */
#define SSL_SESSION_ID_STRING_LEN \
    ((SSL_MAX_SSL_SESSION_ID_LENGTH + 1) * 2)

/**  
 *  Additional Functions
 */
void        SSL_init_app_data2_idx(void);
void       *SSL_get_app_data2(SSL *);
void        SSL_set_app_data2(SSL *, void *);
X509       *SSL_read_X509(char *, X509 **, modssl_read_bio_cb_fn *);
EVP_PKEY   *SSL_read_PrivateKey(char *, EVP_PKEY **, modssl_read_bio_cb_fn *, void *);
int         SSL_smart_shutdown(SSL *ssl);
X509_STORE *SSL_X509_STORE_create(char *, char *);
int         SSL_X509_STORE_lookup(X509_STORE *, int, X509_NAME *, X509_OBJECT *);
char       *SSL_make_ciphersuite(apr_pool_t *, SSL *);
BOOL        SSL_X509_isSGC(X509 *);
BOOL        SSL_X509_getBC(X509 *, int *, int *);
char       *SSL_X509_NAME_to_string(apr_pool_t *, X509_NAME *, unsigned int);
BOOL        SSL_X509_getCN(apr_pool_t *, X509 *, char **);
BOOL        SSL_X509_INFO_load_file(apr_pool_t *, STACK_OF(X509_INFO) *, const char *);
BOOL        SSL_X509_INFO_load_path(apr_pool_t *, STACK_OF(X509_INFO) *, const char *);
int         SSL_CTX_use_certificate_chain(SSL_CTX *, char *, int, modssl_read_bio_cb_fn *);
char       *SSL_SESSION_id2sz(unsigned char *, int, char *, int);

/** util functions for OpenSSL+sslc compat */
int modssl_session_get_time(SSL_SESSION *session);

DH *modssl_dh_configure(unsigned char *p, int plen,
                        unsigned char *g, int glen);

#endif /* __SSL_UTIL_SSL_H__ */
/** @} */

