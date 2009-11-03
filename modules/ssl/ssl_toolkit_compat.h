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

#ifndef SSL_TOOLKIT_COMPAT_H
#define SSL_TOOLKIT_COMPAT_H

/**
 * @file ssl_toolkit_compat.h 
 * @brief this header file provides a compatiblity layer
 *        between OpenSSL and RSA sslc
 *
 * @defgroup MOD_SSL_TOOLKIT Toolkit
 * @ingroup  MOD_SSL
 * @{
 */

#ifdef HAVE_OPENSSL

/** OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

/* hack for non-configure platforms (NetWare, Win32) */
#if !defined(HAVE_OCSP) && (OPENSSL_VERSION_NUMBER >= 0x00907000)
#define HAVE_OCSP
#endif
#ifdef HAVE_OCSP
#include <openssl/x509_vfy.h>
#include <openssl/ocsp.h>
#endif

/** Avoid tripping over an engine build installed globally and detected
 * when the user points at an explicit non-engine flavor of OpenSSL
 */
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
#include <openssl/engine.h>
#endif

/**
 * rsa sslc uses incomplete types for most structures
 * so we macroize for OpenSSL those which cannot be dereferenced
 * using the same sames as the sslc functions
 */

#define EVP_PKEY_key_type(k)              (EVP_PKEY_type(k->type))

#define X509_NAME_get_entries(xs)         (xs->entries)
#define X509_REVOKED_get_serialNumber(xs) (xs->serialNumber)

#define X509_get_signature_algorithm(xs) (xs->cert_info->signature->algorithm)
#define X509_get_key_algorithm(xs)       (xs->cert_info->key->algor->algorithm)

#define X509_NAME_ENTRY_get_data_ptr(xs) (xs->value->data)
#define X509_NAME_ENTRY_get_data_len(xs) (xs->value->length)

#define SSL_CTX_get_extra_certs(ctx)       (ctx->extra_certs)
#define SSL_CTX_set_extra_certs(ctx,value) {ctx->extra_certs = value;}

#define SSL_CIPHER_get_name(s)             (s->name)
#define SSL_CIPHER_get_valid(s)            (s->valid)

#define SSL_SESSION_get_session_id(s)      (s->session_id)
#define SSL_SESSION_get_session_id_length(s) (s->session_id_length)

/**
 * Support for retrieving/overriding states
 */
#ifndef SSL_get_state
#define SSL_get_state(ssl) SSL_state(ssl)
#endif

#define SSL_set_state(ssl,val) (ssl)->state = val

#define MODSSL_BIO_CB_ARG_TYPE const char
#define MODSSL_CRYPTO_CB_ARG_TYPE const char
#if (OPENSSL_VERSION_NUMBER < 0x00907000)
# define MODSSL_INFO_CB_ARG_TYPE SSL*
#else
# define MODSSL_INFO_CB_ARG_TYPE const SSL*
#endif
#define MODSSL_CLIENT_CERT_CB_ARG_TYPE X509
#define MODSSL_PCHAR_CAST

/** ...shifting sands of openssl... */
#if (OPENSSL_VERSION_NUMBER >= 0x0090707f)
# define MODSSL_D2I_SSL_SESSION_CONST    const
# define MODSSL_SSL_CIPHER_CONST         const
#else
# define MODSSL_D2I_SSL_SESSION_CONST
# define MODSSL_SSL_CIPHER_CONST
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x00908000)
# define MODSSL_D2I_PrivateKey_CONST const
# define MODSSL_D2I_X509_CONST const
#else
# define MODSSL_D2I_PrivateKey_CONST
# define MODSSL_D2I_X509_CONST
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x00909000)
# define MODSSL_SSL_METHOD_CONST const
#else
# define MODSSL_SSL_METHOD_CONST
#endif

#define modssl_X509_verify_cert X509_verify_cert

typedef int (modssl_read_bio_cb_fn)(char*,int,int,void*);

#if (OPENSSL_VERSION_NUMBER < 0x00904000)
#define modssl_PEM_read_bio_X509(b, x, cb, arg) PEM_read_bio_X509(b, x, cb)
#else
#define modssl_PEM_read_bio_X509(b, x, cb, arg) PEM_read_bio_X509(b, x, cb, arg)
#endif

#define modssl_PEM_X509_INFO_read_bio PEM_X509_INFO_read_bio 

#define modssl_PEM_read_bio_PrivateKey PEM_read_bio_PrivateKey

#define modssl_set_cipher_list SSL_set_cipher_list

#define modssl_free OPENSSL_free

#define EVP_PKEY_reference_inc(pkey) \
   CRYPTO_add(&((pkey)->references), +1, CRYPTO_LOCK_X509_PKEY)

#define X509_reference_inc(cert) \
   CRYPTO_add(&((cert)->references), +1, CRYPTO_LOCK_X509)

#define HAVE_SSL_RAND_EGD /* since 9.5.1 */

#define HAVE_SSL_X509V3_EXT_d2i

#if OPENSSL_VERSION_NUMBER >= 0x00908080 && defined(HAVE_OCSP) \
    && !defined(OPENSSL_NO_TLSEXT)
#define HAVE_OCSP_STAPLING
#endif

#ifndef PEM_F_DEF_CALLBACK
#ifdef PEM_F_PEM_DEF_CALLBACK
/** In OpenSSL 0.9.8 PEM_F_DEF_CALLBACK was renamed */
#define PEM_F_DEF_CALLBACK PEM_F_PEM_DEF_CALLBACK 
#endif
#endif

#elif defined(HAVE_SSLC)

#include <bio.h>
#include <ssl.h>
#include <err.h>
#include <x509.h>
#include <pem.h>
#include <evp.h>
#include <objects.h>
#include <sslc.h>

/** sslc does not support this function, OpenSSL has since 9.5.1 */
#define RAND_status() 1

/** sslc names this function a bit differently */
#define CRYPTO_num_locks() CRYPTO_get_num_locks()

#ifndef STACK_OF
#define STACK_OF(type) STACK
#endif

#define MODSSL_BIO_CB_ARG_TYPE char
#define MODSSL_CRYPTO_CB_ARG_TYPE char
#define MODSSL_INFO_CB_ARG_TYPE SSL*
#define MODSSL_CLIENT_CERT_CB_ARG_TYPE void
#define MODSSL_PCHAR_CAST (char *)
#define MODSSL_D2I_SSL_SESSION_CONST
#define MODSSL_D2I_PrivateKey_CONST
#define MODSSL_D2I_X509_CONST

typedef int (modssl_read_bio_cb_fn)(char*,int,int);

#define modssl_X509_verify_cert(c) X509_verify_cert(c, NULL)

#define modssl_PEM_read_bio_X509(b, x, cb, arg) \
   PEM_read_bio_X509(b, x, cb)

#define modssl_PEM_X509_INFO_read_bio(b, x, cb, arg)\
   PEM_X509_INFO_read_bio(b, x, cb)

#define modssl_PEM_read_bio_PrivateKey(b, k, cb, arg) \
   PEM_read_bio_PrivateKey(b, k, cb)

#ifndef HAVE_SSL_SET_STATE
#define SSL_set_state(ssl, state) /** XXX: should throw an error */
#endif

#define modssl_set_cipher_list(ssl, l) \
   SSL_set_cipher_list(ssl, (char *)l)

#define modssl_free free

#ifndef PEM_F_DEF_CALLBACK
#define PEM_F_DEF_CALLBACK PEM_F_DEF_CB
#endif

#if SSLC_VERSION_NUMBER < 0x2000

#define X509_STORE_CTX_set_depth(st, d)    
#define X509_CRL_get_lastUpdate(x) ((x)->crl->lastUpdate)
#define X509_CRL_get_nextUpdate(x) ((x)->crl->nextUpdate)
#define X509_CRL_get_REVOKED(x)    ((x)->crl->revoked)
#define X509_REVOKED_get_serialNumber(xs) (xs->serialNumber)

#define modssl_set_verify(ssl, verify, cb) \
    SSL_set_verify(ssl, verify)

#else /** SSLC_VERSION_NUMBER >= 0x2000 */

#define CRYPTO_malloc_init R_malloc_init

#define EVP_cleanup() 

#endif /** SSLC_VERSION_NUMBER >= 0x2000 */

typedef void (*modssl_popfree_fn)(char *data);

#define sk_SSL_CIPHER_dup sk_dup
#define sk_SSL_CIPHER_find(st, data) sk_find(st, (void *)data)
#define sk_SSL_CIPHER_free sk_free
#define sk_SSL_CIPHER_num sk_num
#define sk_SSL_CIPHER_value (SSL_CIPHER *)sk_value
#define sk_X509_num sk_num
#define sk_X509_push sk_push
#define sk_X509_pop_free(st, free) sk_pop_free((STACK*)(st), (modssl_popfree_fn)(free))
#define sk_X509_value (X509 *)sk_value
#define sk_X509_INFO_free sk_free
#define sk_X509_INFO_pop_free(st, free) sk_pop_free((STACK*)(st), (modssl_popfree_fn)(free))
#define sk_X509_INFO_num sk_num
#define sk_X509_INFO_new_null sk_new_null
#define sk_X509_INFO_value (X509_INFO *)sk_value
#define sk_X509_NAME_find(st, data) sk_find(st, (void *)data)
#define sk_X509_NAME_free sk_free
#define sk_X509_NAME_new sk_new
#define sk_X509_NAME_num sk_num
#define sk_X509_NAME_push(st, data) sk_push(st, (void *)data)
#define sk_X509_NAME_value (X509_NAME *)sk_value
#define sk_X509_NAME_ENTRY_num sk_num
#define sk_X509_NAME_ENTRY_value (X509_NAME_ENTRY *)sk_value
#define sk_X509_NAME_set_cmp_func sk_set_cmp_func
#define sk_X509_REVOKED_num sk_num
#define sk_X509_REVOKED_value (X509_REVOKED *)sk_value

#else /** ! HAVE_OPENSSL && ! HAVE_SSLC */

#error "Unrecognized SSL Toolkit!"

#endif /* ! HAVE_OPENSSL && ! HAVE_SSLC */

#ifndef modssl_set_verify
#define modssl_set_verify(ssl, verify, cb) \
    SSL_set_verify(ssl, verify, cb)
#endif

#ifndef SSL_SESS_CACHE_NO_INTERNAL
#define SSL_SESS_CACHE_NO_INTERNAL  SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
#endif

#ifndef OPENSSL_NO_TLSEXT
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#define OPENSSL_NO_TLSEXT
#endif
#endif

#endif /* SSL_TOOLKIT_COMPAT_H */

/** @} */
