/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_util_ssl.h
**  Additional Utility Functions for OpenSSL
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#ifndef SSL_UTIL_SSL_H
#define SSL_UTIL_SSL_H

/*
 * Determine SSL library version number
 */
#ifdef OPENSSL_VERSION_NUMBER
#define SSL_LIBRARY_VERSION OPENSSL_VERSION_NUMBER
#define SSL_LIBRARY_NAME    "OpenSSL"
#define SSL_LIBRARY_TEXT    OPENSSL_VERSION_TEXT
#else
#define SSL_LIBRARY_VERSION 0x0000
#define SSL_LIBRARY_NAME    "OtherSSL"
#define SSL_LIBRARY_TEXT    "OtherSSL 0.0.0 00 XXX 0000"
#endif

/*
 * Support for retrieving/overriding states
 */
#ifndef SSL_get_state
#define SSL_get_state(ssl) SSL_state(ssl)
#endif
#define SSL_set_state(ssl,val) (ssl)->state = val

/*
 *  Maximum length of a DER encoded session.
 *  FIXME: There is no define in OpenSSL, but OpenSSL uses 1024*10,
 *         so this value should be ok. Although we have no warm feeling.
 */
#define SSL_SESSION_MAX_DER 1024*10

/*  
 *  Additional Functions
 */
int         SSL_get_app_data2_idx(void);
void       *SSL_get_app_data2(SSL *);
void        SSL_set_app_data2(SSL *, void *);
X509       *SSL_read_X509(FILE *, X509 **, int (*)());
EVP_PKEY   *SSL_read_PrivateKey(FILE *, EVP_PKEY **, int (*)());
int         SSL_smart_shutdown(SSL *ssl);
X509_STORE *SSL_X509_STORE_create(char *, char *);
int         SSL_X509_STORE_lookup(X509_STORE *, int, X509_NAME *, X509_OBJECT *);
char       *SSL_make_ciphersuite(pool *, SSL *);
BOOL        SSL_X509_isSGC(X509 *);
BOOL        SSL_X509_getBC(X509 *, int *, int *);
BOOL        SSL_X509_getCN(pool *, X509 *, char **);
#ifdef SSL_EXPERIMENTAL_PROXY
BOOL        SSL_load_CrtAndKeyInfo_file(pool *, STACK_OF(X509_INFO) *, char *);
BOOL        SSL_load_CrtAndKeyInfo_path(pool *, STACK_OF(X509_INFO) *, char *);
#endif /* SSL_EXPERIMENTAL_PROXY */
int         SSL_CTX_use_certificate_chain(SSL_CTX *, char *, int, int (*)());
char       *SSL_SESSION_id2sz(unsigned char *, int);

#endif /* SSL_UTIL_SSL_H */
