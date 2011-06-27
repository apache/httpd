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
 * @file ap_ldap_option.h
 * @brief LDAP ldap_*_option() functions
 */
#ifndef AP_LDAP_OPTION_H
#define AP_LDAP_OPTION_H

/**
 * @addtogroup AP_Util_LDAP
 * @{
 */

#if AP_HAS_LDAP

#include "ap_ldap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * The following defines handle the different TLS certificate
 * options available. If these options are missing, this API
 * emulate support for this using the deprecated ldap_start_tls_s()
 * function.
 */
/**
 * Set SSL mode to one of AP_LDAP_NONE, AP_LDAP_SSL, AP_LDAP_STARTTLS
 * or AP_LDAP_STOPTLS.
 */
#define AP_LDAP_OPT_TLS 0x6fff
/**
 * Set zero or more CA certificates, client certificates or private
 * keys globally, or per connection (where supported).
 */
#define AP_LDAP_OPT_TLS_CERT 0x6ffe
/**
 * Set the LDAP library to no verify the server certificate.  This means
 * all servers are considered trusted.
 */
#define AP_LDAP_OPT_VERIFY_CERT 0x6ffd
/**
 * Set the LDAP library to indicate if referrals should be chased during
 * LDAP searches.
 */
#define AP_LDAP_OPT_REFERRALS 0x6ffc
/**
 * Set the LDAP library to indicate a maximum number of referral hops to
 * chase before giving up on the search.
 */
#define AP_LDAP_OPT_REFHOPLIMIT 0x6ffb

/**
 * Structures for the apr_set_option() cases
 */

/**
 * AP_LDAP_OPT_TLS_CERT
 *
 * This structure includes possible options to set certificates on
 * system initialisation. Different SDKs have different certificate
 * requirements, and to achieve this multiple certificates must be
 * specified at once passed as an (apr_array_header_t *).
 *
 * Netscape:
 * Needs the CA cert database (cert7.db), the client cert database (key3.db)
 * and the security module file (secmod.db) set at the system initialisation
 * time. Three types are supported: AP_LDAP_CERT7_DB, AP_LDAP_KEY3_DB and
 * AP_LDAP_SECMOD.
 *
 * To specify a client cert connection, a certificate nickname needs to be
 * provided with a type of AP_LDAP_CERT.
 * int ldapssl_enable_clientauth( LDAP *ld, char *keynickname,
 * char *keypasswd, char *certnickname );
 * keynickname is currently not used, and should be set to ""
 *
 * Novell:
 * Needs CA certificates and client certificates set at system initialisation
 * time. Three types are supported: AP_LDAP_CA*, AP_LDAP_CERT* and
 * AP_LDAP_KEY*.
 *
 * Certificates cannot be specified per connection.
 *
 * The functions used are:
 * ldapssl_add_trusted_cert(serverTrustedRoot, serverTrustedRootEncoding);
 * Clients certs and keys are set at system initialisation time with
 * int ldapssl_set_client_cert (
 *  void   *cert,
 *  int     type
 *  void   *password); 
 * type can be LDAPSSL_CERT_FILETYPE_B64 or LDAPSSL_CERT_FILETYPE_DER
 *  ldapssl_set_client_private_key(clientPrivateKey,
 *                                 clientPrivateKeyEncoding,
 *                                 clientPrivateKeyPassword);
 *
 * OpenSSL:
 * Needs one or more CA certificates to be set at system initialisation time
 * with a type of AP_LDAP_CA*.
 *
 * May have one or more client certificates set per connection with a type of
 * AP_LDAP_CERT*, and keys with AP_LDAP_KEY*.
 */
/** CA certificate type unknown */
#define AP_LDAP_CA_TYPE_UNKNOWN    0
/** binary DER encoded CA certificate */
#define AP_LDAP_CA_TYPE_DER        1
/** PEM encoded CA certificate */
#define AP_LDAP_CA_TYPE_BASE64     2
/** Netscape/Mozilla cert7.db CA certificate database */
#define AP_LDAP_CA_TYPE_CERT7_DB   3
/** Netscape/Mozilla secmod file */
#define AP_LDAP_CA_TYPE_SECMOD     4
/** Client certificate type unknown */
#define AP_LDAP_CERT_TYPE_UNKNOWN  5
/** binary DER encoded client certificate */
#define AP_LDAP_CERT_TYPE_DER      6
/** PEM encoded client certificate */
#define AP_LDAP_CERT_TYPE_BASE64   7
/** Netscape/Mozilla key3.db client certificate database */
#define AP_LDAP_CERT_TYPE_KEY3_DB  8
/** Netscape/Mozilla client certificate nickname */
#define AP_LDAP_CERT_TYPE_NICKNAME 9
/** Private key type unknown */
#define AP_LDAP_KEY_TYPE_UNKNOWN   10
/** binary DER encoded private key */
#define AP_LDAP_KEY_TYPE_DER       11
/** PEM encoded private key */
#define AP_LDAP_KEY_TYPE_BASE64    12
/** PKCS#12 encoded client certificate */
#define AP_LDAP_CERT_TYPE_PFX      13
/** PKCS#12 encoded private key */
#define AP_LDAP_KEY_TYPE_PFX       14
/** Openldap directory full of base64-encoded cert 
 * authorities with hashes in corresponding .0 directory
 */
#define AP_LDAP_CA_TYPE_CACERTDIR_BASE64 15


/**
 * Certificate structure.
 *
 * This structure is used to store certificate details. An array of
 * these structures is passed to ap_ldap_set_option() to set CA
 * and client certificates.
 * @param type Type of certificate AP_LDAP_*_TYPE_*
 * @param path Path, file or nickname of the certificate
 * @param password Optional password, can be NULL
 */
typedef struct ap_ldap_opt_tls_cert_t ap_ldap_opt_tls_cert_t;
struct ap_ldap_opt_tls_cert_t {
    int type;
    const char *path;
    const char *password;
};

/**
 * AP_LDAP_OPT_TLS
 *
 * This sets the SSL level on the LDAP handle.
 *
 * Netscape/Mozilla:
 * Supports SSL, but not STARTTLS
 * SSL is enabled by calling ldapssl_install_routines().
 *
 * Novell:
 * Supports SSL and STARTTLS.
 * SSL is enabled by calling ldapssl_install_routines(). Note that calling
 * other ldap functions before ldapssl_install_routines() may cause this
 * function to fail.
 * STARTTLS is enabled by calling ldapssl_start_tls_s() after calling
 * ldapssl_install_routines() (check this).
 *
 * OpenLDAP:
 * Supports SSL and supports STARTTLS, but none of this is documented:
 * http://www.openldap.org/lists/openldap-software/200409/msg00618.html
 * Documentation for both SSL support and STARTTLS has been deleted from
 * the OpenLDAP documentation and website.
 */

/** No encryption */
#define AP_LDAP_NONE 0
/** SSL encryption (ldaps://) */
#define AP_LDAP_SSL 1
/** TLS encryption (STARTTLS) */
#define AP_LDAP_STARTTLS 2
/** end TLS encryption (STOPTLS) */
#define AP_LDAP_STOPTLS 3

/**
 * LDAP get option function
 *
 * This function gets option values from a given LDAP session if
 * one was specified. It maps to the native ldap_get_option() function.
 * @param pool The pool to use
 * @param ldap The LDAP handle
 * @param option The LDAP_OPT_* option to return
 * @param outvalue The value returned (if any)
 * @param result_err The ap_ldap_err_t structure contained detailed results
 *        of the operation.
 */
APR_DECLARE_OPTIONAL_FN(int, ap_ldap_get_option, (apr_pool_t *pool,
                                                  LDAP *ldap,
                                                  int option,
                                                  void *outvalue,
                                                  ap_ldap_err_t **result_err));

/**
 * LDAP set option function
 * 
 * This function sets option values to a given LDAP session if
 * one was specified. It maps to the native ldap_set_option() function.
 * 
 * Where an option is not supported by an LDAP toolkit, this function
 * will try and apply legacy functions to achieve the same effect,
 * depending on the platform.
 * @param pool The pool to use
 * @param ldap The LDAP handle
 * @param option The LDAP_OPT_* option to set
 * @param invalue The value to set
 * @param result_err The ap_ldap_err_t structure contained detailed results
 *        of the operation.
 */
APR_DECLARE_OPTIONAL_FN(int, ap_ldap_set_option, (apr_pool_t *pool,
                                                  LDAP *ldap,
                                                  int option,
                                                  const void *invalue,
                                                  ap_ldap_err_t **result_err));

#ifdef __cplusplus
}
#endif

#endif /* AP_HAS_LDAP */

/** @} */

#endif /* AP_LDAP_OPTION_H */

