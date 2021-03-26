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
 * @file  http_ssl.h
 * @brief SSL protocol handling
 *
 * @defgroup APACHE_CORE_PROTO SSL Protocol Handling
 * @ingroup  APACHE_CORE
 * @{
 */

#ifndef APACHE_HTTP_SSL_H
#define APACHE_HTTP_SSL_H

#include "httpd.h"
#include "apr_portable.h"
#include "apr_mmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This hook allows modules that manage SSL connection to register their
 * inquiry function for checking if a connection is using SSL from them.
 * @param c The current connection
 * @return OK if the connection is using SSL, DECLINED if not.
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,ssl_conn_is_ssl,(conn_rec *c))

/**
 * Return != 0 iff the connection is encrypted with SSL.
 * @param c the connection
 */
AP_DECLARE(int) ap_ssl_conn_is_ssl(conn_rec *c);

/**
 * This hook allows modules to look up SSL related variables for a
 * server/connection/request, depending on what they inquire. Some
 * variables will only be available for a connection/request, for example.
 * @param p The pool to allocate a returned value in, MUST be provided
 * @param s The server to inquire a value for, maybe NULL
 * @param c The current connection, maybe NULL
 * @param r The current request, maybe NULL
 * @param name The name of the variable to retrieve, MUST be provided
 * @return value or the variable or NULL if not provided/available
 * @ingroup hooks
 */
AP_DECLARE_HOOK(const char *,ssl_var_lookup,
    (apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *name))

/**
 * Lookup an SSL related variable for the server/connection/request or a global
 * value when all those parameters are set to NULL. Pool and name must always be
 * provided and the returned value (if not NULL) will be allocated fromt he pool.
 * @param p The pool to allocate a returned value in, MUST be provided
 * @param s The server to inquire a value for, maybe NULL
 * @param c The current connection, maybe NULL
 * @param r The current request, maybe NULL
 * @param name The name of the variable to retrieve, MUST be provided
 * @return value or the variable or NULL if not provided/available
 */
AP_DECLARE(const char *) ap_ssl_var_lookup(apr_pool_t *p, server_rec *s,
                                           conn_rec *c, request_rec *r,
                                           const char *name);

/**
 * Register to provide certificate/key files for servers. Certificate files are
 * exepcted to contain the certificate chain, beginning with the server's certificate,
 * excluding the trust anchor, in PEM format.
 * They must be accompanied by a private key file, also in PEM format.
 *
 * @param s the server certificates are collected for
 * @param p the pool to use for allocations
 * @param cert_file and array of const char* with the path to the certificate chain
 * @param key_file and array of const char* with the path to the private key file
 * @return OK if files were added, DECLINED if not, or other for error.
 */

AP_DECLARE_HOOK(int, ssl_add_cert_files, (server_rec *s, apr_pool_t *p,
                                          apr_array_header_t *cert_files,
                                          apr_array_header_t *key_files))

/**
 * Collect certificate/key files from all providers registered. This includes
 * providers registered at the global 'ssl_add_cert_files', as well as those
 * installed in the OPTIONAL 'ssl_add_cert_files' hook as may be provided by
 * ssl modules.
 *
 * @param s the server certificates are collected for
 * @param p the pool to use for allocations
 * @param cert_file and array of const char* with the path to the certificate chain
 * @param key_file and array of const char* with the path to the private key file
 */
AP_DECLARE(apr_status_t) ap_ssl_add_cert_files(server_rec *s, apr_pool_t *p,
                                               apr_array_header_t *cert_files,
                                               apr_array_header_t *key_files);


/**
 * Register to provide 'fallback' certificates in case no 'real' certificates
 * have been configured/added by other providers. Modules using these certificates
 * are encouraged to answer requests to this server with a 503 response code.
 *
 * @param s the server certificates are collected for
 * @param p the pool to use for allocations
 * @param cert_file and array of const char* with the path to the certificate chain
 * @param key_file and array of const char* with the path to the private key file
 * @return OK if files were added, DECLINED if not, or other for error.
 */
AP_DECLARE_HOOK(int, ssl_add_fallback_cert_files, (server_rec *s, apr_pool_t *p,
                                                   apr_array_header_t *cert_files,
                                                   apr_array_header_t *key_files))

/**
 * Collect 'fallback' certificate/key files from all registered providers, either
 * in the global 'ssl_add_fallback_cert_files' hook or the optional one of similar
 * name as provided by mod_ssl and sorts.
 * Certificates obtained this way are commonly self signed, temporary crutches.
 * To be used to the time it takes to retrieve a 'read', trusted certificate.
 * A module using fallbacks is encouraged to answer all requests with a 503.
 *
 * @param s the server certificates are collected for
 * @param p the pool to use for allocations
 * @param cert_file and array of const char* with the path to the certificate chain
 * @param key_file and array of const char* with the path to the private key file
 */
AP_DECLARE(apr_status_t) ap_ssl_add_fallback_cert_files(server_rec *s, apr_pool_t *p,
                                                        apr_array_header_t *cert_files,
                                                        apr_array_header_t *key_files);


/**
 * On TLS connections that do not relate to a configured virtual host
 * allow modules to provide a certificate and key to be used on the connection.
 *
 * A Certificate PEM added must be accompanied by a private key PEM. The private
 * key PEM may be given by a NULL pointer, in which case it is expected to be found in
 * the certificate PEM string.
 */
AP_DECLARE_HOOK(int, ssl_answer_challenge, (conn_rec *c, const char *server_name,
                                            const char **pcert_pem, const char **pkey_pem))

/**
 * Returns != 0 iff the connection is a challenge to the server, for example
 * as defined in RFC 8555 for the 'tls-alpn-01' domain verification, and needs
 * a specific certificate as answer in the handshake.
 *
 * ALPN protocol negotiation via the hooks 'protocol_propose' and 'protocol_switch'
 * need to have run before this call is made.
 *
 * Certificate PEMs added must be accompanied by a private key PEM. The private
 * key PEM may be given by a NULL pointer, in which case it is expected to be found in
 * the certificate PEM string.
 *
 * A certificate provided this way needs to replace any other certificates selected
 * by configuration or 'ssl_add_cert_pems` on this connection.
 */
AP_DECLARE(int) ap_ssl_answer_challenge(conn_rec *c, const char *server_name,
                                        const char **pcert_pem, const char **pkey_pem);


/**
 * Setup optional functions for ssl related queries so that functions
 * registered by old-style SSL module functions are interrogated by the
 * the new ap_is_ssl() and friends. Installs own optional functions, so that
 * old modules looking for these find one and get the correct results (shadowing).
 *
 * Needs to run in core's very early POST_CONFIG hook.
 * Modules providing such functions register their own optionals during
 * register_hooks(). Modules using such functions retrieve them often
 * in their own post-config or in the even later retrieval hook. When shadowing
 * other modules functions, core's early post-config is a good time.
 * @param pool The pool to use for allocations
 */
AP_DECLARE(void) ap_setup_ssl_optional_fns(apr_pool_t *pool);


#ifdef __cplusplus
}
#endif

#endif  /* !APACHE_HTTP_SSL_H */
/** @} */
