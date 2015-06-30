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
 * @file mod_ssl.h
 * @brief SSL extension module for Apache
 *
 * @defgroup MOD_SSL mod_ssl
 * @ingroup  APACHE_MODS
 * @{
 */

#ifndef __MOD_SSL_H__
#define __MOD_SSL_H__

#include "httpd.h"
#include "apr_optional.h"

/** The ssl_var_lookup() optional function retrieves SSL environment
 * variables. */
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

/** The ssl_ext_list() optional function attempts to build an array
 * of all the values contained in the named X.509 extension. The
 * returned array will be created in the supplied pool.
 * The client certificate is used if peer is non-zero; the server
 * certificate is used otherwise.
 * Extension specifies the extensions to use as a string. This can be
 * one of the "known" long or short names, or a numeric OID,
 * e.g. "1.2.3.4", 'nsComment' and 'DN' are all valid.
 * A pointer to an apr_array_header_t structure is returned if at
 * least one matching extension is found, NULL otherwise.
 */
APR_DECLARE_OPTIONAL_FN(apr_array_header_t *, ssl_ext_list,
                        (apr_pool_t *p, conn_rec *c, int peer,
                         const char *extension));

/** An optional function which returns non-zero if the given connection
 * is using SSL/TLS. */
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

/** The ssl_proxy_enable() and ssl_engine_disable() optional functions
 * are used by mod_proxy to enable use of SSL for outgoing
 * connections. */

APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));

APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));

/** The alpn_propose_proto callback allows other modules to propose
 * the name of the protocol that will be chosen during the
 * Application-Layer Protocol Negotiation (ALPN) portion of the SSL handshake.
 * The callback is given the connection and a list of NULL-terminated
 * protocol strings as supported by the client.  If this client_protos is 
 * non-empty, it must pick its preferred protocol from that list. Otherwise
 * it should add its supported protocols in order of precedence.
 * The callback should not yet modify the connection or install any filters
 * as its proposal(s) may be overridden by another callback or server 
 * configuration. 
 * It should return OK or, to prevent further processing of (other modules') 
 * callbacks, return DONE.
 */
typedef int (*ssl_alpn_propose_protos)(conn_rec *connection,
									apr_array_header_t *client_protos,
									apr_array_header_t *proposed_protos);

/** The alpn_proto_negotiated callback allows other modules to discover
 * the name of the protocol that was chosen during the Application-Layer
 * Protocol Negotiation (ALPN) portion of the SSL handshake.  
 * The callback is given the connection, a
 * non-NUL-terminated string containing the protocol name, and the
 * length of the string; it should do something appropriate
 * (i.e. insert or remove filters) and return OK. To prevent further
 * processing of (other modules') callbacks, return DONE. */
typedef int (*ssl_alpn_proto_negotiated)(conn_rec *connection,
                                        const char *proto_name,
                                        apr_size_t proto_name_len);

/* An optional function which can be used to register a pair of callbacks 
 * for ALPN handling.
 * This optional function should be invoked from a pre_connection hook 
 * which runs *after* mod_ssl.c's pre_connection hook.  The function returns 
 * OK if the callbacks are registered, or DECLINED otherwise (for example if 
 * mod_ssl does not support ALPN).
 */
APR_DECLARE_OPTIONAL_FN(int, modssl_register_alpn,
						(conn_rec *conn,
						 ssl_alpn_propose_protos proposefn,
						 ssl_alpn_proto_negotiated negotiatedfn));

#endif /* __MOD_SSL_H__ */
/** @} */
