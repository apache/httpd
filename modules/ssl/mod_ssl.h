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

/** The npn_advertise_protos optional hook allows other modules to add entries
 * to the list of protocol names advertised by the server during the Next
 * Protocol Negotiation (NPN) portion of the SSL handshake.  The hook callee is
 * given the connection and an APR array; it should push one or more char*'s
 * pointing to null-terminated strings (such as "http/1.1" or "spdy/2") onto
 * the array and return OK, or do nothing and return DECLINED. */
APR_DECLARE_EXTERNAL_HOOK(modssl, AP, int, npn_advertise_protos_hook,
                          (conn_rec *connection, apr_array_header_t *protos));

/** The npn_proto_negotiated optional hook allows other modules to discover the
 * name of the protocol that was chosen during the Next Protocol Negotiation
 * (NPN) portion of the SSL handshake.  Note that this may be the empty string
 * (in which case modules should probably assume HTTP), or it may be a protocol
 * that was never even advertised by the server.  The hook callee is given the
 * connection, a non-null-terminated string containing the protocol name, and
 * the length of the string; it should do something appropriate (i.e. insert or
 * remove filters) and return OK, or do nothing and return DECLINED. */
APR_DECLARE_EXTERNAL_HOOK(modssl, AP, int, npn_proto_negotiated_hook,
                          (conn_rec *connection, const char *proto_name,
                           apr_size_t proto_name_len));

#endif /* __MOD_SSL_H__ */
/** @} */
