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

/** The ssl_ext_lookup() optional function retrieves the value of a SSL
 * certificate X.509 extension.  The client certificate is used if
 * peer is non-zero; the server certificate is used otherwise.  The
 * oidnum parameter specifies the numeric OID (e.g. "1.2.3.4") of the
 * desired extension.  The string value of the extension is returned,
 * or NULL on error. */
APR_DECLARE_OPTIONAL_FN(const char *, ssl_ext_lookup,
                        (apr_pool_t *p, conn_rec *c, int peer,
                         const char *oidnum));

/** An optional function which returns non-zero if the given connection
 * is using SSL/TLS. */
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

/** The ssl_proxy_enable() and ssl_engine_disable() optional functions
 * are used by mod_proxy to enable use of SSL for outgoing
 * connections. */

APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));

APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));

APR_DECLARE_OPTIONAL_FN(apr_array_header_t *, ssl_extlist_by_oid, (request_rec *r, const char *oidstr));

#endif /* __MOD_SSL_H__ */
/** @} */
