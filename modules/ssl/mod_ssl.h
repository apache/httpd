/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MOD_SSL_H__
#define __MOD_SSL_H__

#include "httpd.h"
#include "apr_optional.h"

/* The ssl_var_lookup() optional function retrieves SSL environment
 * variables. */
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));

/* The ssl_proxy_enable() and ssl_engine_disable() optional functions
 * are used by mod_proxy to enable use of SSL for outgoing
 * connections. */

APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));

APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));

#endif /* __MOD_SSL_H__ */
