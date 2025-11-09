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
 * @file  ssl_policies.h
 * @brief Additional Utility Functions for OpenSSL
 *
 * @defgroup MOD_SSL_UTIL Utilities
 * @ingroup MOD_SSL
 * @{
 */

#ifndef __SSL_POLICIES_H__
#define __SSL_POLICIES_H__

#define SSL_MOD_POLICIES_KEY "ssl_module_policies"

#ifndef OPENSSL_NO_SSL3
#define SSL_PROTOCOL_CONSTANTS_SSLV3        SSL_PROTOCOL_SSLV3
#else
#define SSL_PROTOCOL_CONSTANTS_SSLV3        0
#endif

#ifdef HAVE_TLSV1_X
#define SSL_POLICY_LEGACY_PROTOCOLS  \
    (SSL_PROTOCOL_CONSTANTS_SSLV3|SSL_PROTOCOL_TLSV1|SSL_PROTOCOL_TLSV1_1)
#endif

/* Settings for all policies */
#define SSL_POLICY_HONOR_ORDER              1
#define SSL_POLICY_COMPRESSION              0
#define SSL_POLICY_SESSION_TICKETS          0

/**
 * Define a core set of policies that are always there:
 * - 'modern' from https://wiki.mozilla.org/Security/Server_Side_TLS
 * - 'intermediate' from https://wiki.mozilla.org/Security/Server_Side_TLS
 * - 'old' from https://wiki.mozilla.org/Security/Server_Side_TLS
 * The JSON version can be retrieved here:
 * https://statics.tls.security.mozilla.org/server-side-tls-conf.json
 */

#define SSL_POLICY_MOZILLA_VERSION 4.0

#ifdef HAVE_TLSV1_X
#define SSL_POLICY_MODERN    1
#define SSL_POLICY_MODERN_SSL_CIPHERS "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
#define SSL_POLICY_MODERN_TLS13_CIPHERS NULL
#define SSL_POLICY_MODERN_PROTOCOLS (SSL_PROTOCOL_TLSV1_2|SSL_PROTOCOL_TLSV1_3)
#else /* ifdef HAVE_TLSV1_X */
#define SSL_POLICY_MODERN    0
#endif /* ifdef HAVE_TLSV1_X, else part */

#define SSL_POLICY_INTERMEDIATE    1
#define SSL_POLICY_INTERMEDIATE_SSL_CIPHERS "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS"
#define SSL_POLICY_INTERMEDIATE_TLS13_CIPHERS NULL
#define SSL_POLICY_INTERMEDIATE_PROTOCOLS (SSL_PROTOCOL_ALL & ~(SSL_PROTOCOL_TLSV1_3|SSL_PROTOCOL_CONSTANTS_SSLV3))

#define SSL_POLICY_OLD    1
#define SSL_POLICY_OLD_SSL_CIPHERS "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP"
#define SSL_POLICY_OLD_TLS13_CIPHERS NULL
#define SSL_POLICY_OLD_PROTOCOLS (SSL_PROTOCOL_ALL & ~(SSL_PROTOCOL_TLSV1_3))


#endif /* __SSL_POLICIES_H__ */
/** @} */

