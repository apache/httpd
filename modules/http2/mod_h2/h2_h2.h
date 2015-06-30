/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __mod_h2__h2_h2__
#define __mod_h2__h2_h2__

/**
 * List of ALPN protocol identifiers that we support in ALPN/NPN 
 * negotiations.
 */
extern const char *h2_alpn_protos[];
extern apr_size_t h2_alpn_protos_len;

/**
 * List of ALPN protocol identifiers that we suport in HTTP/1 Upgrade:
 * negotiations.
 */
extern const char *h2_upgrade_protos[];
extern apr_size_t h2_upgrade_protos_len;

/**
 * The magic PRIamble of RFC 7540 that is always sent when starting
 * a h2 communication.
 */
extern const char *H2_MAGIC_TOKEN;

/*
 * One time, post config intialization.
 */
apr_status_t h2_h2_init(apr_pool_t *pool, server_rec *s);

/* Is the connection a TLS connection?
 */
int h2_h2_is_tls(conn_rec *c);

/* Disable SSL for this connection, can only be invoked in a pre-
 * connection hook before mod_ssl.
 * @return != 0 iff disable worked
 */
int h2_tls_disable(conn_rec *c);

/* Register apache hooks for h2 protocol
 */
void h2_h2_register_hooks(void);


#endif /* defined(__mod_h2__h2_h2__) */
