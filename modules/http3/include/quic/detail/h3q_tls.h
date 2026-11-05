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

#ifndef H3Q_DETAIL_TLS_H
#define H3Q_DETAIL_TLS_H

#include <stddef.h>

#include <openssl/ssl.h>

#include "quic/h3q.h"

/**
 * Build the TLS context the listener serves from: the certificate chain files
 * with their keys (one per key type, as mod_ssl allows; a missing key file
 * means the key sits in the chain file), "h3" as the only ALPN protocol, and
 * a key log when SSLKEYLOGFILE is set. Safe before the server forks and drops
 * privileges; children inherit the loaded keys.
 * @param cert_files      Certificate chain files; at least one.
 * @param ncerts          Number of entries in @p cert_files.
 * @param key_files       Private key files, matched by index to @p cert_files.
 * @param nkeys           Number of entries in @p key_files; may be fewer.
 * @param session_tickets Non-zero to issue TLS 1.3 session tickets.
 * @param err             Buffer receiving the reason on failure; may be NULL.
 * @param errlen          Capacity of @p err.
 * @return New context, or NULL on failure.
 */
SSL_CTX* h3q_tls_ctx_create(const char* const* cert_files, size_t ncerts, const char* const* key_files, size_t nkeys, int session_tickets, char* err, size_t errlen);

/**
 * Record a message in a caller-supplied error buffer, appending the OpenSSL
 * error queue's own text when it has any.
 * @param err    Buffer to write to; NULL is ignored.
 * @param errlen Capacity of @p err.
 * @param fmt    printf-style format for the message.
 */
void h3q_tls_error(char* err, size_t errlen, const char* fmt, ...);

#endif /* H3Q_DETAIL_TLS_H */
