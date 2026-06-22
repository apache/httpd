/*
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
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

#ifndef H3_SSL_H
#define H3_SSL_H

#include <openssl/ssl.h>

/**
 * ALPN selection callback for the QUIC SSL_CTX. Negotiates "h3" as the
 * single supported protocol. Per OpenSSL's SSL_CTX_set_alpn_select_cb
 * contract.
 * @param ssl     The SSL object performing the negotiation.
 * @param out     Out: pointer to the selected protocol bytes.
 * @param outlen  Out: length of the selected protocol.
 * @param in      Wire-format ALPN extension from the peer.
 * @param inlen   Length of @p in.
 * @param arg     User data (unused).
 * @return SSL_TLSEXT_ERR_OK on success, SSL_TLSEXT_ERR_ALERT_FATAL on no match.
 */
int h3_alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg);

#endif /* H3_SSL_H */
