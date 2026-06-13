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

#include <httpd.h>

#include <http_config.h>
#include <http_log.h>

#include <openssl/bio.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include "h3_ssl.h"

static const unsigned char alpn_ossltest[] = {5, 'h', '3', '-', '2', '9', 2, 'h', '3'};

static int select_alpn(SSL* /*ssl*/, const unsigned char** out, unsigned char* out_len, const unsigned char* in, unsigned int in_len, void* /*arg*/)
{
    if (SSL_select_next_proto((unsigned char**)out, out_len, alpn_ossltest, sizeof(alpn_ossltest), in, in_len) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

SSL_CTX* create_ctx(server_rec* s, const char* cert_path, const char* key_path)
{
    SSL_CTX* ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /* Load certificate and corresponding private key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "couldn't load certificate file: %s", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "couldn't load key file: %s", key_path);
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "private key check failed");
        goto err;
    }

    /* Setup ALPN negotiation callback. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

int create_socket(server_rec* s, uint16_t port)
{
    int fd = -1;
    struct sockaddr_in6 sa;
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "cannot create socket");
        goto err;
    }
    /* trying */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, optlen) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "cannot setsockopt on socket");
        goto err;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons(port);

    if (bind(fd, (const struct sockaddr*)&sa, sizeof(sa)) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "cannot bind to %u", port);
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        BIO_closesocket(fd);

    return -1;
}
