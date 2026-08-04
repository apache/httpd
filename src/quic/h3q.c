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

#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "h3_check.h"
#include "quic/detail/h3q_addr.h"
#include "quic/detail/h3q_tls.h"
#include "quic/h3q.h"

h3q_engine* h3q_engine_create(const h3q_config* cfg, int udp_fd, char* err, size_t errlen)
{
    CHECK(cfg);
    h3q_engine* engine = calloc(1, sizeof(*engine));
    if (!engine)
    {
        h3q_tls_error(err, errlen, "allocating the engine failed");
        return NULL;
    }
    engine->peer_addr_ex_index = -1;

    engine->ssl_ctx = h3q_tls_ctx_create(cfg, err, errlen);
    if (!engine->ssl_ctx)
    {
        h3q_engine_destroy(engine);
        return NULL;
    }

    BIO_METHOD* bm = BIO_meth_new(BIO_TYPE_FILTER | BIO_get_new_index(), "h3q_peer_addr");
    if (!bm)
    {
        h3q_tls_error(err, errlen, "BIO_meth_new failed");
        h3q_engine_destroy(engine);
        return NULL;
    }
    BIO_meth_set_ctrl(bm, h3q_peer_addr_bio_ctrl);
    BIO_meth_set_sendmmsg(bm, h3q_peer_addr_bio_sendmmsg);
    BIO_meth_set_recvmmsg(bm, h3q_peer_addr_bio_recvmmsg);
    BIO_meth_set_destroy(bm, h3q_peer_addr_bio_destroy);
    engine->peer_addr_bio_method = bm;

    engine->current_peer_addr = BIO_ADDR_new();
    engine->peer_addr_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, h3q_peer_addr_ex_free);
    if (!engine->current_peer_addr || engine->peer_addr_ex_index < 0)
    {
        h3q_tls_error(err, errlen, "initializing peer address recovery failed");
        h3q_engine_destroy(engine);
        return NULL;
    }

    SSL_CTX_set_new_pending_conn_cb(engine->ssl_ctx, h3q_new_pending_conn_cb, engine);

    uint64_t listener_flags = cfg->address_validation ? 0 : (uint64_t)SSL_LISTENER_FLAG_NO_VALIDATE;
    engine->ssl_listener = SSL_new_listener(engine->ssl_ctx, listener_flags);
    if (!engine->ssl_listener)
    {
        h3q_tls_error(err, errlen, "SSL_new_listener failed");
        h3q_engine_destroy(engine);
        return NULL;
    }

    BIO* bio = BIO_new_dgram(udp_fd, BIO_NOCLOSE);
    if (!bio)
    {
        h3q_tls_error(err, errlen, "BIO_new_dgram failed for fd=%d", udp_fd);
        h3q_engine_destroy(engine);
        return NULL;
    }

    BIO* filter_bio = BIO_new(bm);
    if (!filter_bio)
    {
        h3q_tls_error(err, errlen, "BIO_new(h3q_peer_addr) failed");
        BIO_free(bio);
        h3q_engine_destroy(engine);
        return NULL;
    }

    BIO_set_data(filter_bio, engine);
    bio = BIO_push(filter_bio, bio);
    SSL_set_bio(engine->ssl_listener, bio, bio);

    if (!SSL_listen(engine->ssl_listener) || !SSL_set_blocking_mode(engine->ssl_listener, 0))
    {
        h3q_tls_error(err, errlen, "SSL_listen failed");
        h3q_engine_destroy(engine);
        return NULL;
    }

    return engine;
}

void h3q_engine_destroy(h3q_engine* engine)
{
    if (!engine)
    {
        return;
    }
    h3q_peer_addr_queue_clear(engine);
    if (engine->ssl_listener)
    {
        SSL_free(engine->ssl_listener);
    }
    if (engine->current_peer_addr)
    {
        BIO_ADDR_free(engine->current_peer_addr);
    }
    if (engine->peer_addr_bio_method)
    {
        BIO_meth_free(engine->peer_addr_bio_method);
    }
    if (engine->ssl_ctx)
    {
        SSL_CTX_free(engine->ssl_ctx);
    }
    free(engine);
}

int h3q_engine_pump(h3q_engine* engine)
{
    if (!engine || !engine->ssl_listener)
    {
        return 0;
    }
    int work = 0;
    SSL_handle_events(engine->ssl_listener);
    while (engine->peer_rx_head)
    {
        if (SSL_handle_events(engine->ssl_listener) != 1)
        {
            break;
        }
        work = 1;
    }
    return work;
}

void h3q_engine_want(h3q_engine* engine, int* want_read, int* want_write, int* timeout_ms)
{
    if (!engine || !engine->ssl_listener)
    {
        *want_read = 0;
        *want_write = 0;
        *timeout_ms = 1000;
        return;
    }
    *want_read = SSL_net_read_desired(engine->ssl_listener);
    *want_write = SSL_net_write_desired(engine->ssl_listener);

    struct timeval tv = {0};
    int is_infinite = 0;
    if (SSL_get_event_timeout(engine->ssl_listener, &tv, &is_infinite) && !is_infinite)
    {
        long ms = (long)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
        if (ms < *timeout_ms)
        {
            *timeout_ms = (int)ms;
        }
    }
    /* Never hand back a zero: a timer that reports as already due would turn the
     * caller's wait into a busy loop if pumping does not advance it. */
    if (*timeout_ms < 1)
    {
        *timeout_ms = 1;
    }
}

h3q_conn* h3q_engine_accept_conn(h3q_engine* engine)
{
    if (!engine || !engine->ssl_listener)
    {
        return NULL;
    }
    SSL* conn = SSL_accept_connection(engine->ssl_listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
    return (h3q_conn*)conn;
}

int h3q_engine_peer_addr(h3q_engine* engine, h3q_conn* conn, struct sockaddr_storage* addr, socklen_t* addr_len)
{
    CHECK(engine);
    CHECK(conn);
    CHECK(addr);
    CHECK(addr_len);
    if (engine->peer_addr_ex_index < 0)
    {
        return 0;
    }

    /* Recorded by h3q_new_pending_conn_cb when the connection first appeared. */
    const BIO_ADDR* peer = SSL_get_ex_data((SSL*)conn, engine->peer_addr_ex_index);
    if (!peer)
    {
        return 0;
    }

    memset(addr, 0, sizeof(*addr));
    size_t rawlen = 0;
    int family = BIO_ADDR_family(peer);
    if (family == AF_INET)
    {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        if (!BIO_ADDR_rawaddress(peer, &sin->sin_addr, &rawlen) || rawlen != sizeof(sin->sin_addr))
        {
            return 0;
        }
        sin->sin_family = AF_INET;
        sin->sin_port = BIO_ADDR_rawport(peer);
        *addr_len = sizeof(*sin);
        return 1;
    }
    if (family == AF_INET6)
    {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
        if (!BIO_ADDR_rawaddress(peer, &sin6->sin6_addr, &rawlen) || rawlen != sizeof(sin6->sin6_addr))
        {
            return 0;
        }
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = BIO_ADDR_rawport(peer);
        *addr_len = sizeof(*sin6);
        return 1;
    }
    return 0;
}
