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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

#include "h3_check.h"
#include "h3_os.h"
#include "quic/detail/h3q_impl.h"
#include "quic/detail/h3q_tls.h"
#include "quic/h3q.h"
#include "quic/h3q_conn.h"

#ifdef _WIN32
typedef int h3q_iolen; /* winsock takes int lengths */
#else
typedef size_t h3q_iolen;
#endif

/* ngtcp2 aborts if time goes back, so use a monotonic clock, never the wall clock. */
ngtcp2_tstamp h3q_now(void)
{
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (ngtcp2_tstamp)(c.QuadPart / f.QuadPart) * NGTCP2_SECONDS + (ngtcp2_tstamp)(c.QuadPart % f.QuadPart) * NGTCP2_SECONDS / (ngtcp2_tstamp)f.QuadPart;
#else
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (ngtcp2_tstamp)tp.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)tp.tv_nsec;
#endif
}

static void send_raw(h3q_engine* engine, const struct sockaddr* dst, socklen_t dstlen, const uint8_t* buf, size_t len)
{
    /* A failed send is a lost datagram; loss recovery resends it. */
    (void)sendto(engine->fd, (const char*)buf, (h3q_iolen)len, 0, dst, dstlen);
}

void h3q_send(h3q_engine* engine, const ngtcp2_path* path, const uint8_t* buf, size_t len)
{
    send_raw(engine, (const struct sockaddr*)path->remote.addr, (socklen_t)path->remote.addrlen, buf, len);
}

/* A peer that offers an unknown version is told which versions we speak. */
static void send_version_negotiation(h3q_engine* engine, const ngtcp2_version_cid* vc, const struct sockaddr* peer, socklen_t peerlen)
{
    static const uint32_t versions[] = {NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2};
    uint8_t rnd = 0;
    uint8_t buf[H3Q_PKT_BUF];
    if (RAND_bytes(&rnd, 1) != 1)
    {
        return;
    }
    ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(buf, sizeof(buf), rnd, vc->scid, vc->scidlen, vc->dcid, vc->dcidlen, versions, 2);
    if (n > 0)
    {
        send_raw(engine, peer, peerlen, buf, (size_t)n);
    }
}

static void send_retry(h3q_engine* engine, const ngtcp2_pkt_hd* hd, const struct sockaddr* peer, socklen_t peerlen)
{
    ngtcp2_cid scid = {.datalen = H3Q_SCIDLEN};
    uint8_t token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
    uint8_t buf[H3Q_PKT_BUF];
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1)
    {
        return;
    }
    ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_retry_token2(token, engine->secret, sizeof(engine->secret), hd->version, (const ngtcp2_sockaddr*)peer, (ngtcp2_socklen)peerlen, &scid, &hd->dcid, h3q_now());
    if (tokenlen < 0)
    {
        return;
    }
    ngtcp2_ssize n = ngtcp2_crypto_write_retry(buf, sizeof(buf), hd->version, &hd->scid, &scid, &hd->dcid, token, (size_t)tokenlen);
    if (n > 0)
    {
        send_raw(engine, peer, peerlen, buf, (size_t)n);
    }
}

static h3q_conn* accept_initial(h3q_engine* engine, const uint8_t* pkt, size_t pktlen, const struct sockaddr* peer, socklen_t peerlen)
{
    ngtcp2_pkt_hd hd;
    if (ngtcp2_accept(&hd, pkt, pktlen) != 0)
    {
        return NULL;
    }
    if (!engine->address_validation)
    {
        return h3q_conn_new(engine, &hd, NULL, NULL, peer, peerlen);
    }
    ngtcp2_cid odcid;
    if (hd.tokenlen == 0 || hd.token[0] != NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2 || ngtcp2_crypto_verify_retry_token2(&odcid, hd.token, hd.tokenlen, engine->secret, sizeof(engine->secret), hd.version, (const ngtcp2_sockaddr*)peer, (ngtcp2_socklen)peerlen, &hd.dcid, H3Q_RETRY_TOKEN_TIMEOUT, h3q_now()) != 0)
    {
        send_retry(engine, &hd, peer, peerlen);
        return NULL;
    }
    return h3q_conn_new(engine, &hd, &odcid, &hd.dcid, peer, peerlen);
}

static void process_dgram(h3q_engine* engine, uint8_t* buf, size_t len, struct sockaddr_storage* peer, socklen_t peerlen)
{
    ngtcp2_version_cid vc;
    int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, len, H3Q_SCIDLEN);
    if (rv != 0)
    {
        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {
            send_version_negotiation(engine, &vc, (struct sockaddr*)peer, peerlen);
        }
        return;
    }
    h3q_conn* conn = apr_hash_get(engine->conns, vc.dcid, (apr_ssize_t)vc.dcidlen);
    if (!conn)
    {
        conn = accept_initial(engine, buf, len, (struct sockaddr*)peer, peerlen);
    }
    if (conn && conn->close_len)
    {
        h3q_conn_resend_close(conn, (struct sockaddr*)peer, peerlen);
        return;
    }
    if (!conn || conn->closed)
    {
        return;
    }
    ngtcp2_path path = {
        .local = {.addr = (ngtcp2_sockaddr*)&engine->local, .addrlen = (ngtcp2_socklen)engine->local_len},
        .remote = {.addr = (ngtcp2_sockaddr*)peer, .addrlen = (ngtcp2_socklen)peerlen},
    };
    ngtcp2_pkt_info pi = {0};
    rv = ngtcp2_conn_read_pkt(conn->qconn, &path, &pi, buf, len, h3q_now());
    switch (rv)
    {
    case 0:
        h3q_conn_flush(conn);
        return;
    case NGTCP2_ERR_RETRY:
    {
        ngtcp2_pkt_hd hd;
        if (ngtcp2_accept(&hd, buf, len) == 0)
        {
            send_retry(engine, &hd, (struct sockaddr*)peer, peerlen);
        }
        return;
    }
    case NGTCP2_ERR_DROP_CONN:
    case NGTCP2_ERR_DRAINING:
    case NGTCP2_ERR_CLOSING:
        conn->closed = 1;
        return;
    default:
        h3q_conn_fail(conn, rv);
        return;
    }
}

/* 0: nothing to read now. 1: that datagram is lost, read on. -1: the socket is broken. */
static int recv_failed(void)
{
#ifdef _WIN32
    int e = WSAGetLastError();
    if (e == WSAEWOULDBLOCK)
    {
        return 0;
    }
    return (e == WSAEINTR || e == WSAECONNRESET || e == WSAEMSGSIZE) ? 1 : -1;
#else
    if (errno == EAGAIN)
    {
        return 0;
    }
    return (errno == EINTR || errno == ECONNREFUSED) ? 1 : -1;
#endif
}

h3q_engine* h3q_engine_create(const h3q_config* cfg, int udp_fd, char* err, size_t errlen)
{
    CHECK(cfg);
    if (!cfg->ssl_ctx || !cfg->pool)
    {
        h3q_tls_error(err, errlen, "no TLS context to serve from");
        return NULL;
    }
    h3q_engine* engine = calloc(1, sizeof(*engine));
    if (!engine || apr_pool_create(&engine->pool, cfg->pool) != APR_SUCCESS)
    {
        free(engine);
        h3q_tls_error(err, errlen, "allocating the engine failed");
        return NULL;
    }
    engine->conns = apr_hash_make(engine->pool);
    engine->fd = udp_fd;
    engine->stream_acked = cfg->stream_acked;
    engine->idle_timeout_secs = cfg->idle_timeout_secs;
    engine->max_streams_bidi = cfg->max_streams_bidi;
    engine->address_validation = cfg->address_validation;
    engine->early_data = cfg->early_data;
    engine->local_len = (socklen_t)sizeof(engine->local);
    if (getsockname(udp_fd, (struct sockaddr*)&engine->local, &engine->local_len) != 0 || RAND_bytes(engine->secret, (int)sizeof(engine->secret)) != 1 || !SSL_CTX_up_ref(cfg->ssl_ctx))
    {
        h3q_tls_error(err, errlen, "reading the local address of fd=%d failed", udp_fd);
        h3q_engine_destroy(engine);
        return NULL;
    }
    engine->ssl_ctx = cfg->ssl_ctx;
    return engine;
}

void h3q_engine_destroy(h3q_engine* engine)
{
    if (!engine)
    {
        return;
    }
    while (engine->conns_head)
    {
        h3q_conn_free(engine->conns_head);
    }
    apr_pool_destroy(engine->pool);
    if (engine->ssl_ctx)
    {
        SSL_CTX_free(engine->ssl_ctx);
    }
    free(engine);
}

int h3q_engine_pump(h3q_engine* engine)
{
    if (!engine)
    {
        return 0;
    }
    uint8_t buf[65536];
    int work = 0;
    for (int i = 0; i < H3Q_RECV_BUDGET; i++)
    {
        struct sockaddr_storage peer;
        socklen_t peerlen = (socklen_t)sizeof(peer);
        int n = (int)recvfrom(engine->fd, (char*)buf, (h3q_iolen)sizeof(buf), 0, (struct sockaddr*)&peer, &peerlen);
        if (n < 0)
        {
            int why = recv_failed();
            if (why == 0)
            {
                break;
            }
            if (why < 0)
            {
                return -1;
            }
            continue;
        }
        work = 1;
        if (n > 0)
        {
            process_dgram(engine, buf, (size_t)n, &peer, peerlen);
        }
    }
    ngtcp2_tstamp now = h3q_now();
    for (h3q_conn* conn = engine->conns_head; conn; conn = conn->next)
    {
        if (conn->closed || ngtcp2_conn_get_expiry(conn->qconn) > now)
        {
            continue;
        }
        int rv = ngtcp2_conn_handle_expiry(conn->qconn, now);
        if (rv != 0)
        {
            h3q_conn_fail(conn, rv);
            continue;
        }
        h3q_conn_flush(conn);
    }
    return work;
}

void h3q_engine_want(h3q_engine* engine, int* want_read, int* want_write, int* timeout_ms)
{
    *want_read = 1;
    *want_write = 0;
    if (!engine)
    {
        return;
    }
    ngtcp2_tstamp now = h3q_now();
    for (h3q_conn* conn = engine->conns_head; conn; conn = conn->next)
    {
        if (conn->closed)
        {
            continue;
        }
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->qconn);
        int64_t ms = expiry <= now ? 1 : (int64_t)((expiry - now) / NGTCP2_MILLISECONDS) + 1;
        if (ms < *timeout_ms)
        {
            *timeout_ms = (int)ms;
        }
    }
}

h3q_conn* h3q_engine_accept_conn(h3q_engine* engine)
{
    if (!engine || !engine->accept_head)
    {
        return NULL;
    }
    h3q_conn* conn = engine->accept_head;
    engine->accept_head = conn->next_accept;
    if (!engine->accept_head)
    {
        engine->accept_tail = NULL;
    }
    conn->next_accept = NULL;
    conn->queued_accept = 0;
    return conn;
}

int h3q_engine_peer_addr(h3q_engine* engine, h3q_conn* conn, struct sockaddr_storage* addr, socklen_t* addr_len)
{
    (void)engine;
    if (!conn || !addr || !addr_len || conn->path.path.remote.addrlen == 0 || conn->path.path.remote.addrlen > sizeof(*addr))
    {
        return 0;
    }
    memcpy(addr, conn->path.path.remote.addr, conn->path.path.remote.addrlen);
    *addr_len = (socklen_t)conn->path.path.remote.addrlen;
    return 1;
}
