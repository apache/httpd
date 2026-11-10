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

#if defined(__linux__) && !defined(_GNU_SOURCE)
    #define _GNU_SOURCE /* struct in6_pktinfo */
#endif

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

#ifdef __linux__
    #include <netinet/in.h>
    #include <netinet/udp.h>
    #include <sys/uio.h>
    /* Kernel ABI values, for libc headers older than GSO and GRO; old kernels fall back at run time. */
    #ifndef SOL_UDP
        #define SOL_UDP 17
    #endif
    #ifndef UDP_SEGMENT
        #define UDP_SEGMENT 103
    #endif
    #ifndef UDP_GRO
        #define UDP_GRO 104
    #endif
#endif

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

#ifdef __linux__
static int is_wildcard(const struct sockaddr_storage* a)
{
    if (a->ss_family == AF_INET6)
    {
        return IN6_IS_ADDR_UNSPECIFIED(&((const struct sockaddr_in6*)a)->sin6_addr);
    }
    return a->ss_family == AF_INET && ((const struct sockaddr_in*)a)->sin_addr.s_addr == htonl(INADDR_ANY);
}

/* One sendmsg. src picks the source address; seg > 0 asks GSO to cut buf into seg-byte datagrams.
 * An IPv4-mapped source takes IP_PKTINFO: such a packet leaves by the IPv4 path. */
static ssize_t send_msg(h3q_engine* engine, const struct sockaddr* dst, socklen_t dstlen, const struct sockaddr_storage* src, const uint8_t* buf, size_t len, uint16_t seg)
{
    union
    {
        char b[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
    } ctl;
    memset(&ctl, 0, sizeof(ctl));
    struct iovec iov = {.iov_base = (void*)buf, .iov_len = len};
    struct msghdr m = {.msg_name = (void*)dst, .msg_namelen = dstlen, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.b};
    size_t used = 0;
    const struct in6_addr* a6 = src && src->ss_family == AF_INET6 ? &((const struct sockaddr_in6*)src)->sin6_addr : NULL;
    if ((src && src->ss_family == AF_INET) || (a6 && IN6_IS_ADDR_V4MAPPED(a6)))
    {
        struct in_pktinfo pi;
        memset(&pi, 0, sizeof(pi));
        memcpy(&pi.ipi_spec_dst, a6 ? (const void*)&a6->s6_addr[12] : (const void*)&((const struct sockaddr_in*)src)->sin_addr, 4);
        struct cmsghdr* c = (struct cmsghdr*)ctl.b;
        c->cmsg_level = IPPROTO_IP;
        c->cmsg_type = IP_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof(pi));
        memcpy(CMSG_DATA(c), &pi, sizeof(pi));
        used = CMSG_SPACE(sizeof(pi));
    }
    else if (a6)
    {
        struct in6_pktinfo pi;
        memset(&pi, 0, sizeof(pi));
        pi.ipi6_addr = *a6;
        struct cmsghdr* c = (struct cmsghdr*)ctl.b;
        c->cmsg_level = IPPROTO_IPV6;
        c->cmsg_type = IPV6_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof(pi));
        memcpy(CMSG_DATA(c), &pi, sizeof(pi));
        used = CMSG_SPACE(sizeof(pi));
    }
    if (seg)
    {
        struct cmsghdr* c = (struct cmsghdr*)(ctl.b + used);
        c->cmsg_level = SOL_UDP;
        c->cmsg_type = UDP_SEGMENT;
        c->cmsg_len = CMSG_LEN(sizeof(seg));
        memcpy(CMSG_DATA(c), &seg, sizeof(seg));
        used += CMSG_SPACE(sizeof(seg));
    }
    m.msg_controllen = used;
    if (!used)
    {
        m.msg_control = NULL;
    }
    return sendmsg(engine->fd, &m, 0);
}

/* The ECN codepoint is a socket option, so set it only when it changes. IP_TOS covers IPv4-mapped peers. */
static void set_ecn(h3q_engine* engine, uint32_t ecn)
{
    int tos = (int)ecn;
    if (tos == engine->sock_ecn)
    {
        return;
    }
    engine->sock_ecn = tos;
    if (engine->local.ss_family == AF_INET6)
    {
        (void)setsockopt(engine->fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
    }
    (void)setsockopt(engine->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
}
#endif

/* A failed send is a lost datagram; loss recovery resends it. */
static void send_one(h3q_engine* engine, const struct sockaddr* dst, socklen_t dstlen, const struct sockaddr_storage* src, const uint8_t* buf, size_t len)
{
#ifdef __linux__
    if (send_msg(engine, dst, dstlen, src, buf, len, 0) < 0 && errno == EINVAL && src)
    {
        (void)send_msg(engine, dst, dstlen, NULL, buf, len, 0); /* that address is gone: the kernel picks one */
    }
#else
    (void)src;
    (void)sendto(engine->fd, (const char*)buf, (h3q_iolen)len, 0, dst, dstlen);
#endif
}

void h3q_send(h3q_engine* engine, const ngtcp2_path* path, uint32_t ecn, const uint8_t* buf, size_t len)
{
    const struct sockaddr* dst = (const struct sockaddr*)path->remote.addr;
    socklen_t dstlen = (socklen_t)path->remote.addrlen;
    struct sockaddr_storage src;
    memset(&src, 0, sizeof(src));
    if (engine->pktinfo && path->local.addrlen && path->local.addrlen <= sizeof(src))
    {
        memcpy(&src, path->local.addr, path->local.addrlen);
    }
    /* A new peer, source or ECN mark, a larger packet or a full batch starts a new batch. */
    if (engine->tx_n && (dstlen != engine->tx_dstlen || memcmp(dst, &engine->tx_dst, (size_t)dstlen) != 0 || memcmp(&src, &engine->tx_src, sizeof(src)) != 0 || ecn != engine->tx_ecn || len > engine->tx_seg || engine->tx_len + len > H3Q_GSO_BYTES || engine->tx_n == H3Q_GSO_SEGS))
    {
        h3q_tx_flush(engine);
    }
    if (!engine->tx_n)
    {
        memcpy(&engine->tx_dst, dst, (size_t)dstlen);
        engine->tx_dstlen = dstlen;
        engine->tx_src = src;
        engine->tx_ecn = ecn;
        engine->tx_seg = len;
    }
    memcpy(engine->tx + engine->tx_len, buf, len);
    engine->tx_len += len;
    engine->tx_n++;
    if (!engine->gso || len < engine->tx_seg)
    {
        h3q_tx_flush(engine); /* only the last segment may be shorter */
    }
}

void h3q_tx_flush(h3q_engine* engine)
{
    if (!engine->tx_n)
    {
        return;
    }
    const struct sockaddr* dst = (const struct sockaddr*)&engine->tx_dst;
    const struct sockaddr_storage* src = engine->tx_src.ss_family ? &engine->tx_src : NULL;
    int sent = engine->tx_n == 1;
#ifdef __linux__
    set_ecn(engine, engine->tx_ecn);
#endif
    if (sent)
    {
        send_one(engine, dst, engine->tx_dstlen, src, engine->tx, engine->tx_len);
    }
#ifdef __linux__
    else
    {
        /* No GSO in this kernel or device: turn it off and send one by one. */
        sent = send_msg(engine, dst, engine->tx_dstlen, src, engine->tx, engine->tx_len, (uint16_t)engine->tx_seg) >= 0 || (errno != EIO && errno != EINVAL && errno != ENOPROTOOPT);
        engine->gso = sent ? 1u : 0u;
    }
#endif
    for (size_t off = 0; !sent && off < engine->tx_len; off += engine->tx_seg)
    {
        size_t n = engine->tx_len - off < engine->tx_seg ? engine->tx_len - off : engine->tx_seg;
        send_one(engine, dst, engine->tx_dstlen, src, engine->tx + off, n);
    }
    engine->tx_n = 0;
    engine->tx_len = 0;
}

/* One read; with GRO the kernel may join datagrams of one peer, and *seg is their size.
 * On Linux *local becomes the address the peer sent to, and *ecn its ECN mark. */
static int recv_dgram(h3q_engine* engine, uint8_t* buf, size_t cap, struct sockaddr_storage* peer, socklen_t* peerlen, struct sockaddr_storage* local, size_t* seg, uint32_t* ecn)
{
    *ecn = NGTCP2_ECN_NOT_ECT;
#ifdef __linux__
    union
    {
        char b[CMSG_SPACE(sizeof(int)) * 3 + CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo))];
        struct cmsghdr align;
    } ctl;
    struct iovec iov = {.iov_base = buf, .iov_len = cap};
    struct msghdr m = {.msg_name = peer, .msg_namelen = *peerlen, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.b, .msg_controllen = sizeof(ctl.b)};
    int n = (int)recvmsg(engine->fd, &m, 0);
    *peerlen = m.msg_namelen;
    *seg = n > 0 ? (size_t)n : 0;
    for (struct cmsghdr* c = CMSG_FIRSTHDR(&m); n > 0 && c; c = CMSG_NXTHDR(&m, c))
    {
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_GRO)
        {
            int gro = 0;
            memcpy(&gro, CMSG_DATA(c), sizeof(gro));
            *seg = gro > 0 ? (size_t)gro : *seg;
        }
        else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO && local->ss_family == AF_INET6)
        {
            struct in6_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof(pi));
            struct sockaddr_in6* l = (struct sockaddr_in6*)local;
            l->sin6_addr = pi.ipi6_addr;
            l->sin6_scope_id = IN6_IS_ADDR_LINKLOCAL(&pi.ipi6_addr) ? (uint32_t)pi.ipi6_ifindex : 0;
        }
        else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO)
        {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof(pi));
            if (local->ss_family == AF_INET6)
            {
                struct sockaddr_in6* l = (struct sockaddr_in6*)local;
                memset(&l->sin6_addr, 0, sizeof(l->sin6_addr));
                l->sin6_addr.s6_addr[10] = 0xff;
                l->sin6_addr.s6_addr[11] = 0xff;
                memcpy(&l->sin6_addr.s6_addr[12], &pi.ipi_addr, 4);
                l->sin6_scope_id = 0;
            }
            else
            {
                ((struct sockaddr_in*)local)->sin_addr = pi.ipi_addr;
            }
        }
        else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_TCLASS)
        {
            int tclass = 0;
            memcpy(&tclass, CMSG_DATA(c), sizeof(tclass));
            *ecn = (uint32_t)tclass & 0x3;
        }
        else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TOS)
        {
            *ecn = (uint32_t)*(const uint8_t*)CMSG_DATA(c) & 0x3;
        }
    }
    return n;
#else
    (void)local;
    int n = (int)recvfrom(engine->fd, (char*)buf, (h3q_iolen)cap, 0, (struct sockaddr*)peer, peerlen);
    *seg = n > 0 ? (size_t)n : 0;
    return n;
#endif
}

/* A peer that offers an unknown version is told which versions we speak. */
static void send_version_negotiation(h3q_engine* engine, const ngtcp2_version_cid* vc, const ngtcp2_path* path)
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
        h3q_send(engine, path, NGTCP2_ECN_NOT_ECT, buf, (size_t)n);
        h3q_tx_flush(engine);
    }
}

static void send_retry(h3q_engine* engine, const ngtcp2_pkt_hd* hd, const ngtcp2_path* path)
{
    ngtcp2_cid scid = {.datalen = H3Q_SCIDLEN};
    uint8_t token[NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2];
    uint8_t buf[H3Q_PKT_BUF];
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1)
    {
        return;
    }
    ngtcp2_ssize tokenlen = ngtcp2_crypto_generate_retry_token2(token, engine->secret, sizeof(engine->secret), hd->version, path->remote.addr, path->remote.addrlen, &scid, &hd->dcid, h3q_now());
    if (tokenlen < 0)
    {
        return;
    }
    ngtcp2_ssize n = ngtcp2_crypto_write_retry(buf, sizeof(buf), hd->version, &hd->scid, &scid, &hd->dcid, token, (size_t)tokenlen);
    if (n > 0)
    {
        h3q_send(engine, path, NGTCP2_ECN_NOT_ECT, buf, (size_t)n);
        h3q_tx_flush(engine);
    }
}

static h3q_conn* accept_initial(h3q_engine* engine, const uint8_t* pkt, size_t pktlen, const ngtcp2_path* path)
{
    ngtcp2_pkt_hd hd;
    if (ngtcp2_accept(&hd, pkt, pktlen) != 0)
    {
        return NULL;
    }
    if (!engine->address_validation)
    {
        return h3q_conn_new(engine, &hd, NULL, NULL, path);
    }
    ngtcp2_cid odcid;
    if (hd.tokenlen == 0 || hd.token[0] != NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2 || ngtcp2_crypto_verify_retry_token2(&odcid, hd.token, hd.tokenlen, engine->secret, sizeof(engine->secret), hd.version, path->remote.addr, path->remote.addrlen, &hd.dcid, H3Q_RETRY_TOKEN_TIMEOUT, h3q_now()) != 0)
    {
        send_retry(engine, &hd, path);
        return NULL;
    }
    return h3q_conn_new(engine, &hd, &odcid, &hd.dcid, path);
}

static void process_dgram(h3q_engine* engine, uint8_t* buf, size_t len, const ngtcp2_path* path, uint32_t ecn)
{
    ngtcp2_version_cid vc;
    int rv = ngtcp2_pkt_decode_version_cid(&vc, buf, len, H3Q_SCIDLEN);
    if (rv != 0)
    {
        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
        {
            send_version_negotiation(engine, &vc, path);
        }
        return;
    }
    h3q_conn* conn = apr_hash_get(engine->conns, vc.dcid, (apr_ssize_t)vc.dcidlen);
    if (!conn)
    {
        conn = accept_initial(engine, buf, len, path);
    }
    if (conn && conn->close_len)
    {
        h3q_conn_resend_close(conn, path);
        return;
    }
    if (!conn || conn->closed)
    {
        return;
    }
    conn->activity = 1;
    ngtcp2_pkt_info pi = {.ecn = (uint8_t)ecn};
    rv = ngtcp2_conn_read_pkt(conn->qconn, path, &pi, buf, len, h3q_now());
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
            send_retry(engine, &hd, path);
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
    engine->max_window = cfg->max_window;
    engine->address_validation = cfg->address_validation;
    engine->early_data = cfg->early_data;
    engine->local_len = (socklen_t)sizeof(engine->local);
    engine->disable_migration = cfg->disable_migration;
    engine->sock_ecn = -1;
    if (cfg->secret)
    {
        memcpy(engine->secret, cfg->secret, sizeof(engine->secret));
    }
    if (getsockname(udp_fd, (struct sockaddr*)&engine->local, &engine->local_len) != 0 || (!cfg->secret && RAND_bytes(engine->secret, (int)sizeof(engine->secret)) != 1) || !SSL_CTX_up_ref(cfg->ssl_ctx))
    {
        h3q_tls_error(err, errlen, "reading the local address of fd=%d failed", udp_fd);
        h3q_engine_destroy(engine);
        return NULL;
    }
    engine->ssl_ctx = cfg->ssl_ctx;
#ifdef __linux__
    int on = 1;
    (void)setsockopt(udp_fd, SOL_UDP, UDP_GRO, &on, sizeof(on)); /* GRO is optional */
    /* ECN marks in, also optional. IPv4-mapped peers report through the IPv4 option. */
    (void)setsockopt(udp_fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
    (void)setsockopt(udp_fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
    /* A wildcard socket must reply from the address each packet came to, or a host with more than one address replies from the wrong one. */
    if (is_wildcard(&engine->local))
    {
        int v6 = engine->local.ss_family == AF_INET6 && setsockopt(udp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == 0;
        int v4 = setsockopt(udp_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0;
        engine->pktinfo = (v6 || v4) ? 1u : 0u;
    }
    engine->gso = 1;
#endif
    engine->tx = apr_palloc(engine->pool, H3Q_GSO_BYTES);
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
        struct sockaddr_storage local;
        memcpy(&local, &engine->local, (size_t)engine->local_len);
        size_t seg = 0;
        uint32_t ecn = NGTCP2_ECN_NOT_ECT;
        int n = recv_dgram(engine, buf, sizeof(buf), &peer, &peerlen, &local, &seg, &ecn);
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
        ngtcp2_path path = {
            .local = {.addr = (ngtcp2_sockaddr*)&local, .addrlen = (ngtcp2_socklen)engine->local_len},
            .remote = {.addr = (ngtcp2_sockaddr*)&peer, .addrlen = (ngtcp2_socklen)peerlen},
        };
        for (size_t off = 0; off < (size_t)n; off += seg)
        {
            process_dgram(engine, buf + off, (size_t)n - off < seg ? (size_t)n - off : seg, &path, ecn);
        }
    }
    ngtcp2_tstamp now = h3q_now();
    for (h3q_conn* conn = engine->conns_head; conn; conn = conn->next)
    {
        if (conn->closed || ngtcp2_conn_get_expiry(conn->qconn) > now)
        {
            continue;
        }
        conn->activity = 1;
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
