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

#ifndef H3Q_DETAIL_IMPL_H
#define H3Q_DETAIL_IMPL_H

#include <apr_hash.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>

#include "quic/h3q.h"

#define H3Q_SCIDLEN 18
#define H3Q_PKT_BUF 1500
#define H3Q_RECV_BUDGET 64
#define H3Q_GSO_SEGS 64       /* kernel UDP_MAX_SEGMENTS */
#define H3Q_GSO_BYTES 65000
#define H3Q_RETRY_TOKEN_TIMEOUT (10 * NGTCP2_SECONDS)
#define H3Q_CID_SLOTS 16 /* ngtcp2 keeps at most 8 server CIDs, live and retired, plus 2 client DCIDs */

struct h3q_engine
{
    SSL_CTX* ssl_ctx;
    int fd;
    apr_pool_t* pool;
    apr_hash_t* conns; /* CID bytes -> h3q_conn */
    h3q_conn* conns_head;
    h3q_conn* accept_head;
    h3q_conn* accept_tail;
    struct sockaddr_storage local;
    socklen_t local_len;
    void (*stream_acked)(void* user, int64_t stream_id, size_t len);
    uint32_t idle_timeout_secs;
    uint32_t max_streams_bidi;
    size_t max_window;
    uint8_t secret[32];
    /* GSO batch: equal-size packets to one peer, sent with one sendmsg (Linux). */
    uint8_t* tx;
    size_t tx_len;
    size_t tx_seg;
    int tx_n;
    struct sockaddr_storage tx_dst;
    socklen_t tx_dstlen;
    struct sockaddr_storage tx_src; /* the address the peer sent to; ss_family 0: the kernel picks */
    uint32_t tx_ecn;
    int sock_ecn; /* ECN codepoint now set on the socket */
    unsigned gso : 1;
    unsigned pktinfo : 1; /* wildcard socket: reply from the address each packet came to */
    unsigned address_validation : 1;
    unsigned early_data : 1;
    unsigned disable_migration : 1;
};

struct h3q_conn
{
    h3q_engine* engine;
    ngtcp2_conn* qconn;
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_crypto_ossl_ctx* ossl_ctx;
    SSL* ssl;
    ngtcp2_path_storage path;
    ngtcp2_cid cids[H3Q_CID_SLOTS]; /* keys of the engine map; datalen 0: free slot */
    uint8_t* close_pkt;             /* CONNECTION_CLOSE, resent while closing (RFC 9000 10.2.1); malloc */
    size_t close_len;
    ngtcp2_tstamp close_until;
    ngtcp2_tstamp close_next;
    int liberr; /* first local ngtcp2 error, for the log */
    h3q_stream* streams_head;
    h3q_stream* accept_head;
    h3q_stream* accept_tail;
    void* user;
    h3q_conn* next;
    h3q_conn* next_accept;
    unsigned handshake_done : 1;
    unsigned closed : 1;
    unsigned queued_accept : 1;
};

struct h3q_stream
{
    h3q_conn* conn;
    int64_t id;
    unsigned char* rx;
    size_t rx_len;
    size_t rx_cap;
    size_t rx_off;
    h3q_stream* next;
    h3q_stream* next_accept;
    unsigned fin : 1;
    unsigned early : 1;
    unsigned read_reset : 1;
    unsigned write_closed : 1;
    unsigned queued_accept : 1;
    unsigned engine_closed : 1;
    unsigned fin_pending : 1; /* FIN refused by ngtcp2 once; retried on flush */
};

ngtcp2_tstamp h3q_now(void);
void h3q_send(h3q_engine* engine, const ngtcp2_path* path, uint32_t ecn, const uint8_t* buf, size_t len);
void h3q_tx_flush(h3q_engine* engine);
h3q_conn* h3q_conn_new(h3q_engine* engine, const ngtcp2_pkt_hd* hd, const ngtcp2_cid* odcid, const ngtcp2_cid* retry_scid, const ngtcp2_path* path);
void h3q_conn_flush(h3q_conn* conn);
void h3q_conn_close(h3q_conn* conn, const ngtcp2_ccerr* ccerr);
void h3q_conn_fail(h3q_conn* conn, int liberr);
void h3q_conn_resend_close(h3q_conn* conn, const ngtcp2_path* path);
h3q_stream* h3q_stream_get(h3q_conn* conn, int64_t id);

#endif /* H3Q_DETAIL_IMPL_H */
