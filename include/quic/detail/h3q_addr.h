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

#ifndef H3Q_DETAIL_ADDR_H
#define H3Q_DETAIL_ADDR_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "quic/h3q.h"

typedef struct h3q_datagram h3q_datagram;

/** The listener's state. All but the two SSL handles exist to recover a
 *  connection's peer address, which OpenSSL 3.5 does not otherwise expose;
 *  that is why the definition lives beside the machinery that fills it. */
struct h3q_engine
{
    SSL_CTX* ssl_ctx;
    SSL* ssl_listener;

    BIO_METHOD* peer_addr_bio_method;
    BIO_ADDR* current_peer_addr;
    int peer_addr_ex_index;
    h3q_datagram* peer_rx_head;
    h3q_datagram* peer_rx_tail;
};

/**
 * Drop every datagram still queued on the engine.
 * @param engine Engine whose receive queue is emptied.
 */
void h3q_peer_addr_queue_clear(h3q_engine* engine);

/**
 * BIO_meth_set_ctrl handler for the peer-address filter BIO.
 * @param bio Filter BIO receiving the control operation.
 * @param cmd Control command, forwarded to the underlying BIO.
 * @param num Command-specific numeric argument.
 * @param ptr Command-specific pointer argument.
 * @return Whatever the underlying BIO returns for @p cmd.
 */
long h3q_peer_addr_bio_ctrl(BIO* bio, int cmd, long num, void* ptr);

/**
 * BIO_meth_set_sendmmsg handler, forwarding to the underlying BIO.
 * @param bio            Filter BIO the datagrams are written through.
 * @param msg            Array of messages to send.
 * @param stride         Size of one entry in @p msg.
 * @param num_msg        Number of entries in @p msg.
 * @param flags          Flags passed through to the underlying BIO.
 * @param msgs_processed Out: how many messages were sent.
 * @return 1 on success, 0 on failure.
 */
int h3q_peer_addr_bio_sendmmsg(BIO* bio, BIO_MSG* msg, size_t stride, size_t num_msg, uint64_t flags, size_t* msgs_processed);

/**
 * BIO_meth_set_recvmmsg handler, recording each datagram's peer address.
 * @param bio            Filter BIO the datagrams are read through.
 * @param msg            Array receiving the messages.
 * @param stride         Size of one entry in @p msg.
 * @param num_msg        Capacity of @p msg.
 * @param flags          Flags passed through to the underlying BIO.
 * @param msgs_processed Out: how many messages were received.
 * @return 1 on success, 0 on failure.
 */
int h3q_peer_addr_bio_recvmmsg(BIO* bio, BIO_MSG* msg, size_t stride, size_t num_msg, uint64_t flags, size_t* msgs_processed);

/**
 * BIO_meth_set_destroy handler, clearing the datagram queue.
 * @param bio Filter BIO being destroyed.
 * @return 1 on success.
 */
int h3q_peer_addr_bio_destroy(BIO* bio);

/**
 * SSL ex_data free callback for a connection's stored peer address.
 * @param parent Object the ex_data belongs to.
 * @param ptr    The stored BIO_ADDR, freed here.
 * @param ad     ex_data store being torn down.
 * @param idx    Index the value was stored at.
 * @param argl   Long argument registered with the index.
 * @param argp   Pointer argument registered with the index.
 */
void h3q_peer_addr_ex_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

/**
 * SSL_CTX new-pending-conn callback, attaching the peer address to @p conn.
 * @param ctx  Context the connection was created on.
 * @param conn Newly pending connection.
 * @param arg  The owning h3q_engine.
 * @return 1 to accept the connection, 0 to reject it.
 */
int h3q_new_pending_conn_cb(SSL_CTX* ctx, SSL* conn, void* arg);

#endif /* H3Q_DETAIL_ADDR_H */
