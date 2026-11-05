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

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include "h3_os.h"
#include "quic/detail/h3q_addr.h"

#ifdef H3Q_DCID_DEBUG

static void h3q_hex(char* out, const unsigned char* data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

static void h3q_trace_quic(const char* direction, const unsigned char* data, size_t data_len)
{
    unsigned char dcid[20];
    unsigned char scid[20];
    size_t dcid_len = 0;
    size_t scid_len = 0;
    size_t off;
    char dcid_hex[41];
    char scid_hex[41];
    FILE* f;

    if (data_len < 1)
        return;

    if (data[0] & 0x80) {
        /* Long header: [flags(1)][version(4)][dcid_len(1)][dcid...][scid_len(1)][scid...] */
        if (data_len < 6)
            return;
        dcid_len = data[5];
        if (dcid_len > 20 || data_len < 6 + dcid_len)
            return;
        memcpy(dcid, data + 6, dcid_len);

        off = 6 + dcid_len;
        if (data_len > off) {
            scid_len = data[off];
            if (scid_len <= 20 && data_len >= off + 1 + scid_len)
                memcpy(scid, data + off + 1, scid_len);
            else
                scid_len = 0;
        }

        h3q_hex(dcid_hex, dcid, dcid_len);
        h3q_hex(scid_hex, scid, scid_len);
        f = fopen("/tmp/h3q_dcid.log", "a");
        if (f) {
            fprintf(f, "[h3q] %s long  DCID(%zu): %s  SCID(%zu): %s\n",
                    direction, dcid_len, dcid_hex, scid_len, scid_hex);
            fclose(f);
        }
    } else {
        /* Short header: [flags(1)][dcid...] */
        dcid_len = 8;
        if (data_len < 1 + dcid_len)
            return;
        memcpy(dcid, data + 1, dcid_len);

        h3q_hex(dcid_hex, dcid, dcid_len);
        f = fopen("/tmp/h3q_dcid.log", "a");
        if (f) {
            fprintf(f, "[h3q] %s short DCID(%zu): %s\n",
                    direction, dcid_len, dcid_hex);
            fclose(f);
        }
    }
}

#endif /* H3Q_DCID_DEBUG */

struct h3q_datagram
{
    unsigned char* data;
    size_t data_len;
    BIO_ADDR* peer;
    BIO_ADDR* local;
    h3q_datagram* next;
};

static void h3q_datagram_free(h3q_datagram* item)
{
    OPENSSL_free(item->data);
    BIO_ADDR_free(item->peer);
    BIO_ADDR_free(item->local);
    OPENSSL_free(item);
}

static void h3q_queue_drop_head(h3q_engine* engine)
{
    h3q_datagram* item = engine->peer_rx_head;
    engine->peer_rx_head = item->next;
    if (!engine->peer_rx_head)
    {
        engine->peer_rx_tail = NULL;
    }
    h3q_datagram_free(item);
}

void h3q_peer_addr_queue_clear(h3q_engine* engine)
{
    h3q_datagram* item = engine->peer_rx_head;
    while (item)
    {
        h3q_datagram* next = item->next;
        h3q_datagram_free(item);
        item = next;
    }
    engine->peer_rx_head = NULL;
    engine->peer_rx_tail = NULL;
}

static int h3q_queue_fill(h3q_engine* engine, BIO_MSG* msg, size_t stride, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        BIO_MSG* source = (BIO_MSG*)((unsigned char*)msg + i * stride);
        h3q_datagram* item = OPENSSL_zalloc(sizeof(*item));
        if (!item || !source->data || source->data_len == 0)
        {
            OPENSSL_free(item);
            h3q_peer_addr_queue_clear(engine);
            return 0;
        }
#ifdef H3Q_DCID_DEBUG
        h3q_trace_quic("RECV", source->data, source->data_len);
#endif
        item->data = OPENSSL_memdup(source->data, source->data_len);
        item->data_len = source->data_len;
        item->peer = source->peer ? BIO_ADDR_dup(source->peer) : NULL;
        item->local = source->local ? BIO_ADDR_dup(source->local) : NULL;
        if (!item->data || (source->peer && !item->peer) || (source->local && !item->local))
        {
            OPENSSL_free(item->data);
            BIO_ADDR_free(item->peer);
            BIO_ADDR_free(item->local);
            OPENSSL_free(item);
            h3q_peer_addr_queue_clear(engine);
            return 0;
        }
        if (engine->peer_rx_tail)
        {
            engine->peer_rx_tail->next = item;
        }
        else
        {
            engine->peer_rx_head = item;
        }
        engine->peer_rx_tail = item;
    }
    return 1;
}

static int h3q_queue_pop(h3q_engine* engine, BIO_MSG* msg)
{
    h3q_datagram* item = engine->peer_rx_head;
    if (!item || !msg || !msg->data)
    {
        return 0;
    }
    if (msg->data_len < item->data_len)
    {
        /* Drop it, or the queue head never clears and the pump spins. */
        h3q_queue_drop_head(engine);
        return 0;
    }
    memcpy(msg->data, item->data, item->data_len);
    msg->data_len = item->data_len;
    if (msg->peer && item->peer)
    {
        BIO_ADDR_copy(msg->peer, item->peer);
    }
    if (msg->local && item->local)
    {
        BIO_ADDR_copy(msg->local, item->local);
    }
    h3q_queue_drop_head(engine);
    return 1;
}

long h3q_peer_addr_bio_ctrl(BIO* bio, int cmd, long num, void* ptr)
{
    BIO* next = BIO_next(bio);
    return next ? BIO_ctrl(next, cmd, num, ptr) : 0;
}

int h3q_peer_addr_bio_sendmmsg(BIO* bio, BIO_MSG* msg, size_t stride, size_t num_msg, uint64_t flags, size_t* msgs_processed)
{
    BIO* next = BIO_next(bio);

#ifdef H3Q_DCID_DEBUG
    {
        size_t i;
        for (i = 0; i < num_msg; i++) {
            BIO_MSG* m = (BIO_MSG*)((unsigned char*)msg + i * stride);
            if (m->data && m->data_len > 0)
                h3q_trace_quic("SEND", m->data, m->data_len);
        }
    }
#endif

    return next ? BIO_sendmmsg(next, msg, stride, num_msg, flags, msgs_processed) : 0;
}

int h3q_peer_addr_bio_recvmmsg(BIO* bio, BIO_MSG* msg, size_t stride, size_t num_msg, uint64_t flags, size_t* msgs_processed)
{
    h3q_engine* engine = BIO_get_data(bio);
    BIO* next = BIO_next(bio);
    size_t count;

    if (!engine || !next || !msg || !msgs_processed || num_msg == 0)
    {
        return 0;
    }

    BIO_ADDR_clear(engine->current_peer_addr);

    if (!engine->peer_rx_head)
    {
        size_t received = 0;
        int rv = BIO_recvmmsg(next, msg, stride, num_msg, flags, &received);
        if (!rv || received == 0)
        {
            *msgs_processed = received;
            return rv;
        }
        if (!h3q_queue_fill(engine, msg, stride, received))
        {
            *msgs_processed = 0;
            return 0;
        }
    }

    /* Pop from queue: batch short-header packets (existing connections);
     * long-header packets go one at a time for peer-address capture. */
    count = 0;
    while (count < num_msg && engine->peer_rx_head)
    {
        h3q_datagram* head = engine->peer_rx_head;
        int is_long = (head->data_len > 0 && (head->data[0] & 0x80));

        if (is_long && count > 0)
        {
            break;
        }

        BIO_MSG* dst = (BIO_MSG*)((unsigned char*)msg + count * stride);
        if (!h3q_queue_pop(engine, dst))
        {
            break;
        }
        count++;

        if (is_long)
        {
            if (dst->peer)
            {
                BIO_ADDR_copy(engine->current_peer_addr, dst->peer);
            }
            break;
        }
    }
    *msgs_processed = count;
    return count > 0 ? 1 : 0;
}

int h3q_peer_addr_bio_destroy(BIO* bio)
{
    h3q_engine* engine = BIO_get_data(bio);
    if (engine)
    {
        h3q_peer_addr_queue_clear(engine);
    }
    return 1;
}

void h3q_peer_addr_ex_free(void* parent H3_UNUSED, void* ptr, CRYPTO_EX_DATA* ad H3_UNUSED, int idx H3_UNUSED, long argl H3_UNUSED, void* argp H3_UNUSED)
{
    BIO_ADDR_free(ptr);
}

int h3q_new_pending_conn_cb(SSL_CTX* ctx H3_UNUSED, SSL* conn, void* arg)
{
    h3q_engine* engine = arg;
    if (!engine || engine->peer_addr_ex_index < 0 || BIO_ADDR_family(engine->current_peer_addr) == AF_UNSPEC)
    {
        return 1;
    }

    BIO_ADDR* peer = BIO_ADDR_dup(engine->current_peer_addr);
    if (!peer || !SSL_set_ex_data(conn, engine->peer_addr_ex_index, peer))
    {
        BIO_ADDR_free(peer);
        return 0;
    }
    return 1;
}
