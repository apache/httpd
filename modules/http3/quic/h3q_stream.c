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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "quic/detail/h3q_impl.h"
#include "quic/h3q_stream.h"

static_assert(sizeof(h3q_vec) == sizeof(ngtcp2_vec) && offsetof(h3q_vec, len) == offsetof(ngtcp2_vec, len), "h3q_vec must match ngtcp2_vec");

h3q_stream* h3q_stream_get(h3q_conn* conn, int64_t id)
{
    h3q_stream* st = ngtcp2_conn_get_stream_user_data(conn->qconn, id);
    if (st)
    {
        return st;
    }
    st = calloc(1, sizeof(*st));
    if (!st)
    {
        return NULL;
    }
    st->conn = conn;
    st->id = id;
    st->next = conn->streams_head;
    conn->streams_head = st;
    ngtcp2_conn_set_stream_user_data(conn->qconn, id, st);
    return st;
}

int64_t h3q_stream_id(h3q_stream* st)
{
    return st ? st->id : -1;
}

h3q_write_result h3q_stream_write(h3q_stream* st, const h3q_vec* vec, size_t nvec, int fin)
{
    h3q_write_result res = {0};
    if (!st || st->write_closed || st->conn->closed)
    {
        res.broken = 1;
        return res;
    }
    h3q_conn* conn = st->conn;
    const ngtcp2_vec* datav = (const ngtcp2_vec*)vec;
    size_t vi = 0;
    size_t voff = 0;
    uint8_t buf[H3Q_PKT_BUF];
    for (;;)
    {
        ngtcp2_vec head = {0};
        size_t cnt = 0;
        if (vi < nvec)
        {
            head.base = datav[vi].base + voff;
            head.len = datav[vi].len - voff;
            cnt = 1;
        }
        int last = vi + 1 >= nvec;
        uint32_t flags = (fin && last) ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
        ngtcp2_ssize ndatalen = 0;
        ngtcp2_pkt_info pi;
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(conn->qconn, &ps.path, &pi, buf, sizeof(buf), &ndatalen, flags, st->id, cnt ? &head : NULL, cnt, h3q_now());
        if (n < 0)
        {
            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED)
            {
                res.blocked = 1;
            }
            else
            {
                st->write_closed = 1;
                res.broken = 1;
                if (ngtcp2_err_is_fatal((int)n))
                {
                    h3q_conn_fail(conn, (int)n);
                }
            }
            break;
        }
        if (n > 0)
        {
            h3q_send(conn->engine, &ps.path, buf, (size_t)n);
        }
        if (ndatalen > 0)
        {
            res.accepted += (size_t)ndatalen;
            for (size_t left = (size_t)ndatalen; left > 0 && vi < nvec;)
            {
                size_t chunk = datav[vi].len - voff;
                if (chunk > left)
                {
                    voff += left;
                    left = 0;
                }
                else
                {
                    left -= chunk;
                    vi++;
                    voff = 0;
                }
            }
        }
        if (n == 0)
        {
            /* Congestion limited. An owed FIN counts as blocked, or the stream never ends. */
            if (vi < nvec || fin)
            {
                res.blocked = 1;
                st->fin_pending = vi >= nvec && fin;
            }
            break;
        }
        if (vi >= nvec)
        {
            if (flags & NGTCP2_WRITE_STREAM_FLAG_FIN)
            {
                /* ndatalen stays -1 when other frames crowded the STREAM frame out. */
                st->fin_pending = ndatalen < 0;
                st->write_closed = ndatalen >= 0;
                res.blocked |= ndatalen < 0;
            }
            break;
        }
    }
    h3q_conn_flush(conn);
    return res;
}

int h3q_stream_is_write_blocked(h3q_stream* st)
{
    if (!st || st->write_closed || st->conn->closed)
    {
        return 1;
    }
    return ngtcp2_conn_get_max_data_left(st->conn->qconn) == 0 || ngtcp2_conn_get_max_stream_data_left(st->conn->qconn, st->id) == 0;
}

int h3q_stream_read(h3q_stream* st, unsigned char* buf, size_t read_size, size_t* nread, int* fin)
{
    *nread = 0;
    *fin = 0;
    if (!st)
    {
        return 0;
    }
    size_t avail = st->rx_len - st->rx_off;
    if (avail == 0)
    {
        *fin = st->fin;
        return 0;
    }
    size_t n = read_size < avail ? read_size : avail;
    memcpy(buf, st->rx + st->rx_off, n);
    st->rx_off += n;
    *nread = n;
    if (st->rx_off == st->rx_len)
    {
        st->rx_off = 0;
        st->rx_len = 0;
        *fin = st->fin;
    }
    /* Consumed bytes give the peer window back. */
    ngtcp2_conn_extend_max_stream_offset(st->conn->qconn, st->id, n);
    ngtcp2_conn_extend_max_offset(st->conn->qconn, n);
    if (st->rx_len == 0)
    {
        h3q_conn_flush(st->conn); /* Send the window now. A blocked peer sends nothing that causes a flush. */
    }
    return 1;
}

void h3q_stream_is_read_finished(h3q_stream* st, int* read_finished, int* write_finished)
{
    if (!st)
    {
        *read_finished = 1;
        *write_finished = 1;
        return;
    }
    *read_finished = st->read_reset || (st->fin && st->rx_off >= st->rx_len);
    /* Not write_closed: ngtcp2 resends from our buffers until it closes the stream. */
    *write_finished = st->engine_closed || st->conn->closed;
}

int h3q_stream_is_early(h3q_stream* st)
{
    return st ? (int)st->early : 0;
}

void h3q_stream_reset(h3q_stream* st, uint64_t err)
{
    if (st && !st->conn->closed)
    {
        ngtcp2_conn_shutdown_stream_write(st->conn->qconn, 0, st->id, err);
        st->write_closed = 1;
    }
}

void h3q_stream_free(h3q_stream* st)
{
    if (!st)
    {
        return;
    }
    h3q_conn* conn = st->conn;
    if (!st->engine_closed && !conn->closed)
    {
        /* Drop unsent data now: its owner frees it after this call. */
        ngtcp2_conn_shutdown_stream_write(conn->qconn, 0, st->id, 0);
    }
    ngtcp2_conn_set_stream_user_data(conn->qconn, st->id, NULL);
    for (h3q_stream** slot = &conn->streams_head; *slot; slot = &(*slot)->next)
    {
        if (*slot == st)
        {
            *slot = st->next;
            break;
        }
    }
    for (h3q_stream** slot = &conn->accept_head; *slot; slot = &(*slot)->next_accept)
    {
        if (*slot == st)
        {
            *slot = st->next_accept;
            if (!*slot)
            {
                conn->accept_tail = NULL;
            }
            break;
        }
    }
    free(st->rx);
    free(st);
}
