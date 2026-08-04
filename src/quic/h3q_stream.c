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

#include <openssl/ssl.h>

#include "quic/h3q_stream.h"

h3q_write_result h3q_stream_write(h3q_stream* st, const h3q_vec* vec, size_t nvec, int fin)
{
    SSL* ssl = (SSL*)st;
    h3q_write_result res = {0};
    size_t expected = 0;
    for (size_t k = 0; k < nvec; k++)
    {
        expected += vec[k].len;
    }
    for (size_t k = 0; k < nvec; k++)
    {
        size_t w = 0;
        int wrv = SSL_write_ex(ssl, vec[k].base, vec[k].len, &w);
        if (wrv <= 0)
        {
            if (SSL_get_error(ssl, wrv) == SSL_ERROR_WANT_WRITE)
            {
                res.blocked = 1;
            }
            else
            {
                res.broken = 1;
            }
            break;
        }
        res.accepted += w;
        if (w < vec[k].len)
        {
            res.blocked = 1;
            break;
        }
    }
    if (fin && !res.blocked && !res.broken && res.accepted == expected)
    {
        SSL_stream_conclude(ssl, 0);
    }
    return res;
}

int h3q_stream_is_write_blocked(h3q_stream* st)
{
    SSL* ssl = (SSL*)st;
    uint64_t avail = 0;
    if (ssl && SSL_get_generic_value_uint(ssl, SSL_VALUE_STREAM_WRITE_BUF_AVAIL, &avail) == 1 && avail == 0)
    {
        return 1;
    }
    return 0;
}

int h3q_stream_read(h3q_stream* st, unsigned char* buf, size_t read_size, size_t* nread, int* fin)
{
    SSL* ssl = (SSL*)st;
    *fin = 0;
    int rv = SSL_read_ex(ssl, buf, read_size, nread);
    if (rv == 1 || SSL_get_error(ssl, rv) == SSL_ERROR_ZERO_RETURN)
    {
        *fin = 1;
    }
    return (rv == 1 && *nread > 0);
}

void h3q_stream_is_read_finished(h3q_stream* st, int* read_finished, int* write_finished)
{
    SSL* ssl = (SSL*)st;
    int rstate = SSL_get_stream_read_state(ssl);
    *read_finished = (rstate == SSL_STREAM_STATE_FINISHED || rstate == SSL_STREAM_STATE_RESET_REMOTE || rstate == SSL_STREAM_STATE_CONN_CLOSED);
    int wstate = SSL_STREAM_STATE_FINISHED;
    if (rstate != SSL_STREAM_STATE_CONN_CLOSED && rstate != SSL_STREAM_STATE_RESET_REMOTE)
    {
        wstate = SSL_get_stream_write_state(ssl);
    }
    *write_finished = (wstate == SSL_STREAM_STATE_FINISHED || wstate == SSL_STREAM_STATE_RESET_LOCAL);
}

void h3q_stream_reset(h3q_stream* st, uint64_t err)
{
    if (!st)
    {
        return;
    }
    SSL_STREAM_RESET_ARGS args = {err};
    SSL_stream_reset((SSL*)st, &args, sizeof(args));
}

void h3q_stream_free(h3q_stream* st)
{
    if (st)
    {
        SSL_free((SSL*)st);
    }
}

int64_t h3q_stream_id(h3q_stream* st)
{
    SSL* ssl = (SSL*)st;
    return ssl ? (int64_t)SSL_get_stream_id(ssl) : -1;
}
