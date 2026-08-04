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

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "h3_check.h"
#include "quic/h3q_conn.h"

int h3q_conn_prepare(h3q_conn* conn, uint32_t idle_timeout_secs)
{
    SSL* ssl_conn = (SSL*)conn;
    if (!ssl_conn || !SSL_set_blocking_mode(ssl_conn, 0))
    {
        return 0;
    }
    SSL_set_default_stream_mode(ssl_conn, SSL_DEFAULT_STREAM_MODE_NONE);
    SSL_set_incoming_stream_policy(ssl_conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
    SSL_set_generic_value_uint(ssl_conn, SSL_VALUE_QUIC_IDLE_TIMEOUT, (uint64_t)idle_timeout_secs * 1000);
    return 1;
}

h3q_stream* h3q_conn_open_uni_stream(h3q_conn* conn, int64_t* out_id)
{
    SSL* ssl_conn = (SSL*)conn;
    CHECK(ssl_conn);
    CHECK(out_id);
    SSL* stream = SSL_new_stream(ssl_conn, SSL_STREAM_FLAG_UNI);
    if (!stream)
    {
        return NULL;
    }
    *out_id = (int64_t)SSL_get_stream_id(stream);
    return (h3q_stream*)stream;
}

h3q_stream* h3q_conn_accept_stream(h3q_conn* conn)
{
    SSL* ssl_conn = (SSL*)conn;
    if (!ssl_conn)
    {
        return NULL;
    }
    return (h3q_stream*)SSL_accept_stream(ssl_conn, SSL_ACCEPT_STREAM_NO_BLOCK);
}

int h3q_conn_is_handshake_done(h3q_conn* conn)
{
    SSL* ssl_conn = (SSL*)conn;
    return ssl_conn ? SSL_is_init_finished(ssl_conn) : 0;
}

int h3q_conn_is_closed(h3q_conn* conn)
{
    SSL* ssl_conn = (SSL*)conn;
    return ssl_conn ? (SSL_get_shutdown(ssl_conn) != 0) : 1;
}

int h3q_conn_shutdown(h3q_conn* conn, int is_rapid, uint64_t app_error, const char* reason)
{
    SSL* ssl_conn = (SSL*)conn;
    if (!ssl_conn)
    {
        return 1;
    }
    uint64_t flags = is_rapid ? (uint64_t)SSL_SHUTDOWN_FLAG_RAPID : 0;
    int ret = 0;
    if (reason)
    {
        SSL_SHUTDOWN_EX_ARGS args = {.quic_error_code = app_error, .quic_reason = reason};
        ret = SSL_shutdown_ex(ssl_conn, flags, &args, sizeof(args));
    }
    else if (flags != 0)
    {
        SSL_SHUTDOWN_EX_ARGS args = {0};
        ret = SSL_shutdown_ex(ssl_conn, flags, &args, sizeof(args));
    }
    else
    {
        ret = SSL_shutdown(ssl_conn);
    }

    if (ret == 1)
    {
        return 1;
    }
    if (ret < 0)
    {
        int err = SSL_get_error(ssl_conn, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
            return 1;
        }
    }
    return 0;
}

void h3q_conn_free(h3q_conn* conn)
{
    if (conn)
    {
        SSL_free((SSL*)conn);
    }
}

void h3q_conn_close_reason(h3q_conn* conn, char* buf, size_t buflen)
{
    if (!buf || buflen == 0)
    {
        return;
    }
    buf[0] = '\0';

    char errbuf[H3Q_ERRLEN] = {0};
    ERR_error_string_n(ERR_peek_last_error(), errbuf, sizeof(errbuf));

    SSL_CONN_CLOSE_INFO cci = {0};
    if (conn && SSL_get_conn_close_info((SSL*)conn, &cci, sizeof(cci)))
    {
        const char* origin = (cci.flags & SSL_CONN_CLOSE_FLAG_LOCAL) ? "local" : "remote";
        const char* layer = (cci.flags & SSL_CONN_CLOSE_FLAG_TRANSPORT) ? "transport" : "app";
        const char* reason = cci.reason ? cci.reason : "";
        snprintf(buf, buflen, "%s %s err=0x%llx frame=0x%llx reason=\"%.*s\" (%s)", origin, layer, (unsigned long long)cci.error_code, (unsigned long long)cci.frame_type, (int)cci.reason_len, reason, errbuf);
        return;
    }
    snprintf(buf, buflen, "%s", errbuf);
}
