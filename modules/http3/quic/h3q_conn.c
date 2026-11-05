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
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "h3_check.h"
#include "quic/detail/h3q_impl.h"
#include "quic/h3q_conn.h"

/* The map key points into a slot of the connection, so a slot stays until its key leaves the map.
 * A CID that another connection has stays with it: a client must not take over a connection with its DCID. */
static int cid_add(h3q_conn* conn, const ngtcp2_cid* cid)
{
    if (apr_hash_get(conn->engine->conns, cid->data, (apr_ssize_t)cid->datalen))
    {
        return 1;
    }
    for (int i = 0; i < H3Q_CID_SLOTS; i++)
    {
        if (!conn->cids[i].datalen)
        {
            conn->cids[i] = *cid;
            apr_hash_set(conn->engine->conns, conn->cids[i].data, (apr_ssize_t)cid->datalen, conn);
            return 1;
        }
    }
    return 0;
}

static void cid_remove(h3q_conn* conn, ngtcp2_cid* slot)
{
    if (apr_hash_get(conn->engine->conns, slot->data, (apr_ssize_t)slot->datalen) == conn)
    {
        apr_hash_set(conn->engine->conns, slot->data, (apr_ssize_t)slot->datalen, NULL);
    }
    slot->datalen = 0;
}

static h3q_stream* stream_lookup(h3q_conn* conn, int64_t id)
{
    return ngtcp2_conn_get_stream_user_data(conn->qconn, id);
}

static int cb_handshake_completed(ngtcp2_conn* qconn, void* user_data)
{
    (void)qconn;
    ((h3q_conn*)user_data)->handshake_done = 1;
    return 0;
}

static int cb_recv_stream_data(ngtcp2_conn* qconn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t* data, size_t datalen, void* user_data, void* stream_user_data)
{
    (void)qconn;
    (void)offset;
    (void)stream_user_data;
    h3q_conn* conn = user_data;
    h3q_stream* st = h3q_stream_get(conn, stream_id);
    if (!st)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (datalen > 0)
    {
        size_t need = st->rx_len + datalen;
        if (need > st->rx_cap)
        {
            size_t cap = st->rx_cap ? st->rx_cap : 4096;
            while (cap < need)
            {
                cap *= 2;
            }
            unsigned char* grown = realloc(st->rx, cap);
            if (!grown)
            {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            st->rx = grown;
            st->rx_cap = cap;
        }
        memcpy(st->rx + st->rx_len, data, datalen);
        st->rx_len += datalen;
    }
    st->fin |= (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    st->early |= (flags & NGTCP2_STREAM_DATA_FLAG_0RTT) != 0;
    if (!st->queued_accept)
    {
        st->queued_accept = 1;
        if (conn->accept_tail)
        {
            conn->accept_tail->next_accept = st;
        }
        else
        {
            conn->accept_head = st;
        }
        conn->accept_tail = st;
    }
    return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn* qconn, int64_t stream_id, uint64_t offset, uint64_t datalen, void* user_data, void* stream_user_data)
{
    (void)qconn;
    (void)offset;
    (void)stream_user_data;
    h3q_conn* conn = user_data;
    if (conn->user && conn->engine->stream_acked)
    {
        conn->engine->stream_acked(conn->user, stream_id, (size_t)datalen);
    }
    return 0;
}

static int cb_stream_close(ngtcp2_conn* qconn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void* user_data, void* stream_user_data)
{
    (void)flags;
    (void)app_error_code;
    (void)stream_user_data;
    h3q_stream* st = stream_lookup(user_data, stream_id);
    if (st)
    {
        st->fin = 1;
        st->write_closed = 1;
        st->engine_closed = 1;
    }
    /* ngtcp2 leaves stream credit to the application: give the peer one stream back, or it stops after its initial MAX_STREAMS. */
    if (!ngtcp2_conn_is_local_stream(qconn, stream_id))
    {
        if (ngtcp2_is_bidi_stream(stream_id))
        {
            ngtcp2_conn_extend_max_streams_bidi(qconn, 1);
        }
        else
        {
            ngtcp2_conn_extend_max_streams_uni(qconn, 1);
        }
    }
    return 0;
}

static int cb_stream_reset(ngtcp2_conn* qconn, int64_t stream_id, uint64_t final_size, uint64_t app_error_code, void* user_data, void* stream_user_data)
{
    (void)qconn;
    (void)final_size;
    (void)app_error_code;
    (void)stream_user_data;
    h3q_stream* st = stream_lookup(user_data, stream_id);
    if (st)
    {
        st->read_reset = 1;
        st->fin = 1;
    }
    return 0;
}

static void cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx)
{
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn* qconn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data)
{
    (void)qconn;
    h3q_conn* conn = user_data;
    if (RAND_bytes(cid->data, (int)cidlen) != 1)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    if (ngtcp2_crypto_generate_stateless_reset_token(token, conn->engine->secret, sizeof(conn->engine->secret), cid) != 0)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return cid_add(conn, cid) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int cb_remove_connection_id(ngtcp2_conn* qconn, const ngtcp2_cid* cid, void* user_data)
{
    (void)qconn;
    h3q_conn* conn = user_data;
    for (int i = 0; i < H3Q_CID_SLOTS; i++)
    {
        if (ngtcp2_cid_eq(&conn->cids[i], cid))
        {
            cid_remove(conn, &conn->cids[i]);
        }
    }
    return 0;
}

static ngtcp2_conn* conn_ref_get_conn(ngtcp2_crypto_conn_ref* conn_ref)
{
    return ((h3q_conn*)conn_ref->user_data)->qconn;
}

static int tls_init(h3q_conn* conn)
{
    if (ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, NULL) != 0 || !(conn->ssl = SSL_new(conn->engine->ssl_ctx)))
    {
        return 0;
    }
    ngtcp2_crypto_ossl_ctx_set_ssl(conn->ossl_ctx, conn->ssl);
    if (ngtcp2_crypto_ossl_configure_server_session(conn->ssl) != 0)
    {
        return 0;
    }
    conn->conn_ref.get_conn = conn_ref_get_conn;
    conn->conn_ref.user_data = conn;
    SSL_set_app_data(conn->ssl, &conn->conn_ref);
    SSL_set_accept_state(conn->ssl);
    if (conn->engine->early_data)
    {
        SSL_set_quic_tls_early_data_enabled(conn->ssl, 1);
    }
    ngtcp2_conn_set_tls_native_handle(conn->qconn, conn->ossl_ctx);
    return 1;
}

h3q_conn* h3q_conn_new(h3q_engine* engine, const ngtcp2_pkt_hd* hd, const ngtcp2_cid* odcid, const ngtcp2_cid* retry_scid, const ngtcp2_path* path)
{
    h3q_conn* conn = calloc(1, sizeof(*conn));
    if (!conn)
    {
        return NULL;
    }
    conn->engine = engine;
    conn->next = engine->conns_head;
    engine->conns_head = conn;
    ngtcp2_cid scid = {.datalen = H3Q_SCIDLEN};
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1)
    {
        h3q_conn_free(conn);
        return NULL;
    }
    ngtcp2_path_storage_init(&conn->path, path->local.addr, path->local.addrlen, path->remote.addr, path->remote.addrlen, NULL);

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3q_now();
    /* Autotuning: ngtcp2 doubles a window that the peer fills within a few RTTs. */
    settings.max_window = engine->max_window;
    settings.max_stream_window = engine->max_window;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    /* 2s past H3IdleTimeout: the module's clean close (checked each second) must come first. */
    params.max_idle_timeout = ((ngtcp2_duration)engine->idle_timeout_secs + 2) * NGTCP2_SECONDS;
    params.initial_max_data = 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_streams_bidi = engine->max_streams_bidi;
    params.initial_max_streams_uni = 100;
    params.original_dcid = odcid ? *odcid : hd->dcid;
    params.original_dcid_present = 1;
    if (retry_scid)
    {
        params.retry_scid = *retry_scid;
        params.retry_scid_present = 1;
    }
    params.disable_active_migration = engine->disable_migration;
    params.stateless_reset_token_present = ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token, engine->secret, sizeof(engine->secret), &scid) == 0;

    ngtcp2_callbacks cb = {
        .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .handshake_completed = cb_handshake_completed,
        .recv_stream_data = cb_recv_stream_data,
        .acked_stream_data_offset = cb_acked_stream_data_offset,
        .stream_close = cb_stream_close,
        .stream_reset = cb_stream_reset,
        .rand = cb_rand,
        .get_new_connection_id = cb_get_new_connection_id,
        .remove_connection_id = cb_remove_connection_id,
    };
    if (ngtcp2_conn_server_new(&conn->qconn, &hd->scid, &scid, &conn->path.path, hd->version, &cb, &settings, &params, NULL, conn) != 0 || !tls_init(conn))
    {
        h3q_conn_free(conn);
        return NULL;
    }
    cid_add(conn, &scid);
    /* A retransmitted Initial still carries the original DCID. */
    cid_add(conn, &hd->dcid);
    conn->queued_accept = 1;
    if (engine->accept_tail)
    {
        engine->accept_tail->next_accept = conn;
    }
    else
    {
        engine->accept_head = conn;
    }
    engine->accept_tail = conn;
    return conn;
}

/* nghttp3 offers a FIN once; one ngtcp2 refused is retried here. */
static void retry_pending_fins(h3q_conn* conn)
{
    uint8_t buf[H3Q_PKT_BUF];
    for (h3q_stream* st = conn->streams_head; st; st = st->next)
    {
        if (!st->fin_pending || st->write_closed)
        {
            continue;
        }
        ngtcp2_ssize ndatalen = 0;
        ngtcp2_pkt_info pi;
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(conn->qconn, &ps.path, &pi, buf, sizeof(buf), &ndatalen, NGTCP2_WRITE_STREAM_FLAG_FIN, st->id, NULL, 0, h3q_now());
        if (n < 0)
        {
            if (n != NGTCP2_ERR_STREAM_DATA_BLOCKED)
            {
                st->fin_pending = 0;
                st->write_closed = 1;
            }
            continue;
        }
        if (n == 0)
        {
            continue; /* congestion limited; the next expiry retries */
        }
        h3q_send(conn->engine, &ps.path, pi.ecn, buf, (size_t)n);
        if (ndatalen >= 0)
        {
            st->fin_pending = 0;
            st->write_closed = 1;
        }
    }
}

void h3q_conn_flush(h3q_conn* conn)
{
    if (!conn || conn->closed)
    {
        return;
    }
    retry_pending_fins(conn);
    uint8_t buf[H3Q_PKT_BUF];
    for (;;)
    {
        ngtcp2_path_storage ps;
        ngtcp2_pkt_info pi;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize n = ngtcp2_conn_write_pkt(conn->qconn, &ps.path, &pi, buf, sizeof(buf), h3q_now());
        if (n < 0)
        {
            h3q_conn_fail(conn, (int)n);
            return;
        }
        if (n == 0)
        {
            break;
        }
        h3q_send(conn->engine, &ps.path, pi.ecn, buf, (size_t)n);
    }
    h3q_tx_flush(conn->engine);
    /* Without this ngtcp2 never paces and bursts the whole window. */
    ngtcp2_conn_update_pkt_tx_time(conn->qconn, h3q_now());
}

void h3q_conn_set_user(h3q_conn* conn, void* user)
{
    if (conn)
    {
        conn->user = user;
    }
}

h3q_stream* h3q_conn_open_uni_stream(h3q_conn* conn, int64_t* out_id)
{
    CHECK(conn);
    CHECK(out_id);
    if (ngtcp2_conn_open_uni_stream(conn->qconn, out_id, NULL) != 0)
    {
        return NULL;
    }
    return h3q_stream_get(conn, *out_id);
}

h3q_stream* h3q_conn_accept_stream(h3q_conn* conn)
{
    if (!conn || !conn->accept_head)
    {
        return NULL;
    }
    h3q_stream* st = conn->accept_head;
    conn->accept_head = st->next_accept;
    if (!conn->accept_head)
    {
        conn->accept_tail = NULL;
    }
    st->next_accept = NULL;
    st->queued_accept = 0;
    return st;
}

int h3q_conn_is_handshake_done(h3q_conn* conn)
{
    return conn ? (int)conn->handshake_done : 0;
}

int h3q_conn_has_early_data(h3q_conn* conn)
{
    return conn && !conn->handshake_done && conn->accept_head != NULL;
}

int h3q_conn_tls_info(h3q_conn* conn, h3q_tls_info* out)
{
    if (!conn || !out)
    {
        return 0;
    }
    const SSL_CIPHER* cipher = SSL_get_current_cipher(conn->ssl);
    if (!cipher)
    {
        return 0;
    }
    int alg_bits = 0;
    out->cipher_bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
    out->cipher_alg_bits = alg_bits;
    out->cipher = SSL_CIPHER_get_name(cipher);
    out->protocol = SSL_get_version(conn->ssl);
    out->resumed = SSL_session_reused(conn->ssl) ? 1u : 0u;
    return 1;
}

int h3q_conn_is_closed(h3q_conn* conn)
{
    return !conn || conn->closed || ngtcp2_conn_in_closing_period(conn->qconn) || ngtcp2_conn_in_draining_period(conn->qconn);
}

/* Send CONNECTION_CLOSE once and keep it, so the closing period can resend it. */
void h3q_conn_close(h3q_conn* conn, const ngtcp2_ccerr* ccerr)
{
    if (conn->closed)
    {
        return;
    }
    conn->closed = 1;
    if (ngtcp2_conn_in_closing_period(conn->qconn) || ngtcp2_conn_in_draining_period(conn->qconn))
    {
        return;
    }
    if (!(conn->close_pkt = malloc(H3Q_PKT_BUF)))
    {
        return;
    }
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_ssize n = ngtcp2_conn_write_connection_close(conn->qconn, &ps.path, &pi, conn->close_pkt, H3Q_PKT_BUF, ccerr, h3q_now());
    if (n > 0)
    {
        ngtcp2_duration pto = ngtcp2_conn_get_pto(conn->qconn);
        conn->close_len = (size_t)n;
        conn->close_until = h3q_now() + 3 * pto;
        conn->close_next = h3q_now() + pto;
        h3q_send(conn->engine, &ps.path, pi.ecn, conn->close_pkt, conn->close_len);
        h3q_tx_flush(conn->engine);
    }
}

/* Close on a local ngtcp2 error and keep the error for the log. */
void h3q_conn_fail(h3q_conn* conn, int liberr)
{
    if (!conn->liberr)
    {
        conn->liberr = liberr;
    }
    /* Idle timeout and drop: close silently, never send CONNECTION_CLOSE (RFC 9000 10.1). */
    if (liberr == NGTCP2_ERR_IDLE_CLOSE || liberr == NGTCP2_ERR_DROP_CONN)
    {
        conn->closed = 1;
        return;
    }
    ngtcp2_ccerr ccerr;
    if (liberr == NGTCP2_ERR_CRYPTO)
    {
        ngtcp2_ccerr_set_tls_alert(&ccerr, ngtcp2_conn_get_tls_alert(conn->qconn), NULL, 0);
    }
    else
    {
        ngtcp2_ccerr_set_liberr(&ccerr, liberr, NULL, 0);
    }
    h3q_conn_close(conn, &ccerr);
}

/* Closing period: answer the peer with the stored close, at most once per PTO. */
void h3q_conn_resend_close(h3q_conn* conn, const ngtcp2_path* path)
{
    ngtcp2_tstamp now = h3q_now();
    if (now < conn->close_next)
    {
        return;
    }
    conn->close_next = now + ngtcp2_conn_get_pto(conn->qconn);
    h3q_send(conn->engine, path, NGTCP2_ECN_NOT_ECT, conn->close_pkt, conn->close_len);
    h3q_tx_flush(conn->engine);
}

int h3q_conn_shutdown(h3q_conn* conn, int is_rapid, uint64_t app_error, const char* reason)
{
    if (!conn)
    {
        return 1;
    }
    ngtcp2_ccerr ccerr;
    ngtcp2_ccerr_default(&ccerr);
    if (reason)
    {
        ngtcp2_ccerr_set_application_error(&ccerr, app_error, (const uint8_t*)reason, strlen(reason));
    }
    h3q_conn_close(conn, &ccerr);
    return is_rapid || conn->close_len == 0 || h3q_now() >= conn->close_until;
}

void h3q_conn_free(h3q_conn* conn)
{
    if (!conn)
    {
        return;
    }
    h3q_engine* engine = conn->engine;
    for (h3q_conn** slot = &engine->conns_head; *slot; slot = &(*slot)->next)
    {
        if (*slot == conn)
        {
            *slot = conn->next;
            break;
        }
    }
    for (h3q_conn** slot = &engine->accept_head; *slot; slot = &(*slot)->next_accept)
    {
        if (*slot == conn)
        {
            *slot = conn->next_accept;
            if (!*slot)
            {
                engine->accept_tail = NULL;
            }
            break;
        }
    }
    for (int i = 0; i < H3Q_CID_SLOTS; i++)
    {
        if (conn->cids[i].datalen)
        {
            cid_remove(conn, &conn->cids[i]);
        }
    }
    if (conn->qconn)
    {
        ngtcp2_conn_del(conn->qconn);
    }
    if (conn->ssl)
    {
        SSL_set_app_data(conn->ssl, NULL);
        SSL_free(conn->ssl);
    }
    if (conn->ossl_ctx)
    {
        ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);
    }
    while (conn->streams_head)
    {
        h3q_stream* next = conn->streams_head->next;
        free(conn->streams_head->rx);
        free(conn->streams_head);
        conn->streams_head = next;
    }
    free(conn->close_pkt);
    free(conn);
}

void h3q_conn_close_reason(h3q_conn* conn, char* buf, size_t buflen)
{
    if (!buf || buflen == 0)
    {
        return;
    }
    char errbuf[H3Q_ERRLEN] = {0};
    ERR_error_string_n(ERR_peek_last_error(), errbuf, sizeof(errbuf));
    if (conn && conn->liberr)
    {
        snprintf(buf, buflen, "local %s (%s)", ngtcp2_strerror(conn->liberr), errbuf);
        return;
    }
    const ngtcp2_ccerr* cc = conn && conn->qconn ? ngtcp2_conn_get_ccerr(conn->qconn) : NULL;
    if (cc)
    {
        snprintf(buf, buflen, "type=%d err=0x%llx frame=0x%llx reason=\"%.*s\" (%s)", (int)cc->type, (unsigned long long)cc->error_code, (unsigned long long)cc->frame_type, (int)cc->reasonlen, cc->reason ? (const char*)cc->reason : "", errbuf);
        return;
    }
    snprintf(buf, buflen, "%s", errbuf);
}
