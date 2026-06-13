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

#include <httpd.h>

#include <http_log.h>

#include <openssl/ssl.h>

#include "h3_quic_io.h"
#include "h3_request.h"
#include "h3_ssl.h"
#include "h3_stream_ids.h"
#include "h3_util.h"

int quic_server_read(nghttp3_conn* h3conn, SSL* stream, uint64_t id, struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
{
    int ret;
    nghttp3_ssize r;
    uint8_t msg2[16000];
    size_t l = sizeof(msg2);

    if (!SSL_has_pending(stream))
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "SSL_read on %" PRIu64 " !SSL_has_pending!", id);
        if (get_id_status(id, ssl_ids) & CLIENTCLOSED)
        {
            set_id_status(id, TOBEREMOVED, ssl_ids);
            return 0; // H3 already knows the client is closed.
        }
        if (get_id_status(id, ssl_ids) & RETRYWRITE)
        {
            /* We have a READ event but nothing pending, guessing we are closed/reseted */
            r = nghttp3_conn_read_stream(h3conn, (int64_t)id, msg2, 0, 1);
            if (r != 0)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read on %" PRIu64 " !SSL_has_pending! %ld %d %d", id, (long)r, get_id_status(id, ssl_ids), NGHTTP3_ERR_INVALID_STATE);
                if (r == -107 && (get_id_status(id, ssl_ids) & CLIENTCLOSED))
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read on %" PRIu64 " !SSL_has_pending! %ld", id, (long)r);
                    return 0;
                }
                abort();
            }
            set_id_status(id, CLIENTCLOSED, ssl_ids);
        }
        return 0; /* Nothing to read */
    }

    ret = SSL_read(stream, msg2, (int)l);
    if (ret <= 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read %d on %" PRIu64 " failed", SSL_get_error(stream, ret), id);
        switch (SSL_get_error(stream, ret))
        {
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_WANT_WRITE:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read %d on %" PRIu64 " failed SSL_ERROR_WANT_WRITE", SSL_get_error(stream, ret), id);
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read %d on %" PRIu64 " failed SSL_ERROR_ZERO_RETURN/FIN", SSL_get_error(stream, ret), id);
            return 1;
        case SSL_ERROR_SSL:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read %d on %" PRIu64 " failed SSL_ERROR_SSL/RESET", SSL_get_error(stream, ret), id);
            return 1;
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "SSL_read %d on %" PRIu64 " failed OTHER", SSL_get_error(stream, ret), id);
            ERR_print_errors_log(h3ssl);
            return -1;
        }
        return -1;
    }

    /* XXX: work around nghttp3_conn_read_stream returning  -607 on stream 2 */
    if (!ssl_ids_get607(ssl_ids, id, h3ssl))
    {
        uint32_t flags = NGHTTP3_DATA_FLAG_NONE;
        if (SSL_get_stream_read_state(stream) == SSL_STREAM_STATE_FINISHED)
        {
            flags |= NGHTTP3_DATA_FLAG_EOF;
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "nghttp3_conn_read_stream total %ld of %d on %" PRIu64, (long)r, ret, id);
        r = nghttp3_conn_read_stream(h3conn, (int64_t)id, msg2, (size_t)ret, (int)flags);
    }
    else
    {
        r = ret; /* ignore it for the moment ... */
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "nghttp3_conn_read_stream used %ld of %d on %" PRIu64, (long)r, ret, id);
    if (r != ret)
    {
        /* FIXED???? Remove??? chrome returns -607 on stream 2 */
        if (!nghttp3_err_is_fatal((int)r))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "nghttp3_conn_read_stream used %ld of %d (not fatal) on %" PRIu64, (long)r, ret, id);
            ssl_ids_store607(ssl_ids, id, h3ssl); /* store the -607 in the ssl_ids */
            return 1;
        }
        return -1;
    }
    return 1;
}

int quic_server_h3streams(nghttp3_conn* h3conn, struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
{
    SSL* rstream = NULL;
    SSL* pstream = NULL;
    SSL* cstream = NULL;
    SSL* conn;
    uint64_t r_streamid, p_streamid, c_streamid;

    conn = get_ids_connection(ssl_ids, h3ssl);
    if (conn == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "quic_server_h3streams no connection");
        return -1;
    }
    rstream = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
    if (rstream != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "=> Opened on %" PRIu64, SSL_get_stream_id(rstream));
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "=> Stream == NULL!");
        goto err;
    }
    pstream = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
    if (pstream != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "=> Opened on %" PRIu64, SSL_get_stream_id(pstream));
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "=> Stream == NULL!");
        goto err;
    }
    cstream = SSL_new_stream(conn, SSL_STREAM_FLAG_UNI);
    if (cstream != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "=> Opened on %" PRIu64, SSL_get_stream_id(cstream));
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "=> Stream == NULL!");
        goto err;
    }
    r_streamid = SSL_get_stream_id(rstream);
    p_streamid = SSL_get_stream_id(pstream);
    c_streamid = SSL_get_stream_id(cstream);
    if (nghttp3_conn_bind_qpack_streams(h3conn, (int64_t)p_streamid, (int64_t)r_streamid))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "nghttp3_conn_bind_qpack_streams failed!");
        goto err;
    }
    if (nghttp3_conn_bind_control_stream(h3conn, (int64_t)c_streamid))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "nghttp3_conn_bind_qpack_streams failed!");
        goto err;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "control: %" PRIu64 " enc %" PRIu64 " dec %" PRIu64, c_streamid, p_streamid, r_streamid);
    if (add_id(SSL_get_stream_id(rstream), rstream, ssl_ids, h3ssl) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Failed to add rstream");
        SSL_free(pstream);
        SSL_free(cstream);
        return -1;
    }
    if (add_id(SSL_get_stream_id(pstream), pstream, ssl_ids, h3ssl) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Failed to add pstream");
        SSL_free(cstream);
        return -1;
    }
    if (add_id(SSL_get_stream_id(cstream), cstream, ssl_ids, h3ssl) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Failed to add cstream");
        return -1;
    }

    return 0;
err:
    SSL_free(rstream);
    SSL_free(pstream);
    SSL_free(cstream);
    return -1;
}

nghttp3_ssize step_read_data(nghttp3_conn* /*conn*/, int64_t stream_id, nghttp3_vec* vec, size_t /*veccnt*/, uint32_t* pflags, void* user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    if (h3req->datadone)
    {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    /* send the data */
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "step_read_data for %" APR_SIZE_T_FMT " on %" PRIu64, h3req->ldata, stream_id);
    if (h3req->ldata == 0)
    {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        h3req->datadone++;
        return 0;
    }
    if (h3req->ldata <= 4096)
    {
        vec[0].base = &(h3req->ptr_data[h3req->offset_data]);
        vec[0].len = h3req->ldata;
        h3req->datadone++;
        *pflags = NGHTTP3_DATA_FLAG_EOF;
    }
    else
    {
        vec[0].base = &(h3req->ptr_data[h3req->offset_data]);
        vec[0].len = 4096;
        if (h3req->ldata == INT_MAX)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "big = endless!");
        }
        else
        {
            h3req->offset_data = h3req->offset_data + 4096;
            h3req->ldata = h3req->ldata - 4096;
        }
    }

    return 1;
}

int quic_server_write(struct ssl_id* ssl_ids, uint64_t streamid, uint8_t* buff, size_t len, uint64_t flags, size_t* written)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == streamid)
        {
            int ret = SSL_write_ex2(ssl_ids[i].s, buff, len, flags, written);
            if (!ret || *written != len)
            {
                SSL_CONN_CLOSE_INFO info = {0};
                int err = SSL_get_error(ssl_ids[i].s, ret);

                ap_log_error(APLOG_MARK, APLOG_ERR, 0, ssl_ids[i].h3ssl->s, "quic_server_write: couldn't write on %" PRIu64 " connection %d %d %zu %zu", streamid, ret, err, len, *written);
                if (SSL_get_conn_close_info(ssl_ids[i].s, &info, sizeof(info)))
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ssl_ids[i].h3ssl->s, "quic_server_write QUIC Error Code: %" PRIu64, info.error_code);
                    if (info.reason)
                    {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ssl_ids[i].h3ssl->s, "quic_server_write Reason: %s", info.reason);
                    }
                    if (info.error_code == 0 && *written != len)
                    {
                        int status = get_id_status(streamid, ssl_ids);
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ssl_ids[i].h3ssl->s, "quic_server_write: we need to retry %d", status);
                        set_id_status(streamid, RETRYWRITE, ssl_ids);
                        return 1; /* Assume it is OK and call SSL_handle_events */
                    }
                }
                ERR_print_errors_log(ssl_ids[i].h3ssl);
                return 0;
            }
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ssl_ids[i].h3ssl->s, "quic_server_write: written %" PRIu64 " on %" PRIu64 " flags %" PRIu64, (uint64_t)len, streamid, flags);
            return 1;
        }
    }
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "quic_server_write %" PRIu64 " on %" PRIu64 " (NOT FOUND!)", (uint64_t)len, streamid);
    abort(); // JFC something wrong in the logic...
    return 0;
}
