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

#include <http_config.h>
#include <http_log.h>

#include <openssl/quic.h>
#include <openssl/ssl.h>

#include <sys/socket.h>

#include "h3.h"
#include "h3_callbacks.h"
#include "h3_conn.h"
#include "h3_poll.h"
#include "h3_quic_io.h"
#include "h3_request.h"
#include "h3_ssl.h"
#include "h3_stream_ids.h"
#include "h3_util.h"

int read_from_ssl_ids(struct ssl_id* ssl_ids, struct activeh3ssl* activeh3ssl, apr_pool_t* p, server_rec* s)
{
    int hassomething = 0, i;
    SSL_POLL_ITEM items[MAXSSL_IDS] = {0}, *item = items;
    static const struct timeval nz_timeout = {0, 0};
    size_t result_count = SIZE_MAX;
    int ret;
    size_t numitem = 0;
    uint64_t processed_event = 0;
    int has_ids_to_remove = 0;

    /*
     * Process all the streams
     * the first one is the connection if we get something here is a new stream
     */
    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].s != NULL)
        {
            item->desc = SSL_as_poll_descriptor(ssl_ids[i].s);
            item->events = UINT64_MAX;  /* TODO adjust to the event we need process */
            item->revents = UINT64_MAX; /* TODO adjust to the event we need process */
            numitem++;
            item++;
        }
    }
    if (numitem == 0)
        abort();

    /*
     * SSL_POLL_FLAG_NO_HANDLE_EVENTS would require to use:
     * SSL_get_event_timeout on the connection stream
     * select/wait using the timeout value (which could be no wait time)
     * SSL_handle_events
     * SSL_poll
     * for the moment we let SSL_poll to performs ticking internally
     * on an automatic basis.
     */
    ret = SSL_poll(items, numitem, sizeof(SSL_POLL_ITEM), &nz_timeout, SSL_POLL_FLAG_NO_HANDLE_EVENTS, &result_count);
    if (!ret)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SSL_poll failed");
        abort();
        return -1; /* something is wrong */
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids %ld events", (unsigned long)result_count);
    if (result_count == 0)
    {
        /* Timeout may be something somewhere */
        return 0;
    }

    /* Process all the item we have polled */
    item = items;
    for (size_t j = 0; j < numitem; j++, item++)
    {

        if (item->revents == SSL_POLL_EVENT_NONE)
            continue;
        processed_event = 0;
        /* get the stream */

        /* New connection */
        if (item->revents & SSL_POLL_EVENT_IC)
        {
            SSL* conn = SSL_accept_connection(item->desc.value.ssl, 0);
            struct h3ssl* h3ssl;
            nghttp3_conn* curh3conn;
            nghttp3_settings settings = {0};
            const nghttp3_mem* h3mem = {0};
            nghttp3_callbacks callbacks = {0};

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "SSL_accept_connection");
            if (conn == NULL)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "error while accepting connection");
                ret = -1;
                goto err;
            }

            /* create the connection for httpd */
            h3_conn_rec_t* c3 = create_connection(p, s);

            /* create the new h3ssl using the connection pool */
            h3ssl = apr_pcalloc(c3->c->pool, sizeof(struct h3ssl));
            h3ssl->p = c3->c->pool;
            h3ssl->s = s;
            h3ssl->has_uni = 0;
            if (add_ids_connection(ssl_ids, conn, h3ssl) < 0)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Failed to add connection");
                SSL_free(conn);
                ret = -1;
                goto err;
            }

            h3ssl->c = c3->c;
            /* create the new h3conn */
            nghttp3_settings_default(&settings);
            /* Use nghttp3_mem_default for the moment */
            h3mem = nghttp3_mem_default();
            /* Setup callbacks. */
            callbacks.recv_header = on_recv_header;
            callbacks.end_headers = on_end_headers;
            callbacks.recv_data = on_recv_data;
            callbacks.end_stream = on_end_stream;
            callbacks.stream_close = on_stream_close;

            if (nghttp3_conn_server_new(&curh3conn, &callbacks, &settings, h3mem, h3ssl))
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "nghttp3_conn_client_new failed!");
                ret = -1;
                goto err;
            }
            h3ssl->h3conn = curh3conn;
            add_active_h3ssl(activeh3ssl, h3ssl);
            hassomething++;

            if (!SSL_set_incoming_stream_policy(conn, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0))
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "error while setting inccoming stream policy");
                ret = -1;
                goto err;
            }

            /* process the connection here */
            if (process_connection(p, s, h3ssl->c) != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "error in process_connection");
                ret = -1;
                goto err;
            }

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "SSL_accept_connection %p", (void*)h3ssl->c);
            processed_event = processed_event | SSL_POLL_EVENT_IC;
        }
        /* SSL_accept_stream if SSL_POLL_EVENT_ISB or SSL_POLL_EVENT_ISU */
        /* the h3ssl is coming from the connect that receives the new stream */
        if ((item->revents & SSL_POLL_EVENT_ISB) || (item->revents & SSL_POLL_EVENT_ISU))
        {
            size_t l = SSL_get_accept_stream_queue_len(item->desc.value.ssl);
            SSL* stream;
            struct h3ssl* h3ssl = get_h3ssl_ssl(ssl_ids, item->desc.value.ssl);

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "SSL_get_accept_stream_queue_len %zu", l);

            /* Accept all streams until SSL_accept_stream returns NULL */
            while ((stream = SSL_accept_stream(item->desc.value.ssl, 0)) != NULL)
            {
                uint64_t new_id;
                int r;

                new_id = SSL_get_stream_id(stream);
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "=> Received connection on %" PRIu64 " %d", new_id, SSL_get_stream_type(stream));
                if (add_id(new_id, stream, ssl_ids, h3ssl) < 0)
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Failed to add stream %" PRIu64, new_id);
                    ret = -1;
                    goto err;
                }

                if (SSL_get_stream_type(stream) == SSL_STREAM_TYPE_BIDI)
                {
                    /* bidi that is the id  where we have to send the response */
                    /* we have a new bidi so a new request/response processing starting */
                    create_h3_request(h3ssl, (int64_t)new_id);
                    set_id_status(new_id, CLIENTBIDIOPEN, ssl_ids);
                }
                else
                {
                    set_id_status(new_id, CLIENTUNIOPEN, ssl_ids);
                }

                r = quic_server_read(h3ssl->h3conn, stream, new_id, h3ssl, ssl_ids);
                if (r == -1)
                {
                    ret = -1;
                    goto err;
                }
                if (r == 1)
                {
                    hassomething++;
                }

                add_active_h3ssl(activeh3ssl, h3ssl);
            }

            if (item->revents & SSL_POLL_EVENT_ISB)
                processed_event = processed_event | SSL_POLL_EVENT_ISB;
            if (item->revents & SSL_POLL_EVENT_ISU)
                processed_event = processed_event | SSL_POLL_EVENT_ISU;
        }
        if (item->revents & SSL_POLL_EVENT_OSB)
        {
            /* Create new streams when allowed */
            /* at least one bidi */
            processed_event = processed_event | SSL_POLL_EVENT_OSB;
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Create bidi?");
        }
        if (item->revents & SSL_POLL_EVENT_OSU)
        {
            /* at least one uni */
            /* we have 4 streams from the client 2, 6 , 10 and 0 */
            /* need 3 streams to the client */
            struct h3ssl* h3ssl = get_h3ssl_ssl(ssl_ids, item->desc.value.ssl);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Create uni?");
            processed_event = processed_event | SSL_POLL_EVENT_OSU;
            if (!h3ssl->has_uni)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Create uni");
                ret = quic_server_h3streams(h3ssl->h3conn, h3ssl, ssl_ids);
                if (ret == -1)
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_h3streams failed!");
                    goto err;
                }
                h3ssl->has_uni = 1;
                hassomething++;
                add_active_h3ssl(activeh3ssl, h3ssl);
            }
        }
        if (item->revents & SSL_POLL_EVENT_EC)
        {
            /* the connection begins terminating */
            SSL_CONN_CLOSE_INFO info = {0};
            struct h3ssl* h3ssl = get_h3ssl_ssl(ssl_ids, item->desc.value.ssl);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Connection terminated EC");
            h3ssl->c_terminated |= TERM_EC;
            hassomething++;
            add_active_h3ssl(activeh3ssl, h3ssl);

            /* Trace the error code if any */
            if (SSL_get_conn_close_info(item->desc.value.ssl, &info, sizeof(info)))
            {
                if (info.error_code && info.error_code != (uint64_t)-1)
                {
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Connection terminated EC %" PRIu64 ": %s", info.error_code, info.reason);
                    h3ssl->c_terminated |= TERM_ERR;
                }
            }

            processed_event = processed_event | SSL_POLL_EVENT_EC;
        }
        if (item->revents & SSL_POLL_EVENT_ECD)
        {
            struct h3ssl* h3ssl = get_h3ssl_ssl(ssl_ids, item->desc.value.ssl);
            /* the connection is terminated */
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Connection terminated ECD");
            if (item->revents & SSL_POLL_EVENT_ER)
                h3ssl->c_terminated |= TERM_HLF;
            else
                h3ssl->c_terminated |= TERM_ECD;
            hassomething++;
            add_active_h3ssl(activeh3ssl, h3ssl);
            processed_event = processed_event | SSL_POLL_EVENT_ECD;
        }

        if (item->revents & SSL_POLL_EVENT_R)
        {
            /* try to read */
            uint64_t id = UINT64_MAX;
            int r;
            struct h3ssl* h3ssl = get_h3ssl_ssl(ssl_ids, item->desc.value.ssl);

            /* get the id, well the connection has no id... */
            id = SSL_get_stream_id(item->desc.value.ssl);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent READ on %" PRIu64, id);
            r = quic_server_read(h3ssl->h3conn, item->desc.value.ssl, id, h3ssl, ssl_ids);
            if (r == 0)
            {
                uint8_t msg[1];
                size_t l = sizeof(msg);

                /* check that the other side is closed */
                r = SSL_read(item->desc.value.ssl, msg, (int)l);
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "SSL_read tells %d", r);
                if (r > 0)
                {
                    ret = -1;
                    goto err;
                }
                r = SSL_get_error(item->desc.value.ssl, r);
                if (r != SSL_ERROR_ZERO_RETURN)
                {
                    ret = -1;
                    goto err;
                }
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent READ on %" PRIu64 " REMOVE??? %d", id, get_id_status(id, ssl_ids));
                if (get_id_status(id, ssl_ids) & TOBEREMOVED)
                {
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent READ on %" PRIu64 " OK TO REMOVE", id);
                    has_ids_to_remove++;
                }
                else if (get_id_status(id, ssl_ids) & RETRYWRITE)
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent READ on %" PRIu64 " NOT REMOVE", id);
                else
                {
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent READ on %" PRIu64 " REMOVING", id);
                    set_id_status(id, TOBEREMOVED, ssl_ids);
                    has_ids_to_remove++;
                }
                continue;
            }
            if (r == -1)
            {
                ret = -1;
                goto err;
            }
            int state = SSL_get_stream_write_state(item->desc.value.ssl);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent READ on %" PRIu64 " state: %d", id, state);

            hassomething++;
            add_active_h3ssl(activeh3ssl, h3ssl);
            processed_event = processed_event | SSL_POLL_EVENT_R;
        }
        if (item->revents & SSL_POLL_EVENT_ER)
        {
            /* mark it closed XXX: We should read */
            uint64_t id = UINT64_MAX;
            int status;

            id = SSL_get_stream_id(item->desc.value.ssl);
            status = get_id_status(id, ssl_ids);

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent exception READ on %" PRIu64, id);
            if (status & CLIENTUNIOPEN)
            {
                set_id_status(id, CLIENTCLOSED, ssl_ids);
                hassomething++;
            }
            processed_event = processed_event | SSL_POLL_EVENT_ER;
        }
        if (item->revents & SSL_POLL_EVENT_W)
        {
            /* check if we are waiting to write */
            uint64_t id = SSL_get_stream_id(item->desc.value.ssl);
            int status = get_id_status(id, ssl_ids);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent SSL_POLL_EVENT_W on %" PRIu64, id);
            if (status & RETRYWRITE)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "revent SSL_POLL_EVENT_W (RETRYWRITE) on %" PRIu64, id);
            }
            processed_event = processed_event | SSL_POLL_EVENT_W;
        }
        if (item->revents & SSL_POLL_EVENT_EW)
        {
            /* write part received a STOP_SENDING XXX: should we write */
            uint64_t id = UINT64_MAX;
            int status;

            id = SSL_get_stream_id(item->desc.value.ssl);
            status = get_id_status(id, ssl_ids);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "SSL_POLL_EVENT_EW on  %" PRIu64, id);

            if (status & SERVERCLOSED)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "both sides closed on  %" PRIu64, id);
                set_id_status(id, TOBEREMOVED, ssl_ids);
                has_ids_to_remove++;
                hassomething++;
            }
            processed_event = processed_event | SSL_POLL_EVENT_EW;
        }
        if (item->revents != processed_event)
        {
            /* Figure out ??? */
            uint64_t id = UINT64_MAX;

            id = SSL_get_stream_id(item->desc.value.ssl);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "revent %" PRIu64 " (%d) on %" PRIu64 " NOT PROCESSED!", item->revents, SSL_POLL_EVENT_W, id);
        }
    }
    ret = hassomething;
err:
    if (ret == -1)
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "read_from_ssl_ids FAILED!");
    if (has_ids_to_remove)
        remove_marked_ids(ssl_ids);
    return ret;
}

void handle_events_from_ids(struct ssl_id* ssl_ids, server_rec* s)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].s != NULL && (ssl_ids[i].status & ISCONNECTION || ssl_ids[i].status & ISLISTENER))
        {
            int ret = SSL_handle_events(ssl_ids[i].s);
            if (ret)
            {
                int err = SSL_get_error(ssl_ids[i].s, ret);
                if (err == 0)
                    continue; /* XXX we ignore it for the moment */
                else
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "handle_events_from_ids id: %" PRIu64 " %d (%d %d) FAILED!", ssl_ids[i].id, ssl_ids[i].status, ret, err);
            }
            if (ret)
            {
                if (ssl_ids[i].h3ssl != NULL)
                    ERR_print_errors_log(ssl_ids[i].h3ssl); /* XXX to arrange */
            }
        }
    }
}

int wait_for_activity(server_rec* s, SSL* ssl)
{
    int sock, isinfinite;
    fd_set read_fd, write_fd;
    struct timeval tv;
    struct timeval* tvp = NULL;

    /* Get hold of the underlying file descriptor for the socket */
    if ((sock = SSL_get_fd(ssl)) == -1)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Unable to get file descriptor");
        return -1;
    }

    /* Initialize the fd_set structure */
    FD_ZERO(&read_fd);
    FD_ZERO(&write_fd);

    /*
     * Determine if we would like to write to the socket, read from it, or both.
     */
    if (SSL_net_write_desired(ssl))
        FD_SET(sock, &write_fd);
    if (SSL_net_read_desired(ssl))
        FD_SET(sock, &read_fd);

    /* Add the socket file descriptor to the fd_set */
    FD_SET(sock, &read_fd);

    /*
     * Find out when OpenSSL would next like to be called, regardless of
     * whether the state of the underlying socket has changed or not.
     */
    if (SSL_get_event_timeout(ssl, &tv, &isinfinite) && !isinfinite)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "wait_for_activity using timeout %ld %ld", (long)tv.tv_sec, (long)tv.tv_usec);
        if (tv.tv_sec != 0 || tv.tv_usec != 0)
            tvp = &tv; /* 0 0  seems to be looping ... */
    }

    /*
     * Wait until the socket is writeable or readable. We use select here
     * for the sake of simplicity and portability, but you could equally use
     * poll/epoll or similar functions
     *
     * NOTE: For the purposes of this demonstration code this effectively
     * makes this demo block until it has something more useful to do. In a
     * real application you probably want to go and do other work here (e.g.
     * update a GUI, or service other connections).
     *
     * Let's say for example that you want to update the progress counter on
     * a GUI every 100ms. One way to do that would be to use the timeout in
     * the last parameter to "select" below. If the tvp value is greater
     * than 100ms then use 100ms instead. Then, when select returns, you
     * check if it did so because of activity on the file descriptors or
     * because of the timeout. If the 100ms GUI timeout has expired but the
     * tvp timeout has not then go and update the GUI and then restart the
     * "select" (with updated timeouts).
     */

    return (select(sock + 1, &read_fd, &write_fd, NULL, tvp));
}
