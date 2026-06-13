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

#include <assert.h>

#include "h3_stream_ids.h"

void init_ids(struct ssl_id* ssl_ids)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        ssl_ids[i].s = NULL;
        ssl_ids[i].id = UINT64_MAX;
        ssl_ids[i].status = 0;
        ssl_ids[i].h3ssl = NULL;
    }
}

int add_id_status(uint64_t id, SSL* ssl, struct ssl_id* ssl_ids, int status, struct h3ssl* h3ssl)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].s == NULL)
        {
            ssl_ids[i].s = ssl;
            ssl_ids[i].id = id;
            ssl_ids[i].status = status;
            ssl_ids[i].h3ssl = h3ssl;
            return 0;
        }
    }
    if (h3ssl != NULL)
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Too many streams (limit: %d)", MAXSSL_IDS);
    if (ssl != NULL)
    {
        SSL_free(ssl);
    }
    return -1;
}

int add_id(uint64_t id, SSL* ssl, struct ssl_id* ssl_ids, struct h3ssl* h3ssl)
{
    return add_id_status(id, ssl, ssl_ids, 0, h3ssl);
}

int add_ids_listener(SSL* ssl, struct ssl_id* ssl_ids)
{
    return add_id_status(UINT64_MAX, ssl, ssl_ids, ISLISTENER, NULL);
}

int add_ids_connection(struct ssl_id* ssl_ids, SSL* ssl, struct h3ssl* h3ssl)
{
    return add_id_status(UINT64_MAX, ssl, ssl_ids, ISCONNECTION, h3ssl);
}

SSL* get_ids_connection(struct ssl_id* ssl_ids, struct h3ssl* h3ssl)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].status & ISCONNECTION && ssl_ids[i].h3ssl == h3ssl)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "get_ids_connection");
            return ssl_ids[i].s;
        }
    }
    return NULL;
}

void clean_ids_connection(struct ssl_id* ssl_ids, struct h3ssl* h3ssl)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].status & ISCONNECTION && ssl_ids[i].h3ssl == h3ssl)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "clean_ids_connection");
            if (ssl_ids[i].s != NULL)
            {
                SSL_free(ssl_ids[i].s);
            }
            ssl_ids[i].s = NULL;
            ssl_ids[i].id = UINT64_MAX;
            ssl_ids[i].status = 0;
            ssl_ids[i].h3ssl = NULL;
        }
    }
}

void ssl_ids_store607(struct ssl_id* ssl_ids, uint64_t id, struct h3ssl* h3ssl)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == id && ssl_ids[i].h3ssl == h3ssl)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "ssl_ids_store607 on %" PRIu64, id);
            ssl_ids[i].has607 = 1;
        }
    }
}

int ssl_ids_get607(struct ssl_id* ssl_ids, uint64_t id, struct h3ssl* h3ssl)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == id && ssl_ids[i].h3ssl == h3ssl)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "ssl_ids_get607 on %" PRIu64 " %d", id, ssl_ids[i].has607);
            return ssl_ids[i].has607;
        }
    }
    return 0;
}

void check_finish_ids(struct ssl_id* ssl_ids, server_rec* s)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].s && ssl_ids[i].h3ssl && (ssl_ids[i].status & CLIENTBIDIOPEN))
        {
            if (SSL_get_stream_write_state(ssl_ids[i].s) == SSL_STREAM_STATE_FINISHED)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "check_finish_ids on %" PRIu64 " SSL_STREAM_STATE_FINISHED", ssl_ids[i].id);
                nghttp3_conn_close_stream(ssl_ids[i].h3ssl->h3conn, (int64_t)ssl_ids[i].id, NGHTTP3_H3_NO_ERROR);
                /* remove the ids and clean the stream */
                SSL_free(ssl_ids[i].s);
                ssl_ids[i].s = NULL;
                ssl_ids[i].id = UINT64_MAX;
                ssl_ids[i].status = 0;
                ssl_ids[i].h3ssl = NULL; /* the on_stream_close, use get_h3_request() that doesn't use ssl_ids[i] */
            }
        }
    }
}

struct h3ssl* get_h3ssl_ssl(struct ssl_id* ssl_ids, SSL* ssl)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].s == ssl)
        {
            return ssl_ids[i].h3ssl;
        }
    }
    return NULL;
}

void reset_active_h3ssl(struct activeh3ssl* activeh3ssl)
{
    for (int i = 0; i < 10; i++)
    {
        activeh3ssl->receivedh3ssl[i] = NULL;
    }
    activeh3ssl->current = 0;
}

void add_active_h3ssl(struct activeh3ssl* activeh3ssl, struct h3ssl* h3ssl)
{
    for (int i = 0; i < 10; i++)
    {
        if (activeh3ssl->receivedh3ssl[i] == h3ssl)
            return; /* already there */
    }
    activeh3ssl->receivedh3ssl[activeh3ssl->current] = h3ssl;
    activeh3ssl->current++;
    if (activeh3ssl->current >= 10)
        abort();
}

struct h3ssl* next_active_h3ssl(struct activeh3ssl* activeh3ssl)
{
    if (activeh3ssl->current == 0)
        return NULL; /* empty */
    activeh3ssl->current--;
    return activeh3ssl->receivedh3ssl[activeh3ssl->current];
}

void remove_marked_ids(struct ssl_id* ssl_ids)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].status & TOBEREMOVED)
        {
            SSL_free(ssl_ids[i].s);
            ssl_ids[i].s = NULL;
            ssl_ids[i].id = UINT64_MAX;
            ssl_ids[i].status = 0;
            ssl_ids[i].h3ssl = NULL;
        }
    }
}

void set_id_status(uint64_t id, int status, struct ssl_id* ssl_ids)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == id)
        {
            // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "set_id_status: %" PRIu64 " to %d", (unsigned long long) ssl_ids[i].id, status);
            ssl_ids[i].status = ssl_ids[i].status | status;
            return;
        }
    }
    // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Oops can't set status, can't find stream!!!");
    if (!(status & TOBEREMOVED)) // XXX: what is this???
        assert(0);
}

int get_id_status(uint64_t id, struct ssl_id* ssl_ids)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == id)
        {
            // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "get_id_status: %" PRIu64 " to %d",
            //        (unsigned long long) ssl_ids[i].id, ssl_ids[i].status);
            return ssl_ids[i].status;
        }
    }
    // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Oops can't get status, can't find stream!!!");
    assert(0);
    return -1;
}

int are_all_clientid_closed(struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == UINT64_MAX)
            continue;
        if (ssl_ids[i].h3ssl != h3ssl)
            continue;
        // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "are_all_clientid_closed: %" PRIu64 " status %d : %d",
        //        (unsigned long long) ssl_ids[i].id, ssl_ids[i].status, CLIENTUNIOPEN | CLIENTCLOSED);
        if (ssl_ids[i].status & CLIENTUNIOPEN)
        {
            if (ssl_ids[i].status & CLIENTCLOSED)
            {
                // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "are_all_clientid_closed: %" PRIu64 " closed",
                //        (unsigned long long) ssl_ids[i].id);
                SSL_free(ssl_ids[i].s);
                ssl_ids[i].s = NULL;
                ssl_ids[i].id = UINT64_MAX;
                continue;
            }
            // ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "are_all_clientid_closed: %" PRIu64 " open", (unsigned long long) ssl_ids[i].id);
            return 0;
        }
    }
    return 1;
}

void close_all_ids(struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].id == UINT64_MAX)
            continue;
        if (ssl_ids[i].h3ssl != h3ssl)
            continue;
        SSL_free(ssl_ids[i].s);
        ssl_ids[i].s = NULL;
        ssl_ids[i].id = UINT64_MAX;
        ssl_ids[i].h3ssl = NULL;
    }
}

void close_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* /*s*/, apr_pool_t* /*p*/)
{
    int i;

    for (i = 0; i < MAXSSL_IDS; i++)
    {
        if (ssl_ids[i].h3ssl == h3ssl)
        {
            if (!(ssl_ids[i].status & ISCONNECTION) && ssl_ids[i].s != NULL)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "close_h3ssl for %" PRIu64, ssl_ids[i].id);
                // For every active stream ID we are tracking:
                nghttp3_conn_close_stream(h3ssl->h3conn, (int64_t)ssl_ids[i].id, NGHTTP3_H3_GENERAL_PROTOCOL_ERROR);
            }
            /* The connection closed we can't use the corresponding ids any more */
            SSL_free(ssl_ids[i].s);
            ssl_ids[i].s = NULL;
            ssl_ids[i].id = UINT64_MAX;
            ssl_ids[i].h3ssl = NULL;
        }
    }
}

void clean_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* /*p*/)
{
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "clean_h3ssl");
    close_all_ids(h3ssl, ssl_ids);
    clean_ids_connection(ssl_ids, h3ssl);
    /* XXX nghttp3_conn_server_new has allocate the nghttp3_conn, we might use pool for it too */
    if (h3ssl->h3conn)
    {
        nghttp3_conn_del(h3ssl->h3conn);
        h3ssl->h3conn = NULL;
    }
    /* free the pool and the the connection: Note that we have now completly forgot about all the c3 */
    apr_pool_destroy(h3ssl->p);
}
