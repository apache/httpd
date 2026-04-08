/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2026 The mod_http3 Project Authors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is derived from code originally distributed as part of
 * the OpenSSL project and has been modified for use in mod_http3.
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

#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <nghttp3/nghttp3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ossl-nghttp3.h"

APLOG_USE_MODULE(http3);

extern module AP_MODULE_DECLARE_DATA http3_module;

#ifndef PATH_MAX
    #define PATH_MAX 255
#endif
#ifndef MAXHEADER
    #define MAXHEADER 255
#endif

#define MAXREQPERCON 10

#define nghttp3_arraylen(A) (sizeof(A) / sizeof(*(A)))

/* 3 streams created by the server and 4 by the client (one is bidi) */
struct ssl_id
{
    SSL* s;              /* the stream openssl uses in SSL_read(),  SSL_write etc */
    uint64_t id;         /* the stream identifier the nghttp3 uses */
    int status;          /* 0 or one the below status and origin */
    int has607;          /* work around nghttp3_conn_read_stream returning  -607 on stream */
    struct h3ssl* h3ssl; /* pointer to the h3ssl structure */
};
/* status and origin of the streams the possible values are: */
#define CLIENTUNIOPEN (1 << 0)  /* unidirectional open by the client (2, 6 and 10) */
#define CLIENTCLOSED (1 << 1)   /* closed by the client */
#define CLIENTBIDIOPEN (1 << 2) /* bidirectional open by the client (something like 0, 4, 8 ...) */
#define SERVERUNIOPEN (1 << 3)  /* unidirectional open by the server (3, 7 and 11) XXX: Not used ???? */
#define SERVERCLOSED (1 << 4)   /* closed by the server (us) */
#define TOBEREMOVED (1 << 5)    /* marked for removing in read_from_ssl_ids, */
                                /* it will be removed after processing all events */
#define ISLISTENER (1 << 6)     /* the stream is a listener from SSL_new_listener() */
#define ISCONNECTION (1 << 7)   /* the stream is a connection from SSL_accept_connection() */
#define RETRYWRITE (1 << 8)     /* the stream still has some retry to write */

#define MAXSSL_IDS 2000
#define MAXURL 255

/* The different possible terminations */
#define TERM_ECD (1 << 0)
#define TERM_EC (1 << 1)
#define TERM_HLF (1 << 2)
#define TERM_ERR (1 << 3) /* EC and an error */

struct h3ssl
{
    struct h3_request* h3req; /* pointer to the first h3req hack for the moment */
    int has_uni;              /* we have the 3 uni directional stream needed */
    int c_terminated;         /* connection is terminated EVENT_ECD or EVENT_EC or something else */
    int done;                 /* connection terminated EVENT_ECD, after EVENT_EC */
    server_rec* s;            /* server for log and other stuff */
    conn_rec* c;              /* connect to Apache HTTPD */
    apr_pool_t* p;            /* pool from the pchild */
    nghttp3_conn* h3conn;     /* pointer to nghttp3 connection */
};

/* h3ssl with events, 10 max for the moment */
struct activeh3ssl
{
    struct h3ssl* receivedh3ssl[10]; /* pointer to the h3ssl with events, 10 max for the moment */
    int current;
};

/* Note the name MUST be ap_str_tolower(name); before */
static void make_nv(nghttp3_nv* nv, const char* name, const char* value)
{
    nv->name = (uint8_t*)name;
    nv->value = (uint8_t*)value;
    nv->namelen = strlen(name);
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static void init_ids(struct ssl_id* ssl_ids)
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

/* get the h3_request corresponding to the stream_id */
static struct h3_request* get_h3_request(struct h3ssl* h3ssl, int64_t stream_id)
{
    struct h3_request* h3req = h3ssl->h3req;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "get_h3_request for %ld (%p)", (long)stream_id, (void*)h3req);
    while (h3req)
    {
        if (h3req->id_bidi == stream_id)
            return h3req;
        h3req = h3req->next;
    }
    return h3req;
}
/* Create the h3_request and httpd request_rec */
static struct h3_request* create_h3_request(struct h3ssl* h3ssl, int64_t stream_id)
{
    struct h3_request* h3req = h3ssl->h3req;
    struct h3_request* previous = h3ssl->h3req;
    apr_pool_t* pool;
    request_rec* r;
    h3_conn_ctx_t* h3ctx;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "create_h3_request for %ld (%p)", (long)stream_id, (void*)h3req);
    while (h3req)
    {
        previous = h3req;
        h3req = h3req->next;
    }
    /* allocate a new one from the httpd connection pool */
    apr_pool_create(&pool, h3ssl->c->pool);
    apr_pool_tag(pool, "h3_request");
    h3req = apr_pcalloc(pool, sizeof(struct h3_request));
    if (previous)
        previous->next = h3req;
    else
        h3ssl->h3req = h3req;

    h3req->h3reqpool = pool;
    h3req->id_bidi = stream_id;
    r = ap_create_request(h3ssl->c);
    r->request_time = apr_time_now();
    r->per_dir_config = r->server->lookup_defaults;
    r->connection->keepalive = AP_CONN_KEEPALIVE;
    r->protocol = (char*)"HTTP/3.0";
    r->proto_num = HTTP_VERSION(3, 0);
    h3req->r = r;

    h3ctx = apr_pcalloc(pool, sizeof(h3_conn_ctx_t));
    h3ctx->c3reqpool = pool;
    h3ctx->s = h3ssl->s;
    h3req->h3ctx = h3ctx;
    apr_table_set(r->notes, "H3CTX", (char*)h3ctx);
    return h3req;
}

/* free the pools used by h3req and remote it from the h3ssl list of h3req */
static void cleanup_h3_request(struct h3ssl* h3ssl, struct h3_request* h3req, int64_t stream_id)
{
    struct h3_request* previous = h3ssl->h3req;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "cleanup_h3_request for %ld (%p)", (long)stream_id, (void*)h3req);
    while (previous)
    {
        if (previous->id_bidi == stream_id)
        {
            break;
        }
        previous = previous->next;
    }
    if (!previous)
        abort(); // logical error somewhere.
    previous = h3req->next;
    apr_pool_clear(h3req->h3reqpool); // the apr_pool_destroy() is for the connection...
}

static int add_id_status(uint64_t id, SSL* ssl, struct ssl_id* ssl_ids, int status, struct h3ssl* h3ssl)
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
static int add_id(uint64_t id, SSL* ssl, struct ssl_id* ssl_ids, struct h3ssl* h3ssl)
{
    return add_id_status(id, ssl, ssl_ids, 0, h3ssl);
}

/* Add listener and connection */
static int add_ids_listener(SSL* ssl, struct ssl_id* ssl_ids)
{
    return add_id_status(UINT64_MAX, ssl, ssl_ids, ISLISTENER, NULL);
}
static int add_ids_connection(struct ssl_id* ssl_ids, SSL* ssl, struct h3ssl* h3ssl)
{
    return add_id_status(UINT64_MAX, ssl, ssl_ids, ISCONNECTION, h3ssl);
}
static SSL* get_ids_connection(struct ssl_id* ssl_ids, struct h3ssl* h3ssl)
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
static void clean_ids_connection(struct ssl_id* ssl_ids, struct h3ssl* h3ssl)
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

static void ssl_ids_store607(struct ssl_id* ssl_ids, uint64_t id, struct h3ssl* h3ssl)
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
static int ssl_ids_get607(struct ssl_id* ssl_ids, uint64_t id, struct h3ssl* h3ssl)
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

static void check_finish_ids(struct ssl_id* ssl_ids, server_rec* s)
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

static struct h3ssl* get_h3ssl_ssl(struct ssl_id* ssl_ids, SSL* ssl)
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
/* We support 10 for the moment */
static void reset_active_h3ssl(struct activeh3ssl* activeh3ssl)
{
    for (int i = 0; i < 10; i++)
    {
        activeh3ssl->receivedh3ssl[i] = NULL;
    }
    activeh3ssl->current = 0;
}
static void add_active_h3ssl(struct activeh3ssl* activeh3ssl, struct h3ssl* h3ssl)
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
static struct h3ssl* next_active_h3ssl(struct activeh3ssl* activeh3ssl)
{
    if (activeh3ssl->current == 0)
        return NULL; /* empty */
    activeh3ssl->current--;
    return activeh3ssl->receivedh3ssl[activeh3ssl->current];
}

/* remove the ids marked for removal */
static void remove_marked_ids(struct ssl_id* ssl_ids)
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

/* add the status bytes to the status */
static void set_id_status(uint64_t id, int status, struct ssl_id* ssl_ids)
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
static int get_id_status(uint64_t id, struct ssl_id* ssl_ids)
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

/* check that all streams opened by the client are closed */
static int are_all_clientid_closed(struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
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

/* free all the ids from a h3ssl */
static void close_all_ids(struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
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

/* Tell h3 that all the id corresponding to the connection are closed */
static void close_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* /*s*/, apr_pool_t* /*p*/)
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

static int on_recv_header(nghttp3_conn* /*conn*/, int64_t stream_id, int32_t token, nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t /*flags*/, void* user_data, void* /*stream_user_data*/)
{
    nghttp3_vec vname, vvalue;
    struct h3ssl* h3ssl = (struct h3ssl*)user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);
    request_rec* r;

    if (h3req == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_recv_header, create request");
        h3req = create_h3_request(h3ssl, stream_id);
    }

    r = h3req->r;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_recv_header, add header to request");
    h3req->num_headers++;
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);

    /* Process uri */
    if (token == NGHTTP3_QPACK_TOKEN__PATH)
    {
        /* :path */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Path too long or empty: %zu bytes (max %d)", vvalue.len, MAXURL);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        r->uri = apr_pcalloc(r->pool, len);
        memcpy(r->uri, vvalue.base, vvalue.len);

        /* add the unparsed_uri */
        r->unparsed_uri = r->uri;
        apr_uri_parse(r->pool, r->uri, &r->parsed_uri);
        return 0;
    }

    /* Process scheme */
    if (token == NGHTTP3_QPACK_TOKEN__SCHEME)
    {
        /* :scheme */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Scheme too long or empty: %zu bytes", vvalue.len);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        char* scheme = apr_pcalloc(r->pool, len);
        memcpy(scheme, vvalue.base, vvalue.len);
        apr_table_setn(r->headers_in, "Scheme", scheme);
        return 0;
    }

    /* Process method */
    if (token == NGHTTP3_QPACK_TOKEN__METHOD)
    {
        /* :method */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Invalid method length: %zu", vvalue.len);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        r->method = apr_pcalloc(r->pool, len);
        memcpy((char*)r->method, vvalue.base, vvalue.len);
        return 0;
    }

    /* Process authority */
    if (token == NGHTTP3_QPACK_TOKEN__AUTHORITY)
    {
        /* :authority = Host */
        if (vvalue.len == 0 || vvalue.len >= MAXURL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Authority too long or empty: %zu bytes", vvalue.len);
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        size_t len = vvalue.len + 1;
        char* host = apr_pcalloc(r->pool, len);
        memcpy(host, vvalue.base, vvalue.len);
        apr_table_setn(r->headers_in, "Host", host);
        return 0;
    }

    /* Received a single HTTP header. */
    vname = nghttp3_rcbuf_get_buf(name);
    vvalue = nghttp3_rcbuf_get_buf(value);
    if (vname.len == 0 || vname.len >= MAXHEADER)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Header name too long or empty: %zu bytes", vname.len);
        return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    }
    if (vvalue.len >= MAXHEADER)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "Header value too long: %zu bytes", vvalue.len);
        return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    }
    size_t ln = vname.len + 1;
    size_t lv = vvalue.len + 1;
    char* sname = apr_pcalloc(r->pool, ln);
    memcpy(sname, vname.base, vname.len);
    char* svalue = apr_pcalloc(r->pool, lv);
    memcpy(svalue, vvalue.base, vvalue.len);
    apr_table_setn(r->headers_in, sname, svalue);
    return 0;
}

static int on_end_headers(nghttp3_conn* /*conn*/, int64_t stream_id, int /*fin*/, void* user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_end_headers!");
    h3req->end_headers_received = 1;
    return 0;
}

static int on_recv_data(nghttp3_conn* /*conn*/, int64_t stream_id, const uint8_t* data, size_t datalen, void* conn_user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)conn_user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);
    request_rec* r;
    char* postdata;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_recv_data! %ld", (unsigned long)datalen);
    if (h3req == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "on_recv_data: h3req is NULL for stream %" PRIu64, stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    r = h3req->r;
    if (r == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "on_recv_data: request_rec is NULL!");
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    postdata = apr_palloc(r->pool, datalen);
    memcpy(postdata, data, datalen);
    apr_table_set(r->notes, "H3POSTDATA", postdata);
    apr_table_set(r->notes, "H3POSTDATALEN", apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, datalen));
    return 0;
}

static int on_end_stream(nghttp3_conn* /*h3conn*/, int64_t stream_id, void* conn_user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)conn_user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_end_stream on %" PRIu64, stream_id);
    h3req->endstream = 1;
    return 0;
}

/* it is called after SSL_get_stream_write_state() == SSL_STREAM_STATE_FINISHED and nghttp3_conn_close_stream */
static int on_stream_close(nghttp3_conn* /*h3conn*/, int64_t stream_id, uint64_t /*app_error_code*/, void* conn_user_data, void* /*stream_user_data*/)
{
    struct h3ssl* h3ssl = (struct h3ssl*)conn_user_data;
    struct h3_request* h3req = get_h3_request(h3ssl, stream_id);

    h3req->closestream = 1;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ssl->s, "on_stream_close on %" PRIu64, stream_id);
    cleanup_h3_request(h3ssl, h3req, stream_id);
    return 0;
}

static char* get_openssl_error_string(apr_pool_t* p)
{
    char* buf;
    long len;
    char* ret = NULL;

    // 1. Create a Memory BIO
    // BIO_s_mem() is the memory BIO method
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        return strdup("Failed to create memory BIO.");
    }

    // 2. Print Errors to the BIO (This clears the error queue)
    ERR_print_errors(bio);

    // 3. Extract the Data
    // BIO_get_mem_data returns the internal pointer and its length.
    // NOTE: This pointer is managed by the BIO and should NOT be freed separately.
    len = BIO_get_mem_data(bio, &buf);

    if (len > 0)
    {
        // Allocate a new buffer (+1 for the null terminator)
        ret = (char*)apr_palloc(p, (size_t)(len + 1));
        if (ret != NULL)
        {
            // Copy the data and null-terminate the string
            memcpy(ret, buf, (size_t)len);
            ret[len] = '\0';
        }
    }

    // Clean up the BIO object
    BIO_free(bio);

    // Return the dynamically allocated error string
    return ret;
}

/* print the openssl error in the httpd log */
static void ERR_print_errors_log(struct h3ssl* h3ssl)
{
    char* err = NULL;
    char* str;
    // if (h3ssl->r != NULL)
    //     err = get_openssl_error_string(h3ssl->r->pool);
    if (h3ssl->c != NULL)
        err = get_openssl_error_string(h3ssl->c->pool);
    if (h3ssl->p != NULL)
        err = get_openssl_error_string(h3ssl->p);
    if (err == NULL)
    {
        abort(); // JFC error in the logic...
        return;
    }
    /* There might several error print them one by one */
    str = err;
    for (size_t i = 0; i < strlen(err); i++)
    {
        if (err[i] == '\n')
        {
            err[i] = '\0';
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, h3ssl->s, "OPENSSL error %s", str);
            str = err + i + 1;
        }
    }
}

/* Read from the stream and push to the h3conn */
static int quic_server_read(nghttp3_conn* h3conn, SSL* stream, uint64_t id, struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
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

/*
 * creates the control stream, the encoding and decoding streams.
 * nghttp3_conn_bind_control_stream() is for the control stream.
 */
static int quic_server_h3streams(nghttp3_conn* h3conn, struct h3ssl* h3ssl, struct ssl_id* ssl_ids)
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

/* Try to read from the streams we have */
static int read_from_ssl_ids(struct ssl_id* ssl_ids, struct activeh3ssl* activeh3ssl, apr_pool_t* p, server_rec* s)
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

static void handle_events_from_ids(struct ssl_id* ssl_ids, server_rec* s)
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

static nghttp3_ssize step_read_data(nghttp3_conn* /*conn*/, int64_t stream_id, nghttp3_vec* vec, size_t /*veccnt*/, uint32_t* pflags, void* user_data, void* /*stream_user_data*/)
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

static int quic_server_write(struct ssl_id* ssl_ids, uint64_t streamid, uint8_t* buff, size_t len, uint64_t flags, size_t* written)
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

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

/*
 * This is a basic demo of QUIC server functionality in which one connection at
 * a time is accepted in a blocking loop.
 */

/* ALPN string for TLS handshake. We pretent h3-29 and h3 */
static const unsigned char alpn_ossltest[] = {5, 'h', '3', '-', '2', '9', 2, 'h', '3'};

/*
 * This callback validates and negotiates the desired ALPN on the server side.
 */
static int select_alpn(SSL* /*ssl*/, const unsigned char** out, unsigned char* out_len, const unsigned char* in, unsigned int in_len, void* /*arg*/)
{
    if (SSL_select_next_proto((unsigned char**)out, out_len, alpn_ossltest, sizeof(alpn_ossltest), in, in_len) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    return SSL_TLSEXT_ERR_OK;
}

/* Create SSL_CTX. */
static SSL_CTX* create_ctx(server_rec* s, const char* cert_path, const char* key_path)
{
    SSL_CTX* ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    /* Load certificate and corresponding private key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "couldn't load certificate file: %s", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "couldn't load key file: %s", key_path);
        goto err;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "private key check failed");
        goto err;
    }

    /* Setup ALPN negotiation callback. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket using given port. */
static int create_socket(server_rec* s, uint16_t port)
{
    int fd = -1;
    struct sockaddr_in6 sa;
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "cannot create socket");
        goto err;
    }
    /* trying */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, optlen) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "cannot setsockopt on socket");
        goto err;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons(port);

    if (bind(fd, (const struct sockaddr*)&sa, sizeof(sa)) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "cannot bind to %u", port);
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        BIO_closesocket(fd);

    return -1;
}

/* Copied from demos/guide/quic-server-non-block.c */
/**
 * @brief Waits for activity on the SSL socket, either for reading or writing.
 *
 * This function monitors the underlying file descriptor of the given SSL
 * connection to determine when it is ready for reading or writing, or both.
 * It uses the select function to wait until the socket is either readable
 * or writable, depending on what the SSL connection requires.
 *
 * @param ssl A pointer to the SSL object representing the connection.
 *
 * @note This function blocks until there is activity on the socket. In a real
 * application, you might want to perform other tasks while waiting, such as
 * updating a GUI or handling other connections.
 *
 * @note This function uses select for simplicity and portability. Depending
 * on your application's requirements, you might consider using other
 * mechanisms like poll or epoll for handling multiple file descriptors.
 */
static int wait_for_activity(server_rec* s, SSL* ssl)
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

static int add_header_entry(void* rec, const char* key, const char* value)
{
    h3_nvs_t* h3_nvs = (h3_nvs_t*)rec;
    size_t cur_nv = h3_nvs->cur_nv;
    char* header_name;
    char* header_value;
    nghttp3_nv* resp = h3_nvs->resp;
    if (cur_nv == h3_nvs->max_nv)
        return 0; /* stop not enough space */
    header_name = apr_pstrdup(h3_nvs->p, key);
    ap_str_tolower(header_name);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3_nvs->s, "add_header_entry: %s %s", header_name, value);
    header_value = apr_pstrdup(h3_nvs->p, value);
    make_nv(&resp[cur_nv++], header_name, header_value);
    h3_nvs->cur_nv = cur_nv;
    return 1;
}

/* Build the nv using the respnse from httpd */
static void build_nv_from_response(nghttp3_nv* resp, size_t* num_nv, size_t max_nv, h3_conn_ctx_t* h3ctx)
{
    h3_nvs_t h3_nvs;
    ap_bucket_response* response = h3ctx->resp;
    size_t cur_nv = *num_nv;
    char* stringstatus;
    h3_nvs.resp = resp;
    h3_nvs.cur_nv = cur_nv;
    h3_nvs.max_nv = max_nv;
    h3_nvs.s = h3ctx->s;
    h3_nvs.p = h3ctx->c3reqpool;

    /* set response->status */
    stringstatus = apr_psprintf(h3ctx->c3reqpool, "%d", response->status);
    make_nv(&resp[cur_nv++], ":status", stringstatus);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ctx->s, "build_nv_from_response status %s", stringstatus);

    /* set response->reason */
    if (response->reason != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, h3ctx->s, "build_nv_from_response reason %s", response->reason);
    }

    h3_nvs.cur_nv = cur_nv;
    if (response->headers != NULL)
    {
        apr_table_do(add_header_entry, (void*)&h3_nvs, response->headers, NULL);
    }
    *num_nv = h3_nvs.cur_nv;
}

/* XXX to cleanup by moving */
static void clean_h3ssl(struct h3ssl* h3ss, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* /*p*/);
static int process_h3ssl(struct h3ssl* h3ss, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* p);

/* -1 is the SSL error, 0 no error all OK */
#define WAIT_DONE 1
#define WAIT_HEADERS 2 /* waiting for headers */
#define WAIT_CLOSE 3   /* waiting for the other side to close */
#define WAIT_RETRY 4   /* waiting for the other side to send more data */
#define TERMINATING 5  /* the connection is terminating / waiting for ECD */
#define CLOSE_DONE 6   /* both side cleanly closed, connection terminated */
#define CLOSE_ERROR 7  /* client closed without request */
#define ERROR_LOGIC 8  /* some internal states were incorrect, process we should exit or abort() */

/* Main loop for server to accept QUIC connections. */
static int run_quic_server(apr_pool_t* p, server_rec* s, SSL_CTX* ctx, int fd, struct ssl_id* ssl_ids)
{
    int ok = 0;
    int hassomething = 0;
    SSL* listener = NULL;

    /* Create a new QUIC listener. */
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server started!");
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    /* Provide the listener with our UDP socket. */
    if (!SSL_set_fd(listener, fd))
        goto err;

    /* Begin listening. */
    if (!SSL_listen(listener))
        goto err;

    /*
     * Listeners, and other QUIC objects, default to operating in blocking mode.
     * The configured behaviour is inherited by child objects.
     * Make sure we won't block as we use select().
     */
    if (!SSL_set_blocking_mode(listener, 0))
        goto err;

    init_ids(ssl_ids);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "listener: %p", (void*)listener);
    if (add_ids_listener(listener, ssl_ids) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Failed to add listener");
        goto err;
    }

    for (;;)
    {
        int ret;
        struct activeh3ssl activeh3ssl;

        if (!hassomething)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "waiting on socket");
            ret = wait_for_activity(s, listener);
            if (ret == -1)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "wait_for_activity failed!");
                goto err;
            }
            if (ret == 0)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "wait_for_activity timeout");
                continue;
            }
            handle_events_from_ids(ssl_ids, s); /* XXX to check */
        }
        /* Something was received on the listener/socket */
        memset(&activeh3ssl, 0, sizeof(activeh3ssl));
        hassomething = read_from_ssl_ids(ssl_ids, &activeh3ssl, p, s);
        if (hassomething == -1)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "read_from_ssl_ids hassomething failed");
            goto err;
        }
        else if (hassomething == 0)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids hassomething nothing...");
            check_finish_ids(ssl_ids, s);
            continue;
        }
        else
        {
            check_finish_ids(ssl_ids, s);
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids hassomething %d...", hassomething);
            for (;;)
            {
                int status;
                struct h3ssl* receivedh3ssl = next_active_h3ssl(&activeh3ssl);
                /* find the h3ssl that have received something */
                if (receivedh3ssl == NULL)
                    break; /* Done */
                status = process_h3ssl(receivedh3ssl, ssl_ids, s, p);
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids process_h3ssl %d", status);
                if (status < 0)
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "read_from_ssl_ids process_h3ssl failed!");
                    break;
                }
                if (status == CLOSE_DONE)
                {
                    /* the h3ssl can be cleaned we are done */
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids process_h3ssl done! on %p", (void*)receivedh3ssl->c);
                    clean_h3ssl(receivedh3ssl, ssl_ids, s, p); /* remove the ssl_ids that correspond to the h3 connection */
                }
                if (status == CLOSE_ERROR)
                {
                    /* the h3ssl can be cleaned there was no request */
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "read_from_ssl_ids process_h3ssl error no request!");
                    clean_h3ssl(receivedh3ssl, ssl_ids, s, p); /* remove the ssl_ids that correspond to the h3 connection */
                }
                if (status == WAIT_RETRY)
                {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "read_from_ssl_ids process_h3ssl error need retry on write!");
                }
                if (status == TERMINATING)
                {
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids process_h3ssl terminating waiting for ECD!");
                }
                if (status == WAIT_DONE)
                {
                    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "read_from_ssl_ids process_h3ssl terminating wait done!");
                    clean_h3ssl(receivedh3ssl, ssl_ids, s, p); /* remove the ssl_ids that correspond to the h3 connection */
                }
            }
        }
    }
    ok = 1;
err:
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server Done!");
    if (!ok)
    {
        struct h3ssl* mh3ssl;
        mh3ssl = apr_pcalloc(p, sizeof(struct h3ssl));
        mh3ssl->p = p;
        mh3ssl->s = s;
        ERR_print_errors_log(mh3ssl);
    }

    SSL_free(listener);
    return ok;
}
/* Clean the ssl_ids associated with the h3conn */
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

/*
 * write the response that has been prepared by httpd logic.
 * also use to finish write the response after QUIC layer flow stopped us.
 */
static int quic_server_write_response(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* /*p*/)
{
    int ok = -1;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response");
    for (;;)
    {
        nghttp3_vec vec[256];
        nghttp3_ssize sveccnt;
        int fin, i;
        int64_t streamid;

        sveccnt = nghttp3_conn_writev_stream(h3ssl->h3conn, &streamid, &fin, vec, nghttp3_arraylen(vec));
        if (sveccnt <= 0)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: nghttp3_conn_writev_stream done: %ld on %" PRIu64 " fin %d", (long int)sveccnt, (uint64_t)streamid, fin);
            if (streamid != -1 && fin)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: Sending end data on %" PRIu64 " fin %d", (uint64_t)streamid, fin);
                nghttp3_conn_add_write_offset(h3ssl->h3conn, streamid, 0);
                continue;
            }
            break; /* Done */
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: nghttp3_conn_writev_stream: %ld fin: %d", (long int)sveccnt, fin);
        for (i = 0; i < sveccnt; i++)
        {
            size_t numbytes = vec[i].len;
            int flagwrite = 0;

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response: quic_server_write on %" PRIu64 " for %ld", (uint64_t)streamid, (unsigned long)vec[i].len);
            if (get_id_status((uint64_t)streamid, ssl_ids) & RETRYWRITE)
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write RETRYWRITE");
            if (fin && i == sveccnt - 1)
            {
                /* mark that we are using fin */
                struct h3_request* h3req = get_h3_request(h3ssl, streamid);
                h3req->finsend = 1;
                flagwrite = SSL_WRITE_FLAG_CONCLUDE;
            }
            if (!quic_server_write(ssl_ids, (uint64_t)streamid, vec[i].base, vec[i].len, (uint64_t)flagwrite, &numbytes))
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write failed!");
                goto err;
            }
            else
            {
                if (numbytes == 0)
                {
                    /* we need to retry the flow stopped us (quic_server_write sets the RETRYWRITE for us? */
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write RETRYWRITE %" PRIu64 " status: %d", (uint64_t)streamid, get_id_status((uint64_t)streamid, ssl_ids));
                    // return WAIT_RETRY;
                    continue; // We ignore it...
                }
                if (get_id_status((uint64_t)streamid, ssl_ids) & RETRYWRITE)
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: quic_server_write RETRYWRITE %" PRIu64 " OK", (uint64_t)streamid);
            }
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response %d %ld on %" PRIu64 " len: %zu", i, (long)sveccnt, (uint64_t)streamid, (size_t)nghttp3_vec_len(vec, (size_t)i));
        if (nghttp3_conn_add_write_offset(h3ssl->h3conn, streamid, (size_t)nghttp3_vec_len(vec, (size_t)i)))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_write_response: nghttp3_conn_add_write_offset failed!");
            return ERROR_LOGIC;
        }
    }

    ok = 0;
err:
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "quic_server_write_response DONE!!!");
    if (ok)
        ERR_print_errors_log(h3ssl);

    return ok;
}

/* we have received all the headers get httpd to build the response for us */
static int process_h3response(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, struct h3_request* h3req, server_rec* s, apr_pool_t* p)
{
    int ok = -1;
    nghttp3_nv resp[10];
    size_t num_nv = 0;
    nghttp3_data_reader dr;
    h3_conn_ctx_t* h3ctx;

    h3req->end_headers_received = 0;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "end_headers_received!!!");
    if (!h3ssl->has_uni)
    {
        /* time to create those otherwise we can't push anything to the client */
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "Create uni");
        if (quic_server_h3streams(h3ssl->h3conn, h3ssl, ssl_ids) == -1)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "quic_server_h3streams failed!");
            goto err;
        }
        h3ssl->has_uni = 1;
    }

    /* we have receive the request build the response and send it */
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server processing request!");
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server %d %d", h3req->datadone, h3req->num_headers);
    if (h3req->datadone)
        abort(); // JFC logical problem...

    h3ctx = h3req->h3ctx;
    if (process_request(h3req->r, h3ctx) != APR_SUCCESS)
    {
        /* Probably we should return a bad request or something the like */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server processing request FAILED!");
        goto err;
    }
    if (h3ctx->resp == NULL)
    {
        /* Probably we should return a bad request or something the like */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server no response!");
        goto err;
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server processing response part!");
    }
    build_nv_from_response(resp, &num_nv, 10, h3ctx);
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server num_nv: %zu", num_nv);

    /* Process the other bucket */
    uint8_t* buffer;
    apr_size_t len = 0;
    if (h3ctx->otherpart != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server has other part %p %p %p", (void*)h3ctx, (void*)h3ctx->otherpart, (void*)h3ctx->dataheap);
        if (h3ctx->dataheap != NULL)
        {
            abort();
        }
        if (APR_BUCKET_IS_FILE(h3ctx->otherpart))
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_FILE");
            apr_bucket_file* f = (apr_bucket_file*)h3ctx->otherpart->data;
            apr_file_t* fd = f->fd;
            apr_off_t offset = h3ctx->otherpart->start;
            apr_status_t rv;

            len = h3ctx->otherpart->length;
            rv = apr_file_seek(fd, APR_SET, &offset);
            if (rv != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_file_seek failed %d %d", rv, APR_EOF);
                abort(); /* Problem */
            }
            buffer = apr_palloc(p, len);
            rv = apr_file_read(fd, buffer, &len);
            if (rv != APR_SUCCESS && rv != APR_EOF)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_file_read failed %d", rv);
                abort(); /* Problem */
            }
            h3req->ptr_data = buffer;
        }
        else if (APR_BUCKET_IS_MMAP(h3ctx->otherpart))
        {
            const char* data = NULL;
            apr_status_t rv;

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_MMAP");
            len = h3ctx->otherpart->length;
            rv = apr_bucket_read(h3ctx->otherpart, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_bucket_read failed %d %d", rv, APR_EOF);
                abort(); /* Problem */
            }
            if (data == (char*)-1)
            {
                // abort(); /* Problem */
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server apr_bucket_read %s not yet supported", h3ctx->otherpart->type->name);
                buffer = apr_palloc(p, len);
                memset(buffer, 'A', len);
                h3req->ptr_data = buffer;
            }
            else if (len > 0 && data != NULL)
            {
                buffer = apr_palloc(p, len);
                memcpy(buffer, data, len);
                h3req->ptr_data = buffer;
            }
            else
                abort(); /* Problem */
        }
        else if (APR_BUCKET_IS_HEAP(h3ctx->otherpart))
        {
            const char* data;
            apr_size_t datalen;
            const char* cl_str;
            uint8_t* ptr;

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_HEAP");
            // Look up the Content-Length header
            cl_str = apr_table_get(h3req->r->headers_in, "Content-Length");

            if (cl_str)
            {
                // Convert string to an off_t (large integer)
                datalen = (apr_size_t)apr_atoi64(cl_str);
            }
            else
                abort();

            buffer = apr_palloc(p, datalen);
            len = datalen;
            h3req->ptr_data = buffer;

            ptr = buffer;
            apr_bucket_read(h3ctx->otherpart, &data, &len, APR_BLOCK_READ);
            memcpy(ptr, data, len);

            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server other part is APR_BUCKET_IS_HEAP %zu", datalen);
        }
        else
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server %s not yet supported", h3ctx->otherpart->type->name);
            abort(); /* For the moment the otherpart is a FILE bucket */
        }
    }
    if (h3ctx->dataheap != NULL)
    {
        if (h3ctx->otherpart != NULL)
        {
            abort();
        }
        /* We have read the buffer in mod_http3.c */
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server has APR_BUCKET_IS_HEAP %p %zu", (void*)h3ctx, h3ctx->dataheaplen);
        h3req->ptr_data = (uint8_t*)h3ctx->dataheap;
        len = h3ctx->dataheaplen;
    }
    /* Just trying */
    h3req->ldata = len;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server num_nv: %zu Just trying!!!", num_nv);

    dr.read_data = step_read_data;
    if (nghttp3_conn_submit_response(h3ssl->h3conn, h3req->id_bidi, resp, num_nv, &dr))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "nghttp3_conn_submit_response failed!");
        goto err;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "nghttp3_conn_submit_response on %" PRIu64 "...", (uint64_t)h3req->id_bidi);
    ok = quic_server_write_response(h3ssl, ssl_ids, s, p);
    if (ok == -1)
        goto err; /* SSL error, troubles */
    if (ok == ERROR_LOGIC)
        return ERROR_LOGIC;
    if (ok == WAIT_RETRY)
    {
        /* we need to figure out here */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "nghttp3_conn_submit_response PARTIAL!!!");
        return ok;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "nghttp3_conn_submit_response DONE!!!");

    ok = 0;
err:
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "run_quic_server Done!");
    if (ok)
        ERR_print_errors_log(h3ssl);

    return ok;
}

/* Process a h3ssl associated with the h3conn */
int process_h3ssl(struct h3ssl* h3ssl, struct ssl_id* ssl_ids, server_rec* s, apr_pool_t* p)
{
    int ok = -1;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl");

    /* connection terminated EC or ECD or ECD + ER */
    if (h3ssl->c_terminated)
    {
        if (h3ssl->c_terminated & TERM_ERR)
        {
            /* We have EC but an error code */
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: ERR Terminated");
        }
        else if (h3ssl->c_terminated & TERM_EC)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: EC Terminated");
            /* We need to tell h3 that all the streams are closed */
            close_h3ssl(h3ssl, ssl_ids, s, p);
        }
        else if (h3ssl->c_terminated & TERM_ECD)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: ECD Terminated");
        }
        else if (h3ssl->c_terminated & TERM_HLF)
        {
            /* XXX we have stuff to read */
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: HLF Terminated");
        }
        return CLOSE_DONE;
    }

    /* Loop through the request/response/bidi to see if there is something to do */
    struct h3_request* h3req;
    for (h3req = h3ssl->h3req; h3req; h3req = h3req->next)
    {

        if (!h3req->end_headers_received)
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: WAIT_HEADERS");
            continue;
        }

        /* we have the headers get httpd to give us the response */
        if (h3req->end_headers_received)
        {
            ok = process_h3response(h3ssl, ssl_ids, h3req, s, p);
            if (ok)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "process_h3ssl: process_h3response failed");
                continue; // XXX: We have more requests to process or should we clean up the connection?
            }
        }

        if (h3req->datadone)
        {
            /*
             * All the data was sent.
             * close bidi stream. Well mark it closed on our side.
             */
            h3req->end_headers_received = 0; /* Done */
            if (!h3ssl->c_terminated)
            {
                ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: nghttp3_conn_submit_response bidi %" PRIu64 " marked closed on server side", (uint64_t)h3req->id_bidi);
                set_id_status((uint64_t)h3req->id_bidi, SERVERCLOSED, ssl_ids);
            }
        }
        else
        {
            ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: nghttp3_conn_submit_response still not finished");
        }
    }

    ok = 0;
    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "process_h3ssl: Done!");
    if (ok)
        ERR_print_errors_log(h3ssl);

    return ok;
}

/*
 * Call the h3 logic
 */
int server(apr_pool_t* p, server_rec* s, unsigned long port, const char* cert_path, const char* key_path)
{
    int rc = 1;
    SSL_CTX* ctx = NULL;
    int fd = -1;
    struct ssl_id* ssl_ids = apr_pcalloc(p, sizeof(struct ssl_id) * MAXSSL_IDS);

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, s, "server started!");

    /* Create SSL_CTX. */
    if ((ctx = create_ctx(s, cert_path, key_path)) == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "create_ctx failed!");
        goto err;
    }

    /* Parse port number from command line arguments. */
    if (port == 0 || port > UINT16_MAX)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "invalid port: %lu\n", port);
        goto err;
    }

    /* Create UDP socket. */
    if ((fd = create_socket(s, (uint16_t)port)) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "create_socket failed!");
        goto err;
    }

    /* Enter QUIC server connection acceptance loop. */
    if (!run_quic_server(p, s, ctx, fd, ssl_ids))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server failed!");
        goto err;
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "run_quic_server done!");
    }

    rc = 0;
err:
    if (rc != 0)
    {
        char* err = get_openssl_error_string(p);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "failed! %d", rc);
        if (err != NULL)
        {
            char* str;
            str = err;
            for (size_t i = 0; i < strlen(err); i++)
            {
                if (err[i] == '\n')
                {
                    err[i] = '\0';
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "OPENSSL error %s", str);
                    str = err + i + 1;
                }
            }
        }
    }

    SSL_CTX_free(ctx);

    if (fd != -1)
        BIO_closesocket(fd);

    return rc;
}
