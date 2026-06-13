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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "h3_poll.h"
#include "h3_request.h"
#include "h3_response.h"
#include "h3_server.h"
#include "h3_ssl.h"
#include "h3_stream_ids.h"
#include "h3_util.h"

int run_quic_server(apr_pool_t* p, server_rec* s, SSL_CTX* ctx, int fd, struct ssl_id* ssl_ids)
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
