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

/* AJP routines for Apache proxy */

#include "mod_proxy.h"
#include "ajp.h"

module AP_MODULE_DECLARE_DATA proxy_ajp_module;

/*
 * Canonicalise http-like URLs.
 * scheme is the scheme for the URL
 * url is the URL starting with the first '/'
 * def_port is the default port for this scheme.
 */
static int proxy_ajp_canon(request_rec *r, char *url)
{
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    apr_port_t port = AJP13_DEF_PORT;

    /* ap_port_of_scheme() */
    if (strncasecmp(url, "ajp:", 4) == 0) {
        url += 4;
    }
    else {
        return DECLINED;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: AJP: canonicalising URL %s", url);

    /*
     * do syntactic check.
     * We break the URL into host, port, path, search
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse path/search args, according to rfc1738:
     * process the path. With proxy-noncanon set (by
     * mod_proxy) we use the raw, unparsed uri
     */
    if (apr_table_get(r->notes, "proxy-nocanon")) {
        path = url;   /* this is the raw path */
    }
    else {
        path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0,
                                 r->proxyreq);
        search = r->args;
    }
    if (path == NULL)
        return HTTP_BAD_REQUEST;

    apr_snprintf(sport, sizeof(sport), ":%d", port);

    if (ap_strchr_c(host, ':')) {
        /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:ajp://", host, sport,
                              "/", path, (search) ? "?" : "",
                              (search) ? search : "", NULL);
    return OK;
}

#define METHOD_NON_IDEMPOTENT       0
#define METHOD_IDEMPOTENT           1
#define METHOD_IDEMPOTENT_WITH_ARGS 2

static int is_idempotent(request_rec *r)
{
    /*
     * RFC2616 (9.1.2): GET, HEAD, PUT, DELETE, OPTIONS, TRACE are considered
     * idempotent. Hint: HEAD requests use M_GET as method number as well.
     */
    switch (r->method_number) {
        case M_GET:
        case M_DELETE:
        case M_PUT:
        case M_OPTIONS:
        case M_TRACE:
            /*
             * If the request has arguments it might have side-effects and thus
             * it might be undesirable to resent it to a backend again
             * automatically.
             */
            if (r->args) {
                return METHOD_IDEMPOTENT_WITH_ARGS;
            }
            return METHOD_IDEMPOTENT;
        /* Everything else is not considered idempotent. */
        default:
            return METHOD_NON_IDEMPOTENT;
    }
}

static apr_off_t get_content_length(request_rec * r)
{
    apr_off_t len = 0;

    if (r->clength > 0) {
        return r->clength;
    }
    else if (r->main == NULL) {
        const char *clp = apr_table_get(r->headers_in, "Content-Length");

        if (clp) {
            char *errp;
            if (apr_strtoff(&len, clp, &errp, 10) || *errp || len < 0) {
                len = 0; /* parse error */
            }
        }
    }

    return len;
}

/*
 * XXX: AJP Auto Flushing
 *
 * When processing CMD_AJP13_SEND_BODY_CHUNK AJP messages we will do a poll
 * with FLUSH_WAIT miliseconds timeout to determine if more data is currently
 * available at the backend. If there is no more data available, we flush
 * the data to the client by adding a flush bucket to the brigade we pass
 * up the filter chain.
 * This is only a bandaid to fix the AJP/1.3 protocol shortcoming of not
 * sending (actually not having defined) a flush message, when the data
 * should be flushed to the client. As soon as this protocol shortcoming is
 * fixed this code should be removed.
 *
 * For further discussion see PR37100.
 * http://issues.apache.org/bugzilla/show_bug.cgi?id=37100
 */

/*
 * process the request and write the response.
 */
static int ap_proxy_ajp_request(apr_pool_t *p, request_rec *r,
                                proxy_conn_rec *conn,
                                conn_rec *origin,
                                proxy_dir_conf *conf,
                                apr_uri_t *uri,
                                char *url, char *server_portstr)
{
    apr_status_t status;
    int result;
    apr_bucket *e;
    apr_bucket_brigade *input_brigade;
    apr_bucket_brigade *output_brigade;
    ajp_msg_t *msg;
    apr_size_t bufsiz = 0;
    char *buff;
    char *send_body_chunk_buff;
    apr_uint16_t size;
    const char *tenc;
    int havebody = 1;
    int output_failed = 0;
    int backend_failed = 0;
    apr_off_t bb_len;
    int data_sent = 0;
    int headers_sent = 0;
    int rv = 0;
    apr_int32_t conn_poll_fd;
    apr_pollfd_t *conn_poll;
    proxy_server_conf *psf =
    ap_get_module_config(r->server->module_config, &proxy_module);
    apr_size_t maxsize = AJP_MSG_BUFFER_SZ;
    int send_body = 0;
    apr_off_t content_length = 0;

    if (psf->io_buffer_size_set)
       maxsize = psf->io_buffer_size;
    if (maxsize > AJP_MAX_BUFFER_SZ)
       maxsize = AJP_MAX_BUFFER_SZ;
    else if (maxsize < AJP_MSG_BUFFER_SZ)
       maxsize = AJP_MSG_BUFFER_SZ;
    maxsize = APR_ALIGN(maxsize, 1024);
       
    /*
     * Send the AJP request to the remote server
     */

    /* send request headers */
    status = ajp_send_header(conn->sock, r, maxsize, uri);
    if (status != APR_SUCCESS) {
        conn->close++;
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: AJP: request failed to %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        if (status == AJP_EOVERFLOW)
            return HTTP_BAD_REQUEST;
        else {
            /*
             * This is only non fatal when the method is idempotent. In this
             * case we can dare to retry it with a different worker if we are
             * a balancer member.
             */
            if (is_idempotent(r) == METHOD_IDEMPOTENT) {
                return HTTP_SERVICE_UNAVAILABLE;
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* allocate an AJP message to store the data of the buckets */
    bufsiz = maxsize;
    status = ajp_alloc_data_msg(r->pool, &buff, &bufsiz, &msg);
    if (status != APR_SUCCESS) {
        /* We had a failure: Close connection to backend */
        conn->close++;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: ajp_alloc_data_msg failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* read the first bloc of data */
    input_brigade = apr_brigade_create(p, r->connection->bucket_alloc);
    tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    if (tenc && (strcasecmp(tenc, "chunked") == 0)) {
        /* The AJP protocol does not want body data yet */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: request is chunked");
    } else {
        /* Get client provided Content-Length header */
        content_length = get_content_length(r);
        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                maxsize - AJP_HEADER_SZ);

        if (status != APR_SUCCESS) {
            /* We had a failure: Close connection to backend */
            conn->close++;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: ap_get_brigade failed");
            apr_brigade_destroy(input_brigade);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* have something */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: APR_BUCKET_IS_EOS");
        }

        /* Try to send something */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: data to read (max %" APR_SIZE_T_FMT
                     " at %" APR_SIZE_T_FMT ")", bufsiz, msg->pos);

        status = apr_brigade_flatten(input_brigade, buff, &bufsiz);
        if (status != APR_SUCCESS) {
            /* We had a failure: Close connection to backend */
            conn->close++;
            apr_brigade_destroy(input_brigade);
            ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                         "proxy: apr_brigade_flatten");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_brigade_cleanup(input_brigade);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got %" APR_SIZE_T_FMT " bytes of data", bufsiz);
        if (bufsiz > 0) {
            status = ajp_send_data_msg(conn->sock, msg, bufsiz);
            if (status != APR_SUCCESS) {
                /* We had a failure: Close connection to backend */
                conn->close++;
                apr_brigade_destroy(input_brigade);
                ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                             "proxy: send failed to %pI (%s)",
                             conn->worker->cp->addr,
                             conn->worker->hostname);
                /*
                 * It is fatal when we failed to send a (part) of the request
                 * body.
                 */
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            conn->worker->s->transferred += bufsiz;
            send_body = 1;
        }
        else if (content_length > 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                         "proxy: read zero bytes, expecting"
                         " %" APR_OFF_T_FMT " bytes",
                         content_length);
            /*
             * We can only get here if the client closed the connection
             * to us without sending the body.
             * Now the connection is in the wrong state on the backend.
             * Sending an empty data msg doesn't help either as it does
             * not move this connection to the correct state on the backend
             * for later resusage by the next request again.
             * Close it to clean things up.
             */
            conn->close++;
            return HTTP_BAD_REQUEST;
        }
    }

    /* read the response */
    conn->data = NULL;
    status = ajp_read_header(conn->sock, r, maxsize,
                             (ajp_msg_t **)&(conn->data));
    if (status != APR_SUCCESS) {
        /* We had a failure: Close connection to backend */
        conn->close++;
        apr_brigade_destroy(input_brigade);
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: read response failed from %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        /*
         * This is only non fatal when we have not sent (parts) of a possible
         * request body so far (we do not store it and thus cannot sent it
         * again) and the method is idempotent. In this case we can dare to
         * retry it with a different worker if we are a balancer member.
         */
        if (!send_body && (is_idempotent(r) == METHOD_IDEMPOTENT)) {
            return HTTP_SERVICE_UNAVAILABLE;
        }
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* parse the reponse */
    result = ajp_parse_type(r, conn->data);
    output_brigade = apr_brigade_create(p, r->connection->bucket_alloc);

    /*
     * Prepare apr_pollfd_t struct for possible later check if there is currently
     * data available from the backend (do not flush response to client)
     * or not (flush response to client)
     */
    conn_poll = apr_pcalloc(p, sizeof(apr_pollfd_t));
    conn_poll->reqevents = APR_POLLIN;
    conn_poll->desc_type = APR_POLL_SOCKET;
    conn_poll->desc.s = conn->sock;

    bufsiz = maxsize;
    for (;;) {
        switch (result) {
            case CMD_AJP13_GET_BODY_CHUNK:
                if (havebody) {
                    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
                        /* This is the end */
                        bufsiz = 0;
                        havebody = 0;
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                                     "proxy: APR_BUCKET_IS_EOS");
                    } else {
                        status = ap_get_brigade(r->input_filters, input_brigade,
                                                AP_MODE_READBYTES,
                                                APR_BLOCK_READ,
                                                maxsize - AJP_HEADER_SZ);
                        if (status != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, status,
                                         r->server,
                                         "ap_get_brigade failed");
                            output_failed = 1;
                            break;
                        }
                        bufsiz = maxsize;
                        status = apr_brigade_flatten(input_brigade, buff,
                                                     &bufsiz);
                        apr_brigade_cleanup(input_brigade);
                        if (status != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, status,
                                         r->server,
                                         "apr_brigade_flatten failed");
                            output_failed = 1;
                            break;
                        }
                    }

                    ajp_msg_reset(msg);
                    /* will go in ajp_send_data_msg */
                    status = ajp_send_data_msg(conn->sock, msg, bufsiz);
                    if (status != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                                     "ajp_send_data_msg failed");
                        backend_failed = 1;
                        break;
                    }
                    conn->worker->s->transferred += bufsiz;
                } else {
                    /*
                     * something is wrong TC asks for more body but we are
                     * already at the end of the body data
                     */
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                 "ap_proxy_ajp_request error read after end");
                    backend_failed = 1;
                }
                break;
            case CMD_AJP13_SEND_HEADERS:
                /* AJP13_SEND_HEADERS: process them */
                status = ajp_parse_header(r, conf, conn->data);
                if (status != APR_SUCCESS) {
                    backend_failed = 1;
                }
                headers_sent = 1;
                break;
            case CMD_AJP13_SEND_BODY_CHUNK:
                /* AJP13_SEND_BODY_CHUNK: piece of data */
                status = ajp_parse_data(r, conn->data, &size, &send_body_chunk_buff);
                if (status == APR_SUCCESS) {
                    /* AJP13_SEND_BODY_CHUNK with zero length
                     * is explicit flush message
                     */
                    if (size == 0) {
                        if (headers_sent) {
                            e = apr_bucket_flush_create(r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(output_brigade, e);
                        }
                        else {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                 "Ignoring flush message received before headers");
                        }
                    }
                    else {
                        e = apr_bucket_transient_create(send_body_chunk_buff, size,
                                                    r->connection->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(output_brigade, e);

                        if ((conn->worker->flush_packets == flush_on) ||
                            ((conn->worker->flush_packets == flush_auto) &&
                            (apr_poll(conn_poll, 1, &conn_poll_fd,
                                      conn->worker->flush_wait)
                                        == APR_TIMEUP) ) ) {
                            e = apr_bucket_flush_create(r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(output_brigade, e);
                        }
                        apr_brigade_length(output_brigade, 0, &bb_len);
                        if (bb_len != -1)
                            conn->worker->s->read += bb_len;
                    }
                    if (ap_pass_brigade(r->output_filters,
                                        output_brigade) != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "proxy: error processing body");
                        output_failed = 1;
                    }
                    data_sent = 1;
                    apr_brigade_cleanup(output_brigade);
                }
                else {
                    backend_failed = 1;
                }
                break;
            case CMD_AJP13_END_RESPONSE:
                e = apr_bucket_eos_create(r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(output_brigade, e);
                if (ap_pass_brigade(r->output_filters,
                                    output_brigade) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "proxy: error processing end");
                    output_failed = 1;
                }
                /* XXX: what about flush here? See mod_jk */
                data_sent = 1;
                break;
            default:
                backend_failed = 1;
                break;
        }

        /*
         * If connection has been aborted by client: Stop working.
         * Nevertheless, we regard our operation so far as a success:
         * So reset output_failed to 0 and set result to CMD_AJP13_END_RESPONSE
         * But: Close this connection to the backend.
         */
        if (r->connection->aborted) {
            conn->close++;
            output_failed = 0;
            result = CMD_AJP13_END_RESPONSE;
        }

        /*
         * We either have finished successfully or we failed.
         * So bail out
         */
        if ((result == CMD_AJP13_END_RESPONSE) || backend_failed
            || output_failed)
            break;

        /* read the response */
        status = ajp_read_header(conn->sock, r, maxsize,
                                 (ajp_msg_t **)&(conn->data));
        if (status != APR_SUCCESS) {
            backend_failed = 1;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                         "ajp_read_header failed");
            break;
        }
        result = ajp_parse_type(r, conn->data);
    }
    apr_brigade_destroy(input_brigade);

    /*
     * Clear output_brigade to remove possible buckets that remained there
     * after an error.
     */
    apr_brigade_cleanup(output_brigade);

    if (backend_failed || output_failed) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: Processing of request failed backend: %i, "
                     "output: %i", backend_failed, output_failed);
        /* We had a failure: Close connection to backend */
        conn->close++;
        /* Return DONE to avoid error messages being added to the stream */
        if (data_sent) {
            rv = DONE;
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got response from %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        rv = OK;
    }

    if (backend_failed) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: dialog to %pI (%s) failed",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        /*
         * If we already send data, signal a broken backend connection
         * upwards in the chain.
         */
        if (data_sent) {
            ap_proxy_backend_broke(r, output_brigade);
        } else
            rv = HTTP_SERVICE_UNAVAILABLE;
    }

    /*
     * Ensure that we sent an EOS bucket thru the filter chain, if we already
     * have sent some data. Maybe ap_proxy_backend_broke was called and added
     * one to the brigade already (no longer making it empty). So we should
     * not do this in this case.
     */
    if (data_sent && !r->eos_sent && APR_BRIGADE_EMPTY(output_brigade)) {
        e = apr_bucket_eos_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(output_brigade, e);
    }

    /* If we have added something to the brigade above, sent it */
    if (!APR_BRIGADE_EMPTY(output_brigade))
        ap_pass_brigade(r->output_filters, output_brigade);

    apr_brigade_destroy(output_brigade);

    return rv;
}

/*
 * This handles ajp:// URLs
 */
static int proxy_ajp_handler(request_rec *r, proxy_worker *worker,
                             proxy_server_conf *conf,
                             char *url, const char *proxyname,
                             apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    conn_rec *origin = NULL;
    proxy_conn_rec *backend = NULL;
    const char *scheme = "AJP";
    int retry;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    /*
     * Note: Memory pool allocation.
     * A downstream keepalive connection is always connected to the existence
     * (or not) of an upstream keepalive connection. If this is not done then
     * load balancing against multiple backend servers breaks (one backend
     * server ends up taking 100% of the load), and the risk is run of
     * downstream keepalive connections being kept open unnecessarily. This
     * keeps webservers busy and ties up resources.
     *
     * As a result, we allocate all sockets out of the upstream connection
     * pool, and when we want to reuse a socket, we check first whether the
     * connection ID of the current upstream connection is the same as that
     * of the connection when the socket was opened.
     */
    apr_pool_t *p = r->connection->pool;
    apr_uri_t *uri = apr_palloc(r->connection->pool, sizeof(*uri));


    if (strncasecmp(url, "ajp:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: AJP: declining URL %s", url);
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: AJP: serving URL %s", url);

    /* create space for state information */
    if (!backend) {
        status = ap_proxy_acquire_connection(scheme, &backend, worker,
                                             r->server);
        if (status != OK) {
            if (backend) {
                backend->close_on_recycle = 1;
                ap_proxy_release_connection(scheme, backend, r->server);
            }
            return status;
        }
    }

    backend->is_ssl = 0;
    backend->close_on_recycle = 0;

    retry = 0;
    while (retry < 2) {
        char *locurl = url;
        /* Step One: Determine Who To Connect To */
        status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                               uri, &locurl, proxyname, proxyport,
                                               server_portstr,
                                               sizeof(server_portstr));

        if (status != OK)
            break;

        /* Step Two: Make the Connection */
        if (ap_proxy_connect_backend(scheme, backend, worker, r->server)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: AJP: failed to make connection to backend: %s",
                         backend->hostname);
            status = HTTP_SERVICE_UNAVAILABLE;
            break;
        }

        /* Handle CPING/CPONG */
        if (worker->ping_timeout_set) {
            status = ajp_handle_cping_cpong(backend->sock, r,
                                            worker->ping_timeout);
            /*
             * In case the CPING / CPONG failed for the first time we might be
             * just out of luck and got a faulty backend connection, but the
             * backend might be healthy nevertheless. So ensure that the backend
             * TCP connection gets closed and try it once again.
             */
            if (status != APR_SUCCESS) {
                backend->close++;
                ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                             "proxy: AJP: cping/cpong failed to %pI (%s)",
                             worker->cp->addr,
                             worker->hostname);
                status = HTTP_SERVICE_UNAVAILABLE;
                retry++;
                continue;
            }
        }
        /* Step Three: Process the Request */
        status = ap_proxy_ajp_request(p, r, backend, origin, dconf, uri, locurl,
                                      server_portstr);
        break;
    }

    /* Do not close the socket */
    ap_proxy_release_connection(scheme, backend, r->server);
    return status;
}

static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_ajp_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_ajp_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_ajp_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    ap_proxy_http_register_hook /* register hooks */
};

