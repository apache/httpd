/* Copyright 1999-2004 The Apache Software Foundation
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

/* AJP routines for Apache proxy */

#include "mod_proxy.h"
#include "ajp.h"

module AP_MODULE_DECLARE_DATA proxy_ajp_module;
/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
static int proxy_ajp_canon(request_rec *r, char *url)
{
    char *host, *path, *search, sport[7];
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
             "proxy: AJP: canonicalising URL %s", url);

    /* ap_port_of_scheme() */
    if (strncasecmp(url, "ajp:", 4) == 0) {
        url += 4;
        scheme = "ajp";
    }    
    /* XXX This is probably faulty */ 
    else if (strncasecmp(url, "ajps:", 5) == 0) {
        url += 5;
        scheme = "ajps";
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_port_of_scheme(scheme);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: AJP: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }

    /* now parse path/search args, according to rfc1738 */
    /* N.B. if this isn't a true proxy request, then the URL _path_
     * has already been decoded.  True proxy requests have r->uri
     * == r->unparsed_uri, and no others have that property.
     */
    if (r->uri == r->unparsed_uri) {
        search = strchr(url, '?');
        if (search != NULL)
            *(search++) = '\0';
    }
    else
        search = r->args;

    /* process path */
    path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, r->proxyreq);
    if (path == NULL)
        return HTTP_BAD_REQUEST;

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
        sport[0] = '\0';

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport, 
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}

/*
 * process the request and write the respnse.
 */ 
static int ap_proxy_ajp_request(apr_pool_t *p, request_rec *r,
                                proxy_conn_rec *conn, 
                                conn_rec *origin, 
                                proxy_server_conf *conf,
                                apr_uri_t *uri,
                                char *url, char *server_portstr)
{
    apr_status_t status;
    int result;
    apr_bucket *e;
    apr_bucket_brigade *input_brigade;
    apr_bucket_brigade *output_brigade;
    ajp_msg_t *msg;
    apr_size_t bufsiz;
    char *buff;
    apr_uint16_t size;
    const char *tenc;
    int havebody=1;
    int isok=1;
    apr_off_t bb_len;

    /*
     * Send the AJP request to the remote server
     */

    /* send request headers */
    status = ajp_send_header(conn->sock, r);
    if (status != APR_SUCCESS) {
        conn->close++;
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: AJP: request failed to %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* allocate an AJP message to store the data of the buckets */
    status = ajp_alloc_data_msg(r->pool, &buff, &bufsiz, &msg);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: ajp_alloc_data_msg failed");
        return status;
    }
    /* read the first bloc of data */
    input_brigade = apr_brigade_create(p, r->connection->bucket_alloc);
    tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    if (tenc && strcasecmp(tenc, "chunked")==0) {
         /* The AJP protocol does not want body data yet */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: request is chunked");
    } else {
        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                AJP13_MAX_SEND_BODY_SZ);
 
        if (status != APR_SUCCESS) {
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
                apr_brigade_destroy(input_brigade);
                ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                             "proxy: send failed to %pI (%s)",
                             conn->worker->cp->addr,
                             conn->worker->hostname);
                return HTTP_SERVICE_UNAVAILABLE;
            }
            conn->worker->s->transfered += bufsiz;
        }
    }

    /* read the response */
    status = ajp_read_header(conn->sock, r,
                             (ajp_msg_t **)&(conn->data));
    if (status != APR_SUCCESS) {
        apr_brigade_destroy(input_brigade);
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: read response failed from %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    /* parse the reponse */
    result = ajp_parse_type(r, conn->data);
    output_brigade = apr_brigade_create(p, r->connection->bucket_alloc);
    
    bufsiz = AJP13_MAX_SEND_BODY_SZ;
    while (isok) {
        switch (result) {
            case CMD_AJP13_GET_BODY_CHUNK:
                if (havebody) {
                    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
                        /* That is the end */
                        bufsiz = 0;
                        havebody = 0;
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                                     "proxy: APR_BUCKET_IS_EOS");
                    } else {
                        status = ap_get_brigade(r->input_filters, input_brigade,
                                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                                AJP13_MAX_SEND_BODY_SZ);
                        if (status != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                                         "ap_get_brigade failed");
                            break;
                        }
                        bufsiz = AJP13_MAX_SEND_BODY_SZ;
                        status = apr_brigade_flatten(input_brigade, buff, &bufsiz);
                        apr_brigade_cleanup(input_brigade);
                        if (status != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                                         "apr_brigade_flatten failed");
                            break;
                        }
                    }

                    ajp_msg_reset(msg); /* will go in ajp_send_data_msg */
                    status = ajp_send_data_msg(conn->sock, msg, bufsiz);
                    if (status != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                                     "ajp_send_data_msg failed");
                        break;
                    }
                    conn->worker->s->transfered += bufsiz;
                } else {
                    /* something is wrong TC asks for more body but we are
                     * already at the end of the body data
                     */
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "ap_proxy_ajp_request error read after end");
                    isok = 0;
                }
                break;
            case CMD_AJP13_SEND_HEADERS:
                /* AJP13_SEND_HEADERS: process them */
                status = ajp_parse_header(r, conn->data);
                if (status != APR_SUCCESS) {
                    isok=0;
                }
                break;
            case CMD_AJP13_SEND_BODY_CHUNK:
                /* AJP13_SEND_BODY_CHUNK: piece of data */
                status = ajp_parse_data(r, conn->data, &size, &buff);
                e = apr_bucket_transient_create(buff, size,
                                                r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(output_brigade, e);
                if (status != APR_SUCCESS)
                    isok = 0;
                break;
            case CMD_AJP13_END_RESPONSE:
                e = apr_bucket_eos_create(r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(output_brigade, e);
                if (ap_pass_brigade(r->output_filters, output_brigade) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "proxy: error processing body");
                    isok=0;
                }
                break;
            default:
                isok=0;
                break;
        }
        if (!isok)
            break;
        
        if (result == CMD_AJP13_END_RESPONSE)
            break;

        /* read the response */
        status = ajp_read_header(conn->sock, r,
                                 (ajp_msg_t **)&(conn->data));
        if (status != APR_SUCCESS) {
            isok=0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                         "ajp_read_header failed");
            break;
        }
    	result = ajp_parse_type(r, conn->data);
    }
    apr_brigade_destroy(input_brigade);

    apr_brigade_length(output_brigade, 0, &bb_len);
    if (bb_len != -1)
        conn->worker->s->readed += bb_len;

    if (!isok)
        apr_brigade_destroy(output_brigade);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: send body failed to %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Nice we have answer to send to the client */
    if (result == CMD_AJP13_END_RESPONSE && isok) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got response from %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                 "proxy: got bad response (%d) from %pI (%s)",
                 result,
                 conn->worker->cp->addr,
                 conn->worker->hostname);

    return HTTP_SERVICE_UNAVAILABLE;
}

/*
 * This handles http:// URLs, and other URLs using a remote proxy over http
 * If proxyhost is NULL, then contact the server directly, otherwise
 * go via the proxy.
 * Note that if a proxy is used, then URLs other than http: can be accessed,
 * also, if we have trouble which is clearly specific to the proxy, then
 * we return DECLINED so that we can try another proxy. (Or the direct
 * route.)
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

    /* Note: Memory pool allocation.
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
#if 0
    conn_rec *c = r->connection;
#endif
    apr_uri_t *uri = apr_palloc(r->connection->pool, sizeof(*uri));

    
    if (strncasecmp(url, "ajp:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: AJP: declining URL %s", url);
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
             "proxy: AJP: serving URL %s", url);
    

    /* only use stored info for top-level pages. Sub requests don't share 
     * in keepalives
     */
#if 0
    if (!r->main) {
        backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config,
                                                      &proxy_ajp_module);
    }
#endif
    /* create space for state information */
    if (!backend) {
        status = ap_proxy_acquire_connection(scheme, &backend, worker, r->server);
        if (status != OK) {
            if (backend) {
                backend->close_on_recycle = 1;
                ap_proxy_release_connection(scheme, backend, r->server);
            }
            return status;
        }
#if 0
        if (!r->main) {
            ap_set_module_config(c->conn_config, &proxy_ajp_module, backend);
        }
#endif
    }

    backend->is_ssl = 0;
    backend->close_on_recycle = 0;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));

    if (status != OK)
        goto cleanup;
    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(scheme, backend, worker, r->server)) {
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }
#if 0
    /* XXX: we don't need to create the bound client connection */

    /* Step Three: Create conn_rec */
    if (!backend->connection) {
        status = ap_proxy_connection_create(scheme, backend, c, r->server);
        if (status != OK)
            goto cleanup;
    }
#endif
   
   
    /* Step Four: Process the Request */
    status = ap_proxy_ajp_request(p, r, backend, origin, conf, uri, url,
                                  server_portstr);
    if (status != OK)
        goto cleanup;

cleanup:
#if 0
    /* Clear the module config */
    ap_set_module_config(c->conn_config, &proxy_ajp_module, NULL);
#endif
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
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    ap_proxy_http_register_hook/* register hooks */
};

