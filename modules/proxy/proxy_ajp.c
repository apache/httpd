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
int ap_proxy_ajp_canon(request_rec *r, char *url)
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
 
static int ap_proxy_ajp_request(apr_pool_t *p, request_rec *r,
                                proxy_conn_rec *conn, 
                                conn_rec *origin, 
                                proxy_server_conf *conf,
                                apr_uri_t *uri,
                                char *url, char *server_portstr)
{
    apr_status_t status;
    int result;
    apr_bucket_brigade *input_brigade;

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

    /* read the first bloc of data */
    input_brigade = apr_brigade_create(p, r->connection->bucket_alloc);
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

    if (1) { /* XXXX only when something to send ? */
        ajp_msg_t *msg;
        apr_size_t bufsiz;
        char *buff;
        status = ajp_alloc_data_msg(r, &buff, &bufsiz, &msg);
        if (status != APR_SUCCESS) {
            return status;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: data to read (max %d at %08x)", bufsiz, buff);

        /* XXXX calls apr_brigade_flatten... */
        status = apr_brigade_flatten(input_brigade, buff, &bufsiz);
        if (status != APR_SUCCESS) {
             ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: apr_brigade_flatten");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got %d byte of data", bufsiz);
        if (bufsiz > 0) {
            status = ajp_send_data_msg(conn->sock, r, msg, bufsiz);
            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                             "proxy: request failed to %pI (%s)",
                             conn->worker->cp->addr,
                             conn->worker->hostname);
                return HTTP_SERVICE_UNAVAILABLE;
            }
        }
    }

    /* read the response */
    status = ajp_read_header(conn->sock, r,
                             (ajp_msg_t **)&(conn->data));
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: request failed to %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* parse the reponse */
    result = ajp_parse_type(r, conn->data);
    if (result == CMD_AJP13_SEND_HEADERS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: got response from %pI (%s)",
                     conn->worker->cp->addr,
                     conn->worker->hostname);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* XXXX: need logic to send the rest of the data */
/*
    status = ajp_send_data(p_conn->sock,r);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
                     "proxy: request failed to %pI (%s)",
                     p_conn->addr, p_conn->name);
        return status;
    }
 */

    return OK;
}

/*
 * Process the AJP response, data already contains the first part of it.
 */
static int ap_proxy_ajp_process_response(apr_pool_t * p, request_rec *r,
                                         conn_rec *origin,
                                         proxy_conn_rec *backend,
                                         proxy_server_conf *conf,
                                         char *server_portstr) 
{
    conn_rec *c = r->connection;
    apr_bucket *e;
    apr_bucket_brigade *bb;
    int type;
    apr_status_t status;

    bb = apr_brigade_create(p, c->bucket_alloc);
    
    type = ajp_parse_type(r, backend->data);
    status = APR_SUCCESS;
    while (type != CMD_AJP13_END_RESPONSE) {
        if (type == CMD_AJP13_SEND_HEADERS) {
            /* AJP13_SEND_HEADERS: process them */
            status = ajp_parse_header(r, backend->data); 
            if (status != APR_SUCCESS) {
                break;
            }
        } 
        else if  (type == CMD_AJP13_SEND_BODY_CHUNK) {
            /* AJP13_SEND_BODY_CHUNK: piece of data */
            apr_uint16_t size;
            char *buff;

            status = ajp_parse_data(r, backend->data, &size, &buff);
            e = apr_bucket_transient_create(buff, size, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        } 
        else {
            status = APR_EGENERAL;
            break;
        }
        /* Read the next message */
        status = ajp_read_header(backend->sock, r,
                                 (ajp_msg_t **)&(backend->data));
        if (status != APR_SUCCESS) {
            break;
        }
        type = ajp_parse_type(r, backend->data);
    }
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error reading headers from remote "
                      "server %s:%d",
                      backend->worker->cp->addr,
                      backend->worker->hostname);
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    }

    /* The page is ready give it to the rest of the logic */
    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "proxy: error processing body");
        return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                             "Error reading from remote server");
    } 

    return OK;
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
int ap_proxy_ajp_handler(request_rec *r, proxy_worker *worker,
                         proxy_server_conf *conf,
                         char *url, const char *proxyname, 
                         apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    conn_rec *origin = NULL;
    proxy_conn_rec *backend = NULL;
    int is_ssl = 0;
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
    conn_rec *c = r->connection;
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
    status = ap_proxy_determine_connection(p, r, conf, worker, backend, c->pool,
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
   
   
    /* Step Four: Send the Request */
    status = ap_proxy_ajp_request(p, r, backend, origin, conf, uri, url,
                                  server_portstr);
    if (status != OK)
        goto cleanup;

    /* Step Five: Receive the Response */
    status = ap_proxy_ajp_process_response(p, r, origin, backend,
                                           conf, server_portstr);
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
    proxy_hook_scheme_handler(ap_proxy_ajp_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(ap_proxy_ajp_canon, NULL, NULL, APR_HOOK_FIRST);
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

