/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <nghttp2/nghttp2.h>

#include <httpd.h>
#include <mod_proxy.h>


#include "mod_proxy_http2.h"
#include "h2_request.h"
#include "h2_util.h"
#include "h2_version.h"
#include "h2_proxy_session.h"

static void register_hook(apr_pool_t *p);

AP_DECLARE_MODULE(proxy_http2) = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    register_hook      /* register hooks */
};

static int h2_proxy_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *init_key = "mod_proxy_http2_init_counter";
    nghttp2_info *ngh2;
    apr_status_t status = APR_SUCCESS;
    (void)plog;(void)ptemp;
    
    apr_pool_userdata_get(&data, init_key, s->process->pool);
    if ( data == NULL ) {
        apr_pool_userdata_set((const void *)1, init_key,
                              apr_pool_cleanup_null, s->process->pool);
        return APR_SUCCESS;
    }
    
    ngh2 = nghttp2_version(0);
    ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO()
                 "mod_proxy_http2 (v%s, nghttp2 %s), initializing...",
                 MOD_HTTP2_VERSION, ngh2? ngh2->version_str : "unknown");
    
    return status;
}

/**
 * canonicalize the url into the request, if it is meant for us.
 * slightly modified copy from mod_http
 */
static int proxy_http2_canon(request_rec *r, char *url)
{
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    const char *scheme;
    const char *http_scheme;
    apr_port_t port, def_port;

    /* ap_port_of_scheme() */
    if (ap_casecmpstrn(url, "h2c:", 4) == 0) {
        url += 4;
        scheme = "h2c";
        http_scheme = "http";
    }
    else if (ap_casecmpstrn(url, "h2:", 3) == 0) {
        url += 3;
        scheme = "h2";
        http_scheme = "https";
    }
    else {
        return DECLINED;
    }
    port = def_port = ap_proxy_port_of_scheme(http_scheme);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "HTTP2: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse path/search args, according to rfc1738:
     * process the path.
     *
     * In a reverse proxy, our URL has been processed, so canonicalise
     * unless proxy-nocanon is set to say it's raw
     * In a forward proxy, we have and MUST NOT MANGLE the original.
     */
    switch (r->proxyreq) {
    default: /* wtf are we doing here? */
    case PROXYREQ_REVERSE:
        if (apr_table_get(r->notes, "proxy-nocanon")) {
            path = url;   /* this is the raw path */
        }
        else {
            path = ap_proxy_canonenc(r->pool, url, strlen(url),
                                     enc_path, 0, r->proxyreq);
            search = r->args;
        }
        break;
    case PROXYREQ_PROXY:
        path = url;
        break;
    }

    if (path == NULL) {
        return HTTP_BAD_REQUEST;
    }

    if (port != def_port) {
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    }
    else {
        sport[0] = '\0';
    }

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport,
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}

static apr_status_t proxy_http2_cleanup(const char *scheme, request_rec *r,
                                        proxy_conn_rec *backend)
{
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "cleanup, releasing connection");
    ap_proxy_release_connection(scheme, backend, r->server);
    return OK;
}

static
int proxy_http2_process_stream(apr_pool_t *p, const char *url, request_rec *r,
                               proxy_conn_rec **pp_conn, proxy_worker *worker,
                               proxy_server_conf *conf, char *server_portstr,
                               int flushall)
{
    int rv = APR_ENOTIMPL;
    proxy_conn_rec *p_conn = *pp_conn;
    h2_proxy_session *session;
    h2_proxy_stream *stream;
    
    session = h2_proxy_session_setup(r, *pp_conn, conf);
    if (!session) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, p_conn->connection, 
                      "session unavailable");
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    /* TODO
     * - enter http2 client processing loop:
     *   - send any input in datasource callback from r->input_filters
     *   - await response HEADERs
     *   - send any DATA to r->output_filters
     * - on stream close, check for missing response
     * - on certain errors, mark connection for close
     */ 
    rv = h2_proxy_session_open_stream(session, url, r, &stream);
    if (rv == OK) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, 
                      "process stream(%d): %s %s%s, original: %s", 
                      stream->id, stream->req->method, 
                      stream->req->authority, stream->req->path, 
                      r->the_request);
        rv = h2_proxy_stream_process(stream);
    }
    
    if (rv != OK) {
        conn_rec *c = r->connection;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                      "pass request body failed to %pI (%s) from %s (%s)",
                      p_conn->addr, p_conn->hostname ? p_conn->hostname: "",
                      c->client_ip, c->remote_host ? c->remote_host: "");
    }

    return rv;
}

static int proxy_http2_handler(request_rec *r, 
                               proxy_worker *worker,
                               proxy_server_conf *conf,
                               char *url, 
                               const char *proxyname,
                               apr_port_t proxyport)
{
    const char *proxy_function;
    proxy_conn_rec *backend;
    char *locurl = url, *u;
    apr_size_t slen;
    int is_ssl = 0;
    int flushall = 0;
    int status;
    char server_portstr[32];
    conn_rec *c = r->connection;
    apr_pool_t *p = r->pool;
    apr_uri_t *uri = apr_palloc(p, sizeof(*uri));
    const char *ssl_hostname;

    /* find the scheme */
    if ((url[0] != 'h' && url[0] != 'H') || url[1] != '2') {
       return DECLINED;
    }
    u = strchr(url, ':');
    if (u == NULL || u[1] != '/' || u[2] != '/' || u[3] == '\0') {
       return DECLINED;
    }
    slen = (u - url);
    switch(slen) {
        case 2:
            proxy_function = "H2";
            is_ssl = 1;
            break;
        case 3:
            if (url[2] != 'c' && url[2] != 'C') {
                return DECLINED;
            }
            proxy_function = "H2C";
            break;
        default:
            return DECLINED;
    }

    if (apr_table_get(r->subprocess_env, "proxy-flushall")) {
        flushall = 1;
    }

    /* scheme says, this is for us. */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "H2: serving URL %s", url);

    /* Get a proxy_conn_rec from the worker, might be a new one, might
     * be one still open from another request, or it might fail if the
     * worker is stopped or in error. */
    if ((status = ap_proxy_acquire_connection(proxy_function, &backend,
                                              worker, r->server)) != OK) {
        goto cleanup;
    }

    backend->is_ssl = is_ssl;
    if (is_ssl) {
        /* If there is still some data on an existing ssl connection, now
         * would be a good timne to get rid of it. */
        ap_proxy_ssl_connection_cleanup(backend, r);
    }

    do { /* while (0): break out */
        conn_rec *backconn;
        
        /* Step One: Determine the URL to connect to (might be a proxy),
         * initialize the backend accordingly and determine the server 
         * port string we can expect in responses. */
        if ((status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                                    uri, &locurl, proxyname,
                                                    proxyport, server_portstr,
                                                    sizeof(server_portstr))) != OK) {
            break;
        }
        
        if (!ssl_hostname && backend->ssl_hostname) {
            /* When reusing connections and finding sockets closed, the proxy
             * framework loses the ssl_hostname setting. This is vital for us,
             * so we save it once it is known. */
            ssl_hostname = apr_pstrdup(r->pool, backend->ssl_hostname);
        }
        
        /* Step Two: Make the Connection (or check that an already existing
         * socket is still usable). On success, we have a socket connected to
         * backend->hostname. */
        if (ap_proxy_connect_backend(proxy_function, backend, worker, r->server)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                          "H2: failed to make connection to backend: %s",
                          backend->hostname);
            status = HTTP_SERVICE_UNAVAILABLE;
            break;
        }
        
        /* Step Three: Create conn_rec for the socket we have open now. */
        backconn = backend->connection;
        if (!backconn) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO()
                          "setup new connection: is_ssl=%d %s %s %s, was %s", 
                          backend->is_ssl, 
                          backend->ssl_hostname, r->hostname, backend->hostname,
                          ssl_hostname);
            if ((status = ap_proxy_connection_create(proxy_function, backend,
                                                     c, r->server)) != OK) {
                break;
            }
            backconn = backend->connection;
            
            /*
             * On SSL connections set a note on the connection what CN is
             * requested, such that mod_ssl can check if it is requested to do
             * so.
             */
            if (ssl_hostname) {
                apr_table_setn(backend->connection->notes,
                               "proxy-request-hostname", ssl_hostname);
            }
            
            if (backend->is_ssl) {
                apr_table_setn(backend->connection->notes,
                               "proxy-request-alpn-protos", "h2");
            }
        }

        /* Step Four: Send the Request in a new HTTP/2 stream and
         * loop until we got the response or encounter errors.
         */
        if ((status = proxy_http2_process_stream(p, url, r, &backend, worker,
                                                 conf, server_portstr, 
                                                 flushall)) != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO()
                          "H2: failed to process request: %s",
                          r->the_request);
            backend->close = 1;
            if (backend) {
                proxy_run_detach_backend(r, backend);
            }
        }
    } while (0);

    /* clean up before return */
cleanup:
    if (backend) {
        if (status != OK) {
            backend->close = 1;
        }
        proxy_http2_cleanup(proxy_function, r, backend);
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, status, r, "leaving handler");
    return status;
}

static void register_hook(apr_pool_t *p)
{
    ap_hook_post_config(h2_proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    proxy_hook_scheme_handler(proxy_http2_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_http2_canon, NULL, NULL, APR_HOOK_FIRST);
}

