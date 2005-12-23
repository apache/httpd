/* Copyright 2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

#include "mod_proxy.h"

module AP_MODULE_DECLARE_DATA proxy_fcgi_module;

/*
 * Canonicalise http-like URLs.
 * scheme is the scheme for the URL
 * url is the URL starting with the first '/'
 * def_port is the default port for this scheme.
 */
static int proxy_fcgi_canon(request_rec *r, char *url)
{
    char *host, *path, *search, sport[7];
    const char *err;
    const char* scheme;
    apr_port_t port = 8000;

    if (strncasecmp(url, "fcgi-", 5) == 0) {
        url += 5;
    }
    else {
        return DECLINED;
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: canonicalising URL %s", url);

    if (strncmp(url, "tcp://", 6) == 0) {
        url += 4;
        
        scheme = "fcgi-tcp://";

        err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "error parsing URL %s: %s",
                          url, err);
            return HTTP_BAD_REQUEST;
        }
        
        apr_snprintf(sport, sizeof(sport), ":%d", port);
        
        if (ap_strchr_c(host, ':')) {
            /* if literal IPv6 address */
            host = apr_pstrcat(r->pool, "[", host, "]", NULL);
        }
        
        r->filename = apr_pstrcat(r->pool, "proxy:", scheme, host, sport, "/", NULL);
    }
    else if (strncmp(url, "local://", 8) == 0) {
        url += 6;
        scheme = "fcgi-local:";
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: FCGI: Local FastCGI not supported.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
             "proxy: FCGI: mallformed destination: %s", url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

/*
 * process the request and write the response.
 */
static int fcgi_do_request(apr_pool_t *p, request_rec *r,
                            proxy_conn_rec *conn,
                            conn_rec *origin,
                            proxy_dir_conf *conf,
                            apr_uri_t *uri,
                            char *url, char *server_portstr)
{
    /* TODO: Talk to a FastCGI Backend */
    return HTTP_SERVICE_UNAVAILABLE;
}

/*
 * This handles fcgi:(type):(dest) URLs
 */
static int proxy_fcgi_handler(request_rec *r, proxy_worker *worker,
                                 proxy_server_conf *conf,
                                 char *url, const char *proxyname,
                                 apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    conn_rec *origin = NULL;
    proxy_conn_rec *backend = NULL;
    const char *scheme;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    apr_pool_t *p = r->pool;

    apr_uri_t *uri = apr_palloc(r->pool, sizeof(*uri));


    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                 "proxy: FCGI: url: %s proxyname: %s proxyport: %d", url, proxyname, proxyport);

    if (strncasecmp(url, "fcgi-", 5) == 0) {
        url += 5;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: FCGI: declining URL %s", url);
        return DECLINED;
    }
    
    if (strncmp(url, "tcp://", 6) == 0) {
        scheme = "FCGI_TCP";
    }
    else if (strncmp(url, "local://", 8) == 0) {
        scheme = "FCGI_LOCAL";
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: FCGI: local FastCGI not supported.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
             "proxy: FCGI: mallformed destination: %s", url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: FCGI: serving URL %s via %s", url, scheme);

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

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));

    if (status != OK) {
        goto cleanup;
    }

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(scheme, backend, worker, r->server)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: FCGI: failed to make connection to backend: %s",
                     backend->hostname);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Process the Request */
    status = fcgi_do_request(p, r, backend, origin, dconf, uri, url,
                             server_portstr);

cleanup:
    /* Do not close the socket */
    ap_proxy_release_connection(scheme, backend, r->server);
    return status;
}

static void register_hooks(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_fcgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_fcgi_canon, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA proxy_fcgi_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};

