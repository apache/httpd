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
    char *host, sport[7];
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
        
        r->filename = apr_pstrcat(r->pool, "proxy:", scheme, host, sport, "/",
                                  NULL);
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

#define FCGI_VERSION 1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} fcgi_header;

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
#define FCGI_KEEP_CONN  1

/*
 * Values for role component of FCGI_BeginRequestBody
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} fcgi_begin_request_body;

/*
 * Initialize a fastcgi_header H of type TYPE with id ID.
 *
 * Sets the content length and padding length to 0, the caller should
 * reset them to more appropriate values later if needed.
 */
static void fill_in_header(fcgi_header *h, int type, int id)
{
    h->version = FCGI_VERSION;

    h->type = type;

    h->requestIdB1 = ((id >> 8) & 0xff);
    h->requestIdB0 = ((id) & 0xff); 

    h->contentLengthB1 = 0;
    h->contentLengthB0 = 0;
    h->paddingLength = 0;
}

static apr_status_t send_begin_request(proxy_conn_rec *conn, int request_id)
{
    struct iovec vec[2];
    fcgi_header header;
    fcgi_begin_request_body brb;
    apr_size_t len;

    fill_in_header(&header, FCGI_BEGIN_REQUEST, request_id);

    header.contentLengthB1 = ((sizeof(brb) >> 8) & 0xff);
    header.contentLengthB0 = ((sizeof(brb)) & 0xff); 

    brb.roleB1 = ((FCGI_RESPONDER >> 8) & 0xff);
    brb.roleB0 = ((FCGI_RESPONDER) & 0xff); 
    brb.flags = FCGI_KEEP_CONN;

    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);
    vec[1].iov_base = &brb;
    vec[1].iov_len = sizeof(brb);

    return apr_socket_sendv(conn->sock, vec, 2, &len);
}

static apr_status_t send_environment(proxy_conn_rec *conn, request_rec *r, 
                                     int request_id)
{
    const apr_array_header_t *envarr;
    const apr_table_entry_t *elts;
    struct iovec vec[2];
    fcgi_header header;
    apr_size_t bodylen;
    char *body, *itr;
    apr_status_t rv;
    apr_size_t len;
    int i;

    fill_in_header(&header, FCGI_PARAMS, request_id);

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /* XXX are there any FastCGI specific env vars we need to send? */

    /* XXX What if there is over 64k worth of data in the env? */
    bodylen = 0;

    /* XXX mod_cgi/mod_cgid use ap_create_environment here, which fills in
     *     the TZ value specially.  We could use that, but it would mean
     *     parsing the key/value pairs back OUT of the allocated env array,
     *     not to mention allocating a totally useless array in the first
     *     place, which would suck. */

    envarr = apr_table_elts(r->subprocess_env);

    elts = (const apr_table_entry_t *) envarr->elts;

    for (i = 0; i < envarr->nelts; ++i) {
        apr_size_t keylen, vallen;

        if (! elts[i].key) {
            continue;
        }

        keylen = strlen(elts[i].key);

        if (keylen >> 7 == 0) {
            bodylen += 1;
        }
        else {
            bodylen += 4;
        }

        bodylen += keylen;

        vallen = strlen(elts[i].val);

        if (vallen >> 7 == 0) {
            bodylen += 1;
        }
        else {
            bodylen += 4;
        }

        bodylen += vallen;
    }

    body = apr_pcalloc(r->pool, bodylen);

    itr = body;

    for (i = 0; i < envarr->nelts; ++i) {
        apr_size_t keylen, vallen;
       
        if (! elts[i].key) {
            continue;
        }

        keylen = strlen(elts[i].key);

        if (keylen >> 7 == 0) {
            itr[0] = keylen & 0xff;
            itr += 1;
        }
        else {
            itr[0] = ((keylen >> 24) & 0xff) | 0x80;
            itr[1] = ((keylen >> 16) & 0xff);
            itr[2] = ((keylen >> 8) & 0xff);
            itr[3] = ((keylen) & 0xff);
            itr += 4;
        }

        vallen = strlen(elts[i].val);

        if (vallen >> 7 == 0) {
            itr[0] = vallen & 0xff;
            itr += 1;
        }
        else {
            itr[0] = ((vallen >> 24) & 0xff) | 0x80;
            itr[1] = ((vallen >> 16) & 0xff);
            itr[2] = ((vallen >> 8) & 0xff);
            itr[3] = ((vallen) & 0xff);
            itr += 4;
        }

        memcpy(itr, elts[i].key, keylen);
        itr += keylen;

        memcpy(itr, elts[i].val, vallen);
        itr += vallen;
    }

    /* First we send the actual env... */
    header.contentLengthB1 = ((bodylen >> 8) & 0xff);
    header.contentLengthB0 = ((bodylen) & 0xff); 
    header.paddingLength = 0;

    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);
    vec[1].iov_base = body;
    vec[1].iov_len = bodylen;

    rv = apr_socket_sendv(conn->sock, vec, 2, &len);
    if (rv) {
        return rv;
    }

    /* Then, an empty record to signify the end of the stream. */
    header.contentLengthB1 = 0;
    header.contentLengthB0 = 0;
    header.paddingLength = 0;

    vec[0].iov_base = &header;
    vec[0].iov_len = sizeof(header);

    return apr_socket_sendv(conn->sock, vec, 1, &len);
}

/*
 * An arbitrary buffer size for reading the stdin data from the client.
 *
 * Need to find a "better" value here, or at least justify the current
 * value somehow.
 */
#define MAX_INPUT_BYTES 1024

static apr_status_t send_stdin(proxy_conn_rec *conn, request_rec *r,
                               int request_id)
{
    apr_bucket_brigade *input_brigade;
    apr_status_t rv = APR_SUCCESS;
    struct iovec vec[2];
    fcgi_header header;
    int done = 0;

    fill_in_header(&header, FCGI_STDIN, request_id);

    input_brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    while (! done) {
        char buff[MAX_INPUT_BYTES];
        apr_size_t buflen, len;

        rv = ap_get_brigade(r->input_filters, input_brigade,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            MAX_INPUT_BYTES);
        if (rv != APR_SUCCESS) {
            break;
        }

        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            done = 1;
        }

        buflen = sizeof(buff);

        rv = apr_brigade_flatten(input_brigade, buff, &buflen);

        apr_brigade_cleanup(input_brigade);

        if (rv != APR_SUCCESS) {
            break;
        }

        header.contentLengthB1 = ((buflen >> 8) & 0xff);
        header.contentLengthB0 = ((buflen) & 0xff); 

        vec[0].iov_base = &header;
        vec[0].iov_len = sizeof(header);
        vec[1].iov_base = buff;
        vec[1].iov_len = buflen;

        rv = apr_socket_sendv(conn->sock, vec, 2, &len);
        if (rv != APR_SUCCESS) {
            break;
        }

        /* XXX AJP updates conn->worker->s->transferred here, do we need to? */
    }

    /* If we got here successfully it means we sent all the data, so we need
     * to send the final empty record to signify the end of the stream. */
    if (rv == APR_SUCCESS) {
        apr_size_t len;

        header.contentLengthB1 = 0;
        header.contentLengthB0 = 0;

        vec[0].iov_base = &header;
        vec[0].iov_len = sizeof(header);

        rv = apr_socket_sendv(conn->sock, vec, 1, &len);
    }

    apr_brigade_destroy(input_brigade);

    return rv;
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
    /* Request IDs are arbitrary numbers that we assign to a
     * single request. This would allow multiplex/pipelinig of 
     * multiple requests to the same FastCGI connection, but 
     * we don't support that, and always use a value of '1' to
     * keep things simple. */
    int request_id = 1; 
    apr_status_t rv;
   
    /* Step 1: Send FCGI_BEGIN_REQUEST */
    rv = send_begin_request(conn, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "proxy: FCGI: Failed Writing Request to %s:",
                     server_portstr);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    
    /* Step 2: Send Enviroment via FCGI_PARAMS */
    rv = send_environment(conn, r, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "proxy: FCGI: Failed writing Environment to %s:",
                     server_portstr);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Step 3: Send Request Body via FCGI_STDIN */
    rv = send_stdin(conn, r, request_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "proxy: FCGI: Failed writing STDIN to %s:",
                     server_portstr);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Step 4: Read for CGI_STDOUT|CGI_STDERR */
    /* Step 5: Parse reply headers. */
    /* Step 6: Stream reply body. */
    /* Step 7: Read FCGI_END_REQUEST -> Done */
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

