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

/*
 * mod_proxy_scgi.c
 * Proxy backend module for the SCGI protocol
 * (http://python.ca/scgi/protocol.txt)
 *
 * Andr� Malo (nd/perlig.de), August 2007
 */

#define APR_WANT_MEMFUNC
#define APR_WANT_STRFUNC
#include "apr_strings.h"
#include "ap_hooks.h"
#include "apr_optional_hooks.h"
#include "apr_buckets.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "mod_proxy.h"
#include "scgi.h"


#define SCHEME "scgi"
#define PROXY_FUNCTION "SCGI"
#define SCGI_MAGIC "SCGI"
#define SCGI_PROTOCOL_VERSION "1"

/* just protect from typos */
#define CONTENT_LENGTH "CONTENT_LENGTH"
#define GATEWAY_INTERFACE "GATEWAY_INTERFACE"

module AP_MODULE_DECLARE_DATA proxy_scgi_module;


typedef enum {
    scgi_internal_redirect,
    scgi_sendfile
} scgi_request_type;

typedef struct {
    const char *location;    /* target URL */
    scgi_request_type type;  /* type of request */
} scgi_request_config;

const char *scgi_sendfile_off = "off";
const char *scgi_sendfile_on = "X-Sendfile";
const char *scgi_internal_redirect_off = "off";
const char *scgi_internal_redirect_on = "Location";

typedef struct {
    const char *sendfile;
    const char *internal_redirect;
} scgi_config;


/*
 * We create our own bucket type, which is actually derived (c&p) from the
 * socket bucket.
 * Maybe some time this should be made more abstract (like passing an
 * interception function to read or something) and go into the ap_ or
 * even apr_ namespace.
 */

typedef struct {
    apr_socket_t *sock;
    apr_off_t *counter;
} socket_ex_data;

static apr_bucket *bucket_socket_ex_create(socket_ex_data *data,
                                           apr_bucket_alloc_t *list);


static apr_status_t bucket_socket_ex_read(apr_bucket *a, const char **str,
                                          apr_size_t *len,
                                          apr_read_type_e block)
{
    socket_ex_data *data = a->data;
    apr_socket_t *p = data->sock;
    char *buf;
    apr_status_t rv;
    apr_interval_time_t timeout;

    if (block == APR_NONBLOCK_READ) {
        apr_socket_timeout_get(p, &timeout);
        apr_socket_timeout_set(p, 0);
    }

    *str = NULL;
    *len = APR_BUCKET_BUFF_SIZE;
    buf = apr_bucket_alloc(*len, a->list);

    rv = apr_socket_recv(p, buf, len);

    if (block == APR_NONBLOCK_READ) {
        apr_socket_timeout_set(p, timeout);
    }

    if (rv != APR_SUCCESS && rv != APR_EOF) {
        apr_bucket_free(buf);
        return rv;
    }

    if (*len > 0) {
        apr_bucket_heap *h;

        /* count for stats */
        *data->counter += *len;

        /* Change the current bucket to refer to what we read */
        a = apr_bucket_heap_make(a, buf, *len, apr_bucket_free);
        h = a->data;
        h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */
        *str = buf;
        APR_BUCKET_INSERT_AFTER(a, bucket_socket_ex_create(data, a->list));
    }
    else {
        apr_bucket_free(buf);
        a = apr_bucket_immortal_make(a, "", 0);
        *str = a->data;
    }
    return APR_SUCCESS;
}

static const apr_bucket_type_t bucket_type_socket_ex = {
    "SOCKET_EX", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    bucket_socket_ex_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};

static apr_bucket *bucket_socket_ex_make(apr_bucket *b, socket_ex_data *data)
{
    b->type        = &bucket_type_socket_ex;
    b->length      = (apr_size_t)(-1);
    b->start       = -1;
    b->data        = data;
    return b;
}

static apr_bucket *bucket_socket_ex_create(socket_ex_data *data,
                                           apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return bucket_socket_ex_make(b, data);
}


/*
 * Canonicalize scgi-like URLs.
 */
static int scgi_canon(request_rec *r, char *url)
{
    char *host, sport[sizeof(":65535")];
    const char *err, *path;
    apr_port_t port, def_port;
    core_dir_config *d = ap_get_core_module_config(r->per_dir_config);
    int flags = d->allow_encoded_slashes && !d->decode_encoded_slashes ? PROXY_CANONENC_NOENCODEDSLASHENCODING : 0;

    if (ap_cstr_casecmpn(url, SCHEME "://", sizeof(SCHEME) + 2)) {
        return DECLINED;
    }
    url += sizeof(SCHEME); /* Keep slashes */

    port = def_port = SCGI_DEF_PORT;

    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00857)
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    if (port != def_port) {
        apr_snprintf(sport, sizeof(sport), ":%u", port);
    }
    else {
        sport[0] = '\0';
    }

    if (ap_strchr(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }

    path = ap_proxy_canonenc_ex(r->pool, url, strlen(url), enc_path, flags,
                                r->proxyreq);
    if (!path) {
        return HTTP_BAD_REQUEST;
    }

    r->filename = apr_pstrcat(r->pool, "proxy:" SCHEME "://", host, sport, "/",
                              path, NULL);

    if (apr_table_get(r->subprocess_env, "proxy-scgi-pathinfo")) {
        r->path_info = apr_pstrcat(r->pool, "/", path, NULL);
    }

    return OK;
}


/*
 * Send a block of data, ensure, everything is sent
 */
static int sendall(proxy_conn_rec *conn, const char *buf, apr_size_t length,
                   request_rec *r)
{
    apr_status_t rv;
    apr_size_t written;

    while (length > 0) {
        written = length;
        if ((rv = apr_socket_send(conn->sock, buf, &written)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00858)
                          "sending data to %s:%u failed",
                          conn->hostname, conn->port);
            return HTTP_SERVICE_UNAVAILABLE;
        }

        /* count for stats */
        conn->worker->s->transferred += written;
        buf += written;
        length -= written;
    }

    return OK;
}


/*
 * Send SCGI header block
 */
static int send_headers(request_rec *r, proxy_conn_rec *conn)
{
    char *buf, *cp, *bodylen;
    const char *ns_len;
    const apr_array_header_t *env_table;
    const apr_table_entry_t *env;
    int j;
    apr_size_t len, bodylen_size;
    apr_size_t headerlen =   sizeof(CONTENT_LENGTH)
                           + sizeof(SCGI_MAGIC)
                           + sizeof(SCGI_PROTOCOL_VERSION);

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /*
     * The header blob basically takes the environment and concatenates
     * keys and values using 0 bytes. There are special treatments here:
     *   - GATEWAY_INTERFACE and SCGI_MAGIC are dropped
     *   - CONTENT_LENGTH is always set and must be sent as the very first
     *     variable
     *
     * Additionally it's wrapped into a so-called netstring (see SCGI spec)
     */
    env_table = apr_table_elts(r->subprocess_env);
    env = (apr_table_entry_t *)env_table->elts;
    for (j = 0; j < env_table->nelts; ++j) {
        if (   (!strcmp(env[j].key, GATEWAY_INTERFACE))
            || (!strcmp(env[j].key, CONTENT_LENGTH))
            || (!strcmp(env[j].key, SCGI_MAGIC))) {
            continue;
        }
        headerlen += strlen(env[j].key) + strlen(env[j].val) + 2;
    }
    bodylen = apr_psprintf(r->pool, "%" APR_OFF_T_FMT, r->remaining);
    bodylen_size = strlen(bodylen) + 1;
    headerlen += bodylen_size;

    ns_len = apr_psprintf(r->pool, "%" APR_SIZE_T_FMT ":", headerlen);
    len = strlen(ns_len);
    headerlen += len + 1; /* 1 == , */
    cp = buf = apr_palloc(r->pool, headerlen);
    memcpy(cp, ns_len, len);
    cp += len;

    memcpy(cp, CONTENT_LENGTH, sizeof(CONTENT_LENGTH));
    cp += sizeof(CONTENT_LENGTH);
    memcpy(cp, bodylen, bodylen_size);
    cp += bodylen_size;
    memcpy(cp, SCGI_MAGIC, sizeof(SCGI_MAGIC));
    cp += sizeof(SCGI_MAGIC);
    memcpy(cp, SCGI_PROTOCOL_VERSION, sizeof(SCGI_PROTOCOL_VERSION));
    cp += sizeof(SCGI_PROTOCOL_VERSION);

    for (j = 0; j < env_table->nelts; ++j) {
        if (   (!strcmp(env[j].key, GATEWAY_INTERFACE))
            || (!strcmp(env[j].key, CONTENT_LENGTH))
            || (!strcmp(env[j].key, SCGI_MAGIC))) {
            continue;
        }
        len = strlen(env[j].key) + 1;
        memcpy(cp, env[j].key, len);
        cp += len;
        len = strlen(env[j].val) + 1;
        memcpy(cp, env[j].val, len);
        cp += len;
    }
    *cp++ = ',';

    return sendall(conn, buf, headerlen, r);
}


/*
 * Send request body (if any)
 */
static int send_request_body(request_rec *r, proxy_conn_rec *conn)
{
    if (ap_should_client_block(r)) {
        char *buf = apr_palloc(r->pool, AP_IOBUFSIZE);
        int status;
        long readlen;

        readlen = ap_get_client_block(r, buf, AP_IOBUFSIZE);
        while (readlen > 0) {
            status = sendall(conn, buf, (apr_size_t)readlen, r);
            if (status != OK) {
                return HTTP_SERVICE_UNAVAILABLE;
            }
            readlen = ap_get_client_block(r, buf, AP_IOBUFSIZE);
        }
        if (readlen == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00859)
                          "receiving request body failed");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}


/*
 * Fetch response from backend and pass back to the front
 */
static int pass_response(request_rec *r, proxy_conn_rec *conn)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    const char *location;
    scgi_config *conf;
    socket_ex_data *sock_data;
    int status;

    sock_data = apr_palloc(r->pool, sizeof(*sock_data));
    sock_data->sock = conn->sock;
    sock_data->counter = &conn->worker->s->read;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    b = bucket_socket_ex_create(sock_data, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    status = ap_scan_script_header_err_brigade_ex(r, bb, NULL,
                                                  APLOG_MODULE_INDEX);
    if (status != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00860)
                      "error reading response headers from %s:%u",
                      conn->hostname, conn->port);
        r->status_line = NULL;
        apr_brigade_destroy(bb);
        return status;
    }

    conf = ap_get_module_config(r->per_dir_config, &proxy_scgi_module);
    if (conf->sendfile && conf->sendfile != scgi_sendfile_off) {
        short err = 1;

        location = apr_table_get(r->err_headers_out, conf->sendfile);
        if (!location) {
            err = 0;
            location = apr_table_get(r->headers_out, conf->sendfile);
        }
        if (location) {
            scgi_request_config *req_conf = apr_palloc(r->pool,
                                                       sizeof(*req_conf));
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00861)
                          "Found %s: %s - preparing subrequest.",
                          conf->sendfile, location);

            if (err) {
                apr_table_unset(r->err_headers_out, conf->sendfile);
            }
            else {
                apr_table_unset(r->headers_out, conf->sendfile);
            }
            req_conf->location = location;
            req_conf->type = scgi_sendfile;
            ap_set_module_config(r->request_config, &proxy_scgi_module,
                                 req_conf);
            apr_brigade_destroy(bb);
            return OK;
        }
    }

    if (r->status == HTTP_OK 
        && (!conf->internal_redirect /* default === On */
            || conf->internal_redirect != scgi_internal_redirect_off)) {
        short err = 1;
        const char *location_header = conf->internal_redirect ? 
            conf->internal_redirect : scgi_internal_redirect_on;

        location = apr_table_get(r->err_headers_out, location_header);
        if (!location) {
            err = 0;
            location = apr_table_get(r->headers_out, location_header);
        }
        if (location && *location == '/') {
            scgi_request_config *req_conf = apr_palloc(r->pool,
                                                       sizeof(*req_conf));
            if (ap_cstr_casecmp(location_header, "Location")) {
                if (err) {
                    apr_table_unset(r->err_headers_out, location_header);
                }
                else {
                    apr_table_unset(r->headers_out, location_header);
                }
            }
            req_conf->location = location;
            req_conf->type = scgi_internal_redirect;
            ap_set_module_config(r->request_config, &proxy_scgi_module,
                                 req_conf);
            apr_brigade_destroy(bb);
            return OK;
        }
    }

    if (ap_pass_brigade(r->output_filters, bb)) {
        return AP_FILTER_ERROR;
    }

    return OK;
}

/*
 * Internal redirect / subrequest handler, working on request_status hook
 */
static int scgi_request_status(int *status, request_rec *r)
{
    scgi_request_config *req_conf;

    if (   (*status == OK)
        && (req_conf = ap_get_module_config(r->request_config,
                                            &proxy_scgi_module))) {
        switch (req_conf->type) {
        case scgi_internal_redirect:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00862)
                          "Internal redirect to %s", req_conf->location);

            r->status_line = NULL;
            if (r->method_number != M_GET) {
                /* keep HEAD, which is passed around as M_GET, too */
                r->method = "GET";
                r->method_number = M_GET;
            }
            apr_table_unset(r->headers_in, "Content-Length");
            ap_internal_redirect_handler(req_conf->location, r);
            return OK;
            /* break; */

        case scgi_sendfile:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00863)
                          "File subrequest to %s", req_conf->location);
            do {
                request_rec *rr;

                rr = ap_sub_req_lookup_file(req_conf->location, r,
                                            r->output_filters);
                if (rr->status == HTTP_OK && rr->finfo.filetype != APR_NOFILE) {
                    /*
                     * We don't touch Content-Length here. It might be
                     * borked (there's plenty of room for a race condition).
                     * Either the backend sets it or it's gonna be chunked.
                     */
                    ap_run_sub_req(rr);
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00864)
                                  "Subrequest to file '%s' not possible. "
                                  "(rr->status=%d, rr->finfo.filetype=%d)",
                                  req_conf->location, rr->status,
                                  rr->finfo.filetype);
                    *status = HTTP_INTERNAL_SERVER_ERROR;
                    return *status;
                }
            } while (0);

            return OK;
            /* break; */
        }
    }

    return DECLINED;
}


/*
 * This handles scgi:(dest) URLs
 */
static int scgi_handler(request_rec *r, proxy_worker *worker,
                        proxy_server_conf *conf, char *url,
                        const char *proxyname, apr_port_t proxyport)
{
    int status;
    proxy_conn_rec *backend = NULL;
    apr_pool_t *p = r->pool;
    apr_uri_t *uri;
    char dummy;

    if (ap_cstr_casecmpn(url, SCHEME "://", sizeof(SCHEME) + 2)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00865)
                      "declining URL %s", url);
        return DECLINED;
    }

    /* Create space for state information */
    status = ap_proxy_acquire_connection(PROXY_FUNCTION, &backend, worker,
                                         r->server);
    if (status != OK) {
        goto cleanup;
    }
    backend->is_ssl = 0;

    /* Step One: Determine Who To Connect To */
    uri = apr_palloc(p, sizeof(*uri));
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           &dummy, 1);
    if (status != OK) {
        goto cleanup;
    }

    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(PROXY_FUNCTION, backend, worker, r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00866)
                      "failed to make connection to backend: %s:%u",
                      backend->hostname, backend->port);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Process the Request */
    if (   ((status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK)
        || ((status = send_headers(r, backend)) != OK)
        || ((status = send_request_body(r, backend)) != OK)
        || ((status = pass_response(r, backend)) != OK)) {
        goto cleanup;
    }

cleanup:
    if (backend) {
        backend->close = 1; /* always close the socket */
        ap_proxy_release_connection(PROXY_FUNCTION, backend, r->server);
    }
    return status;
}


static void *create_scgi_config(apr_pool_t *p, char *dummy)
{
    scgi_config *conf=apr_palloc(p, sizeof(*conf));

    conf->sendfile = NULL; /* === default (off) */
    conf->internal_redirect = NULL; /* === default (on) */

    return conf;
}


static void *merge_scgi_config(apr_pool_t *p, void *base_, void *add_)
{
    scgi_config *base=base_, *add=add_, *conf=apr_palloc(p, sizeof(*conf));

    conf->sendfile = add->sendfile ? add->sendfile: base->sendfile;
    conf->internal_redirect = add->internal_redirect
                              ? add->internal_redirect
                              : base->internal_redirect;
    return conf;
}


static const char *scgi_set_send_file(cmd_parms *cmd, void *mconfig,
                                      const char *arg)
{
    scgi_config *conf=mconfig;

    if (!strcasecmp(arg, "Off")) {
        conf->sendfile = scgi_sendfile_off;
    }
    else if (!strcasecmp(arg, "On")) {
        conf->sendfile = scgi_sendfile_on;
    }
    else {
        conf->sendfile = arg;
    }
    return NULL;
}


static const char *scgi_set_internal_redirect(cmd_parms *cmd, void *mconfig,
                                              const char *arg)
{
    scgi_config *conf = mconfig;

    if (!strcasecmp(arg, "Off")) {
        conf->internal_redirect = scgi_internal_redirect_off;
    }
    else if (!strcasecmp(arg, "On")) {
        conf->internal_redirect = scgi_internal_redirect_on;
    }
    else {
        conf->internal_redirect = arg;
    }
    return NULL;
}


static const command_rec scgi_cmds[] =
{
    AP_INIT_TAKE1("ProxySCGISendfile", scgi_set_send_file, NULL,
                  RSRC_CONF|ACCESS_CONF,
                  "The name of the X-Sendfile pseudo response header or "
                  "On or Off"),
    AP_INIT_TAKE1("ProxySCGIInternalRedirect", scgi_set_internal_redirect, NULL,
                  RSRC_CONF|ACCESS_CONF,
                  "The name of the pseudo response header or On or Off"),
    {NULL}
};


static void register_hooks(apr_pool_t *p)
{
    proxy_hook_scheme_handler(scgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(scgi_canon, NULL, NULL, APR_HOOK_FIRST);
    APR_OPTIONAL_HOOK(proxy, request_status, scgi_request_status, NULL, NULL,
                      APR_HOOK_MIDDLE);
}


AP_DECLARE_MODULE(proxy_scgi) = {
    STANDARD20_MODULE_STUFF,
    create_scgi_config,  /* create per-directory config structure */
    merge_scgi_config,   /* merge per-directory config structures */
    NULL,                /* create per-server config structure */
    NULL,                /* merge per-server config structures */
    scgi_cmds,           /* command table */
    register_hooks       /* register hooks */
};
