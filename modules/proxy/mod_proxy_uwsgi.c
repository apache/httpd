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
        
*** mod_proxy_uwsgi ***

Copyright 2009-2017 Unbit S.a.s. <info@unbit.it>
     
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#define APR_WANT_MEMFUNC
#define APR_WANT_STRFUNC
#include "apr_strings.h"
#include "apr_hooks.h"
#include "apr_optional_hooks.h"
#include "apr_buckets.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include "mod_proxy.h"


#define UWSGI_SCHEME "uwsgi"
#define UWSGI_DEFAULT_PORT 3031

module AP_MODULE_DECLARE_DATA proxy_uwsgi_module;


static int uwsgi_canon(request_rec *r, char *url)
{
    char *host, sport[sizeof(":65535")];
    const char *err, *path;
    apr_port_t port = UWSGI_DEFAULT_PORT;

    if (ap_cstr_casecmpn(url, UWSGI_SCHEME "://", sizeof(UWSGI_SCHEME) + 2)) {
        return DECLINED;
    }
    url += sizeof(UWSGI_SCHEME);        /* Keep slashes */

    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10097)
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    if (port != UWSGI_DEFAULT_PORT)
        apr_snprintf(sport, sizeof(sport), ":%u", port);
    else
        sport[0] = '\0';

    if (ap_strchr(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }

    if (apr_table_get(r->notes, "proxy-nocanon")
        || apr_table_get(r->notes, "proxy-noencode")) {
        path = url;   /* this is the raw/encoded path */
    }
    else {
        core_dir_config *d = ap_get_core_module_config(r->per_dir_config);
        int flags = d->allow_encoded_slashes && !d->decode_encoded_slashes ? PROXY_CANONENC_NOENCODEDSLASHENCODING : 0;

        path = ap_proxy_canonenc_ex(r->pool, url, strlen(url), enc_path, flags,
                                    r->proxyreq);
        if (!path) {
            return HTTP_BAD_REQUEST;
        }
    }
    /*
     * If we have a raw control character or a ' ' in nocanon path,
     * correct encoding was missed.
     */
    if (path == url && *ap_scan_vchar_obstext(path)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10417)
                      "To be forwarded path contains control "
                      "characters or spaces");
        return HTTP_FORBIDDEN;
    }

    r->filename =
        apr_pstrcat(r->pool, "proxy:" UWSGI_SCHEME "://", host, sport, "/",
                    path, NULL);

    return OK;
}


static int uwsgi_send(proxy_conn_rec * conn, const char *buf,
                      apr_size_t length, request_rec *r)
{
    apr_status_t rv;
    apr_size_t written;

    while (length > 0) {
        written = length;
        if ((rv = apr_socket_send(conn->sock, buf, &written)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10098)
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
 * Send uwsgi header block
 */
static int uwsgi_send_headers(request_rec *r, proxy_conn_rec * conn)
{
    char *buf, *ptr;

    const apr_array_header_t *env_table;
    const apr_table_entry_t *env;

    int j;

    apr_size_t headerlen = 4;
    apr_size_t pktsize, keylen, vallen;
    const char *script_name;
    const char *path_info;
    const char *auth;

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    /*
       this is not a security problem (in Linux) as uWSGI destroy the env memory area readable in /proc
       and generally if you host untrusted apps in your server and allows them to read others uid /proc/<pid>
       files you have higher problems...
     */
    auth = apr_table_get(r->headers_in, "Authorization");
    if (auth) {
        apr_table_setn(r->subprocess_env, "HTTP_AUTHORIZATION", auth);
    }

    script_name = apr_table_get(r->subprocess_env, "SCRIPT_NAME");
    path_info = apr_table_get(r->subprocess_env, "PATH_INFO");

    if (script_name && path_info) {
        if (strcmp(path_info, "/")) {
            apr_table_set(r->subprocess_env, "SCRIPT_NAME",
                          apr_pstrndup(r->pool, script_name,
                                       strlen(script_name) -
                                       strlen(path_info)));
        }
        else {
            if (!strcmp(script_name, "/")) {
                apr_table_setn(r->subprocess_env, "SCRIPT_NAME", "");
            }
        }
    }

    env_table = apr_table_elts(r->subprocess_env);
    env = (apr_table_entry_t *) env_table->elts;

    for (j = 0; j < env_table->nelts; ++j) {
        headerlen += 2 + strlen(env[j].key) + 2 + (env[j].val ? strlen(env[j].val) : 0);
    }

    pktsize = headerlen - 4;
    if (pktsize > APR_UINT16_MAX) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10259)
                      "can't send headers to %s:%u: packet size too "
                      "large (%" APR_SIZE_T_FMT ")",
                      conn->hostname, conn->port, pktsize);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ptr = buf = apr_palloc(r->pool, headerlen);

    ptr += 4;

    for (j = 0; j < env_table->nelts; ++j) {
        keylen = strlen(env[j].key);
        *ptr++ = (apr_byte_t) (keylen & 0xff);
        *ptr++ = (apr_byte_t) ((keylen >> 8) & 0xff);
        memcpy(ptr, env[j].key, keylen);
        ptr += keylen;

        vallen = env[j].val ? strlen(env[j].val) : 0;
        *ptr++ = (apr_byte_t) (vallen & 0xff);
        *ptr++ = (apr_byte_t) ((vallen >> 8) & 0xff);
        if (env[j].val) {
            memcpy(ptr, env[j].val, vallen);
        }
        ptr += vallen;
    }

    buf[0] = 0;
    buf[1] = (apr_byte_t) (pktsize & 0xff);
    buf[2] = (apr_byte_t) ((pktsize >> 8) & 0xff);
    buf[3] = 0;

    return uwsgi_send(conn, buf, headerlen, r);
}


static int uwsgi_send_body(request_rec *r, proxy_conn_rec * conn)
{
    if (ap_should_client_block(r)) {
        char *buf = apr_palloc(r->pool, AP_IOBUFSIZE);
        int status;
        long readlen;

        readlen = ap_get_client_block(r, buf, AP_IOBUFSIZE);
        while (readlen > 0) {
            status = uwsgi_send(conn, buf, (apr_size_t)readlen, r);
            if (status != OK) {
                return HTTP_SERVICE_UNAVAILABLE;
            }
            readlen = ap_get_client_block(r, buf, AP_IOBUFSIZE);
        }
        if (readlen == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10099)
                          "receiving request body failed");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

static request_rec *make_fake_req(conn_rec *c, request_rec *r)
{
    apr_pool_t *pool;
    request_rec *rp;

    apr_pool_create(&pool, c->pool);
    apr_pool_tag(pool, "proxy_uwsgi_rp");

    rp = apr_pcalloc(pool, sizeof(*r));

    rp->pool = pool;
    rp->status = HTTP_OK;

    rp->headers_in = apr_table_make(pool, 50);
    rp->subprocess_env = apr_table_make(pool, 50);
    rp->headers_out = apr_table_make(pool, 12);
    rp->err_headers_out = apr_table_make(pool, 5);
    rp->notes = apr_table_make(pool, 5);

    rp->server = r->server;
    rp->log = r->log;
    rp->proxyreq = r->proxyreq;
    rp->request_time = r->request_time;
    rp->connection = c;
    rp->output_filters = c->output_filters;
    rp->input_filters = c->input_filters;
    rp->proto_output_filters = c->output_filters;
    rp->proto_input_filters = c->input_filters;
    rp->useragent_ip = c->client_ip;
    rp->useragent_addr = c->client_addr;

    rp->request_config = ap_create_request_config(pool);
    proxy_run_create_req(r, rp);

    return rp;
}

static int uwsgi_response(request_rec *r, proxy_conn_rec * backend,
                          proxy_server_conf * conf)
{

    char buffer[HUGE_STRING_LEN];
    const char *buf;
    char *value, *end;
    char keepchar;
    int len;
    int backend_broke = 0;
    int status_start;
    int status_end;
    int finish = 0;
    conn_rec *c = r->connection;
    apr_off_t readbytes;
    apr_status_t rv;
    apr_bucket *e;
    apr_read_type_e mode = APR_NONBLOCK_READ;
    apr_bucket_brigade *pass_bb;
    apr_bucket_brigade *bb;
    proxy_dir_conf *dconf;

    request_rec *rp = make_fake_req(backend->connection, r);
    rp->proxyreq = PROXYREQ_RESPONSE;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    pass_bb = apr_brigade_create(r->pool, c->bucket_alloc);

    len = ap_getline(buffer, sizeof(buffer), rp, 1);
    if (len <= 0) {
        /* invalid or empty */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    backend->worker->s->read += len;
    if ((apr_size_t)len >= sizeof(buffer)) {
        /* too long */
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Position of http status code */
    if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
        status_start = 9;
    }
    else if (apr_date_checkmask(buffer, "HTTP/# ###*")) {
        status_start = 7;
    }
    else {
        /* not HTTP */
        return HTTP_BAD_GATEWAY;
    }
    status_end = status_start + 3;

    keepchar = buffer[status_end];
    buffer[status_end] = '\0';
    r->status = atoi(&buffer[status_start]);

    if (keepchar != '\0') {
        buffer[status_end] = keepchar;
    }
    else {
        /* 2616 requires the space in Status-Line; the origin
         * server may have sent one but ap_rgetline_core will
         * have stripped it. */
        buffer[status_end] = ' ';
        buffer[status_end + 1] = '\0';
    }
    r->status_line = apr_pstrdup(r->pool, &buffer[status_start]);

    /* parse headers */
    while ((len = ap_getline(buffer, sizeof(buffer), rp, 1)) > 0) {
        if ((apr_size_t)len >= sizeof(buffer)) {
            /* too long */
            len = -1;
            break;
        }
        value = strchr(buffer, ':');
        if (!value) {
            /* invalid header */
            len = -1;
            break;
        }
        *value++ = '\0';
        if (*ap_scan_http_token(buffer)) {
            /* invalid name */
            len = -1;
            break;
        }
        while (apr_isspace(*value))
            ++value;
        for (end = &value[strlen(value) - 1];
             end > value && apr_isspace(*end); --end)
            *end = '\0';
        if (*ap_scan_http_field_content(value)) {
            /* invalid value */
            len = -1;
            break;
        }
        apr_table_add(r->headers_out, buffer, value);
    }
    if (len < 0) {
        /* Reset headers, but not to NULL because things below the chain expect
         * this to be non NULL e.g. the ap_content_length_filter.
         */
        r->headers_out = apr_table_make(r->pool, 1);
        return HTTP_BAD_GATEWAY;
    }

    if ((buf = apr_table_get(r->headers_out, "Content-Type"))) {
        ap_set_content_type(r, apr_pstrdup(r->pool, buf));
    }

    /* honor ProxyErrorOverride and ErrorDocument */
#if AP_MODULE_MAGIC_AT_LEAST(20101106,0)
    dconf =
        ap_get_module_config(r->per_dir_config, &proxy_module);
    if (ap_proxy_should_override(dconf, r->status)) {
#else
    if (ap_proxy_should_override(conf, r->status)) {
#endif
        int status = r->status;
        r->status = HTTP_OK;
        r->status_line = NULL;

        apr_brigade_cleanup(bb);
        apr_brigade_cleanup(pass_bb);

        return status;
    }

    while (!finish) {
        rv = ap_get_brigade(rp->input_filters, bb,
                            AP_MODE_READBYTES, mode, conf->io_buffer_size);
        if (APR_STATUS_IS_EAGAIN(rv)
            || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(bb))) {
            e = apr_bucket_flush_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            if (ap_pass_brigade(r->output_filters, bb) || c->aborted) {
                break;
            }
            apr_brigade_cleanup(bb);
            mode = APR_BLOCK_READ;
            continue;
        }
        else if (rv == APR_EOF) {
            break;
        }
        else if (rv != APR_SUCCESS) {
            ap_proxy_backend_broke(r, bb);
            ap_pass_brigade(r->output_filters, bb);
            backend_broke = 1;
            break;
        }

        mode = APR_NONBLOCK_READ;
        apr_brigade_length(bb, 0, &readbytes);
        backend->worker->s->read += readbytes;

        if (APR_BRIGADE_EMPTY(bb)) {
            apr_brigade_cleanup(bb);
            break;
        }

        ap_proxy_buckets_lifetime_transform(r, bb, pass_bb);

        /* found the last brigade? */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb)))
            finish = 1;

        /* do not pass chunk if it is zero_sized */
        apr_brigade_length(pass_bb, 0, &readbytes);

        if ((readbytes > 0
             && ap_pass_brigade(r->output_filters, pass_bb) != APR_SUCCESS)
            || c->aborted) {
            finish = 1;
        }

        apr_brigade_cleanup(bb);
        apr_brigade_cleanup(pass_bb);
    }

    e = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    ap_pass_brigade(r->output_filters, bb);

    apr_brigade_cleanup(bb);

    if (c->aborted || backend_broke) {
        return DONE;
    }

    return OK;
}

static int uwsgi_handler(request_rec *r, proxy_worker * worker,
                         proxy_server_conf * conf, char *url,
                         const char *proxyname, apr_port_t proxyport)
{
    int status;
    proxy_conn_rec *backend = NULL;
    apr_pool_t *p = r->pool;
    char server_portstr[32];
    char *u_path_info;
    apr_uri_t *uri;

    if (ap_cstr_casecmpn(url, UWSGI_SCHEME "://", sizeof(UWSGI_SCHEME) + 2)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining URL %s", url);
        return DECLINED;
    }

    uri = apr_palloc(r->pool, sizeof(*uri));

    /* ADD PATH_INFO (unescaped) */
    u_path_info = ap_strchr(url + sizeof(UWSGI_SCHEME) + 2, '/');
    if (!u_path_info) {
        u_path_info = apr_pstrdup(r->pool, "/");
    }
    else if (ap_unescape_url(u_path_info) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10100)
                      "unable to decode uwsgi uri: %s", url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        /* Remove duplicate slashes at the beginning of PATH_INFO */
        while (u_path_info[1] == '/') {
            u_path_info++;
        }
    }
    apr_table_add(r->subprocess_env, "PATH_INFO", u_path_info);

    /* Create space for state information */
    status = ap_proxy_acquire_connection(UWSGI_SCHEME, &backend, worker,
                                         r->server);
    if (status != OK) {
        goto cleanup;
    }
    backend->is_ssl = 0;

    /* Step One: Determine Who To Connect To */
    status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                           uri, &url, proxyname, proxyport,
                                           server_portstr,
                                           sizeof(server_portstr));
    if (status != OK) {
        goto cleanup;
    }


    /* Step Two: Make the Connection */
    if (ap_proxy_connect_backend(UWSGI_SCHEME, backend, worker, r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10101)
                      "failed to make connection to backend: %s:%u",
                      backend->hostname, backend->port);
        status = HTTP_SERVICE_UNAVAILABLE;
        goto cleanup;
    }

    /* Step Three: Create conn_rec */
    if ((status = ap_proxy_connection_create(UWSGI_SCHEME, backend,
                                             r->connection,
                                             r->server)) != OK)
        goto cleanup;

    /* Step Four: Process the Request */
    if (((status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK)
        || ((status = uwsgi_send_headers(r, backend)) != OK)
        || ((status = uwsgi_send_body(r, backend)) != OK)
        || ((status = uwsgi_response(r, backend, conf)) != OK)) {
        goto cleanup;
    }

  cleanup:
    if (backend) {
        backend->close = 1;     /* always close the socket */
        ap_proxy_release_connection(UWSGI_SCHEME, backend, r->server);
    }
    return status;
}


static void register_hooks(apr_pool_t * p)
{
    proxy_hook_scheme_handler(uwsgi_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(uwsgi_canon, NULL, NULL, APR_HOOK_FIRST);
}


module AP_MODULE_DECLARE_DATA proxy_uwsgi_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command table */
    register_hooks              /* register hooks */
};
