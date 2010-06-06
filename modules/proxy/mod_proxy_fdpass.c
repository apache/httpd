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

#include "mod_proxy.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef CMSG_DATA
#error This module only works on unix platforms with the correct OS support
#endif

#include "apr_version.h"
#if APR_MAJOR_VERSION < 2
/* for apr_wait_for_io_or_timeout */
#include "apr_support.h"
#endif

#include "mod_proxy_fdpass.h"

module AP_MODULE_DECLARE_DATA proxy_fdpass_module;

static int proxy_fdpass_canon(request_rec *r, char *url)
{
    const char *path;

    if (strncasecmp(url, "fd://", 5) == 0) {
        url += 5;
    }
    else {
        return DECLINED;
    }
    
    path = ap_server_root_relative(r->pool, url);

    r->filename = apr_pstrcat(r->pool, "proxy:fd://", path, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "proxy: FD: set r->filename to %s", r->filename);
    return OK;
}

/* TODO: In APR 2.x: Extend apr_sockaddr_t to possibly be a path !!! */
static apr_status_t socket_connect_un(apr_socket_t *sock,
                                      struct sockaddr_un *sa)
{
    apr_status_t rv;
    apr_os_sock_t rawsock;
    apr_interval_time_t t;

    rv = apr_os_sock_get(&rawsock, sock);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_timeout_get(sock, &t);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    do {
        rv = connect(rawsock, (struct sockaddr*)sa,
                               sizeof(*sa) + strlen(sa->sun_path));
    } while (rv == -1 && errno == EINTR);

    if ((rv == -1) && (errno == EINPROGRESS || errno == EALREADY)
        && (t > 0)) {
#if APR_MAJOR_VERSION < 2
        rv = apr_wait_for_io_or_timeout(NULL, sock, 0);
#else
        rv = apr_socket_wait(sock, APR_WAIT_WRITE);
#endif

        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    
    if (rv == -1 && errno != EISCONN) {
        return errno;
    }

    return APR_SUCCESS;
}

static apr_status_t get_socket_from_path(apr_pool_t *p,
                                         const char* path,
                                         apr_socket_t **out_sock)
{
    struct sockaddr_un sa;
    apr_socket_t *s;
    apr_status_t rv;
    *out_sock = NULL;

    rv = apr_socket_create(&s, AF_UNIX, SOCK_STREAM, 0, p);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    sa.sun_family = AF_UNIX;
    apr_cpystrn(sa.sun_path, path, sizeof(sa.sun_path));

    rv = socket_connect_un(s, &sa);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    *out_sock = s;

    return APR_SUCCESS;
}


static apr_status_t send_socket(apr_pool_t *p,
                                apr_socket_t *s,
                                apr_socket_t *outbound)
{
    apr_status_t rv;
    apr_os_sock_t rawsock;
    apr_os_sock_t srawsock;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec iov;
    char b = '\0';
    
    rv = apr_os_sock_get(&rawsock, outbound);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_os_sock_get(&srawsock, s);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = &b;
    iov.iov_len = 1;

    cmsg = apr_palloc(p, sizeof(*cmsg) + sizeof(rawsock));
    cmsg->cmsg_len = sizeof(*cmsg) + sizeof(rawsock);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    memcpy(CMSG_DATA(cmsg), &rawsock, sizeof(rawsock));

    msg.msg_control = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;

    rv = sendmsg(srawsock, &msg, 0);

    if (rv == -1) {
        return errno;
    }

    
    return APR_SUCCESS;
}

static int proxy_fdpass_handler(request_rec *r, proxy_worker *worker,
                              proxy_server_conf *conf,
                              char *url, const char *proxyname,
                              apr_port_t proxyport)
{
    apr_status_t rv;
    apr_socket_t *sock;
    apr_socket_t *clientsock;

    if (strncasecmp(url, "fd://", 5) == 0) {
        url += 5;
    }
    else {
        return DECLINED;
    }

    rv = get_socket_from_path(r->pool, url, &sock);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "proxy: FD: Failed to connect to '%s'",
                      url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        int status;
        const char *flush_method = worker->flusher ? worker->flusher : "flush";

        proxy_fdpass_flush *flush = ap_lookup_provider(PROXY_FDPASS_FLUSHER,
                                                       flush_method, "0");

        if (!flush) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "proxy: FD: Unable to find configured flush "
                          "provider '%s'", flush_method);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        status = flush->flusher(r);
        if (status) {
            return status;
        }
    }

    /* XXXXX: THIS IS AN EVIL HACK */
    /* There should really be a (documented) public API for this ! */
    clientsock = ap_get_module_config(r->connection->conn_config, &core_module);

    rv = send_socket(r->pool, sock, clientsock);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "proxy: FD: send_socket failed:");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        apr_socket_t *dummy;
        /* Create a dummy unconnected socket, and set it as the one we were 
         * connected to, so that when the core closes it, it doesn't close 
         * the tcp connection to the client.
         */
        rv = apr_socket_create(&dummy, APR_INET, SOCK_STREAM, APR_PROTO_TCP,
                               r->connection->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "proxy: FD: failed to create dummy socket");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_set_module_config(r->connection->conn_config, &core_module, dummy);
    }
    
    
    return OK;
}

static int standard_flush(request_rec *r)
{
    int status;
    apr_bucket_brigade *bb;
    apr_bucket *e;

    r->connection->keepalive = AP_CONN_CLOSE;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    e = apr_bucket_flush_create(r->connection->bucket_alloc);
    
    APR_BRIGADE_INSERT_TAIL(bb, e);

    status = ap_pass_brigade(r->output_filters, bb);

    if (status != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "proxy: FD: ap_pass_brigade failed:");
        return status;
    }

    return OK;
}


static const proxy_fdpass_flush builtin_flush =
{
    "flush",
    &standard_flush,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, PROXY_FDPASS_FLUSHER, "flush", "0", &builtin_flush);
    proxy_hook_scheme_handler(proxy_fdpass_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_fdpass_canon, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_fdpass) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
