/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "apr_network_io.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "ap_listen.h"
#include "http_log.h"
#include "mpm.h"
#include "mpm_common.h"

ap_listen_rec *ap_listeners = NULL;

#if APR_HAVE_IPV6
static int default_family = APR_UNSPEC;
#else
static int default_family = APR_INET;
#endif

static ap_listen_rec *old_listeners;
static int ap_listenbacklog;
static int send_buffer_size;

/* TODO: make_sock is just begging and screaming for APR abstraction */
static apr_status_t make_sock(apr_pool_t *p, ap_listen_rec *server)
{
    apr_socket_t *s = server->sd;
    int one = 1;
#if APR_HAVE_IPV6
#ifdef AP_ENABLE_V4_MAPPED
    int v6only_setting = 0;
#else
    int v6only_setting = 1;
#endif
#endif
    apr_status_t stat;

#ifndef WIN32
    stat = apr_socket_opt_set(s, APR_SO_REUSEADDR, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, stat, p,
                      "make_sock: for address %pI, apr_socket_opt_set: (SO_REUSEADDR)",
                      server->bind_addr);
        apr_socket_close(s);
        return stat;
    }
#endif

    stat = apr_socket_opt_set(s, APR_SO_KEEPALIVE, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, stat, p,
                      "make_sock: for address %pI, apr_socket_opt_set: (SO_KEEPALIVE)",
                      server->bind_addr);
        apr_socket_close(s);
        return stat;
    }

#if APR_HAVE_IPV6
    if (server->bind_addr->family == APR_INET6) {
        stat = apr_socket_opt_set(s, APR_IPV6_V6ONLY, v6only_setting);
        if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
            ap_log_perror(APLOG_MARK, APLOG_CRIT, stat, p,
                          "make_sock: for address %pI, apr_socket_opt_set: "
                          "(IPV6_V6ONLY)",
                          server->bind_addr);
            apr_socket_close(s);
            return stat;
        }
    }
#endif

    /*
     * To send data over high bandwidth-delay connections at full
     * speed we must force the TCP window to open wide enough to keep the
     * pipe full.  The default window size on many systems
     * is only 4kB.  Cross-country WAN connections of 100ms
     * at 1Mb/s are not impossible for well connected sites.
     * If we assume 100ms cross-country latency,
     * a 4kB buffer limits throughput to 40kB/s.
     *
     * To avoid this problem I've added the SendBufferSize directive
     * to allow the web master to configure send buffer size.
     *
     * The trade-off of larger buffers is that more kernel memory
     * is consumed.  YMMV, know your customers and your network!
     *
     * -John Heidemann <johnh@isi.edu> 25-Oct-96
     *
     * If no size is specified, use the kernel default.
     */
    if (send_buffer_size) {
        stat = apr_socket_opt_set(s, APR_SO_SNDBUF,  send_buffer_size);
        if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, stat, p,
                          "make_sock: failed to set SendBufferSize for "
                          "address %pI, using default",
                          server->bind_addr);
            /* not a fatal error */
        }
    }

#if APR_TCP_NODELAY_INHERITED
    ap_sock_disable_nagle(s);
#endif

    if ((stat = apr_bind(s, server->bind_addr)) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, stat, p,
                      "make_sock: could not bind to address %pI",
                      server->bind_addr);
        apr_socket_close(s);
        return stat;
    }

    if ((stat = apr_listen(s, ap_listenbacklog)) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, stat, p,
                      "make_sock: unable to listen for connections "
                      "on address %pI",
                      server->bind_addr);
        apr_socket_close(s);
        return stat;
    }

#ifdef WIN32
    /* I seriously doubt that this would work on Unix; I have doubts that
     * it entirely solves the problem on Win32.  However, since setting
     * reuseaddr on the listener -prior- to binding the socket has allowed
     * us to attach to the same port as an already running instance of
     * Apache, or even another web server, we cannot identify that this
     * port was exclusively granted to this instance of Apache.
     *
     * So set reuseaddr, but do not attempt to do so until we have the
     * parent listeners successfully bound.
     */
    stat = apr_socket_opt_set(s, APR_SO_REUSEADDR, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, stat, p,
                    "make_sock: for address %pI, apr_socket_opt_set: (SO_REUSEADDR)", 
                     server->bind_addr);
        apr_socket_close(s);
        return stat;
    }
#endif

#if APR_HAS_SO_ACCEPTFILTER
#ifndef ACCEPT_FILTER_NAME
#define ACCEPT_FILTER_NAME "dataready"
#endif
    apr_socket_accept_filter(s, ACCEPT_FILTER_NAME, "");
#endif

    server->sd = s;
    server->active = 1;

#ifdef MPM_ACCEPT_FUNC
    server->accept_func = MPM_ACCEPT_FUNC;
#else
    server->accept_func = NULL;
#endif

    return APR_SUCCESS;
}

static apr_status_t close_listeners_on_exec(void *v)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_socket_close(lr->sd);
        lr->active = 0;
    }

    return APR_SUCCESS;
}


static void find_default_family(apr_pool_t *p)
{
#if APR_HAVE_IPV6
    /* We know the platform supports IPv6, but this particular
     * system may not have IPv6 enabled.  See if we can get an
     * AF_INET6 socket and bind to an ephemeral port.  (On most
     * systems, getting an AF_INET6 socket is a sufficient test.
     * On certain levels of OpenUNIX, getting the socket is
     * successful but bind always returns ENETUNREACH.)
     */
    if (default_family == APR_UNSPEC) {
        apr_status_t sock_rv;
        apr_socket_t *tmp_sock;
        apr_sockaddr_t *sa;

        if ((sock_rv = apr_socket_create(&tmp_sock, APR_INET6, SOCK_STREAM, p)) 
            == APR_SUCCESS &&
            apr_sockaddr_info_get(&sa, NULL, APR_INET6, 0, 0, p) == APR_SUCCESS &&
            apr_bind(tmp_sock, sa) == APR_SUCCESS) { 
            default_family = APR_INET6;
        }
        else {
            default_family = APR_INET;
        }
        if (sock_rv == APR_SUCCESS) {
            apr_socket_close(tmp_sock);
        }
    }
#endif
}


static const char *alloc_listener(process_rec *process, char *addr, apr_port_t port)
{
    ap_listen_rec **walk;
    ap_listen_rec *new;
    apr_status_t status;
    apr_port_t oldport;
    apr_sockaddr_t *sa;

    if (!addr) { /* don't bind to specific interface */
        find_default_family(process->pool);
        switch(default_family) {
        case APR_INET:
            addr = "0.0.0.0";
            break;

#if APR_HAVE_IPV6
        case APR_INET6:
            addr = "::";
            break;
#endif

        default:
            ap_assert(1 != 1); /* should not occur */
        }
    }

    /* see if we've got an old listener for this address:port */
    for (walk = &old_listeners; *walk; walk = &(*walk)->next) {
        sa = (*walk)->bind_addr;
        /* Some listeners are not real so they will not have a bind_addr. */
        if (sa) {
            apr_sockaddr_port_get(&oldport, sa);
            if (!strcmp(sa->hostname, addr) && port == oldport) {
                /* re-use existing record */
                new = *walk;
                *walk = new->next;
                new->next = ap_listeners;
                ap_listeners = new;
                return NULL;
            }
        }
    }

    /* this has to survive restarts */
    new = apr_palloc(process->pool, sizeof(ap_listen_rec));
    new->active = 0;
    if ((status = apr_sockaddr_info_get(&new->bind_addr, addr, APR_UNSPEC,
                                        port, 0, process->pool))
        != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, status, process->pool,
                      "alloc_listener: failed to set up sockaddr for %s",
                      addr);
        return "Listen setup failed";
    }
    if ((status = apr_socket_create(&new->sd,
                                    new->bind_addr->family,
                                    SOCK_STREAM, process->pool))
        != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, status, process->pool,
                      "alloc_listener: failed to get a socket for %s", addr);
        return "Listen setup failed";
    }

    new->next = ap_listeners;
    ap_listeners = new;
    return NULL;
}

static int ap_listen_open(apr_pool_t *pool, apr_port_t port)
{
    ap_listen_rec *lr;
    ap_listen_rec *next;
    int num_open;

    /* Don't allocate a default listener.  If we need to listen to a
     * port, then the user needs to have a Listen directive in their
     * config file.
     */
    num_open = 0;
    for (lr = ap_listeners; lr; lr = lr->next) {
        if (lr->active) {
            ++num_open;
        }
        else {
            if (make_sock(pool, lr) == APR_SUCCESS) {
                ++num_open;
                lr->active = 1;
            }
            else {
                /* fatal error */
                return -1;
            }
        }
    }

    /* close the old listeners */
    for (lr = old_listeners; lr; lr = next) {
        apr_socket_close(lr->sd);
        lr->active = 0;
        next = lr->next;
    }
    old_listeners = NULL;

    apr_pool_cleanup_register(pool, NULL, apr_pool_cleanup_null,
                              close_listeners_on_exec);

    return num_open ? 0 : -1;
}

int ap_setup_listeners(server_rec *s)
{
    ap_listen_rec *lr;
    int num_listeners = 0;

    if (ap_listen_open(s->process->pool, s->port)) {
       return 0;
    }

    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }

    return num_listeners;
}

void ap_listen_pre_config(void)
{
    old_listeners = ap_listeners;
    ap_listeners = NULL;
    ap_listenbacklog = DEFAULT_LISTENBACKLOG;
}


const char *ap_set_listener(cmd_parms *cmd, void *dummy, const char *ips)
{
    char *host, *scope_id;
    apr_port_t port;
    apr_status_t rv;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    rv = apr_parse_addr_port(&host, &scope_id, &port, ips, cmd->pool);
    if (rv != APR_SUCCESS) {
        return "Invalid address or port";
    }

    if (host && !strcmp(host, "*")) {
        host = NULL;
    }

    if (scope_id) {
        /* XXX scope id support is useful with link-local IPv6 addresses */
        return "Scope id is not supported";
    }

    if (!port) {
        return "Port must be specified";
    }

    return alloc_listener(cmd->server->process, host, port);
}

const char *ap_set_listenbacklog(cmd_parms *cmd, void *dummy, const char *arg)
{
    int b;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    b = atoi(arg);
    if (b < 1) {
        return "ListenBacklog must be > 0";
    }

    ap_listenbacklog = b;
    return NULL;
}

const char *ap_set_send_buffer_size(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    int s = atoi(arg);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    if (s < 512 && s != 0) {
        return "SendBufferSize must be >= 512 bytes, or 0 for system default.";
    }

    send_buffer_size = s;
    return NULL;
}
