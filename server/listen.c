/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "ap_listen.h"
#include "apr_strings.h"
#include "http_log.h"
#include "mpm.h"
#ifdef HAVE_STRING_H
#include <string.h>
#endif

ap_listen_rec *ap_listeners;
static ap_listen_rec *old_listeners;
static int ap_listenbacklog;
static int send_buffer_size;

/* TODO: make_sock is just begging and screaming for APR abstraction */
static apr_status_t make_sock(apr_pool_t *p, ap_listen_rec *server)
{
    apr_socket_t *s = server->sd;
    int one = 1;
    char addr[512];
    apr_status_t stat;
    apr_uint32_t port;
    char *ipaddr;

    apr_get_local_port(&port,s);
    apr_get_local_ipaddr(&ipaddr,s);
    apr_snprintf(addr, sizeof(addr), "address %s port %u", ipaddr,
		(unsigned) port);

    stat = apr_setsocketopt(s, APR_SO_REUSEADDR, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, stat, NULL,
		    "make_sock: for %s, setsockopt: (SO_REUSEADDR)", addr);
	apr_close_socket(s);
	return stat;
    }
    
    stat = apr_setsocketopt(s, APR_SO_KEEPALIVE, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, stat, NULL,
		    "make_sock: for %s, setsockopt: (SO_KEEPALIVE)", addr);
	apr_close_socket(s);
	return stat;
    }

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
	stat = apr_setsocketopt(s, APR_SO_SNDBUF,  send_buffer_size);
        if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, stat, NULL,
			"make_sock: failed to set SendBufferSize for %s, "
			"using default", addr);
	    /* not a fatal error */
	}
    }

    if ((stat = apr_bind(s)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, stat, NULL,
	    "make_sock: could not bind to %s", addr);
	apr_close_socket(s);
	return stat;
    }

    if ((stat = apr_listen(s, ap_listenbacklog)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_ERR, stat, NULL,
	    "make_sock: unable to listen for connections on %s", addr);
	apr_close_socket(s);
	return stat;
    }

    server->sd = s;
    server->active = 1;
    return APR_SUCCESS;
}


static apr_status_t close_listeners_on_exec(void *v)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
	apr_close_socket(lr->sd);
	lr->active = 0;
    }
    return APR_SUCCESS;
}


static void alloc_listener(process_rec *process, char *addr, unsigned int port)
{
    ap_listen_rec **walk;
    ap_listen_rec *new;
    apr_status_t status;
    char *oldaddr;
    unsigned int oldport;

    /* see if we've got an old listener for this address:port */
    for (walk = &old_listeners; *walk; walk = &(*walk)->next) {
        apr_get_local_port(&oldport, (*walk)->sd);
	apr_get_local_ipaddr(&oldaddr,(*walk)->sd);
	if (!strcmp(oldaddr, addr) && port == oldport) {
	    /* re-use existing record */
	    new = *walk;
	    *walk = new->next;
	    new->next = ap_listeners;
	    ap_listeners = new;
	    return;
	}
    }

    /* this has to survive restarts */
    new = apr_palloc(process->pool, sizeof(ap_listen_rec));
    new->active = 0;
    if ((status = apr_create_tcp_socket(&new->sd, process->pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, NULL,
                 "make_sock: failed to get a socket for %s", addr);
        return;
    }
    apr_set_local_port(new->sd, port);
    apr_set_local_ipaddr(new->sd, addr);
    new->next = ap_listeners;
    ap_listeners = new;
}

#if !defined(WIN32) && !defined(PREFORK_MPM) && !defined(SPMT_OS2_MPM)
static
#endif
int ap_listen_open(process_rec *process, unsigned port)
{
    apr_pool_t *pconf = process->pconf;
    ap_listen_rec *lr;
    ap_listen_rec *next;
    int num_open;

    /* allocate a default listener if necessary */
    if (ap_listeners == NULL) {
	alloc_listener(process, APR_ANYADDR, port ? port : DEFAULT_HTTP_PORT);
    }

    num_open = 0;
    for (lr = ap_listeners; lr; lr = lr->next) {
	if (lr->active) {
	    ++num_open;
	}
	else {
	    if (make_sock(pconf, lr) == APR_SUCCESS) {
		++num_open;
		lr->active = 1;
	    }
	}
    }

    /* close the old listeners */
    for (lr = old_listeners; lr; lr = next) {
	apr_close_socket(lr->sd);
	lr->active = 0;
	next = lr->next;
/*	free(lr);*/
    }
    old_listeners = NULL;

    apr_register_cleanup(pconf, NULL, apr_null_cleanup, close_listeners_on_exec);

    return num_open ? 0 : -1;
}

#if !defined(WIN32) && !defined(PREFORK_MPM)
int ap_setup_listeners(server_rec *s)
{
    ap_listen_rec *lr;
    int num_listeners = 0;
    if (ap_listen_open(s->process, s->port)) {
       return 0;
    }
    for (lr = ap_listeners; lr; lr = lr->next) {
        num_listeners++;
    }
    return num_listeners;
}
#endif

void ap_listen_pre_config(void)
{
    old_listeners = ap_listeners;
    ap_listeners = NULL;
    ap_listenbacklog = DEFAULT_LISTENBACKLOG;
}


const char *ap_set_listener(cmd_parms *cmd, void *dummy, const char *ips_)
{
    char *ips=apr_pstrdup(cmd->pool, ips_);
    char *ports;
    unsigned short port;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ports = strchr(ips, ':');
    if (ports != NULL) {
	if (ports == ips) {
	    return "Missing IP address";
	}
	else if (ports[1] == '\0') {
	    return "Address must end in :<port-number>";
	}
	*(ports++) = '\0';
    }
    else {
	ports = ips;
    }

    port = atoi(ports);
    if (!port) {
	return "Port must be numeric";
    }

    if (ports == ips) { /* no address */
        alloc_listener(cmd->server->process, APR_ANYADDR, port);
    }
    else {
        ips[(ports - ips) - 1] = '\0';
	alloc_listener(cmd->server->process, ips, port);
    }

    return NULL;
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

const char *ap_set_send_buffer_size(cmd_parms *cmd, void *dummy, const char *arg)
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
