/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#include "apr_network_io.h"
#include "httpd.h"
#include "http_config.h"
#include "ap_listen.h"
#include "http_log.h"

ap_listen_rec *ap_listeners;
static ap_listen_rec *old_listeners;
static int ap_listenbacklog;
static int send_buffer_size;

/* TODO: make_sock is just begging and screaming for APR abstraction */
static ap_status_t make_sock(ap_context_t *p, ap_listen_rec *server)
{
    ap_socket_t *s = server->sd;
    int one = 1;
    char addr[512];
    ap_status_t stat;

    stat = ap_setsocketopt(s, APR_SO_REUSEADDR, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
		    "make_sock: for %s, setsockopt: (SO_REUSEADDR)", addr);
	ap_close_socket(s);
	return stat;
    }
    
    stat = ap_setsocketopt(s, APR_SO_KEEPALIVE, one);
    if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
		    "make_sock: for %s, setsockopt: (SO_KEEPALIVE)", addr);
	ap_close_socket(s);
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
	stat = ap_setsocketopt(s, SO_SNDBUF,  send_buffer_size);
        if (stat != APR_SUCCESS && stat != APR_ENOTIMPL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
			"make_sock: failed to set SendBufferSize for %s, "
			"using default", addr);
	    /* not a fatal error */
	}
    }

    if ((stat = ap_bind(s)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
	    "make_sock: could not bind to %s", addr);
	ap_close_socket(s);
	return stat;
    }

    if ((stat = ap_listen(s, ap_listenbacklog)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_ERR, NULL,
	    "make_sock: unable to listen for connections on %s", addr);
	ap_close_socket(s);
	return stat;
    }

    server->sd = s;
    return APR_SUCCESS;
}


static ap_status_t close_listeners_on_exec(void *v)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
	ap_close_socket(lr->sd);
    }
    return APR_SUCCESS;
}


static void alloc_listener(char *addr, unsigned int port)
{
    ap_listen_rec **walk;
    ap_listen_rec *new;
    char *oldaddr;
    unsigned int oldport;

    /* see if we've got an old listener for this address:port */
    for (walk = &old_listeners; *walk; walk = &(*walk)->next) {
        ap_getport((*walk)->sd, &oldport);
        ap_getipaddr((*walk)->sd, &oldaddr);
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
    new = malloc(sizeof(ap_listen_rec));
    if (ap_create_tcp_socket(NULL, &new->sd) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
                 "make_sock: failed to get a socket for %s", addr);
        return;
    }
    ap_setport(new->sd, port);
    ap_setipaddr(new->sd, addr);
    new->next = ap_listeners;
    ap_listeners = new;
}


int ap_listen_open(ap_context_t *pconf, unsigned port)
{
    ap_listen_rec *lr;
    ap_listen_rec *next;
    int num_open;
    ap_status_t stat;
    /* allocate a default listener if necessary */
    if (ap_listeners == NULL) {
	alloc_listener(APR_ANYADDR, port ? port : DEFAULT_HTTP_PORT);
    }

    num_open = 0;
    for (lr = ap_listeners; lr; lr = lr->next) {
	stat = make_sock(pconf, lr);
	if (stat == APR_SUCCESS) {
	    ++num_open;
	}
    }

    /* close the old listeners */
    for (lr = old_listeners; lr; lr = next) {
	ap_close_socket(lr->sd);
	next = lr->next;
/*	free(lr);*/
    }
    old_listeners = NULL;

    ap_register_cleanup(pconf, NULL, ap_null_cleanup, close_listeners_on_exec);

    return num_open ? 0 : -1;
}


void ap_listen_pre_config(void)
{
    old_listeners = ap_listeners;
    ap_listeners = NULL;
    ap_listenbacklog = DEFAULT_LISTENBACKLOG;
}


const char *ap_set_listener(cmd_parms *cmd, void *dummy, char *ips)
{
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
        alloc_listener(APR_ANYADDR, port);
    }
    else {
        ips[(ports - ips) - 1] = '\0';
	alloc_listener(ips, port);
    }

    return NULL;
}

const char *ap_set_listenbacklog(cmd_parms *cmd, void *dummy, char *arg) 
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

const char *ap_set_send_buffer_size(cmd_parms *cmd, void *dummy, char *arg)
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
