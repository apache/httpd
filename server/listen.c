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

#include "httpd.h"
#include "http_config.h"
#include "ap_listen.h"
#include "http_log.h"

ap_listen_rec *ap_listeners;
static ap_listen_rec *old_listeners;
static int ap_listenbacklog;
static int send_buffer_size;

/* TODO: make_sock is just begging and screaming for APR abstraction */
static int make_sock(const struct sockaddr_in *server)
{
    int s;
    int one = 1;
    char addr[512];

    if (server->sin_addr.s_addr != htonl(INADDR_ANY))
	ap_snprintf(addr, sizeof(addr), "address %s port %d",
		inet_ntoa(server->sin_addr), ntohs(server->sin_port));
    else
	ap_snprintf(addr, sizeof(addr), "port %d", ntohs(server->sin_port));

#ifdef WIN32
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
                     "make_sock: failed to get a socket for %s", addr);
	return -1;
    }
#else
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
		    "make_sock: failed to get a socket for %s", addr);
	return -1;
    }
#endif

#ifdef SO_REUSEADDR
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
		    "make_sock: for %s, setsockopt: (SO_REUSEADDR)", addr);
	close(s);
	return -1;
    }
#endif
    one = 1;
#ifdef SO_KEEPALIVE
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(int)) < 0) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
		    "make_sock: for %s, setsockopt: (SO_KEEPALIVE)", addr);
	close(s);
	return -1;
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
#ifdef SO_SNDBUF
    if (send_buffer_size) {
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		(char *) &send_buffer_size, sizeof(int)) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
			"make_sock: failed to set SendBufferSize for %s, "
			"using default", addr);
	    /* not a fatal error */
	}
    }
#endif

    if (bind(s, (struct sockaddr *) server, sizeof(struct sockaddr_in)) == -1) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, NULL,
	    "make_sock: could not bind to %s", addr);
	close(s);
	return -1;
    }

    if (listen(s, ap_listenbacklog) == -1) {
	ap_log_error(APLOG_MARK, APLOG_ERR, NULL,
	    "make_sock: unable to listen for connections on %s", addr);
	close(s);
	return -1;
    }

    return s;
}


static void close_listeners_on_exec(void *v)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
	close(lr->fd);
    }
}


static void alloc_listener(struct sockaddr_in *local_addr)
{
    ap_listen_rec **walk;
    ap_listen_rec *new;

    /* see if we've got an old listener for this address:port */
    for (walk = &old_listeners; *walk; walk = &(*walk)->next) {
	if (!memcmp(&(*walk)->local_addr, local_addr, sizeof(local_addr))) {
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
    new->local_addr = *local_addr;
    new->fd = -1;
    new->next = ap_listeners;
    ap_listeners = new;
}


int ap_listen_open(pool *pconf, unsigned port)
{
    ap_listen_rec *lr;
    ap_listen_rec *next;
    int num_open;
    struct sockaddr_in local_addr;

    /* allocate a default listener if necessary */
    if (ap_listeners == NULL) {
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* XXX */
	local_addr.sin_port = htons(port ? port : DEFAULT_HTTP_PORT);
	alloc_listener(&local_addr);
    }

    num_open = 0;
    for (lr = ap_listeners; lr; lr = lr->next) {
	if (lr->fd < 0) {
	    lr->fd = make_sock(&lr->local_addr);
	}
	if (lr->fd >= 0) {
	    ++num_open;
	}
    }

    /* close the old listeners */
    for (lr = old_listeners; lr; lr = next) {
	close(lr->fd);
	next = lr->next;
	free(lr);
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
    struct sockaddr_in local_addr;

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

    local_addr.sin_family = AF_INET;
    if (ports == ips) { /* no address */
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
	local_addr.sin_addr.s_addr = ap_get_virthost_addr(ips, NULL);
    }
    port = atoi(ports);
    if (!port) {
	return "Port must be numeric";
    }
    local_addr.sin_port = htons(port);

    alloc_listener(&local_addr);

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
