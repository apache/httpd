/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 */

#ifndef APACHE_HTTP_VHOST_H
#define APACHE_HTTP_VHOST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Virtual Host package
 */

/**
 * called before any config is read
 * @param p Pool to allocate out of
 */
AP_DECLARE(void) ap_init_vhost_config(apr_pool_t *p);

/**
 * called after the config has been read to compile the tables needed to do 
 * the run-time vhost lookups
 * @param p The pool to allocate out of
 * @param main_server The start of the virtual host list
 * @deffunc ap_fini_vhost_config(apr_pool_t *p, server_rec *main_server)
 */
AP_DECLARE(void) ap_fini_vhost_config(apr_pool_t *p, server_rec *main_server);

/**
 * handle addresses in <VirtualHost> statement
 * @param p The pool to allocate out of
 * @param hostname The hostname in the VirtualHost statement
 * @param s The list of Virtual Hosts.
 */
const char *ap_parse_vhost_addrs(apr_pool_t *p, const char *hostname, server_rec *s);

/* handle NameVirtualHost directive */
const char *ap_set_name_virtual_host (cmd_parms *cmd, void *dummy,
				      const char *arg);

/**
 * given an ip address only, give our best guess as to what vhost it is 
 * @param conn The current connection
 */
AP_DECLARE(void) ap_update_vhost_given_ip(conn_rec *conn);

/**
 * ap_update_vhost_given_ip is never enough, and this is always called after 
 * the headers have been read.  It may change r->server.
 * @param r The current request
 */
AP_DECLARE(void) ap_update_vhost_from_headers(request_rec *r);

/**
 * Match the host in the header with the hostname of the server for this
 * request.
 * @param r The current request
 * @param host The hostname in the headers
 * @param port The port from the headers
 * @return return 1 if the host:port matches any of the aliases of r->server,
 * return 0 otherwise
 * @deffunc int ap_matches_request_vhost(request_rec *r, const char *host, apr_port_t port)
 */
AP_DECLARE(int) ap_matches_request_vhost(request_rec *r, const char *host,
    apr_port_t port);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_VHOST_H */
