/* Copyright 1999-2004 Apache Software Foundation
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
