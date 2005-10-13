/* Copyright 1999-2004 The Apache Software Foundation
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

/* called before any config is read */
API_EXPORT(void) ap_init_vhost_config(pool *p);

/* called after the config has been read */
API_EXPORT(void) ap_fini_vhost_config(pool *p, server_rec *main_server);

/* handle addresses in <VirtualHost> statement */
API_EXPORT(const char *) ap_parse_vhost_addrs(pool *p, const char *hostname, server_rec *s);

/* handle NameVirtualHost directive */
API_EXPORT_NONSTD(const char *) ap_set_name_virtual_host (cmd_parms *cmd, void *dummy, char *arg);

/* given an ip address only, give our best guess as to what vhost it is */
API_EXPORT(void) ap_update_vhost_given_ip(conn_rec *conn);

/* The above is never enough, and this is always called after the headers
 * have been read.  It may change r->server.
 */
API_EXPORT(void) ap_update_vhost_from_headers(request_rec *r);

/* return 1 if the host:port matches any of the aliases of r->server
 * return 0 otherwise
 */
API_EXPORT(int) ap_matches_request_vhost(request_rec *r, const char *host,
    unsigned port);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_VHOST_H */
