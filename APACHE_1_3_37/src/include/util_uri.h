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
 * util_uri.h: External Interface of util_uri.c
 */

#ifndef UTIL_URI_H
#define UTIL_URI_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *name;
    unsigned short default_port;
} schemes_t;

#define	DEFAULT_FTP_DATA_PORT	20
#define	DEFAULT_FTP_PORT	21
#define	DEFAULT_GOPHER_PORT	70
#define	DEFAULT_NNTP_PORT	119
#define	DEFAULT_WAIS_PORT	210
#define	DEFAULT_SNEWS_PORT	563
#define	DEFAULT_PROSPERO_PORT	1525	/* WARNING: conflict w/Oracle */

#define DEFAULT_URI_SCHEME "http"

/* Flags passed to unparse_uri_components(): */
#define UNP_OMITSITEPART	(1U<<0)	/* suppress "scheme://user@site:port" */
#define	UNP_OMITUSER		(1U<<1)	/* Just omit user */
#define	UNP_OMITPASSWORD	(1U<<2)	/* Just omit password */
#define	UNP_OMITUSERINFO	(UNP_OMITUSER|UNP_OMITPASSWORD)	/* omit "user:password@" part */
#define	UNP_REVEALPASSWORD	(1U<<3)	/* Show plain text password (default: show XXXXXXXX) */
#define UNP_OMITPATHINFO	(1U<<4)	/* Show "scheme://user@site:port" only */
#define UNP_OMITQUERY	        (1U<<5)	/* Omit the "?queryarg" from the path */

typedef struct {
    char *scheme;		/* scheme ("http"/"ftp"/...) */
    char *hostinfo;             /* combined [user[:password]@]host[:port] */
    char *user;			/* user name, as in http://user:passwd@host:port/ */
    char *password;		/* password, as in http://user:passwd@host:port/ */
    char *hostname;		/* hostname from URI (or from Host: header) */
    char *port_str;		/* port string (integer representation is in "port") */
    char *path;			/* the request path (or "/" if only scheme://host was given) */
    char *query;		/* Everything after a '?' in the path, if present */
    char *fragment;		/* Trailing "#fragment" string, if present */

    struct hostent *hostent;

    unsigned short port;	/* The port number, numeric, valid only if port_str != NULL */
    
    unsigned is_initialized:1;

    unsigned dns_looked_up:1;
    unsigned dns_resolved:1;

} uri_components;

/* util_uri.c */
API_EXPORT(unsigned short) ap_default_port_for_scheme(const char *scheme_str);
API_EXPORT(unsigned short) ap_default_port_for_request(const request_rec *r);
API_EXPORT(struct hostent *) ap_pduphostent(pool *p, const struct hostent *hp);
API_EXPORT(struct hostent *) ap_pgethostbyname(pool *p, const char *hostname);
API_EXPORT(char *) ap_unparse_uri_components(pool *p, const uri_components *uptr,
    unsigned flags);
API_EXPORT(int) ap_parse_uri_components(pool *p, const char *uri, uri_components *uptr);
API_EXPORT(int) ap_parse_hostinfo_components(pool *p, const char *hostinfo, uri_components *uptr);
/* called by the core in main() */
extern void ap_util_uri_init(void);

#ifdef __cplusplus
}
#endif

#endif /*UTIL_URI_H*/
