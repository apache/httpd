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
