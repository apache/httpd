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

#ifndef MOD_PROXY_H
#define MOD_PROXY_H 

/*
 * Main include file for the Apache proxy
 */

/*

   Note that the Explain() stuff is not yet complete.
   Also note numerous FIXMEs and CHECKMEs which should be eliminated.

   If TESTING is set, then garbage collection doesn't delete ... probably a good
   idea when hacking.

   This code is still experimental!

   Things to do:

   1. Make it garbage collect in the background, not while someone is waiting for
   a response!

   2. Check the logic thoroughly.

   3. Empty directories are only removed the next time round (but this does avoid
   two passes). Consider doing them the first time round.

   Ben Laurie <ben@algroup.co.uk> 30 Mar 96

   More things to do:

   0. Code cleanup (ongoing)

   1. add 230 response output for ftp now that it works

   2. Make the ftp proxy transparent, also same with (future) gopher & wais

   3. Use protocol handler struct a la Apache module handlers (Dirk van Gulik)

   4. Use a cache expiry database for more efficient GC (Jeremy Wohl)

   5. Bulletproof GC against SIGALRM

   Chuck Murcko <chuck@topsail.org> 15 April 1997

 */

#define TESTING	0
#undef EXPLAIN

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_cache.h"

#include "explain.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

extern module MODULE_VAR_EXPORT proxy_module;


/* for proxy_canonenc() */
enum enctype {
    enc_path, enc_search, enc_user, enc_fpath, enc_parm
};

#define HDR_APP (0)		/* append header, for proxy_add_header() */
#define HDR_REP (1)		/* replace header, for proxy_add_header() */

#ifdef CHARSET_EBCDIC
#define CRLF   "\r\n"
#else /*CHARSET_EBCDIC*/
#define CRLF   "\015\012"
#endif /*CHARSET_EBCDIC*/

#define	DEFAULT_FTP_DATA_PORT	20
#define	DEFAULT_FTP_PORT	21
#define	DEFAULT_GOPHER_PORT	70
#define	DEFAULT_NNTP_PORT	119
#define	DEFAULT_WAIS_PORT	210
#define	DEFAULT_HTTPS_PORT	443
#define	DEFAULT_SNEWS_PORT	563
#define	DEFAULT_PROSPERO_PORT	1525	/* WARNING: conflict w/Oracle */

#define DEFAULT_CACHE_COMPLETION (0.9)
/* Some WWW schemes and their default ports; this is basically /etc/services */
struct proxy_services {
    const char *scheme;
    int port;
};

/* static information about a remote proxy */
struct proxy_remote {
    const char *scheme;		/* the schemes handled by this proxy, or '*' */
    const char *protocol;	/* the scheme used to talk to this proxy */
    const char *hostname;	/* the hostname of this proxy */
    int port;			/* the port for this proxy */
};

struct proxy_alias {
    char *real;
    char *fake;
};

struct dirconn_entry {
    char *name;
    struct in_addr addr, mask;
    struct hostent *hostentry;
    int (*matcher) (struct dirconn_entry * This, request_rec *r);
};

struct noproxy_entry {
    char *name;
    struct in_addr addr;
};

struct nocache_entry {
    char *name;
    struct in_addr addr;
};

typedef struct {
    apr_array_header_t *proxies;
    apr_array_header_t *aliases;
    apr_array_header_t *raliases;
    apr_array_header_t *noproxies;
    apr_array_header_t *dirconn;
    apr_array_header_t *nocaches;
    apr_array_header_t *allowed_connect_ports;
    char *domain;		/* domain name to use in absence of a domain name in the request */
    int req;			/* true if proxy requests are enabled */
    float cache_completion;	/* Force cache completion after this point */
    enum {
      via_off,
      via_on,
      via_block,
      via_full
    } viaopt;                   /* how to deal with proxy Via: headers */
    size_t recv_buffer_size;
	ap_cache_handle_t *cache;
} proxy_server_conf;

typedef struct {
	float cache_completion; /* completion percentage */
	int content_length; /* length of the content */
} proxy_completion;

/* Function prototypes */

/* proxy_connect.c */

int ap_proxy_connect_handler(request_rec *r, ap_cache_el *c, char *url,
			  const char *proxyhost, int proxyport);

/* proxy_ftp.c */

int ap_proxy_ftp_canon(request_rec *r, char *url);
int ap_proxy_ftp_handler(request_rec *r, ap_cache_el *c, char *url);

/* proxy_http.c */

int ap_proxy_http_canon(request_rec *r, char *url, const char *scheme,
		     int def_port);
int ap_proxy_http_handler(request_rec *r, ap_cache_el  *c, char *url,
		       const char *proxyhost, int proxyport);

/* proxy_util.c */

int ap_proxy_hex2c(const char *x);
void ap_proxy_c2hex(int ch, char *x);
char *ap_proxy_canonenc(apr_pool_t *p, const char *x, int len, enum enctype t,
		     int isenc);
char *ap_proxy_canon_netloc(apr_pool_t *p, char **const urlp, char **userp,
			 char **passwordp, char **hostp, int *port);
const char *ap_proxy_date_canon(apr_pool_t *p, const char *x);
apr_table_t *ap_proxy_read_headers(request_rec *r, char *buffer, int size, BUFF *f);
long int ap_proxy_send_fb(proxy_completion *, BUFF *f, request_rec *r, ap_cache_el  *c);
void ap_proxy_send_headers(request_rec *r, const char *respline, apr_table_t *hdrs);
int ap_proxy_liststr(const char *list, const char *val);
void ap_proxy_hash(const char *it, char *val, int ndepth, int nlength);
int ap_proxy_hex2sec(const char *x);
void ap_proxy_sec2hex(int t, char *y);
const char *ap_proxy_host2addr(const char *host, struct hostent *reqhp);
int ap_proxy_cache_send(request_rec *r, ap_cache_el *c);
int ap_proxy_cache_should_cache(request_rec *r, apr_table_t *resp_hdrs,
                                const int is_HTTP1);
int ap_proxy_cache_update(ap_cache_el *c);
void ap_proxy_cache_error(ap_cache_el  **r);
int ap_proxyerror(request_rec *r, int statuscode, const char *message);
int ap_proxy_is_ipaddr(struct dirconn_entry *This, apr_pool_t *p);
int ap_proxy_is_domainname(struct dirconn_entry *This, apr_pool_t *p);
int ap_proxy_is_hostname(struct dirconn_entry *This, apr_pool_t *p);
int ap_proxy_is_word(struct dirconn_entry *This, apr_pool_t *p);
int ap_proxy_doconnect(apr_socket_t *sock, char *host, apr_uint32_t port, request_rec *r);
int ap_proxy_garbage_init(server_rec *, apr_pool_t *);
/* This function is called by apr_table_do() for all header lines */
int ap_proxy_send_hdr_line(void *p, const char *key, const char *value);
unsigned ap_proxy_bputs2(const char *data, BUFF *client, ap_cache_el  *cache);

#endif /*MOD_PROXY_H*/
