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

   Note numerous FIXMEs and CHECKMEs which should be eliminated.

   If TESTING is set, then garbage collection doesn't delete ... probably a good
   idea when hacking.

 */

#define TESTING 0

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

#include "explain.h"

extern module MODULE_VAR_EXPORT proxy_module;


/* for proxy_canonenc() */
enum enctype {
    enc_path, enc_search, enc_user, enc_fpath, enc_parm
};

#define HDR_APP (0)             /* append header, for proxy_add_header() */
#define HDR_REP (1)             /* replace header, for proxy_add_header() */

/* number of characters in the hash */
#define HASH_LEN (22*2)

/* maximum  'CacheDirLevels*CacheDirLength' value */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */

#define SEC_ONE_DAY             86400   /* one day, in seconds */
#define SEC_ONE_HR              3600    /* one hour, in seconds */

#define DEFAULT_FTP_DATA_PORT   20
#define DEFAULT_FTP_PORT        21
#define DEFAULT_GOPHER_PORT     70
#define DEFAULT_NNTP_PORT       119
#define DEFAULT_WAIS_PORT       210
#define DEFAULT_HTTPS_PORT      443
#define DEFAULT_SNEWS_PORT      563
#define DEFAULT_PROSPERO_PORT   1525    /* WARNING: conflict w/Oracle */

/* Some WWW schemes and their default ports; this is basically /etc/services */
struct proxy_services {
    const char *scheme;
    int port;
};

/* static information about a remote proxy */
struct proxy_remote {
    const char *scheme;         /* the schemes handled by this proxy, or '*' */
    const char *protocol;       /* the scheme used to talk to this proxy */
    const char *hostname;       /* the hostname of this proxy */
    int port;                   /* the port for this proxy */
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

#define DEFAULT_CACHE_SPACE 5
#define DEFAULT_CACHE_MAXEXPIRE SEC_ONE_DAY
#define DEFAULT_CACHE_EXPIRE    SEC_ONE_HR
#define DEFAULT_CACHE_LMFACTOR (0.1)
#define DEFAULT_CACHE_COMPLETION (0.9)
#define DEFAULT_CACHE_GCINTERVAL SEC_ONE_HR

#ifndef MAX
#define MAX(a,b)                ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)                ((a) < (b) ? (a) : (b))
#endif

/* static information about the local cache */
struct cache_conf {
    const char *root;           /* the location of the cache directory */
    off_t space;                /* Maximum cache size (in 1024 bytes) */
    char space_set;
    time_t maxexpire;           /* Maximum time to keep cached files in secs */
    char maxexpire_set;
    time_t defaultexpire;       /* default time to keep cached file in secs */
    char defaultexpire_set;
    double lmfactor;            /* factor for estimating expires date */
    char lmfactor_set;
    time_t gcinterval;          /* garbage collection interval, in seconds */
    char gcinterval_set;
    int dirlevels;              /* Number of levels of subdirectories */
    char dirlevels_set;
    int dirlength;              /* Length of subdirectory names */
    char dirlength_set;
    float cache_completion;     /* Force cache completion after this point */
    char cache_completion_set;
};

typedef struct {
    struct cache_conf cache;    /* cache configuration */
    array_header *proxies;
    array_header *aliases;
    array_header *raliases;
    array_header *noproxies;
    array_header *dirconn;
    array_header *nocaches;
    array_header *allowed_connect_ports;
    char *domain;               /* domain name to use in absence of a domain name in the request */
    int req;                    /* true if proxy requests are enabled */
    char req_set;
    enum {
      via_off,
      via_on,
      via_block,
      via_full
    } viaopt;                   /* how to deal with proxy Via: headers */
    char viaopt_set;
    size_t recv_buffer_size;
    char recv_buffer_size_set;
    size_t io_buffer_size;
    char io_buffer_size_set;
} proxy_server_conf;

struct hdr_entry {
    const char *field;
    const char *value;
};

/* caching information about a request */
typedef struct {
    request_rec *req;           /* the request */
    char *url;                  /* the URL requested */
    char *filename;             /* name of the cache file,
                                   or NULL if no cache */
    char *tempfile;             /* name of the temporary file,
                                   or NULL if not caching */
    time_t ims;                 /* if-Modified-Since date of request,
                                   -1 if no header */
    time_t ius;                 /* if-Unmodified-Since date of request,
                                   -1 if no header */
    const char *im;             /* if-Match etag of request,
                                   NULL if no header */
    const char *inm;            /* if-None-Match etag of request,
                                   NULL if no header */
    BUFF *fp;                   /* the cache file descriptor if the file
                                   is cached and may be returned,
                                   or NULL if the file is not cached
                                   (or must be reloaded) */
    BUFF *origfp;               /* the old cache file descriptor if the file has
                                   been revalidated and is being rewritten to
                                   disk */
    time_t expire;              /* calculated expire date of cached entity */
    time_t lmod;                /* last-modified date of cached entity */
    time_t date;                /* the date the cached file was last touched */
    time_t req_time;            /* the time the request started */
    time_t resp_time;           /* the time the response was received */
    int version;                /* update count of the file */
    off_t len;                  /* content length */
    char *protocol;             /* Protocol, and major/minor number,
                                   e.g. HTTP/1.1 */
    int status;                 /* the status of the cached file */
    unsigned int written;       /* total *content* bytes written to cache */
    float cache_completion;     /* specific to this request */
    char *resp_line;            /* the whole status line
                                   (protocol, code + message) */
    table *req_hdrs;            /* the original request headers */
    table *hdrs;                /* the original HTTP response headers
                                   of the file */
    char *xcache;               /* the X-Cache header value
                                   to be sent to client */
} cache_req;

struct per_thread_data {
    struct hostent hpbuf;
    u_long ipaddr;
    char *charpbuf[2];
};
/* Function prototypes */

/* proxy_cache.c */

void ap_proxy_cache_tidy(cache_req *c);
int ap_proxy_cache_check(request_rec *r, char *url, struct cache_conf *conf,
                      cache_req **cr);
int ap_proxy_cache_update(cache_req *c, table *resp_hdrs,
                       const int is_HTTP1, int nocache);
void ap_proxy_garbage_coll(request_rec *r);

/* proxy_connect.c */

int ap_proxy_connect_handler(request_rec *r, cache_req *c, char *url,
                          const char *proxyhost, int proxyport);

/* proxy_ftp.c */

int ap_proxy_ftp_canon(request_rec *r, char *url);
int ap_proxy_ftp_handler(request_rec *r, cache_req *c, char *url);

/* proxy_http.c */

int ap_proxy_http_canon(request_rec *r, char *url, const char *scheme,
                     int def_port);
int ap_proxy_http_handler(request_rec *r, cache_req *c, char *url,
                       const char *proxyhost, int proxyport);

/* proxy_util.c */

int ap_proxy_hex2c(const char *x);
void ap_proxy_c2hex(int ch, char *x);
char *ap_proxy_canonenc(pool *p, const char *x, int len, enum enctype t,
                        enum proxyreqtype isenc);
char *ap_proxy_canon_netloc(pool *p, char **const urlp, char **userp,
                         char **passwordp, char **hostp, int *port);
const char *ap_proxy_date_canon(pool *p, const char *x);
table *ap_proxy_read_headers(request_rec *r, char *buffer, int size, BUFF *f);
long int ap_proxy_send_fb(BUFF *f, request_rec *r, cache_req *c, off_t len, int nowrite, int chunked, size_t recv_buffer_size);
void ap_proxy_write_headers(cache_req *c, const char *respline, table *t);
int ap_proxy_liststr(const char *list, const char *key, char **val);
void ap_proxy_hash(const char *it, char *val, int ndepth, int nlength);
int ap_proxy_hex2sec(const char *x);
void ap_proxy_sec2hex(int t, char *y);
cache_req *ap_proxy_cache_error(cache_req *r);
int ap_proxyerror(request_rec *r, int statuscode, const char *message);
const char *ap_proxy_host2addr(const char *host, struct hostent *reqhp);
int ap_proxy_is_ipaddr(struct dirconn_entry *This, pool *p);
int ap_proxy_is_domainname(struct dirconn_entry *This, pool *p);
int ap_proxy_is_hostname(struct dirconn_entry *This, pool *p);
int ap_proxy_is_word(struct dirconn_entry *This, pool *p);
int ap_proxy_doconnect(int sock, struct sockaddr_in *addr, request_rec *r);
int ap_proxy_garbage_init(server_rec *, pool *);
/* This function is called by ap_table_do() for all header lines */
int ap_proxy_send_hdr_line(void *p, const char *key, const char *value);
unsigned ap_proxy_bputs2(const char *data, BUFF *client, cache_req *cache);
time_t ap_proxy_current_age(cache_req *c, const time_t age_value);
BUFF *ap_proxy_open_cachefile(request_rec *r, char *filename);
BUFF *ap_proxy_create_cachefile(request_rec *r, char *filename);
void ap_proxy_clear_connection(pool *p, table *headers);
int ap_proxy_table_replace(table *base, table *overlay);
void ap_proxy_table_unmerge(pool *p, table *t, char *key);
int ap_proxy_read_response_line(BUFF *f, request_rec *r, char *buffer, int size, int *backasswards, int *major, int *minor);

/* WARNING - PRIVATE DEFINITION BELOW */

/* XXX: if you tweak this you should look at is_empty_table() and table_elts()
 * in ap_alloc.h
 *
 * NOTE: this private definition is a duplicate of the one in alloc.c
 * It's here for ap_proxy_table_replace() to avoid breaking binary compat
 */
struct table {
    /* This has to be first to promote backwards compatibility with
     * older modules which cast a table * to an array_header *...
     * they should use the table_elts() function for most of the
     * cases they do this for.
     */
    array_header a;
#ifdef MAKE_TABLE_PROFILE
    void *creator;
#endif
};

#endif /*MOD_PROXY_H*/
