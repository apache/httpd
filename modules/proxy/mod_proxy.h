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

#ifndef MOD_PROXY_H
#define MOD_PROXY_H 

/*
 * Main include file for the Apache proxy
 */

/*

   Also note numerous FIXMEs and CHECKMEs which should be eliminated.

   This code is once again experimental!

   Things to do:

   1. Make it completely work (for FTP too)

   2. HTTP/1.1

   Chuck Murcko <chuck@topsail.org> 02-06-01

 */

#define CORE_PRIVATE

#include "apr_hooks.h"
#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_md5.h"
#include "apr_network_io.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_uri.h"
#include "apr_date.h"
#include "apr_strmatch.h"
#include "apr_fnmatch.h"
#include "apr_reslist.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "ap_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_main.h"
#include "http_log.h"
#include "http_connection.h"
#include "util_filter.h"
#include "util_ebcdic.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* for proxy_canonenc() */
enum enctype {
    enc_path, enc_search, enc_user, enc_fpath, enc_parm
};

#if APR_CHARSET_EBCDIC
#define CRLF   "\r\n"
#else /*APR_CHARSET_EBCDIC*/
#define CRLF   "\015\012"
#endif /*APR_CHARSET_EBCDIC*/

/* default Max-Forwards header setting */
#define DEFAULT_MAX_FORWARDS	10

/* static information about a remote proxy */
struct proxy_remote {
    const char *scheme;		/* the schemes handled by this proxy, or '*' */
    const char *protocol;	/* the scheme used to talk to this proxy */
    const char *hostname;	/* the hostname of this proxy */
    apr_port_t  port;		/* the port for this proxy */
    regex_t *regexp;		/* compiled regex (if any) for the remote */
    int use_regex;		/* simple boolean. True if we have a regex pattern */
};

struct proxy_alias {
    const char  *real;
    const char  *fake;
};

struct dirconn_entry {
    char *name;
    struct in_addr addr, mask;
    struct apr_sockaddr_t *hostaddr;
    int (*matcher) (struct dirconn_entry * This, request_rec *r);
};

struct noproxy_entry {
    const char *name;
    struct apr_sockaddr_t *addr;
};

typedef struct {
    apr_array_header_t *proxies;
    apr_array_header_t *sec_proxy;
    apr_array_header_t *aliases;
    apr_array_header_t *raliases;
    apr_array_header_t *noproxies;
    apr_array_header_t *dirconn;
    apr_array_header_t *allowed_connect_ports;
    apr_array_header_t *workers;
    apr_array_header_t *balancers;
    const char *domain;		/* domain name to use in absence of a domain name in the request */
    int req;			/* true if proxy requests are enabled */
    char req_set;
    enum {
      via_off,
      via_on,
      via_block,
      via_full
    } viaopt;                   /* how to deal with proxy Via: headers */
    char viaopt_set;
    apr_size_t recv_buffer_size;
    char recv_buffer_size_set;
    apr_size_t io_buffer_size;
    char io_buffer_size_set;
    long maxfwd;
    char maxfwd_set;
    /** 
     * the following setting masks the error page
     * returned from the 'proxied server' and just 
     * forwards the status code upwards.
     * This allows the main server (us) to generate
     * the error page, (so it will look like a error
     * returned from the rest of the system 
     */
    int error_override;
    int error_override_set;
    int preserve_host;
    int preserve_host_set;
    apr_interval_time_t timeout;
    char timeout_set;
    enum {
      bad_error,
      bad_ignore,
      bad_body
    } badopt;                   /* how to deal with bad headers */
    char badopt_set;
/* putting new stuff on the end maximises binary back-compatibility.
 * the strmatch_patterns are really a const just to have a
 * case-independent strstr.
 */
    apr_array_header_t* cookie_paths;
    apr_array_header_t* cookie_domains;
    const apr_strmatch_pattern* cookie_path_str;
    const apr_strmatch_pattern* cookie_domain_str;

} proxy_server_conf;

typedef struct proxy_balancer  proxy_balancer;
typedef struct proxy_worker    proxy_worker;
typedef struct proxy_conn_pool proxy_conn_pool;

typedef struct {
    const char *p;            /* The path */
    int         p_is_fnmatch; /* Is this path an fnmatch candidate? */
    regex_t    *r;            /* Is this a regex? */
} proxy_dir_conf;

typedef struct {
    conn_rec     *connection;
    const char   *hostname;
    apr_port_t   port;
    int          is_ssl;
    apr_pool_t   *pool;     /* Subpool used for creating socket */
    apr_socket_t *sock;     /* Connection socket */
    apr_uint32_t flags;     /* Conection flags */
    int          close;     /* Close 'this' connection */
    proxy_worker *worker;   /* Connection pool this connection belogns to */
    void         *data;     /* per scheme connection data */
} proxy_conn_rec;

typedef struct {
        float cache_completion; /* completion percentage */
        int content_length; /* length of the content */
} proxy_completion;

/* Connection pool */
struct proxy_conn_pool {
    apr_pool_t     *pool;   /* The pool used in constructor and destructor calls */
    apr_sockaddr_t *addr;   /* Preparsed remote address info */
#if APR_HAS_THREADS
    apr_reslist_t  *res;    /* Connection resource list */
#endif
    proxy_conn_rec *conn;   /* Single connection for prefork mpm's */
};

/* Worker configuration */
struct proxy_worker {
    int             status;
    apr_time_t      error_time; /* time of the last error */
    apr_interval_time_t retry;  /* retry interval */
    int             retries;    /* number of retries on this worker */
    int             lbfactor;   /* initial load balancing factor */
    const char      *name;
    const char      *scheme;    /* scheme to use ajp|http|https */
    const char      *hostname;  /* remote backend address */
    apr_port_t      port;
    int             min;        /* Desired minimum number of available connections */
    int             smax;       /* Soft maximum on the total number of connections */
    int             hmax;       /* Hard maximum on the total number of connections */
    apr_interval_time_t ttl;    /* maximum amount of time in seconds a connection
                                 * may be available while exceeding the soft limit */
    apr_interval_time_t timeout; /* connection timeout */
    char                timeout_set;
    apr_interval_time_t acquire; /* acquire timeout when the maximum number of connections is exceeded */
    char                acquire_set;
    apr_size_t          recv_buffer_size;
    char                recv_buffer_size_set;
    apr_size_t          io_buffer_size;
    char                io_buffer_size_set;
    char                keepalive;
    proxy_conn_pool *cp;        /* Connection pool to use */
    void            *opaque;    /* per scheme worker data */
};

/* Runtime worker status informations. Shared in scoreboard */
typedef struct {
    proxy_balancer  *b;         /* balancer containing this worker */
    proxy_worker    *w;
    double          lbfactor;   /* dynamic lbfactor */
    double          lbsatus;    /* Current lbstatus */
    apr_size_t      transfered; /* Number of bytes transfered to remote */
    apr_size_t      readed;     /* Number of bytes readed from remote */
} proxy_runtime_worker;

struct proxy_balancer {
    apr_array_header_t *workers; /* array of proxy_runtime_workers */
    const char *name;            /* name of the load balancer */
    const char *sticky;          /* sticky session identifier */
    int         sticky_force;    /* Disable failover for sticky sessions */
    apr_interval_time_t timeout; /* Timeout for waiting on free connection */
#if APR_HAS_THREADS
    apr_thread_mutex_t  *mutex;  /* Thread lock for updating lb params */
#endif
};

/* hooks */

/* Create a set of PROXY_DECLARE(type), PROXY_DECLARE_NONSTD(type) and 
 * PROXY_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define PROXY_DECLARE(type)            type
#define PROXY_DECLARE_NONSTD(type)     type
#define PROXY_DECLARE_DATA
#elif defined(PROXY_DECLARE_STATIC)
#define PROXY_DECLARE(type)            type __stdcall
#define PROXY_DECLARE_NONSTD(type)     type
#define PROXY_DECLARE_DATA
#elif defined(PROXY_DECLARE_EXPORT)
#define PROXY_DECLARE(type)            __declspec(dllexport) type __stdcall
#define PROXY_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define PROXY_DECLARE_DATA             __declspec(dllexport)
#else
#define PROXY_DECLARE(type)            __declspec(dllimport) type __stdcall
#define PROXY_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define PROXY_DECLARE_DATA             __declspec(dllimport)
#endif

/**
 * Hook an optional proxy hook.  Unlike static hooks, this uses a macro
 * instead of a function.
 */
#define PROXY_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(proxy,name,fn,pre,succ,order)

APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, scheme_handler, (request_rec *r, 
                          proxy_server_conf *conf, char *url, 
                          const char *proxyhost, apr_port_t proxyport))
APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, canon_handler, (request_rec *r, 
                          char *url))

APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, create_req, (request_rec *r, request_rec *pr))
APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, fixups, (request_rec *r)) 

/**
 * pre request hook.
 * It will return the most suitable worker at the moment
 * and coresponding balancer.
 * The url is rewritten from balancer://cluster/uri to scheme://host:port/uri
 * and then the scheme_handler is called.
 *
 */
APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, pre_request, (proxy_worker **worker,
                          struct proxy_balancer **balancer,
                          request_rec *r,
                          proxy_server_conf *conf, char **url))                          
/**
 * post request hook.
 * It is called after request for updating runtime balancer status.
 */
APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, post_request, (proxy_worker *worker,
                          struct proxy_balancer *balancer, request_rec *r,
                          proxy_server_conf *conf))


/* proxy_util.c */

PROXY_DECLARE(request_rec *)ap_proxy_make_fake_req(conn_rec *c, request_rec *r);
PROXY_DECLARE(int) ap_proxy_hex2c(const char *x);
PROXY_DECLARE(void) ap_proxy_c2hex(int ch, char *x);
PROXY_DECLARE(char *)ap_proxy_canonenc(apr_pool_t *p, const char *x, int len, enum enctype t,
			int isenc);
PROXY_DECLARE(char *)ap_proxy_canon_netloc(apr_pool_t *p, char **const urlp, char **userp,
			 char **passwordp, char **hostp, apr_port_t *port);
PROXY_DECLARE(const char *)ap_proxy_date_canon(apr_pool_t *p, const char *x);
PROXY_DECLARE(int) ap_proxy_liststr(const char *list, const char *val);
PROXY_DECLARE(char *)ap_proxy_removestr(apr_pool_t *pool, const char *list, const char *val);
PROXY_DECLARE(int) ap_proxy_hex2sec(const char *x);
PROXY_DECLARE(void) ap_proxy_sec2hex(int t, char *y);
PROXY_DECLARE(int) ap_proxyerror(request_rec *r, int statuscode, const char *message);
PROXY_DECLARE(int) ap_proxy_is_ipaddr(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_domainname(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_hostname(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_is_word(struct dirconn_entry *This, apr_pool_t *p);
PROXY_DECLARE(int) ap_proxy_checkproxyblock(request_rec *r, proxy_server_conf *conf, apr_sockaddr_t *uri_addr);
PROXY_DECLARE(int) ap_proxy_pre_http_request(conn_rec *c, request_rec *r);
PROXY_DECLARE(apr_status_t) ap_proxy_string_read(conn_rec *c, apr_bucket_brigade *bb, char *buff, size_t bufflen, int *eos);
PROXY_DECLARE(void) ap_proxy_table_unmerge(apr_pool_t *p, apr_table_t *t, char *key);
/* DEPRECATED (will be replaced with ap_proxy_connect_backend */
PROXY_DECLARE(int) ap_proxy_connect_to_backend(apr_socket_t **, const char *, apr_sockaddr_t *, const char *, proxy_server_conf *, server_rec *, apr_pool_t *);
PROXY_DECLARE(int) ap_proxy_ssl_enable(conn_rec *c);
PROXY_DECLARE(int) ap_proxy_ssl_disable(conn_rec *c);

/* Connection pool API */
PROXY_DECLARE(proxy_worker *) ap_proxy_get_worker(apr_pool_t *p, proxy_server_conf *conf, const char *url);
PROXY_DECLARE(const char *) ap_proxy_add_worker(proxy_worker **worker, apr_pool_t *p, proxy_server_conf *conf, const char *url);
PROXY_DECLARE(struct proxy_balancer *) ap_proxy_get_balancer(apr_pool_t *p, proxy_server_conf *conf, const char *url);
PROXY_DECLARE(const char *) ap_proxy_add_balancer(proxy_balancer **balancer, apr_pool_t *p, proxy_server_conf *conf, const char *url);
PROXY_DECLARE(void) ap_proxy_add_worker_to_balancer(proxy_balancer *balancer, proxy_worker *worker);
PROXY_DECLARE(int) ap_proxy_pre_request(proxy_worker **worker, proxy_balancer **balancer, request_rec *r, proxy_server_conf *conf, char **url);
PROXY_DECLARE(apr_status_t) ap_proxy_determine_connection(apr_pool_t *p, request_rec *r, proxy_server_conf *conf, proxy_worker *worker, proxy_conn_rec *conn,
                                                          apr_pool_t *ppool, apr_uri_t *uri, char **url, const char *proxyname, apr_port_t proxyport,
                                                          char *server_portstr, int server_portstr_size);
PROXY_DECLARE(apr_status_t) ap_proxy_destroy_connection(proxy_conn_rec *conn);
PROXY_DECLARE(apr_status_t) ap_proxy_close_connection(proxy_conn_rec *conn);
PROXY_DECLARE(int) ap_proxy_connect_backend(const char *proxy_function, proxy_conn_rec *conn, proxy_worker *worker,
                                            proxy_server_conf *conf, server_rec *s);

/* For proxy_util */
extern module PROXY_DECLARE_DATA proxy_module;

#endif /*MOD_PROXY_H*/
