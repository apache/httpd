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

#ifndef MOD_PROXY_H
#define MOD_PROXY_H 

/**
 * @file  mod_proxy.h
 * @brief Proxy Extension Module for Apache
 *
 * @defgroup MOD_PROXY mod_proxy
 * @ingroup  APACHE_MODS
 * @{
 */

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
#include "apr_global_mutex.h"

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
#include "ap_provider.h"

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
/* Set this to -1, which complies with RFC2616 by not setting
 * max-forwards if the client didn't send it to us.
 */
#define DEFAULT_MAX_FORWARDS    -1

/* static information about a remote proxy */
struct proxy_remote {
    const char *scheme;     /* the schemes handled by this proxy, or '*' */
    const char *protocol;   /* the scheme used to talk to this proxy */
    const char *hostname;   /* the hostname of this proxy */
    ap_regex_t *regexp;     /* compiled regex (if any) for the remote */
    int use_regex;          /* simple boolean. True if we have a regex pattern */
    apr_port_t  port;       /* the port for this proxy */
};

#define PROXYPASS_NOCANON 0x01
#define PROXYPASS_INTERPOLATE 0x02
struct proxy_alias {
    const char  *real;
    const char  *fake;
    ap_regex_t  *regex;
    unsigned int flags;
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

typedef struct proxy_balancer  proxy_balancer;
typedef struct proxy_worker    proxy_worker;
typedef struct proxy_conn_pool proxy_conn_pool;
typedef struct proxy_balancer_method proxy_balancer_method;

typedef struct {
    apr_array_header_t *proxies;
    apr_array_header_t *sec_proxy;
    apr_array_header_t *aliases;
    apr_array_header_t *noproxies;
    apr_array_header_t *dirconn;
    apr_array_header_t *workers;    /* non-balancer workers, eg ProxyPass http://example.com */
    apr_array_header_t *balancers;  /* list of balancers @ config time */
    proxy_worker       *forward;    /* forward proxy worker */
    proxy_worker       *reverse;    /* reverse "module-driven" proxy worker */
    const char *domain;     /* domain name to use in absence of a domain name in the request */
    apr_pool_t *pool;       /* Pool used for allocating this struct */
    int req;                /* true if proxy requests are enabled */
    enum {
      via_off,
      via_on,
      via_block,
      via_full
    } viaopt;                   /* how to deal with proxy Via: headers */
    apr_size_t recv_buffer_size;
    apr_size_t io_buffer_size;
    long maxfwd;
    apr_interval_time_t timeout;
    enum {
      bad_error,
      bad_ignore,
      bad_body
    } badopt;                   /* how to deal with bad headers */
    enum {
        status_off,
        status_on,
        status_full
    } proxy_status;             /* Status display options */
    apr_sockaddr_t *source_address;
    apr_global_mutex_t  *mutex; /* global lock for updating lb params */
    
    int req_set:1;
    int viaopt_set:1;
    int recv_buffer_size_set:1;
    int io_buffer_size_set:1;
    int maxfwd_set:1;
    int timeout_set:1;
    int badopt_set:1;
    int proxy_status_set:1;
    int source_address_set:1;
} proxy_server_conf;


typedef struct {
    const char *p;            /* The path */
    ap_regex_t  *r;            /* Is this a regex? */

/* FIXME
 * ProxyPassReverse and friends are documented as working inside
 * <Location>.  But in fact they never have done in the case of
 * more than one <Location>, because the server_conf can't see it.
 * We need to move them to the per-dir config.
 * Discussed in February 2005:
 * http://marc.theaimsgroup.com/?l=apache-httpd-dev&m=110726027118798&w=2
 */
    apr_array_header_t *raliases;
    apr_array_header_t* cookie_paths;
    apr_array_header_t* cookie_domains;
    const apr_strmatch_pattern* cookie_path_str;
    const apr_strmatch_pattern* cookie_domain_str;
    signed char p_is_fnmatch; /* Is the path an fnmatch candidate? */
    signed char interpolate_env;
    struct proxy_alias *alias;

    /**
     * the following setting masks the error page
     * returned from the 'proxied server' and just
     * forwards the status code upwards.
     * This allows the main server (us) to generate
     * the error page, (so it will look like a error
     * returned from the rest of the system
     */
    int error_override:1;
    int preserve_host:1;
    int preserve_host_set:1;
    int error_override_set:1;
    int alias_set:1;
} proxy_dir_conf;

/* if we interpolate env vars per-request, we'll need a per-request
 * copy of the reverse proxy config
 */
typedef struct {
    apr_array_header_t *raliases;
    apr_array_header_t* cookie_paths;
    apr_array_header_t* cookie_domains;
} proxy_req_conf;

typedef struct {
    conn_rec     *connection;
    request_rec  *r;           /* Request record of the backend request
                                * that is used over the backend connection. */
    proxy_worker *worker;      /* Connection pool this connection belongs to */
    apr_pool_t   *pool;        /* Subpool for hostname and addr data */
    const char   *hostname;
    apr_sockaddr_t *addr;      /* Preparsed remote address info */
    apr_pool_t   *scpool;      /* Subpool used for socket and connection data */
    apr_socket_t *sock;        /* Connection socket */
    void         *data;        /* per scheme connection data */
    void         *forward;     /* opaque forward proxy data */
    apr_uint32_t flags;        /* Connection flags */
    apr_port_t   port;
    int          is_ssl:1;
    int          close:1;      /* Close 'this' connection */
    int          need_flush:1; /* Flag to decide whether we need to flush the
                                * filter chain or not */
#if APR_HAS_THREADS
    int          inreslist:1;  /* connection in apr_reslist? */
#endif
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
    proxy_conn_rec *conn;   /* Single connection for prefork mpm */
};

/* worker status flags */
#define PROXY_WORKER_INITIALIZED    0x0001
#define PROXY_WORKER_IGNORE_ERRORS  0x0002
#define PROXY_WORKER_DRAIN          0x0004
#define PROXY_WORKER_IN_SHUTDOWN    0x0010
#define PROXY_WORKER_DISABLED       0x0020
#define PROXY_WORKER_STOPPED        0x0040
#define PROXY_WORKER_IN_ERROR       0x0080
#define PROXY_WORKER_HOT_STANDBY    0x0100
#define PROXY_WORKER_FREE           0x0200

#define PROXY_WORKER_NOT_USABLE_BITMAP ( PROXY_WORKER_IN_SHUTDOWN | \
PROXY_WORKER_DISABLED | PROXY_WORKER_STOPPED | PROXY_WORKER_IN_ERROR )

/* NOTE: these check the shared status */
#define PROXY_WORKER_IS_INITIALIZED(f)   ( (f)->s && \
  ( (f)->s->status &  PROXY_WORKER_INITIALIZED ) )

#define PROXY_WORKER_IS_STANDBY(f)   ( (f)->s && \
  ( (f)->s->status &  PROXY_WORKER_HOT_STANDBY ) )

#define PROXY_WORKER_IS_USABLE(f)   ( (f)->s && \
  ( !( (f)->s->status & PROXY_WORKER_NOT_USABLE_BITMAP) ) && \
  PROXY_WORKER_IS_INITIALIZED(f) )

/* default worker retry timeout in seconds */
#define PROXY_WORKER_DEFAULT_RETRY  60
#define PROXY_WORKER_MAX_SCHEME_SIZE  16
#define PROXY_WORKER_MAX_ROUTE_SIZE   64
#define PROXY_WORKER_MAX_NAME_SIZE    96


/* Runtime worker status informations. Shared in scoreboard */
typedef struct {
    char      name[PROXY_WORKER_MAX_NAME_SIZE];
    char      scheme[PROXY_WORKER_MAX_SCHEME_SIZE];   /* scheme to use ajp|http|https */
    char      hostname[PROXY_WORKER_MAX_ROUTE_SIZE];  /* remote backend address */
    char      route[PROXY_WORKER_MAX_ROUTE_SIZE];     /* balancing route */
    char      redirect[PROXY_WORKER_MAX_ROUTE_SIZE];  /* temporary balancing redirection route */
    char      flusher[PROXY_WORKER_MAX_SCHEME_SIZE];  /* flush provider used by mod_proxy_fdpass */
    int             lbset;      /* load balancer cluster set */
    int             status;
    int             retries;    /* number of retries on this worker */
    int             lbstatus;   /* Current lbstatus */
    int             lbfactor;   /* dynamic lbfactor */
    int             min;        /* Desired minimum number of available connections */
    int             smax;       /* Soft maximum on the total number of connections */
    int             hmax;       /* Hard maximum on the total number of connections */
    int             flush_wait; /* poll wait time in microseconds if flush_auto */
    int             index;      /* shm array index */
    unsigned int    apr_hash;    /* hash #0 of worker name */
    unsigned int    our_hash;    /* hash #1 of worker name. Why 2? hash collisions. */
    enum {
        flush_off,
        flush_on,
        flush_auto
    } flush_packets;           /* control AJP flushing */
    apr_time_t      error_time; /* time of the last error */
    apr_interval_time_t ttl;    /* maximum amount of time in seconds a connection
                                 * may be available while exceeding the soft limit */
    apr_interval_time_t retry;   /* retry interval */
    apr_interval_time_t timeout; /* connection timeout */
    apr_interval_time_t acquire; /* acquire timeout when the maximum number of connections is exceeded */
    apr_interval_time_t ping_timeout;
    apr_interval_time_t conn_timeout;
    apr_size_t      recv_buffer_size;
    apr_size_t      io_buffer_size;
    apr_size_t      elected;    /* Number of times the worker was elected */
    apr_size_t      busy;       /* busyness factor */
    apr_port_t      port;
    apr_off_t       transferred;/* Number of bytes transferred to remote */
    apr_off_t       read;       /* Number of bytes read from remote */
    void            *context;   /* general purpose storage */
    unsigned int     keepalive:1;
    unsigned int     disablereuse:1;
    unsigned int     is_address_reusable:1;
    unsigned int     retry_set:1;
    unsigned int     timeout_set:1;
    unsigned int     acquire_set:1;
    unsigned int     ping_timeout_set:1;
    unsigned int     conn_timeout_set:1;
    unsigned int     recv_buffer_size_set:1;
    unsigned int     io_buffer_size_set:1;
    unsigned int     keepalive_set:1;
    unsigned int     disablereuse_set:1;
} proxy_worker_shared;

/* Worker configuration */
struct proxy_worker {
    proxy_conn_pool     *cp;    /* Connection pool to use */
    proxy_worker_shared   *s;   /* Shared data */
    void            *context;   /* general purpose storage */
#if APR_HAS_THREADS
    apr_thread_mutex_t  *mutex; /* Thread lock for updating address cache */
#endif
};

/*
 * Time to wait (in microseconds) to find out if more data is currently
 * available at the backend.
 */
#define PROXY_FLUSH_WAIT 10000

struct proxy_balancer {
    apr_array_header_t *cw;      /* initially configured workers */
    proxy_worker **workers;     /* array of proxy_workers - runtime*/
    int max_workers;             /* maximum number of allowed workers */
    const char *name;            /* name of the load balancer */
    apr_interval_time_t timeout; /* Timeout for waiting on free connection */
    const char *lbprovider;      /* name of the lbmethod provider to use */
    proxy_balancer_method *lbmethod;

    const char      *sticky_path;     /* URL sticky session identifier */
    apr_array_header_t *errstatuses;  /* statuses to force members into error */
    const char      *sticky;          /* sticky session identifier */
    int             max_attempts;     /* Number of attempts before failing */

    int             sticky_force:1;   /* Disable failover for sticky sessions */
    int             scolonsep:1;      /* true if ';' seps sticky session paths */
    int             max_attempts_set:1;
    void            *context;   /* general purpose storage */
    apr_time_t      updated;    /* timestamp of last update */
};

struct proxy_balancer_method {
    const char *name;            /* name of the load balancer method*/
    proxy_worker *(*finder)(proxy_balancer *balancer,
                            request_rec *r);
    void            *context;   /* general purpose storage */
    apr_status_t (*reset)(proxy_balancer *balancer, server_rec *s);
    apr_status_t (*age)(proxy_balancer *balancer, server_rec *s);
    apr_status_t (*updatelbstatus)(proxy_balancer *balancer, proxy_worker *elected, server_rec *s); 
};

#if APR_HAS_THREADS
#define PROXY_THREAD_LOCK(x)      apr_thread_mutex_lock((x)->mutex)
#define PROXY_THREAD_UNLOCK(x)    apr_thread_mutex_unlock((x)->mutex)
#else
#define PROXY_THREAD_LOCK(x)      APR_SUCCESS
#define PROXY_THREAD_UNLOCK(x)    APR_SUCCESS
#endif

#define PROXY_GLOBAL_LOCK(x)      apr_global_mutex_lock((x)->mutex)
#define PROXY_GLOBAL_UNLOCK(x)    apr_global_mutex_unlock((x)->mutex)

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
                          proxy_worker *worker, proxy_server_conf *conf, char *url, 
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
                          proxy_balancer **balancer,
                          request_rec *r,
                          proxy_server_conf *conf, char **url))                          
/**
 * post request hook.
 * It is called after request for updating runtime balancer status.
 */
APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, post_request, (proxy_worker *worker,
                          proxy_balancer *balancer, request_rec *r,
                          proxy_server_conf *conf))

/**
 * request status hook
 * It is called after all proxy processing has been done.  This gives other
 * modules a chance to create default content on failure, for example
 */
APR_DECLARE_EXTERNAL_HOOK(proxy, PROXY, int, request_status,
                          (int *status, request_rec *r))

/* proxy_util.c */

PROXY_DECLARE(request_rec *)ap_proxy_make_fake_req(conn_rec *c, request_rec *r);
PROXY_DECLARE(int) ap_proxy_hex2c(const char *x);
PROXY_DECLARE(void) ap_proxy_c2hex(int ch, char *x);
PROXY_DECLARE(char *)ap_proxy_canonenc(apr_pool_t *p, const char *x, int len, enum enctype t,
                                       int forcedec, int proxyreq);
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
PROXY_DECLARE(int) ap_proxy_connect_to_backend(apr_socket_t **, const char *, apr_sockaddr_t *, const char *, proxy_server_conf *, request_rec *);
PROXY_DECLARE(apr_status_t) ap_proxy_ssl_connection_cleanup(proxy_conn_rec *conn,
                                                            request_rec *r);
PROXY_DECLARE(int) ap_proxy_ssl_enable(conn_rec *c);
PROXY_DECLARE(int) ap_proxy_ssl_disable(conn_rec *c);
PROXY_DECLARE(int) ap_proxy_conn_is_https(conn_rec *c);
PROXY_DECLARE(const char *) ap_proxy_ssl_val(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *var);

/* Header mapping functions, and a typedef of their signature */
PROXY_DECLARE(const char *) ap_proxy_location_reverse_map(request_rec *r, proxy_dir_conf *conf, const char *url);
PROXY_DECLARE(const char *) ap_proxy_cookie_reverse_map(request_rec *r, proxy_dir_conf *conf, const char *str);

#if !defined(WIN32)
typedef const char *(*ap_proxy_header_reverse_map_fn)(request_rec *,
                       proxy_dir_conf *, const char *);
#elif defined(PROXY_DECLARE_STATIC)
typedef const char *(__stdcall *ap_proxy_header_reverse_map_fn)(request_rec *,
                                 proxy_dir_conf *, const char *);
#elif defined(PROXY_DECLARE_EXPORT)
typedef __declspec(dllexport) const char *
  (__stdcall *ap_proxy_header_reverse_map_fn)(request_rec *,
               proxy_dir_conf *, const char *);
#else
typedef __declspec(dllimport) const char *
  (__stdcall *ap_proxy_header_reverse_map_fn)(request_rec *,
               proxy_dir_conf *, const char *);
#endif


/* Connection pool API */
/**
 * Get the worker from proxy configuration
 * @param p     memory pool used for finding worker
 * @param conf  current proxy server configuration
 * @param url   url to find the worker from
 * @return      proxy_worker or NULL if not found
 */
PROXY_DECLARE(proxy_worker *) ap_proxy_get_worker(apr_pool_t *p,
                                                  proxy_server_conf *conf,
                                                  const char *url);
/**
 * Add the worker to proxy configuration
 * @param worker the new worker
 * @param p      memory pool to allocate worker from 
 * @param conf   current proxy server configuration
 * @param url    url containing worker name
 * @param id     slotnumber id or -1 for auto allocation
 * @return       error message or NULL if successful
 */
PROXY_DECLARE(const char *) ap_proxy_add_worker_wid(proxy_worker **worker,
                                                apr_pool_t *p,
                                                proxy_server_conf *conf,
                                                const char *url,
                                                int id);

/**
 * Add the worker to proxy configuration
 * @param worker the new worker
 * @param p      memory pool to allocate worker from 
 * @param conf   current proxy server configuration
 * @param url    url containing worker name
 * @return       error message or NULL if successful
 */
PROXY_DECLARE(const char *) ap_proxy_add_worker(proxy_worker **worker,
                                                apr_pool_t *p,
                                                proxy_server_conf *conf,
                                                const char *url);

/**
 * Create new worker
 * @param p      memory pool to allocate worker from 
 * @param id     slotnumber id or -1 for auto allocation
 * @return       new worker
 */
PROXY_DECLARE(proxy_worker *) ap_proxy_create_worker_wid(apr_pool_t *p, int id);

/**
 * Create new worker
 * @param p      memory pool to allocate worker from 
 * @return       new worker
 */
PROXY_DECLARE(proxy_worker *) ap_proxy_create_worker(apr_pool_t *p);

/**
 * Initialize the worker's shared data
 * @param conf   current proxy server configuration
 * @param worker worker to initialize
 * @param s      current server record
 * @param worker worker to initialize
 */
PROXY_DECLARE(void) ap_proxy_initialize_worker_share(proxy_server_conf *conf,
                                                     proxy_worker *worker,
                                                     server_rec *s);


/**
 * Initialize the worker
 * @param worker worker to initialize
 * @param s      current server record
 * @param p      memory pool used for mutex and connection pool
 * @return       APR_SUCCESS or error code
 */
PROXY_DECLARE(apr_status_t) ap_proxy_initialize_worker(proxy_worker *worker,
                                                       server_rec *s,
                                                       apr_pool_t *p);
/**
 * Get the balancer from proxy configuration
 * @param p     memory pool used for temporary storage while finding balancer
 * @param conf  current proxy server configuration
 * @param url   url to find the worker from; must have balancer:// prefix
 * @return      proxy_balancer or NULL if not found
 */
PROXY_DECLARE(proxy_balancer *) ap_proxy_get_balancer(apr_pool_t *p,
                                                      proxy_server_conf *conf,
                                                      const char *url);
/**
 * Add the balancer to proxy configuration
 * @param balancer the new balancer
 * @param p      memory pool to allocate balancer from 
 * @param conf   current proxy server configuration
 * @param url    url containing balancer name
 * @return       error message or NULL if successfull
 */
PROXY_DECLARE(const char *) ap_proxy_add_balancer(proxy_balancer **balancer,
                                                  apr_pool_t *p,
                                                  proxy_server_conf *conf,
                                                  const char *url);

/**
 * Add the worker to the balancer
 * @param pool     memory pool for adding worker 
 * @param balancer balancer to add to
 * @param worker worker to add
 * @param id     slotnumber id or -1 for auto allocation
 * @note A single worker can be added to multiple balancers.
 */
PROXY_DECLARE(void) ap_proxy_add_worker_to_balancer_wid(apr_pool_t *pool,
                                                    proxy_balancer *balancer,
                                                    proxy_worker *worker,
                                                    int id);
/**
 * Add the worker to the balancer
 * @param pool     memory pool for adding worker 
 * @param balancer balancer to add to
 * @param worker worker to add
 * @note A single worker can be added to multiple balancers.
 */
PROXY_DECLARE(void) ap_proxy_add_worker_to_balancer(apr_pool_t *pool,
                                                    proxy_balancer *balancer,
                                                    proxy_worker *worker);
/**
 * Get the most suitable worker and/or balancer for the request
 * @param worker   worker used for processing request
 * @param balancer balancer used for processing request
 * @param r        current request
 * @param conf     current proxy server configuration
 * @param url      request url that balancer can rewrite.
 * @return         OK or  HTTP_XXX error 
 * @note It calls balancer pre_request hook if the url starts with balancer://
 * The balancer then rewrites the url to particular worker, like http://host:port
 */
PROXY_DECLARE(int) ap_proxy_pre_request(proxy_worker **worker,
                                        proxy_balancer **balancer,
                                        request_rec *r,
                                        proxy_server_conf *conf,
                                        char **url);
/**
 * Post request worker and balancer cleanup
 * @param worker   worker used for processing request
 * @param balancer balancer used for processing request
 * @param r        current request
 * @param conf     current proxy server configuration
 * @return         OK or  HTTP_XXX error
 * @note Whenever the pre_request is called, the post_request has to be
 * called too. 
 */
PROXY_DECLARE(int) ap_proxy_post_request(proxy_worker *worker,
                                         proxy_balancer *balancer,
                                         request_rec *r,
                                         proxy_server_conf *conf);

/**
 * Request status function
 * @param status   status of proxy request (result)
 * @param r        the request to obtain the status for
 * @return         OK or DECLINED
 */
 PROXY_DECLARE(int) ap_proxy_request_status(int *status, request_rec *r);

/**
 * Determine backend hostname and port
 * @param p       memory pool used for processing
 * @param r       current request
 * @param conf    current proxy server configuration
 * @param worker  worker used for processing request
 * @param conn    proxy connection struct
 * @param uri     processed uri
 * @param url     request url
 * @param proxyname are we connecting directly or via a proxy
 * @param proxyport proxy host port
 * @param server_portstr Via headers server port
 * @param server_portstr_size size of the server_portstr buffer
 * @return         OK or HTTP_XXX error
 */                                         
PROXY_DECLARE(int) ap_proxy_determine_connection(apr_pool_t *p, request_rec *r,
                                                 proxy_server_conf *conf,
                                                 proxy_worker *worker,
                                                 proxy_conn_rec *conn,
                                                 apr_uri_t *uri,
                                                 char **url,
                                                 const char *proxyname,
                                                 apr_port_t proxyport,
                                                 char *server_portstr,
                                                 int server_portstr_size);

/**
 * Mark a worker for retry
 * @param proxy_function calling proxy scheme (http, ajp, ...)
 * @param worker  worker used for retrying
 * @param s       current server record
 * @return        OK if marked for retry, DECLINED otherwise
 * @note The error status of the worker will cleared if the retry interval has
 * elapsed since the last error.
 */
PROXY_DECLARE(int) ap_proxy_retry_worker(const char *proxy_function,
                                         proxy_worker *worker,
                                         server_rec *s);

/**
 * Acquire a connection from worker connection pool
 * @param proxy_function calling proxy scheme (http, ajp, ...)
 * @param conn    acquired connection
 * @param worker  worker used for obtaining connection
 * @param s       current server record
 * @return        OK or HTTP_XXX error
 * @note If the connection limit has been reached, the function will
 * block until a connection becomes available or the timeout has
 * elapsed.
 */
PROXY_DECLARE(int) ap_proxy_acquire_connection(const char *proxy_function,
                                               proxy_conn_rec **conn,
                                               proxy_worker *worker,
                                               server_rec *s);
/**
 * Release a connection back to worker connection pool
 * @param proxy_function calling proxy scheme (http, ajp, ...)
 * @param conn    acquired connection
 * @param s       current server record
 * @return        OK or HTTP_XXX error
 * @note The connection will be closed if conn->close_on_release is set
 */                                         
PROXY_DECLARE(int) ap_proxy_release_connection(const char *proxy_function,
                                               proxy_conn_rec *conn,
                                               server_rec *s);
/**
 * Make a connection to the backend
 * @param proxy_function calling proxy scheme (http, ajp, ...)
 * @param conn    acquired connection
 * @param worker  connection worker
 * @param s       current server record
 * @return        OK or HTTP_XXX error
 * @note In case the socket already exists for conn, just check the link
 * status.
 */                                         
PROXY_DECLARE(int) ap_proxy_connect_backend(const char *proxy_function,
                                            proxy_conn_rec *conn,
                                            proxy_worker *worker,
                                            server_rec *s);
/**
 * Make a connection record for backend connection
 * @param proxy_function calling proxy scheme (http, ajp, ...)
 * @param conn    acquired connection
 * @param c       client connection record
 * @param s       current server record
 * @return        OK or HTTP_XXX error
 * @note The function will return immediately if conn->connection
 * is already set,
 */
PROXY_DECLARE(int) ap_proxy_connection_create(const char *proxy_function,
                                              proxy_conn_rec *conn,
                                              conn_rec *c, server_rec *s);
/**
 * Signal the upstream chain that the connection to the backend broke in the
 * middle of the response. This is done by sending an error bucket with
 * status HTTP_BAD_GATEWAY and an EOS bucket up the filter chain.
 * @param r       current request record of client request
 * @param brigade The brigade that is sent through the output filter chain
 */
PROXY_DECLARE(void) ap_proxy_backend_broke(request_rec *r,
                                           apr_bucket_brigade *brigade);

/**
 * Transform buckets from one bucket allocator to another one by creating a
 * transient bucket for each data bucket and let it use the data read from
 * the old bucket. Metabuckets are transformed by just recreating them.
 * Attention: Currently only the following bucket types are handled:
 *
 * All data buckets
 * FLUSH
 * EOS
 *
 * If an other bucket type is found its type is logged as a debug message
 * and APR_EGENERAL is returned.
 * @param r    current request record of client request. Only used for logging
 *             purposes
 * @param from the brigade that contains the buckets to transform
 * @param to   the brigade that will receive the transformed buckets
 * @return     APR_SUCCESS if all buckets could be transformed APR_EGENERAL
 *             otherwise
 */
PROXY_DECLARE(apr_status_t)
ap_proxy_buckets_lifetime_transform(request_rec *r, apr_bucket_brigade *from,
                                        apr_bucket_brigade *to);
/**
 * Return a hash based on the passed string
 * @param str     string to produce hash from
 * @param method  hashing method to use
 * @return        hash as unsigned int
 */

typedef enum { PROXY_HASHFUNC_DEFAULT, PROXY_HASHFUNC_APR,  PROXY_HASHFUNC_FNV } proxy_hash_t;

PROXY_DECLARE(unsigned int)
ap_proxy_hashfunc(const char *str, proxy_hash_t method);

#define PROXY_LBMETHOD "proxylbmethod"

/* The number of dynamic workers that can be added when reconfiguring.
 * If this limit is reached you must stop and restart the server.
 */
#define PROXY_DYNAMIC_BALANCER_LIMIT    16

/**
 * Calculate maximum number of workers in scoreboard.
 * @return  number of workers to allocate in the scoreboard
 */
int ap_proxy_lb_workers(void);

/* For proxy_util */
extern module PROXY_DECLARE_DATA proxy_module;

extern int PROXY_DECLARE_DATA proxy_lb_workers;

#endif /*MOD_PROXY_H*/
/** @} */
