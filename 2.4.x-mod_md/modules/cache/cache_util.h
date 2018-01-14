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

/**
 * @file cache_util.h
 * @brief Cache Storage Functions
 *
 * @defgroup Cache_util  Cache Utility Functions
 * @ingroup  MOD_CACHE
 * @{
 */

#ifndef CACHE_UTIL_H
#define CACHE_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mod_cache.h"

#include "apr_hooks.h"
#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_md5.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_optional.h"
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
#include "apr_uri.h"

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

#include "apr_atomic.h"

#ifndef MAX
#define MAX(a,b)                ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)                ((a) < (b) ? (a) : (b))
#endif

#define MSEC_ONE_DAY    ((apr_time_t)(86400*APR_USEC_PER_SEC)) /* one day, in microseconds */
#define MSEC_ONE_HR     ((apr_time_t)(3600*APR_USEC_PER_SEC))  /* one hour, in microseconds */
#define MSEC_ONE_MIN    ((apr_time_t)(60*APR_USEC_PER_SEC))    /* one minute, in microseconds */
#define MSEC_ONE_SEC    ((apr_time_t)(APR_USEC_PER_SEC))       /* one second, in microseconds */

#define DEFAULT_CACHE_MAXEXPIRE MSEC_ONE_DAY
#define DEFAULT_CACHE_MINEXPIRE 0
#define DEFAULT_CACHE_EXPIRE    MSEC_ONE_HR
#define DEFAULT_CACHE_LMFACTOR  (0.1)
#define DEFAULT_CACHE_MAXAGE    5
#define DEFAULT_X_CACHE         0
#define DEFAULT_X_CACHE_DETAIL  0
#define DEFAULT_CACHE_STALE_ON_ERROR 1
#define DEFAULT_CACHE_LOCKPATH "/mod_cache-lock"
#define CACHE_LOCKNAME_KEY "mod_cache-lockname"
#define CACHE_LOCKFILE_KEY "mod_cache-lockfile"
#define CACHE_CTX_KEY "mod_cache-ctx"
#define CACHE_SEPARATOR ", \t"

/**
 * cache_util.c
 */

struct cache_enable {
    apr_uri_t url;
    const char *type;
    apr_size_t pathlen;
};

struct cache_disable {
    apr_uri_t url;
    apr_size_t pathlen;
};

/* static information about the local cache */
typedef struct {
    apr_array_header_t *cacheenable;    /* URLs to cache */
    apr_array_header_t *cachedisable;   /* URLs not to cache */
    /** store the headers that should not be stored in the cache */
    apr_array_header_t *ignore_headers;
    /** store the identifiers that should not be used for key calculation */
    apr_array_header_t *ignore_session_id;
    const char *lockpath;
    apr_time_t lockmaxage;
    apr_uri_t *base_uri;
    /** ignore client's requests for uncached responses */
    unsigned int ignorecachecontrol:1;
    /** ignore query-string when caching */
    unsigned int ignorequerystring:1;
    /** run within the quick handler */
    unsigned int quick:1;
    /* thundering herd lock */
    unsigned int lock:1;
    unsigned int x_cache:1;
    unsigned int x_cache_detail:1;
    /* flag if CacheIgnoreHeader has been set */
    #define CACHE_IGNORE_HEADERS_SET   1
    #define CACHE_IGNORE_HEADERS_UNSET 0
    unsigned int ignore_headers_set:1;
    /* flag if CacheIgnoreURLSessionIdentifiers has been set */
    #define CACHE_IGNORE_SESSION_ID_SET   1
    #define CACHE_IGNORE_SESSION_ID_UNSET 0
    unsigned int ignore_session_id_set:1;
    unsigned int base_uri_set:1;
    unsigned int ignorecachecontrol_set:1;
    unsigned int ignorequerystring_set:1;
    unsigned int quick_set:1;
    unsigned int lock_set:1;
    unsigned int lockpath_set:1;
    unsigned int lockmaxage_set:1;
    unsigned int x_cache_set:1;
    unsigned int x_cache_detail_set:1;
} cache_server_conf;

typedef struct {
    /* Minimum time to keep cached files in msecs */
    apr_time_t minex;
    /* Maximum time to keep cached files in msecs */
    apr_time_t maxex;
    /* default time to keep cached file in msecs */
    apr_time_t defex;
    /* factor for estimating expires date */
    double factor;
    /* cache enabled for this location */
    apr_array_header_t *cacheenable;
    /* cache disabled for this location */
    unsigned int disable:1;
    /* set X-Cache headers */
    unsigned int x_cache:1;
    unsigned int x_cache_detail:1;
    /* serve stale on error */
    unsigned int stale_on_error:1;
    /** ignore the last-modified header when deciding to cache this request */
    unsigned int no_last_mod_ignore:1;
    /** ignore expiration date from server */
    unsigned int store_expired:1;
    /** ignore Cache-Control: private header from server */
    unsigned int store_private:1;
    /** ignore Cache-Control: no-store header from client or server */
    unsigned int store_nostore:1;
    unsigned int minex_set:1;
    unsigned int maxex_set:1;
    unsigned int defex_set:1;
    unsigned int factor_set:1;
    unsigned int x_cache_set:1;
    unsigned int x_cache_detail_set:1;
    unsigned int stale_on_error_set:1;
    unsigned int no_last_mod_ignore_set:1;
    unsigned int store_expired_set:1;
    unsigned int store_private_set:1;
    unsigned int store_nostore_set:1;
    unsigned int enable_set:1;
    unsigned int disable_set:1;
} cache_dir_conf;

/* A linked-list of authn providers. */
typedef struct cache_provider_list cache_provider_list;

struct cache_provider_list {
    const char *provider_name;
    const cache_provider *provider;
    cache_provider_list *next;
};

/* per request cache information */
typedef struct {
    cache_provider_list *providers;     /* possible cache providers */
    const cache_provider *provider;     /* current cache provider */
    const char *provider_name;          /* current cache provider name */
    int fresh;                          /* is the entity fresh? */
    cache_handle_t *handle;             /* current cache handle */
    cache_handle_t *stale_handle;       /* stale cache handle */
    apr_table_t *stale_headers;         /* original request headers. */
    int in_checked;                     /* CACHE_SAVE must cache the entity */
    int block_response;                 /* CACHE_SAVE must block response. */
    apr_bucket_brigade *saved_brigade;  /* copy of partial response */
    apr_off_t saved_size;               /* length of saved_brigade */
    apr_time_t exp;                     /* expiration */
    apr_time_t lastmod;                 /* last-modified time */
    cache_info *info;                   /* current cache info */
    ap_filter_t *save_filter;           /* Enable us to restore the filter on error */
    ap_filter_t *remove_url_filter;     /* Enable us to remove the filter */
    const char *key;                    /* The cache key created for this
                                         * request
                                         */
    apr_off_t size;                     /* the content length from the headers, or -1 */
    apr_bucket_brigade *out;            /* brigade to reuse for upstream responses */
    cache_control_t control_in;         /* cache control incoming */
} cache_request_rec;

/**
 * Check the whether the request allows a cached object to be served as per RFC2616
 * section 14.9.4 (Cache Revalidation and Reload Controls)
 * @param cache cache_request_rec
 * @param r request_rec
 * @return 0 ==> cache object may not be served, 1 ==> cache object may be served
 */
int ap_cache_check_no_cache(cache_request_rec *cache, request_rec *r);

/**
 * Check the whether the request allows a cached object to be stored as per RFC2616
 * section 14.9.2 (What May be Stored by Caches)
 * @param cache cache_request_rec
 * @param r request_rec
 * @return 0 ==> cache object may not be served, 1 ==> cache object may be served
 */
int ap_cache_check_no_store(cache_request_rec *cache, request_rec *r);

/**
 * Check the freshness of the cache object per RFC2616 section 13.2 (Expiration Model)
 * @param h cache_handle_t
 * @param cache cache_request_rec
 * @param r request_rec
 * @return 0 ==> cache object is stale, 1 ==> cache object is fresh
 */
int cache_check_freshness(cache_handle_t *h, cache_request_rec *cache,
        request_rec *r);

/**
 * Try obtain a cache wide lock on the given cache key.
 *
 * If we return APR_SUCCESS, we obtained the lock, and we are clear to
 * proceed to the backend. If we return APR_EEXISTS, then the lock is
 * already locked, someone else has gone to refresh the backend data
 * already, so we must return stale data with a warning in the mean
 * time. If we return anything else, then something has gone pear
 * shaped, and we allow the request through to the backend regardless.
 *
 * This lock is created from the request pool, meaning that should
 * something go wrong and the lock isn't deleted on return of the
 * request headers from the backend for whatever reason, at worst the
 * lock will be cleaned up when the request is dies or finishes.
 *
 * If something goes truly bananas and the lock isn't deleted when the
 * request dies, the lock will be trashed when its max-age is reached,
 * or when a request arrives containing a Cache-Control: no-cache. At
 * no point is it possible for this lock to permanently deny access to
 * the backend.
 */
apr_status_t cache_try_lock(cache_server_conf *conf, cache_request_rec *cache,
        request_rec *r);

/**
 * Remove the cache lock, if present.
 *
 * First, try to close the file handle, whose delete-on-close should
 * kill the file. Otherwise, just delete the file by name.
 *
 * If no lock name has yet been calculated, do the calculation of the
 * lock name first before trying to delete the file.
 *
 * If an optional bucket brigade is passed, the lock will only be
 * removed if the bucket brigade contains an EOS bucket.
 */
apr_status_t cache_remove_lock(cache_server_conf *conf,
        cache_request_rec *cache, request_rec *r, apr_bucket_brigade *bb);

cache_provider_list *cache_get_providers(request_rec *r,
                                         cache_server_conf *conf);

/**
 * Get a value from a table, where the table may contain multiple
 * values for a given key.
 *
 * When the table contains a single value, that value is returned
 * unchanged.
 *
 * When the table contains two or more values for a key, all values
 * for the key are returned, separated by commas.
 */
const char *cache_table_getm(apr_pool_t *p, const apr_table_t *t,
        const char *key);

/**
 * String tokenizer that ignores separator characters within quoted strings
 * and escaped characters, as per RFC2616 section 2.2.
 */
char *cache_strqtok(char *str, const char *sep, char **last);

/**
 * Merge err_headers_out into headers_out and add request's Content-Type and
 * Content-Encoding if available.
 */
apr_table_t *cache_merge_headers_out(request_rec *r);

/**
 * Return whether to use request's path/query from early stage (r->parsed_uri)
 * or the current/rewritable ones (r->uri/r->args).
 */
int cache_use_early_url(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif /* !CACHE_UTIL_H */
/** @} */
