/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#ifndef MOD_CACHE_H
#define MOD_CACHE_H 

/*
 * Main include file for the Apache Transparent Cache
 */

#define CORE_PRIVATE

#include "apr_hooks.h"
#include "apr.h"
#include "apr_compat.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_md5.h"
#include "apr_pools.h"
#include "apr_strings.h"
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
#include "apr_date.h"
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

#ifndef MAX
#define MAX(a,b)                ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)                ((a) < (b) ? (a) : (b))
#endif


/* default completion is 60% */
#define DEFAULT_CACHE_COMPLETION (60)

#define MSEC_ONE_DAY ((apr_time_t)(86400*APR_USEC_PER_SEC)) /* one day, in microseconds */
#define MSEC_ONE_HR  ((apr_time_t)(3600*APR_USEC_PER_SEC))  /* one hour, in microseconds */
#define MSEC_ONE_MIN  ((apr_time_t)(60*APR_USEC_PER_SEC))   /* one minute, in microseconds */
#define DEFAULT_CACHE_MAXEXPIRE MSEC_ONE_DAY
#define DEFAULT_CACHE_EXPIRE    MSEC_ONE_HR
#define DEFAULT_CACHE_LMFACTOR (0.1)

struct cache_enable {
    const char *url;
    const char *type;
};

struct cache_disable {
    const char *url;
};

/* static information about the local cache */
typedef struct {
    int cacheon;			/* Cache enabled? */
    int cacheon_set;
    apr_array_header_t *cacheenable;	/* URLs to cache */
    apr_array_header_t *cachedisable;	/* URLs not to cache */
    apr_time_t maxex;			/* Maximum time to keep cached files in msecs */
    int maxex_set;
    apr_time_t defex;           /* default time to keep cached file in msecs */
    int defex_set;
    double factor;              /* factor for estimating expires date */
    int factor_set;
    int complete;               /* Force cache completion after this point */
    int complete_set;
    /* ignore the last-modified header when deciding to cache this request */
    int no_last_mod_ignore_set;
    int no_last_mod_ignore; 
} cache_server_conf;

/* cache info information */
typedef struct cache_info cache_info;
struct cache_info {
    const char *content_type;
    const char *etag;
    const char *lastmods;     /* last modified of cache entity */
    const char *filename;   
    apr_time_t date;
    apr_time_t lastmod;
    char lastmod_str[APR_RFC822_DATE_LEN];
    apr_time_t expire;
    apr_time_t request_time;
    apr_time_t response_time;
    apr_size_t len;
};

/* cache handle information */
typedef struct cache_object cache_object_t;
struct cache_object {
    char *key;
    cache_object_t *next;
    cache_info info;
    void *vobj;         /* Opaque portion (specific to the cache implementation) of the cache object */
    apr_size_t count;   /* Number of body bytes written to the cache so far */
    int complete;
};

typedef struct cache_handle cache_handle_t;
struct cache_handle {
    cache_object_t *cache_obj;
    int (*remove_entity) (cache_handle_t *h);
    int (*write_headers)(cache_handle_t *h, request_rec *r, cache_info *i);
    int (*write_body)(cache_handle_t *h, apr_bucket_brigade *b);
    int (*read_headers) (cache_handle_t *h, request_rec *r);
    int (*read_body) (cache_handle_t *h, apr_bucket_brigade *bb); 
};

/* per request cache information */
typedef struct {
    const char *types;			/* the types of caches allowed */
    const char *type;			/* the type of cache selected */
    int fresh;				/* is the entitey fresh? */
    cache_handle_t *handle;		/* current cache handle */
    int in_checked;			/* CACHE_IN must cache the entity */
} cache_request_rec;


/* cache_util.c */
int ap_cache_request_is_conditional(request_rec *r);
void ap_cache_reset_output_filters(request_rec *r);
const char *ap_cache_get_cachetype(request_rec *r, cache_server_conf *conf, const char *url);
int ap_cache_liststr(const char *list, const char *key, char **val);
const char *ap_cache_tokstr(apr_pool_t *p, const char *list, const char **str);

/**
 * cache_storage.c
 */
int cache_remove_url(request_rec *r, const char *types, char *url);
int cache_create_entity(request_rec *r, const char *types, char *url, apr_size_t size);
int cache_remove_entity(request_rec *r, const char *types, cache_handle_t *h);
int cache_select_url(request_rec *r, const char *types, char *url);
/**
 * create a key for the cache based on the request record
 * this is the 'default' version, which can be overridden by a default function
 */
const char* cache_create_key( request_rec*r );

apr_status_t cache_write_entity_headers(cache_handle_t *h, request_rec *r, cache_info *info);
apr_status_t cache_write_entity_body(cache_handle_t *h, apr_bucket_brigade *bb);

apr_status_t cache_read_entity_headers(cache_handle_t *h, request_rec *r);
apr_status_t cache_read_entity_body(cache_handle_t *h, apr_bucket_brigade *bb);


/* hooks */

/* Create a set of CACHE_DECLARE(type), CACHE_DECLARE_NONSTD(type) and 
 * CACHE_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define CACHE_DECLARE(type)            type
#define CACHE_DECLARE_NONSTD(type)     type
#define CACHE_DECLARE_DATA
#elif defined(CACHE_DECLARE_STATIC)
#define CACHE_DECLARE(type)            type __stdcall
#define CACHE_DECLARE_NONSTD(type)     type
#define CACHE_DECLARE_DATA
#elif defined(CACHE_DECLARE_EXPORT)
#define CACHE_DECLARE(type)            __declspec(dllexport) type __stdcall
#define CACHE_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define CACHE_DECLARE_DATA             __declspec(dllexport)
#else
#define CACHE_DECLARE(type)            __declspec(dllimport) type __stdcall
#define CACHE_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define CACHE_DECLARE_DATA             __declspec(dllimport)
#endif

APR_DECLARE_EXTERNAL_HOOK(cache, CACHE, int, create_entity, 
                          (cache_handle_t *h, const char *type,
                           const char *urlkey, apr_size_t len))
APR_DECLARE_EXTERNAL_HOOK(cache, CACHE, int, open_entity,  
                          (cache_handle_t *h, const char *type,
                           const char *urlkey))
APR_DECLARE_EXTERNAL_HOOK(cache, CACHE, int, remove_url, 
                          (const char *type, const char *urlkey))

#endif /*MOD_CACHE_H*/
