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
 * Rules for managing obj->refcount:
 * refcount should be incremented when an object is placed in the cache. Insertion
 *   of an object into the cache and the refcount increment should happen under
 *   protection of the sconf->lock.
 *
 * refcount should be decremented when the object is removed from the cache.
 *   Object should be removed from the cache and the refcount decremented while
 *   under protection of the sconf->lock.
 *
 * refcount should be incremented when an object is retrieved from the cache
 *   by a worker thread. The retrieval/find operation and refcount increment
 *   should occur under protection of the sconf->lock
 *
 * refcount can be atomically decremented w/o protection of the sconf->lock
 *   by worker threads.
 *
 * Any object whose refcount drops to 0 should be freed/cleaned up. A refcount
 * of 0 means the object is not in the cache and no worker threads are accessing
 * it.
 */
#define CORE_PRIVATE
#include "mod_cache.h"
#include "cache_pqueue.h"
#include "cache_cache.h"
#include "ap_provider.h"
#include "ap_mpm.h"
#include "apr_thread_mutex.h"
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#if !APR_HAS_THREADS
#error This module does not currently compile unless you have a thread-capable APR. Sorry!
#endif

module AP_MODULE_DECLARE_DATA mem_cache_module;

typedef enum {
    CACHE_TYPE_FILE = 1,
    CACHE_TYPE_HEAP,
    CACHE_TYPE_MMAP
} cache_type_e;

typedef struct mem_cache_object {
    apr_pool_t *pool;
    apr_thread_mutex_t *lock;  /* pools aren't thread-safe; use this lock when accessing this pool */
    cache_type_e type;
    apr_table_t *header_out;
    apr_table_t *req_hdrs; /* for Vary negotiation */
    apr_size_t m_len;
    void *m;
    apr_os_file_t fd;
    apr_int32_t flags;  /* File open flags */
    long priority;      /**< the priority of this entry */
    long total_refs;          /**< total number of references this entry has had */

    apr_uint32_t pos;   /**< the position of this entry in the cache */

} mem_cache_object_t;

typedef struct {
    apr_thread_mutex_t *lock;
    cache_cache_t *cache_cache;

    /* Fields set by config directives */
    apr_size_t min_cache_object_size;   /* in bytes */
    apr_size_t max_cache_object_size;   /* in bytes */
    apr_size_t max_cache_size;          /* in bytes */
    apr_size_t max_object_cnt;
    cache_pqueue_set_priority cache_remove_algorithm;

    /* maximum amount of data to buffer on a streamed response where
     * we haven't yet seen EOS */
    apr_off_t max_streaming_buffer_size;
} mem_cache_conf;
static mem_cache_conf *sconf;

static int threaded_mpm;

#define DEFAULT_MAX_CACHE_SIZE 100*1024
#define DEFAULT_MIN_CACHE_OBJECT_SIZE 1
#define DEFAULT_MAX_CACHE_OBJECT_SIZE 10000
#define DEFAULT_MAX_OBJECT_CNT 1009
#define DEFAULT_MAX_STREAMING_BUFFER_SIZE 100000
#define CACHEFILE_LEN 20

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

static void cleanup_cache_object(cache_object_t *obj);

static long memcache_get_priority(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    return  mobj->priority;
}

static void memcache_inc_frequency(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    mobj->total_refs++;
    mobj->priority = 0;
}

static void memcache_set_pos(void *a, apr_ssize_t pos)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    apr_atomic_set32(&mobj->pos, pos);
}
static apr_ssize_t memcache_get_pos(void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    return apr_atomic_read32(&mobj->pos);
}

static apr_size_t memcache_cache_get_size(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;
    return mobj->m_len;
}
/** callback to get the key of a item */
static const char* memcache_cache_get_key(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    return obj->key;
}
/**
 * memcache_cache_free()
 * memcache_cache_free is a callback that is only invoked by a thread
 * running in cache_insert(). cache_insert() runs under protection
 * of sconf->lock.  By the time this function has been entered, the cache_object
 * has been ejected from the cache. decrement the refcount and if the refcount drops
 * to 0, cleanup the cache object.
 */
static void memcache_cache_free(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;

    /* Decrement the refcount to account for the object being ejected
     * from the cache. If the refcount is 0, free the object.
     */
    if (!apr_atomic_dec32(&obj->refcount)) {
        cleanup_cache_object(obj);
    }
}
/*
 * functions return a 'negative' score since priority queues
 * dequeue the object with the highest value first
 */
static long memcache_lru_algorithm(long queue_clock, void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;
    if (mobj->priority == 0)
        mobj->priority = queue_clock - mobj->total_refs;

    /*
     * a 'proper' LRU function would just be
     *  mobj->priority = mobj->total_refs;
     */
    return mobj->priority;
}

static long memcache_gdsf_algorithm(long queue_clock, void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    if (mobj->priority == 0)
        mobj->priority = queue_clock -
                           (long)(mobj->total_refs*1000 / mobj->m_len);

    return mobj->priority;
}

static void cleanup_cache_object(cache_object_t *obj)
{
    mem_cache_object_t *mobj = obj->vobj;

    /* Cleanup the mem_cache_object_t */
    if (mobj) {
        if (mobj->m) {
            free(mobj->m);
        }
        if (mobj->type == CACHE_TYPE_FILE && mobj->fd) {
#ifdef WIN32
            CloseHandle(mobj->fd);
#else
            close(mobj->fd);
#endif
        }
        apr_pool_destroy(mobj->pool);
    }
}
static apr_status_t decrement_refcount(void *arg)
{
    cache_object_t *obj = (cache_object_t *) arg;

    /* If obj->complete is not set, the cache update failed and the
     * object needs to be removed from the cache then cleaned up.
     * The garbage collector may have ejected the object from the
     * cache already, so make sure it is really still in the cache
     * before attempting to remove it.
     */
    if (!obj->complete) {
        cache_object_t *tobj = NULL;
        if (sconf->lock) {
            apr_thread_mutex_lock(sconf->lock);
        }
        tobj = cache_find(sconf->cache_cache, obj->key);
        if (tobj == obj) {
            cache_remove(sconf->cache_cache, obj);
            apr_atomic_dec32(&obj->refcount);
        }
        if (sconf->lock) {
            apr_thread_mutex_unlock(sconf->lock);
        }
    }

    /* If the refcount drops to 0, cleanup the cache object */
    if (!apr_atomic_dec32(&obj->refcount)) {
        cleanup_cache_object(obj);
    }
    return APR_SUCCESS;
}
static apr_status_t cleanup_cache_mem(void *sconfv)
{
    cache_object_t *obj;
    mem_cache_conf *co = (mem_cache_conf*) sconfv;

    if (!co) {
        return APR_SUCCESS;
    }
    if (!co->cache_cache) {
        return APR_SUCCESS;
    }

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = cache_pop(co->cache_cache);
    while (obj) {
        /* Iterate over the cache and clean up each unreferenced entry */
        if (!apr_atomic_dec32(&obj->refcount)) {
            cleanup_cache_object(obj);
        }
        obj = cache_pop(co->cache_cache);
    }

    /* Cache is empty, free the cache table */
    cache_free(co->cache_cache);

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }
    return APR_SUCCESS;
}
/*
 * TODO: enable directives to be overridden in various containers
 */
static void *create_cache_config(apr_pool_t *p, server_rec *s)
{
    sconf = apr_pcalloc(p, sizeof(mem_cache_conf));

    sconf->min_cache_object_size = DEFAULT_MIN_CACHE_OBJECT_SIZE;
    sconf->max_cache_object_size = DEFAULT_MAX_CACHE_OBJECT_SIZE;
    /* Number of objects in the cache */
    sconf->max_object_cnt = DEFAULT_MAX_OBJECT_CNT;
    /* Size of the cache in bytes */
    sconf->max_cache_size = DEFAULT_MAX_CACHE_SIZE;
    sconf->cache_cache = NULL;
    sconf->cache_remove_algorithm = memcache_gdsf_algorithm;
    sconf->max_streaming_buffer_size = DEFAULT_MAX_STREAMING_BUFFER_SIZE;

    return sconf;
}

static int create_entity(cache_handle_t *h, cache_type_e type_e,
                         request_rec *r, const char *key, apr_off_t len)
{
    apr_status_t rv;
    apr_pool_t *pool;
    cache_object_t *obj, *tmp_obj;
    mem_cache_object_t *mobj;

    /* we don't support caching of range requests (yet) */
    if (r->status == HTTP_PARTIAL_CONTENT) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "disk_cache: URL %s partial content response not cached",
                     key);
        return DECLINED;
    }

    if (len == -1) {
        /* Caching a streaming response. Assume the response is
         * less than or equal to max_streaming_buffer_size. We will
         * correct all the cache size counters in store_body once
         * we know exactly know how much we are caching.
         */
        len = sconf->max_streaming_buffer_size;
    }

    /* Note: cache_insert() will automatically garbage collect
     * objects from the cache if the max_cache_size threshold is
     * exceeded. This means mod_mem_cache does not need to implement
     * max_cache_size checks.
     */
    if (len < sconf->min_cache_object_size ||
        len > sconf->max_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "mem_cache: URL %s failed the size check and will not be cached.",
                     key);
        return DECLINED;
    }

    if (type_e == CACHE_TYPE_FILE) {
        /* CACHE_TYPE_FILE is only valid for local content handled by the
         * default handler. Need a better way to check if the file is
         * local or not.
         */
        if (!r->filename) {
            return DECLINED;
        }
    }

    rv = apr_pool_create(&pool, NULL);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
                     "mem_cache: Failed to create memory pool.");
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t */
    obj = apr_pcalloc(pool, sizeof(*obj));
    obj->key = apr_pstrdup(pool, key);

    /* Allocate and init mem_cache_object_t */
    mobj = apr_pcalloc(pool, sizeof(*mobj));
    mobj->pool = pool;

    if (threaded_mpm) {
        apr_thread_mutex_create(&mobj->lock, APR_THREAD_MUTEX_DEFAULT, pool);
    }

    /* Finish initing the cache object */
    apr_atomic_set32(&obj->refcount, 1);
    mobj->total_refs = 1;
    obj->complete = 0;
    obj->vobj = mobj;
    /* Safe cast: We tested < sconf->max_cache_object_size above */
    mobj->m_len = (apr_size_t)len;
    mobj->type = type_e;

    /* Place the cache_object_t into the hash table.
     * Note: Perhaps we should wait to put the object in the
     * hash table when the object is complete?  I add the object here to
     * avoid multiple threads attempting to cache the same content only
     * to discover at the very end that only one of them will succeed.
     * Furthermore, adding the cache object to the table at the end could
     * open up a subtle but easy to exploit DoS hole: someone could request
     * a very large file with multiple requests. Better to detect this here
     * rather than after the cache object has been completely built and
     * initialized...
     * XXX Need a way to insert into the cache w/o such coarse grained locking
     */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    tmp_obj = (cache_object_t *) cache_find(sconf->cache_cache, key);

    if (!tmp_obj) {
        cache_insert(sconf->cache_cache, obj);
        /* Add a refcount to account for the reference by the
         * hashtable in the cache. Refcount should be 2 now, one
         * for this thread, and one for the cache.
         */
        apr_atomic_inc32(&obj->refcount);
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (tmp_obj) {
        /* This thread collided with another thread loading the same object
         * into the cache at the same time. Defer to the other thread which
         * is further along.
         */
        cleanup_cache_object(obj);
        return DECLINED;
    }

    apr_pool_cleanup_register(r->pool, obj, decrement_refcount,
                              apr_pool_cleanup_null);

    /* Populate the cache handle */
    h->cache_obj = obj;

    return OK;
}

static int create_mem_entity(cache_handle_t *h, request_rec *r,
                             const char *key, apr_off_t len)
{
    return create_entity(h, CACHE_TYPE_HEAP, r, key, len);
}

static int create_fd_entity(cache_handle_t *h, request_rec *r,
                            const char *key, apr_off_t len)
{
    return create_entity(h, CACHE_TYPE_FILE, r, key, len);
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
{
    cache_object_t *obj;

    /* Look up entity keyed to 'url' */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) cache_find(sconf->cache_cache, key);
    if (obj) {
        if (obj->complete) {
            request_rec *rmain=r, *rtmp;
            apr_atomic_inc32(&obj->refcount);
            /* cache is worried about overall counts, not 'open' ones */
            cache_update(sconf->cache_cache, obj);

            /* If this is a subrequest, register the cleanup against
             * the main request. This will prevent the cache object
             * from being cleaned up from under the request after the
             * subrequest is destroyed.
             */
            rtmp = r;
            while (rtmp) {
                rmain = rtmp;
                rtmp = rmain->main;
            }
            apr_pool_cleanup_register(rmain->pool, obj, decrement_refcount,
                                      apr_pool_cleanup_null);
        }
        else {
            obj = NULL;
        }
    }

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (!obj) {
        return DECLINED;
    }

    /* Initialize the cache_handle */
    h->cache_obj = obj;
    h->req_hdrs = NULL;  /* Pick these up in recall_headers() */
    return OK;
}

/* remove_entity()
 * Notes:
 *   refcount should be at least 1 upon entry to this function to account
 *   for this thread's reference to the object. If the refcount is 1, then
 *   object has been removed from the cache by another thread and this thread
 *   is the last thread accessing the object.
 */
static int remove_entity(cache_handle_t *h)
{
    cache_object_t *obj = h->cache_obj;
    cache_object_t *tobj = NULL;

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }

    /* If the entity is still in the cache, remove it and decrement the
     * refcount. If the entity is not in the cache, do nothing. In both cases
     * decrement_refcount called by the last thread referencing the object will
     * trigger the cleanup.
     */
    tobj = cache_find(sconf->cache_cache, obj->key);
    if (tobj == obj) {
        cache_remove(sconf->cache_cache, obj);
        apr_atomic_dec32(&obj->refcount);
    }

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    return OK;
}

/* Define request processing hook handlers */
/* remove_url()
 * Notes:
 */
static int remove_url(cache_handle_t *h, apr_pool_t *p)
{
    cache_object_t *obj;
    int cleanup = 0;

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }

    obj = h->cache_obj;
    if (obj) {
        cache_remove(sconf->cache_cache, obj);
        /* For performance, cleanup cache object after releasing the lock */
        cleanup = !apr_atomic_dec32(&obj->refcount);
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (cleanup) {
        cleanup_cache_object(obj);
    }

    return OK;
}

static apr_table_t *deep_table_copy(apr_pool_t *p, const apr_table_t *table)
{
    const apr_array_header_t *array = apr_table_elts(table);
    apr_table_entry_t *elts = (apr_table_entry_t *) array->elts;
    apr_table_t *copy = apr_table_make(p, array->nelts);
    int i;

    for (i = 0; i < array->nelts; i++) {
        if (elts[i].key) {  
            apr_table_add(copy, elts[i].key, elts[i].val);
        }
    }

    return copy;
}

static apr_status_t recall_headers(cache_handle_t *h, request_rec *r)
{
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;

    h->req_hdrs = deep_table_copy(r->pool, mobj->req_hdrs);
    h->resp_hdrs = deep_table_copy(r->pool, mobj->header_out);

    return OK;
}

static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;

    if (mobj->type == CACHE_TYPE_FILE) {
        /* CACHE_TYPE_FILE */
        apr_file_t *file;
        apr_os_file_put(&file, &mobj->fd, mobj->flags, p);
        b = apr_bucket_file_create(file, 0, mobj->m_len, p, bb->bucket_alloc);
    }
    else {
        /* CACHE_TYPE_HEAP */
        b = apr_bucket_immortal_create(mobj->m, mobj->m_len, bb->bucket_alloc);
    }
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return APR_SUCCESS;
}


static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    cache_object_t *obj = h->cache_obj;
    mem_cache_object_t *mobj = (mem_cache_object_t*) obj->vobj;
    apr_table_t *headers_out;

    /*
     * The cache needs to keep track of the following information:
     * - Date, LastMod, Version, ReqTime, RespTime, ContentLength
     * - The original request headers (for Vary)
     * - The original response headers (for returning with a cached response)
     * - The body of the message
     */
    if (mobj->lock) {
        apr_thread_mutex_lock(mobj->lock);
    }
    mobj->req_hdrs = deep_table_copy(mobj->pool, r->headers_in);
    if (mobj->lock) {
        apr_thread_mutex_unlock(mobj->lock);
    }

    /* Precompute how much storage we need to hold the headers */
    headers_out = apr_table_overlay(r->pool, r->headers_out,
                                    r->err_headers_out);
    headers_out = ap_cache_cacheable_hdrs_out(r->pool, headers_out,
                                              r->server);

    /* If not set in headers_out, set Content-Type */
    if (!apr_table_get(headers_out, "Content-Type")
        && r->content_type) {
        apr_table_setn(headers_out, "Content-Type",
                       ap_make_content_type(r, r->content_type));
    }

    if (!apr_table_get(headers_out, "Content-Encoding")
        && r->content_encoding) {
        apr_table_setn(headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    if (mobj->lock) {
        apr_thread_mutex_lock(mobj->lock);
    }
    mobj->header_out = deep_table_copy(mobj->pool, headers_out);
    if (mobj->lock) {
        apr_thread_mutex_unlock(mobj->lock);
    }

    /* Init the info struct */
    obj->info.status = info->status;
    if (info->date) {
        obj->info.date = info->date;
    }
    if (info->response_time) {
        obj->info.response_time = info->response_time;
    }
    if (info->request_time) {
        obj->info.request_time = info->request_time;
    }
    if (info->expire) {
        obj->info.expire = info->expire;
    }

    return APR_SUCCESS;
}

static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b)
{
    apr_status_t rv;
    cache_object_t *obj = h->cache_obj;
    cache_object_t *tobj = NULL;
    mem_cache_object_t *mobj = (mem_cache_object_t*) obj->vobj;
    apr_read_type_e eblock = APR_BLOCK_READ;
    apr_bucket *e;
    char *cur;
    int eos = 0;

    if (mobj->type == CACHE_TYPE_FILE) {
        apr_file_t *file = NULL;
        int fd = 0;
        int other = 0;

        /* We can cache an open file descriptor if:
         * - the brigade contains one and only one file_bucket &&
         * - the brigade is complete &&
         * - the file_bucket is the last data bucket in the brigade
         */
        for (e = APR_BRIGADE_FIRST(b);
             e != APR_BRIGADE_SENTINEL(b);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
            }
            else if (APR_BUCKET_IS_FILE(e)) {
                apr_bucket_file *a = e->data;
                fd++;
                file = a->fd;
            }
            else {
                other++;
            }
        }
        if (fd == 1 && !other && eos) {
            apr_file_t *tmpfile;
            const char *name;
            /* Open a new XTHREAD handle to the file */
            apr_file_name_get(&name, file);
            mobj->flags = ((APR_SENDFILE_ENABLED & apr_file_flags_get(file))
                           | APR_READ | APR_BINARY | APR_XTHREAD | APR_FILE_NOCLEANUP);
            rv = apr_file_open(&tmpfile, name, mobj->flags,
                               APR_OS_DEFAULT, r->pool);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            apr_file_inherit_unset(tmpfile);
            apr_os_file_get(&(mobj->fd), tmpfile);

            /* Open for business */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "mem_cache: Cached file: %s with key: %s", name, obj->key);
            obj->complete = 1;
            return APR_SUCCESS;
        }

        /* Content not suitable for fd caching. Cache in-memory instead. */
        mobj->type = CACHE_TYPE_HEAP;
    }

    /*
     * FD cacheing is not enabled or the content was not
     * suitable for fd caching.
     */
    if (mobj->m == NULL) {
        mobj->m = malloc(mobj->m_len);
        if (mobj->m == NULL) {
            return APR_ENOMEM;
        }
        obj->count = 0;
    }
    cur = (char*) mobj->m + obj->count;

    /* Iterate accross the brigade and populate the cache storage */
    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = APR_BUCKET_NEXT(e))
    {
        const char *s;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            const char *cl_header = apr_table_get(r->headers_out, "Content-Length");
            if (cl_header) {
                apr_int64_t cl = apr_atoi64(cl_header);
                if ((errno == 0) && (obj->count != cl)) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                 "mem_cache: URL %s didn't receive complete response, not caching",
                                 h->cache_obj->key);
                    return APR_EGENERAL;
                }
            }
            if (mobj->m_len > obj->count) {
                /* Caching a streamed response. Reallocate a buffer of the
                 * correct size and copy the streamed response into that
                 * buffer */
                mobj->m = realloc(mobj->m, obj->count);
                if (!mobj->m) {
                    return APR_ENOMEM;
                }

                /* Now comes the crufty part... there is no way to tell the
                 * cache that the size of the object has changed. We need
                 * to remove the object, update the size and re-add the
                 * object, all under protection of the lock.
                 */
                if (sconf->lock) {
                    apr_thread_mutex_lock(sconf->lock);
                }
                /* Has the object been ejected from the cache?
                 */
                tobj = (cache_object_t *) cache_find(sconf->cache_cache, obj->key);
                if (tobj == obj) {
                    /* Object is still in the cache, remove it, update the len field then
                     * replace it under protection of sconf->lock.
                     */
                    cache_remove(sconf->cache_cache, obj);
                    /* For illustration, cache no longer has reference to the object
                     * so decrement the refcount
                     * apr_atomic_dec32(&obj->refcount);
                     */
                    mobj->m_len = obj->count;

                    cache_insert(sconf->cache_cache, obj);
                    /* For illustration, cache now has reference to the object, so
                     * increment the refcount
                     * apr_atomic_inc32(&obj->refcount);
                     */
                }
                else if (tobj) {
                    /* Different object with the same key found in the cache. Doing nothing
                     * here will cause the object refcount to drop to 0 in decrement_refcount
                     * and the object will be cleaned up.
                     */

                } else {
                    /* Object has been ejected from the cache, add it back to the cache */
                    mobj->m_len = obj->count;
                    cache_insert(sconf->cache_cache, obj);
                    apr_atomic_inc32(&obj->refcount);
                }

                if (sconf->lock) {
                    apr_thread_mutex_unlock(sconf->lock);
                }
            }
            /* Open for business */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "mem_cache: Cached url: %s", obj->key);
            obj->complete = 1;
            break;
        }
        rv = apr_bucket_read(e, &s, &len, eblock);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        if (len) {
            /* Check for buffer (max_streaming_buffer_size) overflow  */
           if ((obj->count + len) > mobj->m_len) {
               ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                            "mem_cache: URL %s exceeds the MCacheMaxStreamingBuffer (%" APR_SIZE_T_FMT ") limit and will not be cached.", 
                            obj->key, mobj->m_len);
               return APR_ENOMEM;
           }
           else {
               memcpy(cur, s, len);
               cur+=len;
               obj->count+=len;
           }
        }
        /* This should not fail, but if it does, we are in BIG trouble
         * cause we just stomped all over the heap.
         */
        AP_DEBUG_ASSERT(obj->count <= mobj->m_len);
    }
    return APR_SUCCESS;
}
/**
 * Configuration and start-up
 */
static int mem_cache_post_config(apr_pool_t *p, apr_pool_t *plog,
                                 apr_pool_t *ptemp, server_rec *s)
{
    /* Sanity check the cache configuration */
    if (sconf->min_cache_object_size >= sconf->max_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "MCacheMaxObjectSize must be greater than MCacheMinObjectSize");
        return DONE;
    }
    if (sconf->max_cache_object_size >= sconf->max_cache_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "MCacheSize must be greater than MCacheMaxObjectSize");
        return DONE;
    }
    if (sconf->max_streaming_buffer_size > sconf->max_cache_object_size) {
        /* Issue a notice only if something other than the default config
         * is being used */
        if (sconf->max_streaming_buffer_size != DEFAULT_MAX_STREAMING_BUFFER_SIZE &&
            sconf->max_cache_object_size != DEFAULT_MAX_CACHE_OBJECT_SIZE) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                         "MCacheMaxStreamingBuffer must be less than or equal to MCacheMaxObjectSize. "
                         "Resetting MCacheMaxStreamingBuffer to MCacheMaxObjectSize.");
        }
        sconf->max_streaming_buffer_size = sconf->max_cache_object_size;
    }
    if (sconf->max_streaming_buffer_size < sconf->min_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "MCacheMaxStreamingBuffer must be greater than or equal to MCacheMinObjectSize. "
                     "Resetting MCacheMaxStreamingBuffer to MCacheMinObjectSize.");
        sconf->max_streaming_buffer_size = sconf->min_cache_object_size;
    }
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    if (threaded_mpm) {
        apr_thread_mutex_create(&sconf->lock, APR_THREAD_MUTEX_DEFAULT, p);
    }

    sconf->cache_cache = cache_init(sconf->max_object_cnt,
                                    sconf->max_cache_size,
                                    memcache_get_priority,
                                    sconf->cache_remove_algorithm,
                                    memcache_get_pos,
                                    memcache_set_pos,
                                    memcache_inc_frequency,
                                    memcache_cache_get_size,
                                    memcache_cache_get_key,
                                    memcache_cache_free);
    apr_pool_cleanup_register(p, sconf, cleanup_cache_mem, apr_pool_cleanup_null);

    if (sconf->cache_cache)
        return OK;

    return -1;

}

static const char
*set_max_cache_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheSize argument must be an integer representing the max cache size in KBytes.";
    }
    sconf->max_cache_size = val*1024;
    return NULL;
}
static const char
*set_min_cache_object_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheMinObjectSize value must be an positive integer (bytes)";
    }
    if (val > 0)
       sconf->min_cache_object_size = val;
    else
       return  "MCacheMinObjectSize value must be an positive integer (bytes)";
    return NULL;
}
static const char
*set_max_cache_object_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheMaxObjectSize value must be an integer (bytes)";
    }
    sconf->max_cache_object_size = val;
    return NULL;
}
static const char
*set_max_object_count(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheMaxObjectCount value must be an integer";
    }
    sconf->max_object_cnt = val;
    return NULL;
}

static const char
*set_cache_removal_algorithm(cmd_parms *parms, void *name, const char *arg)
{
    if (strcasecmp("LRU", arg)) {
        sconf->cache_remove_algorithm = memcache_lru_algorithm;
    }
    else {
        if (strcasecmp("GDSF", arg)) {
            sconf->cache_remove_algorithm = memcache_gdsf_algorithm;
        }
        else {
            return "currently implemented algorithms are LRU and GDSF";
        }
    }
    return NULL;
}

static const char *set_max_streaming_buffer(cmd_parms *parms, void *dummy,
                                            const char *arg)
{
    char *err;
    if (apr_strtoff(&sconf->max_streaming_buffer_size, arg, &err, 10) || *err) {
        return "MCacheMaxStreamingBuffer value must be a number";
    }

    return NULL;
}

static const command_rec cache_cmds[] =
{
    AP_INIT_TAKE1("MCacheSize", set_max_cache_size, NULL, RSRC_CONF,
     "The maximum amount of memory used by the cache in KBytes"),
    AP_INIT_TAKE1("MCacheMaxObjectCount", set_max_object_count, NULL, RSRC_CONF,
     "The maximum number of objects allowed to be placed in the cache"),
    AP_INIT_TAKE1("MCacheMinObjectSize", set_min_cache_object_size, NULL, RSRC_CONF,
     "The minimum size (in bytes) of an object to be placed in the cache"),
    AP_INIT_TAKE1("MCacheMaxObjectSize", set_max_cache_object_size, NULL, RSRC_CONF,
     "The maximum size (in bytes) of an object to be placed in the cache"),
    AP_INIT_TAKE1("MCacheRemovalAlgorithm", set_cache_removal_algorithm, NULL, RSRC_CONF,
     "The algorithm used to remove entries from the cache (default: GDSF)"),
    AP_INIT_TAKE1("MCacheMaxStreamingBuffer", set_max_streaming_buffer, NULL, RSRC_CONF,
     "Maximum number of bytes of content to buffer for a streamed response"),
    {NULL}
};

static const cache_provider cache_mem_provider =
{
    &remove_entity,
    &store_headers,
    &store_body,
    &recall_headers,
    &recall_body,
    &create_mem_entity,
    &open_entity,
    &remove_url,
};

static const cache_provider cache_fd_provider =
{
    &remove_entity,
    &store_headers,
    &store_body,
    &recall_headers,
    &recall_body,
    &create_fd_entity,
    &open_entity,
    &remove_url,
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(mem_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* cache initializer */
    /* cache_hook_init(cache_mem_init, NULL, NULL, APR_HOOK_MIDDLE);  */
    /*
    cache_hook_create_entity(create_entity, NULL, NULL, APR_HOOK_MIDDLE);
    cache_hook_open_entity(open_entity,  NULL, NULL, APR_HOOK_MIDDLE);
    cache_hook_remove_url(remove_url, NULL, NULL, APR_HOOK_MIDDLE);
    */
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "mem", "0",
                         &cache_mem_provider);
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "fd", "0",
                         &cache_fd_provider);
}

module AP_MODULE_DECLARE_DATA mem_cache_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                    /* create per-directory config structure */
    NULL,                    /* merge per-directory config structures */
    create_cache_config,     /* create per-server config structure */
    NULL,                    /* merge per-server config structures */
    cache_cmds,              /* command apr_table_t */
    register_hooks
};
