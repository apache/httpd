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

#define CORE_PRIVATE
#include "mod_cache.h"
#include "cache_pqueue.h"
#include "cache_cache.h"
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

typedef struct {
    char* hdr;
    char* val;
} cache_header_tbl_t;

typedef struct mem_cache_object {
    cache_type_e type;
    apr_ssize_t num_header_out;
    apr_ssize_t num_err_header_out;
    apr_ssize_t num_subprocess_env;
    apr_ssize_t num_notes;
    apr_ssize_t num_req_hdrs;
    cache_header_tbl_t *header_out;
    cache_header_tbl_t *err_header_out;
    cache_header_tbl_t *subprocess_env;
    cache_header_tbl_t *notes;
    cache_header_tbl_t *req_hdrs; /* for Vary negotiation */
    apr_size_t m_len;
    void *m;
    apr_os_file_t fd;
    apr_int32_t flags;  /* File open flags */
    long priority;      /**< the priority of this entry */
    long total_refs;          /**< total number of references this entry has had */

#ifdef USE_ATOMICS
    apr_atomic_t pos;   /**< the position of this entry in the cache */
#else
    apr_ssize_t pos;
#endif

} mem_cache_object_t;

typedef struct {
    apr_thread_mutex_t *lock;
    cache_cache_t *cache_cache;
    apr_size_t cache_size;
    apr_size_t object_cnt;

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

#define DEFAULT_MAX_CACHE_SIZE 100*1024
#define DEFAULT_MIN_CACHE_OBJECT_SIZE 0
#define DEFAULT_MAX_CACHE_OBJECT_SIZE 10000
#define DEFAULT_MAX_OBJECT_CNT 1009
#define DEFAULT_MAX_STREAMING_BUFFER_SIZE 100000
#define CACHEFILE_LEN 20

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t write_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t write_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static apr_status_t read_headers(cache_handle_t *h, request_rec *r);
static apr_status_t read_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

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

#ifdef USE_ATOMICS
    apr_atomic_set(&mobj->pos, pos);
#else
    mobj->pos = pos;
#endif    
}
static apr_ssize_t memcache_get_pos(void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

#ifdef USE_ATOMICS
    return apr_atomic_read(&mobj->pos);
#else
    return mobj->pos;
#endif    
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
 * callback to free an entry 
 * There is way too much magic in this code. Right now, this callback
 * is only called out of cache_insert() which is called under protection
 * of the sconf->lock, which means that we do not (and should not)
 * attempt to obtain the lock recursively. 
 */
static void memcache_cache_free(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;

    /* Cleanup the cache object. Object should be removed from the cache
     * now. Increment the refcount before setting cleanup to avoid a race 
     * condition. A similar pattern is used in remove_url()
     */
#ifdef USE_ATOMICS
    apr_atomic_inc(&obj->refcount);
#else
    obj->refcount++;
#endif

    obj->cleanup = 1;

#ifdef USE_ATOMICS
    if (!apr_atomic_dec(&obj->refcount)) {
        cleanup_cache_object(obj);
    }
#else
    obj->refcount--;
    if (!obj->refcount) {
        cleanup_cache_object(obj);
    }
#endif
}
/*
 * functions return a 'negative' score as lower is better in a priority Q
 */
static long memcache_lru_algorithm(long queue_clock, void *a) 
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;
    if (mobj->priority == 0)
        mobj->priority = ((long)(queue_clock + mobj->total_refs));

    /*	
     * a 'proper' LRU function would just be
     *  mobj->priority = mobj->total_refs; 
     */
    return -1*mobj->priority;
}

static long memcache_gdsf_algorithm(long queue_clock, void *a) 
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    if (mobj->priority == 0)
        mobj->priority = queue_clock + (long)(mobj->total_refs*1000 / mobj->m_len);

    return -1*mobj->priority;
}

static void cleanup_cache_object(cache_object_t *obj)
{
    mem_cache_object_t *mobj = obj->vobj;

    /* TODO:
     * We desperately need a more efficient way of allocating objects. We're
     * making way too many malloc calls to create a fully populated 
     * cache object...
     */

    /* Cleanup the cache_object_t */
    if (obj->key) {
        free(obj->key);
    }
    if (obj->info.content_type) {
        free(obj->info.content_type);
    }
    if (obj->info.etag) {
        free(obj->info.etag);
    }
    if (obj->info.lastmods) {
        free(obj->info.lastmods);
    }
    if (obj->info.filename) {
        free(obj->info.filename);
    }

    free(obj);
    
    /* Cleanup the mem_cache_object_t */
    if (mobj) {
        if (mobj->type == CACHE_TYPE_HEAP && mobj->m) {
            free(mobj->m);
        }
        if (mobj->type == CACHE_TYPE_FILE && mobj->fd) {
#ifdef WIN32
            CloseHandle(mobj->fd);
#else
            close(mobj->fd);
#endif
        }
        if (mobj->header_out) {
            if (mobj->header_out[0].hdr) 
                free(mobj->header_out[0].hdr);
            free(mobj->header_out);
        }
        if (mobj->err_header_out) {
            if (mobj->err_header_out[0].hdr) 
                free(mobj->err_header_out[0].hdr);
            free(mobj->err_header_out);
        }
        if (mobj->subprocess_env) {
            if (mobj->subprocess_env[0].hdr) 
                free(mobj->subprocess_env[0].hdr);
            free(mobj->subprocess_env);
        }
        if (mobj->notes) {
            if (mobj->notes[0].hdr) 
                free(mobj->notes[0].hdr);
            free(mobj->notes);
        }
        if (mobj->req_hdrs) {
            if (mobj->req_hdrs[0].hdr)
                free(mobj->req_hdrs[0].hdr);
            free(mobj->req_hdrs);
        }
        free(mobj);
    }
}
static apr_status_t decrement_refcount(void *arg) 
{
    cache_object_t *obj = (cache_object_t *) arg;

    /* If obj->complete is not set, the cache update failed and the
     * object needs to be removed from the cache then cleaned up.
     */
    if (!obj->complete) {
        mem_cache_object_t *mobj = (mem_cache_object_t *) obj->vobj;
        if (sconf->lock) {
            apr_thread_mutex_lock(sconf->lock);
        }
        /* Remember, objects marked for cleanup are, by design, already
         * removed from the cache. remove_url() could have already
         * removed the object from the cache (and set obj->cleanup)
         */
        if (!obj->cleanup) {
            cache_remove(sconf->cache_cache, obj);
            sconf->object_cnt--;
            sconf->cache_size -= mobj->m_len;
            obj->cleanup = 1;
        }
        if (sconf->lock) {
            apr_thread_mutex_unlock(sconf->lock);
        }
    }

    /* Cleanup the cache object */
#ifdef USE_ATOMICS
    if (!apr_atomic_dec(&obj->refcount)) {
        if (obj->cleanup) {
            cleanup_cache_object(obj);
        }
    }
#else
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj->refcount--;
    /* If the object is marked for cleanup and the refcount
     * has dropped to zero, cleanup the object
     */
    if ((obj->cleanup) && (!obj->refcount)) {
        cleanup_cache_object(obj);
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }
#endif
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
    /* Iterate over the cache and clean up each entry */  
    /* Free the object if the recount == 0 */
#ifdef USE_ATOMICS
        apr_atomic_inc(&obj->refcount);
        obj->cleanup = 1;
        if (!apr_atomic_dec(&obj->refcount)) {
#else
        obj->cleanup = 1;
        if (!obj->refcount) {
#endif
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
    sconf->object_cnt = 0;
    /* Size of the cache in bytes */
    sconf->max_cache_size = DEFAULT_MAX_CACHE_SIZE;
    sconf->cache_size = 0;
    sconf->cache_cache = NULL;
    sconf->cache_remove_algorithm = memcache_gdsf_algorithm;
    sconf->max_streaming_buffer_size = DEFAULT_MAX_STREAMING_BUFFER_SIZE;

    return sconf;
}

static int create_entity(cache_handle_t *h, request_rec *r,
                         const char *type, 
                         const char *key, 
                         apr_off_t len) 
{
    cache_object_t *obj, *tmp_obj;
    mem_cache_object_t *mobj;
    cache_type_e type_e;
    apr_size_t key_len;

    if (!strcasecmp(type, "mem")) {
        type_e = CACHE_TYPE_HEAP;
    } 
    else if (!strcasecmp(type, "fd")) {
        type_e = CACHE_TYPE_FILE;
    }
    else {
        return DECLINED;
    }

    if (len == -1) {
        /* Caching a streaming response. Assume the response is
         * less than or equal to max_streaming_buffer_size. We will
         * correct all the cache size counters in write_body once
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

    /* Allocate and initialize cache_object_t */
    obj = calloc(1, sizeof(*obj));
    if (!obj) {
        return DECLINED;
    }
    key_len = strlen(key) + 1;
    obj->key = malloc(key_len);
    if (!obj->key) {
        cleanup_cache_object(obj);
        return DECLINED;
    }
    memcpy(obj->key, key, key_len);
    /* Safe cast: We tested < sconf->max_cache_object_size above */
    obj->info.len = (apr_size_t)len;

    /* Allocate and init mem_cache_object_t */
    mobj = calloc(1, sizeof(*mobj));
    if (!mobj) {
        cleanup_cache_object(obj);
        return DECLINED;
    }

    /* Finish initing the cache object */
#ifdef USE_ATOMICS
    apr_atomic_set(&obj->refcount, 1);
#else 
    obj->refcount = 1;
#endif
    mobj->total_refs = 1;
    obj->complete = 0;
    obj->cleanup = 0;
    obj->vobj = mobj;
    /* Safe cast: We tested < sconf->max_cache_object_size above */
    mobj->m_len = (apr_size_t)len;
    mobj->type = type_e;

    /* Place the cache_object_t into the hash table.
     * Note: Perhaps we should wait to put the object in the
     * hash table when the object is complete?  I add the object here to
     * avoid multiple threads attempting to cache the same content only
     * to discover at the very end that only one of them will suceed.
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
        sconf->object_cnt++;
        /* Safe cast: Must fit in cache_size or alloc would have failed */
        sconf->cache_size += (apr_size_t)len;
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
    h->read_body = &read_body;
    h->read_headers = &read_headers;
    h->write_body = &write_body;
    h->write_headers = &write_headers;
    h->remove_entity = &remove_entity;

    return OK;
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *type, const char *key) 
{
    cache_object_t *obj;

    /* Look up entity keyed to 'url' */
    if (strcasecmp(type, "mem") && strcasecmp(type, "fd")) {
        return DECLINED;
    }
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) cache_find(sconf->cache_cache, key);
    if (obj) {
        if (obj->complete) {
            request_rec *rmain=r, *rtmp;
#ifdef USE_ATOMICS
            apr_atomic_inc(&obj->refcount);
#else
            obj->refcount++;
#endif
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
    h->read_body = &read_body;
    h->read_headers = &read_headers;
    h->write_body = &write_body;
    h->write_headers = &write_headers;
    h->remove_entity = &remove_entity;
    h->cache_obj = obj;
    h->req_hdrs = NULL;  /* Pick these up in read_headers() */
    return OK;
}

static int remove_entity(cache_handle_t *h) 
{
    cache_object_t *obj = h->cache_obj;

    /* Remove the cache object from the cache under protection */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    /* If the object is not already marked for cleanup, remove
     * it from the cache and mark it for cleanup. Remember,
     * an object marked for cleanup is by design not in the
     * hash table.
     */
    if (!obj->cleanup) {
        mem_cache_object_t *mobj = (mem_cache_object_t *) obj->vobj;
        cache_remove(sconf->cache_cache, obj);
        sconf->object_cnt--;
        sconf->cache_size -= mobj->m_len;
        obj->cleanup = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL, "gcing a cache entry");
    }

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    return OK;
}
static apr_status_t serialize_table(cache_header_tbl_t **obj, 
                                    apr_ssize_t *nelts, 
                                    apr_table_t *table)
{
    const apr_array_header_t *elts_arr = apr_table_elts(table);
    apr_table_entry_t *elts = (apr_table_entry_t *) elts_arr->elts;
    apr_ssize_t i;
    apr_size_t len = 0;
    apr_size_t idx = 0;
    char *buf;
   
    *nelts = elts_arr->nelts;
    if (*nelts == 0 ) {
        *obj=NULL;
        return APR_SUCCESS;
    }
    *obj = malloc(sizeof(cache_header_tbl_t) * elts_arr->nelts);
    if (NULL == *obj) {
        return APR_ENOMEM;
    }
    for (i = 0; i < elts_arr->nelts; ++i) {
        len += strlen(elts[i].key);
        len += strlen(elts[i].val);
        len += 2;  /* Extra space for NULL string terminator for key and val */
    }

    /* Transfer the headers into a contiguous memory block */
    buf = malloc(len);
    if (!buf) {
        *obj = NULL;
        return APR_ENOMEM;
    }

    for (i = 0; i < *nelts; ++i) {
        (*obj)[i].hdr = &buf[idx];
        len = strlen(elts[i].key) + 1;              /* Include NULL terminator */
        memcpy(&buf[idx], elts[i].key, len);
        idx+=len;

        (*obj)[i].val = &buf[idx];
        len = strlen(elts[i].val) + 1;
        memcpy(&buf[idx], elts[i].val, len);
        idx+=len;
    }
    return APR_SUCCESS;
}
static int unserialize_table( cache_header_tbl_t *ctbl, 
                              int num_headers, 
                              apr_table_t *t )
{
    int i;

    for (i = 0; i < num_headers; ++i) {
        apr_table_addn(t, ctbl[i].hdr, ctbl[i].val);
    } 

    return APR_SUCCESS;
}
/* Define request processing hook handlers */
static int remove_url(const char *type, const char *key) 
{
    cache_object_t *obj;

    if (strcasecmp(type, "mem") && strcasecmp(type, "fd")) {
        return DECLINED;
    }
    /* Order of the operations is important to avoid race conditions. 
     * First, remove the object from the cache. Remember, all additions
     * deletions from the cache are protected by sconf->lock.
     * Increment the ref count on the object to indicate our thread
     * is accessing the object. Then set the cleanup flag on the
     * object. Remember, the cleanup flag is NEVER set on an
     * object in the hash table.  If an object has the cleanup
     * flag set, it is guaranteed to NOT be in the hash table.
     */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
  
    obj = cache_find(sconf->cache_cache, key);       
    if (obj) {
        mem_cache_object_t *mobj;
        cache_remove(sconf->cache_cache, obj);
        mobj = (mem_cache_object_t *) obj->vobj;
        sconf->object_cnt--;
        sconf->cache_size -= mobj->m_len;

#ifdef USE_ATOMICS
        /* Refcount increment in this case MUST be made under 
         * protection of the lock 
         */
        apr_atomic_inc(&obj->refcount);
#else
        if (!obj->refcount) {
            cleanup_cache_object(obj);
            obj = NULL;
        }
#endif
        if (obj) {
            obj->cleanup = 1;
        }
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }
#ifdef USE_ATOMICS
    if (obj) {
        if (!apr_atomic_dec(&obj->refcount)) {
            cleanup_cache_object(obj);
        }
    }
#endif
    return OK;
}

static apr_status_t read_headers(cache_handle_t *h, request_rec *r) 
{
    int rc;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;
 
    h->req_hdrs = apr_table_make(r->pool, mobj->num_req_hdrs);
    r->headers_out = apr_table_make(r->pool, mobj->num_header_out);
    r->err_headers_out = apr_table_make(r->pool, mobj->num_err_header_out);
    r->subprocess_env = apr_table_make(r->pool, mobj->num_subprocess_env);
    r->notes = apr_table_make(r->pool, mobj->num_notes);

    rc = unserialize_table(mobj->req_hdrs,
                           mobj->num_req_hdrs,
                           h->req_hdrs);
    rc = unserialize_table( mobj->header_out,
                            mobj->num_header_out, 
                            r->headers_out);
    rc = unserialize_table( mobj->err_header_out,
                            mobj->num_err_header_out, 
                            r->err_headers_out);
    rc = unserialize_table( mobj->subprocess_env, 
                            mobj->num_subprocess_env, 
                            r->subprocess_env);
    rc = unserialize_table( mobj->notes,
                            mobj->num_notes,
                            r->notes);

    /* Content-Type: header may not be set if content is local since
     * CACHE_IN runs before header filters....
     */
    ap_set_content_type(r, apr_pstrdup(r->pool, h->cache_obj->info.content_type));

    return rc;
}

static apr_status_t read_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb) 
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


static apr_status_t write_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    cache_object_t *obj = h->cache_obj;
    mem_cache_object_t *mobj = (mem_cache_object_t*) obj->vobj;
    int rc;
 
    /*
     * The cache needs to keep track of the following information: 
     * - Date, LastMod, Version, ReqTime, RespTime, ContentLength 
     * - The original request headers (for Vary) 
     * - The original response headers (for returning with a cached response) 
     * - The body of the message
     */
    rc = serialize_table(&mobj->req_hdrs,
                         &mobj->num_req_hdrs,
                         r->headers_in);
    if (rc != APR_SUCCESS) {
        return rc;
    }

    /* Precompute how much storage we need to hold the headers */
    rc = serialize_table(&mobj->header_out, 
                         &mobj->num_header_out, 
                         ap_cache_cacheable_hdrs_out(r->pool, r->headers_out));   
    if (rc != APR_SUCCESS) {
        return rc;
    }
    rc = serialize_table(&mobj->err_header_out, 
                         &mobj->num_err_header_out, 
                         ap_cache_cacheable_hdrs_out(r->pool, r->err_headers_out));   
    if (rc != APR_SUCCESS) {
        return rc;
    }
    rc = serialize_table(&mobj->subprocess_env,
                         &mobj->num_subprocess_env, 
                         r->subprocess_env );
    if (rc != APR_SUCCESS) {
        return rc;
    }

    rc = serialize_table(&mobj->notes, &mobj->num_notes, r->notes);
    if (rc != APR_SUCCESS) {
        return rc;
    }
 
    /* Init the info struct */
    if (info->date) {
        obj->info.date = info->date;
    }
    if (info->lastmod) {
        obj->info.lastmod = info->lastmod;
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
    if (info->content_type) {
        apr_size_t len = strlen(info->content_type) + 1;
        obj->info.content_type = (char*) malloc(len);
        if (!obj->info.content_type) {
            return APR_ENOMEM;
        }
        memcpy(obj->info.content_type, info->content_type, len);
    }
    if (info->etag) {
        apr_size_t len = strlen(info->etag) + 1;
        obj->info.etag = (char*) malloc(len);
        if (!obj->info.etag) {
            return APR_ENOMEM;
        }
        memcpy(obj->info.etag, info->etag, len);
    }
    if (info->lastmods) {
        apr_size_t len = strlen(info->lastmods) + 1;
        obj->info.lastmods = (char*) malloc(len);
        if (!obj->info.lastmods) {
            return APR_ENOMEM;
        }
        memcpy(obj->info.lastmods, info->lastmods, len);
    }
    if ( info->filename) {
        apr_size_t len = strlen(info->filename) + 1;
        obj->info.filename = (char*) malloc(len);
        if (!obj->info.filename ) {
            return APR_ENOMEM;
        }
        memcpy(obj->info.filename, info->filename, len);
    }

    return APR_SUCCESS;
}

static apr_status_t write_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b) 
{
    apr_status_t rv;
    cache_object_t *obj = h->cache_obj;
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
        APR_BRIGADE_FOREACH(e, b) {
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
            apr_file_unset_inherit(tmpfile);
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
    APR_BRIGADE_FOREACH(e, b) {
        const char *s;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            if (mobj->m_len > obj->count) {
                /* Caching a streamed response. Reallocate a buffer of the 
                 * correct size and copy the streamed response into that 
                 * buffer */
                char *buf = malloc(obj->count);
                if (!buf) {
                    return APR_ENOMEM;
                }
                memcpy(buf, mobj->m, obj->count);
                free(mobj->m);
                mobj->m = buf;

                /* Now comes the crufty part... there is no way to tell the
                 * cache that the size of the object has changed. We need
                 * to remove the object, update the size and re-add the 
                 * object, all under protection of the lock.
                 */
                if (sconf->lock) {
                    apr_thread_mutex_lock(sconf->lock);
                }
                cache_remove(sconf->cache_cache, obj);
                mobj->m_len = obj->count;
                cache_insert(sconf->cache_cache, obj);                
                sconf->cache_size -= (mobj->m_len - obj->count);
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
            /* Check for buffer overflow */
           if ((obj->count + len) > mobj->m_len) {
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
    int threaded_mpm;

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
        return "MCacheMinObjectSize value must be an integer (bytes)";
    }
    sconf->min_cache_object_size = val;
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
    apr_off_t val;
    char *err;
    val = (apr_off_t)strtol(arg, &err, 10);
    if (*err != 0) {
        return "MCacheMaxStreamingBuffer value must be a number";
    }
    sconf->max_streaming_buffer_size = val;
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

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(mem_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* cache initializer */
    /* cache_hook_init(cache_mem_init, NULL, NULL, APR_HOOK_MIDDLE);  */
    cache_hook_create_entity(create_entity, NULL, NULL, APR_HOOK_MIDDLE);
    cache_hook_open_entity(open_entity,  NULL, NULL, APR_HOOK_MIDDLE);
    cache_hook_remove_url(remove_url, NULL, NULL, APR_HOOK_MIDDLE);
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
