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

#define CORE_PRIVATE
#define CACHE_FD 0
#include "mod_cache.h"
#include "ap_mpm.h"
#include "apr_thread_mutex.h"

#if !APR_HAS_THREADS
#error This module does not currently compile unless you have a thread-capable APR. Sorry!
#endif

module AP_MODULE_DECLARE_DATA mem_cache_module;

/* 
 * XXX
 * This cache uses apr_hash functions which leak storage when something is removed
 * from the cache. This can be fixed in the apr_hash functions by making them use
 * malloc/free rather than pools to manage their storage requirements.
 */

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
    apr_ssize_t num_subprocess_env;
    apr_ssize_t num_notes;
    cache_header_tbl_t *header_out;
    cache_header_tbl_t *subprocess_env;
    cache_header_tbl_t *notes;
    apr_size_t m_len;
    void *m;
    apr_os_file_t fd;
} mem_cache_object_t;

typedef struct {
    apr_thread_mutex_t *lock;
    apr_hash_t *cacheht;
    apr_size_t cache_size;
    apr_size_t object_cnt;

    /* Fields set by config directives */
    apr_size_t min_cache_object_size;
    apr_size_t max_cache_object_size;
    apr_size_t max_cache_size;
    apr_size_t max_object_cnt;

} mem_cache_conf;
static mem_cache_conf *sconf;

#define DEFAULT_MAX_CACHE_SIZE 100*1024
#define DEFAULT_MIN_CACHE_OBJECT_SIZE 0
#define DEFAULT_MAX_CACHE_OBJECT_SIZE 10000
#define DEFAULT_MAX_OBJECT_CNT 1000
#define CACHEFILE_LEN 20

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t write_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t write_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static apr_status_t read_headers(cache_handle_t *h, request_rec *r);
static apr_status_t read_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

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
        free(mobj);
    }
    return;
}
static apr_status_t decrement_refcount(void *arg) 
{
    cache_object_t *obj = (cache_object_t *) arg;

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
    return APR_SUCCESS;
}
static apr_status_t cleanup_cache_mem(void *sconfv)
{
    cache_object_t *obj;
    apr_hash_index_t *hi;
    mem_cache_conf *co = (mem_cache_conf*) sconfv;

    if (!co) {
        return APR_SUCCESS;
    }

    /* Iterate over the cache and clean up each entry */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    for (hi = apr_hash_first(NULL, co->cacheht); hi; hi=apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void **)&obj);
        if (obj) {
            obj->cleanup = 1;
            if (!obj->refcount) {
                cleanup_cache_object(obj);
            }
        }
    }
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
    int threaded_mpm;

    sconf = apr_pcalloc(p, sizeof(mem_cache_conf));


    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    if (threaded_mpm) {
        apr_thread_mutex_create(&sconf->lock, APR_THREAD_MUTEX_DEFAULT, p);
    }
    sconf->cacheht = apr_hash_make(p);

    sconf->min_cache_object_size = DEFAULT_MIN_CACHE_OBJECT_SIZE;
    sconf->max_cache_object_size = DEFAULT_MAX_CACHE_OBJECT_SIZE;
    /* Number of objects in the cache */
    sconf->max_object_cnt = DEFAULT_MAX_OBJECT_CNT;
    sconf->object_cnt = 0;
    /* Size of the cache in KB */
    sconf->max_cache_size = DEFAULT_MAX_CACHE_SIZE;
    sconf->cache_size = 0;

    apr_pool_cleanup_register(p, NULL, cleanup_cache_mem, apr_pool_cleanup_null);

    return sconf;
}

static int create_entity(cache_handle_t *h, request_rec *r,
                         const char *type, 
                         const char *key, 
                         apr_size_t len) 
{
    cache_object_t *obj, *tmp_obj;
    mem_cache_object_t *mobj;

    if (strcasecmp(type, "mem")) {
        return DECLINED;
    }

    if (len < sconf->min_cache_object_size || 
        len > sconf->max_cache_object_size) {
        return DECLINED;
    }

    /*
     * TODO: Get smarter about managing the cache size.
     * If the cache is full, we need to do garbage collection
     * to weed out old/stale entries
     */
    if ((sconf->cache_size + len) > sconf->max_cache_size) {
        return DECLINED;
    }

    if (sconf->object_cnt >= sconf->max_object_cnt) {
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t */
    obj = calloc(1, sizeof(*obj));
    if (!obj) {
        return DECLINED;
    }
    obj->key = calloc(1, strlen(key) + 1);
    if (!obj->key) {
        cleanup_cache_object(obj);
        return DECLINED;
    }
    strncpy(obj->key, key, strlen(key) + 1);
    obj->info.len = len;


    /* Allocate and init mem_cache_object_t */
    mobj = calloc(1, sizeof(*mobj));
    if (!mobj) {
        cleanup_cache_object(obj);
        return DECLINED;
    }

    /* Reference mem_cache_object_t out of cache_object_t */
    obj->vobj = mobj;
    mobj->m_len = len;
    obj->complete = 0;
    obj->refcount = 1;

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
    tmp_obj = (cache_object_t *) apr_hash_get(sconf->cacheht, 
                                              key, 
                                              APR_HASH_KEY_STRING);
    if (!tmp_obj) {
        apr_hash_set(sconf->cacheht, obj->key, strlen(obj->key), obj);
        sconf->object_cnt++;
        sconf->cache_size += len;
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

    /* Set the cleanup flag and register the cleanup to cleanup
     * the cache_object_t if the cache load is aborted.
     */
    obj->cleanup = 1;
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
    if (strcasecmp(type, "mem")) {
        return DECLINED;
    }
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) apr_hash_get(sconf->cacheht, key, 
                                          APR_HASH_KEY_STRING);
    if (obj) {
        if (obj->complete) {
            obj->refcount++;
            apr_pool_cleanup_register(r->pool, obj, decrement_refcount,
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

    return OK;
}

static int remove_entity(cache_handle_t *h) 
{
    cache_object_t *obj = h->cache_obj;

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) apr_hash_get(sconf->cacheht, obj->key,
                                          APR_HASH_KEY_STRING);
    if (obj) {
        mem_cache_object_t *mobj = (mem_cache_object_t *) obj->vobj;
        apr_hash_set(sconf->cacheht, obj->key, strlen(obj->key), NULL);
        sconf->object_cnt--;
        sconf->cache_size -= mobj->m_len;
        obj->cleanup = 1;
        if (!obj->refcount) {
            cleanup_cache_object(obj);
        }
        h->cache_obj = NULL;
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
    apr_table_entry_t *elts = (apr_table_entry_t *) table->a.elts;
    apr_ssize_t i;
    apr_size_t len = 0;
    apr_size_t idx = 0;
    char *buf;
   
    *nelts = table->a.nelts;
    if (*nelts == 0 ) {
        *obj=NULL;
        return APR_SUCCESS;
    }
    *obj = calloc(1, sizeof(cache_header_tbl_t) * table->a.nelts);
    if (NULL == *obj) {
        return APR_ENOMEM;
    }
    for (i = 0; i < table->a.nelts; ++i) {
        len += strlen(elts[i].key);
        len += strlen(elts[i].val);
        len += 2;  /* Extra space for NULL string terminator for key and val */
    }

    /* Transfer the headers into a contiguous memory block */
    buf = calloc(1, len);
    if (!buf) {
        *obj = NULL;
        return APR_ENOMEM;
    }

    for (i = 0; i < *nelts; ++i) {
        (*obj)[i].hdr = &buf[idx];
        len = strlen(elts[i].key) + 1;              /* Include NULL terminator */
        strncpy(&buf[idx], elts[i].key, len);
        idx+=len;

        (*obj)[i].val = &buf[idx];
        len = strlen(elts[i].val) + 1;
        strncpy(&buf[idx], elts[i].val, len);
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
        apr_table_setn(t, ctbl[i].hdr, ctbl[i].val);
    } 

    return APR_SUCCESS;
}
/* Define request processing hook handlers */
static int remove_url(const char *type, const char *key) 
{
    cache_object_t *obj;

    if (strcasecmp(type, "mem")) {
        return DECLINED;
    }

    /* WIBNIF
     * apr_hash_set(..,..,..,NULL) returned pointer to the object just removed.
     * That way, we could free the object w/o doing another call to an
     * apr_hash function.
     */

    /* First, find the object in the cache */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) apr_hash_get(sconf->cacheht, key, 
                                          APR_HASH_KEY_STRING);
    if (obj) {
        mem_cache_object_t *mobj = (mem_cache_object_t *) obj->vobj;
        apr_hash_set(sconf->cacheht, key, APR_HASH_KEY_STRING, NULL);
        sconf->object_cnt--;
        sconf->cache_size -= mobj->m_len;
        obj->cleanup = 1;
        if (!obj->refcount) {
            cleanup_cache_object(obj);
        }
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (!obj) {
        return DECLINED;
    }
    
    return OK;
}

static apr_status_t read_headers(cache_handle_t *h, request_rec *r) 
{
    int rc;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;

    r->headers_out = apr_table_make(r->pool,mobj->num_header_out);
    r->subprocess_env = apr_table_make(r->pool, mobj->num_subprocess_env);
    r->notes = apr_table_make(r->pool, mobj->num_notes);
    rc = unserialize_table( mobj->header_out,
                            mobj->num_header_out, 
                            r->headers_out);
    rc = unserialize_table( mobj->subprocess_env, 
                            mobj->num_subprocess_env, 
                            r->subprocess_env);
    rc = unserialize_table( mobj->notes,
                            mobj->num_notes,
                            r->notes);
    return rc;
}

static apr_status_t read_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb) 
{
    apr_bucket *b;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;

    if (mobj->type == CACHE_TYPE_FILE) {
        /* CACHE_TYPE_FILE */
        apr_file_t *file;
        apr_os_file_put(&file, &mobj->fd, APR_READ|APR_XTHREAD, p);
        b = apr_bucket_file_create(file, 0, mobj->m_len, p);
    }
    else {
        /* CACHE_TYPE_HEAP */
        b = apr_bucket_immortal_create(mobj->m, mobj->m_len);
    }
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create();
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return APR_SUCCESS;
}


static apr_status_t write_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    cache_object_t *obj = h->cache_obj;
    mem_cache_object_t *mobj = (mem_cache_object_t*) obj->vobj;
    int rc;

    /* Precompute how much storage we need to hold the headers */
    rc = serialize_table(&mobj->header_out, 
                         &mobj->num_header_out, 
                         r->headers_out);   
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
    if (info->expire) {
        obj->info.expire = info->expire;
    }
    if (info->content_type) {
        obj->info.content_type = (char*) calloc(1, strlen(info->content_type) + 1);
        if (!obj->info.content_type) {
            return APR_ENOMEM;
        }
        strcpy(obj->info.content_type, info->content_type);
    }
    if ( info->filename) {
        obj->info.filename = (char*) calloc(1, strlen(info->filename) + 1);
        if (!obj->info.filename ) {
            return APR_ENOMEM;
        }
        strcpy(obj->info.filename, info->filename );
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

    if (CACHE_FD) {
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
                obj->complete = 1;
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
        if (fd == 1 && !other && obj->complete) {
            apr_file_t *tmpfile;

            mobj->type = CACHE_TYPE_FILE;
            /* Open a new XTHREAD handle to the file */
            rv = apr_file_open(&tmpfile, r->filename, 
                               APR_READ | APR_BINARY | APR_XTHREAD | APR_FILE_NOCLEANUP,
                               APR_OS_DEFAULT, r->pool);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            apr_file_unset_inherit(tmpfile);
            apr_os_file_get(&(mobj->fd), tmpfile);

            obj->cleanup = 0;
            obj->refcount--;    /* Count should be 0 now */
            apr_pool_cleanup_kill(r->pool, obj, decrement_refcount);

            /* Open for business */
            obj->complete = 1;
            return APR_SUCCESS;
        }
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
        mobj->type = CACHE_TYPE_HEAP;
        obj->count = 0;
    }
    cur = (char*) mobj->m + obj->count;

    /* Iterate accross the brigade and populate the cache storage */
    APR_BRIGADE_FOREACH(e, b) {
        const char *s;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            obj->cleanup = 0;
            obj->refcount--;    /* Count should be 0 now */
            apr_pool_cleanup_kill(r->pool, obj, decrement_refcount);

            /* Open for business */
            obj->complete = 1;
            break;
        }
        rv = apr_bucket_read(e, &s, &len, eblock);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        /* XXX Check for overflow */
        if (len ) {
            memcpy(cur, s, len);
            cur+=len;
            obj->count+=len;
        }
        /* This should not happen, but if it does, we are in BIG trouble
         * cause we just stomped all over the heap.
         */
        AP_DEBUG_ASSERT(obj->count > mobj->m_len);
    }
    return APR_SUCCESS;
}

static const char 
*set_max_cache_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    int val;

    if (sscanf(arg, "%d", &val) != 1) {
        return "CacheSize value must be an integer (kBytes)";
    }
    sconf->max_cache_size = val;
    return NULL;
}
static const char 
*set_min_cache_object_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%d", &val) != 1) {
        return "CacheMinObjectSize value must be an integer (bytes)";
    }
    sconf->min_cache_object_size = val;
    return NULL;
}
static const char 
*set_max_cache_object_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%d", &val) != 1) {
        return "CacheMaxObjectSize value must be an integer (KB)";
    }
    sconf->max_cache_object_size = val;
    return NULL;
}
static const char 
*set_max_object_count(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%d", &val) != 1) {
        return "CacheMaxObjectCount value must be an integer";
    }
    sconf->max_object_cnt = val;
    return NULL;
}

static const command_rec cache_cmds[] =
{
    AP_INIT_TAKE1("CacheSize", set_max_cache_size, NULL, RSRC_CONF,
     "The maximum space used by the cache in KB"),
    AP_INIT_TAKE1("CacheMaxObjectCount", set_max_object_count, NULL, RSRC_CONF,
     "The maximum number of objects allowed to be placed in the cache"),
    AP_INIT_TAKE1("CacheMinObjectSize", set_min_cache_object_size, NULL, RSRC_CONF,
     "The minimum size (in bytes) of an object to be placed in the cache"),
    AP_INIT_TAKE1("CacheMaxObjectSize", set_max_cache_object_size, NULL, RSRC_CONF,
     "The maximum size (in KB) of an object to be placed in the cache"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    /* cache initializer */
/*    cache_hook_cache_init(cache_init, NULL, NULL, AP_HOOK_FIRST); */
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

