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

#include "mod_cache.h"
#include "ap_mpm.h"
#include "apr_thread_mutex.h"

#if !APR_HAS_THREADS
#error This module does not currently compile unless you have a thread-capable APR. Sorry!
#endif

static apr_size_t max_cache_entry_size = 5000;
module AP_MODULE_DECLARE_DATA mem_cache_module;

/* 
 * XXX
 * This cache uses apr_hash functions which leak storage when something is removed
 * from the cache. This can be fixed in the apr_hash functions by making them use
 * malloc/free rather than pools to manage their storage requirements.
 */

/*
 * XXX Introduce a type field that identifies whether the cache obj
 * references malloc'ed or mmap storage or a file descriptor
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
} mem_cache_object_t;

typedef struct {
    apr_thread_mutex_t *lock;
    apr_hash_t *cacheht;
    int space;
    apr_time_t maxexpire;
    apr_time_t defaultexpire;
} mem_cache_conf;
static mem_cache_conf *sconf;

#define DEFAULT_CACHE_SPACE 100*1024
#define CACHEFILE_LEN 20

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static int write_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static int write_body(cache_handle_t *h, apr_bucket_brigade *b);
static int read_headers(cache_handle_t *h, request_rec *r);
static int read_body(cache_handle_t *h, apr_bucket_brigade *bb);

static void cleanup_cache_object(cache_object_t *obj)
{
    mem_cache_object_t *mobj = obj->vobj;

    /* The cache object has been removed from the cache. Now clean
     * it up, freeing any storage, closing file descriptors, etc.
     */
    /* XXX - 
     * The action of freeing a cache entry is asynchronous with the rest of 
     * the operation of the cache. Frees can be driven by garbage collection,
     * the result of some command or an HTTP request.  It is okay to remove 
     * an entry from the cache at anytime but we need a mechanism to keep 
     * us from cleaning up the cache entry out from under other threads 
     * that may still be referencing it.
     * 
     * Bill thinks that we need a special purpose reference counted 
     * bucket (or three).  When an entry is removed from the cache, the
     * bucket for that entry is marked for cleanup. A bucket marked for 
     * cleanup is freed by the last routine referencing the bucket,
     * either during brigade destroy or this routine.
     */

    /* 
     * Ref count decrementing and checking needs to be atomic

       obj->ref_count--;
       if (obj->ref_count) {
           defer_cleanup (let the brigade cleanup free the bucket)
       }
       else {
           free the bucket
       }
    */

    /* Cleanup the cache_object_t */
    if (obj->key) {
        free(obj->key);
    }
    free(obj);
    
    /* Cleanup the mem_cache_object_t */
    if (!mobj) {
        return;
    }
    if (mobj->m) {
        free(mobj->m);
    }
    /* XXX should freeing of the info be done here or in cache_storage ? 
    if (obj->info.content_type ) {
        free((char*)obj->info.content_type );
        obj->info.content_type =NULL;
    }
    if (obj->info.filename ) {
        free( (char*)obj->info.filename );
        obj->info.filename= NULL;
    }
    */
    /* XXX Cleanup the headers */
    if (mobj->num_header_out) {
        
    }
    free(mobj);
}

static apr_status_t cleanup_cache_mem(void *sconfv)
{
    cache_object_t *obj;
    apr_hash_index_t *hi;
    mem_cache_conf *co = (mem_cache_conf*) sconfv;

    if (!co) {
        return APR_SUCCESS;
    }

    /* Iterate over the frag hash table and clean up each entry */
    /* XXX need to lock the hash */
    for (hi = apr_hash_first(NULL, co->cacheht); hi; hi=apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void **)&obj);
        if (obj)
            cleanup_cache_object(obj);
    }
    return APR_SUCCESS;
}
static void *create_cache_config(apr_pool_t *p, server_rec *s)
{
    int threaded_mpm;

    sconf = apr_pcalloc(p, sizeof(mem_cache_conf));
    sconf->space = DEFAULT_CACHE_SPACE;

    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    if (threaded_mpm) {
        apr_thread_mutex_create(&sconf->lock, APR_THREAD_MUTEX_DEFAULT, p);
    }
    sconf->cacheht = apr_hash_make(p);
    apr_pool_cleanup_register(p, NULL, cleanup_cache_mem, apr_pool_cleanup_null);

    return sconf;
}

static int create_entity(cache_handle_t *h, 
                         const char *type, 
                         const char *key, 
                         apr_size_t len) 
{
    cache_object_t *obj, *tmp_obj;
    mem_cache_object_t *mobj;

    if (strcasecmp(type, "mem")) {
        return DECLINED;
    }

    /* XXX Check len to see if it is withing acceptable bounds 
     * max cache check should be configurable variable.
     */
    if (len < 0 || len > max_cache_entry_size) {
        return DECLINED;
    }
    /* XXX Check total cache size and number of entries. Are they within the
     * configured limits? If not, kick off garbage collection thread.
     */

    /* Allocate and initialize cache_object_t */
    obj = malloc(sizeof(*obj));
    if (!obj) {
        return DECLINED;
    }
    memset(obj,'\0', sizeof(*obj));
    obj->key = malloc(strlen(key) + 1);
    if (!obj->key) {
        free(obj);
        return DECLINED;
    }
    strncpy(obj->key, key, strlen(key) + 1);
    obj->info.len = len;
    obj->complete = 0;   /* Cache object is not complete */


    /* Allocate and init mem_cache_object_t */
    mobj = malloc(sizeof(*mobj));
    if (!mobj) {
        /* XXX: Cleanup */
        cleanup_cache_object(obj);
    }
    memset(mobj,'\0', sizeof(*mobj));
    obj->vobj = mobj;    /* Reference the mem_cache_object_t out of 
                          * cache_object_t 
                          */
    mobj->m_len = len;    /* Duplicates info in cache_object_t info */


    /* Place the cache_object_t into the hash table
     * XXX Need a way to insert into the cache w/o such coarse grained locking 
     * XXX Need to enable caching multiple cache objects (representing different
     * views of the same content) under a single search key
     */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    tmp_obj = (cache_object_t *) apr_hash_get(sconf->cacheht, 
                                              key, 
                                              APR_HASH_KEY_STRING);
    if (!tmp_obj) {
        apr_hash_set(sconf->cacheht, obj->key, strlen(obj->key), obj);
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

    /* Populate the cache handle */
    h->cache_obj = obj;
    h->read_body = &read_body;
    h->read_headers = &read_headers;
    h->write_body = &write_body;
    h->write_headers = &write_headers;
    h->remove_entity = &remove_entity;

    return OK;
}

static int open_entity(cache_handle_t *h, const char *type, const char *key) 
{
    cache_object_t *obj;

    /* Look up entity keyed to 'url' */
    if (strcasecmp(type, "mem")) {
        return DECLINED;
    }
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) apr_hash_get(sconf->cacheht, 
                                          key, 
                                          APR_HASH_KEY_STRING);
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (!obj || !(obj->complete)) {
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
    apr_hash_set(sconf->cacheht, obj->key, strlen(obj->key), NULL);
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    cleanup_cache_object(obj);
    
    return OK;
}
static int serialize_table( cache_header_tbl_t **obj, 
                            int*nelts, 
                            apr_table_t *table) 
{
   apr_table_entry_t *elts = (apr_table_entry_t *) table->a.elts;
   apr_ssize_t i;
   apr_size_t len = 0;
   apr_size_t idx = 0;
   char *buf;
   
   *nelts = table->a.nelts;
   if (*nelts ==0 ) {
       *obj=NULL;
       return OK;
   }
    *obj = malloc(sizeof(cache_header_tbl_t) * table->a.nelts);
    if (NULL == *obj) {
        /* cleanup_cache_obj(h->cache_obj); */
        return DECLINED;
    }
    for (i = 0; i < table->a.nelts; ++i) {
        len += strlen(elts[i].key);
        len += strlen(elts[i].val);
        len += 2;  /* Extra space for NULL string terminator for key and val */
    }

    /* Transfer the headers into a contiguous memory block */
    buf = malloc(len);
    if (!buf) {
        free(obj);
        *obj = NULL;
        /* cleanup_cache_obj(h->cache_obj); */
        return DECLINED;
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
    return OK;
 
}
static int unserialize_table( cache_header_tbl_t *ctbl, 
                              int num_headers, 
                              apr_table_t *t )
{
    int i;

    for (i = 0; i < num_headers; ++i) {
        apr_table_setn(t, ctbl[i].hdr, ctbl[i].val);
    } 

    return OK;
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
    obj = (cache_object_t *) apr_hash_get(sconf->cacheht, 
                                          key, 
                                          APR_HASH_KEY_STRING);
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (!obj) {
        return DECLINED;
    }

    /* Found it. Now take it out of the cache and free it. */
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    apr_hash_set(sconf->cacheht, obj->key, strlen(obj->key), NULL);
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    cleanup_cache_object(obj);

    return OK;
}

static int read_headers(cache_handle_t *h, request_rec *r) 
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

static int read_body(cache_handle_t *h, apr_bucket_brigade *bb) 
{
    apr_bucket *b;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;
    
    b = apr_bucket_immortal_create(mobj->m, mobj->m_len);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create();
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return OK;
}


static int write_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    cache_object_t *obj = h->cache_obj;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;
    int rc;

    /* Precompute how much storage we need to hold the headers */
    rc = serialize_table(&mobj->header_out, 
                         &mobj->num_header_out, 
                         r->headers_out);   
    if (rc != OK ) {
        return rc;
    }
    rc = serialize_table(&mobj->subprocess_env,
                         &mobj->num_subprocess_env, 
                         r->subprocess_env );
    if (rc != OK ) {
        return rc;
    }

    rc = serialize_table(&mobj->notes, &mobj->num_notes, r->notes);
    if (rc != OK ) {
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
        obj->info.content_type = (char*) malloc(strlen(info->content_type) + 1);
        if (!obj->info.content_type) {
            /* cleanup the object? */
            return DECLINED;
        }
        strcpy((char*) obj->info.content_type, info->content_type);
    }
    if ( info->filename) {
        obj->info.filename = (char*) malloc(strlen(info->filename )+1);
        if (!obj->info.filename ) {
            free( (char*)obj->info.content_type );
            obj->info.content_type =NULL;
            return DECLINED;
        }
        strcpy((char*) obj->info.filename, info->filename );
    }

    return OK;
}

static int write_body(cache_handle_t *h, apr_bucket_brigade *b) 
{
    apr_status_t rv;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;
    apr_read_type_e eblock = APR_BLOCK_READ;
    apr_bucket *e;
    char *cur;
    
    /* XXX mmap, malloc or file? 
     * Enable this decision to be configured....
     * XXX cache buckets...
     */
    if (mobj->m == NULL) {
        mobj->m = malloc(mobj->m_len);
        if (mobj->m == NULL) {
            /* Cleanup cache entry and return */
        }
        mobj->type = CACHE_TYPE_HEAP;
        h->cache_obj->count = 0;
    }
    cur = (char*) mobj->m + h->cache_obj->count;

    /* Iterate accross the brigade and populate the cache storage */
    APR_BRIGADE_FOREACH(e, b) {
        const char *s;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            h->cache_obj->complete = 1;
            break;
        }
        rv = apr_bucket_read(e, &s, &len, eblock);
        if (rv != APR_SUCCESS) {
            /* Big problem!  Cleanup cache entry and return */
        }
        /* XXX Check for overflow */
        if (len ) {
            memcpy(cur, s, len);
            cur+=len;
            h->cache_obj->count+=len;
        }
        /* This should not happen, but if it does, we are in BIG trouble
         * cause we just stomped all over the heap.
         */
        AP_DEBUG_ASSERT(h->cache_obj->count > mobj->m_len);
    }
    return OK;
}

static const char 
*set_cache_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    int val;

    if (sscanf(arg, "%d", &val) != 1) {
        return "CacheSize value must be an integer (kBytes)";
    }
    sconf->space = val;
    return NULL;
}
static const char 
*set_cache_entry_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    int val;

    if (sscanf(arg, "%d", &val) != 1) {
        return "CacheSize value must be an integer (bytes)";
    }
    max_cache_entry_size = val;
    return NULL;
}


static const command_rec cache_cmds[] =
{
    /* XXX
     * What config directives does this module need?
     * Should this module manage expire policy for its entries?
     * Certainly cache limits like max number of entries,
     * max entry size, and max size of the cache should
     * be managed by this module. 
     */
    AP_INIT_TAKE1("CacheMemSize", set_cache_size, NULL, RSRC_CONF,
     "The maximum space used by the cache in Kb"),
    AP_INIT_TAKE1("CacheMemEntrySize", set_cache_entry_size, NULL, RSRC_CONF,
     "The maximum size (in bytes) that a entry can take"),
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

