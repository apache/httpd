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

APR_HOOK_STRUCT(
	APR_HOOK_LINK(remove_url)
	APR_HOOK_LINK(create_entity)
	APR_HOOK_LINK(open_entity)
)

AP_DECLARE_DATA extern module cache_module;

/* -------------------------------------------------------------- */

/*
 * delete all URL entities from the cache
 *
 */
int cache_remove_url(request_rec *r, const char *types, char *url)
{
    const char *next = types;
    const char *type;

    /* for each specified cache type, delete the URL */
    while(next) {
        type = ap_cache_tokstr(r->pool, next, &next);
        cache_run_remove_url(type, url);
    }
    return OK;
}


/*
 * create a new URL entity in the cache
 *
 * It is possible to store more than once entity per URL. This
 * function will always create a new entity, regardless of whether
 * other entities already exist for the same URL.
 *
 * The size of the entity is provided so that a cache module can
 * decide whether or not it wants to cache this particular entity.
 * If the size is unknown, a size of -1 should be set.
 */
int cache_create_entity(request_rec *r, const char *types, char *url, apr_size_t size)
{
    cache_handle_t *h = apr_pcalloc(r->pool, sizeof(h));
    const char *next = types;
    const char *type;
    apr_status_t rv;
    cache_request_rec *cache = (cache_request_rec *) ap_get_module_config(r->request_config, 
                                                                          &cache_module);

    /* for each specified cache type, delete the URL */
    while (next) {
        type = ap_cache_tokstr(r->pool, next, &next);
        switch (rv = cache_run_create_entity(h, type, url, size)) {
        case OK: {
            cache->handle = h;
            return OK;
        }
        case DECLINED: {
            continue;
        }
        default: {
            return rv;
        }
        }
    }
    return DECLINED;
}

/*
 * remove a specific URL entity from the cache
 *
 * The specific entity referenced by the cache_handle is removed
 * from the cache, and the cache_handle is closed.
 */
/* XXX Don't think we need to pass in request_rec or types ... */
int cache_remove_entity(request_rec *r, const char *types, cache_handle_t *h)
{
    h->remove_entity(h);
    return 1;
}

/*
 * select a specific URL entity in the cache
 *
 * It is possible to store more than one entity per URL. Content
 * negotiation is used to select an entity. Once an entity is
 * selected, details of it are stored in the per request
 * config to save time when serving the request later.
 *
 * This function returns OK if successful, DECLINED if no
 * cached entity fits the bill.
 */
int cache_select_url(request_rec *r, const char *types, char *url)
{
    const char *next = types;
    const char *type;
    apr_status_t rv;
    cache_request_rec *cache = (cache_request_rec *) ap_get_module_config(r->request_config, 
                                                                          &cache_module);

    /* go through the cache types till we get a match */
    cache->handle = apr_palloc(r->pool, sizeof(cache_handle_t));

    while (next) {
        type = ap_cache_tokstr(r->pool, next, &next);
        switch ((rv = cache_run_open_entity(cache->handle, type, url))) {
        case OK: {
            /* XXX:
             * Handle being returned a collection of entities.
             */

            /* Has the cache entry expired? */
#if 0
            if (r->request_time > cache->handle... need to get info out of the cache... info.expire)
                cache->fresh = 0;
            else
#endif
                cache->fresh = 1;

            /*** do content negotiation here */
            return OK;
        }
        case DECLINED: {
            /* try again with next cache type */
            continue;
        }
        default: {
            /* oo-er! an error */
            cache->handle = NULL;
            return rv;
        }
        }
    }
    cache->handle = NULL;
    return DECLINED;
}

apr_status_t cache_write_entity_headers(cache_handle_t *h, request_rec *r, cache_info *info,
                                        apr_table_t *headers)
{
    h->write_headers(h, r, info, headers);
    return APR_SUCCESS;
}
apr_status_t cache_write_entity_body(cache_handle_t *h, apr_bucket_brigade *b) 
{
    apr_status_t rv = APR_SUCCESS;
    if (h->write_body(h, b) != OK) {
    }
    return rv;
}

apr_status_t cache_read_entity_headers(cache_handle_t *h, request_rec *r, 
                                       apr_table_t **headers)
{
    /* Build the header table from info in the info struct */
    *headers = apr_table_make(r->pool, 15);

    h->read_headers(h, r, *headers);

    return APR_SUCCESS;
}
apr_status_t cache_read_entity_body(cache_handle_t *h, apr_bucket_brigade *b) 
{
    h->read_body(h, b);
    return APR_SUCCESS;
}

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, create_entity, 
                                      (cache_handle_t *h, const char *type, 
                                      char *url, apr_size_t len),(h,type,url,len),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, open_entity,  
                                      (cache_handle_t *h, const char *type, 
                                      char *url),(h,type,url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(cache, CACHE, int, remove_url, 
                                    (const char *type, char *url),(type,url),OK,DECLINED)
#if 0
/* BillS doesn't think these should be hooks.
 * All functions which accept a cache_handle * argument should use
 * function pointers in the cache_handle. Leave them here for now as 
 * points for discussion...
 */

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, remove_entity, 
                                     (cache_handle *h),(h),DECLINED)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, read_entity_headers, 
                                     (cache_handle *h, request_rec *r,
                                      apr_table_t **headers),
                                      (h,info,headers_in,headers_out),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, read_entity_body, 
                                     (cache_handle *h,
                                      apr_bucket_brigade *out),(h,out),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, write_entity_headers, 
                                     (cache_handle *h, cache_info *info,
                                      apr_table_t *headers_in, 
                                      apr_table_t *headers_out),
                                      (h,info,headers_in,headers_out),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, write_entity_body, 
                                     (cache_handle *h,
                                      apr_bucket_brigade *in),(h,in),DECLINED)
#endif
