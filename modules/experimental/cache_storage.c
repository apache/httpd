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

#define CORE_PRIVATE

#include "mod_cache.h"

APR_HOOK_STRUCT(
	APR_HOOK_LINK(remove_url)
	APR_HOOK_LINK(create_entity)
	APR_HOOK_LINK(open_entity)
)

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;

/* -------------------------------------------------------------- */

/*
 * delete all URL entities from the cache
 *
 */
int cache_remove_url(request_rec *r, const char *types, char *url)
{
    const char *next = types;
    const char *type;
    apr_status_t rv;
    char *key;

    rv = cache_generate_key(r,r->pool,&key);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* for each specified cache type, delete the URL */
    while(next) {
        type = ap_cache_tokstr(r->pool, next, &next);
        cache_run_remove_url(type, key);
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
int cache_create_entity(request_rec *r, const char *types, char *url, apr_off_t size)
{
    cache_handle_t *h = apr_pcalloc(r->pool, sizeof(cache_handle_t));
    const char *next = types;
    const char *type;
    char *key;
    apr_status_t rv;
    cache_request_rec *cache = (cache_request_rec *) 
                         ap_get_module_config(r->request_config, &cache_module);

    rv =  cache_generate_key(r,r->pool,&key);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    /* for each specified cache type, delete the URL */
    while (next) {
        type = ap_cache_tokstr(r->pool, next, &next);
        switch (rv = cache_run_create_entity(h, r, type, key, size)) {
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
    cache_handle_t *h;
    char *key;
    cache_request_rec *cache = (cache_request_rec *) 
                         ap_get_module_config(r->request_config, &cache_module);

    rv =  cache_generate_key(r,r->pool,&key);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    /* go through the cache types till we get a match */
    h = cache->handle = apr_palloc(r->pool, sizeof(cache_handle_t));

    while (next) {
        type = ap_cache_tokstr(r->pool, next, &next);
        switch ((rv = cache_run_open_entity(h, r, type, key))) {
        case OK: {
            char *vary = NULL;
            const char *varyhdr = NULL;
            if (cache_read_entity_headers(h, r) != APR_SUCCESS) {
                /* TODO: Handle this error */
                return DECLINED;
            }

            /*
             * Check Content-Negotiation - Vary
             * 
             * At this point we need to make sure that the object we found in the cache
             * is the same object that would be delivered to the client, when the
             * effects of content negotiation are taken into effect.
             * 
             * In plain english, we want to make sure that a language-negotiated
             * document in one language is not given to a client asking for a
             * language negotiated document in a different language by mistake.
             * 
             * This code makes the assumption that the storage manager will
             * cache the req_hdrs if the response contains a Vary
             * header.
             * 
             * RFC2616 13.6 and 14.44 describe the Vary mechanism.
             */
            if ((varyhdr = apr_table_get(r->err_headers_out, "Vary")) == NULL) {
                varyhdr = apr_table_get(r->headers_out, "Vary");
            }
            vary = apr_pstrdup(r->pool, varyhdr);
            while (vary && *vary) {
                char *name = vary;
                const char *h1, *h2;

                /* isolate header name */
                while (*vary && !apr_isspace(*vary) && (*vary != ','))
                    ++vary;
                while (*vary && (apr_isspace(*vary) || (*vary == ','))) {
                    *vary = '\0';
                    ++vary;
                }

                /*
                 * is this header in the request and the header in the cached
                 * request identical? If not, we give up and do a straight get
                 */
                h1 = apr_table_get(r->headers_in, name);
                h2 = apr_table_get(h->req_hdrs, name);
                if (h1 == h2) {
                    /* both headers NULL, so a match - do nothing */
                }
                else if (h1 && h2 && !strcmp(h1, h2)) {
                    /* both headers exist and are equal - do nothing */
                }
                else {
                    /* headers do not match, so Vary failed */
                    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r->server,
                                 "cache_select_url(): Vary header mismatch - Cached document cannot be used. \n");
                    apr_table_clear(r->headers_out);
                    r->status_line = NULL;
                    cache->handle = NULL;
                    return DECLINED;
                }
            }
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

apr_status_t cache_write_entity_headers(cache_handle_t *h, 
                                        request_rec *r, 
                                        cache_info *info)
{
    return (h->write_headers(h, r, info));
}
apr_status_t cache_write_entity_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b) 
{
    return (h->write_body(h, r, b));
}

apr_status_t cache_read_entity_headers(cache_handle_t *h, request_rec *r)
{
    apr_status_t rv;
    cache_info *info = &(h->cache_obj->info);

    /* Build the header table from info in the info struct */
    rv = h->read_headers(h, r);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    r->filename = apr_pstrdup(r->pool, info->filename );

    return APR_SUCCESS;
}
apr_status_t cache_read_entity_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *b) 
{
    return (h->read_body(h, p, b));
}

apr_status_t cache_generate_key_default( request_rec *r, apr_pool_t*p, char**key ) 
{
    if (r->hostname) {
        *key = apr_pstrcat(p, r->hostname, r->uri, "?", r->args, NULL);
    }
    else {
        *key = apr_pstrcat(p, r->uri, "?", r->args, NULL);
    }
    return APR_SUCCESS;
}

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, create_entity, 
                                      (cache_handle_t *h, request_rec *r, const char *type, 
                                      const char *urlkey, apr_off_t len),
                                      (h, r, type,urlkey,len),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(cache, CACHE, int, open_entity,  
                                      (cache_handle_t *h, request_rec *r, const char *type, 
                                      const char *urlkey),(h,r,type,urlkey),
                                      DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(cache, CACHE, int, remove_url, 
                                    (const char *type, const char *urlkey),
                                    (type,urlkey),OK,DECLINED)


