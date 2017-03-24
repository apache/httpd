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

#include "mod_cache.h"

#include "cache_storage.h"
#include "cache_util.h"

module AP_MODULE_DECLARE_DATA cache_module;
APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

/* -------------------------------------------------------------- */


/* Handles for cache filters, resolved at startup to eliminate
 * a name-to-function mapping on each request
 */
static ap_filter_rec_t *cache_filter_handle;
static ap_filter_rec_t *cache_save_filter_handle;
static ap_filter_rec_t *cache_save_subreq_filter_handle;
static ap_filter_rec_t *cache_out_filter_handle;
static ap_filter_rec_t *cache_out_subreq_filter_handle;
static ap_filter_rec_t *cache_remove_url_filter_handle;
static ap_filter_rec_t *cache_invalidate_filter_handle;

/**
 * Entity headers' names
 */
static const char *MOD_CACHE_ENTITY_HEADERS[] = {
    "Allow",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-MD5",
    "Content-Range",
    "Content-Type",
    "Last-Modified",
    NULL
};

/*
 * CACHE handler
 * -------------
 *
 * Can we deliver this request from the cache?
 * If yes:
 *   deliver the content by installing the CACHE_OUT filter.
 * If no:
 *   check whether we're allowed to try cache it
 *   If yes:
 *     add CACHE_SAVE filter
 *   If No:
 *     oh well.
 *
 * By default, the cache handler runs in the quick handler, bypassing
 * virtually all server processing and offering the cache its optimal
 * performance. In this mode, the cache bolts onto the front of the
 * server, and behaves as a discrete RFC2616 caching proxy
 * implementation.
 *
 * Under certain circumstances, an admin might want to run the cache as
 * a normal handler instead of a quick handler, allowing the cache to
 * run after the authorisation hooks, or by allowing fine control over
 * the placement of the cache in the filter chain. This option comes at
 * a performance penalty, and should only be used to achieve specific
 * caching goals where the admin understands what they are doing.
 */

static int cache_quick_handler(request_rec *r, int lookup)
{
    apr_status_t rv;
    const char *auth;
    cache_provider_list *providers;
    cache_request_rec *cache;
    apr_bucket_brigade *out;
    apr_bucket *e;
    ap_filter_t *next;
    ap_filter_rec_t *cache_out_handle;
    cache_server_conf *conf;

    conf = (cache_server_conf *) ap_get_module_config(r->server->module_config,
                                                      &cache_module);

    /* only run if the quick handler is enabled */
    if (!conf->quick) {
        return DECLINED;
    }

    /*
     * Which cache module (if any) should handle this request?
     */
    if (!(providers = cache_get_providers(r, conf))) {
        return DECLINED;
    }

    /* make space for the per request config */
    cache = apr_pcalloc(r->pool, sizeof(cache_request_rec));
    cache->size = -1;
    cache->out = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    /* save away the possible providers */
    cache->providers = providers;

    /*
     * Are we allowed to serve cached info at all?
     */
    if (!ap_cache_check_no_store(cache, r)) {
        return DECLINED;
    }

    /* find certain cache controlling headers */
    auth = apr_table_get(r->headers_in, "Authorization");

    /* First things first - does the request allow us to return
     * cached information at all? If not, just decline the request.
     */
    if (auth) {
        return DECLINED;
    }

    /* Are we PUT/POST/DELETE? If so, prepare to invalidate the cached entities.
     */
    switch (r->method_number) {
    case M_PUT:
    case M_POST:
    case M_DELETE:
    {

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02461)
                "PUT/POST/DELETE: Adding CACHE_INVALIDATE filter for %s",
                r->uri);

        /* Add cache_invalidate filter to this request to force a
         * cache entry to be invalidated if the response is
         * ultimately successful (2xx).
         */
        ap_add_output_filter_handle(
                cache_invalidate_filter_handle, cache, r,
                r->connection);

        return DECLINED;
    }
    case M_GET: {
        break;
    }
    default : {

        ap_log_rerror(
                APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02462) "cache: Method '%s' not cacheable by mod_cache, ignoring: %s", r->method, r->uri);

        return DECLINED;
    }
    }

    /*
     * Try to serve this request from the cache.
     *
     * If no existing cache file (DECLINED)
     *   add cache_save filter
     * If cached file (OK)
     *   clear filter stack
     *   add cache_out filter
     *   return OK
     */
    rv = cache_select(cache, r);
    if (rv != OK) {
        if (rv == DECLINED) {
            if (!lookup) {

                /* try to obtain a cache lock at this point. if we succeed,
                 * we are the first to try and cache this url. if we fail,
                 * it means someone else is already trying to cache this
                 * url, and we should just let the request through to the
                 * backend without any attempt to cache. this stops
                 * duplicated simultaneous attempts to cache an entity.
                 */
                rv = cache_try_lock(conf, cache, r);
                if (APR_SUCCESS == rv) {

                    /*
                     * Add cache_save filter to cache this request. Choose
                     * the correct filter by checking if we are a subrequest
                     * or not.
                     */
                    if (r->main) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                                r, APLOGNO(00749) "Adding CACHE_SAVE_SUBREQ filter for %s",
                                r->uri);
                        cache->save_filter = ap_add_output_filter_handle(
                                cache_save_subreq_filter_handle, cache, r,
                                r->connection);
                    }
                    else {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                                r, APLOGNO(00750) "Adding CACHE_SAVE filter for %s",
                                r->uri);
                        cache->save_filter = ap_add_output_filter_handle(
                                cache_save_filter_handle, cache, r,
                                r->connection);
                    }

                    apr_pool_userdata_setn(cache, CACHE_CTX_KEY, NULL, r->pool);

                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00751)
                            "Adding CACHE_REMOVE_URL filter for %s",
                            r->uri);

                    /* Add cache_remove_url filter to this request to remove a
                     * stale cache entry if needed. Also put the current cache
                     * request rec in the filter context, as the request that
                     * is available later during running the filter may be
                     * different due to an internal redirect.
                     */
                    cache->remove_url_filter = ap_add_output_filter_handle(
                            cache_remove_url_filter_handle, cache, r,
                            r->connection);

                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv,
                            r, APLOGNO(00752) "Cache locked for url, not caching "
                            "response: %s", r->uri);
                    /* cache_select() may have added conditional headers */
                    if (cache->stale_headers) {
                        r->headers_in = cache->stale_headers;
                    }

                }
            }
            else {
                if (cache->stale_headers) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                            r, APLOGNO(00753) "Restoring request headers for %s",
                            r->uri);

                    r->headers_in = cache->stale_headers;
                }
            }
        }
        else {
            /* error */
            return rv;
        }
        return DECLINED;
    }

    /* we've got a cache hit! tell everyone who cares */
    cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_HIT,
            "cache hit");

    /* if we are a lookup, we are exiting soon one way or another; Restore
     * the headers. */
    if (lookup) {
        if (cache->stale_headers) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00754)
                    "Restoring request headers.");
            r->headers_in = cache->stale_headers;
        }
    }

    rv = ap_meets_conditions(r);
    if (rv != OK) {
        /* If we are a lookup, we have to return DECLINED as we have no
         * way of knowing if we will be able to serve the content.
         */
        if (lookup) {
            return DECLINED;
        }

        /* Return cached status. */
        return rv;
    }

    /* If we're a lookup, we can exit now instead of serving the content. */
    if (lookup) {
        return OK;
    }

    /* Serve up the content */

    /* We are in the quick handler hook, which means that no output
     * filters have been set. So lets run the insert_filter hook.
     */
    ap_run_insert_filter(r);

    /*
     * Add cache_out filter to serve this request. Choose
     * the correct filter by checking if we are a subrequest
     * or not.
     */
    if (r->main) {
        cache_out_handle = cache_out_subreq_filter_handle;
    }
    else {
        cache_out_handle = cache_out_filter_handle;
    }
    ap_add_output_filter_handle(cache_out_handle, cache, r, r->connection);

    /*
     * Remove all filters that are before the cache_out filter. This ensures
     * that we kick off the filter stack with our cache_out filter being the
     * first in the chain. This make sense because we want to restore things
     * in the same manner as we saved them.
     * There may be filters before our cache_out filter, because
     *
     * 1. We call ap_set_content_type during cache_select. This causes
     *    Content-Type specific filters to be added.
     * 2. We call the insert_filter hook. This causes filters e.g. like
     *    the ones set with SetOutputFilter to be added.
     */
    next = r->output_filters;
    while (next && (next->frec != cache_out_handle)) {
        ap_remove_output_filter(next);
        next = next->next;
    }

    /* kick off the filter stack */
    out = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    e = apr_bucket_eos_create(out->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(out, e);

    return ap_pass_brigade_fchk(r, out,
                                "cache_quick_handler(%s): ap_pass_brigade returned",
                                cache->provider_name);
}

/**
 * If the two filter handles are present within the filter chain, replace
 * the last instance of the first filter with the last instance of the
 * second filter, and return true. If the second filter is not present at
 * all, the first filter is removed, and false is returned. If neither
 * filter is present, false is returned and this function does nothing.
 * If a stop filter is specified, processing will stop once this filter is
 * reached.
 */
static int cache_replace_filter(ap_filter_t *next, ap_filter_rec_t *from,
        ap_filter_rec_t *to, ap_filter_rec_t *stop) {
    ap_filter_t *ffrom = NULL, *fto = NULL;
    while (next && next->frec != stop) {
        if (next->frec == from) {
            ffrom = next;
        }
        if (next->frec == to) {
            fto = next;
        }
        next = next->next;
    }
    if (ffrom && fto) {
        ffrom->frec = fto->frec;
        ffrom->ctx = fto->ctx;
        ap_remove_output_filter(fto);
        return 1;
    }
    if (ffrom) {
        ap_remove_output_filter(ffrom);
    }
    return 0;
}

/**
 * Find the given filter, and return it if found, or NULL otherwise.
 */
static ap_filter_t *cache_get_filter(ap_filter_t *next, ap_filter_rec_t *rec) {
    while (next) {
        if (next->frec == rec && next->ctx) {
            break;
        }
        next = next->next;
    }
    return next;
}

/**
 * The cache handler is functionally similar to the cache_quick_hander,
 * however a number of steps that are required by the quick handler are
 * not required here, as the normal httpd processing has already handled
 * these steps.
 */
static int cache_handler(request_rec *r)
{
    apr_status_t rv;
    cache_provider_list *providers;
    cache_request_rec *cache;
    apr_bucket_brigade *out;
    apr_bucket *e;
    ap_filter_t *next;
    ap_filter_rec_t *cache_out_handle;
    ap_filter_rec_t *cache_save_handle;
    cache_server_conf *conf;

    conf = (cache_server_conf *) ap_get_module_config(r->server->module_config,
                                                      &cache_module);

    /* only run if the quick handler is disabled */
    if (conf->quick) {
        return DECLINED;
    }

    /*
     * Which cache module (if any) should handle this request?
     */
    if (!(providers = cache_get_providers(r, conf))) {
        return DECLINED;
    }

    /* make space for the per request config */
    cache = apr_pcalloc(r->pool, sizeof(cache_request_rec));
    cache->size = -1;
    cache->out = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    /* save away the possible providers */
    cache->providers = providers;

    /*
     * Are we allowed to serve cached info at all?
     */
    if (!ap_cache_check_no_store(cache, r)) {
        return DECLINED;
    }

    /* Are we PUT/POST/DELETE? If so, prepare to invalidate the cached entities.
     */
    switch (r->method_number) {
    case M_PUT:
    case M_POST:
    case M_DELETE:
    {

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02463)
                "PUT/POST/DELETE: Adding CACHE_INVALIDATE filter for %s",
                r->uri);

        /* Add cache_invalidate filter to this request to force a
         * cache entry to be invalidated if the response is
         * ultimately successful (2xx).
         */
        ap_add_output_filter_handle(
                cache_invalidate_filter_handle, cache, r,
                r->connection);

        return DECLINED;
    }
    case M_GET: {
        break;
    }
    default : {

        ap_log_rerror(
                APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02464) "cache: Method '%s' not cacheable by mod_cache, ignoring: %s", r->method, r->uri);

        return DECLINED;
    }
    }

    /*
     * Try to serve this request from the cache.
     *
     * If no existing cache file (DECLINED)
     *   add cache_save filter
     * If cached file (OK)
     *   clear filter stack
     *   add cache_out filter
     *   return OK
     */
    rv = cache_select(cache, r);
    if (rv != OK) {
        if (rv == DECLINED) {

            /* try to obtain a cache lock at this point. if we succeed,
             * we are the first to try and cache this url. if we fail,
             * it means someone else is already trying to cache this
             * url, and we should just let the request through to the
             * backend without any attempt to cache. this stops
             * duplicated simultaneous attempts to cache an entity.
             */
            rv = cache_try_lock(conf, cache, r);
            if (APR_SUCCESS == rv) {

                /*
                 * Add cache_save filter to cache this request. Choose
                 * the correct filter by checking if we are a subrequest
                 * or not.
                 */
                if (r->main) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                            r, APLOGNO(00756) "Adding CACHE_SAVE_SUBREQ filter for %s",
                            r->uri);
                    cache_save_handle = cache_save_subreq_filter_handle;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                            r, APLOGNO(00757) "Adding CACHE_SAVE filter for %s",
                            r->uri);
                    cache_save_handle = cache_save_filter_handle;
                }
                ap_add_output_filter_handle(cache_save_handle, cache, r,
                        r->connection);

                /*
                 * Did the user indicate the precise location of the
                 * CACHE_SAVE filter by inserting the CACHE filter as a
                 * marker?
                 *
                 * If so, we get cunning and replace CACHE with the
                 * CACHE_SAVE filter. This has the effect of inserting
                 * the CACHE_SAVE filter at the precise location where
                 * the admin wants to cache the content. All filters that
                 * lie before and after the original location of the CACHE
                 * filter will remain in place.
                 */
                if (cache_replace_filter(r->output_filters,
                        cache_filter_handle, cache_save_handle,
                        ap_get_input_filter_handle("SUBREQ_CORE"))) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                            r, APLOGNO(00758) "Replacing CACHE with CACHE_SAVE "
                            "filter for %s", r->uri);
                }

                /* save away the save filter stack */
                cache->save_filter = cache_get_filter(r->output_filters,
                        cache_save_filter_handle);

                apr_pool_userdata_setn(cache, CACHE_CTX_KEY, NULL, r->pool);

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00759)
                        "Adding CACHE_REMOVE_URL filter for %s",
                        r->uri);

                /* Add cache_remove_url filter to this request to remove a
                 * stale cache entry if needed. Also put the current cache
                 * request rec in the filter context, as the request that
                 * is available later during running the filter may be
                 * different due to an internal redirect.
                 */
                cache->remove_url_filter
                        = ap_add_output_filter_handle(
                                cache_remove_url_filter_handle, cache, r,
                                r->connection);

            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv,
                        r, APLOGNO(00760) "Cache locked for url, not caching "
                        "response: %s", r->uri);
            }
        }
        else {
            /* error */
            return rv;
        }
        return DECLINED;
    }

    /* we've got a cache hit! tell everyone who cares */
    cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_HIT,
            "cache hit");

    rv = ap_meets_conditions(r);
    if (rv != OK) {
        return rv;
    }

    /* Serve up the content */

    /*
     * Add cache_out filter to serve this request. Choose
     * the correct filter by checking if we are a subrequest
     * or not.
     */
    if (r->main) {
        cache_out_handle = cache_out_subreq_filter_handle;
    }
    else {
        cache_out_handle = cache_out_filter_handle;
    }
    ap_add_output_filter_handle(cache_out_handle, cache, r, r->connection);

    /*
     * Did the user indicate the precise location of the CACHE_OUT filter by
     * inserting the CACHE filter as a marker?
     *
     * If so, we get cunning and replace CACHE with the CACHE_OUT filters.
     * This has the effect of inserting the CACHE_OUT filter at the precise
     * location where the admin wants to cache the content. All filters that
     * lie *after* the original location of the CACHE filter will remain in
     * place.
     */
    if (cache_replace_filter(r->output_filters, cache_filter_handle,
            cache_out_handle, ap_get_input_filter_handle("SUBREQ_CORE"))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                r, APLOGNO(00761) "Replacing CACHE with CACHE_OUT filter for %s",
                r->uri);
    }

    /*
     * Remove all filters that are before the cache_out filter. This ensures
     * that we kick off the filter stack with our cache_out filter being the
     * first in the chain. This make sense because we want to restore things
     * in the same manner as we saved them.
     * There may be filters before our cache_out filter, because
     *
     * 1. We call ap_set_content_type during cache_select. This causes
     *    Content-Type specific filters to be added.
     * 2. We call the insert_filter hook. This causes filters e.g. like
     *    the ones set with SetOutputFilter to be added.
     */
    next = r->output_filters;
    while (next && (next->frec != cache_out_handle)) {
        ap_remove_output_filter(next);
        next = next->next;
    }

    /* kick off the filter stack */
    out = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    e = apr_bucket_eos_create(out->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(out, e);
    return ap_pass_brigade_fchk(r, out, "cache(%s): ap_pass_brigade returned",
                                cache->provider_name);
}

/*
 * CACHE_OUT filter
 * ----------------
 *
 * Deliver cached content (headers and body) up the stack.
 */
static apr_status_t cache_out_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    cache_request_rec *cache = (cache_request_rec *)f->ctx;

    if (!cache) {
        /* user likely configured CACHE_OUT manually; they should use mod_cache
         * configuration to do that */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00762)
                "CACHE/CACHE_OUT filter enabled while caching is disabled, ignoring");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00763)
            "cache: running CACHE_OUT filter");

    /* clean out any previous response up to EOS, if any */
    while (!APR_BRIGADE_EMPTY(in)) {
        apr_bucket *e = APR_BRIGADE_FIRST(in);
        if (APR_BUCKET_IS_EOS(e)) {
            apr_bucket_brigade *bb = apr_brigade_create(r->pool,
                    r->connection->bucket_alloc);

            /* restore content type of cached response if available */
            /* Needed especially when stale content gets served. */
            const char *ct = apr_table_get(cache->handle->resp_hdrs, "Content-Type");
            if (ct) {
                ap_set_content_type(r, ct);
            }

            /* restore status of cached response */
            r->status = cache->handle->cache_obj->info.status;

            /* recall_headers() was called in cache_select() */
            cache->provider->recall_body(cache->handle, r->pool, bb);
            APR_BRIGADE_PREPEND(in, bb);

            /* This filter is done once it has served up its content */
            ap_remove_output_filter(f);

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00764)
                    "cache: serving %s", r->uri);
            return ap_pass_brigade(f->next, in);

        }
        apr_bucket_delete(e);
    }

    return APR_SUCCESS;
}

/*
 * Having jumped through all the hoops and decided to cache the
 * response, call store_body() for each brigade, handling the
 * case where the provider can't swallow the full brigade. In this
 * case, we write the brigade we were passed out downstream, and
 * loop around to try and cache some more until the in brigade is
 * completely empty. As soon as the out brigade contains eos, call
 * commit_entity() to finalise the cached element.
 */
static int cache_save_store(ap_filter_t *f, apr_bucket_brigade *in,
        cache_server_conf *conf, cache_request_rec *cache)
{
    int rv = APR_SUCCESS;
    apr_bucket *e;

    /* pass the brigade in into the cache provider, which is then
     * expected to move cached buckets to the out brigade, for us
     * to pass up the filter stack. repeat until in is empty, or
     * we fail.
     */
    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(in)) {

        rv = cache->provider->store_body(cache->handle, f->r, in, cache->out);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r, APLOGNO(00765)
                    "cache: Cache provider's store_body failed for URI %s", f->r->uri);
            ap_remove_output_filter(f);

            /* give someone else the chance to cache the file */
            cache_remove_lock(conf, cache, f->r, NULL);

            /* give up trying to cache, just step out the way */
            APR_BRIGADE_PREPEND(in, cache->out);
            return ap_pass_brigade(f->next, in);

        }

        /* does the out brigade contain eos? if so, we're done, commit! */
        for (e = APR_BRIGADE_FIRST(cache->out);
             e != APR_BRIGADE_SENTINEL(cache->out);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_EOS(e)) {
                rv = cache->provider->commit_entity(cache->handle, f->r);
                break;
            }
        }

        /* conditionally remove the lock as soon as we see the eos bucket */
        cache_remove_lock(conf, cache, f->r, cache->out);

        if (APR_BRIGADE_EMPTY(cache->out)) {
            if (APR_BRIGADE_EMPTY(in)) {
                /* cache provider wants more data before passing the brigade
                 * upstream, oblige the provider by leaving to fetch more.
                 */
                break;
            }
            else {
                /* oops, no data out, but not all data read in either, be
                 * safe and stand down to prevent a spin.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, f->r, APLOGNO(00766)
                        "cache: Cache provider's store_body returned an "
                        "empty brigade, but didn't consume all of the "
                        "input brigade, standing down to prevent a spin");
                ap_remove_output_filter(f);

                /* give someone else the chance to cache the file */
                cache_remove_lock(conf, cache, f->r, NULL);

                return ap_pass_brigade(f->next, in);
            }
        }

        rv = ap_pass_brigade(f->next, cache->out);
    }

    return rv;
}

/**
 * Sanity check for 304 Not Modified responses, as per RFC2616 Section 10.3.5.
 */
static int cache_header_cmp(apr_pool_t *pool, apr_table_t *left,
        apr_table_t *right, const char *key)
{
    const char *h1, *h2;

    if ((h1 = cache_table_getm(pool, left, key))
            && (h2 = cache_table_getm(pool, right, key)) && (strcmp(h1, h2))) {
        return 1;
    }
    return 0;
}

/*
 * CACHE_SAVE filter
 * ---------------
 *
 * Decide whether or not this content should be cached.
 * If we decide no it should not:
 *   remove the filter from the chain
 * If we decide yes it should:
 *   Have we already started saving the response?
 *      If we have started, pass the data to the storage manager via store_body
 *      Otherwise:
 *        Check to see if we *can* save this particular response.
 *        If we can, call cache_create_entity() and save the headers and body
 *   Finally, pass the data to the next filter (the network or whatever)
 *
 * After the various failure cases, the cache lock is proactively removed, so
 * that another request is given the opportunity to attempt to cache without
 * waiting for a potentially slow client to acknowledge the failure.
 */

static apr_status_t cache_save_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    int rv = !OK;
    request_rec *r = f->r;
    cache_request_rec *cache = (cache_request_rec *)f->ctx;
    cache_server_conf *conf;
    cache_dir_conf *dconf;
    cache_control_t control;
    const char *cc_out, *cl, *pragma;
    const char *exps, *lastmods, *dates, *etag;
    apr_time_t exp, date, lastmod, now;
    apr_off_t size = -1;
    cache_info *info = NULL;
    const char *reason, **eh;
    apr_pool_t *p;
    apr_bucket *e;
    apr_table_t *headers;
    const char *query;

    conf = (cache_server_conf *) ap_get_module_config(r->server->module_config,
                                                      &cache_module);

    /* Setup cache_request_rec */
    if (!cache) {
        /* user likely configured CACHE_SAVE manually; they should really use
         * mod_cache configuration to do that
         */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00767)
                "CACHE/CACHE_SAVE filter enabled while caching is disabled, ignoring");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    reason = NULL;
    p = r->pool;
    /*
     * Pass Data to Cache
     * ------------------
     * This section passes the brigades into the cache modules, but only
     * if the setup section (see below) is complete.
     */
    if (cache->block_response) {
        /* We've already sent down the response and EOS.  So, ignore
         * whatever comes now.
         */
        return APR_SUCCESS;
    }

    /* have we already run the cacheability check and set up the
     * cached file handle?
     */
    if (cache->in_checked) {
        return cache_save_store(f, in, conf, cache);
    }

    /*
     * Setup Data in Cache
     * -------------------
     * This section opens the cache entity and sets various caching
     * parameters, and decides whether this URL should be cached at
     * all. This section is* run before the above section.
     */

    dconf = ap_get_module_config(r->per_dir_config, &cache_module);

    /* RFC2616 13.8 Errors or Incomplete Response Cache Behavior:
     * If a cache receives a 5xx response while attempting to revalidate an
     * entry, it MAY either forward this response to the requesting client,
     * or act as if the server failed to respond. In the latter case, it MAY
     * return a previously received response unless the cached entry
     * includes the "must-revalidate" cache-control directive (see section
     * 14.9).
     *
     * This covers the case where an error was generated behind us, for example
     * by a backend server via mod_proxy.
     */
    if (dconf->stale_on_error && r->status >= HTTP_INTERNAL_SERVER_ERROR) {

        ap_remove_output_filter(cache->remove_url_filter);

        if (cache->stale_handle
                && !cache->stale_handle->cache_obj->info.control.must_revalidate
                && !cache->stale_handle->cache_obj->info.control.proxy_revalidate) {
            const char *warn_head;

            /* morph the current save filter into the out filter, and serve from
             * cache.
             */
            cache->handle = cache->stale_handle;
            if (r->main) {
                f->frec = cache_out_subreq_filter_handle;
            }
            else {
                f->frec = cache_out_filter_handle;
            }

            r->headers_out = cache->stale_handle->resp_hdrs;

            ap_set_content_type(r, apr_table_get(
                    cache->stale_handle->resp_hdrs, "Content-Type"));

            /* add a revalidation warning */
            warn_head = apr_table_get(r->err_headers_out, "Warning");
            if ((warn_head == NULL) || ((warn_head != NULL)
                    && (ap_strstr_c(warn_head, "111") == NULL))) {
                apr_table_mergen(r->err_headers_out, "Warning",
                        "111 Revalidation failed");
            }

            cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_HIT,
                    apr_psprintf(r->pool,
                            "cache hit: %d status; stale content returned",
                            r->status));

            /* give someone else the chance to cache the file */
            cache_remove_lock(conf, cache, f->r, NULL);

            /* pass brigade to our morphed out filter */
            return ap_pass_brigade(f, in);
        }
    }

    query = cache_use_early_url(r) ? r->parsed_uri.query : r->args;

    /* read expiry date; if a bad date, then leave it so the client can
     * read it
     */
    exps = apr_table_get(r->err_headers_out, "Expires");
    if (exps == NULL) {
        exps = apr_table_get(r->headers_out, "Expires");
    }
    if (exps != NULL) {
        exp = apr_date_parse_http(exps);
    }
    else {
        exp = APR_DATE_BAD;
    }

    /* read the last-modified date; if the date is bad, then delete it */
    lastmods = apr_table_get(r->err_headers_out, "Last-Modified");
    if (lastmods == NULL) {
        lastmods = apr_table_get(r->headers_out, "Last-Modified");
    }
    if (lastmods != NULL) {
        lastmod = apr_date_parse_http(lastmods);
        if (lastmod == APR_DATE_BAD) {
            lastmods = NULL;
        }
    }
    else {
        lastmod = APR_DATE_BAD;
    }

    /* read the etag and cache-control from the entity */
    etag = apr_table_get(r->err_headers_out, "Etag");
    if (etag == NULL) {
        etag = apr_table_get(r->headers_out, "Etag");
    }
    cc_out = cache_table_getm(r->pool, r->err_headers_out, "Cache-Control");
    pragma = cache_table_getm(r->pool, r->err_headers_out, "Pragma");
    headers = r->err_headers_out;
    if (!cc_out && !pragma) {
        cc_out = cache_table_getm(r->pool, r->headers_out, "Cache-Control");
        pragma = cache_table_getm(r->pool, r->headers_out, "Pragma");
        headers = r->headers_out;
    }

    /* Have we received a 304 response without any headers at all? Fall back to
     * the original headers in the original cached request.
     */
    if (r->status == HTTP_NOT_MODIFIED && cache->stale_handle) {
        if (!cc_out && !pragma) {
            cc_out = cache_table_getm(r->pool, cache->stale_handle->resp_hdrs,
                    "Cache-Control");
            pragma = cache_table_getm(r->pool, cache->stale_handle->resp_hdrs,
                    "Pragma");
        }

        /* 304 does not contain Content-Type and mod_mime regenerates the
         * Content-Type based on the r->filename. This would lead to original
         * Content-Type to be lost (overwriten by whatever mod_mime generates).
         * We preserves the original Content-Type here. */
        ap_set_content_type(r, apr_table_get(
                cache->stale_handle->resp_hdrs, "Content-Type"));
    }

    /* Parse the cache control header */
    memset(&control, 0, sizeof(cache_control_t));
    ap_cache_control(r, &control, cc_out, pragma, headers);

    /*
     * what responses should we not cache?
     *
     * At this point we decide based on the response headers whether it
     * is appropriate _NOT_ to cache the data from the server. There are
     * a whole lot of conditions that prevent us from caching this data.
     * They are tested here one by one to be clear and unambiguous.
     */
    if (r->status != HTTP_OK && r->status != HTTP_NON_AUTHORITATIVE
        && r->status != HTTP_PARTIAL_CONTENT
        && r->status != HTTP_MULTIPLE_CHOICES
        && r->status != HTTP_MOVED_PERMANENTLY
        && r->status != HTTP_NOT_MODIFIED) {
        /* RFC2616 13.4 we are allowed to cache 200, 203, 206, 300, 301 or 410
         * We allow the caching of 206, but a cache implementation might choose
         * to decline to cache a 206 if it doesn't know how to.
         * We include 304 Not Modified here too as this is the origin server
         * telling us to serve the cached copy.
         */
        if (exps != NULL || cc_out != NULL) {
            /* We are also allowed to cache any response given that it has a
             * valid Expires or Cache Control header. If we find a either of
             * those here,  we pass request through the rest of the tests. From
             * the RFC:
             *
             * A response received with any other status code (e.g. status
             * codes 302 and 307) MUST NOT be returned in a reply to a
             * subsequent request unless there are cache-control directives or
             * another header(s) that explicitly allow it. For example, these
             * include the following: an Expires header (section 14.21); a
             * "max-age", "s-maxage",  "must-revalidate", "proxy-revalidate",
             * "public" or "private" cache-control directive (section 14.9).
             *
             * FIXME: Wrong if cc_out has just an extension we don't know about 
             */
        }
        else {
            reason = apr_psprintf(p, "Response status %d", r->status);
        }
    }

    if (reason) {
        /* noop */
    }
    else if (exps != NULL && exp == APR_DATE_BAD) {
        /* if a broken Expires header is present, don't cache it */
        reason = apr_pstrcat(p, "Broken expires header: ", exps, NULL);
    }
    else if (!control.s_maxage && !control.max_age
            && !dconf->store_expired && exp != APR_DATE_BAD
            && exp < r->request_time) {
        /* if a Expires header is in the past, don't cache it 
         * Unless CC: s-maxage or max-age is present
         */
        reason = "Expires header already expired; not cacheable";
    }
    else if (!dconf->store_expired && (control.must_revalidate
            || control.proxy_revalidate) && (!control.s_maxage_value
            || (!control.s_maxage && !control.max_age_value)) && lastmods
            == NULL && etag == NULL) {
        /* if we're already stale, but can never revalidate, don't cache it */
        reason
                = "s-maxage or max-age zero and no Last-Modified or Etag; not cacheable";
    }
    else if (!conf->ignorequerystring && query && exps == NULL
            && !control.max_age && !control.s_maxage) {
        /* if a query string is present but no explicit expiration time,
         * don't cache it (RFC 2616/13.9 & 13.2.1)
         */
        reason = "Query string present but no explicit expiration time";
    }
    else if (r->status == HTTP_NOT_MODIFIED &&
             !cache->handle && !cache->stale_handle) {
        /* if the server said 304 Not Modified but we have no cache
         * file - pass this untouched to the user agent, it's not for us.
         */
        reason = "HTTP Status 304 Not Modified";
    }
    else if (r->status == HTTP_OK && lastmods == NULL && etag == NULL && (exps
            == NULL) && (dconf->no_last_mod_ignore == 0) && !control.max_age
            && !control.s_maxage) {
        /* 200 OK response from HTTP/1.0 and up without Last-Modified,
         * Etag, Expires, Cache-Control:max-age, or Cache-Control:s-maxage
         * headers.
         */
        /* Note: mod-include clears last_modified/expires/etags - this
         * is why we have an optional function for a key-gen ;-)
         */
        reason = "No Last-Modified; Etag; Expires; Cache-Control:max-age or Cache-Control:s-maxage headers";
    }
    else if (!dconf->store_nostore && control.no_store) {
        /* RFC2616 14.9.2 Cache-Control: no-store response
         * indicating do not cache, or stop now if you are
         * trying to cache it.
         */
        reason = "Cache-Control: no-store present";
    }
    else if (!dconf->store_private && control.private) {
        /* RFC2616 14.9.1 Cache-Control: private response
         * this object is marked for this user's eyes only. Behave
         * as a tunnel.
         */
        reason = "Cache-Control: private present";
    }
    else if (apr_table_get(r->headers_in, "Authorization")
            && !(control.s_maxage || control.must_revalidate
                    || control.proxy_revalidate || control.public)) {
        /* RFC2616 14.8 Authorisation:
         * if authorisation is included in the request, we don't cache,
         * but we can cache if the following exceptions are true:
         * 1) If Cache-Control: s-maxage is included
         * 2) If Cache-Control: must-revalidate is included
         * 3) If Cache-Control: public is included
         */
        reason = "Authorization required";
    }
    else if (ap_find_token(NULL, apr_table_get(r->headers_out, "Vary"), "*")) {
        reason = "Vary header contains '*'";
    }
    else if (apr_table_get(r->subprocess_env, "no-cache") != NULL) {
        reason = "environment variable 'no-cache' is set";
    }
    else if (r->no_cache) {
        /* or we've been asked not to cache it above */
        reason = "r->no_cache present";
    }
    else if (cache->stale_handle
            && APR_DATE_BAD
                    != (date = apr_date_parse_http(
                            apr_table_get(r->headers_out, "Date")))
            && date < cache->stale_handle->cache_obj->info.date) {

        /**
         * 13.12 Cache Replacement:
         *
         * Note: a new response that has an older Date header value than
         * existing cached responses is not cacheable.
         */
        reason = "updated entity is older than cached entity";

        /* while this response is not cacheable, the previous response still is */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02474)
                "cache: Removing CACHE_REMOVE_URL filter.");
        ap_remove_output_filter(cache->remove_url_filter);
    }
    else if (r->status == HTTP_NOT_MODIFIED && cache->stale_handle) {
        apr_table_t *left = cache->stale_handle->resp_hdrs;
        apr_table_t *right = r->headers_out;
        const char *ehs = NULL;

        /* and lastly, contradiction checks for revalidated responses
         * as per RFC2616 Section 10.3.5
         */
        if (cache_header_cmp(r->pool, left, right, "ETag")) {
            ehs = "ETag";
        }
        for (eh = MOD_CACHE_ENTITY_HEADERS; *eh; ++eh) {
            if (cache_header_cmp(r->pool, left, right, *eh)) {
                ehs = (ehs) ? apr_pstrcat(r->pool, ehs, ", ", *eh, NULL) : *eh;
            }
        }
        if (ehs) {
            reason = apr_pstrcat(r->pool, "contradiction: 304 Not Modified; "
                                 "but ", ehs, " modified", NULL);
        }
    }

    /**
     * Enforce RFC2616 Section 10.3.5, just in case. We caught any
     * inconsistencies above.
     *
     * If the conditional GET used a strong cache validator (see section
     * 13.3.3), the response SHOULD NOT include other entity-headers.
     * Otherwise (i.e., the conditional GET used a weak validator), the
     * response MUST NOT include other entity-headers; this prevents
     * inconsistencies between cached entity-bodies and updated headers.
     */
    if (r->status == HTTP_NOT_MODIFIED) {
        for (eh = MOD_CACHE_ENTITY_HEADERS; *eh; ++eh) {
            apr_table_unset(r->headers_out, *eh);
        }
    }

    /* Hold the phone. Some servers might allow us to cache a 2xx, but
     * then make their 304 responses non cacheable. RFC2616 says this:
     *
     * If a 304 response indicates an entity not currently cached, then
     * the cache MUST disregard the response and repeat the request
     * without the conditional.
     *
     * A 304 response with contradictory headers is technically a
     * different entity, to be safe, we remove the entity from the cache.
     */
    if (reason && r->status == HTTP_NOT_MODIFIED && cache->stale_handle) {

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02473) 
                "cache: %s responded with an uncacheable 304, " 
                "retrying the request %s. Reason: %s", 
                cache->key, r->unparsed_uri, reason);

        /* we've got a cache conditional miss! tell anyone who cares */
        cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_MISS,
                apr_psprintf(r->pool,
                        "conditional cache miss: 304 was uncacheable, entity removed: %s",
                        reason));

        /* remove the cached entity immediately, we might cache it again */
        ap_remove_output_filter(cache->remove_url_filter);
        cache_remove_url(cache, r);

        /* let someone else attempt to cache */
        cache_remove_lock(conf, cache, r, NULL);

        /* remove this filter from the chain */
        ap_remove_output_filter(f);

        /* retry without the conditionals */
        apr_table_unset(r->headers_in, "If-Match");
        apr_table_unset(r->headers_in, "If-Modified-Since");
        apr_table_unset(r->headers_in, "If-None-Match");
        apr_table_unset(r->headers_in, "If-Range");
        apr_table_unset(r->headers_in, "If-Unmodified-Since");

        /* Currently HTTP_NOT_MODIFIED, and after the redirect, handlers won't think to set status to HTTP_OK */
        r->status = HTTP_OK; 
        ap_internal_redirect(r->unparsed_uri, r);

        return APR_SUCCESS;
    }

    if (reason) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00768)
                "cache: %s not cached for request %s. Reason: %s",
                cache->key, r->unparsed_uri, reason);

        /* we've got a cache miss! tell anyone who cares */
        cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_MISS,
                reason);

        /* remove this filter from the chain */
        ap_remove_output_filter(f);

        /* remove the lock file unconditionally */
        cache_remove_lock(conf, cache, r, NULL);

        /* ship the data up the stack */
        return ap_pass_brigade(f->next, in);
    }

    /* Make it so that we don't execute this path again. */
    cache->in_checked = 1;

    /* Set the content length if known.
     */
    cl = apr_table_get(r->err_headers_out, "Content-Length");
    if (cl == NULL) {
        cl = apr_table_get(r->headers_out, "Content-Length");
    }
    if (cl) {
        char *errp;
        if (apr_strtoff(&size, cl, &errp, 10) || *errp || size < 0) {
            cl = NULL; /* parse error, see next 'if' block */
        }
    }

    if (!cl) {
        /* if we don't get the content-length, see if we have all the
         * buckets and use their length to calculate the size
         */
        int all_buckets_here=0;
        size=0;
        for (e = APR_BRIGADE_FIRST(in);
             e != APR_BRIGADE_SENTINEL(in);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_EOS(e)) {
                all_buckets_here=1;
                break;
            }
            if (APR_BUCKET_IS_FLUSH(e)) {
                continue;
            }
            if (e->length == (apr_size_t)-1) {
                break;
            }
            size += e->length;
        }
        if (!all_buckets_here) {
            size = -1;
        }
    }

    /* remember content length to check response size against later */
    cache->size = size;

    /* It's safe to cache the response.
     *
     * There are two possibilities at this point:
     * - cache->handle == NULL. In this case there is no previously
     * cached entity anywhere on the system. We must create a brand
     * new entity and store the response in it.
     * - cache->stale_handle != NULL. In this case there is a stale
     * entity in the system which needs to be replaced by new
     * content (unless the result was 304 Not Modified, which means
     * the cached entity is actually fresh, and we should update
     * the headers).
     */

    /* Did we have a stale cache entry that really is stale?
     */
    if (cache->stale_handle) {
        if (r->status == HTTP_NOT_MODIFIED) {
            /* Oh, hey.  It isn't that stale!  Yay! */
            cache->handle = cache->stale_handle;
            info = &cache->handle->cache_obj->info;
            rv = OK;
        }
        else {
            /* Oh, well.  Toss it. */
            cache->provider->remove_entity(cache->stale_handle);
            /* Treat the request as if it wasn't conditional. */
            cache->stale_handle = NULL;
            /*
             * Restore the original request headers as they may be needed
             * by further output filters like the byterange filter to make
             * the correct decisions.
             */
            r->headers_in = cache->stale_headers;
        }
    }

    /* no cache handle, create a new entity */
    if (!cache->handle) {
        rv = cache_create_entity(cache, r, size, in);
        info = apr_pcalloc(r->pool, sizeof(cache_info));
        /* We only set info->status upon the initial creation. */
        info->status = r->status;
    }

    if (rv != OK) {
        /* we've got a cache miss! tell anyone who cares */
        cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_MISS,
                "cache miss: cache unwilling to store response");

        /* Caching layer declined the opportunity to cache the response */
        ap_remove_output_filter(f);
        cache_remove_lock(conf, cache, r, NULL);
        return ap_pass_brigade(f->next, in);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00769)
            "cache: Caching url %s for request %s",
            cache->key, r->unparsed_uri);

    /* We are actually caching this response. So it does not
     * make sense to remove this entity any more.
     */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00770)
            "cache: Removing CACHE_REMOVE_URL filter.");
    ap_remove_output_filter(cache->remove_url_filter);

    /*
     * We now want to update the cache file header information with
     * the new date, last modified, expire and content length and write
     * it away to our cache file. First, we determine these values from
     * the response, using heuristics if appropriate.
     *
     * In addition, we make HTTP/1.1 age calculations and write them away
     * too.
     */

    /* store away the previously parsed cache control headers */
    memcpy(&info->control, &control, sizeof(cache_control_t));

    /* Read the date. Generate one if one is not supplied */
    dates = apr_table_get(r->err_headers_out, "Date");
    if (dates == NULL) {
        dates = apr_table_get(r->headers_out, "Date");
    }
    if (dates != NULL) {
        info->date = apr_date_parse_http(dates);
    }
    else {
        info->date = APR_DATE_BAD;
    }

    now = apr_time_now();
    if (info->date == APR_DATE_BAD) {  /* No, or bad date */
        /* no date header (or bad header)! */
        info->date = now;
    }
    date = info->date;

    /* set response_time for HTTP/1.1 age calculations */
    info->response_time = now;

    /* get the request time */
    info->request_time = r->request_time;

    /* check last-modified date */
    if (lastmod != APR_DATE_BAD && lastmod > date) {
        /* if it's in the future, then replace by date */
        lastmod = date;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0,
                r, APLOGNO(00771) "cache: Last modified is in the future, "
                "replacing with now");
    }


    /* CC has priority over Expires.  */
    if (control.s_maxage || control.max_age) {
        apr_int64_t x;

        x = control.s_maxage ? control.s_maxage_value : control.max_age_value;
        x = x * MSEC_ONE_SEC;

        if (x < dconf->minex) {
            x = dconf->minex;
        }
        if (x > dconf->maxex) {
            x = dconf->maxex;
        }
        exp = date + x;
    }

    /* if no expiry date then
     *   if Cache-Control: s-maxage
     *      expiry date = date + smaxage
     *   if Cache-Control: max-age
     *      expiry date = date + max-age
     *   else if lastmod
     *      expiry date = date + min((date - lastmod) * factor, maxexpire)
     *   else
     *      expire date = date + defaultexpire
     */

    if (exp == APR_DATE_BAD) {
        if ((lastmod != APR_DATE_BAD) && (lastmod < date)) {
            /* if lastmod == date then you get 0*conf->factor which results in
             * an expiration time of now. This causes some problems with
             * freshness calculations, so we choose the else path...
             */
            apr_time_t x = (apr_time_t) ((date - lastmod) * dconf->factor);

            if (x < dconf->minex) {
                x = dconf->minex;
            }
            if (x > dconf->maxex) {
                x = dconf->maxex;
            }
            exp = date + x;
        }
        else {
            exp = date + dconf->defex;
        }
    }
    info->expire = exp;

    /* We found a stale entry which wasn't really stale. */
    if (cache->stale_handle) {

        /* RFC 2616 10.3.5 states that entity headers are not supposed
         * to be in the 304 response.  Therefore, we need to combine the
         * response headers with the cached headers *before* we update
         * the cached headers.
         *
         * However, before doing that, we need to first merge in
         * err_headers_out (note that store_headers() below already selects
         * the cacheable only headers using ap_cache_cacheable_headers_out(),
         * here we want to keep the original headers in r->headers_out and
         * forward all of them to the client, including non-cacheable ones).
         */
        r->headers_out = cache_merge_headers_out(r);
        apr_table_clear(r->err_headers_out);

        /* Merge in our cached headers.  However, keep any updated values. */
        /* take output, overlay on top of cached */
        cache_accept_headers(cache->handle, r, r->headers_out,
                cache->handle->resp_hdrs, 1);
    }

    /* Write away header information to cache. It is possible that we are
     * trying to update headers for an entity which has already been cached.
     *
     * This may fail, due to an unwritable cache area. E.g. filesystem full,
     * permissions problems or a read-only (re)mount. This must be handled
     * later.
     */
    rv = cache->provider->store_headers(cache->handle, r, info);

    /* Did we just update the cached headers on a revalidated response?
     *
     * If so, we can now decide what to serve to the client.  This is done in
     * the same way as with a regular response, but conditions are now checked
     * against the cached or merged response headers.
     */
    if (cache->stale_handle) {
        apr_bucket_brigade *bb;
        apr_bucket *bkt;
        int status;

        /* Load in the saved status and clear the status line. */
        r->status = info->status;
        r->status_line = NULL;

        /* We're just saving response headers, so we are done. Commit
         * the response at this point, unless there was a previous error.
         */
        if (rv == APR_SUCCESS) {
            rv = cache->provider->commit_entity(cache->handle, r);
        }

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        /* Restore the original request headers and see if we need to
         * return anything else than the cached response (ie. the original
         * request was conditional).
         */
        r->headers_in = cache->stale_headers;
        status = ap_meets_conditions(r);
        if (status != OK) {
            r->status = status;

            /* Strip the entity headers merged from the cached headers before
             * updating the entry (see cache_accept_headers() above).
             */
            for (eh = MOD_CACHE_ENTITY_HEADERS; *eh; ++eh) {
                apr_table_unset(r->headers_out, *eh);
            }

            bkt = apr_bucket_flush_create(bb->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bkt);
        }
        else {
            cache->provider->recall_body(cache->handle, r->pool, bb);

            bkt = apr_bucket_eos_create(bb->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bkt);
        }

        cache->block_response = 1;

        /* Before returning we need to handle the possible case of an
         * unwritable cache. Rather than leaving the entity in the cache
         * and having it constantly re-validated, now that we have recalled
         * the body it is safe to try and remove the url from the cache.
         */
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(00772)
                    "cache: updating headers with store_headers failed. "
                    "Removing cached url.");

            rv = cache->provider->remove_url(cache->stale_handle, r);
            if (rv != OK) {
                /* Probably a mod_cache_disk cache area has been (re)mounted
                 * read-only, or that there is a permissions problem.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(00773)
                        "cache: attempt to remove url from cache unsuccessful.");
            }

            /* we've got a cache conditional hit! tell anyone who cares */
            cache_run_cache_status(cache->handle, r, r->headers_out,
                    AP_CACHE_REVALIDATE,
                    "conditional cache hit: entity refresh failed");

        }
        else {

            /* we've got a cache conditional hit! tell anyone who cares */
            cache_run_cache_status(cache->handle, r, r->headers_out,
                    AP_CACHE_REVALIDATE,
                    "conditional cache hit: entity refreshed");

        }

        /* let someone else attempt to cache */
        cache_remove_lock(conf, cache, r, NULL);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02971)
                    "cache: serving %s (revalidated)", r->uri);

        return ap_pass_brigade(f->next, bb);
    }

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(00774)
                "cache: store_headers failed");

        /* we've got a cache miss! tell anyone who cares */
        cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_MISS,
                "cache miss: store_headers failed");

        ap_remove_output_filter(f);
        cache_remove_lock(conf, cache, r, NULL);
        return ap_pass_brigade(f->next, in);
    }

    /* we've got a cache miss! tell anyone who cares */
    cache_run_cache_status(cache->handle, r, r->headers_out, AP_CACHE_MISS,
            "cache miss: attempting entity save");

    return cache_save_store(f, in, conf, cache);
}

/*
 * CACHE_REMOVE_URL filter
 * -----------------------
 *
 * This filter gets added in the quick handler every time the CACHE_SAVE filter
 * gets inserted. Its purpose is to remove a confirmed stale cache entry from
 * the cache.
 *
 * CACHE_REMOVE_URL has to be a protocol filter to ensure that is run even if
 * the response is a canned error message, which removes the content filters
 * and thus the CACHE_SAVE filter from the chain.
 *
 * CACHE_REMOVE_URL expects cache request rec within its context because the
 * request this filter runs on can be different from the one whose cache entry
 * should be removed, due to internal redirects.
 *
 * Note that CACHE_SAVE_URL (as a content-set filter, hence run before the
 * protocol filters) will remove this filter if it decides to cache the file.
 * Therefore, if this filter is left in, it must mean we need to toss any
 * existing files.
 */
static apr_status_t cache_remove_url_filter(ap_filter_t *f,
                                            apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    cache_request_rec *cache;

    /* Setup cache_request_rec */
    cache = (cache_request_rec *) f->ctx;

    if (!cache) {
        /* user likely configured CACHE_REMOVE_URL manually; they should really
         * use mod_cache configuration to do that. So:
         * 1. Remove ourselves
         * 2. Do nothing and bail out
         */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00775)
                "cache: CACHE_REMOVE_URL enabled unexpectedly");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    /* Now remove this cache entry from the cache */
    cache_remove_url(cache, r);

    /* remove ourselves */
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, in);
}

/*
 * CACHE_INVALIDATE filter
 * -----------------------
 *
 * This filter gets added in the quick handler should a PUT, POST or DELETE
 * method be detected. If the response is successful, we must invalidate any
 * cached entity as per RFC2616 section 13.10.
 *
 * CACHE_INVALIDATE has to be a protocol filter to ensure that is run even if
 * the response is a canned error message, which removes the content filters
 * from the chain.
 *
 * CACHE_INVALIDATE expects cache request rec within its context because the
 * request this filter runs on can be different from the one whose cache entry
 * should be removed, due to internal redirects.
 */
static apr_status_t cache_invalidate_filter(ap_filter_t *f,
                                            apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    cache_request_rec *cache;

    /* Setup cache_request_rec */
    cache = (cache_request_rec *) f->ctx;

    if (!cache) {
        /* user likely configured CACHE_INVALIDATE manually; they should really
         * use mod_cache configuration to do that. So:
         * 1. Remove ourselves
         * 2. Do nothing and bail out
         */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02465)
                "cache: CACHE_INVALIDATE enabled unexpectedly: %s", r->uri);
    }
    else {

        if (r->status > 299) {

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02466)
                    "cache: response status to '%s' method is %d (>299), not invalidating cached entity: %s", r->method, r->status, r->uri);

        }
        else {

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(02467)
                    "cache: Invalidating all cached entities in response to '%s' request for %s",
                    r->method, r->uri);

            cache_invalidate(cache, r);

            /* we've got a cache invalidate! tell everyone who cares */
            cache_run_cache_status(cache->handle, r, r->headers_out,
                    AP_CACHE_INVALIDATE, apr_psprintf(r->pool,
                            "cache invalidated by %s", r->method));

        }

    }

    /* remove ourselves */
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, in);
}

/*
 * CACHE filter
 * ------------
 *
 * This filter can be optionally inserted into the filter chain by the admin as
 * a marker representing the precise location within the filter chain where
 * caching is to be performed.
 *
 * When the filter chain is set up in the non-quick version of the URL handler,
 * the CACHE filter is replaced by the CACHE_OUT or CACHE_SAVE filter,
 * effectively inserting the caching filters at the point indicated by the
 * admin. The CACHE filter is then removed.
 *
 * This allows caching to be performed before the content is passed to the
 * INCLUDES filter, or to a filter that might perform transformations unique
 * to the specific request and that would otherwise be non-cacheable.
 */
static apr_status_t cache_filter(ap_filter_t *f, apr_bucket_brigade *in)
{

    cache_server_conf
            *conf =
                    (cache_server_conf *) ap_get_module_config(f->r->server->module_config,
                            &cache_module);

    /* was the quick handler enabled */
    if (conf->quick) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r, APLOGNO(00776)
                "cache: CACHE filter was added in quick handler mode and "
                "will be ignored: %s", f->r->unparsed_uri);
    }
    /* otherwise we may have been bypassed, nothing to see here */
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, APLOGNO(00777)
                "cache: CACHE filter was added twice, or was added where "
                "the cache has been bypassed and will be ignored: %s",
                f->r->unparsed_uri);
    }

    /* we are just a marker, so let's just remove ourselves */
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, in);
}

/**
 * If configured, add the status of the caching attempt to the subprocess
 * environment, and if configured, to headers in the response.
 *
 * The status is saved below the broad category of the status (hit, miss,
 * revalidate), as well as a single cache-status key. This can be used for
 * conditional logging.
 *
 * The status is optionally saved to an X-Cache header, and the detail of
 * why a particular cache entry was cached (or not cached) is optionally
 * saved to an X-Cache-Detail header. This extra detail is useful for
 * service developers who may need to know whether their Cache-Control headers
 * are working correctly.
 */
static int cache_status(cache_handle_t *h, request_rec *r,
        apr_table_t *headers, ap_cache_status_e status, const char *reason)
{
    cache_server_conf
            *conf =
                    (cache_server_conf *) ap_get_module_config(r->server->module_config,
                            &cache_module);

    cache_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &cache_module);
    int x_cache = 0, x_cache_detail = 0;

    switch (status) {
    case AP_CACHE_HIT: {
        apr_table_setn(r->subprocess_env, AP_CACHE_HIT_ENV, reason);
        break;
    }
    case AP_CACHE_REVALIDATE: {
        apr_table_setn(r->subprocess_env, AP_CACHE_REVALIDATE_ENV, reason);
        break;
    }
    case AP_CACHE_MISS: {
        apr_table_setn(r->subprocess_env, AP_CACHE_MISS_ENV, reason);
        break;
    }
    case AP_CACHE_INVALIDATE: {
        apr_table_setn(r->subprocess_env, AP_CACHE_INVALIDATE_ENV, reason);
        break;
    }
    }

    apr_table_setn(r->subprocess_env, AP_CACHE_STATUS_ENV, reason);

    if (dconf && dconf->x_cache_set) {
        x_cache = dconf->x_cache;
    }
    else {
        x_cache = conf->x_cache;
    }
    if (x_cache) {
        apr_table_setn(headers, "X-Cache", apr_psprintf(r->pool, "%s from %s",
                status == AP_CACHE_HIT ? "HIT"
                        : status == AP_CACHE_REVALIDATE ? "REVALIDATE" : status
                                == AP_CACHE_INVALIDATE ? "INVALIDATE" : "MISS",
                r->server->server_hostname));
    }

    if (dconf && dconf->x_cache_detail_set) {
        x_cache_detail = dconf->x_cache_detail;
    }
    else {
        x_cache_detail = conf->x_cache_detail;
    }
    if (x_cache_detail) {
        apr_table_setn(headers, "X-Cache-Detail", apr_psprintf(r->pool,
                "\"%s\" from %s", reason, r->server->server_hostname));
    }

    return OK;
}

/**
 * If an error has occurred, but we have a stale cached entry, restore the
 * filter stack from the save filter onwards. The canned error message will
 * be discarded in the process, and replaced with the cached response.
 */
static void cache_insert_error_filter(request_rec *r)
{
    void *dummy;
    cache_dir_conf *dconf;

    /* ignore everything except for 5xx errors */
    if (r->status < HTTP_INTERNAL_SERVER_ERROR) {
        return;
    }

    dconf = ap_get_module_config(r->per_dir_config, &cache_module);

    if (!dconf->stale_on_error) {
        return;
    }

    /* RFC2616 13.8 Errors or Incomplete Response Cache Behavior:
     * If a cache receives a 5xx response while attempting to revalidate an
     * entry, it MAY either forward this response to the requesting client,
     * or act as if the server failed to respond. In the latter case, it MAY
     * return a previously received response unless the cached entry
     * includes the "must-revalidate" cache-control directive (see section
     * 14.9).
     *
     * This covers the case where the error was generated by our server via
     * ap_die().
     */
    apr_pool_userdata_get(&dummy, CACHE_CTX_KEY, r->pool);
    if (dummy) {
        cache_request_rec *cache = (cache_request_rec *) dummy;

        ap_remove_output_filter(cache->remove_url_filter);

        if (cache->stale_handle && cache->save_filter
                && !cache->stale_handle->cache_obj->info.control.must_revalidate
                && !cache->stale_handle->cache_obj->info.control.proxy_revalidate
                && !cache->stale_handle->cache_obj->info.control.s_maxage) {
            const char *warn_head;
            cache_server_conf
                    *conf =
                            (cache_server_conf *) ap_get_module_config(r->server->module_config,
                                    &cache_module);

            /* morph the current save filter into the out filter, and serve from
             * cache.
             */
            cache->handle = cache->stale_handle;
            if (r->main) {
                cache->save_filter->frec = cache_out_subreq_filter_handle;
            }
            else {
                cache->save_filter->frec = cache_out_filter_handle;
            }

            r->output_filters = cache->save_filter;

            r->err_headers_out = cache->stale_handle->resp_hdrs;

            /* add a revalidation warning */
            warn_head = apr_table_get(r->err_headers_out, "Warning");
            if ((warn_head == NULL) || ((warn_head != NULL)
                    && (ap_strstr_c(warn_head, "111") == NULL))) {
                apr_table_mergen(r->err_headers_out, "Warning",
                        "111 Revalidation failed");
            }

            cache_run_cache_status(
                    cache->handle,
                    r,
                    r->err_headers_out,
                    AP_CACHE_HIT,
                    apr_psprintf(
                            r->pool,
                            "cache hit: %d status; stale content returned",
                            r->status));

            /* give someone else the chance to cache the file */
            cache_remove_lock(conf, cache, r, NULL);

        }
    }

    return;
}

/* -------------------------------------------------------------- */
/* Setup configurable data */

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    cache_dir_conf *dconf = apr_pcalloc(p, sizeof(cache_dir_conf));

    dconf->no_last_mod_ignore = 0;
    dconf->store_expired = 0;
    dconf->store_private = 0;
    dconf->store_nostore = 0;

    /* maximum time to cache a document */
    dconf->maxex = DEFAULT_CACHE_MAXEXPIRE;
    dconf->minex = DEFAULT_CACHE_MINEXPIRE;
    /* default time to cache a document */
    dconf->defex = DEFAULT_CACHE_EXPIRE;

    /* factor used to estimate Expires date from LastModified date */
    dconf->factor = DEFAULT_CACHE_LMFACTOR;

    dconf->x_cache = DEFAULT_X_CACHE;
    dconf->x_cache_detail = DEFAULT_X_CACHE_DETAIL;

    dconf->stale_on_error = DEFAULT_CACHE_STALE_ON_ERROR;

    /* array of providers for this URL space */
    dconf->cacheenable = apr_array_make(p, 10, sizeof(struct cache_enable));

    return dconf;
}

static void *merge_dir_config(apr_pool_t *p, void *basev, void *addv) {
    cache_dir_conf *new = (cache_dir_conf *) apr_pcalloc(p, sizeof(cache_dir_conf));
    cache_dir_conf *add = (cache_dir_conf *) addv;
    cache_dir_conf *base = (cache_dir_conf *) basev;

    new->no_last_mod_ignore = (add->no_last_mod_ignore_set == 0) ? base->no_last_mod_ignore : add->no_last_mod_ignore;
    new->no_last_mod_ignore_set = add->no_last_mod_ignore_set || base->no_last_mod_ignore_set;

    new->store_expired = (add->store_expired_set == 0) ? base->store_expired : add->store_expired;
    new->store_expired_set = add->store_expired_set || base->store_expired_set;
    new->store_private = (add->store_private_set == 0) ? base->store_private : add->store_private;
    new->store_private_set = add->store_private_set || base->store_private_set;
    new->store_nostore = (add->store_nostore_set == 0) ? base->store_nostore : add->store_nostore;
    new->store_nostore_set = add->store_nostore_set || base->store_nostore_set;

    /* maximum time to cache a document */
    new->maxex = (add->maxex_set == 0) ? base->maxex : add->maxex;
    new->maxex_set = add->maxex_set || base->maxex_set;
    new->minex = (add->minex_set == 0) ? base->minex : add->minex;
    new->minex_set = add->minex_set || base->minex_set;

    /* default time to cache a document */
    new->defex = (add->defex_set == 0) ? base->defex : add->defex;
    new->defex_set = add->defex_set || base->defex_set;

    /* factor used to estimate Expires date from LastModified date */
    new->factor = (add->factor_set == 0) ? base->factor : add->factor;
    new->factor_set = add->factor_set || base->factor_set;

    new->x_cache = (add->x_cache_set == 0) ? base->x_cache : add->x_cache;
    new->x_cache_set = add->x_cache_set || base->x_cache_set;
    new->x_cache_detail = (add->x_cache_detail_set == 0) ? base->x_cache_detail
            : add->x_cache_detail;
    new->x_cache_detail_set = add->x_cache_detail_set
            || base->x_cache_detail_set;

    new->stale_on_error = (add->stale_on_error_set == 0) ? base->stale_on_error
            : add->stale_on_error;
    new->stale_on_error_set = add->stale_on_error_set
            || base->stale_on_error_set;

    new->cacheenable = add->enable_set ? apr_array_append(p, base->cacheenable,
            add->cacheenable) : base->cacheenable;
    new->enable_set = add->enable_set || base->enable_set;
    new->disable = (add->disable_set == 0) ? base->disable : add->disable;
    new->disable_set = add->disable_set || base->disable_set;

    return new;
}

static void * create_cache_config(apr_pool_t *p, server_rec *s)
{
    const char *tmppath = NULL;
    cache_server_conf *ps = apr_pcalloc(p, sizeof(cache_server_conf));

    /* array of URL prefixes for which caching is enabled */
    ps->cacheenable = apr_array_make(p, 10, sizeof(struct cache_enable));
    /* array of URL prefixes for which caching is disabled */
    ps->cachedisable = apr_array_make(p, 10, sizeof(struct cache_disable));
    ps->ignorecachecontrol = 0;
    ps->ignorecachecontrol_set = 0;
    /* array of headers that should not be stored in cache */
    ps->ignore_headers = apr_array_make(p, 10, sizeof(char *));
    ps->ignore_headers_set = CACHE_IGNORE_HEADERS_UNSET;
    /* flag indicating that query-string should be ignored when caching */
    ps->ignorequerystring = 0;
    ps->ignorequerystring_set = 0;
    /* by default, run in the quick handler */
    ps->quick = 1;
    ps->quick_set = 0;
    /* array of identifiers that should not be used for key calculation */
    ps->ignore_session_id = apr_array_make(p, 10, sizeof(char *));
    ps->ignore_session_id_set = CACHE_IGNORE_SESSION_ID_UNSET;
    ps->lock = 0; /* thundering herd lock defaults to off */
    ps->lock_set = 0;
    apr_temp_dir_get(&tmppath, p);
    if (tmppath) {
        ps->lockpath = apr_pstrcat(p, tmppath, DEFAULT_CACHE_LOCKPATH, NULL);
    }
    ps->lockmaxage = apr_time_from_sec(DEFAULT_CACHE_MAXAGE);
    ps->x_cache = DEFAULT_X_CACHE;
    ps->x_cache_detail = DEFAULT_X_CACHE_DETAIL;
    return ps;
}

static void * merge_cache_config(apr_pool_t *p, void *basev, void *overridesv)
{
    cache_server_conf *ps = apr_pcalloc(p, sizeof(cache_server_conf));
    cache_server_conf *base = (cache_server_conf *) basev;
    cache_server_conf *overrides = (cache_server_conf *) overridesv;

    /* array of URL prefixes for which caching is disabled */
    ps->cachedisable = apr_array_append(p,
                                        base->cachedisable,
                                        overrides->cachedisable);
    /* array of URL prefixes for which caching is enabled */
    ps->cacheenable = apr_array_append(p,
                                       base->cacheenable,
                                       overrides->cacheenable);

    ps->ignorecachecontrol  =
        (overrides->ignorecachecontrol_set == 0)
        ? base->ignorecachecontrol
        : overrides->ignorecachecontrol;
    ps->ignore_headers =
        (overrides->ignore_headers_set == CACHE_IGNORE_HEADERS_UNSET)
        ? base->ignore_headers
        : overrides->ignore_headers;
    ps->ignorequerystring =
        (overrides->ignorequerystring_set == 0)
        ? base->ignorequerystring
        : overrides->ignorequerystring;
    ps->ignore_session_id =
        (overrides->ignore_session_id_set == CACHE_IGNORE_SESSION_ID_UNSET)
        ? base->ignore_session_id
        : overrides->ignore_session_id;
    ps->lock =
        (overrides->lock_set == 0)
        ? base->lock
        : overrides->lock;
    ps->lockpath =
        (overrides->lockpath_set == 0)
        ? base->lockpath
        : overrides->lockpath;
    ps->lockmaxage =
        (overrides->lockmaxage_set == 0)
        ? base->lockmaxage
        : overrides->lockmaxage;
    ps->quick =
        (overrides->quick_set == 0)
        ? base->quick
        : overrides->quick;
    ps->x_cache =
        (overrides->x_cache_set == 0)
        ? base->x_cache
        : overrides->x_cache;
    ps->x_cache_detail =
        (overrides->x_cache_detail_set == 0)
        ? base->x_cache_detail
        : overrides->x_cache_detail;
    ps->base_uri =
        (overrides->base_uri_set == 0)
        ? base->base_uri
        : overrides->base_uri;
    return ps;
}

static const char *set_cache_quick_handler(cmd_parms *parms, void *dummy,
                                           int flag)
{
    cache_server_conf *conf;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    conf->quick = flag;
    conf->quick_set = 1;
    return NULL;

}

static const char *set_cache_ignore_no_last_mod(cmd_parms *parms, void *dummy,
                                                int flag)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->no_last_mod_ignore = flag;
    dconf->no_last_mod_ignore_set = 1;
    return NULL;

}

static const char *set_cache_ignore_cachecontrol(cmd_parms *parms,
                                                 void *dummy, int flag)
{
    cache_server_conf *conf;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    conf->ignorecachecontrol = flag;
    conf->ignorecachecontrol_set = 1;
    return NULL;
}

static const char *set_cache_store_expired(cmd_parms *parms, void *dummy,
                                           int flag)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->store_expired = flag;
    dconf->store_expired_set = 1;
    return NULL;
}

static const char *set_cache_store_private(cmd_parms *parms, void *dummy,
                                           int flag)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->store_private = flag;
    dconf->store_private_set = 1;
    return NULL;
}

static const char *set_cache_store_nostore(cmd_parms *parms, void *dummy,
                                           int flag)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->store_nostore = flag;
    dconf->store_nostore_set = 1;
    return NULL;
}

static const char *add_ignore_header(cmd_parms *parms, void *dummy,
                                     const char *header)
{
    cache_server_conf *conf;
    char **new;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    if (!strcasecmp(header, "None")) {
        /* if header None is listed clear array */
        conf->ignore_headers->nelts = 0;
    }
    else {
        if ((conf->ignore_headers_set == CACHE_IGNORE_HEADERS_UNSET) ||
            (conf->ignore_headers->nelts)) {
            /* Only add header if no "None" has been found in header list
             * so far.
             * (When 'None' is passed, IGNORE_HEADERS_SET && nelts == 0.)
             */
            new = (char **)apr_array_push(conf->ignore_headers);
            (*new) = (char *)header;
        }
    }
    conf->ignore_headers_set = CACHE_IGNORE_HEADERS_SET;
    return NULL;
}

static const char *add_ignore_session_id(cmd_parms *parms, void *dummy,
                                         const char *identifier)
{
    cache_server_conf *conf;
    char **new;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    if (!strcasecmp(identifier, "None")) {
        /* if identifier None is listed clear array */
        conf->ignore_session_id->nelts = 0;
    }
    else {
        if ((conf->ignore_session_id_set == CACHE_IGNORE_SESSION_ID_UNSET) ||
            (conf->ignore_session_id->nelts)) {
            /*
             * Only add identifier if no "None" has been found in identifier
             * list so far.
             */
            new = (char **)apr_array_push(conf->ignore_session_id);
            (*new) = (char *)identifier;
        }
    }
    conf->ignore_session_id_set = CACHE_IGNORE_SESSION_ID_SET;
    return NULL;
}

static const char *add_cache_enable(cmd_parms *parms, void *dummy,
                                    const char *type,
                                    const char *url)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;
    cache_server_conf *conf;
    struct cache_enable *new;

    const char *err = ap_check_cmd_context(parms,
                                           NOT_IN_DIRECTORY|NOT_IN_LIMIT|NOT_IN_FILES);
    if (err != NULL) {
        return err;
    }

    if (*type == '/') {
        return apr_psprintf(parms->pool,
          "provider (%s) starts with a '/'.  Are url and provider switched?",
          type);
    }

    if (!url) {
        url = parms->path;
    }
    if (!url) {
        return apr_psprintf(parms->pool,
          "CacheEnable provider (%s) is missing an URL.", type);
    }
    if (parms->path && strncmp(parms->path, url, strlen(parms->path))) {
        return "When in a Location, CacheEnable must specify a path or an URL below "
        "that location.";
    }

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);

    if (parms->path) {
        new = apr_array_push(dconf->cacheenable);
        dconf->enable_set = 1;
    }
    else {
        new = apr_array_push(conf->cacheenable);
    }

    new->type = type;
    if (apr_uri_parse(parms->pool, url, &(new->url))) {
        return NULL;
    }
    if (new->url.path) {
        new->pathlen = strlen(new->url.path);
    } else {
        new->pathlen = 1;
        new->url.path = "/";
    }
    return NULL;
}

static const char *add_cache_disable(cmd_parms *parms, void *dummy,
                                     const char *url)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;
    cache_server_conf *conf;
    struct cache_disable *new;

    const char *err = ap_check_cmd_context(parms,
                                           NOT_IN_DIRECTORY|NOT_IN_LIMIT|NOT_IN_FILES);
    if (err != NULL) {
        return err;
    }

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);

    if (parms->path) {
        if (!strcasecmp(url, "on")) {
            dconf->disable = 1;
            dconf->disable_set = 1;
            return NULL;
        }
        else {
            return "CacheDisable must be followed by the word 'on' when in a Location.";
        }
    }

    if (!url || (url[0] != '/' && !ap_strchr_c(url, ':'))) {
        return "CacheDisable must specify a path or an URL.";
    }

    new = apr_array_push(conf->cachedisable);
    if (apr_uri_parse(parms->pool, url, &(new->url))) {
        return NULL;
    }
    if (new->url.path) {
        new->pathlen = strlen(new->url.path);
    } else {
        new->pathlen = 1;
        new->url.path = "/";
    }
    return NULL;
}

static const char *set_cache_maxex(cmd_parms *parms, void *dummy,
                                   const char *arg)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->maxex = (apr_time_t) (atol(arg) * MSEC_ONE_SEC);
    dconf->maxex_set = 1;
    return NULL;
}

static const char *set_cache_minex(cmd_parms *parms, void *dummy,
                                   const char *arg)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->minex = (apr_time_t) (atol(arg) * MSEC_ONE_SEC);
    dconf->minex_set = 1;
    return NULL;
}

static const char *set_cache_defex(cmd_parms *parms, void *dummy,
                                   const char *arg)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->defex = (apr_time_t) (atol(arg) * MSEC_ONE_SEC);
    dconf->defex_set = 1;
    return NULL;
}

static const char *set_cache_factor(cmd_parms *parms, void *dummy,
                                    const char *arg)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;
    double val;

    if (sscanf(arg, "%lg", &val) != 1) {
        return "CacheLastModifiedFactor value must be a float";
    }
    dconf->factor = val;
    dconf->factor_set = 1;
    return NULL;
}

static const char *set_cache_ignore_querystring(cmd_parms *parms, void *dummy,
                                                int flag)
{
    cache_server_conf *conf;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    conf->ignorequerystring = flag;
    conf->ignorequerystring_set = 1;
    return NULL;
}

static const char *set_cache_lock(cmd_parms *parms, void *dummy,
                                                int flag)
{
    cache_server_conf *conf;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    conf->lock = flag;
    conf->lock_set = 1;
    return NULL;
}

static const char *set_cache_lock_path(cmd_parms *parms, void *dummy,
                                    const char *arg)
{
    cache_server_conf *conf;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);

    conf->lockpath = ap_server_root_relative(parms->pool, arg);
    if (!conf->lockpath) {
        return apr_pstrcat(parms->pool, "Invalid CacheLockPath path ",
                           arg, NULL);
    }
    conf->lockpath_set = 1;
    return NULL;
}

static const char *set_cache_lock_maxage(cmd_parms *parms, void *dummy,
                                    const char *arg)
{
    cache_server_conf *conf;
    apr_int64_t seconds;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    seconds = apr_atoi64(arg);
    if (seconds <= 0) {
        return "CacheLockMaxAge value must be a non-zero positive integer";
    }
    conf->lockmaxage = apr_time_from_sec(seconds);
    conf->lockmaxage_set = 1;
    return NULL;
}

static const char *set_cache_x_cache(cmd_parms *parms, void *dummy, int flag)
{

    if (parms->path) {
        cache_dir_conf *dconf = (cache_dir_conf *)dummy;

        dconf->x_cache = flag;
        dconf->x_cache_set = 1;

    }
    else {
        cache_server_conf *conf =
            (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                      &cache_module);

        conf->x_cache = flag;
        conf->x_cache_set = 1;

    }

    return NULL;
}

static const char *set_cache_x_cache_detail(cmd_parms *parms, void *dummy, int flag)
{

    if (parms->path) {
        cache_dir_conf *dconf = (cache_dir_conf *)dummy;

        dconf->x_cache_detail = flag;
        dconf->x_cache_detail_set = 1;

    }
    else {
        cache_server_conf *conf =
            (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                      &cache_module);

        conf->x_cache_detail = flag;
        conf->x_cache_detail_set = 1;

    }

    return NULL;
}

static const char *set_cache_key_base_url(cmd_parms *parms, void *dummy,
        const char *arg)
{
    cache_server_conf *conf;
    apr_status_t rv;

    conf =
        (cache_server_conf *)ap_get_module_config(parms->server->module_config,
                                                  &cache_module);
    conf->base_uri = apr_pcalloc(parms->pool, sizeof(apr_uri_t));
    rv = apr_uri_parse(parms->pool, arg, conf->base_uri);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(parms->pool, "Could not parse '%s' as an URL.", arg);
    }
    else if (!conf->base_uri->scheme && !conf->base_uri->hostname &&
            !conf->base_uri->port_str) {
        return apr_psprintf(parms->pool, "URL '%s' must contain at least one of a scheme, a hostname or a port.", arg);
    }
    conf->base_uri_set = 1;
    return NULL;
}

static const char *set_cache_stale_on_error(cmd_parms *parms, void *dummy,
        int flag)
{
    cache_dir_conf *dconf = (cache_dir_conf *)dummy;

    dconf->stale_on_error = flag;
    dconf->stale_on_error_set = 1;
    return NULL;
}

static int cache_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    /* This is the means by which unusual (non-unix) os's may find alternate
     * means to run a given command (e.g. shebang/registry parsing on Win32)
     */
    cache_generate_key = APR_RETRIEVE_OPTIONAL_FN(ap_cache_generate_key);
    if (!cache_generate_key) {
        cache_generate_key = cache_generate_key_default;
    }
    return OK;
}


static const command_rec cache_cmds[] =
{
    /* XXX
     * Consider a new config directive that enables loading specific cache
     * implememtations (like mod_cache_mem, mod_cache_file, etc.).
     * Rather than using a LoadModule directive, admin would use something
     * like CacheModule  mem_cache_module | file_cache_module, etc,
     * which would cause the approprpriate cache module to be loaded.
     * This is more intuitive that requiring a LoadModule directive.
     */

    AP_INIT_TAKE12("CacheEnable", add_cache_enable, NULL, RSRC_CONF|ACCESS_CONF,
                   "A cache type and partial URL prefix below which "
                   "caching is enabled"),
    AP_INIT_TAKE1("CacheDisable", add_cache_disable, NULL, RSRC_CONF|ACCESS_CONF,
                  "A partial URL prefix below which caching is disabled"),
    AP_INIT_TAKE1("CacheMaxExpire", set_cache_maxex, NULL, RSRC_CONF|ACCESS_CONF,
                  "The maximum time in seconds to cache a document"),
    AP_INIT_TAKE1("CacheMinExpire", set_cache_minex, NULL, RSRC_CONF|ACCESS_CONF,
                  "The minimum time in seconds to cache a document"),
    AP_INIT_TAKE1("CacheDefaultExpire", set_cache_defex, NULL, RSRC_CONF|ACCESS_CONF,
                  "The default time in seconds to cache a document"),
    AP_INIT_FLAG("CacheQuickHandler", set_cache_quick_handler, NULL,
                 RSRC_CONF,
                 "Run the cache in the quick handler, default on"),
    AP_INIT_FLAG("CacheIgnoreNoLastMod", set_cache_ignore_no_last_mod, NULL,
                 RSRC_CONF|ACCESS_CONF,
                 "Ignore Responses where there is no Last Modified Header"),
    AP_INIT_FLAG("CacheIgnoreCacheControl", set_cache_ignore_cachecontrol,
                 NULL, RSRC_CONF,
                 "Ignore requests from the client for uncached content"),
    AP_INIT_FLAG("CacheStoreExpired", set_cache_store_expired,
                 NULL, RSRC_CONF|ACCESS_CONF,
                 "Ignore expiration dates when populating cache, resulting in "
                 "an If-Modified-Since request to the backend on retrieval"),
    AP_INIT_FLAG("CacheStorePrivate", set_cache_store_private,
                 NULL, RSRC_CONF|ACCESS_CONF,
                 "Ignore 'Cache-Control: private' and store private content"),
    AP_INIT_FLAG("CacheStoreNoStore", set_cache_store_nostore,
                 NULL, RSRC_CONF|ACCESS_CONF,
                 "Ignore 'Cache-Control: no-store' and store sensitive content"),
    AP_INIT_ITERATE("CacheIgnoreHeaders", add_ignore_header, NULL, RSRC_CONF,
                    "A space separated list of headers that should not be "
                    "stored by the cache"),
    AP_INIT_FLAG("CacheIgnoreQueryString", set_cache_ignore_querystring,
                 NULL, RSRC_CONF,
                 "Ignore query-string when caching"),
    AP_INIT_ITERATE("CacheIgnoreURLSessionIdentifiers", add_ignore_session_id,
                    NULL, RSRC_CONF, "A space separated list of session "
                    "identifiers that should be ignored for creating the key "
                    "of the cached entity."),
    AP_INIT_TAKE1("CacheLastModifiedFactor", set_cache_factor, NULL, RSRC_CONF|ACCESS_CONF,
                  "The factor used to estimate Expires date from "
                  "LastModified date"),
    AP_INIT_FLAG("CacheLock", set_cache_lock,
                 NULL, RSRC_CONF,
                 "Enable or disable the thundering herd lock."),
    AP_INIT_TAKE1("CacheLockPath", set_cache_lock_path, NULL, RSRC_CONF,
                  "The thundering herd lock path. Defaults to the '"
                  DEFAULT_CACHE_LOCKPATH "' directory in the system "
                  "temp directory."),
    AP_INIT_TAKE1("CacheLockMaxAge", set_cache_lock_maxage, NULL, RSRC_CONF,
                  "Maximum age of any thundering herd lock."),
    AP_INIT_FLAG("CacheHeader", set_cache_x_cache, NULL, RSRC_CONF | ACCESS_CONF,
                 "Add a X-Cache header to responses. Default is off."),
    AP_INIT_FLAG("CacheDetailHeader", set_cache_x_cache_detail, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Add a X-Cache-Detail header to responses. Default is off."),
    AP_INIT_TAKE1("CacheKeyBaseURL", set_cache_key_base_url, NULL, RSRC_CONF,
                  "Override the base URL of reverse proxied cache keys."),
    AP_INIT_FLAG("CacheStaleOnError", set_cache_stale_on_error,
                 NULL, RSRC_CONF|ACCESS_CONF,
                 "Serve stale content on 5xx errors if present. Defaults to on."),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    /* cache initializer */
    /* cache quick handler */
    ap_hook_quick_handler(cache_quick_handler, NULL, NULL, APR_HOOK_FIRST);
    /* cache handler */
    ap_hook_handler(cache_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    /* cache status */
    cache_hook_cache_status(cache_status, NULL, NULL, APR_HOOK_MIDDLE);
    /* cache error handler */
    ap_hook_insert_error_filter(cache_insert_error_filter, NULL, NULL, APR_HOOK_MIDDLE);
    /* cache filters
     * XXX The cache filters need to run right after the handlers and before
     * any other filters. Consider creating AP_FTYPE_CACHE for this purpose.
     *
     * Depending on the type of request (subrequest / main request) they
     * need to be run before AP_FTYPE_CONTENT_SET / after AP_FTYPE_CONTENT_SET
     * filters. Thus create two filter handles for each type:
     * cache_save_filter_handle / cache_out_filter_handle to be used by
     * main requests and
     * cache_save_subreq_filter_handle / cache_out_subreq_filter_handle
     * to be run by subrequest
     */
    /*
     * CACHE is placed into the filter chain at an admin specified location,
     * and when the cache_handler is run, the CACHE filter is swapped with
     * the CACHE_OUT filter, or CACHE_SAVE filter as appropriate. This has
     * the effect of offering optional fine control of where the cache is
     * inserted into the filter chain.
     */
    cache_filter_handle =
        ap_register_output_filter("CACHE",
                                  cache_filter,
                                  NULL,
                                  AP_FTYPE_RESOURCE);
    /*
     * CACHE_SAVE must go into the filter chain after a possible DEFLATE
     * filter to ensure that the compressed content is stored.
     * Incrementing filter type by 1 ensures this happens.
     */
    cache_save_filter_handle =
        ap_register_output_filter("CACHE_SAVE",
                                  cache_save_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET+1);
    /*
     * CACHE_SAVE_SUBREQ must go into the filter chain before SUBREQ_CORE to
     * handle subrequsts. Decrementing filter type by 1 ensures this
     * happens.
     */
    cache_save_subreq_filter_handle =
        ap_register_output_filter("CACHE_SAVE_SUBREQ",
                                  cache_save_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET-1);
    /*
     * CACHE_OUT must go into the filter chain after a possible DEFLATE
     * filter to ensure that already compressed cache objects do not
     * get compressed again. Incrementing filter type by 1 ensures
     * this happens.
     */
    cache_out_filter_handle =
        ap_register_output_filter("CACHE_OUT",
                                  cache_out_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET+1);
    /*
     * CACHE_OUT_SUBREQ must go into the filter chain before SUBREQ_CORE to
     * handle subrequsts. Decrementing filter type by 1 ensures this
     * happens.
     */
    cache_out_subreq_filter_handle =
        ap_register_output_filter("CACHE_OUT_SUBREQ",
                                  cache_out_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET-1);
    /* CACHE_REMOVE_URL has to be a protocol filter to ensure that is
     * run even if the response is a canned error message, which
     * removes the content filters.
     */
    cache_remove_url_filter_handle =
        ap_register_output_filter("CACHE_REMOVE_URL",
                                  cache_remove_url_filter,
                                  NULL,
                                  AP_FTYPE_PROTOCOL);
    cache_invalidate_filter_handle =
        ap_register_output_filter("CACHE_INVALIDATE",
                                  cache_invalidate_filter,
                                  NULL,
                                  AP_FTYPE_PROTOCOL);
    ap_hook_post_config(cache_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

AP_DECLARE_MODULE(cache) =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config,      /* create per-directory config structure */
    merge_dir_config,       /* merge per-directory config structures */
    create_cache_config,    /* create per-server config structure */
    merge_cache_config,     /* merge per-server config structures */
    cache_cmds,             /* command apr_table_t */
    register_hooks
};

APR_HOOK_STRUCT(
    APR_HOOK_LINK(cache_status)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(cache, CACHE, int, cache_status,
        (cache_handle_t *h, request_rec *r,
                apr_table_t *headers, ap_cache_status_e status,
                const char *reason), (h, r, headers, status, reason),
        OK, DECLINED)
