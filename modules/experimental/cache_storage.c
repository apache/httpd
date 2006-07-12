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

#define CORE_PRIVATE

#include "mod_cache.h"

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;

/* -------------------------------------------------------------- */

/*
 * delete all URL entities from the cache
 *
 */
int cache_remove_url(request_rec *r, char *url)
{
    cache_provider_list *list;
    apr_status_t rv;
    char *key;
    cache_request_rec *cache = (cache_request_rec *) 
                         ap_get_module_config(r->request_config, &cache_module);

    rv = cache_generate_key(r,r->pool,&key);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    list = cache->providers;

    /* for each specified cache type, delete the URL */
    while(list) {
        list->provider->remove_url(key);
        list = list->next;
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
int cache_create_entity(request_rec *r, char *url, apr_off_t size)
{
    cache_provider_list *list;
    cache_handle_t *h = apr_pcalloc(r->pool, sizeof(cache_handle_t));
    char *key;
    apr_status_t rv;
    cache_request_rec *cache = (cache_request_rec *) 
                         ap_get_module_config(r->request_config, &cache_module);

    rv = cache_generate_key(r,r->pool,&key);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    list = cache->providers;
    /* for each specified cache type, delete the URL */
    while (list) {
        switch (rv = list->provider->create_entity(h, r, key, size)) {
        case OK: {
            cache->handle = h;
            cache->provider = list->provider;
            cache->provider_name = list->provider_name;
            return OK;
        }
        case DECLINED: {
            list = list->next;
            continue;
        }
        default: {
            return rv;
        }
        }
    }
    return DECLINED;
}

static int set_cookie_doo_doo(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

static void accept_headers(cache_handle_t *h, request_rec *r)
{
    apr_table_t *cookie_table;
    const char *v;

    v = apr_table_get(h->resp_hdrs, "Content-Type");
    if (v) {
        ap_set_content_type(r, v);
        apr_table_unset(h->resp_hdrs, "Content-Type");
    }

    /* If the cache gave us a Last-Modified header, we can't just
     * pass it on blindly because of restrictions on future values.
     */
    v = apr_table_get(h->resp_hdrs, "Last-Modified");
    if (v) {
        ap_update_mtime(r, apr_date_parse_http(v));
        ap_set_last_modified(r);
        apr_table_unset(h->resp_hdrs, "Last-Modified");
    }

    /* The HTTP specification says that it is legal to merge duplicate
     * headers into one.  Some browsers that support Cookies don't like
     * merged headers and prefer that each Set-Cookie header is sent
     * separately.  Lets humour those browsers by not merging.
     * Oh what a pain it is.
     */
    cookie_table = apr_table_make(r->pool, 2);
    apr_table_do(set_cookie_doo_doo, cookie_table, r->err_headers_out,
                 "Set-Cookie", NULL);
    apr_table_do(set_cookie_doo_doo, cookie_table, h->resp_hdrs,
                 "Set-Cookie", NULL);
    apr_table_unset(r->err_headers_out, "Set-Cookie");
    apr_table_unset(h->resp_hdrs, "Set-Cookie");

    apr_table_overlap(r->headers_out, h->resp_hdrs,
                      APR_OVERLAP_TABLES_SET);
    apr_table_overlap(r->err_headers_out, h->resp_err_hdrs,
                      APR_OVERLAP_TABLES_SET);
    if (!apr_is_empty_table(cookie_table)) {
        r->err_headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                               cookie_table);
    }
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
int cache_select_url(request_rec *r, char *url)
{
    cache_provider_list *list;
    apr_status_t rv;
    cache_handle_t *h;
    char *key;
    cache_request_rec *cache = (cache_request_rec *) 
                         ap_get_module_config(r->request_config, &cache_module);

    rv = cache_generate_key(r, r->pool, &key);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    /* go through the cache types till we get a match */
    h = apr_palloc(r->pool, sizeof(cache_handle_t));

    list = cache->providers;

    while (list) {
        switch ((rv = list->provider->open_entity(h, r, key))) {
        case OK: {
            char *vary = NULL;
            const char *varyhdr = NULL;
            int fresh;

            if (list->provider->recall_headers(h, r) != APR_SUCCESS) {
                /* TODO: Handle this error */
                return DECLINED;
            }

            /*
             * Check Content-Negotiation - Vary
             * 
             * At this point we need to make sure that the object we found in
             * the cache is the same object that would be delivered to the
             * client, when the effects of content negotiation are taken into
             * effect.
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
            if ((varyhdr = apr_table_get(h->resp_err_hdrs, "Vary")) == NULL) {
                varyhdr = apr_table_get(h->resp_hdrs, "Vary");
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
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                                r->server,
                                "cache_select_url(): Vary header mismatch.");
                    return DECLINED;
                }
            }

            cache->provider = list->provider;
            cache->provider_name = list->provider_name;

            /* Is our cached response fresh enough? */
            fresh = ap_cache_check_freshness(h, r);
            if (!fresh) {
                cache_info *info = &(h->cache_obj->info);

                /* Make response into a conditional */
                /* FIXME: What if the request is already conditional? */
                if (info && info->etag) {
                    /* if we have a cached etag */
                    cache->stale_headers = apr_table_copy(r->pool,
                                                          r->headers_in);
                    apr_table_set(r->headers_in, "If-None-Match", info->etag);
                    cache->stale_handle = h;
                }
                else if (info && info->lastmods) {
                    /* if we have a cached Last-Modified header */
                    cache->stale_headers = apr_table_copy(r->pool,
                                                          r->headers_in);
                    apr_table_set(r->headers_in, "If-Modified-Since",
                                  info->lastmods);
                    cache->stale_handle = h;
                }

                return DECLINED;
            }

            /* Okay, this response looks okay.  Merge in our stuff and go. */
            apr_table_setn(r->headers_out, "Content-Type",
                           ap_make_content_type(r, h->content_type));
            r->filename = apr_pstrdup(r->pool, h->cache_obj->info.filename);
            accept_headers(h, r);

            cache->handle = h;
            return OK;
        }
        case DECLINED: {
            /* try again with next cache type */
            list = list->next;
            continue;
        }
        default: {
            /* oo-er! an error */
            return rv;
        }
        }
    }
    return DECLINED;
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

