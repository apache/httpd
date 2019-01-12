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

APLOG_USE_MODULE(cache);

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;

/* -------------------------------------------------------------- */

/*
 * delete all URL entities from the cache
 *
 */
int cache_remove_url(cache_request_rec *cache, request_rec *r)
{
    cache_provider_list *list;
    cache_handle_t *h;

    list = cache->providers;

    /* Remove the stale cache entry if present. If not, we're
     * being called from outside of a request; remove the
     * non-stale handle.
     */
    h = cache->stale_handle ? cache->stale_handle : cache->handle;
    if (!h) {
       return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00691)
                 "cache: Removing url %s from the cache", h->cache_obj->key);

    /* for each specified cache type, delete the URL */
    while (list) {
        list->provider->remove_url(h, r);
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
int cache_create_entity(cache_request_rec *cache, request_rec *r,
                        apr_off_t size, apr_bucket_brigade *in)
{
    cache_provider_list *list;
    cache_handle_t *h = apr_pcalloc(r->pool, sizeof(cache_handle_t));
    apr_status_t rv;

    if (!cache) {
        /* This should never happen */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r, APLOGNO(00692)
                "cache: No cache request information available for key"
                " generation");
        return APR_EGENERAL;
    }

    if (!cache->key) {
        rv = cache_generate_key(r, r->pool, &cache->key);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    list = cache->providers;
    /* for each specified cache type, delete the URL */
    while (list) {
        switch (rv = list->provider->create_entity(h, r, cache->key, size, in)) {
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

static int filter_header_do(void *v, const char *key, const char *val)
{
    if ((*key == 'W' || *key == 'w') && !ap_cstr_casecmp(key, "Warning")
            && *val == '1') {
        /* any stored Warning headers with warn-code 1xx (see section
         * 14.46) MUST be deleted from the cache entry and the forwarded
         * response.
         */
    }
    else {
        apr_table_addn(v, key, val);
    }
    return 1;
}
static int remove_header_do(void *v, const char *key, const char *val)
{
    if ((*key == 'W' || *key == 'w') && !ap_cstr_casecmp(key, "Warning")) {
        /* any stored Warning headers with warn-code 2xx MUST be retained
         * in the cache entry and the forwarded response.
         */
    }
    else {
        apr_table_unset(v, key);
    }
    return 1;
}
static int add_header_do(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

/**
 * Take two sets of headers, sandwich them together, and apply the result to
 * r->headers_out.
 *
 * To complicate this, a header may be duplicated in either table. Should a
 * header exist in the top table, all matching headers will be removed from
 * the bottom table before the headers are combined. The Warning headers are
 * handled specially. Warnings are added rather than being replaced, while
 * in the case of revalidation 1xx Warnings are stripped.
 *
 * The Content-Type and Last-Modified headers are then re-parsed and inserted
 * into the request.
 */
void cache_accept_headers(cache_handle_t *h, request_rec *r, apr_table_t *top,
        apr_table_t *bottom, int revalidation)
{
    const char *v;

    if (revalidation) {
        r->headers_out = apr_table_make(r->pool, 10);
        apr_table_do(filter_header_do, r->headers_out, bottom, NULL);
    }
    else if (r->headers_out != bottom) {
        r->headers_out = apr_table_copy(r->pool, bottom);
    }
    apr_table_do(remove_header_do, r->headers_out, top, NULL);
    apr_table_do(add_header_do, r->headers_out, top, NULL);

    v = apr_table_get(r->headers_out, "Content-Type");
    if (v) {
        ap_set_content_type(r, v);
        /*
         * Also unset possible Content-Type headers in r->headers_out and
         * r->err_headers_out as they may be different to what we have received
         * from the cache.
         * Actually they are not needed as r->content_type set by
         * ap_set_content_type above will be used in the store_headers functions
         * of the storage providers as a fallback and the HTTP_HEADER filter
         * does overwrite the Content-Type header with r->content_type anyway.
         */
        apr_table_unset(r->headers_out, "Content-Type");
        apr_table_unset(r->err_headers_out, "Content-Type");
    }

    /* If the cache gave us a Last-Modified header, we can't just
     * pass it on blindly because of restrictions on future values.
     */
    v = apr_table_get(r->headers_out, "Last-Modified");
    if (v) {
        ap_update_mtime(r, apr_date_parse_http(v));
        ap_set_last_modified(r);
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
int cache_select(cache_request_rec *cache, request_rec *r)
{
    cache_provider_list *list;
    apr_status_t rv;
    cache_handle_t *h;

    if (!cache) {
        /* This should never happen */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r, APLOGNO(00693)
                "cache: No cache request information available for key"
                " generation");
        return DECLINED;
    }

    /* if no-cache, we can't serve from the cache, but we may store to the
     * cache.
     */
    if (!ap_cache_check_no_cache(cache, r)) {
        return DECLINED;
    }

    if (!cache->key) {
        rv = cache_generate_key(r, r->pool, &cache->key);
        if (rv != APR_SUCCESS) {
            return DECLINED;
        }
    }

    /* go through the cache types till we get a match */
    h = apr_palloc(r->pool, sizeof(cache_handle_t));

    list = cache->providers;

    while (list) {
        switch ((rv = list->provider->open_entity(h, r, cache->key))) {
        case OK: {
            char *vary = NULL;
            int mismatch = 0;
            char *last = NULL;

            if (list->provider->recall_headers(h, r) != APR_SUCCESS) {
                /* try again with next cache type */
                list = list->next;
                continue;
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
             * cache the req_hdrs if the response contains a Vary header.
             *
             * RFC2616 13.6 and 14.44 describe the Vary mechanism.
             */
            vary = cache_strqtok(
                    apr_pstrdup(r->pool,
                            cache_table_getm(r->pool, h->resp_hdrs, "Vary")),
                    CACHE_SEPARATOR, &last);
            while (vary) {
                const char *h1, *h2;

                /*
                 * is this header in the request and the header in the cached
                 * request identical? If not, we give up and do a straight get
                 */
                h1 = cache_table_getm(r->pool, r->headers_in, vary);
                h2 = cache_table_getm(r->pool, h->req_hdrs, vary);
                if (h1 == h2) {
                    /* both headers NULL, so a match - do nothing */
                }
                else if (h1 && h2 && !strcmp(h1, h2)) {
                    /* both headers exist and are equal - do nothing */
                }
                else {
                    /* headers do not match, so Vary failed */
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                            r, APLOGNO(00694) "cache_select(): Vary header mismatch.");
                    mismatch = 1;
                    break;
                }
                vary = cache_strqtok(NULL, CACHE_SEPARATOR, &last);
            }

            /* no vary match, try next provider */
            if (mismatch) {
                /* try again with next cache type */
                list = list->next;
                continue;
            }

            cache->provider = list->provider;
            cache->provider_name = list->provider_name;

            /*
             * RFC2616 13.3.4 Rules for When to Use Entity Tags and Last-Modified
             * Dates: An HTTP/1.1 caching proxy, upon receiving a conditional request
             * that includes both a Last-Modified date and one or more entity tags as
             * cache validators, MUST NOT return a locally cached response to the
             * client unless that cached response is consistent with all of the
             * conditional header fields in the request.
             */
            if (ap_condition_if_match(r, h->resp_hdrs) == AP_CONDITION_NOMATCH
                    || ap_condition_if_unmodified_since(r, h->resp_hdrs)
                            == AP_CONDITION_NOMATCH
                    || ap_condition_if_none_match(r, h->resp_hdrs)
                            == AP_CONDITION_NOMATCH
                    || ap_condition_if_modified_since(r, h->resp_hdrs)
                            == AP_CONDITION_NOMATCH
                    || ap_condition_if_range(r, h->resp_hdrs) == AP_CONDITION_NOMATCH) {
                mismatch = 1;
            }

            /* Is our cached response fresh enough? */
            if (mismatch || !cache_check_freshness(h, cache, r)) {
                const char *etag, *lastmod;

                /* Cache-Control: only-if-cached and revalidation required, try
                 * the next provider
                 */
                if (cache->control_in.only_if_cached) {
                    /* try again with next cache type */
                    list = list->next;
                    continue;
                }

                /* set aside the stale entry for accessing later */
                cache->stale_headers = apr_table_copy(r->pool,
                        r->headers_in);
                cache->stale_handle = h;

                /* if no existing conditionals, use conditionals of our own */
                if (!mismatch) {

                    ap_log_rerror(
                            APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00695) "Cached response for %s isn't fresh. Adding "
                            "conditional request headers.", r->uri);

                    /* Remove existing conditionals that might conflict with ours */
                    apr_table_unset(r->headers_in, "If-Match");
                    apr_table_unset(r->headers_in, "If-Modified-Since");
                    apr_table_unset(r->headers_in, "If-None-Match");
                    apr_table_unset(r->headers_in, "If-Range");
                    apr_table_unset(r->headers_in, "If-Unmodified-Since");

                    etag = apr_table_get(h->resp_hdrs, "ETag");
                    lastmod = apr_table_get(h->resp_hdrs, "Last-Modified");

                    if (etag || lastmod) {
                        /* If we have a cached etag and/or Last-Modified add in
                         * our own conditionals.
                         */

                        if (etag) {
                            apr_table_set(r->headers_in, "If-None-Match", etag);
                        }

                        if (lastmod) {
                            apr_table_set(r->headers_in, "If-Modified-Since",
                                    lastmod);
                        }

                        /*
                         * Do not do Range requests with our own conditionals: If
                         * we get 304 the Range does not matter and otherwise the
                         * entity changed and we want to have the complete entity
                         */
                        apr_table_unset(r->headers_in, "Range");

                    }

                }

                /* ready to revalidate, pretend we were never here */
                return DECLINED;
            }

            /* Okay, this response looks okay.  Merge in our stuff and go. */
            cache_accept_headers(h, r, h->resp_hdrs, r->headers_out, 0);

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

    /* if Cache-Control: only-if-cached, and not cached, return 504 */
    if (cache->control_in.only_if_cached) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00696)
                "cache: 'only-if-cached' requested and no cached entity, "
                "returning 504 Gateway Timeout for: %s", r->uri);
        return HTTP_GATEWAY_TIME_OUT;
    }

    return DECLINED;
}

static apr_status_t cache_canonicalise_key(request_rec *r, apr_pool_t* p,
                                           const char *path, const char *query,
                                           apr_uri_t *parsed_uri,
                                           const char **key)
{
    cache_server_conf *conf;
    char *port_str, *hn, *lcs;
    const char *hostname, *scheme;
    int i;
    const char *kpath;
    const char *kquery;

    if (*key) {
        /*
         * We have been here before during the processing of this request.
         */
        return APR_SUCCESS;
    }

    /*
     * Get the module configuration. We need this for the CacheIgnoreQueryString
     * option below.
     */
    conf = (cache_server_conf *) ap_get_module_config(r->server->module_config,
            &cache_module);

    /*
     * Use the canonical name to improve cache hit rate, but only if this is
     * not a proxy request or if this is a reverse proxy request.
     * We need to handle both cases in the same manner as for the reverse proxy
     * case we have the following situation:
     *
     * If a cached entry is looked up by mod_cache's quick handler r->proxyreq
     * is still unset in the reverse proxy case as it only gets set in the
     * translate name hook (either by ProxyPass or mod_rewrite) which is run
     * after the quick handler hook. This is different to the forward proxy
     * case where it gets set before the quick handler is run (in the
     * post_read_request hook).
     * If a cache entry is created by the CACHE_SAVE filter we always have
     * r->proxyreq set correctly.
     * So we must ensure that in the reverse proxy case we use the same code
     * path and using the canonical name seems to be the right thing to do
     * in the reverse proxy case.
     */
    if (!r->proxyreq || (r->proxyreq == PROXYREQ_REVERSE)) {
        if (conf->base_uri && conf->base_uri->hostname) {
            hostname = conf->base_uri->hostname;
        }
        else {
            /* Use _default_ as the hostname if none present, as in mod_vhost */
            hostname = ap_get_server_name(r);
            if (!hostname) {
                hostname = "_default_";
            }
        }
    }
    else if (parsed_uri->hostname) {
        /* Copy the parsed uri hostname */
        hn = apr_pstrdup(p, parsed_uri->hostname);
        ap_str_tolower(hn);
        /* const work-around */
        hostname = hn;
    }
    else {
        /* We are a proxied request, with no hostname. Unlikely
         * to get very far - but just in case */
        hostname = "_default_";
    }

    /*
     * Copy the scheme, ensuring that it is lower case. If the parsed uri
     * contains no string or if this is not a proxy request get the http
     * scheme for this request. As r->parsed_uri.scheme is not set if this
     * is a reverse proxy request, it is ensured that the cases
     * "no proxy request" and "reverse proxy request" are handled in the same
     * manner (see above why this is needed).
     */
    if (r->proxyreq && parsed_uri->scheme) {
        /* Copy the scheme and lower-case it */
        lcs = apr_pstrdup(p, parsed_uri->scheme);
        ap_str_tolower(lcs);
        /* const work-around */
        scheme = lcs;
    }
    else {
        if (conf->base_uri && conf->base_uri->scheme) {
            scheme = conf->base_uri->scheme;
        }
        else {
            scheme = ap_http_scheme(r);
        }
    }

    /*
     * If this is a proxy request, but not a reverse proxy request (see comment
     * above why these cases must be handled in the same manner), copy the
     * URI's port-string (which may be a service name). If the URI contains
     * no port-string, use apr-util's notion of the default port for that
     * scheme - if available. Otherwise use the port-number of the current
     * server.
     */
    if (r->proxyreq && (r->proxyreq != PROXYREQ_REVERSE)) {
        if (parsed_uri->port_str) {
            port_str = apr_pcalloc(p, strlen(parsed_uri->port_str) + 2);
            port_str[0] = ':';
            for (i = 0; parsed_uri->port_str[i]; i++) {
                port_str[i + 1] = apr_tolower(parsed_uri->port_str[i]);
            }
        }
        else if (apr_uri_port_of_scheme(scheme)) {
            port_str = apr_psprintf(p, ":%u", apr_uri_port_of_scheme(scheme));
        }
        else {
            /* No port string given in the AbsoluteUri, and we have no
             * idea what the default port for the scheme is. Leave it
             * blank and live with the inefficiency of some extra cached
             * entities.
             */
            port_str = "";
        }
    }
    else {
        if (conf->base_uri && conf->base_uri->port_str) {
            port_str = apr_pstrcat(p, ":", conf->base_uri->port_str, NULL);
        }
        else if (conf->base_uri && conf->base_uri->hostname) {
            port_str = "";
        }
        else {
            /* Use the server port */
            port_str = apr_psprintf(p, ":%u", ap_get_server_port(r));
        }
    }

    /*
     * Check if we need to ignore session identifiers in the URL and do so
     * if needed.
     */
    kpath = path;
    kquery = conf->ignorequerystring ? NULL : query;
    if (conf->ignore_session_id->nelts) {
        int i;
        char **identifier;

        identifier = (char **) conf->ignore_session_id->elts;
        for (i = 0; i < conf->ignore_session_id->nelts; i++, identifier++) {
            int len;
            const char *param;

            len = strlen(*identifier);
            /*
             * Check that we have a parameter separator in the last segment
             * of the path and that the parameter matches our identifier
             */
            if ((param = ap_strrchr_c(kpath, ';'))
                    && !strncmp(param + 1, *identifier, len)
                    && (*(param + len + 1) == '=')
                    && !ap_strchr_c(param + len + 2, '/')) {
                kpath = apr_pstrmemdup(p, kpath, param - kpath);
                continue;
            }
            /*
             * Check if the identifier is in the query string and cut it out.
             */
            if (kquery && *kquery) {
                /*
                 * First check if the identifier is at the beginning of the
                 * query string and followed by a '='
                 */
                if (!strncmp(kquery, *identifier, len) && kquery[len] == '=') {
                    param = kquery;
                }
                else {
                    char *complete;

                    /*
                     * In order to avoid subkey matching (PR 48401) prepend
                     * identifier with a '&' and append a '='
                     */
                    complete = apr_pstrcat(p, "&", *identifier, "=", NULL);
                    param = ap_strstr_c(kquery, complete);
                    /* If we found something we are sitting on the '&' */
                    if (param) {
                        param++;
                    }
                }
                if (param) {
                    const char *amp;
                    char *dup = NULL;

                    if (kquery != param) {
                        dup = apr_pstrmemdup(p, kquery, param - kquery);
                        kquery = dup;
                    }
                    else {
                        kquery = "";
                    }

                    if ((amp = ap_strchr_c(param + len + 1, '&'))) {
                        kquery = apr_pstrcat(p, kquery, amp + 1, NULL);
                    }
                    else {
                        /*
                         * If query string is not "", then we have the case
                         * that the identifier parameter we removed was the
                         * last one in the original query string. Hence we have
                         * a trailing '&' which needs to be removed.
                         */
                        if (dup) {
                            dup[strlen(dup) - 1] = '\0';
                        }
                    }
                }
            }
        }
    }

    /* Key format is a URI, optionally without the query-string (NULL
     * per above if conf->ignorequerystring)
     */
    *key = apr_pstrcat(p, scheme, "://", hostname, port_str,
                       kpath, "?", kquery, NULL);

    /*
     * Store the key in the request_config for the cache as r->parsed_uri
     * might have changed in the time from our first visit here triggered by the
     * quick handler and our possible second visit triggered by the CACHE_SAVE
     * filter (e.g. r->parsed_uri got unescaped). In this case we would save the
     * resource in the cache under a key where it is never found by the quick
     * handler during following requests.
     */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00698)
                  "cache: Key for entity %s?%s is %s", path, query, *key);

    return APR_SUCCESS;
}

apr_status_t cache_generate_key_default(request_rec *r, apr_pool_t* p,
                                        const char **key)
{
    /* In early processing (quick-handler, forward proxy), we want the initial
     * query-string from r->parsed_uri, since any change before CACHE_SAVE
     * shouldn't modify the key. Otherwise we want the actual query-string.
     */
    const char *path = r->uri;
    const char *query = r->args;
    if (cache_use_early_url(r)) {
        path = r->parsed_uri.path;
        query = r->parsed_uri.query;
    }
    return cache_canonicalise_key(r, p, path, query, &r->parsed_uri, key);
}

/*
 * Invalidate a specific URL entity in all caches
 *
 * All cached entities for this URL are removed, usually in
 * response to a POST/PUT or DELETE.
 *
 * This function returns OK if at least one entity was found and
 * removed, and DECLINED if no cached entities were removed.
 */
int cache_invalidate(cache_request_rec *cache, request_rec *r)
{
    cache_provider_list *list;
    apr_status_t rv, status = DECLINED;
    cache_handle_t *h;
    apr_uri_t location_uri;
    apr_uri_t content_location_uri;

    const char *location, *location_key = NULL;
    const char *content_location, *content_location_key = NULL;

    if (!cache) {
        /* This should never happen */
        ap_log_rerror(
                APLOG_MARK, APLOG_ERR, APR_EGENERAL, r, APLOGNO(00697) "cache: No cache request information available for key"
                " generation");
        return DECLINED;
    }

    if (!cache->key) {
        rv = cache_generate_key(r, r->pool, &cache->key);
        if (rv != APR_SUCCESS) {
            return DECLINED;
        }
    }

    location = apr_table_get(r->headers_out, "Location");
    if (location) {
        if (apr_uri_parse(r->pool, location, &location_uri)
                || cache_canonicalise_key(r, r->pool,
                                          location_uri.path,
                                          location_uri.query,
                                          &location_uri, &location_key)
                || !(r->parsed_uri.hostname
                     && location_uri.hostname
                     && !strcmp(r->parsed_uri.hostname,
                                location_uri.hostname))) {
            location_key = NULL;
        }
    }

    content_location = apr_table_get(r->headers_out, "Content-Location");
    if (content_location) {
        if (apr_uri_parse(r->pool, content_location,
                          &content_location_uri)
                || cache_canonicalise_key(r, r->pool,
                                          content_location_uri.path,
                                          content_location_uri.query,
                                          &content_location_uri,
                                          &content_location_key)
                || !(r->parsed_uri.hostname
                     && content_location_uri.hostname
                     && !strcmp(r->parsed_uri.hostname,
                                content_location_uri.hostname))) {
            content_location_key = NULL;
        }
    }

    /* go through the cache types */
    h = apr_palloc(r->pool, sizeof(cache_handle_t));

    list = cache->providers;

    while (list) {

        /* invalidate the request uri */
        rv = list->provider->open_entity(h, r, cache->key);
        if (OK == rv) {
            rv = list->provider->invalidate_entity(h, r);
            status = OK;
        }
        ap_log_rerror(
                APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(02468) "cache: Attempted to invalidate cached entity with key: %s", cache->key);

        /* invalidate the Location */
        if (location_key) {
            rv = list->provider->open_entity(h, r, location_key);
            if (OK == rv) {
                rv = list->provider->invalidate_entity(h, r);
                status = OK;
            }
            ap_log_rerror(
                    APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(02469) "cache: Attempted to invalidate cached entity with key: %s", location_key);
        }

        /* invalidate the Content-Location */
        if (content_location_key) {
            rv = list->provider->open_entity(h, r, content_location_key);
            if (OK == rv) {
                rv = list->provider->invalidate_entity(h, r);
                status = OK;
            }
            ap_log_rerror(
                    APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(02470) "cache: Attempted to invalidate cached entity with key: %s", content_location_key);
        }

        list = list->next;
    }

    return status;
}
