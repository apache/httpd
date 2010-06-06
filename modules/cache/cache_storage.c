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

APLOG_USE_MODULE(cache);

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;

/* -------------------------------------------------------------- */

/*
 * delete all URL entities from the cache
 *
 */
int cache_remove_url(cache_request_rec *cache, apr_pool_t *p)
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
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "cache: Removing url %s from the cache", h->cache_obj->key);

    /* for each specified cache type, delete the URL */
    while(list) {
        list->provider->remove_url(h, p);
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
int cache_create_entity(request_rec *r, apr_off_t size)
{
    cache_provider_list *list;
    cache_handle_t *h = apr_pcalloc(r->pool, sizeof(cache_handle_t));
    char *key;
    apr_status_t rv;
    cache_request_rec *cache = (cache_request_rec *)
                         ap_get_module_config(r->request_config, &cache_module);

    rv = cache_generate_key(r, r->pool, &key);
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

CACHE_DECLARE(void) ap_cache_accept_headers(cache_handle_t *h, request_rec *r,
                                            int preserve_orig)
{
    apr_table_t *cookie_table, *hdr_copy;
    const char *v;

    v = apr_table_get(h->resp_hdrs, "Content-Type");
    if (v) {
        ap_set_content_type(r, v);
        apr_table_unset(h->resp_hdrs, "Content-Type");
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

    if (preserve_orig) {
        hdr_copy = apr_table_copy(r->pool, h->resp_hdrs);
        apr_table_overlap(hdr_copy, r->headers_out, APR_OVERLAP_TABLES_SET);
        r->headers_out = hdr_copy;
    }
    else {
        apr_table_overlap(r->headers_out, h->resp_hdrs, APR_OVERLAP_TABLES_SET);
    }
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
int cache_select(request_rec *r)
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
            vary = apr_pstrdup(r->pool, apr_table_get(h->resp_hdrs, "Vary"));
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
                const char *etag, *lastmod;

                ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                  "Cached response for %s isn't fresh.  Adding/replacing "
                  "conditional request headers.", r->uri);

                /* Make response into a conditional */
                cache->stale_headers = apr_table_copy(r->pool,
                                                      r->headers_in);

                /* We can only revalidate with our own conditionals: remove the
                 * conditions from the original request.
                 */
                apr_table_unset(r->headers_in, "If-Match");
                apr_table_unset(r->headers_in, "If-Modified-Since");
                apr_table_unset(r->headers_in, "If-None-Match");
                apr_table_unset(r->headers_in, "If-Range");
                apr_table_unset(r->headers_in, "If-Unmodified-Since");

                /*
                 * Do not do Range requests with our own conditionals: If
                 * we get 304 the Range does not matter and otherwise the
                 * entity changed and we want to have the complete entity
                 */
                apr_table_unset(r->headers_in, "Range");

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
                    cache->stale_handle = h;
                }
                else {
                    int irv;

                    /*
                     * The copy isn't fresh enough, but we cannot revalidate.
                     * So it is the same case as if there had not been a cached
                     * entry at all. Thus delete the entry from cache.
                     */
                    irv = cache->provider->remove_url(h, r->pool);
                    if (irv != OK) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, irv, r->server,
                                     "cache: attempt to remove url from cache unsuccessful.");
                    }
                }

                return DECLINED;
            }

            /* Okay, this response looks okay.  Merge in our stuff and go. */
            ap_cache_accept_headers(h, r, 0);

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

apr_status_t cache_generate_key_default(request_rec *r, apr_pool_t* p,
                                        char**key)
{
    cache_server_conf *conf;
    cache_request_rec *cache;
    char *port_str, *hn, *lcs;
    const char *hostname, *scheme;
    int i;
    char *path, *querystring;

    cache = (cache_request_rec *) ap_get_module_config(r->request_config,
                                                       &cache_module);
    if (!cache) {
        /* This should never happen */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "cache: No cache request information available for key"
                     " generation");
        *key = "";
        return APR_EGENERAL;
    }
    if (cache->key) {
        /*
         * We have been here before during the processing of this request.
         * So return the key we already have.
         */
        *key = apr_pstrdup(p, cache->key);
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
        /* Use _default_ as the hostname if none present, as in mod_vhost */
        hostname =  ap_get_server_name(r);
        if (!hostname) {
            hostname = "_default_";
        }
    }
    else if(r->parsed_uri.hostname) {
        /* Copy the parsed uri hostname */
        hn = apr_pstrdup(p, r->parsed_uri.hostname);
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
    if (r->proxyreq && r->parsed_uri.scheme) {
        /* Copy the scheme and lower-case it */
        lcs = apr_pstrdup(p, r->parsed_uri.scheme);
        ap_str_tolower(lcs);
        /* const work-around */
        scheme = lcs;
    }
    else {
        scheme = ap_http_scheme(r);
    }

    /*
     * If this is a proxy request, but not a reverse proxy request (see comment
     * above why these cases must be handled in the same manner), copy the
     * URI's port-string (which may be a service name). If the URI contains
     * no port-string, use apr-util's notion of the default port for that
     * scheme - if available. Otherwise use the port-number of the current
     * server.
     */
    if(r->proxyreq && (r->proxyreq != PROXYREQ_REVERSE)) {
        if (r->parsed_uri.port_str) {
            port_str = apr_pcalloc(p, strlen(r->parsed_uri.port_str) + 2);
            port_str[0] = ':';
            for (i = 0; r->parsed_uri.port_str[i]; i++) {
                port_str[i + 1] = apr_tolower(r->parsed_uri.port_str[i]);
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
        /* Use the server port */
        port_str = apr_psprintf(p, ":%u", ap_get_server_port(r));
    }

    /*
     * Check if we need to ignore session identifiers in the URL and do so
     * if needed.
     */
    path = r->parsed_uri.path;
    querystring = r->parsed_uri.query;
    if (conf->ignore_session_id->nelts) {
        int i;
        char **identifier;

        identifier = (char **)conf->ignore_session_id->elts;
        for (i = 0; i < conf->ignore_session_id->nelts; i++, identifier++) {
            int len;
            char *param;

            len = strlen(*identifier);
            /*
             * Check that we have a parameter separator in the last segment
             * of the path and that the parameter matches our identifier
             */
            if ((param = strrchr(path, ';'))
                && !strncmp(param + 1, *identifier, len)
                && (*(param + len + 1) == '=')
                && !strchr(param + len + 2, '/')) {
                path = apr_pstrndup(p, path, param - path);
                continue;
            }
            /*
             * Check if the identifier is in the querystring and cut it out.
             */
            if (querystring) {
                /*
                 * First check if the identifier is at the beginning of the
                 * querystring and followed by a '='
                 */
                if (!strncmp(querystring, *identifier, len)
                    && (*(querystring + len) == '=')) {
                    param = querystring;
                }
                else {
                    char *complete;

                    /*
                     * In order to avoid subkey matching (PR 48401) prepend
                     * identifier with a '&' and append a '='
                     */
                    complete = apr_pstrcat(p, "&", *identifier, "=", NULL);
                    param = strstr(querystring, complete);
                    /* If we found something we are sitting on the '&' */
                    if (param) {
                        param++;
                    }
                }
                if (param) {
                    char *amp;

                    if (querystring != param) {
                        querystring = apr_pstrndup(p, querystring,
                                               param - querystring);
                    }
                    else {
                        querystring = "";
                    }

                    if ((amp = strchr(param + len + 1, '&'))) {
                        querystring = apr_pstrcat(p, querystring, amp + 1, NULL);
                    }
                    else {
                        /*
                         * If querystring is not "", then we have the case
                         * that the identifier parameter we removed was the
                         * last one in the original querystring. Hence we have
                         * a trailing '&' which needs to be removed.
                         */
                        if (*querystring) {
                            querystring[strlen(querystring) - 1] = '\0';
                        }
                    }
                }
            }
        }
    }

    /* Key format is a URI, optionally without the query-string */
    if (conf->ignorequerystring) {
        *key = apr_pstrcat(p, scheme, "://", hostname, port_str,
                           path, "?", NULL);
    }
    else {
        *key = apr_pstrcat(p, scheme, "://", hostname, port_str,
                           path, "?", querystring, NULL);
    }

    /*
     * Store the key in the request_config for the cache as r->parsed_uri
     * might have changed in the time from our first visit here triggered by the
     * quick handler and our possible second visit triggered by the CACHE_SAVE
     * filter (e.g. r->parsed_uri got unescaped). In this case we would save the
     * resource in the cache under a key where it is never found by the quick
     * handler during following requests.
     */
    cache->key = apr_pstrdup(r->pool, *key);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "cache: Key for entity %s?%s is %s", r->parsed_uri.path,
                 r->parsed_uri.query, *key);

    return APR_SUCCESS;
}
