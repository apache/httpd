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

#include "cache_util.h"
#include <ap_provider.h>

APLOG_USE_MODULE(cache);

/* -------------------------------------------------------------- */

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;

/* Determine if "url" matches the hostname, scheme and port and path
 * in "filter". All but the path comparisons are case-insensitive.
 */
static int uri_meets_conditions(const apr_uri_t *filter, const apr_size_t pathlen,
                                const apr_uri_t *url, const char *path)
{
    /* Scheme, hostname port and local part. The filter URI and the
     * URI we test may have the following shapes:
     *   /<path>
     *   <scheme>[:://<hostname>[:<port>][/<path>]]
     * That is, if there is no scheme then there must be only the path,
     * and we check only the path; if there is a scheme, we check the
     * scheme for equality, and then if present we match the hostname,
     * and then if present match the port, and finally the path if any.
     *
     * Note that this means that "/<path>" only matches local paths,
     * and to match proxied paths one *must* specify the scheme.
     */

    /* Is the filter is just for a local path or a proxy URI? */
    if (!filter->scheme) {
        if (url->scheme || url->hostname) {
            return 0;
        }
    }
    else {
        /* The URI scheme must be present and identical except for case. */
        if (!url->scheme || ap_cstr_casecmp(filter->scheme, url->scheme)) {
            return 0;
        }

        /* If the filter hostname is null or empty it matches any hostname,
         * if it begins with a "*" it matches the _end_ of the URI hostname
         * excluding the "*", if it begins with a "." it matches the _end_
         * of the URI * hostname including the ".", otherwise it must match
         * the URI hostname exactly. */

        if (filter->hostname && filter->hostname[0]) {
            if (filter->hostname[0] == '.') {
                const size_t fhostlen = strlen(filter->hostname);
                const size_t uhostlen = url->hostname ? strlen(url->hostname) : 0;

                if (fhostlen > uhostlen
                    || (url->hostname
                        && strcasecmp(filter->hostname,
                                      url->hostname + uhostlen - fhostlen))) {
                    return 0;
                }
            }
            else if (filter->hostname[0] == '*') {
                const size_t fhostlen = strlen(filter->hostname + 1);
                const size_t uhostlen = url->hostname ? strlen(url->hostname) : 0;

                if (fhostlen > uhostlen
                    || (url->hostname
                        && strcasecmp(filter->hostname + 1,
                                      url->hostname + uhostlen - fhostlen))) {
                    return 0;
                }
            }
            else if (!url->hostname || strcasecmp(filter->hostname, url->hostname)) {
                return 0;
            }
        }

        /* If the filter port is empty it matches any URL port.
         * If the filter or URL port are missing, or the URL port is
         * empty, they default to the port for their scheme. */

        if (!(filter->port_str && !filter->port_str[0])) {
            /* NOTE:  ap_port_of_scheme will return 0 if given NULL input */
            const unsigned fport = filter->port_str ? filter->port
                    : apr_uri_port_of_scheme(filter->scheme);
            const unsigned uport = (url->port_str && url->port_str[0])
                    ? url->port : apr_uri_port_of_scheme(url->scheme);

            if (fport != uport) {
                return 0;
            }
        }
    }

    /* For HTTP caching purposes, an empty (NULL) path is equivalent to
     * a single "/" path. RFCs 3986/2396
     */
    if (!path) {
        if (*filter->path == '/' && pathlen == 1) {
            return 1;
        }
        else {
            return 0;
        }
    }

    /* Url has met all of the filter conditions so far, determine
     * if the paths match.
     */
    return !strncmp(filter->path, path, pathlen);
}

int cache_use_early_url(request_rec *r)
{
    cache_server_conf *conf;

    if (r->proxyreq == PROXYREQ_PROXY) {
        return 1;
    }

    conf = ap_get_module_config(r->server->module_config, &cache_module);
    if (conf->quick) {
        return 1;
    }

    return 0;
}

static cache_provider_list *get_provider(request_rec *r, struct cache_enable *ent,
        cache_provider_list *providers)
{
    /* Fetch from global config and add to the list. */
    cache_provider *provider;
    provider = ap_lookup_provider(CACHE_PROVIDER_GROUP, ent->type,
                                  "0");
    if (!provider) {
        /* Log an error! */
    }
    else {
        cache_provider_list *newp;
        newp = apr_pcalloc(r->pool, sizeof(cache_provider_list));
        newp->provider_name = ent->type;
        newp->provider = provider;

        if (!providers) {
            providers = newp;
        }
        else {
            cache_provider_list *last = providers;

            while (last->next) {
                if (last->provider == provider) {
                    return providers;
                }
                last = last->next;
            }
            if (last->provider == provider) {
                return providers;
            }
            last->next = newp;
        }
    }

    return providers;
}

cache_provider_list *cache_get_providers(request_rec *r,
                                         cache_server_conf *conf)
{
    cache_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &cache_module);
    cache_provider_list *providers = NULL;
    const char *path;
    int i;

    /* per directory cache disable */
    if (dconf->disable) {
        return NULL;
    }

    path = cache_use_early_url(r) ? r->parsed_uri.path : r->uri;

    /* global cache disable */
    for (i = 0; i < conf->cachedisable->nelts; i++) {
        struct cache_disable *ent =
                               (struct cache_disable *)conf->cachedisable->elts;
        if (uri_meets_conditions(&ent[i].url, ent[i].pathlen,
                                 &r->parsed_uri, path)) {
            /* Stop searching now. */
            return NULL;
        }
    }

    /* loop through all the per directory cacheenable entries */
    for (i = 0; i < dconf->cacheenable->nelts; i++) {
        struct cache_enable *ent =
                                (struct cache_enable *)dconf->cacheenable->elts;
        providers = get_provider(r, &ent[i], providers);
    }

    /* loop through all the global cacheenable entries */
    for (i = 0; i < conf->cacheenable->nelts; i++) {
        struct cache_enable *ent =
                                (struct cache_enable *)conf->cacheenable->elts;
        if (uri_meets_conditions(&ent[i].url, ent[i].pathlen,
                                 &r->parsed_uri, path)) {
            providers = get_provider(r, &ent[i], providers);
        }
    }

    return providers;
}


/* do a HTTP/1.1 age calculation */
CACHE_DECLARE(apr_int64_t) ap_cache_current_age(cache_info *info,
                                                const apr_time_t age_value,
                                                apr_time_t now)
{
    apr_time_t apparent_age, corrected_received_age, response_delay,
               corrected_initial_age, resident_time, current_age,
               age_value_usec;

    age_value_usec = apr_time_from_sec(age_value);

    /* Perform an HTTP/1.1 age calculation. (RFC2616 13.2.3) */

    apparent_age = MAX(0, info->response_time - info->date);
    corrected_received_age = MAX(apparent_age, age_value_usec);
    response_delay = info->response_time - info->request_time;
    corrected_initial_age = corrected_received_age + response_delay;
    resident_time = now - info->response_time;
    current_age = corrected_initial_age + resident_time;

    if (current_age < 0) {
        current_age = 0;
    }

    return apr_time_sec(current_age);
}

/**
 * Try obtain a cache wide lock on the given cache key.
 *
 * If we return APR_SUCCESS, we obtained the lock, and we are clear to
 * proceed to the backend. If we return APR_EEXIST, then the lock is
 * already locked, someone else has gone to refresh the backend data
 * already, so we must return stale data with a warning in the mean
 * time. If we return anything else, then something has gone pear
 * shaped, and we allow the request through to the backend regardless.
 *
 * This lock is created from the request pool, meaning that should
 * something go wrong and the lock isn't deleted on return of the
 * request headers from the backend for whatever reason, at worst the
 * lock will be cleaned up when the request dies or finishes.
 *
 * If something goes truly bananas and the lock isn't deleted when the
 * request dies, the lock will be trashed when its max-age is reached,
 * or when a request arrives containing a Cache-Control: no-cache. At
 * no point is it possible for this lock to permanently deny access to
 * the backend.
 */
apr_status_t cache_try_lock(cache_server_conf *conf, cache_request_rec *cache,
        request_rec *r)
{
    apr_status_t status;
    const char *lockname;
    const char *path;
    char dir[5];
    apr_time_t now = apr_time_now();
    apr_finfo_t finfo;
    apr_file_t *lockfile;
    void *dummy;

    finfo.mtime = 0;

    if (!conf || !conf->lock || !conf->lockpath) {
        /* no locks configured, leave */
        return APR_SUCCESS;
    }

    /* lock already obtained earlier? if so, success */
    apr_pool_userdata_get(&dummy, CACHE_LOCKFILE_KEY, r->pool);
    if (dummy) {
        return APR_SUCCESS;
    }

    /* create the key if it doesn't exist */
    if (!cache->key) {
        cache_handle_t *h;
        /*
         * Try to use the key of a possible open but stale cache
         * entry if we have one.
         */
        if (cache->handle != NULL) {
            h = cache->handle;
        }
        else {
            h = cache->stale_handle;
        }
        if ((h != NULL) &&
            (h->cache_obj != NULL) &&
            (h->cache_obj->key != NULL)) {
            cache->key = apr_pstrdup(r->pool, h->cache_obj->key);
        }
        else {
            cache_generate_key(r, r->pool, &cache->key);
        }
    }

    /* create a hashed filename from the key, and save it for later */
    lockname = ap_cache_generate_name(r->pool, 0, 0, cache->key);

    /* lock files represent discrete just-went-stale URLs "in flight", so
     * we support a simple two level directory structure, more is overkill.
     */
    dir[0] = '/';
    dir[1] = lockname[0];
    dir[2] = '/';
    dir[3] = lockname[1];
    dir[4] = 0;

    /* make the directories */
    path = apr_pstrcat(r->pool, conf->lockpath, dir, NULL);
    if (APR_SUCCESS != (status = apr_dir_make_recursive(path,
            APR_UREAD|APR_UWRITE|APR_UEXECUTE, r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(00778)
                "Could not create a cache lock directory: %s",
                path);
        return status;
    }
    lockname = apr_pstrcat(r->pool, path, "/", lockname, NULL);
    apr_pool_userdata_set(lockname, CACHE_LOCKNAME_KEY, NULL, r->pool);

    /* is an existing lock file too old? */
    status = apr_stat(&finfo, lockname,
                APR_FINFO_MTIME | APR_FINFO_NLINK, r->pool);
    if (!(APR_STATUS_IS_ENOENT(status)) && APR_SUCCESS != status) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(00779)
                "Could not stat a cache lock file: %s",
                lockname);
        return status;
    }
    if ((status == APR_SUCCESS) && (((now - finfo.mtime) > conf->lockmaxage)
                                  || (now < finfo.mtime))) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO(00780)
                "Cache lock file for '%s' too old, removing: %s",
                r->uri, lockname);
        apr_file_remove(lockname, r->pool);
    }

    /* try obtain a lock on the file */
    if (APR_SUCCESS == (status = apr_file_open(&lockfile, lockname,
            APR_WRITE | APR_CREATE | APR_EXCL | APR_DELONCLOSE,
            APR_UREAD | APR_UWRITE, r->pool))) {
        apr_pool_userdata_set(lockfile, CACHE_LOCKFILE_KEY, NULL, r->pool);
    }
    return status;

}

/**
 * Remove the cache lock, if present.
 *
 * First, try to close the file handle, whose delete-on-close should
 * kill the file. Otherwise, just delete the file by name.
 *
 * If no lock name has yet been calculated, do the calculation of the
 * lock name first before trying to delete the file.
 *
 * If an optional bucket brigade is passed, the lock will only be
 * removed if the bucket brigade contains an EOS bucket.
 */
apr_status_t cache_remove_lock(cache_server_conf *conf,
        cache_request_rec *cache, request_rec *r, apr_bucket_brigade *bb)
{
    void *dummy;
    const char *lockname;

    if (!conf || !conf->lock || !conf->lockpath) {
        /* no locks configured, leave */
        return APR_SUCCESS;
    }
    if (bb) {
        apr_bucket *e;
        int eos_found = 0;
        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_EOS(e)) {
                eos_found = 1;
                break;
            }
        }
        if (!eos_found) {
            /* no eos found in brigade, don't delete anything just yet,
             * we are not done.
             */
            return APR_SUCCESS;
        }
    }
    apr_pool_userdata_get(&dummy, CACHE_LOCKFILE_KEY, r->pool);
    if (dummy) {
        return apr_file_close((apr_file_t *)dummy);
    }
    apr_pool_userdata_get(&dummy, CACHE_LOCKNAME_KEY, r->pool);
    lockname = (const char *)dummy;
    if (!lockname) {
        char dir[5];

        /* create the key if it doesn't exist */
        if (!cache->key) {
            cache_generate_key(r, r->pool, &cache->key);
        }

        /* create a hashed filename from the key, and save it for later */
        lockname = ap_cache_generate_name(r->pool, 0, 0, cache->key);

        /* lock files represent discrete just-went-stale URLs "in flight", so
         * we support a simple two level directory structure, more is overkill.
         */
        dir[0] = '/';
        dir[1] = lockname[0];
        dir[2] = '/';
        dir[3] = lockname[1];
        dir[4] = 0;

        lockname = apr_pstrcat(r->pool, conf->lockpath, dir, "/", lockname, NULL);
    }
    return apr_file_remove(lockname, r->pool);
}

int ap_cache_check_no_cache(cache_request_rec *cache, request_rec *r)
{

    cache_server_conf *conf =
      (cache_server_conf *)ap_get_module_config(r->server->module_config,
                                                &cache_module);

    /*
     * At this point, we may have data cached, but the request may have
     * specified that cached data may not be used in a response.
     *
     * This is covered under RFC2616 section 14.9.4 (Cache Revalidation and
     * Reload Controls).
     *
     * - RFC2616 14.9.4 End to end reload, Cache-Control: no-cache, or Pragma:
     * no-cache. The server MUST NOT use a cached copy when responding to such
     * a request.
     */

    /* This value comes from the client's initial request. */
    if (!cache->control_in.parsed) {
        const char *cc_req = cache_table_getm(r->pool, r->headers_in,
                "Cache-Control");
        const char *pragma = cache_table_getm(r->pool, r->headers_in, "Pragma");
        ap_cache_control(r, &cache->control_in, cc_req, pragma, r->headers_in);
    }

    if (cache->control_in.no_cache) {

        if (!conf->ignorecachecontrol) {
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02657)
                    "Incoming request is asking for an uncached version of "
                    "%s, but we have been configured to ignore it and serve "
                    "cached content anyway", r->unparsed_uri);
        }
    }

    return 1;
}

int ap_cache_check_no_store(cache_request_rec *cache, request_rec *r)
{

    cache_server_conf *conf =
      (cache_server_conf *)ap_get_module_config(r->server->module_config,
                                                &cache_module);

    /*
     * At this point, we may have data cached, but the request may have
     * specified that cached data may not be used in a response.
     *
     * - RFC2616 14.9.2 What May be Stored by Caches. If Cache-Control:
     * no-store arrives, do not serve from or store to the cache.
     */

    /* This value comes from the client's initial request. */
    if (!cache->control_in.parsed) {
        const char *cc_req = cache_table_getm(r->pool, r->headers_in,
                "Cache-Control");
        const char *pragma = cache_table_getm(r->pool, r->headers_in, "Pragma");
        ap_cache_control(r, &cache->control_in, cc_req, pragma, r->headers_in);
    }

    if (cache->control_in.no_store) {

        if (!conf->ignorecachecontrol) {
            /* We're not allowed to serve a cached copy */
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02658)
                    "Incoming request is asking for a no-store version of "
                    "%s, but we have been configured to ignore it and serve "
                    "cached content anyway", r->unparsed_uri);
        }
    }

    return 1;
}

int cache_check_freshness(cache_handle_t *h, cache_request_rec *cache,
        request_rec *r)
{
    apr_status_t status;
    apr_int64_t age, maxage_req, maxage_cresp, maxage, smaxage, maxstale;
    apr_int64_t minfresh;
    const char *cc_req;
    const char *pragma;
    const char *agestr = NULL;
    apr_time_t age_c = 0;
    cache_info *info = &(h->cache_obj->info);
    const char *warn_head;
    cache_server_conf *conf =
      (cache_server_conf *)ap_get_module_config(r->server->module_config,
                                                &cache_module);

    /*
     * We now want to check if our cached data is still fresh. This depends
     * on a few things, in this order:
     *
     * - RFC2616 14.9.4 End to end reload, Cache-Control: no-cache. no-cache
     * in either the request or the cached response means that we must
     * perform the request unconditionally, and ignore cached content. We
     * should never reach here, but if we do, mark the content as stale,
     * as this is the best we can do.
     *
     * - RFC2616 14.32 Pragma: no-cache This is treated the same as
     * Cache-Control: no-cache.
     *
     * - RFC2616 14.9.3 Cache-Control: max-stale, must-revalidate,
     * proxy-revalidate if the max-stale request header exists, modify the
     * stale calculations below so that an object can be at most <max-stale>
     * seconds stale before we request a revalidation, _UNLESS_ a
     * must-revalidate or proxy-revalidate cached response header exists to
     * stop us doing this.
     *
     * - RFC2616 14.9.3 Cache-Control: s-maxage the origin server specifies the
     * maximum age an object can be before it is considered stale. This
     * directive has the effect of proxy|must revalidate, which in turn means
     * simple ignore any max-stale setting.
     *
     * - RFC2616 14.9.4 Cache-Control: max-age this header can appear in both
     * requests and responses. If both are specified, the smaller of the two
     * takes priority.
     *
     * - RFC2616 14.21 Expires: if this request header exists in the cached
     * entity, and it's value is in the past, it has expired.
     *
     */

    /* This value comes from the client's initial request. */
    cc_req = apr_table_get(r->headers_in, "Cache-Control");
    pragma = apr_table_get(r->headers_in, "Pragma");

    ap_cache_control(r, &cache->control_in, cc_req, pragma, r->headers_in);

    if (cache->control_in.no_cache) {

        if (!conf->ignorecachecontrol) {
            /* Treat as stale, causing revalidation */
            return 0;
        }

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00781)
                "Incoming request is asking for a uncached version of "
                "%s, but we have been configured to ignore it and "
                "serve a cached response anyway",
                r->unparsed_uri);
    }

    /* These come from the cached entity. */
    if (h->cache_obj->info.control.no_cache
            || h->cache_obj->info.control.invalidated) {
        /*
         * The cached entity contained Cache-Control: no-cache, or a
         * no-cache with a header present, or a private with a header
         * present, or the cached entity has been invalidated in the
         * past, so treat as stale causing revalidation.
         */
        return 0;
    }

    if ((agestr = apr_table_get(h->resp_hdrs, "Age"))) {
        char *endp;
        apr_off_t offt;
        if (!apr_strtoff(&offt, agestr, &endp, 10)
                && endp > agestr && !*endp) {
            age_c = offt;
        }
    }

    /* calculate age of object */
    age = ap_cache_current_age(info, age_c, r->request_time);

    /* extract s-maxage */
    smaxage = h->cache_obj->info.control.s_maxage_value;

    /* extract max-age from request */
    maxage_req = -1;
    if (!conf->ignorecachecontrol) {
        maxage_req = cache->control_in.max_age_value;
    }

    /*
     * extract max-age from response, if both s-maxage and max-age, s-maxage
     * takes priority
     */
    if (smaxage != -1) {
        maxage_cresp = smaxage;
    }
    else {
        maxage_cresp = h->cache_obj->info.control.max_age_value;
    }

    /*
     * if both maxage request and response, the smaller one takes priority
     */
    if (maxage_req == -1) {
        maxage = maxage_cresp;
    }
    else if (maxage_cresp == -1) {
        maxage = maxage_req;
    }
    else {
        maxage = MIN(maxage_req, maxage_cresp);
    }

    /* extract max-stale */
    if (cache->control_in.max_stale) {
        if (cache->control_in.max_stale_value != -1) {
            maxstale = cache->control_in.max_stale_value;
        }
        else {
            /*
             * If no value is assigned to max-stale, then the client is willing
             * to accept a stale response of any age (RFC2616 14.9.3). We will
             * set it to one year in this case as this situation is somewhat
             * similar to a "never expires" Expires header (RFC2616 14.21)
             * which is set to a date one year from the time the response is
             * sent in this case.
             */
            maxstale = APR_INT64_C(86400*365);
        }
    }
    else {
        maxstale = 0;
    }

    /* extract min-fresh */
    if (!conf->ignorecachecontrol && cache->control_in.min_fresh) {
        minfresh = cache->control_in.min_fresh_value;
    }
    else {
        minfresh = 0;
    }

    /* override maxstale if must-revalidate, proxy-revalidate or s-maxage */
    if (maxstale && (h->cache_obj->info.control.must_revalidate
            || h->cache_obj->info.control.proxy_revalidate || smaxage != -1)) {
        maxstale = 0;
    }

    /* handle expiration */
    if (((maxage != -1) && (age < (maxage + maxstale - minfresh))) ||
        ((smaxage == -1) && (maxage == -1) &&
         (info->expire != APR_DATE_BAD) &&
         (age < (apr_time_sec(info->expire - info->date) + maxstale - minfresh)))) {

        warn_head = apr_table_get(h->resp_hdrs, "Warning");

        /* it's fresh darlings... */
        /* set age header on response */
        apr_table_set(h->resp_hdrs, "Age",
                      apr_psprintf(r->pool, "%lu", (unsigned long)age));

        /* add warning if maxstale overrode freshness calculation */
        if (!(((maxage != -1) && age < maxage) ||
              (info->expire != APR_DATE_BAD &&
               (apr_time_sec(info->expire - info->date)) > age))) {
            /* make sure we don't stomp on a previous warning */
            if ((warn_head == NULL) ||
                ((warn_head != NULL) && (ap_strstr_c(warn_head, "110") == NULL))) {
                apr_table_mergen(h->resp_hdrs, "Warning",
                                 "110 Response is stale");
            }
        }

        /*
         * If none of Expires, Cache-Control: max-age, or Cache-Control:
         * s-maxage appears in the response, and the response header age
         * calculated is more than 24 hours add the warning 113
         */
        if ((maxage_cresp == -1) && (smaxage == -1) && (apr_table_get(
                h->resp_hdrs, "Expires") == NULL) && (age > 86400)) {

            /* Make sure we don't stomp on a previous warning, and don't dup
             * a 113 marning that is already present. Also, make sure to add
             * the new warning to the correct *headers_out location.
             */
            if ((warn_head == NULL) ||
                ((warn_head != NULL) && (ap_strstr_c(warn_head, "113") == NULL))) {
                apr_table_mergen(h->resp_hdrs, "Warning",
                                 "113 Heuristic expiration");
            }
        }
        return 1;    /* Cache object is fresh (enough) */
    }

    /*
     * At this point we are stale, but: if we are under load, we may let
     * a significant number of stale requests through before the first
     * stale request successfully revalidates itself, causing a sudden
     * unexpected thundering herd which in turn brings angst and drama.
     *
     * So.
     *
     * We want the first stale request to go through as normal. But the
     * second and subsequent request, we must pretend to be fresh until
     * the first request comes back with either new content or confirmation
     * that the stale content is still fresh.
     *
     * To achieve this, we create a very simple file based lock based on
     * the key of the cached object. We attempt to open the lock file with
     * exclusive write access. If we succeed, woohoo! we're first, and we
     * follow the stale path to the backend server. If we fail, oh well,
     * we follow the fresh path, and avoid being a thundering herd.
     *
     * The lock lives only as long as the stale request that went on ahead.
     * If the request succeeds, the lock is deleted. If the request fails,
     * the lock is deleted, and another request gets to make a new lock
     * and try again.
     *
     * At any time, a request marked "no-cache" will force a refresh,
     * ignoring the lock, ensuring an extended lockout is impossible.
     *
     * A lock that exceeds a maximum age will be deleted, and another
     * request gets to make a new lock and try again.
     */
    status = cache_try_lock(conf, cache, r);
    if (APR_SUCCESS == status) {
        /* we obtained a lock, follow the stale path */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00782)
                "Cache lock obtained for stale cached URL, "
                "revalidating entry: %s",
                r->unparsed_uri);
        return 0;
    }
    else if (APR_STATUS_IS_EEXIST(status)) {
        /* lock already exists, return stale data anyway, with a warning */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO(00783)
                "Cache already locked for stale cached URL, "
                "pretend it is fresh: %s",
                r->unparsed_uri);

        /* make sure we don't stomp on a previous warning */
        warn_head = apr_table_get(h->resp_hdrs, "Warning");
        if ((warn_head == NULL) ||
            ((warn_head != NULL) && (ap_strstr_c(warn_head, "110") == NULL))) {
            apr_table_mergen(h->resp_hdrs, "Warning",
                             "110 Response is stale");
        }

        return 1;
    }
    else {
        /* some other error occurred, just treat the object as stale */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO(00784)
                "Attempt to obtain a cache lock for stale "
                "cached URL failed, revalidating entry anyway: %s",
                r->unparsed_uri);
        return 0;
    }

}

/* return each comma separated token, one at a time */
CACHE_DECLARE(const char *)ap_cache_tokstr(apr_pool_t *p, const char *list,
                                           const char **str)
{
    apr_size_t i;
    const char *s;

    s = ap_strchr_c(list, ',');
    if (s != NULL) {
        i = s - list;
        do
            s++;
        while (apr_isspace(*s))
            ; /* noop */
    }
    else
        i = strlen(list);

    while (i > 0 && apr_isspace(list[i - 1]))
        i--;

    *str = s;
    if (i)
        return apr_pstrmemdup(p, list, i);
    else
        return NULL;
}

/*
 * Converts apr_time_t expressed as hex digits to
 * a true apr_time_t.
 */
CACHE_DECLARE(apr_time_t) ap_cache_hex2usec(const char *x)
{
    int i, ch;
    apr_time_t j;
    for (i = 0, j = 0; i < sizeof(j) * 2; i++) {
        ch = x[i];
        j <<= 4;
        if (apr_isdigit(ch))
            j |= ch - '0';
        else if (apr_isupper(ch))
            j |= ch - ('A' - 10);
        else
            j |= ch - ('a' - 10);
    }
    return j;
}

/*
 * Converts apr_time_t to apr_time_t expressed as hex digits.
 */
CACHE_DECLARE(void) ap_cache_usec2hex(apr_time_t j, char *y)
{
    int i, ch;

    for (i = (sizeof(j) * 2)-1; i >= 0; i--) {
        ch = (int)(j & 0xF);
        j >>= 4;
        if (ch >= 10)
            y[i] = ch + ('A' - 10);
        else
            y[i] = ch + '0';
    }
    y[sizeof(j) * 2] = '\0';
}

static void cache_hash(const char *it, char *val, int ndepth, int nlength)
{
    apr_md5_ctx_t context;
    unsigned char digest[16];
    char tmp[22];
    int i, k, d;
    unsigned int x;
    static const char enc_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@";

    apr_md5_init(&context);
    apr_md5_update(&context, (const unsigned char *) it, strlen(it));
    apr_md5_final(digest, &context);

    /* encode 128 bits as 22 characters, using a modified uuencoding
     * the encoding is 3 bytes -> 4 characters* i.e. 128 bits is
     * 5 x 3 bytes + 1 byte -> 5 * 4 characters + 2 characters
     */
    for (i = 0, k = 0; i < 15; i += 3) {
        x = (digest[i] << 16) | (digest[i + 1] << 8) | digest[i + 2];
        tmp[k++] = enc_table[x >> 18];
        tmp[k++] = enc_table[(x >> 12) & 0x3f];
        tmp[k++] = enc_table[(x >> 6) & 0x3f];
        tmp[k++] = enc_table[x & 0x3f];
    }

    /* one byte left */
    x = digest[15];
    tmp[k++] = enc_table[x >> 2];    /* use up 6 bits */
    tmp[k++] = enc_table[(x << 4) & 0x3f];

    /* now split into directory levels */
    for (i = k = d = 0; d < ndepth; ++d) {
        memcpy(&val[i], &tmp[k], nlength);
        k += nlength;
        val[i + nlength] = '/';
        i += nlength + 1;
    }
    memcpy(&val[i], &tmp[k], 22 - k);
    val[i + 22 - k] = '\0';
}

CACHE_DECLARE(char *)ap_cache_generate_name(apr_pool_t *p, int dirlevels,
                                            int dirlength, const char *name)
{
    char hashfile[66];
    cache_hash(name, hashfile, dirlevels, dirlength);
    return apr_pstrdup(p, hashfile);
}

/**
 * String tokenizer that ignores separator characters within quoted strings
 * and escaped characters, as per RFC2616 section 2.2.
 */
char *cache_strqtok(char *str, const char *sep, char **last)
{
    char *token;
    int quoted = 0;

    if (!str) {         /* subsequent call */
        str = *last;    /* start where we left off */
    }

    if (!str) {         /* no more tokens */
        return NULL;
    }

    /* skip characters in sep (will terminate at '\0') */
    while (*str && ap_strchr_c(sep, *str)) {
        ++str;
    }

    if (!*str) {        /* no more tokens */
        return NULL;
    }

    token = str;

    /* skip valid token characters to terminate token and
     * prepare for the next call (will terminate at '\0)
     * on the way, ignore all quoted strings, and within
     * quoted strings, escaped characters.
     */
    *last = token;
    while (**last) {
        if (!quoted) {
            if (**last == '\"' && !ap_strchr_c(sep, '\"')) {
                quoted = 1;
                ++*last;
            }
            else if (!ap_strchr_c(sep, **last)) {
                ++*last;
            }
            else {
                break;
            }
        }
        else {
            if (**last == '\"') {
                quoted = 0;
                ++*last;
            }
            else if (**last == '\\') {
                ++*last;
                if (**last) {
                    ++*last;
                }
            }
            else {
                ++*last;
            }
        }
    }

    if (**last) {
        **last = '\0';
        ++*last;
    }

    return token;
}

/**
 * Parse the Cache-Control and Pragma headers in one go, marking
 * which tokens appear within the header. Populate the structure
 * passed in.
 */
int ap_cache_control(request_rec *r, cache_control_t *cc,
        const char *cc_header, const char *pragma_header, apr_table_t *headers)
{
    char *last;

    if (cc->parsed) {
        return cc->cache_control || cc->pragma;
    }

    cc->parsed = 1;
    cc->max_age_value = -1;
    cc->max_stale_value = -1;
    cc->min_fresh_value = -1;
    cc->s_maxage_value = -1;

    if (pragma_header) {
        char *header = apr_pstrdup(r->pool, pragma_header);
        const char *token = cache_strqtok(header, CACHE_SEPARATOR, &last);
        while (token) {
            if (!ap_cstr_casecmp(token, "no-cache")) {
                cc->no_cache = 1;
            }
            token = cache_strqtok(NULL, CACHE_SEPARATOR, &last);
        }
        cc->pragma = 1;
    }

    if (cc_header) {
        char *endp;
        apr_off_t offt;
        char *header = apr_pstrdup(r->pool, cc_header);
        const char *token = cache_strqtok(header, CACHE_SEPARATOR, &last);
        while (token) {
            switch (token[0]) {
            case 'n':
            case 'N': {
                if (!ap_cstr_casecmpn(token, "no-cache", 8)) {
                    if (token[8] == '=') {
                        cc->no_cache_header = 1;
                    }
                    else if (!token[8]) {
                        cc->no_cache = 1;
                    }
                }
                else if (!ap_cstr_casecmp(token, "no-store")) {
                    cc->no_store = 1;
                }
                else if (!ap_cstr_casecmp(token, "no-transform")) {
                    cc->no_transform = 1;
                }
                break;
            }
            case 'm':
            case 'M': {
                if (!ap_cstr_casecmpn(token, "max-age", 7)) {
                    if (token[7] == '='
                            && !apr_strtoff(&offt, token + 8, &endp, 10)
                            && endp > token + 8 && !*endp) {
                        cc->max_age = 1;
                        cc->max_age_value = offt;
                    }
                }
                else if (!ap_cstr_casecmp(token, "must-revalidate")) {
                    cc->must_revalidate = 1;
                }
                else if (!ap_cstr_casecmpn(token, "max-stale", 9)) {
                    if (token[9] == '='
                            && !apr_strtoff(&offt, token + 10, &endp, 10)
                            && endp > token + 10 && !*endp) {
                        cc->max_stale = 1;
                        cc->max_stale_value = offt;
                    }
                    else if (!token[9]) {
                        cc->max_stale = 1;
                        cc->max_stale_value = -1;
                    }
                }
                else if (!ap_cstr_casecmpn(token, "min-fresh", 9)) {
                    if (token[9] == '='
                            && !apr_strtoff(&offt, token + 10, &endp, 10)
                            && endp > token + 10 && !*endp) {
                        cc->min_fresh = 1;
                        cc->min_fresh_value = offt;
                    }
                }
                break;
            }
            case 'o':
            case 'O': {
                if (!ap_cstr_casecmp(token, "only-if-cached")) {
                    cc->only_if_cached = 1;
                }
                break;
            }
            case 'p':
            case 'P': {
                if (!ap_cstr_casecmp(token, "public")) {
                    cc->public = 1;
                }
                else if (!ap_cstr_casecmpn(token, "private", 7)) {
                    if (token[7] == '=') {
                        cc->private_header = 1;
                    }
                    else if (!token[7]) {
                        cc->private = 1;
                    }
                }
                else if (!ap_cstr_casecmp(token, "proxy-revalidate")) {
                    cc->proxy_revalidate = 1;
                }
                break;
            }
            case 's':
            case 'S': {
                if (!ap_cstr_casecmpn(token, "s-maxage", 8)) {
                    if (token[8] == '='
                            && !apr_strtoff(&offt, token + 9, &endp, 10)
                            && endp > token + 9 && !*endp) {
                        cc->s_maxage = 1;
                        cc->s_maxage_value = offt;
                    }
                }
                break;
            }
            }
            token = cache_strqtok(NULL, CACHE_SEPARATOR, &last);
        }
        cc->cache_control = 1;
    }

    return (cc_header != NULL || pragma_header != NULL);
}

/**
 * Parse the Cache-Control, identifying and removing headers that
 * exist as tokens after the no-cache and private tokens.
 */
static int cache_control_remove(request_rec *r, const char *cc_header,
        apr_table_t *headers)
{
    char *last, *slast;
    int found = 0;

    if (cc_header) {
        char *header = apr_pstrdup(r->pool, cc_header);
        char *token = cache_strqtok(header, CACHE_SEPARATOR, &last);
        while (token) {
            switch (token[0]) {
            case 'n':
            case 'N': {
                if (!ap_cstr_casecmpn(token, "no-cache", 8)) {
                    if (token[8] == '=') {
                        const char *header = cache_strqtok(token + 9,
                                CACHE_SEPARATOR "\"", &slast);
                        while (header) {
                            apr_table_unset(headers, header);
                            header = cache_strqtok(NULL, CACHE_SEPARATOR "\"",
                                    &slast);
                        }
                        found = 1;
                    }
                }
                break;
            }
            case 'p':
            case 'P': {
                if (!ap_cstr_casecmpn(token, "private", 7)) {
                    if (token[7] == '=') {
                        const char *header = cache_strqtok(token + 8,
                                CACHE_SEPARATOR "\"", &slast);
                        while (header) {
                            apr_table_unset(headers, header);
                            header = cache_strqtok(NULL, CACHE_SEPARATOR "\"",
                                    &slast);
                        }
                        found = 1;
                    }
                }
                break;
            }
            }
            token = cache_strqtok(NULL, CACHE_SEPARATOR, &last);
        }
    }

    return found;
}

/*
 * Create a new table consisting of those elements from an
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers(apr_pool_t *pool,
                                                        apr_table_t *t,
                                                        server_rec *s)
{
    cache_server_conf *conf;
    char **header;
    int i;
    apr_table_t *headers_out;

    /* Short circuit the common case that there are not
     * (yet) any headers populated.
     */
    if (t == NULL) {
        return apr_table_make(pool, 10);
    };

    /* Make a copy of the headers, and remove from
     * the copy any hop-by-hop headers, as defined in Section
     * 13.5.1 of RFC 2616
     */
    headers_out = apr_table_copy(pool, t);

    apr_table_unset(headers_out, "Connection");
    apr_table_unset(headers_out, "Keep-Alive");
    apr_table_unset(headers_out, "Proxy-Authenticate");
    apr_table_unset(headers_out, "Proxy-Authorization");
    apr_table_unset(headers_out, "TE");
    apr_table_unset(headers_out, "Trailers");
    apr_table_unset(headers_out, "Transfer-Encoding");
    apr_table_unset(headers_out, "Upgrade");

    conf = (cache_server_conf *)ap_get_module_config(s->module_config,
                                                     &cache_module);

    /* Remove the user defined headers set with CacheIgnoreHeaders.
     * This may break RFC 2616 compliance on behalf of the administrator.
     */
    header = (char **)conf->ignore_headers->elts;
    for (i = 0; i < conf->ignore_headers->nelts; i++) {
        apr_table_unset(headers_out, header[i]);
    }
    return headers_out;
}

/*
 * Create a new table consisting of those elements from an input
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers_in(request_rec *r)
{
    return ap_cache_cacheable_headers(r->pool, r->headers_in, r->server);
}

/*
 * Create a new table consisting of those elements from an output
 * headers table that are allowed to be stored in a cache;
 * ensure there is a content type and capture any errors.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers_out(request_rec *r)
{
    apr_table_t *headers_out;

    headers_out = ap_cache_cacheable_headers(r->pool,
                                             cache_merge_headers_out(r),
                                             r->server);

    cache_control_remove(r,
            cache_table_getm(r->pool, headers_out, "Cache-Control"),
            headers_out);

    return headers_out;
}

apr_table_t *cache_merge_headers_out(request_rec *r)
{
    apr_table_t *headers_out;

    headers_out = apr_table_overlay(r->pool, r->headers_out,
                                    r->err_headers_out);

    if (r->content_type
            && !apr_table_get(headers_out, "Content-Type")) {
        const char *ctype = ap_make_content_type(r, r->content_type);
        if (ctype) {
            apr_table_setn(headers_out, "Content-Type", ctype);
        }
    }

    if (r->content_encoding
            && !apr_table_get(headers_out, "Content-Encoding")) {
        apr_table_setn(headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    return headers_out;
}

typedef struct
{
    apr_pool_t *p;
    const char *first;
    apr_array_header_t *merged;
} cache_table_getm_t;

static int cache_table_getm_do(void *v, const char *key, const char *val)
{
    cache_table_getm_t *state = (cache_table_getm_t *) v;

    if (!state->first) {
        /**
         * The most common case is a single header, and this is covered by
         * a fast path that doesn't allocate any memory. On the second and
         * subsequent header, an array is created and the array concatenated
         * together to form the final value.
         */
        state->first = val;
    }
    else {
        const char **elt;
        if (!state->merged) {
            state->merged = apr_array_make(state->p, 10, sizeof(const char *));
            elt = apr_array_push(state->merged);
            *elt = state->first;
        }
        elt = apr_array_push(state->merged);
        *elt = val;
    }
    return 1;
}

const char *cache_table_getm(apr_pool_t *p, const apr_table_t *t,
        const char *key)
{
    cache_table_getm_t state;

    state.p = p;
    state.first = NULL;
    state.merged = NULL;

    apr_table_do(cache_table_getm_do, &state, t, key, NULL);

    if (!state.first) {
        return NULL;
    }
    else if (!state.merged) {
        return state.first;
    }
    else {
        return apr_array_pstrcat(p, state.merged, ',');
    }
}
