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

#include <ap_provider.h>

/* -------------------------------------------------------------- */

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;

/* Determine if "url" matches the hostname, scheme and port and path
 * in "filter". All but the path comparisons are case-insensitive.
 */
static int uri_meets_conditions(const apr_uri_t filter, const int pathlen,
        const apr_uri_t url) {

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
    if (!filter.scheme) {
        if (url.scheme || url.hostname) {
            return 0;
        }
    }
    else {
        /* The URI scheme must be present and identical except for case. */
        if (!url.scheme || strcasecmp(filter.scheme, url.scheme)) {
            return 0;
        }

        /* If the filter hostname is null or empty it matches any hostname,
         * if it begins with a "*" it matches the _end_ of the URI hostname
         * excluding the "*", if it begins with a "." it matches the _end_
         * of the URI * hostname including the ".", otherwise it must match
         * the URI hostname exactly. */

        if (filter.hostname && filter.hostname[0]) {
            if (filter.hostname[0] == '.') {
                const size_t fhostlen = strlen(filter.hostname);
                const size_t uhostlen = url.hostname ? strlen(url.hostname) : 0;

                if (fhostlen > uhostlen || strcasecmp(filter.hostname,
                        url.hostname + uhostlen - fhostlen)) {
                    return 0;
                }
            }
            else if (filter.hostname[0] == '*') {
                const size_t fhostlen = strlen(filter.hostname + 1);
                const size_t uhostlen = url.hostname ? strlen(url.hostname) : 0;

                if (fhostlen > uhostlen || strcasecmp(filter.hostname + 1,
                        url.hostname + uhostlen - fhostlen)) {
                    return 0;
                }
            }
            else if (!url.hostname || strcasecmp(filter.hostname, url.hostname)) {
                return 0;
            }
        }

        /* If the filter port is empty it matches any URL port.
         * If the filter or URL port are missing, or the URL port is
         * empty, they default to the port for their scheme. */

        if (!(filter.port_str && !filter.port_str[0])) {
            /* NOTE:  ap_port_of_scheme will return 0 if given NULL input */
            const unsigned fport = filter.port_str ? filter.port
                    : apr_uri_port_of_scheme(filter.scheme);
            const unsigned uport = (url.port_str && url.port_str[0])
                    ? url.port : apr_uri_port_of_scheme(url.scheme);

            if (fport != uport) {
                return 0;
            }
        }
    }

    /* For HTTP caching purposes, an empty (NULL) path is equivalent to
     * a single "/" path. RFCs 3986/2396
     */
    if (!url.path) {
        if (*filter.path == '/' && pathlen == 1) {
            return 1;
        }
        else {
            return 0;
        }
    }

    /* Url has met all of the filter conditions so far, determine
     * if the paths match.
     */
    return !strncmp(filter.path, url.path, pathlen);
}

CACHE_DECLARE(cache_provider_list *)ap_cache_get_providers(request_rec *r,
                                                  cache_server_conf *conf,
                                                  apr_uri_t uri)
{
    cache_provider_list *providers = NULL;
    int i;

    /* loop through all the cacheenable entries */
    for (i = 0; i < conf->cacheenable->nelts; i++) {
        struct cache_enable *ent =
                                (struct cache_enable *)conf->cacheenable->elts;
        if (uri_meets_conditions(ent[i].url, ent[i].pathlen, uri)) {
            /* Fetch from global config and add to the list. */
            cache_provider *provider;
            provider = ap_lookup_provider(CACHE_PROVIDER_GROUP, ent[i].type,
                                          "0");
            if (!provider) {
                /* Log an error! */
            }
            else {
                cache_provider_list *newp;
                newp = apr_pcalloc(r->pool, sizeof(cache_provider_list));
                newp->provider_name = ent[i].type;
                newp->provider = provider;

                if (!providers) {
                    providers = newp;
                }
                else {
                    cache_provider_list *last = providers;

                    while (last->next) {
                        last = last->next;
                    }
                    last->next = newp;
                }
            }
        }
    }

    /* then loop through all the cachedisable entries
     * Looking for urls that contain the full cachedisable url and possibly
     * more.
     * This means we are disabling cachedisable url and below...
     */
    for (i = 0; i < conf->cachedisable->nelts; i++) {
        struct cache_disable *ent =
                               (struct cache_disable *)conf->cachedisable->elts;
        if (uri_meets_conditions(ent[i].url, ent[i].pathlen, uri)) {
            /* Stop searching now. */
            return NULL;
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

    return apr_time_sec(current_age);
}

/**
 * Try obtain a cache wide lock on the given cache key.
 *
 * If we return APR_SUCCESS, we obtained the lock, and we are clear to
 * proceed to the backend. If we return APR_EEXISTS, then the lock is
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
CACHE_DECLARE(apr_status_t) ap_cache_try_lock(cache_server_conf *conf,
        request_rec *r, char *key) {
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
    if (!key) {
        cache_generate_key(r, r->pool, &key);
    }

    /* create a hashed filename from the key, and save it for later */
    lockname = ap_cache_generate_name(r->pool, 0, 0, key);

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
        ap_log_error(APLOG_MARK, APLOG_ERR, status, r->server,
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
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EEXIST, r->server,
                     "Could not stat a cache lock file: %s",
                     lockname);
        return status;
    }
    if ((status == APR_SUCCESS) && (((now - finfo.mtime) > conf->lockmaxage)
                                  || (now < finfo.mtime))) {
        ap_log_error(APLOG_MARK, APLOG_INFO, status, r->server,
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
CACHE_DECLARE(apr_status_t) ap_cache_remove_lock(cache_server_conf *conf,
        request_rec *r, char *key, apr_bucket_brigade *bb) {
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
        if (!key) {
            cache_generate_key(r, r->pool, &key);
        }

        /* create a hashed filename from the key, and save it for later */
        lockname = ap_cache_generate_name(r->pool, 0, 0, key);

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

CACHE_DECLARE(int) ap_cache_check_freshness(cache_handle_t *h,
                                            request_rec *r)
{
    apr_status_t status;
    apr_int64_t age, maxage_req, maxage_cresp, maxage, smaxage, maxstale;
    apr_int64_t minfresh;
    const char *cc_cresp, *cc_req;
    const char *pragma;
    const char *agestr = NULL;
    const char *expstr = NULL;
    char *val;
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
     * - RFC2616 14.9.4 End to end reload, Cache-Control: no-cache. no-cache in
     * either the request or the cached response means that we must
     * revalidate the request unconditionally, overriding any expiration
     * mechanism. It's equivalent to max-age=0,must-revalidate.
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

    if (ap_cache_liststr(NULL, pragma, "no-cache", NULL)
        || ap_cache_liststr(NULL, cc_req, "no-cache", NULL)) {

        if (!conf->ignorecachecontrol) {
            /* Treat as stale, causing revalidation */
            return 0;
        }

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "Incoming request is asking for a uncached version of "
                     "%s, but we know better and are ignoring it",
                     r->unparsed_uri);
    }

    /* These come from the cached entity. */
    cc_cresp = apr_table_get(h->resp_hdrs, "Cache-Control");
    expstr = apr_table_get(h->resp_hdrs, "Expires");

    if (ap_cache_liststr(NULL, cc_cresp, "no-cache", NULL)) {
        /*
         * The cached entity contained Cache-Control: no-cache, so treat as
         * stale causing revalidation
         */
        return 0;
    }

    if ((agestr = apr_table_get(h->resp_hdrs, "Age"))) {
        age_c = apr_atoi64(agestr);
    }

    /* calculate age of object */
    age = ap_cache_current_age(info, age_c, r->request_time);

    /* extract s-maxage */
    if (cc_cresp && ap_cache_liststr(r->pool, cc_cresp, "s-maxage", &val)
        && val != NULL) {
        smaxage = apr_atoi64(val);
    }
    else {
        smaxage = -1;
    }

    /* extract max-age from request */
    if (!conf->ignorecachecontrol
        && cc_req && ap_cache_liststr(r->pool, cc_req, "max-age", &val)
        && val != NULL) {
        maxage_req = apr_atoi64(val);
    }
    else {
        maxage_req = -1;
    }

    /* extract max-age from response */
    if (cc_cresp && ap_cache_liststr(r->pool, cc_cresp, "max-age", &val)
        && val != NULL) {
        maxage_cresp = apr_atoi64(val);
    }
    else {
        maxage_cresp = -1;
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
    if (cc_req && ap_cache_liststr(r->pool, cc_req, "max-stale", &val)) {
        if(val != NULL) {
            maxstale = apr_atoi64(val);
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
    if (!conf->ignorecachecontrol
        && cc_req && ap_cache_liststr(r->pool, cc_req, "min-fresh", &val)
        && val != NULL) {
        minfresh = apr_atoi64(val);
    }
    else {
        minfresh = 0;
    }

    /* override maxstale if must-revalidate or proxy-revalidate */
    if (maxstale && ((cc_cresp &&
                      ap_cache_liststr(NULL, cc_cresp,
                                       "must-revalidate", NULL)) ||
                     (cc_cresp &&
                      ap_cache_liststr(NULL, cc_cresp,
                                       "proxy-revalidate", NULL)))) {
        maxstale = 0;
    }

    /* handle expiration */
    if (((smaxage != -1) && (age < (smaxage - minfresh))) ||
        ((maxage != -1) && (age < (maxage + maxstale - minfresh))) ||
        ((smaxage == -1) && (maxage == -1) &&
         (info->expire != APR_DATE_BAD) &&
         (age < (apr_time_sec(info->expire - info->date) + maxstale - minfresh)))) {

        warn_head = apr_table_get(h->resp_hdrs, "Warning");

        /* it's fresh darlings... */
        /* set age header on response */
        apr_table_set(h->resp_hdrs, "Age",
                      apr_psprintf(r->pool, "%lu", (unsigned long)age));

        /* add warning if maxstale overrode freshness calculation */
        if (!(((smaxage != -1) && age < smaxage) ||
              ((maxage != -1) && age < maxage) ||
              (info->expire != APR_DATE_BAD &&
               (apr_time_sec(info->expire - info->date)) > age))) {
            /* make sure we don't stomp on a previous warning */
            if ((warn_head == NULL) ||
                ((warn_head != NULL) && (ap_strstr_c(warn_head, "110") == NULL))) {
                apr_table_merge(h->resp_hdrs, "Warning",
                                "110 Response is stale");
            }
        }
        /*
         * If none of Expires, Cache-Control: max-age, or Cache-Control:
         * s-maxage appears in the response, and the response header age
         * calculated is more than 24 hours add the warning 113
         */
        if ((maxage_cresp == -1) && (smaxage == -1) &&
            (expstr == NULL) && (age > 86400)) {

            /* Make sure we don't stomp on a previous warning, and don't dup
             * a 113 marning that is already present. Also, make sure to add
             * the new warning to the correct *headers_out location.
             */
            if ((warn_head == NULL) ||
                ((warn_head != NULL) && (ap_strstr_c(warn_head, "113") == NULL))) {
                apr_table_merge(h->resp_hdrs, "Warning",
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
    status = ap_cache_try_lock(conf, r, (char *)h->cache_obj->key);
    if (APR_SUCCESS == status) {
        /* we obtained a lock, follow the stale path */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "Cache lock obtained for stale cached URL, "
                     "revalidating entry: %s",
                     r->unparsed_uri);
        return 0;
    }
    else if (APR_EEXIST == status) {
        /* lock already exists, return stale data anyway, with a warning */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "Cache already locked for stale cached URL, "
                     "pretend it is fresh: %s",
                     r->unparsed_uri);

        /* make sure we don't stomp on a previous warning */
        warn_head = apr_table_get(h->resp_hdrs, "Warning");
        if ((warn_head == NULL) ||
            ((warn_head != NULL) && (ap_strstr_c(warn_head, "110") == NULL))) {
            apr_table_merge(h->resp_hdrs, "Warning",
                        "110 Response is stale");
        }

        return 1;
    }
    else {
        /* some other error occurred, just treat the object as stale */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, status, r->server,
                     "Attempt to obtain a cache lock for stale "
                     "cached URL failed, revalidating entry anyway: %s",
                     r->unparsed_uri);
        return 0;
    }

}

/*
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
CACHE_DECLARE(int) ap_cache_liststr(apr_pool_t *p, const char *list,
                                    const char *key, char **val)
{
    apr_size_t key_len;
    const char *next;

    if (!list) {
        return 0;
    }

    key_len = strlen(key);
    next = list;

    for (;;) {

        /* skip whitespace and commas to find the start of the next key */
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            next++;
        }

        if (!*next) {
            return 0;
        }

        if (!strncasecmp(next, key, key_len)) {
            /* this field matches the key (though it might just be
             * a prefix match, so make sure the match is followed
             * by either a space or an equals sign)
             */
            next += key_len;
            if (!*next || (*next == '=') || apr_isspace(*next) ||
                (*next == ',')) {
                /* valid match */
                if (val) {
                    while (*next && (*next != '=') && (*next != ',')) {
                        next++;
                    }
                    if (*next == '=') {
                        next++;
                        while (*next && apr_isspace(*next )) {
                            next++;
                        }
                        if (!*next) {
                            *val = NULL;
                        }
                        else {
                            const char *val_start = next;
                            while (*next && !apr_isspace(*next) &&
                                   (*next != ',')) {
                                next++;
                            }
                            *val = apr_pstrmemdup(p, val_start,
                                                  next - val_start);
                        }
                    }
                    else {
                        *val = NULL;
                    }
                }
                return 1;
            }
        }

        /* skip to the next field */
        do {
            next++;
            if (!*next) {
                return 0;
            }
        } while (*next != ',');
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
        return apr_pstrndup(p, list, i);
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
 * Legacy call - functionally equivalent to ap_cache_cacheable_headers.
 * @deprecated @see ap_cache_cacheable_headers
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_hdrs_out(apr_pool_t *p,
                                                        apr_table_t *t,
                                                        server_rec *s)
{
    return ap_cache_cacheable_headers(p,t,s);
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

    headers_out = apr_table_overlay(r->pool, r->headers_out,
                                        r->err_headers_out);

    apr_table_clear(r->err_headers_out);

    headers_out = ap_cache_cacheable_headers(r->pool, headers_out,
                                                  r->server);

    if (!apr_table_get(headers_out, "Content-Type")
        && r->content_type) {
        apr_table_setn(headers_out, "Content-Type",
                       ap_make_content_type(r, r->content_type));
    }

    if (!apr_table_get(headers_out, "Content-Encoding")
        && r->content_encoding) {
        apr_table_setn(headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    return headers_out;
}
