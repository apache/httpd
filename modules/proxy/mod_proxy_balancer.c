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

/* Load balancer module for Apache proxy */

#include "mod_proxy.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "apr_hooks.h"
#include "apr_date.h"

static const char *balancer_mutex_type = "proxy-balancer-shm";
ap_slotmem_provider_t *storage = NULL;

module AP_MODULE_DECLARE_DATA proxy_balancer_module;

/*
 * Register our mutex type before the config is read so we
 * can adjust the mutex settings using the Mutex directive.
 */
static int balancer_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp)
{

    apr_status_t rv;

    rv = ap_mutex_register(pconf, balancer_mutex_type, NULL,
                               APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return OK;
}

#if 0
extern void proxy_update_members(proxy_balancer **balancer, request_rec *r,
                                 proxy_server_conf *conf);
#endif

static int proxy_balancer_canon(request_rec *r, char *url)
{
    char *host, *path;
    char *search = NULL;
    const char *err;
    apr_port_t port = 0;

    /* TODO: offset of BALANCER_PREFIX ?? */
    if (strncasecmp(url, "balancer:", 9) == 0) {
        url += 9;
    }
    else {
        return DECLINED;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, r->server,
             "proxy: BALANCER: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }
    /*
     * now parse path/search args, according to rfc1738:
     * process the path. With proxy-noncanon set (by
     * mod_proxy) we use the raw, unparsed uri
     */
    if (apr_table_get(r->notes, "proxy-nocanon")) {
        path = url;   /* this is the raw path */
    }
    else {
        path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0,
                                 r->proxyreq);
        search = r->args;
    }
    if (path == NULL)
        return HTTP_BAD_REQUEST;

    r->filename = apr_pstrcat(r->pool, "proxy:", BALANCER_PREFIX, host,
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);

    r->path_info = apr_pstrcat(r->pool, "/", path, NULL);

    return OK;
}

static void init_balancer_members(proxy_server_conf *conf, server_rec *s,
                                 proxy_balancer *balancer)
{
    int i;
    proxy_worker **workers;

    workers = (proxy_worker **)balancer->workers->elts;

    for (i = 0; i < balancer->workers->nelts; i++) {
        int worker_is_initialized;
        proxy_worker *worker = *workers;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "Looking at %s -> %s initialized?", balancer->name, worker->s->name);
        worker_is_initialized = PROXY_WORKER_IS_INITIALIZED(worker);
        if (!worker_is_initialized) {
            ap_proxy_initialize_worker(worker, s, conf->pool);
        }
        ++workers;
    }

    /* Set default number of attempts to the number of
     * workers.
     */
    if (!balancer->s->max_attempts_set && balancer->workers->nelts > 1) {
        balancer->s->max_attempts = balancer->workers->nelts - 1;
        balancer->s->max_attempts_set = 1;
    }
}

/* Retrieve the parameter with the given name
 * Something like 'JSESSIONID=12345...N'
 */
static char *get_path_param(apr_pool_t *pool, char *url,
                            const char *name, int scolon_sep)
{
    char *path = NULL;
    char *pathdelims = "?&";

    if (scolon_sep) {
        pathdelims = ";?&";
    }
    for (path = strstr(url, name); path; path = strstr(path + 1, name)) {
        path += strlen(name);
        if (*path == '=') {
            /*
             * Session path was found, get it's value
             */
            ++path;
            if (*path) {
                char *q;
                path = apr_strtok(apr_pstrdup(pool, path), pathdelims, &q);
                return path;
            }
        }
    }
    return NULL;
}

static char *get_cookie_param(request_rec *r, const char *name)
{
    const char *cookies;
    const char *start_cookie;

    if ((cookies = apr_table_get(r->headers_in, "Cookie"))) {
        for (start_cookie = ap_strstr_c(cookies, name); start_cookie;
             start_cookie = ap_strstr_c(start_cookie + 1, name)) {
            if (start_cookie == cookies ||
                start_cookie[-1] == ';' ||
                start_cookie[-1] == ',' ||
                isspace(start_cookie[-1])) {

                start_cookie += strlen(name);
                while(*start_cookie && isspace(*start_cookie))
                    ++start_cookie;
                if (*start_cookie++ == '=' && *start_cookie) {
                    /*
                     * Session cookie was found, get it's value
                     */
                    char *end_cookie, *cookie;
                    cookie = apr_pstrdup(r->pool, start_cookie);
                    if ((end_cookie = strchr(cookie, ';')) != NULL)
                        *end_cookie = '\0';
                    if((end_cookie = strchr(cookie, ',')) != NULL)
                        *end_cookie = '\0';
                    return cookie;
                }
            }
        }
    }
    return NULL;
}

/* Find the worker that has the 'route' defined
 */
static proxy_worker *find_route_worker(proxy_balancer *balancer,
                                       const char *route, request_rec *r)
{
    int i;
    int checking_standby;
    int checked_standby;

    proxy_worker **workers;

    checking_standby = checked_standby = 0;
    while (!checked_standby) {
        workers = (proxy_worker **)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++, workers++) {
            proxy_worker *worker = *workers;
            if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(worker) : PROXY_WORKER_IS_STANDBY(worker)) )
                continue;
            if (*(worker->s->route) && strcmp(worker->s->route, route) == 0) {
                if (worker && PROXY_WORKER_IS_USABLE(worker)) {
                    return worker;
                } else {
                    /*
                     * If the worker is in error state run
                     * retry on that worker. It will be marked as
                     * operational if the retry timeout is elapsed.
                     * The worker might still be unusable, but we try
                     * anyway.
                     */
                    ap_proxy_retry_worker("BALANCER", worker, r->server);
                    if (PROXY_WORKER_IS_USABLE(worker)) {
                            return worker;
                    } else {
                        /*
                         * We have a worker that is unusable.
                         * It can be in error or disabled, but in case
                         * it has a redirection set use that redirection worker.
                         * This enables to safely remove the member from the
                         * balancer. Of course you will need some kind of
                         * session replication between those two remote.
                         */
                        if (*worker->s->redirect) {
                            proxy_worker *rworker = NULL;
                            rworker = find_route_worker(balancer, worker->s->redirect, r);
                            /* Check if the redirect worker is usable */
                            if (rworker && !PROXY_WORKER_IS_USABLE(rworker)) {
                                /*
                                 * If the worker is in error state run
                                 * retry on that worker. It will be marked as
                                 * operational if the retry timeout is elapsed.
                                 * The worker might still be unusable, but we try
                                 * anyway.
                                 */
                                ap_proxy_retry_worker("BALANCER", rworker, r->server);
                            }
                            if (rworker && PROXY_WORKER_IS_USABLE(rworker))
                                return rworker;
                        }
                    }
                }
            }
        }
        checked_standby = checking_standby++;
    }
    return NULL;
}

static proxy_worker *find_session_route(proxy_balancer *balancer,
                                        request_rec *r,
                                        char **route,
                                        const char **sticky_used,
                                        char **url)
{
    proxy_worker *worker = NULL;

    if (!*balancer->s->sticky)
        return NULL;
    /* Try to find the sticky route inside url */
    *route = get_path_param(r->pool, *url, balancer->s->sticky_path, balancer->s->scolonsep);
    if (*route) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: BALANCER: Found value %s for "
                     "stickysession %s", *route, balancer->s->sticky_path);
        *sticky_used =  balancer->s->sticky_path;
    }
    else {
        *route = get_cookie_param(r, balancer->s->sticky);
        if (*route) {
            *sticky_used =  balancer->s->sticky;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: BALANCER: Found value %s for "
                         "stickysession %s", *route, balancer->s->sticky);
        }
    }
    /*
     * If we found a value for sticksession, find the first '.' within.
     * Everything after '.' (if present) is our route.
     */
    if ((*route) && ((*route = strchr(*route, '.')) != NULL ))
        (*route)++;
    if ((*route) && (**route)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                  "proxy: BALANCER: Found route %s", *route);
        /* We have a route in path or in cookie
         * Find the worker that has this route defined.
         */
        worker = find_route_worker(balancer, *route, r);
        if (worker && strcmp(*route, worker->s->route)) {
            /*
             * Notice that the route of the worker chosen is different from
             * the route supplied by the client.
             */
            apr_table_setn(r->subprocess_env, "BALANCER_ROUTE_CHANGED", "1");
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "proxy: BALANCER: Route changed from %s to %s",
                         *route, worker->s->route);
        }
        return worker;
    }
    else
        return NULL;
}

static proxy_worker *find_best_worker(proxy_balancer *balancer,
                                      request_rec *r)
{
    proxy_worker *candidate = NULL;
    apr_status_t rv;

    if ((rv = PROXY_GLOBAL_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
        "proxy: BALANCER: (%s). Lock failed for find_best_worker()", balancer->name);
        return NULL;
    }

    candidate = (*balancer->s->lbmethod->finder)(balancer, r);

    if (candidate)
        candidate->s->elected++;

/*
        PROXY_GLOBAL_UNLOCK(conf);
        return NULL;
*/

    if ((rv = PROXY_GLOBAL_UNLOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
        "proxy: BALANCER: (%s). Unlock failed for find_best_worker()", balancer->name);
    }

    if (candidate == NULL) {
        /* All the workers are in error state or disabled.
         * If the balancer has a timeout sleep for a while
         * and try again to find the worker. The chances are
         * that some other thread will release a connection.
         * By default the timeout is not set, and the server
         * returns SERVER_BUSY.
         */
        if (balancer->s->timeout) {
            /* XXX: This can perhaps be build using some
             * smarter mechanism, like tread_cond.
             * But since the statuses can came from
             * different childs, use the provided algo.
             */
            apr_interval_time_t timeout = balancer->s->timeout;
            apr_interval_time_t step, tval = 0;
            /* Set the timeout to 0 so that we don't
             * end in infinite loop
             */
            balancer->s->timeout = 0;
            step = timeout / 100;
            while (tval < timeout) {
                apr_sleep(step);
                /* Try again */
                if ((candidate = find_best_worker(balancer, r)))
                    break;
                tval += step;
            }
            /* restore the timeout */
            balancer->s->timeout = timeout;
        }
    }

    return candidate;

}

static int rewrite_url(request_rec *r, proxy_worker *worker,
                        char **url)
{
    const char *scheme = strstr(*url, "://");
    const char *path = NULL;

    if (scheme)
        path = ap_strchr_c(scheme + 3, '/');

    /* we break the URL into host, port, uri */
    if (!worker) {
        return ap_proxyerror(r, HTTP_BAD_REQUEST, apr_pstrcat(r->pool,
                             "missing worker. URI cannot be parsed: ", *url,
                             NULL));
    }

    *url = apr_pstrcat(r->pool, worker->s->name, path, NULL);

    return OK;
}

static void force_recovery(proxy_balancer *balancer, server_rec *s)
{
    int i;
    int ok = 0;
    proxy_worker **worker;

    worker = (proxy_worker **)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++, worker++) {
        if (!((*worker)->s->status & PROXY_WORKER_IN_ERROR)) {
            ok = 1;
            break;
        }
        else {
            /* Try if we can recover */
            ap_proxy_retry_worker("BALANCER", *worker, s);
            if (!((*worker)->s->status & PROXY_WORKER_IN_ERROR)) {
                ok = 1;
                break;
            }
        }
    }
    if (!ok) {
        /* If all workers are in error state force the recovery.
         */
        worker = (proxy_worker **)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++, worker++) {
            ++(*worker)->s->retries;
            (*worker)->s->status &= ~PROXY_WORKER_IN_ERROR;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "proxy: BALANCER: (%s). Forcing recovery for worker (%s)",
                         balancer->name, (*worker)->s->hostname);
        }
    }
}

static int proxy_balancer_pre_request(proxy_worker **worker,
                                      proxy_balancer **balancer,
                                      request_rec *r,
                                      proxy_server_conf *conf, char **url)
{
    int access_status;
    proxy_worker *runtime;
    char *route = NULL;
    const char *sticky = NULL;
    apr_status_t rv;

    *worker = NULL;
    /* Step 1: check if the url is for us
     * The url we can handle starts with 'balancer://'
     * If balancer is already provided skip the search
     * for balancer, because this is failover attempt.
     */
    if (!*balancer &&
        !(*balancer = ap_proxy_get_balancer(r->pool, conf, *url)))
        return DECLINED;

    /* Step 2: Lock the LoadBalancer
     * XXX: perhaps we need the process lock here
     */
    if ((rv = PROXY_GLOBAL_LOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: BALANCER: (%s). Lock failed for pre_request",
                     (*balancer)->name);
        return DECLINED;
    }

    /* Step 3: force recovery */
    force_recovery(*balancer, r->server);

    /* Step 3.5: Update member list for the balancer */
    /* TODO: Implement as provider! */
    /* proxy_update_members(balancer, r, conf); */

    /* Step 4: find the session route */
    runtime = find_session_route(*balancer, r, &route, &sticky, url);
    if (runtime) {
        if ((*balancer)->s->lbmethod && (*balancer)->s->lbmethod->updatelbstatus) {
            /* Call the LB implementation */
            (*balancer)->s->lbmethod->updatelbstatus(*balancer, runtime, r->server);
        }
        else { /* Use the default one */
            int i, total_factor = 0;
            proxy_worker **workers;
            /* We have a sticky load balancer
             * Update the workers status
             * so that even session routes get
             * into account.
             */
            workers = (proxy_worker **)(*balancer)->workers->elts;
            for (i = 0; i < (*balancer)->workers->nelts; i++) {
                /* Take into calculation only the workers that are
                 * not in error state or not disabled.
                 */
                if (PROXY_WORKER_IS_USABLE(*workers)) {
                    (*workers)->s->lbstatus += (*workers)->s->lbfactor;
                    total_factor += (*workers)->s->lbfactor;
                }
                workers++;
            }
            runtime->s->lbstatus -= total_factor;
        }
        runtime->s->elected++;

        *worker = runtime;
    }
    else if (route && (*balancer)->s->sticky_force) {
        int i, member_of = 0;
        proxy_worker **workers;
        /*
         * We have a route provided that doesn't match the
         * balancer name. See if the provider route is the
         * member of the same balancer in which case return 503
         */
        workers = (proxy_worker **)(*balancer)->workers->elts;
        for (i = 0; i < (*balancer)->workers->nelts; i++) {
            if (*((*workers)->s->route) && strcmp((*workers)->s->route, route) == 0) {
                member_of = 1;
                break;
            }
            workers++;
        }
        if (member_of) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: BALANCER: (%s). All workers are in error state for route (%s)",
                         (*balancer)->name, route);
            if ((rv = PROXY_GLOBAL_UNLOCK(*balancer)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                             "proxy: BALANCER: (%s). Unlock failed for pre_request",
                             (*balancer)->name);
            }
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }

    if ((rv = PROXY_GLOBAL_UNLOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: BALANCER: (%s). Unlock failed for pre_request",
                     (*balancer)->name);
    }
    if (!*worker) {
        runtime = find_best_worker(*balancer, r);
        if (!runtime) {
            if ((*balancer)->workers->nelts) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                            "proxy: BALANCER: (%s). All workers are in error state",
                            (*balancer)->name);
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                            "proxy: BALANCER: (%s). No workers in balancer",
                            (*balancer)->name);
            }

            return HTTP_SERVICE_UNAVAILABLE;
        }
        if (*(*balancer)->s->sticky && runtime) {
            /*
             * This balancer has sticky sessions and the client either has not
             * supplied any routing information or all workers for this route
             * including possible redirect and hotstandby workers are in error
             * state, but we have found another working worker for this
             * balancer where we can send the request. Thus notice that we have
             * changed the route to the backend.
             */
            apr_table_setn(r->subprocess_env, "BALANCER_ROUTE_CHANGED", "1");
        }
        *worker = runtime;
    }

    (*worker)->s->busy++;

    /* Add balancer/worker info to env. */
    apr_table_setn(r->subprocess_env,
                   "BALANCER_NAME", (*balancer)->name);
    apr_table_setn(r->subprocess_env,
                   "BALANCER_WORKER_NAME", (*worker)->s->name);
    apr_table_setn(r->subprocess_env,
                   "BALANCER_WORKER_ROUTE", (*worker)->s->route);

    /* Rewrite the url from 'balancer://url'
     * to the 'worker_scheme://worker_hostname[:worker_port]/url'
     * This replaces the balancers fictional name with the
     * real hostname of the elected worker.
     */
    access_status = rewrite_url(r, *worker, url);
    /* Add the session route to request notes if present */
    if (route) {
        apr_table_setn(r->notes, "session-sticky", sticky);
        apr_table_setn(r->notes, "session-route", route);

        /* Add session info to env. */
        apr_table_setn(r->subprocess_env,
                       "BALANCER_SESSION_STICKY", sticky);
        apr_table_setn(r->subprocess_env,
                       "BALANCER_SESSION_ROUTE", route);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: BALANCER (%s) worker (%s) rewritten to %s",
                 (*balancer)->name, (*worker)->s->name, *url);

    return access_status;
}

static int proxy_balancer_post_request(proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf)
{

    apr_status_t rv;

    if ((rv = PROXY_GLOBAL_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "proxy: BALANCER: (%s). Lock failed for post_request",
            balancer->name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!apr_is_empty_array(balancer->errstatuses)) {
        int i;
        for (i = 0; i < balancer->errstatuses->nelts; i++) {
            int val = ((int *)balancer->errstatuses->elts)[i];
            if (r->status == val) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                             "proxy: BALANCER: (%s).  Forcing recovery for worker (%s), failonstatus %d",
                             balancer->name, worker->s->name, val);
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
                break;
            }
        }
    }

    if ((rv = PROXY_GLOBAL_UNLOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "proxy: BALANCER: (%s). Unlock failed for post_request",
            balancer->name);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy_balancer_post_request for (%s)", balancer->name);

    if (worker && worker->s->busy)
        worker->s->busy--;

    return OK;

}

static void recalc_factors(proxy_balancer *balancer)
{
    int i;
    proxy_worker **workers;


    /* Recalculate lbfactors */
    workers = (proxy_worker **)balancer->workers->elts;
    /* Special case if there is only one worker it's
     * load factor will always be 1
     */
    if (balancer->workers->nelts == 1) {
        (*workers)->s->lbstatus = (*workers)->s->lbfactor = 1;
        return;
    }
    for (i = 0; i < balancer->workers->nelts; i++) {
        /* Update the status entries */
        workers[i]->s->lbstatus = workers[i]->s->lbfactor;
    }
}

static apr_status_t lock_remove(void *data)
{
    int i;
    proxy_balancer *balancer;
    server_rec *s = data;
    void *sconf = s->module_config;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    balancer = (proxy_balancer *)conf->balancers->elts;
    for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
        if (balancer->mutex) {
            apr_global_mutex_destroy(balancer->mutex);
            balancer->mutex = NULL;
        }
    }
    return(0);
}

/* post_config hook: */
static int balancer_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                         apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    void *data;
    void *sconf = s->module_config;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    const char *userdata_key = "mod_proxy_balancer_init";
    ap_slotmem_instance_t *new = NULL;
    apr_time_t tstamp;

    /* balancer_post_config() will be called twice during startup.  So, only
     * set up the static data the 1st time through. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /*
     * Get slotmem setups
     */
    storage = ap_lookup_provider(AP_SLOTMEM_PROVIDER_GROUP, "shared", "0");
    if (!storage) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, s,
                     "ap_lookup_provider %s failed", AP_SLOTMEM_PROVIDER_GROUP);
        return !OK;
    }

    tstamp = apr_time_now();
    /*
     * Go thru each Vhost and create the shared mem slotmem for
     * each balancer's workers
     */
    while (s) {
        int i,j;
        proxy_balancer *balancer;
        sconf = s->module_config;
        conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);

        if (conf->balancers->nelts) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Doing balancers create: %d, %d",
                         (int)ALIGNED_PROXY_BALANCER_SHARED_SIZE,
                         (int)conf->balancers->nelts);
            
            rv = storage->create(&new, conf->id,
                                 ALIGNED_PROXY_BALANCER_SHARED_SIZE,
                                 conf->balancers->nelts, AP_SLOTMEM_TYPE_PREGRAB, pconf);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "balancer slotmem_create failed");
                return !OK;
            }
            conf->slot = new;
        }

        /* Initialize shared scoreboard data */
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
            proxy_worker **workers;
            proxy_worker *worker;
            proxy_balancer_shared *bshm;
            unsigned int index;

            balancer->max_workers = balancer->workers->nelts + balancer->growth;
            /* no need for the 'balancer://' prefix */
            ap_pstr2_alnum(pconf, balancer->name + sizeof(BALANCER_PREFIX) - 1, 
                           &balancer->sname);
            balancer->sname = apr_pstrcat(pconf, conf->id, "_", balancer->sname, NULL);

            /* Create global mutex */
            rv = ap_global_mutex_create(&(balancer->mutex), NULL, balancer_mutex_type,
                                        balancer->sname, s, pconf, 0);
            if (rv != APR_SUCCESS || !balancer->mutex) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                             "mutex creation of %s : %s failed", balancer_mutex_type,
                             balancer->sname);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            apr_pool_cleanup_register(pconf, (void *)s, lock_remove,
                                      apr_pool_cleanup_null);

            /* setup shm for balancers */
            if ((rv = storage->grab(conf->slot, &index)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "balancer slotmem_grab failed");
                return !OK;
                
            }
            if ((rv = storage->dptr(conf->slot, index, (void *)&bshm)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "balancer slotmem_dptr failed");
                return !OK;
            }
            if ((rv = ap_proxy_share_balancer(balancer, bshm, index)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "Cannot share balancer");
                return !OK;
            }
            
            /* create slotmem slots for workers */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Doing workers create: %s (%s), %d, %d",
                         balancer->name, balancer->sname,
                         (int)ALIGNED_PROXY_WORKER_SHARED_SIZE,
                         (int)balancer->max_workers);

            rv = storage->create(&new, balancer->sname,
                                 ALIGNED_PROXY_WORKER_SHARED_SIZE,
                                 balancer->max_workers, AP_SLOTMEM_TYPE_PREGRAB, pconf);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "worker slotmem_create failed");
                return !OK;
            }
            balancer->slot = new;

            /* sync all timestamps */
            balancer->wupdated = balancer->s->wupdated = tstamp;

            /* now go thru each worker */
            workers = (proxy_worker **)balancer->workers->elts;
            for (j = 0; j < balancer->workers->nelts; j++, workers++) {
                proxy_worker_shared *shm;

                worker = *workers;
                if ((rv = storage->grab(balancer->slot, &index)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "worker slotmem_grab failed");
                    return !OK;

                }
                if ((rv = storage->dptr(balancer->slot, index, (void *)&shm)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "worker slotmem_dptr failed");
                    return !OK;
                }
                if ((rv = ap_proxy_share_worker(worker, shm, index)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, "Cannot share worker");
                    return !OK;
                }
                worker->s->updated = tstamp;
            }
        }
        s = s->next;
    }

    return OK;
}

static void create_radio(const char *name, unsigned int flag, request_rec *r)
{
    ap_rvputs(r, "<td>On <input name='", name, "' id='", name, "' value='1' type=radio", NULL);
    if (flag)
        ap_rputs(" checked", r);
    ap_rvputs(r, "> <br/> Off <input name='", name, "' id='", name, "' value='0' type=radio", NULL);
    if (!flag)
        ap_rputs(" checked", r);
    ap_rputs("></td>\n", r);
}

/* Manages the loadfactors and member status
 */
static int balancer_handler(request_rec *r)
{
    void *sconf;
    proxy_server_conf *conf;
    proxy_balancer *balancer, *bsel = NULL;
    proxy_worker *worker, *wsel = NULL;
    proxy_worker **workers = NULL;
    apr_table_t *params;
    int access_status;
    int i, n;
    int ok2change = 1;
    const char *name;

    /* is this for us? */
    if (strcmp(r->handler, "balancer-manager")) {
        return DECLINED;
    }

    r->allowed = (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    sconf = r->server->module_config;
    conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    params = apr_table_make(r->pool, 10);

    if (r->args) {
        char *args = apr_pstrdup(r->pool, r->args);
        char *tok, *val;
        while (args && *args) {
            if ((val = ap_strchr(args, '='))) {
                *val++ = '\0';
                if ((tok = ap_strchr(val, '&')))
                    *tok++ = '\0';
                /*
                 * Special case: workers are allowed path information
                 */
                if ((access_status = ap_unescape_url(val)) != OK)
                    if (strcmp(args, "w") || (access_status !=  HTTP_NOT_FOUND))
                        return access_status;
                apr_table_setn(params, args, val);
                args = tok;
            }
            else
                return HTTP_BAD_REQUEST;
        }
    }

    if ((name = apr_table_get(params, "b")))
        bsel = ap_proxy_get_balancer(r->pool, conf,
            apr_pstrcat(r->pool, BALANCER_PREFIX, name, NULL));

    if ((name = apr_table_get(params, "w"))) {
        wsel = ap_proxy_get_worker(r->pool, bsel, conf, name);
    }


    /* Check that the supplied nonce matches this server's nonce;
     * otherwise ignore all parameters, to prevent a CSRF attack. */
    if (!bsel ||
        (*bsel->s->nonce &&
         (
          (name = apr_table_get(params, "nonce")) == NULL ||
          strcmp(bsel->s->nonce, name) != 0
         )
        )
       ) {
        apr_table_clear(params);
        ok2change = 0;
    }

    /* First set the params */
    if (wsel && ok2change) {
        const char *val;
        if ((val = apr_table_get(params, "w_lf"))) {
            int ival = atoi(val);
            if (ival >= 1 && ival <= 100) {
                wsel->s->lbfactor = ival;
                if (bsel)
                    recalc_factors(bsel);
            }
        }
        if ((val = apr_table_get(params, "w_wr"))) {
            if (strlen(val) && strlen(val) < sizeof(wsel->s->route))
                strcpy(wsel->s->route, val);
            else
                *wsel->s->route = '\0';
        }
        if ((val = apr_table_get(params, "w_rr"))) {
            if (strlen(val) && strlen(val) < sizeof(wsel->s->redirect))
                strcpy(wsel->s->redirect, val);
            else
                *wsel->s->redirect = '\0';
        }
        if ((val = apr_table_get(params, "w_status_I"))) {
            ap_proxy_set_wstatus('I', atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_N"))) {
            ap_proxy_set_wstatus('N', atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_D"))) {
            ap_proxy_set_wstatus('D', atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_H"))) {
            ap_proxy_set_wstatus('H', atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_ls"))) {
            int ival = atoi(val);
            if (ival >= 0 && ival <= 99) {
                wsel->s->lbset = ival;
             }
        }

    }

    if (bsel && ok2change) {
        const char *val;
        int ival;
        if ((val = apr_table_get(params, "b_lbm"))) {
            proxy_balancer_method *lbmethod;
            lbmethod = ap_lookup_provider(PROXY_LBMETHOD, val, "0");
            if (lbmethod)
                bsel->s->lbmethod = lbmethod;
        }
        if ((val = apr_table_get(params, "b_tmo"))) {
            ival = atoi(val);
            if (ival >= 0 && ival <= 7200) { /* 2 hrs enuff? */
                bsel->s->timeout = apr_time_from_sec(ival);
            }
        }
        if ((val = apr_table_get(params, "b_max"))) {
            ival = atoi(val);
            if (ival >= 0 && ival <= 99) {
                bsel->s->max_attempts = ival;
            }
        }
        if ((val = apr_table_get(params, "b_sforce"))) {
            ival = atoi(val);
            bsel->s->sticky_force = (ival != 0);
        }
    }

    if (apr_table_get(params, "xml")) {
        ap_set_content_type(r, "text/xml");
        ap_rputs("<?xml version='1.0' encoding='UTF-8' ?>\n", r);
        ap_rputs("<httpd:manager xmlns:httpd='http://httpd.apache.org'>\n", r);
        ap_rputs("  <httpd:balancers>\n", r);
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {
            ap_rputs("    <httpd:balancer>\n", r);
            ap_rvputs(r, "      <httpd:name>", balancer->name, "</httpd:name>\n", NULL);
            ap_rputs("      <httpd:workers>\n", r);
            workers = (proxy_worker **)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                worker = *workers;
                ap_rputs("        <httpd:worker>\n", r);
                ap_rvputs(r, "          <httpd:scheme>", worker->s->scheme,
                          "</httpd:scheme>\n", NULL);
                ap_rvputs(r, "          <httpd:hostname>", worker->s->hostname,
                          "</httpd:hostname>\n", NULL);
                ap_rprintf(r, "          <httpd:loadfactor>%d</httpd:loadfactor>\n",
                          worker->s->lbfactor);
                ap_rputs("        </httpd:worker>\n", r);
                ++workers;
            }
            ap_rputs("      </httpd:workers>\n", r);
            ap_rputs("    </httpd:balancer>\n", r);
            ++balancer;
        }
        ap_rputs("  </httpd:balancers>\n", r);
        ap_rputs("</httpd:manager>", r);
    }
    else {
        ap_set_content_type(r, "text/html; charset=ISO-8859-1");
        ap_rputs(DOCTYPE_HTML_3_2
                 "<html><head><title>Balancer Manager</title></head>\n", r);
        ap_rputs("<body><h1>Load Balancer Manager for ", r);
        ap_rvputs(r, ap_get_server_name(r), "</h1>\n\n", NULL);
        ap_rvputs(r, "<dl><dt>Server Version: ",
                  ap_get_server_description(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server Built: ",
                  ap_get_server_built(), "\n</dt></dl>\n", NULL);
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {

            ap_rputs("<hr />\n<h3>LoadBalancer Status for ", r);
            ap_rvputs(r, "<a href='", r->uri, "?b=",
                      balancer->name + sizeof(BALANCER_PREFIX) - 1,
                      "&nonce=", balancer->s->nonce,
                      "'>", NULL);
            ap_rvputs(r, balancer->name, "</a></h3>\n\n", NULL);
            ap_rputs("\n\n<table border='0' style='text-align: left;'><tr>"
                "<th>MaxMembers</th><th>StickySession</th><th>DisableFailover</th><th>Timeout</th><th>FailoverAttempts</th><th>Method</th>"
                "</tr>\n<tr>", r);
            ap_rprintf(r, "<td align='center'>%d</td>\n", balancer->max_workers);
            if (*balancer->s->sticky) {
                if (strcmp(balancer->s->sticky, balancer->s->sticky_path)) {
                    ap_rvputs(r, "<td align='center'>", balancer->s->sticky, " | ",
                              balancer->s->sticky_path, NULL);
                }
                else {
                    ap_rvputs(r, "<td align='center'>", balancer->s->sticky, NULL);
                }
            }
            else {
                ap_rputs("<td align='center'> - ", r);
            }
            ap_rprintf(r, "<td align='center'>%s</td>\n",
                       balancer->s->sticky_force ? "On" : "Off");
            ap_rprintf(r, "</td><td align='center'>%" APR_TIME_T_FMT "</td>",
                apr_time_sec(balancer->s->timeout));
            ap_rprintf(r, "<td align='center'>%d</td>\n", balancer->s->max_attempts);
            ap_rprintf(r, "<td align='center'>%s</td>\n",
                       balancer->s->lbmethod->name);
            ap_rputs("</table>\n<br />", r);
            ap_rputs("\n\n<table border='0' style='text-align: left;'><tr>"
                "<th>Worker URL</th>"
                "<th>Route</th><th>RouteRedir</th>"
                "<th>Factor</th><th>Set</th><th align='center'>Status</th>"
                "<th>Elected</th><th>To</th><th>From</th>"
                "</tr>\n", r);

            workers = (proxy_worker **)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                char fbuf[50];
                worker = *workers;
                ap_rvputs(r, "<tr>\n<td><a href='", r->uri, "?b=",
                          balancer->name + sizeof(BALANCER_PREFIX) - 1, "&w=",
                          ap_escape_uri(r->pool, worker->s->name),
                          "&nonce=", balancer->s->nonce,
                          "'>", NULL);
                ap_rvputs(r, worker->s->name, "</a></td>", NULL);
                ap_rvputs(r, "<td align='center'>", ap_escape_html(r->pool, worker->s->route),
                          NULL);
                ap_rvputs(r, "</td><td align='center'>",
                          ap_escape_html(r->pool, worker->s->redirect), NULL);
                ap_rprintf(r, "</td><td align='center'>%d</td>", worker->s->lbfactor);
                ap_rprintf(r, "<td align='center'>%d</td><td align='center'>", worker->s->lbset);
                ap_rvputs(r, ap_proxy_parse_wstatus(r->pool, worker), NULL);
                ap_rputs("</td>", r);
                ap_rprintf(r, "<td align='center'>%" APR_SIZE_T_FMT "</td><td align='center'>", worker->s->elected);
                ap_rputs(apr_strfsize(worker->s->transferred, fbuf), r);
                ap_rputs("</td><td align='center'>", r);
                ap_rputs(apr_strfsize(worker->s->read, fbuf), r);
                ap_rputs("</td></tr>\n", r);

                ++workers;
            }
            ap_rputs("</table>\n", r);
            ++balancer;
        }
        ap_rputs("<hr />\n", r);
        if (wsel && bsel) {
            ap_rputs("<h3>Edit worker settings for ", r);
            ap_rvputs(r, wsel->s->name, "</h3>\n", NULL);
            ap_rvputs(r, "<form method='GET' action='", NULL);
            ap_rvputs(r, r->uri, "'>\n<dl>", NULL);
            ap_rputs("<table><tr><td>Load factor:</td><td><input name='w_lf' id='w_lf' type=text ", r);
            ap_rprintf(r, "value='%d'></td></tr>\n", wsel->s->lbfactor);
            ap_rputs("<tr><td>LB Set:</td><td><input name='w_ls' id='w_ls' type=text ", r);
            ap_rprintf(r, "value='%d'></td></tr>\n", wsel->s->lbset);
            ap_rputs("<tr><td>Route:</td><td><input name='w_wr' id='w_wr' type=text ", r);
            ap_rvputs(r, "value='", ap_escape_html(r->pool, wsel->s->route),
                      NULL);
            ap_rputs("'></td></tr>\n", r);
            ap_rputs("<tr><td>Route Redirect:</td><td><input name='w_rr' id='w_rr' type=text ", r);
            ap_rvputs(r, "value='", ap_escape_html(r->pool, wsel->s->redirect),
                      NULL);
            ap_rputs("'></td></tr>\n", r);
            ap_rputs("<tr><td>Status:</td>", r);
            ap_rputs("<td><table border='1'><tr><th>Ign</th><th>Drn</th><th>Dis</th><th>Stby</th></tr>\n<tr>", r);
            create_radio("w_status_I", (PROXY_WORKER_IGNORE_ERRORS & wsel->s->status), r);
            create_radio("w_status_N", (PROXY_WORKER_DRAIN & wsel->s->status), r);
            create_radio("w_status_D", (PROXY_WORKER_DISABLED & wsel->s->status), r);
            create_radio("w_status_H", (PROXY_WORKER_HOT_STANDBY & wsel->s->status), r);
            ap_rputs("</tr></table>\n", r);
            ap_rputs("<tr><td colspan=2><input type=submit value='Submit'></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name='w' id='w' ",  NULL);
            ap_rvputs(r, "value='", ap_escape_uri(r->pool, wsel->s->name), "'>\n", NULL);
            ap_rvputs(r, "<input type=hidden name='b' id='b' ", NULL);
            ap_rvputs(r, "value='", bsel->name + sizeof(BALANCER_PREFIX) - 1,
                      "'>\n", NULL);
            ap_rvputs(r, "<input type=hidden name='nonce' id='nonce' value='",
                      bsel->s->nonce, "'>\n", NULL);
            ap_rvputs(r, "</form>\n", NULL);
            ap_rputs("<hr />\n", r);
        } else if (bsel) {
            const apr_array_header_t *provs;
            const ap_list_provider_names_t *pname;
            int i;
            ap_rputs("<h3>Edit balancer settings for ", r);
            ap_rvputs(r, bsel->name, "</h3>\n", NULL);
            ap_rvputs(r, "<form method='GET' action='", NULL);
            ap_rvputs(r, r->uri, "'>\n<dl>\n<table>\n", NULL);
            provs = ap_list_provider_names(r->pool, PROXY_LBMETHOD, "0");
            if (provs) {
                ap_rputs("<tr><td>LBmethod:</td>", r);
                ap_rputs("<td>\n<select name='b_lbm' id='b_lbm'>", r);
                pname = (ap_list_provider_names_t *)provs->elts;
                for (i = 0; i < provs->nelts; i++, pname++) {
                    ap_rvputs(r,"<option value='", pname->provider_name, "'", NULL);
                    if (strcmp(pname->provider_name, bsel->s->lbmethod->name) == 0)
                        ap_rputs(" selected ", r);
                    ap_rvputs(r, ">", pname->provider_name, "\n", NULL);
                }
                ap_rputs("</select>\n</td></tr>\n", r);
            }
            ap_rputs("<tr><td>Timeout:</td><td><input name='b_tmo' id='b_tmo' type=text ", r);
            ap_rprintf(r, "value='%" APR_TIME_T_FMT "'></td></tr>\n", apr_time_sec(bsel->s->timeout));
            ap_rputs("<tr><td>Failover Attempts:</td><td><input name='b_max' id='b_max' type=text ", r);
            ap_rprintf(r, "value='%d'></td></tr>\n", bsel->s->max_attempts);
            ap_rputs("<tr><td>Disable Failover:</td>", r);
            create_radio("b_sforce", bsel->s->sticky_force, r);
            ap_rputs("<tr><td colspan=2><input type=submit value='Submit'></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name='b' id='b' ", NULL);
            ap_rvputs(r, "value='", bsel->name + sizeof(BALANCER_PREFIX) - 1,
                      "'>\n", NULL);
            ap_rvputs(r, "<input type=hidden name='nonce' id='nonce' value='",
                      bsel->s->nonce, "'>\n", NULL);
            ap_rvputs(r, "</form>\n", NULL);
            ap_rputs("<hr />\n", r);
        }
        ap_rputs(ap_psignature("",r), r);
        ap_rputs("</body></html>\n", r);
}
    return OK;
}

static void balancer_child_init(apr_pool_t *p, server_rec *s)
{
    while (s) {
        proxy_balancer *balancer;
        int i;
        void *sconf = s->module_config;
        proxy_server_conf *conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        apr_size_t size;
        unsigned int num;
        apr_status_t rv;

        if (conf->balancers->nelts) {
            storage->attach(&(conf->slot), conf->id, &size, &num, p);
            if (!conf->slot) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, s, "slotmem_attach failed");
                exit(1); /* Ugly, but what else? */
            }
        }
        
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {

            /*
             * for each balancer we need to init the global
             * mutex and then attach to the shared worker shm
             */
            if (!balancer->mutex) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                             "no mutex %s: %s", balancer->name,
                             balancer_mutex_type);
                return;
            }

            /* Re-open the mutex for the child. */
            rv = apr_global_mutex_child_init(&(balancer->mutex),
                                             apr_global_mutex_lockfile(balancer->mutex),
                                             p);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                             "Failed to reopen mutex %s: %s in child",
                             balancer->name, balancer_mutex_type);
                exit(1); /* Ugly, but what else? */
            }

            /* now attach */
            storage->attach(&(balancer->slot), balancer->sname, &size, &num, p);
            if (!balancer->slot) {
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, 0, s, "slotmem_attach failed");
                exit(1); /* Ugly, but what else? */
            }
            if (balancer->s->lbmethod && balancer->s->lbmethod->reset)
               balancer->s->lbmethod->reset(balancer, s);
            init_balancer_members(conf, s, balancer);
            balancer++;
        }
        s = s->next;
    }

}

static void ap_proxy_balancer_register_hook(apr_pool_t *p)
{
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes
     */
    static const char *const aszPred[] = { "mpm_winnt.c", "mod_slotmem_shm.c", NULL};
     /* manager handler */
    ap_hook_post_config(balancer_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(balancer_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(balancer_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init(balancer_child_init, aszPred, NULL, APR_HOOK_MIDDLE);
    proxy_hook_pre_request(proxy_balancer_pre_request, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_post_request(proxy_balancer_post_request, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_balancer_canon, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_balancer) = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    ap_proxy_balancer_register_hook /* register hooks */
};
