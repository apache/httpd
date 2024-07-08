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
#include "proxy_util.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "ap_hooks.h"
#include "apr_date.h"
#include "util_md5.h"
#include "mod_watchdog.h"

static const char *balancer_mutex_type = "proxy-balancer-shm";
ap_slotmem_provider_t *storage = NULL;

module AP_MODULE_DECLARE_DATA proxy_balancer_module;

static APR_OPTIONAL_FN_TYPE(set_worker_hc_param) *set_worker_hc_param_f = NULL;

static int (*ap_proxy_retry_worker_fn)(const char *proxy_function,
        proxy_worker *worker, server_rec *s) = NULL;

static APR_OPTIONAL_FN_TYPE(hc_show_exprs) *hc_show_exprs_f = NULL;
static APR_OPTIONAL_FN_TYPE(hc_select_exprs) *hc_select_exprs_f = NULL;
static APR_OPTIONAL_FN_TYPE(hc_valid_expr) *hc_valid_expr_f = NULL;


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
    set_worker_hc_param_f = APR_RETRIEVE_OPTIONAL_FN(set_worker_hc_param);
    hc_show_exprs_f = APR_RETRIEVE_OPTIONAL_FN(hc_show_exprs);
    hc_select_exprs_f = APR_RETRIEVE_OPTIONAL_FN(hc_select_exprs);
    hc_valid_expr_f = APR_RETRIEVE_OPTIONAL_FN(hc_valid_expr);
    return OK;
}

#if 0
extern void proxy_update_members(proxy_balancer **balancer, request_rec *r,
                                 proxy_server_conf *conf);
#endif

static int proxy_balancer_canon(request_rec *r, char *url)
{
    char *host;
    apr_port_t port = 0;
    const char *err;

    /* TODO: offset of BALANCER_PREFIX ?? */
    if (ap_cstr_casecmpn(url, "balancer:", 9) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "canonicalising URL %s", url);
        url += 9;
    }
    else {
        return DECLINED;
    }

    /* do syntatic check.
     * We break the URL into host, port, path
     */
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01157)
                      "error parsing URL %s: %s",
                      url, err);
        return HTTP_BAD_REQUEST;
    }

    /* The canon_handler hooks are run per the BalancerMember in
     * balancer_fixup(), keep the original/raw path for now.
     */
    r->filename = apr_pstrcat(r->pool, "proxy:" BALANCER_PREFIX,
                              host, "/", url, NULL);

    return OK;
}

static void init_balancer_members(apr_pool_t *p, server_rec *s,
                                 proxy_balancer *balancer)
{
    int i;
    proxy_worker **workers;

    workers = (proxy_worker **)balancer->workers->elts;

    for (i = 0; i < balancer->workers->nelts; i++) {
        int worker_is_initialized;
        proxy_worker *worker = *workers;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01158)
                     "Looking at %s -> %s initialized?", balancer->s->name,
                     ap_proxy_worker_name(p, worker));
        worker_is_initialized = PROXY_WORKER_IS_INITIALIZED(worker);
        if (!worker_is_initialized) {
            ap_proxy_initialize_worker(worker, s, p);
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
             * Session path was found, get its value
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
                     * Session cookie was found, get its value
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
                                       const char *route, request_rec *r,
                                       int recursion)
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
                if (PROXY_WORKER_IS_USABLE(worker)) {
                    return worker;
                } else {
                    /*
                     * If the worker is in error state run
                     * retry on that worker. It will be marked as
                     * operational if the retry timeout is elapsed.
                     * The worker might still be unusable, but we try
                     * anyway.
                     */
                    ap_proxy_retry_worker_fn("BALANCER", worker, r->server);
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
                         * Also check that we haven't gone thru all the
                         * balancer members by means of redirects.
                         * This should avoid redirect cycles.
                         */
                        if ((*worker->s->redirect)
                            && (recursion < balancer->workers->nelts)) {
                            proxy_worker *rworker = NULL;
                            rworker = find_route_worker(balancer, worker->s->redirect,
                                                        r, recursion + 1);
                            /* Check if the redirect worker is usable */
                            if (rworker && !PROXY_WORKER_IS_USABLE(rworker)) {
                                /*
                                 * If the worker is in error state run
                                 * retry on that worker. It will be marked as
                                 * operational if the retry timeout is elapsed.
                                 * The worker might still be unusable, but we try
                                 * anyway.
                                 */
                                ap_proxy_retry_worker_fn("BALANCER", rworker, r->server);
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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01159)
                     "Found value %s for stickysession %s",
                     *route, balancer->s->sticky_path);
        *sticky_used =  balancer->s->sticky_path;
    }
    else {
        *route = get_cookie_param(r, balancer->s->sticky);
        if (*route) {
            *sticky_used =  balancer->s->sticky;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01160)
                         "Found value %s for stickysession %s",
                         *route, balancer->s->sticky);
        }
    }
    /*
     * If we found a value for stickysession, find the first '.' (or whatever
     * sticky_separator is set to) within. Everything after '.' (if present)
     * is our route. 
     */
    if ((*route) && (balancer->s->sticky_separator != 0) && ((*route = strchr(*route, balancer->s->sticky_separator)) != NULL ))
        (*route)++;
    if ((*route) && (**route)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01161) "Found route %s", *route);
        /* We have a route in path or in cookie
         * Find the worker that has this route defined.
         */
        worker = find_route_worker(balancer, *route, r, 1);
        if (worker && strcmp(*route, worker->s->route)) {
            /*
             * Notice that the route of the worker chosen is different from
             * the route supplied by the client.
             */
            apr_table_setn(r->subprocess_env, "BALANCER_ROUTE_CHANGED", "1");
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01162)
                          "Route changed from %s to %s",
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

#if APR_HAS_THREADS
    if ((rv = PROXY_THREAD_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01163)
                      "%s: Lock failed for find_best_worker()",
                      balancer->s->name);
        return NULL;
    }
#endif

    candidate = (*balancer->lbmethod->finder)(balancer, r);

    if (candidate)
        candidate->s->elected++;

#if APR_HAS_THREADS
    if ((rv = PROXY_THREAD_UNLOCK(balancer)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01164)
                      "%s: Unlock failed for find_best_worker()",
                      balancer->s->name);
    }
#endif

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
             * different children, use the provided algo.
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

static int balancer_fixup(request_rec *r, proxy_worker *worker, char **url)
{
    const char *path;
    int rc;

    /* Build the proxy URL from the worker URL and the actual path */
    path = strstr(*url, "://");
    if (path) {
        path = ap_strchr_c(path + 3, '/');
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", worker->s->name_ex, path, NULL);

    /* Canonicalize r->filename per the worker scheme's canon_handler hook */
    rc = ap_proxy_canon_url(r);
    if (rc == OK) {
        AP_DEBUG_ASSERT(strncmp(r->filename, "proxy:", 6) == 0);
        *url = apr_pstrdup(r->pool, r->filename + 6);
    }
    return rc;
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
            ap_proxy_retry_worker_fn("BALANCER", *worker, s);
            if (!((*worker)->s->status & PROXY_WORKER_IN_ERROR)) {
                ok = 1;
                break;
            }
        }
    }
    if (!ok && balancer->s->forcerecovery) {
        /* If all workers are in error state force the recovery.
         */
        worker = (proxy_worker **)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++, worker++) {
            ++(*worker)->s->retries;
            (*worker)->s->status &= ~PROXY_WORKER_IN_ERROR;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01165)
                         "%s: Forcing recovery for worker (%s:%d)",
                         balancer->s->name, (*worker)->s->hostname_ex,
                         (int)(*worker)->s->port);
        }
    }
}

static apr_status_t decrement_busy_count(void *worker_)
{
    proxy_worker *worker = worker_;
    
    if (worker->s->busy) {
        worker->s->busy--;
    }

    return APR_SUCCESS;
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
        (ap_cstr_casecmpn(*url, BALANCER_PREFIX, sizeof(BALANCER_PREFIX) - 1)
         || !(*balancer = ap_proxy_get_balancer(r->pool, conf, *url, 1))))
        return DECLINED;

    /* Step 2: Lock the LoadBalancer
     * XXX: perhaps we need the process lock here
     */
#if APR_HAS_THREADS
    if ((rv = PROXY_THREAD_LOCK(*balancer)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01166)
                      "%s: Lock failed for pre_request", (*balancer)->s->name);
        return DECLINED;
    }
#endif

    /* Step 3: force recovery */
    force_recovery(*balancer, r->server);

    /* Step 3.5: Update member list for the balancer */
    /* TODO: Implement as provider! */
    ap_proxy_sync_balancer(*balancer, r->server, conf);

    /* Step 4: find the session route */
    runtime = find_session_route(*balancer, r, &route, &sticky, url);
    if (runtime) {
        if ((*balancer)->lbmethod && (*balancer)->lbmethod->updatelbstatus) {
            /* Call the LB implementation */
            (*balancer)->lbmethod->updatelbstatus(*balancer, runtime, r->server);
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01167)
                          "%s: All workers are in error state for route (%s)",
                          (*balancer)->s->name, route);
#if APR_HAS_THREADS
            if ((rv = PROXY_THREAD_UNLOCK(*balancer)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01168)
                              "%s: Unlock failed for pre_request",
                              (*balancer)->s->name);
            }
#endif
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }

#if APR_HAS_THREADS
    if ((rv = PROXY_THREAD_UNLOCK(*balancer)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01169)
                      "%s: Unlock failed for pre_request",
                      (*balancer)->s->name);
    }
#endif
    if (!*worker) {
        runtime = find_best_worker(*balancer, r);
        if (!runtime) {
            if ((*balancer)->workers->nelts) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01170)
                              "%s: All workers are in error state",
                              (*balancer)->s->name);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01171)
                              "%s: No workers in balancer",
                              (*balancer)->s->name);
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
    apr_pool_cleanup_register(r->pool, *worker, decrement_busy_count,
                              apr_pool_cleanup_null);

    /* Add balancer/worker info to env. */
    apr_table_setn(r->subprocess_env,
                   "BALANCER_NAME", (*balancer)->s->name);
    apr_table_setn(r->subprocess_env,
                   "BALANCER_WORKER_NAME", (*worker)->s->name_ex);
    apr_table_setn(r->subprocess_env,
                   "BALANCER_WORKER_ROUTE", (*worker)->s->route);

    /* Rewrite the url from 'balancer://url'
     * to the 'worker_scheme://worker_hostname[:worker_port]/url'
     * This replaces the balancers fictional name with the real
     * hostname of the elected worker and canonicalizes according
     * to the worker scheme (calls canon_handler hooks).
     */
    access_status = balancer_fixup(r, *worker, url);

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
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01172)
                  "%s: worker (%s) rewritten to %s",
                  (*balancer)->s->name, (*worker)->s->name_ex, *url);

    return access_status;
}

static int proxy_balancer_post_request(proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf)
{

    apr_status_t rv;

#if APR_HAS_THREADS
    if ((rv = PROXY_THREAD_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01173)
                      "%s: Lock failed for post_request",
                      balancer->s->name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    if (!apr_is_empty_array(balancer->errstatuses)
        && !(worker->s->status & PROXY_WORKER_IGNORE_ERRORS)) {
        int i;
        for (i = 0; i < balancer->errstatuses->nelts; i++) {
            int val = ((int *)balancer->errstatuses->elts)[i];
            if (r->status == val) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01174)
                              "%s: Forcing worker (%s) into error state "
                              "due to status code %d matching 'failonstatus' "
                              "balancer parameter",
                              balancer->s->name, ap_proxy_worker_name(r->pool, worker),
                              val);
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
                break;
            }
        }
    }

    if (balancer->failontimeout
        && !(worker->s->status & PROXY_WORKER_IGNORE_ERRORS)
        && (apr_table_get(r->notes, "proxy_timedout")) != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02460)
                      "%s: Forcing worker (%s) into error state "
                      "due to timeout and 'failontimeout' parameter being set",
                       balancer->s->name, ap_proxy_worker_name(r->pool, worker));
        worker->s->status |= PROXY_WORKER_IN_ERROR;
        worker->s->error_time = apr_time_now();

    }
#if APR_HAS_THREADS
    if ((rv = PROXY_THREAD_UNLOCK(balancer)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01175)
                      "%s: Unlock failed for post_request", balancer->s->name);
    }
#endif
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01176)
                  "proxy_balancer_post_request for (%s)", balancer->s->name);

    return OK;
}

static void recalc_factors(proxy_balancer *balancer)
{
    int i;
    proxy_worker **workers;


    /* Recalculate lbfactors */
    workers = (proxy_worker **)balancer->workers->elts;
    /* Special case if there is only one worker its
     * load factor will always be 100
     */
    if (balancer->workers->nelts == 1) {
        (*workers)->s->lbstatus = (*workers)->s->lbfactor = 100;
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
        if (balancer->gmutex) {
            apr_global_mutex_destroy(balancer->gmutex);
            balancer->gmutex = NULL;
        }
    }
    return(0);
}

/*
 * Compute an ID for a vhost based on what makes it selected by requests.
 * The second and more Host(s)/IP(s):port(s), and the ServerAlias(es) are
 * optional (see make_servers_ids() below).
 */
 static const char *make_server_id(server_rec *s, apr_pool_t *p, int full)
{
    apr_md5_ctx_t md5_ctx;
    unsigned char md5[APR_MD5_DIGESTSIZE];
    char id[2 * APR_MD5_DIGESTSIZE + 1];
    char host_ip[64]; /* for any IPv[46] string */
    server_addr_rec *sar;
    int i;

    apr_md5_init(&md5_ctx);
    for (sar = s->addrs; sar; sar = sar->next) {
        host_ip[0] = '\0';
        apr_sockaddr_ip_getbuf(host_ip, sizeof host_ip, sar->host_addr);
        apr_md5_update(&md5_ctx, (void *)sar->virthost, strlen(sar->virthost));
        apr_md5_update(&md5_ctx, (void *)host_ip, strlen(host_ip));
        apr_md5_update(&md5_ctx, (void *)&sar->host_port,
                       sizeof(sar->host_port));
        if (!full) {
            break;
        }
    }
    if (s->server_hostname) {
        apr_md5_update(&md5_ctx, (void *)s->server_hostname,
                       strlen(s->server_hostname));
    }
    if (full) {
        if (s->names) {
            for (i = 0; i < s->names->nelts; ++i) {
                const char *name = APR_ARRAY_IDX(s->names, i, char *);
                apr_md5_update(&md5_ctx, (void *)name, strlen(name));
            }
        }
        if (s->wild_names) {
            for (i = 0; i < s->wild_names->nelts; ++i) {
                const char *name = APR_ARRAY_IDX(s->wild_names, i, char *);
                apr_md5_update(&md5_ctx, (void *)name, strlen(name));
            }
        }
    }
    apr_md5_final(md5, &md5_ctx);
    ap_bin2hex(md5, APR_MD5_DIGESTSIZE, id);

    return apr_pstrmemdup(p, id, sizeof(id) - 1);
}

/*
 * First try to compute an unique ID for each vhost with minimal criteria,
 * that is the first Host/IP:port and ServerName. For most cases this should
 * be enough and avoids changing the ID unnecessarily across restart (or
 * stop/start w.r.t. persisted files) for things that this module does not
 * care about.
 *
 * But if it's not enough (collisions) do a second pass for the full monty,
 * that is additionally the other Host(s)/IP(s):port(s) and ServerAlias(es).
 *
 * Finally, for pathological configs where this is still not enough, let's
 * append a counter to duplicates, because we really want that ID to be unique
 * even if the vhost will never be selected to handle requests at run time, at
 * load time a duplicate may steal the original slotmems (depending on its
 * balancers' configurations), see how mod_slotmem_shm reuses slots/files based
 * solely on this ID and resets them if the sizes don't match.
 */
static apr_array_header_t *make_servers_ids(server_rec *main_s, apr_pool_t *p)
{
    server_rec *s = main_s;
    apr_array_header_t *ids = apr_array_make(p, 10, sizeof(const char *));
    apr_hash_t *dups = apr_hash_make(p);
    int idx, *dup, full_monty = 0;
    const char *id;

    for (idx = 0, s = main_s; s; s = s->next, ++idx) {
        id = make_server_id(s, p, 0);
        dup = apr_hash_get(dups, id, APR_HASH_KEY_STRING);
        apr_hash_set(dups, id, APR_HASH_KEY_STRING,
                     apr_pmemdup(p, &idx, sizeof(int)));
        if (dup) {
            full_monty = 1;
            APR_ARRAY_IDX(ids, *dup, const char *) = NULL;
            APR_ARRAY_PUSH(ids, const char *) = NULL;
        }
        else {
            APR_ARRAY_PUSH(ids, const char *) = id;
        }
    }
    if (full_monty) {
        apr_hash_clear(dups);
        for (idx = 0, s = main_s; s; s = s->next, ++idx) {
            id = APR_ARRAY_IDX(ids, idx, const char *);
            if (id) {
                /* Preserve non-duplicates */
                continue;
            }
            id = make_server_id(s, p, 1);
            if (apr_hash_get(dups, id, APR_HASH_KEY_STRING)) {
                id = apr_psprintf(p, "%s_%x", id, idx);
            }
            else {
                apr_hash_set(dups, id, APR_HASH_KEY_STRING, (void *)-1);
            }
            APR_ARRAY_IDX(ids, idx, const char *) = id;
        }
    }

    return ids;
}

/* post_config hook: */
static int balancer_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                         apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    proxy_server_conf *conf;
    ap_slotmem_instance_t *new = NULL;
    apr_time_t tstamp;
    apr_array_header_t *ids;
    int idx;

    /* balancer_post_config() will be called twice during startup.  So, don't
     * set up the static data the 1st time through. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_proxy_retry_worker_fn =
            APR_RETRIEVE_OPTIONAL_FN(ap_proxy_retry_worker);
    if (!ap_proxy_retry_worker_fn) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(02230)
                     "mod_proxy must be loaded for mod_proxy_balancer");
        return !OK;
    }

    /*
     * Get slotmem setups
     */
    storage = ap_lookup_provider(AP_SLOTMEM_PROVIDER_GROUP, "shm",
                                 AP_SLOTMEM_PROVIDER_VERSION);
    if (!storage) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01177)
                     "Failed to lookup provider 'shm' for '%s': is "
                     "mod_slotmem_shm loaded??",
                     AP_SLOTMEM_PROVIDER_GROUP);
        return !OK;
    }

    ids = make_servers_ids(s, ptemp);

    tstamp = apr_time_now();
    /*
     * Go thru each Vhost and create the shared mem slotmem for
     * each balancer's workers
     */
    for (idx = 0; s; ++idx) {
        int i,j;
        const char *id;
        proxy_balancer *balancer;
        ap_slotmem_type_t type;
        void *sconf = s->module_config;
        conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        /*
         * During create_proxy_config() we created a dummy id. Now that
         * we have identifying info, we can create the real id
         */
        id = APR_ARRAY_IDX(ids, idx, const char *);
        conf->id = apr_psprintf(pconf, "p%x",
                                ap_proxy_hashfunc(id, PROXY_HASHFUNC_DEFAULT));
        if (conf->bslot) {
            /* Shared memory already created for this proxy_server_conf.
             */
            s = s->next;
            continue;
        }
        if (conf->bal_persist) {
            type = AP_SLOTMEM_TYPE_PERSIST | AP_SLOTMEM_TYPE_CLEARINUSE;
        } else {
            type = 0;
        }
        if (conf->balancers->nelts) {
            conf->max_balancers = conf->balancers->nelts + conf->bgrowth;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01178) "Doing balancers create: %d, %d (%d)",
                         (int)ALIGNED_PROXY_BALANCER_SHARED_SIZE,
                         (int)conf->balancers->nelts, conf->max_balancers);

            rv = storage->create(&new, conf->id,
                                 ALIGNED_PROXY_BALANCER_SHARED_SIZE,
                                 conf->max_balancers, type, pconf);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01179) "balancer slotmem_create failed");
                return !OK;
            }
            conf->bslot = new;
        }
        conf->storage = storage;

        /* Initialize shared scoreboard data */
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
            proxy_worker **workers;
            proxy_worker *worker;
            proxy_balancer_shared *bshm;
            const char *sname;
            unsigned int index;

            /* now that we have the right id, we need to redo the sname field */
            ap_pstr2_alnum(pconf, balancer->s->name + sizeof(BALANCER_PREFIX) - 1,
                           &sname);
            sname = apr_pstrcat(pconf, conf->id, "_", sname, NULL);
            PROXY_STRNCPY(balancer->s->sname, sname); /* We know this will succeed */

            balancer->max_workers = balancer->workers->nelts + balancer->growth;
            /* Create global mutex */
            rv = ap_global_mutex_create(&(balancer->gmutex), NULL, balancer_mutex_type,
                                        balancer->s->sname, s, pconf, 0);
            if (rv != APR_SUCCESS || !balancer->gmutex) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01180)
                             "mutex creation of %s : %s failed", balancer_mutex_type,
                             balancer->s->sname);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            apr_pool_cleanup_register(pconf, (void *)s, lock_remove,
                                      apr_pool_cleanup_null);

            /* setup shm for balancers */
            bshm = ap_proxy_find_balancershm(storage, conf->bslot, balancer, &index);
            if (bshm) {
                if ((rv = storage->fgrab(conf->bslot, index)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(02408) "balancer slotmem_fgrab failed");
                    return !OK;
                }
            }
            else {
                if ((rv = storage->grab(conf->bslot, &index)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01181) "balancer slotmem_grab failed");
                    return !OK;
                }
                if ((rv = storage->dptr(conf->bslot, index, (void *)&bshm)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01182) "balancer slotmem_dptr failed");
                    return !OK;
                }
            }
            if ((rv = ap_proxy_share_balancer(balancer, bshm, index)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01183) "Cannot share balancer");
                return !OK;
            }

            /* create slotmem slots for workers */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01184) "Doing workers create: %s (%s), %d, %d [%u]",
                         balancer->s->name, balancer->s->sname,
                         (int)ALIGNED_PROXY_WORKER_SHARED_SIZE,
                         (int)balancer->max_workers, i);

            rv = storage->create(&new, balancer->s->sname,
                                 ALIGNED_PROXY_WORKER_SHARED_SIZE,
                                 balancer->max_workers, type, pconf);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01185) "worker slotmem_create failed");
                return !OK;
            }
            balancer->wslot = new;
            balancer->storage = storage;

            /* sync all timestamps */
            balancer->wupdated = balancer->s->wupdated = tstamp;

            /* now go thru each worker */
            workers = (proxy_worker **)balancer->workers->elts;
            for (j = 0; j < balancer->workers->nelts; j++, workers++) {
                proxy_worker_shared *shm;

                worker = *workers;

                shm = ap_proxy_find_workershm(storage, balancer->wslot, worker, &index);
                if (shm) {
                    if ((rv = storage->fgrab(balancer->wslot, index)) != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(02409) "worker slotmem_fgrab failed");
                        return !OK;
                    }
                }
                else {
                    if ((rv = storage->grab(balancer->wslot, &index)) != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01186) "worker slotmem_grab failed");
                        return !OK;

                    }
                    if ((rv = storage->dptr(balancer->wslot, index, (void *)&shm)) != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01187) "worker slotmem_dptr failed");
                        return !OK;
                    }
                }
                if ((rv = ap_proxy_share_worker(worker, shm, index)) != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(01188) "Cannot share worker");
                    return !OK;
                }
                worker->s->updated = tstamp;
            }
            if (conf->bal_persist) {
                /* We could have just read-in a persisted config. Force a sync. */
                balancer->wupdated--;
                ap_proxy_sync_balancer(balancer, s, conf);
            }
        }
        s = s->next;
    }

    return OK;
}

static void create_radio(const char *name, unsigned int flag, request_rec *r)
{
    ap_rvputs(r, "<td><label for='", name, "1'>On</label> <input name='", name, "' id='", name, "1' value='1' type=radio", NULL);
    if (flag)
        ap_rputs(" checked", r);
    ap_rvputs(r, "> <br/> <label for='", name, "0'>Off</label> <input name='", name, "' id='", name, "0' value='0' type=radio", NULL);
    if (!flag)
        ap_rputs(" checked", r);
    ap_rputs("></td>\n", r);
}

static void push2table(const char *input, apr_table_t *params,
                       const char *allowed[], apr_pool_t *p)
{
    char *args;
    char *tok, *val;
    char *key;

    if (input == NULL) {
        return;
    }
    args = apr_pstrdup(p, input);

    key = apr_strtok(args, "&", &tok);
    while (key) {
        val = strchr(key, '=');
        if (val) {
            *val++ = '\0';
        }
        else {
            val = "";
        }
        ap_unescape_url(key);
        ap_unescape_url(val);
        /* hcuri, worker name, balancer name, at least  are escaped when building the form, so twice */
        ap_unescape_url(val);
        if (allowed == NULL) { /* allow all */
            apr_table_set(params, key, val);
        }
        else {
            const char **ok = allowed;
            while (*ok) {
                if (strcmp(*ok, key) == 0) {
                    apr_table_set(params, key, val);
                    break;
                }
                ok++;
            }
        }
        key = apr_strtok(NULL, "&", &tok);
    }
}

/* Returns non-zero if the Referer: header value passed matches the
 * host of the request. */
static int safe_referer(request_rec *r, const char *ref)
{
    apr_uri_t uri;

    if (apr_uri_parse(r->pool, ref, &uri) || !uri.hostname)
        return 0;

    return strcasecmp(uri.hostname, ap_get_server_name(r)) == 0;
}

/*
 * Process the paramters and add or update the worker of the
 * balancer.  Must only be called if the nonce has been validated to
 * match, to avoid XSS attacks.
 */
static int balancer_process_balancer_worker(request_rec *r, proxy_server_conf *conf,
                                            proxy_balancer *bsel,
                                            proxy_worker *wsel,
                                            apr_table_t *params)

{
    apr_status_t rv;
    /* First set the params */
    if (wsel) {
        const char *val;
        int was_usable = PROXY_WORKER_IS_USABLE(wsel);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01192) "settings worker params");

        if ((val = apr_table_get(params, "w_lf"))) {
            int ival;
            double fval = atof(val);
            ival = fval * 100.0;
            if (ival >= 100 && ival <= 10000) {
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
        /*
         * TODO: Look for all 'w_status_#' keys and then loop thru
         * on that # character, since the character == the flag
         */
        if ((val = apr_table_get(params, "w_status_I"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_IGNORE_ERRORS_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_N"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_DRAIN_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_D"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_DISABLED_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_H"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_HOT_STANDBY_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_R"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_HOT_SPARE_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_S"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_STOPPED_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_status_C"))) {
            ap_proxy_set_wstatus(PROXY_WORKER_HC_FAIL_FLAG, atoi(val), wsel);
        }
        if ((val = apr_table_get(params, "w_ls"))) {
            int ival = atoi(val);
            if (ival >= 0 && ival <= 99) {
                wsel->s->lbset = ival;
             }
        }
        if ((val = apr_table_get(params, "w_hi"))) {
            apr_interval_time_t hci;
            if (ap_timeout_parameter_parse(val, &hci, "ms") == APR_SUCCESS) {
                if (hci >= AP_WD_TM_SLICE) {
                    wsel->s->interval = hci;
                }
             }
        }
        if ((val = apr_table_get(params, "w_hp"))) {
            int ival = atoi(val);
            if (ival >= 1) {
                wsel->s->passes = ival;
             }
        }
        if ((val = apr_table_get(params, "w_hf"))) {
            int ival = atoi(val);
            if (ival >= 1) {
                wsel->s->fails = ival;
             }
        }
        if ((val = apr_table_get(params, "w_hm"))) {
            proxy_hcmethods_t *method = proxy_hcmethods;
            for (; method->name; method++) {
                if (!ap_cstr_casecmp(method->name, val) && method->implemented)
                    wsel->s->method = method->method;
            }
        }
        if ((val = apr_table_get(params, "w_hu"))) {
            if (strlen(val) && strlen(val) < sizeof(wsel->s->hcuri))
                strcpy(wsel->s->hcuri, val);
            else
                *wsel->s->hcuri = '\0';
        }
        if (hc_valid_expr_f && (val = apr_table_get(params, "w_he"))) {
            if (strlen(val) && hc_valid_expr_f(r, val) && strlen(val) < sizeof(wsel->s->hcexpr))
                strcpy(wsel->s->hcexpr, val);
            else
                *wsel->s->hcexpr = '\0';
        }
        /* If the health check method doesn't support an expr, then null it */
        if (wsel->s->method == NONE || wsel->s->method == TCP || wsel->s->method == CPING) {
            *wsel->s->hcexpr = '\0';
        }
        /* if enabling, we need to reset all lb params */
        if (bsel && !was_usable && PROXY_WORKER_IS_USABLE(wsel)) {
            bsel->s->need_reset = 1;
        }

    }

    if (bsel) {
        const char *val;
        int ival;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01193)
                      "settings balancer params");
        if ((val = apr_table_get(params, "b_lbm"))) {
            if ((strlen(val) < (sizeof(bsel->s->lbpname)-1)) &&
                strcmp(val, bsel->s->lbpname)) {
                proxy_balancer_method *lbmethod;
                lbmethod = ap_lookup_provider(PROXY_LBMETHOD, val, "0");
                if (lbmethod) {
                    PROXY_STRNCPY(bsel->s->lbpname, val);
                    bsel->lbmethod = lbmethod;
                    bsel->s->wupdated = apr_time_now();
                    bsel->s->need_reset = 1;
                }
            }
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
        if ((val = apr_table_get(params, "b_ss")) && *val) {
            if (strlen(val) < (sizeof(bsel->s->sticky_path)-1)) {
                if (*val == '-' && *(val+1) == '\0')
                    *bsel->s->sticky_path = *bsel->s->sticky = '\0';
                else {
                    char *path;
                    PROXY_STRNCPY(bsel->s->sticky_path, val);
                    PROXY_STRNCPY(bsel->s->sticky, val);

                    if ((path = strchr((char *)bsel->s->sticky, '|'))) {
                        *path++ = '\0';
                        PROXY_STRNCPY(bsel->s->sticky_path, path);
                    }
                }
            }
        }
        if ((val = apr_table_get(params, "b_wyes")) &&
            (*val == '1' && *(val+1) == '\0') &&
            (val = apr_table_get(params, "b_nwrkr"))) {
            char *ret;
            proxy_worker *nworker;
            nworker = ap_proxy_get_worker(r->pool, bsel, conf, val);
            if (!nworker && storage->num_free_slots(bsel->wslot)) {
#if APR_HAS_THREADS
                if ((rv = PROXY_GLOBAL_LOCK(bsel)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01194)
                                  "%s: Lock failed for adding worker",
                                  bsel->s->name);
                }
#endif
                ret = ap_proxy_define_worker(conf->pool, &nworker, bsel, conf, val, 0);
                if (!ret) {
                    unsigned int index;
                    proxy_worker_shared *shm;
                    PROXY_COPY_CONF_PARAMS(nworker, conf);
                    if ((rv = storage->grab(bsel->wslot, &index)) != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r, APLOGNO(01195)
                                      "worker slotmem_grab failed");
#if APR_HAS_THREADS
                        if ((rv = PROXY_GLOBAL_UNLOCK(bsel)) != APR_SUCCESS) {
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01196)
                                          "%s: Unlock failed for adding worker",
                                          bsel->s->name);
                        }
#endif
                        return HTTP_BAD_REQUEST;
                    }
                    if ((rv = storage->dptr(bsel->wslot, index, (void *)&shm)) != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r, APLOGNO(01197)
                                      "worker slotmem_dptr failed");
#if APR_HAS_THREADS
                        if ((rv = PROXY_GLOBAL_UNLOCK(bsel)) != APR_SUCCESS) {
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01198)
                                          "%s: Unlock failed for adding worker",
                                          bsel->s->name);
                        }
#endif
                        return HTTP_BAD_REQUEST;
                    }
                    if ((rv = ap_proxy_share_worker(nworker, shm, index)) != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r, APLOGNO(01199)
                                      "Cannot share worker");
#if APR_HAS_THREADS
                        if ((rv = PROXY_GLOBAL_UNLOCK(bsel)) != APR_SUCCESS) {
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01200)
                                          "%s: Unlock failed for adding worker",
                                          bsel->s->name);
                        }
#endif
                        return HTTP_BAD_REQUEST;
                    }
                    if ((rv = ap_proxy_initialize_worker(nworker, r->server, conf->pool)) != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_EMERG, rv, r, APLOGNO(01201)
                                      "Cannot init worker");
#if APR_HAS_THREADS
                        if ((rv = PROXY_GLOBAL_UNLOCK(bsel)) != APR_SUCCESS) {
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01202)
                                          "%s: Unlock failed for adding worker",
                                          bsel->s->name);
                        }
#endif
                        return HTTP_BAD_REQUEST;
                    }
                    /* sync all timestamps */
                    bsel->wupdated = bsel->s->wupdated = nworker->s->updated = apr_time_now();
                    /* by default, all new workers are disabled */
                    ap_proxy_set_wstatus(PROXY_WORKER_DISABLED_FLAG, 1, nworker);
                } else {
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10163)
                                  "%s: failed to add worker %s",
                                  bsel->s->name, val);
#if APR_HAS_THREADS
                    PROXY_GLOBAL_UNLOCK(bsel);
#endif
                    return HTTP_BAD_REQUEST;
                }
#if APR_HAS_THREADS
                if ((rv = PROXY_GLOBAL_UNLOCK(bsel)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01203)
                                  "%s: Unlock failed for adding worker",
                                  bsel->s->name);
                }
#endif
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10164)
                                  "%s: failed to add worker %s",
                                  bsel->s->name, val);
                return HTTP_BAD_REQUEST;
            }

        }

    }
    return APR_SUCCESS;
}

/*
 * Process a request for balancer or worker management from another module
 */
static apr_status_t balancer_manage(request_rec *r, apr_table_t *params)
{
    void *sconf;
    proxy_server_conf *conf;
    proxy_balancer *bsel = NULL;
    proxy_worker *wsel = NULL;
    const char *name;
    sconf = r->server->module_config;
    conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    /* Process the parameters */
    if ((name = apr_table_get(params, "b"))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "balancer_manage "
                  "balancer: %s", name);
        bsel = ap_proxy_get_balancer(r->pool, conf,
            apr_pstrcat(r->pool, BALANCER_PREFIX, name, NULL), 0);
    }

    if ((name = apr_table_get(params, "w"))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "balancer_manage "
                  "worker: %s", name);
        wsel = ap_proxy_get_worker(r->pool, bsel, conf, name);
    }
    if (bsel) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "balancer_manage "
                  "balancer: %s",  bsel->s->name);
        return(balancer_process_balancer_worker(r, conf, bsel, wsel, params));
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "balancer_manage failed: "
                      "No balancer!");
    return HTTP_BAD_REQUEST;
}

/*
 * builds the page and links to configure via HTLM or XML.
 */
static void balancer_display_page(request_rec *r, proxy_server_conf *conf,
                                  proxy_balancer *bsel,
                                  proxy_worker *wsel,
                                  int usexml)
{
    const char *action;
    proxy_balancer *balancer;
    proxy_worker *worker;
    proxy_worker **workers;
    int i, n;
    action = ap_construct_url(r->pool, r->uri, r);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01204) "genning page");

    if (usexml) {
        char date[APR_RFC822_DATE_LEN];
        ap_set_content_type_ex(r, "text/xml", 1);
        ap_rputs("<?xml version='1.0' encoding='UTF-8' ?>\n", r);
        ap_rputs("<httpd:manager xmlns:httpd='http://httpd.apache.org'>\n", r);
        ap_rputs("  <httpd:balancers>\n", r);
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {
            ap_rputs("    <httpd:balancer>\n", r);
            /* Start proxy_balancer */
            ap_rvputs(r, "      <httpd:name>", balancer->s->name, "</httpd:name>\n", NULL);
            if (*balancer->s->sticky) {
                ap_rvputs(r, "      <httpd:stickysession>", ap_escape_html(r->pool, balancer->s->sticky),
                          "</httpd:stickysession>\n", NULL);
                ap_rprintf(r,
                           "      <httpd:nofailover>%s</httpd:nofailover>\n",
                           (balancer->s->sticky_force ? "On" : "Off"));
            }
            ap_rprintf(r,
                       "      <httpd:timeout>%" APR_TIME_T_FMT "</httpd:timeout>",
                       apr_time_sec(balancer->s->timeout));
            if (balancer->s->max_attempts_set) {
                ap_rprintf(r,
                           "      <httpd:maxattempts>%d</httpd:maxattempts>\n",
                           balancer->s->max_attempts);
            }
            ap_rvputs(r, "      <httpd:lbmethod>", balancer->lbmethod->name,
                      "</httpd:lbmethod>\n", NULL);
            if (*balancer->s->sticky) {
                ap_rprintf(r,
                           "      <httpd:scolonpathdelim>%s</httpd:scolonpathdelim>\n",
                           (balancer->s->scolonsep ? "On" : "Off"));
            }
            /* End proxy_balancer */
            ap_rputs("      <httpd:workers>\n", r);
            workers = (proxy_worker **)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                worker = *workers;
                /* Start proxy_worker */
                ap_rputs("        <httpd:worker>\n", r);
                ap_rvputs(r, "          <httpd:name>", ap_proxy_worker_name(r->pool, worker),
                          "</httpd:name>\n", NULL);
                ap_rvputs(r, "          <httpd:scheme>", worker->s->scheme,
                          "</httpd:scheme>\n", NULL);
                ap_rvputs(r, "          <httpd:hostname>", worker->s->hostname_ex,
                          "</httpd:hostname>\n", NULL);
                ap_rprintf(r, "          <httpd:loadfactor>%.2f</httpd:loadfactor>\n",
                          (float)(worker->s->lbfactor)/100.0);
                ap_rprintf(r,
                           "          <httpd:port>%d</httpd:port>\n",
                           worker->s->port);
                ap_rprintf(r, "          <httpd:min>%d</httpd:min>\n",
                           worker->s->min);
                ap_rprintf(r, "          <httpd:smax>%d</httpd:smax>\n",
                           worker->s->smax);
                ap_rprintf(r, "          <httpd:max>%d</httpd:max>\n",
                           worker->s->hmax);
                ap_rprintf(r,
                           "          <httpd:ttl>%" APR_TIME_T_FMT "</httpd:ttl>\n",
                           apr_time_sec(worker->s->ttl));
                if (worker->s->timeout_set) {
                    ap_rprintf(r,
                               "          <httpd:timeout>%" APR_TIME_T_FMT "</httpd:timeout>\n",
                               apr_time_sec(worker->s->timeout));
                }
                if (worker->s->acquire_set) {
                    ap_rprintf(r,
                               "          <httpd:acquire>%" APR_TIME_T_FMT "</httpd:acquire>\n",
                               apr_time_msec(worker->s->acquire));
                }
                if (worker->s->recv_buffer_size_set) {
                    ap_rprintf(r,
                               "          <httpd:recv_buffer_size>%" APR_SIZE_T_FMT "</httpd:recv_buffer_size>\n",
                               worker->s->recv_buffer_size);
                }
                if (worker->s->io_buffer_size_set) {
                    ap_rprintf(r,
                               "          <httpd:io_buffer_size>%" APR_SIZE_T_FMT "</httpd:io_buffer_size>\n",
                               worker->s->io_buffer_size);
                }
                if (worker->s->keepalive_set) {
                    ap_rprintf(r,
                               "          <httpd:keepalive>%s</httpd:keepalive>\n",
                               (worker->s->keepalive ? "On" : "Off"));
                }
                /* Begin proxy_worker_stat */
                ap_rputs("          <httpd:status>", r);
                ap_rputs(ap_proxy_parse_wstatus(r->pool, worker), r);
                ap_rputs("</httpd:status>\n", r);
                if ((worker->s->error_time > 0) && apr_rfc822_date(date, worker->s->error_time) == APR_SUCCESS) {
                    ap_rvputs(r, "          <httpd:error_time>", date,
                              "</httpd:error_time>\n", NULL);
                }
                ap_rprintf(r,
                           "          <httpd:retries>%d</httpd:retries>\n",
                           worker->s->retries);
                ap_rprintf(r,
                           "          <httpd:lbstatus>%d</httpd:lbstatus>\n",
                           worker->s->lbstatus);
                ap_rprintf(r,
                           "          <httpd:loadfactor>%.2f</httpd:loadfactor>\n",
                           (float)(worker->s->lbfactor)/100.0);
                ap_rprintf(r,
                           "          <httpd:transferred>%" APR_OFF_T_FMT "</httpd:transferred>\n",
                           worker->s->transferred);
                ap_rprintf(r,
                           "          <httpd:read>%" APR_OFF_T_FMT "</httpd:read>\n",
                           worker->s->read);
                ap_rprintf(r,
                           "          <httpd:elected>%" APR_SIZE_T_FMT "</httpd:elected>\n",
                           worker->s->elected);
                ap_rvputs(r, "          <httpd:route>",
                          ap_escape_html(r->pool, worker->s->route),
                          "</httpd:route>\n", NULL);
                ap_rvputs(r, "          <httpd:redirect>",
                          ap_escape_html(r->pool, worker->s->redirect),
                          "</httpd:redirect>\n", NULL);
                ap_rprintf(r,
                           "          <httpd:busy>%" APR_SIZE_T_FMT "</httpd:busy>\n",
                           worker->s->busy);
                ap_rprintf(r, "          <httpd:lbset>%d</httpd:lbset>\n",
                           worker->s->lbset);
                /* End proxy_worker_stat */
                if (!ap_cstr_casecmp(worker->s->scheme, "ajp")) {
                    ap_rputs("          <httpd:flushpackets>", r);
                    switch (worker->s->flush_packets) {
                        case flush_off:
                            ap_rputs("Off", r);
                            break;
                        case flush_on:
                            ap_rputs("On", r);
                            break;
                        case flush_auto:
                            ap_rputs("Auto", r);
                            break;
                    }
                    ap_rputs("</httpd:flushpackets>\n", r);
                    if (worker->s->flush_packets == flush_auto) {
                        ap_rprintf(r,
                                   "          <httpd:flushwait>%d</httpd:flushwait>\n",
                                   worker->s->flush_wait);
                    }
                    if (worker->s->ping_timeout_set) {
                        ap_rprintf(r,
                                   "          <httpd:ping>%" APR_TIME_T_FMT "</httpd:ping>",
                                   apr_time_msec(worker->s->ping_timeout));
                    }
                }
                if (worker->s->disablereuse_set) {
                    ap_rprintf(r,
                               "      <httpd:disablereuse>%s</httpd:disablereuse>\n",
                               (worker->s->disablereuse ? "On" : "Off"));
                }
                if (worker->s->conn_timeout_set) {
                    ap_rprintf(r,
                               "          <httpd:connectiontimeout>%" APR_TIME_T_FMT "</httpd:connectiontimeout>\n",
                               apr_time_msec(worker->s->conn_timeout));
                }
                if (worker->s->retry_set) {
                    ap_rprintf(r,
                               "          <httpd:retry>%" APR_TIME_T_FMT "</httpd:retry>\n",
                               apr_time_sec(worker->s->retry));
                }
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
                 "<html><head><title>Balancer Manager</title>\n", r);
        ap_rputs("<style type='text/css'>\n"
                 "table {\n"
                 " border-width: 1px;\n"
                 " border-spacing: 3px;\n"
                 " border-style: solid;\n"
                 " border-color: gray;\n"
                 " border-collapse: collapse;\n"
                 " background-color: white;\n"
                 " text-align: center;\n"
                 "}\n"
                 "th {\n"
                 " border-width: 1px;\n"
                 " padding: 2px;\n"
                 " border-style: dotted;\n"
                 " border-color: gray;\n"
                 " background-color: lightgray;\n"
                 " text-align: center;\n"
                 "}\n"
                 "td {\n"
                 " border-width: 1px;\n"
                 " padding: 2px;\n"
                 " border-style: dotted;\n"
                 " border-color: gray;\n"
                 " background-color: white;\n"
                 " text-align: center;\n"
                 "}\n"
                 "</style>\n</head>\n", r);
        ap_rputs("<body><h1>Load Balancer Manager for ", r);
        ap_rvputs(r, ap_escape_html(r->pool, ap_get_server_name(r)),
                  "</h1>\n\n", NULL);
        ap_rvputs(r, "<dl><dt>Server Version: ",
                  ap_get_server_description(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server Built: ",
                  ap_get_server_built(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Balancer changes will ", conf->bal_persist ? "" : "NOT ",
                  "be persisted on restart.</dt>", NULL);
        ap_rvputs(r, "<dt>Balancers are ", conf->inherit ? "" : "NOT ",
                  "inherited from main server.</dt>", NULL);
        ap_rvputs(r, "<dt>ProxyPass settings are ", conf->ppinherit ? "" : "NOT ",
                  "inherited from main server.</dt>", NULL);
        ap_rputs("</dl>\n", r);
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {

            ap_rputs("<hr />\n<h3>LoadBalancer Status for ", r);
            ap_rvputs(r, "<a href=\"", ap_escape_uri(r->pool, r->uri), "?b=",
                      balancer->s->name + sizeof(BALANCER_PREFIX) - 1,
                      "&amp;nonce=", balancer->s->nonce,
                      "\">", NULL);
            ap_rvputs(r, balancer->s->name, "</a> [",balancer->s->sname, "]</h3>\n", NULL);
            ap_rputs("\n\n<table><tr>"
                "<th>MaxMembers</th><th>StickySession</th><th>DisableFailover</th><th>Timeout</th><th>FailoverAttempts</th><th>Method</th>"
                "<th>Path</th><th>Active</th></tr>\n<tr>", r);
            /* the below is a safe cast, since the number of slots total will
             * never be more than max_workers, which is restricted to int */
            ap_rprintf(r, "<td>%d [%d Used]</td>\n", balancer->max_workers,
                       balancer->max_workers - (int)storage->num_free_slots(balancer->wslot));
            if (*balancer->s->sticky) {
                if (strcmp(balancer->s->sticky, balancer->s->sticky_path)) {
                    ap_rvputs(r, "<td>", ap_escape_html(r->pool, balancer->s->sticky), " | ",
                              ap_escape_html(r->pool, balancer->s->sticky_path), NULL);
                }
                else {
                    ap_rvputs(r, "<td>", ap_escape_html(r->pool, balancer->s->sticky), NULL);
                }
            }
            else {
                ap_rputs("<td> (None) ", r);
            }
            ap_rprintf(r, "</td><td>%s</td>\n",
                       balancer->s->sticky_force ? "On" : "Off");
            ap_rprintf(r, "<td>%" APR_TIME_T_FMT "</td>",
                apr_time_sec(balancer->s->timeout));
            ap_rprintf(r, "<td>%d</td>\n", balancer->s->max_attempts);
            ap_rprintf(r, "<td>%s</td>\n",
                       balancer->s->lbpname);
            ap_rputs("<td>", r);
            if (*balancer->s->vhost) {
                ap_rvputs(r, balancer->s->vhost, " -> ", NULL);
            }
            ap_rvputs(r, balancer->s->vpath, "</td>\n", NULL);
            ap_rprintf(r, "<td>%s</td>\n",
                       !balancer->s->inactive ? "Yes" : "No");
            ap_rputs("</tr>\n</table>\n<br />", r);
            ap_rputs("\n\n<table><tr>"
                "<th>Worker URL</th>"
                "<th>Route</th><th>RouteRedir</th>"
                "<th>Factor</th><th>Set</th><th>Status</th>"
                "<th>Elected</th><th>Busy</th><th>Load</th><th>To</th><th>From</th>", r);
            if (set_worker_hc_param_f) {
                ap_rputs("<th>HC Method</th><th>HC Interval</th><th>Passes</th><th>Fails</th><th>HC uri</th><th>HC Expr</th>", r);
            }
            ap_rputs("</tr>\n", r);

            workers = (proxy_worker **)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                char fbuf[50];
                worker = *workers;
                ap_rvputs(r, "<tr>\n<td><a href=\"",
                          ap_escape_uri(r->pool, r->uri), "?b=",
                          balancer->s->name + sizeof(BALANCER_PREFIX) - 1, "&amp;w=",
                          ap_escape_uri(r->pool, worker->s->name_ex),
                          "&amp;nonce=", balancer->s->nonce,
                          "\">", NULL);
                ap_rvputs(r, (*worker->s->uds_path ? "<i>" : ""), ap_proxy_worker_name(r->pool, worker),
                          (*worker->s->uds_path ? "</i>" : ""), "</a></td>", NULL);
                ap_rvputs(r, "<td>", ap_escape_html(r->pool, worker->s->route),
                          NULL);
                ap_rvputs(r, "</td><td>",
                          ap_escape_html(r->pool, worker->s->redirect), NULL);
                ap_rprintf(r, "</td><td>%.2f</td>", (float)(worker->s->lbfactor)/100.0);
                ap_rprintf(r, "<td>%d</td><td>", worker->s->lbset);
                ap_rvputs(r, ap_proxy_parse_wstatus(r->pool, worker), NULL);
                ap_rputs("</td>", r);
                ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td>", worker->s->elected);
                ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td>", worker->s->busy);
                ap_rprintf(r, "<td>%d</td><td>", worker->s->lbstatus);
                ap_rputs(apr_strfsize(worker->s->transferred, fbuf), r);
                ap_rputs("</td><td>", r);
                ap_rputs(apr_strfsize(worker->s->read, fbuf), r);
                if (set_worker_hc_param_f) {
                    ap_rprintf(r, "</td><td>%s</td>", ap_proxy_show_hcmethod(worker->s->method));
                    ap_rprintf(r, "<td>%" APR_TIME_T_FMT "ms</td>", apr_time_as_msec(worker->s->interval));
                    ap_rprintf(r, "<td>%d (%d)</td>", worker->s->passes,worker->s->pcount);
                    ap_rprintf(r, "<td>%d (%d)</td>", worker->s->fails, worker->s->fcount);
                    ap_rprintf(r, "<td>%s</td>", ap_escape_html(r->pool, worker->s->hcuri));
                    ap_rprintf(r, "<td>%s", worker->s->hcexpr);
                }
                ap_rputs("</td></tr>\n", r);

                ++workers;
            }
            ap_rputs("</table>\n", r);
            ++balancer;
        }
        ap_rputs("<hr />\n", r);
        if (hc_show_exprs_f) {
            hc_show_exprs_f(r);
        }
        if (wsel && bsel) {
            ap_rputs("<h3>Edit worker settings for ", r);
            ap_rvputs(r, (*wsel->s->uds_path?"<i>":""), ap_proxy_worker_name(r->pool, wsel), (*wsel->s->uds_path?"</i>":""), "</h3>\n", NULL);
            ap_rputs("<form method='POST' enctype='application/x-www-form-urlencoded' action=\"", r);
            ap_rvputs(r, ap_escape_uri(r->pool, action), "\">\n", NULL);
            ap_rputs("<table><tr><td>Load factor:</td><td><input name='w_lf' id='w_lf' type=text ", r);
            ap_rprintf(r, "value='%.2f'></td></tr>\n", (float)(wsel->s->lbfactor)/100.0);
            ap_rputs("<tr><td>LB Set:</td><td><input name='w_ls' id='w_ls' type=text ", r);
            ap_rprintf(r, "value='%d'></td></tr>\n", wsel->s->lbset);
            ap_rputs("<tr><td>Route:</td><td><input name='w_wr' id='w_wr' type=text ", r);
            ap_rvputs(r, "value=\"", ap_escape_html(r->pool, wsel->s->route),
                      NULL);
            ap_rputs("\"></td></tr>\n", r);
            ap_rputs("<tr><td>Route Redirect:</td><td><input name='w_rr' id='w_rr' type=text ", r);
            ap_rvputs(r, "value=\"", ap_escape_html(r->pool, wsel->s->redirect),
                      NULL);
            ap_rputs("\"></td></tr>\n", r);
            ap_rputs("<tr><td>Status:</td>", r);
            ap_rputs("<td><table><tr>"
                     "<th>Ignore Errors</th>"
                     "<th>Draining Mode</th>"
                     "<th>Disabled</th>"
                     "<th>Hot Standby</th>"
                     "<th>Hot Spare</th>", r);
            if (hc_show_exprs_f) {
                ap_rputs("<th>HC Fail</th>", r);
            }
            ap_rputs("<th>Stopped</th></tr>\n<tr>", r);
            create_radio("w_status_I", (PROXY_WORKER_IS(wsel, PROXY_WORKER_IGNORE_ERRORS)), r);
            create_radio("w_status_N", (PROXY_WORKER_IS(wsel, PROXY_WORKER_DRAIN)), r);
            create_radio("w_status_D", (PROXY_WORKER_IS(wsel, PROXY_WORKER_DISABLED)), r);
            create_radio("w_status_H", (PROXY_WORKER_IS(wsel, PROXY_WORKER_HOT_STANDBY)), r);
            create_radio("w_status_R", (PROXY_WORKER_IS(wsel, PROXY_WORKER_HOT_SPARE)), r);
            if (hc_show_exprs_f) {
                create_radio("w_status_C", (PROXY_WORKER_IS(wsel, PROXY_WORKER_HC_FAIL)), r);
            }
            create_radio("w_status_S", (PROXY_WORKER_IS(wsel, PROXY_WORKER_STOPPED)), r);
            ap_rputs("</tr></table></td></tr>\n", r);
            if (hc_select_exprs_f) {
                proxy_hcmethods_t *method = proxy_hcmethods;
                ap_rputs("<tr><td colspan='2'>\n<table align='center'><tr><th>Health Check param</th><th>Value</th></tr>\n", r);
                ap_rputs("<tr><td>Method</td><td><select name='w_hm'>\n", r);
                for (; method->name; method++) {
                    if (method->implemented) {
                        ap_rprintf(r, "<option value='%s' %s >%s</option>\n",
                                method->name,
                                (wsel->s->method == method->method) ? "selected" : "",
                                method->name);
                    }
                }
                ap_rputs("</select>\n</td></tr>\n", r);
                ap_rputs("<tr><td>Expr</td><td><select name='w_he'>\n", r);
                hc_select_exprs_f(r, wsel->s->hcexpr);
                ap_rputs("</select>\n</td></tr>\n", r);
                ap_rprintf(r, "<tr><td>Interval (ms)</td><td><input name='w_hi' id='w_hi' type='text' "
                           "value='%" APR_TIME_T_FMT "'></td></tr>\n", apr_time_as_msec(wsel->s->interval));
                ap_rprintf(r, "<tr><td>Passes trigger</td><td><input name='w_hp' id='w_hp' type='text' "
                           "value='%d'></td></tr>\n", wsel->s->passes);
                ap_rprintf(r, "<tr><td>Fails trigger)</td><td><input name='w_hf' id='w_hf' type='text' "
                           "value='%d'></td></tr>\n", wsel->s->fails);
                ap_rprintf(r, "<tr><td>HC uri</td><td><input name='w_hu' id='w_hu' type='text' "
                           "value=\"%s\"></td></tr>\n", ap_escape_html(r->pool, wsel->s->hcuri));
                ap_rputs("</table>\n</td></tr>\n", r);
            }
            ap_rputs("<tr><td colspan='2'><input type=submit value='Submit'></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name='w' id='w' ",  NULL);
            ap_rvputs(r, "value=\"", ap_escape_uri(r->pool, wsel->s->name_ex), "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name='b' id='b' ", NULL);
            ap_rvputs(r, "value=\"", ap_escape_html(r->pool, bsel->s->name + sizeof(BALANCER_PREFIX) - 1),
                      "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name='nonce' id='nonce' value='",
                      bsel->s->nonce, "'>\n", NULL);
            ap_rputs("</form>\n", r);
            ap_rputs("<hr />\n", r);
        } else if (bsel) {
            const apr_array_header_t *provs;
            const ap_list_provider_names_t *pname;
            int i;
            ap_rputs("<h3>Edit balancer settings for ", r);
            ap_rvputs(r, ap_escape_html(r->pool, bsel->s->name), "</h3>\n", NULL);
            ap_rputs("<form method='POST' enctype='application/x-www-form-urlencoded' action=\"", r);
            ap_rvputs(r, ap_escape_uri(r->pool, action), "\">\n", NULL);
            ap_rputs("<table>\n", r);
            provs = ap_list_provider_names(r->pool, PROXY_LBMETHOD, "0");
            if (provs) {
                ap_rputs("<tr><td>LBmethod:</td>", r);
                ap_rputs("<td>\n<select name='b_lbm' id='b_lbm'>", r);
                pname = (ap_list_provider_names_t *)provs->elts;
                for (i = 0; i < provs->nelts; i++, pname++) {
                    ap_rvputs(r,"<option value='", pname->provider_name, "'", NULL);
                    if (strcmp(pname->provider_name, bsel->s->lbpname) == 0)
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
            ap_rputs("</tr>\n", r);
            ap_rputs("<tr><td>Sticky Session:</td><td><input name='b_ss' id='b_ss' size=64 type=text ", r);
            if (strcmp(bsel->s->sticky, bsel->s->sticky_path)) {
                ap_rvputs(r, "value =\"", ap_escape_html(r->pool, bsel->s->sticky), " | ",
                          ap_escape_html(r->pool, bsel->s->sticky_path), NULL);
            }
            else {
                ap_rvputs(r, "value =\"", ap_escape_html(r->pool, bsel->s->sticky), NULL);
            }
            ap_rputs("\">&nbsp;&nbsp;&nbsp;&nbsp;(Use '-' to delete)</td></tr>\n", r);
            if (storage->num_free_slots(bsel->wslot) != 0) {
                ap_rputs("<tr><td>Add New Worker:</td><td><input name='b_nwrkr' id='b_nwrkr' size=32 type=text>"
                         "&nbsp;&nbsp;&nbsp;&nbsp;Are you sure? <input name='b_wyes' id='b_wyes' type=checkbox value='1'>"
                         "</td></tr>", r);
            }
            ap_rputs("<tr><td colspan=2><input type=submit value='Submit'></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name='b' id='b' ", NULL);
            ap_rvputs(r, "value=\"", ap_escape_html(r->pool, bsel->s->name + sizeof(BALANCER_PREFIX) - 1),
                      "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name='nonce' id='nonce' value='",
                      bsel->s->nonce, "'>\n", NULL);
            ap_rputs("</form>\n", r);
            ap_rputs("<hr />\n", r);
        }
        ap_rputs(ap_psignature("",r), r);
        ap_rputs("</body></html>\n", r);
        ap_rflush(r);
    }
}

/* Manages the loadfactors and member status
 *   The balancer, worker and nonce are obtained from
 *   the request args (?b=...&w=...&nonce=....).
 *   All other params are pulled from any POST
 *   data that exists.
 * TODO:
 *   /.../<whatever>/balancer/worker/nonce
 */
static int balancer_handler(request_rec *r)
{
    void *sconf;
    proxy_server_conf *conf;
    proxy_balancer *balancer, *bsel = NULL;
    proxy_worker *wsel = NULL;
    apr_table_t *params;
    int i;
    const char *name, *ref;
    apr_status_t rv;

    /* is this for us? */
    if (strcmp(r->handler, "balancer-manager")) {
        return DECLINED;
    }

    r->allowed = 0
    | (AP_METHOD_BIT << M_GET)
    | (AP_METHOD_BIT << M_POST);
    if ((r->method_number != M_GET) && (r->method_number != M_POST)) {
        return DECLINED;
    }

    sconf = r->server->module_config;
    conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    params = apr_table_make(r->pool, 10);

    balancer = (proxy_balancer *)conf->balancers->elts;
    for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
#if APR_HAS_THREADS
        if ((rv = PROXY_THREAD_LOCK(balancer)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01189)
                          "%s: Lock failed for balancer_handler",
                          balancer->s->name);
        }
#endif
        ap_proxy_sync_balancer(balancer, r->server, conf);
#if APR_HAS_THREADS
        if ((rv = PROXY_THREAD_UNLOCK(balancer)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01190)
                          "%s: Unlock failed for balancer_handler",
                          balancer->s->name);
        }
#endif
    }

    if (r->args && (r->method_number == M_GET)) {
        const char *allowed[] = { "w", "b", "nonce", "xml", NULL };
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01191) "parsing r->args");

        push2table(r->args, params, allowed, r->pool);
    }
    if (r->method_number == M_POST) {
        apr_bucket_brigade *ib;
        apr_size_t len = 1024;
        char *buf = apr_pcalloc(r->pool, len+1);

        ib = apr_brigade_create(r->connection->pool, r->connection->bucket_alloc);
        rv = ap_get_brigade(r->input_filters, ib, AP_MODE_READBYTES,
                                APR_BLOCK_READ, len);
        if (rv != APR_SUCCESS) {
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }
        apr_brigade_flatten(ib, buf, &len);
        buf[len] = '\0';
        push2table(buf, params, NULL, r->pool);
    }

    /* Ignore parameters if this looks like XSRF */
    ref = apr_table_get(r->headers_in, "Referer");
    if (apr_table_elts(params)
        && (!ref || !safe_referer(r, ref))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10187)
                      "ignoring params in balancer-manager cross-site access %s: %s", ref, ap_get_server_name(r));
        apr_table_clear(params);
    }

    /* Process the parameters */
    if ((name = apr_table_get(params, "b")))
        bsel = ap_proxy_get_balancer(r->pool, conf,
            apr_pstrcat(r->pool, BALANCER_PREFIX, name, NULL), 0);

    if ((name = apr_table_get(params, "w"))) {
        wsel = ap_proxy_get_worker(r->pool, bsel, conf, name);
    }


    /* Check that the supplied nonce matches this server's nonce;
     * otherwise ignore all parameters, to prevent a CSRF
     * attack. */
    if (bsel
        && (*bsel->s->nonce
            && ((name = apr_table_get(params, "nonce")) != NULL
                && strcmp(bsel->s->nonce, name) == 0))) {
        /* Process the parameters and add the worker to the balancer */
        rv = balancer_process_balancer_worker(r, conf, bsel, wsel, params);
        if (rv != APR_SUCCESS) {
            return HTTP_BAD_REQUEST;
        }
    }

    /* display the HTML or XML page */
    if (apr_table_get(params, "xml")) {
        balancer_display_page(r, conf, bsel, wsel, 1);
    } else {
        balancer_display_page(r, conf, bsel, wsel, 0);
    }
    return DONE;
}

static void balancer_child_init(apr_pool_t *p, server_rec *s)
{
    while (s) {
        proxy_balancer *balancer;
        int i;
        void *sconf = s->module_config;
        proxy_server_conf *conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        apr_status_t rv;

        if (conf->balancers->nelts) {
            apr_size_t size;
            unsigned int num;
            storage->attach(&(conf->bslot), conf->id, &size, &num, p);
            if (!conf->bslot) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(01205) "slotmem_attach failed");
                exit(1); /* Ugly, but what else? */
            }
        }

        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
            rv = ap_proxy_initialize_balancer(balancer, s, p);

            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(01206)
                             "Failed to init balancer %s in child",
                             balancer->s->name);
                exit(1); /* Ugly, but what else? */
            }
            init_balancer_members(p, s, balancer);
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
    static const char *const aszPred2[] = { "mod_proxy.c", NULL};
     /* manager handler */
    APR_REGISTER_OPTIONAL_FN(balancer_manage);
    ap_hook_post_config(balancer_post_config, aszPred2, NULL, APR_HOOK_MIDDLE);
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
