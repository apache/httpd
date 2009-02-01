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

#define CORE_PRIVATE

#include "mod_proxy.h"
#include "scoreboard.h"
#include "ap_mpm.h"
#include "apr_version.h"
#include "apr_hooks.h"
#include "apr_uuid.h"

module AP_MODULE_DECLARE_DATA proxy_balancer_module;

static char balancer_nonce[APR_UUID_FORMATTED_LENGTH + 1];

static int proxy_balancer_canon(request_rec *r, char *url)
{
    char *host, *path;
    char *search = NULL;
    const char *err;
    apr_port_t port = 0;

    if (strncasecmp(url, "balancer:", 9) == 0) {
        url += 9;
    }
    else {
        return DECLINED;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
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

    r->filename = apr_pstrcat(r->pool, "proxy:balancer://", host,
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}

static int init_balancer_members(proxy_server_conf *conf, server_rec *s,
                                 proxy_balancer *balancer)
{
    int i;
    proxy_worker *workers;
    int worker_is_initialized;
    proxy_worker_stat *slot;

    workers = (proxy_worker *)balancer->workers->elts;

    for (i = 0; i < balancer->workers->nelts; i++) {
        worker_is_initialized = PROXY_WORKER_IS_INITIALIZED(workers);
        if (!worker_is_initialized) {
            /*
             * If the worker is not initialized check whether its scoreboard
             * slot is already initialized.
             */
            slot = (proxy_worker_stat *) ap_get_scoreboard_lb(workers->id);
            if (slot) {
                worker_is_initialized = slot->status & PROXY_WORKER_INITIALIZED;
            }
            else {
                worker_is_initialized = 0;
            }
        }
        ap_proxy_initialize_worker_share(conf, workers, s);
        ap_proxy_initialize_worker(workers, s);
        if (!worker_is_initialized) {
            /* Set to the original configuration */
            workers->s->lbstatus = workers->s->lbfactor =
            (workers->lbfactor ? workers->lbfactor : 1);
            workers->s->lbset = workers->lbset;
        }
        ++workers;
    }

    /* Set default number of attempts to the number of
     * workers.
     */
    if (!balancer->max_attempts_set && balancer->workers->nelts > 1) {
        balancer->max_attempts = balancer->workers->nelts - 1;
        balancer->max_attempts_set = 1;
    }
    return 0;
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
            if (strlen(path)) {
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
                if (*start_cookie == '=' && start_cookie[1]) {
                    /*
                     * Session cookie was found, get it's value
                     */
                    char *end_cookie, *cookie;
                    ++start_cookie;
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
    
    proxy_worker *worker;

    checking_standby = checked_standby = 0;
    while (!checked_standby) {
        worker = (proxy_worker *)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++, worker++) {
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
                                        char **sticky_used,
                                        char **url)
{
    proxy_worker *worker = NULL;
    char *sticky, *sticky_path, *path;

    if (!balancer->sticky)
        return NULL;
    sticky = sticky_path = apr_pstrdup(r->pool, balancer->sticky);
    if ((path = strchr(sticky, '|'))) {
        *path++ = '\0';
         sticky_path = path;
    }
    
    /* Try to find the sticky route inside url */
    *sticky_used = sticky_path;
    *route = get_path_param(r->pool, *url, sticky_path, balancer->scolonsep);
    if (!*route) {
        *route = get_cookie_param(r, sticky);
        *sticky_used = sticky;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                            "proxy: BALANCER: Found value %s for "
                            "stickysession %s", *route, balancer->sticky);
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

    if ((rv = PROXY_THREAD_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
        "proxy: BALANCER: (%s). Lock failed for find_best_worker()", balancer->name);
        return NULL;
    }

    candidate = (*balancer->lbmethod->finder)(balancer, r);

    if (candidate)
        candidate->s->elected++;

/*
        PROXY_THREAD_UNLOCK(balancer);
        return NULL;
*/

    if ((rv = PROXY_THREAD_UNLOCK(balancer)) != APR_SUCCESS) {
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
#if APR_HAS_THREADS
        if (balancer->timeout) {
            /* XXX: This can perhaps be build using some
             * smarter mechanism, like tread_cond.
             * But since the statuses can came from
             * different childs, use the provided algo.
             */
            apr_interval_time_t timeout = balancer->timeout;
            apr_interval_time_t step, tval = 0;
            /* Set the timeout to 0 so that we don't
             * end in infinite loop
             */
            balancer->timeout = 0;
            step = timeout / 100;
            while (tval < timeout) {
                apr_sleep(step);
                /* Try again */
                if ((candidate = find_best_worker(balancer, r)))
                    break;
                tval += step;
            }
            /* restore the timeout */
            balancer->timeout = timeout;
        }
#endif
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

    *url = apr_pstrcat(r->pool, worker->name, path, NULL);

    return OK;
}

static void force_recovery(proxy_balancer *balancer, server_rec *s)
{
    int i;
    int ok = 0;
    proxy_worker *worker;

    worker = (proxy_worker *)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++, worker++) {
        if (!(worker->s->status & PROXY_WORKER_IN_ERROR)) {
            ok = 1;
            break;
        }
        else {
            /* Try if we can recover */
            ap_proxy_retry_worker("BALANCER", worker, s);
            if (!(worker->s->status & PROXY_WORKER_IN_ERROR)) {
                ok = 1;
                break;
            }
        }
    }
    if (!ok) {
        /* If all workers are in error state force the recovery.
         */
        worker = (proxy_worker *)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++, worker++) {
            ++worker->s->retries;
            worker->s->status &= ~PROXY_WORKER_IN_ERROR;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "proxy: BALANCER: (%s). Forcing recovery for worker (%s)",
                         balancer->name, worker->hostname);
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
    char *sticky = NULL;
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
    if ((rv = PROXY_THREAD_LOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: BALANCER: (%s). Lock failed for pre_request",
                     (*balancer)->name);
        return DECLINED;
    }

    /* Step 3: force recovery */
    force_recovery(*balancer, r->server);

    /* Step 4: find the session route */
    runtime = find_session_route(*balancer, r, &route, &sticky, url);
    if (runtime) {
        int i, total_factor = 0;
        proxy_worker *workers;
        /* We have a sticky load balancer
         * Update the workers status
         * so that even session routes get
         * into account.
         */
        workers = (proxy_worker *)(*balancer)->workers->elts;
        for (i = 0; i < (*balancer)->workers->nelts; i++) {
            /* Take into calculation only the workers that are
             * not in error state or not disabled.
             *
             * TODO: Abstract the below, since this is dependent
             *       on the LB implementation
             */
            if (PROXY_WORKER_IS_USABLE(workers)) {
                workers->s->lbstatus += workers->s->lbfactor;
                total_factor += workers->s->lbfactor;
            }
            workers++;
        }
        runtime->s->lbstatus -= total_factor;
        runtime->s->elected++;

        *worker = runtime;
    }
    else if (route && (*balancer)->sticky_force) {
        int i, member_of = 0;
        proxy_worker *workers;
        /*
         * We have a route provided that doesn't match the
         * balancer name. See if the provider route is the
         * member of the same balancer in which case return 503
         */
        workers = (proxy_worker *)(*balancer)->workers->elts;
        for (i = 0; i < (*balancer)->workers->nelts; i++) {
            if (*(workers->s->route) && strcmp(workers->s->route, route) == 0) {
                member_of = 1;
                break;
            }
            workers++;
        }
        if (member_of) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: BALANCER: (%s). All workers are in error state for route (%s)",
                         (*balancer)->name, route);
            if ((rv = PROXY_THREAD_UNLOCK(*balancer)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                             "proxy: BALANCER: (%s). Unlock failed for pre_request",
                             (*balancer)->name);
            }
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }

    if ((rv = PROXY_THREAD_UNLOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: BALANCER: (%s). Unlock failed for pre_request",
                     (*balancer)->name);
    }
    if (!*worker) {
        runtime = find_best_worker(*balancer, r);
        if (!runtime) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: BALANCER: (%s). All workers are in error state",
                         (*balancer)->name);

            return HTTP_SERVICE_UNAVAILABLE;
        }
        if ((*balancer)->sticky && runtime) {
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
                   "BALANCER_WORKER_NAME", (*worker)->name);
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
                 (*balancer)->name, (*worker)->name, *url);

    return access_status;
}

static int proxy_balancer_post_request(proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf)
{

#if 0
    apr_status_t rv;

    if ((rv = PROXY_THREAD_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "proxy: BALANCER: (%s). Lock failed for post_request",
            balancer->name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* TODO: placeholder for post_request actions
     */

    if ((rv = PROXY_THREAD_UNLOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "proxy: BALANCER: (%s). Unlock failed for post_request",
            balancer->name);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy_balancer_post_request for (%s)", balancer->name);

#endif

    if (worker && worker->s->busy)
        worker->s->busy--;

    return OK;

}

static void recalc_factors(proxy_balancer *balancer)
{
    int i;
    proxy_worker *workers;


    /* Recalculate lbfactors */
    workers = (proxy_worker *)balancer->workers->elts;
    /* Special case if there is only one worker it's
     * load factor will always be 1
     */
    if (balancer->workers->nelts == 1) {
        workers->s->lbstatus = workers->s->lbfactor = 1;
        return;
    }
    for (i = 0; i < balancer->workers->nelts; i++) {
        /* Update the status entries */
        workers[i].s->lbstatus = workers[i].s->lbfactor;
    }
}

/* post_config hook: */
static int balancer_init(apr_pool_t *p, apr_pool_t *plog,
                         apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *userdata_key = "mod_proxy_balancer_init";
    apr_uuid_t uuid;

    /* balancer_init() will be called twice during startup.  So, only
     * set up the static data the second time through. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /* Retrieve a UUID and store the nonce for the lifetime of
     * the process. */
    apr_uuid_get(&uuid);
    apr_uuid_format(balancer_nonce, &uuid);

    return OK;
}

/* Manages the loadfactors and member status
 */
static int balancer_handler(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    proxy_balancer *balancer, *bsel = NULL;
    proxy_worker *worker, *wsel = NULL;
    apr_table_t *params = apr_table_make(r->pool, 10);
    int access_status;
    int i, n;
    const char *name;

    /* is this for us? */
    if (strcmp(r->handler, "balancer-manager"))
        return DECLINED;
    r->allowed = (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

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
    
    /* Check that the supplied nonce matches this server's nonce;
     * otherwise ignore all parameters, to prevent a CSRF attack. */
    if ((name = apr_table_get(params, "nonce")) == NULL 
        || strcmp(balancer_nonce, name) != 0) {
        apr_table_clear(params);
    }

    if ((name = apr_table_get(params, "b")))
        bsel = ap_proxy_get_balancer(r->pool, conf,
            apr_pstrcat(r->pool, "balancer://", name, NULL));
    if ((name = apr_table_get(params, "w"))) {
        proxy_worker *ws;

        ws = ap_proxy_get_worker(r->pool, conf, name);
        if (bsel && ws) {
            worker = (proxy_worker *)bsel->workers->elts;
            for (n = 0; n < bsel->workers->nelts; n++) {
                if (strcasecmp(worker->name, ws->name) == 0) {
                    wsel = worker;
                    break;
                }
                ++worker;
            }
        }
    }
    /* First set the params */
    /*
     * Note that it is not possible set the proxy_balancer because it is not
     * in shared memory.
     */
    if (wsel) {
        const char *val;
        if ((val = apr_table_get(params, "lf"))) {
            int ival = atoi(val);
            if (ival >= 1 && ival <= 100) {
                wsel->s->lbfactor = ival;
                if (bsel)
                    recalc_factors(bsel);
            }
        }
        if ((val = apr_table_get(params, "wr"))) {
            if (strlen(val) && strlen(val) < PROXY_WORKER_MAX_ROUTE_SIZ)
                strcpy(wsel->s->route, val);
            else
                *wsel->s->route = '\0';
        }
        if ((val = apr_table_get(params, "rr"))) {
            if (strlen(val) && strlen(val) < PROXY_WORKER_MAX_ROUTE_SIZ)
                strcpy(wsel->s->redirect, val);
            else
                *wsel->s->redirect = '\0';
        }
        if ((val = apr_table_get(params, "dw"))) {
            if (!strcasecmp(val, "Disable"))
                wsel->s->status |= PROXY_WORKER_DISABLED;
            else if (!strcasecmp(val, "Enable"))
                wsel->s->status &= ~PROXY_WORKER_DISABLED;
        }
        if ((val = apr_table_get(params, "ls"))) {
            int ival = atoi(val);
            if (ival >= 0 && ival <= 99) {
                wsel->s->lbset = ival;
             }
        }

    }
    if (apr_table_get(params, "xml")) {
        ap_set_content_type(r, "text/xml");
        ap_rputs("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n", r);
        ap_rputs("<httpd:manager xmlns:httpd=\"http://httpd.apache.org\">\n", r);
        ap_rputs("  <httpd:balancers>\n", r);
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {
            ap_rputs("    <httpd:balancer>\n", r);
            ap_rvputs(r, "      <httpd:name>", balancer->name, "</httpd:name>\n", NULL);
            ap_rputs("      <httpd:workers>\n", r);
            worker = (proxy_worker *)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                ap_rputs("        <httpd:worker>\n", r);
                ap_rvputs(r, "          <httpd:scheme>", worker->scheme,
                          "</httpd:scheme>\n", NULL);
                ap_rvputs(r, "          <httpd:hostname>", worker->hostname,
                          "</httpd:hostname>\n", NULL);
               ap_rprintf(r, "          <httpd:loadfactor>%d</httpd:loadfactor>\n",
                          worker->s->lbfactor);
                ap_rputs("        </httpd:worker>\n", r);
                ++worker;
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
            ap_rvputs(r, balancer->name, "</h3>\n\n", NULL);
            ap_rputs("\n\n<table border=\"0\" style=\"text-align: left;\"><tr>"
                "<th>StickySession</th><th>Timeout</th><th>FailoverAttempts</th><th>Method</th>"
                "</tr>\n<tr>", r);
            if (balancer->sticky) {
                ap_rvputs(r, "<td>", balancer->sticky, NULL);
            }
            else {
                ap_rputs("<td> - ", r);
            }
            ap_rprintf(r, "</td><td>%" APR_TIME_T_FMT "</td>",
                apr_time_sec(balancer->timeout));
            ap_rprintf(r, "<td>%d</td>\n", balancer->max_attempts);
            ap_rprintf(r, "<td>%s</td>\n",
                       balancer->lbmethod->name);
            ap_rputs("</table>\n<br />", r);
            ap_rputs("\n\n<table border=\"0\" style=\"text-align: left;\"><tr>"
                "<th>Worker URL</th>"
                "<th>Route</th><th>RouteRedir</th>"
                "<th>Factor</th><th>Set</th><th>Status</th>"
                "<th>Elected</th><th>To</th><th>From</th>"
                "</tr>\n", r);

            worker = (proxy_worker *)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                char fbuf[50];
                ap_rvputs(r, "<tr>\n<td><a href=\"", r->uri, "?b=",
                          balancer->name + sizeof("balancer://") - 1, "&w=",
                          ap_escape_uri(r->pool, worker->name),
                          "&nonce=", balancer_nonce, 
                          "\">", NULL);
                ap_rvputs(r, worker->name, "</a></td>", NULL);
                ap_rvputs(r, "<td>", ap_escape_html(r->pool, worker->s->route),
                          NULL);
                ap_rvputs(r, "</td><td>",
                          ap_escape_html(r->pool, worker->s->redirect), NULL);
                ap_rprintf(r, "</td><td>%d</td>", worker->s->lbfactor);
                ap_rprintf(r, "<td>%d</td><td>", worker->s->lbset);
                if (worker->s->status & PROXY_WORKER_DISABLED)
                   ap_rputs("Dis ", r);
                if (worker->s->status & PROXY_WORKER_IN_ERROR)
                   ap_rputs("Err ", r);
                if (worker->s->status & PROXY_WORKER_STOPPED)
                   ap_rputs("Stop ", r);
                if (worker->s->status & PROXY_WORKER_HOT_STANDBY)
                   ap_rputs("Stby ", r);
                if (PROXY_WORKER_IS_USABLE(worker))
                    ap_rputs("Ok", r);
                if (!PROXY_WORKER_IS_INITIALIZED(worker))
                    ap_rputs("-", r);
                ap_rputs("</td>", r);
                ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td><td>", worker->s->elected);
                ap_rputs(apr_strfsize(worker->s->transferred, fbuf), r);
                ap_rputs("</td><td>", r);
                ap_rputs(apr_strfsize(worker->s->read, fbuf), r);
                ap_rputs("</td></tr>\n", r);

                ++worker;
            }
            ap_rputs("</table>\n", r);
            ++balancer;
        }
        ap_rputs("<hr />\n", r);
        if (wsel && bsel) {
            ap_rputs("<h3>Edit worker settings for ", r);
            ap_rvputs(r, wsel->name, "</h3>\n", NULL);
            ap_rvputs(r, "<form method=\"GET\" action=\"", NULL);
            ap_rvputs(r, r->uri, "\">\n<dl>", NULL);
            ap_rputs("<table><tr><td>Load factor:</td><td><input name=\"lf\" type=text ", r);
            ap_rprintf(r, "value=\"%d\"></td></tr>\n", wsel->s->lbfactor);
            ap_rputs("<tr><td>LB Set:</td><td><input name=\"ls\" type=text ", r);
            ap_rprintf(r, "value=\"%d\"></td></tr>\n", wsel->s->lbset);
            ap_rputs("<tr><td>Route:</td><td><input name=\"wr\" type=text ", r);
            ap_rvputs(r, "value=\"", ap_escape_html(r->pool, wsel->s->route),
                      NULL);
            ap_rputs("\"></td></tr>\n", r);
            ap_rputs("<tr><td>Route Redirect:</td><td><input name=\"rr\" type=text ", r);
            ap_rvputs(r, "value=\"", ap_escape_html(r->pool, wsel->s->redirect),
                      NULL);
            ap_rputs("\"></td></tr>\n", r);
            ap_rputs("<tr><td>Status:</td><td>Disabled: <input name=\"dw\" value=\"Disable\" type=radio", r);
            if (wsel->s->status & PROXY_WORKER_DISABLED)
                ap_rputs(" checked", r);
            ap_rputs("> | Enabled: <input name=\"dw\" value=\"Enable\" type=radio", r);
            if (!(wsel->s->status & PROXY_WORKER_DISABLED))
                ap_rputs(" checked", r);
            ap_rputs("></td></tr>\n", r);
            ap_rputs("<tr><td colspan=2><input type=submit value=\"Submit\"></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name=\"w\" ",  NULL);
            ap_rvputs(r, "value=\"", ap_escape_uri(r->pool, wsel->name), "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name=\"b\" ", NULL);
            ap_rvputs(r, "value=\"", bsel->name + sizeof("balancer://") - 1,
                      "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name=\"nonce\" value=\"", 
                      balancer_nonce, "\">\n", NULL);
            ap_rvputs(r, "</form>\n", NULL);
            ap_rputs("<hr />\n", r);
        }
        ap_rputs(ap_psignature("",r), r);
        ap_rputs("</body></html>\n", r);
    }
    return OK;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    while (s) {
        void *sconf = s->module_config;
        proxy_server_conf *conf;
        proxy_balancer *balancer;
        int i;
        conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);

        /* Initialize shared scoreboard data */
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {
            init_balancer_members(conf, s, balancer);
            balancer++;
        }
        s = s->next;
    }

}

/*
 * The idea behind the find_best_byrequests scheduler is the following:
 *
 * lbfactor is "how much we expect this worker to work", or "the worker's
 * normalized work quota".
 *
 * lbstatus is "how urgent this worker has to work to fulfill its quota
 * of work".
 *
 * We distribute each worker's work quota to the worker, and then look
 * which of them needs to work most urgently (biggest lbstatus).  This
 * worker is then selected for work, and its lbstatus reduced by the
 * total work quota we distributed to all workers.  Thus the sum of all
 * lbstatus does not change.(*)
 *
 * If some workers are disabled, the others will
 * still be scheduled correctly.
 *
 * If a balancer is configured as follows:
 *
 * worker     a    b    c    d
 * lbfactor  25   25   25   25
 *
 * And b gets disabled, the following schedule is produced:
 *
 *    a c d a c d a c d ...
 *
 * Note that the above lbfactor setting is the *exact* same as:
 *
 * worker     a    b    c    d
 * lbfactor   1    1    1    1
 *
 * Asymmetric configurations work as one would expect. For
 * example:
 *
 * worker     a    b    c    d
 * lbfactor   1    1    1    2
 *
 * would have a, b and c all handling about the same
 * amount of load with d handling twice what a or b
 * or c handles individually. So we could see:
 *
 *   b a d c d a c d b d ...
 *
 */

static proxy_worker *find_best_byrequests(proxy_balancer *balancer,
                                request_rec *r)
{
    int i;
    int total_factor = 0;
    proxy_worker *worker;
    proxy_worker *mycandidate = NULL;
    int cur_lbset = 0;
    int max_lbset = 0;
    int checking_standby;
    int checked_standby;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Entering byrequests for BALANCER (%s)",
                 balancer->name);

    /* First try to see if we have available candidate */
    do {
        checking_standby = checked_standby = 0;
        while (!mycandidate && !checked_standby) {
            worker = (proxy_worker *)balancer->workers->elts;
            for (i = 0; i < balancer->workers->nelts; i++, worker++) {
                if (!checking_standby) {    /* first time through */
                    if (worker->s->lbset > max_lbset)
                        max_lbset = worker->s->lbset;
                }
                if (worker->s->lbset > cur_lbset)
                    continue;
                if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(worker) : PROXY_WORKER_IS_STANDBY(worker)) )
                    continue;
                /* If the worker is in error state run
                 * retry on that worker. It will be marked as
                 * operational if the retry timeout is elapsed.
                 * The worker might still be unusable, but we try
                 * anyway.
                 */
                if (!PROXY_WORKER_IS_USABLE(worker))
                    ap_proxy_retry_worker("BALANCER", worker, r->server);
                /* Take into calculation only the workers that are
                 * not in error state or not disabled.
                 */
                if (PROXY_WORKER_IS_USABLE(worker)) {
                    worker->s->lbstatus += worker->s->lbfactor;
                    total_factor += worker->s->lbfactor;
                    if (!mycandidate || worker->s->lbstatus > mycandidate->s->lbstatus)
                        mycandidate = worker;
                }
            }
            checked_standby = checking_standby++;
        }
        cur_lbset++;
    } while (cur_lbset <= max_lbset && !mycandidate);

    if (mycandidate) {
        mycandidate->s->lbstatus -= total_factor;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: byrequests selected worker \"%s\" : busy %" APR_SIZE_T_FMT " : lbstatus %d",
                     mycandidate->name, mycandidate->s->busy, mycandidate->s->lbstatus);

    }

    return mycandidate;
}

/*
 * The idea behind the find_best_bytraffic scheduler is the following:
 *
 * We know the amount of traffic (bytes in and out) handled by each
 * worker. We normalize that traffic by each workers' weight. So assuming
 * a setup as below:
 *
 * worker     a    b    c
 * lbfactor   1    1    3
 *
 * the scheduler will allow worker c to handle 3 times the
 * traffic of a and b. If each request/response results in the
 * same amount of traffic, then c would be accessed 3 times as
 * often as a or b. If, for example, a handled a request that
 * resulted in a large i/o bytecount, then b and c would be
 * chosen more often, to even things out.
 */
static proxy_worker *find_best_bytraffic(proxy_balancer *balancer,
                                         request_rec *r)
{
    int i;
    apr_off_t mytraffic = 0;
    apr_off_t curmin = 0;
    proxy_worker *worker;
    proxy_worker *mycandidate = NULL;
    int cur_lbset = 0;
    int max_lbset = 0;
    int checking_standby;
    int checked_standby;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Entering bytraffic for BALANCER (%s)",
                 balancer->name);

    /* First try to see if we have available candidate */
    do {
        checking_standby = checked_standby = 0;
        while (!mycandidate && !checked_standby) {
            worker = (proxy_worker *)balancer->workers->elts;
            for (i = 0; i < balancer->workers->nelts; i++, worker++) {
                if (!checking_standby) {    /* first time through */
                    if (worker->s->lbset > max_lbset)
                        max_lbset = worker->s->lbset;
                }
                if (worker->s->lbset > cur_lbset)
                    continue;
                if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(worker) : PROXY_WORKER_IS_STANDBY(worker)) )
                    continue;
                /* If the worker is in error state run
                 * retry on that worker. It will be marked as
                 * operational if the retry timeout is elapsed.
                 * The worker might still be unusable, but we try
                 * anyway.
                 */
                if (!PROXY_WORKER_IS_USABLE(worker))
                    ap_proxy_retry_worker("BALANCER", worker, r->server);
                /* Take into calculation only the workers that are
                 * not in error state or not disabled.
                 */
                if (PROXY_WORKER_IS_USABLE(worker)) {
                    mytraffic = (worker->s->transferred/worker->s->lbfactor) +
                                (worker->s->read/worker->s->lbfactor);
                    if (!mycandidate || mytraffic < curmin) {
                        mycandidate = worker;
                        curmin = mytraffic;
                    }
                }
            }
            checked_standby = checking_standby++;
        }
        cur_lbset++;
    } while (cur_lbset <= max_lbset && !mycandidate);

    if (mycandidate) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: bytraffic selected worker \"%s\" : busy %" APR_SIZE_T_FMT,
                     mycandidate->name, mycandidate->s->busy);

    }

    return mycandidate;
}

static proxy_worker *find_best_bybusyness(proxy_balancer *balancer,
                                request_rec *r)
{

    int i;
    proxy_worker *worker;
    proxy_worker *mycandidate = NULL;
    int cur_lbset = 0;
    int max_lbset = 0;
    int checking_standby;
    int checked_standby;

    int total_factor = 0;
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy: Entering bybusyness for BALANCER (%s)",
                 balancer->name);

    /* First try to see if we have available candidate */
    do {

        checking_standby = checked_standby = 0;
        while (!mycandidate && !checked_standby) {

            worker = (proxy_worker *)balancer->workers->elts;
            for (i = 0; i < balancer->workers->nelts; i++, worker++) {
                if  (!checking_standby) {    /* first time through */
                    if (worker->s->lbset > max_lbset)
                        max_lbset = worker->s->lbset;
                }

                if (worker->s->lbset > cur_lbset)
                    continue;

                if ( (checking_standby ? !PROXY_WORKER_IS_STANDBY(worker) : PROXY_WORKER_IS_STANDBY(worker)) )
                    continue;

                /* If the worker is in error state run
                 * retry on that worker. It will be marked as
                 * operational if the retry timeout is elapsed.
                 * The worker might still be unusable, but we try
                 * anyway.
                 */
                if (!PROXY_WORKER_IS_USABLE(worker))
                    ap_proxy_retry_worker("BALANCER", worker, r->server);

                /* Take into calculation only the workers that are
                 * not in error state or not disabled.
                 */
                if (PROXY_WORKER_IS_USABLE(worker)) {

                    worker->s->lbstatus += worker->s->lbfactor;
                    total_factor += worker->s->lbfactor;
                    
                    if (!mycandidate
                        || worker->s->busy < mycandidate->s->busy
                        || (worker->s->busy == mycandidate->s->busy && worker->s->lbstatus > mycandidate->s->lbstatus))
                        mycandidate = worker;

                }

            }

            checked_standby = checking_standby++;

        }

        cur_lbset++;

    } while (cur_lbset <= max_lbset && !mycandidate);

    if (mycandidate) {
        mycandidate->s->lbstatus -= total_factor;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: bybusyness selected worker \"%s\" : busy %" APR_SIZE_T_FMT " : lbstatus %d",
                     mycandidate->name, mycandidate->s->busy, mycandidate->s->lbstatus);

    }

    return mycandidate;

}

/*
 * How to add additional lbmethods:
 *   1. Create func which determines "best" candidate worker
 *      (eg: find_best_bytraffic, above)
 *   2. Register it as a provider.
 */
static const proxy_balancer_method byrequests =
{
    "byrequests",
    &find_best_byrequests,
    NULL
};

static const proxy_balancer_method bytraffic =
{
    "bytraffic",
    &find_best_bytraffic,
    NULL
};

static const proxy_balancer_method bybusyness =
{
    "bybusyness",
    &find_best_bybusyness,
    NULL
};


static void ap_proxy_balancer_register_hook(apr_pool_t *p)
{
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes and after the mod_proxy
     */
    static const char *const aszPred[] = { "mpm_winnt.c", "mod_proxy.c", NULL};
     /* manager handler */
    ap_hook_post_config(balancer_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(balancer_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init(child_init, aszPred, NULL, APR_HOOK_MIDDLE);
    proxy_hook_pre_request(proxy_balancer_pre_request, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_post_request(proxy_balancer_post_request, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_balancer_canon, NULL, NULL, APR_HOOK_FIRST);
    ap_register_provider(p, PROXY_LBMETHOD, "bytraffic", "0", &bytraffic);
    ap_register_provider(p, PROXY_LBMETHOD, "byrequests", "0", &byrequests);
    ap_register_provider(p, PROXY_LBMETHOD, "bybusyness", "0", &bybusyness);
}

module AP_MODULE_DECLARE_DATA proxy_balancer_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    ap_proxy_balancer_register_hook /* register hooks */
};
