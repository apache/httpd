/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
#include "ap_mpm.h"
#include "apr_version.h"

module AP_MODULE_DECLARE_DATA proxy_balancer_module;

#if APR_HAS_THREADS
#define PROXY_BALANCER_LOCK(b)      apr_thread_mutex_lock((b)->mutex)
#define PROXY_BALANCER_UNLOCK(b)    apr_thread_mutex_unlock((b)->mutex)
#else
#define PROXY_BALANCER_LOCK(b)      APR_SUCCESS
#define PROXY_BALANCER_UNLOCK(b)    APR_SUCCESS
#endif

/* Retrieve the parameter with the given name                                */
static char *get_path_param(apr_pool_t *pool, char *url,
                            const char *name)
{
    char *path = NULL;
    
    for (path = strstr(url, name); path; path = strstr(path + 1, name)) {
        path += (strlen(name) + 1);
        if (*path == '=') {
            /*
             * Session path was found, get it's value
             */
            ++path;
            if (strlen(path)) {
                char *q;
                path = apr_pstrdup(pool, path);
                if ((q = strchr(path, '?')))
                    *q = '\0';
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
        for (start_cookie = strstr(cookies, name); start_cookie; 
             start_cookie = strstr(start_cookie + 1, name)) {
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

static proxy_runtime_worker *find_route_worker(proxy_balancer *balancer,
                                               const char *route)
{
    int i;
    proxy_runtime_worker *worker = (proxy_runtime_worker *)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++) {
        if (worker->route && strcmp(worker->route, route) == 0) {
            return worker;
        }
        worker++;
    }
    return NULL;
}

static proxy_runtime_worker *find_session_route(proxy_balancer *balancer,
                                                request_rec *r,
                                                char **route,
                                                char **url)
{
    if (!balancer->sticky)
        return NULL;
    /* Try to find the sticky route inside url */
    *route = get_path_param(r->pool, *url, balancer->sticky);
    if (!*route)
        *route = get_cookie_param(r, balancer->sticky);
    if (*route) {
        proxy_runtime_worker *worker =  find_route_worker(balancer, *route);
        /* TODO: make worker status codes */
        /* See if we have a redirection route */
        if (worker && worker->w->status < 2 && worker->redirect)
            worker = find_route_worker(balancer, worker->redirect);
        else
            worker = NULL;
        return worker;
    }
    else
        return NULL;
}

static proxy_runtime_worker *find_best_worker(proxy_balancer *balancer,
                                              request_rec *r)
{
    int i;
    double total_factor = 0.0;
    proxy_runtime_worker *worker = (proxy_runtime_worker *)balancer->workers->elts;
    proxy_runtime_worker *candidate = NULL;

    /* First try to see if we have available candidate */
    for (i = 0; i < balancer->workers->nelts; i++) {
        /* If the worker is not error state
         * or not in disabled mode
         */

        /* TODO: read the scoreboard status */
        if (worker->w->status < 2) {
            if (!candidate)
                candidate = worker;
            else {
                /* See if the worker has a larger number of free channels */
                if (worker->w->cp->nfree > candidate->w->cp->nfree)
                    candidate = worker;
            }
            /* Total factor should allways be 100.
             * This is for cases when worker is in error state.
             * It will force the even request distribution
             */
            total_factor += worker->lbfactor;
        }
        worker++;
    }
    if (!candidate) {
        /* All the workers are in error state or disabled.
         * If the balancer has a timeout wait.
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
    else {
        /* We have at least one candidate that is not in
         * error state or disabled.
         * Now calculate the appropriate one 
         */
        for (i = 0; i < balancer->workers->nelts; i++) {
            /* If the worker is not error state
             * or not in disabled mode
             */
            if (worker->w->status > 2) {
                /* 1. Find the worker with higher lbstatus.
                 * Lbstatus is of higher importance then
                 * the number of empty slots.
                 */
                if (worker->lbstatus > candidate->lbstatus) {
                    candidate = worker;
                }
            }
            worker++;
        }
        for (i = 0; i < balancer->workers->nelts; i++) {
            /* If the worker is not error state
             * or not in disabled mode
             */
            if (worker->w->status > 2) {
                /* XXX: The lbfactor can be update using bytes transfered
                 * Right now, use the round-robin scheme
                 */
                worker->lbstatus += worker->lbfactor;
                if (worker->lbstatus >= total_factor)
                    worker->lbstatus = worker->lbfactor;
            }
            worker++;
        }
    }
    return candidate;
}

static int proxy_balancer_pre_request(proxy_worker **worker,
                                      proxy_balancer **balancer,
                                      request_rec *r,
                                      proxy_server_conf *conf, char **url)
{
    int access_status = OK;
    proxy_runtime_worker *runtime;
    char *route;
    apr_status_t rv;

    *worker = NULL;
    /* Spet 1: check if the url is for us */
    if (!(*balancer = ap_proxy_get_balancer(r->pool, conf, *url)))
        return DECLINED;
    
    /* Step 2: find the session route */
    
    runtime = find_session_route(*balancer, r, &route, url);
    if (!runtime) {
        if (route && (*balancer)->sticky_force) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "balancer: (%s). All workers in error state for route (%s)",
                         (*balancer)->name, route);
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }
    else {
        /* We have a sticky load balancer */
        *worker = runtime->w;
    }
    /* Lock the LoadBalancer
     * XXX: perhaps we need the process lock here
     */
    if ((rv = PROXY_BALANCER_LOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy_balancer_pre_request: lock");
        return DECLINED;
    }
    if (!*worker) {
        runtime = find_best_worker(*balancer, r);
        if (!runtime) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "balancer: (%s). All workers in error state.",
                         (*balancer)->name);
        
            PROXY_BALANCER_UNLOCK(*balancer);
            return HTTP_SERVICE_UNAVAILABLE;
        }
        /* TODO: rewrite the url to coresponds to worker scheme */

        *worker = runtime->w;
    }
    /* Decrease the free channels number */
    if ((*worker)->cp->nfree)
        --(*worker)->cp->nfree;

    PROXY_BALANCER_UNLOCK(*balancer);

    return access_status;
} 

static int proxy_balancer_post_request(proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf)
{
    int access_status;
    if (!balancer)
        access_status = DECLINED;
    else { 
        apr_status_t rv;
        if ((rv = PROXY_BALANCER_LOCK(balancer)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy_balancer_post_request: lock");
            return DECLINED;
        }
        /* increase the free channels number */
        if (worker->cp->nfree)
            worker->cp->nfree++;
        /* TODO: calculate the bytes transfered */

        /* TODO: update the scoreboard status */

        PROXY_BALANCER_UNLOCK(balancer);        
        access_status = OK;
    }

    return access_status;
} 

static void ap_proxy_balancer_register_hook(apr_pool_t *p)
{
    proxy_hook_pre_request(proxy_balancer_pre_request, NULL, NULL, APR_HOOK_FIRST);    
    proxy_hook_post_request(proxy_balancer_post_request, NULL, NULL, APR_HOOK_FIRST);    
}

module AP_MODULE_DECLARE_DATA proxy_balancer_module = {
    STANDARD20_MODULE_STUFF,
    NULL,		/* create per-directory config structure */
    NULL,		/* merge per-directory config structures */
    NULL,		/* create per-server config structure */
    NULL,		/* merge per-server config structures */
    NULL,		/* command apr_table_t */
    ap_proxy_balancer_register_hook	/* register hooks */
};
