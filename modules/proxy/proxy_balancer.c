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

static proxy_runtime_worker *find_route_worker(proxy_balancer *balancer,
                                               const char *route)
{
    int i;
    proxy_runtime_worker *worker = (proxy_runtime_worker *)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++) {
        if (worker->w->route && strcmp(worker->w->route, route) == 0) {
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
        if (worker && !PROXY_WORKER_IS_USABLE(worker->w)) {
            if (worker->w->redirect)
                worker = find_route_worker(balancer, worker->w->redirect);
            /* Check if the redirect worker is usable */
            if (worker && !PROXY_WORKER_IS_USABLE(worker->w))
                worker = NULL;
        }
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
        /* See if the retry timeout is ellapsed
         * for the workers flagged as IN_ERROR
         */
        if (!PROXY_WORKER_IS_USABLE(worker->w))
            ap_proxy_retry_worker("BALANCER", worker->w, r->server);
        /* If the worker is not in error state
         * or not disabled.
         */
        if (PROXY_WORKER_IS_USABLE(worker->w)) {
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
            total_factor += worker->s->lbfactor;
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
        worker = (proxy_runtime_worker *)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++) {
            /* If the worker is not error state
             * or not in disabled mode
             */
            if (PROXY_WORKER_IS_USABLE(worker->w)) {
                /* 1. Find the worker with higher lbstatus.
                 * Lbstatus is of higher importance then
                 * the number of empty slots.
                 */
                if (worker->s->lbstatus > candidate->s->lbstatus) {
                    candidate = worker;
                }
            }
            worker++;
        }
        worker = (proxy_runtime_worker *)balancer->workers->elts;
        for (i = 0; i < balancer->workers->nelts; i++) {
            /* If the worker is not error state
             * or not in disabled mode
             */
            if (PROXY_WORKER_IS_USABLE(worker->w)) {
                /* XXX: The lbfactor can be update using bytes transfered
                 * Right now, use the round-robin scheme
                 */
                worker->s->lbstatus += worker->s->lbfactor;
                if (worker->s->lbstatus >= total_factor)
                    worker->s->lbstatus = worker->s->lbfactor;
            }
            worker++;
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

    *url = apr_pstrcat(r->pool, worker->name, path, NULL);
   
    return OK;
}

static int proxy_balancer_pre_request(proxy_worker **worker,
                                      proxy_balancer **balancer,
                                      request_rec *r,
                                      proxy_server_conf *conf, char **url)
{
    int access_status;
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
                         "proxy: BALANCER: (%s). All workers are in error state for route (%s)",
                         (*balancer)->name, route);
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }
    else {
        int i;
        proxy_runtime_worker *workers;
        /* We have a sticky load balancer */
        runtime->s->elected++;
        *worker = runtime->w;
        /* Update the workers status 
         * so that even session routes get
         * into account.
         */
        workers = (proxy_runtime_worker *)(*balancer)->workers->elts;
        for (i = 0; i < (*balancer)->workers->nelts; i++) {
            /* For now assume that all workers are OK */
            workers->s->lbstatus += workers->s->lbfactor;
            if (workers->s->lbstatus >= 100.0)
                workers->s->lbstatus = workers->s->lbfactor;
            workers++;
        }
    }
    /* Lock the LoadBalancer
     * XXX: perhaps we need the process lock here
     */
    if ((rv = PROXY_BALANCER_LOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: BALANCER: lock");
        return DECLINED;
    }
    if (!*worker) {
        runtime = find_best_worker(*balancer, r);
        if (!runtime) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: BALANCER: (%s). All workers are in error state",
                         (*balancer)->name);
        
            PROXY_BALANCER_UNLOCK(*balancer);
            return HTTP_SERVICE_UNAVAILABLE;
        }
        runtime->s->elected++;
        *worker = runtime->w;
    }
    /* Decrease the free channels number */
    if ((*worker)->cp->nfree)
        --(*worker)->cp->nfree;

    PROXY_BALANCER_UNLOCK(*balancer);
    
    access_status = rewrite_url(r, *worker, url);
    /* Add the session route to request notes if present */
    if (route) {
        apr_table_setn(r->notes, "session-sticky", (*balancer)->sticky);
        apr_table_setn(r->notes, "session-route", route);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy_balancer_pre_request rewriting to %s", *url);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy_balancer_pre_request worker (%s) free %d",
                 (*worker)->name,
                 (*worker)->cp->nfree);

    return access_status;
} 

static int proxy_balancer_post_request(proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf)
{
    apr_status_t rv;

    if ((rv = PROXY_BALANCER_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "proxy: BALANCER: lock");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* increase the free channels number */
    if (worker->cp->nfree)
        worker->cp->nfree++;
    /* TODO: calculate the bytes transfered */

    /* TODO: update the scoreboard status */

    PROXY_BALANCER_UNLOCK(balancer);        
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy_balancer_post_request for (%s)", balancer->name);

    return OK;
} 

static void recalc_factors(proxy_balancer *balancer,
                           proxy_runtime_worker *fixed)
{
    int i;
    double median, ffactor = 0.0;
    proxy_runtime_worker *workers;    


    /* Recalculate lbfactors */
    workers = (proxy_runtime_worker *)balancer->workers->elts;
    /* Special case if there is only one worker it's
     * load factor will always be 100
     */
    if (balancer->workers->nelts == 1) {
        workers->s->lbstatus = workers->s->lbfactor = 100.0;
        return;
    }
    for (i = 0; i < balancer->workers->nelts; i++) {
        if (workers[i].s->lbfactor > 100.0)
            workers[i].s->lbfactor = 100.0;
        ffactor += workers[i].s->lbfactor;
    }
    if (ffactor < 100.0) {
        median = (100.0 - ffactor) / (balancer->workers->nelts - 1);
        for (i = 0; i < balancer->workers->nelts; i++) {
            if (&(workers[i]) != fixed)
                workers[i].s->lbfactor += median;
        }
    }
    else if (fixed->s->lbfactor < 100.0) {
        median = (ffactor - 100.0) / (balancer->workers->nelts - 1);
        for (i = 0; i < balancer->workers->nelts; i++) {
            if (workers[i].s->lbfactor > median &&
                &(workers[i]) != fixed)
                workers[i].s->lbfactor -= median;
        }
    } 
    else {
        median = (ffactor - 100.0) / balancer->workers->nelts;
        for (i = 0; i < balancer->workers->nelts; i++) {
            workers[i].s->lbfactor -= median;
        }
    } 
    for (i = 0; i < balancer->workers->nelts; i++) {
        /* Update the status entires */
        workers[i].s->lbstatus = workers[i].s->lbfactor;
    }
}

/* Invoke handler */
static int balancer_handler(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    apr_array_header_t *proxies = conf->proxies;
    struct proxy_remote *ents = (struct proxy_remote *)proxies->elts;
    proxy_balancer *balancer, *bsel = NULL;
    proxy_runtime_worker *worker, *wsel = NULL;
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
            if ((val = ap_strchr_c(args, '='))) {
                *val++ = '\0';
                if ((tok = ap_strchr_c(val, '&')))
                    *tok++ = '\0';
                if ((access_status = ap_unescape_url(val)) != OK)
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
            apr_pstrcat(r->pool, "balancer://", name, NULL));
    if ((name = apr_table_get(params, "w"))) {
        const char *sc = apr_table_get(params, "s");
        char *asname = NULL;
        proxy_worker *ws = NULL;
        if (sc) {
            asname = apr_pstrcat(r->pool, sc, "://", name, NULL);
            ws = ap_proxy_get_worker(r->pool, conf, asname);
        }
        if (ws) {
            worker = (proxy_runtime_worker *)bsel->workers->elts;
            for (n = 0; n < bsel->workers->nelts; n++) {
                if (strcasecmp(worker->w->name, ws->name) == 0) {
                    wsel = worker;
                    break;
                }
                ++worker;
            }
        }
    }
    /* First set the params */
    if (bsel) {
        const char *val;
        if ((val = apr_table_get(params, "ss"))) {
            if (strlen(val))
                bsel->sticky = apr_pstrdup(conf->pool, val);
            else
                bsel->sticky = NULL;
        }
        if ((val = apr_table_get(params, "tm"))) {
            int ival = atoi(val);
            if (ival >= 0)
                bsel->timeout = apr_time_from_sec(ival);
        }
    }
    if (wsel) {
        const char *val;
        if ((val = apr_table_get(params, "lf"))) {
            char *ep;
            double dval = strtod(val, &ep);
            if (dval > 1) {
                wsel->s->lbfactor = dval;
                if (bsel)
                    recalc_factors(bsel, wsel);
            }
        }
        if ((val = apr_table_get(params, "wr"))) {
            if (strlen(val))
                wsel->w->route = apr_pstrdup(conf->pool, val);
            else
                wsel->w->route = NULL;
        }
        if ((val = apr_table_get(params, "rr"))) {
            if (strlen(val))
                wsel->w->redirect = apr_pstrdup(conf->pool, val);
            else
                wsel->w->redirect = NULL;
        }
        if ((val = apr_table_get(params, "dw")))
            wsel->w->status |= PROXY_WORKER_DISABLED;
        else
            wsel->w->status &= ~PROXY_WORKER_DISABLED;

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
            worker = (proxy_runtime_worker *)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                ap_rputs("        <httpd:worker>\n", r);
                ap_rvputs(r, "          <httpd:scheme>", worker->w->scheme,
                          "</httpd:scheme>\n", NULL);                
                ap_rvputs(r, "          <httpd:hostname>", worker->w->hostname,
                          "</httpd:hostname>\n", NULL);                
               ap_rprintf(r, "          <httpd:loadfactor>%.2f</httpd:loadfactor>\n",
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
        ap_set_content_type(r, "text/html");
        ap_rputs(DOCTYPE_HTML_3_2
                 "<html><head><title>Balancer Manager</title></head>\n", r);
        ap_rputs("<body><h1>Load Balancer Manager for ", r);
        ap_rvputs(r, ap_get_server_name(r), "</h1>\n\n", NULL);
        ap_rvputs(r, "<dl><dt>Server Version: ",
                  ap_get_server_version(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server Built: ",
                  ap_get_server_built(), "\n</dt></dl>\n", NULL);
        balancer = (proxy_balancer *)conf->balancers->elts;
        for (i = 0; i < conf->balancers->nelts; i++) {
            ap_rputs("<hr />\n<h3>LoadBalancer Status for ", r);
            ap_rvputs(r, "<a href=\"", r->uri, "?b=",
                      balancer->name + sizeof("balancer://") - 1,
                      "\">", NULL); 
            ap_rvputs(r, balancer->name, "</a></h3>\n\n", NULL);
            ap_rputs("\n\n<table border=\"0\"><tr>"
                "<th>StickySesion</th><th>Timeout</th>"
                "</tr>\n<tr>", r);                
            ap_rvputs(r, "<td>", balancer->sticky, NULL);
            ap_rprintf(r, "</td><td>%" APR_TIME_T_FMT "</td>\n",
                apr_time_sec(balancer->timeout));
            ap_rputs("</table>\n", r);
            ap_rputs("\n\n<table border=\"0\"><tr>"
                "<th>Scheme</th><th>Host</th>"
                "<th>Route</th><th>RouteRedir</th>"
                "<th>Factor</th><th>Status</th>"
                "</tr>\n", r);

            worker = (proxy_runtime_worker *)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {

                ap_rvputs(r, "<tr>\n<td>", worker->w->scheme, "</td><td>", NULL);
                ap_rvputs(r, "<a href=\"", r->uri, "?b=", 
                          balancer->name + sizeof("balancer://") - 1,
                          "&s=", worker->w->scheme, "&w=", worker->w->hostname,
                          "\">", NULL); 
                ap_rvputs(r, worker->w->hostname, "</a></td>", NULL);
                ap_rvputs(r, "<td>", worker->w->route, NULL);
                ap_rvputs(r, "</td><td>", worker->w->redirect, NULL);
                ap_rprintf(r, "</td><td>%.2f</td><td>", worker->s->lbfactor);
                if (worker->w->status & PROXY_WORKER_DISABLED)
                    ap_rputs("Dis", r);
                else if (worker->w->status & PROXY_WORKER_IN_ERROR)
                    ap_rputs("Err", r);
                else if (worker->w->status & PROXY_WORKER_INITIALIZED)
                    ap_rputs("Ok", r);
                else
                    ap_rputs("-", r);
                ap_rputs("</td></tr>\n", r);

                ++worker;
            }
            ap_rputs("</table>\n", r);
            ++balancer;
        }
        ap_rputs("<hr />\n", r);
        if (wsel && bsel) {
            ap_rputs("<h3>Edit worker settings for ", r);
            ap_rvputs(r, wsel->w->name, "</h3>\n", NULL);
            ap_rvputs(r, "<form method=\"GET\" action=\"", NULL);
            ap_rvputs(r, r->uri, "\">\n<dl>", NULL); 
            ap_rputs("<table><tr><td>Load factor:</td><td><input name=\"lf\" type=text ", r);
            ap_rprintf(r, "value=\"%.2f\"></td><tr>\n", wsel->s->lbfactor);            
            ap_rputs("<tr><td>Route:</td><td><input name=\"wr\" type=text ", r);
            ap_rvputs(r, "value=\"", wsel->w->route, NULL); 
            ap_rputs("\"></td><tr>\n", r);            
            ap_rputs("<tr><td>Route Redirect:</td><td><input name=\"rr\" type=text ", r);
            ap_rvputs(r, "value=\"", wsel->w->redirect, NULL); 
            ap_rputs("\"></td><tr>\n", r);            
            ap_rputs("<tr><td>Disabled:</td><td><input name=\"dw\" type=checkbox", r);
            if (wsel->w->status & PROXY_WORKER_DISABLED)
                ap_rputs(" checked", r);
            ap_rputs("></td><tr>\n", r);            
            ap_rputs("<tr><td colspan=2><input type=submit value=\"Submit\"></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name=\"s\" ", NULL);
            ap_rvputs(r, "value=\"", wsel->w->scheme, "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name=\"w\" ", NULL);
            ap_rvputs(r, "value=\"", wsel->w->hostname, "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name=\"b\" ", NULL);
            ap_rvputs(r, "value=\"", bsel->name + sizeof("balancer://") - 1,
                      "\">\n</form>\n", NULL);
            ap_rputs("<hr />\n", r);
        }
        else if (bsel) {
            ap_rputs("<h3>Edit balancer settings for ", r);
            ap_rvputs(r, bsel->name, "</h3>\n", NULL);
            ap_rvputs(r, "<form method=\"GET\" action=\"", NULL);
            ap_rvputs(r, r->uri, "\">\n<dl>", NULL); 
            ap_rputs("<table><tr><td>StickySession Identifier:</td><td><input name=\"ss\" type=text ", r);
            if (bsel->sticky)
                ap_rvputs(r, "value=\"", bsel->sticky, "\"", NULL);
            ap_rputs("></td><tr>\n<tr><td>Timeout:</td><td><input name=\"tm\" type=text ", r);
            ap_rprintf(r, "value=\"%" APR_TIME_T_FMT "\"></td></tr>\n",
                       apr_time_sec(bsel->timeout));
            ap_rputs("<tr><td colspan=2><input type=submit value=\"Submit\"></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name=\"b\" ", NULL);
            ap_rvputs(r, "value=\"", bsel->name + sizeof("balancer://") - 1,
                      "\">\n</form>\n", NULL);
            ap_rputs("<hr />\n", r);
        }
        ap_rputs(ap_psignature("",r), r);
        ap_rputs("</body></html>\n", r);
    }
    return OK;
}

static void ap_proxy_balancer_register_hook(apr_pool_t *p)
{
    /* manager handler */
    ap_hook_handler(balancer_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_pre_request(proxy_balancer_pre_request, NULL, NULL, APR_HOOK_FIRST);    
    proxy_hook_post_request(proxy_balancer_post_request, NULL, NULL, APR_HOOK_FIRST);    
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
