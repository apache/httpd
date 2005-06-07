/* Copyright 1999-2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

static int proxy_balancer_canon(request_rec *r, char *url)
{
    char *host, *path, *search;
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
    /* now parse path/search args, according to rfc1738 */
    /* N.B. if this isn't a true proxy request, then the URL _path_
     * has already been decoded.  True proxy requests have r->uri
     * == r->unparsed_uri, and no others have that property.
     */
    if (r->uri == r->unparsed_uri) {
        search = strchr(url, '?');
        if (search != NULL)
            *(search++) = '\0';
    }
    else
        search = r->args;

    /* process path */
    path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0, r->proxyreq);
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

    workers = (proxy_worker *)balancer->workers->elts;

    for (i = 0; i < balancer->workers->nelts; i++) {
        ap_proxy_initialize_worker_share(conf, workers, s);
        workers->s->status = PROXY_WORKER_INITIALIZED;
        ++workers;
    }

    workers = (proxy_worker *)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++) {
        /* Set to the original configuration */
        workers[i].s->lbstatus = workers[i].s->lbfactor =
          (workers[i].lbfactor ? workers[i].lbfactor : 1);
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

/* Find the worker that has the 'route' defined
 */
static proxy_worker *find_route_worker(proxy_balancer *balancer,
                                       const char *route)
{
    int i;
    proxy_worker *worker = (proxy_worker *)balancer->workers->elts;
    for (i = 0; i < balancer->workers->nelts; i++) {
        if (*(worker->s->route) && strcmp(worker->s->route, route) == 0) {
            return worker;
        }
        worker++;
    }
    return NULL;
}

static proxy_worker *find_session_route(proxy_balancer *balancer,
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
        /* We have a route in path or in cookie
         * Find the worker that has this route defined.
         */
        proxy_worker *worker =  find_route_worker(balancer, *route);
        if (worker && !PROXY_WORKER_IS_USABLE(worker)) {
            /* We have a worker that is unusable.
             * It can be in error or disabled, but in case
             * it has a redirection set use that redirection worker.
             * This enables to safely remove the member from the
             * balancer. Of course you will need a some kind of
             * session replication between those two remote.
             */
            if (*worker->s->redirect)
                worker = find_route_worker(balancer, worker->s->redirect);
            /* Check if the redirect worker is usable */
            if (worker && !PROXY_WORKER_IS_USABLE(worker))
                worker = NULL;
        }
        return worker;
    }
    else
        return NULL;
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
    proxy_worker *worker = (proxy_worker *)balancer->workers->elts;
    proxy_worker *candidate = NULL;
    
    /* First try to see if we have available candidate */
    for (i = 0; i < balancer->workers->nelts; i++) {
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
            if (!candidate || worker->s->lbstatus > candidate->s->lbstatus)
                candidate = worker;
        }
        worker++;
    }

    if (candidate) {
        candidate->s->lbstatus -= total_factor;
        candidate->s->elected++;
    }

    return candidate;
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
    proxy_worker *worker = (proxy_worker *)balancer->workers->elts;
    proxy_worker *candidate = NULL;
    
    /* First try to see if we have available candidate */
    for (i = 0; i < balancer->workers->nelts; i++) {
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
            if (!candidate || mytraffic < curmin) {
                candidate = worker;
                curmin = mytraffic;
            }
        }
        worker++;
    }
    
    if (candidate) {
        candidate->s->elected++;
    }

    return candidate;
}

static proxy_worker *find_best_worker(proxy_balancer *balancer,
                                      request_rec *r)
{
    proxy_worker *candidate = NULL;
    
    if (PROXY_THREAD_LOCK(balancer) != APR_SUCCESS)
        return NULL;    

    if (balancer->lbmethod == lbmethod_requests) {
        candidate = find_best_byrequests(balancer, r);
    } else if (balancer->lbmethod == lbmethod_traffic) {
        candidate = find_best_bytraffic(balancer, r);
    } else {
        PROXY_THREAD_UNLOCK(balancer);
        return NULL;
    }

    PROXY_THREAD_UNLOCK(balancer);

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

static int proxy_balancer_pre_request(proxy_worker **worker,
                                      proxy_balancer **balancer,
                                      request_rec *r,
                                      proxy_server_conf *conf, char **url)
{
    int access_status;
    proxy_worker *runtime;
    char *route;
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
    
    /* Step 2: find the session route */
    
    runtime = find_session_route(*balancer, r, &route, url);
    /* Lock the LoadBalancer
     * XXX: perhaps we need the process lock here
     */
    if ((rv = PROXY_THREAD_LOCK(*balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "proxy: BALANCER: lock");
        return DECLINED;
    }
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "proxy: BALANCER: (%s). All workers are in error state for route (%s)",
                     (*balancer)->name, route);
        PROXY_THREAD_UNLOCK(*balancer);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    PROXY_THREAD_UNLOCK(*balancer);
    if (!*worker) {
        runtime = find_best_worker(*balancer, r);
        if (!runtime) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "proxy: BALANCER: (%s). All workers are in error state",
                         (*balancer)->name);
        
            return HTTP_SERVICE_UNAVAILABLE;
        }
        *worker = runtime;
    }

    /* Rewrite the url from 'balancer://url'
     * to the 'worker_scheme://worker_hostname[:worker_port]/url'
     * This replaces the balancers fictional name with the
     * real hostname of the elected worker.
     */
    access_status = rewrite_url(r, *worker, url);
    /* Add the session route to request notes if present */
    if (route) {
        apr_table_setn(r->notes, "session-sticky", (*balancer)->sticky);
        apr_table_setn(r->notes, "session-route", route);
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
    apr_status_t rv;

    if ((rv = PROXY_THREAD_LOCK(balancer)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
            "proxy: BALANCER: lock");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* TODO: calculate the bytes transferred
     * This will enable to elect the worker that has
     * the lowest load.
     * The bytes transferred depends on the protocol
     * used, so each protocol handler should keep the
     * track on that.
     */

    PROXY_THREAD_UNLOCK(balancer);        
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "proxy_balancer_post_request for (%s)", balancer->name);

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
        if ((val = apr_table_get(params, "fa"))) {
            int ival = atoi(val);
            if (ival >= 0)
                bsel->max_attempts = ival;
            bsel->max_attempts_set = 1;
        }
        if ((val = apr_table_get(params, "lm"))) {
            int ival = atoi(val);
            switch(ival) {
                case 0:
                    break;
                case lbmethod_traffic:
                    bsel->lbmethod = lbmethod_traffic;
                    break;
                case lbmethod_requests:
                    bsel->lbmethod = lbmethod_requests;
                    break;
                default:
                    break;
            }
        }
    }
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
        if ((val = apr_table_get(params, "dw")))
            wsel->s->status |= PROXY_WORKER_DISABLED;
        else
            wsel->s->status &= ~PROXY_WORKER_DISABLED;

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
                "<th>StickySession</th><th>Timeout</th><th>FailoverAttempts</th><th>Method</th>"
                "</tr>\n<tr>", r);                
            ap_rvputs(r, "<td>", balancer->sticky, NULL);
            ap_rprintf(r, "</td><td>%" APR_TIME_T_FMT "</td>",
                apr_time_sec(balancer->timeout));
            ap_rprintf(r, "<td>%d</td>\n", balancer->max_attempts);
            ap_rprintf(r, "<td>%s</td>\n",
                       balancer->lbmethod == lbmethod_requests ? "Requests" :
                       balancer->lbmethod == lbmethod_traffic  ? "Traffic" : "Unknown");
            ap_rputs("</table>\n", r);
            ap_rputs("\n\n<table border=\"0\"><tr>"
                "<th>Scheme</th><th>Host</th>"
                "<th>Route</th><th>RouteRedir</th>"
                "<th>Factor</th><th>Status</th>"
                "</tr>\n", r);

            worker = (proxy_worker *)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {

                ap_rvputs(r, "<tr>\n<td>", worker->scheme, "</td><td>", NULL);
                ap_rvputs(r, "<a href=\"", r->uri, "?b=", 
                          balancer->name + sizeof("balancer://") - 1,
                          "&s=", worker->scheme, "&w=", worker->hostname,
                          "\">", NULL); 
                ap_rvputs(r, worker->hostname, "</a></td>", NULL);
                ap_rvputs(r, "<td>", worker->s->route, NULL);
                ap_rvputs(r, "</td><td>", worker->s->redirect, NULL);
                ap_rprintf(r, "</td><td>%d</td><td>", worker->s->lbfactor);
                if (worker->s->status & PROXY_WORKER_DISABLED)
                    ap_rputs("Dis", r);
                else if (worker->s->status & PROXY_WORKER_IN_ERROR)
                    ap_rputs("Err", r);
                else if (worker->s->status & PROXY_WORKER_INITIALIZED)
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
            ap_rvputs(r, wsel->name, "</h3>\n", NULL);
            ap_rvputs(r, "<form method=\"GET\" action=\"", NULL);
            ap_rvputs(r, r->uri, "\">\n<dl>", NULL); 
            ap_rputs("<table><tr><td>Load factor:</td><td><input name=\"lf\" type=text ", r);
            ap_rprintf(r, "value=\"%d\"></td><tr>\n", wsel->s->lbfactor);            
            ap_rputs("<tr><td>Route:</td><td><input name=\"wr\" type=text ", r);
            ap_rvputs(r, "value=\"", wsel->route, NULL); 
            ap_rputs("\"></td><tr>\n", r);            
            ap_rputs("<tr><td>Route Redirect:</td><td><input name=\"rr\" type=text ", r);
            ap_rvputs(r, "value=\"", wsel->redirect, NULL); 
            ap_rputs("\"></td><tr>\n", r);            
            ap_rputs("<tr><td>Disabled:</td><td><input name=\"dw\" type=checkbox", r);
            if (wsel->s->status & PROXY_WORKER_DISABLED)
                ap_rputs(" checked", r);
            ap_rputs("></td><tr>\n", r);            
            ap_rputs("<tr><td colspan=2><input type=submit value=\"Submit\"></td></tr>\n", r);
            ap_rvputs(r, "</table>\n<input type=hidden name=\"s\" ", NULL);
            ap_rvputs(r, "value=\"", wsel->scheme, "\">\n", NULL);
            ap_rvputs(r, "<input type=hidden name=\"w\" ", NULL);
            ap_rvputs(r, "value=\"", wsel->hostname, "\">\n", NULL);
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
            ap_rputs("<tr><td>Failover Attempts:</td><td><input name=\"fa\" type=text ", r);
            ap_rprintf(r, "value=\"%d\"></td></tr>\n",
                       bsel->max_attempts);
            ap_rputs("<tr><td>LB Method:</td><td><select name=\"lm\">", r);
            ap_rprintf(r, "<option value=\"%d\" %s>Requests</option>", lbmethod_requests,
                       bsel->lbmethod == lbmethod_requests ? "selected" : "");
            ap_rprintf(r, "<option value=\"%d\" %s>Traffic</option>", lbmethod_traffic,
                       bsel->lbmethod == lbmethod_traffic ? "selected" : "");
            ap_rputs("</select></td></tr>\n", r);
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

static void ap_proxy_balancer_register_hook(apr_pool_t *p)
{
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes and after the mod_proxy
     */
    static const char *const aszPred[] = { "mpm_winnt.c", "mod_proxy.c", NULL};
     /* manager handler */
    ap_hook_handler(balancer_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_child_init(child_init, aszPred, NULL, APR_HOOK_MIDDLE); 
    proxy_hook_pre_request(proxy_balancer_pre_request, NULL, NULL, APR_HOOK_FIRST);    
    proxy_hook_post_request(proxy_balancer_post_request, NULL, NULL, APR_HOOK_FIRST);    
    proxy_hook_canon_handler(proxy_balancer_canon, NULL, NULL, APR_HOOK_FIRST);
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
