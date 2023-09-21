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
#include "mod_proxy.h"
#include "mod_watchdog.h"
#include "ap_slotmem.h"
#include "ap_expr.h"
#if APR_HAS_THREADS
#include "apr_thread_pool.h"
#endif
#include "http_ssl.h"

module AP_MODULE_DECLARE_DATA proxy_hcheck_module;

#define HCHECK_WATHCHDOG_NAME ("_proxy_hcheck_")
#define HC_THREADPOOL_SIZE (16)

/* Why? So we can easily set/clear HC_USE_THREADS during dev testing */
#if APR_HAS_THREADS
#ifndef HC_USE_THREADS
#define HC_USE_THREADS 1
#endif
#else
#define HC_USE_THREADS 0
#endif

typedef struct {
    char *name;
    hcmethod_t method;
    int passes;
    int fails;
    apr_interval_time_t interval;
    char *hurl;
    char *hcexpr;
} hc_template_t;

typedef struct {
    char *expr;
    ap_expr_info_t *pexpr;       /* parsed expression */
} hc_condition_t;

typedef struct {
    apr_pool_t *p;
    apr_array_header_t *templates;
    apr_table_t *conditions;
    apr_hash_t *hcworkers;
    server_rec *s;
} sctx_t;

/* Used in the HC worker via the context field */
typedef struct {
    const char *path;   /* The path of the original worker URL */
    const char *method; /* Method string for the HTTP/AJP request */
    const char *req;    /* pre-formatted HTTP/AJP request */
    proxy_worker *w;    /* Pointer to the actual worker */
    const char *protocol; /* HTTP 1.0 or 1.1? */
} wctx_t;

typedef struct {
    apr_pool_t *ptemp;
    sctx_t *ctx;
    proxy_balancer *balancer;
    proxy_worker *worker;
    proxy_worker *hc;
    apr_time_t *now;
} baton_t;

static APR_OPTIONAL_FN_TYPE(ajp_handle_cping_cpong) *ajp_handle_cping_cpong = NULL;

static void *hc_create_config(apr_pool_t *p, server_rec *s)
{
    sctx_t *ctx = apr_pcalloc(p, sizeof(sctx_t));
    ctx->s = s;
    apr_pool_create(&ctx->p, p);
    apr_pool_tag(ctx->p, "proxy_hcheck");
    ctx->templates = apr_array_make(p, 10, sizeof(hc_template_t));
    ctx->conditions = apr_table_make(p, 10);
    ctx->hcworkers = apr_hash_make(p);
    return ctx;
}

static ap_watchdog_t *watchdog;
#if HC_USE_THREADS
static apr_thread_pool_t *hctp;
static int tpsize;
#endif

/*
 * This serves double duty by not only validating (and creating)
 * the health-check template, but also ties into set_worker_param()
 * which does the actual setting of worker params in shm.
 */
static const char *set_worker_hc_param(apr_pool_t *p,
                                    server_rec *s,
                                    proxy_worker *worker,
                                    const char *key,
                                    const char *val,
                                    void *v)
{
    int ival;
    hc_template_t *temp;
    sctx_t *ctx = (sctx_t *) ap_get_module_config(s->module_config,
                                                  &proxy_hcheck_module);
    if (!worker && !v) {
        return "Bad call to set_worker_hc_param()";
    }
    if (!ctx) {
        ctx = hc_create_config(p, s);
        ap_set_module_config(s->module_config, &proxy_hcheck_module, ctx);
    }
    temp = (hc_template_t *)v;
    if (!strcasecmp(key, "hctemplate")) {
        hc_template_t *template;
        template = (hc_template_t *)ctx->templates->elts;
        for (ival = 0; ival < ctx->templates->nelts; ival++, template++) {
            if (!ap_cstr_casecmp(template->name, val)) {
                if (worker) {
                    worker->s->method = template->method;
                    worker->s->interval = template->interval;
                    worker->s->passes = template->passes;
                    worker->s->fails = template->fails;
                    PROXY_STRNCPY(worker->s->hcuri, template->hurl);
                    PROXY_STRNCPY(worker->s->hcexpr, template->hcexpr);
                } else {
                    temp->method = template->method;
                    temp->interval = template->interval;
                    temp->passes = template->passes;
                    temp->fails = template->fails;
                    temp->hurl = apr_pstrdup(p, template->hurl);
                    temp->hcexpr = apr_pstrdup(p, template->hcexpr);
                }
                return NULL;
            }
        }
        return apr_psprintf(p, "Unknown ProxyHCTemplate name: %s", val);
    }
    else if (!strcasecmp(key, "hcmethod")) {
        proxy_hcmethods_t *method = proxy_hcmethods;
        for (; method->name; method++) {
            if (!ap_cstr_casecmp(val, method->name)) {
                if (!method->implemented) {
                    return apr_psprintf(p, "Health check method %s not (yet) implemented",
                                        val);
                }
                if (worker) {
                    worker->s->method = method->method;
                } else {
                    temp->method = method->method;
                }
                return NULL;
            }
        }
        return "Unknown method";
    }
    else if (!strcasecmp(key, "hcinterval")) {
        apr_interval_time_t hci;
        apr_status_t rv;
        rv = ap_timeout_parameter_parse(val, &hci, "s");
        if (rv != APR_SUCCESS)
            return "Unparse-able hcinterval setting";
        if (hci < AP_WD_TM_SLICE)
            return apr_psprintf(p, "Interval must be a positive value greater than %"
                                APR_TIME_T_FMT "ms", apr_time_as_msec(AP_WD_TM_SLICE));
        if (worker) {
            worker->s->interval = hci;
        } else {
            temp->interval = hci;
        }
    }
    else if (!strcasecmp(key, "hcpasses")) {
        ival = atoi(val);
        if (ival < 0)
            return "Passes must be a positive value";
        if (worker) {
            worker->s->passes = ival;
        } else {
            temp->passes = ival;
        }
    }
    else if (!strcasecmp(key, "hcfails")) {
        ival = atoi(val);
        if (ival < 0)
            return "Fails must be a positive value";
        if (worker) {
            worker->s->fails = ival;
        } else {
            temp->fails = ival;
        }
    }
    else if (!strcasecmp(key, "hcuri")) {
        if (strlen(val) >= sizeof(worker->s->hcuri))
            return apr_psprintf(p, "Health check uri length must be < %d characters",
                    (int)sizeof(worker->s->hcuri));
        if (worker) {
            PROXY_STRNCPY(worker->s->hcuri, val);
        } else {
            temp->hurl = apr_pstrdup(p, val);
        }
    }
    else if (!strcasecmp(key, "hcexpr")) {
        hc_condition_t *cond;
        cond = (hc_condition_t *)apr_table_get(ctx->conditions, val);
        if (!cond) {
            return apr_psprintf(p, "Unknown health check condition expr: %s", val);
        }
        /* This check is wonky... a known expr can't be this big. Check anyway */
        if (strlen(val) >= sizeof(worker->s->hcexpr))
            return apr_psprintf(p, "Health check uri length must be < %d characters",
                    (int)sizeof(worker->s->hcexpr));
        if (worker) {
            PROXY_STRNCPY(worker->s->hcexpr, val);
        } else {
            temp->hcexpr = apr_pstrdup(p, val);
        }
    }
  else {
        return "unknown Worker hcheck parameter";
    }
    return NULL;
}

static const char *set_hc_condition(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *name = NULL;
    char *expr;
    sctx_t *ctx;
    hc_condition_t *cond;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;
    ctx = (sctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &proxy_hcheck_module);

    name = ap_getword_conf(cmd->pool, &arg);
    if (!*name) {
        return apr_pstrcat(cmd->temp_pool, "Missing expression name for ",
                           cmd->cmd->name, NULL);
    }
    if (strlen(name) > (PROXY_WORKER_MAX_SCHEME_SIZE - 1)) {
        return apr_psprintf(cmd->temp_pool, "Expression name limited to %d characters",
                           (PROXY_WORKER_MAX_SCHEME_SIZE - 1));
    }
    /* get expr. Allow fancy new {...} quoting style */
    expr = ap_getword_conf2(cmd->temp_pool, &arg);
    if (!*expr) {
        return apr_pstrcat(cmd->temp_pool, "Missing expression for ",
                           cmd->cmd->name, NULL);
    }
    cond = apr_palloc(cmd->pool, sizeof(hc_condition_t));
    cond->pexpr = ap_expr_parse_cmd(cmd, expr, 0, &err, NULL);
    if (err) {
        return apr_psprintf(cmd->temp_pool, "Could not parse expression \"%s\": %s",
                            expr, err);
    }
    cond->expr = apr_pstrdup(cmd->pool, expr);
    apr_table_setn(ctx->conditions, name, (void *)cond);
    expr = ap_getword_conf(cmd->temp_pool, &arg);
    if (*expr) {
        return "error: extra parameter(s)";
    }
    return NULL;
}

static const char *set_hc_template(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *name = NULL;
    char *word, *val;
    hc_template_t *template;
    sctx_t *ctx;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;
    ctx = (sctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &proxy_hcheck_module);

    name = ap_getword_conf(cmd->temp_pool, &arg);
    if (!*name) {
        return apr_pstrcat(cmd->temp_pool, "Missing template name for ",
                           cmd->cmd->name, NULL);
    }

    template = (hc_template_t *)apr_array_push(ctx->templates);

    template->name = apr_pstrdup(cmd->pool, name);
    template->method = template->passes = template->fails = 1;
    template->interval = apr_time_from_sec(HCHECK_WATHCHDOG_DEFAULT_INTERVAL);
    template->hurl = NULL;
    template->hcexpr = NULL;
    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid ProxyHCTemplate parameter. Parameter must be "
                   "in the form 'key=value'";
        }
        else
            *val++ = '\0';
        err = set_worker_hc_param(cmd->pool, ctx->s, NULL, word, val, template);

        if (err) {
            /* get rid of recently pushed (bad) template */
            apr_array_pop(ctx->templates);
            return apr_pstrcat(cmd->temp_pool, "ProxyHCTemplate: ", err, " ", word, "=", val, "; ", name, NULL);
        }
        /* No error means we have a valid template */
    }
    return NULL;
}

#if HC_USE_THREADS
static const char *set_hc_tpsize (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
        return err;

    tpsize = atoi(arg);
    if (tpsize < 0)
        return "Invalid ProxyHCTPsize parameter. Parameter must be "
               ">= 0";
    return NULL;
}
#endif

/*
 * Create a dummy request rec, simply so we can use ap_expr.
 * Use our short-lived pool for bucket_alloc so that we can simply move
 * buckets and use them after the backend connection is released.
 */
static request_rec *create_request_rec(apr_pool_t *p, server_rec *s,
                                       proxy_balancer *balancer,
                                       const char *method,
                                       const char *protocol)
{
    request_rec *r;

    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->server          = s;

    r->per_dir_config = r->server->lookup_defaults;
    if (balancer->section_config) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool,
                                                     r->per_dir_config,
                                                     balancer->section_config);
    }

    r->proxyreq        = PROXYREQ_RESPONSE;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 1);
    r->trailers_in     = apr_table_make(r->pool, 1);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 1);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  /* Until further notice */
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;


    /* Time to populate r with the data we have. */
    r->method = method;
    /* Provide quick information about the request method as soon as known */
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_OPTIONS
            || (r->method_number == M_GET && r->method[0] == 'H')) {
        r->header_only = 1;
    }
    else {
        r->header_only = 0;
    }
    r->protocol = "HTTP/1.0";
    r->proto_num = HTTP_VERSION(1, 0);
    if ( protocol && (protocol[7] == '1') ) {
        r->protocol = "HTTP/1.1";
        r->proto_num = HTTP_VERSION(1, 1);
    }
    r->hostname = NULL;

    return r;
}

static void set_request_connection(request_rec *r, conn_rec *conn)
{
    conn->bucket_alloc = apr_bucket_alloc_create(r->pool);
    r->connection = conn;

    r->kept_body = apr_brigade_create(r->pool, conn->bucket_alloc);
    r->output_filters = r->proto_output_filters = conn->output_filters;
    r->input_filters = r->proto_input_filters = conn->input_filters;

    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;
}

static void create_hcheck_req(wctx_t *wctx, proxy_worker *hc,
                              apr_pool_t *p)
{
    char *req = NULL;
    const char *method = NULL;
    const char *protocol = NULL;

    /* TODO: Fold into switch/case below? This seems more obvious */
    if ( (hc->s->method == OPTIONS11) || (hc->s->method == HEAD11) || (hc->s->method == GET11) ) {
        protocol = "HTTP/1.1";
    } else {
        protocol = "HTTP/1.0";
    }
    switch (hc->s->method) {
        case OPTIONS:
        case OPTIONS11:
            method = "OPTIONS";
            req = apr_psprintf(p,
                               "OPTIONS * %s\r\n"
                               "Host: %s:%d\r\n"
                               "\r\n", protocol,
                               hc->s->hostname_ex, (int)hc->s->port);
            break;

        case HEAD:
        case HEAD11:
            method = "HEAD";
            /* fallthru */
        case GET:
        case GET11:
            if (!method) { /* did we fall thru? If not, we are GET */
                method = "GET";
            }
            req = apr_psprintf(p,
                               "%s %s%s%s %s\r\n"
                               "Host: %s:%d\r\n"
                               "\r\n",
                               method,
                               (wctx->path ? wctx->path : ""),
                               (wctx->path && *hc->s->hcuri ? "/" : "" ),
                               (*hc->s->hcuri ? hc->s->hcuri : ""),
                               protocol,
                               hc->s->hostname_ex, (int)hc->s->port);
            break;

        default:
            break;
    }
    wctx->req = req;
    wctx->method = method;
    wctx->protocol = protocol;
}

static proxy_worker *hc_get_hcworker(sctx_t *ctx, proxy_worker *worker,
                                     apr_pool_t *p)
{
    proxy_worker *hc = NULL;
    apr_port_t port;

    hc = (proxy_worker *)apr_hash_get(ctx->hcworkers, &worker, sizeof worker);
    if (!hc) {
        apr_uri_t uri;
        apr_status_t rv;
        const char *url = worker->s->name_ex;
        wctx_t *wctx = apr_pcalloc(ctx->p, sizeof(wctx_t));

        port = (worker->s->port ? worker->s->port
                                : ap_proxy_port_of_scheme(worker->s->scheme));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO(03248)
                     "Creating hc worker %pp for %s://%s:%d",
                     worker, worker->s->scheme, worker->s->hostname_ex,
                     (int)port);

        ap_proxy_define_worker(ctx->p, &hc, NULL, NULL, worker->s->name_ex, 0);
        apr_snprintf(hc->s->name, sizeof hc->s->name, "%pp", worker);
        apr_snprintf(hc->s->name_ex, sizeof hc->s->name_ex, "%pp", worker);
        PROXY_STRNCPY(hc->s->hostname, worker->s->hostname); /* for compatibility */
        PROXY_STRNCPY(hc->s->hostname_ex, worker->s->hostname_ex);
        PROXY_STRNCPY(hc->s->scheme,   worker->s->scheme);
        PROXY_STRNCPY(hc->s->hcuri,    worker->s->hcuri);
        PROXY_STRNCPY(hc->s->hcexpr,   worker->s->hcexpr);
        hc->hash.def = hc->s->hash.def = ap_proxy_hashfunc(hc->s->name_ex,
                                                           PROXY_HASHFUNC_DEFAULT);
        hc->hash.fnv = hc->s->hash.fnv = ap_proxy_hashfunc(hc->s->name_ex,
                                                           PROXY_HASHFUNC_FNV);
        hc->s->port = port;
        hc->s->conn_timeout_set = worker->s->conn_timeout_set;
        hc->s->conn_timeout = worker->s->conn_timeout;
        hc->s->ping_timeout_set = worker->s->ping_timeout_set;
        hc->s->ping_timeout = worker->s->ping_timeout;
        hc->s->timeout_set = worker->s->timeout_set;
        hc->s->timeout = worker->s->timeout;
        /* Do not disable worker in case of errors */
        hc->s->status |= PROXY_WORKER_IGNORE_ERRORS;
        /* Mark as the "generic" worker */
        hc->s->status |= PROXY_WORKER_GENERIC;
        ap_proxy_initialize_worker(hc, ctx->s, ctx->p);
        hc->s->is_address_reusable = worker->s->is_address_reusable;
        hc->s->disablereuse = worker->s->disablereuse;
        hc->s->method = worker->s->method;
        rv = apr_uri_parse(p, url, &uri);
        if (rv == APR_SUCCESS) {
            wctx->path = apr_pstrdup(ctx->p, uri.path);
        }
        wctx->w = worker;
        create_hcheck_req(wctx, hc, ctx->p);
        hc->context = wctx;
        apr_hash_set(ctx->hcworkers, &worker, sizeof worker, hc);
    }
    /* This *could* have changed via the Balancer Manager */
    /* TODO */
    if (hc->s->method != worker->s->method) {
        wctx_t *wctx = hc->context;
        port = (worker->s->port ? worker->s->port
                                : ap_proxy_port_of_scheme(worker->s->scheme));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO(03311)
                     "Updating hc worker %pp for %s://%s:%d",
                     worker, worker->s->scheme, worker->s->hostname_ex,
                     (int)port);
        hc->s->method = worker->s->method;
        create_hcheck_req(wctx, hc, ctx->p);
    }
    return hc;
}

static int hc_determine_connection(const char *proxy_function,
                                   proxy_conn_rec *backend,
                                   server_rec *s)
{
    proxy_worker *worker = backend->worker;
    apr_status_t rv;

    /*
     * normally, this is done in ap_proxy_determine_connection().
     * TODO: Look at using ap_proxy_determine_connection() with a
     * fake request_rec
     */
    rv = ap_proxy_determine_address(proxy_function, backend,
                                    worker->s->hostname_ex, worker->s->port,
                                    0, NULL, s);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(03249)
                     "DNS lookup failure for: %s:%hu",
                     worker->s->hostname_ex, worker->s->port);
        return !OK;
    }

    return OK;
}

static apr_status_t backend_cleanup(const char *proxy_function, proxy_conn_rec *backend,
                                    server_rec *s, int status)
{
    if (backend) {
        backend->close = 1;
        ap_proxy_release_connection(proxy_function, backend, s);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03251)
                         "Health check %s Status (%d) for %s.",
                         ap_proxy_show_hcmethod(backend->worker->s->method),
                         status,
                         backend->worker->s->name_ex);
    }
    if (status != OK) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static int hc_get_backend(const char *proxy_function, proxy_conn_rec **backend,
                          proxy_worker *hc, sctx_t *ctx)
{
    int status;

    status = ap_proxy_acquire_connection(proxy_function, backend, hc, ctx->s);
    if (status != OK) {
        return status;
    }

    if (strcmp(hc->s->scheme, "https") == 0 || strcmp(hc->s->scheme, "wss") == 0 ) {
        if (!ap_ssl_has_outgoing_handlers()) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ctx->s, APLOGNO(03252)
                          "mod_ssl not configured?");
            return !OK;
        }
        (*backend)->is_ssl = 1;
    }

    return hc_determine_connection(proxy_function, *backend, ctx->s);
}

static apr_status_t hc_init_baton(baton_t *baton)
{
    sctx_t *ctx = baton->ctx;
    proxy_worker *worker = baton->worker, *hc;
    apr_status_t rv = APR_SUCCESS;
    int once = 0;

    /*
     * Since this is the watchdog, workers never actually handle a
     * request here, and so the local data isn't initialized (of
     * course, the shared memory is). So we need to bootstrap
     * worker->cp. Note, we only need do this once.
     */
    if (!worker->cp) {
        rv = ap_proxy_initialize_worker(worker, ctx->s, ctx->p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ctx->s, APLOGNO(03250) "Cannot init worker");
            return rv;
        }
        once = 1;
    }

    baton->hc = hc = hc_get_hcworker(ctx, worker, baton->ptemp);

    /* Try to resolve the worker address once if it's reusable */
    if (once && worker->s->is_address_reusable) {
        proxy_conn_rec *backend = NULL;
        if (hc_get_backend("HCHECK", &backend, hc, ctx)) {
            rv = APR_EGENERAL;
        }
        if (backend) {
            backend->close = 1;
            ap_proxy_release_connection("HCHECK", backend, ctx->s);
        }
    }

    return rv;
}

static apr_status_t hc_check_cping(baton_t *baton, apr_thread_t *thread)
{
    int status;
    sctx_t *ctx = baton->ctx;
    proxy_worker *hc = baton->hc;
    proxy_conn_rec *backend = NULL;
    apr_pool_t *ptemp = baton->ptemp;
    request_rec *r;
    apr_interval_time_t timeout;

    if (!ajp_handle_cping_cpong) {
        return APR_ENOTIMPL;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, baton->ctx->s, "HCCPING starting");
    if ((status = hc_get_backend("HCCPING", &backend, hc, ctx)) != OK) {
        return backend_cleanup("HCCPING", backend, ctx->s, status);
    }
    if ((status = ap_proxy_connect_backend("HCCPING", backend, hc, ctx->s)) != OK) {
        return backend_cleanup("HCCPING", backend, ctx->s, status);
    }
    r = create_request_rec(ptemp, ctx->s, baton->balancer, "CPING", NULL);
    if ((status = ap_proxy_connection_create_ex("HCCPING", backend, r)) != OK) {
        return backend_cleanup("HCCPING", backend, ctx->s, status);
    }
    set_request_connection(r, backend->connection);
    backend->connection->current_thread = thread;

    if (hc->s->ping_timeout_set) {
        timeout = hc->s->ping_timeout;
    } else if ( hc->s->conn_timeout_set) {
        timeout = hc->s->conn_timeout;
    } else if ( hc->s->timeout_set) {
        timeout = hc->s->timeout;
    } else {
        /* default to socket timeout */
        apr_socket_timeout_get(backend->sock, &timeout); 
    }
    status = ajp_handle_cping_cpong(backend->sock, r, timeout);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, baton->ctx->s, "HCCPING done %d", status);
    return backend_cleanup("HCCPING", backend, ctx->s, status);
}

static apr_status_t hc_check_tcp(baton_t *baton)
{
    int status;
    sctx_t *ctx = baton->ctx;
    proxy_worker *hc = baton->hc;
    proxy_conn_rec *backend = NULL;

    status = hc_get_backend("HCTCP", &backend, hc, ctx);
    if (status == OK) {
        status = ap_proxy_connect_backend("HCTCP", backend, hc, ctx->s);
        /* does an unconditional ap_proxy_is_socket_connected() */
    }
    return backend_cleanup("HCTCP", backend, ctx->s, status);
}

static int hc_send(request_rec *r, const char *out, apr_bucket_brigade *bb)
{
    apr_status_t rv;
    conn_rec *c = r->connection;
    apr_bucket_alloc_t *ba = c->bucket_alloc;
    ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, r->server, "%s", out);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(out, strlen(out),
                                                       r->pool, ba));
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(ba));
    rv = ap_pass_brigade(c->output_filters, bb);
    apr_brigade_cleanup(bb);
    return (rv) ? !OK : OK;
}

static int hc_read_headers(request_rec *r)
{
    char buffer[HUGE_STRING_LEN];
    int len;
    const char *ct;

    len = ap_getline(buffer, sizeof(buffer), r, 1);
    if (len <= 0) {
        return !OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, APLOGNO(03254)
                 "%.*s", len, buffer);
    /* for the below, see ap_proxy_http_process_response() */
    if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
        int major;
        char keepchar;
        int proxy_status = OK;
        const char *proxy_status_line = NULL;

        major = buffer[5] - '0';
        if ((major != 1) || (len >= sizeof(buffer)-1)) {
            return !OK;
        }

        keepchar = buffer[12];
        buffer[12] = '\0';
        proxy_status = atoi(&buffer[9]);
        if (keepchar != '\0') {
            buffer[12] = keepchar;
        } else {
            buffer[12] = ' ';
            buffer[13] = '\0';
        }
        proxy_status_line = apr_pstrdup(r->pool, &buffer[9]);
        r->status = proxy_status;
        r->status_line = proxy_status_line;
    } else {
        return !OK;
    }

    /* OK, 1st line is OK... scarf in the headers */
    while ((len = ap_getline(buffer, sizeof(buffer), r, 1)) > 0) {
        char *value, *end;
        ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, r->server, "%.*s",
                     len, buffer);
        if (!(value = strchr(buffer, ':'))) {
            return !OK;
        }
        *value = '\0';
        ++value;
        while (apr_isspace(*value))
            ++value;            /* Skip to start of value   */
        for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
            *end = '\0';
        apr_table_add(r->headers_out, buffer, value);
    }

    /* Set the Content-Type for the request if set */
    if ((ct = apr_table_get(r->headers_out, "Content-Type")) != NULL)
        ap_set_content_type(r, ct);

    return OK;
}

static int hc_read_body(request_rec *r, apr_bucket_brigade *bb)
{
    apr_status_t rv = APR_SUCCESS;
    int seen_eos = 0;

    do {
        apr_size_t len = HUGE_STRING_LEN;

        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, len);

        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_EOF(rv)) {
                rv = APR_SUCCESS;
                break;
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server, APLOGNO(03300)
                          "Error reading response body");
            break;
        }

        while (!APR_BRIGADE_EMPTY(bb)) {
            apr_bucket *bucket = APR_BRIGADE_FIRST(bb);
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }
            if (APR_BUCKET_IS_FLUSH(bucket)) {
                apr_bucket_delete(bucket);
                continue;
            }
            APR_BUCKET_REMOVE(bucket);
            APR_BRIGADE_INSERT_TAIL(r->kept_body, bucket);
        }
    }
    while (!seen_eos);
    apr_brigade_cleanup(bb);
    return (rv == APR_SUCCESS ? OK : !OK);
}

/*
 * Send the HTTP OPTIONS, HEAD or GET request to the backend
 * server associated w/ worker. If we have Conditions,
 * then apply those to the resulting response, otherwise
 * any status code 2xx or 3xx is considered "passing"
 */
static apr_status_t hc_check_http(baton_t *baton, apr_thread_t *thread)
{
    int status;
    proxy_conn_rec *backend = NULL;
    sctx_t *ctx = baton->ctx;
    proxy_worker *hc = baton->hc;
    proxy_worker *worker = baton->worker;
    apr_pool_t *ptemp = baton->ptemp;
    request_rec *r;
    wctx_t *wctx;
    hc_condition_t *cond;
    apr_bucket_brigade *bb;

    wctx = (wctx_t *)hc->context;
    if (!wctx->req || !wctx->method) {
        return APR_ENOTIMPL;
    }

    if ((status = hc_get_backend("HCOH", &backend, hc, ctx)) != OK) {
        return backend_cleanup("HCOH", backend, ctx->s, status);
    }
    if ((status = ap_proxy_connect_backend("HCOH", backend, hc, ctx->s)) != OK) {
        return backend_cleanup("HCOH", backend, ctx->s, status);
    }

    r = create_request_rec(ptemp, ctx->s, baton->balancer, wctx->method, wctx->protocol);
    if ((status = ap_proxy_connection_create_ex("HCOH", backend, r)) != OK) {
        return backend_cleanup("HCOH", backend, ctx->s, status);
    }
    set_request_connection(r, backend->connection);
    backend->connection->current_thread = thread;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    if ((status = hc_send(r, wctx->req, bb)) != OK) {
        return backend_cleanup("HCOH", backend, ctx->s, status);
    }
    if ((status = hc_read_headers(r)) != OK) {
        return backend_cleanup("HCOH", backend, ctx->s, status);
    }
    if (!r->header_only) {
        apr_table_t *saved_headers_in = r->headers_in;
        r->headers_in = apr_table_copy(r->pool, r->headers_out);
        ap_proxy_pre_http_request(backend->connection, r);
        status = hc_read_body(r, bb);
        r->headers_in = saved_headers_in;
        if (status != OK) {
            return backend_cleanup("HCOH", backend, ctx->s, status);
        }
        r->trailers_out = apr_table_copy(r->pool, r->trailers_in);
    }

    if (*worker->s->hcexpr &&
            (cond = (hc_condition_t *)apr_table_get(ctx->conditions, worker->s->hcexpr)) != NULL) {
        const char *err;
        int ok = ap_expr_exec(r, cond->pexpr, &err);
        if (ok > 0) {
            ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ctx->s,
                         "Condition %s for %s (%s): passed", worker->s->hcexpr,
                         hc->s->name_ex, worker->s->name_ex);
        } else if (ok < 0 || err) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, ctx->s, APLOGNO(03301)
                         "Error on checking condition %s for %s (%s): %s", worker->s->hcexpr,
                         hc->s->name_ex, worker->s->name_ex, err);
            status = !OK;
        } else {
            ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ctx->s,
                         "Condition %s for %s (%s) : failed", worker->s->hcexpr,
                         hc->s->name_ex, worker->s->name_ex);
            status = !OK;
        }
    } else if (r->status < 200 || r->status > 399) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ctx->s,
                     "Response status %i for %s (%s): failed", r->status,
                     hc->s->name_ex, worker->s->name_ex);
        status = !OK;
    }
    return backend_cleanup("HCOH", backend, ctx->s, status);
}

static void * APR_THREAD_FUNC hc_check(apr_thread_t *thread, void *b)
{
    baton_t *baton = (baton_t *)b;
    server_rec *s = baton->ctx->s;
    proxy_worker *worker = baton->worker;
    proxy_worker *hc = baton->hc;
    apr_time_t now;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03256)
                 "%sHealth checking %s", (thread ? "Threaded " : ""),
                 worker->s->name_ex);

    if (hc->s->method == TCP) {
        rv = hc_check_tcp(baton);
    }
    else if (hc->s->method == CPING) {
        rv = hc_check_cping(baton, thread);
    }
    else {
        rv = hc_check_http(baton, thread);
    }

    now = apr_time_now();
    if (rv == APR_ENOTIMPL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(03257)
                         "Somehow tried to use unimplemented hcheck method: %d",
                         (int)hc->s->method);
    }
    /* what state are we in ? */
    else if (PROXY_WORKER_IS_HCFAILED(worker) || PROXY_WORKER_IS_ERROR(worker)) {
        if (rv == APR_SUCCESS) {
            worker->s->pcount += 1;
            if (worker->s->pcount >= worker->s->passes) {
                ap_proxy_set_wstatus(PROXY_WORKER_HC_FAIL_FLAG, 0, worker);
                ap_proxy_set_wstatus(PROXY_WORKER_IN_ERROR_FLAG, 0, worker);
                worker->s->pcount = 0;
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(03302)
                             "%sHealth check ENABLING %s", (thread ? "Threaded " : ""),
                             worker->s->name_ex);

            }
        }
    }
    else {
        if (rv != APR_SUCCESS) {
            worker->s->error_time = now;
            worker->s->fcount += 1;
            if (worker->s->fcount >= worker->s->fails) {
                ap_proxy_set_wstatus(PROXY_WORKER_HC_FAIL_FLAG, 1, worker);
                worker->s->fcount = 0;
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(03303)
                             "%sHealth check DISABLING %s", (thread ? "Threaded " : ""),
                             worker->s->name_ex);
            }
        }
    }
    if (baton->now) {
        *baton->now = now;
    }
    apr_pool_destroy(baton->ptemp);
    worker->s->updated = now;

    return NULL;
}

static apr_status_t hc_watchdog_callback(int state, void *data,
                                         apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    proxy_balancer *balancer;
    sctx_t *ctx = (sctx_t *)data;
    server_rec *s = ctx->s;
    proxy_server_conf *conf;

    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03258)
                         "%s watchdog started.",
                         HCHECK_WATHCHDOG_NAME);
#if HC_USE_THREADS
            if (tpsize && hctp == NULL) {
                rv =  apr_thread_pool_create(&hctp, tpsize,
                                             tpsize, ctx->p);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(03312)
                                 "apr_thread_pool_create() with %d threads failed",
                                 tpsize);
                    /* we can continue on without the threadpools */
                    hctp = NULL;
                } else {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(03313)
                                 "apr_thread_pool_create() with %d threads succeeded",
                                 tpsize);
                }
            } else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(03314)
                             "Skipping apr_thread_pool_create()");
                hctp = NULL;
            }
#endif
            break;

        case AP_WATCHDOG_STATE_RUNNING:
            /* loop thru all workers */
            if (s) {
                int i;
                conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
                balancer = (proxy_balancer *)conf->balancers->elts;
                ctx->s = s;
                for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
                    int n;
                    apr_time_t now;
                    proxy_worker **workers;
                    proxy_worker *worker;
                    /* Have any new balancers or workers been added dynamically? */
                    ap_proxy_sync_balancer(balancer, s, conf);
                    workers = (proxy_worker **)balancer->workers->elts;
                    now = apr_time_now();
                    for (n = 0; n < balancer->workers->nelts; n++) {
                        worker = *workers;
                        if (!PROXY_WORKER_IS(worker, PROXY_WORKER_STOPPED) &&
                            (worker->s->method != NONE) &&
                            (worker->s->updated != 0) &&
                            (now > worker->s->updated + worker->s->interval)) {
                            baton_t *baton;
                            apr_pool_t *ptemp;

                            ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
                                         "Checking %s worker: %s  [%d] (%pp)", balancer->s->name,
                                         worker->s->name_ex, worker->s->method, worker);

                            /* This pool has the lifetime of the check */
                            apr_pool_create(&ptemp, ctx->p);
                            apr_pool_tag(ptemp, "hc_request");
                            baton = apr_pcalloc(ptemp, sizeof(baton_t));
                            baton->ctx = ctx;
                            baton->balancer = balancer;
                            baton->worker = worker;
                            baton->ptemp = ptemp;
                            if ((rv = hc_init_baton(baton))) {
                                worker->s->updated = now;
                                apr_pool_destroy(ptemp);
                                return rv;
                            }
                            worker->s->updated = 0;
#if HC_USE_THREADS
                            if (hctp) {
                                apr_thread_pool_push(hctp, hc_check, (void *)baton,
                                                     APR_THREAD_TASK_PRIORITY_NORMAL,
                                                     NULL);
                            }
                            else
#endif
                            {
                                baton->now = &now;
                                hc_check(NULL, baton);
                            }
                        }
                        workers++;
                    }
                }
            }
            break;

        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03261)
                         "stopping %s watchdog.",
                         HCHECK_WATHCHDOG_NAME);
#if HC_USE_THREADS
            if (hctp) {
                rv =  apr_thread_pool_destroy(hctp);
                if (rv != APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(03315)
                                 "apr_thread_pool_destroy() failed");
                }
                hctp = NULL;
            }
#endif
            break;
    }
    return rv;
}
static int hc_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                         apr_pool_t *ptemp)
{
#if HC_USE_THREADS
    hctp = NULL;
    tpsize = HC_THREADPOOL_SIZE;
#endif

    ajp_handle_cping_cpong = APR_RETRIEVE_OPTIONAL_FN(ajp_handle_cping_cpong);
    if (ajp_handle_cping_cpong) {
       proxy_hcmethods_t *method = proxy_hcmethods;
       for (; method->name; method++) {
           if (method->method == CPING) {
               method->implemented = 1;
               break;
           }
       }
    }

    return OK;
}
static int hc_post_config(apr_pool_t *p, apr_pool_t *plog,
                       apr_pool_t *ptemp, server_rec *main_s)
{
    apr_status_t rv;
    server_rec *s = main_s;

    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *hc_watchdog_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *hc_watchdog_register_callback;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }
    hc_watchdog_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    hc_watchdog_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!hc_watchdog_get_instance || !hc_watchdog_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(03262)
                     "mod_watchdog is required");
        return !OK;
    }
    rv = hc_watchdog_get_instance(&watchdog,
                                  HCHECK_WATHCHDOG_NAME,
                                  0, 1, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(03263)
                     "Failed to create watchdog instance (%s)",
                     HCHECK_WATHCHDOG_NAME);
        return !OK;
    }
    while (s) {
        sctx_t *ctx = ap_get_module_config(s->module_config,
                                           &proxy_hcheck_module);

        if (s != ctx->s) {
            ap_log_error(APLOG_MARK, APLOG_TRACE4, 0, s, APLOGNO(10019)
                         "Missing unique per-server context: %s (%pp:%pp) (no hchecks)",
                         s->server_hostname, s, ctx->s);
            s = s->next;
            continue;
        }
        rv = hc_watchdog_register_callback(watchdog,
                AP_WD_TM_SLICE,
                ctx,
                hc_watchdog_callback);
        if (rv) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(03264)
                         "Failed to register watchdog callback (%s)",
                         HCHECK_WATHCHDOG_NAME);
            return !OK;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(03265)
                     "watchdog callback registered (%s for %s)", HCHECK_WATHCHDOG_NAME, s->server_hostname);
        s = s->next;
    }

    return OK;
}

static void hc_show_exprs(request_rec *r)
{
    const apr_table_entry_t *elts;
    const apr_array_header_t *hdr;
    int i;
    sctx_t *ctx = (sctx_t *) ap_get_module_config(r->server->module_config,
                                                  &proxy_hcheck_module);
    if (!ctx)
        return;
    if (apr_is_empty_table(ctx->conditions))
        return;

    ap_rputs("\n\n<table>"
             "<tr><th colspan='2'>Health check cond. expressions:</th></tr>\n"
             "<tr><th>Expr name</th><th>Expression</th></tr>\n", r);

    hdr = apr_table_elts(ctx->conditions);
    elts = (const apr_table_entry_t *) hdr->elts;
    for (i = 0; i < hdr->nelts; ++i) {
        hc_condition_t *cond;
        if (!elts[i].key) {
            continue;
        }
        cond = (hc_condition_t *)elts[i].val;
        ap_rprintf(r, "<tr><td>%s</td><td>%s</td></tr>\n",
                   ap_escape_html(r->pool, elts[i].key),
                   ap_escape_html(r->pool, cond->expr));
    }
    ap_rputs("</table><hr/>\n", r);
}

static void hc_select_exprs(request_rec *r, const char *expr)
{
    const apr_table_entry_t *elts;
    const apr_array_header_t *hdr;
    int i;
    sctx_t *ctx = (sctx_t *) ap_get_module_config(r->server->module_config,
                                                  &proxy_hcheck_module);
    if (!ctx)
        return;
    if (apr_is_empty_table(ctx->conditions))
        return;

    hdr = apr_table_elts(ctx->conditions);
    elts = (const apr_table_entry_t *) hdr->elts;
    for (i = 0; i < hdr->nelts; ++i) {
        if (!elts[i].key) {
            continue;
        }
        ap_rprintf(r, "<option value='%s' %s >%s</option>\n",
                   ap_escape_html(r->pool, elts[i].key),
                   (!strcmp(elts[i].key, expr)) ? "selected" : "",
                           ap_escape_html(r->pool, elts[i].key));
    }
}

static int hc_valid_expr(request_rec *r, const char *expr)
{
    const apr_table_entry_t *elts;
    const apr_array_header_t *hdr;
    int i;
    sctx_t *ctx = (sctx_t *) ap_get_module_config(r->server->module_config,
                                                  &proxy_hcheck_module);
    if (!ctx)
        return 0;
    if (apr_is_empty_table(ctx->conditions))
        return 0;

    hdr = apr_table_elts(ctx->conditions);
    elts = (const apr_table_entry_t *) hdr->elts;
    for (i = 0; i < hdr->nelts; ++i) {
        if (!elts[i].key) {
            continue;
        }
        if (!strcmp(elts[i].key, expr))
            return 1;
    }
    return 0;
}

static const char *hc_get_body(request_rec *r)
{
    apr_off_t length;
    apr_size_t len;
    apr_status_t rv;
    char *buf;

    if (!r || !r->kept_body)
        return "";

    rv = apr_brigade_length(r->kept_body, 1, &length);
    len = (apr_size_t)length;
    if (rv != APR_SUCCESS || len == 0)
        return "";

    buf = apr_palloc(r->pool, len + 1);
    rv = apr_brigade_flatten(r->kept_body, buf, &len);
    if (rv != APR_SUCCESS)
        return "";
    buf[len] = '\0'; /* ensure */
    return (const char*)buf;
}

static const char *hc_expr_var_fn(ap_expr_eval_ctx_t *ctx, const void *data)
{
    char *var = (char *)data;

    if (var && *var && ctx->r && ap_cstr_casecmp(var, "BODY") == 0) {
        return hc_get_body(ctx->r);
    }
    return NULL;
}

static const char *hc_expr_func_fn(ap_expr_eval_ctx_t *ctx, const void *data,
                                const char *arg)
{
    char *var = (char *)arg;

    if (var && *var && ctx->r && ap_cstr_casecmp(var, "BODY") == 0) {
        return hc_get_body(ctx->r);
    }
    return NULL;
}

static int hc_expr_lookup(ap_expr_lookup_parms *parms)
{
    switch (parms->type) {
    case AP_EXPR_FUNC_VAR:
        /* for now, we just handle everything that starts with HC_.
         */
        if (strncasecmp(parms->name, "HC_", 3) == 0) {
            *parms->func = hc_expr_var_fn;
            *parms->data = parms->name + 3;
            return OK;
        }
        break;
    case AP_EXPR_FUNC_STRING:
        /* Function HC() is implemented by us.
         */
        if (strcasecmp(parms->name, "HC") == 0) {
            *parms->func = hc_expr_func_fn;
            *parms->data = parms->arg;
            return OK;
        }
        break;
    }
    return DECLINED;
}

static const command_rec command_table[] = {
    AP_INIT_RAW_ARGS("ProxyHCTemplate", set_hc_template, NULL, OR_FILEINFO,
                     "Health check template"),
    AP_INIT_RAW_ARGS("ProxyHCExpr", set_hc_condition, NULL, OR_FILEINFO,
                     "Define a health check condition ruleset expression"),
#if HC_USE_THREADS
    AP_INIT_TAKE1("ProxyHCTPsize", set_hc_tpsize, NULL, RSRC_CONF,
                     "Set size of health check thread pool"),
#endif
    { NULL }
};

static void hc_register_hooks(apr_pool_t *p)
{
    static const char *const aszPre[] = { "mod_proxy_balancer.c", "mod_proxy.c", NULL};
    static const char *const aszSucc[] = { "mod_watchdog.c", NULL};
    APR_REGISTER_OPTIONAL_FN(set_worker_hc_param);
    APR_REGISTER_OPTIONAL_FN(hc_show_exprs);
    APR_REGISTER_OPTIONAL_FN(hc_select_exprs);
    APR_REGISTER_OPTIONAL_FN(hc_valid_expr);
    ap_hook_pre_config(hc_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(hc_post_config, aszPre, aszSucc, APR_HOOK_LAST);
    ap_hook_expr_lookup(hc_expr_lookup, NULL, NULL, APR_HOOK_MIDDLE);
}

/* the main config structure */

AP_DECLARE_MODULE(proxy_hcheck) =
{
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-dir config structures */
    NULL,              /* merge  per-dir config structures */
    hc_create_config,  /* create per-server config structures */
    NULL,              /* merge  per-server config structures */
    command_table,     /* table of config file commands */
    hc_register_hooks  /* register hooks */
};
