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

module AP_MODULE_DECLARE_DATA proxy_hcheck_module;

#define HCHECK_WATHCHDOG_NAME ("_proxy_hcheck_")

typedef struct {
    char *name;
    hcmethod_t method;
    int passes;
    int fails;
    apr_interval_time_t interval;
    char *hurl;
} hc_template_t;

typedef struct {
    char *name;
    ap_expr_info_t *expr;       /* parsed expression */
} hc_condition_t;

typedef struct {
    apr_pool_t *p;
    apr_bucket_alloc_t *ba;
    apr_array_header_t *templates;
    apr_array_header_t *conditions;
    ap_watchdog_t *watchdog;
    /* TODO: Make below array/hashtable tagged to each worker */
    apr_hash_t *hcworkers;
    server_rec *s;
} sctx_t;

typedef struct {
    char *path;
    char *req;
} wctx_t;

static void *hc_create_config(apr_pool_t *p, server_rec *s)
{
    sctx_t *ctx = (sctx_t *) apr_palloc(p, sizeof(sctx_t));
    apr_pool_create(&ctx->p, p);
    ctx->ba = apr_bucket_alloc_create(p);
    ctx->templates = apr_array_make(ctx->p, 10, sizeof(hc_template_t));
    ctx->conditions = apr_array_make(ctx->p, 10, sizeof(hc_condition_t));
    ctx->hcworkers = apr_hash_make(ctx->p);
    ctx->s = s;

    return ctx;
}

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
    temp = (hc_template_t *)v;
    if (!strcasecmp(key, "hctemplate")) {
        hc_template_t *template;
        template = (hc_template_t *)ctx->templates->elts;
        for (ival = 0; ival < ctx->templates->nelts; ival++, template++) {
            if (!ap_casecmpstr(template->name, val)) {
                if (worker) {
                    worker->s->method = template->method;
                    worker->s->interval = template->interval;
                    worker->s->passes = template->passes;
                    worker->s->fails = template->fails;
                    PROXY_STRNCPY(worker->s->hcuri, template->hurl);
                } else {
                    temp->method = template->method;
                    temp->interval = template->interval;
                    temp->passes = template->passes;
                    temp->fails = template->fails;
                    temp->hurl = apr_pstrdup(p, template->hurl);
                }
                return NULL;
            }
        }
        return apr_psprintf(p, "Unknown ProxyHCTemplate name: %s", val);
    }
    else if (!strcasecmp(key, "hcmethod")) {
        hcmethods_t *method = hcmethods;
        for (; method->name; method++) {
            if (!ap_casecmpstr(val, method->name)) {
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
        ival = atoi(val);
        if (ival < HCHECK_WATHCHDOG_INTERVAL)
            return apr_psprintf(p, "Interval must be a positive value greater than %d seconds",
                                HCHECK_WATHCHDOG_INTERVAL);
        if (worker) {
            worker->s->interval = apr_time_from_sec(ival);
        } else {
            temp->interval = apr_time_from_sec(ival);
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
    else {
        return "unknown Worker hcheck parameter";
    }
    return NULL;
}

static const char *set_hc_condition(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *name = NULL;
    char *expr;
    hc_condition_t *condition;
    sctx_t *ctx;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;
    ctx = (sctx_t *) ap_get_module_config(cmd->server->module_config,
                                          &proxy_hcheck_module);

    name = ap_getword_conf(cmd->temp_pool, &arg);
    if (!*name) {
        return apr_pstrcat(cmd->temp_pool, "Missing condition name for ",
                           cmd->cmd->name, NULL);
    }
    /* get expr. Allow fancy new {...} quoting style */
    expr = ap_getword_conf2(cmd->temp_pool, &arg);
    if (!*expr) {
        return apr_pstrcat(cmd->temp_pool, "Missing expression for ",
                           cmd->cmd->name, NULL);
    }
    condition = (hc_condition_t *)apr_array_push(ctx->conditions);
    condition->name = apr_pstrdup(ctx->p, name);
    condition->expr = ap_expr_parse_cmd(cmd, expr, 0, &err, NULL);
    if (err) {
        /* get rid of recently pushed (bad) condition */
        apr_array_pop(ctx->conditions);
        return apr_psprintf(cmd->temp_pool, "Could not parse expression \"%s\": %s",
                            expr, err);
    }
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

    template->name = apr_pstrdup(ctx->p, name);
    template->method = template->passes = template->fails = 1;
    template->interval = apr_time_from_sec(HCHECK_WATHCHDOG_DEFAULT_INTERVAL);
    template->hurl = NULL;
    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid ProxyHCTemplate parameter. Parameter must be "
                   "in the form 'key=value'";
        }
        else
            *val++ = '\0';
        err = set_worker_hc_param(ctx->p, ctx->s, NULL, word, val, template);

        if (err) {
            /* get rid of recently pushed (bad) template */
            apr_array_pop(ctx->templates);
            return apr_pstrcat(cmd->temp_pool, "ProxyHCTemplate: ", err, " ", word, "=", val, "; ", name, NULL);
        }
        /* No error means we have a valid template */
    }

    return NULL;
}

static request_rec *create_request_rec(apr_pool_t *p1, conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;

    apr_pool_create(&p, p1);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 25);
    r->trailers_in     = apr_table_make(r->pool, 5);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */

    r->proto_output_filters = conn->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = conn->input_filters;
    r->input_filters   = r->proto_input_filters;
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  /* Until further notice */
    r->header_only     = 0;
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;


    /* Time to populate r with the data we have. */
    r->method = "OPTIONS";
    /* Provide quick information about the request method as soon as known */
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H') {
        r->header_only = 1;
    }

    r->protocol = (char*)"HTTP/1.1";
    r->proto_num = HTTP_VERSION(1, 1);

    r->hostname = NULL;

    return r;
}

static proxy_worker *hc_get_hcworker(sctx_t *ctx, proxy_worker *worker,
                                     apr_pool_t *p)
{
    proxy_worker *hc = NULL;
    const char* wptr;

    wptr = apr_psprintf(ctx->p, "%pp", worker);
    hc = (proxy_worker *)apr_hash_get(ctx->hcworkers, wptr, APR_HASH_KEY_STRING);
    if (!hc) {
        apr_uri_t uri;
        apr_status_t rv;
        const char *url = worker->s->name;
        wctx_t *wctx = apr_pcalloc(ctx->p, sizeof(wctx_t));

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                     "Creating hc worker %s for %s://%s:%d",
                     wptr, worker->s->scheme, worker->s->hostname,
                     (int)worker->s->port);

        ap_proxy_define_worker(ctx->p, &hc, NULL, NULL, worker->s->name, 0);
        PROXY_STRNCPY(hc->s->name,     wptr);
        PROXY_STRNCPY(hc->s->hostname, worker->s->hostname);
        PROXY_STRNCPY(hc->s->scheme,   worker->s->scheme);
        hc->hash.def = hc->s->hash.def = ap_proxy_hashfunc(hc->s->name, PROXY_HASHFUNC_DEFAULT);
        hc->hash.fnv = hc->s->hash.fnv = ap_proxy_hashfunc(hc->s->name, PROXY_HASHFUNC_FNV);
        hc->s->port = worker->s->port;
        /* Do not disable worker in case of errors */
        hc->s->status |= PROXY_WORKER_IGNORE_ERRORS;
        /* Mark as the "generic" worker */
        hc->s->status |= PROXY_WORKER_GENERIC;
        ap_proxy_initialize_worker(hc, ctx->s, ctx->p);
        hc->s->is_address_reusable = worker->s->is_address_reusable;
        hc->s->disablereuse = worker->s->disablereuse;
        /* tuck away since we need the preparsed address */
        hc->cp->addr = worker->cp->addr;
        hc->s->method = worker->s->method;

        rv = apr_uri_parse(p, url, &uri);
        if (rv == APR_SUCCESS) {
            wctx->path = apr_pstrdup(ctx->p, uri.path);
        }
        hc->context = wctx;
        apr_hash_set(ctx->hcworkers, wptr, APR_HASH_KEY_STRING, hc);
    }
    return hc;
}

static int hc_determine_connection(sctx_t *ctx, proxy_worker *worker) {
    apr_status_t rv = APR_SUCCESS;
    int will_reuse = worker->s->is_address_reusable && !worker->s->disablereuse;
    /*
     * normally, this is done in ap_proxy_determine_connection().
     * TODO: Look at using ap_proxy_determine_connection() with a
     * fake request_rec
     */
    if (!worker->cp->addr || !will_reuse) {
        rv = apr_sockaddr_info_get(&(worker->cp->addr), worker->s->hostname, APR_UNSPEC,
                                   worker->s->port, 0, ctx->p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                         "DNS lookup failure for: %s:%d",
                         worker->s->hostname, (int)worker->s->port);
        }
    }
    return (rv == APR_SUCCESS ? OK : !OK);
}

static apr_status_t hc_init_worker(sctx_t *ctx, proxy_worker *worker) {
    apr_status_t rv = APR_SUCCESS;
    /*
     * Since this is the watchdog, workers never actually handle a
     * request here, and so the local data isn't initialized (of
     * course, the shared memory is). So we need to bootstrap
     * worker->cp. Note, we only need do this once.
     */
    if (!worker->cp) {
        rv = ap_proxy_initialize_worker(worker, ctx->s, ctx->p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ctx->s, APLOGNO() "Cannot init worker");
            return rv;
        }
        rv = (hc_determine_connection(ctx, worker) == OK ? APR_SUCCESS : APR_EGENERAL);
    }
    return rv;
}

static apr_status_t backend_cleanup(const char *proxy_function, proxy_conn_rec *backend,
                                    server_rec *s, int status)
{
    if (backend) {
        backend->close = 1;
        ap_proxy_release_connection(proxy_function, backend, s);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                     "Health check %s Status (%d) for %s.",
                     ap_proxy_show_hcmethod(backend->worker->s->method),
                     status,
                     backend->worker->s->name);
    if (status != OK) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static int hc_get_backend(apr_pool_t *p, const char *proxy_function, proxy_conn_rec **backend,
                          proxy_worker *hc, sctx_t *ctx)
{
    int status;
    status = ap_proxy_acquire_connection("HCTCP", backend, hc, ctx->s);
    if (status == OK) {
        (*backend)->addr = hc->cp->addr;
        (*backend)->pool = ctx->p;
        (*backend)->hostname = hc->s->hostname;
        if (strcmp(hc->s->scheme, "https") == 0) {
            if (!ap_proxy_ssl_enable(NULL)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                              "mod_ssl not configured?");
                return !OK;
            }
            (*backend)->is_ssl = 1;
        }

    }
    status = hc_determine_connection(ctx, hc);
    if (status == OK) {
        (*backend)->addr = hc->cp->addr;
    }
    return status;
}

static apr_status_t hc_check_tcp(sctx_t *ctx, apr_pool_t *p, proxy_worker *worker)
{
    int status;
    proxy_conn_rec *backend = NULL;
    proxy_worker *hc;

    hc = hc_get_hcworker(ctx, worker, p);

    status = hc_get_backend(p, "HCTCP", &backend, hc, ctx);
    if (status == OK) {
        backend->addr = hc->cp->addr;
        status = ap_proxy_connect_backend("HCTCP", backend, hc, ctx->s);
        if (status == OK) {
            status = (ap_proxy_is_socket_connected(backend->sock) ? OK : !OK);
        }
    }
    return backend_cleanup("HCTCP", backend, ctx->s, status);
}

static void hc_send(sctx_t *ctx, apr_pool_t *p, const char *out, proxy_conn_rec *backend)
{
    apr_bucket_brigade *tmp_bb = apr_brigade_create(p, ctx->ba);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO() "%s", out);
    APR_BRIGADE_INSERT_TAIL(tmp_bb, apr_bucket_pool_create(out, strlen(out), p,
                            ctx->ba));
    APR_BRIGADE_INSERT_TAIL(tmp_bb, apr_bucket_flush_create(ctx->ba));
    ap_pass_brigade(backend->connection->output_filters, tmp_bb);
    apr_brigade_destroy(tmp_bb);
}

static int hc_read_headers(sctx_t *ctx, request_rec *r)
{
    char buffer[HUGE_STRING_LEN];
    int len;

    len = ap_getline(buffer, sizeof(buffer), r, 1);
    if (len <= 0) {
        return !OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
            "%s", buffer);
    /* for the below, see ap_proxy_http_process_response() */
    if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
        int major, minor;
        char keepchar;
        int proxy_status = OK;
        const char *proxy_status_line = NULL;

        major = buffer[5] - '0';
        minor = buffer[7] - '0';
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
        if (!(value = strchr(buffer, ':'))) {
            return !OK;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ctx->s, APLOGNO()
                "%s", buffer);
        *value = '\0';
        ++value;
        while (apr_isspace(*value))
            ++value;            /* Skip to start of value   */
        for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
            *end = '\0';
        apr_table_add(r->headers_out, buffer, value);
    }
    return OK;
}

static apr_status_t hc_check_headers(sctx_t *ctx, apr_pool_t *p, proxy_worker *worker)
{
    int status;
    proxy_conn_rec *backend = NULL;
    proxy_worker *hc;
    conn_rec c;
    request_rec *r;
    const char *req;
    wctx_t *wctx;

    hc = hc_get_hcworker(ctx, worker, p);
    wctx = (wctx_t *)hc->context;

    if ((status = hc_get_backend(p, "HCTCP", &backend, hc, ctx)) != OK) {
        return backend_cleanup("HCTCP", backend, ctx->s, status);
    }
    if ((status = ap_proxy_connect_backend("HCTCP", backend, hc, ctx->s)) != OK) {
        return backend_cleanup("HCTCP", backend, ctx->s, status);
    }

    if (!backend->connection) {
        if ((status = ap_proxy_connection_create("HCTCP", backend, &c, ctx->s)) != OK) {
            return backend_cleanup("HCTCP", backend, ctx->s, status);
        }
    }
    switch (hc->s->method) {
        case OPTIONS:
            if (!wctx->req) {
                wctx->req = apr_psprintf(ctx->p,
                                   "OPTIONS * HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
                                    hc->s->hostname, (int)hc->s->port);
            }
            req = wctx->req;
            break;

        case HEAD:
            if (!wctx->req) {
                wctx->req = apr_psprintf(p,
                                   "HEAD %s%s%s HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
                                   (wctx->path ? wctx->path : ""),
                                   (wctx->path && *hc->s->hcuri ? "/" : "" ),
                                   (*hc->s->hcuri ? hc->s->hcuri : ""),
                                   hc->s->hostname, (int)hc->s->port);
            }
            req = wctx->req;
            break;

        default:
            return backend_cleanup("HCTCP", backend, ctx->s, !OK);
            break;
    }

    hc_send(ctx, p, req, backend);

    r = create_request_rec(p, backend->connection);
    r->pool = p;
    status = hc_read_headers(ctx, r);

    return backend_cleanup("HCTCP", backend, ctx->s, status);
}


static void hc_check(sctx_t *ctx, apr_pool_t *p, apr_time_t now,
                     proxy_worker *worker)
{
    server_rec *s = ctx->s;
    apr_status_t rv;
    /* TODO: REMOVE ap_log_error call */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                 "Health check (%s).", worker->s->name);

    switch (worker->s->method) {
        case TCP:
            rv = hc_check_tcp(ctx, p, worker);
            break;

        case OPTIONS:
        case HEAD:
             rv = hc_check_headers(ctx, p, worker);
             break;

        default:
            rv = APR_ENOTIMPL;
            break;
    }
    if (rv == APR_ENOTIMPL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO()
                         "Somehow tried to use unimplemented hcheck method: %d", (int)worker->s->method);
        return;
    }
    /* TODO Honor fails and passes */
    ap_proxy_set_wstatus('#', (rv == APR_SUCCESS ? 0 : 1), worker);
    if (rv != APR_SUCCESS) {
        worker->s->error_time = now;
    }
    worker->s->updated = now;
}

static apr_status_t hc_watchdog_callback(int state, void *data,
                                         apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t now = apr_time_now();
    proxy_balancer *balancer;
    sctx_t *ctx = (sctx_t *)data;
    server_rec *s = ctx->s;
    proxy_server_conf *conf;
    apr_pool_t *p;
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                         "%s watchdog started.",
                         HCHECK_WATHCHDOG_NAME);
            break;

        case AP_WATCHDOG_STATE_RUNNING:
            /* loop thru all workers */
            /* TODO: REMOVE ap_log_error call */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                         "Run of %s watchdog.",
                         HCHECK_WATHCHDOG_NAME);
            if (s) {
                int i;
                apr_pool_create(&p, pool);
                conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
                balancer = (proxy_balancer *)conf->balancers->elts;
                for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
                    int n;
                    proxy_worker **workers;
                    proxy_worker *worker;
                    /* Have any new balancers or workers been added dynamically? */
                    ap_proxy_sync_balancer(balancer, s, conf);
                    workers = (proxy_worker **)balancer->workers->elts;
                    for (n = 0; n < balancer->workers->nelts; n++) {
                        worker = *workers;
                        /* TODO: REMOVE ap_log_error call */
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                                     "Checking %s worker: %s  [%d] (%pp)", balancer->s->name,
                                     worker->s->name, worker->s->method, worker);
                        if ((worker->s->method != NONE) && (now > worker->s->updated + worker->s->interval)) {
                            if ((rv = hc_init_worker(ctx, worker)) != APR_SUCCESS) {
                                return rv;
                            }
                            hc_check(ctx, p, now, worker);
                        }
                        workers++;
                    }
                }
                apr_pool_destroy(p);
                /* s = s->next; */
            }
            break;

        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                         "stopping %s watchdog.",
                         HCHECK_WATHCHDOG_NAME);
            break;
    }
    return rv;
}

static int hc_post_config(apr_pool_t *p, apr_pool_t *plog,
                       apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    sctx_t *ctx;

    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *hc_watchdog_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *hc_watchdog_register_callback;

    hc_watchdog_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    hc_watchdog_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!hc_watchdog_get_instance || !hc_watchdog_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO()
                     "mod_watchdog is required");
        return !OK;
    }
    ctx = (sctx_t *) ap_get_module_config(s->module_config,
                                          &proxy_hcheck_module);

    rv = hc_watchdog_get_instance(&ctx->watchdog,
                                  HCHECK_WATHCHDOG_NAME,
                                  0, 1, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "Failed to create watchdog instance (%s)",
                     HCHECK_WATHCHDOG_NAME);
        return !OK;
    }
    rv = hc_watchdog_register_callback(ctx->watchdog,
            apr_time_from_sec(HCHECK_WATHCHDOG_INTERVAL),
            ctx,
            hc_watchdog_callback);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO()
                     "Failed to register watchdog callback (%s)",
                     HCHECK_WATHCHDOG_NAME);
        return !OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                 "watchdog callback registered (%s)", HCHECK_WATHCHDOG_NAME);
    return OK;
}

static const command_rec command_table[] = {
    AP_INIT_RAW_ARGS("ProxyHCTemplate", set_hc_template, NULL, OR_FILEINFO,
                     "Health check template"),
    AP_INIT_RAW_ARGS("ProxyHCCondition", set_hc_condition, NULL, OR_FILEINFO,
                     "Define a health check condition ruleset"),
    { NULL }
};

static void hc_register_hooks(apr_pool_t *p)
{
    static const char *const aszPre[] = { "mod_proxy_balancer.c", "mod_proxy.c", NULL};
    static const char *const aszSucc[] = { "mod_watchdog.c", NULL};
    APR_REGISTER_OPTIONAL_FN(set_worker_hc_param);
    ap_hook_post_config(hc_post_config, aszPre, aszSucc, APR_HOOK_LAST);
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
