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
#include "mod_core.h"
#include "apr_optional.h"
#include "scoreboard.h"
#include "mod_status.h"

#if (MODULE_MAGIC_NUMBER_MAJOR > 20020903)
#include "mod_ssl.h"
#else
APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *, char *));
#endif

#ifndef MAX
#define MAX(x,y) ((x) >= (y) ? (x) : (y))
#endif

/* return the sizeof of one lb_worker in scoreboard. */
static int ap_proxy_lb_worker_size(void)
{
    return sizeof(proxy_worker_stat);
}

/*
 * A Web proxy module. Stages:
 *
 *  translate_name: set filename to proxy:<URL>
 *  map_to_storage: run proxy_walk (rather than directory_walk/file_walk)
 *                  can't trust directory_walk/file_walk since these are
 *                  not in our filesystem.  Prevents mod_http from serving
 *                  the TRACE request we will set aside to handle later.
 *  type_checker:   set type to PROXY_MAGIC_TYPE if filename begins proxy:
 *  fix_ups:        convert the URL stored in the filename to the
 *                  canonical form.
 *  handler:        handle proxy requests
 */

/* -------------------------------------------------------------- */
/* Translate the URL into a 'filename' */

#define PROXY_COPY_CONF_PARAMS(w, c) \
    do {                             \
        (w)->timeout              = (c)->timeout;               \
        (w)->timeout_set          = (c)->timeout_set;           \
        (w)->recv_buffer_size     = (c)->recv_buffer_size;      \
        (w)->recv_buffer_size_set = (c)->recv_buffer_size_set;  \
        (w)->io_buffer_size       = (c)->io_buffer_size;        \
        (w)->io_buffer_size_set   = (c)->io_buffer_size_set;    \
    } while (0)

static const char *set_worker_param(apr_pool_t *p,
                                    proxy_worker *worker,
                                    const char *key,
                                    const char *val)
{

    int ival;
    apr_interval_time_t timeout;

    if (!strcasecmp(key, "loadfactor")) {
        /* Normalized load factor. Used with BalancerMamber,
         * it is a number between 1 and 100.
         */
        worker->lbfactor = atoi(val);
        if (worker->lbfactor < 1 || worker->lbfactor > 100)
            return "LoadFactor must be number between 1..100";
    }
    else if (!strcasecmp(key, "retry")) {
        /* If set it will give the retry timeout for the worker
         * The default value is 60 seconds, meaning that if
         * in error state, it will be retried after that timeout.
         */
        ival = atoi(val);
        if (ival < 0)
            return "Retry must be a positive value";
        worker->retry = apr_time_from_sec(ival);
        worker->retry_set = 1;
    }
    else if (!strcasecmp(key, "ttl")) {
        /* Time in seconds that will destroy all the connections
         * that exceed the smax
         */
        ival = atoi(val);
        if (ival < 1)
            return "TTL must be at least one second";
        worker->ttl = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "min")) {
        /* Initial number of connections to remote
         */
        ival = atoi(val);
        if (ival < 0)
            return "Min must be a positive number";
        worker->min = ival;
    }
    else if (!strcasecmp(key, "max")) {
        /* Maximum number of connections to remote
         */
        ival = atoi(val);
        if (ival < 0)
            return "Max must be a positive number";
        worker->hmax = ival;
    }
    /* XXX: More inteligent naming needed */
    else if (!strcasecmp(key, "smax")) {
        /* Maximum number of connections to remote that
         * will not be destroyed
         */
        ival = atoi(val);
        if (ival < 0)
            return "Smax must be a positive number";
        worker->smax = ival;
    }
    else if (!strcasecmp(key, "acquire")) {
        /* Acquire timeout in given unit (default is milliseconds).
         * If set this will be the maximum time to
         * wait for a free connection.
         */
        if (ap_timeout_parameter_parse(val, &timeout, "ms") != APR_SUCCESS)
            return "Acquire timeout has wrong format";
        if (timeout < 1000)
            return "Acquire must be at least one millisecond";
        worker->acquire = timeout;
        worker->acquire_set = 1;
    }
    else if (!strcasecmp(key, "timeout")) {
        /* Connection timeout in seconds.
         * Defaults to server timeout.
         */
        ival = atoi(val);
        if (ival < 1)
            return "Timeout must be at least one second";
        worker->timeout = apr_time_from_sec(ival);
        worker->timeout_set = 1;
    }
    else if (!strcasecmp(key, "iobuffersize")) {
        long s = atol(val);
        if (s < 512 && s) {
            return "IOBufferSize must be >= 512 bytes, or 0 for system default.";
        }
        worker->io_buffer_size = (s ? s : AP_IOBUFSIZE);
        worker->io_buffer_size_set = 1;
    }
    else if (!strcasecmp(key, "receivebuffersize")) {
        ival = atoi(val);
        if (ival < 512 && ival != 0) {
            return "ReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
        }
        worker->recv_buffer_size = ival;
        worker->recv_buffer_size_set = 1;
    }
    else if (!strcasecmp(key, "keepalive")) {
        if (!strcasecmp(val, "on"))
            worker->keepalive = 1;
        else if (!strcasecmp(val, "off"))
            worker->keepalive = 0;
        else
            return "KeepAlive must be On|Off";
        worker->keepalive_set = 1;
    }
    else if (!strcasecmp(key, "disablereuse")) {
        if (!strcasecmp(val, "on"))
            worker->disablereuse = 1;
        else if (!strcasecmp(val, "off"))
            worker->disablereuse = 0;
        else
            return "DisableReuse must be On|Off";
        worker->disablereuse_set = 1;
    }
    else if (!strcasecmp(key, "route")) {
        /* Worker route.
         */
        if (strlen(val) > PROXY_WORKER_MAX_ROUTE_SIZ)
            return "Route length must be < 64 characters";
        worker->route = apr_pstrdup(p, val);
    }
    else if (!strcasecmp(key, "redirect")) {
        /* Worker redirection route.
         */
        if (strlen(val) > PROXY_WORKER_MAX_ROUTE_SIZ)
            return "Redirect length must be < 64 characters";
        worker->redirect = apr_pstrdup(p, val);
    }
    else if (!strcasecmp(key, "status")) {
        const char *v;
        int mode = 1;
        /* Worker status.
         */
        for (v = val; *v; v++) {
            if (*v == '+') {
                mode = 1;
                v++;
            }
            else if (*v == '-') {
                mode = 0;
                v++;
            }
            if (*v == 'D' || *v == 'd') {
                if (mode)
                    worker->status |= PROXY_WORKER_DISABLED;
                else
                    worker->status &= ~PROXY_WORKER_DISABLED;
            }
            else if (*v == 'S' || *v == 's') {
                if (mode)
                    worker->status |= PROXY_WORKER_STOPPED;
                else
                    worker->status &= ~PROXY_WORKER_STOPPED;
            }
            else if (*v == 'E' || *v == 'e') {
                if (mode)
                    worker->status |= PROXY_WORKER_IN_ERROR;
                else
                    worker->status &= ~PROXY_WORKER_IN_ERROR;
            }
            else if (*v == 'H' || *v == 'h') {
                if (mode)
                    worker->status |= PROXY_WORKER_HOT_STANDBY;
                else
                    worker->status &= ~PROXY_WORKER_HOT_STANDBY;
            }
            else if (*v == 'I' || *v == 'i') {
                if (mode)
                    worker->status |= PROXY_WORKER_IGNORE_ERRORS;
                else
                    worker->status &= ~PROXY_WORKER_IGNORE_ERRORS;
            }
            else {
                return "Unknown status parameter option";
            }
        }
    }
    else if (!strcasecmp(key, "flushpackets")) {
        if (!strcasecmp(val, "on"))
            worker->flush_packets = flush_on;
        else if (!strcasecmp(val, "off"))
            worker->flush_packets = flush_off;
        else if (!strcasecmp(val, "auto"))
            worker->flush_packets = flush_auto;
        else
            return "flushpackets must be on|off|auto";
    }
    else if (!strcasecmp(key, "flushwait")) {
        ival = atoi(val);
        if (ival > 1000 || ival < 0) {
            return "flushwait must be <= 1000, or 0 for system default of 10 millseconds.";
        }
        if (ival == 0)
            worker->flush_wait = PROXY_FLUSH_WAIT;
        else
            worker->flush_wait = ival * 1000;    /* change to microseconds */
    }
    else if (!strcasecmp(key, "ping")) {
        /* Ping/Pong timeout in given unit (default is second).
         */
        if (ap_timeout_parameter_parse(val, &timeout, "s") != APR_SUCCESS)
            return "Ping/Pong timeout has wrong format";
        if (timeout < 1000)
            return "Ping/Pong timeout must be at least one millisecond";
        worker->ping_timeout = timeout;
        worker->ping_timeout_set = 1;
    }
    else if (!strcasecmp(key, "lbset")) {
        ival = atoi(val);
        if (ival < 0 || ival > 99)
            return "lbset must be between 0 and 99";
        worker->lbset = ival;
    }
    else if (!strcasecmp(key, "connectiontimeout")) {
        /* Request timeout in given unit (default is second).
         * Defaults to connection timeout
         */
        if (ap_timeout_parameter_parse(val, &timeout, "s") != APR_SUCCESS)
            return "Connectiontimeout has wrong format";
        if (timeout < 1000)
            return "Connectiontimeout must be at least one millisecond.";
        worker->conn_timeout = timeout;
        worker->conn_timeout_set = 1;
    }
    else if (!strcasecmp(key, "flusher")) {
        worker->flusher = apr_pstrdup(p, val);
    }
    else {
        return "unknown Worker parameter";
    }
    return NULL;
}

static const char *set_balancer_param(proxy_server_conf *conf,
                                      apr_pool_t *p,
                                      proxy_balancer *balancer,
                                      const char *key,
                                      const char *val)
{

    int ival;
    if (!strcasecmp(key, "stickysession")) {
        char *path;
        /* Balancer sticky session name.
         * Set to something like JSESSIONID or
         * PHPSESSIONID, etc..,
         */
        path = apr_pstrdup(p, val);
        balancer->sticky = balancer->sticky_path = path;
        if ((path = strchr(path, '|'))) {
            *path++ = '\0';
            balancer->sticky_path = path;
        }
    }
    else if (!strcasecmp(key, "nofailover")) {
        /* If set to 'on' the session will break
         * if the worker is in error state or
         * disabled.
         */
        if (!strcasecmp(val, "on"))
            balancer->sticky_force = 1;
        else if (!strcasecmp(val, "off"))
            balancer->sticky_force = 0;
        else
            return "failover must be On|Off";
    }
    else if (!strcasecmp(key, "timeout")) {
        /* Balancer timeout in seconds.
         * If set this will be the maximum time to
         * wait for a free worker.
         * Default is not to wait.
         */
        ival = atoi(val);
        if (ival < 1)
            return "timeout must be at least one second";
        balancer->timeout = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "maxattempts")) {
        /* Maximum number of failover attempts before
         * giving up.
         */
        ival = atoi(val);
        if (ival < 0)
            return "maximum number of attempts must be a positive number";
        balancer->max_attempts = ival;
        balancer->max_attempts_set = 1;
    }
    else if (!strcasecmp(key, "lbmethod")) {
        proxy_balancer_method *provider;
        provider = ap_lookup_provider(PROXY_LBMETHOD, val, "0");
        if (provider) {
            balancer->lbmethod = provider;
            return NULL;
        }
        return "unknown lbmethod";
    }
    else if (!strcasecmp(key, "scolonpathdelim")) {
        /* If set to 'on' then ';' will also be
         * used as a session path separator/delim (ala
         * mod_jk)
         */
        if (!strcasecmp(val, "on"))
            balancer->scolonsep = 1;
        else if (!strcasecmp(val, "off"))
            balancer->scolonsep = 0;
        else
            return "scolonpathdelim must be On|Off";
    }
    else {
        return "unknown Balancer parameter";
    }
    return NULL;
}

static int alias_match(const char *uri, const char *alias_fakename)
{
    const char *end_fakename = alias_fakename + strlen(alias_fakename);
    const char *aliasp = alias_fakename, *urip = uri;
    const char *end_uri = uri + strlen(uri);

    while (aliasp < end_fakename && urip < end_uri) {
        if (*aliasp == '/') {
            /* any number of '/' in the alias matches any number in
             * the supplied URI, but there must be at least one...
             */
            if (*urip != '/')
                return 0;

            while (*aliasp == '/')
                ++aliasp;
            while (*urip == '/')
                ++urip;
        }
        else {
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    /* fixup badly encoded stuff (e.g. % as last character) */
    if (aliasp > end_fakename) {
        aliasp = end_fakename;
    }
    if (urip > end_uri) {
        urip = end_uri;
    }

   /* We reach the end of the uri before the end of "alias_fakename"
    * for example uri is "/" and alias_fakename "/examples"
    */
   if (urip == end_uri && aliasp!=end_fakename) {
       return 0;
   }

    /* Check last alias path component matched all the way */
    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    /* Return number of characters from URI which matched (may be
     * greater than length of alias, since we may have matched
     * doubled slashes)
     */

    return urip - uri;
}

/* Detect if an absoluteURI should be proxied or not.  Note that we
 * have to do this during this phase because later phases are
 * "short-circuiting"... i.e. translate_names will end when the first
 * module returns OK.  So for example, if the request is something like:
 *
 * GET http://othervhost/cgi-bin/printenv HTTP/1.0
 *
 * mod_alias will notice the /cgi-bin part and ScriptAlias it and
 * short-circuit the proxy... just because of the ordering in the
 * configuration file.
 */
static int proxy_detect(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    /* Ick... msvc (perhaps others) promotes ternary short results to int */

    if (conf->req && r->parsed_uri.scheme) {
        /* but it might be something vhosted */
        if (!(r->parsed_uri.hostname
              && !strcasecmp(r->parsed_uri.scheme, ap_http_scheme(r))
              && ap_matches_request_vhost(r, r->parsed_uri.hostname,
                                          (apr_port_t)(r->parsed_uri.port_str ? r->parsed_uri.port
                                                       : ap_default_port(r))))) {
            r->proxyreq = PROXYREQ_PROXY;
            r->uri = r->unparsed_uri;
            r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
            r->handler = "proxy-server";
        }
    }
    /* We need special treatment for CONNECT proxying: it has no scheme part */
    else if (conf->req && r->method_number == M_CONNECT
             && r->parsed_uri.hostname
             && r->parsed_uri.port_str) {
        r->proxyreq = PROXYREQ_PROXY;
        r->uri = r->unparsed_uri;
        r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
        r->handler = "proxy-server";
    }
    return DECLINED;
}

static const char *proxy_interpolate(request_rec *r, const char *str)
{
    /* Interpolate an env str in a configuration string
     * Syntax ${var} --> value_of(var)
     * Method: replace one var, and recurse on remainder of string
     * Nothing clever here, and crap like nested vars may do silly things
     * but we'll at least avoid sending the unwary into a loop
     */
    const char *start;
    const char *end;
    const char *var;
    const char *val;
    const char *firstpart;

    start = ap_strstr_c(str, "${");
    if (start == NULL) {
        return str;
    }
    end = ap_strchr_c(start+2, '}');
    if (end == NULL) {
        return str;
    }
    /* OK, this is syntax we want to interpolate.  Is there such a var ? */
    var = apr_pstrndup(r->pool, start+2, end-(start+2));
    val = apr_table_get(r->subprocess_env, var);
    firstpart = apr_pstrndup(r->pool, str, (start-str));

    if (val == NULL) {
        return apr_pstrcat(r->pool, firstpart,
                           proxy_interpolate(r, end+1), NULL);
    }
    else {
        return apr_pstrcat(r->pool, firstpart, val,
                           proxy_interpolate(r, end+1), NULL);
    }
}
static apr_array_header_t *proxy_vars(request_rec *r,
                                      apr_array_header_t *hdr)
{
    int i;
    apr_array_header_t *ret = apr_array_make(r->pool, hdr->nelts,
                                             sizeof (struct proxy_alias));
    struct proxy_alias *old = (struct proxy_alias *) hdr->elts;

    for (i = 0; i < hdr->nelts; ++i) {
        struct proxy_alias *newcopy = apr_array_push(ret);
        newcopy->fake = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? proxy_interpolate(r, old[i].fake) : old[i].fake;
        newcopy->real = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? proxy_interpolate(r, old[i].real) : old[i].real;
    }
    return ret;
}
static int proxy_trans(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    int i, len;
    struct proxy_alias *ent = (struct proxy_alias *) conf->aliases->elts;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);
    const char *fake;
    const char *real;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    ap_regmatch_t reg1[AP_MAX_REG_MATCH];
    char *found = NULL;
    int mismatch = 0;

    if (r->proxyreq) {
        /* someone has already set up the proxy, it was possibly ourselves
         * in proxy_detect
         */
        return OK;
    }

    /* XXX: since r->uri has been manipulated already we're not really
     * compliant with RFC1945 at this point.  But this probably isn't
     * an issue because this is a hybrid proxy/origin server.
     */

    for (i = 0; i < conf->aliases->nelts; i++) {
        unsigned int nocanon = ent[i].flags & PROXYPASS_NOCANON;
        const char *use_uri = nocanon ? r->unparsed_uri : r->uri;
        if ((dconf->interpolate_env == 1)
            && (ent[i].flags & PROXYPASS_INTERPOLATE)) {
            fake = proxy_interpolate(r, ent[i].fake);
            real = proxy_interpolate(r, ent[i].real);
        }
        else {
            fake = ent[i].fake;
            real = ent[i].real;
        }
        if (ent[i].regex) {
            if (!ap_regexec(ent[i].regex, r->uri, AP_MAX_REG_MATCH, regm, 0)) {
                if ((real[0] == '!') && (real[1] == '\0')) {
                    return DECLINED;
                }
                /* test that we haven't reduced the URI */
                if (nocanon && ap_regexec(ent[i].regex, r->unparsed_uri,
                                          AP_MAX_REG_MATCH, reg1, 0)) {
                    mismatch = 1;
                    use_uri = r->uri;
                }
                found = ap_pregsub(r->pool, real, use_uri, AP_MAX_REG_MATCH,
                                   (use_uri == r->uri) ? regm : reg1);
                /* Note: The strcmp() below catches cases where there
                 * was no regex substitution. This is so cases like:
                 *
                 *    ProxyPassMatch \.gif balancer://foo
                 *
                 * will work "as expected". The upshot is that the 2
                 * directives below act the exact same way (ie: $1 is implied):
                 *
                 *    ProxyPassMatch ^(/.*\.gif)$ balancer://foo
                 *    ProxyPassMatch ^(/.*\.gif)$ balancer://foo$1
                 *
                 * which may be confusing.
                 */
                if (found && strcmp(found, real)) {
                    found = apr_pstrcat(r->pool, "proxy:", found, NULL);
                }
                else {
                    found = apr_pstrcat(r->pool, "proxy:", real,
                                        use_uri, NULL);
                }
            }
        }
        else {
            len = alias_match(r->uri, fake);

            if (len != 0) {
                if ((real[0] == '!') && (real[1] == '\0')) {
                    return DECLINED;
                }
                if (nocanon
                    && len != alias_match(r->unparsed_uri, ent[i].fake)) {
                    mismatch = 1;
                    use_uri = r->uri;
                }
                found = apr_pstrcat(r->pool, "proxy:", real,
                                    use_uri + len, NULL);
            }
        }
        if (mismatch) {
            /* We made a reducing transformation, so we can't safely use
             * unparsed_uri.  Safe fallback is to ignore nocanon.
             */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "Unescaped URL path matched ProxyPass; ignoring unsafe nocanon");
        }

        if (found) {
            r->filename = found;
            r->handler = "proxy-server";
            r->proxyreq = PROXYREQ_REVERSE;
            if (nocanon && !mismatch) {
                /* mod_proxy_http needs to be told.  Different module. */
                apr_table_setn(r->notes, "proxy-nocanon", "1");
            }
            return OK;
        }
    }
    return DECLINED;
}

static int proxy_walk(request_rec *r)
{
    proxy_server_conf *sconf = ap_get_module_config(r->server->module_config,
                                                    &proxy_module);
    ap_conf_vector_t *per_dir_defaults = r->server->lookup_defaults;
    ap_conf_vector_t **sec_proxy = (ap_conf_vector_t **) sconf->sec_proxy->elts;
    ap_conf_vector_t *entry_config;
    proxy_dir_conf *entry_proxy;
    int num_sec = sconf->sec_proxy->nelts;
    /* XXX: shouldn't we use URI here?  Canonicalize it first?
     * Pass over "proxy:" prefix
     */
    const char *proxyname = r->filename + 6;
    int j;

    for (j = 0; j < num_sec; ++j)
    {
        entry_config = sec_proxy[j];
        entry_proxy = ap_get_module_config(entry_config, &proxy_module);

        /* XXX: What about case insensitive matching ???
         * Compare regex, fnmatch or string as appropriate
         * If the entry doesn't relate, then continue
         */
        if (entry_proxy->r
              ? ap_regexec(entry_proxy->r, proxyname, 0, NULL, 0)
              : (entry_proxy->p_is_fnmatch
                   ? apr_fnmatch(entry_proxy->p, proxyname, 0)
                   : strncmp(proxyname, entry_proxy->p,
                                        strlen(entry_proxy->p)))) {
            continue;
        }
        per_dir_defaults = ap_merge_per_dir_configs(r->pool, per_dir_defaults,
                                                             entry_config);
    }

    r->per_dir_config = per_dir_defaults;

    return OK;
}

static int proxy_map_location(request_rec *r)
{
    int access_status;

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    /* Don't let the core or mod_http map_to_storage hooks handle this,
     * We don't need directory/file_walk, and we want to TRACE on our own.
     */
    if ((access_status = proxy_walk(r))) {
        ap_die(access_status, r);
        return access_status;
    }

    return OK;
}

/* -------------------------------------------------------------- */
/* Fixup the filename */

/*
 * Canonicalise the URL
 */
static int proxy_fixup(request_rec *r)
{
    char *url, *p;
    int access_status;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                 &proxy_module);

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    /* XXX: Shouldn't we try this before we run the proxy_walk? */
    url = &r->filename[6];

    if ((dconf->interpolate_env == 1) && (r->proxyreq == PROXYREQ_REVERSE)) {
        /* create per-request copy of reverse proxy conf,
         * and interpolate vars in it
         */
        proxy_req_conf *rconf = apr_palloc(r->pool, sizeof(proxy_req_conf));
        ap_set_module_config(r->request_config, &proxy_module, rconf);
        rconf->raliases = proxy_vars(r, dconf->raliases);
        rconf->cookie_paths = proxy_vars(r, dconf->cookie_paths);
        rconf->cookie_domains = proxy_vars(r, dconf->cookie_domains);
    }

    /* canonicalise each specific scheme */
    if ((access_status = proxy_run_canon_handler(r, url))) {
        return access_status;
    }

    p = strchr(url, ':');
    if (p == NULL || p == url)
        return HTTP_BAD_REQUEST;

    return OK;      /* otherwise; we've done the best we can */
}
/* Send a redirection if the request contains a hostname which is not */
/* fully qualified, i.e. doesn't have a domain name appended. Some proxy */
/* servers like Netscape's allow this and access hosts from the local */
/* domain in this case. I think it is better to redirect to a FQDN, since */
/* these will later be found in the bookmarks files. */
/* The "ProxyDomain" directive determines what domain will be appended */
static int proxy_needsdomain(request_rec *r, const char *url, const char *domain)
{
    char *nuri;
    const char *ref;

    /* We only want to worry about GETs */
    if (!r->proxyreq || r->method_number != M_GET || !r->parsed_uri.hostname)
        return DECLINED;

    /* If host does contain a dot already, or it is "localhost", decline */
    if (strchr(r->parsed_uri.hostname, '.') != NULL /* has domain, or IPv4 literal */
     || strchr(r->parsed_uri.hostname, ':') != NULL /* IPv6 literal */
     || strcasecmp(r->parsed_uri.hostname, "localhost") == 0)
        return DECLINED;    /* host name has a dot already */

    ref = apr_table_get(r->headers_in, "Referer");

    /* Reassemble the request, but insert the domain after the host name */
    /* Note that the domain name always starts with a dot */
    r->parsed_uri.hostname = apr_pstrcat(r->pool, r->parsed_uri.hostname,
                                         domain, NULL);
    nuri = apr_uri_unparse(r->pool,
                           &r->parsed_uri,
                           APR_URI_UNP_REVEALPASSWORD);

    apr_table_set(r->headers_out, "Location", nuri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "Domain missing: %s sent to %s%s%s", r->uri,
                  apr_uri_unparse(r->pool, &r->parsed_uri,
                                  APR_URI_UNP_OMITUSERINFO),
                  ref ? " from " : "", ref ? ref : "");

    return HTTP_MOVED_PERMANENTLY;
}

/* -------------------------------------------------------------- */
/* Invoke handler */

static int proxy_handler(request_rec *r)
{
    char *uri, *scheme, *p;
    const char *p2;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    apr_array_header_t *proxies = conf->proxies;
    struct proxy_remote *ents = (struct proxy_remote *) proxies->elts;
    int i, rc, access_status;
    int direct_connect = 0;
    const char *str;
    long maxfwd;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    int attempts = 0, max_attempts = 0;
    struct dirconn_entry *list = (struct dirconn_entry *)conf->dirconn->elts;

    /* is this for us? */
    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    /* handle max-forwards / OPTIONS / TRACE */
    if ((str = apr_table_get(r->headers_in, "Max-Forwards"))) {
        maxfwd = strtol(str, NULL, 10);
        if (maxfwd < 1) {
            switch (r->method_number) {
            case M_TRACE: {
                int access_status;
                r->proxyreq = PROXYREQ_NONE;
                if ((access_status = ap_send_http_trace(r)))
                    ap_die(access_status, r);
                else
                    ap_finalize_request_protocol(r);
                return OK;
            }
            case M_OPTIONS: {
                int access_status;
                r->proxyreq = PROXYREQ_NONE;
                if ((access_status = ap_send_http_options(r)))
                    ap_die(access_status, r);
                else
                    ap_finalize_request_protocol(r);
                return OK;
            }
            default: {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY,
                                     "Max-Forwards has reached zero - proxy loop?");
            }
            }
        }
        maxfwd = (maxfwd > 0) ? maxfwd - 1 : 0;
    }
    else {
        /* set configured max-forwards */
        maxfwd = conf->maxfwd;
    }
    if (maxfwd >= 0) {
        apr_table_set(r->headers_in, "Max-Forwards",
                      apr_psprintf(r->pool, "%ld", maxfwd));
    }

    if (r->method_number == M_TRACE) {
        core_server_config *coreconf = (core_server_config *)
                            ap_get_module_config(sconf, &core_module);

        if (coreconf->trace_enable == AP_TRACE_DISABLE)
        {
            /* Allow "error-notes" string to be printed by ap_send_error_response()
             * Note; this goes nowhere, canned error response need an overhaul.
             */
            apr_table_setn(r->notes, "error-notes",
                           "TRACE forbidden by server configuration");
            apr_table_setn(r->notes, "verbose-error-to", "*");
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "proxy: TRACE forbidden by server configuration");
            return HTTP_METHOD_NOT_ALLOWED;
        }

        /* Can't test ap_should_client_block, we aren't ready to send
         * the client a 100 Continue response till the connection has
         * been established
         */
        if (coreconf->trace_enable != AP_TRACE_EXTENDED
            && (r->read_length || r->read_chunked || r->remaining))
        {
            /* Allow "error-notes" string to be printed by ap_send_error_response()
             * Note; this goes nowhere, canned error response need an overhaul.
             */
            apr_table_setn(r->notes, "error-notes",
                           "TRACE with request body is not allowed");
            apr_table_setn(r->notes, "verbose-error-to", "*");
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "proxy: TRACE with request body is not allowed");
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
    }

    uri = r->filename + 6;
    p = strchr(uri, ':');
    if (p == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "proxy_handler no URL in %s", r->filename);
        return HTTP_BAD_REQUEST;
    }

    /* If the host doesn't have a domain name, add one and redirect. */
    if (conf->domain != NULL) {
        rc = proxy_needsdomain(r, uri, conf->domain);
        if (ap_is_HTTP_REDIRECT(rc))
            return HTTP_MOVED_PERMANENTLY;
    }

    scheme = apr_pstrndup(r->pool, uri, p - uri);
    /* Check URI's destination host against NoProxy hosts */
    /* Bypass ProxyRemote server lookup if configured as NoProxy */
    for (direct_connect = i = 0; i < conf->dirconn->nelts &&
                                        !direct_connect; i++) {
        direct_connect = list[i].matcher(&list[i], r);
    }
#if DEBUGGING
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                (direct_connect) ? "NoProxy for %s" : "UseProxy for %s",
                r->uri);
#endif

    do {
        char *url = uri;
        /* Try to obtain the most suitable worker */
        access_status = ap_proxy_pre_request(&worker, &balancer, r, conf, &url);
        if (access_status != OK) {
            /*
             * Only return if access_status is not HTTP_SERVICE_UNAVAILABLE
             * This gives other modules the chance to hook into the
             * request_status hook and decide what to do in this situation.
             */
            if (access_status != HTTP_SERVICE_UNAVAILABLE)
                return access_status;
            /*
             * Ensure that balancer is NULL if worker is NULL to prevent
             * potential problems in the post_request hook.
             */
            if (!worker)
                balancer = NULL;
            goto cleanup;
        }

        /* Initialise worker if needed, note the shared area must be initialized by the balancer logic */
        if (balancer) {
            ap_proxy_initialize_worker(worker, r->server, conf->pool); 
            ap_proxy_initialize_worker_share(conf, worker, r->server);
        }

        if (balancer && balancer->max_attempts_set && !max_attempts)
            max_attempts = balancer->max_attempts;
        /* firstly, try a proxy, unless a NoProxy directive is active */
        if (!direct_connect) {
            for (i = 0; i < proxies->nelts; i++) {
                p2 = ap_strchr_c(ents[i].scheme, ':');  /* is it a partial URL? */
                if (strcmp(ents[i].scheme, "*") == 0 ||
                    (ents[i].use_regex &&
                     ap_regexec(ents[i].regexp, url, 0, NULL, 0) == 0) ||
                    (p2 == NULL && strcasecmp(scheme, ents[i].scheme) == 0) ||
                    (p2 != NULL &&
                    strncasecmp(url, ents[i].scheme,
                                strlen(ents[i].scheme)) == 0)) {

                    /* handle the scheme */
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                 "Trying to run scheme_handler against proxy");
                    access_status = proxy_run_scheme_handler(r, worker,
                                                             conf, url,
                                                             ents[i].hostname,
                                                             ents[i].port);

                    /* Did the scheme handler process the request? */
                    if (access_status != DECLINED) {
                        const char *cl_a;
                        char *end;
                        apr_off_t cl;

                        /*
                         * An fatal error or success, so no point in
                         * retrying with a direct connection.
                         */
                        if (access_status != HTTP_BAD_GATEWAY) {
                            goto cleanup;
                        }
                        cl_a = apr_table_get(r->headers_in, "Content-Length");
                        if (cl_a) {
                            apr_strtoff(&cl, cl_a, &end, 0);
                            /*
                             * The request body is of length > 0. We cannot
                             * retry with a direct connection since we already
                             * sent (parts of) the request body to the proxy
                             * and do not have any longer.
                             */
                            if (cl > 0) {
                                goto cleanup;
                            }
                        }
                        /*
                         * Transfer-Encoding was set as input header, so we had
                         * a request body. We cannot retry with a direct
                         * connection for the same reason as above.
                         */
                        if (apr_table_get(r->headers_in, "Transfer-Encoding")) {
                            goto cleanup;
                        }
                    }
                }
            }
        }

        /* otherwise, try it direct */
        /* N.B. what if we're behind a firewall, where we must use a proxy or
        * give up??
        */

        /* handle the scheme */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "Running scheme %s handler (attempt %d)",
                     scheme, attempts);
        AP_PROXY_RUN(r, worker, conf, url, attempts);
        access_status = proxy_run_scheme_handler(r, worker, conf,
                                                 url, NULL, 0);
        if (access_status == OK)
            break;
        else if (access_status == HTTP_INTERNAL_SERVER_ERROR) {
            /* Unrecoverable server error.
             * We can not failover to another worker.
             * Mark the worker as unusable if member of load balancer
             */
            if (balancer) {
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
            }
            break;
        }
        else if (access_status == HTTP_SERVICE_UNAVAILABLE) {
            /* Recoverable server error.
             * We can failover to another worker
             * Mark the worker as unusable if member of load balancer
             */
            if (balancer) {
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
            }
        }
        else {
            /* Unrecoverable error.
             * Return the origin status code to the client.
             */
            break;
        }
        /* Try again if the worker is unusable and the service is
         * unavailable.
         */
    } while (!PROXY_WORKER_IS_USABLE(worker) &&
             max_attempts > attempts++);

    if (DECLINED == access_status) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                    "proxy: No protocol handler was valid for the URL %s. "
                    "If you are using a DSO version of mod_proxy, make sure "
                    "the proxy submodules are included in the configuration "
                    "using LoadModule.", r->uri);
        access_status = HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }
cleanup:
    ap_proxy_post_request(worker, balancer, r, conf);

    proxy_run_request_status(&access_status, r);
    AP_PROXY_RUN_FINISHED(r, attempts, access_status);

    return access_status;
}

/* -------------------------------------------------------------- */
/* Setup configurable data */

static void * create_proxy_config(apr_pool_t *p, server_rec *s)
{
    proxy_server_conf *ps = apr_pcalloc(p, sizeof(proxy_server_conf));

    ps->sec_proxy = apr_array_make(p, 10, sizeof(ap_conf_vector_t *));
    ps->proxies = apr_array_make(p, 10, sizeof(struct proxy_remote));
    ps->aliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    ps->noproxies = apr_array_make(p, 10, sizeof(struct noproxy_entry));
    ps->dirconn = apr_array_make(p, 10, sizeof(struct dirconn_entry));
    ps->allowed_connect_ports = apr_array_make(p, 10, sizeof(int));
    ps->workers = apr_array_make(p, 10, sizeof(proxy_worker));
    ps->balancers = apr_array_make(p, 10, sizeof(proxy_balancer));
    ps->forward = NULL;
    ps->reverse = NULL;
    ps->domain = NULL;
    ps->viaopt = via_off; /* initially backward compatible with 1.3.1 */
    ps->viaopt_set = 0; /* 0 means default */
    ps->req = 0;
    ps->req_set = 0;
    ps->recv_buffer_size = 0; /* this default was left unset for some reason */
    ps->recv_buffer_size_set = 0;
    ps->io_buffer_size = AP_IOBUFSIZE;
    ps->io_buffer_size_set = 0;
    ps->maxfwd = DEFAULT_MAX_FORWARDS;
    ps->maxfwd_set = 0;
    ps->error_override = 0;
    ps->error_override_set = 0;
    ps->preserve_host_set = 0;
    ps->preserve_host = 0;
    ps->timeout = 0;
    ps->timeout_set = 0;
    ps->badopt = bad_error;
    ps->badopt_set = 0;
    ps->pool = p;

    return ps;
}

static void * merge_proxy_config(apr_pool_t *p, void *basev, void *overridesv)
{
    proxy_server_conf *ps = apr_pcalloc(p, sizeof(proxy_server_conf));
    proxy_server_conf *base = (proxy_server_conf *) basev;
    proxy_server_conf *overrides = (proxy_server_conf *) overridesv;

    ps->proxies = apr_array_append(p, base->proxies, overrides->proxies);
    ps->sec_proxy = apr_array_append(p, base->sec_proxy, overrides->sec_proxy);
    ps->aliases = apr_array_append(p, base->aliases, overrides->aliases);
    ps->noproxies = apr_array_append(p, base->noproxies, overrides->noproxies);
    ps->dirconn = apr_array_append(p, base->dirconn, overrides->dirconn);
    ps->allowed_connect_ports = apr_array_append(p, base->allowed_connect_ports, overrides->allowed_connect_ports);
    ps->workers = apr_array_append(p, base->workers, overrides->workers);
    ps->balancers = apr_array_append(p, base->balancers, overrides->balancers);
    ps->forward = overrides->forward ? overrides->forward : base->forward;
    ps->reverse = overrides->reverse ? overrides->reverse : base->reverse;

    ps->domain = (overrides->domain == NULL) ? base->domain : overrides->domain;
    ps->viaopt = (overrides->viaopt_set == 0) ? base->viaopt : overrides->viaopt;
    ps->viaopt_set = overrides->viaopt_set || base->viaopt_set;
    ps->req = (overrides->req_set == 0) ? base->req : overrides->req;
    ps->req_set = overrides->req_set || base->req_set;
    ps->recv_buffer_size = (overrides->recv_buffer_size_set == 0) ? base->recv_buffer_size : overrides->recv_buffer_size;
    ps->recv_buffer_size_set = overrides->recv_buffer_size_set || base->recv_buffer_size_set;
    ps->io_buffer_size = (overrides->io_buffer_size_set == 0) ? base->io_buffer_size : overrides->io_buffer_size;
    ps->io_buffer_size_set = overrides->io_buffer_size_set || base->io_buffer_size_set;
    ps->maxfwd = (overrides->maxfwd_set == 0) ? base->maxfwd : overrides->maxfwd;
    ps->maxfwd_set = overrides->maxfwd_set || base->maxfwd_set;
    ps->error_override = (overrides->error_override_set == 0) ? base->error_override : overrides->error_override;
    ps->error_override_set = overrides->error_override_set || base->error_override_set;
    ps->preserve_host = (overrides->preserve_host_set == 0) ? base->preserve_host : overrides->preserve_host;
    ps->preserve_host_set = overrides->preserve_host_set || base->preserve_host_set;
    ps->timeout= (overrides->timeout_set == 0) ? base->timeout : overrides->timeout;
    ps->timeout_set = overrides->timeout_set || base->timeout_set;
    ps->badopt = (overrides->badopt_set == 0) ? base->badopt : overrides->badopt;
    ps->badopt_set = overrides->badopt_set || base->badopt_set;
    ps->proxy_status = (overrides->proxy_status_set == 0) ? base->proxy_status : overrides->proxy_status;
    ps->proxy_status_set = overrides->proxy_status_set || base->proxy_status_set;
    ps->pool = p;
    return ps;
}

static void *create_proxy_dir_config(apr_pool_t *p, char *dummy)
{
    proxy_dir_conf *new =
        (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));

    /* Filled in by proxysection, when applicable */

    /* Put these in the dir config so they work inside <Location> */
    new->raliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_paths = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_domains = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_path_str = apr_strmatch_precompile(p, "path=", 0);
    new->cookie_domain_str = apr_strmatch_precompile(p, "domain=", 0);
    new->interpolate_env = -1; /* unset */

    return (void *) new;
}

static void *merge_proxy_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    proxy_dir_conf *new = (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));
    proxy_dir_conf *add = (proxy_dir_conf *) addv;
    proxy_dir_conf *base = (proxy_dir_conf *) basev;

    new->p = add->p;
    new->p_is_fnmatch = add->p_is_fnmatch;
    new->r = add->r;

    /* Put these in the dir config so they work inside <Location> */
    new->raliases = apr_array_append(p, base->raliases, add->raliases);
    new->cookie_paths
        = apr_array_append(p, base->cookie_paths, add->cookie_paths);
    new->cookie_domains
        = apr_array_append(p, base->cookie_domains, add->cookie_domains);
    new->cookie_path_str = base->cookie_path_str;
    new->cookie_domain_str = base->cookie_domain_str;
    new->interpolate_env = (add->interpolate_env == -1) ? base->interpolate_env
                                                        : add->interpolate_env;
    new->ftp_directory_charset = add->ftp_directory_charset ?
                                 add->ftp_directory_charset :
                                 base->ftp_directory_charset;
    return new;
}


static const char *
    add_proxy(cmd_parms *cmd, void *dummy, const char *f1, const char *r1, int regex)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_remote *new;
    char *p, *q;
    char *r, *f, *scheme;
    ap_regex_t *reg = NULL;
    int port;

    r = apr_pstrdup(cmd->pool, r1);
    scheme = apr_pstrdup(cmd->pool, r1);
    f = apr_pstrdup(cmd->pool, f1);
    p = strchr(r, ':');
    if (p == NULL || p[1] != '/' || p[2] != '/' || p[3] == '\0') {
        if (regex)
            return "ProxyRemoteMatch: Bad syntax for a remote proxy server";
        else
            return "ProxyRemote: Bad syntax for a remote proxy server";
    }
    else {
        scheme[p-r] = 0;
    }
    q = strchr(p + 3, ':');
    if (q != NULL) {
        if (sscanf(q + 1, "%u", &port) != 1 || port > 65535) {
            if (regex)
                return "ProxyRemoteMatch: Bad syntax for a remote proxy server (bad port number)";
            else
                return "ProxyRemote: Bad syntax for a remote proxy server (bad port number)";
        }
        *q = '\0';
    }
    else
        port = -1;
    *p = '\0';
    if (regex) {
        reg = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (!reg)
            return "Regular expression for ProxyRemoteMatch could not be compiled.";
    }
    else
        if (strchr(f, ':') == NULL)
            ap_str_tolower(f);      /* lowercase scheme */
    ap_str_tolower(p + 3);      /* lowercase hostname */

    if (port == -1) {
        port = apr_uri_port_of_scheme(scheme);
    }

    new = apr_array_push(conf->proxies);
    new->scheme = f;
    new->protocol = r;
    new->hostname = p + 3;
    new->port = port;
    new->regexp = reg;
    new->use_regex = regex;
    return NULL;
}

static const char *
    add_proxy_noregex(cmd_parms *cmd, void *dummy, const char *f1, const char *r1)
{
    return add_proxy(cmd, dummy, f1, r1, 0);
}

static const char *
    add_proxy_regex(cmd_parms *cmd, void *dummy, const char *f1, const char *r1)
{
    return add_proxy(cmd, dummy, f1, r1, 1);
}

static const char *
    add_pass(cmd_parms *cmd, void *dummy, const char *arg, int is_regex)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_alias *new;
    char *f = cmd->path;
    char *r = NULL;
    char *word;
    apr_table_t *params = apr_table_make(cmd->pool, 5);
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    int i;
    int use_regex = is_regex;
    unsigned int flags = 0;

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        if (!f) {
            if (!strcmp(word, "~")) {
                if (is_regex) {
                    return "ProxyPassMatch invalid syntax ('~' usage).";
                }
                use_regex = 1;
                continue;
            }
            f = word;
        }
        else if (!r) {
            r = word;
        }
        else if (!strcasecmp(word,"nocanon")) {
            flags |= PROXYPASS_NOCANON;
        }
        else if (!strcasecmp(word,"interpolate")) {
            flags |= PROXYPASS_INTERPOLATE;
        }
        else {
            char *val = strchr(word, '=');
            if (!val) {
                if (cmd->path) {
                    if (*r == '/') {
                        return "ProxyPass|ProxyPassMatch can not have a path when defined in "
                               "a location.";
                    }
                    else {
                        return "Invalid ProxyPass|ProxyPassMatch parameter. Parameter must "
                               "be in the form 'key=value'.";
                    }
                }
                else {
                    return "Invalid ProxyPass|ProxyPassMatch parameter. Parameter must be "
                           "in the form 'key=value'.";
                }
            }
            else
                *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    };

    if (r == NULL)
        return "ProxyPass|ProxyPassMatch needs a path when not defined in a location";

    new = apr_array_push(conf->aliases);
    new->fake = apr_pstrdup(cmd->pool, f);
    new->real = apr_pstrdup(cmd->pool, r);
    new->flags = flags;
    if (use_regex) {
        new->regex = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (new->regex == NULL)
            return "Regular expression could not be compiled.";
    }
    else {
        new->regex = NULL;
    }

    if (r[0] == '!' && r[1] == '\0')
        return NULL;

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    /* Distinguish the balancer from worker */
    if (strncasecmp(r, "balancer:", 9) == 0) {
        proxy_balancer *balancer = ap_proxy_get_balancer(cmd->pool, conf, r);
        if (!balancer) {
            const char *err = ap_proxy_add_balancer(&balancer,
                                                    cmd->pool,
                                                    conf, r);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
        for (i = 0; i < arr->nelts; i++) {
            const char *err = set_balancer_param(conf, cmd->pool, balancer, elts[i].key,
                                                 elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
    }
    else {
        proxy_worker *worker = ap_proxy_get_worker(cmd->temp_pool, conf, r);
        if (!worker) {
            const char *err = ap_proxy_add_worker(&worker, cmd->pool, conf, r);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                         "worker %s already used by another worker", worker->name);
        }
        PROXY_COPY_CONF_PARAMS(worker, conf);

        for (i = 0; i < arr->nelts; i++) {
            const char *err = set_worker_param(cmd->pool, worker, elts[i].key,
                                               elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
    }
    return NULL;
}

static const char *
    add_pass_noregex(cmd_parms *cmd, void *dummy, const char *arg)
{
    return add_pass(cmd, dummy, arg, 0);
}

static const char *
    add_pass_regex(cmd_parms *cmd, void *dummy, const char *arg)
{
    return add_pass(cmd, dummy, arg, 1);
}


static const char * add_pass_reverse(cmd_parms *cmd, void *dconf, const char *f,
                                     const char *r, const char *i)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;
    const char *fake;
    const char *real;
    const char *interp;

    if (cmd->path == NULL) {
        if (r == NULL || !strcasecmp(r, "interpolate")) {
            return "ProxyPassReverse needs a path when not defined in a location";
        }
        fake = f;
        real = r;
        interp = i;
    }
    else {
        if (r && strcasecmp(r, "interpolate")) {
            return "ProxyPassReverse can not have a path when defined in a location";
        }
        fake = cmd->path;
        real = f;
        interp = r;
    }

    new = apr_array_push(conf->raliases);
    new->fake = fake;
    new->real = real;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;

    return NULL;
}
static const char* cookie_path(cmd_parms *cmd, void *dconf, const char *f,
                               const char *r, const char *interp)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;

    new = apr_array_push(conf->cookie_paths);
    new->fake = f;
    new->real = r;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;

    return NULL;
}
static const char* cookie_domain(cmd_parms *cmd, void *dconf, const char *f,
                                 const char *r, const char *interp)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;

    new = apr_array_push(conf->cookie_domains);
    new->fake = f;
    new->real = r;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;
    return NULL;
}

static const char *
    set_proxy_exclude(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct noproxy_entry *new;
    struct noproxy_entry *list = (struct noproxy_entry *) conf->noproxies->elts;
    struct apr_sockaddr_t *addr;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i = 0; i < conf->noproxies->nelts; i++) {
        if (strcasecmp(arg, list[i].name) == 0) { /* ignore case for host names */
            found = 1;
        }
    }

    if (!found) {
        new = apr_array_push(conf->noproxies);
        new->name = arg;
        if (APR_SUCCESS == apr_sockaddr_info_get(&addr, new->name, APR_UNSPEC, 0, 0, parms->pool)) {
            new->addr = addr;
        }
        else {
            new->addr = NULL;
        }
    }
    return NULL;
}

/*
 * Set the ports CONNECT can use
 */
static const char *
    set_allowed_ports(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
        ap_get_module_config(s->module_config, &proxy_module);
    int *New;

    if (!apr_isdigit(arg[0]))
        return "AllowCONNECT: port number must be numeric";

    New = apr_array_push(conf->allowed_connect_ports);
    *New = atoi(arg);
    return NULL;
}

/* Similar to set_proxy_exclude(), but defining directly connected hosts,
 * which should never be accessed via the configured ProxyRemote servers
 */
static const char *
    set_proxy_dirconn(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct dirconn_entry *New;
    struct dirconn_entry *list = (struct dirconn_entry *) conf->dirconn->elts;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i = 0; i < conf->dirconn->nelts; i++) {
        if (strcasecmp(arg, list[i].name) == 0)
            found = 1;
    }

    if (!found) {
        New = apr_array_push(conf->dirconn);
        New->name = apr_pstrdup(parms->pool, arg);
        New->hostaddr = NULL;

    if (ap_proxy_is_ipaddr(New, parms->pool)) {
#if DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "Parsed addr %s", inet_ntoa(New->addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "Parsed mask %s", inet_ntoa(New->mask));
#endif
    }
    else if (ap_proxy_is_domainname(New, parms->pool)) {
        ap_str_tolower(New->name);
#if DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                     "Parsed domain %s", New->name);
#endif
        }
        else if (ap_proxy_is_hostname(New, parms->pool)) {
            ap_str_tolower(New->name);
#if DEBUGGING
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                         "Parsed host %s", New->name);
#endif
        }
        else {
            ap_proxy_is_word(New, parms->pool);
#if DEBUGGING
            fprintf(stderr, "Parsed word %s\n", New->name);
#endif
        }
    }
    return NULL;
}

static const char *
    set_proxy_domain(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (arg[0] != '.')
        return "ProxyDomain: domain name must start with a dot.";

    psf->domain = arg;
    return NULL;
}

static const char *
    set_proxy_req(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->req = flag;
    psf->req_set = 1;
    return NULL;
}

static const char *
    set_proxy_error_override(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->error_override = flag;
    psf->error_override_set = 1;
    return NULL;
}
static const char *
    set_preserve_host(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->preserve_host = flag;
    psf->preserve_host_set = 1;
    return NULL;
}

static const char *
    set_recv_buffer_size(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int s = atoi(arg);
    if (s < 512 && s != 0) {
        return "ProxyReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
    }

    psf->recv_buffer_size = s;
    psf->recv_buffer_size_set = 1;
    return NULL;
}

static const char *
    set_io_buffer_size(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);
    if (s < 512 && s) {
        return "ProxyIOBufferSize must be >= 512 bytes, or 0 for system default.";
    }
    psf->io_buffer_size = (s ? s : AP_IOBUFSIZE);
    psf->io_buffer_size_set = 1;
    return NULL;
}

static const char *
    set_max_forwards(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);

    psf->maxfwd = s;
    psf->maxfwd_set = 1;
    return NULL;
}
static const char*
    set_proxy_timeout(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int timeout;

    timeout=atoi(arg);
    if (timeout<1) {
        return "Proxy Timeout must be at least 1 second.";
    }
    psf->timeout_set=1;
    psf->timeout=apr_time_from_sec(timeout);

    return NULL;
}

static const char*
    set_via_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "Off") == 0)
        psf->viaopt = via_off;
    else if (strcasecmp(arg, "On") == 0)
        psf->viaopt = via_on;
    else if (strcasecmp(arg, "Block") == 0)
        psf->viaopt = via_block;
    else if (strcasecmp(arg, "Full") == 0)
        psf->viaopt = via_full;
    else {
        return "ProxyVia must be one of: "
            "off | on | full | block";
    }

    psf->viaopt_set = 1;
    return NULL;
}

static const char*
    set_bad_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "IsError") == 0)
        psf->badopt = bad_error;
    else if (strcasecmp(arg, "Ignore") == 0)
        psf->badopt = bad_ignore;
    else if (strcasecmp(arg, "StartBody") == 0)
        psf->badopt = bad_body;
    else {
        return "ProxyBadHeader must be one of: "
            "IsError | Ignore | StartBody";
    }

    psf->badopt_set = 1;
    return NULL;
}

static const char*
    set_status_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "Off") == 0)
        psf->proxy_status = status_off;
    else if (strcasecmp(arg, "On") == 0)
        psf->proxy_status = status_on;
    else if (strcasecmp(arg, "Full") == 0)
        psf->proxy_status = status_full;
    else {
        return "ProxyStatus must be one of: "
            "off | on | full";
    }

    psf->proxy_status_set = 1;
    return NULL;
}

static const char *add_member(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    proxy_balancer *balancer;
    proxy_worker *worker;
    char *path = cmd->path;
    char *name = NULL;
    char *word;
    apr_table_t *params = apr_table_make(cmd->pool, 5);
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    int i;

    if (cmd->path)
        path = apr_pstrdup(cmd->pool, cmd->path);

    while (*arg) {
        char *val;
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');

        if (!val) {
            if (!path)
                path = word;
            else if (!name)
                name = word;
            else {
                if (cmd->path)
                    return "BalancerMember can not have a balancer name when defined in a location";
                else
                    return "Invalid BalancerMember parameter. Parameter must "
                           "be in the form 'key=value'";
            }
        } else {
            *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    }
    if (!path)
        return "BalancerMember must define balancer name when outside <Proxy > section";
    if (!name)
        return "BalancerMember must define remote proxy server";

    ap_str_tolower(path);   /* lowercase scheme://hostname */

    /* Try to find existing worker */
    worker = ap_proxy_get_worker(cmd->temp_pool, conf, name);
    if (!worker) {
        const char *err;
        if ((err = ap_proxy_add_worker(&worker, cmd->pool, conf, name)) != NULL)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                     "worker %s already used by another worker", worker->name);
    }
    PROXY_COPY_CONF_PARAMS(worker, conf);

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        const char *err = set_worker_param(cmd->pool, worker, elts[i].key,
                                           elts[i].val);
        if (err)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
    }
    /* Try to find the balancer */
    balancer = ap_proxy_get_balancer(cmd->temp_pool, conf, path);
    if (!balancer) {
        const char *err = ap_proxy_add_balancer(&balancer,
                                                cmd->pool,
                                                conf, path);
        if (err)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
    }
    /* Add the worker to the load balancer */
    ap_proxy_add_worker_to_balancer(cmd->pool, balancer, worker);
    return NULL;
}

static const char *
    set_proxy_param(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    char *name = NULL;
    char *word, *val;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    const char *err;
    int in_proxy_section = 0;

    if (cmd->directive->parent &&
        strncasecmp(cmd->directive->parent->directive,
                    "<Proxy", 6) == 0) {
        const char *pargs = cmd->directive->parent->args;
        /* Directive inside <Proxy section
         * Parent directive arg is the worker/balancer name.
         */
        name = ap_getword_conf(cmd->temp_pool, &pargs);
        if ((word = ap_strchr(name, '>')))
            *word = '\0';
        in_proxy_section = 1;
    }
    else {
        /* Standard set directive with worker/balancer
         * name as first param.
         */
        name = ap_getword_conf(cmd->temp_pool, &arg);
    }

    if (strncasecmp(name, "balancer:", 9) == 0) {
        balancer = ap_proxy_get_balancer(cmd->pool, conf, name);
        if (!balancer) {
            if (in_proxy_section) {
                err = ap_proxy_add_balancer(&balancer,
                                            cmd->pool,
                                            conf, name);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxySet ",
                                       err, NULL);
            }
            else
                return apr_pstrcat(cmd->temp_pool, "ProxySet can not find '",
                                   name, "' Balancer.", NULL);
        }
    }
    else {
        worker = ap_proxy_get_worker(cmd->temp_pool, conf, name);
        if (!worker) {
            if (in_proxy_section) {
                err = ap_proxy_add_worker(&worker, cmd->pool,
                                          conf, name);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxySet ",
                                       err, NULL);
            }
            else
                return apr_pstrcat(cmd->temp_pool, "ProxySet can not find '",
                                   name, "' Worker.", NULL);
        }
    }

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid ProxySet parameter. Parameter must be "
                   "in the form 'key=value'";
        }
        else
            *val++ = '\0';
        if (worker)
            err = set_worker_param(cmd->pool, worker, word, val);
        else
            err = set_balancer_param(conf, cmd->pool, balancer, word, val);

        if (err)
            return apr_pstrcat(cmd->temp_pool, "ProxySet: ", err, " ", word, "=", val, "; ", name, NULL);
    }

    return NULL;
}

static const char *set_ftp_directory_charset(cmd_parms *cmd, void *dconf,
                                             const char *arg)
{
    proxy_dir_conf *conf = dconf;

    conf->ftp_directory_charset = arg;
    return NULL;
}

static void ap_add_per_proxy_conf(server_rec *s, ap_conf_vector_t *dir_config)
{
    proxy_server_conf *sconf = ap_get_module_config(s->module_config,
                                                    &proxy_module);
    void **new_space = (void **)apr_array_push(sconf->sec_proxy);

    *new_space = dir_config;
}

static const char *proxysection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    proxy_dir_conf *conf;
    ap_conf_vector_t *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    ap_regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    char *word, *val;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    proxy_server_conf *sconf =
    (proxy_server_conf *) ap_get_module_config(cmd->server->module_config, &proxy_module);

    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);

    if (!arg) {
        if (thiscmd->cmd_data)
            return "<ProxyMatch > block must specify a path";
        else
            return "<Proxy > block must specify a path";
    }

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (!strncasecmp(cmd->path, "proxy:", 6))
        cmd->path += 6;

    /* XXX Ignore case?  What if we proxy a case-insensitive server?!?
     * While we are at it, shouldn't we also canonicalize the entire
     * scheme?  See proxy_fixup()
     */
    if (thiscmd->cmd_data) { /* <ProxyMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
    }
    else if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        if (!cmd->path)
            return "<Proxy ~ > block must specify a path";
        if (strncasecmp(cmd->path, "proxy:", 6))
            cmd->path += 6;
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
    }

    /* initialize our config and fetch it */
    conf = ap_set_config_vectors(cmd->server, new_dir_conf, cmd->path,
                                 &proxy_module, cmd->pool);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_dir_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->r = r;
    conf->p = cmd->path;
    conf->p_is_fnmatch = apr_fnmatch_test(conf->p);

    ap_add_per_proxy_conf(cmd->server, new_dir_conf);

    if (*arg != '\0') {
        if (thiscmd->cmd_data)
            return "Multiple <ProxyMatch> arguments not (yet) supported.";
        if (conf->p_is_fnmatch)
            return apr_pstrcat(cmd->pool, thiscmd->name,
                               "> arguments are not supported for wildchar url.",
                               NULL);
        if (!ap_strchr_c(conf->p, ':'))
            return apr_pstrcat(cmd->pool, thiscmd->name,
                               "> arguments are not supported for non url.",
                               NULL);
        if (strncasecmp(conf->p, "balancer:", 9) == 0) {
            balancer = ap_proxy_get_balancer(cmd->pool, sconf, conf->p);
            if (!balancer) {
                err = ap_proxy_add_balancer(&balancer,
                                            cmd->pool,
                                            sconf, conf->p);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, thiscmd->name,
                                       " ", err, NULL);
            }
        }
        else {
            worker = ap_proxy_get_worker(cmd->temp_pool, sconf,
                                         conf->p);
            if (!worker) {
                err = ap_proxy_add_worker(&worker, cmd->pool,
                                          sconf, conf->p);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, thiscmd->name,
                                       " ", err, NULL);
            }
        }
        if (worker == NULL && balancer == NULL) {
            return apr_pstrcat(cmd->pool, thiscmd->name,
                               "> arguments are supported only for workers.",
                               NULL);
        }
        while (*arg) {
            word = ap_getword_conf(cmd->pool, &arg);
            val = strchr(word, '=');
            if (!val) {
                return "Invalid Proxy parameter. Parameter must be "
                       "in the form 'key=value'";
            }
            else
                *val++ = '\0';
            if (worker)
                err = set_worker_param(cmd->pool, worker, word, val);
            else
                err = set_balancer_param(sconf, cmd->pool, balancer,
                                         word, val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, thiscmd->name, " ", err, " ",
                                   word, "=", val, "; ", conf->p, NULL);
        }
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const command_rec proxy_cmds[] =
{
    AP_INIT_RAW_ARGS("<Proxy", proxysection, NULL, RSRC_CONF,
    "Container for directives affecting resources located in the proxied "
    "location"),
    AP_INIT_RAW_ARGS("<ProxyMatch", proxysection, (void*)1, RSRC_CONF,
    "Container for directives affecting resources located in the proxied "
    "location, in regular expression syntax"),
    AP_INIT_FLAG("ProxyRequests", set_proxy_req, NULL, RSRC_CONF,
     "on if the true proxy requests should be accepted"),
    AP_INIT_TAKE2("ProxyRemote", add_proxy_noregex, NULL, RSRC_CONF,
     "a scheme, partial URL or '*' and a proxy server"),
    AP_INIT_TAKE2("ProxyRemoteMatch", add_proxy_regex, NULL, RSRC_CONF,
     "a regex pattern and a proxy server"),
    AP_INIT_FLAG("ProxyPassInterpolateEnv", ap_set_flag_slot,
        (void*)APR_OFFSETOF(proxy_dir_conf, interpolate_env),
        RSRC_CONF|ACCESS_CONF, "Interpolate Env Vars in reverse Proxy") ,
    AP_INIT_RAW_ARGS("ProxyPass", add_pass_noregex, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL"),
    AP_INIT_RAW_ARGS("ProxyPassMatch", add_pass_regex, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL"),
    AP_INIT_TAKE123("ProxyPassReverse", add_pass_reverse, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL for reverse proxy behaviour"),
    AP_INIT_TAKE23("ProxyPassReverseCookiePath", cookie_path, NULL,
       RSRC_CONF|ACCESS_CONF, "Path rewrite rule for proxying cookies"),
    AP_INIT_TAKE23("ProxyPassReverseCookieDomain", cookie_domain, NULL,
       RSRC_CONF|ACCESS_CONF, "Domain rewrite rule for proxying cookies"),
    AP_INIT_ITERATE("ProxyBlock", set_proxy_exclude, NULL, RSRC_CONF,
     "A list of names, hosts or domains to which the proxy will not connect"),
    AP_INIT_TAKE1("ProxyReceiveBufferSize", set_recv_buffer_size, NULL, RSRC_CONF,
     "Receive buffer size for outgoing HTTP and FTP connections in bytes"),
    AP_INIT_TAKE1("ProxyIOBufferSize", set_io_buffer_size, NULL, RSRC_CONF,
     "IO buffer size for outgoing HTTP and FTP connections in bytes"),
    AP_INIT_TAKE1("ProxyMaxForwards", set_max_forwards, NULL, RSRC_CONF,
     "The maximum number of proxies a request may be forwarded through."),
    AP_INIT_ITERATE("NoProxy", set_proxy_dirconn, NULL, RSRC_CONF,
     "A list of domains, hosts, or subnets to which the proxy will connect directly"),
    AP_INIT_TAKE1("ProxyDomain", set_proxy_domain, NULL, RSRC_CONF,
     "The default intranet domain name (in absence of a domain in the URL)"),
    AP_INIT_ITERATE("AllowCONNECT", set_allowed_ports, NULL, RSRC_CONF,
     "A list of ports which CONNECT may connect to"),
    AP_INIT_TAKE1("ProxyVia", set_via_opt, NULL, RSRC_CONF,
     "Configure Via: proxy header header to one of: on | off | block | full"),
    AP_INIT_FLAG("ProxyErrorOverride", set_proxy_error_override, NULL, RSRC_CONF,
     "use our error handling pages instead of the servers' we are proxying"),
    AP_INIT_FLAG("ProxyPreserveHost", set_preserve_host, NULL, RSRC_CONF,
     "on if we should preserve host header while proxying"),
    AP_INIT_TAKE1("ProxyTimeout", set_proxy_timeout, NULL, RSRC_CONF,
     "Set the timeout (in seconds) for a proxied connection. "
     "This overrides the server timeout"),
    AP_INIT_TAKE1("ProxyBadHeader", set_bad_opt, NULL, RSRC_CONF,
     "How to handle bad header line in response: IsError | Ignore | StartBody"),
    AP_INIT_RAW_ARGS("BalancerMember", add_member, NULL, RSRC_CONF|ACCESS_CONF,
     "A balancer name and scheme with list of params"),
    AP_INIT_TAKE1("ProxyStatus", set_status_opt, NULL, RSRC_CONF,
     "Configure Status: proxy status to one of: on | off | full"),
    AP_INIT_RAW_ARGS("ProxySet", set_proxy_param, NULL, RSRC_CONF|ACCESS_CONF,
     "A balancer or worker name with list of params"),
    AP_INIT_TAKE1("ProxyFtpDirCharset", set_ftp_directory_charset, NULL,
     RSRC_CONF|ACCESS_CONF, "Define the character set for proxied FTP listings"),
    {NULL}
};

static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable) *proxy_ssl_enable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable) *proxy_ssl_disable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *proxy_is_https = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *proxy_ssl_val = NULL;

PROXY_DECLARE(int) ap_proxy_ssl_enable(conn_rec *c)
{
    /*
     * if c == NULL just check if the optional function was imported
     * else run the optional function so ssl filters are inserted
     */
    if (proxy_ssl_enable) {
        return c ? proxy_ssl_enable(c) : 1;
    }

    return 0;
}

PROXY_DECLARE(int) ap_proxy_ssl_disable(conn_rec *c)
{
    if (proxy_ssl_disable) {
        return proxy_ssl_disable(c);
    }

    return 0;
}

PROXY_DECLARE(int) ap_proxy_conn_is_https(conn_rec *c)
{
    if (proxy_is_https) {
        return proxy_is_https(c);
    }
    else
        return 0;
}

PROXY_DECLARE(const char *) ap_proxy_ssl_val(apr_pool_t *p, server_rec *s,
                                             conn_rec *c, request_rec *r,
                                             const char *var)
{
    if (proxy_ssl_val) {
        /* XXX Perhaps the casting useless */
        return (const char *)proxy_ssl_val(p, s, c, r, (char *)var);
    }
    else
        return NULL;
}

static int proxy_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{

    proxy_ssl_enable = APR_RETRIEVE_OPTIONAL_FN(ssl_proxy_enable);
    proxy_ssl_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
    proxy_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    proxy_ssl_val = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    return OK;
}

/*
 *  proxy Extension to mod_status
 */
static int proxy_status_hook(request_rec *r, int flags)
{
    int i, n;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    proxy_balancer *balancer = NULL;
    proxy_worker **worker = NULL;

    if (flags & AP_STATUS_SHORT || conf->balancers->nelts == 0 ||
        conf->proxy_status == status_off)
        return OK;

    balancer = (proxy_balancer *)conf->balancers->elts;
    for (i = 0; i < conf->balancers->nelts; i++) {
        ap_rputs("<hr />\n<h1>Proxy LoadBalancer Status for ", r);
        ap_rvputs(r, balancer->name, "</h1>\n\n", NULL);
        ap_rputs("\n\n<table border=\"0\"><tr>"
                 "<th>SSes</th><th>Timeout</th><th>Method</th>"
                 "</tr>\n<tr>", r);
        if (balancer->sticky) {
            if (strcmp(balancer->sticky, balancer->sticky_path)) {
                ap_rvputs(r, "<td>", balancer->sticky, " | ",
                          balancer->sticky_path, NULL);
            }
            else {
                ap_rvputs(r, "<td>", balancer->sticky, NULL);
            }
        }
        else {
            ap_rputs("<td> - ", r);
        }
        ap_rprintf(r, "</td><td>%" APR_TIME_T_FMT "</td>",
                   apr_time_sec(balancer->timeout));
        ap_rprintf(r, "<td>%s</td>\n",
                   balancer->lbmethod->name);
        ap_rputs("</table>\n", r);
        ap_rputs("\n\n<table border=\"0\"><tr>"
                 "<th>Sch</th><th>Host</th><th>Stat</th>"
                 "<th>Route</th><th>Redir</th>"
                 "<th>F</th><th>Set</th><th>Acc</th><th>Wr</th><th>Rd</th>"
                 "</tr>\n", r);

        worker = (proxy_worker **)balancer->workers->elts;
        for (n = 0; n < balancer->workers->nelts; n++) {
            char fbuf[50];
            ap_rvputs(r, "<tr>\n<td>", (*worker)->scheme, "</td>", NULL);
            ap_rvputs(r, "<td>", (*worker)->hostname, "</td><td>", NULL);
            if ((*worker)->s->status & PROXY_WORKER_DISABLED)
                ap_rputs("Dis", r);
            else if ((*worker)->s->status & PROXY_WORKER_IN_ERROR)
                ap_rputs("Err", r);
            else if ((*worker)->s->status & PROXY_WORKER_INITIALIZED)
                ap_rputs("Ok", r);
            else
                ap_rputs("-", r);
            ap_rvputs(r, "</td><td>", (*worker)->s->route, NULL);
            ap_rvputs(r, "</td><td>", (*worker)->s->redirect, NULL);
            ap_rprintf(r, "</td><td>%d</td>", (*worker)->s->lbfactor);
            ap_rprintf(r, "<td>%d</td>", (*worker)->s->lbset);
            ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td><td>", (*worker)->s->elected);
            ap_rputs(apr_strfsize((*worker)->s->transferred, fbuf), r);
            ap_rputs("</td><td>", r);
            ap_rputs(apr_strfsize((*worker)->s->read, fbuf), r);
            ap_rputs("</td>\n", r);

            /* TODO: Add the rest of dynamic worker data */
            ap_rputs("</tr>\n", r);

            ++worker;
        }
        ap_rputs("</table>\n", r);
        ++balancer;
    }
    ap_rputs("<hr /><table>\n"
             "<tr><th>SSes</th><td>Sticky session name</td></tr>\n"
             "<tr><th>Timeout</th><td>Balancer Timeout</td></tr>\n"
             "<tr><th>Sch</th><td>Connection scheme</td></tr>\n"
             "<tr><th>Host</th><td>Backend Hostname</td></tr>\n"
             "<tr><th>Stat</th><td>Worker status</td></tr>\n"
             "<tr><th>Route</th><td>Session Route</td></tr>\n"
             "<tr><th>Redir</th><td>Session Route Redirection</td></tr>\n"
             "<tr><th>F</th><td>Load Balancer Factor in %</td></tr>\n"
             "<tr><th>Acc</th><td>Number of requests</td></tr>\n"
             "<tr><th>Wr</th><td>Number of bytes transferred</td></tr>\n"
             "<tr><th>Rd</th><td>Number of bytes read</td></tr>\n"
             "</table>", r);

    return OK;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    proxy_worker *reverse = NULL;

    while (s) {
        void *sconf = s->module_config;
        proxy_server_conf *conf;
        proxy_worker *worker;
        int i;

        conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        /* Initialize worker's shared scoreboard data */
        worker = (proxy_worker *)conf->workers->elts;
        for (i = 0; i < conf->workers->nelts; i++) {
            ap_proxy_initialize_worker_share(conf, worker, s);
            ap_proxy_initialize_worker(worker, s, p);
            worker++;
        }
        /* Create and initialize forward worker if defined */
        if (conf->req_set && conf->req) {
            conf->forward = ap_proxy_create_worker(p);
            conf->forward->name     = "proxy:forward";
            conf->forward->hostname = "*";
            conf->forward->scheme   = "*";
            ap_proxy_initialize_worker_share(conf, conf->forward, s);
            ap_proxy_initialize_worker(conf->forward, s, p);
            /* Do not disable worker in case of errors */
            conf->forward->s->status |= PROXY_WORKER_IGNORE_ERRORS;
            /* Disable address cache for generic forward worker */
            conf->forward->is_address_reusable = 0;
        }
        if (!reverse) {
            reverse = ap_proxy_create_worker(p);
            reverse->name     = "proxy:reverse";
            reverse->hostname = "*";
            reverse->scheme   = "*";
            ap_proxy_initialize_worker_share(conf, reverse, s);
            ap_proxy_initialize_worker(reverse, s, p);
            /* Do not disable worker in case of errors */
            reverse->s->status |= PROXY_WORKER_IGNORE_ERRORS;
            /* Disable address cache for generic reverse worker */
            reverse->is_address_reusable = 0;
        }
        conf->reverse = reverse;
        s = s->next;
    }
}

/*
 * This routine is called before the server processes the configuration
 * files.  There is no return value.
 */
static int proxy_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp)
{
    APR_OPTIONAL_HOOK(ap, status_hook, proxy_status_hook, NULL, NULL,
                      APR_HOOK_MIDDLE);
    /* Reset workers count on gracefull restart */
    proxy_lb_workers = 0;
    return OK;
}
static void register_hooks(apr_pool_t *p)
{
    /* fixup before mod_rewrite, so that the proxied url will not
     * escaped accidentally by our fixup.
     */
    static const char * const aszSucc[]={ "mod_rewrite.c", NULL };
    /* Only the mpm_winnt has child init hook handler.
     * make sure that we are called after the mpm
     * initializes.
     */
    static const char *const aszPred[] = { "mpm_winnt.c", "mod_proxy_balancer.c", NULL};

    APR_REGISTER_OPTIONAL_FN(ap_proxy_lb_workers);
    APR_REGISTER_OPTIONAL_FN(ap_proxy_lb_worker_size);
    /* handler */
    ap_hook_handler(proxy_handler, NULL, NULL, APR_HOOK_FIRST);
    /* filename-to-URI translation */
    ap_hook_translate_name(proxy_trans, aszSucc, NULL, APR_HOOK_FIRST);
    /* walk <Proxy > entries and suppress default TRACE behavior */
    ap_hook_map_to_storage(proxy_map_location, NULL,NULL, APR_HOOK_FIRST);
    /* fixups */
    ap_hook_fixups(proxy_fixup, NULL, aszSucc, APR_HOOK_FIRST);
    /* post read_request handling */
    ap_hook_post_read_request(proxy_detect, NULL, NULL, APR_HOOK_FIRST);
    /* pre config handling */
    ap_hook_pre_config(proxy_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* post config handling */
    ap_hook_post_config(proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* child init handling */
    ap_hook_child_init(child_init, aszPred, NULL, APR_HOOK_MIDDLE);

}

module AP_MODULE_DECLARE_DATA proxy_module =
{
    STANDARD20_MODULE_STUFF,
    create_proxy_dir_config,    /* create per-directory config structure */
    merge_proxy_dir_config,     /* merge per-directory config structures */
    create_proxy_config,        /* create per-server config structure */
    merge_proxy_config,         /* merge per-server config structures */
    proxy_cmds,                 /* command table */
    register_hooks
};

APR_HOOK_STRUCT(
    APR_HOOK_LINK(scheme_handler)
    APR_HOOK_LINK(canon_handler)
    APR_HOOK_LINK(pre_request)
    APR_HOOK_LINK(post_request)
    APR_HOOK_LINK(request_status)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, scheme_handler,
                                     (request_rec *r, proxy_worker *worker,
                                      proxy_server_conf *conf,
                                      char *url, const char *proxyhost,
                                      apr_port_t proxyport),(r,worker,conf,
                                      url,proxyhost,proxyport),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, canon_handler,
                                      (request_rec *r, char *url),(r,
                                      url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, pre_request, (
                                      proxy_worker **worker,
                                      proxy_balancer **balancer,
                                      request_rec *r,
                                      proxy_server_conf *conf,
                                      char **url),(worker,balancer,
                                      r,conf,url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, post_request,
                                      (proxy_worker *worker,
                                       proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf),(worker,
                                       balancer,r,conf),DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, fixups,
                                    (request_rec *r), (r),
                                    OK, DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, request_status,
                                    (int *status, request_rec *r),
                                    (status, r),
                                    OK, DECLINED)
