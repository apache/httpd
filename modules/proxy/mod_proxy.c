#define FIX_15207
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

#define CORE_PRIVATE

#include "mod_proxy.h"
#include "mod_core.h"

#include "apr_optional.h"

#if (MODULE_MAGIC_NUMBER_MAJOR > 20020903)
#include "mod_ssl.h"
#else
APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
#endif

#ifndef MAX
#define MAX(x,y) ((x) >= (y) ? (x) : (y))
#endif

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

#ifdef FIX_15207
/* XXX: EBCDIC safe? --nd */
#define x2c(x) (((x >= '0') && (x <= '9'))         \
                   ? (x - '0')                     \
                   : (((x >= 'a') && (x <= 'f'))   \
                       ? (10 + x - 'a')            \
                       : ((x >= 'A') && (x <='F')) \
                           ? (10 + x - 'A')        \
                           : 0                     \
                     )                             \
               )

static unsigned char hex2c(const char* p) {
  const char c1 = p[1];
  const char c2 = p[1] ? p[2]: '\0';
  int i1 = c1 ? x2c(c1) : 0;
  int i2 = c2 ? x2c(c2) : 0;
  unsigned char ret = (i1 << 4) | i2;

  return ret;
}
#endif

static const char *set_worker_param(proxy_worker *worker,
                                    const char *key,
                                    const char *val)
{

    int ival;
    if (!strcasecmp(key, "loadfactor")) {
        worker->lbfactor = atoi(val);
        if (worker->lbfactor < 1 || worker->lbfactor > 100)
            return "loadfactor must be number between 1..100";
    }
    else if (!strcasecmp(key, "retry")) {
        ival = atoi(val);
        if (ival < 1)
            return "retry must be al least one second";
        worker->retry = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "ttl")) {
        ival = atoi(val);
        if (ival < 1)
            return "ttl must be al least one second";
        worker->ttl = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "min")) {
        ival = atoi(val);
        if (ival < 0)
            return "min must be a positive number";
        worker->min = ival;
    }
    else if (!strcasecmp(key, "max")) {
        ival = atoi(val);
        if (ival < 0)
            return "max must be a positive number";
        worker->hmax = ival;
    }
    /* XXX: More inteligent naming needed */
    else if (!strcasecmp(key, "smax")) {
        ival = atoi(val);
        if (ival < 0)
            return "smax must be a positive number";
        worker->smax = ival;
    }
    else {
        return "unknown parameter";
    }
    return NULL;
}

static const char *set_balancer_param(struct proxy_balancer *balancer,
                                      const char *key,
                                      const char *val)
{

    int ival;
    if (!strcasecmp(key, "stickysession")) {
        balancer->sticky = val;
    }
    else if (!strcasecmp(key, "nofailover")) {
        if (!strcasecmp(val, "on"))
            balancer->sticky_force = 1;
        else if (!strcasecmp(val, "off"))
            balancer->sticky_force = 0;
        else
            return "failover must be On|Off";
    }
    else if (!strcasecmp(key, "timeout")) {
        ival = atoi(val);
        if (ival < 1)
            return "timeout must be al least one second";
        balancer->timeout = apr_time_from_sec(ival);
    }
    else {
        return "unknown parameter";
    }
    return NULL;
}

static int alias_match(const char *uri, const char *alias_fakename)
{
    const char *end_fakename = alias_fakename + strlen(alias_fakename);
    const char *aliasp = alias_fakename, *urip = uri;
    const char *end_uri = uri + strlen(uri);
    unsigned char uric, aliasc;

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
#ifndef FIX_15207
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
#else
            /* Other characters are canonicalised and compared literally */
            if (*urip == '%') {
                uric = hex2c(urip);
                urip += 3;
            } else {
                uric = (unsigned char)*urip++;
            }
            if (*aliasp == '%') {
                aliasc = hex2c(aliasp);
                aliasp += 3;
            } else {
                aliasc = (unsigned char)*aliasp++;
            }
            if (uric != aliasc) {
                return 0;
            }
#endif
        }
    }

    /* fixup badly encoded stuff (e.g. % as last character) */
    if (aliasp > end_fakename) {
        aliasp = end_fakename;
    }
    if (urip > end_uri) {
        urip = end_uri;
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
#ifdef FIX_15207
    int i, len;
    struct proxy_alias *ent = (struct proxy_alias *)conf->aliases->elts;
#endif

    /* Ick... msvc (perhaps others) promotes ternary short results to int */

    if (conf->req && r->parsed_uri.scheme) {
        /* but it might be something vhosted */
        if (!(r->parsed_uri.hostname
              && !strcasecmp(r->parsed_uri.scheme, ap_http_method(r))
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
#ifdef FIX_15207
    } else {
        /* test for a ProxyPass */
        for (i = 0; i < conf->aliases->nelts; i++) {
            len = alias_match(r->unparsed_uri, ent[i].fake);
            if (len > 0) {
                r->filename = apr_pstrcat(r->pool, "proxy:", ent[i].real,
                                          r->unparsed_uri + len, NULL);
                r->handler = "proxy-server";
                r->proxyreq = PROXYREQ_REVERSE;
                r->uri = r->unparsed_uri;
                break;
            }
        }
#endif
    }
    return DECLINED;
}

static int proxy_trans(request_rec *r)
{
#ifndef FIX_15207
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    int i, len;
    struct proxy_alias *ent = (struct proxy_alias *) conf->aliases->elts;
#endif

    if (r->proxyreq) {
        /* someone has already set up the proxy, it was possibly ourselves
         * in proxy_detect
         */
        return OK;
    }

#ifndef FIX_15207
    /* XXX: since r->uri has been manipulated already we're not really
     * compliant with RFC1945 at this point.  But this probably isn't
     * an issue because this is a hybrid proxy/origin server.
     */

    for (i = 0; i < conf->aliases->nelts; i++) {
        len = alias_match(r->uri, ent[i].fake);

       if (len > 0) {
           if ((ent[i].real[0] == '!') && (ent[i].real[1] == 0)) {
               return DECLINED;
           }

           r->filename = apr_pstrcat(r->pool, "proxy:", ent[i].real,
                                     r->uri + len, NULL);
           r->handler = "proxy-server";
           r->proxyreq = PROXYREQ_REVERSE;
           return OK;
       }
    }
#endif
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
#ifndef FIX_15207
/* -------------------------------------------------------------- */
/* Fixup the filename */

/*
 * Canonicalise the URL
 */
static int proxy_fixup(request_rec *r)
{
    char *url, *p;
    int access_status;

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

#ifdef FIX_15207
/* We definitely shouldn't canonicalize a proxy_pass.
 * But should we really canonicalize a STD_PROXY??? -- Fahree
 */
    if (r->proxyreq == PROXYREQ_REVERSE) {
        return OK;
    }
#endif

    /* XXX: Shouldn't we try this before we run the proxy_walk? */
    url = &r->filename[6];

    /* canonicalise each specific scheme */
    if ((access_status = proxy_run_canon_handler(r, url))) {
        return access_status;
    }

    p = strchr(url, ':');
    if (p == NULL || p == url)
        return HTTP_BAD_REQUEST;

    return OK;		/* otherwise; we've done the best we can */
}
#endif
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
    if (strchr(r->parsed_uri.hostname, '.') != NULL
     || strcasecmp(r->parsed_uri.hostname, "localhost") == 0)
        return DECLINED;	/* host name has a dot already */

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
    char *url, *scheme, *p;
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
    struct proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;

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
    apr_table_set(r->headers_in, "Max-Forwards", 
                  apr_psprintf(r->pool, "%ld", (maxfwd > 0) ? maxfwd : 0));

    url = r->filename + 6;
    p = strchr(url, ':');
    if (p == NULL)
        return HTTP_BAD_REQUEST;

    /* If the host doesn't have a domain name, add one and redirect. */
    if (conf->domain != NULL) {
        rc = proxy_needsdomain(r, url, conf->domain);
        if (ap_is_HTTP_REDIRECT(rc))
            return HTTP_MOVED_PERMANENTLY;
    }

    *p = '\0';
    scheme = apr_pstrdup(r->pool, url);
    *p = ':';

    /* Check URI's destination host against NoProxy hosts */
    /* Bypass ProxyRemote server lookup if configured as NoProxy */
    /* we only know how to handle communication to a proxy via http */
    /*if (strcasecmp(scheme, "http") == 0) */
    {
        int ii;
        struct dirconn_entry *list = (struct dirconn_entry *) conf->dirconn->elts;

        for (direct_connect = ii = 0; ii < conf->dirconn->nelts && !direct_connect; ii++) {
            direct_connect = list[ii].matcher(&list[ii], r);
        }
#if DEBUGGING
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      (direct_connect) ? "NoProxy for %s" : "UseProxy for %s",
                      r->uri);
#endif
    }
    /* Try to obtain the most suitable worker */
    access_status = proxy_run_pre_request(&worker, &balancer, r, conf, &url);
    if (access_status != DECLINED && access_status != OK) {
        return access_status;
    }
                                          
    /* firstly, try a proxy, unless a NoProxy directive is active */
    if (!direct_connect) {
        for (i = 0; i < proxies->nelts; i++) {
            p2 = ap_strchr_c(ents[i].scheme, ':');  /* is it a partial URL? */
            if (strcmp(ents[i].scheme, "*") == 0 ||
                (ents[i].use_regex && ap_regexec(ents[i].regexp, url, 0,NULL, 0)) ||
                (p2 == NULL && strcasecmp(scheme, ents[i].scheme) == 0) ||
                (p2 != NULL &&
                 strncasecmp(url, ents[i].scheme, strlen(ents[i].scheme)) == 0)) {

                /* handle the scheme */
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                             "Trying to run scheme_handler against proxy");
                access_status = proxy_run_scheme_handler(r, conf, url, ents[i].hostname, ents[i].port);

                /* an error or success */
                if (access_status != DECLINED && access_status != HTTP_BAD_GATEWAY) {
                    return access_status;
                }
                /* we failed to talk to the upstream proxy */
            }
        }
    }

    /* otherwise, try it direct */
    /* N.B. what if we're behind a firewall, where we must use a proxy or
     * give up??
     */

    /* handle the scheme */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "Trying to run scheme_handler");
    access_status = proxy_run_scheme_handler(r, conf, url, NULL, 0);
    if (DECLINED == access_status) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
                    "proxy: No protocol handler was valid for the URL %s. "
                    "If you are using a DSO version of mod_proxy, make sure "
                    "the proxy submodules are included in the configuration "
                    "using LoadModule.", r->uri);
        return HTTP_FORBIDDEN;
    }
    access_status = proxy_run_post_request(worker, balancer, r, conf);
    if (access_status == DECLINED) {
        access_status = OK; /* no post_request handler available */
        /* TODO: reclycle direct worker */
    }
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
    ps->raliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    ps->cookie_paths = apr_array_make(p, 10, sizeof(struct proxy_alias));
    ps->cookie_domains = apr_array_make(p, 10, sizeof(struct proxy_alias));
    ps->cookie_path_str = apr_strmatch_precompile(p, "path=", 0);
    ps->cookie_domain_str = apr_strmatch_precompile(p, "domain=", 0);
    ps->noproxies = apr_array_make(p, 10, sizeof(struct noproxy_entry));
    ps->dirconn = apr_array_make(p, 10, sizeof(struct dirconn_entry));
    ps->allowed_connect_ports = apr_array_make(p, 10, sizeof(int));
    ps->workers = apr_array_make(p, 10, sizeof(proxy_worker));
    ps->balancers = apr_array_make(p, 10, sizeof(struct proxy_balancer));
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
    ps->raliases = apr_array_append(p, base->raliases, overrides->raliases);
    ps->cookie_paths
        = apr_array_append(p, base->cookie_paths, overrides->cookie_paths);
    ps->cookie_domains
        = apr_array_append(p, base->cookie_domains, overrides->cookie_domains);
    ps->cookie_path_str = base->cookie_path_str;
    ps->cookie_domain_str = base->cookie_domain_str;
    ps->noproxies = apr_array_append(p, base->noproxies, overrides->noproxies);
    ps->dirconn = apr_array_append(p, base->dirconn, overrides->dirconn);
    ps->allowed_connect_ports = apr_array_append(p, base->allowed_connect_ports, overrides->allowed_connect_ports);
    ps->workers = apr_array_append(p, base->workers, overrides->workers);
    ps->balancers = apr_array_append(p, base->balancers, overrides->balancers);

    ps->domain = (overrides->domain == NULL) ? base->domain : overrides->domain;
    ps->viaopt = (overrides->viaopt_set == 0) ? base->viaopt : overrides->viaopt;
    ps->req = (overrides->req_set == 0) ? base->req : overrides->req;
    ps->recv_buffer_size = (overrides->recv_buffer_size_set == 0) ? base->recv_buffer_size : overrides->recv_buffer_size;
    ps->io_buffer_size = (overrides->io_buffer_size_set == 0) ? base->io_buffer_size : overrides->io_buffer_size;
    ps->maxfwd = (overrides->maxfwd_set == 0) ? base->maxfwd : overrides->maxfwd;
    ps->error_override = (overrides->error_override_set == 0) ? base->error_override : overrides->error_override;
    ps->preserve_host = (overrides->preserve_host_set == 0) ? base->preserve_host : overrides->preserve_host;
    ps->timeout= (overrides->timeout_set == 0) ? base->timeout : overrides->timeout;
    ps->badopt = (overrides->badopt_set == 0) ? base->badopt : overrides->badopt;

    return ps;
}

static void *create_proxy_dir_config(apr_pool_t *p, char *dummy)
{
    proxy_dir_conf *new =
        (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));

    /* Filled in by proxysection, when applicable */

    return (void *) new;
}

static void *merge_proxy_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    proxy_dir_conf *new = (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));
    proxy_dir_conf *add = (proxy_dir_conf *) addv;

    new->p = add->p;
    new->p_is_fnmatch = add->p_is_fnmatch;
    new->r = add->r;
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
    regex_t *reg = NULL;
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
        reg = ap_pregcomp(cmd->pool, f, REG_EXTENDED);
        if (!reg)
            return "Regular expression for ProxyRemoteMatch could not be compiled.";
    }
    else
        if (strchr(f, ':') == NULL)
            ap_str_tolower(f);		/* lowercase scheme */
    ap_str_tolower(p + 3);		/* lowercase hostname */

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
    add_pass(cmd_parms *cmd, void *dummy, const char *arg)
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
    
    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        if (!f)
            f = word;
        else if (!r)
            r = word;
        else {
            char *val = strchr(word, '=');
            if (!val) {
                if (cmd->path)
                    return "Invalid ProxyPass parameter. Paramet must be in the form key=value";
                else
                    return "ProxyPass can not have a path when defined in a location"; 
            }
            else
                *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    };

    if (r == NULL)
        return "ProxyPass needs a path when not defined in a location";

    new = apr_array_push(conf->aliases);
    new->fake = apr_pstrdup(cmd->pool, f);
    new->real = apr_pstrdup(cmd->pool, r);
    
    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    /* Distinguish the balancer from woker */
    if (strncasecmp(r, "balancer:", 9) == 0) {
        struct proxy_balancer *balancer = ap_proxy_get_balancer(cmd->pool, conf, r);
        if (!balancer) {
            const char *err = ap_proxy_add_balancer(&balancer,
                                                    cmd->pool,
                                                    conf, r);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "BalancerMember: ", err, NULL);
        }        
        for (i = 0; i < arr->nelts; i++) {
            const char *err = set_balancer_param(balancer, elts[i].key, elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass: ", err, NULL);
        }
    }
    else {
        proxy_worker *worker = ap_proxy_get_worker(cmd->pool, conf, r);
        if (!worker) {
            const char *err = ap_proxy_add_worker(&worker, cmd->pool, conf, r);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass: ", err, NULL);
        }
        for (i = 0; i < arr->nelts; i++) {
            const char *err = set_worker_param(worker, elts[i].key, elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass: ", err, NULL);
        }
    }
    return NULL;
}

static const char *
    add_pass_reverse(cmd_parms *cmd, void *dummy, const char *f, const char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf;
    struct proxy_alias *new;

    conf = (proxy_server_conf *)ap_get_module_config(s->module_config, 
                                                     &proxy_module);
    if (r!=NULL && cmd->path == NULL ) {
        new = apr_array_push(conf->raliases);
        new->fake = f;
        new->real = r;
    } else if (r==NULL && cmd->path != NULL) {
        new = apr_array_push(conf->raliases);
        new->fake = cmd->path;
        new->real = f;
    } else {
        if ( r == NULL)
            return "ProxyPassReverse needs a path when not defined in a location";
        else 
            return "ProxyPassReverse can not have a path when defined in a location";
    }

    return NULL;
}
static const char*
    cookie_path(cmd_parms *cmd, void *dummy, const char *f, const char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf;
    struct proxy_alias *new;

    conf = (proxy_server_conf *)ap_get_module_config(s->module_config,
                                                     &proxy_module);
    new = apr_array_push(conf->cookie_paths);
    new->fake = f;
    new->real = r;

    return NULL;
}
static const char*
    cookie_domain(cmd_parms *cmd, void *dummy, const char *f, const char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf;
    struct proxy_alias *new;

    conf = (proxy_server_conf *)ap_get_module_config(s->module_config,
                                                     &proxy_module);
    new = apr_array_push(conf->cookie_domains);
    new->fake = f;
    new->real = r;

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
        if (apr_strnatcasecmp(arg, list[i].name) == 0) { /* ignore case for host names */
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

    psf->io_buffer_size = ((s > AP_IOBUFSIZE) ? s : AP_IOBUFSIZE);
    psf->io_buffer_size_set = 1;
    return NULL;
}

static const char *
    set_max_forwards(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);
    if (s < 0) {
        return "ProxyMaxForwards must be greater or equal to zero..";
    }

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

static const char *add_member(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_balancer *balancer;
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
        word = ap_getword_conf(cmd->pool, &arg);
        if (!path)
            path = word;
        else if (!name)
            name = word;
        else {
            char *val = strchr(word, '=');
            if (!val)
                if (cmd->path)
                    return "BalancerMember can not have a balancer name when defined in a location";
                else
                    return "Invalid BalancerMember parameter. Paramet must be in the form key=value";
            else
                *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    }
    if (!path)
        return "BalancerMember must define balancer name when outside <Proxy > section";
    if (!name)
        return "BalancerMember must define remote proxy server";
    
    ap_str_tolower(path);	/* lowercase scheme://hostname */
    ap_str_tolower(name);	/* lowercase scheme://hostname */

    /* Try to find existing worker */
    worker = ap_proxy_get_worker(cmd->temp_pool, conf, name);
    if (!worker) {
        const char *err;
        if ((err = ap_proxy_add_worker(&worker, cmd->pool, conf, name)) != NULL)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember: ", err, NULL); 
    }

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        const char *err = set_worker_param(worker, elts[i].key, elts[i].val);
        if (err)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember: ", err, NULL);
    }
    /* Try to find the balancer */
    balancer = ap_proxy_get_balancer(cmd->temp_pool, conf, name); 
    if (!balancer) {
        const char *err = ap_proxy_add_balancer(&balancer,
                                                cmd->pool,
                                                conf, path);
        if (err)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember: ", err, NULL);
    }
    /* Add the worker to the load balancer */
    ap_proxy_add_worker_to_balancer(balancer, worker);

    return NULL;
}

static const char *
    set_sticky_session(cmd_parms *cmd, void *dummy, const char *f, const char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_balancer *balancer;
    const char *name, *sticky;

    if (r != NULL && cmd->path == NULL ) {
        name = f;
        sticky = r;
    } else if (r == NULL && cmd->path != NULL) {
        name = cmd->path;
        sticky = f;
    } else {
        if (r == NULL)
            return "BalancerStickySession needs a path when not defined in a location";
        else 
            return "BalancerStickySession can not have a path when defined in a location";
    }
    /* Try to find the balancer */
    balancer = ap_proxy_get_balancer(cmd->temp_pool, conf, name);
    if (!balancer)
        return apr_pstrcat(cmd->temp_pool, "BalancerStickySession: can not find a load balancer '",
                           name, "'", NULL);
    if (!strcasecmp(sticky, "nofailover"))
        balancer->sticky_force = 1;   
    else
        balancer->sticky = sticky;
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
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;

    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
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
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
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
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
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
        return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
                           "> arguments not (yet) supported.", NULL);
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
    AP_INIT_RAW_ARGS("ProxyPass", add_pass, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL"),
    AP_INIT_TAKE12("ProxyPassReverse", add_pass_reverse, NULL, RSRC_CONF|ACCESS_CONF,
     "a virtual path and a URL for reverse proxy behaviour"),
    AP_INIT_TAKE2("ProxyPassReverseCookiePath", cookie_path, NULL,
       RSRC_CONF|ACCESS_CONF, "Path rewrite rule for proxying cookies"),
    AP_INIT_TAKE2("ProxyPassReverseCookieDomain", cookie_domain, NULL,
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
    AP_INIT_TAKE12("BalancerStickySession", set_sticky_session, NULL, RSRC_CONF|ACCESS_CONF,
     "A balancer and sticky session name"),
    {NULL}
};

static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable) *proxy_ssl_enable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable) *proxy_ssl_disable = NULL;

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

static int proxy_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    proxy_ssl_enable = APR_RETRIEVE_OPTIONAL_FN(ssl_proxy_enable);
    proxy_ssl_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    /* fixup before mod_rewrite, so that the proxied url will not
     * escaped accidentally by our fixup.
     */
#ifndef FIX_15207
    static const char * const aszSucc[]={ "mod_rewrite.c", NULL };
#endif

    /* handler */
    ap_hook_handler(proxy_handler, NULL, NULL, APR_HOOK_FIRST);
    /* filename-to-URI translation */
    ap_hook_translate_name(proxy_trans, NULL, NULL, APR_HOOK_FIRST);
    /* walk <Proxy > entries and suppress default TRACE behavior */
    ap_hook_map_to_storage(proxy_map_location, NULL,NULL, APR_HOOK_FIRST);
#ifndef FIX_15207
    /* fixups */
    ap_hook_fixups(proxy_fixup, NULL, aszSucc, APR_HOOK_FIRST);
#endif
    /* post read_request handling */
    ap_hook_post_read_request(proxy_detect, NULL, NULL, APR_HOOK_FIRST);
    /* post config handling */
    ap_hook_post_config(proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA proxy_module =
{
    STANDARD20_MODULE_STUFF,
    create_proxy_dir_config,    /* create per-directory config structure */
    merge_proxy_dir_config,     /* merge per-directory config structures */
    create_proxy_config,	/* create per-server config structure */
    merge_proxy_config,		/* merge per-server config structures */
    proxy_cmds,			/* command table */
    register_hooks
};

APR_HOOK_STRUCT(
	APR_HOOK_LINK(scheme_handler)
	APR_HOOK_LINK(canon_handler)
	APR_HOOK_LINK(pre_request)
	APR_HOOK_LINK(post_request)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, scheme_handler, 
                                     (request_rec *r, proxy_server_conf *conf, 
                                     char *url, const char *proxyhost, 
                                     apr_port_t proxyport),(r,conf,url,
                                     proxyhost,proxyport),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, canon_handler, 
                                     (request_rec *r, char *url),(r,
                                     url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, pre_request, (
                                      proxy_worker **worker,
                                      struct proxy_balancer **balancer,
                                      request_rec *r, 
                                      proxy_server_conf *conf,
                                      char **url),(worker,balancer,
                                      r,conf,url),DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, post_request,
                                      (proxy_worker *worker,
                                       struct proxy_balancer *balancer,
                                       request_rec *r,
                                       proxy_server_conf *conf),(worker,
                                       balancer,r,conf),DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, fixups,
				    (request_rec *r), (r),
				    OK, DECLINED)
