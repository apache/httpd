/* ====================================================================
 * Copyright (c) 1996-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#include "mod_proxy.h"

#define CORE_PRIVATE

#include "http_log.h"
#include "http_vhost.h"
#include "http_request.h"

/* Some WWW schemes and their default ports; this is basically /etc/services */
/* This will become global when the protocol abstraction comes */
static struct proxy_services defports[] =
{
    {"http", DEFAULT_HTTP_PORT},
    {"ftp", DEFAULT_FTP_PORT},
    {"https", DEFAULT_HTTPS_PORT},
    {"gopher", DEFAULT_GOPHER_PORT},
    {"nntp", DEFAULT_NNTP_PORT},
    {"wais", DEFAULT_WAIS_PORT},
    {"snews", DEFAULT_SNEWS_PORT},
    {"prospero", DEFAULT_PROSPERO_PORT},
    {NULL, -1}			/* unknown port */
};

/*
 * A Web proxy module. Stages:
 *
 *  translate_name: set filename to proxy:<URL>
 *  type_checker:   set type to PROXY_MAGIC_TYPE if filename begins proxy:
 *  fix_ups:        convert the URL stored in the filename to the
 *                  canonical form.
 *  handler:        handle proxy requests
 */

/* -------------------------------------------------------------- */
/* Translate the URL into a 'filename' */

static int alias_match(const char *uri, const char *alias_fakename)
{
    const char *end_fakename = alias_fakename + strlen(alias_fakename);
    const char *aliasp = alias_fakename, *urip = uri;

    while (aliasp < end_fakename) {
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
    proxy_server_conf *conf;

    conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    if (conf->req && r->parsed_uri.scheme) {
	/* but it might be something vhosted */
       if (!(r->parsed_uri.hostname
	    && !strcasecmp(r->parsed_uri.scheme, ap_http_method(r))
	    && ap_matches_request_vhost(r, r->parsed_uri.hostname,
               r->parsed_uri.port_str ? r->parsed_uri.port : ap_default_port(r)))) {
	    r->proxyreq = 1;
	    r->uri = r->unparsed_uri;
	    r->filename = ap_pstrcat(r->pool, "proxy:", r->uri, NULL);
	    r->handler = "proxy-server";
        }
    }
    /* We need special treatment for CONNECT proxying: it has no scheme part */
    else if (conf->req && r->method_number == M_CONNECT
	     && r->parsed_uri.hostname
	     && r->parsed_uri.port_str) {
	    r->proxyreq = 1;
	    r->uri = r->unparsed_uri;
	    r->filename = ap_pstrcat(r->pool, "proxy:", r->uri, NULL);
	    r->handler = "proxy-server";
    }
    return DECLINED;
}

static int proxy_trans(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    int i, len;
    struct proxy_alias *ent = (struct proxy_alias *) conf->aliases->elts;

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
        len = alias_match(r->uri, ent[i].fake);
	    
       if (len > 0) {
           r->filename = ap_pstrcat(r->pool, "proxy:", ent[i].real,
                                 r->uri + len, NULL);
           r->handler = "proxy-server";
           r->proxyreq = 1;
           return OK;
	}
    }
    return DECLINED;
}

/* -------------------------------------------------------------- */
/* Fixup the filename */

/*
 * Canonicalise the URL
 */
static int proxy_fixup(request_rec *r)
{
    char *url, *p;

    if (!r->proxyreq || strncmp(r->filename, "proxy:", 6) != 0)
	return DECLINED;

    url = &r->filename[6];

/* canonicalise each specific scheme */
    if (strncasecmp(url, "http:", 5) == 0)
	return ap_proxy_http_canon(r, url + 5, "http", DEFAULT_HTTP_PORT);
    else if (strncasecmp(url, "ftp:", 4) == 0)
	return ap_proxy_ftp_canon(r, url + 4);

    p = strchr(url, ':');
    if (p == NULL || p == url)
	return HTTP_BAD_REQUEST;

    return OK;		/* otherwise; we've done the best we can */
}

static void proxy_init(server_rec *r, pool *p)
{
    ap_proxy_garbage_init(r, p);
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
    if (strchr(r->parsed_uri.hostname, '.') != NULL
     || strcasecmp(r->parsed_uri.hostname, "localhost") == 0)
	return DECLINED;	/* host name has a dot already */

    ref = ap_table_get(r->headers_in, "Referer");

    /* Reassemble the request, but insert the domain after the host name */
    /* Note that the domain name always starts with a dot */
    r->parsed_uri.hostname = ap_pstrcat(r->pool, r->parsed_uri.hostname,
				     domain, NULL);
    nuri = ap_unparse_uri_components(r->pool,
				  &r->parsed_uri,
				  UNP_REVEALPASSWORD);

    ap_table_set(r->headers_out, "Location", nuri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, r,
		"Domain missing: %s sent to %s%s%s", r->uri,
		ap_unparse_uri_components(r->pool, &r->parsed_uri,
		      UNP_OMITUSERINFO),
		ref ? " from " : "", ref ? ref : "");

    return HTTP_MOVED_PERMANENTLY;
}

/* -------------------------------------------------------------- */
/* Invoke handler */

static int proxy_handler(request_rec *r)
{
    char *url, *scheme, *p;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);
    array_header *proxies = conf->proxies;
    struct proxy_remote *ents = (struct proxy_remote *) proxies->elts;
    int i, rc;
    cache_req *cr;
    int direct_connect = 0;
    const char *maxfwd_str;

    if (!r->proxyreq || strncmp(r->filename, "proxy:", 6) != 0)
	return DECLINED;

    if (r->method_number == M_TRACE &&
	(maxfwd_str = ap_table_get(r->headers_in, "Max-Forwards")) != NULL) {
	int maxfwd = strtol(maxfwd_str, NULL, 10);
	if (maxfwd < 1) {
	    int access_status;
	    r->proxyreq = 0;
	    if ((access_status = ap_send_http_trace(r)))
		ap_die(access_status, r);
	    else
		ap_finalize_request_protocol(r);
	    return OK;
	}
	ap_table_setn(r->headers_in, "Max-Forwards", 
		      ap_psprintf(r->pool, "%d", (maxfwd > 0) ? maxfwd-1 : 0));
    }

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)))
	return rc;

    url = r->filename + 6;
    p = strchr(url, ':');
    if (p == NULL)
	return HTTP_BAD_REQUEST;

    rc = ap_proxy_cache_check(r, url, &conf->cache, &cr);
    if (rc != DECLINED)
	return rc;

    /* If the host doesn't have a domain name, add one and redirect. */
    if (conf->domain != NULL) {
	rc = proxy_needsdomain(r, url, conf->domain);
	if (ap_is_HTTP_REDIRECT(rc))
	    return HTTP_MOVED_PERMANENTLY;
    }

    *p = '\0';
    scheme = ap_pstrdup(r->pool, url);
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
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, r,
		     (direct_connect) ? "NoProxy for %s" : "UseProxy for %s",
		     r->uri);
#endif
    }

/* firstly, try a proxy, unless a NoProxy directive is active */

    if (!direct_connect)
	for (i = 0; i < proxies->nelts; i++) {
	    p = strchr(ents[i].scheme, ':');	/* is it a partial URL? */
	    if (strcmp(ents[i].scheme, "*") == 0 ||
		(p == NULL && strcasecmp(scheme, ents[i].scheme) == 0) ||
		(p != NULL &&
	       strncasecmp(url, ents[i].scheme, strlen(ents[i].scheme)) == 0)) {
		/* CONNECT is a special method that bypasses the normal
		 * proxy code.
		 */
		if (r->method_number == M_CONNECT)
		    rc = ap_proxy_connect_handler(r, cr, url, ents[i].hostname,
					       ents[i].port);
/* we only know how to handle communication to a proxy via http */
		else if (strcasecmp(ents[i].protocol, "http") == 0)
		    rc = ap_proxy_http_handler(r, cr, url, ents[i].hostname,
					    ents[i].port);
		else
		    rc = DECLINED;

		/* an error or success */
		if (rc != DECLINED && rc != HTTP_BAD_GATEWAY)
		    return rc;
		/* we failed to talk to the upstream proxy */
	    }
	}

/* otherwise, try it direct */
/* N.B. what if we're behind a firewall, where we must use a proxy or
 * give up??
 */
    /* handle the scheme */
    if (r->method_number == M_CONNECT)
	return ap_proxy_connect_handler(r, cr, url, NULL, 0);
    if (strcasecmp(scheme, "http") == 0)
	return ap_proxy_http_handler(r, cr, url, NULL, 0);
    if (strcasecmp(scheme, "ftp") == 0)
	return ap_proxy_ftp_handler(r, cr, url);
    else
	return HTTP_FORBIDDEN;
}

/* -------------------------------------------------------------- */
/* Setup configurable data */

static void *
     create_proxy_config(pool *p, server_rec *s)
{
    proxy_server_conf *ps = ap_pcalloc(p, sizeof(proxy_server_conf));

    ps->proxies = ap_make_array(p, 10, sizeof(struct proxy_remote));
    ps->aliases = ap_make_array(p, 10, sizeof(struct proxy_alias));
    ps->raliases = ap_make_array(p, 10, sizeof(struct proxy_alias));
    ps->noproxies = ap_make_array(p, 10, sizeof(struct noproxy_entry));
    ps->dirconn = ap_make_array(p, 10, sizeof(struct dirconn_entry));
    ps->nocaches = ap_make_array(p, 10, sizeof(struct nocache_entry));
    ps->allowed_connect_ports = ap_make_array(p, 10, sizeof(int));
    ps->domain = NULL;
    ps->viaopt = via_off; /* initially backward compatible with 1.3.1 */
    ps->req = 0;

    ps->cache.root = NULL;
    ps->cache.space = DEFAULT_CACHE_SPACE;
    ps->cache.maxexpire = DEFAULT_CACHE_MAXEXPIRE;
    ps->cache.defaultexpire = DEFAULT_CACHE_EXPIRE;
    ps->cache.lmfactor = DEFAULT_CACHE_LMFACTOR;
    ps->cache.gcinterval = -1;
    /* at these levels, the cache can have 2^18 directories (256,000)  */
    ps->cache.dirlevels = 3;
    ps->cache.dirlength = 1;
    ps->cache.cache_completion = DEFAULT_CACHE_COMPLETION;

    return ps;
}

static const char *
     add_proxy(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_remote *new;
    char *p, *q;
    int port;

    p = strchr(r, ':');
    if (p == NULL || p[1] != '/' || p[2] != '/' || p[3] == '\0')
	return "ProxyRemote: Bad syntax for a remote proxy server";
    q = strchr(p + 3, ':');
    if (q != NULL) {
	if (sscanf(q + 1, "%u", &port) != 1 || port > 65535)
	    return "ProxyRemote: Bad syntax for a remote proxy server (bad port number)";
	*q = '\0';
    }
    else
	port = -1;
    *p = '\0';
    if (strchr(f, ':') == NULL)
	ap_str_tolower(f);		/* lowercase scheme */
    ap_str_tolower(p + 3);		/* lowercase hostname */

    if (port == -1) {
	int i;
	for (i = 0; defports[i].scheme != NULL; i++)
	    if (strcasecmp(defports[i].scheme, r) == 0)
		break;
	port = defports[i].port;
    }

    new = ap_push_array(conf->proxies);
    new->scheme = f;
    new->protocol = r;
    new->hostname = p + 3;
    new->port = port;
    return NULL;
}

static const char *
     add_pass(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
    (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_alias *new;

    new = ap_push_array(conf->aliases);
    new->fake = f;
    new->real = r;
    return NULL;
}

static const char *
    add_pass_reverse(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf;
    struct proxy_alias *new;

    conf = (proxy_server_conf *)ap_get_module_config(s->module_config, 
                                                  &proxy_module);
    new = ap_push_array(conf->raliases);
    new->fake = f;
    new->real = r;
    return NULL;
}

static const char *
     set_proxy_exclude(cmd_parms *parms, void *dummy, char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct noproxy_entry *new;
    struct noproxy_entry *list = (struct noproxy_entry *) conf->noproxies->elts;
    struct hostent hp;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i = 0; i < conf->noproxies->nelts; i++) {
	if (strcasecmp(arg, list[i].name) == 0) /* ignore case for host names */
	    found = 1;
    }

    if (!found) {
	new = ap_push_array(conf->noproxies);
	new->name = arg;
	/* Don't do name lookups on things that aren't dotted */
	if (strchr(arg, '.') != NULL && ap_proxy_host2addr(new->name, &hp) == NULL)
	    /*@@@FIXME: This copies only the first of (possibly many) IP addrs */
	    memcpy(&new->addr, hp.h_addr, sizeof(struct in_addr));
	else
	    new->addr.s_addr = 0;
    }
    return NULL;
}

/*
 * Set the ports CONNECT can use
 */
static const char *
    set_allowed_ports(cmd_parms *parms, void *dummy, char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
      ap_get_module_config(s->module_config, &proxy_module);
    int *New;

    if (!isdigit(arg[0]))
	return "AllowCONNECT: port number must be numeric";

    New = ap_push_array(conf->allowed_connect_ports);
    *New = atoi(arg);
    return NULL;
}

/* Similar to set_proxy_exclude(), but defining directly connected hosts,
 * which should never be accessed via the configured ProxyRemote servers
 */
static const char *
     set_proxy_dirconn(cmd_parms *parms, void *dummy, char *arg)
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
	New = ap_push_array(conf->dirconn);
	New->name = arg;
	New->hostentry = NULL;

	if (ap_proxy_is_ipaddr(New, parms->pool)) {
#if DEBUGGING
	    fprintf(stderr, "Parsed addr %s\n", inet_ntoa(New->addr));
	    fprintf(stderr, "Parsed mask %s\n", inet_ntoa(New->mask));
#endif
	}
	else if (ap_proxy_is_domainname(New, parms->pool)) {
	    ap_str_tolower(New->name);
#if DEBUGGING
	    fprintf(stderr, "Parsed domain %s\n", New->name);
#endif
	}
	else if (ap_proxy_is_hostname(New, parms->pool)) {
	    ap_str_tolower(New->name);
#if DEBUGGING
	    fprintf(stderr, "Parsed host %s\n", New->name);
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
     set_proxy_domain(cmd_parms *parms, void *dummy, char *arg)
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
    return NULL;
}


static const char *
     set_cache_size(cmd_parms *parms, char *struct_ptr, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int val;

    if (sscanf(arg, "%d", &val) != 1)
	return "CacheSize value must be an integer (kBytes)";
    psf->cache.space = val;
    return NULL;
}

static const char *
     set_cache_root(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->cache.root = arg;

    return NULL;
}

static const char *
     set_cache_factor(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
	return "CacheLastModifiedFactor value must be a float";
    psf->cache.lmfactor = val;

    return NULL;
}

static const char *
     set_cache_maxex(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
	return "CacheMaxExpire value must be a float";
    psf->cache.maxexpire = (int) (val * (double) SEC_ONE_HR);
    return NULL;
}

static const char *
     set_cache_defex(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
	return "CacheDefaultExpire value must be a float";
    psf->cache.defaultexpire = (int) (val * (double) SEC_ONE_HR);
    return NULL;
}

static const char *
     set_cache_gcint(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
	return "CacheGcInterval value must be a float";
    psf->cache.gcinterval = (int) (val * (double) SEC_ONE_HR);
    return NULL;
}

static const char *
     set_cache_dirlevels(cmd_parms *parms, char *struct_ptr, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int val;

    val = atoi(arg);
    if (val < 1)
	return "CacheDirLevels value must be an integer greater than 0";
    if (val * psf->cache.dirlength > CACHEFILE_LEN)
	return "CacheDirLevels*CacheDirLength value must not be higher than 20";
    psf->cache.dirlevels = val;
    return NULL;
}

static const char *
     set_cache_dirlength(cmd_parms *parms, char *struct_ptr, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int val;

    val = atoi(arg);
    if (val < 1)
	return "CacheDirLength value must be an integer greater than 0";
    if (val * psf->cache.dirlevels > CACHEFILE_LEN)
	return "CacheDirLevels*CacheDirLength value must not be higher than 20";
    psf->cache.dirlength = val;
    return NULL;
}

static const char *
     set_cache_exclude(cmd_parms *parms, void *dummy, char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
    ap_get_module_config(s->module_config, &proxy_module);
    struct nocache_entry *new;
    struct nocache_entry *list = (struct nocache_entry *) conf->nocaches->elts;
    struct hostent hp;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i = 0; i < conf->nocaches->nelts; i++) {
	if (strcasecmp(arg, list[i].name) == 0) /* ignore case for host names */
	    found = 1;
    }

    if (!found) {
	new = ap_push_array(conf->nocaches);
	new->name = arg;
	/* Don't do name lookups on things that aren't dotted */
	if (strchr(arg, '.') != NULL && ap_proxy_host2addr(new->name, &hp) == NULL)
	    /*@@@FIXME: This copies only the first of (possibly many) IP addrs */
	    memcpy(&new->addr, hp.h_addr, sizeof(struct in_addr));
	else
	    new->addr.s_addr = 0;
    }
    return NULL;
}

static const char *
     set_recv_buffer_size(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int s = atoi(arg);
    if (s < 512 && s != 0) {
	return "ProxyReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
    }

    psf->recv_buffer_size = s;
    return NULL;
}

static const char*
    set_cache_completion(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
    ap_get_module_config(parms->server->module_config, &proxy_module);
    int s = atoi(arg);
    if (s > 100 || s < 0) {
	return "CacheForceCompletion must be <= 100 percent, "
               "or 0 for system default.";
    }

    if (s > 0)
      psf->cache.cache_completion = ((float)s / 100);
    return NULL;    
}

static const char*
    set_via_opt(cmd_parms *parms, void *dummy, char *arg)
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

    return NULL;    
}

static const handler_rec proxy_handlers[] =
{
    {"proxy-server", proxy_handler},
    {NULL}
};

static const command_rec proxy_cmds[] =
{
    {"ProxyRequests", set_proxy_req, NULL, RSRC_CONF, FLAG,
     "on if the true proxy requests should be accepted"},
    {"ProxyRemote", add_proxy, NULL, RSRC_CONF, TAKE2,
     "a scheme, partial URL or '*' and a proxy server"},
    {"ProxyPass", add_pass, NULL, RSRC_CONF, TAKE2,
     "a virtual path and a URL"},
    {"ProxyPassReverse", add_pass_reverse, NULL, RSRC_CONF, TAKE2,
     "a virtual path and a URL for reverse proxy behaviour"},
    {"ProxyBlock", set_proxy_exclude, NULL, RSRC_CONF, ITERATE,
     "A list of names, hosts or domains to which the proxy will not connect"},
    {"ProxyReceiveBufferSize", set_recv_buffer_size, NULL, RSRC_CONF, TAKE1,
     "Receive buffer size for outgoing HTTP and FTP connections in bytes"},
    {"NoProxy", set_proxy_dirconn, NULL, RSRC_CONF, ITERATE,
     "A list of domains, hosts, or subnets to which the proxy will connect directly"},
    {"ProxyDomain", set_proxy_domain, NULL, RSRC_CONF, TAKE1,
     "The default intranet domain name (in absence of a domain in the URL)"},
    {"AllowCONNECT", set_allowed_ports, NULL, RSRC_CONF, ITERATE,
     "A list of ports which CONNECT may connect to"},
    {"CacheRoot", set_cache_root, NULL, RSRC_CONF, TAKE1,
     "The directory to store cache files"},
    {"CacheSize", set_cache_size, NULL, RSRC_CONF, TAKE1,
     "The maximum disk space used by the cache in Kb"},
    {"CacheMaxExpire", set_cache_maxex, NULL, RSRC_CONF, TAKE1,
     "The maximum time in hours to cache a document"},
    {"CacheDefaultExpire", set_cache_defex, NULL, RSRC_CONF, TAKE1,
     "The default time in hours to cache a document"},
    {"CacheLastModifiedFactor", set_cache_factor, NULL, RSRC_CONF, TAKE1,
     "The factor used to estimate Expires date from LastModified date"},
    {"CacheGcInterval", set_cache_gcint, NULL, RSRC_CONF, TAKE1,
     "The interval between garbage collections, in hours"},
    {"CacheDirLevels", set_cache_dirlevels, NULL, RSRC_CONF, TAKE1,
     "The number of levels of subdirectories in the cache"},
    {"CacheDirLength", set_cache_dirlength, NULL, RSRC_CONF, TAKE1,
     "The number of characters in subdirectory names"},
    {"NoCache", set_cache_exclude, NULL, RSRC_CONF, ITERATE,
     "A list of names, hosts or domains for which caching is *not* provided"},
    {"CacheForceCompletion", set_cache_completion, NULL, RSRC_CONF, TAKE1,
     "Force a http cache completion after this percentage is loaded"},
    {"ProxyVia", set_via_opt, NULL, RSRC_CONF, TAKE1,
     "Configure Via: proxy header header to one of: on | off | block | full"},
    {NULL}
};

module MODULE_VAR_EXPORT proxy_module =
{
    STANDARD_MODULE_STUFF,
    proxy_init,			/* initializer */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_proxy_config,	/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    proxy_cmds,			/* command table */
    proxy_handlers,		/* handlers */
    proxy_trans,		/* translate_handler */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    proxy_fixup,		/* pre-run fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    proxy_detect		/* post read-request */
};
