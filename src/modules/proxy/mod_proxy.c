/* ====================================================================
 * Copyright (c) 1996,1997 The Apache Group.  All rights reserved.
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
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
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

/* Some WWW schemes and their default ports; this is basically /etc/services */
/* This will become global when the protocol abstraction comes */
static struct proxy_services defports[]={
    { "ftp",      DEFAULT_FTP_PORT},
    { "gopher",   DEFAULT_GOPHER_PORT},
    { "http",     DEFAULT_PORT},
    { "nntp",     DEFAULT_NNTP_PORT},
    { "wais",     DEFAULT_WAIS_PORT}, 
    { "https",    DEFAULT_HTTPS_PORT},
    { "snews",    DEFAULT_SNEWS_PORT},
    { "prospero", DEFAULT_PROSPERO_PORT},
    { NULL, -1}  /* unknown port */
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

static int
alias_match(char *uri, char *alias_fakename)
{
    char *end_fakename = alias_fakename + strlen (alias_fakename);
    char *aliasp = alias_fakename, *urip = uri;

    while (aliasp < end_fakename)
    {
	if (*aliasp == '/')
	{
	    /* any number of '/' in the alias matches any number in
	     * the supplied URI, but there must be at least one...
	     */
	    if (*urip != '/') return 0;
	    
	    while (*aliasp == '/') ++ aliasp;
	    while (*urip == '/') ++ urip;
	}
	else {
	    /* Other characters are compared literally */
	    if (*urip++ != *aliasp++) return 0;
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

static int
proxy_trans(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *)get_module_config(sconf, &proxy_module);

    if (r->proxyreq)
    {
	if (!conf->req) return DECLINED;
	
	r->filename = pstrcat(r->pool, "proxy:", r->uri, NULL);
	r->handler = "proxy-server";
	return OK;
    } else
    {
	int i, len;
	struct proxy_alias *ent=(struct proxy_alias *)conf->aliases->elts;

	for (i=0; i < conf->aliases->nelts; i++)
	{
	    len = alias_match(r->uri, ent[i].fake);

	    if (len > 0)
	    {
		r->filename = pstrcat(r->pool, "proxy:", ent[i].real,
				      r->uri + len, NULL);
		r->handler = "proxy-server";
		return OK;
	    }
	}
	return DECLINED;
    }
}

/* -------------------------------------------------------------- */
/* Fixup the filename */

/*
 * Canonicalise the URL
 */
static int
proxy_fixup(request_rec *r)
{
    char *url, *p;
    int i;

    if (strncmp(r->filename, "proxy:", 6) != 0) return DECLINED;

    url = &r->filename[6];
/* lowercase the scheme */
    p = strchr(url, ':');
    if (p == NULL || p == url) return BAD_REQUEST;
    for (i=0; i != p - url; i++) url[i] = tolower(url[i]);

/* canonicalise each specific scheme */
    if (strncmp(url, "http:", 5) == 0)
	return proxy_http_canon(r, url+5, "http", DEFAULT_PORT);
    else if (strncmp(url, "ftp:", 4) == 0)
	return proxy_ftp_canon(r, url+4);
    else return OK; /* otherwise; we've done the best we can */
}

/* -------------------------------------------------------------- */
/* Invoke handler */
 
static int
proxy_handler(request_rec *r)
{
    char *url, *scheme, *p;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf =
        (proxy_server_conf *)get_module_config(sconf, &proxy_module);
    array_header *proxies=conf->proxies;
    struct proxy_remote *ents=(struct proxy_remote *)proxies->elts;
    int i, rc;
    struct cache_req *cr;

    if (strncmp(r->filename, "proxy:", 6) != 0) return DECLINED;

    if ((rc = setup_client_block(r, REQUEST_CHUNKED_ERROR)))
	return rc;

    url = r->filename + 6;
    p = strchr(url, ':');
    if (p == NULL) return BAD_REQUEST;

    rc = proxy_cache_check(r, url, &conf->cache, &cr);
    if (rc != DECLINED) return rc;

    *p = '\0';
    scheme = pstrdup(r->pool, url);
    *p = ':';

/* firstly, try a proxy */

    for (i=0; i < proxies->nelts; i++)
    {
	p = strchr(ents[i].scheme, ':');  /* is it a partial URL? */
	if (strcmp(ents[i].scheme, "*") == 0 || 
	    (p == NULL && strcmp(scheme, ents[i].scheme) == 0) ||
	    (p != NULL &&
	       strncmp(url, ents[i].scheme, strlen(ents[i].scheme)) == 0))
	{
/* we only know how to handle communication to a proxy via http */
	    if (strcmp(ents[i].protocol, "http") == 0)
		rc = proxy_http_handler(r, cr, url, ents[i].hostname,
		    ents[i].port);
	    else rc = DECLINED;

 /* an error or success */
	    if (rc != DECLINED && rc != BAD_GATEWAY) return rc;
 /* we failed to talk to the upstream proxy */
	}
    }

/* otherwise, try it direct */
/* N.B. what if we're behind a firewall, where we must use a proxy or
 * give up??
 */
    /* handle the scheme */
    if (r->method_number == M_CONNECT)
	return proxy_connect_handler(r, cr, url);
    if (strcmp(scheme, "http") == 0)
	return proxy_http_handler(r, cr, url, NULL, 0);
    if (strcmp(scheme, "ftp") == 0)
	return proxy_ftp_handler(r, cr, url);
    else return NOT_IMPLEMENTED;
}

/* -------------------------------------------------------------- */
/* Setup configurable data */

static void *
create_proxy_config(pool *p, server_rec *s)
{
  proxy_server_conf *ps = pcalloc(p, sizeof(proxy_server_conf));

  ps->proxies = make_array(p, 10, sizeof(struct proxy_remote));
  ps->aliases = make_array(p, 10, sizeof(struct proxy_alias));
  ps->nocaches = make_array(p, 10, sizeof(struct nocache_entry));
  ps->req = 0;

  ps->cache.root = NULL;
  ps->cache.space = DEFAULT_CACHE_SPACE;
  ps->cache.maxexpire = DEFAULT_CACHE_MAXEXPIRE;
  ps->cache.defaultexpire = DEFAULT_CACHE_EXPIRE;
  ps->cache.lmfactor = DEFAULT_CACHE_LMFACTOR;
  ps->cache.gcinterval = -1;
  /* at these levels, the cache can have 2^18 directories (256,000)  */
  ps->cache.dirlevels=3;
  ps->cache.dirlength=1;

  return ps;
}

static const char *
add_proxy(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf =
        (proxy_server_conf *)get_module_config(s->module_config,&proxy_module);
    struct proxy_remote *new;
    char *p, *q;
    int port;

    p = strchr(r, ':');
    if (p == NULL || p[1] != '/' || p[2] != '/' || p[3] == '\0')
	return "Bad syntax for a remote proxy server";
    q = strchr(p + 3, ':');
    if (q != NULL)
    {
	if (sscanf(q+1, "%u", &port) != 1 || port > 65535)
	    return "Bad syntax for a remote proxy server (bad port number)";
	*q = '\0';
    } else port = -1;
    *p = '\0';
    if (strchr(f, ':') == NULL) str_tolower(f);     /* lowercase scheme */
    str_tolower(p + 3); /* lowercase hostname */

    if (port == -1)
    {
	int i;
	for (i=0; defports[i].scheme != NULL; i++)
	    if (strcmp(defports[i].scheme, r) == 0) break;
	port = defports[i].port;
    }

    new = push_array (conf->proxies);
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
        (proxy_server_conf *)get_module_config(s->module_config,&proxy_module);
    struct proxy_alias *new;

    new = push_array (conf->aliases);
    new->fake = f;
    new->real = r;
    return NULL;
}

static const char *
set_proxy_req(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);

    psf->req = flag;
    return NULL;
}


static const char *
set_cache_size(cmd_parms *parms, char *struct_ptr, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    int val;

    if (sscanf(arg, "%d", &val) != 1) return "Value must be an integer";
    psf->cache.space = val;
    return NULL;
}

static const char *
set_cache_root(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);

    psf->cache.root = arg;

    return NULL;
}

static const char *
set_cache_factor(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1) return "Value must be a float";
    psf->cache.lmfactor = val;

    return NULL;
}

static const char *
set_cache_maxex(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1) return "Value must be a float";
    psf->cache.maxexpire = (int)(val * (double)SEC_ONE_HR);
    return NULL;
}

static const char *
set_cache_defex(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1) return "Value must be a float";
    psf->cache.defaultexpire = (int)(val * (double)SEC_ONE_HR);
    return NULL;
}

static const char *
set_cache_gcint(cmd_parms *parms, void *dummy, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1) return "Value must be a float";
    psf->cache.gcinterval = (int)(val * (double)SEC_ONE_HR);
    return NULL;
}

static const char *
set_cache_dirlevels(cmd_parms *parms, char *struct_ptr, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    int val;

    if (sscanf(arg, "%d", &val) != 1) return "Value must be an integer";
    psf->cache.dirlevels = val;
    return NULL;
}

static const char *
set_cache_dirlength(cmd_parms *parms, char *struct_ptr, char *arg)
{
    proxy_server_conf *psf =
	get_module_config (parms->server->module_config, &proxy_module);
    int val;

    if (sscanf(arg, "%d", &val) != 1) return "Value must be an integer";
    psf->cache.dirlength = val;
    return NULL;
}

static const char *
set_cache_exclude(cmd_parms *parms, void *dummy, char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf =
	get_module_config (s->module_config, &proxy_module);
    struct nocache_entry *new;
    struct nocache_entry *list=(struct nocache_entry*)conf->nocaches->elts;
    int found = 0;
    int i;

    /* Don't duplicate entries */
    for (i=0; i < conf->nocaches->nelts; i++)
    {
	if (strcmp(arg, list[i].name) == 0)
	    found = 1;
    }

    if (!found)
    {
	new = push_array (conf->nocaches);
	new->name = arg;
    }
    return NULL;
}

static handler_rec proxy_handlers[] = {
{ "proxy-server", proxy_handler },
{ NULL } 
};  
    
static command_rec proxy_cmds[] = {
{ "ProxyRequests", set_proxy_req, NULL, RSRC_CONF, FLAG,
  "on if the true proxy requests should be accepted"},
{ "ProxyRemote", add_proxy, NULL, RSRC_CONF, TAKE2,
    "a scheme, partial URL or '*' and a proxy server"},
{ "ProxyPass", add_pass, NULL, RSRC_CONF, TAKE2,
    "a virtual path and a URL"},
{ "CacheRoot", set_cache_root, NULL, RSRC_CONF, TAKE1,
      "The directory to store cache files"},
{ "CacheSize", set_cache_size, NULL, RSRC_CONF, TAKE1,
      "The maximum disk space used by the cache in Kb"},
{ "CacheMaxExpire", set_cache_maxex, NULL, RSRC_CONF, TAKE1,
      "The maximum time in hours to cache a document"},
{ "CacheDefaultExpire", set_cache_defex, NULL, RSRC_CONF, TAKE1,
      "The default time in hours to cache a document"}, 
{ "CacheLastModifiedFactor", set_cache_factor, NULL, RSRC_CONF, TAKE1,
      "The factor used to estimate Expires date from LastModified date"},
{ "CacheGcInterval", set_cache_gcint, NULL, RSRC_CONF, TAKE1,
      "The interval between garbage collections, in hours"},
{ "CacheDirLevels", set_cache_dirlevels, NULL, RSRC_CONF, TAKE1,
    "The number of levels of subdirectories in the cache" },
{ "CacheDirLength", set_cache_dirlength, NULL, RSRC_CONF, TAKE1,
    "The number of characters in subdirectory names" },
{ "NoCache", set_cache_exclude, NULL, RSRC_CONF, ITERATE,
    "A list of hosts or domains for which caching is *not* provided" },
{ NULL }
};

module proxy_module = {
   STANDARD_MODULE_STUFF,
   NULL,                        /* initializer */
   NULL,                        /* create per-directory config structure */
   NULL,                        /* merge per-directory config structures */
   create_proxy_config,         /* create per-server config structure */
   NULL,                        /* merge per-server config structures */
   proxy_cmds,                  /* command table */
   proxy_handlers,              /* handlers */
   proxy_trans,                 /* translate_handler */
   NULL,                        /* check_user_id */
   NULL,                        /* check auth */
   NULL,                        /* check access */
   NULL,                        /* type_checker */
   proxy_fixup,                 /* pre-run fixups */
   NULL                         /* logger */
};

