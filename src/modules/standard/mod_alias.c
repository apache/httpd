/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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

/*
 * http_alias.c: Stuff for dealing with directory aliases
 * 
 * Original by Rob McCool, rewritten in succession by David Robinson
 * and rst.
 * 
 */

#include "httpd.h"
#include "http_config.h"

typedef struct {
    char *real;
    char *fake;
    char *handler;
    regex_t *regexp;
    int redir_status;		/* 301, 302, 303, 410, etc */
} alias_entry;

typedef struct {
    array_header *aliases;
    array_header *redirects;
} alias_server_conf;

typedef struct {
    array_header *redirects;
} alias_dir_conf;

module MODULE_VAR_EXPORT alias_module;

static void *create_alias_config(pool *p, server_rec *s)
{
    alias_server_conf *a =
    (alias_server_conf *) ap_pcalloc(p, sizeof(alias_server_conf));

    a->aliases = ap_make_array(p, 20, sizeof(alias_entry));
    a->redirects = ap_make_array(p, 20, sizeof(alias_entry));
    return a;
}

static void *create_alias_dir_config(pool *p, char *d)
{
    alias_dir_conf *a =
    (alias_dir_conf *) ap_pcalloc(p, sizeof(alias_dir_conf));
    a->redirects = ap_make_array(p, 2, sizeof(alias_entry));
    return a;
}

static void *merge_alias_config(pool *p, void *basev, void *overridesv)
{
    alias_server_conf *a =
    (alias_server_conf *) ap_pcalloc(p, sizeof(alias_server_conf));
    alias_server_conf *base = (alias_server_conf *) basev, *overrides = (alias_server_conf *) overridesv;

    a->aliases = ap_append_arrays(p, overrides->aliases, base->aliases);
    a->redirects = ap_append_arrays(p, overrides->redirects, base->redirects);
    return a;
}

static void *merge_alias_dir_config(pool *p, void *basev, void *overridesv)
{
    alias_dir_conf *a =
    (alias_dir_conf *) ap_pcalloc(p, sizeof(alias_dir_conf));
    alias_dir_conf *base = (alias_dir_conf *) basev, *overrides = (alias_dir_conf *) overridesv;
    a->redirects = ap_append_arrays(p, overrides->redirects, base->redirects);
    return a;
}

static const char *add_alias_internal(cmd_parms *cmd, void *dummy, char *f, char *r,
				      int use_regex)
{
    server_rec *s = cmd->server;
    alias_server_conf *conf =
    (alias_server_conf *) ap_get_module_config(s->module_config, &alias_module);
    alias_entry *new = ap_push_array(conf->aliases);

    /* XX r can NOT be relative to DocumentRoot here... compat bug. */

    if (use_regex) {
	new->regexp = ap_pregcomp(cmd->pool, f, REG_EXTENDED);
	if (new->regexp == NULL)
	    return "Regular expression could not be compiled.";
    }

    new->fake = f;
    new->real = r;
    new->handler = cmd->info;

    return NULL;
}

static const char *add_alias(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    return add_alias_internal(cmd, dummy, f, r, 0);
}

static const char *add_alias_regex(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    return add_alias_internal(cmd, dummy, f, r, 1);
}

static const char *add_redirect_internal(cmd_parms *cmd, alias_dir_conf * dirconf,
					 char *arg1, char *arg2, char *arg3,
					 int use_regex)
{
    alias_entry *new;
    server_rec *s = cmd->server;
    alias_server_conf *serverconf =
    (alias_server_conf *) ap_get_module_config(s->module_config, &alias_module);
    int status = (int) (long) cmd->info;
    regex_t *r = NULL;
    char *f = arg2;
    char *url = arg3;

    if (!strcasecmp(arg1, "gone"))
	status = HTTP_GONE;
    else if (!strcasecmp(arg1, "permanent"))
	status = HTTP_MOVED_PERMANENTLY;
    else if (!strcasecmp(arg1, "temp"))
	status = HTTP_MOVED_TEMPORARILY;
    else if (!strcasecmp(arg1, "seeother"))
	status = HTTP_SEE_OTHER;
    else if (ap_isdigit(*arg1))
	status = atoi(arg1);
    else {
	f = arg1;
	url = arg2;
    }

    if (use_regex) {
	r = ap_pregcomp(cmd->pool, f, REG_EXTENDED);
	if (r == NULL)
	    return "Regular expression could not be compiled.";
    }

    if (ap_is_HTTP_REDIRECT(status)) {
	if (!url)
	    return "URL to redirect to is missing";
	if (!use_regex && !ap_is_url(url))
	    return "Redirect to non-URL";
    }
    else {
	if (url)
	    return "Redirect URL not valid for this status";
    }

    if (cmd->path)
	new = ap_push_array(dirconf->redirects);
    else
	new = ap_push_array(serverconf->redirects);

    new->fake = f;
    new->real = url;
    new->regexp = r;
    new->redir_status = status;
    return NULL;
}

static const char *add_redirect(cmd_parms *cmd, alias_dir_conf * dirconf, char *arg1,
				char *arg2, char *arg3)
{
    return add_redirect_internal(cmd, dirconf, arg1, arg2, arg3, 0);
}

static const char *add_redirect_regex(cmd_parms *cmd, alias_dir_conf * dirconf,
				      char *arg1, char *arg2, char *arg3)
{
    return add_redirect_internal(cmd, dirconf, arg1, arg2, arg3, 1);
}

static const command_rec alias_cmds[] =
{
    {"Alias", add_alias, NULL, RSRC_CONF, TAKE2,
     "a fakename and a realname"},
    {"ScriptAlias", add_alias, "cgi-script", RSRC_CONF, TAKE2,
     "a fakename and a realname"},
    {"Redirect", add_redirect, (void *) HTTP_MOVED_TEMPORARILY,
     OR_FILEINFO, TAKE23,
  "an optional status, then document to be redirected and destination URL"},
    {"AliasMatch", add_alias_regex, NULL, RSRC_CONF, TAKE2,
     "a regular expression and a filename"},
    {"ScriptAliasMatch", add_alias_regex, "cgi-script", RSRC_CONF, TAKE2,
     "a regular expression and a filename"},
    {"RedirectMatch", add_redirect_regex, (void *) HTTP_MOVED_TEMPORARILY,
     OR_FILEINFO, TAKE23,
     "an optional status, then a regular expression and destination URL"},
    {"RedirectTemp", add_redirect, (void *) HTTP_MOVED_TEMPORARILY,
     OR_FILEINFO, TAKE2,
     "a document to be redirected, then the destination URL"},
    {"RedirectPermanent", add_redirect, (void *) HTTP_MOVED_PERMANENTLY,
     OR_FILEINFO, TAKE2,
     "a document to be redirected, then the destination URL"},
    {NULL}
};

static int alias_matches(const char *uri, const char *alias_fakename)
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

static char *try_alias_list(request_rec *r, array_header *aliases, int doesc, int *status)
{
    alias_entry *entries = (alias_entry *) aliases->elts;
    regmatch_t regm[10];
    char *found = NULL;
    int i;

    for (i = 0; i < aliases->nelts; ++i) {
	alias_entry *p = &entries[i];
	int l;

	if (p->regexp) {
	    if (!regexec(p->regexp, r->uri, p->regexp->re_nsub + 1, regm, 0)) {
		if (p->real) {
		    found = ap_pregsub(r->pool, p->real, r->uri,
				    p->regexp->re_nsub + 1, regm);
		    if (found && doesc) {
			found = ap_escape_uri(r->pool, found);
		    }
		}
		else {
		    /* need something non-null */
		    found = ap_pstrdup(r->pool, "");
		}
	    }
	}
	else {
	    l = alias_matches(r->uri, p->fake);

	    if (l > 0) {
		if (doesc) {
		    char *escurl;
		    escurl = ap_os_escape_path(r->pool, r->uri + l, 1);

		    found = ap_pstrcat(r->pool, p->real, escurl, NULL);
		}
		else
		    found = ap_pstrcat(r->pool, p->real, r->uri + l, NULL);
	    }
	}

	if (found) {
	    if (p->handler) {	/* Set handler, and leave a note for mod_cgi */
		r->handler = p->handler;
		ap_table_setn(r->notes, "alias-forced-type", r->handler);
	    }

	    *status = p->redir_status;

	    return found;
	}

    }

    return NULL;
}

static int translate_alias_redir(request_rec *r)
{
    void *sconf = r->server->module_config;
    alias_server_conf *serverconf =
    (alias_server_conf *) ap_get_module_config(sconf, &alias_module);
    char *ret;
    int status;

    if (r->uri[0] != '/' && r->uri[0] != '\0')
	return DECLINED;

    if ((ret = try_alias_list(r, serverconf->redirects, 1, &status)) != NULL) {
	if (ap_is_HTTP_REDIRECT(status)) {
	    /* include QUERY_STRING if any */
	    if (r->args) {
		ret = ap_pstrcat(r->pool, ret, "?", r->args, NULL);
	    }
	    ap_table_setn(r->headers_out, "Location", ret);
	}
	return status;
    }

    if ((ret = try_alias_list(r, serverconf->aliases, 0, &status)) != NULL) {
	r->filename = ret;
	return OK;
    }

    return DECLINED;
}

static int fixup_redir(request_rec *r)
{
    void *dconf = r->per_dir_config;
    alias_dir_conf *dirconf =
    (alias_dir_conf *) ap_get_module_config(dconf, &alias_module);
    char *ret;
    int status;

    /* It may have changed since last time, so try again */

    if ((ret = try_alias_list(r, dirconf->redirects, 1, &status)) != NULL) {
	if (ap_is_HTTP_REDIRECT(status))
	    ap_table_setn(r->headers_out, "Location", ret);
	return status;
    }

    return DECLINED;
}

module MODULE_VAR_EXPORT alias_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_alias_dir_config,	/* dir config creater */
    merge_alias_dir_config,	/* dir merger --- default is to override */
    create_alias_config,	/* server config */
    merge_alias_config,		/* merge server configs */
    alias_cmds,			/* command table */
    NULL,			/* handlers */
    translate_alias_redir,	/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    fixup_redir,		/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
