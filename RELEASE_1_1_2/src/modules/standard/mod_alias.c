
/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
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
} alias_entry;

typedef struct {
    array_header *aliases;
    array_header *redirects;
} alias_server_conf;

typedef struct {
    array_header *redirects;
} alias_dir_conf;
module alias_module;

void *create_alias_config (pool *p, server_rec *s)
{
    alias_server_conf *a =
      (alias_server_conf *)pcalloc (p, sizeof(alias_server_conf));

    a->aliases = make_array (p, 20, sizeof(alias_entry));
    a->redirects = make_array (p, 20, sizeof(alias_entry));
    return a;
}

void *create_alias_dir_config (pool *p, char *d)
{
    alias_dir_conf *a =
      (alias_dir_conf *)pcalloc (p, sizeof(alias_dir_conf));
    a->redirects = make_array (p, 2, sizeof(alias_entry));
    return a;
}
void *merge_alias_config (pool *p, void *basev, void *overridesv)
{
    alias_server_conf *a =
	(alias_server_conf *)pcalloc (p, sizeof(alias_server_conf));
    alias_server_conf *base = (alias_server_conf *)basev,
	*overrides = (alias_server_conf *)overridesv;

    a->aliases = append_arrays (p, overrides->aliases, base->aliases);
    a->redirects = append_arrays (p, overrides->redirects, base->redirects);
    return a;
}

void *merge_alias_dir_config (pool *p, void *basev, void *overridesv)
{
    alias_dir_conf *a =
      (alias_dir_conf *)pcalloc (p, sizeof(alias_dir_conf));
    alias_dir_conf *base = (alias_dir_conf *)basev,
      *overrides = (alias_dir_conf *)overridesv;
    a->redirects = append_arrays (p, overrides->redirects, base->redirects);
    return a;
}
char *add_alias(cmd_parms *cmd, void *dummy, char *f, char *r)
{
    server_rec *s = cmd->server;
    alias_server_conf *conf =
        (alias_server_conf *)get_module_config(s->module_config,&alias_module);
    alias_entry *new = push_array (conf->aliases);

    /* XX r can NOT be relative to DocumentRoot here... compat bug. */
    
    new->fake = f; new->real = r; new->handler = cmd->info;
    return NULL;
}

char *add_redirect(cmd_parms *cmd, alias_dir_conf *dirconf, char *f, char *url)
{
    alias_entry *new;
    server_rec *s = cmd->server;
    alias_server_conf *serverconf =
        (alias_server_conf *)get_module_config(s->module_config,&alias_module);

    if (!is_url (url)) return "Redirect to non-URL";
    if ( cmd->path )
    {
        new = push_array (dirconf->redirects);
    }
    else
    {
        new = push_array (serverconf->redirects);
    }
    new->fake = f; new->real = url;
    return NULL;
}

command_rec alias_cmds[] = {
{ "Alias", add_alias, NULL, RSRC_CONF, TAKE2, 
    "a fakename and a realname"},
{ "ScriptAlias", add_alias, "cgi-script", RSRC_CONF, TAKE2, 
    "a fakename and a realname"},
{ "Redirect", add_redirect, NULL, OR_FILEINFO, TAKE2, 
    "a document to be redirected, then the destination URL" },
{ NULL }
};

int alias_matches (char *uri, char *alias_fakename)
{
    char *end_fakename = alias_fakename + strlen (alias_fakename);
    char *aliasp = alias_fakename, *urip = uri;

    while (aliasp < end_fakename) {
	if (*aliasp == '/') {
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

char *try_alias_list (request_rec *r, array_header *aliases, int doesc)
{
    alias_entry *entries = (alias_entry *)aliases->elts;
    int i;
    
    for (i = 0; i < aliases->nelts; ++i) {
        alias_entry *p = &entries[i];
        int l = alias_matches (r->uri, p->fake);

        if (l > 0) {
	    if (p->handler) { /* Set handler, and leave a note for mod_cgi */
	        r->handler = pstrdup(r->pool, p->handler);
		table_set (r->notes, "alias-forced-type", p->handler);
	    }

	    if (doesc) {
		char *escurl;
		escurl = os_escape_path(r->pool, r->uri + l, 1);
		return pstrcat(r->pool, p->real, escurl, NULL);
	    } else
		return pstrcat(r->pool, p->real, r->uri + l, NULL);
        }
    }

    return NULL;
}

int translate_alias_redir(request_rec *r)
{
    void *sconf = r->server->module_config;
    alias_server_conf *serverconf =
        (alias_server_conf *)get_module_config(sconf, &alias_module);
    char *ret;

#ifdef __EMX__
    /* Add support for OS/2 drive names */
    if ((r->uri[0] != '/' && r->uri[0] != '\0') && r->uri[1] != ':')
#else    
    if (r->uri[0] != '/' && r->uri[0] != '\0') 
#endif    
        return BAD_REQUEST;

    if ((ret = try_alias_list (r, serverconf->redirects, 1)) != NULL) {
        table_set (r->headers_out, "Location", ret);
        return REDIRECT;
    }
    
    if ((ret = try_alias_list (r, serverconf->aliases, 0)) != NULL) {
        r->filename = ret;
        return OK;
    }
    
    return DECLINED;
}

int fixup_redir(request_rec *r)
{
    void *dconf = r->per_dir_config;
    alias_dir_conf *dirconf =
        (alias_dir_conf *)get_module_config(dconf, &alias_module);
    char *ret;

    /* It may have changed since last time, so try again */

    if ((ret = try_alias_list (r, dirconf->redirects, 1)) != NULL) {
        table_set (r->headers_out, "Location", ret);
        return REDIRECT;
    }

    return DECLINED;
}

module alias_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_alias_dir_config,	/* dir config creater */
   merge_alias_dir_config,	/* dir merger --- default is to override */
   create_alias_config,		/* server config */
   merge_alias_config,		/* merge server configs */
   alias_cmds,			/* command table */
   NULL,			/* handlers */
   translate_alias_redir,	/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   fixup_redir,			/* fixups */
   NULL				/* logger */
};
