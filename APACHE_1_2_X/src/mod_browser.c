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
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
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
 * mod_browser.c
 * Set environment variables based on browser support.
 * 
 * Alexei Kosut <akosut@organic.com>
 */

#include "httpd.h"
#include "http_config.h"

typedef struct {
    char *name;
    regex_t *preg;
    table *features;
} browser_entry;

typedef struct {
    array_header *browsers;
} browser_server_config_rec;

module browser_module;

void *create_browser_config (pool *p, server_rec *dummy)
{
    browser_server_config_rec *new =
   (browser_server_config_rec *) palloc (p, sizeof(browser_server_config_rec));

    new->browsers = make_array (p, 20, sizeof(browser_entry));
    return (void *)new;
}

void *merge_browser_config (pool *p, void *basev, void *overridesv)
{
    browser_server_config_rec *a =
	pcalloc(p, sizeof(browser_server_config_rec));
    browser_server_config_rec *base = basev, *overrides = overridesv;

    a->browsers = append_arrays(p, base->browsers, overrides->browsers);
    return a;
}

const char *add_browser(cmd_parms *cmd, void *dummy, char *name,
			const char *feature)
{
    browser_server_config_rec *sconf =
      get_module_config (cmd->server->module_config, &browser_module);
    browser_entry *new, *entries = (browser_entry *)sconf->browsers->elts;
    char *var;
    int i, cflags = (int)cmd->info;

    /* First, try to merge into an existing entry */

    for (i = 0; i < sconf->browsers->nelts; ++i) {
	browser_entry *b = &entries[i];
	if (!strcmp(b->name, name)) {
	    var = getword(cmd->pool, &feature, '=');
	    if (*feature) table_set(b->features, var, feature);
	    else if (*var == '!') table_set(b->features, var + 1, "!");
	    else table_set(b->features, var, "1");
	    return NULL;
	}
    }

    /* If none was found, create a new entry */

    new = push_array(sconf->browsers);
    new->name = name;
    new->preg = pregcomp (cmd->pool, name, REG_EXTENDED|REG_NOSUB|cflags);
    if (new->preg == NULL) {
	return "Browser regex could not be compiled.";
    }
    new->features = make_table(cmd->pool, 5);

    var = getword(cmd->pool, &feature, '=');
    if (*feature) table_set(new->features, var, feature);
    else if (*var == '!') table_set(new->features, var + 1, "!");
    else table_set(new->features, var, "1");

    return NULL;
}

command_rec browser_module_cmds[] = {
{ "BrowserMatch", add_browser, (void*)0,
    RSRC_CONF, ITERATE2, "A browser regex and a list of variables." },
{ "BrowserMatchNoCase", add_browser, (void*)REG_ICASE,
    RSRC_CONF, ITERATE2, "a browser regex and a list of variables." },
{ NULL },
};

static int browser_match(request_rec *r)
{
    server_rec *s = r->server;
    browser_server_config_rec *sconf = get_module_config (s->module_config,
							  &browser_module);
    browser_entry *entries = (browser_entry *)sconf->browsers->elts;
    table_entry *elts;
    char *ua = table_get(r->headers_in, "User-Agent");
    int i, j;

    if (!ua) return DECLINED;

    for (i = 0; i < sconf->browsers->nelts; ++i) {
	browser_entry *b = &entries[i];

	if (!regexec(b->preg, ua, 0, NULL, 0)) {
	    elts = (table_entry *)b->features->elts;

	    for (j = 0; j < b->features->nelts; ++j) {
		if (!strcmp(elts[j].val, "!"))
		    table_unset(r->subprocess_env, elts[j].key);
		else
		    table_set(r->subprocess_env, elts[j].key, elts[j].val);
	    }
	}
    }

    return DECLINED;  
}

module browser_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   create_browser_config,	/* server config */
   merge_browser_config,     	/* merge server configs */
   browser_module_cmds,		/* command table */
   NULL,			/* handlers */
   browser_match,		/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
