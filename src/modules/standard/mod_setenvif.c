/* ====================================================================
 * Copyright (c) 1996 The Apache Group.  All rights reserved.
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
 * mod_setenvif.c
 * Set environment variables based on matching request headers or
 * attributes against regex strings
 * 
 * Paul Sutton <paul@ukweb.com> 27 Oct 1996
 * Based on mod_browser by Alexei Kosut <akosut@organic.com>
 */

/*
 * Used to set environment variables based on the incoming request headers,
 * or some selected other attributes of the request (e.g., the remote host
 * name).
 *
 * Usage:
 *
 *   SetEnvIf name regex var ...
 *
 * where name is either a HTTP request header name, or one of the
 * special values (see below). The 'value' of the header (or the
 * value of the special value from below) are compared against the
 * regex argument. If this is a simple string, a simple sub-string
 * match is performed. Otherwise, a request expression match is
 * done. If the value matches the string or regular expression, the
 * environment variables listed as var ... are set. Each var can 
 * be in one of three formats: var, which sets the named variable
 * (the value value "1"); var=value, which sets the variable to
 * the given value; or !var, which unsets the variable is it has
 * been previously set.
 *
 * Normally the strings are compared with regard to case. To ignore
 * case, use the directive SetEnvIfNoCase instead.
 *
 * Special values for 'name' are:
 *
 *   remote_host        Remote host name (if available)
 *   remote_addr        Remote IP address
 *   remote_user        Remote authenticated user (if any)
 *   request_method     Request method (GET, POST, etc)
 *   request_uri        Requested URI
 *
 * Examples:
 *
 * To set the enviroment variable LOCALHOST if the client is the local
 * machine:
 *
 *    SetEnvIf remote_addr 127.0.0.1 LOCALHOST
 *
 * To set LOCAL if the client is the local host, or within our company's
 * domain (192.168.10):
 *
 *    SetEnvIf remote_addr 192.168.10. LOCAL
 *    SetEnvIf remote_addr 127.0.0.1   LOCALHOST
 *
 * This could be written as:
 *
 *    SetEnvIf remote_addr (127.0.0.1|192.168.10.) LOCAL
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

typedef struct {
    char *name;			/* header name */
    char *regex;		/* regex to match against */
    regex_t *preg;		/* compiled regex */
    table *features;		/* env vars to set (or unset) */
} sei_entry;

typedef struct {
    array_header *conditionals;
    int zero_means_unset;
} sei_cfg_rec;

module MODULE_VAR_EXPORT setenvif_module;

static void *create_setenvif_config(pool *p, server_rec *dummy)
{
    sei_cfg_rec *new = (sei_cfg_rec *)palloc(p, sizeof(sei_cfg_rec));

    new->conditionals = make_array(p, 20, sizeof(sei_entry));
    new->zero_means_unset = 0;
    return (void *)new;
}

static void *merge_setenvif_config(pool *p, void *basev, void *overridesv)
{
    sei_cfg_rec *a =
	pcalloc(p, sizeof(sei_cfg_rec));
    sei_cfg_rec *base = basev, *overrides = overridesv;

    a->conditionals = append_arrays(p, base->conditionals, 
				    overrides->conditionals);
    a->zero_means_unset = overrides->zero_means_unset;
    return a;
}

static const char *add_setenvif(cmd_parms *cmd, void *mconfig, const char *args)
{
    char *fname;
    char *regex;
    const char *feature;
    const char *cmdline = args;
    sei_cfg_rec *sconf =
	get_module_config(cmd->server->module_config, &setenvif_module);
    sei_entry *new, *entries = 
	(sei_entry *)sconf->conditionals->elts;
    char *var;
    int i;
    int cflags = (int)cmd->info;
    char *error;
    int beenhere = 0;

    /*
     * Pull in the invariant pieces from the command line.
     */
    fname = getword_conf(cmd->pool, &cmdline);
    if (!*fname) {
	error = pstrcat(cmd->pool, "Missing header-field name for ",
			cmd->cmd->name, NULL);
	return error;
    }
    regex = getword_conf(cmd->pool, &cmdline);
    if (!*regex) {
	error = pstrcat(cmd->pool, "Missing regular expression for ",
		        cmd->cmd->name, NULL);
	return error;
    }
    while ((feature = getword_conf(cmd->pool, &cmdline))) {
	beenhere++;

	/*
	 * First, try to merge into an existing entry
	 */

	for (i = 0; i < sconf->conditionals->nelts; ++i) {
	    sei_entry *b = &entries[i];
	    if (!strcmp(b->name, fname) && !strcmp(b->regex, regex)) {
		var = getword(cmd->pool, &feature, '=');
		if (*feature) {
		    table_set(b->features, var, feature);
		}
		else if (*var == '!') {
		    table_set(b->features, var + 1, "!");
		}
		else {
		    table_set(b->features, var, "1");
		}
		return NULL;
	    }
	}

	/*
	 * If none was found, create a new entry
	 */

	new = push_array(sconf->conditionals);
	new->name = fname;
	new->regex = regex;
	new->preg = pcalloc(cmd->pool, sizeof(regex_t));
	if (regcomp(new->preg, regex, REG_EXTENDED|REG_NOSUB|cflags)) {
	    error = pstrcat(cmd->pool, cmd->cmd->name,
			    " regex could not be compiled.", NULL);
	    return error;
	}
	new->features = make_table(cmd->pool, 5);

	var = getword(cmd->pool, &feature, '=');
	if (*feature) {
	    table_set(new->features, var, feature);
	}
	else if (*var == '!') {
	    table_set(new->features, var + 1, "!");
	}
	else {
	    table_set(new->features, var, "1");
	}
    }

    if (!beenhere) {
	error = pstrcat(cmd->pool, "Missing envariable expression for ",
		        cmd->cmd->name, NULL);
	return error;
    }

    return NULL;
}

/*
 * This routine handles the BrowserMatch* directives.  It simply turns around
 * and feeds them, with the appropriate embellishments, to the general-purpose
 * command handler.
 */
static const char *add_browser(cmd_parms *cmd, void *mconfig, char *word1,
			       char *word2)
{
    const char *match_command;

    match_command = pstrcat(cmd->pool, "User-Agent ", word1, " ", word2, NULL);
    return add_setenvif(cmd, mconfig, match_command);
}

static command_rec setenvif_module_cmds[] = {
{ "SetEnvIf", add_setenvif, (void *)0,
    RSRC_CONF, RAW_ARGS, "A header-name, regex and a list of variables." },
{ "SetEnvIfNoCase", add_setenvif, (void *)REG_ICASE,
    RSRC_CONF, RAW_ARGS, "a header-name, regex and a list of variables." },
{ "UnSetEnvIfZero", set_flag_slot,
    (void *)XtOffsetOf(sei_cfg_rec,zero_means_unset),
    RSRC_CONF, FLAG, "On or Off" },
{ "BrowserMatch", add_browser, (void *)0,
    RSRC_CONF, ITERATE2, "A browser regex and a list of variables." },
{ "BrowserMatchNoCase", add_browser, (void *)REG_ICASE,
    RSRC_CONF, ITERATE2, "A browser regex and a list of variables." },
{ NULL },
};

static int fname_translate_setenvif(request_rec *r)
{
    server_rec *s = r->server;
    sei_cfg_rec *sconf = (sei_cfg_rec *)get_module_config(s->module_config,
					                  &setenvif_module);
    sei_entry *entries = (sei_entry *)sconf->conditionals->elts;
    table_entry *elts;
    char *val;
    int i, j;

    for (i = 0; i < sconf->conditionals->nelts; ++i) {
	sei_entry *b = &entries[i];

	if (!strcasecmp(b->name, "remote_addr")) {
	    val = r->connection->remote_ip;
	}
	else if (!strcasecmp(b->name, "remote_host")) {
	    val = (char *)get_remote_host(r->connection, r->per_dir_config,
					  REMOTE_NAME);
	}
	else if (!strcasecmp(b->name, "remote_user")) {
	    val = r->connection->user;
	}
	else if (!strcasecmp(b->name, "request_uri")) {
	    val = r->uri;
	}
	else if (!strcasecmp(b->name, "request_method")) {
	    val = r->method;
	}
	else {
	    val = table_get(r->headers_in, b->name);
	}

	if (!val) {
	    continue;
	}
 
	if (!regexec(b->preg, val, 0, NULL, 0)) {
	    elts = (table_entry *)b->features->elts;

	    for (j = 0; j < b->features->nelts; ++j) {
		if ((!strcmp(elts[j].val, "!")) ||
		    (sconf->zero_means_unset && (!strcmp(elts[j].val, "0")))) {

		    table_unset(r->subprocess_env, elts[j].key);
#ifdef SETENV_DEBUG
		    log_printf(r->server, "mod_setenvif: unsetting %s",
			       elts[j].key);
#endif
		}
		else {
		    table_set(r->subprocess_env, elts[j].key, elts[j].val);
#ifdef SETENV_DEBUG
		    log_printf(r->server, "mod_setenvif: setting %s to %s",
			       elts[j].key, elts[j].val);
#endif
		}
	    }
	}
    }

    return DECLINED;
}

module MODULE_VAR_EXPORT setenvif_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   create_setenvif_config,	/* server config */
   merge_setenvif_config,     	/* merge server configs */
   setenvif_module_cmds,	/* command table */
   NULL,			/* handlers */
   fname_translate_setenvif,	/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL,			/* logger */
   NULL,			/* browser parse */
   NULL,			/* child (process) initializer */
   NULL				/* child (process) rundown handler */
};
