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
 *   server_addr       IP address of interface on which request arrived
 *                     (analogous to SERVER_ADDR set in ap_add_common_vars())
 *   remote_host        Remote host name (if available)
 *   remote_addr        Remote IP address
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

enum special {
    SPECIAL_NOT,
    SPECIAL_REMOTE_ADDR,
    SPECIAL_REMOTE_HOST,
    SPECIAL_REQUEST_URI,
    SPECIAL_REQUEST_METHOD,
    SPECIAL_REQUEST_PROTOCOL,
    SPECIAL_SERVER_ADDR
};
typedef struct {
    char *name;                 /* header name */
    char *regex;                /* regex to match against */
    regex_t *preg;              /* compiled regex */
    table *features;            /* env vars to set (or unset) */
    ENUM_BITFIELD(              /* is it a "special" header ? */
	enum special,
	special_type,4);
    unsigned icase : 1;		/* ignoring case? */
} sei_entry;

typedef struct {
    array_header *conditionals;
} sei_cfg_rec;

module MODULE_VAR_EXPORT setenvif_module;

/*
 * These routines, the create- and merge-config functions, are called
 * for both the server-wide and the per-directory contexts.  This is
 * because the different definitions are used at different times; the
 * server-wide ones are used in the post-read-request phase, and the
 * per-directory ones are used during the header-parse phase (after
 * the URI has been mapped to a file and we have anything from the
 * .htaccess file and <Directory> and <Files> containers).
 */
static void *create_setenvif_config(pool *p)
{
    sei_cfg_rec *new = (sei_cfg_rec *) ap_palloc(p, sizeof(sei_cfg_rec));

    new->conditionals = ap_make_array(p, 20, sizeof(sei_entry));
    return (void *) new;
}

static void *create_setenvif_config_svr(pool *p, server_rec *dummy)
{
    return create_setenvif_config(p);
}

static void *create_setenvif_config_dir(pool *p, char *dummy)
{
    return create_setenvif_config(p);
}

static void *merge_setenvif_config(pool *p, void *basev, void *overridesv)
{
    sei_cfg_rec *a = ap_pcalloc(p, sizeof(sei_cfg_rec));
    sei_cfg_rec *base = basev, *overrides = overridesv;

    a->conditionals = ap_append_arrays(p, base->conditionals,
				       overrides->conditionals);
    return a;
}

/*
 * any non-NULL magic constant will do... used to indicate if REG_ICASE should
 * be used
 */
#define ICASE_MAGIC	((void *)(&setenvif_module))
#define SEI_MAGIC_HEIRLOOM "setenvif-phase-flag"

static const char *add_setenvif_core(cmd_parms *cmd, void *mconfig,
				     char *fname, const char *args)
{
    char *regex;
    const char *feature;
    sei_cfg_rec *sconf;
    sei_entry *new;
    sei_entry *entries;
    char *var;
    int i;
    int beenhere = 0;
    unsigned icase;
    int perdir;

    /*
     * Determine from our context into which record to put the entry.
     * cmd->path == NULL means we're in server-wide context; otherwise,
     * we're dealing with a per-directory setting.
     */
    perdir = (cmd->path != NULL);
    sconf = perdir
	? (sei_cfg_rec *) mconfig
	: (sei_cfg_rec *) ap_get_module_config(cmd->server->module_config,
					       &setenvif_module);
    entries = (sei_entry *) sconf->conditionals->elts;
    /* get regex */
    regex = ap_getword_conf(cmd->pool, &args);
    if (!*regex) {
        return ap_pstrcat(cmd->pool, "Missing regular expression for ",
			  cmd->cmd->name, NULL);
    }

    /*
     * If we've already got a sei_entry with the same name we want to
     * just copy the name pointer... so that later on we can compare
     * two header names just by comparing the pointers.
     */

    for (i = 0; i < sconf->conditionals->nelts; ++i) {
        new = &entries[i];
	if (!strcasecmp(new->name, fname)) {
	    fname = new->name;
	    break;
	}
    }

    /* if the last entry has an identical headername and regex then
     * merge with it
     */
    i = sconf->conditionals->nelts - 1;
    icase = cmd->info == ICASE_MAGIC;
    if (i < 0
	|| entries[i].name != fname
	|| entries[i].icase != icase
	|| strcmp(entries[i].regex, regex)) {

	/* no match, create a new entry */

	new = ap_push_array(sconf->conditionals);
	new->name = fname;
	new->regex = regex;
	new->icase = icase;
	new->preg = ap_pregcomp(cmd->pool, regex,
				(REG_EXTENDED | REG_NOSUB
				 | (icase ? REG_ICASE : 0)));
	if (new->preg == NULL) {
	    return ap_pstrcat(cmd->pool, cmd->cmd->name,
			      " regex could not be compiled.", NULL);
	}
	new->features = ap_make_table(cmd->pool, 2);

	if (!strcasecmp(fname, "remote_addr")) {
	    new->special_type = SPECIAL_REMOTE_ADDR;
	}
	else if (!strcasecmp(fname, "remote_host")) {
	    new->special_type = SPECIAL_REMOTE_HOST;
	}
	else if (!strcasecmp(fname, "request_uri")) {
	    new->special_type = SPECIAL_REQUEST_URI;
	}
	else if (!strcasecmp(fname, "request_method")) {
	    new->special_type = SPECIAL_REQUEST_METHOD;
	}
	else if (!strcasecmp(fname, "request_protocol")) {
	    new->special_type = SPECIAL_REQUEST_PROTOCOL;
	}
        else if (!strcasecmp(fname, "server_addr")) {
            new->special_type = SPECIAL_SERVER_ADDR;
        }
	else {
	    new->special_type = SPECIAL_NOT;
	}
    }
    else {
	new = &entries[i];
    }

    for ( ; ; ) {
	feature = ap_getword_conf(cmd->pool, &args);
	if (!*feature) {
	    break;
	}
        beenhere++;

        var = ap_getword(cmd->pool, &feature, '=');
        if (*feature) {
            ap_table_setn(new->features, var, feature);
        }
        else if (*var == '!') {
            ap_table_setn(new->features, var + 1, "!");
        }
        else {
            ap_table_setn(new->features, var, "1");
        }
    }

    if (!beenhere) {
        return ap_pstrcat(cmd->pool, "Missing envariable expression for ",
			  cmd->cmd->name, NULL);
    }

    return NULL;
}

static const char *add_setenvif(cmd_parms *cmd, void *mconfig,
				const char *args)
{
    char *fname;

    /* get header name */
    fname = ap_getword_conf(cmd->pool, &args);
    if (!*fname) {
        return ap_pstrcat(cmd->pool, "Missing header-field name for ",
			  cmd->cmd->name, NULL);
    }
    return add_setenvif_core(cmd, mconfig, fname, args);
}

/*
 * This routine handles the BrowserMatch* directives.  It simply turns around
 * and feeds them, with the appropriate embellishments, to the general-purpose
 * command handler.
 */
static const char *add_browser(cmd_parms *cmd, void *mconfig, const char *args)
{
    return add_setenvif_core(cmd, mconfig, "User-Agent", args);
}

static const command_rec setenvif_module_cmds[] =
{
    { "SetEnvIf", add_setenvif, NULL,
      OR_FILEINFO, RAW_ARGS, "A header-name, regex and a list of variables." },
    { "SetEnvIfNoCase", add_setenvif, ICASE_MAGIC,
      OR_FILEINFO, RAW_ARGS, "a header-name, regex and a list of variables." },
    { "BrowserMatch", add_browser, NULL,
      OR_FILEINFO, RAW_ARGS, "A browser regex and a list of variables." },
    { "BrowserMatchNoCase", add_browser, ICASE_MAGIC,
      OR_FILEINFO, RAW_ARGS, "A browser regex and a list of variables." },
    { NULL },
};

/*
 * This routine gets called at two different points in request processing:
 * once before the URI has been translated (during the post-read-request
 * phase) and once after (during the header-parse phase).  We use different
 * config records for the two different calls to reduce overhead (by not
 * re-doing the server-wide settings during directory processing), and
 * signal which call it is by having the earlier one pass a flag to the
 * later one.
 */
static int match_headers(request_rec *r)
{
    sei_cfg_rec *sconf;
    sei_entry *entries;
    table_entry *elts;
    const char *val;
    int i, j;
    int perdir;
    char *last_name;

    perdir = (ap_table_get(r->notes, SEI_MAGIC_HEIRLOOM) != NULL);
    if (! perdir) {
	ap_table_set(r->notes, SEI_MAGIC_HEIRLOOM, "post-read done");
	sconf  = (sei_cfg_rec *) ap_get_module_config(r->server->module_config,
						      &setenvif_module);
    }
    else {
	sconf = (sei_cfg_rec *) ap_get_module_config(r->per_dir_config,
						     &setenvif_module);
    }
    entries = (sei_entry *) sconf->conditionals->elts;
    last_name = NULL;
    val = NULL;
    for (i = 0; i < sconf->conditionals->nelts; ++i) {
        sei_entry *b = &entries[i];

	/* Optimize the case where a bunch of directives in a row use the
	 * same header.  Remember we don't need to strcmp the two header
	 * names because we made sure the pointers were equal during
	 * configuration.
	 */
	if (b->name != last_name) {
	    last_name = b->name;
	    switch (b->special_type) {
	    case SPECIAL_REMOTE_ADDR:
		val = r->connection->remote_ip;
                break;
            case SPECIAL_SERVER_ADDR:
                val = r->connection->local_ip;
                break;
	    case SPECIAL_REMOTE_HOST:
		val =  ap_get_remote_host(r->connection, r->per_dir_config,
					  REMOTE_NAME);
		break;
	    case SPECIAL_REQUEST_URI:
		val = r->uri;
		break;
	    case SPECIAL_REQUEST_METHOD:
		val = r->method;
		break;
	    case SPECIAL_REQUEST_PROTOCOL:
		val = r->protocol;
		break;
	    case SPECIAL_NOT:
		val = ap_table_get(r->headers_in, b->name);
		if (val == NULL) {
		    val = ap_table_get(r->subprocess_env, b->name);
		}
		break;
	    }
        }

	/*
	 * A NULL value indicates that the header field or special entity
	 * wasn't present or is undefined.  Represent that as an empty string
	 * so that REs like "^$" will work and allow envariable setting
	 * based on missing or empty field.
	 */
        if (val == NULL) {
            val = "";
        }

        if (!ap_regexec(b->preg, val, 0, NULL, 0)) {
	    array_header *arr = ap_table_elts(b->features);
            elts = (table_entry *) arr->elts;

            for (j = 0; j < arr->nelts; ++j) {
                if (!strcmp(elts[j].val, "!")) {
                    ap_table_unset(r->subprocess_env, elts[j].key);
                }
                else {
                    ap_table_setn(r->subprocess_env, elts[j].key, elts[j].val);
                }
            }
        }
    }

    return DECLINED;
}

module MODULE_VAR_EXPORT setenvif_module =
{
    STANDARD_MODULE_STUFF,
    NULL,                       /* initializer */
    create_setenvif_config_dir, /* dir config creater */
    merge_setenvif_config,      /* dir merger --- default is to override */
    create_setenvif_config_svr, /* server config */
    merge_setenvif_config,      /* merge server configs */
    setenvif_module_cmds,       /* command table */
    NULL,                       /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,                       /* fixups */
    NULL,                       /* logger */
    match_headers,              /* input header parse */
    NULL,                       /* child (process) initialization */
    NULL,                       /* child (process) rundown */
    match_headers               /* post_read_request */
};
