
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
 * mod_actions.c: executes scripts based on MIME type
 *
 * by Alexei Kosut; based on mod_cgi.c, mod_mime.c and mod_includes.c,
 * adapted by rst from original NCSA code by Rob McCool
 *
 * Usage instructions:
 *
 * Action mime/type /cgi-bin/script
 * 
 * will activate /cgi-bin/script when a file of content type mime/type. It
 * sends the URL and file path of the requested document using the standard
 * CGI PATH_INFO and PATH_TRANSLATED environment variables.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"

typedef struct {
    table *action_types;	/* Added with Action... */
    char *get;			/* Added with Script GET */
    char *post;			/* Added with Script POST */
    char *put;			/* Added with Script PUT */
    char *delete;		/* Added with Script DELETE */
} action_dir_config;

module action_module;

void *create_action_dir_config (pool *p, char *dummy)
{
    action_dir_config *new =
      (action_dir_config *) palloc (p, sizeof(action_dir_config));

    new->action_types = make_table (p, 4);
    new->get = NULL;
    new->post = NULL;
    new->put = NULL;
    new->delete = NULL;
    
    return new;
}

void *merge_action_dir_configs (pool *p, void *basev, void *addv)
{
    action_dir_config *base = (action_dir_config *)basev;
    action_dir_config *add = (action_dir_config *)addv;
    action_dir_config *new =
      (action_dir_config *)palloc (p, sizeof(action_dir_config));

    new->action_types = overlay_tables (p, add->action_types,
					  base->action_types);

    new->get = add->get ? add->get : base->get;
    new->post = add->post ? add->post : base->post;
    new->put = add->put ? add->put : base->put;
    new->delete = add->delete ? add->delete : base->delete;

    return new;
}

char *add_action(cmd_parms *cmd, action_dir_config *m, char *type, char *script)
{
    table_set (m->action_types, type, script);
    return NULL;
}

char *set_script (cmd_parms *cmd, action_dir_config *m, char *method,
		  char *script)
{
    if (!strcmp(method, "GET"))
        m->get = pstrdup(cmd->pool, script);
    else if (!strcmp(method, "POST"))
        m->post = pstrdup(cmd->pool, script);
    else if (!strcmp(method, "PUT"))
        m->put = pstrdup(cmd->pool, script);
    else if (!strcmp(method, "DELETE"))
        m->delete = pstrdup(cmd->pool, script);
    else
        return "Unknown method type for Script";

    return NULL;
}

command_rec action_cmds[] = {
{ "Action", add_action, NULL, OR_FILEINFO, TAKE2, 
    "a media type followed by a script name" },
{ "Script", set_script, NULL, ACCESS_CONF|RSRC_CONF, TAKE2,
    "a method followed by a script name" },
{ NULL }
};

int action_handler (request_rec *r)
{
    action_dir_config *conf =
      (action_dir_config *)get_module_config(r->per_dir_config,&action_module);
    char *t, *action = r->handler ? r->handler : r->content_type;
    char *script = NULL;

    /* First, check for the method-handling scripts */
    if ((r->method_number == M_GET) && r->args && conf->get)
        script = conf->get;
    else if ((r->method_number == M_POST) && conf->post)
        script = conf->post;
    else if ((r->method_number == M_PUT) && conf->put)
        script = conf->put;
    else if ((r->method_number == M_DELETE) && conf->delete)
        script = conf->delete;

    /* Check for looping, which can happen if the CGI script isn't */
    if (script && r->prev && r->prev->prev)
        return DECLINED;

    /* Second, check for actions (which override the method scripts) */
    if ((action || default_type(r)) && (t = table_get(conf->action_types,
					action ? action : default_type(r)))) {
        script = t;
	if (r->finfo.st_mode == 0) {
	    log_reason("File does not exist", r->filename, r);
	    return NOT_FOUND;
	}
    }
  
    if (script == NULL)
        return DECLINED;

    internal_redirect_handler(pstrcat(r->pool, script, escape_uri(r->pool,
			r->uri), r->args ? "?" : NULL, r->args, NULL), r);
    return OK;
}

handler_rec action_handlers[] = {
{ "*/*", action_handler },
{ NULL }
};

module action_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_action_dir_config,	/* dir config creater */
   merge_action_dir_configs,	/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   action_cmds,			/* command table */
   action_handlers,		/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
