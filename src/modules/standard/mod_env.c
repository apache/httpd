/* ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
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
 * mod_env.c
 * version 0.0.5
 * status beta
 * Pass environment variables to CGI/SSI scripts.
 * 
 * Andrew Wilson <Andrew.Wilson@cm.cf.ac.uk> 06.Dec.95
 *
 * Change log:
 * 08.Dec.95 Now allows PassEnv directive to appear more than once in
 *           conf files.
 * 10.Dec.95 optimisation.  getenv() only called at startup and used 
 *           to build a fast-to-access table.  table used to build 
 *           per-server environment for each request.
 *           robustness.  better able to handle errors in configuration
 *           files:
 *           1)  PassEnv directive present, but no environment variable listed
 *           2)  PassEnv FOO present, but $FOO not present in environment
 *           3)  no PassEnv directive present
 * 23.Dec.95 Now allows SetEnv directive with same semantics as 'sh' setenv:
 *		SetEnv Var	sets Var to the empty string
 *		SetEnv Var Val	sets Var to the value Val
 *	     Values containing whitespace should be quoted, eg:
 *		SetEnv Var "this is some text"
 *	     Environment variables take their value from the last instance
 *	     of PassEnv / SetEnv to be reached in the configuration file.
 *	     For example, the sequence:
 *		PassEnv FOO
 *		SetEnv FOO override
 *	     Causes FOO to take the value 'override'.
 * 23.Feb.96 Added UnsetEnv directive to allow environment variables
 *           to be removed.
 *           Virtual hosts now 'inherit' parent server environment which
 *	     they're able to overwrite with their own directives or
 *	     selectively ignore with UnsetEnv.
 *       *** IMPORTANT - the way that virtual hosts inherit their ***
 *       *** environment variables from the default server's      ***
 *	 *** configuration has changed.  You should test your     ***
 *       *** configuration carefully before accepting this        ***
 *       *** version of the module in a live webserver which used ***
 *	 *** older versions of the module.                        ***
 */

#include "httpd.h"
#include "http_config.h"

typedef struct {
    table *vars;
    char *unsetenv;
    int vars_present;
} env_server_config_rec;

module env_module;

void *create_env_server_config (pool *p, server_rec *dummy)
{
    env_server_config_rec *new =
      (env_server_config_rec *) palloc (p, sizeof(env_server_config_rec));
    new->vars = make_table (p, 50);
    new->unsetenv = "";
    new->vars_present = 0;
    return (void *) new;
}

void *merge_env_server_configs (pool *p, void *basev, void *addv)
{
    env_server_config_rec *base = (env_server_config_rec *)basev;
    env_server_config_rec *add = (env_server_config_rec *)addv;
    env_server_config_rec *new =
      (env_server_config_rec *)palloc (p, sizeof(env_server_config_rec));

    table *new_table;
    table_entry *elts;

    int i;
    const char *uenv, *unset;

      /* 
       * new_table = copy_table( p, base->vars );
       * foreach $element ( @add->vars ) {
       *     table_set( new_table, $element.key, $element.val );
       * };
       * foreach $unsetenv ( @UNSETENV ) {
       *     table_unset( new_table, $unsetenv );
       * }
       */

    new_table = copy_table( p, base->vars );

    elts = (table_entry *) add->vars->elts;

    for ( i = 0; i < add->vars->nelts; ++i ) {
	table_set( new_table, elts[i].key, elts[i].val ); 
    }

    unset = add->unsetenv;
    uenv = getword_conf( p, &unset );
    while ( uenv[0] != '\0' ) {
	table_unset( new_table, uenv );
	uenv = getword_conf( p, &unset );
    }

    new->vars = new_table;

    new->vars_present = base->vars_present || add->vars_present;

    return new;
}

const char *add_env_module_vars_passed (cmd_parms *cmd, char *struct_ptr,
				  const char *arg)
{
    env_server_config_rec *sconf =
      get_module_config (cmd->server->module_config, &env_module);
    table *vars = sconf->vars;
    char *env_var;
    char *name_ptr;

    while (*arg) {
        name_ptr = getword_conf (cmd->pool, &arg);
        env_var = getenv(name_ptr);
        if ( env_var != NULL ) { 
            sconf->vars_present = 1;
            table_set (vars, name_ptr, env_var);
        }
    }
    return NULL;
}

const char *add_env_module_vars_set (cmd_parms *cmd, char *struct_ptr,
				     const char *arg)
{
    env_server_config_rec *sconf =
      get_module_config (cmd->server->module_config, &env_module);
    table *vars = sconf->vars;
    char *name, *value;

    name = getword_conf( cmd->pool, &arg );
    value = getword_conf( cmd->pool, &arg );

    /* name is mandatory, value is optional.  no value means
     * set the variable to an empty string
     */


    if ( (*name == '\0') || (*arg != '\0')) {
	return "SetEnv takes one or two arguments.  An environment variable name and an optional value to pass to CGI." ;
    }

    sconf->vars_present = 1;
    table_set (vars, name, value);

    return NULL;
}

const char *add_env_module_vars_unset (cmd_parms *cmd, char *struct_ptr,
				       char *arg)
{
    env_server_config_rec *sconf =
      get_module_config (cmd->server->module_config, &env_module);
    sconf->unsetenv = sconf->unsetenv ? 
	pstrcat( cmd->pool, sconf->unsetenv, " ", arg, NULL ) : 
	pstrdup( cmd->pool, arg );
    return NULL;
}

command_rec env_module_cmds[] = {
{ "PassEnv", add_env_module_vars_passed, NULL,
    RSRC_CONF, RAW_ARGS, "a list of environment variables to pass to CGI." },
{ "SetEnv", add_env_module_vars_set, NULL,
    RSRC_CONF, RAW_ARGS, "an environment variable name and a value to pass to CGI." },
{ "UnsetEnv", add_env_module_vars_unset, NULL,
    RSRC_CONF, RAW_ARGS, "a list of variables to remove from the CGI environment." },
{ NULL },
};

int fixup_env_module(request_rec *r)
{
    table *e = r->subprocess_env;
    server_rec *s = r->server;
    env_server_config_rec *sconf = get_module_config (s->module_config,
						   &env_module);
    table *vars = sconf->vars;

    if ( !sconf->vars_present ) return DECLINED;

    r->subprocess_env = overlay_tables( r->pool, e, vars );

    return OK;  
}

module env_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   create_env_server_config,	/* server config */
   merge_env_server_configs,	/* merge server configs */
   env_module_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   fixup_env_module,		/* fixups */
   NULL,			/* logger */
   NULL				/* header parser */
};
