
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
 * A first stab at dynamic loading, using the GNU dld library
 * (or at least, an embarassingly old version of it...).
 */

#include "httpd.h"
#include "http_config.h"
#include "http_conf_globals.h"	/* server_argv0.  Sigh... */
#include <dld.h>

/*
 * The hard part of implementing LoadModule is deciding what to do about
 * rereading the config files.  This proof-of-concept implementation takes the 
 * cheap way out:  we only actually load the modules the first time through.
 */

static int been_there_done_that = 0; /* Loaded the modules yet? */
static int have_symbol_table = 0;

char *insure_dld_sane()
{
    int errcode;
    char *bin_name;
    
    if (have_symbol_table) return NULL;

    bin_name = dld_find_executable (server_argv0);
    
    if ((errcode = dld_init (bin_name))) {
	dld_perror (server_argv0);
	return "Cannot find server binary (needed for dynamic linking).";
    }

    have_symbol_table = 1;
    return NULL;
}

char *link_file (pool *p, char *filename)
{
    int errcode;
    
    filename = server_root_relative (p, filename);
    if ((errcode = dld_link (filename))) {
	dld_perror (server_argv0);
	return pstrcat (p, "Cannot load ", filename, " into server", NULL);
    }
    return NULL;
}

char *load_module (cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
    char *errname;
    module *modp;

    if (been_there_done_that) return NULL;
    
    if ((errname = insure_dld_sane())) return errname;
    if ((errname = link_file (cmd->pool, filename))) return errname;
    if (!(modp = (module *)dld_get_symbol (modname))) {
	return pstrcat (cmd->pool, "Can't find module ", modname,
			           " in file ", filename, NULL);
    }

    add_module (modp);

    /* Alethea Patch (rws,djw2) - need to run configuration functions
       in new modules */

    if (modp->create_server_config)
      ((void**)cmd->server->module_config)[modp->module_index]=
	(*modp->create_server_config)(cmd->pool, cmd->server);

    if (modp->create_dir_config)
      ((void**)cmd->server->lookup_defaults)[modp->module_index]=
	(*modp->create_dir_config)(cmd->pool, NULL);


    return NULL;
}

char *load_file (cmd_parms *cmd, void *dummy, char *filename)
{
    char *errname;
    
    if (been_there_done_that) return NULL;
    
    if ((errname = insure_dld_sane())) return errname;
    if ((errname = link_file (cmd->pool, filename))) return errname;
    return NULL;
}

void check_loaded_modules (server_rec *dummy, pool *p)
{
    if (been_there_done_that) return;

    if (dld_undefined_sym_count > 0) {
	/* Screwup.  Do the best we can to inform the user, and exit */
	char **bad_syms = dld_list_undefined_sym();
	int i;

	fprintf(stderr, "Dynamic linking error --- symbols left undefined.\n");
	fprintf(stderr, "(It may help to relink libraries).\n");
	fprintf(stderr, "Undefined symbols follow:\n");
	
	for (i = 0; i < dld_undefined_sym_count; ++i)
	    fprintf (stderr, "%s\n", bad_syms[i]);

	exit (1);
    }
    
    been_there_done_that = 1;
}

command_rec dld_cmds[] = {
{ "LoadModule", load_module, NULL, RSRC_CONF, TAKE2,
  "a module name, and the name of a file to load it from"},
{ "LoadFile", load_file, NULL, RSRC_CONF, ITERATE,
  "files or libraries to link into the server at runtime"},
{ NULL }
};

module dld_module = {
   STANDARD_MODULE_STUFF,
   check_loaded_modules,	/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   NULL,			/* server config */
   NULL,			/* merge server config */
   dld_cmds,			/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL				/* logger */
};
