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
 * mod_dll.c - DLL module loader for Windows
 * by Alexei Kosut, based on mod_dld.c by rst
 *
 * This module loads another module into the server that has been
 * compiled as a DLL. It doesn't work perfectly, but well enough.
 *
 * To use, compile the module into a DLL. Then add the following to the
 * server's config file (before any directives belonging to the loaded module):
 *
 * LoadModule module_name mod_name.dll
 *
 * module_name should be the name of the module (e.g. includes_module),
 * and mod_name.dll should be the name of the DLL, relative to the server
 * root.
 *
 * There is also a directive that will load a non-module DLL, if you'd
 * like to load additional libraries into the server:
 *
 * LoadFile filename.dll
 *
 * Compiling a module as a DLL (using Microsoft Visual C++):
 *
 * 1. Add the following to the module source file's module record
 *    definition: MODULE_VAR_EXPORT. i.e. if you have
 *    "module foo_module;", replace it with
 *    "module MODULE_VAR_EXPORT foo_module;". If your module is to be
 *    compiled with both Windows and Unix, you may wish to use an #ifdef
 *    WIN32
 *
 *    Note that your module should still work just fine compiled-in
 *    with this code bit there. It only activates when using the module
 *    as a DLL.
 *
 * 2. Create a DLL file with just the module source file (and any associated
 *    files). Be sure to link it against the ApacheCore.lib created when
 *    compiling ApacheCore.dll. You may also have to tweak the settings to
 *    find all of the Apache includes files correctly. After creating the
 *    DLL, follow the above instructions to load it into Apache.
 */

#include "httpd.h"
#include "http_config.h"

/*
 * The hard part of implementing LoadModule is deciding what to do about
 * rereading the config files.  This proof-of-concept implementation takes the 
 * cheap way out:  we only actually load the modules the first time through.
 */

static int been_there_done_that = 0; /* Loaded the modules yet? */
static int have_symbol_table = 0;

char *load_module (cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
    HINSTANCE modhandle;
    module *modp;
    const char *szModuleFile=ap_server_root_relative(cmd->pool, filename);

    if (been_there_done_that) return NULL;
    
    if (!(modhandle = LoadLibraryEx(szModuleFile, NULL,
				    LOAD_WITH_ALTERED_SEARCH_PATH)))
	return ap_pstrcat (cmd->pool, "Cannot load ", szModuleFile, " into server",
			NULL);
 
    /* If I knew what the correct cast is here, I'd be happy. But 
     * I don't. So I'll use (void *). It works.
     */
    if (!(modp = (module *)(GetProcAddress (modhandle, modname)))) {
	return ap_pstrcat (cmd->pool, "Can't find module ", modname,
			" in file ", filename, NULL);
    }
	
    ap_add_module (modp);

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
   if (been_there_done_that) return NULL;
    
	if (!LoadLibrary(ap_server_root_relative(cmd->pool, filename)))
		return ap_pstrcat (cmd->pool, "Cannot load ", filename, " into server", NULL);
 
	return NULL;
}

void check_loaded_modules (server_rec *dummy, pool *p)
{
    if (been_there_done_that) return;

    been_there_done_that = 1;
}

command_rec dll_cmds[] = {
{ "LoadModule", load_module, NULL, RSRC_CONF, TAKE2,
  "a module name, and the name of a file to load it from"},
{ "LoadFile", load_file, NULL, RSRC_CONF, ITERATE,
  "files or libraries to link into the server at runtime"},
{ NULL }
};

module dll_module = {
   STANDARD_MODULE_STUFF,
   check_loaded_modules,	/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   NULL,			/* server config */
   NULL,			/* merge server config */
   dll_cmds,			/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* logger */
   NULL				/* header parser */
};
