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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
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

/* How to create .so files on various platforms:

   FreeBSD:
      "gcc -fpic" to compile
      "ld -Bshareable" to link

   See for instructions on more platforms:
http://developer.netscape.com/library/documentation/enterprise/unix/svrplug.htm#1013807

*/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

     /* Os-specific stuff that goes in conf.h */

#if defined(LINUX) || defined(__FreeBSD__) || defined(SOLARIS) || \
    defined(__bsdi__) || defined(IRIX)
#define HAS_DLFCN
#endif

#if defined(__FreeBSD__)
#define NEED_RTLD_LAZY
#define NEED_UNDERSCORE_SYM
#endif

     /* OSes that don't support dlopen */
#if defined(UW) || defined(ULTRIX)
#define NO_DL
#endif

     /* Start of real module */
#ifdef HAS_DLFCN
#include <dlfcn.h>
#else
#define NEED_RTLD_LAZY
void * dlopen (__const char * __filename, int __flag);
__const char * dlerror (void);
void * dlsym (void *, __const char *);
int dlclose (void *);
#endif

#ifdef NEED_RTLD_LAZY
#define RTLD_LAZY 1
#endif

/*
 * The hard part of implementing LoadModule is deciding what to do about
 * rereading the config files.  This proof-of-concept implementation takes the 
 * cheap way out:  we only actually load the modules the first time through.
 */

static int been_there_done_that = 0; /* Loaded the modules yet? */
static int have_symbol_table = 0;

#ifndef NO_DLOPEN
static const char *load_module (cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
    void *modhandle;
    module *modp;
    const char *szModuleFile=server_root_relative(cmd->pool, filename);

    if (been_there_done_that) return NULL;
    
    if (!(modhandle = dlopen(szModuleFile, RTLD_NOW)))
      {
	const char *my_error = dlerror();
	return pstrcat (cmd->pool, "Cannot load ", szModuleFile,
			" into server: ", my_error, ":",  dlerror(),
			NULL);
      }
 
    /* If I knew what the correct cast is here, I'd be happy. But 
     * I don't. So I'll use (void *). It works.
     */

    aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL,
		"loaded module %s", modname);

#ifdef NEED_UNDERSCORE_SYM
    modname = pstrcat(cmd->pool, "_", modname, NULL);
#endif

    if (!(modp = (module *)(dlsym (modhandle, modname)))) {
	return pstrcat (cmd->pool, "Can't find module ", modname,
			" in file ", filename, ":", dlerror(), NULL);
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

static const char *load_file (cmd_parms *cmd, void *dummy, char *filename)
{
   if (been_there_done_that) return NULL;
    
	if (!dlopen(server_root_relative(cmd->pool, filename), 1))
		return pstrcat (cmd->pool, "Cannot load ", filename, " into server", NULL);
 
	return NULL;
}
#else
static const char *load_file(cmd_parms *cmd, void *dummy, char *filename)
{
  if(!been_there_done_that)
    fprintf(stderr, "WARNING: LoadFile not supported\n");
  return NULL;
}

static const char *load_module(cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
  if(!been_there_done_that)
    fprintf(stderr, "WARNING: LoadModule not supported\n");
  return NULL;
}
#endif

static void check_loaded_modules (server_rec *dummy, pool *p)
{
    if (been_there_done_that) return;

    been_there_done_that = 1;
}

command_rec so_cmds[] = {
{ "LoadModule", load_module, NULL, RSRC_CONF, TAKE2,
  "a module name, and the name of a file to load it from"},
{ "LoadFile", load_file, NULL, RSRC_CONF, ITERATE,
  "files or libraries to link into the server at runtime"},
{ NULL }
};

module so_module = {
   STANDARD_MODULE_STUFF,
   check_loaded_modules,	/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   NULL,			/* server config */
   NULL,			/* merge server config */
   so_cmds,			/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* logger */
   NULL				/* header parser */
};


