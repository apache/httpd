/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
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

/* 
 * This module is used to load Apache modules at runtime. This means
 * that the server functionality can be extended without recompiling
 * and even without taking the server down at all!
 *
 * To use, you'll first need to build your module as a shared library, then
 * update your configuration (httpd.conf) to get the Apache core to
 * load the module at start-up.
 *
 * The easiest way to build a module as a shared library is to use the
 * "SharedModule" command in the Configuration file, instead of AddModule.
 * You should also change the file extension from .o to .so. So, for example,
 * to build the status module as a shared library edit Configuration
 * and change
 *   AddModule    modules/standard/mod_status.o
 * to
 *   SharedModule modules/standard/mod_status.so
 *
 * Run Configure and make. Now Apache's httpd will _not_ include
 * mod_status. Instead a shared library called mod_status.so will be
 * build, in the modules/standard directory. You can build any or all
 * modules as shared libraries like this.
 *
 * To use the shared module, move the .so file(s) into an appropriate
 * directory. You might like to create a directory called "modules" under
 * you server root for this (e.g. /usr/local/httpd/modules). 
 *
 * Then edit your conf/httpd.conf file, and add LoadModule lines. For
 * example
 *   LoadModule  status_module   modules/mod_status.so
 *
 * The first argument is the module's structure name (look at the
 * end of the module source to find this). The second option is
 * the path to the module file, relative to the server root.
 * Put these directives right at the top of your httpd.conf file.
 *
 * Now you can start Apache. A message will be logged at "debug" level
 * to your error_log to confirm that the module(s) are loaded (use
 * "LogLevel debug" directive to get these log messages).
 *
 * If you edit the LoadModule directives while the server is live you
 * can get Apache to re-load the modules by sending it a HUP or USR1
 * signal as normal. You can use this to dynamically change the 
 * capability of your server without bringing it down.
 *
 * Apache's Configure currently only creates shared modules on
 * Linux 2 and FreeBSD systems. 
 */

/* More details about shared libraries:
 *
 * How to create .so files on various platforms:

   FreeBSD:
      "gcc -fpic" to compile
      "ld -Bshareable" to link

   See for instructions on more platforms:
http://developer.netscape.com/library/documentation/enterprise/unix/svrplug.htm#1013807

*/

/*
 * Module definition information used by Configure
 *
 * MODULE-DEFINITION-START
 * Name: so_module
 * ConfigStart
    if ./helpers/TestCompile func dlopen; then
	:
    else
        DL_LIB=""
        if ./helpers/TestCompile lib dl; then
	    DL_LIB="-ldl"
        fi
        LIBS="$LIBS $DL_LIB"
        if [ "X$DL_LIB" != "X" ]; then
 	    echo " + using $DL_LIB for dynamic loading (mod_so)"
        fi
    fi
 * ConfigEnd
 * MODULE-DEFINITION-END
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#ifndef NO_DLOPEN

/* This is the cleanup for a loaded DLL. It unloads the module.
 * This is called as a cleanup function.
 */

void unload_module(module *modp)
{
    char mod_name[50];		/* Um, no pool, so make this static */

    /* Take a copy of the module name so we can report that it has been
     * unloaded (since modp itself will have been unloaded). */
    strncpy(mod_name, modp->name, 49);
    mod_name[49] = '\0';

    remove_module(modp);

    /* The Linux manpage doesn't give any way to check the success of
     * dlclose() */
    os_dl_unload((os_dl_module_handle_type)modp->dynamic_load_handle);

    aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL,
		"unloaded module %s", mod_name);
}

/* unload_file is the cleanup routine for files loaded by
 * load_file(). Unfortunately we don't keep a record of the filename
 * that was loaded, so we can't report the unload for debug purposes
 * or include the filename in error message.
 */

void unload_file(void *handle)
{
    /* The Linux manpage doesn't give any way to check the success of
     * dlclose() */
    os_dl_unload((os_dl_module_handle_type)handle);
}

#ifdef WIN32
/* This is a cleanup which does nothing. On Win32 using the API-provided
 * null_cleanup() function gives a "pointers to functions 
 * with different attributes" error during compilation.
 */
void mod_so_null_cleanup(module *modp)
{
    /* This function left intentionally blank */
}
#else
# define mod_so_null_cleanup null_cleanup
#endif

/* load_module is called for the directive LoadModule 
 */

static const char *load_module (cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
    void *modhandle;
    module *modp;
    const char *szModuleFile=server_root_relative(cmd->pool, filename);

    if (!(modhandle = os_dl_load(szModuleFile)))
      {
	const char *my_error = os_dl_error();
	return pstrcat (cmd->pool, "Cannot load ", szModuleFile,
			" into server: ", 
			my_error ? my_error : "(reason unknown)",
			NULL);
      }
 
    aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL,
		"loaded module %s", modname);

#ifdef NEED_UNDERSCORE_SYM
    modname = pstrcat(cmd->pool, "_", modname, NULL);
#endif

    if (!(modp = (module *)(os_dl_sym (modhandle, modname)))) {
	return pstrcat (cmd->pool, "Can't find module ", modname,
			" in file ", filename, ":", os_dl_error(), NULL);
    }
	
    modp->dynamic_load_handle = modhandle;

    add_module(modp);

    /* Register a cleanup in the config pool (normally pconf). When
     * we do a restart (or shutdown) this cleanup will cause the
     * DLL to be unloaded.
     */
    register_cleanup(cmd->pool, modp, 
		     (void (*)(void*))unload_module, mod_so_null_cleanup);

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

/* load_file implements the LoadFile directive.
 */

static const char *load_file (cmd_parms *cmd, void *dummy, char *filename)
{
    void *handle;
    char *file;

    file = server_root_relative(cmd->pool, filename);
    
    if (!(handle = os_dl_load(file))) {
	const char *my_error = os_dl_error();
	return pstrcat (cmd->pool, "Cannot load ", filename, 
			" into server:", 
			my_error ? my_error : "(reason unknown)",
			NULL);
    }
    
    aplog_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL,
		"loaded file %s", filename);

    register_cleanup(cmd->pool, handle, unload_file, mod_so_null_cleanup);

    return NULL;
}
#else
static const char *load_file(cmd_parms *cmd, void *dummy, char *filename)
{
  fprintf(stderr, "WARNING: LoadFile not supported\n");
  return NULL;
}

static const char *load_module(cmd_parms *cmd, void *dummy, char *modname, char *filename)
{
  fprintf(stderr, "WARNING: LoadModule not supported\n");
  return NULL;
}
#endif

command_rec so_cmds[] = {
{ "LoadModule", load_module, NULL, RSRC_CONF, TAKE2,
  "a module name, and the name of a file to load it from"},
{ "LoadFile", load_file, NULL, RSRC_CONF, ITERATE,
  "files or libraries to link into the server at runtime"},
{ NULL }
};

module so_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
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
   NULL,			/* header parser */
   NULL,			/* child_init */
   NULL,			/* child_exit */
   NULL				/* post read-request */
};
