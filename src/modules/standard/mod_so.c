/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
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
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/* 
 * This module is used to load Apache modules at runtime. This means that the
 * server functionality can be extended without recompiling and even without
 * taking the server down at all. Only a HUP or USR1 signal needs to be send
 * to the server to reload the dynamically loaded modules.
 *
 * To use, you'll first need to build your module as a shared library, then
 * update your configuration (httpd.conf) to get the Apache core to load the
 * module at start-up.
 *
 * The easiest way to build a module as a shared library is to use the
 * `SharedModule' command in the Configuration file, instead of `AddModule'.
 * You should also change the file extension from `.o' to `.so'. So, for
 * example, to build the status module as a shared library edit Configuration
 * and change
 *   AddModule    modules/standard/mod_status.o
 * to
 *   SharedModule modules/standard/mod_status.so
 *
 * Run Configure and make. Now Apache's httpd binary will _not_ include
 * mod_status. Instead a shared object called mod_status.so will be build, in
 * the modules/standard directory. You can build most of the modules as shared
 * libraries like this.
 *
 * To use the shared module, move the .so file(s) into an appropriate
 * directory. You might like to create a directory called "modules" under you
 * server root for this (e.g. /usr/local/httpd/modules). 
 *
 * Then edit your conf/httpd.conf file, and add LoadModule lines. For
 * example
 *   LoadModule  status_module   modules/mod_status.so
 *
 * The first argument is the module's structure name (look at the end of the
 * module source to find this). The second option is the path to the module
 * file, relative to the server root.  Put these directives right at the top
 * of your httpd.conf file.
 *
 * Now you can start Apache. A message will be logged at "debug" level to your
 * error_log to confirm that the module(s) are loaded (use "LogLevel debug"
 * directive to get these log messages).
 *
 * If you edit the LoadModule directives while the server is live you can get
 * Apache to re-load the modules by sending it a HUP or USR1 signal as normal.
 * You can use this to dynamically change the capability of your server
 * without bringing it down.
 *
 * Because currently there is only limited built-in support in the Configure
 * script for creating the shared library files (`.so'), please consult your
 * vendors cc(1), ld(1) and dlopen(3) manpages to find out the appropriate
 * compiler and linker flags and insert them manually into the Configuration
 * file under CFLAGS_SHLIB, LDFLAGS_SHLIB and LDFLAGS_SHLIB_EXPORT.
 *
 * If you still have problems figuring out the flags both try the paper
 *     http://developer.netscape.com/library/documentation/enterprise
 *                                          /unix/svrplug.htm#1013807
 * or install a Perl 5 interpreter on your platform and then run the command
 *
 *     $ perl -V:usedl -V:ccdlflags -V:cccdlflags -V:lddlflags
 *
 * This gives you what type of dynamic loading Perl 5 uses on your platform
 * and which compiler and linker flags Perl 5 uses to create the shared object
 * files.
 *
 * Another location where you can find useful hints is the `ltconfig' script
 * of the GNU libtool 1.2 package. Search for your platform name inside the
 * various "case" constructs.
 *
 */


#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

module MODULE_VAR_EXPORT so_module;


/*
 * Server configuration to keep track of actually
 * loaded modules and the corresponding module name.
 */

typedef struct moduleinfo {
    char *name;
    module *modp;
} moduleinfo;

typedef struct so_server_conf {
    array_header *loaded_modules;
} so_server_conf;

static void *so_sconf_create(pool *p, server_rec *s)
{
    so_server_conf *soc;

    soc = (so_server_conf *)ap_pcalloc(p, sizeof(so_server_conf));
    soc->loaded_modules = ap_make_array(p, DYNAMIC_MODULE_LIMIT, 
                                     sizeof(moduleinfo));
#ifndef NO_DLOPEN
    ap_os_dso_init();
#endif

    return (void *)soc;
}

#ifndef NO_DLOPEN

/*
 * This is the cleanup for a loaded shared object. It unloads the module.
 * This is called as a cleanup function from the core.
 */

static void unload_module(moduleinfo *modi)
{
    /* only unload if module information is still existing */
    if (modi->modp == NULL)
        return;

    /* remove the module pointer from the core structure */
    ap_remove_loaded_module(modi->modp);

    /* unload the module space itself */
#ifdef NETWARE
    ap_os_dso_unsym((ap_os_dso_handle_t)modi->modp->dynamic_load_handle, modi->name);
#endif
    ap_os_dso_unload((ap_os_dso_handle_t)modi->modp->dynamic_load_handle);

    /* destroy the module information */
    modi->modp = NULL;
    modi->name = NULL;
}

/* 
 * This is the cleanup routine for files loaded by
 * load_file(). Unfortunately we don't keep a record of the filename
 * that was loaded, so we can't report the unload for debug purposes
 * or include the filename in error message.
 */

static void unload_file(void *handle)
{
    ap_os_dso_unload((ap_os_dso_handle_t)handle);
}

/* 
 * This is called for the directive LoadModule and actually loads
 * a shared object file into the address space of the server process.
 */

static const char *load_module(cmd_parms *cmd, void *dummy, 
                               char *modname, char *filename)
{
    ap_os_dso_handle_t modhandle;
    module *modp;
    const char *szModuleFile=ap_server_root_relative(cmd->pool, filename);
    so_server_conf *sconf;
    moduleinfo *modi;
    moduleinfo *modie;
    int i;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    
    /* 
     * check for already existing module
     * If it already exists, we have nothing to do 
     */
    sconf = (so_server_conf *)ap_get_module_config(cmd->server->module_config, 
	                                        &so_module);
    modie = (moduleinfo *)sconf->loaded_modules->elts;
    for (i = 0; i < sconf->loaded_modules->nelts; i++) {
        modi = &modie[i];
        if (modi->name != NULL && strcmp(modi->name, modname) == 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, cmd->server,
                          "module %s is already loaded, skipping", modname);
            return NULL;
        }
    }
    modi = ap_push_array(sconf->loaded_modules);
    modi->name = modname;

    /*
     * Load the file into the Apache address space
     */
    if (!(modhandle = ap_os_dso_load(szModuleFile))) {
	const char *my_error = ap_os_dso_error();
	return ap_pstrcat (cmd->pool, "Cannot load ", szModuleFile,
			" into server: ", 
			my_error ? my_error : "(reason unknown)",
			NULL);
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL,
		"loaded module %s", modname);

    /*
     * Retrieve the pointer to the module structure through the module name:
     * First with the hidden variant (prefix `AP_') and then with the plain
     * symbol name.
     */
    if (!(modp = (module *)(ap_os_dso_sym(modhandle, modname)))) {
	return ap_pstrcat(cmd->pool, "Can't locate API module structure `", modname,
		       "' in file ", szModuleFile, ": ", ap_os_dso_error(), NULL);
    }
    modi->modp = modp;
    modp->dynamic_load_handle = (void *)modhandle;

    /* 
     * Make sure the found module structure is really a module structure
     * 
     */
    if (modp->magic != MODULE_MAGIC_COOKIE) {
        return ap_pstrcat(cmd->pool, "API module structure `", modname,
                          "' in file ", szModuleFile, " is garbled -"
                          " perhaps this is not an Apache module DSO?", NULL);
    }

    /* 
     * Add this module to the Apache core structures
     */
    ap_add_loaded_module(modp);

    /* 
     * Register a cleanup in the config pool (normally pconf). When
     * we do a restart (or shutdown) this cleanup will cause the
     * shared object to be unloaded.
     */
    ap_register_cleanup(cmd->pool, modi, 
		     (void (*)(void*))unload_module, ap_null_cleanup);

    /* 
     * Finally we need to run the configuration process for the module
     */
    ap_single_module_configure(cmd->pool, cmd->server, modp);

    return NULL;
}

/* 
 * This implements the LoadFile directive and loads an arbitrary
 * shared object file into the adress space of the server process.
 */

static const char *load_file(cmd_parms *cmd, void *dummy, char *filename)
{
    ap_os_dso_handle_t handle;
    char *file;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    
    file = ap_server_root_relative(cmd->pool, filename);
    
    if (!(handle = ap_os_dso_load(file))) {
	const char *my_error = ap_os_dso_error();
	return ap_pstrcat (cmd->pool, "Cannot load ", filename, 
			" into server:", 
			my_error ? my_error : "(reason unknown)",
			NULL);
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, NULL,
		"loaded file %s", filename);

    ap_register_cleanup(cmd->pool, (void *)handle, unload_file, ap_null_cleanup);

    return NULL;
}

#else /* not NO_DLOPEN */

static const char *load_file(cmd_parms *cmd, void *dummy, char *filename)
{
    fprintf(stderr, "WARNING: LoadFile not supported on this platform\n");
    return NULL;
}

static const char *load_module(cmd_parms *cmd, void *dummy, 
	                       char *modname, char *filename)
{
    fprintf(stderr, "WARNING: LoadModule not supported on this platform\n");
    return NULL;
}

#endif /* NO_DLOPEN */

static const command_rec so_cmds[] = {
    { "LoadModule", load_module, NULL, RSRC_CONF, TAKE2,
      "a module name and the name of a shared object file to load it from"},
    { "LoadFile", load_file, NULL, RSRC_CONF, ITERATE,
      "shared object file or library to load into the server at runtime"},
    { NULL }
};

module MODULE_VAR_EXPORT so_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   NULL,			/* create per-dir config */
   NULL,			/* merge per-dir config */
   so_sconf_create,		/* server config */
   NULL,			/* merge server config */
   so_cmds,			/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixer_upper */
   NULL,			/* logger */
   NULL,			/* header parser */
   NULL,			/* child_init */
   NULL,			/* child_exit */
   NULL				/* post read-request */
};
