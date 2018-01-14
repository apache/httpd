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
 * This module is used to load Apache modules at runtime. This means that the
 * server functionality can be extended without recompiling and even without
 * taking the server down at all. Only a HUP or AP_SIG_GRACEFUL signal
 * needs to be sent to the server to reload the dynamically loaded modules.
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
 * Apache to re-load the modules by sending it a HUP or AP_SIG_GRACEFUL
 * signal as normal.  You can use this to dynamically change the capability
 * of your server without bringing it down.
 *
 * Because currently there is only limited builtin support in the Configure
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

#include "apr.h"
#include "apr_dso.h"
#include "apr_strings.h"
#include "apr_errno.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"

#include "mod_so.h"

module AP_MODULE_DECLARE_DATA so_module;


/*
 * Server configuration to keep track of actually
 * loaded modules and the corresponding module name.
 */

typedef struct so_server_conf {
    apr_array_header_t *loaded_modules;
} so_server_conf;

static void *so_sconf_create(apr_pool_t *p, server_rec *s)
{
    so_server_conf *soc;

    soc = (so_server_conf *)apr_pcalloc(p, sizeof(so_server_conf));
    soc->loaded_modules = apr_array_make(p, DYNAMIC_MODULE_LIMIT,
                                     sizeof(ap_module_symbol_t));

    return (void *)soc;
}

#ifndef NO_DLOPEN

/*
 * This is the cleanup for a loaded shared object. It unloads the module.
 * This is called as a cleanup function from the core.
 */

static apr_status_t unload_module(void *data)
{
    ap_module_symbol_t *modi = (ap_module_symbol_t*)data;

    /* only unload if module information is still existing */
    if (modi->modp == NULL)
        return APR_SUCCESS;

    /* remove the module pointer from the core structure */
    ap_remove_loaded_module(modi->modp);

    /* destroy the module information */
    modi->modp = NULL;
    modi->name = NULL;
    return APR_SUCCESS;
}

static const char *dso_load(cmd_parms *cmd, apr_dso_handle_t **modhandlep,
                            const char *filename, const char **used_filename)
{
    int retry = 0;
    const char *fullname = ap_server_root_relative(cmd->temp_pool, filename);
    char my_error[256];
    if (filename != NULL && ap_strchr_c(filename, '/') == NULL) {
        /* retry on error without path to use dlopen()'s search path */
        retry = 1;
    }

    if (fullname == NULL && !retry) {
        return apr_psprintf(cmd->temp_pool, "Invalid %s path %s",
                            cmd->cmd->name, filename);
    }
    *used_filename = fullname;
    if (apr_dso_load(modhandlep, fullname, cmd->pool) == APR_SUCCESS) {
        return NULL;
    }
    if (retry) {
        *used_filename = filename;
        if (apr_dso_load(modhandlep, filename, cmd->pool) == APR_SUCCESS)
            return NULL;
    }

    return apr_pstrcat(cmd->temp_pool, "Cannot load ", filename,
                        " into server: ",
                        apr_dso_error(*modhandlep, my_error, sizeof(my_error)),
                        NULL);
}

/*
 * This is called for the directive LoadModule and actually loads
 * a shared object file into the address space of the server process.
 */

static const char *load_module(cmd_parms *cmd, void *dummy,
                               const char *modname, const char *filename)
{
    apr_dso_handle_t *modhandle;
    apr_dso_handle_sym_t modsym;
    module *modp;
    const char *module_file;
    so_server_conf *sconf;
    ap_module_symbol_t *modi;
    ap_module_symbol_t *modie;
    int i;
    const char *error;

    /* we need to setup this value for dummy to make sure that we don't try
     * to add a non-existent tree into the build when we return to
     * execute_now.
     */
    *(ap_directive_t **)dummy = NULL;

    /*
     * check for already existing module
     * If it already exists, we have nothing to do
     * Check both dynamically-loaded modules and statically-linked modules.
     */
    sconf = (so_server_conf *)ap_get_module_config(cmd->server->module_config,
                                                &so_module);
    modie = (ap_module_symbol_t *)sconf->loaded_modules->elts;
    for (i = 0; i < sconf->loaded_modules->nelts; i++) {
        modi = &modie[i];
        if (modi->name != NULL && strcmp(modi->name, modname) == 0) {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, cmd->pool, APLOGNO(01574)
                          "module %s is already loaded, skipping",
                          modname);
            return NULL;
        }
    }

    for (i = 0; ap_preloaded_modules[i]; i++) {
        const char *preload_name;
        apr_size_t preload_len;
        apr_size_t thismod_len;

        modp = ap_preloaded_modules[i];

        /* make sure we're comparing apples with apples
         * make sure name of preloaded module is mod_FOO.c
         * make sure name of structure being loaded is FOO_module
         */

        if (memcmp(modp->name, "mod_", 4)) {
            continue;
        }

        preload_name = modp->name + strlen("mod_");
        preload_len = strlen(preload_name) - 2;

        if (strlen(modname) <= strlen("_module")) {
            continue;
        }
        thismod_len = strlen(modname) - strlen("_module");
        if (strcmp(modname + thismod_len, "_module")) {
            continue;
        }

        if (thismod_len != preload_len) {
            continue;
        }

        if (!memcmp(modname, preload_name, preload_len)) {
            return apr_pstrcat(cmd->pool, "module ", modname,
                               " is built-in and can't be loaded",
                               NULL);
        }
    }

    modi = apr_array_push(sconf->loaded_modules);
    modi->name = modname;

    /*
     * Load the file into the Apache address space
     */
    error = dso_load(cmd, &modhandle, filename, &module_file);
    if (error)
        return error;
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, cmd->pool, APLOGNO(01575)
                 "loaded module %s from %s", modname, module_file);

    /*
     * Retrieve the pointer to the module structure through the module name:
     * First with the hidden variant (prefix `AP_') and then with the plain
     * symbol name.
     */
    if (apr_dso_sym(&modsym, modhandle, modname) != APR_SUCCESS) {
        char my_error[256];

        return apr_pstrcat(cmd->pool, "Can't locate API module structure `",
                          modname, "' in file ", module_file, ": ",
                          apr_dso_error(modhandle, my_error, sizeof(my_error)),
                          NULL);
    }
    modp = (module*) modsym;
    modp->dynamic_load_handle = (apr_dso_handle_t *)modhandle;
    modi->modp = modp;

    /*
     * Make sure the found module structure is really a module structure
     *
     */
    if (modp->magic != MODULE_MAGIC_COOKIE) {
        return apr_psprintf(cmd->pool, "API module structure '%s' in file %s "
                            "is garbled - expected signature %08lx but saw "
                            "%08lx - perhaps this is not an Apache module DSO, "
                            "or was compiled for a different Apache version?",
                            modname, module_file,
                            MODULE_MAGIC_COOKIE, modp->magic);
    }

    /*
     * Add this module to the Apache core structures
     */
    error = ap_add_loaded_module(modp, cmd->pool, modname);
    if (error) {
        return error;
    }

    /*
     * Register a cleanup in the config apr_pool_t (normally pconf). When
     * we do a restart (or shutdown) this cleanup will cause the
     * shared object to be unloaded.
     */
    apr_pool_cleanup_register(cmd->pool, modi, unload_module, apr_pool_cleanup_null);

    /*
     * Finally we need to run the configuration process for the module
     */
    ap_single_module_configure(cmd->pool, cmd->server, modp);

    return NULL;
}

/*
 * This implements the LoadFile directive and loads an arbitrary
 * shared object file into the address space of the server process.
 */

static const char *load_file(cmd_parms *cmd, void *dummy, const char *filename)
{
    apr_dso_handle_t *handle;
    const char *used_file, *error;

    error = dso_load(cmd, &handle, filename, &used_file);
    if (error)
        return error;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(01576)
                 "loaded file %s", used_file);

    return NULL;
}

static module *ap_find_loaded_module_symbol(server_rec *s, const char *modname)
{
    so_server_conf *sconf;
    ap_module_symbol_t *modi;
    ap_module_symbol_t *modie;
    int i;

    sconf = (so_server_conf *)ap_get_module_config(s->module_config,
                                                   &so_module);
    modie = (ap_module_symbol_t *)sconf->loaded_modules->elts;

    for (i = 0; i < sconf->loaded_modules->nelts; i++) {
        modi = &modie[i];
        if (modi->name != NULL && strcmp(modi->name, modname) == 0) {
            return modi->modp;
        }
    }
    return NULL;
}

static void dump_loaded_modules(apr_pool_t *p, server_rec *s)
{
    ap_module_symbol_t *modie;
    ap_module_symbol_t *modi;
    so_server_conf *sconf;
    int i;
    apr_file_t *out = NULL;

    if (!ap_exists_config_define("DUMP_MODULES")) {
        return;
    }

    apr_file_open_stdout(&out, p);

    apr_file_printf(out, "Loaded Modules:\n");

    sconf = (so_server_conf *)ap_get_module_config(s->module_config,
                                                   &so_module);
    for (i = 0; ; i++) {
        modi = &ap_prelinked_module_symbols[i];
        if (modi->name != NULL) {
            apr_file_printf(out, " %s (static)\n", modi->name);
        }
        else {
            break;
        }
    }

    modie = (ap_module_symbol_t *)sconf->loaded_modules->elts;
    for (i = 0; i < sconf->loaded_modules->nelts; i++) {
        modi = &modie[i];
        if (modi->name != NULL) {
            apr_file_printf(out, " %s (shared)\n", modi->name);
        }
    }
}

#else /* not NO_DLOPEN */

static const char *load_file(cmd_parms *cmd, void *dummy, const char *filename)
{
    ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, cmd->pool, APLOGNO(01577)
                 "WARNING: LoadFile not supported on this platform");
    return NULL;
}

static const char *load_module(cmd_parms *cmd, void *dummy,
                               const char *modname, const char *filename)
{
    ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, cmd->pool, APLOGNO(01578)
                 "WARNING: LoadModule not supported on this platform");
    return NULL;
}

#endif /* NO_DLOPEN */

static void register_hooks(apr_pool_t *p)
{
#ifndef NO_DLOPEN
    APR_REGISTER_OPTIONAL_FN(ap_find_loaded_module_symbol);
    ap_hook_test_config(dump_loaded_modules, NULL, NULL, APR_HOOK_MIDDLE);
#endif
}

static const command_rec so_cmds[] = {
    AP_INIT_TAKE2("LoadModule", load_module, NULL, RSRC_CONF | EXEC_ON_READ,
      "a module name and the name of a shared object file to load it from"),
    AP_INIT_ITERATE("LoadFile", load_file, NULL, RSRC_CONF  | EXEC_ON_READ,
      "shared object file or library to load into the server at runtime"),
    { NULL }
};

AP_DECLARE_MODULE(so) = {
   STANDARD20_MODULE_STUFF,
   NULL,                 /* create per-dir config */
   NULL,                 /* merge per-dir config */
   so_sconf_create,      /* server config */
   NULL,                 /* merge server config */
   so_cmds,              /* command apr_table_t */
   register_hooks        /* register hooks */
};
