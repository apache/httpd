/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#ifndef APACHE_HTTP_CONFIG_H
#define APACHE_HTTP_CONFIG_H

#include "ap_hooks.h"
#include "util_cfgtree.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package Apache Configuration
 */

/*
 * The central data structures around here...
 */

/* Command dispatch structures... */

/**
 * How the directives arguments should be parsed.
 * @tip Note that for all of these except RAW_ARGS, the config routine is
 *      passed a freshly allocated string which can be modified or stored
 *      or whatever... it's only necessary to do pstrdup() stuff with
 * <PRE>
 *    RAW_ARGS	--		 cmd_func parses command line itself 
 *    TAKE1	--		 one argument only 
 *    TAKE2	--		 two arguments only 
 *    ITERATE	--		 one argument, occuring multiple times
 *				 * (e.g., IndexIgnore)
 *    ITERATE2	--		 two arguments, 2nd occurs multiple times
 *				 * (e.g., AddIcon)
 *    FLAG	--		 One of 'On' or 'Off' 
 *    NO_ARGS	--		 No args at all, e.g. </Directory> 
 *    TAKE12	--		 one or two arguments 
 *    TAKE3	--		 three arguments only 
 *    TAKE23	--		 two or three arguments
 *    TAKE123	--		 one, two or three arguments 
 *    TAKE13	--		 one or three arguments 
 * </PRE>
 * @defvar enum cmd_how
 */
enum cmd_how {
    RAW_ARGS,			/* cmd_func parses command line itself */
    TAKE1,			/* one argument only */
    TAKE2,			/* two arguments only */
    ITERATE,			/* one argument, occuring multiple times
				 * (e.g., IndexIgnore)
				 */
    ITERATE2,			/* two arguments, 2nd occurs multiple times
				 * (e.g., AddIcon)
				 */
    FLAG,			/* One of 'On' or 'Off' */
    NO_ARGS,			/* No args at all, e.g. </Directory> */
    TAKE12,			/* one or two arguments */
    TAKE3,			/* three arguments only */
    TAKE23,			/* two or three arguments */
    TAKE123,			/* one, two or three arguments */
    TAKE13			/* one or three arguments */
};

typedef struct cmd_parms_struct cmd_parms;

#ifdef AP_DEBUG

typedef union {
    const char *(*no_args) (cmd_parms *parms, void *mconfig);
    const char *(*raw_args) (cmd_parms *parms, void *mconfig,
			     const char *args);
    const char *(*take1) (cmd_parms *parms, void *mconfig, const char *w);
    const char *(*take2) (cmd_parms *parms, void *mconfig, const char *w,
			  const char *w2);
    const char *(*take3) (cmd_parms *parms, void *mconfig, const char *w,
			  const char *w2, const char *w3);
    const char *(*flag) (cmd_parms *parms, void *mconfig, int on);
} cmd_func;

# define AP_NO_ARGS	func.no_args
# define AP_RAW_ARGS	func.raw_args
# define AP_TAKE1	func.take1
# define AP_TAKE2	func.take2
# define AP_TAKE3	func.take3
# define AP_FLAG	func.flag

# define AP_INIT_NO_ARGS(directive, func, mconfig, where, help) \
    { directive, { .no_args=func }, mconfig, where, RAW_ARGS, help }
# define AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) \
    { directive, { .raw_args=func }, mconfig, where, RAW_ARGS, help }
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, { .take1=func }, mconfig, where, TAKE1, help }
# define AP_INIT_ITERATE(directive, func, mconfig, where, help) \
    { directive, { .take1=func }, mconfig, where, ITERATE, help }
# define AP_INIT_TAKE2(directive, func, mconfig, where, help) \
    { directive, { .take2=func }, mconfig, where, TAKE2, help }
# define AP_INIT_TAKE12(directive, func, mconfig, where, help) \
    { directive, { .take2=func }, mconfig, where, TAKE12, help }
# define AP_INIT_ITERATE2(directive, func, mconfig, where, help) \
    { directive, { .take2=func }, mconfig, where, ITERATE2, help }
# define AP_INIT_TAKE23(directive, func, mconfig, where, help) \
    { directive, { .take3=func }, mconfig, where, TAKE23, help }
# define AP_INIT_TAKE3(directive, func, mconfig, where, help) \
    { directive, { .take3=func }, mconfig, where, TAKE3, help }
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, { .flag=func }, mconfig, where, FLAG, help }

#else

typedef const char *(*cmd_func) ();

# define AP_NO_ARGS  func
# define AP_RAW_ARGS func
# define AP_TAKE1    func
# define AP_TAKE2    func
# define AP_TAKE3    func
# define AP_FLAG     func

# define AP_INIT_NO_ARGS(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, RAW_ARGS, help }
# define AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, RAW_ARGS, help }
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE1, help }
# define AP_INIT_ITERATE(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, ITERATE, help }
# define AP_INIT_TAKE2(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE2, help }
# define AP_INIT_TAKE12(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE12, help }
# define AP_INIT_ITERATE2(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, ITERATE2, help }
# define AP_INIT_TAKE23(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE23, help }
# define AP_INIT_TAKE3(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE3, help }
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, FLAG, help }

#endif

typedef struct command_struct command_rec; 
/**
 * The command record structure.  Each modules can define a table of these
 * to define the directives it will implement.
 */
struct command_struct {
    /** Name of this command */
    const char *name;
    /** The function to be called when this directive is parsed */
    cmd_func func;
    /** Extra data, for functions which implement multiple commands... */
    void *cmd_data;		
    /** What overrides need to be allowed to enable this command. */
    int req_override;
    /** What the command expects as arguments 
     *  @defvar cmd_how args_how*/
    enum cmd_how args_how;

    /** 'usage' message, in case of syntax errors */
    const char *errmsg;
};

/* The allowed locations for a configuration directive are the union of
 * those indicated by each set bit in the req_override mask.
 *
 * (req_override & RSRC_CONF)   => *.conf outside <Directory> or <Location>
 * (req_override & ACCESS_CONF) => *.conf inside <Directory> or <Location>
 * (req_override & OR_AUTHCFG)  => *.conf inside <Directory> or <Location>
 *                                 and .htaccess when AllowOverride AuthConfig
 * (req_override & OR_LIMIT)    => *.conf inside <Directory> or <Location>
 *                                 and .htaccess when AllowOverride Limit
 * (req_override & OR_OPTIONS)  => *.conf anywhere
 *                                 and .htaccess when AllowOverride Options
 * (req_override & OR_FILEINFO) => *.conf anywhere
 *                                 and .htaccess when AllowOverride FileInfo
 * (req_override & OR_INDEXES)  => *.conf anywhere
 *                                 and .htaccess when AllowOverride Indexes
 */
#define OR_NONE 0
#define OR_LIMIT 1
#define OR_OPTIONS 2
#define OR_FILEINFO 4
#define OR_AUTHCFG 8
#define OR_INDEXES 16
#define OR_UNSET 32
#define ACCESS_CONF 64
#define RSRC_CONF 128
#define EXEC_ON_READ 256
#define OR_ALL (OR_LIMIT|OR_OPTIONS|OR_FILEINFO|OR_AUTHCFG|OR_INDEXES)

/**
 * This can be returned by a function if they don't wish to handle
 * a command. Make it something not likely someone will actually use
 * as an error code.
 * @defvar DECLINE_CMD "\a\b"
 */
#define DECLINE_CMD "\a\b"

typedef struct configfile_t configfile_t;
/** Common structure for reading of config files / passwd files etc. */
struct configfile_t {
    /** a getc()-like function
     *  @deffunc int getch(void *param) */
    int (*getch) (void *param);	
    /** a fgets()-like function 
     *  @deffunc void *getstr(void *buf, size_t bufsize, void *param)*/
    void *(*getstr) (void *buf, size_t bufsiz, void *param);
    /** a close hander function 
     *  @deffunc int close(void *param)*/
    int (*close) (void *param);	
    /** the argument passed to getch/getstr/close */
    void *param;
    /** the filename / description */
    const char *name;
    /** current line number, starting at 1 */
    unsigned line_number;
};

/**
 * This structure is passed to a command which is being invoked,
 * to carry a large variety of miscellaneous data which is all of
 * use to *somebody*...
 */
struct cmd_parms_struct
    {
    /** Argument to command from cmd_table */
    void *info;
    /** Which allow-override bits are set */
    int override;
    /** Which methods are <Limit>ed */
    int limited;

    /** Config file structure. */
    configfile_t *config_file;
    /** the directive specifying this command */
    ap_directive_t *directive;

    /** Pool to allocate new storage in */
    apr_pool_t *pool;
    /** Pool for scratch memory; persists during configuration, but 
     *  wiped before the first request is served...  */
    apr_pool_t *temp_pool;
    /** Server_rec being configured for */
    server_rec *server;
    /** If configuring for a directory, pathname of that directory.  
     *  NOPE!  That's what it meant previous to the existance of <Files>, 
     * <Location> and regex matching.  Now the only usefulness that can be 
     * derived from this field is whether a command is being called in a 
     * server context (path == NULL) or being called in a dir context 
     * (path != NULL).  */
    char *path;
    /** configuration command */
    const command_rec *cmd;

    /** per_dir_config vector passed to handle_command */
    void *context;
    /** directive with syntax error */
    const ap_directive_t *err_directive;
};

typedef struct handler_rec handler_rec;

/** This structure records the existence of handlers in a module... */
struct handler_rec {
    /** The type of content this handler function will handle.  
     *  MUST be all lower case 
     */
    const char *content_type;
    /** The function to call when this context-type is requested. 
     *  @deffunc int handler(request_rec *)
     */
    int (*handler) (request_rec *);
};

typedef struct module_struct module;
/**
 * Module structures.  Just about everything is dispatched through
 * these, directly or indirectly (through the command and handler
 * tables).
 */
struct module_struct {
    /** API version, *not* module version; check that module is 
     * compatible with this version of the server.
     */
    int version;
    /** API minor version. Provides API feature milestones. Not checked 
     *  during module init */
    int minor_version;
    /** Index to this modules structures in config vectors.  */
    int module_index;

    /** The name of the module's C file */
    const char *name;
    /** The handle for the DSO.  Internal use only */
    void *dynamic_load_handle;

    /** A pointer to the next module in the list
     *  @defvar module_struct *next */
    struct module_struct *next;

    /** Magic Cookie to identify a module structure;  It's mainly 
     *  important for the DSO facility (see also mod_so).  */
    unsigned long magic;

    /** Function to allow MPMs to re-write command line arguments.  This
     *  hook is only available to MPMs.
     *  @param The process that the server is running in.
     *  @deffunc void rewrite_args(process_rec *process);
     */
    void (*rewrite_args) (process_rec *process);
    /** Function to allow all modules to create per directory configuration
     *  structures.
     *  @param p The pool to use for all allocations.
     *  @param dir The directory currently being processed.
     *  @return The per-directory structure created
     *  @deffunc void *create_dir_config(apr_pool_t *p, char *dir)
     */
    void *(*create_dir_config) (apr_pool_t *p, char *dir);
    /** Function to allow all modules to merge the per directory configuration
     *  structures for two directories.
     *  @param p The pool to use for all allocations.
     *  @param base_conf The directory structure created for the parent directory.
     *  @param new_conf The directory structure currently being processed.
     *  @return The new per-directory structure created
     *  @deffunc void *merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
     */
    void *(*merge_dir_config) (apr_pool_t *p, void *base_conf, void *new_conf);
    /** Function to allow all modules to create per server configuration
     *  structures.
     *  @param p The pool to use for all allocations.
     *  @param s The server currently being processed.
     *  @return The per-server structure created
     *  @deffunc void *create_server_config(apr_pool_t *p, server_rec *dir)
     */
    void *(*create_server_config) (apr_pool_t *p, server_rec *s);
    /** Function to allow all modules to merge the per server configuration
     *  structures for two servers.
     *  @param p The pool to use for all allocations.
     *  @param base_conf The directory structure created for the parent directory.
     *  @param new_conf The directory structure currently being processed.
     *  @return The new per-directory structure created
     *  @deffunc void *merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
     */
    void *(*merge_server_config) (apr_pool_t *p, void *base_conf, void *new_conf);

    /** A command_rec table that describes all of the directives this module
     * defines. */
    const command_rec *cmds;
    /** A handler_rec table that describes all of the mime-types this module
     *  will server responses for. */
    const handler_rec *handlers;

    /** A hook to allow modules to hook other points in the request processing.
     *  In this function, modules should call the ap_hook_*() functions to
     *  register an interest in a specific step in processing the current
     *  request.
     *  @deffunc void register_hooks(void)
     */
    void (*register_hooks) (void);
};

/* Initializer for the first few module slots, which are only
 * really set up once we start running.  Note that the first two slots
 * provide a version check; this should allow us to deal with changes to
 * the API. The major number should reflect changes to the API handler table
 * itself or removal of functionality. The minor number should reflect
 * additions of functionality to the existing API. (the server can detect
 * an old-format module, and either handle it back-compatibly, or at least
 * signal an error). See src/include/ap_mmn.h for MMN version history.
 */

#define STANDARD_MODULE_STUFF	this_module_needs_to_be_ported_to_apache_2_0

#define STANDARD20_MODULE_STUFF	MODULE_MAGIC_NUMBER_MAJOR, \
				MODULE_MAGIC_NUMBER_MINOR, \
				-1, \
				__FILE__, \
				NULL, \
				NULL, \
				MODULE_MAGIC_COOKIE, \
                                NULL      /* rewrite args spot */

#define MPM20_MODULE_STUFF	MODULE_MAGIC_NUMBER_MAJOR, \
				MODULE_MAGIC_NUMBER_MINOR, \
				-1, \
				__FILE__, \
				NULL, \
				NULL, \
				MODULE_MAGIC_COOKIE

/**
 * Generic accessors for other modules to get at their own module-specific
 * data
 * @param conf_vector The vector in which the modules configuration is stored.
 *        usually r->per_dir_config or s->module_config
 * @param m The module to get the data for.
 * @return The module-specific data
 * @deffunc void *ap_get_module_config(void *conf_vector, module *m)
 */
API_EXPORT(void *) ap_get_module_config(void *conf_vector, module *m);
/**
 * Generic accessors for other modules to set at their own module-specific
 * data
 * @param conf_vector The vector in which the modules configuration is stored.
 *        usually r->per_dir_config or s->module_config
 * @param m The module to set the data for.
 * @param val The module-specific data to set
 * @deffunc void ap_set_module_config(void *conf_vector, module *m, void *val)
 */
API_EXPORT(void) ap_set_module_config(void *conf_vector, module *m, void *val);

#define ap_get_module_config(v,m)	\
    (((void **)(v))[(m)->module_index])
#define ap_set_module_config(v,m,val)	\
    ((((void **)(v))[(m)->module_index]) = (val))

/**
 * Generic command handling function for strings
 * @param cmd The command parameters for this directive
 * @param struct_ptr pointer into a given type
 * @param arg The argument to the directive
 * @return An error string or NULL on success
 * @deffunc const char *ap_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg)
 */
API_EXPORT_NONSTD(const char *) ap_set_string_slot(cmd_parms *, void *,
						   const char *);
/**
 * Generic command handling function for strings, always sets the value
 * to a lowercase string
 * @param cmd The command parameters for this directive
 * @param struct_ptr pointer into a given type
 * @param arg The argument to the directive
 * @return An error string or NULL on success
 * @deffunc const char *ap_set_string_slot_lower(cmd_parms *cmd, void *struct_ptr, const char *arg)
 */
API_EXPORT_NONSTD(const char *) ap_set_string_slot_lower(cmd_parms *, 
							 void *, const char *);
/**
 * Generic command handling function for flags
 * @param cmd The command parameters for this directive
 * @param struct_ptr pointer into a given type
 * @param arg The argument to the directive (either 1 or 0)
 * @return An error string or NULL on success
 * @deffunc const char *ap_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg)
 */
API_EXPORT_NONSTD(const char *) ap_set_flag_slot(cmd_parms *, void *, int);
/**
 * Generic command handling function for files
 * @param cmd The command parameters for this directive
 * @param struct_ptr pointer into a given type
 * @param arg The argument to the directive
 * @return An error string or NULL on success
 * @deffunc const char *ap_set_file_slot(cmd_parms *cmd, char *struct_ptr, const char *arg)
 */
API_EXPORT_NONSTD(const char *) ap_set_file_slot(cmd_parms *, char *, const char *);

/**
 * For modules which need to read config files, open logs, etc. ...
 * this returns the fname argument if it begins with '/'; otherwise
 * it relativizes it wrt server_root.
 * @param p pool to allocate data out of
 * @param fname The file name
 * @deffunc const char *ap_server_root_relative(apr_pool_t *p, const char *fname)
 */
API_EXPORT(const char *) ap_server_root_relative(apr_pool_t *p, const char *fname);

/* Finally, the hook for dynamically loading modules in... */

/**
 * Add a module to the server
 * @param m the module structure of the module to add
 * @deffunc void ap_add_module(module *m)
 */
API_EXPORT(void) ap_add_module(module *m);
/**
 * Remove a module from the server.  There are some caveats:
 * when the module is removed, its slot is lost so all the current
 * per-dir and per-server configurations are invalid. So we should
 * only ever call this function when you are invalidating almost
 * all our current data. I.e. when doing a restart.
 * @param m the module structure of the module to remove
 * @deffunc void ap_remove_module(module *m)
 */
API_EXPORT(void) ap_remove_module(module *m);
/**
 * Add a module to the chained modules list and the list of loaded modules
 * @param m the module structure of the module to add
 * @deffunc void ap_add_loaded_module(module *m)
 */
API_EXPORT(void) ap_add_loaded_module(module *mod);
/**
 * Remove a module fromthe chained modules list and the list of loaded modules
 * @param m the module structure of the module to remove
 * @deffunc void ap_remove_loaded_module(module *m)
 */
API_EXPORT(void) ap_remove_loaded_module(module *mod);
/**
 * Add a module to the list of loaded module based on the name of the
 * module
 * @param name The name of the module
 * @return 1 on success, 0 on failure
 * @deffunc int ap_add_named_module(const char *name)
 */
API_EXPORT(int) ap_add_named_module(const char *name);
/**
 * Clear all of the modules from the loaded module list 
 * @deffunc void ap_add_named_module(void)
 */
API_EXPORT(void) ap_clear_module_list(void);
/**
 * Find the name of the specified module
 * @param m The module to get the name for
 * @return the name of the module
 * @deffunc const char *ap_find_module_name(module *m)
 */
API_EXPORT(const char *) ap_find_module_name(module *m);
/**
 * Find a module based on the name of the module
 * @param name the name of the module
 * @return the module structure if found, NULL otherwise
 * @deffunc module *ap_find_linked_module(const char *name)
 */
API_EXPORT(module *) ap_find_linked_module(const char *name);

/**
 * Open a configfile_t as apr_file_t
 * @param ret_cfg open configfile_t struct pointer
 * @param p The pool to allocate the structure out of
 * @param name the name of the file to open
 * @deffunc apr_status_t ap_pcfg_openfile(configfile_t **ret_cfg, apr_pool_t *p, const char *name)
 */
API_EXPORT(apr_status_t) ap_pcfg_openfile(configfile_t **, apr_pool_t *p, const char *name);

/**
 * Allocate a configfile_t handle with user defined functions and params 
 * @param p The pool to allocate out of
 * @param descr The name of the file
 * @param param The argument passed to getch/getstr/close
 * @param getc_func The getch function
 * @param gets_func The getstr function
 * @param close_func The close function
 * @deffunc configfile_t *ap_pcfg_open_custom(apr_pool_t *p, const char *descr, void *param, int(*getc_func)(void*), void *(*gets_func) (void *buf, size_t bufsiz, void *param), int(*close_func)(void *param))
 */
API_EXPORT(configfile_t *) ap_pcfg_open_custom(apr_pool_t *p, const char *descr,
    void *param,
    int(*getc_func)(void*),
    void *(*gets_func) (void *buf, size_t bufsiz, void *param),
    int(*close_func)(void *param));

/**
 * Read one line from open configfile_t, strip LF, increase line number
 * @param buf place to store the line read
 * @param bufsize size of the buffer
 * @param cfp File to read from
 * @return 1 on success, 0 on failure
 * @deffunc int ap_cfg_getline(char *buf, size_t bufsize, configfile_t *cfp)
 */
API_EXPORT(int) ap_cfg_getline(char *buf, size_t bufsize, configfile_t *cfp);

/**
 * Read one char from open configfile_t, increase line number upon LF 
 * @param cfp The file to read from
 * @return the character read
 * @deffunc int ap_cfg_getc(configfile_t *cfp)
 */
API_EXPORT(int) ap_cfg_getc(configfile_t *cfp);

/**
 * Detach from open configfile_t, calling the close handler
 * @param cfp The file to close
 * @return 1 on sucess, 0 on failure
 * @deffunc int ap_cfg_closefile(configfile_t *cfp)
 */
API_EXPORT(int) ap_cfg_closefile(configfile_t *cfp);

/**
 * Read all data between the current <foo> and the matching </foo>.  All
 * of this data is forgotten immediately.  
 * @param cmd The cmd_parms to pass to the directives inside the container
 * @param directive The directive name to read until
 * @retrn Error string on failure, NULL on success
 * @deffunc const char *ap_soak_end_container(cmd_parms *cmd, char *directive)
 */
API_EXPORT(const char *) ap_soak_end_container(cmd_parms *cmd, char *directive);

/**
 * Read all data between the current <foo> and the matching </foo> and build
 * a config tree out of it
 * @param p pool to allocate out of
 * @param temp_pool Temporary pool to allocate out of
 * @param parms The cmd_parms to pass to all directives read
 * @param current The current node in the tree
 * @param curr_parent The current parent node
 * @param orig_directive The directive to read until hit.
 * @return Error string on failure, NULL on success
 * @deffunc char *ap_build_cont_config(apr_pool_t *p, apr_pool_t *temp_pool, cmd_parms *parms, ap_directive_t **current, ap_directive_t **curr_parent, char *orig_directive)
*/
const char * ap_build_cont_config(apr_pool_t *p, apr_pool_t *temp_pool,
                                        cmd_parms *parms,
                                        ap_directive_t **current,
                                        ap_directive_t **curr_parent,
                                        char *orig_directive);

/**
 * Build a config tree from a config file
 * @param parms The cmd_parms to pass to all of the directives in the file
 * @param conf_pool The pconf pool
 * @param temp_pool The temporary pool
 * @param conftree Place to store the root node of the config tree
 * @return Error string on erro, NULL otherwise
 * @deffunc const char *ap_build_config(cmd_parms *parms, apr_pool_t *conf_pool, apr_pool_t *temp_pool, ap_directive_t **conftree)
 */
API_EXPORT(const char *) ap_build_config(cmd_parms *parms,
					 apr_pool_t *conf_pool,
					 apr_pool_t *temp_pool,
					 ap_directive_t **conftree);

/**
 * Walk a config tree and setup the server's internal structures
 * @param conftree The config tree to walk
 * @param parms The cmd_parms to pass to all functions
 * @param config The parms context
 * @return Error string on error, NULL otherwise
 * @deffunc const char *ap_walk_config(ap_directive_t *conftree, cmd_parms *parms, void *config)
 */
API_EXPORT(const char *) ap_walk_config(ap_directive_t *conftree,
					cmd_parms *parms, void *config);

/**
 * ap_check_cmd_context() definitions: 
 * @param cmd The cmd_context to check
 * @param forbidden Where the command is forbidden.  One of:
 * <PRE>
 *                NOT_IN_VIRTUALHOST
 *                NOT_IN_LIMIT
 *                NOT_IN_DIRECTORY
 *                NOT_IN_LOCATION
 *                NOT_IN_FILES
 *                NOT_IN_DIR_LOC_FILE
 *                GLOBAL_ONLY
 * </PRE>
 * @return Error string on error, NULL on success
 * @deffunc const char *ap_check_cmd_context(cmd_parms *cmd, unsigned forbidden)
 */
API_EXPORT(const char *) ap_check_cmd_context(cmd_parms *cmd, unsigned forbidden);

/* ap_check_cmd_context():              Forbidden in: */
#define  NOT_IN_VIRTUALHOST     0x01 /* <Virtualhost> */
#define  NOT_IN_LIMIT           0x02 /* <Limit> */
#define  NOT_IN_DIRECTORY       0x04 /* <Directory> */
#define  NOT_IN_LOCATION        0x08 /* <Location> */
#define  NOT_IN_FILES           0x10 /* <Files> */
#define  NOT_IN_DIR_LOC_FILE    (NOT_IN_DIRECTORY|NOT_IN_LOCATION|NOT_IN_FILES) /* <Directory>/<Location>/<Files>*/
#define  GLOBAL_ONLY            (NOT_IN_VIRTUALHOST|NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE)


#ifdef CORE_PRIVATE

/**
 * The topmost module in the list
 * @defvar module *top_module
 */
extern API_VAR_EXPORT module *top_module;

/**
 * Array of all statically linked modules
 * @defvar module *ap_prelinked_modules[]
 */
extern API_VAR_EXPORT module *ap_prelinked_modules[];
/**
 * Array of all preloaded modules
 * @defvar module *ap_preloaded_modules[]
 */
extern API_VAR_EXPORT module *ap_preloaded_modules[];
/**
 * Array of all loaded modules
 * @defvar module **ap_loaded_modules
 */
extern API_VAR_EXPORT module **ap_loaded_modules;

/* For mod_so.c... */
/** Run a single module's two create_config hooks
 *  @param p the pool to allocate out of
 *  @param s The server to configure for.
 *  @param m The module to configure
 */
void ap_single_module_configure(apr_pool_t *p, server_rec *s, module *m);

/* For http_main.c... */
/**
 * Add all of the prelinked modules into the loaded module list
 * @param process The process that is currently running the server
 * @deffunc void ap_setup_prelinked_modules(process_rec *process)
 */
API_EXPORT(void) ap_setup_prelinked_modules(process_rec *process);

/**
 *Show the preloaded configuration directives, the help string explaining
 * the directive arguments, in what module they are handled, and in
 * what parts of the configuration they are allowed.  Used for httpd -h.
 * @deffunc void ap_show_directives(void)
 */
API_EXPORT(void) ap_show_directives(void);

/** 
 * Show the preloaded module names.  Used for httpd -l. 
 * @deffunc void ap_show_modules(void)
 */
API_EXPORT(void) ap_show_modules(void);

/**
 * Read all config files and setup the server
 * @param process The process running the server
 * @param temp_pool A pool to allocate temporary data out of.
 * @param config_name The name of the config file
 * @param conftree Place to store the root of the config tree
 * @return The setup server_rec list.
 * @deffunc server_rec *ap_read_config(process_rec *process, apr_pool_t *temp_pool, const char *config_name, ap_directive_t **conftree)
 */
API_EXPORT(server_rec*) ap_read_config(process_rec *process, apr_pool_t *temp_pool, const char *config_name, ap_directive_t **conftree);

/**
 * Run all post config hooks for loaded modules.
 * @param pconf The configuration pool
 * @param plog The logging pool
 * @param ptemp The temporary pool
 * @param s The list of server_rec structures
 * @deffunc void ap_post_config_hook(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
 */
API_EXPORT(void) ap_post_config_hook(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);

/**
 * Run all rewrite args hooks for loaded modules
 * @param process The process currently running the server
 * @deffunc void ap_run_rewrite_args(process_rec *process)
 */
API_EXPORT(void) ap_run_rewrite_args(process_rec *process);

/**
 * Run the register hooks function for a specified module
 * @param m The module to run the register hooks function fo
 * @deffunc void ap_register_hooks(module *m)
 */
API_EXPORT(void) ap_register_hooks(module *m);

/**
 * Setup all virtual hosts
 * @param p The pool to allocate out of
 * @param main_server The head of the server_rec list
 * @deffunc void ap_fixup_virtual_hosts(apr_pool_t *p, server_rec *main_server)
 */
API_EXPORT(void) ap_fixup_virtual_hosts(apr_pool_t *p, server_rec *main_server);

/* For http_request.c... */

/**
 * Setup the config vector for a request_rec
 * @param p The pool to allocate the config vector out of
 * @return The config vector
 */
void *ap_create_request_config(apr_pool_t *p);

/**
 * Setup the config vector for per dir module configs
 * @param p The pool to allocate the config vector out of
 * @return The config vector
 * @deffunc void *ap_create_per_dir_config(apr_pool_t *p)
 */
CORE_EXPORT(void *) ap_create_per_dir_config(apr_pool_t *p);

/**
 * Run all of the modules merge per dir config functions
 * @param p The pool to pass to the merge functions
 * @param base The base directory config structure
 * @param new The new directory config structure
 */
void *ap_merge_per_dir_configs(apr_pool_t *p, void *base, void *new);

/* For http_connection.c... */
/**
 * Setup the config vector for a connection_rec
 * @param p The pool to allocate the config vector out of
 * @return The config vector
 */
void *ap_create_conn_config(apr_pool_t *p);

/* For http_core.c... (<Directory> command and virtual hosts) */

/**
 * parse an htaccess file
 * @param resulting htaccess_result
 * @param r The request currently being served
 * @param override Which overrides are active
 * @param path The path to the htaccess file
 * @param access_name The list of possible names for .htaccess files
 * int The status of the current request
 */
int ap_parse_htaccess(void **result, request_rec *r, int override,
		const char *path, const char *access_name);

/**
 * Setup a virtual host
 * @param p The pool to allocate all memory out of
 * @param hostname The hostname of the virtual hsot
 * @param main_server The main server for this Apache configuration
 * @param ps Place to store the new server_rec
 * return Error string on error, NULL on success
 * @deffunc const char *ap_init_virtual_host(apr_pool_t *p, const char *hostname, server_rec *main_server, server_rec **ps)
 */
CORE_EXPORT(const char *) ap_init_virtual_host(apr_pool_t *p, const char *hostname,
				server_rec *main_server, server_rec **);

/**
 * Process the config file for Apache
 * @param s The server rec to use for the command parms
 * @param fname The name of the config file
 * @param conftree The root node of the created config tree
 * @param p Pool for general allocation
 * @param ptem Pool for temporary allocation
 */
void ap_process_resource_config(server_rec *s, const char *fname, 
                 ap_directive_t **conftree, apr_pool_t *p, apr_pool_t *ptemp);

/**
 * Process all directives in the config tree
 * @param s The server rec to use in the command parms
 * @param conftree The config tree to process
 * @param p The pool for general allocation
 * @param ptemp The pool for temporary allocations
 */
API_EXPORT(void) ap_process_config_tree(server_rec *s, ap_directive_t *conftree,
                                        apr_pool_t *p, apr_pool_t *ptemp);


/* For individual MPMs... */
/**
 * Run all child init hooks
 * @param pchild The pool for child process allocations
 * @param s The list of all server_recs
 */
void ap_child_init_hook(apr_pool_t *pchild, server_rec *s);

/* Module-method dispatchers, also for http_request.c */
/**
 * Run the handler phase of each module until a module accepts the
 * responsibility of serving the request
 * @param r The current request
 * @return The status of the current request
 */
int ap_invoke_handler(request_rec *);

/* for mod_perl */

/**
 * Find a given directive in a command_rec table
 * @param name The directive to search for
 * @param cmds The table to search
 * @return The directive definition of the specified directive
 * @deffunc const command_rec *ap_find_command(const char *name, const command_rec *cmds)
 */
CORE_EXPORT(const command_rec *) ap_find_command(const char *name, const command_rec *cmds);

/**
 * Find a given directive in a list module
 * @param cmd_name The directive to search for
 * @param mod The module list to search
 * @return The directive definition of the specified directive
 * @deffunc const command_rec *ap_find_command_in_modules(const char *cmd_name,module **mod)
 */
CORE_EXPORT(const command_rec *) ap_find_command_in_modules(const char *cmd_name, module **mod);

/**
 * Add a per_dir and per_server config vector to a given module
 * @param parms The command_parms to use
 * @param config The config vector
 * @param mod The module to add the vector for.
 * @return The new config vector
 * @deffunc void *ap_set_config_vectors(cmd_parms *parms, void *config, module *mod)
 */
CORE_EXPORT(void *) ap_set_config_vectors(cmd_parms *parms, void *config, module *mod);

#endif

  /* Hooks */

/**
 * Run the header parser functions for each module
 * @param r The current request
 * @return OK or DECLINED
 * @deffunc int ap_run_header_parser(request_rec *r)
 */
AP_DECLARE_HOOK(int,header_parser,(request_rec *))

/**
 * Run the pre_config function for each module
 * @param pconf The config pool
 * @param plog The logging streams pool
 * @param ptemp The temporary pool
 * @deffunc void ap_run_pre_config(apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp)
 */
AP_DECLARE_HOOK(void,pre_config,
	     (apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp))

/**
 * Run the post_config function for each module
 * @param pconf The config pool
 * @param plog The logging streams pool
 * @param ptemp The temporary pool
 * @param s The list of server_recs
 * @deffunc void ap_run_post_config(apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp, server_rec *s)
 */
AP_DECLARE_HOOK(void,post_config,
	     (apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp,server_rec *s))

/**
 * Run the open_logs functions for each module
 * @param pconf The config pool
 * @param plog The logging streams pool
 * @param ptemp The temporary pool
 * @param s The list of server_recs
 * @deffunc void ap_run_open_logs(apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp, server_rec *s)
 */
AP_DECLARE_HOOK(void,open_logs,
	     (apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp,server_rec *s))

/**
 * Run the child_init functions for each module
 * @param pchild The child pool
 * @param s The list of server_recs in this server 
 * @deffunc void ap_run_child_init(apr_pool_t *pchild, server_rec *s)
 */
AP_DECLARE_HOOK(void,child_init,(apr_pool_t *pchild, server_rec *s))

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_CONFIG_H */
