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

#ifndef APACHE_HTTP_CONFIG_H
#define APACHE_HTTP_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The central data structures around here...
 */

/* Command dispatch structures... */

/* Note that for all of these except RAW_ARGS, the config routine is
 * passed a freshly allocated string which can be modified or stored
 * or whatever... it's only necessary to do pstrdup() stuff with
 * RAW_ARGS.
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

typedef struct command_struct {
    const char *name;		/* Name of this command */
    const char *(*func) ();	/* Function invoked */
    void *cmd_data;		/* Extra data, for functions which
				 * implement multiple commands...
				 */
    int req_override;		/* What overrides need to be allowed to
				 * enable this command.
				 */
    enum cmd_how args_how;	/* What the command expects as arguments */

    const char *errmsg;		/* 'usage' message, in case of syntax errors */
} command_rec;

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
#define OR_ALL (OR_LIMIT|OR_OPTIONS|OR_FILEINFO|OR_AUTHCFG|OR_INDEXES)

/* This can be returned by a function if they don't wish to handle
 * a command. Make it something not likely someone will actually use
 * as an error code.
 */

#define DECLINE_CMD "\a\b"

/*
 * This structure is passed to a command which is being invoked,
 * to carry a large variety of miscellaneous data which is all of
 * use to *somebody*...
 */

typedef struct {
    void *info;			/* Argument to command from cmd_table */
    int override;		/* Which allow-override bits are set */
    int limited;		/* Which methods are <Limit>ed */

    configfile_t *config_file;	/* Config file structure from pcfg_openfile() */

    ap_pool *pool;			/* Pool to allocate new storage in */
    struct pool *temp_pool;		/* Pool for scratch memory; persists during
				 * configuration, but wiped before the first
				 * request is served...
				 */
    server_rec *server;		/* Server_rec being configured for */
    char *path;			/* If configuring for a directory,
				 * pathname of that directory.
				 * NOPE!  That's what it meant previous to the
				 * existance of <Files>, <Location> and regex
				 * matching.  Now the only usefulness that can
				 * be derived from this field is whether a command
				 * is being called in a server context (path == NULL)
				 * or being called in a dir context (path != NULL).
				 */
    const command_rec *cmd;	/* configuration command */
    const char *end_token;	/* end token required to end a nested section */
    void *context;		/* per_dir_config vector passed 
				 * to handle_command */
} cmd_parms;

/* This structure records the existence of handlers in a module... */

typedef struct {
    const char *content_type;	/* MUST be all lower case */
    int (*handler) (request_rec *);
} handler_rec;

/*
 * Module structures.  Just about everything is dispatched through
 * these, directly or indirectly (through the command and handler
 * tables).
 */

typedef struct module_struct {
    int version;		/* API version, *not* module version;
				 * check that module is compatible with this
				 * version of the server.
				 */
    int minor_version;          /* API minor version. Provides API feature
                                 * milestones. Not checked during module init
				 */
    int module_index;		/* Index to this modules structures in
				 * config vectors.
				 */

    const char *name;
    void *dynamic_load_handle;

    struct module_struct *next;

    unsigned long magic;        /* Magic Cookie to identify a module structure;
                                 * It's mainly important for the DSO facility
                                 * (see also mod_so).
                                 */

    /* init() occurs after config parsing, but before any children are
     * forked.
     * Modules should not rely on the order in which create_server_config
     * and create_dir_config are called.
     */
#ifdef ULTRIX_BRAIN_DEATH
    void (*init) ();
    void *(*create_dir_config) ();
    void *(*merge_dir_config) ();
    void *(*create_server_config) ();
    void *(*merge_server_config) ();
#else
    void (*init) (server_rec *, pool *);
    void *(*create_dir_config) (pool *p, char *dir);
    void *(*merge_dir_config) (pool *p, void *base_conf, void *new_conf);
    void *(*create_server_config) (pool *p, server_rec *s);
    void *(*merge_server_config) (pool *p, void *base_conf, void *new_conf);
#endif

    const command_rec *cmds;
    const handler_rec *handlers;

    /* Hooks for getting into the middle of server ops...

     * translate_handler --- translate URI to filename
     * access_checker --- check access by host address, etc.   All of these
     *                    run; if all decline, that's still OK.
     * check_user_id --- get and validate user id from the HTTP request
     * auth_checker --- see if the user (from check_user_id) is OK *here*.
     *                  If all of *these* decline, the request is rejected
     *                  (as a SERVER_ERROR, since the module which was
     *                  supposed to handle this was configured wrong).
     * type_checker --- Determine MIME type of the requested entity;
     *                  sets content_type, _encoding and _language fields.
     * logger --- log a transaction.
     * post_read_request --- run right after read_request or internal_redirect,
     *                  and not run during any subrequests.
     */

    int (*translate_handler) (request_rec *);
    int (*ap_check_user_id) (request_rec *);
    int (*auth_checker) (request_rec *);
    int (*access_checker) (request_rec *);
    int (*type_checker) (request_rec *);
    int (*fixer_upper) (request_rec *);
    int (*logger) (request_rec *);
    int (*header_parser) (request_rec *);

    /* Regardless of the model the server uses for managing "units of
     * execution", i.e. multi-process, multi-threaded, hybrids of those,
     * there is the concept of a "heavy weight process".  That is, a
     * process with its own memory space, file spaces, etc.  This method,
     * child_init, is called once for each heavy-weight process before
     * any requests are served.  Note that no provision is made yet for
     * initialization per light-weight process (i.e. thread).  The
     * parameters passed here are the same as those passed to the global
     * init method above.
     */
#ifdef ULTRIX_BRAIN_DEATH
    void (*child_init) ();
    void (*child_exit) ();
#else
    void (*child_init) (server_rec *, pool *);
    void (*child_exit) (server_rec *, pool *);
#endif
    int (*post_read_request) (request_rec *);
} module;

/* Initializer for the first few module slots, which are only
 * really set up once we start running.  Note that the first two slots
 * provide a version check; this should allow us to deal with changes to
 * the API. The major number should reflect changes to the API handler table
 * itself or removal of functionality. The minor number should reflect
 * additions of functionality to the existing API. (the server can detect
 * an old-format module, and either handle it back-compatibly, or at least
 * signal an error). See src/include/ap_mmn.h for MMN version history.
 */

#define STANDARD_MODULE_STUFF	MODULE_MAGIC_NUMBER_MAJOR, \
				MODULE_MAGIC_NUMBER_MINOR, \
				-1, \
				__FILE__, \
				NULL, \
				NULL, \
				MODULE_MAGIC_COOKIE

/* Generic accessors for other modules to get at their own module-specific
 * data
 */

API_EXPORT(void *) ap_get_module_config(void *conf_vector, module *m);
API_EXPORT(void) ap_set_module_config(void *conf_vector, module *m, void *val);

#define ap_get_module_config(v,m)	\
    (((void **)(v))[(m)->module_index])
#define ap_set_module_config(v,m,val)	\
    ((((void **)(v))[(m)->module_index]) = (val))

/* Generic command handling function... */

API_EXPORT_NONSTD(const char *) ap_set_string_slot(cmd_parms *, char *, char *);
API_EXPORT_NONSTD(const char *) ap_set_string_slot_lower(cmd_parms *, char *, char *);
API_EXPORT_NONSTD(const char *) ap_set_flag_slot(cmd_parms *, char *, int);
API_EXPORT_NONSTD(const char *) ap_set_file_slot(cmd_parms *, char *, char *);

/* For modules which need to read config files, open logs, etc. ...
 * this returns the fname argument if it begins with '/'; otherwise
 * it relativizes it wrt server_root.
 */

API_EXPORT(char *) ap_server_root_relative(pool *p, char *fname);

/* Finally, the hook for dynamically loading modules in... */

API_EXPORT(void) ap_add_module(module *m);
API_EXPORT(void) ap_remove_module(module *m);
API_EXPORT(void) ap_add_loaded_module(module *mod);
API_EXPORT(void) ap_remove_loaded_module(module *mod);
API_EXPORT(int) ap_add_named_module(const char *name);
API_EXPORT(void) ap_clear_module_list(void);
API_EXPORT(const char *) ap_find_module_name(module *m);
API_EXPORT(module *) ap_find_linked_module(const char *name);

/* for implementing subconfigs and customized config files */
API_EXPORT(const char *) ap_srm_command_loop(cmd_parms *parms, void *config);

#ifdef CORE_PRIVATE

extern API_VAR_EXPORT module *top_module;

extern module *ap_prelinked_modules[];
extern module *ap_preloaded_modules[];
extern API_VAR_EXPORT module **ap_loaded_modules;

/* For mod_so.c... */

API_EXPORT(void) ap_single_module_configure(pool *p, server_rec *s, module *m);

/* For http_main.c... */

API_EXPORT(server_rec *) ap_read_config(pool *conf_pool, pool *temp_pool, char *config_name);
API_EXPORT(void) ap_init_modules(pool *p, server_rec *s);
API_EXPORT(void) ap_child_init_modules(pool *p, server_rec *s);
API_EXPORT(void) ap_child_exit_modules(pool *p, server_rec *s);
API_EXPORT(void) ap_setup_prelinked_modules(void);
API_EXPORT(void) ap_show_directives(void);
API_EXPORT(void) ap_show_modules(void);
void ap_cleanup_method_ptrs(void);

/* For http_request.c... */

CORE_EXPORT(void *) ap_create_request_config(pool *p);
CORE_EXPORT(void *) ap_create_per_dir_config(pool *p);
CORE_EXPORT(void *) ap_merge_per_dir_configs(pool *p, void *base, void *new);

/* For http_core.c... (<Directory> command and virtual hosts) */

CORE_EXPORT(int) ap_parse_htaccess(void **result, request_rec *r, int override,
		const char *path, const char *access_name);

CORE_EXPORT(const char *) ap_init_virtual_host(pool *p, const char *hostname,
				server_rec *main_server, server_rec **);
CORE_EXPORT(void) ap_process_resource_config(server_rec *s, char *fname, pool *p, pool *ptemp);

/* ap_check_cmd_context() definitions: */
API_EXPORT(const char *) ap_check_cmd_context(cmd_parms *cmd, unsigned forbidden);

/* ap_check_cmd_context():              Forbidden in: */
#define  NOT_IN_VIRTUALHOST     0x01 /* <Virtualhost> */
#define  NOT_IN_LIMIT           0x02 /* <Limit> */
#define  NOT_IN_DIRECTORY       0x04 /* <Directory> */
#define  NOT_IN_LOCATION        0x08 /* <Location> */
#define  NOT_IN_FILES           0x10 /* <Files> */
#define  NOT_IN_DIR_LOC_FILE    (NOT_IN_DIRECTORY|NOT_IN_LOCATION|NOT_IN_FILES) /* <Directory>/<Location>/<Files>*/
#define  GLOBAL_ONLY            (NOT_IN_VIRTUALHOST|NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE)


/* Module-method dispatchers, also for http_request.c */

API_EXPORT(int) ap_translate_name(request_rec *);
API_EXPORT(int) ap_check_access(request_rec *);	/* check access on non-auth basis */
API_EXPORT(int) ap_check_user_id(request_rec *);	/* obtain valid username from client auth */
API_EXPORT(int) ap_check_auth(request_rec *);	/* check (validated) user is authorized here */
API_EXPORT(int) ap_find_types(request_rec *);	/* identify MIME type */
API_EXPORT(int) ap_run_fixups(request_rec *);	/* poke around for other metainfo, etc.... */
API_EXPORT(int) ap_invoke_handler(request_rec *);
API_EXPORT(int) ap_log_transaction(request_rec *r);
API_EXPORT(int) ap_header_parse(request_rec *);
API_EXPORT(int) ap_run_post_read_request(request_rec *);

/* for mod_perl */

CORE_EXPORT(const command_rec *) ap_find_command(const char *name, const command_rec *cmds);
CORE_EXPORT(const command_rec *) ap_find_command_in_modules(const char *cmd_name, module **mod);
CORE_EXPORT(void *) ap_set_config_vectors(cmd_parms *parms, void *config, module *mod);
CORE_EXPORT(const char *) ap_handle_command(cmd_parms *parms, void *config, const char *l);

#endif

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_CONFIG_H */
