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
 * The central data structures around here...
 */

/* Command dispatch structures... */

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
  FLAG,				/* One of 'On' or 'Off' */
  NO_ARGS,			/* No args at all, e.g. </Directory> */
  TAKE12,			/* one or two arguments */
  TAKE3,			/* three arguments only */
  TAKE23,			/* two or three arguments */
  TAKE123,			/* one, two or three arguments */
  TAKE13			/* one or three arguments */
};

typedef struct command_struct {
  char *name;			/* Name of this command */
  const char *(*func)();	/* Function invoked */
  void *cmd_data;		/* Extra data, for functions which
				 * implement multiple commands...
				 */
  int req_override;		/* What overrides need to be allowed to
				 * enable this command.
				 */
  enum cmd_how args_how;	/* What the command expects as arguments */
  
  char *errmsg;			/* 'usage' message, in case of syntax errors */
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
    
    char *config_file;		/* Filename cmd read from */
    int config_line;		/* Line cmd read from */
    FILE *infile;		/* fd for more lines (not currently used) */
    
    pool *pool;			/* Pool to allocate new storage in */
    pool *temp_pool;		/* Pool for scratch memory; persists during
				 * configuration, but wiped before the first
				 * request is served...
				 */
    server_rec *server;		/* Server_rec being configured for */
    char *path;			/* If configuring for a directory,
				 * pathname of that directory.
				 */
    const command_rec *cmd;	/* configuration command */
} cmd_parms;

/* This structure records the existence of handlers in a module... */

typedef struct {
    char *content_type;
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
    int module_index;		/* Index to this modules structures in
				 * config vectors.
				 */

    const char *name;

    struct module_struct *next;

#ifdef ULTRIX_BRAIN_DEATH
    void (*init)();
    void *(*create_dir_config)();
    void *(*merge_dir_config)();
    void *(*create_server_config)();
    void *(*merge_server_config)();
#else
    void (*init)(server_rec *, pool *);
    void *(*create_dir_config)(pool *p, char *dir);
    void *(*merge_dir_config)(pool *p, void *base_conf, void *new_conf);
    void *(*create_server_config)(pool *p, server_rec *s);
    void *(*merge_server_config)(pool *p, void *base_conf, void *new_conf);
#endif

    command_rec *cmds;
    handler_rec *handlers;

    /* Hooks for getting into the middle of server ops...
     *
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
     * logger --- log a transaction.  Not supported yet out of sheer
     *            laziness on my part.
     */
    
    int (*translate_handler)(request_rec *);
    int (*check_user_id)(request_rec *);
    int (*auth_checker)(request_rec *);
    int (*access_checker)(request_rec *);
    int (*type_checker)(request_rec *);
    int (*fixer_upper)(request_rec *);
    int (*logger)(request_rec *);
    int (*header_parser)(request_rec *);
} module;

/* Initializer for the first few module slots, which are only
 * really set up once we start running.  Note that the first word
 * is a version check; this should allow us to deal with changes to
 * the API (the server can detect an old-format module, and either
 * handle it back-compatibly, or at least signal an error).
 */

#define MODULE_MAGIC_NUMBER 19970622
#define STANDARD_MODULE_STUFF MODULE_MAGIC_NUMBER, -1, __FILE__, NULL

/* Generic accessors for other modules to get at their own module-specific
 * data
 */

void *get_module_config (void *conf_vector, module *m);
void set_module_config (void *conf_vector, module *m, void *val);     
     
/* Generic command handling function... */

const char *set_string_slot (cmd_parms *, char *, char *);
const char *set_flag_slot (cmd_parms *, char *, int);

/* For modules which need to read config files, open logs, etc. ...
 * this returns the fname argument if it begins with '/'; otherwise
 * it relativizes it wrt server_root.
 */

char *server_root_relative (pool *p, char *fname);
     
/* Finally, the hook for dynamically loading modules in... */

void add_module (module *m);
int add_named_module (const char *name);
void clear_module_list ();
const char *find_module_name (module *m);
module *find_linked_module (const char *name);

#ifdef CORE_PRIVATE

/* For http_main.c... */

server_rec *read_config (pool *conf_pool, pool *temp_pool, char *config_name);
void init_modules(pool *p, server_rec *s);
void setup_prelinked_modules();
void show_directives();
void show_modules();

/* For http_request.c... */

void *create_request_config (pool *p);
void *create_per_dir_config (pool *p);
void *merge_per_dir_configs (pool *p, void *base, void *new);

/* For http_core.c... (<Directory> command and virtual hosts) */

int parse_htaccess(void **result, request_rec *r, int override,
		   char *path, char *file);
const char *srm_command_loop (cmd_parms *parms, void *config);

server_rec *init_virtual_host (pool *p, const char *hostname, server_rec *main_server);
int is_virtual_server (server_rec *);
void process_resource_config(server_rec *s, char *fname, pool *p, pool *ptemp);

/* Module-method dispatchers, also for http_request.c */

int translate_name (request_rec *);
int directory_walk (request_rec *); /* check symlinks, get per-dir config */
int check_access (request_rec *); /* check access on non-auth basis */
int check_user_id (request_rec *); /* obtain valid username from client auth */
int check_auth (request_rec *); /* check (validated) user is authorized here */
int find_types (request_rec *);	/* identify MIME type */
int run_fixups (request_rec *);	/* poke around for other metainfo, etc.... */
int invoke_handler (request_rec *);     
int log_transaction (request_rec *r);
int header_parse (request_rec *);

#endif
