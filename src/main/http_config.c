
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
 * http_config.c: once was auxillary functions for reading httpd's config
 * file and converting filenames into a namespace
 *
 * Rob McCool 
 * 
 * Wall-to-wall rewrite for Shambhala... commands which are part of the
 * server core can now be found next door in "http_core.c".  Now contains
 * general command loop, and functions which do bookkeeping for the new
 * Shambhala config stuff (modules and configuration vectors).
 *
 * rst
 *
 */

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"		/* for errors in parse_htaccess */
#include "http_request.h"	/* for default_handler (see invoke_handler) */
#include "http_conf_globals.h"	/* Sigh... */

/****************************************************************
 *
 * We begin with the functions which deal with the linked list
 * of modules which control just about all of server operation in
 * Shambhala.
 */

static int num_modules = 0;    
module *top_module = NULL;
    
typedef int (*handler)(request_rec *);
typedef void *(*maker)(pool *);
typedef void *(*dir_maker)(pool *, char *);
typedef void *(*merger)(pool *, void *, void *);    

/* Dealing with config vectors.  These are associated with per-directory,
 * per-server, and per-request configuration, and have a void* pointer for
 * each modules.  The nature of the structure pointed to is private to the
 * module in question... the core doesn't (and can't) know.  However, there
 * are defined interfaces which allow it to create instances of its private
 * per-directory and per-server structures, and to merge the per-directory
 * structures of a directory and its subdirectory (producing a new one in
 * which the defaults applying to the base directory have been properly
 * overridden).
 */

void *    
get_module_config (void *conf_vector, module *m)
{
   void **confv = (void**)conf_vector;
   return confv[m->module_index];
}

void
set_module_config (void *conf_vector, module *m, void *val)
{
   void **confv = (void**)conf_vector;
   confv[m->module_index] = val;
}

void *
create_empty_config (pool *p)
{
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * num_modules);
   return (void *)conf_vector;
}

void *
create_default_per_dir_config (pool *p)
{
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * (num_modules+DYNAMIC_MODULE_LIMIT));
   module *modp;

   for (modp = top_module; modp; modp = modp->next) {
       dir_maker df = modp->create_dir_config;

       if (df) conf_vector[modp->module_index] = (*df)(p, NULL);
   }

   return (void*)conf_vector;
}

void *
merge_per_dir_configs (pool *p, void *base, void *new)
{
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * num_modules);
   void **base_vector = (void **) base;
   void **new_vector = (void **) new;
   module *modp;

   for (modp = top_module; modp; modp = modp->next) {
       merger df = modp->merge_dir_config;
       int i = modp->module_index;

       if (df && new_vector[i])
	   conf_vector[i] = (*df)(p, base_vector[i], new_vector[i]);
       else
	   conf_vector[i] = new_vector[i]? new_vector[i] : base_vector[i];
   }

   return (void*)conf_vector;
}

void *
create_server_config (pool *p, server_rec *s)
{
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * (num_modules+DYNAMIC_MODULE_LIMIT));
   module *modp;

   for (modp = top_module; modp; modp = modp->next) {
       if (modp->create_server_config)
	   conf_vector[modp->module_index]=(*modp->create_server_config)(p,s);
   }

   return (void*)conf_vector;
}

void merge_server_configs (pool *p, void *base, void *virt)
{
    /* Can reuse the 'virt' vector for the spine of it, since we don't
     * have to deal with the moral equivalent of .htaccess files here...
     */

    void **base_vector = (void **)base;
    void **virt_vector = (void **)virt;
    module *modp;
    
    for (modp = top_module; modp; modp = modp->next) {
	merger df = modp->merge_server_config;
	int i = modp->module_index;

	if (!virt_vector[i])
	    virt_vector[i] = base_vector[i];
	else if (df)
	    virt_vector[i] = (*df)(p, base_vector[i], virt_vector[i]);
    }
}
 
void *create_connection_config (pool *p) {
    return create_empty_config (p);
}

void *create_request_config (pool *p) {
    return create_empty_config (p);
}

void *create_per_dir_config (pool *p) {
    return create_empty_config (p);
}

/****************************************************************
 *
 * Dispatch through the modules to find handlers for various phases
 * of request handling.  These are invoked by http_request.c to actually
 * do the dirty work of slogging through the module structures.
 */

int
run_method (request_rec *r, int offset, int run_all)
{
   module *modp;
   for (modp = top_module; modp; modp = modp->next) {
       handler mod_handler = *(handler *)(offset + (char *)(modp));

       if (mod_handler) {
	   int result = (*mod_handler)(r);

	   if (result != DECLINED && (!run_all || result != OK))
	       return result;
       }
   }

   return run_all ? OK : DECLINED;
}

int translate_name(request_rec *r) {
   return run_method (r, XtOffsetOf (module, translate_handler), 0);
}

int check_access(request_rec *r) {
   return run_method (r, XtOffsetOf (module, access_checker), 1);
}

int find_types (request_rec *r) {
   return run_method (r, XtOffsetOf (module, type_checker), 0);
}

int run_fixups (request_rec *r) {
   return run_method (r, XtOffsetOf (module, fixer_upper), 1);
}

int log_transaction (request_rec *r) {
   return run_method (r, XtOffsetOf (module, logger), 1);
}

/* Auth stuff --- anything that defines one of these will presumably
 * want to define something for the other.  Note that check_auth is
 * separate from check_access to make catching some config errors easier.
 */

int check_user_id (request_rec *r) {
   return run_method (r, XtOffsetOf (module, check_user_id), 0);
}

int check_auth (request_rec *r) {
   return run_method (r, XtOffsetOf (module, auth_checker), 0);
}

int invoke_handler (request_rec *r)
{
   module *modp;
   handler_rec *handp;
   char *content_type = r->content_type ? r->content_type : default_type (r);
   char *handler = r->handler ? r->handler : content_type;
  
   /* Pass one --- direct matches */
   
   for (modp = top_module; modp; modp = modp->next) 
   {
       if (!modp->handlers) continue;
       
       for (handp = modp->handlers; handp->content_type; ++handp) {
	   if (!strcasecmp (handler, handp->content_type)) {
	       int result = (*handp->handler)(r);

	       if (result != DECLINED) return result;
	   }
       }
   }
   
   /* Pass two --- wildcard matches */
   
   for (modp = top_module; modp; modp = modp->next) 
   {
       if (!modp->handlers) continue;
       
       for (handp = modp->handlers; handp->content_type; ++handp) {
	   char *starp = strchr (handp->content_type, '*');
	   int len;

	   if (!starp) continue;

	   len = starp - handp->content_type;
	   
	   if (!len || !strncasecmp (handler, handp->content_type, len))
	   {
	       int result = (*handp->handler)(r);

	       if (result != DECLINED) return result;
	   }
       }
   }
   
   return NOT_IMPLEMENTED;
}

/* One-time setup for precompiled modules --- NOT to be done on restart */

void add_module (module *m)
{
    /* This could be called from an AddModule httpd.conf command,
     * after the file has been linked and the module structure within it
     * teased out...
     */

    m->next = top_module;
    top_module = m;
    m->module_index = num_modules++;
}

void setup_prelinked_modules ()
{
    extern module *prelinked_modules[];
    module **m = prelinked_modules;

    while (*m) {
        add_module (*m);
	++m;
    }
}

/*****************************************************************
 *
 * Resource, access, and .htaccess config files now parsed by a common
 * command loop.
 *
 * Let's begin with the basics; parsing the line and
 * invoking the function...
 */

char *invoke_cmd(command_rec *cmd, cmd_parms *parms, void *mconfig, char *args)
{
    char *w, *w2, *errmsg;

    if ((parms->override & cmd->req_override) == 0)
        return pstrcat (parms->pool, cmd->name, " not allowed here", NULL);
    
    parms->info = cmd->cmd_data;
    
    switch (cmd->args_how) {
    case RAW_ARGS:
        return (*cmd->func) (parms, mconfig, args);

    case NO_ARGS:
	if (*args != 0)
	    return pstrcat (parms->pool, cmd->name, " takes no arguments",
			    NULL);

	return (*cmd->func) (parms, mconfig);
	
    case TAKE1:
	w = getword_conf (parms->pool, &args);
	
	if (*w == '\0' || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes one argument",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w);
	
    case TAKE2:

	w = getword_conf (parms->pool, &args);
	w2 = getword_conf (parms->pool, &args);
	
	if (*w == '\0' || *w2 == '\0' || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes two arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w, w2);
	
    case ITERATE:

	while (*(w = getword_conf (parms->pool, &args)) != '\0')
	    if ((errmsg = (*cmd->func) (parms, mconfig, w)))
	        return errmsg;

	return NULL;
	
    case ITERATE2:

	w = getword_conf (parms->pool, &args);
	
	if (*w == '\0' || *args == 0) 
	    return pstrcat(parms->pool, cmd->name,
			   " requires at least two arguments",
			   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);
	  

	while (*(w2 = getword_conf (parms->pool, &args)) != '\0')
	    if ((errmsg = (*cmd->func) (parms, mconfig, w, w2)))
	        return errmsg;

	return NULL;
	
    case FLAG:

	w = getword_conf (parms->pool, &args);

	if (*w == '\0' || ((!strcasecmp(w, "on")) && (!strcasecmp (w, "off"))))
	    return pstrcat (parms->pool, cmd->name, " must be On or Off",
			    NULL);

	return (*cmd->func) (parms, mconfig, strcasecmp (w, "off") != 0);

    default:

	return pstrcat (parms->pool, cmd->name,
			" is improperly configured internally (server bug)",
			NULL);
    }
}

command_rec *find_command (char *name, command_rec *cmds)
{
    while (cmds->name) 
        if (!strcasecmp (name, cmds->name))
	    return cmds;
	else
	    ++cmds;

    return NULL;
}
    
command_rec *find_command_in_modules (char *cmd_name, module **mod)
{
   command_rec *cmdp;
   module *modp;

   for (modp = top_module; modp; modp = modp->next) 
       if (modp->cmds && (cmdp = find_command (cmd_name, modp->cmds))) {
	   *mod = modp;
	   return cmdp;
       }

   return NULL;
}

char *handle_command (cmd_parms *parms, void *config, char *l)
{
    char *args, *cmd_name;
    command_rec *cmd;
    module *mod;

    ++parms->config_line;
    if((l[0] == '#') || (!l[0])) return NULL;
	
    args = l;
    cmd_name = getword_conf (parms->temp_pool, &args);
    if (*cmd_name == '\0') return NULL;
	
    if (!(cmd = find_command_in_modules (cmd_name, &mod))) {
	return pstrcat (parms->pool, "Invalid command ", cmd_name, NULL);
    }
    else {
	void *mconfig = get_module_config (config, mod);
	void *sconfig = get_module_config (parms->server->module_config, mod);
	      
	if (!mconfig && mod->create_dir_config) {
	    mconfig = (*mod->create_dir_config) (parms->pool, parms->path);
	    set_module_config (config, mod, mconfig);
	}
	    
	if (!sconfig && mod->create_server_config) {
	    sconfig = (*mod->create_server_config)(parms->pool, parms->server);
	    set_module_config (parms->server->module_config, mod, sconfig);
	}
	
	return invoke_cmd (cmd, parms, mconfig, args);
    }
}

char *srm_command_loop (cmd_parms *parms, void *config)
{
    char l[MAX_STRING_LEN];
    
    while (!(cfg_getline (l, MAX_STRING_LEN, parms->infile))) {
	char *errmsg = handle_command (parms, config, l);
	if (errmsg) return errmsg;
    }

    return NULL;
}

/*
 * Generic command functions...
 */

char *set_string_slot (cmd_parms *cmd, char *struct_ptr, char *arg)
{
    /* This one's pretty generic... */
  
    int offset = (int)cmd->info; 
    *(char **)(struct_ptr + offset) = pstrdup (cmd->pool, arg);
    return NULL;
}

/*****************************************************************
 *
 * Reading whole config files...
 */

cmd_parms default_parms = { NULL, 0, -1, NULL, 0, NULL, NULL, NULL, NULL };

char *server_root_relative (pool *p, char *file)
{
#ifdef __EMX__
    /* Add support for OS/2 drive names */
    if ((file[0] == '/') || (file[1] == ':')) return file;
#else
    if (file[0] == '/') return file;
#endif    
    return make_full_path (p, server_root, file);
}

void process_resource_config(server_rec *s, char *fname, pool *p, pool *ptemp)
{
    FILE *cfg;
    char *errmsg;
    cmd_parms parms;
    
    fname = server_root_relative (p, fname);
    
    /* GCC's initialization extensions are soooo nice here... */
    
    parms = default_parms;
    parms.config_file = fname;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF|OR_ALL)&~(OR_AUTHCFG|OR_LIMIT);
    
    if(!(cfg = fopen(fname, "r"))) {
        fprintf(stderr,"httpd: could not open document config file %s\n",
                fname);
        perror("fopen");
        exit(1);
    } 

    parms.infile = cfg;
    
    errmsg = srm_command_loop (&parms, s->lookup_defaults);
    
    if (errmsg) {
        fprintf (stderr, "Syntax error on line %d of %s:\n",
		 parms.config_line, fname);
	fprintf (stderr, "%s\n", errmsg);
	exit(1);
    }
    
    fclose(cfg);
}


int parse_htaccess(void **result, request_rec *r, int override,
		   char *d, char *filename)
{
    FILE *f;
    cmd_parms parms;
    char *errmsg;
    const struct htaccess_result *cache;
    struct htaccess_result *new;
    void *dc;

/* firstly, search cache */
    for (cache=r->htaccess; cache != NULL; cache=cache->next)
	if (cache->override == override && strcmp(cache->dir, d) == 0)
	{
	    if (cache->htaccess != NULL) *result = cache->htaccess;
	    return OK;
	}

    parms = default_parms;
    parms.override = override;
    parms.pool = r->pool;
    parms.temp_pool = r->pool;
    parms.server = r->server;
    parms.path = d;

    if((f=pfopen(r->pool, filename, "r"))) {
        dc = create_per_dir_config (r->pool);
	
        parms.infile = f;
	parms.config_file = filename;

	errmsg = srm_command_loop (&parms, dc);
	
        pfclose(r->pool, f);

	if (errmsg) {
	    log_reason (errmsg, filename, r);
	    return SERVER_ERROR;
	}
	
	*result = dc;
    } else
	dc = NULL;

/* cache it */
    new = palloc(r->pool, sizeof(struct htaccess_result));
    new->dir = pstrdup(r->pool, d);
    new->override = override;
    new->htaccess = dc;
/* add to head of list */
    new->next = r->htaccess;
    r->htaccess = new;

    return OK;
}

/*****************************************************************
 *
 * Virtual host stuff; note that the commands that invoke this stuff
 * are with the command table in http_core.c.
 */

server_rec *init_virtual_host (pool *p, char *hostname)
{
    server_rec *s = (server_rec *)pcalloc (p, sizeof (server_rec));

#ifdef RLIMIT_NOFILE
    struct rlimit limits;

    getrlimit ( RLIMIT_NOFILE, &limits );
    if ( limits.rlim_cur < limits.rlim_max ) {
      limits.rlim_cur += 2;
      if ( setrlimit ( RLIMIT_NOFILE, &limits ) < 0 )
	fprintf (stderr, "Cannot exceed hard limit for open files");
    }
#endif

    s->server_admin = NULL;
    s->server_hostname = NULL; 
    s->error_fname = NULL;
    s->srm_confname = NULL;
    s->access_confname = NULL;
    s->timeout = 0;
    s->keep_alive_timeout = 0;
    s->keep_alive = -1;
    s->host_addr.s_addr = get_virthost_addr (hostname, &s->host_port);
    s->port = s->host_port;  /* set them the same, by default */
    s->next = NULL;

    s->is_virtual = 1;
    s->virthost = pstrdup(p, hostname);
    s->names = NULL;

    s->module_config = create_empty_config (p);
    s->lookup_defaults = create_per_dir_config (p);
    
    return s;
}

int is_virtual_server (server_rec *s)
{
    return s->is_virtual;
}

void fixup_virtual_hosts (pool *p, server_rec *main_server)
{
    server_rec *virt;

    for (virt = main_server->next; virt; virt = virt->next) {
	merge_server_configs (p, main_server->module_config,
			      virt->module_config);
	
	virt->lookup_defaults =
	    merge_per_dir_configs (p, main_server->lookup_defaults,
				   virt->lookup_defaults);

	if (virt->port == 0)
	    virt->port = main_server->port;

	if (virt->server_admin == NULL)
	    virt->server_admin = main_server->server_admin;

	if (virt->srm_confname == NULL)
	    virt->srm_confname = main_server->srm_confname;

	if (virt->access_confname == NULL)
	    virt->access_confname = main_server->access_confname;

	if (virt->timeout == 0)
	    virt->timeout = main_server->timeout;

	if (virt->keep_alive_timeout == 0)
	    virt->keep_alive_timeout = main_server->keep_alive_timeout;

	if (virt->keep_alive == -1)
	    virt->keep_alive = main_server->keep_alive;
    }
}

/*****************************************************************
 *
 * Getting *everything* configured... 
 */

void init_config_globals (pool *p)
{
    /* ServerRoot, server_confname set in httpd.c */
    
    standalone = 1;
    user_name = DEFAULT_USER;
    user_id = uname2id(DEFAULT_USER);
    group_id = gname2id(DEFAULT_GROUP);
    daemons_to_start = DEFAULT_START_DAEMON;
    daemons_min_free = DEFAULT_MIN_FREE_DAEMON;
    daemons_max_free = DEFAULT_MAX_FREE_DAEMON;
    daemons_limit = HARD_SERVER_LIMIT;
    pid_fname = DEFAULT_PIDLOG;
    scoreboard_fname = DEFAULT_SCOREBOARD;
    max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    bind_address.s_addr = htonl(INADDR_ANY);
    listeners = NULL;
}

server_rec *init_server_config(pool *p)
{
    server_rec *s = (server_rec *)pcalloc (p, sizeof (server_rec));

    s->port = DEFAULT_PORT;
    s->server_admin = DEFAULT_ADMIN;
    s->server_hostname = NULL; 
    s->error_fname = DEFAULT_ERRORLOG;
    s->srm_confname = RESOURCE_CONFIG_FILE;
    s->access_confname = ACCESS_CONFIG_FILE;
    s->timeout = DEFAULT_TIMEOUT;
    s->keep_alive_timeout = DEFAULT_KEEPALIVE_TIMEOUT;
    s->keep_alive = DEFAULT_KEEPALIVE;
    s->next = NULL;
    s->host_addr.s_addr = htonl (INADDR_ANY); /* NOT virtual host;
					       * don't match any real network
					       * interface.
					       */
    s->host_port = 0; /* matches any port */

    s->module_config = create_server_config (p, s);
    s->lookup_defaults = create_default_per_dir_config (p);
    
    return s;
}

server_rec *read_config(pool *p, pool *ptemp, char *confname)
{
    server_rec *s = init_server_config(p);
    module *m;
    
    init_config_globals(p);
    
    /* All server-wide config files now have the SAME syntax... */
    
    process_resource_config (s, confname, p, ptemp);
    process_resource_config (s, s->srm_confname, p, ptemp);
    process_resource_config (s, s->access_confname, p, ptemp);
    
    fixup_virtual_hosts (p, s);
    
    for (m = top_module; m; m = m->next)
        if (m->init)
	    (*m->init) (s, p);
    
    return s;
}

