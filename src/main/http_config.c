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
 * http_config.c: once was auxillary functions for reading httpd's config
 * file and converting filenames into a namespace
 *
 * Rob McCool 
 * 
 * Wall-to-wall rewrite for Apache... commands which are part of the
 * server core can now be found next door in "http_core.c".  Now contains
 * general command loop, and functions which do bookkeeping for the new
 * Apache config stuff (modules and configuration vectors).
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
#include "explain.h"

DEF_Explain

/****************************************************************
 *
 * We begin with the functions which deal with the linked list
 * of modules which control just about all of the server operation.
 */

/* num_modules is the number of currently active modules.  */
static int num_modules = 0;    
/* total_modules is the number of modules linked in.  */
static int total_modules = 0;
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
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * total_modules);
   return (void *)conf_vector;
}

void *
create_default_per_dir_config (pool *p)
{
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * (total_modules+DYNAMIC_MODULE_LIMIT));
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
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * total_modules);
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
   void **conf_vector = (void **)pcalloc(p, sizeof(void*) * (total_modules+DYNAMIC_MODULE_LIMIT));
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

#ifdef EXPLAIN

struct
    {
    int offset;
    char *method;
    } aMethods[]=
    {
#define m(meth)	{ XtOffsetOf(module,meth),#meth }
    m(translate_handler),
    m(check_user_id),
    m(auth_checker),
    m(type_checker),
    m(fixer_upper),
    m(logger),
    { -1,"?" },
#undef m
    };

char *ShowMethod(module *modp,int offset)
    {
    int n;
    static char buf[200];

    for(n=0 ; aMethods[n].offset >= 0 ; ++n)
	if(aMethods[n].offset == offset)
	    break;
    ap_snprintf(buf, sizeof(buf), "%s:%s",modp->name,aMethods[n].method);
    return buf;
    }
#else
#define ShowMethod(modp,offset)
#endif

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
           int result;

           Explain1("Run %s",ShowMethod(modp,offset));
	   result = (*mod_handler)(r);

	   Explain2("%s returned %d",ShowMethod(modp,offset),result);
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

int header_parse (request_rec *r) {
    return run_method (r, XtOffsetOf (module, header_parser), 1);
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
   char *handler, *p; 

   if ((p = strchr(content_type, ';')) != NULL) {  /* MIME type arguments */
       while (p > content_type && p[-1] == ' ') --p; /* strip trailing spaces */
       content_type = pstrndup(r->pool, content_type, p - content_type);
   }
   handler = r->handler ? r->handler : content_type;
  
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

    /* At some point, we may want to offer back-compatibility for
     * loading modules that are for older versions of Apache. For now,
     * though, we don't.
     */

    if (m->version != MODULE_MAGIC_NUMBER) {
	fprintf(stderr, "httpd: module \"%s\" is not compatible with this "
		        "version of Apache.\n", m->name);
	fprintf(stderr, "Please contact the author for the correct version.\n");
	exit(1);
    }

    if (m->next == NULL) {
        m->next = top_module;
	top_module = m;
    }
    if (m->module_index == -1) {
	m->module_index = num_modules++;
    }
}

void setup_prelinked_modules ()
{
    extern module *prelinked_modules[], *preloaded_modules[];
    module **m;

    /* First, set all module indices, and init total_modules.  */
    total_modules = 0;
    for (m = preloaded_modules; *m; ++m, ++total_modules) {
        (*m)->module_index = total_modules;
    }

    for (m = prelinked_modules; *m; ++m) {
        add_module (*m);
    }
}

const char *find_module_name (module *m)
{
    return m->name;
}

module *find_linked_module (const char *name)
{
    module *modp;

    for (modp = top_module; modp; modp = modp->next) {
        if (strcmp(modp->name, name) == 0)
            return modp;
    }
    return NULL;
}

/* Add a named module.  Returns 1 if module found, 0 otherwise.  */
int add_named_module (const char *name)
{
    extern module *preloaded_modules[];
    module *modp;
    int i = 0;

    for (modp = preloaded_modules[i]; modp; modp = preloaded_modules[++i]) {
        if (strcmp(modp->name, name) == 0) {
	    /* Only add modules that are not already enabled.  */
	    if (modp->next == NULL) {
	        add_module(modp);
	    }
	    return 1;
	}
    }

    return 0;
}

/* Clear the internal list of modules, in preparation for starting over. */
void clear_module_list ()
{
    module **m = &top_module;
    module **next_m;

    while (*m) {
	next_m = &((*m)->next);
	*m = NULL;
	m = next_m;
    }

    num_modules = 0;

    /* This is required; so we add it always.  */
    add_named_module ("http_core.c");
}

/*****************************************************************
 *
 * Resource, access, and .htaccess config files now parsed by a common
 * command loop.
 *
 * Let's begin with the basics; parsing the line and
 * invoking the function...
 */

const char *invoke_cmd(const command_rec *cmd, cmd_parms *parms, void *mconfig,
		 const char *args)
{
    char *w, *w2, *w3;
    const char *errmsg;

    if ((parms->override & cmd->req_override) == 0)
        return pstrcat (parms->pool, cmd->name, " not allowed here", NULL);
    
    parms->info = cmd->cmd_data;
    parms->cmd = cmd;
    
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
	
    case TAKE12:

	w = getword_conf (parms->pool, &args);
	w2 = getword_conf (parms->pool, &args);
	
	if (*w == '\0' || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes 1-2 arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w, *w2 ? w2 : NULL);
	
    case TAKE3:

	w = getword_conf (parms->pool, &args);
	w2 = getword_conf (parms->pool, &args);
	w3 = getword_conf (parms->pool, &args);
	
	if (*w == '\0' || *w2 == '\0' || *w3 == '\0' || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w, w2, w3);
	
    case TAKE23:

	w = getword_conf (parms->pool, &args);
	w2 = getword_conf (parms->pool, &args);
	w3 = *args ? getword_conf (parms->pool, &args) : NULL;
	
	if (*w == '\0' || *w2 == '\0' || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes two or three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w, w2, w3);
	
    case TAKE123:

	w = getword_conf (parms->pool, &args);
	w2 = *args ? getword_conf (parms->pool, &args) : NULL;
	w3 = *args ? getword_conf (parms->pool, &args) : NULL;
	
	if (*w == '\0' || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes one, two or three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w, w2, w3);
	
    case TAKE13:

	w = getword_conf (parms->pool, &args);
	w2 = *args ? getword_conf (parms->pool, &args) : NULL;
	w3 = *args ? getword_conf (parms->pool, &args) : NULL;
	
	if (*w == '\0' || (*w2 && !w3) || *args != 0) 
	    return pstrcat (parms->pool, cmd->name, " takes one or three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return (*cmd->func) (parms, mconfig, w, w2, w3);
	
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

	if (*w == '\0' || (strcasecmp(w, "on") && strcasecmp (w, "off")))
	    return pstrcat (parms->pool, cmd->name, " must be On or Off",
			    NULL);

	return (*cmd->func) (parms, mconfig, strcasecmp (w, "off") != 0);

    default:

	return pstrcat (parms->pool, cmd->name,
			" is improperly configured internally (server bug)",
			NULL);
    }
}

const command_rec *find_command (const char *name, const command_rec *cmds)
{
    while (cmds->name) 
        if (!strcasecmp (name, cmds->name))
	    return cmds;
	else
	    ++cmds;

    return NULL;
}
    
const command_rec *find_command_in_modules (const char *cmd_name, module **mod)
{
   const command_rec *cmdp;
   module *modp;

   for (modp = *mod; modp; modp = modp->next) 
       if (modp->cmds && (cmdp = find_command (cmd_name, modp->cmds))) {
	   *mod = modp;
	   return cmdp;
       }

   return NULL;
}

const char *handle_command (cmd_parms *parms, void *config, const char *l)
{
    const char *args, *cmd_name, *retval;
    const command_rec *cmd;
    module *mod = top_module;

    ++parms->config_line;
    if((l[0] == '#') || (!l[0])) return NULL;
	
    args = l;
    cmd_name = getword_conf (parms->temp_pool, &args);
    if (*cmd_name == '\0') return NULL;
	
    do {
	if (!(cmd = find_command_in_modules (cmd_name, &mod))) {
	    return pstrcat (parms->pool, "Invalid command ", cmd_name, NULL);
	}
	else {
	    void *mconfig = get_module_config (config, mod);
	    void *sconfig =
		get_module_config (parms->server->module_config, mod);
	    
	    if (!mconfig && mod->create_dir_config) {
		mconfig = (*mod->create_dir_config) (parms->pool, parms->path);
		set_module_config (config, mod, mconfig);
	    }
	    
	    if (!sconfig && mod->create_server_config) {
		sconfig =
		    (*mod->create_server_config)(parms->pool, parms->server);
		set_module_config (parms->server->module_config, mod, sconfig);
	    }
	    
	    retval = invoke_cmd (cmd, parms, mconfig, args);
	    mod = mod->next;	/* Next time around, skip this one */
	}
    } while (retval && !strcmp(retval, DECLINE_CMD));

    return retval;
}

const char *srm_command_loop (cmd_parms *parms, void *config)
{
    char l[MAX_STRING_LEN];
    
    while (!(cfg_getline (l, MAX_STRING_LEN, parms->infile))) {
	const char *errmsg = handle_command (parms, config, l);
	if (errmsg) return errmsg;
    }

    return NULL;
}

/*
 * Generic command functions...
 */

const char *set_string_slot (cmd_parms *cmd, char *struct_ptr, char *arg)
{
    /* This one's pretty generic... */
  
    int offset = (int)cmd->info; 
    *(char **)(struct_ptr + offset) = pstrdup (cmd->pool, arg);
    return NULL;
}

const char *set_flag_slot (cmd_parms *cmd, char *struct_ptr, int arg)
{
    /* This one's pretty generic too... */
  
    int offset = (int)cmd->info; 
    *(int *)(struct_ptr + offset) = arg ? 1 : 0;
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
    const char *errmsg;
    cmd_parms parms;
    struct stat finfo;
    
    fname = server_root_relative (p, fname);

    if (!(strcmp(fname, server_root_relative(p, RESOURCE_CONFIG_FILE))) ||
	!(strcmp(fname, server_root_relative(p, ACCESS_CONFIG_FILE)))) {
	if (stat(fname, &finfo) == -1)
	    return;
    }
    
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
    const char *errmsg;
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

/*
 * Parses a host of the form <address>[:port]
 * paddr is used to create a list in the order of input
 * **paddr is the ->next pointer of the last entry (or s->addrs)
 * *paddr is the variable used to keep track of **paddr between calls
 * port is the default port to assume
 */
static void get_addresses (pool *p, char *w, server_addr_rec ***paddr, int port)
{
    struct hostent *hep;
    unsigned long my_addr;
    server_addr_rec *sar;
    char *t;
    int i, is_an_ip_addr;

    if( *w == 0 ) return;

    t = strchr(w, ':');
    if (t) {
	if( strcmp(t+1,"*") == 0 ) {
	    port = 0;
	} else if( (i = atoi(t+1)) ) {
	    port = i;
	} else {
	    fprintf( stderr, "Port must be numeric\n" );
	}
	*t = 0;
    }

    is_an_ip_addr = 0;
    if (strcmp(w, "*") == 0) {
	my_addr = htonl(INADDR_ANY);
	is_an_ip_addr = 1;
    } else if( strcmp(w, "_default_") == 0
	    || strcmp(w, "255.255.255.255") == 0 ) {
	my_addr = DEFAULT_VHOST_ADDR;
	is_an_ip_addr = 1;
    } else if(
#ifdef DGUX
	    ( my_addr = inet_network(w) )
#else
	    ( my_addr = inet_addr(w) )
#endif
	    != INADDR_NONE ) {
	is_an_ip_addr = 1;
    }
    if( is_an_ip_addr ) {
	sar = pcalloc( p, sizeof( server_addr_rec ) );
	**paddr = sar;
	*paddr = &sar->next;
	sar->host_addr.s_addr = my_addr;
	sar->host_port = port;
	sar->virthost = pstrdup(p, w);
	if (t != NULL) *t = ':';
	return;
    }

    hep = gethostbyname(w);

    if ((!hep) || (hep->h_addrtype != AF_INET || !hep->h_addr_list[0])) {
	fprintf (stderr, "Cannot resolve host name %s --- exiting!\n", w);
	exit(1);
    }

    for( i = 0; hep->h_addr_list[i]; ++i ) {
	sar = pcalloc( p, sizeof( server_addr_rec ) );
	**paddr = sar;
	*paddr = &sar->next;
	sar->host_addr = *(struct in_addr *)hep->h_addr_list[i];
	sar->host_port = port;
	sar->virthost = pstrdup(p, w);
    }

    if (t != NULL) *t = ':';
}

server_rec *init_virtual_host (pool *p, const char *hostname,
				server_rec *main_server)
{
    server_rec *s = (server_rec *)pcalloc (p, sizeof (server_rec));
    server_addr_rec **addrs;

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
    s->keep_alive_max = -1;
    s->error_log = main_server->error_log;
    /* start the list of addreses */
    addrs = &s->addrs;
    while( hostname[0] ) {
	get_addresses( p, getword_conf( p, &hostname ), &addrs,
	    main_server->port );
    }
    /* terminate the list */
    *addrs = NULL;
    if( s->addrs == NULL ) {
	fprintf( stderr, "virtual host must have at least one address\n" );
	exit(1);
    }
    s->port = s->addrs->host_port;  /* set them the same, by default */
    s->next = NULL;

    s->is_virtual = 1;
    s->names = NULL;

    s->module_config = create_empty_config (p);
    s->lookup_defaults = create_per_dir_config (p);
    
    s->server_uid = user_id;
    s->server_gid = group_id;

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

	if (virt->keep_alive_max == -1)
	    virt->keep_alive_max = main_server->keep_alive_max;

	if (virt->send_buffer_size == 0)
		virt->send_buffer_size = main_server->send_buffer_size;
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
    s->error_log = stderr;
    s->srm_confname = RESOURCE_CONFIG_FILE;
    s->access_confname = ACCESS_CONFIG_FILE;
    s->timeout = DEFAULT_TIMEOUT;
    s->keep_alive_timeout = DEFAULT_KEEPALIVE_TIMEOUT;
    s->keep_alive_max = DEFAULT_KEEPALIVE;
    s->keep_alive = 1;
    s->next = NULL;
    s->addrs = pcalloc(p, sizeof (server_addr_rec));
    s->addrs->host_addr.s_addr = htonl (INADDR_ANY); /* NOT virtual host;
					       * don't match any real network
					       * interface.
					       */
    s->addrs->host_port = 0; /* matches any port */

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

/********************************************************************
 * Configuration directives are restricted in terms of where they may
 * appear in the main configuration files and/or .htaccess files according
 * to the bitmask req_override in the command_rec structure.
 * If any of the overrides set in req_override are also allowed in the
 * context in which the command is read, then the command is allowed.
 * The context is determined as follows:
 *
 *    inside *.conf --> override = (RSRC_CONF|OR_ALL)&~(OR_AUTHCFG|OR_LIMIT);
 *    within <Directory> or <Location> --> override = OR_ALL|ACCESS_CONF;
 *    within .htaccess --> override = AllowOverride for current directory;
 *
 * the result is, well, a rather confusing set of possibilities for when
 * a particular directive is allowed to be used.  This procedure prints
 * in English where the given (pc) directive can be used.
 */
void show_overrides(command_rec *pc, module *pm)
{
    int n = 0;
    
    printf("\tAllowed in *.conf ");
    if ((pc->req_override & (OR_OPTIONS|OR_FILEINFO|OR_INDEXES)) ||
        ((pc->req_override & RSRC_CONF) &&
         ((pc->req_override & (ACCESS_CONF|OR_AUTHCFG|OR_LIMIT)))))
        printf("anywhere");
    else if (pc->req_override & RSRC_CONF)
        printf("only outside <Directory> or <Location>");
    else 
        printf("only inside <Directory> or <Location>");

    /* Warn if the directive is allowed inside <Directory> or .htaccess
     * but module doesn't support per-dir configuration */

    if ((pc->req_override & (OR_ALL|ACCESS_CONF)) && !pm->create_dir_config)
        printf(" [no per-dir config]");

    if (pc->req_override & OR_ALL) {
        printf(" and in .htaccess\n\twhen AllowOverride");

        if ((pc->req_override & OR_ALL) == OR_ALL)
            printf(" isn't None");
        else {
            printf(" includes ");

            if (pc->req_override & OR_AUTHCFG) {
                if (n++) printf(" or ");
                printf("AuthConfig");
            }
            if (pc->req_override & OR_LIMIT) {
                if (n++) printf(" or ");
                printf("Limit");
            }
            if (pc->req_override & OR_OPTIONS) {
                if (n++) printf(" or ");
                printf("Options");
            }
            if (pc->req_override & OR_FILEINFO) {
                if (n++) printf(" or ");
                printf("FileInfo");
            }
            if (pc->req_override & OR_INDEXES) {
                if (n++) printf(" or ");
                printf("Indexes");
            }
        }
    }
    printf("\n");
}

/* Show the preloaded configuration directives, the help string explaining
 * the directive arguments, in what module they are handled, and in
 * what parts of the configuration they are allowed.  Used for httpd -h.
 */
void show_directives()
{
    extern module *preloaded_modules[];
    command_rec *pc;
    int n;
    
    for (n = 0; preloaded_modules[n]; ++n)
        for (pc = preloaded_modules[n]->cmds; pc && pc->name; ++pc) {
            printf("%s\n", pc->name);
            if (pc->errmsg)
                printf("\t%s\n", pc->errmsg);
            printf("\t%s\n", preloaded_modules[n]->name);
            show_overrides(pc, preloaded_modules[n]);
        }
}

/* Show the preloaded module names.  Used for httpd -l. */
void show_modules()
{
    extern module *preloaded_modules[];
    int n;
 
    printf ("Compiled-in modules:\n");
    for (n = 0; preloaded_modules[n]; ++n)
        printf ("  %s\n", preloaded_modules[n]->name);
}

