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

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"	/* For index_of_response().  Grump. */
#include "http_request.h"
#include "http_conf_globals.h"
#include "http_vhost.h"
#include "http_main.h"		/* For the default_handler below... */
#include "http_log.h"
#include "rfc1413.h"
#include "util_md5.h"
#include "scoreboard.h"
#include "fnmatch.h"

#ifdef USE_MMAP_FILES
#include <unistd.h>
#include <sys/mman.h>

/* mmap support for static files based on ideas from John Heidemann's
 * patch against 1.0.5.  See
 * <http://www.isi.edu/~johnh/SOFTWARE/APACHE/index.html>.
 */

/* Files have to be at least this big before they're mmap()d.  This is to
 * deal with systems where the expense of doing an mmap() and an munmap()
 * outweighs the benefit for small files.
 */
#ifndef MMAP_THRESHOLD
#ifdef SUNOS4
#define MMAP_THRESHOLD		(8*1024)
#else
#define MMAP_THRESHOLD		0
#endif
#endif
#endif

/* Server core module... This module provides support for really basic
 * server operations, including options and commands which control the
 * operation of other modules.  Consider this the bureaucracy module.
 *
 * The core module also defines handlers, etc., do handle just enough
 * to allow a server with the core module ONLY to actually serve documents
 * (though it slaps DefaultType on all of 'em); this was useful in testing,
 * but may not be worth preserving.
 *
 * This file could almost be mod_core.c, except for the stuff which affects
 * the http_conf_globals.
 */

void *create_core_dir_config (pool *a, char *dir)
{
    core_dir_config *conf =
      (core_dir_config *)pcalloc(a, sizeof(core_dir_config));
  
    if (!dir || dir[strlen(dir) - 1] == '/') conf->d = dir;
    else if (strncmp(dir,"proxy:",6)==0) conf->d = pstrdup (a, dir);
    else conf->d = pstrcat (a, dir, "/", NULL);
    conf->d_is_fnmatch = conf->d ? (is_fnmatch (conf->d) != 0) : 0;
    conf->d_components = conf->d ? count_dirs (conf->d) : 0;

    conf->opts = dir ? OPT_UNSET : OPT_ALL;
    conf->opts_add = conf->opts_remove = OPT_NONE;
    conf->override = dir ? OR_UNSET : OR_ALL;

    conf->content_md5 = 2;

    conf->hostname_lookups = HOSTNAME_LOOKUP_UNSET;
    conf->do_rfc1413 = DEFAULT_RFC1413 | 2;  /* set bit 1 to indicate default */
    conf->satisfy = SATISFY_NOSPEC;

#ifdef RLIMIT_CPU
    conf->limit_cpu = NULL;
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)
    conf->limit_mem = NULL;
#endif
#ifdef RLIMIT_NPROC
    conf->limit_nproc = NULL;
#endif

    conf->sec = make_array (a, 2, sizeof(void *));

    return (void *)conf;
}

void *merge_core_dir_configs (pool *a, void *basev, void *newv)
{
    core_dir_config *base = (core_dir_config *)basev;
    core_dir_config *new = (core_dir_config *)newv;
    core_dir_config *conf =
      (core_dir_config *)palloc (a, sizeof(core_dir_config));
    int i;
  
    memcpy ((char *)conf, (const char *)base, sizeof(core_dir_config));
    if( base->response_code_strings ) {
	conf->response_code_strings = palloc(a,
	    sizeof(*conf->response_code_strings) * RESPONSE_CODES );
	memcpy( conf->response_code_strings, base->response_code_strings,
	    sizeof(*conf->response_code_strings) * RESPONSE_CODES );
    }
    
    conf->d = new->d;
    conf->d_is_fnmatch = new->d_is_fnmatch;
    conf->d_components = new->d_components;
    conf->r = new->r;
    
    if (new->opts != OPT_UNSET) conf->opts = new->opts;
    if (new->opts_add) conf->opts |= new->opts_add;
    if (new->opts_remove) conf->opts &= ~(new->opts_remove);

    if (new->override != OR_UNSET) conf->override = new->override;
    if (new->default_type) conf->default_type = new->default_type;
    
    if (new->auth_type) conf->auth_type = new->auth_type;
    if (new->auth_name) conf->auth_name = new->auth_name;
    if (new->requires) conf->requires = new->requires;

    if( new->response_code_strings ) {
	if( conf->response_code_strings == NULL ) {
	    conf->response_code_strings = palloc(a,
		sizeof(*conf->response_code_strings) * RESPONSE_CODES );
	    memcpy( conf->response_code_strings, new->response_code_strings,
		sizeof(*conf->response_code_strings) * RESPONSE_CODES );
	} else {
	    for (i = 0; i < RESPONSE_CODES; ++i)
		if (new->response_code_strings[i] != NULL)
		conf->response_code_strings[i] = new->response_code_strings[i];
	}
    }
    if (new->hostname_lookups != HOSTNAME_LOOKUP_UNSET)
	conf->hostname_lookups = new->hostname_lookups;
    if ((new->do_rfc1413 & 2) == 0) conf->do_rfc1413 = new->do_rfc1413;
    if ((new->content_md5 & 2) == 0) conf->content_md5 = new->content_md5;

#ifdef RLIMIT_CPU
    if (new->limit_cpu) conf->limit_cpu = new->limit_cpu;
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)
    if (new->limit_mem) conf->limit_mem = new->limit_mem;
#endif
#ifdef RLIMIT_NPROC    
    if (new->limit_nproc) conf->limit_nproc = new->limit_nproc;
#endif

    conf->sec = append_arrays (a, base->sec, new->sec);

    if (new->satisfy != SATISFY_NOSPEC) conf->satisfy = new->satisfy;
    return (void*)conf;
}

void *create_core_server_config (pool *a, server_rec *s)
{
    core_server_config *conf =
      (core_server_config *)pcalloc(a, sizeof(core_server_config));
    int is_virtual = s->is_virtual;
  
    conf->access_name = is_virtual ? NULL : DEFAULT_ACCESS_FNAME;
    conf->document_root = is_virtual ? NULL : DOCUMENT_LOCATION;
    conf->sec = make_array (a, 40, sizeof(void *));
    conf->sec_url = make_array (a, 40, sizeof(void *));
    
    return (void *)conf;
}

void *merge_core_server_configs (pool *p, void *basev, void *virtv)
{
    core_server_config *base = (core_server_config *)basev;
    core_server_config *virt = (core_server_config *)virtv;
    core_server_config *conf = 
	(core_server_config *)pcalloc(p, sizeof(core_server_config));

    *conf = *virt;
    if (!conf->access_name) conf->access_name = base->access_name;
    if (!conf->document_root) conf->document_root = base->document_root;
    conf->sec = append_arrays (p, base->sec, virt->sec);
    conf->sec_url = append_arrays (p, base->sec_url, virt->sec_url);

    return conf;
}

/* Add per-directory configuration entry (for <directory> section);
 * these are part of the core server config.
 */

void add_per_dir_conf (server_rec *s, void *dir_config)
{
    core_server_config *sconf = get_module_config (s->module_config,
						   &core_module);
    void **new_space = (void **) push_array (sconf->sec);
    
    *new_space = dir_config;
}

void add_per_url_conf (server_rec *s, void *url_config)
{
    core_server_config *sconf = get_module_config (s->module_config,
						   &core_module);
    void **new_space = (void **) push_array (sconf->sec_url);
    
    *new_space = url_config;
}

void add_file_conf (core_dir_config *conf, void *url_config)
{
    void **new_space = (void **) push_array (conf->sec);
    
    *new_space = url_config;
}

/* core_reorder_directories reorders the directory sections such that the
 * 1-component sections come first, then the 2-component, and so on, finally
 * followed by the "special" sections.  A section is "special" if it's a regex,
 * or if it doesn't start with / -- consider proxy: matching.  All movements
 * are in-order to preserve the ordering of the sections from the config files.
 * See directory_walk().
 */

#if defined(__EMX__) || defined(WIN32)
#define IS_SPECIAL(entry_core)	\
    ((entry_core)->r != NULL \
	|| ((entry_core)->d[0] != '/' && (entry_core)->d[1] != ':'))
#else
#define IS_SPECIAL(entry_core)	\
    ((entry_core)->r != NULL || (entry_core)->d[0] != '/')
#endif

/* We need to do a stable sort, qsort isn't stable.  So to make it stable
 * we'll be maintaining the original index into the list, and using it
 * as the minor key during sorting.  The major key is the number of
 * components (where a "special" section has infinite components).
 */
struct reorder_sort_rec {
    void *elt;
    int orig_index;
};

static int reorder_sorter (const void *va, const void *vb)
{
    const struct reorder_sort_rec *a = va;
    const struct reorder_sort_rec *b = vb;
    core_dir_config *core_a;
    core_dir_config *core_b;

    core_a = (core_dir_config *)get_module_config (a->elt, &core_module);
    core_b = (core_dir_config *)get_module_config (b->elt, &core_module);
    if (IS_SPECIAL(core_a)) {
	if (!IS_SPECIAL(core_b)) {
	    return 1;
	}
    } else if (IS_SPECIAL(core_b)) {
	return -1;
    } else {
	/* we know they're both not special */
	if (core_a->d_components < core_b->d_components) {
	    return -1;
	} else if (core_a->d_components > core_b->d_components) {
	    return 1;
	}
    }
    /* Either they're both special, or they're both not special and have the
     * same number of components.  In any event, we now have to compare
     * the minor key. */
    return a->orig_index - b->orig_index;
}

void core_reorder_directories (pool *p, server_rec *s)
{
    core_server_config *sconf;
    array_header *sec;
    struct reorder_sort_rec *sortbin;
    int nelts;
    void **elts;
    int i;

    /* XXX: we are about to waste some ram ... we will build a new array
     * and we need some scratch space to do it.  The old array and the
     * scratch space are never freed.
     */
    sconf = get_module_config (s->module_config, &core_module);
    sec = sconf->sec;
    nelts = sec->nelts;
    elts = (void **)sec->elts;

    /* build our sorting space */
    sortbin = palloc (p, sec->nelts * sizeof (*sortbin));
    for (i = 0; i < nelts; ++i) {
	sortbin[i].orig_index = i;
	sortbin[i].elt = elts[i];
    }

    qsort (sortbin, nelts, sizeof (*sortbin), reorder_sorter);

    /* and now build a new array */
    sec = make_array (p, nelts, sizeof (void *));
    for (i = 0; i < nelts; ++i) {
	*(void **)push_array (sec) = sortbin[i].elt;
    }

    sconf->sec = sec;
}

/*****************************************************************
 *
 * There are some elements of the core config structures in which
 * other modules have a legitimate interest (this is ugly, but necessary
 * to preserve NCSA back-compatibility).  So, we have a bunch of accessors
 * here...
 */

API_EXPORT(int) allow_options (request_rec *r)
{
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    return conf->opts; 
} 

API_EXPORT(int) allow_overrides (request_rec *r) 
{ 
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    return conf->override; 
} 

API_EXPORT(char *) auth_type (request_rec *r)
{
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    return conf->auth_type;
}

API_EXPORT(char *) auth_name (request_rec *r)
{
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    return conf->auth_name;
}

API_EXPORT(char *) default_type (request_rec *r)
{
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    return conf->default_type ? conf->default_type : DEFAULT_CONTENT_TYPE;
}

API_EXPORT(char *) document_root (request_rec *r) /* Don't use this!!! */
{
    core_server_config *conf = 
      (core_server_config *)get_module_config(r->server->module_config,
					      &core_module); 

    return conf->document_root;
}

API_EXPORT(array_header *) requires (request_rec *r)
{
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    return conf->requires;
}

API_EXPORT(int) satisfies (request_rec *r)
{
    core_dir_config *conf =
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module);

    return conf->satisfy;
}

/* Should probably just get rid of this... the only code that cares is
 * part of the core anyway (and in fact, it isn't publicised to other
 * modules).
 */

char *response_code_string (request_rec *r, int error_index)
{
    core_dir_config *conf = 
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module); 

    if( conf->response_code_strings == NULL ) {
	return NULL;
    }
    return conf->response_code_strings[error_index];
}


/* Code from Harald Hanche-Olsen <hanche@imf.unit.no> */
static ap_inline void do_double_reverse (conn_rec *conn)
{
    struct hostent *hptr;

    if (conn->double_reverse) {
	/* already done */
	return;
    }
    if (conn->remote_host == NULL || conn->remote_host[0] == '\0') {
	/* single reverse failed, so don't bother */
	conn->double_reverse = -1;
	return;
    }
    hptr = gethostbyname(conn->remote_host);
    if (hptr) {
	char **haddr;

	for (haddr = hptr->h_addr_list; *haddr; haddr++) {
	    if (((struct in_addr *)(*haddr))->s_addr
		== conn->remote_addr.sin_addr.s_addr) {
		conn->double_reverse = 1;
		return;
	    }
	}
    }
    conn->double_reverse = -1;
}

API_EXPORT(const char *) get_remote_host(conn_rec *conn, void *dir_config, int type)
{
    struct in_addr *iaddr;
    struct hostent *hptr;
    int hostname_lookups;
#ifdef STATUS
    int old_stat = SERVER_UNKNOWN;
#endif

    /* If we haven't checked the host name, and we want to */
    if (dir_config) {
	hostname_lookups =
	    ((core_dir_config *)get_module_config(dir_config, &core_module))
		->hostname_lookups;
    } else {
	/* the default */
	hostname_lookups = HOSTNAME_LOOKUP_OFF;
    }

    if (type != REMOTE_NOLOOKUP
	&& conn->remote_host == NULL
	&& (type == REMOTE_DOUBLE_REV
	    || hostname_lookups != HOSTNAME_LOOKUP_OFF)) {
#ifdef STATUS
	old_stat = update_child_status(conn->child_num, SERVER_BUSY_DNS,
					    (request_rec*)NULL);
#endif /* STATUS */
	iaddr = &(conn->remote_addr.sin_addr);
	hptr = gethostbyaddr((char *)iaddr, sizeof(struct in_addr), AF_INET);
	if (hptr != NULL) {
	    conn->remote_host = pstrdup(conn->pool, (void *)hptr->h_name);
	    str_tolower (conn->remote_host);
	   
	    if (hostname_lookups == HOSTNAME_LOOKUP_DOUBLE) {
		do_double_reverse (conn);
		if (conn->double_reverse != 1) {
		    conn->remote_host = NULL;
		}
	    }
	}
	/* if failed, set it to the NULL string to indicate error */
	if (conn->remote_host == NULL) conn->remote_host = "";
    }
    if (type == REMOTE_DOUBLE_REV) {
	do_double_reverse (conn);
	if (conn->double_reverse == -1) {
	    return NULL;
	}
    }
#ifdef STATUS
    if (old_stat != SERVER_UNKNOWN) {
	(void)update_child_status(conn->child_num,old_stat,(request_rec*)NULL);
    }
#endif /* STATUS */

/*
 * Return the desired information; either the remote DNS name, if found,
 * or either NULL (if the hostname was requested) or the IP address
 * (if any identifier was requested).
 */
    if (conn->remote_host != NULL && conn->remote_host[0] != '\0')
	return conn->remote_host;
    else
    {
	if (type == REMOTE_HOST || type == REMOTE_DOUBLE_REV) return NULL;
	else return conn->remote_ip;
    }
}

API_EXPORT(const char *) get_remote_logname(request_rec *r)
{
    core_dir_config *dir_conf;

    if (r->connection->remote_logname != NULL)
	return r->connection->remote_logname;

/* If we haven't checked the identity, and we want to */
    dir_conf = (core_dir_config *)
	get_module_config(r->per_dir_config, &core_module);

    if (dir_conf->do_rfc1413 & 1)
	return rfc1413(r->connection, r->server);
    else
	return NULL;
}

/*****************************************************************
 *
 * Commands... this module handles almost all of the NCSA httpd.conf
 * commands, but most of the old srm.conf is in the the modules.
 */

const char *set_access_name (cmd_parms *cmd, void *dummy, char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = get_module_config (sconf, &core_module);
  
    conf->access_name = pstrdup(cmd->pool, arg);
    return NULL;
}

const char *set_document_root (cmd_parms *cmd, void *dummy, char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = get_module_config (sconf, &core_module);
  
    if (!is_directory (arg))
	if (cmd->server->is_virtual)
	    fprintf (stderr, "Warning: DocumentRoot [%s] does not exist\n", arg);
	else
	    return "DocumentRoot must be a directory";
    
    conf->document_root = arg;
    return NULL;
}

const char *set_error_document (cmd_parms *cmd, core_dir_config *conf,
				char *line)
{
    int error_number, index_number, idx500;
    char *w;
                
    /* 1st parameter should be a 3 digit number, which we recognize;
     * convert it into an array index
     */
  
    w = getword_conf_nc (cmd->pool, &line);
    error_number = atoi(w);

    idx500 = index_of_response(HTTP_INTERNAL_SERVER_ERROR);

    if (error_number == HTTP_INTERNAL_SERVER_ERROR)
        index_number = idx500;
    else if ((index_number = index_of_response(error_number)) == idx500)
        return pstrcat(cmd->pool, "Unsupported HTTP response code ", w, NULL);
                
    /* Store it... */

    if( conf->response_code_strings == NULL ) {
	conf->response_code_strings = pcalloc(cmd->pool,
	    sizeof(*conf->response_code_strings) * RESPONSE_CODES );
    }
    conf->response_code_strings[index_number] = pstrdup (cmd->pool, line);

    return NULL;
}

/* access.conf commands...
 *
 * The *only* thing that can appear in access.conf at top level is a
 * <Directory> section.  NB we need to have a way to cut the srm_command_loop
 * invoked by dirsection (i.e., <Directory>) short when </Directory> is seen.
 * We do that by returning an error, which dirsection itself recognizes and
 * discards as harmless.  Cheesy, but it works.
 */

const char *set_override (cmd_parms *cmd, core_dir_config *d, const char *l)
{
    char *w;
  
    d->override = OR_NONE;
    while(l[0]) {
        w = getword_conf (cmd->pool, &l);
	if(!strcasecmp(w,"Limit"))
	    d->override |= OR_LIMIT;
	else if(!strcasecmp(w,"Options"))
	    d->override |= OR_OPTIONS;
	else if(!strcasecmp(w,"FileInfo"))
            d->override |= OR_FILEINFO;
	else if(!strcasecmp(w,"AuthConfig"))
	    d->override |= OR_AUTHCFG;
	else if(!strcasecmp(w,"Indexes"))
            d->override |= OR_INDEXES;
	else if(!strcasecmp(w,"None"))
	    d->override = OR_NONE;
	else if(!strcasecmp(w,"All")) 
	    d->override = OR_ALL;
	else 
	    return pstrcat (cmd->pool, "Illegal override option ", w, NULL);
    }

    return NULL;
}

const char *set_options (cmd_parms *cmd, core_dir_config *d, const char *l)
{
    allow_options_t opt;
    int first = 1;
    char action;

    while(l[0]) {
        char *w = getword_conf(cmd->pool, &l);
	action = '\0';

	if (*w == '+' || *w == '-')
	    action = *(w++);
	else if (first) {
  	    d->opts = OPT_NONE;
            first = 0;
        }
	    
	if(!strcasecmp(w,"Indexes"))
	    opt = OPT_INDEXES;
	else if(!strcasecmp(w,"Includes"))
	    opt = OPT_INCLUDES;
	else if(!strcasecmp(w,"IncludesNOEXEC"))
	    opt = (OPT_INCLUDES | OPT_INCNOEXEC);
	else if(!strcasecmp(w,"FollowSymLinks"))
	    opt = OPT_SYM_LINKS;
	else if(!strcasecmp(w,"SymLinksIfOwnerMatch"))
	    opt = OPT_SYM_OWNER;
	else if(!strcasecmp(w,"execCGI"))
	    opt = OPT_EXECCGI;
	else if (!strcasecmp(w,"MultiViews"))
	    opt = OPT_MULTI;
	else if (!strcasecmp(w,"RunScripts")) /* AI backcompat. Yuck */
	    opt = OPT_MULTI|OPT_EXECCGI;
	else if(!strcasecmp(w,"None")) 
	    opt = OPT_NONE;
	else if(!strcasecmp(w,"All")) 
	    opt = OPT_ALL;
	else 
	    return pstrcat (cmd->pool, "Illegal option ", w, NULL);

	if (action == '-')
	    d->opts_remove |= opt;
	else if (action == '+')
	    d->opts_add |= opt;
	else
	  d->opts |= opt;
    }

    return NULL;
}

const char *satisfy (cmd_parms *cmd, core_dir_config *c, char *arg)
{
    if(!strcasecmp(arg,"all"))
        c->satisfy = SATISFY_ALL;
    else if(!strcasecmp(arg,"any"))
        c->satisfy = SATISFY_ANY;
    else
        return "Satisfy either 'any' or 'all'.";
    return NULL;
}

const char *require (cmd_parms *cmd, core_dir_config *c, char *arg)
{
    require_line *r;
  
    if (!c->requires)
        c->requires = make_array (cmd->pool, 2, sizeof(require_line));
    
    r = (require_line *)push_array (c->requires);
    r->requirement = pstrdup (cmd->pool, arg);
    r->method_mask = cmd->limited;
    return NULL;
}

const char *limit_section (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *limited_methods = getword(cmd->pool,&arg,'>');
    int limited = 0;
  
    if (cmd->limited > 0) return "Can't nest <Limit> sections";
    
    while(limited_methods[0]) {
        char *method = getword_conf (cmd->pool, &limited_methods);
	if(!strcasecmp(method,"GET")) limited |= (1 << M_GET);
	else if(!strcasecmp(method,"PUT")) limited |= (1 << M_PUT);
	else if(!strcasecmp(method,"POST")) limited |= (1 << M_POST);
	else if(!strcasecmp(method,"DELETE")) limited |= (1 << M_DELETE);
        else if(!strcasecmp(method,"CONNECT")) limited |= (1 << M_CONNECT);
	else if(!strcasecmp(method,"OPTIONS")) limited |= (1 << M_OPTIONS);
	else return "unknown method in <Limit>";
    }

    cmd->limited = limited;
    return NULL;
}

const char *endlimit_section (cmd_parms *cmd, void *dummy, void *dummy2)
{
    if (cmd->limited == -1) return "</Limit> unexpected";
    
    cmd->limited = -1;
    return NULL;
}

/*
 * When a section is not closed properly when end-of-file is reached,
 * then an error message should be printed:
 */
static const char *missing_endsection (pool *p, const char *secname, int nest)
{
    char rply[100];

    if (nest < 2)
	ap_snprintf(rply, sizeof rply, "Missing </%s> directive at end-of-file",
		    secname);
    else
	ap_snprintf(rply, sizeof rply, "%d missing </%s> directives at end-of-file",
		    nest, secname);

    return pstrdup(p, rply);
}

/* We use this in <DirectoryMatch> and <FilesMatch>, to ensure that 
 * people don't get bitten by wrong-cased regex matches
 */

#ifdef WIN32
#define USE_ICASE REG_ICASE
#else
#define USE_ICASE 0
#endif

static const char end_dir_magic[] = "</Directory> outside of any <Directory> section";

const char *end_dirsection (cmd_parms *cmd, void *dummy) {
    return end_dir_magic;
}

const char *dirsection (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *errmsg;
    char *endp = strrchr (arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    void *new_dir_conf = create_per_dir_config (cmd->pool);
    regex_t *r = NULL;

    if (endp) *endp = '\0';

    if (cmd->path) return "<Directory> sections don't nest";
    if (cmd->limited != -1) return "Can't have <Directory> within <Limit>";

    cmd->path = getword_conf (cmd->pool, &arg);
#ifdef __EMX__
    /* Fix OS/2 HPFS filename case problem. */
    cmd->path = strlwr(cmd->path);
#endif    
    cmd->override = OR_ALL|ACCESS_CONF;

    if (cmd->info) { /* <DirectoryMatch> */
	r = pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (!strcmp(cmd->path, "~")) {
	cmd->path = getword_conf (cmd->pool, &arg);
	r = pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else {
	/* Ensure that the pathname is canonical */
	cmd->path = os_canonical_filename(cmd->pool, cmd->path);
    }

    errmsg = srm_command_loop (cmd, new_dir_conf);
    if (errmsg == NULL)
	return missing_endsection(cmd->pool,
			(cmd->info) ? "DirectoryMatch" : "Directory", 1);
    if (errmsg != end_dir_magic) return errmsg;

    conf = (core_dir_config *)get_module_config(new_dir_conf, &core_module);
    conf->r = r;

    add_per_dir_conf (cmd->server, new_dir_conf);

    if (*arg != '\0')
	return pstrcat (cmd->pool, "Multiple <", (cmd->info) ? "DirectoryMatch" : "Directory",
			"> arguments not (yet) supported.", NULL);

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char end_url_magic[] = "</Location> outside of any <Location> section";

const char *end_urlsection (cmd_parms *cmd, void *dummy) {
    return end_url_magic;
}

const char *urlsection (cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *errmsg;
    char *endp = strrchr (arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    regex_t *r = NULL;

    void *new_url_conf = create_per_dir_config (cmd->pool);

    if (endp) *endp = '\0';

    if (cmd->path) return "<Location> sections don't nest";
    if (cmd->limited != -1) return "Can't have <Location> within <Limit>";
    
    cmd->path = getword_conf (cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (cmd->info) { /* <LocationMatch> */
	r = pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
    }
    else if (!strcmp(cmd->path, "~")) {
	cmd->path = getword_conf (cmd->pool, &arg);
	r = pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
    }

    errmsg = srm_command_loop (cmd, new_url_conf);
    if (errmsg == NULL)
	return missing_endsection(cmd->pool,
			(cmd->info) ? "LocationMatch" : "Location", 1);
    if (errmsg != end_url_magic) return errmsg;

    conf = (core_dir_config *)get_module_config(new_url_conf, &core_module);
    conf->d = pstrdup(cmd->pool, cmd->path);	/* No mangling, please */
    conf->d_is_fnmatch = is_fnmatch( conf->d ) != 0;
    conf->r = r;

    add_per_url_conf (cmd->server, new_url_conf);
    
    if (*arg != '\0')
	return pstrcat (cmd->pool, "Multiple <", (cmd->info) ? "LocationMatch" : "Location",
			"> arguments not (yet) supported.", NULL);

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static char *end_file_magic = "</Files> outside of any <Files> section";

const char *end_filesection (cmd_parms *cmd, void *dummy) {
    return end_file_magic;
}

const char *filesection (cmd_parms *cmd, core_dir_config *c, const char *arg)
{
    const char *errmsg;
    char *endp = strrchr (arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    regex_t *r = NULL;

    void *new_file_conf = create_per_dir_config (cmd->pool);

    if (endp) *endp = '\0';

    if (cmd->limited != -1) return "Can't have <Files> within <Limit>";

    cmd->path = getword_conf (cmd->pool, &arg);
    /* Only if not an .htaccess file */
    if (cmd->path)
	cmd->override = OR_ALL|ACCESS_CONF;

    if (cmd->info) { /* <FilesMatch> */
	if (old_path && cmd->path[0] != '/' && cmd->path[0] != '^')
            cmd->path = pstrcat(cmd->pool, "^", old_path, cmd->path, NULL);
        r = pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (!strcmp(cmd->path, "~")) {
	cmd->path = getword_conf (cmd->pool, &arg);
	if (old_path && cmd->path[0] != '/' && cmd->path[0] != '^')
	    cmd->path = pstrcat(cmd->pool, "^", old_path, cmd->path, NULL);
	r = pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else {
	if (old_path && cmd->path[0] != '/')
	    cmd->path = pstrcat(cmd->pool, old_path, cmd->path, NULL);

	/* Ensure that the pathname is canonical */
	cmd->path = os_canonical_filename(cmd->pool, cmd->path);
    }

    errmsg = srm_command_loop (cmd, new_file_conf);
    if (errmsg == NULL)
	return missing_endsection(cmd->pool,
			(cmd->info) ? "FilesMatch" : "Files", 1);
    if (errmsg != end_file_magic) return errmsg;

    conf = (core_dir_config *)get_module_config(new_file_conf, &core_module);
    conf->d = pstrdup(cmd->pool, cmd->path);
    conf->d_is_fnmatch = is_fnmatch( conf->d ) != 0;
    conf->r = r;

    add_file_conf (c, new_file_conf);
    
    if (*arg != '\0')
	return pstrcat (cmd->pool, "Multiple <", (cmd->info) ? "FilesMatch" : "Files",
			"> arguments not (yet) supported.", NULL);

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

const char *end_ifmod (cmd_parms *cmd, void *dummy) {
    return NULL;
}

const char *start_ifmod (cmd_parms *cmd, void *dummy, char *arg)
{
    char *endp = strrchr (arg, '>');
    char l[MAX_STRING_LEN];
    int not = (arg[0] == '!');
    module *found;
    int nest = 1;

    if (endp) *endp = '\0';
    if (not) arg++;

    found = find_linked_module(arg);

    if ((!not && found) || (not && !found))
      return NULL;

    while (nest && !(cfg_getline (l, MAX_STRING_LEN, cmd->infile))) {
        if (!strncasecmp(l, "<IfModule", 9))
	  nest++;
	if (!strcasecmp(l, "</IfModule>"))
	  nest--;
    }

    return (nest == 0) ? NULL : missing_endsection(cmd->pool, "IfModule", nest);
}

/* httpd.conf commands... beginning with the <VirtualHost> business */

const char end_virthost_magic[] = "</Virtualhost> out of place";

const char *end_virtualhost_section (cmd_parms *cmd, void *dummy)
{
    return end_virthost_magic;
}

const char *virtualhost_section (cmd_parms *cmd, void *dummy, char *arg)
{
    server_rec *main_server = cmd->server, *s;
    const char *errmsg;
    char *endp = strrchr (arg, '>');
    pool *p = cmd->pool, *ptemp = cmd->temp_pool;

    if (endp) *endp = '\0';
    
    /* FIXME: There's another feature waiting to happen here -- since you
	can now put multiple addresses/names on a single <VirtualHost>
	you might want to use it to group common definitions and then
	define other "subhosts" with their individual differences.  But
	personally I'd rather just do it with a macro preprocessor. -djg */
    if (main_server->is_virtual)
	return "<VirtualHost> doesn't nest!";
    
    errmsg = init_virtual_host (p, arg, main_server, &s);
    if (errmsg)
	return errmsg;

    s->next = main_server->next;
    main_server->next = s;
	
    cmd->server = s;
    errmsg = srm_command_loop (cmd, s->lookup_defaults);
    cmd->server = main_server;

    if (s->srm_confname)
	process_resource_config (s, s->srm_confname, p, ptemp);

    if (s->access_confname)
	process_resource_config (s, s->access_confname, p, ptemp);
    
    if (errmsg == NULL)
	return missing_endsection(cmd->pool, "Virtualhost", 1);
    if (errmsg == end_virthost_magic) return NULL;
    return errmsg;
}

const char *add_module_command (cmd_parms *cmd, void *dummy, char *arg)
{
    if (add_named_module (arg))
        return NULL;
    return "required module not found";
}

const char *clear_module_list_command (cmd_parms *cmd, void *dummy)
{
    clear_module_list ();
    return NULL;
}

const char *set_server_string_slot (cmd_parms *cmd, void *dummy, char *arg)
{
    /* This one's pretty generic... */
  
    int offset = (int)(long)cmd->info;
    char *struct_ptr = (char *)cmd->server;
    
    *(char **)(struct_ptr + offset) = pstrdup (cmd->pool, arg);
    return NULL;
}

const char *server_type (cmd_parms *cmd, void *dummy, char *arg)
{
    if (!strcasecmp (arg, "inetd")) standalone = 0;
    else if (!strcasecmp (arg, "standalone")) standalone = 1;
    else return "ServerType must be either 'inetd' or 'standalone'";

    return NULL;
}

const char *server_port (cmd_parms *cmd, void *dummy, char *arg) {
    cmd->server->port = atoi (arg);
    return NULL;
}

const char *set_send_buffer_size (cmd_parms *cmd, void *dummy, char *arg) {
    int s = atoi (arg);
    if (cmd->server->is_virtual) {
        return "SendBufferSize directive can not be used in <VirtualHost>";
    }
    if (s < 512 && s != 0) {
        return "SendBufferSize must be >= 512 bytes, or 0 for system default.";
    }
    cmd->server->send_buffer_size = s;
    return NULL;
}

const char *set_user (cmd_parms *cmd, void *dummy, char *arg)
{
    if (!cmd->server->is_virtual) {
	user_name = pstrdup (cmd->pool, arg);
	cmd->server->server_uid = user_id = uname2id(arg);
    }
    else {
	if (suexec_enabled)
	    cmd->server->server_uid = uname2id(arg);
	else {
	    cmd->server->server_uid = user_id;
	    fprintf(stderr,
		"Warning: User directive in <VirtualHost> "
		"requires SUEXEC wrapper.\n");
	}
    }
#if !defined (BIG_SECURITY_HOLE)
    if (cmd->server->server_uid == 0) {
	fprintf (stderr,
"Error:\tApache has not been designed to serve pages while running\n"
"\tas root.  There are known race conditions that will allow any\n"
"\tlocal user to read any file on the system.  Should you still\n"
"\tdesire to serve pages as root then add -DBIG_SECURITY_HOLE to\n"
"\tthe EXTRA_CFLAGS line in your src/Configuration file and rebuild\n"
"\tthe server.  It is strongly suggested that you instead modify the\n"
"\tUser directive in your httpd.conf file to list a non-root user.\n");
	exit (1);
    }
#endif

    return NULL;
}

const char *set_group (cmd_parms *cmd, void *dummy, char *arg)
{
    if (!cmd->server->is_virtual)
	cmd->server->server_gid = group_id = gname2id(arg);
    else {
	if (suexec_enabled)
	    cmd->server->server_gid = gname2id(arg);
	else {
	    cmd->server->server_gid = group_id;
	    fprintf(stderr,
		    "Warning: Group directive in <VirtualHost> requires SUEXEC wrapper.\n");
	}
    }

    return NULL;
}

const char *set_server_root (cmd_parms *cmd, void *dummy, char *arg) {
    if (!is_directory (arg)) return "ServerRoot must be a valid directory";
    strncpy (server_root, arg, sizeof(server_root)-1);
    server_root[sizeof(server_root)-1] = '\0';
    return NULL;
}

const char *set_timeout (cmd_parms *cmd, void *dummy, char *arg) {
    cmd->server->timeout = atoi (arg);
    return NULL;
}

const char *set_keep_alive_timeout (cmd_parms *cmd, void *dummy, char *arg) {
    cmd->server->keep_alive_timeout = atoi (arg);
    return NULL;
}

const char *set_keep_alive (cmd_parms *cmd, void *dummy, char *arg) {
    /* We've changed it to On/Off, but used to use numbers
     * so we accept anything but "Off" or "0" as "On"
     */
    if (!strcasecmp(arg, "off") || !strcmp(arg, "0"))
	cmd->server->keep_alive = 0;
    else
	cmd->server->keep_alive = 1;
    return NULL;
}

const char *set_keep_alive_max (cmd_parms *cmd, void *dummy, char *arg) {
    cmd->server->keep_alive_max = atoi (arg);
    return NULL;
}

const char *set_pidfile (cmd_parms *cmd, void *dummy, char *arg) {
    pid_fname = pstrdup (cmd->pool, arg);
    return NULL;
}

const char *set_scoreboard (cmd_parms *cmd, void *dummy, char *arg) {
    scoreboard_fname = pstrdup (cmd->pool, arg);
    return NULL;
}

const char *set_lockfile (cmd_parms *cmd, void *dummy, char *arg) {
    lock_fname = pstrdup (cmd->pool, arg);
    return NULL;
}

const char *set_idcheck (cmd_parms *cmd, core_dir_config *d, int arg) {
    d->do_rfc1413 = arg != 0;
    return NULL;
}

const char *set_hostname_lookups (cmd_parms *cmd, core_dir_config *d, char *arg)
{
    if (!strcasecmp (arg, "on")) {
	d->hostname_lookups = HOSTNAME_LOOKUP_ON;
    } else if (!strcasecmp (arg, "off")) {
	d->hostname_lookups = HOSTNAME_LOOKUP_OFF;
    } else if (!strcasecmp (arg, "double")) {
	d->hostname_lookups = HOSTNAME_LOOKUP_DOUBLE;
    } else {
	return "parameter must be 'on', 'off', or 'double'";
    }
    return NULL;
}

const char *set_serverpath (cmd_parms *cmd, void *dummy, char *arg) {
    cmd->server->path = pstrdup (cmd->pool, arg);
    cmd->server->pathlen = strlen (arg);
    return NULL;
}

const char *set_content_md5 (cmd_parms *cmd, core_dir_config *d, int arg) {
    d->content_md5 = arg != 0;
    return NULL;
}

const char *set_daemons_to_start (cmd_parms *cmd, void *dummy, char *arg) {
    daemons_to_start = atoi (arg);
    return NULL;
}

const char *set_min_free_servers (cmd_parms *cmd, void *dummy, char *arg) {
    daemons_min_free = atoi (arg);
    if (daemons_min_free <= 0) {
       fprintf(stderr, "WARNING: detected MinSpareServers set to non-positive.\n");
       fprintf(stderr, "Resetting to 1 to avoid almost certain Apache failure.\n");
       fprintf(stderr, "Please read the documentation.\n");
       daemons_min_free = 1;
    }
       
    return NULL;
}

const char *set_max_free_servers (cmd_parms *cmd, void *dummy, char *arg) {
    daemons_max_free = atoi (arg);
    return NULL;
}

const char *set_server_limit (cmd_parms *cmd, void *dummy, char *arg) {
    daemons_limit = atoi (arg);
    if (daemons_limit > HARD_SERVER_LIMIT) {
       fprintf(stderr, "WARNING: MaxClients of %d exceeds compile time limit "
           "of %d servers,\n", daemons_limit, HARD_SERVER_LIMIT);
       fprintf(stderr, " lowering MaxClients to %d.  To increase, please "
           "see the\n", HARD_SERVER_LIMIT);
       fprintf(stderr, " HARD_SERVER_LIMIT define in src/httpd.h.\n");
       daemons_limit = HARD_SERVER_LIMIT;
    } else if (daemons_limit < 1) {
	fprintf (stderr, "WARNING: Require MaxClients > 0, setting to 1\n");
	daemons_limit = 1;
    }
    return NULL;
}

const char *set_max_requests (cmd_parms *cmd, void *dummy, char *arg) {
    max_requests_per_child = atoi (arg);
    return NULL;
}

const char *set_threads (cmd_parms *cmd, void *dummy, char *arg) {
    threads_per_child = atoi (arg);
    return NULL;
}

const char *set_excess_requests (cmd_parms *cmd, void *dummy, char *arg) {
    excess_requests_per_child = atoi (arg);
    return NULL;
}


#if defined(RLIMIT_CPU) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_NPROC)
static void set_rlimit(cmd_parms *cmd, struct rlimit **plimit, const char *arg,
                       const char * arg2, int type)
{
    char *str;
    struct rlimit *limit;
    /* If your platform doesn't define rlim_t then typedef it in conf.h */
    rlim_t cur = 0;
    rlim_t max = 0;

    *plimit = (struct rlimit *)pcalloc(cmd->pool,sizeof **plimit);
    limit = *plimit;
    if ((getrlimit(type, limit)) != 0)	{
	*plimit = NULL;
	aplog_error(APLOG_MARK, APLOG_ERR, cmd->server,
		    "%s: getrlimit failed", cmd->cmd->name);
	return;
    }

    if ((str = getword_conf(cmd->pool, &arg)))
	if (!strcasecmp(str, "max"))
	    cur = limit->rlim_max;
	else
	    cur = atol(str);
    else {
	aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, cmd->server,
		    "Invalid parameters for %s", cmd->cmd->name);
	return;
    }
    
    if (arg2 && (str = getword_conf(cmd->pool, &arg2)))
	max = atol(str);

    /* if we aren't running as root, cannot increase max */
    if (geteuid()) {
	limit->rlim_cur = cur;
	if (max)
	    aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, cmd->server,
			"Must be uid 0 to raise maximum %s", cmd->cmd->name);
    }
    else {
	if (cur)
	    limit->rlim_cur = cur;
	if (max)
	    limit->rlim_max = max;
    }
}
#endif

#if !defined (RLIMIT_CPU) || !(defined (RLIMIT_DATA) || defined (RLIMIT_VMEM)) || !defined (RLIMIT_NPROC)
static const char *no_set_limit (cmd_parms *cmd, core_dir_config *conf,
				 char *arg, char *arg2)
{
    aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, cmd->server,
		"%s not supported on this platform", cmd->cmd->name);
    return NULL;
}
#endif

#ifdef RLIMIT_CPU
const char *set_limit_cpu (cmd_parms *cmd, core_dir_config *conf, char *arg, char *arg2)
{
    set_rlimit(cmd,&conf->limit_cpu,arg,arg2,RLIMIT_CPU);
    return NULL;
}
#endif

#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM)
const char *set_limit_mem (cmd_parms *cmd, core_dir_config *conf, char *arg, char * arg2)
{
#ifdef RLIMIT_DATA
    set_rlimit(cmd,&conf->limit_mem,arg,arg2,RLIMIT_DATA);
#else
    set_rlimit(cmd,&conf->limit_mem,arg,arg2,RLIMIT_VMEM);
#endif
    return NULL;
}
#endif

#ifdef RLIMIT_NPROC
const char *set_limit_nproc (cmd_parms *cmd, core_dir_config *conf, char *arg, char * arg2)
{
    set_rlimit(cmd,&conf->limit_nproc,arg,arg2,RLIMIT_NPROC);
    return NULL;
}
#endif

const char *set_bind_address (cmd_parms *cmd, void *dummy, char *arg) {
    bind_address.s_addr = get_virthost_addr (arg, NULL);
    return NULL;
}

const char *set_listener(cmd_parms *cmd, void *dummy, char *ips)
{
    listen_rec *new;
    char *ports;
    unsigned short port;

    if (cmd->server->is_virtual) return "Listen not allowed in <VirtualHost>";
    ports=strchr(ips, ':');
    if (ports != NULL)
    {
	if (ports == ips) return "Missing IP address";
	else if (ports[0] == '\0')
	    return "Address must end in :<port-number>";
	*(ports++) = '\0';
    } else
	ports = ips;

    new=pcalloc(cmd->pool, sizeof(listen_rec));
    new->local_addr.sin_family = AF_INET;
    if (ports == ips) /* no address */
	new->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
	new->local_addr.sin_addr.s_addr = get_virthost_addr(ips, NULL);
    port=atoi(ports);
    if(!port)
	return "Port must be numeric";
    new->local_addr.sin_port = htons(port);
    new->fd = -1;
    new->used = 0;
    new->next = listeners;
    listeners = new;
    return NULL;
}

const char *set_listenbacklog (cmd_parms *cmd, void *dummy, char *arg) {
    int b;

    if (cmd->server->is_virtual) 
        return "ListenBacklog not allowed in <VirtualHost>";
    b = atoi (arg);
    if (b < 1) return "ListenBacklog must be > 0";
    listenbacklog = b;
    return NULL;
}

const char *set_coredumpdir (cmd_parms *cmd, void *dummy, char *arg) {
    struct stat finfo;
    if (cmd->server->is_virtual)
        return "CoreDumpDirectory not allowed in <VirtualHost>";
    if ((stat(arg, &finfo) == -1) || !S_ISDIR(finfo.st_mode)) {
	return pstrcat(cmd->pool, "CoreDumpDirectory ", arg, 
	    " does not exist or is not a directory", NULL);
    }
    strncpy(coredump_dir, arg, sizeof(coredump_dir)-1);
    coredump_dir[sizeof(coredump_dir)-1] = '\0';
    return NULL;
}

const char *include_config (cmd_parms *cmd, void *dummy, char *name)
{
    name = server_root_relative(cmd->pool, name);
    
    process_resource_config(cmd->server, name, cmd->pool, cmd->temp_pool);

    return NULL;
}

const char *set_loglevel (cmd_parms *cmd, void *dummy, const char *arg) 
{
   char *str;
    
   if ((str = getword_conf(cmd->pool, &arg))) {
       if (!strcasecmp(str, "emerg"))
	   cmd->server->loglevel = APLOG_EMERG;
       else if (!strcasecmp(str, "alert"))
	   cmd->server->loglevel = APLOG_ALERT;
       else if (!strcasecmp(str, "crit"))
	   cmd->server->loglevel = APLOG_CRIT;
       else if (!strcasecmp(str, "error"))
	   cmd->server->loglevel = APLOG_ERR;
       else if (!strcasecmp(str, "warn"))
	   cmd->server->loglevel = APLOG_WARNING;
       else if (!strcasecmp(str, "notice"))
	   cmd->server->loglevel = APLOG_NOTICE;
       else if (!strcasecmp(str, "info"))
	   cmd->server->loglevel = APLOG_INFO;
       else if (!strcasecmp(str, "debug"))
	   cmd->server->loglevel = APLOG_DEBUG;
       else
           return "LogLevel requires level keyword: one of emerg/alert/crit/error/warn/notice/info/debug";
   }
   else
       return "LogLevel requires level keyword";
   
   return NULL;
}

/* Note --- ErrorDocument will now work from .htaccess files.  
 * The AllowOverride of Fileinfo allows webmasters to turn it off
 */

command_rec core_cmds[] = {

/* Old access config file commands */

{ "<Directory", dirsection, NULL, RSRC_CONF, RAW_ARGS, "Container for directives affecting resources located in the specified directories" },
{ "</Directory>", end_dirsection, NULL, ACCESS_CONF, NO_ARGS, "Marks end of <Directory>" },
{ "<Location", urlsection, NULL, RSRC_CONF, RAW_ARGS, "Container for directives affecting resources accessed through the specified URL paths" },
{ "</Location>", end_urlsection, NULL, ACCESS_CONF, NO_ARGS, "Marks end of <Location>" },
{ "<VirtualHost", virtualhost_section, NULL, RSRC_CONF, RAW_ARGS, "Container to map directives to a particular virtual host" },
{ "</VirtualHost>", end_virtualhost_section, NULL, RSRC_CONF, NO_ARGS, "Marks end of <Directory>" },
{ "<Files", filesection, NULL, OR_ALL, RAW_ARGS, "Container for directives affecting files matching specified patterns" },
{ "</Files>", end_filesection, NULL, OR_ALL, NO_ARGS, "Marks end of <Files>" },
{ "<Limit", limit_section, NULL, OR_ALL, RAW_ARGS, "Container for authentication directives when accessed using specified HTTP methods" },
{ "</Limit>", endlimit_section, NULL, OR_ALL, NO_ARGS, "Marks end of <Limit>" },
{ "<IfModule", start_ifmod, NULL, OR_ALL, RAW_ARGS, "Container for directives based on existance of specified modules" },
{ "</IfModule>", end_ifmod, NULL, OR_ALL, NO_ARGS, "Marks end of <IfModule>" },
{ "<DirectoryMatch", dirsection, (void*)1, RSRC_CONF, RAW_ARGS, "Container for directives affecting resources located in the specified directories" },
{ "</DirectoryMatch>", end_dirsection, NULL, ACCESS_CONF, NO_ARGS, "Marks end of <DirectoryMatch>" },
{ "<LocationMatch", urlsection, (void*)1, RSRC_CONF, RAW_ARGS, "Container for directives affecting resources accessed through the specified URL paths" },
{ "</LocationMatch>", end_urlsection, NULL, ACCESS_CONF, NO_ARGS, "Marks end of <LocationMatch>" },
{ "<FilesMatch", filesection, (void*)1, OR_ALL, RAW_ARGS, "Container for directives affecting files matching specified patterns" },
{ "</FilesMatch>", end_filesection, NULL, OR_ALL, NO_ARGS, "Marks end of <FilesMatch>" },
{ "AuthType", set_string_slot, (void*)XtOffsetOf(core_dir_config, auth_type),
    OR_AUTHCFG, TAKE1, "An HTTP authorization type (e.g., \"Basic\")" },
{ "AuthName", set_string_slot, (void*)XtOffsetOf(core_dir_config, auth_name),
    OR_AUTHCFG, RAW_ARGS, "The authentication realm (e.g. \"Members Only\")" },
{ "Require", require, NULL, OR_AUTHCFG, RAW_ARGS, "Selects which authenticated users or groups may access a protected space" },
{ "Satisfy", satisfy, NULL, OR_AUTHCFG, TAKE1,
    "access policy if both allow and require used ('all' or 'any')" },    

/* Old resource config file commands */
  
{ "AccessFileName", set_access_name, NULL, RSRC_CONF, RAW_ARGS, "Name(s) of per-directory config files (default: .htaccess)" },
{ "DocumentRoot", set_document_root, NULL, RSRC_CONF, TAKE1, "Root directory of the document tree"  },
{ "ErrorDocument", set_error_document, NULL, OR_FILEINFO, RAW_ARGS, "Change responses for HTTP errors" },
{ "AllowOverride", set_override, NULL, ACCESS_CONF, RAW_ARGS, "Controls what groups of directives can be configured by per-directory config files" },
{ "Options", set_options, NULL, OR_OPTIONS, RAW_ARGS, "Set a number of attributes for a given directory" },
{ "DefaultType", set_string_slot,
    (void*)XtOffsetOf (core_dir_config, default_type),
    OR_FILEINFO, TAKE1, "the default MIME type for untypable files" },

/* Old server config file commands */

{ "ServerType", server_type, NULL, RSRC_CONF, TAKE1,"'inetd' or 'standalone'"},
{ "Port", server_port, NULL, RSRC_CONF, TAKE1, "A TCP port number"},
{ "HostnameLookups", set_hostname_lookups, NULL, ACCESS_CONF|RSRC_CONF, TAKE1, "\"on\" to enable, \"off\" to disable reverse DNS lookups, or \"double\" to enable double-reverse DNS lookups" },
{ "User", set_user, NULL, RSRC_CONF, TAKE1, "Effective user id for this server"},
{ "Group", set_group, NULL, RSRC_CONF, TAKE1, "Effective group id for this server"},
{ "ServerAdmin", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, server_admin), RSRC_CONF, TAKE1,
  "The email address of the server administrator" },
{ "ServerName", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, server_hostname), RSRC_CONF, TAKE1,
  "The hostname of the server" },
{ "ServerRoot", set_server_root, NULL, RSRC_CONF, TAKE1, "Common directory of server-related files (logs, confs, etc)" },
{ "ErrorLog", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, error_fname), RSRC_CONF, TAKE1,
  "The filename of the error log" },
{ "PidFile", set_pidfile, NULL, RSRC_CONF, TAKE1,
    "A file for logging the server process ID"},
{ "ScoreBoardFile", set_scoreboard, NULL, RSRC_CONF, TAKE1,
    "A file for Apache to maintain runtime process management information"},
{ "LockFile", set_lockfile, NULL, RSRC_CONF, TAKE1,
    "The lockfile used when Apache needs to lock the accept() call"},
{ "AccessConfig", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, access_confname), RSRC_CONF, TAKE1,
  "The filename of the access config file" },
{ "ResourceConfig", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, srm_confname), RSRC_CONF, TAKE1,
  "The filename of the resource config file" },
{ "ServerAlias", set_server_string_slot,
   (void *)XtOffsetOf (server_rec, names), RSRC_CONF, RAW_ARGS,
   "A name or names alternately used to access the server" },
{ "ServerPath", set_serverpath, NULL, RSRC_CONF, TAKE1,
  "The pathname the server can be reached at" },
{ "Timeout", set_timeout, NULL, RSRC_CONF, TAKE1, "Timeout duration (sec)"},
{ "KeepAliveTimeout", set_keep_alive_timeout, NULL, RSRC_CONF, TAKE1, "Keep-Alive timeout duration (sec)"},
{ "MaxKeepAliveRequests", set_keep_alive_max, NULL, RSRC_CONF, TAKE1, "Maximum number of Keep-Alive requests per connection, or 0 for infinite" },
{ "KeepAlive", set_keep_alive, NULL, RSRC_CONF, TAKE1, "Whether persistent connections should be On or Off" },
{ "IdentityCheck", set_idcheck, NULL, RSRC_CONF|ACCESS_CONF, FLAG, "Enable identd (RFC 1413) user lookups - SLOW" },
{ "ContentDigest", set_content_md5, NULL, RSRC_CONF|ACCESS_CONF|OR_AUTHCFG, FLAG, "whether or not to send a Content-MD5 header with each request" },
{ "StartServers", set_daemons_to_start, NULL, RSRC_CONF, TAKE1, "Number of child processes launched at server startup" },
{ "MinSpareServers", set_min_free_servers, NULL, RSRC_CONF, TAKE1, "Minimum number of idle children, to handle request spikes" },
{ "MaxSpareServers", set_max_free_servers, NULL, RSRC_CONF, TAKE1, "Maximum number of idle children" },
{ "MaxServers", set_max_free_servers, NULL, RSRC_CONF, TAKE1, "Deprecated equivalent to MaxSpareServers" },
{ "ServersSafetyLimit", set_server_limit, NULL, RSRC_CONF, TAKE1, "Deprecated equivalent to MaxClients" },
{ "MaxClients", set_server_limit, NULL, RSRC_CONF, TAKE1, "Maximum number of children alive at the same time" },
{ "MaxRequestsPerChild", set_max_requests, NULL, RSRC_CONF, TAKE1, "Maximum number of requests a particular child serves before dying." },
{ "RLimitCPU",
#ifdef RLIMIT_CPU
 set_limit_cpu, (void*)XtOffsetOf(core_dir_config, limit_cpu),
#else
 no_set_limit, NULL,
#endif
      OR_ALL, TAKE12, "soft/hard limits for max CPU usage in seconds" },
{ "RLimitMEM",
#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM)
 set_limit_mem, (void*)XtOffsetOf(core_dir_config, limit_mem),
#else
 no_set_limit, NULL,
#endif
      OR_ALL, TAKE12, "soft/hard limits for max memory usage per process" },
{ "RLimitNPROC",
#ifdef RLIMIT_NPROC
 set_limit_nproc, (void*)XtOffsetOf(core_dir_config, limit_nproc),
#else
 no_set_limit, NULL,
#endif
      OR_ALL, TAKE12, "soft/hard limits for max number of processes per uid" },
{ "BindAddress", set_bind_address, NULL, RSRC_CONF, TAKE1,
  "'*', a numeric IP address, or the name of a host with a unique IP address"},
{ "Listen", set_listener, NULL, RSRC_CONF, TAKE1,
      "a port number or a numeric IP address and a port number"},
{ "SendBufferSize", set_send_buffer_size, NULL, RSRC_CONF, TAKE1, "send buffer size in bytes"},
{ "AddModule", add_module_command, NULL, RSRC_CONF, ITERATE,
  "the name of a module" },
{ "ClearModuleList", clear_module_list_command, NULL, RSRC_CONF, NO_ARGS, NULL },
{ "ThreadsPerChild", set_threads, NULL, RSRC_CONF, TAKE1, "Number of threads a child creates" },
{ "ExcessRequestsPerChild", set_excess_requests, NULL, RSRC_CONF, TAKE1, "Maximum number of requests a particular child serves after it is ready to die." },
{ "ListenBacklog", set_listenbacklog, NULL, RSRC_CONF, TAKE1, "maximum length of the queue of pending connections, as used by listen(2)" },
{ "CoreDumpDirectory", set_coredumpdir, NULL, RSRC_CONF, TAKE1, "The location of the directory Apache changes to before dumping core" },
{ "Include", include_config, NULL, RSRC_CONF, TAKE1, "config file to be included" },
{ "LogLevel", set_loglevel, NULL, RSRC_CONF, TAKE1, "set level of verbosity in error logging" },
{ "NameVirtualHost", set_name_virtual_host, NULL, RSRC_CONF, TAKE1,
  "a numeric ip address:port, or the name of a host with a single address" },
{ NULL },
};

/*****************************************************************
 *
 * Core handlers for various phases of server operation...
 */

int core_translate (request_rec *r)
{
    void *sconf = r->server->module_config;
    core_server_config *conf = get_module_config (sconf, &core_module);
  
    if (r->proxyreq) return HTTP_FORBIDDEN;
    if ((r->uri[0] != '/') && strcmp(r->uri, "*")) {
	aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		    "Invalid URI in request %s", r->the_request);
	return BAD_REQUEST;
    }
    
    if (r->server->path &&
	!strncmp(r->uri, r->server->path, r->server->pathlen) &&
	(r->server->path[r->server->pathlen - 1] == '/' ||
	 r->uri[r->server->pathlen] == '/' ||
	 r->uri[r->server->pathlen] == '\0'))
      r->filename = pstrcat (r->pool, conf->document_root,
			     (r->uri + r->server->pathlen), NULL);
    else
      r->filename = pstrcat (r->pool, conf->document_root, r->uri, NULL);

    return OK;
}

int do_nothing (request_rec *r) { return OK; }

#ifdef USE_MMAP_FILES
struct mmap {
    void *mm;
    size_t length;
};

static void mmap_cleanup (void *mmv)
{
    struct mmap *mmd = mmv;

    munmap(mmd->mm, mmd->length);
}
#endif

/*
 * Default handler for MIME types without other handlers.  Only GET
 * and OPTIONS at this point... anyone who wants to write a generic
 * handler for PUT or POST is free to do so, but it seems unwise to provide
 * any defaults yet... So, for now, we assume that this will always be
 * the last handler called and return 405 or 501.
 */

int default_handler (request_rec *r)
{
    core_dir_config *d =
      (core_dir_config *)get_module_config(r->per_dir_config, &core_module);
    int rangestatus, errstatus;
    FILE *f;
#ifdef USE_MMAP_FILES
    caddr_t mm;
#endif

    /* This handler has no use for a request body (yet), but we still
     * need to read and discard it if the client sent one.
     */
    if ((errstatus = discard_request_body(r)) != OK)
        return errstatus;

    r->allowed |= (1 << M_GET);
    r->allowed |= (1 << M_OPTIONS);

    if (r->method_number == M_INVALID) {
	aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server,
		    "Invalid method in request %s", r->the_request);
	return NOT_IMPLEMENTED;
    }
    if (r->method_number == M_OPTIONS) return send_http_options(r);
    if (r->method_number == M_PUT) return METHOD_NOT_ALLOWED;

    if (r->finfo.st_mode == 0 || (r->path_info && *r->path_info)) {
	aplog_error(APLOG_MARK, APLOG_ERR, r->server, "File does not exist: %s",
		    r->path_info ? pstrcat(r->pool, r->filename, r->path_info, NULL)
		    : r->filename);
	return NOT_FOUND;
    }
    if (r->method_number != M_GET) return METHOD_NOT_ALLOWED;
	
#if defined(__EMX__) || defined(WIN32)
    /* Need binary mode for OS/2 */
    f = pfopen (r->pool, r->filename, "rb");
#else
    f = pfopen (r->pool, r->filename, "r");
#endif

    if (f == NULL) {
        aplog_error(APLOG_MARK, APLOG_ERR, r->server,
		    "file permissions deny server access: %s", r->filename);
        return FORBIDDEN;
    }
	
    update_mtime (r, r->finfo.st_mtime);
    set_last_modified(r);
    set_etag(r);
    if (((errstatus = meets_conditions(r)) != OK)
	|| (errstatus = set_content_length (r, r->finfo.st_size))) {
	    return errstatus;
    }

#ifdef USE_MMAP_FILES
    block_alarms();
    if (r->finfo.st_size >= MMAP_THRESHOLD) {
	/* we need to protect ourselves in case we die while we've got the
	 * file mmapped */
	mm = mmap (NULL, r->finfo.st_size, PROT_READ, MAP_PRIVATE,
		    fileno(f), 0);
    } else {
	mm = (caddr_t)-1;
    }

    if (mm == (caddr_t)-1) {
	unblock_alarms();

	aplog_error(APLOG_MARK, APLOG_CRIT, r->server,
		    "mmap_handler: mmap failed: %s", r->filename);
#endif

	if (d->content_md5 & 1) {
	    table_set (r->headers_out, "Content-MD5", ap_md5digest(r->pool, f));
	}

	rangestatus = set_byterange(r);
	send_http_header (r);
	
	if (!r->header_only) {
	    if (!rangestatus)
		send_fd (f, r);
	    else {
		long offset, length;
		while (each_byterange(r, &offset, &length)) {
		    fseek(f, offset, SEEK_SET);
		    send_fd_length(f, r, length);
		}
	    }
	}

#ifdef USE_MMAP_FILES
    } else {
	struct mmap *mmd;

	mmd = palloc (r->pool, sizeof (*mmd));
	mmd->mm = mm;
	mmd->length = r->finfo.st_size;
	register_cleanup (r->pool, (void *)mmd, mmap_cleanup, mmap_cleanup);
	unblock_alarms();

	if (d->content_md5 & 1) {
	    AP_MD5_CTX context;
	    
	    MD5Init(&context);
	    MD5Update(&context, (void *)mm, r->finfo.st_size);
	    table_set (r->headers_out, "Content-MD5",
		ap_md5contextTo64(r->pool, &context));
	}

	rangestatus = set_byterange(r);
	send_http_header (r);
	
	if (!r->header_only) {
	    if (!rangestatus)
		send_mmap (mm, r, 0, r->finfo.st_size);
	    else {
		long offset, length;
		while (each_byterange(r, &offset, &length)) {
		    send_mmap(mm, r, offset, length);
		}
	    }
	}
    }
#endif

    pfclose(r->pool, f);
    return OK;
}

handler_rec core_handlers[] = {
{ "*/*", default_handler },
{ NULL }
};

module core_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_core_dir_config,	/* create per-directory config structure */
   merge_core_dir_configs,	/* merge per-directory config structures */
   create_core_server_config,	/* create per-server config structure */
   merge_core_server_configs,	/* merge per-server config structures */
   core_cmds,			/* command table */
   core_handlers,		/* handlers */
   core_translate,		/* translate_handler */
   NULL,			/* check_user_id */
   NULL,			/* check auth */
   do_nothing,			/* check access */
   do_nothing,			/* type_checker */
   NULL,			/* pre-run fixups */
   NULL,			/* logger */
   NULL,			/* header parser */
   NULL,			/* child_init */
   NULL,			/* child_exit */
   NULL				/* post_read_request */
};
