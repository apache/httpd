
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
 * http_request.c: functions to get and process requests
 * 
 * Rob McCool 3/21/93
 *
 * Thoroughly revamped by rst for Shambhala.  NB this file reads
 * best from the bottom up.
 * 
 */

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "scoreboard.h"

/*****************************************************************
 *
 * Getting and checking directory configuration.  Also checks the
 * FollowSymlinks and FollowSymOwner stuff, since this is really the
 * only place that can happen (barring a new mid_dir_walk callout).
 *
 * We can't do it as an access_checker module function which gets
 * called with the final per_dir_config, since we could have a directory
 * with FollowSymLinks disabled, which contains a symlink to another
 * with a .htaccess file which turns FollowSymLinks back on --- and
 * access in such a case must be denied.  So, whatever it is that
 * checks FollowSymLinks needs to know the state of the options as
 * they change, all the way down.
 */

int check_symlinks (char *d, int opts)
{
    struct stat lfi, fi;
    char *lastp;
    int res;
  
#ifdef __EMX__
    /* OS/2 dosen't have symlinks */
    return OK;
#else
  
    if (opts & OPT_SYM_LINKS) return OK;

    /* Strip trailing '/', if any, off what we're checking; trailing
     * slashes make some systems follow symlinks to directories even in
     * lstat().  After we've done the lstat, put it back.  Also, don't
     * bother checking '/' at all...
     *
     * Note that we don't have to worry about multiple slashes here
     * because of no2slash() below...
     */

    lastp = d + strlen(d) - 1;
    if (lastp == d) return OK;	/* Root directory, '/' */
    
    if (*lastp == '/') *lastp = '\0';
    else lastp = NULL;
	
    res = lstat (d, &lfi);

    if (lastp) *lastp = '/';
    
    /* Note that we don't reject accesses to nonexistent files (multiviews
     * or the like may cons up a way to run the transaction anyway)...
     */
		    
    if (!(res >= 0) || !S_ISLNK(lfi.st_mode)) return OK;

    /* OK, it's a symlink.  May still be OK with OPT_SYM_OWNER */
    
    if (!(opts & OPT_SYM_OWNER)) return FORBIDDEN;
	
    if (stat (d, &fi) < 0) return FORBIDDEN;
    
    return (fi.st_uid == lfi.st_uid) ? OK : FORBIDDEN;

#endif    
}
    
/* Dealing with the file system to get PATH_INFO
 */

void get_path_info(request_rec *r)
{
    char *cp;
    char *path = r->filename;
    char *end = &path[strlen(path)];
    char *last_cp = NULL;
    int rv;

    /* Advance over trailing slashes ... NOT part of filename */

    for (cp = end; cp > path && cp[-1] == '/'; --cp)
	continue;
    
    while (cp > path) {
      
	/* See if the pathname ending here exists... */
      
	*cp = '\0';
	rv = stat(path, &r->finfo);
	if (cp != end) *cp = '/';
      
	if (!rv) {

	    /* Aha!  Found something.  If it was a directory, we will
	     * search contents of that directory for a multi_match, so
	     * the PATH_INFO argument starts with the component after that.
	     */
	
	    if (S_ISDIR(r->finfo.st_mode) && last_cp) {
	        r->finfo.st_mode = 0; /* No such file... */
		cp = last_cp;
	    }
	
	    r->path_info = pstrdup (r->pool, cp);
	    *cp = '\0';
	    return;
	}
	else {
	    last_cp = cp;
	
	    while (--cp > path && *cp != '/')
		continue;

	    while (cp > path && cp[-1] == '/')
		--cp;
	}
    }
}

int directory_walk (request_rec *r)
{
    core_server_config *sconf = get_module_config (r->server->module_config,
						   &core_module);
    array_header *sec_array = copy_array (r->pool, sconf->sec);
    void *per_dir_defaults = r->server->lookup_defaults;
    
    core_dir_config **sec = (core_dir_config **)sec_array->elts;
    int num_sec = sec_array->nelts;
    char *test_filename = pstrdup (r->pool, r->filename);

    int num_dirs, res;
    int i;

    /* Are we dealing with a file? If not, we can (hopefuly) safely assume
     * we have a handler that doesn't require one, but for safety's sake,
     * and so we have something find_types() can get something out of,
     * fake one. But don't run through the directory entries.
     */

    if (test_filename == NULL) {
        r->filename = pstrdup(r->pool, r->uri);
	r->finfo.st_mode = 0;	/* Not really a file... */
        r->per_dir_config = per_dir_defaults;

        return OK;
    }

    /* Go down the directory hierarchy.  Where we have to check for symlinks,
     * do so.  Where a .htaccess file has permission to override anything,
     * try to find one.  If either of these things fails, we could poke
     * around, see why, and adjust the lookup_rec accordingly --- this might
     * save us a call to get_path_info (with the attendant stat()s); however,
     * for the moment, that's not worth the trouble.
     */

    if (test_filename[0] != '/')
    {
/* fake filenames only match Directory sections */
        void *this_conf, *entry_config;
        core_dir_config *entry_core;
	char *entry_dir;
	int j;

	for (j = 0; j < num_sec; ++j) {

	    entry_config = sec[j];
	    if (!entry_config) continue;
	    
	    entry_core =(core_dir_config *)
		get_module_config(entry_config, &core_module);
	    entry_dir = entry_core->d;

	    this_conf = NULL;
	    if (is_matchexp(entry_dir)) {
		if (!strcmp_match(test_filename, entry_dir))
		    this_conf = entry_config;
	    }
	    else if (!strncmp (test_filename, entry_dir, strlen(entry_dir)))
	        this_conf = entry_config;

	    if (this_conf)
		per_dir_defaults = merge_per_dir_configs (r->pool,
					   per_dir_defaults, this_conf);
	}

	r->per_dir_config = per_dir_defaults;

	return OK;
    }

    no2slash (test_filename);
    num_dirs = count_dirs(test_filename);
    get_path_info (r);
    
    if (S_ISDIR (r->finfo.st_mode)) ++num_dirs;

    for (i = 1; i <= num_dirs; ++i) {
        core_dir_config *core_dir =
	  (core_dir_config *)get_module_config(per_dir_defaults, &core_module);
	int allowed_here = core_dir->opts;
	int overrides_here = core_dir->override;
        void *this_conf = NULL, *htaccess_conf = NULL;
	char *this_dir = make_dirstr (r->pool, test_filename, i);
	char *config_name = make_full_path(r->pool, this_dir,
					   sconf->access_name);
	int j;
      
	/* Do symlink checks first, because they are done with the
	 * permissions appropriate to the *parent* directory...
	 */
	
	if ((res = check_symlinks (this_dir, allowed_here)))
	{
	    log_reason("Symbolic link not allowed", this_dir, r);
	    return res;
	}
	
	/* Begin *this* level by looking for matching <Directory> sections from
	 * access.conf.
	 */
    
	for (j = 0; j < num_sec; ++j) {
	    void *entry_config = sec[j];
	    core_dir_config *entry_core;
	    char *entry_dir;

	    if (!entry_config) continue;
	    
	    entry_core =
	      (core_dir_config *)get_module_config(entry_config, &core_module);
	    entry_dir = entry_core->d;
	
	    if (is_matchexp(entry_dir) && !strcmp_match(this_dir, entry_dir)) {
		/* Don't try this wildcard again --- if it ends in '*'
		 * it'll match again, and subdirectories won't be able to
		 * override it...
		 */
		sec[j] = NULL;	
	        this_conf = entry_config;
	    }
	    else if (!strcmp (this_dir, entry_dir))
	        this_conf = entry_config;
	}

	if (this_conf)
	{
	    per_dir_defaults =
	        merge_per_dir_configs (r->pool, per_dir_defaults, this_conf);
	    core_dir =(core_dir_config *)get_module_config(per_dir_defaults,
							   &core_module);
	}
	overrides_here = core_dir->override;

	/* If .htaccess files are enabled, check for one.
	 */
	
	if (overrides_here) {
	    res = parse_htaccess (&htaccess_conf, r, overrides_here,
				  this_dir, config_name);
	    if (res) return res;
	}

	if (htaccess_conf)
	    per_dir_defaults =
	        merge_per_dir_configs (r->pool, per_dir_defaults,
				       htaccess_conf);
	
    }

    r->per_dir_config = per_dir_defaults;

    if ((res = check_symlinks (r->filename, allow_options(r))))
    {
	log_reason("Symbolic link not allowed", r->filename, r);
	return res;
    }
    
    return OK;			/* Can only "fail" if access denied
				 * by the symlink goop.
				 */
}

int location_walk (request_rec *r)
{
    core_server_config *sconf = get_module_config (r->server->module_config,
						   &core_module);
    array_header *url_array = copy_array (r->pool, sconf->sec_url);
    void *per_dir_defaults = r->per_dir_config;
    
    core_dir_config **url = (core_dir_config **)url_array->elts;
    int num_url = url_array->nelts;
    char *test_location = pstrdup (r->pool, r->uri);

    /* Go through the location entries, and check for matches. */

    if (num_url) {
        void *this_conf, *entry_config;
	core_dir_config *entry_core;
	char *entry_url;
	int j;

/* 
 * we apply the directive sections in some order; should really try them
 * with the most general first.
 */
	for (j = 0; j < num_url; ++j) {

	    entry_config = url[j];
	    if (!entry_config) continue;
	    
	    entry_core =(core_dir_config *)
		get_module_config(entry_config, &core_module);
	    entry_url = entry_core->d;

	    this_conf = NULL;
	    if (is_matchexp(entry_url)) {
		if (!strcmp_match(test_location, entry_url))
		    this_conf = entry_config;
	    }
	    else if (!strncmp (test_location, entry_url, strlen(entry_url)))
	        this_conf = entry_config;

	    if (this_conf)
	        per_dir_defaults = merge_per_dir_configs (r->pool,
					    per_dir_defaults, this_conf);
	}

	r->per_dir_config = per_dir_defaults;
    }

    return OK;
}

/*****************************************************************
 *
 * The sub_request mechanism.
 *
 * Fns to look up a relative URI from, e.g., a map file or SSI document.
 * These do all access checks, etc., but don't actually run the transaction
 * ... use run_sub_req below for that.  Also, be sure to use destroy_sub_req
 * as appropriate if you're likely to be creating more than a few of these.
 * (An early Shambhala version didn't destroy the sub_reqs used in directory
 * indexing.  The result, when indexing a directory with 800-odd files in
 * it, was massively excessive storage allocation).
 *
 * Note more manipulation of protocol-specific vars in the request
 * structure...
 */

request_rec *make_sub_request (request_rec *r)
{
    pool *rrp = make_sub_pool (r->pool);
    request_rec *rr = pcalloc (rrp, sizeof (request_rec));
    
    rr->pool = rrp;
    return rr;
}

request_rec *sub_req_lookup_simple (char *new_file, request_rec *r)
{
    /* This handles the simple case, common to ..._lookup_uri and _file,
     * of looking up another file in the same directory.
     */
    request_rec *rnew = make_sub_request (r);
    pool *rnewp = rnew->pool;
    int res;
    
    char *udir = make_dirstr(rnewp, r->uri, count_dirs(r->uri));
    char *fdir = make_dirstr(rnewp, r->filename, count_dirs(r->filename));

    *rnew = *r;			/* Copy per_dir config, etc. */
    rnew->pool = rnewp;
    rnew->uri = make_full_path (rnewp, udir, new_file);
    rnew->filename = make_full_path (rnewp, fdir, new_file);
    set_sub_req_protocol (rnew, r);
	
    rnew->finfo.st_mode = 0;
    
    if ((res = check_symlinks (rnew->filename, allow_options (rnew))))
    {
        rnew->status = res;
    }

    if (rnew->finfo.st_mode == 0 && stat (rnew->filename, &rnew->finfo) < 0)
        rnew->finfo.st_mode = 0;

    if ((rnew->status == 200) && (res = find_types (rnew)))
        rnew->status = res;
    
    if ((rnew->status == 200) && (res = run_fixups (rnew)))
        rnew->status = res;
    
    return rnew;
}


static int some_auth_required (request_rec *r);

request_rec *sub_req_lookup_uri (char *new_file, request_rec *r)
{
    request_rec *rnew;
    int res;
    char *udir;
    
    rnew = make_sub_request (r);
    rnew->connection = r->connection; 
    rnew->server = r->server;
    rnew->request_config = create_request_config (rnew->pool);
    rnew->htaccess = r->htaccess; /* copy htaccess cache */
    set_sub_req_protocol (rnew, r);
	
    if (new_file[0] == '/')
	parse_uri(rnew, new_file);
    else
    {
	udir = make_dirstr (rnew->pool, r->uri, count_dirs (r->uri));
	udir = escape_uri(rnew->pool, udir); /* re-escape it */
	parse_uri (rnew, make_full_path (rnew->pool, udir, new_file));
    }
	
    res = unescape_url (rnew->uri);
    if (res)
    {
	rnew->status = res;
	return rnew;
    }

    getparents (rnew->uri);
	
    res = translate_name(rnew);
    if (res)
    {
	rnew->status = res;
	return rnew;
    }

    /* We could be clever at this point, and avoid calling directory_walk, etc.
     * However, we'd need to test that the old and new filenames contain the
     * same directory components, so it would require duplicating the start
     * of translate_name.
     * Instead we rely on the cache of .htaccess results.
     */
    
    if ((res = directory_walk (rnew))
	|| (!some_auth_required (rnew) ? 0 :
	     ((res = check_user_id (rnew)) || (res = check_auth (rnew))))
	|| (res = check_access (rnew))
	|| (res = find_types (rnew))
	|| (res = run_fixups (rnew))
	)
    {
        rnew->status = res;
    }

    return rnew;
}

request_rec *sub_req_lookup_file (char *new_file, request_rec *r)
{
    request_rec *rnew;
    int res;
    char *fdir;
    
    /* Check for a special case... if there are no '/' characters in new_file
     * at all, then we are looking at a relative lookup in the same directory.
     * That means we don't have to redo any access checks.
     */

    if (strchr (new_file, '/') == NULL) 
        return sub_req_lookup_simple (new_file, r);

    rnew = make_sub_request (r);
    fdir = make_dirstr (rnew->pool, r->filename, count_dirs (r->filename));
    
    rnew->connection = r->connection; /* For now... */
    rnew->server = r->server;
    rnew->request_config = create_request_config (rnew->pool);
    rnew->htaccess = r->htaccess; /* copy htaccess cache */
    set_sub_req_protocol (rnew, r);
	
    rnew->uri = "INTERNALLY GENERATED file-relative req";
    rnew->filename = ((new_file[0] == '/') ?
		      new_file :
		      make_full_path (rnew->pool, fdir, new_file));
	
    if ((res = directory_walk (rnew))
	|| (res = check_access (rnew))
	|| (!some_auth_required (rnew) ? 0 :
	     ((res = check_user_id (rnew)) && (res = check_auth (rnew))))
	|| (res = find_types (rnew))
	|| (res = run_fixups (rnew))
	)
    {
        rnew->status = res;
    }

    return rnew;
}

int run_sub_req (request_rec *r)
{
    int retval = invoke_handler (r);
    finalize_sub_req_protocol (r);
    return retval;
}

void destroy_sub_req (request_rec *r)
{
    /* Reclaim the space */
    destroy_pool (r->pool);
}

/*****************************************************************
 *
 * Mainline request processing...
 */

void die(int type, request_rec *r)
{
    int error_index = index_of_response (type);
    char *custom_response = response_code_string(r, error_index);
    int recursive_error = 0;
    
    /* The following takes care of Apache redirects to custom response URLs
     * Note that if we are already dealing with the response to some other
     * error condition, we just report on the original error, and give up on
     * any attempt to handle the other thing "intelligently"...
     */

    if (r->status != 200) {
        recursive_error = type;

	while (r->prev && r->prev->status != 200)
	  r = r->prev; /* Get back to original error */
	
	type = r->status;
	custom_response = NULL;	/* Do NOT retry the custom thing! */
    }
       
    r->status = type;
    
    /* Two types of custom redirects --- plain text, and URLs.
     * Plain text has a leading '"', so the URL code, here, is triggered
     * on its absence
     */
    
    if (custom_response && custom_response[0] != '"') {
          
        if (is_url(custom_response)) {
	    /* The URL isn't local, so lets drop through the rest of
	     * this apache code, and continue with the usual REDIRECT
	     * handler.  But note that the client will ultimately see
	     * the wrong status...
	     */
	    r->status = REDIRECT;
	    table_set (r->headers_out, "Location", custom_response);
	} else if ( custom_response[0] == '/') {
	    r->no_cache = 1;	/* Do NOT send USE_LOCAL_COPY for
				 * error documents!
				 */
	    /* This redirect needs to be a GET no matter what the original
	     * method was.
	     */
	    r->method = pstrdup(r->pool, "GET");
	    r->method_number = M_GET;
	    internal_redirect (custom_response, r);
	    return;
	} else {
	    /* Dumb user has given us a bad url to redirect to
	     * --- fake up dying with a recursive server error...
	     */
	    recursive_error = SERVER_ERROR;
	    log_reason("Invalid error redirection directive", custom_response,
		       r);
	}       
    }

    send_error_response (r, recursive_error);
}

static void decl_die (int status, char *phase, request_rec *r)
{
    if (status == DECLINED) {
	log_reason (pstrcat (r->pool,
			     "configuration error:  couldn't ",
			     phase, NULL),
		    r->uri,
		    r);
	die (SERVER_ERROR, r);
    }
    else die (status, r);
}

static int some_auth_required (request_rec *r)
{
    /* Is there a require line configured for the type of *this* req? */
    
    array_header *reqs_arr = requires (r);
    require_line *reqs;
    int i;
    
    if (!reqs_arr) return 0;
    
    reqs = (require_line *)reqs_arr->elts;

    for (i = 0; i < reqs_arr->nelts; ++i)
	if (reqs[i].method_mask & (1 << r->method_number))
	    return 1;

    return 0;
}

void process_request_internal (request_rec *r)
{
    int access_status;
  
    /* Kludge to be reading the assbackwards field outside of protocol.c,
     * but we've got to check for this sort of nonsense somewhere...
     */
    
    if (r->assbackwards && r->header_only) {
	/* Client asked for headers only with HTTP/0.9, which doesn't
	 * send headers!  Have to dink things even to make sure the
	 * error message comes through...
	 */
	log_reason ("client sent illegal HTTP/0.9 request", r->uri, r);
	r->header_only = 0;
	die (BAD_REQUEST, r);
	return;
    }

    if (!r->hostname && (r->proto_num >= 1001)) {
        /* Client sent us a HTTP/1.1 or later request without telling
	 * us the hostname, either with a full URL or a Host: header.
	 * We therefore need to (as per the 1.1 spec) send an error
	 */
        log_reason ("client sent HTTP/1.1 request without hostname",
		    r->uri, r);
	die (BAD_REQUEST, r);
	return;
    }

    if (!r->proxyreq)
    {
	access_status = unescape_url(r->uri);
	if (access_status)
	{
	    die(access_status, r);
	    return;
	}

	getparents(r->uri);	/* OK --- shrinking transformations... */
    }

    if ((access_status = translate_name (r))) {
        decl_die (access_status, "translate", r);
	return;
    }
    
    if ((access_status = directory_walk (r))) {
        die (access_status, r);
	return;
    }	
    
    if ((access_status = location_walk (r))) {
        die (access_status, r);
	return;
    }	
    
    if ((access_status = check_access (r)) != 0) {
        decl_die (access_status, "check access", r);
	return;
    }
    
    if (some_auth_required (r)) {
        if ((access_status = check_user_id (r)) != 0) {
	    decl_die (access_status, "check user.  No user file?", r);
	    return;
	}

	if ((access_status = check_auth (r)) != 0) {
	    decl_die (access_status, "check access.  No groups file?", r);
	    return;
	}
    }

    if ((access_status = find_types (r)) != 0) {
        decl_die (access_status, "find types", r);
	return;
    }

    if ((access_status = run_fixups (r)) != 0) {
        die (access_status, r);
	return;
    }

    if ((access_status = invoke_handler (r)) != 0)
        die (access_status, r);
}

void process_request (request_rec *r)
{
#ifdef STATUS
    int old_stat;
#endif /* STATUS */
    process_request_internal (r);
#ifdef STATUS
    old_stat = update_child_status (r->connection->child_num, SERVER_BUSY_LOG,
     r);
#endif /* STATUS */
    log_transaction (r);
#ifdef STATUS
    (void)update_child_status (r->connection->child_num, old_stat, r);
#endif /* STATUS */
}

table *rename_original_env (pool *p, table *t)
{
    array_header *env_arr = table_elts (t);
    table_entry *elts = (table_entry *)env_arr->elts;
    table *new = make_table (p, env_arr->nelts);
    int i;
    
    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key) continue;
	table_set (new, pstrcat (p, "REDIRECT_", elts[i].key, NULL),
		   elts[i].val);
    }

    return new;
}

request_rec *internal_internal_redirect (char *new_uri, request_rec *r)
{
    request_rec *new = (request_rec *)pcalloc(r->pool, sizeof(request_rec));
    char t[10];			/* Long enough... */
  
    new->connection = r->connection;
    new->server = r->server;
    new->pool = r->pool;
    
    /* A whole lot of this really ought to be shared with protocol.c...
     * another missing cleanup.  It's particularly inappropriate to be
     * setting header_only, etc., here.
     */
    
    parse_uri (new, new_uri);
    new->request_config = create_request_config (r->pool);
    new->per_dir_config = r->server->lookup_defaults;
    
    new->prev = r;
    r->next = new;
    
    /* Inherit the rest of the protocol info... */

    new->method = r->method;
    new->method_number = r->method_number;
    
    new->status = r->status;
    new->assbackwards = r->assbackwards;
    new->header_only = r->header_only;
    new->protocol = r->protocol;
    new->main = r->main;

    new->headers_in = r->headers_in;
    new->headers_out = make_table (r->pool, 5);
    new->err_headers_out = r->err_headers_out;
    new->subprocess_env = rename_original_env (r->pool, r->subprocess_env);
    new->notes = make_table (r->pool, 5);
    new->htaccess = r->htaccess; /* copy .htaccess cache */
    
    new->no_cache = r->no_cache; /* If we've already made up our minds
				  * about this, don't change 'em back!
				  */

    sprintf (t, "%d", r->status);
    table_set (new->subprocess_env, "REDIRECT_STATUS", pstrdup (r->pool, t));

    return new;
}

void internal_redirect (char *new_uri, request_rec *r)
{
    request_rec *new = internal_internal_redirect(new_uri, r);
    process_request_internal (new);
}

/* This function is designed for things like actions or CGI scripts, when
 * using AddHandler, and you want to preserve the content type across
 * an internal redirect.
 */

void internal_redirect_handler (char *new_uri, request_rec *r)
{
    request_rec *new = internal_internal_redirect(new_uri, r);
    if (r->handler)
        new->content_type = r->content_type;
    process_request_internal (new);
}
