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

/*
 * http_request.c: functions to get and process requests
 *
 * Rob McCool 3/21/93
 *
 * Thoroughly revamped by rst for Apache.  NB this file reads
 * best from the bottom up.
 *
 */

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_charset.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"

AP_HOOK_STRUCT(
	    AP_HOOK_LINK(translate_name)
	    AP_HOOK_LINK(check_user_id)
	    AP_HOOK_LINK(fixups)
	    AP_HOOK_LINK(type_checker)
	    AP_HOOK_LINK(access_checker)
	    AP_HOOK_LINK(auth_checker)
	    AP_HOOK_LINK(insert_filter)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int,translate_name,
                            (request_rec *r),(r),DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,check_user_id,
                            (request_rec *r),(r),DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,fixups,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,type_checker,
                            (request_rec *r),(r),DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,access_checker,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,auth_checker,
                            (request_rec *r),(r),DECLINED)
AP_IMPLEMENT_HOOK_VOID(insert_filter, (request_rec *r), (r))

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

/*
 * We don't want people able to serve up pipes, or unix sockets, or other
 * scary things.  Note that symlink tests are performed later.
 */
static int check_safe_file(request_rec *r)
{

    if (r->finfo.protection == 0      /* doesn't exist */
        || r->finfo.filetype == APR_DIR
        || r->finfo.filetype == APR_REG
        || r->finfo.filetype == APR_LNK) {
        return OK;
    }

    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                "object is not a file, directory or symlink: %s",
                r->filename);
    return HTTP_FORBIDDEN;
}


static int check_symlinks(char *d, int opts, apr_pool_t *p)
{
#if defined(OS2) || defined(WIN32)
    /* OS/2 doesn't have symlinks */
    return OK;
#else
    apr_finfo_t lfi, fi;
    char *lastp;
    int res;

    if (opts & OPT_SYM_LINKS)
        return OK;

    /*
     * Strip trailing '/', if any, off what we're checking; trailing slashes
     * make some systems follow symlinks to directories even in lstat().
     * After we've done the lstat, put it back.  Also, don't bother checking
     * '/' at all...
     * 
     * Note that we don't have to worry about multiple slashes here because of
     * no2slash() below...
     */

    lastp = d + strlen(d) - 1;
    if (lastp == d)
        return OK;              /* Root directory, '/' */

    if (*lastp == '/')
        *lastp = '\0';
    else
        lastp = NULL;

    res = apr_lstat(&lfi, d, p);

    if (lastp)
        *lastp = '/';

    /*
     * Note that we don't reject accesses to nonexistent files (multiviews or
     * the like may cons up a way to run the transaction anyway)...
     */

    if ((res != APR_SUCCESS) || lfi.filetype != APR_LNK)
        return OK;

    /* OK, it's a symlink.  May still be OK with OPT_SYM_OWNER */

    if (!(opts & OPT_SYM_OWNER))
        return HTTP_FORBIDDEN;

    if (apr_stat(&fi, d, p) < 0)
        return HTTP_FORBIDDEN;

    return (fi.user == lfi.user) ? OK : HTTP_FORBIDDEN;

#endif
}

/* Dealing with the file system to get PATH_INFO
 */
static int get_path_info(request_rec *r)
{
    char *cp;
    char *path = r->filename;
    char *end = &path[strlen(path)];
    char *last_cp = NULL;
    int rv, rvc;
#ifdef HAVE_DRIVE_LETTERS
    char bStripSlash=1;
#endif

    if (r->finfo.protection) {
	/* assume path_info already set */
	return OK;
    }

#ifdef HAVE_DRIVE_LETTERS
    /* If the directory is x:\, then we don't want to strip
     * the trailing slash since x: is not a valid directory.
     */
    if (strlen(path) == 3 && path[1] == ':' && path[2] == '/')
        bStripSlash = 0;


    /* If UNC name == //machine/share/, do not 
     * advance over the trailing slash.  Any other
     * UNC name is OK to strip the slash.
     */
    cp = end;
    if (strlen(path) > 2 && path[0] == '/' && path[1] == '/' && 
        path[2] != '/' && cp[-1] == '/') {
        char *p;
        int iCount=0;
        p = path;
        while ((p = strchr(p,'/')) != NULL) {
            p++;
            iCount++;
        }
    
        if (iCount == 4)
            bStripSlash = 0;
    }

    if (bStripSlash)
#endif
        /* Advance over trailing slashes ... NOT part of filename 
         * if file is not a UNC name (Win32 only).
         */
        for (cp = end; cp > path && cp[-1] == '/'; --cp)
            continue;


    while (cp > path) {

        /* See if the pathname ending here exists... */

        *cp = '\0';

         /* We must not stat() filenames that may cause os-specific system
          * problems, such as "/file/aux" on DOS-abused filesystems.
          * So pretend that they do not exist by returning an ENOENT error.
          * This will force us to drop that part of the path and keep
          * looking back for a "real" file that exists, while still allowing
          * the "invalid" path parts within the PATH_INFO.
          */
         if (!ap_os_is_filename_valid(path)) {
             errno = ENOENT;
             rv = -1;
         }
         else {
             errno = 0;
             rv = apr_stat(&r->finfo, path, r->pool);
         }

        if (cp != end)
            *cp = '/';

        if (rv == APR_SUCCESS) {    
            /*
             * Aha!  Found something.  If it was a directory, we will search
             * contents of that directory for a multi_match, so the PATH_INFO
             * argument starts with the component after that.
             */
            if (r->finfo.filetype == APR_DIR && last_cp) {
                r->finfo.protection = 0;   /* No such file... */
                r->finfo.filetype = APR_NOFILE;   /* No such file... */
                cp = last_cp;
            }

            r->path_info = apr_pstrdup(r->pool, cp);
            *cp = '\0';
            return OK;
        }
	/* must set this to zero, some stat()s may have corrupted it
	 * even if they returned an error.
	 */
	r->finfo.protection = 0;
	rvc = apr_canonical_error(rv);

#if defined(APR_ENOENT) && defined(APR_ENOTDIR)
        if (rvc == APR_ENOENT || rvc == APR_ENOTDIR) {
            last_cp = cp;

            while (--cp > path && *cp != '/')
                continue;

            while (cp > path && cp[-1] == '/')
                --cp;
        }
        else {
#if defined(APR_EACCES)
            if (rvc != APR_EACCES)
#endif
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                            "access to %s failed", r->uri);
            return HTTP_FORBIDDEN;
        }
#else
#error ENOENT || ENOTDIR not defined; please see the
#error comments at this line in the source for a workaround.
        /*
         * If ENOENT || ENOTDIR is not defined in one of the your OS's
         * include files, Apache does not know how to check to see why the
         * stat() of the index file failed; there are cases where it can fail
         * even though the file exists.  This means that it is possible for
         * someone to get a directory listing of a directory even though
         * there is an index (eg. index.html) file in it.  If you do not have
         * a problem with this, delete the above #error lines and start the
         * compile again.  If you need to do this, please submit a bug report
         * from http://www.apache.org/bug_report.html letting us know that
         * you needed to do this.  Please be sure to include the operating
         * system you are using.
         */
	last_cp = cp;

	while (--cp > path && *cp != '/')
	    continue;

	while (cp > path && cp[-1] == '/')
	    --cp;
#endif  /* ENOENT && ENOTDIR */
    }
    return OK;
}

static int directory_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                  &core_module);
    void *per_dir_defaults = r->server->lookup_defaults;
    void **sec = (void **) sconf->sec->elts;
    int num_sec = sconf->sec->nelts;
    char *test_filename;
    char *test_dirname;
    int res;
    unsigned i, num_dirs, iStart;
    int j, test_filename_len;

    /*
     * Are we dealing with a file? If not, we can (hopefuly) safely assume we
     * have a handler that doesn't require one, but for safety's sake, and so
     * we have something find_types() can get something out of, fake one. But
     * don't run through the directory entries.
     */

    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
        r->finfo.protection = 0;   /* Not really a file... */
        r->finfo.filetype = APR_NOFILE;
        r->per_dir_config = per_dir_defaults;

        return OK;
    }

    /*
     * Go down the directory hierarchy.  Where we have to check for symlinks,
     * do so.  Where a .htaccess file has permission to override anything,
     * try to find one.  If either of these things fails, we could poke
     * around, see why, and adjust the lookup_rec accordingly --- this might
     * save us a call to get_path_info (with the attendant stat()s); however,
     * for the moment, that's not worth the trouble.
     *
     * Fake filenames (i.e. proxy:) only match Directory sections.
     */

    if (!ap_os_is_path_absolute(r->filename))
    {
        void *this_conf, *entry_config;
        core_dir_config *entry_core;
        char *entry_dir;

        for (j = 0; j < num_sec; ++j) {

            entry_config = sec[j];

            entry_core = (core_dir_config *)
                ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            this_conf = NULL;
            if (entry_core->r) {
                if (!ap_regexec(entry_core->r, r->filename, 0, NULL, 0))
                    this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
                if (!apr_fnmatch(entry_dir, r->filename, 0))
                    this_conf = entry_config;
            }
            else if (!strncmp(r->filename, entry_dir, strlen(entry_dir)))
                this_conf = entry_config;

            if (this_conf)
                per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                         per_dir_defaults,
                                                         this_conf);
        }

        r->per_dir_config = per_dir_defaults;

        return OK;
    }

    r->filename   = ap_os_case_canonical_filename(r->pool, r->filename);

    res = get_path_info(r);
    if (res != OK) {
        return res;
    }

    r->filename   = ap_os_canonical_filename(r->pool, r->filename);

    test_filename = apr_pstrdup(r->pool, r->filename);

    ap_no2slash(test_filename);
    num_dirs = ap_count_dirs(test_filename);

    if (!ap_os_is_filename_valid(r->filename)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "Filename is not valid: %s", r->filename);
        return HTTP_FORBIDDEN;
    }

    if ((res = check_safe_file(r))) {
        return res;
    }

    test_filename_len = strlen(test_filename);
    if (test_filename[test_filename_len - 1] == '/')
        --num_dirs;

    if (r->finfo.filetype == APR_DIR)
        ++num_dirs;

    /*
     * We will use test_dirname as scratch space while we build directory
     * names during the walk.  Profiling shows directory_walk to be a busy
     * function so we try to avoid allocating lots of extra memory here.
     * We need 2 extra bytes, one for trailing \0 and one because
     * make_dirstr_prefix will add potentially one extra /.
     */
    test_dirname = apr_palloc(r->pool, test_filename_len + 2);

    iStart = 1;
#ifdef WIN32
    /* If the name is a UNC name, then do not walk through the
     * machine and share name (e.g. \\machine\share\)
     */
    if (num_dirs > 3 && test_filename[0] == '/' && test_filename[1] == '/')
        iStart = 4;
#endif

    /* j keeps track of which section we're on, see core_reorder_directories */
    j = 0;
    for (i = iStart; i <= num_dirs; ++i) {
        int overrides_here;
        core_dir_config *core_dir = (core_dir_config *)
            ap_get_module_config(per_dir_defaults, &core_module);

        /*
         * XXX: this could be made faster by only copying the next component
         * rather than copying the entire thing all over.
         */
        ap_make_dirstr_prefix(test_dirname, test_filename, i);

        /*
         * Do symlink checks first, because they are done with the
         * permissions appropriate to the *parent* directory...
         */

        if ((res = check_symlinks(test_dirname, core_dir->opts, r->pool))) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        "Symbolic link not allowed: %s", test_dirname);
            return res;
        }

        /*
         * Begin *this* level by looking for matching <Directory> sections
         * from access.conf.
         */

        for (; j < num_sec; ++j) {
            void *entry_config = sec[j];
            core_dir_config *entry_core;
            char *entry_dir;
            void *this_conf;

            entry_core = (core_dir_config *)
                         ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            if (entry_core->r
		|| !ap_os_is_path_absolute(entry_dir)
                || entry_core->d_components > i)
                break;

            this_conf = NULL;
            if (entry_core->d_is_fnmatch) {
                if (!apr_fnmatch(entry_dir, test_dirname, FNM_PATHNAME)) {
                    this_conf = entry_config;
                }
            }
            else if (!strcmp(test_dirname, entry_dir))
                this_conf = entry_config;

            if (this_conf) {
                per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                         per_dir_defaults,
                                                         this_conf);
                core_dir = (core_dir_config *)
                           ap_get_module_config(per_dir_defaults, &core_module);
            }
        }
        overrides_here = core_dir->override;

        /* If .htaccess files are enabled, check for one. */

        if (overrides_here) {
            void *htaccess_conf = NULL;

            res = ap_parse_htaccess(&htaccess_conf, r, overrides_here,
                                 apr_pstrdup(r->pool, test_dirname),
                                 sconf->access_name);
            if (res)
                return res;

            if (htaccess_conf) {
                per_dir_defaults = ap_merge_per_dir_configs(r->pool,
							    per_dir_defaults,
							    htaccess_conf);
		r->per_dir_config = per_dir_defaults;
	    }
        }
    }

    /*
     * There's two types of IS_SPECIAL sections (see http_core.c), and we've
     * already handled the proxy:-style stuff.  Now we'll deal with the
     * regexes.
     */
    for (; j < num_sec; ++j) {
        void *entry_config = sec[j];
        core_dir_config *entry_core;

        entry_core = (core_dir_config *)
                     ap_get_module_config(entry_config, &core_module);

        if (entry_core->r) {
            if (!ap_regexec(entry_core->r, test_dirname, 0, NULL, REG_NOTEOL)) {
                per_dir_defaults =
                    ap_merge_per_dir_configs(r->pool, per_dir_defaults,
                                          entry_config);
            }
        }
    }
    r->per_dir_config = per_dir_defaults;

    /*
     * Symlink permissions are determined by the parent.  If the request is
     * for a directory then applying the symlink test here would use the
     * permissions of the directory as opposed to its parent.  Consider a
     * symlink pointing to a dir with a .htaccess disallowing symlinks.  If
     * you access /symlink (or /symlink/) you would get a 403 without this
     * S_ISDIR test.  But if you accessed /symlink/index.html, for example,
     * you would *not* get the 403.
     */
    if (r->finfo.filetype != APR_DIR
        && (res = check_symlinks(r->filename, ap_allow_options(r), r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    "Symbolic link not allowed: %s", r->filename);
        return res;
    }
    return OK;                  /* Can only "fail" if access denied by the
                                 * symlink goop. */
}

static int location_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                  &core_module);
    void *per_dir_defaults = r->per_dir_config;
    void **url = (void **) sconf->sec_url->elts;
    int len, num_url = sconf->sec_url->nelts;
    char *test_location;
    void *this_conf, *entry_config;
    core_dir_config *entry_core;
    char *entry_url;
    int j;

    if (!num_url) {
	return OK;
    }

    /* Location and LocationMatch differ on their behaviour w.r.t. multiple
     * slashes.  Location matches multiple slashes with a single slash,
     * LocationMatch doesn't.  An exception, for backwards brokenness is
     * absoluteURIs... in which case neither match multiple slashes.
     */
    if (r->uri[0] != '/') {
	test_location = r->uri;
    }
    else {
	test_location = apr_pstrdup(r->pool, r->uri);
	ap_no2slash(test_location);
    }

    /* Go through the location entries, and check for matches. */

    /* we apply the directive sections in some order;
     * should really try them with the most general first.
     */
    for (j = 0; j < num_url; ++j) {

	entry_config = url[j];

	entry_core = (core_dir_config *)
	    ap_get_module_config(entry_config, &core_module);
	entry_url = entry_core->d;

	len = strlen(entry_url);

	this_conf = NULL;

	if (entry_core->r) {
	    if (!ap_regexec(entry_core->r, r->uri, 0, NULL, 0))
		this_conf = entry_config;
	}
	else if (entry_core->d_is_fnmatch) {
	    if (!apr_fnmatch(entry_url, test_location, FNM_PATHNAME)) {
		this_conf = entry_config;
	    }
	}
	else if (!strncmp(test_location, entry_url, len) &&
		    (entry_url[len - 1] == '/' ||
		test_location[len] == '/' || test_location[len] == '\0'))
	    this_conf = entry_config;

	if (this_conf)
	    per_dir_defaults = ap_merge_per_dir_configs(r->pool,
					    per_dir_defaults, this_conf);
    }
    r->per_dir_config = per_dir_defaults;

    return OK;
}

static int file_walk(request_rec *r)
{
    core_dir_config *conf = ap_get_module_config(r->per_dir_config, &core_module);
    void *per_dir_defaults = r->per_dir_config;
    void **file = (void **) conf->sec->elts;
    int num_files = conf->sec->nelts;
    char *test_file;

    /* get the basename */
    test_file = strrchr(r->filename, '/');
    if (test_file == NULL) {
	test_file = r->filename;
    }
    else {
	++test_file;
    }

    /* Go through the file entries, and check for matches. */

    if (num_files) {
        void *this_conf, *entry_config;
        core_dir_config *entry_core;
        char *entry_file;
        int j;

        /* we apply the directive sections in some order;
         * should really try them with the most general first.
         */
        for (j = 0; j < num_files; ++j) {

            entry_config = file[j];

            entry_core = (core_dir_config *)
                         ap_get_module_config(entry_config, &core_module);
            entry_file = entry_core->d;

            this_conf = NULL;

            if (entry_core->r) {
                if (!ap_regexec(entry_core->r, test_file, 0, NULL, 0))
                    this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
                if (!apr_fnmatch(entry_file, test_file, FNM_PATHNAME)) {
                    this_conf = entry_config;
                }
            }
            else if (!strcmp(test_file, entry_file)) {
                this_conf = entry_config;
	    }

            if (this_conf)
                per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                         per_dir_defaults,
                                                         this_conf);
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
 * (An early Apache version didn't destroy the sub_reqs used in directory
 * indexing.  The result, when indexing a directory with 800-odd files in
 * it, was massively excessive storage allocation).
 *
 * Note more manipulation of protocol-specific vars in the request
 * structure...
 */

static request_rec *make_sub_request(const request_rec *r)
{
    apr_pool_t *rrp;
    request_rec *rr;
    
    apr_create_pool(&rrp, r->pool);
    rr = apr_pcalloc(rrp, sizeof(request_rec));
    rr->pool = rrp;
    return rr;
}

API_EXPORT(request_rec *) ap_sub_req_method_uri(const char *method,
                                                const char *new_file,
                                                const request_rec *r)
{
    request_rec *rnew;
    int res;
    char *udir;

    rnew = make_sub_request(r);
    rnew->hostname       = r->hostname;
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;
    rnew->request_config = ap_create_request_config(rnew->pool);
    rnew->htaccess       = r->htaccess;
    rnew->per_dir_config = r->server->lookup_defaults;

    /* start with the same set of output filters */
    rnew->filters = r->filters;

    ap_set_sub_req_protocol(rnew, r);

    /* would be nicer to pass "method" to ap_set_sub_req_protocol */
    rnew->method = method;
    rnew->method_number = ap_method_number_of(method);

    if (new_file[0] == '/')
        ap_parse_uri(rnew, new_file);
    else {
        udir = ap_make_dirstr_parent(rnew->pool, r->uri);
        udir = ap_escape_uri(rnew->pool, udir);    /* re-escape it */
        ap_parse_uri(rnew, ap_make_full_path(rnew->pool, udir, new_file));
    }

    res = ap_unescape_url(rnew->uri);
    if (res) {
        rnew->status = res;
        return rnew;
    }

    ap_getparents(rnew->uri);

    if ((res = location_walk(rnew))) {
        rnew->status = res;
        return rnew;
    }

    res = ap_run_translate_name(rnew);
    if (res) {
        rnew->status = res;
        return rnew;
    }

    /*
     * We could be clever at this point, and avoid calling directory_walk,
     * etc. However, we'd need to test that the old and new filenames contain
     * the same directory components, so it would require duplicating the
     * start of translate_name. Instead we rely on the cache of .htaccess
     * results.
     *
     * NB: directory_walk() clears the per_dir_config, so we don't inherit
     * from location_walk() above
     */

    if ((res = directory_walk(rnew))
        || (res = file_walk(rnew))
        || (res = location_walk(rnew))
        || ((ap_satisfies(rnew) == SATISFY_ALL
             || ap_satisfies(rnew) == SATISFY_NOSPEC)
            ? ((res = ap_run_access_checker(rnew))
               || (ap_some_auth_required(rnew)
                   && ((res = ap_run_check_user_id(rnew))
                       || (res = ap_run_auth_checker(rnew)))))
            : ((res = ap_run_access_checker(rnew))
               && (!ap_some_auth_required(rnew)
                   || ((res = ap_run_check_user_id(rnew))
                       || (res = ap_run_auth_checker(rnew)))))
           )
        || (res = ap_run_type_checker(rnew))
        || (res = ap_run_fixups(rnew))
       ) {
        rnew->status = res;
    }
    return rnew;
}

API_EXPORT(request_rec *) ap_sub_req_lookup_uri(const char *new_file,
                                                const request_rec *r)
{
    return ap_sub_req_method_uri("GET", new_file, r);
}

API_EXPORT(request_rec *) ap_sub_req_lookup_file(const char *new_file,
                                              const request_rec *r)
{
    request_rec *rnew;
    int res;
    char *fdir;

    rnew = make_sub_request(r);
    rnew->hostname       = r->hostname;
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;
    rnew->request_config = ap_create_request_config(rnew->pool);
    rnew->htaccess       = r->htaccess;
    rnew->chunked        = r->chunked;

    /* start with the same set of output filters */
    rnew->filters = r->filters;

    ap_set_sub_req_protocol(rnew, r);
    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);

    /*
     * Check for a special case... if there are no '/' characters in new_file
     * at all, then we are looking at a relative lookup in the same
     * directory. That means we won't have to redo directory_walk, and we may
     * not even have to redo access checks.
     */

    if (ap_strchr_c(new_file, '/') == NULL) {
        char *udir = ap_make_dirstr_parent(rnew->pool, r->uri);

        rnew->uri = ap_make_full_path(rnew->pool, udir, new_file);
        rnew->filename = ap_make_full_path(rnew->pool, fdir, new_file);
        ap_parse_uri(rnew, rnew->uri);    /* fill in parsed_uri values */

        if (apr_stat(&rnew->finfo, rnew->filename, rnew->pool) != APR_SUCCESS) {
            rnew->finfo.protection = 0;
        }

        if ((res = check_safe_file(rnew))) {
            rnew->status = res;
            return rnew;
        }

        rnew->per_dir_config = r->per_dir_config;

        /*
         * no matter what, if it's a subdirectory, we need to re-run
         * directory_walk
         */
        if (rnew->finfo.filetype == APR_DIR) {
            res = directory_walk(rnew);
            if (!res) {
                res = file_walk(rnew);
            }
        }
        else {
            if ((res = check_symlinks(rnew->filename, ap_allow_options(rnew),
                                      rnew->pool))) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, rnew,
                            "Symbolic link not allowed: %s", rnew->filename);
                rnew->status = res;
                return rnew;
            }
            /*
             * do a file_walk, if it doesn't change the per_dir_config then
             * we know that we don't have to redo all the access checks
             */
            if ((res = file_walk(rnew))) {
                rnew->status = res;
                return rnew;
            }
            if (rnew->per_dir_config == r->per_dir_config) {
                if ((res = ap_run_type_checker(rnew)) || (res = ap_run_fixups(rnew))) {
                    rnew->status = res;
                }
                return rnew;
            }
        }
    }
    else {
	/* XXX: @@@: What should be done with the parsed_uri values? */
	ap_parse_uri(rnew, new_file);	/* fill in parsed_uri values */
        /*
         * XXX: this should be set properly like it is in the same-dir case
         * but it's actually sometimes to impossible to do it... because the
         * file may not have a uri associated with it -djg
         */
        rnew->uri = "INTERNALLY GENERATED file-relative req";
        rnew->filename = ((ap_os_is_path_absolute(new_file)) ?
                          apr_pstrdup(rnew->pool, new_file) :
                          ap_make_full_path(rnew->pool, fdir, new_file));
        rnew->per_dir_config = r->server->lookup_defaults;
        res = directory_walk(rnew);
        if (!res) {
            res = file_walk(rnew);
        }
    }

    if (res
        || ((ap_satisfies(rnew) == SATISFY_ALL
             || ap_satisfies(rnew) == SATISFY_NOSPEC)
            ? ((res = ap_run_access_checker(rnew))
               || (ap_some_auth_required(rnew)
                   && ((res = ap_run_check_user_id(rnew))
                       || (res = ap_run_auth_checker(rnew)))))
            : ((res = ap_run_access_checker(rnew))
               && (!ap_some_auth_required(rnew)
                   || ((res = ap_run_check_user_id(rnew))
                       || (res = ap_run_auth_checker(rnew)))))
           )
        || (res = ap_run_type_checker(rnew))
        || (res = ap_run_fixups(rnew))
       ) {
        rnew->status = res;
    }
    return rnew;
}

API_EXPORT(int) ap_run_sub_req(request_rec *r)
{
    int retval;

    /* see comments in process_request_internal() */
    ap_run_insert_filter(r);

#ifndef APACHE_XLATE
    retval = ap_invoke_handler(r);
#else /*APACHE_XLATE*/
    {
        /* Save the output conversion setting across subrequests */
        apr_xlate_t *saved_xlate;

        ap_bgetopt(r->connection->client, BO_WXLATE, &saved_xlate);
        retval  = ap_invoke_handler(r);
        ap_bsetopt(r->connection->client, BO_WXLATE, &saved_xlate);
    }
#endif /*APACHE_XLATE*/
    ap_finalize_sub_req_protocol(r);
    return retval;
}

API_EXPORT(void) ap_destroy_sub_req(request_rec *r)
{
    /* Reclaim the space */
    apr_destroy_pool(r->pool);
}

/*****************************************************************
 *
 * Mainline request processing...
 */

API_EXPORT(void) ap_die(int type, request_rec *r)
{
    int error_index = ap_index_of_response(type);
    char *custom_response = ap_response_code_string(r, error_index);
    int recursive_error = 0;

    if (type == DONE) {
        ap_finalize_request_protocol(r);
        return;
    }

    /*
     * The following takes care of Apache redirects to custom response URLs
     * Note that if we are already dealing with the response to some other
     * error condition, we just report on the original error, and give up on
     * any attempt to handle the other thing "intelligently"...
     */

    if (r->status != HTTP_OK) {
        recursive_error = type;

        while (r->prev && (r->prev->status != HTTP_OK))
            r = r->prev;        /* Get back to original error */

        type = r->status;
        custom_response = NULL; /* Do NOT retry the custom thing! */
    }

    r->status = type;

    /*
     * This test is done here so that none of the auth modules needs to know
     * about proxy authentication.  They treat it like normal auth, and then
     * we tweak the status.
     */
    if (r->status == HTTP_UNAUTHORIZED && r->proxyreq) {
        r->status = HTTP_PROXY_AUTHENTICATION_REQUIRED;
    }

    /*
     * If we want to keep the connection, be sure that the request body
     * (if any) has been read.
     */
    if ((r->status != HTTP_NOT_MODIFIED) && (r->status != HTTP_NO_CONTENT)
        && !ap_status_drops_connection(r->status)
        && r->connection && (r->connection->keepalive != -1)) {

        (void) ap_discard_request_body(r);
    }

    /*
     * Two types of custom redirects --- plain text, and URLs. Plain text has
     * a leading '"', so the URL code, here, is triggered on its absence
     */

    if (custom_response && custom_response[0] != '"') {

        if (ap_is_url(custom_response)) {
            /*
             * The URL isn't local, so lets drop through the rest of this
             * apache code, and continue with the usual REDIRECT handler.
             * But note that the client will ultimately see the wrong
             * status...
             */
            r->status = HTTP_MOVED_TEMPORARILY;
            apr_table_setn(r->headers_out, "Location", custom_response);
        }
        else if (custom_response[0] == '/') {
            const char *error_notes;
            r->no_local_copy = 1;       /* Do NOT send HTTP_NOT_MODIFIED for
                                         * error documents! */
            /*
             * This redirect needs to be a GET no matter what the original
             * method was.
             */
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", r->method);

	    /*
	     * Provide a special method for modules to communicate
	     * more informative (than the plain canned) messages to us.
	     * Propagate them to ErrorDocuments via the ERROR_NOTES variable:
	     */
            if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
		apr_table_setn(r->subprocess_env, "ERROR_NOTES", error_notes);
	    }
            r->method = apr_pstrdup(r->pool, "GET");
            r->method_number = M_GET;
            ap_internal_redirect(custom_response, r);
            return;
        }
        else {
            /*
             * Dumb user has given us a bad url to redirect to --- fake up
             * dying with a recursive server error...
             */
            recursive_error = HTTP_INTERNAL_SERVER_ERROR;
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        "Invalid error redirection directive: %s",
                        custom_response);
        }
    }
    ap_send_error_response(r, recursive_error);
}

static void decl_die(int status, char *phase, request_rec *r)
{
    if (status == DECLINED) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, 0, r,
                    "configuration error:  couldn't %s: %s", phase, r->uri);
        ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
    }
    else
        ap_die(status, r);
}

API_EXPORT(int) ap_some_auth_required(request_rec *r)
{
    /* Is there a require line configured for the type of *this* req? */

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    int i;

    if (!reqs_arr)
        return 0;

    reqs = (require_line *) reqs_arr->elts;

    for (i = 0; i < reqs_arr->nelts; ++i)
        if (reqs[i].method_mask & (1 << r->method_number))
            return 1;

    return 0;
}

static void process_request_internal(request_rec *r)
{
    int access_status;

    /* Ignore embedded %2F's in path for proxy requests */
    if (!r->proxyreq && r->parsed_uri.path) {
	access_status = ap_unescape_url(r->parsed_uri.path);
	if (access_status) {
	    ap_die(access_status, r);
	    return;
	}
    }

    ap_getparents(r->uri);     /* OK --- shrinking transformations... */

    if ((access_status = location_walk(r))) {
        ap_die(access_status, r);
        return;
    }

    if ((access_status = ap_run_translate_name(r))) {
        decl_die(access_status, "translate", r);
        return;
    }

    if (!r->proxyreq) {
	/*
	 * We don't want TRACE to run through the normal handler set, we
	 * handle it specially.
	 */
	if (r->method_number == M_TRACE) {
	    if ((access_status = ap_send_http_trace(r)))
		ap_die(access_status, r);
	    else
		ap_finalize_request_protocol(r);
	    return;
	}
    }

    if (r->proto_num > HTTP_VERSION(1,0) && apr_table_get(r->subprocess_env, "downgrade-1.0")) {
        r->proto_num = HTTP_VERSION(1,0);
    }

    /*
     * NB: directory_walk() clears the per_dir_config, so we don't inherit
     * from location_walk() above
     */

    if ((access_status = directory_walk(r))) {
        ap_die(access_status, r);
        return;
    }

    if ((access_status = file_walk(r))) {
        ap_die(access_status, r);
        return;
    }

    if ((access_status = location_walk(r))) {
        ap_die(access_status, r);
        return;
    }

    if ((access_status = ap_run_header_parser(r))) {
        ap_die(access_status, r);
        return;
    }

    switch (ap_satisfies(r)) {
    case SATISFY_ALL:
    case SATISFY_NOSPEC:
        if ((access_status = ap_run_access_checker(r)) != 0) {
            decl_die(access_status, "check access", r);
            return;
        }
        if (ap_some_auth_required(r)) {
            if (((access_status = ap_run_check_user_id(r)) != 0) || !ap_auth_type(r)) {
                decl_die(access_status, ap_auth_type(r)
		    ? "check user.  No user file?"
		    : "perform authentication. AuthType not set!", r);
                return;
            }
            if (((access_status = ap_run_auth_checker(r)) != 0) || !ap_auth_type(r)) {
                decl_die(access_status, ap_auth_type(r)
		    ? "check access.  No groups file?"
		    : "perform authentication. AuthType not set!", r);
                return;
            }
        }
        break;
    case SATISFY_ANY:
        if (((access_status = ap_run_access_checker(r)) != 0) || !ap_auth_type(r)) {
            if (!ap_some_auth_required(r)) {
                decl_die(access_status, ap_auth_type(r)
		    ? "check access"
		    : "perform authentication. AuthType not set!", r);
                return;
            }
            if (((access_status = ap_run_check_user_id(r)) != 0) || !ap_auth_type(r)) {
                decl_die(access_status, ap_auth_type(r)
		    ? "check user.  No user file?"
		    : "perform authentication. AuthType not set!", r);
                return;
            }
            if (((access_status = ap_run_auth_checker(r)) != 0) || !ap_auth_type(r)) {
                decl_die(access_status, ap_auth_type(r)
		    ? "check access.  No groups file?"
		    : "perform authentication. AuthType not set!", r);
                return;
            }
        }
        break;
    }

    if (! (r->proxyreq 
	   && r->parsed_uri.scheme != NULL
	   && strcmp(r->parsed_uri.scheme, "http") == 0) ) {
	if ((access_status = ap_run_type_checker(r)) != 0) {
	    decl_die(access_status, "find types", r);
	    return;
	}
    }

    if ((access_status = ap_run_fixups(r)) != 0) {
        ap_die(access_status, r);
        return;
    }

    /* The new insert_filter stage makes sense here IMHO.  We are sure that
     * we are going to run the request now, so we may as well insert filters
     * if any are available.  Since the goal of this phase is to allow all
     * modules to insert a filter if they want to, this filter returns
     * void.  I just can't see any way that this filter can reasonably
     * fail, either your modules inserts something or it doesn't.  rbb
     */
    ap_run_insert_filter(r);

    if ((access_status = ap_invoke_handler(r)) != 0) {
        ap_die(access_status, r);
        return;
    }

    /* Take care of little things that need to happen when we're done */
    ap_finalize_request_protocol(r);
}

void ap_process_request(request_rec *r)
{
    process_request_internal(r);

    /*
     * We want to flush the last packet if this isn't a pipelining connection
     * *before* we start into logging.  Suppose that the logging causes a DNS
     * lookup to occur, which may have a high latency.  If we hold off on
     * this packet, then it'll appear like the link is stalled when really
     * it's the application that's stalled.
     */
    ap_bhalfduplex(r->connection->client);
    ap_run_log_transaction(r);
}

static apr_table_t *rename_original_env(apr_pool_t *p, apr_table_t *t)
{
    apr_array_header_t *env_arr = ap_table_elts(t);
    apr_table_entry_t *elts = (apr_table_entry_t *) env_arr->elts;
    apr_table_t *new = apr_make_table(p, env_arr->nalloc);
    int i;

    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;
        apr_table_setn(new, apr_pstrcat(p, "REDIRECT_", elts[i].key, NULL),
                  elts[i].val);
    }

    return new;
}

static request_rec *internal_internal_redirect(const char *new_uri, request_rec *r)
{
    int access_status;
    request_rec *new = (request_rec *) apr_pcalloc(r->pool, sizeof(request_rec));

    new->connection = r->connection;
    new->server     = r->server;
    new->pool       = r->pool;

    /*
     * A whole lot of this really ought to be shared with http_protocol.c...
     * another missing cleanup.  It's particularly inappropriate to be
     * setting header_only, etc., here.
     */

    new->method          = r->method;
    new->method_number   = r->method_number;
    ap_parse_uri(new, new_uri);
    new->request_config = ap_create_request_config(r->pool);
    new->per_dir_config = r->server->lookup_defaults;

    new->prev = r;
    r->next   = new;

    /* Inherit the rest of the protocol info... */

    new->the_request = r->the_request;

    new->allowed         = r->allowed;

    new->status          = r->status;
    new->assbackwards    = r->assbackwards;
    new->header_only     = r->header_only;
    new->protocol        = r->protocol;
    new->proto_num       = r->proto_num;
    new->hostname        = r->hostname;
    new->request_time    = r->request_time;
    new->main            = r->main;

    new->headers_in      = r->headers_in;
    new->headers_out     = apr_make_table(r->pool, 12);
    new->err_headers_out = r->err_headers_out;
    new->subprocess_env  = rename_original_env(r->pool, r->subprocess_env);
    new->notes           = apr_make_table(r->pool, 5);

    new->htaccess        = r->htaccess;
    new->no_cache        = r->no_cache;
    new->expecting_100	 = r->expecting_100;
    new->no_local_copy   = r->no_local_copy;
    new->read_length     = r->read_length;     /* We can only read it once */
    new->vlist_validator = r->vlist_validator;

    apr_table_setn(new->subprocess_env, "REDIRECT_STATUS",
	apr_psprintf(r->pool, "%d", r->status));

    /*
     * XXX: hmm.  This is because mod_setenvif and mod_unique_id really need
     * to do their thing on internal redirects as well.  Perhaps this is a
     * misnamed function.
     */
    if ((access_status = ap_run_post_read_request(new))) {
        ap_die(access_status, new);
        return NULL;
    }

#ifdef APACHE_XLATE
    new->rrx = apr_pcalloc(new->pool, sizeof(struct ap_rr_xlate));
    ap_set_content_xlate(new, 1, ap_locale_to_ascii);
    ap_set_content_xlate(new, 0, ap_locale_from_ascii);
#endif /*APACHE_XLATE*/

    return new;
}

API_EXPORT(void) ap_internal_redirect(const char *new_uri, request_rec *r)
{
    request_rec *new = internal_internal_redirect(new_uri, r);
    process_request_internal(new);
}

/* This function is designed for things like actions or CGI scripts, when
 * using AddHandler, and you want to preserve the content type across
 * an internal redirect.
 */
API_EXPORT(void) ap_internal_redirect_handler(const char *new_uri, request_rec *r)
{
    request_rec *new = internal_internal_redirect(new_uri, r);
    if (r->handler)
        new->content_type = r->content_type;
    process_request_internal(new);
}

/*
 * Is it the initial main request, which we only get *once* per HTTP request?
 */
API_EXPORT(int) ap_is_initial_req(request_rec *r)
{
    return
        (r->main == NULL)       /* otherwise, this is a sub-request */
        &&
        (r->prev == NULL);      /* otherwise, this is an internal redirect */
}

/*
 * Function to set the r->mtime field to the specified value if it's later
 * than what's already there.
 */
API_EXPORT(void) ap_update_mtime(request_rec *r, apr_time_t dependency_mtime)
{
    if (r->mtime < dependency_mtime) {
	r->mtime = dependency_mtime;
    }
}
