/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_filter.h"
#include "util_charset.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif

APR_HOOK_STRUCT(
	    APR_HOOK_LINK(translate_name)
	    APR_HOOK_LINK(map_to_storage)
	    APR_HOOK_LINK(check_user_id)
	    APR_HOOK_LINK(fixups)
	    APR_HOOK_LINK(type_checker)
	    APR_HOOK_LINK(access_checker)
	    APR_HOOK_LINK(auth_checker)
	    APR_HOOK_LINK(insert_filter)
            APR_HOOK_LINK(create_request)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int,translate_name,
                            (request_rec *r),(r),DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,map_to_storage,
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
AP_IMPLEMENT_HOOK_RUN_ALL(int,create_request,(request_rec *r),(r),OK,DECLINED)


static int decl_die(int status, char *phase, request_rec *r)
{
    if (status == DECLINED) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_CRIT, 0, r,
                    "configuration error:  couldn't %s: %s", phase, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else
        return status;
}

/* This is the master logic for processing requests.  Do NOT duplicate
 * this logic elsewhere, or the security model will be broken by future
 * API changes.  Each phase must be individually optimized to pick up
 * redundant/duplicate calls by subrequests, and redirects.
 */
AP_DECLARE(int) ap_process_request_internal(request_rec *r)
{
    int access_status;

    /* Ignore embedded %2F's in path for proxy requests */
    if (!r->proxyreq && r->parsed_uri.path) {
	access_status = ap_unescape_url(r->parsed_uri.path);
	if (access_status) {
	    return access_status;
	}
    }

    ap_getparents(r->uri);     /* OK --- shrinking transformations... */

    if ((access_status = ap_location_walk(r))) {
        return access_status;
    }

    if ((access_status = ap_run_translate_name(r))) {
        return decl_die(access_status, "translate", r);
        return access_status;
    }

    if ((access_status = ap_run_map_to_storage(r))) {
        /* This request wasn't in storage (e.g. TRACE) */
        return access_status;
    }

    if ((access_status = ap_location_walk(r))) {
        return access_status;
    }

    /* Only on the main request! */
    if (r->main == NULL) {
        if ((access_status = ap_run_header_parser(r))) {
            return access_status;
        }
    }

    switch (ap_satisfies(r)) {
    case SATISFY_ALL:
    case SATISFY_NOSPEC:
        if ((access_status = ap_run_access_checker(r)) != 0) {
            return decl_die(access_status, "check access", r);
        }
        if (ap_some_auth_required(r)) {
            if (((access_status = ap_run_check_user_id(r)) != 0) || !ap_auth_type(r)) {
                return decl_die(access_status, ap_auth_type(r)
		            ? "check user.  No user file?"
		            : "perform authentication. AuthType not set!", r);
            }
            if (((access_status = ap_run_auth_checker(r)) != 0) || !ap_auth_type(r)) {
                return decl_die(access_status, ap_auth_type(r)
		            ? "check access.  No groups file?"
		            : "perform authentication. AuthType not set!", r);
            }
        }
        break;
    case SATISFY_ANY:
        if (((access_status = ap_run_access_checker(r)) != 0) || !ap_auth_type(r)) {
            if (!ap_some_auth_required(r)) {
                return decl_die(access_status, ap_auth_type(r)
		            ? "check access"
		            : "perform authentication. AuthType not set!", r);
            }
            if (((access_status = ap_run_check_user_id(r)) != 0) || !ap_auth_type(r)) {
                return decl_die(access_status, ap_auth_type(r)
		            ? "check user.  No user file?"
		            : "perform authentication. AuthType not set!", r);
            }
            if (((access_status = ap_run_auth_checker(r)) != 0) || !ap_auth_type(r)) {
                return decl_die(access_status, ap_auth_type(r)
		            ? "check access.  No groups file?"
		            : "perform authentication. AuthType not set!", r);
            }
        }
        break;
    }

    /* XXX Must make certain the ap_run_type_checker short circuits mime
     * in mod-proxy for r->proxyreq && r->parsed_uri.scheme 
     *                              && !strcmp(r->parsed_uri.scheme, "http")
     */
    if ((access_status = ap_run_type_checker(r)) != 0) {
	return decl_die(access_status, "find types", r);
    }

    if ((access_status = ap_run_fixups(r)) != 0) {
        return access_status;
    }

    /* The new insert_filter stage makes sense here IMHO.  We are sure that
     * we are going to run the request now, so we may as well insert filters
     * if any are available.  Since the goal of this phase is to allow all
     * modules to insert a filter if they want to, this filter returns
     * void.  I just can't see any way that this filter can reasonably
     * fail, either your modules inserts something or it doesn't.  rbb
     */
    ap_run_insert_filter(r);

    return OK;
}


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

    if (r->finfo.filetype == 0      /* doesn't exist */
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

#ifdef REPLACE_PATH_INFO_METHOD
/*
 * resolve_symlink must _always_ be called on an APR_LNK file type!
 * It will resolve the actual target file type, modification date, etc, 
 * and provide any processing required for symlink evaluation.
 * Path must already be cleaned, no trailing slash, no multi-slashes,
 * and don't call this on the root!
 *
 * Simply, the number of times we deref a symlink are minimal compared
 * to the number of times we had an extra lstat() since we 'weren't sure'.
 *
 * To optimize, we stat() anything when given (opts & OPT_SYM_LINKS), otherwise
 * we start off with an lstat().  Every lstat() must be dereferenced in case 
 * it points at a 'nasty' - we must always rerun check_safe_file (or similar.)
 */
static int resolve_symlink(char *d, apr_finfo_t *lfi, int opts, apr_pool_t *p)
{
    apr_finfo_t fi;
    int res;

    if (!(opts & (OPT_SYM_OWNER | OPT_SYM_LINKS)))
        return HTTP_FORBIDDEN;

    if (opts & OPT_SYM_LINKS) {
        if ((res = apr_stat(&fi, d, lfi->valid, p)) != APR_SUCCESS)
            return HTTP_FORBIDDEN;
        return OK;
    }

    /* OPT_SYM_OWNER only works if we can get the owner of 
     * both the file and symlink.  First fill in a missing
     * owner of the symlink, then get the info of the target.
     */
    if (!(lfi->valid & APR_FINFO_OWNER))
        if ((res = apr_lstat(&fi, d, lfi->valid | APR_FINFO_OWNER, p))
                != APR_SUCCESS)
            return HTTP_FORBIDDEN;

    if ((res = apr_stat(&fi, d, lfi->valid, p)) != APR_SUCCESS)
        return HTTP_FORBIDDEN;

    if (apr_compare_users(fi.user, lfi->user) != APR_SUCCESS) 
        return HTTP_FORBIDDEN;

    /* Give back the target */
    memcpy(lfi, &fi, sizeof(fi));
    return OK;
}
#endif /* REPLACE_PATH_INFO_METHOD */

#ifndef REPLACE_PATH_INFO_METHOD

static int check_symlinks(char *d, int opts, apr_pool_t *p)
{
#if defined(OS2)
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

    res = apr_lstat(&lfi, d, APR_FINFO_TYPE | APR_FINFO_OWNER, p);

    if (lastp)
        *lastp = '/';

    /*
     * Note that we don't reject accesses to nonexistent files (multiviews or
     * the like may cons up a way to run the transaction anyway)...
     */

    if ((res != APR_SUCCESS && res != APR_INCOMPLETE)
           || (lfi.filetype != APR_LNK))
        return OK;

    /* OK, it's a symlink.  May still be OK with OPT_SYM_OWNER */

    if (!(opts & OPT_SYM_OWNER))
        return HTTP_FORBIDDEN;

    /* OPT_SYM_OWNER only works if we can get the owner from the file */

    if (res != APR_SUCCESS)
        return HTTP_FORBIDDEN;

    if (apr_stat(&fi, d, APR_FINFO_OWNER, p) != APR_SUCCESS)
        return HTTP_FORBIDDEN;

    /* TODO: replace with an apr_compare_users() fn */
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
    int rv;
#if defined(HAVE_DRIVE_LETTERS) || defined(HAVE_UNC_PATHS)
    char bStripSlash=1;
#endif

    if (r->finfo.filetype != APR_NOFILE) {
	/* assume path_info already set */
	return OK;
    }

#ifdef HAVE_DRIVE_LETTERS
    /* If the directory is x:\, then we don't want to strip
     * the trailing slash since x: is not a valid directory.
     */
    if (strlen(path) == 3 && path[1] == ':' && path[2] == '/')
        bStripSlash = 0;
#endif

#ifdef HAVE_UNC_PATHS
    /* If UNC name == //machine/share/, do not 
     * advance over the trailing slash.  Any other
     * UNC name is OK to strip the slash.
     */
    cp = end;
    if (path[0] == '/' && path[1] == '/' && 
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
#endif
   
#if defined(HAVE_DRIVE_LETTERS) || defined(HAVE_UNC_PATHS)
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

        /* ### We no longer need the test ap_os_is_filename_valid() here 
         * since apr_stat isn't a posix thing - it's apr_stat's responsibility
         * to handle whatever path string arrives at its door - by platform
         * and volume restrictions as applicable... 
         * TODO: This code becomes even simpler if apr_stat grows 
         * an APR_PATHINCOMPLETE result to indicate that we are staring at
         * an partial virtual root.  Only OS2/Win32/Netware need apply it :-)
         */
        rv = apr_stat(&r->finfo, path, APR_FINFO_MIN, r->pool);

        if (cp != end)
            *cp = '/';

        if (rv == APR_SUCCESS || rv == APR_INCOMPLETE) {
            /*
             * Aha!  Found something.  If it was a directory, we will search
             * contents of that directory for a multi_match, so the PATH_INFO
             * argument starts with the component after that.
             */
            if (r->finfo.filetype == APR_DIR && last_cp) {
                r->finfo.filetype = APR_NOFILE;  /* No such file... */
                cp = last_cp;
            }

            r->path_info = apr_pstrdup(r->pool, cp);
            *cp = '\0';
            return OK;
        }
        
        if (APR_STATUS_IS_ENOENT(rv) || APR_STATUS_IS_ENOTDIR(rv)) {
            last_cp = cp;

            while (--cp > path && *cp != '/')
                continue;

            while (cp > path && cp[-1] == '/')
                --cp;
        }
        else {
            if (APR_STATUS_IS_EACCES(rv))
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "access to %s denied", r->uri);
            else
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "access to %s failed", r->uri);
            return HTTP_FORBIDDEN;
        }
    }
    return OK;
}

AP_DECLARE(int) ap_directory_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t *per_dir_defaults = r->server->lookup_defaults;
    ap_conf_vector_t **sec_dir = (ap_conf_vector_t **) sconf->sec_dir->elts;
    int num_sec = sconf->sec_dir->nelts;
    char *test_filename;
    char *test_dirname;
    int res;
    unsigned i, num_dirs;
    int j, test_filename_len;
    unsigned iStart = 1;
    ap_conf_vector_t *entry_config;
    ap_conf_vector_t *this_conf;
    core_dir_config *entry_core;

    /* "OK" as a response to a real problem is not _OK_, but to allow broken 
     * modules to proceed, we will permit the not-a-path filename to pass here.
     * We must catch it later if it's heading for the core handler.  Leave an 
     * INFO note here for module debugging.
     */
    if (r->filename == NULL || !ap_os_is_path_absolute(r->pool, r->filename)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                      "Module bug?  Request filename path %s is missing or "
                      "or not absolute for uri %s", 
                      r->filename ? r->filename : "<NULL>", r->uri);
        return OK;
    }

    /*
     * Go down the directory hierarchy.  Where we have to check for symlinks,
     * do so.  Where a .htaccess file has permission to override anything,
     * try to find one.  If either of these things fails, we could poke
     * around, see why, and adjust the lookup_rec accordingly --- this might
     * save us a call to get_path_info (with the attendant stat()s); however,
     * for the moment, that's not worth the trouble.
     */
    res = get_path_info(r);
    if (res != OK) {
        return res;
    }

    /* XXX Momentary period of extreme danger, Will Robinson.
     * Removed ap_os_canonical_filename.  Anybody munging the
     * r->filename better have pre-canonicalized the name that
     * they just changed.  Since the two most key functions
     * in the entire server, ap_server_root_relative() and
     * ap_make_full_path now canonicalize as they go.
     *
     * To be very safe, the server is in hyper-paranoid mode.
     * That means that non-canonical paths will be captured and
     * denied.  This is very cpu/fs intensive, we need to finish
     * auditing, and remove the paranoia trigger.
     */
    if (r->filename == r->canonical_filename)
#ifdef NO_LONGER_PARANOID
        test_filename = apr_pstrdup(r->pool, r->filename);
#else
    {
        if (apr_filepath_merge(&test_filename, "", r->filename,
                               APR_FILEPATH_NOTRELATIVE | APR_FILEPATH_TRUENAME,
                               r->pool) != APR_SUCCESS
               || strcmp(test_filename, r->filename) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          "Module bug?  Filepath: %s is not the canonical %s", 
                          r->filename, test_filename);
            return HTTP_FORBIDDEN;
        }
    }
#endif
    else {
        /* Apparently, somebody didn't know to update r->canonical_filename
         * which is lucky, since they didn't canonicalize r->filename either.
         */
        if (apr_filepath_merge(&test_filename, NULL, r->filename,
                               APR_FILEPATH_NOTRELATIVE | APR_FILEPATH_TRUENAME,
                               r->pool) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          "Module bug?  Filepath: %s is not an absolute path", 
                          r->filename);
            return HTTP_FORBIDDEN;
        }
        if (strcmp(r->filename, test_filename) != 0)
            r->filename = apr_pstrdup(r->pool, test_filename);
        r->canonical_filename = r->filename;
    }

    num_dirs = ap_count_dirs(test_filename);

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

    /* XXX The garbage below disappears in the new directory_walk;
     */

#if defined(HAVE_UNC_PATHS)
    /* If the name is a UNC name, then do not perform any true file test
     * against the machine name (start at //machine/share/)
     * This is optimized to use the normal walk (skips the redundant '/' root)
     */
    if (num_dirs > 3 && test_filename[0] == '/' && test_filename[1] == '/')
        iStart = 4;
#endif

#if defined(NETWARE)
    /* If the name is a fully qualified volume name, then do not perform any
     * true file test on the machine name (start at machine/share:/)
     * XXX: The implementation eludes me at this moment... 
     *      Does this make sense?  Please test!
     */
    if (num_dirs > 1 && strchr(test_filename, '/') < strchr(test_filename, ':'))
        iStart = 2;
#endif

    /* i keeps track of how many segments we are testing
     * j keeps track of which section we're on, see core_reorder_directories 
     */
    j = 0;
    for (i = 1; i <= num_dirs; ++i) {
        int overrides_here;
        core_dir_config *core_dir = ap_get_module_config(per_dir_defaults,
                                                         &core_module);

        /*
         * XXX: this could be made faster by only copying the next component
         * rather than copying the entire thing all over.
         */
        ap_make_dirstr_prefix(test_dirname, test_filename, i);

        /*
         * Do symlink checks first, because they are done with the
         * permissions appropriate to the *parent* directory...
         */

        /* Test only real names (after the root) against the real filesystem */
        if ((i > iStart) && (res = check_symlinks(test_dirname, core_dir->opts, r->pool))) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        "Symbolic link not allowed: %s", test_dirname);
            return res;
        }

        /*
         * Begin *this* level by looking for matching <Directory> sections
         * from access.conf.
         */

        for (; j < num_sec; ++j) {
            char *entry_dir;

            entry_config = sec_dir[j];
            entry_core = ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            if (entry_core->r || entry_core->d_components > i)
                break;

            this_conf = NULL;
            /* We will always add in '0' element components, e.g. plain old
             * <Directory >, and <Directory "/"> is classified as zero 
             * so that Win32/Netware/OS2 etc all pick that up.
             */
            if (!entry_core->d_components) {
                this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
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
                core_dir = ap_get_module_config(per_dir_defaults,
                                                &core_module);
            }
        }
        overrides_here = core_dir->override;

        /* If .htaccess files are enabled, check for one. */

        /* Test only legal names against the real filesystem */
        if ((i >= iStart) && overrides_here) {
            ap_conf_vector_t *htaccess_conf = NULL;

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
     * Now we'll deal with the regexes.
     */
    for (; j < num_sec; ++j) {

        entry_config = sec_dir[j];
        entry_core = ap_get_module_config(entry_config, &core_module);

        if (!entry_core->r) {
            continue;
        }
        if (!ap_regexec(entry_core->r, test_dirname, 0, NULL, REG_NOTEOL)) {
            per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                        per_dir_defaults,
                                                        entry_config);
        }
    }
    r->per_dir_config = per_dir_defaults;

    /*
     * Symlink permissions are determined by the parent.  If the request is
     * for a directory then applying the symlink test here would use the
     * permissions of the directory as opposed to its parent.  Consider a
     * symlink pointing to a dir with a .htaccess disallowing symlinks.  If
     * you access /symlink (or /symlink/) you would get a 403 without this
     * APR_DIR test.  But if you accessed /symlink/index.html, for example,
     * you would *not* get the 403.
     */
    if (r->finfo.filetype != APR_DIR
        && (res = check_symlinks(r->filename, ap_allow_options(r), r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    "Symbolic link not allowed: %s", r->filename);
        return res;
    }

    /* Save a dummy userdata element till we optimize this function.
     * If this userdata is set, directory_walk has run.
     */
    apr_pool_userdata_set((void *)1, "ap_directory_walk::cache",
                          apr_pool_cleanup_null, r->pool);

    return OK;                  /* Can only "fail" if access denied by the
                                 * symlink goop. */
}

#else /* defined REPLACE_PATH_INFO_METHOD */

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

AP_DECLARE(int) ap_directory_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t *per_dir_defaults = r->server->lookup_defaults;
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **) sconf->sec_dir->elts;
    int num_sec = sconf->sec_dir->nelts;
    int sec_idx;
    unsigned int seg, startseg;
    int res;
    ap_conf_vector_t *entry_config;
    core_dir_config *entry_core;
    apr_status_t rv;
    apr_size_t buflen;
    char *seg_name;
    char *delim;

    /* XXX: Better (faster) tests needed!!!
     *
     * "OK" as a response to a real problem is not _OK_, but to allow broken 
     * modules to proceed, we will permit the not-a-path filename to pass here.
     * We must catch it later if it's heading for the core handler.  Leave an 
     * INFO note here for module debugging.
     */
    if (r->filename == NULL || !ap_os_is_path_absolute(r->pool, r->filename)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                      "Module bug?  Request filename path %s is missing or "
                      "or not absolute for uri %s", 
                      r->filename ? r->filename : "<NULL>", r->uri);
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
     * r->path_info tracks the remaining source path.
     * r->filename  tracks the path as we build it.
     * we begin our adventure at the root...
     */
    r->path_info = r->filename;
    if ((rv = apr_filepath_merge(&r->path_info, NULL, r->filename, 
                                 APR_FILEPATH_NOTRELATIVE, r->pool)) 
                  == APR_SUCCESS) {
        char *buf;
        rv = apr_filepath_root(&r->filename, &r->path_info, 
                               APR_FILEPATH_TRUENAME, r->pool);
        buflen = strlen(r->filename) + strlen(r->path_info) + 1;
        buf = apr_palloc(r->pool, buflen);
        strcpy (buf, r->filename);
        r->filename = buf;
        r->finfo.valid = APR_FINFO_TYPE;
        r->finfo.filetype = APR_DIR; /* It's the root, of course it's a dir */
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "Config bug?  Request filename path %s is invalid or "
                      "or not absolute for uri %s", 
                      r->filename, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * seg keeps track of which segment we've copied.
     * sec_idx keeps track of which section we're on, since sections are
     *     ordered by number of segments. See core_reorder_directories 
     */
    startseg = seg = ap_count_dirs(r->filename);
    sec_idx = 0;
    do {
        int overrides_here;
        core_dir_config *core_dir = ap_get_module_config(per_dir_defaults,
                                                         &core_module);
        
        /* We have no trailing slash, but we sure would appreciate one...
         */
        if (sec_idx && r->filename[strlen(r->filename)-1] != '/')
            strcat(r->filename, "/");

        /* Begin *this* level by looking for matching <Directory> sections
         * from the server config.
         */
        for (; sec_idx < num_sec; ++sec_idx) {
            const char *entry_dir;

            entry_config = sec_ent[sec_idx];
            entry_core = ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            /* No more possible matches for this many segments? 
             * We are done when we find relative/regex/longer components.
             */
            if (entry_core->r || entry_core->d_components > seg)
                break;

            /* We will never skip '0' element components, e.g. plain old
             * <Directory >, and <Directory "/"> are classified as zero 
             * so that Win32/Netware/OS2 etc all pick them up.
             * Otherwise, skip over the mismatches.
             */
            if (entry_core->d_components
                  && (entry_core->d_is_fnmatch
                        ? (apr_fnmatch(entry_dir, r->filename, FNM_PATHNAME) != APR_SUCCESS)
                        : (strcmp(r->filename, entry_dir) != 0))) {
                continue;
            }

            per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                        per_dir_defaults,
                                                        entry_config);
            core_dir = ap_get_module_config(per_dir_defaults,
                                                &core_module);
        }
        overrides_here = core_dir->override;

        /* If .htaccess files are enabled, check for one. */
        if (overrides_here) {
            ap_conf_vector_t *htaccess_conf = NULL;

            res = ap_parse_htaccess(&htaccess_conf, r, overrides_here,
                                    apr_pstrdup(r->pool, r->filename),
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

        /* That temporary trailing slash was useful, now drop it.
         */
        if (seg > startseg)
            r->filename[strlen(r->filename) - 1] = '\0';

        /* Time for all good things to come to an end?
         */
        if (!r->path_info || !*r->path_info)
            break;

        /* Now it's time for the next segment... 
         * We will assume the next element is an end node, and fix it up
         * below as necessary...
         */
        
        seg_name = strchr(r->filename, '\0');
        delim = strchr(r->path_info + (*r->path_info == '/' ? 1 : 0), '/');
        if (delim) {
            *delim = '\0';
            strcpy(seg_name, r->path_info);
            r->path_info = delim;
            *delim = '/';
        }
        else {
            strcpy(seg_name, r->path_info);
            r->path_info = strchr(r->path_info, '\0');
        }
        if (*seg_name == '/') 
            ++seg_name;
        
        /* If nothing remained but a '/' string, we are finished
         */
        if (!*seg_name)
            break;

        /* XXX: Optimization required:
         * If...we have allowed symlinks, and
         * if...we find the segment exists in the directory list
         * skip the lstat and dummy up an APR_DIR value for r->finfo
         * this means case sensitive platforms go quite quickly.
         * Case insensitive platforms might be given the wrong path,
         * but if it's not found in the cache, then we know we have
         * something to test (the misspelling is never cached.)
         */

        /* We choose apr_lstat here, rather that apr_stat, so that we
         * capture this path object rather than its target.  We will
         * replace the info with our target's info below.  We especially
         * want the name of this 'link' object, not the name of its
         * target, if we are fixing case.
         */
        rv = apr_lstat(&r->finfo, r->filename, APR_FINFO_MIN | APR_FINFO_NAME, r->pool);

        if (APR_STATUS_IS_ENOENT(rv)) {
            /* Nothing?  That could be nice.  But our directory walk is done.
             */
            r->finfo.filetype = APR_NOFILE;
            break;
        }
        else if (APR_STATUS_IS_EACCES(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "access to %s denied", r->uri);
            return r->status = HTTP_FORBIDDEN;
        }
        else if ((rv != APR_SUCCESS && rv != APR_INCOMPLETE) 
                 || !(r->finfo.valid & APR_FINFO_TYPE)) {
            /* If we hit ENOTDIR, we must have over-optimized, deny 
             * rather than assume not found.
             */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "access to %s failed", r->uri);
            return r->status = HTTP_FORBIDDEN;
        }
        else if ((res = check_safe_file(r))) {
            r->status = res;
            return res;
        }

        /* Fix up the path now if we have a name, and they don't agree
         */
        if ((r->finfo.valid & APR_FINFO_NAME) 
            && strcmp(seg_name, r->finfo.name)) {
            /* TODO: provide users an option that an internal/external
             * redirect is required here?
             */
            strcpy(seg_name, r->finfo.name);
        }

        if (r->finfo.filetype == APR_LNK) 
        {
            /* Is this an possibly acceptable symlink?
             */
            if ((res = resolve_symlink(r->filename, &r->finfo, 
                                       core_dir->opts, r->pool)) != OK) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                            "Symbolic link not allowed: %s", r->filename);
                return r->status = res;
            }

            /* Ok, we are done with the link's info, test the real target
             */
            if (r->finfo.filetype == APR_REG) {
                /* That was fun, nothing left for us here
                 */
                break;
            }
            else if (r->finfo.filetype != APR_DIR) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                              "symlink doesn't point to a file or directory: %s",
                              r->filename);
                return r->status = HTTP_FORBIDDEN;
            }
        }

        ++seg;
    } while (r->finfo.filetype == APR_DIR);

    /*
     * Now we'll deal with the regexes.
     */
    for (; sec_idx < num_sec; ++sec_idx) {

        entry_config = sec_ent[sec_idx];
        entry_core = ap_get_module_config(entry_config, &core_module);

        if (!entry_core->r) {
            continue;
        }
        if (!ap_regexec(entry_core->r, r->filename, 0, NULL, REG_NOTEOL)) {
            per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                        per_dir_defaults,
                                                        entry_config);
        }
    }
    r->per_dir_config = per_dir_defaults;

/* It seems this shouldn't be needed anymore.  We translated the symlink above
 x  into a real resource, and should have died up there.  Even if we keep this,
 x  it needs more thought (maybe an r->file_is_symlink) perhaps it should actually
 x  happen in file_walk, so we catch more obscure cases in autoindex sub requests, etc.
 x
 x    * Symlink permissions are determined by the parent.  If the request is
 x    * for a directory then applying the symlink test here would use the
 x    * permissions of the directory as opposed to its parent.  Consider a
 x    * symlink pointing to a dir with a .htaccess disallowing symlinks.  If
 x    * you access /symlink (or /symlink/) you would get a 403 without this
 x    * APR_DIR test.  But if you accessed /symlink/index.html, for example,
 x    * you would *not* get the 403.
 x
 x   if (r->finfo.filetype != APR_DIR
 x       && (res = resolve_symlink(r->filename, r->info, ap_allow_options(r), r->pool))) {
 x       ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
 x                   "Symbolic link not allowed: %s", r->filename);
 x       return res;
 x   }
 */

    /* Save a dummy userdata element till we optimize this function.
     * If this userdata is set, directory_walk has run.
     */
    apr_pool_userdata_set((void *)1, "ap_directory_walk::cache",
                          apr_pool_cleanup_null, r->pool);

    return OK;  /* 'no excuses' */
}

#endif /* defined REPLACE_PATH_INFO_METHOD */

typedef struct walk_walked_t {
    ap_conf_vector_t *matched; /* A dir_conf sections we matched */
    ap_conf_vector_t *merged;  /* The dir_conf merged result */
} walk_walked_t;

typedef struct walk_cache_t {
    const char         *cached;         /* The identifier we matched */
    ap_conf_vector_t  **dir_conf_tested;/* The sections we matched against */
    ap_conf_vector_t   *per_dir_result; /* per_dir_config += walked result */
    apr_array_header_t *walked;         /* The list of walk_walked_t results */
} walk_cache_t;

AP_DECLARE(int) ap_location_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t **locations = (ap_conf_vector_t **) sconf->sec_url->elts;
    int num_loc = sconf->sec_url->nelts;
    core_dir_config *entry_core;
    walk_cache_t *cache;
    walk_walked_t *last_walk;
    const char *entry_uri;
    int len, j;

    /* Find the most relevant, recent entry to work from.  That would be
     * this request (on the second call), or the parent request of a
     * subrequest, or the prior request of an internal redirect.
     */
    if ((apr_pool_userdata_get((void **)&cache, 
                               "ap_location_walk::cache", r->pool)
                != APR_SUCCESS) || !cache) 
    {
        if ((r->main && (apr_pool_userdata_get((void **)&cache, 
                                               "ap_location_walk::cache",
                                               r->main->pool)
                                 == APR_SUCCESS) && cache)
         || (r->prev && (apr_pool_userdata_get((void **)&cache, 
                                               "ap_location_walk::cache",
                                               r->prev->pool)
                                 == APR_SUCCESS) && cache)) {
            cache = apr_pmemdup(r->pool, cache, sizeof(*cache));
            cache->walked = apr_array_copy(r->pool, cache->walked);
        }
        else {
            cache = apr_pcalloc(r->pool, sizeof(*cache));
            cache->walked = apr_array_make(r->pool, 4, sizeof(walk_walked_t));
        }
        apr_pool_userdata_set(cache, "ap_location_walk::cache", 
                              apr_pool_cleanup_null, r->pool);
    }

    /* If the initial request creation logic failed to reset the
     * per_dir_config, we will do so here.
     * ### at this time, only subreq creation fails to do so.
     */
    if (!r->per_dir_config)
        r->per_dir_config = r->server->lookup_defaults;
    
    /* No tricks here, there are no <Locations > to parse in this vhost.
     * We won't destroy the cache, just in case _this_ redirect is later
     * redirected again to a vhost with <Location > blocks to optimize.
     */
    if (!num_loc) {
	return OK;
    }

    /* Location and LocationMatch differ on their behaviour w.r.t. multiple
     * slashes.  Location matches multiple slashes with a single slash,
     * LocationMatch doesn't.  An exception, for backwards brokenness is
     * absoluteURIs... in which case neither match multiple slashes.
     */
    if (r->uri[0] != '/') {
	entry_uri = r->uri;
    }
    else {
        char *uri = apr_pstrdup(r->pool, r->uri);
	ap_no2slash(uri);
        entry_uri = uri;
    }

    /* If we have an cache->cached location that matches r->uri,
     * and the vhost's list of locations hasn't changed, we can skip
     * rewalking the location_walk entries.
     */
    if (cache->cached && (cache->dir_conf_tested == locations) 
                      && (strcmp(entry_uri, cache->cached) == 0)) {
        /* Well this looks really familiar!  If our end-result (per_dir_result)
         * didn't change, we have absolutely nothing to do :)  
         * Otherwise (as is the case with most dir_merged/file_merged requests)
         * we must merge our dir_conf_merged onto this new r->per_dir_config.
         */
        if (cache->per_dir_result == r->per_dir_config)
            return OK;
        if (cache->walked->nelts)
            now_merged = ((walk_walked_t*)cache->walked->elts)
                                            [cache->walked->nelts - 1].merged;
    }
    else {
        /* We start now_merged from NULL since we want to build 
         * a locations list that can be merged to any vhost.
         */
        int matches = cache->walked->nelts;
        last_walk = (walk_walked_t*)cache->walked->elts;
        cache->cached = entry_uri;
        cache->dir_conf_tested = locations;

        /* Go through the location entries, and check for matches.
         * We apply the directive sections in given order, we should
         * really try them with the most general first.
         */
        for (j = 0; j < num_loc; ++j) {

	    entry_core = ap_get_module_config(locations[j], &core_module);
	    entry_uri = entry_core->d;

	    len = strlen(entry_uri);

            /* Test the regex, fnmatch or string as appropriate.
             * If it's a strcmp, and the <Location > pattern was 
             * not slash terminated, then this uri must be slash
             * terminated (or at the end of the string) to match.
             */
	    if (entry_core->r 
                  ? ap_regexec(entry_core->r, r->uri, 0, NULL, 0)
                  : (entry_core->d_is_fnmatch
                       ? apr_fnmatch(entry_uri, cache->cached, FNM_PATHNAME)
                       : (strncmp(cache->cached, entry_uri, len)
                            || (entry_uri[len - 1] != '/'
                             && cache->cached[len] != '/' 
                             && cache->cached[len] != '\0')))) {
	        continue;
            }

            /* If we merged this same section last time, reuse it
             */
            if (matches) {
                if (last_walk->matched == locations[j]) {
                    now_merged = last_walk->merged;
                    ++last_walk;
                    --matches;
                    continue;
                }
                /* We fell out of sync.  This is our own copy of walked,
                 * so truncate the remaining matches and reset remaining.
                 */
                cache->walked->nelts -= matches;
                matches = 0;
            }

            if (now_merged)
	        now_merged = ap_merge_per_dir_configs(r->pool, 
                                                      now_merged,
                                                      locations[j]);
            else
                now_merged = locations[j];

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = locations[j];
            last_walk->merged = now_merged;
        }
        /* Whoops - everything matched in sequence, but the original walk
         * found some additional matches.  Truncate them.
         */
        if (matches)
            cache->walked->nelts -= matches;
    }

    /* Merge our cache->dir_conf_merged construct with the r->per_dir_configs,
     * and note the end result to (potentially) skip this step next time.
     */
    if (now_merged)
        r->per_dir_config = ap_merge_per_dir_configs(r->pool,
                                                     r->per_dir_config,
                                                     now_merged);
    cache->per_dir_result = r->per_dir_config;

    return OK;
}

AP_DECLARE(int) ap_file_walk(request_rec *r)
{
    core_dir_config *conf = ap_get_module_config(r->per_dir_config,
                                                 &core_module);
    ap_conf_vector_t *per_dir_defaults = r->per_dir_config;
    ap_conf_vector_t **file = (ap_conf_vector_t **) conf->sec_file->elts;
    int num_files = conf->sec_file->nelts;
    char *test_file;

    /* To allow broken modules to proceed, we allow missing filenames to pass.
     * We will catch it later if it's heading for the core handler.  
     * directory_walk already posted an INFO note for module debugging.
     */
     if (r->filename == NULL) {
        return OK;
    }

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
        ap_conf_vector_t *this_conf;
        ap_conf_vector_t *entry_config;
        core_dir_config *entry_core;
        char *entry_file;
        int j;

        /* we apply the directive sections in some order;
         * should really try them with the most general first.
         */
        for (j = 0; j < num_files; ++j) {

            entry_config = file[j];

            entry_core = ap_get_module_config(entry_config, &core_module);
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

    /* Save a dummy userdata element till we optimize this function.
     * If this userdata is set, file_walk has run.
     */
    apr_pool_userdata_set((void *)1, "ap_file_walk::cache",
                          apr_pool_cleanup_null, r->pool);

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
    
    apr_pool_create(&rrp, r->pool);
    rr = apr_pcalloc(rrp, sizeof(request_rec));
    rr->pool = rrp;
    return rr;
}

static void fill_in_sub_req_vars(request_rec *rnew, const request_rec *r,
                                 ap_filter_t *next_filter)
{
    rnew->hostname       = r->hostname;
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;

    rnew->request_config = ap_create_request_config(rnew->pool);

    rnew->htaccess       = r->htaccess;
    rnew->allowed_methods = ap_make_method_list(rnew->pool, 2);

    /* make a copy of the allowed-methods list */
    ap_copy_method_list(rnew->allowed_methods, r->allowed_methods);

    /* start with the same set of output filters */
    if (next_filter) {
        rnew->output_filters = next_filter;
    }
    else {
        rnew->output_filters = r->output_filters;
    }
    ap_add_output_filter("SUBREQ_CORE", NULL, rnew, rnew->connection); 

    /* no input filters for a subrequest */

    ap_set_sub_req_protocol(rnew, r);
}

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_sub_req_output_filter(ap_filter_t *f,
                                                        apr_bucket_brigade *bb)
{
    apr_bucket *e = APR_BRIGADE_LAST(bb);

    if (APR_BUCKET_IS_EOS(e)) {
        apr_bucket_delete(e);
    }
    return ap_pass_brigade(f->next, bb);
}

 
AP_DECLARE(int) ap_some_auth_required(request_rec *r)
{
    /* Is there a require line configured for the type of *this* req? */
 
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    int i;
 
    if (!reqs_arr)
        return 0;
 
    reqs = (require_line *) reqs_arr->elts;
 
    for (i = 0; i < reqs_arr->nelts; ++i)
        if (reqs[i].method_mask & (AP_METHOD_BIT << r->method_number))
            return 1;
 
    return 0;
} 


AP_DECLARE(request_rec *) ap_sub_req_method_uri(const char *method,
                                                const char *new_file,
                                                const request_rec *r,
                                                ap_filter_t *next_filter)
{
    request_rec *rnew;
    int res;
    char *udir;

    rnew = make_sub_request(r);
    fill_in_sub_req_vars(rnew, r, next_filter);

    rnew->per_dir_config = r->server->lookup_defaults;

    /* We have to run this after fill_in_sub_req_vars, or the r->main
     * pointer won't be setup
     */
    ap_run_create_request(rnew);

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

    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }

    return rnew;
}

AP_DECLARE(request_rec *) ap_sub_req_lookup_uri(const char *new_file,
                                                const request_rec *r,
                                                ap_filter_t *next_filter)
{
    return ap_sub_req_method_uri("GET", new_file, r, next_filter);
}

AP_DECLARE(request_rec *) ap_sub_req_lookup_dirent(const apr_finfo_t *dirent,
                                                   const request_rec *r,
                                                   ap_filter_t *next_filter)
{
    request_rec *rnew;
    int res;
    char *fdir;
    char *udir;

    rnew = make_sub_request(r);
    fill_in_sub_req_vars(rnew, r, next_filter);

    rnew->chunked        = r->chunked;

    /* We have to run this after fill_in_sub_req_vars, or the r->main
     * pointer won't be setup
     */
    ap_run_create_request(rnew);

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);

    /*
     * Special case: we are looking at a relative lookup in the same directory. 
     * That means we won't have to redo directory_walk, and we may
     * not even have to redo access checks.
     */

    udir = ap_make_dirstr_parent(rnew->pool, r->uri);

    /* This is 100% safe, since dirent->name just came from the filesystem */
    rnew->uri = ap_make_full_path(rnew->pool, udir, dirent->name);
    rnew->filename = ap_make_full_path(rnew->pool, fdir, dirent->name);
    if (r->canonical_filename == r->filename)
        rnew->canonical_filename = rnew->filename;
    
    ap_parse_uri(rnew, rnew->uri);    /* fill in parsed_uri values */

#if 0 /* XXX When this is reenabled, the cache triggers need to be set to faux
       * dir_walk/file_walk values.
       */
    rnew->per_dir_config = r->per_dir_config;

    if ((dirent->valid & APR_FINFO_MIN) != APR_FINFO_MIN) {
        /*
         * apr_dir_read isn't very complete on this platform, so
         * we need another apr_lstat (or simply apr_stat if we allow
         * all symlinks here.)  If this is an APR_LNK that resolves 
         * to an APR_DIR, then we will rerun everything anyways... 
         * this should be safe.
         */
        apr_status_t rv;
        if (ap_allow_options(rnew) & OPT_SYM_LINKS) {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename,
                                 APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                                                      && (rv != APR_INCOMPLETE))
                rnew->finfo.filetype = 0;
        }
        else
            if (((rv = apr_lstat(&rnew->finfo, rnew->filename,
                                 APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                                                      && (rv != APR_INCOMPLETE))
                rnew->finfo.filetype = 0;
    }
    else {
        memcpy (&rnew->finfo, dirent, sizeof(apr_finfo_t));
    }

    if ((res = check_safe_file(rnew))) {
        rnew->status = res;
        return rnew;
    }

    if (rnew->finfo.filetype == APR_LNK
        && (res = resolve_symlink(rnew->filename, &rnew->finfo, 
                                  ap_allow_options(rnew), rnew->pool)) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, rnew,
                    "Symbolic link not allowed: %s", rnew->filename);
        rnew->status = res;
        return rnew;
    }

    /*
     * no matter what, if it's a subdirectory, we need to re-run
     * directory_walk
     */
    if (rnew->finfo.filetype == APR_DIR) {
        if (!(res = ap_directory_walk(rnew)))
            if (!(res = ap_file_walk(rnew)))
                res = ap_location_walk(rnew);
    }
    else if (rnew->finfo.filetype == APR_REG || !rnew->finfo.filetype) {
        /*
         * do a file_walk, if it doesn't change the per_dir_config then
         * we know that we don't have to redo all the access checks
         */
        if (   !(res = ap_file_walk(rnew))
            && !(res = ap_location_walk(rnew))
            && (rnew->per_dir_config == r->per_dir_config))
        {
            if (   (res = ap_run_type_checker(rnew)) 
                || (res = ap_run_fixups(rnew))) {
                rnew->status = res;
            }
            return rnew;
        }  
    }
#endif

    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }

    return rnew;
}

AP_DECLARE(request_rec *) ap_sub_req_lookup_file(const char *new_file,
                                              const request_rec *r,
                                              ap_filter_t *next_filter)
{
    request_rec *rnew;
    int res;
    char *fdir;
    apr_size_t fdirlen;

    rnew = make_sub_request(r);
    fill_in_sub_req_vars(rnew, r, next_filter);

    /* XXX Either this is needed for all subreq types (move into
     * fill_in_sub_req_vars), or it isn't needed at all.  
     * WHICH IS IT?
     */
    rnew->chunked        = r->chunked;

    /* We have to run this after fill_in_sub_req_vars, or the r->main
     * pointer won't be setup
     */
    ap_run_create_request(rnew);

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);
    fdirlen = strlen(fdir);

    /* Translate r->filename, if it was canonical, it stays canonical
     */
    if (r->canonical_filename == r->filename)
        rnew->canonical_filename = (char*)(1);
    if (apr_filepath_merge(&rnew->filename, fdir, new_file,
                           APR_FILEPATH_TRUENAME, rnew->pool) != APR_SUCCESS) {
        rnew->status = HTTP_FORBIDDEN;
        return rnew;
    }
    if (rnew->canonical_filename)
        rnew->canonical_filename = rnew->filename;

    /*
     * Check for a special case... if there are no '/' characters in new_file
     * at all, and the path was the same, then we are looking at a relative 
     * lookup in the same directory. That means we won't have to redo 
     * directory_walk, and we may not even have to redo access checks.
     * ### Someday we don't even have to redo the entire directory walk,
     * either, if the base paths match, we can pick up where we leave off.
     */

    if (strncmp(rnew->filename, fdir, fdirlen) == 0
           && rnew->filename[fdirlen] 
           && ap_strchr_c(rnew->filename + fdirlen, '/') == NULL) 
    {
        char *udir = ap_make_dirstr_parent(rnew->pool, r->uri);

        rnew->uri = ap_make_full_path(rnew->pool, udir, new_file);
        ap_parse_uri(rnew, rnew->uri);    /* fill in parsed_uri values */

#if 0 /* XXX When this is reenabled, the cache triggers need to be set to faux
       * dir_walk/file_walk values.
       */

        rnew->per_dir_config = r->per_dir_config;

        /*
         * If this is an APR_LNK that resolves to an APR_DIR, then 
         * we will rerun everything anyways... this should be safe.
         */
        if (ap_allow_options(rnew) & OPT_SYM_LINKS) {
            apr_status_t rv;
            if (((rv = apr_stat(&rnew->finfo, rnew->filename,
                                 APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                                                      && (rv != APR_INCOMPLETE))
                rnew->finfo.filetype = 0;
        }
        else {
            apr_status_t rv;
            if (((rv = apr_lstat(&rnew->finfo, rnew->filename,
                                 APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                                                      && (rv != APR_INCOMPLETE))
                rnew->finfo.filetype = 0;
        }

        if ((res = check_safe_file(rnew))) {
            rnew->status = res;
            return rnew;
        }

        if (rnew->finfo.filetype == APR_LNK
            && (res = resolve_symlink(rnew->filename, &rnew->finfo, 
                                      ap_allow_options(rnew), rnew->pool)) != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, rnew,
                        "Symbolic link not allowed: %s", rnew->filename);
            rnew->status = res;
            return rnew;
        }

        /*
         * no matter what, if it's a subdirectory, we need to re-run
         * directory_walk
         */
        if (rnew->finfo.filetype == APR_DIR) {
            if (!(res = ap_directory_walk(rnew)))
                if (!(res = ap_file_walk(rnew)))
                    res = ap_location_walk(rnew);
        }
        else if (rnew->finfo.filetype == APR_REG || !rnew->finfo.filetype) {
            /*
             * do a file_walk, if it doesn't change the per_dir_config then
             * we know that we don't have to redo all the access checks
             */
            if (   !(res = ap_file_walk(rnew))
                && !(res = ap_location_walk(rnew))
                && (rnew->per_dir_config == r->per_dir_config))
            {
                if (   (res = ap_run_type_checker(rnew)) 
                    || (res = ap_run_fixups(rnew))) {
                    rnew->status = res;
                }
                return rnew;
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, rnew,
                          "symlink doesn't point to a file or directory: %s",
                          r->filename);
            res = HTTP_FORBIDDEN;
        }
#endif
    }
    else {
	/* XXX: @@@: What should be done with the parsed_uri values? */
	ap_parse_uri(rnew, new_file);	/* fill in parsed_uri values */
        /*
         * XXX: this should be set properly like it is in the same-dir case
         * but it's actually sometimes to impossible to do it... because the
         * file may not have a uri associated with it -djg
         */
        rnew->uri = apr_pstrdup(rnew->pool, "");

#if 0 /* XXX When this is reenabled, the cache triggers need to be set to faux
       * dir_walk/file_walk values.
       */

        rnew->per_dir_config = r->server->lookup_defaults;
        res = ap_directory_walk(rnew);
        if (!res) {
            res = ap_file_walk(rnew);
        }
#endif
    }


    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }

    return rnew;
}

AP_DECLARE(int) ap_run_sub_req(request_rec *r)
{
    int retval;

    retval = ap_invoke_handler(r);
    ap_finalize_sub_req_protocol(r);
    return retval;
}

AP_DECLARE(void) ap_destroy_sub_req(request_rec *r)
{
    /* Reclaim the space */
    apr_pool_destroy(r->pool);
}

/*
 * Function to set the r->mtime field to the specified value if it's later
 * than what's already there.
 */
AP_DECLARE(void) ap_update_mtime(request_rec *r, apr_time_t dependency_mtime)
{
    if (r->mtime < dependency_mtime) {
	r->mtime = dependency_mtime;
    }
}

/*
 * Is it the initial main request, which we only get *once* per HTTP request?
 */
AP_DECLARE(int) ap_is_initial_req(request_rec *r)
{
    return
        (r->main == NULL)       /* otherwise, this is a sub-request */
        &&
        (r->prev == NULL);      /* otherwise, this is an internal redirect */
} 

