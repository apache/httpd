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
         * to handle whatever path string arrives at it's door - by platform
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

AP_DECLARE(int) directory_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t *per_dir_defaults = r->server->lookup_defaults;
    ap_conf_vector_t **sec = (ap_conf_vector_t **) sconf->sec->elts;
    int num_sec = sconf->sec->nelts;
    char *test_filename;
    char *test_dirname;
    int res;
    unsigned i, num_dirs;
    int j, test_filename_len;
#if defined(HAVE_UNC_PATHS) || defined(NETWARE)
    unsigned iStart = 1;
#endif
    ap_conf_vector_t *entry_config;
    ap_conf_vector_t *this_conf;
    core_dir_config *entry_core;

    /*
     * Are we dealing with a file? If not, we can (hopefuly) safely assume we
     * have a handler that doesn't require one, but for safety's sake, and so
     * we have something find_types() can get something out of, fake one. But
     * don't run through the directory entries.
     */

    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
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
        const char *entry_dir;

        for (j = 0; j < num_sec; ++j) {

            entry_config = sec[j];
            entry_core = ap_get_module_config(entry_config, &core_module);
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

    /* XXX This needs to be rolled into APR, the APR function will not
     * be allowed to fold the case of any non-existant segment of the path:
     */
    r->filename = ap_os_case_canonical_filename(r->pool, r->filename);

    /* TODO This is rather silly right here, we should simply be setting
     * filename and path_info at the end of our directory_walk
     */
    res = get_path_info(r);
    if (res != OK) {
        return res;
    }

    /* XXX This becomes moot, and will already happen above for elements
     * that actually exist:
     */
    r->filename = ap_os_canonical_filename(r->pool, r->filename);

    test_filename = apr_pstrdup(r->pool, r->filename);

    /* XXX This becomes mute, since the APR canonical parsing will handle
     * 2slash and dot directory issues:
     */
    ap_no2slash(test_filename);
    num_dirs = ap_count_dirs(test_filename);

    /* XXX This needs to be rolled into APR: */
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

    /* XXX These exception cases go away if apr_stat() returns the
     * APR_PATHINCOMPLETE status, so we skip hard filesystem testing
     * of the initial 'pseudo' elements:
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

#if defined(HAVE_DRIVE_LETTERS) || defined(NETWARE)
    /* Should match <Directory> sections starting from '/', not 'e:/' 
     * (for example).  WIN32/OS2/NETWARE do not have a single root directory,
     * they have one for each filesystem.  Traditionally, Apache has treated 
     * <Directory /> permissions as the base for the whole server, and this 
     * tradition should probably be preserved. 
     *
     * NOTE: MUST SYNC WITH ap_make_dirstr_prefix() CHANGE IN src/main/util.c
     */
    if (test_filename[0] == '/')
        i = 1;
    else
        i = 0;
#else
    /* Normal File Systems are rooted at / */
    i = 1;
#endif /* def HAVE_DRIVE_LETTERS || NETWARE */

    /* j keeps track of which section we're on, see core_reorder_directories */
    j = 0;
    for (; i <= num_dirs; ++i) {
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

#if defined(HAVE_UNC_PATHS) || defined(NETWARE)
        /* Test only legal names against the real filesystem */
        if (i >= iStart)
#endif
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
            char *entry_dir;

            entry_config = sec[j];
            entry_core = ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            if (entry_core->r
		|| !entry_core->d_is_absolute
#if defined(HAVE_DRIVE_LETTERS) || defined(NETWARE)
    /* To account for the top-level "/" directory when i == 0 
     * XXX: The net test may be wrong... may fail ap_os_is_path_absolute
     */
                || (entry_core->d_components > 1
                    && entry_core->d_components > i)
#else
                || entry_core->d_components > i
#endif /* def HAVE_DRIVE_LETTERS || NETWARE */
                )
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
                core_dir = ap_get_module_config(per_dir_defaults,
                                                &core_module);
            }
#if defined(HAVE_DRIVE_LETTERS) || defined(NETWARE)
            /* So that other top-level directory sections (e.g. "e:/") aren't
             * skipped when i == 0
             * XXX: I don't get you here, Tim... That's a level 1 section, but
             *      we are at level 0. Did you mean fast-forward to the next?
             */
            else if (!i)
                break;
#endif /* def HAVE_DRIVE_LETTERS || NETWARE */
        }
        overrides_here = core_dir->override;

        /* If .htaccess files are enabled, check for one. */

#if defined(HAVE_UNC_PATHS) || defined(NETWARE)
        /* Test only legal names against the real filesystem */
        if (i >= iStart)
#endif
        if (overrides_here) {
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
     * There's two types of IS_SPECIAL sections (see http_core.c), and we've
     * already handled the proxy:-style stuff.  Now we'll deal with the
     * regexes.
     */
    for (; j < num_sec; ++j) {

        entry_config = sec[j];
        entry_core = ap_get_module_config(entry_config, &core_module);

        if (entry_core->r) {
            if (!ap_regexec(entry_core->r, test_dirname, 0, NULL, REG_NOTEOL)) {
                per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                            per_dir_defaults,
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

AP_DECLARE(int) directory_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t *per_dir_defaults = r->server->lookup_defaults;
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **) sconf->sec->elts;
    int num_sec = sconf->sec->nelts;
    int sec;
    unsigned int seg;
    int res;
    ap_conf_vector_t *entry_config;
    ap_conf_vector_t *this_conf;
    core_dir_config *entry_core;
    apr_status_t rv;
    apr_size_t buflen;
    char *seg_name;
    char *delim;

    /*
     * Are we dealing with a file? If not, we simply assume we have a 
     * handler that doesn't require one, but for safety's sake, and so
     * we have something find_types() can get something out of, fake 
     * one. But don't run through the directory entries.
     */

    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
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
    }
    else {
        return HTTP_FORBIDDEN;
    }
    r->finfo.valid = APR_FINFO_TYPE;
    r->finfo.filetype = APR_DIR; /* It's the root, of course it's a dir */

    /* Fake filenames (i.e. proxy:) only match Directory sections.
     */
    if (rv == APR_EBADPATH)
    {
        const char *entry_dir;

        for (sec = 0; sec < num_sec; ++sec) {

            entry_config = sec_ent[sec];
            entry_core = ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            this_conf = NULL;
            if (entry_core->r) {
                if (!ap_regexec(entry_core->r, r->filename, 0, NULL, 0))
                    this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
                /* XXX: Gut instinct tells me this could be very, very nasty,
                 * have we thought through what 'faux' resource might be
                 * case senstitive or not?
                 */
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

    /*
     * seg keeps track of which segment we've copied.
     * sec keeps track of which section we're on, since sections are
     *     ordered by number of segments. See core_reorder_directories 
     */
    seg = 1; 
    sec = 0;
    do {
        int overrides_here;
        core_dir_config *core_dir = ap_get_module_config(per_dir_defaults,
                                                         &core_module);
        
        /* We have no trailing slash, but we sure would appreciate one...
         */
        if (seg > 1)
            strcat(r->filename, "/");

        /* Begin *this* level by looking for matching <Directory> sections
         * from the server config.
         */
        for (; sec < num_sec; ++sec) {
            char *entry_dir;

            entry_config = sec_ent[sec];
            entry_core = ap_get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            /* No more possible matches? */
            if (entry_core->r || !entry_core->d_is_absolute
                              || entry_core->d_components > seg)
                break;

            this_conf = NULL;
            if (entry_core->d_is_fnmatch) {
                if (!apr_fnmatch(entry_dir, r->filename, FNM_PATHNAME)) {
                    this_conf = entry_config;
                }
            }
            else if (!strcmp(r->filename, entry_dir))
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
        if (seg > 1)
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
         * capture this path object rather than it's target.  We will
         * replace the info with our target's info below.  We especially
         * want the name of this 'link' object, not the name of it's
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
     * There's two types of IS_SPECIAL sections (see http_core.c), and we've
     * already handled the proxy:-style stuff.  Now we'll deal with the
     * regexes.
     */
    for (; sec < num_sec; ++sec) {

        entry_config = sec_ent[sec];
        entry_core = ap_get_module_config(entry_config, &core_module);

        if (entry_core->r) {
            if (!ap_regexec(entry_core->r, r->filename, 0, NULL, REG_NOTEOL)) {
                per_dir_defaults = ap_merge_per_dir_configs(r->pool,
                                                            per_dir_defaults,
                                                            entry_config);
            }
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
 x    * S_ISDIR test.  But if you accessed /symlink/index.html, for example,
 x    * you would *not* get the 403.
 x
 x   if (r->finfo.filetype != APR_DIR
 x       && (res = resolve_symlink(r->filename, r->info, ap_allow_options(r), r->pool))) {
 x       ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
 x                   "Symbolic link not allowed: %s", r->filename);
 x       return res;
 x   }
 */

    return OK;  /* 'no excuses' */
}

#endif /* defined REPLACE_PATH_INFO_METHOD */

AP_DECLARE(int) location_walk(request_rec *r)
{
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t *per_dir_defaults = r->per_dir_config;
    ap_conf_vector_t **url = (ap_conf_vector_t **) sconf->sec_url->elts;
    int len, num_url = sconf->sec_url->nelts;
    char *test_location;
    ap_conf_vector_t *this_conf;
    ap_conf_vector_t *entry_config;
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

	entry_core = ap_get_module_config(entry_config, &core_module);
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
                                                        per_dir_defaults,
                                                        this_conf);
    }
    r->per_dir_config = per_dir_defaults;

    return OK;
}

AP_DECLARE(int) file_walk(request_rec *r)
{
    core_dir_config *conf = ap_get_module_config(r->per_dir_config,
                                                 &core_module);
    ap_conf_vector_t *per_dir_defaults = r->per_dir_config;
    ap_conf_vector_t **file = (ap_conf_vector_t **) conf->sec->elts;
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

static int sub_req_common_validation(request_rec *rnew)
{
    int res;
    if (((   ap_satisfies(rnew) == SATISFY_ALL
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
        || (res = ap_run_fixups(rnew)))
        return res;
    else
        return 0;
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
        if (reqs[i].method_mask & (1 << r->method_number))
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

    /* We have to run this after ap_set_sub_req_protocol, or the r->main
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
        || (res = sub_req_common_validation(rnew))) {
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
    apr_status_t rv;
    request_rec *rnew;
    int res;
    char *fdir;
    char *udir;

    rnew = make_sub_request(r);
    fill_in_sub_req_vars(rnew, r, next_filter);

    rnew->chunked        = r->chunked;

    /* We have to run this after ap_set_sub_req_protocol, or the r->main
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

    rnew->uri = ap_make_full_path(rnew->pool, udir, dirent->name);
    rnew->filename = ap_make_full_path(rnew->pool, fdir, dirent->name);
    ap_parse_uri(rnew, rnew->uri);    /* fill in parsed_uri values */

    rnew->per_dir_config = r->per_dir_config;

    if ((dirent->valid & APR_FINFO_MIN) != APR_FINFO_MIN) {
        /*
         * apr_dir_read isn't very complete on this platform, so
         * we need another apr_lstat (or simply apr_stat if we allow
         * all symlinks here.)  If this is an APR_LNK that resolves 
         * to an APR_DIR, then we will rerun everything anyways... 
         * this should be safe.
         */
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
        res = directory_walk(rnew);
        if (!res) {
            res = file_walk(rnew);
        }
    }
    else if (rnew->finfo.filetype == APR_REG || !rnew->finfo.filetype) {
        /*
         * do a file_walk, if it doesn't change the per_dir_config then
         * we know that we don't have to redo all the access checks
         */
        if ((res = file_walk(rnew))) {
            rnew->status = res;
            return rnew;
        }
        if (rnew->per_dir_config == r->per_dir_config) {
            if ((res = ap_run_type_checker(rnew)) 
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

    if (res || (res = sub_req_common_validation(rnew))) {
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

    rnew = make_sub_request(r);
    fill_in_sub_req_vars(rnew, r, next_filter);

    rnew->chunked        = r->chunked;

    /* We have to run this after ap_set_sub_req_protocol, or the r->main
     * pointer won't be setup
     */
    ap_run_create_request(rnew);

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);

    /*
     * Check for a special case... if there are no '/' characters in new_file
     * at all, then we are looking at a relative lookup in the same
     * directory. That means we won't have to redo directory_walk, and we may
     * not even have to redo access checks.
     */

    if (ap_strchr_c(new_file, '/') == NULL) {
        char *udir = ap_make_dirstr_parent(rnew->pool, r->uri);
        apr_status_t rv;

        rnew->uri = ap_make_full_path(rnew->pool, udir, new_file);
        rnew->filename = ap_make_full_path(rnew->pool, fdir, new_file);
        ap_parse_uri(rnew, rnew->uri);    /* fill in parsed_uri values */

        /*
         * If this is an APR_LNK that resolves to an APR_DIR, then 
         * we will rerun everything anyways... this should be safe.
         */
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

        if ((res = check_safe_file(rnew))) {
            rnew->status = res;
            return rnew;
        }

        rnew->per_dir_config = r->per_dir_config;

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
            res = directory_walk(rnew);
            if (!res) {
                res = file_walk(rnew);
            }
        }
        else if (rnew->finfo.filetype == APR_REG || !rnew->finfo.filetype) {
            /*
             * do a file_walk, if it doesn't change the per_dir_config then
             * we know that we don't have to redo all the access checks
             */
        if ((res = file_walk(rnew))) {
            rnew->status = res;
            return rnew;
        }
        if (rnew->per_dir_config == r->per_dir_config) {
            if ((res = ap_run_type_checker(rnew)) 
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

    if (res || (res = sub_req_common_validation(rnew))) {
        rnew->status = res;
    }
    return rnew;
}

AP_DECLARE(int) ap_run_sub_req(request_rec *r)
{
    int retval;

    /* see comments in process_request_internal() */
    ap_run_insert_filter(r);
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

