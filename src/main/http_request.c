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
 * http_request.c: functions to get and process requests
 *
 * Rob McCool 3/21/93
 *
 * Thoroughly revamped by rst for Apache.  NB this file reads
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
#include "fnmatch.h"

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
    if (r->finfo.st_mode == 0         /* doesn't exist */
        || S_ISDIR(r->finfo.st_mode)
        || S_ISREG(r->finfo.st_mode)
        || S_ISLNK(r->finfo.st_mode)) {
        return OK;
    }
    aplog_error(APLOG_MARK, APLOG_ERR, r->server,
                "object is not a file, directory or symlink: %s",
                r->filename);
    return HTTP_FORBIDDEN;
}


int check_symlinks(char *d, int opts)
{
#if defined(__EMX__) || defined(WIN32)
    /* OS/2 doesn't have symlinks */
    return OK;
#else
    struct stat lfi, fi;
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

    res = lstat(d, &lfi);

    if (lastp)
        *lastp = '/';

    /*
     * Note that we don't reject accesses to nonexistent files (multiviews or
     * the like may cons up a way to run the transaction anyway)...
     */

    if (!(res >= 0) || !S_ISLNK(lfi.st_mode))
        return OK;

    /* OK, it's a symlink.  May still be OK with OPT_SYM_OWNER */

    if (!(opts & OPT_SYM_OWNER))
        return HTTP_FORBIDDEN;

    if (stat(d, &fi) < 0)
        return HTTP_FORBIDDEN;

    return (fi.st_uid == lfi.st_uid) ? OK : HTTP_FORBIDDEN;

#endif
}

/* Dealing with the file system to get PATH_INFO
 */
int get_path_info(request_rec *r)
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

        errno = 0;
        rv = stat(path, &r->finfo);

        if (cp != end)
            *cp = '/';

        if (!rv) {

            /*
             * Aha!  Found something.  If it was a directory, we will search
             * contents of that directory for a multi_match, so the PATH_INFO
             * argument starts with the component after that.
             */

            if (S_ISDIR(r->finfo.st_mode) && last_cp) {
                r->finfo.st_mode = 0;   /* No such file... */
                cp = last_cp;
            }

            r->path_info = pstrdup(r->pool, cp);
            *cp = '\0';
            return OK;
        }
#if defined(ENOENT) && defined(ENOTDIR)
        else if (errno == ENOENT || errno == ENOTDIR) {
            last_cp = cp;

            while (--cp > path && *cp != '/')
                continue;

            while (cp > path && cp[-1] == '/')
                --cp;
        }
        else {
#if defined(EACCES)
            if (errno != EACCES)
#endif
                aplog_error(APLOG_MARK, APLOG_ERR, r->server,
                            "access to %s failed for %s", r->uri,
                            get_remote_host(r->connection, r->per_dir_config,
                                            REMOTE_NAME));
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
        else {
            last_cp = cp;

            while (--cp > path && *cp != '/')
                continue;

            while (cp > path && cp[-1] == '/')
                --cp;
        }
#endif  /* ENOENT && ENOTDIR */
    }
    return OK;
}

int directory_walk(request_rec *r)
{
    core_server_config *sconf = get_module_config(r->server->module_config,
                                                  &core_module);
    void *per_dir_defaults = r->server->lookup_defaults;
    void **sec = (void **) sconf->sec->elts;
    int num_sec = sconf->sec->nelts;
    char *test_filename;
    char *test_dirname;
    int res;
    unsigned i, num_dirs;
    int j, test_filename_len;

    /*
     * Are we dealing with a file? If not, we can (hopefuly) safely assume we
     * have a handler that doesn't require one, but for safety's sake, and so
     * we have something find_types() can get something out of, fake one. But
     * don't run through the directory entries.
     */

    if (r->filename == NULL) {
        r->filename = pstrdup(r->pool, r->uri);
        r->finfo.st_mode = 0;   /* Not really a file... */
        r->per_dir_config = per_dir_defaults;

        return OK;
    }

    r->filename   = os_canonical_filename(r->pool, r->filename);
    test_filename = pstrdup(r->pool, r->filename);

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

#if defined(__EMX__) || defined(WIN32)
    /* Add OS/2 drive name support */
    if ((test_filename[0] != '/') && (test_filename[1] != ':'))
#else
    if (test_filename[0] != '/')
#endif
    {
        void *this_conf, *entry_config;
        core_dir_config *entry_core;
        char *entry_dir;

        for (j = 0; j < num_sec; ++j) {

            entry_config = sec[j];

            entry_core = (core_dir_config *)
                get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            this_conf = NULL;
            if (entry_core->r) {
                if (!regexec(entry_core->r, test_filename, 0, NULL, 0))
                    this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
                if (!fnmatch(entry_dir, test_filename, FNM_PATHNAME))
                    this_conf = entry_config;
            }
            else if (!strncmp(test_filename, entry_dir, strlen(entry_dir)))
                this_conf = entry_config;

            if (this_conf)
                per_dir_defaults = merge_per_dir_configs(r->pool,
                                                         per_dir_defaults,
                                                         this_conf);
        }

        r->per_dir_config = per_dir_defaults;

        return OK;
    }

    no2slash(test_filename);
    num_dirs = count_dirs(test_filename);

    res = get_path_info(r);
    if (res != OK) {
        return res;
    }

    if ((res = check_safe_file(r))) {
        return res;
    }

    test_filename_len = strlen(test_filename);
    if (test_filename[test_filename_len - 1] == '/')
        --num_dirs;

    if (S_ISDIR(r->finfo.st_mode))
        ++num_dirs;

    /*
     * We will use test_dirname as scratch space while we build directory
     * names during the walk.  Profiling shows directory_walk to be a busy
     * function so we try to avoid allocating lots of extra memory here.
     */
    test_dirname = palloc(r->pool, test_filename_len + 1);

    /* j keeps track of which section we're on, see core_reorder_directories */
    j = 0;
    for (i = 1; i <= num_dirs; ++i) {
        int overrides_here;
        core_dir_config *core_dir = (core_dir_config *)
            get_module_config(per_dir_defaults, &core_module);

        /*
         * XXX: this could be made faster by only copying the next component
         * rather than copying the entire thing all over.
         */
        make_dirstr_prefix(test_dirname, test_filename, i);

        /*
         * Do symlink checks first, because they are done with the
         * permissions appropriate to the *parent* directory...
         */

        if ((res = check_symlinks(test_dirname, core_dir->opts))) {
            aplog_error(APLOG_MARK, APLOG_ERR, r->server,
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
                         get_module_config(entry_config, &core_module);
            entry_dir = entry_core->d;

            if (entry_core->r
#if defined(__EMX__) || defined(WIN32)
                || (entry_dir[0] != '/' && entry_dir[1] != ':')
#else
                || entry_dir[0] != '/'
#endif
                || entry_core->d_components > i)
                break;

            this_conf = NULL;
            if (entry_core->d_is_fnmatch) {
                if (!fnmatch(entry_dir, test_dirname, FNM_PATHNAME)) {
                    this_conf = entry_config;
                }
            }
            else if (!strcmp(test_dirname, entry_dir))
                this_conf = entry_config;

            if (this_conf) {
                per_dir_defaults = merge_per_dir_configs(r->pool,
                                                         per_dir_defaults,
                                                         this_conf);
                core_dir = (core_dir_config *)
                           get_module_config(per_dir_defaults, &core_module);
            }
        }
        overrides_here = core_dir->override;

        /* If .htaccess files are enabled, check for one. */

        if (overrides_here) {
            void *htaccess_conf = NULL;

            res = parse_htaccess(&htaccess_conf, r, overrides_here,
                                 pstrdup(r->pool, test_dirname),
                                 sconf->access_name);
            if (res)
                return res;

            if (htaccess_conf)
                per_dir_defaults =
                    merge_per_dir_configs(r->pool, per_dir_defaults,
                                          htaccess_conf);
        }
    }

    /*
     * now match the "special" sections (regex, and "proxy:" stuff).  But
     * note that proxy: stuff doesn't get down this far, it's been handled
     * earlier, so we'll just skip it.
     */
    for (; j < num_sec; ++j) {
        void *entry_config = sec[j];
        core_dir_config *entry_core;

        entry_core = (core_dir_config *)
                     get_module_config(entry_config, &core_module);

        if (entry_core->r) {
            if (!regexec(entry_core->r, test_dirname, 0, NULL, REG_NOTEOL)) {
                per_dir_defaults =
                    merge_per_dir_configs(r->pool, per_dir_defaults,
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
    if (!S_ISDIR(r->finfo.st_mode)
        && (res = check_symlinks(r->filename, allow_options(r)))) {
        aplog_error(APLOG_MARK, APLOG_ERR, r->server,
                    "Symbolic link not allowed: %s", r->filename);
        return res;
    }
    return OK;                  /* Can only "fail" if access denied by the
                                 * symlink goop. */
}

int location_walk(request_rec *r)
{
    core_server_config *sconf = get_module_config(r->server->module_config,
                                                  &core_module);
    void *per_dir_defaults = r->per_dir_config;
    void **url = (void **) sconf->sec_url->elts;
    int len, num_url = sconf->sec_url->nelts;
    char *test_location = pstrdup(r->pool, r->uri);

    /*
     * Collapse multiple slashes, if it's a path URL (we don't want to do
     * anything to <Location http://...> or such).
     */
    if (test_location[0] == '/')
        no2slash(test_location);

    /* Go through the location entries, and check for matches. */

    if (num_url) {
        void *this_conf, *entry_config;
        core_dir_config *entry_core;
        char *entry_url;
        int j;

        /* we apply the directive sections in some order;
         * should really try them with the most general first.
         */
        for (j = 0; j < num_url; ++j) {

            entry_config = url[j];

            entry_core = (core_dir_config *)
                get_module_config(entry_config, &core_module);
            entry_url = entry_core->d;

            len = strlen(entry_url);

            this_conf = NULL;

            if (entry_core->r) {
                if (!regexec(entry_core->r, test_location, 0, NULL, 0))
                    this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
                if (!fnmatch(entry_url, test_location, FNM_PATHNAME)) {
                    this_conf = entry_config;
                }
            }
            else if (!strncmp(test_location, entry_url, len) &&
                     (entry_url[len - 1] == '/' ||
                   test_location[len] == '/' || test_location[len] == '\0'))
                this_conf = entry_config;

            if (this_conf)
                per_dir_defaults = merge_per_dir_configs(r->pool,
                                               per_dir_defaults, this_conf);
        }
        r->per_dir_config = per_dir_defaults;
    }

    return OK;
}

int file_walk(request_rec *r)
{
    core_dir_config *conf = get_module_config(r->per_dir_config, &core_module);
    void *per_dir_defaults = r->per_dir_config;
    void **file = (void **) conf->sec->elts;
    int len, num_files = conf->sec->nelts;
    char *test_file = pstrdup(r->pool, r->filename);

    /* Collapse multiple slashes */
    no2slash(test_file);

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
                         get_module_config(entry_config, &core_module);
            entry_file = entry_core->d;

            len = strlen(entry_file);

            this_conf = NULL;

            if (entry_core->r) {
                if (!regexec(entry_core->r, test_file, 0, NULL, 0))
                    this_conf = entry_config;
            }
            else if (entry_core->d_is_fnmatch) {
                if (!fnmatch(entry_file, test_file, FNM_PATHNAME)) {
                    this_conf = entry_config;
                }
            }
            else if (!strncmp(test_file, entry_file, len) &&
                     (entry_file[len - 1] == '/' ||
                      test_file[len] == '/' || test_file[len] == '\0'))
                this_conf = entry_config;

            if (this_conf)
                per_dir_defaults = merge_per_dir_configs(r->pool,
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

request_rec *make_sub_request(const request_rec *r)
{
    pool *rrp = make_sub_pool(r->pool);
    request_rec *rr = pcalloc(rrp, sizeof(request_rec));

    rr->pool = rrp;
    return rr;
}

API_EXPORT(request_rec *) sub_req_lookup_uri(const char *new_file,
                                             const request_rec *r)
{
    request_rec *rnew;
    int res;
    char *udir;

    rnew = make_sub_request(r);
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;
    rnew->request_config = create_request_config(rnew->pool);
    rnew->htaccess       = r->htaccess;
    rnew->per_dir_config = r->server->lookup_defaults;

    set_sub_req_protocol(rnew, r);

    if (new_file[0] == '/')
        parse_uri(rnew, new_file);
    else {
        udir = make_dirstr_parent(rnew->pool, r->uri);
        udir = escape_uri(rnew->pool, udir);    /* re-escape it */
        parse_uri(rnew, make_full_path(rnew->pool, udir, new_file));
    }

    res = unescape_url(rnew->uri);
    if (res) {
        rnew->status = res;
        return rnew;
    }

    getparents(rnew->uri);

    if ((res = location_walk(rnew))) {
        rnew->status = res;
        return rnew;
    }

    res = translate_name(rnew);
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
        || ((satisfies(rnew) == SATISFY_ALL
             || satisfies(rnew) == SATISFY_NOSPEC)
            ? ((res = check_access(rnew))
               || (some_auth_required(rnew)
                   && ((res = check_user_id(rnew))
                       || (res = check_auth(rnew)))))
            : ((res = check_access(rnew))
               && (!some_auth_required(rnew)
                   || ((res = check_user_id(rnew))
                       || (res = check_auth(rnew)))))
           )
        || (res = find_types(rnew))
        || (res = run_fixups(rnew))
       ) {
        rnew->status = res;
    }
    return rnew;
}

API_EXPORT(request_rec *) sub_req_lookup_file(const char *new_file,
                                              const request_rec *r)
{
    request_rec *rnew;
    int res;
    char *fdir;

    rnew = make_sub_request(r);
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;
    rnew->request_config = create_request_config(rnew->pool);
    rnew->htaccess       = r->htaccess;

    set_sub_req_protocol(rnew, r);
    fdir = make_dirstr_parent(rnew->pool, r->filename);

    /*
     * Check for a special case... if there are no '/' characters in new_file
     * at all, then we are looking at a relative lookup in the same
     * directory. That means we won't have to redo directory_walk, and we may
     * not even have to redo access checks.
     */

    if (strchr(new_file, '/') == NULL) {
        char *udir = make_dirstr_parent(rnew->pool, r->uri);

        rnew->uri = make_full_path(rnew->pool, udir, new_file);
        rnew->filename = make_full_path(rnew->pool, fdir, new_file);
        if (stat(rnew->filename, &rnew->finfo) < 0) {
            rnew->finfo.st_mode = 0;
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
        if (S_ISDIR(rnew->finfo.st_mode)) {
            res = directory_walk(rnew);
            if (!res) {
                res = file_walk(rnew);
            }
        }
        else {
            if ((res = check_symlinks(rnew->filename, allow_options(rnew)))) {
                aplog_error(APLOG_MARK, APLOG_ERR, rnew->server,
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
                if ((res = find_types(rnew)) || (res = run_fixups(rnew))) {
                    rnew->status = res;
                }
                return rnew;
            }
        }
    }
    else {
        /*
         * XXX: this should be set properly like it is in the same-dir case
         * but it's actually sometimes to impossible to do it... because the
         * file may not have a uri associated with it -djg
         */
        rnew->uri = "INTERNALLY GENERATED file-relative req";
        rnew->filename = ((new_file[0] == '/') ?
                          pstrdup(rnew->pool, new_file) :
                          make_full_path(rnew->pool, fdir, new_file));
        rnew->per_dir_config = r->server->lookup_defaults;
        res = directory_walk(rnew);
        if (!res) {
            res = file_walk(rnew);
        }
    }

    if (res
        || ((satisfies(rnew) == SATISFY_ALL
             || satisfies(rnew) == SATISFY_NOSPEC)
            ? ((res = check_access(rnew))
               || (some_auth_required(rnew)
                   && ((res = check_user_id(rnew))
                       || (res = check_auth(rnew)))))
            : ((res = check_access(rnew))
               && (!some_auth_required(rnew)
                   || ((res = check_user_id(rnew))
                       || (res = check_auth(rnew)))))
           )
        || (res = find_types(rnew))
        || (res = run_fixups(rnew))
       ) {
        rnew->status = res;
    }
    return rnew;
}

API_EXPORT(int) run_sub_req(request_rec *r)
{
    int retval = invoke_handler(r);
    finalize_sub_req_protocol(r);
    return retval;
}

API_EXPORT(void) destroy_sub_req(request_rec *r)
{
    /* Reclaim the space */
    destroy_pool(r->pool);
}

/*****************************************************************
 *
 * Mainline request processing...
 */

void die(int type, request_rec *r)
{
    int error_index = index_of_response(type);
    char *custom_response = response_code_string(r, error_index);
    int recursive_error = 0;

    /*
     * This test is done here so that none of the auth modules needs to know
     * about proxy authentication.  They treat it like normal auth, and then
     * we tweak the status.
     */
    if (r->status == AUTH_REQUIRED && r->proxyreq) {
        r->status = HTTP_PROXY_AUTHENTICATION_REQUIRED;
    }

    if (type == DONE) {
        finalize_request_protocol(r);
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
     * Two types of custom redirects --- plain text, and URLs. Plain text has
     * a leading '"', so the URL code, here, is triggered on its absence
     */

    if (custom_response && custom_response[0] != '"') {

        if (is_url(custom_response)) {
            /*
             * The URL isn't local, so lets drop through the rest of this
             * apache code, and continue with the usual REDIRECT handler.
             * But note that the client will ultimately see the wrong
             * status...
             */
            r->status = REDIRECT;
            table_set(r->headers_out, "Location", custom_response);
        }
        else if (custom_response[0] == '/') {
            r->no_local_copy = 1;       /* Do NOT send USE_LOCAL_COPY for
                                         * error documents! */
            /*
             * This redirect needs to be a GET no matter what the original
             * method was.
             */
            table_set(r->subprocess_env, "REQUEST_METHOD", r->method);
            r->method = pstrdup(r->pool, "GET");
            r->method_number = M_GET;
            internal_redirect(custom_response, r);
            return;
        }
        else {
            /*
             * Dumb user has given us a bad url to redirect to --- fake up
             * dying with a recursive server error...
             */
            recursive_error = SERVER_ERROR;
            aplog_error(APLOG_MARK, APLOG_ERR, r->server,
                        "Invalid error redirection directive: %s",
                        custom_response);
        }
    }
    send_error_response(r, recursive_error);
}

static void decl_die(int status, char *phase, request_rec *r)
{
    if (status == DECLINED) {
        aplog_error(APLOG_MARK, APLOG_CRIT, r->server,
                    "configuration error:  couldn't %s: %s", phase, r->uri);
        die(SERVER_ERROR, r);
    }
    else
        die(status, r);
}

API_EXPORT(int) some_auth_required(request_rec *r)
{
    /* Is there a require line configured for the type of *this* req? */

    array_header *reqs_arr = requires(r);
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

void process_request_internal(request_rec *r)
{
    int access_status;

    /*
     * Kluge to be reading the assbackwards field outside of protocol.c, but
     * we've got to check for this sort of nonsense somewhere...
     */

    if (r->assbackwards && r->header_only) {
        /*
         * Client asked for headers only with HTTP/0.9, which doesn't send
         * headers!  Have to dink things even to make sure the error message
         * comes through...
         */
        aplog_error(APLOG_MARK, APLOG_ERR, r->server,
                    "client sent illegal HTTP/0.9 request: %s", r->uri);
        r->header_only = 0;
        die(BAD_REQUEST, r);
        return;
    }

    if ((!r->hostname && (r->proto_num >= 1001)) ||
        ((r->proto_num == 1001) && !table_get(r->headers_in, "Host"))) {
        /*
         * Client sent us a HTTP/1.1 or later request without telling us the
         * hostname, either with a full URL or a Host: header. We therefore
         * need to (as per the 1.1 spec) send an error
         */
        aplog_error(APLOG_MARK, APLOG_ERR, r->server,
               "client sent HTTP/1.1 request without hostname: %s", r->uri);
        die(BAD_REQUEST, r);
        return;
    }

    if (!r->proxyreq) {
        /*
         * We don't want TRACE to run through the normal handler set, we
         * handle it specially.
         */
        if (r->method_number == M_TRACE) {
            if ((access_status = send_http_trace(r)))
                die(access_status, r);
            else
                finalize_request_protocol(r);
            return;
        }

        access_status = unescape_url(r->uri);
        if (access_status) {
            die(access_status, r);
            return;
        }

        getparents(r->uri);     /* OK --- shrinking transformations... */
    }

    if ((access_status = location_walk(r))) {
        die(access_status, r);
        return;
    }

    if ((access_status = translate_name(r))) {
        decl_die(access_status, "translate", r);
        return;
    }

    if (r->proto_num > 1000 && table_get(r->subprocess_env, "downgrade-1.0")) {
        r->proto_num = 1000;
    }

    /*
     * NB: directory_walk() clears the per_dir_config, so we don't inherit
     * from location_walk() above
     */

    if ((access_status = directory_walk(r))) {
        die(access_status, r);
        return;
    }

    if ((access_status = file_walk(r))) {
        die(access_status, r);
        return;
    }

    if ((access_status = location_walk(r))) {
        die(access_status, r);
        return;
    }

    if ((access_status = header_parse(r))) {
        die(access_status, r);
        return;
    }

    switch (satisfies(r)) {
    case SATISFY_ALL:
    case SATISFY_NOSPEC:
        if ((access_status = check_access(r)) != 0) {
            decl_die(access_status, "check access", r);
            return;
        }
        if (some_auth_required(r)) {
            if ((access_status = check_user_id(r)) != 0) {
                decl_die(access_status, "check user.  No user file?", r);
                return;
            }
            if ((access_status = check_auth(r)) != 0) {
                decl_die(access_status, "check access.  No groups file?", r);
                return;
            }
        }
        break;
    case SATISFY_ANY:
        if ((access_status = check_access(r)) != 0) {
            if (!some_auth_required(r)) {
                decl_die(access_status, "check access", r);
                return;
            }
            if ((access_status = check_user_id(r)) != 0) {
                decl_die(access_status, "check user.  No user file?", r);
                return;
            }
            if ((access_status = check_auth(r)) != 0) {
                decl_die(access_status, "check access.  No groups file?", r);
                return;
            }
        }
        break;
    }

    if ((access_status = find_types(r)) != 0) {
        decl_die(access_status, "find types", r);
        return;
    }

    if ((access_status = run_fixups(r)) != 0) {
        die(access_status, r);
        return;
    }

    if ((access_status = invoke_handler(r)) != 0) {
        die(access_status, r);
        return;
    }

    /* Take care of little things that need to happen when we're done */
    finalize_request_protocol(r);
}

void process_request(request_rec *r)
{
#ifdef STATUS
    int old_stat;

    time_process_request(r->connection->child_num, START_PREQUEST);
#endif

    process_request_internal(r);

#ifdef STATUS
    old_stat = update_child_status(r->connection->child_num,
                                   SERVER_BUSY_LOG, r);
#endif

    /*
     * We want to flush the last packet if this isn't a pipelining connection
     * *before* we start into logging.  Suppose that the logging causes a DNS
     * lookup to occur, which may have a high latency.  If we hold off on
     * this packet, then it'll appear like the link is stalled when really
     * it's the application that's stalled.
     */
    bhalfduplex(r->connection->client);
    log_transaction(r);

#ifdef STATUS
    (void) update_child_status(r->connection->child_num, old_stat, r);
    time_process_request(r->connection->child_num, STOP_PREQUEST);
#endif
}

table *rename_original_env(pool *p, table *t)
{
    array_header *env_arr = table_elts(t);
    table_entry *elts = (table_entry *) env_arr->elts;
    table *new = make_table(p, env_arr->nelts);
    int i;

    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;
        table_set(new, pstrcat(p, "REDIRECT_", elts[i].key, NULL),
                  elts[i].val);
    }

    return new;
}

request_rec *internal_internal_redirect(const char *new_uri, request_rec *r)
{
    int access_status;
    request_rec *new = (request_rec *) pcalloc(r->pool, sizeof(request_rec));
    char t[256];                /* Long enough... */

    new->connection = r->connection;
    new->server     = r->server;
    new->pool       = r->pool;

    /*
     * A whole lot of this really ought to be shared with protocol.c...
     * another missing cleanup.  It's particularly inappropriate to be
     * setting header_only, etc., here.
     */

    parse_uri(new, new_uri);
    new->request_config = create_request_config(r->pool);
    new->per_dir_config = r->server->lookup_defaults;

    new->prev = r;
    r->next   = new;

    /* Inherit the rest of the protocol info... */

    new->the_request = r->the_request;

    new->method          = r->method;
    new->method_number   = r->method_number;
    new->allowed         = r->allowed;

    new->status          = r->status;
    new->assbackwards    = r->assbackwards;
    new->header_only     = r->header_only;
    new->protocol        = r->protocol;
    new->proto_num       = r->proto_num;
    new->hostname        = r->hostname;
    new->hostlen         = r->hostlen;
    new->request_time    = r->request_time;
    new->main            = r->main;

    new->headers_in      = r->headers_in;
    new->headers_out     = make_table(r->pool, 5);
    new->err_headers_out = r->err_headers_out;
    new->subprocess_env  = rename_original_env(r->pool, r->subprocess_env);
    new->notes           = make_table(r->pool, 5);

    new->htaccess        = r->htaccess;
    new->no_cache        = r->no_cache;
    new->no_local_copy   = r->no_local_copy;
    new->read_length     = r->read_length;     /* We can only read it once */

    ap_snprintf(t, sizeof(t), "%d", r->status);
    table_set(new->subprocess_env, "REDIRECT_STATUS", pstrdup(r->pool, t));

    /*
     * XXX: hmm.  This is because mod_setenvif and mod_unique_id really need
     * to do their thing on internal redirects as well.  Perhaps this is a
     * misnamed function.
     */
    if ((access_status = run_post_read_request(new))) {
        die(access_status, new);
        return NULL;
    }

    return new;
}

API_EXPORT(void) internal_redirect(const char *new_uri, request_rec *r)
{
    request_rec *new = internal_internal_redirect(new_uri, r);
    process_request_internal(new);
}

/* This function is designed for things like actions or CGI scripts, when
 * using AddHandler, and you want to preserve the content type across
 * an internal redirect.
 */
API_EXPORT(void) internal_redirect_handler(const char *new_uri, request_rec *r)
{
    request_rec *new = internal_internal_redirect(new_uri, r);
    if (r->handler)
        new->content_type = r->content_type;
    process_request_internal(new);
}

/*
 * Is it the initial main request, which we only get *once* per HTTP request?
 */
API_EXPORT(int) is_initial_req(request_rec *r)
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
API_EXPORT(time_t) update_mtime(request_rec *r, time_t dependency_mtime)
{
    if (r->mtime < dependency_mtime) {
        r->mtime = dependency_mtime;
    }
    return r->mtime;
}
