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
#include "util_script.h"

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
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,map_to_storage,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,check_user_id,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,fixups,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,type_checker,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,access_checker,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,auth_checker,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_VOID(insert_filter, (request_rec *r), (r))
AP_IMPLEMENT_HOOK_RUN_ALL(int, create_request,
                          (request_rec *r), (r), OK, DECLINED)


static int decl_die(int status, char *phase, request_rec *r)
{
    if (status == DECLINED) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "configuration error:  couldn't %s: %s", phase, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        return status;
    }
}

/* This is the master logic for processing requests.  Do NOT duplicate
 * this logic elsewhere, or the security model will be broken by future
 * API changes.  Each phase must be individually optimized to pick up
 * redundant/duplicate calls by subrequests, and redirects.
 */
AP_DECLARE(int) ap_process_request_internal(request_rec *r)
{
    int file_req = (r->main && r->filename);
    int access_status;

    /* Ignore embedded %2F's in path for proxy requests */
    if (!r->proxyreq && r->parsed_uri.path) {
        core_dir_config *d;
        d = ap_get_module_config(r->per_dir_config, &core_module);
        if (d->allow_encoded_slashes) {
            access_status = ap_unescape_url_keep2f(r->parsed_uri.path);
        }
        else {
            access_status = ap_unescape_url(r->parsed_uri.path);
        }
        if (access_status) {
            if (access_status == HTTP_NOT_FOUND) {
                if (! d->allow_encoded_slashes) {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                                  "found %%2f (encoded '/') in URI "
                                  "(decoded='%s'), returning 404",
                                  r->parsed_uri.path);
                }
            }
            return access_status;
        }
    }

    ap_getparents(r->uri);     /* OK --- shrinking transformations... */

    /* All file subrequests are a huge pain... they cannot bubble through the
     * next several steps.  Only file subrequests are allowed an empty uri,
     * otherwise let translate_name kill the request.
     */
    if (!file_req) {
        if ((access_status = ap_location_walk(r))) {
            return access_status;
        }

        if ((access_status = ap_run_translate_name(r))) {
            return decl_die(access_status, "translate", r);
        }
    }

    /* Reset to the server default config prior to running map_to_storage
     */
    r->per_dir_config = r->server->lookup_defaults;

    if ((access_status = ap_run_map_to_storage(r))) {
        /* This request wasn't in storage (e.g. TRACE) */
        return access_status;
    }

    /* Excluding file-specific requests with no 'true' URI...
     */
    if (!file_req) {
        /* Rerun the location walk, which overrides any map_to_storage config.
         */
        if ((access_status = ap_location_walk(r))) {
            return access_status;
        }
    }

    /* Only on the main request! */
    if (r->main == NULL) {
        if ((access_status = ap_run_header_parser(r))) {
            return access_status;
        }
    }

    /* Skip authn/authz if the parent or prior request passed the authn/authz,
     * and that configuration didn't change (this requires optimized _walk()
     * functions in map_to_storage that use the same merge results given
     * identical input.)  If the config changes, we must re-auth.
     */
    if (r->main && (r->main->per_dir_config == r->per_dir_config)) {
        r->user = r->main->user;
        r->ap_auth_type = r->main->ap_auth_type;
    }
    else if (r->prev && (r->prev->per_dir_config == r->per_dir_config)) {
        r->user = r->prev->user;
        r->ap_auth_type = r->prev->ap_auth_type;
    }
    else {
        switch (ap_satisfies(r)) {
        case SATISFY_ALL:
        case SATISFY_NOSPEC:
            if ((access_status = ap_run_access_checker(r)) != 0) {
                return decl_die(access_status, "check access", r);
            }

            if (ap_some_auth_required(r)) {
                if (((access_status = ap_run_check_user_id(r)) != 0)
                    || !ap_auth_type(r)) {
                    return decl_die(access_status, ap_auth_type(r)
                                  ? "check user.  No user file?"
                                  : "perform authentication. AuthType not set!",
                                  r);
                }

                if (((access_status = ap_run_auth_checker(r)) != 0)
                    || !ap_auth_type(r)) {
                    return decl_die(access_status, ap_auth_type(r)
                                  ? "check access.  No groups file?"
                                  : "perform authentication. AuthType not set!",
                                   r);
                }
            }
            break;

        case SATISFY_ANY:
            if (((access_status = ap_run_access_checker(r)) != 0)) {
                if (!ap_some_auth_required(r)) {
                    return decl_die(access_status, "check access", r);
                }

                if (((access_status = ap_run_check_user_id(r)) != 0)
                    || !ap_auth_type(r)) {
                    return decl_die(access_status, ap_auth_type(r)
                                  ? "check user.  No user file?"
                                  : "perform authentication. AuthType not set!",
                                  r);
                }

                if (((access_status = ap_run_auth_checker(r)) != 0)
                    || !ap_auth_type(r)) {
                    return decl_die(access_status, ap_auth_type(r)
                                  ? "check access.  No groups file?"
                                  : "perform authentication. AuthType not set!",
                                  r);
                }
            }
            break;
        }
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

    return OK;
}


/* Useful caching structures to repeat _walk/merge sequences as required
 * when a subrequest or redirect reuses substantially the same config.
 *
 * Directive order in the httpd.conf file and its Includes significantly
 * impact this optimization.  Grouping common blocks at the front of the
 * config that are less likely to change between a request and
 * its subrequests, or between a request and its redirects reduced
 * the work of these functions significantly.
 */

typedef struct walk_walked_t {
    ap_conf_vector_t *matched; /* A dir_conf sections we matched */
    ap_conf_vector_t *merged;  /* The dir_conf merged result */
} walk_walked_t;

typedef struct walk_cache_t {
    const char         *cached;          /* The identifier we matched */
    ap_conf_vector_t  **dir_conf_tested; /* The sections we matched against */
    ap_conf_vector_t   *dir_conf_merged; /* Base per_dir_config */
    ap_conf_vector_t   *per_dir_result;  /* per_dir_config += walked result */
    apr_array_header_t *walked;          /* The list of walk_walked_t results */
} walk_cache_t;

static walk_cache_t *prep_walk_cache(apr_size_t t, request_rec *r)
{
    walk_cache_t *cache;
    void **note;

    /* Find the most relevant, recent entry to work from.  That would be
     * this request (on the second call), or the parent request of a
     * subrequest, or the prior request of an internal redirect.  Provide
     * this _walk()er with a copy it is allowed to munge.  If there is no
     * parent or prior cached request, then create a new walk cache.
     */
    note = ap_get_request_note(r, t);
    if (!note) {
        return NULL;
    }

    if (!(cache = *note)) {
        void **inherit_note;

        if ((r->main
             && ((inherit_note = ap_get_request_note(r->main, t)))
             && *inherit_note)
            || (r->prev
                && ((inherit_note = ap_get_request_note(r->prev, t)))
                && *inherit_note)) {
            cache = apr_pmemdup(r->pool, *inherit_note,
                                sizeof(*cache));
            cache->walked = apr_array_copy(r->pool, cache->walked);
        }
        else {
            cache = apr_pcalloc(r->pool, sizeof(*cache));
            cache->walked = apr_array_make(r->pool, 4, sizeof(walk_walked_t));
        }

        *note = cache;
    }
    return cache;
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
    const char *savename;

    if (!(opts & (OPT_SYM_OWNER | OPT_SYM_LINKS))) {
        return HTTP_FORBIDDEN;
    }

    /* Save the name from the valid bits. */
    savename = (lfi->valid & APR_FINFO_NAME) ? lfi->name : NULL;

    if (opts & OPT_SYM_LINKS) {
        if ((res = apr_stat(&fi, d, lfi->valid & ~(APR_FINFO_NAME 
                                                 | APR_FINFO_LINK), p)) 
                 != APR_SUCCESS) {
            return HTTP_FORBIDDEN;
        }

        /* Give back the target */
        memcpy(lfi, &fi, sizeof(fi));
        if (savename) {
            lfi->name = savename;
            lfi->valid |= APR_FINFO_NAME;
        }

        return OK;
    }

    /* OPT_SYM_OWNER only works if we can get the owner of
     * both the file and symlink.  First fill in a missing
     * owner of the symlink, then get the info of the target.
     */
    if (!(lfi->valid & APR_FINFO_OWNER)) {
        if ((res = apr_stat(&fi, d, 
                            lfi->valid | APR_FINFO_LINK | APR_FINFO_OWNER, p))
            != APR_SUCCESS) {
            return HTTP_FORBIDDEN;
        }
    }

    if ((res = apr_stat(&fi, d, lfi->valid & ~(APR_FINFO_NAME), p))
        != APR_SUCCESS) {
        return HTTP_FORBIDDEN;
    }

    if (apr_uid_compare(fi.user, lfi->user) != APR_SUCCESS) {
        return HTTP_FORBIDDEN;
    }

    /* Give back the target */
    memcpy(lfi, &fi, sizeof(fi));
    if (savename) {
        lfi->name = savename;
        lfi->valid |= APR_FINFO_NAME;
    }

    return OK;
}


/*
 * As we walk the directory configuration, the merged config won't
 * be 'rooted' to a specific vhost until the very end of the merge.
 *
 * We need a very fast mini-merge to a real, vhost-rooted merge
 * of core.opts and core.override, the only options tested within
 * directory_walk itself.
 *
 * See core.c::merge_core_dir_configs() for explanation.
 */

typedef struct core_opts_t {
        allow_options_t opts;
        allow_options_t add;
        allow_options_t remove;
        overrides_t override;
} core_opts_t;

static void core_opts_merge(const ap_conf_vector_t *sec, core_opts_t *opts)
{
    core_dir_config *this_dir = ap_get_module_config(sec, &core_module);

    if (!this_dir) {
        return;
    }

    if (this_dir->opts & OPT_UNSET) {
        opts->add = (opts->add & ~this_dir->opts_remove)
                   | this_dir->opts_add;
        opts->remove = (opts->remove & ~this_dir->opts_add)
                      | this_dir->opts_remove;
        opts->opts = (opts->opts & ~opts->remove) | opts->add;
    }
    else {
        opts->opts = this_dir->opts;
        opts->add = this_dir->opts_add;
        opts->remove = this_dir->opts_remove;
    }

    if (!(this_dir->override & OR_UNSET)) {
        opts->override = this_dir->override;
    }
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

AP_DECLARE(int) ap_directory_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **) sconf->sec_dir->elts;
    int num_sec = sconf->sec_dir->nelts;
    walk_cache_t *cache;
    char *entry_dir;
    apr_status_t rv;

    /* XXX: Better (faster) tests needed!!!
     *
     * "OK" as a response to a real problem is not _OK_, but to allow broken
     * modules to proceed, we will permit the not-a-path filename to pass the
     * following two tests.  This behavior may be revoked in future versions
     * of Apache.  We still must catch it later if it's heading for the core
     * handler.  Leave INFO notes here for module debugging.
     */
    if (r->filename == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "Module bug?  Request filename is missing for URI %s",
                      r->uri);
       return OK;
    }

    /* Canonicalize the file path without resolving filename case or aliases
     * so we can begin by checking the cache for a recent directory walk.
     * This call will ensure we have an absolute path in the same pass.
     */
    if ((rv = apr_filepath_merge(&entry_dir, NULL, r->filename,
                                 APR_FILEPATH_NOTRELATIVE, r->pool))
                  != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "Module bug?  Request filename path %s is invalid or "
                      "or not absolute for uri %s",
                      r->filename, r->uri);
        return OK;
    }

    /* XXX Notice that this forces path_info to be canonical.  That might
     * not be desired by all apps.  However, some of those same apps likely
     * have significant security holes.
     */
    r->filename = entry_dir;

    cache = prep_walk_cache(AP_NOTE_DIRECTORY_WALK, r);

    /* If this is not a dirent subrequest with a preconstructed
     * r->finfo value, then we can simply stat the filename to
     * save burning mega-cycles with unneeded stats - if this is
     * an exact file match.  We don't care about failure... we
     * will stat by component failing this meager attempt.
     *
     * It would be nice to distinguish APR_ENOENT from other
     * types of failure, such as APR_ENOTDIR.  We can do something
     * with APR_ENOENT, knowing that the path is good.
     */
    if (!r->finfo.filetype || r->finfo.filetype == APR_LNK) {
        rv = apr_stat(&r->finfo, r->filename, APR_FINFO_MIN, r->pool);

        /* some OSs will return APR_SUCCESS/APR_REG if we stat
         * a regular file but we have '/' at the end of the name;
         *
         * other OSs will return APR_ENOTDIR for that situation;
         *
         * handle it the same everywhere by simulating a failure
         * if it looks like a directory but really isn't
         *
         * Also reset if the stat failed, just for safety.
         */
        if ((rv != APR_SUCCESS) ||
            (r->finfo.filetype &&
             (r->finfo.filetype != APR_DIR) &&
             (r->filename[strlen(r->filename) - 1] == '/'))) {
             r->finfo.filetype = 0; /* forget what we learned */
        }
    }

    if (r->finfo.filetype == APR_REG) {
        entry_dir = ap_make_dirstr_parent(r->pool, entry_dir);
    }
    else if (r->filename[strlen(r->filename) - 1] != '/') {
        entry_dir = apr_pstrcat(r->pool, r->filename, "/", NULL);
    }

    /* If we have a file already matches the path of r->filename,
     * and the vhost's list of directory sections hasn't changed,
     * we can skip rewalking the directory_walk entries.
     */
    if (cache->cached
        && ((r->finfo.filetype == APR_REG)
            || ((r->finfo.filetype == APR_DIR)
                && (!r->path_info || !*r->path_info)))
        && (cache->dir_conf_tested == sec_ent)
        && (strcmp(entry_dir, cache->cached) == 0)) {
        /* Well this looks really familiar!  If our end-result (per_dir_result)
         * didn't change, we have absolutely nothing to do :)
         * Otherwise (as is the case with most dir_merged/file_merged requests)
         * we must merge our dir_conf_merged onto this new r->per_dir_config.
         */
        if (r->per_dir_config == cache->per_dir_result) {
            return OK;
        }

        if (r->per_dir_config == cache->dir_conf_merged) {
            r->per_dir_config = cache->per_dir_result;
            return OK;
        }

        if (cache->walked->nelts) {
            now_merged = ((walk_walked_t*)cache->walked->elts)
                [cache->walked->nelts - 1].merged;
        }
    }
    else {
        /* We start now_merged from NULL since we want to build
         * a locations list that can be merged to any vhost.
         */
        int sec_idx;
        int matches = cache->walked->nelts;
        walk_walked_t *last_walk = (walk_walked_t*)cache->walked->elts;
        core_dir_config *this_dir;
        core_opts_t opts;
        apr_finfo_t thisinfo;
        char *save_path_info;
        apr_size_t buflen;
        char *buf;
        unsigned int seg, startseg;

        /* Invariant: from the first time filename_len is set until
         * it goes out of scope, filename_len==strlen(r->filename)
         */
        apr_size_t filename_len;
#ifdef CASE_BLIND_FILESYSTEM
        apr_size_t canonical_len;
#endif

        /*
         * We must play our own mimi-merge game here, for the few
         * running dir_config values we care about within dir_walk.
         * We didn't start the merge from r->per_dir_config, so we
         * accumulate opts and override as we merge, from the globals.
         */
        this_dir = ap_get_module_config(r->per_dir_config, &core_module);
        opts.opts = this_dir->opts;
        opts.add = this_dir->opts_add;
        opts.remove = this_dir->opts_remove;
        opts.override = this_dir->override;

        /* Set aside path_info to merge back onto path_info later.
         * If r->filename is a directory, we must remerge the path_info,
         * before we continue!  [Directories cannot, by defintion, have
         * path info.  Either the next segment is not-found, or a file.]
         *
         * r->path_info tracks the unconsumed source path.
         * r->filename  tracks the path as we process it
         */
        if ((r->finfo.filetype == APR_DIR) && r->path_info && *r->path_info)
        {
            if ((rv = apr_filepath_merge(&r->path_info, r->filename,
                                         r->path_info,
                                         APR_FILEPATH_NOTABOVEROOT, r->pool))
                != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "dir_walk error, path_info %s is not relative "
                              "to the filename path %s for uri %s",
                              r->path_info, r->filename, r->uri);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            save_path_info = NULL;
        }
        else {
            save_path_info = r->path_info;
            r->path_info = r->filename;
        }

#ifdef CASE_BLIND_FILESYSTEM

        canonical_len = 0;
        while (r->canonical_filename && r->canonical_filename[canonical_len]
               && (r->canonical_filename[canonical_len]
                   == r->path_info[canonical_len])) {
             ++canonical_len;
        }

        while (canonical_len
               && ((r->canonical_filename[canonical_len - 1] != '/'
                   && r->canonical_filename[canonical_len - 1])
                   || (r->path_info[canonical_len - 1] != '/'
                       && r->path_info[canonical_len - 1]))) {
            --canonical_len;
        }

        /*
         * Now build r->filename component by component, starting
         * with the root (on Unix, simply "/").  We will make a huge
         * assumption here for efficiency, that any canonical path
         * already given included a canonical root.
         */
        rv = apr_filepath_root((const char **)&r->filename,
                               (const char **)&r->path_info,
                               canonical_len ? 0 : APR_FILEPATH_TRUENAME,
                               r->pool);
        filename_len = strlen(r->filename);

        /*
         * Bad assumption above?  If the root's length is longer
         * than the canonical length, then it cannot be trusted as
         * a truename.  So try again, this time more seriously.
         */
        if ((rv == APR_SUCCESS) && canonical_len
            && (filename_len > canonical_len)) {
            rv = apr_filepath_root((const char **)&r->filename,
                                   (const char **)&r->path_info,
                                   APR_FILEPATH_TRUENAME, r->pool);
            filename_len = strlen(r->filename);
            canonical_len = 0;
        }

#else /* ndef CASE_BLIND_FILESYSTEM, really this simple for Unix today; */

        rv = apr_filepath_root((const char **)&r->filename,
                               (const char **)&r->path_info,
                               0, r->pool);
        filename_len = strlen(r->filename);

#endif

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "dir_walk error, could not determine the root "
                          "path of filename %s%s for uri %s",
                          r->filename, r->path_info, r->uri);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Working space for terminating null and an extra / is required.
         */
        buflen = filename_len + strlen(r->path_info) + 2;
        buf = apr_palloc(r->pool, buflen);
        memcpy(buf, r->filename, filename_len + 1);
        r->filename = buf;
        thisinfo.valid = APR_FINFO_TYPE;
        thisinfo.filetype = APR_DIR; /* It's the root, of course it's a dir */

        /*
         * seg keeps track of which segment we've copied.
         * sec_idx keeps track of which section we're on, since sections are
         *     ordered by number of segments. See core_reorder_directories
         * startseg tells us how many segments describe the root path
         *     e.g. the complete path "//host/foo/" to a UNC share (4)
         */
        startseg = seg = ap_count_dirs(r->filename);
        sec_idx = 0;

        /*
         * Go down the directory hierarchy.  Where we have to check for
         * symlinks, do so.  Where a .htaccess file has permission to
         * override anything, try to find one.
         */
        do {
            int res;
            char *seg_name;
            char *delim;
            int temp_slash=0;

            /* We have no trailing slash, but we sure would appreciate one.
             * However, we don't want to append a / our first time through.
             */
            if ((seg > startseg) && r->filename[filename_len-1] != '/') {
                r->filename[filename_len++] = '/';
                r->filename[filename_len] = 0;
                temp_slash=1;
            }

            /* Begin *this* level by looking for matching <Directory> sections
             * from the server config.
             */
            for (; sec_idx < num_sec; ++sec_idx) {

                ap_conf_vector_t *entry_config = sec_ent[sec_idx];
                core_dir_config *entry_core;
                entry_core = ap_get_module_config(entry_config, &core_module);

                /* No more possible matches for this many segments?
                 * We are done when we find relative/regex/longer components.
                 */
                if (entry_core->r || entry_core->d_components > seg) {
                    break;
                }

                /* We will never skip '0' element components, e.g. plain old
                 * <Directory >, and <Directory "/"> are classified as zero
                 * so that Win32/Netware/OS2 etc all pick them up.
                 * Otherwise, skip over the mismatches.
                 */
                if (entry_core->d_components
                    && ((entry_core->d_components < seg)
                     || (entry_core->d_is_fnmatch
                         ? (apr_fnmatch(entry_core->d, r->filename,
                                        APR_FNM_PATHNAME) != APR_SUCCESS)
                         : (strcmp(r->filename, entry_core->d) != 0)))) {
                    continue;
                }

                /* If we haven't continue'd above, we have a match.
                 *
                 * Calculate our full-context core opts & override.
                 */
                core_opts_merge(sec_ent[sec_idx], &opts);

                /* If we merged this same section last time, reuse it
                 */
                if (matches) {
                    if (last_walk->matched == sec_ent[sec_idx]) {
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

                if (now_merged) {
                    now_merged = ap_merge_per_dir_configs(r->pool,
                                                          now_merged,
                                                          sec_ent[sec_idx]);
                }
                else {
                    now_merged = sec_ent[sec_idx];
                }

                last_walk = (walk_walked_t*)apr_array_push(cache->walked);
                last_walk->matched = sec_ent[sec_idx];
                last_walk->merged = now_merged;
            }

            /* If .htaccess files are enabled, check for one, provided we
             * have reached a real path.
             */
            do {  /* Not really a loop, just a break'able code block */

                ap_conf_vector_t *htaccess_conf = NULL;

                /* No htaccess in an incomplete root path, 
                 * nor if it's disabled 
                 */
                if (seg < startseg || !opts.override) {
                    break;
                }

                res = ap_parse_htaccess(&htaccess_conf, r, opts.override,
                                        apr_pstrdup(r->pool, r->filename),
                                        sconf->access_name);
                if (res) {
                    return res;
                }

                if (!htaccess_conf) {
                    break;
                }

                /* If we are still here, we found our htaccess.
                 *
                 * Calculate our full-context core opts & override.
                 */
                core_opts_merge(htaccess_conf, &opts);

                /* If we merged this same htaccess last time, reuse it...
                 * this wouldn't work except that we cache the htaccess
                 * sections for the lifetime of the request, so we match
                 * the same conf.  Good planning (no, pure luck ;)
                 */
                if (matches) {
                    if (last_walk->matched == htaccess_conf) {
                        now_merged = last_walk->merged;
                        ++last_walk;
                        --matches;
                        break;
                    }

                    /* We fell out of sync.  This is our own copy of walked,
                     * so truncate the remaining matches and reset
                     * remaining.
                     */
                    cache->walked->nelts -= matches;
                    matches = 0;
                }

                if (now_merged) {
                    now_merged = ap_merge_per_dir_configs(r->pool,
                                                          now_merged,
                                                          htaccess_conf);
                }
                else {
                    now_merged = htaccess_conf;
                }

                last_walk = (walk_walked_t*)apr_array_push(cache->walked);
                last_walk->matched = htaccess_conf;
                last_walk->merged = now_merged;

            } while (0); /* Only one htaccess, not a real loop */

            /* That temporary trailing slash was useful, now drop it.
             */
            if (temp_slash) {
                r->filename[--filename_len] = '\0';
            }

            /* Time for all good things to come to an end?
             */
            if (!r->path_info || !*r->path_info) {
                break;
            }

            /* Now it's time for the next segment...
             * We will assume the next element is an end node, and fix it up
             * below as necessary...
             */

            seg_name = r->filename + filename_len;
            delim = strchr(r->path_info + (*r->path_info == '/' ? 1 : 0), '/');
            if (delim) {
                size_t path_info_len = delim - r->path_info;
                *delim = '\0';
                memcpy(seg_name, r->path_info, path_info_len + 1);
                filename_len += path_info_len;
                r->path_info = delim;
                *delim = '/';
            }
            else {
                size_t path_info_len = strlen(r->path_info);
                memcpy(seg_name, r->path_info, path_info_len + 1);
                filename_len += path_info_len;
                r->path_info += path_info_len;
            }
            if (*seg_name == '/')
                ++seg_name;

            /* If nothing remained but a '/' string, we are finished
             * XXX: NO WE ARE NOT!!!  Now process this puppy!!! */
            if (!*seg_name) {
                break;
            }

            /* First optimization;
             * If...we knew r->filename was a file, and
             * if...we have strict (case-sensitive) filenames, or
             *      we know the canonical_filename matches to _this_ name, and
             * if...we have allowed symlinks
             * skip the lstat and dummy up an APR_DIR value for thisinfo.
             */
            if (r->finfo.filetype
#ifdef CASE_BLIND_FILESYSTEM
                && (filename_len <= canonical_len)
#endif
                && ((opts.opts & (OPT_SYM_OWNER | OPT_SYM_LINKS)) == OPT_SYM_LINKS))
            {

                thisinfo.filetype = APR_DIR;
                ++seg;
                continue;
            }

            /* We choose apr_stat with flag APR_FINFO_LINK here, rather that 
             * plain apr_stat, so that we capture this path object rather than
             * its target.  We will replace the info with our target's info 
             * below.  We especially want the name of this 'link' object, not 
             * the name of its target, if we are fixing the filename 
             * case/resolving aliases.
             */
            rv = apr_stat(&thisinfo, r->filename,
                          APR_FINFO_MIN | APR_FINFO_NAME | APR_FINFO_LINK, 
                          r->pool);

            if (APR_STATUS_IS_ENOENT(rv)) {
                /* Nothing?  That could be nice.  But our directory
                 * walk is done.
                 */
                thisinfo.filetype = APR_NOFILE;
                break;
            }
            else if (APR_STATUS_IS_EACCES(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "access to %s denied", r->uri);
                return r->status = HTTP_FORBIDDEN;
            }
            else if ((rv != APR_SUCCESS && rv != APR_INCOMPLETE)
                     || !(thisinfo.valid & APR_FINFO_TYPE)) {
                /* If we hit ENOTDIR, we must have over-optimized, deny
                 * rather than assume not found.
                 */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "access to %s failed", r->uri);
                return r->status = HTTP_FORBIDDEN;
            }

            /* Fix up the path now if we have a name, and they don't agree
             */
            if ((thisinfo.valid & APR_FINFO_NAME)
                && strcmp(seg_name, thisinfo.name)) {
                /* TODO: provide users an option that an internal/external
                 * redirect is required here?  We need to walk the URI and
                 * filename in tandem to properly correlate these.
                 */
                strcpy(seg_name, thisinfo.name);
                filename_len = strlen(r->filename);
            }

            if (thisinfo.filetype == APR_LNK) {
                /* Is this a possibly acceptable symlink?
                 */
                if ((res = resolve_symlink(r->filename, &thisinfo,
                                           opts.opts, r->pool)) != OK) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "Symbolic link not allowed: %s",
                                  r->filename);
                    return r->status = res;
                }
            }

            /* Ok, we are done with the link's info, test the real target
             */
            if (thisinfo.filetype == APR_REG || 
                thisinfo.filetype == APR_NOFILE) {
                /* That was fun, nothing left for us here
                 */
                break;
            }
            else if (thisinfo.filetype != APR_DIR) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Forbidden: %s doesn't point to "
                              "a file or directory",
                              r->filename);
                return r->status = HTTP_FORBIDDEN;
            }

            ++seg;
        } while (thisinfo.filetype == APR_DIR);

        /* If we have _not_ optimized, this is the time to recover
         * the final stat result.
         */
        if (!r->finfo.filetype || r->finfo.filetype == APR_LNK) {
            r->finfo = thisinfo;
        }

        /* Now splice the saved path_info back onto any new path_info
         */
        if (save_path_info) {
            if (r->path_info && *r->path_info) {
                r->path_info = ap_make_full_path(r->pool, r->path_info,
                                                 save_path_info);
            }
            else {
                r->path_info = save_path_info;
            }
        }

        /*
         * Now we'll deal with the regexes, note we pick up sec_idx
         * where we left off (we gave up after we hit entry_core->r)
         */
        for (; sec_idx < num_sec; ++sec_idx) {

            core_dir_config *entry_core;
            entry_core = ap_get_module_config(sec_ent[sec_idx], &core_module);

            if (!entry_core->r) {
                continue;
            }

            if (ap_regexec(entry_core->r, r->filename, 0, NULL, REG_NOTEOL)) {
                continue;
            }

            /* If we haven't already continue'd above, we have a match.
             *
             * Calculate our full-context core opts & override.
             */
            core_opts_merge(sec_ent[sec_idx], &opts);

            /* If we merged this same section last time, reuse it
             */
            if (matches) {
                if (last_walk->matched == sec_ent[sec_idx]) {
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

            if (now_merged) {
                now_merged = ap_merge_per_dir_configs(r->pool,
                                                      now_merged,
                                                      sec_ent[sec_idx]);
            }
            else {
                now_merged = sec_ent[sec_idx];
            }

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = sec_ent[sec_idx];
            last_walk->merged = now_merged;
        }

        /* Whoops - everything matched in sequence, but the original walk
         * found some additional matches.  Truncate them.
         */
        if (matches) {
            cache->walked->nelts -= matches;
        }
    }

/* It seems this shouldn't be needed anymore.  We translated the
 x symlink above into a real resource, and should have died up there.
 x Even if we keep this, it needs more thought (maybe an r->file_is_symlink)
 x perhaps it should actually happen in file_walk, so we catch more
 x obscure cases in autoindex sub requests, etc.
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
 x       && (res = resolve_symlink(r->filename, r->info, ap_allow_options(r),
 x                                 r->pool))) {
 x       ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
 x                     "Symbolic link not allowed: %s", r->filename);
 x       return res;
 x   }
 */

    /* Save future sub-requestors much angst in processing
     * this subrequest.  If dir_walk couldn't canonicalize
     * the file path, nothing can.
     */
    r->canonical_filename = r->filename;

    if (r->finfo.filetype == APR_DIR) {
        cache->cached = r->filename;
    }
    else {
        cache->cached = ap_make_dirstr_parent(r->pool, r->filename);
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    /* Merge our cache->dir_conf_merged construct with the r->per_dir_configs,
     * and note the end result to (potentially) skip this step next time.
     */
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool,
                                                     r->per_dir_config,
                                                     now_merged);
    }
    cache->per_dir_result = r->per_dir_config;

    return OK;
}


AP_DECLARE(int) ap_location_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_server_config *sconf = ap_get_module_config(r->server->module_config,
                                                     &core_module);
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **)sconf->sec_url->elts;
    int num_sec = sconf->sec_url->nelts;
    walk_cache_t *cache;
    const char *entry_uri;

    /* No tricks here, there are no <Locations > to parse in this vhost.
     * We won't destroy the cache, just in case _this_ redirect is later
     * redirected again to a vhost with <Location > blocks to optimize.
     */
    if (!num_sec) {
        return OK;
    }

    cache = prep_walk_cache(AP_NOTE_LOCATION_WALK, r);

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
    if (cache->cached
        && (cache->dir_conf_tested == sec_ent)
        && (strcmp(entry_uri, cache->cached) == 0)) {
        /* Well this looks really familiar!  If our end-result (per_dir_result)
         * didn't change, we have absolutely nothing to do :)
         * Otherwise (as is the case with most dir_merged/file_merged requests)
         * we must merge our dir_conf_merged onto this new r->per_dir_config.
         */
        if (r->per_dir_config == cache->per_dir_result) {
            return OK;
        }

        if (r->per_dir_config == cache->dir_conf_merged) {
            r->per_dir_config = cache->per_dir_result;
            return OK;
        }

        if (cache->walked->nelts) {
            now_merged = ((walk_walked_t*)cache->walked->elts)
                                            [cache->walked->nelts - 1].merged;
        }
    }
    else {
        /* We start now_merged from NULL since we want to build
         * a locations list that can be merged to any vhost.
         */
        int len, sec_idx;
        int matches = cache->walked->nelts;
        walk_walked_t *last_walk = (walk_walked_t*)cache->walked->elts;
        cache->cached = entry_uri;

        /* Go through the location entries, and check for matches.
         * We apply the directive sections in given order, we should
         * really try them with the most general first.
         */
        for (sec_idx = 0; sec_idx < num_sec; ++sec_idx) {

            core_dir_config *entry_core;
            entry_core = ap_get_module_config(sec_ent[sec_idx], &core_module);

            /* ### const strlen can be optimized in location config parsing */
            len = strlen(entry_core->d);

            /* Test the regex, fnmatch or string as appropriate.
             * If it's a strcmp, and the <Location > pattern was
             * not slash terminated, then this uri must be slash
             * terminated (or at the end of the string) to match.
             */
            if (entry_core->r
                ? ap_regexec(entry_core->r, r->uri, 0, NULL, 0)
                : (entry_core->d_is_fnmatch
                   ? apr_fnmatch(entry_core->d, cache->cached, APR_FNM_PATHNAME)
                   : (strncmp(entry_core->d, cache->cached, len)
                      || (entry_core->d[len - 1] != '/'
                          && cache->cached[len] != '/'
                          && cache->cached[len] != '\0')))) {
                continue;
            }

            /* If we merged this same section last time, reuse it
             */
            if (matches) {
                if (last_walk->matched == sec_ent[sec_idx]) {
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

            if (now_merged) {
                now_merged = ap_merge_per_dir_configs(r->pool,
                                                      now_merged,
                                                      sec_ent[sec_idx]);
            }
            else {
                now_merged = sec_ent[sec_idx];
            }

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = sec_ent[sec_idx];
            last_walk->merged = now_merged;
        }

        /* Whoops - everything matched in sequence, but the original walk
         * found some additional matches.  Truncate them.
         */
        if (matches) {
            cache->walked->nelts -= matches;
        }
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    /* Merge our cache->dir_conf_merged construct with the r->per_dir_configs,
     * and note the end result to (potentially) skip this step next time.
     */
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool,
                                                     r->per_dir_config,
                                                     now_merged);
    }
    cache->per_dir_result = r->per_dir_config;

    return OK;
}

AP_DECLARE(int) ap_file_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_dir_config *dconf = ap_get_module_config(r->per_dir_config,
                                                  &core_module);
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **)dconf->sec_file->elts;
    int num_sec = dconf->sec_file->nelts;
    walk_cache_t *cache;
    const char *test_file;

    /* To allow broken modules to proceed, we allow missing filenames to pass.
     * We will catch it later if it's heading for the core handler.
     * directory_walk already posted an INFO note for module debugging.
     */
    if (r->filename == NULL) {
        return OK;
    }

    cache = prep_walk_cache(AP_NOTE_FILE_WALK, r);

    /* No tricks here, there are just no <Files > to parse in this context.
     * We won't destroy the cache, just in case _this_ redirect is later
     * redirected again to a context containing the same or similar <Files >.
     */
    if (!num_sec) {
        return OK;
    }

    /* Get the basename .. and copy for the cache just
     * in case r->filename is munged by another module
     */
    test_file = strrchr(r->filename, '/');
    if (test_file == NULL) {
        test_file = apr_pstrdup(r->pool, r->filename);
    }
    else {
        test_file = apr_pstrdup(r->pool, ++test_file);
    }

    /* If we have an cache->cached file name that matches test_file,
     * and the directory's list of file sections hasn't changed, we
     * can skip rewalking the file_walk entries.
     */
    if (cache->cached
        && (cache->dir_conf_tested == sec_ent)
        && (strcmp(test_file, cache->cached) == 0)) {
        /* Well this looks really familiar!  If our end-result (per_dir_result)
         * didn't change, we have absolutely nothing to do :)
         * Otherwise (as is the case with most dir_merged requests)
         * we must merge our dir_conf_merged onto this new r->per_dir_config.
         */
        if (r->per_dir_config == cache->per_dir_result) {
            return OK;
        }

        if (r->per_dir_config == cache->dir_conf_merged) {
            r->per_dir_config = cache->per_dir_result;
            return OK;
        }

        if (cache->walked->nelts) {
            now_merged = ((walk_walked_t*)cache->walked->elts)
                [cache->walked->nelts - 1].merged;
        }
    }
    else {
        /* We start now_merged from NULL since we want to build
         * a file section list that can be merged to any dir_walk.
         */
        int sec_idx;
        int matches = cache->walked->nelts;
        walk_walked_t *last_walk = (walk_walked_t*)cache->walked->elts;
        cache->cached = test_file;

        /* Go through the location entries, and check for matches.
         * We apply the directive sections in given order, we should
         * really try them with the most general first.
         */
        for (sec_idx = 0; sec_idx < num_sec; ++sec_idx) {

            core_dir_config *entry_core;
            entry_core = ap_get_module_config(sec_ent[sec_idx], &core_module);

            if (entry_core->r
                ? ap_regexec(entry_core->r, cache->cached , 0, NULL, 0)
                : (entry_core->d_is_fnmatch
                   ? apr_fnmatch(entry_core->d, cache->cached, APR_FNM_PATHNAME)
                   : strcmp(entry_core->d, cache->cached))) {
                continue;
            }

            /* If we merged this same section last time, reuse it
             */
            if (matches) {
                if (last_walk->matched == sec_ent[sec_idx]) {
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

            if (now_merged) {
                now_merged = ap_merge_per_dir_configs(r->pool,
                                                      now_merged,
                                                      sec_ent[sec_idx]);
            }
            else {
                now_merged = sec_ent[sec_idx];
            }

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = sec_ent[sec_idx];
            last_walk->merged = now_merged;
        }

        /* Whoops - everything matched in sequence, but the original walk
         * found some additional matches.  Truncate them.
         */
        if (matches) {
            cache->walked->nelts -= matches;
        }
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    /* Merge our cache->dir_conf_merged construct with the r->per_dir_configs,
     * and note the end result to (potentially) skip this step next time.
     */
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool,
                                                     r->per_dir_config,
                                                     now_merged);
    }
    cache->per_dir_result = r->per_dir_config;

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

static request_rec *make_sub_request(const request_rec *r,
                                     ap_filter_t *next_filter)
{
    apr_pool_t *rrp;
    request_rec *rnew;

    apr_pool_create(&rrp, r->pool);
    apr_pool_tag(rrp, "subrequest");
    rnew = apr_pcalloc(rrp, sizeof(request_rec));
    rnew->pool = rrp;

    rnew->hostname       = r->hostname;
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;

    rnew->request_config = ap_create_request_config(rnew->pool);

    /* Start a clean config from this subrequest's vhost.  Optimization in
     * Location/File/Dir walks from the parent request assure that if the
     * config blocks of the subrequest match the parent request, no merges
     * will actually occur (and generally a minimal number of merges are
     * required, even if the parent and subrequest aren't quite identical.)
     */
    rnew->per_dir_config = r->server->lookup_defaults;

    rnew->htaccess = r->htaccess;
    rnew->allowed_methods = ap_make_method_list(rnew->pool, 2);

    /* make a copy of the allowed-methods list */
    ap_copy_method_list(rnew->allowed_methods, r->allowed_methods);

    /* start with the same set of output filters */
    if (next_filter) {
        /* while there are no input filters for a subrequest, we will
         * try to insert some, so if we don't have valid data, the code
         * will seg fault.
         */
        rnew->input_filters = r->input_filters;
        rnew->proto_input_filters = r->proto_input_filters;
        rnew->output_filters = next_filter;
        rnew->proto_output_filters = r->proto_output_filters;
        ap_add_output_filter_handle(ap_subreq_core_filter_handle,
                                    NULL, rnew, rnew->connection);
    }
    else {
        /* If NULL - we are expecting to be internal_fast_redirect'ed
         * to this subrequest - or this request will never be invoked.
         * Ignore the original request filter stack entirely, and
         * drill the input and output stacks back to the connection.
         */
        rnew->proto_input_filters = r->proto_input_filters;
        rnew->proto_output_filters = r->proto_output_filters;

        rnew->input_filters = r->proto_input_filters;
        rnew->output_filters = r->proto_output_filters;
    }

    /* no input filters for a subrequest */

    ap_set_sub_req_protocol(rnew, r);

    /* We have to run this after we fill in sub req vars,
     * or the r->main pointer won't be setup
     */
    ap_run_create_request(rnew);

    return rnew;
}

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_sub_req_output_filter(ap_filter_t *f,
                                                              apr_bucket_brigade *bb)
{
    apr_bucket *e = APR_BRIGADE_LAST(bb);

    if (APR_BUCKET_IS_EOS(e)) {
        apr_bucket_delete(e);
    }

    if (!APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    return APR_SUCCESS;
}


AP_DECLARE(int) ap_some_auth_required(request_rec *r)
{
    /* Is there a require line configured for the type of *this* req? */

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    int i;

    if (!reqs_arr) {
        return 0;
    }

    reqs = (require_line *) reqs_arr->elts;

    for (i = 0; i < reqs_arr->nelts; ++i) {
        if (reqs[i].method_mask & (AP_METHOD_BIT << r->method_number)) {
            return 1;
        }
    }

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

    rnew = make_sub_request(r, next_filter);

    /* would be nicer to pass "method" to ap_set_sub_req_protocol */
    rnew->method = method;
    rnew->method_number = ap_method_number_of(method);

    if (new_file[0] == '/') {
        ap_parse_uri(rnew, new_file);
    }
    else {
        udir = ap_make_dirstr_parent(rnew->pool, r->uri);
        udir = ap_escape_uri(rnew->pool, udir);    /* re-escape it */
        ap_parse_uri(rnew, ap_make_full_path(rnew->pool, udir, new_file));
    }

    /* We cannot return NULL without violating the API. So just turn this
     * subrequest into a 500 to indicate the failure. */
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }

    /* lookup_uri 
     * If the content can be served by the quick_handler, we can
     * safely bypass request_internal processing.
     */
    res = ap_run_quick_handler(rnew, 1);

    if (res != OK) {
        if ((res = ap_process_request_internal(rnew))) {
            rnew->status = res;
        }
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
                                                   int subtype,
                                                   ap_filter_t *next_filter)
{
    request_rec *rnew;
    int res;
    char *fdir;
    char *udir;

    rnew = make_sub_request(r, next_filter);

    /* Special case: we are looking at a relative lookup in the same directory.
     * This is 100% safe, since dirent->name just came from the filesystem.
     */
    if (r->path_info && *r->path_info) {
        /* strip path_info off the end of the uri to keep it in sync
         * with r->filename, which has already been stripped by directory_walk,
         * merge the dirent->name, and then, if the caller wants us to remerge
         * the original path info, do so.  Note we never fix the path_info back
         * to r->filename, since dir_walk would do so (but we don't expect it
         * to happen in the usual cases)
         */
        udir = apr_pstrdup(rnew->pool, r->uri);
        udir[ap_find_path_info(udir, r->path_info)] = '\0';
        udir = ap_make_dirstr_parent(rnew->pool, udir);

        rnew->uri = ap_make_full_path(rnew->pool, udir, dirent->name);
        if (subtype == AP_SUBREQ_MERGE_ARGS) {
            rnew->uri = ap_make_full_path(rnew->pool, rnew->uri, r->path_info + 1);
            rnew->path_info = apr_pstrdup(rnew->pool, r->path_info);
        }
        rnew->uri = ap_escape_uri(rnew->pool, rnew->uri);
    }
    else {
        udir = ap_make_dirstr_parent(rnew->pool, r->uri);
        rnew->uri = ap_escape_uri(rnew->pool, ap_make_full_path(rnew->pool,
                                                                udir,
                                                                dirent->name));
    }

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);
    rnew->filename = ap_make_full_path(rnew->pool, fdir, dirent->name);
    if (r->canonical_filename == r->filename) {
        rnew->canonical_filename = rnew->filename;
    }

    /* XXX This is now less relevant; we will do a full location walk
     * these days for this case.  Preserve the apr_stat results, and
     * perhaps we also tag that symlinks were tested and/or found for
     * r->filename.
     */
    rnew->per_dir_config = r->server->lookup_defaults;

    if ((dirent->valid & APR_FINFO_MIN) != APR_FINFO_MIN) {
        /*
         * apr_dir_read isn't very complete on this platform, so
         * we need another apr_stat (with or without APR_FINFO_LINK
         * depending on whether we allow all symlinks here.)  If this 
         * is an APR_LNK that resolves to an APR_DIR, then we will rerun 
         * everything anyways... this should be safe.
         */
        apr_status_t rv;
        if (ap_allow_options(rnew) & OPT_SYM_LINKS) {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename,
                                APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = 0;
            }
        }
        else {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename,
                                APR_FINFO_LINK | APR_FINFO_MIN, 
                                rnew->pool)) != APR_SUCCESS)
                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = 0;
            }
        }
    }
    else {
        memcpy(&rnew->finfo, dirent, sizeof(apr_finfo_t));
    }

    if (rnew->finfo.filetype == APR_LNK) {
        /*
         * Resolve this symlink.  We should tie this back to dir_walk's cache
         */
        if ((res = resolve_symlink(rnew->filename, &rnew->finfo,
                                   ap_allow_options(rnew), rnew->pool))
            != OK) {
            rnew->status = res;
            return rnew;
        }
    }

    if (rnew->finfo.filetype == APR_DIR) {
        /* ap_make_full_path overallocated the buffers
         * by one character to help us out here.
         */
        strcpy(rnew->filename + strlen(rnew->filename), "/");
        if (!rnew->path_info || !*rnew->path_info) {
            strcpy(rnew->uri  + strlen(rnew->uri ), "/");
        }
    }

    /* fill in parsed_uri values
     */
    if (r->args && *r->args && (subtype == AP_SUBREQ_MERGE_ARGS)) {
        ap_parse_uri(rnew, apr_pstrcat(r->pool, rnew->uri, "?",
                                       r->args, NULL));
    }
    else {
        ap_parse_uri(rnew, rnew->uri);
    }

    /* We cannot return NULL without violating the API. So just turn this
     * subrequest into a 500. */
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }

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

    rnew = make_sub_request(r, next_filter);

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);
    fdirlen = strlen(fdir);

    /* Translate r->filename, if it was canonical, it stays canonical
     */
    if (r->canonical_filename == r->filename) {
        rnew->canonical_filename = (char*)(1);
    }

    if (apr_filepath_merge(&rnew->filename, fdir, new_file,
                           APR_FILEPATH_TRUENAME, rnew->pool) != APR_SUCCESS) {
        rnew->status = HTTP_FORBIDDEN;
        return rnew;
    }

    if (rnew->canonical_filename) {
        rnew->canonical_filename = rnew->filename;
    }

    /*
     * Check for a special case... if there are no '/' characters in new_file
     * at all, and the path was the same, then we are looking at a relative
     * lookup in the same directory.  Fixup the URI to match.
     */

    if (strncmp(rnew->filename, fdir, fdirlen) == 0
        && rnew->filename[fdirlen]
        && ap_strchr_c(rnew->filename + fdirlen, '/') == NULL) {
        apr_status_t rv;
        if (ap_allow_options(rnew) & OPT_SYM_LINKS) {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename,
                                APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = 0;
            }
        }
        else {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename,
                                APR_FINFO_LINK | APR_FINFO_MIN, 
                                rnew->pool)) != APR_SUCCESS)
                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = 0;
            }
        }

        if (r->uri && *r->uri) {
            char *udir = ap_make_dirstr_parent(rnew->pool, r->uri);
            rnew->uri = ap_make_full_path(rnew->pool, udir,
                                          rnew->filename + fdirlen);
            ap_parse_uri(rnew, rnew->uri);    /* fill in parsed_uri values */
        }
        else {
            ap_parse_uri(rnew, new_file);        /* fill in parsed_uri values */
            rnew->uri = apr_pstrdup(rnew->pool, "");
        }
    }
    else {
        /* XXX: @@@: What should be done with the parsed_uri values?
         * We would be better off stripping down to the 'common' elements
         * of the path, then reassembling the URI as best as we can.
         */
        ap_parse_uri(rnew, new_file);        /* fill in parsed_uri values */
        /*
         * XXX: this should be set properly like it is in the same-dir case
         * but it's actually sometimes to impossible to do it... because the
         * file may not have a uri associated with it -djg
         */
        rnew->uri = apr_pstrdup(rnew->pool, "");
    }

    /* We cannot return NULL without violating the API. So just turn this
     * subrequest into a 500. */
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }

    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }

    return rnew;
}

AP_DECLARE(int) ap_run_sub_req(request_rec *r)
{
    int retval = DECLINED;
    /* Run the quick handler if the subrequest is not a dirent or file 
     * subrequest 
     */
    if (!(r->filename && r->finfo.filetype)) {
        retval = ap_run_quick_handler(r, 0);
    }
    if (retval != OK) {
        retval = ap_invoke_handler(r);
        if (retval == DONE) {
            retval = OK;
        }
    }
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
    return (r->main == NULL)       /* otherwise, this is a sub-request */
           && (r->prev == NULL);   /* otherwise, this is an internal redirect */
}
