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
 */

/*
 * Author: mod_file_cache by Bill Stoddard <stoddard@apache.org> 
 *         Based on mod_mmap_static by Dean Gaudet <dgaudet@arctic.org>
 *
 * v0.01: initial implementation
 */

/*
    Documentation:

    Some sites have a set of static files that are really busy, and 
    change infrequently (or even on a regular schedule). Save time 
    by caching open handles to these files. This module, unlike 
    mod_mmap_static, caches open file handles, not file content. 
    On systems (like Windows) with heavy system call overhead and
    that have an efficient sendfile implementation, caching file handles
    offers several advantages over caching content. First, the file system
    can manage the memory, allowing infrequently hit cached files to
    be paged out. Second, since caching open handles does not consume
    significant resources, it will be possible to enable an AutoLoadCache
    feature where static files are dynamically loaded in the cache 
    as the server runs. On systems that have file change notification,
    this module can be enhanced to automatically garbage collect 
    cached files that change on disk.

    This module should work on Unix systems that have sendfile. Place 
    cachefile directives into your configuration to direct files to
    be cached.

	cachefile /path/to/file1
	cachefile /path/to/file2
	...

    These files are only cached when the server is restarted, so if you 
    change the list, or if the files are changed, then you'll need to 
    restart the server.

    To reiterate that point:  if the files are modified *in place*
    without restarting the server you may end up serving requests that
    are completely bogus.  You should update files by unlinking the old
    copy and putting a new copy in place. 

    There's no such thing as inheriting these files across vhosts or
    whatever... place the directives in the main server only.

    Known problems:

    Don't use Alias or RewriteRule to move these files around...  unless
    you feel like paying for an extra stat() on each request.  This is
    a deficiency in the Apache API that will hopefully be solved some day.
    The file will be served out of the file handle cache, but there will be
    an extra stat() that's a waste.
*/

#include "apr.h"
#include "apr_mmap.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"

module AP_MODULE_DECLARE_DATA file_cache_module;

typedef struct {
#if APR_HAS_SENDFILE
    apr_file_t *file;
#endif
    const char *filename;
    apr_finfo_t finfo;
    int is_mmapped;
#if APR_HAS_MMAP
    apr_mmap_t *mm;
#endif
    char mtimestr[APR_RFC822_DATE_LEN];
    char sizestr[21];	/* big enough to hold any 64-bit file size + null */ 
} a_file;

typedef struct {
    apr_array_header_t *files;
} a_server_config;


static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    a_server_config *sconf = apr_palloc(p, sizeof(*sconf));

    sconf->files = apr_array_make(p, 20, sizeof(a_file));
    return sconf;
}

static apr_status_t cleanup_file_cache(void *sconfv)
{
    a_server_config *sconf = sconfv;
    size_t n;
    a_file *file;

    n = sconf->files->nelts;
    file = (a_file *)sconf->files->elts;
    while(n) {
#if APR_HAS_MMAP
        if (file->is_mmapped) { 
	    apr_mmap_delete(file->mm);
        } 
        else 
#endif 
#if APR_HAS_SENDFILE
            apr_file_close(file->file); 
#endif
	    ++file;
	    --n;
    }
    return APR_SUCCESS;
}

static const char *cachefile(cmd_parms *cmd, void *dummy, const char *filename)

{
    /* ToDo:
     * Disable the file cache on a Windows 9X box. APR_HAS_SENDFILE will be
     * defined in an Apache for Windows build, but apr_sendfile returns
     * APR_ENOTIMPL on Windows 9X because TransmitFile is not available.
     */

#if APR_HAS_SENDFILE
    a_server_config *sconf;
    a_file *new_file;
    a_file tmp;
    apr_file_t *fd = NULL;
    apr_status_t rc;

    /* canonicalize the file name? */
    /* os_canonical... */
    /* XXX: uh... yea, or expect them to be -very- accurate typists */
    if ((rc = apr_stat(&tmp.finfo, filename, APR_FINFO_MIN, 
                       cmd->temp_pool)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
	    "mod_file_cache: unable to stat(%s), skipping", filename);
	return NULL;
    }
    if (tmp.finfo.filetype != APR_REG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
	    "mod_file_cache: %s isn't a regular file, skipping", filename);
	return NULL;
    }

    rc = apr_file_open(&fd, filename, APR_READ | APR_XTHREAD, APR_OS_DEFAULT, cmd->pool);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
                     "mod_file_cache: unable to open(%s, O_RDONLY), skipping", filename);
	return NULL;
    }
    tmp.file = fd;
    tmp.filename = apr_pstrdup(cmd->pool, filename);
    apr_rfc822_date(tmp.mtimestr, tmp.finfo.mtime);
    apr_snprintf(tmp.sizestr, sizeof tmp.sizestr, "%lu", tmp.finfo.size);
    sconf = ap_get_module_config(cmd->server->module_config, &file_cache_module);
    new_file = apr_array_push(sconf->files);
    *new_file = tmp;
    if (sconf->files->nelts == 1) {
	/* first one, register the cleanup */
	apr_pool_cleanup_register(cmd->pool, sconf, cleanup_file_cache, apr_pool_cleanup_null);
    }

    new_file->is_mmapped = FALSE;

    return NULL;
#else
    /* Sendfile not supported on this platform */
    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
                 "mod_file_cache: unable to cache file: %s. Sendfile is not supported on this OS", filename);
    return NULL;
#endif
}

static const char *mmapfile(cmd_parms *cmd, void *dummy, const char *filename)
{
#if APR_HAS_MMAP
    a_server_config *sconf;
    a_file *new_file;
    a_file tmp;
    apr_file_t *fd = NULL;
    apr_status_t rc;
    const char *fspec;

    fspec = ap_os_case_canonical_filename(cmd->pool, filename);
    if ((rc = apr_stat(&tmp.finfo, fspec, APR_FINFO_MIN, 
                       cmd->temp_pool)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
	    "mod_file_cache: unable to stat(%s), skipping", filename);
	return NULL;
    }
    if ((tmp.finfo.filetype) != APR_REG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
	    "mod_file_cache: %s isn't a regular file, skipping", filename);
	return NULL;
    }
    if ((rc = apr_file_open(&fd, fspec, APR_READ, APR_OS_DEFAULT, 
                       cmd->temp_pool)) != APR_SUCCESS) { 
	ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
                     "mod_file_cache: unable to open %s, skipping", 
                     filename);
	return NULL;
    }
    if ((rc = apr_mmap_create(&tmp.mm, fd, 0, tmp.finfo.size, APR_MMAP_READ, cmd->pool)) != APR_SUCCESS) { 
	apr_file_close(fd);
	ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
	    "mod_file_cache: unable to mmap %s, skipping", filename);
	return NULL;
    }
    apr_file_close(fd);
    tmp.filename = fspec;
    apr_rfc822_date(tmp.mtimestr, tmp.finfo.mtime);
    apr_snprintf(tmp.sizestr, sizeof tmp.sizestr, "%lu", tmp.finfo.size);
    sconf = ap_get_module_config(cmd->server->module_config, &file_cache_module);
    new_file = apr_array_push(sconf->files);
    *new_file = tmp;
    if (sconf->files->nelts == 1) {
	/* first one, register the cleanup */
       apr_pool_cleanup_register(cmd->pool, sconf, cleanup_file_cache, apr_pool_cleanup_null); 
    }

    new_file->is_mmapped = TRUE;

    return NULL;
#else
    /* MMAP not supported on this platform*/
    return NULL;
#endif
}


static int file_compare(const void *av, const void *bv)
{
    const a_file *a = av;
    const a_file *b = bv;

    return strcmp(a->filename, b->filename);
}

static void file_cache_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    a_server_config *sconf;
    a_file *elts;
    int nelts;

    /* sort the elements of the main_server, by filename */
    sconf = ap_get_module_config(s->module_config, &file_cache_module);
    elts = (a_file *)sconf->files->elts;
    nelts = sconf->files->nelts;
    qsort(elts, nelts, sizeof(a_file), file_compare);

    /* and make the virtualhosts share the same thing */
    for (s = s->next; s; s = s->next) {
	ap_set_module_config(s->module_config, &file_cache_module, sconf);
    }
}

/* If it's one of ours, fill in r->finfo now to avoid extra stat()... this is a
 * bit of a kludge, because we really want to run after core_translate runs.
 */
static int file_cache_xlat(request_rec *r)
{
    a_server_config *sconf;
    a_file tmp;
    a_file *match;
    int res;

    sconf = ap_get_module_config(r->server->module_config, &file_cache_module);

    /* we only operate when at least one cachefile directive was used */
    if (apr_is_empty_table(sconf->files))
	return DECLINED;

    res = ap_core_translate(r);
    if (res != OK || !r->filename) {
	return res;
    }

    tmp.filename = r->filename;
    match = (a_file *)bsearch(&tmp, sconf->files->elts, sconf->files->nelts,
	sizeof(a_file), file_compare);

    if (match == NULL)
        return DECLINED;

    /* pass bsearch results to handler */
    ap_set_module_config(r->request_config, &file_cache_module, match);

    /* shortcircuit the get_path_info() stat() calls and stuff */
    r->finfo = match->finfo;
    return OK;
}


static int mmap_handler(request_rec *r, a_file *file)
{
#if APR_HAS_MMAP
    ap_send_mmap (file->mm, r, 0, file->finfo.size);
#endif
    return OK;
}

static int sendfile_handler(request_rec *r, a_file *file)
{
#if APR_HAS_SENDFILE
    apr_size_t nbytes;
    apr_status_t rv = APR_EINIT;

    /* A cached file handle (more importantly, its file pointer) is 
     * shared by all threads in the process. The file pointer will 
     * be corrupted if multiple threads attempt to read from the 
     * cached file handle. The sendfile API does not rely on the position 
     * of the file pointer instead taking explicit file offset and 
     * length arguments. 
     *
     * We should call ap_send_fd with a cached file handle IFF 
     * we are CERTAIN the file will be served with apr_sendfile(). 
     * The presense of an AP_FTYPE_FILTER in the filter chain nearly
     * guarantees that apr_sendfile will NOT be used to send the file.
     * Furthermore, AP_FTYPE_CONTENT filters will be at the beginning
     * of the chain, so it should suffice to just check the first 
     * filter in the chain. If the first filter is not a content filter, 
     * assume apr_sendfile() will be used to send the content.
     */
    if (r->output_filters && r->output_filters->frec) {
        if (r->output_filters->frec->ftype == AP_FTYPE_CONTENT)
            return DECLINED;
    }


    rv = ap_send_fd(file->file, r, 0, file->finfo.size, &nbytes);
    if (rv != APR_SUCCESS) {
        /* ap_send_fd will log the error */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif
    return OK;
}

static int file_cache_handler(request_rec *r) 
{
    a_file *match;
    int errstatus;
    int rc = OK;

    /* XXX: not sure if this is right yet
     * see comment in http_core.c:default_handler
     */
    if (ap_strcmp_match(r->handler, "*/*")) {
        return DECLINED;
    }

    /* we don't handle anything but GET */
    if (r->method_number != M_GET) return DECLINED;

    /* did xlat phase find the file? */
    match = ap_get_module_config(r->request_config, &file_cache_module);

    if (match == NULL) {
	return DECLINED;
    }

    /* note that we would handle GET on this resource */
    r->allowed |= (1 << M_GET);

    /* This handler has no use for a request body (yet), but we still
     * need to read and discard it if the client sent one.
     */
    if ((errstatus = ap_discard_request_body(r)) != OK)
        return errstatus;

    ap_update_mtime(r, match->finfo.mtime);

    /* ap_set_last_modified() always converts the file mtime to a string
     * which is slow.  Accelerate the common case.
     * ap_set_last_modified(r);
     */
    {
        apr_time_t mod_time;
        char *datestr;

        mod_time = ap_rationalize_mtime(r, r->mtime);
        if (mod_time == match->finfo.mtime)
            datestr = match->mtimestr;
        else {
            datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
            apr_rfc822_date(datestr, mod_time);
        }
        apr_table_setn(r->headers_out, "Last-Modified", datestr);
    }

    ap_set_etag(r);
    if ((errstatus = ap_meets_conditions(r)) != OK) {
       return errstatus;
    }

    /* ap_set_content_length() always converts the same number and never
     * returns an error.  Accelerate it.
     */
    r->clength = match->finfo.size;
    apr_table_setn(r->headers_out, "Content-Length", match->sizestr);

    ap_send_http_header(r);

    /* Call appropriate handler */
    if (!r->header_only) {    
        if (match->is_mmapped == TRUE)
            rc = mmap_handler(r, match);
        else
            rc = sendfile_handler(r, match);
    }

    return rc;
}

static command_rec file_cache_cmds[] =
{
AP_INIT_ITERATE("cachefile", cachefile, NULL, RSRC_CONF,
     "A space separated list of files to add to the file handle cache at config time"),
AP_INIT_ITERATE("mmapfile", mmapfile, NULL, RSRC_CONF,
     "A space separated list of files to mmap at config time"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(file_cache_handler, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(file_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(file_cache_xlat, NULL, NULL, APR_HOOK_MIDDLE);
    /* This trick doesn't work apparently because the translate hooks
       are single shot. If the core_hook returns OK, then our hook is 
       not called.
    ap_hook_translate_name(file_cache_xlat, aszPre, NULL, APR_HOOK_MIDDLE); 
    */

}

module AP_MODULE_DECLARE_DATA file_cache_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                     /* create per-directory config structure */
    NULL,                     /* merge per-directory config structures */
    create_server_config,     /* create per-server config structure */
    NULL,                     /* merge per-server config structures */
    file_cache_cmds,          /* command handlers */
    register_hooks            /* register hooks */
};
