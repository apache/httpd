/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
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

#ifdef HAVE_STDIOP_H
#include <stdio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"
#include "apr_mmap.h"
#include "apr_strings.h"

module MODULE_VAR_EXPORT file_cache_module;
static int once_through = 0;

typedef struct {
#if APR_HAS_SENDFILE
    apr_file_t *file;
#endif
    char *filename;
    apr_finfo_t finfo;
    int is_mmapped;
#if APR_HAS_MMAP
    apr_mmap_t *mm;
#endif
} a_file;

typedef struct {
    apr_array_header_t *files;
} a_server_config;


static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    a_server_config *sconf = apr_palloc(p, sizeof(*sconf));

    sconf->files = apr_make_array(p, 20, sizeof(a_file));
    return sconf;
}

static apr_status_t open_file(apr_file_t **file, const char *filename, int flg1, int flg2, 
                             apr_pool_t *p)
{
    apr_status_t rv;
#ifdef WIN32
    /* The Windows file needs to be opened for overlapped i/o, which APR doesn't
     * support.
     */
    HANDLE hFile;
    hFile = CreateFile(filename,          /* pointer to name of the file */
                       GENERIC_READ,      /* access (read-write) mode */
                       FILE_SHARE_READ,   /* share mode */
                       NULL,              /* pointer to security attributes */
                       OPEN_EXISTING,     /* how to create */
                       FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN, /* file attributes */
                       NULL);            /* handle to file with attributes to copy */
    if (hFile != INVALID_HANDLE_VALUE) {
        rv = apr_put_os_file(file, &hFile, p);
    }
    else {
        rv = GetLastError();
        *file = NULL;
    }
#else
    rv = apr_open(file, filename, flg1, flg2, p);
#endif

    return rv;
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
            apr_close(file->file); 
#endif
	    ++file;
	    --n;
    }
    return APR_SUCCESS;
}

static const char *cachefile(cmd_parms *cmd, void *dummy, const char *filename)

{
#if APR_HAS_SENDFILE
    a_server_config *sconf;
    a_file *new_file;
    a_file tmp;
    apr_file_t *fd = NULL;
    apr_status_t rc;

    /* canonicalize the file name? */
    /* os_canonical... */
    if (apr_stat(&tmp.finfo, filename, cmd->temp_pool) != APR_SUCCESS) { 
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "file_cache: unable to stat(%s), skipping", filename);
	return NULL;
    }
    if (tmp.finfo.filetype != APR_REG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "file_cache: %s isn't a regular file, skipping", filename);
	return NULL;
    }

    /* Note: open_file should call apr_open for Unix and CreateFile for Windows.
     * The Windows file needs to be opened for async I/O to allow multiple threads
     * to serve it up at once.
     */
    rc = open_file(&fd, filename, APR_READ, APR_OS_DEFAULT, cmd->pool);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
                     "file_cache: unable to open(%s, O_RDONLY), skipping", filename);
	return NULL;
    }
    tmp.file = fd;
    tmp.filename = apr_pstrdup(cmd->pool, filename);
    sconf = ap_get_module_config(cmd->server->module_config, &file_cache_module);
    new_file = apr_push_array(sconf->files);
    *new_file = tmp;
    if (sconf->files->nelts == 1) {
	/* first one, register the cleanup */
	apr_register_cleanup(cmd->pool, sconf, cleanup_file_cache, apr_null_cleanup);
    }

    new_file->is_mmapped = FALSE;

    return NULL;
#else
    /* Sendfile not supported on this platform */
    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
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

    if (apr_stat(&tmp.finfo, filename, cmd->temp_pool) != APR_SUCCESS) { 
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "mod_file_cache: unable to stat(%s), skipping", filename);
	return NULL;
    }
    if ((tmp.finfo.filetype) != APR_REG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "mod_file_cache: %s isn't a regular file, skipping", filename);
	return NULL;
    }
    if (apr_open(&fd, filename, APR_READ, APR_OS_DEFAULT, cmd->temp_pool) 
                != APR_SUCCESS) { 
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "mod_file_cache: unable to open(%s, O_RDONLY), skipping", filename);
	return NULL;
    }
    if (apr_mmap_create(&tmp.mm, fd, 0, tmp.finfo.size, cmd->pool) != APR_SUCCESS) { 
	int save_errno = errno;
	apr_close(fd);
	errno = save_errno;
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "mod_file_cache: unable to mmap %s, skipping", filename);
	return NULL;
    }
    apr_close(fd);
    tmp.filename = apr_pstrdup(cmd->pool, filename);
    sconf = ap_get_module_config(cmd->server->module_config, &file_cache_module);
    new_file = apr_push_array(sconf->files);
    *new_file = tmp;
    if (sconf->files->nelts == 1) {
	/* first one, register the cleanup */
       apr_register_cleanup(cmd->pool, sconf, cleanup_file_cache, apr_null_cleanup); 
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

    once_through++;

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
    if (ap_is_empty_table(sconf->files))
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


static int mmap_handler(request_rec *r, a_file *file, int rangestatus)
{
#if APR_HAS_MMAP
    if (!rangestatus) {
        ap_send_mmap (file->mm, r, 0, file->finfo.size);
    }
    else {
        apr_size_t length;
        apr_off_t offset;
        while (ap_each_byterange(r, &offset, &length)) {
            ap_send_mmap(file->mm, r, offset, length);
        }
    }
#endif
    return OK;
}

static int sendfile_handler(request_rec *r, a_file *file, int rangestatus)
{
#if APR_HAS_SENDFILE
    apr_size_t length, nbytes;
    apr_off_t offset = 0;
    apr_status_t rv = APR_EINIT;

    if (!rangestatus) {
        rv = ap_send_fd(file->file, r, 0, file->finfo.size, &nbytes);
    }
    else {
        while (ap_each_byterange(r, &offset, &length)) {
            if ((rv = ap_send_fd(file->file, r, offset, length, &nbytes)) != APR_SUCCESS)
                break;
        }
    }
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_file_cache: sendfile_handler error serving file: %s", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif
    return OK;
}
#if 0
static int sendfile_handler(request_rec *r, a_file *file, int rangestatus)
{
#if APR_HAS_SENDFILE
    long length;
    apr_off_t offset = 0;
    struct iovec iov;
    apr_hdtr_t hdtr;
    apr_hdtr_t *phdtr = &hdtr;
    apr_status_t rv; 
    apr_int32_t flags = 0;

    /* 
     * We want to send any data held in the client buffer on the
     * call to iol_sendfile. So hijack it then set outcnt to 0
     * to prevent the data from being sent to the client again
     * when the buffer is flushed to the client at the end of the 
     * request.
     */
    iov.iov_base = r->connection->client->outbase;
    iov.iov_len =  r->connection->client->outcnt;
    r->connection->client->outcnt = 0;

    /* initialize the apr_hdtr_t struct */
    phdtr->headers = &iov;
    phdtr->numheaders = 1;
    phdtr->trailers = NULL;
    phdtr->numtrailers = 0;

    if (!rangestatus) {
        length = file->finfo.size;

        if (!r->connection->keepalive) {
            /* Disconnect the socket after the send completes. This
             * should leave the accept socket in a state ready to be
             * reused for the next connection.
             */
            flags |= APR_SENDFILE_DISCONNECT_SOCKET;
        }

        rv = iol_sendfile(r->connection->client->iol, 
                     file->file,
                     phdtr,
                     &offset,
                     &length,
                     flags);
        if (rv != APR_SUCCESS) { 
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                          "mod_file_cache: iol_sendfile failed."); 
        }
    } 
    else {
        while (ap_each_byterange(r, &offset, &length)) {
            rv =iol_sendfile(r->connection->client->iol, 
                         file->file,
                         phdtr,
                         &offset,
                         &length,
                             0); 
            if (rv != APR_SUCCESS) { 
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, 
                              "mod_file_cache: iol_sendfile failed."); 
            } 
            phdtr = NULL;
        }
    }
#endif
    return OK;
}
#endif

static int file_cache_handler(request_rec *r) 
{
    a_file *match;
    int rangestatus, errstatus;
    int rc = OK;

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
    ap_set_last_modified(r);
    ap_set_etag(r);
    if (((errstatus = ap_meets_conditions(r)) != OK)
	|| (errstatus = ap_set_content_length (r, match->finfo.size))) {
	    return errstatus;
    }

    rangestatus = ap_set_byterange(r);
    ap_send_http_header(r);

    /* Call appropriate handler */
    if (!r->header_only) {    
        if (match->is_mmapped == TRUE)
            rc = mmap_handler(r, match, rangestatus);
        else
            rc = sendfile_handler(r, match, rangestatus);
    }

    return rc;
}

static command_rec file_cache_cmds[] =
{
AP_INIT_ITERATE("cachefile", cachefile, NULL, RSRC_CONF,
     "A space seperated list of files to add to the file handle cache at config time"),
AP_INIT_ITERATE("mmapfile", mmapfile, NULL, RSRC_CONF,
     "A space seperated list of files to mmap at config time"),
    {NULL}
};

static void register_hooks(void)
{
    ap_hook_post_config(file_cache_post_config, NULL, NULL, AP_HOOK_MIDDLE);
    ap_hook_translate_name(file_cache_xlat, NULL, NULL, AP_HOOK_MIDDLE);
    /* This trick doesn't work apparently because the translate hooks
       are single shot. If the core_hook returns OK, then our hook is 
       not called.
    ap_hook_translate_name(file_cache_xlat, aszPre, NULL, AP_HOOK_MIDDLE); 
    */

}

static const handler_rec file_cache_handlers[] =
{
    { "*/*", file_cache_handler },
    { NULL }
};

module MODULE_VAR_EXPORT file_cache_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                     /* create per-directory config structure */
    NULL,                     /* merge per-directory config structures */
    create_server_config,     /* create per-server config structure */
    NULL,                     /* merge per-server config structures */
    file_cache_cmds,          /* command handlers */
    file_cache_handlers,      /* handlers */
    register_hooks            /* register hooks */
};
