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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"
#include "apr_mmap.h"

module MODULE_VAR_EXPORT file_cache_module;
static ap_pool_t *context;
static int once_through = 0;

typedef struct {
#if 1
    ap_file_t *file;
#else
    ap_mmap_t *mm;
#endif
    char *filename;
    ap_finfo_t finfo;
} a_file;

typedef struct {
    ap_array_header_t *files;
    ap_array_header_t *inode_sorted;
} a_server_config;


static void *create_server_config(ap_pool_t *p, server_rec *s)
{
    a_server_config *sconf = ap_palloc(p, sizeof(*sconf));

    sconf->files = ap_make_array(p, 20, sizeof(a_file));
    sconf->inode_sorted = NULL;
    return sconf;
}
#if 0
static void pre_config(ap_pool_t *pconf, ap_pool_t *plog, ap_pool_t *ptemp)
{
    context = pconf;
}
#endif
static ap_status_t open_file(ap_file_t **file, char* filename, int flg1, int flg2, 
                             ap_pool_t *context)
{
    ap_status_t rv;
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
        rv = ap_put_os_file(file, &hFile, context);
    }
    else {
        rv = GetLastError();
        *file = NULL;
    }
#else
    rv = ap_open(file, filename, flg1, flg2, context);
#endif

    return rv;
}

ap_status_t cleanup_mmap(void *sconfv)
{
    a_server_config *sconf = sconfv;
    size_t n;
    a_file *file;

    n = sconf->files->nelts;
    file = (a_file *)sconf->files->elts;
    while(n) {
#if 1
        ap_close(file->file);
#else
        ap_mmap_delete(file->mm);
#endif
        ++file;
        --n;
    }
    return APR_SUCCESS;
}

static const char *cachefile(cmd_parms *cmd, void *dummy, char *filename)
{
    a_server_config *sconf;
    a_file *new_file;
    a_file tmp;
    ap_file_t *fd = NULL;
#if 0
    caddr_t mm;
#endif
    ap_status_t rc;
    /* canonicalize the file name */
    /* os_canonical... */
    if (ap_stat(&tmp.finfo, filename, NULL) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "file_cache: unable to stat(%s), skipping", filename);
	return NULL;
    }
    if (tmp.finfo.filetype != APR_REG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "file_cache: %s isn't a regular file, skipping", filename);
	return NULL;
    }
    /* Note: open_file should call ap_open for Unix and CreateFile for Windows.
     * The Windows file needs to be opened for async I/O to allow multiple threads
     * to serve it up at once.
     */
    rc = open_file(&fd, filename, APR_READ, APR_OS_DEFAULT, cmd->pool); //context);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
                     "file_cache: unable to open(%s, O_RDONLY), skipping", filename);
	return NULL;
    }
#if 1
    tmp.file = fd;
#else
    if (ap_mmap_create(&tmp.mm, fd, 0, tmp.finfo.st_size, context) != APR_SUCCESS) {
	int save_errno = errno;
	ap_close(fd);
	errno = save_errno;
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, cmd->server,
	    "file_cache: unable to mmap %s, skipping", filename);
	return NULL;
    }
    ap_close(fd);
#endif
    tmp.filename = ap_pstrdup(cmd->pool, filename);
    sconf = ap_get_module_config(cmd->server->module_config, &file_cache_module);
    new_file = ap_push_array(sconf->files);
    *new_file = tmp;
    if (sconf->files->nelts == 1) {
	/* first one, register the cleanup */
	ap_register_cleanup(cmd->pool, sconf, cleanup_mmap, ap_null_cleanup);
    }
    return NULL;
}

#ifdef WIN32
/* Windows doesn't have inodes. This ifdef should be changed to 
 * something like HAVE_INODES
 */
static int file_compare(const void *av, const void *bv)
{
    const a_file *a = av;
    const a_file *b = bv;

    return strcmp(a->filename, b->filename);
}
#else
static int inode_compare(const void *av, const void *bv)
{
    const a_file *a = *(a_file **)av;
    const a_file *b = *(a_file **)bv;
    long c;

    c = a->finfo.st_ino - b->finfo.st_ino;
    if (c == 0) {
	return a->finfo.st_dev - b->finfo.st_dev;
    }
    return c;
}
#endif
static void file_cache_post_config(ap_pool_t *p, ap_pool_t *plog,
                                   ap_pool_t *ptemp, server_rec *s)
{
    a_server_config *sconf;
    ap_array_header_t *inodes;
    a_file *elts;
    int nelts;
    int i;
    
    context = p;    
    /* sort the elements of the main_server, by filename */
    sconf = ap_get_module_config(s->module_config, &file_cache_module);
    elts = (a_file *)sconf->files->elts;
    nelts = sconf->files->nelts;
    qsort(elts, nelts, sizeof(a_file), file_compare);

    /* build an index by inode as well, speeds up the search in the handler */
#ifndef WIN32
    inodes = ap_make_array(p, nelts, sizeof(a_file *));
    sconf->inode_sorted = inodes;
    for (i = 0; i < nelts; ++i) {
	*(a_file **)ap_push_array(inodes) = &elts[i];
    }
    qsort(inodes->elts, nelts, sizeof(a_file *), inode_compare);
#endif
    /* and make the virtualhosts share the same thing */
    for (s = s->next; s; s = s->next) {
	ap_set_module_config(s->module_config, &file_cache_module, sconf);
    }
}

/* If it's one of ours, fill in r->finfo now to avoid extra stat()... this is a
 * bit of a kludge, because we really want to run after core_translate runs.
 */
int core_translate_copy(request_rec *r)
{
    void *sconf = r->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);
  
    if (r->proxyreq) {
        return HTTP_FORBIDDEN;
    }
    if ((r->uri[0] != '/') && strcmp(r->uri, "*")) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "Invalid URI in request %s", r->the_request);
        return BAD_REQUEST;
    }
    
    if (r->server->path 
        && !strncmp(r->uri, r->server->path, r->server->pathlen)
        && (r->server->path[r->server->pathlen - 1] == '/'
            || r->uri[r->server->pathlen] == '/'
            || r->uri[r->server->pathlen] == '\0')) {
        r->filename = ap_pstrcat(r->pool, conf->ap_document_root,
                                 (r->uri + r->server->pathlen), NULL);
    }
    else {
        /*
         * Make sure that we do not mess up the translation by adding two
         * /'s in a row.  This happens under windows when the document
         * root ends with a /
         */
        if ((conf->ap_document_root[strlen(conf->ap_document_root)-1] == '/')
            && (*(r->uri) == '/')) {
            r->filename = ap_pstrcat(r->pool, conf->ap_document_root, r->uri+1,
                                     NULL);
        }
        else {
            r->filename = ap_pstrcat(r->pool, conf->ap_document_root, r->uri,
                                     NULL);
        }
        
        return OK;
    }
}
static int file_cache_xlat(request_rec *r)
{
    a_server_config *sconf;
    a_file tmp;
    a_file *match;
    int res;

#ifdef WIN32
/*
 * This is really broken on Windows. The call to get the core_module config
 * in core_translate_copy seg faults because 'core_module' is not exported 
 * properly and needs a thunk.
 * Will be fixed when we get API_VAR_EXPORTS working correctly again    
 */
    return DECLINED;
#endif

    sconf = ap_get_module_config(r->server->module_config, &file_cache_module);

    /* we only operate when at least one cachefile directive was used */
    if (ap_is_empty_table(sconf->files))
	return DECLINED;

    res = core_translate_copy(r);
    if (res == DECLINED || !r->filename) {
	return res;
    }
    if (!r->filename)
        return DECLINED;
    tmp.filename = r->filename;
    match = (a_file *)bsearch(&tmp, sconf->files->elts, sconf->files->nelts,
	sizeof(a_file), file_compare);
    if (match == NULL)
	    return DECLINED;

    /* shortcircuit the get_path_info() stat() calls and stuff */
    r->finfo = match->finfo;
    return OK;
}


static int file_cache_handler(request_rec *r)
{
    a_server_config *sconf;
    a_file tmp;
    a_file *ptmp;
    a_file **pmatch;
    a_file *match;
    int rangestatus, errstatus;

    /* we don't handle anything but GET */
    if (r->method_number != M_GET) return DECLINED;

    /* file doesn't exist, we won't be dealing with it */
    if (r->finfo.protection == 0) return DECLINED;

    sconf = ap_get_module_config(r->server->module_config, &file_cache_module);
#ifdef WIN32
    tmp.filename = r->filename;
#else
    tmp.finfo.st_dev = r->finfo.st_dev;
    tmp.finfo.st_ino = r->finfo.st_ino;
#endif
    ptmp = &tmp;
#ifdef WIN32
    match = (a_file *)bsearch(ptmp, sconf->files->elts,
	sconf->files->nelts, sizeof(a_file), file_compare);
    if (match == NULL) {
	return DECLINED;
    }
#else
    pmatch = (a_file **)bsearch(&ptmp, sconf->inode_sorted->elts,
	sconf->inode_sorted->nelts, sizeof(a_file *), inode_compare);
    if (pmatch == NULL) {
	return DECLINED;
    }
    match = *pmatch;
#endif

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

    if (!r->header_only) {
        long length = match->finfo.size;
        ap_off_t offset = 0;
#if 1
        /* ap_bflush(r->connection->client->); */
        struct iovec iov;
        ap_hdtr_t hdtr;
        ap_hdtr_t *phdtr = &hdtr;

        /* frob the client buffer */
        iov.iov_base = r->connection->client->outbase;
        iov.iov_len =  r->connection->client->outcnt;
        r->connection->client->outcnt = 0;

        /* initialize the ap_hdtr_t struct */
        phdtr->headers = &iov;
        phdtr->numheaders = 1;
        phdtr->trailers = NULL;
        phdtr->numtrailers = 0;

	if (!rangestatus) {
            iol_sendfile(r->connection->client->iol,
                         match->file,
                         phdtr,
                         &offset,
                         &length,
                         0);
	}
	else {
	    while (ap_each_byterange(r, &offset, &length)) {
                iol_sendfile(r->connection->client->iol, 
                             match->file,
                             phdtr,
                             &offset,
                             &length,
                             0);
                phdtr = NULL;
	    }
	}
#else
	if (!rangestatus) {
	    ap_send_mmap (match->mm, r, 0, match->finfo.st_size);
	}
	else {
	    while (ap_each_byterange(r, &offset, &length)) {
		ap_send_mmap(match->mm, r, offset, length);
	    }
	}
#endif
    }

    return OK;
}

static command_rec mmap_cmds[] =
{
    {"cachefile", cachefile, NULL, RSRC_CONF, ITERATE,
     "A space seperated list of files to mmap at config time"},
    {NULL}
};

static void register_hooks(void)
{
    /* static const char* const aszPre[]={"http_core.c",NULL}; */
    /* ap_hook_pre_config(pre_config,NULL,NULL,AP_HOOK_MIDDLE); */
    ap_hook_post_config(file_cache_post_config, NULL, NULL, AP_HOOK_MIDDLE);
    ap_hook_translate_name(file_cache_xlat, NULL, NULL, AP_HOOK_MIDDLE);
    /* This trick doesn't work apparently because the translate hooks
       are single shot. If the core_hook returns OK, then our hook is 
       not called.
    ap_hook_translate_name(file_cache_xlat, aszPre, NULL, AP_HOOK_MIDDLE); 
    */

};

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
    mmap_cmds,                /* command handlers */
    file_cache_handlers,      /* handlers */
    register_hooks            /* register hooks */
};
