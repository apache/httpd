/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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
 * mod_mmap_static: mmap a config-time list of files for faster serving
 *
 * v0.04
 * 
 * Author: Dean Gaudet <dgaudet@arctic.org>
 *
 * v0.01: initial implementation
 * v0.02: get rid of the extra stat() in the core by filling in what we know
 * v0.03: get rid of the cached match from the xlat routine since there are
 *        many cases where the request is modified between it and the
 *        handler... so we do the binary search twice, but the second time
 *        we can use st_ino and st_dev to speed it up.
 * v0.04: work around mod_rewrite, which sets r->filename to the uri first
 */

/*
    Documentation:

    The concept is simple.  Some sites have a set of static files that are
    really busy, and change infrequently (or even on a regular schedule).
    Save time by mmap()ing these files into memory and avoid a lot of the
    crap required to do normal file serving.  Place directives such as:

	mmapfile /path/to/file1
	mmapfile /path/to/file2
	...

    into your configuration.  These files are only mmap()d when the server
    is restarted, so if you change the list, or if the files are changed,
    then you'll need to restart the server.

    To reiterate that point:  if the files are modified *in place*
    without restarting the server you may end up serving requests that
    are completely bogus.  You should update files by unlinking the old
    copy and putting a new copy in place.  Most tools such as rdist and
    mv do this.

    There's no such thing as inheriting these files across vhosts or
    whatever... place the directives in the main server only.

    Known problems:

    Don't use Alias or RewriteRule to move these files around...  unless
    you feel like paying for an extra stat() on each request.  This is
    a deficiency in the Apache API that will hopefully be solved some day.
    The file will be served out of the mmap cache, but there will be
    an extra stat() that's a waste.
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"

module MODULE_VAR_EXPORT mmap_static_module;

typedef struct {
    char *filename;
    void *mm;
    struct stat finfo;
} a_file;

typedef struct {
    array_header *files;
    array_header *inode_sorted;
} a_server_config;


static void *create_server_config(pool *p, server_rec *s)
{
    a_server_config *sconf = ap_palloc(p, sizeof(*sconf));

    sconf->files = ap_make_array(p, 20, sizeof(a_file));
    sconf->inode_sorted = NULL;
    return sconf;
}

static void cleanup_mmap(void *sconfv)
{
    a_server_config *sconf = sconfv;
    size_t n;
    a_file *file;

    n = sconf->files->nelts;
    file = (a_file *)sconf->files->elts;
    while(n) {
	munmap(file->mm, file->finfo.st_size);
	++file;
	--n;
    }
}

static const char *mmapfile(cmd_parms *cmd, void *dummy, char *filename)
{
    a_server_config *sconf;
    a_file *new_file;
    a_file tmp;
    int fd;
    caddr_t mm;

    if (stat(filename, &tmp.finfo) == -1) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, cmd->server,
	    "mmap_static: unable to stat(%s), skipping", filename);
	return NULL;
    }
    if ((tmp.finfo.st_mode & S_IFMT) != S_IFREG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, cmd->server,
	    "mmap_static: %s isn't a regular file, skipping", filename);
	return NULL;
    }
    ap_block_alarms();
    fd = open(filename, O_RDONLY, 0);
    if (fd == -1) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, cmd->server,
	    "mmap_static: unable to open(%s, O_RDONLY), skipping", filename);
	return NULL;
    }
    mm = mmap(NULL, tmp.finfo.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mm == (caddr_t)-1) {
	int save_errno = errno;
	close(fd);
	ap_unblock_alarms();
	errno = save_errno;
	ap_log_error(APLOG_MARK, APLOG_WARNING, cmd->server,
	    "mmap_static: unable to mmap %s, skipping", filename);
	return NULL;
    }
    close(fd);
    tmp.mm = mm;
    tmp.filename = ap_pstrdup(cmd->pool, filename);
    sconf = ap_get_module_config(cmd->server->module_config, &mmap_static_module);
    new_file = ap_push_array(sconf->files);
    *new_file = tmp;
    if (sconf->files->nelts == 1) {
	/* first one, register the cleanup */
	ap_register_cleanup(cmd->pool, sconf, cleanup_mmap, ap_null_cleanup);
    }
    ap_unblock_alarms();
    return NULL;
}

static command_rec mmap_static_cmds[] =
{
    {
	"mmapfile", mmapfile, NULL, RSRC_CONF, ITERATE,
	"A space separated list of files to mmap at config time"
    },
    {
	NULL
    }
};

static int file_compare(const void *av, const void *bv)
{
    const a_file *a = av;
    const a_file *b = bv;

    return strcmp(a->filename, b->filename);
}

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

static void mmap_init(server_rec *s, pool *p)
{
    a_server_config *sconf;
    array_header *inodes;
    a_file *elts;
    int nelts;
    int i;
    
    /* sort the elements of the main_server, by filename */
    sconf = ap_get_module_config(s->module_config, &mmap_static_module);
    elts = (a_file *)sconf->files->elts;
    nelts = sconf->files->nelts;
    qsort(elts, nelts, sizeof(a_file), file_compare);

    /* build an index by inode as well, speeds up the search in the handler */
    inodes = ap_make_array(p, nelts, sizeof(a_file *));
    sconf->inode_sorted = inodes;
    for (i = 0; i < nelts; ++i) {
	*(a_file **)ap_push_array(inodes) = &elts[i];
    }
    qsort(inodes->elts, nelts, sizeof(a_file *), inode_compare);

    /* and make the virtualhosts share the same thing */
    for (s = s->next; s; s = s->next) {
	ap_set_module_config(s->module_config, &mmap_static_module, sconf);
    }
}

/* If it's one of ours, fill in r->finfo now to avoid extra stat()... this is a
 * bit of a kludge, because we really want to run after core_translate runs.
 */

static int mmap_static_xlat(request_rec *r)
{
    a_server_config *sconf;
    a_file tmp;
    a_file *match;
    int res;

    sconf = ap_get_module_config(r->server->module_config, &mmap_static_module);

    /* we only operate when at least one mmapfile directive was used */
    if (ap_is_empty_table(sconf->files))
	return DECLINED;

    /* we require other modules to first set up a filename */
    res = core_module.translate_handler(r);
    if (res == DECLINED || !r->filename) {
	return res;
    }
    tmp.filename = r->filename;
    match = (a_file *)bsearch(&tmp, sconf->files->elts, sconf->files->nelts,
	sizeof(a_file), file_compare);
    if (match == NULL) {
	return DECLINED;
    }

    /* shortcircuit the get_path_info() stat() calls and stuff */
    r->finfo = match->finfo;
    return OK;
}


static int mmap_static_handler(request_rec *r)
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
    if (r->finfo.st_mode == 0) return DECLINED;

    sconf = ap_get_module_config(r->server->module_config, &mmap_static_module);
    tmp.finfo.st_dev = r->finfo.st_dev;
    tmp.finfo.st_ino = r->finfo.st_ino;
    ptmp = &tmp;
    pmatch = (a_file **)bsearch(&ptmp, sconf->inode_sorted->elts,
	sconf->inode_sorted->nelts, sizeof(a_file *), inode_compare);
    if (pmatch == NULL) {
	return DECLINED;
    }
    match = *pmatch;

    /* note that we would handle GET on this resource */
    r->allowed |= (1 << M_GET);

    /* This handler has no use for a request body (yet), but we still
     * need to read and discard it if the client sent one.
     */
    if ((errstatus = ap_discard_request_body(r)) != OK)
        return errstatus;

    ap_update_mtime(r, match->finfo.st_mtime);
    ap_set_last_modified(r);
    ap_set_etag(r);
    if (((errstatus = ap_meets_conditions(r)) != OK)
	|| (errstatus = ap_set_content_length (r, match->finfo.st_size))) {
	    return errstatus;
    }

#ifdef CHARSET_EBCDIC
    /* check Content Type to see if ebcdic conversion is appropriate */
    ap_checkconv(r);
#endif 	
    rangestatus = ap_set_byterange(r);
    ap_send_http_header(r);

    if (!r->header_only) {
	if (!rangestatus) {
	    ap_send_mmap (match->mm, r, 0, match->finfo.st_size);
	}
	else {
	    long offset, length;
	    while (ap_each_byterange(r, &offset, &length)) {
		ap_send_mmap(match->mm, r, offset, length);
	    }
	}
    }
    return OK;
}


static const handler_rec mmap_static_handlers[] =
{
    { "*/*", mmap_static_handler },
    { NULL }
};

module MODULE_VAR_EXPORT mmap_static_module =
{
    STANDARD_MODULE_STUFF,
    mmap_init,			/* initializer */
    NULL,			/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    create_server_config,	/* server config */
    NULL,			/* merge server config */
    mmap_static_cmds,		/* command handlers */
    mmap_static_handlers,	/* handlers */
    mmap_static_xlat,		/* filename translation */
    NULL,			/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
