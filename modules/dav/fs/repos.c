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
 */

/*
** DAV filesystem-based repository provider
*/

#include <string.h>

#include "apr_file_io.h"

#include "httpd.h"
#include "http_log.h"
#include "http_protocol.h"	/* for ap_set_* (in dav_fs_set_headers) */
#include "http_request.h"       /* for ap_update_mtime() */

#include "mod_dav.h"
#include "repos.h"


/* to assist in debugging mod_dav's GET handling */
#define DEBUG_GET_HANDLER       0
#define DEBUG_PATHNAME_STYLE    0

#define DAV_FS_COPY_BLOCKSIZE	16384	/* copy 16k at a time */

/* context needed to identify a resource */
struct dav_resource_private {
    apr_pool_t *pool;        /* memory storage pool associated with request */
    const char *pathname;   /* full pathname to resource */
    apr_finfo_t finfo;       /* filesystem info */
};

/* private context for doing a filesystem walk */
typedef struct {
    dav_walker_ctx *wctx;

    dav_resource res1;
    dav_resource res2;
    dav_resource_private info1;
    dav_resource_private info2;
    dav_buffer path1;
    dav_buffer path2;

    dav_buffer locknull_buf;

} dav_fs_walker_context;

/* pull this in from the other source file */
extern const dav_hooks_locks dav_hooks_locks_fs;

/* forward-declare this sucker */
static const dav_hooks_repository dav_hooks_repository_fs;

/*
** The Provider ID is used to differentiate "logical" providers that use
** the same set of hook functions. Essentially, the ID is an instance
** handle and the hooks are a vtable.
**
** In this module, we only have a single provider for each type, so we
** actually ignore the Provider ID.
*/
#define DAV_FS_PROVIDER_ID	0

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const dav_fs_namespace_uris[] =
{
    "DAV:",
    "http://apache.org/dav/props/",

    NULL	/* sentinel */
};
enum {
    DAV_FS_URI_DAV,		/* the DAV: namespace URI */
    DAV_FS_URI_MYPROPS		/* the namespace URI for our custom props */
};

/*
** The properties that we define.
*/
enum {
    /* using DAV_FS_URI_DAV */
    DAV_PROPID_FS_creationdate = DAV_PROPID_FS,
    DAV_PROPID_FS_displayname,
    DAV_PROPID_FS_getcontentlength,
    DAV_PROPID_FS_getetag,
    DAV_PROPID_FS_getlastmodified,
    DAV_PROPID_FS_source,

    /* using DAV_FS_URI_MYPROPS */
    DAV_PROPID_FS_executable
};
/* NOTE: the magic "200" is derived from the ranges in mod_dav.h */
#define DAV_PROPID_FS_OURS(id)	(DAV_PROPID_FS <= (id) && \
				 (id) < DAV_PROPID_FS + 200)

typedef struct {
    int ns;
    const char * name;

    int propid;
} dav_fs_liveprop_name;

static const dav_fs_liveprop_name dav_fs_props[] =
{
    { DAV_FS_URI_DAV,     "creationdate",     DAV_PROPID_FS_creationdate },
    { DAV_FS_URI_DAV,     "getcontentlength", DAV_PROPID_FS_getcontentlength },
    { DAV_FS_URI_DAV,     "getetag",          DAV_PROPID_FS_getetag },
    { DAV_FS_URI_DAV,     "getlastmodified",  DAV_PROPID_FS_getlastmodified },

    { DAV_FS_URI_MYPROPS, "executable",       DAV_PROPID_FS_executable },
      
    /* ### these aren't FS specific */
    { DAV_FS_URI_DAV,     "displayname",      DAV_PROPID_FS_displayname },
    { DAV_FS_URI_DAV,     "source",           DAV_PROPID_FS_source },

    { 0 }	/* sentinel */
};


/* define the dav_stream structure for our use */
struct dav_stream {
    apr_pool_t *p;
    apr_file_t *f;
    const char *pathname;	/* we may need to remove it at close time */
};

/* forward declaration for internal treewalkers */
static dav_error * dav_fs_walk(dav_walker_ctx *wctx, int depth);

/* --------------------------------------------------------------------
**
** PRIVATE REPOSITORY FUNCTIONS
*/
apr_pool_t *dav_fs_pool(const dav_resource *resource)
{
    return resource->info->pool;
}

const char *dav_fs_pathname(const dav_resource *resource)
{
    return resource->info->pathname;
}

void dav_fs_dir_file_name(
    const dav_resource *resource,
    const char **dirpath_p,
    const char **fname_p)
{
    dav_resource_private *ctx = resource->info;

    if (resource->collection) {
        *dirpath_p = ctx->pathname;
        if (fname_p != NULL)
            *fname_p = NULL;
    }
    else {
        char *dirpath = ap_make_dirstr_parent(ctx->pool, ctx->pathname);
        size_t dirlen = strlen(dirpath);

        if (fname_p != NULL)
            *fname_p = ctx->pathname + dirlen;
        *dirpath_p = dirpath;

        /* remove trailing slash from dirpath, unless it's the root dir */
        /* ### Win32 check */
        if (dirlen > 1 && dirpath[dirlen - 1] == '/') {
            dirpath[dirlen - 1] = '\0';
        }
    }
}

/* Note: picked up from ap_gm_timestr_822() */
/* NOTE: buf must be at least DAV_TIMEBUF_SIZE chars in size */
static void dav_format_time(int style, apr_time_t sec, char *buf)
{
    ap_exploded_time_t tms;
    
    /* ### what to do if fails? */
    (void) apr_explode_gmt(&tms, sec);

    if (style == DAV_STYLE_ISO8601) {
	/* ### should we use "-00:00" instead of "Z" ?? */

	/* 20 chars plus null term */
	sprintf(buf, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ",
               tms.tm_year + 1900, tms.tm_mon + 1, tms.tm_mday,
               tms.tm_hour, tms.tm_min, tms.tm_sec);
        return;
    }

    /* RFC 822 date format; as strftime '%a, %d %b %Y %T GMT' */

    /* 29 chars plus null term */
    sprintf(buf,
	    "%s, %.2d %s %d %.2d:%.2d:%.2d GMT",
           ap_day_snames[tms.tm_wday],
           tms.tm_mday, ap_month_snames[tms.tm_mon],
           tms.tm_year + 1900,
           tms.tm_hour, tms.tm_min, tms.tm_sec);
}

static dav_error * dav_fs_copymove_file(
    int is_move,
    apr_pool_t * p,
    const char *src,
    const char *dst,
    dav_buffer *pbuf)
{
    dav_buffer work_buf = { 0 };
    apr_file_t *inf = NULL;
    apr_file_t *outf = NULL;

    if (pbuf == NULL)
	pbuf = &work_buf;

    dav_set_bufsize(p, pbuf, DAV_FS_COPY_BLOCKSIZE);

    if ((apr_open(&inf, src, APR_READ | APR_BINARY, APR_OS_DEFAULT, p)) 
	!= APR_SUCCESS) {
	/* ### use something besides 500? */
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "Could not open file for reading");
    }

    /* ### do we need to deal with the umask? */
    if ((apr_open(&outf, dst, APR_WRITE | APR_CREATE | APR_TRUNCATE | APR_BINARY,
		 APR_OS_DEFAULT, p)) != APR_SUCCESS) {
	apr_close(inf);

	/* ### use something besides 500? */
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "Could not open file for writing");
    }

    while (1) {
	apr_ssize_t len = DAV_FS_COPY_BLOCKSIZE;
	apr_status_t status;

	status = apr_read(inf, pbuf->buf, &len);
	if (status != APR_SUCCESS && status != APR_EOF) {
	    apr_close(inf);
	    apr_close(outf);
	    
	    if (apr_remove_file(dst, p) != APR_SUCCESS) {
		/* ### ACK! Inconsistent state... */

		/* ### use something besides 500? */
		return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				     "Could not delete output after read "
				     "failure. Server is now in an "
				     "inconsistent state.");
	    }

	    /* ### use something besides 500? */
	    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Could not read input file");
	}

        /* write any bytes that were read (applies to APR_EOF, too) */
        if (apr_full_write(outf, pbuf->buf, len, NULL) != APR_SUCCESS) {
            int save_errno = errno;

	    apr_close(inf);
	    apr_close(outf);

	    if (remove(dst) != 0) {
		/* ### ACK! Inconsistent state... */

		/* ### use something besides 500? */
		return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				     "Could not delete output after write "
				     "failure. Server is now in an "
				     "inconsistent state.");
	    }

	    if (save_errno == ENOSPC) {
		return dav_new_error(p, HTTP_INSUFFICIENT_STORAGE, 0,
				     "There is not enough storage to write to "
				     "this resource.");
	    }

	    /* ### use something besides 500? */
	    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Could not write output file");
	}

        if (status == APR_EOF)
            break;
    }

    apr_close(inf);
    apr_close(outf);

    if (is_move && remove(src) != 0) {
	dav_error *err;
	int save_errno = errno;	/* save the errno that got us here */

	if (remove(dst) != 0) {
	    /* ### ACK. this creates an inconsistency. do more!? */

	    /* ### use something besides 500? */
	    /* Note that we use the latest errno */
	    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Could not remove source or destination "
				 "file. Server is now in an inconsistent "
				 "state.");
	}

	/* ### use something besides 500? */
	err = dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			    "Could not remove source file after move. "
			    "Destination was removed to ensure consistency.");
	err->save_errno = save_errno;
	return err;
    }

    return NULL;
}

/* copy/move a file from within a state dir to another state dir */
/* ### need more buffers to replace the pool argument */
static dav_error * dav_fs_copymove_state(
    int is_move,
    apr_pool_t * p,
    const char *src_dir, const char *src_file,
    const char *dst_dir, const char *dst_file,
    dav_buffer *pbuf)
{
    apr_finfo_t src_finfo;	/* finfo for source file */
    apr_finfo_t dst_state_finfo;	/* finfo for STATE directory */
    const char *src;
    const char *dst;

    /* build the propset pathname for the source file */
    src = apr_pstrcat(p, src_dir, "/" DAV_FS_STATE_DIR "/", src_file, NULL);

    /* the source file doesn't exist */
    if (apr_stat(&src_finfo, src, p) != 0) {
	return NULL;
    }

    /* build the pathname for the destination state dir */
    dst = apr_pstrcat(p, dst_dir, "/" DAV_FS_STATE_DIR, NULL);

    /* ### do we need to deal with the umask? */

    /* ensure that it exists */
    if (apr_make_dir(dst, APR_OS_DEFAULT, p) != 0) {
	if (errno != EEXIST) {
	    /* ### use something besides 500? */
	    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Could not create internal state directory");
	}
    }

    /* get info about the state directory */
    if (apr_stat(&dst_state_finfo, dst, p) != 0) {
	/* Ack! Where'd it go? */
	/* ### use something besides 500? */
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "State directory disappeared");
    }

    /* The mkdir() may have failed because a *file* exists there already */
    if (dst_state_finfo.filetype != APR_DIR) {
	/* ### try to recover by deleting this file? (and mkdir again) */
	/* ### use something besides 500? */
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "State directory is actually a file");
    }

    /* append the target file to the state directory pathname */
    dst = apr_pstrcat(p, dst, "/", dst_file, NULL);

    /* copy/move the file now */
    if (is_move && src_finfo.device == dst_state_finfo.device) {
	/* simple rename is possible since it is on the same device */
	if (apr_rename_file(src, dst, p) != APR_SUCCESS) {
	    /* ### use something besides 500? */
	    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Could not move state file.");
	}
    }
    else
    {
	/* gotta copy (and delete) */
	return dav_fs_copymove_file(is_move, p, src, dst, pbuf);
    }

    return NULL;
}

static dav_error *dav_fs_copymoveset(int is_move, apr_pool_t *p,
				     const dav_resource *src,
				     const dav_resource *dst,
				     dav_buffer *pbuf)
{
    const char *src_dir;
    const char *src_file;
    const char *src_state1;
    const char *src_state2;
    const char *dst_dir;
    const char *dst_file;
    const char *dst_state1;
    const char *dst_state2;
    dav_error *err;

    /* Get directory and filename for resources */
    dav_fs_dir_file_name(src, &src_dir, &src_file);
    dav_fs_dir_file_name(dst, &dst_dir, &dst_file);

    /* Get the corresponding state files for each resource */
    dav_dbm_get_statefiles(p, src_file, &src_state1, &src_state2);
    dav_dbm_get_statefiles(p, dst_file, &dst_state1, &dst_state2);
#if DAV_DEBUG
    if ((src_state2 != NULL && dst_state2 == NULL) ||
	(src_state2 == NULL && dst_state2 != NULL)) {
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "DESIGN ERROR: dav_dbm_get_statefiles() "
			     "returned inconsistent results.");
    }
#endif

    err = dav_fs_copymove_state(is_move, p,
				src_dir, src_state1,
				dst_dir, dst_state1,
				pbuf);

    if (err == NULL && src_state2 != NULL) {
	err = dav_fs_copymove_state(is_move, p,
				    src_dir, src_state2,
				    dst_dir, dst_state2,
				    pbuf);

	if (err != NULL) {
	    /* ### CRAP. inconsistency. */
	    /* ### should perform some cleanup at the target if we still
	       ### have the original files */

	    /* Change the error to reflect the bad server state. */
	    err->status = HTTP_INTERNAL_SERVER_ERROR;
	    err->desc =
		"Could not fully copy/move the properties. "
		"The server is now in an inconsistent state.";
	}
    }

    return err;
}

static dav_error *dav_fs_deleteset(apr_pool_t *p, const dav_resource *resource)
{
    const char *dirpath;
    const char *fname;
    const char *state1;
    const char *state2;
    const char *pathname;

    /* Get directory, filename, and state-file names for the resource */
    dav_fs_dir_file_name(resource, &dirpath, &fname);
    dav_dbm_get_statefiles(p, fname, &state1, &state2);

    /* build the propset pathname for the file */
    pathname = apr_pstrcat(p,
			  dirpath,
			  "/" DAV_FS_STATE_DIR "/",
			  state1,
			  NULL);

    /* note: we may get ENOENT if the state dir is not present */
    if (remove(pathname) != 0 && errno != ENOENT) {
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "Could not remove properties.");
    }

    if (state2 != NULL) {
	/* build the propset pathname for the file */
	pathname = apr_pstrcat(p,
			      dirpath,
			      "/" DAV_FS_STATE_DIR "/",
			      state2,
			      NULL);

	if (remove(pathname) != 0 && errno != ENOENT) {
	    /* ### CRAP. only removed half. */
	    return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "Could not fully remove properties. "
				 "The server is now in an inconsistent "
				 "state.");
	}
    }

    return NULL;
}

/* --------------------------------------------------------------------
**
** REPOSITORY HOOK FUNCTIONS
*/

static dav_resource * dav_fs_get_resource(
    request_rec *r,
    const char *root_dir,
    const char *workspace)
{
    dav_resource_private *ctx;
    dav_resource *resource;
    char *s;
    char *filename;
    size_t len;

    /* ### optimize this into a single allocation! */

    /* Create private resource context descriptor */
    ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->pool = r->pool;
    ctx->finfo = r->finfo;

    /* Preserve case on OSes which fold canonical filenames */
#if 0
    /* ### not available in Apache 2.0 yet */
    filename = r->case_preserved_filename;
#else
    filename = r->filename;
#endif

    /*
    ** If there is anything in the path_info, then this indicates that the
    ** entire path was not used to specify the file/dir. We want to append
    ** it onto the filename so that we get a "valid" pathname for null
    ** resources.
    */
    s = apr_pstrcat(r->pool, filename, r->path_info, NULL);

    /* make sure the pathname does not have a trailing "/" */
    len = strlen(s);
    if (len > 1 && s[len - 1] == '/') {
	s[len - 1] = '\0';
    }
    ctx->pathname = s;

    /* Create resource descriptor */
    resource = apr_pcalloc(r->pool, sizeof(*resource));
    resource->type = DAV_RESOURCE_TYPE_REGULAR;
    resource->info = ctx;
    resource->hooks = &dav_hooks_repository_fs;

    /* make sure the URI does not have a trailing "/" */
    len = strlen(r->uri);
    if (len > 1 && r->uri[len - 1] == '/') {
	s = apr_pstrdup(r->pool, r->uri);
	s[len - 1] = '\0';
	resource->uri = s;
    }
    else {
	resource->uri = r->uri;
    }

    if (r->finfo.protection != 0) {
        resource->exists = 1;
        resource->collection = r->finfo.filetype == APR_DIR;

	/* unused info in the URL will indicate a null resource */

	if (r->path_info != NULL && *r->path_info != '\0') {
	    if (resource->collection) {
		/* only a trailing "/" is allowed */
		if (*r->path_info != '/' || r->path_info[1] != '\0') {

		    /*
		    ** This URL/filename represents a locknull resource or
		    ** possibly a destination of a MOVE/COPY
		    */
		    resource->exists = 0;
		    resource->collection = 0;
		}
	    }
	    else
	    {
		/*
		** The base of the path refers to a file -- nothing should
		** be in path_info. The resource is simply an error: it
		** can't be a null or a locknull resource.
		*/
		return NULL;	/* becomes HTTP_NOT_FOUND */
	    }

	    /* retain proper integrity across the structures */
	    if (!resource->exists) {
		ctx->finfo.protection = 0;
	    }
	}
    }

    return resource;
}

static dav_resource * dav_fs_get_parent_resource(const dav_resource *resource)
{
    dav_resource_private *ctx = resource->info;
    dav_resource_private *parent_ctx;
    dav_resource *parent_resource;
    char *dirpath;

    /* If given resource is root, then there is no parent */
    if (strcmp(resource->uri, "/") == 0 ||
#ifdef WIN32
        (strlen(ctx->pathname) == 3 && ctx->pathname[1] == ':' && ctx->pathname[2] == '/')
#else
        strcmp(ctx->pathname, "/") == 0
#endif
	)
        return NULL;

    /* ### optimize this into a single allocation! */

    /* Create private resource context descriptor */
    parent_ctx = apr_pcalloc(ctx->pool, sizeof(*parent_ctx));
    parent_ctx->pool = ctx->pool;

    dirpath = ap_make_dirstr_parent(ctx->pool, ctx->pathname);
    if (strlen(dirpath) > 1 && dirpath[strlen(dirpath) - 1] == '/') 
        dirpath[strlen(dirpath) - 1] = '\0';
    parent_ctx->pathname = dirpath;

    parent_resource = apr_pcalloc(ctx->pool, sizeof(*parent_resource));
    parent_resource->info = parent_ctx;
    parent_resource->collection = 1;
    parent_resource->hooks = &dav_hooks_repository_fs;

    if (resource->uri != NULL) {
        char *uri = ap_make_dirstr_parent(ctx->pool, resource->uri);
        if (strlen(uri) > 1 && uri[strlen(uri) - 1] == '/')
            uri[strlen(uri) - 1] = '\0';
	parent_resource->uri = uri;
    }

    if (apr_stat(&parent_ctx->finfo, parent_ctx->pathname, ctx->pool) == 0) {
        parent_resource->exists = 1;
    }

    return parent_resource;
}

static int dav_fs_is_same_resource(
    const dav_resource *res1,
    const dav_resource *res2)
{
    dav_resource_private *ctx1 = res1->info;
    dav_resource_private *ctx2 = res2->info;

    if (res1->hooks != res2->hooks)
	return 0;

#ifdef WIN32
    return stricmp(ctx1->pathname, ctx2->pathname) == 0;
#else
    if (ctx1->finfo.protection != 0)
        return ctx1->finfo.inode == ctx2->finfo.inode;
    else
        return strcmp(ctx1->pathname, ctx2->pathname) == 0;
#endif
}

static int dav_fs_is_parent_resource(
    const dav_resource *res1,
    const dav_resource *res2)
{
    dav_resource_private *ctx1 = res1->info;
    dav_resource_private *ctx2 = res2->info;
    size_t len1 = strlen(ctx1->pathname);
    size_t len2;

    if (res1->hooks != res2->hooks)
	return 0;

    /* it is safe to use ctx2 now */
    len2 = strlen(ctx2->pathname);

    return (len2 > len1
            && memcmp(ctx1->pathname, ctx2->pathname, len1) == 0
            && ctx2->pathname[len1] == '/');
}

static dav_error * dav_fs_open_stream(const dav_resource *resource,
				      dav_stream_mode mode,
				      dav_stream **stream)
{
    apr_pool_t *p = resource->info->pool;
    dav_stream *ds = apr_pcalloc(p, sizeof(*ds));
    apr_int32_t flags;

    switch (mode) {
    case DAV_MODE_READ:
    case DAV_MODE_READ_SEEKABLE:
    default:
	flags = APR_READ | APR_BINARY;
	break;

    case DAV_MODE_WRITE_TRUNC:
	flags = APR_WRITE | APR_CREATE | APR_TRUNCATE | APR_BINARY;
	break;
    case DAV_MODE_WRITE_SEEKABLE:
	flags = APR_WRITE | APR_CREATE | APR_BINARY;
	break;
    }

    ds->p = p;
    ds->pathname = resource->info->pathname;
    if (apr_open(&ds->f, ds->pathname, flags, APR_OS_DEFAULT, 
		ds->p) != APR_SUCCESS) {
	/* ### use something besides 500? */
	return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "An error occurred while opening a resource.");
    }

    /* (APR registers cleanups for the fd with the pool) */

    *stream = ds;
    return NULL;
}

static dav_error * dav_fs_close_stream(dav_stream *stream, int commit)
{
    apr_close(stream->f);

    if (!commit) {
	if (apr_remove_file(stream->pathname, stream->p) != 0) {
	    /* ### use a better description? */
            return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, 0,
				 "There was a problem removing (rolling "
				 "back) the resource "
				 "when it was being closed.");
	}
    }

    return NULL;
}

static dav_error * dav_fs_read_stream(dav_stream *stream,
				      void *buf, apr_size_t *bufsize)
{
    if (apr_read(stream->f, buf, (apr_ssize_t *)bufsize) != APR_SUCCESS) {
	/* ### use something besides 500? */
	return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "An error occurred while reading from a "
			     "resource.");
    }
    return NULL;
}

static dav_error * dav_fs_write_stream(dav_stream *stream,
				       const void *buf, apr_size_t bufsize)
{
    apr_status_t status;

    status = apr_full_write(stream->f, buf, bufsize, NULL);
    if (status == APR_ENOSPC) {
        return dav_new_error(stream->p, HTTP_INSUFFICIENT_STORAGE, 0,
                             "There is not enough storage to write to "
                             "this resource.");
    }
    else if (status != APR_SUCCESS) {
	/* ### use something besides 500? */
	return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "An error occurred while writing to a "
			     "resource.");
    }
    return NULL;
}

static dav_error * dav_fs_seek_stream(dav_stream *stream, apr_off_t abs_pos)
{
    if (apr_seek(stream->f, APR_SET, &abs_pos) != APR_SUCCESS) {
	/* ### should check whether apr_seek set abs_pos was set to the
	 * correct position? */
	/* ### use something besides 500? */
	return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "Could not seek to specified position in the "
			     "resource.");
    }
    return NULL;
}

static dav_error * dav_fs_set_headers(request_rec *r,
				      const dav_resource *resource)
{
    /* ### this function isn't really used since we have a get_pathname */
#if DEBUG_GET_HANDLER
    if (!resource->exists)
	return NULL;

    /* make sure the proper mtime is in the request record */
    ap_update_mtime(r, resource->info->finfo.mtime);

    /* ### note that these use r->filename rather than <resource> */
    ap_set_last_modified(r);
    ap_set_etag(r);

    /* we accept byte-ranges */
    apr_table_setn(r->headers_out, "Accept-Ranges", "bytes");

    /* set up the Content-Length header */
    ap_set_content_length(r, resource->info->finfo.size);

    /* ### how to set the content type? */
    /* ### until this is resolved, the Content-Type header is busted */

#endif

    return NULL;
}

#if DEBUG_PATHNAME_STYLE
static const char * dav_fs_get_pathname(
    const dav_resource *resource,
    void **free_handle_p)
{
    return resource->info->pathname;
}
#endif

static void dav_fs_free_file(void *free_handle)
{
    /* nothing to free ... */
}

static dav_error * dav_fs_create_collection(apr_pool_t *p, dav_resource *resource)
{
    dav_resource_private *ctx = resource->info;
    apr_status_t status;

    status = apr_make_dir(ctx->pathname, APR_OS_DEFAULT, p);
    if (status == ENOSPC) {
	return dav_new_error(p, HTTP_INSUFFICIENT_STORAGE, 0,
			     "There is not enough storage to create "
			     "this collection.");
    }
    else if (status != APR_SUCCESS) {
	/* ### refine this error message? */
	return dav_new_error(p, HTTP_FORBIDDEN, 0,
                             "Unable to create collection.");
    }

    /* update resource state to show it exists as a collection */
    resource->exists = 1;
    resource->collection = 1;

    return NULL;
}

static dav_error * dav_fs_copymove_walker(dav_walker_ctx *ctx, int calltype)
{
    dav_resource_private *srcinfo = ctx->resource->info;
    dav_resource_private *dstinfo = ctx->res2->info;
    dav_error *err = NULL;

    if (ctx->resource->collection) {
	if (calltype == DAV_CALLTYPE_POSTFIX) {
	    /* Postfix call for MOVE. delete the source dir.
	     * Note: when copying, we do not enable the postfix-traversal.
	     */
	    /* ### we are ignoring any error here; what should we do? */
	    (void) rmdir(srcinfo->pathname);
	}
        else {
	    /* copy/move of a collection. Create the new, target collection */
            if (apr_make_dir(dstinfo->pathname, APR_OS_DEFAULT, ctx->pool) 
		!= APR_SUCCESS) {
		/* ### assume it was a permissions problem */
		/* ### need a description here */
                err = dav_new_error(ctx->pool, HTTP_FORBIDDEN, 0, NULL);
            }
	}
    }
    else {
	err = dav_fs_copymove_file(ctx->is_move, ctx->pool, 
				   srcinfo->pathname, dstinfo->pathname, 
				   &ctx->work_buf);
	/* ### push a higher-level description? */
    }

    /*
    ** If we have a "not so bad" error, then it might need to go into a
    ** multistatus response.
    **
    ** For a MOVE, it will always go into the multistatus. It could be
    ** that everything has been moved *except* for the root. Using a
    ** multistatus (with no errors for the other resources) will signify
    ** this condition.
    **
    ** For a COPY, we are traversing in a prefix fashion. If the root fails,
    ** then we can just bail out now.
    */
    if (err != NULL
        && !ap_is_HTTP_SERVER_ERROR(err->status)
	&& (ctx->is_move
            || !dav_fs_is_same_resource(ctx->resource, ctx->root))) {
	/* ### use errno to generate DAV:responsedescription? */
	dav_add_response(ctx, ctx->resource->uri, err->status, NULL);

        /* the error is in the multistatus now. do not stop the traversal. */
        return NULL;
    }

    return err;
}

static dav_error *dav_fs_copymove_resource(
    int is_move,
    const dav_resource *src,
    const dav_resource *dst,
    int depth,
    dav_response **response)
{
    dav_error *err = NULL;
    dav_buffer work_buf = { 0 };

    *response = NULL;

    /* if a collection, recursively copy/move it and its children,
     * including the state dirs
     */
    if (src->collection) {
	dav_walker_ctx ctx = { 0 };

	ctx.walk_type = DAV_WALKTYPE_ALL | DAV_WALKTYPE_HIDDEN;
	ctx.func = dav_fs_copymove_walker;
	ctx.pool = src->info->pool;
	ctx.resource = src;
	ctx.res2 = dst;
	ctx.is_move = is_move;
	ctx.postfix = is_move;	/* needed for MOVE to delete source dirs */

	/* copy over the source URI */
	dav_buffer_init(ctx.pool, &ctx.uri, src->uri);

	if ((err = dav_fs_walk(&ctx, depth)) != NULL) {
            /* on a "real" error, then just punt. nothing else to do. */
            return err;
        }

        if ((*response = ctx.response) != NULL) {
            /* some multistatus responses exist. wrap them in a 207 */
            return dav_new_error(src->info->pool, HTTP_MULTI_STATUS, 0,
                                 "Error(s) occurred on some resources during "
                                 "the COPY/MOVE process.");
        }

	return NULL;
    }

    /* not a collection */
    if ((err = dav_fs_copymove_file(is_move, src->info->pool,
				    src->info->pathname, dst->info->pathname,
				    &work_buf)) != NULL) {
	/* ### push a higher-level description? */
	return err;
    }
	
    /* copy/move properties as well */
    return dav_fs_copymoveset(is_move, src->info->pool, src, dst, &work_buf);
}

static dav_error * dav_fs_copy_resource(
    const dav_resource *src,
    dav_resource *dst,
    int depth,
    dav_response **response)
{
    dav_error *err;

#if DAV_DEBUG
    if (src->hooks != dst->hooks) {
	/*
	** ### strictly speaking, this is a design error; we should not
	** ### have reached this point.
	*/
	return dav_new_error(src->info->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "DESIGN ERROR: a mix of repositories "
			     "was passed to copy_resource.");
    }
#endif

    if ((err = dav_fs_copymove_resource(0, src, dst, depth,
					response)) == NULL) {

        /* update state of destination resource to show it exists */
        dst->exists = 1;
        dst->collection = src->collection;
    }

    return err;
}

static dav_error * dav_fs_move_resource(
    dav_resource *src,
    dav_resource *dst,
    dav_response **response)
{
    dav_resource_private *srcinfo = src->info;
    dav_resource_private *dstinfo = dst->info;
    dav_error *err;
    int can_rename = 0;

#if DAV_DEBUG
    if (src->hooks != dst->hooks) {
	/*
	** ### strictly speaking, this is a design error; we should not
	** ### have reached this point.
	*/
	return dav_new_error(src->info->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "DESIGN ERROR: a mix of repositories "
			     "was passed to move_resource.");
    }
#endif

    /* determine whether a simple rename will work.
     * Assume source exists, else we wouldn't get called.
     */
    if (dstinfo->finfo.protection != 0) {
	if (dstinfo->finfo.device == srcinfo->finfo.device) {
	    /* target exists and is on the same device. */
	    can_rename = 1;
	}
    }
    else {
	const char *dirpath;
	apr_finfo_t finfo;

	/* destination does not exist, but the parent directory should,
	 * so try it
	 */
	dirpath = ap_make_dirstr_parent(dstinfo->pool, dstinfo->pathname);
	if (apr_stat(&finfo, dirpath, dstinfo->pool) == 0
	    && finfo.device == srcinfo->finfo.device) {
	    can_rename = 1;
	}
    }

    /* if we can't simply rename, then do it the hard way... */
    if (!can_rename) {
        if ((err = dav_fs_copymove_resource(1, src, dst, DAV_INFINITY,
                                            response)) == NULL) {
            /* update resource states */
            dst->exists = 1;
            dst->collection = src->collection;
            src->exists = 0;
            src->collection = 0;
        }

        return err;
    }

    /* a rename should work. do it, and move properties as well */

    /* no multistatus response */
    *response = NULL;

    /* ### APR has no rename? */
    if (apr_rename_file(srcinfo->pathname, dstinfo->pathname,
                       srcinfo->pool) != APR_SUCCESS) {
	/* ### should have a better error than this. */
	return dav_new_error(srcinfo->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "Could not rename resource.");
    }

    /* update resource states */
    dst->exists = 1;
    dst->collection = src->collection;
    src->exists = 0;
    src->collection = 0;

    if ((err = dav_fs_copymoveset(1, src->info->pool,
				  src, dst, NULL)) == NULL) {
	/* no error. we're done. go ahead and return now. */
	return NULL;
    }

    /* error occurred during properties move; try to put resource back */
    if (apr_rename_file(dstinfo->pathname, srcinfo->pathname,
                       srcinfo->pool) != APR_SUCCESS) {
	/* couldn't put it back! */
	return dav_push_error(srcinfo->pool,
			      HTTP_INTERNAL_SERVER_ERROR, 0,
			      "The resource was moved, but a failure "
			      "occurred during the move of its "
			      "properties. The resource could not be "
			      "restored to its original location. The "
			      "server is now in an inconsistent state.",
			      err);
    }

    /* update resource states again */
    src->exists = 1;
    src->collection = dst->collection;
    dst->exists = 0;
    dst->collection = 0;

    /* resource moved back, but properties may be inconsistent */
    return dav_push_error(srcinfo->pool,
			  HTTP_INTERNAL_SERVER_ERROR, 0,
			  "The resource was moved, but a failure "
			  "occurred during the move of its properties. "
			  "The resource was moved back to its original "
			  "location, but its properties may have been "
			  "partially moved. The server may be in an "
			  "inconsistent state.",
			  err);
}

static dav_error * dav_fs_delete_walker(dav_walker_ctx *ctx, int calltype)
{
    dav_resource_private *info = ctx->resource->info;

    /* do not attempt to remove a null resource,
     * or a collection with children
     */
    if (ctx->resource->exists &&
        (!ctx->resource->collection || calltype == DAV_CALLTYPE_POSTFIX)) {
	/* try to remove the resource */
	int result;

	result = ctx->resource->collection
	    ? rmdir(info->pathname)
	    : remove(info->pathname);

	/*
        ** If an error occurred, then add it to multistatus response.
        ** Note that we add it for the root resource, too. It is quite
        ** possible to delete the whole darn tree, yet fail on the root.
        **
        ** (also: remember we are deleting via a postfix traversal)
        */
	if (result != 0) {
            /* ### assume there is a permissions problem */

            /* ### use errno to generate DAV:responsedescription? */
            dav_add_response(ctx, ctx->resource->uri, HTTP_FORBIDDEN, NULL);
	}
    }

    return NULL;
}

static dav_error * dav_fs_remove_resource(dav_resource *resource,
                                          dav_response **response)
{
    dav_resource_private *info = resource->info;

    *response = NULL;

    /* if a collection, recursively remove it and its children,
     * including the state dirs
     */
    if (resource->collection) {
	dav_walker_ctx ctx = { 0 };
	dav_error *err = NULL;

	ctx.walk_type = DAV_WALKTYPE_ALL | DAV_WALKTYPE_HIDDEN;
	ctx.postfix = 1;
	ctx.func = dav_fs_delete_walker;
	ctx.pool = info->pool;
	ctx.resource = resource;

	dav_buffer_init(info->pool, &ctx.uri, resource->uri);

	if ((err = dav_fs_walk(&ctx, DAV_INFINITY)) != NULL) {
            /* on a "real" error, then just punt. nothing else to do. */
            return err;
        }

        if ((*response = ctx.response) != NULL) {
            /* some multistatus responses exist. wrap them in a 207 */
            return dav_new_error(info->pool, HTTP_MULTI_STATUS, 0,
                                 "Error(s) occurred on some resources during "
                                 "the deletion process.");
        }

        /* no errors... update resource state */
        resource->exists = 0;
        resource->collection = 0;

	return NULL;
    }

    /* not a collection; remove the file and its properties */
    if (remove(info->pathname) != 0) {
	/* ### put a description in here */
	return dav_new_error(info->pool, HTTP_FORBIDDEN, 0, NULL);
    }

    /* update resource state */
    resource->exists = 0;
    resource->collection = 0;

    /* remove properties and return its result */
    return dav_fs_deleteset(info->pool, resource);
}

/* ### move this to dav_util? */
/* Walk recursively down through directories, *
 * including lock-null resources as we go.    */
static dav_error * dav_fs_walker(dav_fs_walker_context *fsctx, int depth)
{
    dav_error *err = NULL;
    dav_walker_ctx *wctx = fsctx->wctx;
    int isdir = wctx->resource->collection;
    apr_dir_t *dirp;

    /* ensure the context is prepared properly, then call the func */
    err = (*wctx->func)(wctx,
			isdir
			? DAV_CALLTYPE_COLLECTION
			: DAV_CALLTYPE_MEMBER);
    if (err != NULL) {
	return err;
    }

    if (depth == 0 || !isdir) {
	return NULL;
    }

    /* put a trailing slash onto the directory, in preparation for appending
     * files to it as we discovery them within the directory */
    dav_check_bufsize(wctx->pool, &fsctx->path1, DAV_BUFFER_PAD);
    fsctx->path1.buf[fsctx->path1.cur_len++] = '/';
    fsctx->path1.buf[fsctx->path1.cur_len] = '\0';	/* in pad area */

    /* if a secondary path is present, then do that, too */
    if (fsctx->path2.buf != NULL) {
	dav_check_bufsize(wctx->pool, &fsctx->path2, DAV_BUFFER_PAD);
	fsctx->path2.buf[fsctx->path2.cur_len++] = '/';
	fsctx->path2.buf[fsctx->path2.cur_len] = '\0';	/* in pad area */
    }

    /* Note: the URI should ALREADY have a trailing "/" */

    /* for this first pass of files, all resources exist */
    fsctx->res1.exists = 1;

    /* a file is the default; we'll adjust if we hit a directory */
    fsctx->res1.collection = 0;
    fsctx->res2.collection = 0;

    /* open and scan the directory */
    if ((apr_opendir(&dirp, fsctx->path1.buf, wctx->pool)) != APR_SUCCESS) {
	/* ### need a better error */
	return dav_new_error(wctx->pool, HTTP_NOT_FOUND, 0, NULL);
    }
    while ((apr_readdir(dirp)) == APR_SUCCESS) {
	char *name;
	size_t len;

	apr_get_dir_filename(&name, dirp);
	len = strlen(name);

	/* avoid recursing into our current, parent, or state directories */
	if (name[0] == '.' && (len == 1 || (name[1] == '.' && len == 2))) {
	    continue;
	}

	if (wctx->walk_type & DAV_WALKTYPE_AUTH) {
	    /* ### need to authorize each file */
	    /* ### example: .htaccess is normally configured to fail auth */

	    /* stuff in the state directory is never authorized! */
	    if (!strcmp(name, DAV_FS_STATE_DIR)) {
		continue;
	    }
	}
	/* skip the state dir unless a HIDDEN is performed */
	if (!(wctx->walk_type & DAV_WALKTYPE_HIDDEN)
	    && !strcmp(name, DAV_FS_STATE_DIR)) {
	    continue;
	}

	/* append this file onto the path buffer (copy null term) */
	dav_buffer_place_mem(wctx->pool, &fsctx->path1, name, len + 1, 0);

	if (apr_lstat(&fsctx->info1.finfo, fsctx->path1.buf, wctx->pool) != 0) {
	    /* woah! where'd it go? */
	    /* ### should have a better error here */
	    err = dav_new_error(wctx->pool, HTTP_NOT_FOUND, 0, NULL);
	    break;
	}

	/* copy the file to the URI, too. NOTE: we will pad an extra byte
	   for the trailing slash later. */
	dav_buffer_place_mem(wctx->pool, &wctx->uri, name, len + 1, 1);

	/* if there is a secondary path, then do that, too */
	if (fsctx->path2.buf != NULL) {
	    dav_buffer_place_mem(wctx->pool, &fsctx->path2, name, len + 1, 0);
	}

	/* set up the (internal) pathnames for the two resources */
	fsctx->info1.pathname = fsctx->path1.buf;
	fsctx->info2.pathname = fsctx->path2.buf;

	/* set up the URI for the current resource */
	fsctx->res1.uri = wctx->uri.buf;

	/* ### for now, only process regular files (e.g. skip symlinks) */
	if (fsctx->info1.finfo.filetype == APR_REG) {
	    /* call the function for the specified dir + file */
	    if ((err = (*wctx->func)(wctx, DAV_CALLTYPE_MEMBER)) != NULL) {
		/* ### maybe add a higher-level description? */
		break;
	    }
	}
	else if (fsctx->info1.finfo.filetype == APR_DIR) {
	    size_t save_path_len = fsctx->path1.cur_len;
	    size_t save_uri_len = wctx->uri.cur_len;
	    size_t save_path2_len = fsctx->path2.cur_len;

	    /* adjust length to incorporate the subdir name */
	    fsctx->path1.cur_len += len;
	    fsctx->path2.cur_len += len;

	    /* adjust URI length to incorporate subdir and a slash */
	    wctx->uri.cur_len += len + 1;
	    wctx->uri.buf[wctx->uri.cur_len - 1] = '/';
	    wctx->uri.buf[wctx->uri.cur_len] = '\0';

	    /* switch over to a collection */
	    fsctx->res1.collection = 1;
	    fsctx->res2.collection = 1;

	    /* recurse on the subdir */
	    /* ### don't always want to quit on error from single child */
	    if ((err = dav_fs_walker(fsctx, depth - 1)) != NULL) {
		/* ### maybe add a higher-level description? */
		break;
	    }

	    /* put the various information back */
	    fsctx->path1.cur_len = save_path_len;
	    fsctx->path2.cur_len = save_path2_len;
	    wctx->uri.cur_len = save_uri_len;

	    fsctx->res1.collection = 0;
	    fsctx->res2.collection = 0;

	    /* assert: res1.exists == 1 */
	}
    }

    /* ### check the return value of this? */
    apr_closedir(dirp);

    if (err != NULL)
	return err;

    if (wctx->walk_type & DAV_WALKTYPE_LOCKNULL) {
	size_t offset = 0;

	/* null terminate the directory name */
	fsctx->path1.buf[fsctx->path1.cur_len - 1] = '\0';

	/* Include any lock null resources found in this collection */
	fsctx->res1.collection = 1;
	if ((err = dav_fs_get_locknull_members(&fsctx->res1,
                                               &fsctx->locknull_buf)) != NULL) {
            /* ### maybe add a higher-level description? */
            return err;
	}

	/* put a slash back on the end of the directory */
	fsctx->path1.buf[fsctx->path1.cur_len - 1] = '/';

	/* these are all non-existant (files) */
	fsctx->res1.exists = 0;
	fsctx->res1.collection = 0;
	memset(&fsctx->info1.finfo, 0, sizeof(fsctx->info1.finfo));

	while (offset < fsctx->locknull_buf.cur_len) {
	    size_t len = strlen(fsctx->locknull_buf.buf + offset);
	    dav_lock *locks = NULL;

	    /*
	    ** Append the locknull file to the paths and the URI. Note that
	    ** we don't have to pad the URI for a slash since a locknull
	    ** resource is not a collection.
	    */
	    dav_buffer_place_mem(wctx->pool, &fsctx->path1,
				 fsctx->locknull_buf.buf + offset, len + 1, 0);
	    dav_buffer_place_mem(wctx->pool, &wctx->uri,
				 fsctx->locknull_buf.buf + offset, len + 1, 0);
	    if (fsctx->path2.buf != NULL) {
		dav_buffer_place_mem(wctx->pool, &fsctx->path2,
				     fsctx->locknull_buf.buf + offset,
                                     len + 1, 0);
	    }

	    /* set up the (internal) pathnames for the two resources */
	    fsctx->info1.pathname = fsctx->path1.buf;
	    fsctx->info2.pathname = fsctx->path2.buf;

	    /* set up the URI for the current resource */
	    fsctx->res1.uri = wctx->uri.buf;

	    /*
	    ** To prevent a PROPFIND showing an expired locknull
	    ** resource, query the lock database to force removal
	    ** of both the lock entry and .locknull, if necessary..
	    ** Sure, the query in PROPFIND would do this.. after
	    ** the locknull resource was already included in the 
	    ** return.
	    **
	    ** NOTE: we assume the caller has opened the lock database
	    **       if they have provided DAV_WALKTYPE_LOCKNULL.
	    */
	    /* ### we should also look into opening it read-only and
	       ### eliding timed-out items from the walk, yet leaving
	       ### them in the locknull database until somebody opens
	       ### the thing writable.
	       */
	    /* ### probably ought to use has_locks. note the problem
	       ### mentioned above, though... we would traverse this as
	       ### a locknull, but then a PROPFIND would load the lock
	       ### info, causing a timeout and the locks would not be
	       ### reported. Therefore, a null resource would be returned
	       ### in the PROPFIND.
	       ###
	       ### alternative: just load unresolved locks. any direct
	       ### locks will be timed out (correct). any indirect will
	       ### not (correct; consider if a parent timed out -- the
	       ### timeout routines do not walk and remove indirects;
	       ### even the resolve func would probably fail when it
	       ### tried to find a timed-out direct lock).
	    */
	    if ((err = dav_lock_query(wctx->lockdb, wctx->resource, &locks)) != NULL) {
		/* ### maybe add a higher-level description? */
		return err;
	    }

	    /* call the function for the specified dir + file */
	    if (locks != NULL &&
		(err = (*wctx->func)(wctx, DAV_CALLTYPE_LOCKNULL)) != NULL) {
		/* ### maybe add a higher-level description? */
		return err;
	    }

	    offset += len + 1;
	}

	/* reset the exists flag */
	fsctx->res1.exists = 1;
    }

    if (wctx->postfix) {
	/* replace the dirs' trailing slashes with null terms */
	fsctx->path1.buf[--fsctx->path1.cur_len] = '\0';
	wctx->uri.buf[--wctx->uri.cur_len] = '\0';
	if (fsctx->path2.buf != NULL) {
	    fsctx->path2.buf[--fsctx->path2.cur_len] = '\0';
	}

	/* this is a collection which exists */
	fsctx->res1.collection = 1;

	return (*wctx->func)(wctx, DAV_CALLTYPE_POSTFIX);
    }

    return NULL;
}

static dav_error * dav_fs_walk(dav_walker_ctx *wctx, int depth)
{
    dav_fs_walker_context fsctx = { 0 };

#if DAV_DEBUG
    if ((wctx->walk_type & DAV_WALKTYPE_LOCKNULL) != 0
	&& wctx->lockdb == NULL) {
	return dav_new_error(wctx->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "DESIGN ERROR: walker called to walk locknull "
			     "resources, but a lockdb was not provided.");
    }

    /* ### an assertion that we have space for a trailing slash */
    if (wctx->uri.cur_len + 1 > wctx->uri.alloc_len) {
	return dav_new_error(wctx->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     "DESIGN ERROR: walker should have been called "
			     "with padding in the URI buffer.");
    }
#endif

    fsctx.wctx = wctx;

    wctx->root = wctx->resource;

    /* ### zero out versioned, working, baselined? */

    fsctx.res1 = *wctx->resource;

    fsctx.res1.info = &fsctx.info1;
    fsctx.info1 = *wctx->resource->info;

    dav_buffer_init(wctx->pool, &fsctx.path1, fsctx.info1.pathname);
    fsctx.info1.pathname = fsctx.path1.buf;

    if (wctx->res2 != NULL) {
	fsctx.res2 = *wctx->res2;
	fsctx.res2.exists = 0;
	fsctx.res2.collection = 0;

	fsctx.res2.info = &fsctx.info2;
	fsctx.info2 = *wctx->res2->info;

	/* res2 does not exist -- clear its finfo structure */
	memset(&fsctx.info2.finfo, 0, sizeof(fsctx.info2.finfo));

	dav_buffer_init(wctx->pool, &fsctx.path2, fsctx.info2.pathname);
	fsctx.info2.pathname = fsctx.path2.buf;
    }

    /* if we have a directory, then ensure the URI has a trailing "/" */
    if (fsctx.res1.collection
	&& wctx->uri.buf[wctx->uri.cur_len - 1] != '/') {

	/* this will fall into the pad area */
	wctx->uri.buf[wctx->uri.cur_len++] = '/';
	wctx->uri.buf[wctx->uri.cur_len] = '\0';
    }

    /*
    ** URI is tracked in the walker context. Ensure that people do not try
    ** to fetch it from res2. We will ensure that res1 and uri will remain
    ** synchronized.
    */
    fsctx.res1.uri = wctx->uri.buf;
    fsctx.res2.uri = NULL;

    /* use our resource structures */
    wctx->resource = &fsctx.res1;
    wctx->res2 = &fsctx.res2;

    return dav_fs_walker(&fsctx, depth);
}

/* dav_fs_etag:  Stolen from ap_make_etag.  Creates a strong etag
 *    for file path.
 * ### do we need to return weak tags sometimes?
 */
static const char *dav_fs_getetag(const dav_resource *resource)
{
    dav_resource_private *ctx = resource->info;

    if (!resource->exists) 
	return apr_pstrdup(ctx->pool, "");

    if (ctx->finfo.protection != 0) {
        return apr_psprintf(ctx->pool, "\"%lx-%lx-%lx\"",
			   (unsigned long) ctx->finfo.inode,
			   (unsigned long) ctx->finfo.size,
			   (unsigned long) ctx->finfo.mtime);
    }

    return apr_psprintf(ctx->pool, "\"%lx\"", (unsigned long) ctx->finfo.mtime);
}

static const dav_hooks_repository dav_hooks_repository_fs =
{
    DEBUG_GET_HANDLER,   /* normally: special GET handling not required */
    dav_fs_get_resource,
    dav_fs_get_parent_resource,
    dav_fs_is_same_resource,
    dav_fs_is_parent_resource,
    dav_fs_open_stream,
    dav_fs_close_stream,
    dav_fs_read_stream,
    dav_fs_write_stream,
    dav_fs_seek_stream,
    dav_fs_set_headers,
#if DEBUG_PATHNAME_STYLE
    dav_fs_get_pathname,
#else
    0,
#endif
    dav_fs_free_file,
    dav_fs_create_collection,
    dav_fs_copy_resource,
    dav_fs_move_resource,
    dav_fs_remove_resource,
    dav_fs_walk,
    dav_fs_getetag,
};

static int dav_fs_find_prop(const char *ns_uri, const char *name)
{
    const dav_fs_liveprop_name *scan;
    int ns;

    if (*ns_uri == 'h'
	&& strcmp(ns_uri, dav_fs_namespace_uris[DAV_FS_URI_MYPROPS]) == 0) {
	ns = DAV_FS_URI_MYPROPS;
    }
    else if (*ns_uri == 'D' && strcmp(ns_uri, "DAV:") == 0) {
	ns = DAV_FS_URI_DAV;
    }
    else {
	/* we don't define this property */
	return 0;
    }

    for (scan = dav_fs_props; scan->name != NULL; ++scan)
	if (ns == scan->ns && strcmp(name, scan->name) == 0)
	    return scan->propid;

    return 0;
}

static dav_prop_insert dav_fs_insert_prop(const dav_resource *resource,
					  int propid, int insvalue,
					  ap_text_header *phdr)
{
    const char *value;
    const char *s;
    dav_prop_insert which;
    apr_pool_t *p = resource->info->pool;
    const dav_fs_liveprop_name *scan;
    int ns;

    /* an HTTP-date can be 29 chars plus a null term */
    /* a 64-bit size can be 20 chars plus a null term */
    char buf[DAV_TIMEBUF_SIZE];

    if (!DAV_PROPID_FS_OURS(propid))
	return DAV_PROP_INSERT_NOTME;

    /*
    ** None of FS provider properties are defined if the resource does not
    ** exist. Just bail for this case.
    **
    ** Note that DAV:displayname and DAV:source will be stored as dead
    ** properties; the NOTDEF return code indicates that dav_props.c should
    ** look there for the value.
    **
    ** Even though we state that the FS properties are not defined, the
    ** client cannot store dead values -- we deny that thru the is_writable
    ** hook function.
    */
    if (!resource->exists)
	return DAV_PROP_INSERT_NOTDEF;

    switch (propid) {
    case DAV_PROPID_FS_creationdate:
	/*
	** Closest thing to a creation date. since we don't actually
	** perform the operations that would modify ctime (after we
	** create the file), then we should be pretty safe here.
	*/
	dav_format_time(DAV_STYLE_ISO8601,
                        resource->info->finfo.ctime,
                        buf);
	value = buf;
	break;

    case DAV_PROPID_FS_getcontentlength:
	/* our property, but not defined on collection resources */
	if (resource->collection)
	    return DAV_PROP_INSERT_NOTDEF;

	(void) sprintf(buf, "%ld", resource->info->finfo.size);
	value = buf;
	break;

    case DAV_PROPID_FS_getetag:
	value = dav_fs_getetag(resource);
	break;

    case DAV_PROPID_FS_getlastmodified:
	dav_format_time(DAV_STYLE_RFC822,
                        resource->info->finfo.mtime,
                        buf);
	value = buf;
	break;

    case DAV_PROPID_FS_executable:
#ifdef WIN32
        /* our property, but not defined on the Win32 platform */
        return DAV_PROP_INSERT_NOTDEF;
#else
	/* our property, but not defined on collection resources */
	if (resource->collection)
	    return DAV_PROP_INSERT_NOTDEF;

	/* the files are "ours" so we only need to check owner exec privs */
	if (resource->info->finfo.protection & APR_UEXECUTE)
	    value = "T";
	else
	    value = "F";
	break;
#endif /* WIN32 */

    case DAV_PROPID_FS_displayname:
    case DAV_PROPID_FS_source:
    default:
	/*
	** This property is not defined. However, it may be a dead
	** property.
	*/
	return DAV_PROP_INSERT_NOTDEF;
    }

    /* assert: value != NULL */

    for (scan = dav_fs_props; scan->name != NULL; ++scan)
	if (scan->propid == propid)
	    break;

    /* assert: scan->name != NULL */

    /* map our namespace into a global NS index */
    ns = dav_get_liveprop_ns_index(dav_fs_namespace_uris[scan->ns]);

    /* DBG3("FS: inserting lp%d:%s  (local %d)", ns, scan->name, scan->ns); */

    if (insvalue) {
	/* use D: prefix to refer to the DAV: namespace URI */
	s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
			ns, scan->name, value, ns, scan->name);
	which = DAV_PROP_INSERT_VALUE;
    }
    else {
	/* use D: prefix to refer to the DAV: namespace URI */
	s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, ns, scan->name);
	which = DAV_PROP_INSERT_NAME;
    }
    ap_text_append(p, phdr, s);

    /* we inserted a name or value (this prop is done) */
    return which;
}

static void dav_fs_insert_all(const dav_resource *resource, int insvalue,
			      ap_text_header *phdr)
{
    if (!resource->exists) {
	/* a lock-null resource */
	/*
	** ### technically, we should insert empty properties. dunno offhand
	** ### what part of the spec said this, but it was essentially thus:
	** ### "the properties should be defined, but may have no value".
	*/
	return;
    }

    (void) dav_fs_insert_prop(resource, DAV_PROPID_FS_creationdate,
			      insvalue, phdr);
    (void) dav_fs_insert_prop(resource, DAV_PROPID_FS_getcontentlength,
			      insvalue, phdr);
    (void) dav_fs_insert_prop(resource, DAV_PROPID_FS_getlastmodified,
			      insvalue, phdr);
    (void) dav_fs_insert_prop(resource, DAV_PROPID_FS_getetag,
			      insvalue, phdr);

#ifndef WIN32
    /*
    ** Note: this property is not defined on the Win32 platform.
    **       dav_fs_insert_prop() won't insert it, but we may as
    **       well not even call it.
    */
    (void) dav_fs_insert_prop(resource, DAV_PROPID_FS_executable,
			      insvalue, phdr);
#endif

    /* ### we know the others aren't defined as liveprops */
}

static dav_prop_rw dav_fs_is_writeable(const dav_resource *resource,
				       int propid)
{
    if (!DAV_PROPID_FS_OURS(propid))
	return DAV_PROP_RW_NOTME;

    if (propid == DAV_PROPID_FS_displayname
	|| propid == DAV_PROPID_FS_source
#ifndef WIN32
        /* this property is not usable (writeable) on the Win32 platform */
	|| (propid == DAV_PROPID_FS_executable && !resource->collection)
#endif
	)
	return DAV_PROP_RW_YES;

    return DAV_PROP_RW_NO;
}

static dav_error *dav_fs_patch_validate(const dav_resource *resource,
					const ap_xml_elem *elem,
					int operation,
					void **context,
					int *defer_to_dead)
{
    const ap_text *cdata;
    const ap_text *f_cdata;
    char value;
    dav_elem_private *priv = elem->private;

    if (priv->propid != DAV_PROPID_FS_executable) {
	*defer_to_dead = 1;
	return NULL;
    }

    if (operation == DAV_PROP_OP_DELETE) {
	return dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
			     "The 'executable' property cannot be removed.");
    }

    cdata = elem->first_cdata.first;

    /* ### hmm. this isn't actually looking at all the possible text items */
    f_cdata = elem->first_child == NULL
	? NULL
	: elem->first_child->following_cdata.first;

    /* DBG3("name=%s  cdata=%s  f_cdata=%s",elem->name,cdata ? cdata->text : "[null]",f_cdata ? f_cdata->text : "[null]"); */

    if (cdata == NULL) {
	if (f_cdata == NULL) {
	    return dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
				 "The 'executable' property expects a single "
				 "character, valued 'T' or 'F'. There was no "
				 "value submitted.");
	}
	cdata = f_cdata;
    }
    else if (f_cdata != NULL)
	goto too_long;

    if (cdata->next != NULL || strlen(cdata->text) != 1)
	goto too_long;

    value = cdata->text[0];
    if (value != 'T' && value != 'F') {
	return dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
			     "The 'executable' property expects a single "
			     "character, valued 'T' or 'F'. The value "
			     "submitted is invalid.");
    }

    *context = (void *)(value == 'T');

    return NULL;

  too_long:
    return dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
			 "The 'executable' property expects a single "
			 "character, valued 'T' or 'F'. The value submitted "
			 "has too many characters.");

}

static dav_error *dav_fs_patch_exec(dav_resource *resource,
				    const ap_xml_elem *elem,
				    int operation,
				    void *context,
				    dav_liveprop_rollback **rollback_ctx)
{
    int value = context != NULL;
    apr_fileperms_t perms = resource->info->finfo.protection;
    int old_value = (perms & APR_UEXECUTE) != 0;

    /* assert: prop == executable. operation == SET. */

    /* don't do anything if there is no change. no rollback info either. */
    /* DBG2("new value=%d  (old=%d)", value, old_value); */
    if (value == old_value)
	return NULL;

    perms &= ~APR_UEXECUTE;
    if (value)
	perms |= APR_UEXECUTE;

    if (apr_setfileperms(resource->info->pathname, perms) != APR_SUCCESS) {
	return dav_new_error(resource->info->pool,
			     HTTP_INTERNAL_SERVER_ERROR, 0,
			     "Could not set the executable flag of the "
			     "target resource.");
    }

    /* update the resource and set up the rollback context */
    resource->info->finfo.protection = perms;
    *rollback_ctx = (dav_liveprop_rollback *)old_value;

    return NULL;
}

static void dav_fs_patch_commit(dav_resource *resource,
				int operation,
				void *context,
				dav_liveprop_rollback *rollback_ctx)
{
    /* nothing to do */
}

static dav_error *dav_fs_patch_rollback(dav_resource *resource,
					int operation,
					void *context,
					dav_liveprop_rollback *rollback_ctx)
{
    apr_fileperms_t perms = resource->info->finfo.protection & ~APR_UEXECUTE;
    int value = rollback_ctx != NULL;

    /* assert: prop == executable. operation == SET. */

    /* restore the executable bit */
    if (value)
	perms |= APR_UEXECUTE;

    if (apr_setfileperms(resource->info->pathname, perms) != APR_SUCCESS) {
	return dav_new_error(resource->info->pool,
			     HTTP_INTERNAL_SERVER_ERROR, 0,
			     "After a failure occurred, the resource's "
			     "executable flag could not be restored.");
    }

    /* restore the resource's state */
    resource->info->finfo.protection = perms;

    return NULL;
}


static const dav_hooks_liveprop dav_hooks_liveprop_fs =
{
#ifdef WIN32
    NULL,
#else
    "http://apache.org/dav/propset/fs/1",	/* filesystem, set 1 */
#endif
    dav_fs_find_prop,
    dav_fs_insert_prop,
    dav_fs_insert_all,
    dav_fs_is_writeable,
    dav_fs_namespace_uris,
    dav_fs_patch_validate,
    dav_fs_patch_exec,
    dav_fs_patch_commit,
    dav_fs_patch_rollback,
};


int dav_fs_hook_get_resource(request_rec *r, const char *root_dir,
                             const char *workspace)
{
    dav_resource *resource = dav_fs_get_resource(r, root_dir, workspace);

    if (resource == NULL)
        return DECLINED;

    (void) apr_set_userdata(resource, DAV_KEY_RESOURCE, apr_null_cleanup,
                           r->pool);
    return OK;
}

const dav_hooks_locks *dav_fs_get_lock_hooks(request_rec *r)
{
    return &dav_hooks_locks_fs;
}

const dav_hooks_propdb *dav_fs_get_propdb_hooks(request_rec *r)
{
    return &dav_hooks_db_dbm;
}

void dav_fs_gather_propsets(apr_array_header_t *uris)
{
#ifndef WIN32
    *(const char **)apr_push_array(uris) =
        "<http://apache.org/dav/propset/fs/1>";
#endif
}

int dav_fs_find_liveprop(request_rec *r, const char *ns_uri, const char *name,
                         const dav_hooks_liveprop **hooks)
{
    int propid = dav_fs_find_prop(ns_uri, name);

    if (propid == 0)
        return 0;

    *hooks = &dav_hooks_liveprop_fs;
    return propid;
}

void dav_fs_insert_all_liveprops(request_rec *r, const dav_resource *resource,
                                 int insvalue, ap_text_header *phdr)
{
    dav_fs_insert_all(resource, insvalue, phdr);
}

void dav_fs_register_uris(apr_pool_t *p)
{
    const char * const * uris = dav_fs_namespace_uris;

    for ( ; *uris != NULL; ++uris) {
        dav_register_liveprop_namespace(p, *uris);
    }
}
