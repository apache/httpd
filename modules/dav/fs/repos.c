/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
** DAV filesystem-based repository provider
*/

#include "apr.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apr_buckets.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>              /* for sprintf() */
#endif

#include "httpd.h"
#include "http_log.h"
#include "http_protocol.h"      /* for ap_set_* (in dav_fs_set_headers) */
#include "http_request.h"       /* for ap_update_mtime() */

#include "mod_dav.h"
#include "repos.h"


/* to assist in debugging mod_dav's GET handling */
#define DEBUG_GET_HANDLER       0

#define DAV_FS_COPY_BLOCKSIZE   16384   /* copy 16k at a time */

/* context needed to identify a resource */
struct dav_resource_private {
    apr_pool_t *pool;        /* memory storage pool associated with request */
    const char *pathname;   /* full pathname to resource */
    apr_finfo_t finfo;       /* filesystem info */
    request_rec *r;
};

/* private context for doing a filesystem walk */
typedef struct {
    /* the input walk parameters */
    const dav_walk_params *params;

    /* reused as we walk */
    dav_walk_resource wres;

    dav_resource res1;
    dav_resource_private info1;
    dav_buffer path1;
    dav_buffer uri_buf;

    /* MOVE/COPY need a secondary path */
    dav_resource res2;
    dav_resource_private info2;
    dav_buffer path2;

    dav_buffer locknull_buf;

} dav_fs_walker_context;

typedef struct {
    int is_move;                /* is this a MOVE? */
    dav_buffer work_buf;        /* handy buffer for copymove_file() */

    /* CALLBACK: this is a secondary resource managed specially for us */
    const dav_resource *res_dst;

    /* copied from dav_walk_params (they are invariant across the walk) */
    const dav_resource *root;
    apr_pool_t *pool;

} dav_fs_copymove_walk_ctx;

/* an internal WALKTYPE to walk hidden files (the .DAV directory) */
#define DAV_WALKTYPE_HIDDEN     0x4000

/* an internal WALKTYPE to call collections (again) after their contents */
#define DAV_WALKTYPE_POSTFIX    0x8000

#define DAV_CALLTYPE_POSTFIX    1000    /* a private call type */


/* pull this in from the other source file */
extern const dav_hooks_locks dav_hooks_locks_fs;

/* forward-declare the hook structures */
static const dav_hooks_repository dav_hooks_repository_fs;
static const dav_hooks_liveprop dav_hooks_liveprop_fs;

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const dav_fs_namespace_uris[] =
{
    "DAV:",
    "http://apache.org/dav/props/",

    NULL        /* sentinel */
};
enum {
    DAV_FS_URI_DAV,            /* the DAV: namespace URI */
    DAV_FS_URI_MYPROPS         /* the namespace URI for our custom props */
};

/*
** Does this platform support an executable flag?
**
** ### need a way to portably abstract this query
**
** DAV_FINFO_MASK gives the appropriate mask to use for the stat call
** used to get file attributes.
*/
#ifndef WIN32
#define DAV_FS_HAS_EXECUTABLE
#define DAV_FINFO_MASK (APR_FINFO_LINK | APR_FINFO_TYPE | APR_FINFO_INODE | \
                        APR_FINFO_SIZE | APR_FINFO_CTIME | APR_FINFO_MTIME | \
                        APR_FINFO_PROT)
#else
/* as above, but without APR_FINFO_PROT */
#define DAV_FINFO_MASK (APR_FINFO_LINK | APR_FINFO_TYPE | APR_FINFO_INODE | \
                        APR_FINFO_SIZE | APR_FINFO_CTIME | APR_FINFO_MTIME)
#endif

/*
** The single property that we define (in the DAV_FS_URI_MYPROPS namespace)
*/
#define DAV_PROPID_FS_executable        1

/*
 * prefix for temporary files
 */
#define DAV_FS_TMP_PREFIX ".davfs." 

static const dav_liveprop_spec dav_fs_props[] =
{
    /* standard DAV properties */
    {
        DAV_FS_URI_DAV,
        "creationdate",
        DAV_PROPID_creationdate,
        0
    },
    {
        DAV_FS_URI_DAV,
        "getcontentlength",
        DAV_PROPID_getcontentlength,
        0
    },
    {
        DAV_FS_URI_DAV,
        "getetag",
        DAV_PROPID_getetag,
        0
    },
    {
        DAV_FS_URI_DAV,
        "getlastmodified",
        DAV_PROPID_getlastmodified,
        0
    },

    /* our custom properties */
    {
        DAV_FS_URI_MYPROPS,
        "executable",
        DAV_PROPID_FS_executable,
        0       /* handled special in dav_fs_is_writable */
    },

    { 0 }        /* sentinel */
};

static const dav_liveprop_group dav_fs_liveprop_group =
{
    dav_fs_props,
    dav_fs_namespace_uris,
    &dav_hooks_liveprop_fs
};


/* define the dav_stream structure for our use */
struct dav_stream {
    apr_pool_t *p;
    apr_file_t *f;
    const char *pathname;       /* we may need to remove it at close time */
    const char *temppath;
};

/* returns an appropriate HTTP status code given an APR status code for a
 * failed I/O operation.  ### use something besides 500? */
#define MAP_IO2HTTP(e) (APR_STATUS_IS_ENOSPC(e) ? HTTP_INSUFFICIENT_STORAGE : \
                        HTTP_INTERNAL_SERVER_ERROR)

/* forward declaration for internal treewalkers */
static dav_error * dav_fs_walk(const dav_walk_params *params, int depth,
                               dav_response **response);
static dav_error * dav_fs_internal_walk(const dav_walk_params *params,
                                        int depth, int is_move,
                                        const dav_resource *root_dst,
                                        dav_response **response);

/* --------------------------------------------------------------------
**
** PRIVATE REPOSITORY FUNCTIONS
*/
static request_rec *dav_fs_get_request_rec(const dav_resource *resource)
{
    return resource->info->r;
}

apr_pool_t *dav_fs_pool(const dav_resource *resource)
{
    return resource->info->pool;
}

const char *dav_fs_pathname(const dav_resource *resource)
{
    return resource->info->pathname;
}

dav_error * dav_fs_dir_file_name(
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
        const char *testpath, *rootpath;
        char *dirpath = ap_make_dirstr_parent(ctx->pool, ctx->pathname);
        apr_size_t dirlen = strlen(dirpath);
        apr_status_t rv = APR_SUCCESS;

        testpath = dirpath;
        if (dirlen > 0) {
            rv = apr_filepath_root(&rootpath, &testpath, 0, ctx->pool);
        }

        /* remove trailing slash from dirpath, unless it's a root path
         */
        if ((rv == APR_SUCCESS && testpath && *testpath)
            || rv == APR_ERELATIVE) {
            if (dirpath[dirlen - 1] == '/') {
                dirpath[dirlen - 1] = '\0';
            }
        }

        /* ###: Looks like a response could be appropriate
         *
         * APR_SUCCESS     here tells us the dir is a root
         * APR_ERELATIVE   told us we had no root (ok)
         * APR_EINCOMPLETE an incomplete testpath told us
         *                 there was no -file- name here!
         * APR_EBADPATH    or other errors tell us this file
         *                 path is undecipherable
         */

        if (rv == APR_SUCCESS || rv == APR_ERELATIVE) {
            *dirpath_p = dirpath;
            if (fname_p != NULL)
                *fname_p = ctx->pathname + dirlen;
        }
        else {
            return dav_new_error(ctx->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                                 "An incomplete/bad path was found in "
                                 "dav_fs_dir_file_name.");
        }
    }

    return NULL;
}

/* Note: picked up from ap_gm_timestr_822() */
/* NOTE: buf must be at least DAV_TIMEBUF_SIZE chars in size */
static void dav_format_time(int style, apr_time_t sec, char *buf)
{
    apr_time_exp_t tms;

    /* ### what to do if fails? */
    (void) apr_time_exp_gmt(&tms, sec);

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
           apr_day_snames[tms.tm_wday],
           tms.tm_mday, apr_month_snames[tms.tm_mon],
           tms.tm_year + 1900,
           tms.tm_hour, tms.tm_min, tms.tm_sec);
}

/* Copy or move src to dst; src_finfo is used to propagate permissions
 * bits across if non-NULL; dst_finfo must be non-NULL iff dst already
 * exists. */
static dav_error * dav_fs_copymove_file(
    int is_move,
    apr_pool_t * p,
    const char *src,
    const char *dst,
    const apr_finfo_t *src_finfo,
    const apr_finfo_t *dst_finfo,
    dav_buffer *pbuf)
{
    dav_buffer work_buf = { 0 };
    apr_file_t *inf = NULL;
    apr_file_t *outf = NULL;
    apr_status_t status;
    apr_fileperms_t perms;

    if (pbuf == NULL)
        pbuf = &work_buf;

    /* Determine permissions to use for destination */
    if (src_finfo && src_finfo->valid & APR_FINFO_PROT
        && src_finfo->protection & APR_UEXECUTE) {
        perms = src_finfo->protection;

        if (dst_finfo != NULL) {
            /* chmod it if it already exist */
            if (apr_file_perms_set(dst, perms)) {
                return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
                                     "Could not set permissions on destination");
            }
        }
    }
    else {
        perms = APR_OS_DEFAULT;
    }

    dav_set_bufsize(p, pbuf, DAV_FS_COPY_BLOCKSIZE);

    if ((apr_file_open(&inf, src, APR_READ | APR_BINARY, APR_OS_DEFAULT, p))
            != APR_SUCCESS) {
        /* ### use something besides 500? */
        return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
                             "Could not open file for reading");
    }

    /* ### do we need to deal with the umask? */
    status = apr_file_open(&outf, dst, APR_WRITE | APR_CREATE | APR_TRUNCATE
                           | APR_BINARY, perms, p);
    if (status != APR_SUCCESS) {
        apr_file_close(inf);

        return dav_new_error(p, MAP_IO2HTTP(status), 0,
                             "Could not open file for writing");
    }

    while (1) {
        apr_size_t len = DAV_FS_COPY_BLOCKSIZE;

        status = apr_file_read(inf, pbuf->buf, &len);
        if (status != APR_SUCCESS && status != APR_EOF) {
            apr_file_close(inf);
            apr_file_close(outf);

            if (apr_file_remove(dst, p) != APR_SUCCESS) {
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

        if (status == APR_EOF)
            break;

        /* write any bytes that were read */
        status = apr_file_write_full(outf, pbuf->buf, len, NULL);
        if (status != APR_SUCCESS) {
            apr_file_close(inf);
            apr_file_close(outf);

            if (apr_file_remove(dst, p) != APR_SUCCESS) {
                /* ### ACK! Inconsistent state... */

                /* ### use something besides 500? */
                return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
                                     "Could not delete output after write "
                                     "failure. Server is now in an "
                                     "inconsistent state.");
            }

            return dav_new_error(p, MAP_IO2HTTP(status), 0,
                                 "Could not write output file");
        }
    }

    apr_file_close(inf);
    apr_file_close(outf);

    if (is_move && apr_file_remove(src, p) != APR_SUCCESS) {
        dav_error *err;
        int save_errno = errno;   /* save the errno that got us here */

        if (apr_file_remove(dst, p) != APR_SUCCESS) {
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
    apr_finfo_t src_finfo;        /* finfo for source file */
    apr_finfo_t dst_state_finfo;        /* finfo for STATE directory */
    apr_status_t rv;
    const char *src;
    const char *dst;

    /* build the propset pathname for the source file */
    src = apr_pstrcat(p, src_dir, "/" DAV_FS_STATE_DIR "/", src_file, NULL);

    /* the source file doesn't exist */
    rv = apr_stat(&src_finfo, src, APR_FINFO_NORM, p);
    if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
        return NULL;
    }

    /* build the pathname for the destination state dir */
    dst = apr_pstrcat(p, dst_dir, "/" DAV_FS_STATE_DIR, NULL);

    /* ### do we need to deal with the umask? */

    /* ensure that it exists */
    rv = apr_dir_make(dst, APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        if (!APR_STATUS_IS_EEXIST(rv)) {
            /* ### use something besides 500? */
            return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
                                 "Could not create internal state directory");
        }
    }

    /* get info about the state directory */
    rv = apr_stat(&dst_state_finfo, dst, APR_FINFO_NORM, p);
    if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
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
    if (is_move) {
        /* try simple rename first */
        rv = apr_file_rename(src, dst, p);
        if (APR_STATUS_IS_EXDEV(rv)) {
            return dav_fs_copymove_file(is_move, p, src, dst, NULL, NULL, pbuf);
        }
        if (rv != APR_SUCCESS) {
            /* ### use something besides 500? */
            return dav_new_error(p, HTTP_INTERNAL_SERVER_ERROR, 0,
                                 "Could not move state file.");
        }
    }
    else
    {
        /* gotta copy (and delete) */
        return dav_fs_copymove_file(is_move, p, src, dst, NULL, NULL, pbuf);
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
    /* ### should test these result values... */
    (void) dav_fs_dir_file_name(src, &src_dir, &src_file);
    (void) dav_fs_dir_file_name(dst, &dst_dir, &dst_file);

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
    apr_status_t status;

    /* Get directory, filename, and state-file names for the resource */
    /* ### should test this result value... */
    (void) dav_fs_dir_file_name(resource, &dirpath, &fname);
    dav_dbm_get_statefiles(p, fname, &state1, &state2);

    /* build the propset pathname for the file */
    pathname = apr_pstrcat(p,
                          dirpath,
                          "/" DAV_FS_STATE_DIR "/",
                          state1,
                          NULL);

    /* note: we may get ENOENT if the state dir is not present */
    if ((status = apr_file_remove(pathname, p)) != APR_SUCCESS
        && !APR_STATUS_IS_ENOENT(status)) {
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

        if ((status = apr_file_remove(pathname, p)) != APR_SUCCESS
            && !APR_STATUS_IS_ENOENT(status)) {
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

static dav_error * dav_fs_get_resource(
    request_rec *r,
    const char *root_dir,
    const char *label,
    int use_checked_in,
    dav_resource **result_resource)
{
    dav_resource_private *ctx;
    dav_resource *resource;
    char *s;
    char *filename;
    apr_size_t len;

    /* ### optimize this into a single allocation! */

    /* Create private resource context descriptor */
    ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->finfo = r->finfo;
    ctx->r = r;

    /* ### this should go away */
    ctx->pool = r->pool;

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
    resource->pool = r->pool;

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

    if (r->finfo.filetype != 0) {
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
                return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
                                     "The URL contains extraneous path "
                                     "components. The resource could not "
                                     "be identified.");
            }

            /* retain proper integrity across the structures */
            if (!resource->exists) {
                ctx->finfo.filetype = 0;
            }
        }
    }

    *result_resource = resource;
    return NULL;
}

static dav_error * dav_fs_get_parent_resource(const dav_resource *resource,
                                              dav_resource **result_parent)
{
    dav_resource_private *ctx = resource->info;
    dav_resource_private *parent_ctx;
    dav_resource *parent_resource;
    apr_status_t rv;
    char *dirpath;
    const char *testroot;
    const char *testpath;

    /* If we're at the root of the URL space, then there is no parent. */
    if (strcmp(resource->uri, "/") == 0) {
        *result_parent = NULL;
        return NULL;
    }

    /* If given resource is root, then there is no parent.
     * Unless we can retrieve the filepath root, this is
     * intendend to fail.  If we split the root and
     * no path info remains, then we also fail.
     */
    testpath = ctx->pathname;
    rv = apr_filepath_root(&testroot, &testpath, 0, ctx->pool);
    if ((rv != APR_SUCCESS && rv != APR_ERELATIVE)
        || !testpath || !*testpath) {
        *result_parent = NULL;
        return NULL;
    }

    /* ### optimize this into a single allocation! */

    /* Create private resource context descriptor */
    parent_ctx = apr_pcalloc(ctx->pool, sizeof(*parent_ctx));

    /* ### this should go away */
    parent_ctx->pool = ctx->pool;

    dirpath = ap_make_dirstr_parent(ctx->pool, ctx->pathname);
    if (strlen(dirpath) > 1 && dirpath[strlen(dirpath) - 1] == '/')
        dirpath[strlen(dirpath) - 1] = '\0';
    parent_ctx->pathname = dirpath;

    parent_resource = apr_pcalloc(ctx->pool, sizeof(*parent_resource));
    parent_resource->info = parent_ctx;
    parent_resource->collection = 1;
    parent_resource->hooks = &dav_hooks_repository_fs;
    parent_resource->pool = resource->pool;

    if (resource->uri != NULL) {
        char *uri = ap_make_dirstr_parent(ctx->pool, resource->uri);
        if (strlen(uri) > 1 && uri[strlen(uri) - 1] == '/')
            uri[strlen(uri) - 1] = '\0';
        parent_resource->uri = uri;
    }

    rv = apr_stat(&parent_ctx->finfo, parent_ctx->pathname,
                  APR_FINFO_NORM, ctx->pool);
    if (rv == APR_SUCCESS || rv == APR_INCOMPLETE) {
        parent_resource->exists = 1;
    }

    *result_parent = parent_resource;
    return NULL;
}

static int dav_fs_is_same_resource(
    const dav_resource *res1,
    const dav_resource *res2)
{
    dav_resource_private *ctx1 = res1->info;
    dav_resource_private *ctx2 = res2->info;

    if (res1->hooks != res2->hooks)
        return 0;

    if ((ctx1->finfo.filetype != 0) && (ctx2->finfo.filetype != 0)
        && (ctx1->finfo.valid & ctx2->finfo.valid & APR_FINFO_INODE)) {
        return ctx1->finfo.inode == ctx2->finfo.inode;
    }
    else {
        return strcmp(ctx1->pathname, ctx2->pathname) == 0;
    }
}

static int dav_fs_is_parent_resource(
    const dav_resource *res1,
    const dav_resource *res2)
{
    dav_resource_private *ctx1 = res1->info;
    dav_resource_private *ctx2 = res2->info;
    apr_size_t len1 = strlen(ctx1->pathname);
    apr_size_t len2;

    if (res1->hooks != res2->hooks)
        return 0;

    /* it is safe to use ctx2 now */
    len2 = strlen(ctx2->pathname);

    return (len2 > len1
            && memcmp(ctx1->pathname, ctx2->pathname, len1) == 0
            && ctx2->pathname[len1] == '/');
}

static apr_status_t tmpfile_cleanup(void *data) {
        dav_stream *ds = data;
        if (ds->temppath) {
                apr_file_remove(ds->temppath, ds->p);
        }
        return APR_SUCCESS;
}

static dav_error * dav_fs_open_stream(const dav_resource *resource,
                                      dav_stream_mode mode,
                                      dav_stream **stream)
{
    apr_pool_t *p = resource->info->pool;
    dav_stream *ds = apr_pcalloc(p, sizeof(*ds));
    apr_int32_t flags;
    apr_status_t rv;

    switch (mode) {
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
    ds->temppath = NULL;

    if (mode == DAV_MODE_WRITE_TRUNC) {
        ds->temppath = apr_pstrcat(p, ap_make_dirstr_parent(p, ds->pathname),
                                   DAV_FS_TMP_PREFIX "XXXXXX", NULL);
        rv = apr_file_mktemp(&ds->f, ds->temppath, flags, ds->p);
        apr_pool_cleanup_register(p, ds, tmpfile_cleanup,
                                  apr_pool_cleanup_null);
    }
    else {
        rv = apr_file_open(&ds->f, ds->pathname, flags, APR_OS_DEFAULT, ds->p);
    }

    if (rv != APR_SUCCESS) {
        return dav_new_error(p, MAP_IO2HTTP(rv), 0,
                             "An error occurred while opening a resource.");
    }

    /* (APR registers cleanups for the fd with the pool) */

    *stream = ds;
    return NULL;
}

static dav_error * dav_fs_close_stream(dav_stream *stream, int commit)
{
    apr_status_t rv;

    apr_file_close(stream->f);

    if (!commit) {
        if (stream->temppath) {
            apr_pool_cleanup_run(stream->p, stream, tmpfile_cleanup);
        }
        else {
            if (apr_file_remove(stream->pathname, stream->p) != APR_SUCCESS) {
                /* ### use a better description? */
                return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, 0,
                                     "There was a problem removing (rolling "
                                     "back) the resource "
                                     "when it was being closed.");
            }
        }
    }
    else if (stream->temppath) {
        rv = apr_file_rename(stream->temppath, stream->pathname, stream->p);
        if (rv) {
            return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, rv,
                                 "There was a problem writing the file "
                                 "atomically after writes.");
        }
        apr_pool_cleanup_kill(stream->p, stream, tmpfile_cleanup);
    }

    return NULL;
}

static dav_error * dav_fs_write_stream(dav_stream *stream,
                                       const void *buf, apr_size_t bufsize)
{
    apr_status_t status;

    status = apr_file_write_full(stream->f, buf, bufsize, NULL);
    if (APR_STATUS_IS_ENOSPC(status)) {
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
    if (apr_file_seek(stream->f, APR_SET, &abs_pos) != APR_SUCCESS) {
        /* ### should check whether apr_file_seek set abs_pos was set to the
         * correct position? */
        /* ### use something besides 500? */
        return dav_new_error(stream->p, HTTP_INTERNAL_SERVER_ERROR, 0,
                             "Could not seek to specified position in the "
                             "resource.");
    }
    return NULL;
}


#if DEBUG_GET_HANDLER

/* only define set_headers() and deliver() for debug purposes */


static dav_error * dav_fs_set_headers(request_rec *r,
                                      const dav_resource *resource)
{
    /* ### this function isn't really used since we have a get_pathname */
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

    return NULL;
}

static dav_error * dav_fs_deliver(const dav_resource *resource,
                                  ap_filter_t *output)
{
    apr_pool_t *pool = resource->pool;
    apr_bucket_brigade *bb;
    apr_file_t *fd;
    apr_status_t status;
    apr_bucket *bkt;

    /* Check resource type */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR
        && resource->type != DAV_RESOURCE_TYPE_VERSION
        && resource->type != DAV_RESOURCE_TYPE_WORKING) {
        return dav_new_error(pool, HTTP_CONFLICT, 0,
                             "Cannot GET this type of resource.");
    }
    if (resource->collection) {
        return dav_new_error(pool, HTTP_CONFLICT, 0,
                             "There is no default response to GET for a "
                             "collection.");
    }

    if ((status = apr_file_open(&fd, resource->info->pathname,
                                APR_READ | APR_BINARY, 0,
                                pool)) != APR_SUCCESS) {
        return dav_new_error(pool, HTTP_FORBIDDEN, 0,
                             "File permissions deny server access.");
    }

    bb = apr_brigade_create(pool, output->c->bucket_alloc);

    apr_brigade_insert_file(bb, fd, 0, resource->info->finfo.size, pool);

    bkt = apr_bucket_eos_create(output->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bkt);

    if ((status = ap_pass_brigade(output, bb)) != APR_SUCCESS) {
        return dav_new_error(pool, HTTP_FORBIDDEN, 0,
                             "Could not write contents to filter.");
    }

    return NULL;
}

#endif /* DEBUG_GET_HANDLER */


static dav_error * dav_fs_create_collection(dav_resource *resource)
{
    dav_resource_private *ctx = resource->info;
    apr_status_t status;

    status = apr_dir_make(ctx->pathname, APR_OS_DEFAULT, ctx->pool);
    if (APR_STATUS_IS_ENOSPC(status)) {
        return dav_new_error(ctx->pool, HTTP_INSUFFICIENT_STORAGE, 0,
                             "There is not enough storage to create "
                             "this collection.");
    }
    else if (APR_STATUS_IS_ENOENT(status)) {
        return dav_new_error(ctx->pool, HTTP_CONFLICT, 0,
                             "Cannot create collection; intermediate "
                             "collection does not exist.");
    }
    else if (status != APR_SUCCESS) {
        /* ### refine this error message? */
        return dav_new_error(ctx->pool, HTTP_FORBIDDEN, 0,
                             "Unable to create collection.");
    }

    /* update resource state to show it exists as a collection */
    resource->exists = 1;
    resource->collection = 1;

    return NULL;
}

static dav_error * dav_fs_copymove_walker(dav_walk_resource *wres,
                                          int calltype)
{
    dav_fs_copymove_walk_ctx *ctx = wres->walk_ctx;
    dav_resource_private *srcinfo = wres->resource->info;
    dav_resource_private *dstinfo = ctx->res_dst->info;
    dav_error *err = NULL;

    if (wres->resource->collection) {
        if (calltype == DAV_CALLTYPE_POSTFIX) {
            /* Postfix call for MOVE. delete the source dir.
             * Note: when copying, we do not enable the postfix-traversal.
             */
            /* ### we are ignoring any error here; what should we do? */
            (void) apr_dir_remove(srcinfo->pathname, ctx->pool);
        }
        else {
            /* copy/move of a collection. Create the new, target collection */
            if (apr_dir_make(dstinfo->pathname, APR_OS_DEFAULT,
                             ctx->pool) != APR_SUCCESS) {
                /* ### assume it was a permissions problem */
                /* ### need a description here */
                err = dav_new_error(ctx->pool, HTTP_FORBIDDEN, 0, NULL);
            }
        }
    }
    else {
        err = dav_fs_copymove_file(ctx->is_move, ctx->pool,
                                   srcinfo->pathname, dstinfo->pathname,
                                   &srcinfo->finfo,
                                   ctx->res_dst->exists ? &dstinfo->finfo : NULL,
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
            || !dav_fs_is_same_resource(wres->resource, ctx->root))) {
        /* ### use errno to generate DAV:responsedescription? */
        dav_add_response(wres, err->status, NULL);

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
        dav_walk_params params = { 0 };
        dav_response *multi_status;

        params.walk_type = DAV_WALKTYPE_NORMAL | DAV_WALKTYPE_HIDDEN;
        params.func = dav_fs_copymove_walker;
        params.pool = src->info->pool;
        params.root = src;

        /* params.walk_ctx is managed by dav_fs_internal_walk() */

        /* postfix is needed for MOVE to delete source dirs */
        if (is_move)
            params.walk_type |= DAV_WALKTYPE_POSTFIX;

        /* note that we return the error OR the multistatus. never both */

        if ((err = dav_fs_internal_walk(&params, depth, is_move, dst,
                                        &multi_status)) != NULL) {
            /* on a "real" error, then just punt. nothing else to do. */
            return err;
        }

        if ((*response = multi_status) != NULL) {
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
                                    &src->info->finfo,
                                    dst->exists ? &dst->info->finfo : NULL,
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
    apr_status_t rv;

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


    /* try rename first */
    rv = apr_file_rename(srcinfo->pathname, dstinfo->pathname, srcinfo->pool);

    /* if we can't simply rename, then do it the hard way... */
    if (APR_STATUS_IS_EXDEV(rv)) {
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

    /* no multistatus response */
    *response = NULL;

    if (rv != APR_SUCCESS) {
        /* ### should have a better error than this. */
        return dav_new_error(srcinfo->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                             "Could not rename resource.");
    }

    /* Rename did work. Update resource states and move properties as well */
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
    if (apr_file_rename(dstinfo->pathname, srcinfo->pathname,
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

static dav_error * dav_fs_delete_walker(dav_walk_resource *wres, int calltype)
{
    dav_resource_private *info = wres->resource->info;

    /* do not attempt to remove a null resource,
     * or a collection with children
     */
    if (wres->resource->exists &&
        (!wres->resource->collection || calltype == DAV_CALLTYPE_POSTFIX)) {
        /* try to remove the resource */
        apr_status_t result;

        result = wres->resource->collection
            ? apr_dir_remove(info->pathname, wres->pool)
            : apr_file_remove(info->pathname, wres->pool);

        /*
        ** If an error occurred, then add it to multistatus response.
        ** Note that we add it for the root resource, too. It is quite
        ** possible to delete the whole darn tree, yet fail on the root.
        **
        ** (also: remember we are deleting via a postfix traversal)
        */
        if (result != APR_SUCCESS) {
            /* ### assume there is a permissions problem */

            /* ### use errno to generate DAV:responsedescription? */
            dav_add_response(wres, HTTP_FORBIDDEN, NULL);
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
        dav_walk_params params = { 0 };
        dav_error *err = NULL;
        dav_response *multi_status;

        params.walk_type = (DAV_WALKTYPE_NORMAL
                            | DAV_WALKTYPE_HIDDEN
                            | DAV_WALKTYPE_POSTFIX);
        params.func = dav_fs_delete_walker;
        params.pool = info->pool;
        params.root = resource;

        if ((err = dav_fs_walk(&params, DAV_INFINITY,
                               &multi_status)) != NULL) {
            /* on a "real" error, then just punt. nothing else to do. */
            return err;
        }

        if ((*response = multi_status) != NULL) {
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
    if (apr_file_remove(info->pathname, info->pool) != APR_SUCCESS) {
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
    const dav_walk_params *params = fsctx->params;
    apr_pool_t *pool = params->pool;
    dav_error *err = NULL;
    int isdir = fsctx->res1.collection;
    apr_finfo_t dirent;
    apr_dir_t *dirp;

    /* ensure the context is prepared properly, then call the func */
    err = (*params->func)(&fsctx->wres,
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
    dav_check_bufsize(pool, &fsctx->path1, DAV_BUFFER_PAD);
    fsctx->path1.buf[fsctx->path1.cur_len++] = '/';
    fsctx->path1.buf[fsctx->path1.cur_len] = '\0';        /* in pad area */

    /* if a secondary path is present, then do that, too */
    if (fsctx->path2.buf != NULL) {
        dav_check_bufsize(pool, &fsctx->path2, DAV_BUFFER_PAD);
        fsctx->path2.buf[fsctx->path2.cur_len++] = '/';
        fsctx->path2.buf[fsctx->path2.cur_len] = '\0';        /* in pad area */
    }

    /* Note: the URI should ALREADY have a trailing "/" */

    /* for this first pass of files, all resources exist */
    fsctx->res1.exists = 1;

    /* a file is the default; we'll adjust if we hit a directory */
    fsctx->res1.collection = 0;
    fsctx->res2.collection = 0;

    /* open and scan the directory */
    if ((apr_dir_open(&dirp, fsctx->path1.buf, pool)) != APR_SUCCESS) {
        /* ### need a better error */
        return dav_new_error(pool, HTTP_NOT_FOUND, 0, NULL);
    }
    while ((apr_dir_read(&dirent, APR_FINFO_DIRENT, dirp)) == APR_SUCCESS) {
        apr_size_t len;
        apr_status_t status;

        len = strlen(dirent.name);

        /* avoid recursing into our current, parent, or state directories */
        if (dirent.name[0] == '.'
              && (len == 1 || (dirent.name[1] == '.' && len == 2))) {
            continue;
        }

        if (params->walk_type & DAV_WALKTYPE_AUTH) {
            /* ### need to authorize each file */
            /* ### example: .htaccess is normally configured to fail auth */

            /* stuff in the state directory and temp files are never authorized! */
            if (!strcmp(dirent.name, DAV_FS_STATE_DIR) ||
                !strncmp(dirent.name, DAV_FS_TMP_PREFIX,
                         strlen(DAV_FS_TMP_PREFIX))) {
                continue;
            }
        }
        /* skip the state dir and temp files unless a HIDDEN is performed */
        if (!(params->walk_type & DAV_WALKTYPE_HIDDEN)
            && (!strcmp(dirent.name, DAV_FS_STATE_DIR) ||
                !strncmp(dirent.name, DAV_FS_TMP_PREFIX,
                         strlen(DAV_FS_TMP_PREFIX)))) {
            continue;
        }

        /* append this file onto the path buffer (copy null term) */
        dav_buffer_place_mem(pool, &fsctx->path1, dirent.name, len + 1, 0);

        status = apr_stat(&fsctx->info1.finfo, fsctx->path1.buf,
                          DAV_FINFO_MASK, pool);
        if (status != APR_SUCCESS && status != APR_INCOMPLETE) {
            /* woah! where'd it go? */
            /* ### should have a better error here */
            err = dav_new_error(pool, HTTP_NOT_FOUND, 0, NULL);
            break;
        }

        /* copy the file to the URI, too. NOTE: we will pad an extra byte
           for the trailing slash later. */
        dav_buffer_place_mem(pool, &fsctx->uri_buf, dirent.name, len + 1, 1);

        /* if there is a secondary path, then do that, too */
        if (fsctx->path2.buf != NULL) {
            dav_buffer_place_mem(pool, &fsctx->path2, dirent.name, len + 1, 0);
        }

        /* set up the (internal) pathnames for the two resources */
        fsctx->info1.pathname = fsctx->path1.buf;
        fsctx->info2.pathname = fsctx->path2.buf;

        /* set up the URI for the current resource */
        fsctx->res1.uri = fsctx->uri_buf.buf;

        /* ### for now, only process regular files (e.g. skip symlinks) */
        if (fsctx->info1.finfo.filetype == APR_REG) {
            /* call the function for the specified dir + file */
            if ((err = (*params->func)(&fsctx->wres,
                                       DAV_CALLTYPE_MEMBER)) != NULL) {
                /* ### maybe add a higher-level description? */
                break;
            }
        }
        else if (fsctx->info1.finfo.filetype == APR_DIR) {
            apr_size_t save_path_len = fsctx->path1.cur_len;
            apr_size_t save_uri_len = fsctx->uri_buf.cur_len;
            apr_size_t save_path2_len = fsctx->path2.cur_len;

            /* adjust length to incorporate the subdir name */
            fsctx->path1.cur_len += len;
            fsctx->path2.cur_len += len;

            /* adjust URI length to incorporate subdir and a slash */
            fsctx->uri_buf.cur_len += len + 1;
            fsctx->uri_buf.buf[fsctx->uri_buf.cur_len - 1] = '/';
            fsctx->uri_buf.buf[fsctx->uri_buf.cur_len] = '\0';

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
            fsctx->uri_buf.cur_len = save_uri_len;

            fsctx->res1.collection = 0;
            fsctx->res2.collection = 0;

            /* assert: res1.exists == 1 */
        }
    }

    /* ### check the return value of this? */
    apr_dir_close(dirp);

    if (err != NULL)
        return err;

    if (params->walk_type & DAV_WALKTYPE_LOCKNULL) {
        apr_size_t offset = 0;

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
            apr_size_t len = strlen(fsctx->locknull_buf.buf + offset);
            dav_lock *locks = NULL;

            /*
            ** Append the locknull file to the paths and the URI. Note that
            ** we don't have to pad the URI for a slash since a locknull
            ** resource is not a collection.
            */
            dav_buffer_place_mem(pool, &fsctx->path1,
                                 fsctx->locknull_buf.buf + offset, len + 1, 0);
            dav_buffer_place_mem(pool, &fsctx->uri_buf,
                                 fsctx->locknull_buf.buf + offset, len + 1, 0);
            if (fsctx->path2.buf != NULL) {
                dav_buffer_place_mem(pool, &fsctx->path2,
                                     fsctx->locknull_buf.buf + offset,
                                     len + 1, 0);
            }

            /* set up the (internal) pathnames for the two resources */
            fsctx->info1.pathname = fsctx->path1.buf;
            fsctx->info2.pathname = fsctx->path2.buf;

            /* set up the URI for the current resource */
            fsctx->res1.uri = fsctx->uri_buf.buf;

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
            if ((err = dav_lock_query(params->lockdb, &fsctx->res1,
                                      &locks)) != NULL) {
                /* ### maybe add a higher-level description? */
                return err;
            }

            /* call the function for the specified dir + file */
            if (locks != NULL &&
                (err = (*params->func)(&fsctx->wres,
                                       DAV_CALLTYPE_LOCKNULL)) != NULL) {
                /* ### maybe add a higher-level description? */
                return err;
            }

            offset += len + 1;
        }

        /* reset the exists flag */
        fsctx->res1.exists = 1;
    }

    if (params->walk_type & DAV_WALKTYPE_POSTFIX) {
        /* replace the dirs' trailing slashes with null terms */
        fsctx->path1.buf[--fsctx->path1.cur_len] = '\0';
        fsctx->uri_buf.buf[--fsctx->uri_buf.cur_len] = '\0';
        if (fsctx->path2.buf != NULL) {
            fsctx->path2.buf[--fsctx->path2.cur_len] = '\0';
        }

        /* this is a collection which exists */
        fsctx->res1.collection = 1;

        return (*params->func)(&fsctx->wres, DAV_CALLTYPE_POSTFIX);
    }

    return NULL;
}

static dav_error * dav_fs_internal_walk(const dav_walk_params *params,
                                        int depth, int is_move,
                                        const dav_resource *root_dst,
                                        dav_response **response)
{
    dav_fs_walker_context fsctx = { 0 };
    dav_error *err;
    dav_fs_copymove_walk_ctx cm_ctx = { 0 };

#if DAV_DEBUG
    if ((params->walk_type & DAV_WALKTYPE_LOCKNULL) != 0
        && params->lockdb == NULL) {
        return dav_new_error(params->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                             "DESIGN ERROR: walker called to walk locknull "
                             "resources, but a lockdb was not provided.");
    }
#endif

    fsctx.params = params;
    fsctx.wres.walk_ctx = params->walk_ctx;
    fsctx.wres.pool = params->pool;

    /* ### zero out versioned, working, baselined? */

    fsctx.res1 = *params->root;
    fsctx.res1.pool = params->pool;

    fsctx.res1.info = &fsctx.info1;
    fsctx.info1 = *params->root->info;

    /* the pathname is stored in the path1 buffer */
    dav_buffer_init(params->pool, &fsctx.path1, fsctx.info1.pathname);
    fsctx.info1.pathname = fsctx.path1.buf;

    if (root_dst != NULL) {
        /* internal call from the COPY/MOVE code. set it up. */

        fsctx.wres.walk_ctx = &cm_ctx;
        cm_ctx.is_move = is_move;
        cm_ctx.res_dst = &fsctx.res2;
        cm_ctx.root = params->root;
        cm_ctx.pool = params->pool;

        fsctx.res2 = *root_dst;
        fsctx.res2.exists = 0;
        fsctx.res2.collection = 0;
        fsctx.res2.uri = NULL;          /* we don't track this */
        fsctx.res2.pool = params->pool;

        fsctx.res2.info = &fsctx.info2;
        fsctx.info2 = *root_dst->info;

        /* res2 does not exist -- clear its finfo structure */
        memset(&fsctx.info2.finfo, 0, sizeof(fsctx.info2.finfo));

        /* the pathname is stored in the path2 buffer */
        dav_buffer_init(params->pool, &fsctx.path2, fsctx.info2.pathname);
        fsctx.info2.pathname = fsctx.path2.buf;
    }

    /* prep the URI buffer */
    dav_buffer_init(params->pool, &fsctx.uri_buf, params->root->uri);

    /* if we have a directory, then ensure the URI has a trailing "/" */
    if (fsctx.res1.collection
        && fsctx.uri_buf.buf[fsctx.uri_buf.cur_len - 1] != '/') {

        /* this will fall into the pad area */
        fsctx.uri_buf.buf[fsctx.uri_buf.cur_len++] = '/';
        fsctx.uri_buf.buf[fsctx.uri_buf.cur_len] = '\0';
    }

    /* the current resource's URI is stored in the uri_buf buffer */
    fsctx.res1.uri = fsctx.uri_buf.buf;

    /* point the callback's resource at our structure */
    fsctx.wres.resource = &fsctx.res1;

    /* always return the error, and any/all multistatus responses */
    err = dav_fs_walker(&fsctx, depth);
    *response = fsctx.wres.response;
    return err;
}

static dav_error * dav_fs_walk(const dav_walk_params *params, int depth,
                               dav_response **response)
{
    /* always return the error, and any/all multistatus responses */
    return dav_fs_internal_walk(params, depth, 0, NULL, response);
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

    if (ctx->finfo.filetype != 0) {
        return apr_psprintf(ctx->pool, "\"%" APR_UINT64_T_HEX_FMT "-%"
                            APR_UINT64_T_HEX_FMT "-%" APR_UINT64_T_HEX_FMT "\"",
                            (apr_uint64_t) ctx->finfo.inode,
                            (apr_uint64_t) ctx->finfo.size,
                            (apr_uint64_t) ctx->finfo.mtime);
    }

    return apr_psprintf(ctx->pool, "\"%" APR_UINT64_T_HEX_FMT "\"",
                       (apr_uint64_t) ctx->finfo.mtime);
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
    dav_fs_write_stream,
    dav_fs_seek_stream,
#if DEBUG_GET_HANDLER
    dav_fs_set_headers,
    dav_fs_deliver,
#else
    NULL,
    NULL,
#endif
    dav_fs_create_collection,
    dav_fs_copy_resource,
    dav_fs_move_resource,
    dav_fs_remove_resource,
    dav_fs_walk,
    dav_fs_getetag,
    NULL,
    dav_fs_get_request_rec,
    dav_fs_pathname
};

static dav_prop_insert dav_fs_insert_prop(const dav_resource *resource,
                                          int propid, dav_prop_insert what,
                                          apr_text_header *phdr)
{
    const char *value;
    const char *s;
    apr_pool_t *p = resource->info->pool;
    const dav_liveprop_spec *info;
    int global_ns;

    /* an HTTP-date can be 29 chars plus a null term */
    /* a 64-bit size can be 20 chars plus a null term */
    char buf[DAV_TIMEBUF_SIZE];

    /*
    ** None of FS provider properties are defined if the resource does not
    ** exist. Just bail for this case.
    **
    ** Even though we state that the FS properties are not defined, the
    ** client cannot store dead values -- we deny that thru the is_writable
    ** hook function.
    */
    if (!resource->exists)
        return DAV_PROP_INSERT_NOTDEF;

    switch (propid) {
    case DAV_PROPID_creationdate:
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

    case DAV_PROPID_getcontentlength:
        /* our property, but not defined on collection resources */
        if (resource->collection)
            return DAV_PROP_INSERT_NOTDEF;

        (void) sprintf(buf, "%" APR_OFF_T_FMT, resource->info->finfo.size);
        value = buf;
        break;

    case DAV_PROPID_getetag:
        value = dav_fs_getetag(resource);
        break;

    case DAV_PROPID_getlastmodified:
        dav_format_time(DAV_STYLE_RFC822,
                        resource->info->finfo.mtime,
                        buf);
        value = buf;
        break;

    case DAV_PROPID_FS_executable:
        /* our property, but not defined on collection resources */
        if (resource->collection)
            return DAV_PROP_INSERT_NOTDEF;

        /* our property, but not defined on this platform */
        if (!(resource->info->finfo.valid & APR_FINFO_UPROT))
            return DAV_PROP_INSERT_NOTDEF;

        /* the files are "ours" so we only need to check owner exec privs */
        if (resource->info->finfo.protection & APR_UEXECUTE)
            value = "T";
        else
            value = "F";
        break;

    default:
        /* ### what the heck was this property? */
        return DAV_PROP_INSERT_NOTDEF;
    }

    /* assert: value != NULL */

    /* get the information and global NS index for the property */
    global_ns = dav_get_liveprop_info(propid, &dav_fs_liveprop_group, &info);

    /* assert: info != NULL && info->name != NULL */

    /* DBG3("FS: inserting lp%d:%s  (local %d)", ns, scan->name, scan->ns); */

    if (what == DAV_PROP_INSERT_VALUE) {
        s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
                         global_ns, info->name, value, global_ns, info->name);
    }
    else if (what == DAV_PROP_INSERT_NAME) {
        s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
    }
    else {
        /* assert: what == DAV_PROP_INSERT_SUPPORTED */
        s = apr_psprintf(p,
                         "<D:supported-live-property D:name=\"%s\" "
                         "D:namespace=\"%s\"/>" DEBUG_CR,
                         info->name, dav_fs_namespace_uris[info->ns]);
    }
    apr_text_append(p, phdr, s);

    /* we inserted what was asked for */
    return what;
}

static int dav_fs_is_writable(const dav_resource *resource, int propid)
{
    const dav_liveprop_spec *info;

#ifdef DAV_FS_HAS_EXECUTABLE
    /* if we have the executable property, and this isn't a collection,
       then the property is writable. */
    if (propid == DAV_PROPID_FS_executable && !resource->collection)
        return 1;
#endif

    (void) dav_get_liveprop_info(propid, &dav_fs_liveprop_group, &info);
    return info->is_writable;
}

static dav_error *dav_fs_patch_validate(const dav_resource *resource,
                                        const apr_xml_elem *elem,
                                        int operation,
                                        void **context,
                                        int *defer_to_dead)
{
    const apr_text *cdata;
    const apr_text *f_cdata;
    char value;
    dav_elem_private *priv = elem->priv;

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

    *context = (void *)((long)(value == 'T'));

    return NULL;

  too_long:
    return dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
                         "The 'executable' property expects a single "
                         "character, valued 'T' or 'F'. The value submitted "
                         "has too many characters.");

}

static dav_error *dav_fs_patch_exec(const dav_resource *resource,
                                    const apr_xml_elem *elem,
                                    int operation,
                                    void *context,
                                    dav_liveprop_rollback **rollback_ctx)
{
    long value = context != NULL;
    apr_fileperms_t perms = resource->info->finfo.protection;
    long old_value = (perms & APR_UEXECUTE) != 0;

    /* assert: prop == executable. operation == SET. */

    /* don't do anything if there is no change. no rollback info either. */
    /* DBG2("new value=%d  (old=%d)", value, old_value); */
    if (value == old_value)
        return NULL;

    perms &= ~APR_UEXECUTE;
    if (value)
        perms |= APR_UEXECUTE;

    if (apr_file_perms_set(resource->info->pathname, perms) != APR_SUCCESS) {
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

static void dav_fs_patch_commit(const dav_resource *resource,
                                int operation,
                                void *context,
                                dav_liveprop_rollback *rollback_ctx)
{
    /* nothing to do */
}

static dav_error *dav_fs_patch_rollback(const dav_resource *resource,
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

    if (apr_file_perms_set(resource->info->pathname, perms) != APR_SUCCESS) {
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
    dav_fs_insert_prop,
    dav_fs_is_writable,
    dav_fs_namespace_uris,
    dav_fs_patch_validate,
    dav_fs_patch_exec,
    dav_fs_patch_commit,
    dav_fs_patch_rollback
};

static const dav_provider dav_fs_provider =
{
    &dav_hooks_repository_fs,
    &dav_hooks_db_dbm,
    &dav_hooks_locks_fs,
    NULL,               /* vsn */
    NULL,               /* binding */
    NULL,               /* search */

    NULL                /* ctx */
};

void dav_fs_gather_propsets(apr_array_header_t *uris)
{
#ifdef DAV_FS_HAS_EXECUTABLE
    *(const char **)apr_array_push(uris) =
        "<http://apache.org/dav/propset/fs/1>";
#endif
}

int dav_fs_find_liveprop(const dav_resource *resource,
                         const char *ns_uri, const char *name,
                         const dav_hooks_liveprop **hooks)
{
    /* don't try to find any liveprops if this isn't "our" resource */
    if (resource->hooks != &dav_hooks_repository_fs)
        return 0;
    return dav_do_find_liveprop(ns_uri, name, &dav_fs_liveprop_group, hooks);
}

void dav_fs_insert_all_liveprops(request_rec *r, const dav_resource *resource,
                                 dav_prop_insert what, apr_text_header *phdr)
{
    /* don't insert any liveprops if this isn't "our" resource */
    if (resource->hooks != &dav_hooks_repository_fs)
        return;

    if (!resource->exists) {
        /* a lock-null resource */
        /*
        ** ### technically, we should insert empty properties. dunno offhand
        ** ### what part of the spec said this, but it was essentially thus:
        ** ### "the properties should be defined, but may have no value".
        */
        return;
    }

    (void) dav_fs_insert_prop(resource, DAV_PROPID_creationdate,
                              what, phdr);
    (void) dav_fs_insert_prop(resource, DAV_PROPID_getcontentlength,
                              what, phdr);
    (void) dav_fs_insert_prop(resource, DAV_PROPID_getlastmodified,
                              what, phdr);
    (void) dav_fs_insert_prop(resource, DAV_PROPID_getetag,
                              what, phdr);

#ifdef DAV_FS_HAS_EXECUTABLE
    /* Only insert this property if it is defined for this platform. */
    (void) dav_fs_insert_prop(resource, DAV_PROPID_FS_executable,
                              what, phdr);
#endif

    /* ### we know the others aren't defined as liveprops */
}

void dav_fs_register(apr_pool_t *p)
{
    /* register the namespace URIs */
    dav_register_liveprop_group(p, &dav_fs_liveprop_group);

    /* register the repository provider */
    dav_register_provider(p, "filesystem", &dav_fs_provider);
}
