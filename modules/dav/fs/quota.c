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
** DAV filesystem-based quota routines
*/

#include "apr.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_log.h"
#include "http_main.h"

#include "mod_dav.h"
#include "repos.h"

/*
 * Just use a configure test? fields have been standardized for
 * while: https://pubs.opengroup.org/onlinepubs/7908799/xsh/sysstatvfs.h.html
 */
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(OpenBSD) || \
    defined(linux)
#include <sys/statvfs.h>
#define HAVE_STATVFS
#endif

#define DAV_TRUE                1
#define DAV_FALSE               0

/* Forwared declaration, since it calls itself */
static apr_status_t get_dir_used_bytes_walk(request_rec *r,
                                            const char *path,
                                            apr_off_t *used);

static apr_status_t get_dir_used_bytes_walk(request_rec *r,
                                            const char *path,
                                            apr_off_t *used)
{
    apr_dir_t *dir = NULL;
    apr_finfo_t finfo;
    apr_status_t rv;

    if ((rv = apr_dir_open(&dir, path, r->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "failed to open \"%s\"", path);
        goto out;
    }

    do {
        apr_int32_t wanted;
        char *newpath;

        wanted = APR_FINFO_DIRENT|APR_FINFO_TYPE|APR_FINFO_SIZE|APR_FINFO_NAME;
        rv = apr_dir_read(&finfo, wanted, dir);
        if (rv != APR_SUCCESS && rv != APR_INCOMPLETE)
            break;

        if (finfo.valid & APR_FINFO_NAME == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Cannot get entry name in \"%s\"", path);
            goto out;
        }

        if (!strcmp(finfo.name, ".") ||
            !strcmp(finfo.name, "..") ||
            !strcmp(finfo.name, DAV_FS_STATE_DIR) ||
            !strncmp(finfo.name, DAV_FS_TMP_PREFIX, strlen(DAV_FS_TMP_PREFIX)))
            continue;

        if (finfo.valid & APR_FINFO_TYPE == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Cannot get entry type in \"%s\"", path);
            goto out;
        }

        switch (finfo.filetype) {
        case APR_REG:
            if (finfo.valid & APR_FINFO_SIZE == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Cannot get entry size in \"%s\"", path);
                goto out;
            }
            *used += finfo.size;
            break;

        case APR_DIR:
            if (finfo.valid & APR_FINFO_NAME == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Cannot get entry name in \"%s\"", path);
                goto out;
            }

            rv = apr_filepath_merge(&newpath, path, finfo.name, 0, r->pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "apr_filepath_merge \"%s\" \"%s\" failed",
                              path, finfo.name);
                goto out;
            }

            rv = get_dir_used_bytes_walk(r, newpath, used);
            if (rv != APR_SUCCESS)
                goto out;
            break;

        default:
            /* skip other types */
            break;
        }
    } while (1 /* CONSTCOND */);

    if (rv == APR_ENOENT)
        rv = APR_SUCCESS;
    else
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "apr_dir_read failed on \"%s\"", path);
out:
    if (dir)
        (void)apr_dir_close(dir);

    return rv;
}

static apr_off_t get_dir_used_bytes(request_rec *r, const char *path)
{
    apr_off_t used_bytes = 0;
    apr_status_t rv;

    rv = get_dir_used_bytes_walk(r, path, &used_bytes);

out:
    return (rv == APR_SUCCESS) ? used_bytes : DAV_FS_BYTES_ERROR;
}

static apr_off_t get_fs_used_bytes(const char *path)
{
    apr_off_t used_bytes = DAV_FS_BYTES_ERROR;
#ifdef HAVE_STATVFS
    struct statvfs f;

    if (statvfs(path, &f) != 0)
        goto out;

#ifdef __NetBSD__
    used_bytes = (f.f_blocks - f.f_bfree) * f.f_frsize;
#else
    used_bytes = (f.f_blocks - f.f_bfree) * f.f_bsize;
#endif

#endif
out:
    return used_bytes;
}

static apr_off_t get_fs_available_bytes(const char *path)
{
    apr_off_t available_bytes = DAV_FS_BYTES_ERROR;
#ifdef HAVE_STATVFS
    struct statvfs f;

    if (statvfs(path, &f) != 0)
        goto out;

#ifdef __NetBSD__
    available_bytes = f.f_bavail * f.f_frsize;
#else
    available_bytes = f.f_bavail * f.f_bsize;
#endif
#endif
out:
    return available_bytes;
}

apr_off_t dav_fs_get_used_bytes(request_rec *r, const char *path)
{
    apr_off_t quota;
    apr_off_t used_bytes = DAV_FS_BYTES_ERROR;

    if (dav_fs_get_quota(r, path, &quota) != NULL)
        goto out;

    switch (quota) {
    case DAV_FS_QUOTA_UNSET: /* FALLTHOTUGH */
    case DAV_FS_QUOTA_OFF:
        break;

    case DAV_FS_QUOTA_NONE:;
        used_bytes = get_fs_used_bytes(path);
        break;

    default:
        used_bytes = get_dir_used_bytes(r, path);
        break;
    }

out:
    return used_bytes;
}

apr_off_t dav_fs_get_available_bytes(request_rec *r,
                                     const char *path, int *fs_low)
{
    apr_off_t quota;
    apr_off_t used_bytes;
    apr_off_t fs_available_bytes;
    apr_off_t available_bytes = DAV_FS_BYTES_ERROR;
    int _fs_low = DAV_FALSE;

    if (dav_fs_get_quota(r, path, &quota) != NULL)
        goto out;

    switch (quota) {
    case DAV_FS_QUOTA_UNSET: /* FALLTHROUGH */
    case DAV_FS_QUOTA_OFF:
        break;

    case DAV_FS_QUOTA_NONE:
        available_bytes = get_fs_available_bytes(path);
        if (available_bytes != DAV_FS_BYTES_ERROR)
            _fs_low = DAV_TRUE;
        break;

    default:
        used_bytes = get_dir_used_bytes(r, path);
        if (used_bytes != DAV_FS_BYTES_ERROR) {
            if (used_bytes > quota)
                available_bytes = 0;
            else
                available_bytes = quota - used_bytes;

            /*
             * Use available space from filesystem rather than quota
             * if it is smaller
             */
            fs_available_bytes = get_fs_available_bytes(path);
            if (fs_available_bytes != DAV_FS_BYTES_ERROR) {
                if (fs_available_bytes < available_bytes) {
                    available_bytes = fs_available_bytes;
                    _fs_low = DAV_TRUE;
                }
            }
        }
        break;
    }

out:
    if (available_bytes != DAV_FS_BYTES_ERROR && fs_low)
        *fs_low = _fs_low;

    return available_bytes;
}


int dav_fs_quota_precondition(request_rec *r,
                              dav_resource *src, const dav_resource *dst,
                              const apr_xml_doc *doc, dav_error **err)
{
    apr_off_t quota;
    apr_off_t used_bytes;
    apr_off_t available_bytes;
    apr_off_t size;
    const char *path;
    const char *lenhdr;
    const char *tag;
    const char *msg;
    apr_status_t rv;
    int status = DECLINED;
    int fs_low;

    if (r->method_number == M_COPY || r->method_number == M_MOVE) {
        /*
         * dav_method_copymove() calls dav_run_method_precondition()
         * twice, with dst NULL on first call and set on the second call.
         */
        if (dst == NULL)
             goto out;
        path = dav_fs_fname(dst);
    } else {
        path = dav_fs_fname(src);
    }

    path = ap_make_dirstr_parent(r->pool, path);
    if ((*err = dav_fs_get_quota(r, path, &quota)) != NULL)
        goto out;

    if (quota == DAV_FS_QUOTA_OFF || quota == DAV_FS_QUOTA_UNSET)
        goto out;

    available_bytes = dav_fs_get_available_bytes(r, path, &fs_low);
    if (available_bytes == DAV_FS_BYTES_ERROR) {
        if (quota != DAV_FS_QUOTA_NONE) {
            status = HTTP_INTERNAL_SERVER_ERROR;
            *err = dav_new_error(r->pool, status, 0, 0,
                                 "Quota enabled, but failed to compute "
                                 "available space.");
        }
        goto out;
    }

    tag = fs_low ? "sufficient-disk-space" : "quota-not-exceeded";
    msg = fs_low ? "Insufficient disk space" : "Quota exceeded";

    /*
     * For all operations, report overquota before the operation.
     */
    if (available_bytes == 0) {
        status = HTTP_INSUFFICIENT_STORAGE;
        *err = dav_new_error_tag(r->pool, status, 0, 0,
                                 msg, NULL, tag);
        goto out;
    }

    switch (r->method_number) {
    case M_PUT:
        /*
         * If PUT has Content-Length, we can forecast overquota
         */
        if ((lenhdr = apr_table_get(r->headers_in, "Content-Length")) &&
            (atol(lenhdr) > available_bytes)) {
            status = HTTP_INSUFFICIENT_STORAGE;
            *err = dav_new_error_tag(r->pool, status, 0, 0,
                                     msg, NULL, tag);
            goto out;
        }
        break;
    case M_COPY: /* FALLTHROUGH */
    case M_MOVE:
        /*
         * If source size is known, we can forecast ovequota
         */
        if ((size = dav_fs_size(src) != DAV_FS_BYTES_ERROR) &&
            (size > available_bytes)) {
            status = HTTP_INSUFFICIENT_STORAGE;
            *err = dav_new_error_tag(r->pool, status, 0, 0,
                                     msg, "DAV:", tag);
            goto out;
        }
        break;
    default:
        break;
    }

out:
    return status;
}
