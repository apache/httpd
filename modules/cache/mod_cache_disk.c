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

#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "mod_cache.h"
#include "mod_cache_disk.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "ap_provider.h"
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"

/*
 * mod_cache_disk: Disk Based HTTP 1.1 Cache.
 *
 * Flow to Find the .data file:
 *   Incoming client requests URI /foo/bar/baz
 *   Generate <hash> off of /foo/bar/baz
 *   Open <hash>.header
 *   Read in <hash>.header file (may contain Format #1 or Format #2)
 *   If format #1 (Contains a list of Vary Headers):
 *      Use each header name (from .header) with our request values (headers_in) to
 *      regenerate <hash> using HeaderName+HeaderValue+.../foo/bar/baz
 *      re-read in <hash>.header (must be format #2)
 *   read in <hash>.data
 *
 * Format #1:
 *   apr_uint32_t format;
 *   apr_time_t expire;
 *   apr_array_t vary_headers (delimited by CRLF)
 *
 * Format #2:
 *   disk_cache_info_t (first sizeof(apr_uint32_t) bytes is the format)
 *   entity name (dobj->name) [length is in disk_cache_info_t->name_len]
 *   r->headers_out (delimited by CRLF)
 *   CRLF
 *   r->headers_in (delimited by CRLF)
 *   CRLF
 */

module AP_MODULE_DECLARE_DATA cache_disk_module;

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *in,
                               apr_bucket_brigade *out);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);
static apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
                               apr_file_t *file);

/*
 * Local static functions
 */

static char *header_file(apr_pool_t *p, disk_cache_conf *conf,
                         disk_cache_object_t *dobj, const char *name)
{
    if (!dobj->hashfile) {
        dobj->hashfile = ap_cache_generate_name(p, conf->dirlevels,
                                                conf->dirlength, name);
    }

    if (dobj->prefix) {
        return apr_pstrcat(p, dobj->prefix, CACHE_VDIR_SUFFIX "/",
                           dobj->hashfile, CACHE_HEADER_SUFFIX, NULL);
     }
     else {
        return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
                           CACHE_HEADER_SUFFIX, NULL);
     }
}

static char *data_file(apr_pool_t *p, disk_cache_conf *conf,
                       disk_cache_object_t *dobj, const char *name)
{
    if (!dobj->hashfile) {
        dobj->hashfile = ap_cache_generate_name(p, conf->dirlevels,
                                                conf->dirlength, name);
    }

    if (dobj->prefix) {
        return apr_pstrcat(p, dobj->prefix, CACHE_VDIR_SUFFIX "/",
                           dobj->hashfile, CACHE_DATA_SUFFIX, NULL);
     }
     else {
        return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
                           CACHE_DATA_SUFFIX, NULL);
     }
}

static apr_status_t mkdir_structure(disk_cache_conf *conf, const char *file, apr_pool_t *pool)
{
    apr_status_t rv;
    char *p;

    for (p = (char*)file + conf->cache_root_len + 1;;) {
        p = strchr(p, '/');
        if (!p)
            break;
        *p = '\0';

        rv = apr_dir_make(file,
                          APR_UREAD|APR_UWRITE|APR_UEXECUTE, pool);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_EEXIST(rv)) {
            return rv;
        }
        *p = '/';
        ++p;
    }
    return APR_SUCCESS;
}

/* htcacheclean may remove directories underneath us.
 * So, we'll try renaming three times at a cost of 0.002 seconds.
 */
static apr_status_t safe_file_rename(disk_cache_conf *conf,
                                     const char *src, const char *dest,
                                     apr_pool_t *pool)
{
    apr_status_t rv;

    rv = apr_file_rename(src, dest, pool);

    if (rv != APR_SUCCESS) {
        int i;

        for (i = 0; i < 2 && rv != APR_SUCCESS; i++) {
            /* 1000 micro-seconds aka 0.001 seconds. */
            apr_sleep(1000);

            rv = mkdir_structure(conf, dest, pool);
            if (rv != APR_SUCCESS)
                continue;

            rv = apr_file_rename(src, dest, pool);
        }
    }

    return rv;
}

static apr_status_t file_cache_el_final(disk_cache_conf *conf, disk_cache_file_t *file,
                                        request_rec *r)
{
    apr_status_t rv = APR_SUCCESS;

    /* This assumes that the tempfiles are on the same file system
     * as the cache_root. If not, then we need a file copy/move
     * rather than a rename.
     */

    /* move the file over */
    if (file->tempfd) {

        rv = safe_file_rename(conf, file->tempfile, file->file, file->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00699)
                    "rename tempfile to file failed:"
                    " %s -> %s", file->tempfile, file->file);
            apr_file_remove(file->tempfile, file->pool);
        }

        file->tempfd = NULL;
    }

    return rv;
}

static apr_status_t file_cache_temp_cleanup(void *dummy)
{
    disk_cache_file_t *file = (disk_cache_file_t *)dummy;

    /* clean up the temporary file */
    if (file->tempfd) {
        apr_file_remove(file->tempfile, file->pool);
        file->tempfd = NULL;
    }
    file->tempfile = NULL;
    file->pool = NULL;

    return APR_SUCCESS;
}

static apr_status_t file_cache_create(disk_cache_conf *conf, disk_cache_file_t *file,
                                      apr_pool_t *pool)
{
    file->pool = pool;
    file->tempfile = apr_pstrcat(pool, conf->cache_root, AP_TEMPFILE, NULL);

    apr_pool_cleanup_register(pool, file, file_cache_temp_cleanup, apr_pool_cleanup_null);

    return APR_SUCCESS;
}

/* These two functions get and put state information into the data
 * file for an ap_cache_el, this state information will be read
 * and written transparent to clients of this module
 */
static int file_cache_recall_mydata(apr_file_t *fd, cache_info *info,
                                    disk_cache_object_t *dobj, request_rec *r)
{
    apr_status_t rv;
    char *urlbuff;
    apr_size_t len;

    /* read the data from the cache file */
    len = sizeof(disk_cache_info_t);
    rv = apr_file_read_full(fd, &dobj->disk_info, len, &len);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* Store it away so we can get it later. */
    info->status = dobj->disk_info.status;
    info->date = dobj->disk_info.date;
    info->expire = dobj->disk_info.expire;
    info->request_time = dobj->disk_info.request_time;
    info->response_time = dobj->disk_info.response_time;

    memcpy(&info->control, &dobj->disk_info.control, sizeof(cache_control_t));

    /* Note that we could optimize this by conditionally doing the palloc
     * depending upon the size. */
    urlbuff = apr_palloc(r->pool, dobj->disk_info.name_len + 1);
    len = dobj->disk_info.name_len;
    rv = apr_file_read_full(fd, urlbuff, len, &len);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    urlbuff[dobj->disk_info.name_len] = '\0';

    /* check that we have the same URL */
    /* Would strncmp be correct? */
    if (strcmp(urlbuff, dobj->name) != 0) {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static const char* regen_key(apr_pool_t *p, apr_table_t *headers,
                             apr_array_header_t *varray, const char *oldkey)
{
    struct iovec *iov;
    int i, k;
    int nvec;
    const char *header;
    const char **elts;

    nvec = (varray->nelts * 2) + 1;
    iov = apr_palloc(p, sizeof(struct iovec) * nvec);
    elts = (const char **) varray->elts;

    /* TODO:
     *    - Handle multiple-value headers better. (sort them?)
     *    - Handle Case in-sensitive Values better.
     *        This isn't the end of the world, since it just lowers the cache
     *        hit rate, but it would be nice to fix.
     *
     * The majority are case insenstive if they are values (encoding etc).
     * Most of rfc2616 is case insensitive on header contents.
     *
     * So the better solution may be to identify headers which should be
     * treated case-sensitive?
     *  HTTP URI's (3.2.3) [host and scheme are insensitive]
     *  HTTP method (5.1.1)
     *  HTTP-date values (3.3.1)
     *  3.7 Media Types [excerpt]
     *     The type, subtype, and parameter attribute names are case-
     *     insensitive. Parameter values might or might not be case-sensitive,
     *     depending on the semantics of the parameter name.
     *  4.20 Except [excerpt]
     *     Comparison of expectation values is case-insensitive for unquoted
     *     tokens (including the 100-continue token), and is case-sensitive for
     *     quoted-string expectation-extensions.
     */

    for (i=0, k=0; i < varray->nelts; i++) {
        header = apr_table_get(headers, elts[i]);
        if (!header) {
            header = "";
        }
        iov[k].iov_base = (char*) elts[i];
        iov[k].iov_len = strlen(elts[i]);
        k++;
        iov[k].iov_base = (char*) header;
        iov[k].iov_len = strlen(header);
        k++;
    }
    iov[k].iov_base = (char*) oldkey;
    iov[k].iov_len = strlen(oldkey);
    k++;

    return apr_pstrcatv(p, iov, k, NULL);
}

static int array_alphasort(const void *fn1, const void *fn2)
{
    return strcmp(*(char**)fn1, *(char**)fn2);
}

static void tokens_to_array(apr_pool_t *p, const char *data,
                            apr_array_header_t *arr)
{
    char *token;

    while ((token = ap_get_list_item(p, &data)) != NULL) {
        *((const char **) apr_array_push(arr)) = token;
    }

    /* Sort it so that "Vary: A, B" and "Vary: B, A" are stored the same. */
    qsort((void *) arr->elts, arr->nelts,
         sizeof(char *), array_alphasort);
}

/*
 * Hook and mod_cache callback functions
 */
static int create_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len,
                         apr_bucket_brigade *bb)
{
    disk_cache_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &cache_disk_module);
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_module);
    cache_object_t *obj;
    disk_cache_object_t *dobj;
    apr_pool_t *pool;

    if (conf->cache_root == NULL) {
        return DECLINED;
    }

    /* we don't support caching of range requests (yet) */
    if (r->status == HTTP_PARTIAL_CONTENT) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00700)
                "URL %s partial content response not cached",
                key);
        return DECLINED;
    }

    /* Note, len is -1 if unknown so don't trust it too hard */
    if (len > dconf->maxfs) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00701)
                "URL %s failed the size check "
                "(%" APR_OFF_T_FMT " > %" APR_OFF_T_FMT ")",
                key, len, dconf->maxfs);
        return DECLINED;
    }
    if (len >= 0 && len < dconf->minfs) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00702)
                "URL %s failed the size check "
                "(%" APR_OFF_T_FMT " < %" APR_OFF_T_FMT ")",
                key, len, dconf->minfs);
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t and disk_cache_object_t */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

    obj->key = apr_pstrdup(r->pool, key);

    dobj->name = obj->key;
    dobj->prefix = NULL;
    /* Save the cache root */
    dobj->root = apr_pstrmemdup(r->pool, conf->cache_root, conf->cache_root_len);
    dobj->root_len = conf->cache_root_len;

    apr_pool_create(&pool, r->pool);
    apr_pool_tag(pool, "mod_cache (create_entity)");

    file_cache_create(conf, &dobj->hdrs, pool);
    file_cache_create(conf, &dobj->vary, pool);
    file_cache_create(conf, &dobj->data, pool);

    dobj->data.file = data_file(r->pool, conf, dobj, key);
    dobj->hdrs.file = header_file(r->pool, conf, dobj, key);
    dobj->vary.file = header_file(r->pool, conf, dobj, key);

    dobj->disk_info.header_only = r->header_only;

    return OK;
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
{
    apr_uint32_t format;
    apr_size_t len;
    const char *nkey;
    apr_status_t rc;
    static int error_logged = 0;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_module);
#ifdef APR_SENDFILE_ENABLED
    core_dir_config *coreconf = ap_get_core_module_config(r->per_dir_config);
#endif
    apr_finfo_t finfo;
    cache_object_t *obj;
    cache_info *info;
    disk_cache_object_t *dobj;
    int flags;
    apr_pool_t *pool;

    h->cache_obj = NULL;

    /* Look up entity keyed to 'url' */
    if (conf->cache_root == NULL) {
        if (!error_logged) {
            error_logged = 1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00703)
                    "Cannot cache files to disk without a CacheRoot specified.");
        }
        return DECLINED;
    }

    /* Create and init the cache object */
    obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));

    info = &(obj->info);

    /* Open the headers file */
    dobj->prefix = NULL;

    /* Save the cache root */
    dobj->root = apr_pstrmemdup(r->pool, conf->cache_root, conf->cache_root_len);
    dobj->root_len = conf->cache_root_len;

    dobj->vary.file = header_file(r->pool, conf, dobj, key);
    flags = APR_READ|APR_BINARY|APR_BUFFERED;
    rc = apr_file_open(&dobj->vary.fd, dobj->vary.file, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        return DECLINED;
    }

    /* read the format from the cache file */
    len = sizeof(format);
    apr_file_read_full(dobj->vary.fd, &format, len, &len);

    if (format == VARY_FORMAT_VERSION) {
        apr_array_header_t* varray;
        apr_time_t expire;

        len = sizeof(expire);
        apr_file_read_full(dobj->vary.fd, &expire, len, &len);

        varray = apr_array_make(r->pool, 5, sizeof(char*));
        rc = read_array(r, varray, dobj->vary.fd);
        if (rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(00704)
                    "Cannot parse vary header file: %s",
                    dobj->vary.file);
            apr_file_close(dobj->vary.fd);
            return DECLINED;
        }
        apr_file_close(dobj->vary.fd);

        nkey = regen_key(r->pool, r->headers_in, varray, key);

        dobj->hashfile = NULL;
        dobj->prefix = dobj->vary.file;
        dobj->hdrs.file = header_file(r->pool, conf, dobj, nkey);

        flags = APR_READ|APR_BINARY|APR_BUFFERED;
        rc = apr_file_open(&dobj->hdrs.fd, dobj->hdrs.file, flags, 0, r->pool);
        if (rc != APR_SUCCESS) {
            return DECLINED;
        }
    }
    else if (format != DISK_FORMAT_VERSION) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00705)
                "File '%s' has a version mismatch. File had version: %d.",
                dobj->vary.file, format);
        apr_file_close(dobj->vary.fd);
        return DECLINED;
    }
    else {
        apr_off_t offset = 0;

        /* oops, not vary as it turns out */
        dobj->hdrs.fd = dobj->vary.fd;
        dobj->vary.fd = NULL;
        dobj->hdrs.file = dobj->vary.file;

        /* This wasn't a Vary Format file, so we must seek to the
         * start of the file again, so that later reads work.
         */
        apr_file_seek(dobj->hdrs.fd, APR_SET, &offset);
        nkey = key;
    }

    obj->key = nkey;
    dobj->key = nkey;
    dobj->name = key;

    apr_pool_create(&pool, r->pool);
    apr_pool_tag(pool, "mod_cache (open_entity)");

    file_cache_create(conf, &dobj->hdrs, pool);
    file_cache_create(conf, &dobj->vary, pool);
    file_cache_create(conf, &dobj->data, pool);

    dobj->data.file = data_file(r->pool, conf, dobj, nkey);

    /* Read the bytes to setup the cache_info fields */
    rc = file_cache_recall_mydata(dobj->hdrs.fd, info, dobj, r);
    if (rc != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(00706)
                "Cannot read header file %s", dobj->hdrs.file);
        apr_file_close(dobj->hdrs.fd);
        return DECLINED;
    }


    /* Is this a cached HEAD request? */
    if (dobj->disk_info.header_only && !r->header_only) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(00707)
                "HEAD request cached, non-HEAD requested, ignoring: %s",
                dobj->hdrs.file);
        apr_file_close(dobj->hdrs.fd);
        return DECLINED;
    }

    /* Open the data file */
    if (dobj->disk_info.has_body) {
        flags = APR_READ | APR_BINARY;
#ifdef APR_SENDFILE_ENABLED
        /* When we are in the quick handler we don't have the per-directory
         * configuration, so this check only takes the global setting of
         * the EnableSendFile directive into account.
         */
        flags |= AP_SENDFILE_ENABLED(coreconf->enable_sendfile);
#endif
        rc = apr_file_open(&dobj->data.fd, dobj->data.file, flags, 0, r->pool);
        if (rc != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(00708)
                    "Cannot open data file %s", dobj->data.file);
            apr_file_close(dobj->hdrs.fd);
            return DECLINED;
        }

        rc = apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_IDENT,
                dobj->data.fd);
        if (rc == APR_SUCCESS) {
            dobj->file_size = finfo.size;
        }

        /* Atomic check - does the body file belong to the header file? */
        if (dobj->disk_info.inode == finfo.inode &&
                dobj->disk_info.device == finfo.device) {

            /* Initialize the cache_handle callback functions */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00709)
                    "Recalled cached URL info header %s", dobj->name);

            /* make the configuration stick */
            h->cache_obj = obj;
            obj->vobj = dobj;

            return OK;
        }

    }
    else {

        /* make the configuration stick */
        h->cache_obj = obj;
        obj->vobj = dobj;

        return OK;
    }

    /* Oh dear, no luck matching header to the body */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00710)
            "Cached URL info header '%s' didn't match body, ignoring this entry",
            dobj->name);

    apr_file_close(dobj->hdrs.fd);
    return DECLINED;
}

static void close_disk_cache_fd(disk_cache_file_t *file)
{
   if (file->fd != NULL) {
       apr_file_close(file->fd);
       file->fd = NULL;
   }
   if (file->tempfd != NULL) {
       apr_file_close(file->tempfd);
       file->tempfd = NULL;
   }
}

static int remove_entity(cache_handle_t *h)
{
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    close_disk_cache_fd(&(dobj->hdrs));
    close_disk_cache_fd(&(dobj->vary));
    close_disk_cache_fd(&(dobj->data));

    /* Null out the cache object pointer so next time we start from scratch  */
    h->cache_obj = NULL;
    return OK;
}

static int remove_url(cache_handle_t *h, request_rec *r)
{
    apr_status_t rc;
    disk_cache_object_t *dobj;

    /* Get disk cache object from cache handle */
    dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    if (!dobj) {
        return DECLINED;
    }

    /* Delete headers file */
    if (dobj->hdrs.file) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00711)
                "Deleting %s from cache.", dobj->hdrs.file);

        rc = apr_file_remove(dobj->hdrs.file, r->pool);
        if ((rc != APR_SUCCESS) && !APR_STATUS_IS_ENOENT(rc)) {
            /* Will only result in an output if httpd is started with -e debug.
             * For reason see log_error_core for the case s == NULL.
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r, APLOGNO(00712)
                    "Failed to delete headers file %s from cache.",
                    dobj->hdrs.file);
            return DECLINED;
        }
    }

    /* Delete data file */
    if (dobj->data.file) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00713)
                "Deleting %s from cache.", dobj->data.file);

        rc = apr_file_remove(dobj->data.file, r->pool);
        if ((rc != APR_SUCCESS) && !APR_STATUS_IS_ENOENT(rc)) {
            /* Will only result in an output if httpd is started with -e debug.
             * For reason see log_error_core for the case s == NULL.
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r, APLOGNO(00714)
                    "Failed to delete data file %s from cache.",
                    dobj->data.file);
            return DECLINED;
        }
    }

    /* now delete directories as far as possible up to our cache root */
    if (dobj->root) {
        const char *str_to_copy;

        str_to_copy = dobj->hdrs.file ? dobj->hdrs.file : dobj->data.file;
        if (str_to_copy) {
            char *dir, *slash, *q;

            dir = apr_pstrdup(r->pool, str_to_copy);

            /* remove filename */
            slash = strrchr(dir, '/');
            *slash = '\0';

            /*
             * now walk our way back to the cache root, delete everything
             * in the way as far as possible
             *
             * Note: due to the way we constructed the file names in
             * header_file and data_file, we are guaranteed that the
             * cache_root is suffixed by at least one '/' which will be
             * turned into a terminating null by this loop.  Therefore,
             * we won't either delete or go above our cache root.
             */
            for (q = dir + dobj->root_len; *q ; ) {
                 ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00715)
                        "Deleting directory %s from cache", dir);

                 rc = apr_dir_remove(dir, r->pool);
                 if (rc != APR_SUCCESS && !APR_STATUS_IS_ENOENT(rc)) {
                    break;
                 }
                 slash = strrchr(q, '/');
                 *slash = '\0';
            }
        }
    }

    return OK;
}

static apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
                               apr_file_t *file)
{
    char w[MAX_STRING_LEN];
    apr_size_t p;
    apr_status_t rv;

    while (1) {
        rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00716)
                          "Premature end of vary array.");
            return rv;
        }

        p = strlen(w);
        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == CR) {
                w[p - 2] = '\0';
            }
            else {
                w[p - 1] = '\0';
            }
        }

        /* If we've finished reading the array, break out of the loop. */
        if (w[0] == '\0') {
            break;
        }

        *((const char **) apr_array_push(arr)) = apr_pstrdup(r->pool, w);
    }

    return APR_SUCCESS;
}

static apr_status_t store_array(apr_file_t *fd, apr_array_header_t* arr)
{
    int i;
    apr_status_t rv;
    struct iovec iov[2];
    apr_size_t amt;
    const char **elts;

    elts = (const char **) arr->elts;

    for (i = 0; i < arr->nelts; i++) {
        iov[0].iov_base = (char*) elts[i];
        iov[0].iov_len = strlen(elts[i]);
        iov[1].iov_base = CRLF;
        iov[1].iov_len = sizeof(CRLF) - 1;

        rv = apr_file_writev_full(fd, (const struct iovec *) &iov, 2, &amt);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    iov[0].iov_base = CRLF;
    iov[0].iov_len = sizeof(CRLF) - 1;

    return apr_file_writev_full(fd, (const struct iovec *) &iov, 1, &amt);
}

static apr_status_t read_table(cache_handle_t *handle, request_rec *r,
                               apr_table_t *table, apr_file_t *file)
{
    char w[MAX_STRING_LEN];
    char *l;
    apr_size_t p;
    apr_status_t rv;

    while (1) {

        /* ### What about APR_EOF? */
        rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00717)
                          "Premature end of cache headers.");
            return rv;
        }

        /* Delete terminal (CR?)LF */

        p = strlen(w);
        /* Indeed, the host's '\n':
           '\012' for UNIX; '\015' for MacOS; '\025' for OS/390
           -- whatever the script generates.
        */
        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == CR) {
                w[p - 2] = '\0';
            }
            else {
                w[p - 1] = '\0';
            }
        }

        /* If we've finished reading the headers, break out of the loop. */
        if (w[0] == '\0') {
            break;
        }

#if APR_CHARSET_EBCDIC
        /* Chances are that we received an ASCII header text instead of
         * the expected EBCDIC header lines. Try to auto-detect:
         */
        if (!(l = strchr(w, ':'))) {
            int maybeASCII = 0, maybeEBCDIC = 0;
            unsigned char *cp, native;
            apr_size_t inbytes_left, outbytes_left;

            for (cp = w; *cp != '\0'; ++cp) {
                native = apr_xlate_conv_byte(ap_hdrs_from_ascii, *cp);
                if (apr_isprint(*cp) && !apr_isprint(native))
                    ++maybeEBCDIC;
                if (!apr_isprint(*cp) && apr_isprint(native))
                    ++maybeASCII;
            }
            if (maybeASCII > maybeEBCDIC) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00718)
                        "CGI Interface Error: Script headers apparently ASCII: (CGI = %s)",
                        r->filename);
                inbytes_left = outbytes_left = cp - w;
                apr_xlate_conv_buffer(ap_hdrs_from_ascii,
                                      w, &inbytes_left, w, &outbytes_left);
            }
        }
#endif /*APR_CHARSET_EBCDIC*/

        /* if we see a bogus header don't ignore it. Shout and scream */
        if (!(l = strchr(w, ':'))) {
            return APR_EGENERAL;
        }

        *l++ = '\0';
        while (apr_isspace(*l)) {
            ++l;
        }

        apr_table_add(table, w, l);
    }

    return APR_SUCCESS;
}

/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 * This routine tries to deal with too long lines and continuation lines.
 * @@@: XXX: FIXME: currently the headers are passed thru un-merged.
 * Is that okay, or should they be collapsed where possible?
 */
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r)
{
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    apr_status_t rv;

    /* This case should not happen... */
    if (!dobj->hdrs.fd) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00719)
                "recalling headers; but no header fd for %s", dobj->name);
        return APR_NOTFOUND;
    }

    h->req_hdrs = apr_table_make(r->pool, 20);
    h->resp_hdrs = apr_table_make(r->pool, 20);

    /* Call routine to read the header lines/status line */
    rv = read_table(h, r, h->resp_hdrs, dobj->hdrs.fd);
    if (rv != APR_SUCCESS) { 
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02987) 
                      "Error reading response headers from %s for %s",
                      dobj->hdrs.file, dobj->name);
    }
    rv = read_table(h, r, h->req_hdrs, dobj->hdrs.fd);
    if (rv != APR_SUCCESS) { 
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02988) 
                      "Error reading request headers from %s for %s",
                      dobj->hdrs.file, dobj->name);
    }

    apr_file_close(dobj->hdrs.fd);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00720)
            "Recalled headers for URL %s", dobj->name);
    return APR_SUCCESS;
}

static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb)
{
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    if (dobj->data.fd) {
        apr_brigade_insert_file(bb, dobj->data.fd, 0, dobj->file_size, p);
    }

    return APR_SUCCESS;
}

static apr_status_t store_table(apr_file_t *fd, apr_table_t *table)
{
    int i;
    apr_status_t rv;
    struct iovec iov[4];
    apr_size_t amt;
    apr_table_entry_t *elts;

    elts = (apr_table_entry_t *) apr_table_elts(table)->elts;
    for (i = 0; i < apr_table_elts(table)->nelts; ++i) {
        if (elts[i].key != NULL) {
            iov[0].iov_base = elts[i].key;
            iov[0].iov_len = strlen(elts[i].key);
            iov[1].iov_base = ": ";
            iov[1].iov_len = sizeof(": ") - 1;
            iov[2].iov_base = elts[i].val;
            iov[2].iov_len = strlen(elts[i].val);
            iov[3].iov_base = CRLF;
            iov[3].iov_len = sizeof(CRLF) - 1;

            rv = apr_file_writev_full(fd, (const struct iovec *) &iov, 4, &amt);
            if (rv != APR_SUCCESS) {
                return rv;
            }
        }
    }
    iov[0].iov_base = CRLF;
    iov[0].iov_len = sizeof(CRLF) - 1;
    rv = apr_file_writev_full(fd, (const struct iovec *) &iov, 1, &amt);
    return rv;
}

static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    memcpy(&h->cache_obj->info, info, sizeof(cache_info));

    if (r->headers_out) {
        dobj->headers_out = ap_cache_cacheable_headers_out(r);
    }

    if (r->headers_in) {
        dobj->headers_in = ap_cache_cacheable_headers_in(r);
    }

    if (r->header_only && r->status != HTTP_NOT_MODIFIED) {
        dobj->disk_info.header_only = 1;
    }

    return APR_SUCCESS;
}

static apr_status_t write_headers(cache_handle_t *h, request_rec *r)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_module);
    apr_status_t rv;
    apr_size_t amt;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    disk_cache_info_t disk_info;
    struct iovec iov[2];

    memset(&disk_info, 0, sizeof(disk_cache_info_t));

    if (dobj->headers_out) {
        const char *tmp;

        tmp = apr_table_get(dobj->headers_out, "Vary");

        if (tmp) {
            apr_array_header_t* varray;
            apr_uint32_t format = VARY_FORMAT_VERSION;

            /* If we were initially opened as a vary format, rollback
             * that internal state for the moment so we can recreate the
             * vary format hints in the appropriate directory.
             */
            if (dobj->prefix) {
                dobj->hdrs.file = dobj->prefix;
                dobj->prefix = NULL;
            }

            rv = mkdir_structure(conf, dobj->hdrs.file, r->pool);
            if (rv == APR_SUCCESS) {
                rv = apr_file_mktemp(&dobj->vary.tempfd, dobj->vary.tempfile,
                                     APR_CREATE | APR_WRITE | APR_BINARY | APR_EXCL,
                                     dobj->vary.pool);
            }

            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00721)
                        "could not create vary file %s",
                        dobj->vary.tempfile);
                return rv;
            }

            amt = sizeof(format);
            rv = apr_file_write_full(dobj->vary.tempfd, &format, amt, NULL);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00722)
                        "could not write to vary file %s",
                        dobj->vary.tempfile);
                apr_file_close(dobj->vary.tempfd);
                apr_pool_destroy(dobj->vary.pool);
                return rv;
            }

            amt = sizeof(h->cache_obj->info.expire);
            rv = apr_file_write_full(dobj->vary.tempfd,
                                     &h->cache_obj->info.expire, amt, NULL);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00723)
                        "could not write to vary file %s",
                        dobj->vary.tempfile);
                apr_file_close(dobj->vary.tempfd);
                apr_pool_destroy(dobj->vary.pool);
                return rv;
            }

            varray = apr_array_make(r->pool, 6, sizeof(char*));
            tokens_to_array(r->pool, tmp, varray);

            store_array(dobj->vary.tempfd, varray);

            rv = apr_file_close(dobj->vary.tempfd);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00724)
                        "could not close vary file %s",
                        dobj->vary.tempfile);
                apr_pool_destroy(dobj->vary.pool);
                return rv;
            }

            tmp = regen_key(r->pool, dobj->headers_in, varray, dobj->name);
            dobj->prefix = dobj->hdrs.file;
            dobj->hashfile = NULL;
            dobj->data.file = data_file(r->pool, conf, dobj, tmp);
            dobj->hdrs.file = header_file(r->pool, conf, dobj, tmp);
        }
    }


    rv = apr_file_mktemp(&dobj->hdrs.tempfd, dobj->hdrs.tempfile,
                         APR_CREATE | APR_WRITE | APR_BINARY |
                         APR_BUFFERED | APR_EXCL, dobj->hdrs.pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00725)
                "could not create header file %s",
                dobj->hdrs.tempfile);
        return rv;
    }

    disk_info.format = DISK_FORMAT_VERSION;
    disk_info.date = h->cache_obj->info.date;
    disk_info.expire = h->cache_obj->info.expire;
    disk_info.entity_version = dobj->disk_info.entity_version++;
    disk_info.request_time = h->cache_obj->info.request_time;
    disk_info.response_time = h->cache_obj->info.response_time;
    disk_info.status = h->cache_obj->info.status;
    disk_info.inode = dobj->disk_info.inode;
    disk_info.device = dobj->disk_info.device;
    disk_info.has_body = dobj->disk_info.has_body;
    disk_info.header_only = dobj->disk_info.header_only;

    disk_info.name_len = strlen(dobj->name);

    memcpy(&disk_info.control, &h->cache_obj->info.control, sizeof(cache_control_t));

    iov[0].iov_base = (void*)&disk_info;
    iov[0].iov_len = sizeof(disk_cache_info_t);
    iov[1].iov_base = (void*)dobj->name;
    iov[1].iov_len = disk_info.name_len;

    rv = apr_file_writev_full(dobj->hdrs.tempfd, (const struct iovec *) &iov,
                              2, &amt);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00726)
                "could not write info to header file %s",
                dobj->hdrs.tempfile);
        apr_file_close(dobj->hdrs.tempfd);
        apr_pool_destroy(dobj->hdrs.pool);
        return rv;
    }

    if (dobj->headers_out) {
        rv = store_table(dobj->hdrs.tempfd, dobj->headers_out);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00727)
                    "could not write out-headers to header file %s",
                    dobj->hdrs.tempfile);
            apr_file_close(dobj->hdrs.tempfd);
            apr_pool_destroy(dobj->hdrs.pool);
            return rv;
        }
    }

    /* Parse the vary header and dump those fields from the headers_in. */
    /* FIXME: Make call to the same thing cache_select calls to crack Vary. */
    if (dobj->headers_in) {
        rv = store_table(dobj->hdrs.tempfd, dobj->headers_in);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00728)
                    "could not write in-headers to header file %s",
                    dobj->hdrs.tempfile);
            apr_file_close(dobj->hdrs.tempfd);
            apr_pool_destroy(dobj->hdrs.pool);
            return rv;
        }
    }

    rv = apr_file_close(dobj->hdrs.tempfd); /* flush and close */
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00729)
                "could not close header file %s",
                dobj->hdrs.tempfile);
        apr_pool_destroy(dobj->hdrs.pool);
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t store_body(cache_handle_t *h, request_rec *r,
                               apr_bucket_brigade *in, apr_bucket_brigade *out)
{
    apr_bucket *e;
    apr_status_t rv = APR_SUCCESS;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    disk_cache_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &cache_disk_module);
    int seen_eos = 0;

    if (!dobj->offset) {
        dobj->offset = dconf->readsize;
    }
    if (!dobj->timeout && dconf->readtime) {
        dobj->timeout = apr_time_now() + dconf->readtime;
    }

    if (dobj->offset) {
        apr_brigade_partition(in, dobj->offset, &e);
    }

    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(in)) {
        const char *str;
        apr_size_t length, written;

        e = APR_BRIGADE_FIRST(in);

        /* are we done completely? if so, pass any trailing buckets right through */
        if (dobj->done || !dobj->data.pool) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            continue;
        }

        /* have we seen eos yet? */
        if (APR_BUCKET_IS_EOS(e)) {
            seen_eos = 1;
            dobj->done = 1;
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            break;
        }

        /* honour flush buckets, we'll get called again */
        if (APR_BUCKET_IS_FLUSH(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            break;
        }

        /* metadata buckets are preserved as is */
        if (APR_BUCKET_IS_METADATA(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(out, e);
            continue;
        }

        /* read the bucket, write to the cache */
        rv = apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(out, e);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00730)
                    "Error when reading bucket for URL %s",
                    h->cache_obj->key);
            /* Remove the intermediate cache file and return non-APR_SUCCESS */
            apr_pool_destroy(dobj->data.pool);
            return rv;
        }

        /* don't write empty buckets to the cache */
        if (!length) {
            continue;
        }

        if (!dobj->disk_info.header_only) {

            /* Attempt to create the data file at the last possible moment, if
             * the body is empty, we don't write a file at all, and save an inode.
             */
            if (!dobj->data.tempfd) {
                apr_finfo_t finfo;
                rv = apr_file_mktemp(&dobj->data.tempfd, dobj->data.tempfile,
                        APR_CREATE | APR_WRITE | APR_BINARY | APR_BUFFERED
                                | APR_EXCL, dobj->data.pool);
                if (rv != APR_SUCCESS) {
                    apr_pool_destroy(dobj->data.pool);
                    return rv;
                }
                dobj->file_size = 0;
                rv = apr_file_info_get(&finfo, APR_FINFO_IDENT,
                        dobj->data.tempfd);
                if (rv != APR_SUCCESS) {
                    apr_pool_destroy(dobj->data.pool);
                    return rv;
                }
                dobj->disk_info.device = finfo.device;
                dobj->disk_info.inode = finfo.inode;
                dobj->disk_info.has_body = 1;
            }

            /* write to the cache, leave if we fail */
            rv = apr_file_write_full(dobj->data.tempfd, str, length, &written);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(
                        APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00731) "Error when writing cache file for URL %s", h->cache_obj->key);
                /* Remove the intermediate cache file and return non-APR_SUCCESS */
                apr_pool_destroy(dobj->data.pool);
                return rv;
            }
            dobj->file_size += written;
            if (dobj->file_size > dconf->maxfs) {
                ap_log_rerror(
                        APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00732) "URL %s failed the size check "
                        "(%" APR_OFF_T_FMT ">%" APR_OFF_T_FMT ")", h->cache_obj->key, dobj->file_size, dconf->maxfs);
                /* Remove the intermediate cache file and return non-APR_SUCCESS */
                apr_pool_destroy(dobj->data.pool);
                return APR_EGENERAL;
            }

        }

        /* have we reached the limit of how much we're prepared to write in one
         * go? If so, leave, we'll get called again. This prevents us from trying
         * to swallow too much data at once, or taking so long to write the data
         * the client times out.
         */
        dobj->offset -= length;
        if (dobj->offset <= 0) {
            dobj->offset = 0;
            break;
        }
        if ((dconf->readtime && apr_time_now() > dobj->timeout)) {
            dobj->timeout = 0;
            break;
        }

    }

    /* Was this the final bucket? If yes, close the temp file and perform
     * sanity checks.
     */
    if (seen_eos) {
        if (!dobj->disk_info.header_only) {
            const char *cl_header;
            apr_off_t cl;

            if (dobj->data.tempfd) {
                rv = apr_file_close(dobj->data.tempfd);
                if (rv != APR_SUCCESS) {
                    /* Buffered write failed, abandon attempt to write */
                    apr_pool_destroy(dobj->data.pool);
                    return rv;
                }
            }

            if (r->connection->aborted || r->no_cache) {
                ap_log_rerror(
                        APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00733) "Discarding body for URL %s "
                        "because connection has been aborted.", h->cache_obj->key);
                /* Remove the intermediate cache file and return non-APR_SUCCESS */
                apr_pool_destroy(dobj->data.pool);
                return APR_EGENERAL;
            }

            if (dobj->file_size < dconf->minfs) {
                ap_log_rerror(
                        APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00734) "URL %s failed the size check "
                        "(%" APR_OFF_T_FMT "<%" APR_OFF_T_FMT ")", h->cache_obj->key, dobj->file_size, dconf->minfs);
                /* Remove the intermediate cache file and return non-APR_SUCCESS */
                apr_pool_destroy(dobj->data.pool);
                return APR_EGENERAL;
            }

            cl_header = apr_table_get(r->headers_out, "Content-Length");
            if (cl_header && (!ap_parse_strict_length(&cl, cl_header)
                              || cl != dobj->file_size)) {
                ap_log_rerror(
                        APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00735) "URL %s didn't receive complete response, not caching", h->cache_obj->key);
                /* Remove the intermediate cache file and return non-APR_SUCCESS */
                apr_pool_destroy(dobj->data.pool);
                return APR_EGENERAL;
            }
        }

        /* All checks were fine, we're good to go when the commit comes */
    }

    return APR_SUCCESS;
}

static apr_status_t commit_entity(cache_handle_t *h, request_rec *r)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &cache_disk_module);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    apr_status_t rv;

    /* write the headers to disk at the last possible moment */
    rv = write_headers(h, r);

    /* move header and data tempfiles to the final destination */
    if (APR_SUCCESS == rv) {
        rv = file_cache_el_final(conf, &dobj->hdrs, r);
    }
    if (APR_SUCCESS == rv) {
        rv = file_cache_el_final(conf, &dobj->vary, r);
    }
    if (APR_SUCCESS == rv) {
        if (!dobj->disk_info.header_only) {
            rv = file_cache_el_final(conf, &dobj->data, r);
        }
        else if (dobj->data.file) {
            rv = apr_file_remove(dobj->data.file, dobj->data.pool);
        }
    }

    /* remove the cached items completely on any failure */
    if (APR_SUCCESS != rv) {
        remove_url(h, r);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00736)
                "commit_entity: URL '%s' not cached due to earlier disk error.",
                dobj->name);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00737)
                "commit_entity: Headers and body for URL %s cached.",
                dobj->name);
    }

    apr_pool_destroy(dobj->data.pool);

    return APR_SUCCESS;
}

static apr_status_t invalidate_entity(cache_handle_t *h, request_rec *r)
{
    apr_status_t rv;

    rv = recall_headers(h, r);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* mark the entity as invalidated */
    h->cache_obj->info.control.invalidated = 1;

    return commit_entity(h, r);
}

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    disk_cache_dir_conf *dconf = apr_pcalloc(p, sizeof(disk_cache_dir_conf));

    dconf->maxfs = DEFAULT_MAX_FILE_SIZE;
    dconf->minfs = DEFAULT_MIN_FILE_SIZE;
    dconf->readsize = DEFAULT_READSIZE;
    dconf->readtime = DEFAULT_READTIME;

    return dconf;
}

static void *merge_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    disk_cache_dir_conf *new = (disk_cache_dir_conf *) apr_pcalloc(p, sizeof(disk_cache_dir_conf));
    disk_cache_dir_conf *add = (disk_cache_dir_conf *) addv;
    disk_cache_dir_conf *base = (disk_cache_dir_conf *) basev;

    new->maxfs = (add->maxfs_set == 0) ? base->maxfs : add->maxfs;
    new->maxfs_set = add->maxfs_set || base->maxfs_set;
    new->minfs = (add->minfs_set == 0) ? base->minfs : add->minfs;
    new->minfs_set = add->minfs_set || base->minfs_set;
    new->readsize = (add->readsize_set == 0) ? base->readsize : add->readsize;
    new->readsize_set = add->readsize_set || base->readsize_set;
    new->readtime = (add->readtime_set == 0) ? base->readtime : add->readtime;
    new->readtime_set = add->readtime_set || base->readtime_set;

    return new;
}

static void *create_config(apr_pool_t *p, server_rec *s)
{
    disk_cache_conf *conf = apr_pcalloc(p, sizeof(disk_cache_conf));

    /* XXX: Set default values */
    conf->dirlevels = DEFAULT_DIRLEVELS;
    conf->dirlength = DEFAULT_DIRLENGTH;

    conf->cache_root = NULL;
    conf->cache_root_len = 0;

    return conf;
}

/*
 * mod_cache_disk configuration directives handlers.
 */
static const char
*set_cache_root(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &cache_disk_module);
    conf->cache_root = arg;
    conf->cache_root_len = strlen(arg);
    /* TODO: canonicalize cache_root and strip off any trailing slashes */

    return NULL;
}

/*
 * Consider eliminating the next two directives in favor of
 * Ian's prime number hash...
 * key = hash_fn( r->uri)
 * filename = "/key % prime1 /key %prime2/key %prime3"
 */
static const char
*set_cache_dirlevels(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &cache_disk_module);
    int val = atoi(arg);
    if (val < 1)
        return "CacheDirLevels value must be an integer greater than 0";
    if (val * conf->dirlength > CACHEFILE_LEN)
        return "CacheDirLevels*CacheDirLength value must not be higher than 20";
    conf->dirlevels = val;
    return NULL;
}
static const char
*set_cache_dirlength(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &cache_disk_module);
    int val = atoi(arg);
    if (val < 1)
        return "CacheDirLength value must be an integer greater than 0";
    if (val * conf->dirlevels > CACHEFILE_LEN)
        return "CacheDirLevels*CacheDirLength value must not be higher than 20";

    conf->dirlength = val;
    return NULL;
}

static const char
*set_cache_minfs(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_dir_conf *dconf = (disk_cache_dir_conf *)in_struct_ptr;

    if (apr_strtoff(&dconf->minfs, arg, NULL, 10) != APR_SUCCESS ||
            dconf->minfs < 0)
    {
        return "CacheMinFileSize argument must be a non-negative integer representing the min size of a file to cache in bytes.";
    }
    dconf->minfs_set = 1;
    return NULL;
}

static const char
*set_cache_maxfs(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_dir_conf *dconf = (disk_cache_dir_conf *)in_struct_ptr;

    if (apr_strtoff(&dconf->maxfs, arg, NULL, 10) != APR_SUCCESS ||
            dconf->maxfs < 0)
    {
        return "CacheMaxFileSize argument must be a non-negative integer representing the max size of a file to cache in bytes.";
    }
    dconf->maxfs_set = 1;
    return NULL;
}

static const char
*set_cache_readsize(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_dir_conf *dconf = (disk_cache_dir_conf *)in_struct_ptr;

    if (apr_strtoff(&dconf->readsize, arg, NULL, 10) != APR_SUCCESS ||
            dconf->readsize < 0)
    {
        return "CacheReadSize argument must be a non-negative integer representing the max amount of data to cache in go.";
    }
    dconf->readsize_set = 1;
    return NULL;
}

static const char
*set_cache_readtime(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_dir_conf *dconf = (disk_cache_dir_conf *)in_struct_ptr;
    apr_off_t milliseconds;

    if (apr_strtoff(&milliseconds, arg, NULL, 10) != APR_SUCCESS ||
            milliseconds < 0)
    {
        return "CacheReadTime argument must be a non-negative integer representing the max amount of time taken to cache in go.";
    }
    dconf->readtime = apr_time_from_msec(milliseconds);
    dconf->readtime_set = 1;
    return NULL;
}

static const command_rec disk_cache_cmds[] =
{
    AP_INIT_TAKE1("CacheRoot", set_cache_root, NULL, RSRC_CONF,
                 "The directory to store cache files"),
    AP_INIT_TAKE1("CacheDirLevels", set_cache_dirlevels, NULL, RSRC_CONF,
                  "The number of levels of subdirectories in the cache"),
    AP_INIT_TAKE1("CacheDirLength", set_cache_dirlength, NULL, RSRC_CONF,
                  "The number of characters in subdirectory names"),
    AP_INIT_TAKE1("CacheMinFileSize", set_cache_minfs, NULL, RSRC_CONF | ACCESS_CONF,
                  "The minimum file size to cache a document"),
    AP_INIT_TAKE1("CacheMaxFileSize", set_cache_maxfs, NULL, RSRC_CONF | ACCESS_CONF,
                  "The maximum file size to cache a document"),
    AP_INIT_TAKE1("CacheReadSize", set_cache_readsize, NULL, RSRC_CONF | ACCESS_CONF,
                  "The maximum quantity of data to attempt to read and cache in one go"),
    AP_INIT_TAKE1("CacheReadTime", set_cache_readtime, NULL, RSRC_CONF | ACCESS_CONF,
                  "The maximum time taken to attempt to read and cache in go"),
    {NULL}
};

static const cache_provider cache_disk_provider =
{
    &remove_entity,
    &store_headers,
    &store_body,
    &recall_headers,
    &recall_body,
    &create_entity,
    &open_entity,
    &remove_url,
    &commit_entity,
    &invalidate_entity
};

static void disk_cache_register_hook(apr_pool_t *p)
{
    /* cache initializer */
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "disk", "0",
                         &cache_disk_provider);
}

AP_DECLARE_MODULE(cache_disk) = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-directory config structure */
    merge_dir_config,           /* merge per-directory config structures */
    create_config,              /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    disk_cache_cmds,            /* command apr_table_t */
    disk_cache_register_hook    /* register hooks */
};
