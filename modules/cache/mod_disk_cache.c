/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_file_io.h"
#include "apr_strings.h"
#include "mod_cache.h"
#include "ap_provider.h"
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* needed for unlink/link */
#endif

/* Our on-disk header format is:
 *
 * disk_cache_info_t
 * entity name (dobj->name) [length is in disk_cache_info_t->name_len]
 * r->headers_out (delimited by CRLF)
 * CRLF
 * r->headers_in (delimited by CRLF)
 * CRLF
 */
#define DISK_FORMAT_VERSION 0
typedef struct {
    /* Indicates the format of the header struct stored on-disk. */
    int format;
    /* The HTTP status code returned for this response.  */
    int status;
    /* The size of the entity name that follows. */
    apr_size_t name_len;
    /* The number of times we've cached this entity. */
    apr_size_t entity_version;
    /* Miscellaneous time values. */
    apr_time_t date;
    apr_time_t expire;
    apr_time_t request_time;
    apr_time_t response_time;
} disk_cache_info_t;

/*
 * disk_cache_object_t
 * Pointed to by cache_object_t::vobj
 */
typedef struct disk_cache_object {
    const char *root;        /* the location of the cache directory */
    char *tempfile;          /* temp file tohold the content */
#if 0
    int dirlevels;              /* Number of levels of subdirectories */
    int dirlength;            /* Length of subdirectory names */
#endif
    char *datafile;          /* name of file where the data will go */
    char *hdrsfile;          /* name of file where the hdrs will go */
    char *hashfile;          /* Computed hash key for this URI */
    char *name;
    apr_file_t *fd;          /* data file */
    apr_file_t *hfd;         /* headers file */
    apr_file_t *tfd;         /* temporary file for data */
    apr_off_t file_size;     /*  File size of the cached data file  */
    disk_cache_info_t disk_info; /* Header information. */
} disk_cache_object_t;


/*
 * mod_disk_cache configuration
 */
/* TODO: Make defaults OS specific */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */
#define DEFAULT_DIRLEVELS 3
#define DEFAULT_DIRLENGTH 2
#define DEFAULT_MIN_FILE_SIZE 1
#define DEFAULT_MAX_FILE_SIZE 1000000

typedef struct {
    const char* cache_root;
    apr_size_t cache_root_len;
    int dirlevels;               /* Number of levels of subdirectories */
    int dirlength;               /* Length of subdirectory names */
    apr_size_t minfs;            /* minumum file size for cached files */
    apr_size_t maxfs;            /* maximum file size for cached files */
} disk_cache_conf;

module AP_MODULE_DECLARE_DATA disk_cache_module;

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

/*
 * Local static functions
 */
#define CACHE_HEADER_SUFFIX ".header"
#define CACHE_DATA_SUFFIX   ".data"
static char *header_file(apr_pool_t *p, disk_cache_conf *conf,
                         disk_cache_object_t *dobj, const char *name)
{
    if (!dobj->hashfile) {
        dobj->hashfile = ap_cache_generate_name(p, conf->dirlevels, 
                                                conf->dirlength, name);
    }
    return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
                       CACHE_HEADER_SUFFIX, NULL);
}

static char *data_file(apr_pool_t *p, disk_cache_conf *conf,
                       disk_cache_object_t *dobj, const char *name)
{
    if (!dobj->hashfile) {
        dobj->hashfile = ap_cache_generate_name(p, conf->dirlevels, 
                                                conf->dirlength, name);
    }
    return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
                       CACHE_DATA_SUFFIX, NULL);
}

static void mkdir_structure(disk_cache_conf *conf, char *file, apr_pool_t *pool)
{
    apr_status_t rv;
    char *p;

    for (p = file + conf->cache_root_len + 1;;) {
        p = strchr(p, '/');
        if (!p)
            break;
        *p = '\0';

        rv = apr_dir_make(file,
                          APR_UREAD|APR_UWRITE|APR_UEXECUTE, pool);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_EEXIST(rv)) {
            /* XXX */
        }
        *p = '/';
        ++p;
    }
}

static apr_status_t file_cache_el_final(disk_cache_object_t *dobj,
                                        request_rec *r)
{
    /* move the data over */
    if (dobj->tfd) {
        apr_status_t rv;

        apr_file_close(dobj->tfd);

        /* This assumes that the tempfile is on the same file system
         * as the cache_root. If not, then we need a file copy/move
         * rather than a rename.
         */
        rv = apr_file_rename(dobj->tempfile, dobj->datafile, r->pool);
        if (rv != APR_SUCCESS) {
            /* XXX log */
        }

        dobj->tfd = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t file_cache_errorcleanup(disk_cache_object_t *dobj, request_rec *r)
{
    /* Remove the header file and the body file. */
    apr_file_remove(dobj->hdrsfile, r->pool);
    apr_file_remove(dobj->datafile, r->pool);

    /* If we opened the temporary data file, close and remove it. */
    if (dobj->tfd) {
        apr_file_close(dobj->tfd);
        apr_file_remove(dobj->tempfile, r->pool);
        dobj->tfd = NULL;
    }

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
    disk_cache_info_t disk_info;
    apr_size_t len;

    /* read the data from the cache file */
    len = sizeof(disk_cache_info_t);
    rv = apr_file_read_full(fd, &disk_info, len, &len);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (disk_info.format != DISK_FORMAT_VERSION) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "cache_disk: URL %s had a on-disk version mismatch",
                     r->uri);
        return APR_EGENERAL;
    }

    /* Store it away so we can get it later. */
    dobj->disk_info = disk_info;

    info->status = disk_info.status;
    info->date = disk_info.date;
    info->expire = disk_info.expire;
    info->request_time = disk_info.request_time;
    info->response_time = disk_info.response_time;

    /* Note that we could optimize this by conditionally doing the palloc
     * depending upon the size. */
    urlbuff = apr_palloc(r->pool, disk_info.name_len + 1);
    len = disk_info.name_len;
    rv = apr_file_read_full(fd, urlbuff, len, &len);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    urlbuff[disk_info.name_len] = '\0';

    /* check that we have the same URL */
    /* Would strncmp be correct? */
    if (strcmp(urlbuff, dobj->name) != 0) {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

/*
 * Hook and mod_cache callback functions
 */
#define AP_TEMPFILE "/aptmpXXXXXX"
static int create_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    cache_object_t *obj;
    disk_cache_object_t *dobj;

    if (conf->cache_root == NULL) {
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t and disk_cache_object_t */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

    obj->key = apr_pstrdup(r->pool, key);

    dobj->name = obj->key;
    dobj->datafile = data_file(r->pool, conf, dobj, key);
    dobj->hdrsfile = header_file(r->pool, conf, dobj, key);
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

    return OK;
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
{
    apr_status_t rc;
    static int error_logged = 0;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    apr_finfo_t finfo;
    cache_object_t *obj;
    cache_info *info;
    disk_cache_object_t *dobj;
    int flags;

    h->cache_obj = NULL;

    /* Look up entity keyed to 'url' */
    if (conf->cache_root == NULL) {
        if (!error_logged) {
            error_logged = 1;
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "disk_cache: Cannot cache files to disk without a CacheRoot specified.");
        }
        return DECLINED;
    }

    /* Create and init the cache object */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));

    info = &(obj->info);
    obj->key = (char *) key;
    dobj->name = (char *) key;
    dobj->datafile = data_file(r->pool, conf, dobj, key);
    dobj->hdrsfile = header_file(r->pool, conf, dobj, key);
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

    /* Open the data file */
    flags = APR_READ|APR_BINARY;
#ifdef APR_SENDFILE_ENABLED
    flags |= APR_SENDFILE_ENABLED;
#endif
    rc = apr_file_open(&dobj->fd, dobj->datafile, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        /* XXX: Log message */
        return DECLINED;
    }

    /* Open the headers file */
    flags = APR_READ|APR_BINARY|APR_BUFFERED;
    rc = apr_file_open(&dobj->hfd, dobj->hdrsfile, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        /* XXX: Log message */
        return DECLINED;
    }

    rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, dobj->fd);
    if (rc == APR_SUCCESS) {
        dobj->file_size = finfo.size;
    }

    /* Read the bytes to setup the cache_info fields */
    rc = file_cache_recall_mydata(dobj->hfd, info, dobj, r);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return DECLINED;
    }

    /* Initialize the cache_handle callback functions */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Recalled cached URL info header %s",  dobj->name);
    return OK;
}

static int remove_entity(cache_handle_t *h)
{
    /* Null out the cache object pointer so next time we start from scratch  */
    h->cache_obj = NULL;
    return OK;
}

static int remove_url(const char *key)
{
    /* XXX: Delete file from cache! */
    return OK;
}

static apr_status_t read_table(cache_handle_t *handle, request_rec *r,
                               apr_table_t *table, apr_file_t *file)
{
    char w[MAX_STRING_LEN];
    char *l;
    int p;
    apr_status_t rv;

    while (1) {

        /* ### What about APR_EOF? */
        rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
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
        while (*l && apr_isspace(*l)) {
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

    /* This case should not happen... */
    if (!dobj->hfd) {
        /* XXX log message */
        return APR_NOTFOUND;
    }

    h->req_hdrs = apr_table_make(r->pool, 20);
    h->resp_hdrs = apr_table_make(r->pool, 20);

    /* Call routine to read the header lines/status line */
    read_table(h, r, h->resp_hdrs, dobj->hfd);
    read_table(h, r, h->req_hdrs, dobj->hfd);

    apr_file_close(dobj->hfd);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Recalled headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}

static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    e = apr_bucket_file_create(dobj->fd, 0, (apr_size_t) dobj->file_size, p,
                               bb->bucket_alloc);
    APR_BRIGADE_INSERT_HEAD(bb, e);
    e = apr_bucket_eos_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

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

            rv = apr_file_writev(fd, (const struct iovec *) &iov, 4,
                                 &amt);
            if (rv != APR_SUCCESS) {
                return rv;
            }
        }
    }
    iov[0].iov_base = CRLF;
    iov[0].iov_len = sizeof(CRLF) - 1;
    rv = apr_file_writev(fd, (const struct iovec *) &iov, 1,
                         &amt);
    return rv;
}

static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    apr_status_t rv;
    apr_size_t amt;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    disk_cache_info_t disk_info;
    struct iovec iov[2];

    /* This is flaky... we need to manage the cache_info differently */
    h->cache_obj->info = *info;

    /* Remove old file with the same name. If remove fails, then
     * perhaps we need to create the directory tree where we are
     * about to write the new headers file.
     */
    rv = apr_file_remove(dobj->hdrsfile, r->pool);
    if (rv != APR_SUCCESS) {
        mkdir_structure(conf, dobj->hdrsfile, r->pool);
    }

    rv = apr_file_open(&dobj->hfd, dobj->hdrsfile,
                       APR_WRITE | APR_CREATE | APR_EXCL,
                       APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    dobj->name = h->cache_obj->key;

    disk_info.format = DISK_FORMAT_VERSION;
    disk_info.date = info->date;
    disk_info.expire = info->expire;
    disk_info.entity_version = dobj->disk_info.entity_version++;
    disk_info.request_time = info->request_time;
    disk_info.response_time = info->response_time;
    disk_info.status = info->status;

    disk_info.name_len = strlen(dobj->name);

    iov[0].iov_base = (void*)&disk_info;
    iov[0].iov_len = sizeof(disk_cache_info_t);
    iov[1].iov_base = dobj->name;
    iov[1].iov_len = disk_info.name_len;

    rv = apr_file_writev(dobj->hfd, (const struct iovec *) &iov, 2, &amt);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (r->headers_out) {
        apr_table_t *headers_out;

        headers_out = ap_cache_cacheable_hdrs_out(r->pool, r->headers_out,
                                                  r->server);

        if (!apr_table_get(headers_out, "Content-Type")
            && r->content_type) {
            apr_table_setn(headers_out, "Content-Type",
                           ap_make_content_type(r, r->content_type));
        }

        headers_out = apr_table_overlay(r->pool, headers_out,
                                        r->err_headers_out);
        rv = store_table(dobj->hfd, headers_out);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    /* Parse the vary header and dump those fields from the headers_in. */
    /* FIXME: Make call to the same thing cache_select_url calls to crack Vary. */
    if (r->headers_in) {
        apr_table_t *headers_in;

        headers_in = ap_cache_cacheable_hdrs_out(r->pool, r->headers_in,
                                                 r->server);
        rv = store_table(dobj->hfd, headers_in);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }
    
    apr_file_close(dobj->hfd); /* flush and close */

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Stored headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}

static apr_status_t store_body(cache_handle_t *h, request_rec *r,
                               apr_bucket_brigade *bb)
{
    apr_bucket *e;
    apr_status_t rv;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);

    /* We write to a temp file and then atomically rename the file over
     * in file_cache_el_final().
     */
    if (!dobj->tfd) {
        rv = apr_file_mktemp(&dobj->tfd, dobj->tempfile,
                             APR_CREATE | APR_WRITE | APR_BINARY |
                             APR_BUFFERED | APR_EXCL, r->pool);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        dobj->file_size = 0;
    }

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        const char *str;
        apr_size_t length, written;
        apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
        rv = apr_file_write_full(dobj->tfd, str, length, &written);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "cache_disk: Error when writing cache file for URL %s",
                         h->cache_obj->key);
            /* Remove the intermediate cache file and return non-APR_SUCCESS */
            file_cache_errorcleanup(dobj, r);
            return APR_EGENERAL;
        }
        dobj->file_size += written;
        if (dobj->file_size > conf->maxfs) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "cache_disk: URL %s failed the size check "
                         "(%" APR_OFF_T_FMT ">%" APR_SIZE_T_FMT ")",
                         h->cache_obj->key, dobj->file_size, conf->maxfs);
            /* Remove the intermediate cache file and return non-APR_SUCCESS */
            file_cache_errorcleanup(dobj, r);
            return APR_EGENERAL;
        }
    }

    /* Was this the final bucket? If yes, close the temp file and perform
     * sanity checks.
     */
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
        if (r->connection->aborted) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "disk_cache: Discarding body for URL %s "
                         "because connection has been aborted.",
                         h->cache_obj->key);
            /* Remove the intermediate cache file and return non-APR_SUCCESS */
            file_cache_errorcleanup(dobj, r);
            return APR_EGENERAL;
        }
        if (dobj->file_size < conf->minfs) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "cache_disk: URL %s failed the size check "
                         "(%" APR_OFF_T_FMT "<%" APR_SIZE_T_FMT ")",
                         h->cache_obj->key, dobj->file_size, conf->minfs);
            /* Remove the intermediate cache file and return non-APR_SUCCESS */
            file_cache_errorcleanup(dobj, r);
            return APR_EGENERAL;
        }

        /* All checks were fine. Move tempfile to final destination */
        /* Link to the perm file, and close the descriptor */
        file_cache_el_final(dobj, r);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "disk_cache: Body for URL %s cached.",  dobj->name);
    }

    return APR_SUCCESS;
}

static void *create_config(apr_pool_t *p, server_rec *s)
{
    disk_cache_conf *conf = apr_pcalloc(p, sizeof(disk_cache_conf));

    /* XXX: Set default values */
    conf->dirlevels = DEFAULT_DIRLEVELS;
    conf->dirlength = DEFAULT_DIRLENGTH;
    conf->maxfs = DEFAULT_MAX_FILE_SIZE;
    conf->minfs = DEFAULT_MIN_FILE_SIZE;

    conf->cache_root = NULL;
    conf->cache_root_len = 0;

    return conf;
}

/*
 * mod_disk_cache configuration directives handlers.
 */
static const char
*set_cache_root(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
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
                                                 &disk_cache_module);
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
                                                 &disk_cache_module);
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
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->minfs = atoi(arg);
    return NULL;
}
static const char
*set_cache_maxfs(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->maxfs = atoi(arg);
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
    AP_INIT_TAKE1("CacheMinFileSize", set_cache_minfs, NULL, RSRC_CONF,
                  "The minimum file size to cache a document"),
    AP_INIT_TAKE1("CacheMaxFileSize", set_cache_maxfs, NULL, RSRC_CONF,
                  "The maximum file size to cache a document"),
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
};

static void disk_cache_register_hook(apr_pool_t *p)
{
    /* cache initializer */
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "disk", "0",
                         &cache_disk_provider);
}

module AP_MODULE_DECLARE_DATA disk_cache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_config,              /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    disk_cache_cmds,	        /* command apr_table_t */
    disk_cache_register_hook	/* register hooks */
};
