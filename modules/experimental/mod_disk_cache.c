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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#include "mod_cache.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "util_script.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* needed for unlink/link */
#endif

/*
 * disk_cache_object_t
 * Pointed to by cache_object_t::vobj
 */
typedef struct disk_cache_object {
    const char *root;           /* the location of the cache directory */
    char *tempfile;
    int dirlevels;              /* Number of levels of subdirectories */
    int dirlength;              /* Length of subdirectory names */   

    char *datafile;          /* where the data will go */
    char *hdrsfile;          /* where the hdrs will go */
    char *name;
    int version;             /* update count of the file */
    apr_file_t *fd;          /* pointer to apr_file_t structure for the data file  */
    apr_off_t file_size;    /*  File size of the cached data file  */    
} disk_cache_object_t;

/*
 * mod_disk_cache configuration
 */
/* TODO: Make defaults OS specific */
#define MAX_DIRLEVELS 20
#define MAX_DIRLENGTH 20
#define MIN_FILE_SIZE 1
#define MAX_FILE_SIZE 1000000
#define MAX_CACHE_SIZE 1000000
 
typedef struct {
    const char* cache_root;
    off_t space;                 /* Maximum cache size (in 1024 bytes) */
    apr_time_t maxexpire;        /* Maximum time to keep cached files in msecs */
    apr_time_t defaultexpire;    /* default time to keep cached file in msecs */
    double lmfactor;             /* factor for estimating expires date */
    apr_time_t gcinterval;       /* garbage collection interval, in msec */
    int dirlevels;               /* Number of levels of subdirectories */
    int dirlength;               /* Length of subdirectory names */
    int	expirychk;               /* true if expiry time is observed for cached files */
    apr_size_t minfs;            /* minumum file size for cached files */
    apr_size_t maxfs;            /* maximum file size for cached files */
    apr_time_t mintm;            /* minimum time margin for caching files */
    /* dgc_time_t gcdt;            time of day for daily garbage collection */
    apr_array_header_t *gcclnun; /* gc_retain_t entries for unused files */
    apr_array_header_t *gcclean; /* gc_retain_t entries for all files */
    int maxgcmem;                /* maximum memory used by garbage collection */
} disk_cache_conf;

module AP_MODULE_DECLARE_DATA disk_cache_module;

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static int write_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static int write_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static int read_headers(cache_handle_t *h, request_rec *r);
static int read_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

/*
 * Local static functions
 */
#define CACHE_HEADER_SUFFIX ".header"
#define CACHE_DATA_SUFFIX   ".data"
static char *header_file(apr_pool_t *p, int dirlevels, int dirlength, 
                         const char *root, const char *name)
{
    char *hashfile;
    hashfile = generate_name(p, dirlevels, dirlength, name);
    return apr_pstrcat(p, root, "/", hashfile, CACHE_HEADER_SUFFIX, NULL);
}

static char *data_file(apr_pool_t *p, int dirlevels, int dirlength, 
                       const char *root, const char *name)
{
    char *hashfile;
    hashfile = generate_name(p, dirlevels, dirlength, name);
    return apr_pstrcat(p, root, "/", hashfile, CACHE_DATA_SUFFIX, NULL);
}

static int mkdir_structure(char *file, const char *root)
{
    
    /* XXX TODO: Use APR to make a root directory. Do some sanity checking... */
    return 0;
}

static apr_status_t file_cache_el_final(cache_info *info, cache_handle_t *h, request_rec *r)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    /* move the data over */
    if (dobj->fd) {
        apr_file_flush(dobj->fd);
        if (!dobj->datafile) dobj->datafile = data_file(r->pool, conf->dirlevels, conf->dirlength,
                                                        conf->cache_root, h->cache_obj->key);
        if (unlink(dobj->datafile)) {
            mkdir_structure(dobj->datafile, conf->cache_root);
        }
        else {
            /* XXX log */
        }
#ifdef WIN32
        /* XXX: win32 doesn't have a link */
        if  (apr_file_copy(dobj->tempfile, dobj->datafile, APR_FILE_SOURCE_PERMS, r->pool) != APR_SUCCESS) {
#else
        if (link(dobj->tempfile, dobj->datafile) == -1) {
#endif
            /* XXX log */
        }
        else {
            /* XXX log message */
        }
       if (unlink(dobj->tempfile) == -1) {
           /* XXX log message */
       }
       else {
           /* XXX log message */
       }
   }
   if (dobj->fd) {
       apr_file_close(dobj->fd);     /* if you finalize, you are done writing, so close it */
       dobj->fd = 0;
       /* XXX log */
   }

   return APR_SUCCESS;
}


/* These two functions get and put state information into the data 
 * file for an ap_cache_el, this state information will be read 
 * and written transparent to clients of this module 
 */
static int file_cache_read_mydata(apr_file_t *fd, cache_handle_t *h, 
                                  request_rec *r)
{
    apr_status_t rv;
    char urlbuff[1034];
    int urllen = sizeof(urlbuff);
    int offset=0;
    char * temp;
    cache_info *info = &(h->cache_obj->info);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    
    if(!dobj->hdrsfile) {
        return APR_NOTFOUND;
    }

    /* read the data from the cache file */
    /* format
     * date SP expire SP count CRLF
     * dates are stored as hex seconds since 1970
     */
    rv = apr_file_gets(&urlbuff[0], urllen, fd);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL) /* trim off new line character */
        *temp = '\0';      /* overlay it with the null terminator */

    if (!apr_date_checkmask(urlbuff, "&&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&&")) {
        return APR_EGENERAL;
    }

    info->date = ap_cache_hex2msec(urlbuff + offset);
    offset += (sizeof(info->date)*2) + 1;
    info->expire = ap_cache_hex2msec(urlbuff + offset);
    offset += (sizeof(info->expire)*2) + 1;
    dobj->version = ap_cache_hex2msec(urlbuff + offset);
    
    /* check that we have the same URL */
    rv = apr_file_gets(&urlbuff[0], urllen, fd);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL) { /* trim off new line character */
        *temp = '\0';      /* overlay it with the null terminator */
    }

    if (strncmp(urlbuff, "X-NAME: ", 7) != 0) {
        return APR_EGENERAL;
    }
    if (strcmp(urlbuff + 8, dobj->name) != 0) {
        return APR_EGENERAL;
    }
    
    return APR_SUCCESS;
}

static int file_cache_write_mydata(apr_file_t *fd , cache_handle_t *h, request_rec *r)
{
    apr_status_t rc;
    char *buf;
    apr_size_t amt;

    char	dateHexS[sizeof(apr_time_t) * 2 + 1];
    char	expireHexS[sizeof(apr_time_t) * 2 + 1];
    char	verHexS[sizeof(apr_time_t) * 2 + 1];
    cache_info *info = &(h->cache_obj->info);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    
    if (!r->headers_out) {
        /* XXX log message */
        return 0;
    }

    ap_cache_msec2hex(info->date, dateHexS);
    ap_cache_msec2hex(info->expire, expireHexS);
    ap_cache_msec2hex(dobj->version++, verHexS);
    buf = apr_pstrcat(r->pool, dateHexS, " ", expireHexS, " ", verHexS, "\n", NULL);
    amt = strlen(buf);
    rc = apr_file_write(fd, buf, &amt);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return 0;
    }

    buf = apr_pstrcat(r->pool, "X-NAME: ", dobj->name, "\n", NULL);
    amt = strlen(buf);
    rc = apr_file_write(fd, buf, &amt);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return 0;
    }
    return 1;
}

/*
 * Hook and mod_cache callback functions
 */
static int create_entity(cache_handle_t *h, request_rec *r,
                         const char *type, 
                         const char *key, 
                         apr_size_t len)
{ 
    cache_object_t *obj;
    disk_cache_object_t *dobj;

    cache_info *info;
#ifdef AS400
    char tempfile[L_tmpnam];	/* L_tmpnam defined in stdio.h */
#endif

    if (strcasecmp(type, "disk")) {
	return DECLINED;
    }

    /* Allocate and initialize cache_object_t and disk_cache_object_t */
    obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

    obj->key = apr_pcalloc(r->pool, (strlen(key) + 1));
    strncpy(obj->key, key, strlen(key) + 1);
    obj->info.len = len;
    obj->complete = 0;   /* Cache object is not complete */

    info = apr_pcalloc(r->pool, sizeof(cache_info));
    dobj->name = (char *) key;
    obj->info = *(info);

#ifdef AS400
    AP_INFO_TRACE("file_cache_element(): >>Generating temporary cache file name. (AP_CACHE_CREATE)\n");

    /* open temporary file */
    /* The RPM mktemp() utility is not available on the AS/400 so the	*/
    /* following is used to generate a unique, temporary file for the	*/
    /* cache element.							*/
    /* NOTE: Since this temporary file will need to be hard linked within	*/
    /*       the QOpenSys file system later on [by the file_cache_el_final()*/
    /*       routine] to make it a permanent file we must generate a name	*/
    /*       relative to the same file system, that is, QOpenSys. If we	*/
    /*       don't, the link() API will fail since hard links can't cross	*/
    /*       file systems on the AS/400.					*/

    /* 1st, a unique tempfile is made relative to root. */
    if(!tmpnam(tempfile)) {
	AP_ERROR_TRACE("file_cache_element(): R>Failed to produce unique temporary cache file name.\n");
	return APR_ENOENT;
    }
    /* Then a unique tempfile is made relative to QOpenSys. */
    if(!(obj->tempfile = apr_pstrcat(r->pool, AS400_CTEMP_ROOT, ap_strrchr_c(tempfile, '/')+1, NULL))) {
	return APR_ENOMEM;
    }
    
    AP_INFO_TRACE("file_cache_element(): .>Cache element using temporary file name %s.\n", obj->tempfile);
    ap_log_error400(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, NULL, ZSRV_MSG153D, obj->tempfile);

#endif

    /* Populate the cache handle */
    h->cache_obj = obj;
    h->read_body = &read_body;
    h->read_headers = &read_headers;
    h->write_body = &write_body;
    h->write_headers = &write_headers;
    h->remove_entity = &remove_entity;

    return OK;
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *type, const char *key)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config, 
                                                 &disk_cache_module);
    apr_status_t rc;
    char *data = data_file(r->pool, conf->dirlevels, conf->dirlength, 
                           conf->cache_root, key);
    apr_file_t *fd;
    apr_finfo_t finfo;
    cache_object_t *obj;
    cache_info *info;
    disk_cache_object_t *dobj;

    /* Look up entity keyed to 'url' */
    if (strcasecmp(type, "disk")) {
	return DECLINED;
    }

    obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));
    info = &(obj->info);
    obj->key = (char *) key;

    rc = apr_file_open(&fd, data, APR_WRITE | APR_READ | APR_BINARY, 0, r->pool);
    if (rc == APR_SUCCESS) {
        dobj->name = (char *) key;
        /* XXX log message */
	dobj->fd = fd;
	dobj->datafile = data;
	dobj->hdrsfile = header_file(r->pool, conf->dirlevels, conf->dirlength, 
                                     conf->cache_root, key);
	rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd);
	if (rc == APR_SUCCESS)
	    dobj->file_size = finfo.size;
    }
    else if(errno==APR_ENOENT) {
        /* XXX log message */
	return DECLINED;
    }
    else {
        /* XXX log message */
	return DECLINED;
    }

    /* Initialize the cache_handle */
    h->read_body = &read_body;
    h->read_headers = &read_headers;
    h->write_body = &write_body;
    h->write_headers = &write_headers;
    h->remove_entity = &remove_entity;
    h->cache_obj = obj;
    return OK;
}

static int remove_url(const char *type, char *key) 
{
  return OK;
}

static int remove_entity(cache_handle_t *h) 
{
    cache_object_t *obj = h->cache_obj;

    /* Null out the cache object pointer so next time we start from scratch  */
    h->cache_obj = NULL;
    return OK;
}

/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 * This routine tries to deal with too long lines and continuation lines.
 * @@@: XXX: FIXME: currently the headers are passed thru un-merged. 
 * Is that okay, or should they be collapsed where possible?
 */
static int read_headers(cache_handle_t *h, request_rec *r) 
{
    apr_status_t rv;
    char *temp;
    apr_file_t *fd = NULL;
    char urlbuff[1034];
    int urllen = sizeof(urlbuff);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    if(!r->headers_out)
	r->headers_out = apr_table_make(r->pool, 20);

    if(!dobj->fd) {
        /* XXX log message */
        return APR_NOTFOUND; 
    }
    
    if (!dobj->hdrsfile || (apr_file_open(&fd, dobj->hdrsfile, 
                                         APR_READ | APR_BINARY,         /*  | APR_NONQSYS,  */
                                         0, r->pool) != APR_SUCCESS))
    {
	/* Error. Figure out which message(s) to log. */
	if(!dobj->hdrsfile) {
            /* XXX log message */
	    return APR_NOTFOUND;
	}
	else if(errno==APR_ENOENT) {
            /* XXX log message */
	}
	else {
            /* XXX log message */
	}
	return errno;
    }

    /* XXX log */
    if((rv = file_cache_read_mydata(fd, h, r)) != APR_SUCCESS) {
        /* XXX log message */
        apr_file_close(fd);
        return rv;
    }
    
    /*
     * Call routine to read the header lines/status line 
     */
    ap_scan_script_header_err(r, fd, NULL);
 
    apr_table_setn(r->headers_out, "Content-Type", 
                   ap_make_content_type(r, r->content_type));

    rv = apr_file_gets(&urlbuff[0], urllen, fd);           /* Read status  */
    if (rv != APR_SUCCESS) {
        /* XXX log message */
	return rv;
    }

    r->status = atoi(urlbuff);                           /* Save status line into request rec  */

    rv = apr_file_gets(&urlbuff[0], urllen, fd);               /* Read status line */
    if (rv != APR_SUCCESS) {
        /* XXX log message */
	return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL)       /* trim off new line character */
	*temp = '\0';              /* overlay it with the null terminator */

    r->status_line = apr_pstrdup(r->pool, urlbuff);            /* Save status line into request rec  */

    apr_file_close(fd);
    return APR_SUCCESS;
}

static int read_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb) 
{
    apr_bucket *e;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    e = apr_bucket_file_create(dobj->fd, 0, dobj->file_size, p);

    APR_BRIGADE_INSERT_HEAD(bb, e);
    e = apr_bucket_eos_create();
    APR_BRIGADE_INSERT_TAIL(bb, e);

    return OK;
}

static int write_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config, 
                                                 &disk_cache_module);
    apr_file_t *hfd = NULL;
    apr_status_t rc;
    char *buf;
    char statusbuf[8];
    apr_size_t amt;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    if (!dobj->fd)  {
        if(!dobj->hdrsfile) dobj->hdrsfile = header_file(r->pool, 
                                                         conf->dirlevels, 
                                                         conf->dirlength, 
                                                         conf->cache_root,
                                                         h->cache_obj->key);
        if(unlink(dobj->hdrsfile)) /* if we can remove it, we clearly don't have to build the dirs */
            mkdir_structure(dobj->hdrsfile, conf->cache_root);
        else {
            /* XXX log message */
        }
        if((rc = apr_file_open(&hfd, dobj->hdrsfile,
                              APR_WRITE | APR_CREATE | APR_BINARY | APR_EXCL, /* XXX:? | APR_INHERIT | APR_NONQSYS, */
                              0, r->pool)) != APR_SUCCESS)   {
            /* XXX log message */
            return rc;
        }
	file_cache_write_mydata(hfd, h, r);
        if (r->headers_out) {
            int i;
            apr_table_entry_t *elts = (apr_table_entry_t *) apr_table_elts(r->headers_out)->elts;
            for (i = 0; i < apr_table_elts(r->headers_out)->nelts; ++i) {
                if (elts[i].key != NULL) {
                    buf = apr_pstrcat(r->pool, elts[i].key, ": ",  elts[i].val, CRLF, NULL);
                    amt = strlen(buf);
                    apr_file_write(hfd, buf, &amt);
                }
            }
            buf = apr_pstrcat(r->pool, CRLF, NULL);
            amt = strlen(buf);
            apr_file_write(hfd, buf, &amt);
        }
        sprintf(statusbuf,"%d", r->status);
        buf = apr_pstrcat(r->pool, statusbuf, CRLF, NULL);
        amt = strlen(buf);
        apr_file_write(hfd, buf, &amt);
        buf = apr_pstrcat(r->pool, r->status_line, "\n", NULL);
        amt = strlen(buf);
        apr_file_write(hfd, buf, &amt);
        buf = apr_pstrcat(r->pool, CRLF, NULL);
        amt = strlen(buf);
        apr_file_write(hfd, buf, &amt);
        apr_file_close(hfd); /* flush and close */
    }
    else {
        /* XXX log message */
    }
    return OK;
}
static int write_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b) 
{
    apr_bucket *e;
    apr_status_t rv;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    cache_info *info = &(h->cache_obj->info);

    if (!dobj->fd) {
        rv = apr_file_open(&dobj->fd, dobj->tempfile, 
                           APR_WRITE | APR_CREATE | APR_TRUNCATE | APR_BUFFERED,
                           APR_UREAD | APR_UWRITE, r->pool);
        if (rv != APR_SUCCESS) {
            return DECLINED;
        }
    }
    APR_BRIGADE_FOREACH(e, b) {
        const char *str;
        apr_size_t length;
        apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
        apr_file_write(dobj->fd, str, &length);
    }
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(b))) {
        file_cache_el_final(info, h, r);    /* Link to the perm file, and close the descriptor  */
    }
    return OK;	
}

static void *create_config(apr_pool_t *p, server_rec *s)
{
    disk_cache_conf *conf = apr_pcalloc(p, sizeof(disk_cache_conf));

    /* XXX: Set default values */
    conf->dirlevels = MAX_DIRLEVELS;
    conf->dirlength = MAX_DIRLENGTH;
    conf->space = MAX_CACHE_SIZE;
    conf->maxfs = MAX_FILE_SIZE;
    conf->minfs = MIN_FILE_SIZE;
    
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
    return NULL;
}
static const char
*set_cache_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    conf->space = atoi(arg);
    return NULL;
}
static const char
*set_cache_gcint(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
    return NULL;
}
static const char
*set_cache_dirlevels(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);

    /* TODO: Put some meaningful platform specific constraints on this */
    conf->dirlevels = atoi(arg);
    return NULL;
}
static const char
*set_cache_dirlength(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* TODO: Put some meaningful platform specific constraints on this */
    conf->dirlength = atoi(arg);
    return NULL;
}
static const char
*set_cache_exchk(cmd_parms *parms, void *in_struct_ptr, int flag)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
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
static const char
*set_cache_minetm(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
    return NULL;
}
static const char
*set_cache_gctime(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
    return NULL;
}
static const char
*add_cache_gcclean(cmd_parms *parms, void *in_struct_ptr, const char *arg, const char *arg1)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
    return NULL;
}
static const char
*add_cache_gcclnun(cmd_parms *parms, void *in_struct_ptr, const char *arg, const char *arg1)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
    return NULL;
}
static const char
*set_cache_maxgcmem(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config, 
                                                 &disk_cache_module);
    /* XXX */
    return NULL;
}
static const command_rec disk_cache_cmds[] =
{
    AP_INIT_TAKE1("CacheRoot", set_cache_root, NULL, RSRC_CONF,
                 "The directory to store cache files"),
    AP_INIT_TAKE1("CacheSize", set_cache_size, NULL, RSRC_CONF,
                  "The maximum disk space used by the cache in Kb"),
    AP_INIT_TAKE1("CacheGcInterval", set_cache_gcint, NULL, RSRC_CONF,
                  "The interval between garbage collections, in hours"),
    AP_INIT_TAKE1("CacheDirLevels", set_cache_dirlevels, NULL, RSRC_CONF,
                  "The number of levels of subdirectories in the cache"),
    AP_INIT_TAKE1("CacheDirLength", set_cache_dirlength, NULL, RSRC_CONF,
                  "The number of characters in subdirectory names"),
    AP_INIT_FLAG("CacheExpiryCheck", set_cache_exchk, NULL, RSRC_CONF,
                 "on if cache observes Expires date when seeking files"),
    AP_INIT_TAKE1("CacheMinFileSize", set_cache_minfs, NULL, RSRC_CONF,
                  "The minimum file size to cache a document"),
    AP_INIT_TAKE1("CacheMaxFileSize", set_cache_maxfs, NULL, RSRC_CONF,
                  "The maximum file size to cache a document"),
    AP_INIT_TAKE1("CacheTimeMargin", set_cache_minetm, NULL, RSRC_CONF,
                  "The minimum time margin to cache a document"),
    AP_INIT_TAKE1("CacheGcDaily", set_cache_gctime, NULL, RSRC_CONF,
                  "The time of day for garbage collection (24 hour clock)"),
    AP_INIT_TAKE2("CacheGcUnused", add_cache_gcclnun, NULL, RSRC_CONF,
                  "The time in hours to retain unused file that match a url"),
    AP_INIT_TAKE2("CacheGcClean", add_cache_gcclean, NULL, RSRC_CONF,
                  "The time in hours to retain unchanged files that match a url"),
    AP_INIT_TAKE1("CacheGcMemUsage", set_cache_maxgcmem, NULL, RSRC_CONF,
                  "The maximum kilobytes of memory used for garbage collection"),
    {NULL}
};

static void disk_cache_register_hook(apr_pool_t *p)
{
    /* cache initializer */
    cache_hook_create_entity(create_entity, NULL, NULL, APR_HOOK_MIDDLE);
    cache_hook_open_entity(open_entity,  NULL, NULL, APR_HOOK_MIDDLE);
/*    cache_hook_remove_entity(remove_entity, NULL, NULL, APR_HOOK_MIDDLE); */
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
