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
 
#include <stdio.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_portable.h>
#include <apr_file_info.h>
#include <apr_fnmatch.h>
#include <apr_tables.h>
#include <apr_uri.h>

#include "md_log.h"
#include "md_util.h"

/**************************************************************************************************/
/* pool utils */

apr_status_t md_util_pool_do(md_util_action *cb, void *baton, apr_pool_t *p)
{
    apr_pool_t *ptemp;
    apr_status_t rv = apr_pool_create(&ptemp, p);
    if (APR_SUCCESS == rv) {
        rv = cb(baton, p, ptemp);
        
        apr_pool_destroy(ptemp);
    }
    return rv;
}
 
static apr_status_t pool_vado(md_util_vaction *cb, void *baton, apr_pool_t *p, va_list ap)
{
    apr_pool_t *ptemp;
    apr_status_t rv;
    
    rv = apr_pool_create(&ptemp, p);
    if (APR_SUCCESS == rv) {
        rv = cb(baton, p, ptemp, ap);
        apr_pool_destroy(ptemp);
    }
    return rv;
}
 
apr_status_t md_util_pool_vdo(md_util_vaction *cb, void *baton, apr_pool_t *p, ...)
{
    va_list ap;
    apr_status_t rv;
    
    va_start(ap, p);
    rv = pool_vado(cb, baton, p, ap);
    va_end(ap);
    return rv;
}
 
/**************************************************************************************************/
/* string related */

char *md_util_str_tolower(char *s)
{
    char *orig = s;
    while (*s) {
        *s = (char)apr_tolower(*s);
        ++s;
    }
    return orig;
}

int md_array_str_index(const apr_array_header_t *array, const char *s, 
                       int start, int case_sensitive)
{
    if (start >= 0) {
        int i;
        
        for (i = start; i < array->nelts; i++) {
            const char *p = APR_ARRAY_IDX(array, i, const char *);
            if ((case_sensitive && !strcmp(p, s))
                || (!case_sensitive && !apr_strnatcasecmp(p, s))) {
                return i;
            }
        }
    }
    
    return -1;
}

int md_array_str_eq(const struct apr_array_header_t *a1, 
                    const struct apr_array_header_t *a2, int case_sensitive)
{
    int i;
    const char *s1, *s2;
    
    if (a1 == a2) return 1;
    if (!a1) return 0;
    if (a1->nelts != a2->nelts) return 0;
    for (i = 0; i < a1->nelts; ++i) {
        s1 = APR_ARRAY_IDX(a1, i, const char *);
        s2 = APR_ARRAY_IDX(a2, i, const char *);
        if ((case_sensitive && strcmp(s1, s2))
            || (!case_sensitive && apr_strnatcasecmp(s1, s2))) {
            return 0;
        }
    }
    return 1;
}

apr_array_header_t *md_array_str_clone(apr_pool_t *p, apr_array_header_t *src)
{
    apr_array_header_t *dest = apr_array_make(p, src->nelts, sizeof(const char*));
    if (dest) {
        int i;
        for (i = 0; i < src->nelts; i++) {
            const char *s = APR_ARRAY_IDX(src, i, const char *);
            APR_ARRAY_PUSH(dest, const char *) = apr_pstrdup(p, s); 
        }
    }
    return dest;
}

struct apr_array_header_t *md_array_str_compact(apr_pool_t *p, struct apr_array_header_t *src,
                                                int case_sensitive)
{
    apr_array_header_t *dest = apr_array_make(p, src->nelts, sizeof(const char*));
    if (dest) {
        const char *s;
        int i;
        for (i = 0; i < src->nelts; ++i) {
            s = APR_ARRAY_IDX(src, i, const char *);
            if (md_array_str_index(dest, s, 0, case_sensitive) < 0) {
                APR_ARRAY_PUSH(dest, char *) = md_util_str_tolower(apr_pstrdup(p, s));
            }
        }
    }
    return dest;
}

apr_array_header_t *md_array_str_remove(apr_pool_t *p, apr_array_header_t *src, 
                                        const char *exclude, int case_sensitive)
{
    apr_array_header_t *dest = apr_array_make(p, src->nelts, sizeof(const char*));
    if (dest) {
        int i;
        for (i = 0; i < src->nelts; i++) {
            const char *s = APR_ARRAY_IDX(src, i, const char *);
            if (!exclude 
                || (case_sensitive && strcmp(exclude, s))
                || (!case_sensitive && apr_strnatcasecmp(exclude, s))) {
                APR_ARRAY_PUSH(dest, const char *) = apr_pstrdup(p, s); 
            }
        }
    }
    return dest;
}

int md_array_str_add_missing(apr_array_header_t *dest, apr_array_header_t *src, int case_sensitive)
{
    int i, added = 0;
    for (i = 0; i < src->nelts; i++) {
        const char *s = APR_ARRAY_IDX(src, i, const char *);
        if (md_array_str_index(dest, s, 0, case_sensitive) < 0) {
            APR_ARRAY_PUSH(dest, const char *) = s;
            ++added; 
        }
    }
    return added;
}

/**************************************************************************************************/
/* file system related */

apr_status_t md_util_fopen(FILE **pf, const char *fn, const char *mode)
{
    *pf = fopen(fn, mode);
    if (*pf == NULL) {
        return errno;
    }

    return APR_SUCCESS;
}

apr_status_t md_util_fcreatex(apr_file_t **pf, const char *fn, 
                              apr_fileperms_t perms, apr_pool_t *p)
{
    return apr_file_open(pf, fn, (APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_EXCL),
                         perms, p);
}

apr_status_t md_util_is_dir(const char *path, apr_pool_t *pool)
{
    apr_finfo_t info;
    apr_status_t rv = apr_stat(&info, path, APR_FINFO_TYPE, pool);
    if (rv == APR_SUCCESS) {
        rv = (info.filetype == APR_DIR)? APR_SUCCESS : APR_EINVAL;
    }
    return rv;
}

apr_status_t md_util_is_file(const char *path, apr_pool_t *pool)
{
    apr_finfo_t info;
    apr_status_t rv = apr_stat(&info, path, APR_FINFO_TYPE, pool);
    if (rv == APR_SUCCESS) {
        rv = (info.filetype == APR_REG)? APR_SUCCESS : APR_EINVAL;
    }
    return rv;
}

apr_status_t md_util_path_merge(const char **ppath, apr_pool_t *p, ...)
{
    const char *segment, *path;
    va_list ap;
    apr_status_t rv = APR_SUCCESS;
    
    va_start(ap, p);
    path = va_arg(ap, char *);
    while (path && APR_SUCCESS == rv && (segment = va_arg(ap, char *))) {
        rv = apr_filepath_merge((char **)&path, path, segment, APR_FILEPATH_SECUREROOT , p);
    }
    va_end(ap);
    
    *ppath = (APR_SUCCESS == rv)? (path? path : "") : NULL;
    return rv;
}

apr_status_t md_util_freplace(const char *fpath, apr_fileperms_t perms, apr_pool_t *p, 
                              md_util_file_cb *write_cb, void *baton)
{
    apr_status_t rv = APR_EEXIST;
    apr_file_t *f;
    const char *tmp;
    int i, max;
    
    tmp = apr_psprintf(p, "%s.tmp", fpath);
    i = 0; max = 20;
creat:
    while (i < max && APR_EEXIST == (rv = md_util_fcreatex(&f, tmp, perms, p))) {
        ++i;
        apr_sleep(apr_time_msec(50));
    } 
    if (APR_EEXIST == rv 
        && APR_SUCCESS == (rv = apr_file_remove(tmp, p))
        && max <= 20) {
        max *= 2;
        goto creat;
    }
    
    if (APR_SUCCESS == rv) {
        rv = write_cb(baton, f, p);
        apr_file_close(f);
        
        if (APR_SUCCESS == rv) {
            rv = apr_file_rename(tmp, fpath, p);
            if (APR_SUCCESS != rv) {
                apr_file_remove(tmp, p);
            }
        }
    }
    return rv;
}                            

/**************************************************************************************************/
/* text files */

apr_status_t md_text_fread8k(const char **ptext, apr_pool_t *p, const char *fpath)
{
    apr_status_t rv;
    apr_file_t *f;
    char buffer[8 * 1024];

    *ptext = NULL;
    if (APR_SUCCESS == (rv = apr_file_open(&f, fpath, APR_FOPEN_READ, 0, p))) {
        apr_size_t blen = sizeof(buffer)/sizeof(buffer[0]) - 1;
        rv = apr_file_read_full(f, buffer, blen, &blen);
        if (APR_SUCCESS == rv || APR_STATUS_IS_EOF(rv)) {
            *ptext = apr_pstrndup(p, buffer, blen);
            rv = APR_SUCCESS;
        }
        apr_file_close(f);
    }
    return rv;
}

static apr_status_t write_text(void *baton, struct apr_file_t *f, apr_pool_t *p)
{
    const char *text = baton;
    apr_size_t len = strlen(text);
    
    (void)p;
    return apr_file_write_full(f, text, len, &len);
}

apr_status_t md_text_fcreatex(const char *fpath, apr_fileperms_t perms, 
                              apr_pool_t *p, const char *text)
{
    apr_status_t rv;
    apr_file_t *f;
    
    rv = md_util_fcreatex(&f, fpath, perms, p);
    if (APR_SUCCESS == rv) {
        rv = write_text((void*)text, f, p);
        apr_file_close(f);
    }
    return rv;
}

apr_status_t md_text_freplace(const char *fpath, apr_fileperms_t perms, 
                              apr_pool_t *p, const char *text)
{
    return md_util_freplace(fpath, perms, p, write_text, (void*)text);
}

typedef struct {
    const char *path;
    apr_array_header_t *patterns;
    int follow_links;
    void *baton;
    md_util_fdo_cb *cb;
} md_util_fwalk_t;

static apr_status_t rm_recursive(const char *fpath, apr_pool_t *p, int max_level)
{
    apr_finfo_t info;
    apr_status_t rv;
    const char *npath;
    
    if (APR_SUCCESS != (rv = apr_stat(&info, fpath, (APR_FINFO_TYPE|APR_FINFO_LINK), p))) {
        return rv;
    }
    
    if (info.filetype == APR_DIR) {
        if (max_level > 0) {
            apr_dir_t *d;
            
            if (APR_SUCCESS == (rv = apr_dir_open(&d, fpath, p))) {
            
                while (APR_SUCCESS == rv && 
                       APR_SUCCESS == (rv = apr_dir_read(&info, APR_FINFO_TYPE, d))) {
                    if (!strcmp(".", info.name) || !strcmp("..", info.name)) {
                        continue;
                    }
                    
                    rv = md_util_path_merge(&npath, p, fpath, info.name, NULL);
                    if (APR_SUCCESS == rv) {
                        rv = rm_recursive(npath, p, max_level - 1);
                    }
                }
                apr_dir_close(d);
                if (APR_STATUS_IS_ENOENT(rv)) {
                    rv = APR_SUCCESS;
                }
            }
        }
        if (APR_SUCCESS == rv) {
            rv = apr_dir_remove(fpath, p);
        }
    }
    else {
        rv = apr_file_remove(fpath, p);
    }
    return rv;
}

static apr_status_t prm_recursive(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    int max_level = va_arg(ap, int);
    
    (void)p;
    return rm_recursive(baton, ptemp, max_level); 
}

apr_status_t md_util_rm_recursive(const char *fpath, apr_pool_t *p, int max_level)
{
    return md_util_pool_vdo(prm_recursive, (void*)fpath, p, max_level, NULL);
}

static apr_status_t match_and_do(md_util_fwalk_t *ctx, const char *path, int depth, 
                                 apr_pool_t *p, apr_pool_t *ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    const char *pattern, *npath;
    apr_dir_t *d;
    apr_finfo_t finfo;
    int ndepth = depth + 1;
    apr_int32_t wanted = (APR_FINFO_TYPE);

    if (depth >= ctx->patterns->nelts) {
        return APR_SUCCESS;
    }
    pattern = APR_ARRAY_IDX(ctx->patterns, depth, const char *);
    
    rv = apr_dir_open(&d, path, ptemp);
    if (APR_SUCCESS != rv) {
        return rv;
    }
    
    while (APR_SUCCESS == (rv = apr_dir_read(&finfo, wanted, d))) {
        if (!strcmp(".", finfo.name) || !strcmp("..", finfo.name)) {
            continue;
        } 
        if (APR_SUCCESS == apr_fnmatch(pattern, finfo.name, 0)) {
            if (ndepth < ctx->patterns->nelts) {
                if (APR_DIR == finfo.filetype) { 
                    /* deeper and deeper, irgendwo in der tiefe leuchtet ein licht */
                    rv = md_util_path_merge(&npath, ptemp, path, finfo.name, NULL);
                    if (APR_SUCCESS == rv) {
                        rv = match_and_do(ctx, npath, ndepth, p, ptemp);
                    }
                }
            }
            else {
                rv = ctx->cb(ctx->baton, p, ptemp, path, finfo.name, finfo.filetype);
            }
        }
        if (APR_SUCCESS != rv) {
            break;
        }
    }

    if (APR_STATUS_IS_ENOENT(rv)) {
        rv = APR_SUCCESS;
    }

    apr_dir_close(d);
    return rv;
}

static apr_status_t files_do_start(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_util_fwalk_t *ctx = baton;
    const char *segment;

    ctx->patterns = apr_array_make(ptemp, 5, sizeof(const char*));
    
    segment = va_arg(ap, char *);
    while (segment) {
        APR_ARRAY_PUSH(ctx->patterns, const char *) = segment;
        segment = va_arg(ap, char *);
    }
    
    return match_and_do(ctx, ctx->path, 0, p, ptemp);
}

apr_status_t md_util_files_do(md_util_fdo_cb *cb, void *baton, apr_pool_t *p,
                              const char *path, ...)
{
    apr_status_t rv;
    va_list ap;
    md_util_fwalk_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.path = path;
    ctx.follow_links = 1;
    ctx.cb = cb;
    ctx.baton = baton;
    
    va_start(ap, path);
    rv = pool_vado(files_do_start, &ctx, p, ap);
    va_end(ap);
    
    return rv;
}

static apr_status_t tree_do(void *baton, apr_pool_t *p, apr_pool_t *ptemp, const char *path)
{
    md_util_fwalk_t *ctx = baton;

    apr_status_t rv = APR_SUCCESS;
    const char *name, *fpath;
    apr_filetype_e ftype;
    apr_dir_t *d;
    apr_int32_t wanted = APR_FINFO_TYPE;
    apr_finfo_t finfo;

    if (APR_SUCCESS == (rv = apr_dir_open(&d, path, ptemp))) {
        while (APR_SUCCESS == (rv = apr_dir_read(&finfo, wanted, d))) {
            name = finfo.name;
            if (!strcmp(".", name) || !strcmp("..", name)) {
                continue;
            }

            fpath = NULL;
            ftype = finfo.filetype;
            
            if (APR_LNK == ftype && ctx->follow_links) {
                rv = md_util_path_merge(&fpath, ptemp, path, name, NULL);
                if (APR_SUCCESS == rv) {
                    rv = apr_stat(&finfo, ctx->path, wanted, ptemp);
                }
            }
            
            if (APR_DIR == finfo.filetype) {
                if (!fpath) {
                    rv = md_util_path_merge(&fpath, ptemp, path, name, NULL);
                }
                if (APR_SUCCESS == rv) {
                    rv = tree_do(ctx, p, ptemp, fpath);
                    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, ptemp, "dir cb(%s/%s)", 
                                  path, name);
                    rv = ctx->cb(ctx->baton, p, ptemp, path, name, ftype);
                }
            }
            else {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, ptemp, "file cb(%s/%s)", 
                              path, name);
                rv = ctx->cb(ctx->baton, p, ptemp, path, name, finfo.filetype);
            }
        }

        apr_dir_close(d);
        
        if (APR_STATUS_IS_ENOENT(rv)) {
            rv = APR_SUCCESS;
        }
    }
    return rv;
}

static apr_status_t tree_start_do(void *baton, apr_pool_t *p, apr_pool_t *ptemp)
{
    md_util_fwalk_t *ctx = baton;
    apr_finfo_t info;
    apr_status_t rv;
    apr_int32_t wanted = ctx->follow_links? APR_FINFO_TYPE : (APR_FINFO_TYPE|APR_FINFO_LINK);
    
    rv = apr_stat(&info, ctx->path, wanted, ptemp);
    if (rv == APR_SUCCESS) {
        switch (info.filetype) {
            case APR_DIR:
                rv = tree_do(ctx, p, ptemp, ctx->path);
                break;
            default:
                rv = APR_EINVAL;
        }
    }
    return rv;
}

apr_status_t md_util_tree_do(md_util_fdo_cb *cb, void *baton, apr_pool_t *p, 
                             const char *path, int follow_links)
{
    apr_status_t rv;
    md_util_fwalk_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.path = path;
    ctx.follow_links = follow_links;
    ctx.cb = cb;
    ctx.baton = baton;
    
    rv = md_util_pool_do(tree_start_do, &ctx, p);
    
    return rv;
}

static apr_status_t rm_cb(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                          const char *path, const char *name, apr_filetype_e ftype)
{
    apr_status_t rv;
    const char *fpath;
    
    (void)baton;
    (void)p;
    rv = md_util_path_merge(&fpath, ptemp, path, name, NULL);
    if (APR_SUCCESS == rv) {
        if (APR_DIR == ftype) {
            rv = apr_dir_remove(fpath, ptemp);
        }
        else {
            rv = apr_file_remove(fpath, ptemp);
        }
    }
    return rv;
}

apr_status_t md_util_ftree_remove(const char *path, apr_pool_t *p)
{
    apr_status_t rv = md_util_tree_do(rm_cb, NULL, p, path, 0);
    if (APR_SUCCESS == rv) {
        rv = apr_dir_remove(path, p);
    }
    return rv;
}

/* DNS name checks ********************************************************************************/

int md_util_is_dns_name(apr_pool_t *p, const char *hostname, int need_fqdn)
{
    char c, last = 0;
    const char *cp = hostname;
    int dots = 0;
    
    /* Since we use the names in certificates, we need pure ASCII domain names
     * and IDN need to be converted to unicode. */
    while ((c = *cp++)) {
        switch (c) {
            case '.':
                if (last == '.') {
                    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, "dns name with ..: %s", 
                                  hostname);
                    return 0;
                }
                ++dots;
                break;
            case '-':
                break;
            default:
                if (!apr_isalnum(c)) {
                    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, "dns invalid char %c: %s", 
                                  c, hostname);
                    return 0;
                }
                break;
        }
        last = c;
    }
    
    if (last == '.') { /* DNS names may end with '.' */
        --dots;
    }
    if (need_fqdn && dots <= 0) { /* do not accept just top level domains */
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, "not a FQDN: %s", hostname);
        return 0;
    }
    return 1; /* empty string not allowed */
}

const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme)
{
    const char *cp = s;
    while (*cp) {
        if (*cp == ':') {
            /* could be an url scheme, leave unchanged */
            return s;
        }
        else if (!apr_isalnum(*cp)) {
            break;
        }
        ++cp;
    }
    return apr_psprintf(p, "%s:%s", def_scheme, s);
}

static apr_status_t uri_check(apr_uri_t *uri_parsed, apr_pool_t *p, 
                              const char *uri, const char **perr)
{
    const char *s, *err = NULL;
    apr_status_t rv;
    
    if (APR_SUCCESS != (rv = apr_uri_parse(p, uri, uri_parsed))) {
        err = "not an uri";
    }
    else if (uri_parsed->scheme) {
        if (strlen(uri_parsed->scheme) + 1 >= strlen(uri)) {
            err = "missing uri identifier";
        }
        else if (!strncmp("http", uri_parsed->scheme, 4)) {
            if (!uri_parsed->hostname) {
                err = "missing hostname";
            }
            else if (!md_util_is_dns_name(p, uri_parsed->hostname, 0)) {
                err = "invalid hostname";
            }
            if (uri_parsed->port_str 
                && (!apr_isdigit(uri_parsed->port_str[0])
                || uri_parsed->port == 0
                || uri_parsed->port > 65353)) {
                err = "invalid port";
            }
        }
        else if (!strcmp("mailto", uri_parsed->scheme)) {
            s = strchr(uri, '@');
            if (!s) {
                err = "missing @";
            }
            else if (strchr(s+1, '@')) {
                err = "duplicate @";
            }
            else if (s == uri + strlen(uri_parsed->scheme) + 1) {
                err = "missing local part";
            }
            else if (s == (uri + strlen(uri)-1)) {
                err = "missing hostname";
            }
            else if (strstr(uri, "..")) {
                err = "double period";
            }
        }
    }
    if (strchr(uri, ' ') || strchr(uri, '\t') ) {
        err = "whitespace in uri";
    }
    
    if (err) {
        rv = APR_EINVAL;
    }
    *perr = err;
    return rv;
}

apr_status_t md_util_abs_uri_check(apr_pool_t *p, const char *uri, const char **perr)
{
    apr_uri_t uri_parsed;
    apr_status_t rv;

    if (APR_SUCCESS == (rv = uri_check(&uri_parsed, p, uri, perr))) {
        if (!uri_parsed.scheme) {
            *perr = "missing uri scheme";
            return APR_EINVAL;
        }
    }
    return rv;
}

apr_status_t md_util_abs_http_uri_check(apr_pool_t *p, const char *uri, const char **perr)
{
    apr_uri_t uri_parsed;
    apr_status_t rv;

    if (APR_SUCCESS == (rv = uri_check(&uri_parsed, p, uri, perr))) {
        if (!uri_parsed.scheme) {
            *perr = "missing uri scheme";
            return APR_EINVAL;
        }
        if (apr_strnatcasecmp("http", uri_parsed.scheme) 
            && apr_strnatcasecmp("https", uri_parsed.scheme)) {
            *perr = "uri scheme must be http or https";
            return APR_EINVAL;
        }
    }
    return rv;
}

/* try and retry for a while **********************************************************************/

apr_status_t md_util_try(md_util_try_fn *fn, void *baton, int ignore_errs, 
                         apr_interval_time_t timeout, apr_interval_time_t start_delay, 
                         apr_interval_time_t max_delay, int backoff)
{
    apr_status_t rv;
    apr_time_t now = apr_time_now();
    apr_time_t giveup = now + timeout;
    apr_interval_time_t nap_duration = start_delay? start_delay : apr_time_from_msec(100);
    apr_interval_time_t nap_max = max_delay? max_delay : apr_time_from_sec(10);
    apr_interval_time_t left;
    int i = 0;
    
    while (1) {
        if (APR_SUCCESS == (rv = fn(baton, i++))) {
            break;
        }
        else if (!APR_STATUS_IS_EAGAIN(rv) && !ignore_errs) {
            break;
        }
        
        now = apr_time_now();
        if (now > giveup) {
            rv = APR_TIMEUP;
            break;
        }
        
        left = giveup - now;
        if (nap_duration > left) {
            nap_duration = left;
        }
        if (nap_duration > nap_max) {
            nap_duration = nap_max;
        }
        
        apr_sleep(nap_duration);
        if (backoff) {
            nap_duration *= 2;
        } 
    }
    return rv;
}

/* execute process ********************************************************************************/

apr_status_t md_util_exec(apr_pool_t *p, const char *cmd, const char * const *argv,
                          int *exit_code)
{
    apr_status_t rv;
    apr_procattr_t *procattr;
    apr_proc_t *proc;
    apr_exit_why_e ewhy;

    *exit_code = 0;
    if (!(proc = apr_pcalloc(p, sizeof(*proc)))) {
        return APR_ENOMEM;
    }
    if (   APR_SUCCESS == (rv = apr_procattr_create(&procattr, p))
        && APR_SUCCESS == (rv = apr_procattr_io_set(procattr, APR_NO_FILE, 
                                                    APR_NO_PIPE, APR_NO_PIPE))
        && APR_SUCCESS == (rv = apr_procattr_cmdtype_set(procattr, APR_PROGRAM))
        && APR_SUCCESS == (rv = apr_proc_create(proc, cmd, argv, NULL, procattr, p))
        && APR_CHILD_DONE == (rv = apr_proc_wait(proc, exit_code, &ewhy, APR_WAIT))) {
        /* let's not dwell on exit stati, but core should signal something's bad */
        if (*exit_code > 127 || APR_PROC_SIGNAL_CORE == ewhy) {
            return APR_EINCOMPLETE;
        }
        return APR_SUCCESS;
    }
    return rv;
}


/* date/time encoding *****************************************************************************/

const char *md_print_duration(apr_pool_t *p, apr_interval_time_t duration)
{
    int secs = (int)(apr_time_sec(duration) % MD_SECS_PER_DAY);
    return apr_psprintf(p, "%2d:%02d:%02d hours", 
                        (int)secs/MD_SECS_PER_HOUR, (int)(secs%(MD_SECS_PER_HOUR))/60,
                        (int)(secs%60));
}


/* base64 url encoding ****************************************************************************/

#define N6 (unsigned int)-1

static const unsigned int BASE64URL_UINT6[] = {
/*   0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f        */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  0 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  1 */ 
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, 62, N6, N6, /*  2 */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, N6, N6, N6, N6, N6, N6, /*  3 */ 
    N6, 0,  1,  2,  3,  4,  5,  6,   7,  8,  9, 10, 11, 12, 13, 14, /*  4 */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, N6, N6, N6, N6, 63, /*  5 */
    N6, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*  6 */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, N6, N6, N6, N6, N6, /*  7 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  8 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  9 */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  a */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  b */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  c */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  d */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, /*  e */
    N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6, N6  /*  f */
};
static const unsigned char BASE64URL_CHARS[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', /*  0 -  9 */
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', /* 10 - 19 */
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', /* 20 - 29 */
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', /* 30 - 39 */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', /* 40 - 49 */
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', /* 50 - 59 */
    '8', '9', '-', '_', ' ', ' ', ' ', ' ', ' ', ' ', /* 60 - 69 */
};

#define BASE64URL_CHAR(x)    BASE64URL_CHARS[ (unsigned int)(x) & 0x3fu ]
   
apr_size_t md_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool)
{
    const unsigned char *e = (const unsigned char *)encoded;
    const unsigned char *p = e;
    unsigned char *d;
    unsigned int n;
    long len, mlen, remain, i;
    
    while (*p && BASE64URL_UINT6[ *p ] != N6) {
        ++p;
    }
    len = (int)(p - e);
    mlen = (len/4)*4;
    *decoded = apr_pcalloc(pool, (apr_size_t)len + 1);
    
    i = 0;
    d = (unsigned char*)*decoded;
    for (; i < mlen; i += 4) {
        n = ((BASE64URL_UINT6[ e[i+0] ] << 18) +
             (BASE64URL_UINT6[ e[i+1] ] << 12) +
             (BASE64URL_UINT6[ e[i+2] ] << 6) +
             (BASE64URL_UINT6[ e[i+3] ]));
        *d++ = (unsigned char)(n >> 16);
        *d++ = (unsigned char)(n >> 8 & 0xffu);
        *d++ = (unsigned char)(n & 0xffu);
    }
    remain = len - mlen;
    switch (remain) {
        case 2:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12));
            *d++ = (unsigned char)(n >> 16);
            remain = 1;
            break;
        case 3:
            n = ((BASE64URL_UINT6[ e[mlen+0] ] << 18) +
                 (BASE64URL_UINT6[ e[mlen+1] ] << 12) +
                 (BASE64URL_UINT6[ e[mlen+2] ] << 6));
            *d++ = (unsigned char)(n >> 16);
            *d++ = (unsigned char)(n >> 8 & 0xffu);
            remain = 2;
            break;
        default: /* do nothing */
            break;
    }
    return (apr_size_t)(mlen/4*3 + remain);
}

const char *md_util_base64url_encode(const char *data, apr_size_t dlen, apr_pool_t *pool)
{
    int i, len = (int)dlen;
    apr_size_t slen = ((dlen+2)/3)*4 + 1; /* 0 terminated */
    const unsigned char *udata = (const unsigned char*)data;
    unsigned char *enc, *p = apr_pcalloc(pool, slen);
    
    enc = p;
    for (i = 0; i < len-2; i+= 3) {
        *p++ = BASE64URL_CHAR( (udata[i]   >> 2) );
        *p++ = BASE64URL_CHAR( (udata[i]   << 4) + (udata[i+1] >> 4) );
        *p++ = BASE64URL_CHAR( (udata[i+1] << 2) + (udata[i+2] >> 6) );
        *p++ = BASE64URL_CHAR( (udata[i+2]) );
    }
    
    if (i < len) {
        *p++ = BASE64URL_CHAR( (udata[i] >> 2) );
        if (i == (len - 1)) {
            *p++ = BASE64URL_CHARS[ ((unsigned int)udata[i] << 4) & 0x3fu ];
        }
        else {
            *p++ = BASE64URL_CHAR( (udata[i] << 4) + (udata[i+1] >> 4) );
            *p++ = BASE64URL_CHAR( (udata[i+1] << 2) );
        }
    }
    *p++ = '\0';
    return (char *)enc;
}

/*******************************************************************************
 * link header handling 
 ******************************************************************************/

typedef struct {
    const char *s;
    apr_size_t slen;
    apr_size_t i;
    apr_size_t link_start;
    apr_size_t link_len;
    apr_size_t pn_start;
    apr_size_t pn_len;
    apr_size_t pv_start;
    apr_size_t pv_len;
} link_ctx;

static int attr_char(char c) 
{
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return 1;
        default:
            return apr_isalnum(c);
    }
}

static int ptoken_char(char c) 
{
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case '-':
        case '.':
        case '/':
        case ':':
        case '<':
        case '=':
        case '>':
        case '?':
        case '@':
        case '[':
        case ']':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
            return 1;
        default:
            return apr_isalnum(c);
    }
}

static int skip_ws(link_ctx *ctx)
{
    char c;
    while (ctx->i < ctx->slen 
           && (((c = ctx->s[ctx->i]) == ' ') || (c == '\t'))) {
        ++ctx->i;
    }
    return (ctx->i < ctx->slen);
}

static int skip_nonws(link_ctx *ctx)
{
    char c;
    while (ctx->i < ctx->slen 
           && (((c = ctx->s[ctx->i]) != ' ') && (c != '\t'))) {
        ++ctx->i;
    }
    return (ctx->i < ctx->slen);
}

static unsigned int find_chr(link_ctx *ctx, char c, apr_size_t *pidx)
{
    apr_size_t j;
    for (j = ctx->i; j < ctx->slen; ++j) {
        if (ctx->s[j] == c) {
            *pidx = j;
            return 1;
        }
    } 
    return 0;
}

static int read_chr(link_ctx *ctx, char c)
{
    if (ctx->i < ctx->slen && ctx->s[ctx->i] == c) {
        ++ctx->i;
        return 1;
    }
    return 0;
}

static int skip_qstring(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, '\"')) {
        apr_size_t end;
        if (find_chr(ctx, '\"', &end)) {
            ctx->i = end + 1;
            return 1;
        }
    }
    return 0;
}

static int skip_ptoken(link_ctx *ctx)
{
    if (skip_ws(ctx)) {
        apr_size_t i;
        for (i = ctx->i; i < ctx->slen && ptoken_char(ctx->s[i]); ++i) {
            /* nop */
        }
        if (i > ctx->i) {
            ctx->i = i;
            return 1;
        }
    }
    return 0;
}


static int read_link(link_ctx *ctx)
{
    ctx->link_start = ctx->link_len = 0;
    if (skip_ws(ctx) && read_chr(ctx, '<')) {
        apr_size_t end;
        if (find_chr(ctx, '>', &end)) {
            ctx->link_start = ctx->i;
            ctx->link_len = end - ctx->link_start;
            ctx->i = end + 1;
            return 1;
        }
    }
    return 0;
}

static int skip_pname(link_ctx *ctx)
{
    if (skip_ws(ctx)) {
        apr_size_t i;
        for (i = ctx->i; i < ctx->slen && attr_char(ctx->s[i]); ++i) {
            /* nop */
        }
        if (i > ctx->i) {
            ctx->i = i;
            return 1;
        }
    }
    return 0;
}

static int skip_pvalue(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, '=')) {
        ctx->pv_start = ctx->i;
        if (skip_qstring(ctx) || skip_ptoken(ctx)) {
            ctx->pv_len = ctx->i - ctx->pv_start;
            return 1;
        }
    }
    return 0;
}

static int skip_param(link_ctx *ctx)
{
    if (skip_ws(ctx) && read_chr(ctx, ';')) {
        ctx->pn_start = ctx->i;
        ctx->pn_len = 0;
        if (skip_pname(ctx)) {
            ctx->pn_len = ctx->i - ctx->pn_start;
            ctx->pv_len = 0;
            skip_pvalue(ctx); /* value is optional */
            return 1;
        }
    }
    return 0;
}

static int pv_contains(link_ctx *ctx, const char *s)
{
    apr_size_t pvstart = ctx->pv_start;
    apr_size_t pvlen = ctx->pv_len;
    
    if (ctx->s[pvstart] == '\"' && pvlen > 1) {
        ++pvstart;
        pvlen -= 2;
    }
    if (pvlen > 0) {
        apr_size_t slen = strlen(s);
        link_ctx pvctx;
        apr_size_t i;
        
        memset(&pvctx, 0, sizeof(pvctx));
        pvctx.s = ctx->s + pvstart;
        pvctx.slen = pvlen;

        for (i = 0; i < pvctx.slen; i = pvctx.i) {
            skip_nonws(&pvctx);
            if ((pvctx.i - i) == slen && !strncmp(s, pvctx.s + i, slen)) {
                return 1;
            }
            skip_ws(&pvctx);
        }
    }
    return 0;
}

/* RFC 5988 <https://tools.ietf.org/html/rfc5988#section-6.2.1>
  Link           = "Link" ":" #link-value
  link-value     = "<" URI-Reference ">" *( ";" link-param )
  link-param     = ( ( "rel" "=" relation-types )
                 | ( "anchor" "=" <"> URI-Reference <"> )
                 | ( "rev" "=" relation-types )
                 | ( "hreflang" "=" Language-Tag )
                 | ( "media" "=" ( MediaDesc | ( <"> MediaDesc <"> ) ) )
                 | ( "title" "=" quoted-string )
                 | ( "title*" "=" ext-value )
                 | ( "type" "=" ( media-type | quoted-mt ) )
                 | ( link-extension ) )
  link-extension = ( parmname [ "=" ( ptoken | quoted-string ) ] )
                 | ( ext-name-star "=" ext-value )
  ext-name-star  = parmname "*" ; reserved for RFC2231-profiled
                                ; extensions.  Whitespace NOT
                                ; allowed in between.
  ptoken         = 1*ptokenchar
  ptokenchar     = "!" | "#" | "$" | "%" | "&" | "'" | "("
                 | ")" | "*" | "+" | "-" | "." | "/" | DIGIT
                 | ":" | "<" | "=" | ">" | "?" | "@" | ALPHA
                 | "[" | "]" | "^" | "_" | "`" | "{" | "|"
                 | "}" | "~"
  media-type     = type-name "/" subtype-name
  quoted-mt      = <"> media-type <">
  relation-types = relation-type
                 | <"> relation-type *( 1*SP relation-type ) <">
  relation-type  = reg-rel-type | ext-rel-type
  reg-rel-type   = LOALPHA *( LOALPHA | DIGIT | "." | "-" )
  ext-rel-type   = URI
  
  and from <https://tools.ietf.org/html/rfc5987>
  parmname      = 1*attr-char
  attr-char     = ALPHA / DIGIT
                   / "!" / "#" / "$" / "&" / "+" / "-" / "."
                   / "^" / "_" / "`" / "|" / "~"
 */

typedef struct {
    apr_pool_t *pool;
    const char *relation;
    const char *url;
} find_ctx;

static int find_url(void *baton, const char *key, const char *value)
{
    find_ctx *outer = baton;
    
    if (!apr_strnatcasecmp("link", key)) {
        link_ctx ctx;
        
        memset(&ctx, 0, sizeof(ctx));
        ctx.s = value;
        ctx.slen = strlen(value);
        
        while (read_link(&ctx)) {
            while (skip_param(&ctx)) {
                if (ctx.pn_len == 3 && !strncmp("rel", ctx.s + ctx.pn_start, 3)
                    && pv_contains(&ctx, outer->relation)) {
                    /* this is the link relation we are looking for */
                    outer->url = apr_pstrndup(outer->pool, ctx.s + ctx.link_start, ctx.link_len);
                    return 0;
                }
            }
        }
    }
    return 1;
}

const char *md_link_find_relation(const apr_table_t *headers, 
                                  apr_pool_t *pool, const char *relation)
{
    find_ctx ctx;
    
    memset(&ctx, 0, sizeof(ctx));
    ctx.pool = pool;
    ctx.relation = relation;
    
    apr_table_do(find_url, &ctx, headers, NULL);
    
    return ctx.url;
}

