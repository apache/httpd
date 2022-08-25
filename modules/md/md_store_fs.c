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
 
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_fnmatch.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"
#include "md_log.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_util.h"
#include "md_version.h"

/**************************************************************************************************/
/* file system based implementation of md_store_t */

#define MD_STORE_VERSION        3
#define MD_FS_LOCK_NAME         "store.lock"

typedef struct {
    apr_fileperms_t dir;
    apr_fileperms_t file;
} perms_t;

typedef struct md_store_fs_t md_store_fs_t;
struct md_store_fs_t {
    md_store_t s;
    
    const char *base;       /* base directory of store */
    perms_t def_perms;
    perms_t group_perms[MD_SG_COUNT];
    md_store_fs_cb *event_cb;
    void *event_baton;
    
    md_data_t key;
    int plain_pkey[MD_SG_COUNT];
    
    int port_80;
    int port_443;

    apr_file_t *global_lock;
};

#define FS_STORE(store)     (md_store_fs_t*)(((char*)store)-offsetof(md_store_fs_t, s))
#define FS_STORE_JSON       "md_store.json"
#define FS_STORE_KLEN       48

static apr_status_t fs_load(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void **pvalue, apr_pool_t *p);
static apr_status_t fs_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void *value, int create);
static apr_status_t fs_remove(md_store_t *store, md_store_group_t group, 
                              const char *name, const char *aspect, 
                              apr_pool_t *p, int force);
static apr_status_t fs_purge(md_store_t *store, apr_pool_t *p, 
                             md_store_group_t group, const char *name);
static apr_status_t fs_remove_nms(md_store_t *store, apr_pool_t *p, 
                                  apr_time_t modified, md_store_group_t group, 
                                  const char *name, const char *aspect);
static apr_status_t fs_move(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t from, md_store_group_t to, 
                            const char *name, int archive);
static apr_status_t fs_rename(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t group, const char *from, const char *to);
static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               apr_pool_t *p, md_store_group_t group,  const char *pattern,
                               const char *aspect, md_store_vtype_t vtype);
static apr_status_t fs_iterate_names(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                     apr_pool_t *p, md_store_group_t group, const char *pattern);

static apr_status_t fs_get_fname(const char **pfname, 
                                 md_store_t *store, md_store_group_t group, 
                                 const char *name, const char *aspect, 
                                 apr_pool_t *p);
static int fs_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                       const char *name, const char *aspect, apr_pool_t *p);

static apr_time_t fs_get_modified(md_store_t *store, md_store_group_t group,  
                                  const char *name, const char *aspect, apr_pool_t *p);

static apr_status_t fs_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait);
static void fs_unlock_global(md_store_t *store, apr_pool_t *p);

static apr_status_t init_store_file(md_store_fs_t *s_fs, const char *fname, 
                                    apr_pool_t *p, apr_pool_t *ptemp)
{
    md_json_t *json = md_json_create(p);
    const char *key64;
    apr_status_t rv;
    
    md_json_setn(MD_STORE_VERSION, json, MD_KEY_STORE, MD_KEY_VERSION, NULL);

    md_data_pinit(&s_fs->key, FS_STORE_KLEN, p);
    if (APR_SUCCESS != (rv = md_rand_bytes((unsigned char*)s_fs->key.data, s_fs->key.len, p))) {
        return rv;
    }
        
    key64 = md_util_base64url_encode(&s_fs->key, ptemp);
    md_json_sets(key64, json, MD_KEY_KEY, NULL);
    rv = md_json_fcreatex(json, ptemp, MD_JSON_FMT_INDENT, fname, MD_FPROT_F_UONLY);
    memset((char*)key64, 0, strlen(key64));

    return rv;
}

static apr_status_t rename_pkey(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                                const char *dir, const char *name, 
                                apr_filetype_e ftype)
{
    const char *from, *to;
    apr_status_t rv = APR_SUCCESS;
    
    (void)baton;
    (void)ftype;
    if (   MD_OK(md_util_path_merge(&from, ptemp, dir, name, NULL))
        && MD_OK(md_util_path_merge(&to, ptemp, dir, MD_FN_PRIVKEY, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p, "renaming %s/%s to %s", 
                      dir, name, MD_FN_PRIVKEY);
        return apr_file_rename(from, to, ptemp);
    }
    return rv;
}

static apr_status_t mk_pubcert(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                               const char *dir, const char *name, 
                               apr_filetype_e ftype)
{
    md_cert_t *cert;
    apr_array_header_t *chain, *pubcert;
    const char *fname, *fpubcert;
    apr_status_t rv = APR_SUCCESS;
    
    (void)baton;
    (void)ftype;
    (void)p;
    if (   MD_OK(md_util_path_merge(&fpubcert, ptemp, dir, MD_FN_PUBCERT, NULL))
        && APR_STATUS_IS_ENOENT(rv = md_chain_fload(&pubcert, ptemp, fpubcert))
        && MD_OK(md_util_path_merge(&fname, ptemp, dir, name, NULL))
        && MD_OK(md_cert_fload(&cert, ptemp, fname))
        && MD_OK(md_util_path_merge(&fname, ptemp, dir, "chain.pem", NULL))) {
        
        rv = md_chain_fload(&chain, ptemp, fname);
        if (APR_STATUS_IS_ENOENT(rv)) {
            chain = apr_array_make(ptemp, 1, sizeof(md_cert_t*));
            rv = APR_SUCCESS;
        }
        if (APR_SUCCESS == rv) {
            pubcert = apr_array_make(ptemp, chain->nelts + 1, sizeof(md_cert_t*));
            APR_ARRAY_PUSH(pubcert, md_cert_t *) = cert;
            apr_array_cat(pubcert, chain);
            rv = md_chain_fsave(pubcert, ptemp, fpubcert, MD_FPROT_F_UONLY);
        }
    }
    return rv;
}

static apr_status_t upgrade_from_1_0(md_store_fs_t *s_fs, apr_pool_t *p, apr_pool_t *ptemp)
{
    md_store_group_t g;
    apr_status_t rv = APR_SUCCESS;
    
    (void)ptemp;
    /* Migrate pkey.pem -> privkey.pem */
    for (g = MD_SG_NONE; g < MD_SG_COUNT && APR_SUCCESS == rv; ++g) {
        rv = md_util_files_do(rename_pkey, s_fs, p, s_fs->base, 
                              md_store_group_name(g), "*", "pkey.pem", NULL);
    }
    /* Generate fullcert.pem from cert.pem and chain.pem where missing */
    rv = md_util_files_do(mk_pubcert, s_fs, p, s_fs->base, 
                          md_store_group_name(MD_SG_DOMAINS), "*", MD_FN_CERT, NULL);
    rv = md_util_files_do(mk_pubcert, s_fs, p, s_fs->base, 
                          md_store_group_name(MD_SG_ARCHIVE), "*", MD_FN_CERT, NULL);
    
    return rv;
}

static apr_status_t read_store_file(md_store_fs_t *s_fs, const char *fname, 
                                    apr_pool_t *p, apr_pool_t *ptemp)
{
    md_json_t *json;
    const char *key64;
    apr_status_t rv;
    double store_version;
    
    if (MD_OK(md_json_readf(&json, p, fname))) {
        store_version = md_json_getn(json, MD_KEY_STORE, MD_KEY_VERSION, NULL);
        if (store_version <= 0.0) {
            /* ok, an old one, compatible to 1.0 */
            store_version = 1.0;
        }
        if (store_version > MD_STORE_VERSION) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "version too new: %f", store_version);
            return APR_EINVAL;
        }

        key64 = md_json_dups(p, json, MD_KEY_KEY, NULL);
        if (!key64) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "missing key: %s", MD_KEY_KEY);
            return APR_EINVAL;
        }
        
        md_util_base64url_decode(&s_fs->key, key64, p);
        if (s_fs->key.len != FS_STORE_KLEN) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "key length unexpected: %" APR_SIZE_T_FMT, 
                          s_fs->key.len);
            return APR_EINVAL;
        }

        /* Need to migrate format? */
        if (store_version < MD_STORE_VERSION) {
            if (store_version <= 1.0) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "migrating store v1 -> v2");
                rv = upgrade_from_1_0(s_fs, p, ptemp);
            }
            if (store_version <= 2.0) {
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "migrating store v2 -> v3");
                md_json_del(json, MD_KEY_VERSION, NULL);
            }
            
            if (APR_SUCCESS == rv) {
                md_json_setn(MD_STORE_VERSION, json, MD_KEY_STORE, MD_KEY_VERSION, NULL);
                rv = md_json_freplace(json, ptemp, MD_JSON_FMT_INDENT, fname, MD_FPROT_F_UONLY);
            }
            md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p, "migrated store");
        } 
    }
    return rv;
}

static apr_status_t setup_store_file(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *fname;
    apr_status_t rv;

    (void)ap;
    s_fs->plain_pkey[MD_SG_DOMAINS] = 1;
    /* Added: the encryption of tls-alpn-01 certificate keys is not a security issue
     * for these self-signed, short-lived certificates. Having them unencrypted let's
     * use pass around the files insteak of an *SSL implementation dependent PKEY_something.
     */
    s_fs->plain_pkey[MD_SG_CHALLENGES] = 1;
    s_fs->plain_pkey[MD_SG_TMP] = 1;
    
    if (!MD_OK(md_util_path_merge(&fname, ptemp, s_fs->base, FS_STORE_JSON, NULL))) {
        return rv;
    }
    
read:
    if (MD_OK(md_util_is_file(fname, ptemp))) {
        rv = read_store_file(s_fs, fname, p, ptemp);
    }
    else if (APR_STATUS_IS_ENOENT(rv)
        && APR_STATUS_IS_EEXIST(rv = init_store_file(s_fs, fname, p, ptemp))) {
        goto read;
    }
    return rv;
}

apr_status_t md_store_fs_init(md_store_t **pstore, apr_pool_t *p, const char *path)
{
    md_store_fs_t *s_fs;
    apr_status_t rv = APR_SUCCESS;
    
    s_fs = apr_pcalloc(p, sizeof(*s_fs));

    s_fs->s.load = fs_load;
    s_fs->s.save = fs_save;
    s_fs->s.remove = fs_remove;
    s_fs->s.move = fs_move;
    s_fs->s.rename = fs_rename;
    s_fs->s.purge = fs_purge;
    s_fs->s.iterate = fs_iterate;
    s_fs->s.iterate_names = fs_iterate_names;
    s_fs->s.get_fname = fs_get_fname;
    s_fs->s.is_newer = fs_is_newer;
    s_fs->s.get_modified = fs_get_modified;
    s_fs->s.remove_nms = fs_remove_nms;
    s_fs->s.lock_global = fs_lock_global;
    s_fs->s.unlock_global = fs_unlock_global;

    /* by default, everything is only readable by the current user */ 
    s_fs->def_perms.dir = MD_FPROT_D_UONLY;
    s_fs->def_perms.file = MD_FPROT_F_UONLY;

    /* Account information needs to be accessible to httpd child processes.
     * private keys are, similar to staging, encrypted. */
    s_fs->group_perms[MD_SG_ACCOUNTS].dir = MD_FPROT_D_UALL_WREAD;
    s_fs->group_perms[MD_SG_ACCOUNTS].file = MD_FPROT_F_UALL_WREAD;
    s_fs->group_perms[MD_SG_STAGING].dir = MD_FPROT_D_UALL_WREAD;
    s_fs->group_perms[MD_SG_STAGING].file = MD_FPROT_F_UALL_WREAD;
    /* challenges dir and files are readable by all, no secrets involved */ 
    s_fs->group_perms[MD_SG_CHALLENGES].dir = MD_FPROT_D_UALL_WREAD;
    s_fs->group_perms[MD_SG_CHALLENGES].file = MD_FPROT_F_UALL_WREAD;
    /* OCSP data is readable by all, no secrets involved */ 
    s_fs->group_perms[MD_SG_OCSP].dir = MD_FPROT_D_UALL_WREAD;
    s_fs->group_perms[MD_SG_OCSP].file = MD_FPROT_F_UALL_WREAD;

    s_fs->base = apr_pstrdup(p, path);

    rv = md_util_is_dir(s_fs->base, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_INFO, rv, p,
            "store directory does not exist, creating %s", s_fs->base);
        rv = apr_dir_make_recursive(s_fs->base, s_fs->def_perms.dir, p);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = apr_file_perms_set(s_fs->base, MD_FPROT_D_UALL_WREAD);
        if (APR_STATUS_IS_ENOTIMPL(rv)) {
            rv = APR_SUCCESS;
        }
        if (APR_SUCCESS != rv) goto cleanup;
    }
    else if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, p,
            "not a plain directory, maybe a symlink? %s", s_fs->base);
    }

    rv = md_util_pool_vdo(setup_store_file, s_fs, p, NULL);
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "init fs store at %s", s_fs->base);
    }
cleanup:
    *pstore = (rv == APR_SUCCESS)? &(s_fs->s) : NULL;
    return rv;
}

apr_status_t md_store_fs_default_perms_set(md_store_t *store, 
                                           apr_fileperms_t file_perms,
                                           apr_fileperms_t dir_perms)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    
    s_fs->def_perms.file = file_perms;
    s_fs->def_perms.dir = dir_perms;
    return APR_SUCCESS;
}

apr_status_t md_store_fs_group_perms_set(md_store_t *store, md_store_group_t group, 
                                         apr_fileperms_t file_perms,
                                         apr_fileperms_t dir_perms)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    
    if (group >= (sizeof(s_fs->group_perms)/sizeof(s_fs->group_perms[0]))) {
        return APR_ENOTIMPL;
    }
    s_fs->group_perms[group].file = file_perms;
    s_fs->group_perms[group].dir = dir_perms;
    return APR_SUCCESS;
}

apr_status_t md_store_fs_set_event_cb(struct md_store_t *store, md_store_fs_cb *cb, void *baton)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    
    s_fs->event_cb = cb;
    s_fs->event_baton = baton;
    return APR_SUCCESS;
}

static const perms_t *gperms(md_store_fs_t *s_fs, md_store_group_t group)
{
    if (group >= (sizeof(s_fs->group_perms)/sizeof(s_fs->group_perms[0]))
        || !s_fs->group_perms[group].dir) {
        return &s_fs->def_perms;
    }
    return &s_fs->group_perms[group];
}

static apr_status_t fs_get_fname(const char **pfname, 
                                 md_store_t *store, md_store_group_t group, 
                                 const char *name, const char *aspect, 
                                 apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    if (group == MD_SG_NONE) {
        return md_util_path_merge(pfname, p, s_fs->base, aspect, NULL);
    }
    return md_util_path_merge(pfname, p, 
                              s_fs->base, md_store_group_name(group), name, aspect, NULL);
}

static apr_status_t fs_get_dname(const char **pdname, 
                                 md_store_t *store, md_store_group_t group, 
                                 const char *name, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    if (group == MD_SG_NONE) {
        *pdname = s_fs->base;
        return APR_SUCCESS;
    }
    return md_util_path_merge(pdname, p, s_fs->base, md_store_group_name(group), name, NULL);
}

static void get_pass(const char **ppass, apr_size_t *plen, 
                     md_store_fs_t *s_fs, md_store_group_t group)
{
    if (s_fs->plain_pkey[group]) {
        *ppass = NULL;
        *plen = 0;
    }
    else {
        *ppass = (const char *)s_fs->key.data;
        *plen = s_fs->key.len;
    }
}
 
static apr_status_t fs_fload(void **pvalue, md_store_fs_t *s_fs, const char *fpath, 
                             md_store_group_t group, md_store_vtype_t vtype, 
                             apr_pool_t *p, apr_pool_t *ptemp)
{
    apr_status_t rv;
    const char *pass;
    apr_size_t pass_len;
    
    if (pvalue != NULL) {
        switch (vtype) {
            case MD_SV_TEXT:
                rv = md_text_fread8k((const char **)pvalue, p, fpath);
                break;
            case MD_SV_JSON:
                rv = md_json_readf((md_json_t **)pvalue, p, fpath);
                break;
            case MD_SV_CERT:
                rv = md_cert_fload((md_cert_t **)pvalue, p, fpath);
                break;
            case MD_SV_PKEY:
                get_pass(&pass, &pass_len, s_fs, group);
                rv = md_pkey_fload((md_pkey_t **)pvalue, p, pass, pass_len, fpath);
                break;
            case MD_SV_CHAIN:
                rv = md_chain_fload((apr_array_header_t **)pvalue, p, fpath);
                break;
            default:
                rv = APR_ENOTIMPL;
                break;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, ptemp, 
                      "loading type %d from %s", vtype, fpath);
    }
    else { /* check for existence only */
        rv = md_util_is_file(fpath, p);
    }
    return rv;
}

static apr_status_t pfs_load(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *fpath, *name, *aspect;
    md_store_vtype_t vtype;
    md_store_group_t group;
    void **pvalue;
    apr_status_t rv;
    
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char *);
    aspect = va_arg(ap, const char *);
    vtype = (md_store_vtype_t)va_arg(ap, int);
    pvalue= va_arg(ap, void **);
        
    if (MD_OK(fs_get_fname(&fpath, &s_fs->s, group, name, aspect, ptemp))) {
        rv = fs_fload(pvalue, s_fs, fpath, group, vtype, p, ptemp);
    }
    return rv;
}

static apr_status_t dispatch(md_store_fs_t *s_fs, md_store_fs_ev_t ev, unsigned int group, 
                             const char *fname, apr_filetype_e ftype, apr_pool_t *p)
{
    (void)ev;
    if (s_fs->event_cb) {
        return s_fs->event_cb(s_fs->event_baton, &s_fs->s, MD_S_FS_EV_CREATED, 
                              group, fname, ftype, p);
    }
    return APR_SUCCESS;
}

static apr_status_t mk_group_dir(const char **pdir, md_store_fs_t *s_fs, 
                                 md_store_group_t group, const char *name,
                                 apr_pool_t *p)
{
    const perms_t *perms;
    apr_status_t rv;
    
    perms = gperms(s_fs, group);

    *pdir = NULL;
    rv = fs_get_dname(pdir, &s_fs->s, group, name, p);
    if ((APR_SUCCESS != rv) || (MD_SG_NONE == group)) goto cleanup;

    rv = md_util_is_dir(*pdir, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, "not a directory, creating %s", *pdir);
        rv = apr_dir_make_recursive(*pdir, perms->dir, p);
        if (APR_SUCCESS != rv) goto cleanup;
        dispatch(s_fs, MD_S_FS_EV_CREATED, group, *pdir, APR_DIR, p);
    }

    rv = apr_file_perms_set(*pdir, perms->dir);
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, rv, p, "mk_group_dir %s perm set", *pdir);
    if (APR_STATUS_IS_ENOTIMPL(rv)) {
        rv = APR_SUCCESS;
    }
cleanup:
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "mk_group_dir %d %s",
            group, (*pdir? *pdir : (name? name : "(null)")));
    }
    return rv;
}

static apr_status_t pfs_is_newer(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *fname1, *fname2, *name, *aspect;
    md_store_group_t group1, group2;
    apr_finfo_t inf1, inf2;
    int *pnewer;
    apr_status_t rv;
    
    (void)p;
    group1 = (md_store_group_t)va_arg(ap, int);
    group2 = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char*);
    pnewer = va_arg(ap, int*);
    
    *pnewer = 0;
    if (   MD_OK(fs_get_fname(&fname1, &s_fs->s, group1, name, aspect, ptemp))
        && MD_OK(fs_get_fname(&fname2, &s_fs->s, group2, name, aspect, ptemp))
        && MD_OK(apr_stat(&inf1, fname1, APR_FINFO_MTIME, ptemp))
        && MD_OK(apr_stat(&inf2, fname2, APR_FINFO_MTIME, ptemp))) {
        *pnewer = inf1.mtime > inf2.mtime;
    }

    return rv;
}

static int fs_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                       const char *name, const char *aspect, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    int newer = 0;
    apr_status_t rv;
    
    rv = md_util_pool_vdo(pfs_is_newer, s_fs, p, group1, group2, name, aspect, &newer, NULL);
    if (APR_SUCCESS == rv) {
        return newer;
    }
    return 0;
}

static apr_status_t pfs_get_modified(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *fname, *name, *aspect;
    md_store_group_t group;
    apr_finfo_t inf;
    apr_time_t *pmtime;
    apr_status_t rv;
    
    (void)p;
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char*);
    pmtime = va_arg(ap, apr_time_t*);
    
    *pmtime = 0;
    if (   MD_OK(fs_get_fname(&fname, &s_fs->s, group, name, aspect, ptemp))
        && MD_OK(apr_stat(&inf, fname, APR_FINFO_MTIME, ptemp))) {
        *pmtime = inf.mtime;
    }

    return rv;
}

static apr_time_t fs_get_modified(md_store_t *store, md_store_group_t group,  
                                  const char *name, const char *aspect, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    apr_time_t mtime;
    apr_status_t rv;
    
    rv = md_util_pool_vdo(pfs_get_modified, s_fs, p, group, name, aspect, &mtime, NULL);
    if (APR_SUCCESS == rv) {
        return mtime;
    }
    return 0;
}
 
static apr_status_t pfs_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *gdir, *dir, *fpath, *name, *aspect;
    md_store_vtype_t vtype;
    md_store_group_t group;
    void *value;
    int create;
    apr_status_t rv;
    const perms_t *perms;
    const char *pass;
    apr_size_t pass_len;
    
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char*);
    vtype = (md_store_vtype_t)va_arg(ap, int);
    value = va_arg(ap, void *);
    create = va_arg(ap, int);
    
    perms = gperms(s_fs, group);
    
    if (   MD_OK(mk_group_dir(&gdir, s_fs, group, NULL, p)) 
        && MD_OK(mk_group_dir(&dir, s_fs, group, name, p))
        && MD_OK(md_util_path_merge(&fpath, ptemp, dir, aspect, NULL))) {
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, 0, ptemp, "storing in %s", fpath);
        switch (vtype) {
            case MD_SV_TEXT:
                rv = (create? md_text_fcreatex(fpath, perms->file, p, value)
                      : md_text_freplace(fpath, perms->file, p, value));
                break;
            case MD_SV_JSON:
                rv = (create? md_json_fcreatex((md_json_t *)value, p, MD_JSON_FMT_INDENT, 
                                               fpath, perms->file)
                      : md_json_freplace((md_json_t *)value, p, MD_JSON_FMT_INDENT, 
                                         fpath, perms->file));
                break;
            case MD_SV_CERT:
                rv = md_cert_fsave((md_cert_t *)value, ptemp, fpath, perms->file);
                break;
            case MD_SV_PKEY:
                /* Take care that we write private key with access only to the user,
                 * unless we write the key encrypted */
                get_pass(&pass, &pass_len, s_fs, group);
                rv = md_pkey_fsave((md_pkey_t *)value, ptemp, pass, pass_len, 
                                   fpath, (pass && pass_len)? perms->file : MD_FPROT_F_UONLY);
                break;
            case MD_SV_CHAIN:
                rv = md_chain_fsave((apr_array_header_t*)value, ptemp, fpath, perms->file);
                break;
            default:
                return APR_ENOTIMPL;
        }
        if (APR_SUCCESS == rv) {
            rv = dispatch(s_fs, MD_S_FS_EV_CREATED, group, fpath, APR_REG, p);
        }
    }
    return rv;
}

static apr_status_t pfs_remove(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *dir, *name, *fpath, *groupname, *aspect;
    apr_status_t rv;
    int force;
    apr_finfo_t info;
    md_store_group_t group;
    
    (void)p;
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char *);
    force = va_arg(ap, int);
    
    groupname = md_store_group_name(group);
    
    if (   MD_OK(md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))
        && MD_OK(md_util_path_merge(&fpath, ptemp, dir, aspect, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, ptemp, "start remove of md %s/%s/%s", 
                      groupname, name, aspect);

        if (!MD_OK(apr_stat(&info, dir, APR_FINFO_TYPE, ptemp))) {
            if (APR_ENOENT == rv && force) {
                return APR_SUCCESS;
            }
            return rv;
        }
    
        rv = apr_file_remove(fpath, ptemp);
        if (APR_ENOENT == rv && force) {
            rv = APR_SUCCESS;
        }
    }
    return rv;
}

static apr_status_t fs_load(md_store_t *store, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void **pvalue, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_load, s_fs, p, group, name, aspect, vtype, pvalue, NULL);
}

static apr_status_t fs_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                            const char *name, const char *aspect,  
                            md_store_vtype_t vtype, void *value, int create)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_save, s_fs, p, group, name, aspect, 
                            vtype, value, create, NULL);
}

static apr_status_t fs_remove(md_store_t *store, md_store_group_t group, 
                              const char *name, const char *aspect, 
                              apr_pool_t *p, int force)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_remove, s_fs, p, group, name, aspect, force, NULL);
}

static apr_status_t pfs_purge(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *dir, *name, *groupname;
    md_store_group_t group;
    apr_status_t rv;
    
    (void)p;
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    
    groupname = md_store_group_name(group);

    if (MD_OK(md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))) {
        /* Remove all files in dir, there should be no sub-dirs */
        rv = md_util_rm_recursive(dir, ptemp, 1);
    }
    if (!APR_STATUS_IS_ENOENT(rv)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE2, rv, ptemp, "purge %s/%s (%s)", groupname, name, dir);
    }
    return APR_SUCCESS;
}

static apr_status_t fs_purge(md_store_t *store, apr_pool_t *p, 
                             md_store_group_t group, const char *name)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_purge, s_fs, p, group, name, NULL);
}

/**************************************************************************************************/
/* iteration */

typedef struct {
    md_store_fs_t *s_fs;
    md_store_group_t group;
    const char *pattern;
    const char *aspect;
    md_store_vtype_t vtype;
    md_store_inspect *inspect;
    const char *dirname;
    void *baton;
    apr_time_t ts;
} inspect_ctx;

static apr_status_t insp(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                         const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    apr_status_t rv;
    void *value;
    const char *fpath;
 
    (void)ftype;   
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting value at: %s/%s", dir, name);
    if (APR_SUCCESS == (rv = md_util_path_merge(&fpath, ptemp, dir, name, NULL))) {
        rv = fs_fload(&value, ctx->s_fs, fpath, ctx->group, ctx->vtype, p, ptemp);
        if (APR_SUCCESS == rv 
            && !ctx->inspect(ctx->baton, ctx->dirname, name, ctx->vtype, value, p)) {
            return APR_EOF;
        }
        else if (APR_STATUS_IS_ENOENT(rv)) {
            rv = APR_SUCCESS;
        }
    } 
    return rv;
}

static apr_status_t insp_dir(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                             const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    apr_status_t rv;
    const char *fpath;
 
    (void)ftype;
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting dir at: %s/%s", dir, name);
    if (MD_OK(md_util_path_merge(&fpath, p, dir, name, NULL))) {
        ctx->dirname = name;
        rv = md_util_files_do(insp, ctx, p, fpath, ctx->aspect, NULL);
        if (APR_STATUS_IS_ENOENT(rv)) {
            rv = APR_SUCCESS;
        }
    } 
    return rv;
}

static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               apr_pool_t *p, md_store_group_t group, const char *pattern, 
                               const char *aspect, md_store_vtype_t vtype)
{
    const char *groupname;
    apr_status_t rv;
    inspect_ctx ctx;
    
    ctx.s_fs = FS_STORE(store);
    ctx.group = group;
    ctx.pattern = pattern;
    ctx.aspect = aspect;
    ctx.vtype = vtype;
    ctx.inspect = inspect;
    ctx.baton = baton;
    groupname = md_store_group_name(group);

    rv = md_util_files_do(insp_dir, &ctx, p, ctx.s_fs->base, groupname, pattern, NULL);
    
    return rv;
}

static apr_status_t insp_name(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                              const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    
    (void)ftype;
    (void)p;
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting name at: %s/%s", dir, name);
    return ctx->inspect(ctx->baton, dir, name, 0, NULL, ptemp);
}

static apr_status_t fs_iterate_names(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                     apr_pool_t *p, md_store_group_t group, const char *pattern)
{
    const char *groupname;
    apr_status_t rv;
    inspect_ctx ctx;
    
    ctx.s_fs = FS_STORE(store);
    ctx.group = group;
    ctx.pattern = pattern;
    ctx.inspect = inspect;
    ctx.baton = baton;
    groupname = md_store_group_name(group);

    rv = md_util_files_do(insp_name, &ctx, p, ctx.s_fs->base, groupname, pattern, NULL);
    
    return rv;
}

static apr_status_t remove_nms_file(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                                    const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    const char *fname;
    apr_finfo_t inf;
    apr_status_t rv = APR_SUCCESS;

    (void)p;
    if (APR_DIR == ftype) goto leave;
    if (APR_SUCCESS != (rv = md_util_path_merge(&fname, ptemp, dir, name, NULL))) goto leave;
    if (APR_SUCCESS != (rv = apr_stat(&inf, fname, APR_FINFO_MTIME, ptemp))) goto leave;
    if (inf.mtime >= ctx->ts) goto leave;

    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "remove_nms file: %s/%s", dir, name);
    rv = apr_file_remove(fname, ptemp);

leave:
    return rv;
}

static apr_status_t remove_nms_dir(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                                   const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    apr_status_t rv;
    const char *fpath;
 
    (void)ftype;
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "remove_nms dir at: %s/%s", dir, name);
    if (MD_OK(md_util_path_merge(&fpath, p, dir, name, NULL))) {
        ctx->dirname = name;
        rv = md_util_files_do(remove_nms_file, ctx, p, fpath, ctx->aspect, NULL);
        if (APR_STATUS_IS_ENOENT(rv)) {
            rv = APR_SUCCESS;
        }
    } 
    return rv;
}

static apr_status_t fs_remove_nms(md_store_t *store, apr_pool_t *p, 
                                  apr_time_t modified, md_store_group_t group, 
                                  const char *name, const char *aspect)
{
    const char *groupname;
    apr_status_t rv;
    inspect_ctx ctx;
    
    ctx.s_fs = FS_STORE(store);
    ctx.group = group;
    ctx.pattern = name;
    ctx.aspect = aspect;
    ctx.ts = modified;
    groupname = md_store_group_name(group);

    rv = md_util_files_do(remove_nms_dir, &ctx, p, ctx.s_fs->base, groupname, name, NULL);
    
    return rv;
}

/**************************************************************************************************/
/* moving */

static apr_status_t pfs_move(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *name, *from_group, *to_group, *from_dir, *to_dir, *arch_dir, *dir;
    md_store_group_t from, to;
    int archive;
    apr_status_t rv;
    
    (void)p;
    from = (md_store_group_t)va_arg(ap, int);
    to = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    archive = va_arg(ap, int);
    
    from_group = md_store_group_name(from);
    to_group = md_store_group_name(to);
    if (!strcmp(from_group, to_group)) {
        return APR_EINVAL;
    }

    if (   !MD_OK(md_util_path_merge(&from_dir, ptemp, s_fs->base, from_group, name, NULL))
        || !MD_OK(md_util_path_merge(&to_dir, ptemp, s_fs->base, to_group, name, NULL))) {
        goto out;
    }
    
    if (!MD_OK(md_util_is_dir(from_dir, ptemp))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "source is no dir: %s", from_dir);
        goto out;
    }
    
    if (MD_OK(archive? md_util_is_dir(to_dir, ptemp) : APR_ENOENT)) {
        int n = 1;
        const char *narch_dir;

        if (    !MD_OK(md_util_path_merge(&dir, ptemp, s_fs->base, 
                                          md_store_group_name(MD_SG_ARCHIVE), NULL))
            || !MD_OK(apr_dir_make_recursive(dir, MD_FPROT_D_UONLY, ptemp))
            || !MD_OK(md_util_path_merge(&arch_dir, ptemp, dir, name, NULL))) {
            goto out;
        }
        
#ifdef WIN32
        /* WIN32 and handling of files/dirs. What can one say? */
        
        while (n < 1000) {
            narch_dir = apr_psprintf(ptemp, "%s.%d", arch_dir, n);
            rv = md_util_is_dir(narch_dir, ptemp);
            if (APR_STATUS_IS_ENOENT(rv)) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ptemp, "using archive dir: %s", 
                              narch_dir);
                break;
            }
            else {
                ++n;
                narch_dir = NULL;
            }
        }

#else   /* ifdef WIN32 */

        while (n < 1000) {
            narch_dir = apr_psprintf(ptemp, "%s.%d", arch_dir, n);
            if (MD_OK(apr_dir_make(narch_dir, MD_FPROT_D_UONLY, ptemp))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, ptemp, "using archive dir: %s", 
                              narch_dir);
                break;
            }
            else if (APR_EEXIST == rv) {
                ++n;
                narch_dir = NULL;
            }
            else {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "creating archive dir: %s", 
                              narch_dir);
                goto out;
            }
        }
         
#endif   /* ifdef WIN32 (else part) */
        
        if (!narch_dir) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "ran out of numbers less than 1000 "
                          "while looking for an available one in %s to archive the data "
                          "from %s. Either something is generally wrong or you need to "
                          "clean up some of those directories.", arch_dir, from_dir);
            rv = APR_EGENERAL;
            goto out;
        }
        
        if (!MD_OK(apr_file_rename(to_dir, narch_dir, ptemp))) {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "rename from %s to %s",
                              to_dir, narch_dir);
                goto out;
        }
        if (!MD_OK(apr_file_rename(from_dir, to_dir, ptemp))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "rename from %s to %s",
                          from_dir, to_dir);
            apr_file_rename(narch_dir, to_dir, ptemp);
            goto out;
        }
        if (MD_OK(dispatch(s_fs, MD_S_FS_EV_MOVED, to, to_dir, APR_DIR, ptemp))) {
            rv = dispatch(s_fs, MD_S_FS_EV_MOVED, MD_SG_ARCHIVE, narch_dir, APR_DIR, ptemp);
        }
    }
    else if (APR_STATUS_IS_ENOENT(rv)) {
        if (APR_SUCCESS != (rv = apr_file_rename(from_dir, to_dir, ptemp))) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "rename from %s to %s",
                          from_dir, to_dir);
            goto out;
        }
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "target is no dir: %s", to_dir);
        goto out;
    }
    
out:
    return rv;
}

static apr_status_t fs_move(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t from, md_store_group_t to, 
                            const char *name, int archive)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_move, s_fs, p, from, to, name, archive, NULL);
}

static apr_status_t pfs_rename(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_store_fs_t *s_fs = baton;
    const char *group_name, *from_dir, *to_dir;
    md_store_group_t group;
    const char *from, *to;
    apr_status_t rv;
    
    (void)p;
    group = (md_store_group_t)va_arg(ap, int);
    from = va_arg(ap, const char*);
    to = va_arg(ap, const char*);
    
    group_name = md_store_group_name(group);
    if (   !MD_OK(md_util_path_merge(&from_dir, ptemp, s_fs->base, group_name, from, NULL))
        || !MD_OK(md_util_path_merge(&to_dir, ptemp, s_fs->base, group_name, to, NULL))) {
        goto out;
    }
    
    if (APR_SUCCESS != (rv = apr_file_rename(from_dir, to_dir, ptemp))
        && !APR_STATUS_IS_ENOENT(rv)) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ptemp, "rename from %s to %s",
                      from_dir, to_dir);
        goto out;
    }
out:
    return rv;
}

static apr_status_t fs_rename(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t group, const char *from, const char *to)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    return md_util_pool_vdo(pfs_rename, s_fs, p, group, from, to, NULL);
}

static apr_status_t fs_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait)
{
    md_store_fs_t *s_fs = FS_STORE(store);
    apr_status_t rv;
    const char *lpath;
    apr_time_t end;

    if (s_fs->global_lock) {
        rv = APR_EEXIST;
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "already locked globally");
        goto cleanup;
    }

    rv = md_util_path_merge(&lpath, p, s_fs->base, MD_FS_LOCK_NAME, NULL);
    if (APR_SUCCESS != rv) goto cleanup;
    end = apr_time_now() + max_wait;

    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, 0, p,
                  "acquire global lock: %s", lpath);
    while (apr_time_now() < end) {
        rv = apr_file_open(&s_fs->global_lock, lpath,
                           (APR_FOPEN_WRITE|APR_FOPEN_CREATE),
                           MD_FPROT_F_UALL_GREAD, p);
        if (APR_SUCCESS != rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, p,
                          "unable to create/open lock file: %s",
                          lpath);
            goto next_try;
        }
        rv = apr_file_lock(s_fs->global_lock,
                           APR_FLOCK_EXCLUSIVE|APR_FLOCK_NONBLOCK);
        if (APR_SUCCESS == rv) {
            goto cleanup;
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, p,
                      "unable to obtain lock on: %s",
                      lpath);

    next_try:
        if (s_fs->global_lock) {
            apr_file_close(s_fs->global_lock);
            s_fs->global_lock = NULL;
        }
        apr_sleep(apr_time_from_msec(100));
    }
    rv = APR_EGENERAL;
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE1, rv, p,
                  "acquire global lock: %s", lpath);

cleanup:
    return rv;
}

static void fs_unlock_global(md_store_t *store, apr_pool_t *p)
{
    md_store_fs_t *s_fs = FS_STORE(store);

    (void)p;
    if (s_fs->global_lock) {
        apr_file_close(s_fs->global_lock);
        s_fs->global_lock = NULL;
    }
}
