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
    
    const unsigned char *key;
    apr_size_t key_len;
    int plain_pkey[MD_SG_COUNT];
    
    int port_80;
    int port_443;
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
static apr_status_t fs_move(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t from, md_store_group_t to, 
                            const char *name, int archive);
static apr_status_t fs_iterate(md_store_inspect *inspect, void *baton, md_store_t *store, 
                               apr_pool_t *p, md_store_group_t group,  const char *pattern,
                               const char *aspect, md_store_vtype_t vtype);

static apr_status_t fs_get_fname(const char **pfname, 
                                 md_store_t *store, md_store_group_t group, 
                                 const char *name, const char *aspect, 
                                 apr_pool_t *p);
static int fs_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                       const char *name, const char *aspect, apr_pool_t *p);

static apr_status_t init_store_file(md_store_fs_t *s_fs, const char *fname, 
                                    apr_pool_t *p, apr_pool_t *ptemp)
{
    md_json_t *json = md_json_create(p);
    const char *key64;
    unsigned char *key;
    apr_status_t rv;
    
    md_json_setn(MD_STORE_VERSION, json, MD_KEY_STORE, MD_KEY_VERSION, NULL);

    s_fs->key_len = FS_STORE_KLEN;
    s_fs->key = key = apr_pcalloc(p, FS_STORE_KLEN);
    if (APR_SUCCESS != (rv = md_rand_bytes(key, s_fs->key_len, p))) {
        return rv;
    }
        
    key64 = md_util_base64url_encode((char *)key, s_fs->key_len, ptemp);
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
    MD_CHK_VARS;
    
    (void)baton;
    (void)ftype;
    if (   MD_OK(md_util_path_merge(&from, ptemp, dir, name, NULL))
        && MD_OK(md_util_path_merge(&to, ptemp, dir, MD_FN_PRIVKEY, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, "renaming %s/%s to %s", 
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
    MD_CHK_VARS;
    
    (void)baton;
    (void)ftype;
    (void)p;
    if (   MD_OK(md_util_path_merge(&fpubcert, ptemp, dir, MD_FN_PUBCERT, NULL))
        && MD_IS_ERR(md_chain_fload(&pubcert, ptemp, fpubcert), ENOENT)
        && MD_OK(md_util_path_merge(&fname, ptemp, dir, name, NULL))
        && MD_OK(md_cert_fload(&cert, ptemp, fname))
        && MD_OK(md_util_path_merge(&fname, ptemp, dir, MD_FN_CHAIN, NULL))) {
        
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
    const char *key64, *key;
    apr_status_t rv;
    double store_version;
    MD_CHK_VARS;
    
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
        
        s_fs->key_len = md_util_base64url_decode(&key, key64, p);
        s_fs->key = (const unsigned char*)key;
        if (s_fs->key_len != FS_STORE_KLEN) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, 0, p, "key length unexpected: %" APR_SIZE_T_FMT, 
                          s_fs->key_len);
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
    MD_CHK_VARS;

    (void)ap;
    s_fs->plain_pkey[MD_SG_DOMAINS] = 1;
    s_fs->plain_pkey[MD_SG_TMP] = 1;
    
    if (!MD_OK(md_util_path_merge(&fname, ptemp, s_fs->base, FS_STORE_JSON, NULL))) {
        return rv;
    }
    
read:
    if (MD_OK(md_util_is_file(fname, ptemp))) {
        rv = read_store_file(s_fs, fname, p, ptemp);
    }
    else if (APR_STATUS_IS_ENOENT(rv)
        && MD_IS_ERR(init_store_file(s_fs, fname, p, ptemp), EEXIST)) {
        goto read;
    }
    return rv;
}

apr_status_t md_store_fs_init(md_store_t **pstore, apr_pool_t *p, const char *path)
{
    md_store_fs_t *s_fs;
    apr_status_t rv = APR_SUCCESS;
    MD_CHK_VARS;
    
    s_fs = apr_pcalloc(p, sizeof(*s_fs));

    s_fs->s.load = fs_load;
    s_fs->s.save = fs_save;
    s_fs->s.remove = fs_remove;
    s_fs->s.move = fs_move;
    s_fs->s.purge = fs_purge;
    s_fs->s.iterate = fs_iterate;
    s_fs->s.get_fname = fs_get_fname;
    s_fs->s.is_newer = fs_is_newer;
    
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

    s_fs->base = apr_pstrdup(p, path);
    
    if (MD_IS_ERR(md_util_is_dir(s_fs->base, p), ENOENT)
        && MD_OK(apr_dir_make_recursive(s_fs->base, s_fs->def_perms.dir, p))) {
        rv = apr_file_perms_set(s_fs->base, MD_FPROT_D_UALL_WREAD);
        if (APR_STATUS_IS_ENOTIMPL(rv)) {
            rv = APR_SUCCESS;
        }
    }
    
    if ((APR_SUCCESS != rv) || !MD_OK(md_util_pool_vdo(setup_store_file, s_fs, p, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "init fs store at %s", path);
    }
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
        *ppass = (const char *)s_fs->key;
        *plen = s_fs->key_len;
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
    MD_CHK_VARS;
    
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

static apr_status_t dispatch(md_store_fs_t *s_fs, md_store_fs_ev_t ev, int group, 
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
    MD_CHK_VARS;
    
    perms = gperms(s_fs, group);

    if (MD_OK(fs_get_dname(pdir, &s_fs->s, group, name, p)) && (MD_SG_NONE != group)) {
        if (  !MD_OK(md_util_is_dir(*pdir, p))
            && MD_OK(apr_dir_make_recursive(*pdir, perms->dir, p))) {
            rv = dispatch(s_fs, MD_S_FS_EV_CREATED, group, *pdir, APR_DIR, p);
        }
        
        if (APR_SUCCESS == rv) {
            rv = apr_file_perms_set(*pdir, perms->dir);
            md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, "mk_group_dir %s perm set", *pdir);
            if (APR_STATUS_IS_ENOTIMPL(rv)) {
                rv = APR_SUCCESS;
            }
        }
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, p, "mk_group_dir %d %s", group, name);
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
    MD_CHK_VARS;
    
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
    MD_CHK_VARS;
    
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
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "storing in %s", fpath);
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
    MD_CHK_VARS;
    
    (void)p;
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    aspect = va_arg(ap, const char *);
    force = va_arg(ap, int);
    
    groupname = md_store_group_name(group);
    
    if (   MD_OK(md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))
        && MD_OK(md_util_path_merge(&fpath, ptemp, dir, aspect, NULL))) {
        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, ptemp, "start remove of md %s/%s/%s", 
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
    MD_CHK_VARS;
    
    (void)p;
    group = (md_store_group_t)va_arg(ap, int);
    name = va_arg(ap, const char*);
    
    groupname = md_store_group_name(group);

    if (MD_OK(md_util_path_merge(&dir, ptemp, s_fs->base, groupname, name, NULL))) {
        /* Remove all files in dir, there should be no sub-dirs */
        rv = md_util_rm_recursive(dir, ptemp, 1);
    }
    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "purge %s/%s (%s)", groupname, name, dir);
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
    void *baton;
} inspect_ctx;

static apr_status_t insp(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                         const char *dir, const char *name, apr_filetype_e ftype)
{
    inspect_ctx *ctx = baton;
    apr_status_t rv;
    void *value;
    const char *fpath;
    MD_CHK_VARS;
 
    (void)ftype;   
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting value at: %s/%s", dir, name);
    if (   MD_OK(md_util_path_merge(&fpath, ptemp, dir, name, NULL)) 
        && MD_OK(fs_fload(&value, ctx->s_fs, fpath, ctx->group, ctx->vtype, p, ptemp))
        && !ctx->inspect(ctx->baton, name, ctx->aspect, ctx->vtype, value, ptemp)) {
        return APR_EOF;
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

    rv = md_util_files_do(insp, &ctx, p, ctx.s_fs->base, groupname, ctx.pattern, aspect, NULL);
    
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
    MD_CHK_VARS;
    
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
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "using archive dir: %s", 
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
                md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, rv, ptemp, "using archive dir: %s", 
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
