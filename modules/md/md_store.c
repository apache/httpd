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
#include "md_log.h"
#include "md_json.h"
#include "md_store.h"
#include "md_util.h"

/**************************************************************************************************/
/* generic callback handling */

#define ASPECT_MD           "md.json"
#define ASPECT_CERT         "cert.pem"
#define ASPECT_PKEY         "key.pem"
#define ASPECT_CHAIN        "chain.pem"

#define GNAME_ACCOUNTS     
#define GNAME_CHALLENGES   
#define GNAME_DOMAINS      
#define GNAME_STAGING      
#define GNAME_ARCHIVE      

static const char *GROUP_NAME[] = {
    "none",
    "accounts",
    "challenges",
    "domains",
    "staging",
    "archive",
    "tmp",
    "ocsp",
    NULL
};

const char *md_store_group_name(unsigned int group)
{
    if (group < sizeof(GROUP_NAME)/sizeof(GROUP_NAME[0])) {
        return GROUP_NAME[group];
    }
    return "UNKNOWN";
}

apr_status_t md_store_load(md_store_t *store, md_store_group_t group, 
                           const char *name, const char *aspect, 
                           md_store_vtype_t vtype, void **pdata, 
                           apr_pool_t *p)
{
    return store->load(store, group, name, aspect, vtype, pdata, p);
}

apr_status_t md_store_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                           const char *name, const char *aspect, 
                           md_store_vtype_t vtype, void *data, 
                           int create)
{
    return store->save(store, p, group, name, aspect, vtype, data, create);
}

apr_status_t md_store_remove(md_store_t *store, md_store_group_t group, 
                             const char *name, const char *aspect, 
                             apr_pool_t *p, int force)
{
    return store->remove(store, group, name, aspect, p, force);
}

apr_status_t md_store_purge(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                             const char *name)
{
    return store->purge(store, p, group, name);
}

apr_status_t md_store_iter(md_store_inspect *inspect, void *baton, md_store_t *store, 
                           apr_pool_t *p, md_store_group_t group, const char *pattern, 
                           const char *aspect, md_store_vtype_t vtype)
{
    return store->iterate(inspect, baton, store, p, group, pattern, aspect, vtype);
}

apr_status_t md_store_load_json(md_store_t *store, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                struct md_json_t **pdata, apr_pool_t *p)
{
    return md_store_load(store, group, name, aspect, MD_SV_JSON, (void**)pdata, p);
}

apr_status_t md_store_save_json(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                struct md_json_t *data, int create)
{
    return md_store_save(store, p, group, name, aspect, MD_SV_JSON, (void*)data, create);
}

apr_status_t md_store_move(md_store_t *store, apr_pool_t *p, 
                           md_store_group_t from, md_store_group_t to,
                           const char *name, int archive)
{
    return store->move(store, p, from, to, name, archive);
}

apr_status_t md_store_get_fname(const char **pfname, 
                                md_store_t *store, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                apr_pool_t *p)
{
    if (store->get_fname) {
        return store->get_fname(pfname, store, group, name, aspect, p);
    }
    return APR_ENOTIMPL;
}

int md_store_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                      const char *name, const char *aspect, apr_pool_t *p)
{
    return store->is_newer(store, group1, group2, name, aspect, p);
}

apr_time_t md_store_get_modified(md_store_t *store, md_store_group_t group,  
                                 const char *name, const char *aspect, apr_pool_t *p)
{
    return store->get_modified(store, group, name, aspect, p);
}

apr_status_t md_store_iter_names(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                 apr_pool_t *p, md_store_group_t group, const char *pattern)
{
    return store->iterate_names(inspect, baton, store, p, group, pattern);
}

apr_status_t md_store_remove_not_modified_since(md_store_t *store, apr_pool_t *p, 
                                                apr_time_t modified,
                                                md_store_group_t group, 
                                                const char *name, 
                                                const char *aspect)
{
    return store->remove_nms(store, p, modified, group, name, aspect);
}

apr_status_t md_store_rename(md_store_t *store, apr_pool_t *p,
                             md_store_group_t group, const char *name, const char *to)
{
    return store->rename(store, p, group, name, to);
}

/**************************************************************************************************/
/* convenience */

typedef struct {
    md_store_t *store;
    md_store_group_t group;
} md_group_ctx;

apr_status_t md_load(md_store_t *store, md_store_group_t group, 
                     const char *name, md_t **pmd, apr_pool_t *p)
{
    md_json_t *json;
    apr_status_t rv;
    
    rv = md_store_load_json(store, group, name, MD_FN_MD, pmd? &json : NULL, p);
    if (APR_SUCCESS == rv) {
        if (pmd) {
            *pmd = md_from_json(json, p);
        }
        return APR_SUCCESS;
    }
    return rv;
}

static apr_status_t p_save(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_group_ctx *ctx = baton;
    md_json_t *json;
    md_t *md;
    int create;
    
    md = va_arg(ap, md_t *);
    create = va_arg(ap, int);

    json = md_to_json(md, ptemp);
    assert(json);
    assert(md->name);
    return md_store_save_json(ctx->store, p, ctx->group, md->name, MD_FN_MD, json, create);
}

apr_status_t md_save(md_store_t *store, apr_pool_t *p, 
                     md_store_group_t group, md_t *md, int create)
{
    md_group_ctx ctx;
    
    ctx.store = store;
    ctx.group = group;
    return md_util_pool_vdo(p_save, &ctx, p, md, create, NULL);
}

static apr_status_t p_remove(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap)
{
    md_group_ctx *ctx = baton;
    const char *name;
    int force;
    
    (void)p;
    name = va_arg(ap, const char *);
    force = va_arg(ap, int);

    assert(name);
    return md_store_remove(ctx->store, ctx->group, name, MD_FN_MD, ptemp, force);
}

apr_status_t md_remove(md_store_t *store, apr_pool_t *p, 
                       md_store_group_t group, const char *name, int force)
{
    md_group_ctx ctx;
    
    ctx.store = store;
    ctx.group = group;
    return md_util_pool_vdo(p_remove, &ctx, p, name, force, NULL);
}

int md_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                      const char *name, apr_pool_t *p)
{
    return md_store_is_newer(store, group1, group2, name, MD_FN_MD, p);
}


typedef struct {
    apr_pool_t *p;
    apr_array_header_t *mds;
} md_load_ctx;

static const char *pk_filename(const char *keyname, const char *base, apr_pool_t *p)
{
    char *s, *t;
    /* We also run on various filesystems with difference upper/lower preserve matching
     * rules. Normalize the names we use, since private key specifications are basically
     * user input. */
    s = (keyname && apr_strnatcasecmp("rsa", keyname))?
        apr_pstrcat(p, base, ".", keyname, ".pem", NULL)
        : apr_pstrcat(p, base, ".pem", NULL);
    for (t = s; *t; t++ )
        *t = (char)apr_tolower(*t);
    return s;
}

const char *md_pkey_filename(md_pkey_spec_t *spec, apr_pool_t *p)
{
    return pk_filename(md_pkey_spec_name(spec), "privkey", p);
}

const char *md_chain_filename(md_pkey_spec_t *spec, apr_pool_t *p)
{
    return pk_filename(md_pkey_spec_name(spec), "pubcert", p);
}

apr_status_t md_pkey_load(md_store_t *store, md_store_group_t group, const char *name, 
                          md_pkey_spec_t *spec, md_pkey_t **ppkey, apr_pool_t *p)
{
    const char *fname = md_pkey_filename(spec, p);
    return md_store_load(store, group, name, fname, MD_SV_PKEY, (void**)ppkey, p);
}

apr_status_t md_pkey_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, const char *name, 
                          md_pkey_spec_t *spec, struct md_pkey_t *pkey, int create)
{
    const char *fname = md_pkey_filename(spec, p);
    return md_store_save(store, p, group, name, fname, MD_SV_PKEY, pkey, create);
}

apr_status_t md_pubcert_load(md_store_t *store, md_store_group_t group, const char *name, 
                             md_pkey_spec_t *spec, struct apr_array_header_t **ppubcert, 
                             apr_pool_t *p)
{
    const char *fname = md_chain_filename(spec, p);
    return md_store_load(store, group, name, fname, MD_SV_CHAIN, (void**)ppubcert, p);
}

apr_status_t md_pubcert_save(md_store_t *store, apr_pool_t *p, 
                             md_store_group_t group, const char *name, 
                             md_pkey_spec_t *spec, struct apr_array_header_t *pubcert, int create)
{
    const char *fname = md_chain_filename(spec, p);
    return md_store_save(store, p, group, name, fname, MD_SV_CHAIN, pubcert, create);
}

apr_status_t md_creds_load(md_store_t *store, md_store_group_t group, const char *name, 
                           md_pkey_spec_t *spec, md_credentials_t **pcreds, apr_pool_t *p)
{
    md_credentials_t *creds = apr_pcalloc(p, sizeof(*creds));
    apr_status_t rv;
    
    creds->spec = spec;
    if (APR_SUCCESS != (rv = md_pkey_load(store, group, name, spec, &creds->pkey, p))) {
        goto leave;
    }
    /* chain is optional */
    rv = md_pubcert_load(store, group, name, spec, &creds->chain, p);
    if (APR_STATUS_IS_ENOENT(rv)) rv = APR_SUCCESS;
leave:
    *pcreds = (APR_SUCCESS == rv)? creds : NULL;
    return rv;
}

apr_status_t md_creds_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                           const char *name, md_credentials_t *creds, int create)
{
    apr_status_t rv;

    if (APR_SUCCESS != (rv = md_pkey_save(store, p, group, name, creds->spec, creds->pkey, create))) {
        goto leave;
    }
    rv = md_pubcert_save(store, p, group, name, creds->spec, creds->chain, create);
leave:
    return rv;
}

typedef struct {
    md_store_t *store;
    md_store_group_t group;
    const char *pattern;
    const char *aspect;
    md_store_md_inspect *inspect;
    void *baton;
} inspect_md_ctx;

static int insp_md(void *baton, const char *name, const char *aspect, 
                   md_store_vtype_t vtype, void *value, apr_pool_t *ptemp)
{
    inspect_md_ctx *ctx = baton;
    
    if (!strcmp(MD_FN_MD, aspect) && vtype == MD_SV_JSON) {
        md_t *md = md_from_json(value, ptemp);
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE3, 0, ptemp, "inspecting md at: %s", name);
        return ctx->inspect(ctx->baton, ctx->store, md, ptemp);
    }
    return 1;
}

apr_status_t md_store_md_iter(md_store_md_inspect *inspect, void *baton, md_store_t *store, 
                              apr_pool_t *p, md_store_group_t group, const char *pattern)
{
    inspect_md_ctx ctx;
    
    ctx.store = store;
    ctx.group = group;
    ctx.inspect = inspect;
    ctx.baton = baton;
    
    return md_store_iter(insp_md, &ctx, store, p, group, pattern, MD_FN_MD, MD_SV_JSON);
}

apr_status_t md_store_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait)
{
    return store->lock_global(store, p, max_wait);
}

void md_store_unlock_global(md_store_t *store, apr_pool_t *p)
{
    store->unlock_global(store, p);
}
