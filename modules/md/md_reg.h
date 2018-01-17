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

#ifndef mod_md_md_reg_h
#define mod_md_md_reg_h

struct apr_hash_t;
struct apr_array_header_t;
struct md_store_t;
struct md_pkey_t;
struct md_cert_t;

/**
 * A registry for managed domains with a md_store_t as persistence.
 *
 */
typedef struct md_reg_t md_reg_t;

/**
 * Initialize the registry, using the pool and loading any existing information
 * from the store.
 */
apr_status_t md_reg_init(md_reg_t **preg, apr_pool_t *pm, struct md_store_t *store,
                         const char *proxy_url);

struct md_store_t *md_reg_store_get(md_reg_t *reg);

apr_status_t md_reg_set_props(md_reg_t *reg, apr_pool_t *p, int can_http, int can_https);

/**
 * Add a new md to the registry. This will check the name for uniqueness and
 * that domain names do not overlap with already existing mds.
 */
apr_status_t md_reg_add(md_reg_t *reg, md_t *md, apr_pool_t *p);

/**
 * Find the md, if any, that contains the given domain name. 
 * NULL if none found.
 */
md_t *md_reg_find(md_reg_t *reg, const char *domain, apr_pool_t *p);

/**
 * Find one md, which domain names overlap with the given md and that has a different
 * name. There may be more than one existing md that overlaps. It is not defined
 * which one will be returned. 
 */
md_t *md_reg_find_overlap(md_reg_t *reg, const md_t *md, const char **pdomain, apr_pool_t *p);

/**
 * Get the md with the given unique name. NULL if it does not exist.
 * Will update the md->state.
 */
md_t *md_reg_get(md_reg_t *reg, const char *name, apr_pool_t *p);

/**
 * Assess the capability and need to driving this managed domain.
 */
apr_status_t md_reg_assess(md_reg_t *reg, md_t *md, int *perrored, int *prenew, apr_pool_t *p);

/**
 * Callback invoked for every md in the registry. If 0 is returned, iteration stops.
 */
typedef int md_reg_do_cb(void *baton, md_reg_t *reg, md_t *md);

/**
 * Invoke callback for all mds in this registry. Order is not guaranteed.
 * If the callback returns 0, iteration stops. Returns 0 if iteration was
 * aborted.
 */
int md_reg_do(md_reg_do_cb *cb, void *baton, md_reg_t *reg, apr_pool_t *p);

/**
 * Bitmask for fields that are updated.
 */
#define MD_UPD_DOMAINS       0x0001
#define MD_UPD_CA_URL        0x0002
#define MD_UPD_CA_PROTO      0x0004
#define MD_UPD_CA_ACCOUNT    0x0008
#define MD_UPD_CONTACTS      0x0010
#define MD_UPD_AGREEMENT     0x0020
#define MD_UPD_CERT_URL      0x0040
#define MD_UPD_DRIVE_MODE    0x0080
#define MD_UPD_RENEW_WINDOW  0x0100
#define MD_UPD_CA_CHALLENGES 0x0200
#define MD_UPD_PKEY_SPEC     0x0400
#define MD_UPD_REQUIRE_HTTPS 0x0800
#define MD_UPD_TRANSITIVE    0x1000
#define MD_UPD_MUST_STAPLE   0x2000
#define MD_UPD_ALL           0x7FFFFFFF

/**
 * Update the given fields for the managed domain. Take the new
 * values from the given md, all other values remain unchanged.
 */
apr_status_t md_reg_update(md_reg_t *reg, apr_pool_t *p, 
                           const char *name, const md_t *md, int fields);

/**
 * Get the credentials available for the managed domain md. Returns APR_ENOENT
 * when none is available. The returned values are immutable. 
 */
apr_status_t md_reg_creds_get(const md_creds_t **pcreds, md_reg_t *reg, 
                              md_store_group_t group, const md_t *md, apr_pool_t *p);

apr_status_t md_reg_get_cred_files(md_reg_t *reg, const md_t *md, apr_pool_t *p,
                                   const char **pkeyfile, const char **pcertfile);

/**
 * Synchronise the give master mds with the store.
 */
apr_status_t md_reg_sync(md_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, 
                         apr_array_header_t *master_mds);

/**************************************************************************************************/
/* protocol drivers */

typedef struct md_proto_t md_proto_t;

typedef struct md_proto_driver_t md_proto_driver_t;

struct md_proto_driver_t {
    const md_proto_t *proto;
    apr_pool_t *p;
    const char *challenge;
    int can_http;
    int can_https;
    struct md_store_t *store;
    md_reg_t *reg;
    const md_t *md;
    void *baton;
    int reset;
    apr_time_t stage_valid_from;
    const char *proxy_url;
};

typedef apr_status_t md_proto_init_cb(md_proto_driver_t *driver);
typedef apr_status_t md_proto_stage_cb(md_proto_driver_t *driver);
typedef apr_status_t md_proto_preload_cb(md_proto_driver_t *driver, md_store_group_t group);

struct md_proto_t {
    const char *protocol;
    md_proto_init_cb *init;
    md_proto_stage_cb *stage;
    md_proto_preload_cb *preload;
};


/**
 * Stage a new credentials set for the given managed domain in a separate location
 * without interfering with any existing credentials.
 */
apr_status_t md_reg_stage(md_reg_t *reg, const md_t *md, 
                          const char *challenge, int reset, 
                          apr_time_t *pvalid_from, apr_pool_t *p);

/**
 * Load a staged set of new credentials for the managed domain. This will archive
 * any existing credential data and make the staged set the new live one.
 * If staging is incomplete or missing, the load will fail and all credentials remain
 * as they are.
 */
apr_status_t md_reg_load(md_reg_t *reg, const char *name, apr_pool_t *p);

#endif /* mod_md_md_reg_h */
