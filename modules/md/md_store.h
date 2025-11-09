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

#ifndef mod_md_md_store_h
#define mod_md_md_store_h

struct apr_array_header_t;
struct md_cert_t;
struct md_pkey_t;
struct md_pkey_spec_t;

const char *md_store_group_name(unsigned int group);

typedef struct md_store_t md_store_t;

/**
 * A store for domain related data.
 *
 * The Key for a piece of data is the set of 3 items
 *   <group> + <domain> + <aspect>
 *
 * Examples:
 * "domains" + "greenbytes.de" + "pubcert.pem"
 * "ocsp" + "greenbytes.de" + "ocsp-XXXXX.json"
 *
 * Storage groups are pre-defined, domain and aspect names can be freely chosen.
 *
 * Groups reflect use cases and come with security restrictions. The groups 
 * DOMAINS, ARCHIVE and NONE are only accessible during the startup 
 * phase of httpd.
 *
 * Private key are stored unencrypted only in restricted groups. Meaning that certificate
 * keys in group DOMAINS are not encrypted, but only readable at httpd start/reload.
 * Keys in unrestricted groups are encrypted using a pass phrase generated once and stored
 * in NONE.
 */

/** Value types handled by a store */
typedef enum {
    MD_SV_TEXT,         /* plain text, value is (char*) */
    MD_SV_JSON,         /* JSON serialization, value is (md_json_t*) */
    MD_SV_CERT,         /* PEM x509 certificate, value is (md_cert_t*) */
    MD_SV_PKEY,         /* PEM private key, value is (md_pkey_t*) */
    MD_SV_CHAIN,        /* list of PEM x509 certificates, value is 
                           (apr_array_header_t*) of (md_cert*) */
} md_store_vtype_t;

/** Store storage groups */
typedef enum {
    MD_SG_NONE,         /* top level of store, name MUST be NULL in calls */
    MD_SG_ACCOUNTS,     /* ACME accounts */
    MD_SG_CHALLENGES,   /* challenge response data for a domain */ 
    MD_SG_DOMAINS,      /* live certificates and settings for a domain */
    MD_SG_STAGING,      /* staged set of certificate and settings, maybe incomplete */
    MD_SG_ARCHIVE,      /* Archived live sets of a domain */
    MD_SG_TMP,          /* temporary domain storage */
    MD_SG_OCSP,         /* OCSP stapling related domain data */
    MD_SG_COUNT,        /* number of storage groups, used in setups */
} md_store_group_t;

#define MD_FN_MD                "md.json"
#define MD_FN_JOB               "job.json"
#define MD_FN_HTTPD_JSON        "httpd.json"

/* The corresponding names for current cert & key files are constructed
 * in md_store and md_crypt.
 */

/* These three legacy filenames are only used in md_store_fs to
 * upgrade 1.0 directories.  They should not be used for any other
 * purpose.
 */
#define MD_FN_PRIVKEY           "privkey.pem"
#define MD_FN_PUBCERT           "pubcert.pem"
#define MD_FN_CERT              "cert.pem"

/**
 * Load the JSON value at key "group/name/aspect", allocated from pool p.
 * @return APR_ENOENT if there is no such value
 */
apr_status_t md_store_load_json(md_store_t *store, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                struct md_json_t **pdata, apr_pool_t *p);
/**
 * Save the JSON value at key "group/name/aspect". If create != 0, fail if there
 * already is a value for this key.
 */
apr_status_t md_store_save_json(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                struct md_json_t *data, int create);

/**
 * Load the value of type at key "group/name/aspect", allocated from pool p. Usually, the
 * type is expected to be the same as used in saving the value. Some conversions will work,
 * others will fail the format.
 * @return APR_ENOENT if there is no such value
 */
apr_status_t md_store_load(md_store_t *store, md_store_group_t group, 
                           const char *name, const char *aspect, 
                           md_store_vtype_t vtype, void **pdata, 
                           apr_pool_t *p);
/**
 * Save the JSON value at key "group/name/aspect". If create != 0, fail if there
 * already is a value for this key. The provided data MUST be of the correct type.
 */
apr_status_t md_store_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                           const char *name, const char *aspect, 
                           md_store_vtype_t vtype, void *data, 
                           int create);

/**
 * Remove the value stored at key "group/name/aspect". Unless force != 0, a missing
 * value will cause the call to fail with APR_ENOENT.
 */ 
apr_status_t md_store_remove(md_store_t *store, md_store_group_t group, 
                             const char *name, const char *aspect, 
                             apr_pool_t *p, int force);
/**
 * Remove everything matching key "group/name".
 */ 
apr_status_t md_store_purge(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t group, const char *name);

/**
 * Remove all items matching the name/aspect patterns that have not been
 * modified since the given timestamp.
 */
apr_status_t md_store_remove_not_modified_since(md_store_t *store, apr_pool_t *p, 
                                                apr_time_t modified,
                                                md_store_group_t group, 
                                                const char *name, 
                                                const char *aspect);

/**
 * inspect callback function. Invoked for each matched value. Values allocated from
 * ptemp may disappear any time after the call returned. If this function returns
 * 0, the iteration is aborted. 
 */
typedef int md_store_inspect(void *baton, const char *name, const char *aspect, 
                             md_store_vtype_t vtype, void *value, apr_pool_t *ptemp);

/**
 * Iterator over all existing values matching the name pattern. Patterns are evaluated
 * using apr_fnmatch() without flags.
 */
apr_status_t md_store_iter(md_store_inspect *inspect, void *baton, md_store_t *store, 
                           apr_pool_t *p, md_store_group_t group, const char *pattern, 
                           const char *aspect, md_store_vtype_t vtype);

/**
 * Move everything matching key "from/name" from one group to another. If archive != 0,
 * move any existing "to/name" into a new "archive/new_name" location.
 */
apr_status_t md_store_move(md_store_t *store, apr_pool_t *p,
                           md_store_group_t from, md_store_group_t to,
                           const char *name, int archive);

/**
 * Rename a group member.
 */
apr_status_t md_store_rename(md_store_t *store, apr_pool_t *p,
                             md_store_group_t group, const char *name, const char *to);

/**
 * Get the filename of an item stored in "group/name/aspect". The item does
 * not have to exist.
 */
apr_status_t md_store_get_fname(const char **pfname, 
                                md_store_t *store, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                apr_pool_t *p);

/**
 * Make a compare on the modification time of "group1/name/aspect" vs. "group2/name/aspect".
 */
int md_store_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                      const char *name, const char *aspect, apr_pool_t *p);

/**
 * Iterate over all names that exist in a group, e.g. there are items matching
 * "group/pattern". The inspect function is called with the name and NULL aspect
 * and value.
 */
apr_status_t md_store_iter_names(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                 apr_pool_t *p, md_store_group_t group, const char *pattern);

/**
 * Get the modification time of the item store under "group/name/aspect".
 * @return modification time or 0 if the item does not exist.
 */
apr_time_t md_store_get_modified(md_store_t *store, md_store_group_t group,  
                                 const char *name, const char *aspect, apr_pool_t *p);

/**
 * Acquire a cooperative, global lock on store modifications.

 * This will only prevent other children/processes/cluster nodes from
 * doing the same and does not protect individual store functions from
 * being called without it.
 * @param store the store
 * @param p memory pool to use
 * @param max_wait maximum time to wait in order to acquire
 * @return APR_SUCCESS when lock was obtained
 */
apr_status_t md_store_lock_global(md_store_t *store, apr_pool_t *p, apr_time_t max_wait);

/**
 * Realease the global store lock. Will do nothing if there is no lock.
 */
void md_store_unlock_global(md_store_t *store, apr_pool_t *p);

/**************************************************************************************************/
/* Storage handling utils */

apr_status_t md_load(md_store_t *store, md_store_group_t group, 
                     const char *name, md_t **pmd, apr_pool_t *p);
apr_status_t md_save(struct md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                     md_t *md, int create);
apr_status_t md_remove(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                     const char *name, int force);

int md_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                const char *name, apr_pool_t *p);

typedef int md_store_md_inspect(void *baton, md_store_t *store, md_t *md, apr_pool_t *ptemp);

apr_status_t md_store_md_iter(md_store_md_inspect *inspect, void *baton, md_store_t *store, 
                              apr_pool_t *p, md_store_group_t group, const char *pattern);


const char *md_pkey_filename(struct md_pkey_spec_t *spec, apr_pool_t *p);
const char *md_chain_filename(struct md_pkey_spec_t *spec, apr_pool_t *p);

apr_status_t md_pkey_load(md_store_t *store, md_store_group_t group, 
                          const char *name, struct md_pkey_spec_t *spec,
                          struct md_pkey_t **ppkey, apr_pool_t *p);
apr_status_t md_pkey_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                          const char *name, struct md_pkey_spec_t *spec,
                          struct md_pkey_t *pkey, int create);

apr_status_t md_pubcert_load(md_store_t *store, md_store_group_t group, const char *name, 
                             struct md_pkey_spec_t *spec, struct apr_array_header_t **ppubcert, 
                             apr_pool_t *p);
apr_status_t md_pubcert_save(md_store_t *store, apr_pool_t *p, 
                             md_store_group_t group, const char *name, 
                             struct md_pkey_spec_t *spec, 
                             struct apr_array_header_t *pubcert, int create);

/**************************************************************************************************/
/* X509 complete credentials */

typedef struct md_credentials_t md_credentials_t;
struct md_credentials_t {
    struct md_pkey_spec_t *spec;
    struct md_pkey_t *pkey;
    struct apr_array_header_t *chain;
};

apr_status_t md_creds_load(md_store_t *store, md_store_group_t group, const char *name, 
                           struct md_pkey_spec_t *spec, md_credentials_t **pcreds, apr_pool_t *p);
apr_status_t md_creds_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                           const char *name, md_credentials_t *creds, int create);

/**************************************************************************************************/
/* implementation interface */

typedef apr_status_t md_store_load_cb(md_store_t *store, md_store_group_t group, 
                                      const char *name, const char *aspect, 
                                      md_store_vtype_t vtype, void **pvalue, 
                                      apr_pool_t *p);
typedef apr_status_t md_store_save_cb(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                                      const char *name, const char *aspect, 
                                      md_store_vtype_t vtype, void *value, 
                                      int create);
typedef apr_status_t md_store_remove_cb(md_store_t *store, md_store_group_t group, 
                                        const char *name, const char *aspect,  
                                        apr_pool_t *p, int force);
typedef apr_status_t md_store_purge_cb(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                                        const char *name);

typedef apr_status_t md_store_iter_cb(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                      apr_pool_t *p, md_store_group_t group, const char *pattern,
                                      const char *aspect, md_store_vtype_t vtype);

typedef apr_status_t md_store_names_iter_cb(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                            apr_pool_t *p, md_store_group_t group, const char *pattern);

typedef apr_status_t md_store_move_cb(md_store_t *store, apr_pool_t *p, md_store_group_t from, 
                                      md_store_group_t to, const char *name, int archive);

typedef apr_status_t md_store_rename_cb(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                                        const char *from, const char *to);

typedef apr_status_t md_store_get_fname_cb(const char **pfname, 
                                           md_store_t *store, md_store_group_t group, 
                                           const char *name, const char *aspect, 
                                           apr_pool_t *p);

typedef int md_store_is_newer_cb(md_store_t *store, 
                                 md_store_group_t group1, md_store_group_t group2,  
                                 const char *name, const char *aspect, apr_pool_t *p);

typedef apr_time_t md_store_get_modified_cb(md_store_t *store, md_store_group_t group,  
                                            const char *name, const char *aspect, apr_pool_t *p);

typedef apr_status_t md_store_remove_nms_cb(md_store_t *store, apr_pool_t *p, 
                                            apr_time_t modified, md_store_group_t group, 
                                            const char *name, const char *aspect);
typedef apr_status_t md_store_lock_global_cb(md_store_t *store, apr_pool_t *p, apr_time_t max_wait);
typedef void md_store_unlock_global_cb(md_store_t *store, apr_pool_t *p);

struct md_store_t {
    md_store_save_cb *save;
    md_store_load_cb *load;
    md_store_remove_cb *remove;
    md_store_move_cb *move;
    md_store_rename_cb *rename;
    md_store_iter_cb *iterate;
    md_store_names_iter_cb *iterate_names;
    md_store_purge_cb *purge;
    md_store_get_fname_cb *get_fname;
    md_store_is_newer_cb *is_newer;
    md_store_get_modified_cb *get_modified;
    md_store_remove_nms_cb *remove_nms;
    md_store_lock_global_cb *lock_global;
    md_store_unlock_global_cb *unlock_global;
};


#endif /* mod_md_md_store_h */
