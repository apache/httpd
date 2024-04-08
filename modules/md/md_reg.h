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
struct md_pkey_t;
struct md_cert_t;
struct md_result_t;
struct md_pkey_spec_t;
struct md_ocsp_reg_t;

#include "md_store.h"

/**
 * A registry for managed domains with a md_store_t as persistence.
 *
 */
typedef struct md_reg_t md_reg_t;

/**
 * Create the MD registry, using the pool and store.
 * @param preg on APR_SUCCESS, the create md_reg_t
 * @param pm memory pool to use for creation
 * @param store the store to base on
 * @param proxy_url optional URL of a proxy to use for requests
 * @param ca_file  optioinal CA trust anchor file to use
 * @param min_delay minimum delay between renewal attempts for a domain
 * @param retry_failover numer of failed renewals attempt to fail over to alternate ACME ca
 */
apr_status_t md_reg_create(md_reg_t **preg, apr_pool_t *pm, md_store_t *store,
                           const char *proxy_url, const char *ca_file,
                           apr_time_t min_delay, int retry_failover,
                           int use_store_locks, apr_time_t lock_wait_timeout);

md_store_t *md_reg_store_get(md_reg_t *reg);

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
#define MD_UPD_DOMAINS       0x00001
#define MD_UPD_CA_URL        0x00002
#define MD_UPD_CA_PROTO      0x00004
#define MD_UPD_CA_ACCOUNT    0x00008
#define MD_UPD_CONTACTS      0x00010
#define MD_UPD_AGREEMENT     0x00020
#define MD_UPD_DRIVE_MODE    0x00080
#define MD_UPD_RENEW_WINDOW  0x00100
#define MD_UPD_CA_CHALLENGES 0x00200
#define MD_UPD_PKEY_SPEC     0x00400
#define MD_UPD_REQUIRE_HTTPS 0x00800
#define MD_UPD_TRANSITIVE    0x01000
#define MD_UPD_MUST_STAPLE   0x02000
#define MD_UPD_PROTO         0x04000
#define MD_UPD_WARN_WINDOW   0x08000
#define MD_UPD_STAPLING      0x10000
#define MD_UPD_ALL           0x7FFFFFFF

/**
 * Update the given fields for the managed domain. Take the new
 * values from the given md, all other values remain unchanged.
 */
apr_status_t md_reg_update(md_reg_t *reg, apr_pool_t *p, 
                           const char *name, const md_t *md, 
                           int fields, int check_consistency);

/**
 * Get the chain of public certificates of the managed domain md, starting with the cert
 * of the domain and going up the issuers. Returns APR_ENOENT when not available. 
 */
apr_status_t md_reg_get_pubcert(const md_pubcert_t **ppubcert, md_reg_t *reg, 
                                const md_t *md, int i, apr_pool_t *p);

/**
 * Get the filenames of private key and pubcert of the MD - if they exist.
 * @return APR_ENOENT if one or both do not exist.
 */
apr_status_t md_reg_get_cred_files(const char **pkeyfile, const char **pcertfile,
                                   md_reg_t *reg, md_store_group_t group, 
                                   const md_t *md, struct md_pkey_spec_t *spec, apr_pool_t *p);

/**
 * Synchronize the given master mds with the store.
 */
apr_status_t md_reg_sync_start(md_reg_t *reg, apr_array_header_t *master_mds, apr_pool_t *p);

/**
 * Re-compute the state of the MD, given current store contents.
 */
apr_status_t md_reg_sync_finish(md_reg_t *reg, md_t *md, apr_pool_t *p, apr_pool_t *ptemp);


apr_status_t md_reg_remove(md_reg_t *reg, apr_pool_t *p, const char *name, int archive);

/**
 * Delete the account from the local store.
 */
apr_status_t md_reg_delete_acct(md_reg_t *reg, apr_pool_t *p, const char *acct_id);


/**
 * Cleanup any challenges that are no longer in use.
 * 
 * @param reg   the registry
 * @param p     pool for permanent storage
 * @param ptemp pool for temporary storage
 * @param mds   the list of configured MDs
 */
apr_status_t md_reg_cleanup_challenges(md_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, 
                                       apr_array_header_t *mds);

/**
 * Mark all information from group MD_SG_DOMAINS as readonly, deny future modifications 
 * (MD_SG_STAGING and MD_SG_CHALLENGES remain writeable). For the given MDs, cache
 * the public information (MDs themselves and their pubcerts or lack of).
 */
apr_status_t md_reg_freeze_domains(md_reg_t *reg, apr_array_header_t *mds);

/**
 * Return if the certificate of the MD should be renewed. This includes reaching
 * the renewal window of an otherwise valid certificate. It return also !0 iff
 * no certificate has been obtained yet.
 */
int md_reg_should_renew(md_reg_t *reg, const md_t *md, apr_pool_t *p);

/**
 * Return the timestamp when the certificate should be renewed. A value of 0
 * indicates that that renewal is not configured (see renew_mode).
 */
apr_time_t md_reg_renew_at(md_reg_t *reg, const md_t *md, apr_pool_t *p);

/**
 * Return the timestamp up to which *all* certificates for the MD can be used.
 * A value of 0 indicates that there is no certificate.
 */
apr_time_t md_reg_valid_until(md_reg_t *reg, const md_t *md, apr_pool_t *p);

/**
 * Return if a warning should be issued about the certificate expiration. 
 * This applies the configured warn window to the remaining lifetime of the 
 * current certiciate. If no certificate is present, this returns 0.
 */
int md_reg_should_warn(md_reg_t *reg, const md_t *md, apr_pool_t *p);

/**************************************************************************************************/
/* protocol drivers */

typedef struct md_proto_t md_proto_t;

typedef struct md_proto_driver_t md_proto_driver_t;

/** 
 * Operating environment for a protocol driver. This is valid only for the
 * duration of one run (init + renew, init + preload).
 */
struct md_proto_driver_t {
    const md_proto_t *proto;
    apr_pool_t *p;
    void *baton;
    struct apr_table_t *env;

    md_reg_t *reg;
    md_store_t *store;
    const char *proxy_url;
    const char *ca_file;
    const md_t *md;

    int can_http;
    int can_https;
    int reset;
    int attempt;
    int retry_failover;
    apr_interval_time_t activation_delay;
};

typedef apr_status_t md_proto_init_cb(md_proto_driver_t *driver, struct md_result_t *result);
typedef apr_status_t md_proto_renew_cb(md_proto_driver_t *driver, struct md_result_t *result);
typedef apr_status_t md_proto_init_preload_cb(md_proto_driver_t *driver, struct md_result_t *result);
typedef apr_status_t md_proto_preload_cb(md_proto_driver_t *driver, 
                                         md_store_group_t group, struct md_result_t *result);
typedef apr_status_t md_proto_complete_md_cb(md_t *md, apr_pool_t *p);

struct md_proto_t {
    const char *protocol;
    md_proto_init_cb *init;
    md_proto_renew_cb *renew;
    md_proto_init_preload_cb *init_preload;
    md_proto_preload_cb *preload;
    md_proto_complete_md_cb *complete_md;
};

/**
 * Run a test initialization of the renew protocol for the given MD. This verifies
 * basic parameter settings and is expected to return a description of encountered
 * problems in <pmessage> when != APR_SUCCESS.
 * A message return is allocated fromt the given pool.
 */
apr_status_t md_reg_test_init(md_reg_t *reg, const md_t *md, struct apr_table_t *env, 
                              struct md_result_t *result, apr_pool_t *p);

/**
 * Obtain new credentials for the given managed domain in STAGING.
 * @param reg the registry instance
 * @param md the mdomain to renew
 * @param env global environment of settings
 * @param reset != 0 if any previous, partial information should be wiped
 * @param attempt the number of attempts made this far (for this md)
 * @param result for reporting results of the renewal
 * @param p the memory pool to use
 * @return APR_SUCCESS if new credentials have been staged successfully
 */
apr_status_t md_reg_renew(md_reg_t *reg, const md_t *md, 
                          struct apr_table_t *env, int reset, int attempt,
                          struct md_result_t *result, apr_pool_t *p);

/**
 * Load a new set of credentials for the managed domain from STAGING - if it exists. 
 * This will archive any existing credential data and make the staged set the new one
 * in DOMAINS.
 * If staging is incomplete or missing, the load will fail and all credentials remain
 * as they are.
 *
 * @return APR_SUCCESS on loading new data, APR_ENOENT when nothing is staged, error otherwise.
 */
apr_status_t md_reg_load_staging(md_reg_t *reg, const md_t *md, struct apr_table_t *env, 
                                 struct md_result_t *result, apr_pool_t *p);

/**
 * Check given MDomains for new data in staging areas and, if it exists, load
 * the new credentials. On encountering errors, leave the credentails as
 * they are.
 */
apr_status_t md_reg_load_stagings(md_reg_t *reg, apr_array_header_t *mds,
                                  apr_table_t *env, apr_pool_t *p);

void md_reg_set_renew_window_default(md_reg_t *reg, md_timeslice_t *renew_window);
void md_reg_set_warn_window_default(md_reg_t *reg, md_timeslice_t *warn_window);

struct md_job_t *md_reg_job_make(md_reg_t *reg, const char *mdomain, apr_pool_t *p);

/**
 * Acquire a cooperative, global lock on registry modifications. Will
 * do nothing if locking is not configured.
 *
 * This will only prevent other children/processes/cluster nodes from
 * doing the same and does not protect individual store functions from
 * being called without it.
 * @param reg the registy
 * @param p memory pool to use
 * @param max_wait maximum time to wait in order to acquire
 * @return APR_SUCCESS when lock was obtained
 */
apr_status_t md_reg_lock_global(md_reg_t *reg, apr_pool_t *p);

/**
 * Realease the global registry lock. Will do nothing if there is no lock.
 */
void md_reg_unlock_global(md_reg_t *reg, apr_pool_t *p);

/**
 * @return != 0 iff `md` has any certificates known to be REVOKED.
 */
int md_reg_has_revoked_certs(md_reg_t *reg, struct md_ocsp_reg_t *ocsp,
                             const md_t *md, apr_pool_t *p);

#endif /* mod_md_md_reg_h */
