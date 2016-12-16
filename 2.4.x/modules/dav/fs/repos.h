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

/**
 * @file  repos.h
 * @brief Declarations for the filesystem repository implementation
 *
 * @addtogroup MOD_DAV
 * @{
 */

#ifndef _DAV_FS_REPOS_H_
#define _DAV_FS_REPOS_H_

/* the subdirectory to hold all DAV-related information for a directory */
#define DAV_FS_STATE_DIR                ".DAV"
#define DAV_FS_STATE_FILE_FOR_DIR       ".state_for_dir"
#define DAV_FS_LOCK_NULL_FILE           ".locknull"


/* ensure that our state subdirectory is present */
void dav_fs_ensure_state_dir(apr_pool_t *p, const char *dirname);

/* return the storage pool associated with a resource */
apr_pool_t *dav_fs_pool(const dav_resource *resource);

/* return the full pathname for a resource */
const char *dav_fs_pathname(const dav_resource *resource);

/* return the directory and filename for a resource */
dav_error * dav_fs_dir_file_name(const dav_resource *resource,
                                 const char **dirpath,
                                 const char **fname);

/* return the list of locknull members in this resource's directory */
dav_error * dav_fs_get_locknull_members(const dav_resource *resource,
                                        dav_buffer *pbuf);


/* DBM functions used by the repository and locking providers */
extern const dav_hooks_db dav_hooks_db_dbm;

dav_error * dav_dbm_open_direct(apr_pool_t *p, const char *pathname, int ro,
                                dav_db **pdb);
void dav_dbm_get_statefiles(apr_pool_t *p, const char *fname,
                            const char **state1, const char **state2);
dav_error * dav_dbm_delete(dav_db *db, apr_datum_t key);
dav_error * dav_dbm_store(dav_db *db, apr_datum_t key, apr_datum_t value);
dav_error * dav_dbm_fetch(dav_db *db, apr_datum_t key, apr_datum_t *pvalue);
void dav_dbm_freedatum(dav_db *db, apr_datum_t data);
int dav_dbm_exists(dav_db *db, apr_datum_t key);
void dav_dbm_close(dav_db *db);

/* where is the lock database located? */
const char *dav_get_lockdb_path(const request_rec *r);

const dav_hooks_locks *dav_fs_get_lock_hooks(request_rec *r);
const dav_hooks_propdb *dav_fs_get_propdb_hooks(request_rec *r);

void dav_fs_gather_propsets(apr_array_header_t *uris);
int dav_fs_find_liveprop(const dav_resource *resource,
                         const char *ns_uri, const char *name,
                         const dav_hooks_liveprop **hooks);
void dav_fs_insert_all_liveprops(request_rec *r, const dav_resource *resource,
                                 dav_prop_insert what, apr_text_header *phdr);

void dav_fs_register(apr_pool_t *p);

#endif /* _DAV_FS_REPOS_H_ */
/** @} */

