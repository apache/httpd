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

#ifndef mod_md_md_store_fs_h
#define mod_md_md_store_fs_h

struct md_store_t;

/** 
 * Default file permissions set by the store, user only read/write(/exec),
 * if so supported by the apr. 
 */
#define MD_FPROT_F_UONLY      (APR_FPROT_UREAD|APR_FPROT_UWRITE)
#define MD_FPROT_D_UONLY      (MD_FPROT_F_UONLY|APR_FPROT_UEXECUTE)

/**
 * User has all permission, group can read, other none
 */
#define MD_FPROT_F_UALL_GREAD (MD_FPROT_F_UONLY|APR_FPROT_GREAD)
#define MD_FPROT_D_UALL_GREAD (MD_FPROT_D_UONLY|APR_FPROT_GREAD|APR_FPROT_GEXECUTE)

/**
 * User has all permission, group and others can read
 */
#define MD_FPROT_F_UALL_WREAD (MD_FPROT_F_UALL_GREAD|APR_FPROT_WREAD)
#define MD_FPROT_D_UALL_WREAD (MD_FPROT_D_UALL_GREAD|APR_FPROT_WREAD|APR_FPROT_WEXECUTE)

apr_status_t md_store_fs_init(struct md_store_t **pstore, apr_pool_t *p, 
                              const char *path);


apr_status_t md_store_fs_default_perms_set(struct md_store_t *store, 
                                           apr_fileperms_t file_perms,
                                           apr_fileperms_t dir_perms);
apr_status_t md_store_fs_group_perms_set(struct md_store_t *store, 
                                         md_store_group_t group, 
                                         apr_fileperms_t file_perms,
                                         apr_fileperms_t dir_perms);

typedef enum {
    MD_S_FS_EV_CREATED,
    MD_S_FS_EV_MOVED,
} md_store_fs_ev_t; 

typedef apr_status_t md_store_fs_cb(void *baton, struct md_store_t *store,
                                    md_store_fs_ev_t ev, int group, 
                                    const char *fname, apr_filetype_e ftype,  
                                    apr_pool_t *p);
                                    
apr_status_t md_store_fs_set_event_cb(struct md_store_t *store, md_store_fs_cb *cb, void *baton);

#endif /* mod_md_md_store_fs_h */
