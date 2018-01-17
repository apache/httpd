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

typedef struct md_store_t md_store_t;

typedef void md_store_destroy_cb(md_store_t *store);

const char *md_store_group_name(int group);


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

typedef int md_store_inspect(void *baton, const char *name, const char *aspect, 
                             md_store_vtype_t vtype, void *value, apr_pool_t *ptemp);

typedef apr_status_t md_store_iter_cb(md_store_inspect *inspect, void *baton, md_store_t *store, 
                                      apr_pool_t *p, md_store_group_t group, const char *pattern,
                                      const char *aspect, md_store_vtype_t vtype);

typedef apr_status_t md_store_move_cb(md_store_t *store, apr_pool_t *p, md_store_group_t from, 
                                      md_store_group_t to, const char *name, int archive);

typedef apr_status_t md_store_get_fname_cb(const char **pfname, 
                                           md_store_t *store, md_store_group_t group, 
                                           const char *name, const char *aspect, 
                                           apr_pool_t *p);

typedef int md_store_is_newer_cb(md_store_t *store, 
                                 md_store_group_t group1, md_store_group_t group2,  
                                 const char *name, const char *aspect, apr_pool_t *p);

struct md_store_t {
    md_store_destroy_cb *destroy;

    md_store_save_cb *save;
    md_store_load_cb *load;
    md_store_remove_cb *remove;
    md_store_move_cb *move;
    md_store_iter_cb *iterate;
    md_store_purge_cb *purge;
    md_store_get_fname_cb *get_fname;
    md_store_is_newer_cb *is_newer;
};

void md_store_destroy(md_store_t *store);

apr_status_t md_store_load_json(md_store_t *store, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                struct md_json_t **pdata, apr_pool_t *p);
apr_status_t md_store_save_json(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                struct md_json_t *data, int create);


apr_status_t md_store_load(md_store_t *store, md_store_group_t group, 
                           const char *name, const char *aspect, 
                           md_store_vtype_t vtype, void **pdata, 
                           apr_pool_t *p);
apr_status_t md_store_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                           const char *name, const char *aspect, 
                           md_store_vtype_t vtype, void *data, 
                           int create);
apr_status_t md_store_remove(md_store_t *store, md_store_group_t group, 
                             const char *name, const char *aspect, 
                             apr_pool_t *p, int force);
apr_status_t md_store_purge(md_store_t *store, apr_pool_t *p, 
                            md_store_group_t group, const char *name);


apr_status_t md_store_iter(md_store_inspect *inspect, void *baton, md_store_t *store, 
                           apr_pool_t *p, md_store_group_t group, const char *pattern, 
                           const char *aspect, md_store_vtype_t vtype);

apr_status_t md_store_move(md_store_t *store, apr_pool_t *p,
                           md_store_group_t from, md_store_group_t to,
                           const char *name, int archive);

apr_status_t md_store_get_fname(const char **pfname, 
                                md_store_t *store, md_store_group_t group, 
                                const char *name, const char *aspect, 
                                apr_pool_t *p);

int md_store_is_newer(md_store_t *store, md_store_group_t group1, md_store_group_t group2,  
                      const char *name, const char *aspect, apr_pool_t *p);

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


apr_status_t md_pkey_load(md_store_t *store, md_store_group_t group, 
                          const char *name, struct md_pkey_t **ppkey, apr_pool_t *p);
apr_status_t md_pkey_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                          const char *name, struct md_pkey_t *pkey, int create);
apr_status_t md_cert_load(md_store_t *store, md_store_group_t group, 
                          const char *name, struct md_cert_t **pcert, apr_pool_t *p);
apr_status_t md_cert_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                          const char *name, struct md_cert_t *cert, int create);
apr_status_t md_chain_load(md_store_t *store, md_store_group_t group, 
                           const char *name, struct apr_array_header_t **pchain, apr_pool_t *p);
apr_status_t md_chain_save(md_store_t *store, apr_pool_t *p, md_store_group_t group, 
                           const char *name, struct apr_array_header_t *chain, int create);

apr_status_t md_pubcert_load(md_store_t *store, md_store_group_t group, const char *name, 
                             struct apr_array_header_t **ppubcert, apr_pool_t *p);
apr_status_t md_pubcert_save(md_store_t *store, apr_pool_t *p, 
                             md_store_group_t group, const char *name, 
                             struct apr_array_header_t *pubcert, int create);


#endif /* mod_md_md_store_h */
