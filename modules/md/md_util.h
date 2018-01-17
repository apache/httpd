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

#ifndef mod_md_md_util_h
#define mod_md_md_util_h

#include <stdio.h>
#include <apr_file_io.h>

struct apr_array_header_t;
struct apr_table_t;

/**************************************************************************************************/
/* pool utils */

typedef apr_status_t md_util_action(void *baton, apr_pool_t *p, apr_pool_t *ptemp);
typedef apr_status_t md_util_vaction(void *baton, apr_pool_t *p, apr_pool_t *ptemp, va_list ap);

apr_status_t md_util_pool_do(md_util_action *cb, void *baton, apr_pool_t *p); 
apr_status_t md_util_pool_vdo(md_util_vaction *cb, void *baton, apr_pool_t *p, ...); 

/**************************************************************************************************/
/* string related */
char *md_util_str_tolower(char *s);

int md_array_str_index(const struct apr_array_header_t *array, const char *s, 
                       int start, int case_sensitive);

int md_array_str_eq(const struct apr_array_header_t *a1, 
                    const struct apr_array_header_t *a2, int case_sensitive);

struct apr_array_header_t *md_array_str_clone(apr_pool_t *p, struct apr_array_header_t *array);

struct apr_array_header_t *md_array_str_compact(apr_pool_t *p, struct apr_array_header_t *src,
                                                int case_sensitive);

struct apr_array_header_t *md_array_str_remove(apr_pool_t *p, struct apr_array_header_t *src, 
                                               const char *exclude, int case_sensitive);

int md_array_str_add_missing(struct apr_array_header_t *dest, 
                             struct apr_array_header_t *src, int case_sensitive);

/**************************************************************************************************/
/* process execution */
apr_status_t md_util_exec(apr_pool_t *p, const char *cmd, const char * const *argv,
                          int *exit_code);

/**************************************************************************************************/
/* dns name check */

int md_util_is_dns_name(apr_pool_t *p, const char *hostname, int need_fqdn);

/**************************************************************************************************/
/* file system related */

struct apr_file_t;
struct apr_finfo_t;

apr_status_t md_util_fopen(FILE **pf, const char *fn, const char *mode);

apr_status_t md_util_fcreatex(struct apr_file_t **pf, const char *fn, 
                              apr_fileperms_t perms, apr_pool_t *p);

apr_status_t md_util_path_merge(const char **ppath, apr_pool_t *p, ...);

apr_status_t md_util_is_dir(const char *path, apr_pool_t *pool);
apr_status_t md_util_is_file(const char *path, apr_pool_t *pool);

typedef apr_status_t md_util_file_cb(void *baton, struct apr_file_t *f, apr_pool_t *p);

apr_status_t md_util_freplace(const char *fpath, apr_fileperms_t perms, apr_pool_t *p, 
                              md_util_file_cb *write, void *baton);

/** 
 * Remove a file/directory and all files/directories contain up to max_level. If max_level == 0,
 * only an empty directory or a file can be removed.
 */
apr_status_t md_util_rm_recursive(const char *fpath, apr_pool_t *p, int max_level);

typedef apr_status_t md_util_fdo_cb(void *baton, apr_pool_t *p, apr_pool_t *ptemp, 
                                         const char *dir, const char *name, 
                                         apr_filetype_e ftype);
                                         
apr_status_t md_util_files_do(md_util_fdo_cb *cb, void *baton, apr_pool_t *p, 
                              const char *path, ...);

/**
 * Depth first traversal of directory tree starting at path.
 */
apr_status_t md_util_tree_do(md_util_fdo_cb *cb, void *baton, apr_pool_t *p, 
                             const char *path, int follow_links);

apr_status_t md_util_ftree_remove(const char *path, apr_pool_t *p);

apr_status_t md_text_fread8k(const char **ptext, apr_pool_t *p, const char *fpath);
apr_status_t md_text_fcreatex(const char *fpath, apr_fileperms_t 
                              perms, apr_pool_t *p, const char *text);
apr_status_t md_text_freplace(const char *fpath, apr_fileperms_t perms, 
                              apr_pool_t *p, const char *text); 

/**************************************************************************************************/
/* base64 url encodings */
const char *md_util_base64url_encode(const char *data, 
                                     apr_size_t len, apr_pool_t *pool);
apr_size_t md_util_base64url_decode(const char **decoded, const char *encoded, 
                                    apr_pool_t *pool);

/**************************************************************************************************/
/* http/url related */
const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme);

apr_status_t md_util_abs_uri_check(apr_pool_t *p, const char *s, const char **perr);
apr_status_t md_util_abs_http_uri_check(apr_pool_t *p, const char *uri, const char **perr);

const char *md_link_find_relation(const struct apr_table_t *headers, 
                                  apr_pool_t *pool, const char *relation);

/**************************************************************************************************/
/* retry logic */

typedef apr_status_t md_util_try_fn(void *baton, int i);

apr_status_t md_util_try(md_util_try_fn *fn, void *baton, int ignore_errs,  
                         apr_interval_time_t timeout, apr_interval_time_t start_delay, 
                         apr_interval_time_t max_delay, int backoff);

/**************************************************************************************************/
/* date/time related */

#define MD_SECS_PER_HOUR      (60*60)
#define MD_SECS_PER_DAY       (24*MD_SECS_PER_HOUR)

const char *md_print_duration(apr_pool_t *p, apr_interval_time_t duration);

#endif /* md_util_h */
