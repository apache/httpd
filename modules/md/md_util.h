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
/* data chunks */

typedef void md_data_free_fn(void *data);

typedef struct md_data_t md_data_t;
struct md_data_t {
    const char *data;
    apr_size_t len;
    md_data_free_fn *free_data;
};

/**
 * Init the data to empty, overwriting any content.
 */
void md_data_null(md_data_t *d);

/**
 * Create a new md_data_t, providing `len` bytes allocated from pool `p`.
 */
md_data_t *md_data_pmake(apr_size_t len, apr_pool_t *p);
/**
 * Initialize md_data_t 'd', providing `len` bytes allocated from pool `p`.
 */
void md_data_pinit(md_data_t *d, apr_size_t len, apr_pool_t *p);
/**
 * Initialize md_data_t 'd', by borrowing 'len' bytes in `data` without copying.
 * `d` will not take ownership.
 */
void md_data_init(md_data_t *d, const char *data, apr_size_t len);

/**
 * Initialize md_data_t 'd', by borrowing the NUL-terminated `str`.
 * `d` will not take ownership.
 */
void md_data_init_str(md_data_t *d, const char *str);

/**
 * Free any present data and clear (NULL) it. Passing NULL is permitted.
 */
void md_data_clear(md_data_t *d);

md_data_t *md_data_make_pcopy(apr_pool_t *p, const char *data, apr_size_t len);

apr_status_t md_data_assign_copy(md_data_t *dest, const char *src, apr_size_t src_len);
void md_data_assign_pcopy(md_data_t *dest, const char *src, apr_size_t src_len, apr_pool_t *p);

apr_status_t md_data_to_hex(const char **phex, char separator,
                            apr_pool_t *p, const md_data_t *data);

/**************************************************************************************************/
/* generic arrays */

/**
 * In an array of pointers, remove all entries == elem. Returns the number
 * of entries removed.
 */
int md_array_remove(struct apr_array_header_t *a, void *elem);

/* 
 * Remove the ith entry from the array.
 * @return != 0 iff an entry was removed, e.g. idx was not outside range 
 */
int md_array_remove_at(struct apr_array_header_t *a, int idx);

/**************************************************************************************************/
/* string related */
char *md_util_str_tolower(char *s);

/**
 * Return != 0 iff array is either NULL or empty 
 */ 
int md_array_is_empty(const struct apr_array_header_t *array);

int md_array_str_index(const struct apr_array_header_t *array, const char *s, 
                       int start, int case_sensitive);

int md_array_str_eq(const struct apr_array_header_t *a1, 
                    const struct apr_array_header_t *a2, int case_sensitive);

struct apr_array_header_t *md_array_str_clone(apr_pool_t *p, struct apr_array_header_t *array);

/**
 * Create a new array with duplicates removed.
 */
struct apr_array_header_t *md_array_str_compact(apr_pool_t *p, struct apr_array_header_t *src,
                                                int case_sensitive);

/**
 * Create a new array with all occurrences of <exclude> removed.
 */
struct apr_array_header_t *md_array_str_remove(apr_pool_t *p, struct apr_array_header_t *src, 
                                               const char *exclude, int case_sensitive);

int md_array_str_add_missing(struct apr_array_header_t *dest, 
                             struct apr_array_header_t *src, int case_sensitive);

/**************************************************************************************************/
/* process execution */

apr_status_t md_util_exec(apr_pool_t *p, const char *cmd, const char * const *argv,
                          struct apr_array_header_t *env, int *exit_code);

/**************************************************************************************************/
/* dns name check */

/**
 * Is a host/domain name using allowed characters. Not a wildcard.
 * @param domain     name to check
 * @param need_fqdn  iff != 0, check that domain contains '.'
 * @return != 0 iff domain looks like  a non-wildcard, legal DNS domain name.
 */
int md_dns_is_name(apr_pool_t *p, const char *domain, int need_fqdn);

/**
 * Check if the given domain is a valid wildcard DNS name, e.g. *.example.org
 * @param domain    name to check
 * @return != 0 iff domain is a DNS wildcard.
 */
int md_dns_is_wildcard(apr_pool_t *p, const char *domain);

/**
 * Determine iff pattern matches domain, including case-ignore and wildcard domains.
 * It is assumed that both names follow dns syntax.
 * @return != 0 iff pattern matches domain
 */ 
int md_dns_matches(const char *pattern, const char *domain);

/**
 * Create a new array with the minimal set out of the given domain names that match all
 * of them. If none of the domains is a wildcard, only duplicates are removed.
 * If domains contain a wildcard, any name matching the wildcard will be removed.
 */
struct apr_array_header_t *md_dns_make_minimal(apr_pool_t *p, 
                                               struct apr_array_header_t *domains);

/**
 * Determine if the given domains cover the name, including wildcard matching.
 * @return != 0 iff name is matched by list of domains
 */
int md_dns_domains_match(const apr_array_header_t *domains, const char *name);

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
apr_status_t md_util_is_unix_socket(const char *path, apr_pool_t *pool);
int md_file_exists(const char *fname, apr_pool_t *p);

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
const char *md_util_base64url_encode(const md_data_t *data, apr_pool_t *pool);
apr_size_t md_util_base64url_decode(md_data_t *decoded, const char *encoded, 
                                    apr_pool_t *pool);

/**************************************************************************************************/
/* http/url related */
const char *md_util_schemify(apr_pool_t *p, const char *s, const char *def_scheme);

apr_status_t md_util_abs_uri_check(apr_pool_t *p, const char *s, const char **perr);
apr_status_t md_util_abs_http_uri_check(apr_pool_t *p, const char *uri, const char **perr);

const char *md_link_find_relation(const struct apr_table_t *headers, 
                                  apr_pool_t *pool, const char *relation);

const char *md_util_parse_ct(apr_pool_t *pool, const char *cth);
/**************************************************************************************************/
/* retry logic */

typedef apr_status_t md_util_try_fn(void *baton, int i);

apr_status_t md_util_try(md_util_try_fn *fn, void *baton, int ignore_errs,  
                         apr_interval_time_t timeout, apr_interval_time_t start_delay, 
                         apr_interval_time_t max_delay, int backoff);

#endif /* md_util_h */
