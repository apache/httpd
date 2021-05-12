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

#ifndef mod_md_md_json_h
#define mod_md_md_json_h

#include <apr_file_io.h>

struct apr_bucket_brigade;
struct apr_file_t;

struct md_http_t;
struct md_http_response_t;
struct md_timeperiod_t;

typedef struct md_json_t md_json_t;

typedef enum {
    MD_JSON_TYPE_OBJECT,
    MD_JSON_TYPE_ARRAY,
    MD_JSON_TYPE_STRING,
    MD_JSON_TYPE_REAL,
    MD_JSON_TYPE_INT,
    MD_JSON_TYPE_BOOL,
    MD_JSON_TYPE_NULL,
} md_json_type_t;


typedef enum {
    MD_JSON_FMT_COMPACT,
    MD_JSON_FMT_INDENT,
} md_json_fmt_t;

md_json_t *md_json_create(apr_pool_t *pool);
void md_json_destroy(md_json_t *json);

md_json_t *md_json_copy(apr_pool_t *pool, const md_json_t *json);
md_json_t *md_json_clone(apr_pool_t *pool, const md_json_t *json);


int md_json_has_key(const md_json_t *json, ...);
int md_json_is(const md_json_type_t type, md_json_t *json, ...);

/* boolean manipulation */
int md_json_getb(const md_json_t *json, ...);
apr_status_t md_json_setb(int value, md_json_t *json, ...);

/* number manipulation */
double md_json_getn(const md_json_t *json, ...);
apr_status_t md_json_setn(double value, md_json_t *json, ...);

/* long manipulation */
long md_json_getl(const md_json_t *json, ...);
apr_status_t md_json_setl(long value, md_json_t *json, ...);

/* string manipulation */
md_json_t *md_json_create_s(apr_pool_t *pool, const char *s);
const char *md_json_gets(const md_json_t *json, ...);
const char *md_json_dups(apr_pool_t *p, const md_json_t *json, ...);
apr_status_t md_json_sets(const char *s, md_json_t *json, ...);

/* timestamp manipulation */
apr_time_t md_json_get_time(const md_json_t *json, ...);
apr_status_t md_json_set_time(apr_time_t value, md_json_t *json, ...);

/* json manipulation */
md_json_t *md_json_getj(md_json_t *json, ...);
md_json_t *md_json_dupj(apr_pool_t *p, const md_json_t *json, ...);
const md_json_t *md_json_getcj(const md_json_t *json, ...);
apr_status_t md_json_setj(const md_json_t *value, md_json_t *json, ...);
apr_status_t md_json_addj(const md_json_t *value, md_json_t *json, ...);
apr_status_t md_json_insertj(md_json_t *value, size_t index, md_json_t *json, ...);

/* Array/Object manipulation */
apr_status_t md_json_clr(md_json_t *json, ...);
apr_status_t md_json_del(md_json_t *json, ...);

/* Remove all array elements beyond max_elements */ 
apr_size_t md_json_limita(size_t max_elements, md_json_t *json, ...);

/* conversion function from and to json */
typedef apr_status_t md_json_to_cb(void *value, md_json_t *json, apr_pool_t *p, void *baton);
typedef apr_status_t md_json_from_cb(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton);

/* identity pass through from json to json */
apr_status_t md_json_pass_to(void *value, md_json_t *json, apr_pool_t *p, void *baton);
apr_status_t md_json_pass_from(void **pvalue, md_json_t *json, apr_pool_t *p, void *baton);

/* conversions from json to json in specified pool */
apr_status_t md_json_clone_to(void *value, md_json_t *json, apr_pool_t *p, void *baton);
apr_status_t md_json_clone_from(void **pvalue, const md_json_t *json, apr_pool_t *p, void *baton);

/* Manipulating/Iteration on generic Arrays */
apr_status_t md_json_geta(apr_array_header_t *a, md_json_from_cb *cb, 
                          void *baton, const md_json_t *json, ...);
apr_status_t md_json_seta(apr_array_header_t *a, md_json_to_cb *cb, 
                          void *baton, md_json_t *json, ...);

/* Called on each array element, aborts iteration when returning 0 */
typedef int md_json_itera_cb(void *baton, size_t index, md_json_t *json);
int md_json_itera(md_json_itera_cb *cb, void *baton, md_json_t *json, ...);

/* Called on each object key, aborts iteration when returning 0 */
typedef int md_json_iterkey_cb(void *baton, const char* key, md_json_t *json);
int md_json_iterkey(md_json_iterkey_cb *cb, void *baton, md_json_t *json, ...);

/* Manipulating Object String values */
apr_status_t md_json_gets_dict(apr_table_t *dict, const md_json_t *json, ...);
apr_status_t md_json_sets_dict(apr_table_t *dict, md_json_t *json, ...);

/* Manipulating String Arrays */
apr_status_t md_json_getsa(apr_array_header_t *a, const md_json_t *json, ...);
apr_status_t md_json_dupsa(apr_array_header_t *a, apr_pool_t *p, md_json_t *json, ...);
apr_status_t md_json_setsa(apr_array_header_t *a, md_json_t *json, ...);

/* serialization & parsing */
apr_status_t md_json_writeb(const md_json_t *json, md_json_fmt_t fmt, struct apr_bucket_brigade *bb);
const char *md_json_writep(const md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt);
apr_status_t md_json_writef(const md_json_t *json, apr_pool_t *p, 
                            md_json_fmt_t fmt, struct apr_file_t *f);
apr_status_t md_json_fcreatex(const md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, 
                              const char *fpath, apr_fileperms_t perms);
apr_status_t md_json_freplace(const md_json_t *json, apr_pool_t *p, md_json_fmt_t fmt, 
                              const char *fpath, apr_fileperms_t perms);

apr_status_t md_json_readb(md_json_t **pjson, apr_pool_t *pool, struct apr_bucket_brigade *bb);
apr_status_t md_json_readd(md_json_t **pjson, apr_pool_t *pool, const char *data, size_t data_len);
apr_status_t md_json_readf(md_json_t **pjson, apr_pool_t *pool, const char *fpath);


/* http retrieval */
apr_status_t md_json_http_get(md_json_t **pjson, apr_pool_t *pool,
                              struct md_http_t *http, const char *url);
apr_status_t md_json_read_http(md_json_t **pjson, apr_pool_t *pool, 
                               const struct md_http_response_t *res);

apr_status_t md_json_copy_to(md_json_t *dest, const md_json_t *src, ...);

const char *md_json_dump_state(const md_json_t *json, apr_pool_t *p);

apr_status_t md_json_set_timeperiod(const struct md_timeperiod_t *tp, md_json_t *json, ...);
apr_status_t md_json_get_timeperiod(struct md_timeperiod_t *tp, md_json_t *json, ...);

#endif /* md_json_h */
