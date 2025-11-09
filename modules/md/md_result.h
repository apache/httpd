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

#ifndef mod_md_md_result_h
#define mod_md_md_result_h

struct md_json_t;
struct md_t;

typedef struct md_result_t md_result_t;

typedef void md_result_change_cb(md_result_t *result, void *data);
typedef apr_status_t md_result_raise_cb(md_result_t *result, void *data, const char *event, apr_pool_t *p);
typedef void md_result_holler_cb(md_result_t *result, void *data, const char *event, apr_pool_t *p);

struct md_result_t {
    apr_pool_t *p;
    const char *md_name;
    apr_status_t status;
    const char *problem;
    const char *detail;
    const struct md_json_t *subproblems;
    const char *activity;
    apr_time_t ready_at;
    md_result_change_cb *on_change;
    void *on_change_data;
    md_result_raise_cb *on_raise;
    void *on_raise_data;
    md_result_holler_cb *on_holler;
    void *on_holler_data;
};

md_result_t *md_result_make(apr_pool_t *p, apr_status_t status);
md_result_t *md_result_md_make(apr_pool_t *p, const char *md_name);
void md_result_reset(md_result_t *result);

void md_result_activity_set(md_result_t *result, const char *activity);
void md_result_activity_setn(md_result_t *result, const char *activity);
void md_result_activity_printf(md_result_t *result, const char *fmt, ...);

void md_result_set(md_result_t *result, apr_status_t status, const char *detail);
void md_result_problem_set(md_result_t *result, apr_status_t status, 
                           const char *problem, const char *detail, 
                           const struct md_json_t *subproblems);
void md_result_problem_printf(md_result_t *result, apr_status_t status,
                              const char *problem, const char *fmt, ...);

#define MD_RESULT_LOG_ID(logno)       "urn:org:apache:httpd:log:"logno

void md_result_printf(md_result_t *result, apr_status_t status, const char *fmt, ...);

void md_result_delay_set(md_result_t *result, apr_time_t ready_at);

md_result_t*md_result_from_json(const struct md_json_t *json, apr_pool_t *p);
struct md_json_t *md_result_to_json(const md_result_t *result, apr_pool_t *p);

int md_result_cmp(const md_result_t *r1, const md_result_t *r2);

void md_result_assign(md_result_t *dest, const md_result_t *src);
void md_result_dup(md_result_t *dest, const md_result_t *src);

void md_result_log(md_result_t *result, unsigned int level);

void md_result_on_change(md_result_t *result, md_result_change_cb *cb, void *data);

/* events in the context of a result genesis */

apr_status_t md_result_raise(md_result_t *result, const char *event, apr_pool_t *p);
void md_result_holler(md_result_t *result, const char *event, apr_pool_t *p);

void md_result_on_raise(md_result_t *result, md_result_raise_cb *cb, void *data);
void md_result_on_holler(md_result_t *result, md_result_holler_cb *cb, void *data);

#endif /* mod_md_md_result_h */
