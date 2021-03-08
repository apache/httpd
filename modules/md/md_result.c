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
 
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_date.h>
#include <apr_time.h>
#include <apr_strings.h>

#include "md.h"
#include "md_json.h"
#include "md_log.h"
#include "md_result.h"

static const char *dup_trim(apr_pool_t *p, const char *s)
{
    char *d = apr_pstrdup(p, s);
    if (d) apr_collapse_spaces(d, d);
    return d;
}

md_result_t *md_result_make(apr_pool_t *p, apr_status_t status)
{
    md_result_t *result;
    
    result = apr_pcalloc(p, sizeof(*result));
    result->p = p;
    result->md_name = MD_OTHER;
    result->status = status;
    return result;
}

md_result_t *md_result_md_make(apr_pool_t *p, const char *md_name)
{
    md_result_t *result = md_result_make(p, APR_SUCCESS);
    result->md_name = md_name;
    return result;
}

void md_result_reset(md_result_t *result)
{
    apr_pool_t *p = result->p;
    memset(result, 0, sizeof(*result));
    result->p = p;
}

static void on_change(md_result_t *result)
{
    if (result->on_change) result->on_change(result, result->on_change_data);
}

void md_result_activity_set(md_result_t *result, const char *activity)
{
    md_result_activity_setn(result, activity? apr_pstrdup(result->p, activity) : NULL);
}

void md_result_activity_setn(md_result_t *result, const char *activity)
{
    result->activity = activity;
    result->problem = result->detail = NULL;
    result->subproblems = NULL;
    on_change(result);
}

void md_result_activity_printf(md_result_t *result, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    md_result_activity_setn(result, apr_pvsprintf(result->p, fmt, ap));
    va_end(ap);
}

void md_result_set(md_result_t *result, apr_status_t status, const char *detail)
{
    result->status = status;
    result->problem = NULL;
    result->detail = detail? apr_pstrdup(result->p, detail) : NULL;
    result->subproblems = NULL;
    on_change(result);
}

void md_result_problem_set(md_result_t *result, apr_status_t status,
                           const char *problem, const char *detail, 
                           const md_json_t *subproblems)
{
    result->status = status;
    result->problem = dup_trim(result->p, problem);
    result->detail = apr_pstrdup(result->p, detail);
    result->subproblems = subproblems? md_json_clone(result->p, subproblems) : NULL;
    on_change(result);
}

void md_result_problem_printf(md_result_t *result, apr_status_t status,
                              const char *problem, const char *fmt, ...)
{
    va_list ap;

    result->status = status;
    result->problem = dup_trim(result->p, problem);

    va_start(ap, fmt);
    result->detail = apr_pvsprintf(result->p, fmt, ap);
    va_end(ap);
    result->subproblems = NULL;
    on_change(result);
}

void md_result_printf(md_result_t *result, apr_status_t status, const char *fmt, ...)
{
    va_list ap;

    result->status = status;
    va_start(ap, fmt);
    result->detail = apr_pvsprintf(result->p, fmt, ap);
    va_end(ap);
    result->subproblems = NULL;
    on_change(result);
}

void md_result_delay_set(md_result_t *result, apr_time_t ready_at)
{
    result->ready_at = ready_at;
    on_change(result);
}

md_result_t*md_result_from_json(const struct md_json_t *json, apr_pool_t *p)
{
    md_result_t *result;
    const char *s;
    
    result = md_result_make(p, APR_SUCCESS);
    result->status = (int)md_json_getl(json, MD_KEY_STATUS, NULL);
    result->problem = md_json_dups(p, json, MD_KEY_PROBLEM, NULL);
    result->detail = md_json_dups(p, json, MD_KEY_DETAIL, NULL);
    result->activity = md_json_dups(p, json, MD_KEY_ACTIVITY, NULL);
    s = md_json_dups(p, json, MD_KEY_VALID_FROM, NULL);
    if (s && *s) result->ready_at = apr_date_parse_rfc(s);
    result->subproblems = md_json_dupj(p, json, MD_KEY_SUBPROBLEMS, NULL);
    return result;
}

struct md_json_t *md_result_to_json(const md_result_t *result, apr_pool_t *p)
{
    md_json_t *json;
    char ts[APR_RFC822_DATE_LEN];
   
    json = md_json_create(p);
    md_json_setl(result->status, json, MD_KEY_STATUS, NULL);
    if (result->status > 0) {
        char buffer[HUGE_STRING_LEN];
        apr_strerror(result->status, buffer, sizeof(buffer));
        md_json_sets(buffer, json, "status-description", NULL);
    }
    if (result->problem) md_json_sets(result->problem, json, MD_KEY_PROBLEM, NULL);
    if (result->detail) md_json_sets(result->detail, json, MD_KEY_DETAIL, NULL);
    if (result->activity) md_json_sets(result->activity, json, MD_KEY_ACTIVITY, NULL);
    if (result->ready_at > 0) {
        apr_rfc822_date(ts, result->ready_at);
        md_json_sets(ts, json, MD_KEY_VALID_FROM, NULL);
    }
    if (result->subproblems) {
        md_json_setj(result->subproblems, json, MD_KEY_SUBPROBLEMS, NULL);
    }
    return json;
}

static int str_cmp(const char *s1, const char *s2)
{
    if (s1 == s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return strcmp(s1, s2);
}

int md_result_cmp(const md_result_t *r1, const md_result_t *r2)
{
    int n;
    if (r1 == r2) return 0;
    if (!r1) return -1;
    if (!r2) return 1;
    if ((n = r1->status - r2->status)) return n;
    if ((n = str_cmp(r1->problem, r2->problem))) return n;
    if ((n = str_cmp(r1->detail, r2->detail))) return n;
    if ((n = str_cmp(r1->activity, r2->activity))) return n;
    return (int)(r1->ready_at - r2->ready_at);
}

void md_result_assign(md_result_t *dest, const md_result_t *src)
{
   dest->status = src->status;
   dest->problem = src->problem;
   dest->detail = src->detail;
   dest->activity = src->activity;
   dest->ready_at = src->ready_at;
   dest->subproblems = src->subproblems;
}

void md_result_dup(md_result_t *dest, const md_result_t *src)
{
   dest->status = src->status;
   dest->problem = src->problem? dup_trim(dest->p, src->problem) : NULL; 
   dest->detail = src->detail? apr_pstrdup(dest->p, src->detail) : NULL; 
   dest->activity = src->activity? apr_pstrdup(dest->p, src->activity) : NULL; 
   dest->ready_at = src->ready_at;
   dest->subproblems = src->subproblems? md_json_clone(dest->p, src->subproblems) : NULL;
   on_change(dest);
}

void md_result_log(md_result_t *result, unsigned int level)
{
    if (md_log_is_level(result->p, (md_log_level_t)level)) {
        const char *sep = "";
        const char *msg = "";
        
        if (result->md_name) {
            msg = apr_psprintf(result->p, "md[%s]", result->md_name);
            sep = " ";
        }
        if (result->activity) {
            msg = apr_psprintf(result->p, "%s%swhile[%s]", msg, sep, result->activity);
            sep = " ";
        }
        if (result->problem) {
            msg = apr_psprintf(result->p, "%s%sproblem[%s]", msg, sep, result->problem);
            sep = " ";
        }
        if (result->detail) {
            msg = apr_psprintf(result->p, "%s%sdetail[%s]", msg, sep, result->detail);
            sep = " ";
        }
        if (result->subproblems) {
            msg = apr_psprintf(result->p, "%s%ssubproblems[%s]", msg, sep, 
                md_json_writep(result->subproblems, result->p, MD_JSON_FMT_COMPACT));
            sep = " ";
        }
        md_log_perror(MD_LOG_MARK, (md_log_level_t)level, result->status, result->p, "%s", msg);
    }
}

void md_result_on_change(md_result_t *result, md_result_change_cb *cb, void *data)
{
    result->on_change = cb;
    result->on_change_data = data;
}

apr_status_t md_result_raise(md_result_t *result, const char *event, apr_pool_t *p)
{
    if (result->on_raise) return result->on_raise(result, result->on_raise_data, event, p);
    return APR_SUCCESS;
}

void md_result_holler(md_result_t *result, const char *event, apr_pool_t *p)
{
    if (result->on_holler) result->on_holler(result, result->on_holler_data, event, p);
}

void md_result_on_raise(md_result_t *result, md_result_raise_cb *cb, void *data)
{
    result->on_raise = cb;
    result->on_raise_data = data;
}

void md_result_on_holler(md_result_t *result, md_result_holler_cb *cb, void *data)
{
    result->on_holler = cb;
    result->on_holler_data = data;
}
