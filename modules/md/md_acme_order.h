/* Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef md_acme_order_h
#define md_acme_order_h

struct md_json_t;
struct md_result_t;

typedef struct md_acme_order_t md_acme_order_t;

typedef enum {
    MD_ACME_ORDER_ST_PENDING,
    MD_ACME_ORDER_ST_READY,
    MD_ACME_ORDER_ST_PROCESSING,
    MD_ACME_ORDER_ST_VALID,
    MD_ACME_ORDER_ST_INVALID,
} md_acme_order_st;

struct md_acme_order_t {
    apr_pool_t *p;
    const char *url;
    md_acme_order_st status;
    struct apr_array_header_t *authz_urls;
    struct apr_array_header_t *challenge_setups;
    struct md_json_t *json;
    const char *finalize;
    const char *certificate;
};

#define MD_FN_ORDER             "order.json"

/**************************************************************************************************/

md_acme_order_t *md_acme_order_create(apr_pool_t *p);

apr_status_t md_acme_order_add(md_acme_order_t *order, const char *authz_url);
apr_status_t md_acme_order_remove(md_acme_order_t *order, const char *authz_url);

struct md_json_t *md_acme_order_to_json(md_acme_order_t *set, apr_pool_t *p);
md_acme_order_t *md_acme_order_from_json(struct md_json_t *json, apr_pool_t *p);

apr_status_t md_acme_order_load(struct md_store_t *store, md_store_group_t group, 
                                    const char *md_name, md_acme_order_t **pauthz_set, 
                                    apr_pool_t *p);
apr_status_t md_acme_order_save(struct md_store_t *store, apr_pool_t *p, 
                                    md_store_group_t group, const char *md_name, 
                                    md_acme_order_t *authz_set, int create);

apr_status_t md_acme_order_purge(struct md_store_t *store, apr_pool_t *p, 
                                 md_store_group_t group, const md_t *md,
                                 apr_table_t *env);

apr_status_t md_acme_order_start_challenges(md_acme_order_t *order, md_acme_t *acme,
                                            apr_array_header_t *challenge_types,
                                            md_store_t *store, const md_t *md, 
                                            apr_table_t *env, struct md_result_t *result,
                                            apr_pool_t *p);

apr_status_t md_acme_order_monitor_authzs(md_acme_order_t *order, md_acme_t *acme, 
                                          const md_t *md, apr_interval_time_t timeout,
                                          struct md_result_t *result, apr_pool_t *p);

/* ACMEv2 only ************************************************************************************/

apr_status_t md_acme_order_register(md_acme_order_t **porder, md_acme_t *acme, apr_pool_t *p, 
                                    const char *name, struct apr_array_header_t *domains);

apr_status_t md_acme_order_update(md_acme_order_t *order, md_acme_t *acme, 
                                  struct md_result_t *result, apr_pool_t *p);

apr_status_t md_acme_order_await_ready(md_acme_order_t *order, md_acme_t *acme, 
                                       const md_t *md, apr_interval_time_t timeout, 
                                       struct md_result_t *result, apr_pool_t *p);
apr_status_t md_acme_order_await_valid(md_acme_order_t *order, md_acme_t *acme, 
                                       const md_t *md, apr_interval_time_t timeout, 
                                       struct md_result_t *result, apr_pool_t *p);

#endif /* md_acme_order_h */
