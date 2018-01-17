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

#ifndef mod_md_md_acme_authz_h
#define mod_md_md_acme_authz_h

struct apr_array_header_t;
struct md_acme_t;
struct md_acme_acct_t;
struct md_json_t;
struct md_store_t;
struct md_pkey_spec_t;

typedef struct md_acme_challenge_t md_acme_challenge_t;

/**************************************************************************************************/
/* authorization request for a specific domain name */

#define MD_AUTHZ_TYPE_HTTP01        "http-01"
#define MD_AUTHZ_TYPE_TLSSNI01      "tls-sni-01"

typedef enum {
    MD_ACME_AUTHZ_S_UNKNOWN,
    MD_ACME_AUTHZ_S_PENDING,
    MD_ACME_AUTHZ_S_VALID,
    MD_ACME_AUTHZ_S_INVALID,
} md_acme_authz_state_t;

typedef struct md_acme_authz_t md_acme_authz_t;

struct md_acme_authz_t {
    const char *domain;
    const char *location;
    const char *dir;
    md_acme_authz_state_t state;
    apr_time_t expires;
    struct md_json_t *resource;
};

#define MD_FN_HTTP01            "acme-http-01.txt"
#define MD_FN_TLSSNI01_CERT     "acme-tls-sni-01.cert.pem"
#define MD_FN_TLSSNI01_PKEY     "acme-tls-sni-01.key.pem"
#define MD_FN_AUTHZ             "authz.json"


md_acme_authz_t *md_acme_authz_create(apr_pool_t *p);

struct md_json_t *md_acme_authz_to_json(md_acme_authz_t *a, apr_pool_t *p);
md_acme_authz_t *md_acme_authz_from_json(struct md_json_t *json, apr_pool_t *p);

/* authz interaction with ACME server */
apr_status_t md_acme_authz_register(struct md_acme_authz_t **pauthz, struct md_acme_t *acme,
                                    struct md_store_t *store, const char *domain, apr_pool_t *p);

apr_status_t md_acme_authz_update(md_acme_authz_t *authz, struct md_acme_t *acme, 
                                  struct md_store_t *store, apr_pool_t *p);

apr_status_t md_acme_authz_respond(md_acme_authz_t *authz, struct md_acme_t *acme, 
                                   struct md_store_t *store, apr_array_header_t *challenges, 
                                   struct md_pkey_spec_t *key_spec, apr_pool_t *p);
apr_status_t md_acme_authz_del(md_acme_authz_t *authz, struct md_acme_t *acme, 
                               struct md_store_t *store, apr_pool_t *p);

/**************************************************************************************************/
/* set of authz data for a managed domain */

typedef struct md_acme_authz_set_t md_acme_authz_set_t;

struct md_acme_authz_set_t {
    struct apr_array_header_t *authzs;
};

md_acme_authz_set_t *md_acme_authz_set_create(apr_pool_t *p);
md_acme_authz_t *md_acme_authz_set_get(md_acme_authz_set_t *set, const char *domain);
apr_status_t md_acme_authz_set_add(md_acme_authz_set_t *set, md_acme_authz_t *authz);
apr_status_t md_acme_authz_set_remove(md_acme_authz_set_t *set, const char *domain);

struct md_json_t *md_acme_authz_set_to_json(md_acme_authz_set_t *set, apr_pool_t *p);
md_acme_authz_set_t *md_acme_authz_set_from_json(struct md_json_t *json, apr_pool_t *p);

apr_status_t md_acme_authz_set_load(struct md_store_t *store, md_store_group_t group, 
                                    const char *md_name, md_acme_authz_set_t **pauthz_set, 
                                    apr_pool_t *p);
apr_status_t md_acme_authz_set_save(struct md_store_t *store, apr_pool_t *p, 
                                    md_store_group_t group, const char *md_name, 
                                    md_acme_authz_set_t *authz_set, int create);

apr_status_t md_acme_authz_set_purge(struct md_store_t *store, md_store_group_t group,
                                     apr_pool_t *p, const char *md_name);

#endif /* md_acme_authz_h */
