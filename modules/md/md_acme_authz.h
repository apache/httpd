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
struct apr_table_t;
struct md_acme_t;
struct md_acme_acct_t;
struct md_json_t;
struct md_store_t;
struct md_pkey_spec_t;
struct md_result_t;

typedef struct md_acme_challenge_t md_acme_challenge_t;

/**************************************************************************************************/
/* authorization request for a specific domain name */

#define MD_AUTHZ_TYPE_DNS01         "dns-01"
#define MD_AUTHZ_TYPE_HTTP01        "http-01"
#define MD_AUTHZ_TYPE_TLSALPN01     "tls-alpn-01"

typedef enum {
    MD_ACME_AUTHZ_S_UNKNOWN,
    MD_ACME_AUTHZ_S_PENDING,
    MD_ACME_AUTHZ_S_VALID,
    MD_ACME_AUTHZ_S_INVALID,
} md_acme_authz_state_t;

typedef struct md_acme_authz_t md_acme_authz_t;

struct md_acme_authz_t {
    const char *domain;
    const char *url;
    md_acme_authz_state_t state;
    apr_time_t expires;
    const char *error_type;
    const char *error_detail;
    const struct md_json_t *error_subproblems;
    struct md_json_t *resource;
};

#define MD_FN_HTTP01            "acme-http-01.txt"

void tls_alpn01_fnames(apr_pool_t *p, struct md_pkey_spec_t *kspec, char **keyfn, char **certfn );

md_acme_authz_t *md_acme_authz_create(apr_pool_t *p);

apr_status_t md_acme_authz_retrieve(md_acme_t *acme, apr_pool_t *p, const char *url,
                                    md_acme_authz_t **pauthz);
apr_status_t md_acme_authz_update(md_acme_authz_t *authz, struct md_acme_t *acme, apr_pool_t *p);

apr_status_t md_acme_authz_respond(md_acme_authz_t *authz, struct md_acme_t *acme, 
                                   struct md_store_t *store, apr_array_header_t *challenges, 
                                   struct md_pkeys_spec_t *key_spec,
                                   apr_array_header_t *acme_tls_1_domains, const md_t *md,
                                   struct apr_table_t *env,
                                   apr_pool_t *p, const char **setup_token,
                                   struct md_result_t *result);

apr_status_t md_acme_authz_teardown(struct md_store_t *store, const char *setup_token, 
                                    const md_t *md, struct apr_table_t *env, apr_pool_t *p);

#endif /* md_acme_authz_h */
