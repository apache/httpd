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

#ifndef mod_md_md_acme_acct_h
#define mod_md_md_acme_acct_h

struct md_acme_req;
struct md_json_t;
struct md_pkey_t;

#include "md_store.h"

/** 
 * An ACME account at an ACME server.
 */
typedef struct md_acme_acct_t md_acme_acct_t;

typedef enum {
    MD_ACME_ACCT_ST_UNKNOWN,
    MD_ACME_ACCT_ST_VALID,
    MD_ACME_ACCT_ST_DEACTIVATED,
    MD_ACME_ACCT_ST_REVOKED,
} md_acme_acct_st;

struct md_acme_acct_t {
    const char *id;                 /* short, unique id for the account */
    const char *url;                /* url of the account, once registered */
    const char *ca_url;             /* url of the ACME protocol endpoint */
    md_acme_acct_st status;         /* status of this account */
    apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */
    const char *tos_required;       /* terms of service asked for by CA */
    const char *agreement;          /* terms of service agreed to by user */
    const char *orders;             /* URL where certificate orders are found (ACMEv2) */
    const char *eab_kid;            /* external account binding keyid used or NULL */
    const char *eab_hmac;           /* external account binding hmac used or NULL */
    struct md_json_t *registration; /* data from server registration */
};

#define MD_FN_ACCOUNT           "account.json"
#define MD_FN_ACCT_KEY          "account.pem"

/* ACME account private keys are always RSA and have that many bits. Since accounts
 * are expected to live long, better err on the safe side. */
#define MD_ACME_ACCT_PKEY_BITS  3072

#define MD_ACME_ACCT_STAGED     "staged"

/**
 * Convert an ACME account form/to JSON.
 */
struct md_json_t *md_acme_acct_to_json(md_acme_acct_t *acct, apr_pool_t *p);
apr_status_t md_acme_acct_from_json(md_acme_acct_t **pacct, struct md_json_t *json, apr_pool_t *p);

/**
 * Update the account from the ACME server.
 * - Will update acme->acct structure from server on success
 * - Will return error status when request failed or account is not known.
 */
apr_status_t md_acme_acct_update(md_acme_t *acme);

/**
 * Update the account and persist changes in the store, if given (and not NULL).
 */
apr_status_t md_acme_acct_validate(md_acme_t *acme, md_store_t *store, apr_pool_t *p);

/**
 * Agree to the given Terms-of-Service url for the current account.
 */
apr_status_t md_acme_agree(md_acme_t *acme, apr_pool_t *p, const char *tos);

/**
 * Confirm with the server that the current account agrees to the Terms-of-Service
 * given in the agreement url.
 * If the known agreement is equal to this, nothing is done.
 * If it differs, the account is re-validated in the hope that the server
 * announces the Tos URL it wants. If this is equal to the agreement specified,
 * the server is notified of this. If the server requires a ToS that the account
 * thinks it has already given, it is resend.
 *
 * If an agreement is required, different from the current one, APR_INCOMPLETE is
 * returned and the agreement url is returned in the parameter.
 */
apr_status_t md_acme_check_agreement(md_acme_t *acme, apr_pool_t *p, 
                                     const char *agreement, const char **prequired);

/**
 * Get the ToS agreement for current account.
 */
const char *md_acme_get_agreement(md_acme_t *acme);


/** 
 * Find an existing account in the local store. On APR_SUCCESS, the acme
 * instance will have a current, validated account to use.
 */ 
apr_status_t md_acme_find_acct_for_md(md_acme_t *acme, md_store_t *store, const md_t *md);

/**
 * Find the account id for a given md.
 */
apr_status_t md_acme_acct_id_for_md(const char **pid, md_store_t *store,
                                    md_store_group_t group, const md_t *md, apr_pool_t *p);

/**
 * Create a new account at the ACME server for an MD. The
 * new account is the one used by the acme instance afterwards, on success.
 */
apr_status_t md_acme_acct_register(md_acme_t *acme, md_store_t *store, 
                                   const md_t *md, apr_pool_t *p);

apr_status_t md_acme_acct_save(md_store_t *store, apr_pool_t *p, md_acme_t *acme,  
                               const char **pid, struct md_acme_acct_t *acct, 
                               struct md_pkey_t *acct_key);
                               
/**
 * Deactivate the current account at the ACME server. 
 */
apr_status_t md_acme_acct_deactivate(md_acme_t *acme, apr_pool_t *p);

apr_status_t md_acme_acct_load(struct md_acme_acct_t **pacct, struct md_pkey_t **ppkey,
                               md_store_t *store, md_store_group_t group, 
                               const char *name, apr_pool_t *p);

/*
 * Return != 0 iff the account can be used for the ACME url.
 */
int md_acme_acct_matches_url(md_acme_acct_t *acct, const char *url);

/*
 * Return != 0 iff the account can be used for the MD, including
 * its CA url and EAB settings.
 */
int md_acme_acct_matches_md(md_acme_acct_t *acct, const md_t *md);

#endif /* md_acme_acct_h */
