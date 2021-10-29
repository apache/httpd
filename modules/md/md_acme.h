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

#ifndef mod_md_md_acme_h
#define mod_md_md_acme_h

struct apr_array_header_t;
struct apr_bucket_brigade;
struct md_http_response_t;
struct apr_hash_t;
struct md_http_t;
struct md_json_t;
struct md_pkey_t;
struct md_t;
struct md_acme_acct_t;
struct md_acmev2_acct_t;
struct md_store_t;
struct md_result_t;

#define MD_PROTO_ACME               "ACME"

#define MD_AUTHZ_CHA_HTTP_01        "http-01"
#define MD_AUTHZ_CHA_SNI_01         "tls-sni-01"

#define MD_ACME_VERSION_UNKNOWN    0x0
#define MD_ACME_VERSION_1          0x010000
#define MD_ACME_VERSION_2          0x020000

#define MD_ACME_VERSION_MAJOR(i)    (((i)&0xFF0000) >> 16)

typedef enum {
    MD_ACME_S_UNKNOWN,              /* MD has not been analysed yet */
    MD_ACME_S_REGISTERED,           /* MD is registered at CA, but not more */
    MD_ACME_S_TOS_ACCEPTED,         /* Terms of Service were accepted by account holder */
    MD_ACME_S_CHALLENGED,           /* MD challenge information for all domains is known */
    MD_ACME_S_VALIDATED,            /* MD domains have been validated */
    MD_ACME_S_CERTIFIED,            /* MD has valid certificate */
    MD_ACME_S_DENIED,               /* MD domains (at least one) have been denied by CA */
} md_acme_state_t;

typedef struct md_acme_t md_acme_t;

typedef struct md_acme_req_t md_acme_req_t;
/**
 * Request callback on a successful HTTP response (status 2xx).
 */
typedef apr_status_t md_acme_req_res_cb(md_acme_t *acme, 
                                        const struct md_http_response_t *res, void *baton);

/**
 * Request callback to initialize before sending. May be invoked more than once in
 * case of retries.
 */
typedef apr_status_t md_acme_req_init_cb(md_acme_req_t *req, void *baton);

/**
 * Request callback on a successful response (HTTP response code 2xx) and content
 * type matching application/.*json.
 */
typedef apr_status_t md_acme_req_json_cb(md_acme_t *acme, apr_pool_t *p, 
                                         const apr_table_t *headers, 
                                         struct md_json_t *jbody, void *baton);

/**
 * Request callback on detected errors.
 */
typedef apr_status_t md_acme_req_err_cb(md_acme_req_t *req, 
                                        const struct md_result_t *result, void *baton);


typedef apr_status_t md_acme_new_nonce_fn(md_acme_t *acme);
typedef apr_status_t md_acme_req_init_fn(md_acme_req_t *req, struct md_json_t *jpayload);

typedef apr_status_t md_acme_post_fn(md_acme_t *acme, 
                                     md_acme_req_init_cb *on_init,
                                     md_acme_req_json_cb *on_json,
                                     md_acme_req_res_cb *on_res,
                                     md_acme_req_err_cb *on_err,
                                     void *baton);

struct md_acme_t {
    const char *url;                /* directory url of the ACME service */
    const char *sname;              /* short name for the service, not necessarily unique */
    apr_pool_t *p;
    const char *user_agent;
    const char *proxy_url;
    const char *ca_file;
    
    const char *acct_id;            /* local storage id account was loaded from or NULL */
    struct md_acme_acct_t *acct;    /* account at ACME server to use for requests */
    struct md_pkey_t *acct_key;     /* private RSA key belonging to account */
    
    int version;                    /* as detected from the server */
    union {
        struct { /* obsolete */
            const char *new_authz;
            const char *new_cert;
            const char *new_reg;
            const char *revoke_cert;
            
        } v1;
        struct {
            const char *new_account;
            const char *new_order;
            const char *key_change;
            const char *revoke_cert;
            const char *new_nonce;
        } v2;
    } api;
    const char *ca_agreement;
    const char *acct_name;
    int eab_required;
    
    md_acme_new_nonce_fn *new_nonce_fn;
    md_acme_req_init_fn *req_init_fn;
    md_acme_post_fn *post_new_account_fn;
    
    struct md_http_t *http;
    
    const char *nonce;
    int max_retries;
    struct md_result_t *last;      /* result of last request */
};

/**
 * Global init, call once at start up.
 */
apr_status_t md_acme_init(apr_pool_t *pool, const char *base_version, int init_ssl);

/**
 * Create a new ACME server instance. If path is not NULL, will use that directory
 * for persisting information. Will load any information persisted in earlier session.
 * url needs only be specified for instances where this has never been persisted before.
 *
 * @param pacme   will hold the ACME server instance on success
 * @param p       pool to used
 * @param url     url of the server, optional if known at path
 * @param proxy_url optional url of a HTTP(S) proxy to use
 */
apr_status_t md_acme_create(md_acme_t **pacme, apr_pool_t *p, const char *url,
                            const char *proxy_url, const char *ca_file);

/**
 * Contact the ACME server and retrieve its directory information.
 * 
 * @param acme    the ACME server to contact
 */
apr_status_t md_acme_setup(md_acme_t *acme, struct md_result_t *result);

void md_acme_report_result(md_acme_t *acme, apr_status_t rv, struct md_result_t *result);

/**************************************************************************************************/
/* account handling */

/**
 * Clear any existing account data from acme instance.
 */
void md_acme_clear_acct(md_acme_t *acme);

apr_status_t md_acme_POST_new_account(md_acme_t *acme, 
                                      md_acme_req_init_cb *on_init,
                                      md_acme_req_json_cb *on_json,
                                      md_acme_req_res_cb *on_res,
                                      md_acme_req_err_cb *on_err,
                                      void *baton);

/**
 * Get the local name of the account currently used by the acme instance.
 * Will be NULL if no account has been setup successfully.
 */
const char *md_acme_acct_id_get(md_acme_t *acme);
const char *md_acme_acct_url_get(md_acme_t *acme);

/** 
 * Specify the account to use by name in local store. On success, the account
 * is the "current" one used by the acme instance.
 * @param acme the acme instance to set the account for
 * @param store the store to load accounts from
 * @param p pool for allocations
 * @param acct_id name of the account to load
 */
apr_status_t md_acme_use_acct(md_acme_t *acme, struct md_store_t *store, 
                              apr_pool_t *p, const char *acct_id);

/**
 * Specify the account to use for a specific MD by name in local store.
 * On success, the account is the "current" one used by the acme instance.
 * @param acme the acme instance to set the account for
 * @param store the store to load accounts from
 * @param p pool for allocations
 * @param acct_id name of the account to load
 * @param md the MD the account shall be used for
 */
apr_status_t md_acme_use_acct_for_md(md_acme_t *acme, struct md_store_t *store,
                                     apr_pool_t *p, const char *acct_id,
                                     const md_t *md);

/**
 * Get the local name of the account currently used by the acme instance.
 * Will be NULL if no account has been setup successfully.
 */
const char *md_acme_acct_id_get(md_acme_t *acme);

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

apr_status_t md_acme_save_acct(md_acme_t *acme, apr_pool_t *p, struct md_store_t *store);
                               
/**
 * Deactivate the current account at the ACME server.. 
 */
apr_status_t md_acme_acct_deactivate(md_acme_t *acme, apr_pool_t *p);

/**************************************************************************************************/
/* request handling */

struct md_acme_req_t {
    md_acme_t *acme;               /* the ACME server to talk to */
    apr_pool_t *p;                 /* pool for the request duration */
    
    const char *url;               /* url to POST the request to */
    const char *method;            /* HTTP method to use */
    struct md_json_t *prot_fields; /* JWS protected fields */
    struct md_json_t *req_json;    /* JSON to be POSTed in request body */

    apr_table_t *resp_hdrs;        /* HTTP response headers */
    struct md_json_t *resp_json;   /* JSON response body received */
    
    apr_status_t rv;               /* status of request */
    
    md_acme_req_init_cb *on_init;  /* callback to initialize the request before submit */
    md_acme_req_json_cb *on_json;  /* callback on successful JSON response */
    md_acme_req_res_cb *on_res;    /* callback on generic HTTP response */
    md_acme_req_err_cb *on_err;    /* callback on encountered error */
    int max_retries;               /* how often this might be retried */
    void *baton;                   /* userdata for callbacks */
    struct md_result_t *result;    /* result of this request */
};

apr_status_t md_acme_req_body_init(md_acme_req_t *req, struct md_json_t *payload);

apr_status_t md_acme_GET(md_acme_t *acme, const char *url,
                         md_acme_req_init_cb *on_init,
                         md_acme_req_json_cb *on_json,
                         md_acme_req_res_cb *on_res,
                         md_acme_req_err_cb *on_err,
                         void *baton);
/**
 * Perform a POST against the ACME url. If a on_json callback is given and
 * the HTTP response is JSON, only this callback is invoked. Otherwise, on HTTP status
 * 2xx, the on_res callback is invoked. If no on_res is given, it is considered a
 * response error, since only JSON was expected.
 * At least one callback needs to be non-NULL.
 * 
 * @param acme        the ACME server to talk to
 * @param url         the url to send the request to
 * @param on_init     callback to initialize the request data
 * @param on_json     callback on successful JSON response
 * @param on_res      callback on successful HTTP response
 * @param baton       userdata for callbacks
 */
apr_status_t md_acme_POST(md_acme_t *acme, const char *url,
                          md_acme_req_init_cb *on_init,
                          md_acme_req_json_cb *on_json,
                          md_acme_req_res_cb *on_res,
                          md_acme_req_err_cb *on_err,
                          void *baton);

/**
 * Retrieve a JSON resource from the ACME server 
 */
apr_status_t md_acme_get_json(struct md_json_t **pjson, md_acme_t *acme, 
                              const char *url, apr_pool_t *p);


apr_status_t md_acme_req_body_init(md_acme_req_t *req, struct md_json_t *jpayload);

apr_status_t md_acme_protos_add(struct apr_hash_t *protos, apr_pool_t *p);

/**
 * Return != 0 iff the given problem identifier is an ACME error string
 * indicating something is wrong with the input values, e.g. from our
 * configuration.
 */
int md_acme_problem_is_input_related(const char *problem);

#endif /* md_acme_h */
