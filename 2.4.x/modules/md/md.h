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

#ifndef mod_md_md_h
#define mod_md_md_h

#include "md_version.h"

struct apr_array_header_t;
struct apr_hash_t;
struct md_json_t;
struct md_cert_t;
struct md_pkey_t;
struct md_store_t;
struct md_srv_conf_t;
struct md_pkey_spec_t;

#define MD_TLSSNI01_DNS_SUFFIX     ".acme.invalid"

#define MD_PKEY_RSA_BITS_MIN       2048
#define MD_PKEY_RSA_BITS_DEF       2048

/* Minimum age for the HSTS header (RFC 6797), considered appropriate by Mozilla Security */
#define MD_HSTS_HEADER             "Strict-Transport-Security"
#define MD_HSTS_MAX_AGE_DEFAULT    15768000

typedef enum {
    MD_S_UNKNOWN,                   /* MD has not been analysed yet */
    MD_S_INCOMPLETE,                /* MD is missing necessary information, cannot go live */
    MD_S_COMPLETE,                  /* MD has all necessary information, can go live */
    MD_S_EXPIRED,                   /* MD is complete, but credentials have expired */
    MD_S_ERROR,                     /* MD data is flawed, unable to be processed as is */ 
    MD_S_MISSING,                   /* MD is missing config information, cannot proceed */
} md_state_t;

typedef enum {
    MD_REQUIRE_UNSET = -1,
    MD_REQUIRE_OFF,
    MD_REQUIRE_TEMPORARY,
    MD_REQUIRE_PERMANENT,
} md_require_t;

typedef enum {
    MD_SV_TEXT,
    MD_SV_JSON,
    MD_SV_CERT,
    MD_SV_PKEY,
    MD_SV_CHAIN,
} md_store_vtype_t;

typedef enum {
    MD_SG_NONE,
    MD_SG_ACCOUNTS,
    MD_SG_CHALLENGES,
    MD_SG_DOMAINS,
    MD_SG_STAGING,
    MD_SG_ARCHIVE,
    MD_SG_TMP,
    MD_SG_COUNT,
} md_store_group_t;

typedef enum {
    MD_DRIVE_DEFAULT = -1,          /* default value */
    MD_DRIVE_MANUAL,                /* manually triggered transmission of credentials */
    MD_DRIVE_AUTO,                  /* automatic process performed by httpd */
    MD_DRIVE_ALWAYS,                /* always driven by httpd, even if not used in any vhost */
} md_drive_mode_t;

typedef struct md_t md_t;
struct md_t {
    const char *name;               /* unique name of this MD */
    struct apr_array_header_t *domains; /* all DNS names this MD includes */
    struct apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */

    int transitive;                 /* != 0 iff VirtualHost names/aliases are auto-added */
    md_require_t require_https;     /* Iff https: is required for this MD */
    
    int drive_mode;                 /* mode of obtaining credentials */
    struct md_pkey_spec_t *pkey_spec;/* specification for generating new private keys */
    int must_staple;                /* certificates should set the OCSP Must Staple extension */
    apr_interval_time_t renew_norm; /* if > 0, normalized cert lifetime */
    apr_interval_time_t renew_window;/* time before expiration that starts renewal */
    
    const char *ca_url;             /* url of CA certificate service */
    const char *ca_proto;           /* protocol used vs CA (e.g. ACME) */
    const char *ca_account;         /* account used at CA */
    const char *ca_agreement;       /* accepted agreement uri between CA and user */ 
    struct apr_array_header_t *ca_challenges; /* challenge types configured for this MD */

    md_state_t state;               /* state of this MD */
    apr_time_t valid_from;          /* When the credentials start to be valid. 0 if unknown */
    apr_time_t expires;             /* When the credentials expire. 0 if unknown */
    const char *cert_url;           /* url where cert has been created, remember during drive */ 
    
    const struct md_srv_conf_t *sc; /* server config where it was defined or NULL */
    const char *defn_name;          /* config file this MD was defined */
    unsigned defn_line_number;      /* line number of definition */
};

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_AGREEMENT        "agreement"
#define MD_KEY_BITS             "bits"
#define MD_KEY_CA               "ca"
#define MD_KEY_CA_URL           "ca-url"
#define MD_KEY_CERT             "cert"
#define MD_KEY_CHALLENGES       "challenges"
#define MD_KEY_CONTACT          "contact"
#define MD_KEY_CONTACTS         "contacts"
#define MD_KEY_CSR              "csr"
#define MD_KEY_DETAIL           "detail"
#define MD_KEY_DISABLED         "disabled"
#define MD_KEY_DIR              "dir"
#define MD_KEY_DOMAIN           "domain"
#define MD_KEY_DOMAINS          "domains"
#define MD_KEY_DRIVE_MODE       "drive-mode"
#define MD_KEY_ERRORS           "errors"
#define MD_KEY_EXPIRES          "expires"
#define MD_KEY_HTTP             "http"
#define MD_KEY_HTTPS            "https"
#define MD_KEY_ID               "id"
#define MD_KEY_IDENTIFIER       "identifier"
#define MD_KEY_KEY              "key"
#define MD_KEY_KEYAUTHZ         "keyAuthorization"
#define MD_KEY_LOCATION         "location"
#define MD_KEY_MUST_STAPLE      "must-staple"
#define MD_KEY_NAME             "name"
#define MD_KEY_PERMANENT        "permanent"
#define MD_KEY_PKEY             "privkey"
#define MD_KEY_PROCESSED        "processed"
#define MD_KEY_PROTO            "proto"
#define MD_KEY_REGISTRATION     "registration"
#define MD_KEY_RENEW            "renew"
#define MD_KEY_RENEW_WINDOW     "renew-window"
#define MD_KEY_REQUIRE_HTTPS    "require-https"
#define MD_KEY_RESOURCE         "resource"
#define MD_KEY_STATE            "state"
#define MD_KEY_STATUS           "status"
#define MD_KEY_STORE            "store"
#define MD_KEY_TEMPORARY        "temporary"
#define MD_KEY_TOKEN            "token"
#define MD_KEY_TRANSITIVE       "transitive"
#define MD_KEY_TYPE             "type"
#define MD_KEY_URL              "url"
#define MD_KEY_URI              "uri"
#define MD_KEY_VALID_FROM       "validFrom"
#define MD_KEY_VALUE            "value"
#define MD_KEY_VERSION          "version"

#define MD_FN_MD                "md.json"
#define MD_FN_JOB               "job.json"
#define MD_FN_PRIVKEY           "privkey.pem"
#define MD_FN_PUBCERT           "pubcert.pem"
#define MD_FN_CERT              "cert.pem"
#define MD_FN_CHAIN             "chain.pem"
#define MD_FN_HTTPD_JSON        "httpd.json"

#define MD_FN_FALLBACK_PKEY     "fallback-privkey.pem"
#define MD_FN_FALLBACK_CERT     "fallback-cert.pem"

/* Check if a string member of a new MD (n) has 
 * a value and if it differs from the old MD o
 */
#define MD_VAL_UPDATE(n,o,s)    ((n)->s != (o)->s)
#define MD_SVAL_UPDATE(n,o,s)   ((n)->s && (!(o)->s || strcmp((n)->s, (o)->s)))

/**
 * Determine if the Managed Domain contains a specific domain name.
 */
int md_contains(const md_t *md, const char *domain, int case_sensitive);

/**
 * Determine if the names of the two managed domains overlap.
 */
int md_domains_overlap(const md_t *md1, const md_t *md2);

/**
 * Determine if the domain names are equal.
 */
int md_equal_domains(const md_t *md1, const md_t *md2, int case_sensitive);

/**
 * Determine if the domains in md1 contain all domains of md2.
 */
int md_contains_domains(const md_t *md1, const md_t *md2);

/**
 * Get one common domain name of the two managed domains or NULL.
 */
const char *md_common_name(const md_t *md1, const md_t *md2);

/**
 * Get the number of common domains.
 */
apr_size_t md_common_name_count(const md_t *md1, const md_t *md2);

/**
 * Look up a managed domain by its name.
 */
md_t *md_get_by_name(struct apr_array_header_t *mds, const char *name);

/**
 * Look up a managed domain by a DNS name it contains.
 */
md_t *md_get_by_domain(struct apr_array_header_t *mds, const char *domain);

/**
 * Find a managed domain, different from the given one, that has overlaps
 * in the domain list.
 */
md_t *md_get_by_dns_overlap(struct apr_array_header_t *mds, const md_t *md);

/**
 * Find the managed domain in the list that, for the given md, 
 * has the same name, or the most number of overlaps in domains
 */
md_t *md_find_closest_match(apr_array_header_t *mds, const md_t *md);

/**
 * Create and empty md record, structures initialized.
 */
md_t *md_create_empty(apr_pool_t *p);

/**
 * Create a managed domain, given a list of domain names.
 */
md_t *md_create(apr_pool_t *p, struct apr_array_header_t *domains);

/**
 * Deep copy an md record into another pool.
 */
md_t *md_clone(apr_pool_t *p, const md_t *src);

/**
 * Shallow copy an md record into another pool.
 */
md_t *md_copy(apr_pool_t *p, const md_t *src);

/**
 * Create a merged md with the settings of add overlaying the ones from base.
 */
md_t *md_merge(apr_pool_t *p, const md_t *add, const md_t *base);

/** 
 * Convert the managed domain into a JSON representation and vice versa. 
 *
 * This reads and writes the following information: name, domains, ca_url, ca_proto and state.
 */
struct md_json_t *md_to_json (const md_t *md, apr_pool_t *p);
md_t *md_from_json(struct md_json_t *json, apr_pool_t *p);

/**
 * Determine if MD should renew its cert (if it has one)
 */
int md_should_renew(const md_t *md);

/**************************************************************************************************/
/* domain credentials */

typedef struct md_creds_t md_creds_t;
struct md_creds_t {
    struct md_pkey_t *privkey;
    struct apr_array_header_t *pubcert;    /* complete md_cert* chain */
    struct md_cert_t *cert;
    int expired;
};

/* TODO: not sure this is a good idea, testing some readability and debuggabiltiy of
 * cascaded apr_status_t checks. */
#define MD_CHK_VARS                 const char *md_chk_
#define MD_LAST_CHK                 md_chk_
#define MD_CHK_STEP(c, status, s)   (md_chk_ = s, (void)md_chk_, status == (rv = (c)))
#define MD_CHK(c, status)           MD_CHK_STEP(c, status, #c)
#define MD_IS_ERR(c, err)           (md_chk_ = #c, APR_STATUS_IS_##err((rv = (c))))
#define MD_CHK_SUCCESS(c)           MD_CHK(c, APR_SUCCESS)
#define MD_OK(c)                    MD_CHK_SUCCESS(c)

#endif /* mod_md_md_h */
