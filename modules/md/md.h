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

#include <apr_time.h>

#include "md_time.h"
#include "md_version.h"

struct apr_array_header_t;
struct apr_hash_t;
struct md_json_t;
struct md_cert_t;
struct md_job_t;
struct md_pkey_t;
struct md_result_t;
struct md_store_t;
struct md_srv_conf_t;
struct md_pkey_spec_t;

#define MD_PKEY_RSA_BITS_MIN       2048
#define MD_PKEY_RSA_BITS_DEF       2048

/* Minimum age for the HSTS header (RFC 6797), considered appropriate by Mozilla Security */
#define MD_HSTS_HEADER             "Strict-Transport-Security"
#define MD_HSTS_MAX_AGE_DEFAULT    15768000

#define PROTO_ACME_TLS_1        "acme-tls/1"

#define MD_TIME_LIFE_NORM           (apr_time_from_sec(100 * MD_SECS_PER_DAY))
#define MD_TIME_RENEW_WINDOW_DEF    (apr_time_from_sec(33 * MD_SECS_PER_DAY))
#define MD_TIME_WARN_WINDOW_DEF     (apr_time_from_sec(10 * MD_SECS_PER_DAY))
#define MD_TIME_OCSP_KEEP_NORM      (apr_time_from_sec(7 * MD_SECS_PER_DAY))

#define MD_OTHER                "other"

typedef enum {
    MD_S_UNKNOWN = 0,               /* MD has not been analysed yet */
    MD_S_INCOMPLETE = 1,            /* MD is missing necessary information, cannot go live */
    MD_S_COMPLETE = 2,              /* MD has all necessary information, can go live */
    MD_S_EXPIRED_DEPRECATED = 3,    /* deprecated */
    MD_S_ERROR = 4,                 /* MD data is flawed, unable to be processed as is */ 
    MD_S_MISSING_INFORMATION = 5,     /* User has not agreed to ToS */
} md_state_t;

typedef enum {
    MD_REQUIRE_UNSET = -1,
    MD_REQUIRE_OFF,
    MD_REQUIRE_TEMPORARY,
    MD_REQUIRE_PERMANENT,
} md_require_t;

typedef enum {
    MD_RENEW_DEFAULT = -1,          /* default value */
    MD_RENEW_MANUAL,                /* manually triggered renewal of certificate */
    MD_RENEW_AUTO,                  /* automatic process performed by httpd */
    MD_RENEW_ALWAYS,                /* always renewed by httpd, even if not necessary */
} md_renew_mode_t;

typedef struct md_t md_t;
struct md_t {
    const char *name;               /* unique name of this MD */
    struct apr_array_header_t *domains; /* all DNS names this MD includes */
    struct apr_array_header_t *contacts;   /* list of contact uris, e.g. mailto:xxx */

    int transitive;                 /* != 0 iff VirtualHost names/aliases are auto-added */
    md_require_t require_https;     /* Iff https: is required for this MD */
    
    int renew_mode;                 /* mode of obtaining credentials */
    struct md_pkeys_spec_t *pks;    /* specification for generating private keys */
    int must_staple;                /* certificates should set the OCSP Must Staple extension */
    md_timeslice_t *renew_window;   /* time before expiration that starts renewal */
    md_timeslice_t *warn_window;    /* time before expiration that warnings are sent out */
    
    const char *ca_proto;           /* protocol used vs CA (e.g. ACME) */
    struct apr_array_header_t *ca_urls; /* urls of CAs */
    const char *ca_effective;       /* url of CA used */
    const char *ca_account;         /* account used at CA */
    const char *ca_agreement;       /* accepted agreement uri between CA and user */
    struct apr_array_header_t *ca_challenges; /* challenge types configured for this MD */
    struct apr_array_header_t *cert_files; /* != NULL iff pubcerts explicitly configured */
    struct apr_array_header_t *pkey_files; /* != NULL iff privkeys explicitly configured */
    const char *ca_eab_kid;         /* optional KEYID for external account binding */
    const char *ca_eab_hmac;        /* optional HMAC for external account binding */

    md_state_t state;               /* state of this MD */
    const char *state_descr;        /* description of state of NULL */
    
    struct apr_array_header_t *acme_tls_1_domains; /* domains supporting "acme-tls/1" protocol */
    int stapling;                   /* if OCSP stapling is enabled */
    const char *dns01_cmd;          /* DNS challenge command, override global command */

    int watched;               /* if certificate is supervised (renew or expiration warning) */
    const struct md_srv_conf_t *sc; /* server config where it was defined or NULL */
    const char *defn_name;          /* config file this MD was defined */
    unsigned defn_line_number;      /* line number of definition */
    
    const char *configured_name;    /* name this MD was configured with, if different */
};

#define MD_KEY_ACCOUNT          "account"
#define MD_KEY_ACME_TLS_1       "acme-tls/1"
#define MD_KEY_ACTIVATION_DELAY "activation-delay"
#define MD_KEY_ACTIVITY         "activity"
#define MD_KEY_AGREEMENT        "agreement"
#define MD_KEY_AUTHORIZATIONS   "authorizations"
#define MD_KEY_BITS             "bits"
#define MD_KEY_CA               "ca"
#define MD_KEY_CA_URL           "ca-url"
#define MD_KEY_CERT             "cert"
#define MD_KEY_CERT_FILES       "cert-files"
#define MD_KEY_CERTIFICATE      "certificate"
#define MD_KEY_CHALLENGE        "challenge"
#define MD_KEY_CHALLENGES       "challenges"
#define MD_KEY_CMD_DNS01        "cmd-dns-01"
#define MD_KEY_COMPLETE         "complete"
#define MD_KEY_CONTACT          "contact"
#define MD_KEY_CONTACTS         "contacts"
#define MD_KEY_CSR              "csr"
#define MD_KEY_CURVE            "curve"
#define MD_KEY_DETAIL           "detail"
#define MD_KEY_DISABLED         "disabled"
#define MD_KEY_DIR              "dir"
#define MD_KEY_DOMAIN           "domain"
#define MD_KEY_DOMAINS          "domains"
#define MD_KEY_EAB              "eab"
#define MD_KEY_EAB_REQUIRED     "externalAccountRequired"
#define MD_KEY_ENTRIES          "entries"
#define MD_KEY_ERRORED          "errored"
#define MD_KEY_ERROR            "error"
#define MD_KEY_ERRORS           "errors"
#define MD_KEY_EXPIRES          "expires"
#define MD_KEY_FINALIZE         "finalize"
#define MD_KEY_FINISHED         "finished"
#define MD_KEY_FROM             "from"
#define MD_KEY_GOOD             "good"
#define MD_KEY_HMAC             "hmac"
#define MD_KEY_HTTP             "http"
#define MD_KEY_HTTPS            "https"
#define MD_KEY_ID               "id"
#define MD_KEY_IDENTIFIER       "identifier"
#define MD_KEY_KEY              "key"
#define MD_KEY_KID              "kid"
#define MD_KEY_KEYAUTHZ         "keyAuthorization"
#define MD_KEY_LAST             "last"
#define MD_KEY_LAST_RUN         "last-run"
#define MD_KEY_LOCATION         "location"
#define MD_KEY_LOG              "log"
#define MD_KEY_MDS              "managed-domains"
#define MD_KEY_MESSAGE          "message"
#define MD_KEY_MUST_STAPLE      "must-staple"
#define MD_KEY_NAME             "name"
#define MD_KEY_NEXT_RUN         "next-run"
#define MD_KEY_NOTIFIED         "notified"
#define MD_KEY_NOTIFIED_RENEWED "notified-renewed"
#define MD_KEY_OCSP             "ocsp"
#define MD_KEY_OCSPS            "ocsps"
#define MD_KEY_ORDERS           "orders"
#define MD_KEY_PERMANENT        "permanent"
#define MD_KEY_PKEY             "privkey"
#define MD_KEY_PKEY_FILES       "pkey-files"
#define MD_KEY_PROBLEM          "problem"
#define MD_KEY_PROTO            "proto"
#define MD_KEY_READY            "ready"
#define MD_KEY_REGISTRATION     "registration"
#define MD_KEY_RENEW            "renew"
#define MD_KEY_RENEW_AT         "renew-at"
#define MD_KEY_RENEW_MODE       "renew-mode"
#define MD_KEY_RENEWAL          "renewal"
#define MD_KEY_RENEWING         "renewing"
#define MD_KEY_RENEW_WINDOW     "renew-window"
#define MD_KEY_REQUIRE_HTTPS    "require-https"
#define MD_KEY_RESOURCE         "resource"
#define MD_KEY_RESPONSE         "response"
#define MD_KEY_REVOKED          "revoked"
#define MD_KEY_SERIAL           "serial"
#define MD_KEY_SHA256_FINGERPRINT  "sha256-fingerprint"
#define MD_KEY_STAPLING         "stapling"
#define MD_KEY_STATE            "state"
#define MD_KEY_STATE_DESCR      "state-descr"
#define MD_KEY_STATUS           "status"
#define MD_KEY_STORE            "store"
#define MD_KEY_SUBPROBLEMS      "subproblems"
#define MD_KEY_TEMPORARY        "temporary"
#define MD_KEY_TOS              "termsOfService"
#define MD_KEY_TOKEN            "token"
#define MD_KEY_TOTAL            "total"
#define MD_KEY_TRANSITIVE       "transitive"
#define MD_KEY_TYPE             "type"
#define MD_KEY_UNKNOWN          "unknown"
#define MD_KEY_UNTIL            "until"
#define MD_KEY_URL              "url"
#define MD_KEY_URLS             "urls"
#define MD_KEY_URI              "uri"
#define MD_KEY_VALID            "valid"
#define MD_KEY_VALID_FROM       "valid-from"
#define MD_KEY_VALUE            "value"
#define MD_KEY_VERSION          "version"
#define MD_KEY_WATCHED          "watched"
#define MD_KEY_WHEN             "when"
#define MD_KEY_WARN_WINDOW      "warn-window"

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
 * Convert the managed domain into a JSON representation and vice versa. 
 *
 * This reads and writes the following information: name, domains, ca_url, ca_proto and state.
 */
struct md_json_t *md_to_json(const md_t *md, apr_pool_t *p);
md_t *md_from_json(struct md_json_t *json, apr_pool_t *p);

/**
 * Same as md_to_json(), but with sensitive fields stripped.
 */
struct md_json_t *md_to_public_json(const md_t *md, apr_pool_t *p);

int md_is_covered_by_alt_names(const md_t *md, const struct apr_array_header_t* alt_names);

/* how many certificates this domain has/will eventually have. */
int md_cert_count(const md_t *md);

const char *md_get_ca_name_from_url(apr_pool_t *p, const char *url);
apr_status_t md_get_ca_url_from_name(const char **purl, apr_pool_t *p, const char *name);

/**************************************************************************************************/
/* notifications */

typedef apr_status_t md_job_notify_cb(struct md_job_t *job, const char *reason, 
                                      struct md_result_t *result, apr_pool_t *p, void *baton);

/**************************************************************************************************/
/* domain credentials */

typedef struct md_pubcert_t md_pubcert_t;
struct md_pubcert_t {
    struct apr_array_header_t *certs;     /* chain of const md_cert*, leaf cert first */
    struct apr_array_header_t *alt_names; /* alt-names of leaf cert */
    const char *cert_file;                /* file path of chain */
    const char *key_file;                 /* file path of key for leaf cert */
};

#define MD_OK(c)                    (APR_SUCCESS == (rv = c))

#endif /* mod_md_md_h */
