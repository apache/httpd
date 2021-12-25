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
#ifndef tls_conf_h
#define tls_conf_h

/* Configuration flags */
#define TLS_FLAG_UNSET  (-1)
#define TLS_FLAG_FALSE  (0)
#define TLS_FLAG_TRUE   (1)

struct tls_proto_conf_t;
struct tls_cert_reg_t;
struct tls_cert_root_stores_t;
struct tls_cert_verifiers_t;
struct ap_socache_instance_t;
struct ap_socache_provider_t;
struct apr_global_mutex_t;


/* disabled, since rustls support is lacking
 * - x.509 retrieval of certificate fields and extensions
 * - certificate revocation lists (CRL)
 * - x.509 access to issuer of trust chain in x.509 CA store:
 *      server CA has ca1, ca2, ca3
 *      client present certA
 *      rustls verifies that it is signed by *one of* ca* certs
 *      OCSP check needs (certA, issuing cert) for query
 */
#define TLS_CLIENT_CERTS    0

/* support for this exists as PR <https://github.com/rustls/rustls-ffi/pull/128>
 */
#define TLS_MACHINE_CERTS    1


typedef enum {
    TLS_CLIENT_AUTH_UNSET,
    TLS_CLIENT_AUTH_NONE,
    TLS_CLIENT_AUTH_REQUIRED,
    TLS_CLIENT_AUTH_OPTIONAL,
} tls_client_auth_t;

typedef enum {
    TLS_CONF_ST_INIT,
    TLS_CONF_ST_INCOMING_DONE,
    TLS_CONF_ST_OUTGOING_DONE,
    TLS_CONF_ST_DONE,
} tls_conf_status_t;

/* The global module configuration, created after post-config
 * and then readonly.
 */
typedef struct {
    server_rec *ap_server;            /* the global server we initialized on */
    const char *module_version;
    const char *crustls_version;

    tls_conf_status_t status;
    int mod_proxy_post_config_done;   /* if mod_proxy did its post-config things */

    server_addr_rec *tls_addresses;   /* the addresses/ports our engine is enabled on */
    apr_array_header_t *proxy_configs; /* tls_conf_proxy_t* collected from everywhere */

    struct tls_proto_conf_t *proto;   /* TLS protocol/rustls specific globals */
    apr_hash_t *var_lookups;          /* variable lookup functions by var name */
    struct tls_cert_reg_t *cert_reg;  /* all certified keys loaded */
    struct tls_cert_root_stores_t *stores; /* loaded certificate stores */
    struct tls_cert_verifiers_t *verifiers; /* registry of certificate verifiers */

    const char *session_cache_spec;   /* how the session cache was specified */
    const struct ap_socache_provider_t *session_cache_provider; /* provider used for session cache */
    struct ap_socache_instance_t *session_cache; /* session cache instance */
    struct apr_global_mutex_t *session_cache_mutex; /* global mutex for access to session cache */

    const rustls_server_config *rustls_hello_config; /* used for initial client hello parsing */
} tls_conf_global_t;

/* The module configuration for a server (vhost).
 * Populated during config parsing, merged and completed
 * in the post config phase. Readonly after that.
 */
typedef struct {
    server_rec *server;               /* server this config belongs to */
    tls_conf_global_t *global;        /* global module config, singleton */

    int enabled;                      /* TLS_FLAG_TRUE if mod_tls is active on this server */
    apr_array_header_t *cert_specs;   /* array of (tls_cert_spec_t*) of configured certificates */
    int tls_protocol_min;             /* the minimum TLS protocol version to use */
    apr_array_header_t *tls_pref_ciphers;  /* List of apr_uint16_t cipher ids to prefer */
    apr_array_header_t *tls_supp_ciphers;  /* List of apr_uint16_t cipher ids to suppress */
    const apr_array_header_t *ciphersuites;  /* Computed post-config, ordered list of rustls cipher suites */
    int honor_client_order;           /* honor client cipher ordering */
    int strict_sni;

    const char *client_ca;            /* PEM file with trust anchors for client certs */
    tls_client_auth_t client_auth;    /* how client authentication with certificates is used */
    const char *var_user_name;        /* which SSL variable to use as user name */

    apr_array_header_t *certified_keys; /* rustls_certified_key list configured */
    int base_server;                  /* != 0 iff this is the base server */
    int service_unavailable;          /* TLS not trustworthy configured, return 503s */
} tls_conf_server_t;

typedef struct {
    server_rec *defined_in;           /* the server/host defining this dir_conf */
    tls_conf_global_t *global;        /* global module config, singleton */
    const char *proxy_ca;             /* PEM file with trust anchors for proxied remote server certs */
    int proxy_protocol_min;            /* the minimum TLS protocol version to use for proxy connections */
    apr_array_header_t *proxy_pref_ciphers;  /* List of apr_uint16_t cipher ids to prefer */
    apr_array_header_t *proxy_supp_ciphers;  /* List of apr_uint16_t cipher ids to suppress */
    apr_array_header_t *machine_cert_specs; /* configured machine certificates specs */
    apr_array_header_t *machine_certified_keys;  /* rustls_certified_key list */
    const rustls_client_config *rustls_config;
} tls_conf_proxy_t;

typedef struct {
    int std_env_vars;
    int export_cert_vars;
    int proxy_enabled;                /* TLS_FLAG_TRUE if mod_tls is active on outgoing connections */
    const char *proxy_ca;             /* PEM file with trust anchors for proxied remote server certs */
    int proxy_protocol_min;            /* the minimum TLS protocol version to use for proxy connections */
    apr_array_header_t *proxy_pref_ciphers;  /* List of apr_uint16_t cipher ids to prefer */
    apr_array_header_t *proxy_supp_ciphers;  /* List of apr_uint16_t cipher ids to suppress */
    apr_array_header_t *proxy_machine_cert_specs; /* configured machine certificates specs */

    tls_conf_proxy_t *proxy_config;
} tls_conf_dir_t;

/* our static registry of configuration directives. */
extern const command_rec tls_conf_cmds[];

/* create the modules configuration for a server_rec. */
void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s);

/* merge (inherit) server configurations for the module.
 * Settings in 'add' overwrite the ones in 'base' and unspecified
 * settings shine through. */
void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv);

/* create the modules configuration for a directory. */
void *tls_conf_create_dir(apr_pool_t *pool, char *dir);

/* merge (inherit) directory configurations for the module.
 * Settings in 'add' overwrite the ones in 'base' and unspecified
 * settings shine through. */
void *tls_conf_merge_dir(apr_pool_t *pool, void *basev, void *addv);


/* Get the server specific module configuration. */
tls_conf_server_t *tls_conf_server_get(server_rec *s);

/* Get the directory specific module configuration for the request. */
tls_conf_dir_t *tls_conf_dir_get(request_rec *r);

/* Get the directory specific module configuration for the server. */
tls_conf_dir_t *tls_conf_dir_server_get(server_rec *s);

/* If any configuration values are unset, supply the global server defaults. */
apr_status_t tls_conf_server_apply_defaults(tls_conf_server_t *sc, apr_pool_t *p);

/* If any configuration values are unset, supply the global dir defaults. */
apr_status_t tls_conf_dir_apply_defaults(tls_conf_dir_t *dc, apr_pool_t *p);

/* create a new proxy configuration from directory config in server */
tls_conf_proxy_t *tls_conf_proxy_make(
    apr_pool_t *p, tls_conf_dir_t *dc, tls_conf_global_t *gc, server_rec *s);

int tls_proxy_section_post_config(
    apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s,
    ap_conf_vector_t *section_config);

#endif /* tls_conf_h */
