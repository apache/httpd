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

#ifndef mod_md_md_config_h
#define mod_md_md_config_h

struct apr_hash_t;
struct md_store_t;
struct md_reg_t;
struct md_ocsp_reg_t;
struct md_pkeys_spec_t;

typedef enum {
    MD_CONFIG_CA_CONTACT,
    MD_CONFIG_CA_PROTO,
    MD_CONFIG_BASE_DIR,
    MD_CONFIG_CA_AGREEMENT,
    MD_CONFIG_DRIVE_MODE,
    MD_CONFIG_RENEW_WINDOW,
    MD_CONFIG_WARN_WINDOW,
    MD_CONFIG_TRANSITIVE,
    MD_CONFIG_PROXY,
    MD_CONFIG_REQUIRE_HTTPS,
    MD_CONFIG_MUST_STAPLE,
    MD_CONFIG_NOTIFY_CMD,
    MD_CONFIG_MESSGE_CMD,
    MD_CONFIG_STAPLING,
    MD_CONFIG_STAPLE_OTHERS,
} md_config_var_t;

typedef struct md_mod_conf_t md_mod_conf_t;
struct md_mod_conf_t {
    apr_array_header_t *mds;           /* all md_t* defined in the config, shared */
    const char *base_dir;              /* base dir for store */
    const char *proxy_url;             /* proxy url to use (or NULL) */
    struct md_reg_t *reg;              /* md registry instance */
    struct md_ocsp_reg_t *ocsp;        /* ocsp status registry */

    int local_80;                      /* On which port http:80 arrives */
    int local_443;                     /* On which port https:443 arrives */
    int can_http;                      /* Does someone listen to the local port 80 equivalent? */
    int can_https;                     /* Does someone listen to the local port 443 equivalent? */
    int manage_base_server;            /* If base server outside vhost may be managed */
    int hsts_max_age;                  /* max-age of HSTS (rfc6797) header */
    const char *hsts_header;           /* computed HTST header to use or NULL */
    apr_array_header_t *unused_names;  /* post config, names of all MDs not assigned to a vhost */
    struct apr_hash_t *init_errors;    /* init errors reported with MD name as key */

    const char *notify_cmd;            /* notification command to execute on signup/renew */
    const char *message_cmd;           /* message command to execute on signup/renew/warnings */
    struct apr_table_t *env;           /* environment for operation */
    int dry_run;                       /* != 0 iff config dry run */
    int server_status_enabled;         /* if module should add to server-status handler */
    int certificate_status_enabled;    /* if module should expose /.httpd/certificate-status */
    md_timeslice_t *ocsp_keep_window;  /* time that we keep ocsp responses around */
    md_timeslice_t *ocsp_renew_window; /* time before exp. that we start renewing ocsp resp. */
    const char *cert_check_name;       /* name of the linked certificate check site */
    const char *cert_check_url;        /* url "template for" checking a certificate */
    const char *ca_certs;              /* root certificates to use for connections */
    apr_time_t min_delay;              /* minimum delay for retries */
    int retry_failover;                /* number of errors to trigger CA failover */
    int use_store_locks;               /* use locks when updating store */
    apr_time_t lock_wait_timeout;      /* fail after this time when unable to obtain lock */
};

typedef struct md_srv_conf_t {
    const char *name;
    const server_rec *s;               /* server this config belongs to */
    md_mod_conf_t *mc;                 /* global config settings */
    
    int transitive;                    /* != 0 iff VirtualHost names/aliases are auto-added */
    md_require_t require_https;        /* If MDs require https: access */
    int renew_mode;                    /* mode of obtaining credentials */
    int must_staple;                   /* certificates should set the OCSP Must Staple extension */
    struct md_pkeys_spec_t *pks;       /* specification for private keys */
    md_timeslice_t *renew_window;      /* time before expiration that starts renewal */
    md_timeslice_t *warn_window;       /* time before expiration that warning are sent out */
    
    struct apr_array_header_t *ca_urls; /* urls of CAs */
    const char *ca_contact;            /* contact email registered to account */
    const char *ca_proto;              /* protocol used vs CA (e.g. ACME) */
    const char *ca_agreement;          /* accepted agreement uri between CA and user */ 
    struct apr_array_header_t *ca_challenges; /* challenge types configured */
    const char *ca_eab_kid;            /* != NULL, external account binding keyid */
    const char *ca_eab_hmac;           /* != NULL, external account binding hmac */

    int stapling;                      /* OCSP stapling enabled */
    int staple_others;                 /* Provide OCSP stapling for non-MD certificates */

    const char *dns01_cmd;             /* DNS challenge command, override global command */

    md_t *current;                     /* md currently defined in <MDomainSet xxx> section */
    struct apr_array_header_t *assigned; /* post_config: MDs that apply to this server */
    int is_ssl;                        /* SSLEngine is enabled here */
} md_srv_conf_t;

void *md_config_create_svr(apr_pool_t *pool, server_rec *s);
void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);

extern const command_rec md_cmds[];

apr_status_t md_config_post_config(server_rec *s, apr_pool_t *p);

/* Get the effective md configuration for the connection */
md_srv_conf_t *md_config_cget(conn_rec *c);
/* Get the effective md configuration for the server */
md_srv_conf_t *md_config_get(server_rec *s);
/* Get the effective md configuration for the server, but make it
 * unique to this server_rec, so that any changes only affect this server */
md_srv_conf_t *md_config_get_unique(server_rec *s, apr_pool_t *p);

const char *md_config_gets(const md_srv_conf_t *config, md_config_var_t var);
int md_config_geti(const md_srv_conf_t *config, md_config_var_t var);

void md_config_get_timespan(md_timeslice_t **pspan, const md_srv_conf_t *sc, md_config_var_t var);

const md_t *md_get_for_domain(server_rec *s, const char *domain);

#endif /* md_config_h */
