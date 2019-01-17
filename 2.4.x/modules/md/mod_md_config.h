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

struct md_store_t;
struct md_reg_t;
struct md_pkey_spec_t;

typedef enum {
    MD_CONFIG_CA_URL,
    MD_CONFIG_CA_PROTO,
    MD_CONFIG_BASE_DIR,
    MD_CONFIG_CA_AGREEMENT,
    MD_CONFIG_DRIVE_MODE,
    MD_CONFIG_LOCAL_80,
    MD_CONFIG_LOCAL_443,
    MD_CONFIG_RENEW_NORM,
    MD_CONFIG_RENEW_WINDOW,
    MD_CONFIG_TRANSITIVE,
    MD_CONFIG_PROXY,
    MD_CONFIG_REQUIRE_HTTPS,
    MD_CONFIG_MUST_STAPLE,
    MD_CONFIG_NOTIFY_CMD,
} md_config_var_t;

typedef struct {
    apr_array_header_t *mds;           /* all md_t* defined in the config, shared */
    const char *base_dir;              /* base dir for store */
    const char *proxy_url;             /* proxy url to use (or NULL) */
    struct md_reg_t *reg;              /* md registry instance, singleton, shared */

    int local_80;                      /* On which port http:80 arrives */
    int local_443;                     /* On which port https:443 arrives */
    int can_http;                      /* Does someone listen to the local port 80 equivalent? */
    int can_https;                     /* Does someone listen to the local port 443 equivalent? */
    int manage_base_server;            /* If base server outside vhost may be managed */
    int hsts_max_age;                  /* max-age of HSTS (rfc6797) header */
    const char *hsts_header;           /* computed HTST header to use or NULL */
    apr_array_header_t *unused_names;  /* post config, names of all MDs not assigned to a vhost */

    const char *notify_cmd;            /* notification command to execute on signup/renew */
} md_mod_conf_t;

typedef struct md_srv_conf_t {
    const char *name;
    const server_rec *s;               /* server this config belongs to */
    md_mod_conf_t *mc;                 /* global config settings */
    
    int transitive;                    /* != 0 iff VirtualHost names/aliases are auto-added */
    md_require_t require_https;        /* If MDs require https: access */
    int drive_mode;                    /* mode of obtaining credentials */
    int must_staple;                   /* certificates should set the OCSP Must Staple extension */
    struct md_pkey_spec_t *pkey_spec;  /* specification for generating private keys */
    apr_interval_time_t renew_norm;    /* If > 0, use as normalizing value for cert lifetime
                                        * Example: renew_norm=90d renew_win=30d, cert lives
                                        * for 12 days => renewal 4 days before */
    apr_interval_time_t renew_window;  /* time before expiration that starts renewal */
    
    const char *ca_url;                /* url of CA certificate service */
    const char *ca_proto;              /* protocol used vs CA (e.g. ACME) */
    const char *ca_agreement;          /* accepted agreement uri between CA and user */ 
    struct apr_array_header_t *ca_challenges; /* challenge types configured */

    md_t *current;                     /* md currently defined in <MDomainSet xxx> section */
    md_t *assigned;                    /* post_config: MD that applies to this server or NULL */
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
apr_interval_time_t md_config_get_interval(const md_srv_conf_t *config, md_config_var_t var);

#endif /* md_config_h */
