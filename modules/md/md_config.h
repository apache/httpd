/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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

#ifndef mod_md_md_config_h
#define mod_md_md_config_h

struct md_store_t;

typedef enum {
    MD_CONFIG_CA_URL,
    MD_CONFIG_CA_PROTO,
    MD_CONFIG_BASE_DIR,
    MD_CONFIG_CA_AGREEMENT,
    MD_CONFIG_DRIVE_MODE,
    MD_CONFIG_LOCAL_80,
    MD_CONFIG_LOCAL_443,
    MD_CONFIG_RENEW_WINDOW,
} md_config_var_t;

typedef struct {
    const char *name;
    const server_rec *s;
    
    int local_80;
    int local_443;
    
    apr_array_header_t *mds;           /* array of md_t pointers */
    const char *ca_url;
    const char *ca_proto;
    const char *ca_agreement;
    apr_array_header_t *ca_challenges; /* challenge types allowed */
    
    int drive_mode;
    apr_interval_time_t renew_window;  /* time for renewal before expiry */
    
    const md_t *md;
    const char *base_dir;
    struct md_store_t *store;

} md_config_t;

typedef struct {
    md_t *md;
} md_config_dir_t;

void *md_config_create_svr(apr_pool_t *pool, server_rec *s);
void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);
void *md_config_create_dir(apr_pool_t *pool, char *dummy);
void *md_config_merge_dir(apr_pool_t *pool, void *basev, void *addv);

extern const command_rec md_cmds[];

/* Get the effective md configuration for the connection */
const md_config_t *md_config_cget(conn_rec *c);
/* Get the effective md configuration for the server */
const md_config_t *md_config_get(server_rec *s);
/* Get the effective md configuration for the server, but make it
 * unique to this server_rec, so that any changes only affect this server */
const md_config_t *md_config_get_unique(server_rec *s, apr_pool_t *p);

const char *md_config_gets(const md_config_t *config, md_config_var_t var);
int md_config_geti(const md_config_t *config, md_config_var_t var);
apr_interval_time_t md_config_get_interval(const md_config_t *config, md_config_var_t var);

#endif /* md_config_h */
