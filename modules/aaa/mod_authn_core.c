/* Copyright 2002-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Security options etc.
 *
 * Module derived from code originally written by Rob McCool
 *
 */

#include "apr_strings.h"
#include "apr_network_io.h"
#define APR_WANT_STRFUNC
#define APR_WANT_BYTEFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#include "mod_auth.h"

#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* TODO List

- Track down all of the references to r->ap_auth_type
   and change them to ap_auth_type()
- Remove ap_auth_type and ap_auth_name from the 
   request_rec   

*/

typedef struct {
    char *ap_auth_type;
    char *ap_auth_name;
} authn_core_dir_conf;

module AP_MODULE_DECLARE_DATA authn_core_module;

static void *create_authn_core_dir_config(apr_pool_t *p, char *dummy)
{
    authn_core_dir_conf *conf =
            (authn_core_dir_conf *)apr_pcalloc(p, sizeof(authn_core_dir_conf));

    return (void *)conf;
}

static void *merge_authn_core_dir_config(apr_pool_t *a, void *basev, void *newv)
{
    authn_core_dir_conf *base = (authn_core_dir_conf *)basev;
    authn_core_dir_conf *new = (authn_core_dir_conf *)newv;
    authn_core_dir_conf *conf;

    /* Create this conf by duplicating the base, replacing elements
    * (or creating copies for merging) where new-> values exist.
    */
    conf = (authn_core_dir_conf *)apr_palloc(a, sizeof(authn_core_dir_conf));
    memcpy(conf, base, sizeof(authn_core_dir_conf));

    if (new->ap_auth_type) {
        conf->ap_auth_type = new->ap_auth_type;
    }

    if (new->ap_auth_name) {
        conf->ap_auth_name = new->ap_auth_name;
    }

    return (void*)conf;
}

/*
 * Load an authorisation realm into our location configuration, applying the
 * usual rules that apply to realms.
 */
static const char *set_authname(cmd_parms *cmd, void *mconfig,
                                const char *word1)
{
    authn_core_dir_conf *aconfig = (authn_core_dir_conf *)mconfig;

    aconfig->ap_auth_name = ap_escape_quotes(cmd->pool, word1);
    return NULL;
}


static const char *authn_ap_auth_type(request_rec *r)
{
    authn_core_dir_conf *conf;

    conf = (authn_core_dir_conf *)ap_get_module_config(r->per_dir_config,
        &authn_core_module);

    return apr_pstrdup(r->pool, conf->ap_auth_type);
}

static const char *authn_ap_auth_name(request_rec *r)
{
    authn_core_dir_conf *conf;

    conf = (authn_core_dir_conf *)ap_get_module_config(r->per_dir_config,
        &authn_core_module);

    return apr_pstrdup(r->pool, conf->ap_auth_name);
}

static const command_rec authn_cmds[] =
{
    AP_INIT_TAKE1("AuthType", ap_set_string_slot,
                  (void*)APR_OFFSETOF(authn_core_dir_conf, ap_auth_type), OR_AUTHCFG,
                  "An HTTP authorization type (e.g., \"Basic\")"),
    AP_INIT_TAKE1("AuthName", set_authname, NULL, OR_AUTHCFG,
                  "The authentication realm (e.g. \"Members Only\")"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    APR_REGISTER_OPTIONAL_FN(authn_ap_auth_type);
    APR_REGISTER_OPTIONAL_FN(authn_ap_auth_name);
}

module AP_MODULE_DECLARE_DATA authn_core_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_core_dir_config,        /* dir config creater */
    merge_authn_core_dir_config,         /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    authn_cmds,
    register_hooks                  /* register hooks */
};
