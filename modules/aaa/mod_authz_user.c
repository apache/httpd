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

#include "apr_strings.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

typedef struct {
	int dummy;  /* just here to stop compiler warnings for now. */
} authz_user_config_rec;

static void *create_authz_user_dir_config(apr_pool_t *p, char *d)
{
    authz_user_config_rec *conf = apr_palloc(p, sizeof(*conf));

    return conf;
}

static const command_rec authz_user_cmds[] =
{
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_user_module;

static authz_status user_check_authorization(request_rec *r,
                                             const char *require_args)
{
    const char *t, *w;

    t = require_args;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (!strcmp(r->user, w)) {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s failed, reason: user '%s' does not meet "
                  "'require'ments for user to be allowed access",
                  r->uri, r->user);

    ap_note_auth_failure(r);
    return AUTHZ_DENIED;
}

static authz_status validuser_check_authorization(request_rec *r, const char *require_line)
{
    return AUTHZ_GRANTED;
}

static const authz_provider authz_user_provider =
{
    &user_check_authorization,
};
static const authz_provider authz_validuser_provider =
{
    &validuser_check_authorization,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHZ_PROVIDER_GROUP, "user", "0",
                         &authz_user_provider);
    ap_register_provider(p, AUTHZ_PROVIDER_GROUP, "valid-user", "0",
                         &authz_validuser_provider);
}

module AP_MODULE_DECLARE_DATA authz_user_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_user_dir_config, /* dir config creater */
    NULL,                         /* dir merger --- default is to override */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    authz_user_cmds,              /* command apr_table_t */
    register_hooks                /* register hooks */
};
