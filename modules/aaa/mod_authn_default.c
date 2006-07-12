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

#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

typedef struct {
    int authoritative;
} authn_default_config_rec;

static void *create_authn_default_dir_config(apr_pool_t *p, char *d)
{
    authn_default_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const command_rec authn_default_cmds[] =
{
    AP_INIT_FLAG("AuthDefaultAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_default_config_rec,
                                      authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the UserID is not known to this module. "
                         "(default is On)."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_default_module;

static int authenticate_no_user(request_rec *r)
{
    authn_default_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_default_module);

    const char *type;

    if (!(type = ap_auth_type(r))) {
        return DECLINED;
    }

    /* fill in the r->user field */
    if (!strcasecmp(type, "Basic")) {
        const char *sent_pw;
        int res;

        if ((res = ap_get_basic_auth_pw(r, &sent_pw)) != OK) {
            return res;
        }
    }

    if (conf->authoritative == 0) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "access to %s failed, reason: verification of user id '%s' "
                  "not configured",
                  r->uri, r->user ? r->user : "<null>");

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(authenticate_no_user,NULL,NULL,APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA authn_default_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_default_dir_config,/* dir config creater */
    NULL,                           /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    authn_default_cmds,             /* command apr_table_t */
    register_hooks                  /* register hooks */
};
