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

/* This module is triggered by an
 *
 *          AuthGroupFile standard /path/to/file
 *
 * and the presense of a
 *
 *         require group <list-of-groups>
 *
 * In an applicable limit/directory block for that method.
 *
 * If there are no AuthGroupFile directives valid for
 * the request; we DECLINED.
 *
 * If the AuthGroupFile is defined; but somehow not
 * accessible: we SERVER_ERROR (was DECLINED).
 *
 * If there are no 'require ' directives defined for
 * this request then we DECLINED (was OK).
 *
 * If there are no 'require ' directives valid for
 * this request method then we DECLINED. (was OK)
 *
 * If there are any 'require group' blocks and we
 * are not in any group - we HTTP_UNAUTHORIZE
 *
 */

#include "apr_strings.h"
#include "apr_lib.h" /* apr_isspace */

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
    char *groupfile;
} authz_groupfile_config_rec;

APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_group, (request_rec *r));

static void *create_authz_groupfile_dir_config(apr_pool_t *p, char *d)
{
    authz_groupfile_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->groupfile = NULL;
    return conf;
}

static const char *set_authz_groupfile_slot(cmd_parms *cmd, void *offset, const char *f,
                                 const char *t)
{
    if (t && strcmp(t, "standard")) {
        return apr_pstrcat(cmd->pool, "Invalid auth file type: ", t, NULL);
    }

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec authz_groupfile_cmds[] =
{
    AP_INIT_TAKE12("AuthGroupFile", set_authz_groupfile_slot,
                   (void *)APR_OFFSETOF(authz_groupfile_config_rec, groupfile),
                   OR_AUTHCFG,
                   "text file containing group names and member user IDs"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_groupfile_module;

static apr_status_t groups_for_user(apr_pool_t *p, char *user, char *grpfile,
                                    apr_table_t ** out)
{
    ap_configfile_t *f;
    apr_table_t *grps = apr_table_make(p, 15);
    apr_pool_t *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;
    apr_status_t status;
    apr_size_t group_len;

    if ((status = ap_pcfg_openfile(&f, p, grpfile)) != APR_SUCCESS) {
        return status ;
    }

    apr_pool_create(&sp, p);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }
        ll = l;
        apr_pool_clear(sp);

        group_name = ap_getword(sp, &ll, ':');
        group_len = strlen(group_name);

        while (group_len && apr_isspace(*(group_name + group_len - 1))) {
            --group_len;
        }

        while (ll[0]) {
            w = ap_getword_conf(sp, &ll);
            if (!strcmp(w, user)) {
                apr_table_setn(grps, apr_pstrmemdup(p, group_name, group_len),
                               "in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);

    *out = grps;
    return APR_SUCCESS;
}

static authz_status group_check_authorization(request_rec *r,
                                             const char *require_args)
{
    authz_groupfile_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &authz_groupfile_module);
    char *user = r->user;
    const char *t, *w;
    apr_table_t *grpstatus = NULL;
    apr_status_t status;

    if (!user) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "access to %s failed, reason: no authenticated user", r->uri);
        return AUTHZ_DENIED;
    }

    /* If there is no group file - then we are not
     * configured. So decline.
     */
    if (!(conf->groupfile)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "No group file was specified in the configuration");
        return AUTHZ_DENIED;
    }

    status = groups_for_user(r->pool, user, conf->groupfile,
                                &grpstatus);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                        "Could not open group file: %s",
                        conf->groupfile);
        return AUTHZ_DENIED;
    }

    if (apr_table_elts(grpstatus)->nelts == 0) {
        /* no groups available, so exit immediately */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Authorization of user %s to access %s failed, reason: "
                      "user doesn't appear in group file (%s).",
                      r->user, r->uri, conf->groupfile);
        return AUTHZ_DENIED;
    }

    t = require_args;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (apr_table_get(grpstatus, w)) {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Authorization of user %s to access %s failed, reason: "
                    "user is not part of the 'require'ed group(s).",
                    r->user, r->uri);

    return AUTHZ_DENIED;
}

APR_OPTIONAL_FN_TYPE(authz_owner_get_file_group) *authz_owner_get_file_group;

static authz_status filegroup_check_authorization(request_rec *r,
                                              const char *require_args)
{
    authz_groupfile_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &authz_groupfile_module);
    char *user = r->user;
    apr_table_t *grpstatus = NULL;
    apr_status_t status;
    const char *filegroup = NULL;

    if (!user) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "access to %s failed, reason: no authenticated user", r->uri);
        return AUTHZ_DENIED;
    }

    /* If there is no group file - then we are not
     * configured. So decline.
     */
    if (!(conf->groupfile)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "No group file was specified in the configuration");
        return AUTHZ_DENIED;
    }

    status = groups_for_user(r->pool, user, conf->groupfile,
                             &grpstatus);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "Could not open group file: %s",
                      conf->groupfile);
        return AUTHZ_DENIED;
    }

    if (apr_table_elts(grpstatus)->nelts == 0) {
        /* no groups available, so exit immediately */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Authorization of user %s to access %s failed, reason: "
                        "user doesn't appear in group file (%s).",
                        r->user, r->uri, conf->groupfile);
        return AUTHZ_DENIED;
    }

    filegroup = authz_owner_get_file_group(r);

    if (filegroup) {
        if (apr_table_get(grpstatus, filegroup)) {
            return AUTHZ_GRANTED;
        }
    }
    else {
        /* No need to emit a error log entry because the call
        to authz_owner_get_file_group already did it
        for us.
        */
        return AUTHZ_DENIED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "Authorization of user %s to access %s failed, reason: "
                  "user is not part of the 'require'ed file group.",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static const authz_provider authz_group_provider =
{
    &group_check_authorization,
};

static const authz_provider authz_filegroup_provider =
{
    &filegroup_check_authorization,
};

static void register_hooks(apr_pool_t *p)
{
    authz_owner_get_file_group = APR_RETRIEVE_OPTIONAL_FN(authz_owner_get_file_group);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_group_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "file-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_filegroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_groupfile) =
{
    STANDARD20_MODULE_STUFF,
    create_authz_groupfile_dir_config,/* dir config creater */
    NULL,                             /* dir merger -- default is to override */
    NULL,                             /* server config */
    NULL,                             /* merge server config */
    authz_groupfile_cmds,             /* command apr_table_t */
    register_hooks                    /* register hooks */
};
