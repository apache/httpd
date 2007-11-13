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
 * unless we are non-authoritative; in which
 * case we DECLINED.
 *
 */

#include "apr_strings.h"
#include "apr_lib.h" /* apr_isspace */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

typedef struct {
    char *groupfile;
    int authoritative;
} authz_groupfile_config_rec;

static void *create_authz_groupfile_dir_config(apr_pool_t *p, char *d)
{
    authz_groupfile_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->groupfile = NULL;
    conf->authoritative = 1; /* keep the fortress secure by default */
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
    AP_INIT_FLAG("AuthzGroupFileAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_groupfile_config_rec,
                                      authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the 'require group' fails. (default is "
                 "On)."),
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

/* Checking ID */

static int check_user_access(request_rec *r)
{
    authz_groupfile_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_groupfile_module);
    char *user = r->user;
    int m = r->method_number;
    int required_group = 0;
    register int x;
    const char *t, *w;
    apr_table_t *grpstatus = NULL;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    const char *filegroup = NULL;
    char *reason = NULL;

    /* If there is no group file - then we are not
     * configured. So decline.
     */
    if (!(conf->groupfile)) {
        return DECLINED;
    }

    if (!reqs_arr) {
        return DECLINED; /* XXX change from legacy */
    }

    /* If there's no user, it's a misconfiguration */
    if (!user) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    reqs = (require_line *)reqs_arr->elts;

    for (x = 0; x < reqs_arr->nelts; x++) {

        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        /* needs mod_authz_owner to be present */
        if (!strcasecmp(w, "file-group")) {
            filegroup = apr_table_get(r->notes, AUTHZ_GROUP_NOTE);

            if (!filegroup) {
                /* mod_authz_owner is not present or not
                 * authoritative. We are just a helper module for testing
                 * group membership, so we don't care and decline.
                 */
                continue;
            }
        }

        if (!strcasecmp(w, "group") || filegroup) {
            required_group = 1; /* remember the requirement */

            /* create group table only if actually needed. */
            if (!grpstatus) {
                apr_status_t status;

                status = groups_for_user(r->pool, user, conf->groupfile,
                                         &grpstatus);

                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                                  "Could not open group file: %s",
                                  conf->groupfile);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                if (apr_table_elts(grpstatus)->nelts == 0) {
                    /* no groups available, so exit immediately */
                    reason = apr_psprintf(r->pool,
                                          "user doesn't appear in group file "
                                          "(%s).", conf->groupfile);
                    break;
                }
            }

            if (filegroup) {
                if (apr_table_get(grpstatus, filegroup)) {
                    return OK;
                }

                if (conf->authoritative) {
                    reason = apr_psprintf(r->pool,
                                          "file group '%s' does not match.",
                                          filegroup);
                    break;
                }

                /* now forget the filegroup, thus alternatively require'd
                   groups get a real chance */
                filegroup = NULL;
            }
            else {
                while (t[0]) {
                    w = ap_getword_conf(r->pool, &t);
                    if (apr_table_get(grpstatus, w)) {
                        return OK;
                    }
                }
            }
        }
    }

    /* No applicable "require group" for this method seen */
    if (!required_group || !conf->authoritative) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "Authorization of user %s to access %s failed, reason: %s",
                  r->user, r->uri,
                  reason ? reason : "user is not part of the "
                                    "'require'ed group(s).");

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_authz_owner.c", NULL };

    ap_hook_auth_checker(check_user_access, aszPre, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_groupfile_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_groupfile_dir_config,/* dir config creater */
    NULL,                             /* dir merger -- default is to override */
    NULL,                             /* server config */
    NULL,                             /* merge server config */
    authz_groupfile_cmds,             /* command apr_table_t */
    register_hooks                    /* register hooks */
};
