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

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_md5.h"

#include "httpd.h"
#include "http_config.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/

#include "mod_auth.h"

typedef struct {
    const char *grpfile;
    const char *dbmtype;
} authz_dbm_config_rec;

APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_group, (request_rec *r));


/* This should go into APR; perhaps with some nice
 * caching/locking/flocking of the open dbm file.
 */
static char *get_dbm_entry_as_str(apr_pool_t *pool, apr_dbm_t *f, char *key)
{
    apr_datum_t d, q;
    q.dptr = key;

#ifndef NETSCAPE_DBM_COMPAT
    q.dsize = strlen(q.dptr);
#else
    q.dsize = strlen(q.dptr) + 1;
#endif

    if (apr_dbm_fetch(f, q, &d) == APR_SUCCESS && d.dptr) {
        return apr_pstrmemdup(pool, d.dptr, d.dsize);
    }

    return NULL;
}

static void *create_authz_dbm_dir_config(apr_pool_t *p, char *d)
{
    authz_dbm_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->grpfile = NULL;
    conf->dbmtype = "default";

    return conf;
}

static const command_rec authz_dbm_cmds[] =
{
    AP_INIT_TAKE1("AuthDBMGroupFile", ap_set_file_slot,
     (void *)APR_OFFSETOF(authz_dbm_config_rec, grpfile),
     OR_AUTHCFG, "database file containing group names and member user IDs"),
    AP_INIT_TAKE1("AuthzDBMType", ap_set_string_slot,
     (void *)APR_OFFSETOF(authz_dbm_config_rec, dbmtype),
     OR_AUTHCFG, "what type of DBM file the group file is"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_dbm_module;

/* We do something strange with the group file.  If the group file
 * contains any : we assume the format is
 *      key=username value=":"groupname [":"anything here is ignored]
 * otherwise we now (0.8.14+) assume that the format is
 *      key=username value=groupname
 * The first allows the password and group files to be the same
 * physical DBM file;   key=username value=password":"groupname[":"anything]
 *
 * mark@telescope.org, 22Sep95
 */

static apr_status_t get_dbm_grp(request_rec *r, char *key1, char *key2,
                                const char *dbmgrpfile, const char *dbtype,
                                const char ** out)
{
    char *grp_colon, *val;
    apr_status_t retval;
    apr_dbm_t *f;

    retval = apr_dbm_open_ex(&f, dbtype, dbmgrpfile, APR_DBM_READONLY,
                             APR_OS_DEFAULT, r->pool);

    if (retval != APR_SUCCESS) {
        return retval;
    }

    /* Try key2 only if key1 failed */
    if (!(val = get_dbm_entry_as_str(r->pool, f, key1))) {
        val = get_dbm_entry_as_str(r->pool, f, key2);
    }

    apr_dbm_close(f);

    if (val && (grp_colon = ap_strchr(val, ':')) != NULL) {
        char *grp_colon2 = ap_strchr(++grp_colon, ':');

        if (grp_colon2) {
            *grp_colon2 = '\0';
        }
        *out = grp_colon;
    }
    else {
        *out = val;
    }

    return retval;
}

static authz_status dbmgroup_check_authorization(request_rec *r,
                                                 const char *require_args,
                                                 const void *parsed_require_args)
{
    authz_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_dbm_module);
    char *user = r->user;

    const char *err = NULL;
    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *t;
    char *w;
    const char *orig_groups = NULL;
    const char *realm = ap_auth_name(r);
    const char *groups;
    char *v;

    if (!user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!conf->grpfile) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01798)
                        "No group file was specified in the configuration");
        return AUTHZ_DENIED;
    }

    /* fetch group data from dbm file only once. */
    if (!orig_groups) {
        apr_status_t status;

        status = get_dbm_grp(r, apr_pstrcat(r->pool, user, ":", realm, NULL),
                             user, conf->grpfile, conf->dbmtype, &groups);

        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01799)
                          "could not open dbm (type %s) group access "
                          "file: %s", conf->dbmtype, conf->grpfile);
            return AUTHZ_GENERAL_ERROR;
        }

        if (groups == NULL) {
            /* no groups available, so exit immediately */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01800)
                          "Authorization of user %s to access %s failed, reason: "
                          "user doesn't appear in DBM group file (%s).",
                          r->user, r->uri, conf->grpfile);
            return AUTHZ_DENIED;
        }

        orig_groups = groups;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02591)
                      "authz_dbm authorize: require dbm-group: Can't "
                      "evaluate require expression: %s", err);
        return AUTHZ_DENIED;
    }

    t = require;
    while ((w = ap_getword_white(r->pool, &t)) && w[0]) {
        groups = orig_groups;
        while (groups[0]) {
            v = ap_getword(r->pool, &groups, ',');
            if (!strcmp(v, w)) {
                return AUTHZ_GRANTED;
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01801)
                  "Authorization of user %s to access %s failed, reason: "
                  "user is not part of the 'require'ed group(s).",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

APR_OPTIONAL_FN_TYPE(authz_owner_get_file_group) *authz_owner_get_file_group;

static authz_status dbmfilegroup_check_authorization(request_rec *r,
                                                     const char *require_args,
                                                     const void *parsed_require_args)
{
    authz_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_dbm_module);
    char *user = r->user;
    const char *realm = ap_auth_name(r);
    const char *filegroup = NULL;
    apr_status_t status;
    const char *groups;
    char *v;

    if (!user) {
        return AUTHZ_DENIED_NO_USER;
    }

    if (!conf->grpfile) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01802)
                        "No group file was specified in the configuration");
        return AUTHZ_DENIED;
    }

    /* fetch group data from dbm file. */
    status = get_dbm_grp(r, apr_pstrcat(r->pool, user, ":", realm, NULL),
                         user, conf->grpfile, conf->dbmtype, &groups);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01803)
                      "could not open dbm (type %s) group access "
                      "file: %s", conf->dbmtype, conf->grpfile);
        return AUTHZ_DENIED;
    }

    if (groups == NULL) {
        /* no groups available, so exit immediately */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01804)
                      "Authorization of user %s to access %s failed, reason: "
                      "user doesn't appear in DBM group file (%s).",
                      r->user, r->uri, conf->grpfile);
        return AUTHZ_DENIED;
    }

    filegroup = authz_owner_get_file_group(r);

    if (filegroup) {
        while (groups[0]) {
            v = ap_getword(r->pool, &groups, ',');
            if (!strcmp(v, filegroup)) {
                return AUTHZ_GRANTED;
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01805)
                  "Authorization of user %s to access %s failed, reason: "
                  "user is not part of the 'require'ed group(s).",
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static const char *dbm_parse_config(cmd_parms *cmd, const char *require_line,
                                     const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;

    return NULL;
}

static const authz_provider authz_dbmgroup_provider =
{
    &dbmgroup_check_authorization,
    &dbm_parse_config,
};

static const authz_provider authz_dbmfilegroup_provider =
{
    &dbmfilegroup_check_authorization,
    NULL,
};


static void register_hooks(apr_pool_t *p)
{
    authz_owner_get_file_group = APR_RETRIEVE_OPTIONAL_FN(authz_owner_get_file_group);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "dbm-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_dbmgroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "dbm-file-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_dbmfilegroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authz_dbm) =
{
    STANDARD20_MODULE_STUFF,
    create_authz_dbm_dir_config, /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server config */
    authz_dbm_cmds,              /* command apr_table_t */
    register_hooks               /* register hooks */
};
