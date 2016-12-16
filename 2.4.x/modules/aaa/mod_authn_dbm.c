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

/*
 * http_auth: authentication
 *
 * Rob McCool & Brian Behlendorf.
 *
 * Adapted to Apache by rst.
 *
 */

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_md5.h"        /* for apr_password_validate */

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/

#include "mod_auth.h"

static APR_OPTIONAL_FN_TYPE(ap_authn_cache_store) *authn_cache_store = NULL;
#define AUTHN_CACHE_STORE(r,user,realm,data) \
    if (authn_cache_store != NULL) \
        authn_cache_store((r), "dbm", (user), (realm), (data))

typedef struct {
    const char *pwfile;
    const char *dbmtype;
} authn_dbm_config_rec;

static void *create_authn_dbm_dir_config(apr_pool_t *p, char *d)
{
    authn_dbm_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->pwfile = NULL;
    conf->dbmtype = "default";

    return conf;
}

static const command_rec authn_dbm_cmds[] =
{
    AP_INIT_TAKE1("AuthDBMUserFile", ap_set_file_slot,
     (void *)APR_OFFSETOF(authn_dbm_config_rec, pwfile),
     OR_AUTHCFG, "dbm database file containing user IDs and passwords"),
    AP_INIT_TAKE1("AuthDBMType", ap_set_string_slot,
     (void *)APR_OFFSETOF(authn_dbm_config_rec, dbmtype),
     OR_AUTHCFG, "what type of DBM file the user file is"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_dbm_module;

static apr_status_t fetch_dbm_value(const char *dbmtype, const char *dbmfile,
                                    const char *user, char **value,
                                    apr_pool_t *pool)
{
    apr_dbm_t *f;
    apr_datum_t key, val;
    apr_status_t rv;

    rv = apr_dbm_open_ex(&f, dbmtype, dbmfile, APR_DBM_READONLY,
                         APR_OS_DEFAULT, pool);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    key.dptr = (char*)user;
#ifndef NETSCAPE_DBM_COMPAT
    key.dsize = strlen(key.dptr);
#else
    key.dsize = strlen(key.dptr) + 1;
#endif

    *value = NULL;

    if (apr_dbm_fetch(f, key, &val) == APR_SUCCESS && val.dptr) {
        *value = apr_pstrmemdup(pool, val.dptr, val.dsize);
    }

    apr_dbm_close(f);

    return rv;
}

static authn_status check_dbm_pw(request_rec *r, const char *user,
                                 const char *password)
{
    authn_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_dbm_module);
    apr_status_t rv;
    char *dbm_password;
    char *colon_pw;

    rv = fetch_dbm_value(conf->dbmtype, conf->pwfile, user, &dbm_password,
                         r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01754)
                      "could not open dbm (type %s) auth file: %s",
                      conf->dbmtype, conf->pwfile);
        return AUTH_GENERAL_ERROR;
    }

    if (!dbm_password) {
        return AUTH_USER_NOT_FOUND;
    }

    colon_pw = ap_strchr(dbm_password, ':');
    if (colon_pw) {
        *colon_pw = '\0';
    }
    AUTHN_CACHE_STORE(r, user, NULL, dbm_password);

    rv = apr_password_validate(password, dbm_password);

    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static authn_status get_dbm_realm_hash(request_rec *r, const char *user,
                                       const char *realm, char **rethash)
{
    authn_dbm_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authn_dbm_module);
    apr_status_t rv;
    char *dbm_hash;
    char *colon_hash;

    rv = fetch_dbm_value(conf->dbmtype, conf->pwfile,
                         apr_pstrcat(r->pool, user, ":", realm, NULL),
                         &dbm_hash, r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01755)
                      "Could not open dbm (type %s) hash file: %s",
                      conf->dbmtype, conf->pwfile);
        return AUTH_GENERAL_ERROR;
    }

    if (!dbm_hash) {
        return AUTH_USER_NOT_FOUND;
    }

    colon_hash = ap_strchr(dbm_hash, ':');
    if (colon_hash) {
        *colon_hash = '\0';
    }

    *rethash = dbm_hash;
    AUTHN_CACHE_STORE(r, user, realm, dbm_hash);

    return AUTH_USER_FOUND;
}

static const authn_provider authn_dbm_provider =
{
    &check_dbm_pw,
    &get_dbm_realm_hash,
};

static void opt_retr(void)
{
    authn_cache_store = APR_RETRIEVE_OPTIONAL_FN(ap_authn_cache_store);
}
static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "dbm",
                              AUTHN_PROVIDER_VERSION,
                              &authn_dbm_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_optional_fn_retrieve(opt_retr, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authn_dbm) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_dbm_dir_config, /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server config */
    authn_dbm_cmds,              /* command apr_table_t */
    register_hooks               /* register hooks */
};
