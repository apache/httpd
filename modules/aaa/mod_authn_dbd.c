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

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_lib.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_strings.h"
#include "mod_auth.h"
#include "apr_md5.h"
#include "apu_version.h"

module AP_MODULE_DECLARE_DATA authn_dbd_module;

typedef struct {
    const char *user;
    const char *realm;
} authn_dbd_conf;

/* optional function - look it up once in post_config */
static ap_dbd_t *(*authn_dbd_acquire_fn)(request_rec*) = NULL;
static void (*authn_dbd_prepare_fn)(server_rec*, const char*, const char*) = NULL;
static APR_OPTIONAL_FN_TYPE(ap_authn_cache_store) *authn_cache_store = NULL;
#define AUTHN_CACHE_STORE(r,user,realm,data) \
    if (authn_cache_store != NULL) \
        authn_cache_store((r), "dbd", (user), (realm), (data))

static void *authn_dbd_cr_conf(apr_pool_t *pool, char *dummy)
{
    authn_dbd_conf *ret = apr_pcalloc(pool, sizeof(authn_dbd_conf));
    return ret;
}

static void *authn_dbd_merge_conf(apr_pool_t *pool, void *BASE, void *ADD)
{
    authn_dbd_conf *add = ADD;
    authn_dbd_conf *base = BASE;
    authn_dbd_conf *ret = apr_palloc(pool, sizeof(authn_dbd_conf));
    ret->user = (add->user == NULL) ? base->user : add->user;
    ret->realm = (add->realm == NULL) ? base->realm : add->realm;
    return ret;
}

static const char *authn_dbd_prepare(cmd_parms *cmd, void *cfg, const char *query)
{
    static unsigned int label_num = 0;
    char *label;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    if (authn_dbd_prepare_fn == NULL) {
        authn_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (authn_dbd_prepare_fn == NULL) {
            return "You must load mod_dbd to enable AuthDBD functions";
        }
        authn_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }
    label = apr_psprintf(cmd->pool, "authn_dbd_%d", ++label_num);

    authn_dbd_prepare_fn(cmd->server, query, label);

    /* save the label here for our own use */
    return ap_set_string_slot(cmd, cfg, label);
}

static const command_rec authn_dbd_cmds[] =
{
    AP_INIT_TAKE1("AuthDBDUserPWQuery", authn_dbd_prepare,
                  (void *)APR_OFFSETOF(authn_dbd_conf, user), ACCESS_CONF,
                  "Query used to fetch password for user"),
    AP_INIT_TAKE1("AuthDBDUserRealmQuery", authn_dbd_prepare,
                  (void *)APR_OFFSETOF(authn_dbd_conf, realm), ACCESS_CONF,
                  "Query used to fetch password for user+realm"),
    {NULL}
};

static authn_status authn_dbd_password(request_rec *r, const char *user,
                                       const char *password)
{
    apr_status_t rv;
    const char *dbd_password = NULL;
    apr_dbd_prepared_t *statement;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;
    int ret;

    authn_dbd_conf *conf = ap_get_module_config(r->per_dir_config,
                                                &authn_dbd_module);
    ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01653)
                      "Failed to acquire database connection to look up "
                      "user '%s'", user);
        return AUTH_GENERAL_ERROR;
    }

    if (conf->user == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01654)
                      "No AuthDBDUserPWQuery has been specified");
        return AUTH_GENERAL_ERROR;
    }

    statement = apr_hash_get(dbd->prepared, conf->user, APR_HASH_KEY_STRING);
    if (statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01655)
                      "A prepared statement could not be found for "
                      "AuthDBDUserPWQuery with the key '%s'", conf->user);
        return AUTH_GENERAL_ERROR;
    }
    if ((ret = apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res,
                                statement, 0, user, NULL)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01656)
                      "Query execution error looking up '%s' "
                      "in database [%s]",
                      user, apr_dbd_error(dbd->driver, dbd->handle, ret));
        return AUTH_GENERAL_ERROR;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01657)
                          "Error retrieving results while looking up '%s' "
                          "in database", user);
            return AUTH_GENERAL_ERROR;
        }
        if (dbd_password == NULL) {
            /* add the rest of the columns to the environment */
            int i = 1;
            const char *name;
            for (name = apr_dbd_get_name(dbd->driver, res, i);
                 name != NULL;
                 name = apr_dbd_get_name(dbd->driver, res, i)) {

                char *str = apr_pstrcat(r->pool, AUTHN_PREFIX,
                                        name,
                                        NULL);
                int j = sizeof(AUTHN_PREFIX)-1; /* string length of "AUTHENTICATE_", excluding the trailing NIL */
                while (str[j]) {
                    if (!apr_isalnum(str[j])) {
                        str[j] = '_';
                    }
                    else {
                        str[j] = apr_toupper(str[j]);
                    }
                    j++;
                }
                apr_table_set(r->subprocess_env, str,
                              apr_dbd_get_entry(dbd->driver, row, i));
                i++;
            }

            dbd_password = apr_pstrdup(r->pool,
                                       apr_dbd_get_entry(dbd->driver, row, 0));
        }
        /* we can't break out here or row won't get cleaned up */
    }

    if (!dbd_password) {
        return AUTH_USER_NOT_FOUND;
    }
    AUTHN_CACHE_STORE(r, user, NULL, dbd_password);

    rv = apr_password_validate(password, dbd_password);

    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static authn_status authn_dbd_realm(request_rec *r, const char *user,
                                    const char *realm, char **rethash)
{
    apr_status_t rv;
    const char *dbd_hash = NULL;
    apr_dbd_prepared_t *statement;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;
    int ret;

    authn_dbd_conf *conf = ap_get_module_config(r->per_dir_config,
                                                &authn_dbd_module);
    ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01658)
                      "Failed to acquire database connection to look up "
                      "user '%s:%s'", user, realm);
        return AUTH_GENERAL_ERROR;
    }
    if (conf->realm == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01659)
                      "No AuthDBDUserRealmQuery has been specified");
        return AUTH_GENERAL_ERROR;
    }
    statement = apr_hash_get(dbd->prepared, conf->realm, APR_HASH_KEY_STRING);
    if (statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01660)
                      "A prepared statement could not be found for "
                      "AuthDBDUserRealmQuery with the key '%s'", conf->realm);
        return AUTH_GENERAL_ERROR;
    }
    if ((ret = apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res,
                                statement, 0, user, realm, NULL)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01661)
                      "Query execution error looking up '%s:%s' "
                      "in database [%s]",
                      user, realm,
                      apr_dbd_error(dbd->driver, dbd->handle, ret));
        return AUTH_GENERAL_ERROR;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01662)
                          "Error retrieving results while looking up '%s:%s' "
                          "in database", user, realm);
            return AUTH_GENERAL_ERROR;
        }
        if (dbd_hash == NULL) {
            /* add the rest of the columns to the environment */
            int i = 1;
            const char *name;
            for (name = apr_dbd_get_name(dbd->driver, res, i);
                 name != NULL;
                 name = apr_dbd_get_name(dbd->driver, res, i)) {

                char *str = apr_pstrcat(r->pool, AUTHN_PREFIX,
                                        name,
                                        NULL);
                int j = sizeof(AUTHN_PREFIX)-1; /* string length of "AUTHENTICATE_", excluding the trailing NIL */
                while (str[j]) {
                    if (!apr_isalnum(str[j])) {
                        str[j] = '_';
                    }
                    else {
                        str[j] = apr_toupper(str[j]);
                    }
                    j++;
                }
                apr_table_set(r->subprocess_env, str,
                              apr_dbd_get_entry(dbd->driver, row, i));
                i++;
            }

            dbd_hash = apr_pstrdup(r->pool,
                                   apr_dbd_get_entry(dbd->driver, row, 0));
        }
        /* we can't break out here or row won't get cleaned up */
    }

    if (!dbd_hash) {
        return AUTH_USER_NOT_FOUND;
    }
    AUTHN_CACHE_STORE(r, user, realm, dbd_hash);
    *rethash = apr_pstrdup(r->pool, dbd_hash);
    return AUTH_USER_FOUND;
}

static void opt_retr(void)
{
    authn_cache_store = APR_RETRIEVE_OPTIONAL_FN(ap_authn_cache_store);
}

static void authn_dbd_hooks(apr_pool_t *p)
{
    static const authn_provider authn_dbd_provider = {
        &authn_dbd_password,
        &authn_dbd_realm
    };

    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "dbd",
                              AUTHN_PROVIDER_VERSION,
                              &authn_dbd_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_optional_fn_retrieve(opt_retr, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authn_dbd) =
{
    STANDARD20_MODULE_STUFF,
    authn_dbd_cr_conf,
    authn_dbd_merge_conf,
    NULL,
    NULL,
    authn_dbd_cmds,
    authn_dbd_hooks
};
