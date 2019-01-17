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
#include "apr_md5.h"            /* for apr_password_validate */

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#include "ap_socache.h"
#include "util_mutex.h"
#include "apr_optional.h"

module AP_MODULE_DECLARE_DATA authn_socache_module;

typedef struct authn_cache_dircfg {
    apr_interval_time_t timeout;
    apr_array_header_t *providers;
    const char *context;
} authn_cache_dircfg;

/* FIXME:
 * I think the cache and mutex should be global
 */
static apr_global_mutex_t *authn_cache_mutex = NULL;
static ap_socache_provider_t *socache_provider = NULL;
static ap_socache_instance_t *socache_instance = NULL;
static const char *const authn_cache_id = "authn-socache";
static int configured;

static apr_status_t remove_lock(void *data)
{
    if (authn_cache_mutex) {
        apr_global_mutex_destroy(authn_cache_mutex);
        authn_cache_mutex = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t destroy_cache(void *data)
{
    if (socache_instance) {
        socache_provider->destroy(socache_instance, (server_rec*)data);
        socache_instance = NULL;
    }
    return APR_SUCCESS;
}

static int authn_cache_precfg(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptmp)
{
    apr_status_t rv = ap_mutex_register(pconf, authn_cache_id,
                                        NULL, APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(01673)
                      "failed to register %s mutex", authn_cache_id);
        return 500; /* An HTTP status would be a misnomer! */
    }
    socache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                          AP_SOCACHE_DEFAULT_PROVIDER,
                                          AP_SOCACHE_PROVIDER_VERSION);
    configured = 0;
    return OK;
}

static int authn_cache_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                   apr_pool_t *ptmp, server_rec *s)
{
    apr_status_t rv;
    static struct ap_socache_hints authn_cache_hints = {64, 32, 60000000};
    const char *errmsg;

    if (!configured) {
        return OK;    /* don't waste the overhead of creating mutex & cache */
    }
    if (socache_provider == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, plog, APLOGNO(01674)
                      "Please select a socache provider with AuthnCacheSOCache "
                      "(no default found on this platform). Maybe you need to "
                      "load mod_socache_shmcb or another socache module first");
        return 500; /* An HTTP status would be a misnomer! */
    }

    /* We have socache_provider, but do not have socache_instance. This should
     * happen only when using "default" socache_provider, so create default
     * socache_instance in this case. */
    if (socache_instance == NULL) {
        errmsg = socache_provider->create(&socache_instance, NULL,
                                          ptmp, pconf);
        if (errmsg) {
            ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, plog, APLOGNO(02612)
                        "failed to create mod_socache_shmcb socache "
                        "instance: %s", errmsg);
            return 500;
        }
    }

    rv = ap_global_mutex_create(&authn_cache_mutex, NULL,
                                authn_cache_id, NULL, s, pconf, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(01675)
                      "failed to create %s mutex", authn_cache_id);
        return 500; /* An HTTP status would be a misnomer! */
    }
    apr_pool_cleanup_register(pconf, NULL, remove_lock, apr_pool_cleanup_null);

    rv = socache_provider->init(socache_instance, authn_cache_id,
                                &authn_cache_hints, s, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(01677)
                      "failed to initialise %s cache", authn_cache_id);
        return 500; /* An HTTP status would be a misnomer! */
    }
    apr_pool_cleanup_register(pconf, (void*)s, destroy_cache, apr_pool_cleanup_null);
    return OK;
}

static void authn_cache_child_init(apr_pool_t *p, server_rec *s)
{
    const char *lock;
    apr_status_t rv;
    if (!configured) {
        return;       /* don't waste the overhead of creating mutex & cache */
    }
    lock = apr_global_mutex_lockfile(authn_cache_mutex);
    rv = apr_global_mutex_child_init(&authn_cache_mutex, lock, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(01678)
                     "failed to initialise mutex in child_init");
    }
}

static const char *authn_cache_socache(cmd_parms *cmd, void *CFG,
                                       const char *arg)
{
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    const char *sep, *name;

    if (errmsg)
        return errmsg;

    /* Argument is of form 'name:args' or just 'name'. */
    sep = ap_strchr_c(arg, ':');
    if (sep) {
        name = apr_pstrmemdup(cmd->pool, arg, sep - arg);
        sep++;
    }
    else {
        name = arg;
    }

    socache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, name,
                                          AP_SOCACHE_PROVIDER_VERSION);
    if (socache_provider == NULL) {
        errmsg = apr_psprintf(cmd->pool,
                              "Unknown socache provider '%s'. Maybe you need "
                              "to load the appropriate socache module "
                              "(mod_socache_%s?)", arg, arg);
    }
    else {
        errmsg = socache_provider->create(&socache_instance, sep,
                                          cmd->temp_pool, cmd->pool);
    }

    if (errmsg) {
        errmsg = apr_psprintf(cmd->pool, "AuthnCacheSOCache: %s", errmsg);
    }
    return errmsg;
}

static const char *authn_cache_enable(cmd_parms *cmd, void *CFG)
{
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    configured = 1;
    return errmsg;
}

static const char *const directory = "directory";
static void* authn_cache_dircfg_create(apr_pool_t *pool, char *s)
{
    authn_cache_dircfg *ret = apr_palloc(pool, sizeof(authn_cache_dircfg));
    ret->timeout = apr_time_from_sec(300);
    ret->providers = NULL;
    ret->context = directory;
    return ret;
}

/* not sure we want this.  Might be safer to document use-all-or-none */
static void* authn_cache_dircfg_merge(apr_pool_t *pool, void *BASE, void *ADD)
{
    authn_cache_dircfg *base = BASE;
    authn_cache_dircfg *add = ADD;
    authn_cache_dircfg *ret = apr_pmemdup(pool, add, sizeof(authn_cache_dircfg));
    /* preserve context and timeout if not defaults */
    if (add->context == directory) {
        ret->context = base->context;
    }
    if (add->timeout == apr_time_from_sec(300)) {
        ret->timeout = base->timeout;
    }
    if (add->providers == NULL) {
        ret->providers = base->providers;
    }
    return ret;
}

static const char *authn_cache_setprovider(cmd_parms *cmd, void *CFG,
                                           const char *arg)
{
    authn_cache_dircfg *cfg = CFG;
    if (cfg->providers == NULL) {
        cfg->providers = apr_array_make(cmd->pool, 4, sizeof(const char*));
    }
    APR_ARRAY_PUSH(cfg->providers, const char*) = arg;
    configured = 1;
    return NULL;
}

static const char *authn_cache_timeout(cmd_parms *cmd, void *CFG,
                                       const char *arg)
{
    authn_cache_dircfg *cfg = CFG;
    int secs = atoi(arg);
    cfg->timeout = apr_time_from_sec(secs);
    return NULL;
}

static const command_rec authn_cache_cmds[] =
{
    /* global stuff: cache and mutex */
    AP_INIT_TAKE1("AuthnCacheSOCache", authn_cache_socache, NULL, RSRC_CONF,
                  "socache provider for authn cache"),
    AP_INIT_NO_ARGS("AuthnCacheEnable", authn_cache_enable, NULL, RSRC_CONF,
                    "enable socache configuration in htaccess even if not enabled anywhere else"),
    /* per-dir stuff */
    AP_INIT_ITERATE("AuthnCacheProvideFor", authn_cache_setprovider, NULL,
                    OR_AUTHCFG, "Determine what authn providers to cache for"),
    AP_INIT_TAKE1("AuthnCacheTimeout", authn_cache_timeout, NULL,
                  OR_AUTHCFG, "Timeout (secs) for cached credentials"),
    AP_INIT_TAKE1("AuthnCacheContext", ap_set_string_slot,
                  (void*)APR_OFFSETOF(authn_cache_dircfg, context),
                  ACCESS_CONF, "Context for authn cache"),
    {NULL}
};

static const char *construct_key(request_rec *r, const char *context,
                                 const char *user, const char *realm)
{
    /* handle "special" context values */
    if (!strcmp(context, directory)) {
        /* FIXME: are we at risk of this blowing up? */
        char *new_context;
        char *slash = strrchr(r->uri, '/');
        new_context = apr_palloc(r->pool, slash - r->uri +
                                 strlen(r->server->server_hostname) + 1);
        strcpy(new_context, r->server->server_hostname);
        strncat(new_context, r->uri, slash - r->uri);
        context = new_context;
    }
    else if (!strcmp(context, "server")) {
        context = r->server->server_hostname;
    }
    /* any other context value is literal */

    if (realm == NULL) {                              /* basic auth */
        return apr_pstrcat(r->pool, context, ":", user, NULL);
    }
    else {                                            /* digest auth */
        return apr_pstrcat(r->pool, context, ":", user, ":", realm, NULL);
    }
}

static void ap_authn_cache_store(request_rec *r, const char *module,
                                 const char *user, const char *realm,
                                 const char* data)
{
    apr_status_t rv;
    authn_cache_dircfg *dcfg;
    const char *key;
    apr_time_t expiry;

    /* first check whether we're cacheing for this module */
    dcfg = ap_get_module_config(r->per_dir_config, &authn_socache_module);
    if (!configured || !dcfg->providers) {
        return;
    }
    if (!ap_array_str_contains(dcfg->providers, module)) {
        return;
    }

    /* OK, we're on.  Grab mutex to do our business */
    rv = apr_global_mutex_trylock(authn_cache_mutex);
    if (APR_STATUS_IS_EBUSY(rv)) {
        /* don't wait around; just abandon it */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, APLOGNO(01679)
                      "authn credentials for %s not cached (mutex busy)", user);
        return;
    }
    else if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01680)
                      "Failed to cache authn credentials for %s in %s",
                      module, dcfg->context);
        return;
    }

    /* We have the mutex, so go ahead */
    /* first build our key and determine expiry time */
    key = construct_key(r, dcfg->context, user, realm);
    expiry = apr_time_now() + dcfg->timeout;

    /* store it */
    rv = socache_provider->store(socache_instance, r->server,
                                 (unsigned char*)key, strlen(key), expiry,
                                 (unsigned char*)data, strlen(data), r->pool);
    if (rv == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01681)
                      "Cached authn credentials for %s in %s",
                      user, dcfg->context);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01682)
                      "Failed to cache authn credentials for %s in %s",
                      module, dcfg->context);
    }

    /* We're done with the mutex */
    rv = apr_global_mutex_unlock(authn_cache_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01683) "Failed to release mutex!");
    }
}

#define MAX_VAL_LEN 100
static authn_status check_password(request_rec *r, const char *user,
                                   const char *password)
{
    /* construct key
     * look it up
     * if found, test password
     *
     * mutexing here would be a big performance drag.
     * It's definitely unnecessary with some backends (like ndbm or gdbm)
     * Is there a risk in the general case?  I guess the only risk we
     * care about is a race condition that gets us a dangling pointer
     * to no-longer-defined memory.  Hmmm ...
     */
    apr_status_t rv;
    const char *key;
    authn_cache_dircfg *dcfg;
    unsigned char val[MAX_VAL_LEN];
    unsigned int vallen = MAX_VAL_LEN - 1;
    dcfg = ap_get_module_config(r->per_dir_config, &authn_socache_module);
    if (!configured || !dcfg->providers) {
        return AUTH_USER_NOT_FOUND;
    }
    key = construct_key(r, dcfg->context, user, NULL);
    rv = socache_provider->retrieve(socache_instance, r->server,
                                    (unsigned char*)key, strlen(key),
                                    val, &vallen, r->pool);

    if (APR_STATUS_IS_NOTFOUND(rv)) {
        /* not found - just return */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01684)
                      "Authn cache: no credentials found for %s", user);
        return AUTH_USER_NOT_FOUND;
    }
    else if (rv == APR_SUCCESS) {
        /* OK, we got a value */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01685)
                      "Authn cache: found credentials for %s", user);
        val[vallen] = 0;
    }
    else {
        /* error: give up and pass the buck */
        /* FIXME: getting this for NOTFOUND - prolly a bug in mod_socache */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01686)
                      "Error accessing authentication cache");
        return AUTH_USER_NOT_FOUND;
    }

    rv = apr_password_validate(password, (char*) val);
    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static authn_status get_realm_hash(request_rec *r, const char *user,
                                   const char *realm, char **rethash)
{
    apr_status_t rv;
    const char *key;
    authn_cache_dircfg *dcfg;
    unsigned char val[MAX_VAL_LEN];
    unsigned int vallen = MAX_VAL_LEN - 1;
    dcfg = ap_get_module_config(r->per_dir_config, &authn_socache_module);
    if (!configured || !dcfg->providers) {
        return AUTH_USER_NOT_FOUND;
    }
    key = construct_key(r, dcfg->context, user, realm);
    rv = socache_provider->retrieve(socache_instance, r->server,
                                    (unsigned char*)key, strlen(key),
                                    val, &vallen, r->pool);

    if (APR_STATUS_IS_NOTFOUND(rv)) {
        /* not found - just return */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01687)
                      "Authn cache: no credentials found for %s", user);
        return AUTH_USER_NOT_FOUND;
    }
    else if (rv == APR_SUCCESS) {
        /* OK, we got a value */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01688)
                      "Authn cache: found credentials for %s", user);
    }
    else {
        /* error: give up and pass the buck */
        /* FIXME: getting this for NOTFOUND - prolly a bug in mod_socache */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01689)
                      "Error accessing authentication cache");
        return AUTH_USER_NOT_FOUND;
    }
    *rethash = apr_pstrmemdup(r->pool, (char *)val, vallen);

    return AUTH_USER_FOUND;
}

static const authn_provider authn_cache_provider =
{
    &check_password,
    &get_realm_hash,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "socache",
                              AUTHN_PROVIDER_VERSION,
                              &authn_cache_provider, AP_AUTH_INTERNAL_PER_CONF);
    APR_REGISTER_OPTIONAL_FN(ap_authn_cache_store);
    ap_hook_pre_config(authn_cache_precfg, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(authn_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(authn_cache_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authn_socache) =
{
    STANDARD20_MODULE_STUFF,
    authn_cache_dircfg_create,
    authn_cache_dircfg_merge,
    NULL,
    NULL,
    authn_cache_cmds,
    register_hooks
};
