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

#include "mod_proxy.h"
#include "apr_dbm.h"

module AP_MODULE_DECLARE_DATA proxy_express_module;

static int proxy_available = 0;

typedef struct {
    const char *dbmfile;
    const char *dbmtype;
    int enabled;
} express_server_conf;

static const char *set_dbmfile(cmd_parms *cmd,
                               void *dconf,
                               const char *arg)
{
    express_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_express_module);

    if ((sconf->dbmfile = ap_server_root_relative(cmd->pool, arg)) == NULL) {
        return apr_pstrcat(cmd->pool, "ProxyExpressDBMFile: bad path to file: ",
                           arg, NULL);
    }
    return NULL;
}

static const char *set_dbmtype(cmd_parms *cmd,
                               void *dconf,
                               const char *arg)
{
    express_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_express_module);

    sconf->dbmtype = arg;

    return NULL;
}

static const char *set_enabled(cmd_parms *cmd,
                               void *dconf,
                               int flag)
{
    express_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_express_module);

    sconf->enabled = flag;

    return NULL;
}

static void *server_create(apr_pool_t *p, server_rec *s)
{
    express_server_conf *a;

    a = (express_server_conf *)apr_pcalloc(p, sizeof(express_server_conf));

    a->dbmfile = NULL;
    a->dbmtype = "default";
    a->enabled = 0;

    return (void *)a;
}

static void *server_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    express_server_conf *a, *base, *overrides;

    a         = (express_server_conf *)apr_pcalloc(p,
                                                   sizeof(express_server_conf));
    base      = (express_server_conf *)basev;
    overrides = (express_server_conf *)overridesv;

    a->dbmfile = (overrides->dbmfile) ? overrides->dbmfile : base->dbmfile;
    a->dbmtype = (overrides->dbmtype) ? overrides->dbmtype : base->dbmtype;
    a->enabled = (overrides->enabled) ? overrides->enabled : base->enabled;

    return (void *)a;
}

static int post_config(apr_pool_t *p,
                       apr_pool_t *plog,
                       apr_pool_t *ptemp,
                       server_rec *s)
{
    proxy_available = (ap_find_linked_module("mod_proxy.c") != NULL);
    return OK;
}


static int xlate_name(request_rec *r)
{
    int i;
    const char *name;
    char *backend;
    apr_dbm_t *db;
    apr_status_t rv;
    apr_datum_t key, val;
    struct proxy_alias *ralias;
    proxy_dir_conf *dconf;
    express_server_conf *sconf;

    sconf = ap_get_module_config(r->server->module_config, &proxy_express_module);
    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    if (!sconf->enabled) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01001) "proxy_express: Enabled");
    if (!sconf->dbmfile || (r->filename && strncmp(r->filename, "proxy:", 6) == 0)) {
        /* it should be go on as an internal proxy request */
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01002)
                  "proxy_express: Opening DBM file: %s (%s)",
                  sconf->dbmfile, sconf->dbmtype);
    rv = apr_dbm_open_ex(&db, sconf->dbmtype, sconf->dbmfile, APR_DBM_READONLY,
                         APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        return DECLINED;
    }

    name = ap_get_server_name(r);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01003)
                  "proxy_express: looking for %s", name);
    key.dptr = (char *)name;
    key.dsize = strlen(key.dptr);

    rv = apr_dbm_fetch(db, key, &val);
    apr_dbm_close(db);
    if (rv != APR_SUCCESS) {
        return DECLINED;
    }

    backend = apr_pstrmemdup(r->pool, val.dptr, val.dsize);
    if (!backend) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01004)
                  "proxy_express: found %s -> %s", name, backend);
    r->filename = apr_pstrcat(r->pool, "proxy:", backend, r->uri, NULL);
    r->handler = "proxy-server";
    r->proxyreq = PROXYREQ_REVERSE;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01005)
                  "proxy_express: rewritten as: %s", r->filename);

    ralias = (struct proxy_alias *)dconf->raliases->elts;
    /*
     * See if we have already added a ProxyPassReverse entry
     * for this host... If so, don't do it again.
     */
    /*
     * NOTE: dconf is process specific so this will only
     *       work as long as we maintain that this process
     *       or thread is handling the backend
     */
    for (i = 0; i < dconf->raliases->nelts; i++, ralias++) {
        if (strcasecmp(backend, ralias->real) == 0) {
            ralias = NULL;
            break;
        }
    }

    /* Didn't find one... add it */
    if (!ralias) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01006)
                      "proxy_express: adding PPR entry");
        ralias = apr_array_push(dconf->raliases);
        ralias->fake = "/";
        ralias->real = apr_pstrdup(dconf->raliases->pool, backend);
        ralias->flags = 0;
    }
    return OK;
}

static const command_rec command_table[] = {
    AP_INIT_FLAG("ProxyExpressEnable", set_enabled, NULL, OR_FILEINFO,
                 "Enable the ProxyExpress functionality"),
    AP_INIT_TAKE1("ProxyExpressDBMFile", set_dbmfile, NULL, OR_FILEINFO,
                  "Location of ProxyExpressDBMFile file"),
    AP_INIT_TAKE1("ProxyExpressDBMType", set_dbmtype, NULL, OR_FILEINFO,
                  "Type of ProxyExpressDBMFile file"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_translate_name(xlate_name, NULL, NULL, APR_HOOK_FIRST);
}

/* the main config structure */

AP_DECLARE_MODULE(proxy_express) =
{
    STANDARD20_MODULE_STUFF,
    NULL,           /* create per-dir config structures */
    NULL,           /* merge  per-dir config structures */
    server_create,  /* create per-server config structures */
    server_merge,   /* merge  per-server config structures */
    command_table,  /* table of config file commands */
    register_hooks  /* register hooks */
};
