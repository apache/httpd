/* Copyright 2003-5 WebThing Ltd
 * Copyright 2005 The Apache Software Foundation or its licensors, as
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

/* Overview of what this is and does:
 * http://www.apache.org/~niq/dbd.html
 * or
 * http://apache.webthing.com/database/
 */

/* Bump the version for committing to apache svn */
#define VERSION "0.2"

#include <ctype.h>

#include "http_protocol.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_reslist.h"
#include "apr_strings.h"

#include "apr_dbd.h"
#include "mod_dbd.h"

extern module AP_MODULE_DECLARE_DATA dbd_module;

/************ svr cfg: manage db connection pool ****************/

typedef struct dbd_prepared {
    const char *label;
    const char *query;
    struct dbd_prepared *next;
} dbd_prepared;
typedef struct svr_cfg {
    const char *name;
    const char *params;
    int persist;
    dbd_prepared *prepared;
#if APR_HAS_THREADS
    apr_reslist_t *dbpool;
    int nmin;
    int nkeep;
    int nmax;
    int exptime;
#else
    ap_dbd_t *conn;
#endif
} svr_cfg;

typedef enum { cmd_name, cmd_params, cmd_persist,
               cmd_min, cmd_keep, cmd_max, cmd_exp
} cmd_parts;


#define ISINT(val) \
        for (p = val; *p; ++p)        \
                if (!isdigit(*p))        \
                        return "Argument must be numeric!"
static const char *dbd_param(cmd_parms *cmd, void *cfg, const char *val)
{
    const char *p;
    apr_dbd_driver_t *driver = NULL;
    svr_cfg *svr = (svr_cfg*) ap_get_module_config
        (cmd->server->module_config, &dbd_module);

    switch ((int) cmd->info) {
    case cmd_name:
        svr->name = val;
        /* loading the driver involves once-only dlloading that is
         * best done at server startup.  This also guarantees that
         * load_driver won't return an error later.
         */
        switch (apr_dbd_get_driver(cmd->pool, svr->name, &driver)) {
        case APR_ENOTIMPL:
            return apr_psprintf(cmd->pool, "DBD: No driver for %s", svr->name);
        case APR_EDSOOPEN:
            return apr_psprintf(cmd->pool,
                                "DBD: Can't load driver file apr_dbd_%s.so",
                                svr->name);
        case APR_ESYMNOTFOUND:
            return apr_psprintf(cmd->pool,
                                "DBD: Failed to load driver apr_dbd_%s_driver",
                                svr->name);
        }
        break;
    case cmd_params:
        svr->params = val;
        break;
    case cmd_persist:
        ISINT(val);
        svr->persist = atoi(val);
        break;
#if APR_HAS_THREADS
    case cmd_min:
        ISINT(val);
        svr->nmin = atoi(val);
        break;
    case cmd_keep:
        ISINT(val);
        svr->nkeep = atoi(val);
        break;
    case cmd_max:
        ISINT(val);
        svr->nmax = atoi(val);
        break;
    case cmd_exp:
        ISINT(val);
        svr->exptime = atoi(val);
        break;
#endif
    }
    return NULL;
}
static const char *dbd_prepare(cmd_parms *cmd, void *cfg, const char *query,
                               const char *label)
{
    svr_cfg *svr = (svr_cfg*) ap_get_module_config
        (cmd->server->module_config, &dbd_module);
    dbd_prepared *prepared = apr_pcalloc(cmd->pool, sizeof(dbd_prepared));
    prepared->label = label;
    prepared->query = query;
    prepared->next = svr->prepared;
    svr->prepared = prepared;
    return NULL;
}
static const command_rec dbd_cmds[] = {
    AP_INIT_TAKE1("DBDriver", dbd_param, (void*)cmd_name, RSRC_CONF,
                  "SQL Driver"),
    AP_INIT_TAKE1("DBDParams", dbd_param, (void*)cmd_params, RSRC_CONF,
                  "SQL Driver Params"),
    AP_INIT_TAKE1("DBDPersist", dbd_param, (void*)cmd_persist, RSRC_CONF,
                  "Use persistent connection/pool"),
    AP_INIT_TAKE2("DBDPrepareSQL", dbd_prepare, NULL, RSRC_CONF,
                  "Prepared SQL statement, label"),
#if APR_HAS_THREADS
    AP_INIT_TAKE1("DBDMin", dbd_param, (void*)cmd_min, RSRC_CONF,
                  "Minimum number of connections"),
    AP_INIT_TAKE1("DBDKeep", dbd_param, (void*)cmd_keep, RSRC_CONF,
                  "Maximum number of sustained connections"),
    AP_INIT_TAKE1("DBDMax", dbd_param, (void*)cmd_max, RSRC_CONF,
                  "Maximum number of connections"),
    AP_INIT_TAKE1("DBDExptime", dbd_param, (void*)cmd_exp, RSRC_CONF,
                  "Keepalive time for idle connections"),
#endif
    {NULL}
};
#define COND_PARAM(x,val) \
    if (cfg->x == val) {              \
        cfg->x = ((svr_cfg*)base)->x; \
    }
#define COND_PARAM0(x) COND_PARAM(x,0)
#define COND_PARAM1(x) COND_PARAM(x,-1)
static void *dbd_merge(apr_pool_t *pool, void *base, void *add) {
    svr_cfg *cfg = apr_pmemdup(pool, add, sizeof(svr_cfg));
    COND_PARAM0(name);
    COND_PARAM0(params);
    COND_PARAM1(persist);
#if APR_HAS_THREADS
    COND_PARAM0(nmin);
    COND_PARAM0(nkeep);
    COND_PARAM0(nmax);
    COND_PARAM0(exptime);
#endif
    return cfg;
}
#undef COND_PARAM
#undef COND_PARAM0
#undef COND_PARAM1
static void *dbd_cfg(apr_pool_t *p, server_rec *x)
{
    svr_cfg *svr = (svr_cfg*) apr_pcalloc(p, sizeof(svr_cfg));
    svr->persist = -1;
    return svr;
}
static apr_status_t dbd_prepared_init(apr_pool_t *pool, svr_cfg *svr,
                                      ap_dbd_t *dbd)
{
    dbd_prepared *p;
    apr_status_t ret = APR_SUCCESS;
    apr_dbd_prepared_t *stmt = NULL;
    dbd->prepared = apr_hash_make(pool);

    for (p = svr->prepared; p; p = p->next) {
        if (apr_dbd_prepare(dbd->driver, pool, dbd->handle, p->query,
                            p->label, &stmt) == 0) {
            apr_hash_set(dbd->prepared, p->label, APR_HASH_KEY_STRING, stmt);
        }
        else {
            ret = APR_EGENERAL;
        }
    }
    return ret;
}
#if APR_HAS_THREADS
/************ svr cfg: manage db connection pool ****************/
/* an apr_reslist_constructor for SQL connections */
static apr_status_t dbd_construct(void **db, void *params, apr_pool_t *pool)
{
    svr_cfg *svr = (svr_cfg*) params;
    ap_dbd_t *rec = apr_pcalloc(pool, sizeof(ap_dbd_t));
    apr_status_t rv = apr_dbd_get_driver(pool, svr->name, &rec->driver);

    rv = apr_dbd_open(rec->driver, pool, svr->params, &rec->handle);
    switch (rv) {
    case APR_EGENERAL:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: Can't connect to %s[%s]", svr->name, svr->params);
        return rv;
    }
    *db = rec;
    dbd_prepared_init(pool, svr, rec);
    return rv;
}
static apr_status_t dbd_destruct(void *sql, void *params, apr_pool_t *pool)
{
    ap_dbd_t *rec = sql;
    return apr_dbd_close(rec->driver, rec->handle);
}

static apr_status_t dbd_setup(apr_pool_t *pool, server_rec *s)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    apr_status_t rv = apr_reslist_create(&svr->dbpool, svr->nmin, svr->nkeep,
                                         svr->nmax, svr->exptime,
                                         dbd_construct, dbd_destruct,
                                         svr, pool);
    if (rv == APR_SUCCESS) {
        apr_pool_cleanup_register(pool, svr->dbpool,
                                  (void*)apr_reslist_destroy,
                                  apr_pool_cleanup_null);
    }
    else {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD Pool: failed to initialise");
    }
    return rv;
}

#endif


/* Functions we export for modules to use:
        - open acquires a connection from the pool (opens one if necessary)
        - close releases it back in to the pool
*/

#if APR_HAS_THREADS
ap_dbd_t* ap_dbd_open(apr_pool_t *pool, server_rec *s)
{
    ap_dbd_t *rec = NULL;
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    apr_status_t rv;
    const char *errmsg;

    if (!svr->persist) {
        rec = apr_pcalloc(pool, sizeof(ap_dbd_t));
        rv = apr_dbd_get_driver(pool, svr->name, &rec->driver);

        rv = apr_dbd_open(rec->driver, pool, svr->params, &rec->handle);
        switch (rv) {
        case APR_EGENERAL:
            ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                          "DBD: Can't connect to %s[%s]",
                          svr->name, svr->params);
            return NULL;
        }
        dbd_prepared_init(pool, svr, rec);
        return rec;
    }

    if (!svr->dbpool) {
        if (dbd_setup(s->process->pool, s) != APR_SUCCESS) {
            return NULL;
        }
    }
    if (apr_reslist_acquire(svr->dbpool, (void**)&rec) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                      "Failed to acquire DBD connection from pool!");
        return NULL;
    }
    if (apr_dbd_check_conn(rec->driver, pool, rec->handle) != APR_SUCCESS) {
        errmsg = apr_dbd_error(rec->driver, rec->handle, rv);
        if (!errmsg) {
            errmsg = "(unknown)";
        }
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                      "DBD[%s] Error: %s", svr->name, errmsg );
        apr_reslist_invalidate(svr->dbpool, rec);
        return NULL;
    }
    return rec;
}
#else
ap_dbd_t* ap_dbd_open(apr_pool_t *pool, server_rec *s)
{
    apr_status_t rv;
    const char *errmsg;
    ap_dbd_t *rec = NULL;
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);

    if (!svr->persist) {
        rec = apr_pcalloc(pool, sizeof(ap_dbd_t));
        rv = apr_dbd_get_driver(pool, svr->name, &rec->driver);

        rv = apr_dbd_open(rec->driver, pool, svr->params, &rec->handle);
        switch (rv) {
        case APR_EGENERAL:
            ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                          "DBD: Can't connect to %s[%s]",
                          svr->name, svr->params);
            return NULL;
        }
        dbd_prepared_init(pool, svr, rec);
        return rec;
    }
/* since we're in nothread-land, we can mess with svr->conn with impunity */
    if (svr->conn) {
        if (apr_dbd_check_conn(svr->conn->driver, pool, svr->conn->handle) != 0){
            errmsg = apr_dbd_error(rec->driver, rec->handle, rv);
            if (!errmsg) {
                errmsg = "(unknown)";
            }
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                          "DBD[%s] Error: %s", svr->name, errmsg);
            svr->conn = NULL;
        }
    }
    if (!svr->conn) {
        svr->conn = apr_pcalloc(pool, sizeof(ap_dbd_t));
        rv = apr_dbd_get_driver(pool, svr->name, &svr->conn->driver);

        rv = apr_dbd_open(svr->conn->driver, pool, svr->params,
                          &svr->conn->handle);
        switch (rv) {
        case APR_EGENERAL:
            ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                          "DBD: Can't connect to %s[%s]",
                          svr->name, svr->params);
            return NULL;
        }
        dbd_prepared_init(pool, svr, rec);
    }
    return svr->conn;
}
#endif
void ap_dbd_close(server_rec *s, ap_dbd_t *sql)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    if (!svr->persist) {
        apr_dbd_close(sql->driver, sql->handle);
    }
#if APR_HAS_THREADS
    else {
        apr_reslist_release(svr->dbpool, sql);
    }
#endif
}
#if APR_HAS_THREADS
typedef struct {
    ap_dbd_t *conn;
    apr_reslist_t *dbpool;
} dbd_pool_rec;
static apr_status_t dbd_release(void *REQ)
{
    dbd_pool_rec *req = REQ;
    apr_reslist_release(req->dbpool, req->conn);
    return APR_SUCCESS;
}
ap_dbd_t *ap_dbd_acquire(request_rec *r)
{
    svr_cfg *svr;
    dbd_pool_rec *req = ap_get_module_config(r->request_config, &dbd_module);
    if (!req) {
        req = apr_palloc(r->pool, sizeof(dbd_pool_rec));
        req->conn = ap_dbd_open(r->pool, r->server);
        if (req->conn) {
            svr = ap_get_module_config(r->server->module_config, &dbd_module);
            ap_set_module_config(r->request_config, &dbd_module, req);
            if (svr->persist) {
                req->dbpool = svr->dbpool;
                apr_pool_cleanup_register(r->pool, req, dbd_release,
                                          apr_pool_cleanup_null);
            }
            else {
                apr_pool_cleanup_register(r->pool, req->conn->handle,
                                          (void*)req->conn->driver->close,
                                          apr_pool_cleanup_null);
            }
        }
    }
    return req->conn;
}
#else
ap_dbd_t *ap_dbd_acquire(request_rec *r)
{
    svr_cfg *svr;
    ap_dbd_t *ret = ap_get_module_config(r->request_config, &dbd_module);
    if (!ret) {
        svr = ap_get_module_config(r->server->module_config, &dbd_module);
        ret = ap_dbd_open(r->pool, r->server);
        if ( ret ) {
            ap_set_module_config(r->request_config, &dbd_module, ret);
            if (!svr->persist) {
                apr_pool_cleanup_register(r->pool, svr->conn->handle,
                                          (void*)svr->conn->driver->close,
                                          apr_pool_cleanup_null);
            }
            /* if persist then dbd_open registered cleanup on proc pool */
        }
    }
    return ret;
}
#endif
static int dbd_token(apr_pool_t *pool,  apr_pool_t *p0,
                     apr_pool_t *p1, server_rec *s)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    if (svr && svr->name) {
        ap_add_version_component(pool, apr_psprintf(pool, "DBD:%s/%s",
                                                    svr->name, VERSION));
    }
    else {
        ap_add_version_component(pool, "DBD/" VERSION);
    }
    return OK;
}

static void dbd_hooks(apr_pool_t *pool)
{
#if APR_HAS_THREADS
    ap_hook_child_init((void*)dbd_setup, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_post_config(dbd_token, NULL, NULL, APR_HOOK_MIDDLE);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_open);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_close);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_acquire);
    apr_dbd_init(pool);
}

module AP_MODULE_DECLARE_DATA dbd_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    dbd_cfg,
    dbd_merge,
    dbd_cmds,
    dbd_hooks
};
