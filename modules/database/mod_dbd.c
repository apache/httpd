/* Copyright 2003-5 The Apache Software Foundation or its licensors, as
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
    const apr_dbd_driver_t *driver = NULL;
    svr_cfg *svr = (svr_cfg*) ap_get_module_config
        (cmd->server->module_config, &dbd_module);

    switch ((long) cmd->info) {
    case cmd_name:
        svr->name = val;
        /* loading the driver involves once-only dlloading that is
         * best done at server startup.  This also guarantees that
         * we won't return an error later.
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
AP_DECLARE(void) ap_dbd_prepare(server_rec *s, const char *query,
                                const char *label)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    dbd_prepared *prepared = apr_pcalloc(s->process->pool, sizeof(dbd_prepared));
    prepared->label = label;
    prepared->query = query;
    prepared->next = svr->prepared;
    svr->prepared = prepared;
}
static const char *dbd_prepare(cmd_parms *cmd, void *cfg, const char *query,
                               const char *label)
{
    ap_dbd_prepare(cmd->server, query, label);
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
#define DEFAULT_NMIN 0
#define DEFAULT_NMAX 5
#define DEFAULT_NKEEP 1
#define DEFAULT_EXPTIME 120
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
    COND_PARAM(nmin, DEFAULT_NMIN);
    COND_PARAM(nkeep, DEFAULT_NKEEP);
    COND_PARAM(nmax, DEFAULT_NMAX);
    COND_PARAM(exptime, DEFAULT_EXPTIME);
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
    svr->name = svr->params = ""; /* don't risk segfault on misconfiguration */
#if APR_HAS_THREADS
    svr->nmin = DEFAULT_NMIN;
    svr->nkeep = DEFAULT_NKEEP;
    svr->nmax = DEFAULT_NMAX;
    svr->exptime = DEFAULT_EXPTIME;
#endif
    return svr;
}
static apr_status_t dbd_prepared_init(apr_pool_t *pool, svr_cfg *svr,
                                      ap_dbd_t *dbd)
{
    dbd_prepared *p;
    apr_status_t ret = APR_SUCCESS;
    apr_dbd_prepared_t *stmt;
    dbd->prepared = apr_hash_make(pool);

    for (p = svr->prepared; p; p = p->next) {
        stmt = NULL;
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
/************ svr cfg: manage db connection pool ****************/
/* an apr_reslist_constructor for SQL connections
 * Also use this for opening in non-reslist modes, since it gives
 * us all the error-handling in one place.
 */
static apr_status_t dbd_construct(void **db, void *params, apr_pool_t *pool)
{
    svr_cfg *svr = (svr_cfg*) params;
    ap_dbd_t *rec = apr_pcalloc(pool, sizeof(ap_dbd_t));
    apr_status_t rv = apr_dbd_get_driver(pool, svr->name, &rec->driver);

/* Error-checking get_driver isn't necessary now (because it's done at
 * config-time).  But in case that changes in future ...
 */
    switch (rv) {
    case APR_ENOTIMPL:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: driver for %s not available", svr->name);
        return rv;
    case APR_EDSOOPEN:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: can't find driver for %s", svr->name);
        return rv;
    case APR_ESYMNOTFOUND:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: driver for %s is invalid or corrupted", svr->name);
        return rv;
    default:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: mod_dbd not compatible with apr in get_driver");
        return rv;
    case APR_SUCCESS:
        break;
    }

    rv = apr_dbd_open(rec->driver, pool, svr->params, &rec->handle);
    switch (rv) {
    case APR_EGENERAL:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: Can't connect to %s[%s]", svr->name, svr->params);
        return rv;
    default:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool,
                      "DBD: mod_dbd not compatible with apr in open");
        return rv;
    case APR_SUCCESS:
        break;
    }
    *db = rec;
    rv = dbd_prepared_init(pool, svr, rec);
    return rv;
}
#if APR_HAS_THREADS
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
AP_DECLARE(void) ap_dbd_close(server_rec *s, ap_dbd_t *sql)
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
static apr_status_t dbd_close(void *CONN)
{
    ap_dbd_t *conn = CONN;
    return apr_dbd_close(conn->driver, conn->handle);
}
#define arec ((ap_dbd_t*)rec)
#if APR_HAS_THREADS
AP_DECLARE(ap_dbd_t*) ap_dbd_open(apr_pool_t *pool, server_rec *s)
{
    void *rec = NULL;
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    apr_status_t rv = APR_SUCCESS;
    const char *errmsg;

    if (!svr->persist) {
        /* Return a once-only connection */
        rv = dbd_construct(&rec, svr, s->process->pool);
        return (rv == APR_SUCCESS) ? arec : NULL;
    }

    if (!svr->dbpool) {
        if (dbd_setup(s->process->pool, s) != APR_SUCCESS) {
            return NULL;
        }
    }
    if (apr_reslist_acquire(svr->dbpool, &rec) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                      "Failed to acquire DBD connection from pool!");
        return NULL;
    }
    rv = apr_dbd_check_conn(arec->driver, pool, arec->handle);
    if ((rv != APR_SUCCESS) && (rv != APR_ENOTIMPL)) {
        errmsg = apr_dbd_error(arec->driver, arec->handle, rv);
        if (!errmsg) {
            errmsg = "(unknown)";
        }
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                      "DBD[%s] Error: %s", svr->name, errmsg );
        apr_reslist_invalidate(svr->dbpool, rec);
        return NULL;
    }
    return arec;
}
#else
AP_DECLARE(ap_dbd_t*) ap_dbd_open(apr_pool_t *pool, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    const char *errmsg;
    void *rec = NULL;
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);

    if (!svr->persist) {
        /* Return a once-only connection */
        rv = dbd_construct(&rec, svr, s->process->pool);
        return (rv == APR_SUCCESS) ? arec : NULL;
    }

/* since we're in nothread-land, we can mess with svr->conn with impunity */
/* If we have a persistent connection and it's good, we'll use it */
    if (svr->conn) {
        rv = apr_dbd_check_conn(svr->conn->driver, pool, svr->conn->handle);
        if ((rv != APR_SUCCESS) && (rv != APR_ENOTIMPL)) {
            errmsg = apr_dbd_error(arec->driver, arec->handle, rv);
            if (!errmsg) {
                errmsg = "(unknown)";
            }
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool,
                          "DBD[%s] Error: %s", svr->name, errmsg);
            svr->conn = NULL;
        }
    }
/* We don't have a connection right now, so we'll open one */
    if (!svr->conn) {
        if (dbd_construct(&rec, svr, s->process->pool) == APR_SUCCESS) {
            svr->conn = arec ;
            apr_pool_cleanup_register(s->process->pool, svr->conn,
                                      dbd_close, apr_pool_cleanup_null);
        }
    }
    return svr->conn;
}
#endif
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
AP_DECLARE(ap_dbd_t *) ap_dbd_acquire(request_rec *r)
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
                apr_pool_cleanup_register(r->pool, req->conn, dbd_close,
                                          apr_pool_cleanup_null);
            }
        }
    }
    return req->conn;
}
AP_DECLARE(ap_dbd_t *) ap_dbd_cacquire(conn_rec *c)
{
    svr_cfg *svr;
    dbd_pool_rec *req = ap_get_module_config(c->conn_config, &dbd_module);
    if (!req) {
        req = apr_palloc(c->pool, sizeof(dbd_pool_rec));
        req->conn = ap_dbd_open(c->pool, c->base_server);
        if (req->conn) {
            svr = ap_get_module_config(c->base_server->module_config, &dbd_module);
            ap_set_module_config(c->conn_config, &dbd_module, req);
            if (svr->persist) {
                req->dbpool = svr->dbpool;
                apr_pool_cleanup_register(c->pool, req, dbd_release,
                                          apr_pool_cleanup_null);
            }
            else {
                apr_pool_cleanup_register(c->pool, req->conn, dbd_close,
                                          apr_pool_cleanup_null);
            }
        }
    }
    return req->conn;
}
#else
AP_DECLARE(ap_dbd_t *) ap_dbd_acquire(request_rec *r)
{
    svr_cfg *svr;
    ap_dbd_t *ret = ap_get_module_config(r->request_config, &dbd_module);
    if (!ret) {
        svr = ap_get_module_config(r->server->module_config, &dbd_module);
        ret = ap_dbd_open(r->pool, r->server);
        if (ret) {
            ap_set_module_config(r->request_config, &dbd_module, ret);
            if (!svr->persist) {
                apr_pool_cleanup_register(r->pool, svr->conn, dbd_close,
                                          apr_pool_cleanup_null);
            }
            /* if persist then dbd_open registered cleanup on proc pool */
        }
    }
    return ret;
}
AP_DECLARE(ap_dbd_t *) ap_dbd_cacquire(conn_rec *c)
{
    svr_cfg *svr;
    ap_dbd_t *ret = ap_get_module_config(c->conn_config, &dbd_module);
    if (!ret) {
        svr = ap_get_module_config(c->base_server->module_config, &dbd_module);
        ret = ap_dbd_open(c->pool, c->base_server);
        if (ret) {
            ap_set_module_config(c->conn_config, &dbd_module, ret);
            if (!svr->persist) {
                apr_pool_cleanup_register(c->pool, svr->conn, dbd_close,
                                          apr_pool_cleanup_null);
            }
            /* if persist then dbd_open registered cleanup on proc pool */
        }
    }
    return ret;
}
#endif

static void dbd_hooks(apr_pool_t *pool)
{
#if APR_HAS_THREADS
    ap_hook_child_init((void*)dbd_setup, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    APR_REGISTER_OPTIONAL_FN(ap_dbd_open);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_close);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_acquire);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_cacquire);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_prepare);
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
