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

/* Overview of what this is and does:
 * http://www.apache.org/~niq/dbd.html
 * or
 * http://apache.webthing.com/database/
 */

#include <ctype.h>

#include "http_protocol.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_reslist.h"
#include "apr_strings.h"
#include "apr_dbd.h"
#include "mod_dbd.h"

extern module AP_MODULE_DECLARE_DATA dbd_module;

/************ svr cfg: manage db connection pool ****************/

#define NMIN_SET     0x1
#define NKEEP_SET    0x2
#define NMAX_SET     0x4
#define EXPTIME_SET  0x8

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
    apr_thread_mutex_t *mutex;
    apr_pool_t *pool;
    apr_reslist_t *dbpool;
    int nmin;
    int nkeep;
    int nmax;
    int exptime;
#else
    ap_dbd_t *conn;
#endif
    unsigned int set;
} svr_cfg;

typedef enum { cmd_name, cmd_params, cmd_persist,
               cmd_min, cmd_keep, cmd_max, cmd_exp
} cmd_parts;

static apr_hash_t *dbd_prepared_defns;

/* a default DBDriver value that'll generate meaningful error messages */
static const char *const no_dbdriver = "[DBDriver unset]";

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
#if APR_HAS_THREADS
    case cmd_min:
        ISINT(val);
        svr->nmin = atoi(val);
        svr->set |= NMIN_SET;
        break;
    case cmd_keep:
        ISINT(val);
        svr->nkeep = atoi(val);
        svr->set |= NKEEP_SET;
        break;
    case cmd_max:
        ISINT(val);
        svr->nmax = atoi(val);
        svr->set |= NMAX_SET;
        break;
    case cmd_exp:
        ISINT(val);
        svr->exptime = atoi(val);
        svr->set |= EXPTIME_SET;
        break;
#endif
    }
    return NULL;
}
static const char *dbd_param_flag(cmd_parms *cmd, void *cfg, int flag)
{
    svr_cfg *svr = (svr_cfg*) ap_get_module_config
        (cmd->server->module_config, &dbd_module);

    switch ((long) cmd->info) {
    case cmd_persist:
        svr->persist = flag;
        break;
    }
    return NULL;
}
DBD_DECLARE_NONSTD(void) ap_dbd_prepare(server_rec *s, const char *query,
                                        const char *label)
{
    dbd_prepared *prepared = apr_pcalloc(s->process->pool, sizeof(dbd_prepared));
    const char *key = apr_psprintf(s->process->pool, "%pp", s);
    prepared->label = label;
    prepared->query = query;
    prepared->next = apr_hash_get(dbd_prepared_defns, key, APR_HASH_KEY_STRING);
    apr_hash_set(dbd_prepared_defns, key, APR_HASH_KEY_STRING, prepared);
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
    AP_INIT_FLAG("DBDPersist", dbd_param_flag, (void*)cmd_persist, RSRC_CONF,
                 "Use persistent connection/pool"),
    AP_INIT_TAKE2("DBDPrepareSQL", dbd_prepare, NULL, RSRC_CONF,
                  "Prepared SQL statement, label"),
#if APR_HAS_THREADS
    AP_INIT_TAKE1("DBDMin", dbd_param, (void*)cmd_min, RSRC_CONF,
                  "Minimum number of connections"),
    /* XXX: note that mod_proxy calls this "smax" */
    AP_INIT_TAKE1("DBDKeep", dbd_param, (void*)cmd_keep, RSRC_CONF,
                  "Maximum number of sustained connections"),
    AP_INIT_TAKE1("DBDMax", dbd_param, (void*)cmd_max, RSRC_CONF,
                  "Maximum number of connections"),
    /* XXX: note that mod_proxy calls this "ttl" (time to live) */
    AP_INIT_TAKE1("DBDExptime", dbd_param, (void*)cmd_exp, RSRC_CONF,
                  "Keepalive time for idle connections"),
#endif
    {NULL}
};
static void *dbd_merge(apr_pool_t *pool, void *BASE, void *ADD) {
    svr_cfg *base = (svr_cfg*) BASE;
    svr_cfg *add = (svr_cfg*) ADD;
    svr_cfg *cfg = apr_pcalloc(pool, sizeof(svr_cfg));
    cfg->name = (add->name != no_dbdriver) ? add->name : base->name;
    cfg->params = strcmp(add->params, "") ? add->params : base->params;
    cfg->persist = (add->persist == -1) ? base->persist : add->persist;
#if APR_HAS_THREADS
    cfg->nmin = (add->set&NMIN_SET) ? add->nmin : base->nmin;
    cfg->nkeep = (add->set&NKEEP_SET) ? add->nkeep : base->nkeep;
    cfg->nmax = (add->set&NMAX_SET) ? add->nmax : base->nmax;
    cfg->exptime = (add->set&EXPTIME_SET) ? add->exptime : base->exptime;
#endif
    cfg->set = add->set | base->set;
    cfg->prepared = (add->prepared != NULL) ? add->prepared : base->prepared;
    return (void*) cfg;
}
/* A default nmin of >0 will help with generating meaningful
 * startup error messages if the database is down.
 */
#define DEFAULT_NMIN 1
#define DEFAULT_NKEEP 2
#define DEFAULT_NMAX 10
#define DEFAULT_EXPTIME 300
static void *dbd_cfg(apr_pool_t *p, server_rec *x)
{
    svr_cfg *svr = (svr_cfg*) apr_pcalloc(p, sizeof(svr_cfg));
    svr->params = ""; /* don't risk segfault on misconfiguration */
    svr->name = no_dbdriver; /* to generate meaningful error messages */
    svr->persist = -1;
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
    apr_status_t rv;

    /* this pool is mostly so dbd_close can destroy the prepared stmts */
    rv = apr_pool_create(&rec->pool, pool);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pool,
                      "DBD: Failed to create memory pool");
    }

/* The driver is loaded at config time now, so this just checks a hash.
 * If that changes, the driver DSO could be registered to unload against
 * our pool, which is probably not what we want.  Error checking isn't
 * necessary now, but in case that changes in the future ...
 */
    rv = apr_dbd_get_driver(rec->pool, svr->name, &rec->driver);
    switch (rv) {
    case APR_ENOTIMPL:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: driver for %s not available", svr->name);
        return rv;
    case APR_EDSOOPEN:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: can't find driver for %s", svr->name);
        return rv;
    case APR_ESYMNOTFOUND:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: driver for %s is invalid or corrupted", svr->name);
        return rv;
    default:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: mod_dbd not compatible with apr in get_driver");
        return rv;
    case APR_SUCCESS:
        break;
    }

    rv = apr_dbd_open(rec->driver, rec->pool, svr->params, &rec->handle);
    switch (rv) {
    case APR_EGENERAL:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: Can't connect to %s", svr->name);
        return rv;
    default:
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: mod_dbd not compatible with apr in open");
        return rv;
    case APR_SUCCESS:
        break;
    }
    *db = rec;
    rv = dbd_prepared_init(rec->pool, svr, rec);
    if (rv != APR_SUCCESS) {
        const char *errmsg = apr_dbd_error(rec->driver, rec->handle, rv);
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, rec->pool,
                      "DBD: failed to initialise prepared SQL statements: %s",
                      (errmsg ? errmsg : "[???]"));
    }
    return rv;
}
static apr_status_t dbd_close(void *CONN)
{
    ap_dbd_t *conn = CONN;
    apr_status_t rv = apr_dbd_close(conn->driver, conn->handle);
    apr_pool_destroy(conn->pool);
    return rv;
}
#if APR_HAS_THREADS
static apr_status_t dbd_destruct(void *sql, void *params, apr_pool_t *pool)
{
    return dbd_close(sql);
}

static apr_status_t dbd_setup(apr_pool_t *pool, svr_cfg *svr)
{
    apr_status_t rv;

    /* create a pool just for the reslist from a process-lifetime pool;
     * that pool (s->process->pool in the dbd_setup_lock case,
     * whatever was passed to ap_run_child_init in the dbd_setup_init case)
     * will be shared with other threads doing other non-mod_dbd things
     * so we can't use it for the reslist directly
     */
    rv = apr_pool_create(&svr->pool, pool);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pool,
                      "DBD: Failed to create reslist memory pool");
        return rv;
    }

    rv = apr_reslist_create(&svr->dbpool, svr->nmin, svr->nkeep, svr->nmax,
                            apr_time_from_sec(svr->exptime),
                            dbd_construct, dbd_destruct, svr, svr->pool);
    if (rv == APR_SUCCESS) {
        apr_pool_cleanup_register(svr->pool, svr->dbpool,
                                  (void*)apr_reslist_destroy,
                                  apr_pool_cleanup_null);
    }
    else {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, svr->pool,
                      "DBD: failed to initialise");
        apr_pool_destroy(svr->pool);
        svr->pool = NULL;
    }

    return rv;
}
static apr_status_t dbd_setup_init(apr_pool_t *pool, server_rec *s)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    apr_status_t rv;

    /* dbd_setup in 2.2.3 and under was causing spurious error messages
     * when dbd isn't configured.  We can stop that with a quick check here
     * together with a similar check in ap_dbd_open (where being
     * unconfigured is a genuine error that must be reported).
     */
    if (svr->name == no_dbdriver) {
        return APR_SUCCESS;
    }

    if (!svr->persist) {
        return APR_SUCCESS;
    }

    rv = dbd_setup(pool, svr);
    if (rv == APR_SUCCESS) {
        return rv;
    }

    /* we failed, so create a mutex so that subsequent competing callers
     * to ap_dbd_open can serialize themselves while they retry
     */
    rv = apr_thread_mutex_create(&svr->mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pool,
                      "DBD: Failed to create thread mutex");
    }
    return rv;
}
static apr_status_t dbd_setup_lock(apr_pool_t *pool, server_rec *s)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    apr_status_t rv, rv2 = APR_SUCCESS;

    /* several threads could be here at the same time, all trying to
     * initialize the reslist because dbd_setup_init failed to do so
     */
    if (!svr->mutex) {
        /* we already logged an error when the mutex couldn't be created */
        return APR_EGENERAL;
    }

    rv = apr_thread_mutex_lock(svr->mutex);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pool,
                      "DBD: Failed to acquire thread mutex");
        return rv;
    }

    if (!svr->dbpool) {
        rv2 = dbd_setup(s->process->pool, svr);
    }

    rv = apr_thread_mutex_unlock(svr->mutex);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pool,
                      "DBD: Failed to release thread mutex");
        if (rv2 == APR_SUCCESS) {
            rv2 = rv;
        }
    }
    return rv2;
}
#endif


/* Functions we export for modules to use:
        - open acquires a connection from the pool (opens one if necessary)
        - close releases it back in to the pool
*/
DBD_DECLARE_NONSTD(void) ap_dbd_close(server_rec *s, ap_dbd_t *sql)
{
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    if (!svr->persist) {
        dbd_close((void*) sql);
    }
#if APR_HAS_THREADS
    else {
        apr_reslist_release(svr->dbpool, sql);
    }
#endif
}
#define arec ((ap_dbd_t*)rec)
#if APR_HAS_THREADS
DBD_DECLARE_NONSTD(ap_dbd_t*) ap_dbd_open(apr_pool_t *pool, server_rec *s)
{
    void *rec = NULL;
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);
    apr_status_t rv = APR_SUCCESS;
    const char *errmsg;

    /* If nothing is configured, we shouldn't be here */
    if (svr->name == no_dbdriver) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "DBD: not configured");
        return NULL;
    }

    if (!svr->persist) {
        /* Return a once-only connection */
        rv = dbd_construct(&rec, svr, s->process->pool);
        return (rv == APR_SUCCESS) ? arec : NULL;
    }

    if (!svr->dbpool) {
        if (dbd_setup_lock(pool, s) != APR_SUCCESS) {
            return NULL;
        }
    }
    rv = apr_reslist_acquire(svr->dbpool, &rec);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, pool,
                      "Failed to acquire DBD connection from pool!");
        return NULL;
    }
    rv = apr_dbd_check_conn(arec->driver, pool, arec->handle);
    if ((rv != APR_SUCCESS) && (rv != APR_ENOTIMPL)) {
        errmsg = apr_dbd_error(arec->driver, arec->handle, rv);
        if (!errmsg) {
            errmsg = "(unknown)";
        }
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, pool,
                      "DBD[%s] Error: %s", svr->name, errmsg );
        apr_reslist_invalidate(svr->dbpool, rec);
        return NULL;
    }
    return arec;
}
#else
DBD_DECLARE_NONSTD(ap_dbd_t*) ap_dbd_open(apr_pool_t *pool, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    const char *errmsg;
    void *rec = NULL;
    svr_cfg *svr = ap_get_module_config(s->module_config, &dbd_module);

    /* If nothing is configured, we shouldn't be here */
    if (svr->name == no_dbdriver) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, "DBD: not configured");
        return NULL;
    }

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
            ap_log_perror(APLOG_MARK, APLOG_ERR, rv, pool,
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
DBD_DECLARE_NONSTD(ap_dbd_t *) ap_dbd_acquire(request_rec *r)
{
    svr_cfg *svr;
    dbd_pool_rec *req;

    while (!ap_is_initial_req(r)) {
        if (r->prev) {
            r = r->prev;
        }
        else if (r->main) {
            r = r->main;
        }
    }

    req = ap_get_module_config(r->request_config, &dbd_module);
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
DBD_DECLARE_NONSTD(ap_dbd_t *) ap_dbd_cacquire(conn_rec *c)
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
DBD_DECLARE_NONSTD(ap_dbd_t *) ap_dbd_acquire(request_rec *r)
{
    svr_cfg *svr;
    ap_dbd_t *ret;

    while (!ap_is_initial_req(r)) {
        if (r->prev) {
            r = r->prev;
        }
        else if (r->main) {
            r = r->main;
        }
    }

    ret = ap_get_module_config(r->request_config, &dbd_module);
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
DBD_DECLARE_NONSTD(ap_dbd_t *) ap_dbd_cacquire(conn_rec *c)
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

static int dbd_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
   dbd_prepared_defns = apr_hash_make(ptemp);
   return OK;
}
static int dbd_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp, server_rec *s)
{
    svr_cfg *svr;
    server_rec *sp;
    for (sp = s; sp; sp = sp->next) {
        const char *key = apr_psprintf(s->process->pool, "%pp", s);
        svr = ap_get_module_config(sp->module_config, &dbd_module);
        svr->prepared = apr_hash_get(dbd_prepared_defns, key,
                                     APR_HASH_KEY_STRING);
    }
    return OK;
}
static void dbd_hooks(apr_pool_t *pool)
{
#if APR_HAS_THREADS
    ap_hook_child_init((void*)dbd_setup_init, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    APR_REGISTER_OPTIONAL_FN(ap_dbd_open);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_close);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_acquire);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_cacquire);
    APR_REGISTER_OPTIONAL_FN(ap_dbd_prepare);
    apr_dbd_init(pool);
    ap_hook_pre_config(dbd_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(dbd_post_config, NULL, NULL, APR_HOOK_MIDDLE);
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
