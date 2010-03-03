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

#include "httpd.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_config.h"
#include "mpm_common.h"

#include "apr.h"
#include "apr_strings.h"
#include "apr_time.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_dbm.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ap_socache.h"

#if AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

/* Use of the context structure must be thread-safe after the initial
 * create/init; callers must hold the mutex. */
struct ap_socache_instance_t {
    const char *data_file;
    /* Pool must only be used with the mutex held. */
    apr_pool_t *pool;
    apr_time_t last_expiry;
    apr_interval_time_t expiry_interval;
};

/**
 * Support for DBM library
 */
#define DBM_FILE_MODE ( APR_UREAD | APR_UWRITE | APR_GREAD | APR_WREAD )

/* Check for definition of DEFAULT_REL_RUNTIMEDIR */
#ifndef DEFAULT_REL_RUNTIMEDIR
#define DEFAULT_DBM_PREFIX "logs/socache-dbm-"
#else
#define DEFAULT_DBM_PREFIX DEFAULT_REL_RUNTIMEDIR "/socache-dbm-"
#endif

/* ### this should use apr_dbm_usednames. */
#if !defined(DBM_FILE_SUFFIX_DIR) && !defined(DBM_FILE_SUFFIX_PAG)
#if defined(DBM_SUFFIX)
#define DBM_FILE_SUFFIX_DIR DBM_SUFFIX
#define DBM_FILE_SUFFIX_PAG DBM_SUFFIX
#elif defined(__FreeBSD__) || (defined(DB_LOCK) && defined(DB_SHMEM))
#define DBM_FILE_SUFFIX_DIR ".db"
#define DBM_FILE_SUFFIX_PAG ".db"
#else
#define DBM_FILE_SUFFIX_DIR ".dir"
#define DBM_FILE_SUFFIX_PAG ".pag"
#endif
#endif

static void socache_dbm_expire(ap_socache_instance_t *ctx, server_rec *s);

static apr_status_t socache_dbm_remove(ap_socache_instance_t *ctx, 
                                       server_rec *s, const unsigned char *id, 
                                       unsigned int idlen, apr_pool_t *p);

static const char *socache_dbm_create(ap_socache_instance_t **context, 
                                      const char *arg, 
                                      apr_pool_t *tmp, apr_pool_t *p)
{
    ap_socache_instance_t *ctx;

    *context = ctx = apr_pcalloc(p, sizeof *ctx);

    if (arg && *arg) {
        ctx->data_file = ap_server_root_relative(p, arg);
        if (!ctx->data_file) {
            return apr_psprintf(tmp, "Invalid cache file path %s", arg);
        }
    }

    apr_pool_create(&ctx->pool, p);

    return NULL;
}

static apr_status_t socache_dbm_init(ap_socache_instance_t *ctx, 
                                     const char *namespace, 
                                     const struct ap_socache_hints *hints,
                                     server_rec *s, apr_pool_t *p)
{
    apr_dbm_t *dbm;
    apr_status_t rv;

    /* for the DBM we need the data file */
    if (ctx->data_file == NULL) {
        const char *path = apr_pstrcat(p, DEFAULT_DBM_PREFIX, namespace,
                                       NULL);

        ctx->data_file = ap_server_root_relative(p, path);

        if (ctx->data_file == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "could not use default path '%s' for DBM socache",
                         path);
            return APR_EINVAL;
        }
    }

    /* open it once to create it and to make sure it _can_ be created */
    apr_pool_clear(ctx->pool);

    if ((rv = apr_dbm_open(&dbm, ctx->data_file,
            APR_DBM_RWCREATE, DBM_FILE_MODE, ctx->pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot create socache DBM file `%s'",
                     ctx->data_file);
        return rv;
    }
    apr_dbm_close(dbm);

    ctx->expiry_interval = (hints && hints->expiry_interval 
                            ? hints->expiry_interval : apr_time_from_sec(30));

#if AP_NEED_SET_MUTEX_PERMS
    /*
     * We have to make sure the Apache child processes have access to
     * the DBM file. But because there are brain-dead platforms where we
     * cannot exactly determine the suffixes we try all possibilities.
     */
    if (geteuid() == 0 /* is superuser */) {
        chown(ctx->data_file, ap_unixd_config.user_id, -1 /* no gid change */);
        if (chown(apr_pstrcat(p, ctx->data_file, DBM_FILE_SUFFIX_DIR, NULL),
                  ap_unixd_config.user_id, -1) == -1) {
            if (chown(apr_pstrcat(p, ctx->data_file, ".db", NULL),
                      ap_unixd_config.user_id, -1) == -1)
                chown(apr_pstrcat(p, ctx->data_file, ".dir", NULL),
                      ap_unixd_config.user_id, -1);
        }
        if (chown(apr_pstrcat(p, ctx->data_file, DBM_FILE_SUFFIX_PAG, NULL),
                  ap_unixd_config.user_id, -1) == -1) {
            if (chown(apr_pstrcat(p, ctx->data_file, ".db", NULL),
                      ap_unixd_config.user_id, -1) == -1)
                chown(apr_pstrcat(p, ctx->data_file, ".pag", NULL),
                      ap_unixd_config.user_id, -1);
        }
    }
#endif
    socache_dbm_expire(ctx, s);

    return APR_SUCCESS;
}

static void socache_dbm_kill(ap_socache_instance_t *ctx, server_rec *s)
{
    /* the correct way */
    unlink(apr_pstrcat(ctx->pool, ctx->data_file, DBM_FILE_SUFFIX_DIR, NULL));
    unlink(apr_pstrcat(ctx->pool, ctx->data_file, DBM_FILE_SUFFIX_PAG, NULL));
    /* the additional ways to be sure */
    unlink(apr_pstrcat(ctx->pool, ctx->data_file, ".dir", NULL));
    unlink(apr_pstrcat(ctx->pool, ctx->data_file, ".pag", NULL));
    unlink(apr_pstrcat(ctx->pool, ctx->data_file, ".db", NULL));
    unlink(ctx->data_file);

    return;
}

static apr_status_t socache_dbm_store(ap_socache_instance_t *ctx, 
                                      server_rec *s, const unsigned char *id, 
                                      unsigned int idlen, apr_time_t expiry, 
                                      unsigned char *ucaData, 
                                      unsigned int nData, apr_pool_t *pool)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_status_t rv;

    /* be careful: do not try to store too much bytes in a DBM file! */
#ifdef PAIRMAX
    if ((idlen + nData) >= PAIRMAX) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "data size too large for DBM socache: %d >= %d",
                 (idlen + nData), PAIRMAX);
        return APR_ENOSPC;
    }
#else
    if ((idlen + nData) >= 950 /* at least less than approx. 1KB */) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "data size too large for DBM socache: %d >= %d",
                 (idlen + nData), 950);
        return APR_ENOSPC;
    }
#endif

    /* create DBM key */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* create DBM value */
    dbmval.dsize = sizeof(apr_time_t) + nData;
    dbmval.dptr  = (char *)malloc(dbmval.dsize);
    if (dbmval.dptr == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "malloc error creating DBM value");
        return APR_ENOMEM;
    }
    memcpy((char *)dbmval.dptr, &expiry, sizeof(apr_time_t));
    memcpy((char *)dbmval.dptr+sizeof(apr_time_t), ucaData, nData);

    /* and store it to the DBM file */
    apr_pool_clear(ctx->pool);

    if ((rv = apr_dbm_open(&dbm, ctx->data_file,
                           APR_DBM_RWCREATE, DBM_FILE_MODE, ctx->pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot open socache DBM file `%s' for writing "
                     "(store)",
                     ctx->data_file);
        free(dbmval.dptr);
        return rv;
    }
    if ((rv = apr_dbm_store(dbm, dbmkey, dbmval)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot store socache object to DBM file `%s'",
                     ctx->data_file);
        apr_dbm_close(dbm);
        free(dbmval.dptr);
        return rv;
    }
    apr_dbm_close(dbm);

    /* free temporary buffers */
    free(dbmval.dptr);

    /* allow the regular expiring to occur */
    socache_dbm_expire(ctx, s);

    return APR_SUCCESS;
}

static apr_status_t socache_dbm_retrieve(ap_socache_instance_t *ctx, server_rec *s, 
                                         const unsigned char *id, unsigned int idlen,
                                         unsigned char *dest, unsigned int *destlen,
                                         apr_pool_t *p)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    unsigned int nData;
    apr_time_t expiry;
    apr_time_t now;
    apr_status_t rc;

    /* allow the regular expiring to occur */
    socache_dbm_expire(ctx, s);

    /* create DBM key and values */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* and fetch it from the DBM file
     * XXX: Should we open the dbm against r->pool so the cleanup will
     * do the apr_dbm_close? This would make the code a bit cleaner.
     */
    apr_pool_clear(ctx->pool);
    if ((rc = apr_dbm_open(&dbm, ctx->data_file, APR_DBM_RWCREATE, 
                           DBM_FILE_MODE, ctx->pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s,
                     "Cannot open socache DBM file `%s' for reading "
                     "(fetch)",
                     ctx->data_file);
        return rc;
    }
    rc = apr_dbm_fetch(dbm, dbmkey, &dbmval);
    if (rc != APR_SUCCESS) {
        apr_dbm_close(dbm);
        return rc;
    }
    if (dbmval.dptr == NULL || dbmval.dsize <= sizeof(apr_time_t)) {
        apr_dbm_close(dbm);
        return APR_EGENERAL;
    }

    /* parse resulting data */
    nData = dbmval.dsize-sizeof(apr_time_t);
    if (nData > *destlen) {
        apr_dbm_close(dbm);
        return APR_ENOSPC;
    }    

    *destlen = nData;
    memcpy(&expiry, dbmval.dptr, sizeof(apr_time_t));
    memcpy(dest, (char *)dbmval.dptr + sizeof(apr_time_t), nData);

    apr_dbm_close(dbm);

    /* make sure the stuff is still not expired */
    now = apr_time_now();
    if (expiry <= now) {
        socache_dbm_remove(ctx, s, id, idlen, p);
        return APR_NOTFOUND;
    }

    return APR_SUCCESS;
}

static apr_status_t socache_dbm_remove(ap_socache_instance_t *ctx, 
                                       server_rec *s, const unsigned char *id,
                                       unsigned int idlen, apr_pool_t *p)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_status_t rv;

    /* create DBM key and values */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* and delete it from the DBM file */
    apr_pool_clear(ctx->pool);

    if ((rv = apr_dbm_open(&dbm, ctx->data_file, APR_DBM_RWCREATE, 
                           DBM_FILE_MODE, ctx->pool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot open socache DBM file `%s' for writing "
                     "(delete)",
                     ctx->data_file);
        return rv;
    }
    apr_dbm_delete(dbm, dbmkey);
    apr_dbm_close(dbm);

    return APR_SUCCESS;
}

static void socache_dbm_expire(ap_socache_instance_t *ctx, server_rec *s)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_time_t expiry;
    int elts = 0;
    int deleted = 0;
    int expired;
    apr_datum_t *keylist;
    int keyidx;
    int i;
    apr_time_t now;
    apr_status_t rv;

    /*
     * make sure the expiration for still not-accessed
     * socache entries is done only from time to time
     */
    now = time(NULL);

    if (now < ctx->last_expiry + ctx->expiry_interval) {
        return;
    }

    ctx->last_expiry = now;

    /*
     * Here we have to be very carefully: Not all DBM libraries are
     * smart enough to allow one to iterate over the elements and at the
     * same time delete expired ones. Some of them get totally crazy
     * while others have no problems. So we have to do it the slower but
     * more safe way: we first iterate over all elements and remember
     * those which have to be expired. Then in a second pass we delete
     * all those expired elements. Additionally we reopen the DBM file
     * to be really safe in state.
     */

#define KEYMAX 1024

    for (;;) {
        /* allocate the key array in a memory sub pool */
        apr_pool_clear(ctx->pool);

        if ((keylist = apr_palloc(ctx->pool, sizeof(dbmkey)*KEYMAX)) == NULL) {
            break;
        }

        /* pass 1: scan DBM database */
        keyidx = 0;
        if ((rv = apr_dbm_open(&dbm, ctx->data_file, APR_DBM_RWCREATE,
                               DBM_FILE_MODE, ctx->pool)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot open socache DBM file `%s' for "
                         "scanning",
                         ctx->data_file);
            break;
        }
        apr_dbm_firstkey(dbm, &dbmkey);
        while (dbmkey.dptr != NULL) {
            elts++;
            expired = FALSE;
            apr_dbm_fetch(dbm, dbmkey, &dbmval);
            if (dbmval.dsize <= sizeof(apr_time_t) || dbmval.dptr == NULL)
                expired = TRUE;
            else {
                memcpy(&expiry, dbmval.dptr, sizeof(apr_time_t));
                if (expiry <= now)
                    expired = TRUE;
            }
            if (expired) {
                if ((keylist[keyidx].dptr = apr_pmemdup(ctx->pool, dbmkey.dptr, dbmkey.dsize)) != NULL) {
                    keylist[keyidx].dsize = dbmkey.dsize;
                    keyidx++;
                    if (keyidx == KEYMAX)
                        break;
                }
            }
            apr_dbm_nextkey(dbm, &dbmkey);
        }
        apr_dbm_close(dbm);

        /* pass 2: delete expired elements */
        if (apr_dbm_open(&dbm, ctx->data_file, APR_DBM_RWCREATE,
                         DBM_FILE_MODE, ctx->pool) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot re-open socache DBM file `%s' for "
                         "expiring",
                         ctx->data_file);
            break;
        }
        for (i = 0; i < keyidx; i++) {
            apr_dbm_delete(dbm, keylist[i]);
            deleted++;
        }
        apr_dbm_close(dbm);

        if (keyidx < KEYMAX)
            break;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "DBM socache expiry: "
                 "old: %d, new: %d, removed: %d",
                 elts, elts-deleted, deleted);
}

static void socache_dbm_status(ap_socache_instance_t *ctx, request_rec *r, 
                               int flags)
{
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    int elts;
    long size;
    int avg;
    apr_status_t rv;

    elts = 0;
    size = 0;

    apr_pool_clear(ctx->pool);
    if ((rv = apr_dbm_open(&dbm, ctx->data_file, APR_DBM_RWCREATE, 
                           DBM_FILE_MODE, ctx->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "Cannot open socache DBM file `%s' for status "
                     "retrival",
                     ctx->data_file);
        return;
    }
    /*
     * XXX - Check the return value of apr_dbm_firstkey, apr_dbm_fetch - TBD
     */
    apr_dbm_firstkey(dbm, &dbmkey);
    for ( ; dbmkey.dptr != NULL; apr_dbm_nextkey(dbm, &dbmkey)) {
        apr_dbm_fetch(dbm, dbmkey, &dbmval);
        if (dbmval.dptr == NULL)
            continue;
        elts += 1;
        size += dbmval.dsize;
    }
    apr_dbm_close(dbm);
    if (size > 0 && elts > 0)
        avg = (int)(size / (long)elts);
    else
        avg = 0;
    ap_rprintf(r, "cache type: <b>DBM</b>, maximum size: <b>unlimited</b><br>");
    ap_rprintf(r, "current entries: <b>%d</b>, current size: <b>%ld</b> bytes<br>", elts, size);
    ap_rprintf(r, "average entry size: <b>%d</b> bytes<br>", avg);
    return;
}

static apr_status_t socache_dbm_iterate(ap_socache_instance_t *instance,
                                        server_rec *s,
                                        ap_socache_iterator_t *iterator,
                                        apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

static const ap_socache_provider_t socache_dbm = {
    "dbm",
    AP_SOCACHE_FLAG_NOTMPSAFE,
    socache_dbm_create,
    socache_dbm_init,
    socache_dbm_kill,
    socache_dbm_store,
    socache_dbm_retrieve,
    socache_dbm_remove,
    socache_dbm_status,
    socache_dbm_iterate
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "dbm", 
                         AP_SOCACHE_PROVIDER_VERSION,
                         &socache_dbm);
}

module AP_MODULE_DECLARE_DATA socache_dbm_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL, NULL,
    register_hooks
};
