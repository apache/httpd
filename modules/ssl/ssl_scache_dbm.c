/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_scache_dbm.c
**  Session Cache via DBM
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */

#include "mod_ssl.h"

void ssl_scache_dbm_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_dbm_t *dbm;
    apr_status_t rv;

    /* for the DBM we need the data file */
    if (mc->szSessionCacheDataFile == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SSLSessionCache required");
        ssl_die();
    }

    /* open it once to create it and to make sure it _can_ be created */
    ssl_mutex_on(s);
    if ((rv = apr_dbm_open(&dbm, mc->szSessionCacheDataFile,
	    APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, mc->pPool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot create SSLSessionCache DBM file `%s'",
                     mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return;
    }
    apr_dbm_close(dbm);

#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
    /*
     * We have to make sure the Apache child processes have access to
     * the DBM file. But because there are brain-dead platforms where we
     * cannot exactly determine the suffixes we try all possibilities.
     */
    if (geteuid() == 0 /* is superuser */) {
        chown(mc->szSessionCacheDataFile, unixd_config.user_id, -1 /* no gid change */);
        if (chown(apr_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_DIR, NULL),
                  unixd_config.user_id, -1) == -1) {
            if (chown(apr_pstrcat(p, mc->szSessionCacheDataFile, ".db", NULL),
                      unixd_config.user_id, -1) == -1)
                chown(apr_pstrcat(p, mc->szSessionCacheDataFile, ".dir", NULL),
                      unixd_config.user_id, -1);
        }
        if (chown(apr_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_PAG, NULL),
                  unixd_config.user_id, -1) == -1) {
            if (chown(apr_pstrcat(p, mc->szSessionCacheDataFile, ".db", NULL),
                      unixd_config.user_id, -1) == -1)
                chown(apr_pstrcat(p, mc->szSessionCacheDataFile, ".pag", NULL),
                      unixd_config.user_id, -1);
        }
    }
#endif
    ssl_mutex_off(s);
    ssl_scache_dbm_expire(s);
    return;
}

void ssl_scache_dbm_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_pool_t *p;

    apr_pool_create_ex(&p, mc->pPool, NULL, NULL);
    if (p != NULL) {
        /* the correct way */
        unlink(apr_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_DIR, NULL));
        unlink(apr_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_PAG, NULL));
        /* the additional ways to be sure */
        unlink(apr_pstrcat(p, mc->szSessionCacheDataFile, ".dir", NULL));
        unlink(apr_pstrcat(p, mc->szSessionCacheDataFile, ".pag", NULL));
        unlink(apr_pstrcat(p, mc->szSessionCacheDataFile, ".db", NULL));
        unlink(mc->szSessionCacheDataFile);
        apr_pool_destroy(p);
    }
    return;
}

BOOL ssl_scache_dbm_store(server_rec *s, UCHAR *id, int idlen, time_t expiry, SSL_SESSION *sess)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    UCHAR ucaData[SSL_SESSION_MAX_DER];
    int nData;
    UCHAR *ucp;
    apr_status_t rv;

    /* streamline session data */
    if ((nData = i2d_SSL_SESSION(sess, NULL)) > sizeof(ucaData)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "streamline session data size too large: %d > "
                     "%" APR_SIZE_T_FMT,
                     nData, sizeof(ucaData));
        return FALSE;
    }
    ucp = ucaData;
    i2d_SSL_SESSION(sess, &ucp);

    /* be careful: do not try to store too much bytes in a DBM file! */
#ifdef PAIRMAX
    if ((idlen + nData) >= PAIRMAX) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "data size too large for DBM session cache: %d >= %d",
                 (idlen + nData), PAIRMAX);
        return FALSE;
    }
#else
    if ((idlen + nData) >= 950 /* at least less than approx. 1KB */) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "data size too large for DBM session cache: %d >= %d",
                 (idlen + nData), 950);
        return FALSE;
    }
#endif

    /* create DBM key */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* create DBM value */
    dbmval.dsize = sizeof(time_t) + nData;
    dbmval.dptr  = (char *)malloc(dbmval.dsize);
    if (dbmval.dptr == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "malloc error creating DBM value");
        return FALSE;
    }
    memcpy((char *)dbmval.dptr, &expiry, sizeof(time_t));
    memcpy((char *)dbmval.dptr+sizeof(time_t), ucaData, nData);

    /* and store it to the DBM file */
    ssl_mutex_on(s);
    if ((rv = apr_dbm_open(&dbm, mc->szSessionCacheDataFile,
	    APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, mc->pPool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot open SSLSessionCache DBM file `%s' for writing "
                     "(store)",
                     mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        free(dbmval.dptr);
        return FALSE;
    }
    if ((rv = apr_dbm_store(dbm, dbmkey, dbmval)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot store SSL session to DBM file `%s'",
                     mc->szSessionCacheDataFile);
        apr_dbm_close(dbm);
        ssl_mutex_off(s);
        free(dbmval.dptr);
        return FALSE;
    }
    apr_dbm_close(dbm);
    ssl_mutex_off(s);

    /* free temporary buffers */
    free(dbmval.dptr);

    /* allow the regular expiring to occur */
    ssl_scache_dbm_expire(s);

    return TRUE;
}

SSL_SESSION *ssl_scache_dbm_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    SSL_SESSION *sess = NULL;
    UCHAR *ucpData;
    int nData;
    time_t expiry;
    time_t now;
    apr_status_t rc;

    /* allow the regular expiring to occur */
    ssl_scache_dbm_expire(s);

    /* create DBM key and values */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* and fetch it from the DBM file 
     * XXX: Should we open the dbm against r->pool so the cleanup will
     * do the apr_dbm_close? This would make the code a bit cleaner.
     */
    ssl_mutex_on(s);
    if ((rc = apr_dbm_open(&dbm, mc->szSessionCacheDataFile,
	    APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, mc->pPool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s,
                     "Cannot open SSLSessionCache DBM file `%s' for reading "
                     "(fetch)",
                     mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return NULL;
    }
    rc = apr_dbm_fetch(dbm, dbmkey, &dbmval);
    if (rc != APR_SUCCESS) {
        apr_dbm_close(dbm);
        ssl_mutex_off(s);
        return NULL;
    }
    if (dbmval.dptr == NULL || dbmval.dsize <= sizeof(time_t)) {
        apr_dbm_close(dbm);
        ssl_mutex_off(s);
        return NULL;
    }

    /* parse resulting data */
    nData = dbmval.dsize-sizeof(time_t);
    ucpData = (UCHAR *)malloc(nData);
    if (ucpData == NULL) {
        apr_dbm_close(dbm);
        ssl_mutex_off(s);
        return NULL;
    }
    memcpy(ucpData, (char *)dbmval.dptr+sizeof(time_t), nData);
    memcpy(&expiry, dbmval.dptr, sizeof(time_t));

    apr_dbm_close(dbm);
    ssl_mutex_off(s);

    /* make sure the stuff is still not expired */
    now = time(NULL);
    if (expiry <= now) {
        ssl_scache_dbm_remove(s, id, idlen);
        return NULL;
    }

    /* unstreamed SSL_SESSION */
    sess = d2i_SSL_SESSION(NULL, &ucpData, nData);

    return sess;
}

void ssl_scache_dbm_remove(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_status_t rv;

    /* create DBM key and values */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* and delete it from the DBM file */
    ssl_mutex_on(s);
    if ((rv = apr_dbm_open(&dbm, mc->szSessionCacheDataFile,
	    APR_DBM_RWCREATE, SSL_DBM_FILE_MODE, mc->pPool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot open SSLSessionCache DBM file `%s' for writing "
                     "(delete)",
                     mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return;
    }
    apr_dbm_delete(dbm, dbmkey);
    apr_dbm_close(dbm);
    ssl_mutex_off(s);

    return;
}

void ssl_scache_dbm_expire(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    static time_t tLast = 0;
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    apr_pool_t *p;
    time_t tExpiresAt;
    int nElements = 0;
    int nDeleted = 0;
    int bDelete;
    apr_datum_t *keylist;
    int keyidx;
    int i;
    time_t tNow;
    apr_status_t rv;

    /*
     * make sure the expiration for still not-accessed session
     * cache entries is done only from time to time
     */
    tNow = time(NULL);
    if (tNow < tLast+sc->session_cache_timeout)
        return;
    tLast = tNow;

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

    ssl_mutex_on(s);
    for (;;) {
        /* allocate the key array in a memory sub pool */
        apr_pool_create_ex(&p, mc->pPool, NULL, NULL);
        if (p == NULL)
            break;
        if ((keylist = apr_palloc(p, sizeof(dbmkey)*KEYMAX)) == NULL) {
            apr_pool_destroy(p);
            break;
        }

        /* pass 1: scan DBM database */
        keyidx = 0;
        if ((rv = apr_dbm_open(&dbm, mc->szSessionCacheDataFile, 
                               APR_DBM_RWCREATE,SSL_DBM_FILE_MODE,
                               p)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot open SSLSessionCache DBM file `%s' for "
                         "scanning",
                         mc->szSessionCacheDataFile);
            apr_pool_destroy(p);
            break;
        }
        apr_dbm_firstkey(dbm, &dbmkey);
        while (dbmkey.dptr != NULL) {
            nElements++;
            bDelete = FALSE;
            apr_dbm_fetch(dbm, dbmkey, &dbmval);
            if (dbmval.dsize <= sizeof(time_t) || dbmval.dptr == NULL)
                bDelete = TRUE;
            else {
                memcpy(&tExpiresAt, dbmval.dptr, sizeof(time_t));
                if (tExpiresAt <= tNow)
                    bDelete = TRUE;
            }
            if (bDelete) {
                if ((keylist[keyidx].dptr = apr_palloc(p, dbmkey.dsize)) != NULL) {
                    memcpy(keylist[keyidx].dptr, dbmkey.dptr, dbmkey.dsize);
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
        if (apr_dbm_open(&dbm, mc->szSessionCacheDataFile,
		APR_DBM_RWCREATE,SSL_DBM_FILE_MODE, p) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot re-open SSLSessionCache DBM file `%s' for "
                         "expiring",
                         mc->szSessionCacheDataFile);
            apr_pool_destroy(p);
            break;
        }
        for (i = 0; i < keyidx; i++) {
            apr_dbm_delete(dbm, keylist[i]);
            nDeleted++;
        }
        apr_dbm_close(dbm);

        /* destroy temporary pool */
        apr_pool_destroy(p);

        if (keyidx < KEYMAX)
            break;
    }
    ssl_mutex_off(s);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "Inter-Process Session Cache (DBM) Expiry: "
                 "old: %d, new: %d, removed: %d",
                 nElements, nElements-nDeleted, nDeleted);
    return;
}

void ssl_scache_dbm_status(request_rec *r, int flags, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(r->server);
    apr_dbm_t *dbm;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    int nElem;
    int nSize;
    int nAverage;
    apr_status_t rv;

    nElem = 0;
    nSize = 0;
    ssl_mutex_on(r->server);
    /*
     * XXX - Check what pool is to be used - TBD
     */
    if ((rv = apr_dbm_open(&dbm, mc->szSessionCacheDataFile,
	                       APR_DBM_RWCREATE, SSL_DBM_FILE_MODE,
                           mc->pPool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "Cannot open SSLSessionCache DBM file `%s' for status "
                     "retrival",
                     mc->szSessionCacheDataFile);
        ssl_mutex_off(r->server);
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
        nElem += 1;
        nSize += dbmval.dsize;
    }
    apr_dbm_close(dbm);
    ssl_mutex_off(r->server);
    if (nSize > 0 && nElem > 0)
        nAverage = nSize / nElem;
    else
        nAverage = 0;
    ap_rprintf(r, "cache type: <b>DBM</b>, maximum size: <b>unlimited</b><br>");
    ap_rprintf(r, "current sessions: <b>%d</b>, current size: <b>%d</b> bytes<br>", nElem, nSize);
    ap_rprintf(r, "average session size: <b>%d</b> bytes<br>", nAverage);
    return;
}

