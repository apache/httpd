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
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include "mod_ssl.h"

void ssl_scache_dbm_init(server_rec *s, pool *p)
{
    SSLModConfigRec *mc = myModConfig();
    DBM *dbm;

    /* for the DBM we need the data file */
    if (mc->szSessionCacheDataFile == NULL) {
        ssl_log(s, SSL_LOG_ERROR, "SSLSessionCache required");
        ssl_die();
    }

    /* open it once to create it and to make sure it _can_ be created */
    ssl_mutex_on(s);
    if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                            O_RDWR|O_CREAT, SSL_DBM_FILE_MODE)) == NULL) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Cannot create SSLSessionCache DBM file `%s'",
                mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return;
    }
    ssl_dbm_close(dbm);

#if !defined(OS2) && !defined(WIN32)
    /*
     * We have to make sure the Apache child processes have access to
     * the DBM file. But because there are brain-dead platforms where we
     * cannot exactly determine the suffixes we try all possibilities.
     */
    if (geteuid() == 0 /* is superuser */) {
        chown(mc->szSessionCacheDataFile, ap_user_id, -1 /* no gid change */);
        if (chown(ap_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_DIR, NULL),
                  ap_user_id, -1) == -1) {
            if (chown(ap_pstrcat(p, mc->szSessionCacheDataFile, ".db", NULL),
                      ap_user_id, -1) == -1)
                chown(ap_pstrcat(p, mc->szSessionCacheDataFile, ".dir", NULL),
                      ap_user_id, -1);
        }
        if (chown(ap_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_PAG, NULL),
                  ap_user_id, -1) == -1) {
            if (chown(ap_pstrcat(p, mc->szSessionCacheDataFile, ".db", NULL),
                      ap_user_id, -1) == -1)
                chown(ap_pstrcat(p, mc->szSessionCacheDataFile, ".pag", NULL),
                      ap_user_id, -1);
        }
    }
#endif
    ssl_mutex_off(s);
    ssl_scache_dbm_expire(s);
    return;
}

void ssl_scache_dbm_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();
    pool *p;

    if ((p = ap_make_sub_pool(NULL)) != NULL) {
        /* the correct way */
        unlink(ap_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_DIR, NULL));
        unlink(ap_pstrcat(p, mc->szSessionCacheDataFile, SSL_DBM_FILE_SUFFIX_PAG, NULL));
        /* the additional ways to be sure */
        unlink(ap_pstrcat(p, mc->szSessionCacheDataFile, ".dir", NULL));
        unlink(ap_pstrcat(p, mc->szSessionCacheDataFile, ".pag", NULL));
        unlink(ap_pstrcat(p, mc->szSessionCacheDataFile, ".db", NULL));
        unlink(mc->szSessionCacheDataFile);
        ap_destroy_pool(p);
    }
    return;
}

BOOL ssl_scache_dbm_store(server_rec *s, UCHAR *id, int idlen, time_t expiry, SSL_SESSION *sess)
{
    SSLModConfigRec *mc = myModConfig();
    DBM *dbm;
    datum dbmkey;
    datum dbmval;
    UCHAR ucaData[SSL_SESSION_MAX_DER];
    int nData;
    UCHAR *ucp;

    /* streamline session data */
    ucp = ucaData;
    nData = i2d_SSL_SESSION(sess, &ucp);

    /* be careful: do not try to store too much bytes in a DBM file! */
#ifdef SSL_USE_SDBM
    if ((idlen + nData) >= PAIRMAX)
        return FALSE;
#else
    if ((idlen + nData) >= 950 /* at least less than approx. 1KB */)
        return FALSE;
#endif

    /* create DBM key */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* create DBM value */
    dbmval.dsize = sizeof(time_t) + nData;
    dbmval.dptr  = (char *)malloc(dbmval.dsize);
    if (dbmval.dptr == NULL)
        return FALSE;
    memcpy((char *)dbmval.dptr, &expiry, sizeof(time_t));
    memcpy((char *)dbmval.dptr+sizeof(time_t), ucaData, nData);

    /* and store it to the DBM file */
    ssl_mutex_on(s);
    if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                            O_RDWR, SSL_DBM_FILE_MODE)) == NULL) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Cannot open SSLSessionCache DBM file `%s' for writing (store)",
                mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        free(dbmval.dptr);
        return FALSE;
    }
    if (ssl_dbm_store(dbm, dbmkey, dbmval, DBM_INSERT) < 0) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Cannot store SSL session to DBM file `%s'",
                mc->szSessionCacheDataFile);
        ssl_dbm_close(dbm);
        ssl_mutex_off(s);
        free(dbmval.dptr);
        return FALSE;
    }
    ssl_dbm_close(dbm);
    ssl_mutex_off(s);

    /* free temporary buffers */
    free(dbmval.dptr);

    /* allow the regular expiring to occur */
    ssl_scache_dbm_expire(s);

    return TRUE;
}

SSL_SESSION *ssl_scache_dbm_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig();
    DBM *dbm;
    datum dbmkey;
    datum dbmval;
    SSL_SESSION *sess = NULL;
    UCHAR *ucpData;
    int nData;
    time_t expiry;
    time_t now;

    /* allow the regular expiring to occur */
    ssl_scache_dbm_expire(s);

    /* create DBM key and values */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* and fetch it from the DBM file */
    ssl_mutex_on(s);
    if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                            O_RDONLY, SSL_DBM_FILE_MODE)) == NULL) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Cannot open SSLSessionCache DBM file `%s' for reading (fetch)",
                mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return NULL;
    }
    dbmval = ssl_dbm_fetch(dbm, dbmkey);
    ssl_dbm_close(dbm);
    ssl_mutex_off(s);

    /* immediately return if not found */
    if (dbmval.dptr == NULL || dbmval.dsize <= sizeof(time_t))
        return NULL;

    /* parse resulting data */
    nData = dbmval.dsize-sizeof(time_t);
    ucpData = (UCHAR *)malloc(nData);
    if (ucpData == NULL) 
        return NULL;
    memcpy(ucpData, (char *)dbmval.dptr+sizeof(time_t), nData);
    memcpy(&expiry, dbmval.dptr, sizeof(time_t));

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
    SSLModConfigRec *mc = myModConfig();
    DBM *dbm;
    datum dbmkey;

    /* create DBM key and values */
    dbmkey.dptr  = (char *)id;
    dbmkey.dsize = idlen;

    /* and delete it from the DBM file */
    ssl_mutex_on(s);
    if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                            O_RDWR, SSL_DBM_FILE_MODE)) == NULL) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Cannot open SSLSessionCache DBM file `%s' for writing (delete)",
                mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return;
    }
    ssl_dbm_delete(dbm, dbmkey);
    ssl_dbm_close(dbm);
    ssl_mutex_off(s);

    return;
}

void ssl_scache_dbm_expire(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();
    SSLSrvConfigRec *sc = mySrvConfig(s);
    static time_t tLast = 0;
    DBM *dbm;
    datum dbmkey;
    datum dbmval;
    pool *p;
    time_t tExpiresAt;
    int nElements = 0;
    int nDeleted = 0;
    int bDelete;
    datum *keylist;
    int keyidx;
    int i;
    time_t tNow;

    /*
     * make sure the expiration for still not-accessed session
     * cache entries is done only from time to time
     */
    tNow = time(NULL);
    if (tNow < tLast+sc->nSessionCacheTimeout)
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
        if ((p = ap_make_sub_pool(NULL)) == NULL)
            break;
        if ((keylist = ap_palloc(p, sizeof(dbmkey)*KEYMAX)) == NULL) {
            ap_destroy_pool(p);
            break;
        }

        /* pass 1: scan DBM database */
        keyidx = 0;
        if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                                O_RDWR, SSL_DBM_FILE_MODE)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                    "Cannot open SSLSessionCache DBM file `%s' for scanning",
                    mc->szSessionCacheDataFile);
            ap_destroy_pool(p);
            break;
        }
        dbmkey = ssl_dbm_firstkey(dbm);
        while (dbmkey.dptr != NULL) {
            nElements++;
            bDelete = FALSE;
            dbmval = ssl_dbm_fetch(dbm, dbmkey);
            if (dbmval.dsize <= sizeof(time_t) || dbmval.dptr == NULL)
                bDelete = TRUE;
            else {
                memcpy(&tExpiresAt, dbmval.dptr, sizeof(time_t));
                if (tExpiresAt <= tNow)
                    bDelete = TRUE;
            }
            if (bDelete) {
                if ((keylist[keyidx].dptr = ap_palloc(p, dbmkey.dsize)) != NULL) {
                    memcpy(keylist[keyidx].dptr, dbmkey.dptr, dbmkey.dsize);
                    keylist[keyidx].dsize = dbmkey.dsize;
                    keyidx++;
                    if (keyidx == KEYMAX)
                        break;
                }
            }
            dbmkey = ssl_dbm_nextkey(dbm);
        }
        ssl_dbm_close(dbm);

        /* pass 2: delete expired elements */
        if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                                O_RDWR, SSL_DBM_FILE_MODE)) == NULL) {
            ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                    "Cannot re-open SSLSessionCache DBM file `%s' for expiring",
                    mc->szSessionCacheDataFile);
            ap_destroy_pool(p);
            break;
        }
        for (i = 0; i < keyidx; i++) {
            ssl_dbm_delete(dbm, keylist[i]);
            nDeleted++;
        }
        ssl_dbm_close(dbm);

        /* destroy temporary pool */
        ap_destroy_pool(p);

        if (keyidx < KEYMAX)
            break;
    }
    ssl_mutex_off(s);

    ssl_log(s, SSL_LOG_TRACE, "Inter-Process Session Cache (DBM) Expiry: "
            "old: %d, new: %d, removed: %d", nElements, nElements-nDeleted, nDeleted);
    return;
}

void ssl_scache_dbm_status(server_rec *s, pool *p, void (*func)(char *, void *), void *arg)
{
    SSLModConfigRec *mc = myModConfig();
    DBM *dbm;
    datum dbmkey;
    datum dbmval;
    int nElem;
    int nSize;
    int nAverage;

    nElem = 0;
    nSize = 0;
    ssl_mutex_on(s);
    if ((dbm = ssl_dbm_open(mc->szSessionCacheDataFile,
                            O_RDONLY, SSL_DBM_FILE_MODE)) == NULL) {
        ssl_log(s, SSL_LOG_ERROR|SSL_ADD_ERRNO,
                "Cannot open SSLSessionCache DBM file `%s' for status retrival",
                mc->szSessionCacheDataFile);
        ssl_mutex_off(s);
        return;
    }
    dbmkey = ssl_dbm_firstkey(dbm);
    for ( ; dbmkey.dptr != NULL; dbmkey = ssl_dbm_nextkey(dbm)) {
        dbmval = ssl_dbm_fetch(dbm, dbmkey);
        if (dbmval.dptr == NULL)
            continue;
        nElem += 1;
        nSize += dbmval.dsize;
    }
    ssl_dbm_close(dbm);
    ssl_mutex_off(s);
    if (nSize > 0 && nElem > 0)
        nAverage = nSize / nElem;
    else
        nAverage = 0;
    func(ap_psprintf(p, "cache type: <b>DBM</b>, maximum size: <b>unlimited</b><br>"), arg);
    func(ap_psprintf(p, "current sessions: <b>%d</b>, current size: <b>%d</b> bytes<br>", nElem, nSize), arg);
    func(ap_psprintf(p, "average session size: <b>%d</b> bytes<br>", nAverage), arg);
    return;
}

