/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_scache_shmht.c
**  Session Cache via Shared Memory (Hash Table Variant)
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

/*
 *  Wrapper functions for table library which resemble malloc(3) & Co 
 *  but use the variants from the MM shared memory library.
 */

static void *ssl_scache_shmht_malloc(void *opt_param, size_t size)
{
    SSLModConfigRec *mc = myModConfig((server_rec *)opt_param);

    apr_rmm_off_t off = apr_rmm_calloc(mc->pSessionCacheDataRMM, size);
    return apr_rmm_addr_get(mc->pSessionCacheDataRMM, off);
}

static void *ssl_scache_shmht_calloc(void *opt_param,
                                     size_t number, size_t size)
{
    SSLModConfigRec *mc = myModConfig((server_rec *)opt_param);

    apr_rmm_off_t off = apr_rmm_calloc(mc->pSessionCacheDataRMM, (number*size));

    return apr_rmm_addr_get(mc->pSessionCacheDataRMM, off);
}

static void *ssl_scache_shmht_realloc(void *opt_param, void *ptr, size_t size)
{
    SSLModConfigRec *mc = myModConfig((server_rec *)opt_param);

    apr_rmm_off_t off = apr_rmm_realloc(mc->pSessionCacheDataRMM, ptr, size);
    return apr_rmm_addr_get(mc->pSessionCacheDataRMM, off);
}

static void ssl_scache_shmht_free(void *opt_param, void *ptr)
{
    SSLModConfigRec *mc = myModConfig((server_rec *)opt_param);

    apr_rmm_off_t off = apr_rmm_offset_get(mc->pSessionCacheDataRMM, ptr);
    apr_rmm_free(mc->pSessionCacheDataRMM, off);
    return;
}

/*
 * Now the actual session cache implementation
 * based on a hash table inside a shared memory segment.
 */

void ssl_scache_shmht_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    table_t *ta;
    int ta_errno;
    apr_size_t avail;
    int n;
    apr_status_t rv;

    /*
     * Create shared memory segment
     */
    if (mc->szSessionCacheDataFile == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SSLSessionCache required");
        ssl_die();
    }

    if ((rv = apr_shm_create(&(mc->pSessionCacheDataMM), 
                   mc->nSessionCacheDataSize, 
                   mc->szSessionCacheDataFile, mc->pPool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot allocate shared memory");
        ssl_die();
    }

    if ((rv = apr_rmm_init(&(mc->pSessionCacheDataRMM), NULL,
                   apr_shm_baseaddr_get(mc->pSessionCacheDataMM),
                   mc->nSessionCacheDataSize, mc->pPool)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Cannot initialize rmm");
        ssl_die();
    }
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                 "initialize MM %pp RMM %pp",
                 mc->pSessionCacheDataMM, mc->pSessionCacheDataRMM);

    /*
     * Create hash table in shared memory segment
     */
    avail = mc->nSessionCacheDataSize;
    n = (avail/2) / 1024;
    n = n < 10 ? 10 : n;

    /*
     * Passing server_rec as opt_param to table_alloc so that we can do
     * logging if required ssl_util_table. Otherwise, mc is sufficient.
     */ 
    if ((ta = table_alloc(n, &ta_errno, 
                          ssl_scache_shmht_malloc,  
                          ssl_scache_shmht_calloc, 
                          ssl_scache_shmht_realloc, 
                          ssl_scache_shmht_free, s )) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Cannot allocate hash table in shared memory: %s",
                     table_strerror(ta_errno));
        ssl_die();
    }

    table_attr(ta, TABLE_FLAG_AUTO_ADJUST|TABLE_FLAG_ADJUST_DOWN);
    table_set_data_alignment(ta, sizeof(char *));
    table_clear(ta);
    mc->tSessionCacheDataTable = ta;

    /*
     * Log the done work
     */
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, 
                 "Init: Created hash-table (%d buckets) "
                 "in shared memory (%" APR_SIZE_T_FMT 
                 " bytes) for SSL session cache",
                 n, avail);
    return;
}

void ssl_scache_shmht_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->pSessionCacheDataRMM != NULL) {
        apr_rmm_destroy(mc->pSessionCacheDataRMM);
        mc->pSessionCacheDataRMM = NULL;
    }

    if (mc->pSessionCacheDataMM != NULL) {
        apr_shm_destroy(mc->pSessionCacheDataMM);
        mc->pSessionCacheDataMM = NULL;
    }
    return;
}

BOOL ssl_scache_shmht_store(server_rec *s, UCHAR *id, int idlen, time_t expiry, SSL_SESSION *sess)
{
    SSLModConfigRec *mc = myModConfig(s);
    void *vp;
    UCHAR ucaData[SSL_SESSION_MAX_DER];
    int nData;
    UCHAR *ucp;

    /* streamline session data */
    if ((nData = i2d_SSL_SESSION(sess, NULL)) > sizeof(ucaData))
        return FALSE;
    ucp = ucaData;
    i2d_SSL_SESSION(sess, &ucp);

    ssl_mutex_on(s);
    if (table_insert_kd(mc->tSessionCacheDataTable, 
                        id, idlen, NULL, sizeof(time_t)+nData,
                        NULL, &vp, 1) != TABLE_ERROR_NONE) {
        ssl_mutex_off(s);
        return FALSE;
    }
    memcpy(vp, &expiry, sizeof(time_t));
    memcpy((char *)vp+sizeof(time_t), ucaData, nData);
    ssl_mutex_off(s);

    /* allow the regular expiring to occur */
    ssl_scache_shmht_expire(s);

    return TRUE;
}

SSL_SESSION *ssl_scache_shmht_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    void *vp;
    SSL_SESSION *sess = NULL;
    UCHAR *ucpData;
    int nData;
    time_t expiry;
    time_t now;
    int n;

    /* allow the regular expiring to occur */
    ssl_scache_shmht_expire(s);

    /* lookup key in table */
    ssl_mutex_on(s);
    if (table_retrieve(mc->tSessionCacheDataTable,
                       id, idlen, &vp, &n) != TABLE_ERROR_NONE) {
        ssl_mutex_off(s);
        return NULL;
    }

    /* copy over the information to the SCI */
    nData = n-sizeof(time_t);
    ucpData = (UCHAR *)malloc(nData);
    if (ucpData == NULL) {
        ssl_mutex_off(s);
        return NULL;
    }
    memcpy(&expiry, vp, sizeof(time_t));
    memcpy(ucpData, (char *)vp+sizeof(time_t), nData);
    ssl_mutex_off(s);

    /* make sure the stuff is still not expired */
    now = time(NULL);
    if (expiry <= now) {
        ssl_scache_shmht_remove(s, id, idlen);
        return NULL;
    }

    /* unstreamed SSL_SESSION */
    sess = d2i_SSL_SESSION(NULL, &ucpData, nData);

    return sess;
}

void ssl_scache_shmht_remove(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);

    /* remove value under key in table */
    ssl_mutex_on(s);
    table_delete(mc->tSessionCacheDataTable, id, idlen, NULL, NULL);
    ssl_mutex_off(s);
    return;
}

void ssl_scache_shmht_expire(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSLSrvConfigRec *sc = mySrvConfig(s);
    static time_t tLast = 0;
    table_linear_t iterator;
    time_t tExpiresAt;
    void *vpKey;
    void *vpKeyThis;
    void *vpData;
    int nKey;
    int nKeyThis;
    int nData;
    int nElements = 0;
    int nDeleted = 0;
    int bDelete;
    int rc;
    time_t tNow;

    /*
     * make sure the expiration for still not-accessed session
     * cache entries is done only from time to time
     */
    tNow = time(NULL);
    if (tNow < tLast+sc->session_cache_timeout)
        return;
    tLast = tNow;

    ssl_mutex_on(s);
    if (table_first_r(mc->tSessionCacheDataTable, &iterator,
                      &vpKey, &nKey, &vpData, &nData) == TABLE_ERROR_NONE) {
        do {
            bDelete = FALSE;
            nElements++;
            if (nData < sizeof(time_t) || vpData == NULL)
                bDelete = TRUE;
            else {
                memcpy(&tExpiresAt, vpData, sizeof(time_t));
                /* 
                 * XXX : Force the record to be cleaned up. TBD (Madhu)
                 * tExpiresAt = tNow;
                 */
                if (tExpiresAt <= tNow)
                   bDelete = TRUE;
            }
            vpKeyThis = vpKey;
            nKeyThis  = nKey;
            rc = table_next_r(mc->tSessionCacheDataTable, &iterator,
                              &vpKey, &nKey, &vpData, &nData);
            if (bDelete) {
                table_delete(mc->tSessionCacheDataTable,
                             vpKeyThis, nKeyThis, NULL, NULL);
                nDeleted++;
            }
        } while (rc == TABLE_ERROR_NONE); 
        /* (vpKeyThis != vpKey) && (nKeyThis != nKey) */
    }
    ssl_mutex_off(s);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "Inter-Process Session Cache (SHMHT) Expiry: "
                 "old: %d, new: %d, removed: %d",
                 nElements, nElements-nDeleted, nDeleted);
    return;
}

void ssl_scache_shmht_status(server_rec *s, apr_pool_t *p, void (*func)(char *, void *), void *arg)
{
    SSLModConfigRec *mc = myModConfig(s);
    void *vpKey;
    void *vpData;
    int nKey;
    int nData;
    int nElem;
    int nSize;
    int nAverage;

    nElem = 0;
    nSize = 0;
    ssl_mutex_on(s);
    if (table_first(mc->tSessionCacheDataTable,
                    &vpKey, &nKey, &vpData, &nData) == TABLE_ERROR_NONE) {
        do {
            if (vpKey == NULL || vpData == NULL)
                continue;
            nElem += 1;
            nSize += nData;
        } while (table_next(mc->tSessionCacheDataTable,
                        &vpKey, &nKey, &vpData, &nData) == TABLE_ERROR_NONE);
    }
    ssl_mutex_off(s);
    if (nSize > 0 && nElem > 0)
        nAverage = nSize / nElem;
    else
        nAverage = 0;
    func(apr_psprintf(p, "cache type: <b>SHMHT</b>, maximum size: <b>%d</b> bytes<br>", mc->nSessionCacheDataSize), arg);
    func(apr_psprintf(p, "current sessions: <b>%d</b>, current size: <b>%d</b> bytes<br>", nElem, nSize), arg);
    func(apr_psprintf(p, "average session size: <b>%d</b> bytes<br>", nAverage), arg);
    return;
}
