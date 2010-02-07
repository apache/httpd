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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_engine_mutex.c
 *  Semaphore for Mutual Exclusion
 */
                             /* ``Real programmers confuse
                                  Christmas and Halloween
                                  because DEC 25 = OCT 31.''
                                             -- Unknown     */

#include "ssl_private.h"

int ssl_mutex_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    /* A mutex is only needed if a session cache is configured, and
     * the provider used is not internally multi-process/thread
     * safe. */
    if (!mc->sesscache
        || (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) == 0) {
        return TRUE;
    }

    if (mc->pMutex) {
        return TRUE;
    }

    if ((rv = ap_global_mutex_create(&mc->pMutex, SSL_CACHE_MUTEX_TYPE, NULL,
                                     s, s->process->pool, 0))
            != APR_SUCCESS) {
        return FALSE;
    }

    return TRUE;
}

int ssl_mutex_reinit(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;
    const char *lockfile;

    if (mc->pMutex == NULL || !mc->sesscache
        || (mc->sesscache->flags & AP_SOCACHE_FLAG_NOTMPSAFE) == 0) {
        return TRUE;
    }

    lockfile = apr_global_mutex_lockfile(mc->pMutex);
    if ((rv = apr_global_mutex_child_init(&mc->pMutex,
                                          lockfile,
                                          p)) != APR_SUCCESS) {
        if (lockfile)
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot reinit %s mutex with file `%s'",
                         SSL_CACHE_MUTEX_TYPE, lockfile);
        else
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                         "Cannot reinit %s mutex", SSL_CACHE_MUTEX_TYPE);
        return FALSE;
    }
    return TRUE;
}

int ssl_mutex_on(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if ((rv = apr_global_mutex_lock(mc->pMutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                     "Failed to acquire SSL session cache lock");
        return FALSE;
    }
    return TRUE;
}

int ssl_mutex_off(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if ((rv = apr_global_mutex_unlock(mc->pMutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                     "Failed to release SSL session cache lock");
        return FALSE;
    }
    return TRUE;
}

