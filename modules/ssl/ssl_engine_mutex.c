/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_engine_mutex.c
**  Semaphore for Mutual Exclusion
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
                             /* ``Real programmers confuse
                                  Christmas and Halloween
                                  because DEC 25 = OCT 31.''
                                             -- Unknown     */
#include "mod_ssl.h"
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
#include "unixd.h"
#endif

int ssl_mutex_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if (mc->nMutexMode == SSL_MUTEXMODE_NONE) 
        return TRUE;

    if ((rv = apr_global_mutex_create(&mc->pMutex, mc->szMutexFile,
                                mc->nMutexMech, p)) != APR_SUCCESS) {
        if (mc->szMutexFile)
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot create SSLMutex with file `%s'",
                         mc->szMutexFile);
        else
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot create SSLMutex");
        return FALSE;
    }
#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
    if (mc->szMutexFile && mc->ChownMutexFile == TRUE)
        chown(mc->szMutexFile, unixd_config.user_id, -1);
#endif

#if APR_HAS_SYSVSEM_SERIALIZE
#if APR_USE_SYSVSEM_SERIALIZE
    if (mc->nMutexMech == APR_LOCK_DEFAULT || 
        mc->nMutexMech == APR_LOCK_SYSVSEM) {
#else
    if (mc->nMutexMech == APR_LOCK_SYSVSEM) {
#endif
        rv = unixd_set_global_mutex_perms(mc->pMutex);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Could not set permissions on ssl_mutex; check User "
                         "and Group directives");
            return FALSE;
        }
    }
#endif
    return TRUE;
}

int ssl_mutex_reinit(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if (mc->nMutexMode == SSL_MUTEXMODE_NONE)
        return TRUE;

    if ((rv = apr_global_mutex_child_init(&mc->pMutex,
                                    mc->szMutexFile, p)) != APR_SUCCESS) {
        if (mc->szMutexFile)
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "Cannot reinit SSLMutex with file `%s'",
                         mc->szMutexFile);
        else
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                         "Cannot reinit SSLMutex");
        return FALSE;
    }
    return TRUE;
}

int ssl_mutex_on(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if (mc->nMutexMode == SSL_MUTEXMODE_NONE)
        return TRUE;
    if ((rv = apr_global_mutex_lock(mc->pMutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                     "Failed to acquire global mutex lock");
        return FALSE;
    }
    return TRUE;
}

int ssl_mutex_off(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;

    if (mc->nMutexMode == SSL_MUTEXMODE_NONE)
        return TRUE;
    if ((rv = apr_global_mutex_unlock(mc->pMutex)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
                     "Failed to release global mutex lock");
        return FALSE;
    }
    return TRUE;
}

