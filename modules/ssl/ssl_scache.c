/*                      _             _
**  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
** | | | | | | (_) | (_| |   \__ \__ \ |  www.modssl.org
** |_| |_| |_|\___/ \__,_|___|___/___/_|  ftp.modssl.org
**                      |_____|
**  ssl_scache.c
**  Session Cache Abstraction
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
                             /* ``Open-Source Software: generous
                                  programmers from around the world all
                                  join forces to help you shoot
                                  yourself in the foot for free.''
                                                 -- Unknown         */
#include "mod_ssl.h"

/*  _________________________________________________________________
**
**  Session Cache: Common Abstraction Layer
**  _________________________________________________________________
*/

void ssl_scache_init(server_rec *s, pool *p)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_init(s, p);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_init(s, p);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_init(s, p);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_init",
                    AP_HOOK_SIG3(void,ptr,ptr), AP_HOOK_ALL, s, p);
#endif
    return;
}

void ssl_scache_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_kill(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_kill(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_kill(s);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_kill",
                    AP_HOOK_SIG2(void,ptr), AP_HOOK_ALL, s);
#endif
    return;
}

BOOL ssl_scache_store(server_rec *s, UCHAR *id, int idlen, time_t expiry, SSL_SESSION *sess)
{
    SSLModConfigRec *mc = myModConfig();
    BOOL rv = FALSE;

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        rv = ssl_scache_dbm_store(s, id, idlen, expiry, sess);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        rv = ssl_scache_shmht_store(s, id, idlen, expiry, sess);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        rv = ssl_scache_shmcb_store(s, id, idlen, expiry, sess);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_store",
                    AP_HOOK_SIG6(int,ptr,ptr,int,int,ptr), AP_HOOK_ALL,
                    (int *)&rv, s, id, idlen, (int)expiry, sess);
#endif
    return rv;
}

SSL_SESSION *ssl_scache_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig();
    SSL_SESSION *sess = NULL;

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        sess = ssl_scache_dbm_retrieve(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        sess = ssl_scache_shmht_retrieve(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        sess = ssl_scache_shmcb_retrieve(s, id, idlen);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_retrieve",
                    AP_HOOK_SIG4(ptr,ptr,ptr,int), AP_HOOK_ALL, 
                    &sess, s, id, idlen);
#endif
    return sess;
}

void ssl_scache_remove(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_remove(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_remove(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_remove(s, id, idlen);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_remove",
                    AP_HOOK_SIG4(void,ptr,ptr,int), AP_HOOK_ALL, s, id, idlen);
#endif
    return;
}

void ssl_scache_status(server_rec *s, pool *p, void (*func)(char *, void *), void *arg)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_status(s, p, func, arg);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_status(s, p, func, arg);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_status(s, p, func, arg);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_status",
                    AP_HOOK_SIG5(void,ptr,ptr,ptr,ptr), AP_HOOK_ALL, 
                    s, p, func, arg);
#endif
    return;
}

void ssl_scache_expire(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig();

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_expire(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_expire(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_expire(s);
#ifdef SSL_VENDOR
    else
        ap_hook_use("ap::mod_ssl::vendor::scache_expire",
                    AP_HOOK_SIG2(void,ptr), AP_HOOK_ALL, s);
#endif
    return;
}

