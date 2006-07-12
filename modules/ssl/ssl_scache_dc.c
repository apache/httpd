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
 *  ssl_scache_dc.c
 *  Distributed Session Cache (client support)
 */

#include "ssl_private.h"

/* Only build this code if it's enabled at configure-time. */
#ifdef HAVE_DISTCACHE

#include "distcache/dc_client.h"

#if !defined(DISTCACHE_CLIENT_API) || (DISTCACHE_CLIENT_API < 0x0001)
#error "You must compile with a more recent version of the distcache-base package"
#endif

/*
 * This cache implementation allows modssl to access 'distcache' servers (or
 * proxies) to facilitate distributed session caching. It is based on code
 * released as open source by Cryptographic Appliances Inc, and was developed by
 * Geoff Thorpe, Steve Robb, and Chris Zimmerman.
 */

/*
**
** High-Level "handlers" as per ssl_scache.c
**
*/

void ssl_scache_dc_init(server_rec *s, apr_pool_t *p)
{
    DC_CTX *ctx;
    SSLModConfigRec *mc = myModConfig(s);
    /*
     * Create a session context
     */
    if (mc->szSessionCacheDataFile == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SSLSessionCache required");
        ssl_die();
    }
#if 0
    /* If a "persistent connection" mode of operation is preferred, you *must*
     * also use the PIDCHECK flag to ensure fork()'d processes don't interlace
     * comms on the same connection as each other. */
#define SESSION_CTX_FLAGS        SESSION_CTX_FLAG_PERSISTENT | \
                                 SESSION_CTX_FLAG_PERSISTENT_PIDCHECK | \
                                 SESSION_CTX_FLAG_PERSISTENT_RETRY | \
                                 SESSION_CTX_FLAG_PERSISTENT_LATE
#else
    /* This mode of operation will open a temporary connection to the 'target'
     * for each cache operation - this makes it safe against fork()
     * automatically. This mode is preferred when running a local proxy (over
     * unix domain sockets) because overhead is negligable and it reduces the
     * performance/stability danger of file-descriptor bloatage. */
#define SESSION_CTX_FLAGS        0
#endif
    ctx = DC_CTX_new(mc->szSessionCacheDataFile, SESSION_CTX_FLAGS);
    if (!ctx) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache failed to obtain context");
        ssl_die();
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "distributed scache context initialised");
    /*
     * Success ...
     */
    mc->tSessionCacheDataTable = ctx;
    return;
}

void ssl_scache_dc_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->tSessionCacheDataTable)
        DC_CTX_free(mc->tSessionCacheDataTable);
    mc->tSessionCacheDataTable = NULL;
}

BOOL ssl_scache_dc_store(server_rec *s, UCHAR *id, int idlen,
                           time_t timeout, SSL_SESSION * pSession)
{
    unsigned char der[SSL_SESSION_MAX_DER];
    int der_len;
    unsigned char *pder = der;
    SSLModConfigRec *mc = myModConfig(s);
    DC_CTX *ctx = mc->tSessionCacheDataTable;

    /* Serialise the SSL_SESSION object */
    if ((der_len = i2d_SSL_SESSION(pSession, NULL)) > SSL_SESSION_MAX_DER)
        return FALSE;
    i2d_SSL_SESSION(pSession, &pder);
    /* !@#$%^ - why do we deal with *absolute* time anyway??? */
    timeout -= time(NULL);
    /* Send the serialised session to the distributed cache context */
    if (!DC_CTX_add_session(ctx, id, idlen, der, der_len,
                            (unsigned long)timeout * 1000)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'add_session' failed");
        return FALSE;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'add_session' successful");
    return TRUE;
}

SSL_SESSION *ssl_scache_dc_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    unsigned char der[SSL_SESSION_MAX_DER];
    unsigned int der_len;
    SSL_SESSION *pSession;
    MODSSL_D2I_SSL_SESSION_CONST unsigned char *pder = der;
    SSLModConfigRec *mc = myModConfig(s);
    DC_CTX *ctx = mc->tSessionCacheDataTable;

    /* Retrieve any corresponding session from the distributed cache context */
    if (!DC_CTX_get_session(ctx, id, idlen, der, SSL_SESSION_MAX_DER,
                            &der_len)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'get_session' MISS");
        return NULL;
    }
    if (der_len > SSL_SESSION_MAX_DER) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'get_session' OVERFLOW");
        return NULL;
    }
    pSession = d2i_SSL_SESSION(NULL, &pder, der_len);
    if (!pSession) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'get_session' CORRUPT");
        return NULL;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'get_session' HIT");
    return pSession;
}

void ssl_scache_dc_remove(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    DC_CTX *ctx = mc->tSessionCacheDataTable;

    /* Remove any corresponding session from the distributed cache context */
    if (!DC_CTX_remove_session(ctx, id, idlen)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'remove_session' MISS");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'remove_session' HIT");
    }
}

void ssl_scache_dc_status(request_rec *r, int flags, apr_pool_t *pool)
{
    SSLModConfigRec *mc = myModConfig(r->server);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "distributed scache 'ssl_scache_dc_status'");
    ap_rprintf(r, "cache type: <b>DC (Distributed Cache)</b>, "
               " target: <b>%s</b><br>", mc->szSessionCacheDataFile);
}

#endif

