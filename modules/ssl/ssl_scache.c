/* Copyright 2001-2005 The Apache Software Foundation or its licensors, as
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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_scache.c
 *  Session Cache Abstraction
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

void ssl_scache_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);

    /*
     * Warn the user that he should use the session cache.
     * But we can operate without it, of course.
     */
    if (mc->nSessionCacheMode == SSL_SCMODE_UNSET) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "Init: Session Cache is not configured "
                     "[hint: SSLSessionCache]");
        mc->nSessionCacheMode = SSL_SCMODE_NONE;
        return;
    }

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_init(s, p);
    else if ((mc->nSessionCacheMode == SSL_SCMODE_SHMHT) ||
             (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)) {
        void *data;
        const char *userdata_key = "ssl_scache_init";

        apr_pool_userdata_get(&data, userdata_key, s->process->pool);
        if (!data) {
            apr_pool_userdata_set((const void *)1, userdata_key,
                                  apr_pool_cleanup_null, s->process->pool);
            return;
        }
        if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
            ssl_scache_shmht_init(s, p);
        else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
            ssl_scache_shmcb_init(s, p);
    }
}

void ssl_scache_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_kill(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_kill(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_kill(s);
    return;
}

BOOL ssl_scache_store(server_rec *s, UCHAR *id, int idlen, time_t expiry, SSL_SESSION *sess)
{
    SSLModConfigRec *mc = myModConfig(s);
    BOOL rv = FALSE;

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        rv = ssl_scache_dbm_store(s, id, idlen, expiry, sess);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        rv = ssl_scache_shmht_store(s, id, idlen, expiry, sess);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        rv = ssl_scache_shmcb_store(s, id, idlen, expiry, sess);
    return rv;
}

SSL_SESSION *ssl_scache_retrieve(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);
    SSL_SESSION *sess = NULL;

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        sess = ssl_scache_dbm_retrieve(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        sess = ssl_scache_shmht_retrieve(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        sess = ssl_scache_shmcb_retrieve(s, id, idlen);
    return sess;
}

void ssl_scache_remove(server_rec *s, UCHAR *id, int idlen)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_remove(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_remove(s, id, idlen);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_remove(s, id, idlen);
    return;
}

void ssl_scache_status(server_rec *s, apr_pool_t *p, void (*func)(char *, void *), void *arg)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_status(s, p, func, arg);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_status(s, p, func, arg);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_status(s, p, func, arg);
    return;
}

void ssl_scache_expire(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    if (mc->nSessionCacheMode == SSL_SCMODE_DBM)
        ssl_scache_dbm_expire(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMHT)
        ssl_scache_shmht_expire(s);
    else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB)
        ssl_scache_shmcb_expire(s);
    return;
}

/*  _________________________________________________________________
**
**  SSL Extension to mod_status
**  _________________________________________________________________
*/
#if 0 /* NOT YET */
static void ssl_ext_ms_display(request_rec *, int, int);

void ssl_scache_status_register(apr_pool_t *p)
{
    /* XXX point mod_status to this update, when it grows the opt fn */
#if 0
    ap_hook_register("ap::mod_status::display", ssl_ext_ms_display, AP_HOOK_NOCTX);
#endif
    return;
}

static void ssl_ext_ms_display_cb(char *str, void *_r)
{
    request_rec *r = (request_rec *)_r;
    if (str != NULL)
        ap_rputs(str, r);
    return;
}

static void ssl_ext_ms_display(request_rec *r, int no_table_report, int short_report)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc == NULL)
        return;
    if (short_report)
        return;
    ap_rputs("<hr>\n", r);
    ap_rputs("<table cellspacing=0 cellpadding=0>\n", r);
    ap_rputs("<tr><td bgcolor=\"#000000\">\n", r);
    ap_rputs("<b><font color=\"#ffffff\" face=\"Arial,Helvetica\">SSL/TLS Session Cache Status:</font></b>\r", r);
    ap_rputs("</td></tr>\n", r);
    ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);
    ssl_scache_status(r->server, r->pool, ssl_ext_ms_display_cb, r);
    ap_rputs("</td></tr>\n", r);
    ap_rputs("</table>\n", r);
    return;
}
#endif
