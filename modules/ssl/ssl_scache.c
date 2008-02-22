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
 *  ssl_scache.c
 *  Session Cache Abstraction
 */
                             /* ``Open-Source Software: generous
                                  programmers from around the world all
                                  join forces to help you shoot
                                  yourself in the foot for free.''
                                                 -- Unknown         */
#include "ssl_private.h"
#include "mod_status.h"

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
    if (mc->sesscache == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "Init: Session Cache is not configured "
                     "[hint: SSLSessionCache]");
        return;
    }

    mc->sesscache->init(s, p);
}

void ssl_scache_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);

    mc->sesscache->destroy(s);
}

BOOL ssl_scache_store(server_rec *s, UCHAR *id, int idlen,
                      time_t expiry, SSL_SESSION *sess,
                      apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    
    return mc->sesscache->store(s, id, idlen, expiry, sess);
}

SSL_SESSION *ssl_scache_retrieve(server_rec *s, UCHAR *id, int idlen,
                                 apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);

    return mc->sesscache->retrieve(s, id, idlen, p);
}

void ssl_scache_remove(server_rec *s, UCHAR *id, int idlen,
                       apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);

    mc->sesscache->delete(s, id, idlen, p);

    return;
}

/*  _________________________________________________________________
**
**  SSL Extension to mod_status
**  _________________________________________________________________
*/
static int ssl_ext_status_hook(request_rec *r, int flags)
{
    SSLModConfigRec *mc = myModConfig(r->server);

    if (mc == NULL || flags & AP_STATUS_SHORT)
        return OK;

    ap_rputs("<hr>\n", r);
    ap_rputs("<table cellspacing=0 cellpadding=0>\n", r);
    ap_rputs("<tr><td bgcolor=\"#000000\">\n", r);
    ap_rputs("<b><font color=\"#ffffff\" face=\"Arial,Helvetica\">SSL/TLS Session Cache Status:</font></b>\r", r);
    ap_rputs("</td></tr>\n", r);
    ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);

    mc->sesscache->status(r, flags, r->pool);

    ap_rputs("</td></tr>\n", r);
    ap_rputs("</table>\n", r);
    return OK;
}

void ssl_scache_status_register(apr_pool_t *p)
{
    APR_OPTIONAL_HOOK(ap, status_hook, ssl_ext_status_hook, NULL, NULL,
                      APR_HOOK_MIDDLE);
}

