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
 *  ssl_scache_memcache.c
 *  Distributed Session Cache on top of memcached
 */

#include "ssl_private.h"

#ifdef HAVE_SSL_CACHE_MEMCACHE

#include "apr_memcache.h"
#include "ap_mpm.h"

/*
 * SSL Session Caching using memcached as a backend.
 */

/*
**
** High-Level "handlers" as per ssl_scache.c
**
*/


/* The underlying apr_memcache system is thread safe.. */
static apr_memcache_t *memctxt;

#define MC_TAG "mod_ssl:"
#define MC_TAG_LEN \
    (sizeof(MC_TAG))

#define MC_KEY_LEN 254

#ifndef MC_DEFAULT_SERVER_PORT
#define MC_DEFAULT_SERVER_PORT 11211
#endif


#ifndef MC_DEFAULT_SERVER_MIN
#define MC_DEFAULT_SERVER_MIN 0
#endif

#ifndef MC_DEFAULT_SERVER_SMAX
#define MC_DEFAULT_SERVER_SMAX 1
#endif

#ifndef MC_DEFAULT_SERVER_TTL
#define MC_DEFAULT_SERVER_TTL 600
#endif


static void ssl_scache_mc_init(server_rec *s, apr_pool_t *p)
{
    apr_status_t rv;
    int thread_limit = 0;
    int nservers = 0;
    char *cache_config;
    char *split;
    char *tok;
    SSLModConfigRec *mc = myModConfig(s);

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

    if (mc->szSessionCacheDataFile == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "SSLSessionCache required");
        ssl_die();
    }

    /* Find all the servers in the first run to get a total count */
    cache_config = apr_pstrdup(p, mc->szSessionCacheDataFile);
    split = apr_strtok(cache_config, ",", &tok);
    while (split) {
        nservers++;
        split = apr_strtok(NULL,",", &tok);
    }

    rv = apr_memcache_create(p, nservers, 0, &memctxt);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "SSLSessionCache: Failed to create Memcache Object of '%d' size.", 
                     nservers);
        ssl_die();
    }

    /* Now add each server to the memcache */
    cache_config = apr_pstrdup(p, mc->szSessionCacheDataFile);
    split = apr_strtok(cache_config, ",", &tok);
    while (split) {
        apr_memcache_server_t *st;
        char *host_str;
        char *scope_id;
        apr_port_t port;

        rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "SSLSessionCache: Failed to Parse Server: '%s'", split);
            ssl_die();
        }

        if (host_str == NULL) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "SSLSessionCache: Failed to Parse Server, "
                         "no hostname specified: '%s'", split);
            ssl_die();
        }

        if (port == 0) {
            port = MC_DEFAULT_SERVER_PORT;
        }

        rv = apr_memcache_server_create(p,
                                        host_str, port,
                                        MC_DEFAULT_SERVER_MIN,
                                        MC_DEFAULT_SERVER_SMAX,
                                        thread_limit,
                                        MC_DEFAULT_SERVER_TTL,
                                        &st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "SSLSessionCache: Failed to Create Server: %s:%d", 
                         host_str, port);
            ssl_die();
        }

        rv = apr_memcache_add_server(memctxt, st);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "SSLSessionCache: Failed to Add Server: %s:%d", 
                         host_str, port);
            ssl_die();
        }

        split = apr_strtok(NULL,",", &tok);
    }

    return;
}

static void ssl_scache_mc_kill(server_rec *s)
{

}

static char *mc_session_id2sz(const unsigned char *id, int idlen,
                              char *str, int strsize)
{
    char *cp;
    int n;
    int maxlen = (strsize - MC_TAG_LEN)/2;

    cp = apr_cpystrn(str, MC_TAG, MC_TAG_LEN);
    for (n = 0; n < idlen && n < maxlen; n++) {
        apr_snprintf(cp, 2, "%02X", id[n]);
        cp += 2;
    }

    *cp = '\0';

    return str;
}

static BOOL ssl_scache_mc_store(server_rec *s, UCHAR *id, int idlen,
                                time_t timeout,
                                unsigned char *ucaData, unsigned int nData)
{
    char buf[MC_KEY_LEN];
    char *strkey = NULL;
    apr_status_t rv;

    strkey = mc_session_id2sz(id, idlen, buf, sizeof(buf));
    if(!strkey) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "scache_mc: Key generation borked.");
        return FALSE;
    }

    rv = apr_memcache_set(memctxt, strkey, (char*)ucaData, nData, timeout, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "scache_mc: error setting key '%s' "
                     "with %d bytes of data", strkey, nData);
        return FALSE;
    }

    return TRUE;
}

static BOOL ssl_scache_mc_retrieve(server_rec *s, const UCHAR *id, int idlen,
                                   unsigned char *dest, unsigned int *destlen,
                                   apr_pool_t *p)
{
    apr_size_t der_len;
    char buf[MC_KEY_LEN], *der;
    char* strkey = NULL;
    apr_status_t rv;

    strkey = mc_session_id2sz(id, idlen, buf, sizeof(buf));

    if (!strkey) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "scache_mc: Key generation borked.");
        return FALSE;
    }

    /* ### this could do with a subpool, but _getp looks like it will
     * eat memory like it's going out of fashion anyway. */

    rv = apr_memcache_getp(memctxt, p, strkey,
                           &der, &der_len, NULL);
    if (rv) {
        if (rv != APR_NOTFOUND) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "scache_mc: 'get_session' FAIL");
        }
        return FALSE;
    }
    else if (der_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "scache_mc: 'get_session' OVERFLOW");
        return FALSE;
    }    

    memcpy(dest, der, der_len);
    *destlen = der_len;

    return TRUE;
}

static void ssl_scache_mc_remove(server_rec *s, UCHAR *id, int idlen, apr_pool_t *p)
{
    char buf[MC_KEY_LEN];
    char* strkey = NULL;
    apr_status_t rv;

    strkey = mc_session_id2sz(id, idlen, buf, sizeof(buf));
    if(!strkey) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "scache_mc: Key generation borked.");
        return;
    }

    rv = apr_memcache_delete(memctxt, strkey, 0);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
                     "scache_mc: error deleting key '%s' ",
                     strkey);
        return;
    }
}

static void ssl_scache_mc_status(request_rec *r, int flags, apr_pool_t *pool)
{
    /* SSLModConfigRec *mc = myModConfig(r->server); */
    /* TODO: Make a mod_status handler. meh. */
}

const modssl_sesscache_provider modssl_sesscache_mc = {
    ssl_scache_mc_init,
    ssl_scache_mc_kill,
    ssl_scache_mc_store,
    ssl_scache_mc_retrieve,
    ssl_scache_mc_remove,
    ssl_scache_mc_status
};
#endif
