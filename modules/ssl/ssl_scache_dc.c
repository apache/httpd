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

struct context {
    /* Configured target server: */
    const char *target;
    /* distcache client context: */
    DC_CTX *dc;
};

static const char *ssl_scache_dc_create(void **context, const char *arg, 
                                        apr_pool_t *tmp, apr_pool_t *p)
{
    struct context *ctx;

    ctx = *context = apr_palloc(p, sizeof *ctx);
    
    ctx->target = apr_pstrdup(p, arg);

    return NULL;
}

static apr_status_t ssl_scache_dc_init(void *context, server_rec *s, apr_pool_t *p)
{
    struct context *ctx = ctx;

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
    ctx->dc = DC_CTX_new(ctx->target, SESSION_CTX_FLAGS);
    if (!ctx->dc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache failed to obtain context");
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "distributed scache context initialised");

    return APR_SUCCESS;
}

static void ssl_scache_dc_kill(void *context, server_rec *s)
{
    struct context *ctx = context;

    if (ctx && ctx->dc) {
        DC_CTX_free(ctx->dc);
        ctx->dc = NULL;
    }
}

static BOOL ssl_scache_dc_store(void *context, server_rec *s, UCHAR *id, int idlen,
                                time_t timeout,
                                unsigned char *der, unsigned int der_len)
{
    struct context *ctx = context;

    /* !@#$%^ - why do we deal with *absolute* time anyway??? */
    timeout -= time(NULL);
    /* Send the serialised session to the distributed cache context */
    if (!DC_CTX_add_session(ctx->dc, id, idlen, der, der_len,
                            (unsigned long)timeout * 1000)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'add_session' failed");
        return FALSE;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'add_session' successful");
    return TRUE;
}

static BOOL ssl_scache_dc_retrieve(void *context,
                                   server_rec *s, const UCHAR *id, int idlen,
                                   unsigned char *dest, unsigned int *destlen,
                                   apr_pool_t *p)
{
    unsigned int data_len;
    struct context *ctx = context;

    /* Retrieve any corresponding session from the distributed cache context */
    if (!DC_CTX_get_session(ctx->dc, id, idlen, dest, *destlen, &data_len)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'get_session' MISS");
        return FALSE;
    }
    if (data_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'get_session' OVERFLOW");
        return FALSE;
    }
    *destlen = data_len;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'get_session' HIT");
    return TRUE;
}

static void ssl_scache_dc_remove(void *context, server_rec *s, 
                                 UCHAR *id, int idlen, apr_pool_t *p)
{
    struct context *ctx = context;

    /* Remove any corresponding session from the distributed cache context */
    if (!DC_CTX_remove_session(ctx->dc, id, idlen)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'remove_session' MISS");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'remove_session' HIT");
    }
}

static void ssl_scache_dc_status(void *context, request_rec *r, int flags, apr_pool_t *pool)
{
    struct context *ctx = context;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "distributed scache 'ssl_scache_dc_status'");
    ap_rprintf(r, "cache type: <b>DC (Distributed Cache)</b>, "
               " target: <b>%s</b><br>", ctx->target);
}

const modssl_sesscache_provider modssl_sesscache_dc = {
    "distcache",
    0,
    ssl_scache_dc_create,
    ssl_scache_dc_init,
    ssl_scache_dc_kill,
    ssl_scache_dc_store,
    ssl_scache_dc_retrieve,
    ssl_scache_dc_remove,
    ssl_scache_dc_status
};

#endif

