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

#include "httpd.h"
#include "http_log.h"
#include "http_request.h"
#include "http_config.h"
#include "http_protocol.h"

#include "apr_strings.h"
#include "apr_time.h"

#include "ap_socache.h"

#include "distcache/dc_client.h"

#if !defined(DISTCACHE_CLIENT_API) || (DISTCACHE_CLIENT_API < 0x0001)
#error "You must compile with a more recent version of the distcache-base package"
#endif

struct ap_socache_instance_t {
    /* Configured target server: */
    const char *target;
    /* distcache client context: */
    DC_CTX *dc;
};

static const char *socache_dc_create(ap_socache_instance_t **context,
                                     const char *arg,
                                     apr_pool_t *tmp, apr_pool_t *p)
{
    struct ap_socache_instance_t *ctx;

    ctx = *context = apr_palloc(p, sizeof *ctx);

    ctx->target = apr_pstrdup(p, arg);

    return NULL;
}

static apr_status_t socache_dc_init(ap_socache_instance_t *ctx,
                                    const char *namespace,
                                    const struct ap_socache_hints *hints,
                                    server_rec *s, apr_pool_t *p)
{
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00738) "distributed scache failed to obtain context");
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(00739) "distributed scache context initialised");

    return APR_SUCCESS;
}

static void socache_dc_destroy(ap_socache_instance_t *ctx, server_rec *s)
{
    if (ctx && ctx->dc) {
        DC_CTX_free(ctx->dc);
        ctx->dc = NULL;
    }
}

static apr_status_t socache_dc_store(ap_socache_instance_t *ctx, server_rec *s,
                                     const unsigned char *id, unsigned int idlen,
                                     apr_time_t expiry,
                                     unsigned char *der, unsigned int der_len,
                                     apr_pool_t *p)
{
    /* !@#$%^ - why do we deal with *absolute* time anyway???
     * Uhm - because most things expire things at a specific time?
     * Were the API were thought out expiry - r->request_time is a good approximation
     */
    expiry -= apr_time_now();
    /* Send the serialised session to the distributed cache context */
    if (!DC_CTX_add_session(ctx->dc, id, idlen, der, der_len,
                            apr_time_msec(expiry))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00740) "distributed scache 'store' failed");
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00741) "distributed scache 'store' successful");
    return APR_SUCCESS;
}

static apr_status_t socache_dc_retrieve(ap_socache_instance_t *ctx, server_rec *s,
                                        const unsigned char *id, unsigned int idlen,
                                        unsigned char *dest, unsigned int *destlen,
                                        apr_pool_t *p)
{
    unsigned int data_len;

    /* Retrieve any corresponding session from the distributed cache context */
    if (!DC_CTX_get_session(ctx->dc, id, idlen, dest, *destlen, &data_len)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00742) "distributed scache 'retrieve' MISS");
        return APR_NOTFOUND;
    }
    if (data_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00743) "distributed scache 'retrieve' OVERFLOW");
        return APR_ENOSPC;
    }
    *destlen = data_len;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(00744) "distributed scache 'retrieve' HIT");
    return APR_SUCCESS;
}

static apr_status_t socache_dc_remove(ap_socache_instance_t *ctx,
                                      server_rec *s, const unsigned char *id,
                                      unsigned int idlen, apr_pool_t *p)
{
    /* Remove any corresponding session from the distributed cache context */
    if (!DC_CTX_remove_session(ctx->dc, id, idlen)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00745) "distributed scache 'remove' MISS");
        return APR_NOTFOUND;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00746) "distributed scache 'remove' HIT");
        return APR_SUCCESS;
    }
}

static void socache_dc_status(ap_socache_instance_t *ctx, request_rec *r, int flags)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00747)
                  "distributed scache 'socache_dc_status'");
    ap_rprintf(r, "cache type: <b>DC (Distributed Cache)</b>, "
               " target: <b>%s</b><br>", ctx->target);
}

static apr_status_t socache_dc_iterate(ap_socache_instance_t *instance,
                                       server_rec *s, void *userctx,
                                       ap_socache_iterator_t *iterator,
                                       apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

static const ap_socache_provider_t socache_dc = {
    "distcache",
    0,
    socache_dc_create,
    socache_dc_init,
    socache_dc_destroy,
    socache_dc_store,
    socache_dc_retrieve,
    socache_dc_remove,
    socache_dc_status,
    socache_dc_iterate
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "dc",
                         AP_SOCACHE_PROVIDER_VERSION,
                         &socache_dc);
}

AP_DECLARE_MODULE(socache_dc) = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL, NULL,
    register_hooks
};

