/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#include <apr_strings.h>
#include <apr_optional.h>
#include <apr_optional_hooks.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_log.h>

#include "h2_private.h"

#include "h2_config.h"
#include "h2_ctx.h"
#include "h2_conn.h"
#include "h2_h2.h"
#include "h2_alpn.h"

/*******************************************************************************
 * SSL var lookup
 */
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *,
                         char *));
static char *(*opt_ssl_var_lookup)(apr_pool_t *, server_rec *,
                                   conn_rec *, request_rec *,
                                   char *);

/*******************************************************************************
 * NPN callbacks and registry, deprecated
 */
typedef int (*ssl_npn_advertise_protos)(conn_rec *connection, 
    apr_array_header_t *protos);

typedef int (*ssl_npn_proto_negotiated)(conn_rec *connection, 
    const char *proto_name, apr_size_t proto_name_len);

APR_DECLARE_OPTIONAL_FN(int, modssl_register_npn, 
                        (conn_rec *conn,
                         ssl_npn_advertise_protos advertisefn,
                         ssl_npn_proto_negotiated negotiatedfn));

static int (*opt_ssl_register_npn)(conn_rec*,
                                   ssl_npn_advertise_protos,
                                   ssl_npn_proto_negotiated);

/*******************************************************************************
 * ALPN callbacks and registry
 */
typedef int (*ssl_alpn_propose_protos)(conn_rec *connection,
    apr_array_header_t *client_protos, apr_array_header_t *protos);

typedef int (*ssl_alpn_proto_negotiated)(conn_rec *connection,
    const char *proto_name, apr_size_t proto_name_len);

APR_DECLARE_OPTIONAL_FN(int, modssl_register_alpn,
                        (conn_rec *conn,
                         ssl_alpn_propose_protos proposefn,
                         ssl_alpn_proto_negotiated negotiatedfn));

static int (*opt_ssl_register_alpn)(conn_rec*,
                                    ssl_alpn_propose_protos,
                                    ssl_alpn_proto_negotiated);

/*******************************************************************************
 * Hooks for processing incoming connections:
 * - pre_conn_after_tls registers for ALPN handling
 */
static int h2_alpn_pre_conn(conn_rec* c, void *arg);

/*******************************************************************************
 * Once per lifetime init, retrieve optional functions
 */
apr_status_t h2_alpn_init(apr_pool_t *pool, server_rec *s)
{
    (void)pool;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "h2_alpn init");
    opt_ssl_register_npn = APR_RETRIEVE_OPTIONAL_FN(modssl_register_npn);
    opt_ssl_register_alpn = APR_RETRIEVE_OPTIONAL_FN(modssl_register_alpn);
    opt_ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    if (!opt_ssl_register_alpn && !opt_ssl_register_npn) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_ssl does not offer ALPN or NPN registration");
    }
    return APR_SUCCESS;
}

/*******************************************************************************
 * Register various hooks
 */
static const char *const mod_ssl[]        = { "mod_ssl.c", NULL};
static const char *const mod_core[]       = { "core.c", NULL};

static void check_sni_host(conn_rec *c) 
{
    /* If we have not done so already, ask the connection for the
     * hostname send to us via SNI. This information is later used
     * to retrieve the correct server settings for this connection.
     */
    h2_ctx *ctx = h2_ctx_get(c);
    if (opt_ssl_var_lookup && !ctx->hostname) {
        const char *p = opt_ssl_var_lookup(c->pool, c->base_server, c, 
                                           NULL, (char*)"SSL_TLS_SNI");
        if (p && *p) {
            ctx->hostname = apr_pstrdup(c->pool, p);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                          "h2_h2, connection, SNI %s",
                          ctx->hostname? ctx->hostname : "NULL");
        }
    }
}

void h2_alpn_register_hooks(void)
{
    /* This hook runs on new connection after mod_ssl, but before the core
     * httpd. Its purpose is to register, if TLS is used, the ALPN callbacks
     * that enable us to chose "h2" as next procotol if the client supports it.
     */
    ap_hook_pre_connection(h2_alpn_pre_conn, 
                           mod_ssl, mod_core, APR_HOOK_LAST);
    
}

static int h2_util_array_index(apr_array_header_t *array, const char *s)
{
    for (int i = 0; i < array->nelts; i++) {
        const char *p = APR_ARRAY_IDX(array, i, const char*);
        if (!strcmp(p, s)) {
            return i;
        }
    }
    return -1;
}

static int h2_npn_advertise(conn_rec *c, apr_array_header_t *protos)
{
    h2_config *cfg;
    
    check_sni_host(c);
    cfg = h2_config_get(c);
    if (!h2_config_geti(cfg, H2_CONF_ENABLED)) {
        return DECLINED;
    }
    
    for (apr_size_t i = 0; i < h2_alpn_protos_len; ++i) {
        const char *proto = h2_alpn_protos[i];
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "NPN proposing %s from client selection", proto);
        APR_ARRAY_PUSH(protos, const char*) = proto;
    }
    return OK;
}

static int h2_negotiated(conn_rec *c, const char *via, 
                         const char *proto_name,
                         apr_size_t proto_name_len)
{
    h2_ctx *ctx = h2_ctx_get(c);

    if (h2_ctx_is_task(ctx) ) {
        return DECLINED;
    }
    
    if (h2_ctx_pnego_is_done(ctx)) {
        /* called twice? refraing from overriding existing selection.
         * NPN is fading...
         */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "protocol negotiated via %s called, but already set", 
                      via); 
        return DECLINED;
    }
    
    if (APLOGctrace1(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "protocol negotiated via %s is %s", via, 
                      apr_pstrndup(c->pool, proto_name, proto_name_len));
    }
    
    for (apr_size_t i = 0; i < h2_alpn_protos_len; ++i) {
        const char *proto = h2_alpn_protos[i];
        if (proto_name_len == strlen(proto)
            && strncmp(proto, proto_name, proto_name_len) == 0) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, 
                          "protocol set via %s to %s", via, proto);
            h2_ctx_pnego_set_done(ctx, proto);
            break;
        }
    }    
    return OK;
}

static int h2_npn_negotiated(conn_rec *c,
                             const char *proto_name,
                             apr_size_t proto_name_len)
{
    return h2_negotiated(c, "NPN", proto_name, proto_name_len);
}

static int h2_alpn_propose(conn_rec *c,
                           apr_array_header_t *client_protos,
                           apr_array_header_t *protos)
{
    h2_config *cfg;
    
    check_sni_host(c);
    cfg = h2_config_get(c);
    if (!h2_config_geti(cfg, H2_CONF_ENABLED)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      "ALPN propose, h2 disabled for config %s", cfg->name);
        return DECLINED;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "ALPN propose for config %s", cfg->name);
    /* */
    for (apr_size_t i = 0; i < h2_alpn_protos_len; ++i) {
        const char *proto = h2_alpn_protos[i];
        if (h2_util_array_index(client_protos, proto) >= 0) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                          "ALPN proposing %s", proto);
            APR_ARRAY_PUSH(protos, const char*) = proto;
            return OK; /* propose only one, the first match from our list */
        }
    }
    return OK;
}

static int h2_alpn_negotiated(conn_rec *c,
                              const char *proto_name,
                              apr_size_t proto_name_len)
{
    return h2_negotiated(c, "ALPN", proto_name, proto_name_len);
}



int h2_alpn_pre_conn(conn_rec* c, void *arg)
{
    (void)arg;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                  "h2_h2, pre_connection, start");
    
    h2_ctx *ctx = h2_ctx_get(c);
    if (h2_ctx_is_task(ctx)) {
        /* our stream pseudo connection */
        return DECLINED;
    }
    
    if (h2_h2_is_tls(c)) {
        /* Brand new TLS connection: Does mod_ssl offer ALPN/NPN support? 
         * If so, register at all present, clients may use either/or.
         */
        if (opt_ssl_register_alpn == NULL && opt_ssl_register_npn == NULL) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                          "h2_h2, pre_connection, no ALPN/NPN "
                          "support in mod_ssl");
            return DECLINED;
        }
        
        if (opt_ssl_register_alpn) {
            opt_ssl_register_alpn(c, h2_alpn_propose, h2_alpn_negotiated);
        }
        if (opt_ssl_register_npn) {
            opt_ssl_register_npn(c, h2_npn_advertise, h2_npn_negotiated);
        }
        
        h2_ctx_pnego_set_started(ctx);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c,
                      "h2_alpn, pre_connection, ALPN callback registered");
    }
    
    return DECLINED;
}

