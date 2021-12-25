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
#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_main.h>
#include <http_log.h>
#include <ap_socache.h>

#include <rustls.h>

#include "tls_conf.h"
#include "tls_core.h"
#include "tls_cert.h"
#include "tls_util.h"
#include "tls_var.h"
#include "tls_version.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

typedef struct {
    apr_pool_t *p;
    server_rec *s;
    conn_rec *c;
    request_rec *r;
    tls_conf_conn_t *cc;
    const char *name;
    const char *arg_s;
    int arg_i;
} tls_var_lookup_ctx_t;

typedef const char *var_lookup(const tls_var_lookup_ctx_t *ctx);

static const char *var_get_ssl_protocol(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->tls_protocol_name;
}

static const char *var_get_ssl_cipher(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->tls_cipher_name;
}

static const char *var_get_sni_hostname(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->sni_hostname;
}

static const char *var_get_version_interface(const tls_var_lookup_ctx_t *ctx)
{
    tls_conf_server_t *sc = tls_conf_server_get(ctx->s);
    return sc->global->module_version;
}

static const char *var_get_version_library(const tls_var_lookup_ctx_t *ctx)
{
    tls_conf_server_t *sc = tls_conf_server_get(ctx->s);
    return sc->global->crustls_version;
}

static const char *var_get_false(const tls_var_lookup_ctx_t *ctx)
{
    (void)ctx;
    return "false";
}

static const char *var_get_null(const tls_var_lookup_ctx_t *ctx)
{
    (void)ctx;
    return "NULL";
}

static const char *var_get_client_s_dn_cn(const tls_var_lookup_ctx_t *ctx)
{
    /* There is no support in the crustls/rustls/webpki APIs to
     * parse X.509 certificates and extract information about
     * subject, issuer, etc. */
    if (!ctx->cc->peer_certs || !ctx->cc->peer_certs->nelts) return NULL;
    return "Not Implemented";
}

static const char *var_get_client_verify(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->peer_certs? "SUCCESS" : "NONE";
}

static const char *var_get_session_resumed(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->session_id_cache_hit? "Resumed" : "Initial";
}

static const char *var_get_client_cert(const tls_var_lookup_ctx_t *ctx)
{
    const rustls_certificate *cert;
    const char *pem;
    apr_status_t rv;
    int cert_idx = 0;

    if (ctx->arg_s) {
        if (strcmp(ctx->arg_s, "chain")) return NULL;
        /* ctx->arg_i'th chain cert, which is in out list as */
        cert_idx = ctx->arg_i + 1;
    }
    if (!ctx->cc->peer_certs || cert_idx >= ctx->cc->peer_certs->nelts) return NULL;
    cert = APR_ARRAY_IDX(ctx->cc->peer_certs, cert_idx, const rustls_certificate*);
    if (APR_SUCCESS != (rv = tls_cert_to_pem(&pem, ctx->p, cert))) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ctx->s, APLOGNO(10315)
                         "Failed to create client certificate PEM");
        return NULL;
    }
    return pem;
}

static const char *var_get_server_cert(const tls_var_lookup_ctx_t *ctx)
{
    const rustls_certificate *cert;
    const char *pem;
    apr_status_t rv;

    if (!ctx->cc->key) return NULL;
    cert = rustls_certified_key_get_certificate(ctx->cc->key, 0);
    if (!cert) return NULL;
    if (APR_SUCCESS != (rv = tls_cert_to_pem(&pem, ctx->p, cert))) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, ctx->s, APLOGNO(10316)
                         "Failed to create server certificate PEM");
        return NULL;
    }
    return pem;
}

typedef struct {
    const char *name;
    var_lookup* fn;
    const char *arg_s;
    int arg_i;
} var_def_t;

static const var_def_t VAR_DEFS[] = {
    { "SSL_PROTOCOL", var_get_ssl_protocol, NULL, 0 },
    { "SSL_CIPHER", var_get_ssl_cipher, NULL, 0 },
    { "SSL_TLS_SNI", var_get_sni_hostname, NULL, 0 },
    { "SSL_CLIENT_S_DN_CN", var_get_client_s_dn_cn, NULL, 0 },
    { "SSL_VERSION_INTERFACE", var_get_version_interface, NULL, 0 },
    { "SSL_VERSION_LIBRARY", var_get_version_library, NULL, 0 },
    { "SSL_SECURE_RENEG", var_get_false, NULL, 0 },
    { "SSL_COMPRESS_METHOD", var_get_null, NULL, 0 },
    { "SSL_CIPHER_EXPORT", var_get_false, NULL, 0 },
    { "SSL_CLIENT_VERIFY", var_get_client_verify, NULL, 0 },
    { "SSL_SESSION_RESUMED", var_get_session_resumed, NULL, 0 },
    { "SSL_CLIENT_CERT", var_get_client_cert, NULL, 0 },
    { "SSL_CLIENT_CHAIN_0", var_get_client_cert, "chain", 0 },
    { "SSL_CLIENT_CHAIN_1", var_get_client_cert, "chain", 1 },
    { "SSL_CLIENT_CHAIN_2", var_get_client_cert, "chain", 2 },
    { "SSL_CLIENT_CHAIN_3", var_get_client_cert, "chain", 3 },
    { "SSL_CLIENT_CHAIN_4", var_get_client_cert, "chain", 4 },
    { "SSL_CLIENT_CHAIN_5", var_get_client_cert, "chain", 5 },
    { "SSL_CLIENT_CHAIN_6", var_get_client_cert, "chain", 6 },
    { "SSL_CLIENT_CHAIN_7", var_get_client_cert, "chain", 7 },
    { "SSL_CLIENT_CHAIN_8", var_get_client_cert, "chain", 8 },
    { "SSL_CLIENT_CHAIN_9", var_get_client_cert, "chain", 9 },
    { "SSL_SERVER_CERT", var_get_server_cert, NULL, 0 },
};

static const char *const TlsAlwaysVars[] = {
    "SSL_TLS_SNI",
    "SSL_PROTOCOL",
    "SSL_CIPHER",
    "SSL_CLIENT_S_DN_CN",
};

/* what mod_ssl defines, plus server cert and client cert DN and SAN entries */
static const char *const StdEnvVars[] = {
    "SSL_VERSION_INTERFACE", /* implemented: module version string */
    "SSL_VERSION_LIBRARY",   /* implemented: crustls/rustls version string */
    "SSL_SECURE_RENEG",      /* implemented: always "false" */
    "SSL_COMPRESS_METHOD",   /* implemented: always "NULL" */
    "SSL_CIPHER_EXPORT",     /* implemented: always "false" */
    "SSL_CIPHER_USEKEYSIZE",
    "SSL_CIPHER_ALGKEYSIZE",
    "SSL_CLIENT_VERIFY",     /* implemented: always "SUCCESS" or "NONE" */
    "SSL_CLIENT_M_VERSION",
    "SSL_CLIENT_M_SERIAL",
    "SSL_CLIENT_V_START",
    "SSL_CLIENT_V_END",
    "SSL_CLIENT_V_REMAIN",
    "SSL_CLIENT_S_DN",
    "SSL_CLIENT_I_DN",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_CLIENT_CERT_RFC4523_CEA",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
    "SSL_SERVER_S_DN",
    "SSL_SERVER_I_DN",
    "SSL_SERVER_A_KEY",
    "SSL_SERVER_A_SIG",
    "SSL_SESSION_ID",        /* not implemented: highly sensitive data we do not expose */
    "SSL_SESSION_RESUMED",   /* implemented: if our cache was hit successfully */
};

/* Cert related variables, export when TLSOption ExportCertData is set */
static const char *const ExportCertVars[] = {
    "SSL_CLIENT_CERT",       /* implemented: */
    "SSL_CLIENT_CHAIN_0",    /* implemented: */
    "SSL_CLIENT_CHAIN_1",    /* implemented: */
    "SSL_CLIENT_CHAIN_2",    /* implemented: */
    "SSL_CLIENT_CHAIN_3",    /* implemented: */
    "SSL_CLIENT_CHAIN_4",    /* implemented: */
    "SSL_CLIENT_CHAIN_5",    /* implemented: */
    "SSL_CLIENT_CHAIN_6",    /* implemented: */
    "SSL_CLIENT_CHAIN_7",    /* implemented: */
    "SSL_CLIENT_CHAIN_8",    /* implemented: */
    "SSL_CLIENT_CHAIN_9",    /* implemented: */
    "SSL_SERVER_CERT",       /* implemented: */
};

void tls_var_init_lookup_hash(apr_pool_t *pool, apr_hash_t *map)
{
    const var_def_t *def;
    apr_size_t i;

    (void)pool;
    for (i = 0; i < TLS_DIM(VAR_DEFS); ++i) {
        def = &VAR_DEFS[i];
        apr_hash_set(map, def->name, APR_HASH_KEY_STRING, def);
    }
}

static const char *invoke(var_def_t* def, tls_var_lookup_ctx_t *ctx)
{
    if (TLS_CONN_ST_IS_ENABLED(ctx->cc)) {
        const char *val = ctx->cc->subprocess_env?
            apr_table_get(ctx->cc->subprocess_env, def->name) : NULL;
        if (val && *val) return val;
        ctx->arg_s = def->arg_s;
        ctx->arg_i = def->arg_i;
        return def->fn(ctx);
    }
    return NULL;
}

static void set_var(
    tls_var_lookup_ctx_t *ctx, apr_hash_t *lookups, apr_table_t *table)
{
    var_def_t* def = apr_hash_get(lookups, ctx->name, APR_HASH_KEY_STRING);
    if (def) {
        const char *val = invoke(def, ctx);
        if (val && *val) {
            apr_table_setn(table, ctx->name, val);
        }
    }
}

const char *tls_var_lookup(
    apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *name)
{
    const char *val = NULL;
    tls_conf_server_t *sc;
    var_def_t* def;

    ap_assert(p);
    ap_assert(name);
    s = s? s : (r? r->server : (c? c->base_server : NULL));
    c = c? c : (r? r->connection : NULL);

    sc = tls_conf_server_get(s? s : ap_server_conf);
    def = apr_hash_get(sc->global->var_lookups, name, APR_HASH_KEY_STRING);
    if (def) {
        tls_var_lookup_ctx_t ctx;
        ctx.p = p;
        ctx.s = s;
        ctx.c = c;
        ctx.r = r;
        ctx.cc = c? tls_conf_conn_get(c->master? c->master : c) : NULL;
                ctx.cc = c? tls_conf_conn_get(c->master? c->master : c) : NULL;
        ctx.name = name;
        val = invoke(def, &ctx);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c, "tls lookup of var '%s' -> '%s'", name, val);
    }
    return val;
}

static void add_vars(apr_table_t *env, conn_rec *c, server_rec *s, request_rec *r)
{
    tls_conf_server_t *sc;
    tls_conf_dir_t *dc, *sdc;
    tls_var_lookup_ctx_t ctx;
    apr_size_t i;
    int overlap;

    sc = tls_conf_server_get(s);
    dc = r? tls_conf_dir_get(r) : tls_conf_dir_server_get(s);
    sdc = r? tls_conf_dir_server_get(s): dc;
    ctx.p = r? r->pool : c->pool;
    ctx.s = s;
    ctx.c = c;
    ctx.r = r;
    ctx.cc = tls_conf_conn_get(c->master? c->master : c);
    /* Can we re-use the precomputed connection values? */
    overlap = (r && ctx.cc->subprocess_env && r->server == ctx.cc->server);
    if (overlap) {
        apr_table_overlap(env, ctx.cc->subprocess_env, APR_OVERLAP_TABLES_SET);
    }
    else {
        apr_table_setn(env, "HTTPS", "on");
        for (i = 0; i < TLS_DIM(TlsAlwaysVars); ++i) {
            ctx.name = TlsAlwaysVars[i];
            set_var(&ctx, sc->global->var_lookups, env);
        }
    }
    if (dc->std_env_vars == TLS_FLAG_TRUE) {
        for (i = 0; i < TLS_DIM(StdEnvVars); ++i) {
            ctx.name = StdEnvVars[i];
            set_var(&ctx, sc->global->var_lookups, env);
        }
    }
    else if (overlap && sdc->std_env_vars == TLS_FLAG_TRUE) {
        /* Remove variables added on connection init that are disabled here */
        for (i = 0; i < TLS_DIM(StdEnvVars); ++i) {
            apr_table_unset(env, StdEnvVars[i]);
        }
    }
    if (dc->export_cert_vars == TLS_FLAG_TRUE) {
        for (i = 0; i < TLS_DIM(ExportCertVars); ++i) {
            ctx.name = ExportCertVars[i];
            set_var(&ctx, sc->global->var_lookups, env);
        }
    }
    else if (overlap && sdc->std_env_vars == TLS_FLAG_TRUE) {
        /* Remove variables added on connection init that are disabled here */
        for (i = 0; i < TLS_DIM(ExportCertVars); ++i) {
            apr_table_unset(env, ExportCertVars[i]);
        }
    }
 }

apr_status_t tls_var_handshake_done(conn_rec *c)
{
    tls_conf_conn_t *cc;
    tls_conf_server_t *sc;
    apr_status_t rv = APR_SUCCESS;

    cc = tls_conf_conn_get(c);
    if (!TLS_CONN_ST_IS_ENABLED(cc)) goto cleanup;

    sc = tls_conf_server_get(cc->server);
    if (cc->peer_certs && sc->var_user_name) {
        cc->user_name = tls_var_lookup(c->pool, cc->server, c, NULL, sc->var_user_name);
        if (!cc->user_name) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cc->server, APLOGNO(10317)
                "Failed to set r->user to '%s'", sc->var_user_name);
        }
    }
    cc->subprocess_env = apr_table_make(c->pool, 5);
    add_vars(cc->subprocess_env, c, cc->server, NULL);

cleanup:
    return rv;
}

int tls_var_request_fixup(request_rec *r)
{
    conn_rec *c = r->connection;
    tls_conf_conn_t *cc;

    cc = tls_conf_conn_get(c->master? c->master : c);
    if (!TLS_CONN_ST_IS_ENABLED(cc)) goto cleanup;
    if (cc->user_name) {
        /* why is r->user a char* and not const? */
        r->user = apr_pstrdup(r->pool, cc->user_name);
    }
    add_vars(r->subprocess_env, c, r->server, r);

cleanup:
    return DECLINED;
}
