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
#include <apr_optional.h>
#include <apr_strings.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_ssl.h>
#include <http_request.h>
#include <ap_socache.h>

#include <rustls.h>

#include "mod_tls.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_cache.h"
#include "tls_proto.h"
#include "tls_filter.h"
#include "tls_var.h"
#include "tls_version.h"

#include "mod_proxy.h"

static void tls_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(tls) = {
    STANDARD20_MODULE_STUFF,
    tls_conf_create_dir,   /* create per dir config */
    tls_conf_merge_dir,    /* merge per dir config */
    tls_conf_create_svr,   /* create per server config */
    tls_conf_merge_svr,    /* merge per server config (inheritance) */
    tls_conf_cmds,         /* command handlers */
    tls_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};

static const char* crustls_version(apr_pool_t *p)
{
    struct rustls_str rversion;

    rversion = rustls_version();
    return apr_pstrndup(p, rversion.data, rversion.len);
}

static int tls_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    tls_proto_pre_config(pconf, ptemp);
    tls_cache_pre_config(pconf, plog, ptemp);
    return OK;
}

static apr_status_t tls_post_config(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *s)
{
    const char *tls_init_key = "mod_tls_init_counter";
    tls_conf_server_t *sc;
    void *data = NULL;

    (void)plog;
    sc = tls_conf_server_get(s);
    assert(sc);
    assert(sc->global);
    sc->global->module_version = "mod_tls/" MOD_TLS_VERSION;
    sc->global->crustls_version = crustls_version(p);

    apr_pool_userdata_get(&data, tls_init_key, s->process->pool);
    if (data == NULL) {
        /* At the first start, httpd makes a config check dry run
        * to see if the config is ok in principle.
         */
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "post config dry run");
        apr_pool_userdata_set((const void *)1, tls_init_key,
                              apr_pool_cleanup_null, s->process->pool);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(10365)
                     "%s (%s), initializing...",
                     sc->global->module_version,
                     sc->global->crustls_version);
    }

    return tls_core_init(p, ptemp, s);
}

static apr_status_t tls_post_proxy_config(
    apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    (void)plog;
    sc->global->mod_proxy_post_config_done = 1;
    return tls_core_init(p, ptemp, s);
}

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 109)
static int tls_ssl_outgoing(conn_rec *c, ap_conf_vector_t *dir_conf, int enable_ssl)
{
    /* we are not handling proxy connections - for now */
    tls_core_conn_bind(c, dir_conf);
    if (enable_ssl && tls_core_setup_outgoing(c) == OK) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server,
            "accepted ssl_bind_outgoing(enable=%d) for %s",
            enable_ssl, c->base_server->server_hostname);
        return OK;
    }
    tls_core_conn_disable(c);
    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server,
        "declined ssl_bind_outgoing(enable=%d) for %s",
        enable_ssl, c->base_server->server_hostname);
    return DECLINED;
}

#else /* #if AP_MODULE_MAGIC_AT_LEAST(20120211, 109) */

APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_set, (conn_rec *,
                                              ap_conf_vector_t *,
                                              int proxy, int enable));
static APR_OPTIONAL_FN_TYPE(ssl_engine_set) *module_ssl_engine_set;

static int ssl_engine_set(
    conn_rec *c, ap_conf_vector_t *dir_conf, int proxy, int enable)
{
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, c->base_server,
        "ssl_engine_set(proxy=%d, enable=%d) for %s",
        proxy, enable, c->base_server->server_hostname);
    tls_core_conn_bind(c, dir_conf);
    if (enable && tls_core_setup_outgoing(c) == OK) {
        if (module_ssl_engine_set) {
            module_ssl_engine_set(c, dir_conf, proxy, 0);
        }
        return 1;
    }
    if (proxy || !enable) {
        /* we are not handling proxy connections - for now */
        tls_core_conn_disable(c);
    }
    if (module_ssl_engine_set) {
        return module_ssl_engine_set(c, dir_conf, proxy, enable);
    }
    return 0;
}

static int ssl_proxy_enable(conn_rec *c)
{
    return ssl_engine_set(c, NULL, 1, 1);
}

static int ssl_engine_disable(conn_rec *c)
{
    return ssl_engine_set(c, NULL, 0, 0);
}

static apr_status_t tls_post_config_proxy_ssl(
    apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    if (1) {
        const char *tls_init_key = "mod_tls_proxy_ssl_counter";
        void *data = NULL;
        APR_OPTIONAL_FN_TYPE(ssl_engine_set) *fn_ssl_engine_set;

        (void)p;
        (void)plog;
        (void)ptemp;
        apr_pool_userdata_get(&data, tls_init_key, s->process->pool);
        if (data == NULL) {
            /* At the first start, httpd makes a config check dry run
            * to see if the config is ok in principle.
             */
            apr_pool_userdata_set((const void *)1, tls_init_key,
                                  apr_pool_cleanup_null, s->process->pool);
            return APR_SUCCESS;
        }

        /* mod_ssl (if so loaded, has registered its optional functions.
         * When mod_proxy runs in post-config, it looks up those functions and uses
         * them to manipulate SSL status for backend connections.
         * We provide our own implementations to avoid becoming active on such
         * connections for now.
         * */
        fn_ssl_engine_set = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_set);
        module_ssl_engine_set = (fn_ssl_engine_set
            && fn_ssl_engine_set != ssl_engine_set)? fn_ssl_engine_set : NULL;
        APR_REGISTER_OPTIONAL_FN(ssl_engine_set);
        APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
        APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
    }
    return APR_SUCCESS;
}
#endif /* #if AP_MODULE_MAGIC_AT_LEAST(20120211, 109) */

static void tls_init_child(apr_pool_t *p, server_rec *s)
{
    tls_cache_init_child(p, s);
}

static int hook_pre_connection(conn_rec *c, void *csd)
{
    (void)csd; /* mpm specific socket data, not used */

    /* are we on a primary connection? */
    if (c->master) return DECLINED;

    /* Decide connection TLS stats and install our
     * input/output filters for handling TLS/application data
     * if enabled.
     */
    return tls_filter_pre_conn_init(c);
}

static int hook_connection(conn_rec* c)
{
    tls_filter_conn_init(c);
    /* we do *not* take over. we are not processing requests. */
    return DECLINED;
}

static const char *tls_hook_http_scheme(const request_rec *r)
{
    return (tls_conn_check_ssl(r->connection) == OK)? "https" : NULL;
}

static apr_port_t tls_hook_default_port(const request_rec *r)
{
    return (tls_conn_check_ssl(r->connection) == OK) ? 443 : 0;
}

static const char* const mod_http2[]        = { "mod_http2.c", NULL};

static void tls_hooks(apr_pool_t *pool)
{
    /* If our request check denies further processing, certain things
     * need to be in place for the response to be correctly generated. */
    static const char *dep_req_check[] = { "mod_setenvif.c", NULL };
    static const char *dep_proxy[] = { "mod_proxy.c", NULL };

    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    tls_filter_register(pool);

    ap_hook_pre_config(tls_pre_config, NULL,NULL, APR_HOOK_MIDDLE);
    /* run post-config hooks one before, one after mod_proxy, as the
     * mod_proxy's own one calls us in its "section_post_config" hook. */
    ap_hook_post_config(tls_post_config, NULL, dep_proxy, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(proxy, section_post_config,
                      tls_proxy_section_post_config, NULL, NULL,
                      APR_HOOK_MIDDLE);
    ap_hook_post_config(tls_post_proxy_config, dep_proxy, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(tls_init_child, NULL,NULL, APR_HOOK_MIDDLE);
    /* connection things */
    ap_hook_pre_connection(hook_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_process_connection(hook_connection, NULL, mod_http2, APR_HOOK_MIDDLE);
    /* request things */
    ap_hook_default_port(tls_hook_default_port, NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_http_scheme(tls_hook_http_scheme, NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(tls_core_request_check, dep_req_check, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(tls_var_request_fixup, NULL,NULL, APR_HOOK_MIDDLE);

    ap_hook_ssl_conn_is_ssl(tls_conn_check_ssl, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_ssl_var_lookup(tls_var_lookup, NULL, NULL, APR_HOOK_MIDDLE);

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 109)
    ap_hook_ssl_bind_outgoing(tls_ssl_outgoing, NULL, NULL, APR_HOOK_MIDDLE);
#else
    ap_hook_post_config(tls_post_config_proxy_ssl, NULL, dep_proxy, APR_HOOK_MIDDLE);
#endif

}
