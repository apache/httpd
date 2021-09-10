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

/*
 * ssl.c --- routines for SSL/TLS server infrastructure.
 *
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_strmatch.h"

#define APR_WANT_STDIO          /* for sscanf */
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_main.h"
#include "http_ssl.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "mod_core.h"


#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

APR_HOOK_STRUCT(
    APR_HOOK_LINK(ssl_conn_is_ssl)
    APR_HOOK_LINK(ssl_var_lookup)
    APR_HOOK_LINK(ssl_add_cert_files)
    APR_HOOK_LINK(ssl_add_fallback_cert_files)
    APR_HOOK_LINK(ssl_answer_challenge)
    APR_HOOK_LINK(ssl_ocsp_prime_hook)
    APR_HOOK_LINK(ssl_ocsp_get_resp_hook)
    APR_HOOK_LINK(ssl_bind_outgoing)
)

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *module_ssl_is_https;
APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable) *module_ssl_proxy_enable;
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable) *module_ssl_engine_disable;
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_set, (conn_rec *,
                                              ap_conf_vector_t *,
                                              int proxy, int enable));
static APR_OPTIONAL_FN_TYPE(ssl_engine_set) *module_ssl_engine_set;


static int ssl_is_https(conn_rec *c)
{
    /* Someone retrieved the optional function., not knowing about the
     * new API. We redirect them to what they should have invoked. */
    return ap_ssl_conn_is_ssl(c);
}

AP_DECLARE(int) ap_ssl_conn_is_ssl(conn_rec *c)
{
    int r = (ap_run_ssl_conn_is_ssl(c) == OK);
    if (r == 0 && module_ssl_is_https) {
        r = module_ssl_is_https(c);
    }
    return r;
}

static int ssl_engine_set(conn_rec *c,
                          ap_conf_vector_t *per_dir_config,
                          int proxy, int enable)
{
    if (proxy) {
        return ap_ssl_bind_outgoing(c, per_dir_config, enable) == OK;
    }
    else if (module_ssl_engine_set) {
        return module_ssl_engine_set(c, per_dir_config, 0, enable);
    }
    else if (enable && module_ssl_proxy_enable) {
        return module_ssl_proxy_enable(c);
    }
    else if (!enable && module_ssl_engine_disable) {
        return module_ssl_engine_disable(c);
    }
    return 0;
}

static int ssl_proxy_enable(conn_rec *c)
{
    return ap_ssl_bind_outgoing(c, NULL, 1);
}

static int ssl_engine_disable(conn_rec *c)
{
    return ap_ssl_bind_outgoing(c, NULL, 0);
}

AP_DECLARE(int) ap_ssl_bind_outgoing(conn_rec *c, struct ap_conf_vector_t *dir_conf,
                                     int enable_ssl)
{
    int rv, enabled = 0;

    c->outgoing = 1;
    rv = ap_run_ssl_bind_outgoing(c, dir_conf, enable_ssl);
    enabled = (rv == OK);
    if (enable_ssl && !enabled) {
        /* the hooks did not take over. Is there an old skool optional that will? */
        if (module_ssl_engine_set) {
            enabled = module_ssl_engine_set(c, dir_conf, 1, 1);
        }
        else if (module_ssl_proxy_enable) {
            enabled = module_ssl_proxy_enable(c);
        }
    }
    else {
        /* !enable_ssl || enabled
         * any existing optional funcs need to not enable here */
        if (module_ssl_engine_set) {
            module_ssl_engine_set(c, dir_conf, 1, 0);
        }
        else if (module_ssl_engine_disable) {
            module_ssl_engine_disable(c);
        }
    }
    if (enable_ssl && !enabled) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0,
                      c, APLOGNO(01961) " failed to enable ssl support "
                      "[Hint: if using mod_ssl, see SSLProxyEngine]");
        return DECLINED;
    }
    return OK;
}

AP_DECLARE(int) ap_ssl_has_outgoing_handlers(void)
{
    apr_array_header_t *hooks = ap_hook_get_ssl_bind_outgoing();
    return (hooks && hooks->nelts > 0)
        || module_ssl_engine_set || module_ssl_proxy_enable;
}

APR_DECLARE_OPTIONAL_FN(const char *, ssl_var_lookup,
                        (apr_pool_t *p, server_rec *s,
                         conn_rec *c, request_rec *r,
                         const char *name));
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *module_ssl_var_lookup;

static const char *ssl_var_lookup(apr_pool_t *p, server_rec *s,
                                  conn_rec *c, request_rec *r,
                                  const char *name)
{
    /* Someone retrieved the optional function., not knowing about the
     * new API. We redirect them to what they should have invoked. */
    return ap_ssl_var_lookup(p, s, c, r, name);
}

AP_DECLARE(const char *) ap_ssl_var_lookup(apr_pool_t *p, server_rec *s,
                                           conn_rec *c, request_rec *r,
                                           const char *name)
{
    const char *val = ap_run_ssl_var_lookup(p, s, c, r, name);
    if (val == NULL && module_ssl_var_lookup) {
        val = module_ssl_var_lookup(p, s, c, r, name);
    }
    return val;
}

AP_DECLARE(void) ap_setup_ssl_optional_fns(apr_pool_t *pool)
{
    /* Run as core's very early 'post config' hook, check for any already
     * installed optional functions related to SSL and save them. Install
     * our own instances that invoke the new hooks. */
    APR_OPTIONAL_FN_TYPE(ssl_is_https) *fn_is_https;
    APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *fn_ssl_var_lookup;

    fn_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    module_ssl_is_https = (fn_is_https
        && fn_is_https != ssl_is_https)? fn_is_https : NULL;
    APR_REGISTER_OPTIONAL_FN(ssl_is_https);

    fn_ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    module_ssl_var_lookup = (fn_ssl_var_lookup
        && fn_ssl_var_lookup != ssl_var_lookup)? fn_ssl_var_lookup : NULL;
    APR_REGISTER_OPTIONAL_FN(ssl_var_lookup);

    module_ssl_proxy_enable = APR_RETRIEVE_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    module_ssl_engine_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
    module_ssl_engine_set = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_set);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_set);
}

AP_DECLARE(apr_status_t) ap_ssl_add_cert_files(server_rec *s, apr_pool_t *p,
                                               apr_array_header_t *cert_files,
                                               apr_array_header_t *key_files)
{
    int rv = ap_run_ssl_add_cert_files(s, p, cert_files, key_files);
    return (rv == OK || rv == DECLINED)? APR_SUCCESS : APR_EGENERAL;
}

AP_DECLARE(apr_status_t) ap_ssl_add_fallback_cert_files(server_rec *s, apr_pool_t *p,
                                                        apr_array_header_t *cert_files,
                                                        apr_array_header_t *key_files)
{
    int rv = ap_run_ssl_add_fallback_cert_files(s, p, cert_files, key_files);
    return (rv == OK || rv == DECLINED)? APR_SUCCESS : APR_EGENERAL;
}

AP_DECLARE(int) ap_ssl_answer_challenge(conn_rec *c, const char *server_name,
                                        const char **pcert_pem, const char **pkey_pem)
{
    return (ap_run_ssl_answer_challenge(c, server_name, pcert_pem, pkey_pem) == OK);
}

AP_DECLARE(apr_status_t) ap_ssl_ocsp_prime(server_rec *s, apr_pool_t *p,
                                           const char *id, apr_size_t id_len,
                                           const char *pem)
{
    int rv = ap_run_ssl_ocsp_prime_hook(s, p, id, id_len, pem);
    return rv == OK? APR_SUCCESS : (rv == DECLINED? APR_ENOENT : APR_EGENERAL);
}

AP_DECLARE(apr_status_t) ap_ssl_ocsp_get_resp(server_rec *s, conn_rec *c,
                                              const char *id, apr_size_t id_len,
                                              ap_ssl_ocsp_copy_resp *cb, void *userdata)
{
    int rv = ap_run_ssl_ocsp_get_resp_hook(s, c, id, id_len, cb, userdata);
    return rv == OK? APR_SUCCESS : (rv == DECLINED? APR_ENOENT : APR_EGENERAL);
}

AP_IMPLEMENT_HOOK_RUN_FIRST(int, ssl_conn_is_ssl,
                            (conn_rec *c), (c), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,ssl_var_lookup,
        (apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *name),
        (p, s, c, r, name), NULL)
AP_IMPLEMENT_HOOK_RUN_ALL(int, ssl_add_cert_files,
        (server_rec *s, apr_pool_t *p,
         apr_array_header_t *cert_files, apr_array_header_t *key_files),
        (s, p, cert_files, key_files), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int, ssl_add_fallback_cert_files,
        (server_rec *s, apr_pool_t *p,
         apr_array_header_t *cert_files, apr_array_header_t *key_files),
        (s, p, cert_files, key_files), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, ssl_answer_challenge,
        (conn_rec *c, const char *server_name, const char **pcert_pem, const char **pkey_pem),
        (c, server_name, pcert_pem, pkey_pem), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, ssl_ocsp_prime_hook,
        (server_rec *s, apr_pool_t *p, const char *id, apr_size_t id_len, const char *pem),
        (s, p, id, id_len, pem), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, ssl_ocsp_get_resp_hook,
         (server_rec *s, conn_rec *c, const char *id, apr_size_t id_len,
          ap_ssl_ocsp_copy_resp *cb, void *userdata),
         (s, c, id, id_len, cb, userdata), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,ssl_bind_outgoing,(conn_rec *c, ap_conf_vector_t *dir_conf, int require_ssl),
                            (c, dir_conf, require_ssl), DECLINED)
