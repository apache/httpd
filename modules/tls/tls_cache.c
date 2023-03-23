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
#include <apr_hash.h>

#include <httpd.h>
#include <http_connection.h>
#include <http_log.h>
#include <ap_socache.h>
#include <util_mutex.h>

#include <rustls.h>

#include "tls_conf.h"
#include "tls_core.h"
#include "tls_cache.h"

extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

#define TLS_CACHE_DEF_PROVIDER      "shmcb"
#define TLS_CACHE_DEF_DIR           "tls"
#define TLS_CACHE_DEF_FILE          "session_cache"
#define TLS_CACHE_DEF_SIZE          512000

static const char *cache_provider_unknown(const char *name, apr_pool_t *p)
{
    apr_array_header_t *known;
    const char *known_names;

    known = ap_list_provider_names(p, AP_SOCACHE_PROVIDER_GROUP,
                                   AP_SOCACHE_PROVIDER_VERSION);
    known_names = apr_array_pstrcat(p, known, ',');
    return apr_psprintf(p, "cache type '%s' not supported "
                        "(known names: %s). Maybe you need to load the "
                        "appropriate socache module (mod_socache_%s?).",
                        name, known_names, name);
}

void tls_cache_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    (void)plog;
    (void)ptemp;
    /* we make this visible, in case someone wants to configure it.
     * this does not mean that we will really use it, which is determined
     * by configuration and cache provider capabilities. */
    ap_mutex_register(pconf, TLS_SESSION_CACHE_MUTEX_TYPE, NULL, APR_LOCK_DEFAULT, 0);
}

static const char *cache_init(tls_conf_global_t *gconf, apr_pool_t *p, apr_pool_t *ptemp)
{
    const char *err = NULL;
    const char *name, *args = NULL;
    apr_status_t rv;

    if (gconf->session_cache) {
        goto cleanup;
    }
    else if (!apr_strnatcasecmp("none", gconf->session_cache_spec)) {
        gconf->session_cache_provider = NULL;
        gconf->session_cache = NULL;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, gconf->ap_server, APLOGNO(10346)
                     "session cache explicitly disabled");
        goto cleanup;
    }
    else if (!apr_strnatcasecmp("default", gconf->session_cache_spec)) {
        const char *path = TLS_CACHE_DEF_DIR;

#if AP_MODULE_MAGIC_AT_LEAST(20180906, 2)
        path = ap_state_dir_relative(p, path);
#endif
        gconf->session_cache_spec = apr_psprintf(p, "%s:%s/%s(%ld)",
            TLS_CACHE_DEF_PROVIDER, path, TLS_CACHE_DEF_FILE, (long)TLS_CACHE_DEF_SIZE);
        gconf->session_cache_spec = "shmcb:mod_tls-sesss(64000)";
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, gconf->ap_server, APLOGNO(10347)
                 "Using session cache: %s", gconf->session_cache_spec);
    name = gconf->session_cache_spec;
    args = ap_strchr((char*)name, ':');
    if (args) {
        name = apr_pstrmemdup(p, name, (apr_size_t)(args - name));
        ++args;
    }
    gconf->session_cache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                                       name, AP_SOCACHE_PROVIDER_VERSION);
    if (!gconf->session_cache_provider) {
        err = cache_provider_unknown(name, p);
        goto cleanup;
    }
    err = gconf->session_cache_provider->create(&gconf->session_cache, args, ptemp, p);
    if (err != NULL) goto cleanup;

    if (gconf->session_cache_provider->flags & AP_SOCACHE_FLAG_NOTMPSAFE
        && !gconf->session_cache_mutex) {
        /* we need a global lock to access the cache */
        rv = ap_global_mutex_create(&gconf->session_cache_mutex, NULL,
            TLS_SESSION_CACHE_MUTEX_TYPE, NULL, gconf->ap_server, p, 0);
        if (APR_SUCCESS != rv) {
            err = apr_psprintf(p, "error setting up global %s mutex: %d",
                TLS_SESSION_CACHE_MUTEX_TYPE, rv);
            gconf->session_cache_mutex = NULL;
            goto cleanup;
        }
    }

cleanup:
    if (NULL != err) {
        gconf->session_cache_provider = NULL;
        gconf->session_cache = NULL;
    }
    return err;
}

const char *tls_cache_set_specification(
    const char *spec, tls_conf_global_t *gconf, apr_pool_t *p, apr_pool_t *ptemp)
{
    gconf->session_cache_spec = spec;
    return cache_init(gconf, p, ptemp);
}

apr_status_t tls_cache_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    const char *err;
    apr_status_t rv = APR_SUCCESS;

    err = cache_init(sc->global, p, ptemp);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10348)
                     "session cache [%s] could not be initialized, will continue "
                     "without session one. Since this will impact performance, "
                     "consider making use of the 'TLSSessionCache' directive. The "
                     "error was: %s", sc->global->session_cache_spec, err);
    }

    if (sc->global->session_cache) {
        struct ap_socache_hints hints;

        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "provider init session cache [%s]",
                     sc->global->session_cache_spec);
        memset(&hints, 0, sizeof(hints));
        hints.avg_obj_size = 100;
        hints.avg_id_len = 33;
        hints.expiry_interval = 30;

        rv = sc->global->session_cache_provider->init(
            sc->global->session_cache, "mod_tls-sess", &hints, s, p);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO(10349)
                         "error initializing session cache.");
        }
    }
    return rv;
}

void tls_cache_init_child(apr_pool_t *p, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    const char *lockfile;
    apr_status_t rv;

    if (sc->global->session_cache_mutex) {
        lockfile = apr_global_mutex_lockfile(sc->global->session_cache_mutex);
        rv = apr_global_mutex_child_init(&sc->global->session_cache_mutex, lockfile, p);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10350)
                         "Cannot reinit %s mutex (file `%s`)",
                         TLS_SESSION_CACHE_MUTEX_TYPE, lockfile? lockfile : "-");
        }
    }
}

void tls_cache_free(server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    if (sc->global->session_cache_provider) {
        sc->global->session_cache_provider->destroy(sc->global->session_cache, s);
    }
}

static void tls_cache_lock(tls_conf_global_t *gconf)
{
    if (gconf->session_cache_mutex) {
        apr_status_t rv = apr_global_mutex_lock(gconf->session_cache_mutex);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, gconf->ap_server, APLOGNO(10351)
                         "Failed to acquire TLS session cache lock");
        }
    }
}

static void tls_cache_unlock(tls_conf_global_t *gconf)
{
    if (gconf->session_cache_mutex) {
        apr_status_t rv = apr_global_mutex_unlock(gconf->session_cache_mutex);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, gconf->ap_server, APLOGNO(10352)
                         "Failed to release TLS session cache lock");
        }
    }
}

static rustls_result tls_cache_get(
    void *userdata,
    const rustls_slice_bytes *key,
    int remove_after,
    unsigned char *buf,
    size_t count,
    size_t *out_n)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc = tls_conf_server_get(cc->server);
    apr_status_t rv = APR_ENOENT;
    unsigned int vlen, klen;
    const unsigned char *kdata;

    if (!sc->global->session_cache) goto not_found;
    tls_cache_lock(sc->global);

    kdata = key->data;
    klen = (unsigned int)key->len;
    vlen = (unsigned int)count;
    rv = sc->global->session_cache_provider->retrieve(
        sc->global->session_cache, cc->server, kdata, klen, buf, &vlen, c->pool);

    if (APLOGctrace4(c)) {
        apr_ssize_t n = klen;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, rv, c, "retrieve key %d[%8x], found %d val",
            klen, apr_hashfunc_default((const char*)kdata, &n), vlen);
    }
    if (remove_after || (APR_SUCCESS != rv && !APR_STATUS_IS_NOTFOUND(rv))) {
        sc->global->session_cache_provider->remove(
            sc->global->session_cache, cc->server, key->data, klen, c->pool);
    }

    tls_cache_unlock(sc->global);
    if (APR_SUCCESS != rv) goto not_found;
    cc->session_id_cache_hit = 1;
    *out_n = count;
    return RUSTLS_RESULT_OK;

not_found:
    *out_n = 0;
    return RUSTLS_RESULT_NOT_FOUND;
}

static rustls_result tls_cache_put(
    void *userdata,
    const rustls_slice_bytes *key,
    const rustls_slice_bytes *val)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc = tls_conf_server_get(cc->server);
    apr_status_t rv = APR_ENOENT;
    apr_time_t expires_at;
    unsigned int klen, vlen;
    const unsigned char *kdata;

    if (!sc->global->session_cache) goto not_stored;
    tls_cache_lock(sc->global);

    expires_at = apr_time_now() + apr_time_from_sec(300);
    kdata = key->data;
    klen = (unsigned int)key->len;
    vlen = (unsigned int)val->len;
    rv = sc->global->session_cache_provider->store(sc->global->session_cache, cc->server,
                                                   kdata, klen, expires_at,
                                                   (unsigned char*)val->data, vlen, c->pool);
    if (APLOGctrace4(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, rv, c,
            "stored %d key bytes, with %d val bytes", klen, vlen);
    }
    tls_cache_unlock(sc->global);
    if (APR_SUCCESS != rv) goto not_stored;
    return RUSTLS_RESULT_OK;

not_stored:
    return RUSTLS_RESULT_NOT_FOUND;
}

apr_status_t tls_cache_init_server(
    rustls_server_config_builder *builder, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);

    if (sc && sc->global->session_cache) {
        ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s, "adding session persistence to rustls");
        rustls_server_config_builder_set_persistence(
            builder, tls_cache_get, tls_cache_put);
    }
    return APR_SUCCESS;
}
