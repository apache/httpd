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
#include <apr_version.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_main.h>
#include <ap_socache.h>

#include <rustls.h>

#include "tls_cert.h"
#include "tls_proto.h"
#include "tls_conf.h"
#include "tls_util.h"
#include "tls_var.h"
#include "tls_cache.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

static tls_conf_global_t *conf_global_get_or_make(apr_pool_t *pool, server_rec *s)
{
    tls_conf_global_t *gconf;

    /* we create this only once for apache's one ap_server_conf.
     * If this gets called for another server, we should already have
     * done it for ap_server_conf. */
    if (ap_server_conf && s != ap_server_conf) {
        tls_conf_server_t *sconf = tls_conf_server_get(ap_server_conf);
        ap_assert(sconf);
        ap_assert(sconf->global);
        return sconf->global;
    }

    gconf = apr_pcalloc(pool, sizeof(*gconf));
    gconf->ap_server = ap_server_conf;
    gconf->status = TLS_CONF_ST_INIT;
    gconf->proto = tls_proto_init(pool, s);
    gconf->proxy_configs = apr_array_make(pool, 10, sizeof(tls_conf_proxy_t*));

    gconf->var_lookups = apr_hash_make(pool);
    tls_var_init_lookup_hash(pool, gconf->var_lookups);
    gconf->session_cache_spec = "default";

    return gconf;
}

tls_conf_server_t *tls_conf_server_get(server_rec *s)
{
    tls_conf_server_t *sc = ap_get_module_config(s->module_config, &tls_module);
    ap_assert(sc);
    return sc;
}


#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s)
{
    tls_conf_server_t *conf;

    conf = apr_pcalloc(pool, sizeof(*conf));
    conf->global = conf_global_get_or_make(pool, s);
    conf->server = s;

    conf->enabled = TLS_FLAG_UNSET;
    conf->cert_specs = apr_array_make(pool, 3, sizeof(tls_cert_spec_t*));
    conf->honor_client_order = TLS_FLAG_UNSET;
    conf->strict_sni = TLS_FLAG_UNSET;
    conf->tls_protocol_min = TLS_FLAG_UNSET;
    conf->tls_pref_ciphers = apr_array_make(pool, 3, sizeof(apr_uint16_t));;
    conf->tls_supp_ciphers = apr_array_make(pool, 3, sizeof(apr_uint16_t));;
    return conf;
}

#define MERGE_INT(base, add, field) \
    (add->field == TLS_FLAG_UNSET)? base->field : add->field;

void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    tls_conf_server_t *base = basev;
    tls_conf_server_t *add = addv;
    tls_conf_server_t *nconf;

    nconf = apr_pcalloc(pool, sizeof(*nconf));
    nconf->server = add->server;
    nconf->global = add->global? add->global : base->global;

    nconf->enabled = MERGE_INT(base, add, enabled);
    nconf->cert_specs = apr_array_append(pool, base->cert_specs, add->cert_specs);
    nconf->tls_protocol_min = MERGE_INT(base, add, tls_protocol_min);
    nconf->tls_pref_ciphers = add->tls_pref_ciphers->nelts?
        add->tls_pref_ciphers : base->tls_pref_ciphers;
    nconf->tls_supp_ciphers = add->tls_supp_ciphers->nelts?
        add->tls_supp_ciphers : base->tls_supp_ciphers;
    nconf->honor_client_order = MERGE_INT(base, add, honor_client_order);
    nconf->client_ca = add->client_ca? add->client_ca : base->client_ca;
    nconf->client_auth = (add->client_auth != TLS_CLIENT_AUTH_UNSET)?
        add->client_auth : base->client_auth;
    nconf->var_user_name = add->var_user_name? add->var_user_name : base->var_user_name;
    return nconf;
}

tls_conf_dir_t *tls_conf_dir_get(request_rec *r)
{
    tls_conf_dir_t *dc = ap_get_module_config(r->per_dir_config, &tls_module);
    ap_assert(dc);
    return dc;
}

tls_conf_dir_t *tls_conf_dir_server_get(server_rec *s)
{
    tls_conf_dir_t *dc = ap_get_module_config(s->lookup_defaults, &tls_module);
    ap_assert(dc);
    return dc;
}

void *tls_conf_create_dir(apr_pool_t *pool, char *dir)
{
    tls_conf_dir_t *conf;

    (void)dir;
    conf = apr_pcalloc(pool, sizeof(*conf));
    conf->std_env_vars = TLS_FLAG_UNSET;
    conf->proxy_enabled = TLS_FLAG_UNSET;
    conf->proxy_protocol_min = TLS_FLAG_UNSET;
    conf->proxy_pref_ciphers = apr_array_make(pool, 3, sizeof(apr_uint16_t));;
    conf->proxy_supp_ciphers = apr_array_make(pool, 3, sizeof(apr_uint16_t));;
    conf->proxy_machine_cert_specs = apr_array_make(pool, 3, sizeof(tls_cert_spec_t*));
    return conf;
}


static int same_proxy_settings(tls_conf_dir_t *a, tls_conf_dir_t *b)
{
    return a->proxy_ca == b->proxy_ca;
}

static void dir_assign_merge(
    tls_conf_dir_t *dest, apr_pool_t *pool, tls_conf_dir_t *base, tls_conf_dir_t *add)
{
    tls_conf_dir_t local;

    memset(&local, 0, sizeof(local));
    local.std_env_vars = MERGE_INT(base, add, std_env_vars);
    local.export_cert_vars = MERGE_INT(base, add, export_cert_vars);
    local.proxy_enabled = MERGE_INT(base, add, proxy_enabled);
    local.proxy_ca = add->proxy_ca? add->proxy_ca : base->proxy_ca;
    local.proxy_protocol_min = MERGE_INT(base, add, proxy_protocol_min);
    local.proxy_pref_ciphers = add->proxy_pref_ciphers->nelts?
        add->proxy_pref_ciphers : base->proxy_pref_ciphers;
    local.proxy_supp_ciphers = add->proxy_supp_ciphers->nelts?
        add->proxy_supp_ciphers : base->proxy_supp_ciphers;
    local.proxy_machine_cert_specs = apr_array_append(pool,
        base->proxy_machine_cert_specs, add->proxy_machine_cert_specs);
    if (local.proxy_enabled == TLS_FLAG_TRUE) {
        if (add->proxy_config) {
            local.proxy_config = same_proxy_settings(&local, add)? add->proxy_config : NULL;
        }
        else if (base->proxy_config) {
            local.proxy_config = same_proxy_settings(&local, base)? add->proxy_config : NULL;
        }
    }
    memcpy(dest, &local, sizeof(*dest));
}

void *tls_conf_merge_dir(apr_pool_t *pool, void *basev, void *addv)
{
    tls_conf_dir_t *base = basev;
    tls_conf_dir_t *add = addv;
    tls_conf_dir_t *nconf = apr_pcalloc(pool, sizeof(*nconf));
    dir_assign_merge(nconf, pool, base, add);
    return nconf;
}

static void tls_conf_dir_set_options_defaults(apr_pool_t *pool, tls_conf_dir_t *dc)
{
    (void)pool;
    dc->std_env_vars = TLS_FLAG_FALSE;
    dc->export_cert_vars = TLS_FLAG_FALSE;
}

apr_status_t tls_conf_server_apply_defaults(tls_conf_server_t *sc, apr_pool_t *p)
{
    (void)p;
    if (sc->enabled == TLS_FLAG_UNSET) sc->enabled = TLS_FLAG_FALSE;
    if (sc->tls_protocol_min == TLS_FLAG_UNSET) sc->tls_protocol_min = 0;
    if (sc->honor_client_order == TLS_FLAG_UNSET) sc->honor_client_order = TLS_FLAG_TRUE;
    if (sc->strict_sni == TLS_FLAG_UNSET) sc->strict_sni = TLS_FLAG_TRUE;
    if (sc->client_auth == TLS_CLIENT_AUTH_UNSET) sc->client_auth = TLS_CLIENT_AUTH_NONE;
    return APR_SUCCESS;
}

apr_status_t tls_conf_dir_apply_defaults(tls_conf_dir_t *dc, apr_pool_t *p)
{
    (void)p;
    if (dc->std_env_vars == TLS_FLAG_UNSET) dc->std_env_vars = TLS_FLAG_FALSE;
    if (dc->export_cert_vars == TLS_FLAG_UNSET) dc->export_cert_vars = TLS_FLAG_FALSE;
    if (dc->proxy_enabled == TLS_FLAG_UNSET) dc->proxy_enabled = TLS_FLAG_FALSE;
    return APR_SUCCESS;
}

tls_conf_proxy_t *tls_conf_proxy_make(
    apr_pool_t *p, tls_conf_dir_t *dc, tls_conf_global_t *gc, server_rec *s)
{
    tls_conf_proxy_t *pc = apr_pcalloc(p, sizeof(*pc));
    pc->defined_in = s;
    pc->global = gc;
    pc->proxy_ca = dc->proxy_ca;
    pc->proxy_protocol_min = dc->proxy_protocol_min;
    pc->proxy_pref_ciphers = dc->proxy_pref_ciphers;
    pc->proxy_supp_ciphers = dc->proxy_supp_ciphers;
    pc->machine_cert_specs = dc->proxy_machine_cert_specs;
    pc->machine_certified_keys = apr_array_make(p, 3, sizeof(const rustls_certified_key*));
    return pc;
}

int tls_proxy_section_post_config(
    apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s,
    ap_conf_vector_t *section_config)
{
    tls_conf_dir_t *proxy_dc, *server_dc;
    tls_conf_server_t *sc;

    /* mod_proxy collects the <Proxy>...</Proxy> sections per server (base server or virtualhost)
     * and in its post_config hook, calls our function registered at its hook for each with
     * s - the server they were define in
     * section_config - the set of dir_configs for a <Proxy> section
     *
     * If none of _our_ config directives had been used, here or in the server, we get a NULL.
     * Which means we have to do nothing. Otherwise, we add to `proxy_dc` the
     * settings from `server_dc` - since this is not automagically done by apache.
     *
     * `proxy_dc` is then complete and tells us if we handle outgoing connections
     * here and with what parameter settings.
     */
    (void)ptemp; (void)plog;
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
        "%s: tls_proxy_section_post_config called", s->server_hostname);
    proxy_dc = ap_get_module_config(section_config, &tls_module);
    if (!proxy_dc) goto cleanup;
    server_dc = ap_get_module_config(s->lookup_defaults, &tls_module);
    ap_assert(server_dc);
    dir_assign_merge(proxy_dc, p, server_dc, proxy_dc);
    tls_conf_dir_apply_defaults(proxy_dc, p);
    if (proxy_dc->proxy_enabled && !proxy_dc->proxy_config) {
        /* remember `proxy_dc` for subsequent configuration of outoing TLS setups */
        sc = tls_conf_server_get(s);
        proxy_dc->proxy_config = tls_conf_proxy_make(p, proxy_dc, sc->global, s);
        ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s,
            "%s: adding proxy_conf to globals in proxy_post_config_section",
            s->server_hostname);
        APR_ARRAY_PUSH(sc->global->proxy_configs, tls_conf_proxy_t*) = proxy_dc->proxy_config;
    }
cleanup:
    return OK;
}

static const char *cmd_check_file(cmd_parms *cmd, const char *fpath)
{
    char *real_path;

    /* just a dump of the configuration, dont resolve/check */
    if (ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_DUMP) {
        return NULL;
    }
    real_path = ap_server_root_relative(cmd->pool, fpath);
    if (!real_path) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": Invalid file path ", fpath, NULL);
    }
    if (!tls_util_is_file(cmd->pool, real_path)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": file '", real_path,
                           "' does not exist or is empty", NULL);
    }
    return NULL;
}

static const char *tls_conf_add_engine(cmd_parms *cmd, void *dc, const char*v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    tls_conf_global_t *gc = sc->global;
    const char *err = NULL;
    char *host, *scope_id;
    apr_port_t port;
    apr_sockaddr_t *sa;
    server_addr_rec *sar;
    apr_status_t rv;

    (void)dc;
    /* Example of use:
     * TLSEngine 443
     * TLSEngine hostname:443
     * TLSEngine 91.0.0.1:443
     * TLSEngine [::0]:443
     */
    rv = apr_parse_addr_port(&host, &scope_id, &port, v, cmd->pool);
    if (APR_SUCCESS != rv) {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                          ": invalid address/port in '", v, "'", NULL);
        goto cleanup;
    }

    /* translate host/port to a sockaddr that we can match with incoming connections */
    rv = apr_sockaddr_info_get(&sa, host, APR_UNSPEC, port, 0, cmd->pool);
    if (APR_SUCCESS != rv) {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                          ": unable to get sockaddr for '", host, "'", NULL);
        goto cleanup;
    }

    if (scope_id) {
#if APR_VERSION_AT_LEAST(1,7,0)
        rv = apr_sockaddr_zone_set(sa, scope_id);
        if (APR_SUCCESS != rv) {
            err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                              ": error setting ipv6 scope id: '", scope_id, "'", NULL);
            goto cleanup;
        }
#else
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                          ": IPv6 scopes not supported by your APR: '", scope_id, "'", NULL);
        goto cleanup;
#endif
    }

    sar = apr_pcalloc(cmd->pool, sizeof(*sar));
    sar->host_addr = sa;
    sar->virthost = host;
    sar->host_port = port;

    sar->next = gc->tls_addresses;
    gc->tls_addresses = sar;
cleanup:
    return err;
}

static int flag_value(
    const char *arg)
{
    if (!strcasecmp(arg, "On")) {
        return TLS_FLAG_TRUE;
    }
    else if (!strcasecmp(arg, "Off")) {
        return TLS_FLAG_FALSE;
    }
    return TLS_FLAG_UNSET;
}

static const char *flag_err(
    cmd_parms *cmd, const char *v)
{
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
        ": value must be 'On' or 'Off': '", v, "'", NULL);
}

static const char *tls_conf_add_certificate(
    cmd_parms *cmd, void *dc, const char *cert_file, const char *pkey_file)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL, *fpath;
    tls_cert_spec_t *cert;

    (void)dc;
    if (NULL != (err = cmd_check_file(cmd, cert_file))) goto cleanup;
    /* key file may be NULL, in which case cert_file must contain the key PEM */
    if (pkey_file && NULL != (err = cmd_check_file(cmd, pkey_file))) goto cleanup;

    cert = apr_pcalloc(cmd->pool, sizeof(*cert));
    fpath = ap_server_root_relative(cmd->pool, cert_file);
    if (!tls_util_is_file(cmd->pool, fpath)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": unable to find certificate file: '", fpath, "'", NULL);
    }
    cert->cert_file = cert_file;
    if (pkey_file) {
        fpath = ap_server_root_relative(cmd->pool, pkey_file);
        if (!tls_util_is_file(cmd->pool, fpath)) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name,
                ": unable to find certificate key file: '", fpath, "'", NULL);
        }
    }
    cert->pkey_file = pkey_file;
    *(const tls_cert_spec_t **)apr_array_push(sc->cert_specs) = cert;

cleanup:
    return err;
}

static const char *parse_ciphers(
    cmd_parms *cmd,
    tls_conf_global_t *gc,
    const char *nop_name,
    int argc, char *const argv[],
    apr_array_header_t *ciphers)
{
    apr_array_clear(ciphers);
    if (argc > 1 || apr_strnatcasecmp(nop_name, argv[0])) {
        apr_uint16_t cipher;
        int i;

        for (i = 0; i < argc; ++i) {
            char *name, *last = NULL;
            const char *value = argv[i];

            name = apr_strtok(apr_pstrdup(cmd->pool, value), ":", &last);
            while (name) {
                if (tls_proto_get_cipher_by_name(gc->proto, name, &cipher) != APR_SUCCESS) {
                    return apr_pstrcat(cmd->pool, cmd->cmd->name,
                            ": cipher not recognized '", name, "'", NULL);
                }
                APR_ARRAY_PUSH(ciphers, apr_uint16_t) = cipher;
                name = apr_strtok(NULL, ":", &last);
            }
        }
    }
    return NULL;
}

static const char *tls_conf_set_preferred_ciphers(
    cmd_parms *cmd, void *dc, int argc, char *const argv[])
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    (void)dc;
    if (!argc) {
        err = "specify the TLS ciphers to prefer or 'default' for the rustls default ordering.";
        goto cleanup;
    }
    err = parse_ciphers(cmd, sc->global, "default", argc, argv, sc->tls_pref_ciphers);
cleanup:
    return err;
}

static const char *tls_conf_set_suppressed_ciphers(
    cmd_parms *cmd, void *dc, int argc, char *const argv[])
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    (void)dc;
    if (!argc) {
        err = "specify the TLS ciphers to never use or 'none'.";
        goto cleanup;
    }
    err = parse_ciphers(cmd, sc->global, "none", argc, argv, sc->tls_supp_ciphers);
cleanup:
    return err;
}

static const char *tls_conf_set_honor_client_order(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    int flag = flag_value(v);

    (void)dc;
    if (TLS_FLAG_UNSET == flag) return flag_err(cmd, v);
    sc->honor_client_order = flag;
    return NULL;
}

static const char *tls_conf_set_strict_sni(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    int flag = flag_value(v);

    (void)dc;
    if (TLS_FLAG_UNSET == flag) return flag_err(cmd, v);
    sc->strict_sni = flag;
    return NULL;
}

static const char *get_min_protocol(
    cmd_parms *cmd, const char *v, int *pmin)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    if (!apr_strnatcasecmp("default", v)) {
        *pmin = 0;
    }
    else if (*v && v[strlen(v)-1] == '+') {
        char *name = apr_pstrdup(cmd->pool, v);
        name[strlen(name)-1] = '\0';
        *pmin = tls_proto_get_version_by_name(sc->global->proto, name);
        if (!*pmin) {
            err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                ": unrecognized protocol version specifier (try TLSv1.2+ or TLSv1.3+): '", v, "'", NULL);
            goto cleanup;
        }
    }
    else {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": value must be 'default', 'TLSv1.2+' or 'TLSv1.3+': '", v, "'", NULL);
        goto cleanup;
    }
cleanup:
    return err;
}

static const char *tls_conf_set_protocol(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    (void)dc;
    return get_min_protocol(cmd, v, &sc->tls_protocol_min);
}

static const char *tls_conf_set_options(
    cmd_parms *cmd, void *dcv, int argc, char *const argv[])
{
    tls_conf_dir_t *dc = dcv;
    const char *err = NULL, *option;
    int i, val;

    /* Are we only having deltas (+/-) or do we reset the options? */
    for (i = 0; i < argc; ++i) {
        if (argv[i][0] != '+' && argv[i][0] != '-') {
            tls_conf_dir_set_options_defaults(cmd->pool, dc);
            break;
        }
    }

    for (i = 0; i < argc; ++i) {
        option = argv[i];
        if (!apr_strnatcasecmp("Defaults", option)) {
            dc->std_env_vars = TLS_FLAG_FALSE;
            dc->export_cert_vars = TLS_FLAG_FALSE;
        }
        else {
            val = TLS_FLAG_TRUE;
            if (*option == '+' || *option == '-') {
                val = (*option == '+')? TLS_FLAG_TRUE : TLS_FLAG_FALSE;
                ++option;
            }

            if (!apr_strnatcasecmp("StdEnvVars", option)) {
                dc->std_env_vars = val;
            }
            else if (!apr_strnatcasecmp("ExportCertData", option)) {
                dc->export_cert_vars = val;
            }
            else {
                err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   ": unknown option '", option, "'", NULL);
                goto cleanup;
            }
        }
    }
cleanup:
    return err;
}

static const char *tls_conf_set_session_cache(
    cmd_parms *cmd, void *dc, const char *value)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    (void)dc;
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) goto cleanup;

    err = tls_cache_set_specification(value, sc->global, cmd->pool, cmd->temp_pool);
cleanup:
    return err;
}

static const char *tls_conf_set_proxy_engine(cmd_parms *cmd, void *dir_conf, int flag)
{
    tls_conf_dir_t *dc = dir_conf;
    (void)cmd;
    dc->proxy_enabled = flag ? TLS_FLAG_TRUE : TLS_FLAG_FALSE;
    return NULL;
}

static const char *tls_conf_set_proxy_ca(
    cmd_parms *cmd, void *dir_conf, const char *proxy_ca)
{
    tls_conf_dir_t *dc = dir_conf;
    const char *err = NULL;

    if (strcasecmp(proxy_ca, "default") && NULL != (err = cmd_check_file(cmd, proxy_ca))) goto cleanup;
    dc->proxy_ca = proxy_ca;
cleanup:
    return err;
}

static const char *tls_conf_set_proxy_protocol(
    cmd_parms *cmd, void *dir_conf, const char *v)
{
    tls_conf_dir_t *dc = dir_conf;
    return get_min_protocol(cmd, v, &dc->proxy_protocol_min);
}

static const char *tls_conf_set_proxy_preferred_ciphers(
    cmd_parms *cmd, void *dir_conf, int argc, char *const argv[])
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    tls_conf_dir_t *dc = dir_conf;
    const char *err = NULL;

    if (!argc) {
        err = "specify the proxy TLS ciphers to prefer or 'default' for the rustls default ordering.";
        goto cleanup;
    }
    err = parse_ciphers(cmd, sc->global, "default", argc, argv, dc->proxy_pref_ciphers);
cleanup:
    return err;
}

static const char *tls_conf_set_proxy_suppressed_ciphers(
    cmd_parms *cmd, void *dir_conf, int argc, char *const argv[])
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    tls_conf_dir_t *dc = dir_conf;
    const char *err = NULL;

    if (!argc) {
        err = "specify the proxy TLS ciphers to never use or 'none'.";
        goto cleanup;
    }
    err = parse_ciphers(cmd, sc->global, "none", argc, argv, dc->proxy_supp_ciphers);
cleanup:
    return err;
}

#if TLS_CLIENT_CERTS

static const char *tls_conf_set_client_ca(
    cmd_parms *cmd, void *dc, const char *client_ca)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err;

    (void)dc;
    if (NULL != (err = cmd_check_file(cmd, client_ca))) goto cleanup;
    sc->client_ca = client_ca;
cleanup:
    return err;
}

static const char *tls_conf_set_client_auth(
    cmd_parms *cmd, void *dc, const char *mode)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;
    (void)dc;
    if (!strcasecmp(mode, "required")) {
        sc->client_auth = TLS_CLIENT_AUTH_REQUIRED;
    }
    else if (!strcasecmp(mode, "optional")) {
        sc->client_auth = TLS_CLIENT_AUTH_OPTIONAL;
    }
    else if (!strcasecmp(mode, "none")) {
        sc->client_auth = TLS_CLIENT_AUTH_NONE;
    }
    else {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": unknown value: '", mode, "', use required/optional/none.", NULL);
    }
    return err;
}

static const char *tls_conf_set_user_name(
    cmd_parms *cmd, void *dc, const char *var_user_name)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    (void)dc;
    sc->var_user_name = var_user_name;
    return NULL;
}

#endif /* if TLS_CLIENT_CERTS */

#if TLS_MACHINE_CERTS

static const char *tls_conf_add_proxy_machine_certificate(
    cmd_parms *cmd, void *dir_conf, const char *cert_file, const char *pkey_file)
{
    tls_conf_dir_t *dc = dir_conf;
    const char *err = NULL, *fpath;
    tls_cert_spec_t *cert;

    (void)dc;
    if (NULL != (err = cmd_check_file(cmd, cert_file))) goto cleanup;
    /* key file may be NULL, in which case cert_file must contain the key PEM */
    if (pkey_file && NULL != (err = cmd_check_file(cmd, pkey_file))) goto cleanup;

    cert = apr_pcalloc(cmd->pool, sizeof(*cert));
    fpath = ap_server_root_relative(cmd->pool, cert_file);
    if (!tls_util_is_file(cmd->pool, fpath)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": unable to find certificate file: '", fpath, "'", NULL);
    }
    cert->cert_file = cert_file;
    if (pkey_file) {
        fpath = ap_server_root_relative(cmd->pool, pkey_file);
        if (!tls_util_is_file(cmd->pool, fpath)) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name,
                ": unable to find certificate key file: '", fpath, "'", NULL);
        }
    }
    cert->pkey_file = pkey_file;
    *(const tls_cert_spec_t **)apr_array_push(dc->proxy_machine_cert_specs) = cert;

cleanup:
    return err;
}

#endif  /* if TLS_MACHINE_CERTS */

const command_rec tls_conf_cmds[] = {
    AP_INIT_TAKE12("TLSCertificate", tls_conf_add_certificate, NULL, RSRC_CONF,
        "Add a certificate to the server by specifying a file containing the "
        "certificate PEM, followed by its chain PEMs. The PEM of the key must "
        "either also be there or can be given as a separate file."),
    AP_INIT_TAKE_ARGV("TLSCiphersPrefer", tls_conf_set_preferred_ciphers, NULL, RSRC_CONF,
        "Set the TLS ciphers to prefer when negotiating with a client."),
    AP_INIT_TAKE_ARGV("TLSCiphersSuppress", tls_conf_set_suppressed_ciphers, NULL, RSRC_CONF,
        "Set the TLS ciphers to never use when negotiating with a client."),
    AP_INIT_TAKE1("TLSHonorClientOrder", tls_conf_set_honor_client_order, NULL, RSRC_CONF,
        "Set 'on' to have the server honor client preferences in cipher suites, default off."),
    AP_INIT_TAKE1("TLSEngine", tls_conf_add_engine, NULL, RSRC_CONF,
        "Specify an address+port where the module shall handle incoming TLS connections."),
    AP_INIT_TAKE_ARGV("TLSOptions", tls_conf_set_options, NULL, OR_OPTIONS,
        "En-/disables optional features in the module."),
    AP_INIT_TAKE1("TLSProtocol", tls_conf_set_protocol, NULL, RSRC_CONF,
        "Set the minimum TLS protocol version to use."),
    AP_INIT_TAKE1("TLSStrictSNI", tls_conf_set_strict_sni, NULL, RSRC_CONF,
        "Set strictness of client server name (SNI) check against hosts, default on."),
    AP_INIT_TAKE1("TLSSessionCache", tls_conf_set_session_cache, NULL, RSRC_CONF,
        "Set which cache to use for TLS sessions."),
    AP_INIT_FLAG("TLSProxyEngine", tls_conf_set_proxy_engine, NULL, RSRC_CONF|PROXY_CONF,
        "Enable TLS encryption of outgoing connections in this location/server."),
    AP_INIT_TAKE1("TLSProxyCA", tls_conf_set_proxy_ca, NULL, RSRC_CONF|PROXY_CONF,
        "Set the trust anchors for certificates from proxied backend servers from a PEM file."),
    AP_INIT_TAKE1("TLSProxyProtocol", tls_conf_set_proxy_protocol, NULL, RSRC_CONF|PROXY_CONF,
        "Set the minimum TLS protocol version to use for proxy connections."),
    AP_INIT_TAKE_ARGV("TLSProxyCiphersPrefer", tls_conf_set_proxy_preferred_ciphers, NULL, RSRC_CONF|PROXY_CONF,
        "Set the TLS ciphers to prefer when negotiating a proxy connection."),
    AP_INIT_TAKE_ARGV("TLSProxyCiphersSuppress", tls_conf_set_proxy_suppressed_ciphers, NULL, RSRC_CONF|PROXY_CONF,
        "Set the TLS ciphers to never use when negotiating a proxy connection."),
#if TLS_CLIENT_CERTS
    AP_INIT_TAKE1("TLSClientCA", tls_conf_set_client_ca, NULL, RSRC_CONF,
        "Set the trust anchors for client certificates from a PEM file."),
    AP_INIT_TAKE1("TLSClientCertificate", tls_conf_set_client_auth, NULL, RSRC_CONF,
        "If TLS client authentication is 'required', 'optional' or 'none'."),
    AP_INIT_TAKE1("TLSUserName", tls_conf_set_user_name, NULL, RSRC_CONF,
        "Set the SSL variable to be used as user name."),
#endif  /* if TLS_CLIENT_CERTS */
#if TLS_MACHINE_CERTS
    AP_INIT_TAKE12("TLSProxyMachineCertificate", tls_conf_add_proxy_machine_certificate, NULL, RSRC_CONF|PROXY_CONF,
        "Add a certificate to be used as client certificate on a proxy connection. "),
#endif  /* if TLS_MACHINE_CERTS */
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
