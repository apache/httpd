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
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <ap_listen.h>

#include "mod_status.h"

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_config.h"
#include "mod_md_drive.h"
#include "mod_md_os.h"
#include "mod_md_status.h"
#include "mod_ssl_openssl.h"

static void md_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(md) = {
    STANDARD20_MODULE_STUFF,
    NULL,                 /* func to create per dir config */
    NULL,                 /* func to merge per dir config */
    md_config_create_svr, /* func to create per server config */
    md_config_merge_svr,  /* func to merge per server config */
    md_cmds,              /* command handlers */
    md_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};

/**************************************************************************************************/
/* logging setup */

static server_rec *log_server;

static int log_is_level(void *baton, apr_pool_t *p, md_log_level_t level)
{
    (void)baton;
    (void)p;
    if (log_server) {
        return APLOG_IS_LEVEL(log_server, (int)level);
    }
    return level <= MD_LOG_INFO;
}

#define LOG_BUF_LEN 16*1024

static void log_print(const char *file, int line, md_log_level_t level, 
                      apr_status_t rv, void *baton, apr_pool_t *p, const char *fmt, va_list ap)
{
    if (log_is_level(baton, p, level)) {
        char buffer[LOG_BUF_LEN];
        
        memset(buffer, 0, sizeof(buffer));
        apr_vsnprintf(buffer, LOG_BUF_LEN-1, fmt, ap);
        buffer[LOG_BUF_LEN-1] = '\0';

        if (log_server) {
            ap_log_error(file, line, APLOG_MODULE_INDEX, (int)level, rv, log_server, "%s",buffer);
        }
        else {
            ap_log_perror(file, line, APLOG_MODULE_INDEX, (int)level, rv, p, "%s", buffer);
        }
    }
}

/**************************************************************************************************/
/* mod_ssl interface */

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *opt_ssl_is_https;

static void init_ssl(void)
{
    opt_ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
}

/**************************************************************************************************/
/* lifecycle */

static apr_status_t cleanup_setups(void *dummy)
{
    (void)dummy;
    log_server = NULL;
    return APR_SUCCESS;
}

static void init_setups(apr_pool_t *p, server_rec *base_server) 
{
    log_server = base_server;
    apr_pool_cleanup_register(p, NULL, cleanup_setups, apr_pool_cleanup_null);
}

/**************************************************************************************************/
/* store & registry setup */

static apr_status_t store_file_ev(void *baton, struct md_store_t *store,
                                    md_store_fs_ev_t ev, unsigned int group, 
                                    const char *fname, apr_filetype_e ftype,  
                                    apr_pool_t *p)
{
    server_rec *s = baton;
    apr_status_t rv;
    
    (void)store;
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s, "store event=%d on %s %s (group %d)", 
                 ev, (ftype == APR_DIR)? "dir" : "file", fname, group);
                 
    /* Directories in group CHALLENGES, STAGING and OCSP are written to 
     * under a different user. Give her ownership. 
     */
    if (ftype == APR_DIR) {
        switch (group) {
            case MD_SG_CHALLENGES:
            case MD_SG_STAGING:
                rv = md_make_worker_accessible(fname, p);
                if (APR_ENOTIMPL != rv) {
                    return rv;
                }
                break;
            default: 
                break;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t check_group_dir(md_store_t *store, md_store_group_t group, 
                                    apr_pool_t *p, server_rec *s)
{
    const char *dir;
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = md_store_get_fname(&dir, store, group, NULL, NULL, p))
        && APR_SUCCESS == (rv = apr_dir_make_recursive(dir, MD_FPROT_D_UALL_GREAD, p))) {
        rv = store_file_ev(s, store, MD_S_FS_EV_CREATED, group, dir, APR_DIR, p);
    }
    return rv;
}

static apr_status_t setup_store(md_store_t **pstore, md_mod_conf_t *mc, 
                                apr_pool_t *p, server_rec *s)
{
    const char *base_dir;
    apr_status_t rv;
    
    base_dir = ap_server_root_relative(p, mc->base_dir);
    
    if (APR_SUCCESS != (rv = md_store_fs_init(pstore, p, base_dir))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10046)"setup store for %s", base_dir);
        goto out;
    }

    md_store_fs_set_event_cb(*pstore, store_file_ev, s);
    if (APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_CHALLENGES, p, s))
        || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_STAGING, p, s))
        || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_ACCOUNTS, p, s))
        ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047) 
                     "setup challenges directory");
    }
    
out:
    return rv;
}

/**************************************************************************************************/
/* post config handling */

static void merge_srv_config(md_t *md, md_srv_conf_t *base_sc, apr_pool_t *p)
{
    if (!md->sc) {
        md->sc = base_sc;
    }

    if (!md->ca_url) {
        md->ca_url = md_config_gets(md->sc, MD_CONFIG_CA_URL);
    }
    if (!md->ca_proto) {
        md->ca_proto = md_config_gets(md->sc, MD_CONFIG_CA_PROTO);
    }
    if (!md->ca_agreement) {
        md->ca_agreement = md_config_gets(md->sc, MD_CONFIG_CA_AGREEMENT);
    }
    if (md->sc->s->server_admin && strcmp(DEFAULT_ADMIN, md->sc->s->server_admin)) {
        apr_array_clear(md->contacts);
        APR_ARRAY_PUSH(md->contacts, const char *) = 
        md_util_schemify(p, md->sc->s->server_admin, "mailto");
    }
    if (md->renew_mode == MD_RENEW_DEFAULT) {
        md->renew_mode = md_config_geti(md->sc, MD_CONFIG_DRIVE_MODE);
    }
    if (!md->renew_window) md_config_get_timespan(&md->renew_window, md->sc, MD_CONFIG_RENEW_WINDOW);
    if (!md->warn_window) md_config_get_timespan(&md->warn_window, md->sc, MD_CONFIG_WARN_WINDOW);
    if (md->transitive < 0) {
        md->transitive = md_config_geti(md->sc, MD_CONFIG_TRANSITIVE);
    }
    if (!md->ca_challenges && md->sc->ca_challenges) {
        md->ca_challenges = apr_array_copy(p, md->sc->ca_challenges);
    }        
    if (!md->pkey_spec) {
        md->pkey_spec = md->sc->pkey_spec;
        
    }
    if (md->require_https < 0) {
        md->require_https = md_config_geti(md->sc, MD_CONFIG_REQUIRE_HTTPS);
    }
    if (md->must_staple < 0) {
        md->must_staple = md_config_geti(md->sc, MD_CONFIG_MUST_STAPLE);
    }
}

static apr_status_t check_coverage(md_t *md, const char *domain, server_rec *s, apr_pool_t *p)
{
    if (md_contains(md, domain, 0)) {
        return APR_SUCCESS;
    }
    else if (md->transitive) {
        APR_ARRAY_PUSH(md->domains, const char*) = apr_pstrdup(p, domain);
        return APR_SUCCESS;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(10040)
                     "Virtual Host %s:%d matches Managed Domain '%s', but the "
                     "name/alias %s itself is not managed. A requested MD certificate "
                     "will not match ServerName.",
                     s->server_hostname, s->port, md->name, domain);
        return APR_EINVAL;
    }
}

static apr_status_t md_covers_server(md_t *md, server_rec *s, apr_pool_t *p)
{
    apr_status_t rv;
    const char *name;
    int i;
    
    if (APR_SUCCESS == (rv = check_coverage(md, s->server_hostname, s, p)) && s->names) {
        for (i = 0; i < s->names->nelts; ++i) {
            name = APR_ARRAY_IDX(s->names, i, const char*);
            if (APR_SUCCESS != (rv = check_coverage(md, name, s, p))) {
                break;
            }
        }
    }
    return rv;
}

static int matches_port_somewhere(server_rec *s, int port)
{
    server_addr_rec *sa;
    
    for (sa = s->addrs; sa; sa = sa->next) {
        if (sa->host_port == port) {
            /* host_addr might be general (0.0.0.0) or specific, we count this as match */
            return 1;
        }
        if (sa->host_port == 0) {
            /* wildcard port, answers to all ports. Rare, but may work. */
            return 1;
        }
    }
    return 0;
}

static int uses_port(server_rec *s, int port)
{
    server_addr_rec *sa;
    int match = 0;
    for (sa = s->addrs; sa; sa = sa->next) {
        if (sa->host_port == port) {
            /* host_addr might be general (0.0.0.0) or specific, we count this as match */
            match = 1;
        }
        else {
            /* uses other port/wildcard */
            return 0;
        }
    }
    return match;
}

static apr_status_t detect_supported_ports(md_mod_conf_t *mc, server_rec *s, 
                                           apr_pool_t *p, int log_level)
{
    ap_listen_rec *lr;
    apr_sockaddr_t *sa;

    mc->can_http = 0;
    mc->can_https = 0;
    for (lr = ap_listeners; lr; lr = lr->next) {
        for (sa = lr->bind_addr; sa; sa = sa->next) {
            if  (sa->port == mc->local_80 
                 && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                mc->can_http = 1;
            }
            else if (sa->port == mc->local_443
                     && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                mc->can_https = 1;
            }
        }
    }

    ap_log_error(APLOG_MARK, log_level, 0, s, APLOGNO(10037)
                 "server seems%s reachable via http: (port 80->%d) "
                 "and%s reachable via https: (port 443->%d) ",
                 mc->can_http? "" : " not", mc->local_80,
                 mc->can_https? "" : " not", mc->local_443);
    return md_reg_set_props(mc->reg, p, mc->can_http, mc->can_https); 
}

static server_rec *get_https_server(const char *domain, server_rec *base_server)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    server_rec *s;
    request_rec r;

    sc = md_config_get(base_server);
    mc = sc->mc;
    memset(&r, 0, sizeof(r));
    
    for (s = base_server; s && (mc->local_443 > 0); s = s->next) {
        if (!mc->manage_base_server && s == base_server) {
            /* we shall not assign ourselves to the base server */
            continue;
        }
        r.server = s;
        if (ap_matches_request_vhost(&r, domain, s->port) && uses_port(s, mc->local_443)) {
            return s;
        }
    }
    return NULL;
}

static void init_acme_tls_1_domains(md_t *md, server_rec *base_server)
{
    server_rec *s;
    int i;
    const char *domain;
    
    /* Collect those domains that support the "acme-tls/1" protocol. This
     * is part of the MD (and not tested dynamically), since challenge selection
     * may be done outside the server, e.g. in the a2md command. */
     apr_array_clear(md->acme_tls_1_domains);
    for (i = 0; i < md->domains->nelts; ++i) {
        domain = APR_ARRAY_IDX(md->domains, i, const char*);
        if (NULL == (s = get_https_server(domain, base_server))) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10168)
                         "%s: no https server_rec found for %s", md->name, domain);
            continue;
        }
        if (!ap_is_allowed_protocol(NULL, NULL, s, PROTO_ACME_TLS_1)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10169)
                         "%s: https server_rec for %s does not have protocol %s enabled", 
                         md->name, domain, PROTO_ACME_TLS_1);
            continue;
        }
        APR_ARRAY_PUSH(md->acme_tls_1_domains, const char*) = domain;
    }
}

static apr_status_t link_md_to_servers(md_mod_conf_t *mc, md_t *md, server_rec *base_server, 
                                       apr_pool_t *p, apr_pool_t *ptemp)
{
    server_rec *s, *s_https;
    request_rec r;
    md_srv_conf_t *sc;
    apr_status_t rv = APR_SUCCESS;
    int i;
    const char *domain;
    apr_array_header_t *servers;
    
    sc = md_config_get(base_server);

    /* Assign the MD to all server_rec configs that it matches. If there already
     * is an assigned MD not equal this one, the configuration is in error.
     */
    memset(&r, 0, sizeof(r));
    servers = apr_array_make(ptemp, 5, sizeof(server_rec*));
    
    for (s = base_server; s; s = s->next) {
        if (!mc->manage_base_server && s == base_server) {
            /* we shall not assign ourselves to the base server */
            continue;
        }
        
        r.server = s;
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char*);
            
            if (ap_matches_request_vhost(&r, domain, s->port)) {
                /* Create a unique md_srv_conf_t record for this server, if there is none yet */
                sc = md_config_get_unique(s, p);
                
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10041)
                             "Server %s:%d matches md %s (config %s)", 
                             s->server_hostname, s->port, md->name, sc->name);
                
                if (sc->assigned == md) {
                    /* already matched via another domain name */
                    goto next_server;
                }
                else if (sc->assigned) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10042)
                                 "conflict: MD %s matches server %s, but MD %s also matches.",
                                 md->name, s->server_hostname, sc->assigned->name);
                    return APR_EINVAL;
                }
                
                /* If this server_rec is only for http: requests. Defined
                 * alias names do not matter for this MD.
                 * (see gh issue https://github.com/icing/mod_md/issues/57)
                 * Otherwise, if server has name or an alias not covered,
                 * it is by default auto-added (config transitive).
                 * If mode is "manual", a generated certificate will not match
                 * all necessary names. */
                if (!mc->local_80 || !uses_port(s, mc->local_80)) {
                    if (APR_SUCCESS != (rv = md_covers_server(md, s, p))) {
                        return rv;
                    }
                }

                sc->assigned = md;
                APR_ARRAY_PUSH(servers, server_rec*) = s;
                
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10043)
                             "Managed Domain %s applies to vhost %s:%d", md->name,
                             s->server_hostname, s->port);
                
                goto next_server;
            }
        }
    next_server:
        continue;
    }

    if (APR_SUCCESS == rv) {
        if (apr_is_empty_array(servers)) {
            if (md->renew_mode != MD_RENEW_ALWAYS) {
                /* Not an error, but looks suspicious */
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(10045)
                             "No VirtualHost matches Managed Domain %s", md->name);
                APR_ARRAY_PUSH(mc->unused_names, const char*)  = md->name;
            }
        }
        else {
            const char *uri;
            
            /* Found matching server_rec's. Collect all 'ServerAdmin's into MD's contact list */
            apr_array_clear(md->contacts);
            for (i = 0; i < servers->nelts; ++i) {
                s = APR_ARRAY_IDX(servers, i, server_rec*);
                if (s->server_admin && strcmp(DEFAULT_ADMIN, s->server_admin)) {
                    uri = md_util_schemify(p, s->server_admin, "mailto");
                    if (md_array_str_index(md->contacts, uri, 0, 0) < 0) {
                        APR_ARRAY_PUSH(md->contacts, const char *) = uri; 
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10044)
                                     "%s: added contact %s", md->name, uri);
                    }
                }
            }
            
            if (md->require_https > MD_REQUIRE_OFF) {
                /* We require https for this MD, but do we have port 443 (or a mapped one)
                 * available? */
                if (mc->local_443 <= 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10105)
                                 "MDPortMap says there is no port for https (443), "
                                 "but MD %s is configured to require https. This "
                                 "only works when a 443 port is available.", md->name);
                    return APR_EINVAL;
                    
                }
                
                /* Ok, we know which local port represents 443, do we have a server_rec
                 * for MD that has addresses with port 443? */
                s_https = NULL;
                for (i = 0; i < servers->nelts; ++i) {
                    s = APR_ARRAY_IDX(servers, i, server_rec*);
                    if (matches_port_somewhere(s, mc->local_443)) {
                        s_https = s;
                        break;
                    }
                }
                
                if (!s_https) {
                    /* Did not find any server_rec that matches this MD *and* has an
                     * s->addrs match for the https port. Suspicious. */
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(10106)
                                 "MD %s is configured to require https, but there seems to be "
                                 "no VirtualHost for it that has port %d in its address list. "
                                 "This looks as if it will not work.", 
                                 md->name, mc->local_443);
                }
            }
            
        }
        
    }
    return rv;
}

static apr_status_t link_mds_to_servers(md_mod_conf_t *mc, server_rec *s, 
                                            apr_pool_t *p, apr_pool_t *ptemp)
{
    int i;
    md_t *md;
    apr_status_t rv = APR_SUCCESS;
    
    apr_array_clear(mc->unused_names);
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        if (APR_SUCCESS != (rv = link_md_to_servers(mc, md, s, p, ptemp))) {
            goto leave;
        }
    }
leave:
    return rv;
}

static apr_status_t merge_mds_with_conf(md_mod_conf_t *mc, apr_pool_t *p, 
                                        server_rec *base_server, int log_level)
{
    md_srv_conf_t *base_conf;
    md_t *md, *omd;
    const char *domain;
    const md_timeslice_t *ts;
    apr_status_t rv = APR_SUCCESS;
    int i, j;

    /* The global module configuration 'mc' keeps a list of all configured MDomains
     * in the server. This list is collected during configuration processing and,
     * in the post config phase, get updated from all merged server configurations
     * before the server starts processing.
     */ 
    base_conf = md_config_get(base_server);
    md_config_get_timespan(&ts, base_conf, MD_CONFIG_RENEW_WINDOW);
    if (ts) md_reg_set_renew_window_default(mc->reg, ts);
    md_config_get_timespan(&ts, base_conf, MD_CONFIG_WARN_WINDOW);
    if (ts) md_reg_set_warn_window_default(mc->reg, ts);
 
    /* Complete the properties of the MDs, now that we have the complete, merged
     * server configurations.
     */
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        merge_srv_config(md, base_conf, p);

        /* Check that we have no overlap with the MDs already completed */
        for (j = 0; j < i; ++j) {
            omd = APR_ARRAY_IDX(mc->mds, j, md_t*);
            if ((domain = md_common_name(md, omd)) != NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10038)
                             "two Managed Domains have an overlap in domain '%s'"
                             ", first definition in %s(line %d), second in %s(line %d)",
                             domain, md->defn_name, md->defn_line_number,
                             omd->defn_name, omd->defn_line_number);
                return APR_EINVAL;
            }
        }
        
        if (md->cert_file && !md->pkey_file) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10170)
                         "The Managed Domain '%s', defined in %s(line %d), "
                         "has a MDCertificateFile but no MDCertificateKeyFile.",
                         md->name, md->defn_name, md->defn_line_number);
            return APR_EINVAL;
        }
        if (!md->cert_file && md->pkey_file) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10171)
                         "The Managed Domain '%s', defined in %s(line %d), "
                         "has a MDCertificateKeyFile but no MDCertificateFile.",
                         md->name, md->defn_name, md->defn_line_number);
            return APR_EINVAL;
        }

        init_acme_tls_1_domains(md, base_server);

        if (APLOG_IS_LEVEL(base_server, log_level)) {
            ap_log_error(APLOG_MARK, log_level, 0, base_server, APLOGNO(10039)
                         "Completed MD[%s, CA=%s, Proto=%s, Agreement=%s, renew-mode=%d "
                         "renew_window=%s, warn_window=%s",
                         md->name, md->ca_url, md->ca_proto, md->ca_agreement, md->renew_mode,
                         md->renew_window? md_timeslice_format(md->renew_window, p) : "unset",
                         md->warn_window? md_timeslice_format(md->warn_window, p) : "unset");
        }
    }
    return rv;
}

static void load_staged_data(md_mod_conf_t *mc, server_rec *s, apr_pool_t *p)
{
    apr_status_t rv;
    md_t *md;
    md_result_t *result;
    int i;
    
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t *);
        result = md_result_md_make(p, md);
        if (APR_SUCCESS == (rv = md_reg_load_staging(mc->reg, md, mc->env, result, p))) {
            ap_log_error( APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(10068) 
                         "%s: staged set activated", md->name);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10069)
                         "%s: error loading staged set", md->name);
        }
    }
}

static apr_status_t reinit_mds(md_mod_conf_t *mc, server_rec *s, apr_pool_t *p)
{
    md_t *md; 
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t *);
        if (APR_SUCCESS != (rv = md_reg_reinit_state(mc->reg, (md_t*)md, p))) {
            ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10172)
                         "%s: error reinitiazing from store", md->name);
            break;
        }
    }
    return rv;
}

static void init_watched_names(md_mod_conf_t *mc, apr_pool_t *p, apr_pool_t *ptemp, server_rec *s)
{
    const md_t *md;
    md_result_t *result;
    int i;
    
    /* Calculate the list of MD names which we need to watch:
     * - all MDs that are used somewhere
     * - all MDs in drive mode 'AUTO' that are not in 'unused_names'
     */
    result = md_result_make(ptemp, APR_SUCCESS);
    apr_array_clear(mc->watched_names);
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, const md_t *);
        md_result_set(result, APR_SUCCESS, NULL);

        if (md->state == MD_S_ERROR) {
            md_result_set(result, APR_EGENERAL, 
                          "in error state, unable to drive forward. This "
                          "indicates an incomplete or inconsistent configuration. "
                          "Please check the log for warnings in this regard.");
            continue;
        }

        if (md->renew_mode == MD_RENEW_AUTO
            && md_array_str_index(mc->unused_names, md->name, 0, 0) >= 0) {
            /* This MD is not used in any virtualhost, do not watch */
            continue;
        }
        
        if (md_will_renew_cert(md)) {
            /* make a test init to detect early errors. */
            md_reg_test_init(mc->reg, md, mc->env, result, p);
            if (APR_SUCCESS != result->status && result->detail) {
                apr_hash_set(mc->init_errors, md->name, APR_HASH_KEY_STRING, apr_pstrdup(p, result->detail));
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(10173) 
                             "md[%s]: %s", md->name, result->detail);
            }
        }
        
        APR_ARRAY_PUSH(mc->watched_names, const char *) = md->name; 
    }
}   

static apr_status_t md_post_config_before_ssl(apr_pool_t *p, apr_pool_t *plog,
                                              apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *mod_md_init_key = "mod_md_init_counter";
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_status_t rv = APR_SUCCESS;
    int dry_run = 0, log_level = APLOG_DEBUG;
    md_store_t *store;

    apr_pool_userdata_get(&data, mod_md_init_key, s->process->pool);
    if (data == NULL) {
        /* At the first start, httpd makes a config check dry run. It
         * runs all config hooks to check if it can. If so, it does
         * this all again and starts serving requests.
         * 
         * On a dry run, we therefore do all the cheap config things we
         * need to do to find out if the settings are ok. More expensive
         * things we delay to the real run.
         */
        dry_run = 1;
        log_level = APLOG_TRACE1;
        ap_log_error( APLOG_MARK, log_level, 0, s, APLOGNO(10070)
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, s->process->pool);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(10071)
                     "mod_md (v%s), initializing...", MOD_MD_VERSION);
    }

    (void)plog;
    init_setups(p, s);
    md_log_set(log_is_level, log_print, NULL);

    md_config_post_config(s, p);
    sc = md_config_get(s);
    mc = sc->mc;
    mc->dry_run = dry_run;

    if (APR_SUCCESS != (rv = setup_store(&store, mc, p, s))
        || APR_SUCCESS != (rv = md_reg_create(&mc->reg, p, store, mc->proxy_url))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10072) "setup md registry");
        goto leave;
    }

    init_ssl();

    /* How to bootstrap this module:
     * 1. find out if we know where http: and https: requests will arrive
     * 2. apply the now complete configuration setttings to the MDs
     * 3. Link MDs to the server_recs they are used in. Detect unused MDs.
     * 4. Update the store with the MDs. Change domain names, create new MDs, etc.
     *    Basically all MD properties that are configured directly.
     *    WARNING: this may change the name of an MD. If an MD loses the first
     *    of its domain names, it first gets the new first one as name. The 
     *    store will find the old settings and "recover" the previous name.
     * 5. Load any staged data from previous driving.
     * 6. on a dry run, this is all we do
     * 7. Read back the MD properties that reflect the existance and aspect of
     *    credentials that are in the store (or missing there). 
     *    Expiry times, MD state, etc.
     * 8. Determine the list of MDs that need driving/supervision.
     * 9. Cleanup any left-overs in registry/store that are no longer needed for
     *    the list of MDs as we know it now.
     * 10. If this list is non-empty, setup a watchdog to run. 
     */
    /*1*/
    if (APR_SUCCESS != (rv = detect_supported_ports(mc, s, p, log_level))) goto leave;
    /*2*/
    if (APR_SUCCESS != (rv = merge_mds_with_conf(mc, p, s, log_level))) goto leave;
    /*3*/
    if (APR_SUCCESS != (rv = link_mds_to_servers(mc, s, p, ptemp))) goto leave;
    /*4*/
    if (APR_SUCCESS != (rv = md_reg_sync(mc->reg, p, ptemp, mc->mds))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10073)
                     "synching %d mds to registry", mc->mds->nelts);
        goto leave;
    }
    /*5*/
    load_staged_data(mc, s, p);
    /*6*/
    if (dry_run) goto leave;
    /*7*/
    if (APR_SUCCESS != (rv = reinit_mds(mc, s, p))) goto leave;
    /*8*/
    init_watched_names(mc, p, ptemp, s);
    /*9*/
    md_reg_cleanup_challenges(mc->reg, p, ptemp, mc->mds);
    
    /* From here on, the domains in the registry are readonly 
     * and only staging/challenges may be manipulated */
    md_reg_freeze_domains(mc->reg, mc->mds);
    
    if (mc->watched_names->nelts > 0) {
        /*10*/
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10074)
                     "%d out of %d mds need watching", 
                     mc->watched_names->nelts, mc->mds->nelts);
    
        md_http_use_implementation(md_curl_get_impl(p));
        rv = md_start_watching(mc, s, p);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10075) "no mds to drive");
    }
leave:
    return rv;
}

/**************************************************************************************************/
/* connection context */

typedef struct {
    const char *protocol;
} md_conn_ctx;

static const char *md_protocol_get(const conn_rec *c)
{
    md_conn_ctx *ctx;

    ctx = (md_conn_ctx*)ap_get_module_config(c->conn_config, &md_module);
    return ctx? ctx->protocol : NULL;
}

/**************************************************************************************************/
/* ALPN handling */

static int md_protocol_propose(conn_rec *c, request_rec *r,
                               server_rec *s,
                               const apr_array_header_t *offers,
                               apr_array_header_t *proposals)
{
    (void)s;
    if (!r && offers && opt_ssl_is_https && opt_ssl_is_https(c) 
        && ap_array_str_contains(offers, PROTO_ACME_TLS_1)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "proposing protocol '%s'", PROTO_ACME_TLS_1);
        APR_ARRAY_PUSH(proposals, const char*) = PROTO_ACME_TLS_1;
        return OK;
    }
    return DECLINED;
}

static int md_protocol_switch(conn_rec *c, request_rec *r, server_rec *s,
                              const char *protocol)
{
    md_conn_ctx *ctx;
    
    (void)s;
    if (!r && opt_ssl_is_https && opt_ssl_is_https(c) && !strcmp(PROTO_ACME_TLS_1, protocol)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "switching protocol '%s'", PROTO_ACME_TLS_1);
        ctx = apr_pcalloc(c->pool, sizeof(*ctx));
        ctx->protocol = PROTO_ACME_TLS_1;
        ap_set_module_config(c->conn_config, &md_module, ctx);

        c->keepalive = AP_CONN_CLOSE;
        return OK;
    }
    return DECLINED;
}

 
/**************************************************************************************************/
/* Access API to other httpd components */

static int md_is_managed(server_rec *s)
{
    md_srv_conf_t *conf = md_config_get(s);

    if (conf && conf->assigned) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10076) 
                     "%s: manages server %s", conf->assigned->name, s->server_hostname);
        return 1;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,  
                 "server %s is not managed", s->server_hostname);
    return 0;
}

static apr_status_t setup_fallback_cert(md_store_t *store, const md_t *md, 
                                        server_rec *s, apr_pool_t *p)
{
    md_pkey_t *pkey;
    md_cert_t *cert;
    md_pkey_spec_t spec;
    apr_status_t rv;
    
    spec.type = MD_PKEY_TYPE_RSA;
    spec.params.rsa.bits = MD_PKEY_RSA_BITS_DEF;
    
    if (APR_SUCCESS != (rv = md_pkey_gen(&pkey, p, &spec))
        || APR_SUCCESS != (rv = md_store_save(store, p, MD_SG_DOMAINS, md->name, 
                                MD_FN_FALLBACK_PKEY, MD_SV_PKEY, (void*)pkey, 0))
        || APR_SUCCESS != (rv = md_cert_self_sign(&cert, "Apache Managed Domain Fallback", 
                                    md->domains, pkey, apr_time_from_sec(14 * MD_SECS_PER_DAY), p))
        || APR_SUCCESS != (rv = md_store_save(store, p, MD_SG_DOMAINS, md->name, 
                                MD_FN_FALLBACK_CERT, MD_SV_CERT, (void*)cert, 0))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10174)
                     "%s: setup fallback certificate", md->name);
    }
    return rv;
}

static apr_status_t get_certificate(server_rec *s, apr_pool_t *p, int fallback,
                                    const char **pcertfile, const char **pkeyfile)
{
    apr_status_t rv = APR_ENOENT;    
    md_srv_conf_t *sc;
    md_reg_t *reg;
    md_store_t *store;
    const md_t *md;
    
    *pkeyfile = NULL;
    *pcertfile = NULL;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10113)
                 "get_certificate called for vhost %s.", s->server_hostname);

    sc = md_config_get(s);
    if (!sc) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,  
                     "asked for certificate of server %s which has no md config", 
                     s->server_hostname);
        return APR_ENOENT;
    }
    
    if (!sc->assigned) {
        /* With the new hooks in mod_ssl, we are invoked for all server_rec. It is
         * therefore normal, when we have nothing to add here. */
        return APR_ENOENT;
    }
    
    assert(sc->mc);
    reg = sc->mc->reg;
    assert(reg);
    
    md = sc->assigned;
    if (!md) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10115) 
                     "unable to hand out certificates, as registry can no longer "
                     "find MD '%s'.", sc->assigned->name);
        return APR_ENOENT;
    }
    
    rv = md_reg_get_cred_files(pkeyfile, pcertfile, reg, MD_SG_DOMAINS, md, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        if (fallback) {
            /* Provide temporary, self-signed certificate as fallback, so that
             * clients do not get obscure TLS handshake errors or will see a fallback
             * virtual host that is not intended to be served here. */
            store = md_reg_store_get(reg);
            assert(store);    
            
            md_store_get_fname(pkeyfile, store, MD_SG_DOMAINS, md->name, MD_FN_FALLBACK_PKEY, p);
            md_store_get_fname(pcertfile, store, MD_SG_DOMAINS, md->name, MD_FN_FALLBACK_CERT, p);
            if (!md_file_exists(*pkeyfile, p) || !md_file_exists(*pcertfile, p)) { 
                if (APR_SUCCESS != (rv = setup_fallback_cert(store, md, s, p))) {
                    return rv;
                }
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10116)  
                         "%s: providing fallback certificate for server %s", 
                         md->name, s->server_hostname);
            return APR_EAGAIN;
        }
    }
    else if (APR_SUCCESS != rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10110) 
                     "retrieving credentials for MD %s", md->name);
        return rv;
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10077) 
                 "%s[state=%d]: providing certificate for server %s", 
                 md->name, md->state, s->server_hostname);
    return rv;
}

static apr_status_t md_get_certificate(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, const char **pcertfile)
{
    return get_certificate(s, p, 1, pcertfile, pkeyfile);
}

static int md_add_cert_files(server_rec *s, apr_pool_t *p,
                             apr_array_header_t *cert_files, 
                             apr_array_header_t *key_files)
{
    const char *certfile, *keyfile;
    apr_status_t rv;
    
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "hook ssl_add_cert_files for %s",
                 s->server_hostname);
    rv = get_certificate(s, p, 0, &certfile, &keyfile);
    if (APR_SUCCESS == rv) {
        if (!apr_is_empty_array(cert_files)) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10084)
                         "host '%s' is covered by a Managed Domain, but "
                         "certificate/key files are already configured "
                         "for it (most likely via SSLCertificateFile).", 
                         s->server_hostname);
        } 
        APR_ARRAY_PUSH(cert_files, const char*) = certfile;
        APR_ARRAY_PUSH(key_files, const char*) = keyfile;
        return DONE;
    }
    return DECLINED;
}

static int md_add_fallback_cert_files(server_rec *s, apr_pool_t *p,
                                      apr_array_header_t *cert_files, 
                                      apr_array_header_t *key_files)
{
    const char *certfile, *keyfile;
    apr_status_t rv;
    
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "hook ssl_add_fallback_cert_files for %s",
                 s->server_hostname);
    rv = get_certificate(s, p, 1, &certfile, &keyfile);
    if (APR_EAGAIN == rv) {
        APR_ARRAY_PUSH(cert_files, const char*) = certfile;
        APR_ARRAY_PUSH(key_files, const char*) = keyfile;
        return DONE;
    }
    return DECLINED;
}

static int md_is_challenge(conn_rec *c, const char *servername,
                           X509 **pcert, EVP_PKEY **pkey)
{
    md_srv_conf_t *sc;
    const char *protocol, *challenge, *cert_name, *pkey_name;
    apr_status_t rv;

    if (!servername) goto out;
                  
    challenge = NULL;
    if ((protocol = md_protocol_get(c)) && !strcmp(PROTO_ACME_TLS_1, protocol)) {
        challenge = "tls-alpn-01";
        cert_name = MD_FN_TLSALPN01_CERT;
        pkey_name = MD_FN_TLSALPN01_PKEY;

        sc = md_config_get(c->base_server);
        if (sc && sc->mc->reg) {
            md_store_t *store = md_reg_store_get(sc->mc->reg);
            md_cert_t *mdcert;
            md_pkey_t *mdpkey;
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "%s: load certs/keys %s/%s",
                          servername, cert_name, pkey_name);
            rv = md_store_load(store, MD_SG_CHALLENGES, servername, cert_name, 
                               MD_SV_CERT, (void**)&mdcert, c->pool);
            if (APR_SUCCESS == rv && (*pcert = md_cert_get_X509(mdcert))) {
                rv = md_store_load(store, MD_SG_CHALLENGES, servername, pkey_name, 
                                   MD_SV_PKEY, (void**)&mdpkey, c->pool);
                if (APR_SUCCESS == rv && (*pkey = md_pkey_get_EVP_PKEY(mdpkey))) {
                    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(10078)
                                  "%s: is a %s challenge host", servername, challenge);
                    return 1;
                }
                ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, c, APLOGNO(10079)
                              "%s: challenge data not complete, key unavailable", servername);
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(10080)
                              "%s: unknown %s challenge host", servername, challenge);
            }
        }
    }
out:
    *pcert = NULL;
    *pkey = NULL;
    return 0;
}

static int md_answer_challenge(conn_rec *c, const char *servername,
                               X509 **pcert, EVP_PKEY **pkey)
{
    if (md_is_challenge(c, servername, pcert, pkey)) {
        return APR_SUCCESS;
    }
    return DECLINED;
}

/**************************************************************************************************/
/* ACME 'http-01' challenge responses */

#define WELL_KNOWN_PREFIX           "/.well-known/"
#define ACME_CHALLENGE_PREFIX       WELL_KNOWN_PREFIX"acme-challenge/"

static int md_http_challenge_pr(request_rec *r)
{
    apr_bucket_brigade *bb;
    const md_srv_conf_t *sc;
    const char *name, *data;
    md_reg_t *reg;
    const md_t *md;
    apr_status_t rv;
    
    if (r->parsed_uri.path 
        && !strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
        sc = ap_get_module_config(r->server->module_config, &md_module);
        if (sc && sc->mc) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, 
                          "access inside /.well-known/acme-challenge for %s%s", 
                          r->hostname, r->parsed_uri.path);
            md = md_get_by_domain(sc->mc->mds, r->hostname);
            name = r->parsed_uri.path + sizeof(ACME_CHALLENGE_PREFIX)-1;
            reg = sc && sc->mc? sc->mc->reg : NULL;
            
            if (strlen(name) && !ap_strchr_c(name, '/') && reg) {
                md_store_t *store = md_reg_store_get(reg);
                
                rv = md_store_load(store, MD_SG_CHALLENGES, r->hostname, 
                                   MD_FN_HTTP01, MD_SV_TEXT, (void**)&data, r->pool);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, 
                              "loading challenge for %s (%s)", r->hostname, r->uri);
                if (APR_SUCCESS == rv) {
                    apr_size_t len = strlen(data);
                    
                    if (r->method_number != M_GET) {
                        return HTTP_NOT_IMPLEMENTED;
                    }
                    /* A GET on a challenge resource for a hostname we are
                     * configured for. Let's send the content back */
                    r->status = HTTP_OK;
                    apr_table_setn(r->headers_out, "Content-Length", apr_ltoa(r->pool, (long)len));
                    
                    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
                    apr_brigade_write(bb, NULL, NULL, data, len);
                    ap_pass_brigade(r->output_filters, bb);
                    apr_brigade_cleanup(bb);
                    
                    return DONE;
                }
                else if (!md || md->renew_mode == MD_RENEW_MANUAL
                    || (md->cert_file && md->renew_mode == MD_RENEW_AUTO)) {
                    /* The request hostname is not for a domain - or at least not for
                     * a domain that we renew ourselves. We are not
                     * the sole authority here for /.well-known/acme-challenge (see PR62189).
                     * So, we decline to handle this and give others a chance to provide
                     * the answer.
                     */
                    return DECLINED;
                }
                else if (APR_STATUS_IS_ENOENT(rv)) {
                    return HTTP_NOT_FOUND;
                }
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10081)
                              "loading challenge %s from store", name);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    return DECLINED;
}

/**************************************************************************************************/
/* Require Https hook */

static int md_require_https_maybe(request_rec *r)
{
    const md_srv_conf_t *sc;
    apr_uri_t uri;
    const char *s;
    int status;
    
    if (opt_ssl_is_https && r->parsed_uri.path
        && strncmp(WELL_KNOWN_PREFIX, r->parsed_uri.path, sizeof(WELL_KNOWN_PREFIX)-1)) {
        
        sc = ap_get_module_config(r->server->module_config, &md_module);
        if (sc && sc->assigned && sc->assigned->require_https > MD_REQUIRE_OFF) {
            if (opt_ssl_is_https(r->connection)) {
                /* Using https:
                 * if 'permanent' and no one else set a HSTS header already, do it */
                if (sc->assigned->require_https == MD_REQUIRE_PERMANENT 
                    && sc->mc->hsts_header && !apr_table_get(r->headers_out, MD_HSTS_HEADER)) {
                    apr_table_setn(r->headers_out, MD_HSTS_HEADER, sc->mc->hsts_header);
                }
            }
            else {
                /* Not using https:, but require it. Redirect. */
                if (r->method_number == M_GET) {
                    /* safe to use the old-fashioned codes */
                    status = ((MD_REQUIRE_PERMANENT == sc->assigned->require_https)? 
                              HTTP_MOVED_PERMANENTLY : HTTP_MOVED_TEMPORARILY);
                }
                else {
                    /* these should keep the method unchanged on retry */
                    status = ((MD_REQUIRE_PERMANENT == sc->assigned->require_https)? 
                              HTTP_PERMANENT_REDIRECT : HTTP_TEMPORARY_REDIRECT);
                }
                
                s = ap_construct_url(r->pool, r->uri, r);
                if (APR_SUCCESS == apr_uri_parse(r->pool, s, &uri)) {
                    uri.scheme = (char*)"https";
                    uri.port = 443;
                    uri.port_str = (char*)"443";
                    uri.query = r->parsed_uri.query;
                    uri.fragment = r->parsed_uri.fragment;
                    s = apr_uri_unparse(r->pool, &uri, APR_URI_UNP_OMITUSERINFO);
                    if (s && *s) {
                        apr_table_setn(r->headers_out, "Location", s);
                        return status;
                    }
                }
            }
        }
    }
    return DECLINED;
}

/* Runs once per created child process. Perform any process 
 * related initialization here.
 */
static void md_child_init(apr_pool_t *pool, server_rec *s)
{
    (void)pool;
    (void)s;
}

/* Install this module into the apache2 infrastructure.
 */
static void md_hooks(apr_pool_t *pool)
{
    static const char *const mod_ssl[] = { "mod_ssl.c", NULL};

    /* Leave the ssl initialization to mod_ssl or friends. */
    md_acme_init(pool, AP_SERVER_BASEVERSION, 0);
        
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    
    /* Run once after configuration is set, before mod_ssl.
     * Run again after mod_ssl is done.
     */
    ap_hook_post_config(md_post_config_before_ssl, NULL, mod_ssl, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, mod_ssl, APR_HOOK_MIDDLE);

    /* answer challenges *very* early, before any configured authentication may strike */
    ap_hook_post_read_request(md_require_https_maybe, mod_ssl, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(md_http_challenge_pr, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_protocol_propose(md_protocol_propose, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_protocol_switch(md_protocol_switch, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_protocol_get(md_protocol_get, NULL, NULL, APR_HOOK_MIDDLE);

    /* Status request handlers and contributors */
    ap_hook_post_read_request(md_http_cert_status, NULL, mod_ssl, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ap, status_hook, md_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(md_status_handler, NULL, NULL, APR_HOOK_MIDDLE);

#ifdef SSL_CERT_HOOKS
    (void)md_is_managed;
    (void)md_get_certificate;
    APR_OPTIONAL_HOOK(ssl, add_cert_files, md_add_cert_files, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, add_fallback_cert_files, md_add_fallback_cert_files, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, answer_challenge, md_answer_challenge, NULL, NULL, APR_HOOK_MIDDLE);
#else
    (void)md_add_cert_files;
    (void)md_add_fallback_cert_files;
    (void)md_answer_challenge;
    APR_REGISTER_OPTIONAL_FN(md_is_challenge);
    APR_REGISTER_OPTIONAL_FN(md_is_managed);
    APR_REGISTER_OPTIONAL_FN(md_get_certificate);
#endif
}

