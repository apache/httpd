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

#include <ap_release.h>
#ifndef AP_ENABLE_EXCEPTION_HOOK
#define AP_ENABLE_EXCEPTION_HOOK 0
#endif
#include <mpm_common.h>
#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <ap_listen.h>

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_config.h"
#include "mod_md_os.h"
#include "mod_ssl.h"
#include "mod_watchdog.h"

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

static void md_merge_srv(md_t *md, md_srv_conf_t *base_sc, apr_pool_t *p)
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
    if (md->drive_mode == MD_DRIVE_DEFAULT) {
        md->drive_mode = md_config_geti(md->sc, MD_CONFIG_DRIVE_MODE);
    }
    if (md->renew_norm <= 0 && md->renew_window <= 0) {
        md->renew_norm = md_config_get_interval(md->sc, MD_CONFIG_RENEW_NORM);
        md->renew_window = md_config_get_interval(md->sc, MD_CONFIG_RENEW_WINDOW);
    }
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

static int uses_port_only(server_rec *s, int port)
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

static apr_status_t assign_to_servers(md_t *md, server_rec *base_server, 
                                     apr_pool_t *p, apr_pool_t *ptemp)
{
    server_rec *s, *s_https;
    request_rec r;
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_status_t rv = APR_SUCCESS;
    int i;
    const char *domain;
    apr_array_header_t *servers;
    
    sc = md_config_get(base_server);
    mc = sc->mc;

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
                 * alias names to not matter for this MD.
                 * (see gh issue https://github.com/icing/mod_md/issues/57)
                 * Otherwise, if server has name or an alias not covered,
                 * it is by default auto-added (config transitive).
                 * If mode is "manual", a generated certificate will not match
                 * all necessary names. */
                if ((!mc->local_80 || !uses_port_only(s, mc->local_80))
                    && APR_SUCCESS != (rv = md_covers_server(md, s, p))) {
                    return rv;
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
            if (md->drive_mode != MD_DRIVE_ALWAYS) {
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

static apr_status_t md_calc_md_list(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *base_server)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    md_t *md, *omd;
    const char *domain;
    apr_status_t rv = APR_SUCCESS;
    ap_listen_rec *lr;
    apr_sockaddr_t *sa;
    int i, j;

    (void)plog;
    sc = md_config_get(base_server);
    mc = sc->mc;
    
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
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10037)
                 "server seems%s reachable via http: (port 80->%d) "
                 "and%s reachable via https: (port 443->%d) ",
                 mc->can_http? "" : " not", mc->local_80,
                 mc->can_https? "" : " not", mc->local_443);
    
    /* Complete the properties of the MDs, now that we have the complete, merged
     * server configurations. 
     */
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        md_merge_srv(md, sc, p);

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

        /* Assign MD to the server_rec configs that it matches. Perform some
         * last finishing touches on the MD. */
        if (APR_SUCCESS != (rv = assign_to_servers(md, base_server, p, ptemp))) {
            return rv;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10039)
                     "Completed MD[%s, CA=%s, Proto=%s, Agreement=%s, Drive=%d, renew=%ld]",
                     md->name, md->ca_url, md->ca_proto, md->ca_agreement,
                     md->drive_mode, (long)md->renew_window);
    }
    
    return rv;
}

/**************************************************************************************************/
/* store & registry setup */

static apr_status_t store_file_ev(void *baton, struct md_store_t *store,
                                    md_store_fs_ev_t ev, int group, 
                                    const char *fname, apr_filetype_e ftype,  
                                    apr_pool_t *p)
{
    server_rec *s = baton;
    apr_status_t rv;
    
    (void)store;
    ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, s, "store event=%d on %s %s (group %d)", 
                 ev, (ftype == APR_DIR)? "dir" : "file", fname, group);
                 
    /* Directories in group CHALLENGES and STAGING are written to by our watchdog,
     * running on certain mpms in a child process under a different user. Give them
     * ownership. 
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
    MD_CHK_VARS;
    
    base_dir = ap_server_root_relative(p, mc->base_dir);
    
    if (!MD_OK(md_store_fs_init(pstore, p, base_dir))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10046)"setup store for %s", base_dir);
        goto out;
    }

    md_store_fs_set_event_cb(*pstore, store_file_ev, s);
    if (   !MD_OK(check_group_dir(*pstore, MD_SG_CHALLENGES, p, s))
        || !MD_OK(check_group_dir(*pstore, MD_SG_STAGING, p, s))
        || !MD_OK(check_group_dir(*pstore, MD_SG_ACCOUNTS, p, s))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047) 
                     "setup challenges directory, call %s", MD_LAST_CHK);
    }
    
out:
    return rv;
}

static apr_status_t setup_reg(md_reg_t **preg, apr_pool_t *p, server_rec *s, 
                              int can_http, int can_https)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    md_store_t *store;
    apr_status_t rv;
    MD_CHK_VARS;
    
    sc = md_config_get(s);
    mc = sc->mc;
    
    if (   MD_OK(setup_store(&store, mc, p, s))
        && MD_OK(md_reg_init(preg, p, store, mc->proxy_url))) {
        mc->reg = *preg;
        return md_reg_set_props(*preg, p, can_http, can_https); 
    }
    return rv;
}

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
            ap_log_error(file, line, APLOG_MODULE_INDEX, level, rv, log_server, "%s",buffer);
        }
        else {
            ap_log_perror(file, line, APLOG_MODULE_INDEX, level, rv, p, "%s", buffer);
        }
    }
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
/* mod_ssl interface */

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *opt_ssl_is_https;

static void init_ssl(void)
{
    opt_ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
}

/**************************************************************************************************/
/* watchdog based impl. */

#define MD_WATCHDOG_NAME   "_md_"

static APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *wd_get_instance;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *wd_register_callback;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *wd_set_interval;

typedef struct {
    md_t *md;

    int stalled;
    int renewed;
    int renewal_notified;
    apr_time_t restart_at;
    int need_restart;
    int restart_processed;

    apr_status_t last_rv;
    apr_time_t next_check;
    int error_runs;
} md_job_t;

typedef struct {
    apr_pool_t *p;
    server_rec *s;
    md_mod_conf_t *mc;
    ap_watchdog_t *watchdog;
    
    apr_time_t next_change;
    
    apr_array_header_t *jobs;
    md_reg_t *reg;
} md_watchdog;

static void assess_renewal(md_watchdog *wd, md_job_t *job, apr_pool_t *ptemp) 
{
    apr_time_t now = apr_time_now();
    if (now >= job->restart_at) {
        job->need_restart = 1;
        ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, wd->s, 
                     "md(%s): has been renewed, needs restart now", job->md->name);
    }
    else {
        job->next_check = job->restart_at;
        
        if (job->renewal_notified) {
            ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, wd->s, 
                         "%s: renewed cert valid in %s", 
                         job->md->name, md_print_duration(ptemp, job->restart_at - now));
        }
        else {
            char ts[APR_RFC822_DATE_LEN];

            apr_rfc822_date(ts, job->restart_at);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO(10051) 
                         "%s: has been renewed successfully and should be activated at %s"
                         " (this requires a server restart latest in %s)", 
                         job->md->name, ts, md_print_duration(ptemp, job->restart_at - now));
            job->renewal_notified = 1;
        }
    }
}

static apr_status_t load_job_props(md_reg_t *reg, md_job_t *job, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    md_json_t *jprops;
    apr_status_t rv;
    
    rv = md_store_load_json(store, MD_SG_STAGING, job->md->name,
                            MD_FN_JOB, &jprops, p);
    if (APR_SUCCESS == rv) {
        job->restart_processed = md_json_getb(jprops, MD_KEY_PROCESSED, NULL);
        job->error_runs = (int)md_json_getl(jprops, MD_KEY_ERRORS, NULL);
    }
    return rv;
}

static apr_status_t save_job_props(md_reg_t *reg, md_job_t *job, apr_pool_t *p)
{
    md_store_t *store = md_reg_store_get(reg);
    md_json_t *jprops;
    apr_status_t rv;
    
    rv = md_store_load_json(store, MD_SG_STAGING, job->md->name, MD_FN_JOB, &jprops, p);
    if (APR_STATUS_IS_ENOENT(rv)) {
        jprops = md_json_create(p);
        rv = APR_SUCCESS;
    }
    if (APR_SUCCESS == rv) {
        md_json_setb(job->restart_processed, jprops, MD_KEY_PROCESSED, NULL);
        md_json_setl(job->error_runs, jprops, MD_KEY_ERRORS, NULL);
        rv = md_store_save_json(store, p, MD_SG_STAGING, job->md->name,
                                MD_FN_JOB, jprops, 0);
    }
    return rv;
}

static apr_status_t check_job(md_watchdog *wd, md_job_t *job, apr_pool_t *ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t valid_from, delay;
    int errored, renew, error_runs;
    char ts[APR_RFC822_DATE_LEN];
    
    if (apr_time_now() < job->next_check) {
        /* Job needs to wait */
        return APR_EAGAIN;
    }
    
    job->next_check = 0;
    error_runs = job->error_runs;

    if (job->md->state == MD_S_MISSING) {
        job->stalled = 1;
    }
    
    if (job->stalled) {
        /* Missing information, this will not change until configuration
         * is changed and server restarted */
        rv = APR_INCOMPLETE;
        ++job->error_runs;
        goto out;
    }
    else if (job->renewed) {
        assess_renewal(wd, job, ptemp);
    }
    else if (APR_SUCCESS == (rv = md_reg_assess(wd->reg, job->md, &errored, &renew, wd->p))) {
        if (errored) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10050) 
                         "md(%s): in error state", job->md->name);
        }
        else if (renew) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10052) 
                         "md(%s): state=%d, driving", job->md->name, job->md->state);
                         
            rv = md_reg_stage(wd->reg, job->md, NULL, 0, &valid_from, ptemp);
            
            if (APR_SUCCESS == rv) {
                job->renewed = 1;
                job->restart_at = valid_from;
                assess_renewal(wd, job, ptemp);
            }
        }
        else {
            job->next_check = job->md->expires - job->md->renew_window;

            apr_rfc822_date(ts, job->md->expires);
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10053) 
                         "md(%s): is complete, cert expires %s", job->md->name, ts);
        }
    }
    
    if (APR_SUCCESS == rv) {
        job->error_runs = 0;
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_ERR, rv, wd->s, APLOGNO(10056) 
                     "processing %s", job->md->name);
        ++job->error_runs;
        /* back off duration, depending on the errors we encounter in a row */
        delay = apr_time_from_sec(5 << (job->error_runs - 1));
        if (delay > apr_time_from_sec(60*60)) {
            delay = apr_time_from_sec(60*60);
        }
        job->next_check = apr_time_now() + delay;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO(10057) 
                     "%s: encountered error for the %d. time, next run in %s",
                     job->md->name, job->error_runs, md_print_duration(ptemp, delay));
    }
    
out:
    if (error_runs != job->error_runs) {
        apr_status_t rv2 = save_job_props(wd->reg, job, ptemp);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv2, wd->s, "%s: saving job props", job->md->name);
    }

    job->last_rv = rv;
    return rv;
}

static apr_status_t run_watchdog(int state, void *baton, apr_pool_t *ptemp)
{
    md_watchdog *wd = baton;
    apr_status_t rv = APR_SUCCESS;
    md_job_t *job;
    apr_time_t next_run, now;
    int restart = 0;
    int i;
    
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10054)
                         "md watchdog start, auto drive %d mds", wd->jobs->nelts);
            assert(wd->reg);
        
            for (i = 0; i < wd->jobs->nelts; ++i) {
                job = APR_ARRAY_IDX(wd->jobs, i, md_job_t *);
                load_job_props(wd->reg, job, ptemp);
            }
            break;
        case AP_WATCHDOG_STATE_RUNNING:
        
            wd->next_change = 0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10055)
                         "md watchdog run, auto drive %d mds", wd->jobs->nelts);
                         
            /* normally, we'd like to run at least twice a day */
            next_run = apr_time_now() + apr_time_from_sec(MD_SECS_PER_DAY / 2);

            /* Check on all the jobs we have */
            for (i = 0; i < wd->jobs->nelts; ++i) {
                job = APR_ARRAY_IDX(wd->jobs, i, md_job_t *);
                
                rv = check_job(wd, job, ptemp);

                if (job->need_restart && !job->restart_processed) {
                    restart = 1;
                }
                if (job->next_check && job->next_check < next_run) {
                    next_run = job->next_check;
                }
            }

            now = apr_time_now();
            if (APLOGdebug(wd->s)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10107)
                             "next run in %s", md_print_duration(ptemp, next_run - now));
            }
            wd_set_interval(wd->watchdog, next_run - now, wd, run_watchdog);
            break;
            
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10058)
                         "md watchdog stopping");
            break;
    }

    if (restart) {
        const char *action, *names = "";
        int n;
        
        for (i = 0, n = 0; i < wd->jobs->nelts; ++i) {
            job = APR_ARRAY_IDX(wd->jobs, i, md_job_t *);
            if (job->need_restart && !job->restart_processed) {
                names = apr_psprintf(ptemp, "%s%s%s", names, n? " " : "", job->md->name);
                ++n;
            }
        }

        if (n > 0) {
            int notified = 1;

            /* Run notify command for ready MDs (if configured) and persist that
             * we have done so. This process might be reaped after n requests or die
             * of another cause. The one taking over the watchdog need to notify again.
             */
            if (wd->mc->notify_cmd) {
                const char * const *argv;
                const char *cmdline;
                int exit_code;
                
                cmdline = apr_psprintf(ptemp, "%s %s", wd->mc->notify_cmd, names); 
                apr_tokenize_to_argv(cmdline, (char***)&argv, ptemp);
                if (APR_SUCCESS == (rv = md_util_exec(ptemp, argv[0], argv, &exit_code))) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, wd->s, APLOGNO(10108) 
                                 "notify command '%s' returned %d", 
                                 wd->mc->notify_cmd, exit_code);
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, wd->s, APLOGNO(10109) 
                                 "executing configured MDNotifyCmd %s", wd->mc->notify_cmd);
                    notified = 0;
                } 
            }
            
            if (notified) {
                /* persist the jobs that were notified */
                for (i = 0, n = 0; i < wd->jobs->nelts; ++i) {
                    job = APR_ARRAY_IDX(wd->jobs, i, md_job_t *);
                    if (job->need_restart && !job->restart_processed) {
                        job->restart_processed = 1;
                        save_job_props(wd->reg, job, ptemp);
                    }
                }
            }
            
            /* FIXME: the server needs to start gracefully to take the new certificate in.
             * This poses a variety of problems to solve satisfactory for everyone:
             * - I myself, have no implementation for Windows 
             * - on *NIX, child processes run with less privileges, preventing
             *   the signal based restart trigger to work
             * - admins want better control of timing windows for restarts, e.g.
             *   during less busy hours/days.
             */
            rv = md_server_graceful(ptemp, wd->s);
            if (APR_ENOTIMPL == rv) {
                /* self-graceful restart not supported in this setup */
                action = " and changes will be activated on next (graceful) server restart.";
            }
            else {
                action = " and server has been asked to restart now.";
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO(10059) 
                         "The Managed Domain%s %s %s been setup%s",
                         (n > 1)? "s" : "", names, (n > 1)? "have" : "has", action);
        }
    }
    
    return APR_SUCCESS;
}

static apr_status_t start_watchdog(apr_array_header_t *names, apr_pool_t *p, 
                                   md_reg_t *reg, server_rec *s, md_mod_conf_t *mc)
{
    apr_allocator_t *allocator;
    md_watchdog *wd;
    apr_pool_t *wdp;
    apr_status_t rv;
    const char *name;
    md_t *md;
    md_job_t *job;
    int i, errored, renew;
    
    wd_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    wd_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    wd_set_interval = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_set_callback_interval);
    
    if (!wd_get_instance || !wd_register_callback || !wd_set_interval) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO(10061) "mod_watchdog is required");
        return !OK;
    }
    
    /* We want our own pool with own allocator to keep data across watchdog invocations */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    rv = apr_pool_create_ex(&wdp, p, NULL, allocator);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10062) "md_watchdog: create pool");
        return rv;
    }
    apr_allocator_owner_set(allocator, wdp);
    apr_pool_tag(wdp, "md_watchdog");

    wd = apr_pcalloc(wdp, sizeof(*wd));
    wd->p = wdp;
    wd->reg = reg;
    wd->s = s;
    wd->mc = mc;
    
    wd->jobs = apr_array_make(wd->p, 10, sizeof(md_job_t *));
    for (i = 0; i < names->nelts; ++i) {
        name = APR_ARRAY_IDX(names, i, const char *);
        md = md_reg_get(wd->reg, name, wd->p);
        if (md) {
            md_reg_assess(wd->reg, md, &errored, &renew, wd->p);
            if (errored) {
                ap_log_error( APLOG_MARK, APLOG_WARNING, 0, wd->s, APLOGNO(10063) 
                             "md(%s): seems errored. Will not process this any further.", name);
            }
            else {
                job = apr_pcalloc(wd->p, sizeof(*job));
                
                job->md = md;
                APR_ARRAY_PUSH(wd->jobs, md_job_t*) = job;

                ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10064) 
                             "md(%s): state=%d, driving", name, md->state);
                
                load_job_props(reg, job, wd->p);
                if (job->error_runs) {
                    /* We are just restarting. If we encounter jobs that had errors
                     * running the protocol on previous staging runs, we reset
                     * the staging area for it, in case we persisted something that
                     * causes a loop. */
                    md_store_t *store = md_reg_store_get(wd->reg);
                    
                    md_store_purge(store, p, MD_SG_STAGING, job->md->name);
                    md_store_purge(store, p, MD_SG_CHALLENGES, job->md->name);
                }
            }
        }
    }

    if (!wd->jobs->nelts) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10065)
                     "no managed domain in state to drive, no watchdog needed, "
                     "will check again on next server (graceful) restart");
        apr_pool_destroy(wd->p);
        return APR_SUCCESS;
    }
    
    if (APR_SUCCESS != (rv = wd_get_instance(&wd->watchdog, MD_WATCHDOG_NAME, 0, 1, wd->p))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(10066) 
                     "create md watchdog(%s)", MD_WATCHDOG_NAME);
        return rv;
    }
    rv = wd_register_callback(wd->watchdog, 0, wd, run_watchdog);
    ap_log_error(APLOG_MARK, rv? APLOG_CRIT : APLOG_DEBUG, rv, s, APLOGNO(10067) 
                 "register md watchdog(%s)", MD_WATCHDOG_NAME);
    return rv;
}
 
static void load_stage_sets(apr_array_header_t *names, apr_pool_t *p, 
                            md_reg_t *reg, server_rec *s)
{
    const char *name; 
    apr_status_t rv;
    int i;
    
    for (i = 0; i < names->nelts; ++i) {
        name = APR_ARRAY_IDX(names, i, const char*);
        if (APR_SUCCESS == (rv = md_reg_load(reg, name, p))) {
            ap_log_error( APLOG_MARK, APLOG_INFO, rv, s, APLOGNO(10068) 
                         "%s: staged set activated", name);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10069)
                         "%s: error loading staged set", name);
        }
    }
    return;
}

static apr_status_t md_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *mod_md_init_key = "mod_md_init_counter";
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    md_reg_t *reg;
    const md_t *md;
    apr_array_header_t *drive_names;
    apr_status_t rv = APR_SUCCESS;
    int i, dry_run = 0;

    apr_pool_userdata_get(&data, mod_md_init_key, s->process->pool);
    if (data == NULL) {
        /* At the first start, httpd makes a config check dry run. It
         * runs all config hooks to check if it can. If so, it does
         * this all again and starts serving requests.
         * 
         * This is known.
         *
         * On a dry run, we therefore do all the cheap config things we
         * need to do. Because otherwise mod_ssl fails because it calls
         * us unprepared.
         * But synching our configuration with the md store
         * and determining which domains to drive and start a watchdog
         * and all that, we do not.
         */
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10070)
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, s->process->pool);
        dry_run = 1;
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(10071)
                     "mod_md (v%s), initializing...", MOD_MD_VERSION);
    }

    (void)plog;
    init_setups(p, s);
    md_log_set(log_is_level, log_print, NULL);

    /* Check uniqueness of MDs, calculate global, configured MD list.
     * If successful, we have a list of MD definitions that do not overlap. */
    /* We also need to find out if we can be reached on 80/443 from the outside (e.g. the CA) */
    if (APR_SUCCESS != (rv =  md_calc_md_list(p, plog, ptemp, s))) {
        return rv;
    }

    md_config_post_config(s, p);
    sc = md_config_get(s);
    mc = sc->mc;

    /* Synchronize the definitions we now have with the store via a registry (reg). */
    if (APR_SUCCESS != (rv = setup_reg(&reg, p, s, mc->can_http, mc->can_https))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10072)
                     "setup md registry");
        goto out;
    }
    
    if (APR_SUCCESS != (rv = md_reg_sync(reg, p, ptemp, mc->mds))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10073)
                     "synching %d mds to registry", mc->mds->nelts);
    }
    
    /* Determine the managed domains that are in auto drive_mode. For those,
     * determine in which state they are:
     *  - UNKNOWN:            should not happen, report, don't drive
     *  - ERROR:              something we do not know how to fix, report, don't drive
     *  - INCOMPLETE/EXPIRED: need to drive them right away
     *  - COMPLETE:           determine when cert expires, drive when the time comes
     *
     * Start the watchdog if we have anything, now or in the future.
     */
    drive_names = apr_array_make(ptemp, mc->mds->nelts+1, sizeof(const char *));
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, const md_t *);
        switch (md->drive_mode) {
            case MD_DRIVE_AUTO:
                if (md_array_str_index(mc->unused_names, md->name, 0, 0) >= 0) {
                    break;
                }
                /* fall through */
            case MD_DRIVE_ALWAYS:
                APR_ARRAY_PUSH(drive_names, const char *) = md->name; 
                break;
            default:
                /* leave out */
                break;
        }
    }
    
    init_ssl();
    
    if (dry_run) {
        goto out;
    }
    
    /* If there are MDs to drive, start a watchdog to check on them regularly */
    if (drive_names->nelts > 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10074)
                     "%d out of %d mds are configured for auto-drive", 
                     drive_names->nelts, mc->mds->nelts);
    
        load_stage_sets(drive_names, p, reg, s);
        md_http_use_implementation(md_curl_get_impl(p));
        rv = start_watchdog(drive_names, p, reg, s, mc);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10075)
                     "no mds to auto drive, no watchdog needed");
    }
out:
    return rv;
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
    MD_CHK_VARS;
    
    spec.type = MD_PKEY_TYPE_RSA;
    spec.params.rsa.bits = MD_PKEY_RSA_BITS_DEF;
    
    if (   !MD_OK(md_pkey_gen(&pkey, p, &spec))
        || !MD_OK(md_store_save(store, p, MD_SG_DOMAINS, md->name, 
                                MD_FN_FALLBACK_PKEY, MD_SV_PKEY, (void*)pkey, 0))
        || !MD_OK(md_cert_self_sign(&cert, "Apache Managed Domain Fallback", 
                                    md->domains, pkey, apr_time_from_sec(14 * MD_SECS_PER_DAY), p))
        || !MD_OK(md_store_save(store, p, MD_SG_DOMAINS, md->name, 
                                MD_FN_FALLBACK_CERT, MD_SV_CERT, (void*)cert, 0))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,  
                     "%s: setup fallback certificate, call %s", md->name, MD_LAST_CHK);
    }
    return rv;
}

static int fexists(const char *fname, apr_pool_t *p)
{
    return (*fname && APR_SUCCESS == md_util_is_file(fname, p));
}

static apr_status_t md_get_certificate(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, const char **pcertfile)
{
    apr_status_t rv = APR_ENOENT;    
    md_srv_conf_t *sc;
    md_reg_t *reg;
    md_store_t *store;
    const md_t *md;
    MD_CHK_VARS;
    
    *pkeyfile = NULL;
    *pcertfile = NULL;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10113)
                 "md_get_certificate called for vhost %s.", s->server_hostname);

    sc = md_config_get(s);
    if (!sc) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,  
                     "asked for certificate of server %s which has no md config", 
                     s->server_hostname);
        return APR_ENOENT;
    }
    
    if (!sc->assigned) {
        /* Hmm, mod_ssl (or someone like it) asks for certificates for a server
         * where we did not assign a MD to. Either the user forgot to configure
         * that server with SSL certs, has misspelled a server name or we have
         * a bug that prevented us from taking responsibility for this server.
         * Either way, make some polite noise */
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, APLOGNO(10114)  
                     "asked for certificate of server %s which has no MD assigned. This "
                     "could be ok, but most likely it is either a misconfiguration or "
                     "a bug. Please check server names and MD names carefully and if "
                     "everything checks open, please open an issue.", 
                     s->server_hostname);
        return APR_ENOENT;
    }
    
    assert(sc->mc);
    reg = sc->mc->reg;
    assert(reg);
    
    md = md_reg_get(reg, sc->assigned->name, p);
    if (!md) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10115) 
                     "unable to hand out certificates, as registry can no longer "
                     "find MD '%s'.", sc->assigned->name);
        return APR_ENOENT;
    }
    
    if (!MD_OK(md_reg_get_cred_files(reg, md, p, pkeyfile, pcertfile))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10110) 
                     "retrieving credentials for MD %s", md->name);
        return rv;
    }
    
    if (!fexists(*pkeyfile, p) || !fexists(*pcertfile, p)) { 
        /* Provide temporary, self-signed certificate as fallback, so that
         * clients do not get obscure TLS handshake errors or will see a fallback
         * virtual host that is not intended to be served here. */
        store = md_reg_store_get(reg);
        assert(store);    
        
        md_store_get_fname(pkeyfile, store, MD_SG_DOMAINS, 
                           md->name, MD_FN_FALLBACK_PKEY, p);
        md_store_get_fname(pcertfile, store, MD_SG_DOMAINS, 
                           md->name, MD_FN_FALLBACK_CERT, p);
        if (!fexists(*pkeyfile, p) || !fexists(*pcertfile, p)) { 
            if (!MD_OK(setup_fallback_cert(store, md, s, p))) {
                return rv;
            }
        }
        
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10116)  
                     "%s: providing fallback certificate for server %s", 
                     md->name, s->server_hostname);
        return APR_EAGAIN;
    }
    
    /* We have key and cert files, but they might no longer be valid or not
     * match all domain names. Still use these files for now, but indicate that 
     * resources should no longer be served until we have a new certificate again. */
    if (md->state != MD_S_COMPLETE) {
        rv = APR_EAGAIN;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10077) 
                 "%s: providing certificate for server %s", md->name, s->server_hostname);
    return rv;
}

static int compat_warned;
static apr_status_t md_get_credentials(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, 
                                       const char **pcertfile, 
                                       const char **pchainfile)
{
    *pchainfile = NULL;
    if (!compat_warned) {
        compat_warned = 1;
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, /* no APLOGNO */
                     "You are using mod_md with an old patch to mod_ssl. This will "
                     " work for now, but support will be dropped in a future release.");
    }
    return md_get_certificate(s, p, pkeyfile, pcertfile);
}

static int md_is_challenge(conn_rec *c, const char *servername,
                           X509 **pcert, EVP_PKEY **pkey)
{
    md_srv_conf_t *sc;
    apr_size_t slen, sufflen = sizeof(MD_TLSSNI01_DNS_SUFFIX) - 1;
    apr_status_t rv;

    slen = strlen(servername);
    if (slen <= sufflen 
        || apr_strnatcasecmp(MD_TLSSNI01_DNS_SUFFIX, servername + slen - sufflen)) {
        return 0;
    }
    
    sc = md_config_get(c->base_server);
    if (sc && sc->mc->reg) {
        md_store_t *store = md_reg_store_get(sc->mc->reg);
        md_cert_t *mdcert;
        md_pkey_t *mdpkey;
        
        rv = md_store_load(store, MD_SG_CHALLENGES, servername, 
                           MD_FN_TLSSNI01_CERT, MD_SV_CERT, (void**)&mdcert, c->pool);
        if (APR_SUCCESS == rv && (*pcert = md_cert_get_X509(mdcert))) {
            rv = md_store_load(store, MD_SG_CHALLENGES, servername, 
                               MD_FN_TLSSNI01_PKEY, MD_SV_PKEY, (void**)&mdpkey, c->pool);
            if (APR_SUCCESS == rv && (*pkey = md_pkey_get_EVP_PKEY(mdpkey))) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO(10078)
                              "%s: is a tls-sni-01 challenge host", servername);
                return 1;
            }
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, c, APLOGNO(10079)
                          "%s: challenge data not complete, key unavailable", servername);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(10080)
                          "%s: unknown TLS SNI challenge host", servername);
        }
    }
    *pcert = NULL;
    *pkey = NULL;
    return 0;
}

/**************************************************************************************************/
/* ACME challenge responses */

#define WELL_KNOWN_PREFIX           "/.well-known/"
#define ACME_CHALLENGE_PREFIX       WELL_KNOWN_PREFIX"acme-challenge/"

static int md_http_challenge_pr(request_rec *r)
{
    apr_bucket_brigade *bb;
    const md_srv_conf_t *sc;
    const char *name, *data;
    md_reg_t *reg;
    apr_status_t rv;
    
    if (!strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
        if (r->method_number == M_GET) {
        
            sc = ap_get_module_config(r->server->module_config, &md_module);
            reg = sc && sc->mc? sc->mc->reg : NULL;
            name = r->parsed_uri.path + sizeof(ACME_CHALLENGE_PREFIX)-1;

            r->status = HTTP_NOT_FOUND;
            if (!ap_strchr_c(name, '/') && reg) {
                md_store_t *store = md_reg_store_get(reg);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                              "Challenge for %s (%s)", r->hostname, r->uri);

                rv = md_store_load(store, MD_SG_CHALLENGES, r->hostname, 
                                   MD_FN_HTTP01, MD_SV_TEXT, (void**)&data, r->pool);
                if (APR_SUCCESS == rv) {
                    apr_size_t len = strlen(data);
                    
                    r->status = HTTP_OK;
                    apr_table_setn(r->headers_out, "Content-Length", apr_ltoa(r->pool, (long)len));
                    
                    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
                    apr_brigade_write(bb, NULL, NULL, data, len);
                    ap_pass_brigade(r->output_filters, bb);
                    apr_brigade_cleanup(bb);
                }
                else if (APR_STATUS_IS_ENOENT(rv)) {
                    return HTTP_NOT_FOUND;
                }
                else if (APR_ENOENT != rv) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10081)
                                  "loading challenge %s from store", name);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            return r->status;
        }
        else {
            return HTTP_NOT_IMPLEMENTED;
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
    
    if (opt_ssl_is_https 
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

    md_acme_init(pool, AP_SERVER_BASEVERSION);
        
    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    
    /* Run once after configuration is set, before mod_ssl.
     */
    ap_hook_post_config(md_post_config, NULL, mod_ssl, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, mod_ssl, APR_HOOK_MIDDLE);

    /* answer challenges *very* early, before any configured authentication may strike */
    ap_hook_post_read_request(md_require_https_maybe, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_read_request(md_http_challenge_pr, NULL, NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(md_is_managed);
    APR_REGISTER_OPTIONAL_FN(md_get_certificate);
    APR_REGISTER_OPTIONAL_FN(md_is_challenge);
    APR_REGISTER_OPTIONAL_FN(md_get_credentials);
}

