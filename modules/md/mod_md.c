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

#include <ap_release.h>
#include <mpm_common.h>
#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <ap_listen.h>

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
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
#include "mod_watchdog.h"

static void md_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(md) = {
    STANDARD20_MODULE_STUFF,
    NULL,                 /* func to create per dir config */
    NULL,                 /* func to merge per dir config */
    md_config_create_svr, /* func to create per server config */
    md_config_merge_svr,  /* func to merge per server config */
    md_cmds,              /* command handlers */
    md_hooks
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

static apr_status_t apply_to_servers(md_t *md, server_rec *base_server, 
                                     apr_pool_t *p, apr_pool_t *ptemp)
{
    server_rec *s;
    request_rec r;
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_status_t rv = APR_SUCCESS, rv2;
    int i, j;
    const char *domain, *name;
    
    sc = md_config_get(base_server);
    mc = sc->mc;
    
    /* Find the (at most one) managed domain for each vhost/base server and
     * remember it at our config for it. 
     * The config is not accepted, if a vhost matches 2 or more managed domains.
     */
    memset(&r, 0, sizeof(r));
    sc = NULL;
    
    /* This MD may apply to 0, 1 or more sever_recs */
    for (s = base_server; s; s = s->next) {
        r.server = s;
        
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char*);
            
            if (ap_matches_request_vhost(&r, domain, s->port)) {
                /* Create a unique md_srv_conf_t record for this server. 
                 * We keep local information here. */
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
                    rv = APR_EINVAL;
                    goto next_server;
                }
                
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10043)
                             "Managed Domain %s applies to vhost %s:%d", md->name,
                             s->server_hostname, s->port);
                
                /* If there is a non-default ServerAdmin defined for this vhost, take
                 * that one as contact info */
                if (s->server_admin && strcmp(DEFAULT_ADMIN, s->server_admin)) {
                    apr_array_clear(md->contacts);
                    APR_ARRAY_PUSH(md->contacts, const char *) = 
                    md_util_schemify(p, s->server_admin, "mailto");
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10044)
                                 "Managed Domain %s assigned server admin %s", md->name,
                                 s->server_admin);
                }
                /* remember */
                sc->assigned = md;
                
                /* This server matches a managed domain. If it contains names or
                 * alias that are not in this md, a generated certificate will not match. */
                if (APR_SUCCESS == (rv2 = check_coverage(md, s->server_hostname, s, p))
                    && s->names) {
                    for (j = 0; j < s->names->nelts; ++j) {
                        name = APR_ARRAY_IDX(s->names, j, const char*);
                        if (APR_SUCCESS != (rv2 = check_coverage(md, name, s, p))) {
                            break;
                        }
                    }
                }
                
                if (APR_SUCCESS != rv2) {
                    rv = rv2;
                }
                goto next_server;
            }
        }
    next_server:
        continue;
    }
    
    if (sc == NULL && md->drive_mode != MD_DRIVE_ALWAYS) {
        /* Not an error, but looks suspicious */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(10045)
                     "No VirtualHost matches Managed Domain %s", md->name);
        APR_ARRAY_PUSH(mc->unused_names, const char*)  = md->name;
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

        /* Apply to the vhost(s) that this MD matches - if any. Perform some
         * last finishing touches on the MD. */
        if (APR_SUCCESS != (rv = apply_to_servers(md, base_server, p, ptemp))) {
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

static apr_status_t setup_store(md_mod_conf_t *mc, apr_pool_t *p, server_rec *s,
                                int post_config)
{
    const char *base_dir;
    md_store_t *store;
    apr_status_t rv;
    
    base_dir = ap_server_root_relative(p, mc->base_dir);
    
    if (APR_SUCCESS != (rv = md_store_fs_init(&store, p, base_dir))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10046)"setup store for %s", base_dir);
        goto out;
    }

    if (post_config) {
        md_store_fs_set_event_cb(store, store_file_ev, s);
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_CHALLENGES, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047) 
                         "setup challenges directory");
            goto out;
        }
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_STAGING, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10048) 
                         "setup staging directory");
            goto out;
        }
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_ACCOUNTS, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10049) 
                         "setup accounts directory");
            goto out;
        }
    }
    
    mc->store = store;
out:
    return rv;
}

static apr_status_t setup_reg(md_reg_t **preg, apr_pool_t *p, server_rec *s, int post_config)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    apr_status_t rv;
    
    sc = md_config_get(s);
    mc = sc->mc;
    
    if (mc->store || APR_SUCCESS == (rv = setup_store(mc, p, s, post_config))) {
        return md_reg_init(preg, p, mc->store);
    }
    return rv;
}

/**************************************************************************************************/
/* logging setup */

static server_rec *log_server;

static int log_is_level(void *baton, apr_pool_t *p, md_log_level_t level)
{
    if (log_server) {
        return APLOG_IS_LEVEL(log_server, level);
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
/* watchdog based impl. */

#define MD_WATCHDOG_NAME   "_md_"

static APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *wd_get_instance;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *wd_register_callback;
static APR_OPTIONAL_FN_TYPE(ap_watchdog_set_callback_interval) *wd_set_interval;

typedef struct {
    apr_pool_t *p;
    server_rec *s;
    ap_watchdog_t *watchdog;
    int all_valid;
    apr_time_t valid_not_before;
    int error_count;
    int processed_count;

    int error_runs;
    apr_time_t next_change;
    apr_time_t next_valid;
    
    apr_array_header_t *mds;
    md_reg_t *reg;
} md_watchdog;

static apr_status_t drive_md(md_watchdog *wd, md_t *md, apr_pool_t *ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t renew_time, now, valid_from;
    int errored, renew;
    char ts[APR_RFC822_DATE_LEN];
    
    if (md->state == MD_S_MISSING) {
        rv = APR_INCOMPLETE;
    }
    if (md->state == MD_S_COMPLETE && !md->expires) {
        /* This is our indicator that we did already renewed this managed domain
         * successfully and only wait on the next restart for it to activate */
        now = apr_time_now();
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO(10051) 
                     "md(%s): has been renewed, should be activated in %s", 
                     md->name, (md->valid_from <= now)? "about now" : 
                     md_print_duration(ptemp, md->valid_from - now));
    }
    else if (APR_SUCCESS == (rv = md_reg_assess(wd->reg, md, &errored, &renew, wd->p))) {
        if (errored) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10050) 
                         "md(%s): in error state", md->name);
        }
        else if (renew) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10052) 
                         "md(%s): state=%d, driving", md->name, md->state);
                         
            rv = md_reg_stage(wd->reg, md, NULL, 0, &valid_from, ptemp);
            
            if (APR_SUCCESS == rv) {
                md->state = MD_S_COMPLETE;
                md->expires = 0;
                md->valid_from = valid_from;
                ++wd->processed_count;
                if (!wd->next_valid || wd->next_valid > valid_from) {
                    wd->next_valid = valid_from;
                }
            }
        }
        else {
            apr_rfc822_date(ts, md->expires);
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10053) 
                         "md(%s): is complete, cert expires %s", md->name, ts);
            renew_time = md->expires - md->renew_window;
            if (renew_time < wd->next_change) {
                wd->next_change = renew_time;
            }
        }
    }
    return rv;
}

static apr_status_t run_watchdog(int state, void *baton, apr_pool_t *ptemp)
{
    md_watchdog *wd = baton;
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    apr_time_t next_run, now;
    int i;
    
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10054)
                         "md watchdog start, auto drive %d mds", wd->mds->nelts);
            break;
        case AP_WATCHDOG_STATE_RUNNING:
            assert(wd->reg);
            
            wd->all_valid = 1;
            wd->valid_not_before = 0;
            wd->processed_count = 0;
            wd->error_count = 0;
            wd->next_change = 0;
            wd->next_valid = 0;
            
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10055)
                         "md watchdog run, auto drive %d mds", wd->mds->nelts);
                         
            /* Check if all Managed Domains are ok or if we have to do something */
            for (i = 0; i < wd->mds->nelts; ++i) {
                md = APR_ARRAY_IDX(wd->mds, i, md_t *);
                
                rv = drive_md(wd, md, ptemp);
                
                if (APR_STATUS_IS_INCOMPLETE(rv)) {
                    /* configuration not complete, this MD cannot be driven further */
                    wd->all_valid = 0;
                }
                else if (APR_SUCCESS != rv) {
                    wd->all_valid = 0;
                    ++wd->error_count;
                    ap_log_error( APLOG_MARK, APLOG_ERR, rv, wd->s, APLOGNO(10056) 
                                 "processing %s", md->name);
                }
            }

            /* Determine when we want to run next */
            wd->error_runs = wd->error_count? (wd->error_runs + 1) : 0;

            if (wd->all_valid) {
                ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, wd->s, "all managed domains are valid");
            }
            else if (wd->error_count == 0) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO() 
                             "all managed domains driven as far as possible");
            }
            
            now = apr_time_now();
            /* normally, we'd like to run at least twice a day */
            next_run = now + apr_time_from_sec(MD_SECS_PER_DAY / 2);
            
            /* Unless we know of an MD change before that */
            if (wd->next_change > 0 && wd->next_change < next_run) {
                next_run = wd->next_change;
            }
            
            /* Or have to activate a new cert even before that */
            if (wd->next_valid > now && wd->next_valid < next_run) {
                next_run = wd->next_valid;
                ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, wd->s, 
                             "Delaying activation of %d Managed Domain%s by %s", 
                             wd->processed_count, (wd->processed_count > 1)? "s have" : " has",
                             md_print_duration(ptemp, next_run - now));
            }
            
            /* Or encountered errors and like to retry even before that */
            if (wd->error_count > 0) {
                apr_interval_time_t delay;
                
                /* back off duration, depending on the errors we encounter in a row */
                delay = apr_time_from_sec(5 << (wd->error_runs - 1));
                if (delay > apr_time_from_sec(60*60)) {
                    delay = apr_time_from_sec(60*60);
                }
                if (now + delay < next_run) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO(10057) 
                                 "encountered errors for the %d. time, next try by %s",
                                 wd->error_runs, md_print_duration(ptemp, delay));
                    next_run = now + delay;
                }
            }
            
            if (APLOGdebug(wd->s)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO()
                             "next run in %s", md_print_duration(ptemp, next_run - now));
            }
            wd_set_interval(wd->watchdog, next_run - now, wd, run_watchdog);
            break;
            
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10058)
                         "md watchdog stopping");
            break;
    }

    if (wd->processed_count) {
        now = apr_time_now();
        
        if (wd->all_valid) {
            if (wd->next_valid <= now) {
                rv = md_server_graceful(ptemp, wd->s);
                if (APR_ENOTIMPL == rv) {
                    /* self-graceful restart not supported in this setup */
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO(10059)
                                 "%d Managed Domain%s been setup and changes will be "
                                 "activated on next (graceful) server restart.",
                                 wd->processed_count, (wd->processed_count > 1)? "s have" : " has");
                }
            }
            else {
                /* activation is delayed */
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO(10060)
                         "%d Managed Domain%s been setup, while %d%s "
                         "still being worked on. You may activate the changes made "
                         "by triggering a (graceful) restart at any time.",
                         wd->processed_count, (wd->processed_count > 1)? "s have" : " has",
                         wd->error_count, (wd->error_count > 1)? " are" : " is");
        }
    }
    
    return APR_SUCCESS;
}

static apr_status_t start_watchdog(apr_array_header_t *names, apr_pool_t *p, 
                                   md_reg_t *reg, server_rec *s)
{
    apr_allocator_t *allocator;
    md_watchdog *wd;
    apr_pool_t *wdp;
    apr_status_t rv;
    const char *name;
    md_t *md;
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
    
    wd->mds = apr_array_make(wd->p, 10, sizeof(md_t *));
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
                ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO(10064) 
                             "md(%s): state=%d, driving", name, md->state);
                APR_ARRAY_PUSH(wd->mds, md_t*) = md;
            }
        }
    }

    if (!wd->mds->nelts) {
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

static apr_status_t md_check_config(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *s)
{
    const char *mod_md_init_key = "mod_md_init_counter";
    void *data = NULL;
    
    apr_pool_userdata_get(&data, mod_md_init_key, s->process->pool);
    if (data == NULL) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10070)
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, s->process->pool);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(10071)
                     "mod_md (v%s), initializing...", MOD_MD_VERSION);
    }

    init_setups(p, s);
    md_log_set(log_is_level, log_print, NULL);

    /* Check uniqueness of MDs, calculate global, configured MD list.
     * If successful, we have a list of MD definitions that do not overlap. */
    /* We also need to find out if we can be reached on 80/443 from the outside (e.g. the CA) */
    return md_calc_md_list(p, plog, ptemp, s);
}
    
static apr_status_t md_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    md_reg_t *reg;
    const md_t *md;
    apr_array_header_t *drive_names;
    apr_status_t rv = APR_SUCCESS;
    int i;

    sc = md_config_get(s);
    mc = sc->mc;
    
    /* Synchronize the defintions we now have with the store via a registry (reg). */
    if (APR_SUCCESS != (rv = setup_reg(&reg, p, s, 1))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10072)
                     "setup md registry");
        goto out;
    }
    if (APR_SUCCESS != (rv = md_reg_sync(reg, p, ptemp, mc->mds, 
                                         mc->can_http, mc->can_https))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10073)
                     "synching %d mds to registry", mc->mds->nelts);
    }
    
    /* Determine the managed domains that are in auto drive_mode. For those,
     * determine in which state they are:
     *  - UNKNOWN:            should not happen, report, dont drive
     *  - ERROR:              something we do not know how to fix, report, dont drive
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
    
    /* If there are MDs to drive, start a watchdog to check on them regularly */
    if (drive_names->nelts > 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10074)
                     "%d out of %d mds are configured for auto-drive", 
                     drive_names->nelts, mc->mds->nelts);
    
        load_stage_sets(drive_names, p, reg, s);
        md_http_use_implementation(md_curl_get_impl(p));
        rv = start_watchdog(drive_names, p, reg, s);
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

static apr_status_t md_get_certificate(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, const char **pcertfile)
{
    apr_status_t rv = APR_ENOENT;    
    md_srv_conf_t *sc;
    md_reg_t *reg;
    const md_t *md;
    
    *pkeyfile = NULL;
    *pcertfile = NULL;
    
    sc = md_config_get(s);
    
    if (sc && sc->assigned) {
        assert(sc->mc);
        assert(sc->mc->store);
        if (APR_SUCCESS != (rv = md_reg_init(&reg, p, sc->mc->store))) {
            return rv;
        }

        md = md_reg_get(reg, sc->assigned->name, p);
            
        if (APR_SUCCESS != (rv = md_reg_get_cred_files(reg, md, p, pkeyfile, pcertfile))) {
            return rv;
        }

        if (!*pkeyfile || !*pcertfile 
            || APR_SUCCESS != md_util_is_file(*pkeyfile, p)
            || APR_SUCCESS != md_util_is_file(*pcertfile, p)) {
            /* Provide temporary, self-signed certificate as fallback, so that
             * clients do not get obscure TLS handshake errors or will see a fallback
             * virtual host that is not intended to be served here. */
            md_store_get_fname(pkeyfile, sc->mc->store, MD_SG_NONE, NULL, MD_FN_FALLBACK_PKEY, p);
            md_store_get_fname(pcertfile, sc->mc->store, MD_SG_NONE, NULL, MD_FN_FALLBACK_CERT, p);
            
            return APR_EAGAIN;
        }

        /* We have key and cert files, but they might no longer be valid or not
         * match all domain names. Still use these files for now, but indicate that 
         * resources should no longer be served until we have a new certificate again. */
        if (md->state != MD_S_COMPLETE) {
            return APR_EAGAIN;
        }
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10077) 
                     "%s: providing certificate for server %s", md->name, s->server_hostname);
    }
    return rv;
}

static apr_status_t md_get_credentials(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, const char **pcertfile,
                                       const char **pchainfile)
{
    *pchainfile = NULL;
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
    if (sc && sc->mc->store) {
        md_store_t *store = sc->mc->store;
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

#define ACME_CHALLENGE_PREFIX       "/.well-known/acme-challenge/"

static int md_http_challenge_pr(request_rec *r)
{
    apr_bucket_brigade *bb;
    const md_srv_conf_t *sc;
    const char *name, *data;
    apr_status_t rv;
            
    if (!strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
        if (r->method_number == M_GET) {
            md_store_t *store;
        
            sc = ap_get_module_config(r->server->module_config, &md_module);
            store = sc? sc->mc->store : NULL;
            
            name = r->parsed_uri.path + sizeof(ACME_CHALLENGE_PREFIX)-1;

            r->status = HTTP_NOT_FOUND;
            if (!ap_strchr_c(name, '/') && store) {
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

/* Runs once per created child process. Perform any process 
 * related initionalization here.
 */
static void md_child_init(apr_pool_t *pool, server_rec *s)
{
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
    ap_hook_check_config(md_check_config, NULL, mod_ssl, APR_HOOK_MIDDLE);
    ap_hook_post_config(md_post_config, NULL, mod_ssl, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, mod_ssl, APR_HOOK_MIDDLE);

    /* answer challenges *very* early, before any configured authentication may strike */
    ap_hook_post_read_request(md_http_challenge_pr, NULL, NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(md_is_managed);
    APR_REGISTER_OPTIONAL_FN(md_get_certificate);
    APR_REGISTER_OPTIONAL_FN(md_get_credentials);
    APR_REGISTER_OPTIONAL_FN(md_is_challenge);
}
