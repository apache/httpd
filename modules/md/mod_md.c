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
    md_config_create_dir, /* func to create per dir config */
    md_config_merge_dir,  /* func to merge per dir config */
    md_config_create_svr, /* func to create per server config */
    md_config_merge_svr,  /* func to merge per server config */
    md_cmds,              /* command handlers */
    md_hooks
};

typedef struct {
    apr_array_header_t *mds;
    apr_array_header_t *unused_names;
    int can_http;
    int can_https;
} md_ctx;
 
static apr_status_t md_calc_md_list(md_ctx *ctx, apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *base_server)
{
    server_rec *s;
    apr_array_header_t *mds;
    int i, j;
    md_t *md, *nmd;
    const char *domain;
    apr_status_t rv = APR_SUCCESS;
    md_config_t *config;
    apr_port_t effective_80, effective_443;
    ap_listen_rec *lr;
    apr_sockaddr_t *sa;

    ctx->can_http = 0;
    ctx->can_https = 0;
    mds = apr_array_make(p, 5, sizeof(const md_t*));

    config = (md_config_t *)md_config_get(base_server);
    effective_80 = md_config_geti(config, MD_CONFIG_LOCAL_80);
    effective_443 = md_config_geti(config, MD_CONFIG_LOCAL_443);
    
    for (lr = ap_listeners; lr; lr = lr->next) {
        for (sa = lr->bind_addr; sa; sa = sa->next) {
            if  (sa->port == effective_80 
                 && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                ctx->can_http = 1;
            }
            else if (sa->port == effective_443
                     && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                ctx->can_https = 1;
            }
        }
    }
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                 "server seems%s reachable via http: (port 80->%d) "
                 "and%s reachable via https: (port 443->%d) ",
                 ctx->can_http? "" : " not", effective_80,
                 ctx->can_https? "" : " not", effective_443);
    
    for (s = base_server; s; s = s->next) {
        config = (md_config_t *)md_config_get(s);

        for (i = 0; i < config->mds->nelts; ++i) {
            nmd = APR_ARRAY_IDX(config->mds, i, md_t*);

            for (j = 0; j < mds->nelts; ++j) {
                md = APR_ARRAY_IDX(mds, j, md_t*);

                if (nmd == md) {
                    nmd = NULL;
                    break; /* merged between different configs */
                }
                
                if ((domain = md_common_name(nmd, md)) != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                 "two Managed Domains have an overlap in domain '%s'"
                                 ", first definition in %s(line %d), second in %s(line %d)",
                                 domain, md->defn_name, md->defn_line_number,
                                 nmd->defn_name, nmd->defn_line_number);
                    return APR_EINVAL;
                }
            }
            
            if (nmd) {
                /* new managed domain not seen before */
                if (!nmd->ca_url) {
                    nmd->ca_url = md_config_gets(config, MD_CONFIG_CA_URL);
                }
                if (!nmd->ca_proto) {
                    nmd->ca_proto = md_config_gets(config, MD_CONFIG_CA_PROTO);
                }
                if (!nmd->ca_agreement) {
                    nmd->ca_agreement = md_config_gets(config, MD_CONFIG_CA_AGREEMENT);
                }
                if (s->server_admin && strcmp(DEFAULT_ADMIN, s->server_admin)) {
                    apr_array_clear(nmd->contacts);
                    APR_ARRAY_PUSH(nmd->contacts, const char *) = 
                        md_util_schemify(p, s->server_admin, "mailto");
                }
                if (nmd->drive_mode == MD_DRIVE_DEFAULT) {
                    nmd->drive_mode = md_config_geti(config, MD_CONFIG_DRIVE_MODE);
                }
                if (nmd->renew_window <= 0) {
                    nmd->renew_window = md_config_get_interval(config, MD_CONFIG_RENEW_WINDOW);
                }
                if (!nmd->ca_challenges && config->ca_challenges) {
                    nmd->ca_challenges = apr_array_copy(p, config->ca_challenges);
                }
                APR_ARRAY_PUSH(mds, md_t *) = nmd;
                
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                             "Added MD[%s, CA=%s, Proto=%s, Agreement=%s, Drive=%d, renew=%ld]",
                             nmd->name, nmd->ca_url, nmd->ca_proto, nmd->ca_agreement,
                             nmd->drive_mode, (long)nmd->renew_window);
            }
        }
    }
    ctx->mds = (APR_SUCCESS == rv)? mds : NULL;
    return rv;
}

static apr_status_t md_check_vhost_mapping(md_ctx *ctx, apr_pool_t *p, apr_pool_t *plog,
                                           apr_pool_t *ptemp, server_rec *base_server)
{
    server_rec *s;
    request_rec r;
    md_config_t *config;
    apr_status_t rv = APR_SUCCESS;
    md_t *md;
    int i, j, k;
    const char *domain, *name;
    
    /* Find the (at most one) managed domain for each vhost/base server and
     * remember it at our config for it. 
     * The config is not accepted, if a vhost matches 2 or more managed domains.
     */
    ctx->unused_names = apr_array_make(p, 5, sizeof(const char*));
    memset(&r, 0, sizeof(r));
    for (i = 0; i < ctx->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(ctx->mds, i, md_t*);
        config = NULL;
        /* This MD may apply to 0, 1 or more sever_recs */
        for (s = base_server; s; s = s->next) {
            r.server = s;
            for (j = 0; j < md->domains->nelts; ++j) {
                domain = APR_ARRAY_IDX(md->domains, j, const char*);
                
                if (ap_matches_request_vhost(&r, domain, s->port)) {
                    /* Create a unique md_config_t record for this server. 
                     * We keep local information here. */
                    config = (md_config_t *)md_config_get_unique(s, p);
                
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                                 "Server %s:%d matches md %s (config %s)", 
                                 s->server_hostname, s->port, md->name, config->name);
                    
                    if (config->md == md) {
                        /* already matched via another domain name */
                    }
                    else if (config->md) {
                         
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                     "conflict: MD %s matches server %s, but MD %s also matches.",
                                     md->name, s->server_hostname, config->md->name);
                        rv = APR_EINVAL;
                        goto next_server;
                    }
                    
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                                 "Managed Domain %s applies to vhost %s:%d", md->name,
                                 s->server_hostname, s->port);
                    if (s->server_admin && strcmp(DEFAULT_ADMIN, s->server_admin)) {
                        apr_array_clear(md->contacts);
                        APR_ARRAY_PUSH(md->contacts, const char *) = 
                            md_util_schemify(p, s->server_admin, "mailto");
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO()
                                     "Managed Domain %s assigned server admin %s", md->name,
                                     s->server_admin);
                    }
                    config->md = md;

                    /* This server matches a managed domain. If it contains names or
                     * alias that are not in this md, a generated certificate will not match. */
                    if (!md_contains(md, s->server_hostname)) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                     "Virtual Host %s:%d matches Managed Domain '%s', but the name"
                                     " itself is not managed. A requested MD certificate will "
                                     "not match ServerName.",
                                     s->server_hostname, s->port, md->name);
                        rv = APR_EINVAL;
                        goto next_server;
                    }
                    else {
                        for (k = 0; k < s->names->nelts; ++k) {
                            name = APR_ARRAY_IDX(s->names, k, const char*);
                            if (!md_contains(md, name)) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO()
                                             "Virtual Host %s:%d matches Managed Domain '%s', but "
                                             "the ServerAlias %s is not covered by the MD. "
                                             "A requested MD certificate will not match this " 
                                             "alias.", s->server_hostname, s->port, md->name,
                                             name);
                                rv = APR_EINVAL;
                                goto next_server;
                            }
                        }
                    }
                    goto next_server;
                }
            }
next_server:
            continue;
        }
        
        if (config == NULL && md->drive_mode != MD_DRIVE_ALWAYS) {
            /* Not an error, but looks suspicious */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO()
                         "No VirtualHost matches Managed Domain %s", md->name);
            APR_ARRAY_PUSH(ctx->unused_names, const char*)  = md->name;
        }
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

static apr_status_t setup_store(md_store_t **pstore, apr_pool_t *p, server_rec *s,
                                int post_config)
{
    const char *base_dir;
    md_config_t *config;
    md_store_t *store;
    apr_status_t rv;
    
    config = (md_config_t *)md_config_get(s);
    base_dir = md_config_gets(config, MD_CONFIG_BASE_DIR);
    base_dir = ap_server_root_relative(p, base_dir);
    
    if (APR_SUCCESS != (rv = md_store_fs_init(&store, p, base_dir))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()"setup store for %s", base_dir);
        goto out;
    }

    if (post_config) {
        md_store_fs_set_event_cb(store, store_file_ev, s);
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_CHALLENGES, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO() 
                         "setup challenges directory");
            goto out;
        }
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_STAGING, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO() 
                         "setup staging directory");
            goto out;
        }
        if (APR_SUCCESS != (rv = check_group_dir(store, MD_SG_ACCOUNTS, p, s))) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO() 
                         "setup accounts directory");
            goto out;
        }
        
    }
    
    config->store = store;
    for (s = s->next; s; s = s->next) {
        config = (md_config_t *)md_config_get(s);
        config->store = store;
    }
out:
    *pstore = (APR_SUCCESS == rv)? store : NULL;
    return rv;
}

static apr_status_t setup_reg(md_reg_t **preg, apr_pool_t *p, server_rec *s, int post_config)
{
    md_config_t *config;
    apr_status_t rv;
    
    config = (md_config_t *)md_config_get(s);
    if (config->store 
        || APR_SUCCESS == (rv = setup_store(&config->store, p, s, post_config))) {
        return md_reg_init(preg, p, config->store);
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
    int error_count;
    int processed_count;

    int error_runs;
    apr_time_t next_change;
    
    apr_array_header_t *mds;
    md_reg_t *reg;
} md_watchdog;

static apr_status_t drive_md(md_watchdog *wd, md_t *md, apr_pool_t *ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    apr_time_t renew_time;
    int errored, renew;
    char ts[APR_RFC822_DATE_LEN];
    
    if (APR_SUCCESS == (rv = md_reg_assess(wd->reg, md, &errored, &renew, wd->p))) {
        if (errored) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO() 
                         "md(%s): in error state", md->name);
        }
        else if (md->state == MD_S_COMPLETE && !md->expires) {
            /* This is our indicator that we did already renew this managed domain
             * successfully and only wait on the next restart for it to activate */
            ap_log_error( APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO() 
                         "md(%s): has been renewed, will activate on next restart", md->name);
        }
        else if (renew) {
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO() 
                         "md(%s): state=%d, driving", md->name, md->state);
            rv = md_reg_stage(wd->reg, md, NULL, 0, ptemp);
            if (APR_SUCCESS == rv) {
                md->state = MD_S_COMPLETE;
                md->expires = 0;
                ++wd->processed_count;
            }
        }
        else {
            apr_rfc822_date(ts, md->expires);
            ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO() 
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
    apr_interval_time_t interval;
    int i;
    
    switch (state) {
        case AP_WATCHDOG_STATE_STARTING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO()
                         "md watchdog start, auto drive %d mds", wd->mds->nelts);
            break;
        case AP_WATCHDOG_STATE_RUNNING:
            assert(wd->reg);
            
            /* normally, we'd like to run at least twice a day */
            interval = apr_time_from_sec(MD_SECS_PER_DAY / 2);

            wd->all_valid = 1;
            wd->processed_count = 0;
            wd->error_count = 0;
            wd->next_change = 0;
            
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO()
                         "md watchdog run, auto drive %d mds", wd->mds->nelts);
                         
            /* Check if all Managed Domains are ok or if we have to do something */
            for (i = 0; i < wd->mds->nelts; ++i) {
                md = APR_ARRAY_IDX(wd->mds, i, md_t *);
                if (APR_SUCCESS != (rv = drive_md(wd, md, ptemp))) {
                    wd->all_valid = 0;
                    ++wd->error_count;
                    ap_log_error( APLOG_MARK, APLOG_ERR, rv, wd->s, APLOGNO() 
                                 "processing %s", md->name);
                }
            }

            /* Determine when we want to run next */
            wd->error_runs = wd->error_count? (wd->error_runs + 1) : 0;
            if (wd->all_valid) {
                ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, wd->s, "all managed domains are valid");
            }
            else {
                /* back off duration, depending on the errors we encounter in a row */
                interval = apr_time_from_sec(5 << (wd->error_runs - 1));
                if (interval > apr_time_from_sec(60*60)) {
                    interval = apr_time_from_sec(60*60);
                }
                ap_log_error( APLOG_MARK, APLOG_INFO, 0, wd->s, APLOGNO() 
                             "encountered errors for the %d. time, next run in %d seconds",
                             wd->error_runs, (int)apr_time_sec(interval));
            }
            
            /* We follow the chosen min_interval for re-evaluation, unless we
             * know of a change (renewal) that happens before that. */
            if (wd->next_change) {
                apr_interval_time_t until_next = wd->next_change - apr_time_now();
                if (until_next < interval) {
                    interval = until_next;
                }
            }
            
            /* Set when we'd like to be run next time. 
             * TODO: it seems that this is really only ticking down when the server
             * runs. When you wake up a hibernated machine, the watchdog will not run right away 
             */
            if (APLOGdebug(wd->s)) {
                int secs = (int)(apr_time_sec(interval) % MD_SECS_PER_DAY);
                ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, "next run in %2d:%02d:%02d hours", 
                             (int)secs/MD_SECS_PER_HOUR, (int)(secs%(MD_SECS_PER_HOUR))/60,
                             (int)(secs%60));
            }
            wd_set_interval(wd->watchdog, interval, wd, run_watchdog);
            break;
        case AP_WATCHDOG_STATE_STOPPING:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO()
                         "md watchdog stopping");
            break;
    }

    if (wd->processed_count) {
        if (wd->all_valid) {
            rv = md_server_graceful(ptemp, wd->s);
            if (APR_ENOTIMPL == rv) {
                /* self-graceful restart not supported in this setup */
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO()
                             "%d Managed Domain%s been setup and changes will be "
                             "activated on next (graceful) server restart.",
                             wd->processed_count, (wd->processed_count > 1)? "s have" : " has");
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, wd->s, APLOGNO()
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, APLOGNO() "mod_watchdog is required");
        return !OK;
    }
    
    /* We want our own pool with own allocator to keep data across watchdog invocations */
    apr_allocator_create(&allocator);
    apr_allocator_max_free_set(allocator, ap_max_mem_free);
    rv = apr_pool_create_ex(&wdp, p, NULL, allocator);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO() "md_watchdog: create pool");
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
                ap_log_error( APLOG_MARK, APLOG_WARNING, 0, wd->s, APLOGNO() 
                             "md(%s): seems errored. Will not process this any further.", name);
            }
            else {
                ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, wd->s, APLOGNO() 
                             "md(%s): state=%d, driving", name, md->state);
                APR_ARRAY_PUSH(wd->mds, md_t*) = md;
            }
        }
    }

    if (!wd->mds->nelts) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                     "no managed domain in state to drive, no watchdog needed, "
                     "will check again on next server restart");
        apr_pool_destroy(wd->p);
        return APR_SUCCESS;
    }
    
    if (APR_SUCCESS != (rv = wd_get_instance(&wd->watchdog, MD_WATCHDOG_NAME, 0, 1, wd->p))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO() 
                     "create md watchdog(%s)", MD_WATCHDOG_NAME);
        return rv;
    }
    rv = wd_register_callback(wd->watchdog, 0, wd, run_watchdog);
    ap_log_error(APLOG_MARK, rv? APLOG_CRIT : APLOG_DEBUG, rv, s, APLOGNO() 
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
            ap_log_error( APLOG_MARK, APLOG_INFO, rv, s, APLOGNO() 
                         "%s: staged set activated", name);
        }
        else if (!APR_STATUS_IS_ENOENT(rv)) {
            ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                         "%s: error loading staged set", name);
        }
    }
    return;
}

static apr_status_t md_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    const char *mod_md_init_key = "mod_md_init_counter";
    void *data = NULL;
    md_ctx ctx;
    apr_array_header_t *drive_names;
    md_reg_t *reg;
    apr_status_t rv = APR_SUCCESS;
    const md_t *md;
    int i;
    
    apr_pool_userdata_get(&data, mod_md_init_key, s->process->pool);
    if (data == NULL) {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                     "initializing post config dry run");
        apr_pool_userdata_set((const void *)1, mod_md_init_key,
                              apr_pool_cleanup_null, s->process->pool);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_INFO, 0, s, APLOGNO()
                     "mod_md (v%s), initializing...", MOD_MD_VERSION);
    }

    init_setups(p, s);
    memset(&ctx, 0, sizeof(ctx));
    
    md_log_set(log_is_level, log_print, NULL);

    /* 1. Check uniqueness of MDs, calculate global, configured MD list.
     * If successful, we have a list of MD definitions that do not overlap. */
    /* We also need to find out if we can be reached on 80/443 from the outside (e.g. the CA) */
    if (APR_SUCCESS != (rv = md_calc_md_list(&ctx, p, plog, ptemp, s))) {
        goto out;
    }
    
    /* 2. Check mappings of MDs to VirtulHosts defined.
     * If successful, we have assigned MDs to server_recs in a unique way. Each server_rec
     * config will carry 0 or 1 MD record. */
    if (APR_SUCCESS != (rv = md_check_vhost_mapping(&ctx, p, plog, ptemp, s))) {
        goto out;
    }    
    
    /* 3. Synchronize the defintions we now have with the store via a registry (reg). */
    if (APR_SUCCESS != (rv = setup_reg(&reg, p, s, 1))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                     "setup md registry");
        goto out;
    }
    if (APR_SUCCESS != (rv = md_reg_sync(reg, p, ptemp, ctx.mds, 
                                         ctx.can_http, ctx.can_https))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                     "synching %d mds to registry", ctx.mds->nelts);
        goto out;
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
    drive_names = apr_array_make(ptemp, ctx.mds->nelts+1, sizeof(const char *));
    for (i = 0; i < ctx.mds->nelts; ++i) {
        md = APR_ARRAY_IDX(ctx.mds, i, const md_t *);
        switch (md->drive_mode) {
            case MD_DRIVE_AUTO:
                if (md_array_str_index(ctx.unused_names, md->name, 0, 0) >= 0) {
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
    
    if (drive_names->nelts > 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO()
                     "%d out of %d mds are configured for auto-drive", 
                     drive_names->nelts, ctx.mds->nelts);
    
        load_stage_sets(drive_names, p, reg, s);
        md_http_use_implementation(md_curl_get_impl(p));
        rv = start_watchdog(drive_names, p, reg, s);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO()
                     "no mds to auto drive, no watchdog needed");
    }
out:     
    return rv;
}

/**************************************************************************************************/
/* Access API to other httpd components */

static int md_is_managed(server_rec *s)
{
    md_config_t *conf = (md_config_t *)md_config_get(s);

    if (conf && conf->md) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO() 
                     "%s: manages server %s", conf->md->name, s->server_hostname);
        return 1;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,  
                 "server %s is not managed", s->server_hostname);
    return 0;
}

static apr_status_t md_get_credentials(server_rec *s, apr_pool_t *p,
                                       const char **pkeyfile, const char **pcertfile,
                                       const char **pchainfile)
{
    apr_status_t rv = APR_ENOENT;    
    md_config_t *conf;
    md_reg_t *reg;
    const md_t *md;
    
    *pkeyfile = NULL;
    *pcertfile = NULL;
    *pchainfile = NULL;
    conf = (md_config_t *)md_config_get(s);
    
    if (conf && conf->md && conf->store) {
        if (APR_SUCCESS == (rv = md_reg_init(&reg, p, conf->store))) {
            md = md_reg_get(reg, conf->md->name, p);
            if (md->state != MD_S_COMPLETE) {
                return APR_EAGAIN;
            }
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO() 
                         "%s: loading credentials for server %s", md->name, s->server_hostname);
            return md_reg_get_cred_files(reg, md, p, pkeyfile, pcertfile, pchainfile);
        }
    }
    return rv;
}


static int md_is_challenge(conn_rec *c, const char *servername,
                           X509 **pcert, EVP_PKEY **pkey)
{
    md_config_t *conf;
    apr_size_t slen, sufflen = sizeof(MD_TLSSNI01_DNS_SUFFIX) - 1;
    apr_status_t rv;

    slen = strlen(servername);
    if (slen <= sufflen 
        || apr_strnatcasecmp(MD_TLSSNI01_DNS_SUFFIX, servername + slen - sufflen)) {
        return 0;
    }
    
    conf = (md_config_t *)md_config_get(c->base_server);
    if (conf && conf->store) {
        md_store_t *store = conf->store;
        md_cert_t *mdcert;
        md_pkey_t *mdpkey;
        
        rv = md_store_load(store, MD_SG_CHALLENGES, servername, 
                           MD_FN_TLSSNI01_CERT, MD_SV_CERT, (void**)&mdcert, c->pool);
        if (APR_SUCCESS == rv && (*pcert = md_cert_get_X509(mdcert))) {
            rv = md_store_load(store, MD_SG_CHALLENGES, servername, 
                               MD_FN_TLSSNI01_PKEY, MD_SV_PKEY, (void**)&mdpkey, c->pool);
            if (APR_SUCCESS == rv && (*pkey = md_pkey_get_EVP_PKEY(mdpkey))) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, APLOGNO()
                              "%s: is a tls-sni-01 challenge host", servername);
                return 1;
            }
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, c, APLOGNO()
                          "%s: challenge data not complete, key unavailable", servername);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO()
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
    const md_config_t *conf;
    const char *base_dir, *name, *data;
    apr_status_t rv;
            
    if (!strncmp(ACME_CHALLENGE_PREFIX, r->parsed_uri.path, sizeof(ACME_CHALLENGE_PREFIX)-1)) {
        if (r->method_number == M_GET) {
            md_store_t *store;
        
            conf = ap_get_module_config(r->server->module_config, &md_module);
            store = conf->store;
            
            base_dir = md_config_gets(conf, MD_CONFIG_BASE_DIR);
            name = r->parsed_uri.path + sizeof(ACME_CHALLENGE_PREFIX)-1;

            r->status = HTTP_NOT_FOUND;
            if (!ap_strchr_c(name, '/') && store) {
                base_dir = ap_server_root_relative(r->pool, base_dir);
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
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                                  "loading challenge %s from store %s", name, base_dir);
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
    ap_hook_post_config(md_post_config, NULL, mod_ssl, APR_HOOK_MIDDLE);
    
    /* Run once after a child process has been created.
     */
    ap_hook_child_init(md_child_init, NULL, mod_ssl, APR_HOOK_MIDDLE);

    /* answer challenges *very* early, before any configured authentication may strike */
    ap_hook_post_read_request(md_http_challenge_pr, NULL, NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(md_is_managed);
    APR_REGISTER_OPTIONAL_FN(md_get_credentials);
    APR_REGISTER_OPTIONAL_FN(md_is_challenge);
}
