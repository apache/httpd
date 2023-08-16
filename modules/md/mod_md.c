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
#include <http_ssl.h>
#include <http_log.h>
#include <http_vhost.h>
#include <ap_listen.h>

#include "mod_status.h"

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_event.h"
#include "md_http.h"
#include "md_json.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_ocsp.h"
#include "md_result.h"
#include "md_reg.h"
#include "md_status.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_config.h"
#include "mod_md_drive.h"
#include "mod_md_ocsp.h"
#include "mod_md_os.h"
#include "mod_md_status.h"

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
            ap_log_error(file, line, APLOG_MODULE_INDEX, (int)level, rv, log_server, "%s", buffer);
        }
        else {
            ap_log_perror(file, line, APLOG_MODULE_INDEX, (int)level, rv, p, "%s", buffer);
        }
    }
}

/**************************************************************************************************/
/* mod_ssl interface */

static void init_ssl(void)
{
    /* nop */
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
/* notification handling */

typedef struct {
    const char *reason;         /* what the notification is about */
    apr_time_t min_interim;     /* minimum time between notifying for this reason */
} notify_rate;

static notify_rate notify_rates[] = {
    { "renewing", apr_time_from_sec(MD_SECS_PER_HOUR) }, /* once per hour */
    { "renewed", apr_time_from_sec(MD_SECS_PER_DAY) }, /* once per day */
    { "installed", apr_time_from_sec(MD_SECS_PER_DAY) }, /* once per day */
    { "expiring", apr_time_from_sec(MD_SECS_PER_DAY) },     /* once per day */
    { "errored", apr_time_from_sec(MD_SECS_PER_HOUR) },     /* once per hour */
    { "ocsp-renewed", apr_time_from_sec(MD_SECS_PER_DAY) }, /* once per day */
    { "ocsp-errored", apr_time_from_sec(MD_SECS_PER_HOUR) }, /* once per hour */
};

static apr_status_t notify(md_job_t *job, const char *reason,
                           md_result_t *result, apr_pool_t *p, void *baton)
{
    md_mod_conf_t *mc = baton;
    const char * const *argv;
    const char *cmdline;
    int exit_code;
    apr_status_t rv = APR_SUCCESS;
    apr_time_t min_interim = 0;
    md_timeperiod_t since_last;
    const char *log_msg_reason;
    int i;

    log_msg_reason = apr_psprintf(p, "message-%s", reason);
    for (i = 0; i < (int)(sizeof(notify_rates)/sizeof(notify_rates[0])); ++i) {
        if (!strcmp(reason, notify_rates[i].reason)) {
            min_interim = notify_rates[i].min_interim;
        }
    }
    if (min_interim > 0) {
        since_last.start = md_job_log_get_time_of_latest(job, log_msg_reason);
        since_last.end = apr_time_now();
        if (since_last.start > 0 && md_timeperiod_length(&since_last) < min_interim) {
            /* not enough time has passed since we sent the last notification
             * for this reason. */
            md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, APLOGNO(10267)
                "%s: rate limiting notification about '%s'", job->mdomain, reason);
            return APR_SUCCESS;
        }
    }

    if (!strcmp("renewed", reason)) {
        if (mc->notify_cmd) {
            cmdline = apr_psprintf(p, "%s %s", mc->notify_cmd, job->mdomain);
            apr_tokenize_to_argv(cmdline, (char***)&argv, p);
            rv = md_util_exec(p, argv[0], argv, &exit_code);

            if (APR_SUCCESS == rv && exit_code) rv = APR_EGENERAL;
            if (APR_SUCCESS != rv) {
                md_result_problem_printf(result, rv, MD_RESULT_LOG_ID(APLOGNO(10108)),
                                         "MDNotifyCmd %s failed with exit code %d.",
                                         mc->notify_cmd, exit_code);
                md_result_log(result, MD_LOG_ERR);
                md_job_log_append(job, "notify-error", result->problem, result->detail);
                return rv;
            }
        }
        md_log_perror(MD_LOG_MARK, MD_LOG_NOTICE, 0, p, APLOGNO(10059)
                     "The Managed Domain %s has been setup and changes "
                     "will be activated on next (graceful) server restart.", job->mdomain);
    }
    if (mc->message_cmd) {
        cmdline = apr_psprintf(p, "%s %s %s", mc->message_cmd, reason, job->mdomain);
        apr_tokenize_to_argv(cmdline, (char***)&argv, p);
        rv = md_util_exec(p, argv[0], argv, &exit_code);

        if (APR_SUCCESS == rv && exit_code) rv = APR_EGENERAL;
        if (APR_SUCCESS != rv) {
            md_result_problem_printf(result, rv, MD_RESULT_LOG_ID(APLOGNO(10109)),
                                     "MDMessageCmd %s failed with exit code %d.",
                                     mc->message_cmd, exit_code);
            md_result_log(result, MD_LOG_ERR);
            md_job_log_append(job, "message-error", reason, result->detail);
            return rv;
        }
    }

    md_job_log_append(job, log_msg_reason, NULL, NULL);
    return APR_SUCCESS;
}

static apr_status_t on_event(const char *event, const char *mdomain, void *baton, 
                             md_job_t *job, md_result_t *result, apr_pool_t *p)
{
    (void)mdomain;
    return notify(job, event, result, p, baton);
}

/**************************************************************************************************/
/* store setup */

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
            case MD_SG_OCSP:
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
        goto leave;
    }

    md_store_fs_set_event_cb(*pstore, store_file_ev, s);
    if (APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_CHALLENGES, p, s))
        || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_STAGING, p, s))
        || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_ACCOUNTS, p, s))
        || APR_SUCCESS != (rv = check_group_dir(*pstore, MD_SG_OCSP, p, s))
        ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10047)
                     "setup challenges directory");
        goto leave;
    }

leave:
    return rv;
}

/**************************************************************************************************/
/* post config handling */

static void merge_srv_config(md_t *md, md_srv_conf_t *base_sc, apr_pool_t *p)
{
    const char *contact;

    if (!md->sc) {
        md->sc = base_sc;
    }

    if (!md->ca_urls && md->sc->ca_urls) {
        md->ca_urls = apr_array_copy(p, md->sc->ca_urls);
    }
    if (!md->ca_proto) {
        md->ca_proto = md_config_gets(md->sc, MD_CONFIG_CA_PROTO);
    }
    if (!md->ca_agreement) {
        md->ca_agreement = md_config_gets(md->sc, MD_CONFIG_CA_AGREEMENT);
    }
    contact = md_config_gets(md->sc, MD_CONFIG_CA_CONTACT);
    if (md->contacts && md->contacts->nelts > 0) {
        /* set explicitly */
    }
    else if (contact && contact[0]) {
        apr_array_clear(md->contacts);
        APR_ARRAY_PUSH(md->contacts, const char *) =
        md_util_schemify(p, contact, "mailto");
    }
    else if( md->sc->s->server_admin && strcmp(DEFAULT_ADMIN, md->sc->s->server_admin)) {
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
    if (md_pkeys_spec_is_empty(md->pks)) {
        md->pks = md->sc->pks;
    }
    if (md->require_https < 0) {
        md->require_https = md_config_geti(md->sc, MD_CONFIG_REQUIRE_HTTPS);
    }
    if (!md->ca_eab_kid) {
        md->ca_eab_kid = md->sc->ca_eab_kid;
        md->ca_eab_hmac = md->sc->ca_eab_hmac;
    }
    if (md->must_staple < 0) {
        md->must_staple = md_config_geti(md->sc, MD_CONFIG_MUST_STAPLE);
    }
    if (md->stapling < 0) {
        md->stapling = md_config_geti(md->sc, MD_CONFIG_STAPLING);
    }
}

static apr_status_t check_coverage(md_t *md, const char *domain, server_rec *s,
                                   int *pupdates, apr_pool_t *p)
{
    if (md_contains(md, domain, 0)) {
        return APR_SUCCESS;
    }
    else if (md->transitive) {
        APR_ARRAY_PUSH(md->domains, const char*) = apr_pstrdup(p, domain);
        *pupdates |= MD_UPD_DOMAINS;
        return APR_SUCCESS;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10040)
                     "Virtual Host %s:%d matches Managed Domain '%s', but the "
                     "name/alias %s itself is not managed. A requested MD certificate "
                     "will not match ServerName.",
                     s->server_hostname, s->port, md->name, domain);
        return APR_SUCCESS;
    }
}

static apr_status_t md_cover_server(md_t *md, server_rec *s, int *pupdates, apr_pool_t *p)
{
    apr_status_t rv;
    const char *name;
    int i;

    if (APR_SUCCESS == (rv = check_coverage(md, s->server_hostname, s, pupdates, p))) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                     "md[%s]: auto add, covers name %s", md->name, s->server_hostname);
        for (i = 0; s->names && i < s->names->nelts; ++i) {
            name = APR_ARRAY_IDX(s->names, i, const char*);
            if (APR_SUCCESS != (rv = check_coverage(md, name, s, pupdates, p))) {
                break;
            }
            ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                         "md[%s]: auto add, covers alias %s", md->name, name);
        }
    }
    return rv;
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

static apr_status_t detect_supported_protocols(md_mod_conf_t *mc, server_rec *s,
                                               apr_pool_t *p, int log_level)
{
    ap_listen_rec *lr;
    apr_sockaddr_t *sa;
    int can_http, can_https;

    if (mc->can_http >= 0 && mc->can_https >= 0) goto set_and_leave;

    can_http = can_https = 0;
    for (lr = ap_listeners; lr; lr = lr->next) {
        for (sa = lr->bind_addr; sa; sa = sa->next) {
            if  (sa->port == mc->local_80
                 && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                can_http = 1;
            }
            else if (sa->port == mc->local_443
                     && (!lr->protocol || !strncmp("http", lr->protocol, 4))) {
                can_https = 1;
            }
        }
    }
    if (mc->can_http < 0) mc->can_http = can_http;
    if (mc->can_https < 0) mc->can_https = can_https;
    ap_log_error(APLOG_MARK, log_level, 0, s, APLOGNO(10037)
                 "server seems%s reachable via http: and%s reachable via https:",
                 mc->can_http? "" : " not", mc->can_https? "" : " not");
set_and_leave:
    return md_reg_set_props(mc->reg, p, mc->can_http, mc->can_https);
}

static server_rec *get_public_https_server(md_t *md, const char *domain, server_rec *base_server)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    server_rec *s;
    server_rec *res = NULL;
    request_rec r;
    int i;
    int check_port = 1;

    sc = md_config_get(base_server);
    mc = sc->mc;
    memset(&r, 0, sizeof(r));

    if (md->ca_challenges && md->ca_challenges->nelts > 0) {
        /* skip the port check if "tls-alpn-01" is pre-configured */
        check_port = !(md_array_str_index(md->ca_challenges, MD_AUTHZ_TYPE_TLSALPN01, 0, 0) >= 0);
    }

    if (check_port && !mc->can_https) return NULL;

    /* find an ssl server matching domain from MD */
    for (s = base_server; s; s = s->next) {
        sc = md_config_get(s);
        if (!sc || !sc->is_ssl || !sc->assigned) continue;
        if (base_server == s && !mc->manage_base_server) continue;
        if (base_server != s && check_port && mc->local_443 > 0 && !uses_port(s, mc->local_443)) continue;
        for (i = 0; i < sc->assigned->nelts; ++i) {
            if (md == APR_ARRAY_IDX(sc->assigned, i, md_t*)) {
                r.server = s;
                if (ap_matches_request_vhost(&r, domain, s->port)) {
                    if (check_port) {
                        return s;
                    }
                    else {
                        /* there may be multiple matching servers because we ignore the port.
                           if possible, choose a server that supports the acme-tls/1 protocol */
                        if (ap_is_allowed_protocol(NULL, NULL, s, PROTO_ACME_TLS_1)) {
                            return s;
                        }
                        res = s;
                    }
                }
            }
        }
    }
    return res;
}

static apr_status_t auto_add_domains(md_t *md, server_rec *base_server, apr_pool_t *p)
{
    md_srv_conf_t *sc;
    server_rec *s;
    apr_status_t rv = APR_SUCCESS;
    int updates;

    /* Ad all domain names used in SSL VirtualHosts, if not already there */
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, base_server,
                 "md[%s]: auto add domains", md->name);
    updates = 0;
    for (s = base_server; s; s = s->next) {
        sc = md_config_get(s);
        if (!sc || !sc->is_ssl || !sc->assigned || sc->assigned->nelts != 1) continue;
        if (md != APR_ARRAY_IDX(sc->assigned, 0, md_t*)) continue;
        if (APR_SUCCESS != (rv = md_cover_server(md, s, &updates, p))) {
            return rv;
        }
    }
    return rv;
}

static void init_acme_tls_1_domains(md_t *md, server_rec *base_server)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;
    server_rec *s;
    int i;
    const char *domain;

    /* Collect those domains that support the "acme-tls/1" protocol. This
     * is part of the MD (and not tested dynamically), since challenge selection
     * may be done outside the server, e.g. in the a2md command. */
    sc = md_config_get(base_server);
    mc = sc->mc;
    apr_array_clear(md->acme_tls_1_domains);
    for (i = 0; i < md->domains->nelts; ++i) {
        domain = APR_ARRAY_IDX(md->domains, i, const char*);
        s = get_public_https_server(md, domain, base_server);
        /* If we did not find a specific virtualhost for md and manage
         * the base_server, that one is inspected */
        if (NULL == s && mc->manage_base_server) s = base_server;
        if (NULL == s) {
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
                                       apr_pool_t *p)
{
    server_rec *s;
    request_rec r;
    md_srv_conf_t *sc;
    int i;
    const char *domain, *uri;

    sc = md_config_get(base_server);

    /* Assign the MD to all server_rec configs that it matches. If there already
     * is an assigned MD not equal this one, the configuration is in error.
     */
    memset(&r, 0, sizeof(r));
    for (s = base_server; s; s = s->next) {
        if (!mc->manage_base_server && s == base_server) {
            /* we shall not assign ourselves to the base server */
            continue;
        }

        r.server = s;
        for (i = 0; i < md->domains->nelts; ++i) {
            domain = APR_ARRAY_IDX(md->domains, i, const char*);

            if ((mc->match_mode == MD_MATCH_ALL &&
                 ap_matches_request_vhost(&r, domain, s->port))
                || (((mc->match_mode == MD_MATCH_SERVERNAMES) || md_dns_is_wildcard(p, domain)) &&
                    md_dns_matches(domain, s->server_hostname))) {
                /* Create a unique md_srv_conf_t record for this server, if there is none yet */
                sc = md_config_get_unique(s, p);
                if (!sc->assigned) sc->assigned = apr_array_make(p, 2, sizeof(md_t*));
                if (sc->assigned->nelts == 1 && mc->match_mode == MD_MATCH_SERVERNAMES) {
                    /* there is already an MD assigned for this server. But in
                     * this match mode, wildcard matches are pre-empted by non-wildcards */
                    int existing_wild = md_is_wild_match(
                          APR_ARRAY_IDX(sc->assigned, 0, const md_t*)->domains,
                          s->server_hostname);
                    if (!existing_wild && md_dns_is_wildcard(p, domain))
                        continue;  /* do not add */
                    if (existing_wild && !md_dns_is_wildcard(p, domain))
                        sc->assigned->nelts = 0;  /* overwrite existing */
                }
                APR_ARRAY_PUSH(sc->assigned, md_t*) = md;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10041)
                             "Server %s:%d matches md %s (config %s, match-mode=%d) "
                             "for domain %s, has now %d MDs",
                             s->server_hostname, s->port, md->name, sc->name,
                             mc->match_mode, domain, (int)sc->assigned->nelts);

                if (md->contacts && md->contacts->nelts > 0) {
                    /* set explicitly */
                }
                else if (sc->ca_contact && sc->ca_contact[0]) {
                    uri = md_util_schemify(p, sc->ca_contact, "mailto");
                    if (md_array_str_index(md->contacts, uri, 0, 0) < 0) {
                        APR_ARRAY_PUSH(md->contacts, const char *) = uri;
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10044)
                                     "%s: added contact %s", md->name, uri);
                    }
                }
                else if (s->server_admin && strcmp(DEFAULT_ADMIN, s->server_admin)) {
                    uri = md_util_schemify(p, s->server_admin, "mailto");
                    if (md_array_str_index(md->contacts, uri, 0, 0) < 0) {
                        APR_ARRAY_PUSH(md->contacts, const char *) = uri;
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server, APLOGNO(10237)
                                     "%s: added contact %s", md->name, uri);
                    }
                }
                break;
            }
        }
    }
    return APR_SUCCESS;
}

static apr_status_t link_mds_to_servers(md_mod_conf_t *mc, server_rec *s, apr_pool_t *p)
{
    int i;
    md_t *md;
    apr_status_t rv = APR_SUCCESS;

    apr_array_clear(mc->unused_names);
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        if (APR_SUCCESS != (rv = link_md_to_servers(mc, md, s, p))) {
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
    md_timeslice_t *ts;
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

        if (mc->match_mode == MD_MATCH_ALL) {
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
        }

        if (md->cert_files && md->cert_files->nelts) {
            if (!md->pkey_files || (md->cert_files->nelts != md->pkey_files->nelts)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10170)
                             "The Managed Domain '%s' "
                             "needs one MDCertificateKeyFile for each MDCertificateFile.",
                             md->name);
                return APR_EINVAL;
            }
        }
        else if (md->pkey_files && md->pkey_files->nelts 
            && (!md->cert_files || !md->cert_files->nelts)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10171)
                         "The Managed Domain '%s' "
                         "has MDCertificateKeyFile(s) but no MDCertificateFile.",
                         md->name);
            return APR_EINVAL;
        }

        if (APLOG_IS_LEVEL(base_server, log_level)) {
            ap_log_error(APLOG_MARK, log_level, 0, base_server, APLOGNO(10039)
                         "Completed MD[%s, CA=%s, Proto=%s, Agreement=%s, renew-mode=%d "
                         "renew_window=%s, warn_window=%s",
                         md->name, md->ca_effective, md->ca_proto, md->ca_agreement, md->renew_mode,
                         md->renew_window? md_timeslice_format(md->renew_window, p) : "unset",
                         md->warn_window? md_timeslice_format(md->warn_window, p) : "unset");
        }
    }
    return rv;
}

static apr_status_t check_invalid_duplicates(server_rec *base_server)
{
    server_rec *s;
    md_srv_conf_t *sc;

    ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, base_server,
                 "checking duplicate ssl assignments");
    for (s = base_server; s; s = s->next) {
        sc = md_config_get(s);
        if (!sc || !sc->assigned) continue;

        if (sc->assigned->nelts > 1 && sc->is_ssl) {
            /* duplicate assignment to SSL VirtualHost, not allowed */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server, APLOGNO(10042)
                         "conflict: %d MDs match to SSL VirtualHost %s, there can at most be one.",
                         (int)sc->assigned->nelts, s->server_hostname);
            return APR_EINVAL;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t check_usage(md_mod_conf_t *mc, md_t *md, server_rec *base_server,
                                apr_pool_t *p, apr_pool_t *ptemp)
{
    server_rec *s;
    md_srv_conf_t *sc;
    apr_status_t rv = APR_SUCCESS;
    int i, has_ssl;
    apr_array_header_t *servers;

    (void)p;
    servers = apr_array_make(ptemp, 5, sizeof(server_rec*));
    has_ssl = 0;
    for (s = base_server; s; s = s->next) {
        sc = md_config_get(s);
        if (!sc || !sc->assigned) continue;
        for (i = 0; i < sc->assigned->nelts; ++i) {
            if (md == APR_ARRAY_IDX(sc->assigned, i, md_t*)) {
                APR_ARRAY_PUSH(servers, server_rec*) = s;
                if (sc->is_ssl) has_ssl = 1;
            }
        }
    }

    if (!has_ssl && md->require_https > MD_REQUIRE_OFF) {
        /* We require https for this MD, but do we have a SSL vhost? */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(10105)
                     "MD %s does not match any VirtualHost with 'SSLEngine on', "
                     "but is configured to require https. This cannot work.", md->name);
    }
    if (apr_is_empty_array(servers)) {
        if (md->renew_mode != MD_RENEW_ALWAYS) {
            /* Not an error, but looks suspicious */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server, APLOGNO(10045)
                         "No VirtualHost matches Managed Domain %s", md->name);
            APR_ARRAY_PUSH(mc->unused_names, const char*)  = md->name;
        }
    }
    return rv;
}

static int init_cert_watch_status(md_mod_conf_t *mc, apr_pool_t *p, apr_pool_t *ptemp, server_rec *s)
{
    md_t *md;
    md_result_t *result;
    int i, count;

    /* Calculate the list of MD names which we need to watch:
     * - all MDs that are used somewhere
     * - all MDs in drive mode 'AUTO' that are not in 'unused_names'
     */
    count = 0;
    result = md_result_make(ptemp, APR_SUCCESS);
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t*);
        md_result_set(result, APR_SUCCESS, NULL);
        md->watched = 0;
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

        md->watched = 1;
        ++count;
    }
    return count;
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

    md_event_init(p);
    md_event_subscribe(on_event, mc);

    rv = setup_store(&store, mc, p, s);
    if (APR_SUCCESS != rv) goto leave;

    rv = md_reg_create(&mc->reg, p, store, mc->proxy_url, mc->ca_certs,
                       mc->min_delay, mc->retry_failover,
                       mc->use_store_locks, mc->lock_wait_timeout);
    if (APR_SUCCESS != rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10072) "setup md registry");
        goto leave;
    }

    /* renew on 30% remaining /*/
    rv = md_ocsp_reg_make(&mc->ocsp, p, store, mc->ocsp_renew_window,
                          AP_SERVER_BASEVERSION, mc->proxy_url,
                          mc->min_delay);
    if (APR_SUCCESS != rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10196) "setup ocsp registry");
        goto leave;
    }

    init_ssl();

    /* How to bootstrap this module:
     * 1. find out if we know if http: and/or https: requests will arrive
     * 2. apply the now complete configuration settings to the MDs
     * 3. Link MDs to the server_recs they are used in. Detect unused MDs.
     * 4. Update the store with the MDs. Change domain names, create new MDs, etc.
     *    Basically all MD properties that are configured directly.
     *    WARNING: this may change the name of an MD. If an MD loses the first
     *    of its domain names, it first gets the new first one as name. The
     *    store will find the old settings and "recover" the previous name.
     * 5. Load any staged data from previous driving.
     * 6. on a dry run, this is all we do
     * 7. Read back the MD properties that reflect the existence and aspect of
     *    credentials that are in the store (or missing there).
     *    Expiry times, MD state, etc.
     * 8. Determine the list of MDs that need driving/supervision.
     * 9. Cleanup any left-overs in registry/store that are no longer needed for
     *    the list of MDs as we know it now.
     * 10. If this list is non-empty, setup a watchdog to run.
     */
    /*1*/
    if (APR_SUCCESS != (rv = detect_supported_protocols(mc, s, p, log_level))) goto leave;
    /*2*/
    if (APR_SUCCESS != (rv = merge_mds_with_conf(mc, p, s, log_level))) goto leave;
    /*3*/
    if (APR_SUCCESS != (rv = link_mds_to_servers(mc, s, p))) goto leave;
    /*4*/
    if (APR_SUCCESS != (rv = md_reg_lock_global(mc->reg, ptemp))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10398)
                     "unable to obtain global registry lock, "
                     "renewed certificates may remain inactive on "
                     "this httpd instance!");
        /* FIXME: or should we fail the server start/reload here? */
        rv = APR_SUCCESS;
        goto leave;
    }
    if (APR_SUCCESS != (rv = md_reg_sync_start(mc->reg, mc->mds, ptemp))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10073)
                     "syncing %d mds to registry", mc->mds->nelts);
        goto leave;
    }
    /*5*/
    md_reg_load_stagings(mc->reg, mc->mds, mc->env, p);
leave:
    md_reg_unlock_global(mc->reg, ptemp);
    return rv;
}

static apr_status_t md_post_config_after_ssl(apr_pool_t *p, apr_pool_t *plog,
                                             apr_pool_t *ptemp, server_rec *s)
{
    md_srv_conf_t *sc;
    apr_status_t rv = APR_SUCCESS;
    md_mod_conf_t *mc;
    int watched, i;
    md_t *md;

    (void)ptemp;
    (void)plog;
    sc = md_config_get(s);

    /*6*/
    if (!sc || !sc->mc || sc->mc->dry_run) goto leave;
    mc = sc->mc;

    /*7*/
    if (APR_SUCCESS != (rv = check_invalid_duplicates(s))) {
        goto leave;
    }
    apr_array_clear(mc->unused_names);
    for (i = 0; i < mc->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(mc->mds, i, md_t *);

        ap_log_error( APLOG_MARK, APLOG_TRACE2, rv, s, "md{%s}: auto_add", md->name);
        if (APR_SUCCESS != (rv = auto_add_domains(md, s, p))) {
            goto leave;
        }
        init_acme_tls_1_domains(md, s);
        ap_log_error( APLOG_MARK, APLOG_TRACE2, rv, s, "md{%s}: check_usage", md->name);
        if (APR_SUCCESS != (rv = check_usage(mc, md, s, p, ptemp))) {
            goto leave;
        }
        ap_log_error( APLOG_MARK, APLOG_TRACE2, rv, s, "md{%s}: sync_finish", md->name);
        if (APR_SUCCESS != (rv = md_reg_sync_finish(mc->reg, md, p, ptemp))) {
            ap_log_error( APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10172)
                         "md[%s]: error syncing to store", md->name);
            goto leave;
        }
    }
    /*8*/
    ap_log_error( APLOG_MARK, APLOG_TRACE2, rv, s, "init_cert_watch");
    watched = init_cert_watch_status(mc, p, ptemp, s);
    /*9*/
    ap_log_error( APLOG_MARK, APLOG_TRACE2, rv, s, "cleanup challenges");
    md_reg_cleanup_challenges(mc->reg, p, ptemp, mc->mds);

    /* From here on, the domains in the registry are readonly
     * and only staging/challenges may be manipulated */
    md_reg_freeze_domains(mc->reg, mc->mds);

    if (watched) {
        /*10*/
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10074)
                     "%d out of %d mds need watching", watched, mc->mds->nelts);

        md_http_use_implementation(md_curl_get_impl(p));
        rv = md_renew_start_watching(mc, s, p);
    }
    else {
        ap_log_error( APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10075) "no mds to supervise");
    }

    if (!mc->ocsp || md_ocsp_count(mc->ocsp) == 0) {
        ap_log_error( APLOG_MARK, APLOG_TRACE1, 0, s, "no ocsp to manage");
        goto leave;
    }

    md_http_use_implementation(md_curl_get_impl(p));
    rv = md_ocsp_start_watching(mc, s, p);

leave:
    ap_log_error( APLOG_MARK, APLOG_TRACE2, rv, s, "post_config done");
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
    if (!r && offers && ap_ssl_conn_is_ssl(c)
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
    if (!r && ap_ssl_conn_is_ssl(c) && !strcmp(PROTO_ACME_TLS_1, protocol)) {
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

static void fallback_fnames(apr_pool_t *p, md_pkey_spec_t *kspec, char **keyfn, char **certfn )
{
    *keyfn  = apr_pstrcat(p, "fallback-", md_pkey_filename(kspec, p), NULL);
    *certfn = apr_pstrcat(p, "fallback-", md_chain_filename(kspec, p), NULL);
}

static apr_status_t make_fallback_cert(md_store_t *store, const md_t *md, md_pkey_spec_t *kspec,
                                       server_rec *s, apr_pool_t *p, char *keyfn, char *crtfn)
{
    md_pkey_t *pkey;
    md_cert_t *cert;
    apr_status_t rv;

    if (APR_SUCCESS != (rv = md_pkey_gen(&pkey, p, kspec))
        || APR_SUCCESS != (rv = md_store_save(store, p, MD_SG_DOMAINS, md->name,
                                keyfn, MD_SV_PKEY, (void*)pkey, 0))
        || APR_SUCCESS != (rv = md_cert_self_sign(&cert, "Apache Managed Domain Fallback",
                                    md->domains, pkey, apr_time_from_sec(14 * MD_SECS_PER_DAY), p))
        || APR_SUCCESS != (rv = md_store_save(store, p, MD_SG_DOMAINS, md->name,
                                crtfn, MD_SV_CERT, (void*)cert, 0))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10174)
                     "%s: make fallback %s certificate", md->name, md_pkey_spec_name(kspec));
    }
    return rv;
}

static apr_status_t get_certificates(server_rec *s, apr_pool_t *p, int fallback,
                                     apr_array_header_t **pcert_files,
                                     apr_array_header_t **pkey_files)
{
    apr_status_t rv = APR_ENOENT;
    md_srv_conf_t *sc;
    md_reg_t *reg;
    md_store_t *store;
    const md_t *md;
    apr_array_header_t *key_files, *chain_files;
    const char *keyfile, *chainfile;
    int i;

    *pkey_files = *pcert_files = NULL;
    key_files = apr_array_make(p, 5, sizeof(const char*));
    chain_files = apr_array_make(p, 5, sizeof(const char*));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10113)
                 "get_certificates called for vhost %s.", s->server_hostname);

    sc = md_config_get(s);
    if (!sc) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,
                     "asked for certificate of server %s which has no md config",
                     s->server_hostname);
        return APR_ENOENT;
    }

    assert(sc->mc);
    reg = sc->mc->reg;
    assert(reg);

    sc->is_ssl = 1;

    if (!sc->assigned) {
        /* With the new hooks in mod_ssl, we are invoked for all server_rec. It is
         * therefore normal, when we have nothing to add here. */
        return APR_ENOENT;
    }
    else if (sc->assigned->nelts != 1) {
        if (!fallback) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(10238)
                         "conflict: %d MDs match Virtualhost %s which uses SSL, however "
                         "there can be at most 1.",
                         (int)sc->assigned->nelts, s->server_hostname);
        }
        return APR_EINVAL;
    }
    md = APR_ARRAY_IDX(sc->assigned, 0, const md_t*);

    if (md->cert_files && md->cert_files->nelts) {
        apr_array_cat(chain_files, md->cert_files);
        apr_array_cat(key_files, md->pkey_files);
        rv = APR_SUCCESS;
    }
    else {
        md_pkey_spec_t *spec;
        
        for (i = 0; i < md_cert_count(md); ++i) {
            spec = md_pkeys_spec_get(md->pks, i);
            rv = md_reg_get_cred_files(&keyfile, &chainfile, reg, MD_SG_DOMAINS, md, spec, p);
            if (APR_SUCCESS == rv) {
                APR_ARRAY_PUSH(key_files, const char*) = keyfile;
                APR_ARRAY_PUSH(chain_files, const char*) = chainfile;
            }
            else if (APR_STATUS_IS_ENOENT(rv)) {
                /* certificate for this pkey is not available, others might
                 * if pkeys have been added for a running mdomain.
                 * see issue #260 */
                rv = APR_SUCCESS;
            }
            else if (!APR_STATUS_IS_ENOENT(rv)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(10110)
                             "retrieving credentials for MD %s (%s)",
                             md->name, md_pkey_spec_name(spec));
                return rv;
            }
        }

        if (md_array_is_empty(key_files)) {
            if (fallback) {
                /* Provide temporary, self-signed certificate as fallback, so that
                 * clients do not get obscure TLS handshake errors or will see a fallback
                 * virtual host that is not intended to be served here. */
                char *kfn, *cfn;

                store = md_reg_store_get(reg);
                assert(store);

                for (i = 0; i < md_cert_count(md); ++i) {
                    spec = md_pkeys_spec_get(md->pks, i);
                    fallback_fnames(p, spec, &kfn, &cfn);

                    md_store_get_fname(&keyfile, store, MD_SG_DOMAINS, md->name, kfn, p);
                    md_store_get_fname(&chainfile, store, MD_SG_DOMAINS, md->name, cfn, p);
                    if (!md_file_exists(keyfile, p) || !md_file_exists(chainfile, p)) {
                        if (APR_SUCCESS != (rv = make_fallback_cert(store, md, spec, s, p, kfn, cfn))) {
                            return rv;
                        }
                    }
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10116)
                                 "%s: providing %s fallback certificate for server %s",
                                 md->name, md_pkey_spec_name(spec), s->server_hostname);
                    APR_ARRAY_PUSH(key_files, const char*) = keyfile;
                    APR_ARRAY_PUSH(chain_files, const char*) = chainfile;
                }
                rv = APR_EAGAIN;
                goto leave;
            }
        }
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s, APLOGNO(10077)
                 "%s[state=%d]: providing certificates for server %s",
                 md->name, md->state, s->server_hostname);
leave:
    if (!md_array_is_empty(key_files) && !md_array_is_empty(chain_files)) {
        *pkey_files = key_files;
        *pcert_files = chain_files;
    }
    else if (APR_SUCCESS == rv) {
        rv = APR_ENOENT;
    }
    return rv;
}

static int md_add_cert_files(server_rec *s, apr_pool_t *p,
                             apr_array_header_t *cert_files,
                             apr_array_header_t *key_files)
{
    apr_array_header_t *md_cert_files;
    apr_array_header_t *md_key_files;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "hook ssl_add_cert_files for %s",
                 s->server_hostname);
    rv = get_certificates(s, p, 0, &md_cert_files, &md_key_files);
    if (APR_SUCCESS == rv) {
        if (!apr_is_empty_array(cert_files)) {
            /* downgraded fromm WARNING to DEBUG, since installing separate certificates
             * may be a valid use case. */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(10084)
                         "host '%s' is covered by a Managed Domain, but "
                         "certificate/key files are already configured "
                         "for it (most likely via SSLCertificateFile).",
                         s->server_hostname);
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                     "host '%s' is covered by a Managed Domaina and "
                     "is being provided with %d key/certificate files.",
                     s->server_hostname, md_cert_files->nelts);
        apr_array_cat(cert_files, md_cert_files);
        apr_array_cat(key_files, md_key_files);
        return DONE;
    }
    return DECLINED;
}

static int md_add_fallback_cert_files(server_rec *s, apr_pool_t *p,
                                      apr_array_header_t *cert_files,
                                      apr_array_header_t *key_files)
{
    apr_array_header_t *md_cert_files;
    apr_array_header_t *md_key_files;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "hook ssl_add_fallback_cert_files for %s",
                 s->server_hostname);
    rv = get_certificates(s, p, 1, &md_cert_files, &md_key_files);
    if (APR_EAGAIN == rv) {
        apr_array_cat(cert_files, md_cert_files);
        apr_array_cat(key_files, md_key_files);
        return DONE;
    }
    return DECLINED;
}

static int md_answer_challenge(conn_rec *c, const char *servername,
                               const char **pcert_pem, const char **pkey_pem)
{
    const char *protocol;
    int hook_rv = DECLINED;
    apr_status_t rv = APR_ENOENT;
    md_srv_conf_t *sc;
    md_store_t *store;
    char *cert_name, *pkey_name;
    const char *cert_pem, *key_pem;
    int i;

    if (!servername
        || !(protocol = md_protocol_get(c))
        || strcmp(PROTO_ACME_TLS_1, protocol)) {
        goto cleanup;
    }
    sc = md_config_get(c->base_server);
    if (!sc || !sc->mc->reg) goto cleanup;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "Answer challenge[tls-alpn-01] for %s", servername);
    store = md_reg_store_get(sc->mc->reg);

    for (i = 0; i < md_pkeys_spec_count( sc->pks ); i++) {
        tls_alpn01_fnames(c->pool, md_pkeys_spec_get(sc->pks,i),
                          &pkey_name, &cert_name);

        rv = md_store_load(store, MD_SG_CHALLENGES, servername, cert_name, MD_SV_TEXT,
                           (void**)&cert_pem, c->pool);
        if (APR_STATUS_IS_ENOENT(rv)) continue;
        if (APR_SUCCESS != rv) goto cleanup;

        rv = md_store_load(store, MD_SG_CHALLENGES, servername, pkey_name, MD_SV_TEXT,
                           (void**)&key_pem, c->pool);
        if (APR_STATUS_IS_ENOENT(rv)) continue;
        if (APR_SUCCESS != rv) goto cleanup;

        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "Found challenge cert %s, key %s for %s",
                      cert_name, pkey_name, servername);
        *pcert_pem = cert_pem;
        *pkey_pem = key_pem;
        hook_rv = OK;
        break;
    }

    if (DECLINED == hook_rv) {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(10080)
                      "%s: unknown tls-alpn-01 challenge host", servername);
    }

cleanup:
    return hook_rv;
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

            if (md && md->ca_challenges
                && md_array_str_index(md->ca_challenges, MD_AUTHZ_CHA_HTTP_01, 0, 1) < 0) {
                /* The MD this challenge is for does not allow http-01 challanges,
                 * we have to decline. See #279 for a setup example where this
                 * is necessary.
                 */
                return DECLINED;
            }

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
                    || (md->cert_files && md->cert_files->nelts
                        && md->renew_mode == MD_RENEW_AUTO)) {
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
    const char *s, *host;
    const md_t *md;
    int status;

    /* Requests outside the /.well-known path are subject to possible
     * https: redirects or HSTS header additions.
     */
    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc || !sc->assigned || !sc->assigned->nelts || !r->parsed_uri.path
        || !strncmp(WELL_KNOWN_PREFIX, r->parsed_uri.path, sizeof(WELL_KNOWN_PREFIX)-1)) {
        goto declined;
    }

    host = ap_get_server_name_for_url(r);
    md = md_get_for_domain(r->server, host);
    if (!md) goto declined;

    if (ap_ssl_conn_is_ssl(r->connection)) {
        /* Using https:
         * if 'permanent' and no one else set a HSTS header already, do it */
        if (md->require_https == MD_REQUIRE_PERMANENT
            && sc->mc->hsts_header && !apr_table_get(r->headers_out, MD_HSTS_HEADER)) {
            apr_table_setn(r->headers_out, MD_HSTS_HEADER, sc->mc->hsts_header);
        }
    }
    else {
        if (md->require_https > MD_REQUIRE_OFF) {
            /* Not using https:, but require it. Redirect. */
            if (r->method_number == M_GET) {
                /* safe to use the old-fashioned codes */
                status = ((MD_REQUIRE_PERMANENT == md->require_https)?
                          HTTP_MOVED_PERMANENTLY : HTTP_MOVED_TEMPORARILY);
            }
            else {
                /* these should keep the method unchanged on retry */
                status = ((MD_REQUIRE_PERMANENT == md->require_https)?
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
declined:
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
    static const char *const mod_ssl[] = { "mod_ssl.c", "mod_tls.c", NULL};
    static const char *const mod_wd[] = { "mod_watchdog.c", NULL};

    /* Leave the ssl initialization to mod_ssl or friends. */
    md_acme_init(pool, AP_SERVER_BASEVERSION, 0);

    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");

    /* Run once after configuration is set, before mod_ssl.
     * Run again after mod_ssl is done.
     */
    ap_hook_post_config(md_post_config_before_ssl, NULL, mod_ssl, APR_HOOK_MIDDLE);
    ap_hook_post_config(md_post_config_after_ssl, mod_ssl, mod_wd, APR_HOOK_LAST);

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
    APR_OPTIONAL_HOOK(ap, status_hook, md_domains_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ap, status_hook, md_ocsp_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(md_status_handler, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_ssl_answer_challenge(md_answer_challenge, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_ssl_add_cert_files(md_add_cert_files, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_ssl_add_fallback_cert_files(md_add_fallback_cert_files, NULL, NULL, APR_HOOK_MIDDLE);

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 105)
    ap_hook_ssl_ocsp_prime_hook(md_ocsp_prime_status, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_ssl_ocsp_get_resp_hook(md_ocsp_provide_status, NULL, NULL, APR_HOOK_MIDDLE);
#else
#error "This version of mod_md requires Apache httpd 2.4.48 or newer."
#endif /* AP_MODULE_MAGIC_AT_LEAST() */
}

