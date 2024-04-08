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
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_vhost.h>

#include "md.h"
#include "md_acme.h"
#include "md_crypt.h"
#include "md_log.h"
#include "md_json.h"
#include "md_util.h"
#include "mod_md_private.h"
#include "mod_md_config.h"

#define MD_CMD_MD_SECTION     "<MDomainSet"
#define MD_CMD_MD2_SECTION    "<MDomain"

#define DEF_VAL     (-1)

#ifndef MD_DEFAULT_BASE_DIR
#define MD_DEFAULT_BASE_DIR "md"
#endif

static md_timeslice_t def_ocsp_keep_window = {
    0,
    MD_TIME_OCSP_KEEP_NORM,
};

static md_timeslice_t def_ocsp_renew_window = {
    MD_TIME_LIFE_NORM,
    MD_TIME_RENEW_WINDOW_DEF,
};

/* Default settings for the global conf */
static md_mod_conf_t defmc = {
    NULL,                      /* list of mds */
#if AP_MODULE_MAGIC_AT_LEAST(20180906, 2)
    NULL,                      /* base dirm by default state-dir-relative */
#else
    MD_DEFAULT_BASE_DIR,
#endif
    NULL,                      /* proxy url for outgoing http */
    NULL,                      /* md_reg_t */
    NULL,                      /* md_ocsp_reg_t */
    80,                        /* local http: port */
    443,                       /* local https: port */
    -1,                        /* can http: */
    -1,                        /* can https: */
    0,                         /* manage base server */
    MD_HSTS_MAX_AGE_DEFAULT,   /* hsts max-age */
    NULL,                      /* hsts headers */
    NULL,                      /* unused names */
    NULL,                      /* init errors hash */
    NULL,                      /* notify cmd */
    NULL,                      /* message cmd */
    NULL,                      /* env table */
    0,                         /* dry_run flag */
    1,                         /* server_status_enabled */
    1,                         /* certificate_status_enabled */
    &def_ocsp_keep_window,     /* default time to keep ocsp responses */
    &def_ocsp_renew_window,    /* default time to renew ocsp responses */
    "crt.sh",                  /* default cert checker site name */
    "https://crt.sh?q=",       /* default cert checker site url */
    NULL,                      /* CA cert file to use */
    apr_time_from_sec(MD_SECS_PER_DAY/2), /* default time between cert checks */
    apr_time_from_sec(5),      /* minimum delay for retries */
    13,                        /* retry_failover after 14 errors, with 5s delay ~ half a day */
    0,                         /* store locks, disabled by default */
    apr_time_from_sec(5),      /* max time to wait to obaint a store lock */
    MD_MATCH_ALL,              /* match vhost severname and aliases */
};

static md_timeslice_t def_renew_window = {
    MD_TIME_LIFE_NORM,
    MD_TIME_RENEW_WINDOW_DEF,
};
static md_timeslice_t def_warn_window = {
    MD_TIME_LIFE_NORM,
    MD_TIME_WARN_WINDOW_DEF,
};

/* Default server specific setting */
static md_srv_conf_t defconf = {
    "default",                 /* name */
    NULL,                      /* server_rec */
    &defmc,                    /* mc */
    1,                         /* transitive */
    MD_REQUIRE_OFF,            /* require https */
    MD_RENEW_AUTO,             /* renew mode */
    0,                         /* must staple */
    NULL,                      /* pkey spec */
    &def_renew_window,         /* renew window */
    &def_warn_window,          /* warn window */
    NULL,                      /* ca urls */
    NULL,                      /* ca contact (email) */
    MD_PROTO_ACME,             /* ca protocol */
    NULL,                      /* ca agreemnent */
    NULL,                      /* ca challenges array */
    NULL,                      /* ca eab kid */
    NULL,                      /* ca eab hmac */
    0,                         /* stapling */
    1,                         /* staple others */
    NULL,                      /* dns01_cmd */
    NULL,                      /* currently defined md */
    NULL,                      /* assigned md, post config */
    0,                         /* is_ssl, set during mod_ssl post_config */
};

static md_mod_conf_t *mod_md_config;

static apr_status_t cleanup_mod_config(void *dummy)
{
    (void)dummy;
    mod_md_config = NULL;
    return APR_SUCCESS;
}

static md_mod_conf_t *md_mod_conf_get(apr_pool_t *pool, int create)
{
    if (mod_md_config) {
        return mod_md_config; /* reused for lifetime of the pool */
    }

    if (create) {
        mod_md_config = apr_pcalloc(pool, sizeof(*mod_md_config));
        memcpy(mod_md_config, &defmc, sizeof(*mod_md_config));
        mod_md_config->mds = apr_array_make(pool, 5, sizeof(const md_t *));
        mod_md_config->unused_names = apr_array_make(pool, 5, sizeof(const md_t *));
        mod_md_config->env = apr_table_make(pool, 10);
        mod_md_config->init_errors = apr_hash_make(pool);
         
        apr_pool_cleanup_register(pool, NULL, cleanup_mod_config, apr_pool_cleanup_null);
    }
    
    return mod_md_config;
}

#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

static void srv_conf_props_clear(md_srv_conf_t *sc)
{
    sc->transitive = DEF_VAL;
    sc->require_https = MD_REQUIRE_UNSET;
    sc->renew_mode = DEF_VAL;
    sc->must_staple = DEF_VAL;
    sc->pks = NULL;
    sc->renew_window = NULL;
    sc->warn_window = NULL;
    sc->ca_urls = NULL;
    sc->ca_contact = NULL;
    sc->ca_proto = NULL;
    sc->ca_agreement = NULL;
    sc->ca_challenges = NULL;
    sc->ca_eab_kid = NULL;
    sc->ca_eab_hmac = NULL;
    sc->stapling = DEF_VAL;
    sc->staple_others = DEF_VAL;
    sc->dns01_cmd = NULL;
}

static void srv_conf_props_copy(md_srv_conf_t *to, const md_srv_conf_t *from)
{
    to->transitive = from->transitive;
    to->require_https = from->require_https;
    to->renew_mode = from->renew_mode;
    to->must_staple = from->must_staple;
    to->pks = from->pks;
    to->warn_window = from->warn_window;
    to->renew_window = from->renew_window;
    to->ca_urls = from->ca_urls;
    to->ca_contact = from->ca_contact;
    to->ca_proto = from->ca_proto;
    to->ca_agreement = from->ca_agreement;
    to->ca_challenges = from->ca_challenges;
    to->ca_eab_kid = from->ca_eab_kid;
    to->ca_eab_hmac = from->ca_eab_hmac;
    to->stapling = from->stapling;
    to->staple_others = from->staple_others;
    to->dns01_cmd = from->dns01_cmd;
}

static void srv_conf_props_apply(md_t *md, const md_srv_conf_t *from, apr_pool_t *p)
{
    if (from->require_https != MD_REQUIRE_UNSET) md->require_https = from->require_https;
    if (from->transitive != DEF_VAL) md->transitive = from->transitive;
    if (from->renew_mode != DEF_VAL) md->renew_mode = from->renew_mode;
    if (from->must_staple != DEF_VAL) md->must_staple = from->must_staple;
    if (from->pks) md->pks = md_pkeys_spec_clone(p, from->pks);
    if (from->renew_window) md->renew_window = from->renew_window;
    if (from->warn_window) md->warn_window = from->warn_window;
    if (from->ca_urls) md->ca_urls = apr_array_copy(p, from->ca_urls);
    if (from->ca_proto) md->ca_proto = from->ca_proto;
    if (from->ca_agreement) md->ca_agreement = from->ca_agreement;
    if (from->ca_contact) {
        apr_array_clear(md->contacts);
        APR_ARRAY_PUSH(md->contacts, const char *) =
            md_util_schemify(p, from->ca_contact, "mailto");
    }
    if (from->ca_challenges) md->ca_challenges = apr_array_copy(p, from->ca_challenges);
    if (from->ca_eab_kid) md->ca_eab_kid = from->ca_eab_kid;
    if (from->ca_eab_hmac) md->ca_eab_hmac = from->ca_eab_hmac;
    if (from->stapling != DEF_VAL) md->stapling = from->stapling;
    if (from->dns01_cmd) md->dns01_cmd = from->dns01_cmd;
}

void *md_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    md_srv_conf_t *conf = (md_srv_conf_t *)apr_pcalloc(pool, sizeof(md_srv_conf_t));

    conf->name = apr_pstrcat(pool, "srv[", CONF_S_NAME(s), "]", NULL);
    conf->s = s;
    conf->mc = md_mod_conf_get(pool, 1);

    srv_conf_props_clear(conf);
    
    return conf;
}

static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    md_srv_conf_t *base = (md_srv_conf_t *)basev;
    md_srv_conf_t *add = (md_srv_conf_t *)addv;
    md_srv_conf_t *nsc;
    char *name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);
    
    nsc = (md_srv_conf_t *)apr_pcalloc(pool, sizeof(md_srv_conf_t));
    nsc->name = name;
    nsc->mc = add->mc? add->mc : base->mc;

    nsc->transitive = (add->transitive != DEF_VAL)? add->transitive : base->transitive;
    nsc->require_https = (add->require_https != MD_REQUIRE_UNSET)? add->require_https : base->require_https;
    nsc->renew_mode = (add->renew_mode != DEF_VAL)? add->renew_mode : base->renew_mode;
    nsc->must_staple = (add->must_staple != DEF_VAL)? add->must_staple : base->must_staple;
    nsc->pks = (!md_pkeys_spec_is_empty(add->pks))? add->pks : base->pks;
    nsc->renew_window = add->renew_window? add->renew_window : base->renew_window;
    nsc->warn_window = add->warn_window? add->warn_window : base->warn_window;

    nsc->ca_urls = add->ca_urls? apr_array_copy(pool, add->ca_urls)
                    : (base->ca_urls? apr_array_copy(pool, base->ca_urls) : NULL);
    nsc->ca_contact = add->ca_contact? add->ca_contact : base->ca_contact;
    nsc->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    nsc->ca_agreement = add->ca_agreement? add->ca_agreement : base->ca_agreement;
    nsc->ca_challenges = (add->ca_challenges? apr_array_copy(pool, add->ca_challenges) 
                    : (base->ca_challenges? apr_array_copy(pool, base->ca_challenges) : NULL));
    nsc->ca_eab_kid = add->ca_eab_kid? add->ca_eab_kid : base->ca_eab_kid;
    nsc->ca_eab_hmac = add->ca_eab_hmac? add->ca_eab_hmac : base->ca_eab_hmac;
    nsc->stapling = (add->stapling != DEF_VAL)? add->stapling : base->stapling;
    nsc->staple_others = (add->staple_others != DEF_VAL)? add->staple_others : base->staple_others;
    nsc->dns01_cmd = (add->dns01_cmd)? add->dns01_cmd : base->dns01_cmd;
    nsc->current = NULL;
    
    return nsc;
}

void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    return md_config_merge(pool, basev, addv);
}

static int inside_section(cmd_parms *cmd, const char *section) {
    ap_directive_t *d;
    for (d = cmd->directive->parent; d; d = d->parent) {
       if (!ap_cstr_casecmp(d->directive, section)) {
           return 1;
       }
    }
    return 0; 
}

static int inside_md_section(cmd_parms *cmd) {
    return (inside_section(cmd, MD_CMD_MD_SECTION) || inside_section(cmd, MD_CMD_MD2_SECTION));
}

static const char *md_section_check(cmd_parms *cmd) {
    if (!inside_md_section(cmd)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " is only valid inside a '",  
                           MD_CMD_MD_SECTION, "' context, not here", NULL);
    }
    return NULL;
}

#define MD_LOC_GLOBAL (0x01)
#define MD_LOC_MD     (0x02)
#define MD_LOC_ELSE   (0x04)
#define MD_LOC_ALL    (0x07)
#define MD_LOC_NOT_MD (0x102)

static const char *md_conf_check_location(cmd_parms *cmd, int flags)
{
    if (MD_LOC_GLOBAL == flags) {
        return ap_check_cmd_context(cmd, GLOBAL_ONLY);
    }
    if (MD_LOC_NOT_MD == flags && inside_md_section(cmd)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " is not allowed inside an '",  
                           MD_CMD_MD_SECTION, "' context", NULL);
    }
    if (MD_LOC_MD == flags) {
        return md_section_check(cmd);
    }
    else if ((MD_LOC_MD & flags) && inside_md_section(cmd)) {
        return NULL;
    } 
    return ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_LOCATION);
}

static const char *set_on_off(int *pvalue, const char *s, apr_pool_t *p)
{
    if (!apr_strnatcasecmp("off", s)) {
        *pvalue = 0;
    }
    else if (!apr_strnatcasecmp("on", s)) {
        *pvalue = 1;
    }
    else {
        return apr_pstrcat(p, "unknown '", s, 
                           "', supported parameter values are 'on' and 'off'", NULL);
    }
    return NULL;
}


static void add_domain_name(apr_array_header_t *domains, const char *name, apr_pool_t *p)
{
    if (md_array_str_index(domains, name, 0, 0) < 0) {
        APR_ARRAY_PUSH(domains, char *) = md_util_str_tolower(apr_pstrdup(p, name));
    }
}

static const char *set_transitive(int *ptransitive, const char *value)
{
    if (!apr_strnatcasecmp("auto", value)) {
        *ptransitive = 1;
        return NULL;
    }
    else if (!apr_strnatcasecmp("manual", value)) {
        *ptransitive = 0;
        return NULL;
    }
    return "unknown value, use \"auto|manual\"";
}

static const char *md_config_sec_start(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc;
    md_srv_conf_t save;
    const char *endp;
    const char *err, *name;
    apr_array_header_t *domains;
    md_t *md;
    int transitive = -1;
    
    (void)mconfig;
    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
        
    sc = md_config_get(cmd->server);
    endp = ap_strrchr_c(arg, '>');
    if (endp == NULL) {
        return  MD_CMD_MD_SECTION "> directive missing closing '>'";
    }

    arg = apr_pstrndup(cmd->pool, arg, (apr_size_t)(endp-arg));
    if (!arg || !*arg) {
        return MD_CMD_MD_SECTION " > section must specify a unique domain name";
    }

    name = ap_getword_conf(cmd->pool, &arg);
    domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
    add_domain_name(domains, name, cmd->pool);
    while (*arg != '\0') {
        name = ap_getword_conf(cmd->pool, &arg);
        if (NULL != set_transitive(&transitive, name)) {
            add_domain_name(domains, name, cmd->pool);
        }
    }

    if (domains->nelts == 0) {
        return "needs at least one domain name";
    }
    
    md = md_create(cmd->pool, domains);
    if (transitive >= 0) {
        md->transitive = transitive;
    }
    
    /* Save the current settings in this srv_conf and apply+restore at the
     * end of this section */
    memcpy(&save, sc, sizeof(save));
    srv_conf_props_clear(sc);
    sc->current = md;
    
    if (NULL == (err = ap_walk_config(cmd->directive->first_child, cmd, cmd->context))) {
        srv_conf_props_apply(md, sc, cmd->pool);
        APR_ARRAY_PUSH(sc->mc->mds, const md_t *) = md;
    }
    
    sc->current = NULL;
    srv_conf_props_copy(sc, &save);
    
    return err;
}

static const char *md_config_sec_add_members(cmd_parms *cmd, void *dc, 
                                             int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;
    int i;
    
    (void)dc;
    if (NULL != (err = md_section_check(cmd))) {
        if (argc == 1) {
            /* only these values are allowed outside a section */
            return set_transitive(&sc->transitive, argv[0]);
        }
        return err;
    }
    
    assert(sc->current);
    for (i = 0; i < argc; ++i) {
        if (NULL != set_transitive(&sc->transitive, argv[i])) {
            add_domain_name(sc->current->domains, argv[i], cmd->pool);
        }
    }
    return NULL;
}

static const char *md_config_set_names(cmd_parms *cmd, void *dc, 
                                       int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    apr_array_header_t *domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
    const char *err;
    md_t *md;
    int i, transitive = -1;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }

    for (i = 0; i < argc; ++i) {
        if (NULL != set_transitive(&transitive, argv[i])) {
            add_domain_name(domains, argv[i], cmd->pool);
        }
    }
    
    if (domains->nelts == 0) {
        return "needs at least one domain name";
    }
    md = md_create(cmd->pool, domains);

    if (transitive >= 0) {
        md->transitive = transitive;
    }
    
    if (cmd->config_file) {
        md->defn_name = cmd->config_file->name;
        md->defn_line_number = cmd->config_file->line_number;
    }

    APR_ARRAY_PUSH(sc->mc->mds, md_t *) = md;

    return NULL;
}

static const char *md_config_set_ca(cmd_parms *cmd, void *dc,
                                    int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err, *url;
    int i;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    if (!sc->ca_urls) {
        sc->ca_urls = apr_array_make(cmd->pool, 3, sizeof(const char *));
    }
    else {
        apr_array_clear(sc->ca_urls);
    }
    for (i = 0; i < argc; ++i) {
        if (APR_SUCCESS != md_get_ca_url_from_name(&url, cmd->pool, argv[i])) {
            return url;
        }
        APR_ARRAY_PUSH(sc->ca_urls, const char *) = url;
    }
    return NULL;
}

static const char *md_config_set_contact(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    sc->ca_contact = value;
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    config->ca_proto = value;
    return NULL;
}

static const char *md_config_set_agreement(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    config->ca_agreement = value;
    return NULL;
}

static const char *md_config_set_renew_mode(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    md_renew_mode_t renew_mode;

    (void)dc;
    if (!apr_strnatcasecmp("auto", value) || !apr_strnatcasecmp("automatic", value)) {
        renew_mode = MD_RENEW_AUTO;
    }
    else if (!apr_strnatcasecmp("always", value)) {
        renew_mode = MD_RENEW_ALWAYS;
    }
    else if (!apr_strnatcasecmp("manual", value) || !apr_strnatcasecmp("stick", value)) {
        renew_mode = MD_RENEW_MANUAL;
    }
    else {
        return apr_pstrcat(cmd->pool, "unknown MDDriveMode ", value, NULL);
    }
    
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    config->renew_mode = renew_mode;
    return NULL;
}

static const char *md_config_set_must_staple(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    return set_on_off(&config->must_staple, value, cmd->pool);
}

static const char *md_config_set_stapling(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    return set_on_off(&config->stapling, value, cmd->pool);
}

static const char *md_config_set_staple_others(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    return set_on_off(&config->staple_others, value, cmd->pool);
}

static const char *md_config_set_base_server(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = md_conf_check_location(cmd, MD_LOC_NOT_MD);

    (void)dc;
    if (err) return err;
    return set_on_off(&config->mc->manage_base_server, value, cmd->pool);
}

static const char *md_config_set_check_interval(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = md_conf_check_location(cmd, MD_LOC_NOT_MD);
    apr_time_t interval;

    (void)dc;
    if (err) return err;
    if (md_duration_parse(&interval, value, "s") != APR_SUCCESS) {
        return "unrecognized duration format";
    }
    if (interval < apr_time_from_sec(1)) {
        return "check interval cannot be less than one second";
    }
    config->mc->check_interval = interval;
    return NULL;
}

static const char *md_config_set_min_delay(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = md_conf_check_location(cmd, MD_LOC_NOT_MD);
    apr_time_t delay;

    (void)dc;
    if (err) return err;
    if (md_duration_parse(&delay, value, "s") != APR_SUCCESS) {
        return "unrecognized duration format";
    }
    config->mc->min_delay = delay;
    return NULL;
}

static const char *md_config_set_retry_failover(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = md_conf_check_location(cmd, MD_LOC_NOT_MD);
    int retry_failover;

    (void)dc;
    if (err) return err;
    retry_failover = atoi(value);
    if (retry_failover <= 0) {
        return "invalid argument, must be a number > 0";
    }
    config->mc->retry_failover = retry_failover;
    return NULL;
}

static const char *md_config_set_store_locks(cmd_parms *cmd, void *dc, const char *s)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = md_conf_check_location(cmd, MD_LOC_NOT_MD);
    int use_store_locks;
    apr_time_t wait_time = 0;

    (void)dc;
    if (err) {
        return err;
    }
    else if (!apr_strnatcasecmp("off", s)) {
        use_store_locks = 0;
    }
    else if (!apr_strnatcasecmp("on", s)) {
        use_store_locks = 1;
    }
    else {
        if (md_duration_parse(&wait_time, s, "s") != APR_SUCCESS) {
            return "neither 'on', 'off' or a duration specified";
        }
        use_store_locks = (wait_time != 0);
    }
    config->mc->use_store_locks = use_store_locks;
    if (wait_time) {
        config->mc->lock_wait_timeout = wait_time;
    }
    return NULL;
}

static const char *md_config_set_match_mode(cmd_parms *cmd, void *dc, const char *s)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = md_conf_check_location(cmd, MD_LOC_NOT_MD);

    (void)dc;
    if (err) {
        return err;
    }
    else if (!apr_strnatcasecmp("all", s)) {
        config->mc->match_mode = MD_MATCH_ALL;
    }
    else if (!apr_strnatcasecmp("servernames", s)) {
        config->mc->match_mode = MD_MATCH_SERVERNAMES;
    }
    else {
        return "invalid argument, must be a 'all' or 'servernames'";
    }
    return NULL;
}

static const char *md_config_set_require_https(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    (void)dc;
    if (!apr_strnatcasecmp("off", value)) {
        config->require_https = MD_REQUIRE_OFF;
    }
    else if (!apr_strnatcasecmp(MD_KEY_TEMPORARY, value)) {
        config->require_https = MD_REQUIRE_TEMPORARY;
    }
    else if (!apr_strnatcasecmp(MD_KEY_PERMANENT, value)) {
        config->require_https = MD_REQUIRE_PERMANENT;
    }
    else {
        return apr_pstrcat(cmd->pool, "unknown '", value, 
                           "', supported parameter values are 'temporary' and 'permanent'", NULL);
    }
    return NULL;
}

static const char *md_config_set_renew_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    
    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    err = md_timeslice_parse(&config->renew_window, cmd->pool, value, MD_TIME_LIFE_NORM);
    if (!err && config->renew_window->norm 
        && (config->renew_window->len >= config->renew_window->norm)) {
        err = "a length of 100% or more is not allowed.";
    }
    if (err) return apr_psprintf(cmd->pool, "MDRenewWindow %s", err);
    return NULL;
}

static const char *md_config_set_warn_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    
    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    err = md_timeslice_parse(&config->warn_window, cmd->pool, value, MD_TIME_LIFE_NORM);
    if (!err && config->warn_window->norm 
        && (config->warn_window->len >= config->warn_window->norm)) {
        err = "a length of 100% or more is not allowed.";
    }
    if (err) return apr_psprintf(cmd->pool, "MDWarnWindow %s", err);
    return NULL;
}

static const char *md_config_set_proxy(cmd_parms *cmd, void *arg, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
    md_util_abs_http_uri_check(cmd->pool, value, &err);
    if (err) {
        return err;
    }
    sc->mc->proxy_url = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_store_dir(cmd_parms *cmd, void *arg, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
    sc->mc->base_dir = value;
    (void)arg;
    return NULL;
}

static const char *set_port_map(md_mod_conf_t *mc, const char *value)
{
    int net_port, local_port;
    const char *endp;

    if (!strncmp("http:", value, sizeof("http:") - 1)) {
        net_port = 80; endp = value + sizeof("http") - 1; 
    }
    else if (!strncmp("https:", value, sizeof("https:") - 1)) {
        net_port = 443; endp = value + sizeof("https") - 1; 
    }
    else {
        net_port = (int)apr_strtoi64(value, (char**)&endp, 10);
        if (errno) {
            return "unable to parse first port number";
        }
    }
    if (!endp || *endp != ':') {
        return "no ':' after first port number";
    }
    ++endp;
    if (*endp == '-') {
        local_port = 0;
    }
    else {
        local_port = (int)apr_strtoi64(endp, (char**)&endp, 10);
        if (errno) {
            return "unable to parse second port number";
        }
        if (local_port <= 0 || local_port > 65535) {
            return "invalid number for port map, must be in ]0,65535]";
        }
    }
    switch (net_port) {
        case 80:
            mc->local_80 = local_port;
            break;
        case 443:
            mc->local_443 = local_port;
            break;
        default:
            return "mapped port number must be 80 or 443";
    }
    return NULL;
}

static const char *md_config_set_port_map(cmd_parms *cmd, void *arg, 
                                          const char *v1, const char *v2)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)arg;
    if (!(err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        err = set_port_map(sc->mc, v1);
    }
    if (!err && v2) {
        err = set_port_map(sc->mc, v2);
    }
    return err;
}

static const char *md_config_set_cha_tyes(cmd_parms *cmd, void *dc, 
                                          int argc, char *const argv[])
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    apr_array_header_t **pcha, *ca_challenges;
    const char *err;
    int i;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    pcha = &config->ca_challenges; 
    
    ca_challenges = *pcha;
    if (ca_challenges) {
        apr_array_clear(ca_challenges);
    }
    else {
        *pcha = ca_challenges = apr_array_make(cmd->pool, 5, sizeof(const char *));
    }
    for (i = 0; i < argc; ++i) {
        APR_ARRAY_PUSH(ca_challenges, const char *) = argv[i];
    }
    
    return NULL;
}

static const char *md_config_set_pkeys(cmd_parms *cmd, void *dc, 
                                       int argc, char *const argv[])
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err, *ptype;
    apr_int64_t bits;
    int i;
    
    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    if (argc <= 0) {
        return "needs to specify the private key type";
    }
    
    config->pks = md_pkeys_spec_make(cmd->pool);
    for (i = 0; i < argc; ++i) {
        ptype = argv[i];
        if (!apr_strnatcasecmp("Default", ptype)) {
            if (argc > 1) {
                return "'Default' allows no other parameter";
            }
            md_pkeys_spec_add_default(config->pks);
        }
        else if (strlen(ptype) > 3
            && (ptype[0] == 'R' || ptype[0] == 'r')
            && (ptype[1] == 'S' || ptype[1] == 's')
            && (ptype[2] == 'A' || ptype[2] == 'a')
            && isdigit(ptype[3])) {
            bits = (int)apr_atoi64(ptype+3);
            if (bits < MD_PKEY_RSA_BITS_MIN) {
                return apr_psprintf(cmd->pool,
                                    "must be %d or higher in order to be considered safe.",
                                    MD_PKEY_RSA_BITS_MIN);
            }
            if (bits >= INT_MAX) {
                return apr_psprintf(cmd->pool, "is too large for an RSA key length.");
            }
            if (md_pkeys_spec_contains_rsa(config->pks)) {
                return "two keys of type 'RSA' are not possible.";
            }
            md_pkeys_spec_add_rsa(config->pks, (unsigned int)bits);
        }
        else if (!apr_strnatcasecmp("RSA", ptype)) {
            if (i+1 >= argc || !isdigit(argv[i+1][0])) {
                bits = MD_PKEY_RSA_BITS_DEF;
            }
            else {
                ++i;
                bits = (int)apr_atoi64(argv[i]);
                if (bits < MD_PKEY_RSA_BITS_MIN) {
                    return apr_psprintf(cmd->pool, 
                                        "must be %d or higher in order to be considered safe.", 
                                        MD_PKEY_RSA_BITS_MIN);
                }
                if (bits >= INT_MAX) {
                    return apr_psprintf(cmd->pool, "is too large for an RSA key length.");
                }
            }
            if (md_pkeys_spec_contains_rsa(config->pks)) {
                return "two keys of type 'RSA' are not possible.";
            }
            md_pkeys_spec_add_rsa(config->pks, (unsigned int)bits);
        }
        else {
            if (md_pkeys_spec_contains_ec(config->pks, argv[i])) {
                return apr_psprintf(cmd->pool, "two keys of type '%s' are not possible.", argv[i]);
            }
            md_pkeys_spec_add_ec(config->pks, argv[i]);
        }
    }
    return NULL;
}

static const char *md_config_set_notify_cmd(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
    sc->mc->notify_cmd = arg;
    (void)mconfig;
    return NULL;
}

static const char *md_config_set_msg_cmd(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
    sc->mc->message_cmd = arg;
    (void)mconfig;
    return NULL;
}

static const char *md_config_set_dns01_cmd(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }

    if (inside_md_section(cmd)) {
        sc->dns01_cmd = arg;
    } else {
        apr_table_set(sc->mc->env, MD_KEY_CMD_DNS01, arg);
    }

    (void)mconfig;
    return NULL;
}

static const char *md_config_set_dns01_version(cmd_parms *cmd, void *mconfig, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)mconfig;
    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
    if (!strcmp("1", value) || !strcmp("2", value)) {
        apr_table_set(sc->mc->env, MD_KEY_DNS01_VERSION, value);
    }
    else {
        return "Only versions `1` and `2` are supported";
    }
    return NULL;
}

static const char *md_config_add_cert_file(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err, *fpath;
    
    (void)mconfig;
    if ((err = md_conf_check_location(cmd, MD_LOC_MD))) return err;
    assert(sc->current);
    fpath = ap_server_root_relative(cmd->pool, arg);
    if (!fpath) return apr_psprintf(cmd->pool, "certificate file not found: %s", arg);
    if (!sc->current->cert_files) {
        sc->current->cert_files = apr_array_make(cmd->pool, 3, sizeof(char*));
    }
    APR_ARRAY_PUSH(sc->current->cert_files, const char*) = fpath;
    return NULL;
}

static const char *md_config_add_key_file(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err, *fpath;
    
    (void)mconfig;
    if ((err = md_conf_check_location(cmd, MD_LOC_MD))) return err;
    assert(sc->current);
    fpath = ap_server_root_relative(cmd->pool, arg);
    if (!fpath) return apr_psprintf(cmd->pool, "certificate key file not found: %s", arg);
    if (!sc->current->pkey_files) {
        sc->current->pkey_files = apr_array_make(cmd->pool, 3, sizeof(char*));
    }
    APR_ARRAY_PUSH(sc->current->pkey_files, const char*) = fpath;
    return NULL;
}

static const char *md_config_set_server_status(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    return set_on_off(&sc->mc->server_status_enabled, value, cmd->pool);
}

static const char *md_config_set_certificate_status(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    return set_on_off(&sc->mc->certificate_status_enabled, value, cmd->pool);
}

static const char *md_config_set_ocsp_keep_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    err = md_timeslice_parse(&sc->mc->ocsp_keep_window, cmd->pool, value, MD_TIME_OCSP_KEEP_NORM);
    if (err) return apr_psprintf(cmd->pool, "MDStaplingKeepResponse %s", err);
    return NULL;
}

static const char *md_config_set_ocsp_renew_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    err = md_timeslice_parse(&sc->mc->ocsp_renew_window, cmd->pool, value, MD_TIME_LIFE_NORM);
    if (!err && sc->mc->ocsp_renew_window->norm 
        && (sc->mc->ocsp_renew_window->len >= sc->mc->ocsp_renew_window->norm)) {
        err = "with a length of 100% or more is not allowed.";
    }
    if (err) return apr_psprintf(cmd->pool, "MDStaplingRenewWindow %s", err);
    return NULL;
}

static const char *md_config_set_cert_check(cmd_parms *cmd, void *dc, 
                                            const char *name, const char *url)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    sc->mc->cert_check_name = name;
    sc->mc->cert_check_url = url;
    return NULL;
}

static const char *md_config_set_activation_delay(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;
    apr_interval_time_t delay;

    (void)mconfig;
    if ((err = md_conf_check_location(cmd, MD_LOC_NOT_MD))) {
        return err;
    }
    if (md_duration_parse(&delay, arg, "d") != APR_SUCCESS) {
        return "unrecognized duration format";
    }
    apr_table_set(sc->mc->env, MD_KEY_ACTIVATION_DELAY, md_duration_format(cmd->pool, delay));
    return NULL;
}

static const char *md_config_set_ca_certs(cmd_parms *cmd, void *dc, const char *path)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);

    (void)dc;
    sc->mc->ca_certs = path;
    return NULL;
}

static const char *md_config_set_eab(cmd_parms *cmd, void *dc,
                                     const char *keyid, const char *hmac)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if ((err = md_conf_check_location(cmd, MD_LOC_ALL))) {
        return err;
    }
    if (!hmac) {
        if (!apr_strnatcasecmp("None", keyid)) {
            keyid = "none";
        }
        else {
            /* a JSON file keeping keyid and hmac */
            const char *fpath;
            apr_status_t rv;
            md_json_t *json;

            /* If only dumping the config, don't verify the file */
            if (ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_DUMP) {
                goto leave;
            }

            fpath = ap_server_root_relative(cmd->pool, keyid);
            if (!fpath) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   ": Invalid file path ", keyid, NULL);
            }
            if (!md_file_exists(fpath, cmd->pool)) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   ": file not found: ", fpath, NULL);
            }

            rv = md_json_readf(&json, cmd->pool, fpath);
            if (APR_SUCCESS != rv) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   ": error reading JSON file ", fpath, NULL);
            }
            keyid = md_json_gets(json, MD_KEY_KID, NULL);
            if (!keyid || !*keyid) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   ": JSON does not contain '", MD_KEY_KID,
                                   "' element in file ", fpath, NULL);
            }
            hmac = md_json_gets(json, MD_KEY_HMAC, NULL);
            if (!hmac || !*hmac) {
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   ": JSON does not contain '", MD_KEY_HMAC,
                                   "' element in file ", fpath, NULL);
            }
        }
    }
leave:
    sc->ca_eab_kid = keyid;
    sc->ca_eab_hmac = hmac;
    return NULL;
}

const command_rec md_cmds[] = {
    AP_INIT_TAKE_ARGV("MDCertificateAuthority", md_config_set_ca, NULL, RSRC_CONF,
                      "URL(s) or known name(s) of CA issuing the certificates"),
    AP_INIT_TAKE1("MDCertificateAgreement", md_config_set_agreement, NULL, RSRC_CONF, 
                  "either 'accepted' or the URL of CA Terms-of-Service agreement you accept"),
    AP_INIT_TAKE_ARGV("MDCAChallenges", md_config_set_cha_tyes, NULL, RSRC_CONF, 
                      "A list of challenge types to be used."),
    AP_INIT_TAKE1("MDCertificateProtocol", md_config_set_ca_proto, NULL, RSRC_CONF, 
                  "Protocol used to obtain/renew certificates"),
    AP_INIT_TAKE1("MDContactEmail", md_config_set_contact, NULL, RSRC_CONF,
                  "Email address used for account registration"),
    AP_INIT_TAKE1("MDDriveMode", md_config_set_renew_mode, NULL, RSRC_CONF, 
                  "deprecated, older name for MDRenewMode"),
    AP_INIT_TAKE1("MDRenewMode", md_config_set_renew_mode, NULL, RSRC_CONF, 
                  "Controls how renewal of Managed Domain certificates shall be handled."),
    AP_INIT_TAKE_ARGV("MDomain", md_config_set_names, NULL, RSRC_CONF, 
                      "A group of server names with one certificate"),
    AP_INIT_RAW_ARGS(MD_CMD_MD_SECTION, md_config_sec_start, NULL, RSRC_CONF, 
                     "Container for a managed domain with common settings and certificate."),
    AP_INIT_RAW_ARGS(MD_CMD_MD2_SECTION, md_config_sec_start, NULL, RSRC_CONF, 
                     "Short form for <MDomainSet> container."),
    AP_INIT_TAKE_ARGV("MDMember", md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE_ARGV("MDMembers", md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE1("MDMustStaple", md_config_set_must_staple, NULL, RSRC_CONF, 
                  "Enable/Disable the Must-Staple flag for new certificates."),
    AP_INIT_TAKE12("MDPortMap", md_config_set_port_map, NULL, RSRC_CONF, 
                  "Declare the mapped ports 80 and 443 on the local server. E.g. 80:8000 "
                  "to indicate that the server port 8000 is reachable as port 80 from the "
                  "internet. Use 80:- to indicate that port 80 is not reachable from "
                  "the outside."),
    AP_INIT_TAKE_ARGV("MDPrivateKeys", md_config_set_pkeys, NULL, RSRC_CONF, 
                  "set the type and parameters for private key generation"),
    AP_INIT_TAKE1("MDHttpProxy", md_config_set_proxy, NULL, RSRC_CONF, 
                  "URL of a HTTP(S) proxy to use for outgoing connections"),
    AP_INIT_TAKE1("MDStoreDir", md_config_set_store_dir, NULL, RSRC_CONF, 
                  "the directory for file system storage of managed domain data."),
    AP_INIT_TAKE1("MDRenewWindow", md_config_set_renew_window, NULL, RSRC_CONF, 
                  "Time length for renewal before certificate expires (defaults to days)."),
    AP_INIT_TAKE1("MDRequireHttps", md_config_set_require_https, NULL, RSRC_CONF|OR_AUTHCFG, 
                  "Redirect non-secure requests to the https: equivalent."),
    AP_INIT_RAW_ARGS("MDNotifyCmd", md_config_set_notify_cmd, NULL, RSRC_CONF, 
                  "Set the command to run when signup/renew of domain is complete."),
    AP_INIT_TAKE1("MDBaseServer", md_config_set_base_server, NULL, RSRC_CONF, 
                  "Allow managing of base server outside virtual hosts."),
    AP_INIT_RAW_ARGS("MDChallengeDns01", md_config_set_dns01_cmd, NULL, RSRC_CONF, 
                  "Set the command for setup/teardown of dns-01 challenges"),
    AP_INIT_TAKE1("MDChallengeDns01Version", md_config_set_dns01_version, NULL, RSRC_CONF,
                  "Set the type of arguments to call `MDChallengeDns01` with"),
    AP_INIT_TAKE1("MDCertificateFile", md_config_add_cert_file, NULL, RSRC_CONF,
                  "set the static certificate (chain) file to use for this domain."),
    AP_INIT_TAKE1("MDCertificateKeyFile", md_config_add_key_file, NULL, RSRC_CONF, 
                  "set the static private key file to use for this domain."),
    AP_INIT_TAKE1("MDServerStatus", md_config_set_server_status, NULL, RSRC_CONF, 
                  "On to see Managed Domains in server-status."),
    AP_INIT_TAKE1("MDCertificateStatus", md_config_set_certificate_status, NULL, RSRC_CONF, 
                  "On to see Managed Domain expose /.httpd/certificate-status."),
    AP_INIT_TAKE1("MDWarnWindow", md_config_set_warn_window, NULL, RSRC_CONF, 
                  "When less time remains for a certificate, send our/log a warning (defaults to days)"),
    AP_INIT_RAW_ARGS("MDMessageCmd", md_config_set_msg_cmd, NULL, RSRC_CONF, 
                  "Set the command run when a message about a domain is issued."),
    AP_INIT_TAKE1("MDStapling", md_config_set_stapling, NULL, RSRC_CONF, 
                  "Enable/Disable OCSP Stapling for this/all Managed Domain(s)."),
    AP_INIT_TAKE1("MDStapleOthers", md_config_set_staple_others, NULL, RSRC_CONF, 
                  "Enable/Disable OCSP Stapling for certificates not in Managed Domains."),
    AP_INIT_TAKE1("MDStaplingKeepResponse", md_config_set_ocsp_keep_window, NULL, RSRC_CONF, 
                  "The amount of time to keep an OCSP response in the store."),
    AP_INIT_TAKE1("MDStaplingRenewWindow", md_config_set_ocsp_renew_window, NULL, RSRC_CONF, 
                  "Time length for renewal before OCSP responses expire (defaults to days)."),
    AP_INIT_TAKE2("MDCertificateCheck", md_config_set_cert_check, NULL, RSRC_CONF, 
                  "Set name and URL pattern for a certificate monitoring site."),
    AP_INIT_TAKE1("MDActivationDelay", md_config_set_activation_delay, NULL, RSRC_CONF, 
                  "How long to delay activation of new certificates"),
    AP_INIT_TAKE1("MDCACertificateFile", md_config_set_ca_certs, NULL, RSRC_CONF,
                  "Set the CA file to use for connections"),
    AP_INIT_TAKE12("MDExternalAccountBinding", md_config_set_eab, NULL, RSRC_CONF,
                  "Set the external account binding keyid and hmac values to use at CA"),
    AP_INIT_TAKE1("MDRetryDelay", md_config_set_min_delay, NULL, RSRC_CONF,
                  "Time length for first retry, doubled on every consecutive error."),
    AP_INIT_TAKE1("MDRetryFailover", md_config_set_retry_failover, NULL, RSRC_CONF,
                  "The number of errors before a failover to another CA is triggered."),
    AP_INIT_TAKE1("MDStoreLocks", md_config_set_store_locks, NULL, RSRC_CONF,
                  "Configure locking of store for updates."),
    AP_INIT_TAKE1("MDMatchNames", md_config_set_match_mode, NULL, RSRC_CONF,
                  "Determines how DNS names are matched to vhosts."),
    AP_INIT_TAKE1("MDCheckInterval", md_config_set_check_interval, NULL, RSRC_CONF,
                  "Time between certificate checks."),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};

apr_status_t md_config_post_config(server_rec *s, apr_pool_t *p)
{
    md_srv_conf_t *sc;
    md_mod_conf_t *mc;

    sc = md_config_get(s);
    mc = sc->mc;

    mc->hsts_header = NULL;
    if (mc->hsts_max_age > 0) {
        mc->hsts_header = apr_psprintf(p, "max-age=%d", mc->hsts_max_age);
    }

#if AP_MODULE_MAGIC_AT_LEAST(20180906, 2)
    if (mc->base_dir == NULL) {
        mc->base_dir = ap_state_dir_relative(p, MD_DEFAULT_BASE_DIR);
    }
#endif
    
    return APR_SUCCESS;
}

static md_srv_conf_t *config_get_int(server_rec *s, apr_pool_t *p)
{
    md_srv_conf_t *sc = (md_srv_conf_t *)ap_get_module_config(s->module_config, &md_module);
    ap_assert(sc);
    if (sc->s != s && p) {
        sc = md_config_merge(p, &defconf, sc);
        sc->s = s;
        sc->name = apr_pstrcat(p, CONF_S_NAME(s), sc->name, NULL);
        sc->mc = md_mod_conf_get(p, 1);
        ap_set_module_config(s->module_config, &md_module, sc);
    }
    return sc;
}

md_srv_conf_t *md_config_get(server_rec *s)
{
    return config_get_int(s, NULL);
}

md_srv_conf_t *md_config_get_unique(server_rec *s, apr_pool_t *p)
{
    assert(p);
    return config_get_int(s, p);
}

md_srv_conf_t *md_config_cget(conn_rec *c)
{
    return md_config_get(c->base_server);
}

const char *md_config_gets(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_CA_CONTACT:
            return sc->ca_contact? sc->ca_contact : defconf.ca_contact;
        case MD_CONFIG_CA_PROTO:
            return sc->ca_proto? sc->ca_proto : defconf.ca_proto;
        case MD_CONFIG_BASE_DIR:
            return sc->mc->base_dir;
        case MD_CONFIG_PROXY:
            return sc->mc->proxy_url;
        case MD_CONFIG_CA_AGREEMENT:
            return sc->ca_agreement? sc->ca_agreement : defconf.ca_agreement;
        case MD_CONFIG_NOTIFY_CMD:
            return sc->mc->notify_cmd;
        default:
            return NULL;
    }
}

int md_config_geti(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_DRIVE_MODE:
            return (sc->renew_mode != DEF_VAL)? sc->renew_mode : defconf.renew_mode;
        case MD_CONFIG_TRANSITIVE:
            return (sc->transitive != DEF_VAL)? sc->transitive : defconf.transitive;
        case MD_CONFIG_REQUIRE_HTTPS:
            return (sc->require_https != MD_REQUIRE_UNSET)? sc->require_https : defconf.require_https;
        case MD_CONFIG_MUST_STAPLE:
            return (sc->must_staple != DEF_VAL)? sc->must_staple : defconf.must_staple;
        case MD_CONFIG_STAPLING:
            return (sc->stapling != DEF_VAL)? sc->stapling : defconf.stapling;
        case MD_CONFIG_STAPLE_OTHERS:
            return (sc->staple_others != DEF_VAL)? sc->staple_others : defconf.staple_others;
        default:
            return 0;
    }
}

void md_config_get_timespan(md_timeslice_t **pspan, const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_RENEW_WINDOW:
            *pspan = sc->renew_window? sc->renew_window : defconf.renew_window;
            break;
        case MD_CONFIG_WARN_WINDOW:
            *pspan = sc->warn_window? sc->warn_window : defconf.warn_window;
            break;
        default:
            break;
    }
}

const md_t *md_get_for_domain(server_rec *s, const char *domain)
{
    md_srv_conf_t *sc;
    const md_t *md;
    int i;
    
    sc = md_config_get(s);
    for (i = 0; sc && sc->assigned && i < sc->assigned->nelts; ++i) {
        md = APR_ARRAY_IDX(sc->assigned, i, const md_t*);
        if (md_contains(md, domain, 0)) goto leave;
    }
    md = NULL;
leave:
    return md;
}

