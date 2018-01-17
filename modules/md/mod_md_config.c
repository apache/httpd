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
#include "md_crypt.h"
#include "md_util.h"
#include "mod_md_private.h"
#include "mod_md_config.h"

#define MD_CMD_MD             "MDomain"
#define MD_CMD_OLD_MD         "ManagedDomain"
#define MD_CMD_MD_SECTION     "<MDomainSet"
#define MD_CMD_MD_OLD_SECTION "<ManagedDomain"
#define MD_CMD_BASE_SERVER    "MDBaseServer"
#define MD_CMD_CA             "MDCertificateAuthority"
#define MD_CMD_CAAGREEMENT    "MDCertificateAgreement"
#define MD_CMD_CACHALLENGES   "MDCAChallenges"
#define MD_CMD_CAPROTO        "MDCertificateProtocol"
#define MD_CMD_DRIVEMODE      "MDDriveMode"
#define MD_CMD_MEMBER         "MDMember"
#define MD_CMD_MEMBERS        "MDMembers"
#define MD_CMD_MUSTSTAPLE     "MDMustStaple"
#define MD_CMD_NOTIFYCMD      "MDNotifyCmd"
#define MD_CMD_PORTMAP        "MDPortMap"
#define MD_CMD_PKEYS          "MDPrivateKeys"
#define MD_CMD_PROXY          "MDHttpProxy"
#define MD_CMD_RENEWWINDOW    "MDRenewWindow"
#define MD_CMD_REQUIREHTTPS   "MDRequireHttps"
#define MD_CMD_STOREDIR       "MDStoreDir"

#define DEF_VAL     (-1)

/* Default settings for the global conf */
static md_mod_conf_t defmc = {
    NULL,
    "md",
    NULL,
    NULL,
    80,
    443,
    0,
    0,
    0,
    MD_HSTS_MAX_AGE_DEFAULT,
    NULL,
    NULL,
    NULL,
};

/* Default server specific setting */
static md_srv_conf_t defconf = {
    "default",
    NULL,
    &defmc,

    1,
    MD_REQUIRE_OFF,
    MD_DRIVE_AUTO,
    0,
    NULL, 
    apr_time_from_sec(90 * MD_SECS_PER_DAY), /* If the cert lifetime were 90 days, renew */
    apr_time_from_sec(30 * MD_SECS_PER_DAY), /* 30 days before. Adjust to actual lifetime */
    MD_ACME_DEF_URL,
    "ACME",
    NULL,
    NULL,
    NULL,
    NULL,
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
        
        apr_pool_cleanup_register(pool, NULL, cleanup_mod_config, apr_pool_cleanup_null);
    }
    
    return mod_md_config;
}

#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

static void srv_conf_props_clear(md_srv_conf_t *sc)
{
    sc->transitive = DEF_VAL;
    sc->require_https = MD_REQUIRE_UNSET;
    sc->drive_mode = DEF_VAL;
    sc->must_staple = DEF_VAL;
    sc->pkey_spec = NULL;
    sc->renew_norm = DEF_VAL;
    sc->renew_window = DEF_VAL;
    sc->ca_url = NULL;
    sc->ca_proto = NULL;
    sc->ca_agreement = NULL;
    sc->ca_challenges = NULL;
}

static void srv_conf_props_copy(md_srv_conf_t *to, const md_srv_conf_t *from)
{
    to->transitive = from->transitive;
    to->require_https = from->require_https;
    to->drive_mode = from->drive_mode;
    to->must_staple = from->must_staple;
    to->pkey_spec = from->pkey_spec;
    to->renew_norm = from->renew_norm;
    to->renew_window = from->renew_window;
    to->ca_url = from->ca_url;
    to->ca_proto = from->ca_proto;
    to->ca_agreement = from->ca_agreement;
    to->ca_challenges = from->ca_challenges;
}

static void srv_conf_props_apply(md_t *md, const md_srv_conf_t *from, apr_pool_t *p)
{
    if (from->require_https != MD_REQUIRE_UNSET) md->require_https = from->require_https;
    if (from->transitive != DEF_VAL) md->transitive = from->transitive;
    if (from->drive_mode != DEF_VAL) md->drive_mode = from->drive_mode;
    if (from->must_staple != DEF_VAL) md->must_staple = from->must_staple;
    if (from->pkey_spec) md->pkey_spec = from->pkey_spec;
    if (from->renew_norm != DEF_VAL) md->renew_norm = from->renew_norm;
    if (from->renew_window != DEF_VAL) md->renew_window = from->renew_window;

    if (from->ca_url) md->ca_url = from->ca_url;
    if (from->ca_proto) md->ca_proto = from->ca_proto;
    if (from->ca_agreement) md->ca_agreement = from->ca_agreement;
    if (from->ca_challenges) md->ca_challenges = apr_array_copy(p, from->ca_challenges);
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
    nsc->assigned = add->assigned? add->assigned : base->assigned;

    nsc->transitive = (add->transitive != DEF_VAL)? add->transitive : base->transitive;
    nsc->require_https = (add->require_https != MD_REQUIRE_UNSET)? add->require_https : base->require_https;
    nsc->drive_mode = (add->drive_mode != DEF_VAL)? add->drive_mode : base->drive_mode;
    nsc->must_staple = (add->must_staple != DEF_VAL)? add->must_staple : base->must_staple;
    nsc->pkey_spec = add->pkey_spec? add->pkey_spec : base->pkey_spec;
    nsc->renew_window = (add->renew_norm != DEF_VAL)? add->renew_norm : base->renew_norm;
    nsc->renew_window = (add->renew_window != DEF_VAL)? add->renew_window : base->renew_window;

    nsc->ca_url = add->ca_url? add->ca_url : base->ca_url;
    nsc->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    nsc->ca_agreement = add->ca_agreement? add->ca_agreement : base->ca_agreement;
    nsc->ca_challenges = (add->ca_challenges? apr_array_copy(pool, add->ca_challenges) 
                    : (base->ca_challenges? apr_array_copy(pool, base->ca_challenges) : NULL));
    nsc->current = NULL;
    nsc->assigned = NULL;
    
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
    return (inside_section(cmd, MD_CMD_MD_SECTION) || inside_section(cmd, MD_CMD_MD_OLD_SECTION));
}

static const char *md_section_check(cmd_parms *cmd) {
    if (!inside_md_section(cmd)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " is only valid inside a '",  
                           MD_CMD_MD_SECTION, "' context, not here", NULL);
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
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
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

    name = ap_getword_white(cmd->pool, &arg);
    domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
    add_domain_name(domains, name, cmd->pool);
    while (*arg != '\0') {
        name = ap_getword_white(cmd->pool, &arg);
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
    err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    if (err) {
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

static const char *md_config_set_ca(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if (!inside_md_section(cmd) && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    sc->ca_url = value;
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if (!inside_md_section(cmd) && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
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
    if (!inside_md_section(cmd) && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->ca_agreement = value;
    return NULL;
}

static const char *md_config_set_drive_mode(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    md_drive_mode_t drive_mode;

    (void)dc;
    if (!apr_strnatcasecmp("auto", value) || !apr_strnatcasecmp("automatic", value)) {
        drive_mode = MD_DRIVE_AUTO;
    }
    else if (!apr_strnatcasecmp("always", value)) {
        drive_mode = MD_DRIVE_ALWAYS;
    }
    else if (!apr_strnatcasecmp("manual", value) || !apr_strnatcasecmp("stick", value)) {
        drive_mode = MD_DRIVE_MANUAL;
    }
    else {
        return apr_pstrcat(cmd->pool, "unknown MDDriveMode ", value, NULL);
    }
    
    if (!inside_md_section(cmd) && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->drive_mode = drive_mode;
    return NULL;
}

static const char *md_config_set_must_staple(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if (!inside_md_section(cmd) && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    if (!apr_strnatcasecmp("off", value)) {
        config->must_staple = 0;
    }
    else if (!apr_strnatcasecmp("on", value)) {
        config->must_staple = 1;
    }
    else {
        return apr_pstrcat(cmd->pool, "unknown '", value, 
                           "', supported parameter values are 'on' and 'off'", NULL);
    }
    return NULL;
}

static const char *md_config_set_base_server(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    (void)dc;
    if (!err) {
        if (!apr_strnatcasecmp("off", value)) {
            config->mc->manage_base_server = 0;
        }
        else if (!apr_strnatcasecmp("on", value)) {
            config->mc->manage_base_server = 1;
        }
        else {
            err = apr_pstrcat(cmd->pool, "unknown '", value, 
                              "', supported parameter values are 'on' and 'off'", NULL);
        }
    }
    return err;
}

static const char *md_config_set_require_https(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    (void)dc;
    if (!inside_md_section(cmd) && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

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

static apr_status_t duration_parse(const char *value, apr_interval_time_t *ptimeout, 
                                   const char *def_unit)
{
    char *endp;
    long funits = 1;
    apr_status_t rv;
    apr_int64_t n;
    
    n = apr_strtoi64(value, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        if (strcmp(def_unit, "d") == 0) {
            def_unit = "s";
            funits = MD_SECS_PER_DAY;
        }
    }
    else if (endp == value) {
        return APR_EINVAL;
    }
    else if (*endp == 'd') {
        *ptimeout = apr_time_from_sec(n * MD_SECS_PER_DAY);
        return APR_SUCCESS;
    }
    else {
        def_unit = endp;
    }
    rv = ap_timeout_parameter_parse(value, ptimeout, def_unit);
    if (APR_SUCCESS == rv && funits > 1) {
        *ptimeout *= funits;
    }
    return rv;
}

static apr_status_t percentage_parse(const char *value, int *ppercent)
{
    char *endp;
    apr_int64_t n;
    
    n = apr_strtoi64(value, &endp, 10);
    if (errno) {
        return errno;
    }
    if (*endp == '%') {
        if (n < 0 || n >= 100) {
            return APR_BADARG;
        }
        *ppercent = (int)n;
        return APR_SUCCESS;
    }
    return APR_EINVAL;
}

static const char *md_config_set_renew_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    apr_interval_time_t timeout;
    int percent = 0;
    
    (void)dc;
    if (!inside_md_section(cmd)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }

    /* Inspired by http_core.c */
    if (duration_parse(value, &timeout, "d") == APR_SUCCESS) {
        config->renew_norm = 0;
        config->renew_window = timeout;
        return NULL;
    }
    else {
        switch (percentage_parse(value, &percent)) {
            case APR_SUCCESS:
                config->renew_norm = apr_time_from_sec(100 * MD_SECS_PER_DAY);
                config->renew_window = apr_time_from_sec(percent * MD_SECS_PER_DAY);
                return NULL;
            case APR_BADARG:
                return "MDRenewWindow as percent must be less than 100";
        }
    }
    return "MDRenewWindow has unrecognized format";
}

static const char *md_config_set_proxy(cmd_parms *cmd, void *arg, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
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
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }
    sc->mc->base_dir = value;
    (void)arg;
    return NULL;
}

static const char *set_port_map(md_mod_conf_t *mc, const char *value)
{
    int net_port, local_port;
    char *endp;

    net_port = (int)apr_strtoi64(value, &endp, 10);
    if (errno) {
        return "unable to parse first port number";
    }
    if (!endp || *endp != ':') {
        return "no ':' after first port number";
    }
    ++endp;
    if (*endp == '-') {
        local_port = 0;
    }
    else {
        local_port = (int)apr_strtoi64(endp, &endp, 10);
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
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    (void)arg;
    if (!err) {
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
    if (!inside_md_section(cmd)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    pcha = &config->ca_challenges; 
    
    ca_challenges = *pcha;
    if (!ca_challenges) {
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
    
    (void)dc;
    if (!inside_md_section(cmd)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    if (argc <= 0) {
        return "needs to specify the private key type";
    }
    
    ptype = argv[0];
    if (!apr_strnatcasecmp("Default", ptype)) {
        if (argc > 1) {
            return "type 'Default' takes no parameter";
        }
        if (!config->pkey_spec) {
            config->pkey_spec = apr_pcalloc(cmd->pool, sizeof(*config->pkey_spec));
        }
        config->pkey_spec->type = MD_PKEY_TYPE_DEFAULT;
        return NULL;
    }
    else if (!apr_strnatcasecmp("RSA", ptype)) {
        if (argc == 1) {
            bits = MD_PKEY_RSA_BITS_DEF;
        }
        else if (argc == 2) {
            bits = (int)apr_atoi64(argv[1]);
            if (bits < MD_PKEY_RSA_BITS_MIN || bits >= INT_MAX) {
                return apr_psprintf(cmd->pool, "must be %d or higher in order to be considered "
                "safe. Too large a value will slow down everything. Larger then 4096 probably does "
                "not make sense unless quantum cryptography really changes spin.", 
                MD_PKEY_RSA_BITS_MIN);
            }
        }
        else {
            return "key type 'RSA' has only one optional parameter, the number of bits";
        }

        if (!config->pkey_spec) {
            config->pkey_spec = apr_pcalloc(cmd->pool, sizeof(*config->pkey_spec));
        }
        config->pkey_spec->type = MD_PKEY_TYPE_RSA;
        config->pkey_spec->params.rsa.bits = (unsigned int)bits;
        return NULL;
    }
    return apr_pstrcat(cmd->pool, "unsupported private key type \"", ptype, "\"", NULL);
}

static const char *md_config_set_notify_cmd(cmd_parms *cmd, void *arg, const char *value)
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }
    sc->mc->notify_cmd = value;
    (void)arg;
    return NULL;
}

static const char *md_config_set_names_old(cmd_parms *cmd, void *dc, 
                                           int argc, char *const argv[])
{
    ap_log_error( APLOG_MARK, APLOG_WARNING, 0, cmd->server,  
                 "mod_md: directive 'ManagedDomain' is deprecated, replace with 'MDomain'.");
    return md_config_set_names(cmd, dc, argc, argv);
}

static const char *md_config_sec_start_old(cmd_parms *cmd, void *mconfig, const char *arg)
{
    ap_log_error( APLOG_MARK, APLOG_WARNING, 0, cmd->server,  
                 "mod_md: directive '<ManagedDomain' is deprecated, replace with '<MDomainSet'.");
    return md_config_sec_start(cmd, mconfig, arg);
}

const command_rec md_cmds[] = {
    AP_INIT_TAKE1(     MD_CMD_CA, md_config_set_ca, NULL, RSRC_CONF, 
                  "URL of CA issuing the certificates"),
    AP_INIT_TAKE1(     MD_CMD_CAAGREEMENT, md_config_set_agreement, NULL, RSRC_CONF, 
                  "URL of CA Terms-of-Service agreement you accept"),
    AP_INIT_TAKE_ARGV( MD_CMD_CACHALLENGES, md_config_set_cha_tyes, NULL, RSRC_CONF, 
                      "A list of challenge types to be used."),
    AP_INIT_TAKE1(     MD_CMD_CAPROTO, md_config_set_ca_proto, NULL, RSRC_CONF, 
                  "Protocol used to obtain/renew certificates"),
    AP_INIT_TAKE1(     MD_CMD_DRIVEMODE, md_config_set_drive_mode, NULL, RSRC_CONF, 
                  "method of obtaining certificates for the managed domain"),
    AP_INIT_TAKE_ARGV( MD_CMD_MD, md_config_set_names, NULL, RSRC_CONF, 
                      "A group of server names with one certificate"),
    AP_INIT_RAW_ARGS(  MD_CMD_MD_SECTION, md_config_sec_start, NULL, RSRC_CONF, 
                     "Container for a managed domain with common settings and certificate."),
    AP_INIT_TAKE_ARGV( MD_CMD_MEMBER, md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE_ARGV( MD_CMD_MEMBERS, md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE1(     MD_CMD_MUSTSTAPLE, md_config_set_must_staple, NULL, RSRC_CONF, 
                  "Enable/Disable the Must-Staple flag for new certificates."),
    AP_INIT_TAKE12(    MD_CMD_PORTMAP, md_config_set_port_map, NULL, RSRC_CONF, 
                  "Declare the mapped ports 80 and 443 on the local server. E.g. 80:8000 "
                  "to indicate that the server port 8000 is reachable as port 80 from the "
                  "internet. Use 80:- to indicate that port 80 is not reachable from "
                  "the outside."),
    AP_INIT_TAKE_ARGV( MD_CMD_PKEYS, md_config_set_pkeys, NULL, RSRC_CONF, 
                  "set the type and parameters for private key generation"),
    AP_INIT_TAKE1(     MD_CMD_PROXY, md_config_set_proxy, NULL, RSRC_CONF, 
                  "URL of a HTTP(S) proxy to use for outgoing connections"),
    AP_INIT_TAKE1(     MD_CMD_STOREDIR, md_config_set_store_dir, NULL, RSRC_CONF, 
                  "the directory for file system storage of managed domain data."),
    AP_INIT_TAKE1(     MD_CMD_RENEWWINDOW, md_config_set_renew_window, NULL, RSRC_CONF, 
                  "Time length for renewal before certificate expires (defaults to days)"),
    AP_INIT_TAKE1(     MD_CMD_REQUIREHTTPS, md_config_set_require_https, NULL, RSRC_CONF, 
                  "Redirect non-secure requests to the https: equivalent."),
    AP_INIT_TAKE1(     MD_CMD_NOTIFYCMD, md_config_set_notify_cmd, NULL, RSRC_CONF, 
                  "set the command to run when signup/renew of domain is complete."),
    AP_INIT_TAKE1(     MD_CMD_BASE_SERVER, md_config_set_base_server, NULL, RSRC_CONF, 
                  "allow managing of base server outside virtual hosts."),

/* This will disappear soon */
    AP_INIT_TAKE_ARGV( MD_CMD_OLD_MD, md_config_set_names_old, NULL, RSRC_CONF, 
                      "Deprecated, replace with 'MDomain'."),
    AP_INIT_RAW_ARGS(  MD_CMD_MD_OLD_SECTION, md_config_sec_start_old, NULL, RSRC_CONF, 
                     "Deprecated, replace with '<MDomainSet'."),
/* */

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
    
    return APR_SUCCESS;
}

static md_srv_conf_t *config_get_int(server_rec *s, apr_pool_t *p)
{
    md_srv_conf_t *sc = (md_srv_conf_t *)ap_get_module_config(s->module_config, &md_module);
    ap_assert(sc);
    if (sc->s != s && p) {
        sc = md_config_merge(p, &defconf, sc);
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
        case MD_CONFIG_CA_URL:
            return sc->ca_url? sc->ca_url : defconf.ca_url;
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
            return (sc->drive_mode != DEF_VAL)? sc->drive_mode : defconf.drive_mode;
        case MD_CONFIG_LOCAL_80:
            return sc->mc->local_80;
        case MD_CONFIG_LOCAL_443:
            return sc->mc->local_443;
        case MD_CONFIG_TRANSITIVE:
            return (sc->transitive != DEF_VAL)? sc->transitive : defconf.transitive;
        case MD_CONFIG_REQUIRE_HTTPS:
            return (sc->require_https != MD_REQUIRE_UNSET)? sc->require_https : defconf.require_https;
        case MD_CONFIG_MUST_STAPLE:
            return (sc->must_staple != DEF_VAL)? sc->must_staple : defconf.must_staple;
        default:
            return 0;
    }
}

apr_interval_time_t md_config_get_interval(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_RENEW_NORM:
            return (sc->renew_norm != DEF_VAL)? sc->renew_norm : defconf.renew_norm;
        case MD_CONFIG_RENEW_WINDOW:
            return (sc->renew_window != DEF_VAL)? sc->renew_window : defconf.renew_window;
        default:
            return 0;
    }
}
