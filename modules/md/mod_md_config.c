/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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

#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_vhost.h>

#include "md.h"
#include "md_util.h"
#include "mod_md_private.h"
#include "mod_md_config.h"

#define MD_CMD_MD             "ManagedDomain"
#define MD_CMD_MD_SECTION     "<ManagedDomain"
#define MD_CMD_CA             "MDCertificateAuthority"
#define MD_CMD_CAAGREEMENT    "MDCertificateAgreement"
#define MD_CMD_CACHALLENGES   "MDCAChallenges"
#define MD_CMD_CAPROTO        "MDCertificateProtocol"
#define MD_CMD_DRIVEMODE      "MDDriveMode"
#define MD_CMD_MEMBER         "MDMember"
#define MD_CMD_MEMBERS        "MDMembers"
#define MD_CMD_PORTMAP        "MDPortMap"
#define MD_CMD_RENEWWINDOW    "MDRenewWindow"
#define MD_CMD_STOREDIR       "MDStoreDir"

#define DEF_VAL     (-1)

/* Default settings for the global conf */
static md_mod_conf_t defmc = {
    NULL,
    "md",
    NULL,
    80,
    443,
    0,
    0,
    NULL
};

/* Default server specific setting */
static md_srv_conf_t defconf = {
    "default",
    NULL,
    &defmc,

    1,
    MD_DRIVE_AUTO,
    0,
    apr_time_from_sec(14 * MD_SECS_PER_DAY),

    MD_ACME_DEF_URL,
    "ACME",
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
    sc->drive_mode = DEF_VAL;
    sc->must_staple = DEF_VAL;
    sc->renew_window = DEF_VAL;
    sc->ca_url = NULL;
    sc->ca_proto = NULL;
    sc->ca_agreement = NULL;
    sc->ca_challenges = NULL;
}

static void srv_conf_props_copy(md_srv_conf_t *to, const md_srv_conf_t *from)
{
    to->transitive = from->transitive;
    to->drive_mode = from->drive_mode;
    to->must_staple = from->must_staple;
    to->renew_window = from->renew_window;
    to->ca_url = from->ca_url;
    to->ca_proto = from->ca_proto;
    to->ca_agreement = from->ca_agreement;
    to->ca_challenges = from->ca_challenges;
}

static void srv_conf_props_apply(md_t *md, const md_srv_conf_t *from, apr_pool_t *p)
{
    if (from->transitive != DEF_VAL) md->transitive = from->transitive;
    if (from->drive_mode != DEF_VAL) md->drive_mode = from->drive_mode;
    if (from->must_staple != DEF_VAL) md->must_staple = from->must_staple;
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
    conf->md = apr_pcalloc(pool, sizeof(*conf->md));

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

    nsc->transitive = (add->transitive != DEF_VAL)? add->transitive : base->transitive;
    nsc->drive_mode = (add->drive_mode != DEF_VAL)? add->drive_mode : base->drive_mode;
    nsc->md = NULL;
    nsc->renew_window = (add->renew_window != DEF_VAL)? add->renew_window : base->renew_window;

    nsc->ca_url = add->ca_url? add->ca_url : base->ca_url;
    nsc->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    nsc->ca_agreement = add->ca_agreement? add->ca_agreement : base->ca_agreement;
    nsc->ca_challenges = (add->ca_challenges? apr_array_copy(pool, add->ca_challenges) 
                    : (base->ca_challenges? apr_array_copy(pool, base->ca_challenges) : NULL));
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

static const char *md_section_check(cmd_parms *cmd, const char *section) {
    if (!inside_section(cmd, section)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, " is only valid inside a '", 
                           section, "' context, not here", NULL);
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

    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
        
    sc = md_config_get(cmd->server);
    endp = ap_strrchr_c(arg, '>');
    if (endp == NULL) {
        return  MD_CMD_MD_SECTION "> directive missing closing '>'";
    }

    arg = apr_pstrndup(cmd->pool, arg, endp-arg);
    if (!arg || !*arg) {
        return MD_CMD_MD_SECTION " > section must specify a unique domain name";
    }

    name = ap_getword_white(cmd->pool, &arg);
    domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
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
    sc->md = md;
    
    if (NULL == (err = ap_walk_config(cmd->directive->first_child, cmd, cmd->context))) {
        srv_conf_props_apply(md, sc, cmd->pool);
        APR_ARRAY_PUSH(sc->mc->mds, const md_t *) = md;
    }
    
    sc->md = NULL;
    srv_conf_props_copy(sc, &save);
    
    return err;
}

static const char *md_config_sec_add_members(cmd_parms *cmd, void *dc, 
                                             int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    const char *err;
    int i;
    
    if (NULL != (err = md_section_check(cmd, MD_CMD_MD_SECTION))) {
        if (argc == 1) {
            /* only these values are allowed outside a section */
            return set_transitive(&sc->transitive, argv[0]);
        }
        return err;
    }
    
    assert(sc->md);
    for (i = 0; i < argc; ++i) {
        if (NULL != set_transitive(&sc->transitive, argv[i])) {
            add_domain_name(sc->md->domains, argv[i], cmd->pool);
        }
    }
    return NULL;
}

static const char *md_config_set_names(cmd_parms *cmd, void *arg, 
                                       int argc, char *const argv[])
{
    md_srv_conf_t *sc = md_config_get(cmd->server);
    apr_array_header_t *domains = apr_array_make(cmd->pool, 5, sizeof(const char *));
    const char *err;
    md_t *md;
    int i, transitive = -1;

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

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    sc->ca_url = value;
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->ca_proto = value;
    return NULL;
}

static const char *md_config_set_agreement(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
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
    
    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->drive_mode = drive_mode;
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

static const char *md_config_set_renew_window(cmd_parms *cmd, void *dc, const char *value)
{
    md_srv_conf_t *config = md_config_get(cmd->server);
    const char *err;
    apr_interval_time_t timeout;

    /* Inspired by http_core.c */
    if (duration_parse(value, &timeout, "d") != APR_SUCCESS) {
        return "MDRenewWindow has wrong format";
    }
        
    if (!inside_section(cmd, MD_CMD_MD_SECTION)
        && (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    config->renew_window = timeout;
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

    if (!inside_section(cmd, MD_CMD_MD_SECTION)
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


const command_rec md_cmds[] = {
    AP_INIT_TAKE1(     MD_CMD_CA, md_config_set_ca, NULL, RSRC_CONF, 
                  "URL of CA issueing the certificates"),
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
                     "Container for a manged domain with common settings and certificate."),
    AP_INIT_TAKE_ARGV( MD_CMD_MEMBER, md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE_ARGV( MD_CMD_MEMBERS, md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE12(    MD_CMD_PORTMAP, md_config_set_port_map, NULL, RSRC_CONF, 
                  "Declare the mapped ports 80 and 443 on the local server. E.g. 80:8000 "
                  "to indicate that the server port 8000 is reachable as port 80 from the "
                  "internet. Use 80:- to indicate that port 80 is not reachable from "
                  "the outside."),
    AP_INIT_TAKE1(     MD_CMD_STOREDIR, md_config_set_store_dir, NULL, RSRC_CONF, 
                  "the directory for file system storage of managed domain data."),
    AP_INIT_TAKE1(     MD_CMD_RENEWWINDOW, md_config_set_renew_window, NULL, RSRC_CONF, 
                  "Time length for renewal before certificate expires (defaults to days)"),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};


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
        case MD_CONFIG_CA_AGREEMENT:
            return sc->ca_agreement? sc->ca_agreement : defconf.ca_agreement;
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
        default:
            return 0;
    }
}

apr_interval_time_t md_config_get_interval(const md_srv_conf_t *sc, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_RENEW_WINDOW:
            return (sc->renew_window != DEF_VAL)? sc->renew_window : defconf.renew_window;
        default:
            return 0;
    }
}
