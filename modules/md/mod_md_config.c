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


#define DEF_VAL     (-1)

static md_config_t defconf = {
    "default",
    NULL,
    80,
    443,
    NULL,
    MD_ACME_DEF_URL,
    "ACME",
    NULL, 
    NULL,
    MD_DRIVE_AUTO,
    apr_time_from_sec(14 * MD_SECS_PER_DAY),
    1,  
    NULL, 
    "md",
    NULL
};

#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

void *md_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    md_config_t *conf = (md_config_t *)apr_pcalloc(pool, sizeof(md_config_t));

    conf->name = apr_pstrcat(pool, "srv[", CONF_S_NAME(s), "]", NULL);
    conf->s = s;
    conf->local_80 = DEF_VAL;
    conf->local_443 = DEF_VAL;
    conf->drive_mode = DEF_VAL;
    conf->mds = apr_array_make(pool, 5, sizeof(const md_t *));
    conf->renew_window = DEF_VAL;
    conf->transitive = DEF_VAL;
    
    return conf;
}

static void *md_config_merge(apr_pool_t *pool, void *basev, void *addv)
{
    md_config_t *base = (md_config_t *)basev;
    md_config_t *add = (md_config_t *)addv;
    md_config_t *n = (md_config_t *)apr_pcalloc(pool, sizeof(md_config_t));
    char *name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);
    md_t *md;
    int i;
    
    n->name = name;
    n->local_80 = (add->local_80 != DEF_VAL)? add->local_80 : base->local_80;
    n->local_443 = (add->local_443 != DEF_VAL)? add->local_443 : base->local_443;

    /* I think we should not merge md definitions. They should reside where
     * they were defined */
    n->mds = apr_array_make(pool, add->mds->nelts, sizeof(const md_t *));
    for (i = 0; i < add->mds->nelts; ++i) {
        md = APR_ARRAY_IDX(add->mds, i, md_t*);
        APR_ARRAY_PUSH(n->mds, md_t *) = md_clone(pool, md);
    }
    n->ca_url = add->ca_url? add->ca_url : base->ca_url;
    n->ca_proto = add->ca_proto? add->ca_proto : base->ca_proto;
    n->ca_agreement = add->ca_agreement? add->ca_agreement : base->ca_agreement;
    n->drive_mode = (add->drive_mode != DEF_VAL)? add->drive_mode : base->drive_mode;
    n->md = NULL;
    n->base_dir = add->base_dir? add->base_dir : base->base_dir;
    n->renew_window = (add->renew_window != DEF_VAL)? add->renew_window : base->renew_window;
    n->ca_challenges = (add->ca_challenges? apr_array_copy(pool, add->ca_challenges) 
                    : (base->ca_challenges? apr_array_copy(pool, base->ca_challenges) : NULL));
    n->transitive = (add->transitive != DEF_VAL)? add->transitive : base->transitive;
    return n;
}

void *md_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    return md_config_merge(pool, basev, addv);
}

void *md_config_create_dir(apr_pool_t *pool, char *dummy)
{
    md_config_dir_t *conf = apr_pcalloc(pool, sizeof(*conf));
    return conf;
}

void *md_config_merge_dir(apr_pool_t *pool, void *basev, void *addv)
{
    md_config_dir_t *base = basev;
    md_config_dir_t *add = addv;
    md_config_dir_t *n = apr_pcalloc(pool, sizeof(*n));
    n->md = add->md? add->md : base->md;
    return n;
}

static int inside_section(cmd_parms *cmd) {
    return (cmd->directive->parent 
            && !ap_cstr_casecmp(cmd->directive->parent->directive, "<ManagedDomain"));
}

static const char *md_section_check(cmd_parms *cmd) {
    if (!inside_section(cmd)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, 
                           " is only valid inside a <ManagedDomain context, not ", 
                           cmd->directive->parent? cmd->directive->parent->directive : "root", 
                           NULL);
    }
    return NULL;
}

static void add_domain_name(apr_array_header_t *domains, const char *name, apr_pool_t *p)
{
    if (md_array_str_index(domains, name, 0, 0) < 0) {
        APR_ARRAY_PUSH(domains, char *) = md_util_str_tolower(apr_pstrdup(p, name));
    }
}

static const char *md_config_sec_start(cmd_parms *cmd, void *mconfig, const char *arg)
{
    md_config_t *sconf = ap_get_module_config(cmd->server->module_config, &md_module);
    const char *endp = ap_strrchr_c(arg, '>');
    ap_conf_vector_t *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    const char *err, *name;
    md_config_dir_t *dconf;
    md_t *md;

    if (NULL != (err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE))) {
        return err;
    }
        
    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, "> directive missing closing '>'", NULL);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp-arg);
    if (!arg || !*arg) {
        return "<ManagedDomain > block must specify a unique domain name";
    }

    cmd->path = ap_getword_white(cmd->pool, &arg);
    name = cmd->path;
    
    md = md_create_empty(cmd->pool);
    md->name = name;
    APR_ARRAY_PUSH(md->domains, const char*) = name;
    md->drive_mode = DEF_VAL;
    
    while (*arg != '\0') {
        name = ap_getword_white(cmd->pool, &arg);
        APR_ARRAY_PUSH(md->domains, const char*) = name;
    }

    dconf = ap_set_config_vectors(cmd->server, new_dir_conf, cmd->path, &md_module, cmd->pool);
    dconf->md = md;
    
    if (NULL == (err = ap_walk_config(cmd->directive->first_child, cmd, new_dir_conf))) {
        APR_ARRAY_PUSH(sconf->mds, const md_t *) = md;
    }
    
    cmd->path = old_path;
    cmd->override = old_overrides;

    return err;
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

static const char *md_config_sec_add_members(cmd_parms *cmd, void *dc, 
                                             int argc, char *const argv[])
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    md_config_dir_t *dconfig = dc;
    apr_array_header_t *domains;
    const char *err;
    int i;
    
    if (NULL != (err = md_section_check(cmd))) {
        if (argc == 1) {
            /* only allowed value outside a section */
            return set_transitive(&config->transitive, argv[0]);
        }
        return err;
    }
    
    domains = dconfig->md->domains;
    for (i = 0; i < argc; ++i) {
        if (NULL != set_transitive(&dconfig->md->transitive, argv[i])) {
            add_domain_name(domains, argv[i], cmd->pool);
        }
    }
    return NULL;
}

static const char *md_config_set_names(cmd_parms *cmd, void *arg, 
                                       int argc, char *const argv[])
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
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
    err = md_create(&md, cmd->pool, domains);
    if (err) {
        return err;
    }

    if (transitive >= 0) {
        md->transitive = transitive;
    }
    
    if (cmd->config_file) {
        md->defn_name = cmd->config_file->name;
        md->defn_line_number = cmd->config_file->line_number;
    }

    APR_ARRAY_PUSH(config->mds, md_t *) = md;

    return NULL;
}

static const char *md_config_set_ca(cmd_parms *cmd, void *dc, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    const char *err;

    if (inside_section(cmd)) {
        md_config_dir_t *dconf = dc;
        dconf->md->ca_url = value;
    }
    else {
        if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
            return err;
        }
        config->ca_url = value;
    }
    return NULL;
}

static const char *md_config_set_ca_proto(cmd_parms *cmd, void *dc, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    const char *err;

    if (inside_section(cmd)) {
        md_config_dir_t *dconf = dc;
        dconf->md->ca_proto = value;
    }
    else {
        if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
            return err;
        }
        config->ca_proto = value;
    }
    return NULL;
}

static const char *md_config_set_agreement(cmd_parms *cmd, void *dc, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    const char *err;

    if (inside_section(cmd)) {
        md_config_dir_t *dconf = dc;
        dconf->md->ca_agreement = value;
    }
    else {
        if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
            return err;
        }
        config->ca_agreement = value;
    }
    return NULL;
}

static const char *md_config_set_drive_mode(cmd_parms *cmd, void *dc, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
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
    
    if (inside_section(cmd)) {
        md_config_dir_t *dconf = dc;
        dconf->md->drive_mode = drive_mode;
    }
    else {
        if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
            return err;
        }
        config->drive_mode = drive_mode;
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
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    const char *err;
    apr_interval_time_t timeout;

    /* Inspired by http_core.c */
    if (duration_parse(value, &timeout, "d") != APR_SUCCESS) {
        return "MDRenewWindow has wrong format";
    }
        
    if (inside_section(cmd)) {
        md_config_dir_t *dconf = dc;
        dconf->md->renew_window = timeout;
    }
    else {
        if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
            return err;
        }
        config->renew_window = timeout;
    }
    return NULL;
}

static const char *md_config_set_store_dir(cmd_parms *cmd, void *arg, const char *value)
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }
    config->base_dir = value;
    (void)arg;
    return NULL;
}

static const char *set_port_map(md_config_t *config, const char *value)
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
            config->local_80 = local_port;
            break;
        case 443:
            config->local_443 = local_port;
            break;
        default:
            return "mapped port number must be 80 or 443";
    }
    return NULL;
}

static const char *md_config_set_port_map(cmd_parms *cmd, void *arg, 
                                          const char *v1, const char *v2)
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    (void)arg;
    if (!err) {
        err = set_port_map(config, v1);
    }
    if (!err && v2) {
        err = set_port_map(config, v2);
    }
    return err;
}

static const char *md_config_set_cha_tyes(cmd_parms *cmd, void *dc, 
                                          int argc, char *const argv[])
{
    md_config_t *config = (md_config_t *)md_config_get(cmd->server);
    apr_array_header_t **pcha, *ca_challenges;
    const char *err;
    int i;

    if (inside_section(cmd)) {
        md_config_dir_t *dconf = dc;
        pcha = &dconf->md->ca_challenges;
    }
    else {
        if (NULL != (err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
            return err;
        }
        pcha = &config->ca_challenges; 
    }
    
    ca_challenges = *pcha;
    if (!ca_challenges) {
        *pcha = ca_challenges = apr_array_make(cmd->pool, 5, sizeof(const char *));
    }
    for (i = 0; i < argc; ++i) {
        APR_ARRAY_PUSH(ca_challenges, const char *) = argv[i];
    }
    
    return NULL;
}


#define AP_END_CMD     AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)

const command_rec md_cmds[] = {
    AP_INIT_RAW_ARGS("<ManagedDomain", md_config_sec_start, NULL, RSRC_CONF, 
                      "Container for a manged domain with common settings and certificate."),
    AP_INIT_TAKE_ARGV("MDMember", md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE_ARGV("MDMembers", md_config_sec_add_members, NULL, RSRC_CONF, 
                      "Define domain name(s) part of the Managed Domain. Use 'auto' or "
                      "'manual' to enable/disable auto adding names from virtual hosts."),
    AP_INIT_TAKE_ARGV("ManagedDomain", md_config_set_names, NULL, RSRC_CONF, 
                      "A group of server names with one certificate"),
    AP_INIT_TAKE1("MDCertificateAuthority", md_config_set_ca, NULL, RSRC_CONF, 
                  "URL of CA issueing the certificates"),
    AP_INIT_TAKE1("MDStoreDir", md_config_set_store_dir, NULL, RSRC_CONF, 
                  "the directory for file system storage of managed domain data."),
    AP_INIT_TAKE1("MDCertificateProtocol", md_config_set_ca_proto, NULL, RSRC_CONF, 
                  "Protocol used to obtain/renew certificates"),
    AP_INIT_TAKE1("MDCertificateAgreement", md_config_set_agreement, NULL, RSRC_CONF, 
                  "URL of CA Terms-of-Service agreement you accept"),
    AP_INIT_TAKE1("MDDriveMode", md_config_set_drive_mode, NULL, RSRC_CONF, 
                  "method of obtaining certificates for the managed domain"),
    AP_INIT_TAKE1("MDRenewWindow", md_config_set_renew_window, NULL, RSRC_CONF, 
                  "Time length for renewal before certificate expires (defaults to days)"),
    AP_INIT_TAKE12("MDPortMap", md_config_set_port_map, NULL, RSRC_CONF, 
                  "Declare the mapped ports 80 and 443 on the local server. E.g. 80:8000 "
                  "to indicate that the server port 8000 is reachable as port 80 from the "
                  "internet. Use 80:- to indicate that port 80 is not reachable from "
                  "the outside."),
    AP_INIT_TAKE_ARGV("MDCAChallenges", md_config_set_cha_tyes, NULL, RSRC_CONF, 
                      "A list of challenge types to be used."),
    AP_END_CMD
};


static const md_config_t *config_get_int(server_rec *s, apr_pool_t *p)
{
    md_config_t *cfg = (md_config_t *)ap_get_module_config(s->module_config, &md_module);
    ap_assert(cfg);
    if (cfg->s != s && p) {
        cfg = md_config_merge(p, &defconf, cfg);
        cfg->name = apr_pstrcat(p, CONF_S_NAME(s), cfg->name, NULL);
        ap_set_module_config(s->module_config, &md_module, cfg);
    }
    return cfg;
}

const md_config_t *md_config_get(server_rec *s)
{
    return config_get_int(s, NULL);
}

const md_config_t *md_config_get_unique(server_rec *s, apr_pool_t *p)
{
    assert(p);
    return config_get_int(s, p);
}

const md_config_t *md_config_cget(conn_rec *c)
{
    return md_config_get(c->base_server);
}

const char *md_config_gets(const md_config_t *config, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_CA_URL:
            return config->ca_url? config->ca_url : defconf.ca_url;
        case MD_CONFIG_CA_PROTO:
            return config->ca_proto? config->ca_proto : defconf.ca_proto;
        case MD_CONFIG_BASE_DIR:
            return config->base_dir? config->base_dir : defconf.base_dir;
        case MD_CONFIG_CA_AGREEMENT:
            return config->ca_agreement? config->ca_agreement : defconf.ca_agreement;
        default:
            return NULL;
    }
}

int md_config_geti(const md_config_t *config, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_DRIVE_MODE:
            return (config->drive_mode != DEF_VAL)? config->drive_mode : defconf.drive_mode;
        case MD_CONFIG_LOCAL_80:
            return (config->local_80 != DEF_VAL)? config->local_80 : 80;
        case MD_CONFIG_LOCAL_443:
            return (config->local_443 != DEF_VAL)? config->local_443 : 443;
        case MD_CONFIG_TRANSITIVE:
            return (config->transitive != DEF_VAL)? config->transitive : defconf.transitive;
        default:
            return 0;
    }
}

apr_interval_time_t md_config_get_interval(const md_config_t *config, md_config_var_t var)
{
    switch (var) {
        case MD_CONFIG_RENEW_WINDOW:
            return (config->renew_window != DEF_VAL)? config->renew_window : defconf.renew_window;
        default:
            return 0;
    }
}
