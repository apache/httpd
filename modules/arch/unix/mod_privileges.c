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

#include <priv.h>
#include <sys/types.h>
#include <unistd.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "apr_strings.h"

/* TODO - get rid of unixd dependency */
#include "unixd.h"

#define CFG_CHECK(x) if (x == -1) return strerror(errno);
#define CR_CHECK(x) if (x == -1) \
    ap_log_error(APLOG_MARK, APLOG_CRIT,0,0, \
                 "Failed to initialise privileges: %s", strerror(errno))

module AP_MODULE_DECLARE_DATA privileges_module;

/* #define BIG_SECURITY_HOLE 1 */

typedef struct {
    priv_set_t *priv;
    priv_set_t *child_priv;
    uid_t uid;
    gid_t gid;
} priv_cfg;

static priv_set_t *priv_setid;
static priv_set_t *priv_default = NULL;
static int dtrace_enabled = 0;

static apr_status_t priv_cfg_cleanup(void *CFG)
{
    priv_cfg *cfg = CFG;
    priv_freeset(cfg->priv);
    priv_freeset(cfg->child_priv);
    return APR_SUCCESS;
}
static void *privileges_create_cfg(apr_pool_t *pool, server_rec *s)
{
    priv_cfg *cfg = apr_palloc(pool, sizeof(priv_cfg));

    /* Start at basic privileges all round. */
    cfg->priv = priv_str_to_set("basic", ",", NULL);
    cfg->child_priv = priv_str_to_set("basic", ",", NULL);

    /* By default, run in secure mode.
     * That means dropping basic privileges we don't usually need.
     */
    CR_CHECK(priv_delset(cfg->priv, PRIV_FILE_LINK_ANY));
    CR_CHECK(priv_delset(cfg->priv, PRIV_PROC_INFO));
    CR_CHECK(priv_delset(cfg->priv, PRIV_PROC_SESSION));

/* Hmmm, should CGI default to secure too ? */
/*
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_FILE_LINK_ANY));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_INFO));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_SESSION));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_FORK));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_EXEC));
*/

    /* we´ll use 0 for unset */
    cfg->uid = 0;
    cfg->gid = 0;
    apr_pool_cleanup_register(pool, cfg, priv_cfg_cleanup,
                              apr_pool_cleanup_null);

    /* top-level default_priv wants the top-level cfg */
    if (priv_default == NULL) {
        priv_default = cfg->priv;
    }
    return cfg;
}

static apr_status_t privileges_end_req(void *data)
{
    request_rec *r = data;
    priv_cfg *cfg = ap_get_module_config(r->server->module_config,
                                         &privileges_module);

    /* ugly hack: grab default uid and gid from unixd */
    extern unixd_config_rec ap_unixd_config;

    /* if either user or group are not the default, restore them */
    if (cfg->uid || cfg->gid) {
        if (setppriv(PRIV_ON, PRIV_EFFECTIVE, priv_setid) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "PRIV_ON failed restoring default user/group");
        }
        if (cfg->uid && (setuid(ap_unixd_config.user_id) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error restoring default userid");
        }
        if (cfg->gid && (setgid(ap_unixd_config.group_id) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error restoring default group");
        }
    }

    /* restore default privileges */
    if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_default) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error restoring default privileges: %s", strerror(errno));
    }
    return APR_SUCCESS;
}
static int privileges_req(request_rec *r)
{
    priv_cfg *cfg = ap_get_module_config(r->server->module_config,
                                         &privileges_module);

    /* cleanup should happen even if something fails part-way through here */
    apr_pool_cleanup_register(r->pool, r, privileges_end_req,
                              apr_pool_cleanup_null);

    /* set user and group if configured */
    if (cfg->uid || cfg->gid) {
        if (setppriv(PRIV_ON, PRIV_EFFECTIVE, priv_setid) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "No privilege to set user/group");
        }
        /* if we should be able to set these but can't, it could be
         * a serious security issue.  Bail out rather than risk it!
         */
        if (cfg->uid && (setuid(cfg->uid) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error setting userid");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (cfg->gid && (setgid(cfg->gid) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Error setting group");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    /* set vhost's privileges */
    if (setppriv(PRIV_SET, PRIV_EFFECTIVE, cfg->priv) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error setting effective privileges: %s", strerror(errno));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ... including those of any subprocesses */
    if (setppriv(PRIV_SET, PRIV_INHERITABLE, cfg->child_priv) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error setting inheritable privileges: %s", strerror(errno));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (setppriv(PRIV_SET, PRIV_LIMIT, cfg->child_priv) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error setting limit privileges: %s", strerror(errno));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}
#define PDROP_CHECK(x) if (x == -1) { \
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, \
                     "Error dropping privileges: %s", strerror(errno)); \
        return !OK; \
    }

static int privileges_drop_first(apr_pool_t *pool, server_rec *s)
{
    /* We need to set privileges before mod_unixd,
     * 'cos otherwise setuid will wipe our privilege to do so
     */
    priv_cfg *spcfg;
    server_rec *sp;
    priv_set_t *ppriv = priv_allocset();

    /* compute ppriv from the union of all the vhosts plus setid */
    priv_copyset(priv_setid, ppriv);
    for (sp = s; sp != NULL; sp=sp->next) {
        spcfg = ap_get_module_config(sp->module_config, &privileges_module);
        priv_union(spcfg->priv, ppriv);
    }
    PDROP_CHECK(setppriv(PRIV_SET, PRIV_PERMITTED, ppriv))
    PDROP_CHECK(setppriv(PRIV_SET, PRIV_EFFECTIVE, ppriv))
    priv_freeset(ppriv);

    return OK;
}
static int privileges_drop_last(apr_pool_t *pool, server_rec *s)
{
    /* Our config stuff has set the privileges we need, so now
     * we just set them to those of the parent server_rec
     *
     * This has to happen after mod_unixd, 'cos mod_unixd needs
     * privileges we drop here.
     */
    priv_cfg *cfg = ap_get_module_config(s->module_config, &privileges_module);

    /* defaults - the default vhost */
    PDROP_CHECK(setppriv(PRIV_SET, PRIV_LIMIT, cfg->child_priv))
    PDROP_CHECK(setppriv(PRIV_SET, PRIV_INHERITABLE, cfg->child_priv))
    PDROP_CHECK(setppriv(PRIV_SET, PRIV_EFFECTIVE, cfg->priv))

    return OK;
}
static apr_status_t privileges_term(void *rec)
{
    priv_freeset(priv_setid);
    return APR_SUCCESS;
}
static int privileges_postconf(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    priv_cfg *cfg;
    server_rec *sp;

    /* if we have dtrace enabled, merge it into everything */
    if (dtrace_enabled) {
        for (sp = s; sp != NULL; sp = sp->next) {
            cfg = ap_get_module_config(sp->module_config, &privileges_module);
            CR_CHECK(priv_addset(cfg->priv, PRIV_DTRACE_KERNEL));
            CR_CHECK(priv_addset(cfg->priv, PRIV_DTRACE_PROC));
            CR_CHECK(priv_addset(cfg->priv, PRIV_DTRACE_USER));
            CR_CHECK(priv_addset(cfg->child_priv, PRIV_DTRACE_KERNEL));
            CR_CHECK(priv_addset(cfg->child_priv, PRIV_DTRACE_PROC));
            CR_CHECK(priv_addset(cfg->child_priv, PRIV_DTRACE_USER));
        }
        CR_CHECK(priv_addset(priv_default, PRIV_DTRACE_KERNEL));
        CR_CHECK(priv_addset(priv_default, PRIV_DTRACE_PROC));
        CR_CHECK(priv_addset(priv_default, PRIV_DTRACE_USER));
    }

    /* set up priv_setid for per-request use */
    priv_setid = priv_allocset();
    apr_pool_cleanup_register(pconf, NULL, privileges_term,
                              apr_pool_cleanup_null);
    priv_emptyset(priv_setid);
    if (priv_addset(priv_setid, PRIV_PROC_SETID) == -1) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, ptemp,
                      "priv_addset: %s", strerror(errno));
        return !OK;
    }
    return OK;
}
static int privileges_init(apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp)
{
    /* refuse to work if the MPM is threaded */
    int threaded;
    int rv = ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, rv, ptemp,
                      "mod_privileges: unable to determine MPM characteristics."
                      "  Please ensure you are using a non-threaded MPM "
                      "with this module.");
    }
    if (threaded) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, ptemp,
                      "mod_privileges is not compatible with a threaded MPM.");
        return !OK;
    }
    return OK;
}
static void privileges_hooks(apr_pool_t *pool)
{
    ap_hook_post_read_request(privileges_req, NULL, NULL,
                              APR_HOOK_REALLY_FIRST);
    ap_hook_drop_privileges(privileges_drop_first, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_drop_privileges(privileges_drop_last, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(privileges_postconf, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(privileges_init, NULL, NULL, APR_HOOK_FIRST);
}

static const char *vhost_user(cmd_parms *cmd, void *dir, const char *arg)
{
    priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                         &privileges_module);
    cfg->uid = ap_uname2id(arg);
    if (cfg->uid == 0) {
        return apr_pstrcat(cmd->pool, "Invalid userid for VHostUser: ",
                           arg, NULL);
    }
    return NULL;
}
static const char *vhost_group(cmd_parms *cmd, void *dir, const char *arg)
{
    priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                         &privileges_module);
    cfg->gid = ap_gname2id(arg);
    if (cfg->uid == 0) {
        return apr_pstrcat(cmd->pool, "Invalid groupid for VHostGroup: ",
                           arg, NULL);
    }
    return NULL;
}
static const char *vhost_secure(cmd_parms *cmd, void *dir, int arg)
{
    priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                         &privileges_module);
    if (!arg) {
        /* add basic privileges, excluding those covered by cgimode */
        CFG_CHECK(priv_addset(cfg->priv, PRIV_FILE_LINK_ANY));
        CFG_CHECK(priv_addset(cfg->priv, PRIV_PROC_INFO));
        CFG_CHECK(priv_addset(cfg->priv, PRIV_PROC_SESSION));
    }
    return NULL;
}
static const char *vhost_cgimode(cmd_parms *cmd, void *dir, const char *arg)
{
    priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                         &privileges_module);
    if (!strcasecmp(arg, "on")) {
        /* default - nothing to do */
    }
    else if (!strcasecmp(arg, "off")) {
        /* drop fork+exec privs */
        CFG_CHECK(priv_delset(cfg->priv, PRIV_PROC_FORK));
        CFG_CHECK(priv_delset(cfg->priv, PRIV_PROC_EXEC));
    }
    else if (!strcasecmp(arg, "secure")) {
        /* deny privileges to CGI procs */
        CFG_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_FORK));
        CFG_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_EXEC));
        CFG_CHECK(priv_delset(cfg->child_priv, PRIV_FILE_LINK_ANY));
        CFG_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_INFO));
        CFG_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_SESSION));
    }
    else {
        return "VHostCGIMode must be On, Off or Secure";
    }

    return NULL;
}
static const char *dtraceenable(cmd_parms *cmd, void *dir, int arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    dtrace_enabled = arg;
    return NULL;
}

#ifdef BIG_SECURITY_HOLE
static const char *vhost_privs(cmd_parms *cmd, void *dir, const char *arg)
{
    priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                         &privileges_module);
    const char *priv = arg;

    if (*priv == '-') {
        CFG_CHECK(priv_delset(cfg->priv, priv+1));
    }
    else if (*priv == '+') {
        CFG_CHECK(priv_addset(cfg->priv, priv+1));
    }
    else {
        priv_emptyset(cfg->priv);
        CFG_CHECK(priv_addset(cfg->priv, priv));
    }
    return NULL;
}
static const char *vhost_cgiprivs(cmd_parms *cmd, void *dir, const char *arg)
{
    priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                         &privileges_module);
    const char *priv = arg;
    if (*priv == '-') {
        CFG_CHECK(priv_delset(cfg->child_priv, priv+1));
    }
    else if (*priv == '+') {
        CFG_CHECK(priv_addset(cfg->child_priv, priv+1));
    }
    else {
        priv_emptyset(cfg->child_priv);
        CFG_CHECK(priv_addset(cfg->child_priv, priv));
    }
    return NULL;
}
#endif

static const command_rec privileges_cmds[] = {
    AP_INIT_TAKE1("VHostUser", vhost_user, NULL, RSRC_CONF,
                  "Userid under which the virtualhost will run"),
    AP_INIT_TAKE1("VHostGroup", vhost_group, NULL, RSRC_CONF,
                  "Group under which the virtualhost will run"),
    AP_INIT_FLAG("VHostSecure", vhost_secure, NULL, RSRC_CONF,
                 "Run in secure mode (default ON)"),
    AP_INIT_TAKE1("VHostCGIMode", vhost_cgimode, NULL, RSRC_CONF,
                  "Enable fork+exec for this virtualhost (Off|Secure|On)"),
    AP_INIT_FLAG("DTracePrivileges", dtraceenable, NULL, RSRC_CONF,
                 "Enable DTrace"),
#ifdef BIG_SECURITY_HOLE
    AP_INIT_ITERATE("VHostPrivs", vhost_privs, NULL, RSRC_CONF,
                    "Privileges available in the (virtual) server"),
    AP_INIT_ITERATE("VHostCGIPrivs", vhost_cgiprivs, NULL, RSRC_CONF,
                    "Privileges available to external programs"),
#endif
    {NULL}
};
module AP_MODULE_DECLARE_DATA privileges_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    privileges_create_cfg,
    NULL,
    privileges_cmds,
    privileges_hooks
};
