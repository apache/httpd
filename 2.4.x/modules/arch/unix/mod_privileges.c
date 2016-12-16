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

#define CFG_CHECK(x) if ((x) == -1) { \
    char msgbuf[128]; \
    apr_strerror(errno, msgbuf, sizeof(msgbuf)); \
    return apr_pstrdup(cmd->pool, msgbuf); \
}
#define CR_CHECK(x, y) if (x == -1) \
    ap_log_error(APLOG_MARK, APLOG_CRIT, errno, 0, y \
                 "Failed to initialise privileges")

module AP_MODULE_DECLARE_DATA privileges_module;

/* #define BIG_SECURITY_HOLE 1 */

typedef enum { PRIV_UNSET, PRIV_FAST, PRIV_SECURE, PRIV_SELECTIVE } priv_mode;

typedef struct {
    priv_set_t *priv;
    priv_set_t *child_priv;
    uid_t uid;
    gid_t gid;
    priv_mode mode;
} priv_cfg;

typedef struct {
    priv_mode mode;
} priv_dir_cfg;

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
static void *privileges_merge_cfg(apr_pool_t *pool, void *BASE, void *ADD)
{
    /* inherit the mode if it's not set; the rest won't be inherited */
    priv_cfg *base = BASE;
    priv_cfg *add = ADD;
    priv_cfg *ret = apr_pmemdup(pool, add, sizeof(priv_cfg));
    ret->mode = (add->mode == PRIV_UNSET) ? base->mode : add->mode;
    return ret;
}
static void *privileges_create_cfg(apr_pool_t *pool, server_rec *s)
{
    priv_cfg *cfg = apr_palloc(pool, sizeof(priv_cfg));

    /* Start at basic privileges all round. */
    cfg->priv = priv_str_to_set("basic", ",", NULL);
    cfg->child_priv = priv_str_to_set("basic", ",", NULL);

    /* By default, run in secure vhost mode.
     * That means dropping basic privileges we don't usually need.
     */
    CR_CHECK(priv_delset(cfg->priv, PRIV_FILE_LINK_ANY), APLOGNO(03160));
    CR_CHECK(priv_delset(cfg->priv, PRIV_PROC_INFO), APLOGNO(03161));
    CR_CHECK(priv_delset(cfg->priv, PRIV_PROC_SESSION), APLOGNO(03162));

/* Hmmm, should CGI default to secure too ? */
/*
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_FILE_LINK_ANY), APLOGNO(03163));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_INFO), APLOGNO(03164));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_SESSION), APLOGNO(03165));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_FORK), APLOGNO(03166));
    CR_CHECK(priv_delset(cfg->child_priv, PRIV_PROC_EXEC), APLOGNO(03167));
*/

    /* we´ll use 0 for unset */
    cfg->uid = 0;
    cfg->gid = 0;
    cfg->mode = PRIV_UNSET;
    apr_pool_cleanup_register(pool, cfg, priv_cfg_cleanup,
                              apr_pool_cleanup_null);

    /* top-level default_priv wants the top-level cfg */
    if (priv_default == NULL) {
        priv_default = cfg->priv;
    }
    return cfg;
}
static void *privileges_create_dir_cfg(apr_pool_t *pool, char *dummy)
{
    priv_dir_cfg *cfg = apr_palloc(pool, sizeof(priv_dir_cfg));
    cfg->mode = PRIV_UNSET;
    return cfg;
}
static void *privileges_merge_dir_cfg(apr_pool_t *pool, void *BASE, void *ADD)
{
    priv_dir_cfg *base = BASE;
    priv_dir_cfg *add = ADD;
    priv_dir_cfg *ret = apr_palloc(pool, sizeof(priv_dir_cfg));
    ret->mode = (add->mode == PRIV_UNSET) ? base->mode : add->mode;
    return ret;
}

static apr_status_t privileges_end_req(void *data)
{
    request_rec *r = data;
    priv_cfg *cfg = ap_get_module_config(r->server->module_config,
                                         &privileges_module);
    priv_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                              &privileges_module);

    /* ugly hack: grab default uid and gid from unixd */
    extern unixd_config_rec ap_unixd_config;

    /* If we forked a child, we dropped privilege to revert, so
     * all we can do now is exit
     */
    if ((cfg->mode == PRIV_SECURE) ||
        ((cfg->mode == PRIV_SELECTIVE) && (dcfg->mode == PRIV_SECURE))) {
        exit(0);
    }

    /* if either user or group are not the default, restore them */
    if (cfg->uid || cfg->gid) {
        if (setppriv(PRIV_ON, PRIV_EFFECTIVE, priv_setid) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02136)
                          "PRIV_ON failed restoring default user/group");
        }
        if (cfg->uid && (setuid(ap_unixd_config.user_id) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02137)
                          "Error restoring default userid");
        }
        if (cfg->gid && (setgid(ap_unixd_config.group_id) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02138)
                          "Error restoring default group");
        }
    }

    /* restore default privileges */
    if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_default) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, APLOGNO(02139)
                      "Error restoring default privileges");
    }
    return APR_SUCCESS;
}
static int privileges_req(request_rec *r)
{
    /* secure mode: fork a process to handle the request */
    apr_proc_t proc;
    apr_status_t rv;
    int exitcode;
    apr_exit_why_e exitwhy;
    int fork_req;
    priv_cfg *cfg = ap_get_module_config(r->server->module_config,
                                         &privileges_module);

    void *breadcrumb = ap_get_module_config(r->request_config,
                                            &privileges_module);

    if (!breadcrumb) {
        /* first call: this is the vhost */
        fork_req = (cfg->mode == PRIV_SECURE);

        /* set breadcrumb */
        ap_set_module_config(r->request_config, &privileges_module, &cfg->mode);

        /* If we have per-dir config, defer doing anything */
        if ((cfg->mode == PRIV_SELECTIVE)) {
            /* Defer dropping privileges 'til we have a directory
             * context that'll tell us whether to fork.
             */
            return DECLINED;
        }
    }
    else {
        /* second call is for per-directory. */
        priv_dir_cfg *dcfg;
        if ((cfg->mode != PRIV_SELECTIVE)) {
            /* Our fate was already determined for the vhost -
             * nothing to do per-directory
             */
            return DECLINED;
        }
        dcfg = ap_get_module_config(r->per_dir_config, &privileges_module);
        fork_req = (dcfg->mode == PRIV_SECURE);
    }

    if (fork_req) {
       rv = apr_proc_fork(&proc, r->pool);
        switch (rv) {
        case APR_INPARENT:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02140)
                          "parent waiting for child");
            /* FIXME - does the child need to run synchronously?
             * esp. if we enable mod_privileges with threaded MPMs?
             * We do need at least to ensure r outlives the child.
             */
            rv = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02141) "parent: child %s",
                          (rv == APR_CHILD_DONE) ? "done" : "notdone");

            /* The child has taken responsibility for reading all input
             * and sending all output.  So we need to bow right out,
             * and even abandon "normal" housekeeping.
             */
            r->eos_sent = 1;
            apr_table_unset(r->headers_in, "Content-Type");
            apr_table_unset(r->headers_in, "Content-Length");
            /* Testing with ab and 100k requests reveals no nasties
             * so I infer we're not leaking anything like memory
             * or file descriptors.  That's nice!
             */
            return DONE;
        case APR_INCHILD:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02142) "In child!");
            break;  /* now we'll drop privileges in the child */
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02143)
                          "Failed to fork secure child process!");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* OK, now drop privileges. */

    /* cleanup should happen even if something fails part-way through here */
    apr_pool_cleanup_register(r->pool, r, privileges_end_req,
                              apr_pool_cleanup_null);
    /* set user and group if configured */
    if (cfg->uid || cfg->gid) {
        if (setppriv(PRIV_ON, PRIV_EFFECTIVE, priv_setid) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02144)
                          "No privilege to set user/group");
        }
        /* if we should be able to set these but can't, it could be
         * a serious security issue.  Bail out rather than risk it!
         */
        if (cfg->uid && (setuid(cfg->uid) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02145)
                          "Error setting userid");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (cfg->gid && (setgid(cfg->gid) == -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02146)
                          "Error setting group");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    /* set vhost's privileges */
    if (setppriv(PRIV_SET, PRIV_EFFECTIVE, cfg->priv) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, APLOGNO(02147)
                      "Error setting effective privileges");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ... including those of any subprocesses */
    if (setppriv(PRIV_SET, PRIV_INHERITABLE, cfg->child_priv) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, APLOGNO(02148)
                      "Error setting inheritable privileges");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (setppriv(PRIV_SET, PRIV_LIMIT, cfg->child_priv) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, APLOGNO(02149)
                      "Error setting limit privileges");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* If we're in a child process, drop down PPERM too */
    if (fork_req) {
        if (setppriv(PRIV_SET, PRIV_PERMITTED, cfg->priv) == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r, APLOGNO(02150)
                          "Error setting permitted privileges");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}
#define PDROP_CHECK(x) if (x == -1) { \
        ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s, APLOGNO(02151) \
                     "Error dropping privileges"); \
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
            CR_CHECK(priv_addset(cfg->priv, PRIV_DTRACE_KERNEL), APLOGNO(03168));
            CR_CHECK(priv_addset(cfg->priv, PRIV_DTRACE_PROC), APLOGNO(03169));
            CR_CHECK(priv_addset(cfg->priv, PRIV_DTRACE_USER), APLOGNO(03170));
            CR_CHECK(priv_addset(cfg->child_priv, PRIV_DTRACE_KERNEL), APLOGNO(03171));
            CR_CHECK(priv_addset(cfg->child_priv, PRIV_DTRACE_PROC), APLOGNO(03172));
            CR_CHECK(priv_addset(cfg->child_priv, PRIV_DTRACE_USER), APLOGNO(03173));
        }
        CR_CHECK(priv_addset(priv_default, PRIV_DTRACE_KERNEL), APLOGNO(03174));
        CR_CHECK(priv_addset(priv_default, PRIV_DTRACE_PROC), APLOGNO(03175));
        CR_CHECK(priv_addset(priv_default, PRIV_DTRACE_USER), APLOGNO(03176));
    }

    /* set up priv_setid for per-request use */
    priv_setid = priv_allocset();
    apr_pool_cleanup_register(pconf, NULL, privileges_term,
                              apr_pool_cleanup_null);
    priv_emptyset(priv_setid);
    if (priv_addset(priv_setid, PRIV_PROC_SETID) == -1) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, errno, ptemp, APLOGNO(02152)
                      "priv_addset");
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
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, rv, ptemp, APLOGNO(02153)
                      "mod_privileges: unable to determine MPM characteristics."
                      "  Please ensure you are using a non-threaded MPM "
                      "with this module.");
    }
    if (threaded) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, ptemp, APLOGNO(02154)
                      "mod_privileges is not compatible with a threaded MPM.");
        return !OK;
    }
    return OK;
}
static void privileges_hooks(apr_pool_t *pool)
{
    ap_hook_post_read_request(privileges_req, NULL, NULL,
                              APR_HOOK_REALLY_FIRST);
    ap_hook_header_parser(privileges_req, NULL, NULL, APR_HOOK_REALLY_FIRST);
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

static const char *privs_mode(cmd_parms *cmd, void *dir, const char *arg)
{
    priv_mode mode = PRIV_UNSET;
    if (!strcasecmp(arg, "FAST")) {
        mode = PRIV_FAST;
    }
    else if (!strcasecmp(arg, "SECURE")) {
        mode = PRIV_SECURE;
    }
    else if (!strcasecmp(arg, "SELECTIVE")) {
        mode = PRIV_SELECTIVE;
    }

    if (cmd->path) {
        /* In a directory context, set the per_dir_config */
        priv_dir_cfg *cfg = dir;
        cfg->mode = mode;
        if ((mode == PRIV_UNSET) || (mode == PRIV_SELECTIVE)) {
            return "PrivilegesMode in a Directory context must be FAST or SECURE";
        }
    }
    else {
        /* In a global or vhost context, set the server config */
        priv_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                             &privileges_module);
        cfg->mode = mode;
        if (mode == PRIV_UNSET) {
            return "PrivilegesMode must be FAST, SECURE or SELECTIVE";
        }
    }
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
                 "Run in enhanced security mode (default ON)"),
    AP_INIT_TAKE1("VHostCGIMode", vhost_cgimode, NULL, RSRC_CONF,
                  "Enable fork+exec for this virtualhost (Off|Secure|On)"),
    AP_INIT_FLAG("DTracePrivileges", dtraceenable, NULL, RSRC_CONF,
                 "Enable DTrace"),
    AP_INIT_TAKE1("PrivilegesMode", privs_mode, NULL, RSRC_CONF|ACCESS_CONF,
                  "tradeoff performance vs security (fast or secure)"),
#ifdef BIG_SECURITY_HOLE
    AP_INIT_ITERATE("VHostPrivs", vhost_privs, NULL, RSRC_CONF,
                    "Privileges available in the (virtual) server"),
    AP_INIT_ITERATE("VHostCGIPrivs", vhost_cgiprivs, NULL, RSRC_CONF,
                    "Privileges available to external programs"),
#endif
    {NULL}
};
AP_DECLARE_MODULE(privileges) = {
    STANDARD20_MODULE_STUFF,
    privileges_create_dir_cfg,
    privileges_merge_dir_cfg,
    privileges_create_cfg,
    privileges_merge_cfg,
    privileges_cmds,
    privileges_hooks
};
