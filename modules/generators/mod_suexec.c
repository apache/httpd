/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_strings.h"
#include "unixd.h"
#include "mpm_common.h"
#include "mod_suexec.h"

module AP_MODULE_DECLARE_DATA suexec_module;

/*
 * Create a configuration specific to this module for a server or directory
 * location, and fill it with the default settings.
 */
static void *mkconfig(apr_pool_t *p)
{
    suexec_config_t *cfg = apr_palloc(p, sizeof(suexec_config_t));

    cfg->active = 0;
    return cfg;
}

/*
 * Respond to a callback to create configuration record for a server or
 * vhost environment.
 */
static void *create_mconfig_for_server(apr_pool_t *p, server_rec *s)
{
    return mkconfig(p);
}

/*
 * Respond to a callback to create a config record for a specific directory.
 */
static void *create_mconfig_for_directory(apr_pool_t *p, char *dir)
{
    return mkconfig(p);
}

static const char *set_suexec_ugid(cmd_parms *cmd, void *mconfig,
                                   const char *uid, const char *gid)
{
    suexec_config_t *cfg = (suexec_config_t *) mconfig;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }
    if (unixd_config.suexec_enabled) {
        cfg->ugid.uid = ap_uname2id(uid);
        cfg->ugid.gid = ap_gname2id(gid);
        cfg->ugid.userdir = 0;
        cfg->active = 1;
    }
    else {
        fprintf(stderr,
                "Warning: SuexecUserGroup directive requires SUEXEC wrapper.\n");
    }
    return NULL;
}

static ap_unix_identity_t *get_suexec_id_doer(const request_rec *r)
{
    suexec_config_t *cfg =
    (suexec_config_t *) ap_get_module_config(r->per_dir_config, &suexec_module);

    return cfg->active ? &cfg->ugid : NULL;
}

#define SUEXEC_POST_CONFIG_USERDATA "suexec_post_config_userdata"
static int suexec_post_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s)
{
    void *reported;

    apr_pool_userdata_get(&reported, SUEXEC_POST_CONFIG_USERDATA,
                          s->process->pool);

    if ((reported == NULL) && unixd_config.suexec_enabled) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "suEXEC mechanism enabled (wrapper: %s)", SUEXEC_BIN);

        apr_pool_userdata_set((void *)1, SUEXEC_POST_CONFIG_USERDATA,
                              apr_pool_cleanup_null, s->process->pool);
    }

    return OK;
}
#undef SUEXEC_POST_CONFIG_USERDATA

/*
 * Define the directives specific to this module.  This structure is referenced
 * later by the 'module' structure.
 */
static const command_rec suexec_cmds[] =
{
    /* XXX - Another important reason not to allow this in .htaccess is that
     * the ap_[ug]name2id() is not thread-safe */
    AP_INIT_TAKE2("SuexecUserGroup", set_suexec_ugid, NULL, RSRC_CONF,
      "User and group for spawned processes"),
    { NULL }
};

static void suexec_hooks(apr_pool_t *p)
{
    ap_hook_get_suexec_identity(get_suexec_id_doer,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_post_config(suexec_post_config,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA suexec_module =
{
    STANDARD20_MODULE_STUFF,
    create_mconfig_for_directory,   /* create per-dir config */
    NULL,                       /* merge per-dir config */
    create_mconfig_for_server,  /* server config */
    NULL,                       /* merge server config */
    suexec_cmds,                /* command table */
    suexec_hooks		/* register hooks */
};
