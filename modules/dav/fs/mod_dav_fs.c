/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 */

#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"

#include "mod_dav.h"
#include "repos.h"

/* per-server configuration */
typedef struct {
    const char *lockdb_path;

} dav_fs_server_conf;

extern module AP_MODULE_DECLARE_DATA dav_fs_module;

const char *dav_get_lockdb_path(const request_rec *r)
{
    dav_fs_server_conf *conf;

    conf = ap_get_module_config(r->server->module_config, &dav_fs_module);
    return conf->lockdb_path;
}

static void *dav_fs_create_server_config(apr_pool_t *p, server_rec *s)
{
    return apr_pcalloc(p, sizeof(dav_fs_server_conf));
}

static void *dav_fs_merge_server_config(apr_pool_t *p,
                                        void *base, void *overrides)
{
    dav_fs_server_conf *parent = base;
    dav_fs_server_conf *child = overrides;
    dav_fs_server_conf *newconf;

    newconf = apr_pcalloc(p, sizeof(*newconf));

    newconf->lockdb_path =
        child->lockdb_path ? child->lockdb_path : parent->lockdb_path;

    return newconf;
}

/*
 * Command handler for the DAVLockDB directive, which is TAKE1
 */
static const char *dav_fs_cmd_davlockdb(cmd_parms *cmd, void *config,
                                        const char *arg1)
{
    dav_fs_server_conf *conf;
    conf = ap_get_module_config(cmd->server->module_config,
                                &dav_fs_module);
    conf->lockdb_path = ap_server_root_relative(cmd->pool, arg1);

    if (!conf->lockdb_path) {
        return apr_pstrcat(cmd->pool, "Invalid DAVLockDB path ",
                           arg1, NULL);
    }

    return NULL;
}

static const command_rec dav_fs_cmds[] =
{
    /* per server */
    AP_INIT_TAKE1("DAVLockDB", dav_fs_cmd_davlockdb, NULL, RSRC_CONF,
                  "specify a lock database"),

    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    dav_hook_gather_propsets(dav_fs_gather_propsets, NULL, NULL,
                             APR_HOOK_MIDDLE);
    dav_hook_find_liveprop(dav_fs_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);
    dav_hook_insert_all_liveprops(dav_fs_insert_all_liveprops, NULL, NULL,
                                  APR_HOOK_MIDDLE);

    dav_fs_register(p);
}

module AP_MODULE_DECLARE_DATA dav_fs_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                        /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    dav_fs_create_server_config, /* server config */
    dav_fs_merge_server_config,  /* merge server config */
    dav_fs_cmds,                 /* command table */
    register_hooks,              /* register hooks */
};
