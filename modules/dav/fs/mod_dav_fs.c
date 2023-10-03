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

#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"

#include "mod_dav.h"
#include "repos.h"

/* per-server configuration */
typedef struct {
    const char *lockdb_path;
    const char *lockdb_type;
} dav_fs_server_conf;

extern module AP_MODULE_DECLARE_DATA dav_fs_module;

#ifndef DEFAULT_DAV_LOCKDB
#define DEFAULT_DAV_LOCKDB "davlockdb"
#endif
#ifndef DEFAULT_DAV_LOCKDB_TYPE
#define DEFAULT_DAV_LOCKDB_TYPE "default"
#endif


const char *dav_get_lockdb_path(const request_rec *r, const char **dbmtype)
{
    dav_fs_server_conf *conf;

    conf = ap_get_module_config(r->server->module_config, &dav_fs_module);

    *dbmtype = conf->lockdb_type;

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
    newconf->lockdb_type =
        child->lockdb_type ? child->lockdb_type : parent->lockdb_type;

    return newconf;
}


static apr_status_t dav_fs_post_config(apr_pool_t *p, apr_pool_t *plog,
                                       apr_pool_t *ptemp, server_rec *base_server)
{
    server_rec *s;

    for (s = base_server; s; s = s->next) {
        dav_fs_server_conf *conf;

        conf = ap_get_module_config(s->module_config, &dav_fs_module);

        if (!conf->lockdb_path) {
            conf->lockdb_path = ap_state_dir_relative(p, DEFAULT_DAV_LOCKDB);
        }
        if (!conf->lockdb_type) {
            conf->lockdb_type = DEFAULT_DAV_LOCKDB_TYPE;
        }
    }

    return OK;
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

/*
 * Command handler for the DAVLockDBType directive, which is TAKE1
 */
static const char *dav_fs_cmd_davlockdbtype(cmd_parms *cmd, void *config,
                                        const char *arg1)
{
    dav_fs_server_conf *conf = ap_get_module_config(cmd->server->module_config,
                                                    &dav_fs_module);
    conf->lockdb_type = arg1;

    return NULL;
}

static const command_rec dav_fs_cmds[] =
{
    /* per server */
    AP_INIT_TAKE1("DAVLockDB", dav_fs_cmd_davlockdb, NULL, RSRC_CONF,
                  "specify a lock database"),
    AP_INIT_TAKE1("DAVLockDBType", dav_fs_cmd_davlockdbtype, NULL, RSRC_CONF,
                  "specify a lock database DBM type"),

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

AP_DECLARE_MODULE(dav_fs) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                        /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    dav_fs_create_server_config, /* server config */
    dav_fs_merge_server_config,  /* merge server config */
    dav_fs_cmds,                 /* command table */
    register_hooks,              /* register hooks */
};
