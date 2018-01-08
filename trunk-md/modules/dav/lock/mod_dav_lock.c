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
#include "ap_provider.h"

#include "mod_dav.h"
#include "locks.h"

/* per-dir configuration */
typedef struct {
    const char *lockdb_path;
} dav_lock_dir_conf;

extern const dav_hooks_locks dav_hooks_locks_generic;

extern module AP_MODULE_DECLARE_DATA dav_lock_module;

const char *dav_generic_get_lockdb_path(const request_rec *r)
{
    dav_lock_dir_conf *conf;

    conf = ap_get_module_config(r->per_dir_config, &dav_lock_module);
    return conf->lockdb_path;
}

static void *dav_lock_create_dir_config(apr_pool_t *p, char *dir)
{
    return apr_pcalloc(p, sizeof(dav_lock_dir_conf));
}

static void *dav_lock_merge_dir_config(apr_pool_t *p,
                                       void *base, void *overrides)
{
    dav_lock_dir_conf *parent = base;
    dav_lock_dir_conf *child = overrides;
    dav_lock_dir_conf *newconf;

    newconf = apr_pcalloc(p, sizeof(*newconf));

    newconf->lockdb_path =
        child->lockdb_path ? child->lockdb_path : parent->lockdb_path;

    return newconf;
}

/*
 * Command handler for the DAVGenericLockDB directive, which is TAKE1
 */
static const char *dav_lock_cmd_davlockdb(cmd_parms *cmd, void *config,
                                        const char *arg1)
{
    dav_lock_dir_conf *conf = config;

    conf->lockdb_path = ap_server_root_relative(cmd->pool, arg1);

    if (!conf->lockdb_path) {
        return apr_pstrcat(cmd->pool, "Invalid DAVGenericLockDB path ",
                           arg1, NULL);
    }

    return NULL;
}

static const command_rec dav_lock_cmds[] =
{
    /* per server */
    AP_INIT_TAKE1("DAVGenericLockDB", dav_lock_cmd_davlockdb, NULL, ACCESS_CONF,
                  "specify a lock database"),

    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, "dav-lock", "generic", "0",
                         &dav_hooks_locks_generic);
}

AP_DECLARE_MODULE(dav_lock) =
{
    STANDARD20_MODULE_STUFF,
    dav_lock_create_dir_config,     /* dir config creater */
    dav_lock_merge_dir_config,      /* dir merger --- default is to override */
    NULL,                           /* server config */
    NULL,                           /* merge server config */
    dav_lock_cmds,                  /* command table */
    register_hooks,                 /* register hooks */
};
