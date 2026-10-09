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
#include "http_log.h"
#include "http_request.h"
#include "http_core.h"
#include "util_mutex.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"

#include "mod_dav.h"
#include "repos.h"

/* The dav_fs_server_conf type lives in repos.h so lock.c can see it. */

static const char dav_fs_mutexid[] = "dav_fs-lockdb";

static apr_global_mutex_t *dav_fs_lockdb_mutex;

extern module AP_MODULE_DECLARE_DATA dav_fs_module;

const dav_fs_server_conf *dav_fs_get_server_conf(const request_rec *r)
{
    return ap_get_module_config(r->server->module_config, &dav_fs_module);
}

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

/*
 * dav_fs_get_resource() refuses the state directory, but only requests
 * which mod_dav routes through the repository provider ever reach it.
 * GET is not one of those: mod_dav_fs sets handle_get to false, so
 * dav_fixups() declines and the default handler serves the file straight
 * off the filesystem, property database and all.  Deny the state directory
 * here instead, for every method, wherever mod_dav_fs is the provider.
 */
static int dav_fs_fixups(request_rec *r)
{
    const char *provider_name, *pathname;

    provider_name = dav_get_provider_name(r);
    if (provider_name == NULL
        || strcmp(provider_name, DAV_FS_PROVIDER_NAME) != 0) {
        return DECLINED;
    }

    if (r->filename == NULL) {
        return DECLINED;
    }

    pathname = (r->path_info && *r->path_info)
        ? apr_pstrcat(r->pool, r->filename, r->path_info, NULL)
        : r->filename;

    if (!dav_fs_is_state_path(r->pool, pathname)) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10619)
                  "access to " DAV_FS_STATE_DIR " state directory "
                  "denied for %s", r->filename);
    return HTTP_FORBIDDEN;
}

static int dav_fs_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp)
{
    if (ap_mutex_register(pconf, dav_fs_mutexid, NULL, APR_LOCK_DEFAULT, 0))
        return !OK;
    return OK;
}

static void dav_fs_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    rv = apr_global_mutex_child_init(&dav_fs_lockdb_mutex,
                                     apr_global_mutex_lockfile(dav_fs_lockdb_mutex),
                                     p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     APLOGNO(10488) "child init failed for mutex");
    }
}

static apr_status_t dav_fs_post_config(apr_pool_t *p, apr_pool_t *plog,
                                       apr_pool_t *ptemp, server_rec *base_server)
{
    server_rec *s;
    apr_status_t rv;

    /* Ignore first pass through the config. */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
        return OK;

    rv = ap_global_mutex_create(&dav_fs_lockdb_mutex, NULL, dav_fs_mutexid, NULL,
                                base_server, p, 0);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, base_server,
                     APLOGNO(10489) "could not create lock mutex");
        return !OK;
    }

    for (s = base_server; s; s = s->next) {
        dav_fs_server_conf *conf;

        conf = ap_get_module_config(s->module_config, &dav_fs_module);

        /* Mutex is common across all vhosts, but could have one per
         * vhost if required. */
        conf->lockdb_mutex = dav_fs_lockdb_mutex;
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(dav_fs_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(dav_fs_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(dav_fs_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    /* before mod_dav's fixup, which takes over the request */
    ap_hook_fixups(dav_fs_fixups, NULL, NULL, APR_HOOK_FIRST);

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
