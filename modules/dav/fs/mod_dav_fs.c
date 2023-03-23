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
#include "http_request.h"
#include "apr_strings.h"
#if !defined(_MSC_VER) && !defined(NETWARE)
#include "ap_config_auto.h"
#endif

#include "mod_dav.h"
#include "repos.h"

/* per-dir configuration */
typedef struct {
    const char *dir;
    apr_off_t quota;
} dav_fs_dir_conf;

/* per-server configuration */
typedef struct {
    const char *lockdb_path;

} dav_fs_server_conf;

extern module AP_MODULE_DECLARE_DATA dav_fs_module;

#ifndef DEFAULT_DAV_LOCKDB
#define DEFAULT_DAV_LOCKDB "davlockdb"
#endif

const char *dav_get_lockdb_path(const request_rec *r)
{
    dav_fs_server_conf *conf;

    conf = ap_get_module_config(r->server->module_config, &dav_fs_module);
    return conf->lockdb_path;
}

static const command_rec dav_fs_cmds[];

dav_error *dav_fs_get_quota(const request_rec *r, const char *path,
                            apr_off_t *quota_bytes)
{
    dav_fs_dir_conf *conf = NULL;
    dav_error *err = NULL;
    const char *request_path;
    request_rec *rr;
    int status;

    request_path = ap_make_dirstr_parent(r->pool, r->filename);

    /* 
     * Uses's request's per directry configuration if possible, for
     * efficiency sake.
     */
    if (!strcmp(path, request_path)) {
        conf = ap_get_module_config(r->per_dir_config, &dav_fs_module);
        *quota_bytes = conf->quota;
        goto out;
    }

    /* 
     * We need for a per directory configuration from a random path
     * not tied to current request, for e.g. COPY or MOVE destination.
     * This is done through a subrequest, with just rr->filename
     * changed to target path.
     */
    rr = ap_sub_req_method_uri(r->method, r->uri, r, r->output_filters);
    if (!rr || rr->status != HTTP_OK) {
        err = dav_new_error(r->pool,
                            rr ? rr->status : HTTP_INTERNAL_SERVER_ERROR,
                            0, 0,
                            "quota configuration subrequest failed");
        *quota_bytes = DAV_FS_BYTES_ERROR;
        goto out;
    }

    rr->filename = apr_pstrdup(r->pool, path);
    if ((status = ap_directory_walk(rr)) != OK)  {
        err = dav_new_error(r->pool, status, 0, 0,
                            "quota configuration tree walk failed");
        *quota_bytes = DAV_FS_BYTES_ERROR;
        goto out;
    }

    conf = ap_get_module_config(rr->per_dir_config, &dav_fs_module);
    *quota_bytes = conf->quota;

out:
    return err;
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

static void *dav_fs_create_dir_config(apr_pool_t *p, char *dir)
{
    /* NOTE: dir==NULL creates the default per-dir config */

    dav_fs_dir_conf *conf;

    conf = (dav_fs_dir_conf *)apr_pcalloc(p, sizeof(*conf));
    conf->dir = apr_pstrdup(p, dir);
    conf->quota = DAV_FS_QUOTA_UNSET;

    return conf;
}

static void *dav_fs_merge_dir_config(apr_pool_t *p, void *base, void *overrides)
{
    dav_fs_dir_conf *parent = base;
    dav_fs_dir_conf *child = overrides;
    dav_fs_dir_conf *newconf =
        (dav_fs_dir_conf *)apr_pcalloc(p, sizeof(*newconf));

    newconf->dir = child->dir;

    if (child->quota != DAV_FS_QUOTA_UNSET)
        newconf->quota = child->quota;
    else
        newconf->quota = parent->quota;

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
 * Command handler for the DAVquota directive, which is TAKE1
 */
static const char *dav_fs_cmd_quota(cmd_parms *cmd, void *config,
                                    const char *bytes)
{
    dav_fs_dir_conf *conf = (dav_fs_dir_conf *)config;

    if (!strcasecmp(bytes, "Off"))
        conf->quota = DAV_FS_QUOTA_OFF;
    else if (!strcasecmp(bytes, "None"))
        conf->quota = DAV_FS_QUOTA_NONE;
    else
        conf->quota = atol(bytes);

    return NULL;
}


static const command_rec dav_fs_cmds[] =
{
    /* per server */
    AP_INIT_TAKE1("DAVLockDB", dav_fs_cmd_davlockdb, NULL, RSRC_CONF,
                  "specify a lock database"),

    /* per directory */
    AP_INIT_TAKE1("DAVquota", dav_fs_cmd_quota, NULL, ACCESS_CONF|RSRC_CONF,
                  "specify a directory quota"),

    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(dav_fs_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    dav_hook_gather_propsets(dav_fs_gather_propsets, NULL, NULL,
                             APR_HOOK_MIDDLE);
    dav_hook_find_liveprop(dav_fs_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);
    dav_hook_insert_all_liveprops(dav_fs_insert_all_liveprops, NULL, NULL,
                                  APR_HOOK_MIDDLE);
    dav_hook_method_precondition(dav_fs_method_precondition, NULL, NULL,
                                  APR_HOOK_MIDDLE);

    dav_fs_register(p);
}

AP_DECLARE_MODULE(dav_fs) =
{
    STANDARD20_MODULE_STUFF,
    dav_fs_create_dir_config,    /* dir config */
    dav_fs_merge_dir_config,     /* merger dir config */
    dav_fs_create_server_config, /* server config */
    dav_fs_merge_server_config,  /* merge server config */
    dav_fs_cmds,                 /* command table */
    register_hooks,              /* register hooks */
};
