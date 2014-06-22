/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_lua.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <apr_thread_mutex.h>
#include <apr_pools.h>
#include "lua_apr.h"
#include "lua_config.h"
#include "apr_optional.h"
#include "mod_ssl.h"
#include "mod_auth.h"
#include "util_mutex.h"


#ifdef APR_HAS_THREADS
#include "apr_thread_proc.h"
#endif

/* getpid for *NIX */
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* getpid for Windows */
#if APR_HAVE_PROCESS_H
#include <process.h>
#endif

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap_lua, AP_LUA, int, lua_open,
                                    (lua_State *L, apr_pool_t *p),
                                    (L, p), OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap_lua, AP_LUA, int, lua_request,
                                    (lua_State *L, request_rec *r),
                                    (L, r), OK, DECLINED)
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *lua_ssl_val = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *lua_ssl_is_https = NULL;

module AP_MODULE_DECLARE_DATA lua_module;

#define AP_LUA_HOOK_FIRST (APR_HOOK_FIRST - 1)
#define AP_LUA_HOOK_LAST  (APR_HOOK_LAST  + 1)

typedef struct {
    const char *name;
    const char *file_name;
    const char *function_name;
    ap_lua_vm_spec *spec;
    apr_array_header_t *args;
} lua_authz_provider_spec;

apr_hash_t *lua_authz_providers;

typedef struct
{
    apr_bucket_brigade *tmpBucket;
    lua_State *L;
    ap_lua_vm_spec *spec;
    int broken;
} lua_filter_ctx;

apr_global_mutex_t *lua_ivm_mutex;
apr_shm_t *lua_ivm_shm;
char *lua_ivm_shmfile;

static apr_status_t shm_cleanup_wrapper(void *unused) {
    if (lua_ivm_shm) {
        return apr_shm_destroy(lua_ivm_shm);
    }
    return OK;
}

/**
 * error reporting if lua has an error.
 * Extracts the error from lua stack and prints
 */
static void report_lua_error(lua_State *L, request_rec *r)
{
    const char *lua_response;
    r->status = HTTP_INTERNAL_SERVER_ERROR;
    r->content_type = "text/html";
    ap_rputs("<h3>Error!</h3>\n", r);
    ap_rputs("<pre>", r);
    lua_response = lua_tostring(L, -1);
    ap_rputs(ap_escape_html(r->pool, lua_response), r);
    ap_rputs("</pre>\n", r);

    ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, r->pool, APLOGNO(01471) "Lua error: %s",
                  lua_response);
}

static void lua_open_callback(lua_State *L, apr_pool_t *p, void *ctx)
{
    ap_lua_init(L, p);
    ap_lua_load_apache2_lmodule(L);
    ap_lua_load_request_lmodule(L, p);
    ap_lua_load_config_lmodule(L);
}

static int lua_open_hook(lua_State *L, apr_pool_t *p)
{
    lua_open_callback(L, p, NULL);
    return OK;
}

static const char *scope_to_string(unsigned int scope)
{
    switch (scope) {
    case AP_LUA_SCOPE_ONCE:
    case AP_LUA_SCOPE_UNSET:
        return "once";
    case AP_LUA_SCOPE_REQUEST:
        return "request";
    case AP_LUA_SCOPE_CONN:
        return "conn";
#if APR_HAS_THREADS
    case AP_LUA_SCOPE_THREAD:
        return "thread";
    case AP_LUA_SCOPE_SERVER:
        return "server";
#endif
    default:
        ap_assert(0);
        return 0;
    }
}

static void ap_lua_release_state(lua_State* L, ap_lua_vm_spec* spec, request_rec* r) {
    char *hash;
    apr_reslist_t* reslist = NULL;
    if (spec->scope == AP_LUA_SCOPE_SERVER) {
        ap_lua_server_spec* sspec = NULL;
        lua_settop(L, 0);
        lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Lua.server_spec");
        sspec = (ap_lua_server_spec*) lua_touserdata(L, 1);
        hash = apr_psprintf(r->pool, "reslist:%s", spec->file);
        if (apr_pool_userdata_get((void **)&reslist, hash,
                                r->server->process->pool) == APR_SUCCESS) {
            AP_DEBUG_ASSERT(sspec != NULL);
            if (reslist != NULL) {
                apr_reslist_release(reslist, sspec);
            }
        }
    }
}

static ap_lua_vm_spec *create_vm_spec(apr_pool_t **lifecycle_pool,
                                      request_rec *r,
                                      const ap_lua_dir_cfg *cfg,
                                      const ap_lua_server_cfg *server_cfg,
                                      const char *filename,
                                      const char *bytecode,
                                      apr_size_t bytecode_len,
                                      const char *function,
                                      const char *what)
{
    apr_pool_t *pool;
    ap_lua_vm_spec *spec = apr_pcalloc(r->pool, sizeof(ap_lua_vm_spec));

    spec->scope = cfg->vm_scope;
    spec->pool = r->pool;
    spec->package_paths = cfg->package_paths;
    spec->package_cpaths = cfg->package_cpaths;
    spec->cb = &lua_open_callback;
    spec->cb_arg = NULL;
    spec->bytecode = bytecode;
    spec->bytecode_len = bytecode_len;
    spec->codecache = (cfg->codecache == AP_LUA_CACHE_UNSET) ? AP_LUA_CACHE_STAT : cfg->codecache;
    spec->vm_min = cfg->vm_min ? cfg->vm_min : 1;
    spec->vm_max = cfg->vm_max ? cfg->vm_max : 1;
    
    if (filename) {
        char *file;
        apr_filepath_merge(&file, server_cfg->root_path,
                           filename, APR_FILEPATH_NOTRELATIVE, r->pool);
        spec->file = file;
    }
    else {
        spec->file = r->filename;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, APLOGNO(02313)
                  "%s details: scope: %s, file: %s, func: %s",
                  what, scope_to_string(spec->scope), spec->file,
                  function ? function : "-");

    switch (spec->scope) {
    case AP_LUA_SCOPE_ONCE:
    case AP_LUA_SCOPE_UNSET:
        apr_pool_create(&pool, r->pool);
        break;
    case AP_LUA_SCOPE_REQUEST:
        pool = r->pool;
        break;
    case AP_LUA_SCOPE_CONN:
        pool = r->connection->pool;
        break;
#if APR_HAS_THREADS
    case AP_LUA_SCOPE_THREAD:
        pool = apr_thread_pool_get(r->connection->current_thread);
        break;
    case AP_LUA_SCOPE_SERVER:
        pool = r->server->process->pool;
        break;
#endif
    default:
        ap_assert(0);
    }

    *lifecycle_pool = pool;
    return spec;
}

static const char* ap_lua_interpolate_string(apr_pool_t* pool, const char* string, const char** values)
{
    char *stringBetween;
    const char* ret;
    int srclen,x,y;
    srclen = strlen(string);
    ret = "";
    y = 0;
    for (x=0; x < srclen; x++) {
        if (string[x] == '$' && x != srclen-1 && string[x+1] >= '0' && string[x+1] <= '9') {
            int v = *(string+x+1) - '0';
            if (x-y > 0) {
                stringBetween = apr_pstrndup(pool, string+y, x-y);
            }
            else {
                stringBetween = "";
            }
            ret = apr_pstrcat(pool, ret, stringBetween, values[v], NULL);
            y = ++x+1;
        }
    }
    
    if (x-y > 0 && y > 0) {
        stringBetween = apr_pstrndup(pool, string+y, x-y);
        ret = apr_pstrcat(pool, ret, stringBetween, NULL);
    }
    /* If no replacement was made, just return the original string */
    else if (y == 0) {
        return string;
    }
    return ret;
}



/**
 * "main"
 */
static int lua_handler(request_rec *r)
{
    int rc = OK;
    if (strcmp(r->handler, "lua-script")) {
        return DECLINED;
    }
    /* Decline the request if the script does not exist (or is a directory),
     * rather than just returning internal server error */
    if (
            (r->finfo.filetype == APR_NOFILE)
            || (r->finfo.filetype & APR_DIR)
        ) {
        return DECLINED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, APLOGNO(01472)
                  "handling [%s] in mod_lua", r->filename);

    /* XXX: This seems wrong because it may generate wrong headers for HEAD requests */
    if (!r->header_only) {
        lua_State *L;
        apr_pool_t *pool;
        const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                         &lua_module);
        ap_lua_vm_spec *spec = create_vm_spec(&pool, r, cfg, NULL, NULL, NULL,
                                              0, "handle", "request handler");

        L = ap_lua_get_lua_state(pool, spec, r);
        if (!L) {
            /* TODO annotate spec with failure reason */
            r->status = HTTP_INTERNAL_SERVER_ERROR;
            ap_rputs("Unable to compile VM, see logs", r);
            ap_lua_release_state(L, spec, r);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, APLOGNO(01474) "got a vm!");
        lua_getglobal(L, "handle");
        if (!lua_isfunction(L, -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(01475)
                          "lua: Unable to find entry function '%s' in %s (not a valid function)",
                          "handle",
                          spec->file);
            ap_lua_release_state(L, spec, r);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_lua_run_lua_request(L, r);
        if (lua_pcall(L, 1, 1, 0)) {
            report_lua_error(L, r);
        }
        if (lua_isnumber(L, -1)) {
            rc = lua_tointeger(L, -1);
        }
        ap_lua_release_state(L, spec, r);
    }
    return rc;
}


/* ------------------- Input/output content filters ------------------- */


static apr_status_t lua_setup_filter_ctx(ap_filter_t* f, request_rec* r, lua_filter_ctx** c) {
    apr_pool_t *pool;
    ap_lua_vm_spec *spec;
    int n, rc;
    lua_State *L;
    lua_filter_ctx *ctx;    
    ap_lua_server_cfg *server_cfg = ap_get_module_config(r->server->module_config,
                                                        &lua_module);
    const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                    &lua_module);
    
    ctx = apr_pcalloc(r->pool, sizeof(lua_filter_ctx));
    ctx->broken = 0;
    *c = ctx;
    /* Find the filter that was called.
     * XXX: If we were wired with mod_filter, the filter (mod_filters name)
     *      and the provider (our underlying filters name) need to have matched.
     */
    for (n = 0; n < cfg->mapped_filters->nelts; n++) {
        ap_lua_filter_handler_spec *hook_spec =
            ((ap_lua_filter_handler_spec **) cfg->mapped_filters->elts)[n];

        if (hook_spec == NULL) {
            continue;
        }
        if (!strcasecmp(hook_spec->filter_name, f->frec->name)) {
            spec = create_vm_spec(&pool, r, cfg, server_cfg,
                                    hook_spec->file_name,
                                    NULL,
                                    0,
                                    hook_spec->function_name,
                                    "filter");
            L = ap_lua_get_lua_state(pool, spec, r);
            if (L) {
                L = lua_newthread(L);
            }

            if (!L) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02328)
                                "lua: Failed to obtain lua interpreter for %s %s",
                                hook_spec->function_name, hook_spec->file_name);
                ap_lua_release_state(L, spec, r);
                return APR_EGENERAL;
            }
            if (hook_spec->function_name != NULL) {
                lua_getglobal(L, hook_spec->function_name);
                if (!lua_isfunction(L, -1)) {
                    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02329)
                                "lua: Unable to find entry function '%s' in %s (not a valid function)",
                                    hook_spec->function_name,
                                    hook_spec->file_name);
                    ap_lua_release_state(L, spec, r);
                    return APR_EGENERAL;
                }

                ap_lua_run_lua_request(L, r);
            }
            else {
                int t;
                ap_lua_run_lua_request(L, r);

                t = lua_gettop(L);
                lua_setglobal(L, "r");
                lua_settop(L, t);
            }
            ctx->L = L;
            ctx->spec = spec;
            
            /* If a Lua filter is interested in filtering a request, it must first do a yield, 
             * otherwise we'll assume that it's not interested and pretend we didn't find it.
             */
            rc = lua_resume(L, 1);
            if (rc == LUA_YIELD) {
                if (f->frec->providers == NULL) { 
                    /* Not wired by mod_filter */
                    apr_table_unset(r->headers_out, "Content-Length");
                    apr_table_unset(r->headers_out, "Content-MD5");
                    apr_table_unset(r->headers_out, "ETAG");
                }
                return OK;
            }
            else {
                ap_lua_release_state(L, spec, r);
                return APR_ENOENT;
            }
        }
    }
    return APR_ENOENT;
}

static apr_status_t lua_output_filter_handle(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
    request_rec *r = f->r;
    int rc;
    lua_State *L;
    lua_filter_ctx* ctx;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_status_t rv;
    
    /* Set up the initial filter context and acquire the function.
     * The corresponding Lua function should yield here.
     */
    if (!f->ctx) {
        rc = lua_setup_filter_ctx(f,r,&ctx);
        if (rc == APR_EGENERAL) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (rc == APR_ENOENT) {
            /* No filter entry found (or the script declined to filter), just pass on the buckets */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next,pbbIn);
        }
        else { 
            /* We've got a willing lua filter, setup and check for a prefix */
            size_t olen;
            apr_bucket *pbktOut;
            const char* output = lua_tolstring(ctx->L, 1, &olen);

            f->ctx = ctx;
            ctx->tmpBucket = apr_brigade_create(r->pool, c->bucket_alloc);

            if (olen > 0) { 
                pbktOut = apr_bucket_heap_create(output, olen, NULL, c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, pbktOut);
                rv = ap_pass_brigade(f->next, ctx->tmpBucket);
                apr_brigade_cleanup(ctx->tmpBucket);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
            }
        }
    }
    ctx = (lua_filter_ctx*) f->ctx;
    L = ctx->L;
    /* While the Lua function is still yielding, pass in buckets to the coroutine */
    if (!ctx->broken) {
        for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
            pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
            pbktIn = APR_BUCKET_NEXT(pbktIn))
            {
            const char *data;
            apr_size_t len;
            apr_bucket *pbktOut;

            /* read the bucket */
            apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

            /* Push the bucket onto the Lua stack as a global var */
            lua_pushlstring(L, data, len);
            lua_setglobal(L, "bucket");
            
            /* If Lua yielded, it means we have something to pass on */
            if (lua_resume(L, 0) == LUA_YIELD) {
                size_t olen;
                const char* output = lua_tolstring(L, 1, &olen);
                if (olen > 0) { 
                    pbktOut = apr_bucket_heap_create(output, olen, NULL,
                                            c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, pbktOut);
                    rv = ap_pass_brigade(f->next, ctx->tmpBucket);
                    apr_brigade_cleanup(ctx->tmpBucket);
                    if (rv != APR_SUCCESS) {
                        return rv;
                    }
                }
            }
            else {
                ctx->broken = 1;
                ap_lua_release_state(L, ctx->spec, r);
                ap_remove_output_filter(f);
                apr_brigade_cleanup(pbbIn);
                apr_brigade_cleanup(ctx->tmpBucket);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                    "lua: Error while executing filter: %s",
                        lua_tostring(L, -1));
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        /* If we've safely reached the end, do a final call to Lua to allow for any 
        finishing moves by the script, such as appending a tail. */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(pbbIn))) {
            apr_bucket *pbktEOS;
            lua_pushnil(L);
            lua_setglobal(L, "bucket");
            if (lua_resume(L, 0) == LUA_YIELD) {
                apr_bucket *pbktOut;
                size_t olen;
                const char* output = lua_tolstring(L, 1, &olen);
                if (olen > 0) { 
                    pbktOut = apr_bucket_heap_create(output, olen, NULL,
                            c->bucket_alloc);
                    APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, pbktOut);
                }
            }
            pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->tmpBucket, pbktEOS);
            ap_lua_release_state(L, ctx->spec, r);
            rv = ap_pass_brigade(f->next, ctx->tmpBucket);
            apr_brigade_cleanup(ctx->tmpBucket);
            if (rv != APR_SUCCESS) {
                return rv;
            }
        }
    }
    /* Clean up */
    apr_brigade_cleanup(pbbIn);
    return APR_SUCCESS;    
}



static apr_status_t lua_input_filter_handle(ap_filter_t *f,
                                       apr_bucket_brigade *pbbOut,
                                       ap_input_mode_t eMode,
                                       apr_read_type_e eBlock,
                                       apr_off_t nBytes) 
{
    request_rec *r = f->r;
    int rc, lastCall = 0;
    lua_State *L;
    lua_filter_ctx* ctx;
    conn_rec *c = r->connection;
    apr_status_t ret;
    
    /* Set up the initial filter context and acquire the function.
     * The corresponding Lua function should yield here.
     */
    if (!f->ctx) {
        rc = lua_setup_filter_ctx(f,r,&ctx);
        f->ctx = ctx;
        if (rc == APR_EGENERAL) {
            ctx->broken = 1;
            ap_remove_input_filter(f); 
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (rc == APR_ENOENT ) {
            ap_remove_input_filter(f);
            ctx->broken = 1;
        }
        if (rc == APR_SUCCESS) {
            ctx->tmpBucket = apr_brigade_create(r->pool, c->bucket_alloc);
        }
    }
    ctx = (lua_filter_ctx*) f->ctx;
    L = ctx->L;
    /* If the Lua script broke or denied serving the request, just pass the buckets through */
    if (ctx->broken) {
        return ap_get_brigade(f->next, pbbOut, eMode, eBlock, nBytes);
    }
    
    if (APR_BRIGADE_EMPTY(ctx->tmpBucket)) {
        ret = ap_get_brigade(f->next, ctx->tmpBucket, eMode, eBlock, nBytes);
        if (eMode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
            return ret;
    }
    
    /* While the Lua function is still yielding, pass buckets to the coroutine */
    if (!ctx->broken) {
        lastCall = 0;
        while(!APR_BRIGADE_EMPTY(ctx->tmpBucket)) {
            apr_bucket *pbktIn = APR_BRIGADE_FIRST(ctx->tmpBucket);
            apr_bucket *pbktOut;
            const char *data;
            apr_size_t len;
            
            if (APR_BUCKET_IS_EOS(pbktIn)) {
                APR_BUCKET_REMOVE(pbktIn);
                break;
            }

            /* read the bucket */
            ret = apr_bucket_read(pbktIn, &data, &len, eBlock);
            if (ret != APR_SUCCESS)
                return ret;

            /* Push the bucket onto the Lua stack as a global var */
            lastCall++;
            lua_pushlstring(L, data, len);
            lua_setglobal(L, "bucket");
            
            /* If Lua yielded, it means we have something to pass on */
            if (lua_resume(L, 0) == LUA_YIELD) {
                size_t olen;
                const char* output = lua_tolstring(L, 1, &olen);
                pbktOut = apr_bucket_heap_create(output, olen, 0, c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
                apr_bucket_delete(pbktIn);
                return APR_SUCCESS;
            }
            else {
                ctx->broken = 1;
                ap_lua_release_state(L, ctx->spec, r);
                ap_remove_input_filter(f); 
                apr_bucket_delete(pbktIn);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        /* If we've safely reached the end, do a final call to Lua to allow for any 
        finishing moves by the script, such as appending a tail. */
        if (lastCall == 0) {
            apr_bucket *pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
            lua_pushnil(L);
            lua_setglobal(L, "bucket");
            if (lua_resume(L, 0) == LUA_YIELD) {
                apr_bucket *pbktOut;
                size_t olen;
                const char* output = lua_tolstring(L, 1, &olen);
                pbktOut = apr_bucket_heap_create(output, olen, 0, c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
            }
            APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
            ap_lua_release_state(L, ctx->spec, r);
        }
    }
    return APR_SUCCESS;
}


/* ---------------- Configury stuff --------------- */

/** harnesses for magic hooks **/

static int lua_request_rec_hook_harness(request_rec *r, const char *name, int apr_hook_when)
{
    int rc;
    apr_pool_t *pool;
    lua_State *L;
    ap_lua_vm_spec *spec;
    ap_lua_server_cfg *server_cfg = ap_get_module_config(r->server->module_config,
                                                         &lua_module);
    const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                     &lua_module);
    const char *key = apr_psprintf(r->pool, "%s_%d", name, apr_hook_when);
    apr_array_header_t *hook_specs = apr_hash_get(cfg->hooks, key,
                                                  APR_HASH_KEY_STRING);
    if (hook_specs) {
        int i;
        for (i = 0; i < hook_specs->nelts; i++) {
            ap_lua_mapped_handler_spec *hook_spec =
                ((ap_lua_mapped_handler_spec **) hook_specs->elts)[i];

            if (hook_spec == NULL) {
                continue;
            }
            spec = create_vm_spec(&pool, r, cfg, server_cfg,
                                  hook_spec->file_name,
                                  hook_spec->bytecode,
                                  hook_spec->bytecode_len,
                                  hook_spec->function_name,
                                  "request hook");

            L = ap_lua_get_lua_state(pool, spec, r);

            if (!L) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(01477)
                    "lua: Failed to obtain lua interpreter for entry function '%s' in %s",
                              hook_spec->function_name, hook_spec->file_name);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (hook_spec->function_name != NULL) {
                lua_getglobal(L, hook_spec->function_name);
                if (!lua_isfunction(L, -1)) {
                    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(01478)
                               "lua: Unable to find entry function '%s' in %s (not a valid function)",
                                  hook_spec->function_name,
                                  hook_spec->file_name);
                    ap_lua_release_state(L, spec, r);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                ap_lua_run_lua_request(L, r);
            }
            else {
                int t;
                ap_lua_run_lua_request(L, r);

                t = lua_gettop(L);
                lua_setglobal(L, "r");
                lua_settop(L, t);
            }

            if (lua_pcall(L, 1, 1, 0)) {
                report_lua_error(L, r);
                ap_lua_release_state(L, spec, r);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            rc = DECLINED;
            if (lua_isnumber(L, -1)) {
                rc = lua_tointeger(L, -1);
                ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "Lua hook %s:%s for phase %s returned %d", 
                              hook_spec->file_name, hook_spec->function_name, name, rc);
            }
            else { 
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Lua hook %s:%s for phase %s did not return a numeric value", 
                              hook_spec->file_name, hook_spec->function_name, name);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            if (rc != DECLINED) {
                ap_lua_release_state(L, spec, r);
                return rc;
            }
            ap_lua_release_state(L, spec, r);
        }
    }
    return DECLINED;
}


/* Fix for making sure that LuaMapHandler works when FallbackResource is set */
static int lua_map_handler_fixups(request_rec *r)
{
    /* If there is no handler set yet, this might be a LuaMapHandler request */
    if (r->handler == NULL) {
        int n = 0;
        ap_regmatch_t match[10];
        const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                     &lua_module);
        for (n = 0; n < cfg->mapped_handlers->nelts; n++) {
            ap_lua_mapped_handler_spec *hook_spec =
            ((ap_lua_mapped_handler_spec **) cfg->mapped_handlers->elts)[n];

            if (hook_spec == NULL) {
                continue;
            }
            if (!ap_regexec(hook_spec->uri_pattern, r->uri, 10, match, 0)) {
                r->handler = apr_pstrdup(r->pool, "lua-map-handler");
                return OK;
            }
        }
    }
    return DECLINED;
}


static int lua_map_handler(request_rec *r)
{
    int rc, n = 0;
    apr_pool_t *pool;
    lua_State *L;
    const char *filename, *function_name;
    const char *values[10];
    ap_lua_vm_spec *spec;
    ap_regmatch_t match[10];
    ap_lua_server_cfg *server_cfg = ap_get_module_config(r->server->module_config,
                                                         &lua_module);
    const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                     &lua_module);
    for (n = 0; n < cfg->mapped_handlers->nelts; n++) {
        ap_lua_mapped_handler_spec *hook_spec =
            ((ap_lua_mapped_handler_spec **) cfg->mapped_handlers->elts)[n];

        if (hook_spec == NULL) {
            continue;
        }
        if (!ap_regexec(hook_spec->uri_pattern, r->uri, 10, match, 0)) {
            int i;
            for (i=0 ; i < 10; i++) {
                if (match[i].rm_eo >= 0) {
                    values[i] = apr_pstrndup(r->pool, r->uri+match[i].rm_so, match[i].rm_eo - match[i].rm_so);
                }
                else values[i] = "";
            }
            filename = ap_lua_interpolate_string(r->pool, hook_spec->file_name, values);
            function_name = ap_lua_interpolate_string(r->pool, hook_spec->function_name, values);
            spec = create_vm_spec(&pool, r, cfg, server_cfg,
                                    filename,
                                    hook_spec->bytecode,
                                    hook_spec->bytecode_len,
                                    function_name,
                                    "mapped handler");
            L = ap_lua_get_lua_state(pool, spec, r);

            if (!L) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02330)
                                "lua: Failed to obtain Lua interpreter for entry function '%s' in %s",
                                function_name, filename);
                ap_lua_release_state(L, spec, r);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (function_name != NULL) {
                lua_getglobal(L, function_name);
                if (!lua_isfunction(L, -1)) {
                    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02331)
                                    "lua: Unable to find entry function '%s' in %s (not a valid function)",
                                    function_name,
                                    filename);
                    ap_lua_release_state(L, spec, r);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                ap_lua_run_lua_request(L, r);
            }
            else {
                int t;
                ap_lua_run_lua_request(L, r);

                t = lua_gettop(L);
                lua_setglobal(L, "r");
                lua_settop(L, t);
            }

            if (lua_pcall(L, 1, 1, 0)) {
                report_lua_error(L, r);
                ap_lua_release_state(L, spec, r);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            rc = DECLINED;
            if (lua_isnumber(L, -1)) {
                rc = lua_tointeger(L, -1);
            }
            else { 
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(02483)
                              "lua: Lua handler %s in %s did not return a value, assuming apache2.OK",
                              function_name,
                              filename);
                rc = OK;
            }
            ap_lua_release_state(L, spec, r);
            if (rc != DECLINED) {
                return rc;
            }
        }
    }
    return DECLINED;
}


static apr_size_t config_getstr(ap_configfile_t *cfg, char *buf,
                                size_t bufsiz)
{
    apr_size_t i = 0;

    if (cfg->getstr) {
        apr_status_t rc = (cfg->getstr) (buf, bufsiz, cfg->param);
        if (rc == APR_SUCCESS) {
            i = strlen(buf);
            if (i && buf[i - 1] == '\n')
                ++cfg->line_number;
        }
        else {
            buf[0] = '\0';
            i = 0;
        }
    }
    else {
        while (i < bufsiz) {
            char ch;
            apr_status_t rc = (cfg->getch) (&ch, cfg->param);
            if (rc != APR_SUCCESS)
                break;
            buf[i++] = ch;
            if (ch == '\n') {
                ++cfg->line_number;
                break;
            }
        }
    }
    return i;
}

typedef struct cr_ctx
{
    cmd_parms *cmd;
    ap_configfile_t *cfp;
    size_t startline;
    const char *endstr;
    char buf[HUGE_STRING_LEN];
} cr_ctx;


/* Okay, this deserves a little explaination -- in order for the errors that lua
 * generates to be 'accuarate', including line numbers, we basically inject
 * N line number new lines into the 'top' of the chunk reader.....
 *
 * be happy. this is cool.
 *
 */
static const char *lf =
    "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
#define N_LF 32

static const char *direct_chunkreader(lua_State *lvm, void *udata,
                                      size_t *plen)
{
    const char *p;
    struct cr_ctx *ctx = udata;

    if (ctx->startline) {
        *plen = ctx->startline > N_LF ? N_LF : ctx->startline;
        ctx->startline -= *plen;
        return lf;
    }
    *plen = config_getstr(ctx->cfp, ctx->buf, HUGE_STRING_LEN);

    for (p = ctx->buf; isspace(*p); ++p);
    if (p[0] == '<' && p[1] == '/') {
        apr_size_t i = 0;
        while (i < strlen(ctx->endstr)) {
            if (tolower(p[i + 2]) != ctx->endstr[i])
                return ctx->buf;
            ++i;
        }
        *plen = 0;
        return NULL;
    }
    /*fprintf(stderr, "buf read: %s\n", ctx->buf); */
    return ctx->buf;
}

static int ldump_writer(lua_State *L, const void *b, size_t size, void *B)
{
    (void) L;
    luaL_addlstring((luaL_Buffer *) B, (const char *) b, size);
    return 0;
}

typedef struct hack_section_baton
{
    const char *name;
    ap_lua_mapped_handler_spec *spec;
    int apr_hook_when;
} hack_section_baton;

/* You can be unhappy now.
 *
 * This is uncool.
 *
 * When you create a <Section handler in httpd, the only 'easy' way to create
 * a directory context is to parse the section, and convert it into a 'normal'
 * Configureation option, and then collapse the entire section, in memory,
 * back into the parent section -- from which you can then get the new directive
 * invoked.... anyways. evil. Rici taught me how to do this hack :-)
 */
static const char *hack_section_handler(cmd_parms *cmd, void *_cfg,
                                        const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    ap_directive_t *directive = cmd->directive;
    hack_section_baton *baton = directive->data;
    const char *key = apr_psprintf(cmd->pool, "%s_%d", baton->name, baton->apr_hook_when);

    apr_array_header_t *hook_specs = apr_hash_get(cfg->hooks, key,
                                                  APR_HASH_KEY_STRING);
    if (!hook_specs) {
        hook_specs = apr_array_make(cmd->pool, 2,
                                    sizeof(ap_lua_mapped_handler_spec *));
        apr_hash_set(cfg->hooks, key,
                     APR_HASH_KEY_STRING, hook_specs);
    }

    baton->spec->scope = cfg->vm_scope;

    *(ap_lua_mapped_handler_spec **) apr_array_push(hook_specs) = baton->spec;

    return NULL;
}

static const char *register_named_block_function_hook(const char *name,
                                                      cmd_parms *cmd,
                                                      void *mconfig,
                                                      const char *line)
{
    const char *function = NULL;
    ap_lua_mapped_handler_spec *spec;
    int when = APR_HOOK_MIDDLE;
    const char *endp = ap_strrchr_c(line, '>');

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           "> directive missing closing '>'", NULL);
    }

    line = apr_pstrndup(cmd->temp_pool, line, endp - line);

    if (line[0]) { 
        const char *word;
        word = ap_getword_conf(cmd->temp_pool, &line);
        if (*word) {
            function = apr_pstrdup(cmd->pool, word);
        }
        word = ap_getword_conf(cmd->temp_pool, &line);
        if (*word) {
            if (!strcasecmp("early", word)) { 
                when = AP_LUA_HOOK_FIRST;
            }
            else if (!strcasecmp("late", word)) {
                when = AP_LUA_HOOK_LAST;
            }
            else { 
                return apr_pstrcat(cmd->pool, cmd->cmd->name,
                                   "> 2nd argument must be 'early' or 'late'", NULL);
            }
        }
    }

    spec = apr_pcalloc(cmd->pool, sizeof(ap_lua_mapped_handler_spec));

    {
        cr_ctx ctx;
        lua_State *lvm;
        char *tmp;
        int rv;
        ap_directive_t **current;
        hack_section_baton *baton;

        spec->file_name = apr_psprintf(cmd->pool, "%s:%u",
                                       cmd->config_file->name,
                                       cmd->config_file->line_number);
        if (function) {
            spec->function_name = (char *) function;
        }
        else {
            function = NULL;
        }

        ctx.cmd = cmd;
        tmp = apr_pstrdup(cmd->pool, cmd->err_directive->directive + 1);
        ap_str_tolower(tmp);
        ctx.endstr = tmp;
        ctx.cfp = cmd->config_file;
        ctx.startline = cmd->config_file->line_number;

        /* This lua State is used only to compile the input strings -> bytecode, so we don't need anything extra. */
        lvm = luaL_newstate();

        lua_settop(lvm, 0);

        rv = lua_load(lvm, direct_chunkreader, &ctx, spec->file_name);

        if (rv != 0) {
            const char *errstr = apr_pstrcat(cmd->pool, "Lua Error:",
                                             lua_tostring(lvm, -1), NULL);
            lua_close(lvm);
            return errstr;
        }
        else {
            luaL_Buffer b;
            luaL_buffinit(lvm, &b);
            lua_dump(lvm, ldump_writer, &b);
            luaL_pushresult(&b);
            spec->bytecode_len = lua_strlen(lvm, -1);
            spec->bytecode = apr_pstrmemdup(cmd->pool, lua_tostring(lvm, -1),
                                            spec->bytecode_len);
            lua_close(lvm);
        }

        current = mconfig;

        /* Here, we have to replace our current config node for the next pass */
        if (!*current) {
            *current = apr_pcalloc(cmd->pool, sizeof(**current));
        }

        baton = apr_pcalloc(cmd->pool, sizeof(hack_section_baton));
        baton->name = name;
        baton->spec = spec;
        baton->apr_hook_when = when;

        (*current)->filename = cmd->config_file->name;
        (*current)->line_num = cmd->config_file->line_number;
        (*current)->directive = apr_pstrdup(cmd->pool, "Lua_____ByteCodeHack");
        (*current)->args = NULL;
        (*current)->data = baton;
    }

    return NULL;
}

static const char *register_named_file_function_hook(const char *name,
                                                     cmd_parms *cmd,
                                                     void *_cfg,
                                                     const char *file,
                                                     const char *function,
                                                     int apr_hook_when)
{
    ap_lua_mapped_handler_spec *spec;
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    const char *key = apr_psprintf(cmd->pool, "%s_%d", name, apr_hook_when);
    apr_array_header_t *hook_specs = apr_hash_get(cfg->hooks, key,
                                                  APR_HASH_KEY_STRING);

    if (!hook_specs) {
        hook_specs = apr_array_make(cmd->pool, 2,
                                    sizeof(ap_lua_mapped_handler_spec *));
        apr_hash_set(cfg->hooks, key, APR_HASH_KEY_STRING, hook_specs);
    }

    spec = apr_pcalloc(cmd->pool, sizeof(ap_lua_mapped_handler_spec));
    spec->file_name = apr_pstrdup(cmd->pool, file);
    spec->function_name = apr_pstrdup(cmd->pool, function);
    spec->scope = cfg->vm_scope;

    *(ap_lua_mapped_handler_spec **) apr_array_push(hook_specs) = spec;
    return NULL;
}
static const char *register_mapped_file_function_hook(const char *pattern,
                                                     cmd_parms *cmd,
                                                     void *_cfg,
                                                     const char *file,
                                                     const char *function)
{
    ap_lua_mapped_handler_spec *spec;
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    ap_regex_t *regex = apr_pcalloc(cmd->pool, sizeof(ap_regex_t));
    if (ap_regcomp(regex, pattern,0)) {
        return "Invalid regex pattern!";
    }

    spec = apr_pcalloc(cmd->pool, sizeof(ap_lua_mapped_handler_spec));
    spec->file_name = apr_pstrdup(cmd->pool, file);
    spec->function_name = apr_pstrdup(cmd->pool, function);
    spec->scope = cfg->vm_scope;
    spec->uri_pattern = regex;

    *(ap_lua_mapped_handler_spec **) apr_array_push(cfg->mapped_handlers) = spec;
    return NULL;
}
static const char *register_filter_function_hook(const char *filter,
                                                     cmd_parms *cmd,
                                                     void *_cfg,
                                                     const char *file,
                                                     const char *function,
                                                     int direction)
{
    ap_lua_filter_handler_spec *spec;
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
   
    spec = apr_pcalloc(cmd->pool, sizeof(ap_lua_filter_handler_spec));
    spec->file_name = apr_pstrdup(cmd->pool, file);
    spec->function_name = apr_pstrdup(cmd->pool, function);
    spec->filter_name = filter;

    *(ap_lua_filter_handler_spec **) apr_array_push(cfg->mapped_filters) = spec;
    /* TODO: Make it work on other types than just AP_FTYPE_RESOURCE? */
    if (direction == AP_LUA_FILTER_OUTPUT) {
        spec->direction = AP_LUA_FILTER_OUTPUT;
        ap_register_output_filter_protocol(filter, lua_output_filter_handle, NULL, AP_FTYPE_RESOURCE,
                                            AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH);
    }
    else {
        spec->direction = AP_LUA_FILTER_INPUT;
        ap_register_input_filter(filter, lua_input_filter_handle, NULL, AP_FTYPE_RESOURCE);
    }
    return NULL;
}
/* disabled (see reference below)
static int lua_check_user_id_harness_first(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "check_user_id", AP_LUA_HOOK_FIRST);
}
*/
static int lua_check_user_id_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "check_user_id", APR_HOOK_MIDDLE);
}
/* disabled (see reference below)
static int lua_check_user_id_harness_last(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "check_user_id", AP_LUA_HOOK_LAST);
}
*/

static int lua_translate_name_harness_first(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "translate_name", AP_LUA_HOOK_FIRST);
}
static int lua_translate_name_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "translate_name", APR_HOOK_MIDDLE);
}
static int lua_translate_name_harness_last(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "translate_name", AP_LUA_HOOK_LAST);
}

static int lua_fixup_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "fixups", APR_HOOK_MIDDLE);
}

static int lua_map_to_storage_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "map_to_storage", APR_HOOK_MIDDLE);
}

static int lua_type_checker_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "type_checker", APR_HOOK_MIDDLE);
}

static int lua_access_checker_harness_first(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "access_checker", AP_LUA_HOOK_FIRST);
}
static int lua_access_checker_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "access_checker", APR_HOOK_MIDDLE);
}
static int lua_access_checker_harness_last(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "access_checker", AP_LUA_HOOK_LAST);
}

static int lua_auth_checker_harness_first(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "auth_checker", AP_LUA_HOOK_FIRST);
}
static int lua_auth_checker_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "auth_checker", APR_HOOK_MIDDLE);
}
static int lua_auth_checker_harness_last(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "auth_checker", AP_LUA_HOOK_LAST);
}
static void lua_insert_filter_harness(request_rec *r)
{
    /* ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "LuaHookInsertFilter not yet implemented"); */
}

static int lua_log_transaction_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "log_transaction", APR_HOOK_FIRST);
}

static int lua_quick_harness(request_rec *r, int lookup)
{
    if (lookup) {
        return DECLINED;
    }
    return lua_request_rec_hook_harness(r, "quick", APR_HOOK_MIDDLE);
}

static const char *register_translate_name_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function,
                                                const char *when)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|
                                           NOT_IN_HTACCESS);
    int apr_hook_when = APR_HOOK_MIDDLE;
    if (err) {
        return err;
    }
    
    if (when) { 
        if (!strcasecmp(when, "early")) { 
            apr_hook_when = AP_LUA_HOOK_FIRST;
        } 
        else if (!strcasecmp(when, "late")) { 
            apr_hook_when = AP_LUA_HOOK_LAST;
        } 
        else { 
            return "Third argument must be 'early' or 'late'";
        }
    }

    return register_named_file_function_hook("translate_name", cmd, _cfg,
                                             file, function, apr_hook_when);
}

static const char *register_translate_name_block(cmd_parms *cmd, void *_cfg,
                                                 const char *line)
{
    return register_named_block_function_hook("translate_name", cmd, _cfg,
                                              line);
}


static const char *register_fixups_hook(cmd_parms *cmd, void *_cfg,
                                        const char *file,
                                        const char *function)
{
    return register_named_file_function_hook("fixups", cmd, _cfg, file,
                                             function, APR_HOOK_MIDDLE);
}
static const char *register_fixups_block(cmd_parms *cmd, void *_cfg,
                                         const char *line)
{
    return register_named_block_function_hook("fixups", cmd, _cfg, line);
}

static const char *register_map_to_storage_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function)
{
    return register_named_file_function_hook("map_to_storage", cmd, _cfg,
                                             file, function, APR_HOOK_MIDDLE);
}

static const char *register_log_transaction_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function)
{
    return register_named_file_function_hook("log_transaction", cmd, _cfg,
                                             file, function, APR_HOOK_FIRST);
}

static const char *register_map_to_storage_block(cmd_parms *cmd, void *_cfg,
                                                 const char *line)
{
    return register_named_block_function_hook("map_to_storage", cmd, _cfg,
                                              line);
}


static const char *register_check_user_id_hook(cmd_parms *cmd, void *_cfg,
                                               const char *file,
                                               const char *function,
                                               const char *when)
{
    int apr_hook_when = APR_HOOK_MIDDLE;
/* XXX: This does not currently work!!
    if (when) {
        if (!strcasecmp(when, "early")) {
            apr_hook_when = AP_LUA_HOOK_FIRST;
        }
        else if (!strcasecmp(when, "late")) {
            apr_hook_when = AP_LUA_HOOK_LAST;
        }
        else {
            return "Third argument must be 'early' or 'late'";
        }
    }
*/
    return register_named_file_function_hook("check_user_id", cmd, _cfg, file,
                                             function, apr_hook_when);
}
static const char *register_check_user_id_block(cmd_parms *cmd, void *_cfg,
                                                const char *line)
{
    return register_named_block_function_hook("check_user_id", cmd, _cfg,
                                              line);
}

static const char *register_type_checker_hook(cmd_parms *cmd, void *_cfg,
                                              const char *file,
                                              const char *function)
{
    return register_named_file_function_hook("type_checker", cmd, _cfg, file,
                                             function, APR_HOOK_MIDDLE);
}
static const char *register_type_checker_block(cmd_parms *cmd, void *_cfg,
                                               const char *line)
{
    return register_named_block_function_hook("type_checker", cmd, _cfg,
                                              line);
}

static const char *register_access_checker_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function,
                                                const char *when)
{
    int apr_hook_when = APR_HOOK_MIDDLE;

    if (when) {
        if (!strcasecmp(when, "early")) {
            apr_hook_when = AP_LUA_HOOK_FIRST;
        }
        else if (!strcasecmp(when, "late")) {
            apr_hook_when = AP_LUA_HOOK_LAST;
        }
        else {
            return "Third argument must be 'early' or 'late'";
        }
    }

    return register_named_file_function_hook("access_checker", cmd, _cfg,
                                             file, function, apr_hook_when);
}
static const char *register_access_checker_block(cmd_parms *cmd, void *_cfg,
                                                 const char *line)
{

    return register_named_block_function_hook("access_checker", cmd, _cfg,
                                              line);
}

static const char *register_auth_checker_hook(cmd_parms *cmd, void *_cfg,
                                              const char *file,
                                              const char *function,
                                              const char *when)
{
    int apr_hook_when = APR_HOOK_MIDDLE;

    if (when) {
        if (!strcasecmp(when, "early")) {
            apr_hook_when = AP_LUA_HOOK_FIRST;
        }
        else if (!strcasecmp(when, "late")) {
            apr_hook_when = AP_LUA_HOOK_LAST;
        }
        else {
            return "Third argument must be 'early' or 'late'";
        }
    }

    return register_named_file_function_hook("auth_checker", cmd, _cfg, file,
                                             function, apr_hook_when);
}
static const char *register_auth_checker_block(cmd_parms *cmd, void *_cfg,
                                               const char *line)
{
    return register_named_block_function_hook("auth_checker", cmd, _cfg,
                                              line);
}

static const char *register_insert_filter_hook(cmd_parms *cmd, void *_cfg,
                                               const char *file,
                                               const char *function)
{
    return "LuaHookInsertFilter not yet implemented";
}

static const char *register_quick_hook(cmd_parms *cmd, void *_cfg,
                                       const char *file, const char *function)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|
                                                NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    return register_named_file_function_hook("quick", cmd, _cfg, file,
                                             function, APR_HOOK_MIDDLE);
}
static const char *register_map_handler(cmd_parms *cmd, void *_cfg,
                                       const char* match, const char *file, const char *function)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|
                                                NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    if (!function) function = "handle";
    return register_mapped_file_function_hook(match, cmd, _cfg, file,
                                             function);
}
static const char *register_output_filter(cmd_parms *cmd, void *_cfg,
                                       const char* filter, const char *file, const char *function)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|
                                                NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    if (!function) function = "handle";
    return register_filter_function_hook(filter, cmd, _cfg, file,
                                             function, AP_LUA_FILTER_OUTPUT);
}
static const char *register_input_filter(cmd_parms *cmd, void *_cfg,
                                       const char* filter, const char *file, const char *function)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES|
                                                NOT_IN_HTACCESS);
    if (err) {
        return err;
    }
    if (!function) function = "handle";
    return register_filter_function_hook(filter, cmd, _cfg, file,
                                             function, AP_LUA_FILTER_INPUT);
}
static const char *register_quick_block(cmd_parms *cmd, void *_cfg,
                                        const char *line)
{
    return register_named_block_function_hook("quick", cmd, _cfg,
                                              line);
}



static const char *register_package_helper(cmd_parms *cmd, 
                                           const char *arg,
                                           apr_array_header_t *dir_array)
{
    apr_status_t rv;

    ap_lua_server_cfg *server_cfg =
        ap_get_module_config(cmd->server->module_config, &lua_module);

    char *fixed_filename;
    rv = apr_filepath_merge(&fixed_filename, 
                            server_cfg->root_path, 
                            arg,
                            APR_FILEPATH_NOTRELATIVE, 
                            cmd->pool);

    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "Unable to build full path to file, %s", arg);
    }

    *(const char **) apr_array_push(dir_array) = fixed_filename;
    return NULL;
}


/**
 * Called for config directive which looks like
 * LuaPackagePath /lua/package/path/mapped/thing/like/this/?.lua
 */
static const char *register_package_dir(cmd_parms *cmd, void *_cfg,
                                        const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;

    return register_package_helper(cmd, arg, cfg->package_paths);
}

/**
 * Called for config directive which looks like
 * LuaPackageCPath /lua/package/path/mapped/thing/like/this/?.so
 */
static const char *register_package_cdir(cmd_parms *cmd, 
                                         void *_cfg,
                                         const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;

    return register_package_helper(cmd, arg, cfg->package_cpaths);
}

static const char *register_lua_inherit(cmd_parms *cmd, 
                                      void *_cfg,
                                      const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    
    if (strcasecmp("none", arg) == 0) {
        cfg->inherit = AP_LUA_INHERIT_NONE;
    }
    else if (strcasecmp("parent-first", arg) == 0) {
        cfg->inherit = AP_LUA_INHERIT_PARENT_FIRST;
    }
    else if (strcasecmp("parent-last", arg) == 0) {
        cfg->inherit = AP_LUA_INHERIT_PARENT_LAST;
    }
    else { 
        return apr_psprintf(cmd->pool,
                            "LuaInherit type of '%s' not recognized, valid "
                            "options are 'none', 'parent-first', and 'parent-last'", 
                            arg);
    }
    return NULL;
}
static const char *register_lua_codecache(cmd_parms *cmd, 
                                      void *_cfg,
                                      const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    
    if (strcasecmp("never", arg) == 0) {
        cfg->codecache = AP_LUA_CACHE_NEVER;
    }
    else if (strcasecmp("stat", arg) == 0) {
        cfg->codecache = AP_LUA_CACHE_STAT;
    }
    else if (strcasecmp("forever", arg) == 0) {
        cfg->codecache = AP_LUA_CACHE_FOREVER;
    }
    else { 
        return apr_psprintf(cmd->pool,
                            "LuaCodeCache type of '%s' not recognized, valid "
                            "options are 'never', 'stat', and 'forever'", 
                            arg);
    }
    return NULL;
}
static const char *register_lua_scope(cmd_parms *cmd, 
                                      void *_cfg,
                                      const char *scope, 
                                      const char *min,
                                      const char *max)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    if (strcmp("once", scope) == 0) {
        cfg->vm_scope = AP_LUA_SCOPE_ONCE;
    }
    else if (strcmp("request", scope) == 0) {
        cfg->vm_scope = AP_LUA_SCOPE_REQUEST;
    }
    else if (strcmp("conn", scope) == 0) {
        cfg->vm_scope = AP_LUA_SCOPE_CONN;
    }
    else if (strcmp("thread", scope) == 0) {
#if !APR_HAS_THREADS
        return apr_psprintf(cmd->pool,
                            "Scope type of '%s' cannot be used because this "
                            "server does not have threading support "
                            "(APR_HAS_THREADS)" 
                            scope);
#endif
        cfg->vm_scope = AP_LUA_SCOPE_THREAD;
    }
    else if (strcmp("server", scope) == 0) {
        unsigned int vmin, vmax;
#if !APR_HAS_THREADS
        return apr_psprintf(cmd->pool,
                            "Scope type of '%s' cannot be used because this "
                            "server does not have threading support "
                            "(APR_HAS_THREADS)" 
                            scope);
#endif
        cfg->vm_scope = AP_LUA_SCOPE_SERVER;
        vmin = min ? atoi(min) : 1;
        vmax = max ? atoi(max) : 1;
        if (vmin == 0) {
            vmin = 1;
        }
        if (vmax < vmin) {
            vmax = vmin;
        }
        cfg->vm_min = vmin;
        cfg->vm_max = vmax;
    }
    else {
        return apr_psprintf(cmd->pool,
                            "Invalid value for LuaScope, '%s', acceptable "
                            "values are: 'once', 'request', 'conn'"
#if APR_HAS_THREADS
                            ", 'thread', 'server'"
#endif
                            ,scope);
    }

    return NULL;
}



static const char *register_lua_root(cmd_parms *cmd, void *_cfg,
                                     const char *root)
{
    /* ap_lua_dir_cfg* cfg = (ap_lua_dir_cfg*)_cfg; */
    ap_lua_server_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                                  &lua_module);

    cfg->root_path = root;
    return NULL;
}

const char *ap_lua_ssl_val(apr_pool_t *p, server_rec *s, conn_rec *c,
                           request_rec *r, const char *var)
{
    if (lua_ssl_val) { 
        return (const char *)lua_ssl_val(p, s, c, r, (char *)var);
    }
    return NULL;
}

int ap_lua_ssl_is_https(conn_rec *c)
{
    return lua_ssl_is_https ? lua_ssl_is_https(c) : 0;
}

/*******************************/

static const char *lua_authz_parse(cmd_parms *cmd, const char *require_line,
                                   const void **parsed_require_line)
{
    const char *provider_name;
    lua_authz_provider_spec *spec;

    apr_pool_userdata_get((void**)&provider_name, AUTHZ_PROVIDER_NAME_NOTE,
                          cmd->temp_pool);
    ap_assert(provider_name != NULL);

    spec = apr_hash_get(lua_authz_providers, provider_name, APR_HASH_KEY_STRING);
    ap_assert(spec != NULL);

    if (require_line && *require_line) {
        const char *arg;
        spec->args = apr_array_make(cmd->pool, 2, sizeof(const char *));
        while ((arg = ap_getword_conf(cmd->pool, &require_line)) && *arg) {
            APR_ARRAY_PUSH(spec->args, const char *) = arg;
        }
    }

    *parsed_require_line = spec;
    return NULL;
}

static authz_status lua_authz_check(request_rec *r, const char *require_line,
                                    const void *parsed_require_line)
{
    apr_pool_t *pool;
    ap_lua_vm_spec *spec;
    lua_State *L;
    ap_lua_server_cfg *server_cfg = ap_get_module_config(r->server->module_config,
                                                         &lua_module);
    const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                     &lua_module);
    const lua_authz_provider_spec *prov_spec = parsed_require_line;
    int result;
    int nargs = 0;

    spec = create_vm_spec(&pool, r, cfg, server_cfg, prov_spec->file_name,
                          NULL, 0, prov_spec->function_name, "authz provider");

    L = ap_lua_get_lua_state(pool, spec, r);
    if (L == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02314)
                      "Unable to compile VM for authz provider %s", prov_spec->name);
        return AUTHZ_GENERAL_ERROR;
    }
    lua_getglobal(L, prov_spec->function_name);
    if (!lua_isfunction(L, -1)) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(02319)
                      "Unable to find entry function '%s' in %s (not a valid function)",
                      prov_spec->function_name, prov_spec->file_name);
        ap_lua_release_state(L, spec, r);
        return AUTHZ_GENERAL_ERROR;
    }
    ap_lua_run_lua_request(L, r);
    if (prov_spec->args) {
        int i;
        if (!lua_checkstack(L, prov_spec->args->nelts)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02315)
                          "Error: authz provider %s: too many arguments", prov_spec->name);
            ap_lua_release_state(L, spec, r);
            return AUTHZ_GENERAL_ERROR;
        }
        for (i = 0; i < prov_spec->args->nelts; i++) {
            const char *arg = APR_ARRAY_IDX(prov_spec->args, i, const char *);
            lua_pushstring(L, arg);
        }
        nargs = prov_spec->args->nelts;
    }
    if (lua_pcall(L, 1 + nargs, 1, 0)) {
        const char *err = lua_tostring(L, -1);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02316)
                      "Error executing authz provider %s: %s", prov_spec->name, err);
        ap_lua_release_state(L, spec, r);
        return AUTHZ_GENERAL_ERROR;
    }
    if (!lua_isnumber(L, -1)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02317)
                      "Error: authz provider %s did not return integer", prov_spec->name);
        ap_lua_release_state(L, spec, r);
        return AUTHZ_GENERAL_ERROR;
    }
    result = lua_tointeger(L, -1);
    ap_lua_release_state(L, spec, r);
    switch (result) {
        case AUTHZ_DENIED:
        case AUTHZ_GRANTED:
        case AUTHZ_NEUTRAL:
        case AUTHZ_GENERAL_ERROR:
        case AUTHZ_DENIED_NO_USER:
            return result;
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02318)
                          "Error: authz provider %s: invalid return value %d",
                          prov_spec->name, result);
    }
    return AUTHZ_GENERAL_ERROR;
}

static const authz_provider lua_authz_provider =
{
    &lua_authz_check,
    &lua_authz_parse,
};

static const char *register_authz_provider(cmd_parms *cmd, void *_cfg,
                                           const char *name, const char *file,
                                           const char *function)
{
    lua_authz_provider_spec *spec;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
        return err;

    spec = apr_pcalloc(cmd->pool, sizeof(*spec));
    spec->name = name;
    spec->file_name = file;
    spec->function_name = function;

    apr_hash_set(lua_authz_providers, name, APR_HASH_KEY_STRING, spec);
    ap_register_auth_provider(cmd->pool, AUTHZ_PROVIDER_GROUP, name,
                              AUTHZ_PROVIDER_VERSION,
                              &lua_authz_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
    return NULL;
}


command_rec lua_commands[] = {

    AP_INIT_TAKE1("LuaRoot", register_lua_root, NULL, OR_ALL,
                  "Specify the base path for resolving relative paths for mod_lua directives"),

    AP_INIT_TAKE1("LuaPackagePath", register_package_dir, NULL, OR_ALL,
                  "Add a directory to lua's package.path"),

    AP_INIT_TAKE1("LuaPackageCPath", register_package_cdir, NULL, OR_ALL,
                  "Add a directory to lua's package.cpath"),

    AP_INIT_TAKE3("LuaAuthzProvider", register_authz_provider, NULL, RSRC_CONF|EXEC_ON_READ,
                  "Provide an authorization provider"),

    AP_INIT_TAKE23("LuaHookTranslateName", register_translate_name_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the translate name phase of request processing"),

    AP_INIT_RAW_ARGS("<LuaHookTranslateName", register_translate_name_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the translate name phase of request processing"),

    AP_INIT_TAKE2("LuaHookFixups", register_fixups_hook, NULL, OR_ALL,
                  "Provide a hook for the fixups phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookFixups", register_fixups_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a inline hook for the fixups phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookMapToStorage", register_map_to_storage_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the map_to_storage phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookMapToStorage", register_map_to_storage_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the map_to_storage phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE23("LuaHookCheckUserID", register_check_user_id_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the check_user_id phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookCheckUserID", register_check_user_id_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the check_user_id phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookTypeChecker", register_type_checker_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the type_checker phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookTypeChecker", register_type_checker_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the type_checker phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE23("LuaHookAccessChecker", register_access_checker_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the access_checker phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookAccessChecker", register_access_checker_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the access_checker phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE23("LuaHookAuthChecker", register_auth_checker_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the auth_checker phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookAuthChecker", register_auth_checker_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the auth_checker phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookInsertFilter", register_insert_filter_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the insert_filter phase of request processing"),
    
    AP_INIT_TAKE2("LuaHookLog", register_log_transaction_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the logging phase of request processing"),

    AP_INIT_TAKE123("LuaScope", register_lua_scope, NULL, OR_ALL,
                    "One of once, request, conn, server -- default is once"),

    AP_INIT_TAKE1("LuaInherit", register_lua_inherit, NULL, OR_ALL,
     "Controls how Lua scripts in parent contexts are merged with the current " 
     " context: none|parent-last|parent-first (default: parent-first) "),
    
    AP_INIT_TAKE1("LuaCodeCache", register_lua_codecache, NULL, OR_ALL,
     "Controls the behavior of the in-memory code cache " 
     " context: stat|forever|never (default: stat) "),

    AP_INIT_TAKE2("LuaQuickHandler", register_quick_hook, NULL, OR_ALL,
                  "Provide a hook for the quick handler of request processing"),
    AP_INIT_RAW_ARGS("<LuaQuickHandler", register_quick_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the quick handler of request processing"),
    AP_INIT_RAW_ARGS("Lua_____ByteCodeHack", hack_section_handler, NULL,
                     OR_ALL,
                     "(internal) Byte code handler"),
    AP_INIT_TAKE23("LuaMapHandler", register_map_handler, NULL, OR_ALL,
                  "Maps a path to a lua handler"),
    AP_INIT_TAKE3("LuaOutputFilter", register_output_filter, NULL, OR_ALL,
                  "Registers a Lua function as an output filter"),
    AP_INIT_TAKE3("LuaInputFilter", register_input_filter, NULL, OR_ALL,
                  "Registers a Lua function as an input filter"),
    {NULL}
};


static void *create_dir_config(apr_pool_t *p, char *dir)
{
    ap_lua_dir_cfg *cfg = apr_pcalloc(p, sizeof(ap_lua_dir_cfg));
    cfg->package_paths = apr_array_make(p, 2, sizeof(char *));
    cfg->package_cpaths = apr_array_make(p, 2, sizeof(char *));
    cfg->mapped_handlers =
        apr_array_make(p, 1, sizeof(ap_lua_mapped_handler_spec *));
    cfg->mapped_filters =
        apr_array_make(p, 1, sizeof(ap_lua_filter_handler_spec *));
    cfg->pool = p;
    cfg->hooks = apr_hash_make(p);
    cfg->dir = apr_pstrdup(p, dir);
    cfg->vm_scope = AP_LUA_SCOPE_UNSET;
    cfg->codecache = AP_LUA_CACHE_UNSET;
    cfg->vm_min = 0;
    cfg->vm_max = 0;

    return cfg;
}

static int create_request_config(request_rec *r)
{
    ap_lua_request_cfg *cfg = apr_palloc(r->pool, sizeof(ap_lua_request_cfg));
    cfg->mapped_request_details = NULL;
    cfg->request_scoped_vms = apr_hash_make(r->pool);
    ap_set_module_config(r->request_config, &lua_module, cfg);
    return OK;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{

    ap_lua_server_cfg *cfg = apr_pcalloc(p, sizeof(ap_lua_server_cfg));
    cfg->vm_reslists = apr_hash_make(p);
    apr_thread_rwlock_create(&cfg->vm_reslists_lock, p);
    cfg->root_path = NULL;

    return cfg;
}

static int lua_request_hook(lua_State *L, request_rec *r)
{
    ap_lua_push_request(L, r);
    return OK;
}

static int lua_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp)
{
    ap_mutex_register(pconf, "lua-ivm-shm", NULL, APR_LOCK_DEFAULT, 0);
    return OK;
}

static int lua_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    apr_pool_t **pool;
    const char *tempdir;
    apr_status_t rs;

    lua_ssl_val = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    lua_ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
        return OK;

    /* Create ivm mutex */
    rs = ap_global_mutex_create(&lua_ivm_mutex, NULL, "lua-ivm-shm", NULL,
                            s, pconf, 0);
    if (APR_SUCCESS != rs) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create shared memory space */
    rs = apr_temp_dir_get(&tempdir, pconf);
    if (rs != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, s,
                 "mod_lua IVM: Failed to find temporary directory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    lua_ivm_shmfile = apr_psprintf(pconf, "%s/httpd_lua_shm.%ld", tempdir,
                           (long int)getpid());
    rs = apr_shm_create(&lua_ivm_shm, sizeof(apr_pool_t**),
                    (const char *) lua_ivm_shmfile, pconf);
    if (rs != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, s,
            "mod_lua: Failed to create shared memory segment on file %s",
                     lua_ivm_shmfile);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    pool = (apr_pool_t **)apr_shm_baseaddr_get(lua_ivm_shm);
    apr_pool_create(pool, pconf);
    apr_pool_cleanup_register(pconf, NULL, shm_cleanup_wrapper,
                          apr_pool_cleanup_null);
    return OK;
}
static void *overlay_hook_specs(apr_pool_t *p,
                                        const void *key,
                                        apr_ssize_t klen,
                                        const void *overlay_val,
                                        const void *base_val,
                                        const void *data)
{
    const apr_array_header_t *overlay_info = (const apr_array_header_t*)overlay_val;
    const apr_array_header_t *base_info = (const apr_array_header_t*)base_val;
    return apr_array_append(p, base_info, overlay_info);
}

static void *merge_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    ap_lua_dir_cfg *a, *base, *overrides;

    a         = (ap_lua_dir_cfg *)apr_pcalloc(p, sizeof(ap_lua_dir_cfg));
    base      = (ap_lua_dir_cfg*)basev;
    overrides = (ap_lua_dir_cfg*)overridesv;

    a->pool = overrides->pool;
    a->dir = apr_pstrdup(p, overrides->dir);

    a->vm_scope = (overrides->vm_scope == AP_LUA_SCOPE_UNSET) ? base->vm_scope: overrides->vm_scope;
    a->inherit = (overrides->inherit == AP_LUA_INHERIT_UNSET) ? base->inherit : overrides->inherit;
    a->codecache = (overrides->codecache == AP_LUA_CACHE_UNSET) ? base->codecache : overrides->codecache;
    
    a->vm_min = (overrides->vm_min == 0) ? base->vm_min : overrides->vm_min;
    a->vm_max = (overrides->vm_max == 0) ? base->vm_max : overrides->vm_max;

    if (a->inherit == AP_LUA_INHERIT_UNSET || a->inherit == AP_LUA_INHERIT_PARENT_FIRST) { 
        a->package_paths = apr_array_append(p, base->package_paths, overrides->package_paths);
        a->package_cpaths = apr_array_append(p, base->package_cpaths, overrides->package_cpaths);
        a->mapped_handlers = apr_array_append(p, base->mapped_handlers, overrides->mapped_handlers);
        a->mapped_filters = apr_array_append(p, base->mapped_filters, overrides->mapped_filters);
        a->hooks = apr_hash_merge(p, overrides->hooks, base->hooks, overlay_hook_specs, NULL);
    }
    else if (a->inherit == AP_LUA_INHERIT_PARENT_LAST) { 
        a->package_paths = apr_array_append(p, overrides->package_paths, base->package_paths);
        a->package_cpaths = apr_array_append(p, overrides->package_cpaths, base->package_cpaths);
        a->mapped_handlers = apr_array_append(p, overrides->mapped_handlers, base->mapped_handlers);
        a->mapped_filters = apr_array_append(p, overrides->mapped_filters, base->mapped_filters);
        a->hooks = apr_hash_merge(p, base->hooks, overrides->hooks, overlay_hook_specs, NULL);
    }
    else { 
        a->package_paths = overrides->package_paths;
        a->package_cpaths = overrides->package_cpaths;
        a->mapped_handlers= overrides->mapped_handlers;
        a->mapped_filters= overrides->mapped_filters;
        a->hooks= overrides->hooks;
    }

    return a;
}

static void lua_register_hooks(apr_pool_t *p)
{
    /* ap_register_output_filter("luahood", luahood, NULL, AP_FTYPE_RESOURCE); */
    ap_hook_handler(lua_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(create_request_config, NULL, NULL,
                           APR_HOOK_MIDDLE);

    /* http_request.h hooks */
    ap_hook_translate_name(lua_translate_name_harness_first, NULL, NULL,
                           AP_LUA_HOOK_FIRST);
    ap_hook_translate_name(lua_translate_name_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_translate_name(lua_translate_name_harness_last, NULL, NULL,
                           AP_LUA_HOOK_LAST);

    ap_hook_fixups(lua_fixup_harness, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_map_to_storage(lua_map_to_storage_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);

/*  XXX: Does not work :(  
 *  ap_hook_check_user_id(lua_check_user_id_harness_first, NULL, NULL,
                          AP_LUA_HOOK_FIRST);
 */
    ap_hook_check_user_id(lua_check_user_id_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);
/*  XXX: Does not work :(
 * ap_hook_check_user_id(lua_check_user_id_harness_last, NULL, NULL,
                          AP_LUA_HOOK_LAST);
*/
    ap_hook_type_checker(lua_type_checker_harness, NULL, NULL,
                         APR_HOOK_MIDDLE);

    ap_hook_access_checker(lua_access_checker_harness_first, NULL, NULL,
                           AP_LUA_HOOK_FIRST);
    ap_hook_access_checker(lua_access_checker_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_access_checker(lua_access_checker_harness_last, NULL, NULL,
                           AP_LUA_HOOK_LAST);
    ap_hook_auth_checker(lua_auth_checker_harness_first, NULL, NULL,
                         AP_LUA_HOOK_FIRST);
    ap_hook_auth_checker(lua_auth_checker_harness, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_auth_checker(lua_auth_checker_harness_last, NULL, NULL,
                         AP_LUA_HOOK_LAST);

    ap_hook_insert_filter(lua_insert_filter_harness, NULL, NULL,
                          APR_HOOK_MIDDLE);
    ap_hook_quick_handler(lua_quick_harness, NULL, NULL, APR_HOOK_FIRST);

    ap_hook_post_config(lua_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(lua_pre_config, NULL, NULL, APR_HOOK_MIDDLE);

    APR_OPTIONAL_HOOK(ap_lua, lua_open, lua_open_hook, NULL, NULL,
                      APR_HOOK_REALLY_FIRST);

    APR_OPTIONAL_HOOK(ap_lua, lua_request, lua_request_hook, NULL, NULL,
                      APR_HOOK_REALLY_FIRST);
    ap_hook_handler(lua_map_handler, NULL, NULL, AP_LUA_HOOK_FIRST);
    
    /* Hook this right before FallbackResource kicks in */
    ap_hook_fixups(lua_map_handler_fixups, NULL, NULL, AP_LUA_HOOK_LAST-2);
#if APR_HAS_THREADS
    ap_hook_child_init(ap_lua_init_mutex, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    /* providers */
    lua_authz_providers = apr_hash_make(p);
    
    /* Logging catcher */
    ap_hook_log_transaction(lua_log_transaction_harness,NULL,NULL,
                            APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(lua) = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-dir    config structures */
    merge_dir_config,           /* merge  per-dir    config structures */
    create_server_config,       /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    lua_commands,               /* table of config file commands       */
    lua_register_hooks          /* register hooks                      */
};
