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
#include "http_log.h"
#include "apr_uuid.h"
#include "lua_config.h"
#include "apr_file_info.h"
#include "mod_auth.h"

APLOG_USE_MODULE(lua);

#ifndef AP_LUA_MODULE_EXT
#if defined(NETWARE) 
#define AP_LUA_MODULE_EXT ".nlm"
#elif defined(WIN32)
#define AP_LUA_MODULE_EXT ".dll"
#elif (defined(__hpux__) || defined(__hpux)) && !defined(__ia64)
#define AP_LUA_MODULE_EXT ".sl"
#else
#define AP_LUA_MODULE_EXT ".so"
#endif
#endif

#if APR_HAS_THREADS
    apr_thread_mutex_t *ap_lua_mutex;
#endif
extern apr_global_mutex_t *lua_ivm_mutex;
    
void ap_lua_init_mutex(apr_pool_t *pool, server_rec *s) 
{
    apr_status_t rv;
    
    /* global IVM mutex */
    rv = apr_global_mutex_child_init(&lua_ivm_mutex,
                                     apr_global_mutex_lockfile(lua_ivm_mutex),
                                     pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(03016)
                     "mod_lua: Failed to reopen mutex lua-ivm-shm in child");
        exit(1); /* bah :( */
    }
    
    /* Server pool mutex */
#if APR_HAS_THREADS
    apr_thread_mutex_create(&ap_lua_mutex, APR_THREAD_MUTEX_DEFAULT, pool);
#endif
}

/* forward dec'l from this file */

#if 0
static void pstack_dump(lua_State *L, apr_pool_t *r, int level,
                        const char *msg)
{
    int i;
    int top = lua_gettop(L);

    ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03211)
                  "Lua Stack Dump: [%s]", msg);

    for (i = 1; i <= top; i++) {
        int t = lua_type(L, i);
        switch (t) {
        case LUA_TSTRING:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03212)
                              "%d:  '%s'", i, lua_tostring(L, i));
                break;
            }
        case LUA_TUSERDATA:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03213)
                              "%d:  userdata", i);
                break;
            }
        case LUA_TLIGHTUSERDATA:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03214)
                              "%d:  lightuserdata", i);
                break;
            }
        case LUA_TNIL:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03215)
                              "%d:  NIL", i);
                break;
            }
        case LUA_TNONE:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03216)
                              "%d:  None", i);
                break;
            }
        case LUA_TBOOLEAN:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03217)
                              "%d:  %s",
                              i, lua_toboolean(L, i) ? "true" : "false");
                break;
            }
        case LUA_TNUMBER:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03218)
                              "%d:  %g", i, lua_tonumber(L, i));
                break;
            }
        case LUA_TTABLE:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03219)
                              "%d:  <table>", i);
                break;
            }
        case LUA_TTHREAD:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03220)
                              "%d:  <thread>", i);
                break;
            }
        case LUA_TFUNCTION:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03221)
                              "%d:  <function>", i);
                break;
            }
        default:{
                ap_log_perror(APLOG_MARK, level, 0, r, APLOGNO(03222)
                              "%d:  unknown: [%s]", i, lua_typename(L, i));
                break;
            }
        }
    }
}
#endif

/* BEGIN modules*/

/* BEGIN apache lmodule  */

#define makeintegerfield(L, n) lua_pushinteger(L, n); lua_setfield(L, -2, #n)

void ap_lua_load_apache2_lmodule(lua_State *L)
{
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "loaded");
    lua_newtable(L);
    lua_setfield(L, -2, "apache2");
    lua_setglobal(L, "apache2");
    lua_pop(L, 1);              /* empty stack */

    lua_getglobal(L, "apache2");

    lua_pushstring(L, ap_get_server_banner());
    lua_setfield(L, -2, "version");

    makeintegerfield(L, OK);
    makeintegerfield(L, DECLINED);
    makeintegerfield(L, DONE);
    makeintegerfield(L, HTTP_MOVED_TEMPORARILY);
    makeintegerfield(L, PROXYREQ_NONE);
    makeintegerfield(L, PROXYREQ_PROXY);
    makeintegerfield(L, PROXYREQ_REVERSE);
    makeintegerfield(L, PROXYREQ_RESPONSE);
    makeintegerfield(L, PROXYREQ_RESPONSE);
    makeintegerfield(L, AUTHZ_DENIED);
    makeintegerfield(L, AUTHZ_GRANTED);
    makeintegerfield(L, AUTHZ_NEUTRAL);
    makeintegerfield(L, AUTHZ_GENERAL_ERROR);
    makeintegerfield(L, AUTHZ_DENIED_NO_USER);
    
    /*
       makeintegerfield(L, HTTP_CONTINUE);
       makeintegerfield(L, HTTP_SWITCHING_PROTOCOLS);
       makeintegerfield(L, HTTP_PROCESSING);
       makeintegerfield(L, HTTP_OK);
       makeintegerfield(L, HTTP_CREATED);
       makeintegerfield(L, HTTP_ACCEPTED);
       makeintegerfield(L, HTTP_NON_AUTHORITATIVE);
       makeintegerfield(L, HTTP_NO_CONTENT);
       makeintegerfield(L, HTTP_RESET_CONTENT);
       makeintegerfield(L, HTTP_PARTIAL_CONTENT);
       makeintegerfield(L, HTTP_MULTI_STATUS);
       makeintegerfield(L, HTTP_ALREADY_REPORTED);
       makeintegerfield(L, HTTP_IM_USED);
       makeintegerfield(L, HTTP_MULTIPLE_CHOICES);
       makeintegerfield(L, HTTP_MOVED_PERMANENTLY);
       makeintegerfield(L, HTTP_MOVED_TEMPORARILY);
       makeintegerfield(L, HTTP_SEE_OTHER);
       makeintegerfield(L, HTTP_NOT_MODIFIED);
       makeintegerfield(L, HTTP_USE_PROXY);
       makeintegerfield(L, HTTP_TEMPORARY_REDIRECT);
       makeintegerfield(L, HTTP_PERMANENT_REDIRECT);
       makeintegerfield(L, HTTP_BAD_REQUEST);
       makeintegerfield(L, HTTP_UNAUTHORIZED);
       makeintegerfield(L, HTTP_PAYMENT_REQUIRED);
       makeintegerfield(L, HTTP_FORBIDDEN);
       makeintegerfield(L, HTTP_NOT_FOUND);
       makeintegerfield(L, HTTP_METHOD_NOT_ALLOWED);
       makeintegerfield(L, HTTP_NOT_ACCEPTABLE);
       makeintegerfield(L, HTTP_PROXY_AUTHENTICATION_REQUIRED);
       makeintegerfield(L, HTTP_REQUEST_TIME_OUT);
       makeintegerfield(L, HTTP_CONFLICT);
       makeintegerfield(L, HTTP_GONE);
       makeintegerfield(L, HTTP_LENGTH_REQUIRED);
       makeintegerfield(L, HTTP_PRECONDITION_FAILED);
       makeintegerfield(L, HTTP_REQUEST_ENTITY_TOO_LARGE);
       makeintegerfield(L, HTTP_REQUEST_URI_TOO_LARGE);
       makeintegerfield(L, HTTP_UNSUPPORTED_MEDIA_TYPE);
       makeintegerfield(L, HTTP_RANGE_NOT_SATISFIABLE);
       makeintegerfield(L, HTTP_EXPECTATION_FAILED);
       makeintegerfield(L, HTTP_UNPROCESSABLE_ENTITY);
       makeintegerfield(L, HTTP_LOCKED);
       makeintegerfield(L, HTTP_FAILED_DEPENDENCY);
       makeintegerfield(L, HTTP_UPGRADE_REQUIRED);
       makeintegerfield(L, HTTP_PRECONDITION_REQUIRED);
       makeintegerfield(L, HTTP_TOO_MANY_REQUESTS);
       makeintegerfield(L, HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
       makeintegerfield(L, HTTP_INTERNAL_SERVER_ERROR);
       makeintegerfield(L, HTTP_NOT_IMPLEMENTED);
       makeintegerfield(L, HTTP_BAD_GATEWAY);
       makeintegerfield(L, HTTP_SERVICE_UNAVAILABLE);
       makeintegerfield(L, HTTP_GATEWAY_TIME_OUT);
       makeintegerfield(L, HTTP_VERSION_NOT_SUPPORTED);
       makeintegerfield(L, HTTP_VARIANT_ALSO_VARIES);
       makeintegerfield(L, HTTP_INSUFFICIENT_STORAGE);
       makeintegerfield(L, HTTP_LOOP_DETECTED);
       makeintegerfield(L, HTTP_NOT_EXTENDED);
       makeintegerfield(L, HTTP_NETWORK_AUTHENTICATION_REQUIRED);
     */
}

/* END apache2 lmodule */

/*  END library functions */

/* callback for cleaning up a lua vm when pool is closed */
static apr_status_t cleanup_lua(void *l)
{
    AP_DEBUG_ASSERT(l != NULL);
    lua_close((lua_State *) l);
    return APR_SUCCESS;
}

static apr_status_t server_cleanup_lua(void *resource, void *params, apr_pool_t *pool)
{
    ap_lua_server_spec* spec = (ap_lua_server_spec*) resource;
    AP_DEBUG_ASSERT(spec != NULL);
    if (spec->L != NULL) {
        lua_close((lua_State *) spec->L);
    }
    return APR_SUCCESS;
}

/*
        munge_path(L, 
                   "path", 
                   "?.lua", 
                   "./?.lua", 
                   lifecycle_pool,
                   spec->package_paths, 
                   spec->file);
*/
/**
 * field -> "path" or "cpath"
 * sub_pat -> "?.lua"
 * rep_pat -> "./?.lua"
 * pool -> lifecycle pool for allocations
 * paths -> things to add
 * file -> ???
 */
static void munge_path(lua_State *L,
                       const char *field,
                       const char *sub_pat,
                       const char *rep_pat,
                       apr_pool_t *pool,
                       apr_array_header_t *paths,
                       const char *file)
{
    const char *current;
    const char *parent_dir;
    const char *pattern;
    const char *modified;
    char *part;

    lua_getglobal(L, "package");
    lua_getfield(L, -1, field);
    
    current = lua_tostring(L, -1);

    parent_dir = ap_make_dirstr_parent(pool, file);
 
    pattern = apr_pstrcat(pool, parent_dir, sub_pat, NULL);

    luaL_gsub(L, current, rep_pat, pattern);
    lua_setfield(L, -3, field);
    lua_getfield(L, -2, field);
    modified = lua_tostring(L, -1);


    lua_pop(L, 2);

    part = apr_pstrcat(pool, modified, ";", apr_array_pstrcat(pool, paths, ';'),
                       NULL);

    lua_pushstring(L, part);
    lua_setfield(L, -2, field);
    lua_pop(L, 1);              /* pop "package" off the stack     */
}

#ifdef AP_ENABLE_LUAJIT
static int loadjitmodule(lua_State *L, apr_pool_t *lifecycle_pool)
{
    lua_getglobal(L, "require");
    lua_pushliteral(L, "jit.");
    lua_pushvalue(L, -3);
    lua_concat(L, 2);
    if (lua_pcall(L, 1, 1, 0)) {
        const char *msg = lua_tostring(L, -1);
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, lifecycle_pool, APLOGNO(01480)
                      "Failed to init LuaJIT: %s", msg);
        return 1;
    }
    lua_getfield(L, -1, "start");
    lua_remove(L, -2);  /* drop module table */
    return 0;
}

#endif

static apr_status_t vm_construct(lua_State **vm, void *params, apr_pool_t *lifecycle_pool)
{
    lua_State* L;

    ap_lua_vm_spec *spec = params;

    L = luaL_newstate();
#ifdef AP_ENABLE_LUAJIT
    luaopen_jit(L);
#endif
    luaL_openlibs(L);
    if (spec->package_paths) {
        munge_path(L, 
                   "path", "?.lua", "./?.lua", 
                   lifecycle_pool,
                   spec->package_paths, 
                   spec->file);
    }
    if (spec->package_cpaths) {
        munge_path(L,
                   "cpath", "?" AP_LUA_MODULE_EXT, "./?" AP_LUA_MODULE_EXT,
                   lifecycle_pool,
                   spec->package_cpaths,
                   spec->file);
    }

    if (spec->cb) {
        spec->cb(L, lifecycle_pool, spec->cb_arg);
    }


    if (spec->bytecode && spec->bytecode_len > 0) {
        luaL_loadbuffer(L, spec->bytecode, spec->bytecode_len, spec->file);
        lua_pcall(L, 0, LUA_MULTRET, 0);
    }
    else {
        int rc;
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, lifecycle_pool, APLOGNO(01481)
            "loading lua file %s", spec->file);
        rc = luaL_loadfile(L, spec->file);
        if (rc != 0) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, lifecycle_pool, APLOGNO(01482)
                          "Error loading %s: %s", spec->file,
                          rc == LUA_ERRMEM ? "memory allocation error"
                                           : lua_tostring(L, 0));
            return APR_EBADF;
        }
        if ( lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_ERRRUN ) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, lifecycle_pool, APLOGNO(02613)
                          "Error loading %s: %s", spec->file,
                            lua_tostring(L, -1));
            return APR_EBADF;
        }
    }

#ifdef AP_ENABLE_LUAJIT
    loadjitmodule(L, lifecycle_pool);
#endif
    lua_pushlightuserdata(L, lifecycle_pool);
    lua_setfield(L, LUA_REGISTRYINDEX, "Apache2.Wombat.pool");
    *vm = L;

    return APR_SUCCESS;
}

static ap_lua_vm_spec* copy_vm_spec(apr_pool_t* pool, ap_lua_vm_spec* spec) 
{
    ap_lua_vm_spec* copied_spec = apr_pcalloc(pool, sizeof(ap_lua_vm_spec));
    copied_spec->bytecode_len = spec->bytecode_len;
    copied_spec->bytecode = apr_pstrdup(pool, spec->bytecode);
    copied_spec->cb = spec->cb;
    copied_spec->cb_arg = NULL;
    copied_spec->file = apr_pstrdup(pool, spec->file);
    copied_spec->package_cpaths = apr_array_copy(pool, spec->package_cpaths);
    copied_spec->package_paths = apr_array_copy(pool, spec->package_paths);
    copied_spec->pool = pool;
    copied_spec->scope = AP_LUA_SCOPE_SERVER;
    copied_spec->codecache = spec->codecache;
    return copied_spec;
}

static apr_status_t server_vm_construct(lua_State **resource, void *params, apr_pool_t *pool)
{
    lua_State* L;
    ap_lua_server_spec* spec = apr_pcalloc(pool, sizeof(ap_lua_server_spec));
    *resource = NULL;
    if (vm_construct(&L, params, pool) == APR_SUCCESS) {
        spec->finfo = apr_pcalloc(pool, sizeof(ap_lua_finfo));
        if (L != NULL) {
            spec->L = L;
            *resource = (void*) spec;
            lua_pushlightuserdata(L, spec);
            lua_setfield(L, LUA_REGISTRYINDEX, "Apache2.Lua.server_spec");
            return APR_SUCCESS;
        }
    }
    return APR_EGENERAL;
}

/**
 * Function used to create a lua_State instance bound into the web
 * server in the appropriate scope.
 */
lua_State *ap_lua_get_lua_state(apr_pool_t *lifecycle_pool,
                                               ap_lua_vm_spec *spec, request_rec* r)
{
    lua_State *L = NULL;
    ap_lua_finfo *cache_info = NULL;
    int tryCache = 0;
    
    if (spec->scope == AP_LUA_SCOPE_SERVER) {
        char *hash;
        apr_reslist_t* reslist = NULL;
        ap_lua_server_spec* sspec = NULL;
        hash = apr_psprintf(r->pool, "reslist:%s", spec->file);
#if APR_HAS_THREADS
        apr_thread_mutex_lock(ap_lua_mutex);
#endif
        if (apr_pool_userdata_get((void **)&reslist, hash,
                                  r->server->process->pool) == APR_SUCCESS) {
            if (reslist != NULL) {
                if (apr_reslist_acquire(reslist, (void**) &sspec) == APR_SUCCESS) {
                    L = sspec->L;
                    cache_info = sspec->finfo;
                }
            }
        }
        if (L == NULL) {
            ap_lua_vm_spec* server_spec = copy_vm_spec(r->server->process->pool, spec);
            if (
                    apr_reslist_create(&reslist, spec->vm_min, spec->vm_max, spec->vm_max, 0, 
                                (apr_reslist_constructor) server_vm_construct, 
                                (apr_reslist_destructor) server_cleanup_lua, 
                                server_spec, r->server->process->pool)
                    == APR_SUCCESS && reslist != NULL) {
                apr_pool_userdata_set(reslist, hash, NULL,
                                            r->server->process->pool);
                if (apr_reslist_acquire(reslist, (void**) &sspec) == APR_SUCCESS) {
                    L = sspec->L;
                    cache_info = sspec->finfo;
                }
                else {
#if APR_HAS_THREADS
                    apr_thread_mutex_unlock(ap_lua_mutex);
#endif
                    return NULL;
                }
            }
        }
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(ap_lua_mutex);
#endif
    }
    else {
        if (apr_pool_userdata_get((void **)&L, spec->file,
                              lifecycle_pool) != APR_SUCCESS) {
            L = NULL;
        }
    }
    if (L == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, lifecycle_pool, APLOGNO(01483)
                        "creating lua_State with file %s", spec->file);
        /* not available, so create */

        if (!vm_construct(&L, spec, lifecycle_pool)) {
            AP_DEBUG_ASSERT(L != NULL);
            apr_pool_userdata_set(L, spec->file, cleanup_lua, lifecycle_pool);
        }
    }

    if (spec->codecache == AP_LUA_CACHE_FOREVER || (spec->bytecode && spec->bytecode_len > 0)) {
        tryCache = 1;
    }
    else {
        char* mkey;
        if (spec->scope != AP_LUA_SCOPE_SERVER) {
            mkey = apr_psprintf(r->pool, "ap_lua_modified:%s", spec->file);
            apr_pool_userdata_get((void **)&cache_info, mkey, lifecycle_pool);
            if (cache_info == NULL) {
                cache_info = apr_pcalloc(lifecycle_pool, sizeof(ap_lua_finfo));
                apr_pool_userdata_set((void*) cache_info, mkey, NULL, lifecycle_pool);
            }
        }
        if (spec->codecache == AP_LUA_CACHE_STAT) {
            apr_finfo_t lua_finfo;
            apr_stat(&lua_finfo, spec->file, APR_FINFO_MTIME|APR_FINFO_SIZE, lifecycle_pool);

            /* On first visit, modified will be zero, but that's fine - The file is 
            loaded in the vm_construct function.
            */
            if ((cache_info->modified == lua_finfo.mtime && cache_info->size == lua_finfo.size)
                    || cache_info->modified == 0) {
                tryCache = 1;
            }
            cache_info->modified = lua_finfo.mtime;
            cache_info->size = lua_finfo.size;
        }
        else if (spec->codecache == AP_LUA_CACHE_NEVER) {
            if (cache_info->runs == 0)
                tryCache = 1;
        }
        cache_info->runs++;
    }
    if (tryCache == 0 && spec->scope != AP_LUA_SCOPE_ONCE) {
        int rc;
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, lifecycle_pool, APLOGNO(02332)
            "(re)loading lua file %s", spec->file);
        rc = luaL_loadfile(L, spec->file);
        if (rc != 0) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, lifecycle_pool, APLOGNO(02333)
                          "Error loading %s: %s", spec->file,
                          rc == LUA_ERRMEM ? "memory allocation error"
                                           : lua_tostring(L, 0));
            return 0;
        }
        lua_pcall(L, 0, LUA_MULTRET, 0);
    }

    return L;
}
