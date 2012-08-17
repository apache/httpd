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

/* forward dec'l from this file */

#if 0
static void pstack_dump(lua_State *L, apr_pool_t *r, int level,
                        const char *msg)
{
    int i;
    int top = lua_gettop(L);

    ap_log_perror(APLOG_MARK, level, 0, r, "Lua Stack Dump: [%s]", msg);

    for (i = 1; i <= top; i++) {
        int t = lua_type(L, i);
        switch (t) {
        case LUA_TSTRING:{
                ap_log_perror(APLOG_MARK, level, 0, r,
                              "%d:  '%s'", i, lua_tostring(L, i));
                break;
            }
        case LUA_TUSERDATA:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  userdata", i);
                break;
            }
        case LUA_TLIGHTUSERDATA:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  lightuserdata",
                              i);
                break;
            }
        case LUA_TNIL:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  NIL", i);
                break;
            }
        case LUA_TNONE:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  None", i);
                break;
            }
        case LUA_TBOOLEAN:{
                ap_log_perror(APLOG_MARK, level, 0, r,
                              "%d:  %s", i, lua_toboolean(L,
                                                          i) ? "true" :
                              "false");
                break;
            }
        case LUA_TNUMBER:{
                ap_log_perror(APLOG_MARK, level, 0, r,
                              "%d:  %g", i, lua_tonumber(L, i));
                break;
            }
        case LUA_TTABLE:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  <table>", i);
                break;
            }
        case LUA_TTHREAD:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  <thread>", i);
                break;
            }
        case LUA_TFUNCTION:{
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  <function>", i);
                break;
            }
        default:{
                ap_log_perror(APLOG_MARK, level, 0, r,
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

AP_LUA_DECLARE(void) ap_lua_load_apache2_lmodule(lua_State *L)
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
static int loadjitmodule(lua_State *L, apr_pool_t *lifecycle_pool) {
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
        munge_path(L, "cpath", "?.so", "./?.so", lifecycle_pool,
            spec->package_cpaths, spec->file);
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
        lua_pcall(L, 0, LUA_MULTRET, 0);
    }

#ifdef AP_ENABLE_LUAJIT
    loadjitmodule(L, lifecycle_pool);
#endif
    lua_pushlightuserdata(L, lifecycle_pool);
    lua_setfield(L, LUA_REGISTRYINDEX, "Apache2.Wombat.pool");
    *vm = L;

    return APR_SUCCESS;
}

/**
 * Function used to create a lua_State instance bound into the web
 * server in the appropriate scope.
 */
AP_LUA_DECLARE(lua_State*)ap_lua_get_lua_state(apr_pool_t *lifecycle_pool,
                                               ap_lua_vm_spec *spec)
{
    lua_State *L = NULL;

    if (apr_pool_userdata_get((void **)&L, spec->file,
                              lifecycle_pool) == APR_SUCCESS) {
      
      if(L==NULL) {
        ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, lifecycle_pool, APLOGNO(01483)
                      "creating lua_State with file %s", spec->file);
        /* not available, so create */
        
        if(!vm_construct(&L, spec, lifecycle_pool)) {
          AP_DEBUG_ASSERT(L != NULL);
          apr_pool_userdata_set(L, 
                                spec->file, 
                                cleanup_lua,
                                lifecycle_pool);
        }
      }
    }
        /*}*/

    return L;
}
