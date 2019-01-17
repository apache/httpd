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

#ifndef _MOD_LUA_H_
#define _MOD_LUA_H_

#include <stdio.h>

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_regex.h"

#include "ap_config.h"
#include "util_filter.h"

#include "apr_thread_rwlock.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_hash.h"
#include "apr_buckets.h"
#include "apr_file_info.h"
#include "apr_time.h"
#include "apr_hooks.h"
#include "apr_reslist.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#if LUA_VERSION_NUM > 501
/* Load mode for lua_load() */
#define lua_load(a,b,c,d)  lua_load(a,b,c,d,NULL)
#define lua_resume(a,b)    lua_resume(a, NULL, b)
#define luaL_setfuncs_compat(a,b) luaL_setfuncs(a,b,0)
#else
#define lua_rawlen(L,i)    lua_objlen(L, (i))
#define luaL_setfuncs_compat(a,b) luaL_register(a,NULL,b)
#endif
#if LUA_VERSION_NUM > 502
#define lua_dump(a,b,c) lua_dump(a,b,c,0)
#endif

/* Create a set of AP_LUA_DECLARE(type), AP_LUA_DECLARE_NONSTD(type) and
 * AP_LUA_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define AP_LUA_DECLARE(type)            type
#define AP_LUA_DECLARE_NONSTD(type)     type
#define AP_LUA_DECLARE_DATA
#elif defined(AP_LUA_DECLARE_STATIC)
#define AP_LUA_DECLARE(type)            type __stdcall
#define AP_LUA_DECLARE_NONSTD(type)     type
#define AP_LUA_DECLARE_DATA
#elif defined(AP_LUA_DECLARE_EXPORT)
#define AP_LUA_DECLARE(type)            __declspec(dllexport) type __stdcall
#define AP_LUA_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define AP_LUA_DECLARE_DATA             __declspec(dllexport)
#else
#define AP_LUA_DECLARE(type)            __declspec(dllimport) type __stdcall
#define AP_LUA_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define AP_LUA_DECLARE_DATA             __declspec(dllimport)
#endif


#include "lua_request.h"
#include "lua_vmprep.h"

typedef enum {
    AP_LUA_INHERIT_UNSET        = -1,
    AP_LUA_INHERIT_NONE         =  0,
    AP_LUA_INHERIT_PARENT_FIRST =  1,
    AP_LUA_INHERIT_PARENT_LAST  =  2
} ap_lua_inherit_t;

/**
 * make a userdata out of a C pointer, and vice versa
 * instead of using lightuserdata
 */
#ifndef lua_boxpointer
#define lua_boxpointer(L,u) (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))
#define lua_unboxpointer(L,i)   (*(void **)(lua_touserdata(L, i)))
#endif

void ap_lua_rstack_dump(lua_State *L, request_rec *r, const char *msg);

typedef struct
{
    apr_array_header_t *package_paths;
    apr_array_header_t *package_cpaths;

    /**
     * mapped handlers/filters
     */
    apr_array_header_t *mapped_handlers;
    apr_array_header_t *mapped_filters;

    apr_pool_t *pool;

    /**
     * AP_LUA_SCOPE_ONCE | AP_LUA_SCOPE_REQUEST | AP_LUA_SCOPE_CONN | AP_LUA_SCOPE_SERVER
     */
    unsigned int vm_scope;
    unsigned int vm_min;
    unsigned int vm_max;

    /* info for the hook harnesses */
    apr_hash_t *hooks;          /* <wombat_hook_info> */

    /* the actual directory being configured */
    const char *dir;
  
    /* Whether Lua scripts in a sub-dir are run before parents */
    ap_lua_inherit_t inherit;
    
    /**
     * AP_LUA_CACHE_NEVER | AP_LUA_CACHE_STAT | AP_LUA_CACHE_FOREVER
     */
    unsigned int codecache;

} ap_lua_dir_cfg;

typedef struct
{
    /* value of the LuaRoot directive */
    const char *root_path;
} ap_lua_server_cfg;

typedef struct
{
    const char *function_name;
    ap_lua_vm_spec *spec;
} mapped_request_details;

typedef struct
{
    mapped_request_details *mapped_request_details;
    apr_hash_t *request_scoped_vms;
} ap_lua_request_cfg;

typedef struct
{
    lua_State *L;
    const char *function;
} ap_lua_filter_ctx;

extern module AP_MODULE_DECLARE_DATA lua_module;

APR_DECLARE_EXTERNAL_HOOK(ap_lua, AP_LUA, int, lua_open,
                          (lua_State *L, apr_pool_t *p))

APR_DECLARE_EXTERNAL_HOOK(ap_lua, AP_LUA, int, lua_request,
                          (lua_State *L, request_rec *r))

const char *ap_lua_ssl_val(apr_pool_t *p, server_rec *s, conn_rec *c,
                           request_rec *r, const char *var);

int ap_lua_ssl_is_https(conn_rec *c);

#endif /* !_MOD_LUA_H_ */
