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

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

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


/**
 * make a userdata out of a C pointer, and vice versa
 * instead of using lightuserdata
 */
#ifndef lua_boxpointer
#define lua_boxpointer(L,u) (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))
#define lua_unboxpointer(L,i)	(*(void **)(lua_touserdata(L, i)))
#endif

void ap_lua_rstack_dump(lua_State *L, request_rec *r, const char *msg);

typedef struct
{
    apr_array_header_t *package_paths;
    apr_array_header_t *package_cpaths;

    /**
     * mapped handlers
     */
    apr_array_header_t *mapped_handlers;

    apr_pool_t *pool;

    /**
     * CODE_CACHE_STAT | CODE_CACHE_FOREVER | CODE_CACHE_NEVER
     */
    unsigned int code_cache_style;

    /** 
     * APL_SCOPE_ONCE | APL_SCOPE_REQUEST | APL_SCOPE_CONN | APL_SCOPE_SERVER
     */
    unsigned int vm_scope;
    unsigned int vm_server_pool_min;
    unsigned int vm_server_pool_max;

    /* info for the hook harnesses */
    apr_hash_t *hooks;          /* <wombat_hook_info> */

    /* the actual directory being configured */
    char *dir;
} ap_lua_dir_cfg;

typedef struct
{
    ap_lua_code_cache *code_cache;
    apr_hash_t *vm_reslists;
    apr_thread_rwlock_t *vm_reslists_lock;

    /* value of the LuaRoot directive */
    const char *root_path;
} ap_lua_server_cfg;

typedef struct
{
    char *function_name;
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
    char *function;
} ap_lua_filter_ctx;

extern module AP_MODULE_DECLARE_DATA lua_module;

APR_DECLARE_EXTERNAL_HOOK(ap_lua, AP_LUA, int, lua_open,
                          (lua_State *L, apr_pool_t *p));

APR_DECLARE_EXTERNAL_HOOK(ap_lua, AP_LUA, int, lua_request,
                          (lua_State *L, request_rec *r));

#endif /* !_MOD_LUA_H_ */
