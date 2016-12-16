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

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "httpd.h"

#include "apr_thread_rwlock.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_hash.h"
#include "apr_buckets.h"
#include "apr_file_info.h"
#include "apr_time.h"
#include "apr_pools.h"
#include "apr_reslist.h"


#ifndef VMPREP_H
#define VMPREP_H

#define AP_LUA_SCOPE_UNSET         0
#define AP_LUA_SCOPE_ONCE          1
#define AP_LUA_SCOPE_REQUEST       2
#define AP_LUA_SCOPE_CONN          3
#define AP_LUA_SCOPE_THREAD        4
#define AP_LUA_SCOPE_SERVER        5

#define AP_LUA_CACHE_UNSET         0
#define AP_LUA_CACHE_NEVER         1
#define AP_LUA_CACHE_STAT          2
#define AP_LUA_CACHE_FOREVER       3

#define AP_LUA_FILTER_INPUT        1
#define AP_LUA_FILTER_OUTPUT       2

typedef void (*ap_lua_state_open_callback) (lua_State *L, apr_pool_t *p,
                                             void *ctx);
/**
 * Specification for a lua virtual machine
 */
typedef struct
{
    /* NEED TO ADD ADDITIONAL PACKAGE PATHS AS PART OF SPEC INSTEAD OF DIR CONFIG */
    apr_array_header_t *package_paths;
    apr_array_header_t *package_cpaths;

    /* name of base file to load in the vm */
    const char *file;

    /* APL_SCOPE_ONCE | APL_SCOPE_REQUEST | APL_SCOPE_CONN | APL_SCOPE_THREAD | APL_SCOPE_SERVER */
    int scope;
    unsigned int vm_min;
    unsigned int vm_max;

    ap_lua_state_open_callback cb;
    void* cb_arg;

    /* pool to use for lifecycle if APL_SCOPE_ONCE is set, otherwise unused */
    apr_pool_t *pool;

    /* Pre-compiled Lua Byte code to load directly.  If bytecode_len is >0,
     * the file part of this structure is ignored for loading purposes, but
     * it is used for error messages.
     */
    const char *bytecode;
    apr_size_t bytecode_len;
    
    int codecache;
} ap_lua_vm_spec;

typedef struct
{
    const char *function_name;
    const char *file_name;
    int scope;
    ap_regex_t *uri_pattern;
    const char *bytecode;
    apr_size_t bytecode_len;
    int codecache;
} ap_lua_mapped_handler_spec;

typedef struct
{
    const char *function_name;
    const char *file_name;
    const char* filter_name;
    int         direction; /* AP_LUA_FILTER_INPUT | AP_LUA_FILTER_OUTPUT */
} ap_lua_filter_handler_spec;

typedef struct {
    apr_size_t runs;
    apr_time_t modified;
    apr_off_t  size;
} ap_lua_finfo;

typedef struct {
    lua_State* L;
    ap_lua_finfo* finfo;
} ap_lua_server_spec;

/**
 * Fake out addition of the "apache2" module
 */
void ap_lua_load_apache2_lmodule(lua_State *L);

/*
 * alternate means of getting lua_State (preferred eventually)
 * Obtain a lua_State which has loaded file and is associated with lifecycle_pool
 * If one exists, will return extant one, otherwise will create, attach, and return
 * This does no locking around the lua_State, so if the pool is shared between
 * threads, locking is up the client.
 *
 * @lifecycle_pool -> pool whose lifeycle controls the lua_State
 * @file file to be opened, also used as a key for uniquing lua_States
 * @cb callback for vm initialization called *before* the file is opened
 * @ctx a baton passed to cb
 */
lua_State *ap_lua_get_lua_state(apr_pool_t *lifecycle_pool,
                                                ap_lua_vm_spec *spec, request_rec* r);

#if APR_HAS_THREADS || defined(DOXYGEN)
/*
 * Initialize mod_lua mutex.
 * @pool pool for mutex
 * @s server_rec for logging
 */
void ap_lua_init_mutex(apr_pool_t *pool, server_rec *s);
#endif

#endif
