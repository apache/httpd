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


#ifndef VMPREP_H
#define VMPREP_H

#define APW_CODE_CACHE_STAT     1
#define APW_CODE_CACHE_FOREVER  2
#define APW_CODE_CACHE_NEVER    3

#define APW_SCOPE_ONCE          1
#define APW_SCOPE_REQUEST       2
#define APW_SCOPE_CONN          3
#define APW_SCOPE_SERVER        4

/**
 * Specification for a lua virtual machine
 */ 
typedef struct {

    /* NEED TO ADD ADDITIONAL PACKAGE PATHS AS PART OF SPEC INSTEAD OF DIR CONFIG */
    apr_array_header_t* package_paths;
    apr_array_header_t* package_cpaths;
    
    /* name of base file to load in the vm */
    char *file;             

    /* APW_CODE_CACHE_STAT | APW_CODE_CACHE_FOREVER | APW_CODE_CACHE_NEVER */
    int code_cache_style;

    /* APW_SCOPE_ONCE | APW_SCOPE_REQUEST | APW_SCOPE_CONN | APW_SCOPE_SERVER */
    int scope;
    
    /* pool to use for lifecycle if APW_SCOPE_ONCE is set, otherwise unused */
    apr_pool_t *pool;

    const char *bytecode;
    apr_size_t bytecode_len;
} apw_vm_spec;

typedef struct {
    int code_cache_style;
    char *function_name;
    char *file_name;
    int scope;
    ap_regex_t *uri_pattern;
    const char *bytecode;
    apr_size_t bytecode_len;
} apw_mapped_handler_spec;

typedef struct {
    apr_pool_t *pool;
    apr_hash_t *compiled_files;
    apr_thread_rwlock_t* compiled_files_lock;
} apw_code_cache;

/* remove and make static once out of mod_wombat.c */
void apw_openlibs(lua_State* L);

/* remove and make static once out of mod_wombat.c */
void apw_registerlib(lua_State* L, char* name, lua_CFunction f);

/**
 * Fake out addition of the "apache2" module
 */
void apw_load_apache2_lmodule(lua_State *L);

/**
 * the apw_?getvm family of functions is used to create and/or obtain
 * a handle to a lua state. If there is not an extant vm matching the
 * spec then a new one is created.
 */
/* lua_State* apw_rgetvm(request_rec *r, apw_vm_spec *spec); */

/* returns NULL if the spec requires a request scope */
/* lua_State* apw_cgetvm(conn_rec *r, apw_vm_spec *spec);*/

/* returns NULL if the spec requires a request scope or conn scope */
/* lua_State* apw_sgetvm(server_rec *r, apw_vm_spec *spec); */

typedef void (*apw_lua_state_open_callback) (lua_State* L, apr_pool_t* p, void* ctx);

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
lua_State* apw_get_lua_state(apr_pool_t* lifecycle_pool, 
                             char* file, 
                             apr_array_header_t* package_paths, 
                             apr_array_header_t* package_cpaths,
                             apw_lua_state_open_callback cb,
                             void* btn);
                             
                             

#endif

