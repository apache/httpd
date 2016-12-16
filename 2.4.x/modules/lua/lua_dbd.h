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

#ifndef _LUA_DBD_H_
#define _LUA_DBD_H_

#include "mod_lua.h"
#include "apr.h"
#include "apr_dbd.h"
#include "mod_dbd.h"

#define LUA_DBTYPE_APR_DBD 0
#define LUA_DBTYPE_MOD_DBD 1
typedef struct
{
    apr_dbd_t               *handle;
    const apr_dbd_driver_t  *driver;
    int                     alive;
    apr_pool_t              *pool;
    char                    type;
    ap_dbd_t *              dbdhandle;
    server_rec              *server;
} lua_db_handle;

typedef struct {
    const apr_dbd_driver_t  *driver;
    int                     rows;
    int                     cols;
    apr_dbd_results_t       *results;
    apr_pool_t              *pool;
} lua_db_result_set;

typedef struct {
    apr_dbd_prepared_t      *statement;
    int                     variables;
    lua_db_handle           *db;
} lua_db_prepared_statement;

int lua_db_acquire(lua_State* L);
int lua_db_escape(lua_State* L);
int lua_db_close(lua_State* L);
int lua_db_prepare(lua_State* L);
int lua_db_prepared(lua_State* L);
int lua_db_select(lua_State* L);
int lua_db_query(lua_State* L);
int lua_db_prepared_select(lua_State* L);
int lua_db_prepared_query(lua_State* L);
int lua_db_get_row(lua_State* L);
int lua_db_gc(lua_State* L);
int lua_db_active(lua_State* L);

#endif /* !_LUA_DBD_H_ */
