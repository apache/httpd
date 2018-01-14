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

#ifndef _LUA_REQUEST_H_
#define _LUA_REQUEST_H_

#include "mod_lua.h"
#include "util_varbuf.h"

void ap_lua_load_request_lmodule(lua_State *L, apr_pool_t *p);
void ap_lua_push_connection(lua_State *L, conn_rec *r);
void ap_lua_push_server(lua_State *L, server_rec *r);
void ap_lua_push_request(lua_State *L, request_rec *r);

#define APL_REQ_FUNTYPE_STRING      1
#define APL_REQ_FUNTYPE_INT         2
#define APL_REQ_FUNTYPE_TABLE       3
#define APL_REQ_FUNTYPE_LUACFUN     4
#define APL_REQ_FUNTYPE_BOOLEAN     5

typedef struct
{
    const void *fun;
    int type;
} req_fun_t;


/* Struct to use as userdata for request_rec tables */
typedef struct
{
    request_rec *r; /* Request_rec */
    apr_table_t *t; /* apr_table_t* */
    const char  *n; /* name of table */
} req_table_t;

typedef struct {
    int type;
    size_t size;
    size_t vb_size;
    lua_Number number;
    struct ap_varbuf vb;
} lua_ivm_object;

#endif /* !_LUA_REQUEST_H_ */
