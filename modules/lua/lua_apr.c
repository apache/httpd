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
#include "apr.h"
#include "apr_tables.h"

#include "mod_lua.h"
#include "lua_apr.h"

/**
 * make a userdata out of a C pointer, and vice versa
 * instead of using lightuserdata
 */
#ifndef lua_boxpointer
#define lua_boxpointer(L,u) (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))
#define lua_unboxpointer(L,i)	(*(void **)(lua_touserdata(L, i)))
#endif


AP_LUA_DECLARE(apr_table_t*) ap_lua_check_apr_table(lua_State *L, int index)
{
    apr_table_t *t;
    luaL_checkudata(L, index, "Apr.Table");
    t = (apr_table_t *) lua_unboxpointer(L, index);
    return t;
}


AP_LUA_DECLARE(void) ap_lua_push_apr_table(lua_State *L, apr_table_t *t)
{
    lua_boxpointer(L, t);
    luaL_getmetatable(L, "Apr.Table");
    lua_setmetatable(L, -2);
}

static int lua_table_set(lua_State *L)
{
    apr_table_t *t = ap_lua_check_apr_table(L, 1);
    const char *key = luaL_checkstring(L, 2);
    const char *val = luaL_checkstring(L, 3);

    apr_table_set(t, key, val);
    return 0;
}

static int lua_table_get(lua_State *L)
{
    apr_table_t *t = ap_lua_check_apr_table(L, 1);
    const char *key = luaL_checkstring(L, 2);
    const char *val = apr_table_get(t, key);
    lua_pushstring(L, val);
    return 1;
}

static const luaL_reg lua_table_methods[] = {
    {"set", lua_table_set},
    {"get", lua_table_get},
    {0, 0}
};


AP_LUA_DECLARE(int) ap_lua_init(lua_State *L, apr_pool_t *p)
{
    luaL_newmetatable(L, "Apr.Table");
    luaL_register(L, "apr_table", lua_table_methods);
    lua_pushstring(L, "__index");
    lua_pushstring(L, "get");
    lua_gettable(L, 2);
    lua_settable(L, 1);

    lua_pushstring(L, "__newindex");
    lua_pushstring(L, "set");
    lua_gettable(L, 2);
    lua_settable(L, 1);

    return 0;
}
