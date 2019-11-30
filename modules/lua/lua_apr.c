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
#include "lua_apr.h"
APLOG_USE_MODULE(lua);

req_table_t *ap_lua_check_apr_table(lua_State *L, int index)
{
    req_table_t* t;
    luaL_checkudata(L, index, "Apr.Table");
    t = lua_unboxpointer(L, index);
    return t;
}


void ap_lua_push_apr_table(lua_State *L, req_table_t *t)
{
    lua_boxpointer(L, t);
    luaL_getmetatable(L, "Apr.Table");
    lua_setmetatable(L, -2);
}

static int lua_table_set(lua_State *L)
{
    req_table_t    *t = ap_lua_check_apr_table(L, 1);
    const char     *key = luaL_checkstring(L, 2);
    const char     *val = luaL_optlstring(L, 3, NULL, NULL);

    if (!val) { 
        apr_table_unset(t->t, key);
        return 0;
    }

    /* Unless it's the 'notes' table, check for newline chars */
    /* t->r will be NULL in case of the connection notes, but since 
       we aren't going to check anything called 'notes', we can safely 
       disregard checking whether t->r is defined.
    */
    if (strcmp(t->n, "notes") && ap_strchr_c(val, '\n')) {
        char *badchar;
        char *replacement = apr_pstrdup(t->r->pool, val);
        badchar = replacement;
        while ( (badchar = ap_strchr(badchar, '\n')) ) {
            *badchar = ' ';
        }
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, t->r, APLOGNO(02614)
                      "mod_lua: Value for '%s' in table '%s' contains newline!",
                  key, t->n);
        apr_table_set(t->t, key, replacement);
    }
    else {
        apr_table_set(t->t, key, val);
    }
    return 0;
}

static int lua_table_get(lua_State *L)
{
    req_table_t    *t = ap_lua_check_apr_table(L, 1);
    const char     *key = luaL_checkstring(L, 2);
    const char     *val = apr_table_get(t->t, key);
    lua_pushstring(L, val);
    return 1;
}

static const luaL_Reg lua_table_methods[] = {
    {"set", lua_table_set},
    {"get", lua_table_get},
    {0, 0}
};


int ap_lua_init(lua_State *L, apr_pool_t *p)
{
    luaL_newmetatable(L, "Apr.Table");
#if LUA_VERSION_NUM < 502
    luaL_register(L, "apr_table", lua_table_methods);
#else
    luaL_newlib(L, lua_table_methods);
#endif
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



