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

#include "lua_config.h"
#include "lua_vmprep.h"

APLOG_USE_MODULE(lua);

static ap_lua_dir_cfg *check_dir_config(lua_State *L, int index)
{
    ap_lua_dir_cfg *cfg;
    luaL_checkudata(L, index, "Apache2.DirConfig");
    cfg = (ap_lua_dir_cfg *) lua_unboxpointer(L, index);
    return cfg;
}

static cmd_parms *check_cmd_parms(lua_State *L, int index)
{
    cmd_parms *cmd;
    luaL_checkudata(L, index, "Apache2.CommandParameters");
    cmd = (cmd_parms *) lua_unboxpointer(L, index);
    return cmd;
}

static int apl_toscope(const char *name)
{
    if (0 == strcmp("once", name))
        return AP_LUA_SCOPE_ONCE;
    if (0 == strcmp("request", name))
        return AP_LUA_SCOPE_REQUEST;
    if (0 == strcmp("connection", name))
        return AP_LUA_SCOPE_CONN;
    if (0 == strcmp("conn", name))
        return AP_LUA_SCOPE_CONN;
    if (0 == strcmp("thread", name))
        return AP_LUA_SCOPE_THREAD;
    return AP_LUA_SCOPE_ONCE;
}

apr_status_t ap_lua_map_handler(ap_lua_dir_cfg *cfg,
                                                 const char *file,
                                                 const char *function,
                                                 const char *pattern,
                                                 const char *scope)
{
    ap_regex_t *uri_pattern;
    apr_status_t rv;
    ap_lua_mapped_handler_spec *handler =
        apr_pcalloc(cfg->pool, sizeof(ap_lua_mapped_handler_spec));
    handler->uri_pattern = NULL;
    handler->function_name = NULL;

    uri_pattern = apr_palloc(cfg->pool, sizeof(ap_regex_t));
    if ((rv = ap_regcomp(uri_pattern, pattern, 0)) != APR_SUCCESS) {
        return rv;
    }
    handler->file_name = apr_pstrdup(cfg->pool, file);
    handler->uri_pattern = uri_pattern;
    handler->scope = apl_toscope(scope);

    handler->function_name = apr_pstrdup(cfg->pool, function);
    *(const ap_lua_mapped_handler_spec **) apr_array_push(cfg->mapped_handlers) =
        handler;
    return APR_SUCCESS;
}

/* Change to use ap_lua_map_handler */
static int cfg_lua_map_handler(lua_State *L)
{
    ap_lua_dir_cfg *cfg = check_dir_config(L, 1);
    ap_lua_mapped_handler_spec *handler =
        apr_pcalloc(cfg->pool, sizeof(ap_lua_mapped_handler_spec));
    handler->uri_pattern = NULL;
    handler->function_name = NULL;

    luaL_checktype(L, 2, LUA_TTABLE);
    lua_getfield(L, 2, "file");
    if (lua_isstring(L, -1)) {
        const char *file = lua_tostring(L, -1);
        handler->file_name = apr_pstrdup(cfg->pool, file);
    }
    lua_pop(L, 1);

    lua_getfield(L, 2, "pattern");
    if (lua_isstring(L, -1)) {
        const char *pattern = lua_tostring(L, -1);

        ap_regex_t *uri_pattern = apr_palloc(cfg->pool, sizeof(ap_regex_t));
        if (ap_regcomp(uri_pattern, pattern, 0) != OK) {
            return luaL_error(L, "Unable to compile regular expression, '%s'",
                              pattern);
        }
        handler->uri_pattern = uri_pattern;
    }
    lua_pop(L, 1);

    lua_getfield(L, 2, "scope");
    if (lua_isstring(L, -1)) {
        const char *scope = lua_tostring(L, -1);
        handler->scope = apl_toscope(scope);
    }
    else {
        handler->scope = AP_LUA_SCOPE_ONCE;
    }
    lua_pop(L, 1);

    lua_getfield(L, 2, "func");
    if (lua_isstring(L, -1)) {
        const char *value = lua_tostring(L, -1);
        handler->function_name = apr_pstrdup(cfg->pool, value);
    }
    else {
        handler->function_name = "handle";
    }
    lua_pop(L, 1);


    *(const ap_lua_mapped_handler_spec **) apr_array_push(cfg->mapped_handlers) =
        handler;
    return 0;
}

static int cfg_directory(lua_State *L)
{
    ap_lua_dir_cfg *cfg = check_dir_config(L, 1);
    lua_pushstring(L, cfg->dir);
    return 1;
}

/*static int cfg_root(lua_State *L) {
    ap_lua_dir_cfg *cfg = check_dir_config(L, 1);
    lua_pushstring(L, cfg->root_path);
    return 1;
}*/

static const struct luaL_Reg cfg_methods[] = {
    {"match_handler", cfg_lua_map_handler},
    {"directory", cfg_directory},
    /* {"root", cfg_root}, */
    {NULL, NULL}
};

/* helper function for the logging functions below */
static int cmd_log_at(lua_State *L, int level)
{
    const char *msg;
    cmd_parms *cmd = check_cmd_parms(L, 1);
    lua_Debug dbg;

    lua_getstack(L, 1, &dbg);
    lua_getinfo(L, "Sl", &dbg);

    msg = luaL_checkstring(L, 2);
    ap_log_error(dbg.source, dbg.currentline, APLOG_MODULE_INDEX, level, 0,
                 cmd->server, "%s", msg);
    return 0;
}

/* r:debug(String) and friends which use apache logging */
static int cmd_emerg(lua_State *L)
{
    return cmd_log_at(L, APLOG_EMERG);
}
static int cmd_alert(lua_State *L)
{
    return cmd_log_at(L, APLOG_ALERT);
}
static int cmd_crit(lua_State *L)
{
    return cmd_log_at(L, APLOG_CRIT);
}
static int cmd_err(lua_State *L)
{
    return cmd_log_at(L, APLOG_ERR);
}
static int cmd_warn(lua_State *L)
{
    return cmd_log_at(L, APLOG_WARNING);
}
static int cmd_notice(lua_State *L)
{
    return cmd_log_at(L, APLOG_NOTICE);
}
static int cmd_info(lua_State *L)
{
    return cmd_log_at(L, APLOG_INFO);
}
static int cmd_debug(lua_State *L)
{
    return cmd_log_at(L, APLOG_DEBUG);
}
static int cmd_trace1(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE1);
}
static int cmd_trace2(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE2);
}
static int cmd_trace3(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE3);
}
static int cmd_trace4(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE4);
}
static int cmd_trace5(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE5);
}
static int cmd_trace6(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE6);
}
static int cmd_trace7(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE7);
}
static int cmd_trace8(lua_State *L)
{
    return cmd_log_at(L, APLOG_TRACE8);
}

static const struct luaL_Reg cmd_methods[] = {
    {"trace8", cmd_trace8},
    {"trace7", cmd_trace7},
    {"trace6", cmd_trace6},
    {"trace5", cmd_trace5},
    {"trace4", cmd_trace4},
    {"trace3", cmd_trace3},
    {"trace2", cmd_trace2},
    {"trace1", cmd_trace1},
    {"debug", cmd_debug},
    {"info", cmd_info},
    {"notice", cmd_notice},
    {"warn", cmd_warn},
    {"err", cmd_err},
    {"crit", cmd_crit},
    {"alert", cmd_alert},
    {"emerg", cmd_emerg},

    {NULL, NULL}
};

void ap_lua_load_config_lmodule(lua_State *L)
{
    luaL_newmetatable(L, "Apache2.DirConfig");  /* [metatable] */
    lua_pushvalue(L, -1);

    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, cfg_methods);        /* [metatable] */


    luaL_newmetatable(L, "Apache2.CommandParameters");
    lua_pushvalue(L, -1);

    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, cmd_methods);        /* [metatable] */

}
