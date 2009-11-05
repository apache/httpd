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
#include "util_script.h"
#include "lua_apr.h"

typedef char *(*req_field_string_f) (request_rec * r);
typedef int (*req_field_int_f) (request_rec * r);
typedef apr_table_t *(*req_field_apr_table_f) (request_rec * r);

void ap_lua_rstack_dump(lua_State *L, request_rec *r, const char *msg)
{
    int i;
    int top = lua_gettop(L);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Lua Stack Dump: [%s]", msg);

    for (i = 1; i <= top; i++) {
        int t = lua_type(L, i);
        switch (t) {
        case LUA_TSTRING:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  '%s'", i, lua_tostring(L, i));
                break;
            }
        case LUA_TUSERDATA:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%d:  userdata",
                              i);
                break;
            }
        case LUA_TLIGHTUSERDATA:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  lightuserdata", i);
                break;
            }
        case LUA_TNIL:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%d:  NIL", i);
                break;
            }
        case LUA_TNONE:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "%d:  None", i);
                break;
            }
        case LUA_TBOOLEAN:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  %s", i, lua_toboolean(L,
                                                          i) ? "true" :
                              "false");
                break;
            }
        case LUA_TNUMBER:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  %g", i, lua_tonumber(L, i));
                break;
            }
        case LUA_TTABLE:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  <table>", i);
                break;
            }
        case LUA_TFUNCTION:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  <function>", i);
                break;
            }
        default:{
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "%d:  unkown: -[%s]-", i, lua_typename(L, i));
                break;
            }
        }
    }
}

/**
 * Verify that the thing at index is a request_rec wrapping
 * userdata thingamajig and return it if it is. if it is not
 * lua will enter its error handling routine.
 */
static request_rec *ap_lua_check_request_rec(lua_State *L, int index)
{
    request_rec *r;
    luaL_checkudata(L, index, "Apache2.Request");
    r = (request_rec *) lua_unboxpointer(L, index);
    return r;
}

/* ------------------ request methods -------------------- */
/* helper callback for req_parseargs */
static int req_aprtable2luatable_cb(void *l, const char *key,
                                    const char *value)
{
    int t;
    lua_State *L = (lua_State *) l;     /* [table<s,t>, table<s,s>] */
    /* rstack_dump(L, RRR, "start of cb"); */
    /* L is [table<s,t>, table<s,s>] */
    /* build complex */

    lua_getfield(L, -1, key);   /* [VALUE, table<s,t>, table<s,s>] */
    /* rstack_dump(L, RRR, "after getfield"); */
    t = lua_type(L, -1);
    switch (t) {
    case LUA_TNIL:
    case LUA_TNONE:{
            lua_pop(L, 1);      /* [table<s,t>, table<s,s>] */
            lua_newtable(L);    /* [array, table<s,t>, table<s,s>] */
            lua_pushnumber(L, 1);       /* [1, array, table<s,t>, table<s,s>] */
            lua_pushstring(L, value);   /* [string, 1, array, table<s,t>, table<s,s>] */
            lua_settable(L, -3);        /* [array, table<s,t>, table<s,s>]  */
            lua_setfield(L, -2, key);   /* [table<s,t>, table<s,s>] */
            break;
        }
    case LUA_TTABLE:{
            /* [array, table<s,t>, table<s,s>] */
            int size = lua_objlen(L, -1);
            lua_pushnumber(L, size + 1);        /* [#, array, table<s,t>, table<s,s>] */
            lua_pushstring(L, value);   /* [string, #, array, table<s,t>, table<s,s>] */
            lua_settable(L, -3);        /* [array, table<s,t>, table<s,s>] */
            lua_setfield(L, -2, key);   /* [table<s,t>, table<s,s>] */
            break;
        }
    }

    /* L is [table<s,t>, table<s,s>] */
    /* build simple */
    lua_getfield(L, -2, key);   /* [VALUE, table<s,s>, table<s,t>] */
    if (lua_isnoneornil(L, -1)) {       /* only set if not already set */
        lua_pop(L, 1);          /* [table<s,s>, table<s,t>]] */
        lua_pushstring(L, value);       /* [string, table<s,s>, table<s,t>] */
        lua_setfield(L, -3, key);       /* [table<s,s>, table<s,t>]  */
    }
    else {
        lua_pop(L, 1);
    }
    return 1;
}

/* r:parseargs() returning a lua table */
static int req_parseargs(lua_State *L)
{
    apr_table_t *form_table;
    request_rec *r = ap_lua_check_request_rec(L, 1);
    lua_newtable(L);
    lua_newtable(L);            /* [table, table] */
    ap_args_to_table(r, &form_table);
    apr_table_do(req_aprtable2luatable_cb, L, form_table, NULL);
    return 2;                   /* [table<string, string>, table<string, array<string>>] */
}

/* wrap ap_rputs as r:puts(String) */
static int req_puts(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);

    int argc = lua_gettop(L);
    int i;

    for (i = 2; i <= argc; i++) {
        ap_rputs(luaL_checkstring(L, i), r);
    }
    return 0;
}

/* wrap ap_rwrite as r:write(String) */
static int req_write(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);
    size_t n;
    const char *buf = luaL_checklstring(L, 2, &n);

    ap_rwrite((void *) buf, n, r);
    return 0;
}

/* r:parsebody() */
static int req_parsebody(lua_State *L)
{
    apr_table_t *form_table;
    request_rec *r = ap_lua_check_request_rec(L, 1);
    lua_newtable(L);
    lua_newtable(L);
    if (ap_body_to_table(r, &form_table) == APR_SUCCESS) {
        apr_table_do(req_aprtable2luatable_cb, L, form_table, NULL);
    }
    return 2;
}

/* r:addoutputfilter(name|function) */
static int req_add_output_filter(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);
    const char *name = luaL_checkstring(L, 2);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "adding output filter %s",
                  name);
    ap_add_output_filter(name, L, r, r->connection);
    return 0;
}

/* BEGIN dispatch mathods for request_rec fields */

/* not really a field, but we treat it like one */
static const char *req_document_root(request_rec *r)
{
    return ap_document_root(r);
}

static char *req_uri_field(request_rec *r)
{
    return r->uri;
}

static const char *req_method_field(request_rec *r)
{
    return r->method;
}

static const char *req_hostname_field(request_rec *r)
{
    return r->hostname;
}

static const char *req_args_field(request_rec *r)
{
    return r->args;
}

static const char *req_path_info_field(request_rec *r)
{
    return r->path_info;
}

static const char *req_canonical_filename_field(request_rec *r)
{
    return r->canonical_filename;
}

static const char *req_filename_field(request_rec *r)
{
    return r->filename;
}

static const char *req_user_field(request_rec *r)
{
    return r->user;
}

static const char *req_unparsed_uri_field(request_rec *r)
{
    return r->unparsed_uri;
}

static const char *req_ap_auth_type_field(request_rec *r)
{
    return r->ap_auth_type;
}

static const char *req_content_encoding_field(request_rec *r)
{
    return r->content_encoding;
}

static const char *req_content_type_field(request_rec *r)
{
    return r->content_type;
}

static const char *req_range_field(request_rec *r)
{
    return r->range;
}

static const char *req_protocol_field(request_rec *r)
{
    return r->protocol;
}

static const char *req_the_request_field(request_rec *r)
{
    return r->the_request;
}

static int req_status_field(request_rec *r)
{
    return r->status;
}

static int req_assbackwards_field(request_rec *r)
{
    return r->assbackwards;
}

static apr_table_t* req_headers_in(request_rec *r)
{
    return r->headers_in;
}

static apr_table_t* req_headers_out(request_rec *r)
{
    return r->headers_out;
}

static apr_table_t* req_err_headers_out(request_rec *r)
{
  return r->err_headers_out;
}

static apr_table_t* req_notes(request_rec *r)
{
  return r->notes;
}

/* END dispatch mathods for request_rec fields */

static int req_dispatch(lua_State *L)
{
    apr_hash_t *dispatch;
    req_fun_t *rft;
    request_rec *r = ap_lua_check_request_rec(L, 1);
    const char *name = luaL_checkstring(L, 2);
    lua_pop(L, 2);

    lua_getfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");
    dispatch = lua_touserdata(L, 1);
    lua_pop(L, 1);

    rft = apr_hash_get(dispatch, name, APR_HASH_KEY_STRING);
    if (rft) {
        switch (rft->type) {
        case APL_REQ_FUNTYPE_TABLE:{
                apr_table_t *rs;
                req_field_apr_table_f func = rft->fun;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "request_rec->dispatching %s -> apr table",
                              name);
                rs = (*func)(r);
                ap_lua_push_apr_table(L, rs);          
                return 1;
            }

        case APL_REQ_FUNTYPE_LUACFUN:{
                lua_CFunction func = rft->fun;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "request_rec->dispatching %s -> lua_CFunction",
                              name);
                lua_pushcfunction(L, func);
                return 1;
            }
        case APL_REQ_FUNTYPE_STRING:{
                req_field_string_f func = rft->fun;
                char *rs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "request_rec->dispatching %s -> string", name);
                rs = (*func) (r);
                lua_pushstring(L, rs);
                return 1;
            }
        case APL_REQ_FUNTYPE_INT:{
                req_field_int_f func = rft->fun;
                int rs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "request_rec->dispatching %s -> int", name);
                rs = (*func) (r);
                lua_pushnumber(L, rs);
                return 1;
            }
        case APL_REQ_FUNTYPE_BOOLEAN:{
                req_field_int_f func = rft->fun;
                int rs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "request_rec->dispatching %s -> boolean", name);
                rs = (*func) (r);
                lua_pushboolean(L, rs);
                return 1;
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "nothing for %s", name);
    return 0;
}

/* helper function for the logging functions below */
static int req_log_at(lua_State *L, int level)
{
    const char *msg;
    request_rec *r = ap_lua_check_request_rec(L, 1);
    lua_Debug dbg;

    lua_getstack(L, 1, &dbg);
    lua_getinfo(L, "Sl", &dbg);

    msg = luaL_checkstring(L, 2);
    ap_log_rerror(dbg.source, dbg.currentline, level, 0, r, msg);
    return 0;
}

/* r:debug(String) and friends which use apache logging */
static int req_emerg(lua_State *L)
{
    req_log_at(L, APLOG_EMERG);
    return 0;
}
static int req_alert(lua_State *L)
{
    req_log_at(L, APLOG_ALERT);
    return 0;
}
static int req_crit(lua_State *L)
{
    req_log_at(L, APLOG_CRIT);
    return 0;
}
static int req_err(lua_State *L)
{
    req_log_at(L, APLOG_ERR);
    return 0;
}
static int req_warn(lua_State *L)
{
    req_log_at(L, APLOG_WARNING);
    return 0;
}
static int req_notice(lua_State *L)
{
    req_log_at(L, APLOG_NOTICE);
    return 0;
}
static int req_info(lua_State *L)
{
    req_log_at(L, APLOG_INFO);
    return 0;
}
static int req_debug(lua_State *L)
{
    req_log_at(L, APLOG_DEBUG);
    return 0;
}

/* handle r.status = 201 */
static int req_newindex(lua_State *L)
{
    const char *key;
    /* request_rec* r = lua_touserdata(L, lua_upvalueindex(1)); */
    /* const char* key = luaL_checkstring(L, -2); */
    request_rec *r = ap_lua_check_request_rec(L, 1);
    key = luaL_checkstring(L, 2);
    if (0 == strcmp("status", key)) {
        int code = luaL_checkinteger(L, 3);
        r->status = code;
        return 0;
    }

    if (0 == strcmp("content_type", key)) {
        const char *value = luaL_checkstring(L, 3);
        ap_set_content_type(r, apr_pstrdup(r->pool, value));
        return 0;
    }

    if (0 == strcmp("filename", key)) {
        const char *value = luaL_checkstring(L, 3);
        r->filename = apr_pstrdup(r->pool, value);
        return 0;
    }

    if (0 == strcmp("uri", key)) {
        const char *value = luaL_checkstring(L, 3);
        r->uri = apr_pstrdup(r->pool, value);
        return 0;
    }

    if (0 == apr_strnatcmp("user", key)) {
        const char *value = luaL_checkstring(L, 3);
        r->user = apr_pstrdup(r->pool, value);
        return 0;
    }

    lua_pushstring(L,
                   apr_psprintf(r->pool,
                                "Property [%s] may not be set on a request_rec",
                                key));
    lua_error(L);
    return 0;
}

static const struct luaL_Reg request_methods[] = {
    {"__index", req_dispatch},
    {"__newindex", req_newindex},
    /*   {"__newindex", req_set_field}, */
    {NULL, NULL}
};


static const struct luaL_Reg connection_methods[] = {
    {NULL, NULL}
};


static const struct luaL_Reg server_methods[] = {
    {NULL, NULL}
};


static req_fun_t *makefun(void *fun, int type, apr_pool_t *pool)
{
    req_fun_t *rft = apr_palloc(pool, sizeof(req_fun_t));
    rft->fun = fun;
    rft->type = type;
    return rft;
}

AP_LUA_DECLARE(void) ap_lua_load_request_lmodule(lua_State *L, apr_pool_t *p)
{

    apr_hash_t *dispatch = apr_hash_make(p);

    apr_hash_set(dispatch, "puts", APR_HASH_KEY_STRING,
                 makefun(&req_puts, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "write", APR_HASH_KEY_STRING,
                 makefun(&req_write, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "document_root", APR_HASH_KEY_STRING,
                 makefun(&req_document_root, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "parseargs", APR_HASH_KEY_STRING,
                 makefun(&req_parseargs, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "parsebody", APR_HASH_KEY_STRING,
                 makefun(&req_parsebody, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "debug", APR_HASH_KEY_STRING,
                 makefun(&req_debug, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "info", APR_HASH_KEY_STRING,
                 makefun(&req_info, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "notice", APR_HASH_KEY_STRING,
                 makefun(&req_notice, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "warn", APR_HASH_KEY_STRING,
                 makefun(&req_warn, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "err", APR_HASH_KEY_STRING,
                 makefun(&req_err, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "crit", APR_HASH_KEY_STRING,
                 makefun(&req_crit, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "alert", APR_HASH_KEY_STRING,
                 makefun(&req_alert, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "emerg", APR_HASH_KEY_STRING,
                 makefun(&req_emerg, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "add_output_filter", APR_HASH_KEY_STRING,
                 makefun(&req_add_output_filter, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "assbackwards", APR_HASH_KEY_STRING,
                 makefun(&req_assbackwards_field, APL_REQ_FUNTYPE_BOOLEAN, p));
    apr_hash_set(dispatch, "status", APR_HASH_KEY_STRING,
                 makefun(&req_status_field, APL_REQ_FUNTYPE_INT, p));
    apr_hash_set(dispatch, "protocol", APR_HASH_KEY_STRING,
                 makefun(&req_protocol_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "range", APR_HASH_KEY_STRING,
                 makefun(&req_range_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "content_type", APR_HASH_KEY_STRING,
                 makefun(&req_content_type_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "content_encoding", APR_HASH_KEY_STRING,
                 makefun(&req_content_encoding_field, APL_REQ_FUNTYPE_STRING,
                         p));
    apr_hash_set(dispatch, "ap_auth_type", APR_HASH_KEY_STRING,
                 makefun(&req_ap_auth_type_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "unparsed_uri", APR_HASH_KEY_STRING,
                 makefun(&req_unparsed_uri_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "user", APR_HASH_KEY_STRING,
                 makefun(&req_user_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "filename", APR_HASH_KEY_STRING,
                 makefun(&req_filename_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "canonical_filename", APR_HASH_KEY_STRING,
                 makefun(&req_canonical_filename_field,
                         APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "path_info", APR_HASH_KEY_STRING,
                 makefun(&req_path_info_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "args", APR_HASH_KEY_STRING,
                 makefun(&req_args_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "hostname", APR_HASH_KEY_STRING,
                 makefun(&req_hostname_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "uri", APR_HASH_KEY_STRING,
                 makefun(&req_uri_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "the_request", APR_HASH_KEY_STRING,
                 makefun(&req_the_request_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "method", APR_HASH_KEY_STRING,
                 makefun(&req_method_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "headers_in", APR_HASH_KEY_STRING,
                 makefun(&req_headers_in, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "headers_out", APR_HASH_KEY_STRING,
                 makefun(&req_headers_out, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "err_headers_out", APR_HASH_KEY_STRING,
                 makefun(&req_err_headers_out, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "notes", APR_HASH_KEY_STRING,
                 makefun(&req_notes, APL_REQ_FUNTYPE_TABLE, p));

    

    lua_pushlightuserdata(L, dispatch);
    lua_setfield(L, LUA_REGISTRYINDEX, "Apache2.Request.dispatch");

    luaL_newmetatable(L, "Apache2.Request");    /* [metatable] */
    lua_pushvalue(L, -1);

    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, request_methods);    /* [metatable] */

    lua_pop(L, 2);

    luaL_newmetatable(L, "Apache2.Connection"); /* [metatable] */
    lua_pushvalue(L, -1);

    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, connection_methods); /* [metatable] */

    lua_pop(L, 2);

    luaL_newmetatable(L, "Apache2.Server");     /* [metatable] */
    lua_pushvalue(L, -1);

    lua_setfield(L, -2, "__index");
    luaL_register(L, NULL, server_methods);     /* [metatable] */

    lua_pop(L, 2);

}

AP_LUA_DECLARE(void) ap_lua_push_connection(lua_State *L, conn_rec *c)
{
    lua_boxpointer(L, c);
    luaL_getmetatable(L, "Apache2.Connection");
    lua_setmetatable(L, -2);
    luaL_getmetatable(L, "Apache2.Connection");

    ap_lua_push_apr_table(L, c->notes);
    lua_setfield(L, -2, "notes");

    lua_pushstring(L, c->remote_ip);
    lua_setfield(L, -2, "remote_ip");

    lua_pop(L, 1);
}


AP_LUA_DECLARE(void) ap_lua_push_server(lua_State *L, server_rec *s)
{
    lua_boxpointer(L, s);
    luaL_getmetatable(L, "Apache2.Server");
    lua_setmetatable(L, -2);
    luaL_getmetatable(L, "Apache2.Server");

    lua_pushstring(L, s->server_hostname);
    lua_setfield(L, -2, "server_hostname");

    lua_pop(L, 1);
}

AP_LUA_DECLARE(void) ap_lua_push_request(lua_State *L, request_rec *r)
{
    lua_boxpointer(L, r);
    luaL_getmetatable(L, "Apache2.Request");
    lua_setmetatable(L, -2);
}
