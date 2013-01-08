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
#include "scoreboard.h"
#include "lua_dbd.h"

APLOG_USE_MODULE(lua);
#define POST_MAX_VARS 500

typedef char *(*req_field_string_f) (request_rec * r);
typedef int (*req_field_int_f) (request_rec * r);
typedef apr_table_t *(*req_field_apr_table_f) (request_rec * r);

void ap_lua_rstack_dump(lua_State *L, request_rec *r, const char *msg)
{
    int i;
    int top = lua_gettop(L);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01484) "Lua Stack Dump: [%s]", msg);
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
                              "%d:  unknown: -[%s]-", i, lua_typename(L, i));
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


/*
 =======================================================================================================================
    lua_read_body(request_rec *r, const char **rbuf, apr_off_t *size): Reads any additional form data sent in POST/PUT
    requests. Used for multipart POST data.
 =======================================================================================================================
 */
static int lua_read_body(request_rec *r, const char **rbuf, apr_off_t *size)
{
    int rc = OK;

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return (rc);
    }
    if (ap_should_client_block(r)) {

        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        char         argsbuffer[HUGE_STRING_LEN];
        apr_off_t    rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        *rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = length - rpos;
            }
            else {
                rsize = len_read;
            }

            memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
        }
    }

    return (rc);
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

/* r:parsebody(): Parses regular (url-enocded) or multipart POST data and returns two tables*/
static int req_parsebody(lua_State *L)
{
    apr_array_header_t          *pairs;
    apr_off_t len;
    int res;
    apr_size_t size;
    apr_size_t max_post_size;
    char *multipart;
    const char *contentType;
    request_rec *r = ap_lua_check_request_rec(L, 1);
    max_post_size = (apr_size_t) luaL_optint(L, 2, MAX_STRING_LEN);
    multipart = apr_pcalloc(r->pool, 256);
    contentType = apr_table_get(r->headers_in, "Content-Type");
    lua_newtable(L);
    lua_newtable(L);            /* [table, table] */    
    if (contentType != NULL && (sscanf(contentType, "multipart/form-data; boundary=%250c", multipart) == 1)) {
        char        *buffer, *key, *filename;
        char        *start = 0, *end = 0, *crlf = 0;
        const char  *data;
        int         i;
        size_t      vlen = 0;
        size_t      len = 0;
        if (lua_read_body(r, &data, (apr_off_t*) &size) != OK) {
            return 2;
        }
        len = strlen(multipart);
        i = 0;
        for
        (
            start = strstr((char *) data, multipart);
            start != start + size;
            start = end
        ) {
            i++;
            if (i == POST_MAX_VARS) break;
            end = strstr((char *) (start + 1), multipart);
            if (!end) end = start + size;
            crlf = strstr((char *) start, "\r\n\r\n");
            if (!crlf) break;
            key = (char *) apr_pcalloc(r->pool, 256);
            filename = (char *) apr_pcalloc(r->pool, 256);
            vlen = end - crlf - 8;
            buffer = (char *) apr_pcalloc(r->pool, vlen+1);
            memcpy(buffer, crlf + 4, vlen);
            sscanf(start + len + 2,
                "Content-Disposition: form-data; name=\"%255[^\"]\"; filename=\"%255[^\"]\"",
                key, filename);
            if (strlen(key)) {
                req_aprtable2luatable_cb(L, key, buffer);
            }
        }
    }
    else {
        char *buffer;
        res = ap_parse_form_data(r, NULL, &pairs, -1, max_post_size);
        if (res == OK) {
            while(pairs && !apr_is_empty_array(pairs)) {
                ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
                apr_brigade_length(pair->value, 1, &len);
                size = (apr_size_t) len;
                buffer = apr_palloc(r->pool, size + 1);
                apr_brigade_flatten(pair->value, buffer, &size);
                buffer[len] = 0;
                req_aprtable2luatable_cb(L, pair->name, buffer);
            }
        }
    }
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
    int rv;
    const char *buf = luaL_checklstring(L, 2, &n);

    rv = ap_rwrite((void *) buf, n, r);
    lua_pushinteger(L, rv);
    return 1;
}

/* r:addoutputfilter(name|function) */
static int req_add_output_filter(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);
    const char *name = luaL_checkstring(L, 2);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01485) "adding output filter %s",
                  name);
    ap_add_output_filter(name, L, r, r->connection);
    return 0;
}

/* wrap ap_construct_url as r:construct_url(String) */
static int req_construct_url(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);
    const char *name = luaL_checkstring(L, 2);
    lua_pushstring(L, ap_construct_url(r->pool, name, r));
    return 1;
}

/* wrap ap_escape_html r:escape_html(String) */
static int req_escape_html(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);
    const char *s = luaL_checkstring(L, 2);
    lua_pushstring(L, ap_escape_html(r->pool, s));
    return 1;
}
/* wrap optional ssl_var_lookup as  r:ssl_var_lookup(String) */
static int req_ssl_var_lookup(lua_State *L)
{
    request_rec *r = ap_lua_check_request_rec(L, 1);
    const char *s = luaL_checkstring(L, 2);
    const char *res = ap_lua_ssl_val(r->pool, r->server, r->connection, r, 
                                     (char *)s);
    lua_pushstring(L, res);
    return 1;
}
/* BEGIN dispatch mathods for request_rec fields */

/* not really a field, but we treat it like one */
static const char *req_document_root(request_rec *r)
{
    return ap_document_root(r);
}

static const char *req_context_prefix(request_rec *r)
{
    return ap_context_prefix(r);
}

static const char *req_context_document_root(request_rec *r)
{
    return ap_context_document_root(r);
}

static char *req_uri_field(request_rec *r)
{
    return r->uri;
}

static const char *req_method_field(request_rec *r)
{
    return r->method;
}
static const char *req_handler_field(request_rec *r)
{
    return r->handler;
}
static const char *req_proxyreq_field(request_rec *r)
{
    switch (r->proxyreq) {
        case PROXYREQ_NONE:     return "PROXYREQ_NONE";
        case PROXYREQ_PROXY:    return "PROXYREQ_PROXY";
        case PROXYREQ_REVERSE:  return "PROXYREQ_REVERSE";
        case PROXYREQ_RESPONSE: return "PROXYREQ_RESPONSE";
        default: return NULL;
    }
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

static const char *req_log_id_field(request_rec *r)
{
    return r->log_id;
}

static const char *req_useragent_ip_field(request_rec *r)
{
    return r->useragent_ip;
}

static int req_remaining_field(request_rec *r)
{
    return r->remaining;
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

static apr_table_t* req_subprocess_env(request_rec *r)
{
  return r->subprocess_env;
}

static apr_table_t* req_notes(request_rec *r)
{
  return r->notes;
}

static int req_ssl_is_https_field(request_rec *r)
{
    return ap_lua_ssl_is_https(r->connection);
}

static int lua_ap_rflush (lua_State *L) {

    int returnValue;
    request_rec *r;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    returnValue = ap_rflush(r);
    lua_pushboolean(L, (returnValue == 0));
    return 1;
}

static int lua_ap_port(request_rec* r) 
{
    return (int) ap_get_server_port(r);
}

static const char* lua_ap_options(request_rec* r) 
{
    int opts;
    opts = ap_allow_options(r);
    return apr_psprintf(r->pool, "%s %s %s %s %s %s", (opts&OPT_INDEXES) ? "Indexes" : "", (opts&OPT_INCLUDES) ? "Includes" : "", (opts&OPT_SYM_LINKS) ? "FollowSymLinks" : "", (opts&OPT_EXECCGI) ? "ExecCGI" : "", (opts&OPT_MULTI) ? "MultiViews" : "", (opts&OPT_ALL) == OPT_ALL ? "All" : "" );
}

static const char* lua_ap_allowoverrides(request_rec* r) 
{
    int opts;
    opts = ap_allow_overrides(r);
    return apr_psprintf(r->pool, "%s %s %s %s %s %s", (opts&OR_NONE) ? "None" : "", (opts&OR_LIMIT) ? "Limit" : "", (opts&OR_OPTIONS) ? "Options" : "", (opts&OR_FILEINFO) ? "FileInfo" : "", (opts&OR_AUTHCFG) ? "AuthCfg" : "", (opts&OR_INDEXES) ? "Indexes" : "" );
}

static int lua_ap_started(request_rec* r) 
{
    return ap_scoreboard_image->global->restart_time;
}

static const char* lua_ap_basic_auth_pw(request_rec* r) 
{
    const char* pw = NULL;
    ap_get_basic_auth_pw(r, &pw);
    return pw ? pw : "";
}

static int lua_ap_limit_req_body(request_rec* r) 
{
    return (int) ap_get_limit_req_body(r);
}

static int lua_ap_is_initial_req(request_rec *r)
{
    return ap_is_initial_req(r);
}

static int lua_ap_some_auth_required(request_rec *r)
{
    return ap_some_auth_required(r);
}

static int lua_ap_sendfile(lua_State *L)
{

    apr_finfo_t file_info;
    const char  *filename;
    request_rec *r;

    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TSTRING);
    r = ap_lua_check_request_rec(L, 1);
    filename = lua_tostring(L, 2);
    apr_stat(&file_info, filename, APR_FINFO_NORM, r->pool);
    if (file_info.filetype == APR_NOFILE || file_info.filetype == APR_DIR) {
        lua_pushboolean(L, 0);
    }
    else {
        apr_size_t      sent;
        apr_status_t    rc;
        apr_file_t      *file;

        rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT,
                            r->pool);
        if (rc == APR_SUCCESS) {
            ap_send_fd(file, r, 0, file_info.size, &sent);
            apr_file_close(file);
            lua_pushinteger(L, sent);
        }
        else {
            lua_pushboolean(L, 0);
        }
    }

    return (1);
}


/* END dispatch methods for request_rec fields */

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
                req_field_apr_table_f func = (req_field_apr_table_f)rft->fun;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01486)
                              "request_rec->dispatching %s -> apr table",
                              name);
                rs = (*func)(r);
                ap_lua_push_apr_table(L, rs);
                return 1;
            }

        case APL_REQ_FUNTYPE_LUACFUN:{
                lua_CFunction func = (lua_CFunction)rft->fun;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01487)
                              "request_rec->dispatching %s -> lua_CFunction",
                              name);
                lua_pushcfunction(L, func);
                return 1;
            }
        case APL_REQ_FUNTYPE_STRING:{
                req_field_string_f func = (req_field_string_f)rft->fun;
                char *rs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01488)
                              "request_rec->dispatching %s -> string", name);
                rs = (*func) (r);
                lua_pushstring(L, rs);
                return 1;
            }
        case APL_REQ_FUNTYPE_INT:{
                req_field_int_f func = (req_field_int_f)rft->fun;
                int rs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01489)
                              "request_rec->dispatching %s -> int", name);
                rs = (*func) (r);
                lua_pushnumber(L, rs);
                return 1;
            }
        case APL_REQ_FUNTYPE_BOOLEAN:{
                req_field_int_f func = (req_field_int_f)rft->fun;
                int rs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01490)
                              "request_rec->dispatching %s -> boolean", name);
                rs = (*func) (r);
                lua_pushboolean(L, rs);
                return 1;
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01491) "nothing for %s", name);
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
    ap_log_rerror(dbg.source, dbg.currentline, APLOG_MODULE_INDEX, level, 0,
                  r, "%s", msg);
    return 0;
}

/* r:debug(String) and friends which use apache logging */
static int req_emerg(lua_State *L)
{
    return req_log_at(L, APLOG_EMERG);
}
static int req_alert(lua_State *L)
{
    return req_log_at(L, APLOG_ALERT);
}
static int req_crit(lua_State *L)
{
    return req_log_at(L, APLOG_CRIT);
}
static int req_err(lua_State *L)
{
    return req_log_at(L, APLOG_ERR);
}
static int req_warn(lua_State *L)
{
    return req_log_at(L, APLOG_WARNING);
}
static int req_notice(lua_State *L)
{
    return req_log_at(L, APLOG_NOTICE);
}
static int req_info(lua_State *L)
{
    return req_log_at(L, APLOG_INFO);
}
static int req_debug(lua_State *L)
{
    return req_log_at(L, APLOG_DEBUG);
}

#define APLUA_REQ_TRACE(lev) static int req_trace##lev(lua_State *L)  \
{                                                               \
    return req_log_at(L, APLOG_TRACE##lev);                     \
}

APLUA_REQ_TRACE(1)
APLUA_REQ_TRACE(2)
APLUA_REQ_TRACE(3)
APLUA_REQ_TRACE(4)
APLUA_REQ_TRACE(5)
APLUA_REQ_TRACE(6)
APLUA_REQ_TRACE(7)
APLUA_REQ_TRACE(8)

/* handle r.status = 201 */
static int req_newindex(lua_State *L)
{
    const char *key;
    /* request_rec* r = lua_touserdata(L, lua_upvalueindex(1)); */
    /* const char* key = luaL_checkstring(L, -2); */
    request_rec *r = ap_lua_check_request_rec(L, 1);
    key = luaL_checkstring(L, 2);

    if (0 == strcmp("args", key)) {
        const char *value = luaL_checkstring(L, 3);
        r->args = apr_pstrdup(r->pool, value);
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

    if (0 == strcmp("handler", key)) {
        const char *value = luaL_checkstring(L, 3);
        r->handler = apr_pstrdup(r->pool, value);
        return 0;
    }

    if (0 == strcmp("proxyreq", key)) {
        int value = luaL_checkinteger(L, 3);
        r->proxyreq = value;
        return 0;
    }

    if (0 == strcmp("status", key)) {
        int code = luaL_checkinteger(L, 3);
        r->status = code;
        return 0;
    }

    if (0 == strcmp("uri", key)) {
        const char *value = luaL_checkstring(L, 3);
        r->uri = apr_pstrdup(r->pool, value);
        return 0;
    }

    if (0 == strcmp("user", key)) {
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


static req_fun_t *makefun(const void *fun, int type, apr_pool_t *pool)
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
    apr_hash_set(dispatch, "context_prefix", APR_HASH_KEY_STRING,
                 makefun(&req_context_prefix, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "context_document_root", APR_HASH_KEY_STRING,
                 makefun(&req_context_document_root, APL_REQ_FUNTYPE_STRING, p));
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
    apr_hash_set(dispatch, "trace1", APR_HASH_KEY_STRING,
                 makefun(&req_trace1, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace2", APR_HASH_KEY_STRING,
                 makefun(&req_trace2, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace3", APR_HASH_KEY_STRING,
                 makefun(&req_trace3, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace4", APR_HASH_KEY_STRING,
                 makefun(&req_trace4, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace5", APR_HASH_KEY_STRING,
                 makefun(&req_trace5, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace6", APR_HASH_KEY_STRING,
                 makefun(&req_trace6, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace7", APR_HASH_KEY_STRING,
                 makefun(&req_trace7, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "trace8", APR_HASH_KEY_STRING,
                 makefun(&req_trace8, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "add_output_filter", APR_HASH_KEY_STRING,
                 makefun(&req_add_output_filter, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "construct_url", APR_HASH_KEY_STRING,
                 makefun(&req_construct_url, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "escape_html", APR_HASH_KEY_STRING,
                 makefun(&req_escape_html, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "ssl_var_lookup", APR_HASH_KEY_STRING,
                 makefun(&req_ssl_var_lookup, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "is_https", APR_HASH_KEY_STRING,
                 makefun(&req_ssl_is_https_field, APL_REQ_FUNTYPE_BOOLEAN, p));
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
    apr_hash_set(dispatch, "handler", APR_HASH_KEY_STRING,
                 makefun(&req_handler_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "hostname", APR_HASH_KEY_STRING,
                 makefun(&req_hostname_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "uri", APR_HASH_KEY_STRING,
                 makefun(&req_uri_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "the_request", APR_HASH_KEY_STRING,
                 makefun(&req_the_request_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "log_id", APR_HASH_KEY_STRING,
                 makefun(&req_log_id_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "useragent_ip", APR_HASH_KEY_STRING,
                 makefun(&req_useragent_ip_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "method", APR_HASH_KEY_STRING,
                 makefun(&req_method_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "proxyreq", APR_HASH_KEY_STRING,
                 makefun(&req_proxyreq_field, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "headers_in", APR_HASH_KEY_STRING,
                 makefun(&req_headers_in, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "headers_out", APR_HASH_KEY_STRING,
                 makefun(&req_headers_out, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "err_headers_out", APR_HASH_KEY_STRING,
                 makefun(&req_err_headers_out, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "notes", APR_HASH_KEY_STRING,
                 makefun(&req_notes, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "subprocess_env", APR_HASH_KEY_STRING,
                 makefun(&req_subprocess_env, APL_REQ_FUNTYPE_TABLE, p));
    apr_hash_set(dispatch, "flush", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_rflush, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "port", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_port, APL_REQ_FUNTYPE_INT, p));
    apr_hash_set(dispatch, "banner", APR_HASH_KEY_STRING,
                 makefun(&ap_get_server_banner, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "options", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_options, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "allowoverrides", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_allowoverrides, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "started", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_started, APL_REQ_FUNTYPE_INT, p));
    apr_hash_set(dispatch, "basic_auth_pw", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_basic_auth_pw, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "limit_req_body", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_limit_req_body, APL_REQ_FUNTYPE_INT, p));
    apr_hash_set(dispatch, "server_built", APR_HASH_KEY_STRING,
                 makefun(&ap_get_server_built, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "is_initial_req", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_is_initial_req, APL_REQ_FUNTYPE_BOOLEAN, p));
    apr_hash_set(dispatch, "remaining", APR_HASH_KEY_STRING,
                 makefun(&req_remaining_field, APL_REQ_FUNTYPE_INT, p));
    apr_hash_set(dispatch, "some_auth_required", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_some_auth_required, APL_REQ_FUNTYPE_BOOLEAN, p));
    apr_hash_set(dispatch, "server_name", APR_HASH_KEY_STRING,
                 makefun(&ap_get_server_name, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "auth_name", APR_HASH_KEY_STRING,
                 makefun(&ap_auth_name, APL_REQ_FUNTYPE_STRING, p));
    apr_hash_set(dispatch, "sendfile", APR_HASH_KEY_STRING,
                 makefun(&lua_ap_sendfile, APL_REQ_FUNTYPE_LUACFUN, p));
    apr_hash_set(dispatch, "dbacquire", APR_HASH_KEY_STRING,
                 makefun(&lua_db_acquire, APL_REQ_FUNTYPE_LUACFUN, p));
    

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

    lua_pushstring(L, c->client_ip);
    lua_setfield(L, -2, "client_ip");

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
