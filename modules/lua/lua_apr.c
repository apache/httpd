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


/**
 * make a userdata out of a C pointer, and vice versa
 * instead of using lightuserdata
 */
#ifndef lua_boxpointer
#define lua_boxpointer(L,u) (*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))
#define lua_unboxpointer(L,i)   (*(void **)(lua_touserdata(L, i)))
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

static const luaL_Reg lua_table_methods[] = {
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


/*
 =======================================================================================================================
    util_read(request_rec *r, const char **rbuf, apr_off_t *size): Reads any additional form data sent in POST/PUT
    requests.
 =======================================================================================================================
 */
static int util_read(request_rec *r, const char **rbuf, apr_off_t *size)
{
    /*~~~~~~~~*/
    int rc = OK;
    /*~~~~~~~~*/

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

/*
 =======================================================================================================================
    util_write(request_rec *r, const char **rbuf, apr_off_t *size): Reads any additional form data sent in POST/PUT
    requests and writes to a file.
 =======================================================================================================================
 */
static int util_write(request_rec *r, apr_file_t *file, apr_off_t *size)
{
    /*~~~~~~~~*/
    int rc = OK;
    /*~~~~~~~~*/

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return (rc);
    }
    
    if (ap_should_client_block(r)) {

        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        char        argsbuffer[HUGE_STRING_LEN];
        apr_off_t  rsize, len_read, rpos = 0;
        apr_off_t   length = r->remaining;
		apr_size_t  written;
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        *size = length;
        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = (apr_size_t) length - rpos;
            }
            else {
                rsize = len_read;
            }

            rc = apr_file_write_full(file, argsbuffer, (apr_size_t) rsize, &written);
            if (written != rsize) return -1;
            rpos += rsize;
        }
    }

    return (rc);
}

static request_rec *ap_lua_check_request_rec(lua_State *L, int index)
{
    request_rec *r;
    luaL_checkudata(L, index, "Apache2.Request");
    r = (request_rec*) lua_unboxpointer(L, index);
    return r;
}

/* lua_apr_b64encode; r:encode_base64(string) - encodes a string to Base64 format */
static int lua_apr_b64encode (lua_State *L) {
    const char *plain;
    char *encoded;
    size_t x,y,z;
    request_rec *r;
    
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    plain = lua_tolstring(L, 2, &x);
    y = apr_base64_encode_len(x)+1;
    if (y) {
        encoded = apr_palloc(r->pool, y);
        z = apr_base64_encode(encoded, plain, x);
        lua_pushlstring(L, encoded, z);
        return 1;
    }
    return 0;
}

/* lua_apr_b64decode; r:decode_base64(string) - decodes a Base64 string*/
static int lua_apr_b64decode (lua_State *L) {
    const char *encoded;
    char *plain;
    size_t x,y,z;
    request_rec *r;
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    encoded = lua_tolstring(L, 2, &x);
    y = apr_base64_decode_len(encoded)+1;
    if (y) {
        plain = apr_palloc(r->pool, y);
        z = apr_base64_decode(plain, encoded);
        lua_pushlstring(L, plain, z);
        return 1;
    }
    return 0;
}

/* lua_ap_unescape; r:unescape(string) - Unescapes an URL-encoded string */
static int lua_ap_unescape (lua_State *L) {
    const char *escaped;
    char *plain;
    size_t x,y;
    request_rec *r;
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    escaped = lua_tolstring(L, 2, &x);
    plain = apr_pstrdup(r->pool, escaped);
    strncpy(plain, escaped, x);
    y = ap_unescape_urlencoded(plain);
    if (!y) {
        lua_pushstring(L, plain);
        return 1;
    }
    return 0;
}

/* lua_ap_escape; r:escape(string) - URL-escapes a string */
static int lua_ap_escape (lua_State *L) {
    const char *plain;
    char *escaped;
    size_t x;
    request_rec *r;
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    plain = lua_tolstring(L, 2, &x);
    escaped = ap_escape_urlencoded(r->pool, plain);
    lua_pushstring(L, escaped);
    return 1;
}

/* lua_apr_md5; r:md5(string) - Calculates an MD5 digest of a string */
static int lua_apr_md5(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~*/
    union {
        unsigned char      chr[16];
        apr_uint32_t   num[4];
    } digest;
    apr_md5_ctx_t md5;
    const char* buffer;
    char* result;
    char Rmd5[16];
    apr_uint32_t   *md5X;
    size_t x,y;
    request_rec *r;
    /*~~~~~~~~~~~~~~~~*/
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    result = apr_pcalloc(r->pool, (APR_MD5_DIGESTSIZE*2)+1);
    buffer = lua_tolstring(L, 2, &y);
    apr_md5_init(&md5);
    apr_md5_update(&md5, buffer, y);
    apr_md5_final(digest.chr, &md5);

    for (x = 0; x < 16; x += 4) {
        Rmd5[x] = digest.chr[x + 3];
        Rmd5[x + 1] = digest.chr[x + 2];
        Rmd5[x + 2] = digest.chr[x + 1];
        Rmd5[x + 3] = digest.chr[x];
    }

    md5X = (apr_uint32_t  *) Rmd5;
    sprintf(result, "%08x%08x%08x%08x", md5X[0], md5X[1], md5X[2], md5X[3]);
    lua_pushstring(L, result);
    return 1;
}

/* lua_apr_sha1; r:sha1(string) - Calculates the SHA1 digest of a string */
static int lua_apr_sha1(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~*/
    union {
        unsigned char      chr[16];
        apr_uint32_t   num[4];
    } digest;
    apr_sha1_ctx_t sha1;
    const char* buffer;
    char* result;
    unsigned char Rsha1[20];
    apr_uint32_t  *sha1X;
    size_t x,y;
    request_rec *r;
    /*~~~~~~~~~~~~~~~~*/
    
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    result = apr_pcalloc(r->pool, (APR_SHA1_DIGESTSIZE*2)+1);
    buffer = lua_tolstring(L, 2, &y);
    apr_sha1_init(&sha1);
    apr_sha1_update(&sha1, buffer, y);
    apr_sha1_final(digest.chr, &sha1);

    for (x = 0; x < 20; x += 4) {
        Rsha1[x] = digest.chr[x + 3];
        Rsha1[x + 1] = digest.chr[x + 2];
        Rsha1[x + 2] = digest.chr[x + 1];
        Rsha1[x + 3] = digest.chr[x];
    }

    sha1X = (apr_uint32_t  *) Rsha1;
    sprintf(result, "%08x%08x%08x%08x%08x", sha1X[0], sha1X[1], sha1X[2], sha1X[3], sha1X[4]);
    lua_pushstring(L, result);
    return 1;
}



/* lua_ap_banner; r:banner() - Returns the current server banner */
static int lua_ap_banner(lua_State *L) 
{
    lua_pushstring(L, ap_get_server_banner());
    return 1;
}

/* lua_ap_port; r:port() - Returns the port used by the request */
static int lua_ap_port(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    apr_port_t port;
    /*~~~~~~~~~~~~~~~~~~*/
    r = ap_lua_check_request_rec(L, 1);
    port = ap_get_server_port(r);
    lua_pushnumber(L, port);
    return 1;
}

/* lua_ap_mpm_query; r:mpm_query(info) - Queries for MPM info */
static int lua_ap_mpm_query(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    int x,y;
    /*~~~~~~~~~~~~~~~~~~*/
    x = lua_tonumber(L, 1);
    ap_mpm_query(x, &y);
    lua_pushnumber(L, y);
    return 1;
}

/* lua_ap_expr; r:expr(string) - Evaluates an expr statement. */
static int lua_ap_expr(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    int x = 0;
    const char *expr, *err;
    ap_expr_info_t res;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TSTRING);
    r = ap_lua_check_request_rec(L, 1);
    expr = lua_tostring(L, 2);
    
    
    res.filename = NULL;
    res.flags = 0;
    res.line_number = 0;
    res.module_index = 0;
   
    err = ap_expr_parse(r->pool, r->pool, &res, expr, NULL);
    if (!err) {
        x = ap_expr_exec(r, &res, &err);
        lua_pushboolean(L, x);
        if (x < 0) {
            lua_pushstring(L, err);
            return 2;
        }
        return 1;
    }
    else {
        lua_pushboolean(L, 0);
        lua_pushstring(L, err);
        return 2;
    }
    lua_pushboolean(L, 0);
    return 1;
}


/* lua_ap_regex; r:regex(string, pattern) - Evaluates a regex and returns captures if matched */
static int lua_ap_regex(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    int i, rv;
    const char *pattern, *source;
    char *err;
    ap_regex_t regex;
    ap_regmatch_t matches[10];
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TSTRING);
    luaL_checktype(L, 3, LUA_TSTRING);
    r = ap_lua_check_request_rec(L, 1);
    pattern = lua_tostring(L, 2);
    source = lua_tostring(L, 3);
    
    rv = ap_regcomp(&regex, pattern,0);
    if (rv) {
        lua_pushboolean(L, 0);
        err = apr_palloc(r->pool, 256);
        ap_regerror(rv, &regex, err, 256);
        lua_pushstring(L, err);
        return 2;
    }

    rv = ap_regexec(&regex, source, 10, matches, 0);
    if (rv < 0) {
        lua_pushboolean(L, 0);
        err = apr_palloc(r->pool, 256);
        ap_regerror(rv, &regex, err, 256);
        lua_pushstring(L, err);
        return 2;
    }
    lua_newtable(L);
    for (i=0;i<10;i++) {
        lua_pushinteger(L, i);
        if (matches[i].rm_so >= 0 && matches[i].rm_eo >= 0) {
            lua_pushstring(L,apr_pstrndup(r->pool, source+matches[i].rm_so, matches[i].rm_eo - matches[i].rm_so));
        }
        else {
            lua_pushnil(L);
        }
        lua_settable(L, -3);

    }
    return 1;
}




/* lua_ap_scoreboard_process; r:scoreboard_process(a) - returns scoreboard info */
static int lua_ap_scoreboard_process(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    int i;
    process_score* ps_record;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TNUMBER);
    i = lua_tonumber(L, 2);
    ps_record = ap_get_scoreboard_process(i);
    if (ps_record) {
        lua_newtable(L);
        
        lua_pushstring(L, "connections");
        lua_pushnumber(L, ps_record->connections);
        lua_settable(L, -3);
        
        lua_pushstring(L, "keepalive");
        lua_pushnumber(L, ps_record->keep_alive);
        lua_settable(L, -3);
        
        lua_pushstring(L, "lingering_close");
        lua_pushnumber(L, ps_record->lingering_close);
        lua_settable(L, -3);
        
        lua_pushstring(L, "pid");
        lua_pushnumber(L, ps_record->pid);
        lua_settable(L, -3);
        
        lua_pushstring(L, "suspended");
        lua_pushnumber(L, ps_record->suspended);
        lua_settable(L, -3);
        
        lua_pushstring(L, "write_completion");
        lua_pushnumber(L, ps_record->write_completion);
        lua_settable(L, -3);
        
        lua_pushstring(L, "not_accepting");
        lua_pushnumber(L, ps_record->not_accepting);
        lua_settable(L, -3);
        
        lua_pushstring(L, "quiescing");
        lua_pushnumber(L, ps_record->quiescing);
        lua_settable(L, -3);
        
        return 1;
    }
    return 0;
}

/* lua_ap_scoreboard_worker; r:scoreboard_worker(proc, thread) - Returns thread info */
static int lua_ap_scoreboard_worker(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    int i,j;
    worker_score* ws_record;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TNUMBER);
    luaL_checktype(L, 3, LUA_TNUMBER);
    i = lua_tonumber(L, 2);
    j = lua_tonumber(L, 3);
    ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
    if (ws_record) {
        lua_newtable(L);
        
        lua_pushstring(L, "access_count");
        lua_pushnumber(L, ws_record->access_count);
        lua_settable(L, -3);
        
        lua_pushstring(L, "bytes_served");
        lua_pushnumber(L, ws_record->bytes_served);
        lua_settable(L, -3);
        
        lua_pushstring(L, "client");
        lua_pushstring(L, ws_record->client);
        lua_settable(L, -3);
        
        lua_pushstring(L, "conn_bytes");
        lua_pushnumber(L, ws_record->conn_bytes);
        lua_settable(L, -3);
        
        lua_pushstring(L, "conn_count");
        lua_pushnumber(L, ws_record->conn_count);
        lua_settable(L, -3);
        
        lua_pushstring(L, "generation");
        lua_pushnumber(L, ws_record->generation);
        lua_settable(L, -3);
        
        lua_pushstring(L, "last_used");
        lua_pushnumber(L, ws_record->last_used);
        lua_settable(L, -3);
        
        lua_pushstring(L, "pid");
        lua_pushnumber(L, ws_record->pid);
        lua_settable(L, -3);
        
        lua_pushstring(L, "request");
        lua_pushstring(L, ws_record->request);
        lua_settable(L, -3);
        
        lua_pushstring(L, "start_time");
        lua_pushnumber(L, ws_record->start_time);
        lua_settable(L, -3);
        
        lua_pushstring(L, "status");
        lua_pushnumber(L, ws_record->status);
        lua_settable(L, -3);
        
        lua_pushstring(L, "stop_time");
        lua_pushnumber(L, ws_record->stop_time);
        lua_settable(L, -3);
        
        lua_pushstring(L, "tid");

        lua_pushinteger(L, (lua_Integer) ws_record->tid);
        lua_settable(L, -3);
        
        lua_pushstring(L, "vhost");
        lua_pushstring(L, ws_record->vhost);
        lua_settable(L, -3);
#ifdef HAVE_TIMES
        lua_pushstring(L, "stimes");
        lua_pushnumber(L, ws_record->times.tms_stime);
        lua_settable(L, -3);
        
        lua_pushstring(L, "utimes");
        lua_pushnumber(L, ws_record->times.tms_utime);
        lua_settable(L, -3);
#endif
        return 1;
    }
    return 0;
}

/* lua_ap_restarted; r:started() - Returns the timestamp of last server (re)start */
static int lua_ap_restarted(lua_State *L) 
{
        lua_pushnumber(L, ap_scoreboard_image->global->restart_time);
        return 1;
}

/* lua_ap_clock; r:clock() - Returns timestamp with microsecond precision*/
static int lua_ap_clock(lua_State *L)  {
    apr_time_t now;
    now = apr_time_now();
    lua_pushnumber(L, now);
    return 1;
}


/* lua_ap_requestbody; r:requestbody([filename]) - Reads or stores the request body */
static int lua_ap_requestbody(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~*/
    const char  *filename;
    request_rec* r;
    /*~~~~~~~~~~~~~~~~~~*/

    r = ap_lua_check_request_rec(L, 1);
    filename = luaL_optstring(L, 2, 0);
    
    if (r) {

        /*~~~~~~~~~~~~~*/
        apr_off_t   size;
        /*~~~~~~~~~~~~~*/

        if
        (
            r->method_number != M_POST
        &&  r->method_number != M_PUT
        ) return (0);
        if (!filename) {

            /*~~~~~~~~~~~~~~*/
            const char  *data;
            /*~~~~~~~~~~~~~~*/

            if (util_read(r, &data, &size) != OK) {
                return (0);
            }

            lua_pushlstring(L, data, (size_t) size);
            lua_pushinteger(L, (lua_Integer) size);
            return (2);
        }
        else {

            /*~~~~~~~~~~~~~~~~~~*/
            apr_status_t    rc;
            apr_file_t      *file;
            /*~~~~~~~~~~~~~~~~~~*/

            rc = apr_file_open(&file, filename, APR_CREATE | APR_FOPEN_WRITE,
                               APR_FPROT_OS_DEFAULT, r->pool);
            lua_settop(L, 0);
            if (rc == APR_SUCCESS) {
                rc = util_write(r, file, &size);
                apr_file_close(file);
                if (rc == -1) {
                    return (0);
                }

                lua_pushinteger(L, (lua_Integer) size);
                return (1);
            }
            else
                lua_pushboolean(L, 0);
            return (1);
        }
    }

    return (0);
}

/* lua_ap_add_input_filter; r:add_input_filter(name) - Adds an input filter to the chain */
static int lua_ap_add_input_filter(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    const char* filterName;
    ap_filter_rec_t *filter;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TSTRING);
    r = ap_lua_check_request_rec(L, 1);
    filterName = lua_tostring(L, 2);
    filter = ap_get_input_filter_handle(filterName);
    if (filter) {
        ap_add_input_filter_handle(filter, NULL, r, r->connection);
        lua_pushboolean(L, 1);
    }
    else {
        lua_pushboolean(L, 0);
    }
    return 1;
}


/* lua_ap_module_info; r:module_info(mod_name) - Returns information about a loaded module */
static int lua_ap_module_info(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    const char* moduleName;
    module* mod;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TSTRING);
    moduleName = lua_tostring(L, 1);
    mod = ap_find_linked_module(moduleName);
    if (mod) {
        int i = 0;
        const command_rec *cmd;
        lua_newtable(L);
        lua_pushstring(L, "commands");
        lua_newtable(L);
        for (cmd = mod->cmds; cmd->name; ++cmd) {
            lua_pushstring(L, cmd->name);
            lua_pushstring(L, cmd->errmsg);
            lua_settable(L, -3);
        }
        lua_settable(L, -3);
        return 1;
    }
    return 0;
}

/* lua_ap_runtime_dir_relative: r:runtime_dir_relative(file): Returns the filename as relative to the runtime dir*/
static int lua_ap_runtime_dir_relative(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    const char* file;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    file = luaL_optstring(L, 2, ".");
    lua_pushstring(L, ap_runtime_dir_relative(r->pool, file));
    return 1;
}

/* lua_ap_set_document_root; r:set_document_root(path) - sets the current doc root for the request */
static int lua_ap_set_document_root(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    const char* root;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TSTRING);
    r = ap_lua_check_request_rec(L, 1);
    root = lua_tostring(L, 2);
    ap_set_document_root(r, root);
    return 0;
}

/* lua_ap_stat; r:stat(filename) - Runs stat on a file and returns the file info as a table */
static int lua_ap_stat(lua_State *L) 
{
    /*~~~~~~~~~~~~~~~~~~*/
    request_rec *r;
    const char* filename;
    apr_finfo_t file_info;
    /*~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 1, LUA_TUSERDATA);
    luaL_checktype(L, 2, LUA_TSTRING);
    r = ap_lua_check_request_rec(L, 1);
    filename = lua_tostring(L, 2);
    apr_stat(&file_info, filename, APR_FINFO_NORM, r->pool);
    lua_newtable(L);
    
    lua_pushstring(L, "mtime");
    lua_pushinteger(L, file_info.mtime);
    lua_settable(L, -3);
    
    lua_pushstring(L, "atime");
    lua_pushinteger(L, file_info.atime);
    lua_settable(L, -3);
    
    lua_pushstring(L, "ctime");
    lua_pushinteger(L, file_info.ctime);
    lua_settable(L, -3);
    
    lua_pushstring(L, "size");
    lua_pushinteger(L, file_info.size);
    lua_settable(L, -3);
    
    lua_pushstring(L, "filetype");
    lua_pushinteger(L, file_info.filetype);
    lua_settable(L, -3);
    
    return 1;
}

/* lua_ap_loaded_modules; r:loaded_modules() - Returns a list of loaded modules */
static int lua_ap_loaded_modules(lua_State *L) 
{
    int i;
    lua_newtable(L);
    for (i = 0; ap_loaded_modules[i] && ap_loaded_modules[i]->name; i++) {
        lua_pushinteger(L, i+1);
        lua_pushstring(L, ap_loaded_modules[i]->name);
        lua_settable(L, -3);
    }
    return 1;
}

/* lua_ap_server_info; r:server_info() - Returns server info, such as the executable filename, server root, mpm etc*/
static int lua_ap_server_info(lua_State *L) 
{
    lua_newtable(L);
    
    lua_pushstring(L, "server_executable");
    lua_pushstring(L, ap_server_argv0);
    lua_settable(L, -3);
    
    lua_pushstring(L, "server_root");
    lua_pushstring(L, ap_server_root);
    lua_settable(L, -3);
    
    lua_pushstring(L, "scoreboard_fname");
    lua_pushstring(L, ap_scoreboard_fname);
    lua_settable(L, -3);
    
    lua_pushstring(L, "server_mpm");
    lua_pushstring(L, ap_show_mpm());
    lua_settable(L, -3);
    
    return 1;
}


/* === Auto-scraped functions === */

/** 
 * ap_add_version_component (apr_pool_t *pconf, const char *component)
 * Add a component to the server description and banner strings
 * @param pconf The pool to allocate the component from
 * @param component The string to add
  */
static int lua_ap_add_version_component (lua_State *L) {

    request_rec *r;
    const char* component;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    component = lua_tostring(L, 2);
    ap_add_version_component(r->server->process->pconf, component);
    return 0;
}


/** 
 * ap_set_context_info (request_rec *r, const char *prefix,
                                     const char *document_root) Set context_prefix and context_document_root for a request.
 * @param r The request
 * @param prefix the URI prefix, without trailing slash
 * @param document_root the corresponding directory on disk, without trailing
 * slash
 * @note If one of prefix of document_root is NULL, the corrsponding
 * property will not be changed.
  */
static int lua_ap_set_context_info (lua_State *L) {

    request_rec *r;
    const char* prefix;
    const char* document_root;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    prefix = lua_tostring(L, 2);
    luaL_checktype(L, 3, LUA_TSTRING);
    document_root = lua_tostring(L, 3);
    ap_set_context_info(r, prefix, document_root);
    return 0;
}


/** 
 * ap_os_escape_path (apr_pool_t *p, const char *path, int partial)
 * convert an OS path to a URL in an OS dependant way.
 * @param p The pool to allocate from
 * @param path The path to convert
 * @param partial if set, assume that the path will be appended to something
 *        with a '/' in it (and thus does not prefix "./")
 * @return The converted URL
  */
static int lua_ap_os_escape_path (lua_State *L) {

    char * returnValue;
    request_rec *r;
    const char* path;
    int partial = 0;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    path = lua_tostring(L, 2);
    if ( lua_isboolean( L, 3 ) ) partial =  lua_toboolean( L, 3 );
    returnValue = ap_os_escape_path(r->pool, path, partial);
    lua_pushstring(L, returnValue);
    return 1;
}


/** 
 * ap_escape_logitem (apr_pool_t *p, const char *str)
 * Escape a string for logging
 * @param p The pool to allocate from
 * @param str The string to escape
 * @return The escaped string
  */
static int lua_ap_escape_logitem (lua_State *L) {

    char * returnValue;
    request_rec *r;
    const char* str;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    str = lua_tostring(L, 2);
    returnValue = ap_escape_logitem(r->pool, str);
    lua_pushstring(L, returnValue);
    return 1;
}

/** 
 * ap_strcmp_match (const char *str, const char *expected)
 * Determine if a string matches a patterm containing the wildcards '?' or '*'
 * @param str The string to check
 * @param expected The pattern to match against
 * @return 1 if the two strings match, 0 otherwise
  */
static int lua_ap_strcmp_match (lua_State *L) {
    
    int returnValue;
    const char* str;
    const char* expected;
    int ignoreCase = 0;
    luaL_checktype(L, 1, LUA_TSTRING);
    str = lua_tostring(L, 1);
    luaL_checktype(L, 2, LUA_TSTRING);
    expected = lua_tostring(L, 2);
    if ( lua_isboolean( L, 3 ) ) ignoreCase =  lua_toboolean( L, 3 );
    if (!ignoreCase) returnValue = ap_strcmp_match(str, expected);
    else returnValue = ap_strcasecmp_match(str, expected);
    lua_pushboolean(L, (!returnValue)); /* Somehow, this doesn't match the docs */
    return 1;
}


/** 
 * ap_set_keepalive (request_rec *r)
 * Set the keepalive status for this request
 * @param r The current request
 * @return 1 if keepalive can be set, 0 otherwise
  */
static int lua_ap_set_keepalive (lua_State *L) {

    int returnValue;
    request_rec *r;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    returnValue = ap_set_keepalive(r);
    lua_pushboolean(L, returnValue);
    return 1;
}

/** 
 * ap_make_etag (request_rec *r, int force_weak)
 * Construct an entity tag from the resource information.  If it's a real
 * file, build in some of the file characteristics.
 * @param r The current request
 * @param force_weak Force the entity tag to be weak - it could be modified
 *                   again in as short an interval.
 * @return The entity tag
  */
static int lua_ap_make_etag (lua_State *L) {

    char * returnValue;
    request_rec *r;
    int force_weak;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TBOOLEAN);
    force_weak = luaL_optint(L, 2, 0);
    returnValue = ap_make_etag(r, force_weak);
    lua_pushstring(L, returnValue);
    return 1;
}



/** 
 * ap_send_interim_response (request_rec *r, int send_headers)
 * Send an interim (HTTP 1xx) response immediately.
 * @param r The request
 * @param send_headers Whether to send&clear headers in r->headers_out
  */
static int lua_ap_send_interim_response (lua_State *L) {

    request_rec *r;
    int send_headers = 0;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    if ( lua_isboolean( L, 2 ) ) send_headers =  lua_toboolean( L, 2 );
    ap_send_interim_response(r, send_headers);
    return 0;
}


/** 
 * ap_custom_response (request_rec *r, int status, const char *string)
 * Install a custom response handler for a given status
 * @param r The current request
 * @param status The status for which the custom response should be used
 * @param string The custom response.  This can be a static string, a file
 *               or a URL
  */
static int lua_ap_custom_response (lua_State *L) {

    request_rec *r;
    int status;
    const char* string;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    luaL_checktype(L, 2, LUA_TNUMBER);
    status = lua_tointeger(L, 2);
    luaL_checktype(L, 3, LUA_TSTRING);
    string = lua_tostring(L, 3);
    ap_custom_response(r, status, string);
    return 0;
}


/** 
 * ap_exists_config_define (const char *name)
 * Check for a definition from the server command line
 * @param name The define to check for
 * @return 1 if defined, 0 otherwise
  */
static int lua_ap_exists_config_define (lua_State *L) {

    int returnValue;
    const char* name;
    luaL_checktype(L, 1, LUA_TSTRING);
    name = lua_tostring(L, 1);
    returnValue = ap_exists_config_define(name);
    lua_pushinteger(L, returnValue);
    return 1;
}

static int lua_ap_get_server_name_for_url (lua_State *L) {

    const char* servername;
    request_rec *r;
    luaL_checktype(L, 1, LUA_TUSERDATA);
    r = ap_lua_check_request_rec(L, 1);
    servername = ap_get_server_name_for_url(r);
    lua_pushstring(L, servername);
    return 1;
}



/** 
 * ap_state_query (int query_code) item starts a new field  */
static int lua_ap_state_query (lua_State *L) {

    int returnValue;
    int query_code;
    luaL_checktype(L, 1, LUA_TNUMBER);
    query_code = lua_tointeger(L, 1);
    returnValue = ap_state_query(query_code);
    lua_pushinteger(L, returnValue);
    return 1;
}

static int lua_ap_sleep (lua_State *L) {

    int msec;
    luaL_checktype(L, 1, LUA_TNUMBER);
    msec = (lua_tonumber(L, 1) * 1000000);
    apr_sleep(msec);
    return 0;
}

static const struct luaL_Reg httpd_functions [] = {
      {"base64_encode",         lua_apr_b64encode},
      {"base64_decode",         lua_apr_b64decode},
      {"md5",                   lua_apr_md5},
      {"sha1",                  lua_apr_sha1},
      {"escape",                lua_ap_escape},
      {"unescape",              lua_ap_unescape},
      {"banner",                lua_ap_banner},
      {"port",                  lua_ap_port},
      {"mpm_query",             lua_ap_mpm_query},
      {"expr",                  lua_ap_expr},
      {"scoreboard_process",    lua_ap_scoreboard_process},
      {"scoreboard_worker",     lua_ap_scoreboard_worker},
      {"started",               lua_ap_restarted},
      {"clock",                 lua_ap_clock},
      {"requestbody",           lua_ap_requestbody},
      {"add_input_filter",      lua_ap_add_input_filter},
      {"module_info",           lua_ap_module_info},
      {"loaded_modules",        lua_ap_loaded_modules},
      {"runtime_dir_relative",  lua_ap_runtime_dir_relative},
      {"server_info",           lua_ap_server_info},
      {"set_document_root",     lua_ap_set_document_root},
      {"add_version_component"         , lua_ap_add_version_component},
      {"set_context_info"              , lua_ap_set_context_info},
      {"os_escape_path"                , lua_ap_os_escape_path},
      {"escape_logitem"                , lua_ap_escape_logitem},
      {"strcmp_match"                  , lua_ap_strcmp_match},
      {"set_keepalive"                 , lua_ap_set_keepalive},
      {"make_etag"                     , lua_ap_make_etag},     
      {"send_interim_response"         , lua_ap_send_interim_response},
      {"custom_response"               , lua_ap_custom_response},
      {"exists_config_define"          , lua_ap_exists_config_define},
      {"state_query"                   , lua_ap_state_query},
      {"stat"                          , lua_ap_stat},
      {"regex"                         , lua_ap_regex},
      {"sleep"                         , lua_ap_sleep},
      {"get_server_name_for_url"       , lua_ap_get_server_name_for_url},
      {NULL, NULL}  /* sentinel */
};

AP_LUA_DECLARE(int) ap_lua_load_httpd_functions(lua_State *L) 
{
    lua_getglobal(L, "apache2");
    luaL_register(L, NULL, httpd_functions);
    return 0;
}
