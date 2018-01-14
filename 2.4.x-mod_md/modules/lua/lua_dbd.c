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
#include "lua_dbd.h"

APLOG_USE_MODULE(lua);
static APR_OPTIONAL_FN_TYPE(ap_dbd_close) *lua_ap_dbd_close = NULL;
static APR_OPTIONAL_FN_TYPE(ap_dbd_open) *lua_ap_dbd_open = NULL;




static request_rec *ap_lua_check_request_rec(lua_State *L, int index)
{
    request_rec *r;
    luaL_checkudata(L, index, "Apache2.Request");
    r = lua_unboxpointer(L, index);
    return r;
}

static lua_db_handle *lua_get_db_handle(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_rawgeti(L, 1, 0);
    luaL_checktype(L, -1, LUA_TUSERDATA);
    return (lua_db_handle *) lua_topointer(L, -1);
}

static lua_db_result_set *lua_get_result_set(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_rawgeti(L, 1, 0);
    luaL_checktype(L, -1, LUA_TUSERDATA);
    return (lua_db_result_set *) lua_topointer(L, -1);
}


/*
   =============================================================================
    db:close(): Closes an open database connection.
   =============================================================================
 */
int lua_db_close(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle   *db;
    apr_status_t     rc = 0;
    /*~~~~~~~~~~~~~~~~~~~~*/
    
    db = lua_get_db_handle(L);
    if (db && db->alive) {
        if (db->type == LUA_DBTYPE_APR_DBD) {
            rc = apr_dbd_close(db->driver, db->handle);
            if (db->pool) apr_pool_destroy(db->pool);
        }
        else {
            lua_ap_dbd_close = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_close);
            if (lua_ap_dbd_close != NULL)
                if (db->dbdhandle) lua_ap_dbd_close(db->server, db->dbdhandle);
        }

        db->driver = NULL;
        db->handle = NULL;
        db->alive = 0;
        db->pool = NULL;
    }

    lua_settop(L, 0);
    lua_pushnumber(L, rc);
    return 1;
} 

/*
   =============================================================================
     db:__gc(): Garbage collecting function.
   =============================================================================
 */
int lua_db_gc(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~*/
    lua_db_handle    *db;
    /*~~~~~~~~~~~~~~~~~~~~*/

    db = lua_touserdata(L, 1);
    if (db && db->alive) {
        if (db->type == LUA_DBTYPE_APR_DBD) {
            apr_dbd_close(db->driver, db->handle);
            if (db->pool) apr_pool_destroy(db->pool);
        }
        else {
            lua_ap_dbd_close = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_close);
            if (lua_ap_dbd_close != NULL)
                if (db->dbdhandle) lua_ap_dbd_close(db->server, db->dbdhandle);
        }
        db->driver = NULL;
        db->handle = NULL;
        db->alive = 0;
        db->pool = NULL;
    }
    lua_settop(L, 0);
    return 0;
}

/*
   =============================================================================
    db:active(): Returns true if the connection to the db is still active.
   =============================================================================
 */
int lua_db_active(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle   *db = 0;
    apr_status_t     rc = 0;
    /*~~~~~~~~~~~~~~~~~~~~*/

    db = lua_get_db_handle(L);
    if (db && db->alive) {
        rc = apr_dbd_check_conn(db->driver, db->pool, db->handle);
        if (rc == APR_SUCCESS) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

/*
   =============================================================================
    db:query(statement): Executes the given database query and returns the 
    number of rows affected. If an error is encountered, returns nil as the 
    first parameter and the error message as the second.
   =============================================================================
 */
int lua_db_query(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle   *db = 0;
    apr_status_t     rc = 0;
    int              x = 0;
    const char      *statement;
    /*~~~~~~~~~~~~~~~~~~~~~~~*/
    luaL_checktype(L, 3, LUA_TSTRING);
    statement = lua_tostring(L, 3);
    db = lua_get_db_handle(L);
    if (db && db->alive)
        rc = apr_dbd_query(db->driver, db->handle, &x, statement);
    else {
        rc = 0;
        x = -1;
    }

    if (rc == APR_SUCCESS)
        lua_pushnumber(L, x);
    else {

        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        const char  *err = apr_dbd_error(db->driver, db->handle, rc);
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        lua_pushnil(L);
        if (err) {
            lua_pushstring(L, err);
            return 2;
        }
    }

    return 1;
}

/*
   =============================================================================
    db:escape(string): Escapes a string for safe use in the given database type.
   =============================================================================
 */
int lua_db_escape(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle    *db = 0;
    const char       *statement;
    const char       *escaped = 0;
    request_rec      *r;
    /*~~~~~~~~~~~~~~~~~~~~~*/

    r = ap_lua_check_request_rec(L, 2);
    if (r) {
        luaL_checktype(L, 3, LUA_TSTRING);
        statement = lua_tostring(L, 3);
        db = lua_get_db_handle(L);
        if (db && db->alive) {
            apr_dbd_init(r->pool);
            escaped = apr_dbd_escape(db->driver, r->pool, statement,
                                     db->handle);
            if (escaped) {
                lua_pushstring(L, escaped);
                return 1;
            }
        }
        else {
            lua_pushnil(L);
        }
        return (1);
    }

    return 0;
}

/*
   =============================================================================
     resultset(N): Fetches one or more rows from a result set.
   =============================================================================
 */
int lua_db_get_row(lua_State *L) 
{
    int row_no,x,alpha = 0;
    const char      *entry, *rowname;
    apr_dbd_row_t   *row = 0;
    lua_db_result_set *res = lua_get_result_set(L);
    
    row_no = luaL_optinteger(L, 2, 0);
    if (lua_isboolean(L, 3)) {
        alpha = lua_toboolean(L, 3);
    }
    lua_settop(L,0);
    
    /* Fetch all rows at once? */
    
    if (row_no == 0) {
        row_no = 1;
        lua_newtable(L);
        while (apr_dbd_get_row(res->driver, res->pool, res->results,
                            &row, -1) != -1)
         {
            lua_pushinteger(L, row_no);
            lua_newtable(L);
            for (x = 0; x < res->cols; x++) {
                entry = apr_dbd_get_entry(res->driver, row, x);
                if (entry) {
                    if (alpha == 1) {
                        rowname = apr_dbd_get_name(res->driver, 
                                res->results, x);
                        lua_pushstring(L, rowname ? rowname : "(oob)");
                    }
                    else {
                        lua_pushinteger(L, x + 1);
                    }
                    lua_pushstring(L, entry);
                    lua_rawset(L, -3);
                }
            }
            lua_rawset(L, -3);
            row_no++;
        }
        return 1;
    }
    
    /* Just fetch a single row */
    if (apr_dbd_get_row(res->driver, res->pool, res->results,
                            &row, row_no) != -1)
         {
        
        lua_newtable(L);
        for (x = 0; x < res->cols; x++) {
            entry = apr_dbd_get_entry(res->driver, row, x);
            if (entry) {
                if (alpha == 1) {
                    rowname = apr_dbd_get_name(res->driver, 
                            res->results, x);
                    lua_pushstring(L, rowname ? rowname : "(oob)");
                }
                else {
                    lua_pushinteger(L, x + 1);
                }
                lua_pushstring(L, entry);
                lua_rawset(L, -3);
            }
        }
        return 1;
    }
    return 0;
}


/*
   =============================================================================
    db:select(statement): Queries the database for the given statement and 
    returns the rows/columns found as a table. If an error is encountered, 
    returns nil as the first parameter and the error message as the second.
   =============================================================================
 */
int lua_db_select(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle   *db = 0;
    apr_status_t     rc = 0;
    const char      *statement;
    request_rec     *r;
    /*~~~~~~~~~~~~~~~~~~~~~~~*/
    r = ap_lua_check_request_rec(L, 2);
    if (r) {
        luaL_checktype(L, 3, LUA_TSTRING);
        statement = lua_tostring(L, 3);
        db = lua_get_db_handle(L);
        if (db && db->alive) {

            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
            int cols;
            apr_dbd_results_t   *results = 0;
            lua_db_result_set* resultset = NULL;
            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

            rc = apr_dbd_select(db->driver, db->pool, db->handle,
                                &results, statement, 0);
            if (rc == APR_SUCCESS) {
                
                cols = apr_dbd_num_cols(db->driver, results);
                
                if (cols > 0) {
                    lua_newtable(L);
                    resultset = lua_newuserdata(L, sizeof(lua_db_result_set));
                    resultset->cols = cols;
                    resultset->driver = db->driver;
                    resultset->pool = db->pool;
                    resultset->rows = apr_dbd_num_tuples(db->driver, results);
                    resultset->results = results;
                    luaL_newmetatable(L, "lua_apr.dbselect");
                    lua_pushliteral(L, "__call");
                    lua_pushcfunction(L, lua_db_get_row);
                    lua_rawset(L, -3);
                    lua_setmetatable(L, -3);
                    lua_rawseti(L, -2, 0);
                    return 1;
                }
                return 0;
            }
            else {

                /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
                const char  *err = apr_dbd_error(db->driver, db->handle, rc);
                /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

                lua_pushnil(L);
                if (err) {
                    lua_pushstring(L, err);
                    return 2;
                }
            }
        }

        lua_pushboolean(L, 0);
        return 1;
    }

    return 0;
}



/*
   =============================================================================
    statement:select(var1, var2, var3...): Injects variables into a prepared 
    statement and returns the number of rows matching the query.
   =============================================================================
 */
int lua_db_prepared_select(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_prepared_statement  *st = 0;
    apr_status_t     rc = 0;
    const char       **vars;
    int              x, have;
    /*~~~~~~~~~~~~~~~~~~~~~~~*/
    
    /* Fetch the prepared statement and the vars passed */
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_rawgeti(L, 1, 0);
    luaL_checktype(L, -1, LUA_TUSERDATA);
    st = (lua_db_prepared_statement*) lua_topointer(L, -1);
    
    /* Check if we got enough variables passed on to us.
     * This, of course, only works for prepared statements made through lua. */
    have = lua_gettop(L) - 2;
    if (st->variables != -1 && have < st->variables ) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, 
                "Error in executing prepared statement: Expected %d arguments, got %d.", 
                st->variables, have);
        return 2;
    }
    vars = apr_pcalloc(st->db->pool, have*sizeof(char *));
    for (x = 0; x < have; x++) {
        vars[x] = lua_tostring(L, x + 2);
    }

    /* Fire off the query */
    if (st->db && st->db->alive) {

        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        int cols;
        apr_dbd_results_t   *results = 0;
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        rc = apr_dbd_pselect(st->db->driver, st->db->pool, st->db->handle,
                                &results, st->statement, 0, have, vars);
        if (rc == APR_SUCCESS) {

            /*~~~~~~~~~~~~~~~~~~~~~*/
            lua_db_result_set *resultset;
            /*~~~~~~~~~~~~~~~~~~~~~*/

            cols = apr_dbd_num_cols(st->db->driver, results);
            lua_newtable(L);
            resultset = lua_newuserdata(L, sizeof(lua_db_result_set));
            resultset->cols = cols;
            resultset->driver = st->db->driver;
            resultset->pool = st->db->pool;
            resultset->rows = apr_dbd_num_tuples(st->db->driver, results);
            resultset->results = results;
            luaL_newmetatable(L, "lua_apr.dbselect");
            lua_pushliteral(L, "__call");
            lua_pushcfunction(L, lua_db_get_row);
            lua_rawset(L, -3);
            lua_setmetatable(L, -3);
            lua_rawseti(L, -2, 0);
            return 1;
            
        }
        else {

            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
            const char  *err = apr_dbd_error(st->db->driver, st->db->handle, rc);
            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

            lua_pushnil(L);
            if (err) {
                lua_pushstring(L, err);
                return 2;
            }
            return 1;
        }
    }

    lua_pushboolean(L, 0);
    lua_pushliteral(L, 
            "Database connection seems to be closed, please reacquire it.");
    return (2);
}


/*
   =============================================================================
    statement:query(var1, var2, var3...): Injects variables into a prepared 
    statement and returns the number of rows affected.
   =============================================================================
 */
int lua_db_prepared_query(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_prepared_statement  *st = 0;
    apr_status_t     rc = 0;
    const char       **vars;
    int              x, have;
    /*~~~~~~~~~~~~~~~~~~~~~~~*/
    
    /* Fetch the prepared statement and the vars passed */
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_rawgeti(L, 1, 0);
    luaL_checktype(L, -1, LUA_TUSERDATA);
    st = (lua_db_prepared_statement*) lua_topointer(L, -1);
    
    /* Check if we got enough variables passed on to us.
     * This, of course, only works for prepared statements made through lua. */
    have = lua_gettop(L) - 2;
    if (st->variables != -1 && have < st->variables ) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, 
                "Error in executing prepared statement: Expected %d arguments, got %d.", 
                st->variables, have);
        return 2;
    }
    vars = apr_pcalloc(st->db->pool, have*sizeof(char *));
    for (x = 0; x < have; x++) {
        vars[x] = lua_tostring(L, x + 2);
    }

    /* Fire off the query */
    if (st->db && st->db->alive) {

        /*~~~~~~~~~~~~~~*/
        int affected = 0;
        /*~~~~~~~~~~~~~~*/

        rc = apr_dbd_pquery(st->db->driver, st->db->pool, st->db->handle,
                                &affected, st->statement, have, vars);
        if (rc == APR_SUCCESS) {
            lua_pushinteger(L, affected);
            return 1;
        }
        else {

            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
            const char  *err = apr_dbd_error(st->db->driver, st->db->handle, rc);
            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

            lua_pushnil(L);
            if (err) {
                lua_pushstring(L, err);
                return 2;
            }
            return 1;
        }
    }

    lua_pushboolean(L, 0);
    lua_pushliteral(L, 
            "Database connection seems to be closed, please reacquire it.");
    return (2);
}

/*
   =============================================================================
    db:prepare(statement): Prepares a statement for later query/select.
    Returns a table with a :query and :select function, same as the db funcs.
   =============================================================================
 */
int lua_db_prepare(lua_State* L) 
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle   *db = 0;
    apr_status_t     rc = 0;
    const char      *statement, *at;
    request_rec     *r;
    lua_db_prepared_statement* st;
    int need = 0;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    
    r = ap_lua_check_request_rec(L, 2);
    if (r) {
        apr_dbd_prepared_t *pstatement = NULL;
        luaL_checktype(L, 3, LUA_TSTRING);
        statement = lua_tostring(L, 3);
        
        /* Count number of variables in statement */
        at = ap_strchr_c(statement,'%');
        while (at != NULL) {
            if (at[1] == '%') {
                at++;
            }
            else {
                need++;
            }
            at = ap_strchr_c(at+1,'%');
        }
        
        
        db = lua_get_db_handle(L);
        rc = apr_dbd_prepare(db->driver, r->pool, db->handle, statement, 
                    NULL, &pstatement);
        if (rc != APR_SUCCESS) {
            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
            const char  *err = apr_dbd_error(db->driver, db->handle, rc);
            /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

            lua_pushnil(L);
            if (err) {
                lua_pushstring(L, err);
                return 2;
            }
            return 1;
        }
        
        /* Push the prepared statement table */
        lua_newtable(L);
        st = lua_newuserdata(L, sizeof(lua_db_prepared_statement));
        st->statement = pstatement;
        st->variables = need;
        st->db = db;
        
        lua_pushliteral(L, "select");
        lua_pushcfunction(L, lua_db_prepared_select);
        lua_rawset(L, -4);
        lua_pushliteral(L, "query");
        lua_pushcfunction(L, lua_db_prepared_query);
        lua_rawset(L, -4);
        lua_rawseti(L, -2, 0);
        return 1;
    }
    return 0;
}



/*
   =============================================================================
    db:prepared(statement): Fetches a prepared statement made through 
    DBDPrepareSQL.
   =============================================================================
 */
int lua_db_prepared(lua_State* L) 
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    lua_db_handle   *db = 0;
    const char      *tag;
    request_rec     *r;
    lua_db_prepared_statement* st;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    
    r = ap_lua_check_request_rec(L, 2);
    if (r) {
        apr_dbd_prepared_t *pstatement = NULL;
        db = lua_get_db_handle(L);
        luaL_checktype(L, 3, LUA_TSTRING);
        tag = lua_tostring(L, 3);
        
        /* Look for the statement */
        pstatement = apr_hash_get(db->dbdhandle->prepared, tag, 
                APR_HASH_KEY_STRING);
        
        if (pstatement == NULL) {
            lua_pushnil(L);
            lua_pushfstring(L, 
                    "Could not find any prepared statement called %s!", tag);
            return 2;
        }
        
        
        /* Push the prepared statement table */
        lua_newtable(L);
        st = lua_newuserdata(L, sizeof(lua_db_prepared_statement));
        st->statement = pstatement;
        st->variables = -1; /* we don't know :( */
        st->db = db;
        lua_pushliteral(L, "select");
        lua_pushcfunction(L, lua_db_prepared_select);
        lua_rawset(L, -4);
        lua_pushliteral(L, "query");
        lua_pushcfunction(L, lua_db_prepared_query);
        lua_rawset(L, -4);
        lua_rawseti(L, -2, 0);
        return 1;
    }
    return 0;
}



/* lua_push_db_handle: Creates a database table object with database functions 
   and a userdata at index 0, which will call lua_dbgc when garbage collected.
 */
static lua_db_handle* lua_push_db_handle(lua_State *L, request_rec* r, int type,
        apr_pool_t* pool) 
{
    lua_db_handle* db;
    lua_newtable(L);
    db = lua_newuserdata(L, sizeof(lua_db_handle));
    db->alive = 1;
    db->pool = pool;
    db->type = type;
    db->dbdhandle = 0;
    db->server = r->server;
    luaL_newmetatable(L, "lua_apr.dbacquire");
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, lua_db_gc);
    lua_rawset(L, -3);
    lua_setmetatable(L, -2);
    lua_rawseti(L, -2, 0);
    
    lua_pushliteral(L, "escape");
    lua_pushcfunction(L, lua_db_escape);
    lua_rawset(L, -3);
    
    lua_pushliteral(L, "close");
    lua_pushcfunction(L, lua_db_close);
    lua_rawset(L, -3);
    
    lua_pushliteral(L, "select");
    lua_pushcfunction(L, lua_db_select);
    lua_rawset(L, -3);
    
    lua_pushliteral(L, "query");
    lua_pushcfunction(L, lua_db_query);
    lua_rawset(L, -3);
    
    lua_pushliteral(L, "active");
    lua_pushcfunction(L, lua_db_active);
    lua_rawset(L, -3);
    
    lua_pushliteral(L, "prepare");
    lua_pushcfunction(L, lua_db_prepare);
    lua_rawset(L, -3);
    
    lua_pushliteral(L, "prepared");
    lua_pushcfunction(L, lua_db_prepared);
    lua_rawset(L, -3);
    return db;
}

/*
   =============================================================================
    dbacquire(dbType, dbString): Opens a new connection to a database of type 
    _dbType_ and with the connection parameters _dbString_. If successful, 
    returns a table with functions for using the database handle. If an error 
    occurs, returns nil as the first parameter and the error message as the 
    second. See the APR_DBD for a list of database types and connection strings 
    supported.
   =============================================================================
 */
int lua_db_acquire(lua_State *L)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    const char      *type;
    const char      *arguments;
    const char      *error = 0;
    request_rec     *r;
    lua_db_handle   *db = 0;
    apr_status_t     rc = 0;
    ap_dbd_t        *dbdhandle = NULL;
    apr_pool_t      *pool = NULL;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    r = ap_lua_check_request_rec(L, 1);
    if (r) {
        type = luaL_optstring(L, 2, "mod_dbd"); /* Defaults to mod_dbd */
        
        if (!strcmp(type, "mod_dbd")) {

            lua_settop(L, 0);
            lua_ap_dbd_open = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_open);
            if (lua_ap_dbd_open)
                dbdhandle = (ap_dbd_t *) lua_ap_dbd_open(
                        r->server->process->pool, r->server);

            if (dbdhandle) {
                db = lua_push_db_handle(L, r, LUA_DBTYPE_MOD_DBD, dbdhandle->pool);
                db->driver = dbdhandle->driver;
                db->handle = dbdhandle->handle;
                db->dbdhandle = dbdhandle;
                return 1;
            }
            else {
                lua_pushnil(L);
                if ( lua_ap_dbd_open == NULL )
                    lua_pushliteral(L,
                                    "mod_dbd doesn't seem to have been loaded.");
                else
                    lua_pushliteral(
                        L,
                        "Could not acquire connection from mod_dbd. If your database is running, this may indicate a permission problem.");
                return 2;
            }
        }
        else {
            rc = apr_pool_create(&pool, NULL);
            if (rc != APR_SUCCESS) {
                lua_pushnil(L);
                lua_pushliteral(L, "Could not allocate memory for database!");
                return 2;
            }
            apr_pool_tag(pool, "lua_dbd_pool");
            apr_dbd_init(pool);
            dbdhandle = apr_pcalloc(pool, sizeof(ap_dbd_t));
            rc = apr_dbd_get_driver(pool, type, &dbdhandle->driver);
            if (rc == APR_SUCCESS) {
                luaL_checktype(L, 3, LUA_TSTRING);
                arguments = lua_tostring(L, 3);
                lua_settop(L, 0);
                
                if (*arguments) {
                    rc = apr_dbd_open_ex(dbdhandle->driver, pool, 
                            arguments, &dbdhandle->handle, &error);
                    if (rc == APR_SUCCESS) {
                        db = lua_push_db_handle(L, r, LUA_DBTYPE_APR_DBD, pool);
                        db->driver = dbdhandle->driver;
                        db->handle = dbdhandle->handle;
                        db->dbdhandle = dbdhandle;
                        return 1;
                    }
                    else {
                        lua_pushnil(L);
                        if (error) {
                            lua_pushstring(L, error);
                            return 2;
                        }

                        return 1;
                    }
                }

                lua_pushnil(L);
                lua_pushliteral(L,
                                "No database connection string was specified.");
                apr_pool_destroy(pool);
                return (2);
            }
            else {
                lua_pushnil(L);
                if (APR_STATUS_IS_ENOTIMPL(rc)) {
                    lua_pushfstring(L, 
                         "driver for %s not available", type);
                }
                else if (APR_STATUS_IS_EDSOOPEN(rc)) {
                    lua_pushfstring(L, 
                                "can't find driver for %s", type);
                }
                else if (APR_STATUS_IS_ESYMNOTFOUND(rc)) {
                    lua_pushfstring(L, 
                                "driver for %s is invalid or corrupted",
                                type);
                }
                else {
                    lua_pushliteral(L, 
                                "mod_lua not compatible with APR in get_driver");
                }
                lua_pushinteger(L, rc);
                apr_pool_destroy(pool);
                return 3;
            }
        }

        lua_pushnil(L);
        return 1;
    }

    return 0;
}

