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
#include "vmprep.h"
#include "mod_wombat.h"
#include "http_log.h"
#include "apr_reslist.h"
#include "apr_uuid.h"
#include "config.h"
#include "apr_file_info.h"

/* forward dec'l from this file */
// static int load_file(apr_pool_t *working_pool, lua_State* L, const apw_code_cache* cfg, apw_vm_spec *spec);

void pstack_dump(lua_State* L, apr_pool_t* r, int level, const char* msg) {
    ap_log_perror(APLOG_MARK, level, 0, r, "Lua Stack Dump: [%s]", msg);

    int i;
    int top = lua_gettop(L);
    for (i = 1; i<= top; i++) {
        int t = lua_type(L, i);
        switch(t) {
            case LUA_TSTRING: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  '%s'", i, lua_tostring(L, i));
                break;
            }
            case LUA_TUSERDATA: {
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  userdata", i);                
                break;
            }
            case LUA_TLIGHTUSERDATA: {
                ap_log_perror(APLOG_MARK, level, 0, r, "%d:  lightuserdata", i);
                break;
            }
            case LUA_TNIL: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  NIL", i);
                break;
            }
            case LUA_TNONE: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  None", i);
                break;
            }
            case LUA_TBOOLEAN: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  %s", i,  lua_toboolean(L, i) ? "true" : "false");
                break;
            }
            case LUA_TNUMBER: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  %g", i, lua_tonumber(L, i));
                break;
            }
            case LUA_TTABLE: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  <table>", i);
                break;
            }
            case LUA_TTHREAD: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  <thread>", i);
                break;
            }
            case LUA_TFUNCTION: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  <function>", i);
                break;
            }
            default: {
                ap_log_perror(APLOG_MARK, level, 0, r, 
                              "%d:  unkown: [%s]", i, lua_typename(L, i));
                break;                
            }
        }
    }
}

/* BEGIN modules*/

/* BEGIN apache lmodule  */

void apw_load_apache2_lmodule(lua_State *L) {
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "loaded");
    lua_newtable(L);    
    lua_setfield(L, -2, "apache2");
    lua_setglobal(L, "apache2");
    lua_pop(L, 1); /* empty stack */

    lua_getglobal(L, "apache2");
    lua_pushinteger(L, OK);
    lua_setfield(L, -2, "OK");

    lua_pushinteger(L, DECLINED);
    lua_setfield(L, -2, "DECLINED");

    lua_pushinteger(L, DONE);
    lua_setfield(L, -2, "DONE");
   
    lua_pushstring(L, ap_get_server_banner());
    lua_setfield(L, -2, "version");

    lua_pushinteger(L, HTTP_MOVED_TEMPORARILY);
    lua_setfield(L, -2, "HTTP_MOVED_TEMPORARILY");
    
    /*
    lua_pushinteger(L, HTTP_CONTINUE);
    lua_setfield(L, -2, "HTTP_CONTINUE");
    lua_pushinteger(L, HTTP_SWITCHING_PROTOCOLS);
    lua_setfield(L, -2, "HTTP_SWITCHING_PROTOCOLS");
    lua_pushinteger(L, HTTP_PROCESSING);
    lua_setfield(L, -2, "HTTP_PROCESSING");
    lua_pushinteger(L, HTTP_OK);
    lua_setfield(L, -2, "HTTP_OK");
    lua_pushinteger(L, HTTP_CREATED);
    lua_setfield(L, -2, "HTTP_CREATED");
    lua_pushinteger(L, HTTP_ACCEPTED);
    lua_setfield(L, -2, "HTTP_ACCEPTED");
    lua_pushinteger(L, HTTP_NON_AUTHORITATIVE);
    lua_setfield(L, -2, "HTTP_NON_AUTHORITATIVE");
    lua_pushinteger(L, HTTP_NO_CONTENT);
    lua_setfield(L, -2, "HTTP_NO_CONTENT");
    lua_pushinteger(L, HTTP_RESET_CONTENT);
    lua_setfield(L, -2, "HTTP_RESET_CONTENT");
    lua_pushinteger(L, HTTP_PARTIAL_CONTENT);
    lua_setfield(L, -2, "HTTP_PARTIAL_CONTENT");
    lua_pushinteger(L, HTTP_MULTI_STATUS);
    lua_setfield(L, -2, "HTTP_MULTI_STATUS");
    lua_pushinteger(L, HTTP_MULTIPLE_CHOICES);
    lua_setfield(L, -2, "HTTP_MULTIPLE_CHOICES");
    lua_pushinteger(L, HTTP_MOVED_PERMANENTLY);
    lua_setfield(L, -2, "HTTP_MOVED_PERMANENTLY");
    lua_pushinteger(L, HTTP_SEE_OTHER);
    lua_setfield(L, -2, "HTTP_SEE_OTHER");
    lua_pushinteger(L, HTTP_NOT_MODIFIED);
    lua_setfield(L, -2, "HTTP_NOT_MODIFIED");
    lua_pushinteger(L, HTTP_USE_PROXY);
    lua_setfield(L, -2, "HTTP_USE_PROXY");
    lua_pushinteger(L, HTTP_TEMPORARY_REDIRECT);
    lua_setfield(L, -2, "HTTP_TEMPORARY_REDIRECT");
    lua_pushinteger(L, HTTP_BAD_REQUEST);
    lua_setfield(L, -2, "HTTP_BAD_REQUEST");
    lua_pushinteger(L, HTTP_UNAUTHORIZED);
    lua_setfield(L, -2, "HTTP_UNAUTHORIZED");
    lua_pushinteger(L, HTTP_PAYMENT_REQUIRED);
    lua_setfield(L, -2, "HTTP_PAYMENT_REQUIRED");
    lua_pushinteger(L, HTTP_FORBIDDEN);
    lua_setfield(L, -2, "HTTP_FORBIDDEN");
    lua_pushinteger(L, HTTP_NOT_FOUND);
    lua_setfield(L, -2, "HTTP_NOT_FOUND");
    lua_pushinteger(L, HTTP_METHOD_NOT_ALLOWED);
    lua_setfield(L, -2, "HTTP_METHOD_NOT_ALLOWED");
    lua_pushinteger(L, HTTP_NOT_ACCEPTABLE);
    lua_setfield(L, -2, "HTTP_NOT_ACCEPTABLE");
    lua_pushinteger(L, HTTP_PROXY_AUTHENTICATION_REQUIRED);
    lua_setfield(L, -2, "HTTP_PROXY_AUTHENTICATION_REQUIRED");
    lua_pushinteger(L, HTTP_REQUEST_TIME_OUT);
    lua_setfield(L, -2, "HTTP_REQUEST_TIME_OUT");
    lua_pushinteger(L, HTTP_CONFLICT);
    lua_setfield(L, -2, "HTTP_CONFLICT");
    lua_pushinteger(L, HTTP_GONE);
    lua_setfield(L, -2, "HTTP_GONE");
    lua_pushinteger(L, HTTP_LENGTH_REQUIRED);
    lua_setfield(L, -2, "HTTP_LENGTH_REQUIRED");
    lua_pushinteger(L, HTTP_PRECONDITION_FAILED);
    lua_setfield(L, -2, "HTTP_PRECONDITION_FAILED");
    lua_pushinteger(L, HTTP_REQUEST_ENTITY_TOO_LARGE);
    lua_setfield(L, -2, "HTTP_REQUEST_ENTITY_TOO_LARGE");
    lua_pushinteger(L, HTTP_REQUEST_URI_TOO_LARGE);
    lua_setfield(L, -2, "HTTP_REQUEST_URI_TOO_LARGE");
    lua_pushinteger(L, HTTP_UNSUPPORTED_MEDIA_TYPE);
    lua_setfield(L, -2, "HTTP_UNSUPPORTED_MEDIA_TYPE");
    lua_pushinteger(L, HTTP_RANGE_NOT_SATISFIABLE);
    lua_setfield(L, -2, "HTTP_RANGE_NOT_SATISFIABLE");
    lua_pushinteger(L, HTTP_EXPECTATION_FAILED);
    lua_setfield(L, -2, "HTTP_EXPECTATION_FAILED");
    lua_pushinteger(L, HTTP_UNPROCESSABLE_ENTITY);
    lua_setfield(L, -2, "HTTP_UNPROCESSABLE_ENTITY");
    lua_pushinteger(L, HTTP_LOCKED);
    lua_setfield(L, -2, "HTTP_LOCKED");
    lua_pushinteger(L, HTTP_FAILED_DEPENDENCY);
    lua_setfield(L, -2, "HTTP_FAILED_DEPENDENCY");
    lua_pushinteger(L, HTTP_UPGRADE_REQUIRED);
    lua_setfield(L, -2, "HTTP_UPGRADE_REQUIRED");
    lua_pushinteger(L, HTTP_INTERNAL_SERVER_ERROR);
    lua_setfield(L, -2, "HTTP_INTERNAL_SERVER_ERROR");
    lua_pushinteger(L, HTTP_NOT_IMPLEMENTED);
    lua_setfield(L, -2, "HTTP_NOT_IMPLEMENTED");
    lua_pushinteger(L, HTTP_BAD_GATEWAY);
    lua_setfield(L, -2, "HTTP_BAD_GATEWAY");
    lua_pushinteger(L, HTTP_SERVICE_UNAVAILABLE);
    lua_setfield(L, -2, "HTTP_SERVICE_UNAVAILABLE");
    lua_pushinteger(L, HTTP_GATEWAY_TIME_OUT);
    lua_setfield(L, -2, "HTTP_GATEWAY_TIME_OUT");
    lua_pushinteger(L, HTTP_VERSION_NOT_SUPPORTED);
    lua_setfield(L, -2, "HTTP_VERSION_NOT_SUPPORTED");
    lua_pushinteger(L, HTTP_VARIANT_ALSO_VARIES);
    lua_setfield(L, -2, "HTTP_VARIANT_ALSO_VARIES");
    lua_pushinteger(L, HTTP_INSUFFICIENT_STORAGE);
    lua_setfield(L, -2, "HTTP_INSUFFICIENT_STORAGE");
    lua_pushinteger(L, HTTP_NOT_EXTENDED);
    lua_setfield(L, -2, "HTTP_NOT_EXTENDED");
    */
} 

/* END apache2 lmodule */

/*  END library functions */

/* callback for cleaning up a lua vm when pool is closed */
static apr_status_t cleanup_lua(void *l) {
  lua_close((lua_State*) l);
  return APR_SUCCESS;
}

static void munge_path(lua_State *L, 
                       const char *field,
                       const char *sub_pat, 
                       const char *rep_pat,
                       apr_pool_t *pool, 
                       apr_array_header_t *paths, 
                       const char *file) {
  lua_getglobal(L, "package");
  lua_getfield(L, -1, field);
  const char* current = lua_tostring(L, -1);
  const char* parent_dir = ap_make_dirstr_parent(pool, file);
  const char* pattern = apr_pstrcat(pool, parent_dir, sub_pat, NULL);
  luaL_gsub(L, current, rep_pat, pattern);
  lua_setfield(L, -3, field);
  lua_getfield(L, -2, field);
  const char* modified = lua_tostring(L, -1);
  lua_pop(L, 2);
  
  char * part = apr_pstrdup(pool, modified);
  int i;
  for (i = 0; i < paths->nelts; i++) {
    const char *new_path = ((const char**)paths->elts)[i];
    part = apr_pstrcat(pool, part, ";", new_path, NULL);
  }
  lua_pushstring(L, part);
  lua_setfield(L, -2, field);
  lua_pop(L, 1); /* pop "package" off the stack     */
}

/**
 * pool is a working pool
 */
// static lua_State* create_vm(apw_vm_spec *spec, 
//                             apw_code_cache *cache, 
//                             apr_pool_t *pool) {
//     lua_State* L =  luaL_newstate();
//     luaL_openlibs(L);
//     
//     apw_run_wombat_open(L, pool);
// 
//     munge_path(L, "path", "?.lua", "./?.lua", pool, spec->package_paths, spec->file);
//     munge_path(L, "cpath", "?.so", "./?.so", pool, spec->package_cpaths, spec->file);
//     
//     if (load_file(pool, L, cache, spec)) {
//         ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pool, 
//                      "Unable to compile Lua file '%s' because of '%s'",
//                      spec->file, luaL_checkstring(L, -1));
//         return NULL;
//     }    
//     return L;
// }

// typedef struct {
//     server_rec *server;
//     apw_vm_spec *spec;
// } server_vm_params;


// static apr_status_t server_vm_ctor(void **resource, void *_params, apr_pool_t *pool) {
//     server_vm_params *params = _params;
//     apw_server_cfg *cfg = ap_get_module_config(params->server->module_config, &wombat_module);    
//     lua_State *L = create_vm(params->spec, cfg->code_cache, pool);
//     *resource = L;
//     /* ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, params->server, "L is %d", (int)L); */
//     return OK;
// }
// 
// static apr_status_t server_vm_dtor(void *resource, void *_params, apr_pool_t *pool) {
//     return OK;
// }
// 
// typedef struct {
//     apr_reslist_t *reslist;
//     lua_State *L;
// } server_release_t;
// 
// static apr_status_t release_server_vm(void *l) {
//     server_release_t *srt = l;
//     apr_reslist_release(srt->reslist, srt->L);
//     return APR_SUCCESS;
// }

/* Initially we will just use a resource list keyed to the file name */
// static lua_State* get_server_vm(server_rec *server, apw_vm_spec *spec) {
//     apr_status_t rv;
//     apw_server_cfg *cfg = ap_get_module_config(server->module_config, &wombat_module);
//         
//     apr_thread_rwlock_rdlock(cfg->vm_reslists_lock);
//     apr_reslist_t *rlist = apr_hash_get(cfg->vm_reslists, spec->file, APR_HASH_KEY_STRING);
//     apr_thread_rwlock_unlock(cfg->vm_reslists_lock);
//     if (!rlist) {
//         apr_thread_rwlock_wrlock(cfg->vm_reslists_lock);    
//         /* double checked lock (works in C :-) */
//         rlist = apr_hash_get(cfg->vm_reslists, spec->file, APR_HASH_KEY_STRING);
//         if (!rlist) {
//             ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Creating RESLIST");
//     
//             server_vm_params *params = apr_palloc(server->process->pconf, sizeof(server_vm_params));
//             
//             params->server = server;
//             params->spec = apr_pcalloc(server->process->pconf, sizeof(apw_vm_spec));
//             params->spec->file = apr_pstrdup(server->process->pconf, spec->file);
//             params->spec->code_cache_style = spec->code_cache_style;
//             params->spec->scope = APW_SCOPE_SERVER;
//             params->spec->package_paths = spec->package_paths;
//             params->spec->package_cpaths = spec->package_cpaths;
//             ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Creating reslist for %s", spec->file);
//             rv = apr_reslist_create(&rlist,      /* the list */
//                                     10, 100, 100, /* min, soft max, hard max */
//                                     0,           /* TTL */
//                                     server_vm_ctor,
//                                     server_vm_dtor,
//                                     params,
//                                     server->process->pconf);
// 
//             apr_hash_set(cfg->vm_reslists, params->spec->file, APR_HASH_KEY_STRING, (void*)rlist);
//         }
//         apr_thread_rwlock_unlock(cfg->vm_reslists_lock);
//     }
//     lua_State *L;
//     apr_reslist_acquire(rlist, (void*)&L);
//     
//     server_release_t *srt = apr_palloc(spec->pool, sizeof(server_release_t));
//     srt->reslist = rlist;
//     srt->L = L;
//     apr_pool_cleanup_register(spec->pool, srt, release_server_vm, apr_pool_cleanup_null);
//     
//     /* apr_pool_cleanup_register(r->pool, L, cleanup_lua, apr_pool_cleanup_null); */
//     
//     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "Acquired lua_State %p", L);
//     return L;
// }

/* Initially we will just use a resource list keyed to the file name */
// static lua_State* get_request_vm(request_rec *r, apw_vm_spec *spec) {
//     /* apr_status_t rv; */
//     apw_request_cfg *cfg = ap_get_module_config(r->request_config, &wombat_module);
//     apw_server_cfg *server_cfg = ap_get_module_config(r->server->module_config, &wombat_module);    
//     
//     ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "got module config! %p", cfg);
//     lua_State *L = apr_hash_get(cfg->request_scoped_vms, spec->file, APR_HASH_KEY_STRING);
//     if (!L) {
//         L = create_vm(spec, server_cfg->code_cache, r->pool);
//         apr_hash_set(cfg->request_scoped_vms, spec->file, APR_HASH_KEY_STRING, L);
//     }
//     return L;
// }

// lua_State* apw_rgetvm(request_rec *r, apw_vm_spec *spec) {
//     apr_status_t rv;
//     const apw_dir_cfg* cfg = ap_get_module_config(r->per_dir_config, &wombat_module);
//     apw_server_cfg *server_cfg = ap_get_module_config(r->server->module_config, &wombat_module);
//     char *fixed_filename;
//     rv = apr_filepath_merge(&fixed_filename, server_cfg->root_path, spec->file, APR_FILEPATH_NOTRELATIVE, r->pool);
//     if (rv != APR_SUCCESS) {
//         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Unable to build full path to file, %s", spec->file);
//         return NULL;
//     }
//     spec->file = fixed_filename;
//     lua_State* L;
//     switch (spec->scope) {            
//         case APW_SCOPE_REQUEST: 
//             spec->package_paths = cfg->package_paths;
//             spec->package_cpaths = cfg->package_cpaths;
//             spec->pool = r->pool;
//             L = get_request_vm(r, spec);           
//             return L;
//             return NULL;
// 
//         case APW_SCOPE_CONN:
//             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Conn Scoped Lua VMs not implemented yet");
//             return NULL;
// 
//         case APW_SCOPE_SERVER:
//             spec->package_paths = cfg->package_paths;
//             spec->package_cpaths = cfg->package_cpaths;
//             spec->pool = r->pool;
//             L = get_server_vm(r->server, spec);           
//             return L;
// 
//         default:
//             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unknown Lua VM scope specified, using 'once'");
//             /* fall through on purpose */
//         case APW_SCOPE_ONCE:
//             spec->package_paths = cfg->package_paths;
//             spec->package_cpaths = cfg->package_cpaths;
//             L =  create_vm(spec, server_cfg->code_cache, r->pool);
//             if (spec->pool == NULL) {
//                 apr_pool_cleanup_register(r->pool, L, cleanup_lua, apr_pool_cleanup_null);                
//             }
//             apr_pool_cleanup_register(spec->pool, L, cleanup_lua, apr_pool_cleanup_null);
//             break;
//     }
//     
//     return L;
// }

/* returns NULL if the spec requires a request scope */
// lua_State* apw_cgetvm(conn_rec *conn, apw_vm_spec *spec) {
//     
//     return NULL;
// }

/**
 * TODO Redo to make use of the create_vm
 */
// lua_State* apw_sgetvm(server_rec *server, apw_vm_spec *spec) {
//     apr_status_t rv;
//     if (spec->scope == APW_SCOPE_REQUEST || spec->scope == APW_SCOPE_CONN) {
//         return NULL;
//     }
//     
//     apw_server_cfg *server_cfg = ap_get_module_config(server->module_config, &wombat_module);
//     char *fixed_filename;
//     rv = apr_filepath_merge(&fixed_filename, server_cfg->root_path, spec->file, APR_FILEPATH_NOTRELATIVE, 
//                             server->process->pconf);
//     if (rv != APR_SUCCESS) {
//         ap_log_error(APLOG_MARK, APLOG_ERR, rv, server, "Unable to build full path to file, %s", spec->file);
//         return NULL;
//     }
//     spec->file = fixed_filename;
//     
//     apr_pool_t *pool = NULL;
//     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "ALLOCATING A LUA");
//     /* TODO change to use load_file */
//     lua_State* L = luaL_newstate();
//     luaL_openlibs(L);
//     apw_load_apache2_lmodule(L);
//     apw_load_config_lmodule(L);
//     
//     if (luaL_loadfile(L, spec->file)) {
//         ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
//                      "Unable to compile Lua file '%s' because of '%s'",
//                      spec->file, luaL_checkstring(L, -1));
//         return NULL;
//     }
//     
//     if (lua_pcall(L, 0, LUA_MULTRET, 0)) {
//         ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
//                      "Unable to compile Lua file '%s' because of '%s'",
//                      spec->file, luaL_checkstring(L, -1));
//         return NULL;
//     }
//     
//     switch (spec->scope) {
//         case APW_SCOPE_ONCE:
//             if (spec->pool == NULL) {
//                 ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
//                              "You must provide a pool for APW_SCOPE_ONCE");                
//                 lua_close(L);
//                 return NULL;
//             }
//             pool = spec->pool;
//             break;
//             
//         case APW_SCOPE_REQUEST: 
//             break;
// 
//         case APW_SCOPE_CONN: 
//             break;
// 
//         case APW_SCOPE_SERVER: 
//             lua_close(L);
//             ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
//                          "Server Scoped Lua VMs not implemented yet");
//             return NULL;
// 
//         default:
//             pool = spec->pool;
//             ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, 
//                          "Unknown Lua VM scope specified, using 'once'");
//     }
//     
//     apr_pool_cleanup_register(pool, L, cleanup_lua, apr_pool_cleanup_null);
//     return L;
// }

/* represents a cache entry */
// typedef struct {
//     apr_array_header_t *parts; /* <part_t> */
//     apr_time_t mtime;
//     apr_pool_t *pool;
// } code_cache_entry;
// 
// typedef struct {
//     apr_pool_t *pool;
//     apr_array_header_t *parts; /* <part_t> */
// } dumper_t;
// 
// typedef struct {
//     apr_array_header_t* parts;
//     int idx;
//     request_rec* r;
// } loader_t;
// 
// typedef struct {
//     const void* chunk;
//     size_t sz;
// } part_t;
// 
// static int wlua_dumper(lua_State *L, const void* p, size_t sz, void* ud) {
//     dumper_t* d = (dumper_t*)ud;    
//     part_t* part = apr_palloc(d->pool, sizeof(part_t));
//     void* mine = apr_palloc(d->pool, sz);
//     memcpy(mine, p, sz);
//     part->chunk = mine;
//     part->sz = sz;
//     *(const part_t**)apr_array_push(d->parts) = part;
//     return 0;
// }
// 
// static const char* wlua_loader(lua_State* L, void* data, size_t* size) {
//     loader_t* l = (loader_t*) data;
//     /* ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, l->r, "part count %d", l->parts->nelts); */
//     if (l->idx == l->parts->nelts) {
//         return NULL;
//     }
//     part_t* part = ((part_t**)l->parts->elts)[l->idx++];
//     *size = part->sz;
//     /* ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, l->r, "got part of size %lu", *size); */
//     return part->chunk;
// }

// static int load_file(apr_pool_t *working_pool, lua_State* L, const apw_code_cache* cfg, apw_vm_spec *spec) {
//     int rs;
// 
//     if (spec->bytecode_len != 0) {
//         rs = luaL_loadbuffer(L, spec->bytecode, spec->bytecode_len, spec->file);
//         if (rs) {
//             ap_log_perror(APLOG_MARK, APLOG_DEBUG, rs, working_pool, "Unable to load %s from buffer", spec->file);
//             return rs;
//         }
//     }
//     else if (spec->code_cache_style != APW_CODE_CACHE_NEVER) {
//         /* start code caching magic */
//         apr_thread_rwlock_rdlock(cfg->compiled_files_lock);
//         code_cache_entry *cache = apr_hash_get(cfg->compiled_files, spec->file, APR_HASH_KEY_STRING);
//         apr_thread_rwlock_unlock(cfg->compiled_files_lock);
// 
//         int stale = 0;
//         apr_finfo_t *finfo = NULL;
//         if (cache == NULL || spec->code_cache_style == APW_CODE_CACHE_STAT) {
//             ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, working_pool, "stating %s", spec->file);
// 
//             finfo = apr_palloc(working_pool, sizeof(apr_finfo_t));
//             apr_stat(finfo, spec->file, APR_FINFO_MTIME, working_pool);
// 
//             /* has the file been modified or is this the first time we load the file? */
//             if (cache == NULL || finfo->mtime > cache->mtime) {
//                 /* we're expired */
//                 ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, working_pool, "file is stale: %s ", spec->file);
//                 stale = 1;
//             }
//         }    
// 
//         if (!stale) {
//             ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, working_pool, "loading from cache: %s", spec->file);
// 
//             loader_t* l = apr_palloc(working_pool, sizeof(loader_t));
//             apr_thread_rwlock_rdlock(cfg->compiled_files_lock);
//             l->parts = cache->parts;
//             l->idx = 0;
//             if ((rs = lua_load(L, wlua_loader, l, spec->file))) {
//                 apr_thread_rwlock_unlock(cfg->compiled_files_lock);                
//                 switch (rs) {
//                     case LUA_ERRSYNTAX: {
//                         ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, working_pool, 
//                             "syntax error on compiled [%s] from cache", spec->file);
//                         return rs;
//                     }
//                     case LUA_ERRMEM: {
//                         ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, working_pool, 
//                             "memory error on compiled [%s] from cache", spec->file);
//                         return rs;
//                     }
//                     default: {
//                         ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, working_pool, 
//                             "other error, %d, on compiled [%s] from cache", rs, spec->file);
//                         return rs;
//                     }
//                 }
//                 return rs;
//             }
//             else {
//                 apr_thread_rwlock_unlock(cfg->compiled_files_lock);
//             }
//         }
//         else {
//             ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, working_pool, "loading & caching: %s", spec->file);
//         
//             if ((rs = luaL_loadfile(L, spec->file))) {
//                 return rs;
//             }
//             
//             int is_new = 0;
//             if (!cache) { 
//                 /* allocate a new code_cache_entry from the cfg pool. Since entries are reused
//                  * when files are re-loaded and we don't evict entries from the cache, 
//                  * we don't need to care about de-allocation. 
//                  */
//                 cache = apr_palloc(cfg->pool, sizeof(code_cache_entry));
//                 is_new = 1;
//             }
//             
//             
//             apr_pool_t *mp;
//             apr_pool_create(&mp, cfg->pool);  /* pool from which everything in this code_cache_entry
//                                                * will be allocated */
// 
//             dumper_t* d = apr_palloc(working_pool, sizeof(dumper_t));
//             d->pool = mp;
//             d->parts = apr_array_make(mp, 250, sizeof(part_t*));
//             lua_dump(L, wlua_dumper, d);
// 
//             apr_thread_rwlock_wrlock(cfg->compiled_files_lock);
//             
//             if (is_new) {
//                 /* we copy the filename into a string allocated from the cfg pool. apr_hash keeps
//                  * pointers to keys and values, and we need the key to survive beyond the request lifetime
//                  */
//                 const char* key = apr_pstrdup(cfg->pool, spec->file);
//                 apr_hash_set(cfg->compiled_files, key, APR_HASH_KEY_STRING, cache);
//             }
//             else {
//                 apr_pool_clear(cache->pool);
//             }
// 
//             cache->parts = d->parts;
//             cache->pool = d->pool; 
//             cache->mtime = finfo->mtime;
//             
//             apr_thread_rwlock_unlock(cfg->compiled_files_lock);
// 
//             /* end code caching magic             */
//         }
//     }
//     else { /* CODE_CACHE_NEVER */
//         ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, working_pool, "loading: %s", spec->file);
//         
//         if ((rs = luaL_loadfile(L, spec->file))) {
//             return rs;
//         }
//     }
// 
//     return 0;
// }

/* BEGIN NEW STYLE lua_State MANAGEMENT */

lua_State* apw_get_lua_state(apr_pool_t* lifecycle_pool, 
                            char* file, 
                            apr_array_header_t* package_paths, 
                            apr_array_header_t* package_cpaths,
                            apw_lua_state_open_callback cb,
                            void* btn) {
    
    lua_State* L;
    ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, lifecycle_pool, "obtaining lua_State");
    if (!apr_pool_userdata_get((void**)&L, file, lifecycle_pool)) {
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, lifecycle_pool, "creating lua_State with file %s", file);
        /* not available, so create */
        L =  luaL_newstate();
        luaL_openlibs(L);        
        if (package_paths) 
            munge_path(L, "path", "?.lua", "./?.lua", lifecycle_pool, package_paths, file);
        if (package_cpaths) 
            munge_path(L, "cpath", "?.so", "./?.so", lifecycle_pool, package_cpaths, file);
        
        if (cb) {
            cb(L, lifecycle_pool, btn);
        }
        
        luaL_loadfile(L, file);
        lua_pcall(L, 0, LUA_MULTRET, 0);
        apr_pool_userdata_set(L, file, &cleanup_lua, lifecycle_pool);
        
        lua_pushlightuserdata(L, lifecycle_pool);
        lua_setfield(L, LUA_REGISTRYINDEX, "Apache2.Wombat.pool");  
    }
    return L;
}






