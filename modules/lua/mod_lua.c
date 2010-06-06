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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "lua_apr.h"
#include "lua_config.h"

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap_lua, AP_LUA, int, lua_open,
                                    (lua_State *L, apr_pool_t *p),
                                    (L, p), OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap_lua, AP_LUA, int, lua_request,
                                    (lua_State *L, request_rec *r),
                                    (L, r), OK, DECLINED)

     module AP_MODULE_DECLARE_DATA lua_module;

/**
 * error reporting if lua has an error. 
 * Extracts the error from lua stack and prints
 */
static void report_lua_error(lua_State *L, request_rec *r)
{
    const char *lua_response;
    r->status = HTTP_INTERNAL_SERVER_ERROR;
    r->content_type = "text/html";

    ap_rputs("<b>Error!</b>\n", r);
    ap_rputs("<p>", r);
    lua_response = lua_tostring(L, -1);
    ap_rputs(lua_response, r);
    ap_rputs("</p>\n", r);

    ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, r->pool, "Lua error: %s",
                  lua_response);
}

static void lua_open_callback(lua_State *L, apr_pool_t *p, void *ctx)
{
    ap_lua_init(L, p);
    ap_lua_load_apache2_lmodule(L);
    ap_lua_load_request_lmodule(L, p);
    ap_lua_load_config_lmodule(L);
}

static int lua_open_hook(lua_State *L, apr_pool_t *p)
{
    lua_open_callback(L, p, NULL);
    return OK;
}

/*
static apr_status_t luahood(ap_filter_t *f, apr_bucket_brigade *bb) {
    apr_bucket* b;
    apr_status_t rs;
    for ( b = APR_BRIGADE_FIRST(bb);
          b != APR_BRIGADE_SENTINEL(bb);
          b = APR_BUCKET_NEXT(b)) 
    {
        if (APR_BUCKET_IS_EOS(b)) {kl
            break;
        }
        const char *buffer;
        size_t bytes;
        if (( rs = apr_bucket_read(b, &buffer, &bytes, APR_BLOCK_READ))) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rs, f->r, "read failure in luahood");
            return rs;
        }
        char *mine = apr_pstrmemdup(f->r->pool, buffer, bytes);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "sending '%s'", mine);
    }
    
    ap_pass_brigade(f->next, bb);
    
    return OK;
}
*/

/**
 * "main"
 */
static int lua_handler(request_rec *r)
{
    ap_lua_dir_cfg *dcfg;
    if (strcmp(r->handler, "lua-script")) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "handling [%s] in mod_lua",
                  r->filename);
    dcfg = ap_get_module_config(r->per_dir_config, &lua_module);

    if (!r->header_only) {
        lua_State *L;
        const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                      &lua_module);
        ap_lua_request_cfg *rcfg =
            ap_get_module_config(r->request_config, &lua_module);
        mapped_request_details *d = rcfg->mapped_request_details;
        ap_lua_vm_spec *spec = NULL;

        if (!d) {
            d = apr_palloc(r->pool, sizeof(mapped_request_details));
            spec = apr_pcalloc(r->pool, sizeof(ap_lua_vm_spec));
            spec->scope = dcfg->vm_scope;
            spec->pool = r->pool;
            spec->file = r->filename;
            spec->code_cache_style = dcfg->code_cache_style;
            d->spec = spec;
            d->function_name = "handle";
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "request details scope:%u, cache:%u, filename:%s, function:%s",
                      d->spec->scope,
                      d->spec->code_cache_style,
                      d->spec->file,
                      d->function_name);
        L = ap_lua_get_lua_state(r->pool,
                              d->spec,
                              cfg->package_paths,
                              cfg->package_cpaths,
                              &lua_open_callback, NULL);

        if (!L) {
            /* TODO annotate spec with failure reason */
            r->status = HTTP_INTERNAL_SERVER_ERROR;
            ap_rputs("Unable to compile VM, see logs", r);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "got a vm!");
        lua_getglobal(L, d->function_name);
        if (!lua_isfunction(L, -1)) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                          "lua: Unable to find function %s in %s",
                          d->function_name,
                          d->spec->file);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ap_lua_run_lua_request(L, r);
        if (lua_pcall(L, 1, 0, 0)) {
            report_lua_error(L, r);
        }
    }
    return OK;
}



/**
 * Like mod_alias except for lua handler fun :-) 
 */
static int lua_alias_munger(request_rec *r)
{
    ap_lua_vm_spec *spec;
    ap_lua_request_cfg *rcfg = ap_get_module_config(r->request_config,
                                                 &lua_module);
    const ap_lua_dir_cfg *cfg =
        ap_get_module_config(r->per_dir_config, &lua_module);
    int i;
    ap_regmatch_t matches[AP_MAX_REG_MATCH];

    for (i = 0; i < cfg->mapped_handlers->nelts; i++) {
        const ap_lua_mapped_handler_spec *cnd =
            ((const ap_lua_mapped_handler_spec **) cfg->mapped_handlers->elts)[i];

        if (OK ==
            ap_regexec(cnd->uri_pattern, r->uri, AP_MAX_REG_MATCH, matches,
                       0)) {
            mapped_request_details *d;
            r->handler = "lua-script";

            spec = apr_pcalloc(r->pool, sizeof(ap_lua_vm_spec));
            spec->file =
                ap_pregsub(r->pool, cnd->file_name, r->uri, AP_MAX_REG_MATCH,
                           matches);
            spec->scope = cnd->scope;
            spec->code_cache_style = cnd->code_cache_style;
            spec->bytecode = cnd->bytecode;
            spec->bytecode_len = cnd->bytecode_len;
            if (spec->scope == APL_SCOPE_ONCE) {
                spec->pool = r->pool;
            }

            d = apr_palloc(r->pool, sizeof(mapped_request_details));

            d->function_name =
                ap_pregsub(r->pool, cnd->function_name, r->uri,
                           AP_MAX_REG_MATCH, matches);
            d->spec = spec;

            /* now do replacement on method name where? */
            r->filename = apr_pstrdup(r->pool, spec->file);
            rcfg->mapped_request_details = d;
            return OK;
        }
    }
    return DECLINED;
}

/* ---------------- Configury stuff --------------- */

/** harnesses for magic hooks **/

static int lua_request_rec_hook_harness(request_rec *r, const char *name)
{
    int rc;
    lua_State *L;
    ap_lua_vm_spec *spec;
    ap_lua_server_cfg *server_cfg = ap_get_module_config(r->server->module_config,
                                                      &lua_module);
    const ap_lua_dir_cfg *cfg =
        (ap_lua_dir_cfg *) ap_get_module_config(r->per_dir_config,
                                             &lua_module);
    apr_array_header_t *hook_specs =
        apr_hash_get(cfg->hooks, name, APR_HASH_KEY_STRING);
    if (hook_specs) {
        int i;
        for (i = 0; i < hook_specs->nelts; i++) {
            ap_lua_mapped_handler_spec *hook_spec =
                ((ap_lua_mapped_handler_spec **) hook_specs->elts)[i];

            if (hook_spec == NULL) {
                continue;
            }
            spec = apr_pcalloc(r->pool, sizeof(ap_lua_vm_spec));

            spec->file = hook_spec->file_name;
            spec->code_cache_style = hook_spec->code_cache_style;
            spec->scope = hook_spec->scope;
            spec->bytecode = hook_spec->bytecode;
            spec->bytecode_len = hook_spec->bytecode_len;
            spec->pool = r->pool;

            apr_filepath_merge(&spec->file, server_cfg->root_path,
                               spec->file, APR_FILEPATH_NOTRELATIVE, r->pool);
            L = ap_lua_get_lua_state(r->pool,
                                  spec,
                                  cfg->package_paths,
                                  cfg->package_cpaths,
                                  &lua_open_callback, NULL);



            if (!L) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                              "lua: Failed to obtain lua interpreter for %s %s",
                              hook_spec->function_name, hook_spec->file_name);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (hook_spec->function_name != NULL) {
                lua_getglobal(L, hook_spec->function_name);
                if (!lua_isfunction(L, -1)) {
                    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                                  "lua: Unable to find function %s in %s",
                                  hook_spec->function_name,
                                  hook_spec->file_name);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                ap_lua_run_lua_request(L, r);
            }
            else {
                int t;
                ap_lua_run_lua_request(L, r);

                t = lua_gettop(L);
                lua_setglobal(L, "r");
                lua_settop(L, t);
            }

            if (lua_pcall(L, 1, 1, 0)) {
                report_lua_error(L, r);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            rc = DECLINED;
            if (lua_isnumber(L, -1)) {
                rc = lua_tointeger(L, -1);
            }
            if (rc != DECLINED) {
                return rc;
            }
        }
    }
    return DECLINED;
}


static apr_size_t config_getstr(ap_configfile_t *cfg, char *buf,
                                size_t bufsiz)
{
    apr_size_t i = 0;

    if (cfg->getstr) {
        const char *res = (cfg->getstr) (buf, bufsiz, cfg->param);
        if (res) {
            i = strlen(buf);
            if (i && buf[i - 1] == '\n')
                ++cfg->line_number;
        }
        else {
            buf[0] = '\0';
            i = 0;
        }
    }
    else {
        while (i < bufsiz) {
            int ch = (cfg->getch) (cfg->param);
            if (ch == EOF)
                break;
            buf[i++] = ch;
            if (ch == '\n') {
                ++cfg->line_number;
                break;
            }
        }
    }
    return i;
}

typedef struct cr_ctx
{
    cmd_parms *cmd;
    ap_configfile_t *cfp;
    size_t startline;
    const char *endstr;
    char buf[HUGE_STRING_LEN];
} cr_ctx;


/* Okay, this deserves a little explaination -- in order for the errors that lua
 * generates to be 'accuarate', including line numbers, we basically inject
 * N line number new lines into the 'top' of the chunk reader..... 
 *
 * be happy. this is cool.
 *
 */
static const char *lf =
    "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
#define N_LF 32

static const char *direct_chunkreader(lua_State *lvm, void *udata,
                                      size_t *plen)
{
    const char *p;
    struct cr_ctx *ctx = udata;

    if (ctx->startline) {
        *plen = ctx->startline > N_LF ? N_LF : ctx->startline;
        ctx->startline -= *plen;
        return lf;
    }
    *plen = config_getstr(ctx->cfp, ctx->buf, HUGE_STRING_LEN);

    for (p = ctx->buf; isspace(*p); ++p);
    if (p[0] == '<' && p[1] == '/') {
        int i = 0;
        while (i < strlen(ctx->endstr)) {
            if (tolower(p[i + 2]) != ctx->endstr[i])
                return ctx->buf;
            ++i;
        }
        *plen = 0;
        return NULL;
    }
    /*fprintf(stderr, "buf read: %s\n", ctx->buf); */
    return ctx->buf;
}

static int ldump_writer(lua_State *L, const void *b, size_t size, void *B)
{
    (void) L;
    luaL_addlstring((luaL_Buffer *) B, (const char *) b, size);
    return 0;
}

typedef struct hack_section_baton
{
    const char *name;
    ap_lua_mapped_handler_spec *spec;
} hack_section_baton;

/* You can be unhappy now.
 *
 * This is uncool.
 *
 * When you create a <Section handler in httpd, the only 'easy' way to create
 * a directory context is to parse the section, and convert it into a 'normal'
 * Configureation option, and then collapse the entire section, in memory,
 * back into the parent section -- from which you can then get the new directive
 * invoked.... anyways. evil. Rici taught me how to do this hack :-)
 */
static const char *hack_section_handler(cmd_parms *cmd, void *_cfg,
                                        const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    ap_directive_t *directive = cmd->directive;
    hack_section_baton *baton = directive->data;

    apr_array_header_t *hook_specs =
        apr_hash_get(cfg->hooks, baton->name, APR_HASH_KEY_STRING);
    if (!hook_specs) {
        hook_specs =
            apr_array_make(cmd->pool, 2, sizeof(ap_lua_mapped_handler_spec *));
        apr_hash_set(cfg->hooks, apr_pstrdup(cmd->pool, baton->name),
                     APR_HASH_KEY_STRING, hook_specs);
    }

    baton->spec->scope = cfg->vm_scope;

    *(ap_lua_mapped_handler_spec **) apr_array_push(hook_specs) = baton->spec;

    return NULL;
}

static const char *register_named_block_function_hook(const char *name,
                                                      cmd_parms *cmd,
                                                      void *mconfig,
                                                      const char *line)
{
    const char *function;
    ap_lua_mapped_handler_spec *spec;

    if (line && line[0] == '>') {
        function = NULL;
    }
    else {
        const char *word;
        apr_size_t wordlen;
        word = ap_getword_conf(cmd->pool, &line);
        wordlen = strlen(word);
        if (wordlen == 0 || word[wordlen - 1] != '>') {
            return apr_pstrcat(cmd->pool, cmd->directive->directive,
                               "> takes exactly one argument", NULL);
        }
        else {
            function = apr_pstrndup(cmd->pool, word, wordlen - 1);
        }
    }

    spec = apr_pcalloc(cmd->pool, sizeof(ap_lua_mapped_handler_spec));

    {
        cr_ctx ctx;
        char buf[32];
        lua_State *lvm;
        char *tmp;
        int rv;
        ap_directive_t **current;
        hack_section_baton *baton;

        apr_snprintf(buf, sizeof(buf), "%u", cmd->config_file->line_number);
        spec->file_name =
            apr_pstrcat(cmd->pool, cmd->config_file->name, ":", buf, NULL);
        if (function) {
            spec->function_name = (char *) function;
        }
        else {
            function = NULL;
        }
        spec->code_cache_style = APL_CODE_CACHE_FOREVER;

        ctx.cmd = cmd;
        tmp = apr_pstrdup(cmd->pool, cmd->err_directive->directive + 1);
        ap_str_tolower(tmp);
        ctx.endstr = tmp;
        ctx.cfp = cmd->config_file;
        ctx.startline = cmd->config_file->line_number;

        /* This lua State is used only to compile the input strings -> bytecode, so we don't need anything extra. */
        lvm = luaL_newstate();

        lua_settop(lvm, 0);

        rv = lua_load(lvm, direct_chunkreader, &ctx, spec->file_name);

        if (rv != 0) {
            const char *errstr =
                apr_pstrcat(cmd->pool, "Lua Error:", lua_tostring(lvm, -1),
                            NULL);
            lua_close(lvm);
            return errstr;
        }
        else {
            luaL_Buffer b;
            luaL_buffinit(lvm, &b);
            lua_dump(lvm, ldump_writer, &b);
            luaL_pushresult(&b);
            spec->bytecode_len = lua_strlen(lvm, -1);
            spec->bytecode =
                apr_pstrmemdup(cmd->pool, lua_tostring(lvm, -1),
                               spec->bytecode_len);
            lua_close(lvm);
        }

        current = mconfig;

        /* Here, we have to replace our current config node for the next pass */
        if (!*current) {
            *current = apr_pcalloc(cmd->pool, sizeof(**current));
        }

        baton = apr_pcalloc(cmd->pool, sizeof(hack_section_baton));
        baton->name = name;
        baton->spec = spec;

        (*current)->filename = cmd->config_file->name;
        (*current)->line_num = cmd->config_file->line_number;
        (*current)->directive =
            apr_pstrdup(cmd->pool, "Lua_____ByteCodeHack");
        (*current)->args = NULL;
        (*current)->data = baton;
    }

    return NULL;
}

static const char *register_named_file_function_hook(const char *name,
                                                     cmd_parms *cmd,
                                                     void *_cfg,
                                                     const char *file,
                                                     const char *function)
{
    ap_lua_mapped_handler_spec *spec;
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;

    apr_array_header_t *hook_specs =
        apr_hash_get(cfg->hooks, name, APR_HASH_KEY_STRING);
    if (!hook_specs) {
        hook_specs =
            apr_array_make(cmd->pool, 2, sizeof(ap_lua_mapped_handler_spec *));
        apr_hash_set(cfg->hooks, apr_pstrdup(cmd->pool, name),
                     APR_HASH_KEY_STRING, hook_specs);
    }

    spec = apr_pcalloc(cmd->pool, sizeof(ap_lua_mapped_handler_spec));
    spec->file_name = apr_pstrdup(cmd->pool, file);
    spec->function_name = apr_pstrdup(cmd->pool, function);
    spec->scope = cfg->vm_scope;
    spec->code_cache_style = APL_CODE_CACHE_STAT;
    /*
       int code_cache_style;
       char *function_name;
       char *file_name;
       int scope;
     */
    *(ap_lua_mapped_handler_spec **) apr_array_push(hook_specs) = spec;
    return NULL;
}

static int lua_check_user_id_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "check_user_id");
}

static int lua_translate_name_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "translate_name");
}

static int lua_fixup_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "fixups");
}

static int lua_map_to_storage_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "map_to_storage");
}

static int lua_type_checker_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "type_checker");
}

static int lua_access_checker_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "access_checker");
}

static int lua_auth_checker_harness(request_rec *r)
{
    return lua_request_rec_hook_harness(r, "auth_checker");
}

static void lua_insert_filter_harness(request_rec *r)
{
    /* ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "LuaHookInsertFilter not yet implemented"); */
}

static int lua_quick_harness(request_rec *r, int lookup)
{
    if (lookup) {
        return DECLINED;
    }
    return lua_request_rec_hook_harness(r, "quick");
}

static const char *register_translate_name_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function)
{
    return register_named_file_function_hook("translate_name", cmd, _cfg,
                                             file, function);
}

static const char *register_translate_name_block(cmd_parms *cmd, void *_cfg,
                                                 const char *line)
{
    return register_named_block_function_hook("translate_name", cmd, _cfg,
                                              line);
}


static const char *register_fixups_hook(cmd_parms *cmd, void *_cfg,
                                        const char *file,
                                        const char *function)
{
    return register_named_file_function_hook("fixups", cmd, _cfg, file,
                                             function);
}
static const char *register_fixups_block(cmd_parms *cmd, void *_cfg,
                                         const char *line)
{
    return register_named_block_function_hook("fixups", cmd, _cfg, line);
}

static const char *register_map_to_storage_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function)
{
    return register_named_file_function_hook("map_to_storage", cmd, _cfg,
                                             file, function);
}
static const char *register_map_to_storage_block(cmd_parms *cmd, void *_cfg,
                                                 const char *line)
{
    return register_named_block_function_hook("map_to_storage", cmd, _cfg,
                                              line);
}

static const char *register_check_user_id_hook(cmd_parms *cmd, void *_cfg,
                                               const char *file,
                                               const char *function)
{
    return register_named_file_function_hook("check_user_id", cmd, _cfg, file,
                                             function);
}
static const char *register_check_user_id_block(cmd_parms *cmd, void *_cfg,
                                                const char *line)
{
    return register_named_block_function_hook("check_user_id", cmd, _cfg,
                                              line);
}

static const char *register_type_checker_hook(cmd_parms *cmd, void *_cfg,
                                              const char *file,
                                              const char *function)
{
    return register_named_file_function_hook("type_checker", cmd, _cfg, file,
                                             function);
}
static const char *register_type_checker_block(cmd_parms *cmd, void *_cfg,
                                               const char *line)
{
    return register_named_block_function_hook("type_checker", cmd, _cfg,
                                              line);
}

static const char *register_access_checker_hook(cmd_parms *cmd, void *_cfg,
                                                const char *file,
                                                const char *function)
{
    return register_named_file_function_hook("access_checker", cmd, _cfg,
                                             file, function);
}
static const char *register_access_checker_block(cmd_parms *cmd, void *_cfg,
                                                 const char *line)
{
    return register_named_block_function_hook("access_checker", cmd, _cfg,
                                              line);
}

static const char *register_auth_checker_hook(cmd_parms *cmd, void *_cfg,
                                              const char *file,
                                              const char *function)
{
    return register_named_file_function_hook("auth_checker", cmd, _cfg, file,
                                             function);
}
static const char *register_auth_checker_block(cmd_parms *cmd, void *_cfg,
                                               const char *line)
{
    return register_named_block_function_hook("auth_checker", cmd, _cfg,
                                              line);
}

static const char *register_insert_filter_hook(cmd_parms *cmd, void *_cfg,
                                               const char *file,
                                               const char *function)
{
    return "LuaHookInsertFilter not yet implemented";
}

static const char *register_quick_hook(cmd_parms *cmd, void *_cfg,
                                       const char *file, const char *function)
{
    return register_named_file_function_hook("quick", cmd, _cfg, file,
                                             function);
}
static const char *register_quick_block(cmd_parms *cmd, void *_cfg,
                                        const char *line)
{
    return "LuaQuickHook in an inline block not yet implemented";
}



static const char *register_package_helper(cmd_parms *cmd, const char *arg,
                                           apr_array_header_t *dir_array)
{
    apr_status_t rv;

    ap_lua_server_cfg *server_cfg =
        ap_get_module_config(cmd->server->module_config, &lua_module);
    char *fixed_filename;
    rv = apr_filepath_merge(&fixed_filename, server_cfg->root_path, arg,
                            APR_FILEPATH_NOTRELATIVE, cmd->pool);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "Unable to build full path to file, %s", arg);
    }

    *(const char **) apr_array_push(dir_array) = fixed_filename;
    return NULL;
}


/**
 * Called for config directive which looks like
 * LuaPackagePath /lua/package/path/mapped/thing/like/this/?.lua
 */
static const char *register_package_dir(cmd_parms *cmd, void *_cfg,
                                        const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;

    return register_package_helper(cmd, arg, cfg->package_paths);
}

/**
 * Called for config directive which looks like
 * LuaPackageCPath /lua/package/path/mapped/thing/like/this/?.so
 */
static const char *register_package_cdir(cmd_parms *cmd, void *_cfg,
                                         const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;

    return register_package_helper(cmd, arg, cfg->package_cpaths);
}

/**
 * Called for config directive which looks like
 * LuaCodeCache 
 */
static const char *register_code_cache(cmd_parms *cmd, void *_cfg,
                                       const char *arg)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    if (strcmp("stat", arg) == 0) {
        cfg->code_cache_style = APL_CODE_CACHE_STAT;
    }
    else if (strcmp("forever", arg) == 0) {
        cfg->code_cache_style = APL_CODE_CACHE_FOREVER;
    }
    else if (strcmp("never", arg) == 0) {
        cfg->code_cache_style = APL_CODE_CACHE_NEVER;
    }
    else {
        return apr_psprintf(cmd->pool,
                            "Invalid value for LuaCodeCache, '%s', acceptable values are %s",
                            arg, "'stat', 'forever', and 'never'");
    }
    return NULL;
}

static const char *register_lua_scope(cmd_parms *cmd, void *_cfg,
                                      const char *scope, const char *min,
                                      const char *max)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    if (strcmp("once", scope) == 0) {
        cfg->vm_scope = APL_SCOPE_ONCE;
    }
    else if (strcmp("request", scope) == 0) {
        cfg->vm_scope = APL_SCOPE_REQUEST;
    }
    else if (strcmp("conn", scope) == 0) {
        cfg->vm_scope = APL_SCOPE_CONN;
    }
    else if (strcmp("server", scope) == 0) {
        cfg->vm_scope = APL_SCOPE_SERVER;
        if (min)
            cfg->vm_server_pool_min = atoi(min);
        if (max)
            cfg->vm_server_pool_max = atoi(max);
    }
    else {
        return apr_psprintf(cmd->pool,
                            "Invalid value for LuaScope, '%s', acceptable values are %s",
                            scope, "'once', 'request', 'conn', and 'server'");
    }
    return NULL;
}


/**
 * Called for config directive which looks like
 * AddLuaHandler /alias /path/to/lua/file.lua [handler_function_name]
 */
static const char *lua_map_handler(cmd_parms *cmd, void *_cfg,
                                   const char *path, const char *file,
                                   const char *function)
{
    ap_lua_dir_cfg *cfg = (ap_lua_dir_cfg *) _cfg;
    apr_status_t rv;
    const char *function_name;
    function_name = function ? function : "handle";
    rv = ap_lua_map_handler(cfg, file, function_name, path, "once");
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "Unable to configure a lua handler for path '%s', handler %s#%s",
                            path, file, function_name);
    }
    return NULL;
}

static const char *register_lua_root(cmd_parms *cmd, void *_cfg,
                                     const char *root)
{
    /* ap_lua_dir_cfg* cfg = (ap_lua_dir_cfg*)_cfg; */
    ap_lua_server_cfg *cfg =
        ap_get_module_config(cmd->server->module_config, &lua_module);

    cfg->root_path = root;
    return NULL;
}

/*******************************/

command_rec lua_commands[] = {

    AP_INIT_TAKE1("LuaRoot", register_lua_root, NULL, OR_ALL,
                  "Specify the base path for resolving relative paths for mod_lua directives"),


    AP_INIT_TAKE1("LuaPackagePath", register_package_dir, NULL, OR_ALL,
                  "Add a directory to lua's package.path"),

    AP_INIT_TAKE1("LuaPackageCPath", register_package_cdir, NULL, OR_ALL,
                  "Add a directory to lua's package.cpath"),

    AP_INIT_TAKE23("LuaMapHandler", lua_map_handler, NULL, OR_ALL,
                   "Map a path to a lua handler"),

    AP_INIT_TAKE2("LuaHookTranslateName", register_translate_name_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the translate name phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookTranslateName", register_translate_name_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the translate name phase of request processing"),

    AP_INIT_TAKE2("LuaHookFixups", register_fixups_hook, NULL, OR_ALL,
                  "Provide a hook for the fixups phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookFixups", register_fixups_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a inline hook for the fixups phase of request processing"),

/* todo: test */
    AP_INIT_TAKE2("LuaHookMapToStorage", register_map_to_storage_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the map_to_storage phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookMapToStorage", register_map_to_storage_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the map_to_storage phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookCheckUserID", register_check_user_id_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the check_user_id phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookCheckUserID", register_check_user_id_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the check_user_id phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookTypeChecker", register_type_checker_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the type_checker phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookTypeChecker", register_type_checker_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the type_checker phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookAccessChecker", register_access_checker_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the access_checker phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookAccessChecker", register_access_checker_block,
                     NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the access_checker phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookAuthChecker", register_auth_checker_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the auth_checker phase of request processing"),
    AP_INIT_RAW_ARGS("<LuaHookAuthChecker", register_auth_checker_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the auth_checker phase of request processing"),

    /* todo: test */
    AP_INIT_TAKE2("LuaHookInsertFilter", register_insert_filter_hook, NULL,
                  OR_ALL,
                  "Provide a hook for the insert_filter phase of request processing"),

    AP_INIT_TAKE1("LuaCodeCache", register_code_cache, NULL, OR_ALL,
                  "Configure the compiled code cache. \
                   Default is to stat the file each time, options are stat|forever|never"),

    AP_INIT_TAKE123("LuaScope", register_lua_scope, NULL, OR_ALL,
                    "One of once, request, conn, server -- default is once"),

    AP_INIT_TAKE2("LuaQuickHandler", register_quick_hook, NULL, OR_ALL,
                  "Provide a hook for the quick handler of request processing"),
    AP_INIT_RAW_ARGS("<LuaQuickHandler", register_quick_block, NULL,
                     EXEC_ON_READ | OR_ALL,
                     "Provide a hook for the quick handler of request processing"),

    AP_INIT_RAW_ARGS("Lua_____ByteCodeHack", hack_section_handler, NULL,
                     OR_ALL,
                     "(internal) Byte code handler"),
    {NULL}
};


static void *create_dir_config(apr_pool_t *p, char *dir)
{
    ap_lua_dir_cfg *cfg = apr_pcalloc(p, sizeof(ap_lua_dir_cfg));
    cfg->package_paths = apr_array_make(p, 2, sizeof(char *));
    cfg->package_cpaths = apr_array_make(p, 2, sizeof(char *));
    cfg->mapped_handlers =
        apr_array_make(p, 1, sizeof(ap_lua_mapped_handler_spec *));
    cfg->code_cache_style = APL_CODE_CACHE_STAT;
    cfg->pool = p;
    cfg->hooks = apr_hash_make(p);
    cfg->dir = apr_pstrdup(p, dir);
    cfg->vm_scope = APL_SCOPE_ONCE;
    return cfg;
}

static int create_request_config(request_rec *r)
{
    ap_lua_request_cfg *cfg = apr_palloc(r->pool, sizeof(ap_lua_request_cfg));
    cfg->mapped_request_details = NULL;
    cfg->request_scoped_vms = apr_hash_make(r->pool);
    ap_set_module_config(r->request_config, &lua_module, cfg);
    return OK;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{

    ap_lua_server_cfg *cfg = apr_pcalloc(p, sizeof(ap_lua_server_cfg));
    cfg->code_cache = apr_pcalloc(p, sizeof(ap_lua_code_cache));
    apr_thread_rwlock_create(&cfg->code_cache->compiled_files_lock, p);
    cfg->code_cache->compiled_files = apr_hash_make(p);
    cfg->vm_reslists = apr_hash_make(p);
    apr_thread_rwlock_create(&cfg->vm_reslists_lock, p);
    cfg->code_cache->pool = p;
    cfg->root_path = NULL;

    return cfg;
}

static int lua_request_hook(lua_State *L, request_rec *r)
{
    ap_lua_push_request(L, r);
    return OK;
}

static void lua_register_hooks(apr_pool_t *p)
{
    /* ap_register_output_filter("luahood", luahood, NULL, AP_FTYPE_RESOURCE); */
    ap_hook_handler(lua_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_create_request(create_request_config, NULL, NULL,
                           APR_HOOK_MIDDLE);

    /* http_request.h hooks */
    ap_hook_translate_name(lua_translate_name_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_fixups(lua_fixup_harness, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_map_to_storage(lua_map_to_storage_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_check_user_id(lua_check_user_id_harness, NULL, NULL,
                          APR_HOOK_MIDDLE);
    ap_hook_type_checker(lua_type_checker_harness, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_access_checker(lua_access_checker_harness, NULL, NULL,
                           APR_HOOK_MIDDLE);
    ap_hook_auth_checker(lua_auth_checker_harness, NULL, NULL,
                         APR_HOOK_MIDDLE);
    ap_hook_insert_filter(lua_insert_filter_harness, NULL, NULL,
                          APR_HOOK_MIDDLE);
    ap_hook_quick_handler(lua_quick_harness, NULL, NULL, APR_HOOK_FIRST);

    /* ap_hook_translate_name(lua_alias_munger, NULL, NULL, APR_HOOK_MIDDLE); */
    ap_hook_translate_name(lua_alias_munger, NULL, NULL, APR_HOOK_MIDDLE);

    APR_OPTIONAL_HOOK(ap_lua, lua_open, lua_open_hook, NULL, NULL,
                      APR_HOOK_REALLY_FIRST);

    APR_OPTIONAL_HOOK(ap_lua, lua_request, lua_request_hook, NULL, NULL,
                      APR_HOOK_REALLY_FIRST);
}

AP_DECLARE_MODULE(lua) = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    create_server_config,       /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    lua_commands,               /* table of config file commands       */
    lua_register_hooks          /* register hooks                      */
};
