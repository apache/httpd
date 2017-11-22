/* Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_getopt.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_acme.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_util.h"
#include "md_version.h"

#include "md_cmd.h"
#include "md_cmd_acme.h"
#include "md_cmd_reg.h"
#include "md_cmd_store.h"
#include "md_curl.h"


/**************************************************************************************************/
/* command infrastructure */

apr_getopt_option_t MD_NoOptions [] = {
    { NULL, 0, 0, NULL }
};

apr_status_t usage(const md_cmd_t *cmd, const char *msg) 
{
    const apr_getopt_option_t *opt;
    int i;

    if (msg) {
        fprintf(stderr, "%s\n", msg);
    }
    fprintf(stderr, "usage: %s\n", cmd->synopsis);
    if (cmd->description) {
        fprintf(stderr, "\t%s\n", cmd->description);
    }
    if (cmd->opts[0].name) {
        fprintf(stderr, "  with the following options:\n");
    
        opt = NULL;
        for (i = 0; !opt || opt->optch; ++i) {
            opt = cmd->opts + i;
            if (opt->optch) {
                fprintf(stderr, "  -%c | --%s    %s\t%s\n", 
                        opt->optch, opt->name, opt->has_arg? "arg" : "", opt->description);
                
            }
        }
    }
    if (cmd->sub_cmds && cmd->sub_cmds[0]) {
        fprintf(stderr, "  using one of the following commands:\n");
        for (i = 0; cmd->sub_cmds[i]; ++i) {
            fprintf(stderr, "  \t%s\n", cmd->sub_cmds[i]->synopsis);
            fprintf(stderr, "  \t\t%s\n", cmd->sub_cmds[i]->description);
        }
    }
    
    exit(msg? 1 : 2);
}

static apr_status_t md_cmd_ctx_init(md_cmd_ctx *ctx, apr_pool_t *p, 
                                    int argc, const char *const *argv)
{
    ctx->p = p;
    ctx->argc = argc;
    ctx->argv = argv;
    ctx->options = apr_table_make(p, 5);
    
    return ctx->options? APR_SUCCESS : APR_ENOMEM;
}

void md_cmd_ctx_set_option(md_cmd_ctx *ctx, const char *key, const char *value)
{
    apr_table_setn(ctx->options, key, value);
}

int md_cmd_ctx_has_option(md_cmd_ctx *ctx, const char *option)
{
    return NULL != apr_table_get(ctx->options, option);
}

const char *md_cmd_ctx_get_option(md_cmd_ctx *ctx, const char *key)
{
    return apr_table_get(ctx->options, key);
}

static const md_cmd_t *find_cmd(const md_cmd_t **cmds, const char *name) 
{
    int i;
    if (cmds) {
        for (i = 0; cmds[i]; ++i) {
            if (!strcmp(name, cmds[i]->name)) {
                return cmds[i];
            }
        }
    }
    return NULL;
}

static apr_status_t cmd_process(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_getopt_t *os;
    const char *optarg;
    int opt;
    apr_status_t rv = APR_SUCCESS;

    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, 
                  "start processing cmd %s", cmd->name); 

    apr_getopt_init(&os, ctx->p, ctx->argc, ctx->argv);
    while ((rv = apr_getopt_long(os, cmd->opts, &opt, &optarg)) == APR_SUCCESS) {
        if (!cmd->opt_fn) {
            return usage(cmd, NULL);
        }
        else if (APR_SUCCESS != (rv = cmd->opt_fn(ctx, opt, optarg))) {
            return usage(cmd, NULL);
        }
    }
    if (rv != APR_EOF) {
        return usage(cmd, NULL);
    }
    
    if (md_cmd_ctx_has_option(ctx, "help")) {
        return usage(cmd, NULL);
    }
    if (md_cmd_ctx_has_option(ctx, "version")) {
        fprintf(stdout, "version: %s\n", MOD_MD_VERSION);
        exit(0);
    }
    
    ctx->argv = os->argv + os->ind;
    ctx->argc -= os->ind;
    
    md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "args remaining: %d", ctx->argc);
                   
    if (cmd->needs & (MD_CTX_STORE|MD_CTX_REG|MD_CTX_ACME) && !ctx->store) {
        if (!ctx->base_dir) {
            fprintf(stderr, "need store directory for command: %s\n", cmd->name);
            return APR_EINVAL;
        }
        if (APR_SUCCESS != (rv = md_store_fs_init(&ctx->store, ctx->p, ctx->base_dir))) {
            fprintf(stderr, "error %d creating store for: %s\n", rv, ctx->base_dir);
            return APR_EINVAL;
        }
    }
    if (cmd->needs & MD_CTX_REG && !ctx->reg) {
        if (!ctx->store) {
            fprintf(stderr, "need store for registry: %s\n", cmd->name);
            return APR_EINVAL;
        }
        if (APR_SUCCESS != (rv = md_reg_init(&ctx->reg, ctx->p, ctx->store,
                                             md_cmd_ctx_get_option(ctx, MD_CMD_OPT_PROXY_URL)))) {
            fprintf(stderr, "error %d creating registry from store: %s\n", rv, ctx->base_dir);
            return APR_EINVAL;
        }
    }
    if (cmd->needs & MD_CTX_ACME && !ctx->acme) {
        if (!ctx->store) {
            fprintf(stderr, "need store for ACME: %s\n", cmd->name);
            return APR_EINVAL;
        }
        rv = md_acme_create(&ctx->acme, ctx->p, ctx->ca_url, 
                            md_cmd_ctx_get_option(ctx, MD_CMD_OPT_PROXY_URL));
        if (APR_SUCCESS != rv) {
            fprintf(stderr, "error creating acme instance %s (%s)\n", 
                    ctx->ca_url, ctx->base_dir);
            return rv;
        }
        rv = md_acme_setup(ctx->acme);
        if (rv != APR_SUCCESS) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "contacting %s", ctx->ca_url);
            return rv;
        }
    }
    
    if (cmd->sub_cmds && cmd->sub_cmds[0]) {
        const md_cmd_t *sub_cmd;
        
        if (!ctx->argc) {
            return usage(cmd, "sub command is missing");
        }
        
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "sub command %s", ctx->argv[0]);
        
        sub_cmd = find_cmd(cmd->sub_cmds, ctx->argv[0]);
        if (sub_cmd) {
            return cmd_process(ctx, sub_cmd);
        }
        else if (!cmd->do_fn) {
            fprintf(stderr, "unknown cmd: %s\n", ctx->argv[0]);
            return APR_EINVAL;
        }
    }
    
    if (cmd->do_fn) {
        md_log_perror(MD_LOG_MARK, MD_LOG_TRACE4, 0, ctx->p, "%s->do_fn", cmd->name);
        return cmd->do_fn(ctx, cmd);
    }
    return APR_EINVAL;
}

/**************************************************************************************************/
/* logging setup */

static md_log_level_t active_level = MD_LOG_INFO;

static int log_is_level(void *baton, apr_pool_t *p, md_log_level_t level)
{
    (void)baton;
    (void)p;
    return level <= active_level;
}

#define LOG_BUF_LEN 16*1024

static void log_print(const char *file, int line, md_log_level_t level, 
                      apr_status_t rv, void *baton, apr_pool_t *p, const char *fmt, va_list ap)
{
    if (log_is_level(baton, p, level)) {
        char buffer[LOG_BUF_LEN];
        char errbuff[32];
        
        apr_vsnprintf(buffer, LOG_BUF_LEN-1, fmt, ap);
        buffer[LOG_BUF_LEN-1] = '\0';
        
        if (rv) {
            fprintf(stderr, "[%s:%d %s][%d(%s)] %s\n", file, line, 
                    md_log_level_name(level), rv, 
                    apr_strerror(rv, errbuff, sizeof(errbuff)/sizeof(errbuff[0])), 
                    buffer);
        }
        else if (active_level == MD_LOG_INFO) {
            fprintf(stderr, "%s\n", buffer);
        }
        else {
            fprintf(stderr, "[%s:%d %s][ok] %s\n", file, line, 
                    md_log_level_name(level), buffer);
        }
    }
}

/**************************************************************************************************/
/* utils */

void md_cmd_print_md(md_cmd_ctx *ctx, const md_t *md)
{
    assert(md);
    if (ctx->json_out) {
        md_json_t *json = md_to_json(md, ctx->p);
        md_json_addj(json, ctx->json_out, "output", NULL);
    }
    else {
        int i;
        fprintf(stdout, "md: %s [", md->name);
        for (i = 0; i < md->domains->nelts; ++i) {
            const char *domain = APR_ARRAY_IDX(md->domains, i, const char*);
            fprintf(stdout, "%s%s", (i? ", " : ""), domain);
        }
        fprintf(stdout, "]\n");
    }
}

static int pool_abort(int rv)
{
    (void)rv;
    abort();
}

apr_array_header_t *md_cmd_gather_args(md_cmd_ctx *ctx, int index)
{
    int i;
    
    apr_array_header_t *args = apr_array_make(ctx->p, 5, sizeof(const char *));
    for (i = index; i < ctx->argc; ++i) {
        APR_ARRAY_PUSH(args, const char *) = ctx->argv[i];
    }
    return args;
}

/**************************************************************************************************/
/* command: main() */

static void init_json_out(md_cmd_ctx *ctx) 
{
    apr_array_header_t *empty = apr_array_make(ctx->p, 1, sizeof(char*));
    
    ctx->json_out = md_json_create(ctx->p);
    
    md_json_setsa(empty, ctx->json_out, "output", NULL);
    md_json_setl(0, ctx->json_out, "status", NULL);
}

static apr_status_t main_opts(md_cmd_ctx *ctx, int option, const char *optarg)
{
    switch (option) {
        case 'a':
            ctx->ca_url = optarg;
            break;
        case 'd':
            ctx->base_dir = optarg;
            break;
        case 'h':
            md_cmd_ctx_set_option(ctx, "help", "1");
            break;
        case 'j':
            init_json_out(ctx);
            break;
        case 'p':
            md_cmd_ctx_set_option(ctx, MD_CMD_OPT_PROXY_URL, optarg);
            break;
        case 'q':
            if (active_level > 0) {
                --active_level;
            }
            break;
        case 'v':
            if (active_level < MD_LOG_TRACE8) {
                ++active_level;
            }
            break;
        case 'V':
            md_cmd_ctx_set_option(ctx, "version", "1");
            break;
        case 't':
            ctx->tos = optarg;
            break;
        default:
            return APR_EINVAL;
    }
    return APR_SUCCESS;
}

static const md_cmd_t *MainSubCmds[] = {
    &MD_AcmeCmd,
    &MD_RegAddCmd,
    &MD_RegUpdateCmd, 
    &MD_RegDriveCmd,
    &MD_RegListCmd,
    &MD_StoreCmd,
    NULL
};

static apr_getopt_option_t MainOptions [] = {
    { "acme",    'a', 1, "the url of the ACME server directory"},
    { "dir",     'd', 1, "directory for file data"},
    { "help",    'h', 0, "print usage information"},
    { "json",    'j', 0, "produce json output"},
    { "proxy",   'p', 1, "use the HTTP proxy url"},
    { "quiet",   'q', 0, "produce less output"},
    { "terms",   't', 1, "you agree to the terms of services (url)" },
    { "verbose", 'v', 0, "produce more output" },
    { "version", 'V', 0, "print version" },
    { NULL,       0,  0, NULL }
};

static md_cmd_t MainCmd = {
    "a2md", MD_CTX_NONE, 
    main_opts, NULL,
    MainOptions, MainSubCmds,
    "a2md [options] cmd [cmd options] [args]", 
    "Show and manipulate Apache Managed Domains", 
};

#define BASE_VERSION "apachemd/" MOD_MD_VERSION

int main(int argc, const char *const *argv)
{
    apr_allocator_t *allocator;
    apr_status_t rv;
    apr_pool_t *p;
    md_cmd_ctx ctx;

    rv = apr_app_initialize(&argc, &argv, NULL);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "error initializing APR (error code %d)\n", (int) rv);
        return 1;
    }

    if (atexit(apr_terminate)) {
        perror("error registering atexit");
        return 1;
    }
    
    memset(&ctx, 0, sizeof(ctx));
    md_log_set(log_is_level, log_print, NULL);
    
    apr_allocator_create(&allocator);
    rv = apr_pool_create_ex(&p, NULL, pool_abort, allocator);
    if (rv != APR_SUCCESS) {
        fprintf(stderr, "error initializing pool\n");
        return 1;
    }
    
    md_http_use_implementation(md_curl_get_impl(p));
    md_acme_init(p, BASE_VERSION);
    md_cmd_ctx_init(&ctx, p, argc, argv);
    
    rv = cmd_process(&ctx, &MainCmd);
    
    if (ctx.json_out) {
        const char *out;

        md_json_setl(rv, ctx.json_out, "status", NULL);
        if (APR_SUCCESS != rv) {
            char errbuff[32];
            
            apr_strerror(rv, errbuff, sizeof(errbuff)/sizeof(errbuff[0]));
            md_json_sets(apr_pstrdup(p, errbuff), ctx.json_out, "description", NULL);
        }

        out = md_json_writep(ctx.json_out, p, MD_JSON_FMT_INDENT);
        if (!out) {
            rv = APR_EINVAL;
        }

        fprintf(stdout, "%s\n", out ? out : "<failed to serialize!>");
    }
    
    return (rv == APR_SUCCESS)? 0 : 1;
}
