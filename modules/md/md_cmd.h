/* Copyright 2017 greenbytes GmbH (https://www.greenbytes.de)
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

#ifndef md_cmd_h
#define md_cmd_h

struct apr_getopt_option_t;
struct apr_table_t;
struct md_json_t;
struct md_store_t;
struct md_ref_t;
struct md_acme_t;

typedef struct md_opts md_opts;
typedef struct md_cmd_ctx  md_cmd_ctx;
typedef struct md_cmd_t md_cmd_t;

typedef apr_status_t md_cmd_opt_fn(md_cmd_ctx *ctx, int option, const char *optarg);
typedef apr_status_t md_cmd_do_fn(md_cmd_ctx *ctx, const md_cmd_t *cmd);

struct md_cmd_ctx {
    apr_pool_t *p;
    
    const char *base_dir;
    const char *ca_url;
    
    struct md_store_t *store;
    struct md_reg_t *reg;
    struct md_acme_t *acme;

    struct apr_table_t *options;
    
    const char *tos;

    struct md_json_t *json_out;
    
    int argc;
    const char *const *argv;
};

int md_cmd_ctx_has_option(md_cmd_ctx *ctx, const char *key);
const char *md_cmd_ctx_get_option(md_cmd_ctx *ctx, const char *key);

void md_cmd_ctx_set_option(md_cmd_ctx *ctx, const char *key, const char *value);


/* needs */
#define MD_CTX_NONE            0x0000
#define MD_CTX_STORE           0x0001
#define MD_CTX_REG             0x0002
#define MD_CTX_ACME            0x0004

struct md_cmd_t {
    const char *name;                   /* command name */
    int needs;                          /* command needs: store, reg, acme etc. */
    
    md_cmd_opt_fn *opt_fn;              /* callback for options handling */
    md_cmd_do_fn *do_fn;                /* callback for executing the command */
    
    const struct apr_getopt_option_t *opts;    /* options definitions */
    const md_cmd_t **sub_cmds;          /* sub commands of this command or NULL */
    
    const char *synopsis;               /* command line synopsis for this command */
    const char *description;            /* textual description of this command */
};

extern apr_getopt_option_t MD_NoOptions[];

apr_status_t usage(const md_cmd_t *cmd, const char *msg);

apr_array_header_t *md_cmd_gather_args(md_cmd_ctx *ctx, int index);

void md_cmd_print_md(md_cmd_ctx *ctx, const md_t *md);

#endif /* md_cmd_h */
