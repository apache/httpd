/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*                      _             _
 *  ap_expr_eval.c, based on ssl_expr_eval.c from mod_ssl
 */

#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_provider.h"
#include "util_expr_private.h"

#include "apr_lib.h"

APLOG_USE_MODULE(core);

APR_HOOK_STRUCT(
    APR_HOOK_LINK(expr_lookup)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int, expr_lookup, (ap_expr_lookup_parms *parms),
                            (parms), DECLINED)

static const char *ap_expr_eval_string_func(ap_expr_eval_ctx *ctx, const ap_expr *info,
                                            const ap_expr *args);
static const char *ap_expr_eval_var(ap_expr_eval_ctx *ctx,
                                    const ap_expr_var_func_t *func,
                                    const void *data);
static void expr_dump_tree(const ap_expr *e, const server_rec *s, int loglevel, int indent);

static const char *ap_expr_eval_word(ap_expr_eval_ctx *ctx, const ap_expr *node)
{
    const char *result = "";
    switch (node->node_op) {
        case op_Digit:
            result = node->node_arg1;
            break;
        case op_String:
            result = node->node_arg1;
            break;
        case op_Var:
            result = ap_expr_eval_var(ctx, node->node_arg1, node->node_arg2);
            break;
        case op_StringFuncCall: {
            const ap_expr *info = node->node_arg1;
            const ap_expr *args = node->node_arg2;
            result = ap_expr_eval_string_func(ctx, info, args);
            break;
        }
        default:
            *ctx->err = "Internal evaluation error: Unknown expression node";
            break;
    }
    if (!result)
        result = "";
    return result;
}

static const char *ap_expr_eval_var(ap_expr_eval_ctx *ctx, 
                                    const ap_expr_var_func_t *func,
                                    const void *data)
{
    AP_DEBUG_ASSERT(func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*func)(ctx, data);
}

static const char *ap_expr_eval_string_func(ap_expr_eval_ctx *ctx, const ap_expr *info,
                                            const ap_expr *arg)
{
    ap_expr_string_func_t *func = (ap_expr_string_func_t *)info->node_arg1;
    const void *data = info->node_arg2;

    AP_DEBUG_ASSERT(info->node_op == op_StringFuncInfo);
    AP_DEBUG_ASSERT(func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*func)(ctx, data, ap_expr_eval_word(ctx, arg));
}

static int intstrcmp(const char *s1, const char *s2)
{
    apr_int64_t i1 = apr_atoi64(s1);
    apr_int64_t i2 = apr_atoi64(s2);

    if (i1 < i2)
        return -1;
    else if (i1 == i2)
        return 0;
    else
        return 1;
}

static int ap_expr_eval_comp(ap_expr_eval_ctx *ctx, const ap_expr *node)
{
    switch (node->node_op) {
        case op_EQ: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) == 0);
        }
        case op_NE: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) != 0);
        }
        case op_LT: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <  0);
        }
        case op_LE: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <= 0);
        }
        case op_GT: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >  0);
        }
        case op_GE: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >= 0);
        }
        case op_STR_EQ: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) == 0);
        }
        case op_STR_NE: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) != 0);
        }
        case op_STR_LT: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <  0);
        }
        case op_STR_LE: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <= 0);
        }
        case op_STR_GT: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >  0);
        }
        case op_STR_GE: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >= 0);
        }
        case op_IN: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            const char *needle = ap_expr_eval_word(ctx, e1);
            if (e2->node_op == op_ListElement) {
                do {
                    const ap_expr *val = e2->node_arg1;
                    AP_DEBUG_ASSERT(e2->node_op == op_ListElement);
                    if (strcmp(needle, ap_expr_eval_word(ctx, val)) == 0) {
                        return 1;
                        break;
                    }
                    e2 = e2->node_arg2;
                } while (e2 != NULL);
            }
            else if (e2->node_op == op_ListFuncCall) {
                const ap_expr *info = e2->node_arg1;
                const ap_expr *arg = e2->node_arg2;
                ap_expr_list_func_t *func = (ap_expr_list_func_t *)info->node_arg1;
                apr_array_header_t *haystack;
                int i = 0;
                AP_DEBUG_ASSERT(func != NULL);
                AP_DEBUG_ASSERT(info->node_op == op_ListFuncInfo);
                haystack = (*func)(ctx, info->node_arg2, ap_expr_eval_word(ctx, arg));
                if (haystack == NULL)
                    return 0;
                for (; i < haystack->nelts; i++) {
                    if (strcmp(needle, APR_ARRAY_IDX(haystack,i,char *)) == 0)
                        return 1;
                }
            }
            return 0;
        }
        case op_REG: {
            const ap_expr *e1;
            const ap_expr *e2;
            const char *word;
            const ap_regex_t *regex;

            e1 = node->node_arg1;
            e2 = node->node_arg2;
            word = ap_expr_eval_word(ctx, e1);
            regex = e2->node_arg1;
            return (ap_regexec(regex, word, 0, NULL, 0) == 0);
        }
        case op_NRE: {
            const ap_expr *e1;
            const ap_expr *e2;
            const char *word;
            const ap_regex_t *regex;

            e1 = node->node_arg1;
            e2 = node->node_arg2;
            word = ap_expr_eval_word(ctx, e1);
            regex = e2->node_arg1;
            return !(ap_regexec(regex, word, 0, NULL, 0) == 0);
        }
        default: {
            *ctx->err = "Internal evaluation error: Unknown expression node";
            return -1;
        }
    }
}

/* combined string/int comparison for compatibility with ssl_expr */
static int strcmplex(const char *str1, const char *str2)
{
    int i, n1, n2;

    if (str1 == NULL)
        return -1;
    if (str2 == NULL)
        return +1;
    n1 = strlen(str1);
    n2 = strlen(str2);
    if (n1 > n2)
        return 1;
    if (n1 < n2)
        return -1;
    for (i = 0; i < n1; i++) {
        if (str1[i] > str2[i])
            return 1;
        if (str1[i] < str2[i])
            return -1;
    }
    return 0;
}

static int ssl_expr_eval_comp(ap_expr_eval_ctx *ctx, const ap_expr *node)
{
    const ap_expr *e1 = node->node_arg1;
    const ap_expr *e2 = node->node_arg2;
    switch (node->node_op) {
    case op_EQ:
    case op_STR_EQ:
        return (strcmplex(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) == 0);
    case op_NE:
    case op_STR_NE:
        return (strcmplex(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) != 0);
    case op_LT:
    case op_STR_LT:
        return (strcmplex(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <  0);
    case op_LE:
    case op_STR_LE:
        return (strcmplex(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <= 0);
    case op_GT:
    case op_STR_GT:
        return (strcmplex(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >  0);
    case op_GE:
    case op_STR_GE:
        return (strcmplex(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >= 0);
    default:
        return ap_expr_eval_comp(ctx, node);
    }
}


AP_DECLARE(const char *) ap_expr_parse(apr_pool_t *pool, apr_pool_t *ptemp,
                                       ap_expr_info_t *info, const char *expr,
                                       ap_expr_lookup_fn *lookup_fn)
{
    ap_expr_parse_ctx ctx;
    int rc;

    ctx.pool     = pool;
    ctx.ptemp    = ptemp;
    ctx.inputbuf = expr;
    ctx.inputlen = strlen(expr);
    ctx.inputptr = ctx.inputbuf;
    ctx.expr     = NULL;
    ctx.error    = NULL;        /* generic bison error message (usually not very useful) */
    ctx.error2   = NULL;        /* additional error message */
    ctx.flags    = info->flags;
    ctx.scan_del    = '\0';
    ctx.scan_buf[0] = '\0';
    ctx.scan_ptr    = ctx.scan_buf;
    ctx.lookup_fn   = lookup_fn ? lookup_fn : ap_run_expr_lookup;

    ap_expr_yylex_init(&ctx.scanner);
    ap_expr_yyset_extra(&ctx, ctx.scanner);
    rc = ap_expr_yyparse(&ctx);
    ap_expr_yylex_destroy(ctx.scanner);
    if (ctx.error) {
        if (ctx.error2)
            return apr_psprintf(pool, "%s: %s", ctx.error, ctx.error2);
        else
            return ctx.error;
    }
    else if (ctx.error2) {
        return ctx.error2;
    }

    if (rc) /* XXX can this happen? */
        return "syntax error";

    /* XXX Make this properly depend on the loglevel, which requires
     * XXX having a server_rec
     */
    /*
    if (ctx.expr)
        expr_dump_tree(ctx.expr, NULL, APLOG_NOTICE, 2);
    */

    info->root_node = ctx.expr;

    return NULL;
}

AP_DECLARE(ap_expr_info_t*) ap_expr_parse_cmd(const cmd_parms *cmd,
                                              const char *expr,
                                              const char **err,
                                              ap_expr_lookup_fn *lookup_fn)
{
    ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
    info->filename = cmd->directive->filename;
    info->line_number = cmd->directive->line_num;
    *err = ap_expr_parse(cmd->pool, cmd->temp_pool, info, expr, lookup_fn);

    if (*err)
        return NULL;

    return info;
}

ap_expr *ap_expr_make(ap_expr_node_op op, const void *a1, const void *a2,
                      ap_expr_parse_ctx *ctx)
{
    ap_expr *node = apr_palloc(ctx->pool, sizeof(ap_expr));
    node->node_op   = op;
    node->node_arg1 = a1;
    node->node_arg2 = a2;
    return node;
}


static ap_expr *ap_expr_info_make(int type, const char *name, ap_expr_parse_ctx *ctx)
{
    ap_expr *info = apr_palloc(ctx->pool, sizeof(ap_expr));
    ap_expr_lookup_parms parms;
    parms.type  = type;
    parms.flags = 0;
    parms.pool  = ctx->pool;
    parms.ptemp = ctx->ptemp;
    parms.name  = name;
    parms.func  = &info->node_arg1;
    parms.data  = &info->node_arg2;
    parms.err   = &ctx->error2;
    if (ctx->lookup_fn(&parms) != OK)
        return NULL;
    return info;
}

ap_expr *ap_expr_str_func_make(const char *name, const ap_expr *arg,
                               ap_expr_parse_ctx *ctx)
{
    ap_expr *info = ap_expr_info_make(AP_EXPR_FUNC_STRING, name, ctx);
    if (!info)
        return NULL;

    info->node_op = op_StringFuncInfo;
    return ap_expr_make(op_StringFuncCall, info, arg, ctx);
}

ap_expr *ap_expr_list_func_make(const char *name, const ap_expr *arg,
                                ap_expr_parse_ctx *ctx)
{
    ap_expr *info = ap_expr_info_make(AP_EXPR_FUNC_LIST, name, ctx);
    if (!info)
        return NULL;

    info->node_op = op_ListFuncInfo;
    return ap_expr_make(op_ListFuncCall, info, arg, ctx);
}

ap_expr *ap_expr_unary_op_make(const char *name, const ap_expr *arg,
                               ap_expr_parse_ctx *ctx)
{
    ap_expr *info = ap_expr_info_make(AP_EXPR_FUNC_OP_UNARY, name, ctx);
    if (!info)
        return NULL;

    info->node_op = op_UnaryOpInfo;
    return ap_expr_make(op_UnaryOpCall, info, arg, ctx);
}

ap_expr *ap_expr_binary_op_make(const char *name, const ap_expr *arg1,
                                const ap_expr *arg2, ap_expr_parse_ctx *ctx)
{
    ap_expr *args;
    ap_expr *info = ap_expr_info_make(AP_EXPR_FUNC_OP_UNARY, name, ctx);
    if (!info)
        return NULL;

    info->node_op = op_BinaryOpInfo;
    args = ap_expr_make(op_BinaryOpArgs, arg1, arg2, ctx);
    return ap_expr_make(op_BinaryOpCall, info, args, ctx);
}


ap_expr *ap_expr_var_make(const char *name, ap_expr_parse_ctx *ctx)
{
    ap_expr *node = ap_expr_info_make(AP_EXPR_FUNC_VAR, name, ctx);
    if (!node)
        return NULL;

    node->node_op = op_Var;
    return node;
}


#define MARK                        APLOG_MARK,loglevel,0,s
#define DUMP_E_E(op, e1, e2)                                                \
    do { ap_log_error(MARK,"%*s%s: %pp %pp", indent, " ", op, e1, e2);      \
         if (e1) expr_dump_tree(e1, s, loglevel, indent + 2);               \
         if (e2) expr_dump_tree(e2, s, loglevel, indent + 2);               \
    } while (0)
#define DUMP_S_E(op, s1, e1)                                                    \
    do { ap_log_error(MARK,"%*s%s: '%s' %pp", indent, " ", op, (char *)s1, e1); \
         if (e1) expr_dump_tree(e1, s, loglevel, indent + 2);                   \
    } while (0)
#define DUMP_S_P(op, s1, p1)                                                \
    ap_log_error(MARK,"%*s%s: '%s' %pp", indent, " ", op, (char *)s1, p1);
#define DUMP_P_P(op, p1, p2)                                                \
    ap_log_error(MARK,"%*s%s: %pp %pp", indent, " ", op, p1, p2);
#define DUMP_S_S(op, s1, s2)                                                       \
    ap_log_error(MARK,"%*s%s: '%s' '%s'", indent, " ", op, (char *)s1, (char *)s2)
#define DUMP_P(op, p1)                                                      \
    ap_log_error(MARK,"%*s%s: %pp", indent, " ", op, p1);
#define DUMP_S(op, s1)                                                      \
    ap_log_error(MARK,"%*s%s: '%s'", indent, " ", op, (char *)s1)

#define CASE_OP(op)                  case op: name = #op ; break;

static void expr_dump_tree(const ap_expr *e, const server_rec *s, int loglevel, int indent)
{
    switch (e->node_op) {
    /* no arg */
    case op_NOP:
    case op_True:
    case op_False:
        {
            char *name;
            switch (e->node_op) {
            CASE_OP(op_NOP);
            CASE_OP(op_True);
            CASE_OP(op_False);
            default:
                ap_assert(0);
            }
            ap_log_error(MARK, "%*s%s", indent, " ", name);
        }
        break;

    /* arg1: string, arg2: expr */
    case op_UnaryOpCall:
    case op_BinaryOpCall:
    case op_BinaryOpArgs:
        {
            char *name;
            switch (e->node_op) {
            CASE_OP(op_BinaryOpCall);
            CASE_OP(op_UnaryOpCall);
            CASE_OP(op_BinaryOpArgs);
            default:
                ap_assert(0);
            }
            DUMP_S_E(name, e->node_arg1, e->node_arg2);
        }
        break;

    /* arg1: expr, arg2: expr */
    case op_Comp:
    case op_Not:
    case op_Or:
    case op_And:
    case op_EQ:
    case op_NE:
    case op_LT:
    case op_LE:
    case op_GT:
    case op_GE:
    case op_STR_EQ:
    case op_STR_NE:
    case op_STR_LT:
    case op_STR_LE:
    case op_STR_GT:
    case op_STR_GE:
    case op_IN:
    case op_REG:
    case op_NRE:
    case op_Concat:
    case op_StringFuncCall:
    case op_ListFuncCall:
    case op_ListElement:
        {
            char *name;
            switch (e->node_op) {
            CASE_OP(op_Comp);
            CASE_OP(op_Not);
            CASE_OP(op_Or);
            CASE_OP(op_And);
            CASE_OP(op_EQ);
            CASE_OP(op_NE);
            CASE_OP(op_LT);
            CASE_OP(op_LE);
            CASE_OP(op_GT);
            CASE_OP(op_GE);
            CASE_OP(op_STR_EQ);
            CASE_OP(op_STR_NE);
            CASE_OP(op_STR_LT);
            CASE_OP(op_STR_LE);
            CASE_OP(op_STR_GT);
            CASE_OP(op_STR_GE);
            CASE_OP(op_IN);
            CASE_OP(op_REG);
            CASE_OP(op_NRE);
            CASE_OP(op_Concat);
            CASE_OP(op_StringFuncCall);
            CASE_OP(op_ListFuncCall);
            CASE_OP(op_ListElement);
            default:
                ap_assert(0);
            }
            DUMP_E_E(name, e->node_arg1, e->node_arg2);
        }
        break;
    /* arg1: string */
    case op_Digit:
    case op_String:
        {
            char *name;
            switch (e->node_op) {
            CASE_OP(op_Digit);
            CASE_OP(op_String);
            default:
                ap_assert(0);
            }
            DUMP_S(name, e->node_arg1);
        }
        break;
    /* arg1: pointer, arg2: pointer */
    case op_Var:
    case op_StringFuncInfo:
    case op_UnaryOpInfo:
    case op_BinaryOpInfo:
    case op_ListFuncInfo:
        {
            char *name;
            switch (e->node_op) {
            CASE_OP(op_Var);
            CASE_OP(op_StringFuncInfo);
            CASE_OP(op_UnaryOpInfo);
            CASE_OP(op_BinaryOpInfo);
            CASE_OP(op_ListFuncInfo);
            default:
                ap_assert(0);
            }
            DUMP_P_P(name, e->node_arg1, e->node_arg2);
        }
        break;
    /* arg1: pointer */
    case op_Regex:
        DUMP_P("op_Regex", e->node_arg1);
        break;
    default:
        ap_log_error(MARK, "%*sERROR: INVALID OP %d", indent, " ", e->node_op);
        break;
    }
}
static int ap_expr_eval_unary_op(ap_expr_eval_ctx *ctx, const ap_expr *info,
                                 const ap_expr *arg)
{
    const ap_expr_op_unary_t *op_func = info->node_arg1;
    const void *data = info->node_arg2;

    AP_DEBUG_ASSERT(info->node_op == op_UnaryOpInfo);
    AP_DEBUG_ASSERT(op_func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*op_func)(ctx, data, ap_expr_eval_word(ctx, arg));
}

static int ap_expr_eval_binary_op(ap_expr_eval_ctx *ctx, const ap_expr *info,
                                  const ap_expr *args)
{
    const ap_expr_op_binary_t *op_func = info->node_arg1;
    const void *data = info->node_arg2;
    const ap_expr *a1 = args->node_arg1;
    const ap_expr *a2 = args->node_arg2;

    AP_DEBUG_ASSERT(info->node_op == op_BinaryOpInfo);
    AP_DEBUG_ASSERT(args->node_op == op_BinaryOpArgs);
    AP_DEBUG_ASSERT(op_func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*op_func)(ctx, data, ap_expr_eval_word(ctx, a1),
                      ap_expr_eval_word(ctx, a2));
}


static int ap_expr_eval(ap_expr_eval_ctx *ctx, const ap_expr *node)
{
    switch (node->node_op) {
        case op_True: {
            return 1;
        }
        case op_False: {
            return 0;
        }
        case op_Not: {
            const ap_expr *e = node->node_arg1;
            return (!ap_expr_eval(ctx, e));
        }
        case op_Or: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (ap_expr_eval(ctx, e1) || ap_expr_eval(ctx, e2));
        }
        case op_And: {
            const ap_expr *e1 = node->node_arg1;
            const ap_expr *e2 = node->node_arg2;
            return (ap_expr_eval(ctx, e1) && ap_expr_eval(ctx, e2));
        }
        case op_UnaryOpCall: {
            const ap_expr *info = node->node_arg1;
            const ap_expr *args = node->node_arg2;
            return ap_expr_eval_unary_op(ctx, info, args);
        }
        case op_BinaryOpCall: {
            const ap_expr *info = node->node_arg1;
            const ap_expr *args = node->node_arg2;
            return ap_expr_eval_binary_op(ctx, info, args);
        }
        case op_Comp: {
            const ap_expr *e = node->node_arg1;
            if (ctx->info->flags & AP_EXPR_FLAGS_SSL_EXPR_COMPAT)
                return ssl_expr_eval_comp(ctx, e);
            else
                return ap_expr_eval_comp(ctx, e);
        }
        default: {
            *ctx->err = "Internal evaluation error: Unknown expression node";
            return FALSE;
        }
    }
}


AP_DECLARE(int) ap_expr_exec(request_rec *r, const ap_expr_info_t *info, const char **err)
{
    ap_expr_eval_ctx ctx;
    int rc;
    ctx.r = r;
    ctx.c = r->connection;
    ctx.s = r->server;
    ctx.p = r->pool;
    ctx.err  = err;
    ctx.info = info;

    *err = NULL;
    rc = ap_expr_eval(&ctx, info->root_node);
    if (*err != NULL) {
        ap_log_rerror(__FILE__, __LINE__, info->module_index, APLOG_ERR, 0,
                      r, "Evaluation of expression from %s:%d failed: %s",
                      info->filename, info->line_number, *err);
        return -1;
    } else {
        rc = rc ? 1 : 0;
        ap_log_rerror(__FILE__, __LINE__, info->module_index, APLOG_TRACE4, 0,
                      r, "Evaluation of expression from %s:%d gave: %d",
                      info->filename, info->line_number, rc);
        return rc;
    }
}

static const char *req_table_func(ap_expr_eval_ctx *ctx, const void *data,
                                  const char *arg)
{
    const char *name = (const char *)data;
    apr_table_t *t;
    if (!ctx->r)
        return "";

    if (name[3] == 's')             /* resp */
        t = ctx->r->headers_out;
    else if (name[4] == 'e')        /* reqenv */
        t = ctx->r->subprocess_env;
    else if (name[0] == 'n')        /* notes */
        t = ctx->r->notes;
    else
        t = ctx->r->headers_in;
    return apr_table_get(t, arg);
}

static const char *env_func(ap_expr_eval_ctx *ctx, const void *data,
                            const char *arg)
{
    const char *res;
    /* this order is for ssl_expr compatibility */
    if (ctx->r) {
        if ((res = apr_table_get(ctx->r->notes, arg)) != NULL)
            return res;
        else if ((res = apr_table_get(ctx->r->subprocess_env, arg)) != NULL)
            return res;
    }
    return getenv(arg);
}

static const char *osenv_func(ap_expr_eval_ctx *ctx, const void *data,
                              const char *arg)
{
    return getenv(arg);
}

static const char *tolower_func(ap_expr_eval_ctx *ctx, const void *data,
                                const char *arg)
{
    char *result = apr_pstrdup(ctx->p, arg);
    ap_str_tolower(result);
    return result;
}

static const char *toupper_func(ap_expr_eval_ctx *ctx, const void *data,
                                const char *arg)
{
    char *p;
    char *result = apr_pstrdup(ctx->p, arg);

    for (p = result; *p; ++p) {
         *p = apr_toupper(*p);
    }

    return result;
}

static const char *escape_func(ap_expr_eval_ctx *ctx, const void *data,
                               const char *arg)
{
    return ap_escape_uri(ctx->p, arg);
}

#define MAX_FILE_SIZE 10*1024*1024
static const char *file_func(ap_expr_eval_ctx *ctx, const void *data, char *arg)
{
    apr_file_t *fp;
    char *buf;
    apr_off_t offset;
    apr_size_t len;
    apr_finfo_t finfo;

    if (apr_file_open(&fp, arg, APR_READ|APR_BUFFERED,
                      APR_OS_DEFAULT, ctx->p) != APR_SUCCESS) {
        *ctx->err = apr_psprintf(ctx->p, "Cannot open file %s", arg);
        return "";
    }
    apr_file_info_get(&finfo, APR_FINFO_SIZE, fp);
    if (finfo.size > MAX_FILE_SIZE) {
        *ctx->err = apr_psprintf(ctx->p, "File %s too large", arg);
        apr_file_close(fp);
        return "";
    }
    len = (apr_size_t)finfo.size;
    if (len == 0) {
        apr_file_close(fp);
        return "";
    }
    else {
        if ((buf = (char *)apr_palloc(ctx->p, sizeof(char)*(len+1))) == NULL) {
            *ctx->err = "Cannot allocate memory";
            apr_file_close(fp);
            return "";
        }
        offset = 0;
        apr_file_seek(fp, APR_SET, &offset);
        if (apr_file_read(fp, buf, &len) != APR_SUCCESS) {
            *ctx->err = apr_psprintf(ctx->p, "Cannot read from file %s", arg);
            apr_file_close(fp);
            return "";
        }
        buf[len] = '\0';
    }
    apr_file_close(fp);
    return buf;
}


static const char *unescape_func(ap_expr_eval_ctx *ctx, const void *data,
                                 const char *arg)
{
    char *result = apr_pstrdup(ctx->p, arg);
    if (ap_unescape_url(result))
        return "";
    else
        return result;

}

static int op_nz(ap_expr_eval_ctx *ctx, const void *data, const char *arg)
{
    const char *name = (const char *)data;
    if (name[0] == 'z')
        return (arg[0] == '\0');
    else
        return (arg[0] != '\0');
}

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *is_https = NULL;

static const char *conn_var_names[] = {
    "REMOTE_ADDR",              /*  0 */
    "HTTPS",                    /*  1 */
    "IPV6",                     /*  2 */
    "CONN_LOG_ID",              /*  3 */
    NULL
};

static const char *conn_var_fn(ap_expr_eval_ctx *ctx, const void *data)
{
    int index = ((const char **)data - conn_var_names);
    conn_rec *c = ctx->c;
    if (!c)
        return "";

    switch (index) {
    case 0:
        return c->remote_ip;
    case 1:
        if (is_https && is_https(c))
            return "on";
        else
            return "off";
    case 2:
#if APR_HAVE_IPV6
        {
            apr_sockaddr_t *addr = c->remote_addr;
            if (addr->family == AF_INET6
                && !IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr->ipaddr_ptr))
                return "on";
            else
                return "off";
        }
#else
        return "off";
#endif
    case 3:
        return c->log_id;
    default:
        ap_assert(0);
        return NULL;
    }
}

static const char *request_var_names[] = {
    "REQUEST_METHOD",           /*  0 */
    "REQUEST_SCHEME",           /*  1 */
    "REQUEST_URI",              /*  2 */
    "REQUEST_FILENAME",         /*  3 */
    "REMOTE_HOST",              /*  4 */
    "REMOTE_IDENT",             /*  5 */
    "REMOTE_USER",              /*  6 */
    "SERVER_ADMIN",             /*  7 */
    "SERVER_NAME",              /*  8 */
    "SERVER_PORT",              /*  9 */
    "SERVER_PROTOCOL",          /* 10 */
    "SCRIPT_FILENAME",          /* 11 */
    "PATH_INFO",                /* 12 */
    "QUERY_STRING",             /* 13 */
    "IS_SUBREQ",                /* 14 */
    "DOCUMENT_ROOT",            /* 15 */
    "AUTH_TYPE",                /* 16 */
    "THE_REQUEST",              /* 17 */
    "CONTENT_TYPE",             /* 18 */
    "HANDLER",                  /* 19 */
    "REQUEST_LOG_ID",           /* 20 */
    NULL
};

static const char *request_var_fn(ap_expr_eval_ctx *ctx, const void *data)
{
    int index = ((const char **)data - request_var_names);
    request_rec *r = ctx->r;
    if (!r)
        return "";

    switch (index) {
    case 0:
        return r->method;
    case 1:
        return ap_http_scheme(r);
    case 2:
        return r->uri;
    case 3:
        return r->filename;
    case 4:
        return ap_get_remote_host(r->connection, r->per_dir_config,
                                  REMOTE_NAME, NULL);
    case 5:
        return ap_get_remote_logname(r);
    case 6:
        return r->user;
    case 7:
        return r->server->server_admin;
    case 8:
        return ap_get_server_name(r);
    case 9:
        return apr_psprintf(ctx->p, "%u", ap_get_server_port(r));
    case 10:
        return r->protocol;
    case 11:
        return r->filename;
    case 12:
        return r->path_info;
    case 13:
        return r->args;
    case 14:
        return (r->main != NULL ? "true" : "false");
    case 15:
        return ap_document_root(r);
    case 16:
        return r->ap_auth_type;
    case 17:
        return r->the_request;
    case 18:
        return r->content_type;
    case 19:
        return r->handler;
    case 20:
        return r->log_id;
    default:
        ap_assert(0);
        return NULL;
    }
}

static const char *req_header_var_names[] = {
    "HTTP_USER_AGENT",          /* 0 */
    "HTTP_PROXY_CONNECTION",    /* 1 */
    "HTTP_REFERER",
    "HTTP_COOKIE",
    "HTTP_FORWARDED",
    "HTTP_HOST",
    "HTTP_ACCEPT",
    NULL
};

static const char *req_header_var_fn(ap_expr_eval_ctx *ctx, const void *data)
{
    const char **name = (const char **)data;
    int index = (name - req_header_var_names);
    if (!ctx->r)
        return "";

    switch (index) {
    case 0:
        return apr_table_get(ctx->r->headers_in, "User-Agent");
    case 1:
        return apr_table_get(ctx->r->headers_in, "Proxy-Connection");
    default:
        /* apr_table_get is case insensitive, just skip leading "HTTP_" */
        return apr_table_get(ctx->r->headers_in, *name + 5);
    }
}

static const char *misc_var_names[] = {
    "TIME_YEAR",        /* 0 */
    "TIME_MON",         /* 1 */
    "TIME_DAY",         /* 2 */
    "TIME_HOUR",        /* 3 */
    "TIME_MIN",         /* 4 */
    "TIME_SEC",         /* 5 */
    "TIME_WDAY",        /* 6 */
    "TIME",             /* 7 */
    "SERVER_SOFTWARE",  /* 8 */
    "API_VERSION",      /* 9 */
    NULL
};

static const char *misc_var_fn(ap_expr_eval_ctx *ctx, const void *data)
{
    apr_time_exp_t tm;
    int index = ((const char **)data - misc_var_names);
    apr_time_exp_lt(&tm, apr_time_now());

    switch (index) {
    case 0:
        return apr_psprintf(ctx->p, "%02d%02d", (tm.tm_year / 100) + 19,
                            tm.tm_year % 100);
    case 1:
        return apr_psprintf(ctx->p, "%02d", tm.tm_mon+1);
    case 2:
        return apr_psprintf(ctx->p, "%02d", tm.tm_mday);
    case 3:
        return apr_psprintf(ctx->p, "%02d", tm.tm_hour);
    case 4:
        return apr_psprintf(ctx->p, "%02d", tm.tm_min);
    case 5:
        return apr_psprintf(ctx->p, "%02d", tm.tm_sec);
    case 6:
        return apr_psprintf(ctx->p, "%d", tm.tm_wday);
    case 7:
        return apr_psprintf(ctx->p, "%02d%02d%02d%02d%02d%02d%02d",
                            (tm.tm_year / 100) + 19, (tm.tm_year % 100),
                            tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min,
                            tm.tm_sec);
    case 8:
        return ap_get_server_banner();
    case 9:
        return apr_itoa(ctx->p, MODULE_MAGIC_NUMBER);
    default:
        ap_assert(0);
    }

    return NULL;
}

struct expr_provider_single {
    const void *func;
    const char *name;
};
struct expr_provider_multi {
    const void *func;
    const char **names;
};

static const struct expr_provider_multi var_providers[] = {
    { misc_var_fn, misc_var_names },
    { req_header_var_fn, req_header_var_names },
    { request_var_fn, request_var_names },
    { conn_var_fn, conn_var_names },
    { NULL, NULL }
};

static const struct expr_provider_single string_func_providers[] = {
    { osenv_func, "osenv" },
    { env_func, "env" },
    { req_table_func, "resp" },
    { req_table_func, "req" },
    /* 'http' as alias for 'req' for compatibility with ssl_expr */
    { req_table_func, "http" },
    { req_table_func, "note" },
    { tolower_func, "tolower" },
    { toupper_func, "toupper" },
    { escape_func, "escape" },
    { unescape_func, "unescape" },
    { file_func, "file" },
    { NULL, NULL}
};
/* XXX: base64 encode/decode ? */

static const struct expr_provider_single unary_op_providers[] = {
    { op_nz, "n" },
    { op_nz, "z" },
    { NULL, NULL}
};
static int core_expr_lookup(ap_expr_lookup_parms *parms)
{
    switch (parms->type) {
    case AP_EXPR_FUNC_VAR: {
        const struct expr_provider_multi *prov = var_providers;
        while (prov->func) {
            const char **name = prov->names;
            while (*name) {
                if (strcasecmp(*name, parms->name) == 0) {
                    *parms->func = prov->func;
                    *parms->data = name;
                    return OK;
                }
                name++;
            }
            prov++;
        }
        break;
    }
    case AP_EXPR_FUNC_STRING: {
        const struct expr_provider_single *prov = string_func_providers;
        while (prov->func) {
            if (strcasecmp(prov->name, parms->name) == 0) {
                *parms->func = prov->func;
                *parms->data = prov->name;
                return OK;
            }
            prov++;
        }
        break;
    }
    case AP_EXPR_FUNC_OP_UNARY: {
        const struct expr_provider_single *prov = unary_op_providers;
        while (prov->func) {
            if (strcasecmp(prov->name, parms->name) == 0) {
                *parms->func = prov->func;
                *parms->data = prov->name;
                return OK;
            }
            prov++;
        }
        break;
    }
    default:
        break;
    }
    return DECLINED;
}

static int expr_lookup_not_found(ap_expr_lookup_parms *parms)
{
    const char *type;

    switch (parms->type) {
    case AP_EXPR_FUNC_VAR:
        type = "Variable";
        break;
    case AP_EXPR_FUNC_STRING:
        type = "Function";
        break;
    case AP_EXPR_FUNC_LIST:
        type = "List-returning function";
        break;
    case AP_EXPR_FUNC_OP_UNARY:
        type = "Unary operator";
        break;
    case AP_EXPR_FUNC_OP_BINARY:
        type = "Binary operator";
        break;
    default:
        *parms->err = "Inavalid expression type in expr_lookup";
        return !OK;
    }
    *parms->err = apr_psprintf(parms->ptemp, "%s '%s' does not exist", type,
                               parms->name);
    return !OK;
}

static int ap_expr_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    apr_pool_cleanup_register(pconf, &is_https, ap_pool_cleanup_set_null,
                              apr_pool_cleanup_null);
    return OK;
}

void ap_expr_init(apr_pool_t *p)
{
    ap_hook_expr_lookup(core_expr_lookup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_expr_lookup(expr_lookup_not_found, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_hook_post_config(ap_expr_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

