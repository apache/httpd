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
#include "apr_fnmatch.h"

APLOG_USE_MODULE(core);

APR_HOOK_STRUCT(
    APR_HOOK_LINK(expr_lookup)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int, expr_lookup, (ap_expr_lookup_parms *parms),
                            (parms), DECLINED)

static const char *ap_expr_eval_string_func(ap_expr_eval_ctx_t *ctx,
                                            const ap_expr_t *info,
                                            const ap_expr_t *args);
static const char *ap_expr_eval_re_backref(ap_expr_eval_ctx_t *ctx, int n);
static const char *ap_expr_eval_var(ap_expr_eval_ctx_t *ctx,
                                    const ap_expr_var_func_t *func,
                                    const void *data);

/* define AP_EXPR_DEBUG to log the parse tree when parsing an expression */
#ifdef AP_EXPR_DEBUG
static void expr_dump_tree(const ap_expr_t *e, const server_rec *s,
                           int loglevel, int indent);
#endif

static const char *ap_expr_eval_word(ap_expr_eval_ctx_t *ctx,
                                     const ap_expr_t *node)
{
    const char *result = "";
    switch (node->node_op) {
    case op_Digit:
    case op_String:
        result = node->node_arg1;
        break;
    case op_Var:
        result = ap_expr_eval_var(ctx, node->node_arg1, node->node_arg2);
        break;
    case op_Concat: {
        const char *s1 = ap_expr_eval_word(ctx, node->node_arg1);
        const char *s2 = ap_expr_eval_word(ctx, node->node_arg2);
        if (!*s1)
            result = s2;
        else if (!*s2)
            result = s1;
        else
            result = apr_pstrcat(ctx->p, s1, s2, NULL);
        break;
    }
    case op_StringFuncCall: {
        const ap_expr_t *info = node->node_arg1;
        const ap_expr_t *args = node->node_arg2;
        result = ap_expr_eval_string_func(ctx, info, args);
        break;
    }
    case op_RegexBackref: {
        const int *np = node->node_arg1;
        result = ap_expr_eval_re_backref(ctx, *np);
        break;
    }
    default:
        *ctx->err = "Internal evaluation error: Unknown word expression node";
        break;
    }
    if (!result)
        result = "";
    return result;
}

static const char *ap_expr_eval_var(ap_expr_eval_ctx_t *ctx, 
                                    const ap_expr_var_func_t *func,
                                    const void *data)
{
    AP_DEBUG_ASSERT(func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*func)(ctx, data);
}

static const char *ap_expr_eval_re_backref(ap_expr_eval_ctx_t *ctx, int n)
{
    int len;

    if (!ctx->re_pmatch || !ctx->re_source || *ctx->re_source == '\0' ||
        ctx->re_nmatch < n + 1)
        return "";

    len = ctx->re_pmatch[n].rm_eo - ctx->re_pmatch[n].rm_so;
    if (len == 0)
        return "";

    return apr_pstrndup(ctx->p, *ctx->re_source + ctx->re_pmatch[n].rm_so, len);
}

static const char *ap_expr_eval_string_func(ap_expr_eval_ctx_t *ctx,
                                            const ap_expr_t *info,
                                            const ap_expr_t *arg)
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

static int ap_expr_eval_comp(ap_expr_eval_ctx_t *ctx, const ap_expr_t *node)
{
    const ap_expr_t *e1 = node->node_arg1;
    const ap_expr_t *e2 = node->node_arg2;
    switch (node->node_op) {
    case op_EQ:
        return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) == 0);
    case op_NE:
        return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) != 0);
    case op_LT:
        return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <  0);
    case op_LE:
        return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <= 0);
    case op_GT:
        return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >  0);
    case op_GE:
        return (intstrcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >= 0);
    case op_STR_EQ:
        return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) == 0);
    case op_STR_NE:
        return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) != 0);
    case op_STR_LT:
        return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <  0);
    case op_STR_LE:
        return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) <= 0);
    case op_STR_GT:
        return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >  0);
    case op_STR_GE:
        return (strcmp(ap_expr_eval_word(ctx, e1), ap_expr_eval_word(ctx, e2)) >= 0);
    case op_IN: {
            const char *needle = ap_expr_eval_word(ctx, e1);
            if (e2->node_op == op_ListElement) {
                do {
                    const ap_expr_t *val = e2->node_arg1;
                    AP_DEBUG_ASSERT(e2->node_op == op_ListElement);
                    if (strcmp(needle, ap_expr_eval_word(ctx, val)) == 0) {
                        return 1;
                        break;
                    }
                    e2 = e2->node_arg2;
                } while (e2 != NULL);
            }
            else if (e2->node_op == op_ListFuncCall) {
                const ap_expr_t *info = e2->node_arg1;
                const ap_expr_t *arg = e2->node_arg2;
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
    case op_REG:
    case op_NRE: {
            const char *word = ap_expr_eval_word(ctx, e1);
            const ap_regex_t *regex = e2->node_arg1;
            int result;

            /*
             * $0 ... $9 may contain stuff the user wants to keep. Therefore
             * we only set them if there are capturing parens in the regex.
             */
            if (regex->re_nsub > 0) {
                result = (0 == ap_regexec(regex, word, ctx->re_nmatch,
                                          ctx->re_pmatch, 0));
                *ctx->re_source = result ? word : NULL;
            }
            else {
                result = (0 == ap_regexec(regex, word, 0, NULL, 0));
            }

            if (node->node_op == op_REG)
                return result;
            else
                return !result;
        }
    default:
        *ctx->err = "Internal evaluation error: Unknown comp expression node";
        return -1;
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

static int ssl_expr_eval_comp(ap_expr_eval_ctx_t *ctx, const ap_expr_t *node)
{
    const ap_expr_t *e1 = node->node_arg1;
    const ap_expr_t *e2 = node->node_arg2;
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

AP_DECLARE_NONSTD(int) ap_expr_lookup_default(ap_expr_lookup_parms *parms)
{
    return ap_run_expr_lookup(parms);
}

AP_DECLARE(const char *) ap_expr_parse(apr_pool_t *pool, apr_pool_t *ptemp,
                                       ap_expr_info_t *info, const char *expr,
                                       ap_expr_lookup_fn_t *lookup_fn)
{
    ap_expr_parse_ctx_t ctx;
    int rc;

    ctx.pool     = pool;
    ctx.ptemp    = ptemp;
    ctx.inputbuf = expr;
    ctx.inputlen = strlen(expr);
    ctx.inputptr = ctx.inputbuf;
    ctx.expr     = NULL;
    ctx.error    = NULL;        /* generic bison error message (XXX: usually not very useful, should be axed) */
    ctx.error2   = NULL;        /* additional error message */
    ctx.flags    = info->flags;
    ctx.scan_del    = '\0';
    ctx.scan_buf[0] = '\0';
    ctx.scan_ptr    = ctx.scan_buf;
    ctx.lookup_fn   = lookup_fn ? lookup_fn : ap_expr_lookup_default;


    /*
     * Be sure to avoid overflows in the scanner. In practice the input length
     * will be limited by the config file parser, anyway.
     * XXX: The scanner really should do proper buffer overflow checks
     */
    if (ctx.inputlen >= MAX_STRING_LEN)
        return "Expression too long";

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

#ifdef AP_EXPR_DEBUG
    if (ctx.expr)
        expr_dump_tree(ctx.expr, NULL, APLOG_NOTICE, 2);
#endif

    info->root_node = ctx.expr;

    return NULL;
}

AP_DECLARE(ap_expr_info_t*) ap_expr_parse_cmd(const cmd_parms *cmd,
                                              const char *expr,
                                              const char **err,
                                              ap_expr_lookup_fn_t *lookup_fn)
{
    ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
    info->filename = cmd->directive->filename;
    info->line_number = cmd->directive->line_num;
    *err = ap_expr_parse(cmd->pool, cmd->temp_pool, info, expr, lookup_fn);

    if (*err)
        return NULL;

    return info;
}

ap_expr_t *ap_expr_make(ap_expr_node_op_e op, const void *a1, const void *a2,
                      ap_expr_parse_ctx_t *ctx)
{
    ap_expr_t *node = apr_palloc(ctx->pool, sizeof(ap_expr_t));
    node->node_op   = op;
    node->node_arg1 = a1;
    node->node_arg2 = a2;
    return node;
}

static ap_expr_t *ap_expr_info_make(int type, const char *name,
                                  ap_expr_parse_ctx_t *ctx,
                                  const ap_expr_t *arg)
{
    ap_expr_t *info = apr_palloc(ctx->pool, sizeof(ap_expr_t));
    ap_expr_lookup_parms parms;
    parms.type  = type;
    parms.flags = 0;
    parms.pool  = ctx->pool;
    parms.ptemp = ctx->ptemp;
    parms.name  = name;
    parms.func  = &info->node_arg1;
    parms.data  = &info->node_arg2;
    parms.err   = &ctx->error2;
    parms.arg   = (arg && arg->node_op == op_String) ? arg->node_arg1 : NULL;
    if (ctx->lookup_fn(&parms) != OK)
        return NULL;
    return info;
}

ap_expr_t *ap_expr_str_func_make(const char *name, const ap_expr_t *arg,
                               ap_expr_parse_ctx_t *ctx)
{
    ap_expr_t *info = ap_expr_info_make(AP_EXPR_FUNC_STRING, name, ctx, arg);
    if (!info)
        return NULL;

    info->node_op = op_StringFuncInfo;
    return ap_expr_make(op_StringFuncCall, info, arg, ctx);
}

ap_expr_t *ap_expr_list_func_make(const char *name, const ap_expr_t *arg,
                                ap_expr_parse_ctx_t *ctx)
{
    ap_expr_t *info = ap_expr_info_make(AP_EXPR_FUNC_LIST, name, ctx, arg);
    if (!info)
        return NULL;

    info->node_op = op_ListFuncInfo;
    return ap_expr_make(op_ListFuncCall, info, arg, ctx);
}

ap_expr_t *ap_expr_unary_op_make(const char *name, const ap_expr_t *arg,
                               ap_expr_parse_ctx_t *ctx)
{
    ap_expr_t *info = ap_expr_info_make(AP_EXPR_FUNC_OP_UNARY, name, ctx, arg);
    if (!info)
        return NULL;

    info->node_op = op_UnaryOpInfo;
    return ap_expr_make(op_UnaryOpCall, info, arg, ctx);
}

ap_expr_t *ap_expr_binary_op_make(const char *name, const ap_expr_t *arg1,
                                const ap_expr_t *arg2, ap_expr_parse_ctx_t *ctx)
{
    ap_expr_t *args;
    ap_expr_t *info = ap_expr_info_make(AP_EXPR_FUNC_OP_BINARY, name, ctx,
                                        arg2);
    if (!info)
        return NULL;

    info->node_op = op_BinaryOpInfo;
    args = ap_expr_make(op_BinaryOpArgs, arg1, arg2, ctx);
    return ap_expr_make(op_BinaryOpCall, info, args, ctx);
}


ap_expr_t *ap_expr_var_make(const char *name, ap_expr_parse_ctx_t *ctx)
{
    ap_expr_t *node = ap_expr_info_make(AP_EXPR_FUNC_VAR, name, ctx, NULL);
    if (!node)
        return NULL;

    node->node_op = op_Var;
    return node;
}

#ifdef AP_EXPR_DEBUG

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
#define DUMP_IP(op, p1)                                                     \
    ap_log_error(MARK,"%*s%s: %d", indent, " ", op, *(int *)p1);
#define DUMP_S(op, s1)                                                      \
    ap_log_error(MARK,"%*s%s: '%s'", indent, " ", op, (char *)s1)

#define CASE_OP(op)                  case op: name = #op ; break;

static void expr_dump_tree(const ap_expr_t *e, const server_rec *s,
                           int loglevel, int indent)
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
    /* arg1: pointer to int */
    case op_RegexBackref:
        DUMP_IP("op_RegexBackref", e->node_arg1);
        break;
    default:
        ap_log_error(MARK, "%*sERROR: INVALID OP %d", indent, " ", e->node_op);
        break;
    }
}
#endif /* AP_EXPR_DEBUG */

static int ap_expr_eval_unary_op(ap_expr_eval_ctx_t *ctx, const ap_expr_t *info,
                                 const ap_expr_t *arg)
{
    const ap_expr_op_unary_t *op_func = info->node_arg1;
    const void *data = info->node_arg2;

    AP_DEBUG_ASSERT(info->node_op == op_UnaryOpInfo);
    AP_DEBUG_ASSERT(op_func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*op_func)(ctx, data, ap_expr_eval_word(ctx, arg));
}

static int ap_expr_eval_binary_op(ap_expr_eval_ctx_t *ctx,
                                  const ap_expr_t *info,
                                  const ap_expr_t *args)
{
    const ap_expr_op_binary_t *op_func = info->node_arg1;
    const void *data = info->node_arg2;
    const ap_expr_t *a1 = args->node_arg1;
    const ap_expr_t *a2 = args->node_arg2;

    AP_DEBUG_ASSERT(info->node_op == op_BinaryOpInfo);
    AP_DEBUG_ASSERT(args->node_op == op_BinaryOpArgs);
    AP_DEBUG_ASSERT(op_func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*op_func)(ctx, data, ap_expr_eval_word(ctx, a1),
                      ap_expr_eval_word(ctx, a2));
}


static int ap_expr_eval(ap_expr_eval_ctx_t *ctx, const ap_expr_t *node)
{
    const ap_expr_t *e1 = node->node_arg1;
    const ap_expr_t *e2 = node->node_arg2;
    switch (node->node_op) {
    case op_True:
        return 1;
    case op_False:
        return 0;
    case op_Not:
        return (!ap_expr_eval(ctx, e1));
    case op_Or:
        return (ap_expr_eval(ctx, e1) || ap_expr_eval(ctx, e2));
    case op_And:
        return (ap_expr_eval(ctx, e1) && ap_expr_eval(ctx, e2));
    case op_UnaryOpCall:
        return ap_expr_eval_unary_op(ctx, e1, e2);
    case op_BinaryOpCall:
        return ap_expr_eval_binary_op(ctx, e1, e2);
    case op_Comp:
        if (ctx->info->flags & AP_EXPR_FLAGS_SSL_EXPR_COMPAT)
            return ssl_expr_eval_comp(ctx, e1);
        else
            return ap_expr_eval_comp(ctx, e1);
    default:
        *ctx->err = "Internal evaluation error: Unknown expression node";
        return FALSE;
    }
}

AP_DECLARE(int) ap_expr_exec(request_rec *r, const ap_expr_info_t *info,
                             const char **err)
{
    return ap_expr_exec_re(r, info, 0, NULL, NULL, err);
}

AP_DECLARE(int) ap_expr_exec_re(request_rec *r, const ap_expr_info_t *info,
                                apr_size_t nmatch, ap_regmatch_t *pmatch,
                                const char **source, const char **err)
{
    ap_expr_eval_ctx_t ctx;
    int rc;
    int dont_vary = (info->flags & AP_EXPR_FLAGS_DONT_VARY);
    const char *tmp_source = NULL, *vary_this = NULL;
    ap_regmatch_t tmp_pmatch[10];

    ctx.r = r;
    ctx.c = r->connection;
    ctx.s = r->server;
    ctx.p = r->pool;
    ctx.err  = err;
    ctx.info = info;
    ctx.re_nmatch = nmatch;
    ctx.re_pmatch = pmatch;
    ctx.re_source = source;
    ctx.vary_this = dont_vary ? NULL : &vary_this;

    if (!pmatch) {
        ctx.re_nmatch = 10;
        ctx.re_pmatch = tmp_pmatch;
        ctx.re_source = &tmp_source;
    }
    else {
        AP_DEBUG_ASSERT(source != NULL);
        AP_DEBUG_ASSERT(nmatch > 0);
    }

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

        if (vary_this)
            apr_table_merge(r->headers_out, "Vary", vary_this);

        return rc;
    }
}

static void add_vary(ap_expr_eval_ctx_t *ctx, const char *name)
{
    if (!ctx->vary_this)
        return;

    if (*ctx->vary_this) {
        *ctx->vary_this = apr_pstrcat(ctx->p, *ctx->vary_this, ", ", name,
                                      NULL);
    }
    else {
        *ctx->vary_this = name;
    }
}

static const char *req_table_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                  const char *arg)
{
    const char *name = (const char *)data;
    apr_table_t *t;
    if (!ctx->r)
        return "";

    if (name[2] == 's') {           /* resp */
        /* Try r->headers_out first, fall back on err_headers_out. */
        const char *v = apr_table_get(ctx->r->headers_out, arg);
        if (v) {
            return v;
        }
        t = ctx->r->err_headers_out;
    }        
    else if (name[0] == 'n')        /* notes */
        t = ctx->r->notes;
    else if (name[3] == 'e')        /* reqenv */
        t = ctx->r->subprocess_env;
    else {                          /* req, http */
        t = ctx->r->headers_in;
        add_vary(ctx, arg);
    }
    return apr_table_get(t, arg);
}

static const char *env_func(ap_expr_eval_ctx_t *ctx, const void *data,
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

static const char *osenv_func(ap_expr_eval_ctx_t *ctx, const void *data,
                              const char *arg)
{
    return getenv(arg);
}

static const char *tolower_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                const char *arg)
{
    char *result = apr_pstrdup(ctx->p, arg);
    ap_str_tolower(result);
    return result;
}

static const char *toupper_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                const char *arg)
{
    char *p;
    char *result = apr_pstrdup(ctx->p, arg);

    for (p = result; *p; ++p) {
         *p = apr_toupper(*p);
    }

    return result;
}

static const char *escape_func(ap_expr_eval_ctx_t *ctx, const void *data,
                               const char *arg)
{
    return ap_escape_uri(ctx->p, arg);
}

#define MAX_FILE_SIZE 10*1024*1024
static const char *file_func(ap_expr_eval_ctx_t *ctx, const void *data,
                             char *arg)
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


static const char *unescape_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                 const char *arg)
{
    char *result = apr_pstrdup(ctx->p, arg);
    if (ap_unescape_url(result))
        return "";
    else
        return result;

}

static int op_nz(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
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

static const char *conn_var_fn(ap_expr_eval_ctx_t *ctx, const void *data)
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
    "SCRIPT_USER",              /* 21 */
    "SCRIPT_GROUP",             /* 22 */
    NULL
};

static const char *request_var_fn(ap_expr_eval_ctx_t *ctx, const void *data)
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
    case 21:
        {
            char *result = "";
            if (r->finfo.valid & APR_FINFO_USER)
                apr_uid_name_get(&result, r->finfo.user, ctx->p);
            return result;
        }
    case 22:
        {
            char *result = "";
            if (r->finfo.valid & APR_FINFO_USER)
                apr_gid_name_get(&result, r->finfo.group, ctx->p);
            return result;
        }
    default:
        ap_assert(0);
        return NULL;
    }
}

static const char *req_header_var_names[] = {
    "HTTP_USER_AGENT",
    "HTTP_PROXY_CONNECTION",
    "HTTP_REFERER",
    "HTTP_COOKIE",
    "HTTP_FORWARDED",
    "HTTP_HOST",
    "HTTP_ACCEPT",
    NULL
};

static const char *req_header_header_names[] = {
    "User-Agent",
    "Proxy-Connection",
    "Referer",
    "Cookie",
    "Forwarded",
    "Host",
    "Accept"
};

static const char *req_header_var_fn(ap_expr_eval_ctx_t *ctx, const void *data)
{
    const char **varname = (const char **)data;
    int index = (varname - req_header_var_names);
    const char *name;

    AP_DEBUG_ASSERT(index < 6);
    if (!ctx->r)
        return "";

    name = req_header_header_names[index];
    add_vary(ctx, name);
    return apr_table_get(ctx->r->headers_in, name);
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

static const char *misc_var_fn(ap_expr_eval_ctx_t *ctx, const void *data)
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

static int subnet_parse_arg(ap_expr_lookup_parms *parms)
{
    apr_ipsubnet_t *subnet;
    const char *addr = parms->arg;
    const char *mask;
    apr_status_t ret;

    if (!parms->arg) {
        *parms->err = apr_psprintf(parms->ptemp,
                                   "-%s requires subnet/netmask as constant argument",
                                   parms->name);
        return !OK;
    }

    mask = ap_strchr_c(addr, '/');
    if (mask) {
        addr = apr_pstrmemdup(parms->ptemp, addr, mask - addr);
        mask++;
    }

    ret = apr_ipsubnet_create(&subnet, addr, mask, parms->pool);
    if (ret != APR_SUCCESS) {
        *parms->err = "parsing of subnet/netmask failed";
        return !OK;
    }

    *parms->data = subnet;
    return OK;
}

static int op_ipmatch(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg1,
                const char *arg2)
{
    apr_ipsubnet_t *subnet = (apr_ipsubnet_t *)data;
    apr_sockaddr_t *saddr;

    AP_DEBUG_ASSERT(subnet != NULL);

    /* maybe log an error if this goes wrong? */
    if (apr_sockaddr_info_get(&saddr, arg1, APR_UNSPEC, 0, 0, ctx->p) != APR_SUCCESS)
        return FALSE;

    return apr_ipsubnet_test(subnet, saddr);
}

static int op_R(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg1)
{
    apr_ipsubnet_t *subnet = (apr_ipsubnet_t *)data;

    AP_DEBUG_ASSERT(subnet != NULL);

    if (!ctx->c)
        return FALSE;

    return apr_ipsubnet_test(subnet, ctx->c->remote_addr);
}

static int op_T(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
    switch (arg[0]) {
    case '\0':
        return FALSE;
    case 'o':
    case 'O':
        return strcasecmp(arg, "off") == 0 ? FALSE : TRUE;
    case 'n':
    case 'N':
        return strcasecmp(arg, "no") == 0 ? FALSE : TRUE;
    case 'f':
    case 'F':
        return strcasecmp(arg, "false") == 0 ? FALSE : TRUE;
    case '0':
        return arg[1] == '\0' ? FALSE : TRUE;
    default:
        return TRUE;
    }
}

static int op_fnmatch(ap_expr_eval_ctx_t *ctx, const void *data,
                      const char *arg1, const char *arg2)
{
    return (APR_SUCCESS == apr_fnmatch(arg2, arg1, APR_FNM_PATHNAME));
}

static int op_strmatch(ap_expr_eval_ctx_t *ctx, const void *data,
                       const char *arg1, const char *arg2)
{
    return (APR_SUCCESS == apr_fnmatch(arg2, arg1, 0));
}

static int op_strcmatch(ap_expr_eval_ctx_t *ctx, const void *data,
                        const char *arg1, const char *arg2)
{
    return (APR_SUCCESS == apr_fnmatch(arg2, arg1, APR_FNM_CASE_BLIND));
}

struct expr_provider_single {
    const void *func;
    const char *name;
    ap_expr_lookup_fn_t *arg_parsing_func;
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
    { osenv_func,           "osenv",          NULL },
    { env_func,             "env",            NULL },
    { req_table_func,       "resp",           NULL },
    { req_table_func,       "req",            NULL },
    /* 'http' as alias for 'req' for compatibility with ssl_expr */
    { req_table_func,       "http",           NULL },
    { req_table_func,       "note",           NULL },
    { req_table_func,       "reqenv",         NULL },
    { tolower_func,         "tolower",        NULL },
    { toupper_func,         "toupper",        NULL },
    { escape_func,          "escape",         NULL },
    { unescape_func,        "unescape",       NULL },
    { file_func,            "file",           NULL },
    { NULL, NULL, NULL}
};
/* XXX: base64 encode/decode ? */

static const struct expr_provider_single unary_op_providers[] = {
    { op_nz, "n", NULL },
    { op_nz, "z", NULL },
    { op_R,  "R", subnet_parse_arg },
    { op_T,  "T", NULL },
    { NULL, NULL, NULL }
};

static const struct expr_provider_single binary_op_providers[] = {
    { op_ipmatch,   "ipmatch",      subnet_parse_arg },
    { op_fnmatch,   "fnmatch",      NULL },
    { op_strmatch,  "strmatch",     NULL },
    { op_strcmatch, "strcmatch",    NULL },
    { NULL, NULL, NULL }
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
        }
        break;
    case AP_EXPR_FUNC_STRING:
    case AP_EXPR_FUNC_OP_UNARY:
    case AP_EXPR_FUNC_OP_BINARY: {
            const struct expr_provider_single *prov;
            switch (parms->type) {
            case AP_EXPR_FUNC_STRING:
                prov = string_func_providers;
                break;
            case AP_EXPR_FUNC_OP_UNARY:
                prov = unary_op_providers;
                break;
            case AP_EXPR_FUNC_OP_BINARY:
                prov = binary_op_providers;
                break;
            default:
                ap_assert(0);
            }
            while (prov->func) {
                if (strcasecmp(prov->name, parms->name) == 0) {
                    *parms->func = prov->func;
                    if (prov->arg_parsing_func) {
                        return prov->arg_parsing_func(parms);
                    }
                    else {
                        *parms->data = prov->name;
                        return OK;
                    }
                }
                prov++;
            }
        }
        break;
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

