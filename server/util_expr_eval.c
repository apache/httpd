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
#include "http_request.h"
#include "ap_provider.h"
#include "util_expr_private.h"
#include "util_md5.h"

#include "apr_lib.h"
#include "apr_fnmatch.h"
#include "apr_base64.h"
#include "apr_sha1.h"

#include <limits.h>     /* for INT_MAX */

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

APR_HOOK_STRUCT(
    APR_HOOK_LINK(expr_lookup)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int, expr_lookup, (ap_expr_lookup_parms *parms),
                            (parms), DECLINED)

#define  LOG_MARK(info)  __FILE__, __LINE__, (info)->module_index

static const char *ap_expr_eval_string_func(ap_expr_eval_ctx_t *ctx,
                                            const ap_expr_t *info,
                                            const ap_expr_t *args);
static const char *ap_expr_eval_re_backref(ap_expr_eval_ctx_t *ctx,
                                           unsigned int n);
static const char *ap_expr_eval_var(ap_expr_eval_ctx_t *ctx,
                                    ap_expr_var_func_t *func,
                                    const void *data);

/* define AP_EXPR_DEBUG to log the parse tree when parsing an expression */
#ifdef AP_EXPR_DEBUG
static void expr_dump_tree(const ap_expr_t *e, const server_rec *s,
                           int loglevel, int indent);
#endif

/*
 * To reduce counting overhead, we only count calls to
 * ap_expr_eval_word() and ap_expr_eval(). The max number of
 * stack frames is larger by some factor.
 */
#define AP_EXPR_MAX_RECURSION   20
static int inc_rec(ap_expr_eval_ctx_t *ctx)
{
    if (ctx->reclvl < AP_EXPR_MAX_RECURSION) {
        ctx->reclvl++;
        return 0;
    }
    *ctx->err = "Recursion limit reached";
    /* short circuit further evaluation */
    ctx->reclvl = INT_MAX;
    return 1;
}

static const char *ap_expr_eval_word(ap_expr_eval_ctx_t *ctx,
                                     const ap_expr_t *node)
{
    const char *result = "";
    if (inc_rec(ctx))
        return result;
    switch (node->node_op) {
    case op_Digit:
    case op_String:
        result = node->node_arg1;
        break;
    case op_Var:
        result = ap_expr_eval_var(ctx, (ap_expr_var_func_t *)node->node_arg1,
                                  node->node_arg2);
        break;
    case op_Concat:
        if (((ap_expr_t *)node->node_arg2)->node_op != op_Concat) {
            const char *s1 = ap_expr_eval_word(ctx, node->node_arg1);
            const char *s2 = ap_expr_eval_word(ctx, node->node_arg2);
            if (!*s1)
                result = s2;
            else if (!*s2)
                result = s1;
            else
                result = apr_pstrcat(ctx->p, s1, s2, NULL);
        }
        else {
            const ap_expr_t *nodep = node;
            int i = 1;
            struct iovec *vec;
            do {
                nodep = nodep->node_arg2;
                i++;
            } while (nodep->node_op == op_Concat);
            vec = apr_palloc(ctx->p, i * sizeof(struct iovec));
            nodep = node;
            i = 0;
            do {
                vec[i].iov_base = (void *)ap_expr_eval_word(ctx,
                                                            nodep->node_arg1);
                vec[i].iov_len = strlen(vec[i].iov_base);
                i++;
                nodep = nodep->node_arg2;
            } while (nodep->node_op == op_Concat);
            vec[i].iov_base = (void *)ap_expr_eval_word(ctx, nodep);
            vec[i].iov_len = strlen(vec[i].iov_base);
            i++;
            result = apr_pstrcatv(ctx->p, vec, i, NULL);
        }
        break;
    case op_StringFuncCall: {
        const ap_expr_t *info = node->node_arg1;
        const ap_expr_t *args = node->node_arg2;
        result = ap_expr_eval_string_func(ctx, info, args);
        break;
    }
    case op_RegexBackref: {
        const unsigned int *np = node->node_arg1;
        result = ap_expr_eval_re_backref(ctx, *np);
        break;
    }
    default:
        *ctx->err = "Internal evaluation error: Unknown word expression node";
        break;
    }
    if (!result)
        result = "";
    ctx->reclvl--;
    return result;
}

static const char *ap_expr_eval_var(ap_expr_eval_ctx_t *ctx,
                                    ap_expr_var_func_t *func,
                                    const void *data)
{
    AP_DEBUG_ASSERT(func != NULL);
    AP_DEBUG_ASSERT(data != NULL);
    return (*func)(ctx, data);
}

static const char *ap_expr_eval_re_backref(ap_expr_eval_ctx_t *ctx, unsigned int n)
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
    ctx.at_start    = 1;

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

AP_DECLARE(ap_expr_info_t*) ap_expr_parse_cmd_mi(const cmd_parms *cmd,
                                                 const char *expr,
                                                 unsigned int flags,
                                                 const char **err,
                                                 ap_expr_lookup_fn_t *lookup_fn,
                                                 int module_index)
{
    ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
    info->filename = cmd->directive->filename;
    info->line_number = cmd->directive->line_num;
    info->flags = flags;
    info->module_index = module_index;
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
    parms.flags = ctx->flags;
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
    ap_expr_op_unary_t *op_func = (ap_expr_op_unary_t *)info->node_arg1;
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
    ap_expr_op_binary_t *op_func = (ap_expr_op_binary_t *)info->node_arg1;
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
    int result = FALSE;
    if (inc_rec(ctx))
        return result;
    while (1) {
        switch (node->node_op) {
        case op_True:
            result ^= TRUE;
            goto out;
        case op_False:
            result ^= FALSE;
            goto out;
        case op_Not:
            result = !result;
            node = e1;
            break;
        case op_Or:
            do {
                if (e1->node_op == op_Not) {
                    if (!ap_expr_eval(ctx, e1->node_arg1)) {
                        result ^= TRUE;
                        goto out;
                    }
                }
                else {
                    if (ap_expr_eval(ctx, e1)) {
                        result ^= TRUE;
                        goto out;
                    }
                }
                node = node->node_arg2;
                e1 = node->node_arg1;
            } while (node->node_op == op_Or);
            break;
        case op_And:
            do {
                if (e1->node_op == op_Not) {
                    if (ap_expr_eval(ctx, e1->node_arg1)) {
                        result ^= FALSE;
                        goto out;
                    }
                }
                else {
                    if (!ap_expr_eval(ctx, e1)) {
                        result ^= FALSE;
                        goto out;
                    }
                }
                node = node->node_arg2;
                e1 = node->node_arg1;
            } while (node->node_op == op_And);
            break;
        case op_UnaryOpCall:
            result ^= ap_expr_eval_unary_op(ctx, e1, e2);
            goto out;
        case op_BinaryOpCall:
            result ^= ap_expr_eval_binary_op(ctx, e1, e2);
            goto out;
        case op_Comp:
            if (ctx->info->flags & AP_EXPR_FLAG_SSL_EXPR_COMPAT)
                result ^= ssl_expr_eval_comp(ctx, e1);
            else
                result ^= ap_expr_eval_comp(ctx, e1);
            goto out;
        default:
            *ctx->err = "Internal evaluation error: Unknown expression node";
            goto out;
        }
        e1 = node->node_arg1;
        e2 = node->node_arg2;
    }
out:
    ctx->reclvl--;
    return result;
}

AP_DECLARE(int) ap_expr_exec(request_rec *r, const ap_expr_info_t *info,
                             const char **err)
{
    return ap_expr_exec_re(r, info, 0, NULL, NULL, err);
}

AP_DECLARE(int) ap_expr_exec_ctx(ap_expr_eval_ctx_t *ctx)
{
    int rc;

    AP_DEBUG_ASSERT(ctx->p != NULL);
    /* XXX: allow r, c == NULL */
    AP_DEBUG_ASSERT(ctx->r != NULL);
    AP_DEBUG_ASSERT(ctx->c != NULL);
    AP_DEBUG_ASSERT(ctx->s != NULL);
    AP_DEBUG_ASSERT(ctx->err != NULL);
    AP_DEBUG_ASSERT(ctx->info != NULL);
    if (ctx->re_pmatch) {
        AP_DEBUG_ASSERT(ctx->re_source != NULL);
        AP_DEBUG_ASSERT(ctx->re_nmatch > 0);
    }
    ctx->reclvl = 0;

    *ctx->err = NULL;
    if (ctx->info->flags & AP_EXPR_FLAG_STRING_RESULT) {
        *ctx->result_string = ap_expr_eval_word(ctx, ctx->info->root_node);
        if (*ctx->err != NULL) {
            ap_log_rerror(LOG_MARK(ctx->info), APLOG_ERR, 0, ctx->r,
                          "Evaluation of expression from %s:%d failed: %s",
                          ctx->info->filename, ctx->info->line_number, *ctx->err);
            return -1;
        } else {
            ap_log_rerror(LOG_MARK(ctx->info), APLOG_TRACE4, 0, ctx->r,
                          "Evaluation of string expression from %s:%d gave: %s",
                          ctx->info->filename, ctx->info->line_number,
                          *ctx->result_string);
            return 1;
        }
    }
    else {
        rc = ap_expr_eval(ctx, ctx->info->root_node);
        if (*ctx->err != NULL) {
            ap_log_rerror(LOG_MARK(ctx->info), APLOG_ERR, 0, ctx->r,
                          "Evaluation of expression from %s:%d failed: %s",
                          ctx->info->filename, ctx->info->line_number, *ctx->err);
            return -1;
        } else {
            rc = rc ? 1 : 0;
            ap_log_rerror(LOG_MARK(ctx->info), APLOG_TRACE4, 0, ctx->r,
                          "Evaluation of expression from %s:%d gave: %d",
                          ctx->info->filename, ctx->info->line_number, rc);

            if (ctx->vary_this && *ctx->vary_this)
                apr_table_merge(ctx->r->headers_out, "Vary", *ctx->vary_this);

            return rc;
        }
    }
}

AP_DECLARE(int) ap_expr_exec_re(request_rec *r, const ap_expr_info_t *info,
                                apr_size_t nmatch, ap_regmatch_t *pmatch,
                                const char **source, const char **err)
{
    ap_expr_eval_ctx_t ctx;
    int dont_vary = (info->flags & AP_EXPR_FLAG_DONT_VARY);
    const char *tmp_source = NULL, *vary_this = NULL;
    ap_regmatch_t tmp_pmatch[AP_MAX_REG_MATCH];

    AP_DEBUG_ASSERT((info->flags & AP_EXPR_FLAG_STRING_RESULT) == 0);

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
    ctx.data = NULL;

    if (!pmatch) {
        ctx.re_nmatch = AP_MAX_REG_MATCH;
        ctx.re_pmatch = tmp_pmatch;
        ctx.re_source = &tmp_source;
    }

    return ap_expr_exec_ctx(&ctx);
}

AP_DECLARE(const char *) ap_expr_str_exec_re(request_rec *r,
                                             const ap_expr_info_t *info,
                                             apr_size_t nmatch,
                                             ap_regmatch_t *pmatch,
                                             const char **source,
                                             const char **err)
{
    ap_expr_eval_ctx_t ctx;
    int dont_vary, rc;
    const char *tmp_source = NULL, *vary_this = NULL;
    ap_regmatch_t tmp_pmatch[AP_MAX_REG_MATCH];
    const char *result;

    AP_DEBUG_ASSERT(info->flags & AP_EXPR_FLAG_STRING_RESULT);

    if (info->root_node->node_op == op_String) {
        /* short-cut for constant strings */
        *err = NULL;
        return (const char *)info->root_node->node_arg1;
    }

    dont_vary = (info->flags & AP_EXPR_FLAG_DONT_VARY);

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
    ctx.data = NULL;
    ctx.result_string = &result;

    if (!pmatch) {
        ctx.re_nmatch = AP_MAX_REG_MATCH;
        ctx.re_pmatch = tmp_pmatch;
        ctx.re_source = &tmp_source;
    }

    rc = ap_expr_exec_ctx(&ctx);
    if (rc > 0)
        return result;
    else if (rc < 0)
        return NULL;
    else
        ap_assert(0);
    /* Not reached */
    return NULL;
}

AP_DECLARE(const char *) ap_expr_str_exec(request_rec *r,
                                          const ap_expr_info_t *info,
                                          const char **err)
{
    return ap_expr_str_exec_re(r, info, 0, NULL, NULL, err);
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
    else if (name[3] == '_')        /* req_novary */
        t = ctx->r->headers_in;
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
    char *result = apr_pstrdup(ctx->p, arg);
    ap_str_toupper(result);
    return result;
}

static const char *escape_func(ap_expr_eval_ctx_t *ctx, const void *data,
                               const char *arg)
{
    return ap_escape_uri(ctx->p, arg);
}

static const char *base64_func(ap_expr_eval_ctx_t *ctx, const void *data,
                               const char *arg)
{
    return ap_pbase64encode(ctx->p, (char *)arg);
}

static const char *unbase64_func(ap_expr_eval_ctx_t *ctx, const void *data,
                               const char *arg)
{
    return ap_pbase64decode(ctx->p, arg);
}

static const char *sha1_func(ap_expr_eval_ctx_t *ctx, const void *data,
                               const char *arg)
{
    apr_sha1_ctx_t context;
    apr_byte_t sha1[APR_SHA1_DIGESTSIZE];
    char *out;

    out = apr_palloc(ctx->p, APR_SHA1_DIGESTSIZE*2+1);

    apr_sha1_init(&context);
    apr_sha1_update(&context, arg, strlen(arg));
    apr_sha1_final(sha1, &context);

    ap_bin2hex(sha1, APR_SHA1_DIGESTSIZE, out);

    return out;
}

static const char *md5_func(ap_expr_eval_ctx_t *ctx, const void *data,
                               const char *arg)
{
	return ap_md5(ctx->p, (const unsigned char *)arg);
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

static const char *filesize_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                  char *arg)
{
    apr_finfo_t sb;
    if (apr_stat(&sb, arg, APR_FINFO_MIN, ctx->p) == APR_SUCCESS
        && sb.filetype == APR_REG && sb.size > 0)
        return apr_psprintf(ctx->p, "%" APR_OFF_T_FMT, sb.size);
    else
        return "0";
}

static const char *unescape_func(ap_expr_eval_ctx_t *ctx, const void *data,
                                 const char *arg)
{
    char *result = apr_pstrdup(ctx->p, arg);
    int ret = ap_unescape_url_keep2f(result, 0);
    if (ret == OK)
        return result;
    ap_log_rerror(LOG_MARK(ctx->info), APLOG_DEBUG, 0, ctx->r, APLOGNO(00538)
                  "%s %% escape in unescape('%s') at %s:%d",
                  ret == HTTP_BAD_REQUEST ? "Bad" : "Forbidden", arg,
                  ctx->info->filename, ctx->info->line_number);
    return "";
}

static int op_nz(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
    const char *name = (const char *)data;
    if (name[0] == 'z')
        return (arg[0] == '\0');
    else
        return (arg[0] != '\0');
}

static int op_file_min(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
    apr_finfo_t sb;
    const char *name = (const char *)data;
    if (apr_stat(&sb, arg, APR_FINFO_MIN, ctx->p) != APR_SUCCESS)
        return FALSE;
    switch (name[0]) {
    case 'd':
        return (sb.filetype == APR_DIR);
    case 'e':
        return TRUE;
    case 'f':
        return (sb.filetype == APR_REG);
    case 's':
        return (sb.filetype == APR_REG && sb.size > 0);
    default:
        ap_assert(0);
    }
    return FALSE;
}

static int op_file_link(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
#if !defined(OS2)
    apr_finfo_t sb;
    if (apr_stat(&sb, arg, APR_FINFO_MIN | APR_FINFO_LINK, ctx->p) == APR_SUCCESS
        && sb.filetype == APR_LNK) {
        return TRUE;
    }
#endif
    return FALSE;
}

static int op_file_xbit(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
    apr_finfo_t sb;
    if (apr_stat(&sb, arg, APR_FINFO_PROT| APR_FINFO_LINK, ctx->p) == APR_SUCCESS
        && (sb.protection & (APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE))) {
        return TRUE;
    }
    return FALSE;
}

static int op_url_subr(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
    int rc = FALSE;
    request_rec  *rsub, *r = ctx->r;
    if (!r)
        return FALSE;
    /* avoid some infinite recursions */
    if (r->main && r->main->uri && r->uri && strcmp(r->main->uri, r->uri) == 0)
        return FALSE;

    rsub = ap_sub_req_lookup_uri(arg, r, NULL);
    if (rsub->status < 400) {
            rc = TRUE;
    }
    ap_log_rerror(LOG_MARK(ctx->info), APLOG_TRACE5, 0, r,
                  "Subrequest for -U %s at %s:%d gave status: %d",
                  arg, ctx->info->filename, ctx->info->line_number,
                  rsub->status);
    ap_destroy_sub_req(rsub);
    return rc;
}

static int op_file_subr(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
{
    int rc = FALSE;
    apr_finfo_t sb;
    request_rec *rsub, *r = ctx->r;
    if (!r)
        return FALSE;
    rsub = ap_sub_req_lookup_file(arg, r, NULL);
    if (rsub->status < 300 &&
        /* double-check that file exists since default result is 200 */
        apr_stat(&sb, rsub->filename, APR_FINFO_MIN, ctx->p) == APR_SUCCESS) {
        rc = TRUE;
    }
    ap_log_rerror(LOG_MARK(ctx->info), APLOG_TRACE5, 0, r,
                  "Subrequest for -F %s at %s:%d gave status: %d",
                  arg, ctx->info->filename, ctx->info->line_number,
                  rsub->status);
    ap_destroy_sub_req(rsub);
    return rc;
}


APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *is_https = NULL;

static const char *conn_var_names[] = {
    "HTTPS",                    /*  0 */
    "IPV6",                     /*  1 */
    "CONN_LOG_ID",              /*  2 */
    "CONN_REMOTE_ADDR",         /*  3 */
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
        if (is_https && is_https(c))
            return "on";
        else
            return "off";
    case 1:
#if APR_HAVE_IPV6
        {
            apr_sockaddr_t *addr = c->client_addr;
            if (addr->family == AF_INET6
                && !IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr->ipaddr_ptr))
                return "on";
            else
                return "off";
        }
#else
        return "off";
#endif
    case 2:
        return c->log_id;
    case 3:
        return c->client_ip;
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
    "DOCUMENT_URI",             /* 23 */
    "LAST_MODIFIED",            /* 24 */
    "CONTEXT_PREFIX",           /* 25 */
    "CONTEXT_DOCUMENT_ROOT",    /* 26 */
    "REQUEST_STATUS",           /* 27 */
    "REMOTE_ADDR",              /* 28 */
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
        return ap_get_server_name_for_url(r);
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
    case 23:
        return r->uri;
    case 24:
        {
            apr_time_exp_t tm;
            apr_time_exp_lt(&tm, r->mtime);
            return apr_psprintf(ctx->p, "%02d%02d%02d%02d%02d%02d%02d",
                                (tm.tm_year / 100) + 19, (tm.tm_year % 100),
                                tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min,
                                tm.tm_sec);
        }
    case 25:
        return ap_context_prefix(r);
    case 26:
        return ap_context_document_root(r);
    case 27:
        return r->status ? apr_psprintf(ctx->p, "%d", r->status) : "";
    case 28:
        return r->useragent_ip;
    default:
        ap_assert(0);
        return NULL;
    }
}

static const char *req_header_var_names[] = {
    "HTTP_USER_AGENT",       /* 0 */
    "HTTP_PROXY_CONNECTION", /* 1 */
    "HTTP_REFERER",          /* 2 */
    "HTTP_COOKIE",           /* 3 */
    "HTTP_FORWARDED",        /* 4 */
    "HTTP_HOST",             /* 5 */
    "HTTP_ACCEPT",           /* 6 */
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

    AP_DEBUG_ASSERT(index < 7);
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

    if (!ctx->r)
        return FALSE;

    return apr_ipsubnet_test(subnet, ctx->r->useragent_addr);
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
    int restricted;
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
    { osenv_func,           "osenv",          NULL, 0 },
    { env_func,             "env",            NULL, 0 },
    { req_table_func,       "resp",           NULL, 0 },
    { req_table_func,       "req",            NULL, 0 },
    /* 'http' as alias for 'req' for compatibility with ssl_expr */
    { req_table_func,       "http",           NULL, 0 },
    { req_table_func,       "note",           NULL, 0 },
    { req_table_func,       "reqenv",         NULL, 0 },
    { req_table_func,       "req_novary",     NULL, 0 },
    { tolower_func,         "tolower",        NULL, 0 },
    { toupper_func,         "toupper",        NULL, 0 },
    { escape_func,          "escape",         NULL, 0 },
    { unescape_func,        "unescape",       NULL, 0 },
    { file_func,            "file",           NULL, 1 },
    { filesize_func,        "filesize",       NULL, 1 },
    { base64_func,          "base64",         NULL, 0 },
    { unbase64_func,        "unbase64",       NULL, 0 },
    { sha1_func,            "sha1",           NULL, 0 },
    { md5_func,             "md5",            NULL, 0 },
    { NULL, NULL, NULL}
};

static const struct expr_provider_single unary_op_providers[] = {
    { op_nz,        "n", NULL,             0 },
    { op_nz,        "z", NULL,             0 },
    { op_R,         "R", subnet_parse_arg, 0 },
    { op_T,         "T", NULL,             0 },
    { op_file_min,  "d", NULL,             1 },
    { op_file_min,  "e", NULL,             1 },
    { op_file_min,  "f", NULL,             1 },
    { op_file_min,  "s", NULL,             1 },
    { op_file_link, "L", NULL,             1 },
    { op_file_link, "h", NULL,             1 },
    { op_file_xbit, "x", NULL,             1 },
    { op_file_subr, "F", NULL,             0 },
    { op_url_subr,  "U", NULL,             0 },
    { op_url_subr,  "A", NULL,             0 },
    { NULL, NULL, NULL }
};

static const struct expr_provider_single binary_op_providers[] = {
    { op_ipmatch,   "ipmatch",      subnet_parse_arg, 0 },
    { op_fnmatch,   "fnmatch",      NULL,             0 },
    { op_strmatch,  "strmatch",     NULL,             0 },
    { op_strcmatch, "strcmatch",    NULL,             0 },
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
                int match;
                if (parms->type == AP_EXPR_FUNC_OP_UNARY)
                    match = !strcmp(prov->name, parms->name);
                else
                    match = !strcasecmp(prov->name, parms->name);
                if (match) {
                    if ((parms->flags & AP_EXPR_FLAG_RESTRICTED)
                        && prov->restricted) {
                        *parms->err =
                            apr_psprintf(parms->ptemp,
                                         "%s%s not available in restricted context",
                                         (parms->type == AP_EXPR_FUNC_STRING) ? "" : "-",
                                         prov->name);
                        return !OK;
                    }
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
    const char *prefix = "";

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
    if (   parms->type == AP_EXPR_FUNC_OP_UNARY
        || parms->type == AP_EXPR_FUNC_OP_BINARY) {
        prefix = "-";
    }
    *parms->err = apr_psprintf(parms->ptemp, "%s '%s%s' does not exist", type,
                               prefix, parms->name);
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

