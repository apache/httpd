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

#ifndef __AP_EXPR_PRIVATE_H__
#define __AP_EXPR_PRIVATE_H__

#include "httpd.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "ap_expr.h"

#ifndef YY_NULL
#define YY_NULL 0
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#if !APR_HAVE_UNISTD_H
#define YY_NO_UNISTD_H
#endif

#ifdef _MSC_VER
/* Avoid some warnings with Visual Studio (likely due to a bug in bison) */
#define YYMALLOC malloc
#define YYFREE   free
#endif

#ifndef YYDEBUG
#define YYDEBUG 0
#endif

/** The operations in a parse tree node */
typedef enum {
    op_NOP,
    op_True, op_False,
    op_Not, op_Or, op_And,
    op_Comp,
    op_EQ, op_NE, op_LT, op_LE, op_GT, op_GE, op_IN,
    op_REG, op_NRE,
    op_STR_EQ, op_STR_NE, op_STR_LT, op_STR_LE, op_STR_GT, op_STR_GE,
    op_Concat,
    op_Digit, op_String, op_Regex, op_RegexBackref,
    op_Var,
    op_ListElement,
    /*
     * call external functions/operators.
     * The info node contains the function pointer and some function specific
     * info.
     * For Binary operators, the Call node links to the Info node and the
     * Args node, which in turn links to the left and right operand.
     * For all other variants, the Call node links to the Info node and the
     * argument.
     */
    op_UnaryOpCall, op_UnaryOpInfo,
    op_BinaryOpCall, op_BinaryOpInfo, op_BinaryOpArgs,
    op_StringFuncCall, op_StringFuncInfo,
    op_ListFuncCall, op_ListFuncInfo
} ap_expr_node_op_e;

/** The basic parse tree node */
struct ap_expr_node {
    ap_expr_node_op_e node_op;
    const void *node_arg1;
    const void *node_arg2;
};

/** The context used by scanner and parser */
typedef struct {
    /* internal state of the scanner */
    const char        *inputbuf;
    int                inputlen;
    const char        *inputptr;
    void              *scanner;
    char              *scan_ptr;
    char               scan_buf[MAX_STRING_LEN];
    char               scan_del;
    int                at_start;

    /* pools for result and temporary usage */
    apr_pool_t        *pool;
    apr_pool_t        *ptemp;

    /* The created parse tree */
    ap_expr_t         *expr;

    const char        *error;
    const char        *error2;
    unsigned           flags;

    /*
     * The function to use to lookup provider functions for variables
     * and funtctions
     */
    ap_expr_lookup_fn_t *lookup_fn;
} ap_expr_parse_ctx_t;

/* flex/bison functions */
int  ap_expr_yyparse(ap_expr_parse_ctx_t *context);
void ap_expr_yyerror(ap_expr_parse_ctx_t *context, const char *err);
int  ap_expr_yylex_init(void **scanner);
int  ap_expr_yylex_destroy(void *scanner);
void ap_expr_yyset_extra(ap_expr_parse_ctx_t *context, void *scanner);

/* create a parse tree node */
ap_expr_t *ap_expr_make(ap_expr_node_op_e op, const void *arg1,
                        const void *arg2, ap_expr_parse_ctx_t *ctx);
/* create parse tree node for the string-returning function 'name' */
ap_expr_t *ap_expr_str_func_make(const char *name, const ap_expr_t *arg,
                               ap_expr_parse_ctx_t *ctx);
/* create parse tree node for the list-returning function 'name' */
ap_expr_t *ap_expr_list_func_make(const char *name, const ap_expr_t *arg,
                                ap_expr_parse_ctx_t *ctx);
/* create parse tree node for the variable 'name' */
ap_expr_t *ap_expr_var_make(const char *name, ap_expr_parse_ctx_t *ctx);
/* create parse tree node for the unary operator 'name' */
ap_expr_t *ap_expr_unary_op_make(const char *name, const ap_expr_t *arg,
                               ap_expr_parse_ctx_t *ctx);
/* create parse tree node for the binary operator 'name' */
ap_expr_t *ap_expr_binary_op_make(const char *name, const ap_expr_t *arg1,
                                  const ap_expr_t *arg2,
                                  ap_expr_parse_ctx_t *ctx);


#endif /* __AP_EXPR_PRIVATE_H__ */
/** @} */

