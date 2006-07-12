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

/**
 * @verbatim
                        _             _
    _ __ ___   ___   __| |    ___ ___| |  mod_ssl
   | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
   | | | | | | (_) | (_| |   \__ \__ \ |
   |_| |_| |_|\___/ \__,_|___|___/___/_|
                        |_____|
 @endverbatim
 *  @file  ssl_expr.h
 *  @brief Expression Handling (Header).
 *         ``May all your PUSHes be POPed.'' 
 * 
 * @defgroup MOD_SSL_EXPR Expression Handling
 * @ingroup MOD_SSL
 * @{
 */

#ifndef __SSL_EXPR_H__
#define __SSL_EXPR_H__

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef YY_NULL
#define YY_NULL 0
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef BOOL
#define BOOL unsigned int
#endif

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef NUL
#define NUL '\0'
#endif

#ifndef YYDEBUG
#define YYDEBUG 0
#endif

typedef enum {
    op_NOP, op_ListElement, op_OidListElement,
    op_True, op_False, op_Not, op_Or, op_And, op_Comp,
    op_EQ, op_NE, op_LT, op_LE, op_GT, op_GE, op_IN, op_REG, op_NRE,
    op_Digit, op_String, op_Regex, op_Var, op_Func
} ssl_expr_node_op;

typedef struct {
    ssl_expr_node_op node_op;
    void *node_arg1;
    void *node_arg2;
    apr_pool_t *p;
} ssl_expr_node;

typedef ssl_expr_node ssl_expr;

typedef struct {
	apr_pool_t *pool;
    char     *inputbuf;
    int       inputlen;
    char     *inputptr;
    ssl_expr *expr;
} ssl_expr_info_type;

extern ssl_expr_info_type ssl_expr_info;
extern char *ssl_expr_error;

#define yylval  ssl_expr_yylval
#define yyerror ssl_expr_yyerror
#define yyinput ssl_expr_yyinput

extern int ssl_expr_yyparse(void);
extern int ssl_expr_yyerror(char *);
extern int ssl_expr_yylex(void);

extern ssl_expr *ssl_expr_comp(apr_pool_t *, char *);
extern int       ssl_expr_exec(request_rec *, ssl_expr *);
extern char     *ssl_expr_get_error(void);
extern ssl_expr *ssl_expr_make(ssl_expr_node_op, void *, void *);
extern BOOL      ssl_expr_eval(request_rec *, ssl_expr *);

#endif /* __SSL_EXPR_H__ */
/** @} */

