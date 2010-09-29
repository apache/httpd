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
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_expr.c
 *  Expression Handling
 */
                             /* ``It is hard to fly with
                                  the eagles when you work
                                  with the turkeys.''
                                          -- Unknown  */
#include "ssl_private.h"

/*  _________________________________________________________________
**
**  Expression Handling
**  _________________________________________________________________
*/


ssl_expr *ssl_expr_comp(apr_pool_t *p, const char *expr, const char **err)
{
    ssl_expr_info_type context;
    int rc;

    context.pool     = p;
    context.inputbuf = expr;
    context.inputlen = strlen(expr);
    context.inputptr = context.inputbuf;
    context.expr     = FALSE;
    context.error    = NULL;

    ssl_expr_yylex_init(&context.scanner);
    ssl_expr_yyset_extra(&context, context.scanner);
    rc = ssl_expr_yyparse(&context);
    ssl_expr_yylex_destroy(context.scanner);
    *err = context.error;

    if (rc)
        return NULL;

    return context.expr;
}

ssl_expr *ssl_expr_make(ssl_expr_node_op op, void *a1, void *a2,
                        ssl_expr_info_type *context)
{
    ssl_expr *node;

    node = (ssl_expr *)apr_palloc(context->pool, sizeof(ssl_expr));
    node->node_op   = op;
    node->node_arg1 = (char *)a1;
    node->node_arg2 = (char *)a2;
    return node;
}

int ssl_expr_exec(request_rec *r, const ssl_expr *expr, const char **err)
{
    BOOL rc;

    *err = NULL;
    rc = ssl_expr_eval(r, expr, err);
    if (*err != NULL)
        return (-1);
    else
        return (rc ? 1 : 0);
}
