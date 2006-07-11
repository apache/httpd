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

ssl_expr_info_type ssl_expr_info;
char              *ssl_expr_error;

ssl_expr *ssl_expr_comp(apr_pool_t *p, char *expr)
{
    ssl_expr_info.pool       = p;
    ssl_expr_info.inputbuf   = expr;
    ssl_expr_info.inputlen   = strlen(expr);
    ssl_expr_info.inputptr   = ssl_expr_info.inputbuf;
    ssl_expr_info.expr       = FALSE;

    ssl_expr_error = NULL;
    if (ssl_expr_yyparse())
        return NULL;
    return ssl_expr_info.expr;
}

char *ssl_expr_get_error(void)
{
    if (ssl_expr_error == NULL)
        return "";
    return ssl_expr_error;
}

ssl_expr *ssl_expr_make(ssl_expr_node_op op, void *a1, void *a2)
{
    ssl_expr *node;

    node = (ssl_expr *)apr_palloc(ssl_expr_info.pool, sizeof(ssl_expr));
    node->node_op   = op;
    node->node_arg1 = (char *)a1;
    node->node_arg2 = (char *)a2;
    return node;
}

int ssl_expr_exec(request_rec *r, ssl_expr *expr)
{
    BOOL rc;

    rc = ssl_expr_eval(r, expr);
    if (ssl_expr_error != NULL)
        return (-1);
    else
        return (rc ? 1 : 0);
}
