/*                      _             _ 
**  _ __ ___   ___   __| |    ___ ___| |  
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  
** | | | | | | (_) | (_| |   \__ \__ \ | mod_ssl - Apache Interface to OpenSSL
** |_| |_| |_|\___/ \__,_|___|___/___/_| http://www.modssl.org/
**                      |_____|         
**  ssl_expr_parse.y
**  Expression LR(1) Parser
*/

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */
                             /* ``What you see is all you get.''
							              -- Brian Kernighan      */

/*  _________________________________________________________________
**
**  Expression Parser
**  _________________________________________________________________
*/

%{
#include "mod_ssl.h"
%}

%union {
    char     *cpVal;
    ssl_expr *exVal;
}

%token  T_TRUE
%token  T_FALSE

%token  <cpVal> T_DIGIT
%token  <cpVal> T_ID
%token  <cpVal> T_STRING
%token  <cpVal> T_REGEX
%token  <cpVal> T_REGEX_I

%token  T_FUNC_FILE

%token  T_OP_EQ
%token  T_OP_NE
%token  T_OP_LT
%token  T_OP_LE
%token  T_OP_GT
%token  T_OP_GE
%token  T_OP_REG
%token  T_OP_NRE
%token  T_OP_IN

%token  T_OP_OR
%token  T_OP_AND
%token  T_OP_NOT

%left   T_OP_OR
%left   T_OP_AND
%left   T_OP_NOT

%type   <exVal>   expr
%type   <exVal>   comparison
%type   <exVal>   funccall
%type   <exVal>   regex
%type   <exVal>   words
%type   <exVal>   word

%%

root      : expr                         { ssl_expr_info.expr = $1; }
          ;

expr      : T_TRUE                       { $$ = ssl_expr_make(op_True,  NULL, NULL); }
          | T_FALSE                      { $$ = ssl_expr_make(op_False, NULL, NULL); }
          | T_OP_NOT expr                { $$ = ssl_expr_make(op_Not,   $2,   NULL); }
          | expr T_OP_OR expr            { $$ = ssl_expr_make(op_Or,    $1,   $3);   }
          | expr T_OP_AND expr           { $$ = ssl_expr_make(op_And,   $1,   $3);   }
          | comparison                   { $$ = ssl_expr_make(op_Comp,  $1,   NULL); }
          | '(' expr ')'                 { $$ = $2; }
          ;

comparison: word T_OP_EQ word            { $$ = ssl_expr_make(op_EQ,  $1, $3); }
          | word T_OP_NE word            { $$ = ssl_expr_make(op_NE,  $1, $3); }
          | word T_OP_LT word            { $$ = ssl_expr_make(op_LT,  $1, $3); }
          | word T_OP_LE word            { $$ = ssl_expr_make(op_LE,  $1, $3); }
          | word T_OP_GT word            { $$ = ssl_expr_make(op_GT,  $1, $3); }
          | word T_OP_GE word            { $$ = ssl_expr_make(op_GE,  $1, $3); }
          | word T_OP_IN '{' words '}'   { $$ = ssl_expr_make(op_IN,  $1, $4); }
          | word T_OP_REG regex          { $$ = ssl_expr_make(op_REG, $1, $3); }
          | word T_OP_NRE regex          { $$ = ssl_expr_make(op_NRE, $1, $3); }
          ;

words     : word                         { $$ = ssl_expr_make(op_ListElement, $1, NULL); }
          | words ',' word               { $$ = ssl_expr_make(op_ListElement, $3, $1);   }
          ;

word      : T_DIGIT                      { $$ = ssl_expr_make(op_Digit,  $1, NULL); }
          | T_STRING                     { $$ = ssl_expr_make(op_String, $1, NULL); }
          | '%' '{' T_ID '}'             { $$ = ssl_expr_make(op_Var,    $3, NULL); }
          | funccall                     { $$ = $1; }
          ;

regex     : T_REGEX { 
                regex_t *regex;
                if ((regex = ap_pregcomp(ssl_expr_info.pool, $1, 
                                         REG_EXTENDED|REG_NOSUB)) == NULL) {
                    ssl_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = ssl_expr_make(op_Regex, regex, NULL);
            }
          | T_REGEX_I {
                regex_t *regex;
                if ((regex = ap_pregcomp(ssl_expr_info.pool, $1, 
                                         REG_EXTENDED|REG_NOSUB|REG_ICASE)) == NULL) {
                    ssl_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = ssl_expr_make(op_Regex, regex, NULL);
            }
          ;

funccall  : T_FUNC_FILE '(' T_STRING ')' { 
               ssl_expr *args = ssl_expr_make(op_ListElement, $3, NULL);
               $$ = ssl_expr_make(op_Func, "file", args);
            }
          ;

%%

int yyerror(char *s)
{
    ssl_expr_error = s;
    return 2;
}

