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
 *  _ __ ___   ___   __| |    ___ ___| |  
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  
 * | | | | | | (_) | (_| |   \__ \__ \ | mod_ssl - Apache Interface to OpenSSL
 * |_| |_| |_|\___/ \__,_|___|___/___/_| http://www.modssl.org/
 *                      |_____|         
 *  ssl_expr_parse.y
 *  Expression LR(1) Parser
 */
                             /* ``What you see is all you get.''
							              -- Brian Kernighan      */

/*  _________________________________________________________________
**
**  Expression Parser
**  _________________________________________________________________
*/

%{
#include "ssl_private.h"
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
%token  T_OP_OID

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
%type   <exVal>   wordlist
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
          | word T_OP_IN wordlist        { $$ = ssl_expr_make(op_IN,  $1, $3); }
          | word T_OP_REG regex          { $$ = ssl_expr_make(op_REG, $1, $3); }
          | word T_OP_NRE regex          { $$ = ssl_expr_make(op_NRE, $1, $3); }
          ;

wordlist  : T_OP_OID '(' word ')'	 { $$ = ssl_expr_make(op_OidListElement, $3, NULL); }
          | '{' words '}'                { $$ = $2 ; }
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
                ap_regex_t *regex;
                if ((regex = ap_pregcomp(ssl_expr_info.pool, $1, 
                                         AP_REG_EXTENDED|AP_REG_NOSUB)) == NULL) {
                    ssl_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = ssl_expr_make(op_Regex, regex, NULL);
            }
          | T_REGEX_I {
                ap_regex_t *regex;
                if ((regex = ap_pregcomp(ssl_expr_info.pool, $1, 
                                         AP_REG_EXTENDED|AP_REG_NOSUB|AP_REG_ICASE)) == NULL) {
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

