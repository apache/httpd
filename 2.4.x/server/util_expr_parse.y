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

/* based on ap_expr_parse.y from mod_ssl */

/*  _________________________________________________________________
**
**  Expression Parser
**  _________________________________________________________________
*/

%pure-parser
%error-verbose
%defines
%lex-param   { void *yyscanner }
%parse-param { ap_expr_parse_ctx_t *ctx }

%{
#include "util_expr_private.h"
%}

%union {
    char      *cpVal;
    ap_expr_t *exVal;
    int        num;
}

%token  T_TRUE
%token  T_FALSE

%token  T_EXPR_BOOL
%token  T_EXPR_STRING

%token  <cpVal> T_ERROR

%token  <cpVal> T_DIGIT
%token  <cpVal> T_ID
%token  <cpVal> T_STRING
%token  <cpVal> T_REGEX
%token  <cpVal> T_REGEX_I
%token  <num>   T_REGEX_BACKREF
%token  <cpVal> T_OP_UNARY
%token  <cpVal> T_OP_BINARY

%token  T_STR_BEGIN
%token  T_STR_END
%token  T_VAR_BEGIN
%token  T_VAR_END

%token  T_OP_EQ
%token  T_OP_NE
%token  T_OP_LT
%token  T_OP_LE
%token  T_OP_GT
%token  T_OP_GE
%token  T_OP_REG
%token  T_OP_NRE
%token  T_OP_IN
%token  T_OP_STR_EQ
%token  T_OP_STR_NE
%token  T_OP_STR_LT
%token  T_OP_STR_LE
%token  T_OP_STR_GT
%token  T_OP_STR_GE
%token  T_OP_CONCAT

%token  T_OP_OR
%token  T_OP_AND
%token  T_OP_NOT

%right  T_OP_OR
%right  T_OP_AND
%right  T_OP_NOT
%right  T_OP_CONCAT

%type   <exVal>   expr
%type   <exVal>   comparison
%type   <exVal>   strfunccall
%type   <exVal>   lstfunccall
%type   <exVal>   regex
%type   <exVal>   words
%type   <exVal>   wordlist
%type   <exVal>   word
%type   <exVal>   string
%type   <exVal>   strpart
%type   <exVal>   var
%type   <exVal>   backref

%{
#include "util_expr_private.h"
#define yyscanner ctx->scanner

int ap_expr_yylex(YYSTYPE *lvalp, void *scanner);
%}


%%

root      : T_EXPR_BOOL   expr           { ctx->expr = $2; }
          | T_EXPR_STRING string         { ctx->expr = $2; }
          | T_ERROR                      { YYABORT; }
          ;

expr      : T_TRUE                       { $$ = ap_expr_make(op_True,        NULL, NULL, ctx); }
          | T_FALSE                      { $$ = ap_expr_make(op_False,       NULL, NULL, ctx); }
          | T_OP_NOT expr                { $$ = ap_expr_make(op_Not,         $2,   NULL, ctx); }
          | expr T_OP_OR expr            { $$ = ap_expr_make(op_Or,          $1,   $3,   ctx); }
          | expr T_OP_AND expr           { $$ = ap_expr_make(op_And,         $1,   $3,   ctx); }
          | comparison                   { $$ = ap_expr_make(op_Comp,        $1,   NULL, ctx); }
          | T_OP_UNARY word              { $$ = ap_expr_unary_op_make(       $1,   $2,   ctx); }
          | word T_OP_BINARY word        { $$ = ap_expr_binary_op_make($2,   $1,   $3,   ctx); }
          | '(' expr ')'                 { $$ = $2; }
          | T_ERROR                      { YYABORT; }
          ;

comparison: word T_OP_EQ word            { $$ = ap_expr_make(op_EQ,      $1, $3, ctx); }
          | word T_OP_NE word            { $$ = ap_expr_make(op_NE,      $1, $3, ctx); }
          | word T_OP_LT word            { $$ = ap_expr_make(op_LT,      $1, $3, ctx); }
          | word T_OP_LE word            { $$ = ap_expr_make(op_LE,      $1, $3, ctx); }
          | word T_OP_GT word            { $$ = ap_expr_make(op_GT,      $1, $3, ctx); }
          | word T_OP_GE word            { $$ = ap_expr_make(op_GE,      $1, $3, ctx); }
          | word T_OP_STR_EQ word        { $$ = ap_expr_make(op_STR_EQ,  $1, $3, ctx); }
          | word T_OP_STR_NE word        { $$ = ap_expr_make(op_STR_NE,  $1, $3, ctx); }
          | word T_OP_STR_LT word        { $$ = ap_expr_make(op_STR_LT,  $1, $3, ctx); }
          | word T_OP_STR_LE word        { $$ = ap_expr_make(op_STR_LE,  $1, $3, ctx); }
          | word T_OP_STR_GT word        { $$ = ap_expr_make(op_STR_GT,  $1, $3, ctx); }
          | word T_OP_STR_GE word        { $$ = ap_expr_make(op_STR_GE,  $1, $3, ctx); }
          | word T_OP_IN wordlist        { $$ = ap_expr_make(op_IN,      $1, $3, ctx); }
          | word T_OP_REG regex          { $$ = ap_expr_make(op_REG,     $1, $3, ctx); }
          | word T_OP_NRE regex          { $$ = ap_expr_make(op_NRE,     $1, $3, ctx); }
          ;

wordlist  : lstfunccall                  { $$ = $1; }
          | '{' words '}'                { $$ = $2; }
          ;

words     : word                         { $$ = ap_expr_make(op_ListElement, $1, NULL, ctx); }
          | words ',' word               { $$ = ap_expr_make(op_ListElement, $3, $1,   ctx); }
          ;

string    : string strpart               { $$ = ap_expr_make(op_Concat, $1, $2, ctx); }
          | strpart                      { $$ = $1; }
          | T_ERROR                      { YYABORT; }
          ;

strpart   : T_STRING                     { $$ = ap_expr_make(op_String, $1, NULL, ctx); }
          | var                          { $$ = $1; }
          | backref                      { $$ = $1; }
          ;

var       : T_VAR_BEGIN T_ID T_VAR_END            { $$ = ap_expr_var_make($2, ctx); }
          | T_VAR_BEGIN T_ID ':' string T_VAR_END { $$ = ap_expr_str_func_make($2, $4, ctx); }
          ;

word      : T_DIGIT                      { $$ = ap_expr_make(op_Digit,  $1, NULL, ctx); }
          | word T_OP_CONCAT word        { $$ = ap_expr_make(op_Concat, $1, $3,   ctx); }
          | var                          { $$ = $1; }
          | backref                      { $$ = $1; }
          | strfunccall                  { $$ = $1; }
          | T_STR_BEGIN string T_STR_END { $$ = $2; }
          | T_STR_BEGIN T_STR_END        { $$ = ap_expr_make(op_String, "", NULL, ctx); }
          ;

regex     : T_REGEX {
                ap_regex_t *regex;
                if ((regex = ap_pregcomp(ctx->pool, $1,
                                         AP_REG_EXTENDED|AP_REG_NOSUB)) == NULL) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = ap_expr_make(op_Regex, regex, NULL, ctx);
            }
          | T_REGEX_I {
                ap_regex_t *regex;
                if ((regex = ap_pregcomp(ctx->pool, $1,
                                         AP_REG_EXTENDED|AP_REG_NOSUB|AP_REG_ICASE)) == NULL) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = ap_expr_make(op_Regex, regex, NULL, ctx);
            }
          ;

backref     : T_REGEX_BACKREF   {
                int *n = apr_palloc(ctx->pool, sizeof(int));
                *n = $1;
                $$ = ap_expr_make(op_RegexBackref, n, NULL, ctx);
            }
            ;

lstfunccall : T_ID '(' word ')' { $$ = ap_expr_list_func_make($1, $3, ctx); }
            ;

strfunccall : T_ID '(' word ')' { $$ = ap_expr_str_func_make($1, $3, ctx); }
            ;

%%

void yyerror(ap_expr_parse_ctx_t *ctx, const char *s)
{
    /* s is allocated on the stack */
    ctx->error = apr_pstrdup(ctx->ptemp, s);
}

