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

%token  T_TRUE                      "true"
%token  T_FALSE                     "false"

%token  T_EXPR_BOOL                 "boolean expression"
%token  T_EXPR_STRING               "string expression"

%token  <cpVal> T_ERROR             "error token"

%token  <cpVal> T_DIGIT             "number"
%token  <cpVal> T_ID                "identifier"
%token  <cpVal> T_STRING            "string literal"

%token          T_REGEX             "start of matching regex"
%token          T_REGSUB            "start of substitution regex"
%token  <cpVal> T_REG_MATCH         "pattern of the regex"
%token  <cpVal> T_REG_SUBST         "substitution of the regex"
%token  <cpVal> T_REG_FLAGS         "pattern flags of the regex"
%token  <num>   T_BACKREF           "regex back reference"

%token  <cpVal> T_OP_UNARY          "unary operator"
%token  <cpVal> T_OP_BINARY         "binary operator"

%token  T_STR_BEGIN                 "start of string"
%token  T_STR_END                   "end of string"
%token  T_VAR_BEGIN                 "start of variable name"
%token  T_VAR_END                   "end of variable name"
%token  T_VAREXP_BEGIN              "start of variable expression"
%token  T_VAREXP_END                "end of variable expression"

%token  T_OP_EQ                     "integer equal"
%token  T_OP_NE                     "integer not equal"
%token  T_OP_LT                     "integer less than"
%token  T_OP_LE                     "integer less or equal"
%token  T_OP_GT                     "integer greater than"
%token  T_OP_GE                     "integer greater or equal"
%token  T_OP_REG                    "regex match"
%token  T_OP_NRE                    "regex non-match"
%token  T_OP_IN                     "contained in"
%token  T_OP_STR_EQ                 "string equal"
%token  T_OP_STR_NE                 "string not equal"
%token  T_OP_STR_LT                 "string less than"
%token  T_OP_STR_LE                 "string less or equal"
%token  T_OP_STR_GT                 "string greater than"
%token  T_OP_STR_GE                 "string greater or equal"

%token  T_OP_CONCAT                 "string concatenation"

%token  T_OP_JOIN                   "join operator"
%token  T_OP_SPLIT                  "split operator"
%token  T_OP_SUB                    "substitute operator"

%token  T_OP_OR                     "logical or"
%token  T_OP_AND                    "logical and"
%token  T_OP_NOT                    "logical not"

%left   T_OP_OR
%left   T_OP_AND
%right  T_OP_NOT
%right  T_OP_CONCAT

%type   <exVal>   cond              "condition"
%type   <exVal>   comp              "comparison"
%type   <exVal>   strfunc           "string function"
%type   <exVal>   listfunc          "list function"
%type   <exVal>   list              "list"
%type   <exVal>   words             "words"
%type   <exVal>   word              "word"
%type   <exVal>   string            "string"
%type   <exVal>   substr            "substring"
%type   <exVal>   var               "variable"
%type   <exVal>   regex             "match regex"
%type   <exVal>   regsub            "substitution regex"
%type   <exVal>   regany            "any regex"
%type   <exVal>   split             "split"
%type   <exVal>   join              "join"
%type   <exVal>   sub               "sub"

%{
#include "util_expr_private.h"
#define yyscanner ctx->scanner

int ap_expr_yylex(YYSTYPE *lvalp, void *scanner);
%}


%%

expr      : T_EXPR_STRING string         { ctx->expr = $2; }
          | T_EXPR_BOOL   cond           { ctx->expr = $2; }
          | T_ERROR                      { YYABORT; }
          ;

string    : substr                       { $$ = $1; }
          | string substr                { $$ = ap_expr_concat_make($1, $2, ctx); }
          | T_ERROR                      { YYABORT; }
          ;

cond      : T_TRUE                       { $$ = ap_expr_make(op_True,        NULL, NULL, ctx); }
          | T_FALSE                      { $$ = ap_expr_make(op_False,       NULL, NULL, ctx); }
          | T_OP_NOT cond                { $$ = ap_expr_make(op_Not,         $2,   NULL, ctx); }
          | cond T_OP_OR cond            { $$ = ap_expr_make(op_Or,          $1,   $3,   ctx); }
          | cond T_OP_AND cond           { $$ = ap_expr_make(op_And,         $1,   $3,   ctx); }
          | comp                         { $$ = ap_expr_make(op_Comp,        $1,   NULL, ctx); }
          | T_OP_UNARY word              { $$ = ap_expr_unary_op_make(       $1,   $2,   ctx); }
          | word T_OP_BINARY word        { $$ = ap_expr_binary_op_make($2,   $1,   $3,   ctx); }
          | '(' cond ')'                 { $$ = $2; }
          | T_ERROR                      { YYABORT; }
          ;

comp      : word T_OP_EQ word            { $$ = ap_expr_make(op_EQ,      $1, $3, ctx); }
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
          | word T_OP_REG regex          { $$ = ap_expr_make(op_REG,     $1, $3, ctx); }
          | word T_OP_NRE regex          { $$ = ap_expr_make(op_NRE,     $1, $3, ctx); }
          | word T_OP_IN list            { $$ = ap_expr_make(op_IN,      $1, $3, ctx); }
          ;

word      : T_DIGIT                      { $$ = ap_expr_make(op_Digit,  $1, NULL, ctx); }
          | T_STR_BEGIN T_STR_END        { $$ = ap_expr_make(op_String, "", NULL, ctx); }
          | T_STR_BEGIN string T_STR_END { $$ = $2; }
          | word T_OP_CONCAT word        { $$ = ap_expr_make(op_Concat, $1, $3,   ctx); }
          | var                          { $$ = $1; }
          | sub                          { $$ = $1; }
          | join                         { $$ = $1; }
          | strfunc                      { $$ = $1; }
          | '(' word ')'                 { $$ = $2; }
          ;

list      : split                        { $$ = $1; }
          | listfunc                     { $$ = $1; }
          | '{' words '}'                { $$ = $2; }
          | '(' list ')'                 { $$ = $2; }
          ;

substr    : T_STRING                     { $$ = ap_expr_make(op_String, $1, NULL, ctx); }
          | var                          { $$ = $1; }
          ;

var       : T_VAR_BEGIN T_ID T_VAR_END            { $$ = ap_expr_var_make($2, ctx); }
          | T_VAR_BEGIN T_ID ':' string T_VAR_END { $$ = ap_expr_str_func_make($2, $4, ctx); }
          | T_VAREXP_BEGIN cond T_VAREXP_END      { $$ = ap_expr_make(op_Bool, $2, NULL, ctx); }
          | T_VAREXP_BEGIN word T_VAREXP_END      { $$ = ap_expr_make(op_Word, $2, NULL, ctx); }
          | T_BACKREF                             { $$ = ap_expr_backref_make($1, ctx); }
          ;

strfunc   : T_ID '(' word ')'            { $$ = ap_expr_str_func_make($1, $3, ctx); }
          | T_ID '(' words ')'           { $$ = ap_expr_str_func_make($1, $3, ctx); }
          ;

listfunc  : T_ID '(' word ')'            { $$ = ap_expr_list_func_make($1, $3, ctx); }
       /* | T_ID '(' words ')'           { $$ = ap_expr_list_func_make($1, $3, ctx); } */
          ;

sub       : T_OP_SUB     regsub ',' word     { $$ = ap_expr_make(op_Sub, $4, $2, ctx); }
          | T_OP_SUB '(' regsub ',' word ')' { $$ = ap_expr_make(op_Sub, $5, $3, ctx); }
          ;

join      : T_OP_JOIN     list              { $$ = ap_expr_make(op_Join, $2, NULL, ctx); }
          | T_OP_JOIN '(' list ')'          { $$ = ap_expr_make(op_Join, $3, NULL, ctx); }
          | T_OP_JOIN     list ',' word     { $$ = ap_expr_make(op_Join, $2, $4,   ctx); }
          | T_OP_JOIN '(' list ',' word ')' { $$ = ap_expr_make(op_Join, $3, $5,   ctx); }
          ;

split     : T_OP_SPLIT     regany ',' list     { $$ = ap_expr_make(op_Split, $4, $2, ctx); }
          | T_OP_SPLIT '(' regany ',' list ')' { $$ = ap_expr_make(op_Split, $5, $3, ctx); }
          | T_OP_SPLIT     regany ',' word     { $$ = ap_expr_make(op_Split, $4, $2, ctx); }
          | T_OP_SPLIT '(' regany ',' word ')' { $$ = ap_expr_make(op_Split, $5, $3, ctx); }
          ;

words     : word                         { $$ = ap_expr_make(op_ListElement, $1, NULL, ctx); }
          | word ',' words               { $$ = ap_expr_make(op_ListElement, $1, $3,   ctx); }
          ;

regex     : T_REGEX T_REG_MATCH T_REG_FLAGS {
                ap_expr_t *e = ap_expr_regex_make($2, NULL, $3, ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = e;
            }
          ;
regsub    : T_REGSUB T_REG_MATCH string T_REG_FLAGS {
                ap_expr_t *e = ap_expr_regex_make($2, $3, $4, ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = e;
            }
          ;
regany    : regex   { $$ = $1; }
          | regsub  { $$ = $1; }
          ;

%%

void yyerror(ap_expr_parse_ctx_t *ctx, const char *s)
{
    /* s is allocated on the stack */
    ctx->error = apr_pstrdup(ctx->ptemp, s);
}

