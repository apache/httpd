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
%token  <cpVal> T_STRING            "string"

%token          T_REGEX             "match regex"
%token          T_REGSUB            "substitution regex"
%token  <cpVal> T_REG_MATCH         "match pattern of the regex"
%token  <cpVal> T_REG_SUBST         "substitution pattern of the regex"
%token  <cpVal> T_REG_FLAGS         "flags of the regex"
%token  <num>   T_REG_REF           "regex back reference"

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

%token  T_OP_SPLIT                  "split operator"
%token  T_OP_JOIN                   "join operator"

%token  T_OP_OR                     "logical or"
%token  T_OP_AND                    "logical and"
%token  T_OP_NOT                    "logical not"

%right  T_OP_OR
%right  T_OP_AND
%right  T_OP_NOT
%right  T_OP_CONCAT

%type   <exVal>   cond              "condition"
%type   <exVal>   comp              "comparison"
%type   <exVal>   strfunc           "string function"
%type   <exVal>   lstfunc           "list function"
%type   <exVal>   wordlist          "list of words"
%type   <exVal>   words             "tuple of words"
%type   <exVal>   word              "word expression"
%type   <exVal>   string            "string expression"
%type   <exVal>   strany            "any string expression"
%type   <exVal>   var               "variable expression"
%type   <exVal>   regex             "regular expression match"
%type   <exVal>   regsub            "regular expression substitution"
%type   <exVal>   regsplit          "regular expression split"
%type   <exVal>   regany            "any regular expression"
%type   <exVal>   regref            "regular expression back reference"

%{
#include "util_expr_private.h"
#define yyscanner ctx->scanner

int ap_expr_yylex(YYSTYPE *lvalp, void *scanner);
%}


%%

root      : T_EXPR_BOOL   cond           { ctx->expr = $2; }
          | T_EXPR_STRING string         { ctx->expr = $2; }
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
          | word T_OP_IN wordlist        { $$ = ap_expr_make(op_IN,      $1, $3, ctx); }
          | word T_OP_REG regex          { $$ = ap_expr_make(op_REG,     $1, $3, ctx); }
          | word T_OP_NRE regex          { $$ = ap_expr_make(op_NRE,     $1, $3, ctx); }
          ;

wordlist  : lstfunc                      { $$ = $1; }
          | word     T_OP_REG regsplit   { $$ = ap_expr_list_regex_make($1, $3, ctx); }
          | wordlist T_OP_REG regany     { $$ = ap_expr_list_regex_make($1, $3, ctx); }
          | '{' words '}'                { $$ = $2; }
          | '(' wordlist ')'             { $$ = $2; }
          ;

words     : word                         { $$ = ap_expr_make(op_ListElement, $1, NULL, ctx); }
          | word ',' words               { $$ = ap_expr_make(op_ListElement, $1, $3,   ctx); }
          ;

string    : strany                       { $$ = $1; }
          | string strany                { $$ = ap_expr_concat_make($1, $2, ctx); }
          | T_ERROR                      { YYABORT; }
          ;

strany    : T_STRING                     { $$ = ap_expr_make(op_String, $1, NULL, ctx); }
          | var                          { $$ = $1; }
          | regref                       { $$ = $1; }
          ;

var       : T_VAR_BEGIN T_ID T_VAR_END            { $$ = ap_expr_var_make($2, ctx); }
          | T_VAR_BEGIN T_ID ':' string T_VAR_END { $$ = ap_expr_str_func_make($2, $4, ctx); }
          | T_VAREXP_BEGIN word T_VAREXP_END      { $$ = ap_expr_str_word_make($2, ctx); }
          | T_VAREXP_BEGIN cond T_VAREXP_END      { $$ = ap_expr_str_bool_make($2, ctx); }
          ;

word      : T_DIGIT                      { $$ = ap_expr_make(op_Digit,  $1, NULL, ctx); }
          | T_STR_BEGIN T_STR_END        { $$ = ap_expr_make(op_String, "", NULL, ctx); }
          | T_STR_BEGIN string T_STR_END { $$ = $2; }
          | word T_OP_CONCAT word        { $$ = ap_expr_make(op_Concat, $1, $3,   ctx); }
          | word T_OP_REG regsub         { $$ = ap_expr_make(op_Regsub, $1, $3,   ctx); }
          | var                          { $$ = $1; }
          | regref                       { $$ = $1; }
          | strfunc                      { $$ = $1; }
          | T_OP_JOIN     wordlist              {
                                           $$ = ap_expr_make(op_Join,   $2, NULL, ctx);
            }
          | T_OP_JOIN     wordlist ',' word     {
                                           $$ = ap_expr_make(op_Join,   $2, $4,   ctx);
            }
          | T_OP_JOIN '(' wordlist ',' word ')' {
                                           $$ = ap_expr_make(op_Join,   $3, $5,   ctx);
            }
          | '(' word ')'                 { $$ = $2; }
          ;

regex     : T_REGEX T_REG_MATCH T_REG_FLAGS {
                ap_expr_t *e = ap_expr_regex_make($2, $3, NULL, 0, ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = e;
            }
          ;
regsub    : T_REGSUB T_REG_MATCH string T_REG_FLAGS {
                ap_expr_t *e = ap_expr_regex_make($2, $4, $3, 0, ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = e;
            }
          ;
regsplit  : T_OP_SPLIT T_REG_MATCH string T_REG_FLAGS {
                /* Returns a list:
                 * <word> ~= split/://
                 *  => split around ':', replace it with empty
                 * <word> ~= split/:/\n/
                 *  => split around ':', replace it with '\n'
                 * <list> ~= split/.*?Ip Address:([^,]+)/$1/
                 *  => split around the whole match, replace it with $1
                 */
                ap_expr_t *e = ap_expr_regex_make($2, $4, $3, 1, ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = e;
            }
          ;
regany    : regex     { $$ = $1; }
          | regsub    { $$ = $1; }
          | regsplit  { $$ = $1; }
          ;

regref    : T_REG_REF {
                int *n = apr_palloc(ctx->pool, sizeof(int));
                *n = $1;
                $$ = ap_expr_make(op_Regref, n, NULL, ctx);
            }
          ;

lstfunc   : T_ID '(' word ')'  { $$ = ap_expr_list_func_make($1, $3, ctx); }
       /* | T_ID '(' words ')' { $$ = ap_expr_list_func_make($1, $3, ctx); } */
          ;

strfunc   : T_ID '(' word ')'  { $$ = ap_expr_str_func_make($1, $3, ctx); }
          | T_ID '(' words ')' { $$ = ap_expr_str_func_make($1, $3, ctx); }
          ;

%%

void yyerror(ap_expr_parse_ctx_t *ctx, const char *s)
{
    /* s is allocated on the stack */
    ctx->error = apr_pstrdup(ctx->ptemp, s);
}

