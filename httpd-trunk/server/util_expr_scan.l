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

/*
 *  ap_expr_scan.l, based on ssl_expr_scan.l from mod_ssl
 */

/*  _________________________________________________________________
**
**  Expression Scanner
**  _________________________________________________________________
*/

%pointer
%option batch
%option never-interactive
%option nodefault
%option noyywrap
%option reentrant
%option bison-bridge
%option warn
%option noinput nounput noyy_top_state
%option stack
%x str
%x var
%x vararg
%x regex regex_flags

%{
#include "util_expr_private.h"
#include "util_expr_parse.h"

#undef  YY_INPUT
#define YY_INPUT(buf,result,max_size)                       \
{                                                           \
    if ((result = MIN(max_size, yyextra->inputbuf           \
                              + yyextra->inputlen           \
                              - yyextra->inputptr)) <= 0)   \
    {                                                       \
        result = YY_NULL;                                   \
    }                                                       \
    else {                                                  \
        memcpy(buf, yyextra->inputptr, result);             \
        yyextra->inputptr += result;                        \
    }                                                       \
}

#define YY_EXTRA_TYPE ap_expr_parse_ctx_t*

#define PERROR(msg) do { yyextra->error2 = msg ; return T_ERROR; } while (0)

#define str_ptr     (yyextra->scan_ptr)
#define str_buf     (yyextra->scan_buf)
#define str_del     (yyextra->scan_del)

#define STR_APPEND(c) do {                          \
        *str_ptr++ = (c);                           \
        if (str_ptr >= str_buf + sizeof(str_buf))   \
            PERROR("String too long");              \
    } while (0)

%}


%%

  char  regex_buf[MAX_STRING_LEN];
  char *regex_ptr = NULL;
  char  regex_del = '\0';

%{
 /*
  * Set initial state for string expressions
  */
  if (yyextra->at_start) {
    yyextra->at_start = 0;
    if (yyextra->flags & AP_EXPR_FLAG_STRING_RESULT) {
        BEGIN(str);
        return T_EXPR_STRING;
    }
    else {
        return T_EXPR_BOOL;
    }
  }
%}

 /*
  * Whitespaces
  */
[ \t\n]+ { 
    /* NOP */
}

 /*
  * strings ("..." and '...')
  */
["'] {
    str_ptr = str_buf;
    str_del = yytext[0];
    BEGIN(str);
    return T_STR_BEGIN;
}
<str>["'] {
    if (yytext[0] == str_del) {
        if (YY_START == var) {
            PERROR("Unterminated variable in string");
        }
        else if (str_ptr == str_buf) {
            BEGIN(INITIAL);
            return T_STR_END;
        }
        else {
            /* return what we have so far and scan delimiter again */
            *str_ptr = '\0';
            yylval->cpVal = apr_pstrdup(yyextra->pool, str_buf);
            yyless(0);
            str_ptr = str_buf;
            return T_STRING;
        }
    }
    else {
        STR_APPEND(yytext[0]);
    }
}
<str,var,vararg>\n {
    PERROR("Unterminated string or variable");
}
<var,vararg><<EOF>> {
    PERROR("Unterminated string or variable");
}
<str><<EOF>> {
    if (!(yyextra->flags & AP_EXPR_FLAG_STRING_RESULT)) {
        PERROR("Unterminated string or variable");
    }
    else {
        *str_ptr = '\0';
        yylval->cpVal = apr_pstrdup(yyextra->pool, str_buf);
        str_ptr = str_buf;
        BEGIN(INITIAL);
        return T_STRING;
    }
}

<str,vararg>\\[0-7]{1,3} {
    int result;

    (void)sscanf(yytext+1, "%o", &result);
    if (result > 0xff) {
        PERROR("Escape sequence out of bound");
    }
    else {
        STR_APPEND(result);
    }
}
<str,vararg>\\[0-9]+ {
    PERROR("Bad escape sequence");
}
<str,vararg>\\n      { STR_APPEND('\n'); }
<str,vararg>\\r      { STR_APPEND('\r'); }
<str,vararg>\\t      { STR_APPEND('\t'); }
<str,vararg>\\b      { STR_APPEND('\b'); }
<str,vararg>\\f      { STR_APPEND('\f'); }
<str,vararg>\\(.|\n) { STR_APPEND(yytext[1]); }

 /* regexp backref inside string/arg */
<str,vararg>[$][0-9] {
    if (str_ptr != str_buf) {
        /* return what we have so far and scan '$x' again */
        *str_ptr = '\0';
        yylval->cpVal = apr_pstrdup(yyextra->pool, str_buf);
        str_ptr = str_buf;
        yyless(0);
        return T_STRING;
    }
    else {
        yylval->num = yytext[1] - '0';
        return T_REGEX_BACKREF;
    }
}

<str,vararg>[^\\\n"'%}$]+ {
    char *cp = yytext;
    while (*cp != '\0') {
        STR_APPEND(*cp);
        cp++;
    }
}

 /* variable inside string/arg */
<str,vararg>%\{ {
    if (str_ptr != str_buf) {
        /* return what we have so far and scan '%{' again */
        *str_ptr = '\0';
        yylval->cpVal = apr_pstrdup(yyextra->pool, str_buf);
        yyless(0);
        str_ptr = str_buf;
        return T_STRING;
    }
    else {
        yy_push_state(var, yyscanner);
        return T_VAR_BEGIN;
    }
}

<vararg>[%$] {
     STR_APPEND(yytext[0]);
}

<str>[%}$] {
     STR_APPEND(yytext[0]);
}

%\{ {
    yy_push_state(var, yyscanner);
    return T_VAR_BEGIN;
}

[$][0-9] {
    yylval->num = yytext[1] - '0';
    return T_REGEX_BACKREF;
}

 /*
  * fixed name variable expansion %{XXX} and function call in %{func:arg} syntax
  */
<var>[a-zA-Z][a-zA-Z0-9_]* {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext);
    return T_ID;
}

<var>\} {
    yy_pop_state(yyscanner);
    return T_VAR_END;
}

<var>: {
    BEGIN(vararg);
    return yytext[0];
}

<var>.|\n {
    char *msg = apr_psprintf(yyextra->pool,
                             "Invalid character in variable name '%c'", yytext[0]);
    PERROR(msg);
}

<vararg>\} {
    if (str_ptr != str_buf) {
        /* return what we have so far and scan '}' again */
        *str_ptr = '\0';
        yylval->cpVal = apr_pstrdup(yyextra->pool, str_buf);
        str_ptr = str_buf;
        yyless(0);
        return T_STRING;
    }
    else {
        yy_pop_state(yyscanner);
        return T_VAR_END;
    }
}

 /*
  * Regular Expression
  */
"m"[/#$%^,;:_\?\|\^\-\!\.\'\"] {
    regex_del = yytext[1];
    regex_ptr = regex_buf;
    BEGIN(regex);
}
"/" {
    regex_del = yytext[0];
    regex_ptr = regex_buf;
    BEGIN(regex);
}
<regex>.|\n {
    if (yytext[0] == regex_del) {
        *regex_ptr = '\0';
        BEGIN(regex_flags);
    }
    else {
        *regex_ptr++ = yytext[0];
        if (regex_ptr >= regex_buf + sizeof(regex_buf))
            PERROR("Regexp too long");
    }
}
<regex_flags>i {
    yylval->cpVal = apr_pstrdup(yyextra->pool, regex_buf);
    BEGIN(INITIAL);
    return T_REGEX_I;
}
<regex_flags>.|\n {
    yylval->cpVal = apr_pstrdup(yyextra->pool, regex_buf);
    yyless(0);
    BEGIN(INITIAL);
    return T_REGEX;
}
<regex_flags><<EOF>> {
    yylval->cpVal = apr_pstrdup(yyextra->pool, regex_buf);
    BEGIN(INITIAL);
    return T_REGEX;
}

 /*
  * Operators
  */
==?   { return T_OP_STR_EQ; }
"!="  { return T_OP_STR_NE; }
"<"   { return T_OP_STR_LT; }
"<="  { return T_OP_STR_LE; }
">"   { return T_OP_STR_GT; }
">="  { return T_OP_STR_GE; }
"=~"  { return T_OP_REG; }
"!~"  { return T_OP_NRE; }
"and" { return T_OP_AND; }
"&&"  { return T_OP_AND; }
"or"  { return T_OP_OR; }
"||"  { return T_OP_OR; }
"not" { return T_OP_NOT; }
"!"   { return T_OP_NOT; }
"."   { return T_OP_CONCAT; }
"-in"  { return T_OP_IN; }
"-eq"  { return T_OP_EQ; }
"-ne"  { return T_OP_NE; }
"-ge"  { return T_OP_GE; }
"-le"  { return T_OP_LE; }
"-gt"  { return T_OP_GT; }
"-lt"  { return T_OP_LT; }

 /* for compatibility with ssl_expr */
"lt"  { return T_OP_LT; }
"le"  { return T_OP_LE; }
"gt"  { return T_OP_GT; }
"ge"  { return T_OP_GE; }
"ne"  { return T_OP_NE; }
"eq"  { return T_OP_EQ; }
"in"  { return T_OP_IN; }

"-"[a-zA-Z_] {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext + 1);
    return T_OP_UNARY;
}

"-"[a-zA-Z_][a-zA-Z_0-9]+ {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext + 1);
    return T_OP_BINARY;
}

 /*
  * Specials
  */
"true"  { return T_TRUE; }
"false" { return T_FALSE; }

 /*
  * Digits
  */
-?[0-9]+ {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext);
    return T_DIGIT;
}

 /*
  * Identifiers
  */
[a-zA-Z][a-zA-Z0-9_]* {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext);
    return T_ID;
}

 /*
  * These are parts of the grammar and are returned as is
  */
[(){},:] {
    return yytext[0];
}

 /*
  * Anything else is an error
  */
.|\n {
    char *msg = apr_psprintf(yyextra->pool, "Parse error near '%c'", yytext[0]);
    PERROR(msg);
}

%%


