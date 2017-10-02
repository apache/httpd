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

%x str expr
%x var vararg
%x split regex regsub regflags

%{
#include "util_expr_private.h"
#include "util_expr_parse.h"
#include "http_main.h"
#include "http_log.h"
#include "apr_lib.h"

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

/*
 * XXX: It would be nice if we could recover somehow, e.g. via
 * XXX: longjmp. It is not clear if the scanner is in any state
 * XXX: to be cleaned up, though.
 */
static int unreachable = 0;
#define YY_FATAL_ERROR(msg)                                     \
    do {                                                        \
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, \
                     APLOGNO(03296)                             \
                     "expr parser fatal error (BUG?): "         \
                     "%s, exiting", msg);                       \
        if (unreachable) {                                      \
            /* Not reached, silence [-Wunused-function] */      \
            yy_fatal_error(msg, yyscanner);                     \
        }                                                       \
        else {                                                  \
            abort();                                            \
        }                                                       \
    } while (0)

#define YY_EXTRA_TYPE ap_expr_parse_ctx_t*

#define PERROR(msg) do {    \
    yyextra->error2 = msg;  \
    return T_ERROR;         \
} while (0)

#define PERROR_CHAR(prefix, chr) do {                                       \
    char *msg;                                                              \
    if (apr_isprint((chr))) {                                               \
        msg = apr_psprintf(yyextra->pool, prefix "'%c'", (char)(chr));      \
    }                                                                       \
    else {                                                                  \
        msg = apr_psprintf(yyextra->pool, prefix "'\\x%.2X'", (int)(chr));  \
    }                                                                       \
    PERROR(msg);                                                            \
} while (0)

#define STACK_PUSH() do {                               \
    ap_expr_parser_stack_t *sk;                         \
    if (yyextra->spares) {                              \
        sk = yyextra->spares;                           \
        yyextra->spares = sk->next;                     \
    }                                                   \
    else {                                              \
        sk = apr_palloc(yyextra->ptemp, sizeof(*sk));   \
    }                                                   \
    sk->scan_ptr  = sk->scan_buf;                       \
    sk->scan_stop = sk->scan_buf[0] = '\0';             \
    sk->scan_flag = 0;                                  \
    sk->next = yyextra->current;                        \
    yyextra->current = sk;                              \
} while (0)

#define STACK_POP() do {            \
    ap_expr_parser_stack_t *sk;     \
    sk = yyextra->current;          \
    yyextra->current = sk->next;    \
    sk->next = yyextra->spares;     \
    yyextra->spares = sk;           \
} while (0)

#define STATE_PUSH(st, sk) do {     \
    yy_push_state((st), yyscanner); \
    if ((sk)) {                     \
        STACK_PUSH();               \
    }                               \
} while (0)

#define STATE_POP(sk) do {          \
    if ((sk)) {                     \
        STACK_POP();                \
    }                               \
    yy_pop_state(yyscanner);        \
} while (0)

#define str_ptr  (yyextra->current->scan_ptr)
#define str_buf  (yyextra->current->scan_buf)
#define str_stop (yyextra->current->scan_stop)
#define str_flag (yyextra->current->scan_flag)

#define STR_APPEND_CHECK(chr, chk) do {                     \
    if ((chk) && apr_iscntrl((chr))) {                      \
        PERROR_CHAR("Invalid string character ", (chr));    \
    }                                                       \
    if (str_ptr >= str_buf + sizeof(str_buf) - 1) {         \
        PERROR("String too long");                          \
    }                                                       \
    *str_ptr++ = (char)(chr);                               \
} while (0)

#define STR_APPEND_NOCHECK(chr) \
    STR_APPEND_CHECK((chr), 0)

#define STR_EMPTY() \
    (str_ptr == str_buf)

#define STR_RETURN() \
    (apr_pstrdup(yyextra->pool, (*str_ptr = '\0', str_ptr = str_buf)))

%}

ANY          (.|\n)
SPACE        [ \t\n]
QUOTE        ["']
TOKEN        ([a-zA-Z][a-zA-Z0-9_]*)
VAR_BEGIN    (\%\{)
VAR_ARG      (\:)
VAR_END      (\})
VAREXP_BEGIN (\%\{\:)
VAREXP_END   (\:\})
REG_SEP      [/#$%^|?!'",;:._-]
REG_REF      (\$[0-9])

%%

%{
 /*
  * Set initial state for string expressions
  */
  if (yyextra->at_start) {
    yyextra->at_start = 0;
    if (yyextra->flags & AP_EXPR_FLAG_STRING_RESULT) {
        STATE_PUSH(str, 1);
        return T_EXPR_STRING;
    }
    else {
        STATE_PUSH(expr, 1);
        return T_EXPR_BOOL;
    }
  }
%}

 /*
  * Back off INITIAL pushes
  */
<str><<EOF>> {
    STATE_POP(0); /* <str> */
    if (YY_START != INITIAL) {
        PERROR("Unterminated string");
    }
    yylval->cpVal = STR_RETURN();
    STACK_POP(); /* ^ after this */
    return T_STRING;
}
<expr><<EOF>> {
    STATE_POP(1); /* <expr> */
    if (YY_START != INITIAL) {
        PERROR("Unterminated expression");
    }
}

<str>{QUOTE} {
    if (yytext[0] == str_stop) {
        if (!STR_EMPTY()) {
            yyless(0); /* come back below */
            yylval->cpVal = STR_RETURN();
            return T_STRING;
        }
        STATE_POP(1); /* <str> */
        return T_STR_END;
    }
    STR_APPEND_NOCHECK(yytext[0]);
}

 /* regexp backref inside string/arg */
<str,vararg,regsub>{REG_REF} {
    if (!STR_EMPTY()) {
        yyless(0); /* come back below */
        yylval->cpVal = STR_RETURN();
        return T_STRING;
    }
    yylval->num = yytext[1] - '0';
    return T_REG_REF;
}

 /* variable inside string/arg */
<str,vararg,regsub>{VAR_BEGIN} {
    if (!STR_EMPTY()) {
        yyless(0); /* come back below */
        yylval->cpVal = STR_RETURN();
        return T_STRING;
    }
    STATE_PUSH(var, 1);
    return T_VAR_BEGIN;
}

<str,vararg,regsub>{VAREXP_BEGIN} {
    if (!STR_EMPTY()) {
        yyless(0); /* come back below */
        yylval->cpVal = STR_RETURN();
        return T_STRING;
    }
    STATE_PUSH(expr, 1);
    return T_VAREXP_BEGIN;
}

 /* Any non-octal or octal higher than 377 (decimal 255) is invalid */
<str,vararg,regsub>\\([4-9][0-9]{2}|[8-9][0-9]{0,2}) {
    PERROR("Bad character escape sequence");
}
<str,vararg,regsub>\\[0-7]{1,3} {
    int result;
    (void)sscanf(yytext+1, "%o", &result);
    STR_APPEND_NOCHECK(result);
}
<str,vararg,regsub>\\x[0-9A-Fa-f]{1,2} {
    int result;
    (void)sscanf(yytext+1, "%x", &result);
    STR_APPEND_NOCHECK(result);
}
<str,vararg,regsub>\\n  { STR_APPEND_NOCHECK('\n'); }
<str,vararg,regsub>\\r  { STR_APPEND_NOCHECK('\r'); }
<str,vararg,regsub>\\t  { STR_APPEND_NOCHECK('\t'); }
<str,vararg,regsub>\\b  { STR_APPEND_NOCHECK('\b'); }
<str,vararg,regsub>\\f  { STR_APPEND_NOCHECK('\f'); }
<str,vararg,regsub>\\.  { STR_APPEND_CHECK(yytext[1], 1); }

<str,vararg,regsub>\n {
    PERROR("Unterminated string or variable");
}

<str>{ANY} {
    STR_APPEND_CHECK(yytext[0], 1);
}

<expr>{SPACE}+ { 
    /* NOP */
}

<expr>{QUOTE} {
    STATE_PUSH(str, 1);
    str_stop = yytext[0];
    return T_STR_BEGIN;
}

<expr>{VAREXP_BEGIN} {
    STATE_PUSH(expr, 1);
    return T_VAREXP_BEGIN;
}
<expr>{VAREXP_END} {
    STATE_POP(1); /* <expr> */
    return T_VAREXP_END;
}


<expr>{VAR_BEGIN} {
    STATE_PUSH(var, 1);
    return T_VAR_BEGIN;
}
<var>{TOKEN} {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext);
    return T_ID;
}
<var>{VAR_ARG} {
    STATE_PUSH(vararg, 0);
    return yytext[0];
}
<vararg>{VAR_END} {
    yyless(0); /* let <var> handle */
    yylval->cpVal = STR_RETURN();
    STATE_POP(0); /* <vararg> */
    return T_STRING;
}
<vararg>{ANY} {
    STR_APPEND_CHECK(yytext[0], 1);
}
<var>{VAR_END} {
    STATE_POP(1); /* <var> */
    return T_VAR_END;
}
<var>{ANY} {
    PERROR_CHAR("Unexpected variable character ", yytext[0]);
}
<var,vararg><<EOF>> {
    PERROR("Unterminated variable");
}


 /*
  * Regular Expression
  */
<expr>\/ {
    STATE_PUSH(regex, 1);
    str_stop = yytext[0];
    str_flag = 'm';
    return T_REGEX;
}
<expr>[ms]{REG_SEP} {
    STATE_PUSH(regex, 1);
    str_stop = yytext[1];
    str_flag = yytext[0];
    return (str_flag == 'm') ? T_REGEX : T_REGSUB;
}
<regex>{ANY} {
    if (yytext[0] == str_stop) {
        STATE_POP(0); /* <regex> */
        if (str_flag == 'm') {
            STATE_PUSH(regflags, 0);
        }
        else {
            STATE_PUSH(regsub, 0);
        }
        yylval->cpVal = STR_RETURN();
        return T_REG_MATCH;
    }
    STR_APPEND_CHECK(yytext[0], 1);
}
<regsub>{ANY} {
    if (yytext[0] == str_stop) {
        STATE_POP(0); /* <regsub> */
        STATE_PUSH(regflags, 0);
    }
    else {
        STR_APPEND_CHECK(yytext[0], 1);
    }
}
<regflags>{ANY} {
    if (ap_strchr_c("ismg", yytext[0])) {
        STR_APPEND_NOCHECK(yytext[0]);
    }
    else if (apr_isalnum(yytext[0])) {
        PERROR("Invalid regexp flag(s)");
    }
    else {
        yyless(0); /* not a flags, rewind */
        yylval->cpVal = STR_RETURN();
        STATE_POP(1); /* <regflags> */
        return T_REG_FLAGS;
    }
}
<regflags><<EOF>> {
    yylval->cpVal = STR_RETURN();
    STATE_POP(1); /* <regflags> */
    return T_REG_FLAGS;
}
<regex,regsub><<EOF>> {
    PERROR("Unterminated regexp");
}

<expr>{REG_REF} {
    yylval->num = yytext[1] - '0';
    return T_REG_REF;
}

 /*
  * Operators
  */
<expr>==?   { return T_OP_STR_EQ; }
<expr>"!="  { return T_OP_STR_NE; }
<expr>"<"   { return T_OP_STR_LT; }
<expr>"<="  { return T_OP_STR_LE; }
<expr>">"   { return T_OP_STR_GT; }
<expr>">="  { return T_OP_STR_GE; }
<expr>"=~"  { return T_OP_REG; }
<expr>"!~"  { return T_OP_NRE; }
<expr>"and" { return T_OP_AND; }
<expr>"&&"  { return T_OP_AND; }
<expr>"or"  { return T_OP_OR; }
<expr>"||"  { return T_OP_OR; }
<expr>"not" { return T_OP_NOT; }
<expr>"!"   { return T_OP_NOT; }
<expr>"."   { return T_OP_CONCAT; }
<expr>"-in" { return T_OP_IN; }
<expr>"-eq" { return T_OP_EQ; }
<expr>"-ne" { return T_OP_NE; }
<expr>"-ge" { return T_OP_GE; }
<expr>"-le" { return T_OP_LE; }
<expr>"-gt" { return T_OP_GT; }
<expr>"-lt" { return T_OP_LT; }

 /* for compatibility with ssl_expr */
<expr>"lt"  { return T_OP_LT; }
<expr>"le"  { return T_OP_LE; }
<expr>"gt"  { return T_OP_GT; }
<expr>"ge"  { return T_OP_GE; }
<expr>"ne"  { return T_OP_NE; }
<expr>"eq"  { return T_OP_EQ; }
<expr>"in"  { return T_OP_IN; }

<expr>"-"[a-zA-Z_][a-zA-Z_0-9]+ {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext + 1);
    return T_OP_BINARY;
}

<expr>"-"[a-zA-Z_] {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext + 1);
    return T_OP_UNARY;
}

 /* Split a string (or list) into a(nother) list */
<expr>"split" {
    STATE_PUSH(split, 0);
    return T_OP_SPLIT;
}
<split>{REG_SEP} {
    STATE_POP(0); /* <split> */
    STATE_PUSH(regex, 1);
    str_stop = yytext[0];
    str_flag = 'S';
}
<split>{ANY} {
    PERROR("Expecting split regular expression");
}
<split><<EOF>> {
    PERROR("Unterminated split");
}

 /* Join a list into a string */
<expr>"join"  {
    return T_OP_JOIN;
}

 /*
  * Specials
  */
<expr>"true"  { return T_TRUE; }
<expr>"false" { return T_FALSE; }

 /*
  * Digits
  */
<expr>\-?[0-9]+ {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext);
    return T_DIGIT;
}

 /*
  * Identifiers
  */
<expr>{TOKEN} {
    yylval->cpVal = apr_pstrdup(yyextra->pool, yytext);
    return T_ID;
}

 /*
  * These are parts of the grammar and are returned as is
  */
<expr>[(){},] {
    return yytext[0];
}

 /*
  * Anything else is an error
  */
<INITIAL,expr>{ANY} {
    PERROR_CHAR("Parse error near character ", yytext[0]);
}

%%


