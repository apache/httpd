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
 *  ssl_expr_scan.l
 *  Expression Scanner
 */
                             /* ``Killing for peace is 
                                  like fucking for virginity.''
                                             -- Unknown  */

/*  _________________________________________________________________
**
**  Expression Scanner
**  _________________________________________________________________
*/

%{
#include "ssl_private.h"

#include "ssl_expr_parse.h"

#define YY_NO_UNPUT 1
int yyinput(char *buf, int max_size);

#undef  YY_INPUT
#define YY_INPUT(buf,result,max_size) \
    (result = yyinput(buf, max_size))

#define MAX_STR_LEN 2048
%}

%pointer
/* %option stack */
%option never-interactive
%option noyywrap
%x str
%x regex regex_flags

%%
  
  char  caStr[MAX_STR_LEN];
  char *cpStr = NULL;
  char  caRegex[MAX_STR_LEN];
  char *cpRegex = NULL;
  char  cRegexDel = NUL;

 /*
  * Whitespaces
  */
[ \t\n]+ { 
    /* NOP */
}

 /*
  * C-style strings ("...")
  */
\" {
    cpStr = caStr;
    BEGIN(str);
}
<str>\" {
    BEGIN(INITIAL);
    *cpStr = NUL;
    yylval.cpVal = apr_pstrdup(ssl_expr_info.pool, caStr);
    return T_STRING;
}
<str>\n {
    yyerror("Unterminated string");
}
<str>\\[0-7]{1,3} {
    int result;

    (void)sscanf(yytext+1, "%o", &result);
    if (result > 0xff)
        yyerror("Escape sequence out of bound");
    else
        *cpStr++ = result;
}
<str>\\[0-9]+ {
    yyerror("Bad escape sequence");
}
<str>\\n { *cpStr++ = '\n'; }
<str>\\r { *cpStr++ = '\r'; }
<str>\\t { *cpStr++ = '\t'; }
<str>\\b { *cpStr++ = '\b'; }
<str>\\f { *cpStr++ = '\f'; }
<str>\\(.|\n) {
    *cpStr++ = yytext[1];
}
<str>[^\\\n\"]+ {
    char *cp = yytext;
    while (*cp != NUL)
        *cpStr++ = *cp++;
}
<str>. {
    *cpStr++ = yytext[1];
}

 /*
  * Regular Expression
  */
"m". {
    cRegexDel = yytext[1];
    cpRegex = caRegex;
    BEGIN(regex);
}
<regex>.|\n {
    if (yytext[0] == cRegexDel) {
        *cpRegex = NUL;
        BEGIN(regex_flags);
    }
    else {
        *cpRegex++ = yytext[0];
    }
}
<regex_flags>i {
    yylval.cpVal = apr_pstrdup(ssl_expr_info.pool, caRegex);
    BEGIN(INITIAL);
    return T_REGEX_I;
}
<regex_flags>.|\n {
    yylval.cpVal = apr_pstrdup(ssl_expr_info.pool, caRegex);
    yyless(0);
    BEGIN(INITIAL);
    return T_REGEX;
}
<regex_flags><<EOF>> {
    yylval.cpVal = apr_pstrdup(ssl_expr_info.pool, caRegex);
    BEGIN(INITIAL);
    return T_REGEX;
}

 /*
  * Operators
  */
"eq"  { return T_OP_EQ; }
"=="  { return T_OP_EQ; }
"ne"  { return T_OP_NE; }
"!="  { return T_OP_NE; }
"lt"  { return T_OP_LT; }
"<"   { return T_OP_LT; }
"le"  { return T_OP_LE; }
"<="  { return T_OP_LE; }
"gt"  { return T_OP_GT; }
">"   { return T_OP_GT; }
"ge"  { return T_OP_GE; }
">="  { return T_OP_GE; }
"=~"  { return T_OP_REG; }
"!~"  { return T_OP_NRE; }
"and" { return T_OP_AND; }
"&&"  { return T_OP_AND; }
"or"  { return T_OP_OR; }
"||"  { return T_OP_OR; }
"not" { return T_OP_NOT; }
"!"   { return T_OP_NOT; }
"in"  { return T_OP_IN; }
[Oo][Ii][Dd] { return T_OP_OID; }

 /*
  * Functions
  */
"file" { return T_FUNC_FILE; }

 /*
  * Specials
  */
"true"  { return T_TRUE; }
"false" { return T_FALSE; }

 /*
  * Digits
  */
[0-9]+ {
    yylval.cpVal = apr_pstrdup(ssl_expr_info.pool, yytext);
    return T_DIGIT;
}

 /*
  * Identifiers
  */
[a-zA-Z][a-zA-Z0-9_:-]* {
    yylval.cpVal = apr_pstrdup(ssl_expr_info.pool, yytext);
    return T_ID;
}

 /*
  * Anything else is returned as is...
  */
.|\n { 
    return yytext[0];
}

%%

int yyinput(char *buf, int max_size)
{
    int n;

    if ((n = MIN(max_size, ssl_expr_info.inputbuf
                         + ssl_expr_info.inputlen 
                         - ssl_expr_info.inputptr)) <= 0)
        return YY_NULL;
    memcpy(buf, ssl_expr_info.inputptr, n);
    ssl_expr_info.inputptr += n;
    return n;
}

