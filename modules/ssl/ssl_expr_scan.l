/*                      _             _ 
**  _ __ ___   ___   __| |    ___ ___| |  
** | '_ ` _ \ / _ \ / _` |   / __/ __| |  
** | | | | | | (_) | (_| |   \__ \__ \ | mod_ssl - Apache Interface to OpenSSL
** |_| |_| |_|\___/ \__,_|___|___/___/_| http://www.modssl.org/
**                      |_____|         
**  ssl_expr_scan.l
**  Expression Scanner
*/

/* ====================================================================
 * Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by 
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * 4. The names "mod_ssl" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    rse@engelschall.com.
 *
 * 5. Products derived from this software may not be called "mod_ssl"
 *    nor may "mod_ssl" appear in their names without prior
 *    written permission of Ralf S. Engelschall.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by 
 *     Ralf S. Engelschall <rse@engelschall.com> for use in the
 *     mod_ssl project (http://www.modssl.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
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
#include "mod_ssl.h"

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
    yylval.cpVal = ap_pstrdup(ssl_expr_info.pool, caStr);
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
    yylval.cpVal = ap_pstrdup(ssl_expr_info.pool, caRegex);
    BEGIN(INITIAL);
    return T_REGEX_I;
}
<regex_flags>.|\n {
    yylval.cpVal = ap_pstrdup(ssl_expr_info.pool, caRegex);
    yyless(0);
    BEGIN(INITIAL);
    return T_REGEX;
}
<regex_flags><<EOF>> {
    yylval.cpVal = ap_pstrdup(ssl_expr_info.pool, caRegex);
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
    yylval.cpVal = ap_pstrdup(ssl_expr_info.pool, yytext);
    return T_DIGIT;
}

 /*
  * Identifiers
  */
[a-zA-Z][a-zA-Z0-9_:-]* {
    yylval.cpVal = ap_pstrdup(ssl_expr_info.pool, yytext);
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

