#ifndef lint
static char const 
ssl_expr_yyrcsid[] = "$FreeBSD: src/usr.bin/yacc/skeleton.c,v 1.28 2000/01/17 02:04:06 bde Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX ssl_expr_yylex()
#define YYEMPTY -1
#define ssl_expr_yyclearin (ssl_expr_yychar=(YYEMPTY))
#define ssl_expr_yyerrok (ssl_expr_yyerrflag=0)
#define YYRECOVERING() (ssl_expr_yyerrflag!=0)
static int ssl_expr_yygrowstack();
#define YYPREFIX "ssl_expr_yy"
#line 72 "ssl_expr_parse.y"
#include "mod_ssl.h"
#line 75 "ssl_expr_parse.y"
typedef union {
    char     *cpVal;
    ssl_expr *exVal;
} YYSTYPE;
#line 24 "y.tab.c"
#define YYERRCODE 256
#define T_TRUE 257
#define T_FALSE 258
#define T_DIGIT 259
#define T_ID 260
#define T_STRING 261
#define T_REGEX 262
#define T_REGEX_I 263
#define T_FUNC_FILE 264
#define T_OP_EQ 265
#define T_OP_NE 266
#define T_OP_LT 267
#define T_OP_LE 268
#define T_OP_GT 269
#define T_OP_GE 270
#define T_OP_REG 271
#define T_OP_NRE 272
#define T_OP_IN 273
#define T_OP_OR 274
#define T_OP_AND 275
#define T_OP_NOT 276
const short ssl_expr_yylhs[] = {                                        -1,
    0,    1,    1,    1,    1,    1,    1,    1,    2,    2,
    2,    2,    2,    2,    2,    2,    2,    5,    5,    6,
    6,    6,    6,    4,    4,    3,
};
const short ssl_expr_yylen[] = {                                         2,
    1,    1,    1,    2,    3,    3,    1,    3,    3,    3,
    3,    3,    3,    3,    5,    3,    3,    1,    3,    1,
    1,    4,    1,    1,    1,    4,
};
const short ssl_expr_yydefred[] = {                                      0,
    2,    3,   20,   21,    0,    0,    0,    0,    0,    0,
    7,   23,    0,    0,    4,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    8,
    0,    0,    6,    9,   10,   11,   12,   13,   14,   24,
   25,   16,   17,    0,   26,   22,    0,   18,   15,    0,
   19,
};
const short ssl_expr_yydgoto[] = {                                       9,
   10,   11,   12,   42,   47,   13,
};
const short ssl_expr_yysindex[] = {                                    -37,
    0,    0,    0,    0,  -35,  -37,  -37,  -99,    0, -247,
    0,    0, -250, -229,    0,  -39, -227,  -37,  -37,  -33,
  -33,  -33,  -33,  -33,  -33, -233, -233,  -89,   -6,    0,
  -87, -239,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  -33,    0,    0,  -38,    0,    0,  -33,
    0,
};
const short ssl_expr_yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   39,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    1,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,
};
const short ssl_expr_yygindex[] = {                                      0,
    7,    0,    0,   13,    0,  -13,
};
#define YYTABLESIZE 275
const short ssl_expr_yytable[] = {                                       8,
    5,   30,    7,    8,   14,   50,   34,   35,   36,   37,
   38,   39,   15,   16,   20,   21,   22,   23,   24,   25,
   26,   27,   28,   17,   32,   33,   18,   19,   40,   41,
   48,   29,   31,   44,   45,   19,   51,   46,    1,   43,
    0,    5,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   49,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    1,
    2,    3,    0,    4,    0,    3,    5,    4,    0,    0,
    5,    0,    0,    0,   18,   19,    0,    0,    6,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    5,
};
const short ssl_expr_yycheck[] = {                                      37,
    0,   41,   40,   37,   40,   44,   20,   21,   22,   23,
   24,   25,    6,    7,  265,  266,  267,  268,  269,  270,
  271,  272,  273,  123,   18,   19,  274,  275,  262,  263,
   44,  261,  260,  123,   41,  275,   50,  125,    0,   27,
   -1,   41,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  125,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  257,
  258,  259,   -1,  261,   -1,  259,  264,  261,   -1,   -1,
  264,   -1,   -1,   -1,  274,  275,   -1,   -1,  276,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  274,
};
#define YYFINAL 9
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 276
#if YYDEBUG
const char * const ssl_expr_yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,"'%'",0,0,"'('","')'",0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"T_TRUE",
"T_FALSE","T_DIGIT","T_ID","T_STRING","T_REGEX","T_REGEX_I","T_FUNC_FILE",
"T_OP_EQ","T_OP_NE","T_OP_LT","T_OP_LE","T_OP_GT","T_OP_GE","T_OP_REG",
"T_OP_NRE","T_OP_IN","T_OP_OR","T_OP_AND","T_OP_NOT",
};
const char * const ssl_expr_yyrule[] = {
"$accept : root",
"root : expr",
"expr : T_TRUE",
"expr : T_FALSE",
"expr : T_OP_NOT expr",
"expr : expr T_OP_OR expr",
"expr : expr T_OP_AND expr",
"expr : comparison",
"expr : '(' expr ')'",
"comparison : word T_OP_EQ word",
"comparison : word T_OP_NE word",
"comparison : word T_OP_LT word",
"comparison : word T_OP_LE word",
"comparison : word T_OP_GT word",
"comparison : word T_OP_GE word",
"comparison : word T_OP_IN '{' words '}'",
"comparison : word T_OP_REG regex",
"comparison : word T_OP_NRE regex",
"words : word",
"words : words ',' word",
"word : T_DIGIT",
"word : T_STRING",
"word : '%' '{' T_ID '}'",
"word : funccall",
"regex : T_REGEX",
"regex : T_REGEX_I",
"funccall : T_FUNC_FILE '(' T_STRING ')'",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int ssl_expr_yydebug;
int ssl_expr_yynerrs;
int ssl_expr_yyerrflag;
int ssl_expr_yychar;
short *ssl_expr_yyssp;
YYSTYPE *ssl_expr_yyvsp;
YYSTYPE ssl_expr_yyval;
YYSTYPE ssl_expr_yylval;
short *ssl_expr_yyss;
short *ssl_expr_yysslim;
YYSTYPE *ssl_expr_yyvs;
int ssl_expr_yystacksize;
#line 180 "ssl_expr_parse.y"

int ssl_expr_yyerror(char *s)
{
    ssl_expr_error = s;
    return 2;
}

#line 230 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int ssl_expr_yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = ssl_expr_yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = ssl_expr_yyssp - ssl_expr_yyss;
    newss = ssl_expr_yyss ? (short *)realloc(ssl_expr_yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    ssl_expr_yyss = newss;
    ssl_expr_yyssp = newss + i;
    newvs = ssl_expr_yyvs ? (YYSTYPE *)realloc(ssl_expr_yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    ssl_expr_yyvs = newvs;
    ssl_expr_yyvsp = newvs + i;
    ssl_expr_yystacksize = newsize;
    ssl_expr_yysslim = ssl_expr_yyss + newsize - 1;
    return 0;
}

#define YYABORT goto ssl_expr_yyabort
#define YYREJECT goto ssl_expr_yyabort
#define YYACCEPT goto ssl_expr_yyaccept
#define YYERROR goto ssl_expr_yyerrlab

#ifndef YYPARSE_PARAM
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG void
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif	/* ANSI-C/C++ */
#else	/* YYPARSE_PARAM */
#ifndef YYPARSE_PARAM_TYPE
#define YYPARSE_PARAM_TYPE void *
#endif
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG YYPARSE_PARAM_TYPE YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL YYPARSE_PARAM_TYPE YYPARSE_PARAM;
#endif	/* ANSI-C/C++ */
#endif	/* ! YYPARSE_PARAM */

int
ssl_expr_yyparse (YYPARSE_PARAM_ARG)
    YYPARSE_PARAM_DECL
{
    register int ssl_expr_yym, ssl_expr_yyn, ssl_expr_yystate;
#if YYDEBUG
    register const char *ssl_expr_yys;

    if ((ssl_expr_yys = getenv("YYDEBUG")))
    {
        ssl_expr_yyn = *ssl_expr_yys;
        if (ssl_expr_yyn >= '0' && ssl_expr_yyn <= '9')
            ssl_expr_yydebug = ssl_expr_yyn - '0';
    }
#endif

    ssl_expr_yynerrs = 0;
    ssl_expr_yyerrflag = 0;
    ssl_expr_yychar = (-1);

    if (ssl_expr_yyss == NULL && ssl_expr_yygrowstack()) goto ssl_expr_yyoverflow;
    ssl_expr_yyssp = ssl_expr_yyss;
    ssl_expr_yyvsp = ssl_expr_yyvs;
    *ssl_expr_yyssp = ssl_expr_yystate = 0;

ssl_expr_yyloop:
    if ((ssl_expr_yyn = ssl_expr_yydefred[ssl_expr_yystate])) goto ssl_expr_yyreduce;
    if (ssl_expr_yychar < 0)
    {
        if ((ssl_expr_yychar = ssl_expr_yylex()) < 0) ssl_expr_yychar = 0;
#if YYDEBUG
        if (ssl_expr_yydebug)
        {
            ssl_expr_yys = 0;
            if (ssl_expr_yychar <= YYMAXTOKEN) ssl_expr_yys = ssl_expr_yyname[ssl_expr_yychar];
            if (!ssl_expr_yys) ssl_expr_yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, ssl_expr_yystate, ssl_expr_yychar, ssl_expr_yys);
        }
#endif
    }
    if ((ssl_expr_yyn = ssl_expr_yysindex[ssl_expr_yystate]) && (ssl_expr_yyn += ssl_expr_yychar) >= 0 &&
            ssl_expr_yyn <= YYTABLESIZE && ssl_expr_yycheck[ssl_expr_yyn] == ssl_expr_yychar)
    {
#if YYDEBUG
        if (ssl_expr_yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, ssl_expr_yystate, ssl_expr_yytable[ssl_expr_yyn]);
#endif
        if (ssl_expr_yyssp >= ssl_expr_yysslim && ssl_expr_yygrowstack())
        {
            goto ssl_expr_yyoverflow;
        }
        *++ssl_expr_yyssp = ssl_expr_yystate = ssl_expr_yytable[ssl_expr_yyn];
        *++ssl_expr_yyvsp = ssl_expr_yylval;
        ssl_expr_yychar = (-1);
        if (ssl_expr_yyerrflag > 0)  --ssl_expr_yyerrflag;
        goto ssl_expr_yyloop;
    }
    if ((ssl_expr_yyn = ssl_expr_yyrindex[ssl_expr_yystate]) && (ssl_expr_yyn += ssl_expr_yychar) >= 0 &&
            ssl_expr_yyn <= YYTABLESIZE && ssl_expr_yycheck[ssl_expr_yyn] == ssl_expr_yychar)
    {
        ssl_expr_yyn = ssl_expr_yytable[ssl_expr_yyn];
        goto ssl_expr_yyreduce;
    }
    if (ssl_expr_yyerrflag) goto ssl_expr_yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto ssl_expr_yynewerror;
#endif
ssl_expr_yynewerror:
    ssl_expr_yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto ssl_expr_yyerrlab;
#endif
ssl_expr_yyerrlab:
    ++ssl_expr_yynerrs;
ssl_expr_yyinrecovery:
    if (ssl_expr_yyerrflag < 3)
    {
        ssl_expr_yyerrflag = 3;
        for (;;)
        {
            if ((ssl_expr_yyn = ssl_expr_yysindex[*ssl_expr_yyssp]) && (ssl_expr_yyn += YYERRCODE) >= 0 &&
                    ssl_expr_yyn <= YYTABLESIZE && ssl_expr_yycheck[ssl_expr_yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (ssl_expr_yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *ssl_expr_yyssp, ssl_expr_yytable[ssl_expr_yyn]);
#endif
                if (ssl_expr_yyssp >= ssl_expr_yysslim && ssl_expr_yygrowstack())
                {
                    goto ssl_expr_yyoverflow;
                }
                *++ssl_expr_yyssp = ssl_expr_yystate = ssl_expr_yytable[ssl_expr_yyn];
                *++ssl_expr_yyvsp = ssl_expr_yylval;
                goto ssl_expr_yyloop;
            }
            else
            {
#if YYDEBUG
                if (ssl_expr_yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *ssl_expr_yyssp);
#endif
                if (ssl_expr_yyssp <= ssl_expr_yyss) goto ssl_expr_yyabort;
                --ssl_expr_yyssp;
                --ssl_expr_yyvsp;
            }
        }
    }
    else
    {
        if (ssl_expr_yychar == 0) goto ssl_expr_yyabort;
#if YYDEBUG
        if (ssl_expr_yydebug)
        {
            ssl_expr_yys = 0;
            if (ssl_expr_yychar <= YYMAXTOKEN) ssl_expr_yys = ssl_expr_yyname[ssl_expr_yychar];
            if (!ssl_expr_yys) ssl_expr_yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, ssl_expr_yystate, ssl_expr_yychar, ssl_expr_yys);
        }
#endif
        ssl_expr_yychar = (-1);
        goto ssl_expr_yyloop;
    }
ssl_expr_yyreduce:
#if YYDEBUG
    if (ssl_expr_yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, ssl_expr_yystate, ssl_expr_yyn, ssl_expr_yyrule[ssl_expr_yyn]);
#endif
    ssl_expr_yym = ssl_expr_yylen[ssl_expr_yyn];
    ssl_expr_yyval = ssl_expr_yyvsp[1-ssl_expr_yym];
    switch (ssl_expr_yyn)
    {
case 1:
#line 118 "ssl_expr_parse.y"
{ ssl_expr_info.expr = ssl_expr_yyvsp[0].exVal; }
break;
case 2:
#line 121 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_True,  NULL, NULL); }
break;
case 3:
#line 122 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_False, NULL, NULL); }
break;
case 4:
#line 123 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_Not,   ssl_expr_yyvsp[0].exVal,   NULL); }
break;
case 5:
#line 124 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_Or,    ssl_expr_yyvsp[-2].exVal,   ssl_expr_yyvsp[0].exVal);   }
break;
case 6:
#line 125 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_And,   ssl_expr_yyvsp[-2].exVal,   ssl_expr_yyvsp[0].exVal);   }
break;
case 7:
#line 126 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_Comp,  ssl_expr_yyvsp[0].exVal,   NULL); }
break;
case 8:
#line 127 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_yyvsp[-1].exVal; }
break;
case 9:
#line 130 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_EQ,  ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 10:
#line 131 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_NE,  ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 11:
#line 132 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_LT,  ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 12:
#line 133 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_LE,  ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 13:
#line 134 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_GT,  ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 14:
#line 135 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_GE,  ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 15:
#line 136 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_IN,  ssl_expr_yyvsp[-4].exVal, ssl_expr_yyvsp[-1].exVal); }
break;
case 16:
#line 137 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_REG, ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 17:
#line 138 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_NRE, ssl_expr_yyvsp[-2].exVal, ssl_expr_yyvsp[0].exVal); }
break;
case 18:
#line 141 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_ListElement, ssl_expr_yyvsp[0].exVal, NULL); }
break;
case 19:
#line 142 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_ListElement, ssl_expr_yyvsp[0].exVal, ssl_expr_yyvsp[-2].exVal);   }
break;
case 20:
#line 145 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_Digit,  ssl_expr_yyvsp[0].cpVal, NULL); }
break;
case 21:
#line 146 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_String, ssl_expr_yyvsp[0].cpVal, NULL); }
break;
case 22:
#line 147 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_make(op_Var,    ssl_expr_yyvsp[-1].cpVal, NULL); }
break;
case 23:
#line 148 "ssl_expr_parse.y"
{ ssl_expr_yyval.exVal = ssl_expr_yyvsp[0].exVal; }
break;
case 24:
#line 151 "ssl_expr_parse.y"
{ 
                regex_t *regex;
                if ((regex = ap_pregcomp(ssl_expr_info.pool, ssl_expr_yyvsp[0].cpVal, 
                                         REG_EXTENDED|REG_NOSUB)) == NULL) {
                    ssl_expr_error = "Failed to compile regular expression";
                    YYERROR;
                    regex = NULL;
                }
                ssl_expr_yyval.exVal = ssl_expr_make(op_Regex, regex, NULL);
            }
break;
case 25:
#line 161 "ssl_expr_parse.y"
{
                regex_t *regex;
                if ((regex = ap_pregcomp(ssl_expr_info.pool, ssl_expr_yyvsp[0].cpVal, 
                                         REG_EXTENDED|REG_NOSUB|REG_ICASE)) == NULL) {
                    ssl_expr_error = "Failed to compile regular expression";
                    YYERROR;
                    regex = NULL;
                }
                ssl_expr_yyval.exVal = ssl_expr_make(op_Regex, regex, NULL);
            }
break;
case 26:
#line 173 "ssl_expr_parse.y"
{ 
               ssl_expr *args = ssl_expr_make(op_ListElement, ssl_expr_yyvsp[-1].cpVal, NULL);
               ssl_expr_yyval.exVal = ssl_expr_make(op_Func, "file", args);
            }
break;
#line 550 "y.tab.c"
    }
    ssl_expr_yyssp -= ssl_expr_yym;
    ssl_expr_yystate = *ssl_expr_yyssp;
    ssl_expr_yyvsp -= ssl_expr_yym;
    ssl_expr_yym = ssl_expr_yylhs[ssl_expr_yyn];
    if (ssl_expr_yystate == 0 && ssl_expr_yym == 0)
    {
#if YYDEBUG
        if (ssl_expr_yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        ssl_expr_yystate = YYFINAL;
        *++ssl_expr_yyssp = YYFINAL;
        *++ssl_expr_yyvsp = ssl_expr_yyval;
        if (ssl_expr_yychar < 0)
        {
            if ((ssl_expr_yychar = ssl_expr_yylex()) < 0) ssl_expr_yychar = 0;
#if YYDEBUG
            if (ssl_expr_yydebug)
            {
                ssl_expr_yys = 0;
                if (ssl_expr_yychar <= YYMAXTOKEN) ssl_expr_yys = ssl_expr_yyname[ssl_expr_yychar];
                if (!ssl_expr_yys) ssl_expr_yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, ssl_expr_yychar, ssl_expr_yys);
            }
#endif
        }
        if (ssl_expr_yychar == 0) goto ssl_expr_yyaccept;
        goto ssl_expr_yyloop;
    }
    if ((ssl_expr_yyn = ssl_expr_yygindex[ssl_expr_yym]) && (ssl_expr_yyn += ssl_expr_yystate) >= 0 &&
            ssl_expr_yyn <= YYTABLESIZE && ssl_expr_yycheck[ssl_expr_yyn] == ssl_expr_yystate)
        ssl_expr_yystate = ssl_expr_yytable[ssl_expr_yyn];
    else
        ssl_expr_yystate = ssl_expr_yydgoto[ssl_expr_yym];
#if YYDEBUG
    if (ssl_expr_yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *ssl_expr_yyssp, ssl_expr_yystate);
#endif
    if (ssl_expr_yyssp >= ssl_expr_yysslim && ssl_expr_yygrowstack())
    {
        goto ssl_expr_yyoverflow;
    }
    *++ssl_expr_yyssp = ssl_expr_yystate;
    *++ssl_expr_yyvsp = ssl_expr_yyval;
    goto ssl_expr_yyloop;
ssl_expr_yyoverflow:
    ssl_expr_yyerror("yacc stack overflow");
ssl_expr_yyabort:
    return (1);
ssl_expr_yyaccept:
    return (0);
}
