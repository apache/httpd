
Digit		[0-9]
Literal		[a-zA-Z_]
Hex		[a-fA-F0-9]
Exp		[Ee][+-]?{Digit}+
FS		(f|F|l|L)
IS		(u|U|l|L)+

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "tokens.h"

extern int opt_directives;

static void string(void);
static void comment(void);
static int directive(void);

static int yywrap(void) { return 1; }
%}

%%

"/*"					{ comment(); return COMMENT; }
"#"					{ return directive(); }

"auto"					{ return KEYWORD; }
"break"					{ return KEYWORD; }
"case"					{ return KEYWORD; }
"char"					{ return KEYWORD; }
"const"					{ return KEYWORD; }
"continue"				{ return KEYWORD; }
"default"				{ return KEYWORD; }
"do"					{ return KEYWORD; }
"double"				{ return KEYWORD; }
"else"					{ return KEYWORD; }
"enum"					{ return KEYWORD; }
"extern"				{ return KEYWORD; }
"float"					{ return KEYWORD; }
"for"					{ return KEYWORD; }
"goto"					{ return KEYWORD; }
"if"					{ return KEYWORD; }
"int"					{ return KEYWORD; }
"long"					{ return KEYWORD; }
"register"				{ return KEYWORD; }
"return"				{ return KEYWORD; }
"short"					{ return KEYWORD; }
"signed"				{ return KEYWORD; }
"sizeof"				{ return KEYWORD; }
"static"				{ return KEYWORD; }
"struct"				{ return KEYWORD; }
"switch"				{ return KEYWORD; }
"typedef"				{ return KEYWORD; }
"union"					{ return KEYWORD; }
"unsigned"				{ return KEYWORD; }
"void"					{ return KEYWORD; }
"volatile"				{ return KEYWORD; }
"while"					{ return KEYWORD; }

{Literal}({Literal}|{Digit})*		{ return IDENTIFIER; }

0[xX]{Hex}+{IS}?			{ return CONSTANT; }
0{Digit}+{IS}?				{ return CONSTANT; }
{Digit}+{IS}				{ return CONSTANT; }
{Digit}+				{ return CONSTANT; }
'(\\.|[^\\'])+'				{ return CHARACTER; }

{Digit}+{Exp}{FS}?			{ return CONSTANT; }
{Digit}*"."{Digit}+({Exp})?{FS}?	{ return CONSTANT; }
{Digit}+"."{Digit}*({Exp})?{FS}?	{ return CONSTANT; }

"\""					{ string(); return STRING; }

">>="					{ return OPERATOR; }
"<<="					{ return OPERATOR; }
"+="					{ return OPERATOR; }
"-="					{ return OPERATOR; }
"*="					{ return OPERATOR; }
"/="					{ return OPERATOR; }
"%="					{ return OPERATOR; }
"&="					{ return OPERATOR; }
"^="					{ return OPERATOR; }
"|="					{ return OPERATOR; }
">>"					{ return OPERATOR; }
"<<"					{ return OPERATOR; }
"++"					{ return OPERATOR; }
"--"					{ return OPERATOR; }
"->"					{ return OPERATOR; }
"&&"					{ return OPERATOR; }
"||"					{ return OPERATOR; }
"<="					{ return OPERATOR; }
">="					{ return OPERATOR; }
"=="					{ return OPERATOR; }
"!="					{ return OPERATOR; }
"..."					{ return ELLIPSIS; }
";"					{ return ';'; }
"{"					{ return '{'; }
"}"					{ return '}'; }
","					{ return ','; }
":"					{ return ':'; }
"="					{ return '='; }
"("					{ return '('; }
")"					{ return ')'; }
"["					{ return '['; }
"]"					{ return ']'; }
"."					{ return '.'; }
"&"					{ return '&'; }
"!"					{ return '!'; }
"~"					{ return '~'; }
"-"					{ return '-'; }
"+"					{ return '+'; }
"*"					{ return '*'; }
"/"					{ return '/'; }
"%"					{ return '%'; }
"<"					{ return '<'; }
">"					{ return '>'; }
"^"					{ return '^'; }
"|"					{ return '|'; }
"?"					{ return '?'; }

[ \t\v\n\f]				{ return yytext[0]; }
.					{ return yytext[0]; }

%%

char *token_buffer;

static int maxtoken;

void
init_lex(void)
{
	maxtoken = 40;
	token_buffer = (char *)xmalloc(maxtoken + 1);
}

void
done_lex(void)
{
	free(token_buffer);
}

static char *
extend_token_buffer(char *p)
{
	int offset = p - token_buffer;

	maxtoken = maxtoken * 2 + 10;

	token_buffer = (char *)xrealloc(token_buffer, maxtoken + 2);

	return token_buffer + offset;
}

static void
string(void)
{
	char *p;
	int c;

	p = token_buffer;
	*p++ = '"';
	while ((c = input()) != EOF && c != '"') {
		if (p >= token_buffer + maxtoken)
			p = extend_token_buffer(p);
		*p++ = c;
		if (c == '\\')
			*p++ = input();
	}
	if (c == EOF)
		errx(1, "unexpected end of file in string");
	*p++ = '"';
	*p = '\0';
}

static void
comment(void)
{
	char *p;
	int c;

	p = token_buffer;
	*p++ = '/';
	*p++ = '*';
	while ((c = input()) != EOF) {
resync:		if (p >= token_buffer + maxtoken)
			p = extend_token_buffer(p);
		*p++ = c;
		if (c == '*')
			if ((c = input()) == '/') {
				*p++ = c;
				*p = '\0';
				return;
			} else
				goto resync;
	}
	*p = '\0';
}

static int
directive(void)
{
	char *p;
	int c;

	if (opt_directives)
		return '#';

	p = token_buffer;
	*p++ = '#';

	while ((c = input()) != EOF && c != '\n') {
		if (p >= token_buffer + maxtoken)
			p = extend_token_buffer(p);
		*p++ = c;
		if (c == '\\')
			*p++ = input();
	}
	*p++ = c;
	*p = '\0';
	return DIRECTIVE;
}
