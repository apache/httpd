#ifndef YYERRCODE
#define YYERRCODE 256
#endif

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
typedef union {
    char     *cpVal;
    ssl_expr *exVal;
} YYSTYPE;
extern YYSTYPE ssl_expr_yylval;
