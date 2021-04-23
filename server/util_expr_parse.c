/* A Bison parser, made by GNU Bison 3.0.5.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.5"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         ap_expr_yyparse
#define yylex           ap_expr_yylex
#define yyerror         ap_expr_yyerror
#define yydebug         ap_expr_yydebug
#define yynerrs         ap_expr_yynerrs


/* Copy the first part of user declarations.  */
#line 31 "util_expr_parse.y" /* yacc.c:339  */

#include "util_expr_private.h"

#line 76 "util_expr_parse.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif

/* In a future release of Bison, this section will be replaced
   by #include "util_expr_parse.h".  */
#ifndef YY_AP_EXPR_YY_UTIL_EXPR_PARSE_H_INCLUDED
# define YY_AP_EXPR_YY_UTIL_EXPR_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int ap_expr_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    T_TRUE = 258,
    T_FALSE = 259,
    T_EXPR_BOOL = 260,
    T_EXPR_STRING = 261,
    T_ERROR = 262,
    T_DIGIT = 263,
    T_ID = 264,
    T_STRING = 265,
    T_REGEX = 266,
    T_REGSUB = 267,
    T_REG_MATCH = 268,
    T_REG_SUBST = 269,
    T_REG_FLAGS = 270,
    T_BACKREF = 271,
    T_OP_UNARY = 272,
    T_OP_BINARY = 273,
    T_STR_BEGIN = 274,
    T_STR_END = 275,
    T_VAR_BEGIN = 276,
    T_VAR_END = 277,
    T_VAREXP_BEGIN = 278,
    T_VAREXP_END = 279,
    T_OP_EQ = 280,
    T_OP_NE = 281,
    T_OP_LT = 282,
    T_OP_LE = 283,
    T_OP_GT = 284,
    T_OP_GE = 285,
    T_OP_REG = 286,
    T_OP_NRE = 287,
    T_OP_IN = 288,
    T_OP_STR_EQ = 289,
    T_OP_STR_NE = 290,
    T_OP_STR_LT = 291,
    T_OP_STR_LE = 292,
    T_OP_STR_GT = 293,
    T_OP_STR_GE = 294,
    T_OP_CONCAT = 295,
    T_OP_JOIN = 296,
    T_OP_SPLIT = 297,
    T_OP_SUB = 298,
    T_OP_OR = 299,
    T_OP_AND = 300,
    T_OP_NOT = 301
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 35 "util_expr_parse.y" /* yacc.c:355  */

    char      *cpVal;
    ap_expr_t *exVal;
    int        num;

#line 169 "util_expr_parse.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int ap_expr_yyparse (ap_expr_parse_ctx_t *ctx);

#endif /* !YY_AP_EXPR_YY_UTIL_EXPR_PARSE_H_INCLUDED  */

/* Copy the second part of user declarations.  */
#line 118 "util_expr_parse.y" /* yacc.c:358  */

#include "util_expr_private.h"
#define yyscanner ctx->scanner

int ap_expr_yylex(YYSTYPE *lvalp, void *scanner);

#line 191 "util_expr_parse.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  31
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   274

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  53
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  18
/* YYNRULES -- Number of rules.  */
#define YYNRULES  71
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  154

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   301

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      47,    48,     2,     2,    52,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    51,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    49,     2,    50,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint8 yyrline[] =
{
       0,   128,   128,   129,   130,   133,   134,   135,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   150,   151,
     152,   153,   154,   155,   156,   157,   158,   159,   160,   161,
     162,   163,   164,   167,   168,   169,   170,   171,   172,   173,
     174,   175,   178,   179,   180,   181,   184,   185,   188,   189,
     190,   191,   192,   195,   196,   199,   203,   204,   207,   208,
     209,   210,   213,   214,   215,   216,   219,   220,   223,   232,
     241,   242
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 1
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "\"true\"", "\"false\"",
  "\"boolean expression\"", "\"string expression\"", "\"error token\"",
  "\"number\"", "\"identifier\"", "\"string literal\"",
  "\"start of matching regex\"", "\"start of substitution regex\"",
  "\"pattern of the regex\"", "\"substitution of the regex\"",
  "\"pattern flags of the regex\"", "\"regex back reference\"",
  "\"unary operator\"", "\"binary operator\"", "\"start of string\"",
  "\"end of string\"", "\"start of variable name\"",
  "\"end of variable name\"", "\"start of variable expression\"",
  "\"end of variable expression\"", "\"integer equal\"",
  "\"integer not equal\"", "\"integer less than\"",
  "\"integer less or equal\"", "\"integer greater than\"",
  "\"integer greater or equal\"", "\"regex match\"", "\"regex non-match\"",
  "\"contained in\"", "\"string equal\"", "\"string not equal\"",
  "\"string less than\"", "\"string less or equal\"",
  "\"string greater than\"", "\"string greater or equal\"",
  "\"string concatenation\"", "\"join operator\"", "\"split operator\"",
  "\"substitute operator\"", "\"logical or\"", "\"logical and\"",
  "\"logical not\"", "'('", "')'", "'{'", "'}'", "':'", "','", "$accept",
  "cond", "comp", "strfunc", "listfunc", "list", "words", "word", "string",
  "substr", "var", "regex", "regsub", "regany", "split", "join", "sub",
  "expr", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,    40,    41,   123,
     125,    58,    44
};
# endif

#define YYPACT_NINF -38

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-38)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     148,   126,   101,   -38,     9,   -38,   -38,   -38,   -38,   -33,
     -38,   171,    93,    22,   126,    52,    -4,   126,   126,    18,
     -38,   -38,   170,   -38,   -38,   -38,   -38,   -38,   136,   -38,
     -38,   -38,   171,   171,     1,   -38,    66,     2,    -5,   220,
      32,     5,    55,   171,   -38,    13,   -38,    77,    81,    46,
     -38,    96,   195,   126,   126,   171,   171,   171,   171,   171,
     171,   171,    95,    95,    55,   171,   171,   171,   171,   171,
     171,   171,   -38,    83,   -22,   -25,   -38,   -38,   101,   -38,
     -38,   171,   135,    57,   -38,   -38,   104,    55,   -14,   110,
     -27,   171,   101,   112,   171,   -38,   -38,   117,   -38,     1,
       1,     1,     1,     1,     1,     1,   -38,   -38,   -38,     1,
       1,     1,     1,     1,     1,     1,   -38,   -38,   171,   116,
     -20,   151,   118,   142,   120,   -38,   171,   -38,     1,   251,
     171,     1,   -38,   -38,   -38,   -38,   142,   124,   142,   -38,
       1,   -38,    27,   -38,    44,   127,    48,   171,   -38,   -38,
     -38,   -38,    26,   -38
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,     0,     4,     0,     8,     9,    17,    33,     0,
      52,     0,     0,     0,     0,     0,     0,     0,     0,     3,
      13,    40,     0,    37,    39,    38,     7,    46,     2,     5,
      47,     1,     0,     0,    14,    34,     0,     0,     0,     0,
       0,     0,     0,     0,    43,    58,    42,     0,     0,     0,
      10,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     6,     0,     0,     0,    35,    48,     0,    50,
      51,     0,     0,     0,    70,    71,     0,     0,     0,     0,
      66,     0,     0,     0,     0,    16,    41,    11,    12,    15,
      18,    19,    20,    21,    22,    23,    30,    31,    32,    24,
      25,    26,    27,    28,    29,    36,    54,    53,     0,     0,
       0,     0,     0,     0,     0,    45,     0,    44,    60,     0,
       0,    56,    67,    49,    55,    68,     0,     0,     0,    62,
      64,    45,     0,    69,     0,     0,     0,     0,    61,    57,
      63,    65,     0,    53
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -38,    19,   -38,   -38,   -38,   -13,   -37,   -11,    -7,   -24,
      -1,    58,    -6,    91,   -38,   -38,   -38,   -38
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,    19,    20,    21,    44,   124,    73,    22,    28,    29,
      23,    84,    85,    86,    46,    24,    25,     4
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      34,    30,    45,    39,    72,    36,    89,    52,    47,    31,
      49,    30,    72,    71,    32,    71,    82,    47,    71,    79,
      71,    74,    75,    96,    77,   118,   117,    30,   134,    88,
     118,    37,    90,    38,   125,    30,    50,    51,   126,    53,
      54,    71,    93,    48,    99,   100,   101,   102,   103,   104,
     105,   108,    83,    78,   109,   110,   111,   112,   113,   114,
     115,    40,    53,    54,    40,    91,    71,    71,    82,    47,
     120,   119,    97,    98,   153,   148,    27,    30,   118,    81,
     128,   132,    10,   131,    71,   129,    76,    13,    71,    14,
      92,    30,   149,    47,    41,    72,   151,    41,    94,    42,
      26,    43,    87,    27,    43,    72,    82,    90,    26,    10,
     139,    27,   140,    35,    13,   142,    14,    10,    30,   144,
     106,   107,    13,   145,    14,   146,    27,    75,    30,     5,
       6,   116,    10,     7,     8,     9,   152,    13,   133,    14,
      53,    54,    10,    11,    95,    12,    27,    13,   121,    14,
       8,   137,    10,     1,     2,     3,   123,    13,    10,    14,
     127,    12,    54,    13,   130,    14,   135,    15,   141,    16,
     136,   147,    17,    18,   122,   150,     0,     0,     0,     8,
       9,     0,     0,    15,    41,    16,     0,    10,    55,   138,
      12,    43,    13,     0,    14,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,     0,    15,    55,    16,     0,     0,     0,    33,     0,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,     0,     0,    55,     0,
       0,     0,     0,    96,    80,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    27,     0,     0,     0,     0,   143,    10,     0,     0,
       0,     0,    13,     0,    14
};

static const yytype_int16 yycheck[] =
{
      11,     2,    15,    14,    28,    12,    43,    18,    12,     0,
      16,    12,    36,    40,    47,    40,    11,    12,    40,    24,
      40,    32,    33,    48,    22,    52,    48,    28,    48,    42,
      52,     9,    43,    14,    48,    36,    17,    18,    52,    44,
      45,    40,    48,    47,    55,    56,    57,    58,    59,    60,
      61,    64,    47,    51,    65,    66,    67,    68,    69,    70,
      71,     9,    44,    45,     9,    52,    40,    40,    11,    12,
      81,    78,    53,    54,    48,    48,    10,    78,    52,    47,
      91,   118,    16,    94,    40,    92,    20,    21,    40,    23,
      13,    92,    48,    12,    42,   119,    48,    42,    52,    47,
       7,    49,    47,    10,    49,   129,    11,   118,     7,    16,
     123,    10,   123,    20,    21,   126,    23,    16,   119,   130,
      62,    63,    21,   136,    23,   136,    10,   138,   129,     3,
       4,    48,    16,     7,     8,     9,   147,    21,    22,    23,
      44,    45,    16,    17,    48,    19,    10,    21,    13,    23,
       8,     9,    16,     5,     6,     7,    52,    21,    16,    23,
      50,    19,    45,    21,    52,    23,    15,    41,    48,    43,
      52,    47,    46,    47,    83,    48,    -1,    -1,    -1,     8,
       9,    -1,    -1,    41,    42,    43,    -1,    16,    18,    47,
      19,    49,    21,    -1,    23,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    -1,    41,    18,    43,    -1,    -1,    -1,    47,    -1,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    -1,    -1,    18,    -1,
      -1,    -1,    -1,    48,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    10,    -1,    -1,    -1,    -1,    15,    16,    -1,    -1,
      -1,    -1,    21,    -1,    23
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     5,     6,     7,    70,     3,     4,     7,     8,     9,
      16,    17,    19,    21,    23,    41,    43,    46,    47,    54,
      55,    56,    60,    63,    68,    69,     7,    10,    61,    62,
      63,     0,    47,    47,    60,    20,    61,     9,    54,    60,
       9,    42,    47,    49,    57,    58,    67,    12,    47,    65,
      54,    54,    60,    44,    45,    18,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,    62,    59,    60,    60,    20,    22,    51,    24,
      24,    47,    11,    47,    64,    65,    66,    47,    58,    59,
      60,    52,    13,    65,    52,    48,    48,    54,    54,    60,
      60,    60,    60,    60,    60,    60,    64,    64,    58,    60,
      60,    60,    60,    60,    60,    60,    48,    48,    52,    61,
      60,    13,    66,    52,    58,    48,    52,    50,    60,    61,
      52,    60,    59,    22,    48,    15,    52,     9,    47,    58,
      60,    48,    60,    15,    60,    58,    60,    47,    48,    48,
      48,    48,    60,    48
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    53,    70,    70,    70,    61,    61,    61,    54,    54,
      54,    54,    54,    54,    54,    54,    54,    54,    55,    55,
      55,    55,    55,    55,    55,    55,    55,    55,    55,    55,
      55,    55,    55,    60,    60,    60,    60,    60,    60,    60,
      60,    60,    58,    58,    58,    58,    62,    62,    63,    63,
      63,    63,    63,    56,    56,    57,    69,    69,    68,    68,
      68,    68,    67,    67,    67,    67,    59,    59,    64,    65,
      66,    66
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     2,     2,     1,     1,     2,     1,     1,     1,
       2,     3,     3,     1,     2,     3,     3,     1,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     1,     2,     3,     3,     1,     1,     1,
       1,     3,     1,     1,     3,     3,     1,     1,     3,     5,
       3,     3,     1,     4,     4,     4,     4,     6,     2,     4,
       4,     6,     4,     6,     4,     6,     1,     3,     3,     4,
       1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (ctx, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, ctx); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, ap_expr_parse_ctx_t *ctx)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (ctx);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, ap_expr_parse_ctx_t *ctx)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, ctx);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, ap_expr_parse_ctx_t *ctx)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              , ctx);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, ctx); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, ap_expr_parse_ctx_t *ctx)
{
  YYUSE (yyvaluep);
  YYUSE (ctx);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (ap_expr_parse_ctx_t *ctx)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, yyscanner);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 128 "util_expr_parse.y" /* yacc.c:1648  */
    { ctx->expr = (yyvsp[0].exVal); }
#line 1415 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 3:
#line 129 "util_expr_parse.y" /* yacc.c:1648  */
    { ctx->expr = (yyvsp[0].exVal); }
#line 1421 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 4:
#line 130 "util_expr_parse.y" /* yacc.c:1648  */
    { YYABORT; }
#line 1427 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 5:
#line 133 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1433 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 6:
#line 134 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_concat_make((yyvsp[-1].exVal), (yyvsp[0].exVal), ctx); }
#line 1439 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 7:
#line 135 "util_expr_parse.y" /* yacc.c:1648  */
    { YYABORT; }
#line 1445 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 8:
#line 138 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_True,        NULL, NULL, ctx); }
#line 1451 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 9:
#line 139 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_False,       NULL, NULL, ctx); }
#line 1457 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 10:
#line 140 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Not,         (yyvsp[0].exVal),   NULL, ctx); }
#line 1463 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 11:
#line 141 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Or,          (yyvsp[-2].exVal),   (yyvsp[0].exVal),   ctx); }
#line 1469 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 12:
#line 142 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_And,         (yyvsp[-2].exVal),   (yyvsp[0].exVal),   ctx); }
#line 1475 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 13:
#line 143 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Comp,        (yyvsp[0].exVal),   NULL, ctx); }
#line 1481 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 14:
#line 144 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_unary_op_make(       (yyvsp[-1].cpVal),   (yyvsp[0].exVal),   ctx); }
#line 1487 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 15:
#line 145 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_binary_op_make((yyvsp[-1].cpVal),   (yyvsp[-2].exVal),   (yyvsp[0].exVal),   ctx); }
#line 1493 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 16:
#line 146 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[-1].exVal); }
#line 1499 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 17:
#line 147 "util_expr_parse.y" /* yacc.c:1648  */
    { YYABORT; }
#line 1505 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 18:
#line 150 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_EQ,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1511 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 19:
#line 151 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_NE,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1517 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 20:
#line 152 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_LT,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1523 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 21:
#line 153 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_LE,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1529 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 22:
#line 154 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_GT,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1535 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 23:
#line 155 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_GE,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1541 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 24:
#line 156 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_STR_EQ,  (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1547 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 25:
#line 157 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_STR_NE,  (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1553 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 26:
#line 158 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_STR_LT,  (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1559 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 27:
#line 159 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_STR_LE,  (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1565 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 28:
#line 160 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_STR_GT,  (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1571 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 29:
#line 161 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_STR_GE,  (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1577 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 30:
#line 162 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_REG,     (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1583 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 31:
#line 163 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_NRE,     (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1589 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 32:
#line 164 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_IN,      (yyvsp[-2].exVal), (yyvsp[0].exVal), ctx); }
#line 1595 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 33:
#line 167 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Digit,  (yyvsp[0].cpVal), NULL, ctx); }
#line 1601 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 34:
#line 168 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_String, "", NULL, ctx); }
#line 1607 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 35:
#line 169 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[-1].exVal); }
#line 1613 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 36:
#line 170 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Concat, (yyvsp[-2].exVal), (yyvsp[0].exVal),   ctx); }
#line 1619 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 37:
#line 171 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1625 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 38:
#line 172 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1631 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 39:
#line 173 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1637 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 40:
#line 174 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1643 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 41:
#line 175 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[-1].exVal); }
#line 1649 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 42:
#line 178 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1655 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 43:
#line 179 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1661 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 44:
#line 180 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[-1].exVal); }
#line 1667 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 45:
#line 181 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[-1].exVal); }
#line 1673 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 46:
#line 184 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_String, (yyvsp[0].cpVal), NULL, ctx); }
#line 1679 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 47:
#line 185 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1685 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 48:
#line 188 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_var_make((yyvsp[-1].cpVal), ctx); }
#line 1691 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 49:
#line 189 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_str_func_make((yyvsp[-3].cpVal), (yyvsp[-1].exVal), ctx); }
#line 1697 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 50:
#line 190 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Bool, (yyvsp[-1].exVal), NULL, ctx); }
#line 1703 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 51:
#line 191 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Word, (yyvsp[-1].exVal), NULL, ctx); }
#line 1709 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 52:
#line 192 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_backref_make((yyvsp[0].num), ctx); }
#line 1715 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 53:
#line 195 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_str_func_make((yyvsp[-3].cpVal), (yyvsp[-1].exVal), ctx); }
#line 1721 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 54:
#line 196 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_str_func_make((yyvsp[-3].cpVal), (yyvsp[-1].exVal), ctx); }
#line 1727 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 55:
#line 199 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_list_func_make((yyvsp[-3].cpVal), (yyvsp[-1].exVal), ctx); }
#line 1733 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 56:
#line 203 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Sub, (yyvsp[0].exVal), (yyvsp[-2].exVal), ctx); }
#line 1739 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 57:
#line 204 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Sub, (yyvsp[-1].exVal), (yyvsp[-3].exVal), ctx); }
#line 1745 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 58:
#line 207 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Join, (yyvsp[0].exVal), NULL, ctx); }
#line 1751 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 59:
#line 208 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Join, (yyvsp[-1].exVal), NULL, ctx); }
#line 1757 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 60:
#line 209 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Join, (yyvsp[-2].exVal), (yyvsp[0].exVal),   ctx); }
#line 1763 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 61:
#line 210 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Join, (yyvsp[-3].exVal), (yyvsp[-1].exVal),   ctx); }
#line 1769 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 62:
#line 213 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Split, (yyvsp[0].exVal), (yyvsp[-2].exVal), ctx); }
#line 1775 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 63:
#line 214 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Split, (yyvsp[-1].exVal), (yyvsp[-3].exVal), ctx); }
#line 1781 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 64:
#line 215 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Split, (yyvsp[0].exVal), (yyvsp[-2].exVal), ctx); }
#line 1787 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 65:
#line 216 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_Split, (yyvsp[-1].exVal), (yyvsp[-3].exVal), ctx); }
#line 1793 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 66:
#line 219 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_ListElement, (yyvsp[0].exVal), NULL, ctx); }
#line 1799 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 67:
#line 220 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = ap_expr_make(op_ListElement, (yyvsp[-2].exVal), (yyvsp[0].exVal),   ctx); }
#line 1805 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 68:
#line 223 "util_expr_parse.y" /* yacc.c:1648  */
    {
                ap_expr_t *e = ap_expr_regex_make((yyvsp[-1].cpVal), NULL, (yyvsp[0].cpVal), ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                (yyval.exVal) = e;
            }
#line 1818 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 69:
#line 232 "util_expr_parse.y" /* yacc.c:1648  */
    {
                ap_expr_t *e = ap_expr_regex_make((yyvsp[-2].cpVal), (yyvsp[-1].exVal), (yyvsp[0].cpVal), ctx);
                if (!e) {
                    ctx->error = "Failed to compile regular expression";
                    YYERROR;
                }
                (yyval.exVal) = e;
            }
#line 1831 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 70:
#line 241 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1837 "util_expr_parse.c" /* yacc.c:1648  */
    break;

  case 71:
#line 242 "util_expr_parse.y" /* yacc.c:1648  */
    { (yyval.exVal) = (yyvsp[0].exVal); }
#line 1843 "util_expr_parse.c" /* yacc.c:1648  */
    break;


#line 1847 "util_expr_parse.c" /* yacc.c:1648  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (ctx, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (ctx, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, ctx);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, ctx);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (ctx, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, ctx);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, ctx);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 245 "util_expr_parse.y" /* yacc.c:1907  */


void yyerror(ap_expr_parse_ctx_t *ctx, const char *s)
{
    /* s is allocated on the stack */
    ctx->error = apr_pstrdup(ctx->ptemp, s);
}

