#ifndef __pre_nw__
#define __pre_nw__

#pragma precompile_target "precomp.mch"
#define NETWARE


#define N_PLAT_NLM

/* hint for MSL C++ that we're on NetWare platform */
#define __NETWARE__

/* the FAR keyword has no meaning in a 32-bit environment 
   but is used in the SDK headers so we take it out */
#define FAR
#define far

/* no-op for Codewarrior C compiler; a functions are cdecl 
   by default */
#define cdecl

/* if we have wchar_t enabled in C++, predefine this type to avoid
   a conflict in Novell's header files */
#if (__option(cplusplus) && __option(wchar_type))
#define _WCHAR_T
#endif

/* C9X defintion used by MSL C++ library */
#define DECIMAL_DIG 17

/* define long long typedefs for Watcom compatiblity */
typedef long long int64_t;
typedef unsigned long long uint64_t;

/* some code may want to use the MS convention for long long */
#ifndef __int64
#define __int64 long long
#endif

/* Don't use the DBM rewrite map for mod_rewrite */
#define NO_DBM_REWRITEMAP

/* Allow MOD_AUTH_DBM to use APR */
#define AP_AUTH_DBM_USE_APR

#endif



