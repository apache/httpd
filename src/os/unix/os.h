/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#if defined(__GNUC__) && !defined(INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern __inline__
#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int os_is_path_absolute(char *f);
#endif
