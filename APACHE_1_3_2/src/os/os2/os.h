#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "OS/2"
#define HAVE_CANONICAL_FILENAME

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
extern int ap_os_is_path_absolute(const char *f);
#endif

/* OS/2 doesn't have symlinks so S_ISLNK is always false */
#define S_ISLNK(m) 0

#endif   /* ! APACHE_OS_H */
