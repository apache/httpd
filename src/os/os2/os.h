#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "OS/2"
#define HAVE_CANONICAL_FILENAME
#define HAVE_DRIVE_LETTERS
#define HAVE_UNC_PATHS

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

INLINE int ap_os_is_path_absolute(const char *file);

#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int ap_os_is_path_absolute(const char *file);
#endif

/* FIXME: the following should be implemented on this platform */
#define ap_os_is_filename_valid(f)         (1)

/* Use a specialized kill() function */
int ap_os_kill(int pid, int sig);

/* Maps an OS error code to an error message */
char *ap_os_error_message(int err);

/* OS/2 doesn't have symlinks so S_ISLNK is always false */
#define S_ISLNK(m) 0
#define lstat(x, y) stat(x, y)

#define isinf(n) (!isfinite(n))
#define HAVE_ISINF
#define HAVE_ISNAN

/* strtol() correctly returns ERANGE on overflow, use it */
#define ap_strtol strtol

/* Dynamic loading functions */
#define     ap_os_dso_handle_t  unsigned long
void        ap_os_dso_init(void);
ap_os_dso_handle_t ap_os_dso_load(const char *);
void        ap_os_dso_unload(ap_os_dso_handle_t);
void *      ap_os_dso_sym(ap_os_dso_handle_t, const char *);
const char *ap_os_dso_error(void);

#endif   /* ! APACHE_OS_H */
