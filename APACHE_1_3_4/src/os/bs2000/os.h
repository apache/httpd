#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "BS2000"

/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#include "ap_config.h"

#if !defined(INLINE) && defined(USE_GNU_INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern ap_inline

INLINE int ap_os_is_path_absolute(const char *file);

#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int ap_os_is_path_absolute(const char *file);
#endif

/* Other ap_os_ routines not used by this platform */

#define ap_os_is_filename_valid(f)          (1)

/* Sorry if this is ugly, but the include order doesn't allow me
 * to use request_rec here... */
struct request_rec;
extern int ap_checkconv(struct request_rec *r);
extern pid_t os_fork(void);

#endif /*! APACHE_OS_H*/
