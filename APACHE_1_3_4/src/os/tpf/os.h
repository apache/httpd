#ifndef APACHE_OS_H
#define APACHE_OS_H

#define PLATFORM "TPF"

#ifdef errno
#undef errno
#endif

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
 
#ifdef FD_SETSIZE
#undef FD_SETSIZE 
#endif

#define FD_SETSIZE    2048 
 
#ifdef __FD_MASK
#undef __FD_MASK 
#endif

typedef long __FD_MASK;

#ifdef __NBBY
#undef __NBBY 
#endif

#define __NBBY    8    /* number of bits in a byte */

#ifdef __NFDBITS
#undef __NFDBITS 
#endif

#define __NFDBITS (sizeof(__FD_MASK) * __NBBY)

#ifndef __howmany
#define  __howmany(x, y)  (((x)+((y)-1))/(y))
#endif 
 
typedef struct fd_set { 
        __FD_MASK fds_bits [__howmany(FD_SETSIZE, __NFDBITS)]; 
} fd_set; 

#define  FD_SET(n, p)((p)->fds_bits[(n)/__NFDBITS] |= (1 <<((n) % __NFDBITS)))

#define  FD_CLR(n, p)((p)->fds_bits[(n)/__NFDBITS] &= ~(1 << ((n) % __NFDBITS)))

#define  FD_ISSET(n, p)((p)->fds_bits[(n)/__NFDBITS] & (1 <<((n) % __NFDBITS)))

#define  FD_ZERO(p)   memset((char *)(p), 0, sizeof(*(p)))
    

#define  SIGPIPE  13
#define  SIGQUIT  24
#define  SO_KEEPALIVE  0x0008

/* TPF doesn't have, or need, tzset (it is used in mod_expires.c) */
#define tzset()

#include <stdarg.h>
#undef va_list
#undef va_start
#undef va_arg
#undef va_end

typedef char *va_list;

#define __va_promote(type) (((sizeof(type) + sizeof(int) - 1) \
                           / sizeof(int)) * sizeof(int))

#define va_start(ap, last) (ap = ((char *)&(last) + __va_promote(last)))

#define va_arg(ap, type) ((type *)(ap += sizeof(type) < sizeof(int) ? \
                         (abort(), 0) : sizeof(type)))[-1]

#define va_end(ap)

#endif /*! APACHE_OS_H*/
