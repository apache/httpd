/*
 * This file in included in all Apache source code. It contains definitions
 * of facilities available on _this_ operating system (HAVE_* macros),
 * and prototypes of OS specific functions defined in os.c or os-inline.c
 */

#if !defined(INLINE) && defined(USE_GNU_INLINE)
/* Compiler supports inline, so include the inlineable functions as
 * part of the header
 */
#define INLINE extern ap_inline
#include "os-inline.c"
#endif

#ifndef INLINE
/* Compiler does not support inline, so prototype the inlineable functions
 * as normal
 */
extern int os_is_path_absolute(const char *f);
#endif

/*
 * Abstraction layer for dynamic loading of modules (mod_so.c)
 */

#if defined(LINUX) || defined(__FreeBSD__) || defined(SOLARIS) || \
    defined(__bsdi__) || defined(IRIX)
# define HAS_DLFCN
#endif

#if defined(__FreeBSD__)
# define NEED_UNDERSCORE_SYM
#endif

     /* OSes that don't support dlopen */
#if defined(UW) || defined(ULTRIX)
# define NO_DL
#endif

     /* Start of real module */
#ifdef HAS_DLFCN
# include <dlfcn.h>
#else
void * dlopen (__const char * __filename, int __flag);
__const char * dlerror (void);
void * dlsym (void *, __const char *);
int dlclose (void *);
#endif

#ifndef RTLD_NOW
/* 
 * probably on an older system that doesn't support RTLD_NOW or RTLD_LAZY.
 * The below define is a lie since we are really doing RTLD_LAZY since the
 * system doesn't support RTLD_NOW.
 */
# define RTLD_NOW 1
#endif

#define os_dl_module_handle_type void *
#define os_dl_load(l)   dlopen(l, RTLD_NOW)
#define os_dl_unload(l) dlclose(l)
#define os_dl_sym(h,s)  dlsym(h,s)
#define os_dl_error()   dlerror()
