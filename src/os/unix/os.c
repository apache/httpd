/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "ap_config.h"
#include "os.h"


/* some linkers complain unless there's at least one function in each
 * .o file... and extra prototype is for gcc -Wmissing-prototypes
 */
extern void ap_is_not_here(void);
void ap_is_not_here(void) {}

/*
 * Insert the DSO emulation code for AIX
 */
#ifdef AIX
#include "os-aix-dso.c"
#endif

/*
 *  Abstraction layer for loading
 *  Apache modules under run-time via 
 *  dynamic shared object (DSO) mechanism
 */

void *ap_os_dso_load(const char *path)
{
#if defined(HPUX) || defined(HPUX10)
    shl_t handle;
    handle = shl_load(path, BIND_IMMEDIATE|BIND_VERBOSE|BIND_NOSTART, 0L);
    return (void *)handle;
#else
#if defined(OSF1) ||\
    (defined(__FreeBSD_version) && (__FreeBSD_version >= 220000))
    return dlopen((char *)path, RTLD_NOW | RTLD_GLOBAL);
#else
    return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
#endif
#endif
}

void ap_os_dso_unload(void *handle) 
{
#if defined(HPUX) || defined(HPUX10)
    shl_unload((shl_t)handle);
#else
    dlclose(handle);
#endif
    return;
}

void *ap_os_dso_sym(void *handle, const char *symname)
{
#if defined(HPUX) || defined(HPUX10)
    void *symaddr = NULL;
    int status;

    errno = 0;
    status = shl_findsym((shl_t *)&handle, symname, TYPE_PROCEDURE, &symaddr);
    if (status == -1 && errno == 0) /* try TYPE_DATA instead */
        status = shl_findsym((shl_t *)&handle, symname, TYPE_DATA, &symaddr);
    return (status == -1 ? NULL : symaddr);
#else /* ndef HPUX */
#ifdef DLSYM_NEEDS_UNDERSCORE
    char symbol[256];
    sprintf(symbol, "_%s", symname);
    return dlsym(handle, symbol);
#else
    return dlsym(handle, symname);
#endif
#endif /* ndef HPUX */
}

const char *ap_os_dso_error(void)
{
#if defined(HPUX) || defined(HPUX10)
    return strerror(errno);
#else
    return dlerror();
#endif
}

