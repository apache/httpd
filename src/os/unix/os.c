/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "conf.h"
#include "os.h"


/* some linkers complain unless there's at least one function in each
 * .o file... and extra prototype is for gcc -Wmissing-prototypes
 */
extern void os_is_not_here(void);
void os_is_not_here(void) {}


#if defined(HPUX) || defined(HPUX10)

/*
 * HPUX dlopen interface-emulation
 */

#include <dl.h>
#include <errno.h>

void *os_dl_load(char *path)
{
    shl_t handle;
    handle = shl_load(path, BIND_IMMEDIATE|BIND_VERBOSE|BIND_NOSTART, 0L);
    return (void *)handle;
}

void os_dl_unload(void *handle) 
{
    shl_unload((shl_t)handle);
    return;
}

void *os_dl_sym(void *handle, char *symname)
{
    void *symaddr = NULL;
    int status;

    errno = 0;
    status = shl_findsym((shl_t *)&handle, symname, TYPE_PROCEDURE, &symaddr);
    if (status == -1 && errno == 0) /* try TYPE_DATA instead */
        status = shl_findsym((shl_t *)&handle, symname, TYPE_DATA, &symaddr);
    return (status == -1 ? NULL : symaddr);
}

char *os_dl_error(void)
{
    return strerror(errno);
}

#endif /* HPUX dlopen interface-emulation */

