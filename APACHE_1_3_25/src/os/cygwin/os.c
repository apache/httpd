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
 *  Abstraction layer for loading
 *  Apache modules under run-time via 
 *  dynamic shared object (DSO) mechanism
 */

void ap_os_dso_init(void)
{
}

void *ap_os_dso_load(const char *path)
{
    return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
}

void ap_os_dso_unload(void *handle)
{
    dlclose(handle);

    return;
}

void *ap_os_dso_sym(void *handle, const char *symname)
{
    return dlsym(handle, symname);
}

const char *ap_os_dso_error(void)
{
    return dlerror();
}
