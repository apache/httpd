/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "os.h"
#define INCL_DOS
#include <os2.h>
#include <stdio.h>

static int rc=0;

void ap_os_dso_init(void)
{
}



ap_os_dso_handle_t ap_os_dso_load(const char *module_name)
{
    char errorstr[200];
    HMODULE handle;

    rc = DosLoadModule(errorstr, sizeof(errorstr), module_name, &handle);

    if (rc == 0)
        return handle;

    return 0;
}



void ap_os_dso_unload(ap_os_dso_handle_t handle)
{
    DosFreeModule(handle);
}



void *ap_os_dso_sym(ap_os_dso_handle_t handle, const char *funcname)
{
    PFN func;
    
    rc = DosQueryProcAddr( handle, 0, funcname, &func );
    
    if (rc == 0)
        return func;

    return NULL;
}



const char *ap_os_dso_error(void)
{
    return ap_os_error_message(rc);
}
