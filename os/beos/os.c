/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "ap_config.h"
#include "os.h"

int ap_os_is_path_absolute(const char *file)
{
  return file[0] == '/';
}

int ap_spawnvp(const char *file, char *const argv[])
{
    int pid;

    if ((pid = fork()) == -1) {
        return pid;
    } else if (pid == 0) {
        if (execvp(file, argv) == -1)
            return -1;
        else
            return -1;  /* If we get, we have a real error, but this keeps
                           us from getting a warning during compile time. */
    } else 
        return pid;
}


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
    /* Nothing required to be done! */ 
}

void* ap_os_dso_load(const char *path)
{
    return (void*) load_add_on(path);
}

void ap_os_dso_unload(void* handle)
{
    unload_add_on((image_id)handle);
}

void *ap_os_dso_sym(void *handle, const char *symname)
{
    void * retval = 0;
#if defined(DLSYM_NEEDS_UNDERSCORE)
    char *symbol = (char*)malloc(sizeof(char)*(strlen(symname)+2));
    sprintf(symbol, "_%s", symname);
    get_image_symbol((image_id)handle, symbol, B_SYMBOL_TYPE_ANY, (void **)&retval);
    free(symbol);
    return retval;
#endif
    get_image_symbol((image_id)handle, symname, B_SYMBOL_TYPE_ANY, (void **)&retval);
    return retval;
}

const char *ap_os_dso_error(void)
{
    return NULL;
}
