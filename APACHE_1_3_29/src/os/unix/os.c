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
 * Insert the DSO emulation code for AIX for releases of AIX prior
 * to 4.3. Use the native DSO code for 4.3 and later.
 */
#if defined(AIX) && !defined(NO_DL_NEEDED)
#if AIX < 430
#include "os-aix-dso.c"
#endif
#endif

/*
 *  Abstraction layer for loading
 *  Apache modules under run-time via 
 *  dynamic shared object (DSO) mechanism
 */

#ifdef HAVE_DYLD		/* NeXT/Apple dynamic linker */
#include <mach-o/dyld.h>

/*
 * NSUnlinkModule() is a noop in old versions of dyld.
 * Let's install an error handler to deal with "multiply defined
 * symbol" runtime errors.
 */
#ifdef DYLD_CANT_UNLOAD
#include "httpd.h"
#include "http_log.h"

ap_private_extern
void undefined_symbol_handler(const char *symbolName)
{
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, NULL,
                 "dyld found undefined symbol: %s\n"
                 "Aborting.\n",
                 symbolName);
    abort();
}

ap_private_extern
NSModule multiple_symbol_handler (NSSymbol s, NSModule old, NSModule new)
{
    /*
     * Since we can't unload symbols, we're going to run into this
     * every time we reload a module. Workaround here is to just
     * rebind to the new symbol, and forget about the old one.
     * This is crummy, because it's basically a memory leak.
     */

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, NULL,
                 "dyld found a multiply defined symbol %s in modules:\n"
                 "%s\n%s\n",
                 NSNameOfSymbol(s),
                 NSNameOfModule(old), NSNameOfModule(new));
#endif

    return(new);
}

ap_private_extern
void linkEdit_symbol_handler (NSLinkEditErrors c, int errorNumber,
                              const char *fileName, const char *errorString)
{
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_EMERG, NULL,
                 "dyld errors during link edit for file %s\n%s\n",
                 fileName, errorString);
    abort();
}

#endif /* DYLD_CANT_UNLOAD */
#endif /* HAVE_DYLD */

void ap_os_dso_init(void)
{
#if defined(HAVE_DYLD) && defined(DYLD_CANT_UNLOAD)
    NSLinkEditErrorHandlers handlers;

    handlers.undefined = undefined_symbol_handler;
    handlers.multiple  = multiple_symbol_handler;
    handlers.linkEdit  = linkEdit_symbol_handler;

    NSInstallLinkEditErrorHandlers(&handlers);
#endif
}

void *ap_os_dso_load(const char *path)
{
#if defined(HPUX) || defined(HPUX10) || defined(HPUX11)
    shl_t handle;
    handle = shl_load(path, BIND_IMMEDIATE|BIND_VERBOSE, 0L);
    return (void *)handle;

#elif defined(HAVE_DYLD)
    NSObjectFileImage image;
    NSModule handle;
    if (NSCreateObjectFileImageFromFile(path, &image) !=
        NSObjectFileImageSuccess)
        return NULL;
#if defined(NSLINKMODULE_OPTION_RETURN_ON_ERROR) && defined(NSLINKMODULE_OPTION_NONE)
    handle = NSLinkModule(image, path,
                          NSLINKMODULE_OPTION_RETURN_ON_ERROR |
                          NSLINKMODULE_OPTION_NONE);
#else
    handle = NSLinkModule(image, path, FALSE);
#endif
    NSDestroyObjectFileImage(image);
    return handle;

#elif defined(OSF1) || defined(SEQUENT) ||\
    (defined(__FreeBSD_version) && (__FreeBSD_version >= 220000))
    return dlopen((char *)path, RTLD_NOW | RTLD_GLOBAL);

#else
    return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
#endif
}

void ap_os_dso_unload(void *handle)
{
#if defined(HPUX) || defined(HPUX10) || defined(HPUX11)
    shl_unload((shl_t)handle);

#elif defined(HAVE_DYLD)
    NSUnLinkModule(handle,FALSE);

#else
    dlclose(handle);
#endif

    return;
}

void *ap_os_dso_sym(void *handle, const char *symname)
{
#if defined(HPUX) || defined(HPUX10) || defined(HPUX11)
    void *symaddr = NULL;
    int status;

    errno = 0;
    status = shl_findsym((shl_t *)&handle, symname, TYPE_PROCEDURE, &symaddr);
    if (status == -1 && errno == 0) /* try TYPE_DATA instead */
        status = shl_findsym((shl_t *)&handle, symname, TYPE_DATA, &symaddr);
    return (status == -1 ? NULL : symaddr);

#elif defined(HAVE_DYLD)
    NSSymbol symbol;
    char *symname2 = (char*)malloc(sizeof(char)*(strlen(symname)+2));
    sprintf(symname2, "_%s", symname);
    symbol = NSLookupAndBindSymbol(symname2);
    free(symname2);
    return NSAddressOfSymbol(symbol);

#elif defined(DLSYM_NEEDS_UNDERSCORE)
    char *symbol = (char*)malloc(sizeof(char)*(strlen(symname)+2));
    void *retval;
    sprintf(symbol, "_%s", symname);
    retval = dlsym(handle, symbol);
    free(symbol);
    return retval;

#elif defined(SEQUENT)
    return dlsym(handle, (char *)symname);

#else
    return dlsym(handle, symname);
#endif
}

const char *ap_os_dso_error(void)
{
#if defined(HPUX) || defined(HPUX10) || defined(HPUX11)
    return strerror(errno);
#elif defined(HAVE_DYLD)
    return NULL;
#else
    return dlerror();
#endif
}
