/*
 * This file contains functions which can be inlined if the compiler
 * has an "inline" modifier. Because of this, this file is both a
 * header file and a compilable module.
 *
 * Only inlineable functions should be defined in here. They must all
 * include the INLINE modifier. 
 *
 * If the compiler supports inline, this file will be #included as a
 * header file from os.h to create all the inline function
 * definitions. INLINE will be defined to whatever is required on
 * function definitions to make them inline declarations.
 *
 * If the compiler does not support inline, this file will be compiled
 * as a normal C file into libos.a (along with os.c). In this case
 * INLINE will _not_ be set so we can use this to test if we are
 * compiling this source file.  
 */
#include <unistd.h>

#ifndef INLINE
#define INLINE

/* Anything required only when compiling */
#include "ap_config.h"

#endif

INLINE int ap_os_is_path_absolute(const char *file)
{
  return file[0] == '/';
}

INLINE int ap_spawnvp(const char *file, char *const argv[])
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
    
