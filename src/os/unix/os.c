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
