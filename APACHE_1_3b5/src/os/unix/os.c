/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "os.h"


/* some linkers complain unless there's at least one function in each
 * .o file
 */
void os_is_not_here(void) {}
