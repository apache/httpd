/*
 * This file will include OS specific functions which are not inlineable.
 * Any inlineable functions should be defined in os-inline.c instead.
 */

#include "os.h"

API_EXPORT(int)ap_is_path_absolute(char *file)
{
  return (file && file[0] == '/' ? 1 : 0);
}
