/*
 * OS abstraction functions
 */

#include "os.h"

API_EXPORT(int)os_is_path_absolute(char *file)
{
  /* For now, just do the same check that http_request.c and mod_alias.c
   * do. 
   */
  return (file && (file[0] == '/' || file[1] == ':') ? 1 : 0);
}
