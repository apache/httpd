/* modules.c --- major modules compiled into Apache for Win32.
 * Only insert an entry for a module if it must be compiled into
 * the core server
 */

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"

extern module core_module;
extern module win32_module;
extern module mpm_winnt_module;
extern module http_module;
extern module so_module;

AP_DECLARE_DATA module *ap_prelinked_modules[] = {
  &core_module,
  &win32_module,
  &mpm_winnt_module,
  &http_module,
  &so_module,
  NULL
};

AP_DECLARE_DATA module *ap_preloaded_modules[] = {
  &core_module,
  &win32_module,
  &mpm_winnt_module,
  &http_module,
  &so_module,
  NULL
};
