/* modules.c --- major modules compiled into Apache for Win32.
 * Only insert an entry for a module if it must be compiled into
 * the core server
 */

#include "httpd.h"
#include "http_config.h"

extern module core_module;
extern module so_module;
extern module mime_module;
extern module access_module;
extern module auth_module;
extern module negotiation_module;
extern module includes_module;
extern module autoindex_module;
extern module dir_module;
extern module cgi_module;
extern module userdir_module;
extern module alias_module;
extern module env_module;
extern module config_log_module;
extern module asis_module;
extern module imap_module;
extern module action_module;
extern module setenvif_module;
extern module isapi_module;

module *ap_prelinked_modules[] = {
  &core_module,
  &so_module,
  &mime_module,
  &access_module,
  &auth_module,
  &negotiation_module,
  &includes_module,
  &autoindex_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &env_module,
  &config_log_module,
  &asis_module,
  &imap_module,
  &action_module,
  &setenvif_module,
  &isapi_module,
  NULL
};
module *ap_preloaded_modules[] = {
  &core_module,
  &so_module,
  &mime_module,
  &access_module,
  &auth_module,
  &negotiation_module,
  &includes_module,
  &autoindex_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &env_module,
  &config_log_module,
  &asis_module,
  &imap_module,
  &action_module,
  &setenvif_module,
  &isapi_module,
  NULL
};
