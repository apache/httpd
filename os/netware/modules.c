/* modules.c --- major modules compiled into Apache for NetWare.
 * Only insert an entry for a module if it must be compiled into
 * the core server
 */

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"

extern module core_module;
extern module mpm_netware_module;
extern module http_module;
extern module so_module;
extern module mime_module;
extern module access_module;
extern module auth_module;
extern module negotiation_module;
extern module include_module;
extern module autoindex_module;
extern module dir_module;
extern module cgi_module;
extern module userdir_module;
extern module alias_module;
extern module env_module;
extern module log_config_module;
extern module asis_module;
extern module imap_module;
extern module actions_module;
extern module setenvif_module;
extern module nwssl_module;
extern module netware_module;

module *ap_prelinked_modules[] = {
  &core_module,
  &mpm_netware_module,
  &http_module,
  &so_module,
  &mime_module,
  &access_module,
  &auth_module,
  &negotiation_module,
  &include_module,
  &autoindex_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &env_module,
  &log_config_module,
  &asis_module,
  &imap_module,
  &actions_module,
  &setenvif_module,
  &nwssl_module,
  &netware_module,
  NULL
};

module *ap_preloaded_modules[] = {
  &core_module,
  &mpm_netware_module,
  &http_module,
  &so_module,
  &mime_module,
  &access_module,
  &auth_module,
  &negotiation_module,
  &include_module,
  &autoindex_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &env_module,
  &log_config_module,
  &asis_module,
  &imap_module,
  &actions_module,
  &setenvif_module,
  &nwssl_module,
  &netware_module,
  NULL
};
