#include "httpd.h"
#include "http_config.h"

/*
 * This file just tells the core what other modules have been compiled
 * in, so it knows to go out and configure them.  Someday, it might be
 * automatically generated from a config file which is intelligible to
 * J. Random Sysadmin...
 */

extern module core_module;
extern module mime_module;
extern module access_module;
extern module alias_module;
extern module auth_module;
extern module dbm_auth_module;
extern module negotiation_module;
extern module userdir_module;
extern module cgi_module;
extern module includes_module;
extern module dir_module;
extern module common_log_module;
extern module asis_module;
#ifdef DLD
extern module dld_module;
#endif

module *prelinked_modules[] = {
  &core_module,
  &mime_module,
  &access_module,
  &auth_module,
  &dbm_auth_module,
  &negotiation_module,
  &includes_module,
  &dir_module,
  &cgi_module,
  &userdir_module,
  &alias_module,
  &common_log_module,
  &asis_module,
#ifdef DLD  
  &dld_module,
#endif  
  NULL,
};
