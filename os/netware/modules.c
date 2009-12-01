/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* modules.c --- major modules compiled into Apache for NetWare.
 * Only insert an entry for a module if it must be compiled into
 * the core server
 */


#include "httpd.h"
#include "http_config.h"

extern module core_module;
extern module mpm_netware_module;
extern module http_module;
extern module so_module;
extern module mime_module;
extern module authn_core_module;
extern module authz_core_module;
extern module authz_host_module;
extern module negotiation_module;
extern module include_module;
extern module dir_module;
extern module alias_module;
extern module env_module;
extern module log_config_module;
extern module setenvif_module;
extern module watchdog_module;
#ifdef USE_WINSOCK
extern module nwssl_module;
#endif
extern module netware_module;

module *ap_prelinked_modules[] = {
  &core_module,
  &mpm_netware_module,
  &http_module,
  &so_module,
  &mime_module,
  &authn_core_module,
  &authz_core_module,
  &authz_host_module,
  &negotiation_module,
  &include_module,
  &dir_module,
  &alias_module,
  &env_module,
  &log_config_module,
  &setenvif_module,
  &watchdog_module,
#ifdef USE_WINSOCK
  &nwssl_module,
#endif
  &netware_module,
  NULL
};

ap_module_symbol_t ap_prelinked_module_symbols[] = {
  {"core_module", &core_module},
  {"mpm_netware_module", &mpm_netware_module},
  {"http_module", &http_module},
  {"so_module", &so_module},
  {"mime_module", &mime_module},
  {"authn_core_module", &authn_core_module},
  {"authz_core_module", &authz_core_module},
  {"authz_host_module", &authz_host_module},
  {"negotiation_module", &negotiation_module},
  {"include_module", &include_module},
  {"dir_module", &dir_module},
  {"alias_module", &alias_module},
  {"env_module", &env_module},
  {"log_config_module", &log_config_module},
  {"setenvif_module", &setenvif_module},
  {"watchdog module", &watchdog_module},
#ifdef USE_WINSOCK
  {"nwssl_module", &nwssl_module},
#endif
  {"netware_module", &netware_module},
  {NULL, NULL}
};

module *ap_preloaded_modules[] = {
  &core_module,
  &mpm_netware_module,
  &http_module,
  &so_module,
  &mime_module,
  &authn_core_module,
  &authz_core_module,
  &authz_host_module,
  &negotiation_module,
  &include_module,
  &dir_module,
  &alias_module,
  &env_module,
  &log_config_module,
  &setenvif_module,
  &watchdog_module,
#ifdef USE_WINSOCK
  &nwssl_module,
#endif
  &netware_module,
  NULL
};
