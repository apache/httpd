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

/* modules.c --- major modules compiled into Apache for Win32.
 * Only insert an entry for a module if it must be compiled into
 * the core server
 */

#include "httpd.h"
#include "http_config.h"

extern module core_module;
extern module win32_module;
extern module mpm_winnt_module;
extern module http_module;
extern module so_module;
extern module watchdog_module;

AP_DECLARE_DATA module *ap_prelinked_modules[] = {
  &core_module,
  &win32_module,
  &mpm_winnt_module,
  &http_module,
  &so_module,
  NULL
};

ap_module_symbol_t ap_prelinked_module_symbols[] = {
  {"core_module", &core_module},
  {"win32_module", &win32_module},
  {"mpm_winnt_module", &mpm_winnt_module},
  {"http_module", &http_module},
  {"so_module", &so_module},
  {NULL, NULL}
};

AP_DECLARE_DATA module *ap_preloaded_modules[] = {
  &core_module,
  &win32_module,
  &mpm_winnt_module,
  &http_module,
  &so_module,
  &watchdog_module,
  NULL
};
