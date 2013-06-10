/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_lua.h"

#ifndef _APL_CONFIG_H_
#define _APL_CONFIG_H_

void ap_lua_load_config_lmodule(lua_State *L);

apr_status_t ap_lua_map_handler(ap_lua_dir_cfg *cfg,
                                                const char *file,
                                                const char *function,
                                                const char *pattern,
                                                const char *scope);

#endif /* !_APL_CONFIG_H_ */
