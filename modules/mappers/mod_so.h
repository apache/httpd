/* Copyright 2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOD_SO_H
#define MOD_SO_H 1

#include "apr_optional.h"
#include "httpd.h"

/* optional function declaration */
APR_DECLARE_OPTIONAL_FN(module *, ap_find_loaded_module_symbol,
                        (server_rec *s, const char *modname));
APR_DECLARE_OPTIONAL_FN(void, ap_dump_loaded_modules,
                        (apr_pool_t* p, server_rec *s));

#endif /* MOD_SO_H */

