/* Copyright 2002-2004 The Apache Software Foundation
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

#ifndef AP_PROVIDER_H
#define AP_PROVIDER_H

#include "ap_config.h"

/**
 * @package Provider API
 */

/**
 * This function is used to register a provider with the global
 * provider pool.
 * @param pool The pool to create any storage from
 * @param provider_group The group to store the provider in
 * @param provider_name The name for this provider
 * @param provider_version The version for this provider
 * @param provider Opaque structure for this provider
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_register_provider(apr_pool_t *pool,
                                              const char *provider_group,
                                              const char *provider_name,
                                              const char *provider_version,
                                              const void *provider);

/**
 * This function is used to retrieve a provider from the global
 * provider pool.
 * @param provider_group The group to look for this provider in
 * @param provider_name The name for the provider
 * @param provider_version The version for the provider
 * @return provider pointer to provider if found, NULL otherwise
 */
AP_DECLARE(void *) ap_lookup_provider(const char *provider_group,
                                      const char *provider_name,
                                      const char *provider_version);

#endif
