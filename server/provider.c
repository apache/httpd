/* Copyright 2002-2005 The Apache Software Foundation or its licensors, as
 * applicable.
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

#include "apr_pools.h"
#include "apr_hash.h"

#include "ap_provider.h"

static apr_hash_t *global_providers = NULL;

static apr_status_t cleanup_global_providers(void *ctx)
{
    global_providers = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_register_provider(apr_pool_t *pool,
                                              const char *provider_group,
                                              const char *provider_name,
                                              const char *provider_version,
                                              const void *provider)
{
    apr_hash_t *provider_group_hash;
    apr_hash_t *provider_version_hash;

    if (global_providers == NULL) {
        global_providers = apr_hash_make(pool);
        apr_pool_cleanup_register(pool, NULL, cleanup_global_providers,
                                  apr_pool_cleanup_null);
    }

    provider_group_hash = apr_hash_get(global_providers, provider_group,
                                       APR_HASH_KEY_STRING);

    if (!provider_group_hash) {
        provider_group_hash = apr_hash_make(pool);
        apr_hash_set(global_providers, provider_group, APR_HASH_KEY_STRING,
                     provider_group_hash);
        
    }

    provider_version_hash = apr_hash_get(provider_group_hash, provider_name,
                                         APR_HASH_KEY_STRING);

    if (!provider_version_hash) {
        provider_version_hash = apr_hash_make(pool);
        apr_hash_set(provider_group_hash, provider_name, APR_HASH_KEY_STRING,
                     provider_version_hash);
        
    }

    /* just set it. no biggy if it was there before. */
    apr_hash_set(provider_version_hash, provider_version, APR_HASH_KEY_STRING,
                 provider);

    return APR_SUCCESS;
}

AP_DECLARE(void *) ap_lookup_provider(const char *provider_group,
                                      const char *provider_name,
                                      const char *provider_version)
{
    apr_hash_t *provider_group_hash, *provider_name_hash;

    if (global_providers == NULL) {
        return NULL;
    }

    provider_group_hash = apr_hash_get(global_providers, provider_group,
                                       APR_HASH_KEY_STRING);

    if (provider_group_hash == NULL) {
        return NULL;
    }

    provider_name_hash = apr_hash_get(provider_group_hash, provider_name,
                                      APR_HASH_KEY_STRING);

    if (provider_name_hash == NULL) {
        return NULL;
    }

    return apr_hash_get(provider_name_hash, provider_version,
                        APR_HASH_KEY_STRING);
}
