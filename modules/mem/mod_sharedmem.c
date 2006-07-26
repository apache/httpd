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

/* Memory handler for a shared memory divided in slot.
 * This one uses shared memory.
 */
#define CORE_PRIVATE

#include "apr.h"
#include "apr_pools.h"
#include "apr_shm.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include  "slotmem.h"

/* make sure the shared memory is cleaned */
static int initialize_cleanup(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    sharedmem_initialize_cleanup(p);
    return OK;
}

static int pre_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp)
{
    sharedmem_initglobalpool(p);
    return OK;
}

static void ap_sharedmem_register_hook(apr_pool_t *p)
{
    slotmem_storage_method *storage = sharedmem_getstorage();
    ap_register_provider(p, SLOTMEM_STORAGE, "shared", "0", storage);
    ap_hook_post_config(initialize_cleanup, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA sharedmem_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    ap_sharedmem_register_hook /* register hooks */
};
