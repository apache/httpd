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

/* Memory handler for memory divided in slot.
 * We provide a universal API and are a simple
 * front-end to the actual memory providers.
 */

#include  "ap_slotmem.h"

AP_DECLARE(apr_array_header_t *) ap_slotmem_methods(apr_pool_t *pool)
{
    return (ap_list_provider_names(pool, AP_SLOTMEM_STORAGE, "0"));
}

AP_DECLARE(ap_slotmem_storage_method *) ap_slotmem_method(const char *provider)
{
    return (ap_lookup_provider(AP_SLOTMEM_STORAGE, provider, "0"));
}

AP_DECLARE(apr_status_t) ap_slotmem_do(ap_slotmem_storage_method *sm,
                                       ap_slotmem_t *s,
                                       ap_slotmem_callback_fn_t *func,
                                       void *data, apr_pool_t *pool)
{
    return (sm->slotmem_do(s, func, data, pool));
}

AP_DECLARE(apr_status_t) ap_slotmem_create(ap_slotmem_storage_method *sm,
                                           ap_slotmem_t **new, const char *name,
                                           apr_size_t item_size, unsigned int item_num,
                                           apr_pool_t *pool)
{
    return (sm->slotmem_create(new, name, item_size, item_num, pool));
}

AP_DECLARE(apr_status_t) ap_slotmem_attach(ap_slotmem_storage_method *sm,
                                           ap_slotmem_t **new, const char *name,
                                           apr_size_t *item_size, unsigned int *item_num,
                                           apr_pool_t *pool)
{
    return (sm->slotmem_attach(new, name, item_size, item_num, pool));
}

AP_DECLARE(apr_status_t) ap_slotmem_mem(ap_slotmem_storage_method *sm,
                                        ap_slotmem_t *s, unsigned int item_id, void**mem)
{
    return (sm->slotmem_mem(s, item_id, mem));
}

AP_DECLARE(apr_status_t) ap_slotmem_lock(ap_slotmem_storage_method *sm,
                                         ap_slotmem_t *s)
{
    return (sm->slotmem_lock(s));
}

AP_DECLARE(apr_status_t) ap_slotmem_unlock(ap_slotmem_storage_method *sm,
                                           ap_slotmem_t *s)
{
    return (sm->slotmem_unlock(s));
}

AP_DECLARE(apr_status_t) ap_slotmem_get(ap_slotmem_storage_method *sm,
                                        ap_slotmem_t *s, unsigned int item_id,
                                        unsigned char *dest, apr_size_t dest_len)
{
    return (sm->slotmem_get(s, item_id, dest, dest_len));
}
AP_DECLARE(apr_status_t) ap_slotmem_put(ap_slotmem_storage_method *sm, ap_slotmem_t *s,
                                        unsigned int item_id, unsigned char *src,
                                        apr_size_t src_len)
{
    return (sm->slotmem_put(s, item_id, src, src_len));
}

module AP_MODULE_DECLARE_DATA slotmem_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    NULL                        /* register hooks */
};

