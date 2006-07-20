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
 * This one uses the scoreboard and is only the proxy_worker loadbalancer
 */
#define CORE_PRIVATE

#include "apr.h"
#include "apr_pools.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "scoreboard.h"

#include "slotmem.h"

#if MODULE_MAGIC_NUMBER_MAJOR > 20020903
#define PROXY_HAS_SCOREBOARD 1
#else
#define PROXY_HAS_SCOREBOARD 0
#endif

struct ap_slotmem {
    void *ptr;
    apr_size_t size;
    int num;
};

static apr_status_t ap_slotmem_do(ap_slotmem_t *mem, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool)
{
    int i;
    void *ptr;

    if (!mem)
        return APR_ENOSHMAVAIL;

#if PROXY_HAS_SCOREBOARD
    for (i = 0; i < mem->num; i++) {
        ptr = (void *)ap_get_scoreboard_lb(i);
        func((void *)ptr, data, pool);
    }
    return 0;
#else
    return APR_ENOSHMAVAIL;
#endif
}
static apr_status_t ap_slotmem_create(ap_slotmem_t **new, const char *name, apr_size_t item_size, int item_num, apr_pool_t *pool)
{
    void *score = NULL;
    ap_slotmem_t *res;

#if PROXY_HAS_SCOREBOARD
    if (ap_scoreboard_image) {
        score = (void *)ap_get_scoreboard_lb(0);
        if (!score)
            return APR_ENOSHMAVAIL;
    }
#else
    return APR_ENOSHMAVAIL;
#endif
    if (!score)
        return APR_ENOSHMAVAIL;

    res = (ap_slotmem_t *) apr_pcalloc(pool, sizeof(ap_slotmem_t));
    res->ptr = score;
    res->size = item_size;
    res->num = item_num;
    *new = res;
    return APR_SUCCESS;
}
static apr_status_t ap_slotmem_mem(ap_slotmem_t *score, int id, void**mem)
{
    void *ptr;
    if (!score)
        return APR_ENOSHMAVAIL;

#if PROXY_HAS_SCOREBOARD
    if (ap_scoreboard_image)
        ptr = (void *)ap_get_scoreboard_lb(id);
#else
    return APR_ENOSHMAVAIL;
#endif

    if (!ptr)
        return APR_ENOSHMAVAIL;
    *mem = ptr;
    return APR_SUCCESS;
}

static const slotmem_storage_method storage = {
    &ap_slotmem_do,
    &ap_slotmem_create,
    &ap_slotmem_mem
};

static int pre_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp)
{
#if PROXY_HAS_SCOREBOARD
    return OK;
#else
    return DECLINED;
#endif
}

static void ap_scoreboard_register_hook(apr_pool_t *p)
{
    ap_register_provider(p, SLOTMEM_STORAGE, "score", "0", &storage);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA scoreboard_module = {
    STANDARD20_MODULE_STUFF,
    NULL,       /* create per-directory config structure */
    NULL,       /* merge per-directory config structures */
    NULL,       /* create per-server config structure */
    NULL,       /* merge per-server config structures */
    NULL,       /* command apr_table_t */
    ap_scoreboard_register_hook /* register hooks */
};
